#!/usr/bin/env python3
"""
Simple threaded port scanner with host discovery and CSV output.
Usage examples:
  python port_scanner.py --target 192.168.0.0/24 --ports 22 80 443 --workers 200 --outfile results.csv
  python port_scanner.py                      # tries to auto-detect local /24
"""

import argparse
import csv
import ipaddress
import platform
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------- Config defaults ----------
DEFAULT_PORTS = [22, 80, 443]
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 200

# ---------- Helpers ----------

def detect_local_network():
    """Try to detect local IPv4 and return a /24 network as fallback."""
    # Try socket hostname first
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # If it's loopback, fall back to parsing ipconfig/ifconfig
        if local_ip.startswith("127.") or local_ip == "0.0.0.0":
            raise Exception("loopback")
        return ipaddress.ip_network(local_ip + '/24', strict=False)
    except Exception:
        # Try platform-specific commands
        try:
            if platform.system().lower().startswith("win"):
                out = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
                # For Windows, attempt to find "IPv4 Address" or localized variants
                for line in out.splitlines():
                    if "IPv4 Address" in line or "IPv4-Adresse" in line or "IPv4" in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ip = parts[-1].strip()
                            return ipaddress.ip_network(ip + '/24', strict=False)
            else:
                # Try `hostname -I` (common) and fallback to `ip addr`
                try:
                    out = subprocess.check_output("hostname -I", shell=True, text=True, stderr=subprocess.DEVNULL)
                    ip = out.split()[0].strip()
                    return ipaddress.ip_network(ip + '/24', strict=False)
                except Exception:
                    out = subprocess.check_output("ip addr", shell=True, text=True, stderr=subprocess.DEVNULL)
                    # crude parse: find first 'inet ' followed by IPv4
                    for line in out.splitlines():
                        line = line.strip()
                        if line.startswith("inet "):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip_cidr = parts[1]
                                # ip_cidr like '192.168.1.5/24'
                                try:
                                    net = ipaddress.ip_network(ip_cidr, strict=False)
                                    return net
                                except Exception:
                                    # fallback: take ip part
                                    ip = ip_cidr.split('/')[0]
                                    return ipaddress.ip_network(ip + '/24', strict=False)
        except Exception:
            # fall back to common private space
            return ipaddress.ip_network("192.168.0.0/24")


def shutil_which_ping() -> bool:
    """Return True if 'ping' is available on PATH."""
    return shutil.which("ping") is not None


def is_host_up(ip, use_ping=True, timeout=DEFAULT_TIMEOUT):
    """Check if host is up. Prefer ping; fallback to quick TCP connect on common ports."""
    ip_str = str(ip)
    if use_ping and shutil_which_ping():
        ping_cmd = None
        if platform.system().lower().startswith("win"):
            # -n 1 (one echo request), -w timeout in ms
            ping_cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_str]
        else:
            # -c 1 (one packet), -W timeout in seconds (may behave differently across platforms)
            ping_cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout))), ip_str]
        try:
            res = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            pass

    # Fallback: try connecting to common ports quickly
    for p in (80, 443, 22):
        try:
            with socket.create_connection((ip_str, p), timeout=timeout):
                return True
        except Exception:
            continue
    return False


def scan_port(ip, port, timeout=DEFAULT_TIMEOUT) -> bool:
    """Return True if port open, False otherwise."""
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False

# ---------- Main runner ----------

def main():
    parser = argparse.ArgumentParser(description="Threaded port scanner with host discovery.")
    parser.add_argument("--target", "-t", help="Target network (CIDR) or single IP (e.g. 192.168.0.0/24 or 192.168.0.10)")
    parser.add_argument("--ports", "-p", nargs="+", type=int, default=DEFAULT_PORTS, help="Ports to scan (space separated)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="ThreadPool max workers")
    parser.add_argument("--outfile", "-o", help="CSV output file")
    parser.add_argument("--no-ping", dest="no_ping", action="store_true", help="Don't try ping for host discovery (use TCP only)")
    args = parser.parse_args()

    # Resolve target -> list of hosts
    if args.target:
        try:
            if '/' in args.target:
                net = ipaddress.ip_network(args.target, strict=False)
                hosts = list(net.hosts())
            else:
                # single IP
                hosts = [ipaddress.ip_address(args.target)]
        except Exception as e:
            print("Invalid target:", e)
            sys.exit(1)
    else:
        net = detect_local_network()
        print("Auto-detected network:", net)
        hosts = list(net.hosts())

    ports = sorted(set(args.ports))
    timeout = args.timeout
    workers = args.workers

    start = datetime.now()
    print("Scan started:", start)
    results = []  # list of (ip_str, open_ports_list)

    # Limit worker count sensibly
    if workers < 1:
        workers = 1

    # Host discovery first to avoid scanning unreachable hosts
    print("Discovering live hosts (this may use ping / TCP) ...")
    live_hosts = []
    use_ping = (not args.no_ping) and shutil_which_ping()
    with ThreadPoolExecutor(max_workers=min(100, workers)) as exec_srv:
        futures = {exec_srv.submit(is_host_up, ip, use_ping, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    live_hosts.append(ip)
            except Exception:
                continue

    if not live_hosts:
        print("No live hosts found. Exiting.")
        sys.exit(0)

    print(f"Found {len(live_hosts)} live hosts — scanning {len(ports)} ports per host with {workers} workers...")

    # Scan ports for each live host using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as executor:
        all_futures = {}
        for ip in live_hosts:
            for port in ports:
                f = executor.submit(scan_port, ip, port, timeout)
                all_futures[f] = (ip, port)

        # collect results
        open_map = {}  # ip -> [ports]
        try:
            for fut in as_completed(all_futures):
                ip, port = all_futures[fut]
                try:
                    if fut.result():
                        open_map.setdefault(str(ip), []).append(port)
                except Exception:
                    pass
        except KeyboardInterrupt:
            print('\nScan interrupted by user. Exiting.')
            executor.shutdown(wait=False)
            sys.exit(1)

    # Print and save
    for ip in sorted(open_map.keys(), key=lambda x: tuple(int(p) for p in x.split('.'))):
        open_ports = sorted(open_map[ip])
        print(f"{ip} -> {open_ports}")
        results.append((ip, open_ports))

    finished = datetime.now()
    print("Scan finished:", finished, "Duration:", finished - start)

    if args.outfile:
        try:
            with open(args.outfile, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip", "open_ports"])
                for ip, ports in results:
                    w.writerow([ip, ";".join(str(p) for p in ports)])
            print("Results saved to", args.outfile)
        except Exception as e:
            print("Failed to write CSV:", e)


if __name__ == "__main__":
    main()
