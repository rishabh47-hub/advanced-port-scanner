 Advanced Python Port Scanner

A fast, multi-threaded port scanner built in Python using:
- socket
- concurrent.futures
- ipaddress

This tool:
- Discovers live hosts on a subnet
- Scans common TCP ports on each live host
- Uses 200 concurrent workers for high-speed scanning
- Prints clean, structured results



 🚀 Features

✔ Live Host Discovery
Uses system ping to detect active IPs on the subnet.

 ✔ Multi-Threaded TCP Port Scanning
Uses ThreadPoolExecutor for maximum speed.

✔ Customizable Settings
You can easily update:
- Target subnet
- Port list
- Thread count
- Scan timeout


🧪 Example Output

Scan started: 2025-11-13 21:24:36.892
Discovering live hosts (this may use ping)...
Found 1 live hosts. Scanning ports (TCP)...
192.168.0.1 -> [80]
Scan finished: 2025-11-13 21:24:40.527
Duration: 0:00:04.527040
Screenshot 2025-11-13 211125.png

🚀 Features

>Fast multi-threaded port scanning

>Automatic live-host discovery (ping sweep)

>Scans common ports or custom port lists

>Clean, readable Python code

>Beginner-friendly project that demonstrates real network enumeration skills



How to Run

1. Make sure Python 3 is installed


2. Open a terminal in the project folder


3. Run:


python port_scanner.py

4. Edit the target subnet inside the script if needed:


TARGET = "192.168.0.0/24"


📌 Why This Project?

I built this project to strengthen my Python + networking fundamentals by applying:

Socket programming

Subnet scanning with the ipaddress module

Multi-threading for high-speed enumeration

Real-world port scanning logic

This project combines CCNA networking knowledge with Python scripting, making it a solid foundation for cybersecurity and automation work.


🤝 Contributions

This project is open for improvements.
If you have ideas to make it faster, more accurate, or feature-rich, feel free to:

Fork the repository

Improve the code

Submit a pull request



License

This project is released under the MIT License.
You are free to use, modify, and distribute it for educational and ethical purposes.

