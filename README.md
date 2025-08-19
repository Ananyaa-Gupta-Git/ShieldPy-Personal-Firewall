🛡️ **ShieldPy - Personal Firewall for Windows**

ShieldPy is a custom personal firewall built in Python for Windows systems.
It monitors and filters network traffic in real-time, applies customizable security rules, and integrates with Windows Firewall to dynamically block malicious traffic.
The project also includes a Flask-based dashboard to visualize traffic stats, logs, and manage firewall rules interactively.


📌 **Why ShieldPy?**

Firewalls are a core concept in cybersecurity. While enterprise firewalls are complex, this project demonstrates:

Low-level network monitoring with Python (scapy)

Rule-based filtering (IP, Ports, Protocols)

Integration with OS-level firewalls (Windows netsh advfirewall)

Live dashboards for security visibility

Hands-on cybersecurity + Python development skills

This project serves as both an educational tool and a resume-ready showcase.


🚀 **Features**

✅ Packet Sniffing (scapy)

Captures incoming/outgoing packets in real-time

Extracts source/destination IP, ports, and protocol

✅ Rule-Based Blocking

Block traffic by IP address

Block traffic by Protocol (TCP/UDP/ICMP)

Allow only specific Ports (default: 80, 443, 22)

✅ Interactive Mode

For unknown connections, ShieldPy asks:

New connection: 192.168.1.5 -> 142.250.183.78:443
Allow (A) / Block (B)?


✅ Windows Firewall Integration

Blocks IPs using netsh advfirewall

Rules persist until manually removed

✅ Web Dashboard (Flask + Chart.js)

Live pie chart of allowed vs blocked traffic

Live logs of all connections

Rule management panel to add/remove rules directly in browser

✅ Logging & Auditing

All events stored in logs/shieldpy.log

Supports review for suspicious activity

📂 **Project Structure**

ShieldPy/

│── shieldpy.py       # Main firewall script (packet sniffer + rule engine)

│── dashboard.py         # Flask web dashboard

│── rules.json           # Configurable rules (auto-reload on changes)

│── requirements.txt     # Dependencies

│── /logs/

    └── shieldpy.log   # Log file (auto-generated)

│── /templates/

    └── index.html     # Dashboard frontend (Chart.js + JS)

│── README.md            # Documentation


⚙️ *Installation*

**1. Clone the Repository**
   
git clone https://github.com/YOUR_USERNAME/ShieldPy-Personal-Firewall.git
cd ShieldPy-Personal-Firewall

**2. Install Dependencies**
   
pip install -r requirements.txt

**3. Run Firewall (Requires Admin Rights)**

python shieldpy.py

**4. Run Dashboard (In another terminal)**
   
python dashboard.py

**5. Open Dashboard**


Visit 👉 http://127.0.0.1:5000

📜 Example rules.json
{
  "blocked_ips": [
    "8.8.8.8",
    "157.240.239.60"
  ],
  "allowed_ports": [
    80,
    443,
    22
  ],
  "blocked_protocols": [
    "ICMP"
  ]
}

blocked_ips → Any traffic to/from these IPs is blocked

allowed_ports → Only listed ports are allowed (default: HTTP, HTTPS, SSH)

blocked_protocols → Entire protocols can be blocked (e.g., ICMP blocks ping)


📊 **Dashboard Features**

Traffic Stats

Pie chart: Allowed vs Blocked traffic

Logs

Live logs of allowed/blocked packets

Rule Management

Add/remove IPs, Ports, Protocols via web form

No need to manually edit rules.json


🔮 **Future Enhancements**

🔗 **Threat Intelligence Integration**
Fetch malicious IPs from AbuseIPDB

 or AlienVault OTX
 
Auto-update rules.json


📈 **Traffic Trends**

Add line chart for packets over time


📂 **Report Export**

Save logs as CSV/HTML for security review


🌍 **Cross-platform Support**

Extend to Linux (iptables) and MacOS (pfctl)


🎓**Learning Outcomes**

By building ShieldPy, I learned:

Python networking with scapy

Real-world firewall design principles

Integrating Python with Windows system commands

Developing Flask dashboards for cybersecurity projects

Logging, auditing, and real-time monitoring


🛠️ **Tech Stack**

Python → Core development

Scapy → Packet sniffing & parsing

Flask → Web dashboard backend

Chart.js → Traffic visualization

Windows Firewall (netsh) → OS-level enforcement


👩‍💻 Author
**Ananyaa Gupta**

🔗 **LinkedIn**-*https://www.linkedin.com/in/ananyaa--gupta/*

🐙 **GitHub**-*https://github.com/Ananyaa-Gupta-Git*

⚠️ Disclaimer: This project is for educational purposes only.
Running ShieldPy with administrator privileges can affect system networking. Use responsibly.
