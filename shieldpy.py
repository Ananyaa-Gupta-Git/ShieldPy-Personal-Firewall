from scapy.all import sniff, IP, TCP, UDP
import logging, os, json, subprocess, signal, sys

# === Setup logging ===
if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    filename="logs/shieldpy.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

RULES_FILE = "rules.json"
last_modified = 0
rules = {"blocked_ips": [], "allowed_ports": [], "blocked_protocols": []}

# === Load rules from JSON ===
def load_rules():
    global last_modified, rules
    try:
        mtime = os.path.getmtime(RULES_FILE)
        if mtime != last_modified:
            with open(RULES_FILE, "r") as f:
                rules = json.load(f)
            last_modified = mtime
            print("[*] Reloaded rules.json")
    except FileNotFoundError:
        pass

# === Windows Firewall Helpers ===
def add_firewall_rule(ip, proto="any"):
    rule_name = f"ShieldPy_Block_{ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", "action=block",
             f"remoteip={ip}", f"protocol={proto}"],
            capture_output=True
        )
        logging.info(f"Firewall rule added: {rule_name}")
    except Exception as e:
        logging.error(f"Failed to add firewall rule: {e}")

def delete_firewall_rules():
    """Delete all ShieldPy rules"""
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=all"],
            capture_output=True
        )
        print("[*] Cleaned up ShieldPy firewall rules")
    except Exception as e:
        print(f"[!] Failed to clean rules: {e}")

# === Handle exit cleanup ===
def handle_exit(sig, frame):
    print("\n[!] Exiting... Cleaning ShieldPy rules...")
    delete_firewall_rules()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# === Ask user for unknown connections ===
def ask_user(src_ip, dst_ip, dst_port, proto):
    print(f"\n[NEW CONNECTION] {src_ip} -> {dst_ip}:{dst_port if dst_port else 'N/A'} [{proto}]")
    choice = input("Allow (A) / Block (B)? ").strip().lower()
    if choice == "b":
        print(f"[USER BLOCKED] {dst_ip}")
        add_firewall_rule(dst_ip, proto.lower())
        logging.info(f"User blocked: {src_ip}->{dst_ip} [{proto}]")
        return False
    else:
        print(f"[USER ALLOWED] {dst_ip}")
        logging.info(f"User allowed: {src_ip}->{dst_ip} [{proto}]")
        return True

# === Packet Processing ===
def packet_callback(packet):
    load_rules()

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        dst_port = None

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        # Rule 1: Block specific IPs
        if src_ip in rules["blocked_ips"] or dst_ip in rules["blocked_ips"]:
            print(f"[BLOCKED IP] {src_ip} -> {dst_ip}")
            logging.info(f"Blocked by IP rule: {src_ip} -> {dst_ip}")
            add_firewall_rule(dst_ip)
            return

        # Rule 2: Block by Protocol
        if proto in rules.get("blocked_protocols", []):
            print(f"[BLOCKED PROTOCOL {proto}] {src_ip} -> {dst_ip}")
            logging.info(f"Blocked by protocol: {proto} {src_ip}->{dst_ip}")
            add_firewall_rule(dst_ip, proto.lower())
            return

        # Rule 3: Allow only specific ports
        if dst_port and dst_port not in rules.get("allowed_ports", []):
            print(f"[BLOCKED PORT] {src_ip} -> {dst_ip}:{dst_port}")
            logging.info(f"Blocked by port rule: {src_ip} -> {dst_ip}:{dst_port}")
            add_firewall_rule(dst_ip)
            return

        # === NEW: Interactive Mode for unknown traffic ===
        if not ask_user(src_ip, dst_ip, dst_port, proto):
            return

        # Otherwise Allowed
        print(f"[ALLOWED] {src_ip} -> {dst_ip}:{dst_port if dst_port else 'N/A'}")
        logging.info(f"Allowed: {src_ip}->{dst_ip}:{dst_port if dst_port else 'N/A'}")

# === Start ===
print("[*] ShieldPy started (Windows firewall enforcement + Interactive Mode)...")
print("[*] Press CTRL+C to stop and auto-clean rules")
sniff(prn=packet_callback, store=False)
