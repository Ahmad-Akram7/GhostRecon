import subprocess
import re
from datetime import datetime

def is_valid_ip_or_domain(target):
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(ip_pattern, target) or re.match(domain_pattern, target)

def run_nmap_scan(target, scan_name, command, ports=None):
    cmd = command.copy()
    cmd.append(target)
    if ports:
        cmd += ["-p", ports]

    try:
        print(f"\n[+] Running {scan_name.upper()} scan on {target}...\n")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Safe file name generation
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', scan_name.lower())
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nmap_{target.replace('.', '_')}_{safe_name}_{timestamp}.txt"

        with open(filename, "w") as f:
            f.write(result.stdout)

        print(f"[✓] Scan completed successfully. Output saved to '{filename}'")
        print("\n📄 Scan output:\n")
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"[X] Error running Nmap scan:\n{e.stderr}")

if __name__ == "__main__":
    print(r"""
  _____  _                    _         _   _                             _____
 / ____|(_)                  | |       | \ | |                           / ____|
| (___   _  _ __ ___   _ __  | |  ___  |  \| | _ __ ___    __ _  _ __   | (___    ___  __ _  _ __   _ __    ___  _ __
 \___ \ | || '_ ` _ \ | '_ \ | | / _ \ | . ` || '_ ` _ \  / _` || '_ \   \___ \  / __|/ _` || '_ \ | '_ \  / _ \| '__|
 ____) || || | | | | || |_) || ||  __/ | |\  || | | | | || (_| || |_) |  ____) || (__| (_| || | | || | | ||  __/| |
|_____/ |_||_| |_| |_|| .__/ |_| \___| |_| \_||_| |_| |_| \__,_|| .__/  |_____/  \___|\__,_||_| |_||_| |_| \___||_|
                     | |                                       | |
                     |_|                                       |_|
    """)

    # Dictionary of scan types with descriptions
    scan_types = {
        "1":  ("Ping(port availability)",       ["nmap", "-sn"]),                     # ICMP echo to check if host is up (no port scan)
        "2":  ("SYN(Stealth Scan)",             ["nmap", "-sS"]),                     # Stealth SYN scan (half-open TCP handshake)
        "3":  ("UDP(Open UDP services)",        ["nmap", "-sU"]),                     # UDP scan
        "4":  ("Version(Service Versions)",     ["nmap", "-sV"]),                     # Detect service versions
        "5":  ("OS(OS Detection)",              ["nmap", "-O"]),                      # OS fingerprinting
        "6":  ("Aggressive(All of them)",       ["nmap", "-A"]),                      # Combo scan
        "7":  ("Stealth(Stealthier)",           ["nmap", "-sS", "-Pn"]),              # SYN + No Ping
        "8":  ("Full TCP",                      ["nmap", "-sT"]),                     # Full TCP connect scan
        "9":  ("Slow(Evade Detection)",         ["nmap", "-sS", "-T2", "-Pn"]),       # Slow stealth scan
        "10": ("No Ping(Skip Ping)",            ["nmap", "-Pn"]),                     # No host discovery
        "11": ("Traceroute(Shows Path)",        ["nmap", "--traceroute"]),            # Traceroute to target
        "12": ("Top Ports(Top 100 Ports)",      ["nmap", "--top-ports", "100"])       # Scan top 100 common ports
    }

    # Get target input
    target_ip = input("👉 Enter the target IP or domain: ").strip()
    if not is_valid_ip_or_domain(target_ip):
        print("[X] Invalid IP address or domain name.")
        exit(1)

    # Display scan options
    print("\n🧪 Available scan types:")
    for key, (name, _) in scan_types.items():
        print(f"  {key}. {name}")

    # Get scan type choice
    while True:
        choice = input("\n🔎 Enter the number of the scan type you want: ").strip()
        if choice in scan_types:
            scan_name, scan_cmd = scan_types[choice]
            break
        print("[!] Invalid choice. Please enter a valid number from the list above.")

    # Get ports (optional)
    custom_ports = input("🎯 Enter ports (e.g. 22,80,443) or press Enter to scan default ports: ").strip()
    ports = custom_ports if custom_ports else None

    # Run scan
    run_nmap_scan(target_ip, scan_name, scan_cmd, ports)
