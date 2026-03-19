import subprocess
import re
import os
from datetime import datetime

# ─── Validation ────────────────────────────────────────────────────────────────

def is_valid_ip_or_domain(target):
    ip_pattern     = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(ip_pattern, target) or re.match(domain_pattern, target)

# ─── Scanner ───────────────────────────────────────────────────────────────────

def run_nmap_scan(target, scan_name, command, ports=None):
    cmd = command.copy()
    cmd.append(target)
    if ports:
        cmd += ["-p", ports]

    print(f"\n[+] Running {scan_name.upper()} scan on {target}...")
    if ports:
        print(f"[+] Port filter: {ports}")
    print()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Save to results/ folder with timestamp to avoid collisions
        os.makedirs("results", exist_ok=True)
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', scan_name.lower())
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename   = os.path.join("results", f"nmap_{target.replace('.', '_')}_{safe_name}_{timestamp}.txt")

        with open(filename, "w") as f:
            f.write(f"GhostRecon Scan Report\n")
            f.write(f"Target    : {target}\n")
            f.write(f"Scan Type : {scan_name}\n")
            f.write(f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Command   : {' '.join(cmd)}\n")
            f.write("=" * 60 + "\n\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)

        print(f"[✓] Scan complete. Results saved to: {filename}\n")
        print("─" * 60)
        print(result.stdout)

        if result.stderr:
            print("[!] Warnings/Info from Nmap:")
            print(result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"[✗] Nmap scan failed.")
        if e.stderr:
            print(f"    Error: {e.stderr.strip()}")
        print("    Tip: Some scan types (syn, os) require root — try: sudo python GhostRecon.py")
    except FileNotFoundError:
        print("[✗] Nmap not found. Install it first:")
        print("    Linux  : sudo apt install nmap")
        print("    macOS  : brew install nmap")
        print("    Windows: https://nmap.org/download.html")

# ─── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(r"""
  _____  _                    _         _   _                             _____
 / ____|(_)                  | |       | \ | |                           / ____|
| (___   _  _ __ ___   _ __  | |  ___  |  \| | _ __ ___    __ _  _ __   | (___    ___  __ _  _ __   _ __    ___  _ __
 \___ \ | || '_ ` _ \ | '_ \ | | / _ \ | . ` || '_ ` _ \  / _` || '_ \   \___ \  / __|/ _` || '_ \ | '_ \  / _ \| '__|
 ____) || || | | | | || |_) || ||  __/ | |\  || | | | | || (_| || |_) |  ____) || (__| (_| || | | || | | ||  __/| |
|_____/ |_||_| |_| |_|| .__/ |_| \___| |_| \_||_| |_| |_| \__,_|| .__/  |_____/  \___|\__,_||_| |_||_| |_| \___||_|
                      |_|                                         |_|
    """)
    print("  Beginner-friendly Nmap wrapper | Ethical use only\n")

    # Scan type definitions
    scan_types = {
        "1": ("Ping — Host Discovery",    ["nmap", "-sn"]),
        "2": ("SYN  — Stealth Scan",      ["nmap", "-sS"]),
        "3": ("UDP  — UDP Services",      ["nmap", "-sU"]),
        "4": ("Ver  — Service Versions",  ["nmap", "-sV"]),
        "5": ("OS   — OS Detection",      ["nmap", "-O"]),
        "6": ("Aggr — Aggressive (All)",  ["nmap", "-A"]),
    }

    # ── Step 1: Target ──
    while True:
        target_ip = input("👉 Enter target IP or domain: ").strip()
        if not target_ip:
            print("[!] Target cannot be empty.")
            continue
        if not is_valid_ip_or_domain(target_ip):
            print("[✗] Invalid IP or domain. Examples: 192.168.1.1 or example.com")
            continue
        break

    # ── Step 2: Scan type ──
    print("\n📡 Available scan types:")
    for key, (name, _) in scan_types.items():
        print(f"   {key}. {name}")

    while True:
        choice = input("\n🔎 Enter scan number (1–6): ").strip()
        if choice in scan_types:
            scan_name, scan_cmd = scan_types[choice]
            break
        print(f"[!] Invalid choice '{choice}'. Enter a number between 1 and 6.")

    # ── Step 3: Optional ports ──
    custom_ports = input("🎯 Ports to scan (e.g. 22,80,443) or press Enter for default: ").strip()
    ports = custom_ports if custom_ports else None

    # ── Run ──
    run_nmap_scan(target_ip, scan_name, scan_cmd, ports)
