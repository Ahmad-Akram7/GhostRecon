import subprocess
import re

def is_valid_ip_or_domain(target):
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(ip_pattern, target) or re.match(domain_pattern, target)

def run_nmap_scan(target, scan_type, ports=None):
    scan_options = {
        "ping"     : ["nmap", "-sn"],
        "syn"      : ["nmap", "-sS"],
        "udp"      : ["nmap", "-sU"],
        "version"  : ["nmap", "-sV"],
        "os"       : ["nmap", "-O"],
        "aggressive": ["nmap", "-A"]
    }

    command = scan_options.get(scan_type)
    if not command:
        print("[!] Unknown scan type. Available types: ping, syn, udp, version, os, aggressive")
        return

    command.append(target)
    if ports:
        command += ["-p", ports]

    try:
        print(f"\n[+] Running {scan_type.upper()} scan on {target}...\n")
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        filename = f"nmap_{target.replace('.', '_')}_{scan_type}.txt"
        with open(filename, "w") as f:
            f.write(result.stdout)

        print(f"[✓] Scan completed successfully. Output saved to '{filename}'\n")
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
    
    target_ip = input("👉 Enter the target IP or domain: ").strip()
    if not is_valid_ip_or_domain(target_ip):
        print("[X] Invalid IP address or domain name.")
        exit(1)

    scan_type = input("🔎 Enter scan type (ping, syn, udp, version, os, aggressive): ").strip().lower()
    custom_ports = input("🎯 Enter ports (e.g. 22,80,443) or press Enter to skip: ").strip()
    ports = custom_ports if custom_ports else None

    run_nmap_scan(target_ip, scan_type, ports)
