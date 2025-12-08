***GhostRecon***
***Beginner-friendly automated Nmap scanning tool** for ethical hacking, penetration testing, and reconnaissance.  
Run powerful Nmap scans with a single command (no prior experience required).

***What is GhostRecon?***

`GhostRecon` is a Python-based wrapper around Nmap that streamlines essential network scans like:

- Ping Sweep
- SYN Scan
- UDP Scan
- Version Detection
- OS Detection
- Aggressive Scan (combined techniques)

Perfect for cybersecurity learners, CTF players, bug bounty beginners, and sysadmins who want quick insights with minimal commands.

## 📸 Screenshot

![GhostRecon Preview](ghostrecon-preview.png)

### ✨ Features
- **Supports multiple scan types**: `ping`, `syn`, `udp`, `version`, `os`, and `aggressive`
- **Smart input validation** for IPs/domains
- **Saves scan results** in organized `.txt` files
- **Python-powered CLI interface** — clean and interactive
- **Beginner-friendly** — no need to memorize Nmap commands
- Works on **Linux**, **macOS**, and **Windows (via WSL)**

## 🚀 Getting Started

### 🧰 Requirements
- Python 3.6 or higher
- Nmap installed on your system (GhostRecon is a wrapper around Nmap)

**Install Nmap:**
```bash
# For Debian/Ubuntu
sudo apt update && sudo apt install nmap

# For macOS (using Homebrew)
brew install nmap

# For Windows
# Download the official installer from nmap.org/download.html
```

### 💻 Installation (Clone and Setup)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Ahmad-Akram7/GhostRecon.git
    cd GhostRecon
    ```
2.  **Install Python Dependencies (Optional):**
    This project primarily uses standard Python libraries. If `requirements.txt` contains any entries in the future, install them:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: Currently, `requirements.txt` is empty as only built-in Python modules are used.)*

### 👟 Usage

#### Using `GhostRecon.py` (Basic Scans)

This script offers a straightforward interactive interface for common Nmap scans.

**Example:**
```bash
python GhostRecon.py
```
Follow the prompts to enter the target IP/domain and select a scan type.

#### Using `nmapscanner.py` (Advanced Interactive Scans)

`nmapscanner.py` provides a more advanced and interactive command-line interface with 12 selectable scan types, timestamped output files, and a cleaner user experience.

**Example:**
```bash
python nmapscanner.py
```
Follow the interactive menu to choose from various scan modes:

**Available Scan Types in `nmapscanner.py`:**
1.  **Ping (port availability):** ICMP echo to check if the host is up (no port scan).
2.  **SYN (Stealth Scan):** Stealth SYN scan (half-open TCP handshake).
3.  **UDP (Open UDP services):** UDP scan.
4.  **Version (Service Versions):** Detect service versions.
5.  **OS (OS Detection):** OS fingerprinting.
6.  **Aggressive (All of them):** Combination scan including OS detection, version detection, script scanning, and traceroute.
7.  **Stealth (Stealthier):** SYN scan with no ping (`-sS -Pn`).
8.  **Full TCP:** Full TCP connect scan (`-sT`).
9.  **Slow (Evade Detection):** Slower stealth scan with timing template (`-sS -T2 -Pn`).
10. **No Ping (Skip Ping):** No host discovery (`-Pn`).
11. **Traceroute (Shows Path):** Traceroute to target (`--traceroute`).
12. **Top Ports (Top 100 Ports):** Scans the top 100 most common ports (`--top-ports 100`).

## 🤝 Contributing

Contributions are welcome! If you find a bug, have an idea for an improvement, or want to add more scan types, please feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🏷️ GitHub Topics (for Discoverability)

To improve the visibility and searchability of this repository on GitHub, it is highly recommended to add the following topics via your repository settings:
- `nmap`
- `ethical-hacking`
- `penetration-testing`
- `reconnaissance`
- `cybersecurity`
- `python`
- `network-scanning`
- `security-tools`
- `beginner-friendly`
- `nmap-wrapper`
- `automation`