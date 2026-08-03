# 🛡️ Honeypot Deception System (HDS)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Ubuntu-orange.svg)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/type-Active%20Defense-red.svg)](#)

A high-performance, **Python-based active defense & deception architecture** designed to safeguard production services (e.g., OpenSSH) against automated brute-force attacks by dynamically rerouting malicious actors into a multi-port honeypot cluster.

---

## 🌟 Key Architecture & Capabilities

* **🐝 18-Port Decoy Cluster:** Spawns asynchronous honeypot listeners across common service ports (FTP, SSH, Telnet, SMTP, MySQL, RDP, Redis, MongoDB, etc.) as defined in `config.py`[cite: 2, 3].
* **👁️ Dynamic Service Guard (`log_watcher.py`):** Real-time tailing of host log files (e.g., `/var/log/auth.log`)[cite: 2, 3]. Upon hitting **5 failed attempts**, the system silently diverts traffic via `iptables DNAT` to a honeypot—keeping the attacker unaware of the transition[cite: 2, 3].
* **🔄 Silent Honeypot Rotation:** Automatically rotates connection targets across secondary honeypots after **10 failed attempts** within a decoy environment.
* **🚫 Targeted User Blacklisting:** Any username targeted by an attacking host—whether against real or fake endpoints—is permanently recorded and restricted[cite: 2, 3].
* **⚡ Automated Bot & Tool Detection (`detector.py`):** Instantly flags high-velocity attacks (e.g., 4+ attempts within 5 seconds) and triggers defensive rotation without waiting for standard attempt thresholds[cite: 2, 3].
* **💥 Network-Level Mitigation:** Reaching the maximum total limit (`block_after_total_attempts: 15`) triggers a permanent `iptables DROP` rule to instantly sever connection at the transport layer[cite: 2, 3].

---

## 📁 Repository Structure

```text
├── ⚙️ config.py           # Global configurations, thresholds, and decoy ports[cite: 2, 3]
├── 🗄️ database.py         # SQLite persistence for attempt tracking & blocklists[cite: 2, 3]
├── 🧱 firewall.py         # Low-level iptables wrapper (DNAT redirect & DROP rules)[cite: 2, 3]
├── 🎯 detector.py         # Velocity and timing analysis engine for bot detection[cite: 2, 3]
├── 🍯 honeypot_server.py # Asyncio multi-protocol decoy server implementation[cite: 2, 3]
├── 👁️ log_watcher.py      # Real-time native auth log parser daemon[cite: 2, 3]
├── 🧠 coordinator.py      # Core orchestration and decision logic engine[cite: 3]
└── 🚀 main.py             # Master system bootstrap entry point[cite: 2, 3]
PrerequisitesOperating System: Linux (Ubuntu / Debian recommended)  Privileges: root access (required for socket binding <1024 and iptables rule manipulation)[cite: 2, 3]Bash# 1. Install system dependencies
sudo apt-get update && sudo apt-get install iptables -y

# 2. Clone the repository
git clone [https://github.com/your-username/honeypot-deception-system.git](https://github.com/your-username/honeypot-deception-system.git)
cd honeypot-deception-system

# 3. Configure parameters (Optional)
# Edit config.py to adjust paths like REAL_SERVICE["log_path"] or THRESHOLDS[cite: 2, 3]

# 4. Launch the engine
sudo python3 main.py
🧪 Local Testing (Non-Root / Sandbox Mode)If you want to evaluate socket capturing capabilities without manipulating firewall rules or acquiring root privileges:Bashpython3 -c "
import asyncio, honeypot_server

async def fake_attempt(ip, u, p, port):
    print('CAPTURED:', ip, u, p, port)

async def run():
    servers = await honeypot_server.start_all_honeypots({2121:'ftp', 2222:'ssh'}, fake_attempt)
    await asyncio.gather(*[s.serve_forever() for s in servers])

asyncio.run(run())
"
In a second terminal, send test traffic:Bashftp localhost 2121
# OR
telnet localhost 2222
