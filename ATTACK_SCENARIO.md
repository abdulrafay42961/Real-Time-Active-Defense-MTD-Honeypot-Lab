# Real-Time Attack Scenario & Proof of Concept (PoC)

This document outlines the step-by-step attack simulation, threat detection, dynamic rerouting (Moving Target Defense), and active defense mitigation implemented by the Honeypot Deception System (HDS).

---

## 1. Network Topology & Lab Setup

| Role | Machine / OS | IP Address | Tools / Services Used |
| :--- | :--- | :--- | :--- |
| **Attacker** | Kali Linux | `192.168.189.129` | THC-Hydra v9.7, `rockyou.txt`, OpenSSH client |
| **Defender Host** | Ubuntu Server 22.04 | `192.168.189.136` | OpenSSH (`/var/log/auth.log`), HDS (`main.py`), `iptables` |
| **Internal Target** | Decoy Cluster (Local) | `127.0.0.1` | 18 Fake Asyncio Listener Ports (21, 23, 8080, etc.) |

---

## 2. Attack Lifecycle & Active Mitigation Workflow

```text
[Attacker: Kali Linux (192.168.189.129)] 
         │
         │ (1) Brute-Force Attack on SSH Port 22
         ▼
[Ubuntu Server: Real SSH Port 22] ────► [/var/log/auth.log]
                                                │
                                                │ (2) Tailed by log_watcher.py
                                                ▼
                                        [HDS Coordinator & Detector]
                                                │
                                                │ (3) Threshold / Heuristic Breach Detected
                                                ▼
                                        [firewall.py: iptables DNAT]
                                                │
   ┌────────────────────────────────────────────┴────────────────────────────────────────────┐
   │ Transparent Redirection                                                                 │
   ▼                                                                                         ▼
[Honeypot Decoy 1 (e.g., Port 2121)] ──► 10 Failures ──► [Honeypot Decoy 2 (e.g., Port 2222)]
   │                                                                                         │
   └────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │ (4) Exceeded 15 Total Attempts
                                                ▼
                                     [iptables INPUT DROP]
                                   (Attacker Socket Terminated)
3. Step-by-Step Execution Breakdown
Phase 1: Reconnaissance & Initial SSH Brute-Force
The attacker initiates an automated brute-force attack against the host's real SSH service using THC-Hydra from Kali Linux:

hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.189.136 -t 4
3. Step-by-Step Execution Breakdown
Phase 1: Reconnaissance & Initial SSH Brute-Force
The attacker initiates an automated brute-force attack against the host's real SSH service using THC-Hydra from Kali Linux:

Bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.189.136 -t 4
Phase 2: Active Monitoring & Heuristic Detection
log_watcher.py continuously tails /var/log/auth.log in real-time using regex pattern matching.

detector.py evaluates attempt frequency. If 4 or more attempts occur within 5 seconds, it instantly flags the traffic as an automated brute-force script, bypassing standard threshold delays.

Phase 3: Moving Target Defense (MTD) Rerouting
Once the threshold (5 failed SSH attempts) or automated tool signature is breached:

coordinator.py selects a target decoy port from the 18 active decoy services.

firewall.py injects an iptables NAT rule:

Bash
iptables -t nat -A HDS_REDIRECT -s 192.168.189.129 -p tcp --dport 22 -j DNAT --to-destination 127.0.0.1:<honeypot_port>
The attacker remains completely unaware; their active TCP stream is transparently shifted away from the genuine SSH service onto the fake honeypot listener.

Phase 4: Honeypot Trapping & Decoy Hopping
The attacker continues guessing credentials against the decoy protocol listener.

honeypot_server.py logs all captured credentials (username, password, source_ip, timestamp) into hds_state.db.

If the attacker performs 10 consecutive failed attempts on one decoy port, coordinator.py transparently rotates them to another decoy port.

Phase 5: Absolute Isolation (Permanent DROP)
When total malicious attempts cross the threshold of 15 attempts:

Bash
iptables -I INPUT -s 192.168.189.129 -j DROP
The IP is permanently blocked at Layer 4. Hydra execution freezes with socket timeouts.

All usernames attempted by this attacker IP are automatically appended to the global username blocklist.

4. System Configuration & Threshold Matrix
Parameter Key	Value	Description / Security Impact
real_service_fail_limit	5 attempts	Failed attempts on REAL SSH port 22 before triggering transparent honeypot DNAT redirection.
honeypot_fail_limit	10 attempts	Failed attempts on a single decoy port before rotating the attacker to a new honeypot port.
tool_detection_window_sec	5 seconds	Time window analyzed by detector.py for high-frequency request clustering.
tool_detection_attempts	4 attempts	Minimum attempts within window required to instantly classify traffic as an automated tool.
block_after_total_attempts	15 attempts	Total cumulative attempts (Real + Honeypots) required for permanent iptables DROP.
5. Administrative Audit & Management (admin.py)
The admin.py CLI engine provides real-time audit capabilities and manual remediation options for security administrators:

python3 admin.py list: Displays all currently blocked IP addresses and banned usernames alongside timestamps and violation reasons.

python3 admin.py unblock-ip <ip>: Removes the specified IP address from the database blocklist and firewall rules.

python3 admin.py unblock-username <user>: Removes a restricted username from the global blocklist.

python3 admin.py block-ip <ip>: Manually forces an immediate Layer 4 DROP for the specified IP address.
