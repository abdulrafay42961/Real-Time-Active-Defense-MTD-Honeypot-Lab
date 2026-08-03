# Honeypot Deception System (HDS)

Ek Python-based deception/defense system jo real service (masalan SSH)
ko brute-force se bachata hai using a cluster of 18 honeypots on
well-known ports.

## Kya karta hai

1. **18 honeypots** well-known ports par (FTP, SSH, Telnet, SMTP, MySQL,
   RDP, Redis, MongoDB, etc.) — `config.py` mein `HONEYPOT_PORTS`.
2. **Real service monitor** (`log_watcher.py`) — asli SSH service ke
   `/var/log/auth.log` ko tail karta hai. 5 galat attempts par attacker
   ko iptables `DNAT` se silently kisi honeypot par redirect kar deta hai
   — attacker ko pata nahi chalta, wo wahi port (22) use kar raha
   samajhta hai.
3. Usi honeypot par 10 galat attempts → doosre honeypot par silently
   rotate.
4. Har username jo malicious IP ne kahin bhi (real ya honeypot) try
   kiya, wo permanently block ho jata hai.
5. **Tool detection** (`detector.py`) — agar IP se 5 second ke andar 4+
   attempts aayen (script/tool ka pattern), to full count ka wait kiye
   bagair hi turant redirect/rotate trigger ho jata hai.
6. Total attempts (real + honeypot mila kar) `block_after_total_attempts`
   (default 15) cross karne par IP ko permanently `iptables DROP` kar
   diya jata hai.

## Files

| File | Kaam |
|---|---|
| `config.py` | Sab thresholds, ports, paths yahan configure karo |
| `database.py` | SQLite state (attempts, blocklists, per-IP rotation state) |
| `firewall.py` | iptables DNAT redirect + IP DROP wrapper |
| `detector.py` | Timing-based automated-tool detection |
| `honeypot_server.py` | asyncio multi-protocol fake service listener |
| `log_watcher.py` | Real SSH service ke logs tail karta hai |
| `coordinator.py` | Poori decision logic (redirect/rotate/block) |
| `main.py` | Entry point — sab kuch start karta hai |

## Setup

```bash
# Linux (Ubuntu/Debian tested), root required for:
#  - privileged ports (<1024) binding
#  - iptables rule management
sudo apt-get install iptables

# config.py mein apni environment ke hisaab se adjust karo:
#  - REAL_SERVICE["log_path"]  (Ubuntu: /var/log/auth.log, RHEL: /var/log/secure)
#  - HONEYPOT_HOST             (agar honeypots kisi doosre VM/container par hain)
#  - THRESHOLDS                (apni policy ke hisaab se)

sudo python3 main.py
```

## ⚠️ Important limitations / real-world notes

- **SSH honeypot simplified hai**: asli SSH crypto handshake (key exchange
  waghera) implement nahi kiya — sirf banner + credential capture hai.
  Production-grade SSH honeypot ke liye **Cowrie** project consider karo,
  ya `asyncssh` library se full protocol implement karo.
- **iptables rules root ke bina kaam nahi karengi.** Container ya
  restricted environment mein test karne ke liye pehle
  `NET_ADMIN` capability chahiye hogi.
- Ye system **defensive/deception** tool hai — kisi bhi system par sirf
  apne khud ke infrastructure par test/deploy karo. Kisi third-party
  network par bagair authorization test karna illegal hai.
- Log-format regex (`log_watcher.py`) sirf standard Ubuntu `sshd` format
  ke liye hai. Agar tum koi doosri service (FTP, RDP, web login) protect
  kar rahe ho, us service ke log format ke hisaab se
  `FAILED_PATTERNS` update karo.
- `firewall.clear_redirect()` best-effort hai (iptables rule delete
  exact match maangta hai) — production mein rule IDs track karna
  behtar hoga agar bohot zyada IPs handle karni hon.

## Testing locally (bina root/iptables)

Agar sirf honeypot logging test karni ho (firewall ke bagair):

```bash
python3 -c "
import asyncio, honeypot_server

async def fake_attempt(ip, u, p, port):
    print('CAPTURED:', ip, u, p, port)

async def run():
    servers = await honeypot_server.start_all_honeypots({2121:'ftp', 2222:'ssh'}, fake_attempt)
    await asyncio.gather(*[s.serve_forever() for s in servers])

asyncio.run(run())
"
```
Phir doosri terminal se: `ftp localhost 2121` ya `telnet localhost 2222`
karke dekho attempts capture hote hain.
