"""
Configuration for the Honeypot Deception System (HDS)
--------------------------------------------------------
Edit these values to match your environment before running main.py
"""

# ---------------------------------------------------------------------------
# Honeypot ports -> service type emulated on that port
# (18 entries -> satisfies the "15 to 20 honeypots" requirement)
# ---------------------------------------------------------------------------
HONEYPOT_PORTS = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    110:  "pop3",
    143:  "imap",
    445:  "smb",
    993:  "imaps",
    995:  "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    27017: "mongodb",
}

# ---------------------------------------------------------------------------
# The REAL service you are protecting.
# HDS watches its auth log for failed-login lines.
# ---------------------------------------------------------------------------
REAL_SERVICE = {
    "name": "ssh",
    "port": 22,
    # Debian/Ubuntu -> /var/log/auth.log
    # RHEL/CentOS   -> /var/log/secure
    "log_path": "/var/log/auth.log",
}

# ---------------------------------------------------------------------------
# Thresholds (tune to taste)
# ---------------------------------------------------------------------------
THRESHOLDS = {
    # attempts on the REAL service before we silently reroute the attacker
    "real_service_fail_limit": 5,

    # attempts on ONE honeypot before we rotate the attacker to another
    "honeypot_fail_limit": 10,

    # if an IP fires >= tool_detection_attempts within this many seconds,
    # we treat it as an automated brute-force tool (fast, mechanical timing)
    "tool_detection_window_sec": 5,
    "tool_detection_attempts": 4,

    # total malicious attempts (real + honeypots combined) before a
    # permanent firewall DROP of the IP
    "block_after_total_attempts": 15,
}

DB_PATH = "hds_state.db"

# "iptables" or "nftables" - only iptables backend is implemented below,
# nftables left as a stub you can extend the same way.
FIREWALL_BACKEND = "iptables"

# Name of the internal chain HDS creates/uses for redirection rules
REDIRECT_CHAIN = "HDS_REDIRECT"

# The internal IP:port pool of honeypots that real DNAT rules point to.
# Usually 127.0.0.1 if honeypots run on the same box, or a dedicated
# honeypot VM/container IP in a real deployment.
HONEYPOT_HOST = "127.0.0.1"
