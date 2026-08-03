"""
log_watcher.py
--------------
Tails the REAL service's auth log (e.g. /var/log/auth.log for sshd)
and extracts failed-login events (ip, username), forwarding them to
the coordinator. This is the same technique fail2ban uses.

If you're protecting a service other than SSH, adjust FAILED_PATTERNS
to match that service's log format.
"""

import asyncio
import re
import logging

log = logging.getLogger("hds.logwatcher")

# sshd failed-password / invalid-user log line patterns (Debian/Ubuntu format)
FAILED_PATTERNS = [
    re.compile(
        r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
    ),
    re.compile(
        r"authentication failure;.*rhost=(?P<ip>[\d.]+).*user=(?P<user>\S+)"
    ),
]


async def tail_file(path):
    """Async generator yielding new lines appended to `path`, like `tail -F`."""
    proc = await asyncio.create_subprocess_exec(
        "tail", "-n", "0", "-F", path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        yield line.decode(errors="ignore").rstrip("\n")


def parse_failed_login(line):
    for pattern in FAILED_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group("ip"), m.group("user")
    return None, None


async def watch_real_service(log_path, on_failed_login):
    """
    on_failed_login: async callback(ip, username)
    """
    log.info("Watching real-service log: %s", log_path)
    try:
        async for line in tail_file(log_path):
            ip, username = parse_failed_login(line)
            if ip:
                await on_failed_login(ip, username)
    except FileNotFoundError:
        log.error(
            "Log file %s not found. Check config.REAL_SERVICE['log_path'] "
            "for your distro (auth.log vs secure).",
            log_path,
        )
