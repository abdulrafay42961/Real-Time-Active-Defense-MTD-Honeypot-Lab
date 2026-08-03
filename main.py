"""
main.py
-------
Entry point for the Honeypot Deception System (HDS).

Run as root (needed for iptables rules and binding privileged ports):

    sudo python3 main.py

What it does:
  1. Initializes the SQLite state database.
  2. Sets up the iptables redirect chain.
  3. Starts 15-20 honeypot listeners on well-known ports.
  4. Starts a log watcher tailing the REAL service's auth log.
  5. Wires both into coordinator.py, which implements the
     redirect / rotate / block decision logic.
"""

import asyncio
import logging
import sys

import database
import firewall
import coordinator
from config import HONEYPOT_PORTS, REAL_SERVICE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("hds.main")

from honeypot_server import start_all_honeypots
from log_watcher import watch_real_service


async def on_honeypot_attempt(ip, username, password, port):
    await coordinator.handle_honeypot_attempt(ip, username, password, port)


async def on_real_service_failure(ip, username):
    await coordinator.handle_real_service_failure(ip, username)


async def main():
    log.info("Starting Honeypot Deception System")
    log.info("Honeypot count: %d", len(HONEYPOT_PORTS))

    database.init_db()
    firewall.ensure_chain()

    servers = await start_all_honeypots(HONEYPOT_PORTS, on_honeypot_attempt)
    if not servers:
        log.error("No honeypots could bind. Are you running as root?")
        sys.exit(1)

    log_watch_task = asyncio.create_task(
        watch_real_service(REAL_SERVICE["log_path"], on_real_service_failure)
    )

    log.info("HDS is live. Protecting %s on port %s.", REAL_SERVICE["name"], REAL_SERVICE["port"])

    # Keep everything alive
    await asyncio.gather(log_watch_task, *[s.serve_forever() for s in servers])


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down HDS.")
