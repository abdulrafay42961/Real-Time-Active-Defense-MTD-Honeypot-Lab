"""
firewall.py
-----------
Thin wrapper around iptables that gives us two capabilities:

1. redirect_ip_to_honeypot(ip, real_port, honeypot_port)
   -> transparently DNATs all future packets FROM `ip` TO `real_port`
      over to `honeypot_port`. The attacker keeps talking to the same
      port number and has no way to tell the traffic is being diverted.

2. block_ip(ip)
   -> drops all traffic from that IP entirely.

Requires root privileges and a Linux host with iptables installed.
All commands are logged; if a command fails we raise so the caller
can decide how to handle it (e.g. log and continue).
"""

import subprocess
import logging

from config import REDIRECT_CHAIN, HONEYPOT_HOST

log = logging.getLogger("hds.firewall")


def _run(cmd):
    log.debug("iptables cmd: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("Command failed (%s): %s", " ".join(cmd), result.stderr.strip())
    return result


def ensure_chain():
    """Create our custom PREROUTING jump chain once, idempotent."""
    _run(["iptables", "-t", "nat", "-N", REDIRECT_CHAIN])  # ignore error if exists
    # Make sure PREROUTING jumps into our chain (only add once)
    check = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", REDIRECT_CHAIN])
    if check.returncode != 0:
        _run(["iptables", "-t", "nat", "-I", "PREROUTING", "-j", REDIRECT_CHAIN])


def redirect_ip_to_honeypot(ip, real_port, honeypot_port):
    """
    Any packet from `ip` destined for `real_port` gets DNAT'd to
    HONEYPOT_HOST:honeypot_port instead. Attacker's TCP session looks
    completely normal to them.
    """
    # Remove any previous redirect rule for this ip+real_port combo first
    clear_redirect(ip, real_port)
    _run([
        "iptables", "-t", "nat", "-A", REDIRECT_CHAIN,
        "-s", ip, "-p", "tcp", "--dport", str(real_port),
        "-j", "DNAT", "--to-destination", f"{HONEYPOT_HOST}:{honeypot_port}",
    ])
    log.info("Redirecting %s (port %s) -> honeypot port %s", ip, real_port, honeypot_port)


def clear_redirect(ip, real_port):
    _run([
        "iptables", "-t", "nat", "-D", REDIRECT_CHAIN,
        "-s", ip, "-p", "tcp", "--dport", str(real_port),
        "-j", "DNAT", "--to-destination", "0.0.0.0:0",  # best effort; harmless if not matched
    ])


def block_ip(ip):
    """Drop all inbound traffic from this IP, at the filter/INPUT level."""
    check = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if check.returncode != 0:
        _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    log.warning("IP %s permanently BLOCKED", ip)
