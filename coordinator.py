"""
coordinator.py
---------------
This is where the actual decision logic lives, matching the flow you
described:

  Real service (e.g. SSH, port 22):
    - 5 failed attempts on the REAL port -> silently DNAT-redirect that
      IP to a random honeypot. Attacker keeps hitting "port 22" but is
      actually now talking to a honeypot.

  Honeypot cluster:
    - 10 failed attempts on the SAME honeypot -> rotate the IP to a
      different honeypot (new DNAT target), still transparent.
    - Every username seen from a malicious IP, across any honeypot,
      gets added to the username blocklist.
    - If total attempts (real + honeypot) cross block_after_total_attempts
      -> permanent iptables DROP of the IP.

  Automated-tool shortcut:
    - If timing analysis (detector.py) flags the IP as a scripted tool
      (many attempts in a very short window), we skip straight to the
      "redirect / rotate" action even if the raw attempt count hasn't
      hit the normal threshold yet.
"""

import asyncio
import logging
import random

import database
import detector
import firewall
from config import HONEYPOT_PORTS, REAL_SERVICE, THRESHOLDS

log = logging.getLogger("hds.coordinator")


def _pick_new_honeypot(exclude_port=None):
    candidates = [p for p in HONEYPOT_PORTS if p != exclude_port]
    return random.choice(candidates)


def _maybe_block_username(ip):
    """Any username this IP has tried anywhere becomes blocked."""
    for uname in database.usernames_used_by_ip(ip):
        if uname and not database.is_username_blocked(uname):
            database.block_username(uname, reason=f"used by malicious IP {ip}")
            log.warning("Username '%s' blocked (seen from %s)", uname, ip)


def _maybe_block_ip(ip):
    total = database.count_attempts(ip)
    if total >= THRESHOLDS["block_after_total_attempts"] and not database.is_ip_blocked(ip):
        database.block_ip(ip, reason="exceeded total attempt threshold")
        firewall.block_ip(ip)
        _maybe_block_username(ip)
        log.warning("IP %s permanently blocked after %s total attempts", ip, total)
        return True
    return False


# ---------------------------------------------------------------------------
# Handler for failures on the REAL protected service (from log_watcher.py)
# ---------------------------------------------------------------------------
async def handle_real_service_failure(ip, username):
    if database.is_ip_blocked(ip):
        return  # already fully blocked, nothing to do

    database.log_attempt(ip, username, None, REAL_SERVICE["port"], source="real")

    fail_count = database.count_attempts(ip, source="real")
    tool_flag = detector.is_automated_tool(ip)

    if fail_count >= THRESHOLDS["real_service_fail_limit"] or tool_flag:
        honeypot_port = _pick_new_honeypot()
        firewall.redirect_ip_to_honeypot(ip, REAL_SERVICE["port"], honeypot_port)
        database.set_ip_state(ip, honeypot_port, fail_count=0)
        reason = "automated tool detected" if tool_flag else f"{fail_count} failed attempts"
        log.info(
            "IP %s -> redirected from real port %s to honeypot port %s (%s)",
            ip, REAL_SERVICE["port"], honeypot_port, reason,
        )

    _maybe_block_ip(ip)


# ---------------------------------------------------------------------------
# Handler for attempts captured by a honeypot (from honeypot_server.py)
# ---------------------------------------------------------------------------
async def handle_honeypot_attempt(ip, username, password, honeypot_port):
    if database.is_ip_blocked(ip):
        return

    if username and database.is_username_blocked(username):
        # Known-bad username re-appearing -> escalate immediately
        firewall.block_ip(ip)
        database.block_ip(ip, reason=f"blocked username '{username}' reused")
        log.warning("IP %s blocked instantly: reused blocked username '%s'", ip, username)
        return

    database.log_attempt(ip, username, password, honeypot_port, source="honeypot")

    state = database.get_ip_state(ip)
    if state is None or state["current_honeypot_port"] != honeypot_port:
        # First time we're seeing this ip on this honeypot in our state table
        database.set_ip_state(ip, honeypot_port, fail_count=1)
        fail_count = 1
    else:
        fail_count = database.increment_honeypot_fail_count(ip)

    tool_flag = detector.is_automated_tool(ip)

    if fail_count >= THRESHOLDS["honeypot_fail_limit"] or tool_flag:
        new_port = _pick_new_honeypot(exclude_port=honeypot_port)
        # Redirect from the OLD honeypot port to the NEW one, using the
        # same DNAT mechanism, so the attacker's traffic keeps moving
        # between honeypots without ever knowing.
        firewall.redirect_ip_to_honeypot(ip, honeypot_port, new_port)
        database.set_ip_state(ip, new_port, fail_count=0)
        reason = "automated tool detected" if tool_flag else f"{fail_count} failed attempts"
        log.info(
            "IP %s -> rotated from honeypot %s to honeypot %s (%s)",
            ip, honeypot_port, new_port, reason,
        )

    _maybe_block_username(ip)
    _maybe_block_ip(ip)
