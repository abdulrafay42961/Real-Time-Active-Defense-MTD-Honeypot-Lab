"""
database.py
-----------
All persistent state (attempt logs, IP block list, username block list,
per-IP honeypot assignment) lives in a small SQLite database so the
system survives restarts.
"""

import sqlite3
import time
import threading
from contextlib import contextmanager

from config import DB_PATH


_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_conn():
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT,
                password TEXT,
                port INTEGER,
                source TEXT,          -- 'real' or 'honeypot'
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ip_blocklist (
                ip TEXT PRIMARY KEY,
                blocked_at REAL NOT NULL,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS username_blocklist (
                username TEXT PRIMARY KEY,
                blocked_at REAL NOT NULL,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS ip_state (
                ip TEXT PRIMARY KEY,
                current_honeypot_port INTEGER,
                redirected_at REAL,
                honeypot_fail_count INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip);
            CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts);
            """
        )


# ---------------------------------------------------------------------------
# Attempt logging
# ---------------------------------------------------------------------------
def log_attempt(ip, username, password, port, source):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO attempts (ip, username, password, port, source, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, username, password, port, source, time.time()),
        )


def get_recent_attempt_timestamps(ip, window_sec):
    cutoff = time.time() - window_sec
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ts FROM attempts WHERE ip = ? AND ts >= ? ORDER BY ts",
            (ip, cutoff),
        ).fetchall()
    return [r["ts"] for r in rows]


def count_attempts(ip, source=None):
    with get_conn() as conn:
        if source:
            row = conn.execute(
                "SELECT COUNT(*) c FROM attempts WHERE ip=? AND source=?",
                (ip, source),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) c FROM attempts WHERE ip=?", (ip,)
            ).fetchone()
    return row["c"]


def usernames_used_by_ip(ip):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT username FROM attempts WHERE ip=? AND username IS NOT NULL",
            (ip,),
        ).fetchall()
    return [r["username"] for r in rows]


# ---------------------------------------------------------------------------
# IP block list
# ---------------------------------------------------------------------------
def block_ip(ip, reason=""):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ip_blocklist (ip, blocked_at, reason) VALUES (?, ?, ?)",
            (ip, time.time(), reason),
        )


def is_ip_blocked(ip):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM ip_blocklist WHERE ip=?", (ip,)
        ).fetchone()
    return row is not None


def unblock_ip(ip):
    with get_conn() as conn:
        conn.execute("DELETE FROM ip_blocklist WHERE ip=?", (ip,))


def get_blocked_ips():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ip, blocked_at, reason FROM ip_blocklist ORDER BY blocked_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Username block list
# ---------------------------------------------------------------------------
def block_username(username, reason=""):
    if not username:
        return
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO username_blocklist (username, blocked_at, reason) VALUES (?, ?, ?)",
            (username, time.time(), reason),
        )


def is_username_blocked(username):
    if not username:
        return False
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM username_blocklist WHERE username=?", (username,)
        ).fetchone()
    return row is not None


def unblock_username(username):
    if not username:
        return
    with get_conn() as conn:
        conn.execute("DELETE FROM username_blocklist WHERE username=?", (username,))


def get_blocked_usernames():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT username, blocked_at, reason FROM username_blocklist ORDER BY blocked_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Per-IP honeypot assignment / rotation state
# ---------------------------------------------------------------------------
def get_ip_state(ip):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM ip_state WHERE ip=?", (ip,)
        ).fetchone()
    return dict(row) if row else None


def set_ip_state(ip, honeypot_port, fail_count=0):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO ip_state (ip, current_honeypot_port, redirected_at, honeypot_fail_count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                current_honeypot_port=excluded.current_honeypot_port,
                redirected_at=excluded.redirected_at,
                honeypot_fail_count=excluded.honeypot_fail_count
            """,
            (ip, honeypot_port, time.time(), fail_count),
        )


def increment_honeypot_fail_count(ip):
    with get_conn() as conn:
        conn.execute(
            "UPDATE ip_state SET honeypot_fail_count = honeypot_fail_count + 1 WHERE ip=?",
            (ip,),
        )
        row = conn.execute(
            "SELECT honeypot_fail_count FROM ip_state WHERE ip=?", (ip,)
        ).fetchone()
    return row["honeypot_fail_count"] if row else 0
