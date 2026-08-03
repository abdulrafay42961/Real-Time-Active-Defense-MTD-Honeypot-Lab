"""
honeypot_server.py
-------------------
Lightweight asyncio TCP listener that emulates simple login banners for
common services (SSH, FTP, Telnet, MySQL, etc). It never grants real
access -- every credential is captured and always "rejected" (or, in the
case of SSH, the connection is dropped after the banner, since a fully
correct SSH protocol handshake requires a real crypto library like
asyncssh -- this simplified banner is enough to capture scanner/brute
force attempts, which is the goal here).

Each honeypot port runs its own asyncio server. On every connection we:
  1. Send a realistic-looking banner/prompt for that service.
  2. Read a username/password (protocol dependent, simplified).
  3. Hand the (ip, username, password, port) tuple to `coordinator`.
  4. Always reply "Access denied" / equivalent and close.
"""

import asyncio
import logging

log = logging.getLogger("hds.honeypot")

BANNERS = {
    "ftp": "220 (vsFTPd 3.0.5)\r\n",
    "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
    "telnet": "Ubuntu 22.04 LTS\r\nlogin: ",
    "smtp": "220 mail.example.com ESMTP Postfix\r\n",
    "pop3": "+OK POP3 server ready\r\n",
    "imap": "* OK IMAP4rev1 Service Ready\r\n",
    "smb": "",  # binary protocol, we just accept and drop
    "imaps": "* OK IMAP4rev1 Service Ready\r\n",
    "pop3s": "+OK POP3 server ready\r\n",
    "mssql": "",
    "oracle": "",
    "mysql": "\x4a\x00\x00\x00\x0a5.7.31-log\x00",  # fake MySQL greeting
    "rdp": "",
    "postgres": "",
    "vnc": "RFB 003.008\n",
    "redis": "-ERR unknown command\r\n",
    "http-alt": "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\n\r\n",
    "mongodb": "",
}


class HoneypotHandler:
    """Handles one honeypot TCP port and forwards captured creds to coordinator."""

    def __init__(self, port, service, on_attempt):
        self.port = port
        self.service = service
        self.on_attempt = on_attempt  # callback(ip, username, password, port)

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        try:
            banner = BANNERS.get(self.service, "")
            if banner:
                writer.write(banner.encode(errors="ignore"))
                await writer.drain()

            username, password = await self._read_credentials(reader, writer)

            log.info(
                "[honeypot:%s/%s] capture from %s -> user=%r pass=%r",
                self.port, self.service, ip, username, password,
            )
            await self.on_attempt(ip, username, password, self.port)

            # Always deny, whatever the "creds" were
            deny_msg = self._deny_message()
            if deny_msg:
                writer.write(deny_msg.encode(errors="ignore"))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            log.debug("honeypot handler error on port %s: %s", self.port, e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_credentials(self, reader, writer):
        """
        Very simplified credential capture. Real-world honeypots
        (Cowrie, etc.) implement the full protocol; here we just try to
        prompt for a username/password over plaintext services and read
        raw bytes for binary ones, which is enough to log the attempt
        and the source IP for the redirect/block logic.
        """
        service = self.service
        try:
            if service in ("ftp", "telnet", "smtp", "pop3", "imap", "imaps", "pop3s"):
                if service != "telnet":
                    writer.write(b"Username: ")
                    await writer.drain()
                uline = await asyncio.wait_for(reader.readline(), timeout=15)
                username = uline.decode(errors="ignore").strip()

                writer.write(b"Password: ")
                await writer.drain()
                pline = await asyncio.wait_for(reader.readline(), timeout=15)
                password = pline.decode(errors="ignore").strip()
                return username, password
            else:
                # Binary / unknown protocol: just sniff whatever bytes arrive
                data = await asyncio.wait_for(reader.read(256), timeout=10)
                return "<binary>", data.hex()
        except asyncio.TimeoutError:
            return None, None

    def _deny_message(self):
        if self.service == "ftp":
            return "530 Login incorrect.\r\n"
        if self.service in ("pop3", "pop3s"):
            return "-ERR authentication failed\r\n"
        if self.service in ("imap", "imaps"):
            return "* BAD authentication failed\r\n"
        if self.service == "smtp":
            return "535 5.7.8 Authentication failed\r\n"
        if self.service == "telnet":
            return "Login incorrect\r\n"
        return ""


async def start_honeypot(port, service, on_attempt):
    handler = HoneypotHandler(port, service, on_attempt)
    server = await asyncio.start_server(handler.handle_client, host="0.0.0.0", port=port)
    log.info("Honeypot listening: port=%s service=%s", port, service)
    return server


async def start_all_honeypots(honeypot_ports: dict, on_attempt):
    """
    honeypot_ports: {port: service_name}
    Returns list of asyncio Server objects (keep references so they
    don't get garbage collected / closed).
    """
    servers = []
    for port, service in honeypot_ports.items():
        try:
            server = await start_honeypot(port, service, on_attempt)
            servers.append(server)
        except PermissionError:
            log.error(
                "Permission denied binding port %s (ports <1024 need root). Skipping.",
                port,
            )
        except OSError as e:
            log.error("Could not bind honeypot port %s: %s", port, e)
    return servers
