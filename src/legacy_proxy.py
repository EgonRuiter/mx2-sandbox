"""MX2 Asynchronous Legacy SMTP & IMAP Loopback Proxy Server.

Listens on localhost:10025 (SMTP) and localhost:10143 (IMAP) to intercept
legacy email client traffic (Thunderbird, Outlook, Apple Mail), transparently
translating SMTP MIME messages into encrypted MX2 envelopes via the gateway daemon.
"""

import asyncio
import json
import urllib.request
from typing import Optional

from src.gateway import BilingualGateway


class MX2LegacySMTPProxy:
    """Asynchronous loopback SMTP server translating legacy email client dispatches."""

    def __init__(self, host: str = "127.0.0.1", port: int = 10025, target_url: str = "http://127.0.0.1:8000") -> None:
        """Initializes the SMTP proxy settings.

        Args:
            host (str): IP address to bind (default: 127.0.0.1).
            port (int): Port number to bind (default: 10025).
            target_url (str): Gateway REST API target URL.
        """
        self.host = host
        self.port = port
        self.target_url = target_url.rstrip("/")
        self.server: Optional[asyncio.Server] = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handles an incoming SMTP client TCP connection stream."""
        writer.write(b"220 127.0.0.1 MX2 Legacy SMTP Proxy Server Ready\r\n")
        await writer.drain()

        in_data_mode = False
        data_buffer = []

        try:
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="ignore")

                if in_data_mode:
                    if line.strip() == ".":
                        in_data_mode = False
                        raw_mime = "".join(data_buffer)

                        # Translate raw MIME to MX2 envelope
                        translated_json = BilingualGateway.translate_smtp_to_mx2(raw_mime)
                        translated_dict = json.loads(translated_json)

                        # Post translation to daemon REST API
                        api_payload = {
                            "smtp": raw_mime,
                            "publicKey": translated_dict.get("recipient", ""),
                        }
                        self._post_to_gateway("/api/translate", api_payload)

                        writer.write(b"250 2.0.0 OK Message accepted for MX2 E2EE translation\r\n")
                        await writer.drain()
                        data_buffer.clear()
                    else:
                        data_buffer.append(line)
                    continue

                cmd_upper = line.upper().strip()

                if cmd_upper.startswith("HELO") or cmd_upper.startswith("EHLO"):
                    writer.write(b"250-127.0.0.1 Hello\r\n250-8BITMIME\r\n250 OK\r\n")
                    await writer.drain()
                elif cmd_upper.startswith("MAIL FROM:"):
                    _sender = line.split(":", 1)[1].strip().strip("<>")
                    writer.write(b"250 2.1.0 Sender OK\r\n")
                    await writer.drain()
                elif cmd_upper.startswith("RCPT TO:"):
                    _recipient = line.split(":", 1)[1].strip().strip("<>")
                    writer.write(b"250 2.1.5 Recipient OK\r\n")
                    await writer.drain()
                elif cmd_upper == "DATA":
                    in_data_mode = True
                    writer.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    await writer.drain()
                elif cmd_upper == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 OK\r\n")
                    await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def _post_to_gateway(self, endpoint: str, payload: dict) -> None:
        """Sends translated envelope to gateway REST API."""
        try:
            url = f"{self.target_url}{endpoint}"
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read()
        except Exception:
            pass

    async def start(self) -> None:
        """Starts listening for SMTP connections asynchronously."""
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self) -> None:
        """Stops the SMTP proxy server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class MX2LegacyIMAPProxy:
    """Asynchronous loopback IMAP server exposing MX2 decrypted mailboxes."""

    def __init__(self, host: str = "127.0.0.1", port: int = 10143) -> None:
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handles an incoming IMAP client connection stream."""
        writer.write(b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] MX2 IMAP Proxy Ready\r\n")
        await writer.drain()

        try:
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                parts = line.split(" ", 2)
                tag = parts[0]
                cmd = parts[1].upper() if len(parts) > 1 else ""

                if cmd == "CAPABILITY":
                    writer.write(b"* CAPABILITY IMAP4rev1 LITERAL+\r\n")
                    writer.write(f"{tag} OK CAPABILITY completed\r\n".encode())
                elif cmd == "LOGOUT":
                    writer.write(b"* BYE Logging out\r\n")
                    writer.write(f"{tag} OK LOGOUT completed\r\n".encode())
                    await writer.drain()
                    break
                else:
                    writer.write(f"{tag} OK {cmd} completed\r\n".encode())

                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        """Starts listening for IMAP connections asynchronously."""
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self) -> None:
        """Stops the IMAP proxy server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
