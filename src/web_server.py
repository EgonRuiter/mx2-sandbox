"""MX2 Headless Daemon HTTP Server.

A zero-dependency Python HTTP server running the MX2 daemon. Exposes REST API
endpoints for envelope translations, HPKE decrypts, capabilities negotiation,
and anti-spam administration.
"""

import configparser
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# Allow importing 'src' package components when run directly as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.anti_spam import MX2AntiSpamEngine
from src.cas import MX2CASEngine
from src.gateway import BilingualGateway
from src.logger import log_event, setup_logger


class MX2SandboxHTTPHandler(BaseHTTPRequestHandler):
    """Hardened REST API and Prometheus telemetries handler for the MX2 Daemon."""

    anti_spam = MX2AntiSpamEngine()
    cas_engine = MX2CASEngine()

    # Telemetry metrics counters
    api_connections_total = 0

    def log_message(self, format: str, *args: Any) -> None:
        """Overrides default stderr logs to use our structured JSON logger."""
        log_event("INFO", "Daemon-HTTP", format % args)

    def do_GET(self) -> None:
        """Handles telemetry reads. All other GET paths return 404."""
        MX2SandboxHTTPHandler.api_connections_total += 1
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/metrics":
            self._handle_metrics()
        elif path in ("/", ""):
            self._send_json(
                {"status": "alive", "message": "MX2 Headless Gateway Daemon running. Administer using mx2ctl."}, 200
            )
        elif path == "/health":
            self._send_json({"status": "healthy"}, 200)
        else:
            self._send_json({"error": "Headless Daemon. No web UI served."}, 404)

    def do_HEAD(self) -> None:
        """Handles HEAD probes for liveness checks."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_POST(self) -> None:
        """Processes incoming REST API requests."""
        MX2SandboxHTTPHandler.api_connections_total += 1
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        endpoints = {
            "/api/translate": self._handle_translate,
            "/api/decrypt": self._handle_decrypt,
            "/api/receipt/generate": self._handle_receipt_generate,
            "/api/negotiate": self._handle_negotiate,
            "/api/vouch/verify": self._handle_vouch_verify,
            "/api/trust/evaluate": self._handle_trust_evaluate,
            "/api/queue/list": self._handle_queue_list,
            "/api/queue/approve": self._handle_queue_approve,
            "/api/queue/reject": self._handle_queue_reject,
            "/api/cas/upload": self._handle_cas_upload,
            "/api/cas/download": self._handle_cas_download,
        }

        if path in endpoints:
            endpoints[path]()
        else:
            self._send_json({"error": f"Endpoint '{path}' not found"}, 404)

    def _read_post_body(self) -> str:
        """Helper to read the content body of a POST request."""
        content_length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(content_length).decode("utf-8")

    def _send_json(self, data: dict, status_code: int = 200) -> None:
        """Sends a JSON formatted HTTP response."""
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_error(self, code: str, message: str, err_type: str = "validation", status_code: int = 400) -> None:
        """Sends a structured, human-readable MX2ErrorPayload JSON response."""
        error_payload = {
            "success": False,
            "error": {
                "code": code,
                "message": message,
                "type": err_type,
                "details": {"timestamp": datetime.now(timezone.utc).isoformat() + "Z"},
            },
        }
        log_event("WARNING", "Daemon-API", f"API Error [{code}]: {message}")
        self._send_json(error_payload, status_code)

    def _handle_metrics(self) -> None:
        """Serves Prometheus scraped telemetry counters."""
        try:
            quarantine_len = len(self.anti_spam.holding_queue)

            metrics_lines = [
                "# HELP mx2_api_connections_total Total HTTP API calls resolved.",
                "# TYPE mx2_api_connections_total counter",
                f"mx2_api_connections_total {self.api_connections_total}",
                "",
                "# HELP mx2_quarantine_count Current number of emails held in the quarantine queue.",
                "# TYPE mx2_quarantine_count gauge",
                f"mx2_quarantine_count {quarantine_len}",
            ]

            response_bytes = "\n".join(metrics_lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        except Exception as err:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error calculating metrics: {err}".encode())

    def _handle_translate(self) -> None:
        """Translates raw legacy SMTP data, returning JSON errors on failure."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)
            raw_smtp = payload.get("smtp", "").strip()
            pubkey = payload.get("publicKey", "")
            features = payload.get("features", [])

            if not raw_smtp:
                self._send_error(
                    "ERR_EMPTY_PAYLOAD",
                    "De e-mailinhoud is leeg of kon niet correct worden gelezen. Controleer je SMTP-invoer.",
                    "validation",
                    400,
                )
                return

            sender_addr = "alice@example.com"
            recipient_addr = "bob@example.com"
            for line in raw_smtp.splitlines():
                if line.lower().startswith("from:"):
                    sender_addr = line.split(":", 1)[1].strip()
                elif line.lower().startswith("to:"):
                    recipient_addr = line.split(":", 1)[1].strip()

            sender_domain = sender_addr.split("@")[-1].split(">")[0].strip().lower()
            recipient_domain = recipient_addr.split("@")[-1].split(">")[0].strip().lower()

            vouch_token = payload.get("vouchingToken", None)
            voucher_pubkey = payload.get("voucherPublicKey", "")
            signature_valid = payload.get("signatureValid", True)

            # Evaluate trust grade in anti-spam engine
            trust_result = self.anti_spam.evaluate_trust_grade(
                sender_addr, sender_domain, recipient_addr, vouch_token, voucher_pubkey, signature_valid
            )

            # Check quota rate limiting
            hourly_count = self.anti_spam.get_hourly_count(sender_domain, recipient_domain)
            if hourly_count >= self.anti_spam.quota_limit:
                self._send_error(
                    "ERR_RATE_LIMIT_EXCEEDED",
                    f"Transmissie geweigerd: het verzendquota voor '{sender_domain}' is overschreden.",
                    "security",
                    429,
                )
                return

            # Translate message
            translated_envelope_str = BilingualGateway.translate_smtp_to_mx2(raw_smtp, pubkey, features, vouch_token)
            translated_dict = json.loads(translated_envelope_str)

            # Record sending
            self.anti_spam.record_message(sender_domain, recipient_domain)

            # If Grade E: Quarantine Holding Queue
            if trust_result["destination"] == "Quarantine":
                subject = "Unknown Subject"
                for line in raw_smtp.splitlines():
                    if line.lower().startswith("subject:"):
                        subject = line.split(":", 1)[1].strip()

                msg_id = translated_dict.get("encryptedPayload", "")[:12]
                self.anti_spam.quarantine_message(msg_id, sender_addr, subject, translated_dict)

                log_event(
                    "INFO",
                    "Daemon-Gateway",
                    f"Quarantined message {msg_id} from {sender_addr} due to Grade E trust routing.",
                )
                self._send_json(
                    {
                        "success": True,
                        "status": "QUARANTINE",
                        "grade": trust_result["grade"],
                        "reason": trust_result["reason"],
                        "messageId": msg_id,
                        "payload": translated_dict,
                    }
                )
                return

            log_event(
                "INFO",
                "Daemon-Gateway",
                f"Translated message successfully (Grade {trust_result['grade']} -> {trust_result['destination']}).",
            )
            self._send_json(
                {
                    "success": True,
                    "status": trust_result["destination"].upper(),
                    "grade": trust_result["grade"],
                    "reason": trust_result["reason"],
                    "payload": translated_dict,
                }
            )
        except Exception as err:
            self._send_error(
                "ERR_TRANSLATION_FAILED",
                f"De Bilingual Gateway kon het e-mailbericht niet vertalen naar MX2: {str(err)}",
                "server",
                500,
            )

    def _handle_decrypt(self) -> None:
        """Decrypts the E2EE Sealed Sender payload."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)

            encrypted_b64 = payload.get("encryptedPayload", "")
            ephemeral_public = payload.get("ephemeralPublicKey", "")
            private_key = payload.get("privateKey", "mock-private-key-12345")

            if not encrypted_b64 or not ephemeral_public:
                self._send_error(
                    "ERR_DECRYPTION_PARAMETERS_MISSING",
                    "Kan bericht niet ontsleutelen: ontbrekende E2EE parameters in envelop.",
                    "security",
                    400,
                )
                return

            decrypted_str = BilingualGateway.decrypt_payload(encrypted_b64, ephemeral_public, private_key)
            decrypted_dict = json.loads(decrypted_str)

            self._send_json({"success": True, "payload": decrypted_dict})
        except Exception:
            self._send_error(
                "ERR_DECRYPTION_FAILED",
                "Decryptie mislukt. De afgeleide sessiesleutel komt niet overeen met de envelop-sleutel.",
                "security",
                403,
            )

    def _handle_receipt_generate(self) -> None:
        """Generates a signed delivery receipt for the envelope."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)

            envelope = payload.get("envelope", {})
            privkey = payload.get("privateKey", "mock-private-key-12345")

            if not envelope:
                self._send_error(
                    "ERR_RECEIPT_MISSING_ENVELOPE",
                    "Geen e-mailenvelop ontvangen om een afleverbewijs voor te genereren.",
                    "validation",
                    400,
                )
                return

            receipt = BilingualGateway.generate_delivery_receipt(envelope, privkey)

            self._send_json({"success": True, "receipt": receipt})
        except Exception as err:
            self._send_error(
                "ERR_RECEIPT_GENERATION_FAILED",
                f"Fout bij het genereren van het ontvangstbewijs: {str(err)}",
                "server",
                500,
            )

    def _handle_negotiate(self) -> None:
        """Negotiates compatible SemVer and features."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)

            client_ver = payload.get("clientVersion", "1.0.0")
            client_feats = payload.get("clientFeatures", [])
            server_ver = payload.get("serverVersion", "2.0.0")

            negotiated = BilingualGateway.negotiate_capabilities(client_ver, client_feats, server_ver)

            self._send_json({"success": True, "negotiated": negotiated})
        except Exception as err:
            self._send_error(
                "ERR_NEGOTIATION_FAILED",
                f"Sleutel/functie-onderhandeling tussen client en server is mislukt: {str(err)}",
                "routing",
                500,
            )

    def _handle_vouch_verify(self) -> None:
        """Validates a Web of Trust vouching token."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)

            token = payload.get("vouchingToken", {})
            pubkey = payload.get("publicKey", "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327")

            is_valid = self.anti_spam.verify_vouch_token(token, pubkey)

            self._send_json({"success": True, "valid": is_valid})
        except Exception as err:
            self._send_error(
                "ERR_VOUCH_VERIFICATION_FAILED", f"Fout bij valideren van vouching token: {str(err)}", "security", 500
            )

    def _handle_trust_evaluate(self) -> None:
        """API endpoint to directly evaluate a sender profile."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)

            sender = payload.get("sender", "")
            sender_domain = payload.get("senderDomain", "")
            recipient = payload.get("recipient", "bob@example.com")
            vouch_token = payload.get("vouchingToken", None)
            voucher_pubkey = payload.get("voucherPublicKey", "")
            signature_valid = payload.get("signatureValid", True)

            trust_result = self.anti_spam.evaluate_trust_grade(
                sender, sender_domain, recipient, vouch_token, voucher_pubkey, signature_valid
            )

            self._send_json({"success": True, "trustResult": trust_result})
        except Exception as err:
            self._send_error(
                "ERR_TRUST_EVALUATION_FAILED", f"Fout bij berekenen van trust grade: {str(err)}", "server", 500
            )

    def _handle_queue_list(self) -> None:
        """Lists all quarantined messages."""
        self._send_json({"success": True, "queue": self.anti_spam.holding_queue})

    def _handle_queue_approve(self) -> None:
        """Approves a quarantined message, whitelisting the sender."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)
            msg_id = payload.get("messageId", "")

            success, approved_msg = self.anti_spam.approve_quarantined_sender(msg_id)

            if success:
                log_event("INFO", "Daemon-Queue", f"Released message {msg_id} and whitelisted identity.")
                self._send_json(
                    {
                        "success": True,
                        "message": "Sender whitelisted and message released.",
                        "releasedMessage": approved_msg,
                    }
                )
            else:
                self._send_error(
                    "ERR_QUEUE_MESSAGE_NOT_FOUND",
                    "Bericht niet gevonden in quarantine-holding queue.",
                    "validation",
                    404,
                )
        except Exception as err:
            self._send_error("ERR_QUEUE_APPROVE_FAILED", f"Fout bij whitelisten: {str(err)}", "server", 500)

    def _handle_queue_reject(self) -> None:
        """Rejects and discards a quarantined message."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)
            msg_id = payload.get("messageId", "")

            success = self.anti_spam.reject_quarantined_sender(msg_id)

            if success:
                log_event("INFO", "Daemon-Queue", f"Discarded quarantined message {msg_id}.")
                self._send_json({"success": True, "message": "Quarantined email discarded."})
            else:
                self._send_error(
                    "ERR_QUEUE_MESSAGE_NOT_FOUND",
                    "Bericht niet gevonden in quarantine-holding queue.",
                    "validation",
                    404,
                )
        except Exception as err:
            self._send_error("ERR_QUEUE_REJECT_FAILED", f"Fout bij verwerpen: {str(err)}", "server", 500)

    def _handle_cas_upload(self) -> None:
        """Uploads and deduplicates file content to the CAS Engine."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)
            content = payload.get("content", "")

            sha256_hash, cas_uri = self.cas_engine.write(content)
            log_event("INFO", "Daemon-CAS", f"Stored attachment under CAS URI {cas_uri}.")

            self._send_json({"success": True, "sha256": sha256_hash, "uri": cas_uri})
        except Exception as err:
            self._send_error(
                "ERR_CAS_UPLOAD_FAILED", f"Kan bijlage niet uploaden naar CAS-opslag: {str(err)}", "server", 500
            )

    def _handle_cas_download(self) -> None:
        """Downloads file content from CAS store by SHA-256 hash."""
        try:
            body = self._read_post_body()
            payload = json.loads(body)
            sha256_hash = payload.get("sha256", "")

            content_bytes = self.cas_engine.read(sha256_hash)

            self._send_json({"success": True, "content": content_bytes.decode("utf-8", errors="ignore")})
        except Exception as err:
            self._send_error(
                "ERR_CAS_DOWNLOAD_FAILED",
                f"Hash niet gevonden of kon niet worden gelezen: {str(err)}",
                "validation",
                404,
            )


def run_server() -> None:
    """Loads configuration and starts the HTTP server."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_file = os.path.join(base_dir, "config", "mx2.conf")

    # Read INI settings
    config = configparser.ConfigParser()
    config.read(config_file)

    port = config.getint("daemon", "port", fallback=8000)
    host = config.get("daemon", "host", fallback="127.0.0.1")
    log_file = config.get("daemon", "log_file", fallback="logs/mx2.log")

    # Configure structured logging
    setup_logger(os.path.join(base_dir, log_file))

    log_event("INFO", "Daemon-Init", "Initializing MX2 Gateway Server (Headless Mode)...")

    server_address = (host, port)
    httpd = HTTPServer(server_address, MX2SandboxHTTPHandler)
    log_event("INFO", "Daemon-Init", f"API Server listening on http://{host}:{port}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event("INFO", "Daemon-Shutdown", "Shutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
