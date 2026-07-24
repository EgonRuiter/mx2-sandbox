"""Unit tests for the MX2 Headless REST Daemon HTTP Server."""

import json
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import HTTPServer

from src.web_server import MX2SandboxHTTPHandler


class TestMX2WebServer(unittest.TestCase):
    """Integration test suite for the REST API and Prometheus metrics daemon."""

    @classmethod
    def setUpClass(cls) -> None:
        # Start HTTPServer on loopback with port 0 (OS chooses a random free port)
        cls.server = HTTPServer(("127.0.0.1", 0), MX2SandboxHTTPHandler)
        cls.host, cls.port = cls.server.server_address
        cls.base_url = f"http://{cls.host}:{cls.port}"

        # Start server in a background daemon thread
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        # Shutdown the server cleanly
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def _post(self, path: str, data: dict) -> tuple[int, dict]:
        """Helper to post JSON data to the daemon."""
        url = f"{self.base_url}{path}"
        req_data = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read().decode("utf-8")
                return resp.status, json.loads(body)
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8")
            try:
                return err.code, json.loads(body)
            except Exception:
                return err.code, {"error": body}

    def test_metrics_endpoint(self) -> None:
        """Tests that Prometheus metrics are served successfully."""
        url = f"{self.base_url}/metrics"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"text/plain", resp.headers.get("Content-Type", b"").encode())
            body = resp.read().decode("utf-8")
            self.assertIn("mx2_api_connections_total", body)
            self.assertIn("mx2_quarantine_count", body)

    def test_health_endpoint(self) -> None:
        """Healthcheck for orchestrators (K8s/Docker) returns 200 + healthy JSON."""
        url = f"{self.base_url}/health"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data, {"status": "healthy"})

    def test_invalid_endpoint(self) -> None:
        """Tests that request to invalid endpoint returns 404."""
        code, data = self._post("/api/non-existent", {})
        self.assertEqual(code, 404)
        self.assertIn("error", data)

        # GET request to non-existent endpoint
        url = f"{self.base_url}/invalid-get"
        req = urllib.request.Request(url, method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)

    def test_translate_api(self) -> None:
        """Tests translating SMTP MIME messages over the REST API."""
        smtp_payload = (
            "From: alice@example.com\nTo: bob@example.com\nSubject: REST Test\n\nTesting translation over HTTP."
        )
        payload = {
            "smtp": smtp_payload,
            "publicKey": "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327",
            "features": ["HPKE", "Sealed-Sender"],
        }
        code, data = self._post("/api/translate", payload)
        self.assertEqual(code, 200)
        self.assertTrue(data["success"])
        # Unverified legacy SMTP from new sender maps to JUNK (Grade D) by default
        self.assertEqual(data["status"], "JUNK")
        self.assertIn("recipient", data["payload"])
        self.assertIn("encryptedPayload", data["payload"])

    def test_decrypt_api(self) -> None:
        """Tests HPKE payload decryption via the REST API."""
        # 1. Translate message to get encrypted envelope
        smtp_payload = (
            "From: alice@example.com\nTo: bob@example.com\nSubject: Decrypt Test\n\nTesting decryption over HTTP."
        )
        translate_payload = {"smtp": smtp_payload, "publicKey": "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"}
        _, tr_data = self._post("/api/translate", translate_payload)

        # 2. Call decryption endpoint
        decrypt_payload = {
            "encryptedPayload": tr_data["payload"]["encryptedPayload"],
            "ephemeralPublicKey": tr_data["payload"]["ephemeralPublicKey"],
            "privateKey": "mock-private-key-12345",
        }
        code, data = self._post("/api/decrypt", decrypt_payload)
        self.assertEqual(code, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["payload"]["content"]["subject"], "Decrypt Test")

    def test_negotiate_api(self) -> None:
        """Tests version and capability negotiation over the REST API."""
        payload = {"clientVersion": "1.0.0", "clientFeatures": ["HPKE", "Trust-Routing"]}
        code, data = self._post("/api/negotiate", payload)
        self.assertEqual(code, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["negotiated"]["protocolVersion"], "1.0.0")
        self.assertIn("HPKE", data["negotiated"]["features"])

    def test_cas_roundtrip_api(self) -> None:
        """Tests writing and reading file attachments in CAS via the REST API."""
        # Upload
        payload = {"content": "Sample file data for CAS."}
        code, data = self._post("/api/cas/upload", payload)
        self.assertEqual(code, 200)
        self.assertTrue(data["success"])
        sha256 = data["sha256"]

        # Download
        dl_payload = {"sha256": sha256}
        code, dl_data = self._post("/api/cas/download", dl_payload)
        self.assertEqual(code, 200)
        self.assertTrue(dl_data["success"])
        self.assertEqual(dl_data["content"], "Sample file data for CAS.")


if __name__ == "__main__":
    unittest.main()
