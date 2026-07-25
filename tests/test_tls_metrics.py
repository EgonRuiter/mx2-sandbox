"""Unit tests for the MX2 TLS Manager and Prometheus Metrics Engine."""

import os
import tempfile
import unittest

from src.metrics import MX2MetricsEngine
from src.tls_manager import MX2TLSManager


class TestMX2TLSAndMetrics(unittest.TestCase):
    """Test suite for MX2TLSManager and MX2MetricsEngine classes."""

    def setUp(self) -> None:
        """Sets up temporary test directory for TLS certificate generation."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tls_manager = MX2TLSManager(cert_dir=self.temp_dir.name)
        self.metrics = MX2MetricsEngine()

    def tearDown(self) -> None:
        """Cleans up temporary directory."""
        self.temp_dir.cleanup()

    def test_tls_certificate_generation(self) -> None:
        """Tests self-signed TLS certificate generation and SSLContext creation."""
        cert_path, key_path = self.tls_manager.ensure_self_signed_cert(domain="localhost")

        self.assertTrue(os.path.exists(cert_path))
        self.assertTrue(os.path.exists(key_path))

        context = self.tls_manager.create_ssl_context(cert_path, key_path)
        self.assertIsNotNone(context)

    def test_acme_challenge_handling(self) -> None:
        """Tests ACME http-01 challenge registration and resolution."""
        token = "sample_acme_token_123"
        key_auth = "sample_acme_token_123.thumbprint_abc"

        self.tls_manager.register_acme_challenge(token, key_auth)
        res = self.tls_manager.resolve_acme_challenge(token)

        self.assertEqual(res, key_auth)
        self.assertIsNone(self.tls_manager.resolve_acme_challenge("non_existent_token"))

    def test_prometheus_metrics_counters(self) -> None:
        """Tests thread-safe metrics incrementation and Prometheus text output format."""
        self.metrics.inc_api_requests()
        self.metrics.inc_translations()
        self.metrics.inc_pow_verified()
        self.metrics.inc_decrypted()

        export = self.metrics.export_prometheus_metrics(quarantine_count=5)

        self.assertIn("mx2_api_requests_total 1", export)
        self.assertIn("mx2_e2ee_translations_total 1", export)
        self.assertIn("mx2_pow_verified_total 1", export)
        self.assertIn("mx2_decrypted_messages_total 1", export)
        self.assertIn("mx2_quarantine_count 5", export)


if __name__ == "__main__":
    unittest.main()
