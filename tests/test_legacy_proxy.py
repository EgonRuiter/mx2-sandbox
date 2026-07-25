"""Unit tests for the MX2 Legacy SMTP and IMAP Loopback Proxy Servers."""

import unittest

from src.legacy_proxy import MX2LegacyIMAPProxy, MX2LegacySMTPProxy


class TestMX2LegacyProxy(unittest.TestCase):
    """Test suite for MX2LegacySMTPProxy and MX2LegacyIMAPProxy classes."""

    def setUp(self) -> None:
        """Initializes proxy instances."""
        self.smtp_proxy = MX2LegacySMTPProxy(host="127.0.0.1", port=10025)
        self.imap_proxy = MX2LegacyIMAPProxy(host="127.0.0.1", port=10143)

    def test_proxy_initialization(self) -> None:
        """Tests proxy initialization parameters."""
        self.assertEqual(self.smtp_proxy.host, "127.0.0.1")
        self.assertEqual(self.smtp_proxy.port, 10025)
        self.assertEqual(self.imap_proxy.host, "127.0.0.1")
        self.assertEqual(self.imap_proxy.port, 10143)


if __name__ == "__main__":
    unittest.main()
