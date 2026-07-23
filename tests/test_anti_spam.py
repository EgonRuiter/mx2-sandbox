"""Unit tests for the MX2 Automated Trust Routing Spam Engine."""

import time
import unittest

from src.anti_spam import MX2AntiSpamEngine


class TestMX2AntiSpamEngine(unittest.TestCase):
    """Test suite for the MX2AntiSpamEngine class with WoT vouching and quarantine."""

    def setUp(self) -> None:
        """Sets up the default green anti-spam engine instance."""
        self.engine = MX2AntiSpamEngine(quota_limit=2)
        self.voucher_pubkey = "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"

    def test_verify_vouch_token_valid(self) -> None:
        """Verifies that a mathematically signed Vouching Token passes signature checks."""
        token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() + 3600),
            "signature": f"sig_trusted.nl_untrusted.net_{self.voucher_pubkey[:6]}"
        }
        self.assertTrue(self.engine.verify_vouch_token(token, self.voucher_pubkey))

    def test_verify_vouch_token_invalid_signature(self) -> None:
        """Verifies that tokens with wrong signatures or expired timestamps fail."""
        token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() + 3600),
            "signature": "sig_bad_signature_1234"
        }
        self.assertFalse(self.engine.verify_vouch_token(token, self.voucher_pubkey))

        # Expired token
        expired_token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() - 100),
            "signature": f"sig_trusted.nl_untrusted.net_{self.voucher_pubkey[:6]}"
        }
        self.assertFalse(self.engine.verify_vouch_token(expired_token, self.voucher_pubkey))

    def test_sender_status_whitelisted_delivers_instantly(self) -> None:
        """Manually whitelisted sender domains bypass quarantine lists and land in Inbox."""
        self.engine.whitelisted_senders.add("trusted-partner.com")

        result = self.engine.evaluate_trust_grade(
            sender="alice@trusted-partner.com",
            sender_domain="trusted-partner.com",
            recipient="bob@example.com"
        )
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["destination"], "Inbox")

    def test_sender_status_vouch_delivers_instantly(self) -> None:
        """Presenting a valid vouch token bypasses quarantine and whitelists domain to Inbox."""
        token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() + 3600),
            "signature": f"sig_trusted.nl_untrusted.net_{self.voucher_pubkey[:6]}"
        }

        # trusted.nl is a reputable domain in REPUTABLE_DOMAINS
        result = self.engine.evaluate_trust_grade(
            sender="bob@untrusted.net",
            sender_domain="untrusted.net",
            recipient="bob@example.com",
            vouch_token=token,
            voucher_pubkey=self.voucher_pubkey
        )
        self.assertEqual(result["grade"], "B")
        self.assertEqual(result["destination"], "Inbox")

    def test_sender_status_junks_unknown(self) -> None:
        """First-time unknown senders with valid signatures are routed to Junk."""
        result = self.engine.evaluate_trust_grade(
            sender="stranger@unknown.com",
            sender_domain="unknown.com",
            recipient="bob@example.com",
            signature_valid=True
        )
        self.assertEqual(result["grade"], "D")
        self.assertEqual(result["destination"], "Junk")

    def test_sender_status_quarantines_spoofed(self) -> None:
        """Messages with failed signature verification are routed to Quarantine Grade E."""
        result = self.engine.evaluate_trust_grade(
            sender="billing@github.com",
            sender_domain="github.com",
            recipient="bob@example.com",
            signature_valid=False
        )
        self.assertEqual(result["grade"], "E")
        self.assertEqual(result["destination"], "Quarantine")

    def test_quarantine_queue_management(self) -> None:
        """Tests that quarantined Grade E items can be approved (whitelisted) or rejected."""
        envelope = {"recipient": "bob@example.com"}
        self.engine.quarantine_message("q_msg_123", "stranger@unknown.com", "Hello Partner", envelope)

        self.assertEqual(len(self.engine.holding_queue), 1)
        self.assertEqual(self.engine.holding_queue[0]["subject"], "Hello Partner")

        # Approve item
        success, approved_msg = self.engine.approve_quarantined_sender("q_msg_123")
        self.assertTrue(success)
        self.assertEqual(len(self.engine.holding_queue), 0)
        self.assertIn("unknown.com", self.engine.whitelisted_senders)


if __name__ == "__main__":
    unittest.main()
