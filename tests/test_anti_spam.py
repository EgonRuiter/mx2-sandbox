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
            "signature": f"sig_trusted.nl_untrusted.net_{self.voucher_pubkey[:6]}",
        }
        self.assertTrue(self.engine.verify_vouch_token(token, self.voucher_pubkey))

    def test_verify_vouch_token_real_cryptography(self) -> None:
        """Verifies that an Ed25519 signed vouch token passes cryptographic signature verification."""
        import base64

        from src.gateway import parse_ed25519_private_key

        ed_priv = parse_ed25519_private_key(self.voucher_pubkey)
        vouched = "untrusted.net"
        voucher = "trusted.nl"
        expires = str(time.time() + 3600)

        # Sign using Utrecht University private key
        data_to_sign = f"{voucher}_{vouched}_{expires}".encode()
        signature_bytes = ed_priv.sign(data_to_sign)
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        token = {
            "vouchedDomain": vouched,
            "voucherDomain": voucher,
            "expires": expires,
            "signature": signature_b64,
        }
        self.assertTrue(self.engine.verify_vouch_token(token, self.voucher_pubkey))

    def test_verify_vouch_token_invalid_signature(self) -> None:
        """Verifies that tokens with wrong signatures or expired timestamps fail."""
        token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() + 3600),
            "signature": "sig_bad_signature_1234",
        }
        self.assertFalse(self.engine.verify_vouch_token(token, self.voucher_pubkey))

        # Expired token
        expired_token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() - 100),
            "signature": f"sig_trusted.nl_untrusted.net_{self.voucher_pubkey[:6]}",
        }
        self.assertFalse(self.engine.verify_vouch_token(expired_token, self.voucher_pubkey))

    def test_sender_status_whitelisted_delivers_instantly(self) -> None:
        """Manually whitelisted sender domains bypass quarantine lists and land in Inbox."""
        self.engine.whitelisted_senders.add("trusted-partner.com")

        result = self.engine.evaluate_trust_grade(
            sender="alice@trusted-partner.com", sender_domain="trusted-partner.com", recipient="bob@example.com"
        )
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["destination"], "Inbox")

    def test_sender_status_vouch_delivers_instantly(self) -> None:
        """Presenting a valid vouch token bypasses quarantine and whitelists domain to Inbox."""
        token = {
            "vouchedDomain": "untrusted.net",
            "voucherDomain": "trusted.nl",
            "expires": str(time.time() + 3600),
            "signature": f"sig_trusted.nl_untrusted.net_{self.voucher_pubkey[:6]}",
        }

        # trusted.nl is a reputable domain in REPUTABLE_DOMAINS
        result = self.engine.evaluate_trust_grade(
            sender="bob@untrusted.net",
            sender_domain="untrusted.net",
            recipient="bob@example.com",
            vouch_token=token,
            voucher_pubkey=self.voucher_pubkey,
        )
        self.assertEqual(result["grade"], "B")
        self.assertEqual(result["destination"], "Inbox")

    def test_sender_status_junks_unknown(self) -> None:
        """First-time unknown senders with valid signatures are routed to Junk."""
        result = self.engine.evaluate_trust_grade(
            sender="stranger@unknown.com",
            sender_domain="unknown.com",
            recipient="bob@example.com",
            signature_valid=True,
        )
        self.assertEqual(result["grade"], "D")
        self.assertEqual(result["destination"], "Junk")

    def test_sender_status_quarantines_spoofed(self) -> None:
        """Messages with failed signature verification are routed to Quarantine Grade E."""
        result = self.engine.evaluate_trust_grade(
            sender="billing@github.com", sender_domain="github.com", recipient="bob@example.com", signature_valid=False
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

    def test_proof_of_work_verification(self) -> None:
        """Tests that a computed Proof-of-Work challenge of 10 bits is correctly validated."""
        challenge = "bob@example.com:alice@example.com:1710000000"

        # 1. Compute valid nonce
        nonce = 0
        while not MX2AntiSpamEngine.verify_proof_of_work(challenge, str(nonce), difficulty_bits=10):
            nonce += 1

        # 2. Verify it passes
        self.assertTrue(MX2AntiSpamEngine.verify_proof_of_work(challenge, str(nonce), difficulty_bits=10))

        # 3. Verify that an incorrect nonce fails
        self.assertFalse(MX2AntiSpamEngine.verify_proof_of_work(challenge, str(nonce + 1), difficulty_bits=10))


if __name__ == "__main__":
    unittest.main()
