"""Unit tests for the MX2 Bilingual Gateway with HPKE, receipts, DIDs, and feature negotiation."""

import json
import unittest
from src.gateway import BilingualGateway


class TestBilingualGateway(unittest.TestCase):
    """Test suite for the BilingualGateway class with E2EE, HPKE, DIDs, and Receipts."""

    def setUp(self) -> None:
        self.recipient_pubkey = "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
        self.recipient_privkey = "mock-private-key-12345"

    def test_translate_smtp_to_mx2_envelope(self) -> None:
        """Tests that translating SMTP content results in a secure outer envelope."""
        raw_smtp = (
            "From: alice@example.com\n"
            "To: bob@example.com\n"
            "Subject: Confidential Project\n"
            "Content-Type: text/plain\n\n"
            "This is a secret message."
        )

        translated_envelope_str = BilingualGateway.translate_smtp_to_mx2(raw_smtp, self.recipient_pubkey)
        envelope = json.loads(translated_envelope_str)

        # Outer Envelope Validation (Sealed Sender)
        self.assertEqual(envelope["recipient"], "bob@example.com")
        self.assertIn("encryptedPayload", envelope)
        self.assertIn("ephemeralPublicKey", envelope)
        
        # Ensure private content is NOT visible in the outer envelope
        self.assertNotIn("alice@example.com", translated_envelope_str)
        self.assertNotIn("Confidential Project", translated_envelope_str)
        self.assertNotIn("This is a secret message.", translated_envelope_str)

    def test_hpke_message_encryption_and_decryption(self) -> None:
        """Tests that a payload encrypted via HPKE can be decrypted by the recipient."""
        raw_smtp = (
            "From: alice@example.com\n"
            "To: bob@example.com\n"
            "Subject: HPKE Test\n"
            "Content-Type: text/plain\n\n"
            "Highly confidential contents."
        )

        # Encrypt
        translated_envelope_str = BilingualGateway.translate_smtp_to_mx2(raw_smtp, self.recipient_pubkey)
        envelope = json.loads(translated_envelope_str)

        # Decrypt using the correct private key (must succeed)
        decrypted_str = BilingualGateway.decrypt_payload(
            envelope["encryptedPayload"],
            envelope["ephemeralPublicKey"],
            self.recipient_privkey
        )
        payload = json.loads(decrypted_str)
        self.assertEqual(payload["content"]["subject"], "HPKE Test")
        self.assertEqual(payload["sender"], "alice@example.com")

    def test_decentralized_identifier_did_routing(self) -> None:
        """Tests that DIDs are correctly parsed and bypassed in the key lookup routing."""
        recipient_did = "did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
        raw_smtp = (
            "From: did:mx2:senderPubKeyHex\n"
            "To: did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327\n"
            "Subject: DID Message\n"
            "Content-Type: text/plain\n\n"
            "Routed via DID."
        )

        translated_envelope_str = BilingualGateway.translate_smtp_to_mx2(raw_smtp, recipient_did)
        envelope = json.loads(translated_envelope_str)

        # Outer envelope must target the recipient DID
        self.assertEqual(envelope["recipient"], recipient_did)

        # Decrypt using the private key mapping
        decrypted_str = BilingualGateway.decrypt_payload(
            envelope["encryptedPayload"],
            envelope["ephemeralPublicKey"],
            "mock-private-key-12345"
        )
        payload = json.loads(decrypted_str)
        self.assertEqual(payload["sender"], "did:mx2:senderPubKeyHex")
        self.assertEqual(payload["content"]["blocks"][0]["body"].strip(), "Routed via DID.")

    def test_verifiable_delivery_receipt_generation(self) -> None:
        """Tests that a recipient domain can generate a signed receipt confirming delivery."""
        envelope = {
            "recipient": "bob@example.com",
            "encryptedPayload": "someencryptedblob",
            "ephemeralPublicKey": "someephemeralkey"
        }

        receipt = BilingualGateway.generate_delivery_receipt(envelope, self.recipient_privkey)

        self.assertTrue(receipt["messageId"].startswith("receipt_"))
        self.assertEqual(len(receipt["sha256Digest"]), 64)
        self.assertIn("Z", receipt["timestamp"])
        self.assertIn("signature", receipt)

    def test_capabilities_negotiation(self) -> None:
        """Tests SemVer and features list negotiation between client and server."""
        client_version = "1.2.0"
        client_features = ["HPKE", "Sealed-Sender", "Trust-Routing"]
        server_version = "2.1.0"
        server_features = ["HPKE", "Sealed-Sender", "Trust-Routing", "Delivery-Receipts"]

        negotiated = BilingualGateway.negotiate_capabilities(
            client_version, client_features, server_version, server_features
        )

        self.assertEqual(negotiated["protocolVersion"], "1.1.0")
        self.assertIn("HPKE", negotiated["features"])
        self.assertIn("Sealed-Sender", negotiated["features"])
        self.assertIn("Trust-Routing", negotiated["features"])


if __name__ == "__main__":
    unittest.main()
