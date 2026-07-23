#!/usr/bin/env python3
"""MX2 Local Development Sandbox Runner.

Demonstrates SemVer capabilities negotiation, E2EE HPKE message encryption
and decryption, DIDs, delivery receipts, and Automated Trust Routing (Grades A-E).
"""

import json
import sys
import time

from src.anti_spam import MX2AntiSpamEngine
from src.gateway import BilingualGateway


def print_banner(title: str) -> None:
    """Helper to display visual section banners."""
    print("\n" + "=" * 60)
    print(f" {title.upper()} ".center(60, "="))
    print("=" * 60)


def run_demo() -> None:
    """Executes the complete MX2 v11 integration walk-through."""
    print("Initializing MX2 Local Development Sandbox Demo (v11)...")

    # --- Section 1: Capabilities & Version Negotiation ---
    print_banner("1. Version & Capabilities Negotiation Handshake")

    client_version = "1.2.0"
    client_features = ["HPKE", "Sealed-Sender", "Trust-Routing"]
    server_version = "2.1.0"
    server_features = ["HPKE", "Sealed-Sender", "Trust-Routing", "Delivery-Receipts"]

    print(f"Client: version {client_version} | features: {client_features}")
    print(f"Server: version {server_version} | features: {server_features}")

    negotiated = BilingualGateway.negotiate_capabilities(
        client_version, client_features, server_version, server_features
    )
    print("\nNegotiated result:")
    print(f"-> Selected Version: {negotiated['protocolVersion']}")
    print(f"-> Enabled Features: {negotiated['features']}")

    # --- Section 2: E2EE translation using DIDs ---
    print_banner("2. E2EE translation using Decentralized Identifiers")

    did_recipient = "did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
    print(f"Sending message to recipient DID: {did_recipient}")

    test_mime_content = """From: did:mx2:senderPubKey12345
To: did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327
Subject: Decentralized Encrypted Chat
Content-Type: text/plain

Hello! This mail is routed directly via DIDs without DNSSEC requirements.
"""

    try:
        translated_envelope_str = BilingualGateway.translate_smtp_to_mx2(
            test_mime_content, recipient_public_key=did_recipient, negotiated_features=negotiated["features"]
        )
        envelope = json.loads(translated_envelope_str)
        print("\nSerialized Envelope (recipient resolves via DID):")
        print(json.dumps(envelope, indent=2))
    except Exception as err:
        print(f"[!] Error during DID translation: {err}")
        sys.exit(1)

    # --- Section 3: HPKE Encryption & Decryption ---
    print_banner("3. HPKE Message Decryption")

    mock_private_key = "mock-private-key-12345"
    wrong_private_key = "wrong-private-key-99999"

    # 3.1 Attempt Decryption with wrong private key
    print("[*] Attempting decryption with incorrect private key...")
    try:
        decrypted_fail_str = BilingualGateway.decrypt_payload(
            envelope["encryptedPayload"], envelope["ephemeralPublicKey"], wrong_private_key
        )
        decrypted_fail = json.loads(decrypted_fail_str)
        print(f"[!] Decryption succeeded unexpectedly? Content: {decrypted_fail}")
    except Exception:
        print("[+] Decryption failed! (Access Denied - only recipient key holder can decrypt).")

    # 3.2 Decrypt with correct private key
    print("\n[*] Attempting decryption with correct private key...")
    try:
        decrypted_success_str = BilingualGateway.decrypt_payload(
            envelope["encryptedPayload"], envelope["ephemeralPublicKey"], mock_private_key
        )
        decrypted_success = json.loads(decrypted_success_str)
        print("[+] Decryption succeeded!")
        print(f"    Subject: {decrypted_success['content']['subject']}")
        print(f"    Body: {decrypted_success['content']['blocks'][0]['body'].strip()}")
    except Exception as err:
        print(f"[!] Decryption failed: {err}")
        sys.exit(1)

    # --- Section 4: Cryptographic Delivery Receipts ---
    print_banner("4. Cryptographic Delivery Receipts")
    print("Generating non-repudiation receipt from recipient domain...")
    try:
        receipt = BilingualGateway.generate_delivery_receipt(envelope, mock_private_key)
        print("\nVerifiable Delivery Receipt JSON:")
        print(json.dumps(receipt, indent=2))
    except Exception as err:
        print(f"[!] Receipt generation failed: {err}")
        sys.exit(1)

    # --- Section 5: Automated Trust Routing ---
    print_banner("5. Automated Trust Routing (Grades A-E)")

    engine = MX2AntiSpamEngine()
    recipient = "bob@example.com"
    voucher_pubkey = "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"

    # Utrecht University signs a vouch token
    vouch_token = {
        "vouchedDomain": "untrusted-startup.net",
        "voucherDomain": "trusted.nl",
        "expires": str(time.time() + 3600),
        "signature": f"sig_trusted.nl_untrusted-startup.net_{voucher_pubkey[:6]}",
    }

    scenarios = [
        {
            "name": "Scenario 1: Reputable Domain (Grade A)",
            "sender": "notifications@github.com",
            "domain": "github.com",
            "vouch": None,
            "sig_valid": True,
        },
        {
            "name": "Scenario 2: Vouched Startup Domain (Grade B)",
            "sender": "ceo@untrusted-startup.net",
            "domain": "untrusted-startup.net",
            "vouch": vouch_token,
            "sig_valid": True,
        },
        {
            "name": "Scenario 3: Social Graph Contact (Grade C)",
            "sender": "friend@collaborator.com",
            "domain": "collaborator.com",
            "vouch": None,
            "sig_valid": True,
        },
        {
            "name": "Scenario 4: Validated Unknown Domain (Grade D)",
            "sender": "newsletter@marketing-bot.com",
            "domain": "marketing-bot.com",
            "vouch": None,
            "sig_valid": True,
        },
        {
            "name": "Scenario 5: Spoofed Domain Identity (Grade E)",
            "sender": "billing@github.com",
            "domain": "github.com",
            "vouch": None,
            "sig_valid": False,
        },
    ]

    for sc in scenarios:
        print(f"\n[*] Evaluating {sc['name']}...")
        result = engine.evaluate_trust_grade(
            sc["sender"], sc["domain"], recipient, sc["vouch"], voucher_pubkey, sc["sig_valid"]
        )
        print(f"    - Computed Grade: {result['grade']}")
        print(f"    - Routing Target: {result['destination']}")
        print(f"    - Diagnostic: {result['reason']}")

        if result["destination"] == "Quarantine":
            print("    [!] Placing unverified mail in Inbox Holding Queue...")
            engine.quarantine_message("q_msg_github_spoof", sc["sender"], "Update your credentials", {})

    print(f"\nActive Holding Queue Length (Grade E quarantine): {len(engine.holding_queue)}")
    for item in engine.holding_queue:
        print(f"    - [{item['messageId']}] Sender: {item['sender']} | Subject: {item['subject']}")

    # --- Section 6: Structured Human-Readable JSON Errors ---
    print_banner("6. Structured Human-Readable JSON Errors")
    print("Simulating error response for an empty email submission...")

    error_payload = {
        "success": False,
        "error": {
            "code": "ERR_EMPTY_PAYLOAD",
            "message": "De e-mailinhoud is leeg of kon niet correct worden gelezen. Controleer je SMTP-invoer.",
            "type": "validation",
            "details": {"timestamp": "2026-07-16T12:00:00Z"},
        },
    }
    print(json.dumps(error_payload, indent=2))

    print_banner("Sandbox Demo Completed Successfully")


if __name__ == "__main__":
    run_demo()
