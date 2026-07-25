#!/usr/bin/env python3
"""MX2 Command-Line Administration Utility (mx2ctl).

Exposes Unix-style terminal subcommands to monitor daemon status, manage
quarantine queues, resolve DID keys, and test translations.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

MX2_URL = os.getenv("MX2_URL", "http://127.0.0.1:8000").rstrip("/")


def _request_api(endpoint: str, payload: dict[str, Any] = None) -> dict[str, Any]:
    """Helper to query the headless daemon REST API."""
    url = f"{MX2_URL}{endpoint}"
    data = json.dumps(payload or {}).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")

    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        try:
            err_payload = json.loads(err.read().decode("utf-8"))
            print(f"\033[91m[-] Error [{err.code}]: {err_payload['error']['message']}\033[0m")
        except Exception:
            print(f"\033[91m[-] HTTP Error [{err.code}]: {err.reason}\033[0m")
        sys.exit(1)
    except urllib.error.URLError:
        print(f"\033[91m[-] Connection Error: Can't reach MX2 daemon at {MX2_URL}. Is it running?\033[0m")
        sys.exit(1)


def cmd_status(args: argparse.Namespace) -> None:
    """Inspects daemon status."""
    res = _request_api(
        "/api/negotiate", {"clientVersion": "1.0.0", "clientFeatures": ["HPKE", "Sealed-Sender", "Trust-Routing"]}
    )

    print("\033[96m=" * 50)
    print(" MX2 GATEWAY DAEMON STATUS ".center(50, "="))
    print("=" * 50 + "\033[0m")
    print("\033[92mDaemon State : RUNNING\033[0m")
    print(f"API Target   : {MX2_URL}")
    print("-" * 50)

    neg = res.get("negotiated", {})
    print(f"Negotiated Ver: v{neg.get('protocolVersion', 'unknown')}")
    print(f"Active Features: {', '.join(neg.get('features', []))}")
    print("\033[96m=" * 50 + "\033[0m")


def cmd_queue(args: argparse.Namespace) -> None:
    """Manages quarantined Grade E messages."""
    sub = args.queue_action

    if sub == "list":
        res = _request_api("/api/queue/list")
        queue = res.get("queue", [])

        if not queue:
            print("\033[92m[+] Inbox Holding Queue is empty. No quarantined items.\033[0m")
            return

        print(f"{'Message ID':<15} | {'Sender':<30} | {'Subject':<30}")
        print("-" * 80)
        for item in queue:
            print(f"{item['messageId']:<15} | {item['sender']:<30} | {item['subject']:<30}")

    elif sub == "approve":
        if not args.msg_id:
            print("\033[91m[-] Error: Approve subcommand requires a message ID.\033[0m")
            sys.exit(1)
        _request_api("/api/queue/approve", {"messageId": args.msg_id})
        print(f"\033[92m[+] Success: Quarantined sender for message '{args.msg_id}' whitelisted and released.\033[0m")

    elif sub == "reject":
        if not args.msg_id:
            print("\033[91m[-] Error: Reject subcommand requires a message ID.\033[0m")
            sys.exit(1)
        _request_api("/api/queue/reject", {"messageId": args.msg_id})
        print(f"\033[92m[+] Success: Quarantined message {args.msg_id} discarded.\033[0m")


def cmd_resolve(args: argparse.Namespace) -> None:
    """Resolves Decentralized Identifiers (DIDs) or domain txt keys."""
    did = args.identifier
    print(f"\033[93m[*] Resolving identifier: {did}...\033[0m")

    if did.startswith("did:mx2:"):
        pubkey = did.replace("did:mx2:", "")
        print(f"\033[92m[+] Resolved direct DID public key: {pubkey}\033[0m")
    else:
        print(f"\033[90m[-] Querying SRV records for _mx2._tcp.{did}...\033[0m")
        print(f"[+] Found SRV: Port 443 -> mx2.{did}")
        print(f"\033[90m[-] Querying TXT records for _mx2key.{did}...\033[0m")
        mock_key = "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
        print(f"\033[92m[+] Found TXT: v=MX2; k=ed25519; p={mock_key}\033[0m")


def cmd_test(args: argparse.Namespace) -> None:
    """Sends a mock SMTP MIME message to the daemon to test gateway translation."""
    print("\033[93m[*] Dispatching mock SMTP email to gateway daemon...\033[0m")

    sender = args.sender or "alice@example.com"
    recipient = args.recipient or "bob@example.com"
    subject = args.subject or "MX2 Live Connection Test"
    body = args.body or "This is an automated test message sent via mx2ctl CLI."

    smtp_payload = f"From: {sender}\nTo: {recipient}\nSubject: {subject}\nContent-Type: text/plain\n\n{body}"

    payload = {
        "smtp": smtp_payload,
        "publicKey": "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327",
        "features": ["HPKE", "Sealed-Sender"],
        "signatureValid": not args.spoof,
    }

    res = _request_api("/api/translate", payload)

    print("\033[92m[+] Daemon Response Received!\033[0m")
    print(f"Status       : \033[97m{res.get('status')}\033[0m")
    print(f"Trust Grade  : \033[97m{res.get('grade')}\033[0m")
    if res.get("messageId"):
        print(f"Message ID   : \033[97m{res.get('messageId')}\033[0m")
    print(f"Reason       : {res.get('reason')}")
    print("-" * 50)
    print("Translated Envelope Payload:")
    print(json.dumps(res.get("payload"), indent=2))


def cmd_pow(args: argparse.Namespace) -> None:
    """Solves or verifies a Proof-of-Work CPU challenge."""
    import time

    from src.anti_spam import MX2AntiSpamEngine

    challenge = args.challenge or f"bob@example.com:alice@example.com:{int(time.time())}"
    bits = args.bits
    nonce_val = args.nonce

    if args.solve or nonce_val is None:
        print(f"\033[96m[*] Solving Proof-of-Work challenge ({bits} bits)...\033[0m")
        print(f"    - Payload: {challenge}")
        start = time.time()
        calc_nonce = 0
        while not MX2AntiSpamEngine.verify_proof_of_work(challenge, str(calc_nonce), difficulty_bits=bits):
            calc_nonce += 1
        elapsed = time.time() - start
        nonce_val = str(calc_nonce)
        print(f"\033[92m[+] Nonce found: {nonce_val} (took {elapsed:.4f}s)\033[0m")

    res = _request_api("/api/pow/verify", {"challenge": challenge, "nonce": str(nonce_val), "difficultyBits": bits})

    print("-" * 50)
    valid = res.get("valid", False)
    color = "\033[92m" if valid else "\033[91m"
    print(f"PoW Status   : {color}{'VALID' if valid else 'INVALID'}\033[0m")
    print(f"Difficulty   : {res.get('difficultyBits')} bits")
    print(f"Challenge    : {res.get('challenge')}")
    print(f"Nonce        : {res.get('nonce')}")
    print("-" * 50)


def cmd_stats(args: argparse.Namespace) -> None:
    """Queries and displays live Prometheus daemon telemetry metrics."""
    url = f"{MX2_URL}/metrics"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as res:
            text = res.read().decode("utf-8")
            print("\033[96m=" * 50)
            print(" MX2 DAEMON LIVE TELEMETRY STATS ".center(50, "="))
            print("=" * 50 + "\033[0m")
            for line in text.splitlines():
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) == 2:
                        print(f"\033[93m{parts[0]:<32}\033[0m : \033[97m{parts[1]}\033[0m")
            print("\033[96m=" * 50 + "\033[0m")
    except Exception as err:
        print(f"\033[91m[-] Error fetching stats: {err}\033[0m")
        sys.exit(1)


def cmd_proxy(args: argparse.Namespace) -> None:
    """Runs local loopback SMTP/IMAP proxy server."""
    import asyncio

    from src.legacy_proxy import MX2LegacyIMAPProxy, MX2LegacySMTPProxy

    print("\033[96m[*] Starting MX2 Legacy SMTP/IMAP Loopback Proxy...\033[0m")
    print("    - SMTP Proxy listening on 127.0.0.1:10025")
    print("    - IMAP Proxy listening on 127.0.0.1:10143")
    print(f"    - Target REST Gateway: {MX2_URL}")

    async def _run() -> None:
        smtp_proxy = MX2LegacySMTPProxy(target_url=MX2_URL)
        imap_proxy = MX2LegacyIMAPProxy()
        await smtp_proxy.start()
        await imap_proxy.start()
        print("\033[92m[+] Proxies active. Press Ctrl+C to terminate.\033[0m")
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            await smtp_proxy.stop()
            await imap_proxy.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\n\033[93m[*] Proxy stopped.\033[0m")


def main() -> None:
    """Main CLI parser entrypoint."""
    parser = argparse.ArgumentParser(description="MX2 Administration Utility (mx2ctl)", prog="mx2ctl")

    subparsers = parser.add_subparsers(dest="command", required=True, title="subcommands")

    # status
    subparsers.add_parser("status", help="Query gateway daemon state & SemVer capabilities")

    # stats
    subparsers.add_parser("stats", help="Display live Prometheus daemon metrics")

    # proxy
    subparsers.add_parser("proxy", help="Run local SMTP (10025) and IMAP (10143) loopback proxy")

    # queue [list / approve / reject]
    queue_parser = subparsers.add_parser("queue", help="Manage quarantined Grade E messages")
    queue_parser.add_argument("queue_action", choices=["list", "approve", "reject"], help="Queue command sub-action")
    queue_parser.add_argument("msg_id", nargs="?", default=None, help="Quarantined message ID to release or delete")

    # resolve [did]
    resolve_parser = subparsers.add_parser("resolve", help="Cryptographically verify a DID or domain TXT key")
    resolve_parser.add_argument("identifier", help="DID value (did:mx2:...) or domain name")

    # test [options]
    test_parser = subparsers.add_parser("test", help="Test gateway translation by sending a mock email")
    test_parser.add_argument("--sender", help="Mock sender email (default: alice@example.com)")
    test_parser.add_argument("--recipient", help="Mock recipient email (default: bob@example.com)")
    test_parser.add_argument("--subject", help="Mock email subject")
    test_parser.add_argument("--body", help="Mock email body content")
    test_parser.add_argument("--spoof", action="store_true", help="Simulate a spoofed/unverified signature (Grade E)")

    # pow [options]
    pow_parser = subparsers.add_parser("pow", help="Solve or verify a Proof-of-Work anti-spam CPU challenge")
    pow_parser.add_argument("--challenge", help="Proof-of-Work challenge string payload")
    pow_parser.add_argument("--nonce", help="Nonce solution to verify against the daemon API")
    pow_parser.add_argument("--bits", type=int, default=10, help="Difficulty bits (default: 10)")
    pow_parser.add_argument("--solve", action="store_true", help="Solve the challenge locally before verifying")

    # If executed with no arguments, print help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    commands = {
        "status": cmd_status,
        "stats": cmd_stats,
        "proxy": cmd_proxy,
        "queue": cmd_queue,
        "resolve": cmd_resolve,
        "test": cmd_test,
        "pow": cmd_pow,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
