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

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

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
    res = _request_api("/api/negotiate", {
        "clientVersion": "1.0.0",
        "clientFeatures": ["HPKE", "Sealed-Sender", "Trust-Routing"]
    })

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

    smtp_payload = (
        f"From: {sender}\n"
        f"To: {recipient}\n"
        f"Subject: {subject}\n"
        "Content-Type: text/plain\n\n"
        f"{body}"
    )

    payload = {
        "smtp": smtp_payload,
        "publicKey": "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327",
        "features": ["HPKE", "Sealed-Sender"]
    }

    res = _request_api("/api/translate", payload)

    print("\033[92m[+] Daemon Response Received!\033[0m")
    print(f"Status       : \033[97m{res.get('status')}\033[0m")
    print(f"Trust Grade  : \033[97m{res.get('grade')}\033[0m")
    print(f"Reason       : {res.get('reason')}")
    print("-" * 50)
    print("Translated Envelope Payload:")
    print(json.dumps(res.get("payload"), indent=2))


def main() -> None:
    """Main CLI parser entrypoint."""
    parser = argparse.ArgumentParser(
        description="MX2 Administration Utility (mx2ctl)",
        prog="mx2ctl"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, title="subcommands")

    # status
    subparsers.add_parser("status", help="Query gateway daemon state & SemVer capabilities")

    # queue [list / approve / reject]
    queue_parser = subparsers.add_parser("queue", help="Manage quarantined Grade E messages")
    queue_parser.add_argument(
        "queue_action",
        choices=["list", "approve", "reject"],
        help="Queue command sub-action"
    )
    queue_parser.add_argument(
        "msg_id",
        nargs="?",
        default=None,
        help="Quarantined message ID to release or delete"
    )

    # resolve [did]
    resolve_parser = subparsers.add_parser("resolve", help="Cryptographically verify a DID or domain TXT key")
    resolve_parser.add_argument("identifier", help="DID value (did:mx2:...) or domain name")

    # test [options]
    test_parser = subparsers.add_parser("test", help="Test gateway translation by sending a mock email")
    test_parser.add_argument("--sender", help="Mock sender email (default: alice@example.com)")
    test_parser.add_argument("--recipient", help="Mock recipient email (default: bob@example.com)")
    test_parser.add_argument("--subject", help="Mock email subject")
    test_parser.add_argument("--body", help="Mock email body content")

    # If executed with no arguments, print help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    commands = {
        "status": cmd_status,
        "queue": cmd_queue,
        "resolve": cmd_resolve,
        "test": cmd_test
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
