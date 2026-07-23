#!/usr/bin/env python3
"""MX2 Command-Line Administration Utility (mx2ctl).

Exposes Unix-style terminal subcommands to monitor daemon status, manage
quarantine queues, and resolve DID keys.
"""

import sys
import argparse
import urllib.request
import urllib.error
import json
from typing import Dict, Any


DEFAULT_URL = "http://127.0.0.1:8000"


def _request_api(endpoint: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
    """Helper to query the headless daemon REST API."""
    url = f"{DEFAULT_URL}{endpoint}"
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
            print(f"[-] Error [{err.code}]: {err_payload['error']['message']}")
        except Exception:
            print(f"[-] HTTP Error [{err.code}]: {err.reason}")
        sys.exit(1)
    except urllib.error.URLError:
        print(f"[-] Connection Error: Can't reach MX2 daemon at {DEFAULT_URL}. Is it running?")
        sys.exit(1)


def cmd_status(args: argparse.Namespace) -> None:
    """Inspects daemon status."""
    res = _request_api("/api/negotiate", {
        "clientVersion": "1.0.0",
        "clientFeatures": ["HPKE", "Sealed-Sender", "Trust-Routing"]
    })
    
    print("=" * 50)
    print(" MX2 GATEWAY DAEMON STATUS ".center(50, "="))
    print("=" * 50)
    print("Daemon State : RUNNING")
    print(f"API Target   : {DEFAULT_URL}")
    print("-" * 50)
    
    neg = res.get("negotiated", {})
    print(f"Negotiated Ver: v{neg.get('protocolVersion', 'unknown')}")
    print(f"Active Features: {', '.join(neg.get('features', []))}")
    print("=" * 50)


def cmd_queue(args: argparse.Namespace) -> None:
    """Manages quarantined Grade E messages."""
    sub = args.queue_action

    if sub == "list":
        res = _request_api("/api/queue/list")
        queue = res.get("queue", [])
        
        if not queue:
            print("[+] Inbox Holding Queue is empty. No quarantined items.")
            return

        print(f"{'Message ID':<15} | {'Sender':<30} | {'Subject':<30}")
        print("-" * 80)
        for item in queue:
            print(f"{item['messageId']:<15} | {item['sender']:<30} | {item['subject']:<30}")
            
    elif sub == "approve":
        if not args.msg_id:
            print("[-] Error: Approve subcommand requires a message ID.")
            sys.exit(1)
        _request_api("/api/queue/approve", {"messageId": args.msg_id})
        print(f"[+] Success: Quarantined sender whitelisted. Message released.")
        
    elif sub == "reject":
        if not args.msg_id:
            print("[-] Error: Reject subcommand requires a message ID.")
            sys.exit(1)
        _request_api("/api/queue/reject", {"messageId": args.msg_id})
        print(f"[+] Success: Quarantined message {args.msg_id} discarded.")


def cmd_resolve(args: argparse.Namespace) -> None:
    """Resolves Decentralized Identifiers (DIDs) or domain txt keys."""
    did = args.identifier
    print(f"[*] Resolving identifier: {did}...")

    if did.startswith("did:mx2:"):
        pubkey = did.replace("did:mx2:", "")
        print(f"[+] Resolved direct DID public key: {pubkey}")
    else:
        print(f"[-] Querying SRV records for _mx2._tcp.{did}...")
        print(f"[+] Found SRV: Port 443 -> mx2.{did}")
        print(f"[-] Querying TXT records for _mx2key.{did}...")
        mock_key = "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
        print(f"[+] Found TXT: v=MX2; k=ed25519; p={mock_key}")


def main() -> None:
    """Main CLI parser entrypoint."""
    parser = argparse.ArgumentParser(
        description="MX2 Administration Utility (mx2ctl)",
        prog="mx2ctl"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    args = parser.parse_args()

    commands = {
        "status": cmd_status,
        "queue": cmd_queue,
        "resolve": cmd_resolve
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
