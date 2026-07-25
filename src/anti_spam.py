"""MX2 Automated Trust Routing Spam Engine.

This module implements the 5-tiered Automated Trust Grading system (A-E),
routing messages to the Inbox, Junk, or Quarantine Queue based on identity keys,
WoT vouches, shared social graphs, and signature verification.
"""

import base64
import hashlib
import time
from typing import Any, Optional


class MX2AntiSpamEngine:
    """Automated Trust Engine evaluating sender identity profiles.

    Attributes:
        quota_limit (int): Hourly free message threshold.
        quota_history (dict): Timestamps of sent messages.
        holding_queue (list): Quarantined emails from unverified senders.
        whitelisted_senders (set): Sender domains/identities manually approved.
        contacts_database (dict): Hashed/mock social contact directory.
    """

    # Established high-reputation domain names
    REPUTABLE_DOMAINS: set[str] = {"github.com", "google.com", "utrecht-uni.nl", "trusted.nl", "trusted.com"}

    def __init__(self, quota_limit: int = 100, storage_engine: Optional[Any] = None) -> None:
        """Initializes the trust engine with default settings and optional persistent storage.

        Args:
            quota_limit (int): Hourly free message threshold. Defaults to 100.
            storage_engine (Optional[Any]): Persistent storage engine instance.
        """
        self.quota_limit = quota_limit
        # Key: (sender_domain, recipient_domain) -> List of timestamps (floats)
        self.quota_history: dict[tuple[str, str], list[float]] = {}
        self._holding_queue: list[dict[str, Any]] = []
        self._whitelisted_senders: set[str] = set()
        self.storage_engine = storage_engine

        # Mock Social Graph contacts for Grade C evaluation
        self.contacts_database: dict[str, set[str]] = {
            "bob@example.com": {"friend@collaborator.com", "partner@startup.nl"}
        }

    @property
    def holding_queue(self) -> list[dict[str, Any]]:
        """Returns holding queue from persistent storage engine or memory fallback."""
        if self.storage_engine:
            return self.storage_engine.get_holding_queue()
        return self._holding_queue

    @property
    def whitelisted_senders(self) -> set[str]:
        """Returns whitelisted senders set from persistent storage engine or memory fallback."""
        if self.storage_engine:
            return self.storage_engine.get_whitelisted_set().union(self._whitelisted_senders)
        return self._whitelisted_senders

    def record_message(self, sender_domain: str, recipient_domain: str) -> None:
        """Records a message transmission for rate-limiting calculations.

        Args:
            sender_domain (str): Domain of the sender.
            recipient_domain (str): Domain of the recipient.
        """
        key = (sender_domain.lower().strip(), recipient_domain.lower().strip())
        current_time = time.time()
        if key not in self.quota_history:
            self.quota_history[key] = []
        self.quota_history[key].append(current_time)

    def get_hourly_count(self, sender_domain: str, recipient_domain: str) -> int:
        """Returns the number of messages sent in the last hour, pruning old records.

        Args:
            sender_domain (str): Domain of the sender.
            recipient_domain (str): Domain of the recipient.

        Returns:
            int: The active message count in the last hour.
        """
        key = (sender_domain.lower().strip(), recipient_domain.lower().strip())
        if key not in self.quota_history:
            return 0

        current_time = time.time()
        one_hour_ago = current_time - 3600.0

        # Efficient list comprehension to filter out timestamps older than 1 hour
        history = [t for t in self.quota_history[key] if t > one_hour_ago]
        self.quota_history[key] = history

        return len(history)

    def verify_vouch_token(self, token: dict[str, Any], voucher_public_key: str) -> bool:
        """Verifies a Web of Trust vouching token signature (Ed25519 with mock fallback).

        Args:
            token (dict): Cryptographic token dictionary.
            voucher_public_key (str): Public key of the vouching domain.

        Returns:
            bool: True if the vouching token signature is valid, False otherwise.
        """
        if not token:
            return False

        try:
            vouched = token.get("vouchedDomain", "")
            voucher = token.get("voucherDomain", "")
            expires_val = token.get("expires", "0")
            signature = token.get("signature", "")

            # Check expiration
            if float(expires_val) < time.time():
                return False

            # 1. Try real Ed25519 signature verification
            try:
                from src.gateway import parse_ed25519_public_key

                pub_key = parse_ed25519_public_key(voucher_public_key)
                sig_bytes = base64.b64decode(signature)
                data_to_verify = f"{voucher}_{vouched}_{expires_val}".encode()
                pub_key.verify(sig_bytes, data_to_verify)
                return True
            except Exception:
                pass

            # 2. Fallback to mock signature format
            expected_sig = f"sig_{voucher}_{vouched}_{voucher_public_key[:6]}"
            return signature == expected_sig
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def verify_proof_of_work(challenge_payload: str, nonce: str, difficulty_bits: int = 10) -> bool:
        """Verifies a Proof-of-Work challenge by counting leading zero bits in SHA-256."""
        hash_input = f"{challenge_payload}:{nonce}".encode()
        h = hashlib.sha256(hash_input).digest()

        total_zero_bits = 0
        for byte in h:
            if byte == 0:
                total_zero_bits += 8
            else:
                binary_str = f"{byte:08b}"
                leading_zeros = len(binary_str) - len(binary_str.lstrip("0"))
                total_zero_bits += leading_zeros
                break
        return total_zero_bits >= difficulty_bits

    def evaluate_trust_grade(
        self,
        sender: str,
        sender_domain: str,
        recipient: str,
        vouch_token: dict[str, Any] = None,
        voucher_pubkey: str = "",
        signature_valid: bool = True,
    ) -> dict[str, Any]:
        """Evaluates sender context and computes the Automated Trust Grade.

        Args:
            sender (str): Email/identity of the sender.
            sender_domain (str): Domain of the sender.
            recipient (str): Email of the recipient.
            vouch_token (dict): Optional vouching token.
            voucher_pubkey (str): Public key of the voucher domain.
            signature_valid (bool): Verification state of sender identity keys.

        Returns:
            Dict[str, Any]: Dictionary containing "grade", "destination", and "reason".
        """
        sender_clean = sender.lower().strip()
        sender_domain_clean = sender_domain.lower().strip()
        recipient_clean = recipient.lower().strip()

        # Grade E: Unverified / Spoofed Identity -> Quarantine
        if not signature_valid:
            return {
                "grade": "E",
                "destination": "Quarantine",
                "reason": "Authenticatiefout: handtekening van afzender komt niet overeen met DNS/DID-sleutel.",
            }

        # Grade A: Reputable / Whitelisted Domain -> Inbox
        if sender_clean in self.whitelisted_senders or sender_domain_clean in self.whitelisted_senders:
            return {
                "grade": "A",
                "destination": "Inbox",
                "reason": "Zender staat expliciet op de whitelist van de ontvanger.",
            }

        if sender_domain_clean in self.REPUTABLE_DOMAINS:
            return {
                "grade": "A",
                "destination": "Inbox",
                "reason": "Gevestigde domeinreputatie via DNSSEC/DID-verificatie.",
            }

        # Grade B: Web of Trust Vouched -> Inbox
        if vouch_token and voucher_pubkey:
            if self.verify_vouch_token(vouch_token, voucher_pubkey):
                voucher_domain = vouch_token.get("voucherDomain", "").lower().strip()
                if voucher_domain in self.REPUTABLE_DOMAINS:
                    return {
                        "grade": "B",
                        "destination": "Inbox",
                        "reason": f"Nieuw domein succesvol geverifieerd via Vouching Token van '{voucher_domain}'.",
                    }

        # Grade C: Shared Social Graph contact -> Inbox
        if recipient_clean in self.contacts_database:
            if sender_clean in self.contacts_database[recipient_clean]:
                return {
                    "grade": "C",
                    "destination": "Inbox",
                    "reason": "Gemeenschappelijk contact of gedeelde connectie gevonden in sociaal netwerk.",
                }

        # Grade D: Unknown Sender -> Junk (Auto-delivered, no user interruption)
        return {
            "grade": "D",
            "destination": "Junk",
            "reason": "Onbekende afzender met geldige cryptografische handtekening, maar zonder WoT-garantie.",
        }

    def quarantine_message(self, message_id: str, sender: str, subject: str, envelope: dict) -> None:
        """Quarantines a Grade E message into the holding queue.

        Args:
            message_id (str): Generated message identifier.
            sender (str): Email address of the sender.
            subject (str): Subject line.
            envelope (dict): Outer envelope dict.
        """
        if self.storage_engine:
            self.storage_engine.quarantine_message(message_id, sender, subject, envelope)
            return

        if any(msg["messageId"] == message_id for msg in self._holding_queue):
            return

        self._holding_queue.append(
            {
                "messageId": message_id,
                "sender": sender,
                "subject": subject,
                "envelope": envelope,
                "timestamp": time.time(),
            }
        )

    def approve_quarantined_sender(self, message_id: str) -> tuple[bool, dict[str, Any]]:
        """Approves a quarantined message, whitelisting its sender identity.

        Args:
            message_id (str): The quarantined message id.

        Returns:
            Tuple[bool, dict]: (Success, Approved message dictionary).
        """
        if self.storage_engine:
            return self.storage_engine.approve_quarantined_sender(message_id)

        for i, msg in enumerate(self._holding_queue):
            if msg["messageId"] == message_id:
                sender_domain = msg["sender"].split("@")[-1].lower().strip()
                self._whitelisted_senders.add(msg["sender"].lower().strip())
                self._whitelisted_senders.add(sender_domain)
                approved_msg = self._holding_queue.pop(i)
                return True, approved_msg
        return False, {}

    def reject_quarantined_sender(self, message_id: str) -> bool:
        """Rejects a quarantined message, discarding it from the queue.

        Args:
            message_id (str): The quarantined message id.

        Returns:
            bool: True if removed, False otherwise.
        """
        if self.storage_engine:
            return self.storage_engine.reject_quarantined_sender(message_id)

        for i, msg in enumerate(self._holding_queue):
            if msg["messageId"] == message_id:
                self._holding_queue.pop(i)
                return True
        return False
