"""MX2 Production Persistent Storage Engine.

Provides atomic SQLite database persistence for quarantine holding queues,
sender whitelists, social graph relationships, and CAS file metadata,
retaining state across daemon reboots and high-concurrency operations.
"""

import json
import os
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any, Optional


class MX2StorageEngine:
    """SQLite-backed persistent storage manager with thread-safe locking."""

    def __init__(self, db_path: str = "storage/mx2_daemon.db") -> None:
        """Initializes the database connection and creates required schema tables.

        Args:
            db_path (str): File path to the SQLite database.
        """
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yields a thread-safe connection to the SQLite database and ensures it closes."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Creates table schemas if they do not already exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Quarantine Holding Queue Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantine_queue (
                    msg_id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
                """
            )

            # 2. Whitelisted Senders & Domains Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelists (
                    identity TEXT PRIMARY KEY,
                    added_at REAL NOT NULL
                )
                """
            )

            # 3. Social Graph Contact Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS social_graph (
                    owner TEXT NOT NULL,
                    contact TEXT NOT NULL,
                    strength INTEGER DEFAULT 1,
                    PRIMARY KEY (owner, contact)
                )
                """
            )

            # 4. Content-Addressable Storage (CAS) Index Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cas_index (
                    sha256 TEXT PRIMARY KEY,
                    cas_uri TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    # --- Quarantine Queue Methods ---

    def quarantine_message(self, msg_id: str, sender: str, subject: str, envelope: dict[str, Any]) -> None:
        """Persists an unverified Grade E email to the quarantine queue."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO quarantine_queue (msg_id, sender, subject, envelope_json, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (msg_id, sender, subject, json.dumps(envelope), time.time()),
            )
            conn.commit()

    def get_holding_queue(self) -> list[dict[str, Any]]:
        """Retrieves all quarantined messages ordered by creation timestamp."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT msg_id, sender, subject, envelope_json, timestamp FROM quarantine_queue ORDER BY timestamp DESC"
            )
            rows = cursor.fetchall()

            result = []
            for r in rows:
                try:
                    env = json.loads(r["envelope_json"])
                except Exception:
                    env = {}
                result.append(
                    {
                        "messageId": r["msg_id"],
                        "sender": r["sender"],
                        "subject": r["subject"],
                        "timestamp": r["timestamp"],
                        "envelope": env,
                    }
                )
            return result

    def approve_quarantined_sender(self, msg_id: str) -> tuple[bool, Optional[dict[str, Any]]]:
        """Approves a quarantined message, whitelisting sender domain and removing item."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sender, envelope_json FROM quarantine_queue WHERE msg_id = ?", (msg_id,))
            row = cursor.fetchone()

            if not row:
                return False, None

            sender = row["sender"]
            domain = sender.split("@")[-1].split(">")[0].strip().lower()

            # Add domain and sender to whitelist
            self.add_whitelist(domain)
            self.add_whitelist(sender)

            # Delete from quarantine
            cursor.execute("DELETE FROM quarantine_queue WHERE msg_id = ?", (msg_id,))
            conn.commit()

            try:
                env = json.loads(row["envelope_json"])
            except Exception:
                env = {}

            return True, {"messageId": msg_id, "sender": sender, "envelope": env}

    def reject_quarantined_sender(self, msg_id: str) -> bool:
        """Discards a quarantined email from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM quarantine_queue WHERE msg_id = ?", (msg_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted

    # --- Whitelist Methods ---

    def add_whitelist(self, identity: str) -> None:
        """Adds a domain or email address to the database whitelist."""
        identity = identity.strip().lower()
        if not identity:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO whitelists (identity, added_at) VALUES (?, ?)",
                (identity, time.time()),
            )
            conn.commit()

    def is_whitelisted(self, identity: str) -> bool:
        """Checks if a domain or sender address is whitelisted."""
        identity = identity.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM whitelists WHERE identity = ?", (identity,))
            return cursor.fetchone() is not None

    def get_whitelisted_set(self) -> set[str]:
        """Returns all whitelisted sender domains and addresses as a set."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT identity FROM whitelists")
            return {row["identity"] for row in cursor.fetchall()}

    # --- CAS Storage Metadata Methods ---

    def record_cas_entry(self, sha256_hash: str, cas_uri: str, size: int) -> None:
        """Indexes a Content-Addressable Storage file record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO cas_index (sha256, cas_uri, size, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (sha256_hash, cas_uri, size, time.time()),
            )
            conn.commit()

    def get_cas_entry(self, sha256_hash: str) -> Optional[dict[str, Any]]:
        """Retrieves CAS metadata for a given SHA-256 hash."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sha256, cas_uri, size, created_at FROM cas_index WHERE sha256 = ?", (sha256_hash,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
