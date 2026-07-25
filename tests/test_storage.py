"""Unit tests for the MX2 Persistent Storage Engine."""

import os
import tempfile
import unittest

from src.storage import MX2StorageEngine


class TestMX2StorageEngine(unittest.TestCase):
    """Test suite for MX2StorageEngine class with SQLite persistence."""

    def setUp(self) -> None:
        """Sets up a temporary SQLite database file for isolation."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_mx2.db")
        self.storage = MX2StorageEngine(db_path=self.db_path)

    def tearDown(self) -> None:
        """Cleans up temporary directory and database."""
        self.temp_dir.cleanup()

    def test_quarantine_flow(self) -> None:
        """Tests quarantining, listing, approving, and rejecting messages."""
        envelope = {"recipient": "bob@example.com", "encryptedPayload": "test_data"}

        # 1. Quarantine message
        self.storage.quarantine_message("q_1", "spammer@bad.com", "Free Money", envelope)
        queue = self.storage.get_holding_queue()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["messageId"], "q_1")
        self.assertEqual(queue[0]["sender"], "spammer@bad.com")

        # 2. Approve message
        success, approved = self.storage.approve_quarantined_sender("q_1")
        self.assertTrue(success)
        self.assertIsNotNone(approved)
        self.assertEqual(len(self.storage.get_holding_queue()), 0)

        # 3. Verify sender and domain are now whitelisted
        self.assertTrue(self.storage.is_whitelisted("spammer@bad.com"))
        self.assertTrue(self.storage.is_whitelisted("bad.com"))

        # 4. Reject message flow
        self.storage.quarantine_message("q_2", "junk@spam.org", "Win Cash", envelope)
        self.assertEqual(len(self.storage.get_holding_queue()), 1)
        rejected = self.storage.reject_quarantined_sender("q_2")
        self.assertTrue(rejected)
        self.assertEqual(len(self.storage.get_holding_queue()), 0)

    def test_cas_index_storage(self) -> None:
        """Tests recording and retrieving CAS file index records."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cas_uri = f"cas://sha256/{sha256}"

        self.storage.record_cas_entry(sha256, cas_uri, 1024)
        entry = self.storage.get_cas_entry(sha256)

        self.assertIsNotNone(entry)
        self.assertEqual(entry["sha256"], sha256)
        self.assertEqual(entry["cas_uri"], cas_uri)
        self.assertEqual(entry["size"], 1024)


if __name__ == "__main__":
    unittest.main()
