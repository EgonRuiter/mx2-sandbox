"""Unit tests for the MX2 Content-Addressable Storage (CAS) engine."""

import os
import shutil
import tempfile
import unittest

from src.cas import MX2CASEngine


class TestMX2CASEngine(unittest.TestCase):
    """Test suite for the MX2CASEngine validating file deduplication."""

    def setUp(self) -> None:
        """Sets up a temporary storage directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.engine = MX2CASEngine(base_dir=self.test_dir)

    def tearDown(self) -> None:
        """Removes the temporary directory after tests complete."""
        shutil.rmtree(self.test_dir)

    def test_write_and_read_text(self) -> None:
        """Verifies text content can be written to and read from CAS."""
        content = "Collaborative Thread Draft v8"
        sha256, uri = self.engine.write(content)

        self.assertEqual(uri, f"cas://sha256/{sha256}")
        self.assertTrue(self.engine.exists(sha256))

        # Check content match
        read_bytes = self.engine.read(sha256)
        self.assertEqual(read_bytes.decode("utf-8"), content)

    def test_write_deduplication(self) -> None:
        """Verifies duplicate contents are stored exactly once on disk."""
        content = "Binary blob test data"
        sha256_1, _ = self.engine.write(content)
        sha256_2, _ = self.engine.write(content)

        # Hash matches
        self.assertEqual(sha256_1, sha256_2)

        # Verify exactly one file exists in the directory
        files_list = os.listdir(self.test_dir)
        self.assertEqual(len(files_list), 1)

    def test_read_missing_hash_raises_error(self) -> None:
        """Reading a non-existent hash raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.engine.read("non_existent_sha256_hash_value_12345")


if __name__ == "__main__":
    unittest.main()
