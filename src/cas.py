"""MX2 Content-Addressable Storage (CAS) engine.

Deduplicates attachments by saving them exactly once using their cryptographically
secure SHA-256 hash.
"""

import hashlib
import os
from typing import Union


class MX2CASEngine:
    """Manages file reading, writing, and deduplication using SHA-256 hashes."""

    def __init__(self, base_dir: str = "") -> None:
        """Initializes the CAS engine.

        Args:
            base_dir (str): Root directory for file storage.
        """
        if not base_dir:
            # Default to <sandbox>/storage/cas
            base_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "storage",
                "cas"
            )
        self.storage_dir = base_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def write(self, data: Union[str, bytes]) -> tuple[str, str]:
        """Saves data to store, deduplicating if it already exists.

        Args:
            data (str or bytes): Attachment data to store.

        Returns:
            Tuple[str, str]: (sha256_hash, cas_uri)
        """
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        sha256_hash = hashlib.sha256(data_bytes).hexdigest()
        file_path = os.path.join(self.storage_dir, sha256_hash)

        # Deduplication check: if file exists, skip writing
        if not os.path.exists(file_path):
            with open(file_path, "wb") as f:
                f.write(data_bytes)

        return sha256_hash, f"cas://sha256/{sha256_hash}"

    def exists(self, sha256_hash: str) -> bool:
        """Checks if a hash exists in the storage directory.

        Args:
            sha256_hash (str): SHA-256 identifier.

        Returns:
            bool: True if found, False otherwise.
        """
        file_path = os.path.join(self.storage_dir, sha256_hash)
        return os.path.exists(file_path)

    def read(self, sha256_hash: str) -> bytes:
        """Reads and returns the data bytes for the given hash.

        Args:
            sha256_hash (str): SHA-256 identifier.

        Returns:
            bytes: Content bytes.

        Raises:
            FileNotFoundError: If the hash does not exist in the store.
        """
        file_path = os.path.join(self.storage_dir, sha256_hash)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Hash '{sha256_hash}' not found in CAS store.")

        with open(file_path, "rb") as f:
            return f.read()

    def get_path(self, sha256_hash: str) -> str:
        """Returns the absolute filesystem path for the given hash.

        Args:
            sha256_hash (str): SHA-256 identifier.

        Returns:
            str: Absolute path string.
        """
        return os.path.join(self.storage_dir, sha256_hash)
