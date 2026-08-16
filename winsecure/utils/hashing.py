"""
WinSecure Cryptographic and Hashing Utilities
"""
import hashlib
import os
from typing import Optional, Union


def compute_sha256(data: Union[str, bytes]) -> str:
    """Computes the SHA-256 hash of a string or byte array."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(file_path: str) -> Optional[str]:
    """Computes the SHA-256 hash of an entire file."""
    if not os.path.isfile(file_path):
        return None
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
