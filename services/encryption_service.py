"""Encryption service layer for Q-SAFE Nexus."""

from pathlib import Path

from analyzer.pqc_scanner import calculate_sha256
from encryption.aes import encrypt_file


def encrypt_uploaded_file(file_path: str | Path, key: bytes) -> dict:
    """Encrypt an uploaded file and return encryption metadata.

    Security note: callers receive the encrypted file hash so integrity can be
    verified later without relying on plaintext retention.
    """
    encrypted_path = encrypt_file(file_path, key)

    return {
        "encrypted_path": encrypted_path,
        "encrypted_file_name": encrypted_path.name,
        "encrypted_hash": calculate_sha256(encrypted_path),
        "encryption_status": "Encrypted",
    }
