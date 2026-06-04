"""Tests for AES-GCM file encryption helpers."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from encryption.aes import KEY_SIZE_BITS, NONCE_SIZE, decrypt_file, encrypt_file, generate_key


def test_generate_key_length() -> None:
    key = generate_key()
    assert len(key) == KEY_SIZE_BITS // 8


def test_encrypt_creates_enc_file(tmp_path, aes_key: bytes) -> None:
    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("quantum-safe payload", encoding="utf-8")

    encrypted_path = encrypt_file(plaintext, aes_key)

    assert encrypted_path.exists()
    assert encrypted_path.suffix == ".enc"
    assert encrypted_path.name == "secret.txt.enc"
    assert len(encrypted_path.read_bytes()) > NONCE_SIZE


def test_encrypt_decrypt_roundtrip(tmp_path, aes_key: bytes) -> None:
    original = b"round-trip-bytes-12345"
    source = tmp_path / "data.bin"
    source.write_bytes(original)

    encrypted_path = encrypt_file(source, aes_key)
    decrypted_path = decrypt_file(encrypted_path, aes_key)

    assert decrypted_path.read_bytes() == original


def test_decrypt_with_wrong_key_fails(tmp_path, aes_key: bytes) -> None:
    source = tmp_path / "locked.bin"
    source.write_bytes(b"protected")

    encrypted_path = encrypt_file(source, aes_key)
    wrong_key = generate_key()

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted_path, wrong_key)
