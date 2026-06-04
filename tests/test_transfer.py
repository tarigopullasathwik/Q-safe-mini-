"""Tests for encrypted file transfer simulation."""

from __future__ import annotations

from pathlib import Path

import pytest

from encryption.aes import encrypt_file, generate_key
from transfer.file_transfer import (
    TRANSFER_STATUSES,
    TransferSender,
    simulate_file_transfer,
)


def test_transfer_sender_rejects_plaintext(tmp_path, isolated_db) -> None:
    plaintext = tmp_path / "plain.txt"
    plaintext.write_text("not encrypted", encoding="utf-8")

    sender = TransferSender("tid-1", "Alice", "Bob", plaintext)

    with pytest.raises(ValueError, match="encrypted .enc file"):
        sender.confirm_encrypted_payload()


def test_simulate_transfer_verifies_integrity(tmp_path, isolated_db) -> None:
    source = tmp_path / "payload.txt"
    source.write_bytes(b"transfer-me")
    key = generate_key()
    encrypted = encrypt_file(source, key)

    dest_dir = tmp_path / "inbox"
    result = simulate_file_transfer(encrypted, dest_dir, simulate_tampering=False)

    assert result["integrity_verified"] is True
    assert result["status"] == "VERIFIED"
    assert result["sender_hash"] == result["receiver_hash"]
    assert Path(result["destination_file"]).exists()
    statuses = [event["status"] for event in result["events"]]
    assert statuses == list(TRANSFER_STATUSES)


def test_simulate_transfer_detects_tampering(tmp_path, isolated_db) -> None:
    source = tmp_path / "payload.txt"
    source.write_bytes(b"tamper-target")
    encrypted = encrypt_file(source, generate_key())

    dest_dir = tmp_path / "inbox"
    result = simulate_file_transfer(encrypted, dest_dir, simulate_tampering=True)

    assert result["integrity_verified"] is False
    assert result["status"] == "FAILED"
    assert result["sender_hash"] != result["receiver_hash"]
