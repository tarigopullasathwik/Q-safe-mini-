"""Tests for MITM attack simulation and detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.score_engine import compute_security_score
from encryption.aes import encrypt_file, generate_key
from services.attack_service import get_attack_logs, get_attacks_by_type, log_mitm_attack
from services.score_service import evaluate_security_score
from transfer.file_transfer import MITM_TRANSFER_STATUSES, simulate_file_transfer
from transfer.mitm_simulator import (
    ATTACK_STATUS_DETECTED,
    ATTACK_TYPE,
    INTEGRITY_FAILED,
    build_mitm_outcome,
    intercept_and_modify,
)


def test_mitm_modifies_encrypted_payload(tmp_path: Path) -> None:
    source = tmp_path / "secret.txt"
    source.write_bytes(b"payload")
    encrypted = encrypt_file(source, generate_key())
    original_ciphertext = encrypted.read_bytes()

    result = intercept_and_modify(encrypted)

    assert result["bytes_modified"] >= 1
    assert result["sender_hash_before"] != result["sender_hash_after"]
    assert encrypted.read_bytes() != original_ciphertext


def test_mitm_transfer_integrity_fails(tmp_path: Path, isolated_db: Path) -> None:
    source = tmp_path / "data.txt"
    source.write_bytes(b"mitm-target")
    encrypted = encrypt_file(source, generate_key())

    transfer = simulate_file_transfer(
        encrypted,
        tmp_path / "inbox",
        simulate_mitm=True,
    )

    assert transfer["integrity_verified"] is False
    assert transfer["sender_hash"] != transfer["receiver_hash"]
    assert transfer["status"] == "COMPROMISED"
    assert transfer["compromised"] is True
    assert transfer["mitm"] is not None
    assert transfer["mitm"]["attack_status"] == ATTACK_STATUS_DETECTED
    assert transfer["mitm"]["integrity_result"] == INTEGRITY_FAILED

    statuses = [event["status"] for event in transfer["events"]]
    assert statuses == list(MITM_TRANSFER_STATUSES)


def test_mitm_attack_event_stored(tmp_path: Path, isolated_db: Path) -> None:
    source = tmp_path / "log.txt"
    source.write_bytes(b"log-me")
    encrypted = encrypt_file(source, generate_key())

    transfer = simulate_file_transfer(encrypted, tmp_path / "inbox", simulate_mitm=True)
    logged = log_mitm_attack(transfer["mitm"])

    assert logged["attack_type"] == ATTACK_TYPE
    assert logged["attack_id"] == transfer["mitm"]["attack_id"]
    assert logged["transfer_id"] == transfer["transfer_id"]
    assert logged["attack_status"] == ATTACK_STATUS_DETECTED
    assert logged["integrity_result"] == INTEGRITY_FAILED
    assert logged["timestamp"]

    mitm_rows = get_attacks_by_type("MITM", limit=5)
    assert any(row["attack_id"] == logged["attack_id"] for row in mitm_rows)
    assert get_attack_logs(limit=1)[0]["attack_id"] == logged["attack_id"]


def test_mitm_lowers_security_score() -> None:
    clean = evaluate_security_score(
        encryption_status="Encrypted",
        bb84_qber=0.02,
        transfer_integrity=True,
        security_status="SAFE",
        mitm_attack_status="CLEAN",
    )
    detected = evaluate_security_score(
        encryption_status="Encrypted",
        bb84_qber=0.02,
        transfer_integrity=False,
        security_status="SAFE",
        mitm_attack_status=ATTACK_STATUS_DETECTED,
    )

    assert detected.score < clean.score
    assert detected.dimensions.attack == 0
    assert clean.dimensions.attack == 10


def test_mitm_detected_maps_to_score_engine() -> None:
    result = compute_security_score(
        encryption_status="Encrypted",
        bb84_qber=0.02,
        transfer_integrity=False,
        security_status="SAFE",
        attack_status=ATTACK_STATUS_DETECTED,
    )
    assert result.dimensions.attack == 0


def test_normal_transfer_still_verified(tmp_path: Path, isolated_db: Path) -> None:
    source = tmp_path / "ok.txt"
    source.write_bytes(b"clean")
    encrypted = encrypt_file(source, generate_key())

    transfer = simulate_file_transfer(encrypted, tmp_path / "inbox")

    assert transfer["integrity_verified"] is True
    assert transfer["status"] == "VERIFIED"
    assert transfer["compromised"] is False
    assert transfer.get("mitm") is None


def test_build_mitm_outcome_structure() -> None:
    intercept = {
        "attack_id": "test-uuid",
        "attack_type": ATTACK_TYPE,
        "file_name": "file.txt.enc",
        "description": "intercepted",
    }
    outcome = build_mitm_outcome(
        intercept,
        transfer_id="transfer-1",
        sender_hash="aaa",
        receiver_hash="bbb",
        integrity_verified=False,
    )
    assert outcome["attack_status"] == ATTACK_STATUS_DETECTED
    assert outcome["integrity_result"] == INTEGRITY_FAILED
