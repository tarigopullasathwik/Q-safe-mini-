"""Man-in-the-Middle (MITM) attack simulation for Q-SAFE Nexus.

Educational simulation only: an attacker (Eve) intercepts ciphertext in
transit, modifies the encrypted payload, and relies on SHA-256 verification at
the receiver to detect the alteration. This module is independent of the core
transfer state machine and can be invoked from services or tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from analyzer.pqc_scanner import calculate_sha256

ATTACK_TYPE = "MITM"
ATTACKER_ID = "Eve"

# attack_status values persisted for dashboard / scoring integration
ATTACK_STATUS_DETECTED = "DETECTED"
ATTACK_STATUS_SUCCESSFUL = "SUCCESSFUL"  # reserved: attacker evades detection

INTEGRITY_VERIFIED = "VERIFIED"
INTEGRITY_FAILED = "FAILED"


def intercept_and_modify(
    encrypted_path: str | Path,
    *,
    attack_id: str | None = None,
) -> dict[str, Any]:
    """Simulate MITM interception by altering ciphertext bytes in place.

  Security note: only encrypted ``.enc`` artifacts should be targeted so the
  exercise models in-transit tampering, not plaintext exposure.
    """
    path = Path(encrypted_path)
    if not path.exists():
        raise FileNotFoundError(f"Encrypted payload not found: {path}")
    if path.suffix != ".enc":
        raise ValueError("MITM simulation requires an encrypted .enc file.")

    attack_id = attack_id or str(uuid4())
    sender_hash_before = calculate_sha256(path)

    content = bytearray(path.read_bytes())
    bytes_modified = 0
    if content:
        content[0] ^= 0xFF
        bytes_modified = 1
    else:
        content.extend(b"MITM_TAMPERED")
        bytes_modified = len(content)

    path.write_bytes(content)
    sender_hash_after = calculate_sha256(path)

    return {
        "attack_id": attack_id,
        "attack_type": ATTACK_TYPE,
        "attacker_id": ATTACKER_ID,
        "file_name": path.name,
        "sender_hash_before": sender_hash_before,
        "sender_hash_after": sender_hash_after,
        "bytes_modified": bytes_modified,
        "description": (
            f"MITM intercept by {ATTACKER_ID}: modified {bytes_modified} byte(s) "
            f"of ciphertext {path.name}. Pre-intercept SHA-256: {sender_hash_before[:16]}…"
        ),
    }


def classify_integrity_result(integrity_verified: bool) -> str:
    """Map boolean verification to a persisted integrity_result label."""
    return INTEGRITY_VERIFIED if integrity_verified else INTEGRITY_FAILED


def classify_attack_status(integrity_verified: bool) -> str:
    """Derive attack_status from whether integrity verification caught the MITM."""
    if integrity_verified:
        return ATTACK_STATUS_SUCCESSFUL
    return ATTACK_STATUS_DETECTED


def build_mitm_outcome(
    intercept_event: dict[str, Any],
    *,
    transfer_id: str,
    sender_hash: str,
    receiver_hash: str,
    integrity_verified: bool,
) -> dict[str, Any]:
    """Assemble the full MITM attack record after receiver verification."""
    integrity_result = classify_integrity_result(integrity_verified)
    attack_status = classify_attack_status(integrity_verified)

    description = (
        f"{intercept_event['description']} "
        f"Transfer {transfer_id}: expected sender hash {sender_hash[:16]}…, "
        f"receiver computed {receiver_hash[:16]}… — "
        f"integrity {integrity_result}."
    )

    return {
        "attack_id": intercept_event["attack_id"],
        "attack_type": ATTACK_TYPE,
        "transfer_id": transfer_id,
        "file_name": intercept_event["file_name"],
        "attack_status": attack_status,
        "integrity_result": integrity_result,
        "description": description,
        "sender_hash": sender_hash,
        "receiver_hash": receiver_hash,
        "integrity_verified": integrity_verified,
        "intercept": intercept_event,
    }
