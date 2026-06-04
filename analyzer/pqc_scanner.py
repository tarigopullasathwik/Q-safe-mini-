"""Cybersecurity threat analyzer for Q-SAFE Nexus.

The scanner performs lightweight checks that are useful for a post-quantum
readiness workflow. It returns structured JSON-compatible dictionaries rather
than printing text, which makes it easy to use from Flask routes or APIs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


WEAK_ENCRYPTION_PATTERNS = {
    "RSA": ("rsa", "-----begin rsa", "rsa_private_key", "rsa_public_key"),
    "ECC": ("ecc", "ecdsa", "ecdh", "elliptic curve", "secp256", "prime256v1"),
}


def calculate_sha256(file_path: str | Path) -> str:
    """Calculate a SHA-256 hash for tamper detection."""
    digest = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def detect_weak_encryption(file_path: str | Path) -> list[dict[str, str]]:
    """Detect placeholder signs of RSA or ECC usage in a file."""
    file_bytes = Path(file_path).read_bytes()
    file_text = file_bytes.decode("utf-8", errors="ignore").lower()
    findings = []

    for algorithm, patterns in WEAK_ENCRYPTION_PATTERNS.items():
        if any(pattern in file_text for pattern in patterns):
            findings.append(
                {
                    "type": "WEAK_ENCRYPTION",
                    "algorithm": algorithm,
                    "severity": "HIGH",
                    "message": f"{algorithm} usage detected. Review for post-quantum risk.",
                }
            )

    return findings


def detect_file_tampering(
    file_path: str | Path,
    expected_hash: str | None = None,
) -> dict[str, Any]:
    """Compare the current file hash with an expected hash when provided."""
    current_hash = calculate_sha256(file_path)
    tampered = expected_hash is not None and current_hash != expected_hash

    return {
        "checked": expected_hash is not None,
        "tampered": tampered,
        "expected_hash": expected_hash,
        "current_hash": current_hash,
    }


def generate_risk_score(
    weak_encryption_findings: list[dict[str, str]],
    tampering_result: dict[str, Any],
    mitm_simulated: bool = False,
    replay_simulated: bool = False,
) -> int:
    """Generate a bounded cybersecurity risk score from 0 to 100."""
    score = 0

    if weak_encryption_findings:
        score += min(60, len(weak_encryption_findings) * 30)

    if tampering_result.get("tampered", False):
        score += 70

    if mitm_simulated:
        score += 80

    if replay_simulated:
        score += 50

    return min(score, 100)


def determine_security_status(risk_score: int) -> str:
    """Map the numeric risk score to a security status label."""
    if risk_score >= 70:
        return "DANGEROUS"

    if risk_score >= 30:
        return "WARNING"

    return "SAFE"


def analyze_file(
    file_path: str | Path,
    expected_hash: str | None = None,
    mitm_simulated: bool = False,
    replay_simulated: bool = False,
) -> dict[str, Any]:
    """Analyze a file and return a JSON-compatible security result."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    weak_encryption_findings = detect_weak_encryption(path)
    tampering_result = detect_file_tampering(path, expected_hash)
    risk_score = generate_risk_score(
        weak_encryption_findings,
        tampering_result,
        mitm_simulated=mitm_simulated,
        replay_simulated=replay_simulated,
    )

    return {
        "file_name": path.name,
        "file_path": str(path),
        "risk_score": risk_score,
        "security_status": determine_security_status(risk_score),
        "findings": weak_encryption_findings,
        "tampering": tampering_result,
        "mitm_simulated": mitm_simulated,
        "replay_simulated": replay_simulated,
    }


def analyze_file_json(
    file_path: str | Path,
    expected_hash: str | None = None,
) -> str:
    """Analyze a file and return a formatted JSON string."""
    return json.dumps(analyze_file(file_path, expected_hash), indent=2)


if __name__ == "__main__":
    sample_path = Path(__file__)
    print(analyze_file_json(sample_path))
