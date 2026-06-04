"""Threat analysis service layer for Q-SAFE Nexus."""

from pathlib import Path

from analyzer.pqc_scanner import analyze_file, calculate_sha256


def scan_uploaded_file(
    file_path: str | Path,
    mitm_simulated: bool = False,
    replay_simulated: bool = False,
) -> dict:
    """Scan an uploaded file and return analyzer results with baseline hash.

    Security note: the original SHA-256 hash is captured before plaintext is
    deleted, giving the dashboard and audit history a stable integrity record.
    """
    original_hash = calculate_sha256(file_path)
    scan_result = analyze_file(
        file_path,
        expected_hash=original_hash,
        mitm_simulated=mitm_simulated,
        replay_simulated=replay_simulated,
    )

    return {
        **scan_result,
        "original_hash": original_hash,
    }
