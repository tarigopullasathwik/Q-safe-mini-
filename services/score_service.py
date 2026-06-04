"""Security Score Engine v2 — data preparation and persistence.

This module maps raw pipeline results into the five engine inputs, calls
``analyzer.score_engine`` (the only place scoring rules are defined), and
stores rows in SQLite.
"""

from __future__ import annotations

import json
from typing import Any

from analyzer.score_engine import SecurityScoreResult, compute_security_score
from services.database import get_connection, init_database


# ---------------------------------------------------------------------------
# Input preparation (no scoring math here — only normalization / derivation)
# ---------------------------------------------------------------------------

def derive_attack_status(
    *,
    mitm_simulated: bool = False,
    replay_simulated: bool = False,
    tampering_simulated: bool = False,
    mitm_attack_status: str | None = None,
) -> str:
    """Map attack simulation flags to a single attack_status label.

    CLEAN      — no attacks were simulated
    DETECTED   — MITM or tampering was simulated and caught (integrity failure)
    SUCCESSFUL — reserved: MITM evaded detection (integrity still verified)
    BLOCKED    — only replay was simulated and the pipeline blocked it
    """
    if mitm_attack_status:
        return mitm_attack_status.upper()
    if not (mitm_simulated or replay_simulated or tampering_simulated):
        return "CLEAN"
    if mitm_simulated or tampering_simulated:
        return "DETECTED"
    if replay_simulated:
        return "BLOCKED"
    return "CLEAN"


def prepare_score_inputs(
    *,
    encryption_status: str,
    bb84_qber: float,
    transfer_integrity: bool,
    security_status: str,
    mitm_simulated: bool = False,
    replay_simulated: bool = False,
    tampering_simulated: bool = False,
    attack_status: str | None = None,
    mitm_attack_status: str | None = None,
) -> dict[str, Any]:
    """Build the keyword arguments expected by ``compute_security_score``."""
    return {
        "encryption_status": encryption_status,
        "bb84_qber": bb84_qber,
        "transfer_integrity": transfer_integrity,
        "security_status": security_status,
        "attack_status": attack_status
        or derive_attack_status(
            mitm_simulated=mitm_simulated,
            replay_simulated=replay_simulated,
            tampering_simulated=tampering_simulated,
            mitm_attack_status=mitm_attack_status,
        ),
    }


def evaluate_security_score(**pipeline_fields: Any) -> SecurityScoreResult:
    """Prepare inputs from pipeline fields and run the score engine."""
    inputs = prepare_score_inputs(**pipeline_fields)
    return compute_security_score(**inputs)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _record_from_result(
    score_id: int,
    scan_result_id: int,
    file_name: str,
    result: SecurityScoreResult,
    created_at: str,
) -> dict[str, Any]:
    """Shape a DB row + template-friendly aliases for the dashboard."""
    dims = result.dimensions
    payload = result.to_dict()
    return {
        "id": score_id,
        "scan_result_id": scan_result_id,
        "file_name": file_name,
        "created_at": created_at,
        **payload,
        # Aliases kept for existing templates and dashboard queries.
        "total_score": payload["score"],
        "deductions": payload["explanation"],
        "encryption_score": dims.encryption,
        "bb84_score": dims.bb84,
        "transfer_score": dims.transfer,
        "threat_score": dims.security,
        "attack_score": dims.attack,
    }


def store_score(
    scan_result_id: int,
    result: SecurityScoreResult,
    file_name: str,
) -> dict[str, Any]:
    """Persist one v2 score linked to a scan_results row."""
    init_database()
    dims = result.dimensions
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO security_scores (
                scan_result_id,
                file_name,
                total_score,
                risk_category,
                encryption_score,
                bb84_score,
                transfer_score,
                threat_score,
                attack_score,
                deductions_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_result_id,
                file_name,
                result.score,
                result.risk_category,
                dims.encryption,
                dims.bb84,
                dims.transfer,
                dims.security,
                dims.attack,
                json.dumps(result.explanation),
            ),
        )
        row = conn.execute(
            "SELECT created_at FROM security_scores WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _record_from_result(
        cursor.lastrowid,
        scan_result_id,
        file_name,
        result,
        row["created_at"] if row else "",
    )


def get_scores(limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent security score records."""
    init_database()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM security_scores
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    result: list[dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        explanation = json.loads(record.pop("deductions_json"))
        record["explanation"] = explanation
        record["deductions"] = explanation
        record["score"] = record["total_score"]
        result.append(record)
    return result


def get_latest_score() -> dict[str, Any] | None:
    """Return the most recently computed score or None."""
    scores = get_scores(limit=1)
    return scores[0] if scores else None


def compute_and_store_score(
    scan_result_id: int,
    file_name: str,
    *,
    encryption_status: str,
    bb84_qber: float,
    transfer_integrity: bool,
    security_status: str,
    mitm_simulated: bool = False,
    replay_simulated: bool = False,
    tampering_simulated: bool = False,
    attack_status: str | None = None,
) -> dict[str, Any]:
    """Prepare pipeline data, score it, persist, and return the full record."""
    score_result = evaluate_security_score(
        encryption_status=encryption_status,
        bb84_qber=bb84_qber,
        transfer_integrity=transfer_integrity,
        security_status=security_status,
        mitm_simulated=mitm_simulated,
        replay_simulated=replay_simulated,
        tampering_simulated=tampering_simulated,
        attack_status=attack_status,
    )
    return store_score(scan_result_id, score_result, file_name)
