"""Security report orchestration — SQLite aggregation and PDF export."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import BASE_DIR
from reports.report_generator import (
    generate_security_report_pdf,
    report_output_path,
)
from services import database as db
from transfer.file_transfer import get_transfer_history_by_id


class ReportNotFoundError(LookupError):
    """Raised when no scan/transfer data exists for the requested transfer ID."""


REPORTS_ROOT = BASE_DIR / "reports"


def fetch_report_context(transfer_id: str) -> dict[str, Any]:
    """Load scan, score, transfer, and attack data for one transfer from SQLite."""
    db.init_database(db.DATABASE_PATH)
    scan = _fetch_scan_by_transfer_id(transfer_id)
    if scan is None:
        raise ReportNotFoundError(f"No scan result found for transfer_id={transfer_id!r}")

    scan_result_id = scan.get("id")
    security_score = _fetch_security_score(scan_result_id, scan.get("file_name"))
    attacks = _fetch_attacks_by_transfer(transfer_id)
    transfer_events = get_transfer_history_by_id(transfer_id)
    transfer_summary = scan.get("transfer_log") or {}

    return {
        "transfer_id": transfer_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan": scan,
        "security_score": security_score,
        "attacks": attacks,
        "transfer_events": transfer_events,
        "transfer": transfer_summary,
    }


def generate_security_report(transfer_id: str, *, reports_root: Path | None = None) -> Path:
    """Build and save ``security_report_<transfer_id>.pdf``; return the file path."""
    root = reports_root or REPORTS_ROOT
    context = fetch_report_context(transfer_id)
    output_path = report_output_path(root, transfer_id)
    return generate_security_report_pdf(context, output_path)


def get_existing_report_path(transfer_id: str, *, reports_root: Path | None = None) -> Path | None:
    """Return path if the report PDF already exists on disk."""
    path = report_output_path(reports_root or REPORTS_ROOT, transfer_id)
    return path if path.is_file() else None


def _fetch_scan_by_transfer_id(transfer_id: str) -> dict[str, Any] | None:
    """Find the scan_results row whose transfer_log JSON references transfer_id."""
    with db.get_connection(db.DATABASE_PATH) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM scan_results
            WHERE json_extract(transfer_log_json, '$.transfer_id') = ?
               OR transfer_log_json LIKE ?
            ORDER BY id DESC
            """,
            (transfer_id, f'%"{transfer_id}"%'),
        ).fetchall()

    for row in rows:
        scan = _deserialize_scan(dict(row))
        log = scan.get("transfer_log") or {}
        if log.get("transfer_id") == transfer_id or log.get("session_id") == transfer_id:
            return scan

    return None


def _fetch_security_score(
    scan_result_id: int | None,
    file_name: str | None,
) -> dict[str, Any] | None:
    """Load the v2 security_scores row linked to this scan or file."""
    with db.get_connection(db.DATABASE_PATH) as connection:
        if scan_result_id:
            row = connection.execute(
                """
                SELECT *
                FROM security_scores
                WHERE scan_result_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (scan_result_id,),
            ).fetchone()
            if row:
                return _deserialize_score(dict(row))

        if file_name:
            row = connection.execute(
                """
                SELECT *
                FROM security_scores
                WHERE file_name = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (file_name,),
            ).fetchone()
            if row:
                return _deserialize_score(dict(row))

    return None


def _fetch_attacks_by_transfer(transfer_id: str) -> list[dict[str, Any]]:
    """Return attack_logs rows for the transfer (MITM, replay, etc.)."""
    with db.get_connection(db.DATABASE_PATH) as connection:
        rows = connection.execute(
            """
            SELECT id, attack_id, attack_type, transfer_id, file_name,
                   status, attack_status, integrity_result, details, created_at
            FROM attack_logs
            WHERE transfer_id = ?
            ORDER BY id ASC
            """,
            (transfer_id,),
        ).fetchall()

    attacks = []
    for row in rows:
        record = dict(row)
        record["description"] = record.get("details", "")
        record["timestamp"] = record.get("created_at", "")
        attacks.append(record)
    return attacks


def _deserialize_scan(row: dict[str, Any]) -> dict[str, Any]:
    row["findings"] = json.loads(row.pop("findings_json"))
    row["tampering"] = json.loads(row.pop("tampering_json"))
    row["transfer_log"] = json.loads(row.pop("transfer_log_json"))
    row["bb84_eavesdropping_detected"] = bool(row["bb84_eavesdropping_detected"])
    row["transfer_integrity"] = bool(row["transfer_integrity"])
    row["mitm_simulated"] = bool(row.get("mitm_simulated", False))
    row["replay_simulated"] = bool(row.get("replay_simulated", False))
    return row


def _deserialize_score(row: dict[str, Any]) -> dict[str, Any]:
    explanation = json.loads(row.pop("deductions_json"))
    row["explanation"] = explanation
    row["deductions"] = explanation
    row["score"] = row["total_score"]
    return row
