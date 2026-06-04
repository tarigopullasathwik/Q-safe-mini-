"""Attack simulation services for Q-SAFE Nexus."""

from __future__ import annotations

from typing import Any

from services.database import get_connection, init_database


def log_attack(
    attack_type: str,
    file_name: str,
    status: str,
    details: str,
) -> dict[str, Any]:
    """Log a generic simulated attack event (legacy shape)."""
    return log_attack_event(
        attack_type=attack_type,
        file_name=file_name,
        attack_status=status,
        description=details,
    )


def log_attack_event(
    *,
    attack_type: str,
    file_name: str,
    attack_status: str,
    description: str,
    attack_id: str | None = None,
    transfer_id: str | None = None,
    integrity_result: str | None = None,
) -> dict[str, Any]:
    """Persist one attack event with structured fields for dashboard timelines."""
    init_database()
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO attack_logs (
                attack_id,
                attack_type,
                transfer_id,
                file_name,
                status,
                attack_status,
                integrity_result,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attack_id,
                attack_type,
                transfer_id,
                file_name,
                attack_status,
                attack_status,
                integrity_result,
                description,
            ),
        )
        row = connection.execute(
            """
            SELECT id, attack_id, attack_type, transfer_id, file_name,
                   status, attack_status, integrity_result, details, created_at
            FROM attack_logs
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()

    return _normalize_attack_row(dict(row)) if row else {}


def log_mitm_attack(mitm_outcome: dict[str, Any]) -> dict[str, Any]:
    """Persist a MITM simulation outcome produced by ``mitm_simulator``."""
    return log_attack_event(
        attack_id=mitm_outcome["attack_id"],
        attack_type=mitm_outcome["attack_type"],
        transfer_id=mitm_outcome["transfer_id"],
        file_name=mitm_outcome["file_name"],
        attack_status=mitm_outcome["attack_status"],
        integrity_result=mitm_outcome["integrity_result"],
        description=mitm_outcome["description"],
    )


def get_attack_logs(limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve the latest simulated attack logs (recent attacks / timeline)."""
    init_database()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, attack_id, attack_type, transfer_id, file_name,
                   status, attack_status, integrity_result, details, created_at
            FROM attack_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_normalize_attack_row(dict(row)) for row in rows]


def get_attack_timeline(limit: int = 50) -> list[dict[str, Any]]:
    """Return attack events oldest-first for timeline visualizations."""
    events = get_attack_logs(limit=limit)
    return list(reversed(events))


def get_attacks_by_type(attack_type: str, limit: int = 50) -> list[dict[str, Any]]:
    """Filter attack history by type (e.g. MITM, REPLAY, TAMPERING)."""
    init_database()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, attack_id, attack_type, transfer_id, file_name,
                   status, attack_status, integrity_result, details, created_at
            FROM attack_logs
            WHERE attack_type = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (attack_type, limit),
        ).fetchall()
    return [_normalize_attack_row(dict(row)) for row in rows]


def clear_attack_logs() -> None:
    """Clear all attack logs."""
    init_database()
    with get_connection() as connection:
        connection.execute("DELETE FROM attack_logs")


def _normalize_attack_row(row: dict[str, Any]) -> dict[str, Any]:
    """Expose consistent keys for templates and APIs."""
    row["timestamp"] = row.get("created_at", "")
    row["description"] = row.get("details", "")
    row.setdefault("attack_status", row.get("status", ""))
    row.setdefault("attack_id", None)
    row.setdefault("transfer_id", None)
    row.setdefault("integrity_result", None)
    return row
