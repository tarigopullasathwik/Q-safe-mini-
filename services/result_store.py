"""Persistent scan result storage for Q-SAFE Nexus."""

import json

from services.database import get_connection, init_database


class ResultStore:
    """Store dashboard results in SQLite so history survives restarts."""

    def add(self, result: dict) -> None:
        """Persist one completed upload workflow result."""
        init_database()
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_results (
                    file_name,
                    encrypted_file_name,
                    encryption_status,
                    security_status,
                    risk_score,
                    findings_json,
                    tampering_json,
                    original_hash,
                    encrypted_hash,
                    bb84_key_length,
                    bb84_eavesdropping_detected,
                    bb84_qber,
                    transfer_status,
                    transfer_integrity,
                    transfer_log_json,
                    mitm_simulated,
                    replay_simulated,
                    v2_score,
                    v2_risk_category
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["file_name"],
                    result["encrypted_file_name"],
                    result["encryption_status"],
                    result["security_status"],
                    result["risk_score"],
                    json.dumps(result["findings"]),
                    json.dumps(result["tampering"]),
                    result["original_hash"],
                    result["encrypted_hash"],
                    result["bb84_key_length"],
                    int(result["bb84_eavesdropping_detected"]),
                    result["bb84_qber"],
                    result["transfer_status"],
                    int(result["transfer_integrity"]),
                    json.dumps(result["transfer_log"]),
                    int(result.get("mitm_simulated", 0)),
                    int(result.get("replay_simulated", 0)),
                    result.get("v2_score"),
                    result.get("v2_risk_category"),
                ),
            )
            return cursor.lastrowid

    def all(self) -> list[dict]:
        """Return all stored results ordered newest first."""
        init_database()
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM scan_results
                ORDER BY id DESC
                """
            ).fetchall()

        results = []
        for row in rows:
            result = dict(row)
            result["findings"] = json.loads(result.pop("findings_json"))
            result["tampering"] = json.loads(result.pop("tampering_json"))
            result["transfer_log"] = json.loads(result.pop("transfer_log_json"))
            result["bb84_eavesdropping_detected"] = bool(
                result["bb84_eavesdropping_detected"]
            )
            result["transfer_integrity"] = bool(result["transfer_integrity"])
            result["mitm_simulated"] = bool(result.get("mitm_simulated", False))
            result["replay_simulated"] = bool(result.get("replay_simulated", False))
            result["v2_score"] = result.get("v2_score")
            result["v2_risk_category"] = result.get("v2_risk_category")
            results.append(result)

        return results

    def clear(self) -> None:
        """Clear stored results, mainly useful for tests."""
        init_database()
        with get_connection() as connection:
            connection.execute("DELETE FROM scan_results")
            connection.execute("DELETE FROM transfer_logs")


result_store = ResultStore()
