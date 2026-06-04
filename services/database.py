"""SQLite database setup for Q-SAFE Nexus."""

import sqlite3
from pathlib import Path

from config import DATABASE_PATH


TRANSFER_LOG_COLUMNS = {
    "transfer_id": "TEXT",
    "sender_id": "TEXT",
    "receiver_id": "TEXT",
}


def get_connection(database_path: str | Path = DATABASE_PATH) -> sqlite3.Connection:
    """Open a SQLite connection with dictionary-like row access."""
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_database(database_path: str | Path = DATABASE_PATH) -> None:
    """Create persistent tables required by the application."""
    Path(database_path).parent.mkdir(exist_ok=True)

    with get_connection(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                encrypted_file_name TEXT NOT NULL,
                encryption_status TEXT NOT NULL,
                security_status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                tampering_json TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                encrypted_hash TEXT NOT NULL,
                bb84_key_length INTEGER NOT NULL,
                bb84_eavesdropping_detected INTEGER NOT NULL,
                bb84_qber REAL NOT NULL,
                transfer_status TEXT NOT NULL,
                transfer_integrity INTEGER NOT NULL,
                transfer_log_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS transfer_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_id TEXT,
                session_id TEXT,
                sender_id TEXT,
                receiver_id TEXT,
                status TEXT NOT NULL,
                actor TEXT NOT NULL,
                message TEXT NOT NULL,
                file_name TEXT,
                file_hash TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                file_name TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id INTEGER,
                file_name TEXT NOT NULL,
                total_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                encryption_score INTEGER NOT NULL,
                bb84_score INTEGER NOT NULL,
                transfer_score INTEGER NOT NULL,
                threat_score INTEGER NOT NULL,
                attack_score INTEGER NOT NULL,
                deductions_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        _ensure_transfer_log_columns(connection)
        _ensure_scan_result_columns(connection)
        _ensure_attack_log_columns(connection)


ATTACK_LOG_COLUMNS = {
    "attack_id": "TEXT",
    "transfer_id": "TEXT",
    "attack_status": "TEXT",
    "integrity_result": "TEXT",
}


SCAN_RESULT_COLUMNS = {
    "mitm_simulated": "INTEGER DEFAULT 0",
    "replay_simulated": "INTEGER DEFAULT 0",
    "v2_score": "INTEGER DEFAULT NULL",
    "v2_risk_category": "TEXT DEFAULT NULL",
}


def _ensure_transfer_log_columns(connection: sqlite3.Connection) -> None:
    """Add new transfer log columns when an older SQLite file already exists."""
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(transfer_logs)").fetchall()
    }

    for column_name, column_type in TRANSFER_LOG_COLUMNS.items():
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE transfer_logs ADD COLUMN {column_name} {column_type}"
            )


def _ensure_scan_result_columns(connection: sqlite3.Connection) -> None:
    """Add new scan result columns when an older SQLite file already exists."""
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(scan_results)").fetchall()
    }

    for column_name, column_type in SCAN_RESULT_COLUMNS.items():
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE scan_results ADD COLUMN {column_name} {column_type}"
            )


def _ensure_attack_log_columns(connection: sqlite3.Connection) -> None:
    """Add MITM / timeline columns when an older attack_logs table already exists."""
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(attack_logs)").fetchall()
    }

    for column_name, column_type in ATTACK_LOG_COLUMNS.items():
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE attack_logs ADD COLUMN {column_name} {column_type}"
            )
