"""Tests for security PDF report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reports.report_generator import (
    build_recommendations,
    build_report_context_summary,
    extract_report_text,
    generate_security_report_pdf,
    report_output_path,
)
from services.database import get_connection, init_database
from services.report_service import ReportNotFoundError, fetch_report_context, generate_security_report

TRANSFER_ID = "11111111-2222-4333-8444-555555555555"


@pytest.fixture
def report_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Isolated SQLite database with one complete scan record."""
    db_path = tmp_path / "reports_test.db"
    monkeypatch.setattr("services.database.DATABASE_PATH", db_path)
    monkeypatch.setattr("config.DATABASE_PATH", db_path)
    init_database(db_path)

    transfer_log = {
        "transfer_id": TRANSFER_ID,
        "status": "COMPROMISED",
        "integrity_verified": False,
        "compromised": True,
        "sender_hash": "a" * 64,
        "receiver_hash": "b" * 64,
    }

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_results (
                file_name, encrypted_file_name, encryption_status, security_status,
                risk_score, findings_json, tampering_json, original_hash,
                encrypted_hash, bb84_key_length, bb84_eavesdropping_detected,
                bb84_qber, transfer_status, transfer_integrity, transfer_log_json,
                mitm_simulated, replay_simulated, v2_score, v2_risk_category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "sample.txt",
                "sample.txt.enc",
                "Encrypted",
                "WARNING",
                45,
                json.dumps([{"type": "WEAK_ENCRYPTION", "algorithm": "RSA"}]),
                json.dumps({"checked": True, "tampered": True}),
                "orig" * 16,
                "enc" * 16,
                128,
                1,
                0.12,
                "COMPROMISED",
                0,
                json.dumps(transfer_log),
                1,
                0,
                58,
                "MEDIUM RISK",
            ),
        )
        scan_id = cursor.lastrowid
        conn.execute(
            """
            INSERT INTO security_scores (
                scan_result_id, file_name, total_score, risk_category,
                encryption_score, bb84_score, transfer_score, threat_score,
                attack_score, deductions_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                "sample.txt",
                58,
                "MEDIUM RISK",
                25,
                8,
                0,
                8,
                0,
                json.dumps(["Transfer integrity failed"]),
            ),
        )
        conn.execute(
            """
            INSERT INTO attack_logs (
                attack_id, attack_type, transfer_id, file_name,
                status, attack_status, integrity_result, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "attack-uuid-1",
                "MITM",
                TRANSFER_ID,
                "sample.txt",
                "DETECTED",
                "DETECTED",
                "FAILED",
                "MITM intercept detected during educational simulation.",
            ),
        )

    return db_path


def test_fetch_report_context(report_db: Path) -> None:
    context = fetch_report_context(TRANSFER_ID)
    assert context["transfer_id"] == TRANSFER_ID
    assert context["scan"]["file_name"] == "sample.txt"
    assert context["security_score"]["total_score"] == 58
    assert len(context["attacks"]) == 1


def test_fetch_missing_transfer_raises(report_db: Path) -> None:
    with pytest.raises(ReportNotFoundError):
        fetch_report_context("00000000-0000-4000-8000-000000000000")


def test_pdf_is_generated(report_db: Path, tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    pdf_path = generate_security_report(TRANSFER_ID, reports_root=reports_root)

    assert pdf_path.exists()
    assert pdf_path.name == f"security_report_{TRANSFER_ID}.pdf"
    assert pdf_path.parent == reports_root / "generated"
    assert pdf_path.stat().st_size > 500


def test_report_contains_required_content(report_db: Path, tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    pdf_path = generate_security_report(TRANSFER_ID, reports_root=reports_root)
    text = extract_report_text(pdf_path)

    assert TRANSFER_ID in text
    assert "Security Score" in text
    assert "58" in text
    assert "Recommendations" in text
    assert len(build_recommendations(fetch_report_context(TRANSFER_ID))) >= 1


def test_build_recommendations_includes_transfer_warning(report_db: Path) -> None:
    context = fetch_report_context(TRANSFER_ID)
    recs = build_recommendations(context)
    joined = " ".join(recs).lower()
    assert "integrity" in joined or "mitm" in joined or "score" in joined


def test_summary_contains_transfer_id(report_db: Path) -> None:
    context = fetch_report_context(TRANSFER_ID)
    summary = build_report_context_summary(context)
    assert summary["transfer_id"] == TRANSFER_ID
    assert summary["security_score"]["Score (v2)"] == "58"


def test_generator_writes_directly(tmp_path: Path) -> None:
    context = {
        "transfer_id": "direct-id",
        "scan": {
            "file_name": "x.enc",
            "encrypted_file_name": "x.enc",
            "encryption_status": "Encrypted",
            "security_status": "SAFE",
            "risk_score": 10,
            "findings": [],
            "tampering": {},
            "bb84_key_length": 64,
            "bb84_qber": 0.02,
            "bb84_eavesdropping_detected": False,
            "transfer_status": "VERIFIED",
            "transfer_integrity": True,
            "transfer_log": {"transfer_id": "direct-id", "status": "VERIFIED"},
        },
        "security_score": {
            "total_score": 100,
            "risk_category": "SAFE",
            "encryption_score": 25,
            "bb84_score": 25,
            "transfer_score": 25,
            "threat_score": 15,
            "attack_score": 10,
        },
        "attacks": [],
    }
    out = report_output_path(tmp_path, "direct-id")
    generate_security_report_pdf(context, out)
    assert out.exists()


def test_generate_report_route_returns_pdf(
    report_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app as app_module
    import services.report_service as report_service

    monkeypatch.setattr(report_service, "REPORTS_ROOT", tmp_path / "reports")
    app = app_module.create_app()
    client = app.test_client()
    response = client.get(f"/generate-report/{TRANSFER_ID}")

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert "security_report_" in response.headers["Content-Disposition"]
    assert response.data.startswith(b"%PDF")
