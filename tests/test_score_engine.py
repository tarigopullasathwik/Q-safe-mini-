"""Tests for Security Score Engine v2."""

from __future__ import annotations

import pytest

from analyzer.score_engine import compute_security_score


def test_perfect_pipeline_scores_100_safe() -> None:
    result = compute_security_score(
        encryption_status="Encrypted",
        bb84_qber=0.02,
        transfer_integrity=True,
        security_status="SAFE",
        attack_status="CLEAN",
    )

    assert result.score == 100
    assert result.risk_category == "SAFE"
    assert result.dimensions.encryption == 25
    assert result.dimensions.bb84 == 25
    assert result.dimensions.transfer == 25
    assert result.dimensions.security == 15
    assert result.dimensions.attack == 10


def test_to_dict_shape() -> None:
    payload = compute_security_score(
        encryption_status="aes-gcm",
        bb84_qber=0.0,
        transfer_integrity=True,
        security_status="safe",
        attack_status="clean",
    ).to_dict()

    assert set(payload.keys()) == {"score", "risk_category", "explanation"}
    assert isinstance(payload["explanation"], list)
    assert len(payload["explanation"]) >= 1


@pytest.mark.parametrize(
    ("qber", "expected_bb84_points"),
    [
        (0.05, 25),
        (0.08, 18),
        (0.12, 8),
    ],
)
def test_bb84_qber_tiers(qber: float, expected_bb84_points: int) -> None:
    result = compute_security_score(
        encryption_status="Encrypted",
        bb84_qber=qber,
        transfer_integrity=True,
        security_status="SAFE",
        attack_status="CLEAN",
    )
    assert result.dimensions.bb84 == expected_bb84_points


@pytest.mark.parametrize(
    ("security_status", "expected_points"),
    [
        ("SAFE", 15),
        ("WARNING", 8),
        ("DANGEROUS", 0),
    ],
)
def test_security_status_tiers(security_status: str, expected_points: int) -> None:
    result = compute_security_score(
        encryption_status="Encrypted",
        bb84_qber=0.01,
        transfer_integrity=True,
        security_status=security_status,
        attack_status="CLEAN",
    )
    assert result.dimensions.security == expected_points


@pytest.mark.parametrize(
    ("attack_status", "expected_points"),
    [
        ("CLEAN", 10),
        ("BLOCKED", 7),
        ("DETECTED", 0),
    ],
)
def test_attack_status_tiers(attack_status: str, expected_points: int) -> None:
    result = compute_security_score(
        encryption_status="Encrypted",
        bb84_qber=0.01,
        transfer_integrity=True,
        security_status="SAFE",
        attack_status=attack_status,
    )
    assert result.dimensions.attack == expected_points


def test_worst_case_high_risk() -> None:
    result = compute_security_score(
        encryption_status="failed",
        bb84_qber=0.20,
        transfer_integrity=False,
        security_status="DANGEROUS",
        attack_status="DETECTED",
    )

    assert result.score == 8
    assert result.risk_category == "HIGH RISK"


@pytest.mark.parametrize(
    ("score_inputs", "expected_category"),
    [
        (
            dict(
                encryption_status="Encrypted",
                bb84_qber=0.01,
                transfer_integrity=True,
                security_status="SAFE",
                attack_status="CLEAN",
            ),
            "SAFE",
        ),
        (
            dict(
                encryption_status="Encrypted",
                bb84_qber=0.08,
                transfer_integrity=True,
                security_status="WARNING",
                attack_status="BLOCKED",
            ),
            "LOW RISK",
        ),
    ],
)
def test_risk_category_boundaries(score_inputs: dict, expected_category: str) -> None:
    result = compute_security_score(**score_inputs)
    assert result.risk_category == expected_category
