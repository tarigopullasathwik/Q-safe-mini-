"""Security Score Engine v2 for Q-SAFE Nexus.

All scoring rules live in this module. Callers pass five pipeline signals;
the engine returns a score (0-100), a risk category, and explanations.

Scoring table (weights sum to 100)
----------------------------------
| Input               | Condition / value      | Points |
|---------------------|------------------------|--------|
| encryption_status   | encrypted or aes-gcm   |     25 |
| encryption_status   | any other value        |      0 |
| bb84_qber           | <= 5% (0.05)           |     25 |
| bb84_qber           | > 5% and <= 11%        |     18 |
| bb84_qber           | > 11%                  |      8 |
| transfer_integrity  | True (hash verified)   |     25 |
| transfer_integrity  | False                  |      0 |
| security_status     | SAFE                   |     15 |
| security_status     | WARNING                |      8 |
| security_status     | DANGEROUS              |      0 |
| attack_status       | CLEAN                  |     10 |
| attack_status       | BLOCKED                |      7 |
| attack_status       | DETECTED               |      0 |

Risk categories (applied to the final score)
--------------------------------------------
| Score range | Category    |
|-------------|-------------|
| 85 - 100    | SAFE        |
| 60 - 84     | LOW RISK    |
| 30 - 59     | MEDIUM RISK |
| 0 - 29      | HIGH RISK   |
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Maximum points per input dimension (must sum to 100).
POINTS_ENCRYPTION = 25
POINTS_BB84 = 25
POINTS_TRANSFER = 25
POINTS_SECURITY = 15
POINTS_ATTACK = 10

# QBER thresholds used only by the BB84 row in the scoring table.
QBER_SAFE_MAX = 0.05
QBER_ELEVATED_MAX = 0.11

# Final score → risk label lookup (highest matching threshold wins).
RISK_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (85, "SAFE"),
    (60, "LOW RISK"),
    (30, "MEDIUM RISK"),
    (0, "HIGH RISK"),
)


@dataclass
class DimensionScores:
    """Per-dimension points earned (used when persisting to SQLite)."""
    encryption: int = 0
    bb84: int = 0
    transfer: int = 0
    security: int = 0
    attack: int = 0


@dataclass
class SecurityScoreResult:
    """Engine output; ``to_dict()`` matches the public v2 JSON shape."""
    score: int
    risk_category: str
    explanation: list[str] = field(default_factory=list)
    dimensions: DimensionScores = field(default_factory=DimensionScores)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "risk_category": self.risk_category,
            "explanation": self.explanation,
        }


def _normalize(value: str) -> str:
    return (value or "").strip().upper()


def _risk_category(score: int) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "HIGH RISK"


def _points_encryption(encryption_status: str) -> tuple[int, list[str]]:
    """Apply the encryption_status row of the scoring table."""
    status = (encryption_status or "").strip().lower()
    if status in {"encrypted", "aes-gcm"}:
        return POINTS_ENCRYPTION, [f"Encryption active ({encryption_status}) — +{POINTS_ENCRYPTION} pts"]
    return 0, [f"Encryption not confirmed ({encryption_status!r}) — 0 pts"]


def _points_bb84(bb84_qber: float) -> tuple[int, list[str]]:
    """Apply the bb84_qber rows of the scoring table."""
    qber = max(0.0, float(bb84_qber))
    if qber <= QBER_SAFE_MAX:
        return POINTS_BB84, [f"QBER {qber:.1%} within safe range (≤5%) — +{POINTS_BB84} pts"]
    if qber <= QBER_ELEVATED_MAX:
        return 18, [f"QBER {qber:.1%} elevated (5–11%) — +18 pts"]
    return 8, [f"QBER {qber:.1%} above 11% threshold — +8 pts"]


def _points_transfer(transfer_integrity: bool) -> tuple[int, list[str]]:
    """Apply the transfer_integrity rows of the scoring table."""
    if transfer_integrity:
        return POINTS_TRANSFER, ["Transfer integrity verified — +25 pts"]
    return 0, ["Transfer integrity failed — hash mismatch in transit — 0 pts"]


def _points_security(security_status: str) -> tuple[int, list[str]]:
    """Apply the security_status rows of the scoring table."""
    status = _normalize(security_status)
    if status == "SAFE":
        return POINTS_SECURITY, ["Threat analysis: SAFE — +15 pts"]
    if status == "WARNING":
        return 8, ["Threat analysis: WARNING — +8 pts"]
    if status == "DANGEROUS":
        return 0, ["Threat analysis: DANGEROUS — 0 pts"]
    return 0, [f"Unknown security_status {security_status!r} — 0 pts"]


def _points_attack(attack_status: str) -> tuple[int, list[str]]:
    """Apply the attack_status rows of the scoring table."""
    status = _normalize(attack_status)
    if status == "CLEAN":
        return POINTS_ATTACK, ["No active attack indicators — +10 pts"]
    if status == "BLOCKED":
        return 7, ["Attack blocked (e.g. replay) — +7 pts"]
    if status == "DETECTED":
        return 0, ["Attack detected (MITM/tampering) — 0 pts"]
    if status == "SUCCESSFUL":
        return 0, ["Attack succeeded (integrity not restored) — 0 pts"]
    return 0, [f"Unknown attack_status {attack_status!r} — 0 pts"]


def compute_security_score(
    encryption_status: str,
    bb84_qber: float,
    transfer_integrity: bool,
    security_status: str,
    attack_status: str,
) -> SecurityScoreResult:
    """Compute the v2 security score from the five required inputs.

    Returns a :class:`SecurityScoreResult`. Use ``result.to_dict()`` for the
    public payload: ``score``, ``risk_category``, and ``explanation``.
    """
    enc_pts, enc_notes = _points_encryption(encryption_status)
    bb84_pts, bb84_notes = _points_bb84(bb84_qber)
    tx_pts, tx_notes = _points_transfer(transfer_integrity)
    sec_pts, sec_notes = _points_security(security_status)
    atk_pts, atk_notes = _points_attack(attack_status)

    total = enc_pts + bb84_pts + tx_pts + sec_pts + atk_pts
    total = max(0, min(100, total))

    explanation = enc_notes + bb84_notes + tx_notes + sec_notes + atk_notes
    explanation.append(f"Composite score: {total}/100 → {_risk_category(total)}")

    return SecurityScoreResult(
        score=total,
        risk_category=_risk_category(total),
        explanation=explanation,
        dimensions=DimensionScores(
            encryption=enc_pts,
            bb84=bb84_pts,
            transfer=tx_pts,
            security=sec_pts,
            attack=atk_pts,
        ),
    )
