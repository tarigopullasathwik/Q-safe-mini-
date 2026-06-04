"""Tests for the BB84 key-distribution simulation."""

from __future__ import annotations

import pytest

from quantum.bb84 import simulate_bb84


def test_key_length_must_be_positive() -> None:
    with pytest.raises(ValueError, match="key_length must be greater than zero"):
        simulate_bb84(key_length=0)


def test_result_contains_expected_fields() -> None:
    result = simulate_bb84(key_length=64, simulate_eavesdropper=False)

    assert set(result.keys()) >= {
        "alice_bits",
        "alice_bases",
        "bob_bases",
        "bob_bits",
        "matching_positions",
        "mismatched_positions",
        "error_positions",
        "qber",
        "eavesdropping_detected",
        "final_shared_key",
    }
    assert len(result["alice_bits"]) == 64
    assert len(result["bob_bits"]) == 64


def test_shared_key_uses_only_matching_bases() -> None:
    result = simulate_bb84(key_length=32, simulate_eavesdropper=False)
    matching = result["matching_positions"]
    alice_bits = result["alice_bits"]

    expected_key = "".join(str(alice_bits[i]) for i in matching)
    assert result["final_shared_key"] == expected_key


def test_qber_is_bounded() -> None:
    result = simulate_bb84(key_length=256, simulate_eavesdropper=False)
    assert 0.0 <= result["qber"] <= 1.0


def test_eavesdropper_raises_qber_or_detection() -> None:
    """With Eve active, QBER should often exceed the default 11% threshold."""
    detections = 0
    trials = 30

    for _ in range(trials):
        result = simulate_bb84(key_length=128, simulate_eavesdropper=True)
        if result["eavesdropping_detected"]:
            detections += 1

    assert detections > 0, "eavesdropper simulation should trigger detection sometimes"
