"""BB84 quantum key distribution simulation for Q-SAFE Nexus.

This module models the high-level BB84 workflow in classical Python code.
It is useful for education and testing, but it does not communicate with
real quantum hardware.
"""

from secrets import choice


BASES = ("+", "x")


def _random_bits(length: int) -> list[int]:
    """Create Alice's random bit stream."""
    return [choice((0, 1)) for _ in range(length)]


def _random_bases(length: int) -> list[str]:
    """Choose random measurement bases for Alice or Bob."""
    return [choice(BASES) for _ in range(length)]


def _measure_qubits(
    alice_bits: list[int],
    alice_bases: list[str],
    bob_bases: list[str],
    simulate_eavesdropper: bool = False,
) -> list[int]:
    """Simulate Bob measuring Alice's transmitted qubits.

    When Alice and Bob use the same basis, Bob receives Alice's bit.
    When the bases differ, Bob's measurement is random because the state
    is measured in the wrong basis.
    """
    measured_bits = []

    eve_bases = _random_bases(len(alice_bits)) if simulate_eavesdropper else []

    for index, (bit, alice_basis, bob_basis) in enumerate(
        zip(alice_bits, alice_bases, bob_bases)
    ):
        transmitted_bit = bit

        # Security note: an eavesdropper measuring with the wrong basis can
        # disturb the bit that later reaches Bob. This is what BB84 samples for.
        if simulate_eavesdropper and eve_bases[index] != alice_basis:
            transmitted_bit = choice((0, 1))

        if alice_basis == bob_basis:
            measured_bits.append(transmitted_bit)
        else:
            measured_bits.append(choice((0, 1)))

    return measured_bits


def simulate_bb84(
    key_length: int = 32,
    simulate_eavesdropper: bool = False,
    qber_threshold: float = 0.11,
) -> dict[str, object]:
    """Simulate Alice and Bob producing a shared key with BB84.

    The shared key is built only from positions where Alice and Bob selected
    the same basis. Basis mismatches are normal in BB84 and are discarded.
    Eavesdropping is estimated from the error rate in the matched-basis bits.
    """
    if key_length <= 0:
        raise ValueError("key_length must be greater than zero.")

    alice_bits = _random_bits(key_length)
    alice_bases = _random_bases(key_length)
    bob_bases = _random_bases(key_length)
    bob_bits = _measure_qubits(
        alice_bits,
        alice_bases,
        bob_bases,
        simulate_eavesdropper=simulate_eavesdropper,
    )

    matching_positions = [
        index
        for index, (alice_basis, bob_basis) in enumerate(zip(alice_bases, bob_bases))
        if alice_basis == bob_basis
    ]
    mismatched_positions = [
        index
        for index, (alice_basis, bob_basis) in enumerate(zip(alice_bases, bob_bases))
        if alice_basis != bob_basis
    ]

    error_positions = [
        index
        for index in matching_positions
        if alice_bits[index] != bob_bits[index]
    ]
    qber = len(error_positions) / len(matching_positions) if matching_positions else 0.0

    final_shared_key = "".join(str(alice_bits[index]) for index in matching_positions)
    eavesdropping_detected = qber > qber_threshold

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_bits": bob_bits,
        "matching_positions": matching_positions,
        "mismatched_positions": mismatched_positions,
        "error_positions": error_positions,
        "qber": qber,
        "eavesdropping_detected": eavesdropping_detected,
        "final_shared_key": final_shared_key,
    }


if __name__ == "__main__":
    result = simulate_bb84()
    print("Final shared key:", result["final_shared_key"])
    print("Eavesdropping detected:", result["eavesdropping_detected"])
