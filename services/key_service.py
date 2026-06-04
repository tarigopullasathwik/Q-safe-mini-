"""Key orchestration services for Q-SAFE Nexus."""

import hashlib

from quantum.bb84 import simulate_bb84


def derive_aes_key(shared_key: str) -> bytes:
    """Derive a fixed-size AES-256 key from simulated BB84 key material.

    Security note: the BB84 module is a simulation. SHA-256 is used here to
    normalize variable-length simulated key material into the 32 bytes required
    by AES-256.
    """
    return hashlib.sha256(shared_key.encode("utf-8")).digest()


def generate_bb84_aes_key(
    key_length: int = 128,
    simulate_eavesdropper: bool = False,
) -> dict[str, object]:
    """Generate simulated BB84 data and a derived AES key."""
    bb84_result = simulate_bb84(
        key_length=key_length,
        simulate_eavesdropper=simulate_eavesdropper,
    )
    shared_key = bb84_result["final_shared_key"]

    return {
        "aes_key": derive_aes_key(shared_key),
        "bb84_shared_key": shared_key,
        "bb84_key_length": len(shared_key),
        "bb84_eavesdropping_detected": bb84_result["eavesdropping_detected"],
        "bb84_qber": bb84_result["qber"],
    }
