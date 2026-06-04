"""Transfer service layer for Q-SAFE Nexus."""

from pathlib import Path

from transfer.file_transfer import (
    get_transfer_history,
    get_transfer_history_by_id,
    simulate_file_transfer,
)


def execute_encrypted_transfer(
    encrypted_path: str | Path,
    transfer_folder: str | Path,
    sender_id: str = "Alice",
    receiver_id: str = "Bob",
    simulate_tampering: bool = False,
    simulate_mitm: bool = False,
) -> dict:
    """Run the structured encrypted transfer simulation."""
    return simulate_file_transfer(
        encrypted_path,
        transfer_folder,
        sender_id=sender_id,
        receiver_id=receiver_id,
        simulate_tampering=simulate_tampering,
        simulate_mitm=simulate_mitm,
    )


def list_transfer_history(limit: int = 100) -> list[dict]:
    """Return transfer log history for future backend views."""
    return get_transfer_history(limit=limit)


def get_transfer_details(transfer_id: str) -> list[dict]:
    """Return lifecycle logs for one transfer ID."""
    return get_transfer_history_by_id(transfer_id)
