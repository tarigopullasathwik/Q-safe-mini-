"""Encrypted file transfer simulation for Q-SAFE Nexus."""

import shutil
from pathlib import Path
from uuid import uuid4

from analyzer.pqc_scanner import calculate_sha256
from services.database import get_connection, init_database


TRANSFER_STATUSES = ("CREATED", "ENCRYPTED", "SENT", "RECEIVED", "VERIFIED")
MITM_TRANSFER_STATUSES = (
    "CREATED",
    "ENCRYPTED",
    "SENT",
    "MITM_INTERCEPTED",
    "RECEIVED",
    "VERIFIED",
)


def log_transfer_step(
    transfer_id: str,
    sender_id: str,
    receiver_id: str,
    status: str,
    actor: str,
    message: str,
    file_name: str | None = None,
    file_hash: str | None = None,
) -> dict:
    """Persist one transfer lifecycle event to SQLite."""
    init_database()
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO transfer_logs (
                transfer_id,
                session_id,
                sender_id,
                receiver_id,
                status,
                actor,
                message,
                file_name,
                file_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transfer_id,
                transfer_id,
                sender_id,
                receiver_id,
                status,
                actor,
                message,
                file_name,
                file_hash,
            ),
        )
        row = connection.execute(
            "SELECT created_at FROM transfer_logs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return {
        "transfer_id": transfer_id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "status": status,
        "actor": actor,
        "message": message,
        "file_name": file_name,
        "file_hash": file_hash,
        "created_at": row["created_at"],
    }


class TransferSender:
    """Sender entity for encrypted file transfer simulation."""

    def __init__(self, transfer_id: str, sender_id: str, receiver_id: str, source_path: str | Path) -> None:
        self.transfer_id = transfer_id
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.source_path = Path(source_path)

    def create_session(self) -> dict:
        """Create the transfer session before sending bytes."""
        return log_transfer_step(
            self.transfer_id,
            self.sender_id,
            self.receiver_id,
            "CREATED",
            self.sender_id,
            "Transfer session created.",
            self.source_path.name,
        )

    def confirm_encrypted_payload(self) -> dict:
        """Confirm the sender is transferring only encrypted content."""
        # Security note: transfer simulation must only send .enc artifacts so
        # plaintext is not exposed between sender and receiver.
        if self.source_path.suffix != ".enc":
            raise ValueError("Transfer requires an encrypted .enc file.")

        file_hash = calculate_sha256(self.source_path)
        return log_transfer_step(
            self.transfer_id,
            self.sender_id,
            self.receiver_id,
            "ENCRYPTED",
            self.sender_id,
            "Encrypted payload ready for transfer.",
            self.source_path.name,
            file_hash,
        )

    def send(self, destination_folder: str | Path) -> tuple[Path, dict]:
        """Send the encrypted payload to the receiver location."""
        destination_dir = Path(destination_folder)
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination_path = destination_dir / self.source_path.name
        shutil.copy2(self.source_path, destination_path)
        file_hash = calculate_sha256(self.source_path)

        event = log_transfer_step(
            self.transfer_id,
            self.sender_id,
            self.receiver_id,
            "SENT",
            self.sender_id,
            "Encrypted payload sent to receiver.",
            self.source_path.name,
            file_hash,
        )
        return destination_path, event


class TransferReceiver:
    """Receiver entity for encrypted file transfer simulation."""

    def __init__(self, transfer_id: str, sender_id: str, receiver_id: str, received_path: str | Path) -> None:
        self.transfer_id = transfer_id
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.received_path = Path(received_path)

    def receive(self) -> dict:
        """Record receipt of the encrypted payload."""
        file_hash = calculate_sha256(self.received_path)
        return log_transfer_step(
            self.transfer_id,
            self.sender_id,
            self.receiver_id,
            "RECEIVED",
            self.receiver_id,
            "Encrypted payload received.",
            self.received_path.name,
            file_hash,
        )

    def verify(self, expected_hash: str) -> tuple[bool, dict]:
        """Validate receiver hash against sender hash."""
        # Security note: sender and receiver hashes must match to prove the
        # encrypted artifact was not corrupted or altered during transfer.
        receiver_hash = calculate_sha256(self.received_path)
        integrity_verified = receiver_hash == expected_hash
        event = log_transfer_step(
            self.transfer_id,
            self.sender_id,
            self.receiver_id,
            "VERIFIED",
            self.receiver_id,
            "Transfer integrity verified."
            if integrity_verified
            else "Transfer integrity verification failed.",
            self.received_path.name,
            receiver_hash,
        )
        return integrity_verified, event


def simulate_file_transfer(
    source_path: str | Path,
    destination_folder: str | Path,
    sender_id: str = "Alice",
    receiver_id: str = "Bob",
    simulate_tampering: bool = False,
    simulate_mitm: bool = False,
) -> dict:
    """Run a sender-to-receiver encrypted file transfer simulation.

    Security note: this transfer simulation copies only the encrypted artifact.
    The receiver calculates its own hash and compares it with the sender hash
    to detect corruption or tampering during transfer.

    When ``simulate_mitm`` is True, interception is delegated to
    ``transfer.mitm_simulator`` (educational MITM). Legacy ``simulate_tampering``
    uses inline byte modification when MITM is not enabled.
    """
    transfer_id = str(uuid4())
    sender = TransferSender(transfer_id, sender_id, receiver_id, source_path)
    events = [
        sender.create_session(),
        sender.confirm_encrypted_payload(),
    ]
    sender_hash = events[-1]["file_hash"]
    destination_path, sent_event = sender.send(destination_folder)
    events.append(sent_event)

    mitm_intercept: dict | None = None
    mitm_outcome: dict | None = None

    if simulate_mitm and destination_path.exists():
        from transfer.mitm_simulator import ATTACKER_ID, intercept_and_modify

        mitm_intercept = intercept_and_modify(destination_path)
        events.append(
            log_transfer_step(
                transfer_id,
                sender_id,
                receiver_id,
                "MITM_INTERCEPTED",
                ATTACKER_ID,
                mitm_intercept["description"],
                mitm_intercept["file_name"],
                mitm_intercept["sender_hash_after"],
            )
        )
    elif simulate_tampering and destination_path.exists():
        content = bytearray(destination_path.read_bytes())
        if content:
            content[0] = content[0] ^ 0xFF
        else:
            content.extend(b"TAMPERED")
        destination_path.write_bytes(content)

    receiver = TransferReceiver(transfer_id, sender_id, receiver_id, destination_path)
    received_event = receiver.receive()
    receiver_hash = received_event["file_hash"]
    events.append(received_event)

    integrity_verified, verified_event = receiver.verify(sender_hash)
    events.append(verified_event)

    compromised = simulate_mitm and not integrity_verified

    if simulate_mitm and mitm_intercept is not None:
        from transfer.mitm_simulator import build_mitm_outcome

        mitm_outcome = build_mitm_outcome(
            mitm_intercept,
            transfer_id=transfer_id,
            sender_hash=sender_hash,
            receiver_hash=receiver_hash,
            integrity_verified=integrity_verified,
        )

    transfer_status = "VERIFIED" if integrity_verified else "FAILED"
    if compromised:
        transfer_status = "COMPROMISED"

    return {
        "transfer_id": transfer_id,
        "session_id": transfer_id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "source_file": str(Path(source_path)),
        "destination_file": str(destination_path),
        "sender_hash": sender_hash,
        "receiver_hash": receiver_hash,
        "integrity_verified": integrity_verified,
        "status": transfer_status,
        "compromised": compromised,
        "mitm_simulated": simulate_mitm,
        "mitm": mitm_outcome,
        "lifecycle": list(MITM_TRANSFER_STATUSES if simulate_mitm else TRANSFER_STATUSES),
        "events": events,
    }


def get_transfer_history(limit: int = 100) -> list[dict]:
    """Return transfer lifecycle history for future backend/API views."""
    init_database()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                COALESCE(transfer_id, session_id) AS transfer_id,
                COALESCE(sender_id, 'Alice') AS sender_id,
                COALESCE(receiver_id, 'Bob') AS receiver_id,
                status,
                actor,
                message,
                file_name,
                file_hash,
                created_at
            FROM transfer_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_transfer_history_by_id(transfer_id: str) -> list[dict]:
    """Return all logged stages for one transfer ID in lifecycle order."""
    init_database()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                COALESCE(transfer_id, session_id) AS transfer_id,
                COALESCE(sender_id, 'Alice') AS sender_id,
                COALESCE(receiver_id, 'Bob') AS receiver_id,
                status,
                actor,
                message,
                file_name,
                file_hash,
                created_at
            FROM transfer_logs
            WHERE COALESCE(transfer_id, session_id) = ?
            ORDER BY id ASC
            """,
            (transfer_id,),
        ).fetchall()

    return [dict(row) for row in rows]
