"""Upload workflow service for Q-SAFE Nexus."""

from pathlib import Path

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from services.analyzer_service import scan_uploaded_file
from services.encryption_service import encrypt_uploaded_file
from services.key_service import generate_bb84_aes_key
from services.result_store import result_store
from services.transfer_service import execute_encrypted_transfer
from services.attack_service import log_attack, log_mitm_attack
from services.score_service import evaluate_security_score, store_score


class UploadValidationError(ValueError):
    """Raised when an uploaded file is missing or invalid."""


def validate_upload(file: FileStorage | None) -> str:
    """Validate upload input and return a safe filename."""
    if file is None or file.filename == "":
        raise UploadValidationError("Please select a file before uploading.")

    # Security note: secure_filename removes path separators and unsafe names.
    file_name = secure_filename(file.filename)
    if file_name == "":
        raise UploadValidationError("Please upload a file with a valid file name.")

    return file_name


def process_uploaded_file(
    file: FileStorage,
    upload_folder: str | Path,
    transfer_folder: str | Path,
    simulate_mitm: bool = False,
    simulate_replay: bool = False,
    simulate_tampering: bool = False,
) -> dict:
    """Save, analyze, encrypt, and record one uploaded file with simulated attacks."""
    upload_path = Path(upload_folder)
    upload_path.mkdir(exist_ok=True)

    file_name = validate_upload(file)
    saved_path = upload_path / file_name
    file.save(saved_path)

    scan_result = scan_uploaded_file(
        saved_path,
        mitm_simulated=simulate_mitm,
        replay_simulated=simulate_replay,
    )

    # Security note: AES key material is derived from the simulated BB84 output.
    key_result = generate_bb84_aes_key(
        key_length=128,
        simulate_eavesdropper=simulate_mitm,
    )
    encryption_result = encrypt_uploaded_file(saved_path, key_result["aes_key"])

    # Security note: plaintext is removed after encryption and scanning so the
    # system retains only protected file content plus audit hashes.
    saved_path.unlink(missing_ok=True)

    transfer_result = execute_encrypted_transfer(
        encryption_result["encrypted_path"],
        transfer_folder,
        simulate_mitm=simulate_mitm,
        simulate_tampering=simulate_tampering and not simulate_mitm,
    )

    mitm_attack_log: dict | None = None
    if simulate_mitm and transfer_result.get("mitm"):
        mitm_outcome = dict(transfer_result["mitm"])
        if key_result["bb84_eavesdropping_detected"]:
            mitm_outcome["description"] += (
                f" BB84 channel QBER {key_result['bb84_qber']:.2%} indicates "
                "quantum eavesdropping during key exchange."
            )
        mitm_attack_log = log_mitm_attack(mitm_outcome)

    if simulate_replay:
        log_attack(
            attack_type="REPLAY",
            file_name=file_name,
            status="BLOCKED",
            details=f"Blocked Replay attack: Duplicated transmission attempt with reused session footprint.",
        )

    if simulate_tampering:
        log_attack(
            attack_type="TAMPERING",
            file_name=file_name,
            status="DETECTED",
            details=f"File tampering detected: hash mismatch on receiver end. Expected: {encryption_result['encrypted_hash']}, Received: {transfer_result['receiver_hash'] or 'None'}",
        )

    from analyzer.pqc_scanner import generate_risk_score, determine_security_status

    final_tampering = {
        "checked": True,
        "tampered": not transfer_result["integrity_verified"],
        "expected_hash": encryption_result["encrypted_hash"],
        "current_hash": transfer_result["receiver_hash"],
    }

    final_risk_score = generate_risk_score(
        scan_result["findings"],
        final_tampering,
        mitm_simulated=simulate_mitm,
        replay_simulated=simulate_replay,
    )

    result = {
        **scan_result,
        "encrypted_file_name": encryption_result["encrypted_file_name"],
        "encryption_status": encryption_result["encryption_status"],
        "encrypted_hash": encryption_result["encrypted_hash"],
        "bb84_key_length": key_result["bb84_key_length"],
        "bb84_eavesdropping_detected": key_result["bb84_eavesdropping_detected"],
        "bb84_qber": key_result["bb84_qber"],
        "transfer_status": transfer_result["status"],
        "transfer_integrity": transfer_result["integrity_verified"],
        "transfer_log": transfer_result,
        "mitm_simulated": simulate_mitm,
        "mitm_attack": mitm_attack_log,
        "compromised": transfer_result.get("compromised", False),
        "replay_simulated": simulate_replay,
        "tampering": final_tampering,
        "risk_score": final_risk_score,
        "security_status": determine_security_status(final_risk_score),
    }

    # --- Security Score Engine v2 (scoring rules live in score_engine.py) ---
    mitm_attack_status = None
    if transfer_result.get("mitm"):
        mitm_attack_status = transfer_result["mitm"]["attack_status"]

    score_result = evaluate_security_score(
        encryption_status=encryption_result["encryption_status"],
        bb84_qber=key_result["bb84_qber"],
        transfer_integrity=transfer_result["integrity_verified"],
        security_status=result["security_status"],
        mitm_simulated=simulate_mitm,
        replay_simulated=simulate_replay,
        tampering_simulated=simulate_tampering,
        mitm_attack_status=mitm_attack_status,
    )
    result["v2_score"] = score_result.score
    result["v2_risk_category"] = score_result.risk_category
    result["v2"] = score_result.to_dict()

    scan_result_id = result_store.add(result)
    result["v2_breakdown"] = store_score(scan_result_id or 0, score_result, file_name)

    return result
