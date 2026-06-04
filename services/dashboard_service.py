"""Dashboard summary services for Q-SAFE Nexus."""

from services.score_service import get_scores


def _safe_avg(values: list) -> int:
    """Return integer average or 0 for an empty list."""
    return round(sum(values) / len(values)) if values else 0


def summarize_dashboard(results: list[dict]) -> dict:
    """Build dashboard summary values from uploaded file scan results."""
    if not results:
        return {
            "uploaded_count": 0,
            "encrypted_count": 0,
            "threat_level": "SAFE",
            "security_score": 100,
            "weak_crypto_detected": "None",
            "hash_integrity": "No files",
            "transfer_status": "Ready",
            "latest_key_length": 0,
            # v2 engine defaults
            "v2_avg_score": 100,
            "v2_latest_score": None,
            "v2_latest_category": None,
            "v2_category_counts": {},
            "v2_avg_encryption": 0,
            "v2_avg_bb84": 0,
            "v2_avg_transfer": 0,
            "v2_avg_threat": 0,
            "v2_avg_attack": 0,
        }

    latest_result = results[0]
    highest_risk = max(result["risk_score"] for result in results)
    average_score = sum(100 - result["risk_score"] for result in results) // len(results)

    if highest_risk >= 70:
        threat_level = "DANGEROUS"
    elif highest_risk >= 30:
        threat_level = "WARNING"
    else:
        threat_level = "SAFE"

    weak_crypto_detected = (
        "Detected"
        if any(result["findings"] for result in results)
        else "None"
    )

    transfer_failures = [result for result in results if not result["transfer_integrity"]]

    # ---- v2 Score Engine aggregates ----------------------------------------
    score_rows = get_scores(limit=500)

    v2_latest_score    = score_rows[0]["total_score"]       if score_rows else None
    v2_latest_category = score_rows[0]["risk_category"]     if score_rows else None
    v2_avg_score       = _safe_avg([r["total_score"]        for r in score_rows])
    v2_avg_encryption  = _safe_avg([r["encryption_score"]   for r in score_rows])
    v2_avg_bb84        = _safe_avg([r["bb84_score"]         for r in score_rows])
    v2_avg_transfer    = _safe_avg([r["transfer_score"]     for r in score_rows])
    v2_avg_threat      = _safe_avg([r["threat_score"]       for r in score_rows])
    v2_avg_attack      = _safe_avg([r["attack_score"]       for r in score_rows])

    v2_category_counts: dict[str, int] = {}
    for row in score_rows:
        cat = row["risk_category"]
        v2_category_counts[cat] = v2_category_counts.get(cat, 0) + 1

    return {
        "uploaded_count": len(results),
        "encrypted_count": sum(1 for result in results if result["encrypted_file_name"]),
        "threat_level": threat_level,
        "security_score": average_score,
        "weak_crypto_detected": weak_crypto_detected,
        "hash_integrity": "Failed" if transfer_failures else "Verified",
        "transfer_status": "FAILED" if transfer_failures else latest_result["transfer_status"],
        "latest_key_length": latest_result["bb84_key_length"],
        # v2 engine
        "v2_avg_score": v2_avg_score,
        "v2_latest_score": v2_latest_score,
        "v2_latest_category": v2_latest_category,
        "v2_category_counts": v2_category_counts,
        "v2_avg_encryption": v2_avg_encryption,
        "v2_avg_bb84": v2_avg_bb84,
        "v2_avg_transfer": v2_avg_transfer,
        "v2_avg_threat": v2_avg_threat,
        "v2_avg_attack": v2_avg_attack,
    }
