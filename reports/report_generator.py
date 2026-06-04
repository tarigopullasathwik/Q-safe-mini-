"""PDF security report builder for Q-SAFE Nexus (ReportLab)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

REPORTS_SUBDIR = "generated"


def report_output_path(reports_root: Path, transfer_id: str) -> Path:
    """Return the canonical PDF path for a transfer."""
    return reports_root / REPORTS_SUBDIR / f"security_report_{transfer_id}.pdf"


def build_recommendations(context: dict[str, Any]) -> list[str]:
    """Derive actionable recommendations from aggregated report context."""
    items: list[str] = []

    scan = context.get("scan") or {}
    score = context.get("security_score") or {}
    attacks = context.get("attacks") or []

    v2_score = score.get("total_score") or scan.get("v2_score")
    risk = score.get("risk_category") or scan.get("v2_risk_category") or "UNKNOWN"

    if v2_score is not None and v2_score < 60:
        items.append(
            "Security score is below acceptable thresholds. Review encryption, "
            "transfer integrity, and threat findings before releasing this file."
        )
    if risk in {"MEDIUM RISK", "HIGH RISK"}:
        items.append(
            f"Risk category is {risk}. Schedule a full post-quantum readiness review."
        )
    if not scan.get("transfer_integrity", True):
        items.append(
            "Transfer integrity verification failed. Re-transmit the encrypted "
            "artifact and confirm SHA-256 hashes match at the receiver."
        )
    if scan.get("bb84_eavesdropping_detected"):
        items.append(
            "BB84 simulation reported eavesdropping indicators. Re-run key "
            "exchange and avoid reusing compromised session material."
        )
    if scan.get("findings"):
        items.append(
            "Weak classical cryptography patterns were detected. Plan migration "
            "to NIST post-quantum algorithms for long-term confidentiality."
        )
    if any(a.get("attack_type") == "MITM" for a in attacks):
        items.append(
            "A MITM attack was logged against this transfer. Audit network path "
            "controls and enforce end-to-end integrity monitoring."
        )
    if scan.get("mitm_simulated") or scan.get("replay_simulated"):
        items.append(
            "This record includes simulated attack exercises. Use results to "
            "validate detection pipelines and dashboard alerting."
        )

    if not items:
        items.append(
            "No critical issues identified. Continue periodic scanning, encrypted "
            "transfers, and BB84 key-exchange health monitoring."
        )

    return items


def build_report_context_summary(context: dict[str, Any]) -> dict[str, Any]:
    """Flatten context into section payloads used by the PDF renderer."""
    scan = context.get("scan") or {}
    transfer = context.get("transfer") or {}
    transfer_log = scan.get("transfer_log") or transfer
    transfer_id = context.get("transfer_id", "")
    score = context.get("security_score") or {}

    return {
        "transfer_id": transfer_id,
        "generated_at": context.get("generated_at")
        or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "file_information": {
            "File name": scan.get("file_name", "—"),
            "Encrypted file": scan.get("encrypted_file_name", "—"),
            "Original SHA-256": _short_hash(scan.get("original_hash")),
            "Encrypted SHA-256": _short_hash(scan.get("encrypted_hash")),
            "Scan recorded": scan.get("created_at", "—"),
        },
        "encryption_analysis": {
            "Status": scan.get("encryption_status", "—"),
            "Algorithm": "AES-256-GCM",
            "Plaintext retained": "No (removed after encryption)",
        },
        "bb84_analysis": {
            "Key length (bits)": str(scan.get("bb84_key_length", "—")),
            "QBER": _format_qber(scan.get("bb84_qber")),
            "Eavesdropping detected": _yes_no(scan.get("bb84_eavesdropping_detected")),
        },
        "transfer_analysis": {
            "Transfer ID": transfer_id,
            "Status": scan.get("transfer_status")
            or transfer_log.get("status", "—"),
            "Integrity verified": _yes_no(scan.get("transfer_integrity")),
            "Sender hash": _short_hash(
                transfer_log.get("sender_hash") or scan.get("encrypted_hash")
            ),
            "Receiver hash": _short_hash(transfer_log.get("receiver_hash")),
            "Compromised": _yes_no(transfer_log.get("compromised")),
        },
        "threat_analysis": {
            "Security status (v1)": scan.get("security_status", "—"),
            "Risk score (v1)": str(scan.get("risk_score", "—")),
            "Weak crypto findings": str(len(scan.get("findings") or [])),
            "Tampering checked": _yes_no((scan.get("tampering") or {}).get("checked")),
        },
        "security_score": {
            "Score (v2)": str(score.get("total_score") or scan.get("v2_score") or "—"),
            "Risk category": score.get("risk_category")
            or scan.get("v2_risk_category")
            or "—",
            "Encryption pts": str(score.get("encryption_score", "—")),
            "BB84 pts": str(score.get("bb84_score", "—")),
            "Transfer pts": str(score.get("transfer_score", "—")),
            "Threat pts": str(score.get("threat_score", "—")),
            "Attack pts": str(score.get("attack_score", "—")),
        },
        "attacks": context.get("attacks") or [],
        "recommendations": build_recommendations(context),
    }


def generate_security_report_pdf(context: dict[str, Any], output_path: Path) -> Path:
    """Render a professional PDF report to ``output_path``."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary = build_report_context_summary(context)
    transfer_id = summary["transfer_id"]

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"Q-SAFE Security Report — {transfer_id}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#0f766e"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#134e4a"),
        spaceBefore=14,
        spaceAfter=8,
    )
    body_style = styles["BodyText"]

    story: list[Any] = []
    story.append(Paragraph("Q-SAFE Nexus — Security Assessment Report", title_style))
    story.append(
        Paragraph(
            f"<b>Transfer ID:</b> {transfer_id}<br/>"
            f"<b>Generated:</b> {summary['generated_at']}",
            body_style,
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    _add_section(story, heading_style, body_style, "File Information", summary["file_information"])
    _add_section(story, heading_style, body_style, "Encryption Analysis", summary["encryption_analysis"])
    _add_section(story, heading_style, body_style, "BB84 Analysis", summary["bb84_analysis"])
    _add_section(story, heading_style, body_style, "Transfer Analysis", summary["transfer_analysis"])
    _add_section(story, heading_style, body_style, "Threat Analysis", summary["threat_analysis"])
    _add_section(story, heading_style, body_style, "Security Score", summary["security_score"])

    story.append(Paragraph("Attack Events", heading_style))
    attacks = summary["attacks"]
    if attacks:
        attack_rows = [["Type", "Status", "Integrity", "Timestamp"]]
        for attack in attacks:
            attack_rows.append(
                [
                    attack.get("attack_type", "—"),
                    attack.get("attack_status") or attack.get("status", "—"),
                    attack.get("integrity_result") or "—",
                    attack.get("created_at") or attack.get("timestamp", "—"),
                ]
            )
        story.append(_key_value_table(attack_rows[1:], attack_rows[0]))
    else:
        story.append(Paragraph("No attack events recorded for this transfer.", body_style))

    story.append(Paragraph("Recommendations", heading_style))
    for index, item in enumerate(summary["recommendations"], start=1):
        story.append(Paragraph(f"{index}. {item}", body_style))
        story.append(Spacer(1, 0.08 * inch))

    doc.build(story)
    return output_path


def extract_report_text(pdf_path: Path) -> str:
    """Extract text from a generated PDF (used in tests)."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ImportError("pypdf is required to extract PDF text in tests") from exc

    reader = PdfReader(str(pdf_path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _add_section(
    story: list[Any],
    heading_style: ParagraphStyle,
    body_style: ParagraphStyle,
    title: str,
    data: dict[str, str],
) -> None:
    story.append(Paragraph(title, heading_style))
    rows = [[key, value] for key, value in data.items()]
    story.append(_key_value_table(rows))
    story.append(Spacer(1, 0.12 * inch))


def _key_value_table(rows: list[list[str]], header: list[str] | None = None) -> Table:
    if header:
        table_data = [header, *rows]
    else:
        table_data = [["Field", "Value"], *rows]
    table = Table(table_data, colWidths=[2.2 * inch, 4.3 * inch])
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecfdf5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#134e4a")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#99f6e4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    table.setStyle(TableStyle(style_commands))
    return table


def _short_hash(value: Any) -> str:
    if not value:
        return "—"
    text = str(value)
    return f"{text[:16]}…" if len(text) > 16 else text


def _format_qber(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value):.2%}"
    except (TypeError, ValueError):
        return str(value)


def _yes_no(value: Any) -> str:
    if value is None:
        return "—"
    return "Yes" if bool(value) else "No"
