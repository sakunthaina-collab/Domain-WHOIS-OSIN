"""Forensic report rendering for Trustworthy Agent.

Developer: NAKARIN SAKULTHAI
License: MIT License
"""
from __future__ import annotations

import hashlib
import json
from io import BytesIO
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors


def model_dict(incident: Any) -> dict[str, Any]:
    return incident.model_dump() if hasattr(incident, "model_dump") else incident


def report_payload(incident: Any, integrity_ok: bool) -> dict[str, Any]:
    item = model_dict(incident)
    return {
        "report_type": "defensive-incident-forensic-report",
        "report_version": "1.0",
        "developer": "NAKARIN SAKULTHAI",
        "license": "MIT License",
        "incident": item,
        "integrity": {"audit_chain": "verified" if integrity_ok else "tampered", "attribution": item.get("attribution", "unknown")},
    }


def render_markdown(incident: Any, integrity_ok: bool) -> str:
    item = model_dict(incident)
    lines = [
        "# Defensive Incident Forensic Report",
        "",
        "> DEMO / DEFENSIVE-ONLY REPORT — attribution is not established by this document.",
        "",
        f"- **Incident ID:** `{item['incident_id']}`",
        f"- **Status:** `{item['status']}`",
        f"- **Severity:** `{item['severity']}`",
        f"- **Risk score:** `{item['risk_score']}/100`",
        f"- **Confidence:** `{item['confidence']}`",
        f"- **Attribution:** `{item.get('attribution', 'unknown')}`",
        f"- **Created:** `{item['created_at']}`",
        "",
        "## Executive finding",
        "",
        "This report records defensive observations, risk signals, evidence hashes, and approval history. It does not establish actor attribution and does not authorize offensive action.",
        "",
        "## Risk signal breakdown",
        "",
        "| Category | Factor | Weight | Detail | Evidence |\n|---|---|---:|---|---|",
    ]
    for signal in item.get("signals", []):
        lines.append(f"| {signal['category']} | `{signal['factor']}` | {signal['weight']} | {signal['detail']} | {', '.join(signal.get('evidence_ids', [])) or '—'} |")
    lines += ["", "## Evidence integrity", "", f"- **Audit chain:** `{'verified' if integrity_ok else 'tampered'}`", f"- **Evidence records:** `{len(item.get('evidence', []))}`", "", "| Evidence ID | Claim | Source | Retrieved | Raw response SHA-256 |", "|---|---|---|---|---|"]
    for evidence in item.get("evidence", []):
        lines.append(f"| `{evidence['evidence_id']}` | {evidence['claim']} | {evidence['source']} | {evidence['retrieved_at']} | `{evidence['raw_response_sha256']}` |")
    lines += ["", "## Audit timeline", "", "| Seq | Timestamp | Action | Actor | Entry hash |", "|---:|---|---|---|---|"]
    for entry in item.get("audit_trail", []):
        lines.append(f"| {entry['sequence']} | {entry['ts']} | `{entry['action']}` | {entry['actor']} | `{entry['entry_hash']}` |")
    lines += ["", "## Governance notes", "", "- Human approval is required for containment actions.", "- External actions are disabled in this prototype.", "- Offensive actions such as exploit, brute force, port scan, and attack-back are prohibited.", "", "---", "", "Developer: NAKARIN SAKULTHAI  ", "License: MIT License"]
    return "\n".join(lines) + "\n"


def render_pdf(incident: Any, integrity_ok: bool) -> bytes:
    item = model_dict(incident)
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("Defensive Incident Forensic Report", styles["Title"]), Paragraph("DEMO / DEFENSIVE-ONLY — attribution is not established.", styles["Normal"]), Spacer(1, 8)]
    summary = [["Incident ID", item["incident_id"]], ["Status", item["status"]], ["Severity", item["severity"]], ["Risk score", f"{item['risk_score']}/100"], ["Confidence", item["confidence"]], ["Attribution", item.get("attribution", "unknown")], ["Audit chain", "verified" if integrity_ok else "tampered"]]
    table = Table(summary, colWidths=[42 * mm, 125 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9f3f5")), ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [table, Spacer(1, 12), Paragraph("Risk signal breakdown", styles["Heading2"])]
    signal_rows = [["Category", "Factor", "Weight", "Detail"]]
    for signal in item.get("signals", []):
        signal_rows.append([signal["category"], signal["factor"], str(signal["weight"]), signal["detail"]])
    signal_table = Table(signal_rows, colWidths=[25 * mm, 42 * mm, 18 * mm, 82 * mm], repeatRows=1)
    signal_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f5360")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [signal_table, Spacer(1, 12), Paragraph("Evidence hashes", styles["Heading2"])]
    evidence_rows = [["ID", "Source", "SHA-256"]] + [[e["evidence_id"], e["source"], e["raw_response_sha256"]] for e in item.get("evidence", [])]
    evidence_table = Table(evidence_rows, colWidths=[28 * mm, 45 * mm, 94 * mm], repeatRows=1)
    evidence_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f5360")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 6), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [evidence_table, Spacer(1, 12), Paragraph("Governance: human approval required; external actions disabled; offensive actions prohibited.", styles["Normal"]), Spacer(1, 12), Paragraph("Developer: NAKARIN SAKULTHAI · MIT License", styles["Normal"])]
    doc.build(story)
    return buffer.getvalue()


def report_sha256(markdown: str) -> str:
    return hashlib.sha256(markdown.encode("utf-8")).hexdigest()
