"""
Forensic Report Generation Utility for Autonomous Multi-Agent SOC Framework.
Exports structured incident dossiers, mitigation playbooks, and telemetry audits
in TXT, Markdown, CSV, and print-ready HTML/PDF formats.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional

class ForensicReportGenerator:
    @staticmethod
    def generate_investigation_markdown(inv_data: Dict[str, Any], event_data: Optional[Dict[str, Any]] = None) -> str:
        """Generates an academic and operational forensic investigation report in Markdown format."""
        inv_id = inv_data.get("investigation_id", "INV-UNKNOWN")
        verdict = inv_data.get("verdict", "PENDING")
        score = inv_data.get("composite_threat_score", 0)
        confidence = inv_data.get("overall_confidence", 0.0) * 100
        summary = inv_data.get("executive_summary", "No summary provided.")
        timestamp = inv_data.get("timestamp", datetime.utcnow().isoformat() + "Z")

        # Parse JSON fields if strings
        mitre_tactics = inv_data.get("mitre_tactics") or []
        if isinstance(mitre_tactics, str):
            try:
                mitre_tactics = json.loads(mitre_tactics)
            except Exception:
                mitre_tactics = [mitre_tactics]

        mitre_techs = inv_data.get("mitre_techniques") or []
        if isinstance(mitre_techs, str):
            try:
                mitre_techs = json.loads(mitre_techs)
            except Exception:
                mitre_techs = [mitre_techs]

        votes = inv_data.get("agent_votes") or {}
        if isinstance(votes, str):
            try:
                votes = json.loads(votes)
            except Exception:
                votes = {}

        playbook = inv_data.get("containment_playbook") or []
        if isinstance(playbook, str):
            try:
                playbook = json.loads(playbook)
            except Exception:
                playbook = []

        md = f"""# 🛡️ Autonomous SOC Incident Forensic Dossier: {inv_id}

**Project Title:** An Autonomous Multi-Agent Framework for Fraud and Cyber Threat Detection Using Large Language Models  
**Report Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Incident Reference:** `{inv_id}` &nbsp;|&nbsp; **Alert Reference:** `{inv_data.get('alert_id', 'N/A')}`  
**Classification:** ENTERPRISE RESTRICTED / DEFENSIVE FORENSICS

---

## 1. Executive Incident Assessment

| Assessment Dimension | Operational Finding |
| :--- | :--- |
| **Final Multi-Agent Verdict** | **{verdict}** |
| **Composite Threat Score** | **{score}/100** |
| **Consensus Confidence** | **{confidence:.1f}%** |
| **Analysis Timestamp** | `{timestamp}` |

### Forensic Summary
> {summary}

---

## 2. Specialized Multi-Agent Consensus & Votes

"""
        if votes:
            md += "| Agent Name | Consensus Vote / Finding |\n| :--- | :--- |\n"
            for agent, vote in votes.items():
                md += f"| **{agent}** | `{vote}` |\n"
        else:
            md += "*No specialized agent voting breakdown recorded.*\n"

        md += "\n---\n\n## 3. Adversary Tactics & Techniques (MITRE ATT&CK)\n\n"
        md += f"- **Tactics Observed:** `{', '.join(mitre_tactics) if mitre_tactics else 'None'}`\n"
        md += f"- **Techniques Identified:** `{', '.join(mitre_techs) if mitre_techs else 'None'}`\n\n"

        md += "---\n\n## 4. Orchestrated Incident Containment Playbook\n\n"
        if playbook:
            md += "| Step | Priority | Action Type | Target Entity | Technical Action Description |\n"
            md += "| :---: | :---: | :--- | :--- | :--- |\n"
            for p in playbook:
                step_num = p.get("step_number") or p.get("step", 1)
                priority = p.get("priority", "HIGH")
                action = p.get("action_type") or p.get("action", "MITIGATION")
                target = p.get("target", "N/A")
                desc = p.get("description", "")
                md += f"| {step_num} | **{priority}** | `{action}` | `{target}` | {desc} |\n"
        else:
            md += "*No containment actions required for benign/clean telemetry.*\n"

        if event_data:
            md += "\n---\n\n## 5. Raw Event Telemetry\n\n```json\n"
            md += json.dumps(event_data, indent=2)
            md += "\n```\n"

        return md

    @staticmethod
    def generate_investigation_text(inv_data: Dict[str, Any], event_data: Optional[Dict[str, Any]] = None) -> str:
        """Generates plain text incident report."""
        md_text = ForensicReportGenerator.generate_investigation_markdown(inv_data, event_data)
        # Clean basic markdown tags
        clean_text = md_text.replace("#", "").replace("**", "").replace("`", "").replace("---", "==================================================")
        return clean_text

    @staticmethod
    def generate_investigation_csv(inv_data: Dict[str, Any], event_data: Optional[Dict[str, Any]] = None) -> str:
        """Generates CSV format of key incident metrics."""
        rows = [
            ["Metric", "Value"],
            ["Investigation_ID", inv_data.get("investigation_id", "")],
            ["Alert_ID", inv_data.get("alert_id", "")],
            ["Verdict", inv_data.get("verdict", "")],
            ["Composite_Threat_Score", str(inv_data.get("composite_threat_score", 0))],
            ["Overall_Confidence", f"{float(inv_data.get('overall_confidence', 0.0)):.4f}"],
            ["Timestamp", inv_data.get("timestamp", "")],
            ["Executive_Summary", inv_data.get("executive_summary", "").replace('"', '""')]
        ]
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(rows)
        return output.getvalue()

    @staticmethod
    def generate_investigation_html(inv_data: Dict[str, Any], event_data: Optional[Dict[str, Any]] = None) -> str:
        """Generates an enterprise-styled, print-friendly HTML dossier for PDF conversion or browser viewing."""
        inv_id = inv_data.get("investigation_id", "INV-UNKNOWN")
        verdict = inv_data.get("verdict", "PENDING")
        is_mal = "MALICIOUS" in verdict.upper()
        v_color = "#dc3545" if is_mal else "#28a745"
        score = inv_data.get("composite_threat_score", 0)
        confidence = float(inv_data.get("overall_confidence", 0.0)) * 100
        summary = inv_data.get("executive_summary", "No summary provided.")
        timestamp = inv_data.get("timestamp", datetime.utcnow().isoformat() + "Z")

        votes = inv_data.get("agent_votes") or {}
        if isinstance(votes, str):
            try:
                votes = json.loads(votes)
            except Exception:
                votes = {}

        playbook = inv_data.get("containment_playbook") or []
        if isinstance(playbook, str):
            try:
                playbook = json.loads(playbook)
            except Exception:
                playbook = []

        vote_rows = "".join([f"<tr><td><b>{agent}</b></td><td><code>{v}</code></td></tr>" for agent, v in votes.items()])
        playbook_rows = "".join([
            f"<tr><td>{p.get('step_number', p.get('step', 1))}</td><td><b>{p.get('priority', 'HIGH')}</b></td><td><code>{p.get('action_type', p.get('action', ''))}</code></td><td><code>{p.get('target', '')}</code></td><td>{p.get('description', '')}</td></tr>"
            for p in playbook
        ])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Incident Report: {inv_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1e293b; padding: 30px; max-width: 900px; margin: auto; }}
        .header {{ border-bottom: 3px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; }}
        .badge {{ background-color: {v_color}; color: white; padding: 6px 14px; border-radius: 14px; font-weight: bold; font-size: 1.1em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0 25px 0; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
        th {{ background-color: #f1f5f9; }}
        .callout {{ background-color: #f8fafc; border-left: 5px solid #0284c7; padding: 15px; margin: 20px 0; border-radius: 4px; }}
        pre {{ background-color: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>🛡️ Autonomous SOC Incident Forensic Dossier</h2>
        <p><b>Project Title:</b> An Autonomous Multi-Agent Framework for Fraud & Cyber Threat Detection Using Large Language Models</p>
        <p><b>Investigation ID:</b> <code>{inv_id}</code> | <b>Timestamp:</b> {timestamp}</p>
        <p><b>Incident Verdict:</b> <span class="badge">{verdict}</span> | <b>Threat Score:</b> {score}/100 | <b>Confidence:</b> {confidence:.1f}%</p>
    </div>

    <div class="callout">
        <h3>Executive Forensic Summary</h3>
        <p>{summary}</p>
    </div>

    <h3>Specialized Agent Consensus Breakdown</h3>
    <table>
        <thead><tr><th>Agent Name</th><th>Consensus Vote</th></tr></thead>
        <tbody>{vote_rows if vote_rows else "<tr><td colspan='2'>No agent breakdown recorded.</td></tr>"}</tbody>
    </table>

    <h3>Automated Incident Containment Playbook</h3>
    <table>
        <thead><tr><th>Step</th><th>Priority</th><th>Action</th><th>Target</th><th>Description</th></tr></thead>
        <tbody>{playbook_rows if playbook_rows else "<tr><td colspan='5'>No containment actions required.</td></tr>"}</tbody>
    </table>

    <h3>Raw Investigation Telemetry</h3>
    <pre>{json.dumps(event_data or {}, indent=2)}</pre>
</body>
</html>
"""
        return html
