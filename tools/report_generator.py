"""
Forensic Report Generation Utility for Autonomous Multi-Agent SOC Framework.
Exports structured incident dossiers, mitigation playbooks, and telemetry audits
in TXT, Markdown, CSV, and print-ready HTML/PDF formats.
"""

import io
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

    @staticmethod
    def generate_investigation_pdf(inv_data: Dict[str, Any], event_data: Optional[Dict[str, Any]] = None) -> bytes:
        """Generates an academic, publication-quality forensic PDF report for the incident investigation."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()

            inv_id = str(inv_data.get("investigation_id", "INV-UNKNOWN"))
            verdict = str(inv_data.get("verdict", "PENDING"))
            is_mal = "MALICIOUS" in verdict.upper()
            v_color = colors.HexColor("#dc2626") if is_mal else colors.HexColor("#16a34a")
            score = inv_data.get("composite_threat_score", 0)
            confidence = float(inv_data.get("overall_confidence", 0.0)) * 100
            summary = inv_data.get("executive_summary", "No summary provided.")
            timestamp = str(inv_data.get("timestamp", datetime.utcnow().isoformat() + "Z"))

            title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor("#0f172a"), spaceAfter=4)
            sub_style = ParagraphStyle('SubStyle', parent=styles['Normal'], fontSize=8.5, textColor=colors.HexColor("#64748b"), spaceAfter=12)
            h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=11, textColor=colors.HexColor("#0284c7"), spaceBefore=10, spaceAfter=4)
            body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=8.5, leading=12, textColor=colors.HexColor("#1e293b"))
            cell_bold = ParagraphStyle('CellBold', parent=styles['Normal'], fontSize=8, leading=10, fontName="Helvetica-Bold")
            cell_norm = ParagraphStyle('CellNorm', parent=styles['Normal'], fontSize=8, leading=10)

            elements = []

            # Document Header
            elements.append(Paragraph("🛡️ Autonomous SOC Incident Forensic Dossier", title_style))
            elements.append(Paragraph(
                f"<b>Project Title:</b> An Autonomous Multi-Agent Framework for Fraud & Cyber Threat Detection Using LLMs<br/>"
                f"<b>Investigation Reference:</b> {inv_id} &nbsp;|&nbsp; <b>Alert ID:</b> {inv_data.get('alert_id', 'N/A')} &nbsp;|&nbsp; <b>Timestamp:</b> {timestamp}",
                sub_style
            ))

            # Verdict Box Table
            verdict_text = f"<font color='white'><b>VERDICT: {verdict}</b> &nbsp;|&nbsp; Threat Score: {score}/100 &nbsp;|&nbsp; Confidence: {confidence:.1f}%</font>"
            verdict_table = Table([[Paragraph(verdict_text, ParagraphStyle('V', parent=styles['Normal'], fontSize=10, textColor=colors.white))]], colWidths=[540])
            verdict_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), v_color),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            elements.append(verdict_table)
            elements.append(Spacer(1, 10))

            # Executive Forensic Summary
            elements.append(Paragraph("Executive Forensic Summary", h2_style))
            elements.append(Paragraph(str(summary), body_style))
            elements.append(Spacer(1, 8))

            # MITRE Tactics & Techniques
            tactics = inv_data.get("mitre_tactics") or []
            techs = inv_data.get("mitre_techniques") or []
            if isinstance(tactics, str):
                try: tactics = json.loads(tactics)
                except Exception: tactics = [tactics]
            if isinstance(techs, str):
                try: techs = json.loads(techs)
                except Exception: techs = [techs]

            elements.append(Paragraph("MITRE ATT&CK Mapping", h2_style))
            mitre_info = f"<b>Tactics:</b> {', '.join(tactics) if tactics else 'None'}<br/><b>Techniques:</b> {', '.join(techs) if techs else 'None'}"
            elements.append(Paragraph(mitre_info, body_style))
            elements.append(Spacer(1, 8))

            # Agent Consensus Votes Table
            votes = inv_data.get("agent_votes") or {}
            if isinstance(votes, str):
                try: votes = json.loads(votes)
                except Exception: votes = {}
            if votes:
                elements.append(Paragraph("Specialized Agent Consensus Breakdown", h2_style))
                vote_data = [[Paragraph("Agent Name", cell_bold), Paragraph("Consensus Verdict / Findings", cell_bold)]]
                for ag_name, ag_vote in votes.items():
                    vote_data.append([Paragraph(str(ag_name), cell_norm), Paragraph(str(ag_vote), cell_norm)])
                t_vote = Table(vote_data, colWidths=[200, 340])
                t_vote.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_vote)
                elements.append(Spacer(1, 8))

            # Containment Playbook Table
            playbook = inv_data.get("containment_playbook") or []
            if isinstance(playbook, str):
                try: playbook = json.loads(playbook)
                except Exception: playbook = []
            if playbook:
                elements.append(Paragraph("Automated Incident Containment Playbook", h2_style))
                pb_data = [[Paragraph("#", cell_bold), Paragraph("Priority", cell_bold), Paragraph("Action", cell_bold), Paragraph("Target", cell_bold), Paragraph("Description", cell_bold)]]
                for p in playbook:
                    step = str(p.get("step_number", p.get("step", 1)))
                    priority = str(p.get("priority", "HIGH"))
                    action = str(p.get("action_type", p.get("action", "")))
                    target = str(p.get("target", ""))
                    desc = str(p.get("description", ""))
                    pb_data.append([
                        Paragraph(step, cell_norm),
                        Paragraph(priority, cell_norm),
                        Paragraph(action, cell_norm),
                        Paragraph(target, cell_norm),
                        Paragraph(desc, cell_norm)
                    ])
                t_pb = Table(pb_data, colWidths=[25, 55, 110, 110, 240])
                t_pb.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(t_pb)
                elements.append(Spacer(1, 8))

            # Raw Event Telemetry (truncated if excessive)
            if event_data:
                elements.append(Paragraph("Event Telemetry Reference", h2_style))
                telemetry_str = json.dumps(event_data, indent=2)
                if len(telemetry_str) > 1200:
                    telemetry_str = telemetry_str[:1200] + "\n... [truncated for report brevity]"
                t_p = Paragraph(f"<font face='Courier' size='7'>{telemetry_str.replace('<', '&lt;').replace('>', '&gt;').replace(chr(10), '<br/>')}</font>", body_style)
                elements.append(t_p)

            doc.build(elements)
            return buf.getvalue()
        except Exception as e:
            # Fallback simple text-based PDF or empty bytes
            try:
                import io
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph
                from reportlab.lib.styles import getSampleStyleSheet
                buf = io.BytesIO()
                doc = SimpleDocTemplate(buf, pagesize=letter)
                styles = getSampleStyleSheet()
                doc.build([Paragraph(f"Forensic Report: {inv_data.get('investigation_id', 'INCIDENT')}<br/>Verdict: {inv_data.get('verdict')}", styles['Normal'])])
                return buf.getvalue()
            except Exception:
                return b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
