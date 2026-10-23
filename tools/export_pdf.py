"""
Export Script: Converts COMPLETE_PROJECT_ANALYSIS_AND_VIVA_REPORT.md into a high-quality academic PDF.
Utilizes markdown-it-py with custom enterprise CSS, math formatting, and headless Chromium/Edge.
"""

import os
import sys
import re
import subprocess
import shutil
from markdown_it import MarkdownIt

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACT_DIR = r"C:\Users\Hemanth Gowda T\.gemini\antigravity\brain\d13b0228-2574-4661-b4b3-2ffb10e4aeeb"
MD_PATH = os.path.join(ARTIFACT_DIR, "COMPLETE_PROJECT_ANALYSIS_AND_VIVA_REPORT.md")
if not os.path.exists(MD_PATH):
    # Fallback to project root or results directory
    if os.path.exists(os.path.join(ROOT_DIR, "COMPLETE_PROJECT_ANALYSIS_AND_VIVA_REPORT.md")):
        MD_PATH = os.path.join(ROOT_DIR, "COMPLETE_PROJECT_ANALYSIS_AND_VIVA_REPORT.md")
    elif os.path.exists(os.path.join(ROOT_DIR, "results", "EVALUATION_REPORT.md")):
        MD_PATH = os.path.join(ROOT_DIR, "results", "EVALUATION_REPORT.md")

OUTPUT_PDF_PROJECT = os.path.join(ROOT_DIR, "COMPLETE_PROJECT_ANALYSIS_AND_VIVA_REPORT.pdf")
OUTPUT_PDF_ARTIFACT = os.path.join(ARTIFACT_DIR, "COMPLETE_PROJECT_ANALYSIS_AND_VIVA_REPORT.pdf")
TEMP_HTML_PATH = os.path.join(ROOT_DIR, "results", "report_printable.html")

os.makedirs(os.path.join(ROOT_DIR, "results"), exist_ok=True)

def preprocess_markdown(text: str) -> str:
    """Cleans LaTeX math markers and format callouts for optimal HTML printing."""
    # Convert display LaTeX math: $$ \text{Accuracy} = \frac{TP + TN}{Total} $$
    def format_math_block(match):
        inner = match.group(1).strip()
        # Clean LaTeX commands to clean readable typography
        inner = inner.replace(r"\text{Accuracy}", "<strong>Accuracy</strong>")
        inner = inner.replace(r"\text{Precision}", "<strong>Precision</strong>")
        inner = inner.replace(r"\text{Recall (Sensitivity)}", "<strong>Recall (Sensitivity)</strong>")
        inner = inner.replace(r"\text{Recall}", "<strong>Recall</strong>")
        inner = inner.replace(r"\text{Specificity}", "<strong>Specificity</strong>")
        inner = inner.replace(r"\text{Threat}", "Threat")
        inner = inner.replace(r"\times", "×")
        inner = inner.replace(r"\le", "≤")
        inner = inner.replace(r"\ge", "≥")
        inner = inner.replace(r"\ne", "≠")
        inner = inner.replace(r"\in", "∈")
        inner = inner.replace(r"\exists", "∃")
        
        # Replace \frac{A}{B} with (A) / (B)
        inner = re.sub(r"\\frac\{([^{}]+)\}\{([^{}]+)\}", r"(\1) / (\2)", inner)
        inner = re.sub(r"\\frac\{([^{}]+)\}\{([^{}]+)\}", r"(\1) / (\2)", inner)
        return f'<div class="math-card">{inner}</div>'

    text = re.sub(r"\$\$(.*?)\$\$", format_math_block, text, flags=re.DOTALL)

    # Convert inline LaTeX math: $TN = 20,155$
    def format_math_inline(match):
        inner = match.group(1).strip()
        inner = inner.replace(r"\times", "×")
        inner = inner.replace(r"\le", "≤")
        inner = inner.replace(r"\ge", "≥")
        inner = inner.replace(r"\ne", "≠")
        inner = inner.replace(r"\%", "%")
        return f'<span class="math-inline">{inner}</span>'

    text = re.sub(r"(?<!\$)\$([^\$\n]+)\$(?!\$)", format_math_inline, text)

    # Convert callouts: > [!NOTE], > [!WARNING], > [!IMPORTANT]
    text = re.sub(r"> \[!WARNING\]", r'<div class="callout callout-warning"><strong>⚠️ WARNING:</strong>', text)
    text = re.sub(r"> \[!IMPORTANT\]", r'<div class="callout callout-important"><strong>📌 IMPORTANT:</strong>', text)
    text = re.sub(r"> \[!NOTE\]", r'<div class="callout callout-note"><strong>ℹ️ NOTE:</strong>', text)
    text = re.sub(r"> \[!TIP\]", r'<div class="callout callout-tip"><strong>💡 TIP:</strong>', text)

    return text

def build_html(body_html: str) -> str:
    css = """
    @page {
        size: A4;
        margin: 18mm 16mm 18mm 16mm;
        @bottom-right {
            content: "Page " counter(page);
            font-size: 9pt;
            color: #64748b;
        }
    }
    
    * {
        box-sizing: border-box;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        color: #1e293b;
        line-height: 1.6;
        font-size: 10.5pt;
        background: #ffffff;
        margin: 0;
        padding: 0;
    }

    /* Cover / Academic Header Banner */
    .report-header {
        border-bottom: 3px solid #0284c7;
        padding-bottom: 22px;
        margin-bottom: 28px;
    }

    .report-title {
        color: #0f172a;
        font-size: 20pt;
        font-weight: 800;
        line-height: 1.25;
        margin: 0 0 10px 0;
        letter-spacing: -0.5px;
    }

    .report-meta {
        font-size: 10pt;
        color: #475569;
        margin-top: 10px;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
    }

    .report-meta span {
        display: block;
    }

    /* Headings */
    h1 {
        color: #0f172a;
        font-size: 14pt;
        font-weight: 700;
        border-bottom: 1.5px solid #cbd5e1;
        padding-bottom: 6px;
        margin-top: 26px;
        margin-bottom: 14px;
        page-break-after: avoid;
    }

    .phase-break {
        page-break-before: always;
    }

    h2 {
        color: #0369a1;
        font-size: 12pt;
        font-weight: 700;
        margin-top: 20px;
        margin-bottom: 10px;
        page-break-after: avoid;
    }

    h3 {
        color: #334155;
        font-size: 11pt;
        font-weight: 600;
        margin-top: 16px;
        margin-bottom: 8px;
        page-break-after: avoid;
    }

    h4 {
        color: #475569;
        font-size: 10.5pt;
        font-weight: 600;
        margin-top: 12px;
        margin-bottom: 6px;
        page-break-after: avoid;
    }

    p, li {
        color: #334155;
        font-size: 10pt;
        margin-bottom: 8px;
    }

    ul, ol {
        margin-top: 4px;
        margin-bottom: 12px;
        padding-left: 24px;
    }

    li {
        margin-bottom: 4px;
    }

    /* Tables */
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 16px 0 20px 0;
        font-size: 8.5pt;
        page-break-inside: avoid;
    }

    th, td {
        border: 1px solid #cbd5e1;
        padding: 6px 9px;
        text-align: left;
        vertical-align: top;
    }

    th {
        background-color: #0f172a;
        color: #f8fafc;
        font-weight: 600;
        font-size: 8.8pt;
    }

    tr:nth-child(even) {
        background-color: #f8fafc;
    }

    tr:hover {
        background-color: #f1f5f9;
    }

    /* Code & Technical Blocks */
    code {
        font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        font-size: 8.8pt;
        background-color: #f1f5f9;
        color: #0369a1;
        padding: 2px 5px;
        border-radius: 4px;
        border: 1px solid #e2e8f0;
    }

    pre {
        background-color: #0f172a;
        color: #e2e8f0;
        padding: 12px 14px;
        border-radius: 6px;
        font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        font-size: 8pt;
        line-height: 1.45;
        overflow-x: auto;
        margin: 14px 0;
        page-break-inside: avoid;
        border: 1px solid #1e293b;
    }

    pre code {
        background-color: transparent;
        color: inherit;
        padding: 0;
        border: none;
        font-size: 8pt;
    }

    /* Math Cards */
    .math-card {
        background: #f8fafc;
        border-left: 4px solid #0284c7;
        padding: 10px 16px;
        margin: 12px 0;
        font-family: "Cambria Math", "Georgia", serif;
        font-size: 10.5pt;
        color: #0f172a;
        border-radius: 0 6px 6px 0;
        page-break-inside: avoid;
    }

    .math-inline {
        font-family: "Cambria Math", "Georgia", serif;
        font-weight: 600;
        color: #0f172a;
        background: #f1f5f9;
        padding: 1px 4px;
        border-radius: 3px;
    }

    /* Callouts */
    .callout {
        padding: 12px 16px;
        margin: 14px 0;
        border-radius: 6px;
        font-size: 9.5pt;
        page-break-inside: avoid;
    }

    .callout-warning {
        background-color: #fff1f2;
        border-left: 4px solid #e11d48;
        color: #9f1239;
    }

    .callout-important {
        background-color: #eff6ff;
        border-left: 4px solid #2563eb;
        color: #1e40af;
    }

    .callout-note {
        background-color: #f0fdf4;
        border-left: 4px solid #16a34a;
        color: #166534;
    }

    .callout-tip {
        background-color: #fefce8;
        border-left: 4px solid #ca8a04;
        color: #854d0e;
    }

    hr {
        border: 0;
        border-top: 1px solid #e2e8f0;
        margin: 22px 0;
    }

    blockquote {
        border-left: 4px solid #94a3b8;
        padding-left: 14px;
        margin: 10px 0;
        color: #475569;
        font-style: italic;
    }

    /* Footer styling */
    .doc-footer {
        margin-top: 36px;
        padding-top: 14px;
        border-top: 1px solid #cbd5e1;
        font-size: 8.5pt;
        color: #64748b;
        display: flex;
        justify-content: space-between;
    }
    """

    # Wrap body
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Autonomous Multi-Agent Fraud & Cyber Threat Detection - Comprehensive Project & Viva Defense Report</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="report-header">
        <div style="color: #0284c7; font-size: 9.5pt; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 6px;">
            B.Tech Final-Year Capstone Project &bull; Comprehensive Examination Manual
        </div>
        <h1 class="report-title" style="border: none; margin: 0; padding: 0;">
            An Autonomous Multi-Agent Framework for Fraud & Cyber Threat Detection Using Large Language Models
        </h1>
        <div class="report-meta">
            <div><strong>Candidate / Project Lead:</strong> Hemanth Gowda T</div>
            <div><strong>Evaluation Framework:</strong> Two-Tier Hybrid Multi-Agent Architecture</div>
            <div><strong>Verification Date:</strong> October 2026</div>
            <div><strong>Status:</strong> Evaluated & Benchmarked (N = 27,938 Independent Samples)</div>
        </div>
    </div>

{body_html}

    <div class="doc-footer">
        <div>Autonomous Multi-Agent SOC Framework &bull; Incident Command</div>
        <div>Defense Dossier Compiled from Verified Project Workspace</div>
    </div>
</body>
</html>
"""
    return full_html

def convert():
    print(f"Reading markdown from: {MD_PATH}")
    with open(MD_PATH, "r", encoding="utf-8") as f:
        md_text = f.read()

    processed_md = preprocess_markdown(md_text)

    # Initialize parser
    md = MarkdownIt().enable("table").enable("strikethrough")
    body_html = md.render(processed_md)

    # Inject page breaks for Phase headers
    body_html = re.sub(r"<h1>(PHASE \d+:.*?)</h1>", r'<h1 class="phase-break">\1</h1>', body_html)

    full_html = build_html(body_html)

    with open(TEMP_HTML_PATH, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"Saved styled HTML to: {TEMP_HTML_PATH} ({len(full_html):,} bytes)")

    # Locate Edge or Chrome executable
    browser_exe = None
    edge_candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    ]
    for c in edge_candidates:
        if os.path.exists(c):
            browser_exe = c
            break

    if not browser_exe:
        print("[ERROR] No Microsoft Edge or Chrome executable found on system!")
        sys.exit(1)

    print(f"Using browser rendering engine: {browser_exe}")

    cmd = [
        browser_exe,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={OUTPUT_PDF_PROJECT}",
        TEMP_HTML_PATH
    ]

    print(f"Executing PDF conversion to: {OUTPUT_PDF_PROJECT}...")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if os.path.exists(OUTPUT_PDF_PROJECT):
        size_kb = os.path.getsize(OUTPUT_PDF_PROJECT) / 1024
        print(f"[SUCCESS] PDF generated successfully!")
        print(f"  -> File: {OUTPUT_PDF_PROJECT} ({size_kb:,.1f} KB)")
        
        # Also copy to artifact directory if available
        if os.path.exists(ARTIFACT_DIR):
            shutil.copyfile(OUTPUT_PDF_PROJECT, OUTPUT_PDF_ARTIFACT)
            print(f"  -> Artifact Copy: {OUTPUT_PDF_ARTIFACT}")
    else:
        print(f"[ERROR] PDF generation failed! Return code: {proc.returncode}")
        print(f"STDOUT: {proc.stdout}")
        print(f"STDERR: {proc.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    convert()
