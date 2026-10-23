# An Autonomous Multi-Agent Framework for Fraud & Cyber Threat Detection Using Large Language Models

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Multi-Agent](https://img.shields.io/badge/Architecture-2--Tier%20Hybrid%20Multi--Agent-orange.svg)]()
[![SOC-Ready](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-red.svg)]()

> **B.Tech Major Capstone Project**  
> An enterprise-grade, two-tier collaborative AI system combining statistical anomaly filtering with specialized LLM security agents for high-throughput fraud prevention and automated incident containment.

---

## 📌 Executive Summary & Novelty

Modern Security Operations Centers (SOCs) and financial institutions process millions of telemetry events every minute. Directly streaming raw logs to Large Language Models (LLMs) is economically unviable and technically flawed due to token costs, latency, hallucinations, and context saturation.

This framework introduces a **Two-Tier Hybrid Architecture**:
1. **Tier-1 (Fast Telemetry Filter):** Evaluates high-velocity streams via statistical Z-score deviation, velocity counters, and heuristic regex scanners. It safely filters out benign events without making expensive LLM calls.
2. **Tier-2 (Autonomous Multi-Agent SOC):** When anomalies exceed severity thresholds, specialized domain LLM agents collaborate on a shared blackboard to debate findings, map adversary tactics to the **MITRE ATT&CK** taxonomy, and synthesize an automated incident containment playbook.

---

## 🏛️ System Architecture

```
[ Ingested Telemetry ]
  ├── Network / SSH Auth Logs
  ├── Banking & Wire Transactions
  └── Inbound Corporate Emails
         │
         ▼
┌────────────────────────────────────────────────────────┐
│  Tier-1: Fast Statistical & Heuristic Anomaly Filter   │
│  (Z-Score Deviation, Regex Payloads, SPF/DMARC Checks)  │
└────────────────────────────────────────────────────────┘
         │
         ├── [Passed as Benign: 0 LLM Tokens Spent]
         ▼
   [Flagged Anomaly Alert]
         │
         ▼
┌────────────────────────────────────────────────────────┐
│         Master Orchestrator / Dispatcher               │
└────────────────────────────────────────────────────────┘
         │
    ┌────┴───────────────────────────┬───────────────────────────┐
    ▼                                ▼                           ▼
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│ 🛡️ Cyber Sentinel    │  │ 💳 Fraud Investigator│  │ 🎣 Phishing Analyst  │
│ Network & Auth Logs  │  │ Outlier Spends & ATO │  │ Headers & Homoglyphs │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘
    │                                │                           │
    └────────────────────────────────┼───────────────────────────┘
                                     ▼
                      ┌──────────────────────────────┐
                      │ 🌐 Threat Intel / OSINT      │
                      │ AbuseIPDB, C2 & IP Rep       │
                      └──────────────────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │ ⚖️ Inter-Agent Debate Loop   │
                      │ (Cross-Domain Arbitration)   │
                      └──────────────────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │ 🎖️ Lead Incident Commander   │
                      │ • Composite Threat Score     │
                      │ • MITRE ATT&CK Mapping       │
                      │ • Containment Playbook       │
                      └──────────────────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │ ⚡ SOC Action & Containment  │
                      │ Firewall Drop, Token Revoke, │
                      │ Account Freeze, Mail Purge   │
                      └──────────────────────────────┘
```

---

## 🤖 Specialized Multi-Agent Roles

| Agent | Responsibility | Key Telemetry / Tooling |
| :--- | :--- | :--- |
| **🛡️ Cyber Sentinel** | Analyzes authentication logs, SSH attempts, brute force, and privilege escalation. | Auth status, IP frequency, SQLi regex, user-agent signatures |
| **💳 Fraud Investigator** | Uncovers account takeover (ATO), spending outliers, and card testing velocity. | Baseline Z-scores, merchant classification, currency velocity |
| **🎣 Phishing Analyst** | Dissects email headers, homoglyph lookalike domains, and urgency sentiment. | SPF / DKIM / DMARC verification, Unicode inspect, body NLP |
| **🌐 Threat Intel (OSINT)** | Correlates observed IOCs against global threat intelligence feeds. | AbuseIPDB scores, known C2 botnets, ISP & country attribution |
| **🎖️ Incident Commander** | Arbitrates debates, computes composite risk score (0-100), and outputs playbooks. | Weighted consensus, MITRE ATT&CK matrix, Playbook Generator |

---

## 📂 Project Structure

```text
major-project/
├── .env.example                  # Environment configuration template
├── config.py                     # Central configuration & pluggable LLM factory
├── requirements.txt              # Production dependency specifications
├── core/
│   ├── auth.py                   # Private access verification & cryptographic PBKDF2 hashing
│   ├── orchestrator.py           # Master Multi-Agent Orchestrator
│   ├── state.py                  # Shared investigation blackboard schema
│   └── agents/                   # Specialized autonomous agents
│       ├── cyber_sentinel.py     # Network & auth log analysis
│       ├── fraud_investigator.py # Financial fraud & ATO detection
│       ├── phishing_analyst.py   # Phishing & social engineering detection
│       ├── threat_intel.py       # OSINT & reputation correlation
│       └── incident_commander.py # Final synthesis, consensus & mitigation
├── detectors/                    # Tier-1 Fast ML & Heuristics
│   ├── tier1_pipeline.py         # Unified ingestion & triage dispatcher
│   ├── log_anomaly.py            # Fast regex & brute-force frequency tracker
│   ├── transaction_anomaly.py    # Z-score & spending deviation detector
│   └── email_anomaly.py          # Header authentication & homoglyph scanner
├── tools/                        # Agent tool definitions
│   ├── mitre_mapper.py           # MITRE ATT&CK taxonomy mapper
│   ├── threat_intel_tools.py     # IP & Domain reputation intelligence
│   └── response_playbooks.py     # Automated containment plan generator
├── data/                         # Benchmark security datasets
│   ├── generator.py              # Reproducible dataset generator script
│   ├── auth_logs.json            # SSH brute force, credential stuffing, SQLi
│   ├── financial_transactions.csv# Normal spends, ATO drains, card testing
│   ├── suspicious_emails.json    # Spear phishing, BEC, invoice lures
│   └── combined_scenarios.json   # Multi-vector coordinated attack scenarios
├── dashboard/                    # Interactive SOC Analyst UI
│   ├── app.py                    # Streamlit real-time interactive dashboard
│   └── login_view.py             # Private access login gate & session manager
└── tests/
    ├── test_auth.py              # Private authentication & PBKDF2 verification suite
    ├── test_tier1.py             # Tier-1 fast filter validation suite
    └── test_multi_agent.py       # Full end-to-end multi-agent test suite
```

---

## 🚀 Quickstart Guide

### 1. Activate Environment
```powershell
.venv\Scripts\activate
```

### 2. Configure LLM Backend (Optional)
The project is configured by default with a high-fidelity **Mock LLM engine** (`LLM_PROVIDER=mock` in `.env`), allowing instant full demonstration without API keys or internet connection.

To connect live cloud or local LLMs, edit `.env`:
- **Google Gemini (Free tier):** Set `LLM_PROVIDER=gemini` and enter `GEMINI_API_KEY`.
- **Groq (Fast Llama 3.3 70B):** Set `LLM_PROVIDER=groq` and enter `GROQ_API_KEY`.
- **Local Ollama (100% offline):** Set `LLM_PROVIDER=ollama` with `OLLAMA_BASE_URL=http://localhost:11434`.

### 3. Dataset Acquisition, ML Training & Evaluation Workflows
```powershell
# 1. Download, clean, and cache authentic expanded benchmarks (143,897 samples)
.venv\Scripts\python.exe data/download_datasets.py

# 2. Train and calibrate production ML models (Platt Sigmoid Scaling)
.venv\Scripts\python.exe models/train_models.py

# 3. Run independent statistical evaluation on 27,938 strictly held-out test samples
.venv\Scripts\python.exe tests/evaluate_models.py

# 4. Test Tier-1 Fast Anomaly Filter & Calibrated Probabilities
.venv\Scripts\python.exe tests/test_tier1.py

# 5. Test Full End-to-End Multi-Agent Collaborative Framework
.venv\Scripts\python.exe tests/test_multi_agent.py

# 6. Test Private Access Authentication & Password Hashing
.venv\Scripts\python.exe tests/test_auth.py
```

### 4. Launch the Interactive SOC Dashboard
```powershell
.venv\Scripts\streamlit.exe run dashboard/app.py
```
Open your browser at `http://localhost:8501`.

#### 🔐 Private Access Authentication
The SOC Dashboard is protected by a private access authorization gateway:
- **Authorized Owner:** `Hemanth Gowda T`
- **Login Identifier:** Either registered **Gmail** (`hemanthhemu6557@gmail.com`) OR registered **Mobile Number** (`9886966865` or `+919886966865`)
- **Default Password:** `Hemanth@6557`
- **Security Features:** PBKDF2-HMAC-SHA256 password hashing with salt, brute-force rate-limiting lockout, session isolation, and secure credential management on the login gateway.
- **Access Control:** All telemetry tabs, war room, and simulator features are completely restricted until successful authentication.

Once authenticated, access the **Nine Selectable Modules** via the sidebar navigation:
1. **Module 1: System Testing & Validation:** Automated 9-point pipeline test suite (WAL DB, dataset inventory, normalization, Tier-1 calibrated ML, epistemic uncertainty, multi-agent dispatch, cross-domain scenarios, simulation reset, held-out test evaluation).
2. **Module 2: Microsoft & OSINT Threat Intelligence:** Correlates IPs, URLs, and domains against Microsoft Defender Threat Intelligence, M365 credential harvester feeds, AbuseIPDB, VirusTotal, and Tor exit nodes.
3. **Module 3: OWASP Security & Vulnerability Analysis:** Inspects web payloads against OWASP Top 10 (2021) categories using trained machine learning models (`sqli_payload_model.joblib`) and regex heuristic scanners.
4. **Module 4: CISA Threat Intelligence (KEV):** Searchable CISA Known Exploited Vulnerabilities catalog with CVSS scores, ransomware campaign linkages, and federal mitigation deadlines.
5. **Module 5: Vulnerability & CVSS Analysis:** Interactive FIRST.org CVSS v3.1 Base Score calculator evaluating attack vectors, exploitability, and impact sub-scores.
6. **Module 6: Threat Intel & Report Summarization:** LLM and NLP intelligence summarizer extracting IOCs (IPs, domains, hashes, CVEs), targeted sectors, and synthesizing executive briefings.
7. **Module 7: Fraud Detection & Anomaly Analysis:** Validates financial transactions, calculates statistical Z-score deviation against historical baselines, and evaluates PaySim Random Forest ML models.
8. **Module 8: Cybersecurity Risk Assessment & War Room:** Full collaborative multi-agent investigation, inter-agent debate transcripts, composite threat score gauge (0-100), MITRE ATT&CK matrix, and automated containment playbook dispatcher.
9. **Module 9: Final Report Generation & Export:** Previews and exports incident forensic dossiers in Markdown (`.md`), Plain Text (`.txt`), Metrics CSV (`.csv`), Print-ready HTML (`.html`), and Academic PDF (`.pdf`).

Plus:
- **Real-Time SOC Monitor & Telemetry:** Ingestion metrics, telemetry pagination, search, multi-vector coordinated scenarios, and live attack simulator.

---

### 5. One-Click Batch Startup Scripts (Windows)
For convenience during academic evaluation and demonstration:
- **`run_dashboard.bat`**: Launches the complete Streamlit SOC Analyst Web Interface with 1 click.
- **`run_tests.bat`**: Executes all automated test suites across all 9 modules and pipeline checkpoints.

---

## 🎓 Viva Voce & Presentation Cheat-Sheet

1. **Why multi-agent instead of a single LLM prompt?**  
   *Answer:* A monolithic prompt suffers from cognitive overload, hallucinations, and context pollution. By modularizing into specialized agents (Cyber, Fraud, Phishing, OSINT), each agent is prompted with domain-specific heuristics and strict guardrails.

2. **How does the system prevent high LLM API costs?**  
   *Answer:* Through our 2-Tier Architecture. The Tier-1 filter handles high-throughput telemetry using fast statistical algorithms (Z-score deviation, regex filters). Up to 80% of benign noise is dropped without spending a single LLM token.

3. **What happens when two agents disagree?**  
   *Answer:* The framework triggers an *Inter-Agent Debate Round*. The Incident Commander shares the conflicting findings (e.g. valid 2FA token vs malicious foreign IP) and demands secondary evidence re-evaluation before voting.

4. **Why is private authentication implemented on the dashboard?**  
   *Answer:* Enterprise SOC and financial containment platforms have the authority to trigger perimeter firewall blocks and account freezes. Restricting access via private multi-identifier authentication (Gmail / Mobile + salted PBKDF2 hash) ensures only authorized defense operators can review incidents and execute mitigation playbooks.

5. **What is the practical outcome of an investigation?**  
   *Answer:* The Incident Commander generates an automated containment playbook (e.g., dropping perimeter firewall IP packets, invalidating active JWT tokens, and placing an administrative freeze on banking accounts).
