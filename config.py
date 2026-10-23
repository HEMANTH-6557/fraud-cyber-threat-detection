"""
Configuration module for Autonomous Multi-Agent Framework.
Supports flexible LLM backends: Gemini, Groq, Ollama, OpenAI, and Mock.
"""

import os
from typing import Any, Optional
from dotenv import load_dotenv

load_dotenv()

# General Settings
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "mock").lower()
TIER1_ANOMALY_THRESHOLD = float(os.getenv("TIER1_ANOMALY_THRESHOLD", "0.55"))
AGENT_CONSENSUS_THRESHOLD = float(os.getenv("AGENT_CONSENSUS_THRESHOLD", "0.70"))
ENABLE_DEBATE_ROUND = os.getenv("ENABLE_DEBATE_ROUND", "true").lower() == "true"
MAX_DEBATE_ROUNDS = int(os.getenv("MAX_DEBATE_ROUNDS", "2"))

# API Keys & Endpoints
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# SOC Private Access / Authentication Settings
SOC_OWNER_NAME = os.getenv("SOC_OWNER_NAME", "Hemanth Gowda T")
SOC_OWNER_GMAIL = os.getenv("SOC_OWNER_GMAIL", "hemanthhemu6557@gmail.com")
SOC_OWNER_MOBILE = os.getenv("SOC_OWNER_MOBILE", "+919886966865")
SOC_OWNER_PASSWORD = os.getenv("SOC_OWNER_PASSWORD", "Hemanth@6557")


class MockChatModel:
    """
    High-fidelity Mock LLM for offline demonstration, testing, and evaluation
    without requiring paid API credits or internet connectivity.
    """
    def __init__(self, name: str = "MockSOCAgent"):
        self.name = name

    def invoke(self, messages: Any) -> Any:
        # Extract prompt text
        prompt_str = ""
        if isinstance(messages, list):
            prompt_str = "\n".join([str(getattr(m, "content", m)) for m in messages])
        else:
            prompt_str = str(messages)

        prompt_lower = prompt_str.lower()

        # Dynamic heuristic reasoning simulation
        is_cyber = any(k in prompt_lower for k in ["ssh", "brute", "sql", "port", "auth", "login", "ip", "fail"])
        is_fraud = any(k in prompt_lower for k in ["transaction", "amount", "card", "bank", "velocity", "transfer", "currency"])
        is_phish = any(k in prompt_lower for k in ["email", "subject", "urgent", "ceo", "link", "payload", "wire transfer", "invoice"])
        is_osint = "threat intel" in prompt_lower or "reputation" in prompt_lower or "osint" in prompt_lower
        is_commander = "incident commander" in prompt_lower or "consensus" in prompt_lower or "synthesis" in prompt_lower

        import json

        if is_commander:
            # Dynamic calculation based on event context
            calc_score = 80
            calc_conf = 0.90
            summary_text = "Multi-agent evaluation confirmed elevated threat indicators."

            # Check for arbitrary numeric amounts dynamically
            import re
            amt_search = re.search(r'"amount":\s*([0-9.]+)', prompt_str)
            custom_amt = None
            if amt_search:
                try:
                    custom_amt = float(amt_search.group(1))
                except ValueError:
                    pass

            if "union" in prompt_lower or "select" in prompt_lower or "sqlmap" in prompt_lower or "' or '" in prompt_lower:
                calc_score = 97
                calc_conf = 0.96
                summary_text = "Critical SQL Injection and unauthorized database extraction exploit confirmed by Cyber Sentinel."
            elif custom_amt is not None and custom_amt >= 30000:
                calc_score = 96
                calc_conf = 0.95
                summary_text = f"High-confidence Account Takeover (ATO) and unauthorized large wire transfer drain (${custom_amt:,.2f}) detected."
            elif custom_amt is not None and custom_amt >= 10000:
                calc_score = 89
                calc_conf = 0.92
                summary_text = f"Elevated outlier wire transfer (${custom_amt:,.2f}) deviating significantly from historical account profile."
            elif custom_amt is not None and custom_amt >= 400:
                calc_score = 74
                calc_conf = 0.88
                summary_text = f"Rapid velocity card testing / high-risk merchant transaction (${custom_amt:,.2f}) detected."
            elif custom_amt is not None and custom_amt < 100 and not (is_cyber or is_phish):
                calc_score = 14
                calc_conf = 0.96
                summary_text = f"Routine low-value retail spend (${custom_amt:,.2f}) verified within normal baseline parameters."
            elif "wire_escrow_details" in prompt_lower or ".pdf.exe" in prompt_lower or "ceo-jonathan" in prompt_lower:
                calc_score = 95
                calc_conf = 0.94
                summary_text = "Executive impersonation / Business Email Compromise (BEC) with malicious payload detected."
            elif "m365" in prompt_lower or "password expiration" in prompt_lower:
                calc_score = 92
                calc_conf = 0.93
                summary_text = "Credential harvesting campaign impersonating Microsoft 365 identity provider confirmed."
            elif "bypass" in prompt_lower or "185.220.101.5" in prompt_lower:
                calc_score = 91
                calc_conf = 0.92
                summary_text = "Impossible geographic velocity and anomalous authentication bypass detected across European Tor exit nodes."
            elif "brute" in prompt_lower or "failed" in prompt_lower:
                calc_score = 82
                calc_conf = 0.89
                summary_text = "Sustained high-frequency SSH credential brute-force attack from known hostile IP infrastructure."
            elif not (is_cyber or is_fraud or is_phish) or "mfa_totp" in prompt_lower or "benign" in prompt_lower:
                calc_score = 12
                calc_conf = 0.97
                summary_text = "Normal authorized operational activity verified. No indicators of compromise detected."

            response_data = {
                "final_verdict": "MALICIOUS" if calc_score >= 50 else "BENIGN",
                "composite_threat_score": calc_score,
                "overall_confidence": calc_conf,
                "confidence": calc_conf,
                "mitre_attack": {
                    "tactics": ["Initial Access (TA0001)", "Credential Access (TA0006)", "Impact (TA0040)"],
                    "techniques": ["T1110 - Brute Force", "T1566 - Phishing", "T1657 - Financial Theft"]
                },
                "executive_summary": summary_text,
                "consensus_breakdown": {
                    "cyber_sentinel": "Agreed (High Threat)" if is_cyber else "Neutral",
                    "fraud_investigator": "Agreed (Abnormal Velocity)" if is_fraud else "Neutral",
                    "phishing_analyst": "Confirmed Suspicious Lure" if is_phish else "Neutral",
                    "threat_intel": "Known Malicious Infrastructure" if is_osint else "Clean"
                },
                "containment_playbook": [
                    {"step": 1, "action": "BLOCK_IP", "target": "Suspicious Source IP", "priority": "CRITICAL"},
                    {"step": 2, "action": "TERMINATE_SESSION", "target": "Compromised User Session / Token", "priority": "HIGH"},
                    {"step": 3, "action": "FREEZE_TRANSACTION", "target": "Pending Outbound Wire Transfer", "priority": "IMMEDIATE"},
                    {"step": 4, "action": "NOTIFY_SOC", "target": "L2/L3 Incident Response Team", "priority": "MEDIUM"}
                ]
            }
        elif is_cyber:
            response_data = {
                "agent": "Cyber Sentinel",
                "threat_detected": True,
                "risk_score": 85,
                "attack_type": "Credential Stuffing & Unauthorized Lateral Movement",
                "mitre_technique": "T1110.001 - Password Guessing",
                "evidence": [
                    "High frequency of failed authentication attempts exceeding baseline threshold (>5 per minute).",
                    "Suspicious geolocation jump observed in telemetry.",
                    "Anomalous root/sudo privilege escalation attempt logged."
                ],
                "recommended_action": "Enforce immediate IP blacklist and mandate MFA reset for target user."
            }
        elif is_fraud:
            response_data = {
                "agent": "Fraud Investigator",
                "fraud_detected": True,
                "risk_score": 90,
                "fraud_type": "Account Takeover (ATO) & Mule Dispersal",
                "indicators": [
                    "Transaction value is 4.8 standard deviations above user 30-day historical mean.",
                    "Impossible geographic velocity: IP location differs by 6,000 km from transaction device within 10 minutes.",
                    "Newly added high-risk beneficiary account."
                ],
                "recommended_action": "Halt payment processing immediately; place 24-hour verification hold on account."
            }
        elif is_phish:
            response_data = {
                "agent": "Phishing Analyst",
                "is_phishing": True,
                "confidence_score": 94,
                "phishing_type": "Business Email Compromise (BEC) / Executive Impersonation",
                "indicators": [
                    "Mismatched reply-to domain spoofing internal corporate executive address.",
                    "Psychological urgency flags: high-stress wire transfer coercion.",
                    "URL contains homograph lookalike character set and low domain age (<48 hours)."
                ],
                "recommended_action": "Quarantine email across all gateway mailboxes; add domain to perimeter blocklist."
            }
        elif is_osint:
            response_data = {
                "agent": "Threat Intel Correlator",
                "reputation_status": "CONFIRMED_MALICIOUS",
                "threat_intel_score": 89,
                "associated_campaigns": ["APT-29 / CozyBear credential harvester", "Known Mirai botnet C2"],
                "abuse_confidence_score": 100,
                "ip_domain_indicators": [
                    "Reported 47 times in the last 24 hours on AbuseIPDB for port scanning and SSH brute force.",
                    "Domain registrar privacy shielded with high toxicity score."
                ]
            }
        else:
            response_data = {
                "status": "ANALYSIS_COMPLETE",
                "threat_level": "SUSPICIOUS",
                "risk_score": 65,
                "summary": "Multi-agent evaluation complete with potential threat indicators observed."
            }

        class MockResponse:
            def __init__(self, text):
                self.content = text

        return MockResponse(json.dumps(response_data, indent=2))


def get_llm(temperature: float = 0.1, provider: Optional[str] = None) -> Any:
    """
    Factory function returning the configured LLM instance.
    Falls back cleanly to Mock LLM if credentials are not configured or provider is 'mock'.
    """
    selected_provider = (provider or LLM_PROVIDER).lower()

    if selected_provider == "gemini":
        if not GEMINI_API_KEY:
            print("[Config] WARNING: GEMINI_API_KEY not found. Falling back to Mock LLM.")
            return MockChatModel("MockGemini")
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(
                model=GEMINI_MODEL,
                google_api_key=GEMINI_API_KEY,
                temperature=temperature
            )
        except Exception as e:
            print(f"[Config] Error initializing Gemini LLM: {e}. Falling back to Mock.")
            return MockChatModel("MockGemini")

    elif selected_provider == "groq":
        if not GROQ_API_KEY:
            print("[Config] WARNING: GROQ_API_KEY not found. Falling back to Mock LLM.")
            return MockChatModel("MockGroq")
        try:
            from langchain_groq import ChatGroq
            return ChatGroq(
                model=GROQ_MODEL,
                groq_api_key=GROQ_API_KEY,
                temperature=temperature
            )
        except Exception as e:
            print(f"[Config] Error initializing Groq LLM: {e}. Falling back to Mock.")
            return MockChatModel("MockGroq")

    elif selected_provider == "ollama":
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                base_url=f"{OLLAMA_BASE_URL}/v1",
                api_key="ollama",
                model=OLLAMA_MODEL,
                temperature=temperature
            )
        except Exception as e:
            print(f"[Config] Error initializing Ollama: {e}. Falling back to Mock.")
            return MockChatModel("MockOllama")

    elif selected_provider == "openai":
        if not OPENAI_API_KEY:
            print("[Config] WARNING: OPENAI_API_KEY not found. Falling back to Mock LLM.")
            return MockChatModel("MockOpenAI")
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=OPENAI_MODEL,
                api_key=OPENAI_API_KEY,
                temperature=temperature
            )
        except Exception as e:
            print(f"[Config] Error initializing OpenAI LLM: {e}. Falling back to Mock.")
            return MockChatModel("MockOpenAI")

    # Default to Mock LLM
    return MockChatModel("MockSOCAgent")
