"""
Phishing & Social Engineering Analyst Agent.
Specializes in email headers, homoglyphs, BEC wire lures, and credential harvesters.
"""

import json
from typing import Dict, Any
from core.state import AgentFinding

PHISHING_SYSTEM_PROMPT = """You are the Senior Phishing & Social Engineering Analyst Agent in an autonomous SOC.
Your role is to analyze suspicious emails, communication headers, and social engineering lures.
Identify Business Email Compromise (BEC), CEO fraud, credential harvesting, and spear-phishing.

You must respond ONLY with valid JSON in this exact structure:
{
  "is_suspicious": true,
  "confidence": 0.94,
  "threat_category": "Business Email Compromise (BEC) / CEO Impersonation",
  "evidence": [
    "SPF and DMARC authentication failure",
    "Executive display name spoofing with lookalike unicode domain",
    "Psychological coercion demanding urgent confidential wire transfer"
  ],
  "mitre_techniques": ["T1566.002 - Spearphishing Link", "T1566.001 - Spearphishing Attachment"],
  "action_recommendation": "Quarantine email across all enterprise mailboxes and blacklist sender domain."
}
"""

class PhishingAnalystAgent:
    def __init__(self, llm):
        self.llm = llm

    def analyze(self, event_telemetry: Dict[str, Any], initial_reasons: list) -> AgentFinding:
        """Analyzes email telemetry."""
        prompt = f"""{PHISHING_SYSTEM_PROMPT}

[INVESTIGATION TELEMETRY]
Email Data: {json.dumps(event_telemetry, indent=2)}
Initial Tier-1 Flags: {initial_reasons}

Perform in-depth social engineering and header forensic analysis and output JSON:"""

        try:
            response = self.llm.invoke(prompt)
            content = getattr(response, "content", str(response)).strip()

            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            data = json.loads(content)
            return AgentFinding(
                agent_name="Phishing Analyst",
                is_suspicious=data.get("is_suspicious", True),
                confidence=float(data.get("confidence", 0.92)),
                threat_category=data.get("threat_category", "Phishing Threat"),
                evidence=data.get("evidence", initial_reasons),
                mitre_techniques=data.get("mitre_techniques", ["T1566 - Phishing"]),
                action_recommendation=data.get("action_recommendation", "Quarantine email across organization."),
                raw_response=content
            )
        except Exception as e:
            return AgentFinding(
                agent_name="Phishing Analyst",
                is_suspicious=True,
                confidence=0.90,
                threat_category="Suspicious Email Telemetry",
                evidence=initial_reasons,
                mitre_techniques=["T1566 - Phishing"],
                action_recommendation="Quarantine email and block sender domain.",
                raw_response=str(e)
            )
