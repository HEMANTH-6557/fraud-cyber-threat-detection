"""
Financial Fraud Investigator Agent.
Specializes in transaction anomaly analysis, velocity bursts, mule patterns, and account takeovers.
"""

import json
from typing import Dict, Any
from core.state import AgentFinding

FRAUD_SYSTEM_PROMPT = """You are the Senior Financial Fraud Investigator Agent in an autonomous SOC.
Your role is to analyze banking, payment, wire, and credit card transactions.
Identify account takeovers (ATO), money laundering/mule dispersal, velocity spikes, and outlier spending.

You must respond ONLY with valid JSON in this exact structure:
{
  "is_suspicious": true,
  "confidence": 0.92,
  "threat_category": "Account Takeover & High-Value Asset Drain",
  "evidence": [
    "Transaction amount ($48,500) deviates by >300 standard deviations from user baseline",
    "Destination merchant is a high-risk crypto exchange"
  ],
  "mitre_techniques": ["T1657 - Financial Theft"],
  "action_recommendation": "Freeze outgoing wire transfer and place 48-hour hold on account."
}
"""

class FraudInvestigatorAgent:
    def __init__(self, llm):
        self.llm = llm

    def analyze(self, event_telemetry: Dict[str, Any], initial_reasons: list) -> AgentFinding:
        """Analyzes financial transaction telemetry."""
        prompt = f"""{FRAUD_SYSTEM_PROMPT}

[INVESTIGATION TELEMETRY]
Transaction Data: {json.dumps(event_telemetry, indent=2)}
Initial Tier-1 Flags: {initial_reasons}

Perform in-depth fraud behavioral analysis and output JSON:"""

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
                agent_name="Fraud Investigator",
                is_suspicious=data.get("is_suspicious", True),
                confidence=float(data.get("confidence", 0.90)),
                threat_category=data.get("threat_category", "Financial Fraud"),
                evidence=data.get("evidence", initial_reasons),
                mitre_techniques=data.get("mitre_techniques", ["T1657 - Financial Theft"]),
                action_recommendation=data.get("action_recommendation", "Halt transaction processing."),
                raw_response=content
            )
        except Exception as e:
            return AgentFinding(
                agent_name="Fraud Investigator",
                is_suspicious=True,
                confidence=0.88,
                threat_category="Anomalous Financial Activity",
                evidence=initial_reasons,
                mitre_techniques=["T1657 - Financial Theft"],
                action_recommendation="Suspend card and prompt cardholder for out-of-band verification.",
                raw_response=str(e)
            )
