"""
Cyber Sentinel Agent.
Specializes in network intrusion, authentication telemetry, brute force, and lateral movement.
"""

import json
from typing import Dict, Any
from core.state import AgentFinding
from tools.mitre_mapper import MitreMapper

CYBER_SYSTEM_PROMPT = """You are the Cyber Sentinel Agent in an autonomous SOC.
Your role is to analyze network logs, authentication events, API requests, and system telemetry.
Identify brute-force attempts, credential stuffing, SQL injection, privilege escalation, or unauthorized access.

You must respond ONLY with valid JSON in this exact structure:
{
  "is_suspicious": true,
  "confidence": 0.95,
  "threat_category": "Credential Stuffing & Unauthorized Access",
  "evidence": [
    "Repeated failed logins from IP 194.26.29.112",
    "Rapid breakthrough login for high-privilege account"
  ],
  "mitre_techniques": ["T1110.001 - Password Guessing", "T1078 - Valid Accounts"],
  "action_recommendation": "Block source IP at firewall and force immediate MFA re-authentication."
}
"""

class CyberSentinelAgent:
    def __init__(self, llm):
        self.llm = llm

    def analyze(self, event_telemetry: Dict[str, Any], initial_reasons: list) -> AgentFinding:
        """Analyzes cyber log telemetry."""
        prompt = f"""{CYBER_SYSTEM_PROMPT}

[INVESTIGATION TELEMETRY]
Event Data: {json.dumps(event_telemetry, indent=2)}
Initial Tier-1 Flags: {initial_reasons}

Perform in-depth cyber forensic analysis and output JSON:"""

        try:
            response = self.llm.invoke(prompt)
            content = getattr(response, "content", str(response)).strip()

            # Clean JSON formatting if wrapped in code blocks
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            data = json.loads(content)
            return AgentFinding(
                agent_name="Cyber Sentinel",
                is_suspicious=data.get("is_suspicious", True),
                confidence=float(data.get("confidence", 0.85)),
                threat_category=data.get("threat_category", "Cyber Attack"),
                evidence=data.get("evidence", initial_reasons),
                mitre_techniques=data.get("mitre_techniques", ["T1110"]),
                action_recommendation=data.get("action_recommendation", "Block source IP"),
                raw_response=content
            )
        except Exception as e:
            # Fallback heuristic
            mitre_info = MitreMapper.map_indicators(initial_reasons)
            return AgentFinding(
                agent_name="Cyber Sentinel",
                is_suspicious=True,
                confidence=0.85,
                threat_category="Suspicious Cyber Telemetry",
                evidence=initial_reasons,
                mitre_techniques=mitre_info["techniques"],
                action_recommendation="Isolate endpoint and inspect authentication logs.",
                raw_response=str(e)
            )
