"""
Incident Commander Agent.
Synthesizes findings from specialized agents, arbitrates debates,
evaluates consensus, maps MITRE ATT&CK, and generates containment playbooks.
"""

import json
from typing import Dict, Any, List
from core.state import IncidentConsensus, PlaybookStep, AgentFinding
from tools.mitre_mapper import MitreMapper
from tools.response_playbooks import PlaybookGenerator

COMMANDER_SYSTEM_PROMPT = """You are the Lead Incident Commander and Master SOC Orchestrator.
Your role is to aggregate findings from specialized agents (Cyber Sentinel, Fraud Investigator, Phishing Analyst, Threat Intel).
Evaluate consensus, resolve conflicting assessments, determine the overall threat verdict, and formulate a mitigation plan.

You must respond ONLY with valid JSON in this exact structure:
{
  "verdict": "CONFIRMED_MALICIOUS",
  "composite_threat_score": 90,
  "overall_confidence": 0.94,
  "executive_summary": "High-confidence multi-vector threat confirmed. Compromised credentials were used immediately to trigger unauthorized wire transfers.",
  "mitre_tactics": ["Initial Access", "Credential Access", "Impact"],
  "mitre_techniques": ["T1566 - Phishing", "T1110 - Brute Force", "T1657 - Financial Theft"]
}
"""

class IncidentCommanderAgent:
    def __init__(self, llm):
        self.llm = llm

    def synthesize(
        self,
        event_telemetry: Dict[str, Any],
        agent_findings: List[AgentFinding]
    ) -> IncidentConsensus:
        """Synthesizes all findings into a unified incident consensus."""
        votes = {}
        all_reasons = []
        suspicious_count = 0
        total_confidence = 0.0

        for f in agent_findings:
            vote_status = "MALICIOUS" if f.is_suspicious else "BENIGN"
            votes[f.agent_name] = f"{vote_status} (Confidence: {f.confidence:.2f})"
            if f.is_suspicious:
                suspicious_count += 1
                total_confidence += f.confidence
            all_reasons.extend(f.evidence)

        # Target entities for automated playbook
        targets = {
            "ip": event_telemetry.get("source_ip") or event_telemetry.get("ip_address"),
            "user": event_telemetry.get("user") or event_telemetry.get("user_name"),
            "account_id": event_telemetry.get("account_id"),
            "tx_id": event_telemetry.get("tx_id"),
            "domain": event_telemetry.get("sender_email", "").split("@")[-1] if "@" in event_telemetry.get("sender_email", "") else None
        }

        # Format findings for LLM prompt
        findings_summary = [
            {
                "agent": f.agent_name,
                "is_suspicious": f.is_suspicious,
                "threat_category": f.threat_category,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "recommendation": f.action_recommendation
            }
            for f in agent_findings
        ]

        prompt = f"""{COMMANDER_SYSTEM_PROMPT}

[INPUT TELEMETRY]
Event Data: {json.dumps(event_telemetry, indent=2)}

[SPECIALIZED AGENT FINDINGS & VOTES]
{json.dumps(findings_summary, indent=2)}

Synthesize the final incident assessment and output JSON:"""

        mitre_data = MitreMapper.map_indicators(all_reasons)
        raw_playbook = PlaybookGenerator.create_containment_plan("MULTI_VECTOR_THREAT", targets)
        playbook_steps = [
            PlaybookStep(
                step_number=p["step"],
                action_type=p["action"],
                target=str(p["target"]),
                priority=p["priority"],
                description=p["description"]
            )
            for p in raw_playbook
        ]

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
            verdict = data.get("verdict", "CONFIRMED_MALICIOUS" if suspicious_count >= 1 else "BENIGN_FALSE_POSITIVE")
            composite_score = int(data.get("composite_threat_score", 85 if suspicious_count >= 1 else 15))

            return IncidentConsensus(
                verdict=verdict,
                composite_threat_score=composite_score,
                overall_confidence=float(data.get("overall_confidence", 0.90)),
                executive_summary=data.get("executive_summary", "Incident synthesis completed across all specialized agents."),
                mitre_tactics=data.get("mitre_tactics", mitre_data["tactics"]),
                mitre_techniques=data.get("mitre_techniques", mitre_data["techniques"]),
                containment_playbook=playbook_steps if verdict != "BENIGN_FALSE_POSITIVE" else [],
                agent_votes=votes
            )
        except Exception as e:
            # Deterministic consensus fallback
            is_threat = suspicious_count >= 1
            return IncidentConsensus(
                verdict="CONFIRMED_MALICIOUS" if is_threat else "BENIGN_FALSE_POSITIVE",
                composite_threat_score=85 if is_threat else 20,
                overall_confidence=0.88,
                executive_summary=f"Incident confirmed by {suspicious_count}/{len(agent_findings)} specialized detection agents.",
                mitre_tactics=mitre_data["tactics"],
                mitre_techniques=mitre_data["techniques"],
                containment_playbook=playbook_steps if is_threat else [],
                agent_votes=votes
            )
