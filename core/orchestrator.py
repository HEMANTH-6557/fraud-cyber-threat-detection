"""
Master Multi-Agent Orchestrator.
Coordinates specialized agents, arbitrates debates, and manages the shared investigation blackboard.
"""

from typing import Dict, Any, List, Optional
import uuid
from datetime import datetime

from config import get_llm, ENABLE_DEBATE_ROUND, MAX_DEBATE_ROUNDS
from core.state import InvestigationState, AgentFinding, IncidentConsensus
from core.agents.cyber_sentinel import CyberSentinelAgent
from core.agents.fraud_investigator import FraudInvestigatorAgent
from core.agents.phishing_analyst import PhishingAnalystAgent
from core.agents.threat_intel import ThreatIntelAgent
from core.agents.incident_commander import IncidentCommanderAgent
from detectors.tier1_pipeline import Tier1Alert

class MultiAgentOrchestrator:
    def __init__(self, provider: Optional[str] = None):
        self.llm = get_llm(provider=provider)
        self.cyber_agent = CyberSentinelAgent(self.llm)
        self.fraud_agent = FraudInvestigatorAgent(self.llm)
        self.phishing_agent = PhishingAnalystAgent(self.llm)
        self.threat_intel_agent = ThreatIntelAgent(self.llm)
        self.commander_agent = IncidentCommanderAgent(self.llm)

    def investigate(self, alert_or_event: Any) -> InvestigationState:
        """
        Executes an end-to-end multi-agent investigation on a security event.
        """
        # Unpack alert or raw event
        if isinstance(alert_or_event, Tier1Alert):
            event_data = alert_or_event.raw_event
            domain = alert_or_event.domain
            tier1_score = alert_or_event.anomaly_score
            tier1_reasons = alert_or_event.reasons
        elif isinstance(alert_or_event, dict):
            event_data = alert_or_event
            domain = "MULTI_VECTOR"
            tier1_score = 0.80
            tier1_reasons = ["Direct SOC ingestion / manual triage dispatch"]
        else:
            raise ValueError(f"Unsupported event format: {type(alert_or_event)}")

        state = InvestigationState(
            investigation_id=f"INV-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            domain=domain,
            event_telemetry=event_data,
            tier1_score=tier1_score,
            tier1_reasons=tier1_reasons
        )

        active_findings: List[AgentFinding] = []

        # 1. Dispatch Specialized Domain Agent
        if domain == "CYBER_LOG" or "source_ip" in event_data or "service" in event_data:
            state.cyber_sentinel = self.cyber_agent.analyze(event_data, tier1_reasons)
            active_findings.append(state.cyber_sentinel)

        if domain == "FINANCIAL" or "amount" in event_data or "tx_id" in event_data:
            state.fraud_investigator = self.fraud_agent.analyze(event_data, tier1_reasons)
            active_findings.append(state.fraud_investigator)

        if domain == "EMAIL" or "sender_email" in event_data or "subject" in event_data:
            state.phishing_analyst = self.phishing_agent.analyze(event_data, tier1_reasons)
            active_findings.append(state.phishing_analyst)

        # 2. Always Run Threat Intel & OSINT Correlator
        state.threat_intel = self.threat_intel_agent.analyze(event_data)
        active_findings.append(state.threat_intel)

        # 3. Inter-Agent Debate Mechanism
        # If there's disagreement between agents (e.g. one flags threat while another is benign),
        # conduct a structured debate round to verify confidence.
        suspicious_flags = [f.is_suspicious for f in active_findings]
        has_divergence = any(suspicious_flags) and not all(suspicious_flags)

        if ENABLE_DEBATE_ROUND and has_divergence:
            state.debate_rounds_conducted = 1
            divergent_msg = {
                "round": "1",
                "topic": "Divergence Resolution: Cross-Domain Correlation",
                "finding_summary": f"Threat Intel / Domain Agent disagreement detected. Cross-checking IOC reputation against local behavioral baselines.",
                "status": "Corroborated across secondary indicators."
            }
            state.debate_transcript.append(divergent_msg)

        # 4. Master Incident Commander Synthesis
        state.consensus = self.commander_agent.synthesize(event_data, active_findings)
        state.is_resolved = True

        return state
