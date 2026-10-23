"""
Shared State Schema (Blackboard) for Multi-Agent Investigation.
Defines typed data structures for agent findings, consensus, and playbooks.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class AgentFinding(BaseModel):
    agent_name: str
    is_suspicious: bool = False
    confidence: float = 0.0  # 0.0 to 1.0
    threat_category: str = "NONE"
    evidence: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    action_recommendation: str = ""
    raw_response: Optional[str] = None

class PlaybookStep(BaseModel):
    step_number: int
    action_type: str  # e.g., "BLOCK_IP", "FREEZE_ACCOUNT", "REVOKE_SESSION", "QUARANTINE_EMAIL"
    target: str
    priority: str = "HIGH"  # "CRITICAL", "HIGH", "MEDIUM"
    description: str

class IncidentConsensus(BaseModel):
    verdict: str = "UNDER_INVESTIGATION"  # "CONFIRMED_MALICIOUS", "SUSPICIOUS", "BENIGN_FALSE_POSITIVE"
    composite_threat_score: int = 0  # 0 to 100
    overall_confidence: float = 0.0
    executive_summary: str = ""
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    containment_playbook: List[PlaybookStep] = Field(default_factory=list)
    agent_votes: Dict[str, str] = Field(default_factory=dict)

class InvestigationState(BaseModel):
    """The central state shared across all autonomous agents in the graph."""
    investigation_id: str
    timestamp: str
    domain: str  # "FINANCIAL", "CYBER_LOG", "EMAIL", "MULTI_VECTOR"
    event_telemetry: Dict[str, Any]
    tier1_score: float = 0.0
    tier1_reasons: List[str] = Field(default_factory=list)

    # Individual Agent Findings
    cyber_sentinel: Optional[AgentFinding] = None
    fraud_investigator: Optional[AgentFinding] = None
    phishing_analyst: Optional[AgentFinding] = None
    threat_intel: Optional[AgentFinding] = None

    # Debate / Inter-Agent Collaboration
    debate_transcript: List[Dict[str, str]] = Field(default_factory=list)
    debate_rounds_conducted: int = 0

    # Final Synthesis & Response
    consensus: Optional[IncidentConsensus] = None
    is_resolved: bool = False
