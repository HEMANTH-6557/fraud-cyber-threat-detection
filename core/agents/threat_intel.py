"""
Threat Intelligence & OSINT Correlator Agent.
Specializes in IP reputation, domain toxicity, known C2 servers, and threat actor attribution.
"""

import json
from typing import Dict, Any, List
from core.state import AgentFinding
from tools.threat_intel_tools import ThreatIntelTool

THREAT_INTEL_SYSTEM_PROMPT = """You are the Threat Intelligence & OSINT Correlator Agent in an autonomous SOC.
Your role is to assess external indicators of compromise (IOCs), IP reputation, domain history, and threat actor infrastructure.
Correlate observed technical indicators with known threat groups (e.g. APT groups, cybercrime syndicates).

You must respond ONLY with valid JSON in this exact structure:
{
  "is_suspicious": true,
  "confidence": 0.96,
  "threat_category": "Malicious Infrastructure & Known Threat Actor",
  "evidence": [
    "Source IP 194.26.29.112 has 98% abuse confidence score on threat feeds",
    "Linked to known credential-harvesting campaigns"
  ],
  "mitre_techniques": ["T1583 - Acquire Infrastructure"],
  "action_recommendation": "Deploy edge firewall block and report IP to national CERT/ISAC."
}
"""

class ThreatIntelAgent:
    def __init__(self, llm):
        self.llm = llm

    def extract_iocs(self, event_telemetry: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extracts IPs, domains, and URLs from any telemetry structure."""
        iocs = {"ips": [], "domains_urls": []}

        # IP fields
        for key in ["source_ip", "ip_address", "ip"]:
            if key in event_telemetry and event_telemetry[key]:
                iocs["ips"].append(str(event_telemetry[key]))

        # URL / Domain fields
        for key in ["sender_email", "endpoint"]:
            if key in event_telemetry and event_telemetry[key]:
                iocs["domains_urls"].append(str(event_telemetry[key]))

        if "urls" in event_telemetry and isinstance(event_telemetry["urls"], list):
            iocs["domains_urls"].extend(event_telemetry["urls"])

        return iocs

    def analyze(self, event_telemetry: Dict[str, Any]) -> AgentFinding:
        """Queries OSINT tools and synthesizes reputation findings."""
        iocs = self.extract_iocs(event_telemetry)
        osint_results = []

        for ip in iocs["ips"]:
            lookup = ThreatIntelTool.lookup_ip(ip)
            osint_results.append(lookup)

        for target in iocs["domains_urls"]:
            lookup = ThreatIntelTool.lookup_domain_or_url(target)
            osint_results.append(lookup)

        prompt = f"""{THREAT_INTEL_SYSTEM_PROMPT}

[OBSERVED IOCS & THREAT INTEL TELEMETRY]
OSINT Tool Queries: {json.dumps(osint_results, indent=2)}
Event Context: {json.dumps(event_telemetry, indent=2)}

Perform threat intelligence correlation and output JSON:"""

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
                agent_name="Threat Intel Correlator",
                is_suspicious=data.get("is_suspicious", True),
                confidence=float(data.get("confidence", 0.90)),
                threat_category=data.get("threat_category", "Threat Intel Match"),
                evidence=data.get("evidence", [f"OSINT Match: {r.get('verdict')}" for r in osint_results]),
                mitre_techniques=data.get("mitre_techniques", ["T1583"]),
                action_recommendation=data.get("action_recommendation", "Block IOCs across firewalls."),
                raw_response=content
            )
        except Exception as e:
            has_mal = any(r.get("is_malicious", False) for r in osint_results)
            return AgentFinding(
                agent_name="Threat Intel Correlator",
                is_suspicious=has_mal,
                confidence=0.85 if has_mal else 0.50,
                threat_category="OSINT Feed Hit" if has_mal else "No Known Threat",
                evidence=[f"{r.get('target', r.get('ip'))}: {r.get('verdict')}" for r in osint_results],
                mitre_techniques=["T1583"],
                action_recommendation="Blacklist confirmed malicious IP/domain." if has_mal else "Log and monitor.",
                raw_response=str(e)
            )
