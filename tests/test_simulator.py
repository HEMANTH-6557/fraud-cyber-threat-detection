import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.tier1_pipeline import Tier1Pipeline
from core.orchestrator import MultiAgentOrchestrator

pipeline = Tier1Pipeline()
orch = MultiAgentOrchestrator(provider='mock')

tests = [
    ("Custom $35,000 Offshore Wire", {"amount": 35000.0, "merchant": "Offshore Capital Transfers", "merchant_category": "Wire Transfer", "location_country": "RU"}),
    ("Custom Web SQL Injection", {"payload": "' UNION SELECT * FROM users--", "user": "root", "service": "ssh", "status": "FAILED"}),
    ("Custom Urgent BEC Phishing", {"subject": "URGENT wire transfer", "sender_name": "CEO Jonathan", "sender_email": "ceo@corp-enterprise-mgmt.com", "headers": {"spf": "FAIL", "dmarc": "FAIL"}}),
    ("Custom Normal $25 Retail Spend", {"amount": 25.0, "merchant": "Starbucks Coffee", "merchant_category": "Retail", "location_country": "US"})
]

print("=====================================================================")
print("EVALUATING CUSTOM SIMULATOR LOGIC ACROSS SECTIONS")
print("=====================================================================")
for name, ev in tests:
    alert = pipeline.process_event(ev)
    if alert:
        res = orch.investigate(alert)
        print(f"[FLAGGED] {name:<32} -> Threat Score: {res.consensus.composite_threat_score}/100 | Conf: {res.consensus.overall_confidence:.2f} | Verdict: {res.consensus.verdict}")
    else:
        print(f"[BENIGN ] {name:<32} -> Passed Tier-1 filter cleanly without spending tokens.")
print("=====================================================================")
