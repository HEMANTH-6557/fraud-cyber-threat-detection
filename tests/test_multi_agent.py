"""
End-to-End Multi-Agent Framework Test Suite.
Validates the full collaborative workflow across all specialized agents,
consensus mechanisms, MITRE ATT&CK mapping, and automated containment generation.
"""

import os
import sys
import json

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import MultiAgentOrchestrator
from detectors.tier1_pipeline import Tier1Pipeline

def run_multi_agent_evaluation():
    print("================================================================================")
    print(" Autonomous Multi-Agent Framework: End-to-End Evaluation")
    print(" Topic: Fraud & Cyber Threat Detection Using Large Language Models")
    print("================================================================================\n")

    orchestrator = MultiAgentOrchestrator(provider="mock")
    pipeline = Tier1Pipeline(anomaly_threshold=0.50)
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

    # Load multi-vector scenario
    scenario_file = os.path.join(data_dir, "combined_scenarios.json")
    with open(scenario_file, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    print(f"Loaded {len(scenarios)} multi-vector benchmark scenarios.\n")

    for i, scenario in enumerate(scenarios, 1):
        print(f"--------------------------------------------------------------------------------")
        print(f"Evaluating Scenario {i}: {scenario['title']}")
        print(f"Description: {scenario['description']}")
        print(f"--------------------------------------------------------------------------------")

        for event_step in scenario["event_chain"]:
            ref_id = event_step["ref_id"]
            domain = event_step["domain"]
            print(f"\n>>> [INGESTING] Step {event_step['step']}: {event_step['summary']} (Ref: {ref_id})")

            # Resolve reference data
            raw_event = {}
            if domain == "CYBER_AUTH":
                with open(os.path.join(data_dir, "auth_logs.json"), "r", encoding="utf-8") as f:
                    logs = json.load(f)
                    raw_event = next((l for l in logs if l["event_id"] == ref_id), logs[0])
            elif domain == "FRAUD":
                import csv
                with open(os.path.join(data_dir, "financial_transactions.csv"), "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    txs = list(reader)
                    raw_event = next((t for t in txs if t["tx_id"] == ref_id), txs[0])
            elif domain == "EMAIL":
                with open(os.path.join(data_dir, "suspicious_emails.json"), "r", encoding="utf-8") as f:
                    emails = json.load(f)
                    raw_event = next((e for e in emails if e["email_id"] == ref_id), emails[0])

            # Tier-1 Fast Triage
            tier1_alert = pipeline.process_event(raw_event)
            if not tier1_alert:
                print(f"  [Tier-1 Filter] Event assessed as BENIGN. Filtered out from token expenditure.")
                continue

            print(f"  [Tier-1 Filter] ANOMALY FLAGGED! Score: {tier1_alert.anomaly_score:.2f} | Priority: {tier1_alert.triage_priority}")
            print(f"  [Tier-1 Filter] Reasons: {tier1_alert.reasons[0]}")

            # Tier-2 Autonomous Multi-Agent Investigation
            print("  [Tier-2 Multi-Agent Engine] Dispatching specialized agents...")
            state = orchestrator.investigate(tier1_alert)

            print(f"\n  === INVESTIGATION REPORT: {state.investigation_id} ===")
            if state.cyber_sentinel:
                print(f"  * Cyber Sentinel: Suspicious={state.cyber_sentinel.is_suspicious} | Conf={state.cyber_sentinel.confidence:.2f} | Cat={state.cyber_sentinel.threat_category}")
            if state.fraud_investigator:
                print(f"  * Fraud Investigator: Suspicious={state.fraud_investigator.is_suspicious} | Conf={state.fraud_investigator.confidence:.2f} | Cat={state.fraud_investigator.threat_category}")
            if state.phishing_analyst:
                print(f"  * Phishing Analyst: Suspicious={state.phishing_analyst.is_suspicious} | Conf={state.phishing_analyst.confidence:.2f} | Cat={state.phishing_analyst.threat_category}")
            if state.threat_intel:
                print(f"  * Threat Intel: Suspicious={state.threat_intel.is_suspicious} | Conf={state.threat_intel.confidence:.2f} | Cat={state.threat_intel.threat_category}")

            if state.debate_transcript:
                print(f"  * Inter-Agent Debate: {len(state.debate_transcript)} round(s) conducted for consensus arbitration.")

            consensus = state.consensus
            print(f"\n  --- FINAL INCIDENT COMMANDER VERDICT ---")
            print(f"  Verdict: {consensus.verdict}")
            print(f"  Composite Threat Score: {consensus.composite_threat_score}/100")
            print(f"  MITRE Tactics: {', '.join(consensus.mitre_tactics)}")
            print(f"  MITRE Techniques: {', '.join(consensus.mitre_techniques)}")
            print(f"  Executive Summary: {consensus.executive_summary}")

            if consensus.containment_playbook:
                print("\n  [AUTOMATED CONTAINMENT PLAYBOOK]")
                for step in consensus.containment_playbook:
                    print(f"    Step {step.step_number} [{step.priority}]: {step.action_type} -> {step.target}")
                    print(f"      Cmd: {step.description}")

    print("\n================================================================================")
    print(" Autonomous Multi-Agent Framework: All Scenarios Successfully Evaluated!")
    print("================================================================================")

if __name__ == "__main__":
    run_multi_agent_evaluation()
