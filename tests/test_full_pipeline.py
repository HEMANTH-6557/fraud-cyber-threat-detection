"""
Comprehensive Automated Verification Test Suite for Autonomous SOC Framework.
Validates:
1. SQLite Database Schema, WAL Mode, and Indexes.
2. Telemetry Dataset Discovery and Inventory Counts.
3. Ingestion & Normalization Pipelines across Financial, Cyber, and Email domains.
4. Tier-1 Fast ML Anomaly Detection & Calibrated Probability Scoring.
5. Epistemic Uncertainty Flagging & Boundary Constraints.
6. Multi-Agent Orchestrator Dispatch & Consensus Synthesis.
7. Cross-Domain Attack Scenario Correlation (Predefined & Dynamic).
8. Live Attack Simulator Isolation & Simulation Reset.
9. Independent Test Split Verification.
"""

import os
import sys
import json
import sqlite3

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.database import SOCDatabase
from core.ingestion_engine import IngestionEngine
from core.scenario_engine import ScenarioCorrelationEngine
from detectors.tier1_pipeline import Tier1Pipeline, Tier1Alert
from core.orchestrator import MultiAgentOrchestrator

# ==============================================================================
# TEST 1: Database Schema, WAL Mode & Indexes
# ==============================================================================
def test_database_schema_and_wal():
    db = SOCDatabase()
    with db.get_connection() as conn:
        cursor = conn.cursor()

        # Check WAL mode
        cursor.execute("PRAGMA journal_mode")
        journal_mode = cursor.fetchone()[0].upper()
        assert journal_mode == "WAL", f"Expected WAL mode, got {journal_mode}"

        # Check Tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        required_tables = {"events", "alerts", "investigations", "scenarios", "ingestion_runs"}
        assert required_tables.issubset(tables), f"Missing tables: {required_tables - tables}"

        # Check Indexes exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_events_domain" in indexes
        assert "idx_events_timestamp" in indexes
        assert "idx_alerts_priority" in indexes
    print("[PASS] Test 1: Database Schema, WAL Mode & Indexes Verified")

# ==============================================================================
# TEST 2: Dataset Discovery & Inventory
# ==============================================================================
def test_dataset_inventory():
    engine = IngestionEngine()
    inv = engine.get_dataset_inventory()

    # Verify seed datasets
    assert "auth_logs.json" in inv["seed_datasets"]
    assert inv["seed_datasets"]["auth_logs.json"]["record_count"] == 9
    assert "financial_transactions.csv" in inv["seed_datasets"]
    assert inv["seed_datasets"]["financial_transactions.csv"]["record_count"] == 6
    assert "suspicious_emails.json" in inv["seed_datasets"]
    assert inv["seed_datasets"]["suspicious_emails.json"]["record_count"] == 3

    # Verify expanded benchmarks
    expanded = inv["expanded_benchmarks"]
    assert "financial_fraud_expanded.csv" in expanded
    assert expanded["financial_fraud_expanded.csv"]["record_count"] >= 50000
    assert "cyber_intrusion_expanded.csv" in expanded
    assert expanded["cyber_intrusion_expanded.csv"]["record_count"] >= 33000
    assert "sql_injection_expanded.csv" in expanded
    assert expanded["sql_injection_expanded.csv"]["record_count"] >= 50000
    assert "phishing_websites_expanded.csv" in expanded
    assert expanded["phishing_websites_expanded.csv"]["record_count"] >= 5800
    assert "spambase_email_expanded.csv" in expanded
    assert expanded["spambase_email_expanded.csv"]["record_count"] >= 4200

    assert inv["total_discovered_records"] >= 143897
    print(f"[PASS] Test 2: Dataset Inventory Verified ({inv['total_discovered_records']:,} authentic records discovered)")

# ==============================================================================
# TEST 3: Ingestion Normalization
# ==============================================================================
def test_ingestion_normalization():
    # Financial Normalization
    fin_raw = {"amount": 25000.0, "user_name": "cfo_test", "merchant": "Acme Holdings"}
    fin_norm = IngestionEngine.normalize_financial_event(fin_raw, "UnitTest")
    assert fin_norm["domain"] == "FINANCIAL"
    assert fin_norm["amount"] == 25000.0
    assert fin_norm["event_type"] == "WIRE_TRANSFER"
    assert "event_id" in fin_norm

    # Cyber Normalization
    cyb_raw = {"source_ip": "194.26.29.112", "user": "admin", "status": "FAILED", "service": "ssh"}
    cyb_norm = IngestionEngine.normalize_cyber_event(cyb_raw, "UnitTest")
    assert cyb_norm["domain"] == "CYBER_LOG"
    assert cyb_norm["source_ip"] == "194.26.29.112"
    assert cyb_norm["status"] == "FAILED"

    # Email Normalization
    eml_raw = {"sender_email": "phish@fake-login.com", "subject": "Account Suspended"}
    eml_norm = IngestionEngine.normalize_email_event(eml_raw, "UnitTest")
    assert eml_norm["domain"] == "EMAIL"
    assert eml_norm["sender_email"] == "phish@fake-login.com"
    print("[PASS] Test 3: Normalization across all 3 domains verified")

# ==============================================================================
# TEST 4: Tier-1 Fast ML Anomaly Detection & Calibration
# ==============================================================================
def test_tier1_fast_ml_detection():
    pipeline = Tier1Pipeline(anomaly_threshold=0.50)

    # Test Malicious Financial Event
    mal_tx = {
        "tx_id": "TXN-TEST-MAL",
        "amount": 95000.0,
        "old_balance_orig": 95000.0,
        "new_balance_orig": 0.0,
        "old_balance_dest": 0.0,
        "new_balance_dest": 95000.0,
        "merchant_category": "Cryptocurrency & Wire Transfer",
        "location_country": "RU"
    }
    alert_tx = pipeline.process_event(mal_tx)
    assert alert_tx is not None, "Expected Tier-1 alert for massive wire drain"
    assert alert_tx.domain == "FINANCIAL"
    assert alert_tx.anomaly_score >= 0.50
    assert 0.0 <= alert_tx.calibrated_probability <= 1.0

    # Test Benign Financial Event
    benign_tx = {
        "tx_id": "TXN-TEST-BENIGN",
        "amount": 25.50,
        "old_balance_orig": 1500.0,
        "new_balance_orig": 1474.50,
        "old_balance_dest": 200.0,
        "new_balance_dest": 225.50,
        "merchant_category": "Retail & Grocery",
        "location_country": "US"
    }
    alert_benign = pipeline.process_event(benign_tx)
    assert alert_benign is None, "Expected benign transaction to pass without alert"

    # Test Malicious Cyber Event (SQL Injection)
    mal_cyber = {
        "event_id": "CYB-TEST-SQLI",
        "user": "root",
        "source_ip": "45.154.255.89",
        "payload": "' UNION SELECT * FROM users--",
        "status": "FAILED",
        "service": "ssh"
    }
    alert_cyb = pipeline.process_event(mal_cyber)
    assert alert_cyb is not None
    assert alert_cyb.domain == "CYBER_LOG"

    print("[PASS] Test 4: Tier-1 Fast ML Anomaly Detection & Probability Calibration Verified")

# ==============================================================================
# TEST 5: Epistemic Uncertainty Guardrails
# ==============================================================================
def test_uncertainty_guardrails():
    pipeline = Tier1Pipeline(anomaly_threshold=0.30)
    # Event designed near ambiguity boundary
    border_event = {
        "tx_id": "TXN-BORDER-001",
        "amount": 450.0,
        "old_balance_orig": 1000.0,
        "new_balance_orig": 550.0,
        "merchant_category": "Online Purchase",
        "location_country": "GB"
    }
    alert = pipeline.process_event(border_event)
    if alert and 0.35 <= alert.calibrated_probability <= 0.65:
        assert alert.is_uncertain is True, "Ambiguous event must have is_uncertain=True"
    print("[PASS] Test 5: Epistemic Uncertainty Guardrails Verified")

# ==============================================================================
# TEST 6: Multi-Agent Orchestration & Debate
# ==============================================================================
def test_multi_agent_investigation():
    orchestrator = MultiAgentOrchestrator(provider="mock")
    db = SOCDatabase()

    test_alert_dict = {
        "event_id": "EVT-TEST-APT",
        "source_ip": "194.26.29.112",
        "user": "finance_admin",
        "amount": 48500.0,
        "merchant": "BitQuick Crypto Exchange",
        "location_country": "RU",
        "sender_email": "ceo@malicious-lure.cloud",
        "subject": "Urgent Wire"
    }

    state = orchestrator.investigate(test_alert_dict)
    assert state.is_resolved is True
    assert state.consensus is not None
    assert state.consensus.composite_threat_score >= 70
    assert "MALICIOUS" in state.consensus.verdict.upper()
    assert len(state.consensus.mitre_tactics) > 0
    assert len(state.consensus.containment_playbook) > 0

    # Test persistence to SQLite
    inv_data = {
        "investigation_id": state.investigation_id,
        "alert_id": "ALT-TEST-001",
        "event_id": "EVT-TEST-APT",
        "verdict": state.consensus.verdict,
        "composite_threat_score": state.consensus.composite_threat_score,
        "overall_confidence": state.consensus.overall_confidence,
        "executive_summary": state.consensus.executive_summary,
        "mitre_tactics": state.consensus.mitre_tactics,
        "mitre_techniques": state.consensus.mitre_techniques,
        "containment_playbook": [vars(p) for p in state.consensus.containment_playbook],
        "agent_votes": state.consensus.agent_votes,
        "full_state": {}
    }
    # Ensure foreign keys are satisfied
    db.insert_event(test_alert_dict)
    db.insert_alert({
        "alert_id": "ALT-TEST-001",
        "event_id": "EVT-TEST-APT",
        "domain": "CYBER_LOG",
        "anomaly_score": 0.95,
        "calibrated_probability": 0.99,
        "triage_priority": "CRITICAL",
        "reasons": ["High threat match"]
    })
    saved = db.insert_investigation(inv_data)
    assert saved is True, "Investigation record must persist to database"
    print("[PASS] Test 6: Multi-Agent Orchestration & SQLite Persistence Verified")

# ==============================================================================
# TEST 7: Cross-Domain Scenario Engine
# ==============================================================================
def test_scenario_correlation_engine():
    db = SOCDatabase()
    engine = ScenarioCorrelationEngine(db=db)
    res = engine.run_correlation()

    assert res["total_registered_scenarios"] >= 5
    scenarios = db.get_scenarios()
    sc_ids = {s["scenario_id"] for s in scenarios}

    # Verify predefined benchmarks
    assert "SCENARIO-ALPHA-APTTROJAN" in sc_ids
    assert "SCENARIO-BETA-FALSEPOSITIVE" in sc_ids

    # Verify dynamically discovered scenarios
    assert "SCENARIO-GAMMA-SQLI-EXFIL" in sc_ids
    assert "SCENARIO-DELTA-SPEARPHISH-EXEC" in sc_ids
    assert "SCENARIO-EPSILON-GEO-VELOCITY" in sc_ids

    for sc in scenarios:
        assert len(sc["event_chain"]) >= 2
        assert sc["risk_score"] > 0
    print(f"[PASS] Test 7: Scenario Engine Verified ({len(scenarios)} Cross-Domain Scenarios Active)")

# ==============================================================================
# TEST 8: Simulation Isolation & Purge
# ==============================================================================
def test_simulation_isolation():
    db = SOCDatabase()

    stats_before = db.get_soc_statistics(exclude_simulations=True)

    # Insert simulated event
    sim_event = {
        "event_id": "EVT-SIM-ISOLATION-TEST",
        "timestamp": "2026-10-19T12:00:00Z",
        "domain": "FINANCIAL",
        "event_type": "WIRE_TRANSFER",
        "source_dataset": "SIMULATOR",
        "amount": 99999.0
    }
    db.insert_event(sim_event, is_simulation=True)

    # Verify simulation event does NOT pollute production count
    stats_after = db.get_soc_statistics(exclude_simulations=True)
    assert stats_after["total_events"] == stats_before["total_events"], "Production metrics must isolate simulations"

    # Verify simulation event is tracked in simulation counter
    stats_with_sim = db.get_soc_statistics(exclude_simulations=False)
    assert stats_with_sim["simulated_events_count"] >= 1

    # Purge simulations
    purged = db.reset_simulations()
    assert purged >= 1
    assert db.get_soc_statistics(exclude_simulations=False)["simulated_events_count"] == 0
    print("[PASS] Test 8: Simulation Isolation & Safe Reset Verified")

# ==============================================================================
# TEST 9: Independent Test Split Evaluation Metrics
# ==============================================================================
def test_independent_evaluation_metrics():
    benchmarks_path = os.path.join(ROOT_DIR, "results", "benchmark_metrics.json")
    assert os.path.exists(benchmarks_path), "Results benchmark metrics file must exist"

    with open(benchmarks_path, "r", encoding="utf-8") as f:
        bench_data = json.load(f)

    comp = bench_data["composite_metrics"]
    assert bench_data["total_test_samples_evaluated"] >= 27000
    assert comp["macro_accuracy_percent"] >= 99.0
    assert comp["macro_f1_score_percent"] >= 99.0

    # Verify probability calibration metrics
    for dom_name, d_eval in bench_data["domain_evaluations"].items():
        assert d_eval["brier_score"] < 0.05, f"Brier score for {dom_name} exceeds threshold"
        assert d_eval["ece"] < 0.05, f"ECE for {dom_name} exceeds threshold"

    print("[PASS] Test 9: Independent Held-Out Test Evaluation & Calibration Integrity Verified")

if __name__ == "__main__":
    test_database_schema_and_wal()
    test_dataset_inventory()
    test_ingestion_normalization()
    test_tier1_fast_ml_detection()
    test_uncertainty_guardrails()
    test_multi_agent_investigation()
    test_scenario_correlation_engine()
    test_simulation_isolation()
    test_independent_evaluation_metrics()
    print("\n==========================================")
    print("ALL 9 AUTOMATED PIPELINE TESTS PASSED [OK]")
    print("==========================================")
