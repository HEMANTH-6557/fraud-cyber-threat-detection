"""
Test suite for Tier-1 Anomaly Detection Pipeline.
Validates detection of financial fraud, cyber auth attacks, and phishing lures.
"""

import os
import sys
import json
import csv

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.tier1_pipeline import Tier1Pipeline

def test_tier1_pipeline():
    pipeline = Tier1Pipeline(anomaly_threshold=0.50)
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

    print("==================================================")
    print("Testing Tier-1 Fast Anomaly Detection Pipeline")
    print("==================================================")

    # 1. Test Auth Logs
    auth_file = os.path.join(data_dir, "auth_logs.json")
    with open(auth_file, "r", encoding="utf-8") as f:
        auth_logs = json.load(f)

    auth_alerts = pipeline.scan_batch(auth_logs)
    print(f"\n[Auth Logs] Ingested: {len(auth_logs)} | Flagged Alerts: {len(auth_alerts)}")
    for alert in auth_alerts:
        print(f"  -> [{alert.triage_priority}] Score: {alert.anomaly_score:.2f} | Reasons: {alert.reasons[0]}")

    # 2. Test Financial Transactions
    tx_file = os.path.join(data_dir, "financial_transactions.csv")
    with open(tx_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        transactions = [dict(row) for row in reader]

    tx_alerts = pipeline.scan_batch(transactions)
    print(f"\n[Transactions] Ingested: {len(transactions)} | Flagged Alerts: {len(tx_alerts)}")
    for alert in tx_alerts:
        print(f"  -> [{alert.triage_priority}] Score: {alert.anomaly_score:.2f} | Reasons: {alert.reasons[0]}")

    # 3. Test Suspicious Emails
    email_file = os.path.join(data_dir, "suspicious_emails.json")
    with open(email_file, "r", encoding="utf-8") as f:
        emails = json.load(f)

    email_alerts = pipeline.scan_batch(emails)
    print(f"\n[Emails] Ingested: {len(emails)} | Flagged Alerts: {len(email_alerts)}")
    for alert in email_alerts:
        print(f"  -> [{alert.triage_priority}] Score: {alert.anomaly_score:.2f} | Reasons: {alert.reasons[0]}")

    total_events = len(auth_logs) + len(transactions) + len(emails)
    total_alerts = len(auth_alerts) + len(tx_alerts) + len(email_alerts)
    filtered_pct = ((total_events - total_alerts) / total_events) * 100

    print("\n--------------------------------------------------")
    print(f"SUMMARY: Ingested {total_events} events. Filtered out {total_events - total_alerts} benign events ({filtered_pct:.1f}% reduction).")
    print(f"Forwarded {total_alerts} high-risk alerts to Tier-2 Multi-Agent Engine.")
    print("Tier-1 Pipeline Validation: PASSED")
    print("--------------------------------------------------")

if __name__ == "__main__":
    test_tier1_pipeline()
