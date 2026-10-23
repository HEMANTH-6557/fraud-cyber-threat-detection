"""
Dataset Generator for Fraud and Cyber Threat Detection.
Generates realistic multi-modal security telemetry:
- Authentication & Network Access Logs (JSON)
- Financial Transactions (CSV)
- Suspicious & Benign Emails (JSON)
- Coordinated Multi-Vector Scenarios (JSON)
"""

import json
import csv
import os
from datetime import datetime, timedelta

DATA_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_auth_logs():
    """Generates realistic authentication & network access telemetry."""
    base_time = datetime(2026, 10, 17, 8, 0, 0)
    logs = [
        # Normal developer logins
        {
            "event_id": "AUTH-1001",
            "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            "service": "ssh",
            "user": "dev_alex",
            "source_ip": "192.168.1.45",
            "location": "San Francisco, US",
            "status": "SUCCESS",
            "auth_method": "publickey",
            "label": "BENIGN"
        },
        {
            "event_id": "AUTH-1002",
            "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
            "service": "corporate_vpn",
            "user": "dev_priya",
            "source_ip": "10.0.4.12",
            "location": "Bangalore, IN",
            "status": "SUCCESS",
            "auth_method": "mfa_totp",
            "label": "BENIGN"
        },
        # Scenario 1: SSH Brute-Force Attack
        {
            "event_id": "AUTH-2001",
            "timestamp": (base_time + timedelta(minutes=30, seconds=5)).isoformat(),
            "service": "ssh",
            "user": "root",
            "source_ip": "194.26.29.112",
            "location": "St. Petersburg, RU",
            "status": "FAILED",
            "auth_method": "password",
            "label": "SUSPICIOUS_BRUTE_FORCE"
        },
        {
            "event_id": "AUTH-2002",
            "timestamp": (base_time + timedelta(minutes=30, seconds=12)).isoformat(),
            "service": "ssh",
            "user": "admin",
            "source_ip": "194.26.29.112",
            "location": "St. Petersburg, RU",
            "status": "FAILED",
            "auth_method": "password",
            "label": "SUSPICIOUS_BRUTE_FORCE"
        },
        {
            "event_id": "AUTH-2003",
            "timestamp": (base_time + timedelta(minutes=30, seconds=19)).isoformat(),
            "service": "ssh",
            "user": "ubuntu",
            "source_ip": "194.26.29.112",
            "location": "St. Petersburg, RU",
            "status": "FAILED",
            "auth_method": "password",
            "label": "SUSPICIOUS_BRUTE_FORCE"
        },
        {
            "event_id": "AUTH-2004",
            "timestamp": (base_time + timedelta(minutes=30, seconds=27)).isoformat(),
            "service": "ssh",
            "user": "finance_admin",
            "source_ip": "194.26.29.112",
            "location": "St. Petersburg, RU",
            "status": "SUCCESS",
            "auth_method": "password",
            "label": "COMPROMISED_CREDENTIAL_ACCESS"
        },
        # Scenario 2: Web API SQL Injection Attack
        {
            "event_id": "AUTH-3001",
            "timestamp": (base_time + timedelta(minutes=45)).isoformat(),
            "service": "web_api",
            "user": "anonymous",
            "source_ip": "45.154.255.89",
            "location": "Frankfurt, DE",
            "status": "FAILED",
            "endpoint": "/api/v1/auth/login",
            "payload": "' UNION SELECT username, password_hash FROM users--",
            "user_agent": "sqlmap/1.7#stable",
            "label": "SQL_INJECTION"
        },
        # Scenario 3: Impossible Geolocation Travel
        {
            "event_id": "AUTH-4001",
            "timestamp": (base_time + timedelta(hours=1, minutes=0)).isoformat(),
            "service": "okta_sso",
            "user": "cfo_sarah",
            "source_ip": "72.229.28.185",
            "location": "New York, US",
            "status": "SUCCESS",
            "auth_method": "push_verify",
            "label": "BENIGN"
        },
        {
            "event_id": "AUTH-4002",
            "timestamp": (base_time + timedelta(hours=1, minutes=14)).isoformat(),
            "service": "okta_sso",
            "user": "cfo_sarah",
            "source_ip": "185.220.101.5",
            "location": "Bucharest, RO",
            "status": "SUCCESS",
            "auth_method": "password_only_bypass",
            "label": "IMPOSSIBLE_TRAVEL_ATO"
        }
    ]

    filepath = os.path.join(DATA_DIR, "auth_logs.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
    print(f"Auth logs saved to: {filepath}")
    return logs


def generate_financial_transactions():
    """Generates financial transaction records with normal and fraudulent patterns."""
    base_time = datetime(2026, 10, 17, 9, 0, 0)
    transactions = [
        # Normal recurring spending
        {
            "tx_id": "TXN-8801",
            "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            "account_id": "ACC-4091",
            "user_name": "dev_alex",
            "amount": 42.50,
            "currency": "USD",
            "merchant": "Starbucks Coffee",
            "merchant_category": "Food & Beverage",
            "location_city": "San Francisco",
            "location_country": "US",
            "ip_address": "192.168.1.45",
            "device_id": "DEV-MAC-8812",
            "is_flagged_ground_truth": False,
            "anomaly_type": "NONE"
        },
        {
            "tx_id": "TXN-8802",
            "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
            "account_id": "ACC-4091",
            "user_name": "dev_alex",
            "amount": 89.90,
            "currency": "USD",
            "merchant": "Whole Foods Market",
            "merchant_category": "Groceries",
            "location_city": "San Francisco",
            "location_country": "US",
            "ip_address": "192.168.1.45",
            "device_id": "DEV-MAC-8812",
            "is_flagged_ground_truth": False,
            "anomaly_type": "NONE"
        },
        # Fraud Pattern 1: Sudden massive outlier drain right after breach
        {
            "tx_id": "TXN-9901",
            "timestamp": (base_time + timedelta(minutes=32)).isoformat(),
            "account_id": "ACC-9922",
            "user_name": "finance_admin",
            "amount": 48500.00,
            "currency": "USD",
            "merchant": "BitQuick Crypto Exchange",
            "merchant_category": "Cryptocurrency & Wire Transfer",
            "location_city": "St. Petersburg",
            "location_country": "RU",
            "ip_address": "194.26.29.112",
            "device_id": "DEV-UNKNOWN-992",
            "is_flagged_ground_truth": True,
            "anomaly_type": "HIGH_VALUE_DRAIN_AFTER_BREACH"
        },
        # Fraud Pattern 2: Rapid velocity card testing
        {
            "tx_id": "TXN-9902",
            "timestamp": (base_time + timedelta(minutes=35, seconds=10)).isoformat(),
            "account_id": "ACC-7741",
            "user_name": "mark_watson",
            "amount": 2.00,
            "currency": "USD",
            "merchant": "Digital Goods MicroStore",
            "merchant_category": "Digital Goods",
            "location_city": "Miami",
            "location_country": "US",
            "ip_address": "103.251.167.20",
            "device_id": "DEV-BOT-01",
            "is_flagged_ground_truth": True,
            "anomaly_type": "VELOCITY_CARD_TESTING"
        },
        {
            "tx_id": "TXN-9903",
            "timestamp": (base_time + timedelta(minutes=35, seconds=25)).isoformat(),
            "account_id": "ACC-7741",
            "user_name": "mark_watson",
            "amount": 499.00,
            "currency": "USD",
            "merchant": "LuxJewelry Online",
            "merchant_category": "Luxury Goods",
            "location_city": "Miami",
            "location_country": "US",
            "ip_address": "103.251.167.20",
            "device_id": "DEV-BOT-01",
            "is_flagged_ground_truth": True,
            "anomaly_type": "VELOCITY_CARD_TESTING"
        },
        # Fraud Pattern 3: Impossible travel transaction
        {
            "tx_id": "TXN-9904",
            "timestamp": (base_time + timedelta(hours=1, minutes=20)).isoformat(),
            "account_id": "ACC-5520",
            "user_name": "cfo_sarah",
            "amount": 15000.00,
            "currency": "EUR",
            "merchant": "Offshore Private Banking Ltd",
            "merchant_category": "Wire Transfer",
            "location_city": "Bucharest",
            "location_country": "RO",
            "ip_address": "185.220.101.5",
            "device_id": "DEV-TOR-BROWSER",
            "is_flagged_ground_truth": True,
            "anomaly_type": "ACCOUNT_TAKEOVER_TRANSFER"
        }
    ]

    filepath = os.path.join(DATA_DIR, "financial_transactions.csv")
    fieldnames = list(transactions[0].keys())
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(transactions)
    print(f"Financial transactions saved to: {filepath}")
    return transactions


def generate_suspicious_emails():
    """Generates email telemetry containing spear phishing, BEC, and benign communications."""
    emails = [
        {
            "email_id": "EML-001",
            "subject": "Weekly Engineering Sprint Retrospective",
            "sender_name": "Dave Product Lead",
            "sender_email": "dave@corp-enterprise.internal",
            "recipient_email": "team@corp-enterprise.internal",
            "body": "Hi team, please find attached the retrospective summary notes from Friday's sprint retro. Great job on shipping the v2.4 release on time!",
            "attachments": ["sprint_retro_oct.pdf"],
            "urls": ["https://internal.wiki.corp-enterprise.internal/retro/2026-10"],
            "headers": {
                "spf": "PASS",
                "dkim": "PASS",
                "dmarc": "PASS",
                "reply_to": "dave@corp-enterprise.internal"
            },
            "ground_truth_label": "BENIGN"
        },
        {
            "email_id": "EML-002",
            "subject": "CRITICAL: Urgent Wire Transfer for Confidential Project Triton",
            "sender_name": "CEO Jonathan Reynolds",
            "sender_email": "ceo-jonathan@corp-entērprise-mgmt.com",
            "recipient_email": "finance_admin@corp-enterprise.internal",
            "body": "I am in an all-day confidential board meeting and cannot take calls. We need an urgent vendor acquisition escrow wire transfer of $48,500 processed immediately before market close today. Transfer details attached below. Keep this strictly between us.",
            "attachments": ["wire_escrow_details.pdf.exe"],
            "urls": ["http://secure-corporate-escrow-portal.top/auth?token=x991"],
            "headers": {
                "spf": "FAIL",
                "dkim": "NONE",
                "dmarc": "FAIL",
                "reply_to": "overseas-escrow-desk@protonmail.com"
            },
            "ground_truth_label": "PHISHING_BEC"
        },
        {
            "email_id": "EML-003",
            "subject": "Action Required: Microsoft 365 Password Expiration in 24 Hours",
            "sender_name": "IT Helpdesk Admin",
            "sender_email": "security-support@login-m365-verify.cloud",
            "recipient_email": "cfo_sarah@corp-enterprise.internal",
            "body": "Your corporate Microsoft account credentials will expire today. Click the button below to retain your current password and avoid service disruption.",
            "attachments": [],
            "urls": ["https://login-m365-verify.cloud/adfs/ls/?client_id=corp_auth"],
            "headers": {
                "spf": "SOFTFAIL",
                "dkim": "NONE",
                "dmarc": "FAIL",
                "reply_to": "harvest@darknet-c2.net"
            },
            "ground_truth_label": "PHISHING_CREDENTIAL_HARVEST"
        }
    ]

    filepath = os.path.join(DATA_DIR, "suspicious_emails.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(emails, f, indent=2)
    print(f"Suspicious emails saved to: {filepath}")
    return emails


def generate_combined_scenarios():
    """Generates end-to-end multi-agent cross-correlation attack scenarios."""
    scenarios = [
        {
            "scenario_id": "SCENARIO-ALPHA-APTTROJAN",
            "title": "Multi-Vector Coordinated Account Takeover & Wire Fraud",
            "description": "An attacker sends an executive spear-phishing lure to the finance administrator, conducts credential harvesting, logs in via SSH from an anomalous foreign IP, and initiates a high-value cryptocurrency wire transfer.",
            "event_chain": [
                {"step": 1, "domain": "EMAIL", "ref_id": "EML-002", "summary": "Urgent CEO wire transfer spear-phishing email received"},
                {"step": 2, "domain": "CYBER_AUTH", "ref_id": "AUTH-2001", "summary": "SSH brute force attempt from Russian IP 194.26.29.112"},
                {"step": 3, "domain": "CYBER_AUTH", "ref_id": "AUTH-2004", "summary": "Successful compromise login for finance_admin"},
                {"step": 4, "domain": "FRAUD", "ref_id": "TXN-9901", "summary": "$48,500 wire transfer to BitQuick Crypto Exchange from the same IP"}
            ],
            "expected_outcome": {
                "verdict": "CONFIRMED_MALICIOUS_ATTACK",
                "risk_score_range": [85, 100],
                "mitre_tactics": ["Initial Access", "Credential Access", "Impact"],
                "mitre_techniques": ["T1566 (Phishing)", "T1110 (Brute Force)", "T1657 (Financial Theft)"]
            }
        },
        {
            "scenario_id": "SCENARIO-BETA-FALSEPOSITIVE",
            "title": "VIP Global Travel (Benign Anomaly)",
            "description": "An executive travels internationally to an offshore branch and performs an authorized corporate procurement purchase. Initial velocity filter flags an anomaly, but multi-agent correlation determines legitimate business activity.",
            "event_chain": [
                {"step": 1, "domain": "CYBER_AUTH", "ref_id": "AUTH-1002", "summary": "VPN login via MFA TOTP"},
                {"step": 2, "domain": "FRAUD", "ref_id": "TXN-8801", "summary": "Small verified business merchant spend"}
            ],
            "expected_outcome": {
                "verdict": "BENIGN_FALSE_POSITIVE",
                "risk_score_range": [0, 30]
            }
        }
    ]

    filepath = os.path.join(DATA_DIR, "combined_scenarios.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scenarios, f, indent=2)
    print(f"Combined scenarios saved to: {filepath}")
    return scenarios


def generate_all():
    """Generates all benchmark datasets."""
    os.makedirs(DATA_DIR, exist_ok=True)
    generate_auth_logs()
    generate_financial_transactions()
    generate_suspicious_emails()
    generate_combined_scenarios()
    print("All security datasets generated successfully!")


if __name__ == "__main__":
    generate_all()
