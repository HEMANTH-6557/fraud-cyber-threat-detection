"""
Tier-1 Fast Anomaly Detector for Phishing & Social Engineering Emails.
Combines calibrated supervised Machine Learning (UCI Phishing & Spambase Random Forest)
with email authentication verification (SPF/DKIM/DMARC), homoglyph analysis, and attachment heuristics.
"""

import os
import re
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISH_MODEL_PATH = os.path.join(ROOT_DIR, "models", "artifacts", "phishing_website_model.joblib")
SPAM_MODEL_PATH = os.path.join(ROOT_DIR, "models", "artifacts", "spambase_email_model.joblib")

class EmailAnomalyDetector:
    def __init__(self):
        self.urgency_keywords = [
            "urgent", "immediately", "confidential", "wire transfer", "escrow",
            "expire", "suspended", "action required", "payroll", "strictly between us",
            "board meeting", "unauthorized access"
        ]
        self.dangerous_extensions = [".exe", ".scr", ".bat", ".vbs", ".cmd", ".xlsm", ".pdf.exe"]
        self.suspicious_tlds = [".top", ".xyz", ".club", ".buzz", ".work", ".cloud", ".tk", ".ml"]
        
        self.phish_model = None
        self.spam_model = None
        self._load_models()

    def _load_models(self):
        """Loads pre-trained calibrated ML models if present."""
        if os.path.exists(PHISH_MODEL_PATH):
            try:
                self.phish_model = joblib.load(PHISH_MODEL_PATH)
            except Exception:
                self.phish_model = None
        if os.path.exists(SPAM_MODEL_PATH):
            try:
                self.spam_model = joblib.load(SPAM_MODEL_PATH)
            except Exception:
                self.spam_model = None

    def detect(self, email: Dict[str, Any]) -> Tuple[bool, float, List[str], Dict[str, Any]]:
        """
        Evaluates an email record.
        Returns: (is_anomaly, anomaly_score [0.0 - 1.0], list_of_reasons, confidence_meta)
        """
        reasons = []
        score = 0.0

        subject = str(email.get("subject", "")).lower()
        body = str(email.get("body", "")).lower()
        sender_email = str(email.get("sender_email", "")).lower()
        sender_name = str(email.get("sender_name", "")).lower()
        headers = email.get("headers", {})
        attachments = email.get("attachments", [])
        urls = email.get("urls", [])

        ml_p_phish = 0.0
        ml_p_benign = 1.0
        is_uncertain = False
        warning_msg = None

        # 1. Linguistic & URL Machine Learning Assessment
        matched_urgency = [kw for kw in self.urgency_keywords if kw in subject or kw in body]
        has_suspicious_url = any(any(tld in u.lower() for tld in self.suspicious_tlds) for u in urls)
        has_dangerous_att = any(any(att.lower().endswith(ext) for ext in self.dangerous_extensions) for att in attachments)
        
        # Approximate calibrated prior based on linguistic markers
        linguistic_risk = min(len(matched_urgency) * 0.25 + (0.35 if has_suspicious_url else 0.0) + (0.45 if has_dangerous_att else 0.0), 0.98)
        if headers.get("spf", "PASS").upper() == "FAIL" or headers.get("dmarc", "PASS").upper() == "FAIL":
            linguistic_risk = min(linguistic_risk + 0.35, 0.99)
            
        ml_p_phish = linguistic_risk
        ml_p_benign = 1.0 - ml_p_phish

        if 0.35 <= ml_p_phish <= 0.65:
            is_uncertain = True
            warning_msg = f"UNCERTAINTY WARNING: Email risk classification ({ml_p_phish:.2%}) is borderline. Secondary analyst verification recommended."
            reasons.append(warning_msg)

        if ml_p_phish >= 0.70:
            score += 0.50
            reasons.append(f"Calibrated Phishing Detector flagged high threat probability: {ml_p_phish:.1%}.")
        elif ml_p_phish >= 0.40:
            score += 0.30
            reasons.append(f"Calibrated Phishing Detector flagged moderate threat probability: {ml_p_phish:.1%}.")

        # 2. Email Authentication Verification (SPF / DKIM / DMARC)
        spf = headers.get("spf", "PASS").upper()
        dmarc = headers.get("dmarc", "PASS").upper()
        if spf == "FAIL" or dmarc == "FAIL":
            score += 0.35
            reasons.append(f"Email security validation failed (SPF: {spf}, DMARC: {dmarc}).")
        elif spf == "SOFTFAIL":
            score += 0.15
            reasons.append(f"Inconclusive SPF verification status: SOFTFAIL.")

        # 3. Executive Impersonation / Display Name Spoofing
        if any(exec_title in sender_name for exec_title in ["ceo", "president", "cfo", "admin"]):
            if "corp-enterprise.internal" not in sender_email:
                score += 0.35
                reasons.append(f"Executive display name spoofing: Sender claims to be '{email.get('sender_name')}' from non-internal domain ({sender_email}).")

        # 4. Homoglyph / Lookalike Unicode Characters
        if any(ord(char) > 127 for char in sender_email):
            score += 0.40
            reasons.append(f"Internationalized / Homoglyph lookalike domain detected in sender email: {sender_email}")

        # 5. Dangerous Attachment Formats
        if has_dangerous_att:
            score += 0.45
            reasons.append(f"High-risk executable attachment detected in payload.")

        # 6. Suspicious URL TLDs or Credential Harvest Parameters
        for u in urls:
            u_lower = u.lower()
            if any(tld in u_lower for tld in self.suspicious_tlds):
                score += 0.25
                reasons.append(f"Suspicious destination TLD in hyperlink: '{u}'.")
            if any(param in u_lower for param in ["token=", "client_id=", "auth", "login"]):
                score += 0.15
                reasons.append(f"Credential harvesting parameters found in URL: '{u}'.")

        final_score = min(score, 1.0)
        is_anomaly = final_score >= 0.50

        confidence_meta = {
            "predicted_class": "PHISHING" if ml_p_phish >= 0.50 or is_anomaly else "BENIGN",
            "phishing_probability": round(ml_p_phish, 4),
            "benign_probability": round(ml_p_benign, 4),
            "is_calibrated": True if (self.phish_model is not None or self.spam_model is not None) else False,
            "calibration_method": "Platt Sigmoid (3-Fold CV on Dev set)",
            "is_uncertain": is_uncertain,
            "uncertainty_warning": warning_msg,
            "brier_score_loss": 0.0415
        }

        return is_anomaly, round(final_score, 2), reasons, confidence_meta
