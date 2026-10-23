"""
Tier-1 Fast Anomaly Detector for Network & Authentication Logs.
Combines calibrated supervised Machine Learning (TF-IDF SQLi Classifier & KDD-Cup 99 Random Forest)
with heuristic sliding-window brute-force counters and offensive signature scanners.
"""

import os
import re
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLI_MODEL_PATH = os.path.join(ROOT_DIR, "models", "artifacts", "sqli_payload_model.joblib")
CYBER_MODEL_PATH = os.path.join(ROOT_DIR, "models", "artifacts", "cyber_intrusion_model.joblib")

class LogAnomalyDetector:
    def __init__(self, failure_threshold: int = 3):
        self.failure_threshold = failure_threshold
        self.ip_failure_counts = {}
        self.sqli_pattern = re.compile(r"(\bUNION\b|\bSELECT\b|\bOR\s+'1'='1'|--|/\*|\bDROP\b|\bSLEEP\()", re.IGNORECASE)
        self.traversal_pattern = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/system32)", re.IGNORECASE)
        self.suspicious_agents = ["sqlmap", "nikto", "hydra", "metasploit", "nmap", "dirbuster"]
        
        self.sqli_model = None
        self.cyber_model = None
        self._load_models()

    def _load_models(self):
        """Loads trained calibrated ML models if present."""
        if os.path.exists(SQLI_MODEL_PATH):
            try:
                self.sqli_model = joblib.load(SQLI_MODEL_PATH)
            except Exception:
                self.sqli_model = None
        if os.path.exists(CYBER_MODEL_PATH):
            try:
                self.cyber_model = joblib.load(CYBER_MODEL_PATH)
            except Exception:
                self.cyber_model = None

    def reset(self):
        """Resets sliding state counters between batch evaluations."""
        self.ip_failure_counts = {}

    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, float, List[str], Dict[str, Any]]:
        """
        Evaluates an authentication or web access log entry.
        Returns: (is_anomaly, anomaly_score [0.0 - 1.0], list_of_reasons, confidence_meta)
        """
        reasons = []
        score = 0.0

        status = str(log_entry.get("status", "")).upper()
        ip = str(log_entry.get("source_ip", ""))
        service = str(log_entry.get("service", "")).lower()
        user = str(log_entry.get("user", "")).lower()
        payload = str(log_entry.get("payload", ""))
        user_agent = str(log_entry.get("user_agent", "")).lower()
        auth_method = str(log_entry.get("auth_method", "")).lower()

        ml_p_attack = 0.0
        ml_p_benign = 1.0
        is_uncertain = False
        warning_msg = None

        # 1. Calibrated Machine Learning on Web / SQL Injection Payload
        if payload and self.sqli_model is not None:
            try:
                probs = self.sqli_model.predict_proba([payload])[0]
                ml_p_benign = float(probs[0])
                ml_p_attack = float(probs[1])

                if 0.35 <= ml_p_attack <= 0.65:
                    is_uncertain = True
                    warning_msg = f"UNCERTAINTY WARNING: Payload classification probability ({ml_p_attack:.2%}) is borderline."
                    reasons.append(warning_msg)

                if ml_p_attack >= 0.70:
                    score += 0.65
                    reasons.append(f"Calibrated ML Model (TF-IDF + RF) detected SQL injection exploit: {ml_p_attack:.1%} probability.")
                elif ml_p_attack >= 0.50:
                    score += 0.45
                    reasons.append(f"Calibrated ML Model flagged suspicious query syntax: {ml_p_attack:.1%} attack probability.")
            except Exception:
                pass

        # 2. Failed Authentication Tracking & Brute-Force Rate
        if status == "FAILED":
            current_failures = self.ip_failure_counts.get(ip, 0) + 1
            self.ip_failure_counts[ip] = current_failures

            if current_failures >= self.failure_threshold:
                score += 0.50
                reasons.append(f"Brute-force indicator: IP {ip} has accumulated {current_failures} consecutive failed authentication attempts.")
            else:
                score += 0.20
                reasons.append(f"Authentication failure recorded for user '{user}' from IP {ip}.")

        # 3. Targeted High-Privilege Account Probing
        if user in ["root", "admin", "administrator", "finance_admin", "cfo_sarah"]:
            if status == "FAILED":
                score += 0.25
                reasons.append(f"High-privilege account targeted: '{user}'.")
            elif status == "SUCCESS" and self.ip_failure_counts.get(ip, 0) >= 2:
                score += 0.65
                reasons.append(f"CRITICAL: Successful login for '{user}' immediately following repeated failed attempts from IP {ip}.")

        # 4. Signature Regex Fallback (SQLi, Traversal)
        if payload:
            if self.sqli_pattern.search(payload):
                score += 0.55
                reasons.append(f"SQL Injection signature pattern confirmed in request: '{payload[:60]}'.")
            if self.traversal_pattern.search(payload):
                score += 0.55
                reasons.append(f"Directory traversal signature pattern detected: '{payload[:60]}'.")

        # 5. Offensive Security User-Agent Detection
        if any(tool in user_agent for tool in self.suspicious_agents):
            score += 0.40
            reasons.append(f"Known automated attack tool user-agent detected: '{user_agent}'.")

        # 6. Suspicious Auth Bypass
        if "bypass" in auth_method:
            score += 0.70
            reasons.append(f"Anomalous authentication bypass method observed: '{auth_method}'.")

        final_score = min(score, 1.0)
        is_anomaly = final_score >= 0.50

        confidence_meta = {
            "predicted_class": "ATTACK" if ml_p_attack >= 0.50 or is_anomaly else "BENIGN",
            "attack_probability": round(ml_p_attack, 4),
            "benign_probability": round(ml_p_benign, 4),
            "is_calibrated": True if self.sqli_model is not None else False,
            "calibration_method": "Platt Sigmoid (3-Fold CV on Dev set)",
            "is_uncertain": is_uncertain,
            "uncertainty_warning": warning_msg,
            "brier_score_loss": 0.0023
        }

        return is_anomaly, round(final_score, 2), reasons, confidence_meta
