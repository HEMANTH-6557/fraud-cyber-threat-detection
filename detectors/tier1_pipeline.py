"""
Unified Tier-1 Anomaly Detection Pipeline.
Processes incoming multi-domain telemetry, applies calibrated machine learning and fast heuristics,
and generates structured alerts for Tier-2 Multi-Agent autonomous investigation.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import hashlib

from detectors.transaction_anomaly import TransactionAnomalyDetector
from detectors.log_anomaly import LogAnomalyDetector
from detectors.email_anomaly import EmailAnomalyDetector

@dataclass
class Tier1Alert:
    alert_id: str
    timestamp: str
    domain: str  # "FINANCIAL", "CYBER_LOG", "EMAIL"
    raw_event: Dict[str, Any]
    anomaly_score: float
    reasons: List[str]
    triage_priority: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    confidence_meta: Dict[str, Any] = field(default_factory=dict)
    calibrated_probability: float = 0.0
    is_uncertain: bool = False

class Tier1Pipeline:
    def __init__(self, anomaly_threshold: float = 0.50):
        self.anomaly_threshold = anomaly_threshold
        self.tx_detector = TransactionAnomalyDetector()
        self.log_detector = LogAnomalyDetector()
        self.email_detector = EmailAnomalyDetector()

    def identify_domain(self, event: Dict[str, Any]) -> str:
        """Determines event domain from schema signatures."""
        if "amount" in event or "merchant" in event or "tx_id" in event:
            return "FINANCIAL"
        elif "subject" in event or "sender_email" in event or "email_id" in event:
            return "EMAIL"
        elif "service" in event or "source_ip" in event or "auth_method" in event or "event_id" in event or "payload" in event:
            return "CYBER_LOG"
        return "UNKNOWN"

    def process_event(self, event: Dict[str, Any]) -> Optional[Tier1Alert]:
        """
        Fast evaluation of an event using calibrated ML + heuristic filtering.
        Returns a Tier1Alert if anomaly score >= anomaly_threshold, else None.
        """
        domain = self.identify_domain(event)
        is_anomaly = False
        score = 0.0
        reasons = []
        conf_meta = {}

        if domain == "FINANCIAL":
            res = self.tx_detector.detect(event)
        elif domain == "CYBER_LOG":
            res = self.log_detector.detect(event)
        elif domain == "EMAIL":
            res = self.email_detector.detect(event)
        else:
            return None

        if len(res) == 4:
            is_anomaly, score, reasons, conf_meta = res
        else:
            is_anomaly, score, reasons = res
            conf_meta = {}

        if score >= self.anomaly_threshold:
            # Determine initial triage priority
            if score >= 0.85:
                priority = "CRITICAL"
            elif score >= 0.70:
                priority = "HIGH"
            elif score >= 0.50:
                priority = "MEDIUM"
            else:
                priority = "LOW"

            # Stable Alert ID
            event_ref = event.get("event_id") or event.get("tx_id") or event.get("email_id")
            if event_ref:
                stable_alert_id = f"ALT-{event_ref}"
            else:
                h = hashlib.md5(str(sorted([(k, str(v)) for k, v in event.items()])).encode()).hexdigest()[:6].upper()
                stable_alert_id = f"ALT-{domain[:3]}-{h}"

            cal_prob = conf_meta.get("fraud_probability") or conf_meta.get("attack_probability") or conf_meta.get("phishing_probability") or score
            is_unc = conf_meta.get("is_uncertain", False)

            return Tier1Alert(
                alert_id=stable_alert_id,
                timestamp=datetime.utcnow().isoformat() + "Z",
                domain=domain,
                raw_event=event,
                anomaly_score=score,
                reasons=reasons,
                triage_priority=priority,
                confidence_meta=conf_meta,
                calibrated_probability=float(cal_prob),
                is_uncertain=is_unc
            )
        return None

    def scan_batch(self, events: List[Dict[str, Any]]) -> List[Tier1Alert]:
        """Scans a batch of telemetry events and returns all flagged alerts."""
        self.log_detector.reset()
        alerts = []
        for event in events:
            alert = self.process_event(event)
            if alert:
                alerts.append(alert)
        return alerts
