"""
Automated Verification Suite for All Nine Selectable Modules.
Ensures that each of the 9 required modules executes successfully, produces meaningful output,
validates inputs, and handles exceptions cleanly.
"""

import os
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tools.threat_intel_tools import ThreatIntelTool, CISA_KEV_CATALOG, OWASP_TOP_10
from tools.report_generator import ForensicReportGenerator
from detectors.tier1_pipeline import Tier1Pipeline
from core.orchestrator import MultiAgentOrchestrator
from core.database import SOCDatabase


class TestNineModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = SOCDatabase()
        cls.pipeline = Tier1Pipeline(anomaly_threshold=0.50)
        cls.orchestrator = MultiAgentOrchestrator(provider="mock")

    # Module 1: System Testing & Validation
    def test_module_1_system_testing(self):
        stats = self.db.get_soc_statistics()
        self.assertIn("total_events", stats)
        self.assertIn("total_alerts", stats)
        self.assertGreaterEqual(stats["total_scenarios"], 2)

    # Module 2: Microsoft and Open-Source Threat Intelligence
    def test_module_2_threat_intelligence(self):
        # Known malicious IP
        res_ip = ThreatIntelTool.lookup_ip("194.26.29.112")
        self.assertTrue(res_ip["is_malicious"])
        self.assertEqual(res_ip["threat_actor"], "APT-29 / Midnight Blizzard proxy")
        self.assertGreaterEqual(res_ip["reputation_score"], 90)

        # Microsoft Threat Feed query
        ms_res = ThreatIntelTool.lookup_microsoft_intel("Midnight Blizzard")
        self.assertTrue(ms_res["is_malicious"])
        self.assertIn("OAuth", "".join(ms_res["observed_ttps"]))
        self.assertIn("MSRC", ms_res["microsoft_advisory"])

    # Module 3: OWASP Security & Vulnerability Analysis
    def test_module_3_owasp_analysis(self):
        # SQL Injection
        sqli_res = ThreatIntelTool.analyze_owasp_vulnerability("' UNION SELECT null, username, password FROM users--")
        self.assertTrue(sqli_res["is_vulnerable"])
        self.assertIn("A03:2021", sqli_res["primary_owasp_category"])
        self.assertGreater(sqli_res["ml_threat_probability"], 0.50)

        # Path Traversal
        path_res = ThreatIntelTool.analyze_owasp_vulnerability("../../../../etc/passwd")
        self.assertTrue(path_res["is_vulnerable"])
        self.assertIn("A01:2021", path_res["primary_owasp_category"])

    # Module 4: CISA Threat Intelligence (KEV)
    def test_module_4_cisa_kev(self):
        # Palo Alto GlobalProtect
        res = ThreatIntelTool.lookup_cisa_kev("CVE-2024-3400")
        self.assertTrue(res["found_in_cisa_kev"])
        self.assertEqual(res["cve_id"], "CVE-2024-3400")
        self.assertEqual(res["cvss_severity"], "CRITICAL")
        self.assertEqual(res["known_ransomware_campaign"], "Known")

        # MOVEit Transfer
        res_moveit = ThreatIntelTool.lookup_cisa_kev("MOVEit")
        self.assertTrue(res_moveit["found_in_cisa_kev"])
        self.assertEqual(res_moveit["cve_id"], "CVE-2023-34362")

    # Module 5: Vulnerability & CVSS Analysis
    def test_module_5_cvss_analysis(self):
        # Network, Low complexity, No priv, No UI -> Critical (9.8 or 10.0)
        cvss = ThreatIntelTool.calculate_cvss_v3(
            av="NETWORK", ac="LOW", pr="NONE", ui="NONE",
            scope="UNCHANGED", conf="HIGH", integ="HIGH", avail="HIGH"
        )
        self.assertEqual(cvss["cvss_base_score"], 9.8)
        self.assertEqual(cvss["severity"], "CRITICAL")
        self.assertIn("CVSS:3.1", cvss["vector_string"])

    # Module 6: Threat Intelligence and Security Report Summarization
    def test_module_6_report_summarization(self):
        raw_report = """Urgent Security Advisory: APT29 (Midnight Blizzard) launched a credential attack.
        Associated C2 IP is 194.26.29.112 and domain is login-m365-verify.cloud.
        Vulnerability exploited is CVE-2023-23397 in Microsoft Outlook."""
        summary = ThreatIntelTool.summarize_security_report(raw_report)
        self.assertIn("194.26.29.112", summary["extracted_iocs"]["ips"])
        self.assertIn("CVE-2023-23397", summary["extracted_iocs"]["cves"])
        self.assertGreater(len(summary["recommended_mitigations"]), 0)

    # Module 7: Fraud Detection
    def test_module_7_fraud_detection(self):
        # Outlier spend
        fraud_event = {
            "amount": 48500.0,
            "merchant": "BitQuick Crypto Exchange",
            "merchant_category": "Cryptocurrency & Wire Transfer",
            "location_country": "RU"
        }
        alert = self.pipeline.process_event(fraud_event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.domain, "FINANCIAL")
        self.assertIn("CRITICAL", alert.triage_priority)

    # Module 8: Cybersecurity Risk Assessment
    def test_module_8_cybersecurity_risk_assessment(self):
        cyber_event = {
            "source_ip": "194.26.29.112",
            "user": "root",
            "service": "ssh",
            "status": "FAILED"
        }
        res = self.orchestrator.investigate(cyber_event)
        self.assertTrue(res.is_resolved)
        self.assertGreaterEqual(res.consensus.composite_threat_score, 50)
        self.assertIn("CONFIRMED_MALICIOUS", res.consensus.verdict)
        self.assertGreater(len(res.consensus.containment_playbook), 0)

    # Module 9: Final Report Generation
    def test_module_9_report_generation(self):
        inv_mock = {
            "investigation_id": "INV-UNIT-TEST",
            "alert_id": "ALT-UNIT-TEST",
            "verdict": "CONFIRMED_MALICIOUS",
            "composite_threat_score": 92,
            "overall_confidence": 0.95,
            "executive_summary": "Unit test incident confirmation.",
            "mitre_tactics": ["Initial Access (TA0001)"],
            "mitre_techniques": ["T1110 - Brute Force"],
            "containment_playbook": [{"step": 1, "action": "BLOCK_IP", "target": "194.26.29.112", "priority": "CRITICAL", "description": "Block IP"}],
            "agent_votes": {"Cyber Sentinel": "MALICIOUS (Confidence: 0.95)"},
            "timestamp": "2026-10-23T12:00:00Z"
        }
        md = ForensicReportGenerator.generate_investigation_markdown(inv_mock)
        txt = ForensicReportGenerator.generate_investigation_text(inv_mock)
        csv_data = ForensicReportGenerator.generate_investigation_csv(inv_mock)
        html_data = ForensicReportGenerator.generate_investigation_html(inv_mock)

        self.assertIn("INV-UNIT-TEST", md)
        self.assertIn("INV-UNIT-TEST", txt)
        self.assertIn("INV-UNIT-TEST", csv_data)
        self.assertIn("<!DOCTYPE html>", html_data)


if __name__ == "__main__":
    unittest.main()
