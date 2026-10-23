"""
MITRE ATT&CK Taxonomy Mapping Tool.
Maps detected security alerts to enterprise adversary tactics, techniques, and procedures (TTPs).
"""

from typing import Dict, Any, List

MITRE_DATABASE = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access (TA0006)",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "subtechniques": ["T1110.001 (Password Guessing)", "T1110.003 (Password Spraying)"]
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access (TA0001)",
        "description": "Adversaries may send phishing messages to gain access to victim systems via malicious links or attachments.",
        "subtechniques": ["T1566.001 (Spearphishing Attachment)", "T1566.002 (Spearphishing Link)"]
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence (TA0005)",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Persistence.",
        "subtechniques": ["T1078.004 (Cloud Accounts)", "T1078.001 (Default Accounts)"]
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access (TA0001)",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or application such as SQL injection.",
        "subtechniques": []
    },
    "T1657": {
        "id": "T1657",
        "name": "Financial Theft",
        "tactic": "Impact (TA0040)",
        "description": "Adversaries may conduct unauthorized wire transfers, crypto drainage, or illicit financial transactions to siphon funds.",
        "subtechniques": []
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence (TA0003)",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems, such as modifying credentials or permissions.",
        "subtechniques": []
    }
}

class MitreMapper:
    @staticmethod
    def map_indicators(text_or_reasons: List[str]) -> Dict[str, Any]:
        """Maps finding descriptions to corresponding MITRE ATT&CK entries."""
        matched_techniques = []
        matched_tactics = set()

        combined_text = " ".join(text_or_reasons).lower()

        if "brute" in combined_text or "failed" in combined_text or "password" in combined_text:
            matched_techniques.append(MITRE_DATABASE["T1110"])
            matched_tactics.add("Credential Access (TA0006)")

        if "phish" in combined_text or "email" in combined_text or "spoof" in combined_text or "urgent" in combined_text:
            matched_techniques.append(MITRE_DATABASE["T1566"])
            matched_tactics.add("Initial Access (TA0001)")

        if "sql" in combined_text or "injection" in combined_text or "traversal" in combined_text:
            matched_techniques.append(MITRE_DATABASE["T1190"])
            matched_tactics.add("Initial Access (TA0001)")

        if "outlier" in combined_text or "spending" in combined_text or "wire" in combined_text or "crypto" in combined_text or "transfer" in combined_text:
            matched_techniques.append(MITRE_DATABASE["T1657"])
            matched_tactics.add("Impact (TA0040)")

        if "bypass" in combined_text or "compromise" in combined_text or "privilege" in combined_text:
            matched_techniques.append(MITRE_DATABASE["T1078"])
            matched_tactics.add("Defense Evasion (TA0005)")

        return {
            "tactics": list(matched_tactics),
            "techniques": [t["name"] + f" ({t['id']})" for t in matched_techniques],
            "details": matched_techniques
        }
