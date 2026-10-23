"""
Automated Incident Response Playbook Tool.
Generates deterministic, executable mitigation commands and containment playbooks
for cybersecurity operations and financial fraud response.
"""

from typing import Dict, Any, List

class PlaybookGenerator:
    @staticmethod
    def create_containment_plan(
        threat_type: str,
        target_entities: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Synthesizes an orchestrated multi-action containment playbook.
        """
        playbook = []
        step = 1

        ip = target_entities.get("ip")
        user = target_entities.get("user")
        account_id = target_entities.get("account_id")
        tx_id = target_entities.get("tx_id")
        domain = target_entities.get("domain")

        # 1. Network / IP Level Containment
        if ip and ip not in ["127.0.0.1", "192.168.1.1"]:
            playbook.append({
                "step": step,
                "action": "BLOCK_IP_PERIMETER",
                "priority": "CRITICAL",
                "target": ip,
                "technical_command": f"iptables -A INPUT -s {ip} -j DROP; aws ec2 create-network-acl-entry --cidr-block {ip}/32 --rule-action deny",
                "description": f"Drop all incoming and egress traffic from adversary source IP {ip} across edge firewalls."
            })
            step += 1

        # 2. Identity / Session Revocation
        if user:
            playbook.append({
                "step": step,
                "action": "REVOKE_USER_TOKENS",
                "priority": "HIGH",
                "target": user,
                "technical_command": f"redis-cli DEL 'session:{user}:*'; okta-cli users revoke-tokens --username {user}",
                "description": f"Invalidate active OAuth2/JWT refresh tokens for compromised user account '{user}' and enforce password reset."
            })
            step += 1

        # 3. Financial Transaction Freeze / Rollback
        if tx_id or account_id:
            playbook.append({
                "step": step,
                "action": "FREEZE_BANKING_ACCOUNT",
                "priority": "CRITICAL",
                "target": f"Account: {account_id} | Txn: {tx_id}",
                "technical_command": f"POST /core-banking/v1/accounts/{account_id}/holds?tx_id={tx_id}&reason=FRAUD_SUSPECTED",
                "description": f"Place an immediate 48-hour administrative freeze on account {account_id} and halt pending wire release for {tx_id}."
            })
            step += 1

        # 4. Email / Domain Perimeter Blacklist
        if domain:
            playbook.append({
                "step": step,
                "action": "QUARANTINE_EMAIL_DOMAIN",
                "priority": "HIGH",
                "target": domain,
                "technical_command": f"powershell.exe -Command \"Set-TenantAllowBlockListItems -ListType Url -Entry '{domain}' -Action Block\"",
                "description": f"Purge all unread emails containing '{domain}' across all corporate mailboxes and blacklist at secure email gateway."
            })
            step += 1

        # 5. SIEM / SOC Notification
        playbook.append({
            "step": step,
            "action": "ESCALATE_TO_L3_SOC",
            "priority": "MEDIUM",
            "target": "SOC Incident Response PagerDuty",
            "technical_command": "POST /api/v1/incidents/pagerduty-alert",
            "description": "Trigger PagerDuty incident for on-call Principal Security Engineer with compiled multi-agent forensic dossier."
        })

        return playbook
