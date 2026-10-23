"""
Persistent Database and Data Access Layer for Autonomous SOC Framework.
Provides SQLite-backed persistence with WAL mode and indexing for:
- Telemetry Events (Mutual exclusivity across domains, stable IDs, deduplication)
- Tier-1 Alerts (Flagged anomalies, calibrated probabilities, triage priorities)
- Multi-Agent Investigations (Findings, consensus, playbooks, MITRE ATT&CK)
- Multi-Vector Scenarios (Predefined benchmarks & dynamically discovered attack chains)
- Ingestion Run Audits (Discovered, ingested, skipped, failed counts)
"""

import os
import json
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "soc_telemetry.db")

class SOCDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self):
        """Initializes database schema with appropriate tables and indexes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Telemetry Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_dataset TEXT NOT NULL,
                user_identifier TEXT,
                source_ip TEXT,
                amount REAL,
                raw_json TEXT NOT NULL,
                is_simulation INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """)

            # 2. Tier-1 Alerts Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                calibrated_probability REAL NOT NULL,
                triage_priority TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                is_uncertain INTEGER DEFAULT 0,
                investigation_status TEXT DEFAULT 'PENDING',
                timestamp TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE
            )
            """)

            # 3. Investigations Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                composite_threat_score INTEGER NOT NULL,
                overall_confidence REAL NOT NULL,
                executive_summary TEXT NOT NULL,
                mitre_tactics_json TEXT NOT NULL,
                mitre_techniques_json TEXT NOT NULL,
                playbook_steps_json TEXT NOT NULL,
                agent_votes_json TEXT NOT NULL,
                full_state_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts (alert_id) ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE
            )
            """)

            # 4. Multi-Vector Scenarios Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scenarios (
                scenario_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                domain_count INTEGER NOT NULL,
                event_chain_json TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                correlation_rule TEXT NOT NULL,
                is_predefined INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """)

            # 5. Ingestion Runs Audit Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ingestion_runs (
                run_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_name TEXT NOT NULL,
                records_discovered INTEGER NOT NULL,
                records_ingested INTEGER NOT NULL,
                records_skipped INTEGER NOT NULL,
                alerts_generated INTEGER NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT
            )
            """)

            # Performance Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_identifier)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_sim ON events(is_simulation)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_priority ON alerts(triage_priority)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(investigation_status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain)")

            conn.commit()

    # ==========================================================================
    # EVENT CRUD OPERATIONS
    # ==========================================================================
    def insert_event(self, event_data: Dict[str, Any], is_simulation: bool = False) -> bool:
        """Idempotent insert of a single normalized telemetry event."""
        with self.get_connection() as conn:
            return self._insert_event_conn(conn, event_data, is_simulation)

    def _insert_event_conn(self, conn: sqlite3.Connection, event_data: Dict[str, Any], is_simulation: bool = False) -> bool:
        event_id = event_data.get("event_id")
        if not event_id:
            # Deterministic hash ID
            h = hashlib.sha256(json.dumps(event_data, sort_keys=True).encode()).hexdigest()[:12].upper()
            event_id = f"EVT-{h}"
            event_data["event_id"] = event_id

        timestamp = event_data.get("timestamp", datetime.utcnow().isoformat() + "Z")
        domain = event_data.get("domain", "UNKNOWN")
        event_type = event_data.get("event_type", "GENERAL_TELEMETRY")
        source_dataset = event_data.get("source_dataset", "MANUAL")
        user = event_data.get("user") or event_data.get("user_name")
        ip = event_data.get("source_ip") or event_data.get("ip_address")
        amount = event_data.get("amount")
        amount_val = float(amount) if amount is not None else None

        try:
            cursor = conn.execute("""
            INSERT OR IGNORE INTO events (
                event_id, timestamp, domain, event_type, source_dataset,
                user_identifier, source_ip, amount, raw_json, is_simulation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, timestamp, domain, event_type, source_dataset,
                user, ip, amount_val, json.dumps(event_data),
                1 if is_simulation else 0, datetime.utcnow().isoformat() + "Z"
            ))
            return cursor.rowcount > 0
        except Exception:
            return False

    def insert_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Inserts a Tier-1 alert into the alerts table."""
        with self.get_connection() as conn:
            try:
                conn.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, event_id, domain, anomaly_score, calibrated_probability,
                    triage_priority, reasons_json, is_uncertain, investigation_status, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_data["alert_id"],
                    alert_data["event_id"],
                    alert_data["domain"],
                    float(alert_data["anomaly_score"]),
                    float(alert_data.get("calibrated_probability", alert_data["anomaly_score"])),
                    alert_data["triage_priority"],
                    json.dumps(alert_data.get("reasons", [])),
                    1 if alert_data.get("is_uncertain", False) else 0,
                    alert_data.get("investigation_status", "PENDING"),
                    alert_data.get("timestamp", datetime.utcnow().isoformat() + "Z")
                ))
                conn.commit()
                return True
            except Exception:
                return False

    def insert_investigation(self, inv_data: Dict[str, Any]) -> bool:
        """Inserts or updates an investigation record."""
        with self.get_connection() as conn:
            try:
                conn.execute("""
                INSERT OR REPLACE INTO investigations (
                    investigation_id, alert_id, event_id, verdict, composite_threat_score,
                    overall_confidence, executive_summary, mitre_tactics_json, mitre_techniques_json,
                    playbook_steps_json, agent_votes_json, full_state_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inv_data["investigation_id"],
                    inv_data["alert_id"],
                    inv_data["event_id"],
                    inv_data["verdict"],
                    int(inv_data["composite_threat_score"]),
                    float(inv_data["overall_confidence"]),
                    inv_data["executive_summary"],
                    json.dumps(inv_data.get("mitre_tactics", [])),
                    json.dumps(inv_data.get("mitre_techniques", [])),
                    json.dumps(inv_data.get("containment_playbook", [])),
                    json.dumps(inv_data.get("agent_votes", {})),
                    json.dumps(inv_data.get("full_state", {})),
                    inv_data.get("timestamp", datetime.utcnow().isoformat() + "Z")
                ))
                # Update alert status
                conn.execute("UPDATE alerts SET investigation_status = 'INVESTIGATED' WHERE alert_id = ?", (inv_data["alert_id"],))
                conn.commit()
                return True
            except Exception:
                return False

    def insert_scenario(self, scenario_data: Dict[str, Any]) -> bool:
        """Inserts a coordinated attack scenario."""
        with self.get_connection() as conn:
            try:
                conn.execute("""
                INSERT OR REPLACE INTO scenarios (
                    scenario_id, title, description, domain_count, event_chain_json,
                    verdict, risk_score, correlation_rule, is_predefined, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scenario_data["scenario_id"],
                    scenario_data["title"],
                    scenario_data["description"],
                    int(scenario_data.get("domain_count", len(scenario_data.get("event_chain", [])))),
                    json.dumps(scenario_data.get("event_chain", [])),
                    scenario_data.get("verdict", "CONFIRMED_MALICIOUS"),
                    int(scenario_data.get("risk_score", 85)),
                    scenario_data.get("correlation_rule", "MULTI_VECTOR_CROSS_CORRELATION"),
                    1 if scenario_data.get("is_predefined", False) else 0,
                    datetime.utcnow().isoformat() + "Z"
                ))
                conn.commit()
                return True
            except Exception:
                return False

    # ==========================================================================
    # AGGREGATE SUMMARY & STATISTICS (CONSISTENT SOURCE OF TRUTH)
    # ==========================================================================
    def get_soc_statistics(self, exclude_simulations: bool = True) -> Dict[str, Any]:
        """Returns single consistent source-of-truth statistics across the entire database."""
        sim_clause = "WHERE is_simulation = 0" if exclude_simulations else ""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Event Counts
            cursor.execute(f"SELECT COUNT(*) as total FROM events {sim_clause}")
            total_events = cursor.fetchone()["total"]

            cursor.execute(f"SELECT domain, COUNT(*) as cnt FROM events {sim_clause} GROUP BY domain")
            domain_counts = {row["domain"]: row["cnt"] for row in cursor.fetchall()}

            # Alert Counts
            alert_filter = "WHERE e.is_simulation = 0" if exclude_simulations else ""
            cursor.execute(f"""
            SELECT COUNT(*) as total FROM alerts a
            JOIN events e ON a.event_id = e.event_id
            {alert_filter}
            """)
            total_alerts = cursor.fetchone()["total"]

            cursor.execute(f"""
            SELECT a.triage_priority, COUNT(*) as cnt FROM alerts a
            JOIN events e ON a.event_id = e.event_id
            {alert_filter}
            GROUP BY a.triage_priority
            """)
            priority_counts = {row["triage_priority"]: row["cnt"] for row in cursor.fetchall()}

            # Investigation Counts
            cursor.execute(f"""
            SELECT COUNT(*) as total FROM investigations i
            JOIN events e ON i.event_id = e.event_id
            {alert_filter}
            """)
            total_investigations = cursor.fetchone()["total"]

            # Scenario Counts
            cursor.execute("SELECT COUNT(*) as total FROM scenarios")
            total_scenarios = cursor.fetchone()["total"]

            # Simulation Event Count
            cursor.execute("SELECT COUNT(*) as total FROM events WHERE is_simulation = 1")
            sim_count = cursor.fetchone()["total"]

            # Benign filtered count
            benign_events = total_events - total_alerts

            return {
                "total_events": total_events,
                "financial_events": domain_counts.get("FINANCIAL", 0),
                "cyber_events": domain_counts.get("CYBER_LOG", 0),
                "email_events": domain_counts.get("EMAIL", 0),
                "total_alerts": total_alerts,
                "critical_alerts": priority_counts.get("CRITICAL", 0),
                "high_alerts": priority_counts.get("HIGH", 0),
                "medium_alerts": priority_counts.get("MEDIUM", 0),
                "low_alerts": priority_counts.get("LOW", 0),
                "benign_filtered_events": max(benign_events, 0),
                "noise_reduction_pct": round((benign_events / total_events * 100), 2) if total_events > 0 else 0.0,
                "total_investigations": total_investigations,
                "total_scenarios": total_scenarios,
                "simulated_events_count": sim_count
            }

    # ==========================================================================
    # PAGINATED QUERIES
    # ==========================================================================
    def get_events_paginated(
        self,
        domain: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 25,
        offset: int = 0,
        exclude_simulations: bool = True
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated, filtered telemetry events and total matching count."""
        conditions = []
        params = []

        if exclude_simulations:
            conditions.append("e.is_simulation = 0")
        if domain:
            dom_upper = str(domain).strip().upper()
            if "FINANCIAL" in dom_upper or "TRANSACTION" in dom_upper:
                conditions.append("e.domain = 'FINANCIAL'")
            elif "CYBER" in dom_upper or "AUTH" in dom_upper or "LOG" in dom_upper or "NETWORK" in dom_upper or "SQL" in dom_upper:
                conditions.append("e.domain = 'CYBER_LOG'")
            elif "EMAIL" in dom_upper or "PHISH" in dom_upper or "SPAM" in dom_upper:
                conditions.append("e.domain = 'EMAIL'")
            elif dom_upper not in ["ALL", "ALL DOMAINS", "ALL_DOMAINS"]:
                conditions.append("e.domain = ?")
                params.append(domain)
        if search_query:
            conditions.append("(e.event_id LIKE ? OR e.user_identifier LIKE ? OR e.source_ip LIKE ? OR e.raw_json LIKE ?)")
            q = f"%{search_query.strip()}%"
            params.extend([q, q, q, q])

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) as total FROM events e {where_clause}", params)
            total_count = cursor.fetchone()["total"]

            cursor.execute(f"""
            SELECT e.*, a.alert_id, a.anomaly_score, a.triage_priority, a.is_uncertain, a.investigation_status
            FROM events e
            LEFT JOIN alerts a ON e.event_id = a.event_id
            {where_clause}
            ORDER BY e.timestamp DESC
            LIMIT ? OFFSET ?
            """, params + [limit, offset])

            rows = [dict(row) for row in cursor.fetchall()]
            for r in rows:
                try:
                    r["raw_json"] = json.loads(r["raw_json"])
                except Exception:
                    pass
            return rows, total_count

    def get_alerts_paginated(
        self,
        domain: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated alerts for the multi-agent war room triage queue."""
        conditions = ["e.is_simulation = 0"]
        params = []

        if domain:
            dom_upper = str(domain).strip().upper()
            if "FINANCIAL" in dom_upper or "TRANSACTION" in dom_upper:
                conditions.append("a.domain = 'FINANCIAL'")
            elif "CYBER" in dom_upper or "AUTH" in dom_upper or "LOG" in dom_upper or "NETWORK" in dom_upper or "SQL" in dom_upper:
                conditions.append("a.domain = 'CYBER_LOG'")
            elif "EMAIL" in dom_upper or "PHISH" in dom_upper or "SPAM" in dom_upper:
                conditions.append("a.domain = 'EMAIL'")
            elif dom_upper not in ["ALL", "ALL DOMAINS", "ALL_DOMAINS"]:
                conditions.append("a.domain = ?")
                params.append(domain)
        if priority and priority != "ALL PRIORITIES":
            conditions.append("a.triage_priority = ?")
            params.append(priority)
        if status and status != "ALL STATUS":
            conditions.append("a.investigation_status = ?")
            params.append(status)

        where_clause = "WHERE " + " AND ".join(conditions)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
            SELECT COUNT(*) as total FROM alerts a
            JOIN events e ON a.event_id = e.event_id
            {where_clause}
            """, params)
            total_count = cursor.fetchone()["total"]

            cursor.execute(f"""
            SELECT a.*, e.raw_json, e.user_identifier, e.source_ip, e.amount, e.source_dataset
            FROM alerts a
            JOIN events e ON a.event_id = e.event_id
            {where_clause}
            ORDER BY a.anomaly_score DESC, a.timestamp DESC
            LIMIT ? OFFSET ?
            """, params + [limit, offset])

            rows = [dict(row) for row in cursor.fetchall()]
            for r in rows:
                try:
                    r["reasons"] = json.loads(r["reasons_json"])
                    r["raw_event"] = json.loads(r["raw_json"])
                except Exception:
                    r["reasons"] = []
                    r["raw_event"] = {}
            return rows, total_count

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetches a single alert with its full raw event data."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT a.*, e.raw_json
            FROM alerts a
            JOIN events e ON a.event_id = e.event_id
            WHERE a.alert_id = ?
            """, (alert_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            try:
                data["reasons"] = json.loads(data["reasons_json"])
                data["raw_event"] = json.loads(data["raw_json"])
            except Exception:
                data["reasons"] = []
                data["raw_event"] = {}
            return data

    def get_scenarios(self) -> List[Dict[str, Any]]:
        """Returns all registered attack scenarios (predefined + dynamically discovered)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scenarios ORDER BY is_predefined DESC, risk_score DESC")
            rows = [dict(row) for row in cursor.fetchall()]
            for r in rows:
                try:
                    r["event_chain"] = json.loads(r["event_chain_json"])
                except Exception:
                    r["event_chain"] = []
            return rows

    def reset_simulations(self) -> int:
        """Purges only simulated test events without affecting real telemetry."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events WHERE is_simulation = 1")
            deleted = cursor.rowcount
            conn.commit()
            return deleted
