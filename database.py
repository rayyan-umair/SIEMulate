"""
SIEMulate — Database Layer
database.py — DuckDB persistence, schema management, Parquet archiving

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : All storage operations for SIEMulate. DuckDB acts as the
          persistent intelligence store — fast enough for real-time
          alert ingestion, powerful enough for SQL JOINs between
          entities, alerts, and attack chains for investigation.
          Parquet handles long-term compressed historical archives.
          Nothing outside this file touches the database directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
import duckdb

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from models import (
    Alert,
    AlertSeverity,
    AttackChain,
    ChainLink,
    ChainStage,
    EntityProfile,
    EntityType,
    MitreMapping,
    ReplayJob,
    ReplayStatus,
    RiskLevel,
    SigmaRule,
    TimelineEntry,
)

logger = logging.getLogger(__name__)


# ── Schema Definitions ────────────────────────────────────────────────────────

_ALERTS_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        VARCHAR PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    rule_id         VARCHAR     NOT NULL,
    rule_title      VARCHAR     NOT NULL,
    rule_level      VARCHAR     NOT NULL,
    severity        INTEGER     NOT NULL,

    entity_name     VARCHAR     NOT NULL,
    entity_type     VARCHAR     NOT NULL,
    entity_host     VARCHAR,

    who             TEXT        NOT NULL,
    what            TEXT        NOT NULL,
    where_field     TEXT        NOT NULL,
    when_field      TEXT        NOT NULL,
    why             TEXT        NOT NULL,
    how             TEXT        NOT NULL,

    mitre_id        VARCHAR,
    mitre_tactic    VARCHAR,
    chain_stage     VARCHAR,
    chain_id        VARCHAR,
    chain_position  INTEGER,

    source          VARCHAR     NOT NULL,
    is_replay       BOOLEAN     DEFAULT FALSE,
    ai_explanation  TEXT,

    raw_event       JSON
);
"""

_CHAINS_DDL = """
CREATE TABLE IF NOT EXISTS chains (
    chain_id            VARCHAR PRIMARY KEY,
    entity_name         VARCHAR     NOT NULL,
    entity_type         VARCHAR     NOT NULL,
    entity_host         VARCHAR,

    started_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,

    risk_score          INTEGER     DEFAULT 0,
    risk_level          VARCHAR     NOT NULL,
    stages_seen         JSON,
    is_escalated        BOOLEAN     DEFAULT FALSE,
    link_count          INTEGER     DEFAULT 0,
    links               JSON,

    narrative           TEXT,
    ai_summary          TEXT
);
"""

_ENTITIES_DDL = """
CREATE TABLE IF NOT EXISTS entities (
    entity_id           VARCHAR PRIMARY KEY,
    name                VARCHAR     NOT NULL UNIQUE,
    type                VARCHAR     NOT NULL,
    host                VARCHAR,
    domain              VARCHAR,

    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,

    risk_score          INTEGER     DEFAULT 0,
    risk_level          VARCHAR     NOT NULL,
    peak_risk           INTEGER     DEFAULT 0,

    total_alerts        INTEGER     DEFAULT 0,
    alert_ids           JSON,
    rules_fired         JSON,

    active_chain_id     VARCHAR,
    chain_ids           JSON,
    total_chains        INTEGER     DEFAULT 0,

    techniques_seen     JSON,
    tactics_seen        JSON,
    timeline            JSON
);
"""

_RULES_DDL = """
CREATE TABLE IF NOT EXISTS rules (
    rule_id         VARCHAR PRIMARY KEY,
    title           VARCHAR     NOT NULL,
    description     TEXT,
    author          VARCHAR,
    status          VARCHAR,
    level           VARCHAR,
    tags            JSON,
    mitre_id        VARCHAR,
    mitre_tactic    VARCHAR,
    chain_stage     VARCHAR,
    logsource       JSON,
    detection       JSON,
    condition       VARCHAR,
    fields          JSON,
    file_path       VARCHAR,
    loaded_at       TIMESTAMPTZ NOT NULL,
    match_count     INTEGER     DEFAULT 0,
    enabled         BOOLEAN     DEFAULT TRUE
);
"""

_REPLAY_DDL = """
CREATE TABLE IF NOT EXISTS replay_jobs (
    job_id          VARCHAR PRIMARY KEY,
    file_name       VARCHAR     NOT NULL,
    file_path       VARCHAR     NOT NULL,
    status          VARCHAR     NOT NULL,
    speed           DOUBLE      DEFAULT 10.0,
    total_events    INTEGER     DEFAULT 0,
    processed       INTEGER     DEFAULT 0,
    alerts_fired    INTEGER     DEFAULT 0,
    chains_formed   INTEGER     DEFAULT 0,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error           TEXT
);
"""

_INDEXES_DDL = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_entity   ON alerts (entity_name);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts (rule_id);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_chain    ON alerts (chain_id);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);",
    "CREATE INDEX IF NOT EXISTS idx_chains_entity   ON chains (entity_name);",
    "CREATE INDEX IF NOT EXISTS idx_chains_risk     ON chains (risk_score);",
    "CREATE INDEX IF NOT EXISTS idx_chains_updated  ON chains (updated_at);",
    "CREATE INDEX IF NOT EXISTS idx_entities_name   ON entities (name);",
    "CREATE INDEX IF NOT EXISTS idx_entities_risk   ON entities (risk_score);",
    "CREATE INDEX IF NOT EXISTS idx_entities_type   ON entities (type);",
]


# ── Database Manager ──────────────────────────────────────────────────────────

class Database:
    """
    SIEMulate database manager.

    Wraps DuckDB for all read/write operations across five tables:
    alerts, chains, entities, rules, replay_jobs.

    One instance is created at startup and shared across the application.
    All methods are synchronous — DuckDB is not async-native.

    Usage:
        db = Database(settings)
        db.connect()
        db.insert_alert(alert)
        db.close()
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._db_path  = settings.db_path
        self._conn     : Optional[duckdb.DuckDBPyConnection] = None
        self._connected: bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        logger.info(f"Connecting to DuckDB at: {self._db_path}")
        try:
            self._conn = duckdb.connect(self._db_path)
            self._init_schema()
            self._connected = True
            logger.info("Database connected and schema verified.")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._connected = False
            logger.info("Database connection closed.")

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.execute(_ALERTS_DDL)
        self._conn.execute(_CHAINS_DDL)
        self._conn.execute(_ENTITIES_DDL)
        self._conn.execute(_RULES_DDL)
        self._conn.execute(_REPLAY_DDL)
        for idx in _INDEXES_DDL:
            self._conn.execute(idx)
        logger.debug("Schema initialised.")

    def _require_connection(self) -> None:
        if not self._connected or self._conn is None:
            raise RuntimeError(
                "Database.connect() must be called before any operations."
            )

    # ── Alert Operations ──────────────────────────────────────────────────────

    def insert_alert(self, alert: Alert) -> None:
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            INSERT OR REPLACE INTO alerts VALUES (
                ?,?,?,?,?,?,
                ?,?,?,
                ?,?,?,?,?,?,
                ?,?,?,?,?,
                ?,?,?,?
            )
        """, [
            alert.alert_id,
            alert.timestamp,
            alert.rule.rule_id,
            alert.rule.title,
            alert.rule.level,
            alert.severity.value,

            alert.entity_name,
            alert.entity_type.value,
            alert.entity_host,

            alert.who,
            alert.what,
            alert.where,
            alert.when,
            alert.why,
            alert.how,

            alert.mitre.technique_id,
            alert.mitre.tactic,
            alert.chain_stage.value,
            alert.chain_id,
            alert.chain_position,

            alert.source.value,
            alert.is_replay,
            alert.ai_explanation,

            json.dumps(alert.event.raw_payload),
        ])

    def get_alerts(
        self,
        entity_name : Optional[str]   = None,
        since       : Optional[datetime] = None,
        chain_id    : Optional[str]   = None,
        min_severity: int              = 0,
        is_replay   : Optional[bool]  = None,
        limit       : int              = 200,
    ) -> List[dict]:
        self._require_connection()
        assert self._conn is not None

        query  = "SELECT * FROM alerts WHERE 1=1"
        params : list = []

        if entity_name:
            query += " AND entity_name = ?"
            params.append(entity_name)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        if chain_id:
            query += " AND chain_id = ?"
            params.append(chain_id)
        if min_severity:
            query += " AND severity >= ?"
            params.append(min_severity)
        if is_replay is not None:
            query += " AND is_replay = ?"
            params.append(is_replay)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return (
            self._conn.execute(query, params)
            .fetchdf()
            .to_dict(orient="records")
        )

    def get_alert_count_by_rule(self) -> dict:
        self._require_connection()
        assert self._conn is not None
        rows = self._conn.execute("""
            SELECT rule_title, COUNT(*) as count
            FROM alerts
            GROUP BY rule_title
            ORDER BY count DESC
            LIMIT 20
        """).fetchall()
        return {row[0]: row[1] for row in rows}

    # ── Chain Operations ──────────────────────────────────────────────────────

    def upsert_chain(self, chain: AttackChain) -> None:
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            INSERT OR REPLACE INTO chains VALUES (
                ?,?,?,?,
                ?,?,
                ?,?,?,?,?,?,
                ?,?
            )
        """, [
            chain.chain_id,
            chain.entity_name,
            chain.entity_type.value,
            chain.entity_host,

            chain.started_at,
            chain.updated_at,

            chain.risk_score,
            chain.risk_level.value,
            json.dumps([s.value for s in chain.stages_seen]),
            chain.is_escalated,
            chain.link_count,
            json.dumps([lnk.model_dump(mode="json") for lnk in chain.links]),

            chain.narrative,
            chain.ai_summary,
        ])

    def get_chains(
        self,
        entity_name  : Optional[str]  = None,
        is_escalated : Optional[bool] = None,
        min_risk     : int             = 0,
        limit        : int             = 100,
    ) -> List[dict]:
        self._require_connection()
        assert self._conn is not None

        query  = "SELECT * FROM chains WHERE 1=1"
        params : list = []

        if entity_name:
            query += " AND entity_name = ?"
            params.append(entity_name)
        if is_escalated is not None:
            query += " AND is_escalated = ?"
            params.append(is_escalated)
        if min_risk:
            query += " AND risk_score >= ?"
            params.append(min_risk)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        return (
            self._conn.execute(query, params)
            .fetchdf()
            .to_dict(orient="records")
        )

    def get_chain(self, chain_id: str) -> Optional[dict]:
        self._require_connection()
        assert self._conn is not None
        rows = (
            self._conn
            .execute("SELECT * FROM chains WHERE chain_id = ?", [chain_id])
            .fetchdf()
            .to_dict(orient="records")
        )
        return rows[0] if rows else None

    # ── Entity Operations ─────────────────────────────────────────────────────

    def upsert_entity(self, entity: EntityProfile) -> None:
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            INSERT OR REPLACE INTO entities VALUES (
                ?,?,?,?,?,
                ?,?,
                ?,?,?,
                ?,?,?,
                ?,?,?,
                ?,?,?
            )
        """, [
            entity.entity_id,
            entity.name,
            entity.type.value,
            entity.host,
            entity.domain,

            entity.first_seen,
            entity.last_seen,

            entity.risk_score,
            entity.risk_level.value,
            entity.peak_risk,

            entity.total_alerts,
            json.dumps(entity.alert_ids),
            json.dumps(entity.rules_fired),

            entity.active_chain_id,
            json.dumps(entity.chain_ids),
            entity.total_chains,

            json.dumps(entity.techniques_seen),
            json.dumps(entity.tactics_seen),
            json.dumps([t.model_dump(mode="json") for t in entity.timeline]),
        ])

    def get_entity(self, name: str) -> Optional[dict]:
        self._require_connection()
        assert self._conn is not None
        rows = (
            self._conn
            .execute("SELECT * FROM entities WHERE name = ?", [name])
            .fetchdf()
            .to_dict(orient="records")
        )
        return rows[0] if rows else None

    def get_all_entities(
        self,
        min_risk: int = 0,
        limit   : int = 500,
    ) -> List[dict]:
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("""
                SELECT * FROM entities
                WHERE risk_score >= ?
                ORDER BY risk_score DESC
                LIMIT ?
            """, [min_risk, limit])
            .fetchdf()
            .to_dict(orient="records")
        )

    def get_critical_entities(self, threshold: int = 75) -> List[dict]:
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("""
                SELECT * FROM entities
                WHERE risk_score >= ?
                ORDER BY risk_score DESC
            """, [threshold])
            .fetchdf()
            .to_dict(orient="records")
        )

    # ── Rule Operations ───────────────────────────────────────────────────────

    def upsert_rule(self, rule: SigmaRule) -> None:
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            INSERT OR REPLACE INTO rules VALUES (
                ?,?,?,?,?,?,
                ?,?,?,?,
                ?,?,?,?,?,
                ?,?,?
            )
        """, [
            rule.rule_id,
            rule.title,
            rule.description,
            rule.author,
            rule.status,
            rule.level,
            json.dumps(rule.tags),
            rule.mitre.technique_id,
            rule.mitre.tactic,
            rule.mitre.chain_stage.value,
            json.dumps(rule.logsource),
            json.dumps(rule.detection),
            rule.condition,
            json.dumps(rule.fields),
            rule.file_path,
            rule.loaded_at,
            rule.match_count,
            rule.enabled,
        ])

    def get_rules(self, enabled_only: bool = True) -> List[dict]:
        self._require_connection()
        assert self._conn is not None
        query = "SELECT * FROM rules"
        if enabled_only:
            query += " WHERE enabled = TRUE"
        query += " ORDER BY title ASC"
        return (
            self._conn.execute(query)
            .fetchdf()
            .to_dict(orient="records")
        )

    def increment_rule_match(self, rule_id: str) -> None:
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            UPDATE rules SET match_count = match_count + 1
            WHERE rule_id = ?
        """, [rule_id])

    # ── Replay Job Operations ─────────────────────────────────────────────────

    def upsert_replay_job(self, job: ReplayJob) -> None:
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            INSERT OR REPLACE INTO replay_jobs VALUES (
                ?,?,?,?,?,?,?,?,?,?,?,?
            )
        """, [
            job.job_id,
            job.file_name,
            job.file_path,
            job.status.value,
            job.speed,
            job.total_events,
            job.processed,
            job.alerts_fired,
            job.chains_formed,
            job.started_at,
            job.completed_at,
            job.error,
        ])

    def get_replay_jobs(self, limit: int = 20) -> List[dict]:
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("""
                SELECT * FROM replay_jobs
                ORDER BY started_at DESC NULLS LAST
                LIMIT ?
            """, [limit])
            .fetchdf()
            .to_dict(orient="records")
        )

    # ── Investigation Query ───────────────────────────────────────────────────

    def investigation_query(self, sql: str) -> List[dict]:
        """
        Execute a raw SQL SELECT for analyst investigation.
        Auto-generated HOW queries from the 5W+H engine use this.
        SELECT only — mutations are blocked.
        """
        self._require_connection()
        assert self._conn is not None
        if not sql.strip().upper().startswith("SELECT"):
            raise ValueError("investigation_query only permits SELECT statements.")
        return (
            self._conn.execute(sql)
            .fetchdf()
            .to_dict(orient="records")
        )

    def generate_investigation_sql(
        self,
        entity_name : str,
        rule_title  : str,
        since       : Optional[datetime] = None,
    ) -> str:
        """
        Auto-generate the DuckDB SQL investigation query for the
        5W+H HOW field. Pulls all alerts for this entity and rule
        within the correlation window.
        """
        since_clause = ""
        if since:
            since_clause = f" AND timestamp >= '{since.isoformat()}'"

        return (
            f"SELECT alert_id, timestamp, rule_title, entity_name, "
            f"entity_host, severity, what, why, chain_id "
            f"FROM alerts "
            f"WHERE entity_name = '{entity_name}'"
            f"{since_clause} "
            f"ORDER BY timestamp ASC;"
        )

    # ── Parquet Archiving ─────────────────────────────────────────────────────

    def archive_old_alerts(self) -> int:
        self._require_connection()
        assert self._conn is not None

        cutoff       = datetime.now(timezone.utc) - timedelta(days=self._settings.retention_days)
        parquet_path = self._settings.parquet_path
        archive_file = parquet_path / f"alerts_{cutoff.strftime('%Y%m%d_%H%M%S')}.parquet"

        count = self._conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp < ?", [cutoff]
        ).fetchone()[0]

        if count == 0:
            return 0

        self._conn.execute(f"""
            COPY (SELECT * FROM alerts WHERE timestamp < ?)
            TO '{archive_file}' (FORMAT PARQUET)
        """, [cutoff])
        self._conn.execute("DELETE FROM alerts WHERE timestamp < ?", [cutoff])

        logger.info(f"Archived {count} alerts to {archive_file}")
        return count

    def archive_old_chains(self) -> int:
        self._require_connection()
        assert self._conn is not None

        cutoff       = datetime.now(timezone.utc) - timedelta(days=self._settings.retention_days)
        parquet_path = self._settings.parquet_path
        archive_file = parquet_path / f"chains_{cutoff.strftime('%Y%m%d_%H%M%S')}.parquet"

        count = self._conn.execute(
            "SELECT COUNT(*) FROM chains WHERE updated_at < ?", [cutoff]
        ).fetchone()[0]

        if count == 0:
            return 0

        self._conn.execute(f"""
            COPY (SELECT * FROM chains WHERE updated_at < ?)
            TO '{archive_file}' (FORMAT PARQUET)
        """, [cutoff])
        self._conn.execute("DELETE FROM chains WHERE updated_at < ?", [cutoff])

        logger.info(f"Archived {count} chains to {archive_file}")
        return count

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        self._require_connection()
        assert self._conn is not None

        return {
            "total_alerts"    : self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "total_chains"    : self._conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0],
            "total_entities"  : self._conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            "total_rules"     : self._conn.execute("SELECT COUNT(*) FROM rules WHERE enabled = TRUE").fetchone()[0],
            "critical_entities": self._conn.execute(
                f"SELECT COUNT(*) FROM entities WHERE risk_score >= {self._settings.risk_threshold_critical}"
            ).fetchone()[0],
            "escalated_chains": self._conn.execute(
                "SELECT COUNT(*) FROM chains WHERE is_escalated = TRUE"
            ).fetchone()[0],
        }