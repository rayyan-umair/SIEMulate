"""
SIEMulate — Data Models
models.py — Pydantic schemas for all internal data structures

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Canonical data models for SIEMulate. Every layer of the
          pipeline communicates exclusively through these schemas.
          No raw dicts. No ad-hoc structures. No exceptions.
          If data moves between layers, it is one of these models.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from pydantic import BaseModel, Field, field_validator


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enumerations ──────────────────────────────────────────────────────────────

class EntityType(str, Enum):
    USER    = "user"
    HOST    = "host"
    IP      = "ip"
    SERVICE = "service"


class EventSource(str, Enum):
    LOGCLAW      = "logclaw"
    PACKETSTRIKE = "packetstrike"
    DNSTALON     = "dnstalon"
    REPLAY       = "replay"
    MANUAL       = "manual"


class EventType(str, Enum):
    AUTH      = "auth"
    PROCESS   = "process"
    NETWORK   = "network"
    CONFIG    = "config"
    DNS       = "dns"
    FILE      = "file"
    REGISTRY  = "registry"
    OTHER     = "other"


class RiskLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AlertSeverity(int, Enum):
    INFO     = 1
    LOW      = 3
    MEDIUM   = 5
    HIGH     = 7
    CRITICAL = 10


class ChainStage(str, Enum):
    RECONNAISSANCE    = "Reconnaissance"
    INITIAL_ACCESS    = "Initial Access"
    EXECUTION         = "Execution"
    PERSISTENCE       = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION   = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY         = "Discovery"
    LATERAL_MOVEMENT  = "Lateral Movement"
    COLLECTION        = "Collection"
    EXFILTRATION      = "Exfiltration"
    COMMAND_CONTROL   = "Command & Control"
    IMPACT            = "Impact"
    UNKNOWN           = "Unknown"


class ReplayStatus(str, Enum):
    IDLE      = "idle"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETE  = "complete"
    ERROR     = "error"


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

class MitreMapping(BaseModel):
    """MITRE ATT&CK technique reference attached to a rule or alert."""

    technique_id  : Optional[str] = Field(default=None, description="e.g. T1059.001")
    technique_name: Optional[str] = Field(default=None, description="e.g. PowerShell")
    tactic        : Optional[str] = Field(default=None, description="e.g. Execution")
    tactic_id     : Optional[str] = Field(default=None, description="e.g. TA0002")
    chain_stage   : ChainStage    = Field(default=ChainStage.UNKNOWN)

    @classmethod
    def from_tactic(cls, tactic: str) -> "MitreMapping":
        """Map a MITRE tactic string to a ChainStage."""
        mapping = {
            "reconnaissance"      : ChainStage.RECONNAISSANCE,
            "initial-access"      : ChainStage.INITIAL_ACCESS,
            "execution"           : ChainStage.EXECUTION,
            "persistence"         : ChainStage.PERSISTENCE,
            "privilege-escalation": ChainStage.PRIVILEGE_ESCALATION,
            "defense-evasion"     : ChainStage.DEFENSE_EVASION,
            "credential-access"   : ChainStage.CREDENTIAL_ACCESS,
            "discovery"           : ChainStage.DISCOVERY,
            "lateral-movement"    : ChainStage.LATERAL_MOVEMENT,
            "collection"          : ChainStage.COLLECTION,
            "exfiltration"        : ChainStage.EXFILTRATION,
            "command-and-control" : ChainStage.COMMAND_CONTROL,
            "impact"              : ChainStage.IMPACT,
        }
        stage = mapping.get(tactic.lower().replace(" ", "-"), ChainStage.UNKNOWN)
        return cls(tactic=tactic, chain_stage=stage)


# ── Inbound Event ─────────────────────────────────────────────────────────────

class EntityRef(BaseModel):
    """Lightweight entity reference embedded in every inbound event."""

    name  : str             = Field(..., description="Entity identifier — username, hostname, or IP")
    type  : EntityType      = Field(..., description="Entity type classification")
    host  : Optional[str]   = Field(default=None, description="Host the entity was observed on")
    domain: Optional[str]   = Field(default=None, description="Domain context if applicable")


class EventContext(BaseModel):
    """Event classification fields embedded in every inbound event."""

    type    : EventType     = Field(default=EventType.OTHER)
    action  : Optional[str] = Field(default=None, description="e.g. login, execute, connect")
    severity: int           = Field(default=0,    description="Source-assigned severity 0-10")
    outcome : Optional[str] = Field(default=None, description="success | failure | unknown")


class InboundEvent(BaseModel):
    """
    The universal inbound event schema for SIEMulate.
    Every event from LogClaw, PacketStrike, DNStalon, or the
    Replay Engine is normalised into this structure before
    being evaluated against Sigma rules.

    # NetRaptor integration hook:
    # This schema is intentionally compatible with the NetRaptor
    # universal event schema. Field names match exactly for
    # direct mapping when the shared core is built.
    """

    event_id   : str          = Field(default_factory=_new_uuid)
    timestamp  : datetime     = Field(default_factory=_now_utc)
    source     : EventSource  = Field(..., description="Which sensor produced this event")
    entity     : EntityRef    = Field(..., description="The primary entity involved")
    event      : EventContext = Field(default_factory=EventContext)
    mitre      : MitreMapping = Field(default_factory=MitreMapping)
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Original event fields preserved for Sigma matching")

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        if isinstance(v, str):
            from datetime import timezone
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        return v


# ── Sigma Rule ────────────────────────────────────────────────────────────────

class SigmaRule(BaseModel):
    """
    Parsed representation of a Sigma YAML rule.
    Populated by the Sigma engine after loading from disk.
    """

    rule_id       : str             = Field(default_factory=_new_uuid)
    title         : str             = Field(..., description="Rule title from Sigma YAML")
    description   : str             = Field(default="", description="Rule description")
    author        : Optional[str]   = Field(default=None)
    status        : str             = Field(default="experimental")
    level         : str             = Field(default="medium", description="low | medium | high | critical")
    tags          : List[str]       = Field(default_factory=list, description="Sigma tags including MITRE mappings")
    mitre         : MitreMapping    = Field(default_factory=MitreMapping)
    logsource     : Dict[str, Any]  = Field(default_factory=dict)
    detection     : Dict[str, Any]  = Field(default_factory=dict)
    condition     : str             = Field(default="", description="Sigma condition string")
    fields        : List[str]       = Field(default_factory=list)
    file_path     : Optional[str]   = Field(default=None, description="Path to the YAML file on disk")
    loaded_at     : datetime        = Field(default_factory=_now_utc)
    match_count   : int             = Field(default=0, description="Total times this rule has fired")
    enabled       : bool            = Field(default=True)

    @property
    def severity_int(self) -> int:
        mapping = {"low": 3, "medium": 5, "high": 7, "critical": 10}
        return mapping.get(self.level.lower(), 5)

    @property
    def plain_english(self) -> str:
        """Human-readable one-liner for the 5W+H WHAT field."""
        if self.description:
            return self.description.split(".")[0].strip()
        return self.title


# ── Alert ─────────────────────────────────────────────────────────────────────

class Alert(BaseModel):
    """
    A confirmed detection produced when a Sigma rule matches an event.
    One Alert is generated per rule-event match.
    Alerts feed the correlation engine which builds attack chains.
    """

    alert_id      : str             = Field(default_factory=_new_uuid)
    timestamp     : datetime        = Field(default_factory=_now_utc)
    rule          : SigmaRule       = Field(..., description="The Sigma rule that fired")
    event         : InboundEvent    = Field(..., description="The event that triggered the rule")
    severity      : AlertSeverity   = Field(..., description="Severity at time of firing")

    # ── Entity context ────────────────────────────────────────────────────────
    entity_name   : str             = Field(..., description="Primary entity name")
    entity_type   : EntityType      = Field(..., description="Primary entity type")
    entity_host   : Optional[str]   = Field(default=None)

    # ── 5W+H ──────────────────────────────────────────────────────────────────
    who           : str             = Field(..., description="WHO: entity + risk score")
    what          : str             = Field(..., description="WHAT: plain-English rule summary")
    where         : str             = Field(..., description="WHERE: host + target asset")
    when          : str             = Field(..., description="WHEN: chain start vs detection time")
    why           : str             = Field(..., description="WHY: Sigma selection logic")
    how           : str             = Field(..., description="HOW: auto-generated DuckDB SQL query")

    # ── MITRE ─────────────────────────────────────────────────────────────────
    mitre         : MitreMapping    = Field(default_factory=MitreMapping)
    chain_stage   : ChainStage      = Field(default=ChainStage.UNKNOWN)

    # ── Chain reference ───────────────────────────────────────────────────────
    chain_id      : Optional[str]   = Field(default=None, description="Attack chain ID if part of a chain")
    chain_position: Optional[int]   = Field(default=None, description="Position in the attack chain (1-indexed)")

    # ── AI enrichment ─────────────────────────────────────────────────────────
    ai_explanation: Optional[str]   = Field(default=None)

    # ── Source ────────────────────────────────────────────────────────────────
    source        : EventSource     = Field(default=EventSource.LOGCLAW)
    is_replay     : bool            = Field(default=False)


# ── Attack Chain ──────────────────────────────────────────────────────────────

class ChainLink(BaseModel):
    """A single step in an attack chain — one alert with its stage context."""

    position      : int             = Field(..., description="Step number in the chain (1-indexed)")
    alert_id      : str             = Field(...)
    timestamp     : datetime        = Field(...)
    rule_title    : str             = Field(...)
    chain_stage   : ChainStage      = Field(...)
    mitre_id      : Optional[str]   = Field(default=None)
    entity_name   : str             = Field(...)
    severity      : int             = Field(...)
    investigation_sql: str          = Field(default="", description="DuckDB SQL for this step")


class AttackChain(BaseModel):
    """
    A confirmed attack chain — two or more Sigma rules firing on the
    same entity within the correlation window.

    This is the primary output of the SIEMulate correlation engine.
    Attack chains are the evidence that an attack is in progress,
    not just a single anomalous event.
    """

    chain_id      : str             = Field(default_factory=_new_uuid)
    entity_name   : str             = Field(..., description="Entity the chain is building on")
    entity_type   : EntityType      = Field(...)
    entity_host   : Optional[str]   = Field(default=None)

    started_at    : datetime        = Field(default_factory=_now_utc, description="Timestamp of first link")
    updated_at    : datetime        = Field(default_factory=_now_utc, description="Timestamp of most recent link")
    links         : List[ChainLink] = Field(default_factory=list)

    risk_score    : int             = Field(default=0, description="Accumulated risk score 0-100")
    risk_level    : RiskLevel       = Field(default=RiskLevel.LOW)
    stages_seen   : List[ChainStage]= Field(default_factory=list, description="MITRE stages observed so far")
    is_escalated  : bool            = Field(default=False, description="True once risk crosses CRITICAL threshold")

    narrative     : str             = Field(default="", description="Auto-generated plain-English chain summary")
    ai_summary    : Optional[str]   = Field(default=None)

    @property
    def duration_minutes(self) -> float:
        delta = self.updated_at - self.started_at
        return round(delta.total_seconds() / 60, 1)

    @property
    def link_count(self) -> int:
        return len(self.links)

    @property
    def stage_progression(self) -> str:
        """One-line chain stage progression string for display."""
        return " → ".join(s.value for s in self.stages_seen)


# ── Entity Profile ────────────────────────────────────────────────────────────

class TimelineEntry(BaseModel):
    """A single entry in an entity's behavioral timeline."""

    timestamp     : datetime        = Field(default_factory=_now_utc)
    entry_type    : str             = Field(..., description="alert | chain | system")
    description   : str             = Field(...)
    alert_id      : Optional[str]   = Field(default=None)
    chain_id      : Optional[str]   = Field(default=None)
    severity      : int             = Field(default=0)
    rule_title    : Optional[str]   = Field(default=None)
    mitre_id      : Optional[str]   = Field(default=None)


class EntityProfile(BaseModel):
    """
    A tracked entity in the SIEMulate correlation engine.
    Entities accumulate risk, alerts, and chain history over time.

    # NetRaptor integration hook:
    # EntityProfile maps directly to the NetRaptor universal
    # EntityProfile schema. Field names are intentionally compatible.
    """

    entity_id     : str             = Field(default_factory=_new_uuid)
    name          : str             = Field(..., description="Entity identifier")
    type          : EntityType      = Field(...)
    host          : Optional[str]   = Field(default=None)
    domain        : Optional[str]   = Field(default=None)

    first_seen    : datetime        = Field(default_factory=_now_utc)
    last_seen     : datetime        = Field(default_factory=_now_utc)

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_score    : int             = Field(default=0, description="Current risk score 0-100")
    risk_level    : RiskLevel       = Field(default=RiskLevel.LOW)
    peak_risk     : int             = Field(default=0, description="Highest risk score ever observed")

    # ── Alert history ─────────────────────────────────────────────────────────
    total_alerts  : int             = Field(default=0)
    alert_ids     : List[str]       = Field(default_factory=list, description="IDs of all alerts on this entity")
    rules_fired   : List[str]       = Field(default_factory=list, description="Distinct rule titles that have fired")

    # ── Chain history ─────────────────────────────────────────────────────────
    active_chain_id : Optional[str] = Field(default=None, description="Currently active attack chain ID")
    chain_ids       : List[str]     = Field(default_factory=list, description="All chain IDs involving this entity")
    total_chains    : int           = Field(default=0)

    # ── MITRE ─────────────────────────────────────────────────────────────────
    techniques_seen : List[str]     = Field(default_factory=list, description="MITRE technique IDs observed")
    tactics_seen    : List[str]     = Field(default_factory=list, description="MITRE tactic names observed")

    # ── Timeline ──────────────────────────────────────────────────────────────
    timeline        : List[TimelineEntry] = Field(default_factory=list)

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 50

    @property
    def is_critical(self) -> bool:
        return self.risk_score >= 75

    @property
    def display_name(self) -> str:
        if self.host:
            return f"{self.name}@{self.host}"
        return self.name


# ── Replay Models ─────────────────────────────────────────────────────────────

class ReplayJob(BaseModel):
    """State of a replay session."""

    job_id        : str             = Field(default_factory=_new_uuid)
    file_name     : str             = Field(...)
    file_path     : str             = Field(...)
    status        : ReplayStatus    = Field(default=ReplayStatus.IDLE)
    speed         : float           = Field(default=10.0)
    total_events  : int             = Field(default=0)
    processed     : int             = Field(default=0)
    alerts_fired  : int             = Field(default=0)
    chains_formed : int             = Field(default=0)
    started_at    : Optional[datetime] = Field(default=None)
    completed_at  : Optional[datetime] = Field(default=None)
    error         : Optional[str]   = Field(default=None)

    @property
    def progress_pct(self) -> float:
        if self.total_events == 0:
            return 0.0
        return round((self.processed / self.total_events) * 100, 1)


# ── API Response Models ───────────────────────────────────────────────────────

class AlertSummary(BaseModel):
    """Lightweight alert for list endpoints."""

    alert_id    : str           = Field(...)
    timestamp   : datetime      = Field(...)
    rule_title  : str           = Field(...)
    entity_name : str           = Field(...)
    entity_host : Optional[str] = Field(default=None)
    severity    : int           = Field(...)
    chain_id    : Optional[str] = Field(default=None)
    mitre_id    : Optional[str] = Field(default=None)
    chain_stage : ChainStage    = Field(default=ChainStage.UNKNOWN)
    is_replay   : bool          = Field(default=False)


class EntitySummary(BaseModel):
    """Lightweight entity for list endpoints."""

    entity_id   : str           = Field(...)
    name        : str           = Field(...)
    type        : EntityType    = Field(...)
    host        : Optional[str] = Field(default=None)
    risk_score  : int           = Field(...)
    risk_level  : RiskLevel     = Field(...)
    total_alerts: int           = Field(...)
    total_chains: int           = Field(...)
    last_seen   : datetime      = Field(...)
    is_critical : bool          = Field(...)


class ChainSummary(BaseModel):
    """Lightweight chain for list endpoints."""

    chain_id        : str           = Field(...)
    entity_name     : str           = Field(...)
    risk_score      : int           = Field(...)
    risk_level      : RiskLevel     = Field(...)
    link_count      : int           = Field(...)
    stage_progression: str          = Field(...)
    started_at      : datetime      = Field(...)
    updated_at      : datetime      = Field(...)
    is_escalated    : bool          = Field(...)
    duration_minutes: float         = Field(...)


class HealthResponse(BaseModel):
    """API health check response."""

    status          : str   = Field(default="ok")
    app_name        : str   = Field(...)
    version         : str   = Field(...)
    rules_loaded    : int   = Field(...)
    entities_tracked: int   = Field(...)
    active_chains   : int   = Field(...)
    ai_enabled      : bool  = Field(...)
    uptime_seconds  : float = Field(...)
    replay_status   : str   = Field(default="idle")