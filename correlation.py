"""
SIEMulate - Correlation Engine
correlation.py - Entity state tracking, attack chain detection,
                 risk scoring, escalation narratives, 5W+H generation

Author  : Rayyan Umair
Date    : 13 May, 2026
Purpose : The judgment layer of SIEMulate. Receives Alert objects from
          the detection pipeline and determines whether they form part
          of a larger attack chain. Maintains live entity profiles,
          accumulates risk scores, detects chain escalations, and
          generates the full 5W+H investigation narrative for every
          alert - including the auto-generated DuckDB SQL HOW query.
          No Sigma logic lives here. No storage logic lives here.
          This layer only correlates, scores, and narrates.

          # NetRaptor integration hook:
          # When the shared core is built, replace the in-memory
          # entity registry with the NetRaptor entity engine.
          # The correlation logic and chain detection remain intact.

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from database import Database
from models import (
    Alert,
    AlertSeverity,
    AttackChain,
    ChainLink,
    ChainStage,
    EntityProfile,
    EntityType,
    InboundEvent,
    MitreMapping,
    RiskLevel,
    SigmaRule,
    TimelineEntry,
)

logger = logging.getLogger(__name__)


# ── Risk Constants ────────────────────────────────────────────────────────────

_RISK_BY_LEVEL: Dict[str, int] = {
    "informational": 2,
    "low"          : 5,
    "medium"       : 10,
    "high"         : 20,
    "critical"     : 35,
}

_RISK_CHAIN_BONUS    = 15   # Extra risk when a chain escalates
_RISK_MAX            = 100
_RISK_MIN            = 0


# ── Risk Level Classifier ─────────────────────────────────────────────────────

def _classify_risk(score: int, settings: Settings) -> RiskLevel:
    if score >= settings.risk_threshold_critical:
        return RiskLevel.CRITICAL
    if score >= settings.risk_threshold_high:
        return RiskLevel.HIGH
    if score >= settings.risk_threshold_medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ── Chain Narrative Builder ───────────────────────────────────────────────────

def _build_chain_narrative(chain: AttackChain) -> str:
    """
    Generate a plain-English narrative summarising the attack chain.
    Used in the chain record and the 5W+H WHAT field.
    """
    if not chain.links:
        return ""

    entity   = chain.entity_name
    host     = f" on {chain.entity_host}" if chain.entity_host else ""
    duration = chain.duration_minutes
    stages   = chain.stage_progression or "Unknown progression"
    count    = chain.link_count

    lines = [
        f"Attack chain detected on {entity}{host}.",
        f"{count} distinct rule{'s' if count != 1 else ''} fired "
        f"over {duration:.1f} minutes.",
        f"Observed progression: {stages}.",
    ]

    if chain.is_escalated:
        lines.append(
            f"Entity risk score reached {chain.risk_score}/100 - "
            f"CRITICAL escalation triggered."
        )

    # Add each chain link as a numbered step
    lines.append("")
    for link in chain.links:
        ts    = link.timestamp.strftime("%H:%M:%S UTC")
        mitre = f" [{link.mitre_id}]" if link.mitre_id else ""
        lines.append(
            f"  {link.position}. {ts} - {link.chain_stage.value}{mitre}: "
            f"{link.rule_title}"
        )

    return "\n".join(lines)


# ── 5W+H Builder ─────────────────────────────────────────────────────────────

def _build_fivewh(
    rule    : SigmaRule,
    event   : InboundEvent,
    entity  : EntityProfile,
    chain   : Optional[AttackChain],
    db      : Database,
    settings: Settings,
) -> Tuple[str, str, str, str, str, str]:
    """
    Build the six 5W+H fields for an Alert.
    Returns: (who, what, where, when, why, how)
    """

    # ── WHO ───────────────────────────────────────────────────────────────────
    host_part  = f"@{entity.host}" if entity.host else ""
    chain_part = f" | Chain: {chain.link_count} steps" if chain else ""
    who = (
        f"{entity.display_name} "
        f"[{entity.type.value.upper()}] "
        f"Risk {entity.risk_score}/100 ({entity.risk_level.value})"
        f"{chain_part}"
    )

    # ── WHAT ──────────────────────────────────────────────────────────────────
    mitre_part = ""
    if rule.mitre.technique_id:
        mitre_part = f" [{rule.mitre.technique_id}]"
    if rule.mitre.tactic:
        mitre_part += f" - {rule.mitre.tactic}"

    what = (
        f"{rule.plain_english}{mitre_part}. "
        f"Rule: '{rule.title}' (level: {rule.level}). "
        f"Source: {event.source.value}."
    )

    # ── WHERE ─────────────────────────────────────────────────────────────────
    host   = event.entity.host or "unknown host"
    domain = f"\\{event.entity.domain}" if event.entity.domain else ""
    where  = f"{domain}{host}"

    target = event.raw_payload.get("TargetHostName") or \
             event.raw_payload.get("target_host") or \
             event.raw_payload.get("destination")
    if target:
        where += f" → {target}"

    # ── WHEN ──────────────────────────────────────────────────────────────────
    ts_now = event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    if chain and chain.link_count > 1:
        chain_start = chain.started_at.strftime("%H:%M:%S UTC")
        elapsed     = chain.duration_minutes
        when = (
            f"{ts_now} - Chain started at {chain_start} "
            f"({elapsed:.1f} minutes ago, "
            f"step {chain.link_count} of chain)"
        )
    else:
        when = f"{ts_now} (first detection on this entity)"

    # ── WHY ───────────────────────────────────────────────────────────────────
    # Extract the Sigma selection logic as the WHY explanation
    detection = rule.detection
    why_parts = []

    if isinstance(detection, dict):
        for key, val in detection.items():
            if key == "condition":
                why_parts.append(f"Condition: {val}")
            elif isinstance(val, dict):
                for field, criteria in val.items():
                    why_parts.append(f"  {field}: {criteria}")
            elif isinstance(val, list):
                why_parts.append(f"  {key}: {val[:3]}")

    why = (
        f"Sigma rule '{rule.title}' fired.\n"
        + "\n".join(why_parts[:6])
        + f"\n\nRule file: {rule.file_path or 'embedded'}"
    )

    # ── HOW ───────────────────────────────────────────────────────────────────
    since = event.timestamp - timedelta(minutes=settings.entity_lookback_minutes)
    sql   = db.generate_investigation_sql(
        entity_name = entity.name,
        rule_title  = rule.title,
        since       = since,
    )
    how = (
        f"Run this DuckDB investigation query to pull all related alerts:\n\n"
        f"{sql}\n\n"
        f"Then cross-reference with LogClaw at {settings.logclaw_api} "
        f"and PacketStrike at {settings.packetstrike_api} "
        f"for full context on {entity.display_name}."
    )

    return who, what, where, when, why, how


# ── Cooldown Tracker ──────────────────────────────────────────────────────────

class AlertCooldown:
    """
    Prevents the same rule firing repeatedly on the same entity
    within the cooldown window.
    Key: "{entity_name}:{rule_id}"
    """

    def __init__(self, cooldown_seconds: int) -> None:
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._fired   : Dict[str, datetime] = {}

    def is_cooling(self, entity_name: str, rule_id: str) -> bool:
        key  = f"{entity_name}:{rule_id}"
        last = self._fired.get(key)
        if last is None:
            return False
        return (datetime.now(timezone.utc) - last) < self._cooldown

    def record(self, entity_name: str, rule_id: str) -> None:
        key = f"{entity_name}:{rule_id}"
        self._fired[key] = datetime.now(timezone.utc)


# ── Correlation Engine ────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    The judgment layer of SIEMulate.

    Receives (event, matched_rules) pairs from the pipeline and:

      1. Gets or creates the EntityProfile for the event's entity
      2. Applies cooldown - skips re-alerts within cooldown window
      3. Builds the full Alert with 5W+H narrative
      4. Accumulates risk score on the entity
      5. Checks if an attack chain is forming or extending
      6. Escalates if chain crosses the CRITICAL threshold
      7. Generates the chain narrative
      8. Updates the entity timeline
      9. Persists entity and chain to DuckDB
      10. Returns all Alerts generated

    Thread safety: a single lock protects the entity registry and
    active chain registry.

    Usage:
        engine = CorrelationEngine(settings, db)
        engine.start()
        alerts = engine.process(event, matched_rules)
        engine.stop()
    """

    def __init__(self, settings: Settings, db: Database) -> None:
        self._settings  = settings
        self._db        = db
        self._lock      = threading.Lock()
        self._cooldown  = AlertCooldown(settings.alert_cooldown_seconds)

        # In-memory registries
        self._entities  : Dict[str, EntityProfile] = {}
        self._chains    : Dict[str, AttackChain]   = {}

        # Stats
        self._alerts_generated = 0
        self._chains_formed    = 0
        self._escalations      = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Load existing entities and chains from DuckDB into memory."""
        logger.info("CorrelationEngine starting - loading state from database...")

        entity_rows = self._db.get_all_entities(limit=10_000)
        for row in entity_rows:
            try:
                entity = self._deserialise_entity(row)
                self._entities[entity.name] = entity
            except Exception as e:
                logger.debug(f"Failed to load entity: {e}")

        chain_rows = self._db.get_chains(limit=5_000)
        for row in chain_rows:
            try:
                chain = self._deserialise_chain(row)
                self._chains[chain.chain_id] = chain
                # Re-attach active chain to entity
                if chain.entity_name in self._entities:
                    ent = self._entities[chain.entity_name]
                    if not ent.active_chain_id:
                        ent.active_chain_id = chain.chain_id
            except Exception as e:
                logger.debug(f"Failed to load chain: {e}")

        logger.info(
            f"CorrelationEngine ready - "
            f"{len(self._entities)} entities, "
            f"{len(self._chains)} chains loaded."
        )

    def stop(self) -> None:
        """Flush all state to DuckDB on shutdown."""
        logger.info("CorrelationEngine stopping - flushing state...")
        with self._lock:
            for entity in self._entities.values():
                try:
                    self._db.upsert_entity(entity)
                except Exception as e:
                    logger.error(f"Entity flush failed: {e}")
            for chain in self._chains.values():
                try:
                    self._db.upsert_chain(chain)
                except Exception as e:
                    logger.error(f"Chain flush failed: {e}")
        logger.info("CorrelationEngine stopped.")

    # ── Main Entry Point ──────────────────────────────────────────────────────

    def process(
        self,
        event        : InboundEvent,
        matched_rules: List[SigmaRule],
        is_replay    : bool = False,
    ) -> List[Alert]:
        """
        Process an event and its matching Sigma rules.
        Returns a list of Alert objects generated (may be empty if
        all rules are cooling down).
        """
        if not matched_rules:
            return []

        with self._lock:
            alerts: List[Alert] = []

            entity = self._get_or_create_entity(event)

            for rule in matched_rules:
                # ── Cooldown check ────────────────────────────────────────────
                if self._cooldown.is_cooling(entity.name, rule.rule_id):
                    logger.debug(
                        f"Cooldown active: '{rule.title}' on '{entity.name}'"
                    )
                    continue

                self._cooldown.record(entity.name, rule.rule_id)

                # ── Get or extend attack chain ────────────────────────────────
                chain = self._get_or_extend_chain(entity, rule, event)

                # ── Build 5W+H ────────────────────────────────────────────────
                who, what, where, when, why, how = _build_fivewh(
                    rule     = rule,
                    event    = event,
                    entity   = entity,
                    chain    = chain,
                    db       = self._db,
                    settings = self._settings,
                )

                # ── Build alert ───────────────────────────────────────────────
                severity = AlertSeverity(min(rule.severity_int, 10))
                alert = Alert(
                    rule          = rule,
                    event         = event,
                    severity      = severity,
                    entity_name   = entity.name,
                    entity_type   = entity.type,
                    entity_host   = entity.host,
                    who           = who,
                    what          = what,
                    where         = where,
                    when          = when,
                    why           = why,
                    how           = how,
                    mitre         = rule.mitre,
                    chain_stage   = rule.mitre.chain_stage,
                    chain_id      = chain.chain_id if chain else None,
                    chain_position= chain.link_count if chain else None,
                    source        = event.source,
                    is_replay     = is_replay,
                )

                # ── Apply risk to entity ───────────────────────────────────────
                self._apply_risk(entity, rule, chain)

                # ── Update entity state ───────────────────────────────────────
                self._update_entity(entity, alert, chain)

                # ── Persist ───────────────────────────────────────────────────
                try:
                    self._db.insert_alert(alert)
                    self._db.upsert_entity(entity)
                    if chain:
                        self._db.upsert_chain(chain)
                    self._db.increment_rule_match(rule.rule_id)
                except Exception as e:
                    logger.error(f"Persist failed for alert {alert.alert_id}: {e}")

                alerts.append(alert)
                self._alerts_generated += 1

                logger.info(
                    f"Alert generated: '{rule.title}' | "
                    f"entity='{entity.name}' | "
                    f"risk={entity.risk_score}/100 | "
                    f"chain={'yes' if chain else 'no'}"
                )

            return alerts

    # ── Entity Management ─────────────────────────────────────────────────────

    def _get_or_create_entity(self, event: InboundEvent) -> EntityProfile:
        name = event.entity.name
        if name not in self._entities:
            entity = EntityProfile(
                name   = name,
                type   = event.entity.type,
                host   = event.entity.host,
                domain = event.entity.domain,
            )
            self._entities[name] = entity
            logger.debug(f"New entity: {name} [{event.entity.type.value}]")
        else:
            entity = self._entities[name]
            entity.last_seen = datetime.now(timezone.utc)
            # Update host if now known
            if event.entity.host and not entity.host:
                entity.host = event.entity.host
        return entity

    def get_entity(self, name: str) -> Optional[EntityProfile]:
        with self._lock:
            return self._entities.get(name)

    def get_all_entities(self) -> List[EntityProfile]:
        with self._lock:
            return list(self._entities.values())

    def get_critical_entities(self) -> List[EntityProfile]:
        with self._lock:
            return sorted(
                [
                    e for e in self._entities.values()
                    if e.risk_score >= self._settings.risk_threshold_critical
                ],
                key=lambda e: e.risk_score,
                reverse=True,
            )

    # ── Attack Chain Management ───────────────────────────────────────────────

    def _get_or_extend_chain(
        self,
        entity: EntityProfile,
        rule  : SigmaRule,
        event : InboundEvent,
    ) -> Optional[AttackChain]:
        """
        Check if this rule fires within the chain window of an existing chain
        on this entity. If so, extend it. If not, start a new chain.
        A chain requires at least attack_chain_min_rules distinct rules.
        """
        now    = datetime.now(timezone.utc)
        window = timedelta(seconds=self._settings.attack_chain_window_seconds)

        # Check existing active chain
        if entity.active_chain_id and entity.active_chain_id in self._chains:
            chain = self._chains[entity.active_chain_id]
            # Still within window?
            if (now - chain.updated_at) <= window:
                # Don't duplicate the same rule in the same chain
                existing_rules = {lnk.rule_title for lnk in chain.links}
                if rule.title not in existing_rules:
                    self._extend_chain(chain, rule, event)
                return chain
            else:
                # Window expired - close this chain, start fresh
                entity.active_chain_id = None

        # Start a new chain candidate
        chain = AttackChain(
            entity_name = entity.name,
            entity_type = entity.type,
            entity_host = entity.host,
            started_at  = now,
            updated_at  = now,
        )
        self._extend_chain(chain, rule, event)
        self._chains[chain.chain_id] = chain
        entity.active_chain_id = chain.chain_id

        if chain.chain_id not in entity.chain_ids:
            entity.chain_ids.append(chain.chain_id)
            entity.total_chains += 1
            self._chains_formed += 1

        return chain

    def _extend_chain(
        self,
        chain: AttackChain,
        rule : SigmaRule,
        event: InboundEvent,
    ) -> None:
        """Add a new ChainLink to an existing AttackChain."""
        now = datetime.now(timezone.utc)

        # Generate investigation SQL for this link
        since = event.timestamp - timedelta(
            minutes=self._settings.entity_lookback_minutes
        )
        sql = self._db.generate_investigation_sql(
            entity_name = chain.entity_name,
            rule_title  = rule.title,
            since       = since,
        )

        link = ChainLink(
            position    = len(chain.links) + 1,
            alert_id    = "",           # Filled after alert creation
            timestamp   = event.timestamp,
            rule_title  = rule.title,
            chain_stage = rule.mitre.chain_stage,
            mitre_id    = rule.mitre.technique_id,
            entity_name = chain.entity_name,
            severity    = rule.severity_int,
            investigation_sql = sql,
        )
        chain.links.append(link)
        chain.updated_at = now

        # Track stages seen
        if rule.mitre.chain_stage not in chain.stages_seen:
            chain.stages_seen.append(rule.mitre.chain_stage)

        # Rebuild narrative
        chain.narrative = _build_chain_narrative(chain)

        # Check escalation threshold
        if (
            chain.risk_score >= self._settings.risk_threshold_critical
            and not chain.is_escalated
        ):
            chain.is_escalated = True
            self._escalations += 1
            logger.warning(
                f"CHAIN ESCALATED: entity='{chain.entity_name}' "
                f"risk={chain.risk_score} "
                f"stages={chain.stage_progression}"
            )

    # ── Risk Scoring ──────────────────────────────────────────────────────────

    def _apply_risk(
        self,
        entity: EntityProfile,
        rule  : SigmaRule,
        chain : Optional[AttackChain],
    ) -> None:
        """Increment entity and chain risk scores."""
        delta = _RISK_BY_LEVEL.get(rule.level.lower(), 5)

        # Chain bonus - escalating chains add extra risk
        if chain and chain.link_count >= self._settings.attack_chain_min_rules:
            delta += _RISK_CHAIN_BONUS

        entity.risk_score = min(_RISK_MAX, entity.risk_score + delta)
        entity.risk_level = _classify_risk(entity.risk_score, self._settings)
        entity.peak_risk  = max(entity.peak_risk, entity.risk_score)

        if chain:
            chain.risk_score = min(_RISK_MAX, chain.risk_score + delta)
            chain.risk_level = _classify_risk(chain.risk_score, self._settings)

    def decay_risk_scores(self) -> None:
        """
        Apply time-based risk decay to all entities.
        Called by the background scheduler at decay_interval_hours.
        Quiet entities cool down - active threats stay hot.
        """
        with self._lock:
            threshold = timedelta(hours=self._settings.risk_decay_interval_hours)
            now       = datetime.now(timezone.utc)
            decayed   = 0

            for entity in self._entities.values():
                if entity.risk_score <= _RISK_MIN:
                    continue
                quiet = now - entity.last_seen
                if quiet >= threshold:
                    decay  = max(1, int(entity.risk_score * self._settings.risk_decay_rate))
                    entity.risk_score = max(_RISK_MIN, entity.risk_score - decay)
                    entity.risk_level = _classify_risk(entity.risk_score, self._settings)
                    decayed += 1

            if decayed:
                logger.info(f"Risk decay applied to {decayed} entities.")

    # ── Entity State Update ───────────────────────────────────────────────────

    def _update_entity(
        self,
        entity: EntityProfile,
        alert : Alert,
        chain : Optional[AttackChain],
    ) -> None:
        """Update entity counters, rule history, MITRE tracking, timeline."""
        entity.total_alerts += 1
        entity.alert_ids.append(alert.alert_id)

        if alert.rule.title not in entity.rules_fired:
            entity.rules_fired.append(alert.rule.title)

        if alert.mitre.technique_id:
            if alert.mitre.technique_id not in entity.techniques_seen:
                entity.techniques_seen.append(alert.mitre.technique_id)

        if alert.mitre.tactic:
            if alert.mitre.tactic not in entity.tactics_seen:
                entity.tactics_seen.append(alert.mitre.tactic)

        # Timeline entry
        chain_ref = f" | Chain step {chain.link_count}" if chain else ""
        entry = TimelineEntry(
            timestamp  = alert.timestamp,
            entry_type = "alert",
            description= (
                f"⚠ {alert.rule.title}{chain_ref} - "
                f"Risk now {entity.risk_score}/100"
            ),
            alert_id   = alert.alert_id,
            chain_id   = alert.chain_id,
            severity   = alert.severity.value,
            rule_title = alert.rule.title,
            mitre_id   = alert.mitre.technique_id,
        )
        entity.timeline.append(entry)

        # Prune timeline
        max_events = self._settings.max_timeline_events
        if len(entity.timeline) > max_events:
            entity.timeline = entity.timeline[-max_events:]

    # ── Chain Access ──────────────────────────────────────────────────────────

    def get_chain(self, chain_id: str) -> Optional[AttackChain]:
        with self._lock:
            return self._chains.get(chain_id)

    def get_all_chains(self) -> List[AttackChain]:
        with self._lock:
            return list(self._chains.values())

    def get_escalated_chains(self) -> List[AttackChain]:
        with self._lock:
            return sorted(
                [c for c in self._chains.values() if c.is_escalated],
                key=lambda c: c.risk_score,
                reverse=True,
            )

    # ── Deserialisation ───────────────────────────────────────────────────────

    def _deserialise_entity(self, row: dict) -> EntityProfile:
        import json
        return EntityProfile(
            entity_id       = row["entity_id"],
            name            = row["name"],
            type            = EntityType(row["type"]),
            host            = row.get("host"),
            domain          = row.get("domain"),
            first_seen      = row["first_seen"],
            last_seen       = row["last_seen"],
            risk_score      = int(row.get("risk_score", 0)),
            risk_level      = RiskLevel(row.get("risk_level", "LOW")),
            peak_risk       = int(row.get("peak_risk", 0)),
            total_alerts    = int(row.get("total_alerts", 0)),
            alert_ids       = json.loads(row.get("alert_ids") or "[]"),
            rules_fired     = json.loads(row.get("rules_fired") or "[]"),
            active_chain_id = row.get("active_chain_id"),
            chain_ids       = json.loads(row.get("chain_ids") or "[]"),
            total_chains    = int(row.get("total_chains", 0)),
            techniques_seen = json.loads(row.get("techniques_seen") or "[]"),
            tactics_seen    = json.loads(row.get("tactics_seen") or "[]"),
            timeline        = [],   # Timeline rebuilt from DB on demand
        )

    def _deserialise_chain(self, row: dict) -> AttackChain:
        import json
        raw_links  = json.loads(row.get("links") or "[]")
        raw_stages = json.loads(row.get("stages_seen") or "[]")

        links = []
        for lnk in raw_links:
            try:
                links.append(ChainLink(**lnk))
            except Exception:
                pass

        stages = []
        for s in raw_stages:
            try:
                stages.append(ChainStage(s))
            except Exception:
                pass

        return AttackChain(
            chain_id     = row["chain_id"],
            entity_name  = row["entity_name"],
            entity_type  = EntityType(row["entity_type"]),
            entity_host  = row.get("entity_host"),
            started_at   = row["started_at"],
            updated_at   = row["updated_at"],
            risk_score   = int(row.get("risk_score", 0)),
            risk_level   = RiskLevel(row.get("risk_level", "LOW")),
            stages_seen  = stages,
            is_escalated = bool(row.get("is_escalated", False)),
            links        = links,
            narrative    = row.get("narrative", ""),
            ai_summary   = row.get("ai_summary"),
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "entities_tracked"  : len(self._entities),
                "active_chains"     : len(self._chains),
                "escalated_chains"  : sum(
                    1 for c in self._chains.values() if c.is_escalated
                ),
                "critical_entities" : sum(
                    1 for e in self._entities.values()
                    if e.risk_score >= self._settings.risk_threshold_critical
                ),
                "alerts_generated"  : self._alerts_generated,
                "chains_formed"     : self._chains_formed,
                "escalations"       : self._escalations,
            }