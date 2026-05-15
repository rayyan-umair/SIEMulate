"""
SIEMulate - Replay Engine
replay.py - Historic log replay, fast-forward simulation, rule regression

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Baked into the main pipeline. Accepts a historic JSON log
          file, parses it into InboundEvents, and fast-forwards them
          through the identical detection and correlation pipeline used
          for live events. Alerts fire, chains form, and entities score
          exactly as they would in production.
          Use cases:
            - Test new Sigma rules against known attacks
            - Demo the platform without live traffic
            - Regression test after rule changes
            - Interview and portfolio demonstrations
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from correlation import CorrelationEngine
from database import Database
from models import (
    Alert,
    EntityRef,
    EntityType,
    EventContext,
    EventSource,
    EventType,
    InboundEvent,
    MitreMapping,
    ReplayJob,
    ReplayStatus,
)
from sigma_engine import SigmaEngine

logger = logging.getLogger(__name__)


# ── Event Normaliser ──────────────────────────────────────────────────────────

def _normalise_raw_event(raw: Dict[str, Any], index: int) -> Optional[InboundEvent]:
    """
    Normalise a raw JSON log entry into an InboundEvent.

    Supports multiple common log formats:
      - NetRaptor universal schema (LogClaw / PacketStrike output)
      - Windows Event Log JSON export
      - Generic syslog JSON
      - Flat key-value dicts

    Returns None if the event cannot be normalised.
    """
    if not isinstance(raw, dict):
        return None

    try:
        # ── Timestamp ─────────────────────────────────────────────────────────
        ts_raw = (
            raw.get("timestamp") or
            raw.get("TimeCreated") or
            raw.get("time") or
            raw.get("@timestamp") or
            raw.get("eventTime")
        )
        if ts_raw:
            ts = datetime.fromisoformat(
                str(ts_raw).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        # ── Entity extraction ─────────────────────────────────────────────────
        entity_block = raw.get("entity", {})

        name = (
            entity_block.get("actor") or
            entity_block.get("name") or
            raw.get("user") or
            raw.get("username") or
            raw.get("TargetUserName") or
            raw.get("SubjectUserName") or
            raw.get("src_user") or
            raw.get("actor") or
            f"unknown_{index}"
        )

        host = (
            entity_block.get("target") or
            raw.get("host") or
            raw.get("hostname") or
            raw.get("Computer") or
            raw.get("source") or
            raw.get("WorkstationName")
        )

        # Entity type inference
        entity_type_raw = entity_block.get("type", "")
        if entity_type_raw in EntityType._value2member_map_:
            entity_type = EntityType(entity_type_raw)
        elif _looks_like_ip(name):
            entity_type = EntityType.IP
        elif host and name == host:
            entity_type = EntityType.HOST
        else:
            entity_type = EntityType.USER

        entity = EntityRef(
            name   = str(name),
            type   = entity_type,
            host   = str(host) if host else None,
            domain = raw.get("domain") or raw.get("Domain"),
        )

        # ── Event context ─────────────────────────────────────────────────────
        event_block = raw.get("event", {})
        raw_severity = (
            event_block.get("severity") or
            raw.get("severity") or
            raw.get("Level") or
            0
        )
        try:
            severity = int(raw_severity)
        except (ValueError, TypeError):
            severity = 0

        event_type_raw = event_block.get("type") or raw.get("event_type") or "other"
        if event_type_raw in EventType._value2member_map_:
            event_type = EventType(event_type_raw)
        else:
            event_type = _infer_event_type(raw)

        event_ctx = EventContext(
            type     = event_type,
            action   = event_block.get("action") or raw.get("action") or raw.get("EventType"),
            severity = severity,
            outcome  = event_block.get("outcome") or raw.get("outcome"),
        )

        # ── MITRE ─────────────────────────────────────────────────────────────
        mitre_block = raw.get("mitre", {})
        mitre = MitreMapping(
            technique_id = mitre_block.get("technique_id"),
            tactic       = mitre_block.get("tactic"),
        )

        # ── Build event ───────────────────────────────────────────────────────
        return InboundEvent(
            timestamp   = ts,
            source      = EventSource.REPLAY,
            entity      = entity,
            event       = event_ctx,
            mitre       = mitre,
            raw_payload = raw,
        )

    except Exception as e:
        logger.debug(f"Event normalisation failed at index {index}: {e}")
        return None


def _looks_like_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(value)))


def _infer_event_type(raw: Dict[str, Any]) -> EventType:
    """Infer event type from raw fields when not explicitly set."""
    event_id = str(raw.get("EventID", raw.get("event_id", ""))).strip()
    keywords = str(raw).lower()

    # Windows auth events
    if event_id in ("4624", "4625", "4634", "4648", "4768", "4771"):
        return EventType.AUTH

    # Windows process events
    if event_id in ("4688", "4689", "1"):
        return EventType.PROCESS

    # Network
    if event_id in ("3", "5156", "5158"):
        return EventType.NETWORK

    # Registry
    if event_id in ("4657", "12", "13", "14"):
        return EventType.REGISTRY

    # Keyword inference
    if any(k in keywords for k in ("login", "logon", "auth", "password", "credential")):
        return EventType.AUTH
    if any(k in keywords for k in ("process", "cmd", "powershell", "exec", "command")):
        return EventType.PROCESS
    if any(k in keywords for k in ("network", "connect", "socket", "dns", "http")):
        return EventType.NETWORK
    if any(k in keywords for k in ("registry", "regedit", "hklm", "hkcu")):
        return EventType.REGISTRY
    if any(k in keywords for k in ("file", "write", "read", "delete", "create")):
        return EventType.FILE

    return EventType.OTHER


# ── Replay Engine ─────────────────────────────────────────────────────────────

class ReplayEngine:
    """
    The simulation layer of SIEMulate.

    Loads a JSON log file, normalises every entry into an InboundEvent,
    and feeds them through the identical Sigma + correlation pipeline
    used for live events - at a configurable speed multiplier.

    One replay job runs at a time. A background thread drives the
    replay loop. Progress is tracked in the ReplayJob model and
    persisted to DuckDB after every batch.

    WebSocket broadcast is optional - pass a broadcast_fn callable
    that accepts an Alert and sends it to connected clients.

    Usage:
        engine = ReplayEngine(settings, db, sigma, correlation)
        job = await engine.start_replay("attack_log.json", speed=10.0)
        # ... job runs in background thread
        engine.stop_replay()
    """

    def __init__(
        self,
        settings    : Settings,
        db          : Database,
        sigma       : SigmaEngine,
        correlation : CorrelationEngine,
        broadcast_fn: Optional[Callable[[Alert], None]] = None,
        ws_loop     : Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._settings    = settings
        self._db          = db
        self._sigma       = sigma
        self._correlation = correlation
        self._broadcast   = broadcast_fn
        self._ws_loop     = ws_loop

        self._current_job : Optional[ReplayJob]   = None
        self._thread      : Optional[threading.Thread] = None
        self._running     = False
        self._lock        = threading.Lock()

    # ── Public Interface ──────────────────────────────────────────────────────

    def start_replay(
        self,
        file_name : str,
        speed     : float = 10.0,
    ) -> ReplayJob:
        """
        Start a replay job for the given file.
        File must exist in the replay directory.
        Returns the ReplayJob immediately - replay runs in background.
        Raises if a replay is already running or file not found.
        """
        with self._lock:
            if self._running:
                raise RuntimeError(
                    "A replay is already in progress. "
                    "Call stop_replay() first."
                )

            file_path = Path(self._settings.replay_dir) / file_name
            if not file_path.exists():
                raise FileNotFoundError(
                    f"Replay file not found: {file_path}. "
                    f"Upload files to the replay directory: "
                    f"{self._settings.replay_dir}"
                )

            job = ReplayJob(
                file_name  = file_name,
                file_path  = str(file_path),
                status     = ReplayStatus.IDLE,
                speed      = max(0.1, min(speed, 100.0)),
            )
            self._current_job = job
            self._running     = True

            self._thread = threading.Thread(
                target = self._run,
                name   = "siemulate-replay",
                daemon = True,
                args   = (job, file_path),
            )
            self._thread.start()

            logger.info(
                f"Replay started: {file_name} "
                f"speed={job.speed}x"
            )
            return job

    def stop_replay(self) -> None:
        """Signal the replay thread to stop cleanly."""
        with self._lock:
            self._running = False
        if self._current_job:
            self._current_job.status = ReplayStatus.IDLE
        logger.info("Replay stop requested.")

    def pause_replay(self) -> None:
        """Pause the replay - sets status flag checked by the run loop."""
        if self._current_job:
            self._current_job.status = ReplayStatus.PAUSED
            logger.info("Replay paused.")

    def resume_replay(self) -> None:
        """Resume a paused replay."""
        if self._current_job and self._current_job.status == ReplayStatus.PAUSED:
            self._current_job.status = ReplayStatus.RUNNING
            logger.info("Replay resumed.")

    @property
    def current_job(self) -> Optional[ReplayJob]:
        return self._current_job

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Replay Loop ───────────────────────────────────────────────────────────

    def _run(self, job: ReplayJob, file_path: Path) -> None:
        """
        Main replay loop - runs in a daemon thread.

        1. Load and parse the JSON file
        2. Normalise all entries into InboundEvents
        3. Sort by timestamp for correct temporal ordering
        4. Feed through Sigma + correlation in batches
        5. Sleep between batches to simulate real time
        6. Persist progress after every batch
        """
        job.status     = ReplayStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        self._db.upsert_replay_job(job)

        try:
            # ── Load file ─────────────────────────────────────────────────────
            logger.info(f"Loading replay file: {file_path}")
            raw_events = self._load_json_file(file_path)
            if not raw_events:
                raise ValueError("No events found in replay file.")

            # ── Normalise ─────────────────────────────────────────────────────
            events: List[InboundEvent] = []
            for i, raw in enumerate(raw_events):
                ev = _normalise_raw_event(raw, i)
                if ev:
                    events.append(ev)

            if not events:
                raise ValueError(
                    "No events could be normalised from the replay file. "
                    "Check the file format matches the NetRaptor schema."
                )

            # ── Sort by timestamp ─────────────────────────────────────────────
            events.sort(key=lambda e: e.timestamp)

            job.total_events = len(events)
            logger.info(
                f"Replay: {len(events)} events loaded from {file_path.name}"
            )

            # ── Batch processing loop ─────────────────────────────────────────
            batch_size  = self._settings.replay_batch_size
            sleep_per_batch = batch_size / job.speed  # seconds of real time per batch

            i = 0
            while i < len(events) and self._running:

                # Pause check
                while (
                    self._current_job
                    and self._current_job.status == ReplayStatus.PAUSED
                    and self._running
                ):
                    time.sleep(0.5)

                batch = events[i : i + batch_size]

                for event in batch:
                    if not self._running:
                        break
                    try:
                        matched = self._sigma.evaluate(event)
                        alerts  = self._correlation.process(
                            event        = event,
                            matched_rules= matched,
                            is_replay    = True,
                        )
                        job.alerts_fired += len(alerts)

                        # Broadcast each alert over WebSocket
                        for alert in alerts:
                            self._maybe_broadcast(alert)
                            if alert.chain_id:
                                job.chains_formed = max(
                                    job.chains_formed,
                                    alert.chain_position or 0,
                                )

                    except Exception as e:
                        logger.debug(f"Replay event error at index {i}: {e}")

                    job.processed += 1

                i += batch_size

                # Persist progress
                try:
                    self._db.upsert_replay_job(job)
                except Exception:
                    pass

                # Throttle to simulate real time
                if sleep_per_batch > 0 and self._running:
                    time.sleep(sleep_per_batch)

            # ── Completion ────────────────────────────────────────────────────
            if self._running:
                job.status       = ReplayStatus.COMPLETE
                job.completed_at = datetime.now(timezone.utc)
                logger.info(
                    f"Replay complete: {job.processed} events | "
                    f"{job.alerts_fired} alerts | "
                    f"{job.chains_formed} chain steps"
                )
            else:
                job.status = ReplayStatus.IDLE
                logger.info("Replay stopped by request.")

        except Exception as e:
            job.status = ReplayStatus.ERROR
            job.error  = str(e)
            logger.error(f"Replay failed: {e}")

        finally:
            job.completed_at = job.completed_at or datetime.now(timezone.utc)
            try:
                self._db.upsert_replay_job(job)
            except Exception:
                pass
            with self._lock:
                self._running = False

    # ── File Loader ───────────────────────────────────────────────────────────

    def _load_json_file(self, path: Path) -> List[Dict[str, Any]]:
        """
        Load a JSON replay file.

        Supports three formats:
          1. JSON array:  [ {...}, {...}, ... ]
          2. NDJSON:      one JSON object per line
          3. Wrapped:     { "events": [ {...}, ... ] }
        """
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        # Try JSON array first
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                # Wrapped format
                for key in ("events", "logs", "records", "data", "results"):
                    if key in parsed and isinstance(parsed[key], list):
                        return parsed[key]
                # Single event dict
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Try NDJSON (newline-delimited JSON)
        events = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue

        return events

    # ── WebSocket Broadcast ───────────────────────────────────────────────────

    def _maybe_broadcast(self, alert: Alert) -> None:
        """
        Broadcast an alert over WebSocket if a broadcast function
        and event loop are configured.
        """
        if not self._broadcast or not self._ws_loop:
            return
        try:
            self._broadcast(alert)
        except Exception as e:
            logger.debug(f"Replay broadcast error: {e}")

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        job = self._current_job
        if not job:
            return {"status": "idle", "job": None}
        return {
            "status"        : job.status.value,
            "file_name"     : job.file_name,
            "speed"         : job.speed,
            "total_events"  : job.total_events,
            "processed"     : job.processed,
            "progress_pct"  : job.progress_pct,
            "alerts_fired"  : job.alerts_fired,
            "chains_formed" : job.chains_formed,
            "started_at"    : job.started_at.isoformat() if job.started_at else None,
        }