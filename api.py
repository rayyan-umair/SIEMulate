"""
SIEMulate - API Layer
api.py - FastAPI server, WebSocket streaming, REST endpoints

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : The external interface of SIEMulate. Exposes a FastAPI
          server with REST endpoints for querying alerts, chains,
          entities, and rules, plus a WebSocket endpoint that streams
          alert events to connected dashboard clients in real time.
          Replay jobs are started and monitored via REST.
          All business logic lives in the engine layers - the API
          only reads, formats, and streams. No analysis happens here.
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
import os
import shutil
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from correlation import CorrelationEngine
from database import Database
from models import (
    Alert,
    HealthResponse,
    InboundEvent,
    EntitySource,
    EventSource,
    RiskLevel,
)
from replay import ReplayEngine
from sigma_engine import SigmaEngine

logger = logging.getLogger(__name__)


# ── WebSocket Manager ─────────────────────────────────────────────────────────

class ConnectionManager:
    """
    Manages all active WebSocket connections.
    Broadcasts alert events to every connected client.
    Dead connections are removed silently.
    """

    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info(
            f"WebSocket client connected. "
            f"Total: {len(self._connections)}"
        )

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info(
            f"WebSocket client disconnected. "
            f"Total: {len(self._connections)}"
        )

    async def broadcast(self, payload: dict) -> None:
        if not self._connections:
            return
        message = json.dumps(payload, default=str)
        dead: Set[WebSocket] = set()
        async with self._lock:
            connections = set(self._connections)
        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self._connections -= dead

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# ── App Factory ───────────────────────────────────────────────────────────────

def create_app(
    settings          : Settings,
    db                : Database,
    sigma             : SigmaEngine,
    correlation       : CorrelationEngine,
    replay_engine     : ReplayEngine,
    sigma_stats_fn    : callable,
    correlation_stats_fn: callable,
    started_at        : datetime,
) -> tuple:
    """
    Build and return the FastAPI application and WebSocket manager.
    Called once from main.py at startup.
    All engine references are injected - the API layer owns nothing.
    """

    app = FastAPI(
        title       = "SIEMulate",
        description = "Local-first detection intelligence and entity correlation engine.",
        version     = settings.app_version,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins     = ["*"],
        allow_credentials = True,
        allow_methods     = ["*"],
        allow_headers     = ["*"],
    )

    manager = ConnectionManager()

    # ── Health ────────────────────────────────────────────────────────────────

    @app.get(
        "/health",
        response_model = HealthResponse,
        tags           = ["System"],
        summary        = "Health check and system status",
    )
    async def health() -> HealthResponse:
        uptime  = (datetime.now(timezone.utc) - started_at).total_seconds()
        s_stats = sigma_stats_fn()
        c_stats = correlation_stats_fn()
        return HealthResponse(
            status           = "ok",
            app_name         = settings.app_name,
            version          = settings.app_version,
            rules_loaded     = s_stats.get("rules_loaded", 0),
            entities_tracked = c_stats.get("entities_tracked", 0),
            active_chains    = c_stats.get("active_chains", 0),
            ai_enabled       = settings.ai_enabled,
            uptime_seconds   = uptime,
            replay_status    = replay_engine.stats.get("status", "idle"),
        )

    @app.get(
        "/stats",
        tags    = ["System"],
        summary = "Full engine statistics",
    )
    async def stats() -> dict:
        return {
            "sigma"      : sigma_stats_fn(),
            "correlation": correlation_stats_fn(),
            "replay"     : replay_engine.stats,
            "database"   : db.get_stats(),
            "websocket"  : {"active_connections": manager.connection_count},
        }

    # ── Ingest ────────────────────────────────────────────────────────────────

    @app.post(
        "/ingest",
        tags    = ["Ingest"],
        summary = "Ingest a single event for detection and correlation",
        status_code = status.HTTP_202_ACCEPTED,
    )
    async def ingest_event(event: InboundEvent) -> dict:
        """
        Submit a single InboundEvent for real-time Sigma evaluation
        and correlation. Returns any alerts generated.
        """
        try:
            matched = sigma.evaluate(event)
            alerts  = correlation.process(
                event         = event,
                matched_rules = matched,
                is_replay     = False,
            )
            for alert in alerts:
                payload = {
                    "type": "alert",
                    "data": alert.model_dump(mode="json"),
                }
                asyncio.create_task(manager.broadcast(payload))

            return {
                "event_id"    : event.event_id,
                "rules_matched": len(matched),
                "alerts_fired" : len(alerts),
                "alert_ids"    : [a.alert_id for a in alerts],
            }
        except Exception as e:
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail      = f"Ingest failed: {e}",
            )

    @app.post(
        "/ingest/batch",
        tags    = ["Ingest"],
        summary = "Ingest a batch of events",
        status_code = status.HTTP_202_ACCEPTED,
    )
    async def ingest_batch(events: List[InboundEvent]) -> dict:
        """
        Submit a list of InboundEvents for bulk processing.
        Returns aggregate counts.
        """
        total_matched = 0
        total_alerts  = 0
        alert_ids     = []

        for event in events:
            try:
                matched = sigma.evaluate(event)
                alerts  = correlation.process(
                    event         = event,
                    matched_rules = matched,
                    is_replay     = False,
                )
                total_matched += len(matched)
                total_alerts  += len(alerts)
                alert_ids.extend([a.alert_id for a in alerts])

                for alert in alerts:
                    asyncio.create_task(manager.broadcast({
                        "type": "alert",
                        "data": alert.model_dump(mode="json"),
                    }))
            except Exception as e:
                logger.error(f"Batch ingest error on event {event.event_id}: {e}")

        return {
            "events_processed": len(events),
            "rules_matched"   : total_matched,
            "alerts_fired"    : total_alerts,
            "alert_ids"       : alert_ids,
        }

    # ── Alerts ────────────────────────────────────────────────────────────────

    @app.get(
        "/alerts",
        tags    = ["Alerts"],
        summary = "List recent alerts",
    )
    async def get_alerts(
        entity_name  : Optional[str]  = Query(default=None),
        chain_id     : Optional[str]  = Query(default=None),
        min_severity : int            = Query(default=0),
        since_hours  : int            = Query(default=24),
        is_replay    : Optional[bool] = Query(default=None),
        limit        : int            = Query(default=200, le=2000),
    ) -> List[dict]:
        since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        return db.get_alerts(
            entity_name  = entity_name,
            since        = since,
            chain_id     = chain_id,
            min_severity = min_severity,
            is_replay    = is_replay,
            limit        = limit,
        )

    @app.get(
        "/alerts/summary",
        tags    = ["Alerts"],
        summary = "Alert count by rule",
    )
    async def get_alert_summary() -> dict:
        return db.get_alert_count_by_rule()

    @app.post(
        "/alerts/investigate",
        tags    = ["Alerts"],
        summary = "Run a raw SQL investigation query",
    )
    async def investigate(body: dict) -> List[dict]:
        """
        Execute a SQL SELECT against the alerts and chains tables.
        Auto-generated HOW queries from the 5W+H engine use this endpoint.
        Only SELECT statements are permitted.

        Example:
            { "sql": "SELECT * FROM alerts WHERE entity_name = 'admin' LIMIT 50" }
        """
        sql = body.get("sql", "").strip()
        if not sql:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = "Request body must contain a 'sql' field.",
            )
        try:
            return db.investigation_query(sql)
        except ValueError as e:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = str(e),
            )
        except Exception as e:
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail      = f"Query failed: {e}",
            )

    # ── Attack Chains ─────────────────────────────────────────────────────────

    @app.get(
        "/chains",
        tags    = ["Chains"],
        summary = "List attack chains",
    )
    async def get_chains(
        entity_name : Optional[str]  = Query(default=None),
        is_escalated: Optional[bool] = Query(default=None),
        min_risk    : int            = Query(default=0),
        limit       : int            = Query(default=100, le=1000),
    ) -> List[dict]:
        """Return attack chains with optional filters."""
        return db.get_chains(
            entity_name  = entity_name,
            is_escalated = is_escalated,
            min_risk     = min_risk,
            limit        = limit,
        )

    @app.get(
        "/chains/escalated",
        tags    = ["Chains"],
        summary = "List escalated attack chains",
    )
    async def get_escalated_chains() -> List[dict]:
        """Return all chains that have crossed the CRITICAL risk threshold."""
        chains = correlation.get_escalated_chains()
        return [c.model_dump(mode="json") for c in chains]

    @app.get(
        "/chains/{chain_id}",
        tags    = ["Chains"],
        summary = "Get a single attack chain by ID",
    )
    async def get_chain(chain_id: str) -> dict:
        chain = correlation.get_chain(chain_id)
        if not chain:
            chain_row = db.get_chain(chain_id)
            if not chain_row:
                raise HTTPException(
                    status_code = status.HTTP_404_NOT_FOUND,
                    detail      = f"Chain {chain_id} not found.",
                )
            return chain_row
        return chain.model_dump(mode="json")

    @app.get(
        "/chains/{chain_id}/alerts",
        tags    = ["Chains"],
        summary = "Get all alerts in an attack chain",
    )
    async def get_chain_alerts(chain_id: str) -> List[dict]:
        return db.get_alerts(chain_id=chain_id, limit=500)

    # ── Entities ──────────────────────────────────────────────────────────────

    @app.get(
        "/entities",
        tags    = ["Entities"],
        summary = "List all tracked entities",
    )
    async def get_entities(
        min_risk: int = Query(default=0),
        limit   : int = Query(default=200, le=2000),
    ) -> List[dict]:
        entities = correlation.get_all_entities()
        if min_risk > 0:
            entities = [e for e in entities if e.risk_score >= min_risk]
        entities.sort(key=lambda e: e.risk_score, reverse=True)
        return [e.model_dump(mode="json") for e in entities[:limit]]

    @app.get(
        "/entities/critical",
        tags    = ["Entities"],
        summary = "List CRITICAL risk entities",
    )
    async def get_critical_entities() -> List[dict]:
        entities = correlation.get_critical_entities()
        return [e.model_dump(mode="json") for e in entities]

    @app.get(
        "/entities/{name}",
        tags    = ["Entities"],
        summary = "Get full entity profile",
    )
    async def get_entity(name: str) -> dict:
        entity = correlation.get_entity(name)
        if not entity:
            row = db.get_entity(name)
            if not row:
                raise HTTPException(
                    status_code = status.HTTP_404_NOT_FOUND,
                    detail      = f"Entity '{name}' has not been observed.",
                )
            return row
        return entity.model_dump(mode="json")

    @app.get(
        "/entities/{name}/timeline",
        tags    = ["Entities"],
        summary = "Get entity behavior timeline",
    )
    async def get_entity_timeline(
        name : str,
        limit: int = Query(default=100, le=1000),
    ) -> List[dict]:
        entity = correlation.get_entity(name)
        if not entity:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Entity '{name}' has not been observed.",
            )
        timeline = sorted(
            entity.timeline,
            key     = lambda t: t.timestamp,
            reverse = True,
        )
        return [t.model_dump(mode="json") for t in timeline[:limit]]

    @app.get(
        "/entities/{name}/chains",
        tags    = ["Entities"],
        summary = "Get all chains for an entity",
    )
    async def get_entity_chains(name: str) -> List[dict]:
        return db.get_chains(entity_name=name, limit=50)

    # ── Sigma Rules ───────────────────────────────────────────────────────────

    @app.get(
        "/rules",
        tags    = ["Rules"],
        summary = "List all loaded Sigma rules",
    )
    async def get_rules() -> List[dict]:
        rules = sigma.get_all_rules()
        return [r.model_dump(mode="json") for r in rules]

    @app.get(
        "/rules/stats",
        tags    = ["Rules"],
        summary = "Rule match statistics",
    )
    async def get_rule_stats() -> dict:
        return {
            "engine"   : sigma.stats,
            "top_rules": db.get_alert_count_by_rule(),
        }

    @app.post(
        "/rules/reload",
        tags    = ["Rules"],
        summary = "Reload Sigma rules from disk",
    )
    async def reload_rules() -> dict:
        count = sigma.reload_rules()
        return {
            "status"      : "reloaded",
            "rules_loaded": count,
        }

    @app.patch(
        "/rules/{rule_id}/disable",
        tags    = ["Rules"],
        summary = "Disable a Sigma rule",
    )
    async def disable_rule(rule_id: str) -> dict:
        ok = sigma.disable_rule(rule_id)
        if not ok:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Rule {rule_id} not found.",
            )
        return {"status": "disabled", "rule_id": rule_id}

    @app.patch(
        "/rules/{rule_id}/enable",
        tags    = ["Rules"],
        summary = "Enable a Sigma rule",
    )
    async def enable_rule(rule_id: str) -> dict:
        ok = sigma.enable_rule(rule_id)
        if not ok:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Rule {rule_id} not found.",
            )
        return {"status": "enabled", "rule_id": rule_id}

    # ── Replay ────────────────────────────────────────────────────────────────

    @app.post(
        "/replay/start",
        tags    = ["Replay"],
        summary = "Start a replay job",
        status_code = status.HTTP_202_ACCEPTED,
    )
    async def start_replay(body: dict) -> dict:
        """
        Start replaying a historic JSON log file through the full
        detection and correlation pipeline.

        Body:
            { "file": "attack_log.json", "speed": 10.0 }

        Speed multiplier: 10.0 = 10 seconds of logs per real second.
        File must exist in the replay directory.
        """
        file_name = body.get("file", "").strip()
        speed     = float(body.get("speed", 10.0))

        if not file_name:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = "Request body must contain a 'file' field.",
            )
        try:
            job = replay_engine.start_replay(file_name=file_name, speed=speed)
            return job.model_dump(mode="json")
        except FileNotFoundError as e:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = str(e),
            )
        except RuntimeError as e:
            raise HTTPException(
                status_code = status.HTTP_409_CONFLICT,
                detail      = str(e),
            )

    @app.post(
        "/replay/stop",
        tags    = ["Replay"],
        summary = "Stop the current replay job",
    )
    async def stop_replay() -> dict:
        replay_engine.stop_replay()
        return {"status": "stopped"}

    @app.post(
        "/replay/pause",
        tags    = ["Replay"],
        summary = "Pause the current replay job",
    )
    async def pause_replay() -> dict:
        replay_engine.pause_replay()
        return {"status": "paused"}

    @app.post(
        "/replay/resume",
        tags    = ["Replay"],
        summary = "Resume a paused replay job",
    )
    async def resume_replay() -> dict:
        replay_engine.resume_replay()
        return {"status": "resumed"}

    @app.get(
        "/replay/status",
        tags    = ["Replay"],
        summary = "Get current replay job status",
    )
    async def replay_status() -> dict:
        return replay_engine.stats

    @app.get(
        "/replay/jobs",
        tags    = ["Replay"],
        summary = "List all past replay jobs",
    )
    async def get_replay_jobs() -> List[dict]:
        return db.get_replay_jobs(limit=20)

    @app.post(
        "/replay/upload",
        tags    = ["Replay"],
        summary = "Upload a JSON log file for replay",
    )
    async def upload_replay_file(file: UploadFile = File(...)) -> dict:
        """
        Upload a JSON log file to the replay directory.
        Accepts JSON array, NDJSON, or wrapped format.
        """
        from pathlib import Path
        if not file.filename:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = "No filename provided.",
            )
        if not file.filename.endswith(".json"):
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = "Only .json files are accepted for replay.",
            )

        dest = Path(settings.replay_dir) / file.filename
        try:
            with open(dest, "wb") as f:
                shutil.copyfileobj(file.file, f)
            size = dest.stat().st_size
            return {
                "status"   : "uploaded",
                "file_name": file.filename,
                "size_bytes": size,
                "path"     : str(dest),
            }
        except Exception as e:
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail      = f"Upload failed: {e}",
            )

    # ── Risk Management ───────────────────────────────────────────────────────

    @app.post(
        "/risk/decay",
        tags    = ["Risk"],
        summary = "Manually trigger risk score decay",
    )
    async def trigger_decay() -> dict:
        """Force an immediate risk decay cycle across all entities."""
        correlation.decay_risk_scores()
        return {"status": "decay applied"}

    # ── WebSocket ─────────────────────────────────────────────────────────────

    @app.websocket("/ws/alerts")
    async def ws_alerts(ws: WebSocket) -> None:
        """
        Real-time WebSocket stream of alert events.

        Connect to receive JSON-encoded Alert objects as they fire.
        Message format:
            { "type": "alert",     "data": { ...Alert fields... } }
            { "type": "heartbeat", "timestamp": "UTC ISO8601" }
        """
        await manager.connect(ws)
        try:
            while True:
                await asyncio.sleep(settings.ws_heartbeat_interval)
                await ws.send_text(json.dumps({
                    "type"     : "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"WebSocket error: {e}")
        finally:
            await manager.disconnect(ws)

    @app.websocket("/ws/chains")
    async def ws_chains(ws: WebSocket) -> None:
        """
        Real-time WebSocket stream of attack chain updates.

        Message format:
            { "type": "chain_update", "data": { ...AttackChain fields... } }
        """
        await manager.connect(ws)
        try:
            while True:
                await asyncio.sleep(settings.ws_heartbeat_interval)
                await ws.send_text(json.dumps({
                    "type"     : "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"WebSocket error: {e}")
        finally:
            await manager.disconnect(ws)

    return app, manager