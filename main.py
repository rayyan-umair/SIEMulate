"""
SIEMulate - Entry Point
main.py - Application bootstrap, pipeline wiring, startup/shutdown

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Wires every engine layer together and starts the application.
          Startup sequence:
            1. Load settings
            2. Connect database
            3. Load Sigma rules
            4. Start correlation engine (loads entity/chain state)
            5. Wire replay engine
            6. Start background schedulers (rule reload, risk decay, archive)
            7. Start FastAPI server (uvicorn)
          Shutdown sequence (SIGINT / SIGTERM):
            1. Stop replay if running
            2. Stop correlation engine (flush state)
            3. Close database connection
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

# ── Third Party ───────────────────────────────────────────────────────────────
import uvicorn

# ── Internal ──────────────────────────────────────────────────────────────────
from api import ConnectionManager, create_app
from config import Settings
from correlation import CorrelationEngine
from database import Database
from replay import ReplayEngine
from sigma_engine import SigmaEngine


# ── Logging Setup ─────────────────────────────────────────────────────────────

def _setup_logging(settings: Settings) -> None:
    fmt = "%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s"
    logging.basicConfig(
        level   = getattr(logging, settings.log_level, logging.INFO),
        format  = fmt,
        datefmt = "%Y-%m-%d %H:%M:%S",
        handlers= [logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sigma").setLevel(logging.WARNING)


logger = logging.getLogger(__name__)


# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = """
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   ███████╗██╗███████╗███╗   ███╗██╗   ██╗██╗      █████╗████████╗███████╗│
│   ██╔════╝██║██╔════╝████╗ ████║██║   ██║██║     ██╔══██╚══██╔══╝██╔════╝│
│   ███████╗██║█████╗  ██╔████╔██║██║   ██║██║     ███████║  ██║   █████╗  │
│   ╚════██║██║██╔══╝  ██║╚██╔╝██║██║   ██║██║     ██╔══██║  ██║   ██╔══╝  │
│   ███████║██║███████╗██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║  ██║   ███████╗│
│   ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝  ╚═╝   ╚══════╝│
│                                                                 │
│   "Context is the only defense."                                │
│   Part of the NetRaptor ecosystem.                              │
│   Built by Rayyan Umair                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
"""


# ── Background Schedulers ─────────────────────────────────────────────────────

class RuleReloadScheduler:
    """
    Reloads Sigma rules from disk on a configurable interval.
    Allows adding or editing rules without restarting the server.
    """

    def __init__(self, sigma: SigmaEngine, interval_seconds: int) -> None:
        self._sigma    = sigma
        self._interval = interval_seconds
        self._running  = False
        self._thread   : Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "siemulate-rule-reload",
            daemon = True,
        )
        self._thread.start()
        logger.info(
            f"RuleReloadScheduler started - "
            f"interval={self._interval}s"
        )

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                count = self._sigma.reload_rules()
                logger.debug(f"Rule reload: {count} rules loaded.")
            except Exception as e:
                logger.error(f"Rule reload failed: {e}")


class RiskDecayScheduler:
    """
    Applies risk score decay to all entities on a configurable interval.
    Quiet entities cool down - active threats stay elevated.
    """

    def __init__(
        self,
        correlation     : CorrelationEngine,
        interval_hours  : int,
    ) -> None:
        self._correlation = correlation
        self._interval    = interval_hours * 3600
        self._running     = False
        self._thread      : Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "siemulate-risk-decay",
            daemon = True,
        )
        self._thread.start()
        logger.info(
            f"RiskDecayScheduler started - "
            f"interval={self._interval // 3600}h"
        )

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self._correlation.decay_risk_scores()
            except Exception as e:
                logger.error(f"Risk decay failed: {e}")


class ArchiveScheduler:
    """
    Archives old alerts and chains to Parquet on a configurable interval.
    """

    def __init__(self, db: Database, settings: Settings) -> None:
        self._db       = db
        self._interval = settings.archive_interval_hours * 3600
        self._running  = False
        self._thread   : Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "siemulate-archive",
            daemon = True,
        )
        self._thread.start()
        logger.info(
            f"ArchiveScheduler started - "
            f"interval={self._interval // 3600}h"
        )

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                alerts_archived = self._db.archive_old_alerts()
                chains_archived = self._db.archive_old_chains()
                logger.info(
                    f"Archive complete - "
                    f"alerts={alerts_archived} chains={chains_archived}"
                )
            except Exception as e:
                logger.error(f"Archive failed: {e}")


# ── Application Bootstrap ─────────────────────────────────────────────────────

class SIEMulate:
    """
    Top-level application class.
    Owns all engine instances and coordinates startup / shutdown.
    """

    def __init__(self) -> None:
        self._settings   = Settings()
        self._started_at = datetime.now(timezone.utc)

        # ── Engine instances ──────────────────────────────────────────────────
        self._db          = Database(self._settings)
        self._sigma       = SigmaEngine(self._settings, self._db)
        self._correlation = CorrelationEngine(self._settings, self._db)
        self._replay      : Optional[ReplayEngine] = None

        # ── Schedulers ────────────────────────────────────────────────────────
        self._rule_reload = RuleReloadScheduler(
            self._sigma,
            self._settings.rules_reload_interval,
        )
        self._risk_decay  = RiskDecayScheduler(
            self._correlation,
            self._settings.risk_decay_interval_hours,
        )
        self._archive     = ArchiveScheduler(self._db, self._settings)

        # ── Async ─────────────────────────────────────────────────────────────
        self._loop        : Optional[asyncio.AbstractEventLoop] = None
        self._ws_manager  : Optional[ConnectionManager]         = None

    # ── Startup ───────────────────────────────────────────────────────────────

    def startup(self) -> None:
        """Full startup sequence - called before uvicorn begins serving."""
        print(_BANNER)

        logger.info("=" * 60)
        logger.info(f"  SIEMulate v{self._settings.app_version} starting")
        logger.info(f"  Port     : {self._settings.port}")
        logger.info(f"  DB       : {self._settings.db_path}")
        logger.info(f"  Rules    : {self._settings.rules_dir}")
        logger.info(f"  LogClaw  : {self._settings.logclaw_api}")
        logger.info(f"  PS       : {self._settings.packetstrike_api}")
        logger.info(f"  AI       : {'enabled' if self._settings.ai_enabled else 'disabled'}")
        logger.info("=" * 60)

        # 1. Database
        self._db.connect()

        # 2. Sigma rules
        rule_count = self._sigma.load_rules()
        if rule_count == 0:
            logger.warning(
                "No Sigma rules loaded. "
                "Add YAML files to the rules/ directory and call POST /rules/reload. "
                "Download community rules from https://github.com/SigmaHQ/sigma"
            )

        # 3. Correlation engine (loads entity + chain state from DB)
        self._correlation.start()

        # 4. Schedulers
        self._rule_reload.start()
        self._risk_decay.start()
        self._archive.start()

        logger.info("Startup complete - SIEMulate ready.")

    def build_app(self):
        """Build the FastAPI app after startup() completes."""
        self._loop = asyncio.get_event_loop()

        # Wire replay engine with WebSocket broadcast
        def _broadcast_alert(alert):
            if self._ws_manager and self._loop:
                payload = {
                    "type": "alert",
                    "data": alert.model_dump(mode="json"),
                }
                asyncio.run_coroutine_threadsafe(
                    self._ws_manager.broadcast(payload),
                    self._loop,
                )

        self._replay = ReplayEngine(
            settings    = self._settings,
            db          = self._db,
            sigma       = self._sigma,
            correlation = self._correlation,
            broadcast_fn= _broadcast_alert,
            ws_loop     = self._loop,
        )

        app, self._ws_manager = create_app(
            settings             = self._settings,
            db                   = self._db,
            sigma                = self._sigma,
            correlation          = self._correlation,
            replay_engine        = self._replay,
            sigma_stats_fn       = lambda: self._sigma.stats,
            correlation_stats_fn = lambda: self._correlation.stats,
            started_at           = self._started_at,
        )

        @app.on_event("shutdown")
        async def on_shutdown() -> None:
            self.shutdown()

        return app

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """Graceful shutdown - flushes all state to DuckDB."""
        logger.info("SIEMulate shutting down...")

        if self._replay and self._replay.is_running:
            self._replay.stop_replay()

        self._rule_reload.stop()
        self._risk_decay.stop()
        self._archive.stop()

        self._correlation.stop()
        self._db.close()

        logger.info("SIEMulate shutdown complete.")


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    settings = Settings()
    _setup_logging(settings)

    app_instance = SIEMulate()
    app_instance.startup()
    app = app_instance.build_app()

    def _handle_signal(sig, frame):
        logger.info(f"Signal {sig} received - initiating shutdown.")
        app_instance.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    uvicorn.run(
        app,
        host      = settings.host,
        port      = settings.port,
        log_level = settings.log_level.lower(),
        reload    = False,
    )


if __name__ == "__main__":
    main()