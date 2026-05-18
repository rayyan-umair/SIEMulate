"""
SIEMulate - Configuration
config.py - Settings, environment variables, .env file loading

Author  : Rayyan Umair
Date    : 13 May, 2026
Purpose : Centralised configuration for SIEMulate. All settings are
          read from environment variables or a .env file with sensible
          defaults. Every setting is documented. Nothing is hardcoded
          anywhere else in the codebase - always import from here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
from pathlib import Path
from typing import List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Base Paths ────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
LOGS_DIR    = BASE_DIR / "logs"
RULES_DIR   = BASE_DIR / "rules"
REPLAY_DIR  = BASE_DIR / "replay"

DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
RULES_DIR.mkdir(exist_ok=True)
REPLAY_DIR.mkdir(exist_ok=True)


# ── Settings ──────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    """
    All SIEMulate configuration.
    Values are loaded from environment variables or .env file.
    Defaults are production-safe and work out of the box.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────

    app_name: str = Field(
        default="SIEMulate",
        description="Application name shown in logs and API responses",
    )
    app_version: str = Field(
        default="1.0.0",
        description="Application version",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode - verbose logging, auto-reload",
    )

    # ── Server ────────────────────────────────────────────────────────────────

    host: str = Field(
        default="0.0.0.0",
        description="Host to bind the FastAPI server",
    )
    port: int = Field(
        default=8002,
        description="Port to bind the FastAPI server (8002 - LogClaw=8000, PacketStrike=8001)",
    )

    # ── Storage ───────────────────────────────────────────────────────────────

    db_path: str = Field(
        default=str(DATA_DIR / "siemulate.duckdb"),
        description="Path to DuckDB persistent database file",
    )
    parquet_dir: str = Field(
        default=str(DATA_DIR / "parquet"),
        description="Directory for Parquet historical archive files",
    )
    retention_days: int = Field(
        default=90,
        description="Days to retain alert records before archiving to Parquet",
    )
    archive_interval_hours: int = Field(
        default=24,
        description="Hours between Parquet archiving runs",
    )

    # ── Sigma Rules ───────────────────────────────────────────────────────────

    rules_dir: str = Field(
        default=str(RULES_DIR),
        description="Directory containing Sigma YAML rule files",
    )
    rules_reload_interval: int = Field(
        default=300,
        description="Seconds between automatic Sigma rule reloads from disk",
    )
    rules_enabled: bool = Field(
        default=True,
        description="Master switch - disable to run in passive/replay-only mode",
    )

    # ── Risk Scoring ──────────────────────────────────────────────────────────

    risk_threshold_critical: int = Field(
        default=75,
        description="Risk score (0-100) at which an entity is escalated to CRITICAL",
    )
    risk_threshold_high: int = Field(
        default=50,
        description="Risk score at which an entity is escalated to HIGH",
    )
    risk_threshold_medium: int = Field(
        default=25,
        description="Risk score at which an entity is escalated to MEDIUM",
    )
    risk_decay_interval_hours: int = Field(
        default=24,
        description="Hours before entity risk score begins decaying toward baseline",
    )
    risk_decay_rate: float = Field(
        default=0.05,
        description="Risk score decay per interval (0.0-1.0 as fraction of current score)",
    )

    # ── Correlation Engine ────────────────────────────────────────────────────

    entity_lookback_minutes: int = Field(
        default=60,
        description="Sliding window in minutes for entity correlation",
    )
    attack_chain_window_minutes: int = Field(
        default=15,
        description="Rules firing within this window on same entity trigger attack chain escalation",
    )
    attack_chain_min_rules: int = Field(
        default=2,
        description="Minimum distinct rules required to form an attack chain",
    )
    alert_cooldown_seconds: int = Field(
        default=60,
        description="Seconds before the same rule can re-alert on the same entity",
    )
    max_timeline_events: int = Field(
        default=500,
        description="Maximum timeline events stored per entity before oldest are pruned",
    )

    # ── Replay Engine ─────────────────────────────────────────────────────────

    replay_dir: str = Field(
        default=str(REPLAY_DIR),
        description="Directory for uploaded replay JSON log files",
    )
    replay_speed_multiplier: float = Field(
        default=10.0,
        description="Speed multiplier for replay - 10x means 10 seconds of logs per real second",
    )
    replay_batch_size: int = Field(
        default=100,
        description="Number of log events to process per replay tick",
    )

    # ── Integration - NetRaptor Ecosystem ─────────────────────────────────────

    logclaw_api: str = Field(
        default="http://localhost:8000",
        description="LogClaw API base URL - log ingestion source",
    )
    packetstrike_api: str = Field(
        default="http://localhost:8001",
        description="PacketStrike API base URL - network behavior source",
    )
    dnstalon_api: str = Field(
        default="http://localhost:8003",
        description="DNStalon API base URL - DNS behavior source (future)",
    )
    ecosystem_poll_interval: int = Field(
        default=30,
        description="Seconds between polling LogClaw and PacketStrike for new events",
    )
    ecosystem_enabled: bool = Field(
        default=False,
        description="Enable live polling of LogClaw/PacketStrike - False for standalone mode",
    )

    # ── WebSocket ─────────────────────────────────────────────────────────────

    ws_max_connections: int = Field(
        default=50,
        description="Maximum concurrent WebSocket connections",
    )
    ws_heartbeat_interval: int = Field(
        default=30,
        description="Seconds between WebSocket heartbeat pings",
    )

    # ── AI Layer ──────────────────────────────────────────────────────────────

    ai_enabled: bool = Field(
        default=False,
        description="Master switch for AI features",
    )
    ai_provider: Optional[str] = Field(
        default=None,
        description="AI provider: anthropic | openai | gemini | groq | ollama | None",
    )
    ai_api_key: Optional[str] = Field(
        default=None,
        description="API key for the chosen AI provider",
    )
    ai_model: Optional[str] = Field(
        default=None,
        description="Model override - uses provider default if not set",
    )
    ai_max_tokens: int = Field(
        default=800,
        description="Maximum tokens per AI response",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for Ollama local AI server",
    )
    ollama_model: str = Field(
        default="llama3",
        description="Ollama model name for local AI",
    )

    # ── Security ──────────────────────────────────────────────────────────────

    secret_key: str = Field(
        default="change-this-in-production-siemulate-secret-key-2026",
        description="Secret key for JWT signing - MUST be changed in production",
    )
    allow_anonymous: bool = Field(
        default=True,
        description="Allow unauthenticated API access - True for local-only deployments",
    )

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v = v.upper()
        if v not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid = {"anthropic", "openai", "gemini", "groq", "ollama"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"ai_provider must be one of {valid}")
        return v

    @field_validator("risk_decay_rate")
    @classmethod
    def validate_decay_rate(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("risk_decay_rate must be between 0.0 and 1.0")
        return v

    # ── Derived Properties ────────────────────────────────────────────────────

    @property
    def parquet_path(self) -> Path:
        p = Path(self.parquet_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_ai_configured(self) -> bool:
        if not self.ai_enabled:
            return False
        if self.ai_provider == "ollama":
            return True
        return bool(self.ai_api_key)

    @property
    def effective_model(self) -> Optional[str]:
        if self.ai_model:
            return self.ai_model
        defaults = {
            "anthropic": "claude-haiku-4-5-20251001",
            "openai":    "gpt-4o",
            "gemini":    "gemini-2.0-flash",
            "groq":      "llama-3.1-8b-instant",
            "ollama":    self.ollama_model,
        }
        return defaults.get(self.ai_provider or "", None)

    @property
    def attack_chain_window_seconds(self) -> int:
        return self.attack_chain_window_minutes * 60

    @property
    def entity_lookback_seconds(self) -> int:
        return self.entity_lookback_minutes * 60


# ── .env.example Generator ────────────────────────────────────────────────────

def generate_env_example():
    lines = [
        "# SIEMulate - Environment Configuration",
        "# Copy this file to .env and fill in your values",
        "# Built by Rayyan Umair - Context is the only defense.",
        "",
        "# ── Application ──────────────────────────────────────",
        "LOG_LEVEL=INFO",
        "DEBUG=false",
        "",
        "# ── Server ───────────────────────────────────────────",
        "HOST=0.0.0.0",
        "PORT=8002",
        "",
        "# ── Storage ──────────────────────────────────────────",
        "DB_PATH=./data/siemulate.duckdb",
        "PARQUET_DIR=./data/parquet",
        "RETENTION_DAYS=90",
        "",
        "# ── Sigma Rules ──────────────────────────────────────",
        "RULES_DIR=./rules",
        "RULES_RELOAD_INTERVAL=300",
        "RULES_ENABLED=true",
        "",
        "# ── Risk Scoring ─────────────────────────────────────",
        "RISK_THRESHOLD_CRITICAL=75",
        "RISK_THRESHOLD_HIGH=50",
        "RISK_THRESHOLD_MEDIUM=25",
        "",
        "# ── Correlation ──────────────────────────────────────",
        "ENTITY_LOOKBACK_MINUTES=60",
        "ATTACK_CHAIN_WINDOW_MINUTES=15",
        "ATTACK_CHAIN_MIN_RULES=2",
        "ALERT_COOLDOWN_SECONDS=60",
        "",
        "# ── Replay Engine ────────────────────────────────────",
        "REPLAY_SPEED_MULTIPLIER=10.0",
        "REPLAY_BATCH_SIZE=100",
        "",
        "# ── Ecosystem Integration ────────────────────────────",
        "ECOSYSTEM_ENABLED=false",
        "LOGCLAW_API=http://localhost:8000",
        "PACKETSTRIKE_API=http://localhost:8001",
        "ECOSYSTEM_POLL_INTERVAL=30",
        "",
        "# ── AI Layer ─────────────────────────────────────────",
        "AI_ENABLED=false",
        "# AI_PROVIDER=groq",
        "# AI_API_KEY=your-api-key-here",
        "",
        "# ── Security ─────────────────────────────────────────",
        "SECRET_KEY=change-this-in-production-siemulate-secret-key-2026",
        "ALLOW_ANONYMOUS=true",
        "",
    ]
    env_example = BASE_DIR / ".env.example"
    env_example.write_text("\n".join(lines))
    print(f"Written: {env_example}")


if __name__ == "__main__":
    generate_env_example()
    settings = Settings()
    print(f"\nLoaded settings:")
    print(f"  Port              : {settings.port}")
    print(f"  DB path           : {settings.db_path}")
    print(f"  Rules dir         : {settings.rules_dir}")
    print(f"  Risk critical thr : {settings.risk_threshold_critical}")
    print(f"  Chain window      : {settings.attack_chain_window_minutes}m")
    print(f"  Ecosystem enabled : {settings.ecosystem_enabled}")
    print(f"  AI enabled        : {settings.ai_enabled}")
    print(f"  Log level         : {settings.log_level}")