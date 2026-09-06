"""PITBULL configuration — Pydantic Settings loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings. All values can be overridden with env vars."""

    # ── Application ────────────────────────────────────────────────
    app_name: str = "PITBULL"
    app_version: str = "0.8.1"
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8001

    # ── CORS ────────────────────────────────────────────────────────
    cors_origins: list[str] = [
        "http://localhost:5174",
        "http://localhost:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5173",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://0.0.0.0:8001",
    ]

    # ── Neo4j ───────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"

    # ── LLM (Ollama) ────────────────────────────────────────────────
    llm_base_url: str = "http://127.0.0.1:11434"
    llm_model: str = "qwen2.5:7b"  # LOCAL ONLY — no cloud models

    # ── Shodan ─────────────────────────────────────────────────────
    shodan_api_key: str = ""

    # ── API Key ─────────────────────────────────────────────────────
    api_key: str = "pitbull-explorer-dev-key-2026"

    # ── Crawler ─────────────────────────────────────────────────────
    crawler_max_depth: int = 3
    crawler_max_pages: int = 100
    crawler_timeout_s: int = 30
    crawler_rate_limit_ms: int = 500
    crawler_user_agent: str = "PITBULL/0.8 (+https://github.com/pitbull)"

    # ── Recon ────────────────────────────────────────────────────────
    crtsh_api: str = "https://crt.sh/?q=%s&output=json"
    wayback_api: str = "https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey"
    nvd_api: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # ── Tor ─────────────────────────────────────────────────────────
    tor_enabled: bool = True
    tor_socks_port: int = 9050
    tor_control_port: int = 9051

    # ── State ─────────────────────────────────────────────────────
    # Persistent state directory (survives reboots). Was /run/pitbull (tmpfs).
    state_dir: str = "/var/lib/pitbull"

    # ── Personality ─────────────────────────────────────────────────
    personality_openness: float = 0.7
    personality_conscientiousness: float = 0.6
    personality_extraversion: float = 0.5
    personality_agreeableness: float = 0.4
    personality_neuroticism: float = 0.3

    class Config:
        env_prefix = "PITBULL_"
        env_file = ".env"


settings = Settings()