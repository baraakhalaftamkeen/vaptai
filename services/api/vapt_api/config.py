"""Backend settings, loaded from environment (12-factor)."""
from __future__ import annotations

import json
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # enable_decoding=False stops pydantic-settings from JSON-decoding complex fields at
    # the source, so list fields like cors_origins reach our validator as the raw string.
    # This matters because sourcing .env in bash (set -a; . ./.env) strips the quotes
    # from a JSON array, leaving e.g. [http://localhost:3000] which isn't valid JSON.
    model_config = SettingsConfigDict(
        env_prefix="VAPT_", env_file=".env", extra="ignore", enable_decoding=False
    )

    # Default to SQLite for local/dev + tests; compose overrides with MariaDB.
    database_url: str = "sqlite:///./vapt_v2_dev.db"
    redis_url: str = "redis://localhost:6379/0"

    session_ttl_hours: int = 12
    session_cookie_name: str = "vapt_session"
    cookie_secure: bool = False          # True behind TLS in staging/prod
    cors_origins: list[str] = ["http://localhost:3000"]

    bootstrap_admin_user: str = "admin"
    bootstrap_admin_password: str = "change-me-on-first-run"

    default_project_name: str = "Default"

    # Where uploaded white-box source bundles are stored + extracted (BAR-27). Shared
    # between the API (writes) and the orchestrator worker (reads) on a single host.
    source_root: str = "./var/source"
    source_max_bytes: int = 200 * 1024 * 1024   # 200 MB cap per upload

    echo_sql: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, v):
        """Accept a Python list, a JSON array, or a comma-separated string — and tolerate
        the quote-stripping that bash does when .env is sourced (so `[a,b]` and `a,b`
        both work)."""
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return ["http://localhost:3000"]
            if s.startswith("["):
                try:
                    return json.loads(s)            # proper JSON array
                except json.JSONDecodeError:
                    s = s[1:-1] if s.endswith("]") else s[1:]   # bash-stripped: drop [ ]
            return [part.strip().strip('"').strip("'") for part in s.split(",") if part.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
