"""Centralized environment configuration for Scam Shield Backend."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend/ root or workspace root if present
_BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(_BACKEND_DIR / ".env")
load_dotenv(_BACKEND_DIR.parent / ".env")


def _parse_origins(raw: str) -> list[str]:
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


@dataclass(frozen=True)
class Settings:
    service_name: str = "scam-shield"
    version: str = "1.0.0"

    # AI Keys (Optional — smart rule-based engine runs regardless and acts as fallback)
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"

    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    ai_timeout_seconds: float = 8.0

    # Security, CORS & Rate limits
    allowed_origins: tuple[str, ...] = ()
    allow_localhost_any_port: bool = True
    rate_limit_per_minute: int = 60
    max_message_length: int = 5000

    @property
    def active_ai_provider(self) -> str:
        """Returns the primary configured AI provider, or 'rules_only' if no key is set."""
        if self.gemini_api_key:
            return "gemini"
        if self.groq_api_key:
            return "groq"
        if self.openai_api_key:
            return "openai"
        return "rules_only"


def get_settings() -> Settings:
    raw_origins = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    )
    allow_local_any = os.getenv("ALLOW_LOCALHOST_ANY_PORT", "true").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    try:
        rate_limit = max(1, int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))
    except ValueError:
        rate_limit = 60

    try:
        max_len = max(100, int(os.getenv("MAX_MESSAGE_LENGTH", "5000")))
    except ValueError:
        max_len = 5000

    try:
        ai_timeout = max(2.0, float(os.getenv("AI_TIMEOUT_SECONDS", "8.0")))
    except ValueError:
        ai_timeout = 8.0

    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash",
        groq_api_key=os.getenv("GROQ_API_KEY", "").strip(),
        groq_model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip() or "llama-3.3-70b-versatile",
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
        ai_timeout_seconds=ai_timeout,
        allowed_origins=tuple(_parse_origins(raw_origins)),
        allow_localhost_any_port=allow_local_any,
        rate_limit_per_minute=rate_limit,
        max_message_length=max_len,
    )
