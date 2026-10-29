"""Strict Pydantic request/response schemas matching SCAM_SHIELD_PROJECT_SPEC.md Section 8."""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Allowed enum types from Spec Section 8.2
VerdictType = Literal["safe", "suspicious", "danger"]
VerdictEmojiType = Literal["🟢", "🟡", "🔴"]
ScamType = Literal[
    "safe",
    "phishing",
    "lottery",
    "job_scam",
    "bank_fraud",
    "payment_scam",
    "authority_impersonation",
    "other",
]
TacticType = Literal[
    "urgency",
    "authority",
    "reward",
    "loss_aversion",
    "credential_phishing",
]
SourceType = Literal["web", "whatsapp", "sms", "email", "apk"]

ALLOWED_SCAM_TYPES: set[str] = {
    "safe",
    "phishing",
    "lottery",
    "job_scam",
    "bank_fraud",
    "payment_scam",
    "authority_impersonation",
    "other",
}

ALLOWED_TACTICS: tuple[str, ...] = (
    "urgency",
    "authority",
    "reward",
    "loss_aversion",
    "credential_phishing",
)

ALLOWED_SOURCES: set[str] = {"web", "whatsapp", "sms", "email", "apk"}


class HealthResponse(BaseModel):
    """Exact response shape for GET /api/v1/health (Spec Section 8.1)."""

    status: Literal["ok"] = "ok"
    service: str = "scam-shield"
    version: str = "1.0.0"


class AnalyzeMetadata(BaseModel):
    """Optional client-supplied metadata (Spec Section 8.2)."""

    model_config = ConfigDict(extra="ignore")

    has_url: Optional[bool] = False
    urls: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)

    @field_validator("urls", "phone_numbers", mode="before")
    @classmethod
    def coerce_none_to_list(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if item is not None and str(item).strip()]
        raise ValueError("Must be a list of strings.")


class AnalyzeRequest(BaseModel):
    """Request body for POST /api/v1/analyze (Spec Section 8.2 & 8.7)."""

    model_config = ConfigDict(extra="ignore")

    message: str = Field(
        ...,
        description="Raw text of SMS/chat/email to analyze (required, max 5000 chars).",
    )
    language: Optional[str] = Field(
        default=None,
        description="Optional ISO language code (e.g. en, hi, kn, ta, te, sw). Omit or 'auto' for auto-detect.",
    )
    source: Optional[str] = Field(
        default="web",
        description="Channel source: web | whatsapp | sms | email | apk (default: web).",
    )
    metadata: Optional[AnalyzeMetadata] = Field(
        default=None,
        description="Optional extracted URLs or phone numbers from the client.",
    )

    @field_validator("message", mode="before")
    @classmethod
    def check_message_type(cls, value: object) -> str:
        if value is None or not isinstance(value, str):
            raise ValueError("Field 'message' is required and must be a string.")
        return value

    @field_validator("language", mode="before")
    @classmethod
    def clean_language(cls, value: object) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Field 'language' must be an ISO language string (e.g. 'en', 'hi').")
        cleaned = value.strip().lower()
        if not cleaned or cleaned in {"auto", "default", "detect"}:
            return None
        if len(cleaned) > 25:
            raise ValueError("Field 'language' must be a valid short ISO code (e.g. 'en', 'hi', 'ta').")
        return cleaned

    @field_validator("source", mode="before")
    @classmethod
    def clean_source(cls, value: object) -> str:
        if value is None:
            return "web"
        if not isinstance(value, str):
            raise ValueError("Field 'source' must be one of: web, whatsapp, sms, email, apk.")
        cleaned = value.strip().lower()
        if not cleaned:
            return "web"
        if cleaned not in ALLOWED_SOURCES:
            raise ValueError("Field 'source' must be one of: web, whatsapp, sms, email, apk.")
        return cleaned


class DisplayBlock(BaseModel):
    """User-facing ready-to-render warning strings (Spec Section 8.2)."""

    headline: str
    body: str
    bullets: list[str]


class AnalyzeResponse(BaseModel):
    """Exact response contract for POST /api/v1/analyze (Spec Section 8.2)."""

    request_id: str
    verdict: VerdictType
    verdict_emoji: VerdictEmojiType
    risk_score: int = Field(..., ge=0, le=100)
    scam_type: ScamType
    red_flags: list[str]
    explanation: str
    safe_action: str
    tactics: list[TacticType]
    language_detected: str
    language_response: str
    display: DisplayBlock


class ErrorResponse(BaseModel):
    """Standard error envelope (Spec Section 8.2)."""

    error: str
    message: str
