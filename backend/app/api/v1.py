"""Version 1 REST API Endpoints implementing SCAM_SHIELD_PROJECT_SPEC.md Section 8."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.engine.language import SUPPORTED_TEMPLATE_LANGS
from app.engine.pipeline import analyze_message
from app.rate_limiter import rate_limiter
from app.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse, HealthResponse

router = APIRouter(prefix="/api/v1", tags=["Scam Shield v1"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check (Spec Section 8.1)",
)
async def health_check() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.service_name,
        version=settings.version,
    )


@router.get(
    "/meta",
    summary="Backend engine diagnostics (AI provider mode & built-in languages)",
)
async def engine_meta() -> dict[str, object]:
    settings = get_settings()
    return {
        "service": settings.service_name,
        "version": settings.version,
        "ai_provider": settings.active_ai_provider,
        "rule_engine": "enabled",
        "fallback_enabled": True,
        "max_message_length": settings.max_message_length,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
        "builtin_languages": sorted(SUPPORTED_TEMPLATE_LANGS),
    }


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input payload"},
        429: {"model": ErrorResponse, "description": "IP rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Unexpected server error"},
    },
    summary="Analyze suspicious message text (Spec Section 8.2 — CORE MVP)",
)
async def analyze_endpoint(payload: AnalyzeRequest, request: Request) -> AnalyzeResponse | JSONResponse:
    settings = get_settings()

    client_ip = _get_client_ip(request)
    allowed, retry_after = rate_limiter.check(client_ip, settings.rate_limit_per_minute)
    if not allowed:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "rate_limited",
                "message": f"Too many requests. Please wait {retry_after} seconds and try again.",
            },
        )

    return await analyze_message(req=payload, settings=settings)
