"""Unified Scam Shield Detection Pipeline (Spec Section 6.1 & Section 10).

Designed under the 'One Brain, Many Channels' architecture:
Both `POST /api/v1/analyze` (Web/APK) and future `/webhooks/whatsapp` or `/webhooks/sms`
call `analyze_message()` directly.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid

from app.config import Settings
from app.engine.ai_analyzer import run_ai_analysis
from app.engine.language import (
    SUPPORTED_TEMPLATE_LANGS,
    detect_language,
    get_localized_copy,
    localize_flag,
    normalize_language_code,
)
from app.engine.rules import run_rule_engine, sanitize_text
from app.schemas import (
    ALLOWED_SCAM_TYPES,
    ALLOWED_TACTICS,
    AnalyzeRequest,
    AnalyzeResponse,
    DisplayBlock,
    ScamType,
    TacticType,
    VerdictEmojiType,
    VerdictType,
)

logger = logging.getLogger("scam_shield.pipeline")


class InvalidMessageError(ValueError):
    """Raised when input message fails validation limits (maps to HTTP 400)."""


def score_to_verdict(score: int) -> tuple[VerdictType, VerdictEmojiType]:
    """Single source of truth mapping risk_score (0-100) -> (verdict, emoji) per Spec Section 8.3."""
    clamped = max(0, min(100, score))
    if clamped <= 30:
        return "safe", "🟢"
    if clamped <= 65:
        return "suspicious", "🟡"
    return "danger", "🔴"


async def analyze_message(
    req: AnalyzeRequest,
    settings: Settings,
) -> AnalyzeResponse:
    """Executes Steps 1-8 of the Scam Shield detection pipeline."""
    start_ts = time.perf_counter()
    request_id = str(uuid.uuid4())

    # Step 1: Validate & sanitize input (Spec Section 8.7)
    cleaned_msg = sanitize_text(req.message)
    if not cleaned_msg:
        raise InvalidMessageError("Message cannot be empty or whitespace only.")
    if len(req.message) > settings.max_message_length:
        raise InvalidMessageError(
            f"Message exceeds maximum allowed length of {settings.max_message_length} characters."
        )

    # Step 2: Language detection & response language resolution
    detected_lang = detect_language(cleaned_msg)
    requested_lang = normalize_language_code(req.language)
    desired_response_lang = requested_lang or detected_lang

    # Step 3 & 4: Rule-based red flags + URL/phone heuristic analysis
    extra_urls = req.metadata.urls if req.metadata else None
    extra_phones = req.metadata.phone_numbers if req.metadata else None
    rule_res = run_rule_engine(
        message=cleaned_msg,
        extra_urls=extra_urls,
        extra_phones=extra_phones,
    )

    preliminary_en_flags = [localize_flag(fid, "en") for fid in rule_res.flag_ids]

    # Step 5: Optional AI structured analysis (with automatic fallback on failure/no-key)
    ai_res = await run_ai_analysis(
        settings=settings,
        message=cleaned_msg,
        response_language=desired_response_lang,
        extracted_urls=rule_res.extracted_urls,
        rule_hint_score=rule_res.risk_score,
        rule_flags=preliminary_en_flags,
    )

    # Step 6: Merge Rule Engine + AI into final risk_score, verdict, scam_type, tactics
    if ai_res is not None:
        engine_used = ai_res.provider
        if ai_res.language_detected and len(ai_res.language_detected) in (2, 3) and detected_lang == "en":
            norm_ai_lang = normalize_language_code(ai_res.language_detected)
            if norm_ai_lang:
                detected_lang = norm_ai_lang
                if not requested_lang:
                    desired_response_lang = detected_lang

        if rule_res.critical_match:
            # Safety floor: prevent prompt injection inside scam text from tricking AI into 'safe'
            merged_score = max(ai_res.risk_score, int(round(rule_res.risk_score * 0.88)))
        elif rule_res.risk_score > 0:
            merged_score = int(round(0.65 * ai_res.risk_score + 0.35 * rule_res.risk_score))
            merged_score = max(merged_score, min(ai_res.risk_score, rule_res.risk_score))
        else:
            merged_score = ai_res.risk_score
    else:
        engine_used = "rules"
        merged_score = rule_res.risk_score

    final_score = max(0, min(100, int(merged_score)))
    verdict, verdict_emoji = score_to_verdict(final_score)

    # Resolve scam_type strictly consistent with verdict
    if verdict == "safe":
        final_scam_type: ScamType = "safe"
    else:
        candidate_type = (
            ai_res.scam_type
            if (ai_res and ai_res.scam_type not in {"safe", "other"})
            else rule_res.scam_type
        )
        if candidate_type == "safe" or candidate_type not in ALLOWED_SCAM_TYPES:
            candidate_type = ai_res.scam_type if (ai_res and ai_res.scam_type in ALLOWED_SCAM_TYPES and ai_res.scam_type != "safe") else "other"
        final_scam_type = candidate_type  # type: ignore[assignment]

    # Merge tactics strictly within ALLOWED_TACTICS
    merged_tactics: list[TacticType] = []
    if verdict != "safe":
        for t in [*(rule_res.tactics), *(ai_res.tactics if ai_res else [])]:
            if t in ALLOWED_TACTICS and t not in merged_tactics:
                merged_tactics.append(t)  # type: ignore[arg-type]

    # Step 7: Build localized strings & display block
    # Only use AI's narrative copy if AI's assessment agrees with the final safety state
    ai_agrees_with_verdict = (
        ai_res is not None
        and ((verdict == "safe" and ai_res.risk_score <= 30) or (verdict != "safe" and ai_res.risk_score > 30))
    )

    if ai_res is not None and ai_agrees_with_verdict:
        final_response_lang = desired_response_lang
        fallback_copy = get_localized_copy(
            verdict=verdict,
            scam_type=final_scam_type,
            lang=desired_response_lang if desired_response_lang in SUPPORTED_TEMPLATE_LANGS else "en",
        )
        if verdict == "safe":
            red_flags: list[str] = []
        else:
            rule_localized_flags = [
                localize_flag(fid, final_response_lang) for fid in rule_res.flag_ids
            ]
            combined_flags: list[str] = []
            for flag in [*(ai_res.red_flags), *rule_localized_flags]:
                if flag and flag not in combined_flags:
                    combined_flags.append(flag)
            red_flags = combined_flags[:5]

        explanation = ai_res.explanation or str(fallback_copy["explanation"])
        safe_action = ai_res.safe_action or str(fallback_copy["safe_action"])
        headline = ai_res.headline or str(fallback_copy["headline"])
        body = ai_res.body or str(fallback_copy["body"])
        bullets = ai_res.bullets if len(ai_res.bullets) >= 2 else list(fallback_copy["bullets"])  # type: ignore[arg-type]
    else:
        # Template-based multilingual localization (also used if critical rules overruled tricked AI)
        final_response_lang = (
            desired_response_lang if desired_response_lang in SUPPORTED_TEMPLATE_LANGS else "en"
        )
        copy_pack = get_localized_copy(
            verdict=verdict,
            scam_type=final_scam_type,
            lang=final_response_lang,
        )
        red_flags = (
            []
            if verdict == "safe"
            else [localize_flag(fid, final_response_lang) for fid in rule_res.flag_ids][:5]
        )
        explanation = str(copy_pack["explanation"])
        safe_action = str(copy_pack["safe_action"])
        headline = str(copy_pack["headline"])
        body = str(copy_pack["body"])
        bullets = list(copy_pack["bullets"])  # type: ignore[arg-type]

    # Step 8: Privacy-safe telemetry log (hash prefix only, never raw message)
    elapsed_ms = round((time.perf_counter() - start_ts) * 1000, 1)
    msg_hash = hashlib.sha256(cleaned_msg.encode("utf-8")).hexdigest()[:10]
    logger.info(
        "analyze request_id=%s source=%s len=%d sha256=%s verdict=%s score=%d type=%s lang=%s->%s engine=%s ms=%.1f",
        request_id,
        req.source or "web",
        len(cleaned_msg),
        msg_hash,
        verdict,
        final_score,
        final_scam_type,
        detected_lang,
        final_response_lang,
        engine_used,
        elapsed_ms,
    )

    return AnalyzeResponse(
        request_id=request_id,
        verdict=verdict,
        verdict_emoji=verdict_emoji,
        risk_score=final_score,
        scam_type=final_scam_type,
        red_flags=red_flags,
        explanation=explanation,
        safe_action=safe_action,
        tactics=merged_tactics,
        language_detected=detected_lang,
        language_response=final_response_lang,
        display=DisplayBlock(
            headline=headline,
            body=body,
            bullets=bullets,
        ),
    )
