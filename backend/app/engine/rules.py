"""Fast, deterministic multilingual rule & URL heuristic engine (Spec Section 10 Step 3 & 4).

Works completely offline (0ms external dependency) and provides both:
1. Immediate scam signals for merging with AI models
2. Reliable 100% uptime fallback when no AI API key is configured or AI is down
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from urllib.parse import urlparse

# Zero-width characters scammers insert to evade filters
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")

# URL extraction: full http(s) URLs + www. + bare suspicious domains/shorteners
_URL_RE = re.compile(
    r"""(?ix)
    \b(
        https?://[^\s<>'"]+
        | www\.[^\s<>'"]+
        | (?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|shorturl\.at)/[a-z0-9_-]+
        | [a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?\.(?:xyz|top|click|buzz|icu|vip|win|loan|tk|ml|cf|gq|work|rest)(?:/[^\s<>'"]*)?
    )
    """
)

_PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s-]?)?(?:\d[\s-]?){9,12}\d")

# Suspicious URL shorteners & high-risk TLDs
_SHORTENER_DOMAINS: set[str] = {
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "t.co",
    "shorturl.at",
    "ow.ly",
    "tiny.cc",
    "rebrand.ly",
}

_SUSPICIOUS_TLDS: set[str] = {
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".icu",
    ".vip",
    ".win",
    ".loan",
    ".tk",
    ".ml",
    ".cf",
    ".gq",
    ".work",
    ".rest",
    ".monster",
    ".sbs",
}

_BRAND_BAIT_TOKENS: tuple[str, ...] = (
    "bank",
    "login",
    "verify",
    "kyc",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "paytm",
    "phonepe",
    "gpay",
    "upi",
    "reward",
    "prize",
    "claim",
    "secure",
    "update",
    "account",
    "indiapost",
    "customs",
)

# Legitimate defensive warning phrases ("Do NOT share this OTP with anyone")
_DEFENSIVE_OTP_WARNING_RE = re.compile(
    r"""(?ix)
    (
        (?:do\s+not|don'?t|never)\s+(?:share|disclose|give|forward|reveal).{0,35}\b(?:otp|pin|password|code)\b
        | किसी\s+के\s+साथ.{0,25}(?:शेयर|साझा)\s+न\s+करें
        | किसी\s+को\s+(?:न|मत)\s+बताएं
        | kisko\s+bhi\s+share\s+(?:na|mat)\s+kare
    )
    """
)


@dataclass
class RuleSignal:
    flag_id: str
    weight: int
    scam_type: str
    tactics: tuple[str, ...] = ()
    critical: bool = False


@dataclass
class RuleAnalysisResult:
    risk_score: int
    scam_type: str
    flag_ids: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    extracted_phones: list[str] = field(default_factory=list)
    critical_match: bool = False


def sanitize_text(text: str) -> str:
    """Strips zero-width obfuscation characters and normalizes excessive whitespace."""
    cleaned = _ZERO_WIDTH_RE.sub("", text)
    return cleaned.strip()


def _deobfuscate_for_matching(text: str) -> str:
    """Normalizes common leetspeak tricks like '0TP' or 'O.T.P' for pattern matching."""
    lowered = text.lower()
    lowered = re.sub(r"\bo[\.\-\s]?t[\.\-\s]?p\b", "otp", lowered)
    lowered = re.sub(r"\b0tp\b", "otp", lowered)
    lowered = lowered.replace("hxxp://", "http://").replace("hxxps://", "https://")
    return lowered


def extract_urls(text: str, extra_urls: list[str] | None = None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(text):
        raw_url = match.group(1).rstrip(".,!?;:)>]\"'")
        if raw_url.lower() not in seen:
            seen.add(raw_url.lower())
            found.append(raw_url)

    for item in extra_urls or []:
        cleaned = item.strip()
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            found.append(cleaned)

    return found


def extract_phones(text: str, extra_phones: list[str] | None = None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    for match in _PHONE_RE.finditer(text):
        raw = match.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        if 10 <= len(digits) <= 13 and digits not in seen:
            seen.add(digits)
            found.append(raw)

    for item in extra_phones or []:
        digits = re.sub(r"\D", "", item)
        if 7 <= len(digits) <= 15 and digits not in seen:
            seen.add(digits)
            found.append(item.strip())

    return found


# ---------------------------------------------------------------------------
# Multilingual Pattern Definitions
# ---------------------------------------------------------------------------
_PATTERN_RULES: tuple[tuple[re.Pattern[str], RuleSignal], ...] = (
    # 1. Malicious OTP / PIN solicitation (English + Hindi/Hinglish + KN/TA/TE/BN/SW)
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:send|share|reply(?:\s+with)?|forward|give|tell|submit|enter|verify|provide|confirm)\b.{0,30}\b(?:your\s+)?(?:otp|mpin|upi\s*pin|atm\s*pin|secret\s*code)\b
                | \b(?:otp|upi\s*pin|mpin)\b.{0,25}\b(?:send|share|bheje|bhejein|bhejo|bataye|dijiye|do)\b
                | (?:अपना\s+)?(?:ओटीपी|otp|पिन|pin)\s*(?:भेजें|भेजो|बताएं|साझा\s*करें|शेयर\s*करें|दर्ज\s*करें)
                | (?:ಓಟಿಪಿ|otp)\s*(?:ಕಳುಹಿಸಿ|ಹಂಚಿಕೊಳ್ಳಿ|ನೀಡಿ)
                | (?:ஓடிபி|otp)\s*(?:அனுப்பவும்|பகிரவும்|சொல்லவும்)
                | (?:ఓటీపీ|otp)\s*(?:పంపండి|చెప్పండి|షేర్)
                | (?:ওটিপি|otp)\s*(?:পাঠান|শেয়ার\s*করুন|দিন)
                | \btuma\b.{0,20}\b(?:otp|siri|pin)\b
            )
            """
        ),
        RuleSignal(
            flag_id="otp_solicitation",
            weight=55,
            scam_type="bank_fraud",
            tactics=("credential_phishing",),
            critical=True,
        ),
    ),
    # 2. Password / CVV / Card details request
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:send|share|enter|confirm|update|verify)\b.{0,30}\b(?:password|cvv|card\s*number|net\s*banking|debit\s*card|credit\s*card|passcode)\b
                | (?:पासवर्ड|सीवीवी|cvv|कार्ड\s*नंबर).{0,20}(?:भेजें|बताएं|दर्ज\s*करें|अपडेट\s*करें)
            )
            """
        ),
        RuleSignal(
            flag_id="credential_request",
            weight=50,
            scam_type="phishing",
            tactics=("credential_phishing",),
            critical=True,
        ),
    ),
    # 3. Fake Prize / Lottery / Jackpot / KBC
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:congratulations|congrats)\b.{0,45}\b(?:won|winner|selected|prize|reward|cashback|gift|lottery|jackpot|\$\d+|₹\s*\d+|rs\.?\s*\d+)\b
                | \byou\s+(?:have\s+)?won\b
                | \b(?:lucky\s+draw|lucky\s+winner| lottery\s+winner|claim\s+(?:your\s+)?(?:prize|reward|bonus|cash)|kbc\s+lottery|spin\s+and\s+win)\b
                | (?:बधाई\s*हो|मुबारक\s*हो).{0,45}(?:जीता|जीते|इनाम|लॉटरी|कैशबैक|लाख|रुपये|₹)
                | (?:इनाम|लॉटरी|लकी\s*ड्रा).{0,30}(?:जीता|जीते|पाएं|क्लेम)
                | \b(?:badhai\s+ho|inam\s+jeeta|jeete\s+hain|lottery\s+lagi)\b
                | (?:ಬಹುಮಾನ|ಲಾಟರಿ)\s*(?:ಗೆದ್ದಿದ್ದೀರಿ|ಗೆದ್ದಿದ್ದಾರೆ)
                | (?:பரிசு|லாட்டரி)\s*(?:வென்றுள்ளீர்கள்|ஜெயித்துள்ளீர்கள்)
                | (?:బహుమతి|లాటరీ)\s*(?:గెలుచుకున్నారు|గెలిచారు)
                | (?:পুরস্কার|লটারি)\s*(?:জিতেছেন)
                | \bhongera\b.{0,30}\bumeshinda\b
            )
            """
        ),
        RuleSignal(
            flag_id="fake_prize",
            weight=56,
            scam_type="lottery",
            tactics=("reward",),
            critical=True,
        ),
    ),
    # 4. Fake Scholarship / Student Grant Trap
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:scholarship|student\s+grant|education\s+grant|pm\s+scholarship|free\s+laptop\s+scheme)\b
                .{0,60}
                \b(?:approved|selected|claim|processing\s+fee|registration\s+fee|apply\s+now|click|otp|bank\s+details)\b
                | (?:स्कॉलरशिप|छात्रवृत्ति|फ्री\s*लैपटॉप).{0,40}(?:पास|चयन|फीस|लिंक|आवेदन)
            )
            """
        ),
        RuleSignal(
            flag_id="scholarship_grant_scam",
            weight=45,
            scam_type="lottery",
            tactics=("reward", "authority"),
            critical=True,
        ),
    ),
    # 5. Account Blocked / Suspended / Electricity Cut Threat
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:your\s+)?(?:bank\s+)?(?:account|ac|a/c|sim\s*card|upi|netbanking|debit\s*card)\b
                .{0,30}
                \b(?:is\s+blocked|has\s+been\s+blocked|will\s+be\s+blocked|suspended|frozen|deactivated|closed|restricted|on\s+hold)\b
                | \b(?:electricity|power)\s+(?:supply|connection)\s+will\s+be\s+(?:disconnected|cut)\s+tonight\b
                | (?:आपका\s+)?(?:बैंक\s+)?(?:खाता|अकाउंट|सिम|कार्ड).{0,25}(?:ब्लॉक|बंद|सस्पेंड|फ्रीज)
                | (?:बिजली\s+कनेक्शन).{0,25}(?:काट\s+दिया\s+जाएगा|बंद\s+हो\s+जाएगा)
                | \b(?:khata|account)\s+(?:block|band)\s+(?:ho\s+jayega|kar\s+diya)\b
                | (?:ಖಾತೆ).{0,20}(?:ಬ್ಲಾಕ್|ಸ್ಥಗಿತ)
                | (?:கணக்கு).{0,20}(?:முடக்கப்படும்|நிறுத்தப்படும்)
                | (?:ఖాతా).{0,20}(?:బ్లాక్|నిలిపివేయబడుతుంది)
                | \bakaunti\s+yako\s+imefungwa\b
            )
            """
        ),
        RuleSignal(
            flag_id="account_blocked_threat",
            weight=48,
            scam_type="bank_fraud",
            tactics=("loss_aversion", "authority"),
            critical=True,
        ),
    ),
    # 6. Fake KYC / PAN / Aadhaar Update Scam
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:kyc|pan\s*card|aadhaar)\b.{0,30}\b(?:expired|incomplete|pending|update\s+immediately|verify\s+now|link\s+immediately|suspended)\b
                | \b(?:update|complete|verify)\s+(?:your\s+)?kyc\b
                | (?:केवाईसी|kyc|पैन\s*कार्ड).{0,25}(?:अपडेट|पूरा|समाप्त|लिंक\s*करें)
            )
            """
        ),
        RuleSignal(
            flag_id="kyc_scam",
            weight=38,
            scam_type="bank_fraud",
            tactics=("loss_aversion", "authority"),
        ),
    ),
    # 7. Fake Job / Internship Registration Fee Scam
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:job|internship|hiring|offer\s+letter|joining|work\s+from\s+home|part[\s-]*time)\b
                .{0,65}
                \b(?:registration\s+fee|security\s+deposit|training\s+fee|onboarding\s+fee|laptop\s+fee|processing\s+fee|refundable\s+deposit|pay\s+₹|pay\s+rs)\b
                | \b(?:registration\s+fee|security\s+deposit|training\s+fee)\b.{0,45}\b(?:job|internship|joining|offer)\b
                | (?:नौकरी|जॉब|इंटर्नशिप).{0,40}(?:रजिस्ट्रेशन\s*फीस|सिक्योरिटी\s*डिपॉजिट|शुल्क|पैसे\s*जमा)
            )
            """
        ),
        RuleSignal(
            flag_id="job_fee_scam",
            weight=54,
            scam_type="job_scam",
            tactics=("reward", "loss_aversion"),
            critical=True,
        ),
    ),
    # 8. Unrealistic Work-from-Home / YouTube/Telegram Task Scam
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:earn|make|income)\b.{0,25}(?:₹|rs\.?|\$|usd|inr)\s*\d{3,6}\s*(?:/|-|\s+per\s+|\s+every\s+)?(?:day|daily|hour|weekly)\b
                | \b(?:like\s+youtube\s+videos|subscribe\s+channels|google\s+maps\s+review|telegram\s+task|prepaid\s+task)\b.{0,40}\b(?:earn|paid|money|income|₹|rs)\b
                | \b(?:part[\s-]*time\s+job|work\s+from\s+home)\b.{0,45}\b(?:no\s+experience|daily\s+payout|whatsapp\s+now|contact\s+hr\s+on\s+telegram)\b
                | (?:घर\s+बैठे|पार्ट\s+टाइम).{0,30}(?:रोज|प्रतिदिन|कमाएं|कमायें).{0,25}(?:₹|रुपये|हजार)
                | \bghar\s+baithe\b.{0,25}\bkamaye\b
            )
            """
        ),
        RuleSignal(
            flag_id="unrealistic_job",
            weight=45,
            scam_type="job_scam",
            tactics=("reward",),
            critical=True,
        ),
    ),
    # 9. UPI PIN / QR Scan / Collect Request Trick ("Enter PIN to receive money")
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:scan\s+(?:this\s+)?qr|enter\s+(?:your\s+)?(?:upi\s+)?pin|approve\s+(?:collect\s+)?request)\b
                .{0,35}
                \b(?:to\s+receive|to\s+get|for\s+refund|cashback|credit\s+money|receive\s+payment)\b
                | \bsend\s+(?:₹|rs\.?|\$)\s*\d+\s+to\s+(?:receive|get|verify)\b
                | (?:पैसे\s+पाने|पैसे\s+प्राप्त\s+करने|रिफंड\s+पाने).{0,30}(?:पिन\s+डालें|qr\s+स्कैन|क्यूआर\s+स्कैन)
            )
            """
        ),
        RuleSignal(
            flag_id="upi_pin_trick",
            weight=62,
            scam_type="payment_scam",
            tactics=("reward", "credential_phishing"),
            critical=True,
        ),
    ),
    # 10. Fake Delivery / Customs Parcel Fee Scam
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:parcel|package|delivery|shipment|india\s*post|fedex|dhl|bluedart)\b
                .{0,50}
                \b(?:customs\s+fee|clearance\s+fee|address\s+incomplete|on\s+hold|pay\s+(?:₹|rs|\$)|update\s+address\s+link)\b
                | (?:पार्सल|डिलीवरी|कस्टम).{0,35}(?:रुका\s+हुआ|फीस|शुल्क|पता\s+अपडेट)
            )
            """
        ),
        RuleSignal(
            flag_id="delivery_fee_scam",
            weight=42,
            scam_type="payment_scam",
            tactics=("urgency", "loss_aversion"),
        ),
    ),
    # 11. Authority Impersonation / Digital Arrest / Police / Tax Warrant
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:digital\s+arrest|arrest\s+warrant|cyber\s*crime\s*police|cbi\s+officer|narcotics\s+bureau|ed\s+summon|income\s+tax\s+raid|illegal\s+parcel\s+in\s+your\s+aadhaar)\b
                | \b(?:police|court|customs|rbi|tax\s+department)\b.{0,45}\b(?:fine|penalty|arrest|legal\s+action|pay\s+immediately|transfer\s+to\s+safe\s+account)\b
                | (?:डिजिटल\s*अरेस्ट|गिरफ्तारी\s*वारंट|पुलिस\s*केस|सीबीआई|साइबर\s*पुलिस).{0,35}(?:जुर्माना|पैसे|गिरफ्तार|कार्रवाई)
            )
            """
        ),
        RuleSignal(
            flag_id="authority_threat",
            weight=58,
            scam_type="authority_impersonation",
            tactics=("authority", "loss_aversion", "urgency"),
            critical=True,
        ),
    ),
    # 12. Direct Urgent Money / Fee Transfer Demand
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:pay|transfer|deposit|send)\s+(?:processing\s+fee|claiming\s+fee|tax\s+fee|unlock\s+fee|immediately|urgently)\b
                | \btuma\s+pesa\b
                | (?:तुरंत\s+पैसे\s+भेजें|शुल्क\s+जमा\s+करें)
            )
            """
        ),
        RuleSignal(
            flag_id="payment_demand",
            weight=35,
            scam_type="payment_scam",
            tactics=("urgency",),
        ),
    ),
    # 13. Urgency / Pressure language
    (
        re.compile(
            r"""(?ix)
            (
                \b(?:immediately|urgent|urgently|act\s+now|claim\s+now|verify\s+now|within\s+\d+\s*(?:minutes?|hours?|hrs?)|last\s+warning|final\s+notice|expire\s+today|hurry\s+up)\b
                | (?:तुरंत|अभी\s+के\s+अभी|जल्द\s+से\s+जल्द|24\s*घंटे\s+के\s+अंदर|अंतिम\s+चेतावनी)
                | \b(?:turant|abhi\s+turant|haraka\s+sasa)\b
                | (?:ತಕ್ಷಣ|உடனடியாக|వెంటనే|অবিলম্বে)
            )
            """
        ),
        RuleSignal(
            flag_id="urgency_pressure",
            weight=20,
            scam_type="other",
            tactics=("urgency",),
        ),
    ),
)


def _analyze_urls(urls: list[str]) -> list[RuleSignal]:
    """Inspects extracted URLs for phishing indicators, suspicious TLDs, shorteners, and plain HTTP."""
    signals: list[RuleSignal] = []

    for raw_url in urls:
        normalized = raw_url if "://" in raw_url else f"https://{raw_url}"
        try:
            parsed = urlparse(normalized)
        except ValueError:
            continue

        host = (parsed.hostname or "").lower()
        if not host:
            continue

        # Plain unencrypted http:// explicitly typed in message
        if raw_url.lower().startswith("http://"):
            signals.append(
                RuleSignal(
                    flag_id="insecure_http_link",
                    weight=22,
                    scam_type="phishing",
                    tactics=("credential_phishing",),
                )
            )

        # URL shorteners hiding true destination
        if host in _SHORTENER_DOMAINS or any(host.endswith("." + d) for d in _SHORTENER_DOMAINS):
            signals.append(
                RuleSignal(
                    flag_id="shortened_link",
                    weight=28,
                    scam_type="phishing",
                    tactics=("credential_phishing",),
                )
            )

        # Suspicious TLDs (.xyz, .top, .click, etc.), raw IP host, or hyphenated brand bait
        has_bad_tld = any(host.endswith(tld) for tld in _SUSPICIOUS_TLDS)
        is_raw_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
        hyphen_count = host.count("-")
        has_brand_bait = any(tok in host for tok in _BRAND_BAIT_TOKENS) and (
            hyphen_count >= 1 or has_bad_tld or "fake" in host
        )

        if has_bad_tld or is_raw_ip or has_brand_bait:
            signals.append(
                RuleSignal(
                    flag_id="suspicious_link",
                    weight=46,
                    scam_type="phishing",
                    tactics=("credential_phishing",),
                    critical=True,
                )
            )

    return signals


def run_rule_engine(
    message: str,
    extra_urls: list[str] | None = None,
    extra_phones: list[str] | None = None,
) -> RuleAnalysisResult:
    """Executes deterministic rule & URL analysis on normalized input."""
    cleaned = sanitize_text(message)
    match_text = _deobfuscate_for_matching(cleaned)

    urls = extract_urls(cleaned, extra_urls)
    phones = extract_phones(cleaned, extra_phones)

    matched_signals: list[RuleSignal] = []
    seen_flags: set[str] = set()

    is_defensive_otp = bool(_DEFENSIVE_OTP_WARNING_RE.search(cleaned))

    for pattern, signal in _PATTERN_RULES:
        if pattern.search(match_text):
            # Guard against false positive on genuine bank OTP SMS ("Your OTP is 1234. Do NOT share OTP")
            if signal.flag_id == "otp_solicitation" and is_defensive_otp and not urls:
                continue
            if signal.flag_id not in seen_flags:
                seen_flags.add(signal.flag_id)
                matched_signals.append(signal)

    for url_sig in _analyze_urls(urls):
        if url_sig.flag_id not in seen_flags:
            seen_flags.add(url_sig.flag_id)
            matched_signals.append(url_sig)

    if not matched_signals:
        return RuleAnalysisResult(
            risk_score=0,
            scam_type="safe",
            flag_ids=[],
            tactics=[],
            extracted_urls=urls,
            extracted_phones=phones,
            critical_match=False,
        )

    # Compute weighted score with multi-signal synergy bonus
    raw_sum = sum(sig.weight for sig in matched_signals)
    distinct_non_trivial = sum(1 for sig in matched_signals if sig.weight >= 20)
    synergy_bonus = 10 if distinct_non_trivial >= 2 else 0
    if distinct_non_trivial >= 3:
        synergy_bonus = 18

    # Prevent lone mild urgency ("Please reply urgently about tomorrow's assignment") from becoming Suspicious/Danger
    if len(matched_signals) == 1 and matched_signals[0].flag_id == "urgency_pressure" and not urls:
        risk_score = 18
    else:
        risk_score = min(98, raw_sum + synergy_bonus)

    # Determine dominant scam_type by summing weights per category
    type_scores: dict[str, int] = {}
    for sig in matched_signals:
        if sig.scam_type != "other":
            type_scores[sig.scam_type] = type_scores.get(sig.scam_type, 0) + sig.weight

    if risk_score <= 30:
        dominant_type = "safe"
    elif type_scores:
        # Prefer specific fraud intent (bank_fraud, lottery, job_scam, payment_scam, authority_impersonation)
        # over generic phishing when weights are close
        dominant_type = max(
            type_scores.items(),
            key=lambda kv: (kv[1], 0 if kv[0] == "phishing" else 1),
        )[0]
    else:
        dominant_type = "other"

    tactics: list[str] = []
    for sig in matched_signals:
        for t in sig.tactics:
            if t not in tactics:
                tactics.append(t)

    flag_ids = [sig.flag_id for sig in matched_signals]
    critical = any(sig.critical for sig in matched_signals)

    return RuleAnalysisResult(
        risk_score=risk_score,
        scam_type=dominant_type,
        flag_ids=flag_ids,
        tactics=tactics,
        extracted_urls=urls,
        extracted_phones=phones,
        critical_match=critical,
    )
