"""Language detection and multilingual warning templates (Spec Section 5.1 F5 & Section 12).

Supports instant zero-latency localization in:
- English (en)
- Hindi (hi) — including Hinglish auto-detection
- Kannada (kn)
- Tamil (ta)
- Telugu (te)
- Bengali (bn)
- Swahili (sw)
"""

from __future__ import annotations

import re

LANGUAGE_ALIASES: dict[str, str] = {
    "en": "en",
    "eng": "en",
    "english": "en",
    "hi": "hi",
    "hin": "hi",
    "hindi": "hi",
    "hinglish": "hi",
    "kn": "kn",
    "kan": "kn",
    "kannada": "kn",
    "ta": "ta",
    "tam": "ta",
    "tamil": "ta",
    "te": "te",
    "tel": "te",
    "telugu": "te",
    "bn": "bn",
    "ben": "bn",
    "bengali": "bn",
    "bangla": "bn",
    "sw": "sw",
    "swa": "sw",
    "swahili": "sw",
    "kiswahili": "sw",
    "ur": "ur",
    "urdu": "ur",
    "ml": "ml",
    "malayalam": "ml",
    "mr": "mr",
    "marathi": "mr",
    "gu": "gu",
    "gujarati": "gu",
    "pa": "pa",
    "punjabi": "pa",
}

SUPPORTED_TEMPLATE_LANGS: set[str] = {"en", "hi", "kn", "ta", "te", "bn", "sw"}

# Unicode script ranges for Indian & regional scripts
_SCRIPT_RANGES: tuple[tuple[str, int, int], ...] = (
    ("hi", 0x0900, 0x097F),  # Devanagari (Hindi / Marathi)
    ("bn", 0x0980, 0x09FF),  # Bengali
    ("pa", 0x0A00, 0x0A7F),  # Gurmukhi
    ("gu", 0x0A80, 0x0AFF),  # Gujarati
    ("ta", 0x0B80, 0x0BFF),  # Tamil
    ("te", 0x0C00, 0x0C7F),  # Telugu
    ("kn", 0x0C80, 0x0CFF),  # Kannada
    ("ml", 0x0D00, 0x0D7F),  # Malayalam
    ("ur", 0x0600, 0x06FF),  # Arabic / Urdu
)

_HINGLISH_WORDS: set[str] = {
    "aap",
    "aapka",
    "aapke",
    "aapne",
    "apna",
    "apne",
    "turant",
    "abhi",
    "bheje",
    "bhejein",
    "bhejo",
    "khata",
    "band",
    "inam",
    "inaam",
    "jeeta",
    "jeete",
    "badhai",
    "paisa",
    "paise",
    "rupaye",
    "kripya",
    "karein",
    "karo",
    "jayega",
    "hoga",
    "sampark",
    "naukri",
    "ghar",
    "baithe",
    "kamaye",
}

_SWAHILI_WORDS: set[str] = {
    "hongera",
    "umeshinda",
    "akaunti",
    "yako",
    "imefungwa",
    "tuma",
    "pesa",
    "zawadi",
    "haraka",
    "sasa",
    "nambari",
    "siri",
    "bofya",
    "malipo",
}


def normalize_language_code(raw: str | None) -> str | None:
    """Normalizes user-provided language strings like 'en-IN', 'Hindi', 'hi' -> ISO 639-1."""
    if not raw:
        return None
    cleaned = raw.strip().lower()
    if not cleaned or cleaned in {"auto", "default", "detect"}:
        return None
    # Strip region subtag (e.g., en-IN -> en, hi_IN -> hi)
    primary = re.split(r"[-_]", cleaned)[0]
    if cleaned in LANGUAGE_ALIASES:
        return LANGUAGE_ALIASES[cleaned]
    if primary in LANGUAGE_ALIASES:
        return LANGUAGE_ALIASES[primary]
    if len(primary) in (2, 3) and primary.isalpha():
        return primary
    return None


def detect_language(text: str) -> str:
    """Detects primary language of message via Unicode script ranges + Romanized vocabulary."""
    counts: dict[str, int] = {}
    latin_alpha = 0

    for ch in text:
        cp = ord(ch)
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            latin_alpha += 1
            continue
        for lang_code, start, end in _SCRIPT_RANGES:
            if start <= cp <= end:
                counts[lang_code] = counts.get(lang_code, 0) + 1
                break

    if counts:
        dominant_lang, top_count = max(counts.items(), key=lambda kv: kv[1])
        if top_count >= 3:
            return dominant_lang

    # Check Romanized Hindi (Hinglish) or Swahili
    tokens = set(re.findall(r"[a-zA-Z]{3,}", text.lower()))
    hi_hits = len(tokens & _HINGLISH_WORDS)
    sw_hits = len(tokens & _SWAHILI_WORDS)

    if hi_hits >= 2 and hi_hits >= sw_hits:
        return "hi"
    if sw_hits >= 2:
        return "sw"

    return "en"


# ---------------------------------------------------------------------------
# Localized Red Flag Chip Labels (concise for mobile UI chips)
# ---------------------------------------------------------------------------
RED_FLAG_LABELS: dict[str, dict[str, str]] = {
    "otp_solicitation": {
        "en": "Asks for OTP or PIN",
        "hi": "OTP या PIN मांगा गया है",
        "kn": "OTP ಅಥವಾ PIN ಕೇಳುತ್ತಿದೆ",
        "ta": "OTP அல்லது PIN கேட்கிறது",
        "te": "OTP లేదా PIN అడుగుతోంది",
        "bn": "OTP বা PIN চাওয়া হয়েছে",
        "sw": "Inaomba OTP au nambari ya siri",
    },
    "credential_request": {
        "en": "Asks for password or card details",
        "hi": "पासवर्ड या कार्ड विवरण मांगा गया",
        "kn": "ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ ಕಾರ್ಡ್ ವಿವರ ಕೇಳಿದೆ",
        "ta": "கடவுச்சொல் அல்லது கார்டு விவரம் கேட்கிறது",
        "te": "పాస్‌వర్డ్ లేదా కార్డ్ వివరాలు అడుగుతోంది",
        "bn": "পাসওয়ার্ড বা কার্ডের তথ্য চাওয়া হয়েছে",
        "sw": "Inaomba nenosiri au taarifa za benki",
    },
    "fake_prize": {
        "en": "Fake lottery or prize claim",
        "hi": "नकली लॉटरी या इनाम का दावा",
        "kn": "ನಕಲಿ ಲಾಟರಿ ಅಥವಾ ಬಹುಮಾನದ ಆಮಿಷ",
        "ta": "போலி லாட்டரி அல்லது பரிசு ஆசை",
        "te": "నకిలీ లాటరీ లేదా బహుమతి ప్రకటన",
        "bn": "ভুয়া লটারি বা পুরস্কারের প্রলোভন",
        "sw": "Ahadi ya zawadi au bahati nasibu feki",
    },
    "account_blocked_threat": {
        "en": "Threatens account block or suspension",
        "hi": "खाता ब्लॉक या बंद होने की धमकी",
        "kn": "ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ ಎಂಬ ಬೆದರಿಕೆ",
        "ta": "கணக்கு முடக்கப்படும் என்ற மிரட்டல்",
        "te": "ఖాతా బ్లాక్ అవుతుందని బెదిరింపు",
        "bn": "অ্যাকাউন্ট ব্লক করার হুমকি",
        "sw": "Tishio la kufungiwa akaunti",
    },
    "kyc_scam": {
        "en": "Fake KYC or PAN update demand",
        "hi": "नकली KYC अपडेट की मांग",
        "kn": "ನಕಲಿ KYC ಅಪ್‌ಡೇಟ್ ಒತ್ತಾಯ",
        "ta": "போலி KYC புதுப்பிப்பு கோரிக்கை",
        "te": "నకిలీ KYC అప్‌డేట్ డిమాండ్",
        "bn": "ভুয়া KYC আপডেটের দাবি",
        "sw": "Dai feki la kusasisha akaunti",
    },
    "job_fee_scam": {
        "en": "Asks for fee to get a job",
        "hi": "नौकरी के नाम पर फीस की मांग",
        "kn": "ಕೆಲಸಕ್ಕಾಗಿ ನೋಂದಣಿ ಶುಲ್ಕ ಕೇಳುತ್ತಿದೆ",
        "ta": "வேலைக்கு பதிவு கட்டணம் கேட்கிறது",
        "te": "ఉద్యోగం కోసం రిజిస్ట్రేషన్ ఫీజు అడుగుతోంది",
        "bn": "চাকরির নামে ফি দাবি করা হয়েছে",
        "sw": "Inaomba ada ili kupata kazi",
    },
    "unrealistic_job": {
        "en": "Unrealistic easy daily earnings",
        "hi": "घर बैठे अवास्तविक कमाई का वादा",
        "kn": "ಮನೆಯಲ್ಲೇ ಸುಲಭವಾಗಿ ಭಾರೀ ಹಣ ಗಳಿಸುವ ಆಮಿಷ",
        "ta": "வீட்டிலிருந்தே அதிக வருமானம் என்ற ஆசை",
        "te": "ఇంటి నుండే భారీ ఆదాయం అనే ప్రలోభం",
        "bn": "ঘরে বসে অস্বাভাবিক আয়ের প্রলোভন",
        "sw": "Ahadi ya kipato kikubwa cha haraka",
    },
    "upi_pin_trick": {
        "en": "UPI / QR trick to steal money",
        "hi": "पैसे पाने के नाम पर UPI पिन धोखा",
        "kn": "ಹಣ ಪಡೆಯಲು UPI ಪಿನ್ ಹಾಕುವ ಮೋಸ",
        "ta": "பணம் பெற UPI பின் கேட்கும் மோசடி",
        "te": "డబ్బు పొందడానికి UPI పిన్ అడిగే మోసం",
        "bn": "টাকা পাওয়ার নামে UPI পিন প্রতারণা",
        "sw": "Udanganyifu wa malipo ya simu",
    },
    "payment_demand": {
        "en": "Demands urgent money or fee transfer",
        "hi": "तुरंत पैसे या शुल्क भेजने की मांग",
        "kn": "ತಕ್ಷಣ ಹಣ ಕಳುಹಿಸಲು ಒತ್ತಾಯ",
        "ta": "உடனடியாக பணம் அனுப்பக் கோரிக்கை",
        "te": "వెంటనే డబ్బు పంపాలని ఒత్తిడి",
        "bn": "জরুরি টাকা পাঠানোর দাবি",
        "sw": "Inadai kutuma pesa haraka",
    },
    "authority_threat": {
        "en": "Impersonates police, CBI, or officials",
        "hi": "पुलिस या सरकारी अधिकारी बनकर धमकी",
        "kn": "ಪೊಲೀಸ್ ಅಥವಾ ಅಧಿಕಾರಿಗಳ ಹೆಸರಿನಲ್ಲಿ ಬೆದರಿಕೆ",
        "ta": "காவல்துறை அல்லது அதிகாரி பெயரில் மிரட்டல்",
        "te": "పోలీసు లేదా అధికారుల పేరుతో బెదిరింపు",
        "bn": "পুলিশ বা সরকারি কর্মকর্তার ছদ্মবেশে হুমকি",
        "sw": "Inajifanya polisi au mamlaka ya serikali",
    },
    "suspicious_link": {
        "en": "Suspicious or fake website link",
        "hi": "संदिग्ध या नकली वेबसाइट लिंक",
        "kn": "ಅನುಮಾನಾಸ್ಪದ ಅಥವಾ ನಕಲಿ ಲಿಂಕ್",
        "ta": "சந்தேகத்திற்குரிய போலி இணைய இணைப்பு",
        "te": "అనుమానాస్పద లేదా నకిలీ వెబ్‌సైట్ లింక్",
        "bn": "সন্দেহজনক বা ভুয়া ওয়েবসাইট লিংক",
        "sw": "Kiungo (link) cha tovuti feki",
    },
    "shortened_link": {
        "en": "Hidden shortened URL link",
        "hi": "छुपा हुआ शॉर्ट लिंक (URL)",
        "kn": "ಮರೆಮಾಡಿದ ಚಿಕ್ಕ ಲಿಂಕ್ (Short URL)",
        "ta": "மறைக்கப்பட்ட குறுகிய இணைப்பு (Short URL)",
        "te": "దాచిన షార్ట్ లింక్ (Short URL)",
        "bn": "লুকানো শর্ট লিংক (URL)",
        "sw": "Kiungo kilichofupishwa",
    },
    "insecure_http_link": {
        "en": "Unencrypted HTTP link",
        "hi": "असुरक्षित HTTP लिंक",
        "kn": "ಅಸುರಕ್ಷಿತ HTTP ಲಿಂಕ್",
        "ta": "பாதுகாப்பற்ற HTTP இணைப்பு",
        "te": "అసురక్షిత HTTP లింక్",
        "bn": "অসুরক্ষিত HTTP লিংক",
        "sw": "Kiungo kisicho salama cha HTTP",
    },
    "urgency_pressure": {
        "en": "Creates panic or extreme urgency",
        "hi": "तुरंत कार्रवाई करने का दबाव",
        "kn": "ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳುವಂತೆ ಒತ್ತಡ",
        "ta": "உடனே செயல்படுமாறு அவசரப்படுத்துகிறது",
        "te": "వెంటనే స్పందించాలని ఒత్తిడి చేస్తోంది",
        "bn": "তাড়াহুড়ো বা আতঙ্ক সৃষ্টি করছে",
        "sw": "Inatia hofu na haraka kubwa",
    },
    "scholarship_grant_scam": {
        "en": "Fake scholarship or grant fee trap",
        "hi": "नकली स्कॉलरशिप या अनुदान का झांसा",
        "kn": "ನಕಲಿ ವಿದ್ಯಾರ್ಥಿವೇತನದ ಆಮಿಷ",
        "ta": "போலி கல்வி உதவித்தொகை மோசடி",
        "te": "నకిలీ స్కాలర్‌షిప్ మోసం",
        "bn": "ভুয়া স্কলারশিপের ফাঁদ",
        "sw": "Udanganyifu wa ufadhili wa masomo",
    },
    "delivery_fee_scam": {
        "en": "Fake parcel or customs fee request",
        "hi": "पार्सल या कस्टम शुल्क का नकली संदेश",
        "kn": "ನಕಲಿ ಪಾರ್ಸೆಲ್ ಅಥವಾ ಕಸ್ಟಮ್ಸ್ ಶುಲ್ಕ",
        "ta": "போலி பார்சல் கட்டண மோசடி",
        "te": "నకిలీ పార్శిల్ లేదా కస్టమ్స్ ఫీజు",
        "bn": "ভুয়া পার্সেল বা কাস্টমস ফি দাবি",
        "sw": "Dai feki la ada ya mzigo",
    },
}


# ---------------------------------------------------------------------------
# Localized Verdict & Scam-Type Templates
# ---------------------------------------------------------------------------
VERDICT_TEMPLATES: dict[str, dict[str, dict[str, object]]] = {
    "en": {
        "safe": {
            "headline": "Looks Safe — No Scam Signals Found",
            "explanation": "This message looks like normal communication and does not ask for OTPs, passwords, or suspicious payments.",
            "safe_action": "No action needed. Still avoid sharing OTPs or passwords with anyone.",
            "body": "We did not detect urgent threats, fake links, or requests for secret codes in this message.",
            "bullets": [
                "Looks like an ordinary message",
                "Never share OTP or UPI PIN if asked later",
                "Verify with the sender if anything feels unusual",
            ],
        },
        "suspicious": {
            "headline": "Be Careful — Suspicious Message",
            "explanation": "This message contains warning signs often used in scams, such as unusual links, money requests, or urgency.",
            "safe_action": "Do not click links or send money. Verify directly through an official app or known number.",
            "body": "Pause before replying. Scammers try to make you act fast before you can double-check.",
            "bullets": [
                "Do not click unknown links",
                "Never share OTP, PIN, or passwords",
                "Check directly using the official app or helpline",
            ],
        },
        "danger": {
            "headline": "High Scam Risk — Do Not Reply or Pay!",
            "explanation_by_type": {
                "lottery": "Real lotteries and prizes never ask for an OTP, bank PIN, or claiming fee. This is a fake prize trap.",
                "bank_fraud": "Real banks never ask you to share an OTP or click untrusted links to unblock your account.",
                "phishing": "This message uses a fake link or impersonation trick to steal your login details or money.",
                "job_scam": "Legitimate employers never charge registration fees or offer huge daily pay for simple phone tasks.",
                "payment_scam": "You never need to enter a UPI PIN or scan a QR code to receive money. Entering your PIN sends money out.",
                "authority_impersonation": "Police, courts, and government agencies never demand money on WhatsApp/SMS or conduct 'digital arrests'.",
                "other": "This message shows strong scam patterns trying to trick you into sharing secret codes or money.",
            },
            "safe_action": "Do not reply, click any link, or share OTP/money. Block and report the sender immediately.",
            "body": "Stop! This message strongly matches known scam tactics targeting students and earners. Protect your account and money.",
            "bullets": [
                "Do NOT share OTP, password, or UPI PIN",
                "Do NOT click links or send any fee/money",
                "Block the sender and report on 1930 / cybercrime.gov.in",
            ],
        },
    },
    "hi": {
        "safe": {
            "headline": "सुरक्षित लगता है — कोई धोखाधड़ी के संकेत नहीं मिले",
            "explanation": "यह एक सामान्य संदेश लगता है। इसमें OTP, पासवर्ड या संदिग्ध पैसे की मांग नहीं की गई है।",
            "safe_action": "चिंता की बात नहीं है, लेकिन कभी भी किसी के साथ OTP या UPI पिन शेयर न करें।",
            "body": "हमें इस संदेश में कोई नकली लिंक, धमकी या गुप्त कोड मांगने के संकेत नहीं मिले।",
            "bullets": [
                "यह एक सामान्य संदेश दिखता है",
                "भविष्य में भी किसी को OTP या UPI पिन न बताएं",
                "शक होने पर सीधे व्यक्ति या आधिकारिक नंबर से पूछें",
            ],
        },
        "suspicious": {
            "headline": "सावधान रहें — यह संदेश संदिग्ध है",
            "explanation": "इस संदेश में अनजान लिंक, जल्दबाजी या पैसे से जुड़े कुछ संदिग्ध संकेत मिले हैं।",
            "safe_action": "किसी लिंक पर क्लिक न करें और पैसे न भेजें। पहले आधिकारिक ऐप या नंबर से जांच करें।",
            "body": "जवाब देने से पहले रुकें। ठग आपको बिना सोचे-समझे जल्दी कदम उठाने के लिए मजबूर करते हैं।",
            "bullets": [
                "अनजान लिंक पर क्लिक न करें",
                "अपना OTP, पिन या पासवर्ड किसी को न दें",
                "आधिकारिक बैंक/कंपनी ऐप से सीधे जांच करें",
            ],
        },
        "danger": {
            "headline": "खतरा! यह स्कैम (धोखाधड़ी) हो सकता है — जवाब न दें!",
            "explanation_by_type": {
                "lottery": "असली इनाम या लॉटरी के लिए कभी भी OTP, पिन या फीस नहीं मांगी जाती। यह ठगी का जाल है।",
                "bank_fraud": "कोई भी असली बैंक खाता चालू रखने के लिए आपसे OTP नहीं मांगता और न ही संदिग्ध लिंक भेजता है।",
                "phishing": "यह संदेश नकली लिंक के जरिए आपकी बैंक जानकारी या पासवर्ड चुराने की कोशिश कर रहा है।",
                "job_scam": "असली कंपनियां नौकरी देने के लिए रजिस्ट्रेशन फीस नहीं मांगतीं और न ही आसान टास्क के हजारों रुपये देती हैं।",
                "payment_scam": "पैसे प्राप्त करने के लिए कभी भी UPI पिन डालने या QR स्कैन करने की जरूरत नहीं होती। पिन डालने से पैसे कट जाते हैं।",
                "authority_impersonation": "पुलिस, CBI या कोर्ट कभी भी फोन/मैसेज पर पैसे नहीं मांगते और 'डिजिटल अरेस्ट' जैसा कुछ नहीं होता।",
                "other": "इस संदेश में ठगी के गंभीर संकेत हैं जो आपका पैसा या गुप्त कोड चुराने के लिए बनाए गए हैं।",
            },
            "safe_action": "कोई जवाब न दें, लिंक न खोलें और OTP या पैसे बिल्कुल न भेजें। भेजने वाले को तुरंत ब्लॉक करें।",
            "body": "रुकिए! यह संदेश छात्रों और कामकाजी लोगों को ठगने वाले स्कैम जैसा है। अपना OTP और पैसा सुरक्षित रखें।",
            "bullets": [
                "OTP, पासवर्ड या UPI पिन किसी के साथ शेयर न करें",
                "किसी लिंक पर क्लिक न करें और पैसे न भेजें",
                "नंबर को ब्लॉक करें और 1930 पर साइबर शिकायत करें",
            ],
        },
    },
    "kn": {
        "safe": {
            "headline": "ಸುರಕ್ಷಿತವಾಗಿದೆ — ಯಾವುದೇ ವಂಚನೆಯ ಲಕ್ಷಣಗಳಿಲ್ಲ",
            "explanation": "ಇದು ಸಾಮಾನ್ಯ ಸಂದೇಶದಂತೆ ಕಾಣುತ್ತದೆ. ಇದರಲ್ಲಿ OTP, ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ ಹಣದ ಬೇಡಿಕೆ ಇಲ್ಲ.",
            "safe_action": "ಯಾವುದೇ ಆತಂಕ ಬೇಡ. ಆದರೆ ನಿಮ್ಮ OTP ಅಥವಾ UPI ಪಿನ್ ಅನ್ನು ಯಾರಿಗೂ ನೀಡಬೇಡಿ.",
            "body": "ಈ ಸಂದೇಶದಲ್ಲಿ ನಕಲಿ ಲಿಂಕ್ ಅಥವಾ ಬೆದರಿಕೆ ಕಂಡುಬಂದಿಲ್ಲ.",
            "bullets": [
                "ಸಾಮಾನ್ಯ ಸಂದೇಶದಂತೆ ಕಾಣುತ್ತದೆ",
                "OTP ಅಥವಾ UPI ಪಿನ್ ಯಾರಿಗೂ ಹೇಳಬೇಡಿ",
                "ಅನುಮಾನವಿದ್ದರೆ ನೇರವಾಗಿ ಪರಿಶೀಲಿಸಿ",
            ],
        },
        "suspicious": {
            "headline": "ಎಚ್ಚರಿಕೆ — ಈ ಸಂದೇಶ ಅನುಮಾನಾಸ್ಪದವಾಗಿದೆ",
            "explanation": "ಈ ಸಂದೇಶದಲ್ಲಿ ವಂಚಕರು ಬಳಸುವ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಅಥವಾ ತುರ್ತು ಒತ್ತಡದ ಲಕ್ಷಣಗಳಿವೆ.",
            "safe_action": "ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಹಣ ಕಳುಹಿಸಬೇಡಿ. ಅಧಿಕೃತ ಆಪ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
            "body": "ಪ್ರತಿಕ್ರಿಯಿಸುವ ಮೊದಲು ನಿಲ್ಲಿರಿ. ವಂಚಕರು ನಿಮ್ಮನ್ನು ಆತುರಪಡಿಸಲು ಪ್ರಯತ್ನಿಸುತ್ತಾರೆ.",
            "bullets": [
                "ಅಪರಿಚಿತ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ",
                "OTP ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
                "ಅಧಿಕೃತ ಸಹಾಯವಾಣಿ ಮೂಲಕ ದೃಢಪಡಿಸಿಕೊಳ್ಳಿ",
            ],
        },
        "danger": {
            "headline": "ಅಪಾಯ! ಇದು ವಂಚನೆಯ ಸಂದೇಶ — ಉತ್ತರಿಸಬೇಡಿ!",
            "explanation_by_type": {
                "lottery": "ನಿಜವಾದ ಬಹುಮಾನಕ್ಕಾಗಿ ಯಾರೂ OTP ಅಥವಾ ಶುಲ್ಕ ಕೇಳುವುದಿಲ್ಲ. ಇದು ನಕಲಿ ಬಹುಮಾನದ ವಂಚನೆ.",
                "bank_fraud": "ಯಾವುದೇ ಬ್ಯಾಂಕ್ ಫೋನ್ ಅಥವಾ ಲಿಂಕ್ ಮೂಲಕ OTP ಕೇಳುವುದಿಲ್ಲ. ಇದು ಬ್ಯಾಂಕ್ ವಂಚನೆಯಾಗಿದೆ.",
                "phishing": "ನಕಲಿ ಲಿಂಕ್ ಮೂಲಕ ನಿಮ್ಮ ಖಾತೆಯ ಮಾಹಿತಿ ಕದಿಯುವ ಪ್ರಯತ್ನ ಇದಾಗಿದೆ.",
                "job_scam": "ನಿಜವಾದ ಕಂಪನಿಗಳು ಕೆಲಸ ನೀಡಲು ನೋಂದಣಿ ಶುಲ್ಕ ಕೇಳುವುದಿಲ್ಲ.",
                "payment_scam": "ಹಣ ಪಡೆಯಲು UPI ಪಿನ್ ಹಾಕುವ ಅಗತ್ಯವಿಲ್ಲ. ಪಿನ್ ಹಾಕಿದರೆ ನಿಮ್ಮ ಹಣ ಕಡಿತವಾಗುತ್ತದೆ.",
                "authority_impersonation": "ಪೊಲೀಸ್ ಅಥವಾ ಅಧಿಕಾರಿಗಳು ಸಂದೇಶದ ಮೂಲಕ ಹಣ ಕೇಳುವುದಿಲ್ಲ.",
                "other": "ಈ ಸಂದೇಶವು ನಿಮ್ಮ ಹಣ ಅಥವಾ OTP ಕದಿಯಲು ಮಾಡಿದ ವಂಚನೆಯಾಗಿದೆ.",
            },
            "safe_action": "ಪ್ರತಿಕ್ರಿಯಿಸಬೇಡಿ, ಲಿಂಕ್ ಒತ್ತಬೇಡಿ ಮತ್ತು OTP/ಹಣ ಕಳುಹಿಸಬೇಡಿ. ತಕ್ಷಣ ಬ್ಲಾಕ್ ಮಾಡಿ.",
            "body": "ನಿಲ್ಲಿಸಿ! ಇದು ಮೋಸದ ಸಂದೇಶವಾಗಿದೆ. ನಿಮ್ಮ ಹಣ ಮತ್ತು ಬ್ಯಾಂಕ್ ಖಾತೆಯನ್ನು ರಕ್ಷಿಸಿಕೊಳ್ಳಿ.",
            "bullets": [
                "OTP, ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ UPI ಪಿನ್ ನೀಡಬೇಡಿ",
                "ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಹಣ ಕಳುಹಿಸಬೇಡಿ",
                "ನಂಬರ್ ಬ್ಲಾಕ್ ಮಾಡಿ ಮತ್ತು 1930 ಕ್ಕೆ ವರದಿ ಮಾಡಿ",
            ],
        },
    },
    "ta": {
        "safe": {
            "headline": "பாதுகாப்பானது — மோசடி அறிகுறிகள் இல்லை",
            "explanation": "இது சாதாரண செய்தியாகத் தெரிகிறது. இதில் OTP அல்லது பணம் கேட்கப்படவில்லை.",
            "safe_action": "கவலை வேண்டாம். எப்போதும் OTP அல்லது UPI பின்னை யாருடனும் பகிர வேண்டாம்.",
            "body": "இந்தச் செய்தியில் போலி இணைப்புகள் அல்லது மிரட்டல்கள் எதுவும் கண்டறியப்படவில்லை.",
            "bullets": [
                "சாதாரண செய்தியாகத் தெரிகிறது",
                "OTP அல்லது கடவுச்சொல்லை பகிர வேண்டாம்",
                "சந்தேகம் இருந்தால் நேரில் சரிபார்க்கவும்",
            ],
        },
        "suspicious": {
            "headline": "கவனம் — சந்தேகத்திற்குரிய செய்தி",
            "explanation": "இந்தச் செய்தியில் அவசரப்படுத்துதல் அல்லது சந்தேகத்திற்குரிய இணைப்பு போன்ற அறிகுறிகள் உள்ளன.",
            "safe_action": "இணைப்புகளைத் தொட வேண்டாம், பணம் அனுப்ப வேண்டாம். அதிகாரப்பூர்வ செயலி மூலம் சரிபார்க்கவும்.",
            "body": "பதிலளிக்கும் முன் சற்று சிந்தியுங்கள். மோசடியாளர்கள் உங்களை அவசரப்படுத்துவார்கள்.",
            "bullets": [
                "அறியாத இணைப்புகளை (Links) கிளிக் செய்ய வேண்டாம்",
                "OTP அல்லது UPI பின்னை பகிர வேண்டாம்",
                "அதிகாரப்பூர்வ எண்ணில் தொடர்பு கொண்டு சரிபார்க்கவும்",
            ],
        },
        "danger": {
            "headline": "ஆபத்து! இது மோசடிச் செய்தி — பதிலளிக்க வேண்டாம்!",
            "explanation_by_type": {
                "lottery": "உண்மையான பரிசுகளுக்கு ஒருபோதும் OTP அல்லது கட்டணம் கேட்க மாட்டார்கள். இது போலி பரிசு மோசடி.",
                "bank_fraud": "எந்த வங்கியும் கணக்கைச் செயல்படுத்த OTP அல்லது போலி இணைப்பை அனுப்பாது.",
                "phishing": "போலி இணைய இணைப்பு மூலம் உங்கள் வங்கி விவரங்களைத் திருடும் முயற்சி இது.",
                "job_scam": "உண்மையான நிறுவனங்கள் வேலை தர முன்பணம் அல்லது பதிவு கட்டணம் கேட்காது.",
                "payment_scam": "பணம் பெறுவதற்கு UPI பின் போடத் தேவையில்லை. பின் போட்டால் உங்கள் பணம் போய்விடும்.",
                "authority_impersonation": "காவல்துறை அல்லது அதிகாரிகள் வாட்ஸ்அப்/எஸ்எம்எஸ் மூலம் பணம் கேட்க மாட்டார்கள்.",
                "other": "உங்கள் பணம் அல்லது ரகசியக் குறியீட்டைத் திருட முயலும் ஆபத்தான மோசடிச் செய்தி இது.",
            },
            "safe_action": "பதிலளிக்க வேண்டாம், இணைப்பைத் தொட வேண்டாம், OTP/பணம் அனுப்ப வேண்டாம். உடனே பிளாக் (Block) செய்யவும்.",
            "body": "நிறுத்துங்கள்! இது மோசடிச் செய்தியாகும். உங்கள் பணம் மற்றும் கணக்கைப் பாதுகாத்துக் கொள்ளுங்கள்.",
            "bullets": [
                "OTP, கடவுச்சொல் அல்லது UPI பின்னை பகிர வேண்டாம்",
                "எந்த இணைப்பையும் தொட வேண்டாம், பணம் அனுப்ப வேண்டாம்",
                "எண்ணை பிளாக் செய்து 1930 எண்ணில் புகார் அளிக்கவும்",
            ],
        },
    },
    "te": {
        "safe": {
            "headline": "సురక్షితమైనది — మోసం ఆనవాళ్లు లేవు",
            "explanation": "ఇది సాధారణ సందేశంలా కనిపిస్తోంది. ఇందులో OTP లేదా డబ్బు అడగలేదు.",
            "safe_action": "ఆందోళన అవసరం లేదు. అయినప్పటికీ OTP లేదా UPI పిన్ ఎవరికీ చెప్పకండి.",
            "body": "ఈ సందేశంలో నకిలీ లింకులు లేదా బెదిరింపులు కనిపించలేదు.",
            "bullets": [
                "సాధారణ సందేశంలా కనిపిస్తోంది",
                "OTP లేదా పాస్‌వర్డ్ ఎవరితోనూ పంచుకోకండి",
                "అనుమానం ఉంటే నేరుగా నిర్ధారించుకోండి",
            ],
        },
        "suspicious": {
            "headline": "జాగ్రత్త — ఇది అనుమానాస్పద సందేశం",
            "explanation": "ఈ సందేశంలో అనుమానాస్పద లింక్ లేదా తొందరపెట్టే మాటలు ఉన్నాయి.",
            "safe_action": "లింకులు క్లిక్ చేయకండి, డబ్బు పంపకండి. అధికారిక యాప్ ద్వారా తనిఖీ చేయండి.",
            "body": "స్పందించే ముందు ఆలోచించండి. మోసగాళ్లు మిమ్మల్ని కంగారు పెట్టడానికి ప్రయత్నిస్తారు.",
            "bullets": [
                "తెలియని లింకులను క్లిక్ చేయవద్దు",
                "OTP లేదా UPI పిన్ ఎవరికీ ఇవ్వవద్దు",
                "అధికారిక నంబర్ ద్వారా నిర్ధారించుకోండి",
            ],
        },
        "danger": {
            "headline": "ప్రమాదం! ఇది స్కామ్ (మోసం) — స్పందించవద్దు!",
            "explanation_by_type": {
                "lottery": "నిజమైన బహుమతుల కోసం ఎవరూ OTP లేదా రుసుము అడగరు. ఇది నకిలీ లాటరీ మోసం.",
                "bank_fraud": "ఏ బ్యాంకూ ఖాతా కోసం OTP అడగదు లేదా నకిలీ లింకులు పంపదు.",
                "phishing": "నకిలీ లింక్ ద్వారా మీ బ్యాంక్ వివరాలు దొంగిలించే ప్రయత్నం ఇది.",
                "job_scam": "నిజమైన కంపెనీలు ఉద్యోగం ఇవ్వడానికి రిజిస్ట్రేషన్ ఫీజు అడగవు.",
                "payment_scam": "డబ్బు అందుకోవడానికి UPI పిన్ ఎంటర్ చేయాల్సిన అవసరం లేదు.",
                "authority_impersonation": "పోలీసులు లేదా అధికారులు మెసేజ్ ద్వారా డబ్బు డిమాండ్ చేయరు.",
                "other": "మీ డబ్బు లేదా OTP దొంగిలించడానికి చేసిన ప్రమాదకరమైన మోసం ఇది.",
            },
            "safe_action": "రిప్లై ఇవ్వకండి, లింక్ తెరవకండి, OTP లేదా డబ్బు పంపకండి. వెంటనే బ్లాక్ చేయండి.",
            "body": "ఆగండి! ఇది మోసపూరిత సందేశం. మీ ఖాతాను మరియు డబ్బును కాపాడుకోండి.",
            "bullets": [
                "OTP, పాస్‌వర్డ్ లేదా UPI పిన్ షేర్ చేయవద్దు",
                "లింకులు క్లిక్ చేయవద్దు మరియు డబ్బు పంపవద్దు",
                "నంబర్‌ను బ్లాక్ చేసి 1930 కి ఫిర్యాదు చేయండి",
            ],
        },
    },
    "bn": {
        "safe": {
            "headline": "নিরাপদ মনে হচ্ছে — প্রতারণার লক্ষণ নেই",
            "explanation": "এটি একটি সাধারণ বার্তা বলে মনে হচ্ছে এবং এতে OTP বা টাকা চাওয়া হয়নি।",
            "safe_action": "চিন্তার কিছু নেই। তবুও কখনো কারো সাথে OTP বা পিন শেয়ার করবেন না।",
            "body": "এই বার্তায় কোনো ভুয়া লিংক বা হুমকির চিহ্ন পাওয়া যায়নি।",
            "bullets": [
                "সাধারণ বার্তা বলে মনে হচ্ছে",
                "কখনো OTP বা পিন শেয়ার করবেন না",
                "সন্দেহ হলে সরাসরি যাচাই করুন",
            ],
        },
        "suspicious": {
            "headline": "সাবধান — সন্দেহজনক বার্তা",
            "explanation": "এই বার্তায় অচেনা লিংক বা তাড়াহুড়োর মতো সন্দেহজনক লক্ষণ রয়েছে।",
            "safe_action": "কোনো লিংকে ক্লিক করবেন না বা টাকা পাঠাবেন না। অফিসিয়াল অ্যাপ থেকে যাচাই করুন।",
            "body": "উত্তর দেওয়ার আগে থামুন। প্রতারকরা আপনাকে তাড়াহুড়ো করাতে চায়।",
            "bullets": [
                "অপরিচিত লিংকে ক্লিক করবেন না",
                "OTP বা পাসওয়ার্ড কাউকে দেবেন না",
                "অফিসিয়াল মাধ্যমে সত্যতা যাচাই করুন",
            ],
        },
        "danger": {
            "headline": "বিপদ! এটি প্রতারণামূলক বার্তা — উত্তর দেবেন না!",
            "explanation_by_type": {
                "lottery": "আসল পুরস্কারের জন্য কখনো OTP বা ফি চাওয়া হয় না। এটি ভুয়া লটারির ফাঁদ।",
                "bank_fraud": "কোনো আসল ব্যাংক অ্যাকাউন্ট চালু রাখতে OTP চায় না বা ভুয়া লিংক পাঠায় না।",
                "phishing": "ভুয়া লিংকের মাধ্যমে আপনার পাসওয়ার্ড বা ব্যাংকের তথ্য চুরির চেষ্টা করা হচ্ছে।",
                "job_scam": "আসল প্রতিষ্ঠান চাকরির জন্য রেজিস্ট্রেশন ফি চায় না।",
                "payment_scam": "টাকা পেতে কখনো UPI পিন দিতে হয় না। পিন দিলেই আপনার টাকা কেটে যাবে।",
                "authority_impersonation": "পুলিশ বা সরকারি কর্মকর্তা মেসেজে টাকা দাবি করেন না।",
                "other": "এই বার্তায় আপনার টাকা বা গোপন কোড হাতিয়ে নেওয়ার স্পষ্ট লক্ষণ রয়েছে।",
            },
            "safe_action": "উত্তর দেবেন না, লিংকে ক্লিক করবেন না এবং OTP বা টাকা পাঠাবেন না। নম্বরটি ব্লক করুন।",
            "body": "থামুন! এটি একটি প্রতারণামূলক বার্তা। আপনার অর্থ ও অ্যাকাউন্ট নিরাপদ রাখুন।",
            "bullets": [
                "OTP, পাসওয়ার্ড বা পিন শেয়ার করবেন না",
                "লিংকে ক্লিক করবেন না এবং টাকা পাঠাবেন না",
                "প্রেরককে ব্লক করুন এবং রিপোর্ট করুন",
            ],
        },
    },
    "sw": {
        "safe": {
            "headline": "Inaonekana Salama — Hakuna Dalili za Utapeli",
            "explanation": "Ujumbe huu unaonekana wa kawaida na hauombi OTP, nenosiri, au malipo yenye mashaka.",
            "safe_action": "Hakuna hatua inayohitajika. Usishiriki OTP au PIN yako na mtu yeyote.",
            "body": "Hatujagundua viungo feki, vitisho, au maombi ya nambari za siri kwenye ujumbe huu.",
            "bullets": [
                "Inaonekana kama ujumbe wa kawaida",
                "Usitoe OTP au PIN ya malipo kwa yeyote",
                "Thibitisha na mtumaji ikiwa una shaka",
            ],
        },
        "suspicious": {
            "headline": "Kuwa Makini — Ujumbe Wenye Mashaka",
            "explanation": "Ujumbe huu una dalili za utapeli kama vile viungo visivyojulikana au shinikizo la haraka.",
            "safe_action": "Usibofye viungo wala kutuma pesa. Hakikisha kupitia huduma rasmi kwanza.",
            "body": "Subiri kabla ya kujibu. Matapeli hujaribu kukuharakisha ili usichunguze ukweli.",
            "bullets": [
                "Usibofye viungo usivyovijua",
                "Usishiriki OTP, PIN, au nenosiri",
                "Wasiliana na benki au kampuni kwa nambari rasmi",
            ],
        },
        "danger": {
            "headline": "Hatari Kubwa ya Utapeli — Usijibu Wala Kulipa!",
            "explanation_by_type": {
                "lottery": "Zawadi halali haziombi OTP, PIN, au ada ya kuchukua zawadi. Huu ni mtego wa utapeli.",
                "bank_fraud": "Benki halisi haziombi OTP wala kutuma viungo visivyo rasmi kufungua akaunti yako.",
                "phishing": "Ujumbe huu unatumia kiungo feki kuiba taarifa zako za siri au pesa.",
                "job_scam": "Waajiri halali hawatozi ada ya usajili ili kukupa kazi.",
                "payment_scam": "Huhitaji kuweka PIN ili kupokea pesa. Kuweka PIN kunatuma pesa zako nje.",
                "authority_impersonation": "Polisi au mamlaka za serikali hazidai malipo kupitia SMS au WhatsApp.",
                "other": "Ujumbe huu una dalili kali za utapeli zinazolenga kuiba pesa au taarifa zako za siri.",
            },
            "safe_action": "Usijibu, usibofye kiungo, wala kutoa OTP au pesa. Mzuie (Block) mtumaji mara moja.",
            "body": "Simama! Ujumbe huu unafanana kabisa na mbinu za matapeli. Linda akaunti na pesa zako.",
            "bullets": [
                "Usitoe OTP, nenosiri, au PIN yako",
                "Usibofye kiungo chochote wala kutuma pesa",
                "Mzuie mtumaji na uripoti ujumbe huu",
            ],
        },
    },
}


def localize_flag(flag_id: str, lang: str) -> str:
    """Returns a short localized red-flag chip label."""
    entry = RED_FLAG_LABELS.get(flag_id)
    if not entry:
        return flag_id.replace("_", " ").capitalize()
    return entry.get(lang) or entry["en"]


def get_localized_copy(verdict: str, scam_type: str, lang: str) -> dict[str, object]:
    """Returns localized explanation, safe_action, headline, body, and bullets."""
    lang_pack = VERDICT_TEMPLATES.get(lang) or VERDICT_TEMPLATES["en"]
    verdict_pack = lang_pack.get(verdict) or lang_pack["safe"]

    if verdict == "danger":
        by_type = verdict_pack.get("explanation_by_type", {})
        assert isinstance(by_type, dict)
        explanation = by_type.get(scam_type) or by_type.get("other") or ""
    else:
        explanation = str(verdict_pack.get("explanation", ""))

    return {
        "headline": str(verdict_pack["headline"]),
        "explanation": str(explanation),
        "safe_action": str(verdict_pack["safe_action"]),
        "body": str(verdict_pack["body"]),
        "bullets": list(verdict_pack["bullets"]),  # type: ignore[arg-type]
    }
