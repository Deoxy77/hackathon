# 🛡️ SCAM SHIELD — Project Specification & FE/BE Integration Guide

**Version:** 1.0  
**Status:** Planning complete — ready for parallel Frontend + Backend development  
**Document purpose:** Single source of truth so the Frontend developer, Backend developer, and any other AI/tool understand the product and connect FE + BE correctly.

### Locked Kickoff Choices (Backend)
- **Backend Framework:** Python 3 + FastAPI (`http://localhost:8000`)
- **AI Engine:** Hybrid Rule-Based Engine + Free-Tier AI Support (Google Gemini Free Tier / Groq Free Tier / OpenAI) with automatic zero-downtime fallback
- **Languages Supported Out-of-the-Box:** English (`en`), Hindi (`hi` + Hinglish), Kannada (`kn`), Tamil (`ta`), Telugu (`te`), Bengali (`bn`), Swahili (`sw`), plus any ISO language when AI key is active
- **MVP Auth:** Public endpoint protected by sliding-window IP rate limiting (`429` on abuse)

---

## 1. Project Overview

### 1.1 What is Scam Shield?

Scam Shield is a **scam-detection and warning system** built for **students and first-time earners**.

Users submit suspicious content (SMS text, WhatsApp messages, emails, links, call descriptions, or later screenshots). The system analyzes it and returns:

- A **risk score** (0–100)
- A clear **verdict** (Safe / Suspicious / Danger)
- **Why** it is dangerous (red flags + simple explanation)
- A **safe action** the user should take
- Preferably in the **user’s local language**

### 1.2 Core problem

- Students and first-time earners fall for fake messages, calls, and payment requests.
- Scams use urgency, fake authority (bank/police/job), OTP/password requests, fake prizes, fake jobs, and UPI/payment tricks.
- Many vulnerable users have **low literacy**, **cheap phones**, or **limited internet**.
- A web app alone is not enough for everyone — but a web app is still valuable for literate smartphone users and as the first client of a shared backend.

### 1.3 Product vision — one brain, many channels

```
                    ┌── Web App (checker UI)          ← MVP client (Frontend)
                    ├── WhatsApp Bot (forward → reply)
                    ├── SMS Bot (forward → SMS reply)
 ONE SCAM ENGINE ───┼── Email checker (forward to address)
    (Backend)       ├── Future: IVR / voice call
                    ├── Future: USSD (*123#)
                    └── Future: Android APK (notification/SMS listener)
```

**Critical principle:**  
The **same detection engine** powers every channel.  
The Web App is **one client**. Bots and future apps are other clients talking to the **same Backend API**.

### 1.4 Current build split

| Person | Responsibility |
|--------|----------------|
| **Frontend Partner** | Web app UI/UX only |
| **Backend Owner** | API + scam detection engine + future channel webhooks |
| **Both** | Follow the API contract in this document so FE and BE merge cleanly |

---

## 2. Target Users

| Priority | User | Main risks / needs |
|----------|------|--------------------|
| Primary | Students | Fake jobs, scholarships, OTP, prize scams |
| Primary | First-time earners | UPI/payment scams, fake bank alerts, job registration fees |
| Secondary | Low-literacy / rural users | Voice, emojis, SMS/USSD/call — not complex UI |
| Secondary | Family helpers | Someone checks a message for a parent/grandparent |

**Design implication:** Web UI must be extremely simple. Big risk colors, icons, short sentences, language support. Accessibility is not optional.

---

## 3. Goals and Non-Goals

### Goals

- Analyze text (and later images/URLs/phone numbers) for scam signals.
- Return: risk score, verdict, scam type, red flags, explanation, safe action.
- Support local languages (auto-detect + user preference).
- One backend engine reusable by web + bots + future APK.
- Clear FE/BE split with a stable API contract.

### Non-Goals (MVP)

- Becoming the user’s default SMS app.
- Fully automatic SMS reading with zero install (not possible without app or carrier).
- Perfect accuracy (aim for strong explainable signals + AI assist).
- Building every channel on day one.

---

## 4. Key Product Decisions

| Topic | Decision |
|-------|----------|
| Web-only for all users | **Rejected** as the only solution — many users can’t or won’t use a browser well |
| Best early reach channels | WhatsApp bot + SMS bot (user forwards the message) |
| Automatic SMS reading | Only realistic via **Android APK** (Notification Listener or SMS permissions) — high setup/trust friction |
| APK vs SMS bot | **SMS/WhatsApp bot:** low friction, high reach. **APK:** automatic after hard setup; trust and Play Store issues |
| Architecture | **One scam brain → many channels** |
| Web app role | Checker UI for smartphone/literate users; shares the same backend as bots |
| FE/BE merge rule | Frontend never calls AI/Twilio directly. Only the Backend API. |
| MVP focus | Web paste-to-check + shared analyze API |

---

## 5. Features

### 5.1 MVP (Web + shared Backend) — build first

| ID | Feature | Description | FE | BE |
|----|---------|-------------|----|----|
| F1 | Text message check | User pastes SMS/WhatsApp/email text | Form + submit | `POST /api/v1/analyze` |
| F2 | Risk score & verdict | 0–100 + Safe / Suspicious / Danger | Display | Compute |
| F3 | Red flags & explanation | Why it was flagged + short explanation | Simple UI | Generate |
| F4 | Safe action | Clear “what to do now” | Highlight | Generate |
| F5 | Language | Auto-detect + optional user choice; warning in local language | Language picker | Detect + translate |
| F6 | Scam type label | phishing, lottery, job_scam, bank_fraud, etc. | Badge | Classify |

### 5.2 Phase 2+ (same backend, more inputs/channels)

| ID | Feature | Notes |
|----|---------|--------|
| F7 | URL / link scan | Safe Browsing / heuristics / VirusTotal |
| F8 | Screenshot upload | OCR → same analyze pipeline |
| F9 | Phone number check | Reported scam numbers DB |
| F10 | WhatsApp bot | Webhook → same engine → reply (+ optional voice note) |
| F11 | SMS bot | Gateway → same engine → short SMS reply |
| F12 | Email forward | Inbound parse → analyze → reply |
| F13 | Voice warnings | TTS for bots / low-literacy |
| F14 | Tactic explainer | Urgency, authority, reward, loss aversion, credential phishing |
| F15 | Education snippets | Short tip after each result |
| F16 | Optional Android APK | Notification listener; calls same API or on-device rules |

---

## 8. API Contract (FE and BE must match this)

**Base URL (dev example):** `http://localhost:8000`  
**Base URL (prod example):** `https://api.scamshield.example.com`  
**API prefix:** `/api/v1`  
**Format:** JSON, UTF-8  

### 8.1 Health check

```
GET /api/v1/health
```

**Response 200:**

```json
{
  "status": "ok",
  "service": "scam-shield",
  "version": "1.0.0"
}
```

### 8.2 Analyze message (CORE — MVP)

```
POST /api/v1/analyze
Content-Type: application/json
```

**Request body:**

```json
{
  "message": "string (required) — raw text of SMS/chat/email",
  "language": "string (optional) — ISO code like en, hi, sw, ta. If omitted, backend auto-detects",
  "source": "string (optional) — web | whatsapp | sms | email | apk — default: web",
  "metadata": {
    "has_url": false,
    "urls": [],
    "phone_numbers": []
  }
}
```

**Response 200:**

```json
{
  "request_id": "uuid-or-string",
  "verdict": "safe",
  "verdict_emoji": "🟢",
  "risk_score": 0,
  "scam_type": "safe",
  "red_flags": [],
  "explanation": "Short plain-language explanation in the response language",
  "safe_action": "What the user should do — short",
  "tactics": [],
  "language_detected": "en",
  "language_response": "en",
  "display": {
    "headline": "Short headline ready to show",
    "body": "Full user-facing warning text ready to show",
    "bullets": [
      "Do not reply",
      "Do not share OTP",
      "Block the sender"
    ]
  }
}
```

**Allowed values**

| Field | Allowed values |
|-------|----------------|
| `verdict` | `safe` \| `suspicious` \| `danger` |
| `verdict_emoji` | `🟢` \| `🟡` \| `🔴` |
| `risk_score` | integer 0–100 |
| `scam_type` | `safe` \| `phishing` \| `lottery` \| `job_scam` \| `bank_fraud` \| `payment_scam` \| `authority_impersonation` \| `other` |
| `tactics` | subset of: `urgency`, `authority`, `reward`, `loss_aversion`, `credential_phishing` |

**Error responses**

**400 invalid input:**

```json
{
  "error": "invalid_request",
  "message": "Human-readable error"
}
```

**429** — rate limited  
**500** — server/AI failure (Frontend must show a friendly fallback, not raw errors)

### 8.3 Risk score meaning (shared constant)

| Score | Verdict | UI color |
|-------|---------|----------|
| 0–30 | `safe` | Green |
| 31–65 | `suspicious` | Yellow / Amber |
| 66–100 | `danger` | Red |

Backend **must** set `verdict` consistently with `risk_score`.
