# 🛡️ Scam Shield — Full-Stack Web App & Scam Detection Engine

**Scam Shield** is a mobile-first scam-detection and warning system built for **students, first-time earners, and families**. Users submit suspicious SMS messages, WhatsApp forwards, call descriptions, or payment requests and receive an instant **risk score (0–100)**, **color-coded verdict**, **red flags**, and **safe next steps** in their local language.

Built on the **"One Scam Brain, Many Channels"** architecture (`SCAM_SHIELD_PROJECT_SPEC.md` v1.0):
- **Frontend (`frontend/`)**: Responsive, zero-build, mobile-first web checker (English, Hindi, and Kannada UI). Never makes scam decisions or stores secrets in the browser.
- **Backend (`backend/`)**: Python **FastAPI** REST API (`POST /api/v1/analyze` & `GET /api/v1/health`) powered by a deterministic multilingual rule & URL heuristic engine + optional **100% free-tier AI** (Google Gemini / GroqCloud) with automatic zero-downtime fallback.

---

## 📁 Repository Folder Structure

```text
scam-shield/
├── README.md                       # Unified Full-Stack Project Guide (this file)
├── SCAM_SHIELD_PROJECT_SPEC.md     # Single source of truth & FE/BE API Contract
├── .gitignore                      # Protects .env secrets, caches, and local files
│
├── frontend/                       # Responsive Web Checker UI (No build step needed)
│   ├── index.html                  # Main mobile-first application
│   └── ...                         # Static CSS / JS assets
│
└── backend/                        # Python FastAPI Scam Detection Engine
    ├── app/
    │   ├── main.py                 # FastAPI app, CORS, error handlers, API console (/)
    │   ├── config.py               # Environment settings (.env loader)
    │   ├── schemas.py              # Strict Pydantic models matching Spec Section 8
    │   ├── rate_limiter.py         # Sliding-window IP rate limiter (HTTP 429)
    │   ├── api/
    │   │   └── v1.py               # GET /api/v1/health & POST /api/v1/analyze
    │   └── engine/
    │       ├── pipeline.py         # Unified 8-step analyze_message() pipeline
    │       ├── rules.py            # Offline regex + URL + UPI + OTP + Call heuristics
    │       ├── language.py         # Script + Hinglish/Swahili detector & i18n templates
    │       └── ai_analyzer.py      # Free-tier Gemini / Groq / OpenAI adapters + fallback
    ├── tests/
    │   └── test_api.py             # 13 automated contract & integration tests
    ├── .env.example                # Template for optional free AI keys & CORS origins
    ├── requirements.txt            # Backend Python dependencies
    ├── Dockerfile                  # Ready for Render / Railway / Fly.io deployment
    └── Procfile                    # Process start command for cloud hosting
```

---

## 🚀 Quick Start — Run the Full Project Locally

Both the Backend and Frontend run with **Python**—no Node.js or frontend build step is required. Open **two terminals** from the `scam-shield/` root folder:

### Terminal 1: Start the Backend API (`http://localhost:8000`)

**Windows (PowerShell):**
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Mac / Linux:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

> **Works immediately without an API key!** The backend's built-in multilingual rule & URL engine works out-of-the-box. Add a free Gemini or Groq key later (see below) to upgrade to **Hybrid Mode (Rules + AI)**.

---

### Terminal 2: Start the Frontend Web App (`http://localhost:5173`)

No package installation or build step is needed.

**Windows (PowerShell):**
```powershell
cd frontend
python -m http.server 5173 --bind 0.0.0.0
```

**Mac / Linux:**
```bash
cd frontend
python3 -m http.server 5173 --bind 0.0.0.0
```

### Open in Your Browser
- **Scam Shield Web App (Frontend):** `http://localhost:5173`
- **Backend API Contract Tester:** `http://localhost:8000/`
- **Backend Interactive Swagger Docs:** `http://localhost:8000/docs`
- **Backend Health Check:** `http://localhost:8000/api/v1/health`

---

## ✨ Features Included

### Frontend (`frontend/`)
- **Three Input Modes:**
  - **SMS / Messages** — Paste suspicious SMS, WhatsApp, or email text with context-aware examples.
  - **Suspicious Calls** — Selectable warning-sign checkboxes combined with the user's call notes.
  - **Payment Requests** — Check UPI, QR, registration fee, or refund tricks with context-aware examples.
- **Horizontal Risk Meter:** Color-coded visual bar — **Green (`0–30` Safe)**, **Yellow (`31–65` Suspicious)**, **Red (`66–100` Danger)**.
- **Input Safeguards:** 5,000-character limit with a live character counter.
- **Full Interface Language Switcher:** **English (`en`, default)**, **Hindi (`hi`)**, and **Kannada (`kn`)** — switches UI labels and sends the chosen language code to the backend for localized analysis.
- **Resilient UX States:** Dedicated loading, validation (`400`), timeout, rate-limit (`429`), and server-error (`500`) states.
- **Zero Secrets in Browser:** No API keys or scam-scoring logic in the frontend. Defaults to `http://localhost:8000` and supports overriding the backend URL via browser console:
  ```javascript
  localStorage.setItem('scamshield_api_base', 'https://your-api.example')
  ```

### Backend (`backend/`)
- **100% Spec Contract Compliance:** Exact JSON request/response schemas, verdict thresholds, and HTTP `400` / `429` / `500` error envelopes.
- **CORS Pre-Configured:** Allows `http://localhost:5173` out-of-the-box (plus configurable production origins via `ALLOWED_ORIGINS`).
- **Multilingual Detection & Responses:** Built-in support for **English (`en`)**, **Hindi (`hi` + Romanized Hinglish)**, **Kannada (`kn`)**, **Tamil (`ta`)**, **Telugu (`te`)**, **Bengali (`bn`)**, and **Swahili (`sw`)**—plus any ISO language when an AI key is active.
- **Smart Scam Signal Coverage:** Detects OTP/PIN solicitation, fake prizes/lotteries, fake job registration fees, UPI PIN tricks, bank/KYC block threats, "digital arrest" / police impersonation, screen-sharing/APK traps, URL shorteners, and suspicious domains (`.xyz`, `.top`, plain `http://`), while avoiding false positives on genuine *"Do NOT share this OTP"* alerts.
- **Abuse & Privacy Protection:** Sliding-window IP rate limiting (`60 req/min` default), prompt-injection safety floor, and privacy-safe logging (logs SHA-256 hash prefix only—never raw messages).

---

## 🔑 Optional: Add a 100% FREE AI API Key (No Credit Card Needed)

Pick **Option A** (recommended) or **Option B**—or add both to `backend/.env` so one automatically backs up the other:

### Option A: Google Gemini Free Tier (Recommended — Best for Indian Languages)
1. Go to **[Google AI Studio](https://aistudio.google.com/apikey)** and sign in with your Google account.
2. Click **"Create API key"** (no credit card required).
3. Open `backend/.env` and paste:
   ```env
   GEMINI_API_KEY=AIzaSyYourCopiedKeyHere
   ```

### Option B: GroqCloud Free Tier (Ultra-Fast Llama 3.3 70B — Free, No Card)
1. Go to **[GroqCloud Console](https://console.groq.com/keys)** and sign in.
2. Click **"Create API Key"** and copy the key (`gsk_...`).
3. Open `backend/.env` and paste:
   ```env
   GROQ_API_KEY=gsk_YourCopiedKeyHere
   ```

---

## 🔌 Frontend ↔ Backend API Contract

### Health Check
`GET /api/v1/health`
```json
{
  "status": "ok",
  "service": "scam-shield",
  "version": "1.0.0"
}
```

### Analyze Message
`POST /api/v1/analyze`

**Request Payload (sent by Frontend):**
```json
{
  "message": "Congratulations! You won $5000! Claim now, send your OTP!",
  "language": "hi",
  "source": "web",
  "metadata": {
    "has_url": false,
    "urls": [],
    "phone_numbers": []
  }
}
```
*(The `language` field follows the selected interface language—`en`, `hi`, or `kn`—or auto-detects if omitted.)*

**Response `200 OK` (returned by Backend):**
```json
{
  "request_id": "cff62040-3949-40ca-958f-1e52b6e2ad0d",
  "verdict": "danger",
  "verdict_emoji": "🔴",
  "risk_score": 98,
  "scam_type": "lottery",
  "red_flags": [
    "OTP या PIN मांगा गया है",
    "नकली लॉटरी या इनाम का दावा",
    "तुरंत कार्रवाई करने का दबाव"
  ],
  "explanation": "असली इनाम या लॉटरी के लिए कभी भी OTP, पिन या फीस नहीं मांगी जाती। यह ठगी का जाल है।",
  "safe_action": "कोई जवाब न दें, लिंक न खोलें और OTP या पैसे बिल्कुल न भेजें। भेजने वाले को तुरंत ब्लॉक करें।",
  "tactics": ["credential_phishing", "reward", "urgency"],
  "language_detected": "en",
  "language_response": "hi",
  "display": {
    "headline": "खतरा! यह स्कैम (धोखाधड़ी) हो सकता है — जवाब न दें!",
    "body": "रुकिए! यह संदेश छात्रों और कामकाजी लोगों को ठगने वाले स्कैम जैसा है। अपना OTP और पैसा सुरक्षित रखें।",
    "bullets": [
      "OTP, पासवर्ड या UPI पिन किसी के साथ शेयर न करें",
      "किसी लिंक पर क्लिक न करें और पैसे न भेजें",
      "नंबर को ब्लॉक करें और 1930 पर साइबर शिकायत करें"
    ]
  }
}
```

---

## 🧪 Automated Backend Tests

Run the 13 contract, multilingual, CORS, validation, and rate-limiting tests:

```bash
cd backend
pytest -v
```

---

## ☁️ Deploying Online for Free

1. **Deploy Backend (`backend/`) on [Render.com](https://render.com):**
   - Connect your GitHub repo → **New Web Service** → set **Root Directory** to `backend`.
   - Choose **Docker** (or **Python 3** with start command `uvicorn app.main:app --host 0.0.0.0 --port $PORT`).
   - Add Environment Variables:
     - `GEMINI_API_KEY` = your free key
     - `ALLOWED_ORIGINS` = `http://localhost:5173,https://your-frontend-domain.pages.dev`
2. **Deploy Frontend (`frontend/`) on Cloudflare Pages / Netlify / Vercel:**
   - Set **Root Directory** to `frontend` with **no build command** and output directory `.`.
   - Point the frontend to your live Render backend URL (or test immediately in the browser console via `localStorage.setItem('scamshield_api_base', 'https://your-backend.onrender.com')`).
