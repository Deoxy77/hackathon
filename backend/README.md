# 🛡️ Scam Shield — Backend API & Scam Detection Engine

Complete Python **FastAPI** backend implementing `SCAM_SHIELD_PROJECT_SPEC.md` (Version 1.0) with **100% API contract fidelity**, built-in **multilingual scam rules**, and **free-tier AI support** (Google Gemini & GroqCloud) with automatic zero-downtime fallback.

---

## 📁 Folder Structure

```text
backend/
├── app/
│   ├── main.py              # FastAPI app, CORS, error handlers, dev API inspector (/)
│   ├── config.py            # Environment settings (.env loader)
│   ├── schemas.py           # Strict Pydantic models matching Spec Section 8
│   ├── rate_limiter.py      # Sliding-window IP rate limiter (returns HTTP 429)
│   ├── api/
│   │   └── v1.py            # GET /api/v1/health & POST /api/v1/analyze
│   └── engine/
│       ├── pipeline.py      # Unified 8-step analyze_message() pipeline
│       ├── rules.py         # Offline regex + URL + UPI + OTP heuristic engine
│       ├── language.py      # Script + Hinglish/Swahili detector & i18n templates
│       └── ai_analyzer.py   # Free-tier Gemini / Groq / OpenAI adapters + fallback
├── tests/
│   └── test_api.py          # 13 automated contract & integration tests
├── .env.example             # Copy to .env to add your free AI key
├── requirements.txt         # Python dependencies
├── Dockerfile               # Ready for Render / Railway / Fly.io deployment
└── Procfile                 # Process command for PaaS hosting
```

---

## 🚀 Quick Start (Run on Your Computer in 2 Minutes)

### 1. Open terminal in `backend/` and create a virtual environment

**Windows (PowerShell):**
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Mac / Linux:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Copy `.env.example` to `.env`

**Windows:**
```powershell
copy .env.example .env
```

**Mac / Linux:**
```bash
cp .env.example .env
```

> **Note:** The backend works **immediately even before you add an API key** using its built-in multilingual rule & URL engine! When you add a free Gemini or Groq key below, it automatically upgrades to **Hybrid Mode (Rules + AI)**.

### 3. Start the Backend Server (Port `8000`)

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Now open in your browser:
- **Live Contract Tester UI:** `http://localhost:8000/`
- **Swagger Interactive Docs:** `http://localhost:8000/docs`
- **Health Check JSON:** `http://localhost:8000/api/v1/health`

---

## 🔑 How to Get a 100% FREE AI API Key (No Credit Card Needed!)

You do **not** need to pay anything. Pick **Option A** (recommended) or **Option B** — or add both so one backs up the other!

### Option A: Google Gemini Free Tier (Recommended — Best for Indian Languages)
1. Go to **[Google AI Studio](https://aistudio.google.com/apikey)** and sign in with your normal Gmail account.
2. Click **"Create API key"**. (No credit card required!)
3. Copy the key (starts with `AIza...`).
4. Open `backend/.env` and paste it:
   ```env
   GEMINI_API_KEY=AIzaSyYourCopiedKeyHere
   ```
5. Save `.env` — if `uvicorn --reload` is running, it picks up your key automatically!

### Option B: GroqCloud Free Tier (Super Fast Llama 3.3 70B — Free, No Card)
1. Go to **[GroqCloud Console](https://console.groq.com/keys)** and sign up with Google/GitHub.
2. Click **"Create API Key"** and copy the key (starts with `gsk_...`).
3. Open `backend/.env` and paste it:
   ```env
   GROQ_API_KEY=gsk_YourCopiedKeyHere
   ```

---

## 🤝 Connecting with Your Partner's Frontend

Share these 3 details with your Frontend partner so your repos merge cleanly on the first try:

### 1. Frontend `.env` setting
In their Vite or Next.js project:
```env
VITE_API_BASE_URL=http://localhost:8000
# or for Next.js:
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

### 2. Ready-to-use Frontend `fetch()` snippet
```javascript
const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export async function checkScamMessage(message, language = "") {
  const payload = { message, source: "web" };
  if (language && language !== "auto") {
    payload.language = language;
  }

  const res = await fetch(`${API_BASE}/api/v1/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  if (!res.ok) {
    // Handles 400 (invalid_request), 429 (rate_limited), and 500 gracefully
    throw new Error(data.message || "Could not check this message right now.");
  }
  return data;
}
```

### 3. Supported Local Languages Out-of-the-Box
- `en` — English
- `hi` — Hindi (auto-detects both Devanagari `हिंदी` and Romanized **Hinglish**!)
- `kn` — Kannada (`ಕನ್ನಡ`)
- `ta` — Tamil (`தமிழ்`)
- `te` — Telugu (`తెలుగు`)
- `bn` — Bengali (`বাংলা`)
- `sw` — Swahili (`Kiswahili`)
- Plus **any ISO language** automatically when `GEMINI_API_KEY` or `GROQ_API_KEY` is set!

---

## 🧪 Run Automated Tests

```bash
cd backend
pytest -v
```

Verifies:
- `GET /api/v1/health` exact JSON
- All 4 Shared Test Messages from Section 14 of `SCAM_SHIELD_PROJECT_SPEC.md`
- Hindi, Hinglish, Kannada, and Tamil localization
- Legitimate bank OTP messages ("Do NOT share OTP") are NOT falsely flagged
- HTTP `400` on empty/missing/oversized (>5000 chars) input
- HTTP `429` IP rate limiting
- CORS preflight headers for `http://localhost:5173`
- Prompt-injection defense floor

---

## ☁️ Free Cloud Deployment (Render.com)

When you and your partner are ready to put Scam Shield online:
1. Push `backend/` to GitHub (**make sure `.env` is NOT committed** — `.gitignore` already protects it).
2. Create a free account on **[Render.com](https://render.com)** → **New +** → **Web Service** → Connect your GitHub repo.
3. If using a monorepo (`scam-shield/backend`), set **Root Directory** to `backend`.
4. Set **Environment** to `Docker` (or `Python 3` with Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`).
5. Under **Environment Variables**, add:
   - `GEMINI_API_KEY` = your free key
   - `ALLOWED_ORIGINS` = `http://localhost:5173,https://your-partner-frontend.vercel.app`
6. Copy your live Render URL (e.g., `https://scam-shield-api.onrender.com`) and give it to your frontend partner for their `VITE_API_BASE_URL`!
