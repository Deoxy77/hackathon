"""FastAPI Entry Point for Scam Shield Backend."""

from __future__ import annotations

import logging
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.v1 import router as v1_router
from app.config import get_settings
from app.engine.pipeline import InvalidMessageError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("scam_shield.main")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Scam Shield Backend API",
        description=(
            "Shared scam-detection engine and REST API for Scam Shield "
            "(Web App, WhatsApp/SMS Bots, and future channels)."
        ),
        version=settings.version,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ------------------------------------------------------------------
    # CORS Configuration (Spec Section 8.5)
    # ------------------------------------------------------------------
    origins = list(settings.allowed_origins)
    if "*" in origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "Accept"],
        )
    else:
        origin_regex = (
            r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$|^https://.*\.e2b\.app$"
            if settings.allow_localhost_any_port
            else None
        )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_origin_regex=origin_regex,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "Accept"],
        )

    # ------------------------------------------------------------------
    # Unified Error Handlers matching Spec Section 8.2 (HTTP 400 / 500)
    # ------------------------------------------------------------------
    @app.exception_handler(InvalidMessageError)
    async def handle_invalid_message(_request: Request, exc: InvalidMessageError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "message": str(exc),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = exc.errors()
        if errors:
            first = errors[0]
            loc = [str(part) for part in first.get("loc", []) if part != "body"]
            field_label = ".".join(loc)
            raw_msg = str(first.get("msg", "Invalid request body")).replace("Value error, ", "")
            human_msg = f"{field_label}: {raw_msg}" if field_label and field_label not in raw_msg.lower() else raw_msg
        else:
            human_msg = "Invalid JSON request body."

        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "message": human_msg,
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error in Scam Shield API: %s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "message": "We couldn't check this message right now. Please try again shortly.",
            },
        )

    app.include_router(v1_router)

    # ------------------------------------------------------------------
    # Developer API Inspector & Contract Tester at GET /
    # (Helps Backend & Frontend devs test the live API immediately)
    # ------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def developer_console() -> HTMLResponse:
        return HTMLResponse(content=_DEV_CONSOLE_HTML)

    return app


_DEV_CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Scam Shield — Backend API Console</title>
  <style>
    :root {
      --bg: #0b1120;
      --panel: #111827;
      --panel-2: #1f2937;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --safe: #22c55e;
      --safe-bg: rgba(34, 197, 94, 0.14);
      --suspicious: #f59e0b;
      --suspicious-bg: rgba(245, 158, 11, 0.14);
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.15);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .wrap {
      max-width: 1120px;
      margin: 0 auto;
      padding: 28px 20px 60px;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.5rem;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .brand p {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .links {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 600;
      background: var(--panel-2);
      border: 1px solid var(--border);
      color: var(--text);
      text-decoration: none;
    }
    .pill.ok { border-color: rgba(34,197,94,0.5); color: #86efac; }
    .pill.link:hover { border-color: var(--accent); color: var(--accent); }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 860px) {
      .grid { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
    }
    .card h2 {
      margin: 0 0 12px;
      font-size: 1.05rem;
      color: #e2e8f0;
    }
    .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 14px;
    }
    .preset-btn {
      background: var(--panel-2);
      color: #cbd5e1;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 6px 10px;
      font-size: 0.8rem;
      cursor: pointer;
      transition: all 0.15s;
    }
    .preset-btn:hover {
      border-color: var(--accent);
      color: #fff;
    }
    textarea {
      width: 100%;
      min-height: 118px;
      background: #0f172a;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      font-size: 0.95rem;
      resize: vertical;
      font-family: inherit;
    }
    textarea:focus, select:focus {
      outline: none;
      border-color: var(--accent);
    }
    .controls {
      display: flex;
      gap: 12px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    select {
      background: #0f172a;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 0.9rem;
    }
    button.primary {
      background: #0284c7;
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 10px 20px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      flex: 1;
      min-width: 160px;
    }
    button.primary:hover { background: #0369a1; }
    button.primary:disabled { opacity: 0.6; cursor: wait; }
    .verdict-box {
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 14px;
      border: 1px solid var(--border);
      background: #0f172a;
    }
    .verdict-box.safe { background: var(--safe-bg); border-color: var(--safe); }
    .verdict-box.suspicious { background: var(--suspicious-bg); border-color: var(--suspicious); }
    .verdict-box.danger { background: var(--danger-bg); border-color: var(--danger); }
    .verdict-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }
    .verdict-title { font-size: 1.15rem; font-weight: 700; }
    .score-badge {
      font-size: 0.9rem;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.65);
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin: 10px 0;
    }
    .chip {
      font-size: 0.78rem;
      padding: 3px 9px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid rgba(255,255,255,0.18);
    }
    pre {
      margin: 0;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      overflow-x: auto;
      font-size: 0.82rem;
      color: #bae6fd;
      max-height: 360px;
    }
    .endpoint-bar {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.82rem;
      color: var(--muted);
      margin-bottom: 12px;
      padding: 8px 12px;
      background: #090d16;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <h1>🛡️ Scam Shield — Backend API Server</h1>
        <p>Contract v1.0.0 ready for Frontend integration • One Scam Brain, Many Channels</p>
      </div>
      <div class="links">
        <span id="healthPill" class="pill">Checking /api/v1/health...</span>
        <span id="enginePill" class="pill">Engine: ...</span>
        <a class="pill link" href="/docs" target="_blank">Open Swagger /docs ↗</a>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <h2>Test <code>POST /api/v1/analyze</code> (Spec Shared Test Cases)</h2>
        <div class="presets">
          <button class="preset-btn" onclick="loadPreset(0)">1. Prize + OTP Scam</button>
          <button class="preset-btn" onclick="loadPreset(1)">2. Fake Bank URL</button>
          <button class="preset-btn" onclick="loadPreset(2)">3. Safe Class Message</button>
          <button class="preset-btn" onclick="loadPreset(3)">4. Hindi OTP Scam</button>
          <button class="preset-btn" onclick="loadPreset(4)">5. Fake Job Fee</button>
          <button class="preset-btn" onclick="loadPreset(5)">6. Kannada Bank Scam</button>
        </div>

        <textarea id="msgInput" placeholder="Paste suspicious SMS, WhatsApp, or email text here...">Congratulations! You won $5000! Claim now, send your OTP!</textarea>

        <div class="controls">
          <select id="langSelect" title="Response Language">
            <option value="">Language: Auto-detect</option>
            <option value="en">English (en)</option>
            <option value="hi">Hindi (hi)</option>
            <option value="kn">Kannada (kn)</option>
            <option value="ta">Tamil (ta)</option>
            <option value="te">Telugu (te)</option>
            <option value="bn">Bengali (bn)</option>
            <option value="sw">Swahili (sw)</option>
          </select>
          <button id="runBtn" class="primary" onclick="runAnalyze()">Send POST /api/v1/analyze</button>
        </div>
      </div>

      <div class="card">
        <h2>Contract Response Inspector</h2>
        <div id="visualPreview" class="verdict-box">
          <div class="verdict-top">
            <span class="verdict-title" id="vHeadline">Click "Send POST /api/v1/analyze" to test</span>
            <span class="score-badge" id="vScore">Score: —</span>
          </div>
          <div id="vExplain" style="font-size:0.92rem; color:#e2e8f0;"></div>
          <div id="vChips" class="chips"></div>
          <div id="vAction" style="font-size:0.88rem; font-weight:600; margin-top:6px;"></div>
        </div>

        <div class="endpoint-bar" id="statusBar">HTTP Status: Ready</div>
        <pre id="jsonOut">{
  "tip": "Raw JSON returned by POST /api/v1/analyze will appear here so your Frontend partner can inspect every field."
}</pre>
      </div>
    </div>
  </div>

  <script>
    const PRESETS = [
      { text: "Congratulations! You won $5000! Claim now, send your OTP!", lang: "" },
      { text: "Your account is blocked. Verify immediately: http://fake-bank-login.xyz", lang: "" },
      { text: "Class moved to 10am. Bring your notebook.", lang: "" },
      { text: "बधाई हो! आपने ₹5,00,000 का लकी ड्रा इनाम जीता है! अभी अपना OTP भेजें और पैसे प्राप्त करें।", lang: "" },
      { text: "Urgent Hiring! Work from home & earn ₹4500 daily. Pay ₹499 refundable registration fee to join immediately.", lang: "" },
      { text: "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗಿದೆ. ತಕ್ಷಣ ನಿಮ್ಮ OTP ಕಳುಹಿಸಿ.", lang: "" }
    ];

    function loadPreset(idx) {
      const p = PRESETS[idx];
      document.getElementById("msgInput").value = p.text;
      document.getElementById("langSelect").value = p.lang;
      runAnalyze();
    }

    async function checkServerStatus() {
      try {
        const [hRes, mRes] = await Promise.all([
          fetch("/api/v1/health"),
          fetch("/api/v1/meta")
        ]);
        const h = await hRes.json();
        const m = await mRes.json();
        const hp = document.getElementById("healthPill");
        hp.textContent = "Health: " + h.status.toUpperCase() + " (v" + h.version + ")";
        hp.classList.add("ok");

        const ep = document.getElementById("enginePill");
        ep.textContent = m.ai_provider === "rules_only"
          ? "Mode: Smart Rules (Add Free Gemini/Groq Key Optional)"
          : "Mode: Hybrid Rules + AI (" + m.ai_provider + ")";
      } catch (err) {
        document.getElementById("healthPill").textContent = "Health check error";
      }
    }

    async function runAnalyze() {
      const btn = document.getElementById("runBtn");
      const msg = document.getElementById("msgInput").value;
      const lang = document.getElementById("langSelect").value;
      btn.disabled = true;
      btn.textContent = "Analyzing...";

      const payload = { message: msg, source: "web" };
      if (lang) payload.language = lang;

      const t0 = performance.now();
      try {
        const res = await fetch("/api/v1/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const ms = Math.round(performance.now() - t0);
        const data = await res.json();

        document.getElementById("statusBar").textContent =
          "HTTP " + res.status + " • " + ms + " ms • Content-Type: application/json";
        document.getElementById("jsonOut").textContent = JSON.stringify(data, null, 2);

        const box = document.getElementById("visualPreview");
        box.className = "verdict-box " + (data.verdict || "");

        if (res.ok) {
          document.getElementById("vHeadline").textContent =
            data.verdict_emoji + " " + data.display.headline;
          document.getElementById("vScore").textContent =
            data.verdict.toUpperCase() + " • " + data.risk_score + "/100 • " + data.scam_type;
          document.getElementById("vExplain").textContent = data.explanation;
          document.getElementById("vAction").textContent = "Safe Action: " + data.safe_action;

          const chips = document.getElementById("vChips");
          chips.innerHTML = "";
          (data.red_flags || []).forEach(f => {
            const s = document.createElement("span");
            s.className = "chip";
            s.textContent = "🚩 " + f;
            chips.appendChild(s);
          });
        } else {
          document.getElementById("vHeadline").textContent = "⚠️ HTTP " + res.status + " (" + data.error + ")";
          document.getElementById("vScore").textContent = "Error";
          document.getElementById("vExplain").textContent = data.message || "";
          document.getElementById("vChips").innerHTML = "";
          document.getElementById("vAction").textContent = "";
        }
      } catch (e) {
        document.getElementById("statusBar").textContent = "Network error: " + e.message;
      } finally {
        btn.disabled = false;
        btn.textContent = "Send POST /api/v1/analyze";
      }
    }

    checkServerStatus();
    runAnalyze();
  </script>
</body>
</html>
"""

app = create_app()
