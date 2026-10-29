# Scam Shield — Frontend

A responsive, mobile-first web checker for the Scam Shield API. This frontend does **not** make scam decisions in the browser: it sends the message to the backend's `POST /api/v1/analyze` endpoint and displays the returned verdict, score, explanation, red flags, and safe action.

## Run locally

No build step or package installation is required.

```bash
cd scam-shield/frontend
python3 -m http.server 5173 --bind 0.0.0.0
```

Open `http://localhost:5173` and start the backend separately. The default API base URL is `http://localhost:8000`; the frontend appends `/api/v1/analyze`. To use another backend during local development, set `localStorage.setItem('scamshield_api_base', 'https://your-api.example')` in the browser console before checking a message.

The backend must allow the frontend origin through CORS. For local development, allow `http://localhost:5173` (and whichever host/origin you use to view the app).

## Included

- Three input modes: SMS, suspicious calls, and payment requests
- Context-aware examples for SMS and payment requests; call mode uses selectable warning-sign checkboxes that are included with the user's notes
- Horizontal risk meter: green for 0–30, yellow for 31–65, red for 66–100
- Message input with a 5,000-character limit and live counter
- Full interface language switcher: English (default), Hindi, and Kannada; the selected language is sent to the backend for localized analysis
- Loading, validation, timeout, rate-limit, and server-error states
- Accessible, responsive result card for safe / suspicious / danger verdicts
- API base URL stored in browser local storage; no API keys or secrets in the frontend

## API payload

```json
{
  "message": "message text",
  "language": "hi",
  "source": "web",
  "metadata": { "has_url": false, "urls": [], "phone_numbers": [] }
}
```

The `language` property follows the selected interface language (`en`, `hi`, or `kn`). See the project specification for the full response contract.
