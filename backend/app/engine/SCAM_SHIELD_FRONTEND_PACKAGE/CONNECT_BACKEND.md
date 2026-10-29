# Connect Scam Shield to the backend

The frontend calls the backend analyze endpoint at:

```text
POST http://localhost:8000/api/v1/analyze
```

By default, the app uses `http://localhost:8000` as its API base URL. If your backend runs on a different URL, open the browser developer console on the frontend page and run:

```js
localStorage.setItem('scamshield_api_base', 'https://your-backend-host.example')
location.reload()
```

Set the value to the backend **base URL only**—do not include `/api/v1/analyze`; the frontend appends that path automatically. To clear the override and return to the local default:

```js
localStorage.removeItem('scamshield_api_base')
location.reload()
```

## Local integration checklist

1. Start the backend so it is reachable at `http://localhost:8000`.
2. Make sure it implements `POST /api/v1/analyze` and the Scam Shield response contract.
3. Allow the frontend's origin in backend CORS settings. With the included static server, allow `http://localhost:5173`.
4. Serve the frontend from this folder:

   ```bash
   python3 -m http.server 5173 --bind 0.0.0.0
   ```

5. Open `http://localhost:5173`, submit a test message, and check the browser console/network panel if the request fails.

The frontend sends JSON in this shape:

```json
{
  "message": "message text or call description",
  "language": "en",
  "source": "web",
  "metadata": {
    "has_url": false,
    "urls": [],
    "phone_numbers": []
  }
}
```

The selected site language is sent as `language` (`en`, `hi`, or `kn`). Call-mode checkbox choices are included as part of the message text. Never put AI-provider credentials in the frontend.
