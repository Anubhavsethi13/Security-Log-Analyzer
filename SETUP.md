# Setup

## Prerequisites

- Python 3.10+
- A modern browser
- [Groq API key](https://console.groq.com) (required)
- [Tavily API key](https://tavily.com) (optional — threat intel enrichment is skipped if absent)

---

## API keys

```bash
cp backend/.env.example backend/.env
# Edit backend/.env and fill in GROQ_API_KEY (and optionally TAVILY_API_KEY)
```

Never commit `.env`.

---

## Backend

**macOS / Linux**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

**Windows (PowerShell)**

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

API docs available at <http://127.0.0.1:8000/docs>.

---

## Frontend

In a second terminal:

```bash
cd frontend
python -m http.server 5500
```

Open <http://127.0.0.1:5500>.

---

## Running tests

```bash
cd backend                        # or from project root:
pytest backend/ -v                #   pytest backend/ -v
```

No real API keys are needed — all external HTTP calls are mocked.  
Requirements: install from `requirements.txt` (pytest, pytest-asyncio, pytest-httpx are included).

---

## Environment variable reference

| Variable          | Required | Default                                          | Description                                  |
|-------------------|----------|--------------------------------------------------|----------------------------------------------|
| `GROQ_API_KEY`    | ✅ yes   | —                                                | Groq API key                                 |
| `TAVILY_API_KEY`  | ❌ no    | —                                                | Tavily key; enrichment skipped if absent     |
| `GROQ_MODEL`      | ❌ no    | `llama-3.3-70b-versatile`                        | Groq model ID                                |
| `ALLOWED_ORIGINS` | ❌ no    | `http://localhost:5500,http://127.0.0.1:5500`    | Comma-separated CORS origins                 |
| `LOG_LEVEL`       | ❌ no    | `INFO`                                           | `DEBUG` / `INFO` / `WARNING` / `ERROR`       |
| `PORT`            | ❌ no    | `8000`                                           | Informational — pass to uvicorn manually     |

---

## Production hardening

1. **CORS** — Set `ALLOWED_ORIGINS` to your actual frontend domain only:
   ```
   ALLOWED_ORIGINS=https://your-app.example.com
   ```

2. **No `--reload`** — The reload flag is for development only. In production:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2
   ```

3. **Reverse proxy** — Run behind nginx or caddy; let the proxy handle TLS termination
   and static file serving. Example nginx block:
   ```nginx
   location /api/ {
       proxy_pass http://127.0.0.1:8000;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
   }
   ```

4. **Keep API keys server-side** — Never expose `GROQ_API_KEY` or `TAVILY_API_KEY`
   to the browser or client code.

5. **Avoid uploading real production logs** — This is a course-ready educational tool;
   sanitise or anonymise logs before uploading.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Backend not reachable | uvicorn not running | Start on port 8000 |
| `GROQ_API_KEY is not configured` | Missing `.env` | Copy `.env.example` → `.env`, add key |
| Tavily errors in response | Missing key or Tavily down | Enrichment is skipped/reported — analysis still works |
| Invalid JSON error | Pasted text isn't JSON | Use **Load sample** or upload `mock-logs.json` |
| CORS errors in browser | `ALLOWED_ORIGINS` mismatch | Add your origin to `ALLOWED_ORIGINS` in `.env` |
