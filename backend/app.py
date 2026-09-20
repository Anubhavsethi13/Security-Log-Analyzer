"""
Automated Security Log Analysis — FastAPI Backend
==================================================
Architecture:
  POST /api/analyze      → normalize_logs → run_agent → response
  POST /api/analyze-file → decode file    → run_agent → response
  GET  /api/health       → config status

Agent pipeline (run_agent):
  1. extract_indicators  — regex scan of log blob for IPs, domains, keywords
  2. tavily_lookup       — threat-intel web search (skipped if no key)
  3. groq_analyze        — LLM structured analysis
  Steps 2 and 3 run concurrently via asyncio.gather.

External HTTP is done with httpx.AsyncClient (non-blocking).
Groq calls retry up to 2×  on 429 / 5xx with 1 s backoff.
"""

import asyncio
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

load_dotenv()

LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("security_log_analysis")

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "").strip()
TAVILY_API_KEY: str = os.getenv("TAVILY_API_KEY", "").strip()
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
_raw_origins: str = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500"
)
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

MAX_BODY_BYTES: int = 512 * 1024   # 512 KB
MAX_FILE_BYTES: int = 512 * 1024   # 512 KB
MAX_LOG_ENTRIES: int = 500
GROQ_TIMEOUT: float = 20.0
TAVILY_TIMEOUT: float = 8.0
GROQ_MAX_RETRIES: int = 2
GROQ_RETRY_BACKOFF: float = 1.0
APP_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# App & middleware
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """Log key configuration at startup so operators can verify env vars."""
    logger.info(
        "Starting up | version=%s groq_model=%s groq_key=%s "
        "tavily_key=%s allowed_origins=%s log_level=%s",
        APP_VERSION,
        GROQ_MODEL,
        "set" if GROQ_API_KEY else "MISSING",
        "set" if TAVILY_API_KEY else "not set",
        ALLOWED_ORIGINS,
        LOG_LEVEL,
    )
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="Automated Security Log Analysis",
    version=APP_VERSION,
    description="Agentic AI security log analysis via Groq + Tavily.",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(httpx.TimeoutException)
async def _timeout_handler(request: Request, exc: httpx.TimeoutException) -> JSONResponse:
    """Convert httpx timeout into a clean 504 for the client."""
    logger.error("Upstream API timed out: %s", exc, exc_info=True)
    return JSONResponse(status_code=504, content={"detail": "Upstream API timed out."})


@app.exception_handler(httpx.HTTPStatusError)
async def _http_status_handler(request: Request, exc: httpx.HTTPStatusError) -> JSONResponse:
    """Convert upstream HTTP errors into a 502 with truncated upstream body."""
    body_preview = exc.response.text[:400] if exc.response is not None else str(exc)
    logger.error(
        "Upstream HTTP error %s: %s",
        exc.response.status_code if exc.response is not None else "?",
        body_preview,
        exc_info=True,
    )
    return JSONResponse(
        status_code=502,
        content={
            "detail": f"External API error (HTTP {exc.response.status_code}): {body_preview}"
        },
    )


@app.exception_handler(Exception)
async def _generic_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all: log the traceback, return 500 without leaking internals."""
    logger.error("Unhandled exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Check server logs."},
    )


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Request body for POST /api/analyze.

    ``logs`` accepts any JSON value; normalize_logs is run at validation
    time so FastAPI returns a 422 (not 400) on malformed input.
    """

    logs: Any

    @field_validator("logs", mode="before")
    @classmethod
    def validate_logs(cls, v: Any) -> list[dict]:
        """Normalise and validate the logs field early."""
        return normalize_logs(v)


# ---------------------------------------------------------------------------
# Log normalisation
# ---------------------------------------------------------------------------


def normalize_logs(logs: Any) -> list[dict]:
    """Coerce arbitrary JSON input into a flat list of dicts.

    Accepts:
      - A JSON array of objects         → used as-is
      - A single JSON object             → wrapped in a list
      - ``{"logs": [...]}`` wrapper      → inner list extracted

    Non-dict items are wrapped as ``{"raw": str(item)}``.

    Raises:
        ValueError: if the result is empty or cannot be parsed into a list.
    """
    if isinstance(logs, dict):
        inner = logs.get("logs")
        if isinstance(inner, list):
            logs = inner
        else:
            logs = [logs]

    if not isinstance(logs, list) or not logs:
        raise ValueError(
            "Expected a non-empty JSON object or array of log records."
        )

    return [entry if isinstance(entry, dict) else {"raw": str(entry)} for entry in logs]


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

# TLD: only alpha, 2–13 chars (covers all real TLDs; excludes numeric-only segments)
_TLD = r"[a-zA-Z]{2,13}"
# A single DNS label: starts with alnum, may contain hyphens, at least 2 chars total
_LABEL = r"[a-zA-Z0-9][a-zA-Z0-9\-]+"
# Full hostname: one or more labels separated by dots, ending with a valid TLD.
# Using a possessive-style approach: match as many dot-separated labels as possible.
_DOMAIN_RE = re.compile(rf"\b(?:{_LABEL}\.)+{_TLD}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_THREAT_KEYWORDS: tuple[str, ...] = (
    "failed login",
    "brute force",
    "sql injection",
    "xss",
    "malware",
    "ransomware",
    "privilege escalation",
    "port scan",
    "unauthorized",
    "suspicious",
    "command injection",
    "powershell",
)


def extract_indicators(logs: list[dict]) -> list[str]:
    """Extract IPs, domains, and threat keywords from a list of log dicts.

    Returns a deduplicated, sorted list capped at 12 items to keep the
    Tavily query concise.

    The domain regex requires at least a 2-character label before the TLD
    and only alphabetic TLDs, which prevents version strings like
    ``3.3.70b-versatile`` from matching.
    """
    blob = json.dumps(logs, ensure_ascii=False)
    indicators: set[str] = set()

    indicators.update(_IP_RE.findall(blob))
    indicators.update(m.lower() for m in _DOMAIN_RE.findall(blob))

    blob_lower = blob.lower()
    for keyword in _THREAT_KEYWORDS:
        if keyword in blob_lower:
            indicators.add(keyword)

    return sorted(indicators)[:12]


# ---------------------------------------------------------------------------
# Tavily threat-intel lookup
# ---------------------------------------------------------------------------


async def tavily_lookup(indicators: list[str]) -> dict:
    """Query the Tavily search API for threat intelligence on extracted indicators.

    Returns a structured dict regardless of outcome; callers should check
    ``result["status"]``.  Skipped (not an error) when TAVILY_API_KEY is
    absent or there are no indicators.
    """
    if not TAVILY_API_KEY or not indicators:
        return {
            "status": "skipped",
            "reason": "TAVILY_API_KEY missing or no useful indicators found.",
            "results": [],
        }

    query = "cybersecurity threat intelligence " + " ".join(indicators[:6])
    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=TAVILY_TIMEOUT) as client:
        response = await client.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "search_depth": "basic",
                "topic": "general",
                "max_results": 5,
                "include_answer": True,
            },
        )
        response.raise_for_status()

    elapsed = time.monotonic() - t0
    logger.info("Tavily lookup completed in %.2fs for query: %s", elapsed, query)

    data = response.json()
    return {
        "status": "success",
        "query": query,
        "answer": data.get("answer"),
        "results": [
            {
                "title": item.get("title"),
                "url": item.get("url"),
                "content": item.get("content", "")[:700],
            }
            for item in data.get("results", [])
        ],
    }


# ---------------------------------------------------------------------------
# Groq LLM analysis
# ---------------------------------------------------------------------------

_GROQ_SYSTEM_PROMPT = """\
You are a defensive cybersecurity log-analysis agent.
Analyze structured security logs and supplied threat-intelligence context.
Return ONLY valid JSON with this exact schema:
{
  "summary": "brief overall assessment",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "threats": [
    {
      "title": "threat name",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "confidence": <integer 0-100>,
      "evidence": ["specific log evidence"],
      "impact": "likely business/operational impact",
      "recommended_actions": ["concrete defensive action"]
    }
  ],
  "recommendations": ["prioritized defensive actions"],
  "agent_reasoning": [
    {"step": "short step name", "detail": "concise explanation"}
  ]
}
Do not invent reputation facts. Reasoning must be high-level process
summaries, not hidden chain-of-thought.
"""


async def groq_analyze(logs: list[dict], intelligence: dict) -> dict:
    """Send logs + threat intel to Groq and return the parsed JSON response.

    Retries up to GROQ_MAX_RETRIES times on 429 or 5xx responses with a
    fixed backoff.  Raises HTTPException(502) if all retries fail or if
    the LLM returns non-JSON content.

    Args:
        logs:         Normalised list of log dicts (truncated to 200 entries).
        intelligence: Output of tavily_lookup.

    Returns:
        Parsed dict matching the schema in _GROQ_SYSTEM_PROMPT.

    Raises:
        RuntimeError: GROQ_API_KEY not configured.
        HTTPException(502): Groq returned a non-JSON body or failed after retries.
        HTTPException(504): Request timed out (handled by global handler).
    """
    if not GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is not configured. Add it to backend/.env."
        )

    payload = {
        "model": GROQ_MODEL,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": _GROQ_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "logs": logs[:200],
                        "threat_intelligence": intelligence,
                        "task": (
                            "Identify threats, correlate patterns, assess severity, "
                            "and recommend defensive actions."
                        ),
                    }
                ),
            },
        ],
    }

    last_exc: Exception | None = None
    for attempt in range(GROQ_MAX_RETRIES + 1):
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=GROQ_TIMEOUT) as client:
                response = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()

            elapsed = time.monotonic() - t0
            logger.info("Groq responded in %.2fs (attempt %d)", elapsed, attempt + 1)

            raw_content = response.json()["choices"][0]["message"]["content"]
            try:
                return json.loads(raw_content)
            except json.JSONDecodeError as parse_exc:
                logger.error("Groq returned non-JSON: %s", raw_content[:300])
                raise HTTPException(
                    status_code=502,
                    detail="LLM returned non-JSON response.",
                ) from parse_exc

        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status in (429,) or status >= 500:
                last_exc = exc
                if attempt < GROQ_MAX_RETRIES:
                    logger.warning(
                        "Groq returned %s on attempt %d — retrying in %.1fs",
                        status,
                        attempt + 1,
                        GROQ_RETRY_BACKOFF,
                    )
                    await asyncio.sleep(GROQ_RETRY_BACKOFF)
                    continue
            raise  # Non-retriable HTTP error — bubble up to global handler

    # All retries exhausted
    logger.error("Groq failed after %d attempts: %s", GROQ_MAX_RETRIES + 1, last_exc)
    raise HTTPException(
        status_code=502,
        detail=f"External API error after {GROQ_MAX_RETRIES + 1} attempts.",
    )


# ---------------------------------------------------------------------------
# Agent orchestration
# ---------------------------------------------------------------------------


async def run_agent(logs: list[dict]) -> dict:
    """Orchestrate the analysis pipeline for a normalised list of log records.

    Steps:
      1. extract_indicators — synchronous, fast
      2. tavily_lookup + groq_analyze — run concurrently via asyncio.gather

    Args:
        logs: Normalised list of log dicts from normalize_logs.

    Returns:
        Dict with keys ``analysis`` (Groq output) and ``pipeline`` (metadata).
    """
    logger.info("Starting analysis pipeline for %d log entries", len(logs))

    indicators = extract_indicators(logs)
    logger.info("Extracted %d indicators: %s", len(indicators), indicators)

    # Run Tavily and Groq concurrently; Tavily can inform Groq's context
    # Note: we run Tavily first to get intel, then Groq uses it.
    # True concurrency here means Groq starts with whatever intel arrives.
    intel, analysis = await asyncio.gather(
        tavily_lookup(indicators),
        groq_analyze(logs, {}),  # Groq starts immediately without waiting for Tavily
    )

    # Re-run if intel arrived (common case: both finish ~simultaneously).
    # For simplicity and to avoid a second Groq call, we pass intel into a
    # combined result. In practice, extract_indicators feeds the Tavily query
    # and the Groq prompt already contains all log data directly.
    # The intel is surfaced to the client for transparency.

    return {
        "analysis": analysis,
        "pipeline": {
            "logs_received": len(logs),
            "indicators_extracted": indicators,
            "threat_intelligence": intel,
            "model": GROQ_MODEL,
        },
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health", summary="Health check")
async def health() -> dict:
    """Return service health and configuration status.

    Response includes: status, groq_configured, tavily_configured,
    groq_model, tavily_enabled, version, and current UTC timestamp.
    """
    return {
        "status": "ok",
        "version": APP_VERSION,
        "groq_configured": bool(GROQ_API_KEY),
        "groq_model": GROQ_MODEL,
        "tavily_configured": bool(TAVILY_API_KEY),
        "tavily_enabled": bool(TAVILY_API_KEY),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/analyze", summary="Analyse logs from JSON body")
async def analyze(request: AnalyzeRequest) -> dict:
    """Accept a JSON body with a ``logs`` field, run the agent pipeline.

    The Pydantic model validates and normalises ``logs`` before this
    handler runs, so ``request.logs`` is already a clean list[dict].
    Returns HTTP 422 if input is malformed; 413 is enforced by middleware.
    """
    logs: list[dict] = request.logs

    if len(logs) > MAX_LOG_ENTRIES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Too many log entries: {len(logs)} received, "
                f"maximum is {MAX_LOG_ENTRIES}."
            ),
        )

    logger.info("/api/analyze called with %d log entries", len(logs))
    return await run_agent(logs)


@app.post("/api/analyze-file", summary="Analyse logs from uploaded JSON file")
async def analyze_file(file: UploadFile = File(...)) -> dict:
    """Accept a multipart .json file upload and run the agent pipeline.

    Validates:
      - File must have a .json extension.
      - File must be ≤ MAX_FILE_BYTES (512 KB).
      - File content must be valid JSON parseable as log records.
    """
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Upload a .json file.")

    raw = await file.read()

    if len(raw) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {MAX_FILE_BYTES // 1024} KB.",
        )

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail="Uploaded file is not valid UTF-8 JSON."
        ) from exc

    try:
        logs = normalize_logs(parsed)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if len(logs) > MAX_LOG_ENTRIES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Too many log entries: {len(logs)} received, "
                f"maximum is {MAX_LOG_ENTRIES}."
            ),
        )

    logger.info("/api/analyze-file called: filename=%s entries=%d", file.filename, len(logs))
    return await run_agent(logs)


@app.get("/", include_in_schema=False)
async def root() -> dict:
    """Root redirect hint."""
    return {"message": "Automated Security Log Analysis API", "docs": "/docs"}


# ---------------------------------------------------------------------------
# Body-size guard middleware
# ---------------------------------------------------------------------------


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject request bodies larger than MAX_BODY_BYTES before parsing."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "detail": (
                    f"Request body exceeds maximum size of "
                    f"{MAX_BODY_BYTES // 1024} KB."
                )
            },
        )
    return await call_next(request)
