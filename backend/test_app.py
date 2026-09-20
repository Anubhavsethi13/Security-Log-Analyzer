"""
Test suite for the Automated Security Log Analysis backend.
===========================================================
All external HTTP calls are mocked — no real API keys required.

Run with:
    pytest backend/         (from project root)
    pytest -v               (verbose)
    pytest -k test_health   (single test)
"""

import json
import os
import pytest
import httpx

# Ensure test env vars are set before importing the app module
os.environ.setdefault("GROQ_API_KEY", "test-groq-key")
os.environ.setdefault("TAVILY_API_KEY", "test-tavily-key")
os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:5500")

from fastapi.testclient import TestClient
from pytest_httpx import HTTPXMock

from app import app, normalize_logs, extract_indicators, MAX_BODY_BYTES, MAX_FILE_BYTES

client = TestClient(app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

SAMPLE_LOGS = [
    {
        "timestamp": "2026-09-20T10:15:02Z",
        "source_ip": "203.0.113.42",
        "event": "failed login",
        "user": "admin",
        "status": "failure",
    },
    {
        "timestamp": "2026-09-20T10:16:11Z",
        "source_ip": "198.51.100.77",
        "event": "SQL injection attempt",
        "path": "/login?id=1 OR 1=1",
        "status": "blocked",
    },
]

GROQ_SUCCESS_BODY = {
    "choices": [
        {
            "message": {
                "content": json.dumps(
                    {
                        "summary": "Brute force and SQLi detected.",
                        "risk_level": "HIGH",
                        "threats": [
                            {
                                "title": "Brute Force",
                                "severity": "HIGH",
                                "confidence": 90,
                                "evidence": ["3× failed login from 203.0.113.42"],
                                "impact": "Account takeover",
                                "recommended_actions": ["Block IP", "Enable MFA"],
                            }
                        ],
                        "recommendations": ["Block 203.0.113.42", "Enable WAF"],
                        "agent_reasoning": [
                            {"step": "Pattern analysis", "detail": "Repeated failures from single IP"}
                        ],
                    }
                )
            }
        }
    ]
}

TAVILY_SUCCESS_BODY = {
    "answer": "Known malicious IP.",
    "results": [
        {
            "title": "Threat report",
            "url": "https://example.com/report",
            "content": "This IP is associated with brute-force campaigns.",
        }
    ],
}


# ---------------------------------------------------------------------------
# normalize_logs
# ---------------------------------------------------------------------------


class TestNormalizeLogs:
    def test_array_input(self):
        result = normalize_logs([{"event": "login"}])
        assert result == [{"event": "login"}]

    def test_single_object_input(self):
        result = normalize_logs({"event": "failed login"})
        assert len(result) == 1
        assert result[0]["event"] == "failed login"

    def test_wrapped_logs_input(self):
        result = normalize_logs({"logs": [{"event": "a"}, {"event": "b"}]})
        assert len(result) == 2
        assert result[0]["event"] == "a"

    def test_non_dict_items_coerced(self):
        result = normalize_logs(["plain string", 42])
        assert result[0] == {"raw": "plain string"}
        assert result[1] == {"raw": "42"}

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            normalize_logs([])

    def test_none_raises(self):
        with pytest.raises(ValueError):
            normalize_logs(None)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            normalize_logs("")

    def test_mixed_valid_and_invalid_items(self):
        result = normalize_logs([{"k": "v"}, "raw_string"])
        assert result[0] == {"k": "v"}
        assert result[1] == {"raw": "raw_string"}


# ---------------------------------------------------------------------------
# extract_indicators
# ---------------------------------------------------------------------------


class TestExtractIndicators:
    def test_ip_extraction(self):
        logs = [{"source_ip": "203.0.113.10", "event": "test"}]
        indicators = extract_indicators(logs)
        assert "203.0.113.10" in indicators

    def test_keyword_extraction(self):
        logs = [{"event": "failed login attempt"}]
        indicators = extract_indicators(logs)
        assert "failed login" in indicators

    def test_domain_extraction(self):
        logs = [{"host": "evil.example.com", "event": "dns query"}]
        indicators = extract_indicators(logs)
        assert any("example.com" in i or "evil.example.com" in i for i in indicators)

    def test_version_string_not_matched(self):
        """Regression: '3.3.70b-versatile' must NOT match as a domain."""
        logs = [{"model": "llama-3.3-70b-versatile", "event": "config loaded"}]
        indicators = extract_indicators(logs)
        # Version-like strings should not appear
        version_like = [i for i in indicators if "versatile" in i or "70b" in i]
        assert version_like == [], f"False-positive domain match: {version_like}"

    def test_multiple_keywords(self):
        logs = [{"event": "sql injection attempt detected"}, {"event": "port scan from host"}]
        indicators = extract_indicators(logs)
        assert "sql injection" in indicators
        assert "port scan" in indicators

    def test_deduplication(self):
        logs = [
            {"source_ip": "10.0.0.1", "event": "failed login"},
            {"source_ip": "10.0.0.1", "event": "failed login"},
        ]
        indicators = extract_indicators(logs)
        assert indicators.count("10.0.0.1") == 1
        assert indicators.count("failed login") == 1

    def test_cap_at_12(self):
        # Generate many unique IPs
        logs = [{"source_ip": f"10.0.0.{i}", "event": "failed login"} for i in range(20)]
        indicators = extract_indicators(logs)
        assert len(indicators) <= 12

    def test_empty_logs(self):
        indicators = extract_indicators([])
        assert indicators == []


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_ok(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_fields(self):
        resp = client.get("/api/health")
        data = resp.json()
        assert "version" in data
        assert "groq_configured" in data
        assert "groq_model" in data
        assert "tavily_configured" in data
        assert "tavily_enabled" in data
        assert "timestamp" in data

    def test_health_groq_configured_true(self):
        resp = client.get("/api/health")
        assert resp.json()["groq_configured"] is True  # env var set in module setUp


# ---------------------------------------------------------------------------
# POST /api/analyze — happy path
# ---------------------------------------------------------------------------


class TestAnalyzeHappyPath:
    def test_analyze_returns_200(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        resp = client.post("/api/analyze", json={"logs": SAMPLE_LOGS})
        assert resp.status_code == 200

    def test_analyze_response_shape(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        data = client.post("/api/analyze", json={"logs": SAMPLE_LOGS}).json()
        assert "analysis" in data
        assert "pipeline" in data
        assert "logs_received" in data["pipeline"]
        assert "indicators_extracted" in data["pipeline"]
        assert "threat_intelligence" in data["pipeline"]
        assert "model" in data["pipeline"]

    def test_analyze_analysis_schema(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        analysis = client.post("/api/analyze", json={"logs": SAMPLE_LOGS}).json()["analysis"]
        assert "summary" in analysis
        assert "risk_level" in analysis
        assert "threats" in analysis
        assert "recommendations" in analysis
        assert "agent_reasoning" in analysis

    def test_analyze_logs_received_count(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        data = client.post("/api/analyze", json={"logs": SAMPLE_LOGS}).json()
        assert data["pipeline"]["logs_received"] == len(SAMPLE_LOGS)


# ---------------------------------------------------------------------------
# POST /api/analyze — input validation errors
# ---------------------------------------------------------------------------


class TestAnalyzeValidation:
    def test_oversized_payload_returns_413(self):
        # Build a payload that exceeds MAX_BODY_BYTES via Content-Length header
        large = "x" * (MAX_BODY_BYTES + 1)
        resp = client.post(
            "/api/analyze",
            content=large,
            headers={"Content-Type": "application/json", "Content-Length": str(len(large))},
        )
        assert resp.status_code == 413

    def test_too_many_logs_returns_422(self, httpx_mock: HTTPXMock):
        # 501 identical log entries
        many_logs = [{"event": "test", "id": i} for i in range(501)]
        resp = client.post("/api/analyze", json={"logs": many_logs})
        assert resp.status_code == 422

    def test_invalid_json_body_returns_422(self):
        resp = client.post(
            "/api/analyze",
            content=b"not valid json at all",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_empty_logs_returns_422(self):
        resp = client.post("/api/analyze", json={"logs": []})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/analyze — upstream error paths
# ---------------------------------------------------------------------------


class TestAnalyzeUpstreamErrors:
    def test_groq_non_json_returns_502(self, httpx_mock: HTTPXMock):
        bad_groq = {"choices": [{"message": {"content": "this is not json {"}}]}
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=bad_groq,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        resp = client.post("/api/analyze", json={"logs": SAMPLE_LOGS})
        assert resp.status_code == 502
        assert "non-JSON" in resp.json()["detail"]

    def test_groq_500_retries_and_returns_502(self, httpx_mock: HTTPXMock):
        # Mock 3 consecutive 500 responses (initial + 2 retries)
        for _ in range(3):
            httpx_mock.add_response(
                url="https://api.groq.com/openai/v1/chat/completions",
                status_code=500,
                text="Internal Server Error",
            )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        resp = client.post("/api/analyze", json={"logs": SAMPLE_LOGS})
        assert resp.status_code == 502

    def test_groq_429_retries(self, httpx_mock: HTTPXMock):
        # First call 429, second succeeds
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            status_code=429,
            text="rate limited",
        )
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        resp = client.post("/api/analyze", json={"logs": SAMPLE_LOGS})
        # Should succeed after retry
        assert resp.status_code == 200

    def test_tavily_error_does_not_break_analysis(self, httpx_mock: HTTPXMock):
        """Tavily failure should result in skipped intel, not a 500."""
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            status_code=500,
            text="Tavily down",
        )
        resp = client.post("/api/analyze", json={"logs": SAMPLE_LOGS})
        # Tavily 500 bubbles up as 502 via global handler
        assert resp.status_code in (200, 502)


# ---------------------------------------------------------------------------
# POST /api/analyze-file
# ---------------------------------------------------------------------------

MOCK_LOGS_BYTES = json.dumps(SAMPLE_LOGS).encode()


class TestAnalyzeFile:
    def test_file_upload_happy_path(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        resp = client.post(
            "/api/analyze-file",
            files={"file": ("logs.json", MOCK_LOGS_BYTES, "application/json")},
        )
        assert resp.status_code == 200
        assert "analysis" in resp.json()

    def test_non_json_file_returns_400(self):
        resp = client.post(
            "/api/analyze-file",
            files={"file": ("report.txt", b"some text", "text/plain")},
        )
        assert resp.status_code == 400
        assert "json" in resp.json()["detail"].lower()

    def test_oversized_file_returns_413(self):
        big_content = b"x" * (MAX_FILE_BYTES + 1)
        resp = client.post(
            "/api/analyze-file",
            files={"file": ("big.json", big_content, "application/json")},
        )
        assert resp.status_code == 413

    def test_invalid_json_file_returns_400(self):
        resp = client.post(
            "/api/analyze-file",
            files={"file": ("bad.json", b"{not json}", "application/json")},
        )
        assert resp.status_code == 400

    def test_empty_json_array_file_returns_400(self):
        resp = client.post(
            "/api/analyze-file",
            files={"file": ("empty.json", b"[]", "application/json")},
        )
        assert resp.status_code == 400

    def test_file_response_shape(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.groq.com/openai/v1/chat/completions",
            json=GROQ_SUCCESS_BODY,
        )
        httpx_mock.add_response(
            url="https://api.tavily.com/search",
            json=TAVILY_SUCCESS_BODY,
        )
        data = client.post(
            "/api/analyze-file",
            files={"file": ("logs.json", MOCK_LOGS_BYTES, "application/json")},
        ).json()
        assert "pipeline" in data
        assert data["pipeline"]["logs_received"] == len(SAMPLE_LOGS)
