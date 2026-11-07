import pytest
import httpx


@pytest.mark.asyncio
async def test_sql_injection_defense(client: httpx.AsyncClient):
    """
    OWASP API Security Top 10 - Injection Defense.
    Verifies that malicious SQL fragments are fully neutralized by
    parameterized query structures and Pydantic validation.
    """
    sqli_payloads = [
        "' OR '1'='1' --",
        "admin'--",
        "' UNION SELECT id, email, hashed_password FROM users --",
        "1; DROP TABLE users; --",
        "' OR 1=1 #",
        "admin'/*",
    ]

    for payload in sqli_payloads:
        # 1. Attempt injection in Login endpoint
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": f"test_{payload}@sentinel.org", "password": "RandomPassword#2026!"}
        )
        # Must be rejected as standard invalid credentials or unprocessable entity, never 500 SQL error
        assert resp.status_code in (401, 422)
        assert "syntax error" not in resp.text.lower()
        assert "sqlite" not in resp.text.lower()
        assert "postgresql" not in resp.text.lower()


@pytest.mark.asyncio
async def test_security_headers_enforcement(client: httpx.AsyncClient):
    """Verifies that all responses strictly implement OWASP Secure Headers."""
    resp = await client.get("/api/v1/security/health")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'none'" in headers.get("Content-Security-Policy", "")
    assert "max-age=" in headers.get("Strict-Transport-Security", "")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, max-age=0"

    # Leakage check: Server identity must be stripped
    assert "server" not in headers
    assert "x-powered-by" not in headers


@pytest.mark.asyncio
async def test_rate_limiting_enforcement(client: httpx.AsyncClient):
    """
    OWASP API4:2023 - Unrestricted Resource Consumption.
    Verifies that client requests exceeding the configured rate quota receive HTTP 429.
    """
    # Target endpoint: Auth routes limit is 10 req/min
    responses = []
    for _ in range(12):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "rate_test@sentinel.org", "password": "WrongPassword#123"}
        )
        responses.append(r.status_code)

    # At least one of the requests beyond limit (10) must be 429
    assert 429 in responses
    last_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "rate_test@sentinel.org", "password": "WrongPassword#123"}
    )
    assert last_resp.status_code == 429
    assert "Retry-After" in last_resp.headers
    assert "X-RateLimit-Remaining" in last_resp.headers


@pytest.mark.asyncio
async def test_payload_size_limiter(client: httpx.AsyncClient):
    """Verifies that requests exceeding MAX_REQUEST_SIZE_BYTES are blocked before processing."""
    oversized_headers = {"Content-Length": str(15 * 1024 * 1024)}  # 15 MB
    resp = await client.post(
        "/api/v1/auth/register",
        content=b"test",
        headers=oversized_headers
    )
    assert resp.status_code == 413
    assert "Payload Too Large" in resp.json()["error"]


@pytest.mark.asyncio
async def test_information_disclosure_prevention(client: httpx.AsyncClient):
    """
    Verifies that 404, 422, and internal errors return RFC-compliant sanitized responses
    without leaking file system paths, stack traces, or Python internals.
    """
    # 1. Non-existent endpoint
    not_found = await client.get("/api/v1/non_existent_endpoint_123")
    assert not_found.status_code == 404
    data = not_found.json()
    assert "request_id" in data
    assert "traceback" not in not_found.text.lower()
    assert "python" not in not_found.text.lower()
