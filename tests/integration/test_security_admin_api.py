import pytest
import httpx


@pytest.mark.asyncio
async def test_health_check_public(client: httpx.AsyncClient):
    resp = await client.get("/api/v1/security/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "UP"
    assert data["database"] == "HEALTHY"
    assert "ARGON2ID" in data["crypto_engine"]


@pytest.mark.asyncio
async def test_security_telemetry_access(client: httpx.AsyncClient):
    # 1. Analyst login
    analyst_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@sentinel.org", "password": "Analyst#2026!Sec"}
    )
    analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}

    # 2. Analyst accesses security events
    events_resp = await client.get("/api/v1/security/events", headers=analyst_headers)
    assert events_resp.status_code == 200
    assert isinstance(events_resp.json(), list)

    # 3. Analyst accesses audit logs
    audit_resp = await client.get("/api/v1/security/audit-logs", headers=analyst_headers)
    assert audit_resp.status_code == 200
    assert isinstance(audit_resp.json(), list)

    # 4. Standard User denied access
    user_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user1@sentinel.org", "password": "Standard#2026!Sec"}
    )
    user_headers = {"Authorization": f"Bearer {user_login.json()['access_token']}"}

    denied_events = await client.get("/api/v1/security/events", headers=user_headers)
    assert denied_events.status_code == 403

    denied_audit = await client.get("/api/v1/security/audit-logs", headers=user_headers)
    assert denied_audit.status_code == 403


@pytest.mark.asyncio
async def test_admin_dashboard_and_users(client: httpx.AsyncClient):
    # 1. Admin login
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@sentinel.org", "password": "Admin#2026!Sec"}
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}

    # 2. Admin dashboard
    dash_resp = await client.get("/api/v1/admin/dashboard", headers=admin_headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert dash_data["total_users"] >= 4
    assert dash_data["system_status"] == "OPERATIONAL"

    # 3. Admin user roster
    users_resp = await client.get("/api/v1/admin/users", headers=admin_headers)
    assert users_resp.status_code == 200
    assert isinstance(users_resp.json(), list)

    # 4. Admin tries to access SUPER_ADMIN only endpoint (/admin/system-status) -> 403 Forbidden
    status_denied = await client.get("/api/v1/admin/system-status", headers=admin_headers)
    assert status_denied.status_code == 403


@pytest.mark.asyncio
async def test_super_admin_system_status(client: httpx.AsyncClient):
    # Super Admin login
    sa_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "superadmin@sentinel.org", "password": "SuperAdmin#2026!Sec"}
    )
    sa_headers = {"Authorization": f"Bearer {sa_login.json()['access_token']}"}

    resp = await client.get("/api/v1/admin/system-status", headers=sa_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["database_status"] == "ONLINE"
    assert "SecurityHeadersMiddleware" in data["active_middleware"]
