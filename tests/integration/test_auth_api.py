import pytest
import pyotp
import httpx
from app.services.email_adapter import email_adapter
from app.middleware.rate_limit import limiter


@pytest.mark.asyncio
async def test_user_registration_success(client: httpx.AsyncClient):
    payload = {
        "email": "newuser@sentinel.org",
        "password": "StrongPassword#2026!",
        "full_name": "New Sentinel User"
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@sentinel.org"
    assert data["full_name"] == "New Sentinel User"
    assert "roles" in data
    assert "hashed_password" not in data  # Ensure sensitive data not exposed

    # Verify email adapter caught notification
    last_email = email_adapter.get_last_email_for("newuser@sentinel.org")
    assert last_email is not None
    assert "Welcome" in last_email["subject"]


@pytest.mark.asyncio
async def test_user_registration_duplicate_email(client: httpx.AsyncClient):
    payload = {
        "email": "user1@sentinel.org",  # Already seeded
        "password": "StrongPassword#2026!",
        "full_name": "Duplicate User"
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


@pytest.mark.asyncio
async def test_user_registration_weak_password_validation(client: httpx.AsyncClient):
    # Missing uppercase, number, symbol
    payload = {
        "email": "weak@sentinel.org",
        "password": "weakpassword",
        "full_name": "Weak User"
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    assert "validation failed" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_user_login_success(client: httpx.AsyncClient):
    payload = {
        "email": "user1@sentinel.org",
        "password": "Standard#2026!Sec"
    }
    response = await client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_user_login_invalid_credentials(client: httpx.AsyncClient):
    payload = {
        "email": "user1@sentinel.org",
        "password": "WrongPassword#999"
    }
    response = await client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_account_lockout_after_repeated_failed_attempts(client: httpx.AsyncClient):
    await limiter.reset()
    email = "user2@sentinel.org"
    # Execute 5 consecutive failed logins
    for _ in range(5):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword#123"}
        )
        assert resp.status_code == 401

    # 6th attempt: Must return 423 Locked
    locked_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword#123"}
    )
    assert locked_resp.status_code == 423
    assert "locked" in locked_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_reuse_detection(client: httpx.AsyncClient):
    # 1. Login to obtain initial tokens
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@sentinel.org", "password": "Analyst#2026!Sec"}
    )
    tokens1 = login_resp.json()
    refresh_token_1 = tokens1["refresh_token"]

    # 2. Legitimate token rotation
    rotate_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_1}
    )
    assert rotate_resp.status_code == 200
    tokens2 = rotate_resp.json()
    refresh_token_2 = tokens2["refresh_token"]
    assert refresh_token_1 != refresh_token_2

    # 3. ATTACK SIMULATION: Replay of refresh_token_1 (Token Reuse Attack)
    # The server must detect that refresh_token_1 is revoked, trigger token family revocation,
    # and invalidate refresh_token_2 as well!
    attack_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_1}
    )
    assert attack_resp.status_code == 401
    assert "reuse detected" in attack_resp.json()["detail"].lower()

    # 4. Verify that refresh_token_2 is now ALSO revoked due to family invalidation
    subsequent_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_2}
    )
    assert subsequent_resp.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_workflow(client: httpx.AsyncClient):
    email = "reset_user@sentinel.org"
    pwd = "OldPassword#2026!"
    # Register test user
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pwd, "full_name": "Reset Test User"}
    )

    # 1. Request password reset
    req_resp = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": email}
    )
    assert req_resp.status_code == 200

    # 2. Extract reset token from email adapter
    email_msg = email_adapter.get_last_email_for(email)
    assert email_msg is not None
    body = email_msg["body"]
    token = body.split("is: ")[1].split(".")[0].strip()

    # 3. Confirm reset with new password
    new_pwd = "NewResetPassword#2026!Sec"
    reset_resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": new_pwd}
    )
    assert reset_resp.status_code == 200

    # 4. Login with new password
    login_new = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": new_pwd}
    )
    assert login_new.status_code == 200

    # 5. Token reuse attempt should fail
    replay_resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "AnotherPassword#2026!Sec"}
    )
    assert replay_resp.status_code == 400


@pytest.mark.asyncio
async def test_mfa_full_lifecycle(client: httpx.AsyncClient):
    # 1. Register a dedicated user for MFA testing
    email = "mfa_user@sentinel.org"
    pwd = "MfaUserPassword#2026!"
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pwd, "full_name": "MFA Test User"}
    )

    # 2. Login to get access token
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd}
    )
    auth_header = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # 3. Enable MFA
    enable_resp = await client.post("/api/v1/auth/mfa/enable", headers=auth_header)
    assert enable_resp.status_code == 200
    mfa_data = enable_resp.json()
    secret = mfa_data["secret"]
    assert "provisioning_uri" in mfa_data
    assert len(mfa_data["backup_codes"]) == 8

    # 4. Verify MFA setup with valid TOTP
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    verify_resp = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": valid_code},
        headers=auth_header
    )
    assert verify_resp.status_code == 200
    assert "activated" in verify_resp.json()["detail"].lower()

    # 5. Subsequent login MUST now challenge with MFA
    challenged_login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd}
    )
    assert challenged_login.status_code == 200
    ch_data = challenged_login.json()
    assert ch_data.get("mfa_required") is True
    assert "mfa_token" in ch_data

    # 6. Complete login using challenge token + valid TOTP
    final_verify = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": totp.now(), "mfa_token": ch_data["mfa_token"]}
    )
    assert final_verify.status_code == 200
    final_tokens = final_verify.json()
    assert "access_token" in final_tokens
    assert "refresh_token" in final_tokens
