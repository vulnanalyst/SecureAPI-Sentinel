import pytest
import httpx


@pytest.mark.asyncio
async def test_users_me_profile(client: httpx.AsyncClient):
    # Login as user1
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "user1@sentinel.org", "password": "Standard#2026!Sec"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET /me
    me_resp = await client.get("/api/v1/users/me", headers=headers)
    assert me_resp.status_code == 200
    user_data = me_resp.json()
    assert user_data["email"] == "user1@sentinel.org"
    assert "USER" in user_data["roles"]

    # 2. PUT /me
    put_resp = await client.put(
        "/api/v1/users/me",
        json={"full_name": "Updated User One Name"},
        headers=headers
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["full_name"] == "Updated User One Name"


@pytest.mark.asyncio
async def test_users_list_rbac(client: httpx.AsyncClient):
    # Standard user cannot list users
    user_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user1@sentinel.org", "password": "Standard#2026!Sec"}
    )
    user_token = user_login.json()["access_token"]
    user_resp = await client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert user_resp.status_code == 403
    assert "Insufficient role privileges" in user_resp.json()["detail"]

    # Admin user can list users
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@sentinel.org", "password": "Admin#2026!Sec"}
    )
    admin_token = admin_login.json()["access_token"]
    admin_resp = await client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_resp.status_code == 200
    assert isinstance(admin_resp.json(), list)
    assert len(admin_resp.json()) > 0


@pytest.mark.asyncio
async def test_bola_idor_defense(client: httpx.AsyncClient):
    """
    OWASP API1:2023 - Broken Object Level Authorization (BOLA).
    Verifies that a user cannot access or tamper with another user's resource
    merely by guessing or substituting their ID.
    """
    # 1. Fetch User 1 ID
    u1_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user1@sentinel.org", "password": "Standard#2026!Sec"}
    )
    u1_token = u1_login.json()["access_token"]
    u1_profile = await client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {u1_token}"}
    )
    u1_id = u1_profile.json()["id"]

    # 2. Fetch User 2 ID via Admin
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@sentinel.org", "password": "Admin#2026!Sec"}
    )
    admin_token = admin_login.json()["access_token"]
    users_list = await client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {admin_token}"}
    )
    u2 = next(u for u in users_list.json() if u["email"] == "user2@sentinel.org")
    u2_id = u2["id"]

    # 3. BOLA ATTACK: User 1 attempts to query User 2's private profile
    attack_resp = await client.get(
        f"/api/v1/users/{u2_id}",
        headers={"Authorization": f"Bearer {u1_token}"}
    )
    assert attack_resp.status_code == 403
    assert "BOLA Guard" in attack_resp.json()["detail"]

    # 4. User 1 queries their OWN profile by ID -> Allowed
    own_resp = await client.get(
        f"/api/v1/users/{u1_id}",
        headers={"Authorization": f"Bearer {u1_token}"}
    )
    assert own_resp.status_code == 200
    assert own_resp.json()["id"] == u1_id

    # 5. Admin queries User 2's profile by ID -> Allowed by administrative privilege
    admin_get_resp = await client.get(
        f"/api/v1/users/{u2_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_get_resp.status_code == 200
    assert admin_get_resp.json()["id"] == u2_id


@pytest.mark.asyncio
async def test_privilege_escalation_defense(client: httpx.AsyncClient):
    """
    OWASP API5:2023 - Broken Function Level Authorization (BFLA) / Privilege Escalation.
    Verifies that a standard user cannot elevate their privileges or modify role assignments.
    """
    u1_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "user1@sentinel.org", "password": "Standard#2026!Sec"}
    )
    u1_token = u1_login.json()["access_token"]
    u1_id = (await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {u1_token}"})).json()["id"]

    # Privilege Escalation Attempt: Standard user assigns SUPER_ADMIN role to themselves
    escalate_resp = await client.patch(
        f"/api/v1/users/{u1_id}/role",
        json={"roles": ["SUPER_ADMIN"]},
        headers={"Authorization": f"Bearer {u1_token}"}
    )
    assert escalate_resp.status_code == 403
    assert "Insufficient role privileges" in escalate_resp.json()["detail"]


@pytest.mark.asyncio
async def test_super_admin_role_assignment_and_deletion(client: httpx.AsyncClient):
    # Login as Super Admin
    sa_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "superadmin@sentinel.org", "password": "SuperAdmin#2026!Sec"}
    )
    sa_token = sa_login.json()["access_token"]
    sa_headers = {"Authorization": f"Bearer {sa_token}"}

    # Create a dummy user to modify and delete
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "tobedeleted@sentinel.org",
            "password": "DeleteMePassword#2026!",
            "full_name": "Delete Target"
        }
    )
    target_id = reg_resp.json()["id"]

    # 1. Super Admin modifies role
    role_mod = await client.patch(
        f"/api/v1/users/{target_id}/role",
        json={"roles": ["SECURITY_ANALYST"]},
        headers=sa_headers
    )
    assert role_mod.status_code == 200
    assert "SECURITY_ANALYST" in role_mod.json()["roles"]

    # 2. Super Admin deletes target user
    del_resp = await client.delete(f"/api/v1/users/{target_id}", headers=sa_headers)
    assert del_resp.status_code == 200
    assert "deleted successfully" in del_resp.json()["detail"]

    # 3. Super Admin self-deletion prevention
    sa_id = (await client.get("/api/v1/users/me", headers=sa_headers)).json()["id"]
    self_del_resp = await client.delete(f"/api/v1/users/{sa_id}", headers=sa_headers)
    assert self_del_resp.status_code == 400
    assert "self-deletion is forbidden" in self_del_resp.json()["detail"].lower()
