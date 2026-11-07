import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Configure Windows event loop policy if on Windows
import sys
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

from app.main import app
from app.database.base import Base
from app.database.session import get_db
from app.database.init_db import init_db
from app.core.config import settings
from app.models.user import User
from app.models.role import Role, UserRole
from app.core.permissions import RoleEnum
from app.core.security import hash_password, create_access_token
from app.middleware.rate_limit import limiter
from app.services.email_adapter import email_adapter

# Dedicated test database URL
TEST_DB_URL = "sqlite+aiosqlite:///./test_sentinel.db"

test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


@pytest_asyncio.fixture(scope="session", loop_scope="session", autouse=True)
async def prepare_test_db():
    # Setup tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    # Initialize seed roles and permissions
    async with TestSessionLocal() as db:
        # Seed roles
        role_map = {}
        for role_enum in RoleEnum:
            r = Role(name=role_enum.value, description=f"Test {role_enum.value}")
            db.add(r)
            role_map[role_enum.value] = r
        await db.commit()

        # Seed baseline accounts
        accounts = [
            ("superadmin@sentinel.org", "SuperAdmin#2026!Sec", RoleEnum.SUPER_ADMIN, "Super Admin"),
            ("admin@sentinel.org", "Admin#2026!Sec", RoleEnum.ADMIN, "Admin User"),
            ("analyst@sentinel.org", "Analyst#2026!Sec", RoleEnum.SECURITY_ANALYST, "Security Analyst"),
            ("user1@sentinel.org", "Standard#2026!Sec", RoleEnum.USER, "Standard User One"),
            ("user2@sentinel.org", "Standard#2026!Sec", RoleEnum.USER, "Standard User Two"),
        ]
        for email, password, role_enum, name in accounts:
            u = User(
                email=email,
                hashed_password=hash_password(password),
                full_name=name,
                is_active=True,
                is_verified=True,
                is_locked=False,
            )
            db.add(u)
            await db.flush()
            assoc = UserRole(user_id=u.id, role_id=role_map[role_enum.value].id)
            db.add(assoc)
        await db.commit()

    yield

    # Teardown
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()
    if os.path.exists("./test_sentinel.db"):
        try:
            os.remove("./test_sentinel.db")
        except Exception:
            pass


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    # Reset in-memory rate limiter and email adapter before each test
    await limiter.reset()
    email_adapter.clear()

    async def override_get_db():
        async with TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    def _make_headers(user_id: str, roles: list[str]) -> dict:
        token = create_access_token(user_id=user_id, roles=roles)
        return {"Authorization": f"Bearer {token}"}
    return _make_headers
