import sys
from datetime import datetime, timezone
from typing import Annotated, List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text

from app.database.session import get_db
from app.models.user import User
from app.models.session import UserSession
from app.models.audit import SecurityEvent
from app.schemas.admin import DashboardStatsResponse, SystemStatusResponse
from app.schemas.user import UserResponse
from app.services.user_service import user_service
from app.api.deps import require_roles
from app.core.permissions import RoleEnum
from app.core.config import settings

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get(
    "/dashboard",
    response_model=DashboardStatsResponse,
    summary="Retrieve high-level administrative dashboard statistics"
)
async def get_admin_dashboard(
    current_user: Annotated[User, Depends(require_roles(RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    # Total users
    users_count = await db.scalar(select(func.count(User.id))) or 0

    # Active sessions
    now = datetime.now(timezone.utc)
    sessions_count = await db.scalar(
        select(func.count(UserSession.id)).where(
            UserSession.is_active == True,
            UserSession.expires_at > now
        )
    ) or 0

    # Locked accounts
    locked_count = await db.scalar(
        select(func.count(User.id)).where(User.is_locked == True)
    ) or 0

    # Security alerts
    alerts_count = await db.scalar(select(func.count(SecurityEvent.id))) or 0

    return DashboardStatsResponse(
        total_users=users_count,
        active_sessions=sessions_count,
        locked_accounts=locked_count,
        security_alerts_count=alerts_count,
        system_status="OPERATIONAL"
    )


@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="Administrative user roster with security status"
)
async def get_admin_users(
    current_user: Annotated[User, Depends(require_roles(RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
    offset: int = 0
):
    return await user_service.list_users(db=db, limit=limit, offset=offset)


@router.get(
    "/system-status",
    response_model=SystemStatusResponse,
    summary="Runtime system diagnostics and security controls status (Super Admin only)"
)
async def get_system_status(
    current_user: Annotated[User, Depends(require_roles(RoleEnum.SUPER_ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    db_status = "ONLINE"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "ERROR"

    return SystemStatusResponse(
        python_version=sys.version.split(" ")[0],
        environment=settings.ENVIRONMENT,
        database_status=db_status,
        redis_status="DISABLED (IN-MEMORY RATELIMITER ACTIVE)" if not settings.REDIS_URL else "ONLINE",
        active_middleware=[
            "SecurityHeadersMiddleware",
            "CORSMiddleware",
            "RequestSizeLimitMiddleware",
            "RateLimitMiddleware",
            "AuditCorrelationMiddleware",
        ],
        timestamp=datetime.now(timezone.utc)
    )

