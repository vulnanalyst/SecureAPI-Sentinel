from datetime import datetime, timezone
from typing import Annotated, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database.session import get_db
from app.models.user import User
from app.schemas.security import (
    SecurityEventResponse,
    AuditLogResponse,
    HealthResponse,
)
from app.services.audit_service import audit_service
from app.api.deps import require_roles
from app.core.permissions import RoleEnum
from app.core.config import settings

router = APIRouter(prefix="/security", tags=["Security Telemetry & Audit"])


@router.get(
    "/events",
    response_model=List[SecurityEventResponse],
    summary="Retrieve high-priority security telemetry events (Security Analyst / Admin)"
)
async def get_security_events(
    current_user: Annotated[
        User,
        Depends(require_roles(RoleEnum.SECURITY_ANALYST, RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
    offset: int = 0
):
    return await audit_service.get_security_events(db=db, limit=limit, offset=offset)


@router.get(
    "/audit-logs",
    response_model=List[AuditLogResponse],
    summary="Access immutable audit logs for compliance and forensics"
)
async def get_audit_logs(
    current_user: Annotated[
        User,
        Depends(require_roles(RoleEnum.SECURITY_ANALYST, RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
    offset: int = 0
):
    return await audit_service.get_audit_logs(db=db, limit=limit, offset=offset)


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="System liveness and security subsystem health check"
)
async def security_health_check(
    db: Annotated[AsyncSession, Depends(get_db)]
):
    db_status = "HEALTHY"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "DEGRADED"

    redis_status = "DISABLED" if not settings.REDIS_URL else "HEALTHY"

    return HealthResponse(
        status="UP",
        database=db_status,
        redis=redis_status,
        crypto_engine="ARGON2ID_AES256GCM_ACTIVE",
        timestamp=datetime.now(timezone.utc)
    )

