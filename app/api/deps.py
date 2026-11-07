from typing import Annotated, List, Optional
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.user import User
from app.core.security import decode_access_token
from app.core.permissions import RoleEnum, PermissionEnum, has_permission

security_scheme = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> str:
    """Extracts client IP, respecting trusted proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def get_current_user(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)]
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is locked due to security policy"
        )

    return user


def require_roles(*allowed_roles: RoleEnum):
    """Factory dependency enforcing Role-Based Access Control (RBAC)."""
    async def role_checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        user_roles = [r.role.name for r in current_user.roles if r.role]
        allowed_names = [r.value for r in allowed_roles]

        if not any(role in allowed_names for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted: Insufficient role privileges"
            )
        return current_user

    return role_checker


def require_ownership_or_admin(target_user_id: str, current_user: User):
    """
    Enforces Broken Object Level Authorization (BOLA/IDOR) defense.
    Ensures a subject can only operate on their own user resource,
    unless they hold an ADMIN or SUPER_ADMIN role.
    """
    user_roles = [r.role.name for r in current_user.roles if r.role]
    is_admin = RoleEnum.ADMIN.value in user_roles or RoleEnum.SUPER_ADMIN.value in user_roles

    if current_user.id != target_user_id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You cannot access or modify resources owned by other users (BOLA Guard)."
        )
