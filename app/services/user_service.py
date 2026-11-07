from datetime import datetime, timezone
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.user import User
from app.models.role import Role, UserRole
from app.schemas.user import UserUpdateRequest, UserResponse
from app.services.audit_service import audit_service


class UserService:
    @staticmethod
    def _to_user_response(user: User) -> UserResponse:
        roles = [r.role.name for r in user.roles if r.role]
        return UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_locked=user.is_locked,
            roles=roles,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: str) -> UserResponse:
        res = await db.execute(select(User).where(User.id == user_id))
        user = res.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return cls._to_user_response(user)

    @classmethod
    async def list_users(
        cls, db: AsyncSession, limit: int = 50, offset: int = 0
    ) -> List[UserResponse]:
        res = await db.execute(select(User).limit(limit).offset(offset))
        users = res.scalars().all()
        return [cls._to_user_response(u) for u in users]

    @classmethod
    async def update_profile(
        cls, db: AsyncSession, user_id: str, payload: UserUpdateRequest
    ) -> UserResponse:
        res = await db.execute(select(User).where(User.id == user_id))
        user = res.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if payload.full_name is not None:
            user.full_name = payload.full_name.strip()
        user.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(user)

        await audit_service.log_action(
            db=db,
            action="USER_PROFILE_UPDATED",
            resource="user",
            resource_id=user.id,
            user_id=user.id,
            status_code=200
        )
        return cls._to_user_response(user)

    @classmethod
    async def assign_roles(
        cls, db: AsyncSession, target_user_id: str, new_role_names: List[str], actor_user_id: str
    ) -> UserResponse:
        res = await db.execute(select(User).where(User.id == target_user_id))
        user = res.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target user not found"
            )

        # Clear existing roles
        await db.execute(delete(UserRole).where(UserRole.user_id == target_user_id))

        for r_name in new_role_names:
            role_res = await db.execute(select(Role).where(Role.name == r_name.strip().upper()))
            role_obj = role_res.scalar_one_or_none()
            if not role_obj:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role '{r_name}' does not exist"
                )
            assoc = UserRole(user_id=user.id, role_id=role_obj.id)
            db.add(assoc)

        user.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(user)

        await audit_service.log_action(
            db=db,
            action="USER_ROLES_MODIFIED",
            resource="user",
            resource_id=user.id,
            user_id=actor_user_id,
            status_code=200,
            details={"assigned_roles": new_role_names}
        )
        return cls._to_user_response(user)

    @classmethod
    async def delete_user(
        cls, db: AsyncSession, target_user_id: str, actor_user_id: str
    ) -> bool:
        res = await db.execute(select(User).where(User.id == target_user_id))
        user = res.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if user.id == actor_user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrative self-deletion is forbidden"
            )

        await db.delete(user)
        await db.commit()

        await audit_service.log_action(
            db=db,
            action="USER_DELETED",
            resource="user",
            resource_id=target_user_id,
            user_id=actor_user_id,
            status_code=200
        )
        return True


user_service = UserService()
