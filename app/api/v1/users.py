from typing import Annotated, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserUpdateRequest, UserRoleUpdateRequest
from app.services.user_service import UserService, user_service
from app.api.deps import (
    get_current_user,
    require_roles,
    require_ownership_or_admin,
)
from app.core.permissions import RoleEnum

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get profile of the currently authenticated user"
)
async def get_my_profile(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return UserService._to_user_response(current_user)


@router.put(
    "/me",
    response_model=UserResponse,
    summary="Update profile details of the current user"
)
async def update_my_profile(
    payload: UserUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    return await user_service.update_profile(
        db=db, user_id=current_user.id, payload=payload
    )


@router.get(
    "",
    response_model=List[UserResponse],
    summary="List all users (Admin/Super Admin only)"
)
async def list_users(
    current_user: Annotated[User, Depends(require_roles(RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
    offset: int = 0
):
    return await user_service.list_users(db=db, limit=limit, offset=offset)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Retrieve user details (Guarded against BOLA/IDOR)"
)
async def get_user_by_id(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    # Enforce BOLA Defense: verify that current_user is either requesting their own ID or is an admin
    require_ownership_or_admin(target_user_id=user_id, current_user=current_user)
    return await user_service.get_by_id(db=db, user_id=user_id)


@router.patch(
    "/{user_id}/role",
    response_model=UserResponse,
    summary="Assign user roles (Super Admin only)"
)
async def update_user_roles(
    user_id: str,
    payload: UserRoleUpdateRequest,
    current_user: Annotated[User, Depends(require_roles(RoleEnum.SUPER_ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    return await user_service.assign_roles(
        db=db, target_user_id=user_id, new_role_names=payload.roles, actor_user_id=current_user.id
    )


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a user account (Super Admin only)"
)
async def delete_user(
    user_id: str,
    current_user: Annotated[User, Depends(require_roles(RoleEnum.SUPER_ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    await user_service.delete_user(
        db=db, target_user_id=user_id, actor_user_id=current_user.id
    )
    return {"detail": f"User {user_id} deleted successfully."}
