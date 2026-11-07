from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    is_active: bool
    is_verified: bool
    is_locked: bool
    roles: List[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)


class UserRoleUpdateRequest(BaseModel):
    roles: List[str] = Field(..., min_length=1, description="List of role names: SUPER_ADMIN, ADMIN, SECURITY_ANALYST, USER")
