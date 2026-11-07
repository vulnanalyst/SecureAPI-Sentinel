import re
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, field_validator


def validate_strong_password(v: str) -> str:
    if len(v) < 10:
        raise ValueError("Password must be at least 10 characters long")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", v):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_]", v):
        raise ValueError("Password must contain at least one special character")
    return v


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=100)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        return validate_strong_password(v)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MFAChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    message: str = "Multi-Factor Authentication required. Provide TOTP code via /auth/mfa/verify"


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=10, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        return validate_strong_password(v)


class MFAEnableResponse(BaseModel):
    secret: str
    provisioning_uri: str
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)
    mfa_token: Optional[str] = None
