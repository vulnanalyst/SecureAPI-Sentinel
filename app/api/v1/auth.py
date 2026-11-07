from typing import Annotated, Optional, Union
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    MFAChallengeResponse,
    LogoutRequest,
    TokenRefreshRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MFAEnableResponse,
    MFAVerifyRequest,
)
from app.schemas.user import UserResponse
from app.services.auth_service import auth_service
from app.services.mfa_service import mfa_service
from app.services.user_service import UserService
from app.api.deps import get_current_user, get_client_ip, security_scheme
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account"
)
async def register(
    request: Request,
    payload: UserRegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    user = await auth_service.register_user(db=db, payload=payload, client_ip=ip)
    return UserService._to_user_response(user)


@router.post(
    "/login",
    response_model=Union[TokenResponse, MFAChallengeResponse],
    summary="Authenticate with credentials; returns tokens or MFA challenge"
)
async def login(
    request: Request,
    payload: UserLoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    return await auth_service.authenticate_user(
        db=db, payload=payload, client_ip=ip, user_agent=user_agent
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke refresh token and terminate active session"
)
async def logout(
    request: Request,
    payload: LogoutRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    await auth_service.logout(
        db=db, refresh_token_str=payload.refresh_token, user_id=current_user.id, client_ip=ip
    )
    return {"detail": "Successfully logged out and revoked refresh token."}


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and issue new access token"
)
async def refresh_token(
    request: Request,
    payload: TokenRefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    return await auth_service.refresh_token_rotation(
        db=db, refresh_token_str=payload.refresh_token, client_ip=ip
    )


@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    summary="Request a password reset link/token via email"
)
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    await auth_service.request_password_reset(db=db, email=payload.email, client_ip=ip)
    return {"detail": "If the email is registered, password reset instructions have been dispatched."}


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    summary="Reset password using a valid, unexpired reset token"
)
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    await auth_service.reset_password(
        db=db, raw_token=payload.token, new_password=payload.new_password, client_ip=ip
    )
    return {"detail": "Password has been successfully updated. Please login with your new credentials."}


@router.post(
    "/mfa/enable",
    response_model=MFAEnableResponse,
    summary="Generate TOTP secret, provisioning URI, and backup recovery codes"
)
async def enable_mfa(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    secret, uri, backup_codes = await mfa_service.setup_mfa(
        db=db, user_id=current_user.id, user_email=current_user.email
    )
    return MFAEnableResponse(
        secret=secret,
        provisioning_uri=uri,
        backup_codes=backup_codes,
    )


@router.post(
    "/mfa/verify",
    response_model=Union[TokenResponse, dict],
    summary="Verify TOTP code during initial setup or completing MFA login"
)
async def verify_mfa(
    request: Request,
    payload: MFAVerifyRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")

    # Flow A: Completing login using mfa_token challenge
    if payload.mfa_token:
        try:
            challenge_payload = jwt.decode(
                payload.mfa_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                issuer=settings.MFA_ISSUER,
                options={"require": ["exp", "sub", "type"]}
            )
            if challenge_payload.get("type") != "mfa_challenge":
                raise HTTPException(status_code=400, detail="Invalid MFA challenge token")
            user_id = challenge_payload.get("sub")
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA challenge token has expired or is invalid."
            )

        valid = await mfa_service.verify_totp_or_backup(db=db, user_id=user_id, code=payload.code)
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid TOTP authentication code or backup code."
            )

        res = await db.execute(
            select(User)
            .options(selectinload(User.roles).selectinload(UserRole.role))
            .where(User.id == user_id)
        )
        user = res.scalar_one_or_none()
        if not user or not user.is_active or user.is_locked:
            raise HTTPException(status_code=401, detail="User account is inactive or locked.")

        return await auth_service._issue_tokens(db, user, client_ip=ip, user_agent=user_agent)

    # Flow B: Enabling MFA for an authenticated session
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token or mfa_token required to verify MFA."
        )

    # Validate bearer token
    token = auth_header.split(" ")[1]
    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], issuer=settings.MFA_ISSUER)
    user_id = decoded.get("sub")

    verified = await mfa_service.verify_and_enable(db=db, user_id=user_id, code=payload.code)
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Could not enable MFA."
        )

    return {"detail": "Multi-Factor Authentication has been successfully verified and activated."}
