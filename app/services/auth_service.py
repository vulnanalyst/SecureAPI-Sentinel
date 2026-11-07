import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Union
import jwt
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.user import User
from app.models.role import Role, UserRole
from app.models.token import RefreshToken, PasswordResetToken
from app.models.session import UserSession
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    MFAChallengeResponse,
)
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    hash_token,
    create_access_token,
    create_refresh_token,
    generate_secure_token,
)
from app.core.permissions import RoleEnum
from app.services.email_adapter import email_adapter
from app.services.audit_service import audit_service


class AuthService:
    @classmethod
    async def register_user(
        cls, db: AsyncSession, payload: UserRegisterRequest, client_ip: Optional[str] = None
    ) -> User:
        # Check existing user
        query = select(User).where(User.email == payload.email.lower().strip())
        res = await db.execute(query)
        if res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email already exists."
            )

        # Hash password using Argon2id
        hashed_pw = hash_password(payload.password)

        new_user = User(
            email=payload.email.lower().strip(),
            hashed_password=hashed_pw,
            full_name=payload.full_name.strip(),
            is_active=True,
            is_verified=True,  # Dev verification
            is_locked=False,
            failed_login_attempts=0,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(new_user)
        await db.flush()

        # Assign default USER role
        role_res = await db.execute(select(Role).where(Role.name == RoleEnum.USER.value))
        user_role = role_res.scalar_one_or_none()
        if user_role:
            assoc = UserRole(user_id=new_user.id, role_id=user_role.id)
            db.add(assoc)

        await db.commit()
        await db.refresh(new_user)

        # Send welcome/verification email via adapter
        await email_adapter.send_email(
            to_email=new_user.email,
            subject="Welcome to SecureAPI Sentinel",
            body=f"Hello {new_user.full_name}, your account has been registered successfully."
        )

        await audit_service.log_action(
            db=db,
            action="USER_REGISTRATION",
            resource="user",
            resource_id=new_user.id,
            user_id=new_user.id,
            ip_address=client_ip,
            status_code=201,
            details={"email": new_user.email}
        )

        return new_user

    @classmethod
    async def authenticate_user(
        cls, db: AsyncSession, payload: UserLoginRequest, client_ip: Optional[str] = None, user_agent: Optional[str] = None
    ) -> Union[TokenResponse, MFAChallengeResponse]:
        query = select(User).where(User.email == payload.email.lower().strip())
        res = await db.execute(query)
        user = res.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        # Generic 401 error message to prevent user enumeration
        invalid_cred_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

        if not user or not user.is_active:
            raise invalid_cred_exception

        # Check account lockout
        if user.is_locked:
            if user.lockout_until and user.lockout_until > now:
                remaining_secs = int((user.lockout_until - now).total_seconds())
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account is temporarily locked due to repeated failed login attempts. Retry in {remaining_secs} seconds."
                )
            else:
                # Lockout window elapsed -> Auto-unlock
                user.is_locked = False
                user.failed_login_attempts = 0
                user.lockout_until = None
                await db.commit()

        # Verify password
        if not verify_password(payload.password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.is_locked = True
                user.lockout_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                await db.commit()

                await audit_service.log_security_event(
                    db=db,
                    event_type="ACCOUNT_LOCKED",
                    severity="CRITICAL",
                    description=f"Account {user.email} locked after {user.failed_login_attempts} failed attempts",
                    user_id=user.id,
                    source_ip=client_ip,
                )
            else:
                await db.commit()
                await audit_service.log_security_event(
                    db=db,
                    event_type="LOGIN_FAILED",
                    severity="MEDIUM",
                    description=f"Failed login attempt {user.failed_login_attempts}/{settings.MAX_FAILED_LOGIN_ATTEMPTS} for {user.email}",
                    user_id=user.id,
                    source_ip=client_ip,
                )
            raise invalid_cred_exception

        # Password is correct -> Reset failed attempts
        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            user.is_locked = False
            user.lockout_until = None
            await db.commit()

        # Check if MFA is enabled
        if user.mfa and user.mfa.is_enabled:
            # Issue temporary MFA challenge token valid for 5 minutes
            mfa_payload = {
                "sub": user.id,
                "type": "mfa_challenge",
                "exp": int((now + timedelta(minutes=5)).timestamp()),
                "iat": int(now.timestamp()),
                "iss": settings.MFA_ISSUER
            }
            mfa_token = jwt.encode(mfa_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
            return MFAChallengeResponse(mfa_token=mfa_token)

        # Issue access & refresh tokens
        return await cls._issue_tokens(db, user, client_ip, user_agent)

    @classmethod
    async def _issue_tokens(
        cls, db: AsyncSession, user: User, client_ip: Optional[str] = None, user_agent: Optional[str] = None
    ) -> TokenResponse:
        roles = [r.role.name for r in user.roles if r.role]
        access_token = create_access_token(user_id=user.id, roles=roles)
        raw_refresh, token_hash, family_id, expires_at = create_refresh_token(user_id=user.id)

        # Store refresh token record
        rt_entry = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            family_id=family_id,
            is_revoked=False,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
        )
        db.add(rt_entry)

        # Store session record
        session_token = generate_secure_token(32)
        sess_entry = UserSession(
            user_id=user.id,
            session_token_hash=hash_token(session_token),
            ip_address=client_ip,
            user_agent=user_agent,
            is_active=True,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
        )
        db.add(sess_entry)

        await db.commit()

        await audit_service.log_action(
            db=db,
            action="USER_LOGIN_SUCCESS",
            resource="auth",
            resource_id=user.id,
            user_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            status_code=200
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @classmethod
    async def refresh_token_rotation(
        cls, db: AsyncSession, refresh_token_str: str, client_ip: Optional[str] = None
    ) -> TokenResponse:
        """
        Refresh Token Rotation with Automatic Token Family Reuse Detection (RFC 6749 / 6819).
        If an already-revoked refresh token is presented, this constitutes a token reuse anomaly
        (e.g., token stolen from client storage), triggering immediate revocation of ALL tokens in the family.
        """
        token_hash = hash_token(refresh_token_str.strip())
        res = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        rt = res.scalar_one_or_none()

        if not rt:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token."
            )

        now = datetime.now(timezone.utc)

        # REUSE DETECTION CHECK
        if rt.is_revoked:
            # Revoke all tokens in this family immediately!
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == rt.family_id)
                .values(is_revoked=True)
            )
            await db.commit()

            await audit_service.log_security_event(
                db=db,
                event_type="TOKEN_REUSE_DETECTED",
                severity="CRITICAL",
                description=f"Compromised token family {rt.family_id} reused. All sibling tokens revoked.",
                user_id=rt.user_id,
                source_ip=client_ip,
                metadata={"family_id": rt.family_id, "token_id": rt.id}
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Security alert: Token reuse detected. The session token family has been revoked."
            )

        # Check expiration
        if rt.expires_at < now:
            rt.is_revoked = True
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired. Please login again."
            )

        # Token is valid -> Revoke current token and rotate
        rt.is_revoked = True
        rt.replaced_by_at = now

        # Fetch user
        user_res = await db.execute(select(User).where(User.id == rt.user_id))
        user = user_res.scalar_one_or_none()
        if not user or not user.is_active or user.is_locked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or locked."
            )

        # Create new tokens under the SAME family_id
        roles = [r.role.name for r in user.roles if r.role]
        new_access_token = create_access_token(user_id=user.id, roles=roles)
        new_raw_refresh, new_token_hash, family_id, new_expires_at = create_refresh_token(
            user_id=user.id, family_id=rt.family_id
        )

        new_rt = RefreshToken(
            user_id=user.id,
            token_hash=new_token_hash,
            family_id=family_id,
            is_revoked=False,
            expires_at=new_expires_at,
            created_at=now,
        )
        db.add(new_rt)
        await db.commit()

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_raw_refresh,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @classmethod
    async def logout(
        cls, db: AsyncSession, refresh_token_str: str, user_id: str, client_ip: Optional[str] = None
    ) -> bool:
        token_hash = hash_token(refresh_token_str.strip())
        res = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        rt = res.scalar_one_or_none()
        if rt:
            rt.is_revoked = True
            await db.commit()

        await audit_service.log_action(
            db=db,
            action="USER_LOGOUT",
            resource="auth",
            resource_id=user_id,
            user_id=user_id,
            ip_address=client_ip,
            status_code=200
        )
        return True

    @classmethod
    async def request_password_reset(
        cls, db: AsyncSession, email: str, client_ip: Optional[str] = None
    ) -> bool:
        res = await db.execute(select(User).where(User.email == email.lower().strip()))
        user = res.scalar_one_or_none()

        # Always return True regardless of existence to prevent user enumeration
        if user and user.is_active:
            raw_token = generate_secure_token(32)
            token_hash = hash_token(raw_token)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

            prt = PasswordResetToken(
                user_id=user.id,
                token_hash=token_hash,
                is_used=False,
                expires_at=expires_at,
                created_at=datetime.now(timezone.utc),
            )
            db.add(prt)
            await db.commit()

            await email_adapter.send_email(
                to_email=user.email,
                subject="SecureAPI Sentinel - Password Reset Request",
                body=f"Your password reset token is: {raw_token}. It expires in 15 minutes."
            )

            await audit_service.log_action(
                db=db,
                action="PASSWORD_RESET_REQUESTED",
                resource="auth",
                resource_id=user.id,
                user_id=user.id,
                ip_address=client_ip,
                status_code=200
            )

        return True

    @classmethod
    async def reset_password(
        cls, db: AsyncSession, raw_token: str, new_password: str, client_ip: Optional[str] = None
    ) -> bool:
        token_hash = hash_token(raw_token.strip())
        res = await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.is_used == False
            )
        )
        prt = res.scalar_one_or_none()
        now = datetime.now(timezone.utc)

        if not prt or prt.expires_at < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token."
            )

        # Fetch user
        user_res = await db.execute(select(User).where(User.id == prt.user_id))
        user = user_res.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found."
            )

        # Update password
        user.hashed_password = hash_password(new_password)
        user.updated_at = now
        prt.is_used = True

        # Invalidate all active refresh tokens for the user
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id)
            .values(is_revoked=True)
        )

        await db.commit()

        await audit_service.log_action(
            db=db,
            action="PASSWORD_RESET_SUCCESS",
            resource="auth",
            resource_id=user.id,
            user_id=user.id,
            ip_address=client_ip,
            status_code=200
        )
        return True


auth_service = AuthService()
