import base64
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

# Initialize Argon2id password hasher (RFC 9106 compliant)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    type=Type.ID
)


def hash_password(password: str) -> str:
    """Hashes plaintext password using Argon2id with automatic salt generation."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies plaintext password against Argon2id hash with constant-time comparison."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, Exception):
        return False


def hash_token(token: str) -> str:
    """Computes SHA-256 digest of sensitive tokens (refresh, reset, session) before database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Generates cryptographically strong random token."""
    return secrets.token_urlsafe(nbytes)


def create_access_token(
    user_id: str,
    roles: list[str],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Issues short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "roles": roles,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "nbf": int(now.timestamp()),
        "iss": settings.MFA_ISSUER,
        "type": "access",
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and cryptographically validates JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.MFA_ISSUER,
            options={"require": ["exp", "iat", "sub", "type"]}
        )
        if payload.get("type") != "access":
            raise jwt.InvalidTokenError("Token type must be 'access'")
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError:
        raise


def create_refresh_token(
    user_id: str,
    family_id: Optional[str] = None
) -> Tuple[str, str, str, datetime]:
    """
    Creates an opaque refresh token with its SHA-256 hash, jti, and family_id for rotation.
    Returns: (raw_token, token_hash, family_id, expires_at)
    """
    raw_token = generate_secure_token(48)
    token_hash = hash_token(raw_token)
    fam_id = family_id or str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return raw_token, token_hash, fam_id, expires_at


# Sensitive Data Encryption (for TOTP secrets stored in DB)
def _get_fernet_cipher() -> Fernet:
    """Retrieves or derives a valid 32-byte Fernet key from settings."""
    key = settings.MFA_ENCRYPTION_KEY.encode("utf-8")
    # If key is already valid base64 32-bytes
    try:
        return Fernet(key)
    except Exception:
        # Fallback to key derivation via sha256 to guarantee 32 urlsafe bytes
        derived = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        return Fernet(derived)


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypts plaintext TOTP base32 secret using AES-256 (Fernet)."""
    cipher = _get_fernet_cipher()
    return cipher.encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_mfa_secret(secret_enc: str) -> str:
    """Decrypts AES-256 encrypted TOTP secret."""
    cipher = _get_fernet_cipher()
    try:
        return cipher.decrypt(secret_enc.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Failed to decrypt MFA secret: invalid token or corrupted key")
