import pytest
import time
from datetime import timedelta
import jwt

from app.core.security import (
    hash_password,
    verify_password,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    create_access_token,
    decode_access_token,
    hash_token,
    generate_secure_token,
)
from app.services.mfa_service import mfa_service
from app.core.config import settings


def test_argon2id_password_hashing():
    raw_pwd = "P@ssw0rdSecure!2026"
    h1 = hash_password(raw_pwd)
    h2 = hash_password(raw_pwd)

    # Must produce distinct salt-based hashes
    assert h1 != h2
    assert h1.startswith("$argon2id$")

    # Verification
    assert verify_password(raw_pwd, h1) is True
    assert verify_password(raw_pwd, h2) is True
    assert verify_password("WrongPassword!123", h1) is False
    assert verify_password("", h1) is False


def test_mfa_secret_encryption_and_decryption():
    raw_secret = "JBSWY3DPEHPK3PXP"
    encrypted = encrypt_mfa_secret(raw_secret)

    assert encrypted != raw_secret
    decrypted = decrypt_mfa_secret(encrypted)
    assert decrypted == raw_secret

    # Corrupted ciphertext
    with pytest.raises(ValueError):
        decrypt_mfa_secret("InvalidCorruptedCiphertext==")


def test_jwt_access_token_lifecycle():
    user_id = "test-user-uuid-1234"
    roles = ["USER", "SECURITY_ANALYST"]

    token = create_access_token(user_id=user_id, roles=roles)
    payload = decode_access_token(token)

    assert payload["sub"] == user_id
    assert payload["roles"] == roles
    assert payload["type"] == "access"
    assert payload["iss"] == settings.MFA_ISSUER


def test_jwt_access_token_expiration():
    user_id = "test-expired-user"
    token = create_access_token(
        user_id=user_id, roles=["USER"], expires_delta=timedelta(seconds=-10)
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_jwt_signature_tampering():
    user_id = "test-tampered-user"
    token = create_access_token(user_id=user_id, roles=["USER"])

    parts = token.split(".")
    # Modify payload slightly
    tampered_token = f"{parts[0]}.eyJhZG1pbiI6IHRydWV9.{parts[2]}"

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tampered_token)


def test_mfa_backup_codes_generation():
    raw_codes, hashed_codes = mfa_service.generate_backup_codes(count=8)
    assert len(raw_codes) == 8
    assert len(hashed_codes) == 8

    for raw, hashed in zip(raw_codes, hashed_codes):
        assert len(raw) == 9  # format XXXX-XXXX
        assert hash_token(raw) == hashed


def test_token_hash_entropy():
    t1 = generate_secure_token(32)
    t2 = generate_secure_token(32)
    assert t1 != t2
    assert len(t1) >= 40
    assert hash_token(t1) != hash_token(t2)
    assert len(hash_token(t1)) == 64

