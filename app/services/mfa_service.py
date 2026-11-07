import json
import secrets
from datetime import datetime, timezone
from typing import Tuple, List, Optional
import pyotp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.mfa import MFASecurity
from app.core.config import settings
from app.core.security import (
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    hash_token,
)


class MFAService:
    @staticmethod
    def generate_backup_codes(count: int = 8) -> Tuple[List[str], List[str]]:
        """
        Generates human-readable 8-character backup recovery codes and their SHA-256 hashes.
        Returns: (raw_codes, hashed_codes)
        """
        raw_codes = []
        hashed_codes = []
        for _ in range(count):
            part1 = secrets.token_hex(2).upper()
            part2 = secrets.token_hex(2).upper()
            code = f"{part1}-{part2}"
            raw_codes.append(code)
            hashed_codes.append(hash_token(code))
        return raw_codes, hashed_codes

    @classmethod
    async def setup_mfa(
        cls, db: AsyncSession, user_id: str, user_email: str
    ) -> Tuple[str, str, List[str]]:
        """
        Generates new encrypted TOTP secret, provisioning URI, and backup recovery codes.
        Returns: (secret, provisioning_uri, raw_backup_codes)
        """
        # Check existing record
        res = await db.execute(select(MFASecurity).where(MFASecurity.user_id == user_id))
        mfa_entry = res.scalar_one_or_none()

        raw_secret = pyotp.random_base32()
        secret_enc = encrypt_mfa_secret(raw_secret)
        raw_codes, hashed_codes = cls.generate_backup_codes()

        if mfa_entry:
            mfa_entry.secret_enc = secret_enc
            mfa_entry.is_enabled = False
            mfa_entry.backup_codes_hash = json.dumps(hashed_codes)
            mfa_entry.verified_at = None
        else:
            mfa_entry = MFASecurity(
                user_id=user_id,
                secret_enc=secret_enc,
                is_enabled=False,
                backup_codes_hash=json.dumps(hashed_codes),
                created_at=datetime.now(timezone.utc),
            )
            db.add(mfa_entry)

        await db.commit()
        await db.refresh(mfa_entry)

        totp = pyotp.TOTP(raw_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email, issuer_name=settings.MFA_ISSUER
        )

        return raw_secret, provisioning_uri, raw_codes

    @classmethod
    async def verify_and_enable(
        cls, db: AsyncSession, user_id: str, code: str
    ) -> bool:
        """Verifies initial setup TOTP code and activates MFA if valid."""
        res = await db.execute(select(MFASecurity).where(MFASecurity.user_id == user_id))
        mfa_entry = res.scalar_one_or_none()
        if not mfa_entry:
            return False

        raw_secret = decrypt_mfa_secret(mfa_entry.secret_enc)
        totp = pyotp.TOTP(raw_secret)

        if totp.verify(code.strip(), valid_window=1):
            mfa_entry.is_enabled = True
            mfa_entry.verified_at = datetime.now(timezone.utc)
            await db.commit()
            return True

        return False

    @classmethod
    async def verify_totp_or_backup(
        cls, db: AsyncSession, user_id: str, code: str
    ) -> bool:
        """Verifies TOTP code or consumes a single-use backup code."""
        res = await db.execute(select(MFASecurity).where(MFASecurity.user_id == user_id))
        mfa_entry = res.scalar_one_or_none()
        if not mfa_entry or not mfa_entry.is_enabled:
            return False

        clean_code = code.strip()

        # Check TOTP
        raw_secret = decrypt_mfa_secret(mfa_entry.secret_enc)
        totp = pyotp.TOTP(raw_secret)
        if totp.verify(clean_code, valid_window=1):
            return True

        # Check backup code
        if mfa_entry.backup_codes_hash:
            hashes: List[str] = json.loads(mfa_entry.backup_codes_hash)
            candidate_hash = hash_token(clean_code.upper())
            if candidate_hash in hashes:
                hashes.remove(candidate_hash)
                mfa_entry.backup_codes_hash = json.dumps(hashes)
                await db.commit()
                return True

        return False


mfa_service = MFAService()
