import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class RefreshToken(Base):
    """
    Refresh Token record supporting Token Family Rotation and Reuse Detection (RFC 6749 / RFC 6819).
    Never stores plaintext tokens.
    """
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    family_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    jti: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, default=lambda: str(uuid.uuid4())
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    replaced_by_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user = relationship("User", back_populates="refresh_tokens")

    __table_args__ = (
        Index("ix_refresh_tokens_family_revoked", "family_id", "is_revoked"),
    )


class PasswordResetToken(Base):
    """Single-use password reset tokens with SHA-256 hashing and expiration."""
    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    user = relationship("User", back_populates="password_reset_tokens")

