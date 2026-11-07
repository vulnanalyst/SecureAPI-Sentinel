import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class MFASecurity(Base):
    __tablename__ = "mfa_secrets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True
    )
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    backup_codes_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    user = relationship("User", back_populates="mfa")

