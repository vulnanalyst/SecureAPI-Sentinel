import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.models.audit import AuditLog, SecurityEvent
from app.core.logging import logger


class AuditService:
    @staticmethod
    async def log_action(
        db: AsyncSession,
        action: str,
        resource: str,
        status_code: int,
        user_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Records an immutable audit log entry into the database."""
        details_str = json.dumps(details) if details else None
        audit = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status_code=status_code,
            details=details_str,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(audit)
        await db.commit()
        await db.refresh(audit)
        return audit

    @staticmethod
    async def log_security_event(
        db: AsyncSession,
        event_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """Records high-severity security incidents (e.g. token reuse, lockouts)."""
        meta_str = json.dumps(metadata) if metadata else None
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            description=description,
            metadata_json=meta_str,
            created_at=datetime.now(timezone.utc),
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)

        logger.warning(
            f"SECURITY ALERT [{severity}] {event_type}: {description}",
            extra={
                "security_event": event_type,
                "user_id": user_id,
                "client_ip": source_ip,
            }
        )
        return event

    @staticmethod
    async def get_security_events(
        db: AsyncSession, limit: int = 50, offset: int = 0
    ) -> list[SecurityEvent]:
        query = (
            select(SecurityEvent)
            .order_by(desc(SecurityEvent.created_at))
            .limit(limit)
            .offset(offset)
        )
        res = await db.execute(query)
        return list(res.scalars().all())

    @staticmethod
    async def get_audit_logs(
        db: AsyncSession, limit: int = 50, offset: int = 0
    ) -> list[AuditLog]:
        query = (
            select(AuditLog)
            .order_by(desc(AuditLog.timestamp))
            .limit(limit)
            .offset(offset)
        )
        res = await db.execute(query)
        return list(res.scalars().all())


audit_service = AuditService()

