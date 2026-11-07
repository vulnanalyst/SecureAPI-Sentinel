from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: Optional[str] = None
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    description: str
    metadata_json: Optional[str] = None
    created_at: datetime


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: Optional[str] = None
    action: str
    resource: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: int
    details: Optional[str] = None
    timestamp: datetime


class HealthResponse(BaseModel):
    status: str
    database: str
    redis: str
    crypto_engine: str
    timestamp: datetime
