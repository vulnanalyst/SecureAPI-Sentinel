from datetime import datetime
from typing import List
from pydantic import BaseModel


class DashboardStatsResponse(BaseModel):
    total_users: int
    active_sessions: int
    locked_accounts: int
    security_alerts_count: int
    system_status: str


class SystemStatusResponse(BaseModel):
    python_version: str
    environment: str
    database_status: str
    redis_status: str
    active_middleware: List[str]
    timestamp: datetime
