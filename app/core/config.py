from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Project Information
    PROJECT_NAME: str = "SecureAPI Sentinel"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Cryptographic & Authentication Secrets
    SECRET_KEY: str = Field(
        default="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
        description="Master secret key for JWT signing"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # TOTP MFA Settings & Secret Encryption Key (Must be 32 URL-safe base64 or 32 hex chars)
    MFA_ISSUER: str = "SecureAPI Sentinel"
    MFA_ENCRYPTION_KEY: str = Field(
        default="k8Z_0sX2wV7mQ9tL4rP1yN3eU6bJ8hF5xG2aD4cE6wA=",
        description="Fernet/AES-256 encryption key for sensitive MFA secret storage"
    )

    # Brute Force & Account Lockout
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Database Configuration (Supports async PostgreSQL and fallback async SQLite)
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./sentinel.db",
        description="Async SQLAlchemy database connection URI"
    )
    DB_ECHO: bool = False

    # Redis Cache Configuration
    REDIS_URL: Optional[str] = None

    # Security Controls & Limits
    RATE_LIMIT_PER_MINUTE: int = 60
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 Megabytes

    # CORS Allowlisting
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "testserver"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)


settings = Settings()
