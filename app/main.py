import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import logger
from app.database.init_db import init_db
from app.api.v1 import api_v1_router
from app.middleware import (
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
    RateLimitMiddleware,
    AuditCorrelationMiddleware,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database schema & baseline seed data
    logger.info("Initializing SecureAPI Sentinel persistence and security configurations...")
    await init_db()
    logger.info("Database and RBAC seeds initialized successfully.")
    yield
    # Shutdown
    logger.info("Shutting down SecureAPI Sentinel cleanly.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Advanced Production-Grade Secure REST API Platform & Cybersecurity Assessment Suite",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# 1. Mount Security Headers Middleware (Outer perimeter)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Mount Anti-DoS Request Size Limiter Middleware
app.add_middleware(
    RequestSizeLimitMiddleware, max_size_bytes=settings.MAX_REQUEST_SIZE_BYTES
)

# 3. Mount Rate Limiting Middleware
app.add_middleware(RateLimitMiddleware)

# 4. Mount Correlation & Audit Logging Middleware
app.add_middleware(AuditCorrelationMiddleware)

# 5. Strict CORS Allowlisting
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time-MS", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
)


# Global Secure Exception Handlers (Information Disclosure Defense)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.__class__.__name__,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "request_id": request_id,
        },
        headers=getattr(exc, "headers", None)
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    errors = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append({"field": field, "message": err.get("msg")})

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Unprocessable Entity",
            "status_code": 422,
            "detail": "Input validation failed. Please check field requirements.",
            "errors": errors,
            "request_id": request_id,
        }
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Catches all unhandled exceptions. Prevents stack trace disclosure,
    database schema leakage, and file system path exposure.
    """
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    client_ip = getattr(request.state, "client_ip", "unknown")

    logger.error(
        f"Unhandled Internal Server Error on {request.method} {request.url.path}: {str(exc)}",
        exc_info=True,
        extra={"request_id": request_id, "client_ip": client_ip}
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "status_code": 500,
            "detail": "An internal server error occurred. Please contact the security administrator.",
            "request_id": request_id,
        }
    )


# Include API v1 Router
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
async def root():
    return {
        "title": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "status": "OPERATIONAL",
        "documentation": "/docs"
    }
