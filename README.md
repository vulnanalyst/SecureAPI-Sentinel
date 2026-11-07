# SecureAPI Sentinel

> **Advanced Secure REST API Platform** — Cybersecurity Capstone Project

A production-inspired, modular REST API platform built with **FastAPI**, **SQLAlchemy 2**, and **PostgreSQL**, demonstrating advanced backend engineering, secure software development, API testing, and practical vulnerability assessment.

---

## Table of Contents

- [Overview](#overview)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Running Tests](#running-tests)
- [Docker Deployment](#docker-deployment)
- [Project Structure](#project-structure)
- [Seed Credentials](#seed-credentials)
- [Security Assessment](#security-assessment)
- [Contributing](#contributing)

---

## Overview

SecureAPI Sentinel is a fully featured, security-first REST API that implements:

- **Advanced authentication**: Argon2id password hashing, JWT access tokens, refresh token rotation with reuse detection, TOTP-based MFA, account lockout
- **Role-based access control (RBAC)**: Four roles — SUPER_ADMIN, ADMIN, SECURITY_ANALYST, USER — enforced server-side with no frontend reliance
- **Security middleware pipeline**: OWASP security headers, CORS allowlisting, sliding-window rate limiting, request size limiting, audit logging
- **Comprehensive test suite**: 30 pytest tests (100% pass rate) covering authentication, authorization, BOLA/IDOR, SQL injection, rate limiting, and information disclosure
- **OWASP API Security assessment**: Code-review-verified coverage of all OWASP API Top 10 (2023) risks

This project was built as a four-agent orchestrated capstone demonstrating the full software development lifecycle for a security-critical API.

---

## Technology Stack

| Category | Technology | Version |
|----------|-----------|---------|
| Language | Python | 3.12+ |
| Framework | FastAPI | 0.115.x |
| ORM | SQLAlchemy (async) | 2.0.x |
| Migrations | Alembic | 1.14.x |
| Database (dev) | SQLite (aiosqlite) | — |
| Database (prod) | PostgreSQL | 16 |
| Password hashing | Argon2id (argon2-cffi) | 23.1.x |
| JWT | python-jose | 3.3.x |
| MFA | pyotp | 2.9.x |
| Encryption | cryptography (Fernet) | 44.x |
| Validation | Pydantic v2 | 2.10.x |
| Testing | pytest + pytest-asyncio + HTTPX | 8.x |
| Containers | Docker + Docker Compose | — |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│                 CLIENT                       │
└──────────────────┬──────────────────────────┘
                   │ HTTPS (TLS 1.3)
┌──────────────────▼──────────────────────────┐
│          MIDDLEWARE PIPELINE                 │
│  SizeLimitMiddleware → SecurityHeaders →     │
│  RateLimitMiddleware → AuditMiddleware       │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│              API ROUTES (v1)                 │
│  /auth  /users  /security  /admin            │
│  + FastAPI Dependency Injection (RBAC)       │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│              SERVICES LAYER                  │
│  AuthService  UserService  MFAService        │
│  AuditService  EmailAdapter                  │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│          DATABASE LAYER (SQLAlchemy 2)       │
│  Async sessions  •  10 normalized models     │
│  Alembic migrations  •  Indexing             │
└──────────────────┬──────────────────────────┘
                   │
         ┌─────────▼────────┐
         │   PostgreSQL 16   │
         └──────────────────┘
```

For the full architecture, threat model, and ER diagram, see [ARCHITECTURE_PLAN.md](docs/ARCHITECTURE_PLAN.md).

---

## Quick Start

### Prerequisites

- Python 3.12+
- Git
- (Optional) Docker & Docker Compose for containerized deployment

### 1. Clone and Setup

```powershell
git clone <repository-url>
cd SecureAPI-Sentinel

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```powershell
# Copy the example env file
cp .env.example .env

# Edit .env with your settings
# At minimum, generate new SECRET_KEY and MFA_ENCRYPTION_KEY
```

### 3. Initialize Database

```powershell
# Apply migrations
alembic upgrade head

# Seed the database with roles and default users
python -m app.database.init_db
```

### 4. Start the Server

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The API will be available at `http://localhost:8000`.

Interactive docs: `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

---

## Configuration

All configuration is managed via environment variables. Copy `.env.example` to `.env` and customize:

```env
# Application
APP_NAME=SecureAPI Sentinel
APP_VERSION=1.0.0
ENVIRONMENT=development
DEBUG=false

# Database
DATABASE_URL=sqlite+aiosqlite:///./sentinel.db
# Production: postgresql+asyncpg://user:password@localhost:5432/sentinel_db

# Security — GENERATE THESE WITH: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your-256-bit-secret-key-here
MFA_ENCRYPTION_KEY=your-fernet-key-here  # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# JWT
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS — comma-separated list of allowed origins
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# Rate limiting
RATE_LIMIT_AUTH_REQUESTS=10
RATE_LIMIT_AUTH_WINDOW_SECONDS=60
```

> **Security:** Never commit `.env` to version control. The `.gitignore` excludes it by default.

---

## API Documentation

### Base URL
```
http://localhost:8000/api/v1
```

### Authentication Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|--------------|-------------|
| POST | `/auth/register` | No | Register new user |
| POST | `/auth/login` | No | Login and receive tokens |
| POST | `/auth/logout` | Yes | Logout and revoke tokens |
| POST | `/auth/refresh` | No (token) | Rotate refresh token |
| POST | `/auth/forgot-password` | No | Request password reset |
| POST | `/auth/reset-password` | No (token) | Reset password |
| POST | `/auth/mfa/enable` | Yes | Initiate TOTP MFA setup |
| POST | `/auth/mfa/verify` | Yes | Complete MFA enrollment |

### User Endpoints

| Method | Endpoint | Required Role | Description |
|--------|----------|--------------|-------------|
| GET | `/users/me` | USER+ | Get own profile |
| PUT | `/users/me` | USER+ | Update own profile |
| GET | `/users` | ADMIN+ | List all users |
| GET | `/users/{id}` | USER (own) / ADMIN+ | Get user by ID |
| PATCH | `/users/{id}/role` | SUPER_ADMIN | Assign user roles |
| DELETE | `/users/{id}` | SUPER_ADMIN | Delete user |

### Security Endpoints

| Method | Endpoint | Required Role | Description |
|--------|----------|--------------|-------------|
| GET | `/security/health` | Public | Health check |
| GET | `/security/events` | ANALYST+ | Security events |
| GET | `/security/audit-logs` | ADMIN+ | Audit log entries |

### Administration Endpoints

| Method | Endpoint | Required Role | Description |
|--------|----------|--------------|-------------|
| GET | `/admin/dashboard` | ADMIN+ | Dashboard metrics |
| GET | `/admin/users` | ADMIN+ | Admin user listing |
| GET | `/admin/system-status` | SUPER_ADMIN | Full system status |

Full OpenAPI specification: `http://localhost:8000/docs`

---

## Security Features

### Authentication
- **Argon2id** password hashing (m=65536, t=3, p=4) — OWASP recommended
- **JWT** access tokens with 15-minute TTL
- **Refresh token rotation** — new pair issued on every refresh; old token immediately revoked
- **Reuse detection** — entire token family revoked if a rotated token is reused (theft detection)
- **TOTP MFA** — RFC 6238 compliant; secrets encrypted with AES-256 (Fernet) at rest
- **Account lockout** — 5 failed attempts triggers 30-minute lockout
- **Secure password reset** — single-use tokens with 1-hour expiry; anti-enumeration response

### Authorization
- **RBAC** enforced via FastAPI dependency injection — not client-enforced
- **Ownership validation** on all resource endpoints (BOLA/IDOR prevention)
- **Privilege escalation prevention** — users cannot modify their own roles

### Middleware
- **Security headers**: HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy
- **CORS allowlisting**: Explicit origin list; never wildcard in production
- **Rate limiting**: 10 req/60s on auth endpoints; 60 req/60s general
- **Payload size limit**: 10 MB maximum request body
- **Audit logging**: All security-relevant actions recorded

### Database
- **ORM-only queries**: No raw SQL; SQLAlchemy prevents SQL injection by design
- **Parameterized queries**: All user input is bound as parameters
- **Foreign keys and constraints**: Referential integrity enforced
- **Sensitive data encryption**: MFA secrets encrypted at rest

---

## Running Tests

```powershell
cd SecureAPI-Sentinel
.venv\Scripts\activate

# Run all 30 tests
pytest

# Run with coverage report
pytest --cov=app --cov-report=html --cov-report=term-missing

# Run specific test suites
pytest tests/unit/                    # 7 unit tests
pytest tests/integration/             # 18 integration tests
pytest tests/security/                # 5 security tests

# View HTML coverage report
start reports/coverage_html/index.html
```

**Test results summary:**
```
30 passed, 0 failed
Coverage: 74%
```

---

## Docker Deployment

```powershell
# Start all services (API + PostgreSQL + Redis)
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down

# Stop and remove volumes (data loss!)
docker-compose down -v
```

The Docker setup includes:
- **api**: FastAPI application (non-root user `sentinel`)
- **postgres**: PostgreSQL 16 with persistent volume
- **redis**: Redis 7 (for future Redis-backed rate limiting)

> **Note:** The Docker daemon must be running. If unavailable, use the local development setup above.

---

## Project Structure

```
SecureAPI-Sentinel/
├── app/
│   ├── api/
│   │   ├── deps.py              # Shared dependencies (auth, RBAC, ownership)
│   │   └── v1/
│   │       ├── auth.py          # Authentication endpoints
│   │       ├── users.py         # User management endpoints
│   │       ├── security.py      # Security monitoring endpoints
│   │       └── admin.py         # Administration endpoints
│   ├── core/
│   │   ├── config.py            # Pydantic settings
│   │   ├── security.py          # Argon2id, JWT, encryption
│   │   ├── logging.py           # Structured JSON logging
│   │   └── permissions.py       # Roles, permissions, RBAC mapping
│   ├── models/                  # SQLAlchemy ORM models (10 tables)
│   ├── schemas/                 # Pydantic request/response schemas
│   ├── services/                # Business logic layer
│   │   ├── auth_service.py      # Registration, login, token lifecycle
│   │   ├── user_service.py      # User CRUD operations
│   │   ├── mfa_service.py       # TOTP setup and verification
│   │   ├── audit_service.py     # Security event and audit logging
│   │   └── email_adapter.py     # Development email adapter
│   ├── middleware/              # ASGI middleware components
│   └── database/               # Engine, session, initialization
├── migrations/                  # Alembic migration scripts
├── tests/
│   ├── unit/                    # Core logic unit tests (7)
│   ├── integration/             # API integration tests (18)
│   └── security/               # Security defense tests (5)
├── postman/                     # Postman collection (25 requests)
├── reports/                     # Assessment reports and coverage
├── docs/                        # Architecture and API documentation
├── scripts/                     # Utility scripts
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
└── README.md
```

---

## Seed Credentials

The database is seeded with these accounts for development and testing:

> **⚠️ Change all passwords before any deployment, even internal.**

| Role | Email | Default Password |
|------|-------|-----------------|
| SUPER_ADMIN | superadmin@sentinel.org | SuperAdmin#2026!Sec |
| ADMIN | admin@sentinel.org | Admin#2026!Sec |
| SECURITY_ANALYST | analyst@sentinel.org | Analyst#2026!Sec |
| USER | user1@sentinel.org | Standard#2026!Sec |
| USER | user2@sentinel.org | Standard#2026!Sec |

---

## Security Assessment

The following security assessment documents are included:

| Document | Description |
|----------|-------------|
| [`reports/owasp_assessment.md`](reports/owasp_assessment.md) | OWASP API Top 10 (2023) assessment with verified findings |
| [`reports/wireshark_analysis.md`](reports/wireshark_analysis.md) | HTTP/HTTPS traffic analysis guide |
| [`reports/coverage_html/`](reports/coverage_html/) | Test coverage HTML report |
| [`SECURITY.md`](SECURITY.md) | Security policy and vulnerability reporting |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and code standards.

---

## License

This project is created for academic purposes as a cybersecurity capstone project. All security testing is performed exclusively against the local development environment.

---

*Built by: SecureAPI Sentinel Engineering Team (Four-Agent Orchestration)*  
*See [MULTI_AGENT_REPORT.md](MULTI_AGENT_REPORT.md) for the full multi-agent execution report*

