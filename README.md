# SecureAPI-Sentinel

> **Security-First REST API Platform** — Cybersecurity Capstone Project

SecureAPI-Sentinel is a modular REST API built with **FastAPI**, **SQLAlchemy 2**, and **Python**. It demonstrates secure API development through authentication, authorization, defensive middleware, automated testing, and practical security assessment.

## Overview

- **Authentication:** Argon2id password hashing, JWT access tokens, refresh-token rotation and reuse detection, TOTP-based MFA, account lockout, and password-reset workflows.
- **Authorization:** Server-side role-based access control (RBAC) with SUPER_ADMIN, ADMIN, SECURITY_ANALYST, and USER roles.
- **API protections:** Security headers, CORS allowlisting, rate limiting, request-size limits, audit logging, and resource-ownership checks.
- **Data layer:** SQLAlchemy ORM, Alembic migrations, SQLite for development, and PostgreSQL for production configuration.
- **Testing and assessment:** pytest, Postman, OWASP ZAP, and Wireshark.

This repository is intended for academic and defensive security learning. Test only systems you own or are explicitly authorized to assess.

## Technology Stack

| Area | Technology |
|---|---|
| Language | Python 3.12+ |
| API framework | FastAPI |
| ORM | SQLAlchemy 2 |
| Development database | SQLite with aiosqlite |
| Production database configuration | PostgreSQL 16 |
| Schema migrations | Alembic |
| Validation | Pydantic v2 |
| Password hashing | Argon2id |
| Tokens | JWT and refresh-token rotation |
| MFA and encryption | TOTP, PyOTP, Fernet |
| Testing | pytest, pytest-asyncio, HTTPX |
| API testing | Postman |
| Security assessment | OWASP ZAP |
| Network analysis | Wireshark |
| Containerization | Docker and Docker Compose |

## Architecture

    Client (Postman / Swagger UI / HTTP client)
                     |
                     v
             Security Middleware
       Request Size | Security Headers
       Rate Limiting | CORS | Audit Logging
                     |
                     v
                FastAPI v1
          /auth /users /security /admin
                     |
            Authentication & RBAC
                     |
                     v
                  Services
       Auth | User | MFA | Audit | Email
                     |
                     v
            SQLAlchemy Async ORM
               + Alembic Migrations
                     |
              SQLite / PostgreSQL

For the detailed architecture, threat model, and ER diagram, see [docs/ARCHITECTURE_PLAN.md](docs/ARCHITECTURE_PLAN.md).

## Security Features

### Authentication
- Argon2id password hashing.
- Short-lived JWT access tokens.
- Refresh-token rotation with reuse detection.
- TOTP-based MFA with encrypted MFA secrets.
- Account lockout after repeated failed login attempts.
- Single-use password-reset tokens with expiry.

### Authorization
- Server-side RBAC enforced through FastAPI dependencies.
- Four roles: SUPER_ADMIN, ADMIN, SECURITY_ANALYST, and USER.
- Resource-ownership checks for user-specific resources.
- Protection against unauthorized role changes and privilege escalation.

### Middleware and Data Protection
- Security headers including HSTS, CSP, and content-type protections.
- Explicit CORS origin allowlisting.
- Configurable rate limiting.
- Request body size limit.
- Audit logs and security-event records.
- SQLAlchemy ORM queries and parameter binding.

## API Documentation

Run the application locally and open:

- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

The API base path is /api/v1.

### Main API Groups

| Group | Example endpoints | Purpose |
|---|---|---|
| Authentication | POST /auth/register, POST /auth/login, POST /auth/refresh | Registration, login, and token lifecycle |
| Users | GET /users/me, PUT /users/me, GET /users/{id} | Profile and user management |
| Security | GET /security/health, GET /security/events | Health and security-event information |
| Administration | GET /admin/dashboard, GET /admin/system-status | Role-restricted administrative operations |

See the live OpenAPI documentation for the exact routes and schemas exposed by the running application.

## Quick Start (Windows PowerShell)

### 1. Clone the repository

    git clone https://github.com/vulnanalyst/SecureAPI-Sentinel.git
    cd SecureAPI-Sentinel

### 2. Create and activate a virtual environment

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

### 3. Install dependencies

    python -m pip install -r requirements.txt

### 4. Configure environment variables

    Copy-Item .env.example .env

Edit .env and set unique secret values for the local environment. Never commit a real .env file or production credentials.

Generate a secret key:

    python -c "import secrets; print(secrets.token_hex(32))"

Generate a Fernet key:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

### 5. Initialize the database

    alembic upgrade head
    python -m app.database.init_db

### 6. Run the API

    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

The local API is available at http://127.0.0.1:8000.

## Running Tests

    python -m pytest -v

Run the test suite with coverage:

    python -m pytest --cov=app --cov-report=term-missing --cov-report=html

Run individual test groups:

    python -m pytest tests/unit/
    python -m pytest tests/integration/
    python -m pytest tests/security/

The repository's documented test-suite layout is 7 unit tests, 18 integration tests, and 5 security tests (30 total). Test counts and coverage should be confirmed by running the commands in the target environment; results can vary with the checked-out code and installed dependencies.

## Security Assessment Tools

| Tool / Document | Purpose |
|---|---|
| Postman collection (postman/) | Manual endpoint and response testing |
| OWASP ZAP | API security scanning |
| Wireshark | Network packet and HTTP/HTTPS traffic analysis |
| reports/owasp_assessment.md | OWASP API Security Top 10 (2023) code-review assessment |
| reports/wireshark_analysis.md | Traffic-analysis guide |
| SECURITY.md | Security policy and vulnerability reporting |

A code-review assessment and an automated scan are different forms of evidence. Scanning selected endpoints does not establish that every endpoint is vulnerability-free.

## Docker Deployment

With Docker Desktop running:

    docker-compose up -d
    docker-compose logs -f api
    docker-compose down

The documented Compose setup includes the API, PostgreSQL, and Redis services. Review and configure environment variables before deployment.

## Project Structure

    SecureAPI-Sentinel/
    ├── app/
    │   ├── api/
    │   │   ├── deps.py
    │   │   └── v1/
    │   │       ├── auth.py
    │   │       ├── users.py
    │   │       ├── security.py
    │   │       └── admin.py
    │   ├── core/
    │   ├── models/
    │   ├── schemas/
    │   ├── services/
    │   ├── middleware/
    │   └── database/
    ├── migrations/
    ├── tests/
    │   ├── unit/
    │   ├── integration/
    │   └── security/
    ├── postman/
    ├── reports/
    ├── docs/
    ├── scripts/
    ├── docker-compose.yml
    ├── Dockerfile
    ├── requirements.txt
    ├── .env.example
    └── README.md

## Repository

https://github.com/vulnanalyst/SecureAPI-Sentinel

## Academic Use

This project was developed as a cybersecurity capstone to demonstrate secure REST API design, implementation, and assessment. All testing should be limited to local development environments or explicitly authorized systems.
