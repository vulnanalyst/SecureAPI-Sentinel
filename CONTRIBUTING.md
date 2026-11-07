# Contributing to SecureAPI Sentinel

Thank you for your interest in contributing to the SecureAPI Sentinel project. This document provides guidelines for development contributions.

> **Note:** This is an academic cybersecurity capstone project. All contributions must maintain the security-first development philosophy.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Architecture Guidelines](#architecture-guidelines)
- [Security Requirements](#security-requirements)
- [Testing Requirements](#testing-requirements)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)

---

## Development Setup

### 1. Prerequisites

- Python 3.12+
- Git 2.x
- (Optional) Docker for containerized development

### 2. Fork and Clone

```bash
git clone <your-fork-url>
cd SecureAPI-Sentinel
git remote add upstream <original-repo-url>
```

### 3. Virtual Environment

```powershell
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

pip install -r requirements.txt
```

### 4. Environment Configuration

```powershell
cp .env.example .env
# Edit .env with development settings
```

### 5. Database Setup

```powershell
alembic upgrade head
python -m app.database.init_db
```

### 6. Verify Setup

```powershell
pytest
# Expected: 30 passed, 0 failed
```

---

## Code Style

### Python Standards

- **Style guide:** PEP 8
- **Line length:** 100 characters maximum
- **Type hints:** Required on all function signatures
- **Docstrings:** Required for all public functions, classes, and modules

### Formatting Tools

```powershell
# Format code
black app/ tests/

# Sort imports
isort app/ tests/

# Type checking
mypy app/

# Linting
ruff check app/ tests/
```

### Type Annotations

All functions must be fully annotated:

```python
# ✅ Correct
async def authenticate(
    db: AsyncSession,
    email: str,
    password: str,
) -> Optional[User]:
    ...

# ❌ Incorrect
async def authenticate(db, email, password):
    ...
```

### Pydantic Models

- Use `model_config = ConfigDict(...)` (Pydantic v2 style)
- Never use `class Config:` (deprecated Pydantic v1 style)
- Always define explicit response schemas — never return raw ORM objects

```python
# ✅ Correct
class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    email: EmailStr
    # Only expose what is needed

# ❌ Incorrect — exposes password_hash, internal fields
def get_user(user: User) -> User:
    return user
```

---

## Architecture Guidelines

### Layer Separation

Maintain strict separation between layers:

```
API Routes (app/api/)        — HTTP handling, validation, response formatting
    ↓
Services (app/services/)     — Business logic, orchestration
    ↓
Models (app/models/)         — Database schema, relationships
    ↓
Database (app/database/)     — Engine, sessions, initialization
```

**Rules:**
- Routes must not contain business logic
- Services must not import from `app/api/`
- Models must not contain business logic
- Cross-service calls are allowed; keep them minimal

### Dependency Injection

Use FastAPI's dependency injection for all shared resources:

```python
# ✅ Correct — testable, injectable
@router.get("/users/me")
async def get_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ...

# ❌ Incorrect — not testable
@router.get("/users/me")
async def get_me():
    db = get_database_connection()
    ...
```

### Error Handling

- Never expose stack traces in API responses
- Use `HTTPException` for client errors (4xx)
- Let the global exception handler catch unexpected 500 errors
- Log errors server-side with full context

```python
# ✅ Correct
raise HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid credentials",
)

# ❌ Incorrect — leaks implementation details
raise HTTPException(
    status_code=500,
    detail=str(exc),  # May contain sensitive info
)
```

### Database Access

- Always use async SQLAlchemy sessions
- Always use the ORM (never raw SQL strings)
- Always use `selectinload()` for related collections to avoid N+1
- Always commit within the same function that initiates a transaction

---

## Security Requirements

> **All contributions must maintain or improve the security posture.**

### Mandatory Security Checks

Before submitting any PR, verify:

- [ ] No secrets hardcoded in code
- [ ] No raw SQL queries (use ORM only)
- [ ] All new endpoints have authentication/authorization applied
- [ ] New resource endpoints implement ownership validation
- [ ] Sensitive data is not returned in API responses
- [ ] Error messages do not leak internal implementation details
- [ ] New dependencies are from trusted sources and pinned to specific versions

### Adding New Endpoints

Every new protected endpoint must have:

1. **Authentication dependency:** `current_user: User = Depends(get_current_user)`
2. **Authorization check:** `Depends(require_roles([...]))` or manual ownership check
3. **Audit logging:** Call `audit_service.log_action(...)` for sensitive operations
4. **Input validation:** Pydantic schema with strict field definitions
5. **Response schema:** Pydantic model that excludes sensitive fields

### Adding New Dependencies

- Review the dependency's security history before adding
- Pin to a specific version in `requirements.txt`
- Check for known CVEs: `pip audit`
- Document why the dependency is needed in the PR description

---

## Testing Requirements

### Test Coverage

- All new features must include tests
- Maintain overall coverage above 70%
- Security-critical paths must have dedicated tests

### Test Structure

```
tests/
├── unit/           # Pure function tests (no database, no HTTP)
├── integration/    # API endpoint tests (async HTTP via HTTPX)
└── security/       # Security-specific defense tests
```

### Writing Integration Tests

```python
# ✅ Correct pattern
@pytest.mark.asyncio
async def test_my_feature(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/v1/endpoint", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "expected_field" in data
    assert "password_hash" not in data  # Security assertion
```

### Security Tests

For security-sensitive features, always add negative test cases:

```python
# ✅ Always test the negative case
async def test_cannot_access_other_users_resource(client, user_token, other_user_id):
    response = await client.get(
        f"/api/v1/users/{other_user_id}",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Must be blocked

async def test_cannot_escalate_privileges(client, user_token, user_id):
    response = await client.patch(
        f"/api/v1/users/{user_id}/role",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"roles": ["SUPER_ADMIN"]}
    )
    assert response.status_code == 403  # Must be blocked
```

### Running Tests

```powershell
# Full suite
pytest

# With coverage
pytest --cov=app --cov-report=html --cov-report=term-missing

# Single file
pytest tests/security/test_security_defenses.py -v

# Specific test
pytest tests/integration/test_auth_api.py::test_account_lockout -v
```

---

## Commit Guidelines

### Commit Message Format

Use Conventional Commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `security` — Security fix or improvement
- `docs` — Documentation only
- `test` — Adding or updating tests
- `refactor` — Code refactoring (no behavior change)
- `chore` — Build, dependency, or tooling changes

**Examples:**

```
feat(auth): add TOTP backup code consumption

security(tokens): revoke entire family on refresh token reuse

fix(users): correct selectinload for roles after assignment

test(security): add SQL injection defense tests

docs(readme): add Docker deployment instructions
```

### Commit Size

- Keep commits focused and atomic
- One logical change per commit
- Do not combine unrelated changes

---

## Pull Request Process

### Before Submitting

1. Run the full test suite: `pytest` — must be 0 failures
2. Run type checking: `mypy app/`
3. Run linting: `ruff check app/ tests/`
4. Update documentation if behavior changes
5. Add tests for all new functionality
6. Update `SECURITY.md` if security controls change

### PR Description Template

```markdown
## Summary
Brief description of what this PR does.

## Changes
- List of specific changes

## Security Impact
- [ ] No security-sensitive code changed
- [ ] Security controls added/modified (describe below)
- [ ] New dependency added (security review below)

## Testing
- Tests added: [list new test names]
- All 30 existing tests: PASSING

## Checklist
- [ ] No secrets in code
- [ ] No raw SQL queries
- [ ] All new endpoints have auth/authz
- [ ] Error messages don't leak internals
- [ ] Type hints on all new functions
- [ ] Docstrings on all public functions
```

### Review Criteria

PRs are evaluated on:
1. **Correctness** — Does it work as intended?
2. **Security** — Does it maintain or improve security?
3. **Code quality** — Is it readable, typed, documented?
4. **Tests** — Are the tests meaningful and complete?
5. **Consistency** — Does it follow existing patterns?

---

## Questions?

If you have questions about the architecture, security controls, or development guidelines, review:

- [`README.md`](README.md) — Project overview and setup
- [`SECURITY.md`](SECURITY.md) — Security policy and controls
- [`reports/owasp_assessment.md`](reports/owasp_assessment.md) — OWASP assessment
- [`MULTI_AGENT_REPORT.md`](MULTI_AGENT_REPORT.md) — Multi-agent development report

---

*SecureAPI Sentinel Capstone Project — Security-first development guidelines*

