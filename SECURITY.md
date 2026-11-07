# Security Policy — SecureAPI Sentinel

## Overview

This document describes the security policy for the SecureAPI Sentinel project, including:
- Supported versions
- Vulnerability reporting process
- Security controls summary
- Known security considerations

---

## Supported Versions

This is an academic capstone project. The following version receives security attention:

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes |
| < 1.0   | ❌ No |

---

## Reporting a Vulnerability

This is an academic project. If you discover a security vulnerability:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. **Do** email the project maintainer directly with details
3. Include: description, reproduction steps, potential impact, suggested fix

We aim to acknowledge reports within 48 hours and provide a resolution within 7 days for academic scope.

---

## Security Controls

### Authentication

| Control | Implementation | Standard |
|---------|---------------|---------|
| Password hashing | Argon2id (m=65536, t=3, p=4) | OWASP Password Storage |
| Access tokens | JWT (HS256), 15-minute TTL | RFC 7519 |
| Refresh tokens | Rotation on every use; SHA-256 hash stored | OWASP Session Management |
| Reuse detection | Full family revocation on reuse | Refresh Token Best Practices |
| MFA | TOTP (RFC 6238) via pyotp | NIST 800-63B AAL2 |
| Account lockout | 5 failures → 30-minute lockout | OWASP Authentication |
| Password reset | Single-use tokens, 1-hour expiry | OWASP Forgot Password |

### Authorization

| Control | Implementation |
|---------|---------------|
| RBAC | FastAPI dependency injection, server-side enforced |
| Object-level auth | Ownership validation on all resource endpoints |
| BOLA prevention | UUID-based IDs; ownership check before data access |
| Privilege escalation | Role assignment restricted to SUPER_ADMIN |

### Transport

| Control | Recommendation |
|---------|---------------|
| TLS | 1.3 with AEAD cipher suites (production requirement) |
| HSTS | `max-age=31536000; includeSubDomains` (header implemented) |
| Certificate | Valid CA-signed certificate required in production |

### Headers

All HTTP responses include:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store
```

### Database

| Control | Implementation |
|---------|---------------|
| SQL injection prevention | SQLAlchemy ORM (parameterized queries only) |
| Credentials | Environment variables; never hardcoded |
| Sensitive data | MFA secrets encrypted (AES-256/Fernet) at rest |
| Connection security | Pooled async connections with timeout |

### Logging and Audit

| Control | Implementation |
|---------|---------------|
| Audit logs | All sensitive actions recorded in `audit_logs` table |
| Security events | Failed logins, lockouts, token reuse recorded |
| Sensitive field scrubbing | Passwords, tokens scrubbed from log output |
| Request tracking | X-Request-ID on every request |

---

## Known Security Considerations

### Development vs Production

| Item | Development | Production Requirement |
|------|-------------|----------------------|
| Database | SQLite | PostgreSQL 16 with TLS |
| Rate limiter | In-memory | Redis-backed |
| TLS | Not applied | Required at reverse proxy |
| Seed passwords | Weak for usability | Must be changed |
| OpenAPI docs | Enabled (`/docs`, `/redoc`) | Disable or restrict |
| Debug mode | May be enabled | Must be `false` |

### Secrets Management

The following secrets **must** be regenerated before any deployment:

```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate MFA_ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Never:**
- Commit `.env` to version control
- Use the example keys from `.env.example` in any deployed environment
- Share production secrets in code reviews, chat, or documentation

### JWT Security

- Access tokens expire in 15 minutes (configurable)
- Refresh tokens expire in 7 days (configurable)
- Token revocation is implemented (logout revokes the refresh token)
- Refresh token reuse triggers full family revocation (theft detection)
- The JWT signing secret must be at least 256 bits of entropy

### Password Policy

Passwords must meet these minimum requirements:
- At least 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

This is enforced by Pydantic validators on the registration and password-reset schemas.

---

## Security Architecture References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)

---

*This security policy is part of the SecureAPI Sentinel academic cybersecurity capstone project.*

