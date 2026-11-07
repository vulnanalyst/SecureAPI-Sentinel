# SecureAPI-Sentinel

SecureAPI-Sentinel is a FastAPI-based API security project for demonstrating authentication, authorization, access control, and security testing workflows.

## Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite
- JWT bearer authentication
- Postman for API testing
- OWASP ZAP for security assessment
- Wireshark for localhost traffic inspection

> Confirm the exact dependency versions in `requirements.txt` before reproducing the environment.

## Features demonstrated

- User registration and login
- Bearer-token protected user profile endpoint
- Role-based access control on the admin dashboard
- Ownership checks intended to mitigate Broken Object Level Authorization (BOLA/IDOR)
- Security health endpoint
- OpenAPI documentation
- API testing with Postman
- Security assessment with OWASP ZAP
- Local HTTP traffic inspection with Wireshark

## Run locally (Windows PowerShell)

1. Clone the repository:

   ```powershell
   git clone https://github.com/vulnanalyst/SecureAPI-Sentinel.git
   cd SecureAPI-Sentinel
   ```

2. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Start the API:

   ```powershell
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

5. Open the API documentation:

   - Swagger UI: http://127.0.0.1:8000/docs
   - OpenAPI JSON: http://127.0.0.1:8000/api/v1/openapi.json

Keep the terminal running while using the API. Stop the server with `Ctrl+C`.

## Main API routes tested

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/v1/auth/register` | Register a test user |
| POST | `/api/v1/auth/login` | Authenticate and obtain tokens |
| GET | `/api/v1/users/me` | Read the authenticated user's profile |
| GET | `/api/v1/admin/dashboard` | Admin-only dashboard |
| GET | `/api/v1/security/health` | Security/service health information |

Use Swagger UI or the Postman collection to inspect the full route list. Routes and request schemas may change as the project evolves.

## Security testing evidence

The project was tested locally using Postman, OWASP ZAP, and Wireshark. The current ZAP report recorded:
- 40 API paths discovered from the imported OpenAPI definition.
- 0 High, 0 Medium, and 0 Low alerts in the generated report.
- 2 Informational alert types.
- The active scan was run against `GET /api/v1/security/health`; this does **not** mean every discovered API route received an active scan.

See [Security Assessment](docs/SECURITY_ASSESSMENT.md) and [Test Cases](docs/TEST_CASES.md) for scope and observed results.

## Repository structure

```text
SecureAPI-Sentinel/
├── app/                 # FastAPI application source
├── tests/               # Automated tests
├── postman/             # Postman collection/environment (sanitize before publishing)
├── reports/             # Sanitized security assessment reports
├── docs/                # Project and security documentation
├── requirements.txt
├── pytest.ini
├── README.md
└── SECURITY.md
```

The structure above is a guide; consult the repository tree for the exact current files.

## Important security notes

- Use only dummy accounts and local/test data.
- Never commit `.env` files, credentials, JWTs, private keys, database files containing personal data, or unsanitized packet captures.
- Do not expose the development server publicly.
- The ZAP result is limited to the scan scope and configuration described in the report. A clean report is not proof that the API is secure.

## Disclaimer

This project is intended for educational and authorized security testing. Test only systems you own or have explicit permission to assess.
