# Security Assessment

## Assessment environment

- Target: local development API at `http://127.0.0.1:8000`
- API definition imported from: `/api/v1/openapi.json`
- OWASP ZAP version: 2.17.0
- Wireshark: used to inspect localhost API traffic
- Test data: dummy local account

## OWASP ZAP assessment

The OpenAPI definition was imported into ZAP and 40 API paths were discovered.

The active scan was run against:

```text
GET http://127.0.0.1:8000/api/v1/security/health
```

The generated HTML report recorded:

| Severity | Alert count |
|---|---:|
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 2 |

The two informational alert types were:

- Authentication Request Identified: ZAP sent a test login request using dummy credentials and received an authentication failure response.
- User Agent Fuzzer: ZAP sent requests with modified User-Agent values to the security health endpoint, which returned a successful health response.

These informational alerts are not confirmed vulnerabilities.

### Scope limitation

The 40 paths were discovered through OpenAPI import. The active scan described above targeted only the security health endpoint. Therefore, the report must not be interpreted as evidence that all 40 paths received an active scan.

The report's response statistics also showed a high proportion of 4xx responses. These can result from authentication requirements, invalid test requests, or rate limiting; they require endpoint-by-endpoint review and are not automatically vulnerabilities.

## Wireshark traffic inspection

Wireshark was used to capture localhost traffic between Postman and the API. A successful `GET /api/v1/users/me` request and its `200 OK` response were observed over loopback traffic.

The capture also demonstrated an important limitation: HTTP does not encrypt request headers. A bearer token visible in an HTTP capture must be treated as exposed.

For future testing:
- Use dummy accounts and short-lived test tokens.
- Do not share packet captures containing Authorization headers.
- Use HTTPS for deployments beyond local development.
- Revoke or rotate any token that has been exposed.

## Conclusion

The recorded ZAP report contained no High, Medium, or Low alerts within its tested scope. This is not a guarantee that the application is secure. Further testing should cover authenticated routes, authorization boundaries, input validation, rate limiting, error handling, and all state-changing endpoints.

## Responsible use

Only assess systems that you own or have explicit authorization to test.
