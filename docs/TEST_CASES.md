# API Test Cases

This document records the API checks performed during the local project walkthrough. Results are limited to the requests actually executed; they are not a complete penetration test.

## Postman test matrix

| Test | Request | Observed result | Notes |
|---|---|---|---|
| User registration | `POST /api/v1/auth/register` | 201 Created | A dummy test account was registered. |
| User login | `POST /api/v1/auth/login` | 200 OK | Response returned access and refresh tokens. |
| Authenticated profile | `GET /api/v1/users/me` with bearer token | 200 OK | Profile endpoint returned the authenticated user's data. |
| Profile without token | `GET /api/v1/users/me` without bearer token | 401 Unauthorized | Authentication was required. |
| Admin route with normal user token | `GET /api/v1/admin/dashboard` | 403 Forbidden observed | Normal user token did not receive admin access. A rate-limit response was also encountered during an earlier attempt. |
| Cross-user access / BOLA | `GET /api/v1/users/{user_id}` | 403 Forbidden observed in one attempt | To conclusively verify ownership enforcement, test the authenticated user's own ID and a second account's ID separately. |

## Recommended repeatable BOLA verification

1. Register two separate dummy users.
2. Log in as User A and save User A's access token.
3. Request User A's own user resource; record the response.
4. Without changing the token, request User B's resource ID.
5. Confirm that User A cannot read or modify User B's resource.
6. Repeat for any update/delete routes that accept a user or resource ID.

Do not use real user data during these tests.

## Postman environment

Suggested local variables:

- `base_url`: `http://127.0.0.1:8000`
- `token`: access token from the dummy test account

Treat tokens as secrets. Do not commit an environment export containing live tokens or passwords.

## Limitations

- These are selected functional and authorization checks, not exhaustive endpoint coverage.
- A 403 response alone does not prove all BOLA/IDOR cases are prevented.
- Rate limiting can affect repeatability; wait for the server's indicated retry period before rerunning a rate-limited request.
