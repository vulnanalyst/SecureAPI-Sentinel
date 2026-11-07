# Wireshark Traffic Analysis — SecureAPI Sentinel

**Project:** SecureAPI Sentinel Cybersecurity Capstone  
**Author:** Agent 4 — Application Security Engineer  
**Scope:** Practical local HTTP/HTTPS traffic analysis against `localhost:8000`  
**Tool version:** Wireshark 4.x (recommended: 4.4.x LTS)  
**Date:** November 2026  
**Classification:** Academic / Authorized Testing Only

---

## 1. Overview

Wireshark is a network packet capture and protocol analyzer. This document provides a structured walkthrough of using Wireshark to inspect traffic flowing to and from the SecureAPI Sentinel application running locally (`http://localhost:8000`).

The exercise covers:
- Capturing HTTP (plaintext) traffic
- Inspecting requests, responses, headers, payloads, and authentication tokens
- Understanding TLS/HTTPS encryption and what it hides from a network observer
- Identifying sensitive information exposure risks in HTTP vs HTTPS
- Practical capture filters and display filters

> **Important:** All captures are performed against `localhost` only. No production traffic is inspected. This exercise is purely educational.

---

## 2. Environment Setup

### 2.1 Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| Wireshark | 4.x | Download from wireshark.org |
| SecureAPI Sentinel | v1.0 | Running via `uvicorn` on port 8000 |
| curl / Postman | Any | For generating test traffic |
| OS | Windows 10/11 | Npcap required for packet capture |

### 2.2 Starting the Application (HTTP mode — for capture)

For this exercise, the application is started without TLS so traffic is visible:

```powershell
cd J:\Academic\Projects\SecureAPI-Sentinel
.venv\Scripts\activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

> **Note:** In a production deployment, TLS would be terminated at a reverse proxy (nginx/Caddy). The application itself does not currently implement TLS directly — traffic analysis is therefore over plaintext HTTP on localhost.

### 2.3 Installing Npcap (Windows)

Wireshark on Windows requires Npcap to capture packets:
1. Download from: https://npcap.com/#download
2. Run installer with "WinPcap API-compatible mode" enabled
3. Restart Wireshark after installation

---

## 3. Capturing Local HTTP Traffic

### 3.1 Interface Selection

1. Open Wireshark
2. In the "Capture Interfaces" list, select the **Loopback: lo** adapter (or `\Device\NPF_Loopback` on Windows)
3. If the loopback adapter is not visible, install Npcap with loopback support

> On Windows, the loopback adapter may appear as `Adapter for loopback traffic capture` in the interface list.

### 3.2 Capture Filter

Apply this capture filter before starting to limit noise:

```
host 127.0.0.1 and port 8000
```

**Start capture:** Click the blue shark fin icon or press `Ctrl+E`

---

## 4. Generating Test Traffic

Open a new terminal and generate traffic against the running API:

### 4.1 Health Check (GET)

```powershell
curl http://127.0.0.1:8000/api/v1/security/health
```

**Expected response:**
```json
{"status": "healthy", "version": "1.0.0", "timestamp": "..."}
```

### 4.2 User Registration (POST with JSON body)

```powershell
curl -X POST http://127.0.0.1:8000/api/v1/auth/register `
  -H "Content-Type: application/json" `
  -d "{\"email\":\"wireshark_test@example.com\",\"password\":\"TestPass#2026!\",\"full_name\":\"Wireshark Test\"}"
```

### 4.3 Login (credential transmission)

```powershell
curl -X POST http://127.0.0.1:8000/api/v1/auth/login `
  -H "Content-Type: application/json" `
  -d "{\"email\":\"wireshark_test@example.com\",\"password\":\"TestPass#2026!\"}"
```

### 4.4 Authenticated Request (JWT in header)

```powershell
# Replace TOKEN with the access_token from the login response
curl http://127.0.0.1:8000/api/v1/users/me `
  -H "Authorization: Bearer TOKEN"
```

---

## 5. HTTP Traffic Inspection

Stop the capture after generating the traffic above. Apply the display filter:

```
http
```

### 5.1 Locating HTTP Packets

| Packet type | Display filter | Color |
|-------------|---------------|-------|
| All HTTP | `http` | Green (default) |
| POST requests | `http.request.method == "POST"` | — |
| GET requests | `http.request.method == "GET"` | — |
| HTTP 200 OK | `http.response.code == 200` | — |
| HTTP 401 | `http.response.code == 401` | — |

### 5.2 Inspecting a POST /api/v1/auth/login Request

Click on the POST packet. Expand the **Hypertext Transfer Protocol** section in the packet details pane:

```
Hypertext Transfer Protocol
  POST /api/v1/auth/login HTTP/1.1\r\n
  Host: 127.0.0.1:8000\r\n
  User-Agent: curl/8.x\r\n
  Content-Type: application/json\r\n
  Content-Length: 65\r\n
  Accept: */*\r\n
  \r\n
  File data: 65 bytes
```

Expand **JavaScript Object Notation** (or **Line-based text data**) to see the payload:

```json
{
  "email": "wireshark_test@example.com",
  "password": "TestPass#2026!"
}
```

> **⚠️ Security Finding:** Over plaintext HTTP, the user's password is fully visible in the packet capture. Any network observer (attacker, ISP, proxy) on the same network can capture this credential. This is why HTTPS is mandatory for any authentication endpoint.

### 5.3 Inspecting HTTP Response Headers

Click on the corresponding HTTP 200 response packet. Expand **Hypertext Transfer Protocol**:

```
HTTP/1.1 200 OK\r\n
content-type: application/json\r\n
x-content-type-options: nosniff\r\n
x-frame-options: DENY\r\n
strict-transport-security: max-age=31536000; includeSubDomains\r\n
content-security-policy: default-src 'none'...\r\n
x-request-id: 3a7f1b29-...\r\n
x-process-time: 0.0423\r\n
content-length: 312\r\n
```

**Security headers visible in Wireshark:**

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Strict-Transport-Security` | `max-age=31536000` | Force HTTPS (after first visit) |
| `Content-Security-Policy` | `default-src 'none'` | Restrict resource loading |
| `X-Request-ID` | UUID | Request tracing |

### 5.4 Inspecting the Login Response Payload

The JSON response body contains the JWT tokens:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

> **⚠️ Security Finding:** Over HTTP, the JWT access token is fully visible. An attacker who captures this token can impersonate the user for the token's lifetime (15 minutes for access tokens). This demonstrates why HTTPS is essential — it encrypts the response body.

### 5.5 Inspecting an Authenticated GET Request

Find the GET `/api/v1/users/me` packet. The Authorization header is visible:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

> **⚠️ Security Finding:** The JWT Bearer token in the Authorization header is transmitted in plaintext over HTTP. Any network observer can extract this token and make authenticated API calls.

### 5.6 HTTP Methods Observed

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/security/health` | Read-only resource retrieval |
| POST | `/api/v1/auth/register` | Create new resource (user) |
| POST | `/api/v1/auth/login` | Authentication action |
| PUT | `/api/v1/users/me` | Full resource update |
| PATCH | `/api/v1/users/{id}/role` | Partial resource update |
| DELETE | `/api/v1/users/{id}` | Resource deletion |

### 5.7 HTTP Status Codes Observed

| Code | Meaning | Example endpoint |
|------|---------|-----------------|
| 200 OK | Success | GET /users/me |
| 201 Created | Resource created | POST /auth/register |
| 400 Bad Request | Validation failure | Invalid email format |
| 401 Unauthorized | Missing/invalid token | No Authorization header |
| 403 Forbidden | Insufficient permissions | Regular user → admin endpoint |
| 404 Not Found | Resource not found | GET /users/nonexistent-id |
| 409 Conflict | Duplicate resource | Register with existing email |
| 422 Unprocessable Content | Schema validation error | Missing required field |
| 429 Too Many Requests | Rate limit exceeded | >10 auth requests/minute |

---

## 6. Following a TCP Stream

Wireshark's "Follow TCP Stream" shows the complete HTTP conversation:

1. Right-click any HTTP packet
2. Select: **Follow → TCP Stream**
3. A dialog shows the full raw HTTP exchange as text

This reveals:
- Complete request including body
- Complete response including headers and body
- The sequence of packets in that connection

**Keyboard shortcut:** `Ctrl+Alt+Shift+T`

---

## 7. TLS/HTTPS Traffic Analysis

### 7.1 Enabling TLS (Test Procedure)

To observe encrypted traffic, start the application behind a TLS proxy. Using `caddy` as a local TLS terminator:

```
caddy reverse-proxy --from localhost:443 --to localhost:8000
```

Or use `mkcert` to generate a self-signed certificate and serve via uvicorn:

```powershell
pip install uvicorn[standard]
uvicorn app.main:app --host 127.0.0.1 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

### 7.2 TLS Handshake Inspection

Apply the display filter:
```
tls
```

You will see the TLS handshake packets:

| Packet | Description |
|--------|-------------|
| **Client Hello** | Client advertises TLS version, cipher suites, extensions (SNI, ALPN) |
| **Server Hello** | Server selects cipher suite and TLS version |
| **Certificate** | Server sends its X.509 certificate |
| **Certificate Verify** | Server proves private key ownership |
| **Finished** | Handshake complete, encrypted session established |
| **Application Data** | All subsequent packets are encrypted |

### 7.3 TLS Packet Structure (Client Hello)

Expand a **Client Hello** packet in the detail pane:

```
Transport Layer Security
  TLSv1.3 Record Layer: Handshake Protocol: Client Hello
    Handshake Protocol: Client Hello
      Version: TLS 1.2 (for compatibility)
      Random: [32 bytes]
      Session ID: [0 bytes]
      Cipher Suites (n):
        TLS_AES_128_GCM_SHA256 (0x1301)
        TLS_AES_256_GCM_SHA384 (0x1302)
        TLS_CHACHA20_POLY1305_SHA256 (0x1303)
      Extensions:
        server_name: localhost
        supported_versions: TLS 1.3, TLS 1.2
        supported_groups: x25519, secp256r1
```

### 7.4 What Wireshark CAN See with TLS Enabled

| Observable | Details |
|-----------|---------|
| IP source/destination | 127.0.0.1 ↔ 127.0.0.1 |
| TCP port | Destination port 8443 or 443 |
| TLS version negotiated | TLS 1.3 |
| Cipher suite selected | e.g., TLS_AES_256_GCM_SHA384 |
| SNI (Server Name Indication) | The hostname in Client Hello (plaintext extension) |
| Certificate details | Subject, issuer, validity, SANs |
| Packet sizes and timing | Traffic metadata (useful for traffic analysis) |
| Number of requests | Approximate, based on TLS record boundaries |

### 7.5 What Wireshark CANNOT See with TLS Enabled

| Hidden data | Why |
|------------|-----|
| HTTP method (GET, POST) | Encrypted in Application Data record |
| URL path (`/api/v1/auth/login`) | Encrypted after TLS handshake |
| Request headers | Encrypted, including Authorization |
| JWT Bearer tokens | Encrypted |
| Request body / JSON payload | Encrypted |
| Response status code | Encrypted |
| Response body | Encrypted |
| Passwords submitted | Encrypted |

> **Conclusion:** TLS encryption renders all application-layer data opaque to a network observer. An attacker on the network path can determine that *some* HTTPS traffic occurred (and roughly how much, based on packet sizes), but cannot read credentials, tokens, or any HTTP content.

### 7.6 TLS Session Key Logging (Advanced — Debug Only)

Modern TLS clients can export session keys for Wireshark decryption in a local debug environment. This is NOT possible in production without access to the client machine.

```powershell
# Set SSLKEYLOGFILE environment variable before starting the client
$env:SSLKEYLOGFILE = "C:\temp\tls_keys.log"
curl https://localhost:8443/api/v1/security/health --insecure
```

Then configure Wireshark:
1. Edit → Preferences → Protocols → TLS
2. Set "(Pre)-Master-Secret log filename" to `C:\temp\tls_keys.log`
3. TLS traffic will now be decrypted in Wireshark (locally only)

> **⚠️ Warning:** This is a debug technique only. Never deploy SSLKEYLOGFILE in production. The session key log file must be protected and deleted after use.

---

## 8. Sensitive Information Exposure Analysis

### 8.1 What Should Never Appear in HTTP Traffic

| Sensitive data | Risk if exposed | Status in SecureAPI Sentinel |
|----------------|----------------|------------------------------|
| Plaintext passwords | Credential theft | ✅ Hashed with Argon2id; not returned in any response |
| JWT tokens (over HTTP) | Session hijacking | ⚠️ Visible in HTTP; hidden in HTTPS |
| Password hashes | Offline cracking | ✅ Never returned in API responses |
| MFA secrets | TOTP compromise | ✅ AES-256 encrypted at rest; never returned in API |
| Database credentials | Backend access | ✅ Only in `.env` (server-side) |
| Stack traces | Information disclosure | ✅ Global exception handler returns generic errors |
| Internal IP/server info | Reconnaissance | ✅ Server header stripped by security middleware |
| Refresh tokens (over HTTP) | Token theft | ⚠️ Visible in HTTP body; hidden in HTTPS |

### 8.2 Information Disclosure Check

Apply this Wireshark display filter to find error responses:

```
http.response.code >= 400
```

Inspect each error response body. Acceptable responses:

```json
{"detail": "Invalid credentials"}
{"detail": "Access forbidden"}
{"detail": "Not Found"}
```

Unacceptable responses (should never appear):

```json
{"detail": "sqlalchemy.exc.OperationalError: ..."}
{"traceback": "File '/app/api/v1/auth.py', line 42..."}
{"error": "password_hash: $argon2id$v=19$m=65536..."}
```

---

## 9. Rate Limiting Traffic Demonstration

Generate rapid requests to trigger rate limiting:

```powershell
# Powershell loop — 15 rapid POST requests to auth endpoint
1..15 | ForEach-Object {
    curl -X POST http://127.0.0.1:8000/api/v1/auth/login `
      -H "Content-Type: application/json" `
      -d '{"email":"test@example.com","password":"wrong"}' `
      -s -o NUL -w "%{http_code}\n"
}
```

In Wireshark, observe:
- Requests 1-10: HTTP 401 responses
- Requests 11+: HTTP 429 responses with `Retry-After` header

Display filter to isolate rate-limit responses:

```
http.response.code == 429
```

---

## 10. Recommended Wireshark Filters for API Security Testing

| Scenario | Display Filter |
|----------|---------------|
| All HTTP traffic | `http` |
| POST requests only | `http.request.method == "POST"` |
| Authentication traffic | `http and (tcp.port == 8000)` |
| Error responses | `http.response.code >= 400` |
| Rate limit responses | `http.response.code == 429` |
| Requests with Authorization header | `http.authorization` |
| TLS handshakes | `tls.handshake` |
| All TLS traffic | `tls` |
| Specific host | `ip.addr == 127.0.0.1` |
| JSON content type | `http.content_type contains "json"` |

---

## 11. Key Findings and Takeaways

### 11.1 HTTP (Plaintext) Risks Demonstrated

1. **Credentials in transit:** POST body (email, password) is fully readable in every authentication request
2. **Token exposure:** JWT access and refresh tokens visible in response bodies and Authorization headers
3. **Session hijacking potential:** An attacker capturing a JWT can replay it until expiry (15 minutes for access tokens)
4. **Traffic metadata:** Even without reading content, timing and size patterns can reveal user activity

### 11.2 HTTPS Mitigations

1. **End-to-end encryption:** All HTTP payload data encrypted; passwords and tokens hidden from network observers
2. **Certificate validation:** Prevents man-in-the-middle attacks (attacker cannot decrypt without the private key)
3. **TLS 1.3:** Modern cipher suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy
4. **Residual metadata:** SNI hostname and packet timing remain visible even with HTTPS

### 11.3 Application-Level Controls Observed

The following controls were verified visible in HTTP responses:

- ✅ Security headers present (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`)
- ✅ No `Server` header exposed (stripped by middleware)
- ✅ No `X-Powered-By` header
- ✅ Generic error messages (no stack traces)
- ✅ `X-Request-ID` for request tracing
- ✅ `Retry-After` header on 429 rate-limit responses

---

## 12. Remediation Recommendations

| Finding | Severity | Recommendation |
|---------|----------|----------------|
| Passwords visible over HTTP | Critical | Deploy TLS 1.3 at reverse proxy; enforce HTTPS redirect |
| JWT tokens visible over HTTP | High | Same as above; also implement short token expiry (implemented: 15 min) |
| Token interception window | Medium | Short access token TTL (implemented); consider refresh token rotation (implemented) |
| SNI hostname visible in TLS | Informational | No practical mitigation; acceptable for most deployments |

---

## 13. Conclusion

This analysis demonstrates the critical difference between HTTP and HTTPS:

- **HTTP (port 8000):** All traffic is visible. Passwords, tokens, and payloads are readable by any network observer with packet capture capability.
- **HTTPS (TLS 1.3):** All application data is encrypted. Network observers see only metadata (IP addresses, packet sizes, timing, SNI hostname).

For the SecureAPI Sentinel application, the following network security posture is recommended for a production deployment:

1. All traffic must be served over HTTPS with TLS 1.3
2. HTTP requests must redirect to HTTPS (301 Permanent Redirect)
3. HSTS must be enforced (`Strict-Transport-Security: max-age=31536000; includeSubDomains`)
4. Certificates must be from a trusted CA (Let's Encrypt recommended for development)
5. TLS cipher suites should be limited to AEAD ciphers (AES-GCM, ChaCha20-Poly1305)

The application already implements `Strict-Transport-Security` in its security headers middleware, which is the correct posture assuming TLS is enforced by the reverse proxy.

---

*Analysis prepared by: Agent 4 — Application Security Engineer*  
*Authorized scope: localhost:8000 test environment only*  
*No production traffic was captured or analyzed*
