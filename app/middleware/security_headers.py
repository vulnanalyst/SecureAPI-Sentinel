from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Enforces hardening headers according to OWASP Secure Headers guidelines.
    Strips information-disclosing headers (Server, X-Powered-By).
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # Defense-in-depth security headers
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "X-XSS-Protection": "0",  # Modern standard disables legacy buggy audit mode in favor of CSP
        }

        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value

        # Scrub identifying headers
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]

        return response
