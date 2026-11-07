from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status
from app.core.config import settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Guards against HTTP payload bombs and memory exhaustion attacks (Denial of Service).
    Rejects any request body exceeding configured maximum size (default 10 MB).
    """
    def __init__(self, app, max_size_bytes: int = settings.MAX_REQUEST_SIZE_BYTES):
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_size_bytes:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "error": "Payload Too Large",
                            "detail": f"Request body exceeds maximum allowed size of {self.max_size_bytes} bytes."
                        }
                    )
            except ValueError:
                pass

        return await call_next(request)
