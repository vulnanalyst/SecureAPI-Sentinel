import uuid
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from app.core.logging import logger


class AuditCorrelationMiddleware(BaseHTTPMiddleware):
    """
    Injects distributed correlation ID (X-Request-ID) and instruments
    request latency and contextual metadata.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")

        request.state.request_id = request_id
        request.state.client_ip = client_ip
        request.state.user_agent = user_agent

        start_time = time.perf_counter()
        response: Response = await call_next(request)
        process_time_ms = (time.perf_counter() - start_time) * 1000

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = f"{process_time_ms:.2f}"

        logger.info(
            f"{request.method} {request.url.path} responded {response.status_code} in {process_time_ms:.2f}ms",
            extra={
                "request_id": request_id,
                "client_ip": client_ip,
                "user_agent": user_agent,
            }
        )

        return response

