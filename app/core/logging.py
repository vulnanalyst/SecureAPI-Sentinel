import logging
import json
import sys
from typing import Any, Dict
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Structured JSON log formatter for production and SIEM ingestion.
    Automatically scrubs sensitive fields (passwords, tokens, keys)
    to prevent accidental credential disclosure.
    """
    SENSITIVE_KEYS = {
        "password", "hashed_password", "token", "access_token",
        "refresh_token", "secret", "secret_key", "authorization",
        "cookie", "secret_enc", "backup_codes"
    }

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func_name": record.funcName,
            "line_no": record.lineno,
        }

        # Include contextual extras if present
        if hasattr(record, "client_ip"):
            log_obj["client_ip"] = record.client_ip
        if hasattr(record, "request_id"):
            log_obj["request_id"] = record.request_id
        if hasattr(record, "user_id"):
            log_obj["user_id"] = record.user_id
        if hasattr(record, "security_event"):
            log_obj["security_event"] = record.security_event

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(self._scrub_sensitive(log_obj))

    def _scrub_sensitive(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k: ("[REDACTED]" if k.lower() in self.SENSITIVE_KEYS else self._scrub_sensitive(v))
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self._scrub_sensitive(item) for item in data]
        return data


def setup_logger(name: str = "sentinel") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


logger = setup_logger()

