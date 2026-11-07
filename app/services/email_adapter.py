from typing import List, Dict, Any
from app.core.logging import logger


class DevelopmentEmailAdapter:
    """
    Development & Testing email adapter.
    Captures sent emails in an internal ring-buffer for automated test assertions
    and local verification, preventing accidental leakage to external relays.
    """
    def __init__(self):
        self.outbox: List[Dict[str, Any]] = []

    async def send_email(self, to_email: str, subject: str, body: str) -> bool:
        message = {
            "to": to_email,
            "subject": subject,
            "body": body,
        }
        self.outbox.append(message)
        logger.info(
            f"[EMAIL ADAPTER] Dispatched email to {to_email} with subject: '{subject}'"
        )
        return True

    def clear(self):
        self.outbox.clear()

    def get_last_email_for(self, email: str) -> Dict[str, Any] | None:
        for msg in reversed(self.outbox):
            if msg["to"] == email:
                return msg
        return None


email_adapter = DevelopmentEmailAdapter()
