import json
from typing import Annotated

from fastapi import Depends
from pydantic import BaseModel

from app.config import Config


class QueuedEmailMessage(BaseModel):
    to: list[str]
    subject: str
    body: str
    template_id: str
    created: str
    not_before: str | None = None


class SentEmailMessage(QueuedEmailMessage):
    sent: str

class EmailManager:
    base_dir = Config.BASE_MAILS_DIR
    outbox_dir = base_dir / "outbox"
    sent_dir = base_dir / "sent"

    def get_outbox(self) -> list[QueuedEmailMessage]:
        outbox = [json.loads(f.read_text()) for f in self.outbox_dir.glob("*.json")]
        outbox.sort(key=lambda m: m["created"], reverse=True)
        return outbox

    def get_sent(self) -> list[SentEmailMessage]:
        sent = [json.loads(f.read_text()) for f in self.sent_dir.glob("*.json")]
        sent.sort(key=lambda m: (m["sent"], m["created"]), reverse=True)
        return sent

    def get_send_mails_last_run(self) -> str:
        send_mails_last_run = "1970-01-01T00:00:00+00:00"
        send_mails_last_run_file = self.base_dir / "send-mails-last-run"
        if send_mails_last_run_file.is_file():
            send_mails_last_run = send_mails_last_run_file.read_text()
        return send_mails_last_run


def get_email_manager():
    yield EmailManager()


EmailsDep = Annotated[EmailManager, Depends(get_email_manager)]
