import json
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from starlette.responses import JSONResponse
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from app.config import Config
from app.database import EmailTemplate, SessionDep, User
from app.routers.users import admin_only, get_current_user
from app.util import to_json, ts

router = APIRouter()
logger = logging.getLogger(__name__)


class FrequencyEnum(str, Enum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class MonthDay(BaseModel):
    month: int
    day: int


class EmailTemplateMeta(BaseModel):
    fixed_dates: None | list[MonthDay]
    days_before: None | int
    frequency: None | FrequencyEnum
    targets: list[str]


class EmailTemplateData(BaseModel):
    template_id: str
    meta: EmailTemplateMeta
    subject: str
    body: str


class EmailTemplateDataWithMeta(EmailTemplateData):
    last_modified_timestamp: str
    last_modified_by: str


class QueuedEmailMessage(BaseModel):
    to: list[str]
    subject: str
    body: str
    template_id: str
    created: str
    not_before: str | None = None


class SentEmailMessage(QueuedEmailMessage):
    sent: str


class EmailQueues(BaseModel):
    outbox: list[QueuedEmailMessage]
    sent: list[SentEmailMessage]


@router.get("", dependencies=[Depends(admin_only)], response_model=list[EmailTemplateDataWithMeta])
async def list_email_templates(session: SessionDep):
    subquery = (
        session.query(EmailTemplate.template_id, func.max(EmailTemplate.id).label("id"))
        .group_by(EmailTemplate.template_id)
        .subquery()
    )
    data = (
        session.query(EmailTemplate)
        .join(subquery, EmailTemplate.id == subquery.c.id)
        .order_by(EmailTemplate.template_id)
        .all()
    )
    return [
        EmailTemplateDataWithMeta(
            meta=json.loads(item.meta),
            template_id=item.template_id,
            subject=item.subject,
            body=item.body,
            last_modified_by=item.last_modified_by,
            last_modified_timestamp=item.last_modified_timestamp,
        )
        for item in data
    ]


@router.post("/save", dependencies=[Depends(admin_only)])
async def save_email_template(
    data: EmailTemplateData, session: SessionDep, current_user: User = Depends(get_current_user())
):
    logger.info(f"save_email_template({data=}, {current_user.username=})")
    now = ts()
    email_template = EmailTemplate()
    email_template.template_id = data.template_id
    email_template.meta = to_json(data.meta)
    email_template.subject = data.subject
    email_template.body = data.body
    email_template.last_modified_timestamp = now
    email_template.last_modified_by = current_user.username
    session.add(email_template)
    session.commit()


@router.get("/state")
async def email_state():
    send_mails_last_run = "1970-01-01T00:00:00+00:00"
    status = HTTP_500_INTERNAL_SERVER_ERROR
    send_mails_last_run_file = get_base_dir() / "send-mails-last-run"
    if send_mails_last_run_file.is_file():
        send_mails_last_run = send_mails_last_run_file.read_text()
    one_hour_ago = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    if send_mails_last_run > one_hour_ago.isoformat():
        status = HTTP_200_OK
    return JSONResponse({"send-mails-last-run": send_mails_last_run}, status_code=status)


@router.get("/queues", dependencies=[Depends(admin_only)], response_model=EmailQueues)
async def email_queues():
    base_dir = get_base_dir()
    outbox_dir = base_dir / "outbox"
    sent_dir = base_dir / "sent"
    outbox = [json.loads(f.read_text()) for f in outbox_dir.glob("*.json")]
    sent = [json.loads(f.read_text()) for f in sent_dir.glob("*.json")]
    outbox.sort(key=lambda m: m["created"], reverse=True)
    sent.sort(key=lambda m: (m["sent"], m["created"]), reverse=True)
    return EmailQueues(outbox=outbox, sent=sent)


def get_base_dir():
    return Config.BASE_MAILS_DIR
