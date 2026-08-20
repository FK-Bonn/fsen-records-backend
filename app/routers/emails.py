import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from starlette.responses import JSONResponse
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from app.database import EmailTemplate, SessionDep, User
from app.emails import EmailsDep, EmailTemplateData, EmailTemplateDataWithMeta, QueuedEmailMessage, SentEmailMessage
from app.routers.users import admin_only, get_current_user
from app.util import to_json, ts

router = APIRouter()
logger = logging.getLogger(__name__)



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
async def email_state(emails: EmailsDep):
    send_mails_last_run = emails.get_send_mails_last_run()
    one_hour_ago = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    status = HTTP_200_OK if send_mails_last_run > one_hour_ago.isoformat() else HTTP_500_INTERNAL_SERVER_ERROR
    return JSONResponse({"send-mails-last-run": send_mails_last_run}, status_code=status)


@router.get("/queues", dependencies=[Depends(admin_only)], response_model=EmailQueues)
async def email_queues(emails: EmailsDep):
    outbox = emails.get_outbox()
    sent = emails.get_sent()
    return EmailQueues(outbox=outbox, sent=sent)
