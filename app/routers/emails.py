import json
import logging
from enum import Enum

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func

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


@router.get("/", dependencies=[Depends(admin_only)], response_model=list[EmailTemplateDataWithMeta])
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
    return [EmailTemplateDataWithMeta(meta=json.loads(item.meta),
                                           template_id=item.template_id,
                                           subject=item.subject,
                                           body=item.body,
                                           last_modified_by=item.last_modified_by,
                                           last_modified_timestamp=item.last_modified_timestamp) for item in data]


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
