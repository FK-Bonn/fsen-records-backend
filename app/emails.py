import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated

from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import Config
from app.database import Annotation, BaseFsData, Document, Election, EmailTemplate, PayoutRequest, ProtectedFsData
from app.util import Now, build_filename_str


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
    meta: dict | None = None

    def __repr__(self):
        return f'{self.__repr_name__()}({self.__repr_str__(",\n")})'


class SentEmailMessage(QueuedEmailMessage):
    sent: str

class EmailManager:
    base_dir = Config.BASE_MAILS_DIR
    outbox_dir = base_dir / "outbox"
    sent_dir = base_dir / "sent"

    def get_outbox_files(self) -> dict[Path, QueuedEmailMessage]:
        outbox = {f: QueuedEmailMessage.model_validate_json(f.read_text()) for f in self.outbox_dir.glob("*.json")}
        return outbox

    def get_outbox(self) -> list[QueuedEmailMessage]:
        return sorted(self.get_outbox_files().values(), key=lambda m: m.created, reverse=True)

    def get_sent(self) -> list[SentEmailMessage]:
        sent = [SentEmailMessage.model_validate_json(f.read_text()) for f in self.sent_dir.glob("*.json")]
        sent.sort(key=lambda m: (m.sent, m.created), reverse=True)
        return sent

    def get_send_mails_last_run(self) -> str:
        send_mails_last_run = "1970-01-01T00:00:00+00:00"
        send_mails_last_run_file = self.base_dir / "send-mails-last-run"
        if send_mails_last_run_file.is_file():
            send_mails_last_run = send_mails_last_run_file.read_text()
        return send_mails_last_run

    def get_pending_outbox_mail(self, template_id: str, key: str) -> None | tuple[Path, QueuedEmailMessage]:
        now = datetime.now(tz=timezone.utc)
        cutoff = (now + timedelta(minutes=5)).isoformat()
        for filepath, mail in self.get_outbox_files().items():
            if (
                mail.template_id == template_id
                and mail.meta
                and mail.meta["key"] == key
                and mail.not_before
                and mail.not_before > cutoff
            ):
                return filepath, mail
        return None

    def upsert_election(self, key: str, current: Election, previous: Election | None, session: Session):
        template_key = "election_created" if previous is None else "election_updated"

        previous_json = election_to_json(previous)
        current_json = election_to_json(current)

        self.generic_modified_mail(
            key=key,
            template_key=template_key,
            fs_id=current.fs,
            current_json=current_json,
            previous_json=previous_json,
            additional_items={"election_id": current.election_id},
            session=session,
        )

    def generic_modified_mail(
        self,
        key: str,
        template_key: str,
        fs_id: str,
        current_json: dict,
        previous_json: dict,
        additional_items: dict,
        session: Session,
    ):
        fs_name, target_file, template, to, created, not_before = self.setup(fs_id, session, template_key)

        outbox_email = self.get_pending_outbox_mail(template_id=template.template_id, key=key)
        if outbox_email:
            filepath, mail = outbox_email
            target_file = filepath
            created = mail.created
            if mail.meta:
                previous_json = mail.meta["base"]

        diff = diff_dicts(current_json, previous_json)
        items = {"fs_name": fs_name, "diff": diff, **additional_items}
        subject, body = render(template, items)
        data = QueuedEmailMessage(
            to=to,
            subject=subject,
            body=body,
            template_id=template.template_id,
            created=created,
            not_before=None if not previous_json else not_before,
            meta={
                "key": key,
                "base": previous_json,
            },
        )
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            data.model_dump_json(
                indent=2,
            )
        )

    def setup(
        self, fs_id: str, session: Session, template_key: str
    ) -> tuple[str, Path, EmailTemplateData, list[str], str, str]:
        t = Now()
        created = t.utc.date_time
        not_before = (t.utc.value + timedelta(minutes=10)).isoformat()
        uuid_ = str(uuid.uuid4())
        target_file = self.outbox_dir / f"{t.unixtime}-{t.berlin.date}-{uuid_}.json"

        template = get_template(template_id=template_key, session=session)
        email_addresses = get_email_addresses(fs=fs_id, session=session)
        fs_name = get_fs_name(fs_id=fs_id, session=session)
        to = []
        for target in template.meta.targets:
            to.extend(email_addresses.get(target, []))
        to = sorted(set(to))
        return fs_name, target_file, template, to, created, not_before

    def payout_request_created(self, payout_request: PayoutRequest | None, session: Session):
        if payout_request is None:
            return
        template_id = "payout_request_created"
        fs_id = payout_request.fs
        fs_name, target_file, template, to, created, _ = self.setup(fs_id, session, template_id)

        as_json = payout_request_to_json(payout_request)
        request_data = list_keys_and_values(as_json)

        subject, body = render(
            template,
            {"fs_name": fs_name, "request_data": request_data, "request_id": payout_request.request_id},
        )
        data = QueuedEmailMessage(
            to=to,
            subject=subject,
            body=body,
            template_id=template.template_id,
            created=created,
            not_before=None,
            meta=None,
        )
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            data.model_dump_json(
                indent=2,
            )
        )


    def payout_request_modified(self,  current: PayoutRequest | None, previous: PayoutRequest | None, session: Session):
        if current is None or previous is None:
            return
        key = current.request_id
        template_key = "payout_request_updated"

        previous_json = payout_request_to_json(previous)
        current_json = payout_request_to_json(current)

        self.generic_modified_mail(
            key=key,
            template_key=template_key,
            fs_id=current.fs,
            current_json=current_json,
            previous_json=previous_json,
            additional_items={"request_id": current.request_id},
            session=session,
        )


    def document_uploaded(self, document: Document, session: Session):
        if document.category == "AFSG":
            return
        template_id = "document_uploaded"
        key = document.request_id
        fs_id = document.fs
        fs_name, target_file, template, to, created, not_before = self.setup(fs_id, session, template_id)

        as_json = []
        outbox_email = self.get_pending_outbox_mail(template_id=template.template_id, key=key)
        if outbox_email:
            filepath, mail = outbox_email
            target_file = filepath
            created = mail.created
            if mail.meta:
                as_json = mail.meta["base"]

        as_json.append(document_to_json(document))
        document_data = '\n\n'.join(list_keys_and_values(item) for item in as_json)

        subject, body = render(
            template,
            {"fs_name": fs_name, "document_data": document_data, "request_id": key},
        )
        data = QueuedEmailMessage(
            to=to,
            subject=subject,
            body=body,
            template_id=template.template_id,
            created=created,
            not_before=not_before,
            meta={
                "key": key,
                "base": as_json,
            },
        )
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            data.model_dump_json(
                indent=2,
            )
        )

    def document_annotated(self, current: Annotation, previous: Annotation | None, session: Session):
        template_id = "document_annotated" if previous is None else "annotation_updated"
        key = str(current.document)
        outbox_email = self.get_pending_outbox_mail(template_id="document_annotated", key=key)
        if outbox_email:
            template_id = "document_annotated"
        elif template_id != "document_annotated":
            outbox_email = self.get_pending_outbox_mail(template_id=template_id, key=key)
        document = get_document(current.document, session)
        fs_id = document.fs
        fs_name, target_file, template, to, created, not_before = self.setup(fs_id, session, template_id)

        previous_json = annotation_to_json(previous)
        current_json = annotation_to_json(current)

        if outbox_email:
            filepath, mail = outbox_email
            target_file = filepath
            created = mail.created
            if mail.meta:
                previous_json = mail.meta["base"]

        diff = diff_dicts(current_json, previous_json)
        filename = build_filename_str(
            request_id=document.request_id,
            category=document.category,
            base_name=document.base_name,
            date_start=document.date_start,
            date_end=document.date_end,
            file_extension=document.file_extension,
            sha256hash=document.sha256hash,
        )
        url_fragment = f"/payout-request/{document.request_id}" if document.request_id else f"/document/{filename}"
        subject, body = render(template, {"fs_name": fs_name, "diff": diff, "url_fragment": url_fragment})
        data = QueuedEmailMessage(
            to=to,
            subject=subject,
            body=body,
            template_id=template.template_id,
            created=created,
            not_before=not_before,
            meta={
                "key": key,
                "base": previous_json,
            },
        )
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            data.model_dump_json(
                indent=2,
            )
        )


def election_to_json(election: Election | None) -> dict:
    if election is None:
        return {}
    return {
        "election_id": election.election_id,
        "fs": election.fs,
        "committee": election.committee,
        "election_method": election.election_method,
        "first_election_day": election.first_election_day,
        "last_election_day": election.last_election_day,
        "electoral_register_request_date": election.electoral_register_request_date,
        "electoral_register_hand_out_date": election.electoral_register_hand_out_date,
        "result_url": election.result_url,
        "result_published_date": election.result_published_date,
        "scrutiny_status": election.scrutiny_status,
        "comments": election.comments,
    }


def payout_request_to_json(payout_request: PayoutRequest | None) -> dict:
    if payout_request is None:
        return {}
    return {
        "request_id": payout_request.request_id,
        "type": payout_request.type,
        "category": payout_request.category,
        "fs": payout_request.fs,
        "semester": payout_request.semester,
        "status": payout_request.status,
        "status_date": payout_request.status_date,
        "amount_cents": payout_request.amount_cents,
        "comment": payout_request.comment,
        "request_date": payout_request.request_date,
        "completion_deadline": payout_request.completion_deadline,
        "reference": payout_request.reference,
    }

def document_to_json(document: Document) -> dict:
    return {
        "fs": document.fs,
        "category": document.category,
        "request_id": document.request_id,
        "base_name": document.base_name,
        "date_start": document.date_start,
        "date_end": document.date_end,
        "file_extension": document.file_extension,
        "sha256hash": document.sha256hash,
    }

def annotation_to_json(annotation: Annotation | None) -> dict:
    if not annotation:
        return {}
    value = {
        "tags": annotation.tags,
        "url": annotation.url,
    }
    if annotation.references:
        for i, reference in enumerate(json.loads(annotation.references)):
            value[f"reference_{i}"] = json.dumps(reference)
    else:
        value["references"] = None
    if annotation.annotations:
        for i, annotation_item in enumerate(json.loads(annotation.annotations)):
            value[f"annotation_{i}"] = f"{annotation_item['level']}: {annotation_item['text']}"
    else:
        value["annotations"] = None
    return value


def diff_dicts(current: dict, previous: dict) -> str:
    value = ""
    if not previous:
        value = list_keys_and_values(current)
    else:
        for key, current_value in sorted(current.items()):
            previous_value = previous.get(key, None)
            if previous_value == "":
                previous_value = "–"
            if current_value == "":
                current_value = "–"
            if previous_value != current_value:
                value += f"{key}: {previous_value} → {current_value}\n"
        for key, previous_value in sorted(previous.items()):
            if key not in current:
                value += f"{key}: {previous_value} → {None}\n"
    if not value:
        return "Keine Änderungen"
    return value

def list_keys_and_values(item: dict) -> str:
    value = ""
    for key, current_value in sorted(item.items()):
        if current_value == "":
            current_value = "–"
        value += f"{key}: {current_value}\n"
    return value

def get_template(template_id: str, session: Session) -> EmailTemplateData:
    subquery = (
        session.query(EmailTemplate.template_id, func.max(EmailTemplate.id).label("id"))
        .group_by(EmailTemplate.template_id)
        .subquery()
    )
    item = (
        session.query(EmailTemplate)
        .join(subquery, EmailTemplate.id == subquery.c.id)
        .where(EmailTemplate.template_id == template_id)
        .first()
    )
    if item:
        return EmailTemplateData(
            meta=EmailTemplateMeta.model_validate_json(item.meta),
            template_id=item.template_id,
            subject=item.subject,
            body=item.body,
        )
    return EmailTemplateData(
        meta=EmailTemplateMeta(fixed_dates=None, days_before=None, frequency=None, targets=["fsk"]),
        template_id=template_id,
        subject=f"Fehlendes E-Mail-Template: {template_id}",
        body="kwt",
    )


def get_email_addresses(fs: str, session: Session) -> dict:
    subquery = (
        session.query(func.max(ProtectedFsData.id).label("id"))
        .where(ProtectedFsData.fs == fs, ProtectedFsData.approved.is_(True))
        .subquery()
    )
    data = session.query(ProtectedFsData).filter(ProtectedFsData.id == subquery.c.id).first()
    result = defaultdict(list)
    result["fsk"].append(Config.FSK_EMAIL_ADDRESS)
    if not data:
        return dict(result)
    content = json.loads(data.data)
    for item in content["email_addresses"]:
        for usage in item["usages"]:
            result[usage].append(item["address"])
    return dict(result)


def get_fs_name(fs_id: str, session: Session) -> str:
    subquery = (
        session.query(func.max(BaseFsData.id).label("id"))
        .where(BaseFsData.fs == fs_id, BaseFsData.approved.is_(True))
        .subquery()
    )
    data = session.query(BaseFsData).filter(BaseFsData.id == subquery.c.id).first()
    if not data:
        return fs_id
    content = json.loads(data.data)
    return content.get("name", fs_id)

def get_document(document_id: int, session: Session) -> Document:
    document = session.get(Document, document_id)
    assert document
    return document


def render(template: EmailTemplateData, items: dict) -> tuple[str, str]:
    subject = template.subject.format(**items)
    body = template.body.format(**items)
    return subject, body

def get_email_manager():
    yield EmailManager()


EmailsDep = Annotated[EmailManager, Depends(get_email_manager)]
