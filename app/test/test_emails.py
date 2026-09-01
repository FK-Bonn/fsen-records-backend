import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import (
    ADMIN,
    USER_INFO_ALL,
    USER_INFO_READ,
    USER_NO_PERMS,
    fake_session,
    get_auth_header,
)

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session

DEFAULT_EMAIL_TEMPLATE = {
    "template_id": "deadbeef",
    "meta": {
        "targets": ["finanzen"],
        "fixed_dates": [
            {"month": 3, "day": 31},
            {"month": 9, "day": 30},
        ],
        "frequency": None,
        "days_before": None,
    },
    "subject": "subject content",
    "body": "body content",
}


def test_save_email_template_as_admin():
    result = client.post("/api/v1/emails/save", json=DEFAULT_EMAIL_TEMPLATE, headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200


@pytest.mark.parametrize(
    "user",
    [
        None,
        USER_NO_PERMS,
        USER_INFO_READ,
        USER_INFO_ALL,
    ],
)
def test_save_email_as_other_user(user):
    result = client.post("/api/v1/emails/save", json=DEFAULT_EMAIL_TEMPLATE, headers=get_auth_header(client, user))
    assert result.status_code == 401
    result = client.get("/api/v1/emails", headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.json() == []


def test_email_templates_index_as_admin():
    with travel("2025-10-03T10:00:00Z", tick=False):
        create_email_template(id_="deadbeef", body="Informatik")
    with travel("2025-10-03T11:00:00Z", tick=False):
        create_email_template(id_="bedbedbe", body="Agrarwissenschaft")
    with travel("2025-10-03T12:00:00Z", tick=False):
        create_email_template(id_="01234567", body="Geographie")
    with travel("2025-10-03T13:00:00Z", tick=False):
        create_email_template(id_="01234567", body="Geographie")
    result = client.get("/api/v1/emails", headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.json() == [
        {
            **DEFAULT_EMAIL_TEMPLATE,
            "template_id": "01234567",
            "body": "Geographie",
            "last_modified_by": ADMIN,
            "last_modified_timestamp": "2025-10-03T13:00:00+00:00",
        },
        {
            **DEFAULT_EMAIL_TEMPLATE,
            "template_id": "bedbedbe",
            "body": "Agrarwissenschaft",
            "last_modified_by": ADMIN,
            "last_modified_timestamp": "2025-10-03T11:00:00+00:00",
        },
        {
            **DEFAULT_EMAIL_TEMPLATE,
            "template_id": "deadbeef",
            "body": "Informatik",
            "last_modified_by": ADMIN,
            "last_modified_timestamp": "2025-10-03T10:00:00+00:00",
        },
    ]


@pytest.mark.parametrize(
    "user",
    [
        None,
        USER_NO_PERMS,
        USER_INFO_READ,
        USER_INFO_ALL,
    ],
)
def test_email_templates_index_as_other_user(user, fake_email_manager):
    create_email_template(id_="deadbeef", text="Informatik")
    result = client.get("/api/v1/emails", headers=get_auth_header(client, user))
    assert result.status_code == 401
    assert (
        result.json() == {"detail": "Not authenticated"} if user is None else {"detail": "This requires admin rights"}
    )


def test_email_state_no_run_file_error(fake_email_manager):
    result = client.get("/api/v1/emails/state")
    assert result.status_code == 500
    assert result.json() == {
        "send-mails-last-run": "1970-01-01T00:00:00+00:00",
        "create-daily-mails-last-run": "1970-01-01T00:00:00+00:00",
    }


@pytest.mark.parametrize(
    "user",
    [
        None,
        USER_NO_PERMS,
        USER_INFO_READ,
        USER_INFO_ALL,
        ADMIN,
    ],
)
@pytest.mark.parametrize(
    "send_mails,create_daily_mails,status",
    [
        ["2026-06-06T00:00:00+00:00", "2026-06-05T00:00:00+00:00", 500],
        ["2026-06-06T01:00:00+00:00", "2026-06-05T00:00:00+00:00", 500],
        ["2026-06-06T00:00:00+00:00", "2026-06-05T01:00:00+00:00", 500],
        ["2026-06-06T01:00:00+00:00", "2026-06-05T01:00:00+00:00", 200],
    ],
)
@travel("2026-06-06T01:00:01+00:00", tick=False)
def test_email_state_error(user, send_mails, create_daily_mails, status, fake_email_manager):
    (fake_email_manager.base_dir / "send-mails-last-run").write_text(send_mails)
    (fake_email_manager.base_dir / "create-daily-mails-last-run").write_text(create_daily_mails)
    result = client.get("/api/v1/emails/state", headers=get_auth_header(client, user))
    assert result.status_code == status
    assert result.json() == {"send-mails-last-run": send_mails, "create-daily-mails-last-run": create_daily_mails}


def test_email_queues_as_admin_empty(fake_email_manager):
    result = client.get("/api/v1/emails/queues", headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.json() == {"outbox": [], "sent": []}


def test_email_queues_as_admin(fake_email_manager):
    result_json = create_mail_files(fake_email_manager.base_dir)
    for sublist in result_json.values():
        for item in sublist:
            item["not_before"] = item.get("not_before", None)
            item["meta"] = item.get("meta", None)
    result = client.get("/api/v1/emails/queues", headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.json() == result_json


@pytest.mark.parametrize(
    "user",
    [
        None,
        USER_NO_PERMS,
        USER_INFO_READ,
        USER_INFO_ALL,
    ],
)
def test_email_queues_other_users_no_access(user, fake_email_manager):
    create_mail_files(fake_email_manager.base_dir)
    result = client.get("/api/v1/emails/queues", headers=get_auth_header(client, user))
    assert result.status_code == 401
    assert result.json() == {"detail": "Not authenticated" if user is None else "This requires admin rights"}


def create_mail_files(base_dir: Path) -> dict:
    outbox = base_dir / "outbox"
    sent = base_dir / "sent"
    outbox.mkdir(parents=True, exist_ok=True)
    sent.mkdir(parents=True, exist_ok=True)
    outbox_0 = {
        "to": ["test@example.org"],
        "subject": "subject 0000",
        "body": "body 0000",
        "template_id": "template_id_0",
        "created": "2026-08-02T11:11:11+00:00",
        "not_before": "2026-08-02T12:12:12+00:00",
    }
    (outbox / "2026-08-02-deadbeef-1337-1337-0000-deadbeef.json").write_text(json.dumps(outbox_0, indent=2))
    outbox_1 = {
        "to": ["test@example.org"],
        "subject": "subject 0001",
        "body": "body 0001",
        "template_id": "template_id_1",
        "created": "2026-08-02T11:11:12+00:00",
    }
    (outbox / "2026-08-02-deadbeef-1337-1337-0001-deadbeef.json").write_text(json.dumps(outbox_1, indent=2))
    sent_0 = {
        "to": ["test@example.org"],
        "subject": "subject 1000",
        "body": "body 1000",
        "template_id": "template_id_0",
        "created": "2026-08-02T10:10:10+00:00",
        "not_before": "2026-08-02T10:20:10+00:00",
        "sent": "2026-08-02T10:33:33+00:00",
    }
    (sent / "2026-08-02-deadbeef-1337-1337-1000-deadbeef.json").write_text(json.dumps(sent_0, indent=2))
    sent_1 = {
        "to": ["test@example.org"],
        "subject": "subject 1001",
        "body": "body 1001",
        "template_id": "template_id_1",
        "created": "2026-08-02T10:10:10+00:00",
        "sent": "2026-08-02T10:33:34+00:00",
    }
    (sent / "2026-08-02-deadbeef-1337-1337-1001-deadbeef.json").write_text(json.dumps(sent_1, indent=2))
    return {
        "outbox": [outbox_1, outbox_0],
        "sent": [sent_1, sent_0],
    }


def create_email_template(id_: str, **kwargs: str):
    data = {**DEFAULT_EMAIL_TEMPLATE, "template_id": id_, **kwargs}
    result = client.post("/api/v1/emails/save", json=data, headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
