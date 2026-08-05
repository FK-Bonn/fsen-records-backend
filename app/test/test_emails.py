from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import ADMIN, USER_INFO_ALL, USER_INFO_READ, USER_NO_PERMS, fake_session, get_auth_header

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
def test_email_templates_index_as_other_user(user):
    create_email_template(id_="deadbeef", text="Informatik")
    result = client.get("/api/v1/emails", headers=get_auth_header(client, user))
    assert result.status_code == 401
    assert (
        result.json() == {"detail": "Not authenticated"} if user is None else {"detail": "This requires admin rights"}
    )


@mock.patch("app.routers.emails.get_base_dir", return_value=Path(TemporaryDirectory().name))
def test_email_state_no_run_file_error(mocked_base_dir):
    result = client.get("/api/v1/emails/state")
    assert result.status_code == 500
    assert result.json() == {"send-mails-last-run": "1970-01-01T00:00:00+00:00"}


@mock.patch("app.routers.emails.get_base_dir", return_value=Path(TemporaryDirectory().name))
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
@travel("2026-06-06T01:00:01+00:00", tick=False)
def test_email_state_error(mocked_base_dir, user):
    last_run = "2026-06-06T00:00:00+00:00"
    mocked_base_dir.return_value.mkdir(parents=True, exist_ok=True)
    (mocked_base_dir.return_value / "send-mails-last-run").write_text(last_run)
    result = client.get("/api/v1/emails/state", headers=get_auth_header(client, user))
    assert result.status_code == 500
    assert result.json() == {"send-mails-last-run": last_run}


@mock.patch("app.routers.emails.get_base_dir", return_value=Path(TemporaryDirectory().name))
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
@travel("2026-06-06T01:00:00+00:00", tick=False)
def test_email_state_ok(mocked_base_dir, user):
    last_run = "2026-06-06T00:00:00+00:00"
    mocked_base_dir.return_value.mkdir(parents=True, exist_ok=True)
    (mocked_base_dir.return_value / "send-mails-last-run").write_text(last_run)
    result = client.get("/api/v1/emails/state", headers=get_auth_header(client, user))
    assert result.status_code == 500
    assert result.json() == {"send-mails-last-run": last_run}


def create_email_template(id_: str, **kwargs: str):
    data = {**DEFAULT_EMAIL_TEMPLATE, "template_id": id_, **kwargs}
    result = client.post("/api/v1/emails/save", json=data, headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
