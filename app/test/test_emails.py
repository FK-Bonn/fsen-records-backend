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
    result = client.get("/api/v1/emails/", headers=get_auth_header(client, ADMIN))
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
    result = client.get("/api/v1/emails/", headers=get_auth_header(client, ADMIN))
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
    result = client.get("/api/v1/emails/", headers=get_auth_header(client, user))
    assert result.status_code == 401
    assert (
        result.json() == {"detail": "Not authenticated"} if user is None else {"detail": "This requires admin rights"}
    )


def create_email_template(id_: str, **kwargs: str):
    data = {**DEFAULT_EMAIL_TEMPLATE, "template_id": id_, **kwargs}
    result = client.post("/api/v1/emails/save", json=data, headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
