import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.emails import QueuedEmailMessage
from app.main import app, subapp
from app.test.conftest import ADMIN, USER_INFO_ALL, USER_INFO_READ, USER_NO_PERMS, fake_session, get_auth_header

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session

DEFAULT_ELECTION = {
    'election_id': 'deadbeef',
    'fs': 'Informatik',
    'committee': 'FSR',
    'election_method': 'Urnenwahl',
    'first_election_day': '2025-11-11',
    'last_election_day': '2025-11-14',
    'electoral_register_request_date': '',
    'electoral_register_hand_out_date': '',
    'result_url': '',
    'result_published_date': '',
    'scrutiny_status': '',
    'comments': '',
}


def test_save_election_as_admin(fake_email_manager):
    setup_templates_and_data()
    result = client.post('/api/v1/elections/save',
                         json=DEFAULT_ELECTION,
                         headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200


@pytest.mark.parametrize('user', [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_save_election_as_other_user(user):
    result = client.post('/api/v1/elections/save',
                         json=DEFAULT_ELECTION,
                         headers=get_auth_header(client, user))
    assert result.status_code == 401
    result = client.get('/api/v1/elections/', headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.json() == []


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_elections_index(user, fake_email_manager):
    setup_templates_and_data()
    create_election(id_='deadbeef', fs='Informatik')
    create_election(id_='bedbedbe', fs='Agrarwissenschaft', first_election_day='2025-11-12')
    create_election(id_='01234567', fs='Geographie', first_election_day='2025-11-11')
    create_election(id_='01234567', fs='Geographie', first_election_day='2025-11-12')
    result = client.get('/api/v1/elections/', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == [
        {**DEFAULT_ELECTION, 'election_id': 'bedbedbe', 'fs': 'Agrarwissenschaft', 'first_election_day': '2025-11-12'},
        {**DEFAULT_ELECTION, 'election_id': '01234567', 'fs': 'Geographie', 'first_election_day': '2025-11-12'},
        {**DEFAULT_ELECTION, 'election_id': 'deadbeef', 'fs': 'Informatik', 'first_election_day': '2025-11-11'},
    ]


def test_get_history_as_admin(fake_email_manager):
    setup_templates_and_data()
    election_id = 'deadbeef'

    with travel("2025-10-03T10:00:00Z", tick=False):
        create_election(id_=election_id, fs='Geographie', first_election_day='2025-11-12')
    with travel("2025-10-03T11:00:00Z", tick=False):
        create_election(id_=election_id, fs='Geographie')
    with travel("2025-10-03T12:00:00Z", tick=False):
        create_election(id_='a0a0a0a0', fs='Geographie')
    with travel("2025-10-03T13:00:00Z", tick=False):
        create_election(id_=election_id, fs='Geographie', result_url='https://example.org/res')
    result = client.get(f'/api/v1/elections/{election_id}/history',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.json() == [
        {**DEFAULT_ELECTION, 'election_id': election_id, 'fs': 'Geographie', 'result_url': 'https://example.org/res',
         'last_modified_timestamp': '2025-10-03T13:00:00+00:00', 'last_modified_by': ADMIN},
        {**DEFAULT_ELECTION, 'election_id': election_id, 'fs': 'Geographie',
         'last_modified_timestamp': '2025-10-03T11:00:00+00:00', 'last_modified_by': ADMIN},
        {**DEFAULT_ELECTION, 'election_id': election_id, 'fs': 'Geographie', 'first_election_day': '2025-11-12',
         'last_modified_timestamp': '2025-10-03T10:00:00+00:00', 'last_modified_by': ADMIN},
    ]


def test_get_history_unauthenticated():
    election_id = 'deadbeef'
    result = client.get(f'/api/v1/elections/{election_id}/history',
                        headers={})
    assert result.status_code == 401
    assert result.json() == {'detail': 'Not authenticated'}


def test_get_empty_history():
    election_id = 'deadbeef'
    result = client.get(f'/api/v1/elections/{election_id}/history',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 404
    assert result.json() == {'detail': 'Election not found'}


@pytest.mark.parametrize('user', [
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_get_history_as_other_user(user):
    election_id = 'deadbeef'
    result = client.get(f'/api/v1/elections/{election_id}/history',
                        headers=get_auth_header(client, user))
    assert result.status_code == 401
    assert result.json() == {'detail': 'This requires admin rights'}


def test_save_election_creates_email(fake_email_manager):
    setup_templates_and_data()
    with travel("2026-06-06T10:00:00Z", tick=False):
        result = client.post("/api/v1/elections/save", json=DEFAULT_ELECTION, headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert fake_email_manager.get_outbox() == [
        QueuedEmailMessage(
            to=["informatik@example.org"],
            subject="election_created subject content",
            body="""election_created body content
Infor Matik
election_id: deadbeef
fs: Informatik
committee: FSR
election_method: Urnenwahl
first_election_day: 2025-11-11
last_election_day: 2025-11-14
electoral_register_request_date: –
electoral_register_hand_out_date: –
result_url: –
result_published_date: –
scrutiny_status: –
comments: –

https://example.org/wahltermine/deadbeef""",
            template_id="election_created",
            created="2026-06-06T10:00:00+00:00",
            not_before=None,
            meta={
                "key": "deadbeef",
                "base": None,
            },
        ),
    ]


def test_save_election_again_within_five_minutes_updates_email(fake_email_manager):
    setup_templates_and_data()
    with travel("2026-01-01:00:00Z", tick=False):
        result = client.post("/api/v1/elections/save", json=DEFAULT_ELECTION, headers=get_auth_header(client, ADMIN))
    fake_email_manager.clear()

    with travel("2026-06-06T10:00:00Z", tick=False):
        result = client.post(
            "/api/v1/elections/save",
            json={**DEFAULT_ELECTION, "result_url": "wrong_result_url"},
            headers=get_auth_header(client, ADMIN),
        )
    with travel("2026-06-06T10:04:59Z", tick=False):
        result = client.post(
            "/api/v1/elections/save",
            json={**DEFAULT_ELECTION, "result_url": "correct_result_url"},
            headers=get_auth_header(client, ADMIN),
        )
    assert result.status_code == 200
    assert fake_email_manager.get_outbox() == [
        QueuedEmailMessage(
            to=["informatik@example.org"],
            subject="election_updated subject content",
            body="election_updated body content\nInfor Matik\nresult_url: – → correct_result_url\n\nhttps://example.org/wahltermine/deadbeef",
            template_id="election_updated",
            created="2026-06-06T10:00:00+00:00",
            not_before="2026-06-06T10:14:59+00:00",
            meta={
                "key": "deadbeef",
                "base": DEFAULT_ELECTION,
            },
        ),
    ]


def test_save_election_again_after_five_minutes_creates_new_email(fake_email_manager):
    setup_templates_and_data()
    with travel("2026-01-01T10:00:00Z", tick=False):
        result = client.post("/api/v1/elections/save", json=DEFAULT_ELECTION, headers=get_auth_header(client, ADMIN))
    fake_email_manager.clear()

    with travel("2026-06-06T10:00:00Z", tick=False):
        result = client.post(
            "/api/v1/elections/save",
            json={**DEFAULT_ELECTION, "result_url": "wrong_result_url"},
            headers=get_auth_header(client, ADMIN),
        )
    with travel("2026-06-06T10:05:00Z", tick=False):
        result = client.post(
            "/api/v1/elections/save",
            json={**DEFAULT_ELECTION, "result_url": "correct_result_url"},
            headers=get_auth_header(client, ADMIN),
        )
    assert result.status_code == 200
    assert fake_email_manager.get_outbox() == [
        QueuedEmailMessage(
            to=["informatik@example.org"],
            subject="election_updated subject content",
            body="election_updated body content\nInfor Matik\nresult_url: wrong_result_url → correct_result_url\n\nhttps://example.org/wahltermine/deadbeef",
            template_id="election_updated",
            created="2026-06-06T10:05:00+00:00",
            not_before="2026-06-06T10:15:00+00:00",
            meta={
                "key": "deadbeef",
                "base": {**DEFAULT_ELECTION, "result_url": "wrong_result_url"},
            },
        ),
        QueuedEmailMessage(
            to=["informatik@example.org"],
            subject="election_updated subject content",
            body="election_updated body content\nInfor Matik\nresult_url: – → wrong_result_url\n\nhttps://example.org/wahltermine/deadbeef",
            template_id="election_updated",
            created="2026-06-06T10:00:00+00:00",
            not_before="2026-06-06T10:10:00+00:00",
            meta={
                "key": "deadbeef",
                "base": DEFAULT_ELECTION,
            },
        ),
    ]

def test_missing_template_results_in_default_error_template(fake_email_manager):
    with travel("2026-06-06T10:00:00Z", tick=False):
        result = client.post("/api/v1/elections/save", json=DEFAULT_ELECTION, headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert fake_email_manager.get_outbox() == [
        QueuedEmailMessage(
            to=["fsk@example.org"],
            subject="Fehlendes E-Mail-Template: election_created",
            body="kwt",
            template_id="election_created",
            created="2026-06-06T10:00:00+00:00",
            not_before=None,
            meta={
                "key": "deadbeef",
                "base": None,
            },
        ),
    ]


def create_election(id_: str, **kwargs: str):
    data = {**DEFAULT_ELECTION, 'election_id': id_, **kwargs}
    result = client.post('/api/v1/elections/save',
                         json=data,
                         headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200


def setup_templates_and_data():
    for template_id in ["election_created", "election_updated"]:
        template = {
            "template_id": template_id,
            "meta": {
                "targets": ["kontakt"],
                "fixed_dates": None,
                "frequency": None,
                "days_before": None,
            },
            "subject": f"{template_id} subject content",
            "body": f"{template_id} body content\n{{fs_name}}\n{{diff}}\nhttps://example.org/wahltermine/{{election_id}}",
        }
        result = client.post("/api/v1/emails/save", json=template, headers=get_auth_header(client, ADMIN))
        assert result.status_code == 200
    protected_data = {
        "email_addresses": [
            {
                "address": "informatik@example.org",
                "usages": ["kontakt", "finanzen"],
            },
            {
                "address": "kasse@example.org",
                "usages": ["finanzen"],
            },
        ],
        "iban": "DE02120300000000202051",
        "bic": "BYLADEM1001",
        "other": {},
    }
    response = client.put(
        "/api/v1/data/Informatik/protected", json=protected_data, headers=get_auth_header(client, ADMIN)
    )
    assert response.status_code == 200
    base_data = {
        "fs_id": "Informatik",
        "name": "Infor Matik",
        "statutes": "",
        "financial_year_start": "01.07.",
        "financial_year_override": None,
        "proceedings_urls": [
            {"url": "https://example.org/proceedings-a", "annotation": "Proceedings A"},
            {"url": "https://example.org/proceedings-f", "annotation": ""},
        ],
        "annotation": "",
        "active": True,
    }
    response = client.put("/api/v1/data/Informatik/base", json=base_data, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
