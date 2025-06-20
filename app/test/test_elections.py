import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import get_auth_header, USER_INFO_ALL, USER_INFO_READ, ADMIN, USER_NO_PERMS, fake_session

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


def test_save_election_as_admin():
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
def test_elections_index(user):
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


def test_get_history_as_admin():
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


def create_election(id_: str, **kwargs: str):
    data = {**DEFAULT_ELECTION, 'election_id': id_, **kwargs}
    result = client.post('/api/v1/elections/save',
                         json=data,
                         headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
