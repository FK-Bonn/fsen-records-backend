from fastapi.testclient import TestClient
from freezegun import freeze_time

from conftest import get_auth_header
from app.main import app

client = TestClient(app)

SAMPLE_PAYOUT_REQUEST = {
    'request_id': 'A22W-0023',
    'fs': 'Informatik',
    'semester': '2022-WiSe',
    'status': 'GESTELLT',
    'status_date': '2023-01-07',
    'amount_cents': 111100,
    'comment': 'comment',
    'request_date': '2023-01-07',
    'requester': 'tim.test',
    'last_modified_timestamp': '2023-01-07T22:11:07+00:00',
    'last_modified_by': 'tim.test',
}


def test_get_all_payout_requests():
    response = client.get('/api/v1/payout-request/afsg')
    assert response.status_code == 200
    assert response.json() == [SAMPLE_PAYOUT_REQUEST]


@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_as_admin():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2023-SoSe',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        'request_id': 'A23S-0001',
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'status': 'GESTELLT',
        'status_date': '2023-04-04',
        'amount_cents': 0,
        'comment': '',
        'request_date': '2023-04-04',
        'requester': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_as_write_user():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2023-SoSe',
    }, headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {
        'request_id': 'A23S-0001',
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'status': 'GESTELLT',
        'status_date': '2023-04-04',
        'amount_cents': 0,
        'comment': '',
        'request_date': '2023-04-04',
        'requester': 'user3',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'user3',
    }


def test_create_payout_requests_as_read_user_fails():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2023-SoSe',
    }, headers=get_auth_header(client, 'user2'))
    assert response.status_code == 401


@freeze_time("2023-04-04T10:00:00Z")
def test_modify_payout_requests_as_admin():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'Endlich ist es fertig',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        'request_id': 'A22W-0023',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'Endlich ist es fertig',
        'request_date': '2023-01-07',
        'requester': 'tim.test',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
    }

@freeze_time("2023-04-04T10:00:00Z")
def test_modify_payout_requests_set_empty_values():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={
        'amount_cents': 0,
        'comment': '',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        'request_id': 'A22W-0023',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'GESTELLT',
        'status_date': '2023-01-07',
        'amount_cents': 0,
        'comment': '',
        'request_date': '2023-01-07',
        'requester': 'tim.test',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_modify_payout_requests_no_changes():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={}, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        'request_id': 'A22W-0023',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'GESTELLT',
        'status_date': '2023-01-07',
        'amount_cents': 111100,
        'comment': 'comment',
        'request_date': '2023-01-07',
        'requester': 'tim.test',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
    }


def test_modify_payout_requests_as_user_fails():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={
        'status': 'VOLLSTAENDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'Endlich ist es fertig',
    }, headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401
