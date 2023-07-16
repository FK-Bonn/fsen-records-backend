from typing import Optional

import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time

from app.main import app
from app.routers.payout_requests import get_default_completion_deadline
from app.test.conftest import get_auth_header

client = TestClient(app)

SAMPLE_PAYOUT_REQUEST:  dict[str, str | int | None] = {
    'request_id': 'A22W-0023',
    'fs': 'Informatik',
    'semester': '2022-WiSe',
    'status': 'GESTELLT',
    'status_date': '2023-01-07',
    'amount_cents': 111100,
    'comment': 'comment',
    'request_date': '2023-01-07',
    'completion_deadline': '2025-03-31',
    'last_modified_by': None,
    'last_modified_timestamp': None,
    'requester': None,
}

SAMPLE_FULL_PAYOUT_REQUEST: dict[str, str | int | None] = {
    **SAMPLE_PAYOUT_REQUEST,
    'last_modified_by': 'tim.test',
    'last_modified_timestamp': '2023-01-07T22:11:07+00:00',
    'requester': 'tim.test',
}


def test_get_all_payout_requests():
    response = client.get('/api/v1/payout-request/afsg')
    assert response.status_code == 200
    assert response.json() == [SAMPLE_PAYOUT_REQUEST]


def test_get_all_payout_requests_as_admin():
    response = client.get('/api/v1/payout-request/afsg', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == [SAMPLE_FULL_PAYOUT_REQUEST]


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
        'status': 'EINGEREICHT',
        'status_date': '2023-04-04',
        'amount_cents': 0,
        'comment': '',
        'request_date': '2023-04-04',
        'requester': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
        'completion_deadline': '2025-09-30',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_invalid_semester_format():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': 'SoSe-2022',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 422
    assert response.json() == {
        'detail': 'Invalid semester format',
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
        'status': 'EINGEREICHT',
        'status_date': '2023-04-04',
        'amount_cents': 0,
        'comment': '',
        'request_date': '2023-04-04',
        'requester': 'user3',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'user3',
        'completion_deadline': '2025-09-30',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_as_write_user_fails_if_already_exists():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2022-WiSe',
    }, headers=get_auth_header(client, 'user3'))
    assert response.status_code == 422
    assert response.json() == {
        'detail': 'There already is a payout request for this semester',
    }


@pytest.mark.parametrize("timestamp,semester,status_code", [
    ['2023-04-01T00:00:00+02:00', '2023-SoSe', 200],
    ['2023-04-01T00:00:00+02:00', '2022-WiSe', 200],
    ['2023-04-01T00:00:00+02:00', '2022-SoSe', 200],
    ['2023-04-01T00:00:00+02:00', '2021-WiSe', 422],
    ['2023-03-31T23:59:59+02:00', '2023-SoSe', 422],
    ['2023-03-31T23:59:59+02:00', '2021-WiSe', 200],
    ['2023-10-01T00:00:00+02:00', '2023-WiSe', 200],
    ['2023-10-01T00:00:00+02:00', '2023-SoSe', 200],
    ['2023-10-01T00:00:00+02:00', '2022-WiSe', 200],
    ['2023-10-01T00:00:00+02:00', '2022-SoSe', 422],
    ['2023-09-30T23:59:59+02:00', '2023-WiSe', 422],
    ['2023-09-30T23:59:59+02:00', '2022-SoSe', 200],
])
def test_create_payout_requests_checks_semester(timestamp, semester, status_code):
    with freeze_time(timestamp):
        response = client.post('/api/v1/payout-request/afsg/create', json={
            'fs': 'Geographie',
            'semester': semester,
        }, headers=get_auth_header(client, 'user5'))
    assert response.status_code == status_code


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
        'completion_deadline': '2025-05-31',
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
        'completion_deadline': '2025-05-31',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_modify_nonexisting_payout_requests_fails():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0069', json={
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'This will not work',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 404
    assert response.json() == {
        'detail': 'PayoutRequest not found',
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
        'completion_deadline': '2025-03-31',
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
        'completion_deadline': '2025-03-31',
    }


def test_modify_payout_requests_as_user_fails():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={
        'status': 'VOLLSTAENDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'Endlich ist es fertig',
    }, headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401


@freeze_time("2023-04-04T10:00:00Z")
def test_get_payout_request_history_as_admin():
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'completion_deadline': '2025-05-31',
        'comment': 'Endlich ist es fertig',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    response = client.get('/api/v1/payout-request/afsg/A22W-0023/history', headers=get_auth_header(client, 'admin'))
    assert response.json() == [
        {
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
            'completion_deadline': '2025-05-31',
        },
        SAMPLE_FULL_PAYOUT_REQUEST,
    ]

@pytest.mark.parametrize("username", [
    None,
    "user",
    "user2",
    "user4",
])
@freeze_time("2023-04-04T10:00:00Z")
def test_get_payout_request_history_no_admin(username: Optional[str]):
    response = client.patch('/api/v1/payout-request/afsg/A22W-0023', json={
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'completion_deadline': '2025-05-31',
        'comment': 'Endlich ist es fertig',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    headers = {}
    if username:
        headers = get_auth_header(client, username)
    response = client.get('/api/v1/payout-request/afsg/A22W-0023/history', headers=headers)
    assert response.json() == [
        {
            'request_id': 'A22W-0023',
            'fs': 'Informatik',
            'semester': '2022-WiSe',
            'status': 'VOLLSTÄNDIG',
            'status_date': '2023-05-05',
            'amount_cents': 100000,
            'comment': 'Endlich ist es fertig',
            'request_date': '2023-01-07',
            'requester': None,
            'last_modified_timestamp': None,
            'last_modified_by': None,
            'completion_deadline': '2025-05-31',
        },
        SAMPLE_PAYOUT_REQUEST,
    ]


def test_get_payout_request_history_not_found():
    response = client.get('/api/v1/payout-request/afsg/A22W-0069/history', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 404


@freeze_time("2023-04-04T10:00:00Z")
def test_get_payout_request_with_date_filter():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2023-SoSe',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200

    response = client.get('/api/v1/payout-request/afsg/2023-04-03')
    assert response.status_code == 200
    assert response.json() == [SAMPLE_PAYOUT_REQUEST]

    response = client.get('/api/v1/payout-request/afsg/2023-04-04')
    assert response.status_code == 200
    assert response.json() == [
        SAMPLE_PAYOUT_REQUEST,
        {'amount_cents': 0,
         'comment': '',
         'fs': 'Informatik',
         'request_date': '2023-04-04',
         'request_id': 'A23S-0001',
         'semester': '2023-SoSe',
         'status': 'EINGEREICHT',
         'status_date': '2023-04-04',
         'completion_deadline': '2025-09-30',
         'last_modified_by': None,
         'last_modified_timestamp': None,
         'requester': None,
         },
    ]

    response = client.get('/api/v1/payout-request/afsg/2023-04-04', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == [
        {
            **SAMPLE_PAYOUT_REQUEST,
            'last_modified_by': 'tim.test',
            'last_modified_timestamp': '2023-01-07T22:11:07+00:00',
            'requester': 'tim.test',
        },
        {
            'amount_cents': 0,
            'comment': '',
            'fs': 'Informatik',
            'request_date': '2023-04-04',
            'request_id': 'A23S-0001',
            'semester': '2023-SoSe',
            'status': 'EINGEREICHT',
            'status_date': '2023-04-04',
            'completion_deadline': '2025-09-30',
            'last_modified_by': 'admin',
            'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
            'requester': 'admin',
        },
    ]


@pytest.mark.parametrize("semester,expiration_date", [
    ['2023-SoSe', '2025-09-30'],
    ['2023-WiSe', '2026-03-31'],
    ['2024-SoSe', '2026-09-30'],
    ['2024-WiSe', '2027-03-31'],
    ['2025-SoSe', '2027-09-30'],
    ['2025-WiSe', '2028-03-31'],
])
def test_get_default_completion_deadline(semester: str, expiration_date: str):
    assert get_default_completion_deadline(semester) == expiration_date
