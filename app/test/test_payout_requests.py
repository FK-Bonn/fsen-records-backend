from typing import Optional
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time

from app.main import app
from app.routers.payout_requests import get_default_afsg_completion_deadline, get_default_bfsg_completion_deadline
from app.test.conftest import get_auth_header

DEFAULT_PARAMETERS: dict[str, str | int] = {
    'status': 'VOLLSTÄNDIG',
    'status_date': '2023-05-05',
    'amount_cents': 100000,
    'completion_deadline': '2025-05-31',
    'comment': 'Endlich ist es fertig',
}

client = TestClient(app)

SAMPLE_PAYOUT_REQUEST: dict[str, dict[str, str | int | None]] = {
    'afsg': {
        'request_id': 'A22W-0023',
        'type': 'afsg',
        'category': 'AFSG',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'GESTELLT',
        'status_date': '2023-01-07',
        'amount_cents': 111100,
        'comment': 'comment',
        'request_date': '2023-01-07',
        'completion_deadline': '2025-03-31',
        'reference': None,
        'last_modified_by': None,
        'last_modified_timestamp': None,
        'requester': None,
    },
    'bfsg': {
        'request_id': 'B22W-0023',
        'type': 'bfsg',
        'category': 'Erstiarbeit',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'GESTELLT',
        'status_date': '2023-01-07',
        'amount_cents': 23456,
        'comment': 'comment',
        'request_date': '2023-01-07',
        'completion_deadline': '2023-07-07',
        'reference': None,
        'last_modified_by': None,
        'last_modified_timestamp': None,
        'requester': None,
    }
}

SAMPLE_FULL_PAYOUT_REQUEST: dict[str, dict[str, str | int | None]] = {
    'afsg': {
        **SAMPLE_PAYOUT_REQUEST['afsg'],
        'last_modified_by': 'tim.test',
        'last_modified_timestamp': '2023-01-07T22:11:07+00:00',
        'requester': 'tim.test',
    },
    'bfsg': {
        **SAMPLE_PAYOUT_REQUEST['bfsg'],
        'last_modified_by': 'tim.test',
        'last_modified_timestamp': '2023-01-07T22:11:07+00:00',
        'requester': 'tim.test',
    }
}

CREATED_PAYOUT_REQUEST: dict[str, dict[str, str | int | None]] = {
    'afsg': {
        'request_id': 'A23S-0001',
        'type': 'afsg',
        'category': 'AFSG',
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'status': 'EINGEREICHT',
        'status_date': '2023-04-04',
        'amount_cents': 0,
        'comment': '',
        'request_date': '2023-04-04',
        'completion_deadline': '2025-09-30',
        'reference': None,
        'requester': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
    },
    'bfsg': {
        'request_id': 'B23S-0001',
        'type': 'bfsg',
        'category': 'Erstiarbeit',
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'status': 'GESTELLT',
        'status_date': '2023-04-04',
        'amount_cents': 6969,
        'comment': '',
        'request_date': '2023-04-04',
        'reference': None,
        'requester': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'admin',
        'completion_deadline': '2023-10-04',
    }
}

CREATE_PARAMS: dict[str, dict[str, str | int | None]] = {
    'afsg': {
        'fs': 'Informatik',
        'semester': '2023-SoSe',
    },
    'bfsg': {
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'category': 'Erstiarbeit',
        'amount_cents': 6969,
    }
}


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
])
def test_get_all_payout_requests(_type):
    response = client.get(f'/api/v1/payout-request/{_type}')
    assert response.status_code == 200
    assert response.json() == [SAMPLE_PAYOUT_REQUEST[_type]]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
])
def test_get_all_payout_requests_as_admin(_type):
    response = client.get(f'/api/v1/payout-request/{_type}', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == [SAMPLE_FULL_PAYOUT_REQUEST[_type]]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
])
@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_as_admin(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == CREATED_PAYOUT_REQUEST[_type]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
])
@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_invalid_semester_format(_type):
    response = client.post('/api/v1/payout-request/afsg/create', json={
        **CREATE_PARAMS[_type],
        'semester': 'SoSe-2022',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 422
    assert response.json() == {
        'detail': 'Invalid semester format',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_create_afsg_payout_requests_as_write_user():
    response = client.post('/api/v1/payout-request/afsg/create', json=CREATE_PARAMS['afsg'],
                           headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {
        **CREATED_PAYOUT_REQUEST['afsg'],
        'requester': 'user3',
        'last_modified_by': 'user3',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_create_bfsg_payout_requests_as_write_user_currently_not_allowed():
    response = client.post('/api/v1/payout-request/bfsg/create', json=CREATE_PARAMS['bfsg']
                           , headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401


@freeze_time("2023-04-04T10:00:00Z")
@patch('app.routers.payout_requests.check_user_may_submit_payout_request')
def test_create_bfsg_payout_requests_as_write_user(mocked_func):
    response = client.post('/api/v1/payout-request/bfsg/create', json=CREATE_PARAMS['bfsg'],
                           headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {
        **CREATED_PAYOUT_REQUEST['bfsg'],
        'requester': 'user3',
        'last_modified_by': 'user3',
    }


@freeze_time("2023-04-04T10:00:00Z")
def test_create_afsg_payout_requests_as_write_user_fails_if_already_exists():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2022-WiSe',
    }, headers=get_auth_header(client, 'user3'))
    assert response.status_code == 422
    assert response.json() == {
        'detail': 'There already is a payout request for this semester',
    }


@freeze_time("2023-04-04T10:00:00Z")
@patch('app.routers.payout_requests.check_user_may_submit_payout_request')
def test_create_bfsg_payout_requests_as_write_user_does_not_fail_if_already_exists(mocked_func):
    response = client.post('/api/v1/payout-request/bfsg/create', json={
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'category': 'Erstiarbeit',
        'amount_cents': 6969,
    }, headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {
        'request_id': 'B22W-0024',
        'type': 'bfsg',
        'category': 'Erstiarbeit',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'GESTELLT',
        'status_date': '2023-04-04',
        'amount_cents': 6969,
        'comment': '',
        'request_date': '2023-04-04',
        'requester': 'user3',
        'reference': None,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': 'user3',
        'completion_deadline': '2023-10-04',
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
def test_create_afsg_payout_requests_checks_semester(timestamp, semester, status_code):
    with freeze_time(timestamp):
        response = client.post('/api/v1/payout-request/afsg/create', json={
            'fs': 'Geographie',
            'semester': semester,
        }, headers=get_auth_header(client, 'user5'))
    assert response.status_code == status_code


@pytest.mark.parametrize("timestamp,semester,status_code", [
    ['2023-04-01T00:00:00+02:00', '2023-SoSe', 200],
    ['2023-04-01T00:00:00+02:00', '2022-WiSe', 200],
    ['2023-04-01T00:00:00+02:00', '2022-SoSe', 422],
    ['2023-04-01T00:00:00+02:00', '2021-WiSe', 422],
    ['2023-03-31T23:59:59+02:00', '2023-SoSe', 422],
    ['2023-03-31T23:59:59+02:00', '2022-WiSe', 200],
    ['2023-03-31T23:59:59+02:00', '2022-SoSe', 200],
    ['2023-03-31T23:59:59+02:00', '2021-WiSe', 422],
    ['2023-10-01T00:00:00+02:00', '2023-WiSe', 200],
    ['2023-10-01T00:00:00+02:00', '2023-SoSe', 200],
    ['2023-10-01T00:00:00+02:00', '2022-WiSe', 422],
    ['2023-10-01T00:00:00+02:00', '2022-SoSe', 422],
    ['2023-09-30T23:59:59+02:00', '2023-WiSe', 422],
    ['2023-09-30T23:59:59+02:00', '2023-SoSe', 200],
    ['2023-09-30T23:59:59+02:00', '2022-WiSe', 200],
    ['2023-09-30T23:59:59+02:00', '2022-SoSe', 422],
])
def test_create_bfsg_payout_requests_checks_semester(timestamp, semester, status_code):
    with freeze_time(timestamp):
        response = client.post('/api/v1/payout-request/bfsg/create', json={
            'fs': 'Geographie',
            'semester': semester,
            'category': 'Erstiarbeit',
            'amount_cents': 6969,
        }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == status_code


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
])
@freeze_time("2023-04-04T10:00:00Z")
def test_create_payout_requests_as_read_user_fails(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, 'user2'))
    assert response.status_code == 401


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
])
@freeze_time("2023-04-04T10:00:00Z")
def test_modify_payout_requests_as_admin(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=DEFAULT_PARAMETERS,
                            headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        **SAMPLE_FULL_PAYOUT_REQUEST[_type],
        **DEFAULT_PARAMETERS,
        'last_modified_by': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0069'],
    ['bfsg', 'B22W-0069'],
])
@freeze_time("2023-04-04T10:00:00Z")
def test_modify_nonexisting_payout_requests_fails(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json={
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'This will not work',
    }, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 404
    assert response.json() == {
        'detail': 'PayoutRequest not found',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
])
@freeze_time("2023-04-04T10:00:00Z")
def test_modify_payout_requests_set_empty_values(_type, request_id):
    parameters = {
        'amount_cents': 0,
        'comment': '',
    }
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=parameters,
                            headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        **SAMPLE_FULL_PAYOUT_REQUEST[_type],
        **parameters,
        'last_modified_by': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
])
@freeze_time("2023-04-04T10:00:00Z")
def test_modify_payout_requests_no_changes(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json={},
                            headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        **SAMPLE_FULL_PAYOUT_REQUEST[_type],
        'last_modified_by': 'admin',
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
])
def test_modify_payout_requests_as_user_fails(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=DEFAULT_PARAMETERS,
                            headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
])
@freeze_time("2023-04-04T10:00:00Z")
def test_get_payout_request_history_as_admin(_type, request_id):
    edit_request(_type, request_id)
    response = client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                          headers=get_auth_header(client, 'admin'))
    assert response.json() == [
        {
            **SAMPLE_FULL_PAYOUT_REQUEST[_type],
            **DEFAULT_PARAMETERS,
            'last_modified_by': 'admin',
            'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        },
        SAMPLE_FULL_PAYOUT_REQUEST[_type],
    ]


@pytest.mark.parametrize("username", [
    None,
    "user",
    "user2",
    "user4",
])
@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
])
@freeze_time("2023-04-04T10:00:00Z")
def test_get_payout_request_history_no_admin(username: Optional[str], _type, request_id):
    edit_request(_type, request_id)
    headers = {}
    if username:
        headers = get_auth_header(client, username)
    response = client.get(f'/api/v1/payout-request/{_type}/{request_id}/history', headers=headers)
    assert response.json() == [
        {
            **SAMPLE_PAYOUT_REQUEST[_type],
            **DEFAULT_PARAMETERS,
        },
        SAMPLE_PAYOUT_REQUEST[_type],
    ]


def edit_request(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=DEFAULT_PARAMETERS,
                            headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0069'],
    ['bfsg', 'B22W-0069'],
])
def test_get_payout_request_history_not_found(_type, request_id):
    response = client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                          headers=get_auth_header(client, 'admin'))
    assert response.status_code == 404


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
])
@freeze_time("2023-04-04T10:00:00Z")
def test_get_payout_request_with_date_filter(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200

    response = client.get(f'/api/v1/payout-request/{_type}/2023-04-03')
    assert response.status_code == 200
    assert response.json() == [SAMPLE_PAYOUT_REQUEST[_type]]

    response = client.get(f'/api/v1/payout-request/{_type}/2023-04-04')
    assert response.status_code == 200
    assert response.json() == [
        SAMPLE_PAYOUT_REQUEST[_type],
        {
            **CREATED_PAYOUT_REQUEST[_type],
            'last_modified_by': None,
            'last_modified_timestamp': None,
            'requester': None,
        }
    ]

    response = client.get(f'/api/v1/payout-request/{_type}/2023-04-04', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == [
        {
            **SAMPLE_PAYOUT_REQUEST[_type],
            'last_modified_by': 'tim.test',
            'last_modified_timestamp': '2023-01-07T22:11:07+00:00',
            'requester': 'tim.test',
        },
        {
            **CREATED_PAYOUT_REQUEST[_type],
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
def test_get_default_afsg_completion_deadline(semester: str, expiration_date: str):
    assert get_default_afsg_completion_deadline(semester) == expiration_date

@pytest.mark.parametrize("today,expiration_date", [
    ['2023-01-01', '2023-07-01'],
    ['2023-02-28', '2023-08-28'],
    ['2024-02-29', '2024-08-29'],
    ['2024-08-29', '2025-03-01'],
    ['2024-08-30', '2025-03-01'],
    ['2024-08-31', '2025-03-01'],
    ['2023-01-31', '2023-07-31'],
    ['2023-03-31', '2023-10-01'],
    ['2023-09-30', '2024-03-30'],
    ['2023-10-31', '2024-05-01'],
])
def test_get_default_bfsg_completion_deadline(today: str, expiration_date: str):
    assert get_default_bfsg_completion_deadline(today) == expiration_date
