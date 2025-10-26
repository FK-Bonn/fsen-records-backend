from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.main import app, subapp
from app.routers.payout_requests import get_default_afsg_completion_deadline, get_default_bfsg_completion_deadline, \
    get_default_vorankuendigung_completion_deadline
from app.test.conftest import get_auth_header, ADMIN, USER_NO_PERMS, USER_INFO_READ, USER_INFO_GEO_READ, USER_INFO_ALL, \
    USER_INFO_GEO_ALL, fake_session

DEFAULT_PARAMETERS: dict[str, str | int] = {
    'status': 'VOLLSTÄNDIG',
    'status_date': '2023-05-05',
    'amount_cents': 100000,
    'completion_deadline': '2025-05-31',
    'comment': 'Endlich ist es fertig',
    'reference': 'V22W-6969',
}

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session

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
    },
    'vorankuendigung': {
        'request_id': 'V22W-0023',
        'type': 'vorankuendigung',
        'category': 'Erstiarbeit',
        'fs': 'Informatik',
        'semester': '2022-WiSe',
        'status': 'GESTELLT',
        'status_date': '2023-01-07',
        'amount_cents': 100000,
        'comment': 'comment',
        'request_date': '2023-01-07',
        'completion_deadline': '',
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
    },
    'vorankuendigung': {
        **SAMPLE_PAYOUT_REQUEST['vorankuendigung'],
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
        'requester': ADMIN,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': ADMIN,
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
        'requester': ADMIN,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': ADMIN,
        'completion_deadline': '2023-10-31',
    },
    'vorankuendigung': {
        'request_id': 'V23S-0001',
        'type': 'vorankuendigung',
        'category': 'Erstiarbeit',
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'status': 'GESTELLT',
        'status_date': '2023-04-04',
        'amount_cents': 99900,
        'comment': '',
        'request_date': '2023-04-04',
        'reference': None,
        'requester': ADMIN,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': ADMIN,
        'completion_deadline': '2024-03-31',
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
    },
    'vorankuendigung': {
        'fs': 'Informatik',
        'semester': '2023-SoSe',
        'category': 'Erstiarbeit',
        'amount_cents': 99900,
    }
}


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
def test_get_all_payout_requests(_type):
    response = client.get(f'/api/v1/payout-request/{_type}')
    assert response.status_code == 200
    assert response.json() == [SAMPLE_PAYOUT_REQUEST[_type]]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
def test_get_all_payout_requests_as_admin(_type):
    response = client.get(f'/api/v1/payout-request/{_type}', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == [SAMPLE_FULL_PAYOUT_REQUEST[_type]]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_create_payout_requests_as_admin(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == CREATED_PAYOUT_REQUEST[_type]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_create_payout_requests_invalid_semester_format(_type):
    response = client.post('/api/v1/payout-request/afsg/create', json={
        **CREATE_PARAMS[_type],
        'semester': 'SoSe-2022',
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 422
    assert response.json() == {
        'detail': 'Invalid semester format',
    }


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_create_payout_requests_as_write_user_mocked(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        **CREATED_PAYOUT_REQUEST[_type],
        'requester': USER_INFO_ALL,
        'last_modified_by': USER_INFO_ALL,
    }


@travel("2023-04-04T10:00:00Z", tick=False)
def test_create_afsg_payout_requests_as_write_user_fails_if_already_exists():
    response = client.post('/api/v1/payout-request/afsg/create', json={
        'fs': 'Informatik',
        'semester': '2022-WiSe',
    }, headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 422
    assert response.json() == {
        'detail': 'There already is a payout request for this semester',
    }


@pytest.mark.parametrize('_type', [
    'bfsg',
    'vorankuendigung',
])
@travel("2023-04-04T10:00:00Z", tick=False)
@patch('app.routers.payout_requests.check_user_may_submit_payout_request')
def test_create_payout_requests_as_write_user_does_not_fail_if_already_exists(mocked_func, _type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        **CREATED_PAYOUT_REQUEST[_type],
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        'last_modified_by': USER_INFO_ALL,
        'requester': USER_INFO_ALL,
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
    with travel(timestamp, tick=False):
        response = client.post('/api/v1/payout-request/afsg/create', json={
            'fs': 'Geographie',
            'semester': semester,
        }, headers=get_auth_header(client, USER_INFO_GEO_ALL))
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
    with travel(timestamp, tick=False):
        response = client.post('/api/v1/payout-request/bfsg/create', json={
            'fs': 'Geographie',
            'semester': semester,
            'category': 'Erstiarbeit',
            'amount_cents': 6969,
        }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == status_code


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_create_payout_requests_as_read_user_fails(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, USER_INFO_READ))
    assert response.status_code == 401


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_modify_payout_requests_as_admin(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=DEFAULT_PARAMETERS,
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {
        **SAMPLE_FULL_PAYOUT_REQUEST[_type],
        **DEFAULT_PARAMETERS,
        'last_modified_by': ADMIN,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@pytest.mark.parametrize("username", [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_GEO_READ,
])
def test_delete_payout_requests_as_non_admin_fails(username, _type, request_id):
    response = client.delete(f'/api/v1/payout-request/{_type}/{request_id}',
                             headers=get_auth_header(client, username))
    assert response.status_code == 401
    assert len(client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                          headers=get_auth_header(client, ADMIN)).json()) == 1


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
def test_delete_payout_request_as_admin(_type, request_id):
    response = client.delete(f'/api/v1/payout-request/{_type}/{request_id}',
                             headers=get_auth_header(client, ADMIN))

    assert response.status_code == 200
    assert client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                      headers=get_auth_header(client, ADMIN)).status_code == 404

@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0069'],
    ['bfsg', 'B22W-0069'],
    ['vorankuendigung', 'V22W-0069'],
])
def test_delete_nonexistent_payout_request_as_admin_fails(_type, request_id):
    response = client.delete(f'/api/v1/payout-request/{_type}/{request_id}',
                             headers=get_auth_header(client, ADMIN))

    assert response.status_code == 404


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
def test_delete_payout_request_reveals_previous_state(_type, request_id):
    assert client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=DEFAULT_PARAMETERS,
                        headers=get_auth_header(client, ADMIN)).status_code == 200
    assert len(client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                          headers=get_auth_header(client, ADMIN)).json()) == 2

    response = client.delete(f'/api/v1/payout-request/{_type}/{request_id}',
                             headers=get_auth_header(client, ADMIN))

    assert response.status_code == 200
    history = client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                         headers=get_auth_header(client, ADMIN)).json()
    assert len(history) == 1
    assert history[0]['status'] == 'GESTELLT'


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_modify_payout_requests_with_silly_date_formats(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}',
                            json={
                                'status_date': '5.5.2023',
                                'completion_deadline': '05/31/2024',
                            },
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 422
    assert response.json() == {'detail': [
        {'ctx': {'error': 'input is too short'},
         'input': '5.5.2023',
         'loc': ['body', 'status_date'],
         'msg': 'Input should be a valid date or datetime, input is too short',
         'type': 'date_from_datetime_parsing'},
        {'ctx': {'error': 'invalid character in year'},
         'input': '05/31/2024',
         'loc': ['body', 'completion_deadline'],
         'msg': 'Input should be a valid date or datetime, invalid character in year',
         'type': 'date_from_datetime_parsing'},
    ]}


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0069'],
    ['bfsg', 'B22W-0069'],
    ['vorankuendigung', 'V22W-0069'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_modify_nonexisting_payout_requests_fails(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json={
        'status': 'VOLLSTÄNDIG',
        'status_date': '2023-05-05',
        'amount_cents': 100000,
        'comment': 'This will not work',
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404
    assert response.json() == {
        'detail': 'PayoutRequest not found',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_modify_payout_requests_set_empty_values(_type, request_id):
    parameters = {
        'amount_cents': 0,
        'comment': '',
    }
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=parameters,
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {
        **SAMPLE_FULL_PAYOUT_REQUEST[_type],
        **parameters,
        'last_modified_by': ADMIN,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_modify_payout_requests_no_changes(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json={},
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {
        **SAMPLE_FULL_PAYOUT_REQUEST[_type],
        'last_modified_by': ADMIN,
        'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
    }


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
def test_modify_payout_requests_as_user_fails(_type, request_id):
    response = client.patch(f'/api/v1/payout-request/{_type}/{request_id}', json=DEFAULT_PARAMETERS,
                            headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_get_payout_request_history_as_admin(_type, request_id):
    edit_request(_type, request_id)
    response = client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                          headers=get_auth_header(client, ADMIN))
    assert response.json() == [
        {
            **SAMPLE_FULL_PAYOUT_REQUEST[_type],
            **DEFAULT_PARAMETERS,
            'last_modified_by': ADMIN,
            'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
        },
        SAMPLE_FULL_PAYOUT_REQUEST[_type],
    ]


@pytest.mark.parametrize("username", [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_GEO_READ,
])
@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0023'],
    ['bfsg', 'B22W-0023'],
    ['vorankuendigung', 'V22W-0023'],
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_get_payout_request_history_no_admin(username: str | None, _type, request_id):
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
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


@pytest.mark.parametrize('_type,request_id', [
    ['afsg', 'A22W-0069'],
    ['bfsg', 'B22W-0069'],
    ['vorankuendigung', 'V22W-0069'],
])
def test_get_payout_request_history_not_found(_type, request_id):
    response = client.get(f'/api/v1/payout-request/{_type}/{request_id}/history',
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
@travel("2023-04-04T10:00:00Z", tick=False)
def test_get_payout_request_with_date_filter(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, ADMIN))
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

    response = client.get(f'/api/v1/payout-request/{_type}/2023-04-04', headers=get_auth_header(client, ADMIN))
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
            'last_modified_by': ADMIN,
            'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
            'requester': ADMIN,
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
    ['2023-01-01', '2023-07-31'],
    ['2023-02-28', '2023-08-31'],
    ['2024-02-29', '2024-08-31'],
    ['2023-08-31', '2024-02-29'],
    ['2024-08-29', '2025-02-28'],
    ['2024-08-30', '2025-02-28'],
    ['2024-08-31', '2025-02-28'],
    ['2023-01-31', '2023-07-31'],
    ['2023-03-31', '2023-09-30'],
    ['2023-09-30', '2024-03-31'],
    ['2023-10-31', '2024-04-30'],
    ['2023-06-15', '2023-12-31'],
])
def test_get_default_bfsg_completion_deadline(today: str, expiration_date: str):
    assert get_default_bfsg_completion_deadline(today) == expiration_date

@pytest.mark.parametrize("semester,expiration_date", [
    ['2023-SoSe', '2024-03-31'],
    ['2023-WiSe', '2024-09-30'],
    ['2024-SoSe', '2025-03-31'],
    ['2024-WiSe', '2025-09-30'],
    ['2025-SoSe', '2026-03-31'],
    ['2025-WiSe', '2026-09-30'],
])
def test_get_default_vorankuendigung_completion_deadline(semester: str, expiration_date: str):
    assert get_default_vorankuendigung_completion_deadline(semester) == expiration_date
