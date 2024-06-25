import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time

from app.main import app
from app.test.conftest import get_auth_header, USER_INFO_READ, USER_INFO_ALL, ADMIN, USER_NO_PERMS

client = TestClient(app)

SAMPLE_DATA = {
    'email': 'informatik@example.org',
    'phone': '+49228730123',
    'website': 'https://example.org',
    'address': 'Regina-Pacis-Weg 3\n532113 Bonn',
    'serviceTimes': {'monday': '-', 'tuesday': '-', 'wednesday': '-', 'thursday': '-', 'friday': '-'},
    'regularMeeting': {'dayOfWeek': '-', 'time': '-', 'location': '-'},
    'other': {},
}

SAMPLE_PROTECTED_DATA = {
    'email_addresses': [
        {
            'address': 'informatik@example.org',
            'usages': ['fsl', 'finanzen'],
        }, {
            'address': 'kasse@example.org',
            'usages': ['finanzen'],
        }
    ],
    'iban': 'DE02120300000000202051',
    'bic': 'BYLADEM1001',
    'other': {},
}


def test_get_all_fsdata_needs_authentication():
    response = client.get('/api/v1/data')
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_get_all_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == {}


def test_get_all_fsdata_no_permissions():
    set_sample_data()
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 200
    assert response.json() == {}


def test_get_all_fsdata():
    set_sample_data(fs='Informatik')
    set_sample_protected_data(fs='Informatik')
    set_sample_data(fs='Metaphysik-Astrologie')
    set_sample_protected_data(fs='Metaphysik-Astrologie')
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': {'data': SAMPLE_DATA, 'is_latest': True},
            'protected_data': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        }
    }


def test_get_all_fsdata_multiple_fs():
    set_sample_data(fs='Informatik')
    set_sample_protected_data(fs='Informatik')
    set_sample_data(fs='Metaphysik-Astrologie')
    set_sample_protected_data(fs='Metaphysik-Astrologie')
    response = client.get('/api/v1/data', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': {'data': SAMPLE_DATA, 'is_latest': True},
            'protected_data': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        },
        'Metaphysik-Astrologie': {
            'data': {'data': SAMPLE_DATA, 'is_latest': True},
            'protected_data': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        }
    }


def test_get_all_fsdata_only_data_no_protected_data():
    set_sample_data()
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_INFO_READ))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': {'data': SAMPLE_DATA, 'is_latest': True},
            'protected_data': None,
        }
    }


def test_get_all_fsdata_only_protected_data_present():
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': None,
            'protected_data': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        }
    }


@pytest.mark.parametrize('user', [
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_get_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data/Informatik', headers=get_auth_header(client, user))
    assert response.status_code == 404


@pytest.mark.parametrize('user,fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_ALL, 'Metaphysik-Astrologie'],
])
def test_get_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.get(f'/api/v1/data/{fs}', headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user,fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_READ, 'Informatik'],
    [USER_INFO_ALL, 'Metaphysik-Astrologie'],
])
def test_set_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.put(f'/api/v1/data/{fs}', json=SAMPLE_DATA, headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    USER_INFO_ALL,
    ADMIN,
])
def test_set_and_get_fsdata(user):
    response = client.put('/api/v1/data/Informatik', json=SAMPLE_DATA, headers=get_auth_header(client, user))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == {'data': SAMPLE_DATA, 'is_latest': True}


@freeze_time("2023-04-04T10:00:00Z")
def test_set_and_approve_fsdata():
    response = client.put('/api/v1/data/Informatik', json=SAMPLE_DATA, headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/history', headers=get_auth_header(client, ADMIN))
    data_id = response.json()[0]['id']
    response = client.post(f'/api/v1/data/approve/{data_id}', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/history', headers=get_auth_header(client, ADMIN))
    assert response.json() == [{
        **SAMPLE_DATA,
        'id': 1,
        'user': USER_INFO_ALL,
        'timestamp': '2023-04-04T10:00:00+00:00',
        'approval_timestamp': '2023-04-04T10:00:00+00:00',
        'approved': True,
        'approved_by': ADMIN,
    }]


def test_fsdata_history_as_admin():
    data1 = SAMPLE_DATA
    data2 = {**SAMPLE_DATA, 'website': 'https://changed.xyz', }
    with freeze_time("2023-04-04T10:00:00Z"):
        response = client.put('/api/v1/data/Informatik', json=data1, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
    with freeze_time("2023-07-07T17:00:00Z"):
        response = client.put('/api/v1/data/Informatik', json=data2, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/history', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == [
        {
            **data2,
            'id': 2,
            'user': ADMIN,
            'timestamp': '2023-07-07T17:00:00+00:00',
            'approval_timestamp': '2023-07-07T17:00:00+00:00',
            'approved': True,
            'approved_by': 'auto',
        },
        {
            **data1,
            'id': 1,
            'user': ADMIN,
            'timestamp': '2023-04-04T10:00:00+00:00',
            'approval_timestamp': '2023-04-04T10:00:00+00:00',
            'approved': True,
            'approved_by': 'auto',
        },
    ]


def test_fsdata_history_unauthorized():
    response = client.get('/api/v1/data/Informatik/history', headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401


def test_fsdata_history_does_not_exist():
    response = client.get('/api/v1/data/Metaphysik-Astrologie/history', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_protected_fsdata_history_does_not_exist():
    response = client.get('/api/v1/data/Metaphysik-Astrologie/protected/history',
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_approve_fsdata_does_not_exist():
    response = client.post('/api/v1/data/approve/69', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_approve_protected_fsdata_does_not_exist():
    response = client.post('/api/v1/data/approve/protected/69', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_protected_fsdata_history_as_admin():
    data1 = SAMPLE_PROTECTED_DATA
    data2 = {**SAMPLE_PROTECTED_DATA, 'iban': 'AT1234567890', }
    with freeze_time("2023-04-04T10:00:00Z"):
        response = client.put('/api/v1/data/Informatik/protected', json=data1, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
    with freeze_time("2023-07-07T17:00:00Z"):
        response = client.put('/api/v1/data/Informatik/protected', json=data2, headers=get_auth_header(client, USER_INFO_ALL))
        assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/protected/history', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == [
        {
            **data2,
            'id': 2,
            'user': USER_INFO_ALL,
            'timestamp': '2023-07-07T17:00:00+00:00',
            'approval_timestamp': None,
            'approved': False,
            'approved_by': None,
        },
        {
            **data1,
            'id': 1,
            'user': ADMIN,
            'timestamp': '2023-04-04T10:00:00+00:00',
            'approval_timestamp': '2023-04-04T10:00:00+00:00',
            'approved': True,
            'approved_by': 'auto',
        },
    ]


def test_protected_fsdata_history_unauthorized():
    response = client.get('/api/v1/data/Informatik/protected/history', headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    USER_INFO_ALL,
    ADMIN,
])
def test_get_protected_fsdata_no_data_set(user):
    queryresponse = client.get('/api/v1/data/Informatik/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 404


@pytest.mark.parametrize('user,fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_READ, 'Informatik'],
    [USER_INFO_ALL, 'Metaphysik-Astrologie'],
])
def test_get_protected_fsdata_insufficient_permissions(user: str, fs: str):
    queryresponse = client.get(f'/api/v1/data/{fs}/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 401


@pytest.mark.parametrize('user,fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_READ, 'Informatik'],
    [USER_INFO_ALL, 'Metaphysik-Astrologie'],
])
def test_set_protected_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.put(f'/api/v1/data/{fs}/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    USER_INFO_ALL,
    ADMIN,
])
def test_set_and_get_protected_fsdata(user: str):
    response = client.put('/api/v1/data/Informatik/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, user))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/protected/history', headers=get_auth_header(client, ADMIN))
    data_id = response.json()[0]['id']
    response = client.post(f'/api/v1/data/approve/protected/{data_id}', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    queryresponse = client.get('/api/v1/data/Informatik/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 200
    assert queryresponse.json() == {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True}


def set_sample_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}', json=SAMPLE_DATA, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


def set_sample_protected_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
