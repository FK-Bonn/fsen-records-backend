import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time

from app.main import app
from app.test.conftest import get_auth_header, USER_INFO_READ, USER_INFO_ALL, ADMIN, USER_NO_PERMS

client = TestClient(app)

SAMPLE_PUBLIC_DATA = {
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

SAMPLE_BASE_DATA = {
    'fs_id': 'Informatik',
    'name': 'Informatik',
    'statutes': '',
    'financial_year_start': '01.04.',
    'financial_year_override': {
        'previous': {'date_start': '2023-01-01', 'date_end': '2023-12-31'},
        'current': {'date_start': '2024-01-01', 'date_end': '2024-03-31'}
    },
    'proceedings_urls': [
        {'url': 'https://example.org/proceedings-a', 'annotation': 'Proceedings A'},
        {'url': 'https://example.org/proceedings-f', 'annotation': ''},
    ],
    'annotation': '',
    'active': True,
}


@pytest.mark.parametrize('user', [
    None,
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_get_all_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == {}


def test_get_all_fsdata_no_permissions():
    set_sample_base_data()
    set_sample_public_data()
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
            'public': None,
            'protected': None,
        }
    }


def test_get_all_fsdata_filters_inactive_fsen():
    set_sample_base_data(fs='Informatik')
    set_sample_public_data(fs='Informatik')
    set_sample_protected_data(fs='Informatik')
    set_sample_base_data(fs='Metaphysik-Astrologie')
    set_sample_public_data(fs='Metaphysik-Astrologie')
    set_sample_protected_data(fs='Metaphysik-Astrologie')
    set_sample_base_data(fs='Inactive')
    set_sample_public_data(fs='Inactive')
    set_sample_protected_data(fs='Inactive')
    client.put('/api/v1/data/Inactive/base', json={**SAMPLE_BASE_DATA, 'active': False},
               headers=get_auth_header(client, ADMIN))
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
            'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
            'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        },
        'Metaphysik-Astrologie': {
            'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
            'public': None,
            'protected': None,
        }
    }


def test_get_all_fsdata_multiple_fs():
    set_sample_base_data(fs='Informatik')
    set_sample_public_data(fs='Informatik')
    set_sample_protected_data(fs='Informatik')
    set_sample_base_data(fs='Metaphysik-Astrologie')
    set_sample_public_data(fs='Metaphysik-Astrologie')
    set_sample_protected_data(fs='Metaphysik-Astrologie')
    response = client.get('/api/v1/data', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
            'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
            'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        },
        'Metaphysik-Astrologie': {
            'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
            'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
            'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        }
    }


def test_get_all_fsdata_limit_date():
    with freeze_time("2023-04-04T10:00:00Z"):
        set_sample_base_data(fs='Informatik')
        set_sample_public_data(fs='Informatik')
        set_sample_protected_data(fs='Informatik')
        set_sample_base_data(fs='Metaphysik-Astrologie')
        set_sample_public_data(fs='Metaphysik-Astrologie')
        set_sample_protected_data(fs='Metaphysik-Astrologie')

    modified_base_data = {**SAMPLE_BASE_DATA, 'annotation': 'Warning! Do not use!', 'financial_year_override': None}
    modified_public_data = {**SAMPLE_PUBLIC_DATA, 'email': 'foo@bar.xyz'}
    modified_protected_data = {**SAMPLE_PROTECTED_DATA, 'iban': 'DE0123456789'}
    with freeze_time("2023-05-05T10:00:00Z"):
        response = client.put('/api/v1/data/Informatik/base', json=modified_base_data, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
        response = client.put('/api/v1/data/Informatik/public', json=modified_public_data, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
        response = client.put('/api/v1/data/Informatik/protected', json=modified_protected_data, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200

    with freeze_time("2023-06-06T10:00:00Z"):
        response = client.get('/api/v1/data/2023-05-01', headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
        assert response.json() == {
            'Informatik': {
                'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
                'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
                'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
            },
            'Metaphysik-Astrologie': {
                'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
                'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
                'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
            }
        }
        response = client.get('/api/v1/data/2023-06-01', headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
        assert response.json() == {
            'Informatik': {
                'base': {'data': modified_base_data, 'is_latest': True},
                'public': {'data': modified_public_data, 'is_latest': True},
                'protected': {'data': modified_protected_data, 'is_latest': True},
            },
            'Metaphysik-Astrologie': {
                'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
                'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
                'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
            }
        }


def test_get_all_fsdata_only_public_data_no_protected_data():
    set_sample_base_data()
    set_sample_public_data()
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_INFO_READ))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'base': {'data': SAMPLE_BASE_DATA, 'is_latest': True},
            'public': {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True},
            'protected': None,
        }
    }


def test_get_all_fsdata_only_protected_data_present():
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'base': None,
            'public': None,
            'protected': {'data': SAMPLE_PROTECTED_DATA, 'is_latest': True},
        }
    }


@pytest.mark.parametrize('user', [
    None,
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_get_base_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data/Informatik/base', headers=get_auth_header(client, user))
    assert response.status_code == 404


def test_set_and_get_base_fsdata():
    response = client.put('/api/v1/data/Informatik/base', json=SAMPLE_BASE_DATA,
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/base', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {'data': SAMPLE_BASE_DATA, 'is_latest': True}


@freeze_time("2023-04-04T10:00:00Z")
def test_set_and_approve_base_fsdata():
    response = client.put('/api/v1/data/Informatik/base', json=SAMPLE_BASE_DATA,
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/base/history', headers=get_auth_header(client, ADMIN))
    data_id = response.json()[0]['id']
    response = client.post(f'/api/v1/data/approve/base/{data_id}', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/base/history', headers=get_auth_header(client, ADMIN))
    assert response.json() == [{
        **SAMPLE_BASE_DATA,
        'id': 1,
        'user': ADMIN,
        'timestamp': '2023-04-04T10:00:00+00:00',
        'approval_timestamp': '2023-04-04T10:00:00+00:00',
        'approved': True,
        'approved_by': ADMIN,
    }]


def test_base_fsdata_history_as_admin():
    data1 = SAMPLE_BASE_DATA
    data2 = {**SAMPLE_BASE_DATA, 'annotation': 'Warning! Do not use!', 'financial_year_override': None}
    with freeze_time("2023-04-04T10:00:00Z"):
        response = client.put('/api/v1/data/Informatik/base', json=data1, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
    with freeze_time("2023-07-07T17:00:00Z"):
        response = client.put('/api/v1/data/Informatik/base', json=data2, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/base/history', headers=get_auth_header(client, ADMIN))
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


def test_base_fsdata_history_unauthorized():
    response = client.get('/api/v1/data/Informatik/base/history', headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401


def test_base_fsdata_history_does_not_exist():
    response = client.get('/api/v1/data/Metaphysik-Astrologie/base/history', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


@pytest.mark.parametrize('user', [
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_get_public_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data/Informatik/public', headers=get_auth_header(client, user))
    assert response.status_code == 404


@pytest.mark.parametrize('user,fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_ALL, 'Metaphysik-Astrologie'],
])
def test_get_public_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.get(f'/api/v1/data/{fs}/public', headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user,fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_READ, 'Informatik'],
    [USER_INFO_ALL, 'Metaphysik-Astrologie'],
])
def test_set_public_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.put(f'/api/v1/data/{fs}/public', json=SAMPLE_PUBLIC_DATA, headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    USER_INFO_ALL,
    ADMIN,
])
def test_set_and_get_public_fsdata(user):
    response = client.put('/api/v1/data/Informatik/public', json=SAMPLE_PUBLIC_DATA,
                          headers=get_auth_header(client, user))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/public', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == {'data': SAMPLE_PUBLIC_DATA, 'is_latest': True}


@freeze_time("2023-04-04T10:00:00Z")
def test_set_and_approve_public_fsdata():
    response = client.put('/api/v1/data/Informatik/public', json=SAMPLE_PUBLIC_DATA,
                          headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/public/history', headers=get_auth_header(client, ADMIN))
    data_id = response.json()[0]['id']
    response = client.post(f'/api/v1/data/approve/public/{data_id}', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/public/history', headers=get_auth_header(client, ADMIN))
    assert response.json() == [{
        **SAMPLE_PUBLIC_DATA,
        'id': 1,
        'user': USER_INFO_ALL,
        'timestamp': '2023-04-04T10:00:00+00:00',
        'approval_timestamp': '2023-04-04T10:00:00+00:00',
        'approved': True,
        'approved_by': ADMIN,
    }]


def test_public_fsdata_history_as_admin():
    data1 = SAMPLE_PUBLIC_DATA
    data2 = {**SAMPLE_PUBLIC_DATA, 'website': 'https://changed.xyz', }
    with freeze_time("2023-04-04T10:00:00Z"):
        response = client.put('/api/v1/data/Informatik/public', json=data1, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200
    with freeze_time("2023-07-07T17:00:00Z"):
        response = client.put('/api/v1/data/Informatik/public', json=data2, headers=get_auth_header(client, ADMIN))
        assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik/public/history', headers=get_auth_header(client, ADMIN))
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


def test_public_fsdata_history_unauthorized():
    response = client.get('/api/v1/data/Informatik/public/history', headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401


def test_public_fsdata_history_does_not_exist():
    response = client.get('/api/v1/data/Metaphysik-Astrologie/public/history', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_protected_fsdata_history_does_not_exist():
    response = client.get('/api/v1/data/Metaphysik-Astrologie/protected/history',
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_approve_public_fsdata_does_not_exist():
    response = client.post('/api/v1/data/approve/public/69', headers=get_auth_header(client, ADMIN))
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


def set_sample_base_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}/base', json=SAMPLE_BASE_DATA, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


def set_sample_public_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}/public', json=SAMPLE_PUBLIC_DATA, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


def set_sample_protected_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
