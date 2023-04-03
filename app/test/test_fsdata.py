import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.test.conftest import get_auth_header

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
    'user2',
    'user3',
    'admin',
])
def test_get_all_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == {}


def test_get_all_fsdata_no_permissions():
    set_sample_data()
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, 'user'))
    assert response.status_code == 200
    assert response.json() == {}


def test_get_all_fsdata():
    set_sample_data(fs='Informatik')
    set_sample_protected_data(fs='Informatik')
    set_sample_data(fs='Metaphysik-Astrologie')
    set_sample_protected_data(fs='Metaphysik-Astrologie')
    response = client.get('/api/v1/data', headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': SAMPLE_DATA,
            'protected_data': SAMPLE_PROTECTED_DATA
        }
    }


def test_get_all_fsdata_multiple_fs():
    set_sample_data(fs='Informatik')
    set_sample_protected_data(fs='Informatik')
    set_sample_data(fs='Metaphysik-Astrologie')
    set_sample_protected_data(fs='Metaphysik-Astrologie')
    response = client.get('/api/v1/data', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': SAMPLE_DATA,
            'protected_data': SAMPLE_PROTECTED_DATA
        },
        'Metaphysik-Astrologie': {
            'data': SAMPLE_DATA,
            'protected_data': SAMPLE_PROTECTED_DATA
        }
    }


def test_get_all_fsdata_only_data_no_protected_data():
    set_sample_data()
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, 'user2'))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': SAMPLE_DATA,
            'protected_data': None,
        }
    }


def test_get_all_fsdata_only_protected_data_present():
    set_sample_protected_data()
    response = client.get('/api/v1/data', headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {
        'Informatik': {
            'data': None,
            'protected_data': SAMPLE_PROTECTED_DATA
        }
    }


@pytest.mark.parametrize('user', [
    'user2',
    'user3',
    'admin',
])
def test_get_fsdata_no_data_set(user: str):
    response = client.get('/api/v1/data/Informatik', headers=get_auth_header(client, user))
    assert response.status_code == 404


@pytest.mark.parametrize('user,fs', [
    ['user', 'Informatik'],
    ['user3', 'Metaphysik-Astrologie'],
])
def test_get_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.get(f'/api/v1/data/{fs}', headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user,fs', [
    ['user', 'Informatik'],
    ['user2', 'Informatik'],
    ['user3', 'Metaphysik-Astrologie'],
])
def test_set_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.put(f'/api/v1/data/{fs}', json=SAMPLE_DATA, headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    'user3',
    'admin',
])
def test_set_and_get_fsdata(user):
    response = client.put('/api/v1/data/Informatik', json=SAMPLE_DATA, headers=get_auth_header(client, user))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == SAMPLE_DATA


@pytest.mark.parametrize('user', [
    'user3',
    'admin',
])
def test_get_protected_fsdata_no_data_set(user):
    queryresponse = client.get('/api/v1/data/Informatik/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 404


@pytest.mark.parametrize('user,fs', [
    ['user', 'Informatik'],
    ['user2', 'Informatik'],
    ['user3', 'Metaphysik-Astrologie'],
])
def test_get_protected_fsdata_insufficient_permissions(user: str, fs: str):
    queryresponse = client.get(f'/api/v1/data/{fs}/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 401


@pytest.mark.parametrize('user,fs', [
    ['user', 'Informatik'],
    ['user2', 'Informatik'],
    ['user3', 'Metaphysik-Astrologie'],
])
def test_set_protected_fsdata_insufficient_permissions(user: str, fs: str):
    response = client.put(f'/api/v1/data/{fs}/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    'user3',
    'admin',
])
def test_set_and_get_protected_fsdata(user: str):
    response = client.put('/api/v1/data/Informatik/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, user))
    assert response.status_code == 200

    queryresponse = client.get('/api/v1/data/Informatik/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 200
    assert queryresponse.json() == SAMPLE_PROTECTED_DATA


def set_sample_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}', json=SAMPLE_DATA, headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200


def set_sample_protected_data(fs='Informatik'):
    response = client.put(f'/api/v1/data/{fs}/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
