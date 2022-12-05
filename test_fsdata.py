import pytest
from fastapi.testclient import TestClient

from conftest import get_auth_header
from main import app

client = TestClient(app)


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
    obj = {
        'email': 'informatik@example.org',
        'phone': '+49228730123',
        'website': 'https://example.org',
        'address': 'Regina-Pacis-Weg 3\n532113 Bonn',
        'other': {},
    }
    response = client.put(f'/api/v1/data/{fs}', json=obj, headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    'user3',
    'admin',
])
def test_set_and_get_fsdata(user):
    obj = {
        'email': 'informatik@example.org',
        'phone': '+49228730123',
        'website': 'https://example.org',
        'address': 'Regina-Pacis-Weg 3\n532113 Bonn',
        'other': {},
    }
    response = client.put('/api/v1/data/Informatik', json=obj, headers=get_auth_header(client, user))
    assert response.status_code == 200

    response = client.get('/api/v1/data/Informatik', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert response.json() == obj


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
    obj = {
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
    response = client.put(f'/api/v1/data/{fs}/protected', json=obj, headers=get_auth_header(client, user))
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    'user3',
    'admin',
])
def test_set_and_get_protected_fsdata(user: str):
    obj = {
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
    response = client.put('/api/v1/data/Informatik/protected', json=obj, headers=get_auth_header(client, user))
    assert response.status_code == 200

    queryresponse = client.get('/api/v1/data/Informatik/protected', headers=get_auth_header(client, user))
    assert queryresponse.status_code == 200
    assert queryresponse.json() == obj
