from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from conftest import get_auth_header
from main import app

client = TestClient(app)


def test_login():
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'password'})
    assert response.status_code == 200
    response_json = response.json()
    assert 'access_token' in response_json
    assert response_json['token_type'] == 'bearer'


def test_create_user():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik', 'level': 2}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    usersresponse = client.get('/api/v1/user', headers=get_auth_header(client, 'admin'))
    users = usersresponse.json()
    assert users['user-to-create']['created_by'] == 'admin'


def test_create_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200


@pytest.mark.parametrize('username,target_fs,target_level', [
    ['user', 'Informatik', 1],
    ['user2', 'Informatik', 2],
    ['user2', 'Metaphysik-Astrologie', 1],
])
def test_create_user_missing_permission(username, target_fs, target_level):
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': target_fs, 'level': target_level}],
                                 },
                           headers=get_auth_header(client, username))
    assert response.status_code == 401


def test_create_admin_user_missing_permission():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, 'user'))
    assert response.status_code == 401


def test_create_user_no_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik', 'level': 1}],
                                 },
                           headers=get_auth_header(client, 'user2'))
    assert response.status_code == 200


def test_set_user_permissions():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie', 'level': 2}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    fsen = [p['fs'] for p in response.json()['permissions']]
    assert 'Informatik' not in fsen
    assert 'Geographie' in fsen


def test_promote_user_to_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json()['admin']
    assert not response.json()['permissions']


def test_get_users():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {
        'admin': {'username': 'admin', 'admin': True, 'created_by': 'root', 'permissions': []},
        'user': {'username': 'user', 'admin': False, 'created_by': 'root', 'permissions': []},
        'user2': {'username': 'user2', 'admin': False, 'created_by': 'root',
                  'permissions': [{'fs': 'Informatik', 'level': 1}]},
        'user3': {'username': 'user3', 'admin': False, 'created_by': 'root',
                  'permissions': [{'fs': 'Informatik', 'level': 2}]},
    }


@pytest.mark.parametrize('username,response_data', [
    ['admin', {'username': 'admin', 'admin': True, 'created_by': 'root', 'permissions': []}],
    ['user', {'username': 'user', 'admin': False, 'created_by': 'root', 'permissions': []}],
    ['user2',
     {'username': 'user2', 'admin': False, 'created_by': 'root', 'permissions': [{'fs': 'Informatik', 'level': 1}]}],
    ['user3',
     {'username': 'user3', 'admin': False, 'created_by': 'root', 'permissions': [{'fs': 'Informatik', 'level': 2}]}],
])
def test_who_am_i(username: str, response_data: Dict[str, Any]):
    response = client.get('/api/v1/user/me', headers=get_auth_header(client, username))
    assert response.status_code == 200
    assert response.json() == response_data


def test_change_own_password():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'password', 'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'user'))
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_admin_change_other_password():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_change_other_password_without_admin():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'user2'))
    assert response.status_code == 401
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'password'})
    assert 'access_token' in response.json()
