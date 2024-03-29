from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.test.conftest import get_auth_header

client = TestClient(app)

PERMISSIONS_LEVEL_0 = {
    'read_files': False,
    'read_permissions': False,
    'write_permissions': False,
    'read_public_data': False,
    'write_public_data': False,
    'read_protected_data': False,
    'write_protected_data': False,
    'submit_payout_request': False,
    'locked': False,
}

PERMISSIONS_LEVEL_1 = {
    'read_files': True,
    'read_permissions': True,
    'write_permissions': False,
    'read_public_data': True,
    'write_public_data': False,
    'read_protected_data': False,
    'write_protected_data': False,
    'submit_payout_request': False,
    'locked': False,
}

PERMISSIONS_LEVEL_2 = {
    'read_files': True,
    'read_permissions': True,
    'write_permissions': True,
    'read_public_data': True,
    'write_public_data': True,
    'read_protected_data': True,
    'write_protected_data': True,
    'submit_payout_request': True,
    'locked': False,
}


def test_login():
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'password'})
    assert response.status_code == 200
    response_json = response.json()
    assert 'access_token' in response_json
    assert response_json['token_type'] == 'bearer'


def test_invalid_login_wrong_password():
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'wrong-password'})
    assert response.status_code == 401
    assert response.json() == {
        'detail': 'Incorrect username or password',
    }


def test_invalid_login_wrong_username():
    response = client.post('/api/v1/token', data={'username': 'user-does-not-exist', 'password': 'password'})
    assert response.status_code == 401
    assert response.json() == {
        'detail': 'Incorrect username or password',
    }


def test_create_user():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik',
                                                  'locked': False,
                                                  'read_files': True,
                                                  'read_permissions': True,
                                                  'write_permissions': True,
                                                  'read_public_data': True,
                                                  'write_public_data': True,
                                                  'read_protected_data': True,
                                                  'write_protected_data': True,
                                                  'submit_payout_request': True}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    usersresponse = client.get('/api/v1/user', headers=get_auth_header(client, 'admin'))
    users = usersresponse.json()
    assert users['user-to-create']['created_by'] == 'admin'
    assert not users['user-to-create']['permissions'][0]['locked']


def test_create_user_locked_permissions_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik',
                                                  'read_files': True,
                                                  'read_permissions': True,
                                                  'write_permissions': True,
                                                  'read_public_data': True,
                                                  'write_public_data': True,
                                                  'read_protected_data': True,
                                                  'write_protected_data': True,
                                                  'submit_payout_request': True,
                                                  'locked': True}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    usersresponse = client.get('/api/v1/user', headers=get_auth_header(client, 'admin'))
    users = usersresponse.json()
    assert users['user-to-create']['created_by'] == 'admin'
    assert users['user-to-create']['permissions'][0]['locked']


def test_create_existing_user_fails():
    response = client.post('/api/v1/user/create',
                           json={'username': 'admin',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik',
                                                  'locked': False,
                                                  'read_files': True,
                                                  'read_permissions': True,
                                                  'write_permissions': True,
                                                  'read_public_data': True,
                                                  'write_public_data': True,
                                                  'read_protected_data': True,
                                                  'write_protected_data': True,
                                                  'submit_payout_request': True}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 409
    assert response.json() == {
        'detail': 'Already exists',
    }


def test_create_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200


@pytest.mark.parametrize('username,target_fs', [
    ['user', 'Informatik'],
    ['user2', 'Informatik'],
    ['user2', 'Metaphysik-Astrologie'],
])
def test_create_user_missing_permission(username, target_fs):
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': target_fs,
                                                  **PERMISSIONS_LEVEL_1}],
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


def test_create_user_bad_permission_list():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': [
                                     {'fs': 'Informatik',
                                      **PERMISSIONS_LEVEL_2},
                                     {'fs': 'Informatik',
                                      **PERMISSIONS_LEVEL_1},
                                 ],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 400


def test_create_user_empty_username():
    response = client.post('/api/v1/user/create',
                           json={'username': '',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 422


def test_create_user_empty_password():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': '',
                                 'admin': False,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 422


def test_create_user_no_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik',
                                                  **PERMISSIONS_LEVEL_2}],
                                 },
                           headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200


def test_create_user_no_admin_locked_fails():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik',
                                                  **PERMISSIONS_LEVEL_2,
                                                  'locked': True,
                                                  }],
                                 },
                           headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401


def test_set_user_permissions_as_admin_invalid_user():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'does-not-exist',
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie',
                                                  **PERMISSIONS_LEVEL_2}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 404


def test_set_user_permissions_as_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie',
                                                  **PERMISSIONS_LEVEL_2}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    fsen = [p['fs'] for p in response.json()['permissions']]
    assert 'Informatik' not in fsen
    assert 'Geographie' in fsen


def test_set_user_permissions_0_as_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie',
                                                  **PERMISSIONS_LEVEL_0}],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    fsen = [p['fs'] for p in response.json()['permissions']]
    assert 'Geographie' not in fsen


def test_set_user_permissions_as_admin_bad_permission_list():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': False,
                                 'permissions': [
                                     {'fs': 'Geographie',
                                      **PERMISSIONS_LEVEL_2},
                                     {'fs': 'Geographie',
                                      **PERMISSIONS_LEVEL_1},
                                 ],
                                 },
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 400


def test_add_user_permission_as_user_missing_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'does-not-exist',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_1}],
                            },
                            headers=get_auth_header(client, 'user3'))
    assert response.status_code == 404


def test_add_user_permission_as_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_1}],
                            },
                            headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json()['permissions'] == [{'fs': 'Informatik',
                                               **PERMISSIONS_LEVEL_1}]


def test_add_second_user_permission_as_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user3',
                                'permissions': [{'fs': 'Geographie',
                                                 **PERMISSIONS_LEVEL_1}],
                            },
                            headers=get_auth_header(client, 'user5'))
    assert response.status_code == 200
    assert response.json()['permissions'] == [{'fs': 'Geographie',
                                               **PERMISSIONS_LEVEL_1},
                                              {'fs': 'Informatik',
                                               **PERMISSIONS_LEVEL_2}]


def test_change_user_permission_level_as_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user2',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2}],
                            },
                            headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json()['permissions'] == [{'fs': 'Informatik',
                                               **PERMISSIONS_LEVEL_2}]


def test_change_user_permission_level_set_locked_fails():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user2',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2,
                                                 'locked': True,
                                                 }],
                            },
                            headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401


@pytest.mark.parametrize('locked_value', [
    True, False
])
def test_change_user_permission_level_is_locked_fails(locked_value):
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user2',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_1,
                                                 'locked': locked_value,
                                                 }],
                            },
                            headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user2',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2,
                                                 'locked': True,
                                                 }],
                            },
                            headers=get_auth_header(client, 'user3'))
    assert response.status_code == 401


def test_set_user_permissions_as_user_not_allowed():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'user',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2}],
                            },
                            headers=get_auth_header(client, 'user2'))
    assert response.status_code == 401


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


def test_get_users_as_admin():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    assert response.json() == {'admin': {'admin': True,
                                         'created_by': 'root',
                                         'permissions': [],
                                         'username': 'admin'},
                               'user': {'admin': False,
                                        'created_by': 'root',
                                        'permissions': [],
                                        'username': 'user'},
                               'user2': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user2'},
                               'user3': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user3'},
                               'user4': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Geographie',
                                                          **PERMISSIONS_LEVEL_1},
                                                         {'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user4'},
                               'user5': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Geographie',
                                                          **PERMISSIONS_LEVEL_2},
                                                         {'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user5'}}


def test_get_users_as_user_with_write_permission():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, 'user3'))
    assert response.status_code == 200
    assert response.json() == {'user2': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user2'},
                               'user3': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user3'},
                               'user4': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user4'},
                               'user5': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user5'}}


def test_get_users_as_user_with_read_permission():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, 'user2'))
    assert response.status_code == 200
    assert response.json() == {'user2': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user2'},
                               'user3': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user3'},
                               'user4': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user4'},
                               'user5': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user5'}}


def test_get_users_as_user_with_multiple_write_permissions():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, 'user5'))
    assert response.status_code == 200
    assert response.json() == {'user2': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user2'},
                               'user3': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user3'},
                               'user4': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Geographie',
                                                          **PERMISSIONS_LEVEL_1},
                                                         {'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_1}],
                                         'username': 'user4'},
                               'user5': {'admin': False,
                                         'created_by': 'root',
                                         'permissions': [{'fs': 'Geographie',
                                                          **PERMISSIONS_LEVEL_2},
                                                         {'fs': 'Informatik',
                                                          **PERMISSIONS_LEVEL_2}],
                                         'username': 'user5'}}


@pytest.mark.parametrize('username,response_data', [
    ['admin', {'username': 'admin', 'admin': True, 'created_by': 'root', 'permissions': []}],
    ['user', {'username': 'user', 'admin': False, 'created_by': 'root', 'permissions': []}],
    ['user2',
     {'username': 'user2', 'admin': False, 'created_by': 'root', 'permissions': [{'fs': 'Informatik',
                                                                                  'locked': False,
                                                                                  'read_files': True,
                                                                                  'read_permissions': True,
                                                                                  'write_permissions': False,
                                                                                  'read_public_data': True,
                                                                                  'write_public_data': False,
                                                                                  'read_protected_data': False,
                                                                                  'write_protected_data': False,
                                                                                  'submit_payout_request': False,
                                                                                  }]}],
    ['user3',
     {'username': 'user3', 'admin': False, 'created_by': 'root', 'permissions': [{'fs': 'Informatik',
                                                                                  'locked': False,
                                                                                  'read_files': True,
                                                                                  'read_permissions': True,
                                                                                  'write_permissions': True,
                                                                                  'read_public_data': True,
                                                                                  'write_public_data': True,
                                                                                  'read_protected_data': True,
                                                                                  'write_protected_data': True,
                                                                                  'submit_payout_request': True,
                                                                                  }]}],
])
def test_who_am_i(username: str, response_data: dict[str, Any]):
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


def test_change_own_password_wrong_old_password_fails():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'wrong-password', 'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'user'))
    assert response.status_code == 401
    assert response.json() == {
        'detail': 'Wrong current password',
    }


def test_change_own_password_new_password_empty_fails():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'password', 'new_password': ''},
                           headers=get_auth_header(client, 'user'))
    assert response.status_code == 422
    assert response.json()['detail'][0]['msg'] == 'String should have at least 8 characters'


def test_admin_change_other_password():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_admin_change_other_password_user_does_not_exist():
    response = client.post('/api/v1/user/password/invalid-user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'admin'))
    assert response.status_code == 404
    assert response.json() == {
        'detail': 'That user does not exist',
    }


def test_change_other_password_without_admin():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, 'user2'))
    assert response.status_code == 401
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'password'})
    assert 'access_token' in response.json()
