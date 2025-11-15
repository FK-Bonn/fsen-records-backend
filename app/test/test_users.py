import re
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.database import get_session
from app.main import app
from app.main import subapp
from app.routers.token import create_access_token, new_token
from app.test.conftest import get_auth_header, USER_NO_PERMS, USER_INFO_READ, USER_INFO_GEO_ALL, USER_INFO_GEO_READ, \
    USER_INFO_ALL, ADMIN, fake_session, USER_OIDC

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session

PERMISSIONS_LEVEL_0 = {
    'read_files': False,
    'read_permissions': False,
    'write_permissions': False,
    'read_public_data': False,
    'write_public_data': False,
    'read_protected_data': False,
    'write_protected_data': False,
    'submit_payout_request': False,
    'upload_proceedings': False,
    'delete_proceedings': False,
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
    'upload_proceedings': False,
    'delete_proceedings': False,
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
    'upload_proceedings': True,
    'delete_proceedings': True,
    'locked': False,
}


def test_login():
    response = client.post('/api/v1/token', data={'username': USER_NO_PERMS, 'password': 'password'})
    assert response.status_code == 200
    response_json = response.json()
    assert 'access_token' in response_json
    assert response_json['token_type'] == 'bearer'


def test_invalid_login_wrong_password():
    response = client.post('/api/v1/token', data={'username': USER_NO_PERMS, 'password': 'wrong-password'})
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


def test_fake_sso_login_auth_page():
    response = client.get('/api/v1/fake-sso/realms/fake-realm/protocol/openid-connect/auth', follow_redirects=False,
                          params={'response_type': 'code', 'client_id': 'client-id', 'redirect_uri': 'http://my-url'})
    assert response.status_code == 200


def test_fake_sso_login_auth():
    response = client.post('/api/v1/fake-sso/realms/fake-realm/protocol/openid-connect/auth', follow_redirects=False,
                           params={'response_type': 'code', 'client_id': 'client-id', 'redirect_uri': 'http://my-url'},
                           data={'username': 'user', 'given_name': 'Test', 'family_name': 'User'})
    assert response.status_code == 307
    assert re.match(r'http://my-url\?session_state=fake-session-state&state=None&iss=fake-iss&code=[A-Z]{6}',
                    response.headers['Location'])


def get_code():
    response = client.post('/api/v1/fake-sso/realms/fake-realm/protocol/openid-connect/auth', follow_redirects=False,
                           params={'response_type': 'code', 'client_id': 'client-id', 'redirect_uri': 'http://my-url'},
                           data={'username': 'user', 'given_name': 'Test', 'family_name': 'User'})
    code = response.headers['Location'][-6:]
    return code


def get_tokens(code):
    response = client.post('/api/v1/fake-sso/realms/fake-realm/protocol/openid-connect/token',
                           follow_redirects=False,
                           data={'grant_type': 'authorization_code', 'client_id': 'client-id', 'code': code,
                                 'redirect_uri': 'http://my-url'})
    assert response.status_code == 200
    response_json = response.json()
    return response_json['access_token'], response_json['refresh_token']


def test_fake_sso_login_token():
    code = get_code()

    access_token, refresh_token = get_tokens(code)

    assert access_token
    assert refresh_token


def test_fake_sso_login_refresh():
    code = get_code()
    _, refresh_token = get_tokens(code)

    response = client.post('/api/v1/fake-sso/realms/fake-realm/protocol/openid-connect/token',
                           follow_redirects=False,
                           data={'grant_type': 'refresh_token', 'client_id': 'client-id',
                                 'refresh_token': refresh_token})
    assert response.status_code == 200
    response_json = response.json()
    assert response_json['access_token']
    assert response_json['refresh_token']


def test_fake_sso_login_logout():
    response = client.get('/api/v1/fake-sso/realms/fake-realm/protocol/openid-connect/logout',
                          follow_redirects=False,
                          params={'client_id': 'client-id', 'post_logout_redirect_uri': 'http://my-url'})
    assert response.status_code == 307
    assert response.headers['Location'] == 'http://my-url'


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
                                                  'submit_payout_request': True,
                                                  'upload_proceedings': True,
                                                  'delete_proceedings': True,
                                                  }],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    usersresponse = client.get('/api/v1/user', headers=get_auth_header(client, ADMIN))
    users = usersresponse.json()
    assert users['user-to-create']['created_by'] == ADMIN
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
                                                  'upload_proceedings': True,
                                                  'delete_proceedings': True,
                                                  'locked': True}],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    usersresponse = client.get('/api/v1/user', headers=get_auth_header(client, ADMIN))
    users = usersresponse.json()
    assert users['user-to-create']['created_by'] == ADMIN
    assert users['user-to-create']['permissions'][0]['locked']


def test_create_existing_user_fails():
    response = client.post('/api/v1/user/create',
                           json={'username': ADMIN,
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
                                                  'submit_payout_request': True,
                                                  'upload_proceedings': True,
                                                  'delete_proceedings': True,
                                                  }],
                                 },
                           headers=get_auth_header(client, ADMIN))
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
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


@pytest.mark.parametrize('username,target_fs', [
    [USER_NO_PERMS, 'Informatik'],
    [USER_INFO_READ, 'Informatik'],
    [USER_INFO_READ, 'Metaphysik-Astrologie'],
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
                           headers=get_auth_header(client, USER_NO_PERMS))
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
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 400


def test_create_user_empty_username():
    response = client.post('/api/v1/user/create',
                           json={'username': '',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 422


def test_create_user_empty_password():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': '',
                                 'admin': False,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 422


def test_create_user_no_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': [{'fs': 'Informatik',
                                                  **PERMISSIONS_LEVEL_2}],
                                 },
                           headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401


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
                           headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401


def test_set_user_permissions_as_admin_invalid_user():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'does-not-exist',
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie',
                                                  **PERMISSIONS_LEVEL_2}],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


def test_set_user_permissions_as_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': USER_NO_PERMS,
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie',
                                                  **PERMISSIONS_LEVEL_2}],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    fsen = [p['fs'] for p in response.json()['permissions']]
    assert 'Informatik' not in fsen
    assert 'Geographie' in fsen


def test_set_user_permissions_0_as_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': USER_NO_PERMS,
                                 'admin': False,
                                 'permissions': [{'fs': 'Geographie',
                                                  **PERMISSIONS_LEVEL_0}],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    fsen = [p['fs'] for p in response.json()['permissions']]
    assert 'Geographie' not in fsen


def test_set_user_permissions_as_admin_bad_permission_list():
    response = client.post('/api/v1/user/permissions',
                           json={'username': USER_NO_PERMS,
                                 'admin': False,
                                 'permissions': [
                                     {'fs': 'Geographie',
                                      **PERMISSIONS_LEVEL_2},
                                     {'fs': 'Geographie',
                                      **PERMISSIONS_LEVEL_1},
                                 ],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 400


def test_add_user_permission_as_user_missing_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': 'does-not-exist',
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_1}],
                            },
                            headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 404


def test_add_user_permission_as_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_NO_PERMS,
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_1}],
                            },
                            headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json()['permissions'] == [{'fs': 'Informatik',
                                               **PERMISSIONS_LEVEL_1}]


def test_add_second_user_permission_as_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_INFO_ALL,
                                'permissions': [{'fs': 'Geographie',
                                                 **PERMISSIONS_LEVEL_1}],
                            },
                            headers=get_auth_header(client, USER_INFO_GEO_ALL))
    assert response.status_code == 200
    assert response.json()['permissions'] == [{'fs': 'Geographie',
                                               **PERMISSIONS_LEVEL_1},
                                              {'fs': 'Informatik',
                                               **PERMISSIONS_LEVEL_2}]


def test_change_user_permission_level_as_user():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_INFO_READ,
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2}],
                            },
                            headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json()['permissions'] == [{'fs': 'Informatik',
                                               **PERMISSIONS_LEVEL_2}]


def test_change_user_permission_level_set_locked_fails():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_INFO_READ,
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2,
                                                 'locked': True,
                                                 }],
                            },
                            headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401


@pytest.mark.parametrize('locked_value', [
    True, False
])
def test_change_user_permission_level_is_locked_fails(locked_value):
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_INFO_READ,
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_1,
                                                 'locked': locked_value,
                                                 }],
                            },
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_INFO_READ,
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2,
                                                 'locked': True,
                                                 }],
                            },
                            headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401


def test_set_user_permissions_as_user_not_allowed():
    response = client.patch('/api/v1/user/permissions',
                            json={
                                'username': USER_NO_PERMS,
                                'permissions': [{'fs': 'Informatik',
                                                 **PERMISSIONS_LEVEL_2}],
                            },
                            headers=get_auth_header(client, USER_INFO_READ))
    assert response.status_code == 401


def test_promote_user_to_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': USER_NO_PERMS,
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json()['admin']
    assert not response.json()['permissions']


def test_get_users_as_admin():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {
        ADMIN: {'admin': True,
                'created_by': 'root',
                'permissions': [],
                'username': ADMIN,
                'full_name': ADMIN},
        USER_NO_PERMS: {'admin': False,
                        'created_by': 'root',
                        'permissions': [],
                        'username': USER_NO_PERMS,
                        'full_name': USER_NO_PERMS},
        USER_INFO_READ: {'admin': False,
                         'created_by': 'root',
                         'permissions': [{'fs': 'Informatik',
                                          **PERMISSIONS_LEVEL_1}],
                         'username': USER_INFO_READ,
                         'full_name': USER_INFO_READ},
        USER_INFO_ALL: {'admin': False,
                        'created_by': 'root',
                        'permissions': [{'fs': 'Informatik',
                                         **PERMISSIONS_LEVEL_2}],
                        'username': USER_INFO_ALL,
                        'full_name': USER_INFO_ALL},
        USER_INFO_GEO_READ: {'admin': False,
                             'created_by': 'root',
                             'permissions': [{'fs': 'Geographie',
                                              **PERMISSIONS_LEVEL_1},
                                             {'fs': 'Informatik',
                                              **PERMISSIONS_LEVEL_1}],
                             'username': USER_INFO_GEO_READ,
                             'full_name': USER_INFO_GEO_READ},
        USER_INFO_GEO_ALL: {'admin': False,
                            'created_by': 'root',
                            'permissions': [{'fs': 'Geographie',
                                             **PERMISSIONS_LEVEL_2},
                                            {'fs': 'Informatik',
                                             **PERMISSIONS_LEVEL_2}],
                            'username': USER_INFO_GEO_ALL,
                            'full_name': USER_INFO_GEO_ALL},
        USER_OIDC: {'admin': False,
                            'created_by': 'oidc',
                            'permissions': [],
                            'username': USER_OIDC,
                            'full_name': USER_OIDC},
    }


def test_get_users_as_user_with_write_permission():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        USER_INFO_READ: {'admin': False,
                         'created_by': 'root',
                         'permissions': [{'fs': 'Informatik',
                                          **PERMISSIONS_LEVEL_1}],
                         'username': USER_INFO_READ,
                         'full_name': USER_INFO_READ},
        USER_INFO_ALL: {'admin': False,
                        'created_by': 'root',
                        'permissions': [{'fs': 'Informatik',
                                         **PERMISSIONS_LEVEL_2}],
                        'username': USER_INFO_ALL,
                        'full_name': USER_INFO_ALL},
        USER_INFO_GEO_READ: {'admin': False,
                             'created_by': 'root',
                             'permissions': [{'fs': 'Informatik',
                                              **PERMISSIONS_LEVEL_1}],
                             'username': USER_INFO_GEO_READ,
                             'full_name': USER_INFO_GEO_READ},
        USER_INFO_GEO_ALL: {'admin': False,
                            'created_by': 'root',
                            'permissions': [{'fs': 'Informatik',
                                             **PERMISSIONS_LEVEL_2}],
                            'username': USER_INFO_GEO_ALL,
                            'full_name': USER_INFO_GEO_ALL},
    }


def test_get_users_as_user_with_read_permission():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, USER_INFO_READ))
    assert response.status_code == 200
    assert response.json() == {
        USER_INFO_READ: {'admin': False,
                         'created_by': 'root',
                         'permissions': [{'fs': 'Informatik',
                                          **PERMISSIONS_LEVEL_1}],
                         'username': USER_INFO_READ,
                         'full_name': USER_INFO_READ},
        USER_INFO_ALL: {'admin': False,
                        'created_by': 'root',
                        'permissions': [{'fs': 'Informatik',
                                         **PERMISSIONS_LEVEL_2}],
                        'username': USER_INFO_ALL,
                        'full_name': USER_INFO_ALL},
        USER_INFO_GEO_READ: {'admin': False,
                             'created_by': 'root',
                             'permissions': [{'fs': 'Informatik',
                                              **PERMISSIONS_LEVEL_1}],
                             'username': USER_INFO_GEO_READ,
                             'full_name': USER_INFO_GEO_READ},
        USER_INFO_GEO_ALL: {'admin': False,
                            'created_by': 'root',
                            'permissions': [{'fs': 'Informatik',
                                             **PERMISSIONS_LEVEL_2}],
                            'username': USER_INFO_GEO_ALL,
                            'full_name': USER_INFO_GEO_ALL},
    }


def test_get_users_as_user_with_multiple_write_permissions():
    response = client.get('/api/v1/user/', headers=get_auth_header(client, USER_INFO_GEO_ALL))
    assert response.status_code == 200
    assert response.json() == {
        USER_INFO_READ: {'admin': False,
                         'created_by': 'root',
                         'permissions': [{'fs': 'Informatik',
                                          **PERMISSIONS_LEVEL_1}],
                         'username': USER_INFO_READ,
                         'full_name': USER_INFO_READ},
        USER_INFO_ALL: {'admin': False,
                        'created_by': 'root',
                        'permissions': [{'fs': 'Informatik',
                                         **PERMISSIONS_LEVEL_2}],
                        'username': USER_INFO_ALL,
                        'full_name': USER_INFO_ALL},
        USER_INFO_GEO_READ: {'admin': False,
                             'created_by': 'root',
                             'permissions': [{'fs': 'Geographie',
                                              **PERMISSIONS_LEVEL_1},
                                             {'fs': 'Informatik',
                                              **PERMISSIONS_LEVEL_1}],
                             'username': USER_INFO_GEO_READ,
                             'full_name': USER_INFO_GEO_READ},
        USER_INFO_GEO_ALL: {'admin': False,
                            'created_by': 'root',
                            'permissions': [{'fs': 'Geographie',
                                             **PERMISSIONS_LEVEL_2},
                                            {'fs': 'Informatik',
                                             **PERMISSIONS_LEVEL_2}],
                            'username': USER_INFO_GEO_ALL,
                            'full_name': USER_INFO_GEO_ALL},
    }


@pytest.mark.parametrize('username,response_data', [
    [ADMIN,
     {'username': ADMIN, 'full_name': ADMIN, 'admin': True, 'created_by': 'root', 'permissions': []}],
    [USER_NO_PERMS,
     {'username': USER_NO_PERMS, 'full_name': USER_NO_PERMS, 'admin': False, 'created_by': 'root', 'permissions': []}],
    [USER_INFO_READ,
     {'username': USER_INFO_READ, 'full_name': USER_INFO_READ, 'admin': False, 'created_by': 'root',
      'permissions': [{'fs': 'Informatik',
                       'locked': False,
                       'read_files': True,
                       'read_permissions': True,
                       'write_permissions': False,
                       'read_public_data': True,
                       'write_public_data': False,
                       'read_protected_data': False,
                       'write_protected_data': False,
                       'submit_payout_request': False,
                       'upload_proceedings': False,
                       'delete_proceedings': False,
                       }]}],
    [USER_INFO_ALL,
     {'username': USER_INFO_ALL, 'full_name': USER_INFO_ALL, 'admin': False, 'created_by': 'root',
      'permissions': [{'fs': 'Informatik',
                       'locked': False,
                       'read_files': True,
                       'read_permissions': True,
                       'write_permissions': True,
                       'read_public_data': True,
                       'write_public_data': True,
                       'read_protected_data': True,
                       'write_protected_data': True,
                       'submit_payout_request': True,
                       'upload_proceedings': True,
                       'delete_proceedings': True,
                       }]}],
])
def test_who_am_i(username: str, response_data: dict[str, Any]):
    response = client.get('/api/v1/user/me', headers=get_auth_header(client, username))
    assert response.status_code == 200
    assert response.json() == response_data


def test_who_am_i_oidc():
    token = new_token(None)['access_token']
    response = client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'username': 'user', 'full_name': 'Test User', 'admin': False, 'created_by': 'oidc',
                               'permissions': []}

def test_who_am_i_oidc_no_student_no_access():
    token = new_token(None, is_student=False)['access_token']
    response = client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 403
    assert response.json() == {'detail': 'Only students may log in'}


def test_change_own_password():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'password', 'new_password': 'motdepasse'},
                           headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': USER_NO_PERMS, 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_change_own_password_wrong_old_password_fails():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'wrong-password', 'new_password': 'motdepasse'},
                           headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401
    assert response.json() == {
        'detail': 'Wrong current password',
    }


def test_change_own_password_new_password_empty_fails():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'password', 'new_password': ''},
                           headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 422
    assert response.json()['detail'][0]['msg'] == 'String should have at least 8 characters'


def test_admin_change_other_password():
    response = client.post(f'/api/v1/user/password/{USER_NO_PERMS}',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': USER_NO_PERMS, 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_admin_change_other_password_user_does_not_exist():
    response = client.post('/api/v1/user/password/invalid-user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404
    assert response.json() == {
        'detail': 'That user does not exist',
    }


def test_admin_change_other_password_user_has_no_password():
    response = client.post(f'/api/v1/user/password/{USER_OIDC}',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404
    assert response.json() == {
        'detail': 'That user does not have a password',
    }


def test_change_other_password_without_admin():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header(client, USER_INFO_READ))
    assert response.status_code == 401
    response = client.post('/api/v1/token', data={'username': USER_NO_PERMS, 'password': 'password'})
    assert 'access_token' in response.json()


def test_broken_token():
    response = client.get('/api/v1/user/me', headers={'Authorization': 'Bearer broken-token'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_invalid_token_no_username():
    token = create_access_token(data={})
    response = client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_invalid_token_missing_user():
    token = create_access_token(data={'sub': 'does-not-exist'})
    response = client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}
