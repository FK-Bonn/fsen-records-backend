from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database

from database import Base, User, get_password_hash, Permission
from main import app

client = TestClient(app)


class DBTestHelper:
    def __init__(self, tmppath: Path):
        self.connection_str = f'sqlite:///{tmppath.absolute()}/test.db'
        self._session = None

    def __enter__(self):
        if self._session:
            return self._session
        do_init = False
        if not database_exists(self.connection_str):
            do_init = True
            create_database(self.connection_str)
        engine = create_engine(self.connection_str)

        Base.metadata.create_all(engine)

        self._session = Session(engine)

        if do_init:
            user = User()
            user.username = "user"
            user.created_by = "root"
            user.hashed_password = get_password_hash("password")
            user2 = User()
            user2.username = "user2"
            user2.created_by = "root"
            user2.hashed_password = get_password_hash("password")
            permission = Permission()
            permission.user = user.username
            permission.fs = 'Informatik'
            admin = User()
            admin.username = "admin"
            admin.created_by = "root"
            admin.hashed_password = get_password_hash("password")
            admin.admin = True
            self._session.add_all([user, permission, user2, admin])

            self._session.commit()
        return self._session

    def __exit__(self, type, value, traceback):
        self._session.close()
        self._session = None


@pytest.fixture(autouse=True)
def fake_db(monkeypatch, tmp_path):
    monkeypatch.setattr('users.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('fsen.DBHelper', lambda: DBTestHelper(tmp_path))


def get_token(user: str):
    response = client.post('/api/v1/token', data={'username': user, 'password': 'password'})
    return response.json()['access_token']


def get_auth_header(user: str = 'user'):
    token = get_token(user)
    return {'Authorization': f'Bearer {token}'}


def test_read_main():
    response = client.get('/api/v1')
    assert response.status_code == 200


def test_login():
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'password'})
    assert response.status_code == 200
    response_json = response.json()
    assert 'access_token' in response_json
    assert response_json['token_type'] == 'bearer'


def test_read_admin_only_without_login():
    response = client.get('/api/v1/require-admin')
    assert response.status_code == 401


def test_read_admin_only_without_admin_privilegues():
    response = client.get('/api/v1/require-admin', headers=get_auth_header())
    assert response.status_code == 401


def test_read_admin_only():
    response = client.get('/api/v1/require-admin', headers=get_auth_header('admin'))
    assert response.status_code == 200


def test_get_single_file_unauthorized():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf')
    assert response.status_code == 401


def test_get_single_file_no_permission():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf', headers=get_auth_header('user2'))
    assert response.status_code == 401


def test_get_single_file():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf', headers=get_auth_header())
    assert response.status_code == 200


def test_get_single_file_as_admin():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf', headers=get_auth_header('admin'))
    assert response.status_code == 200


def test_get_single_nonexisting_file():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31-does-not-exist.pdf',
                          headers=get_auth_header())
    assert response.status_code == 404


def test_create_user():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': ['Informatik'],
                                 },
                           headers=get_auth_header('admin'))
    assert response.status_code == 200
    usersresponse = client.get('/api/v1/user', headers=get_auth_header('admin'))
    users = usersresponse.json()
    assert users['user-to-create']['created_by'] == 'admin'


def test_create_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': ['Informatik'],
                                 },
                           headers=get_auth_header('admin'))
    assert response.status_code == 200


def test_create_user_missing_permission():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': ['Informatik'],
                                 },
                           headers=get_auth_header('user2'))
    assert response.status_code == 401


def test_create_admin_user_missing_permission():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header('user'))
    assert response.status_code == 401


def test_create_user_no_admin():
    response = client.post('/api/v1/user/create',
                           json={'username': 'user-to-create',
                                 'password': 'password',
                                 'admin': False,
                                 'permissions': ['Informatik'],
                                 },
                           headers=get_auth_header('user'))
    assert response.status_code == 200


def test_set_user_permissions():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': False,
                                 'permissions': ['Geographie'],
                                 },
                           headers=get_auth_header('admin'))
    assert response.status_code == 200
    assert 'Informatik' not in response.json()['permissions']
    assert 'Geographie' in response.json()['permissions']


def test_promote_user_to_admin():
    response = client.post('/api/v1/user/permissions',
                           json={'username': 'user',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers=get_auth_header('admin'))
    assert response.status_code == 200
    assert response.json()['admin']
    assert not response.json()['permissions']


def test_get_users():
    response = client.get('/api/v1/user/', headers=get_auth_header('admin'))
    assert response.status_code == 200
    assert response.json() == {
        'admin': {'username': 'admin', 'admin': True, 'created_by': 'root', 'permissions': []},
        'user': {'username': 'user', 'admin': False, 'created_by': 'root', 'permissions': ['Informatik']},
        'user2': {'username': 'user2', 'admin': False, 'created_by': 'root', 'permissions': []},
    }


@pytest.mark.parametrize('username,response_data', [
    ['admin', {'username': 'admin', 'admin': True, 'created_by': 'root', 'permissions': []}],
    ['user', {'username': 'user', 'admin': False, 'created_by': 'root', 'permissions': ['Informatik']}],
    ['user2', {'username': 'user2', 'admin': False, 'created_by': 'root', 'permissions': []}],
])
def test_who_am_i(username: str, response_data: Dict[str, Any]):
    response = client.get('/api/v1/user/me', headers=get_auth_header(username))
    assert response.status_code == 200
    assert response.json() == response_data


def test_change_own_password():
    response = client.post('/api/v1/user/password',
                           json={'current_password': 'password', 'new_password': 'motdepasse'},
                           headers=get_auth_header())
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_admin_change_other_password():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header('admin'))
    assert response.status_code == 200
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'motdepasse'})
    assert 'access_token' in response.json()


def test_change_other_password_without_admin():
    response = client.post('/api/v1/user/password/user',
                           json={'new_password': 'motdepasse'},
                           headers=get_auth_header('user2'))
    assert response.status_code == 401
    response = client.post('/api/v1/token', data={'username': 'user', 'password': 'password'})
    assert 'access_token' in response.json()
