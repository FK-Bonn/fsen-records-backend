from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
from starlette.testclient import TestClient

from database import Base, User, get_password_hash, Permission


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
            permission2 = Permission()
            permission2.user = user2.username
            permission2.fs = 'Informatik'
            permission2.level = 1
            user3 = User()
            user3.username = "user3"
            user3.created_by = "root"
            user3.hashed_password = get_password_hash("password")
            permission3 = Permission()
            permission3.user = user3.username
            permission3.fs = 'Informatik'
            permission3.level = 2
            admin = User()
            admin.username = "admin"
            admin.created_by = "root"
            admin.hashed_password = get_password_hash("password")
            admin.admin = True
            self._session.add_all([user, permission2, user2, permission3, user3, admin])

            self._session.commit()
        return self._session

    def __exit__(self, type, value, traceback):
        self._session.close()
        self._session = None


@pytest.fixture(autouse=True)
def fake_db(monkeypatch, tmp_path):
    monkeypatch.setattr('users.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('fsen.DBHelper', lambda: DBTestHelper(tmp_path))


def get_token(client: TestClient, user: str):
    response = client.post('/api/v1/token', data={'username': user, 'password': 'password'})
    return response.json()['access_token']


def get_auth_header(client: TestClient, user: str = 'user2'):
    token = get_token(client, user)
    return {'Authorization': f'Bearer {token}'}
