from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
from starlette.testclient import TestClient

from app.database import Base, User, get_password_hash, Permission, PayoutRequest


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
            self.add_user('user', 'root')
            self.add_user('user2', 'root')
            self.add_user('user3', 'root')
            self.add_user('user4', 'root')
            self.add_user('user5', 'root')
            self.add_user('admin', 'root', admin=True)
            self.add_permission('user2', 'Informatik', 1)
            self.add_permission('user3', 'Informatik', 2)
            self.add_permission('user4', 'Informatik', 1)
            self.add_permission('user4', 'Geographie', 1)
            self.add_permission('user5', 'Informatik', 2)
            self.add_permission('user5', 'Geographie', 2)
            self.add_payout_request()
            self._session.commit()
        return self._session

    def add_user(self, username: str, created_by: str, admin=False):
        user = User()
        user.username = username
        user.created_by = created_by
        user.hashed_password = get_password_hash("password")
        user.admin = admin
        self._session.add(user)

    def add_permission(self, username: str, fs: str, level: int):
        permission = Permission()
        permission.user = username
        permission.fs = fs
        permission.level = level
        self._session.add(permission)

    def add_payout_request(self):
        payout_request = PayoutRequest()
        payout_request.request_id = 'A22W-0023'
        payout_request.fs = 'Informatik'
        payout_request.semester = '2022-WiSe'
        payout_request.status = 'GESTELLT'
        payout_request.status_date = '2023-01-07'
        payout_request.amount_cents = 111100
        payout_request.comment = 'comment'
        payout_request.request_date = '2023-01-07'
        payout_request.requester = 'tim.test'
        payout_request.last_modified_timestamp = '2023-01-07T22:11:07+00:00'
        payout_request.last_modified_by = 'tim.test'
        self._session.add(payout_request)

    def __exit__(self, type, value, traceback):
        self._session.close()
        self._session = None


@pytest.fixture(autouse=True)
def fake_db(monkeypatch, tmp_path):
    monkeypatch.setattr('app.routers.users.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.fsen.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.payout_requests.DBHelper', lambda: DBTestHelper(tmp_path))


def get_token(client: TestClient, user: str):
    response = client.post('/api/v1/token', data={'username': user, 'password': 'password'})
    return response.json()['access_token']


def get_auth_header(client: TestClient, user: str = 'user2'):
    token = get_token(client, user)
    return {'Authorization': f'Bearer {token}'}
