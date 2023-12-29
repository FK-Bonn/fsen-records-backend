from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
from starlette.testclient import TestClient

from app.database import Base, User, get_password_hash, Permission, PayoutRequest

HASH_CACHE = {}

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
            self.add_permission('user2', 'Informatik', read_files=True, read_permissions=True, read_public_data=True)
            self.add_permission('user3', 'Informatik', read_files=True, read_permissions=True, write_permissions=True,
                                read_public_data=True, write_public_data=True, read_protected_data=True,
                                write_protected_data=True, submit_payout_request=True)
            self.add_permission('user4', 'Informatik', read_files=True, read_permissions=True, read_public_data=True)
            self.add_permission('user4', 'Geographie', read_files=True, read_permissions=True, read_public_data=True)
            self.add_permission('user5', 'Informatik', read_files=True, read_permissions=True, write_permissions=True,
                                read_public_data=True, write_public_data=True, read_protected_data=True,
                                write_protected_data=True, submit_payout_request=True)
            self.add_permission('user5', 'Geographie', read_files=True, read_permissions=True, write_permissions=True,
                                read_public_data=True, write_public_data=True, read_protected_data=True,
                                write_protected_data=True, submit_payout_request=True)
            self.add_afsg_payout_request()
            self.add_bfsg_payout_request()
            self.add_vorankuendigung_payout_request()
            self._session.commit()
        return self._session

    def add_user(self, username: str, created_by: str, admin=False):
        assert self._session
        user = User()
        user.username = username
        user.created_by = created_by
        user.hashed_password = _cached_password_hash("password")
        user.admin = admin
        self._session.add(user)

    def add_permission(self, username: str, fs: str,
                       read_permissions: bool = False,
                       write_permissions: bool = False,
                       read_files: bool = False,
                       read_public_data: bool = False,
                       write_public_data: bool = False,
                       read_protected_data: bool = False,
                       write_protected_data: bool = False,
                       submit_payout_request: bool = False,
                       locked: bool = False,
                       ):
        assert self._session
        permission = Permission()
        permission.user = username
        permission.fs = fs
        permission.locked = locked
        permission.read_permissions = read_permissions
        permission.write_permissions = write_permissions
        permission.read_files = read_files
        permission.read_public_data = read_public_data
        permission.write_public_data = write_public_data
        permission.read_protected_data = read_protected_data
        permission.write_protected_data = write_protected_data
        permission.submit_payout_request = submit_payout_request
        self._session.add(permission)

    def add_afsg_payout_request(self):
        assert self._session
        payout_request = PayoutRequest()
        payout_request.request_id = 'A22W-0023'
        payout_request.type = 'afsg'
        payout_request.category = 'AFSG'
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
        payout_request.completion_deadline = '2025-03-31'
        self._session.add(payout_request)

    def add_bfsg_payout_request(self):
        assert self._session
        payout_request = PayoutRequest()
        payout_request.request_id = 'B22W-0023'
        payout_request.type = 'bfsg'
        payout_request.category = 'Erstiarbeit'
        payout_request.fs = 'Informatik'
        payout_request.semester = '2022-WiSe'
        payout_request.status = 'GESTELLT'
        payout_request.status_date = '2023-01-07'
        payout_request.amount_cents = 23456
        payout_request.comment = 'comment'
        payout_request.request_date = '2023-01-07'
        payout_request.requester = 'tim.test'
        payout_request.last_modified_timestamp = '2023-01-07T22:11:07+00:00'
        payout_request.last_modified_by = 'tim.test'
        payout_request.completion_deadline = '2023-07-07'
        self._session.add(payout_request)

    def add_vorankuendigung_payout_request(self):
        assert self._session
        payout_request = PayoutRequest()
        payout_request.request_id = 'V22W-0023'
        payout_request.type = 'vorankuendigung'
        payout_request.category = 'Erstiarbeit'
        payout_request.fs = 'Informatik'
        payout_request.semester = '2022-WiSe'
        payout_request.status = 'GESTELLT'
        payout_request.status_date = '2023-01-07'
        payout_request.amount_cents = 100000
        payout_request.comment = 'comment'
        payout_request.request_date = '2023-01-07'
        payout_request.requester = 'tim.test'
        payout_request.last_modified_timestamp = '2023-01-07T22:11:07+00:00'
        payout_request.last_modified_by = 'tim.test'
        payout_request.completion_deadline = ''
        self._session.add(payout_request)

    def __exit__(self, type, value, traceback):
        self._session.close()
        self._session = None


@pytest.fixture(autouse=True)
def fake_db(monkeypatch, tmp_path):
    monkeypatch.setattr('app.routers.users.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.fsen.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.payout_requests.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.database.get_password_hash', _cached_password_hash)
    monkeypatch.setattr('app.routers.users.get_password_hash', _cached_password_hash)

def _cached_password_hash(password: str) -> str:
    if password not in HASH_CACHE:
        hash_value = get_password_hash(password)
        HASH_CACHE[password] = hash_value
    return HASH_CACHE[password]

def get_token(client: TestClient, user: str):
    response = client.post('/api/v1/token', data={'username': user, 'password': 'password'})
    return response.json()['access_token']


def get_auth_header(client: TestClient, user: str = 'user2'):
    token = get_token(client, user)
    return {'Authorization': f'Bearer {token}'}
