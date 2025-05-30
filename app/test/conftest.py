import base64
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
from starlette.testclient import TestClient

from app.database import Base, User, get_password_hash, Permission, PayoutRequest, AdminPermission, UserPassword

ADMIN = 'admin'
USER_NO_PERMS = 'user_no_perms'
USER_INFO_READ = 'user_info_read'
USER_INFO_ALL = 'user_info_all'
USER_INFO_GEO_READ = 'user_geo_read'
USER_INFO_GEO_ALL = 'user_geo_all'

PDF_STRING = """JVBERi0xLjUKJbXtrvsKNCAwIG9iago8PCAvTGVuZ3RoIDUgMCBSCiAgIC9GaWx0ZXIgL0ZsYXRl
RGVjb2RlCj4+CnN0cmVhbQp4nDNUMABCXUMgYWFiqGdhYWlubqiQnMtVyBXIBQBPJAWjCmVuZHN0
cmVhbQplbmRvYmoKNSAwIG9iagogICAzNAplbmRvYmoKMyAwIG9iago8PAo+PgplbmRvYmoKMiAw
IG9iago8PCAvVHlwZSAvUGFnZSAlIDEKICAgL1BhcmVudCAxIDAgUgogICAvTWVkaWFCb3ggWyAw
IDAgNTk1LjI3NTU3NCA4NDEuODg5NzcxIF0KICAgL0NvbnRlbnRzIDQgMCBSCiAgIC9Hcm91cCA8
PAogICAgICAvVHlwZSAvR3JvdXAKICAgICAgL1MgL1RyYW5zcGFyZW5jeQogICAgICAvSSB0cnVl
CiAgICAgIC9DUyAvRGV2aWNlUkdCCiAgID4+CiAgIC9SZXNvdXJjZXMgMyAwIFIKPj4KZW5kb2Jq
CjEgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzCiAgIC9LaWRzIFsgMiAwIFIgXQogICAvQ291bnQgMQo+
PgplbmRvYmoKNiAwIG9iago8PCAvUHJvZHVjZXIgKGNhaXJvIDEuMTYuMCAoaHR0cHM6Ly9jYWly
b2dyYXBoaWNzLm9yZykpCiAgIC9DcmVhdGlvbkRhdGUgKEQ6MjAyMDA1MDYwMDUzNDUrMDInMDAp
Cj4+CmVuZG9iago3IDAgb2JqCjw8IC9UeXBlIC9DYXRhbG9nCiAgIC9QYWdlcyAxIDAgUgo+Pgpl
bmRvYmoKeHJlZgowIDgKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwNDAwIDAwMDAwIG4gCjAw
MDAwMDAxNjggMDAwMDAgbiAKMDAwMDAwMDE0NyAwMDAwMCBuIAowMDAwMDAwMDE1IDAwMDAwIG4g
CjAwMDAwMDAxMjYgMDAwMDAgbiAKMDAwMDAwMDQ2NSAwMDAwMCBuIAowMDAwMDAwNTgxIDAwMDAw
IG4gCnRyYWlsZXIKPDwgL1NpemUgOAogICAvUm9vdCA3IDAgUgogICAvSW5mbyA2IDAgUgo+Pgpz
dGFydHhyZWYKNjMzCiUlRU9GCg=="""

PDF_STRING_2 = PDF_STRING[:315] + '0' + PDF_STRING[316:]
PDF_STRING_3 = PDF_STRING[:315] + '2' + PDF_STRING[316:]

EMPTY_PDF_PAGE = base64.b64decode(PDF_STRING)
EMPTY_PDF_PAGE_2 = base64.b64decode(PDF_STRING_2)
EMPTY_PDF_PAGE_3 = base64.b64decode(PDF_STRING_3)

PDF_HASH = '1b318799de440475e51646b29c4c5a838d031548e0bdf6566802b6731082a23c'
PDF_HASH_2 = '367fde40660a01135966537de958326cf9a0fec1eff0a8a4888b2536c1721c7e'
PDF_HASH_3 = 'dec6ae7d6cdf2103d86b80453cd05e3e980ce0b8ee92773865ec174c9a935cbb'

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
            self.add_user(USER_NO_PERMS, 'root')
            self.add_user(USER_INFO_READ, 'root')
            self.add_user(USER_INFO_ALL, 'root')
            self.add_user(USER_INFO_GEO_READ, 'root')
            self.add_user(USER_INFO_GEO_ALL, 'root')
            self.add_user(ADMIN, 'root', admin=True)
            self.add_permission(USER_INFO_READ, 'Informatik', read_files=True, read_permissions=True, read_public_data=True)
            self.add_permission(USER_INFO_ALL, 'Informatik', read_files=True, read_permissions=True, write_permissions=True,
                                read_public_data=True, write_public_data=True, read_protected_data=True,
                                write_protected_data=True, submit_payout_request=True, upload_proceedings=True,
                                delete_proceedings=True, upload_documents=True)
            self.add_permission(USER_INFO_GEO_READ, 'Informatik', read_files=True, read_permissions=True, read_public_data=True)
            self.add_permission(USER_INFO_GEO_READ, 'Geographie', read_files=True, read_permissions=True, read_public_data=True)
            self.add_permission(USER_INFO_GEO_ALL, 'Informatik', read_files=True, read_permissions=True, write_permissions=True,
                                read_public_data=True, write_public_data=True, read_protected_data=True,
                                write_protected_data=True, submit_payout_request=True, upload_proceedings=True,
                                delete_proceedings=True, upload_documents=True)
            self.add_permission(USER_INFO_GEO_ALL, 'Geographie', read_files=True, read_permissions=True, write_permissions=True,
                                read_public_data=True, write_public_data=True, read_protected_data=True,
                                write_protected_data=True, submit_payout_request=True, upload_proceedings=True,
                                delete_proceedings=True, upload_documents=True)
            self.add_afsg_payout_request()
            self.add_bfsg_payout_request()
            self.add_vorankuendigung_payout_request()
            self._session.commit()
        return self._session

    def add_user(self, username: str, created_by: str, admin=False):
        assert self._session
        user = User()
        user.username = username
        user.full_name = username
        user.created_by = created_by
        self._session.add(user)
        user_password = UserPassword(user=username, hashed_password=_cached_password_hash("password"))
        self._session.add(user_password)
        if admin:
            admin_permission = AdminPermission(user=username, created_by='test')
            self._session.add(admin_permission)


    def add_permission(self, username: str, fs: str,
                       read_permissions: bool = False,
                       write_permissions: bool = False,
                       read_files: bool = False,
                       read_public_data: bool = False,
                       write_public_data: bool = False,
                       read_protected_data: bool = False,
                       write_protected_data: bool = False,
                       submit_payout_request: bool = False,
                       upload_proceedings: bool = False,
                       delete_proceedings: bool = False,
                       upload_documents: bool = False,
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
        permission.upload_proceedings = upload_proceedings
        permission.delete_proceedings = delete_proceedings
        permission.upload_documents = upload_documents
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
    monkeypatch.setattr('app.routers.elections.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.electoral_registers.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.export.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.files.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.fsen.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.payout_requests.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.proceedings.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.token.DBHelper', lambda: DBTestHelper(tmp_path))
    monkeypatch.setattr('app.routers.users.DBHelper', lambda: DBTestHelper(tmp_path))
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


def get_auth_header(client: TestClient, user: str | None = USER_INFO_READ):
    if not user:
        return {}
    token = get_token(client, user)
    return {'Authorization': f'Bearer {token}'}
