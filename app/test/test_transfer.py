from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time
from sqlalchemy import select

from app.database import get_session, AdminPermission, Proceedings, Document
from app.main import app
from app.main import subapp
from app.routers.token import new_token
from app.test.conftest import get_auth_header, USER_NO_PERMS, USER_INFO_READ, USER_INFO_GEO_ALL, USER_INFO_ALL, ADMIN, \
    fake_session, get_token, EMPTY_PDF_PAGE, PDF_HASH
from app.test.test_elections import create_election
from app.test.test_electoral_registers import create_register
from app.test.test_files import DEFAULT_AFSG_DATA, mask_list
from app.test.test_fsdata import set_sample_base_data, SAMPLE_BASE_DATA, set_sample_public_data, SAMPLE_PUBLIC_DATA, \
    set_sample_protected_data, SAMPLE_PROTECTED_DATA
from app.test.test_payout_requests import CREATE_PARAMS, CREATED_PAYOUT_REQUEST, SAMPLE_FULL_PAYOUT_REQUEST
from app.test.test_proceedings import create_sample_proceedings

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session


def assert_user_exists(username: str):
    response = client.post('/api/v1/token', data={'username': username, 'password': 'password'})
    assert response.status_code == 200


def assert_user_does_not_exist(username: str):
    response = client.post('/api/v1/token', data={'username': username, 'password': 'password'})
    assert response.status_code == 401


@pytest.mark.parametrize('user', [
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_transfer_deletes_old_user(user):
    oidc_token = new_token(None)['access_token']
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'}).status_code == 200

    token = get_token(client, user)
    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})
    assert response.status_code == 200

    assert_user_does_not_exist(user)

@pytest.mark.parametrize('user', [
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_transfer_twice_fails(user):
    oidc_token = new_token(None)['access_token']
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'}).status_code == 200
    token = get_token(client, user)
    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})
    assert response.status_code == 200
    assert_user_does_not_exist(user)

    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})

    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}


@pytest.mark.parametrize('user', [
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_transfer_to_newly_created_oidc_user(user):
    oidc_token = new_token(None)['access_token']

    token = get_token(client, user)
    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})
    assert response.status_code == 200

    assert_user_does_not_exist(user)


def test_transfer_invalid_token_fails():
    oidc_token = new_token(None)['access_token']
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'}).status_code == 200

    token = 'not-a-real-token'
    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}


@pytest.mark.parametrize('user', [
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_transfer_invalid_oidc_token_fails(user):
    oidc_token = 'invalid-oidc-token'
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'}).status_code == 401

    token = get_token(client, user)
    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}

    assert_user_exists(user)


def test_transfer_two_tokens_fails():
    token1 = get_token(client, USER_INFO_READ)
    token2 = get_token(client, USER_INFO_GEO_ALL)
    response = client.post('/api/v1/user/transfer', json={'token': token1, 'oidc_token': token2})
    assert response.status_code == 400
    assert response.json() == {'detail': 'oidc_token must be for an oidc user'}

    assert_user_exists(USER_INFO_READ)
    assert_user_exists(USER_INFO_GEO_ALL)


def test_transfer_two_oidc_tokens_fails():
    oidc_token_1 = new_token(None)['access_token']
    oidc_token_2 = new_token(None)['access_token']
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token_1}'}).status_code == 200
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token_2}'}).status_code == 200

    response = client.post('/api/v1/user/transfer', json={'token': oidc_token_1, 'oidc_token': oidc_token_2})
    assert response.status_code == 400
    assert response.json() == {'detail': 'token must be for a native user'}


@pytest.mark.parametrize('user', [
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_transfer_switched_tokens_fails(user):
    oidc_token = new_token(None)['access_token']
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'}).status_code == 200

    token = get_token(client, user)
    response = client.post('/api/v1/user/transfer', json={'token': oidc_token, 'oidc_token': token})
    assert response.status_code == 400
    assert response.json() == {'detail': 'token must be for a native user'}

    assert_user_exists(user)


def transfer(old_username: str, new_username: str):
    oidc_token = new_token(None, username=new_username)['access_token']
    assert client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'}).status_code == 200

    token = get_token(client, old_username)
    response = client.post('/api/v1/user/transfer', json={'token': token, 'oidc_token': oidc_token})
    assert response.status_code == 200

    assert_user_does_not_exist(old_username)
    return oidc_token


def test_transfer_user_created_by():
    assert client.post('/api/v1/user/create',
                       json={'username': 'user-to-create',
                             'password': 'password',
                             'admin': False,
                             'permissions': [],
                             },
                       headers=get_auth_header(client, ADMIN)
                       ).status_code == 200

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.get('/api/v1/user', headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.json()['user-to-create']['created_by'] == 'oidc_user'
    assert response.json()['oidc_user']['created_by'] == 'oidc'


def test_transfer_admin_permission():
    assert client.post('/api/v1/user/permissions',
                       json={'username': USER_NO_PERMS,
                             'admin': True,
                             'permissions': [],
                             },
                       headers=get_auth_header(client, ADMIN)).status_code == 200

    oidc_token = transfer(USER_NO_PERMS, 'oidc_user')

    response = client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.json() == {
        'admin': True,
        'created_by': 'oidc',
        'full_name': 'Test User',
        'permissions': [],
        'username': 'oidc_user'
    }


def test_transfer_admin_permission_created_by():
    assert client.post('/api/v1/user/permissions',
                       json={'username': USER_NO_PERMS,
                             'admin': True,
                             'permissions': [],
                             },
                       headers=get_auth_header(client, ADMIN)).status_code == 200

    transfer(ADMIN, 'oidc_user')

    session = next(fake_session())
    statement = select(AdminPermission.created_by).where(AdminPermission.user == USER_NO_PERMS)
    result = session.scalar(statement)
    assert result == 'oidc_user'


def test_transfer_permissions():
    oidc_token = transfer(USER_INFO_ALL, 'oidc_user')

    response = client.get('/api/v1/user/me', headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.json() == {
        'admin': False,
        'created_by': 'oidc',
        'full_name': 'Test User',
        'permissions': [{
            'fs': 'Informatik',
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
        }],
        'username': 'oidc_user'
    }


def test_transfer_base_fs_data_user():
    with freeze_time("2023-07-07T17:00:00Z"):
        set_sample_base_data()

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.get('/api/v1/data/Informatik/base/history', headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
    assert response.json() == [
        {
            **SAMPLE_BASE_DATA,
            'id': 1,
            'user': 'oidc_user',
            'timestamp': '2023-07-07T17:00:00+00:00',
            'approval_timestamp': '2023-07-07T17:00:00+00:00',
            'approved': True,
            'approved_by': 'auto',
        }
    ]


def test_transfer_public_fs_data_user():
    with freeze_time("2023-07-07T17:00:00Z"):
        set_sample_public_data()

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.get('/api/v1/data/Informatik/public/history', headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
    assert response.json() == [
        {
            **SAMPLE_PUBLIC_DATA,
            'id': 1,
            'user': 'oidc_user',
            'timestamp': '2023-07-07T17:00:00+00:00',
            'approval_timestamp': '2023-07-07T17:00:00+00:00',
            'approved': True,
            'approved_by': 'auto',
        }
    ]


def test_transfer_protected_fs_data_user():
    with freeze_time("2023-07-07T17:00:00Z"):
        set_sample_protected_data()

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.get('/api/v1/data/Informatik/protected/history',
                          headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
    assert response.json() == [
        {
            **SAMPLE_PROTECTED_DATA,
            'id': 1,
            'user': 'oidc_user',
            'timestamp': '2023-07-07T17:00:00+00:00',
            'approval_timestamp': '2023-07-07T17:00:00+00:00',
            'approved': True,
            'approved_by': 'auto',
        }
    ]


def test_transfer_protected_fs_data_approved_by():
    with freeze_time("2023-07-07T17:00:00Z"):
        assert client.put('/api/v1/data/Informatik/protected', json=SAMPLE_PROTECTED_DATA,
                          headers=get_auth_header(client, USER_INFO_ALL)).status_code == 200
        data_id = client.get('/api/v1/data/Informatik/protected/history',
                             headers=get_auth_header(client, ADMIN)).json()[0]['id']
        assert client.post(f'/api/v1/data/approve/protected/{data_id}',
                           headers=get_auth_header(client, ADMIN)).status_code == 200

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.get('/api/v1/data/Informatik/protected/history',
                          headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
    assert response.json() == [
        {
            **SAMPLE_PROTECTED_DATA,
            'id': 1,
            'user': USER_INFO_ALL,
            'timestamp': '2023-07-07T17:00:00+00:00',
            'approval_timestamp': '2023-07-07T17:00:00+00:00',
            'approved': True,
            'approved_by': 'oidc_user',
        }
    ]


@pytest.mark.parametrize('_type', [
    'afsg',
    'bfsg',
    'vorankuendigung',
])
@freeze_time("2023-04-04T10:00:00Z")
def test_transfer_payout_requests(_type):
    response = client.post(f'/api/v1/payout-request/{_type}/create', json=CREATE_PARAMS[_type],
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == CREATED_PAYOUT_REQUEST[_type]

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.get(f'/api/v1/payout-request/{_type}', headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
    assert response.json() == [
        SAMPLE_FULL_PAYOUT_REQUEST[_type],
        {
            **CREATED_PAYOUT_REQUEST[_type],
            'requester': 'oidc_user',
            'last_modified_timestamp': '2023-04-04T10:00:00+00:00',
            'last_modified_by': 'oidc_user',
        }
    ]


@pytest.mark.parametrize('username', [
    USER_INFO_ALL,
    ADMIN,
])
@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_transfer_proceedings(mocked_base_dir, username):
    target_file = (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf')
    create_sample_proceedings(target_file, user=username)
    assert client.delete('/api/v1/proceedings/Informatik/FSV/2024-05-30',
                         headers=get_auth_header(client, username)).status_code == 200

    transfer(username, 'oidc_user')

    session = next(fake_session())
    statement = select(Proceedings)
    result = session.scalar(statement)
    assert result.uploaded_by == 'oidc_user'
    assert result.deleted_by == 'oidc_user'


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_transfer_file(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    assert client.post('/api/v1/file/Informatik',
                       data=DEFAULT_AFSG_DATA,
                       files={'file': ('hhp.pdf', handle, 'application/pdf')},
                       headers=get_auth_header(client, ADMIN)).status_code == 200
    assert client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN)).status_code == 200

    transfer(ADMIN, 'oidc_user')

    session = next(fake_session())
    statement = select(Document)
    result = session.scalar(statement)
    assert result.uploaded_by == 'oidc_user'
    assert result.deleted_by == 'oidc_user'


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_transfer_annotation(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    assert client.post('/api/v1/file/Informatik',
                       data=DEFAULT_AFSG_DATA,
                       files={'file': ('hhp.pdf', handle, 'application/pdf')},
                       headers=get_auth_header(client, ADMIN)).status_code == 200
    assert client.post('/api/v1/file/Informatik/annotate', json={
        'target': DEFAULT_AFSG_DATA,
        'references': None,
        'tags': ['HHP'],
        'annotations': None,
        'url': None,
    }, headers=get_auth_header(client, ADMIN)).status_code == 200
    assert client.post('/api/v1/file/Informatik/annotate', json={
        'target': DEFAULT_AFSG_DATA,
        'references': None,
        'tags': ['NHHP'],
        'annotations': None,
        'url': None,
    }, headers=get_auth_header(client, ADMIN)).status_code == 200

    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.post('/api/v1/file/Informatik/history',
                           json=DEFAULT_AFSG_DATA,
                           headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
    assert mask_list(response.json()) == [
        {
            'annotations': None,
            'annotations_created_by': 'oidc_user',
            'annotations_created_timestamp': '[masked]',
            'base_name': 'HHP',
            'category': 'AFSG',
            'created_timestamp': '[masked]',
            'date_end': '2024-09-30',
            'date_start': '2023-10-01',
            'deleted_by': None,
            'deleted_timestamp': None,
            'file_extension': 'pdf',
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'references': None,
            'request_id': '',
            'sha256hash': PDF_HASH,
            'tags': ['NHHP'],
            'url': None,
            'uploaded_by': 'oidc_user',
        },
        {
            'annotations': None,
            'annotations_created_by': 'oidc_user',
            'annotations_created_timestamp': '[masked]',
            'base_name': 'HHP',
            'category': 'AFSG',
            'created_timestamp': '[masked]',
            'date_end': '2024-09-30',
            'date_start': '2023-10-01',
            'deleted_by': None,
            'deleted_timestamp': None,
            'file_extension': 'pdf',
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
            'obsoleted_by': 'oidc_user',
            'obsoleted_timestamp': '[masked]',
            'references': None,
            'request_id': '',
            'sha256hash': PDF_HASH,
            'tags': ['HHP'],
            'url': None,
            'uploaded_by': 'oidc_user',
        },
    ]


@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
@freeze_time("2024-11-11T11:11:00Z")
def test_transfer_electoral_register_download(mocked_base_dir, ):
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Informatik.zip')
    result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200

    transfer(ADMIN, 'oidc_user')

    result = client.get('/api/v1/electoral-registers/log',
                        headers=get_auth_header(client, None))
    assert result.status_code == 200
    assert result.json() == [
        {
            'timestamp': '2024-11-11T11:11:00+00:00',
            'username': 'oidc_user',
            'filepath': '2024-11-11/Informatik.zip',
        }
    ]


def test_transfer_election():
    create_election(id_='deadbeef')

    oidc_token = transfer(ADMIN, 'oidc_user')

    result = client.get('/api/v1/elections/deadbeef/history', headers={'Authorization': f'Bearer {oidc_token}'})
    assert result.json()[0]['last_modified_by'] == 'oidc_user'


def test_transfer_deleted_user_can_be_created_again():
    oidc_token = transfer(ADMIN, 'oidc_user')

    response = client.post('/api/v1/user/create',
                           json={'username': ADMIN,
                                 'password': 'password',
                                 'admin': True,
                                 'permissions': [],
                                 },
                           headers={'Authorization': f'Bearer {oidc_token}'})
    assert response.status_code == 200
