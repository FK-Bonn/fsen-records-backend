from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import get_auth_header, USER_NO_PERMS, ADMIN, EMPTY_PDF_PAGE, USER_INFO_ALL, PDF_HASH, \
    USER_INFO_GEO_READ, USER_INFO_GEO_ALL, USER_INFO_READ, EMPTY_PDF_PAGE_2, PDF_HASH_2, PDF_HASH_3, EMPTY_PDF_PAGE_3, \
    fake_session

DEFAULT_AFSG_DATA = {
    'category': 'AFSG',
    'base_name': 'HHP',
    'date_start': '2023-10-01',
    'date_end': '2024-09-30',
    'request_id': '',
}
DEFAULT_BFSG_DATA = {
    'category': 'BFSG',
    'base_name': 'kassenbon',
    'date_start': None,
    'date_end': None,
    'request_id': 'B24S-0001',
}

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_get_single_file_unauthorized(mocked_base_dir):
    (mocked_base_dir() / 'Informatik').mkdir(parents=True)
    (mocked_base_dir() / 'Informatik' / 'AFSG-HHP-2022-02-01--2023-03-31.pdf').write_bytes(EMPTY_PDF_PAGE)
    response = client.get('/api/v1/file/get/Informatik/AFSG-HHP-2022-02-01--2023-03-31.pdf')
    assert response.status_code == 401


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_get_single_file_no_permission(mocked_base_dir):
    (mocked_base_dir() / 'Informatik').mkdir(parents=True)
    (mocked_base_dir() / 'Informatik' / 'AFSG-HHP-2022-02-01--2023-03-31.pdf').write_bytes(EMPTY_PDF_PAGE)
    response = client.get('/api/v1/file/get/Informatik/AFSG-HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_get_single_file(mocked_base_dir):
    (mocked_base_dir() / 'Informatik').mkdir(parents=True)
    (mocked_base_dir() / 'Informatik' / 'AFSG-HHP-2022-02-01--2023-03-31.pdf').write_bytes(EMPTY_PDF_PAGE)
    response = client.get('/api/v1/file/get/Informatik/AFSG-HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 200


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_get_single_file_as_admin(mocked_base_dir):
    (mocked_base_dir() / 'Informatik').mkdir(parents=True)
    (mocked_base_dir() / 'Informatik' / 'AFSG-HHP-2022-02-01--2023-03-31.pdf').write_bytes(EMPTY_PDF_PAGE)
    response = client.get('/api/v1/file/get/Informatik/AFSG-HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_get_single_nonexisting_file(mocked_base_dir):
    (mocked_base_dir() / 'Informatik').mkdir(parents=True)
    response = client.get('/api/v1/file/get/Informatik/HHP-2022-02-01--2023-03-31-does-not-exist.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 404


@mock.patch('app.routers.files.hook_for_testing', return_value='..')
@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_try_path_traversal(mocked_base_dir, mocked_hook):
    (mocked_base_dir() / 'Informatik').mkdir(parents=True)
    response = client.get('/api/v1/file/get/this-will-be-replaced/something',
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404
    assert response.json() == {'detail': 'Unknown filename format'}


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_upload_file_afsg(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert (mocked_base_dir() / 'Informatik' / f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf').is_file()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_upload_file_afsg_no_path_traversal(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data={
                               'category': 'AFSG',
                               'base_name': 'HHP/../../xD',
                               'date_start': '2023-10-01',
                               'date_end': '2024-09-30',
                               'request_id': '',
                           },
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 403
    assert response.json() == {'detail': 'Invalid data'}
    assert not (mocked_base_dir() / f'xD-2023-10-01--2024-09-30-{PDF_HASH}.pdf').is_file()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_update_file_afsg(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    handle2 = BytesIO(EMPTY_PDF_PAGE_2)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert (mocked_base_dir() / 'Informatik' / f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf').is_file()
    assert (mocked_base_dir() / 'Informatik' / f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf').is_file()
    response = client.get('/api/v1/file/AFSG')
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH_2,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
                'uploaded_by': None,
                'created_timestamp': None,
                'references': None,
                'tags': None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
    }


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
    USER_INFO_GEO_READ,
    USER_INFO_GEO_ALL,
])
def test_upload_file_afsg_forbidden(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401
    assert not (mocked_base_dir() / 'Informatik').exists()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_upload_file_bfsg(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_BFSG_DATA,
                           files={'file': ('kassenbon.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert (mocked_base_dir() / 'Informatik' / f'BFSG-B24S-0001-kassenbon-{PDF_HASH}.pdf').is_file()


@mock.patch('app.routers.files.only_admin_bfsg', return_value=False)
@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    ADMIN,
    USER_INFO_ALL,
    USER_INFO_GEO_ALL,
])
def test_upload_file_bfsg_patched(mocked_base_dir, mocked_only_admin_bfsg, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_BFSG_DATA,
                           files={'file': ('kassenbon.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert (mocked_base_dir() / 'Informatik' / f'BFSG-B24S-0001-kassenbon-{PDF_HASH}.pdf').is_file()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
    USER_INFO_GEO_READ,
    USER_INFO_GEO_ALL,
])
def test_upload_file_bfsg_forbidden(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_BFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, USER_INFO_ALL))
    assert response.status_code == 401
    assert not (mocked_base_dir() / 'Informatik').exists()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_upload_file_invalid_file_type(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.rtf', handle, 'application/rtf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 415
    assert response.json() == {'detail': "File format not supported. Please only upload ('pdf', 'odt', "
                                         "'ods', 'txt', 'md', 'doc', 'docx', 'xls', 'xlsx')"}
    assert not (mocked_base_dir() / 'Informatik').exists()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    ADMIN,
])
def test_add_annotation(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    client.post('/api/v1/file/Informatik',
                data=DEFAULT_AFSG_DATA,
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN)).json()
    response = client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
        },
        'references': None,
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
            {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
        ]}, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'references': None,
                'tags': None,
                'url': None,
                'annotations': [
                    {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
                    {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
                ],
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
    USER_INFO_GEO_READ,
    USER_INFO_GEO_ALL,
])
def test_add_annotation_forbidden(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    client.post('/api/v1/file/Informatik',
                data=DEFAULT_AFSG_DATA,
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    response = client.post('/api/v1/file/Informatik/annotate', json={
        'target': DEFAULT_AFSG_DATA,
        'references': None,
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
            {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
        ]}, headers=get_auth_header(client, user))
    assert response.status_code == 401


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_add_annotation_document_not_found(mocked_base_dir):
    response = client.post('/api/v1/file/Informatik/annotate', json={
        'target': DEFAULT_AFSG_DATA,
        'references': None,
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Warning', 'text': 'Foo Bar'},
        ]}, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 404


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    ADMIN,
])
def test_update_annotation(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    client.post('/api/v1/file/Informatik',
                data=DEFAULT_AFSG_DATA,
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN)).json()
    response = client.post('/api/v1/file/Informatik/annotate', json={
        'target': DEFAULT_AFSG_DATA,
        'references': None,
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Error', 'text': 'kaputt'},
        ]}, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.post('/api/v1/file/Informatik/annotate', json={
        'target': DEFAULT_AFSG_DATA,
        'references': None,
        'tags': None,
        'url': 'https://example.org/2024-69.pdf',
        'annotations': [
            {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
            {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
        ]}, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'references': None,
                'tags': None,
                'url': 'https://example.org/2024-69.pdf',
                'annotations': [
                    {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
                    {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
                ],
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_retrieve_file_list(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'Prot',
                    'date_start': '2023-10-02',
                    'date_end': None,
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'Prot',
            'date_start': '2023-10-02',
            'date_end': None,
            'request_id': '',
        },
        'references': None,
        'tags': ['HHP'],
        'url': None,
        'annotations': None,
    },
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'HHP',
                    'date_start': '2023-10-01',
                    'date_end': '2024-09-30',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'HHP',
                    'date_start': '2023-10-01',
                    'date_end': '2024-09-30',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
        },
        'references': [{"category": "AFSG", "base_name": "Prot", "date_start": "2023-10-01",
                        "date_end": None, "request_id": ""}],
        'tags': None,
        'url': None,
        'annotations': None,
    },
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Geographie',
                data={
                    'category': 'AFSG',
                    'base_name': 'Wahlergebnis',
                    'date_start': '2023-11-11',
                    'date_end': '2023-11-13',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Geographie',
                data={
                    'category': 'BFSG',
                    'base_name': 'Abrechnung Getränkebestellung',
                    'date_start': None,
                    'date_end': None,
                    'request_id': 'B23W-0003',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Geographie/annotate', json={
        'target': {
            'category': 'BFSG',
            'base_name': 'Abrechnung Getränkebestellung',
            'date_start': None,
            'date_end': None,
            'request_id': 'B23W-0003',
        },
        'references': None,
        'tags': ['Erstifahrt'],
        'url': None,
        'annotations': None,
    },
                headers=get_auth_header(client, ADMIN))
    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Geographie': [
            {
                'category': 'AFSG',
                'base_name': 'Wahlergebnis',
                'date_start': '2023-11-11',
                'date_end': '2023-11-13',
                'request_id': '',
                'filename': f'AFSG-Wahlergebnis-2023-11-11--2023-11-13-{PDF_HASH}.pdf',
                'references': None,
                'tags': None,
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'references': [
                    {
                        "category": "AFSG",
                        "base_name": "Prot",
                        "date_start": "2023-10-01",
                        "date_end": None,
                        "request_id": "",
                    },
                ],
                'tags': None,
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
            {
                'category': 'AFSG',
                'base_name': 'Prot',
                'date_start': '2023-10-02',
                'date_end': None,
                'request_id': '',
                'references': None,
                'filename': f'AFSG-Prot-2023-10-02-{PDF_HASH}.pdf',
                'tags': ['HHP'],
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }
    response = client.get('/api/v1/file/BFSG', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Geographie': [
            {
                'category': 'BFSG',
                'base_name': 'Abrechnung Getränkebestellung',
                'date_start': None,
                'date_end': None,
                'request_id': 'B23W-0003',
                'filename': f'BFSG-B23W-0003-Abrechnung Getränkebestellung-{PDF_HASH}.pdf',
                'references': None,
                'tags': ['Erstifahrt'],
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_get_file_history(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    handle2 = BytesIO(EMPTY_PDF_PAGE_2)
    handle3 = BytesIO(EMPTY_PDF_PAGE_3)
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'Prot',
                    'date_start': '2023-10-01',
                    'date_end': None,
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'Prot',
            'date_start': '2023-10-01',
            'date_end': None,
            'request_id': '',
        },
        'references': None,
        'tags': ['HHP', 'NHHP'],
        'url': None,
        'annotations': None,
    })
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'HHP',
                    'date_start': '2023-10-01',
                    'date_end': '2024-09-30',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
        },
        'references': None,
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Error', 'text': 'kaputt'},
        ]}, headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
        },
        'references': None,
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
            {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
        ]}, headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'HHP',
                    'date_start': '2023-10-01',
                    'date_end': '2024-09-30',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle3, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
        },
        'references': [{"category": "AFSG", "base_name": "Prot", "date_start": "2023-10-01",
                        "date_end": None, "request_id": ""}],
        'tags': None,
        'url': None,
        'annotations': [
            {'level': 'Error', 'text': 'Rechenfehler in der Summe der Einnahmen'},
        ]}, headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'AFSG',
                    'base_name': 'HHP',
                    'date_start': '2023-10-01',
                    'date_end': '2024-09-30',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))

    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
        },
        'references': [{"category": "AFSG", "base_name": "Prot", "date_start": "2023-10-01",
                        "date_end": None, "request_id": ""}],
        'tags': None,
        'url': None,
        'annotations': None,
    }, headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Geographie',
                data={
                    'category': 'AFSG',
                    'base_name': 'HHP',
                    'date_start': '2023-10-01',
                    'date_end': '2024-09-30',
                    'request_id': '',
                },
                files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))

    response = client.post('/api/v1/file/Informatik/history',
                           json={
                               'category': 'AFSG',
                               'base_name': 'HHP',
                               'date_start': '2023-10-01',
                               'date_end': '2024-09-30',
                               'request_id': '',
                           },
                           headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask_list(response.json()) == [
        {
            'annotations': None,
            'annotations_created_by': ADMIN if user == ADMIN else None,
            'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
            'base_name': 'HHP',
            'category': 'AFSG',
            'created_timestamp': '[masked]' if user == ADMIN else None,
            'date_end': '2024-09-30',
            'date_start': '2023-10-01',
            'deleted_by': None,
            'deleted_timestamp': None,
            'file_extension': 'pdf',
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'references': [{
                'base_name': 'Prot',
                'category': 'AFSG',
                'date_end': None,
                'date_start': '2023-10-01',
                'request_id': '',
            }],
            'request_id': '',
            'sha256hash': PDF_HASH_2,
            'tags': None,
            'url': None,
            'uploaded_by': ADMIN if user == ADMIN else None,
        },
        {
            'annotations': [
                {
                    'level': 'Error',
                    'text': 'Rechenfehler in der Summe der Einnahmen',
                },
            ],
            'annotations_created_by': ADMIN if user == ADMIN else None,
            'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
            'base_name': 'HHP',
            'category': 'AFSG',
            'created_timestamp': '[masked]' if user == ADMIN else None,
            'date_end': '2024-09-30',
            'date_start': '2023-10-01',
            'deleted_by': ADMIN if user == ADMIN else None,
            'deleted_timestamp': '[masked]' if user == ADMIN else None,
            'file_extension': 'pdf',
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'references': [{
                'base_name': 'Prot',
                'category': 'AFSG',
                'date_end': None,
                'date_start': '2023-10-01',
                'request_id': '',
            }],
            'request_id': '',
            'sha256hash': PDF_HASH_3,
            'tags': None,
            'url': None,
            'uploaded_by': ADMIN if user == ADMIN else None,
        },
        {
            'annotations': [
                {
                    'level': 'Warning',
                    'text': 'Das Haushaltsjahr sollte angegeben werden'
                },
                {
                    'level': 'Info',
                    'text': 'Es handelt sich um das Sose 2023',
                },
            ],
            'annotations_created_by': ADMIN if user == ADMIN else None,
            'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
            'base_name': 'HHP',
            'category': 'AFSG',
            'created_timestamp': '[masked]' if user == ADMIN else None,
            'date_end': '2024-09-30',
            'date_start': '2023-10-01',
            'deleted_by': ADMIN if user == ADMIN else None,
            'deleted_timestamp': '[masked]' if user == ADMIN else None,
            'file_extension': 'pdf',
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'references': None,
            'request_id': '',
            'sha256hash': PDF_HASH_2,
            'tags': None,
            'url': None,
            'uploaded_by': ADMIN if user == ADMIN else None,
        },
        {
            'annotations': [
                {
                    'level': 'Error',
                    'text': 'kaputt',
                },
            ],
            'annotations_created_by': ADMIN if user == ADMIN else None,
            'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
            'base_name': 'HHP',
            'category': 'AFSG',
            'created_timestamp': '[masked]' if user == ADMIN else None,
            'date_end': '2024-09-30',
            'date_start': '2023-10-01',
            'deleted_by': ADMIN if user == ADMIN else None,
            'deleted_timestamp': '[masked]' if user == ADMIN else None,
            'file_extension': 'pdf',
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
            'obsoleted_by': ADMIN if user == ADMIN else None,
            'obsoleted_timestamp': '[masked]' if user == ADMIN else None,
            'references': None,
            'request_id': '',
            'sha256hash': PDF_HASH_2,
            'tags': None,
            'url': None,
            'uploaded_by': ADMIN if user == ADMIN else None,
        },
    ]


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_use_file_twice_with_different_annotations(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'BFSG',
                    'base_name': 'Nachhaltigkeitskonzept',
                    'date_start': None,
                    'date_end': None,
                    'request_id': 'B24S-0012',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'BFSG',
            'base_name': 'Nachhaltigkeitskonzept',
            'date_start': None,
            'date_end': None,
            'request_id': 'B24S-0012',
        },
        'references': None,
        'tags': ['Nachhaltigkeitskonzept'],
        'url': None,
        'annotations': [{
            'level': 'Error',
            'text': 'Dieses Nachhaltigkeitskonzept gab es zum Zeitpunkt der Veranstaltung noch gar nicht',
        }],
    }, headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik',
                data={
                    'category': 'BFSG',
                    'base_name': 'Nachhaltigkeitskonzept',
                    'date_start': None,
                    'date_end': None,
                    'request_id': 'B24S-0032',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Informatik/annotate', json={
        'target': {
            'category': 'BFSG',
            'base_name': 'Nachhaltigkeitskonzept',
            'date_start': None,
            'date_end': None,
            'request_id': 'B24S-0032',
        },
        'references': None,
        'tags': ['Nachhaltigkeitskonzept'],
        'url': None,
        'annotations': [{
            'level': 'Info',
            'text': 'Ein mustergültiges Konzept, wundervoll!',
        }],
    }, headers=get_auth_header(client, ADMIN))
    assert (mocked_base_dir() / 'Informatik' / f'BFSG-B24S-0012-Nachhaltigkeitskonzept-{PDF_HASH}.pdf').is_file()
    assert (mocked_base_dir() / 'Informatik' / f'BFSG-B24S-0032-Nachhaltigkeitskonzept-{PDF_HASH}.pdf').is_file()
    response = client.get('/api/v1/file/BFSG', headers=get_auth_header(client, ADMIN))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'annotations': [
                    {
                        'level': 'Error',
                        'text': 'Dieses Nachhaltigkeitskonzept gab es zum Zeitpunkt der Veranstaltung noch gar nicht',
                    },
                ],
                'annotations_created_by': 'admin',
                'annotations_created_timestamp': '[masked]',
                'base_name': 'Nachhaltigkeitskonzept',
                'category': 'BFSG',
                'created_timestamp': '[masked]',
                'date_end': None,
                'date_start': None,
                'file_extension': 'pdf',
                'filename': f'BFSG-B24S-0012-Nachhaltigkeitskonzept-{PDF_HASH}.pdf',
                'references': None,
                'request_id': 'B24S-0012',
                'sha256hash': PDF_HASH,
                'tags': ['Nachhaltigkeitskonzept'],
                'url': None,
                'uploaded_by': 'admin',
            },
            {
                'annotations': [
                    {
                        'level': 'Info',
                        'text': 'Ein mustergültiges Konzept, wundervoll!',
                    },
                ],
                'annotations_created_by': 'admin',
                'annotations_created_timestamp': '[masked]',
                'base_name': 'Nachhaltigkeitskonzept',
                'category': 'BFSG',
                'created_timestamp': '[masked]',
                'date_end': None,
                'date_start': None,
                'file_extension': 'pdf',
                'filename': f'BFSG-B24S-0032-Nachhaltigkeitskonzept-{PDF_HASH}.pdf',
                'references': None,
                'request_id': 'B24S-0032',
                'sha256hash': PDF_HASH,
                'tags': ['Nachhaltigkeitskonzept'],
                'url': None,
                'uploaded_by': 'admin',
            },
        ],
    }


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_fixed_date_annotations(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    handle2 = BytesIO(EMPTY_PDF_PAGE_2)
    handle3 = BytesIO(EMPTY_PDF_PAGE_3)
    with travel("2023-04-03T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()
    with travel("2023-04-04T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()
    with travel("2023-04-05T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': None,
            'url': None,
            'annotations': [
                {'level': 'Error', 'text': 'kaputt'},
            ]}, headers=get_auth_header(client, ADMIN))
        client.post('/api/v1/file/Informatik',
                    data={**DEFAULT_AFSG_DATA, 'base_name': 'HHR'},
                    files={'file': ('hhr.pdf', handle3, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': {**DEFAULT_AFSG_DATA, 'base_name': 'HHR'},
            'references': None,
            'tags': None,
            'url': None,
            'annotations': [
                {'level': 'Error', 'text': 'das ist auch nix'},
            ]}, headers=get_auth_header(client, ADMIN))
    with travel("2023-04-06T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': None,
            'url': 'https://example.org/2023-69.pdf',
            'annotations': [
                {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
                {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
            ]}, headers=get_auth_header(client, ADMIN))

    response = client.get('/api/v1/file/AFSG/2023-04-02', headers=get_auth_header(client, ADMIN))
    assert mask(response.json()) == {}
    response = client.get('/api/v1/file/AFSG/2023-04-03', headers=get_auth_header(client, ADMIN))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH_2,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'references': None,
                'tags': None,
                'url': None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
    }
    response = client.get('/api/v1/file/AFSG/2023-04-04', headers=get_auth_header(client, ADMIN))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'references': None,
                'tags': None,
                'url': None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
    }
    response = client.get('/api/v1/file/AFSG/2023-04-05', headers=get_auth_header(client, ADMIN))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'references': None,
                'tags': None,
                'url': None,
                'annotations': [
                    {'level': 'Error', 'text': 'kaputt'},
                ],
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
            },
            {
                'category': 'AFSG',
                'base_name': 'HHR',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH_3,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHR-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'references': None,
                'tags': None,
                'url': None,
                'annotations': [
                    {'level': 'Error', 'text': 'das ist auch nix'},
                ],
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
            },
        ],
    }
    response = client.get('/api/v1/file/AFSG/2023-04-06', headers=get_auth_header(client, ADMIN))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'references': None,
                'tags': None,
                'url': 'https://example.org/2023-69.pdf',
                'annotations': [
                    {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
                    {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
                ],
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
            },
            {
                'category': 'AFSG',
                'base_name': 'HHR',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'sha256hash': PDF_HASH_3,
                'file_extension': 'pdf',
                'filename': f'AFSG-HHR-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'references': None,
                'tags': None,
                'url': None,
                'annotations': [
                    {'level': 'Error', 'text': 'das ist auch nix'},
                ],
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
            },
        ],
    }

@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
    ADMIN,
])
def test_delete_file(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    handle2 = BytesIO(EMPTY_PDF_PAGE_2)
    handle3 = BytesIO(EMPTY_PDF_PAGE_3)
    with travel("2023-04-03T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN))
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': ['HHP'],
            'annotations': None,
            'url': None,
        }, headers=get_auth_header(client, ADMIN))
    with travel("2023-04-04T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN))
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': ['NHHP'],
            'annotations': None,
            'url': None,
        }, headers=get_auth_header(client, ADMIN))
    with travel("2023-04-05T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle3, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN))
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': ['NHHP2'],
            'annotations': None,
            'url': None,
        }, headers=get_auth_header(client, ADMIN))

    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
                'tags': ['NHHP2'],
                'sha256hash': PDF_HASH_3,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
                'tags': ['NHHP'],
                'sha256hash': PDF_HASH_2,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'tags': ['HHP'],
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations_created_by': ADMIN if user == ADMIN else None,
            },
        ],
    }

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {}

@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
def test_delete_file_not_allowed(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    with travel("2023-04-03T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, user))
    assert response.status_code == 401

    response = client.get('/api/v1/file/AFSG', headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'tags': None,
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
    }



@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_delete_file_history(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    handle2 = BytesIO(EMPTY_PDF_PAGE_2)
    handle3 = BytesIO(EMPTY_PDF_PAGE_3)
    with travel("2023-04-03T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': ['HHP'],
            'annotations': None,
            'url': None,
        }, headers=get_auth_header(client, ADMIN))
    with travel("2023-04-04T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle2, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': ['NHHP'],
            'annotations': None,
            'url': None,
        }, headers=get_auth_header(client, ADMIN))
    with travel("2023-04-05T10:00:00Z", tick=False):
        client.post('/api/v1/file/Informatik',
                    data=DEFAULT_AFSG_DATA,
                    files={'file': ('hhp.pdf', handle3, 'application/pdf')},
                    headers=get_auth_header(client, ADMIN)).json()
        client.post('/api/v1/file/Informatik/annotate', json={
            'target': DEFAULT_AFSG_DATA,
            'references': None,
            'tags': ['NHHP2'],
            'annotations': None,
            'url': None,
        }, headers=get_auth_header(client, ADMIN))

    response = client.post('/api/v1/file/Informatik/history',
                           json={
                               'category': 'AFSG',
                               'base_name': 'HHP',
                               'date_start': '2023-10-01',
                               'date_end': '2024-09-30',
                               'request_id': '',
                           },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert mask_list(response.json()) == [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
                'tags': ['NHHP2'],
                'sha256hash': PDF_HASH_3,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
                'obsoleted_by': None,
                'obsoleted_timestamp': None,
                'deleted_by': None,
                'deleted_timestamp': None,
            },
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
                'tags': ['NHHP'],
                'sha256hash': PDF_HASH_2,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
                'obsoleted_by': None,
                'obsoleted_timestamp': None,
                'deleted_by': ADMIN,
                'deleted_timestamp': '[masked]',
            },
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': None,
                'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
                'tags': ['HHP'],
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN,
                'created_timestamp': '[masked]',
                'annotations': None,
                'url': None,
                'annotations_created_timestamp': '[masked]',
                'annotations_created_by': ADMIN,
                'obsoleted_by': None,
                'obsoleted_timestamp': None,
                'deleted_by': ADMIN,
                'deleted_timestamp': '[masked]',
            },
        ]

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.post('/api/v1/file/Informatik/history',
                           json={
                               'category': 'AFSG',
                               'base_name': 'HHP',
                               'date_start': '2023-10-01',
                               'date_end': '2024-09-30',
                               'request_id': '',
                           },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert mask_list(response.json()) == [
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
            'tags': ['NHHP2'],
            'sha256hash': PDF_HASH_3,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
            'tags': ['NHHP'],
            'sha256hash': PDF_HASH_2,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': None,
            'deleted_timestamp': None,
        },
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
            'tags': ['HHP'],
            'sha256hash': PDF_HASH,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
    ]

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.post('/api/v1/file/Informatik/history',
                           json={
                               'category': 'AFSG',
                               'base_name': 'HHP',
                               'date_start': '2023-10-01',
                               'date_end': '2024-09-30',
                               'request_id': '',
                           },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert mask_list(response.json()) == [
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
            'tags': ['NHHP2'],
            'sha256hash': PDF_HASH_3,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
            'tags': ['NHHP'],
            'sha256hash': PDF_HASH_2,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
            'tags': ['HHP'],
            'sha256hash': PDF_HASH,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': None,
            'deleted_timestamp': None,
        },
    ]

    response = client.post('/api/v1/file/Informatik/delete', json={
        'target': DEFAULT_AFSG_DATA,
    }, headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.post('/api/v1/file/Informatik/history',
                           json={
                               'category': 'AFSG',
                               'base_name': 'HHP',
                               'date_start': '2023-10-01',
                               'date_end': '2024-09-30',
                               'request_id': '',
                           },
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert mask_list(response.json()) == [
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_3}.pdf',
            'tags': ['NHHP2'],
            'sha256hash': PDF_HASH_3,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH_2}.pdf',
            'tags': ['NHHP'],
            'sha256hash': PDF_HASH_2,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
        {
            'category': 'AFSG',
            'base_name': 'HHP',
            'date_start': '2023-10-01',
            'date_end': '2024-09-30',
            'request_id': '',
            'references': None,
            'filename': f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf',
            'tags': ['HHP'],
            'sha256hash': PDF_HASH,
            'file_extension': 'pdf',
            'uploaded_by': ADMIN,
            'created_timestamp': '[masked]',
            'annotations': None,
            'url': None,
            'annotations_created_timestamp': '[masked]',
            'annotations_created_by': ADMIN,
            'obsoleted_by': None,
            'obsoleted_timestamp': None,
            'deleted_by': ADMIN,
            'deleted_timestamp': '[masked]',
        },
    ]


def mask(elements: dict[str, list[dict]]):
    for key, value in elements.items():
        mask_list(value)
    return elements


def mask_list(value: list[dict]):
    for element in value:
        for key in ('created_timestamp', 'annotations_created_timestamp', 'deleted_timestamp', 'obsoleted_timestamp'):
            if key in element and element[key]:
                element[key] = '[masked]'
    return value
