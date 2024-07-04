from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.test.conftest import get_auth_header, USER_NO_PERMS, ADMIN, EMPTY_PDF_PAGE, USER_INFO_ALL, PDF_HASH, \
    USER_INFO_GEO_READ, USER_INFO_GEO_ALL, USER_INFO_READ

DEFAULT_AFSG_DATA = {
    'category': 'AFSG',
    'base_name': 'HHP',
    'date_start': '2023-10-01',
    'date_end': '2024-09-30',
    'request_id': '',
    'references': '',
    'tags': '',
}
DEFAULT_BFSG_DATA = {
    'category': 'BFSG',
    'base_name': 'kassenbon',
    'date_start': None,
    'date_end': None,
    'request_id': 'B24S-0001',
    'references': '',
    'tags': '',
}

client = TestClient(app)


def test_get_single_file_unauthorized():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf')
    assert response.status_code == 401


def test_get_single_file_no_permission():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client, USER_NO_PERMS))
    assert response.status_code == 401


def test_get_single_file():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 200


def test_get_single_file_as_admin():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200


def test_get_single_nonexisting_file():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31-does-not-exist.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 404


def test_get_single_file_wrong_format():
    response = client.get('/api/v1/file/Informatik/ABC-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 404


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_upload_file_afsg(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {'fs': 'Informatik', 'sha256hash': PDF_HASH}
    assert (mocked_base_dir() / 'Informatik' / f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf').is_file()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_update_file_afsg(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.post('/api/v1/file/Informatik',
                           data={
                               **DEFAULT_AFSG_DATA,
                               'references': '[{"category": "AFSG", "base_name": "Prot", "date_start": "2023-10-01",'
                                             ' "date_end": null, "request_id": ""}]',
                           },
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    assert response.json() == {'fs': 'Informatik', 'sha256hash': PDF_HASH}
    assert (mocked_base_dir() / 'Informatik' / f'AFSG-HHP-2023-10-01--2024-09-30-{PDF_HASH}.pdf').is_file()
    response = client.get('/api/v1/file')
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': [
                    {
                        "category": "AFSG",
                        "base_name": "Prot",
                        "date_start": "2023-10-01",
                        "date_end": None,
                        "request_id": "",
                    }
                ],
                'tags': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': None,
                'created_timestamp': None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
    }


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('tags', [None, 'hype, yolo'])
@pytest.mark.parametrize('references', [
    None,
    [{"category": "AFSG", "base_name": "Prot", "date_start": "2023-10-01", "date_end": None, "request_id": ""}],
])
def test_patch_file_afsg(mocked_base_dir, tags, references):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data=DEFAULT_AFSG_DATA,
                           files={'file': ('hhp.pdf', handle, 'application/pdf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    items = response.json()
    fs = items['fs']
    sha256hash = items['sha256hash']
    response = client.patch(f'/api/v1/file/{fs}/{sha256hash}',
                            json={
                                'tags': tags,
                                'references': references,
                            },
                            headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    # TODO check with history that old one is still there
    response = client.get('/api/v1/file')
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': references or [],
                'tags': tags or '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': None,
                'created_timestamp': None,
                'annotations': None,
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
    assert response.json() == {'fs': 'Informatik', 'sha256hash': PDF_HASH}
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
    assert response.json() == {'fs': 'Informatik', 'sha256hash': PDF_HASH}
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
def test_upload_file_invalid_references_value(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response = client.post('/api/v1/file/Informatik',
                           data={
                               **DEFAULT_AFSG_DATA,
                               'references': 'some string but this is invalid',
                           },
                           files={'file': ('hhp.pdf', handle, 'application/rtf')},
                           headers=get_auth_header(client, ADMIN))
    assert response.status_code == 422
    assert response.json() == {'detail': 'references is not a valid json encoded list of values'}
    assert not (mocked_base_dir() / 'Informatik').exists()


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    ADMIN,
])
def test_add_annotation(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response_data = client.post('/api/v1/file/Informatik',
                                data=DEFAULT_AFSG_DATA,
                                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                                headers=get_auth_header(client, ADMIN)).json()
    fs = response_data['fs']
    sha256hash = response_data['sha256hash']
    response = client.post(f'/api/v1/file/{fs}/{sha256hash}', json=[
        {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
        {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
    ], headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.get('/api/v1/file', headers=get_auth_header(client, user))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': [],
                'tags': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
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
    response_data = client.post('/api/v1/file/Informatik',
                                data=DEFAULT_AFSG_DATA,
                                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                                headers=get_auth_header(client, ADMIN)).json()
    fs = response_data['fs']
    sha256hash = response_data['sha256hash']
    response = client.post(f'/api/v1/file/{fs}/{sha256hash}', json=[
        {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
        {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
    ], headers=get_auth_header(client, user))
    assert response.status_code == 401


@mock.patch('app.routers.files.get_base_dir', return_value=Path(TemporaryDirectory().name))
@pytest.mark.parametrize('user', [
    None,
    ADMIN,
])
def test_update_annotation(mocked_base_dir, user):
    handle = BytesIO(EMPTY_PDF_PAGE)
    response_data = client.post('/api/v1/file/Informatik',
                                data=DEFAULT_AFSG_DATA,
                                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                                headers=get_auth_header(client, ADMIN)).json()
    fs = response_data['fs']
    sha256hash = response_data['sha256hash']
    response = client.post(f'/api/v1/file/{fs}/{sha256hash}', json=[
        {'level': 'Error', 'text': 'kaputt'},
    ], headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200
    response = client.post(f'/api/v1/file/{fs}/{sha256hash}', json=[
        {'level': 'Warning', 'text': 'Das Haushaltsjahr sollte angegeben werden'},
        {'level': 'Info', 'text': 'Es handelt sich um das Sose 2023'},
    ], headers=get_auth_header(client, ADMIN))
    assert response.status_code == 200

    response = client.get('/api/v1/file', headers=get_auth_header(client, user))
    assert mask(response.json()) == {
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': [],
                'tags': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
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
                    'date_start': '2023-10-01',
                    'date_end': None,
                    'request_id': '',
                    'references': '',
                    'tags': 'HHP',
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
                    'references': '',
                    'tags': '',
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
                    'references': '[{"category": "AFSG", "base_name": "Prot", "date_start": "2023-10-01",'
                                  ' "date_end": null, "request_id": ""}]',
                    'tags': '',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    client.post('/api/v1/file/Geographie',
                data={
                    'category': 'AFSG',
                    'base_name': 'Wahlergebnis',
                    'date_start': '2023-11-11',
                    'date_end': '2023-11-13',
                    'request_id': '',
                    'references': '',
                    'tags': '',
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
                    'references': '',
                    'tags': 'Erstifahrt',
                },
                files={'file': ('hhp.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, ADMIN))
    response = client.get('/api/v1/file', headers=get_auth_header(client, user))
    assert response.status_code == 200
    assert mask(response.json()) == {
        'Geographie': [
            {
                'category': 'AFSG',
                'base_name': 'Wahlergebnis',
                'date_start': '2023-11-11',
                'date_end': '2023-11-13',
                'request_id': '',
                'references': [],
                'tags': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
            {
                'category': 'BFSG',
                'base_name': 'Abrechnung Getränkebestellung',
                'date_start': None,
                'date_end': None,
                'request_id': 'B23W-0003',
                'references': [],
                'tags': 'Erstifahrt',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
        'Informatik': [
            {
                'category': 'AFSG',
                'base_name': 'Prot',
                'date_start': '2023-10-01',
                'date_end': None,
                'request_id': '',
                'references': [],
                'tags': 'HHP',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
            {
                'category': 'AFSG',
                'base_name': 'HHP',
                'date_start': '2023-10-01',
                'date_end': '2024-09-30',
                'request_id': '',
                'references': [
                    {
                        "category": "AFSG",
                        "base_name": "Prot",
                        "date_start": "2023-10-01",
                        "date_end": None,
                        "request_id": "",
                    },
                ],
                'tags': '',
                'sha256hash': PDF_HASH,
                'file_extension': 'pdf',
                'uploaded_by': ADMIN if user == ADMIN else None,
                'created_timestamp': '[masked]' if user == ADMIN else None,
                'annotations': None,
                'annotations_created_timestamp': None,
                'annotations_created_by': None,
            },
        ],
    }


def test_get_file_history():
    pass
    raise NotImplementedError


def mask(elements: dict[str, list[dict]]):
    for key, value in elements.items():
        for element in value:
            if element['created_timestamp']:
                element['created_timestamp'] = '[masked]'
            if element['annotations_created_timestamp']:
                element['annotations_created_timestamp'] = '[masked]'
    return elements
