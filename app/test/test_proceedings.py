import base64
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.test.conftest import get_auth_header

EMPTY_PDF_PAGE = base64.b64decode("""JVBERi0xLjUKJbXtrvsKNCAwIG9iago8PCAvTGVuZ3RoIDUgMCBSCiAgIC9GaWx0ZXIgL0ZsYXRl
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
dGFydHhyZWYKNjMzCiUlRU9GCg==""")

PDF_HASH = '1b318799de440475e51646b29c4c5a838d031548e0bdf6566802b6731082a23c'

client = TestClient(app)


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'},
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user3'))
    assert result.status_code == 200
    assert (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf').exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload_unauthenticated_fails(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'},
                         files={'file': ('prot.pdf', handle, 'application/pdf')})
    assert result.status_code == 401
    assert not (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf').exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload_no_fs_permission(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'},
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user'))
    assert result.status_code == 401
    assert not (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf').exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload_missing_upload_permission(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'},
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user2'))
    assert result.status_code == 401
    assert not (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf').exists()


@pytest.mark.parametrize('key_to_set_none', [
    'committee',
    'date',
])
@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload_missing_field_fails(mocked_base_dir, key_to_set_none):
    handle = BytesIO(EMPTY_PDF_PAGE)
    data = {'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'}
    data[key_to_set_none] = None
    result = client.post('/api/v1/proceedings/Informatik',
                         data=data,
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user2'))
    assert result.status_code == 422
    assert not (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf').exists()


@pytest.mark.parametrize('key,value', [
    ['committee', 'Invalid'],
    ['date', '30.05.2024'],
])
@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload_invalid_field_values(mocked_base_dir, key, value):
    handle = BytesIO(EMPTY_PDF_PAGE)
    data = {'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'}
    data[key] = value
    result = client.post('/api/v1/proceedings/Informatik',
                         data=data,
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user2'))
    assert result.status_code == 422
    assert not (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf').exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_upload_overwrite_existing_file(mocked_base_dir):
    target_file = (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf')

    handle = BytesIO(b'%PDF-overwrite_me')
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': 'HHP,Wahl KP'},
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user3'))
    assert result.status_code == 200
    assert target_file.read_bytes() == b'%PDF-overwrite_me'

    handle = BytesIO(EMPTY_PDF_PAGE)
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': ''},
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user3'))
    assert result.status_code == 200
    assert target_file.read_bytes() == EMPTY_PDF_PAGE


def create_sample_proceedings(target_file):
    handle = BytesIO(EMPTY_PDF_PAGE)
    result = client.post('/api/v1/proceedings/Informatik',
                         data={'committee': 'FSV', 'date': '2024-05-30', 'tags': ''},
                         files={'file': ('prot.pdf', handle, 'application/pdf')},
                         headers=get_auth_header(client, 'user3'))
    assert result.status_code == 200
    assert target_file.exists()


@pytest.mark.parametrize('username', [
    'user3',
    'admin',
])
@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_delete_file(mocked_base_dir, username):
    target_file = (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf')
    create_sample_proceedings(target_file)

    result = client.delete('/api/v1/proceedings/Informatik/FSV/2024-05-30',
                           headers=get_auth_header(client, username))
    assert result.status_code == 200
    assert not target_file.exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_nonexisting_file(mocked_base_dir):
    result = client.delete('/api/v1/proceedings/Informatik/FSR/2024-11-11',
                           headers=get_auth_header(client, 'user3'))
    assert result.status_code == 404


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_delete_file_not_authorized(mocked_base_dir):
    target_file = (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf')
    create_sample_proceedings(target_file)

    result = client.delete('/api/v1/proceedings/Informatik/FSV/2024-05-30')
    assert result.status_code == 401
    assert target_file.exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_delete_file_missing_permission(mocked_base_dir):
    target_file = (mocked_base_dir.return_value / 'Informatik' / 'Prot-FSV-2024-05-30.pdf')
    create_sample_proceedings(target_file)

    result = client.delete('/api/v1/proceedings/Informatik/FSV/2024-05-30',
                           headers=get_auth_header(client, 'user2'))
    assert result.status_code == 401
    assert target_file.exists()


@mock.patch('app.routers.proceedings.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_proceedings_list(mocked_base_dir):
    handle = BytesIO(EMPTY_PDF_PAGE)
    client.post('/api/v1/proceedings/Informatik',
                data={'committee': 'FSV', 'date': '2024-03-30', 'tags': 'HHP,Wahl KP'},
                files={'file': ('prot.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, 'user3'))
    client.post('/api/v1/proceedings/Informatik',
                data={'committee': 'FSV', 'date': '2024-03-20', 'tags': 'hoppla'},
                files={'file': ('prot.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, 'user3'))
    client.post('/api/v1/proceedings/Informatik',
                data={'committee': 'FSV', 'date': '2024-03-20', 'tags': 'HHP,Wahl KP'},
                files={'file': ('prot.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, 'user3'))
    client.post('/api/v1/proceedings/Informatik',
                data={'committee': 'FSR', 'date': '2024-02-22', 'tags': 'oopsie'},
                files={'file': ('prot.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, 'user3'))
    client.delete('/api/v1/proceedings/Informatik/FSR/2024-02-22',
                  headers=get_auth_header(client, 'user3'))
    client.post('/api/v1/proceedings/Geographie',
                data={'committee': 'FSV', 'date': '2024-04-30', 'tags': 'Finanzen'},
                files={'file': ('prot.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, 'user5'))
    client.post('/api/v1/proceedings/Informatik',
                data={'committee': 'FSR', 'date': '2024-05-30', 'tags': ''},
                files={'file': ('prot.pdf', handle, 'application/pdf')},
                headers=get_auth_header(client, 'user3'))
    response = client.get('/api/v1/proceedings')
    assert response.status_code == 200
    assert response.json() == [
        {'fs': 'Geographie', 'committee': 'FSV', 'date': '2024-04-30', 'tags': 'Finanzen', 'sha256hash': PDF_HASH},
        {'fs': 'Informatik', 'committee': 'FSR', 'date': '2024-05-30', 'tags': '', 'sha256hash': PDF_HASH},
        {'fs': 'Informatik', 'committee': 'FSV', 'date': '2024-03-30', 'tags': 'HHP,Wahl KP', 'sha256hash': PDF_HASH},
        {'fs': 'Informatik', 'committee': 'FSV', 'date': '2024-03-20', 'tags': 'HHP,Wahl KP', 'sha256hash': PDF_HASH},
    ]


@pytest.mark.parametrize('source_ip', [
    '127.0.0.1',
    '::1',
    '131.220.69.69',
    '2a00:5ba0::6969:6969',
])
def test_proceedings_download(source_ip: str):
    with mock.patch('app.routers.proceedings.get_source_ip', return_value=source_ip):
        response = client.get('/api/v1/proceedings/Informatik/Prot-FSV-2024-05-30.pdf')
    assert response.status_code == 200


@pytest.mark.parametrize('source_ip', [
    '10.20.30.40',
    '0000:1111:2222:3333:4444:5555:6666:7777',
])
def test_proceedings_download_outside_of_allowed_network_fails(source_ip: str):
    with mock.patch('app.routers.proceedings.get_source_ip', return_value=source_ip):
        response = client.get('/api/v1/proceedings/Informatik/Prot-FSV-2024-05-30.pdf')
    assert response.status_code == 401


@pytest.mark.parametrize('source_ip', [
    '10.20.30.40',
    '0000:1111:2222:3333:4444:5555:6666:7777',
])
def test_proceedings_download_outside_of_allowed_network_while_authenticated(source_ip: str):
    with mock.patch('app.routers.proceedings.get_source_ip', return_value=source_ip):
        response = client.get('/api/v1/proceedings/Informatik/Prot-FSV-2024-05-30.pdf',
                              headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200
