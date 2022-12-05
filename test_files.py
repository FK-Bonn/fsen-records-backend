from fastapi.testclient import TestClient

from conftest import get_auth_header
from main import app

client = TestClient(app)


def test_get_single_file_unauthorized():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf')
    assert response.status_code == 401


def test_get_single_file_no_permission():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client, 'user'))
    assert response.status_code == 401


def test_get_single_file():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 200


def test_get_single_file_as_admin():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31.pdf',
                          headers=get_auth_header(client, 'admin'))
    assert response.status_code == 200


def test_get_single_nonexisting_file():
    response = client.get('/api/v1/file/Informatik/HHP-2022-02-01--2023-03-31-does-not-exist.pdf',
                          headers=get_auth_header(client))
    assert response.status_code == 404
