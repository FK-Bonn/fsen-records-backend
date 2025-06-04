from fastapi.testclient import TestClient

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import get_auth_header, ADMIN, fake_session
from app.test.test_fsdata import set_sample_public_data, SAMPLE_PUBLIC_DATA, set_sample_base_data, SAMPLE_BASE_DATA

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session

FILTERED_DATA = {key: value for key, value in SAMPLE_PUBLIC_DATA.items() if key not in ('other', 'email')}


def test_export_public_fs_data():
    set_sample_base_data()
    set_sample_public_data()
    set_sample_base_data(fs='Geographie')
    set_sample_public_data(fs='Geographie')
    set_sample_base_data(fs='Inactive')
    set_sample_public_data(fs='Inactive')
    client.put('/api/v1/data/Inactive/base', json={**SAMPLE_BASE_DATA, 'name': 'Inactive', 'active': False},
               headers=get_auth_header(client, ADMIN))
    response = client.get('/api/v1/export/public-fs-data')
    assert response.status_code == 200
    assert response.json() == {
        'Geographie': {**FILTERED_DATA, 'name': 'Geographie'},
        'Informatik': {**FILTERED_DATA, 'name': 'Informatik'},
    }
