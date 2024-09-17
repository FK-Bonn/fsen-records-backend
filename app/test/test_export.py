from fastapi.testclient import TestClient

from app.main import app
from app.test.test_fsdata import set_sample_public_data, SAMPLE_PUBLIC_DATA

client = TestClient(app)

FILTERED_DATA = {key: value for key, value in SAMPLE_PUBLIC_DATA.items() if key not in ('other', 'email')}


def test_export_public_fs_data():
    set_sample_public_data()
    set_sample_public_data(fs='Geographie')
    response = client.get('/api/v1/export/public-fs-data')
    assert response.status_code == 200
    assert response.json() == {'Geographie': FILTERED_DATA, 'Informatik': FILTERED_DATA}
