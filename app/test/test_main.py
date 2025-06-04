from fastapi.testclient import TestClient

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import fake_session

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session


def test_read_main():
    response = client.get('/api/v1')
    assert response.status_code == 404

