import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from time_machine import travel

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import get_auth_header, USER_INFO_ALL, USER_INFO_READ, ADMIN, USER_NO_PERMS, fake_session
from app.util import ts

ZIP_FILE = b'not-a-real-zip'

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session



@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_index(mocked_base_dir, user):
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Fachschaft-Informatik.zip')
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Fachschaft-Physik-Astronomie.zip')
    create_register(mocked_base_dir.return_value / '2024-11-12' / 'Fachschaft-Informatik.zip')
    create_register(mocked_base_dir.return_value / '2024-11-12' / 'Fachschaft-Geod-sie.zip')
    result = client.get('/api/v1/electoral-registers/', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == {
        '2024-11-11': [
            'Fachschaft-Informatik.zip',
            'Fachschaft-Physik-Astronomie.zip',
        ],
        '2024-11-12': [
            'Fachschaft-Geod-sie.zip',
            'Fachschaft-Informatik.zip',
        ],
    }


@pytest.mark.parametrize('user', [
    None,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_download_fails_for_non_admin(mocked_base_dir, user):
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Informatik.zip')
    result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, user))
    assert result.status_code == 401
    assert result.read() != ZIP_FILE


@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_download_succeeds_for_admin(mocked_base_dir):
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Informatik.zip')
    result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200
    assert result.read() == ZIP_FILE


@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_only_five_downloads_per_day(mocked_base_dir):
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Informatik.zip')
    for i in range(5):
        result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, ADMIN))
        assert result.status_code == 200
        assert result.read() == ZIP_FILE

    result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 403
    assert result.json() == {'detail': 'Only five electoral registers may be downloaded every day'}


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
@travel("2024-11-11T11:11:00Z", tick=False)
def test_electoral_registers_successful_download_gets_logged(mocked_base_dir, user):
    create_register(mocked_base_dir.return_value / '2024-11-11' / 'Informatik.zip')
    result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 200

    result = client.get('/api/v1/electoral-registers/log',
                        headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == [
        {
            'timestamp': '2024-11-11T11:11:00+00:00',
            'username': ADMIN,
            'filepath': '2024-11-11/Informatik.zip',
        }
    ]


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_miss_does_not_get_logged(mocked_base_dir, user):
    result = client.get('/api/v1/electoral-registers/2024-11-11/Informatik.zip',
                        headers=get_auth_header(client, ADMIN))
    assert result.status_code == 404

    result = client.get('/api/v1/electoral-registers/log',
                        headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == []


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_status_success(mocked_base_dir, user):
    expected = {
        'last_successful_run': ts(),
        'last_data_change': '1970-01-01T00:00:00Z',
        'unassigned_faks': [],
    }
    mocked_base_dir.return_value.mkdir(exist_ok=True, parents=True)
    (mocked_base_dir.return_value / 'status.json').write_text(json.dumps(expected))
    result = client.get('/api/v1/electoral-registers/status', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == expected
    result = client.get('/api/v1/electoral-registers/status/unassigned-faks', headers=get_auth_header(client, user))
    assert result.status_code == 200
    result = client.get('/api/v1/electoral-registers/status/last-run', headers=get_auth_header(client, user))
    assert result.status_code == 200


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_status_issue_missed_run(mocked_base_dir, user):
    error_ts = (datetime.now(tz=timezone.utc) - timedelta(hours=26)).isoformat()
    expected = {
        'last_successful_run': error_ts,
        'last_data_change': '1970-01-01T00:00:00Z',
        'unassigned_faks': [],
    }
    mocked_base_dir.return_value.mkdir(exist_ok=True, parents=True)
    (mocked_base_dir.return_value / 'status.json').write_text(json.dumps(expected))
    result = client.get('/api/v1/electoral-registers/status', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == expected
    result = client.get('/api/v1/electoral-registers/status/unassigned-faks', headers=get_auth_header(client, user))
    assert result.status_code == 200
    result = client.get('/api/v1/electoral-registers/status/last-run', headers=get_auth_header(client, user))
    assert result.status_code == 500


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_status_issue_unassigned_faks(mocked_base_dir, user):
    expected = {
        'last_successful_run': ts(),
        'last_data_change': '1970-01-01T00:00:00Z',
        'unassigned_faks': [
            "FAK(degree='Promotion', subject='Didaktik der Naturwiss.')"
        ],
    }
    mocked_base_dir.return_value.mkdir(exist_ok=True, parents=True)
    (mocked_base_dir.return_value / 'status.json').write_text(json.dumps(expected))
    result = client.get('/api/v1/electoral-registers/status', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == expected
    result = client.get('/api/v1/electoral-registers/status/unassigned-faks', headers=get_auth_header(client, user))
    assert result.status_code == 500
    result = client.get('/api/v1/electoral-registers/status/last-run', headers=get_auth_header(client, user))
    assert result.status_code == 200

@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_status_issue_unassigned_faks_and_last_run(mocked_base_dir, user):
    error_ts = (datetime.now(tz=timezone.utc) - timedelta(hours=26)).isoformat()
    expected = {
        'last_successful_run': error_ts,
        'last_data_change': '1970-01-01T00:00:00Z',
        'unassigned_faks': [
            "FAK(degree='Promotion', subject='Didaktik der Naturwiss.')"
        ],
    }
    mocked_base_dir.return_value.mkdir(exist_ok=True, parents=True)
    (mocked_base_dir.return_value / 'status.json').write_text(json.dumps(expected))
    result = client.get('/api/v1/electoral-registers/status', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == expected
    result = client.get('/api/v1/electoral-registers/status/unassigned-faks', headers=get_auth_header(client, user))
    assert result.status_code == 500
    result = client.get('/api/v1/electoral-registers/status/last-run', headers=get_auth_header(client, user))
    assert result.status_code == 500


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.electoral_registers.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_funds_index(mocked_base_dir, user):
    expected1 = create_funds(mocked_base_dir.return_value / '2024-11-11', 69)
    expected2 = create_funds(mocked_base_dir.return_value / '2024-11-12', 420)
    result = client.get('/api/v1/electoral-registers/funds', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == {
        '2024-11-11': expected1,
        '2024-11-12': expected2,
    }


def create_register(target_file: Path):
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_bytes(ZIP_FILE)


def create_funds(target_dir: Path, value: int) -> dict:
    content = {
        "unknown": {
            "numerator": value,
            "denominator": 20
        },
        "Psychologie": {
            "numerator": 62279,
            "denominator": 60
        },
        "Lehramt": {
            "numerator": 202917,
            "denominator": 140
        },
    }
    target_dir.mkdir(exist_ok=True, parents=True)
    (target_dir / 'funds-distribution.json').write_text(json.dumps(content))
    return content
