import json
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.database import get_session
from app.main import app, subapp
from app.test.conftest import get_auth_header, USER_INFO_ALL, USER_INFO_READ, ADMIN, USER_NO_PERMS, fake_session

client = TestClient(app)
subapp.dependency_overrides[get_session] = fake_session


@pytest.mark.parametrize('user', [
    None,
    ADMIN,
    USER_NO_PERMS,
    USER_INFO_READ,
    USER_INFO_ALL,
])
@mock.patch('app.routers.sglieds.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_sglieds_index(mocked_base_dir, user):
    json_file = create_mock_json(mocked_base_dir())
    result = client.get('/api/v1/sglieds/', headers=get_auth_header(client, user))
    assert result.status_code == 200
    assert result.json() == json.loads(json_file.read_text())


@pytest.mark.parametrize('extra_sglieds,wrong_crm,missing_in_crm,missing_in_sglieds,last_run_too_late', [
    [True, False, False, False, False],
    [False, True, False, False, False],
    [False, False, True, False, False],
    [False, False, False, True, False],
    [False, False, False, False, True],
])
@mock.patch('app.routers.sglieds.get_base_dir', return_value=Path(TemporaryDirectory().name))
def test_electoral_registers_status(
        mocked_base_dir,
        extra_sglieds: bool,
        wrong_crm: bool,
        missing_in_crm: bool,
        missing_in_sglieds: bool,
        last_run_too_late: bool,
):
    json_file = create_mock_json(
        mocked_base_dir(),
        extra_sglieds=extra_sglieds,
        wrong_crm=wrong_crm,
        missing_in_crm=missing_in_crm,
        missing_in_sglieds=missing_in_sglieds,
        last_run_too_late=last_run_too_late,
    )
    result = client.get('/api/v1/sglieds/')
    assert result.status_code == 200
    assert result.json() == json.loads(json_file.read_text())

    result = client.get('/api/v1/sglieds/crm-update-required')
    assert result.status_code == 500 if (wrong_crm or missing_in_crm) else 200
    result = client.get('/api/v1/sglieds/sglieds-update-required')
    assert result.status_code == 500 if missing_in_sglieds else 200
    result = client.get('/api/v1/sglieds/last-run-status')
    assert result.status_code == 500 if last_run_too_late else 200


def create_mock_json(
        directory: Path,
        extra_sglieds: bool = False,
        wrong_crm: bool = False,
        missing_in_crm: bool = False,
        missing_in_sglieds: bool = False,
        last_run_too_late: bool = False,
) -> Path:
    sglieds_with_crm_assignments = [
        {
            "sglieds": {
                "nr": "1.1.",
                "fs": "Agrarwissenschaften",
                "subject": "Agrarwissenschaften",
                "degree": "Bachelor of Science",
                "m": ""
            },
            "crm": [
                {
                    "fs_id": "0020",
                    "subject": "Agrarwissenschaften",
                    "subject_id": "317",
                    "degree": "Bachelor of Science",
                    "degree_id": "44"
                }
            ]
        }
    ]
    in_sglieds_but_not_in_crm = []
    if extra_sglieds:
        in_sglieds_but_not_in_crm.append({
            "sglieds": {
                "nr": "1.4.",
                "fs": "Agrarwissenschaften",
                "subject": "Naturschutz u.Landsch.ök.",
                "degree": "Master of Science",
                "m": ""
            },
            "crm": []
        })
    wrong_crm_assignments = []
    if wrong_crm:
        wrong_crm_assignments.append({
            "fs_id": "0044",
            "subject": "Katholische Theologie",
            "subject_id": "099",
            "degree": "Promotion",
            "degree_id": "31"
        })
    needs_assignment_in_crm = []
    if missing_in_crm:
        needs_assignment_in_crm.append({
            "unassigned": {
                "degree_id": "56",
                "degree": "Bachelor of Arts",
                "subject_id": "433",
                "subject": "Kunstgeschichte"
            },
            "fs": "Kunstgeschichte"
        })
    needs_assignment_in_sglieds = []
    if missing_in_sglieds:
        needs_assignment_in_sglieds.append({
            "degree_id": "31",
            "degree": "Promotion",
            "subject_id": "633",
            "subject": "Ökonomie"
        })
    if last_run_too_late:
        now = datetime.now() - timedelta(days=1, hours=12)
    else:
        now = datetime.now()
    target_file = directory / 'crm-state.json'
    directory.mkdir(parents=True, exist_ok=True)
    target_file.write_text(json.dumps({
        "sglieds_with_crm_assignments": sglieds_with_crm_assignments,
        "in_sglieds_but_not_in_crm": in_sglieds_but_not_in_crm,  # WARNING?
        "wrong_crm_assignments": wrong_crm_assignments,  # ERROR
        "needs_assignment_in_crm": needs_assignment_in_crm,  # ERROR
        "needs_assignment_in_sglieds": needs_assignment_in_sglieds,  # ERROR
        "last_run": now.isoformat(),
    }))
    return target_file
