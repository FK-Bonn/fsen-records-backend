import json
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from app.config import Config

router = APIRouter()


class SGliedSLine(BaseModel):
    nr: str
    fs: str
    subject: str
    degree: str
    m: str


class CrmLine(BaseModel):
    subject: str
    subject_id: str
    degree: str
    degree_id: str


class CrmLineWithFsId(CrmLine):
    fs_id: str


class SGliedSWithCrmAssignment(BaseModel):
    sglieds: SGliedSLine
    crm: list[CrmLineWithFsId]


class NeedsAssignmentInCrm(BaseModel):
    unassigned: CrmLine
    fs: str


class SGliedSStatusData(BaseModel):
    sglieds_with_crm_assignments: list[SGliedSWithCrmAssignment]
    in_sglieds_but_not_in_crm: list[SGliedSWithCrmAssignment]
    wrong_crm_assignments: list[CrmLineWithFsId]
    needs_assignment_in_crm: list[NeedsAssignmentInCrm]
    needs_assignment_in_sglieds: list[CrmLine]
    last_run: str


def get_base_dir():
    return Config.BASE_SGLIEDS_DIR


@router.get("", response_model=SGliedSStatusData)
async def get_electoral_registers_index():
    return load_state()


@router.get("/crm-update-required", response_model=bool)
async def get_crm_update_required():
    state = load_state()
    if state.wrong_crm_assignments or state.needs_assignment_in_crm:
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail='CRM update required')
    return True


@router.get("/sglieds-update-required", response_model=bool)
async def get_sglieds_update_required():
    state = load_state()
    if state.needs_assignment_in_sglieds:
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail='SGliedS update required')
    return True


@router.get("/last-run-status", response_model=bool)
async def get_last_run_status():
    cutoff = datetime.now(tz=UTC) - timedelta(hours=25)
    state = load_state()
    if state.last_run < cutoff.isoformat():
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail='Last run was more than 25 hours ago')
    return True


def load_state() -> SGliedSStatusData:
    json_file = get_base_dir() / 'crm-state.json'
    return SGliedSStatusData(**json.loads(json_file.read_text()))
