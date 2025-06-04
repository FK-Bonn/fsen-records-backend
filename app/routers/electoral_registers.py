import json
from datetime import datetime, date, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, ElectoralRegisterDownload, SessionDep
from app.routers.users import get_current_user, admin_only
from app.util import ts

router = APIRouter()


class ElectoralRegisterDownloadData(BaseModel):
    timestamp: str
    username: str
    filepath: str


class ElectoralRegisterStatusData(BaseModel):
    last_successful_run: str
    last_data_change: str
    unassigned_faks: list[str]


class Fraction(BaseModel):
    numerator: int
    denominator: int

def get_base_dir():
    return Config.BASE_ELECTORAL_REGISTERS_DIR


@router.get("", response_model=dict[str, list[str]])
async def get_electoral_registers_index():
    files = {}
    for subdir in sorted(d for d in get_base_dir().glob('*') if d.is_dir()):
        registers = sorted(f.name for f in subdir.glob('*.zip'))
        files[subdir.name] = registers
    return files


@router.get("/log", response_model=list[ElectoralRegisterDownloadData])
async def get_electoral_registers_log(session: SessionDep):
    one_year_ago = (datetime.now(tz=timezone.utc) - timedelta(days=365)).isoformat()
    return session.query(ElectoralRegisterDownload). \
        where(ElectoralRegisterDownload.timestamp > one_year_ago). \
        order_by(desc(ElectoralRegisterDownload.timestamp)).all()


@router.get("/funds", response_model=dict[date, dict[str, Fraction]])
async def get_funds():
    funds = {}
    for subdir in sorted(d for d in get_base_dir().glob('*') if d.is_dir()):
        file_path = subdir / 'funds-distribution.json'
        if file_path.is_file():
            value = json.loads(file_path.read_text())
            funds[subdir.name] = dict(sorted(value.items()))
    return funds


@router.get("/status", response_model=ElectoralRegisterStatusData)
async def get_electoral_registers_status():
    file_path = get_base_dir() / 'status.json'
    return ElectoralRegisterStatusData(**json.loads(file_path.read_text()))


@router.get("/status/unassigned-faks")
async def get_electoral_registers_status_unassigned_faks(response: Response):
    file_path = get_base_dir() / 'status.json'
    data = ElectoralRegisterStatusData(**json.loads(file_path.read_text()))
    if is_unhealthy_unassigned_faks(data):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return data


@router.get("/status/last-run")
async def get_electoral_registers_status_last_run(response: Response):
    file_path = get_base_dir() / 'status.json'
    data = ElectoralRegisterStatusData(**json.loads(file_path.read_text()))
    if is_unhealthy_last_run(data):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return data


@router.get("/{deadline_date}/{filename}", response_class=FileResponse, dependencies=[Depends(admin_only)])
async def get_individual_file(deadline_date: date, filename: str, session: SessionDep,
                              current_user: User = Depends(get_current_user())):
    if '/' in filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    raise_if_more_than_five_downloads_today(session)
    file_path = get_base_dir() / str(deadline_date) / filename
    if file_path.is_file():
        log_access(file_path, current_user.username, session)
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


def raise_if_more_than_five_downloads_today(session: Session):
    start_of_today = datetime.now(tz=timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    count = session.query(func.count(ElectoralRegisterDownload.id)). \
        where(ElectoralRegisterDownload.timestamp > start_of_today).scalar()
    if count >= 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only five electoral registers may be downloaded every day",
        )


def log_access(file_path: Path, username: str, session: Session):
    logged_path = str(file_path.relative_to(get_base_dir()))
    item = ElectoralRegisterDownload(timestamp=ts(), username=username, filepath=logged_path)
    session.add(item)
    session.commit()


def is_unhealthy_last_run(data):
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(hours=25)).isoformat()
    return data.last_successful_run < cutoff


def is_unhealthy_unassigned_faks(data):
    return len(data.unassigned_faks) != 0
