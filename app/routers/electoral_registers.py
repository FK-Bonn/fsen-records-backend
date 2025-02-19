import json
from datetime import datetime, date, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import desc
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, ElectoralRegisterDownload
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


def get_base_dir():
    return Config.BASE_ELECTORAL_REGISTERS_DIR


@router.get("/{deadline_date}/{filename}", response_class=FileResponse, dependencies=[Depends(admin_only)])
async def get_individual_file(deadline_date: date, filename: str,
                              current_user: User = Depends(get_current_user())):
    if '/' in filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    file_path = get_base_dir() / str(deadline_date) / filename
    if file_path.is_file():
        log_access(file_path, current_user.username)
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


def log_access(file_path: Path, username: str):
    logged_path = str(file_path.relative_to(get_base_dir()))
    with DBHelper() as session:
        item = ElectoralRegisterDownload(timestamp=ts(), username=username, filepath=logged_path)
        session.add(item)
        session.commit()


@router.get("", response_model=dict[str, list[str]])
async def get_electoral_registers_index():
    files = {}
    for subdir in sorted(d for d in get_base_dir().glob('*') if d.is_dir()):
        registers = sorted(f.name for f in subdir.glob('*.zip'))
        files[subdir.name] = registers
    return files


@router.get("/log", response_model=list[ElectoralRegisterDownloadData])
async def get_electoral_registers_log():
    one_year_ago = (datetime.now(tz=timezone.utc) - timedelta(days=365)).isoformat()
    with DBHelper() as session:
        return session.query(ElectoralRegisterDownload). \
            where(ElectoralRegisterDownload.timestamp > one_year_ago). \
            order_by(desc(ElectoralRegisterDownload.timestamp)).all()


@router.get("/status", response_model=ElectoralRegisterStatusData)
async def get_electoral_registers_status(response: Response):
    file_path = get_base_dir() / 'status.json'
    data = ElectoralRegisterStatusData(**json.loads(file_path.read_text()))
    if is_unhealthy(data):
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return data


def is_unhealthy(data):
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(hours=25)).isoformat()
    return data.last_successful_run < cutoff or len(data.unassigned_faks)
