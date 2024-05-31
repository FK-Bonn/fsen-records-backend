import datetime
import shutil
from enum import Enum
from hashlib import file_digest
from ipaddress import IPv6Address, IPv4Address, IPv4Network, IPv6Network, ip_address
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, Form
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, Proceedings
from app.routers.users import get_current_user
from app.util import ts

router = APIRouter()

IPV4_LOCALHOST = IPv4Address("127.0.0.1")
IPV6_LOCALHOST = IPv6Address("::1")
IPV4_UNI_NETWORK = IPv4Network("131.220.0.0/16")
IPV6_UNI_NETWORK = IPv6Network("2a00:5ba0::/29")


class CommitteeType(Enum):
    FSV = 'FSV'
    FSR = 'FSR'
    FSVV = 'FSVV'
    WVV = 'WVV'
    WA = 'WA'


class ProceedingsData(BaseModel):
    fs: str
    committee: str
    date: str
    tags: str
    sha256hash: str


def get_base_dir():
    return Config.BASE_PROCEEDINGS_DIR


def is_access_allowed(source_ip: str, current_user: User | None) -> bool:
    try:
        if current_user:
            return True
        address = ip_address(source_ip)
        return address == IPV6_LOCALHOST or address in IPV6_UNI_NETWORK \
            or address == IPV4_LOCALHOST or address in IPV4_UNI_NETWORK
    except ValueError:
        return False


def get_source_ip(request: Request) -> str:
    return request.client.host if request.client else 'invalid'


def check_user_may_upload_proceedings(current_user: User, fs: str, session: Session):
    creator = session.get(User, current_user.username)
    if not creator:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User not found",
        )
    if creator.admin:
        return

    creatorpermissions = {p.fs: p.upload_proceedings for p in creator.permissions}
    if not creatorpermissions.get(fs, False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to upload proceedings for this fs",
        )


def check_user_may_delete_proceedings(current_user: User, fs: str, session: Session):
    creator = session.get(User, current_user.username)
    if not creator:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User not found",
        )
    if creator.admin:
        return

    creatorpermissions = {p.fs: p.delete_proceedings for p in creator.permissions}
    if not creatorpermissions.get(fs, False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to delete proceedings for this fs",
        )


async def check_uploaded_file_is_pdf(file: UploadFile):
    start = await file.read(5)
    await file.seek(0)
    if start != b'%PDF-':
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only PDF files are allowed",
        )


@router.post("/proceedings/{fs}")
async def upload_proceedings(
        fs: str,
        file: UploadFile,
        committee: Annotated[CommitteeType, Form()],
        date: Annotated[datetime.date, Form()],
        tags: Annotated[str, Form()] = '',
        current_user: User = Depends(get_current_user()),
):
    with DBHelper() as session:
        check_user_may_upload_proceedings(current_user, fs, session)
        await check_uploaded_file_is_pdf(file)
        filename = f'Prot-{committee.value}-{date}.pdf'
        target_dir = get_base_dir() / fs
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / filename
        with target_file.open('wb+') as f:
            shutil.copyfileobj(file.file, f)
        with target_file.open('rb') as f:
            sha256hash = file_digest(f, 'sha256')
        session.query(Proceedings). \
            where(Proceedings.fs == fs,
                  Proceedings.committee == committee.value,
                  Proceedings.date == date.isoformat(),
                  Proceedings.deleted_by.is_(None)). \
            update({'deleted_by': current_user.username})
        proceedings = Proceedings()
        proceedings.fs = fs
        proceedings.committee = committee.value
        proceedings.date = date.isoformat()
        proceedings.tags = tags or ''
        proceedings.sha256hash = sha256hash.hexdigest()
        proceedings.upload_date = ts()
        proceedings.uploaded_by = current_user.username
        session.add(proceedings)
        session.commit()


@router.delete("/proceedings/{fs}/{committee}/{date}")
async def delete_proceedings(
        fs: str,
        committee: CommitteeType,
        date: datetime.date,
        current_user: User = Depends(get_current_user()),
):
    with DBHelper() as session:
        check_user_may_delete_proceedings(current_user, fs, session)
        filename = f'Prot-{committee.value}-{date}.pdf'
        target_file = get_base_dir() / fs / filename
        if not target_file.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="This proceedings file does not exist",
            )
        target_file.unlink(missing_ok=True)
        session.query(Proceedings). \
            where(Proceedings.fs == fs,
                  Proceedings.committee == committee.value,
                  Proceedings.date == date.isoformat(),
                  Proceedings.deleted_by.is_(None)). \
            update({Proceedings.deleted_by: current_user.username})
        session.commit()


@router.get("/proceedings/{fs}/{filename}", response_class=FileResponse)
async def get_individual_file(fs: str, filename: str, request: Request,
                              current_user: User | None = Depends(get_current_user(auto_error=False))):
    source_ip = get_source_ip(request)
    if not is_access_allowed(source_ip, current_user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Only available from the university network. You are however coming from: " + source_ip,
        )
    if '/' in fs or '/' in filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    file_path = Config.BASE_PROCEEDINGS_DIR / fs / filename
    if file_path.is_file():
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


@router.get("/proceedings", response_model=list[ProceedingsData])
async def get_proceedings_index():
    with DBHelper() as session:
        return session.query(Proceedings). \
            where(Proceedings.deleted_by.is_(None)). \
            order_by(Proceedings.fs, Proceedings.committee, desc(Proceedings.date)).all()
