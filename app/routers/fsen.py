import json
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, Permission, FsData, ProtectedFsData
from app.routers.users import get_current_user, admin_only
from app.util import ts, to_json

SUBFOLDERS = {
    'HHP-': 'HHP',
    'HHR-': 'HHR',
    'KP-': 'Kassenpruefungen',
    'Prot-': 'Protokolle',
    'Wahlergebnis-': 'Wahlergebnisse',
}

router = APIRouter()


class EmailAddress(BaseModel):
    address: str
    usages: list[str]


class ServiceTimes(BaseModel):
    monday: str
    tuesday: str
    wednesday: str
    thursday: str
    friday: str


class RegularMeeting(BaseModel):
    dayOfWeek: str
    time: str
    location: str


class FsDataType(BaseModel):
    email: str
    phone: str
    website: str
    address: str
    serviceTimes: ServiceTimes
    regularMeeting: RegularMeeting
    other: dict


class TimestampedFsDataType(FsDataType):
    timestamp: str


class ProtectedFsDataType(BaseModel):
    email_addresses: list[EmailAddress]
    iban: str
    bic: str
    other: dict


class TimestampedProtectedFsDataType(ProtectedFsDataType):
    timestamp: str

class FsDataTuple(BaseModel):
    data: Optional[FsDataType]
    protected_data: Optional[ProtectedFsDataType]


def get_subfolder_from_filename(filename: str) -> Optional[str]:
    for key, value in SUBFOLDERS.items():
        if filename.startswith(key):
            return value
    return None


def check_permission(current_user: User, fs: str,
                     manage_permissions: bool = False,
                     read_files: bool = False,
                     read_public_data: bool = False,
                     write_public_data: bool = False,
                     read_protected_data: bool = False,
                     write_protected_data: bool = False,
                     submit_payout_request: bool = False,
                     ):
    if current_user.admin:
        return
    with DBHelper() as session:
        permission = session.get(Permission, (current_user.username, fs))
        if not permission or \
                (manage_permissions and not permission.write_permissions) or \
                (read_files and not permission.read_files) or \
                (read_public_data and not permission.read_public_data) or \
                (write_public_data and not permission.write_public_data) or \
                (read_protected_data and not permission.read_protected_data) or \
                (write_protected_data and not permission.write_protected_data) or \
                (submit_payout_request and not permission.submit_payout_request):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing permission",
            )


@router.get("/file/{fs}/{filename}", response_class=FileResponse)
async def get_individual_file(fs: str, filename: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_files=True)
    subfolder = get_subfolder_from_filename(filename)
    if not subfolder or '/' in fs or '/' in filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    file_path = Config.BASE_DATA_DIR / fs / subfolder / filename
    if file_path.is_file():
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


@router.get("/data", response_model=dict[str, FsDataTuple])
async def get_all_fsdata(current_user: User = Depends(get_current_user())):
    retval = {}
    with DBHelper() as session:
        subquery = session.query(func.max(FsData.id).label('id'), FsData.fs).group_by(FsData.fs).subquery()
        data = session.query(FsData).join(subquery, FsData.id == subquery.c.id).all()
        prot_subquery = session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
            group_by(ProtectedFsData.fs).subquery()
        prot_data = session.query(ProtectedFsData).join(prot_subquery, ProtectedFsData.id == prot_subquery.c.id).all()
        for row in data:
            permission = session.get(Permission, (current_user.username, row.fs))
            if current_user.admin or (permission and permission.read_public_data):
                retval[row.fs] = FsDataTuple(data=json.loads(row.data), protected_data=None)
        for row in prot_data:
            permission = session.get(Permission, (current_user.username, row.fs))
            if current_user.admin or (permission and permission.read_protected_data):
                if row.fs not in retval:
                    retval[row.fs] = FsDataTuple(data=None, protected_data=None)
                retval[row.fs].protected_data = json.loads(row.data)
        return retval


@router.get("/data/{fs}", response_model=FsDataType)
async def get_fsdata(fs: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_public_data=True)
    with DBHelper() as session:
        subquery = session.query(func.max(FsData.id).label('id')).where(FsData.fs == fs).subquery()
        data = session.query(FsData).filter(FsData.id == subquery.c.id).first()
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return json.loads(data.data)


@router.get("/data/{fs}/history", dependencies=[Depends(admin_only)], response_model=List[TimestampedFsDataType])
async def get_fsdata_history(fs: str):
    with DBHelper() as session:
        data = session.query(FsData).filter(FsData.fs == fs).order_by(FsData.timestamp.desc()).all()
        if not len(data):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return [TimestampedFsDataType(**json.loads(item.data), timestamp=item.timestamp) for item in data]


@router.get("/data/{fs}/protected/history", dependencies=[Depends(admin_only)],
            response_model=List[TimestampedProtectedFsDataType])
async def get_protected_fsdata_history(fs: str):
    with DBHelper() as session:
        data = session.query(ProtectedFsData).filter(ProtectedFsData.fs == fs).order_by(
            ProtectedFsData.timestamp.desc()).all()
        if not len(data):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return [TimestampedProtectedFsDataType(**json.loads(item.data), timestamp=item.timestamp) for item in data]


@router.put("/data/{fs}")
async def set_fsdata(data: FsDataType, fs: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, write_public_data=True)
    with DBHelper() as session:
        db_data = FsData()
        db_data.user = current_user.username
        db_data.fs = fs
        db_data.timestamp = ts()
        db_data.data = to_json(data)
        session.add(db_data)
        session.commit()


@router.get("/data/{fs}/protected", response_model=ProtectedFsDataType)
async def get_protected_fsdata(fs: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_protected_data=True)
    with DBHelper() as session:
        subquery = session.query(func.max(ProtectedFsData.id).label('id')).where(ProtectedFsData.fs == fs).subquery()
        data = session.query(ProtectedFsData).filter(ProtectedFsData.id == subquery.c.id).first()
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return json.loads(data.data)


@router.put("/data/{fs}/protected")
async def set_protected_fsdata(data: ProtectedFsDataType, fs: str,
                               current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, write_protected_data=True)
    with DBHelper() as session:
        db_data = ProtectedFsData()
        db_data.user = current_user.username
        db_data.fs = fs
        db_data.timestamp = ts()
        db_data.data = to_json(data)
        session.add(db_data)
        session.commit()
