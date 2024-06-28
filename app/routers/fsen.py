import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from starlette import status

from app.database import User, DBHelper, Permission, FsData, ProtectedFsData
from app.routers.users import get_current_user, admin_only
from app.util import ts, to_json

LAST_FS_DATA_FORMAT_UPDATE = '2023-01-01'

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


class PublicFsData(BaseModel):
    phone: str
    website: str
    address: str
    serviceTimes: ServiceTimes
    regularMeeting: RegularMeeting


class FsDataType(PublicFsData):
    email: str
    other: dict


class FsDataResponse(BaseModel):
    data: FsDataType
    is_latest: bool


class TimestampedFsDataType(FsDataType):
    id: int
    user: str
    approved: bool
    approved_by: str | None
    approval_timestamp: str | None
    timestamp: str


class ProtectedFsDataType(BaseModel):
    email_addresses: list[EmailAddress]
    iban: str
    bic: str
    other: dict


class ProtectedFsDataResponse(BaseModel):
    data: ProtectedFsDataType
    is_latest: bool


class TimestampedProtectedFsDataType(ProtectedFsDataType):
    id: int
    user: str
    approved: bool
    approved_by: str | None
    approval_timestamp: str | None
    timestamp: str


class FsDataTuple(BaseModel):
    data: FsDataResponse | None
    protected_data: ProtectedFsDataResponse | None


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


@router.get("", response_model=dict[str, FsDataTuple])
async def get_all_fsdata(current_user: User = Depends(get_current_user())):
    retval = {}
    with DBHelper() as session:
        subquery = session.query(func.max(FsData.id).label('id'), FsData.fs). \
            where(FsData.approved.is_(True)). \
            group_by(FsData.fs).subquery()
        data = session.query(FsData).join(subquery, FsData.id == subquery.c.id).all()
        latest_ids_for_data = {row.fs: row.id for row in
                               session.query(func.max(FsData.id).label('id'), FsData.fs). \
                                   group_by(FsData.fs).all()}
        prot_subquery = session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
            where(ProtectedFsData.approved.is_(True)). \
            group_by(ProtectedFsData.fs).subquery()
        prot_data = session.query(ProtectedFsData).join(prot_subquery, ProtectedFsData.id == prot_subquery.c.id).all()
        latest_ids_for_prot_data = {row.fs: row.id for row in
                                    session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
                                        group_by(ProtectedFsData.fs).all()}
        for row in data:
            permission = session.get(Permission, (current_user.username, row.fs))
            if current_user.admin or (permission and permission.read_public_data):
                retval[row.fs] = FsDataTuple(data=FsDataResponse(data=json.loads(row.data), is_latest=(
                        row.id == latest_ids_for_data.get(row.fs, None))),
                                             protected_data=None)
        for row in prot_data:
            permission = session.get(Permission, (current_user.username, row.fs))
            if current_user.admin or (permission and permission.read_protected_data):
                if row.fs not in retval:
                    retval[row.fs] = FsDataTuple(data=None, protected_data=None)
                retval[row.fs].protected_data = ProtectedFsDataResponse(data=json.loads(row.data), is_latest=(
                        row.id == latest_ids_for_prot_data.get(row.fs, None)))
        return retval


@router.get("/{fs}", response_model=FsDataResponse)
async def get_fsdata(fs: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_public_data=True)
    with DBHelper() as session:
        subquery = session.query(func.max(FsData.id).label('id')). \
            where(FsData.fs == fs, FsData.approved.is_(True)).subquery()
        data = session.query(FsData).filter(FsData.id == subquery.c.id).first()
        latest_id = session.query(func.max(FsData.id).label('id')). \
            where(FsData.fs == fs).scalar()
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return FsDataResponse(data=json.loads(data.data), is_latest=data.id == latest_id)


@router.get("/{fs}/history", dependencies=[Depends(admin_only)], response_model=list[TimestampedFsDataType])
async def get_fsdata_history(fs: str):
    with DBHelper() as session:
        data = session.query(FsData). \
            filter(FsData.fs == fs, FsData.timestamp > LAST_FS_DATA_FORMAT_UPDATE). \
            order_by(FsData.timestamp.desc()).all()
        if not len(data):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return [TimestampedFsDataType(**json.loads(item.data),
                                      id=item.id,
                                      user=item.user,
                                      timestamp=item.timestamp,
                                      approved=item.approved,
                                      approved_by=item.approved_by,
                                      approval_timestamp=item.approval_timestamp) for item in data]


@router.get("/{fs}/protected/history", dependencies=[Depends(admin_only)],
            response_model=list[TimestampedProtectedFsDataType])
async def get_protected_fsdata_history(fs: str):
    with DBHelper() as session:
        data = session.query(ProtectedFsData).filter(ProtectedFsData.fs == fs).order_by(
            ProtectedFsData.timestamp.desc()).all()
        if not len(data):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return [TimestampedProtectedFsDataType(**json.loads(item.data),
                                               id=item.id,
                                               user=item.user,
                                               timestamp=item.timestamp,
                                               approved=item.approved,
                                               approved_by=item.approved_by,
                                               approval_timestamp=item.approval_timestamp) for item in data]


@router.put("/{fs}")
async def set_fsdata(data: FsDataType, fs: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, write_public_data=True)
    with DBHelper() as session:
        db_data = FsData()
        db_data.user = current_user.username
        db_data.fs = fs
        now = ts()
        db_data.timestamp = now
        db_data.data = to_json(data)
        db_data.approved = True
        db_data.approved_by = 'auto'
        db_data.approval_timestamp = now
        session.add(db_data)
        session.commit()


@router.get("/{fs}/protected", response_model=ProtectedFsDataResponse)
async def get_protected_fsdata(fs: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_protected_data=True)
    with DBHelper() as session:
        subquery = session.query(func.max(ProtectedFsData.id).label('id')). \
            where(ProtectedFsData.fs == fs, ProtectedFsData.approved.is_(True)).subquery()
        data = session.query(ProtectedFsData).filter(ProtectedFsData.id == subquery.c.id).first()
        latest_id = session.query(func.max(ProtectedFsData.id).label('id')). \
            where(ProtectedFsData.fs == fs).scalar()
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        return ProtectedFsDataResponse(data=json.loads(data.data), is_latest=data.id == latest_id)


@router.put("/{fs}/protected")
async def set_protected_fsdata(data: ProtectedFsDataType, fs: str,
                               current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, write_protected_data=True)
    with DBHelper() as session:
        db_data = ProtectedFsData()
        db_data.user = current_user.username
        db_data.fs = fs
        now = ts()
        db_data.timestamp = now
        db_data.data = to_json(data)
        if current_user.admin:
            db_data.approved = True
            db_data.approved_by = 'auto'
            db_data.approval_timestamp = now
        session.add(db_data)
        session.commit()


@router.post("/approve/{id_}", dependencies=[Depends(admin_only)])
async def approve_fs_data(id_: int, current_user: User = Depends(get_current_user())):
    with DBHelper() as session:
        data = session.get(FsData, id_)
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        data.approved = True
        data.approved_by = current_user.username
        data.approval_timestamp = ts()
        session.commit()


@router.post("/approve/protected/{id_}", dependencies=[Depends(admin_only)])
async def approve_protected_fs_data(id_: int, current_user: User = Depends(get_current_user())):
    with DBHelper() as session:
        data = session.get(ProtectedFsData, id_)
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No data found",
            )
        data.approved = True
        data.approved_by = current_user.username
        data.approval_timestamp = ts()
        session.commit()
