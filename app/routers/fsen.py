import json
import logging
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette import status

from app.database import User, Permission, PublicFsData, ProtectedFsData, BaseFsData, SessionDep
from app.routers.users import get_current_user, admin_only, is_admin
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


class Interval(BaseModel):
    date_start: date
    date_end: date


class FinancialYearOverride(BaseModel):
    previous: Interval
    current: Interval


class AnnotatedUrl(BaseModel):
    url: str
    annotation: str


class BaseFsDataType(BaseModel):
    fs_id: str
    name: str
    statutes: str
    financial_year_start: str
    financial_year_override: FinancialYearOverride | None
    proceedings_urls: list[AnnotatedUrl]
    annotation: str
    active: bool


class BaseFsDataResponse(BaseModel):
    data: BaseFsDataType
    is_latest: bool


class TimestampedBaseFsDataType(BaseFsDataType):
    id: int
    user: str
    approved: bool
    approved_by: str | None
    approval_timestamp: str | None
    timestamp: str


class PublicFsDataType(BaseModel):
    phone: str
    website: str
    address: str
    serviceTimes: ServiceTimes
    regularMeeting: RegularMeeting


class FsDataType(PublicFsDataType):
    email: str
    other: dict


class PublicFsDataResponse(BaseModel):
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
    base: BaseFsDataResponse | None
    public: PublicFsDataResponse | None
    protected: ProtectedFsDataResponse | None


def check_permission(current_user: User, fs: str, session: Session,
                     manage_permissions: bool = False,
                     read_files: bool = False,
                     read_public_data: bool = False,
                     write_public_data: bool = False,
                     read_protected_data: bool = False,
                     write_protected_data: bool = False,
                     submit_payout_request: bool = False,
                     ):
    if is_admin(current_user.username, session):
        return
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
async def get_all_fsdata(session: SessionDep, current_user: User = Depends(get_current_user(auto_error=False))):
    retval = {}
    base_subquery = session.query(func.max(BaseFsData.id).label('id'), BaseFsData.fs). \
        where(BaseFsData.approved.is_(True)). \
        group_by(BaseFsData.fs).subquery()
    base_data = session.query(BaseFsData).join(base_subquery, BaseFsData.id == base_subquery.c.id).all()
    latest_ids_for_base_data = {row.fs: row.id for row in
                                session.query(func.max(BaseFsData.id).label('id'), BaseFsData.fs). \
                                    group_by(BaseFsData.fs).all()}
    for base_row in base_data:
        retval[base_row.fs] = FsDataTuple(base=None, public=None, protected=None)
        retval[base_row.fs].base = BaseFsDataResponse(data=json.loads(base_row.data), is_latest=(
                base_row.id == latest_ids_for_base_data.get(base_row.fs, None)))

    if current_user:
        public_subquery = session.query(func.max(PublicFsData.id).label('id'), PublicFsData.fs). \
            where(PublicFsData.approved.is_(True)). \
            group_by(PublicFsData.fs).subquery()
        public_data = session.query(PublicFsData).join(public_subquery,
                                                       PublicFsData.id == public_subquery.c.id).all()
        latest_ids_for_public_data = {row.fs: row.id for row in
                                      session.query(func.max(PublicFsData.id).label('id'), PublicFsData.fs). \
                                          group_by(PublicFsData.fs).all()}
        prot_subquery = session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
            where(ProtectedFsData.approved.is_(True)). \
            group_by(ProtectedFsData.fs).subquery()
        prot_data = session.query(ProtectedFsData).join(prot_subquery,
                                                        ProtectedFsData.id == prot_subquery.c.id).all()
        latest_ids_for_prot_data = {row.fs: row.id for row in
                                    session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
                                        group_by(ProtectedFsData.fs).all()}
        for public_row in public_data:
            permission = session.get(Permission, (current_user.username, public_row.fs))
            if is_admin(current_user.username, session) or (permission and permission.read_public_data):
                if public_row.fs not in retval:
                    retval[public_row.fs] = FsDataTuple(base=None, public=None, protected=None)
                retval[public_row.fs].public = PublicFsDataResponse(data=json.loads(public_row.data), is_latest=(
                        public_row.id == latest_ids_for_public_data.get(public_row.fs, None)))
        for prot_row in prot_data:
            permission = session.get(Permission, (current_user.username, prot_row.fs))
            if is_admin(current_user.username, session) or (permission and permission.read_protected_data):
                if prot_row.fs not in retval:
                    retval[prot_row.fs] = FsDataTuple(base=None, public=None, protected=None)
                retval[prot_row.fs].protected = ProtectedFsDataResponse(data=json.loads(prot_row.data), is_latest=(
                        prot_row.id == latest_ids_for_prot_data.get(prot_row.fs, None)))
    retval = {key: item for key, item in retval.items() if (not item.base or item.base.data.active)}
    return retval

@router.get("/{limit_date}", response_model=dict[str, FsDataTuple])
async def get_all_fsdata_for_date(limit_date: date, session: SessionDep,
                                  current_user: User = Depends(get_current_user(auto_error=False))):
    limit_date += timedelta(days=1)
    date_string = str(limit_date)
    retval = {}
    base_subquery = session.query(func.max(BaseFsData.id).label('id'), BaseFsData.fs). \
        where(BaseFsData.approval_timestamp <= date_string). \
        group_by(BaseFsData.fs).subquery()
    base_data = session.query(BaseFsData).join(base_subquery, BaseFsData.id == base_subquery.c.id).all()
    latest_ids_for_base_data = {row.fs: row.id for row in
                                session.query(func.max(BaseFsData.id).label('id'), BaseFsData.fs). \
                                    where(BaseFsData.timestamp <= date_string). \
                                    group_by(BaseFsData.fs).all()}
    for base_row in base_data:
        retval[base_row.fs] = FsDataTuple(base=None, public=None, protected=None)
        retval[base_row.fs].base = BaseFsDataResponse(data=json.loads(base_row.data), is_latest=(
                base_row.id == latest_ids_for_base_data.get(base_row.fs, None)))

    if current_user:
        public_subquery = session.query(func.max(PublicFsData.id).label('id'), PublicFsData.fs). \
            where(PublicFsData.approval_timestamp <= date_string). \
            group_by(PublicFsData.fs).subquery()
        public_data = session.query(PublicFsData).join(public_subquery,
                                                       PublicFsData.id == public_subquery.c.id).all()
        latest_ids_for_public_data = {row.fs: row.id for row in
                                      session.query(func.max(PublicFsData.id).label('id'), PublicFsData.fs). \
                                          where(PublicFsData.timestamp <= date_string). \
                                          group_by(PublicFsData.fs).all()}
        prot_subquery = session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
            where(ProtectedFsData.approval_timestamp < date_string). \
            group_by(ProtectedFsData.fs).subquery()
        prot_data = session.query(ProtectedFsData).join(prot_subquery,
                                                        ProtectedFsData.id == prot_subquery.c.id).all()
        latest_ids_for_prot_data = {row.fs: row.id for row in
                                    session.query(func.max(ProtectedFsData.id).label('id'), ProtectedFsData.fs). \
                                        where(ProtectedFsData.timestamp <= date_string). \
                                        group_by(ProtectedFsData.fs).all()}
        for public_row in public_data:
            permission = session.get(Permission, (current_user.username, public_row.fs))
            if is_admin(current_user.username, session) or (permission and permission.read_public_data):
                if public_row.fs not in retval:
                    retval[public_row.fs] = FsDataTuple(base=None, public=None, protected=None)
                retval[public_row.fs].public = PublicFsDataResponse(data=json.loads(public_row.data), is_latest=(
                        public_row.id == latest_ids_for_public_data.get(public_row.fs, None)))
        for prot_row in prot_data:
            permission = session.get(Permission, (current_user.username, prot_row.fs))
            if is_admin(current_user.username, session) or (permission and permission.read_protected_data):
                if prot_row.fs not in retval:
                    retval[prot_row.fs] = FsDataTuple(base=None, public=None, protected=None)
                retval[prot_row.fs].protected = ProtectedFsDataResponse(data=json.loads(prot_row.data), is_latest=(
                        prot_row.id == latest_ids_for_prot_data.get(prot_row.fs, None)))
    retval = {key: item for key, item in retval.items() if (not item.base or item.base.data.active)}
    return retval


@router.get("/{fs}/base", response_model=BaseFsDataResponse)
async def get_base_fsdata(fs: str, session: SessionDep):
    subquery = session.query(func.max(BaseFsData.id).label('id')). \
        where(BaseFsData.fs == fs, BaseFsData.approved.is_(True)).subquery()
    data = session.query(BaseFsData).filter(BaseFsData.id == subquery.c.id).first()
    latest_id = session.query(func.max(BaseFsData.id).label('id')). \
        where(BaseFsData.fs == fs).scalar()
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No data found",
        )
    return BaseFsDataResponse(data=json.loads(data.data), is_latest=data.id == latest_id)


@router.get("/{fs}/public", response_model=PublicFsDataResponse)
async def get_public_fsdata(fs: str, session: SessionDep, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, session, read_public_data=True)
    subquery = session.query(func.max(PublicFsData.id).label('id')). \
        where(PublicFsData.fs == fs, PublicFsData.approved.is_(True)).subquery()
    data = session.query(PublicFsData).filter(PublicFsData.id == subquery.c.id).first()
    latest_id = session.query(func.max(PublicFsData.id).label('id')). \
        where(PublicFsData.fs == fs).scalar()
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No data found",
        )
    return PublicFsDataResponse(data=json.loads(data.data), is_latest=data.id == latest_id)


@router.get("/{fs}/protected", response_model=ProtectedFsDataResponse)
async def get_protected_fsdata(fs: str, session: SessionDep, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, session, read_protected_data=True)
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


@router.get("/{fs}/base/history", dependencies=[Depends(admin_only)],
            response_model=list[TimestampedBaseFsDataType])
async def get_base_fsdata_history(fs: str, session: SessionDep):
    data = session.query(BaseFsData). \
        filter(BaseFsData.fs == fs). \
        order_by(BaseFsData.timestamp.desc()).all()
    if not len(data):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No data found",
        )
    return [TimestampedBaseFsDataType(**json.loads(item.data),
                                      id=item.id,
                                      user=item.user,
                                      timestamp=item.timestamp,
                                      approved=item.approved,
                                      approved_by=item.approved_by,
                                      approval_timestamp=item.approval_timestamp) for item in data]

@router.get("/{fs}/public/history", dependencies=[Depends(admin_only)], response_model=list[TimestampedFsDataType])
async def get_public_fsdata_history(fs: str, session: SessionDep):
    data = session.query(PublicFsData). \
        filter(PublicFsData.fs == fs, PublicFsData.timestamp > LAST_FS_DATA_FORMAT_UPDATE). \
        order_by(PublicFsData.timestamp.desc()).all()
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
async def get_protected_fsdata_history(fs: str, session: SessionDep):
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


@router.put("/{fs}/base", dependencies=[Depends(admin_only)])
async def set_base_fsdata(data: BaseFsDataType, fs: str, session: SessionDep,
                          current_user: User = Depends(get_current_user())):
    logging.info(f'set_base_fsdata({data=}, {fs=}, {current_user.username=})')
    db_data = BaseFsData()
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

@router.put("/{fs}/public")
async def set_public_fsdata(data: FsDataType, fs: str, session: SessionDep,
                            current_user: User = Depends(get_current_user())):
    logging.info(f'set_public_fsdata({data=}, {fs=}, {current_user.username=})')
    check_permission(current_user, fs, session, write_public_data=True)
    db_data = PublicFsData()
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


@router.put("/{fs}/protected")
async def set_protected_fsdata(data: ProtectedFsDataType, fs: str, session: SessionDep,
                               current_user: User = Depends(get_current_user())):
    logging.info(f'set_protected_fsdata({data=}, {current_user.username=})')
    check_permission(current_user, fs, session, write_protected_data=True)
    db_data = ProtectedFsData()
    db_data.user = current_user.username
    db_data.fs = fs
    now = ts()
    db_data.timestamp = now
    db_data.data = to_json(data)
    if is_admin(current_user.username, session):
        db_data.approved = True
        db_data.approved_by = 'auto'
        db_data.approval_timestamp = now
    session.add(db_data)
    session.commit()


@router.post("/approve/base/{id_}", dependencies=[Depends(admin_only)])
async def approve_base_fs_data(id_: int, session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'approve_base_fs_data({id_=}, {current_user.username=})')
    data = session.get(BaseFsData, id_)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No data found",
        )
    data.approved = True
    data.approved_by = current_user.username
    data.approval_timestamp = ts()
    session.commit()

@router.post("/approve/public/{id_}", dependencies=[Depends(admin_only)])
async def approve_public_fs_data(id_: int, session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'approve_public_fs_data({id_=}, {current_user.username=})')
    data = session.get(PublicFsData, id_)
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
async def approve_protected_fs_data(id_: int, session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'approve_protected_fs_data({id_=}, {current_user.username=})')
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
