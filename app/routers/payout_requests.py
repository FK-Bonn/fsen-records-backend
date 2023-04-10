import re
from datetime import datetime
from enum import Enum
from typing import List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette import status

from app.database import User, DBHelper, PermissionLevel, PayoutRequest
from app.util import ts, get_europe_berlin_date
from app.routers.users import get_current_user, admin_only

router = APIRouter()


class PayoutRequestStatus(Enum):
    EINGEREICHT = 'EINGEREICHT'
    GESTELLT = 'GESTELLT'
    VOLLSTAENDIG = 'VOLLSTÄNDIG'
    ANGEWIESEN = 'ANGEWIESEN'
    UEBERWIESEN = 'ÜBERWIESEN'
    FAILED = 'FAILED'


class PayoutRequestForCreation(BaseModel):
    fs: str
    semester: str


class ModifiablePayoutRequestProperties(BaseModel):
    status: Optional[PayoutRequestStatus]
    status_date: Optional[str]
    amount_cents: Optional[int]
    comment: Optional[str]


class PublicPayoutRequest(PayoutRequestForCreation):
    status: PayoutRequestStatus
    status_date: str
    amount_cents: int
    comment: str
    request_id: str
    request_date: str

    class Config:
        orm_mode = True


class PayoutRequestData(PublicPayoutRequest):
    requester: str
    last_modified_timestamp: str
    last_modified_by: str


def check_user_may_submit_payout_request(current_user: User, fs: str, session: Session):
    creator = session.get(User, current_user.username)
    if not creator:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User not found",
        )
    if creator.admin:
        return

    creatorpermissions = {p.fs: p.level for p in creator.permissions}
    if creatorpermissions.get(fs, PermissionLevel.NONE.value) < PermissionLevel.WRITE.value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to submit payout request for this fs",
        )


def check_semester_is_open_for_submissions(semester: str):
    m = re.match(r'\d\d\d\d-(?:SoSe|WiSe)', semester)
    if not m:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid semester format",
        )
    if semester not in get_currently_valid_semesters():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Semester is not open for requests",
        )


def get_currently_valid_semesters() -> List[str]:
    today = datetime.now(tz=ZoneInfo('Europe/Berlin'))
    semester_type = 'WiSe'
    if 4 <= today.month <= 9:
        semester_type = 'SoSe'
    year = today.year
    if today.month < 4:
        year -= 1
    previous_semester_type = 'WiSe' if semester_type == 'SoSe' else 'SoSe'
    previous_semester_year = (year - 1) if semester_type == 'SoSe' else year
    two_semesters_ago_type = semester_type
    two_semesters_ago_year = year - 1
    valid_semesters = [
        f'{year}-{semester_type}',
        f'{previous_semester_year}-{previous_semester_type}',
        f'{two_semesters_ago_year}-{two_semesters_ago_type}',
    ]
    return valid_semesters


def get_request_id(semester: str, session: Session) -> str:
    year_short = semester[2:4]
    semester_type = semester[5]
    prefix = f'A{year_short}{semester_type}-'
    filter = prefix + '%'
    latest = session.query(func.max(PayoutRequest.request_id)).filter(
        PayoutRequest.request_id.like(filter)).scalar() or prefix + '0000'
    return prefix + f'{int(latest[5:]) + 1:04d}'


def check_no_existing_payout_request(semester: str, fs: str, session: Session) -> None:
    latest = session.query(func.max(PayoutRequest.id)).filter(
        PayoutRequest.fs == fs, PayoutRequest.semester == semester).scalar()
    if latest is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="There already is a payout request for this semester",
        )


def get_payout_request(session: Session, request_id: str) -> Optional[PayoutRequest]:
    subquery = session.query(PayoutRequest.request_id, func.max(PayoutRequest.id).label('id')).group_by(
        PayoutRequest.request_id).subquery()
    data = session.query(PayoutRequest).join(subquery, PayoutRequest.id == subquery.c.id).filter(
        PayoutRequest.request_id == request_id).first()
    return data


@router.get("/payout-request/afsg", response_model=List[PayoutRequestData])
async def list_afsg_requests():
    with DBHelper() as session:
        subquery = session.query(PayoutRequest.request_id, func.max(PayoutRequest.id).label('id')).group_by(
            PayoutRequest.request_id).subquery()
        data = session.query(PayoutRequest).join(subquery, PayoutRequest.id == subquery.c.id).all()
        return data


@router.post("/payout-request/afsg/create", response_model=PayoutRequestData)
async def create_afsg_request(data: PayoutRequestForCreation, current_user: User = Depends(get_current_user)):
    check_semester_is_open_for_submissions(data.semester)
    with DBHelper() as session:
        check_user_may_submit_payout_request(current_user, data.fs, session)
        check_no_existing_payout_request(data.semester, data.fs, session)
        request_id = get_request_id(data.semester, session)
        today = get_europe_berlin_date()
        now = ts()

        payout_request = PayoutRequest()
        payout_request.request_id = request_id
        payout_request.fs = data.fs
        payout_request.semester = data.semester
        payout_request.status = PayoutRequestStatus.EINGEREICHT.value
        payout_request.status_date = today
        payout_request.amount_cents = 0
        payout_request.comment = ''
        payout_request.request_date = today
        payout_request.requester = current_user.username
        payout_request.last_modified_timestamp = now
        payout_request.last_modified_by = current_user.username
        session.add(payout_request)
        session.commit()
        return get_payout_request(session, request_id)


@router.patch("/payout-request/afsg/{request_id}", dependencies=[Depends(admin_only)], response_model=PayoutRequestData)
async def modify_afsg_request(request_id: str, data: ModifiablePayoutRequestProperties,
                              current_user: User = Depends(get_current_user)):
    with DBHelper() as session:
        payout_request = get_payout_request(session, request_id)
        if not payout_request:
            raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PayoutRequest not found",
        )
        if data.status_date is not None:
            payout_request.status_date = data.status_date
        if data.status is not None:
            payout_request.status = data.status.value
        if data.amount_cents is not None:
            payout_request.amount_cents = data.amount_cents
        if data.comment is not None:
            payout_request.comment = data.comment
        payout_request.last_modified_by = current_user.username
        payout_request.last_modified_timestamp = ts()
        session.commit()
        return get_payout_request(session, request_id)
