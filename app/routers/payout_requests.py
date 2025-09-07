import logging
import re
from datetime import datetime, date, timedelta
from enum import Enum
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func
from sqlalchemy.orm import Session, make_transient
from starlette import status

from app.database import User, PayoutRequest, SessionDep
from app.routers.users import get_current_user, admin_only, is_admin
from app.util import ts, get_europe_berlin_date

router = APIRouter()


class PayoutRequestType(Enum):
    AFSG = 'afsg'
    BFSG = 'bfsg'
    VORANKUENDIGUNG = 'vorankuendigung'


class PayoutRequestStatus(Enum):
    EINGEREICHT = 'EINGEREICHT'
    GESTELLT = 'GESTELLT'
    VOLLSTAENDIG = 'VOLLSTÄNDIG'
    ANGEWIESEN = 'ANGEWIESEN'
    UEBERWIESEN = 'ÜBERWIESEN'
    FAILED = 'FAILED'
    VORGESTELLT = 'VORGESTELLT'
    ANGENOMMEN = 'ANGENOMMEN'
    ABGELEHNT = 'ABGELEHNT'
    GENUTZT = 'GENUTZT'


class PayoutRequestForCreation(BaseModel):
    fs: str
    semester: str


class BfsgPayoutRequestForCreation(PayoutRequestForCreation):
    category: str
    amount_cents: int
    status: PayoutRequestStatus | None = None
    status_date: date | None = None
    request_date: date | None = None
    comment: str | None = None
    completion_deadline: date | None = None
    reference: str | None = None


class VorankuendigungPayoutRequestForCreation(BfsgPayoutRequestForCreation):
    pass


class ModifiablePayoutRequestProperties(BaseModel):
    status: PayoutRequestStatus | None = None
    status_date: date | None = None
    amount_cents: int | None = None
    comment: str | None = None
    completion_deadline: date | None = None
    reference: str | None = None


class PublicPayoutRequest(PayoutRequestForCreation):
    model_config = ConfigDict(from_attributes=True)

    status: PayoutRequestStatus
    status_date: str
    amount_cents: int
    comment: str
    request_id: str
    type: str
    category: str
    request_date: str
    completion_deadline: str
    reference: str | None


class PayoutRequestData(PublicPayoutRequest):
    requester: str | None = None
    last_modified_timestamp: str | None = None
    last_modified_by: str | None = None


def check_user_may_submit_payout_request(current_user: User, fs: str, session: Session,
                                         _type: PayoutRequestType = PayoutRequestType.AFSG):
    if is_admin(current_user.username, session):
        return

    # TODO remove this block when regular users may request BFSG/VORANKUENDIGUNG themselves
    if _type != PayoutRequestType.AFSG:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to submit bfsg payout request for this fs",
        )

    creatorpermissions = {p.fs: p.submit_payout_request for p in current_user.permissions}
    if not creatorpermissions.get(fs, False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to submit payout request for this fs",
        )


def check_semester_is_valid_format(semester: str):
    m = re.match(r'\d\d\d\d-(?:SoSe|WiSe)', semester)
    if not m:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid semester format",
        )


def check_semester_is_open_for_afsg_submissions(semester: str):
    if semester not in get_currently_valid_afsg_semesters():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Semester is not open for requests",
        )


def get_currently_valid_afsg_semesters() -> list[str]:
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


def check_semester_is_open_for_bfsg_submissions(semester: str):
    if semester not in get_currently_valid_bfsg_semesters():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Semester is not open for requests",
        )


def get_currently_valid_bfsg_semesters() -> list[str]:
    return get_currently_valid_afsg_semesters()[:2]


def get_default_afsg_completion_deadline(semester: str) -> str:
    semester_year = int(semester[:4])
    semester_type = semester[5:]
    expiration_month = 10 if semester_type == 'SoSe' else 4
    expiration_year = semester_year + (2 if semester_type == 'SoSe' else 3)
    expiration_date = date(expiration_year, expiration_month, 1)
    deadline_date = expiration_date - timedelta(days=1)
    return str(deadline_date)


def get_default_bfsg_completion_deadline(today: str) -> str:
    parsedDate = datetime.strptime(today, '%Y-%m-%d').date()
    year = parsedDate.year
    month = parsedDate.month + 7
    day = 1
    while month > 12:
        month -= 12
        year += 1
    value = date(year=year, month=month, day=day) - timedelta(days=1)
    return value.strftime('%Y-%m-%d')


def get_default_vorankuendigung_completion_deadline(semester: str) -> str:
    semester_year = int(semester[:4])
    semester_type = semester[5:]
    expiration_month = 4 if semester_type == 'SoSe' else 10
    expiration_year = semester_year + 1
    expiration_date = date(expiration_year, expiration_month, 1)
    deadline_date = expiration_date - timedelta(days=1)
    return str(deadline_date)


def get_request_id(semester: str, type_prefix: str, session: Session) -> str:
    year_short = semester[2:4]
    semester_type = semester[5]
    prefix = f'{type_prefix}{year_short}{semester_type}-'
    filter = prefix + '%'
    latest = session.query(func.max(PayoutRequest.request_id)).filter(
        PayoutRequest.request_id.like(filter)).scalar() or prefix + '0000'
    return prefix + f'{int(latest[5:]) + 1:04d}'


def check_no_existing_afsg_payout_request(semester: str, fs: str, session: Session) -> None:
    latest = session.query(func.max(PayoutRequest.id)). \
        filter(PayoutRequest.fs == fs,
               PayoutRequest.semester == semester,
               PayoutRequest.type == PayoutRequestType.AFSG.value).scalar()
    if latest is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="There already is a payout request for this semester",
        )


def get_payout_request(session: Session, request_id: str, _type: PayoutRequestType) -> PayoutRequest | None:
    subquery = session.query(PayoutRequest.request_id, func.max(PayoutRequest.id).label('id')). \
        filter(PayoutRequest.type == _type.value). \
        group_by(PayoutRequest.request_id).subquery()
    data = session.query(PayoutRequest).join(subquery, PayoutRequest.id == subquery.c.id).filter(
        PayoutRequest.request_id == request_id).first()
    return data


def get_payout_request_history(session: Session, request_id: str, _type: PayoutRequestType) -> list[PayoutRequest]:
    return session.query(PayoutRequest). \
        filter(PayoutRequest.request_id == request_id). \
        filter(PayoutRequest.type == _type.value). \
        order_by(PayoutRequest.last_modified_timestamp.desc()).all()


@router.get("/{_type}", response_model=list[PayoutRequestData])
async def list_requests(_type: PayoutRequestType, session: SessionDep,
                        current_user: User = Depends(get_current_user(auto_error=False))):
    subquery = session.query(PayoutRequest.request_id, func.max(PayoutRequest.id).label('id')). \
        filter(PayoutRequest.type == _type.value). \
        group_by(PayoutRequest.request_id).subquery()
    data = session.query(PayoutRequest).join(subquery, PayoutRequest.id == subquery.c.id).all()
    if current_user and is_admin(current_user.username, session):
        return data
    else:
        return [PublicPayoutRequest(**item.__dict__) for item in data]


@router.get("/{_type}/{limit_date}", response_model=list[PayoutRequestData])
async def list_requests_before_date(_type: PayoutRequestType, limit_date: date, session: SessionDep,
                                    current_user: User = Depends(get_current_user(auto_error=False))):
    limit_date += timedelta(days=1)
    date_string = str(limit_date)
    subquery = session.query(PayoutRequest.request_id, func.max(PayoutRequest.id).label('id')). \
        filter(PayoutRequest.last_modified_timestamp < date_string). \
        filter(PayoutRequest.type == _type.value). \
        group_by(PayoutRequest.request_id).subquery()
    data = session.query(PayoutRequest).join(subquery, PayoutRequest.id == subquery.c.id).all()
    if current_user and is_admin(current_user.username, session):
        return data
    else:
        return [PublicPayoutRequest(**item.__dict__) for item in data]


@router.post("/afsg/create", response_model=PayoutRequestData)
async def create_afsg_request(data: PayoutRequestForCreation, session: SessionDep,
                              current_user: User = Depends(get_current_user())):
    logging.info(f'create_afsg_request({data=}, {current_user.username=})')
    check_semester_is_valid_format(data.semester)
    check_semester_is_open_for_afsg_submissions(data.semester)
    check_user_may_submit_payout_request(current_user, data.fs, session)
    check_no_existing_afsg_payout_request(data.semester, data.fs, session)
    request_id = get_request_id(data.semester, 'A', session)
    today = get_europe_berlin_date()
    now = ts()

    payout_request = PayoutRequest()
    payout_request.request_id = request_id
    payout_request.type = PayoutRequestType.AFSG.value
    payout_request.category = PayoutRequestType.AFSG.value.upper()
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
    payout_request.completion_deadline = get_default_afsg_completion_deadline(data.semester)
    payout_request.reference = None  # type: ignore
    session.add(payout_request)
    session.commit()
    return get_payout_request(session, request_id, PayoutRequestType.AFSG)


@router.post("/bfsg/create", response_model=PayoutRequestData)
async def create_bfsg_request(data: BfsgPayoutRequestForCreation, session: SessionDep,
                              current_user: User = Depends(get_current_user())):
    logging.info(f'create_bfsg_request({data=}, {current_user.username=})')
    check_semester_is_valid_format(data.semester)
    # check_semester_is_open_for_bfsg_submissions(data.semester)
    check_user_may_submit_payout_request(current_user, data.fs, session, _type=PayoutRequestType.BFSG)
    request_id = get_request_id(data.semester, 'B', session)
    today = get_europe_berlin_date()
    now = ts()
    completion_deadline = data.completion_deadline.isoformat() if data.completion_deadline else \
        get_default_bfsg_completion_deadline(today)

    payout_request = PayoutRequest()
    payout_request.request_id = request_id
    payout_request.type = PayoutRequestType.BFSG.value
    payout_request.category = data.category
    payout_request.fs = data.fs
    payout_request.semester = data.semester
    payout_request.status = data.status.value if data.status else PayoutRequestStatus.GESTELLT.value
    payout_request.status_date = data.status_date.isoformat() if data.status_date else today
    payout_request.amount_cents = data.amount_cents
    payout_request.comment = data.comment or ''
    payout_request.request_date = data.request_date.isoformat() if data.request_date else today
    payout_request.requester = current_user.username
    payout_request.last_modified_timestamp = now
    payout_request.last_modified_by = current_user.username
    payout_request.completion_deadline = completion_deadline
    payout_request.reference = data.reference  # type: ignore
    session.add(payout_request)
    session.commit()
    return get_payout_request(session, request_id, PayoutRequestType.BFSG)


@router.post("/vorankuendigung/create", response_model=PayoutRequestData)
async def create_vorankuendigung_request(data: VorankuendigungPayoutRequestForCreation, session: SessionDep,
                                         current_user: User = Depends(get_current_user())):
    logging.info(f'create_vorankuendigung_request({data=}, {current_user.username=})')
    check_semester_is_valid_format(data.semester)
    check_user_may_submit_payout_request(current_user, data.fs, session, _type=PayoutRequestType.VORANKUENDIGUNG)
    request_id = get_request_id(data.semester, 'V', session)
    today = get_europe_berlin_date()
    now = ts()
    completion_deadline = data.completion_deadline.isoformat() if data.completion_deadline else \
        get_default_vorankuendigung_completion_deadline(data.semester)

    payout_request = PayoutRequest()
    payout_request.request_id = request_id
    payout_request.type = PayoutRequestType.VORANKUENDIGUNG.value
    payout_request.category = data.category
    payout_request.fs = data.fs
    payout_request.semester = data.semester
    payout_request.status = data.status.value if data.status else PayoutRequestStatus.GESTELLT.value
    payout_request.status_date = data.status_date.isoformat() if data.status_date else today
    payout_request.amount_cents = data.amount_cents
    payout_request.comment = data.comment or ''
    payout_request.request_date = data.request_date.isoformat() if data.request_date else today
    payout_request.requester = current_user.username
    payout_request.last_modified_timestamp = now
    payout_request.last_modified_by = current_user.username
    payout_request.completion_deadline = completion_deadline
    payout_request.reference = data.reference  # type: ignore
    session.add(payout_request)
    session.commit()
    return get_payout_request(session, request_id, PayoutRequestType.VORANKUENDIGUNG)


@router.patch("/{_type}/{request_id}", dependencies=[Depends(admin_only)],
              response_model=PayoutRequestData)
async def modify_request(_type: PayoutRequestType, request_id: str, data: ModifiablePayoutRequestProperties,
                         session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'modify_request({_type=}, {request_id=}, {data=}, {current_user.username=})')
    payout_request = get_payout_request(session, request_id, _type)
    if not payout_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PayoutRequest not found",
        )
    session.expunge(payout_request)
    make_transient(payout_request)
    payout_request.id = None  # type: ignore
    if data.status_date is not None:
        payout_request.status_date = data.status_date.isoformat()
    if data.status is not None:
        payout_request.status = data.status.value
    if data.amount_cents is not None:
        payout_request.amount_cents = data.amount_cents
    if data.completion_deadline is not None:
        payout_request.completion_deadline = data.completion_deadline.isoformat()
    if data.comment is not None:
        payout_request.comment = data.comment
    if data.reference is not None:
        payout_request.reference = data.reference
    payout_request.last_modified_by = current_user.username
    payout_request.last_modified_timestamp = ts()
    session.add(payout_request)
    session.commit()
    return get_payout_request(session, request_id, _type)


@router.delete("/{_type}/{request_id}", dependencies=[Depends(admin_only)])
async def delete_request(_type: PayoutRequestType, request_id: str,
                         session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'delete_request({_type=}, {request_id=}, {current_user.username=})')
    payout_request = get_payout_request(session, request_id, _type)
    if not payout_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PayoutRequest not found",
        )
    session.delete(payout_request)
    session.commit()


@router.get("/{_type}/{request_id}/history", response_model=list[PayoutRequestData])
async def get_request_history(_type: PayoutRequestType, request_id: str, session: SessionDep,
                              current_user: User = Depends(get_current_user(auto_error=False))):
    payout_request_history = get_payout_request_history(session, request_id, _type)
    if not len(payout_request_history):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PayoutRequest not found",
        )
    if current_user and is_admin(current_user.username, session):
        return payout_request_history
    return [PublicPayoutRequest(**item.__dict__) for item in payout_request_history]
