import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, desc
from sqlalchemy.orm import Session
from starlette import status

from app.database import User, Election, SessionDep
from app.routers.users import get_current_user, admin_only
from app.util import ts

router = APIRouter()


class ElectionData(BaseModel):
    election_id: str
    fs: str
    committee: str
    election_method: str
    first_election_day: str
    last_election_day: str
    electoral_register_request_date: str
    electoral_register_hand_out_date: str
    result_url: str
    result_published_date: str
    scrutiny_status: str
    comments: str


class ElectionDataWithMeta(ElectionData):
    last_modified_timestamp: str
    last_modified_by: str


def get_election_history(session: Session, election_id: str) -> list[Election]:
    return session.query(Election). \
        filter(Election.election_id == election_id). \
        order_by(Election.last_modified_timestamp.desc()).all()


@router.get("/", response_model=list[ElectionData])
async def list_elections(session: SessionDep):
    subquery = session.query(Election.election_id, func.max(Election.id).label('id')). \
        group_by(Election.election_id).subquery()
    data = session.query(Election).join(subquery, Election.id == subquery.c.id). \
        order_by(desc(Election.first_election_day), Election.fs, desc(Election.id)).all()
    return data


@router.post("/save", dependencies=[Depends(admin_only)])
async def save_election_data(data: ElectionData, session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'save_election_data({data=}, {current_user.username=})')
    now = ts()
    election = Election()
    election.election_id = data.election_id
    election.fs = data.fs
    election.committee = data.committee
    election.election_method = data.election_method
    election.first_election_day = data.first_election_day
    election.last_election_day = data.last_election_day
    election.electoral_register_request_date = data.electoral_register_request_date
    election.electoral_register_hand_out_date = data.electoral_register_hand_out_date
    election.result_url = data.result_url
    election.result_published_date = data.result_published_date
    election.scrutiny_status = data.scrutiny_status
    election.comments = data.comments
    election.last_modified_timestamp = now
    election.last_modified_by = current_user.username
    session.add(election)
    session.commit()


@router.get("/{election_id}/history", dependencies=[Depends(admin_only)], response_model=list[ElectionDataWithMeta])
async def get_history(election_id: str, session: SessionDep):
    election_history = get_election_history(session, election_id)
    if not len(election_history):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Election not found",
        )
    return election_history
