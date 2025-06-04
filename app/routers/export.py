import json

from fastapi import APIRouter
from sqlalchemy import func

from app.database import PublicFsData, BaseFsData, SessionDep
from app.routers.fsen import PublicFsDataType

router = APIRouter()


class ExportFsDataType(PublicFsDataType):
    name: str


@router.get("/public-fs-data", response_model=dict[str, ExportFsDataType])
async def export_public_fs_data(session: SessionDep):
    base_subquery = session.query(func.max(BaseFsData.id).label('id'), BaseFsData.fs). \
        where(BaseFsData.approved.is_(True)). \
        group_by(BaseFsData.fs).subquery()
    public_subquery = session.query(func.max(PublicFsData.id).label('id'), PublicFsData.fs). \
        where(PublicFsData.approved.is_(True)). \
        group_by(PublicFsData.fs).subquery()
    data = session.query(PublicFsData.fs, PublicFsData.data.label('publicData'), BaseFsData.data.label('baseData')). \
        select_from(PublicFsData). \
        join(BaseFsData, BaseFsData.fs == PublicFsData.fs). \
        join(public_subquery, PublicFsData.id == public_subquery.c.id). \
        join(base_subquery, BaseFsData.id == base_subquery.c.id). \
        order_by(PublicFsData.fs).all()
    retval = {}
    for d in data:
        public_data = json.loads(d.publicData)
        base_data = json.loads(d.baseData)
        if base_data['active']:
            retval[d.fs] = {**public_data, 'name': base_data['name']}
    return retval
