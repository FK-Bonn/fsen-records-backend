import json

from fastapi import APIRouter
from sqlalchemy import func

from app.database import DBHelper, PublicFsData
from app.routers.fsen import PublicFsDataType

router = APIRouter()


@router.get("/public-fs-data", response_model=dict[str, PublicFsDataType])
async def export_public_fs_data():
    with DBHelper() as session:
        subquery = session.query(func.max(PublicFsData.id).label('id'), PublicFsData.fs). \
            where(PublicFsData.approved.is_(True)). \
            group_by(PublicFsData.fs).subquery()
        data = session.query(PublicFsData).join(subquery, PublicFsData.id == subquery.c.id).order_by(PublicFsData.fs).all()
        return {d.fs: json.loads(d.data) for d in data}
