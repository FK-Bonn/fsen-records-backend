import json

from fastapi import APIRouter
from sqlalchemy import func

from app.database import DBHelper, FsData
from app.routers.fsen import PublicFsData

router = APIRouter()


@router.get("/public-fs-data", response_model=dict[str, PublicFsData])
async def export_public_fs_data():
    with DBHelper() as session:
        subquery = session.query(func.max(FsData.id).label('id'), FsData.fs). \
            where(FsData.approved.is_(True)). \
            group_by(FsData.fs).subquery()
        data = session.query(FsData).join(subquery, FsData.id == subquery.c.id).order_by(FsData.fs).all()
        return {d.fs: json.loads(d.data) for d in data}
