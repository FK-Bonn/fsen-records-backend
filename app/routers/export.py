import datetime
import json
import shutil
from enum import Enum
from hashlib import file_digest
from ipaddress import IPv6Address, IPv4Address, IPv4Network, IPv6Network, ip_address
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, Form
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, Proceedings, FsData
from app.routers.fsen import PublicFsData
from app.routers.users import get_current_user
from app.util import ts

router = APIRouter()


@router.get("/export/public-fs-data", response_model=dict[str, PublicFsData])
async def export_public_fs_data():
    with DBHelper() as session:
        subquery = session.query(func.max(FsData.id).label('id'), FsData.fs). \
            where(FsData.approved.is_(True)). \
            group_by(FsData.fs).subquery()
        data = session.query(FsData).join(subquery, FsData.id == subquery.c.id).order_by(FsData.fs).all()
        return {d.fs: json.loads(d.data) for d in data}
