import datetime
import enum
import hashlib
import json
import logging
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Annotated, BinaryIO

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Form
from pydantic import BaseModel
from sqlalchemy import select, or_, and_, desc
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, Permission, Document, Annotation
from app.routers.users import get_current_user, admin_only
from app.util import ts, to_json

LAST_FS_DATA_FORMAT_UPDATE = '2023-01-01'

ALLOWED_EXTENSIONS = ('pdf', 'odt', 'ods', 'txt', 'md', 'doc', 'docx', 'xls', 'xlsx')

router = APIRouter()


class AnnotationLevel(enum.Enum):
    Error = "Error"
    Warning = "Warning"
    Info = "Info"
    Unchecked = "Unchecked"
    Ok = "Ok"


class DocumentCategory(enum.Enum):
    AFSG = "AFSG"
    BFSG = "BFSG"


class DocumentAnnotation(BaseModel):
    level: AnnotationLevel
    text: str


class DocumentUploadResult(BaseModel):
    fs: str
    sha256hash: str


class DocumentReference(BaseModel):
    category: DocumentCategory
    request_id: str
    base_name: str
    date_start: datetime.date | None
    date_end: datetime.date | None


class DocumentData(DocumentReference):
    file_extension: str
    sha256hash: str
    filename: str
    created_timestamp: str | None
    uploaded_by: str | None
    tags: list[str] | None
    references: list[DocumentReference] | None
    url: str | None
    annotations: list[DocumentAnnotation] | None
    annotations_created_timestamp: str | None
    annotations_created_by: str | None


class DocumentHistoryData(DocumentData):
    deleted_by: str | None
    deleted_timestamp: str | None
    obsoleted_by: str | None
    obsoleted_timestamp: str | None


class EditableDocumentProperties(BaseModel):
    tags: str | None
    references: list[DocumentReference] | None


class AnnotateData(BaseModel):
    target: DocumentReference
    annotations: list[DocumentAnnotation] | None
    tags: list[str] | None
    references: list[DocumentReference] | None
    url: str | None


def get_base_dir():
    return Config.BASE_DOCUMENTS_DIR


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


def is_subpath(shorter: Path, longer: Path) -> bool:
    try:
        longer.resolve().relative_to(shorter.resolve())
        return True
    except ValueError:
        return False


def hook_for_testing(fs: str) -> str:
    return fs


@router.get("/get/{fs}/{filename}", response_class=FileResponse)
async def get_individual_file(fs: str, filename: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_files=True)
    fs = hook_for_testing(fs)
    base_dir = get_base_dir()
    file_path = base_dir / fs / filename
    if '/' in fs or '/' in filename or not is_subpath(shorter=base_dir, longer=file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    if file_path.is_file():
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


@router.get("/{category}", response_model=dict[str, list[DocumentData]])
async def list_documents(category: DocumentCategory, current_user: User = Depends(get_current_user(auto_error=False))):
    items = defaultdict(list)
    with DBHelper() as session:
        is_admin = False
        if current_user:
            user = session.get(User, current_user.username)
            is_admin = user.admin if user else False
        statement = select(
            Document.fs,
            Document.category,
            Document.request_id,
            Document.base_name,
            Document.date_start,
            Document.date_end,
            Document.file_extension,
            Document.sha256hash,
            Document.created_timestamp,
            Document.uploaded_by,
            Annotation.annotations,
            Annotation.tags,
            Annotation.references,
            Annotation.url,
            Annotation.created_timestamp.label('annotations_created_timestamp'),
            Annotation.created_by,
        ). \
            select_from(Document). \
            outerjoin(Annotation). \
            where(Document.category == category.value,
                  Document.deleted_by.is_(None),
                  Annotation.obsoleted_by.is_(None)). \
            order_by(Document.fs, Document.created_timestamp)
        result = session.execute(statement)
    for item in result:
        filename = build_filename_str(request_id=item.request_id, category=item.category, base_name=item.base_name,
                                      date_start=item.date_start, date_end=item.date_end,
                                      file_extension=item.file_extension, sha256hash=item.sha256hash)
        items[item.fs].append(DocumentData(
            category=item.category,
            request_id=item.request_id,
            base_name=item.base_name,
            date_start=item.date_start,
            date_end=item.date_end,
            file_extension=item.file_extension,
            sha256hash=item.sha256hash,
            filename=filename,
            annotations=json.loads(item.annotations) if item.annotations else None,
            tags=json.loads(item.tags) if item.tags else None,
            references=json.loads(item.references) if item.references else None,
            url=item.url if item.url else None,
            annotations_created_timestamp=item.annotations_created_timestamp if is_admin else None,
            annotations_created_by=item.created_by if is_admin else None,
            created_timestamp=item.created_timestamp if is_admin else None,
            uploaded_by=item.uploaded_by if is_admin else None,
        ))
    return items


@router.get("/{category}/{limit_date}", response_model=dict[str, list[DocumentData]])  # TODO make speedy
async def list_documents_with_limit(category: DocumentCategory, limit_date: datetime.date,
                                    current_user: User = Depends(get_current_user(auto_error=False))):
    limit_date += datetime.timedelta(days=1)
    date_string = str(limit_date)
    items = defaultdict(list)
    with DBHelper() as session:
        is_admin = False
        if current_user:
            user = session.get(User, current_user.username)
            is_admin = user.admin if user else False
        statement = select(
            Document.fs,
            Document.category,
            Document.request_id,
            Document.base_name,
            Document.date_start,
            Document.date_end,
            Document.file_extension,
            Document.sha256hash,
            Document.created_timestamp,
            Document.uploaded_by,
            Annotation.annotations,
            Annotation.tags,
            Annotation.references,
            Annotation.url,
            Annotation.created_timestamp.label('annotations_created_timestamp'),
            Annotation.created_by,
        ). \
            select_from(Document). \
            outerjoin(Annotation, and_(Annotation.document == Document.id,
            Annotation.created_timestamp < date_string,
            or_(Annotation.obsoleted_by.is_(None), Annotation.obsoleted_timestamp >= date_string))
                      ). \
            where(Document.category == category.value, Document.created_timestamp < date_string,
                  or_(Document.deleted_by.is_(None), Document.deleted_timestamp >= date_string)). \
            order_by(Document.fs, Document.created_timestamp)
        result = session.execute(statement)
    for item in result:
        filename = build_filename_str(request_id=item.request_id, category=item.category, base_name=item.base_name,
                                      date_start=item.date_start, date_end=item.date_end,
                                      file_extension=item.file_extension, sha256hash=item.sha256hash)
        items[item.fs].append(DocumentData(
            category=item.category,
            request_id=item.request_id,
            base_name=item.base_name,
            date_start=item.date_start,
            date_end=item.date_end,
            file_extension=item.file_extension,
            sha256hash=item.sha256hash,
            filename=filename,
            annotations=json.loads(item.annotations) if item.annotations else None,
            tags=json.loads(item.tags) if item.tags else None,
            references=json.loads(item.references) if item.references else None,
            url=item.url if item.url else None,
            annotations_created_timestamp=item.annotations_created_timestamp if is_admin else None,
            annotations_created_by=item.created_by if is_admin else None,
            created_timestamp=item.created_timestamp if is_admin else None,
            uploaded_by=item.uploaded_by if is_admin else None,
        ))
    return items


@router.post("/{fs}/history", response_model=list[DocumentHistoryData])
async def document_history(fs: str, reference: DocumentReference,
                           current_user: User = Depends(get_current_user(auto_error=False))):
    with DBHelper() as session:
        is_admin = False
        if current_user:
            user = session.get(User, current_user.username)
            is_admin = user.admin if user else False
        statement = select(
            Document.fs,
            Document.category,
            Document.request_id,
            Document.base_name,
            Document.date_start,
            Document.date_end,
            Document.file_extension,
            Document.sha256hash,
            Document.created_timestamp,
            Document.uploaded_by,
            Document.deleted_by,
            Document.deleted_timestamp,
            Annotation.annotations,
            Annotation.tags,
            Annotation.references,
            Annotation.url,
            Annotation.created_timestamp.label('annotations_created_timestamp'),
            Annotation.created_by,
            Annotation.obsoleted_by,
            Annotation.obsoleted_timestamp,
        ). \
            select_from(Document). \
            outerjoin(Annotation, Annotation.document == Document.id). \
            where(Document.fs == fs,
            Document.category == reference.category.value,
                  Document.request_id == reference.request_id,
                  Document.base_name == reference.base_name,
                  Document.date_start == (reference.date_start.isoformat() if reference.date_start else None),
                  Document.date_end == (reference.date_end.isoformat() if reference.date_end else None)). \
            order_by(desc(Document.created_timestamp), desc(Annotation.created_timestamp))
        result = session.execute(statement)
    items = []
    for item in result:
        filename = build_filename_str(request_id=item.request_id, category=item.category, base_name=item.base_name,
                                      date_start=item.date_start, date_end=item.date_end,
                                      file_extension=item.file_extension, sha256hash=item.sha256hash)
        items.append(DocumentHistoryData(
            category=item.category,
            request_id=item.request_id,
            base_name=item.base_name,
            date_start=item.date_start,
            date_end=item.date_end,
            file_extension=item.file_extension,
            sha256hash=item.sha256hash,
            filename=filename,
            annotations=json.loads(item.annotations) if item.annotations else None,
            tags=json.loads(item.tags) if item.tags else None,
            references=json.loads(item.references) if item.references else None,
            url=item.url if item.url else None,
            annotations_created_timestamp=item.annotations_created_timestamp if is_admin else None,
            annotations_created_by=item.created_by if is_admin else None,
            created_timestamp=item.created_timestamp if is_admin else None,
            uploaded_by=item.uploaded_by if is_admin else None,
            deleted_by=item.deleted_by if is_admin else None,
            deleted_timestamp=item.deleted_timestamp if is_admin else None,
            obsoleted_by=item.obsoleted_by if is_admin else None,
            obsoleted_timestamp=item.obsoleted_timestamp if is_admin else None,
        ))
    return items


@router.post("/{fs}")
async def upload_document(
        fs: str,
        file: UploadFile,
        category: Annotated[DocumentCategory, Form()],
        base_name: Annotated[str, Form()],
        date_start: Annotated[datetime.date | None, Form()] = None,
        date_end: Annotated[datetime.date | None, Form()] = None,
        request_id: Annotated[str, Form()] = '',
        current_user: User = Depends(get_current_user()),
):
    logging.info(f'upload_document({fs=}, {file.filename=}, {category=}, {base_name=}, {date_start=}, {date_end=}, '
                 f'{request_id=}, {current_user.username=})')
    with DBHelper() as session:
        check_user_may_upload_document(current_user, fs, category, session)
        if not file.filename:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='the file needs to have a filename with an extension')
        file_extension = file.filename.split('.')[-1].lower()
        sha256hash = calculate_sha256(file.file)
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                                detail=f"File format not supported. Please only upload {ALLOWED_EXTENSIONS}")
        filename = build_filename(request_id=request_id, category=category, base_name=base_name,
                                  date_start=date_start, date_end=date_end, file_extension=file_extension,
                                  sha256hash=sha256hash)
        target_dir = get_base_dir() / fs
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / filename
        with target_file.open('wb+') as f:
            shutil.copyfileobj(file.file, f)
        now = ts()
        session.query(Document). \
            where(Document.fs == fs,
                  Document.category == category.value,
                  Document.request_id == request_id,
                  Document.base_name == base_name,
                  Document.date_start == (date_start.isoformat() if date_start else None),
                  Document.date_end == (date_end.isoformat() if date_end else None),
                  Document.deleted_by.is_(None)). \
            update({'deleted_by': current_user.username, 'deleted_timestamp': now})
        document = Document()
        document.fs = fs
        document.category = category.value
        document.request_id = request_id
        document.base_name = base_name
        document.date_start = date_start.isoformat() if date_start else None
        document.date_end = date_end.isoformat() if date_end else None
        document.file_extension = file_extension
        document.sha256hash = sha256hash
        document.created_timestamp = now
        document.uploaded_by = current_user.username
        session.add(document)
        session.commit()


@router.post("/{fs}/annotate", dependencies=[Depends(admin_only)])
async def annotate(fs: str, data: AnnotateData,
                   current_user: User = Depends(get_current_user())):
    logging.info(f'annotate({fs=}, {data=}, {current_user.username=})')
    with DBHelper() as session:
        document_id = session.query(Document.id). \
            where(Document.fs == fs,
                  Document.category == data.target.category.value,
                  Document.request_id == data.target.request_id,
                  Document.base_name == data.target.base_name,
                  Document.date_start == (data.target.date_start.isoformat() if data.target.date_start else None),
                  Document.date_end == (data.target.date_end.isoformat() if data.target.date_end else None),
                  Document.deleted_by.is_(None)). \
            scalar()
        if not document_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        now = ts()
        session.query(Annotation). \
            where(Annotation.document == document_id, Annotation.obsoleted_by.is_(None)). \
            update({'obsoleted_by': current_user.username, 'obsoleted_timestamp': now})
        annotation = Annotation()
        annotation.document = document_id
        if data.annotations is not None:
            annotation.annotations = to_json(data.annotations)
        if data.tags is not None:
            annotation.tags = to_json(data.tags)
        if data.references is not None:
            annotation.references = to_json(data.references)
        if data.url is not None:
            annotation.url = data.url
        annotation.created_timestamp = now
        annotation.created_by = current_user.username
        session.add(annotation)
        session.commit()


def calculate_sha256(uploaded_file: BinaryIO):
    file_hash = hashlib.sha256()
    while chunk := uploaded_file.read(8192):
        file_hash.update(chunk)
    uploaded_file.seek(0)
    return file_hash.hexdigest()


def build_filename(request_id: str, category: DocumentCategory, base_name: str, date_start: datetime.date | None,
                   date_end: datetime.date | None, file_extension: str, sha256hash: str) -> str:
    date_start_str = date_start.isoformat() if date_start else None
    date_end_str = date_end.isoformat() if date_end else None
    return build_filename_str(request_id, category.value, base_name, date_start_str, date_end_str, file_extension,
                              sha256hash)


def build_filename_str(request_id: str, category: str, base_name: str, date_start: str | None,
                       date_end: str | None, file_extension: str, sha256hash: str) -> str:
    filename = f'{category}-{request_id}-{base_name}'.replace('--', '-')
    if date_start:
        filename += f'-{date_start}'
        if date_end:
            filename += f'--{date_end}'
    filename += f'-{sha256hash}.{file_extension}'
    return filename


def only_admin_bfsg() -> bool:
    return True


def check_user_may_upload_document(current_user: User, fs: str, category: DocumentCategory, session: Session):
    creator = session.get(User, current_user.username)
    if not creator:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User not found",
        )
    if creator.admin:
        return
    if category == DocumentCategory.AFSG:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to upload AFSG documents",
        )
    creatorpermissions = {p.fs: p.upload_documents for p in creator.permissions}
    if not creatorpermissions.get(fs, False) or only_admin_bfsg():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to upload documents for this fs",
        )