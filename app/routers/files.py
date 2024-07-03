import datetime
import enum
import hashlib
import json
import shutil
from collections import defaultdict
from json import JSONDecodeError
from typing import Annotated, BinaryIO

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Form
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, Permission, Document, Annotation
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
    tags: str
    references: list[DocumentReference]
    file_extension: str
    sha256hash: str
    created_timestamp: str | None
    uploaded_by: str | None
    annotations: list[DocumentAnnotation] | None
    annotations_created_timestamp: str | None
    annotations_created_by: str | None


def get_base_dir():
    return Config.BASE_DOCUMENTS_DIR


def get_subfolder_from_filename(filename: str) -> str | None:
    for key, value in SUBFOLDERS.items():
        if filename.startswith(key):
            return value
    return None


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


@router.get("/{fs}/{filename}", response_class=FileResponse)
async def get_individual_file(fs: str, filename: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_files=True)
    subfolder = get_subfolder_from_filename(filename)
    if not subfolder or '/' in fs or '/' in filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    file_path = Config.BASE_DATA_DIR / fs / subfolder / filename
    if file_path.is_file():
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


@router.get("", response_model=dict[str, list[DocumentData]])
async def list_documents(current_user: User = Depends(get_current_user(auto_error=False))):
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
            Document.tags,
            Document.references,
            Document.file_extension,
            Document.sha256hash,
            Document.created_timestamp,
            Document.uploaded_by,
            Annotation.content,
            Annotation.created_timestamp.label('annotations_created_timestamp'),
            Annotation.created_by,
        ). \
            select_from(Document). \
            outerjoin(Annotation). \
            where(Document.deleted_by.is_(None), Annotation.obsoleted_by.is_(None)). \
            order_by(Document.fs, Document.created_timestamp)
        result = session.execute(statement)
    for item in result:
        items[item.fs].append(DocumentData(
            category=item.category,
            request_id=item.request_id,
            base_name=item.base_name,
            date_start=item.date_start,
            date_end=item.date_end,
            tags=item.tags,
            references=json.loads(item.references),
            file_extension=item.file_extension,
            sha256hash=item.sha256hash,
            annotations=json.loads(item.content) if item.content else None,
            # TODO only if admin ↓
            annotations_created_timestamp=item.annotations_created_timestamp if is_admin else None,
            annotations_created_by=item.created_by if is_admin else None,
            created_timestamp=item.created_timestamp if is_admin else None,
            uploaded_by=item.uploaded_by if is_admin else None,
        ))
    return items


@router.post("/{fs}", response_model=DocumentUploadResult)
async def upload_document(
        fs: str,
        file: UploadFile,
        category: Annotated[DocumentCategory, Form()],
        base_name: Annotated[str, Form()],
        date_start: Annotated[datetime.date | None, Form()] = None,
        date_end: Annotated[datetime.date | None, Form()] = None,
        request_id: Annotated[str, Form()] = '',
        tags: Annotated[str, Form()] = '',
        references: Annotated[str, Form()] = '',
        current_user: User = Depends(get_current_user()),
):
    with DBHelper() as session:
        check_user_may_upload_document(current_user, fs, category, session)
        references = references or '[]'
        try:
            parsed_references = json.loads(references)
            assert isinstance(parsed_references, list)
        except (JSONDecodeError, AssertionError):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='references is not a valid json encoded list of values')
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
        session.query(Document). \
            where(Document.fs == fs,
                  Document.category == category.value,
                  Document.request_id == request_id,
                  Document.base_name == base_name,
                  Document.date_start == date_start.isoformat() if date_start else None,
                  Document.date_end == date_end.isoformat() if date_end else None,
                  Document.deleted_by.is_(None)). \
            update({'deleted_by': current_user.username})
        document = Document()
        document.fs = fs
        document.category = category.value
        document.request_id = request_id
        document.base_name = base_name
        document.date_start = date_start.isoformat() if date_start else None
        document.date_end = date_end.isoformat() if date_end else None
        document.tags = tags
        document.references = references
        document.file_extension = file_extension
        document.sha256hash = sha256hash
        document.created_timestamp = ts()
        document.uploaded_by = current_user.username
        session.add(document)
        session.commit()
        return DocumentUploadResult(fs=fs, sha256hash=sha256hash)


@router.post("/{fs}/{sha256hash}", dependencies=[Depends(admin_only)])
async def annotate(fs: str, sha256hash: str, annotations: list[DocumentAnnotation],
                   current_user: User = Depends(get_current_user())):
    with DBHelper() as session:
        document_id = session.query(Document.id). \
            where(Document.fs == fs,
                  Document.sha256hash == sha256hash,
                  Document.deleted_by.is_(None)). \
            scalar()
        if not document_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        session.query(Annotation). \
            where(Annotation.document == document_id, Annotation.obsoleted_by.is_(None)). \
            update({'obsoleted_by': current_user.username})
        annotation = Annotation()
        annotation.document = document_id
        annotation.content = to_json(annotations)
        annotation.created_timestamp = ts()
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
    filename = f'{category.value}-{request_id}-{base_name}'.replace('--', '-')
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
