from typing import Annotated

import bcrypt
from fastapi import Depends
from sqlalchemy import String, ForeignKey, Text
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, relationship, Mapped, mapped_column, DeclarativeBase
from sqlalchemy_utils import create_database, database_exists

from app.config import Config


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    if hashed_password is None:
        return False
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(200), unique=True, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password: Mapped['UserPassword'] = relationship(back_populates='user_obj')
    admin: Mapped['AdminPermission'] = relationship(back_populates='user_obj')
    permissions = relationship('Permission')
    created_by: Mapped[str] = mapped_column(String(200))


class UserPassword(Base):
    __tablename__ = "user_passwords"
    user: Mapped[str] = mapped_column(ForeignKey(User.username, ondelete='CASCADE'), primary_key=True)
    user_obj: Mapped['User'] = relationship(back_populates='password')
    hashed_password: Mapped[str] = mapped_column(String(200))


class AdminPermission(Base):
    __tablename__ = "admin_permissions"
    user: Mapped[str] = mapped_column(ForeignKey(User.username, ondelete='CASCADE'), primary_key=True)
    user_obj: Mapped['User'] = relationship(back_populates='admin')
    created_by: Mapped[str] = mapped_column(String(200))


class Permission(Base):
    __tablename__ = "permissions"
    user: Mapped[str] = mapped_column(ForeignKey(User.username, ondelete='CASCADE'), primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), primary_key=True)
    read_permissions: Mapped[bool] = mapped_column(nullable=False, default=False)
    write_permissions: Mapped[bool] = mapped_column(nullable=False, default=False)
    read_files: Mapped[bool] = mapped_column(nullable=False, default=False)
    read_public_data: Mapped[bool] = mapped_column(nullable=False, default=False)
    write_public_data: Mapped[bool] = mapped_column(nullable=False, default=False)
    read_protected_data: Mapped[bool] = mapped_column(nullable=False, default=False)
    write_protected_data: Mapped[bool] = mapped_column(nullable=False, default=False)
    submit_payout_request: Mapped[bool] = mapped_column(nullable=False, default=False)
    upload_proceedings: Mapped[bool] = mapped_column(nullable=False, default=False)
    delete_proceedings: Mapped[bool] = mapped_column(nullable=False, default=False)
    upload_documents: Mapped[bool] = mapped_column(nullable=False, default=False)
    locked: Mapped[bool] = mapped_column(nullable=False, default=False)


class BaseFsData(Base):
    __tablename__ = "base_fs_data"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)
    user: Mapped[str] = mapped_column(String(200), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    approved: Mapped[bool] = mapped_column(nullable=False, default=False)
    approved_by: Mapped[str] = mapped_column(String(200), nullable=True, default=None)
    approval_timestamp: Mapped[str] = mapped_column(String(200), nullable=True, default=None)


class PublicFsData(Base):
    __tablename__ = "public_fs_data"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)
    user: Mapped[str] = mapped_column(String(200), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    approved: Mapped[bool] = mapped_column(nullable=False, default=False)
    approved_by: Mapped[str] = mapped_column(String(200), nullable=True, default=None)
    approval_timestamp: Mapped[str] = mapped_column(String(200), nullable=True, default=None)


class ProtectedFsData(Base):
    __tablename__ = "protected_fs_data"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)
    user: Mapped[str] = mapped_column(String(200), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    approved: Mapped[bool] = mapped_column(nullable=False, default=False)
    approved_by: Mapped[str] = mapped_column(String(200), nullable=True, default=None)
    approval_timestamp: Mapped[str] = mapped_column(String(200), nullable=True, default=None)


class PayoutRequest(Base):
    __tablename__ = "payout_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(200), nullable=False)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    semester: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(200), nullable=False)
    status_date: Mapped[str] = mapped_column(String(200), nullable=False)
    amount_cents: Mapped[int] = mapped_column(nullable=False)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    request_date: Mapped[str] = mapped_column(String(200), nullable=False)
    requester: Mapped[str] = mapped_column(String(200), nullable=False)
    last_modified_timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    last_modified_by: Mapped[str] = mapped_column(String(200), nullable=False)
    completion_deadline: Mapped[str] = mapped_column(String(200), nullable=False)
    reference: Mapped[str] = mapped_column(String(200), nullable=True)


class Proceedings(Base):
    __tablename__ = "proceedings"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    committee: Mapped[str] = mapped_column(String(200), nullable=False)
    date: Mapped[str] = mapped_column(String(200), nullable=False)
    tags: Mapped[str] = mapped_column(Text, nullable=False)
    sha256hash: Mapped[str] = mapped_column(String(200), nullable=False)
    upload_date: Mapped[str] = mapped_column(String(200), nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(200), nullable=False)
    deleted_by: Mapped[str] = mapped_column(String(200), nullable=True, default=None)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(200), nullable=False)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    base_name: Mapped[str] = mapped_column(String(200), nullable=False)
    date_start: Mapped[str | None] = mapped_column(String(200), nullable=True)
    date_end: Mapped[str | None] = mapped_column(String(200), nullable=True)
    file_extension: Mapped[str] = mapped_column(String(200), nullable=False)
    sha256hash: Mapped[str] = mapped_column(String(200), nullable=False)
    created_timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(200), nullable=False)
    deleted_by: Mapped[str | None] = mapped_column(String(200), nullable=True, default=None)
    deleted_timestamp: Mapped[str | None] = mapped_column(String(200), nullable=True, default=None)


class Annotation(Base):
    __tablename__ = "annotations"
    id: Mapped[int] = mapped_column(primary_key=True)
    document: Mapped[int] = mapped_column(ForeignKey(Document.id, ondelete='CASCADE'), nullable=False)
    annotations: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    obsoleted_by: Mapped[str | None] = mapped_column(String(200), nullable=True, default=None)
    obsoleted_timestamp: Mapped[str | None] = mapped_column(String(200), nullable=True, default=None)


class Election(Base):
    __tablename__ = "elections"
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[str] = mapped_column(String(200), nullable=False)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    committee: Mapped[str] = mapped_column(String(200), nullable=False)
    election_method: Mapped[str] = mapped_column(String(200), nullable=False)
    first_election_day: Mapped[str] = mapped_column(String(200), nullable=False)
    last_election_day: Mapped[str] = mapped_column(String(200), nullable=False)
    electoral_register_request_date: Mapped[str] = mapped_column(String(200), nullable=False)
    electoral_register_hand_out_date: Mapped[str] = mapped_column(String(200), nullable=False)
    result_url: Mapped[str] = mapped_column(String(200), nullable=False)
    result_published_date: Mapped[str] = mapped_column(String(200), nullable=False)
    scrutiny_status: Mapped[str] = mapped_column(String(200), nullable=False)
    comments: Mapped[str] = mapped_column(Text, nullable=False)
    last_modified_timestamp: Mapped[str] = mapped_column(String(200), nullable=False)
    last_modified_by: Mapped[str] = mapped_column(String(200), nullable=False)


if not database_exists(Config.DB_CONNECTION_STRING):
    create_database(Config.DB_CONNECTION_STRING)
engine = create_engine(Config.DB_CONNECTION_STRING, connect_args={"check_same_thread": False})


def create_db_and_tables():
    Base.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
