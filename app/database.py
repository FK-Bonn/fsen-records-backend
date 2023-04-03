from enum import Enum

from passlib.context import CryptContext
from sqlalchemy import String, ForeignKey, Text
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, relationship, Mapped, mapped_column, DeclarativeBase
from sqlalchemy_utils import create_database, database_exists

from app.config import Config


def verify_password(plain_password, hashed_password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)


class Base(DeclarativeBase):
    pass

class PermissionLevel(Enum):
    NONE = 0
    READ = 1
    WRITE = 2


class User(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(200), unique=True, primary_key=True)
    hashed_password: Mapped[str] = mapped_column(String(200))
    admin: Mapped[bool] = mapped_column(default=False)
    permissions = relationship('Permission')
    created_by: Mapped[str] = mapped_column(String(200))


class Permission(Base):
    __tablename__ = "permissions"
    user: Mapped[str] = mapped_column(ForeignKey(User.username, ondelete='CASCADE'), primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), primary_key=True)
    level: Mapped[int] = mapped_column(nullable=False, default=PermissionLevel.NONE)

class FsData(Base):
    __tablename__ = "fs_data"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)
    user: Mapped[str] = mapped_column(String(200), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(200), nullable=False)

class ProtectedFsData(Base):
    __tablename__ = "protected_fs_data"
    id: Mapped[int] = mapped_column(primary_key=True)
    fs: Mapped[str] = mapped_column(String(200), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)
    user: Mapped[str] = mapped_column(String(200), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(200), nullable=False)

class PayoutRequest(Base):
    __tablename__ = "payout_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(200), nullable=False)
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


class DBHelper:
    def __init__(self):
        self.connection_str = Config.DB_CONNECTION_STRING
        self._session = None

    def __enter__(self):
        if self._session:
            return self._session
        if not database_exists(self.connection_str):
            create_database(self.connection_str)
        engine = create_engine(self.connection_str)

        Base.metadata.create_all(engine)

        self._session = Session(engine)
        return self._session

    def __exit__(self, type, value, traceback):
        self._session.close()
        self._session = None
