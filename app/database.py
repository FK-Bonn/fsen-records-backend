from enum import Enum

from passlib.context import CryptContext
from sqlalchemy import Column, String, Boolean, ForeignKey, Integer, Text
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship
from sqlalchemy_utils import create_database, database_exists

from app.config import Config


def verify_password(plain_password, hashed_password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)


Base = declarative_base()

class PermissionLevel(Enum):
    NONE = 0
    READ = 1
    WRITE = 2


class User(Base):
    __tablename__ = "users"
    username = Column(String(200), unique=True, primary_key=True)
    hashed_password = Column(String(200))
    admin = Column(Boolean(), default=False)
    permissions = relationship('Permission')
    created_by = Column(String(200))


class Permission(Base):
    __tablename__ = "permissions"
    user = Column(ForeignKey(User.username, ondelete='CASCADE'), primary_key=True)
    fs = Column(String(200), primary_key=True)
    level = Column(Integer, nullable=False, default=PermissionLevel.NONE)

class FsData(Base):
    __tablename__ = "fs_data"
    id = Column(Integer, primary_key=True)
    fs = Column(String(200), nullable=False)
    data = Column(Text, nullable=False)
    user = Column(String(200), nullable=False)
    timestamp = Column(String(200), nullable=False)

class ProtectedFsData(Base):
    __tablename__ = "protected_fs_data"
    id = Column(Integer, primary_key=True)
    fs = Column(String(200), nullable=False)
    data = Column(Text, nullable=False)
    user = Column(String(200), nullable=False)
    timestamp = Column(String(200), nullable=False)

class PayoutRequest(Base):
    __tablename__ = "payout_requests"
    id = Column(Integer, primary_key=True)
    request_id = Column(String(200), nullable=False)
    fs = Column(String(200), nullable=False)
    semester = Column(String(200), nullable=False)
    status = Column(String(200), nullable=False)
    status_date = Column(String(200), nullable=False)
    amount_cents = Column(Integer, nullable=False)
    comment = Column(Text, nullable=False)
    request_date = Column(String(200), nullable=False)
    requester = Column(String(200), nullable=False)
    last_modified_timestamp = Column(String(200), nullable=False)
    last_modified_by = Column(String(200), nullable=False)


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
