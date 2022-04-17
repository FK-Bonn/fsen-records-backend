from passlib.context import CryptContext
from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship
from sqlalchemy_utils import create_database, database_exists

from config import Config


def verify_password(plain_password, hashed_password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)


Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    username = Column(String(200), unique=True, primary_key=True)
    hashed_password = Column(String(200))
    admin = Column(Boolean(), default=False)
    permissions = relationship('Permission')


class Permission(Base):
    __tablename__ = "permissions"
    user = Column(ForeignKey(User.username, ondelete='CASCADE'), primary_key=True)
    fs = Column(String(200), primary_key=True)


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
