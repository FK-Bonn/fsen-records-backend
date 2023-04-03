#! /usr/bin/env python3

import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database

from app.database import Base, User, get_password_hash


def main():
    db_file, username, password = sys.argv[1:]
    connection_string = 'sqlite:///' + str(Path(db_file).resolve())
    print(connection_string)
    if not database_exists(connection_string):
        create_database(connection_string)
    engine = create_engine(connection_string)
    Base.metadata.create_all(engine)
    session = Session(engine)
    user = User()
    user.username = username
    user.hashed_password = get_password_hash(password)
    user.admin = True
    user.created_by = 'root'
    session.add_all([user])
    session.commit()
    session.close()


if __name__ == '__main__':
    main()
