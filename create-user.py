#! /usr/bin/env python3

import sys
from argparse import ArgumentParser
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database

from app.database import Base, User, get_password_hash, UserPassword, AdminPermission


def main():
    parser = ArgumentParser('Create Admin user')
    parser.add_argument('db_file', type=Path)
    parser.add_argument('username', type=str)
    parser.add_argument('password', type=str)
    args = parser.parse_args()
    connection_string = 'sqlite:///' + str(args.db_file.resolve())
    print(connection_string)
    if not database_exists(connection_string):
        create_database(connection_string)
    engine = create_engine(connection_string)
    Base.metadata.create_all(engine)
    session = Session(engine)
    items = []
    user = User()
    user.username = args.username
    user.full_name = args.username
    user.created_by = 'root'
    items.append(user)
    user_password = UserPassword(user=args.username, hashed_password=get_password_hash(args.password))
    items.append(user_password)
    admin_permission = AdminPermission(user=args.username, created_by='root')
    items.append(admin_permission)
    session.add_all(items)
    session.commit()
    session.close()


if __name__ == '__main__':
    main()
