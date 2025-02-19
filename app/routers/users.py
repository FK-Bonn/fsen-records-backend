import logging
from collections.abc import Coroutine, Callable
from typing import Any, Annotated

from fastapi import HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette import status

from app.database import DBHelper, User, verify_password, Permission as DbPermission, get_password_hash, \
    Base
from app.routers.token import get_user_for_token


class Token(BaseModel):
    access_token: str
    token_type: str


class Permission(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    fs: str
    read_permissions: bool
    write_permissions: bool
    read_files: bool
    read_public_data: bool
    write_public_data: bool
    read_protected_data: bool
    write_protected_data: bool
    submit_payout_request: bool
    upload_proceedings: bool
    delete_proceedings: bool
    locked: bool


class PermissionList(BaseModel):
    username: Annotated[str, Field(min_length=1)]
    permissions: list[Permission]


class PermissionsForUser(PermissionList):
    admin: bool


class UserWithPermissions(PermissionsForUser):
    created_by: str


class TokenData(BaseModel):
    username: str | None = None


class UserForCreation(PermissionsForUser):
    password: Annotated[str, Field(min_length=8)]


class PasswordChangeData(BaseModel):
    current_password: str
    new_password: Annotated[str, Field(min_length=8)]


class NewPasswordData(BaseModel):
    new_password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

router = APIRouter()


async def get_current_user_or_raise(token: str = Depends(oauth2_scheme)) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return get_user_for_token(token)


async def get_current_user_or_none(token: str = Depends(oauth2_scheme)) -> User | None:
    if not token:
        return None
    return get_user_for_token(token)


def get_current_user(auto_error: bool = True) -> Callable[[str], Coroutine[Any, Any, User]] | Callable[
    [str], Coroutine[Any, Any, User | None]]:
    if auto_error:
        return get_current_user_or_raise
    else:
        return get_current_user_or_none


async def admin_only(current_user: User = Depends(get_current_user())):
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This requires admin rights",
        )


def check_if_user_may_grant_permissions(current_user: User, userdata: PermissionsForUser, session: Session):
    creator = get_user_or_throw(current_user, session)
    if creator.admin:
        return

    creatorpermissions = {p.fs: p.write_permissions for p in creator.permissions}
    is_subset = True
    for permission in userdata.permissions:
        if permission.locked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User is not authorized to modify those permissions",
            )
    for permission in userdata.permissions:
        if permission.fs not in creatorpermissions or not creatorpermissions[permission.fs]:
            is_subset = False
    if userdata.admin or not is_subset:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not authorized to grant those permissions",
        )


def get_user_or_throw(current_user, session):
    creator = session.get(User, current_user.username)
    if not creator:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist",
        )
    return creator


def check_permission_list(userdata: PermissionList):
    seen_permissions = set()
    for permission in userdata.permissions:
        t = (userdata.username, permission.fs)
        if t in seen_permissions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Conflicting permissions for {userdata.username=} and {permission.fs=}",
            )
        seen_permissions.add(t)


@router.post("/create", response_model=UserWithPermissions)
async def create_user(userdata: UserForCreation, current_user: User = Depends(get_current_user())):
    logging.info(f'create_user({userdata=}, {current_user.username=})')
    try:
        with DBHelper() as session:
            check_if_user_may_grant_permissions(current_user, userdata, session)
            check_permission_list(userdata)

            items: list[Base] = []
            user = User()
            user.username = userdata.username
            user.hashed_password = get_password_hash(userdata.password)
            user.admin = userdata.admin
            user.created_by = current_user.username
            items.append(user)
            for p in userdata.permissions:
                permission = to_db_permission(p, userdata.username)
                items.append(permission)

            session.add_all(items)
            session.commit()
            return {'username': user.username,
                    'admin': user.admin,
                    'created_by': user.created_by,
                    'permissions': [p for p in user.permissions]}
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Already exists",
        )


def is_empty(p: DbPermission):
    return not (p.read_files or p.read_permissions or p.write_permissions or p.read_public_data or
                p.write_public_data or p.read_protected_data or p.write_protected_data or p.submit_payout_request)


@router.post("/permissions", dependencies=[Depends(admin_only)], response_model=UserWithPermissions)
async def set_user_permissions(userdata: PermissionsForUser, current_user: User = Depends(get_current_user())):
    logging.info(f'set_user_permissions({userdata=}, {current_user.username=})')
    check_permission_list(userdata)
    with DBHelper() as session:
        user: User = session.get(User, userdata.username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        user.admin = userdata.admin
        stmt = delete(DbPermission).where(DbPermission.user == user.username).execution_options(
            synchronize_session="fetch")
        session.execute(stmt)
        for p in userdata.permissions:
            permission = to_db_permission(p, userdata.username)
            if not is_empty(permission):
                session.add(permission)
        session.commit()
        return {'username': user.username,
                'admin': user.admin,
                'created_by': user.created_by,
                'permissions': [p for p in user.permissions]}


@router.patch("/permissions", response_model=UserWithPermissions)
async def patch_user_permissions(userdata: PermissionList, current_user: User = Depends(get_current_user())):
    logging.info(f'patch_user_permissions({userdata=}, {current_user.username=})')
    check_permission_list(userdata)
    with DBHelper() as session:
        user: User = session.get(User, userdata.username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        userdata_for_check = PermissionsForUser(username=userdata.username, permissions=userdata.permissions,
                                                admin=False)
        check_if_user_may_grant_permissions(current_user=current_user, userdata=userdata_for_check, session=session)

        for permission in userdata.permissions:
            stmt = delete(DbPermission). \
                where(DbPermission.user == user.username, DbPermission.fs == permission.fs). \
                execution_options(synchronize_session="fetch")
            session.execute(stmt)
        for p in userdata.permissions:
            db_permission = to_db_permission(p, userdata.username)
            session.add(db_permission)
        session.commit()
        actor: User = session.get(User, current_user.username)
        managed_fs = {p.fs for p in actor.permissions if p.write_permissions}
        return {'username': user.username,
                'admin': user.admin,
                'created_by': user.created_by,
                'permissions': [p for p in user.permissions if p.fs in managed_fs]}


def to_db_permission(p: Permission, username: str):
    db_permission = DbPermission()
    db_permission.user = username
    db_permission.fs = p.fs
    db_permission.locked = p.locked
    db_permission.read_permissions = p.read_permissions
    db_permission.write_permissions = p.write_permissions
    db_permission.read_files = p.read_files
    db_permission.read_public_data = p.read_public_data
    db_permission.write_public_data = p.write_public_data
    db_permission.read_protected_data = p.read_protected_data
    db_permission.write_protected_data = p.write_protected_data
    db_permission.submit_payout_request = p.submit_payout_request
    db_permission.upload_proceedings = p.upload_proceedings
    db_permission.delete_proceedings = p.delete_proceedings
    return db_permission


@router.get("", response_model=dict[str, UserWithPermissions])
async def get_user_list(current_user: User = Depends(get_current_user())):
    with DBHelper() as session:
        users: list[User] = session.query(User).all()
        allusers = {}
        if current_user.admin:
            for user in users:
                allusers[user.username] = {
                    'username': user.username,
                    'admin': user.admin,
                    'created_by': user.created_by,
                    'permissions': [p for p in user.permissions],
                }
        else:
            actor: User = session.get(User, current_user.username)
            readable_fs = {p.fs for p in actor.permissions if p.read_permissions}
            for user in users:
                if {p.fs for p in user.permissions}.intersection(readable_fs):
                    allusers[user.username] = {
                        'username': user.username,
                        'admin': user.admin,
                        'created_by': user.created_by,
                        'permissions': [p for p in user.permissions if p.fs in readable_fs],
                    }
        return allusers


@router.get("/me", response_model=UserWithPermissions)
async def who_am_i(current_user: User = Depends(get_current_user())):
    with DBHelper() as session:
        user: User = session.get(User, current_user.username)
        return {
            'username': user.username,
            'admin': user.admin,
            'created_by': user.created_by,
            'permissions': [p for p in user.permissions],
        }


@router.post("/password", status_code=200)
async def change_password(password_change_data: PasswordChangeData, current_user: User = Depends(get_current_user())):
    logging.info(f'{current_user.username} is changing their password')
    with DBHelper() as session:
        user: User = session.get(User, current_user.username)
        if not verify_password(password_change_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Wrong current password",
            )
        user.hashed_password = get_password_hash(password_change_data.new_password)
        session.commit()


@router.post("/password/{username}", dependencies=[Depends(admin_only)], status_code=200)
async def change_password_for_user(username: str, new_password_data: NewPasswordData,
                                   current_user: User = Depends(get_current_user())):
    logging.info(f'{current_user.username} is changing the password for {username}')
    with DBHelper() as session:
        user: User = session.get(User, username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="That user does not exist",
            )
        user.hashed_password = get_password_hash(new_password_data.new_password)
        session.commit()
