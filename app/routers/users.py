import logging
from collections.abc import Coroutine, Callable
from typing import Any, Annotated

from fastapi import HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette import status

from app.database import User, verify_password, Permission as DbPermission, get_password_hash, \
    Base, AdminPermission, UserPassword, SessionDep, BaseFsData, PublicFsData, ProtectedFsData, PayoutRequest, \
    Proceedings, Document, Annotation, ElectoralRegisterDownload, Election
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
    full_name: str
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


class TransferData(BaseModel):
    token: str
    oidc_token: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

router = APIRouter()


async def get_current_user_or_raise(session: SessionDep, token: str = Depends(oauth2_scheme)) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return get_user_for_token(token, session)


async def get_current_user_or_none(session: SessionDep, token: str = Depends(oauth2_scheme)) -> User | None:
    if not token:
        return None
    return get_user_for_token(token, session)


def get_current_user(auto_error: bool = True) -> Callable[[Session, str], Coroutine[Any, Any, User]] | Callable[
    [Session, str], Coroutine[Any, Any, User | None]]:
    if auto_error:
        return get_current_user_or_raise
    else:
        return get_current_user_or_none


def is_admin(username: str, session: Session) -> bool:
    permission = session.get(AdminPermission, username)
    return permission is not None


async def admin_only(session: SessionDep, current_user: User = Depends(get_current_user())):
    if not is_admin(current_user.username, session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This requires admin rights",
        )
    else:
        pass


def check_if_user_may_grant_permissions(current_user: User, userdata: PermissionsForUser, session: Session):
    if current_user.admin:
        return

    creatorpermissions = {p.fs: p.write_permissions for p in current_user.permissions}
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


@router.post("/create", dependencies=[Depends(admin_only)], response_model=UserWithPermissions)
async def create_user(userdata: UserForCreation, session: SessionDep, current_user: User = Depends(get_current_user())):
    logging.info(f'create_user({userdata=}, {current_user.username=})')
    try:
        check_if_user_may_grant_permissions(current_user, userdata, session)
        check_permission_list(userdata)

        items: list[Base] = []
        user = User()
        user.username = userdata.username
        user.full_name = userdata.username
        user.created_by = current_user.username
        items.append(user)
        user_password = UserPassword(user=userdata.username, hashed_password=get_password_hash(userdata.password))
        items.append(user_password)
        if userdata.admin:
            admin_permission = AdminPermission(user=userdata.username, created_by=current_user.username)
            items.append(admin_permission)
        for p in userdata.permissions:
            permission = to_db_permission(p, userdata.username)
            items.append(permission)

        session.add_all(items)
        session.commit()
        return {'username': user.username,
                'full_name': user.full_name,
                'admin': bool(user.admin),
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
async def set_user_permissions(userdata: PermissionsForUser, session: SessionDep,
                               current_user: User = Depends(get_current_user())):
    logging.info(f'set_user_permissions({userdata=}, {current_user.username=})')
    check_permission_list(userdata)
    user: User | None = session.get(User, userdata.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    stmt = delete(AdminPermission).where(AdminPermission.user == user.username).execution_options(
        synchronize_session="fetch")
    session.execute(stmt)
    if userdata.admin:
        session.add(AdminPermission(user=userdata.username, created_by=current_user.username))
    stmt = delete(DbPermission).where(DbPermission.user == user.username).execution_options(
        synchronize_session="fetch")
    session.execute(stmt)
    for p in userdata.permissions:
        permission = to_db_permission(p, userdata.username)
        if not is_empty(permission):
            session.add(permission)
    session.commit()
    return {'username': user.username,
            'full_name': user.full_name,
            'admin': bool(user.admin),
            'created_by': user.created_by,
            'permissions': [p for p in user.permissions]}


@router.patch("/permissions", response_model=UserWithPermissions)
async def patch_user_permissions(userdata: PermissionList, session: SessionDep,
                                 current_user: User = Depends(get_current_user())):
    logging.info(f'patch_user_permissions({userdata=}, {current_user.username=})')
    check_permission_list(userdata)
    user: User | None = session.get(User, userdata.username)
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
    managed_fs = {p.fs for p in current_user.permissions if p.write_permissions}
    return {'username': user.username,
            'full_name': user.full_name,
            'admin': bool(user.admin),
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
async def get_user_list(session: SessionDep, current_user: User = Depends(get_current_user())):
    users: list[User] = session.query(User).all()
    allusers = {}
    if is_admin(current_user.username, session):
        for user in users:
            allusers[user.username] = {
                'username': user.username,
                'full_name': user.full_name,
                'admin': bool(user.admin),
                'created_by': user.created_by,
                'permissions': [p for p in user.permissions],
            }
    else:
        readable_fs = {p.fs for p in current_user.permissions if p.read_permissions}
        for user in users:
            if {p.fs for p in user.permissions}.intersection(readable_fs):
                allusers[user.username] = {
                    'username': user.username,
                    'full_name': user.full_name,
                    'admin': bool(user.admin),
                    'created_by': user.created_by,
                    'permissions': [p for p in user.permissions if p.fs in readable_fs],
                }
    return allusers


@router.get("/me", response_model=UserWithPermissions)
async def who_am_i(current_user: User = Depends(get_current_user())):
    return {
        'username': current_user.username,
        'full_name': current_user.full_name,
        'admin': bool(current_user.admin),
        'created_by': current_user.created_by,
        'permissions': [p for p in current_user.permissions],
    }


@router.post("/password", status_code=200)
async def change_password(password_change_data: PasswordChangeData, session: SessionDep,
                          current_user: User = Depends(get_current_user())):
    logging.info(f'{current_user.username} is changing their password')
    hashed_password = current_user.password.hashed_password if current_user.password else None
    if not verify_password(password_change_data.current_password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong current password",
        )
    current_user.password.hashed_password = get_password_hash(password_change_data.new_password)
    session.commit()


@router.post("/password/{username}", dependencies=[Depends(admin_only)], status_code=200)
async def change_password_for_user(username: str, new_password_data: NewPasswordData, session: SessionDep,
                                   current_user: User = Depends(get_current_user())):
    logging.info(f'{current_user.username} is changing the password for {username}')
    user: User | None = session.get(User, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="That user does not exist",
        )
    if not user.password:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="That user does not have a password",
        )
    user.password.hashed_password = get_password_hash(new_password_data.new_password)
    session.commit()


@router.post('/transfer')
async def transfer(data: TransferData, session: SessionDep):
    token_user = get_user_for_token(data.token, session)
    oidc_token_user = get_user_for_token(data.oidc_token, session)
    if not token_user.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='token must be for a native user',
        )
    if oidc_token_user.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='oidc_token must be for an oidc user',
        )
    old_user = token_user.username
    new_user = oidc_token_user.username
    statements = [
        update(User).where(User.created_by == old_user).values(created_by=new_user),
        update(AdminPermission).where(AdminPermission.user == old_user).values(user=new_user),
        update(AdminPermission).where(AdminPermission.created_by == old_user).values(created_by=new_user),
        update(DbPermission).where(DbPermission.user == old_user).values(user=new_user),
        update(BaseFsData).where(BaseFsData.user == old_user).values(user=new_user),
        update(PublicFsData).where(PublicFsData.user == old_user).values(user=new_user),
        update(ProtectedFsData).where(ProtectedFsData.user == old_user).values(user=new_user),
        update(ProtectedFsData).where(ProtectedFsData.approved_by == old_user).values(approved_by=new_user),
        update(PayoutRequest).where(PayoutRequest.requester == old_user).values(requester=new_user),
        update(PayoutRequest).where(PayoutRequest.last_modified_by == old_user).values(last_modified_by=new_user),
        update(Proceedings).where(Proceedings.uploaded_by == old_user).values(uploaded_by=new_user),
        update(Proceedings).where(Proceedings.deleted_by == old_user).values(deleted_by=new_user),
        update(Document).where(Document.uploaded_by == old_user).values(uploaded_by=new_user),
        update(Document).where(Document.deleted_by == old_user).values(deleted_by=new_user),
        update(Annotation).where(Annotation.created_by == old_user).values(created_by=new_user),
        update(Annotation).where(Annotation.obsoleted_by == old_user).values(obsoleted_by=new_user),
        update(ElectoralRegisterDownload).where(ElectoralRegisterDownload.username == old_user).values(
            username=new_user),
        update(Election).where(Election.last_modified_by == old_user).values(last_modified_by=new_user),
    ]
    for statement in statements:
        session.execute(statement)
    delete_statements = [
        delete(User).where(User.username == old_user),
        delete(UserPassword).where(UserPassword.user == old_user),
    ]
    for delete_statement in delete_statements:
        session.execute(delete_statement)
    session.commit()
