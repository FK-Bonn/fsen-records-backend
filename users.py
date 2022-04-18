from datetime import datetime, timedelta
from typing import Optional, Union, List, Dict

from fastapi import HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from starlette import status

from config import Config
from database import DBHelper, User, verify_password, Permission, get_password_hash


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserForCreation(BaseModel):
    username: str
    password: str
    admin: bool
    permissions: List[str]


class UserWithPermissions(BaseModel):
    username: str
    admin: bool
    permissions: List[str]


class PasswordChangeData(BaseModel):
    current_password: str
    new_password: str


class NewPasswordData(BaseModel):
    new_password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter()


def get_user(username: str) -> Optional[User]:
    with DBHelper() as session:
        user = session.query(User).get(username)
        if user:
            return user


def authenticate_user(username: str, password: str) -> Union[User, bool]:
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def admin_only(current_user: User = Depends(get_current_user)):
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This requires admin rights",
        )


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=Config.ACCESS_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/user/create", dependencies=[Depends(admin_only)], response_model=UserWithPermissions)
async def create_user(userdata: UserForCreation):
    try:
        with DBHelper() as session:
            items = []
            user = User()
            user.username = userdata.username
            user.hashed_password = get_password_hash(userdata.password)
            user.admin = userdata.admin
            items.append(user)
            for fs in userdata.permissions:
                permission = Permission()
                permission.user = userdata.username
                permission.fs = fs
                items.append(permission)

            session.add_all(items)
            session.commit()
            return {'username': user.username, 'admin': user.admin, 'permissions': [p.fs for p in user.permissions]}
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Already exists",
        )


@router.post("/user/permissions", dependencies=[Depends(admin_only)], response_model=UserWithPermissions)
async def set_user_permissions(userdata: UserWithPermissions):
    with DBHelper() as session:
        user: User = session.query(User).get(userdata.username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        user.admin = userdata.admin
        stmt = delete(Permission).where(Permission.user == user.username).execution_options(synchronize_session="fetch")
        session.execute(stmt)
        for fs in userdata.permissions:
            permission = Permission()
            permission.user = userdata.username
            permission.fs = fs
            session.add(permission)
        session.commit()
        return {'username': user.username, 'admin': user.admin, 'permissions': [p.fs for p in user.permissions]}


@router.get("/user", dependencies=[Depends(admin_only)], response_model=Dict[str, UserWithPermissions])
async def get_user_list():
    with DBHelper() as session:
        users: List[User] = session.query(User).all()
        allusers = {}
        for user in users:
            allusers[user.username] = {
                'username': user.username,
                'admin': user.admin,
                'permissions': [p.fs for p in user.permissions],
            }
        return allusers


@router.get("/user/me", response_model=UserWithPermissions)
async def who_am_i(current_user: User = Depends(get_current_user)):
    with DBHelper() as session:
        user: User = session.query(User).get(current_user.username)
        return {
            'username': user.username,
            'admin': user.admin,
            'permissions': [p.fs for p in user.permissions],
        }


@router.post("/user/password", status_code=200)
async def change_password(password_change_data: PasswordChangeData, current_user: User = Depends(get_current_user)):
    with DBHelper() as session:
        user: User = session.query(User).get(current_user.username)
        if not verify_password(password_change_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Wrong current password",
            )
        user.hashed_password = get_password_hash(password_change_data.new_password)
        session.commit()


@router.post("/user/password/{username}", dependencies=[Depends(admin_only)], status_code=200)
async def change_password_for_user(username: str, new_password_data: NewPasswordData):
    with DBHelper() as session:
        user: User = session.query(User).get(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="That user does not exist",
            )
        user.hashed_password = get_password_hash(new_password_data.new_password)
        session.commit()
