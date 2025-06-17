import os
import random
import string
from datetime import datetime, timedelta, UTC
from typing import Annotated

from fastapi import HTTPException, Depends, APIRouter, Form
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt, ExpiredSignatureError, constants
from jose.backends.rsa_backend import RSAKey
from jose.exceptions import JWKError
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from fastapi.responses import HTMLResponse

from app.config import Config, DUMMY_PRIVATE_KEY
from app.database import SessionDep
from app.database import User, verify_password, UserPassword


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


router = APIRouter()


def get_user(username: str, session: Session) -> tuple[User | None, str | None]:
    user = session.get(User, username)
    password_hash = None
    user_hash = session.get(UserPassword, username)
    if user_hash:
        password_hash = user_hash.hashed_password
    return user, password_hash


def get_or_create_user(username: str, full_name: str, session: Session) -> User:
    user = session.get(User, username)
    if not user:
        user = User(username=username, full_name=full_name, created_by='oidc')
        session.add(user)
        session.commit()
    return user


def authenticate_user(username: str, password: str, session: Session) -> User | None:
    user, hashed_password = get_user(username, session)
    if not user:
        return None
    if not verify_password(password, hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
    return encoded_jwt


def get_user_for_token(token: str, session: Session) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, Config.JWKS, audience='account')
        name = payload.get('name')
        username: str | None = payload.get('preferred_username')
        if not name or not username:
            raise credentials_exception
        user = get_or_create_user(username=username, full_name=name, session=session)
        return user
    except ExpiredSignatureError:
        raise credentials_exception
    except (JWTError, JWKError):
        pass  # try native auth before erroring
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user_, _ = get_user(username=token_data.username, session=session)
    if user_ is None:
        raise credentials_exception
    return user_


@router.post("/token", response_model=Token)
async def login_for_access_token(session: SessionDep, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password, session)
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


if os.getenv('TEST_FAKE_SSO_ACTIVE'):
    nonces = {}
    user_data = {}

    class FormData(BaseModel):
        client_id: str
        grant_type: str
        redirect_uri: str | None = None
        code: str | None = None
        refresh_token: str | None = None

    class UserData(BaseModel):
        given_name: str
        family_name: str
        username: str

    def create_oidc_token(content: dict, expiry: timedelta) -> str:
        private_key = RSAKey(algorithm=constants.Algorithms.RS256, key=DUMMY_PRIVATE_KEY)
        issued_at = datetime.now(UTC)
        expire = issued_at + expiry
        content = {**content, 'exp': expire, 'iat': issued_at}
        return jwt.encode(content, private_key)


    def new_token(nonce: str | None, username: str = 'user',
                  given_name: str = 'Test', family_name: str = 'User') -> dict:
        access_token = create_oidc_token({
            "scope": "profile email",
            "aud": "account",
            "email_verified": True,
            "name": f'{given_name} {family_name}',
            "preferred_username": username,
            "given_name": given_name,
            "family_name": family_name,
            "email": "user@example.org",
            "nonce": nonce,
        }, expiry=timedelta(seconds=60))
        refresh_token = create_oidc_token({
            "typ": "Refresh",
            "azp": "fake-iss",
            "nonce": nonce,
        }, expiry=timedelta(minutes=15))
        return {
            "access_token": access_token,
            "expires_in": 60,
            "refresh_expires_in": 36000,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "not-before-policy": 0,
            "session_state": "fake-session-state",
            "scope": "profile email"
        }


    @router.get('/fake-sso/realms/fake-realm/protocol/openid-connect/auth', response_class=HTMLResponse)
    async def fake_sso_auth_site():
        return '''<!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>Fake SSO</title>
        </head>
        <body>
        <h1>Fake SSO</h1>
        <form method="POST">
        <label for='username'>Username</label>
        <input type='text' id='username' name='username' value='user'/>
        <label for='given_name'>Given Name</label>
        <input type='text' id='given_name' name='given_name' value='Test'/>
        <label for='family_name'>Family Name</label>
        <input type='text' id='family_name' name='family_name' value='User'/>
        <button>Submit</button>
        </form>
        </body>
        </html>
        '''


    @router.post('/fake-sso/realms/fake-realm/protocol/openid-connect/auth')
    async def fake_sso_auth(data: Annotated[UserData, Form()], response_type: str, client_id: str, redirect_uri: str,
                            state: str | None = None, nonce: str | None = None):
        if response_type != 'code':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="response_type must be 'code'",
            )
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="client_id must be provided",
            )
        code = ''.join(random.choice(string.ascii_uppercase) for _ in range(6))
        nonces[code] = nonce
        user_data[code] = (data.username, data.given_name, data.family_name)
        return RedirectResponse(f'{redirect_uri}?session_state=fake-session-state&state={state}&iss=fake-iss&code={code}')

    @router.get('/fake-sso/realms/fake-realm/protocol/openid-connect/logout')
    async def fake_sso_logout(client_id: str, post_logout_redirect_uri: str):
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="client_id must be provided",
            )
        return RedirectResponse(post_logout_redirect_uri)


    @router.post('/fake-sso/realms/fake-realm/protocol/openid-connect/token')
    async def fake_sso_token(form_data: Annotated[FormData, Form()]):
        if form_data.code and form_data.redirect_uri:
            nonce = nonces[form_data.code]
            username, given_name, family_name = user_data[form_data.code]
            return new_token(nonce, username=username, given_name=given_name, family_name=family_name)
        elif form_data.refresh_token:
            try:
                payload = jwt.decode(form_data.refresh_token, Config.JWKS)
                nonce = payload.get('nonce')
                return new_token(nonce)
            except ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Refresh Token Expired',
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You need to provide either (code and redirect_uri) or refresh_token",
            )
