from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from starlette import status
from starlette.responses import HTMLResponse, FileResponse

from config import Config
from database import User, DBHelper, Permission, PermissionLevel
from users import get_current_user, admin_only

SUBFOLDERS = {
    'HHP-': 'HHP',
    'HHR-': 'HHR',
    'KP-': 'Kassenpruefungen',
    'Prot-': 'Protokolle',
    'Wahlergebnis-': 'Wahlergebnisse',
}

router = APIRouter()


def get_subfolder_from_filename(filename: str) -> Optional[str]:
    for key, value in SUBFOLDERS.items():
        if filename.startswith(key):
            return value
    return None


@router.get("/", response_class=HTMLResponse)
async def root():
    return 'oi'


@router.get("/require-admin", dependencies=[Depends(admin_only)], response_class=HTMLResponse)
async def require_admin():
    return 'aha'


def check_permission(current_user: User, fs: str, minimum_level: PermissionLevel):
    if current_user.admin:
        return
    with DBHelper() as session:
        permission = session.query(Permission).get((current_user.username, fs))
        if not permission or permission.level < minimum_level.value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing permission",
            )


@router.get("/file/{fs}/{filename}", response_class=FileResponse)
async def get_individual_file(fs: str, filename: str, current_user: User = Depends(get_current_user)):
    check_permission(current_user, fs, PermissionLevel.READ)
    subfolder = get_subfolder_from_filename(filename)
    if not subfolder or '/' in fs or '/' in filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown filename format",
        )
    file_path = Config.BASE_DATA_DIR / fs / subfolder / filename
    if file_path.is_file():
        return file_path
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )
