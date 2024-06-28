from fastapi import APIRouter, Depends, HTTPException
from starlette import status
from starlette.responses import FileResponse

from app.config import Config
from app.database import User, DBHelper, Permission
from app.routers.users import get_current_user

LAST_FS_DATA_FORMAT_UPDATE = '2023-01-01'

SUBFOLDERS = {
    'HHP-': 'HHP',
    'HHR-': 'HHR',
    'KP-': 'Kassenpruefungen',
    'Prot-': 'Protokolle',
    'Wahlergebnis-': 'Wahlergebnisse',
}

router = APIRouter()


def get_subfolder_from_filename(filename: str) -> str | None:
    for key, value in SUBFOLDERS.items():
        if filename.startswith(key):
            return value
    return None


def check_permission(current_user: User, fs: str,
                     manage_permissions: bool = False,
                     read_files: bool = False,
                     read_public_data: bool = False,
                     write_public_data: bool = False,
                     read_protected_data: bool = False,
                     write_protected_data: bool = False,
                     submit_payout_request: bool = False,
                     ):
    if current_user.admin:
        return
    with DBHelper() as session:
        permission = session.get(Permission, (current_user.username, fs))
        if not permission or \
                (manage_permissions and not permission.write_permissions) or \
                (read_files and not permission.read_files) or \
                (read_public_data and not permission.read_public_data) or \
                (write_public_data and not permission.write_public_data) or \
                (read_protected_data and not permission.read_protected_data) or \
                (write_protected_data and not permission.write_protected_data) or \
                (submit_payout_request and not permission.submit_payout_request):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing permission",
            )


@router.get("/{fs}/{filename}", response_class=FileResponse)
async def get_individual_file(fs: str, filename: str, current_user: User = Depends(get_current_user())):
    check_permission(current_user, fs, read_files=True)
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
