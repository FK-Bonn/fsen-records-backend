import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, BinaryIO
from zoneinfo import ZoneInfo

from fastapi.encoders import jsonable_encoder


def ts() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def get_europe_berlin_date() -> str:
    return datetime.now(tz=ZoneInfo("Europe/Berlin")).isoformat()[:10]


@dataclass(frozen=True, slots=True)
class TimeValues:
    date: str
    date_time: str
    value: datetime


class Now:
    unixtime: int
    utc: TimeValues
    berlin: TimeValues

    def __init__(self):
        now = datetime.now(tz=timezone.utc)
        self.unixtime = int(now.timestamp())
        self.utc = TimeValues(date=now.date().isoformat(), date_time=now.isoformat(), value=now)
        berlin = now.astimezone(ZoneInfo("Europe/Berlin"))
        self.berlin = TimeValues(date=berlin.date().isoformat(), date_time=berlin.isoformat(), value=berlin)
        

def to_json(data: Any) -> str:
    return json.dumps(jsonable_encoder(data), indent=2)


def calculate_sha256(uploaded_file: BinaryIO):
    file_hash = hashlib.sha256()
    while chunk := uploaded_file.read(8192):
        file_hash.update(chunk)
    uploaded_file.seek(0)
    return file_hash.hexdigest()


def build_filename_str(request_id: str, category: str, base_name: str, date_start: str | None,
                       date_end: str | None, file_extension: str, sha256hash: str) -> str:
    base_name = re.sub(r'[^a-zA-Z0-9äöüÄÖÜßẞ]', '_', base_name)[:50]
    filename = f'{category}-{request_id}-{base_name}'.replace('--', '-')
    if date_start:
        filename += f'-{date_start}'
        if date_end:
            filename += f'--{date_end}'
    filename += f'-{sha256hash}.{file_extension}'
    return filename
