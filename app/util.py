import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi.encoders import jsonable_encoder


def ts() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def to_json(data: any) -> str:
    return json.dumps(jsonable_encoder(data), indent=2)


def get_europe_berlin_date()-> str:
    return datetime.now(tz=ZoneInfo('Europe/Berlin')).isoformat()[:10]
