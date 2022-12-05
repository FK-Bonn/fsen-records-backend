import json
from datetime import datetime, timezone

from fastapi.encoders import jsonable_encoder


def ts() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def to_json(data: any) -> str:
    return json.dumps(jsonable_encoder(data), indent=2)
