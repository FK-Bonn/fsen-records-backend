import os
from pathlib import Path


class Config:
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_DAYS = 6 * 31

    SECRET_KEY = os.environ["SECRET_KEY"] \
        if "SECRET_KEY" in os.environ \
        else "1883eb9a04f787018d99ff7dceb4ade9af17cf91d70593336e13a40630dd18c5"
    DB_CONNECTION_STRING = os.environ["DB_CONNECTION_STRING"] \
        if "DB_CONNECTION_STRING" in os.environ \
        else 'sqlite:///' + str(Path(__file__).resolve().parent.parent / 'data' / 'data.db')
    BASE_DATA_DIR = Path(os.environ["BASE_DATA_DIR"]) \
        if "BASE_DATA_DIR" in os.environ \
        else Path(__file__).parent.resolve().parent / 'data' / 'files'
