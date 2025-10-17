#! /usr/bin/env python3
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.database import create_db_and_tables
from app.routers import elections
from app.routers import fsen, proceedings, export, token, files
from app.routers import payout_requests
from app.routers import users

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S:%z',
)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:5173",
    "https://fsen.datendrehschei.be",
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)
subapp = FastAPI()
app.mount('/api/v1', subapp)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

subapp.include_router(
    token.router,
    tags=['token'],
)

subapp.include_router(
    users.router,
    prefix="/user",
    tags=['users'],
)

subapp.include_router(
    files.router,
    prefix="/file",
    tags=['files'],
)

subapp.include_router(
    fsen.router,
    prefix="/data",
    tags=['data'],
)

subapp.include_router(
    payout_requests.router,
    prefix="/payout-request",
    tags=['payout requests'],
)

subapp.include_router(
    proceedings.router,
    prefix="/proceedings",
    tags=['proceedings'],
)

subapp.include_router(
    elections.router,
    prefix="/elections",
    tags=['elections'],
)

subapp.include_router(
    export.router,
    prefix="/export",
    tags=['export'],
)

if __name__ == "__main__":
    uvicorn.run(app, host='::')
