#! /usr/bin/env python3

import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.routers import fsen, proceedings
from app.routers import users
from app.routers import payout_requests

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:5173",
    "https://fsen.datendrehschei.be",
]


app = FastAPI(
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    users.router,
    prefix="/api/v1"
)

app.include_router(
    fsen.router,
    prefix="/api/v1"
)

app.include_router(
    payout_requests.router,
    prefix="/api/v1"
)

app.include_router(
    proceedings.router,
    prefix="/api/v1"
)

if __name__ == "__main__":
    uvicorn.run(app, host='::')
