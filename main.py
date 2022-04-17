#! /usr/bin/env python3

import uvicorn
from fastapi import FastAPI

import fsen
import users

app = FastAPI(
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
)

app.include_router(
    users.router,
    prefix="/api/v1"
)

app.include_router(
    fsen.router,
    prefix="/api/v1"
)

if __name__ == "__main__":
    uvicorn.run(app)
