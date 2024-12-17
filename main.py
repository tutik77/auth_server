from fastapi import FastAPI

from db import tables
from api import router
from database import engine

app = FastAPI()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(tables.Base.metadata.create_all)

@app.on_event("startup")
async def startup_event():
    await init_db()

app.include_router(router)