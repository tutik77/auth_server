import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
from sqlalchemy.orm import sessionmaker
from db_setup import Base, engine, TestingSessionLocal

# эта тема почему то не чистила таблицу после теста
# @pytest_asyncio.fixture(scope="function")
# async def setup_database():
#     async with engine.begin() as conn:
#         await conn.run_sync(Base.metadata.drop_all)
#         await conn.run_sync(Base.metadata.create_all)

#эта тема вроде как чистит
@pytest_asyncio.fixture(scope="function")
async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        
@pytest_asyncio.fixture(scope="function")
async def session() -> AsyncSession:
    async with TestingSessionLocal() as session:
        yield session
