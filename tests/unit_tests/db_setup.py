from sqlalchemy import Column, Integer, String, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from settings import settings

TEST_DATABASE_URL = settings.test_database_url

Base = declarative_base()
engine = create_async_engine(TEST_DATABASE_URL, echo=True)

TestingSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

class User(Base):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    phone_number = Column(String)
    password_hash = Column(Text)
    is_active = Column(Boolean, default=False)
    role = Column(String, default="user")
    is_2fa = Column(Boolean, default=False)
    secret = Column(String)
