from sqlalchemy import Column, Integer, String, Boolean, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

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
    secret = Column(Text)