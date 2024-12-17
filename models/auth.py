from __future__ import annotations
import re

from fastapi import Form
from pydantic import EmailStr, BaseModel, field_validator


class OAuth2EmailPasswordRequestForm:
    def __init__(
        self,
        email: str = Form(...),
        password: str = Form(...),
        code: str = Form(...)
    ):
        self.email = email
        self.password = password
        self.code = code

class BaseUser(BaseModel):
    email: EmailStr
    username: str
    phone_number: str

    @field_validator("phone_number")
    def phone_number_complexity(cls, v):
        return PhoneNumberValidator.validate_phone_number(v)

class UserRegistration(BaseUser):
    password: str

    @field_validator("password")
    def password_complexity(cls, v):
        return PasswordValidator.validate_password(v)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    type_token: str = 'bearer'


class PasswordResetRequestModel(BaseModel):
    email: str


class PasswordResetConfirmModel(BaseModel):
    new_password: str
    confirm_new_password: str

    @field_validator("new_password")
    def password_complexity(cls, v):
        return PasswordValidator.validate_password(v)

class UserTwoFa(BaseModel):
    email: str
    is_2fa: bool
    secret: str


class PasswordValidator:
    @staticmethod
    def validate_password(v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password should be at least 8 characters long")
        if not any(char.isdigit() for char in v):
            raise ValueError("Password should contain at least one number")
        if not any(char.isupper() for char in v):
            raise ValueError("Password should contain at least one capital letter")
        if not any(char.islower() for char in v):
            raise ValueError("Password should contain at least one small letter")
        if not any(char in '!@#$%^&*()_+-=' for char in v):
            raise ValueError("Password should contain at least one special character")
        return v

class PhoneNumberValidator:
    @staticmethod
    def validate_phone_number(v: str) -> str:
        if not re.match(r'^(\+7|7|8)?[\s\-]?\(?[489][0-9]{2}\)?[\s\-]?[0-9]{3}[\s\-]?[0-9]{2}[\s\-]?[0-9]{2}$', v):
            raise ValueError("Invalid phone number")
        return v