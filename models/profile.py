from pydantic import BaseModel, EmailStr, field_validator

from models.auth import PasswordValidator, PhoneNumberValidator

class ToChangeData(BaseModel):
    password: str

class ToChangeEmail(ToChangeData):
    new_email: EmailStr

class ToChangeUsername(BaseModel):
    new_username: str

class ToChangePhoneNumber(BaseModel):
    new_phone_number: str

    @field_validator("new_phone_number")
    def phone_number_complexity(cls, v):
        return PhoneNumberValidator.validate_phone_number(v)

class ToChangePassword(ToChangeData):
    new_password: str
    confirm_new_password: str

    @field_validator("new_password")
    def password_complexity(cls, v):
        return PasswordValidator.validate_password(v)

class ProfileOut(BaseModel):
    username: str
    email: str
    phone_number: str