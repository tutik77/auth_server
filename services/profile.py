from fastapi import Depends
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.future import select

from models.profile import ToChangePhoneNumber
from mail import send_email_to_confirm
from services.auth import ph

from database import get_session
from db import tables
from logger import logger


class ProfileService:

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session


    async def get_user_by_id(self, user_id):
        user_id = int(user_id)
        stmt = select(tables.User).filter(tables.User.id == user_id)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user


    async def change_password(self, user_id, data):
        if data.new_password != data.confirm_new_password:
            logger.error({
                "action": "change_password",
                "status": "failed",
                "user_data": f"user_id: {user_id}",
                "message": "Passwords do not match"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        user = await self.get_user_by_id(user_id)
        if not self.verify_passwords(data.password, user.password_hash):
            logger.warning({
                "action": "change_password",
                "status": "failed",
                "user_data": f"user_email: {user.email}",
                "message": "Incorrect password"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user.password_hash = self.hash_password(data.new_password)
        await self.session.commit()
        return


    async def change_email(self, user_id, data):
        existing_user = await self.get_user_by_email(data.new_email)

        if existing_user:
            logger.error({
                "action": "change_email",
                "status": "failed",
                "user_data": f"user_email: {data.new_email}",
                "message": "User with this email already exists"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        user = await self.get_user_by_id(user_id)
        if not self.verify_passwords(data.password, user.password_hash):
            logger.error({
                "action": "change_email",
                "status": "failed",
                "user_data": f"user_email: {user.email}",
                "message": "Incorrect password"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        previous_email = user.email
        user.email = data.new_email
        user.is_active = False
        await self.session.commit()

        logger.info({
            "action": "change_email",
            "status": "success",
            "user_data": f"user_old_email: {previous_email}, user_new_email: {data.new_email}",
            "message": "Email changed successfully"
        })
        
        await send_email_to_confirm(data.new_email)
        logger.info({
            "action": "change_email",
            "status": "success",
            "user_data": f"user_email: {data.new_email}",
            "message": "Confirmation (email) message sent successfully to {data.new_email}"
        })
        return JSONResponse(
            content={
                "message": "На вашу почту отправлена инструкция для подтверждения почты",
            },
            status_code=status.HTTP_200_OK,
        )


    async def change_phone_number(self, user_id, number:ToChangePhoneNumber):
        existing_user = await self.get_user_by_phone_number(number.new_phone_number)
        if existing_user:
            logger.error({
                "action": "change_phone_number",
                "status": "failed",
                "user_data": f"user_id: {user_id}",
                "message": f"User with phone number {number.new_phone_number} already exists"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this phone number already exists",
                headers={
                    
                })

        user = await self.get_user_by_id(user_id)
        user.phone_number = number.new_phone_number
        await self.session.commit()
        logger.info({
            "action": "change_phone_number",
            "status": "success",
            "user_data": f"user_email: {user.email}, user_new_phone_number: {number.new_phone_number}",
            "message": "Phone number changed successfully"
        })
        return


    async def change_username(self, user_id, data):
        user = await self.get_user_by_id(user_id)
        user.username = data.new_username
        await self.session.commit()
        logger.info({
            "action": "change_username",
            "status": "success",
            "user_data": f"user_email: {user.email}, user_new_username: {data.new_username}",
            "message": "Username changed successfully"
        })
        return


    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False


    def hash_password(self, password: str) -> str:
        return ph.hash(password)


    async def get_user_by_email(
            self,
            email: str
    ):
        stmt = select(tables.User).filter(tables.User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user


    async def get_user_by_username(
            self,
            username: str
    ):
        stmt = select(tables.User).filter(tables.User.username == username)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user


    async def get_user_by_phone_number(
            self,
            phone_number: str
    ):
        stmt = select(tables.User).filter(tables.User.phone_number == phone_number)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user