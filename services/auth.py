from datetime import timedelta, datetime

from fastapi import Depends
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fastapi import status
from fastapi.responses import JSONResponse
from sqlalchemy.future import select

from services.twoFactorAuth import TwoFactorAuthService as Tfs
from url_token import verify_token, decode_url_safe_token, create_url_safe_token
from database import get_session
from db import tables
from models.auth import Token, UserRegistration, PasswordResetConfirmModel, PasswordResetRequestModel
from settings import settings
from services.token import TokenService as TS, RefreshTokenBearer
from logger import logger
from mail import send_email_to_confirm, send_email


ph = PasswordHasher()

class AuthService:

    def __init__(self, session: Session = Depends(get_session), token_service: TS=Depends(), factor_service: Tfs = Depends()):
        self.session = session
        self.token_service = token_service
        self.factor_service = factor_service

    async def register(
            self,
            user_data: UserRegistration
    ):

        attributes = {
            "email": user_data.email,
            "username": user_data.username,
            "phone_number": user_data.phone_number
        }

        for attr, value in attributes.items():
            stmt = select(tables.User).filter(getattr(tables.User, attr) == value)
            result = await self.session.execute(stmt)
            existing_user = result.scalars().first()

            if existing_user:
                logger.error({
                    "action": "register",
                    "status": "failed",
                    "user_data": f"{attr}: {value}",
                    "message": f"User with this {attr} already exists"
                })
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"User with this {attr} already exists",
                    headers={
                        'WWW-Authenticate': 'Bearer'
                    },
                )

        user = tables.User(
            email = user_data.email,
            username = user_data.username,
            phone_number = user_data.phone_number,
            password_hash = self.hash_password(user_data.password)
        )
        self.session.add(user)
        await self.session.commit()
        await send_email_to_confirm(user_data.email)
        logger.info({
            "action": "register",
            "status": "success",
            "user_data": f"email: {user_data.email}",
            "message": "User registered successfully"
        })
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "User registered successfully", "user": user_data.__dict__}
        )


    async def authenticate_user(
            self,
            user_email: str,
            password: str,
            code: str
    ) -> Token:
        user = await self.get_user_by_email(user_email)
        access_token_expires = timedelta(seconds=settings.jwt_expiration)

        if not user or not self.verify_passwords(password, user.password_hash):
            logger.warning({
                "action": "login",
                "status": "failed",
                "user_data": f"email: {user_email}",
                "message": "Incorrect email or password"
            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        if not user.is_active:
            logger.error({
                "action": "login",
                "status": "failed",
                "user_data": f"email: {user_email}",
                "message": "Account is not confirmed"

            })
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account is not confirmed",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        verify_code: bool
        if not user.is_2fa:
            verify_code = True
        else:
            verify_code = await self.factor_service.verify_2fa_code(user, code)
        if verify_code:
            access_token = self.token_service.create_access_token(
                data = {
                    "sub" : str(user.id),
                    "exp": access_token_expires
                }
            )
            refresh_token = self.token_service.create_access_token(
                data={
                    "sub": str(user.id),

                },
                expires_delta=timedelta(days=settings.refresh_token_expire),
                refresh = True,
            )

            logger.info({
                "action": "login",
                "status": "success",
                "user_data": f"email: {user_email}",
                "message": "User logged in successfully"
            })
            return Token(access_token=access_token, refresh_token=refresh_token)
        logger.error({
            "action": "login",
            "status": "failed",
            "user_data": f"email: {user_email}",
            "message": "Incorrect 2fa code"
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect 2fa code",
        )


    async def password_reset_request(
            self,
            email_data:PasswordResetRequestModel,
    ):
        email = email_data.email
        token = create_url_safe_token({"email": email})
        verify_token(token, expires_in=900)
        link = f"http://127.0.0.1:8000/auth/reset-password?token={token}"
        html_message = f'Инструкция для сброса пароля: <p>{link}</p>'
        subject = "Reset Your Password"
        await send_email([email], subject, html_message)
        logger.info({
            "action": "password_reset_request",
            "status": "success",
            "user_data": f"email: {email}",
            "message": f"Reset password message sent successfully to {email}"
        })
        return JSONResponse(
            content={
                "message": "На вашу почту отправлена инструкция для сброса пароля",
            },
            status_code=status.HTTP_200_OK,
        )


    async def reset_password(
            self,
            token: str,
            password: PasswordResetConfirmModel,
    ):
        new_password = password.new_password
        confirm_password = password.confirm_new_password
        if new_password != confirm_password:
            raise HTTPException(
                detail="Passwords don't match",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        token_data = decode_url_safe_token(token)
        if not token_data:
            logger.error({
                "action": "reset_password",
                "status": "failed",
                "data": f"token: {token}",
                "message": "Invalid or expired token"
            })
            return JSONResponse(
                content={"message": "Invalid or expired token"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        user_email = token_data.get("email")

        if user_email:
            user = await self.get_user_by_email(user_email)
            if not user:
                logger.warning({
                    "action": "reset_password",
                    "status": "failed",
                    "user_data": f"email: {user_email}",
                    "message": "User not found"
                })
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            passwd_hash = self.hash_password(new_password)
            await self.update_user(user, {"password_hash": passwd_hash})
            logger.info({
                "action": "reset_password",
                "status": "success",
                "user_data": f"email: {user_email}",
                "message": "Password reset Successfully"
            })
            return JSONResponse(
                content={"message": "Password reset Successfully"},
                status_code=status.HTTP_200_OK,
            )
        logger.warning({
            "action": "reset_password",
            "status": "failed",
            "user_data": f"email: {user_email}",
            "message": "Error occured during password reset."
        })
        return JSONResponse(
            content={"message": "Error occured during password reset."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


    async def verify_user_account(self, token: str):
        token_data = decode_url_safe_token(token)
        if not token_data:
            logger.error({
                "action": "verify_user_account",
                "status": "failed",
                "data": f"token: {token}",
                "message": "Invalid or expired token"
            })
            return JSONResponse(
                content={"message": "Invalid or expired token"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        user_email = token_data.get("email")
        if user_email:
            user = await self.get_user_by_email(user_email)
            if not user:
                logger.error({
                    "action": "verify_user_account",
                    "status": "failed",
                    "user_data": f"email: {user_email}",
                    "message": "User not found"
                })
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Incorrect email",
                    headers={
                        'WWW-Authenticate': 'Bearer'
                    },
                )

            await self.update_user(user, {"is_active": True})
            logger.info({
                "action": "verify_user_account",
                "status": "success",
                "user_data": f"email: {user_email}",
                "message": "Account verified successfully"
            })
            return JSONResponse(
                content={"message": "Account verified successfully"},
                status_code=status.HTTP_200_OK,
            )
        logger.error({
            "action": "verify_user_account",
            "status": "failed",
            "user_data": f"email: {user_email}",
            "message": "Error occured during verification"
        })
        return JSONResponse(
            content={"message": "Error occured during verification"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


    async def get_new_refresh_token(
            self,
            token_detail: dict = Depends(RefreshTokenBearer()),
    ):
        expiry_timestamp = token_detail['exp']

        if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
            new_access_token = self.token_service.create_access_token(
                data={
                    "sub": str(token_detail['sub']),
                },
            )

            return JSONResponse({'access_token': new_access_token})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired Token')


    async def update_user(
            self,
            user: tables.User,
            user_data: dict
    ):
        for k, v in user_data.items():
            setattr(user, k, v)

        await self.session.commit()
        return user


    async def get_user_by_email(
            self,
            email: str
    ):
        stmt = select(tables.User).filter(tables.User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user


    def hash_password(
            self,
            password: str
    ) -> str:
        return ph.hash(password)


    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False