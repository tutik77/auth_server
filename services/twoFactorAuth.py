import pyotp
import qrcode
from fastapi import Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from fastapi import status
from sqlalchemy.future import select
from cryptography.fernet import Fernet
from models.auth import UserTwoFa
from database import get_session
from db.tables import User
from logger import logger
from settings import settings

cipher_suite = Fernet(settings.TOTP_SECRET)
class TwoFactorAuthService:

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    async def enable_otp(self, user_data: UserTwoFa):
        if user_data.is_2fa is False:
            secret = pyotp.random_base32()
            encrypted_secret = cipher_suite.encrypt(secret.encode()).decode()
            user_data.secret = encrypted_secret
            uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_data.username, issuer_name="Gamma")
            qrcode.make(uri).save(f"{user_data.username}_qrcode.png")
            user_data.is_2fa = True
            self.session.add(user_data)
            await self.session.commit()
            logger.info({
                "action": "enable 2fa",
                "status": "success",
                "user_data": f"email: {user_data.email}",
                "message": "Enable 2fa successfully"
            })
            return JSONResponse(
                content={"message": "Enable 2fa successfully"},
                status_code=status.HTTP_200_OK,
            )
        else:
            logger.error({
                "action": "enable 2fa",
                "status": "failed",
                "user_data": f"email: {user_data.email}",
                "message": "2fa is already enabled"
            })
            return JSONResponse(
                content={"message": "Failed! 2fa is already enabled"},
                status_code=status.HTTP_400_BAD_REQUEST,

            )

    async def verify_2fa_code(self, user, code: str):
        decrypted_secret = cipher_suite.decrypt(user.secret.encode()).decode()
        totp = pyotp.TOTP(decrypted_secret)
        if totp.verify(code):
            return True
        return False

    async def disable_2fa(self, user_data:UserTwoFa):
        user_data.secret = None
        user_data.is_2fa = False
        self.session.add(user_data)
        await self.session.commit()
        logger.info({
            "action": "enable 2fa",
            "status": "success",
            "user_data": f"email: {user_data.email}",
            "message": "Disable 2fa successfully"
        })
        return JSONResponse(
            content={"message": "Disable 2fa successfully"},
            status_code=status.HTTP_200_OK,
        )





