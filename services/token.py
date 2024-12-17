from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.orm import Session
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer

from database import get_session
from settings import settings
from logger import logger


http_bearer = HTTPBearer(auto_error=False)

class TokenService:

    def __init__(self, session: Session=Depends(get_session)):
        self.session = session


    @staticmethod
    def get_current_user(credentials=Depends(http_bearer)):
        if not credentials:
            logger.error({
                "action": "get_current_user",
                "status": "failed",
                "token": f"{credentials}",
                "message": "Invalid token"
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = credentials.credentials
        try:
            payload = jwt.decode(token, key=settings.jwt_secret, algorithms=settings.jwt_algorithm)
            user_id: str = payload.get("sub")
            if user_id is None:
                logger.error({
                    "action": "get_current_user",
                    "status": "failed",
                    "token": f"{token}",
                    "message": "No user ID in token"
                })
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                )

            issuer = payload.get("iss")
            if issuer != settings.jwt_issuer:
                logger.error({
                    "action": "get_current_user",
                    "status": "failed",
                    "token": f"{token}",
                    "message": "Invalid issuer in token"
                })
                raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                )

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.PyJWTError:
            logger.error({
                "action": "get_current_user",
                "status": "failed",
                "token": f"{token}",
                "message": "Invalid token"
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        logger.info({
            "action": "get_current_user",
            "status": "success",
            "user_id": f"{user_id}",
            "message": "User authenticated"
        })
        return user_id


    def create_access_token(self, data: dict, expires_delta: timedelta | None = None, refresh: bool = False):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update(
            {
                "exp": expire,
                "refresh" : refresh,
                "iss": settings.jwt_issuer
            }

        )
        encoded_jwt = jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return encoded_jwt


    def decode_token(self, token:str) ->dict:
        try:
            token_data = jwt.decode(token, key=settings.jwt_secret, algorithms=[settings.jwt_algorithm])
            return token_data
        except jwt.PyJWTError as e:
            logger.error({
                "action": "decode_token",
                "status": "failed",
                "token": f"{token}",
                "message": f"Error decoding token: {e}"
            })
            return None


class AccessTokenBearer(TokenService):
    def verify_token(self, token_data: dict) -> None:
        if token_data and token_data['refresh']:
            logger.error({
                "action": "verify_token",
                "status": "failed",
                "token": f"{token_data}",
                "message": "Refresh token should be access token"
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide an access token",
            )


class RefreshTokenBearer(TokenService):
    def __call__(self, credentials=Depends(http_bearer)) -> dict:
        if not credentials:
            logger.error({
                "action": "get_current_user",
                "status": "failed",
                "token": f"{credentials}",
                "message": "Invalid token"
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = self.decode_token(credentials.credentials)

        self.verify_token(token_data)
        return token_data


    def verify_token(self, token_data: dict) -> None:
        if token_data and not token_data.get('refresh'):
            logger.error({
                "action": "verify_token",
                "status": "failed",
                "token": f"{token_data}",
                "message": "Access token should be a refresh token"
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide a refresh token",
            )
