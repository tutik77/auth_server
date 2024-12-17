from fastapi import HTTPException, Depends, status 
from sqlalchemy.orm import Session
from sqlalchemy.future import select

from db import tables
from database import get_session
from settings import settings
from models.owner import SetRoleModel
from logger import logger

def owner_check(password):
    if password != settings.OWNER_PASSWORD:
        logger.warning({
            "action": "owner_check",
            "status": "failed",
            "message": "Incorrect password"
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
            headers={
                'WWW-Authenticate': 'Bearer'
            },
        )

class OwnerService():

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session


    async def set_role(self, data: SetRoleModel):
        user = await self.get_user_by_email(data.email)
        await self.update_user(user, {"role": data.role})
        logger.info({
            "action": "set_role",
            "status": "success",
            "user_data": f"user_email: {data.email}, user_role: {data.role}",
            "message": "Role changed successfully"
        })
        return user


    async def get_user_by_email(
            self,
            email: str
    ):
        stmt = select(tables.User).filter(tables.User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()

        if not user:
            logger.error({
                "action": "get_user_by_email",
                "status": "failed",
                "user_data": f"email: {email}",
                "message": "User not found"
            })
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return user


    async def get_users(self):
        stmt = select(tables.User)
        result = await self.session.execute(stmt)
        users = result.scalars().all()

        if not users:
            logger.info({
                "action": "get_users",
                "status": "success",
                "message": "Users table is empty"
            })
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Users not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return users
 

    async def delete_user(self, email):
        user = await self.get_user_by_email(email)

        await self.session.delete(user)
        await self.session.commit()
        logger.info({
            "action": "delete_user",
            "status": "success",
            "user_data": f"user_email: {email}",
            "message": "User deleted successfully"
        })
        return


    async def update_user(
            self,
            user: tables.User,
            user_data: dict
    ):
        for k, v in user_data.items():
            setattr(user, k, v)

        await self.session.commit()
        return user
    
