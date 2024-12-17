from fastapi import APIRouter
from fastapi import Depends

from models.owner import ProfileOut, SetRoleModel, OwnerGetProfile
from services.owner import OwnerService, owner_check


router = APIRouter(
    prefix='/owner'
)

@router.patch("/set-role")
async def set_role(
    data: SetRoleModel,
    service: OwnerService = Depends(),
):
    owner_check(data.owner_password)
    return await service.set_role(data)


@router.get("/get-profile", response_model=ProfileOut)
async def get_profile(
    owner_password: str,
    user_email: str,
    service: OwnerService = Depends(),
):  
    owner_check(owner_password)
    return await service.get_user_by_email(user_email)


@router.get("/get-profiles", response_model=list[ProfileOut])
async def get_profiles(
    owner_password: str,
    service: OwnerService = Depends(),
):
    owner_check(owner_password)
    return await service.get_users()


@router.delete("/delete-user")
async def delete_user(
    data: OwnerGetProfile,
    service: OwnerService = Depends(),
):
    owner_check(data.owner_password)
    return await service.delete_user(data.email)