from fastapi import APIRouter
from fastapi import Depends

from models.profile import ToChangePhoneNumber
from models.profile import ProfileOut, ToChangeEmail, ToChangePassword, ToChangeUsername
from services.profile import ProfileService
from services.token import TokenService
from services.twoFactorAuth import TwoFactorAuthService

router = APIRouter(
    prefix='/profile'
)

@router.get('/', response_model = ProfileOut)
async def get_profile(
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    user = await service.get_user_by_id(current_user)
    return ProfileOut(username=user.username, email=user.email, phone_number=user.phone_number)


@router.patch('/change-password')
async def change_password(
    data:  ToChangePassword,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_password(current_user, data)


@router.patch('/change-email')
async def change_email(
    data: ToChangeEmail,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_email(current_user, data)


@router.patch('/change-username')
async def change_username(
    data: ToChangeUsername,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_username(current_user, data)


@router.patch('/change-phone-number')
async def change_phone_number(
    number: ToChangePhoneNumber,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_phone_number(current_user, number)

@router.post("/enable_twoFactorAuth")
async def enable_2fa(
        current_user: str = Depends(TokenService.get_current_user),
        service: TwoFactorAuthService = Depends(),
        profile_service: ProfileService = Depends()
):
    user_data = await profile_service.get_user_by_id(current_user)
    return await service.enable_otp(user_data)

@router.post("/disable_twoFactorAuth")
async def disable_2fa(
        current_user: str = Depends(TokenService.get_current_user),
        service: TwoFactorAuthService = Depends(),
        profile_service: ProfileService = Depends()
):
    user_data = await profile_service.get_user_by_id(current_user)
    return await service.disable_2fa(user_data)

