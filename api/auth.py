from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends

from models.auth import Token, PasswordResetConfirmModel
from models.auth import UserRegistration
from services.auth import AuthService
from models.auth import PasswordResetRequestModel
from models.auth import OAuth2EmailPasswordRequestForm
from services.token import RefreshTokenBearer


router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
async def sign_up(
        user_data: UserRegistration,
        service: AuthService = Depends(),
):
    return await service.register(user_data)


@router.post('/sign-in', response_model=Token)
async def sign_in(
        form_data: Annotated[OAuth2EmailPasswordRequestForm, Depends()],
        service: AuthService = Depends(),
) -> Token:
    return await service.authenticate_user(form_data.email, form_data.password, form_data.code)


@router.post('/password-reset-request')
async def password_reset_request(
        email_data:PasswordResetRequestModel,
        service: AuthService = Depends(),
):
    return await service.password_reset_request(email_data)


@router.post('/reset-password/{token}')
async def reset_password(
        token,
        password: PasswordResetConfirmModel,
        service: AuthService = Depends(),
):
    return await service.reset_password(token, password)


@router.get("/email-confirm")
async def email_confirm(
        token,
        service: AuthService = Depends(),
):
    return await service.verify_user_account(token)


@router.get("/refresh_token")
async def get_new_refresh_token(
        token_detail: dict = Depends(RefreshTokenBearer()),
        service: AuthService = Depends(),
):

    return await service.get_new_refresh_token(token_detail)


