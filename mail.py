from fastapi_mail import FastMail, ConnectionConfig, MessageSchema, MessageType
from pathlib import Path

from settings import settings
from url_token import create_url_safe_token
from url_token import verify_token

BASE_DIR = Path(__file__).resolve().parent


mail_config = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=587,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)


mail = FastMail(config=mail_config)


def create_message(recipients: list[str], subject: str, body: str):

    message = MessageSchema(
        recipients=recipients,
        subject=subject,
        body=body,
        subtype=MessageType.html
    )
    return message


async def send_email(recipients: list[str], subject: str, body: str):
    message = create_message(recipients=recipients, subject=subject, body=body)
    await mail.send_message(message)


async def send_email_to_confirm(email):
    token = create_url_safe_token({"email": email})
    verify_token(token, expires_in=900)  # 15 min
    link = f"http://127.0.0.1:8000/auth/email-confirm?token={token}"
    html_message = f'Инструкция для подтверждения почты: <p>{link}</p>'
    subject = "Email Confirm Instructions"
    await send_email([email], subject, html_message)