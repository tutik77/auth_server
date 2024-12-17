from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    test_database_url: str
    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expiration: int = 3600
    jwt_issuer: str
    refresh_token_expire: int = 7# неделя
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_FROM_NAME: str
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = True
    OWNER_PASSWORD: str
    TOTP_SECRET: str
    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'

settings = Settings(

)