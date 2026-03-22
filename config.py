import os
from datetime import timedelta


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str) -> list[str]:
    value = os.environ.get(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


class Config:
    """Application configuration for FastAPI."""

    BASE_DIR = os.path.dirname(__file__)

    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "users.db")

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME") or "admin"
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "letmein1234"

    FACE_TOLERANCE = float(os.environ.get("FACE_TOLERANCE") or 0.6)
    CAPTURE_DIR = os.path.join(BASE_DIR, "captured")
    MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES") or 5_000_000)
    MAX_IMAGE_DIMENSION = int(os.environ.get("MAX_IMAGE_DIMENSION") or 4096)

    OTP_TTL = timedelta(minutes=int(os.environ.get("OTP_TTL_MINUTES") or 5))

    LOG_LEVEL = os.environ.get("LOG_LEVEL") or "INFO"
    LOG_FILE = os.path.join(BASE_DIR, "3fa.log")

    HOST = os.environ.get("HOST") or "127.0.0.1"
    PORT = int(os.environ.get("PORT") or 8000)
    DEBUG = env_bool("DEBUG", False)

    FIDO_RP_ID = os.environ.get("FIDO_RP_ID") or None
    APP_NAME = os.environ.get("APP_NAME") or "3FA Authentication System"

    RATE_LIMIT_LOGIN = int(os.environ.get("RATE_LIMIT_LOGIN") or 5)
    RATE_LIMIT_REGISTER = int(os.environ.get("RATE_LIMIT_REGISTER") or 10)

    ALLOWED_HOSTS = env_list(
        "ALLOWED_HOSTS",
        "localhost,127.0.0.1,0.0.0.0,testserver"
    )
    CORS_ORIGINS = env_list(
        "CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000"
    )
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME") or "threefa_session"
    SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE") or 3600)
    SESSION_SAME_SITE = os.environ.get("SESSION_SAME_SITE") or "lax"
    SESSION_HTTPS_ONLY = env_bool("SESSION_HTTPS_ONLY", False)

    @classmethod
    def init_app(cls, app):
        os.makedirs(os.path.dirname(cls.DATABASE_PATH), exist_ok=True)
        os.makedirs(cls.CAPTURE_DIR, exist_ok=True)

        import logging
        from logging.handlers import RotatingFileHandler

        logger = logging.getLogger("3fa")
        if not logger.handlers:
            file_handler = RotatingFileHandler(
                cls.LOG_FILE,
                maxBytes=2 * 1024 * 1024,
                backupCount=2,
            )
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            )
            file_handler.setLevel(getattr(logging, cls.LOG_LEVEL.upper()))
            logger.addHandler(file_handler)
            logger.setLevel(getattr(logging, cls.LOG_LEVEL.upper()))


class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    DEBUG = False
    LOG_LEVEL = "WARNING"
    SESSION_HTTPS_ONLY = True
    SESSION_SAME_SITE = "lax"
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        try:
            with open("secret.key", "r", encoding="utf-8") as f:
                SECRET_KEY = f.read().strip()
        except FileNotFoundError:
            raise ValueError(
                "SECRET_KEY environment variable must be set in production or secret.key file must exist"
            )


class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = ":memory:"


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
