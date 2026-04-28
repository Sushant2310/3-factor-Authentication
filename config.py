import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet


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
    BASE_PATH = Path(__file__).resolve().parent

    @staticmethod
    def _read_or_create_text_secret(path: Path, generator) -> str:
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        value = generator()
        path.write_text(value, encoding="utf-8")
        return value

    @classmethod
    def _secret_key(cls) -> str:
        return os.environ.get("SECRET_KEY") or cls._read_or_create_text_secret(
            cls.BASE_PATH / "secret.key",
            lambda: secrets.token_urlsafe(48),
        )

    @classmethod
    def _fernet_key(cls) -> bytes:
        env_value = os.environ.get("ENCRYPTION_KEY")
        if env_value:
            return env_value.encode("ascii")
        key_path = cls.BASE_PATH / "encryption.key"
        if key_path.exists():
            return key_path.read_bytes().strip()
        generated = Fernet.generate_key()
        key_path.write_bytes(generated)
        return generated

    SECRET_KEY = None
    ENCRYPTION_KEY = None
    SESSION_ENCRYPTION_KEY = None
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "users.db")

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME") or "admin"
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "letmein1234"

    MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES") or 5_000_000)

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


class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = ":memory:"


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


for _config_class in {Config, DevelopmentConfig, ProductionConfig, TestingConfig}:
    if not getattr(_config_class, "SECRET_KEY", None):
        _config_class.SECRET_KEY = _config_class._secret_key()
    _config_class.ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    _config_class.SESSION_ENCRYPTION_KEY = _config_class._fernet_key()
