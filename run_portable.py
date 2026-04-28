#!/usr/bin/env python3
"""
Cross-platform launcher for the FastAPI 3FA application.
Run with: python run_portable.py
"""

import importlib.util
import os
import secrets
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS = BASE_DIR / "requirements.txt"
SECRET_FILE = BASE_DIR / "secret.key"
ENCRYPTION_FILE = BASE_DIR / "encryption.key"


def ensure_text_secret(path: Path, env_name: str, length: int = 48) -> None:
    if os.environ.get(env_name):
        return
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return
    path.write_text(secrets.token_urlsafe(length), encoding="utf-8")


def ensure_fernet_secret(path: Path, env_name: str) -> None:
    if os.environ.get(env_name):
        return
    if path.exists() and path.read_bytes().strip():
        return
    from cryptography.fernet import Fernet
    path.write_bytes(Fernet.generate_key())


def module_exists(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def install_requirements() -> None:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)])


def ensure_dependencies() -> None:
    required_modules = ("fastapi", "uvicorn", "pyotp", "fido2", "cryptography")
    if all(module_exists(module) for module in required_modules):
        return
    print("Installing missing dependencies from requirements.txt ...")
    install_requirements()


def main() -> None:
    os.chdir(BASE_DIR)
    sys.path.insert(0, str(BASE_DIR))

    os.environ.setdefault("FASTAPI_ENV", "development")
    os.environ.setdefault("HOST", "127.0.0.1")
    os.environ.setdefault("PORT", "8000")
    os.environ.setdefault("RELOAD", "false")

    ensure_dependencies()
    ensure_text_secret(SECRET_FILE, "SECRET_KEY")
    ensure_fernet_secret(ENCRYPTION_FILE, "ENCRYPTION_KEY")

    import uvicorn

    host = os.environ["HOST"]
    port = int(os.environ["PORT"])
    reload_enabled = os.environ.get("RELOAD", "false").strip().lower() in {"1", "true", "yes", "on"}

    print("3FA application loaded")
    print(f"Open: http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}")

    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=reload_enabled,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
