#!/usr/bin/env python3
"""
Portable runner for the FastAPI 3FA application.
It installs missing requirements when possible, ensures local secrets exist,
and starts the app with safe local-development defaults.
"""

import os
import secrets
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault("FASTAPI_ENV", "development")
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("PORT", "8000")
os.environ.setdefault("RELOAD", "false")


def ensure_secret(name: str, length: int = 48) -> str:
    value = os.environ.get(name)
    if value:
        return value
    generated = secrets.token_urlsafe(length)
    os.environ[name] = generated
    return generated


def install_requirements() -> bool:
    requirements = BASE_DIR / "requirements.txt"
    try:
      subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements)])
      return True
    except subprocess.CalledProcessError:
      print("Failed to install requirements automatically.")
      print(f"Run manually: {sys.executable} -m pip install -r requirements.txt")
      return False


def dependencies_ready() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        import numpy  # noqa: F401
        import cv2  # noqa: F401
        import pyotp  # noqa: F401
        return True
    except ImportError:
        return False


def main():
    ensure_secret("SECRET_KEY")

    if not dependencies_ready():
        print("Installing missing dependencies from requirements.txt ...")
        if not install_requirements():
            sys.exit(1)

    from app import app, FACE_AVAILABLE  # noqa: WPS433
    import uvicorn  # noqa: WPS433

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    reload_enabled = os.environ.get("RELOAD", "false").lower() == "true"

    print("3FA FastAPI application loaded successfully")
    print(f"Face recognition available: {FACE_AVAILABLE}")
    print(f"Open: http://localhost:{port}")

    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=reload_enabled,
        log_level="info",
    )


if __name__ == "__main__":
    main()
