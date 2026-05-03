"""
FastAPI-based 3FA (Three-Factor Authentication) System.
"""

import os
import secrets
import logging
import base64
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
from typing import Dict, Any
import pyotp
import qrcode
from fido2 import cbor
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.server import Fido2Server
from io import BytesIO
from cryptography.fernet import Fernet, InvalidToken


from data_manager import *
from utils import *
from config import config
from exceptions import *
from validators import *
from validators import rate_limit

# Pydantic models for JSON requests
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    enable_totp: bool = False
    enable_fido: bool = False
    enable_biometric: bool = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get configuration
config_name = os.environ.get('FASTAPI_ENV') or 'default'
cfg = config[config_name]
cfg.init_app(None)

# Global variables
ADMIN_USERNAME = cfg.ADMIN_USERNAME
ADMIN_PASSWORD = cfg.ADMIN_PASSWORD

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting FastAPI 3FA application...")
    yield
    # Shutdown
    logger.info("Shutting down FastAPI 3FA application...")

# Create FastAPI app
app = FastAPI(
    title=cfg.APP_NAME,
    description="Modern three-factor authentication with password, TOTP, and FIDO2",
    version="2.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.ALLOWED_HOSTS)


@app.middleware("http")
async def encrypted_session_middleware(request: Request, call_next):
    cookie_value = request.cookies.get(cfg.SESSION_COOKIE_NAME)
    session_data = {}

    if cookie_value:
        try:
            decrypted = Fernet(cfg.SESSION_ENCRYPTION_KEY).decrypt(cookie_value.encode("ascii"))
            session_data = json.loads(decrypted.decode("utf-8"))
        except (InvalidToken, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            session_data = {}

    request.scope["session"] = session_data
    response = await call_next(request)

    if request.session:
        encrypted = Fernet(cfg.SESSION_ENCRYPTION_KEY).encrypt(
            json.dumps(request.session, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        response.set_cookie(
            cfg.SESSION_COOKIE_NAME,
            encrypted,
            max_age=cfg.SESSION_MAX_AGE,
            httponly=True,
            secure=cfg.SESSION_HTTPS_ONLY,
            samesite=cfg.SESSION_SAME_SITE,
        )
    elif cookie_value:
        response.delete_cookie(
            cfg.SESSION_COOKIE_NAME,
            httponly=True,
            secure=cfg.SESSION_HTTPS_ONLY,
            samesite=cfg.SESSION_SAME_SITE,
        )

    return response


def template_context(request: Request) -> Dict[str, Any]:
    return {
        "request": request,
        "app_name": cfg.APP_NAME,
        "csrf_token": get_or_create_csrf_token(request),
    }

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates", context_processors=[template_context])

# Dependency to check if user is logged in
def get_current_user(request: Request):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return username

# Dependency to check if user is admin
def get_current_admin(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return True


def get_post_auth_redirect(request: Request) -> str:
    auth_methods = set(request.session.get("auth_methods", []))
    return "/auth/success" if len(auth_methods) >= 3 else "/dashboard"


def mark_auth_method(request: Request, method: str):
    current_methods = set(request.session.get("auth_methods", []))
    current_methods.add(method)
    request.session["auth_methods"] = sorted(current_methods)


def get_auth_progress(request: Request, username: str) -> Dict[str, Any]:
    auth_methods = set(request.session.get("auth_methods", []))
    user = get_user_by_username(username)
    has_totp = bool(user and get_totp_secret(username))
    has_fido = bool(user and get_fido_credentials(username))

    return {
        "methods": sorted(auth_methods),
        "count": len(auth_methods),
        "is_complete": len(auth_methods) >= 3,
        "has_totp": has_totp,
        "has_fido": has_fido,
    }


def render_page(request: Request, template: str, **context):
    return templates.TemplateResponse(template, {"request": request, **context})


async def request_payload(request: Request) -> Dict[str, Any]:
    try:
        data = await request.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return dict(await request.form())


def reset_session(request: Request, **values):
    request.session.clear()
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    request.session.update(values)


def request_audit_context(request: Request) -> Dict[str, Any]:
    return {
        "ip_address": getattr(getattr(request, "client", None), "host", None),
        "user_agent": request.headers.get("user-agent"),
    }


def get_authenticator_preference(request: Request) -> str:
    preference = (request.session.get("authenticator_preference") or "auto").strip().lower()
    if preference in {"security_key", "biometric", "auto"}:
        return preference
    return "auto"


def get_request_hostname(request: Request) -> str:
    return (request.url.hostname or request.headers.get("host", "").split(":")[0] or "").strip().lower()


def get_canonical_local_url(request: Request) -> str | None:
    host = get_request_hostname(request)
    if host not in {"127.0.0.1", "0.0.0.0"}:
        return None
    port = request.url.port
    canonical = request.url.replace(
        netloc=f"localhost:{port}" if port else "localhost"
    )
    return str(canonical)

# FIDO2 server setup
def get_fido_server(request: Request):
    host = get_request_hostname(request)
    rp_id = cfg.FIDO_RP_ID or (
        "localhost" if host in {"", "localhost", "127.0.0.1", "0.0.0.0"} else host
    )
    if "." not in rp_id and rp_id != "localhost":
        rp_id = "localhost"
    logger.info(f"FIDO2 rp.id used: {rp_id}")
    rp = PublicKeyCredentialRpEntity(id=rp_id, name="3FA Demo")
    return Fido2Server(rp)


def as_bool(value):
    """Normalize HTML form checkbox values and JSON booleans."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "on", "yes"}


def to_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url for WebAuthn payloads."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def get_or_create_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


async def verify_csrf(request: Request):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return

    expected = get_or_create_csrf_token(request)
    provided = request.headers.get("X-CSRF-Token")

    if not provided:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                payload = await request.json()
                provided = payload.get("csrf_token")
            except Exception:
                provided = None
        else:
            try:
                form = await request.form()
                provided = form.get("csrf_token")
            except Exception:
                provided = None

    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    canonical_local_url = get_canonical_local_url(request)
    if canonical_local_url and request.method in {"GET", "HEAD"} and request.url.path != "/health":
        return RedirectResponse(url=canonical_local_url, status_code=307)

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max(cfg.MAX_UPLOAD_BYTES, 6_000_000):
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Invalid content length"}, status_code=400)

    response = await call_next(request)
    csp = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "media-src 'self' blob:;"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response

# Routes
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root route: redirect to login or dashboard if logged in."""
    if request.session.get("username"):
        return RedirectResponse(url=get_post_auth_redirect(request), status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/health")
async def health():
    return {"status": "ok", "app": cfg.APP_NAME}


async def read_request_value(request: Request, field: str) -> Any:
    return (await request_payload(request)).get(field)


def verify_totp_submission(request: Request, username: str, code: str) -> Dict[str, Any]:
    if not code or len(code) != 6:
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    totp_secret = get_totp_secret(username)
    if not totp_secret:
        raise HTTPException(status_code=400, detail="TOTP not initialized")

    if not pyotp.TOTP(totp_secret).verify(code):
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    request.session["totp_verified"] = True
    mark_auth_method(request, "totp")
    return {
        "success": True,
        "message": "TOTP verified",
        "redirect": get_post_auth_redirect(request),
    }

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return render_page(request, "login.html")

@app.post("/login")
@rate_limit(max_calls=5, time_window=300)  # 5 attempts per 5 minutes
async def login(request: Request, csrf: None = Depends(verify_csrf)):
    """Handle login."""
    data = await request_payload(request)
    username = data.get("username")
    password = data.get("password")
    audit_context = request_audit_context(request)

    try:
        username = validate_username(username)
        password = validate_login_password(password)

        recent_failures = get_failed_login_attempts(username, time_window_minutes=15)
        if len(recent_failures) >= 5:
            return RedirectResponse(url="/login?error=too_many_attempts", status_code=302)

        user_id = get_user_id_by_username(username)
        if not user_id:
            log_audit_event(
                None,
                "login_failed",
                f"Unknown user login attempt for {username}",
                success=False,
                **audit_context,
            )
            raise UserNotFoundError(username)

        if not verify_password(username, password):
            log_audit_event(
                user_id,
                "login_failed",
                "Invalid password",
                success=False,
                **audit_context,
            )
            raise InvalidPasswordError()

        reset_session(request, username=username, user_id=user_id)
        mark_auth_method(request, "password")
        log_audit_event(
            user_id,
            "login_success",
            "User logged in successfully",
            success=True,
            **audit_context,
        )

        return RedirectResponse(url=get_post_auth_redirect(request), status_code=302)

    except HTTPException:
        # Redirect back to login with error
        return RedirectResponse(url="/login?error=invalid_credentials", status_code=302)
    except Exception as e:
        logger.exception("Login failed")
        return RedirectResponse(url="/login?error=server_error", status_code=302)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page."""
    return render_page(request, "register.html")

@app.post("/register")
@rate_limit(max_calls=10, time_window=3600)  # 10 registrations per hour for testing
async def register(request: Request, csrf: None = Depends(verify_csrf)):
    """Handle user registration."""
    data = await request_payload(request)
    username = data.get("username")
    password = data.get("password")
    confirm_password = data.get("confirm_password")
    enable_totp = data.get("enable_totp", False)
    enable_fido = data.get("enable_fido", False)
    enable_biometric = data.get("enable_biometric", False)

    enable_totp = as_bool(enable_totp)
    enable_fido = as_bool(enable_fido)
    enable_biometric = as_bool(enable_biometric)

    username = (username or "").strip()
    password = password or ""
    confirm_password = confirm_password or ""

    # Validation
    if not username or not password:
        return RedirectResponse(url="/register?error=username_password_required", status_code=302)
    if password != confirm_password:
        return RedirectResponse(url="/register?error=passwords_dont_match", status_code=302)

    try:
        username = validate_username(username)
        password = validate_password(password)
    except HTTPException as exc:
        error_map = {
            "Username must be at least 3 characters long": "username_too_short",
            "Password must be at least 8 characters long": "password_too_short",
            "Username contains invalid characters": "invalid_username",
            "Password must contain at least one uppercase letter": "password_complexity",
            "Password must contain at least one lowercase letter": "password_complexity",
            "Password must contain at least one digit": "password_complexity",
        }
        return RedirectResponse(
            url=f"/register?error={error_map.get(exc.detail, 'invalid_input')}",
            status_code=302
        )

    # Enforce password + TOTP + one WebAuthn authenticator path.
    if not enable_totp or (not enable_fido and not enable_biometric):
        return RedirectResponse(url="/register?error=select_required_methods", status_code=302)

    # Check if user exists
    try:
        existing = get_user_id_by_username(username)
        if existing:
            return RedirectResponse(url="/register?error=username_exists", status_code=302)
    except Exception:
        pass

    # Generate TOTP secret if enabled
    totp_secret = pyotp.random_base32() if enable_totp else None

    # Create user
    try:
        uid = create_user(username, password, totp_secret)
        logger.info(f"Created user: {username} (id={uid})")
    except Exception as e:
        logger.exception(f"create_user failed for {username}")
        return RedirectResponse(url="/register?error=account_creation_failed", status_code=302)

    reset_session(
        request,
        username=username,
        user_id=uid,
        authenticator_preference=(
            "auto" if enable_fido and enable_biometric
            else "biometric" if enable_biometric
            else "security_key"
        ),
    )
    mark_auth_method(request, "password")

    return RedirectResponse(url="/totp_setup", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, username: str = Depends(get_current_user)):
    """Dashboard page."""
    return render_page(
        request,
        "dashboard.html",
        username=username,
        auth_progress=get_auth_progress(request, username),
    )


@app.get("/auth/success", response_class=HTMLResponse)
async def auth_success_page(request: Request, username: str = Depends(get_current_user)):
    auth_progress = get_auth_progress(request, username)
    if not auth_progress["is_complete"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    return render_page(request, "auth_success.html", username=username, auth_progress=auth_progress)

@app.post("/logout")
async def logout(request: Request, csrf: None = Depends(verify_csrf)):
    """Logout the user."""
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@app.get("/totp_setup", response_class=HTMLResponse)
async def totp_setup_page(request: Request, username: str = Depends(get_current_user)):
    """TOTP setup page."""
    totp_secret = get_totp_secret(username)
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        set_totp_secret(username, totp_secret)

    # Generate QR code
    totp = pyotp.TOTP(totp_secret)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp.provisioning_uri(name=username, issuer_name="3FA"))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_page(request, "totp_setup.html", qr_image=qr_b64, secret=totp_secret)

@app.post("/totp_setup")
async def totp_setup_verify(
    request: Request,
    username: str = Depends(get_current_user),
    csrf: None = Depends(verify_csrf)
):
    """Verify TOTP code during setup."""
    return verify_totp_submission(request, username, await read_request_value(request, "code"))

@app.post("/totp_verify")
async def totp_verify(
    request: Request,
    code: str = Form(...),
    username: str = Depends(get_current_user),
    csrf: None = Depends(verify_csrf)
):
    """Verify TOTP code."""
    return verify_totp_submission(request, username, code)

@app.get("/fido_register", response_class=HTMLResponse)
async def fido_register_page(request: Request, username: str = Depends(get_current_user)):
    """FIDO2 registration page."""
    user = PublicKeyCredentialUserEntity(
        id=username.encode(),
        name=username,
        display_name=username
    )

    fido_server = get_fido_server(request)
    options, state = fido_server.register_begin(user, [])
    request.session["fido_state"] = state
    authenticator_preference = get_authenticator_preference(request)
    attachment = {"security_key": "cross-platform", "biometric": "platform"}.get(authenticator_preference)

    options_dict = {
        "publicKey": {
            "challenge": to_base64url(options.public_key.challenge),
            "rp": {
                "id": options.public_key.rp.id,
                "name": options.public_key.rp.name
            },
            "user": {
                "id": to_base64url(options.public_key.user.id),
                "name": options.public_key.user.name,
                "displayName": options.public_key.user.display_name
            },
            "pubKeyCredParams": [
                {"alg": param.alg, "type": param.type}
                for param in options.public_key.pub_key_cred_params
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": attachment,
                "requireResidentKey": getattr(options.public_key.authenticator_selection, 'require_resident_key', False),
                "userVerification": getattr(options.public_key.authenticator_selection, 'user_verification', 'preferred')
            } if options.public_key.authenticator_selection else None,
            "timeout": getattr(options.public_key, 'timeout', 60000),
            "attestation": getattr(options.public_key, 'attestation', 'none')
        },
        "authenticatorPreference": authenticator_preference,
    }

    return render_page(request, "fido_register.html", username=username, options=options_dict)

@app.post("/fido_register")
async def fido_register(
    request: Request,
    username: str = Depends(get_current_user),
    csrf: None = Depends(verify_csrf)
):
    """Complete FIDO2 registration."""
    try:
        data = await request.json()
    except Exception:
        form_data = await request_payload(request)
        data = {
            "id": form_data.get("id"),
            "rawId": form_data.get("rawId"),
            "type": form_data.get("type"),
            "response": {
                "attestationObject": form_data.get("attestationObject"),
                "clientDataJSON": form_data.get("clientDataJSON")
            }
        }

    if not data or not data.get("id") or not data.get("rawId") or not data.get("response"):
        raise HTTPException(status_code=400, detail="Missing FIDO2 registration payload")

    fido_server = get_fido_server(request)
    state = request.session.get("fido_state")
    if not state:
        raise HTTPException(status_code=400, detail="Registration state missing")

    try:
        auth_data = fido_server.register_complete(state, data)
    except Exception as exc:
        logger.exception("FIDO2 registration failed")
        raise HTTPException(status_code=400, detail=f"FIDO2 registration failed: {exc}")

    credential_data = auth_data.credential_data
    if credential_data is None:
        raise HTTPException(status_code=400, detail="FIDO2 credential data missing")

    credential_data = {
        "credential_id": to_base64url(credential_data.credential_id),
        "public_key": to_base64url(cbor.encode(credential_data.public_key)),
        "sign_count": auth_data.counter
    }

    set_fido_credentials(username, json.dumps(credential_data))

    request.session.pop("fido_state", None)
    request.session.pop("authenticator_preference", None)
    mark_auth_method(request, "fido")
    return {
        "success": True,
        "message": "FIDO2 key registered",
        "redirect": get_post_auth_redirect(request),
    }

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """Admin login page."""
    return render_page(request, "admin_login.html")

@app.post("/admin/login")
async def admin_login(request: Request, csrf: None = Depends(verify_csrf)):
    """Handle admin login."""
    data = await request_payload(request)
    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        reset_session(request, admin=True)
        return {"success": True, "next": "/admin"}
    raise HTTPException(status_code=401, detail="Invalid admin credentials")

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin: bool = Depends(get_current_admin)):
    """Admin dashboard."""
    conn = get_db()
    users = conn.execute("SELECT id, username FROM users ORDER BY id").fetchall()
    conn.close()
    return render_page(request, "admin_dashboard.html", users=users, user_count=len(users))

@app.post("/admin/delete_user")
async def admin_delete_user(
    request: Request,
    user_id: int = Form(...),
    admin: bool = Depends(get_current_admin),
    csrf: None = Depends(verify_csrf)
):
    """Delete user (admin only)."""
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)

@app.post("/admin/reset_password")
async def admin_reset_password(
    request: Request,
    admin: bool = Depends(get_current_admin),
    csrf: None = Depends(verify_csrf)
):
    """Reset user password."""
    user_id = (await request_payload(request)).get("user_id")

    new_password = f"Tmp-{secrets.token_urlsafe(9)}A1"
    from werkzeug.security import generate_password_hash
    hashed = generate_password_hash(new_password)
    conn = get_db()
    conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()
    if request.headers.get("content-type", "").startswith("application/json"):
        return {"success": True, "temporary_password": new_password}
    return RedirectResponse(
        url=f"/admin?reset_password={new_password}&reset_user={user_id}",
        status_code=302
    )

@app.post("/admin/logout")
async def admin_logout(request: Request, csrf: None = Depends(verify_csrf)):
    """Logout admin."""
    request.session.pop("admin", None)
    return RedirectResponse(url="/admin/login", status_code=302)

if __name__ == "__main__":
    import subprocess
    import sys

    # Try to run with uvicorn first
    try:
        import uvicorn
        uvicorn.run(
            "app:app",
            host="127.0.0.1",
            port=8000,
            reload=True,
            log_level="info"
        )
    except ImportError:
        # Fallback to using subprocess with uvicorn command
        try:
            subprocess.run([
                sys.executable, "-m", "uvicorn",
                "app:app",
                "--host", "127.0.0.1",
                "--port", "8000",
                "--reload",
                "--log-level", "info"
            ], check=True)
        except subprocess.CalledProcessError:
            print("Error: Could not start server. Please install uvicorn:")
            print("pip install uvicorn")
            print("Then run: uvicorn app:app --reload")
            sys.exit(1)
