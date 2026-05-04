"""
FastAPI-based 3FA (Three-Factor Authentication) System.
"""

import os
import secrets
import logging
import base64
import json
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
config_name = os.environ.get('FASTAPI_ENV') or 'default'
cfg = config[config_name]
cfg.init_app(None)
ADMIN_USERNAME = cfg.ADMIN_USERNAME
ADMIN_PASSWORD = cfg.ADMIN_PASSWORD

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting FastAPI 3FA application...")
    yield
    logger.info("Shutting down FastAPI 3FA application...")

app = FastAPI(title=cfg.APP_NAME, description="Modern three-factor authentication with password, TOTP, and FIDO2", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=cfg.CORS_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-CSRF-Token"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.ALLOWED_HOSTS)


@app.middleware("http")
async def encrypted_session_middleware(request: Request, call_next):
    cookie_value = request.cookies.get(cfg.SESSION_COOKIE_NAME)
    session_data = {}

    if cookie_value:
        try:
            decrypted = decrypt_text(cookie_value)
            session_data = json.loads(decrypted)
        except (InvalidToken, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            try:
                decrypted = Fernet(cfg.SESSION_ENCRYPTION_KEY).decrypt(cookie_value.encode("ascii"))
                session_data = json.loads(decrypted.decode("utf-8"))
            except (InvalidToken, ValueError, json.JSONDecodeError, UnicodeDecodeError):
                session_data = {}

    request.scope["session"] = session_data
    response = await call_next(request)

    if request.session:
        encrypted = encrypt_text(json.dumps(request.session, separators=(",", ":")))
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

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates", context_processors=[template_context])

def get_current_user(request: Request):
    if not (username := request.session.get("username")):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return username

def get_current_admin(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return True


def get_post_auth_redirect(request: Request) -> str:
    username = request.session.get("username")
    if username:
        try:
            progress = get_auth_progress(request, username)
            if not progress.get("is_complete"):
                return "/settings"
        except Exception:
            pass
    return "/inventory"


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
            return sanitize_payload(data)
    except Exception:
        pass
    return sanitize_payload(dict(await request.form()))


def sanitize_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_text(value, strip=key not in {"password", "confirm_password"})
        else:
            sanitized[key] = value
    return sanitized


def wants_json(request: Request) -> bool:
    return "application/json" in (request.headers.get("content-type", "") + request.headers.get("accept", ""))


def login_error_response(request: Request, error: str = "invalid_credentials", status_code: int = 401):
    request.session.clear()
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    if wants_json(request):
        return JSONResponse({"success": False, "error": error}, status_code=status_code)
    return RedirectResponse(url=f"/login?error={error}", status_code=302)


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
    return (request.url.hostname or request.headers.get("host", "").split(":")[0] or "").lower().strip()


def get_canonical_local_url(request: Request) -> str | None:
    host = get_request_hostname(request)
    if host not in {"127.0.0.1", "0.0.0.0"}:
        return None
    port = request.url.port
    canonical = request.url.replace(
        netloc=f"localhost:{port}" if port else "localhost"
    )
    return str(canonical)

def get_fido_server(request: Request):
    host = get_request_hostname(request)
    rp_id = cfg.FIDO_RP_ID or ("localhost" if host in {"", "localhost", "127.0.0.1", "0.0.0.0"} else host)
    if "." not in rp_id and rp_id != "localhost": rp_id = "localhost"
    logger.info(f"FIDO2 rp.id used: {rp_id}")
    return Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name="3FA Demo"))


def as_bool(value):
    """Normalize HTML form checkbox values and JSON booleans."""
    return value if isinstance(value, bool) else (False if value is None else str(value).strip().lower() in {"1", "true", "on", "yes"})


def to_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url for WebAuthn payloads."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def get_or_create_csrf_token(request: Request) -> str:
    if not (token := request.session.get("csrf_token")):
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

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse(url=get_post_auth_redirect(request) if request.session.get("username") else "/login", status_code=302)


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
        raise HTTPException(status_code=401, detail="Incorrect OTP")

    request.session["totp_verified"] = True
    mark_auth_method(request, "totp")
    return {
        "success": True,
        "message": "TOTP verified",
        "redirect": "/settings",
    }


def create_registration_user(username: str, password: str, totp_secret: str | None) -> int:
    """Create a user, repairing stale local DB schema before giving up."""
    try:
        uid = create_user(username, password, totp_secret)
        if uid:
            return int(uid)
    except UserAlreadyExistsError:
        raise
    except Exception:
        logger.exception("Primary create_user path failed; retrying after DB initialization")

    try:
        init_db()
        if get_user_id_by_username(username):
            raise UserAlreadyExistsError(username)
    except UserAlreadyExistsError:
        raise
    except Exception:
        logger.exception("DB initialization failed during registration recovery; continuing to direct insert fallback")

    try:
        uid = create_user(username, password, totp_secret)
        if uid:
            return int(uid)
    except UserAlreadyExistsError:
        raise
    except Exception:
        logger.exception("create_user retry failed; using direct registration insert fallback")

    conn = get_db()
    try:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        for column, definition in {
            "username_hash": "TEXT",
            "username_encrypted": "TEXT",
        }.items():
            if column not in columns:
                conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
                columns.add(column)

        lookup = username_lookup(username)
        if conn.execute("SELECT id FROM users WHERE username_hash = ?", (lookup,)).fetchone():
            raise UserAlreadyExistsError(username)

        encrypted_totp_secret = encrypt_text(totp_secret) if totp_secret else None
        if "username" in columns:
            conn.execute(
                '''INSERT INTO users (username, username_hash, username_encrypted, password, totp_secret)
                   VALUES (?, ?, ?, ?, ?)''',
                (lookup, lookup, encrypt_text(username), hash_password(password), encrypted_totp_secret),
            )
        else:
            conn.execute(
                '''INSERT INTO users (username_hash, username_encrypted, password, totp_secret)
                   VALUES (?, ?, ?, ?)''',
                (lookup, encrypt_text(username), hash_password(password), encrypted_totp_secret),
            )
        conn.commit()
        row = conn.execute("SELECT id FROM users WHERE username_hash = ?", (lookup,)).fetchone()
        if not row:
            raise RuntimeError("Registration insert completed but user id was not found")
        return int(row["id"])
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        if "UNIQUE" in str(exc).upper():
            raise UserAlreadyExistsError(username) from exc
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return render_page(request, "login.html")

@app.post("/login")
@rate_limit(max_calls=5, time_window=300)
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
            return login_error_response(request, "too_many_attempts", 429)

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

        redirect = get_post_auth_redirect(request)
        if wants_json(request):
            return {"success": True, "redirect": redirect}
        return RedirectResponse(url=redirect, status_code=302)

    except HTTPException:
        return login_error_response(request)
    except Exception as e:
        logger.exception("Login failed")
        return login_error_response(request, "server_error", 500)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return render_page(request, "register.html")

@app.post("/register")
@rate_limit(max_calls=10, time_window=3600)
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

    if not enable_totp or (not enable_fido and not enable_biometric):
        return RedirectResponse(url="/register?error=select_required_methods", status_code=302)
    try:
        if get_user_id_by_username(username):
            return RedirectResponse(url="/register?error=username_exists", status_code=302)
    except Exception:
        logger.exception("Username existence check failed; retrying after DB initialization")
        try:
            init_db()
            if get_user_id_by_username(username):
                return RedirectResponse(url="/register?error=username_exists", status_code=302)
        except Exception:
            logger.exception("Username existence check failed after DB initialization; continuing to create fallback")

    totp_secret = pyotp.random_base32() if enable_totp else None
    try:
        uid = create_registration_user(username, password, totp_secret)
        logger.info(f"Created user: {username} (id={uid})")
    except UserAlreadyExistsError:
        return RedirectResponse(url="/register?error=username_exists", status_code=302)
    except Exception as e:
        logger.exception(f"create_user failed for {username}")
        return RedirectResponse(url="/register?error=account_creation_failed", status_code=302)

    reset_session(request, username=username, user_id=uid, registration_in_progress=True, authenticator_preference="auto" if enable_fido and enable_biometric else "biometric" if enable_biometric else "security_key")
    mark_auth_method(request, "password")
    return RedirectResponse(url="/registration/totp_setup", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, username: str = Depends(get_current_user)):
    if request.session.get("registration_in_progress"):
        return RedirectResponse(url="/registration/totp_setup", status_code=302)
    return render_page(request, "dashboard.html", username=username, auth_progress=get_auth_progress(request, username))


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, username: str = Depends(get_current_user)):
    return await dashboard(request, username)


@app.get("/auth/success", response_class=HTMLResponse)
async def auth_success_page(request: Request, username: str = Depends(get_current_user)):
    if request.session.get("registration_in_progress"):
        return RedirectResponse(url="/registration/totp_setup", status_code=302)
    auth_progress = get_auth_progress(request, username)
    if not auth_progress["is_complete"]:
        return RedirectResponse(url="/settings", status_code=302)
    user_id = int(request.session.get("user_id") or get_user_id_by_username(username))
    items = list_inventory_items(user_id)
    return render_page(request, "auth_success.html", username=username, auth_progress=auth_progress, items=items, item_count=len(items), total_quantity=sum(int(item["quantity"] or 0) for item in items), low_stock_count=sum(1 for item in items if int(item["quantity"] or 0) <= 5))


@app.get("/inventory", response_class=HTMLResponse)
async def inventory_page(request: Request, username: str = Depends(get_current_user)):
    if request.session.get("registration_in_progress"):
        return RedirectResponse(url="/registration/totp_setup", status_code=302)
    return await auth_success_page(request, username)


@app.post("/inventory/add")
async def inventory_add(
    request: Request,
    username: str = Depends(get_current_user),
    csrf: None = Depends(verify_csrf)
):
    if not get_auth_progress(request, username)["is_complete"]:
        return RedirectResponse(url="/settings", status_code=302)
    data = await request_payload(request)
    user_id = int(request.session.get("user_id") or get_user_id_by_username(username))
    try:
        create_inventory_item(
            user_id,
            validate_inventory_text(data.get("item_name"), "Item name", required=True),
            validate_inventory_text(data.get("sku"), "SKU"),
            validate_inventory_quantity(data.get("quantity")),
            validate_inventory_text(data.get("location"), "Location"),
            validate_inventory_status(data.get("status")),
            validate_inventory_text(data.get("notes"), "Notes", max_length=300),
        )
    except HTTPException:
        return RedirectResponse(url="/inventory?error=inventory_invalid", status_code=302)
    except Exception:
        logger.exception("Inventory add failed")
        return RedirectResponse(url="/inventory?error=inventory_failed", status_code=302)
    return RedirectResponse(url="/inventory?inventory_added=1", status_code=302)


@app.post("/inventory/update")
async def inventory_update(
    request: Request,
    username: str = Depends(get_current_user),
    csrf: None = Depends(verify_csrf)
):
    if not get_auth_progress(request, username)["is_complete"]:
        return RedirectResponse(url="/settings", status_code=302)
    data = await request_payload(request)
    user_id = int(request.session.get("user_id") or get_user_id_by_username(username))
    try:
        update_inventory_item(
            user_id,
            int(data.get("item_id")),
            validate_inventory_text(data.get("item_name"), "Item name", required=True),
            validate_inventory_text(data.get("sku"), "SKU"),
            validate_inventory_quantity(data.get("quantity")),
            validate_inventory_text(data.get("location"), "Location"),
            validate_inventory_status(data.get("status")),
            validate_inventory_text(data.get("notes"), "Notes", max_length=300),
        )
    except Exception:
        logger.exception("Inventory update failed")
        return RedirectResponse(url="/inventory?error=inventory_failed", status_code=302)
    return RedirectResponse(url="/inventory?inventory_updated=1", status_code=302)


@app.post("/inventory/delete")
async def inventory_delete(
    request: Request,
    username: str = Depends(get_current_user),
    csrf: None = Depends(verify_csrf)
):
    if not get_auth_progress(request, username)["is_complete"]:
        return RedirectResponse(url="/settings", status_code=302)
    data = await request_payload(request)
    user_id = int(request.session.get("user_id") or get_user_id_by_username(username))
    try:
        delete_inventory_item(user_id, int(data.get("item_id")))
    except Exception:
        logger.exception("Inventory delete failed")
        return RedirectResponse(url="/inventory?error=inventory_failed", status_code=302)
    return RedirectResponse(url="/inventory?inventory_deleted=1", status_code=302)

@app.post("/logout")
async def logout(request: Request, csrf: None = Depends(verify_csrf)):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@app.get("/totp_setup", response_class=HTMLResponse)
async def totp_setup_page(request: Request, username: str = Depends(get_current_user)):
    if not (totp_secret := get_totp_secret(username)):
        totp_secret = pyotp.random_base32()
        set_totp_secret(username, totp_secret)
    totp, qr = pyotp.TOTP(totp_secret), qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp.provisioning_uri(name=username, issuer_name="3FA"))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return render_page(request, "totp_setup.html", qr_image=base64.b64encode(buf.getvalue()).decode(), secret=totp_secret)

@app.post("/totp_setup")
async def totp_setup_verify(request: Request, username: str = Depends(get_current_user), csrf: None = Depends(verify_csrf)):
    return verify_totp_submission(request, username, await read_request_value(request, "code"))

@app.post("/totp_verify")
async def totp_verify(request: Request, code: str = Form(...), username: str = Depends(get_current_user), csrf: None = Depends(verify_csrf)):
    return verify_totp_submission(request, username, code)

@app.get("/fido_register", response_class=HTMLResponse)
async def fido_register_page(request: Request, username: str = Depends(get_current_user)):
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
async def fido_register(request: Request, username: str = Depends(get_current_user), csrf: None = Depends(verify_csrf)):
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
        "redirect": "/settings",
    }

def get_registration_user(request: Request):
    if not (username := request.session.get("username")) or not request.session.get("registration_in_progress"):
        raise HTTPException(status_code=403, detail="Not in registration flow")
    return username

@app.get("/registration/totp_setup", response_class=HTMLResponse)
async def registration_totp_setup_page(request: Request, username: str = Depends(get_registration_user)):
    if not (totp_secret := get_totp_secret(username)):
        totp_secret = pyotp.random_base32()
        set_totp_secret(username, totp_secret)
    totp, qr = pyotp.TOTP(totp_secret), qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp.provisioning_uri(name=username, issuer_name="3FA"))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return render_page(request, "totp_setup.html", qr_image=base64.b64encode(buf.getvalue()).decode(), secret=totp_secret, registration_flow=True)

@app.post("/registration/totp_setup")
async def registration_totp_setup_verify(request: Request, username: str = Depends(get_registration_user), csrf: None = Depends(verify_csrf)):
    code = await read_request_value(request, "code")
    
    if not code or len(code) != 6:
        if wants_json(request):
            return JSONResponse({"success": False, "error": "Invalid OTP code"}, status_code=400)
        return RedirectResponse(url="/registration/totp_setup?error=invalid_code", status_code=302)

    totp_secret = get_totp_secret(username)
    if not totp_secret:
        if wants_json(request):
            return JSONResponse({"success": False, "error": "TOTP not initialized"}, status_code=400)
        return RedirectResponse(url="/registration/totp_setup?error=totp_init_failed", status_code=302)

    if not pyotp.TOTP(totp_secret).verify(code):
        if wants_json(request):
            return JSONResponse({"success": False, "error": "Incorrect OTP"}, status_code=401)
        return RedirectResponse(url="/registration/totp_setup?error=incorrect_otp", status_code=302)

    request.session["totp_verified"] = True
    mark_auth_method(request, "totp")
    
    if wants_json(request):
        return {
            "success": True,
            "message": "TOTP verified. Proceeding to FIDO2 setup.",
            "redirect": "/registration/fido_setup",
        }
    return RedirectResponse(url="/registration/fido_setup", status_code=302)

@app.get("/registration/fido_setup", response_class=HTMLResponse)
async def registration_fido_setup_page(request: Request, username: str = Depends(get_registration_user)):
    if not request.session.get("totp_verified"):
        return RedirectResponse(url="/registration/totp_setup", status_code=302)
    
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

    return render_page(
        request, 
        "fido_register.html", 
        username=username, 
        options=options_dict,
        registration_flow=True
    )

@app.post("/registration/fido_setup")
async def registration_fido_setup_complete(request: Request, username: str = Depends(get_registration_user), csrf: None = Depends(verify_csrf)):
    if not request.session.get("totp_verified"):
        raise HTTPException(status_code=403, detail="TOTP verification required first")
    
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

    for key in ["fido_state", "authenticator_preference", "totp_verified", "registration_in_progress"]:
        request.session.pop(key, None)
    mark_auth_method(request, "fido")
    return {"success": True, "message": "3FA setup complete! You are now fully authenticated.", "redirect": "/inventory"}

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return render_page(request, "admin_login.html")

@app.post("/admin/login")
async def admin_login(request: Request, csrf: None = Depends(verify_csrf)):
    data = await request_payload(request)
    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        reset_session(request, admin=True)
        return {"success": True, "next": "/admin"}
    raise HTTPException(status_code=401, detail="Invalid admin credentials")

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin: bool = Depends(get_current_admin)):
    users = list_users_for_admin()
    return render_page(request, "admin_dashboard.html", users=users, user_count=len(users))


@app.post("/admin/create_user")
async def admin_create_user(
    request: Request,
    admin: bool = Depends(get_current_admin),
    csrf: None = Depends(verify_csrf)
):
    """Create a user from the admin dashboard."""
    data = await request_payload(request)
    username = data.get("username")
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    if password != confirm_password:
        return RedirectResponse(url="/admin?error=passwords_dont_match", status_code=302)

    try:
        username = validate_username(username)
        password = validate_password(password)
        create_user(username, password)
    except UserAlreadyExistsError:
        return RedirectResponse(url="/admin?error=username_exists", status_code=302)
    except HTTPException:
        return RedirectResponse(url="/admin?error=invalid_user_input", status_code=302)
    except Exception:
        logger.exception("Admin user creation failed")
        return RedirectResponse(url="/admin?error=user_create_failed", status_code=302)

    return RedirectResponse(url="/admin?created_user=1", status_code=302)


@app.post("/admin/update_user")
async def admin_update_user(
    request: Request,
    admin: bool = Depends(get_current_admin),
    csrf: None = Depends(verify_csrf)
):
    """Rename a user from the admin dashboard."""
    data = await request_payload(request)
    user_id = data.get("user_id")
    username = data.get("username")

    try:
        username = validate_username(username)
        update_username_by_id(int(user_id), username)
    except UserAlreadyExistsError:
        return RedirectResponse(url="/admin?error=username_exists", status_code=302)
    except Exception:
        logger.exception("Admin user update failed")
        return RedirectResponse(url="/admin?error=user_update_failed", status_code=302)

    return RedirectResponse(url="/admin?updated_user=1", status_code=302)


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


@app.post("/admin/reset_authenticators")
async def admin_reset_authenticators(
    request: Request,
    admin: bool = Depends(get_current_admin),
    csrf: None = Depends(verify_csrf)
):
    """Clear a user's enrolled TOTP and FIDO credentials."""
    user_id = (await request_payload(request)).get("user_id")

    try:
        reset_user_authenticators(int(user_id))
    except Exception:
        logger.exception("Admin authenticator reset failed")
        return RedirectResponse(url="/admin?error=auth_reset_failed", status_code=302)

    return RedirectResponse(url="/admin?auth_reset=1", status_code=302)


@app.post("/admin/reset_password")
async def admin_reset_password(
    request: Request,
    admin: bool = Depends(get_current_admin),
    csrf: None = Depends(verify_csrf)
):
    """Reset user password."""
    user_id = (await request_payload(request)).get("user_id")

    new_password = f"Tmp-{secrets.token_urlsafe(9)}A1"
    conn = get_db()
    conn.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(new_password), user_id))
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
