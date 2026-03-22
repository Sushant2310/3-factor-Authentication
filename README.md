# 3FA Authentication System

FastAPI-based three-factor authentication demo with password, TOTP, face verification, and FIDO2/WebAuthn enrollment.

## What is included

- OWASP-oriented baseline hardening:
  - CSRF protection on state-changing routes
  - restrictive security headers and trusted hosts
  - stricter session cookie defaults
  - reduced CORS surface
  - upload-size and image-dimension limits
  - failed-login tracking with temporary lockout
- Portable startup:
  - `run_portable.py` bootstraps local development
  - `.env.example` for environment-based configuration
  - Docker and Compose files for containerized runs
- Refreshed UI across the active pages

## Local run

1. Create a virtual environment.
2. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

3. Optional: copy `.env.example` to `.env` and set your values.
4. Start the app:

```powershell
python run_portable.py
```

Open [http://localhost:8000](http://localhost:8000).

Important for FIDO2/WebAuthn:
- Use `http://localhost:8000`
- Do not use `http://127.0.0.1:8000` for registration flows if the browser rejects the relying-party domain

## Docker

```powershell
docker compose up --build
```

Then open [http://localhost:8000](http://localhost:8000).

## Key environment variables

- `SECRET_KEY`: session signing secret
- `ENCRYPTION_KEY`: optional Fernet key for encrypted uploads
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `ALLOWED_HOSTS`
- `CORS_ORIGINS`
- `MAX_UPLOAD_BYTES`
- `SESSION_HTTPS_ONLY`

## Security notes

- Set real secrets before exposing the app outside local development.
- Use HTTPS in production.
- Keep biometric and encryption key files secure.
- Review admin credentials and allowed hosts before deployment.
