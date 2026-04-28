# Platform Runbook

## Goal

Run the same 3FA web app on Windows, macOS, Linux, Docker, or a hosted VM without code changes.

## Local Run

Windows:

```powershell
python -m pip install -r requirements.txt
python run_portable.py
```

macOS or Linux:

```bash
python3 -m pip install -r requirements.txt
python3 run_portable.py
```

The app opens at `http://127.0.0.1:8000` by default. Override with `HOST` and `PORT`.

## Docker Run

```bash
docker compose up --build
```

## Required Production Settings

- Set `FASTAPI_ENV=production`.
- Set a strong `SECRET_KEY`.
- Set a Fernet `ENCRYPTION_KEY`.
- Set strong `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
- Set `SESSION_HTTPS_ONLY=true` behind HTTPS.
- Set `ALLOWED_HOSTS` to real hostnames only.
- Set `CORS_ORIGINS` to trusted origins only.
- Keep `secret.key`, `encryption.key`, `.env`, and `database/` out of git.

## Security Checks

- Session cookies are encrypted with Fernet.
- TOTP secrets are encrypted before database storage.
- FIDO2 credential JSON is encrypted before database storage.
- CSRF is enforced on state-changing routes.
- Security headers are applied to every response.
- Failed password attempts are tracked and temporarily blocked.
- The final workspace is reachable only after password, TOTP, and FIDO2 are complete in the session.

## Final App Route

After all three checks pass, users land on `/auth/success`, which is now a protected workspace shell with Overview, Vault, Activity, and Profile sections.
