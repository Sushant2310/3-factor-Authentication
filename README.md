# 3FA Authentication System

A FastAPI-based multi-factor authentication web application that combines:

- password authentication
- TOTP authenticator verification
- face registration and face-based verification
- FIDO2 / WebAuthn security key support

The project is designed as a portable authentication platform and strong portfolio project, with a modern UI, local-first setup, and practical security hardening.

## Overview

This application lets users create accounts and enroll multiple authentication factors inside one workflow. It also includes an admin dashboard for user management, password reset, and operational control.

It is suitable as:

- a security-focused FastAPI portfolio project
- a prototype for secure login portals
- a base for identity verification or attendance systems
- a starting point for internal admin access platforms

## Features

- User registration with multiple factors
- Password-based login
- TOTP setup using QR codes
- Face capture, framing validation, and face verification
- FIDO2 / WebAuthn security key enrollment
- Admin login and user management
- Portable local startup with `run_portable.py`
- Docker support
- Shared front-end theme and improved UX

## Security Highlights

- CSRF protection on state-changing routes
- Trusted host restrictions
- Safer session cookie defaults
- Security headers
- Reduced CORS exposure
- Upload-size and image-dimension limits
- Failed-login tracking and temporary lockout behavior
- Encrypted handling for biometric-related stored data

## Tech Stack

- FastAPI
- Jinja2
- SQLite
- OpenCV
- PyOTP
- FIDO2 / WebAuthn
- Docker

## Quick Start

### Local

```powershell
cd D:\3fa
python -m pip install -r requirements.txt
python run_portable.py
```

Open:

[http://localhost:8000](http://localhost:8000)

Important for FIDO2/WebAuthn:

- use `http://localhost:8000`
- avoid `127.0.0.1` if the browser rejects the relying-party domain

### Docker

```powershell
docker compose up --build
```

Then open:

[http://localhost:8000](http://localhost:8000)

## Git Workflow

To stage, commit, and push in one command on Windows:

```powershell
cd D:\3fa
.\git_publish.ps1 -Message "Describe your changes"
```

If there are no new local changes, the script skips the commit step and only pushes.

## Configuration

Copy `.env.example` and set environment values as needed.

Important variables:

- `SECRET_KEY`
- `ENCRYPTION_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `ALLOWED_HOSTS`
- `CORS_ORIGINS`
- `MAX_UPLOAD_BYTES`
- `SESSION_HTTPS_ONLY`

## Project Structure

```text
app.py                  Main FastAPI app
config.py               Environment-based configuration
data_manager.py         Database and persistence helpers
face_handler.py         Face detection and verification logic
templates/              Jinja templates
static/                 Shared CSS and JS
database/               Local SQLite database
captured/               Local stored capture artifacts
run_portable.py         Portable startup script
```

## Admin Access

The admin dashboard supports:

- viewing users
- deleting users
- resetting passwords

Admin credentials are controlled through environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`

## Notes

- Local database and capture folders are excluded from Git with `.gitignore`
- This project is best treated as a strong prototype or foundation, not a finished enterprise product
- For production use, add HTTPS, PostgreSQL, centralized logging, proper secrets management, and automated tests

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
