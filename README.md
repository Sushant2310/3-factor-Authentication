# 3FA Authentication System

A secure FastAPI-based multi-factor authentication web application that combines password login with TOTP, face verification, and FIDO2/WebAuthn security keys.

## Overview

This project is designed as a portable authentication platform and portfolio-ready security application. It allows users to register accounts, enroll multiple authentication factors, and complete login workflows with stronger identity verification than password-only systems.

It also includes an admin dashboard for user management, operational control, and account support tasks.

## Core Features

- Password-based authentication
- TOTP authenticator app setup and verification
- Face registration, framing validation, and face-based login
- FIDO2 / WebAuthn security key registration
- Admin login and user management
- Password visibility and password strength feedback
- Improved UI across active authentication flows
- Portable local startup script
- Docker support

## Security Highlights

- CSRF protection on state-changing routes
- Trusted host enforcement
- Security headers
- Safer session handling
- Reduced CORS exposure
- Request, upload, and image-size validation
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

## Use Cases

This project can be used as:

- a secure authentication platform prototype
- a cybersecurity or backend portfolio project
- a base for identity verification systems
- a starting point for attendance or admin access platforms

## Quick Start

### Local Setup

```powershell
cd D:\3fa
python -m pip install -r requirements.txt
python run_portable.py
```

Open:

[http://localhost:8000](http://localhost:8000)

Important for FIDO2 / WebAuthn:

- use `http://localhost:8000`
- avoid `127.0.0.1` if the browser rejects the relying-party domain

### Docker

```powershell
docker compose up --build
```

Then open:

[http://localhost:8000](http://localhost:8000)

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

## Git Workflow

To stage, commit, and push in one command on Windows:

```powershell
cd D:\3fa
.\publish.bat
```

If you want a custom commit message:

```powershell
cd D:\3fa
.\git_publish.ps1 -Message "Describe your changes"
```

## Project Structure

```text
app.py                  Main FastAPI application
config.py               Environment-based configuration
data_manager.py         Database and persistence helpers
face_handler.py         Face detection and verification logic
templates/              Jinja templates
static/                 Shared CSS and JavaScript
database/               Local SQLite database
captured/               Local capture artifacts
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

## Production Notes

This repository is a strong prototype and deployment base, but production use should still include:

- HTTPS
- PostgreSQL or another production database
- centralized logging and monitoring
- managed secrets
- automated test coverage
- backup and recovery planning

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
