"""
Custom exceptions for the 3FA authentication system.
"""

from fastapi import HTTPException
from typing import Optional, Dict, Any


class AuthenticationError(HTTPException):
    """Base authentication error."""

    def __init__(
        self,
        status_code: int = 401,
        detail: str = "Authentication failed",
        headers: Optional[Dict[str, str]] = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class UserNotFoundError(AuthenticationError):
    """User not found error."""

    def __init__(self, username: str):
        super().__init__(
            status_code=401,
            detail=f"User '{username}' not found"
        )


class InvalidPasswordError(AuthenticationError):
    """Invalid password error."""

    def __init__(self):
        super().__init__(
            status_code=401,
            detail="Invalid password"
        )


class UserAlreadyExistsError(HTTPException):
    """User already exists error."""

    def __init__(self, username: str):
        super().__init__(
            status_code=409,
            detail=f"Username '{username}' already exists"
        )


class ValidationError(HTTPException):
    """Input validation error."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=400,
            detail=detail
        )


class DatabaseError(HTTPException):
    """Database operation error."""

    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(
            status_code=500,
            detail=detail
        )


class ConfigurationError(Exception):
    """Configuration error."""

    def __init__(self, detail: str):
        super().__init__(f"Configuration error: {detail}")


class FileOperationError(HTTPException):
    """File operation error."""

    def __init__(self, detail: str = "File operation failed"):
        super().__init__(
            status_code=500,
            detail=detail
        )


class EncryptionError(HTTPException):
    """Encryption/decryption error."""

    def __init__(self, detail: str = "Encryption operation failed"):
        super().__init__(
            status_code=500,
            detail=detail
        )


class TokenExpiredError(HTTPException):
    """Token expired error."""

    def __init__(self):
        super().__init__(
            status_code=401,
            detail="Token has expired"
        )


class InvalidTokenError(HTTPException):
    """Invalid token error."""

    def __init__(self):
        super().__init__(
            status_code=401,
            detail="Invalid token"
        )


class AdminRequiredError(HTTPException):
    """Admin access required error."""

    def __init__(self):
        super().__init__(
            status_code=403,
            detail="Admin access required"
        )


class TOTPError(HTTPException):
    """TOTP verification error."""

    def __init__(self, detail: str = "TOTP verification failed"):
        super().__init__(
            status_code=401,
            detail=detail
        )


class FIDO2Error(HTTPException):
    """FIDO2 operation error."""

    def __init__(self, detail: str = "FIDO2 operation failed"):
        super().__init__(
            status_code=400,
            detail=detail
        )


