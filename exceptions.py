from typing import Optional
from fastapi import HTTPException


class AuthenticationError(HTTPException):
    """Base authentication error."""

    def __init__(
        self,
        status_code: int = 401,
        detail: str = "Authentication failed",
        headers: Optional[dict[str, str]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class UserNotFoundError(AuthenticationError):
    def __init__(self, username: str):
        super().__init__(detail=f"User '{username}' not found")


class InvalidPasswordError(AuthenticationError):
    def __init__(self):
        super().__init__(detail="Invalid password")


class UserAlreadyExistsError(HTTPException):
    def __init__(self, username: str):
        super().__init__(status_code=409, detail=f"Username '{username}' already exists")


class ValidationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


class DatabaseError(HTTPException):
    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(status_code=500, detail=detail)


class ConfigurationError(Exception):
    def __init__(self, detail: str):
        super().__init__(f"Configuration error: {detail}")


class FileOperationError(HTTPException):
    def __init__(self, detail: str = "File operation failed"):
        super().__init__(status_code=500, detail=detail)


class EncryptionError(HTTPException):
    def __init__(self, detail: str = "Encryption operation failed"):
        super().__init__(status_code=500, detail=detail)


class TokenExpiredError(HTTPException):
    def __init__(self):
        super().__init__(status_code=401, detail="Token has expired")


class InvalidTokenError(HTTPException):
    def __init__(self):
        super().__init__(status_code=401, detail="Invalid token")


class AdminRequiredError(HTTPException):
    def __init__(self):
        super().__init__(status_code=403, detail="Admin access required")


class TOTPError(HTTPException):
    def __init__(self, detail: str = "TOTP verification failed"):
        super().__init__(status_code=401, detail=detail)


class FIDO2Error(HTTPException):
    def __init__(self, detail: str = "FIDO2 operation failed"):
        super().__init__(status_code=400, detail=detail)
