"""
Input validation decorators and utilities for the 3FA authentication system.
"""

import re
from functools import wraps
from typing import Callable, Any, Optional
from fastapi import HTTPException
from exceptions import ValidationError


def validate_username(username: str) -> str:
    """Validate username format and return cleaned version."""
    if not username:
        raise ValidationError("Username is required")

    username = username.strip()

    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters long")

    if len(username) > 50:
        raise ValidationError("Username must be less than 50 characters long")

    # Allow alphanumeric, underscore, hyphen, and dot
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        raise ValidationError("Username contains invalid characters")

    return username


def validate_password(password: str) -> str:
    """Validate password strength."""
    if not password:
        raise ValidationError("Password is required")

    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")

    if len(password) > 128:
        raise ValidationError("Password must be less than 128 characters long")

    # Check for at least one uppercase, one lowercase, and one digit
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Password must contain at least one uppercase letter")

    if not re.search(r'[a-z]', password):
        raise ValidationError("Password must contain at least one lowercase letter")

    if not re.search(r'\d', password):
        raise ValidationError("Password must contain at least one digit")

    return password


def validate_login_password(password: str) -> str:
    """Validate login password input without enforcing registration complexity rules."""
    if not password:
        raise ValidationError("Password is required")
    if len(password) > 128:
        raise ValidationError("Password must be less than 128 characters long")
    return password


def validate_email(email: str) -> str:
    """Validate email format."""
    if not email:
        raise ValidationError("Email is required")

    email = email.strip().lower()

    # Basic email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_pattern, email):
        raise ValidationError("Invalid email format")

    return email


def validate_totp_code(code: str) -> str:
    """Validate TOTP code format."""
    if not code:
        raise ValidationError("TOTP code is required")

    code = code.strip()

    if not code.isdigit():
        raise ValidationError("TOTP code must contain only digits")

    if len(code) != 6:
        raise ValidationError("TOTP code must be exactly 6 digits")

    return code


def validate_image_data(image_data: str) -> str:
    """Validate base64 image data."""
    if not image_data:
        raise ValidationError("Image data is required")

    # Check if it's a valid base64 data URL
    if not image_data.startswith('data:image/'):
        raise ValidationError("Invalid image data format")

    # Check for base64 content
    if ',' not in image_data:
        raise ValidationError("Invalid image data format")

    return image_data


def validate_token(token: str) -> str:
    """Validate token format."""
    if not token:
        raise ValidationError("Token is required")

    token = token.strip()

    # UUID4 format validation
    uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'

    if not re.match(uuid_pattern, token):
        raise ValidationError("Invalid token format")

    return token


def sanitize_input(func: Callable) -> Callable:
    """Decorator to sanitize string inputs by stripping whitespace."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Sanitize string arguments
        sanitized_args = []
        for arg in args:
            if isinstance(arg, str):
                sanitized_args.append(arg.strip())
            else:
                sanitized_args.append(arg)

        sanitized_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str):
                sanitized_kwargs[key] = value.strip()
            else:
                sanitized_kwargs[key] = value

        return await func(*sanitized_args, **sanitized_kwargs)
    return wrapper


def rate_limit(max_calls: int = 10, time_window: int = 60):
    """Simple rate limiting decorator (in-memory implementation)."""
    from collections import defaultdict, deque
    import time

    calls = defaultdict(lambda: deque(maxlen=max_calls))

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = next((arg for arg in args if hasattr(arg, "client")), None)
            client_host = getattr(getattr(request, "client", None), "host", None)
            route_name = getattr(func, "__name__", "route")
            client_id = f"{client_host or 'default'}:{route_name}"

            current_time = time.time()
            call_times = calls[client_id]

            # Remove old calls outside the time window
            while call_times and current_time - call_times[0] > time_window:
                call_times.popleft()

            # Check if rate limit exceeded
            if len(call_times) >= max_calls:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Maximum {max_calls} calls per {time_window} seconds"
                )

            # Add current call
            call_times.append(current_time)

            return await func(*args, **kwargs)
        return wrapper
    return decorator
