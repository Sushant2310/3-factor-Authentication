"""
Input validation decorators and utilities for the 3FA authentication system.
"""

import re
from functools import wraps
from typing import Callable, Any, Optional
from fastapi import HTTPException
from exceptions import ValidationError


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: str, *, strip: bool = True) -> str:
    value = CONTROL_CHARS.sub("", str(value))
    return value.strip() if strip else value


def validate_username(username: str) -> str:
    """Validate username format and return cleaned version."""
    if not username:
        raise ValidationError("Username is required")

    username = sanitize_text(username)
    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters long")
    if len(username) > 50:
        raise ValidationError("Username must be less than 50 characters long")
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        raise ValidationError("Username contains invalid characters")
    return username


def validate_password(password: str) -> str:
    """Validate password strength."""
    if not password:
        raise ValidationError("Password is required")
    password = sanitize_text(password, strip=False)
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    if len(password) > 128:
        raise ValidationError("Password must be less than 128 characters long")
    for pattern, message in (
        (r'[A-Z]', "Password must contain at least one uppercase letter"),
        (r'[a-z]', "Password must contain at least one lowercase letter"),
        (r'\d', "Password must contain at least one digit"),
    ):
        if not re.search(pattern, password):
            raise ValidationError(message)
    return password


def validate_login_password(password: str) -> str:
    """Validate login password input without enforcing registration complexity rules."""
    if not password:
        raise ValidationError("Password is required")
    password = sanitize_text(password, strip=False)
    if len(password) > 128:
        raise ValidationError("Password must be less than 128 characters long")
    return password


def validate_email(email: str) -> str:
    """Validate email format."""
    if not email:
        raise ValidationError("Email is required")
    email = sanitize_text(email).lower()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValidationError("Invalid email format")
    return email


def validate_inventory_text(
    value: str,
    field_name: str,
    *,
    required: bool = False,
    max_length: int = 120,
) -> str:
    value = sanitize_text(value or "")
    if required and not value:
        raise ValidationError(f"{field_name} is required")
    if len(value) > max_length:
        raise ValidationError(f"{field_name} must be less than {max_length} characters")
    return value


def validate_inventory_quantity(value) -> int:
    try:
        quantity = int(value or 0)
    except (TypeError, ValueError):
        raise ValidationError("Quantity must be a number")
    if quantity < 0:
        raise ValidationError("Quantity cannot be negative")
    if quantity > 1_000_000:
        raise ValidationError("Quantity is too large")
    return quantity


def validate_inventory_status(value: str) -> str:
    status = sanitize_text(value or "In stock")
    allowed = {"In stock", "Low stock", "Reserved", "Ordered", "Retired"}
    if status not in allowed:
        raise ValidationError("Invalid inventory status")
    return status


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
    if not image_data.startswith('data:image/') or ',' not in image_data:
        raise ValidationError("Invalid image data format")
    return image_data


def validate_token(token: str) -> str:
    """Validate token format."""
    if not token:
        raise ValidationError("Token is required")
    token = token.strip()
    uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'
    if not re.match(uuid_pattern, token):
        raise ValidationError("Invalid token format")
    return token


def sanitize_input(func: Callable) -> Callable:
    """Decorator to sanitize string inputs by stripping whitespace."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        sanitized_args = [arg.strip() if isinstance(arg, str) else arg for arg in args]
        sanitized_kwargs = {
            key: value.strip() if isinstance(value, str) else value
            for key, value in kwargs.items()
        }
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

            while call_times and current_time - call_times[0] > time_window:
                call_times.popleft()
            if len(call_times) >= max_calls:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Maximum {max_calls} calls per {time_window} seconds"
                )
            call_times.append(current_time)
            return await func(*args, **kwargs)
        return wrapper
    return decorator
