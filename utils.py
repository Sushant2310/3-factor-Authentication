import os
import base64
import hashlib
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "gif", "tiff", "tif", "webp", "ico"}
SECRET_KEY_PATH = os.path.join(os.path.dirname(__file__), "secret.key")
ENCRYPTION_KEY_PATH = os.path.join(os.path.dirname(__file__), "encryption.key")
ENCRYPTED_PREFIX = "enc:"
LAYERED_ENCRYPTED_PREFIX = "enc2:"


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_encryption_key():
    key = os.environ.get('ENCRYPTION_KEY')
    if key:
        return key.encode('ascii')

    if not os.path.exists(ENCRYPTION_KEY_PATH):
        generated = Fernet.generate_key()
        with open(ENCRYPTION_KEY_PATH, "wb") as f:
            f.write(generated)
        return generated

    with open(ENCRYPTION_KEY_PATH, "rb") as f:
        return f.read().strip()


def get_secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if key:
        return key

    if not os.path.exists(SECRET_KEY_PATH):
        import secrets
        generated = secrets.token_urlsafe(48)
        with open(SECRET_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(generated)
        return generated

    with open(SECRET_KEY_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()


def get_secondary_fernet_key() -> bytes:
    material = get_secret_key().encode("utf-8") + b":3fa-storage-layer"
    return base64.urlsafe_b64encode(hashlib.sha256(material).digest())


def encrypt_bytes(value: bytes) -> bytes:
    inner = Fernet(get_encryption_key()).encrypt(value)
    return Fernet(get_secondary_fernet_key()).encrypt(inner)


def decrypt_bytes(value: bytes) -> bytes:
    try:
        inner = Fernet(get_secondary_fernet_key()).decrypt(value)
        return Fernet(get_encryption_key()).decrypt(inner)
    except Exception:
        return Fernet(get_encryption_key()).decrypt(value)


def encrypt_text(value: str) -> str:
    """Encrypt a small UTF-8 value with two Fernet layers for storage."""
    if value is None:
        return value
    if isinstance(value, str) and value.startswith(LAYERED_ENCRYPTED_PREFIX):
        return value
    if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
        value = decrypt_text(value)
    encrypted = encrypt_bytes(str(value).encode("utf-8"))
    return LAYERED_ENCRYPTED_PREFIX + encrypted.decode("ascii")


def decrypt_text(value: str) -> str:
    """Decrypt layered or legacy encrypted values; return legacy plaintext unchanged."""
    if not value or not isinstance(value, str):
        return value
    if value.startswith(LAYERED_ENCRYPTED_PREFIX):
        token = value[len(LAYERED_ENCRYPTED_PREFIX):].encode("ascii")
        return decrypt_bytes(token).decode("utf-8")
    if not value.startswith(ENCRYPTED_PREFIX):
        return value
    token = value[len(ENCRYPTED_PREFIX):].encode("ascii")
    return Fernet(get_encryption_key()).decrypt(token).decode("utf-8")

def save_uploaded_file(file, username, capture_dir):
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = secure_filename(f"{username}_upload.{ext}")
    path = os.path.join(capture_dir, filename)
    file_data = file.file.read() if hasattr(file, "file") else file.read()
    with open(path, 'wb') as f:
        f.write(encrypt_bytes(file_data))
    return path


def load_encrypted_file(path):
    """Load and decrypt an encrypted file."""
    with open(path, 'rb') as f:
        return decrypt_bytes(f.read())
