import os
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import base64

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "gif", "tiff", "tif", "webp", "ico"}
ENCRYPTION_KEY_PATH = os.path.join(os.path.dirname(__file__), "encryption.key")

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

def save_uploaded_file(file, username, capture_dir):
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = secure_filename(f"{username}_upload.{ext}")
    path = os.path.join(capture_dir, filename)

    # Read file data
    file_data = file.file.read() if hasattr(file, "file") else file.read()

    # Encrypt the file data
    key = get_encryption_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)

    # Save encrypted data
    with open(path, 'wb') as f:
        f.write(encrypted_data)

    return path

def load_encrypted_file(path):
    """Load and decrypt an encrypted file."""
    with open(path, 'rb') as f:
        encrypted_data = f.read()

    key = get_encryption_key()
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data
