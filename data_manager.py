import sqlite3
import os
import numpy as np
import pyotp
from datetime import datetime
from cryptography.fernet import Fernet
import threading
import logging
from typing import Optional, List, Tuple, Any

logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), "database", "users.db")
SECRET_KEY_PATH = 'secret.key'
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Connection pool for better performance
_connection_pool = {}
_pool_lock = threading.Lock()

# ---------- Encryption Setup ----------
def load_secret_key() -> Fernet:
    """Generate or load the encryption key used for TOTP secrets"""
    if not os.path.exists(SECRET_KEY_PATH):
        key = Fernet.generate_key()
        with open(SECRET_KEY_PATH, "wb") as f:
            f.write(key)
    else:
        with open(SECRET_KEY_PATH, "rb") as f:
            key = f.read()
    return Fernet(key)

# Separate key for biometric data encryption
BIOMETRIC_KEY_PATH = 'biometric.key'
def load_biometric_key() -> Fernet:
    """Generate or load the encryption key used for biometric data"""
    if not os.path.exists(BIOMETRIC_KEY_PATH):
        key = Fernet.generate_key()
        with open(BIOMETRIC_KEY_PATH, "wb") as f:
            f.write(key)
        logger.info("Generated new biometric encryption key")
    else:
        with open(BIOMETRIC_KEY_PATH, "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_secret_key()
biometric_fernet = load_biometric_key()


def get_db() -> sqlite3.Connection:
    """Get database connection - create new connection for each request to avoid threading issues"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


# ---------- Database Setup ----------
def init_db():
    """Initialize database tables"""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT,
            totp_secret TEXT,
            fido_credentials TEXT,
            face_encoding BLOB,
            phone_verified INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            auth_method TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            event_description TEXT,
            ip_address TEXT,
            user_agent TEXT,
            success INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    # Don't close connection - it's from the pool


# ---------- User Management ----------
def create_user(username: str, password: str, totp_secret: Optional[str] = None) -> Optional[int]:
    """Create a new user account."""
    conn = get_db()
    try:
        # hash the password (use werkzeug or bcrypt)
        from werkzeug.security import generate_password_hash
        hashed = generate_password_hash(password)

        conn.execute(
            '''INSERT INTO users (username, password, totp_secret, phone_verified)
               VALUES (?, ?, ?, 0)''',
            (username, hashed, totp_secret)
        )
        conn.commit()

        # Return the user ID
        cursor = conn.execute('SELECT id FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        return row['id'] if row else None
    except Exception as e:
        logger.error(f"Failed to create user {username}: {e}")
        conn.rollback()
        raise


def get_user_id_by_username(username: str) -> Optional[int]:
    """Get user ID from username"""
    conn = get_db()
    cursor = conn.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    return result['id'] if result else None


def verify_password(username: str, password: str) -> bool:
    """Verify password for a user."""
    from werkzeug.security import check_password_hash
    conn = get_db()
    cursor = conn.execute('SELECT password FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    if not row:
        return False
    return check_password_hash(row['password'], password)


def generate_totp_secret() -> str:
    """Generate new TOTP secret"""
    return pyotp.random_base32()


def get_totp_secret(username: str) -> Optional[str]:
    """Get TOTP secret for user"""
    conn = get_db()
    cursor = conn.execute(
        'SELECT totp_secret FROM users WHERE username = ?',
        (username,)
    )
    result = cursor.fetchone()
    return result['totp_secret'] if result else None


def verify_totp(username: str, code: str) -> bool:
    """Verify TOTP code"""
    secret = get_totp_secret(username)
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


# ---------- Logging ----------
def add_login_time(username):
    """Record login time for user"""
    user_id = get_user_id_by_username(username)
    if user_id:
        conn = get_db()
        conn.execute(
            'INSERT INTO login_history (user_id, auth_method, timestamp) VALUES (?, ?, ?)',
            (user_id, 'face', datetime.now())
        )
        conn.commit()


def get_login_times(username):
    """Get login history for user"""
    user_id = get_user_id_by_username(username)
    if not user_id:
        return []

    conn = get_db()
    cursor = conn.execute(
        'SELECT timestamp FROM login_history WHERE user_id = ? ORDER BY timestamp DESC',
        (user_id,)
    )
    return [row['timestamp'] for row in cursor.fetchall()]


# ---------- Audit Logging ----------
def log_audit_event(user_id: Optional[int], event_type: str, event_description: str,
                   ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                   success: bool = False):
    """Log security audit events"""
    conn = get_db()
    try:
        conn.execute(
            '''INSERT INTO audit_log (user_id, event_type, event_description, ip_address, user_agent, success)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, event_type, event_description, ip_address, user_agent, 1 if success else 0)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")


def get_audit_events(user_id: Optional[int] = None, limit: int = 100):
    """Get audit events, optionally filtered by user"""
    conn = get_db()
    if user_id:
        cursor = conn.execute(
            'SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?',
            (user_id, limit)
        )
    else:
        cursor = conn.execute(
            'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
    return [dict(row) for row in cursor.fetchall()]


def get_failed_login_attempts(username: str, time_window_minutes: int = 30):
    """Get failed login attempts for user within time window"""
    user_id = get_user_id_by_username(username)
    if not user_id:
        return []

    conn = get_db()
    cursor = conn.execute(
        '''SELECT timestamp, event_description FROM audit_log
           WHERE user_id = ? AND event_type = 'login_failed'
           AND timestamp > datetime('now', '-{} minutes')
           ORDER BY timestamp DESC'''.format(time_window_minutes),
        (user_id,)
    )
    return [dict(row) for row in cursor.fetchall()]


def store_face_encoding(username, encoding):
    """Store face encoding as encrypted binary blob"""
    conn = get_db()
    # Convert numpy array to bytes (InsightFace embeddings are float32)
    encoding_bytes = encoding.astype(np.float32).tobytes()

    # Encrypt the biometric data before storing
    encrypted_data = biometric_fernet.encrypt(encoding_bytes)

    conn.execute(
        'UPDATE users SET face_encoding = ? WHERE username = ?',
        (encrypted_data, username)
    )
    conn.commit()
    logger.info(f"Encrypted face encoding stored for user: {username}")


def get_face_encoding(username):
    """Retrieve and decrypt face encoding as numpy array"""
    conn = get_db()
    cursor = conn.execute(
        'SELECT face_encoding FROM users WHERE username = ?',
        (username,)
    )
    result = cursor.fetchone()
    if result and result[0]:
        try:
            # Decrypt the biometric data
            decrypted_data = biometric_fernet.decrypt(result[0])
            # Convert bytes back to numpy array (InsightFace uses float32)
            return np.frombuffer(decrypted_data, dtype=np.float32)
        except Exception as e:
            logger.error(f"Failed to decrypt face encoding for user {username}: {e}")
            return None
    return None


def set_phone_verified(username, value=True):
    """Set phone verified status for user"""
    conn = get_db()
    conn.execute('UPDATE users SET phone_verified = ? WHERE username = ?', (1 if value else 0, username))
    conn.commit()


def get_phone_verified(username):
    """Get phone verified status for user"""
    conn = get_db()
    cur = conn.execute('SELECT phone_verified FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    return bool(row['phone_verified']) if row else False


# Initialize database when module is imported
init_db()