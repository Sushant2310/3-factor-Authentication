import sqlite3
import os
import pyotp
import logging
from typing import Optional
from utils import decrypt_text, encrypt_text

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "database", "users.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def get_db() -> sqlite3.Connection:
    """Get database connection - create new connection for each request to avoid threading issues"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def fetch_user_value(username: str, column: str):
    row = get_db().execute(f"SELECT {column} FROM users WHERE username = ?", (username,)).fetchone()
    return row[column] if row else None


def update_user_value(username: str, column: str, value) -> None:
    conn = get_db()
    conn.execute(f"UPDATE users SET {column} = ? WHERE username = ?", (value, username))
    conn.commit()


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
            fido_credentials TEXT
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
    migrate_plaintext_auth_secrets(conn)


def migrate_plaintext_auth_secrets(conn: sqlite3.Connection) -> None:
    """Encrypt legacy plaintext TOTP and FIDO values in existing databases."""
    rows = conn.execute(
        "SELECT id, totp_secret, fido_credentials FROM users"
    ).fetchall()
    for row in rows:
        updates = {}
        if row["totp_secret"] and not str(row["totp_secret"]).startswith("enc:"):
            updates["totp_secret"] = encrypt_text(row["totp_secret"])
        if row["fido_credentials"] and not str(row["fido_credentials"]).startswith("enc:"):
            updates["fido_credentials"] = encrypt_text(row["fido_credentials"])
        for column, value in updates.items():
            conn.execute(f"UPDATE users SET {column} = ? WHERE id = ?", (value, row["id"]))
    if rows:
        conn.commit()


def create_user(username: str, password: str, totp_secret: Optional[str] = None) -> Optional[int]:
    """Create a new user account."""
    conn = get_db()
    try:
        from werkzeug.security import generate_password_hash
        hashed = generate_password_hash(password)

        encrypted_totp_secret = encrypt_text(totp_secret) if totp_secret else None
        conn.execute(
            '''INSERT INTO users (username, password, totp_secret)
               VALUES (?, ?, ?)''',
            (username, hashed, encrypted_totp_secret)
        )
        conn.commit()

        cursor = conn.execute('SELECT id FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        return row['id'] if row else None
    except Exception as e:
        logger.error(f"Failed to create user {username}: {e}")
        conn.rollback()
        raise


def get_user_id_by_username(username: str) -> Optional[int]:
    """Get user ID from username"""
    return fetch_user_value(username, "id")


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    return get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def verify_password(username: str, password: str) -> bool:
    """Verify password for a user."""
    from werkzeug.security import check_password_hash
    hashed = fetch_user_value(username, "password")
    return bool(hashed and check_password_hash(hashed, password))


def generate_totp_secret() -> str:
    """Generate new TOTP secret"""
    return pyotp.random_base32()


def get_totp_secret(username: str) -> Optional[str]:
    """Get TOTP secret for user"""
    secret = fetch_user_value(username, "totp_secret")
    return decrypt_text(secret) if secret else None


def set_totp_secret(username: str, totp_secret: str) -> None:
    """Store an encrypted TOTP secret for a user."""
    update_user_value(username, "totp_secret", encrypt_text(totp_secret))


def get_fido_credentials(username: str) -> Optional[str]:
    """Get encrypted-at-rest FIDO credential JSON for user."""
    credentials = fetch_user_value(username, "fido_credentials")
    return decrypt_text(credentials) if credentials else None


def set_fido_credentials(username: str, credential_json: str) -> None:
    """Store encrypted FIDO credential JSON for user."""
    update_user_value(username, "fido_credentials", encrypt_text(credential_json))


def verify_totp(username: str, code: str) -> bool:
    """Verify TOTP code"""
    secret = get_totp_secret(username)
    return bool(secret and pyotp.TOTP(secret).verify(code))

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
    query = 'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?'
    params = (limit,)
    if user_id:
        query = 'SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?'
        params = (user_id, limit)
    cursor = conn.execute(query, params)
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
init_db()
