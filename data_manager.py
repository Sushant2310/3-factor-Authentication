import sqlite3
import os
import pyotp
import logging
import hmac
import hashlib
from typing import Optional
from exceptions import UserAlreadyExistsError
from utils import decrypt_text, encrypt_text, get_encryption_key

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "database", "users.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

USER_LOOKUP_COLUMNS = {
    "id",
    "password",
    "totp_secret",
    "fido_credentials",
    "username_hash",
    "username_encrypted",
}

def get_db() -> sqlite3.Connection:
    """Get database connection - create new connection for each request to avoid threading issues"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def username_lookup(username: str) -> str:
    return hmac.new(get_encryption_key(), username.encode("utf-8"), hashlib.sha256).hexdigest()


def decrypt_audit_row(row) -> dict:
    data = dict(row)
    for column in ("event_description", "ip_address", "user_agent"):
        if data.get(column):
            data[column] = decrypt_text(data[column])
    return data


def fetch_user_value(username: str, column: str):
    if column not in USER_LOOKUP_COLUMNS:
        raise ValueError("Unsupported user column")
    row = get_db().execute(
        f"SELECT {column} FROM users WHERE username_hash = ?",
        (username_lookup(username),)
    ).fetchone()
    return row[column] if row else None


def update_user_value(username: str, column: str, value) -> None:
    if column not in USER_LOOKUP_COLUMNS:
        raise ValueError("Unsupported user column")
    conn = get_db()
    conn.execute(
        f"UPDATE users SET {column} = ? WHERE username_hash = ?",
        (value, username_lookup(username))
    )
    conn.commit()


def hash_password(password: str) -> str:
    from werkzeug.security import generate_password_hash
    peppered = hmac.new(get_encryption_key(), password.encode("utf-8"), hashlib.sha256).hexdigest()
    return "v2$" + generate_password_hash(peppered, method="scrypt")


def password_matches(stored_hash: str, password: str) -> bool:
    from werkzeug.security import check_password_hash
    if stored_hash.startswith("v2$"):
        peppered = hmac.new(get_encryption_key(), password.encode("utf-8"), hashlib.sha256).hexdigest()
        return check_password_hash(stored_hash[3:], peppered)
    return check_password_hash(stored_hash, password)


def init_db():
    """Initialize database tables"""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_hash TEXT UNIQUE NOT NULL,
            username_encrypted TEXT NOT NULL,
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

    c.execute('''
        CREATE TABLE IF NOT EXISTS inventory_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            sku TEXT,
            quantity INTEGER DEFAULT 0,
            location TEXT,
            status TEXT,
            notes TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    ensure_user_columns(conn)
    conn.commit()
    migrate_sensitive_data(conn)


def ensure_user_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    for column, definition in {
        "username_hash": "TEXT",
        "username_encrypted": "TEXT",
    }.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")


def migrate_sensitive_data(conn: sqlite3.Connection) -> None:
    """Encrypt legacy plaintext values and backfill private username storage."""
    user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    select_columns = ["id", "totp_secret", "fido_credentials", "username_hash", "username_encrypted"]
    if "username" in user_columns:
        select_columns.append("username")

    rows = conn.execute(f"SELECT {', '.join(select_columns)} FROM users").fetchall()
    for row in rows:
        updates = {}
        legacy_username = row["username"] if "username" in row.keys() else None
        stored_username = decrypt_text(row["username_encrypted"]) if row["username_encrypted"] else legacy_username
        if stored_username:
            expected_hash = username_lookup(stored_username)
            if row["username_hash"] != expected_hash:
                updates["username_hash"] = expected_hash
            if not row["username_encrypted"] or not str(row["username_encrypted"]).startswith("enc2:"):
                updates["username_encrypted"] = encrypt_text(stored_username)
            if "username" in user_columns and row["username"] != expected_hash:
                updates["username"] = expected_hash
        if row["totp_secret"] and not str(row["totp_secret"]).startswith("enc:"):
            updates["totp_secret"] = encrypt_text(row["totp_secret"])
        elif row["totp_secret"] and str(row["totp_secret"]).startswith("enc:"):
            updates["totp_secret"] = encrypt_text(row["totp_secret"])
        if row["fido_credentials"] and not str(row["fido_credentials"]).startswith("enc:"):
            updates["fido_credentials"] = encrypt_text(row["fido_credentials"])
        elif row["fido_credentials"] and str(row["fido_credentials"]).startswith("enc:"):
            updates["fido_credentials"] = encrypt_text(row["fido_credentials"])
        for column, value in updates.items():
            conn.execute(f"UPDATE users SET {column} = ? WHERE id = ?", (value, row["id"]))

    audit_rows = conn.execute("SELECT * FROM audit_log").fetchall()
    for row in audit_rows:
        updates = {}
        for column in ("event_description", "ip_address", "user_agent"):
            value = row[column]
            if value and not str(value).startswith("enc2:"):
                updates[column] = encrypt_text(value)
        for column, value in updates.items():
            conn.execute(f"UPDATE audit_log SET {column} = ? WHERE id = ?", (value, row["id"]))

    if rows or audit_rows:
        conn.commit()


def create_user(
    username: str,
    password: str,
    totp_secret: Optional[str] = None,
) -> Optional[int]:
    """Create a new user account."""
    conn = get_db()
    try:
        encrypted_totp_secret = encrypt_text(totp_secret) if totp_secret else None
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "username" in columns:
            conn.execute(
                '''INSERT INTO users (username, username_hash, username_encrypted, password, totp_secret)
                   VALUES (?, ?, ?, ?, ?)''',
                (
                    username_lookup(username),
                    username_lookup(username),
                    encrypt_text(username),
                    hash_password(password),
                    encrypted_totp_secret,
                )
            )
        else:
            conn.execute(
                '''INSERT INTO users (username_hash, username_encrypted, password, totp_secret)
                   VALUES (?, ?, ?, ?)''',
                (username_lookup(username), encrypt_text(username), hash_password(password), encrypted_totp_secret)
            )
        conn.commit()

        cursor = conn.execute('SELECT id FROM users WHERE username_hash = ?', (username_lookup(username),))
        row = cursor.fetchone()
        return row['id'] if row else None
    except sqlite3.IntegrityError as e:
        conn.rollback()
        if "UNIQUE" in str(e).upper():
            raise UserAlreadyExistsError(username) from e
        logger.error(f"Failed to create user {username}: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to create user {username}: {e}")
        conn.rollback()
        raise


def get_user_id_by_username(username: str) -> Optional[int]:
    """Get user ID from username"""
    return fetch_user_value(username, "id")


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    return get_db().execute(
        'SELECT * FROM users WHERE username_hash = ?',
        (username_lookup(username),)
    ).fetchone()


def get_admin_user_by_id(user_id: int) -> Optional[dict]:
    conn = get_db()
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "username_encrypted" in columns:
        row = conn.execute(
            "SELECT id, username_encrypted FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        user = {
            "id": row["id"],
            "username": decrypt_text(row["username_encrypted"]) if row and row["username_encrypted"] else "",
        } if row else None
    else:
        row = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
        user = {"id": row["id"], "username": row["username"]} if row else None
    conn.close()
    return user


def list_users_for_admin() -> list[dict]:
    conn = get_db()
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "username_encrypted" in columns:
        rows = conn.execute("SELECT id, username_encrypted FROM users ORDER BY id").fetchall()
        users = [
            {
                "id": row["id"],
                "username": decrypt_text(row["username_encrypted"]) if row["username_encrypted"] else "",
            }
            for row in rows
        ]
    else:
        rows = conn.execute("SELECT id, username FROM users ORDER BY id").fetchall()
        users = [{"id": row["id"], "username": row["username"]} for row in rows]
    conn.close()
    return users


def update_username_by_id(user_id: int, username: str) -> None:
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE username_hash = ? AND id != ?",
            (username_lookup(username), user_id)
        ).fetchone()
        if existing:
            raise UserAlreadyExistsError(username)

        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "username" in columns:
            conn.execute(
                "UPDATE users SET username = ?, username_hash = ?, username_encrypted = ? WHERE id = ?",
                (username_lookup(username), username_lookup(username), encrypt_text(username), user_id)
            )
        else:
            conn.execute(
                "UPDATE users SET username_hash = ?, username_encrypted = ? WHERE id = ?",
                (username_lookup(username), encrypt_text(username), user_id)
            )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.rollback()
        if "UNIQUE" in str(e).upper():
            raise UserAlreadyExistsError(username) from e
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reset_user_authenticators(user_id: int) -> None:
    conn = get_db()
    conn.execute(
        "UPDATE users SET totp_secret = NULL, fido_credentials = NULL WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def list_inventory_items(user_id: int) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        '''SELECT id, item_name, sku, quantity, location, status, notes, updated_at
           FROM inventory_items
           WHERE user_id = ?
           ORDER BY updated_at DESC, id DESC''',
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def create_inventory_item(
    user_id: int,
    item_name: str,
    sku: str = "",
    quantity: int = 0,
    location: str = "",
    status: str = "",
    notes: str = "",
) -> None:
    conn = get_db()
    conn.execute(
        '''INSERT INTO inventory_items (user_id, item_name, sku, quantity, location, status, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (user_id, item_name, sku, quantity, location, status, notes)
    )
    conn.commit()
    conn.close()


def update_inventory_item(
    user_id: int,
    item_id: int,
    item_name: str,
    sku: str = "",
    quantity: int = 0,
    location: str = "",
    status: str = "",
    notes: str = "",
) -> None:
    conn = get_db()
    conn.execute(
        '''UPDATE inventory_items
           SET item_name = ?, sku = ?, quantity = ?, location = ?, status = ?, notes = ?,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND user_id = ?''',
        (item_name, sku, quantity, location, status, notes, item_id, user_id)
    )
    conn.commit()
    conn.close()


def delete_inventory_item(user_id: int, item_id: int) -> None:
    conn = get_db()
    conn.execute(
        "DELETE FROM inventory_items WHERE id = ? AND user_id = ?",
        (item_id, user_id)
    )
    conn.commit()
    conn.close()


def verify_password(username: str, password: str) -> bool:
    """Verify password for a user."""
    hashed = fetch_user_value(username, "password")
    if not hashed or not password_matches(hashed, password):
        return False
    if not hashed.startswith("v2$"):
        update_user_value(username, "password", hash_password(password))
    return True


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
            (
                user_id,
                event_type,
                encrypt_text(event_description) if event_description else None,
                encrypt_text(ip_address) if ip_address else None,
                encrypt_text(user_agent) if user_agent else None,
                1 if success else 0,
            )
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
    return [decrypt_audit_row(row) for row in cursor.fetchall()]


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
    return [decrypt_audit_row(row) for row in cursor.fetchall()]
init_db()
