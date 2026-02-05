
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = 'idps.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            last_login TEXT
        )
    ''')
    # Création de l'admin par défaut s'il n'existe pas
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       ('admin', generate_password_hash('admin'), 'Administrateur'))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        return dict(user)
    return None

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, last_login FROM users")
    users = [dict(u) for u in cursor.fetchall()]
    conn.close()
    return users

def update_user_password(user_id, new_password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    hashed = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def create_user(username, password, role):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (username, generate_password_hash(password), role))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()
