import os
import sqlite3
import hashlib
import base64

def hash_password(password, salt=None):
    if salt is None:
        salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    salted = (salt + password).encode('utf-8')
    hashed = hashlib.sha256(salted).hexdigest()
    return f'{salt}${hashed}'

def verify_password(password, hashed):
    try:
        salt, hash_val = hashed.split('$', 1)
    except ValueError:
        return False
    return hash_password(password, salt) == hashed

def get_db_connection():
    conn = sqlite3.connect('db/subnets.db')
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON;')
    return conn

def init_db():
    os.makedirs('db', exist_ok=True)
    conn = sqlite3.connect('db/subnets.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS User (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS AuditLog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        subnet_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES User(id),
        FOREIGN KEY (subnet_id) REFERENCES Subnet(id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Subnet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        cidr TEXT NOT NULL,
        site TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS IPAddress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        hostname TEXT,
        subnet_id INTEGER NOT NULL,
        FOREIGN KEY (subnet_id) REFERENCES Subnet (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Device (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DeviceIPAddress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        ip_id INTEGER NOT NULL,
        FOREIGN KEY (device_id) REFERENCES Device (id),
        FOREIGN KEY (ip_id) REFERENCES IPAddress (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DHCPPool (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subnet_id INTEGER NOT NULL,
        start_ip TEXT NOT NULL,
        end_ip TEXT NOT NULL,
        excluded_ips TEXT,
        FOREIGN KEY (subnet_id) REFERENCES Subnet(id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('SELECT COUNT(*) FROM User')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''INSERT INTO User (name, email, password) VALUES (?, ?, ?)''',
            ('Jamie Banks', 'jamie@jdbnet.co.uk', hash_password('Drippy-Cavity-Jawline')))

    conn.commit()
    conn.close()
