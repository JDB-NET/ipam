import os
import hashlib
import base64
import mysql.connector
from flask import current_app

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

def get_db_connection(app=None):
    if app is None:
        app = current_app
    conn = mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DATABASE'],
        autocommit=True
    )
    return conn

def init_db(app=None):
    if app is None:
        app = current_app
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS User (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Subnet (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        cidr VARCHAR(255) NOT NULL,
        site VARCHAR(255)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS AuditLog (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        user_id INTEGER,
        action VARCHAR(255) NOT NULL,
        details TEXT,
        subnet_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES User(id),
        FOREIGN KEY (subnet_id) REFERENCES Subnet(id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS IPAddress (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        ip VARCHAR(255) NOT NULL,
        hostname VARCHAR(255),
        subnet_id INTEGER NOT NULL,
        FOREIGN KEY (subnet_id) REFERENCES Subnet (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DeviceType (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL UNIQUE,
        icon_class VARCHAR(255) NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Device (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        device_type_id INTEGER DEFAULT 1,
        FOREIGN KEY (device_type_id) REFERENCES DeviceType(id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DeviceIPAddress (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        device_id INTEGER NOT NULL,
        ip_id INTEGER NOT NULL,
        FOREIGN KEY (device_id) REFERENCES Device (id),
        FOREIGN KEY (ip_id) REFERENCES IPAddress (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DHCPPool (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        subnet_id INTEGER NOT NULL,
        start_ip VARCHAR(255) NOT NULL,
        end_ip VARCHAR(255) NOT NULL,
        excluded_ips TEXT,
        FOREIGN KEY (subnet_id) REFERENCES Subnet(id) ON DELETE CASCADE
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Rack (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        site VARCHAR(255) NOT NULL,
        height_u INTEGER NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS RackDevice (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        rack_id INTEGER NOT NULL,
        device_id INTEGER,
        position_u INTEGER NOT NULL,
        side ENUM('front', 'back') NOT NULL,
        nonnet_device_name VARCHAR(255),
        FOREIGN KEY (rack_id) REFERENCES Rack(id) ON DELETE CASCADE,
        FOREIGN KEY (device_id) REFERENCES Device(id) ON DELETE CASCADE
    )
    ''')
    cursor.execute('SELECT COUNT(*) FROM DeviceType')
    if cursor.fetchone()[0] == 0:
        cursor.executemany('INSERT INTO DeviceType (name, icon_class) VALUES (%s, %s)', [
            ('Server', 'fa-server'),
            ('Virtual Machine', 'fa-boxes-stacked'),
            ('Switch', 'fa-network-wired'),
            ('Firewall', 'fa-shield-halved'),
            ('WiFi AP', 'fa-wifi'),
            ('Printer', 'fa-print'),
            ('Other', 'fa-question')
        ])
    cursor.execute("SHOW COLUMNS FROM Device LIKE 'device_type_id'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Device ADD COLUMN device_type_id INTEGER DEFAULT NULL')
    cursor.execute("SELECT id FROM DeviceType WHERE name='Other'")
    other_id = cursor.fetchone()[0]
    cursor.execute('UPDATE Device SET device_type_id = %s WHERE device_type_id IS NULL', (other_id,))
    try:
        cursor.execute('ALTER TABLE Device ADD CONSTRAINT fk_device_type FOREIGN KEY (device_type_id) REFERENCES DeviceType(id)')
    except mysql.connector.Error as e:
        if e.errno != 1061 and e.errno != 1826 and 'Duplicate' not in str(e):
            raise
    cursor.execute('SELECT COUNT(*) FROM User')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''INSERT INTO User (name, email, password) VALUES (%s, %s, %s)''',
            ('admin', 'admin@example.com', hash_password('password')))
    conn.commit()
    conn.close()
