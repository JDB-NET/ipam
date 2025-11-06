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
    # Create Role table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Role (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT
    )
    ''')
    
    # Create Permission table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Permission (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT,
        category VARCHAR(255)
    )
    ''')
    
    # Create RolePermission junction table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS RolePermission (
        role_id INTEGER NOT NULL,
        permission_id INTEGER NOT NULL,
        PRIMARY KEY (role_id, permission_id),
        FOREIGN KEY (role_id) REFERENCES Role(id) ON DELETE CASCADE,
        FOREIGN KEY (permission_id) REFERENCES Permission(id) ON DELETE CASCADE
    )
    ''')
    
    # Add role_id column to User table if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM User LIKE 'role_id'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE User ADD COLUMN role_id INTEGER DEFAULT NULL')
        try:
            cursor.execute('ALTER TABLE User ADD CONSTRAINT fk_user_role FOREIGN KEY (role_id) REFERENCES Role(id)')
        except mysql.connector.Error as e:
            if e.errno != 1061 and e.errno != 1826 and 'Duplicate' not in str(e):
                raise
    
    # Define all permissions with categories
    permissions = [
        # View permissions
        ('view_index', 'View Home/Index page', 'View'),
        ('view_devices', 'View Devices page', 'View'),
        ('view_device', 'View Device details', 'View'),
        ('view_subnet', 'View Subnet details', 'View'),
        ('view_racks', 'View Racks page', 'View'),
        ('view_rack', 'View Rack details', 'View'),
        ('view_audit', 'View Audit Log', 'View'),
        ('view_admin', 'View Admin panel', 'View'),
        ('view_users', 'View Users page', 'View'),
        ('view_device_types', 'View Device Types page', 'View'),
        ('view_device_type_stats', 'View Device Type Statistics', 'View'),
        ('view_devices_by_type', 'View Devices by Type', 'View'),
        ('view_dhcp', 'View DHCP configuration', 'View'),
        ('view_help', 'View Help page', 'View'),
        
        # Device permissions
        ('add_device', 'Add new device', 'Device'),
        ('edit_device', 'Edit device (rename, description, type)', 'Device'),
        ('delete_device', 'Delete device', 'Device'),
        ('add_device_ip', 'Add IP address to device', 'Device'),
        ('remove_device_ip', 'Remove IP address from device', 'Device'),
        
        # Subnet permissions
        ('add_subnet', 'Add new subnet', 'Subnet'),
        ('edit_subnet', 'Edit subnet (name, CIDR, site)', 'Subnet'),
        ('delete_subnet', 'Delete subnet', 'Subnet'),
        ('export_subnet_csv', 'Export subnet as CSV', 'Subnet'),
        
        # Rack permissions
        ('add_rack', 'Add new rack', 'Rack'),
        ('delete_rack', 'Delete rack', 'Rack'),
        ('add_device_to_rack', 'Add device to rack', 'Rack'),
        ('remove_device_from_rack', 'Remove device from rack', 'Rack'),
        ('add_nonnet_device_to_rack', 'Add non-networked device to rack', 'Rack'),
        ('export_rack_csv', 'Export rack as CSV', 'Rack'),
        
        # DHCP permissions
        ('configure_dhcp', 'Configure DHCP pools', 'DHCP'),
        
        # Device Type permissions
        ('add_device_type', 'Add device type', 'Device Type'),
        ('edit_device_type', 'Edit device type', 'Device Type'),
        ('delete_device_type', 'Delete device type', 'Device Type'),
        
        # Admin permissions
        ('manage_users', 'Manage users (add, edit, delete)', 'Admin'),
        ('manage_roles', 'Manage roles and permissions', 'Admin'),
    ]
    
    # Insert permissions
    for perm_name, perm_desc, perm_category in permissions:
        cursor.execute('SELECT id FROM Permission WHERE name = %s', (perm_name,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO Permission (name, description, category) VALUES (%s, %s, %s)',
                          (perm_name, perm_desc, perm_category))
    
    # Create default roles if they don't exist
    cursor.execute('SELECT id FROM Role WHERE name = %s', ('admin',))
    admin_role = cursor.fetchone()
    if not admin_role:
        cursor.execute('INSERT INTO Role (name, description) VALUES (%s, %s)',
                      ('admin', 'Administrator with full access to all features'))
        admin_role_id = cursor.lastrowid
    else:
        admin_role_id = admin_role[0]
    
    cursor.execute('SELECT id FROM Role WHERE name = %s', ('user',))
    user_role = cursor.fetchone()
    if not user_role:
        cursor.execute('INSERT INTO Role (name, description) VALUES (%s, %s)',
                      ('user', 'Standard user with access to most features except admin functions'))
        user_role_id = cursor.lastrowid
    else:
        user_role_id = user_role[0]
    
    cursor.execute('SELECT id FROM Role WHERE name = %s', ('view_only',))
    view_only_role = cursor.fetchone()
    if not view_only_role:
        cursor.execute('INSERT INTO Role (name, description) VALUES (%s, %s)',
                      ('view_only', 'View-only user with read-only access to all pages'))
        view_only_role_id = cursor.lastrowid
    else:
        view_only_role_id = view_only_role[0]
    
    # Assign all permissions to admin role
    cursor.execute('SELECT id FROM Permission')
    all_permission_ids = [row[0] for row in cursor.fetchall()]
    for perm_id in all_permission_ids:
        cursor.execute('SELECT role_id FROM RolePermission WHERE role_id = %s AND permission_id = %s',
                      (admin_role_id, perm_id))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO RolePermission (role_id, permission_id) VALUES (%s, %s)',
                          (admin_role_id, perm_id))
    
    # Assign non-admin permissions to user role
    non_admin_permissions = [
        'view_index', 'view_devices', 'view_device', 'view_subnet', 'view_racks', 'view_rack',
        'view_audit', 'view_device_types', 'view_device_type_stats', 'view_devices_by_type',
        'view_dhcp', 'view_help',
        'add_device', 'edit_device', 'delete_device', 'add_device_ip', 'remove_device_ip',
        'add_subnet', 'edit_subnet', 'delete_subnet', 'export_subnet_csv',
        'add_rack', 'delete_rack', 'add_device_to_rack', 'remove_device_from_rack',
        'add_nonnet_device_to_rack', 'export_rack_csv',
        'configure_dhcp',
        'add_device_type', 'edit_device_type', 'delete_device_type'
    ]
    
    for perm_name in non_admin_permissions:
        cursor.execute('SELECT id FROM Permission WHERE name = %s', (perm_name,))
        perm_result = cursor.fetchone()
        if perm_result:
            perm_id = perm_result[0]
            cursor.execute('SELECT role_id FROM RolePermission WHERE role_id = %s AND permission_id = %s',
                          (user_role_id, perm_id))
            if not cursor.fetchone():
                cursor.execute('INSERT INTO RolePermission (role_id, permission_id) VALUES (%s, %s)',
                              (user_role_id, perm_id))
    
    # Assign view-only permissions to view_only role
    # Same view permissions as user role, but excluding admin views (view_admin, view_users)
    view_only_permissions = [
        'view_index', 'view_devices', 'view_device', 'view_subnet', 'view_racks', 'view_rack',
        'view_audit', 'view_device_types', 'view_device_type_stats', 'view_devices_by_type',
        'view_dhcp', 'view_help'
    ]
    
    for perm_name in view_only_permissions:
        cursor.execute('SELECT id FROM Permission WHERE name = %s', (perm_name,))
        perm_result = cursor.fetchone()
        if perm_result:
            perm_id = perm_result[0]
            cursor.execute('SELECT role_id FROM RolePermission WHERE role_id = %s AND permission_id = %s',
                          (view_only_role_id, perm_id))
            if not cursor.fetchone():
                cursor.execute('INSERT INTO RolePermission (role_id, permission_id) VALUES (%s, %s)',
                              (view_only_role_id, perm_id))
    
    # Assign existing users to 'admin' role if they don't have a role
    # This ensures existing users maintain admin access
    cursor.execute('UPDATE User SET role_id = %s WHERE role_id IS NULL', (admin_role_id,))
    
    cursor.execute('SELECT COUNT(*) FROM User')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''INSERT INTO User (name, email, password, role_id) VALUES (%s, %s, %s, %s)''',
            ('admin', 'admin@example.com', hash_password('password'), admin_role_id))
    conn.commit()
    conn.close()
