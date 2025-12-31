import os
import hashlib
import base64
import secrets
import mysql.connector
import logging
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

def generate_api_key():
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)

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
        FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE SET NULL,
        FOREIGN KEY (subnet_id) REFERENCES Subnet(id) ON DELETE SET NULL
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
    # Initialize default device types only if table is empty
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
        conn.commit()  # Commit the inserts before querying
    
    # Add device_type_id column if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM Device LIKE 'device_type_id'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Device ADD COLUMN device_type_id INTEGER DEFAULT NULL')
    
    # Set default device_type_id for devices that don't have one
    # Use the first available device type, or leave NULL if no types exist
    cursor.execute('SELECT id FROM DeviceType ORDER BY id LIMIT 1')
    first_type_result = cursor.fetchone()
    if first_type_result:
        first_type_id = first_type_result[0]
        cursor.execute('UPDATE Device SET device_type_id = %s WHERE device_type_id IS NULL', (first_type_id,))
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
    
    # Add api_key column to User table if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM User LIKE 'api_key'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE User ADD COLUMN api_key VARCHAR(255) DEFAULT NULL UNIQUE')
    
    # Add 2FA columns to User table if they don't exist
    cursor.execute("SHOW COLUMNS FROM User LIKE 'totp_secret'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE User ADD COLUMN totp_secret VARCHAR(255) DEFAULT NULL')
    
    cursor.execute("SHOW COLUMNS FROM User LIKE 'totp_enabled'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE User ADD COLUMN totp_enabled BOOLEAN DEFAULT FALSE')
    
    cursor.execute("SHOW COLUMNS FROM User LIKE 'backup_codes'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE User ADD COLUMN backup_codes TEXT DEFAULT NULL')
    
    cursor.execute("SHOW COLUMNS FROM User LIKE 'two_fa_setup_complete'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE User ADD COLUMN two_fa_setup_complete BOOLEAN DEFAULT FALSE')
    
    # Add require_2fa column to Role table if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM Role LIKE 'require_2fa'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Role ADD COLUMN require_2fa BOOLEAN DEFAULT FALSE')
    
    # Ensure AuditLog foreign keys have ON DELETE SET NULL to preserve audit logs
    # This is critical - audit logs should NEVER be deleted, even when referenced entities are deleted
    try:
        # Check and update user_id foreign key
        cursor.execute('''
            SELECT CONSTRAINT_NAME 
            FROM information_schema.KEY_COLUMN_USAGE 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'AuditLog' 
            AND COLUMN_NAME = 'user_id' 
            AND REFERENCED_TABLE_NAME = 'User'
        ''')
        fk_user = cursor.fetchone()
        if fk_user:
            fk_name = fk_user[0]
            # Drop and recreate with ON DELETE SET NULL
            cursor.execute(f'ALTER TABLE AuditLog DROP FOREIGN KEY {fk_name}')
            cursor.execute('ALTER TABLE AuditLog ADD CONSTRAINT fk_auditlog_user FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE SET NULL')
    except mysql.connector.Error as e:
        # Foreign key might not exist or already be correct, continue
        if e.errno != 1025 and e.errno != 1091:  # Not "Cannot drop foreign key" or "Unknown key"
            logging.warning(f"Could not update AuditLog user_id foreign key: {e}")
    
    try:
        # Check and update subnet_id foreign key
        cursor.execute('''
            SELECT CONSTRAINT_NAME 
            FROM information_schema.KEY_COLUMN_USAGE 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'AuditLog' 
            AND COLUMN_NAME = 'subnet_id' 
            AND REFERENCED_TABLE_NAME = 'Subnet'
        ''')
        fk_subnet = cursor.fetchone()
        if fk_subnet:
            fk_name = fk_subnet[0]
            # Drop and recreate with ON DELETE SET NULL
            cursor.execute(f'ALTER TABLE AuditLog DROP FOREIGN KEY {fk_name}')
            cursor.execute('ALTER TABLE AuditLog ADD CONSTRAINT fk_auditlog_subnet FOREIGN KEY (subnet_id) REFERENCES Subnet(id) ON DELETE SET NULL')
    except mysql.connector.Error as e:
        # Foreign key might not exist or already be correct, continue
        if e.errno != 1025 and e.errno != 1091:  # Not "Cannot drop foreign key" or "Unknown key"
            logging.warning(f"Could not update AuditLog subnet_id foreign key: {e}")
    
    # Create Tag table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Tag (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL UNIQUE,
        color VARCHAR(7) DEFAULT '#6B7280',
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create DeviceTag junction table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DeviceTag (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        device_id INTEGER NOT NULL,
        tag_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_device_tag (device_id, tag_id),
        FOREIGN KEY (device_id) REFERENCES Device(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id) REFERENCES Tag(id) ON DELETE CASCADE
    )
    ''')
    
    # Create CustomFieldDefinition table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS CustomFieldDefinition (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        entity_type ENUM('device', 'subnet') NOT NULL,
        name VARCHAR(255) NOT NULL,
        field_key VARCHAR(255) NOT NULL UNIQUE,
        field_type VARCHAR(50) NOT NULL,
        required BOOLEAN DEFAULT FALSE,
        default_value TEXT,
        help_text TEXT,
        display_order INTEGER DEFAULT 0,
        validation_rules TEXT,
        searchable BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
    ''')
    
    # Add custom_fields column to Device table if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM Device LIKE 'custom_fields'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Device ADD COLUMN custom_fields TEXT DEFAULT NULL')
        # Initialize existing records with empty JSON object
        cursor.execute("UPDATE Device SET custom_fields = '{}' WHERE custom_fields IS NULL")
    
    # Add custom_fields column to Subnet table if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM Subnet LIKE 'custom_fields'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Subnet ADD COLUMN custom_fields TEXT DEFAULT NULL')
        # Initialize existing records with empty JSON object
        cursor.execute("UPDATE Subnet SET custom_fields = '{}' WHERE custom_fields IS NULL")
    
    # Add notes column to IPAddress table if it doesn't exist
    cursor.execute("SHOW COLUMNS FROM IPAddress LIKE 'notes'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE IPAddress ADD COLUMN notes TEXT DEFAULT NULL')
    
    # Add VLAN columns to Subnet table if they don't exist
    cursor.execute("SHOW COLUMNS FROM Subnet LIKE 'vlan_id'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Subnet ADD COLUMN vlan_id INTEGER DEFAULT NULL')
    
    cursor.execute("SHOW COLUMNS FROM Subnet LIKE 'vlan_description'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Subnet ADD COLUMN vlan_description VARCHAR(255) DEFAULT NULL')
    
    cursor.execute("SHOW COLUMNS FROM Subnet LIKE 'vlan_notes'")
    if not cursor.fetchone():
        cursor.execute('ALTER TABLE Subnet ADD COLUMN vlan_notes TEXT DEFAULT NULL')
    
    # Create FeatureFlags table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS FeatureFlags (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        feature_key VARCHAR(255) NOT NULL UNIQUE,
        enabled BOOLEAN DEFAULT TRUE,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
    ''')
    
    # Initialize default feature flags
    default_features = [
        ('racks', True, 'Enable rack management functionality'),
        ('ip_address_notes', True, 'Enable IP address notes/descriptions editing on subnet page'),
        ('device_tags', True, 'Enable device tagging functionality'),
        ('bulk_operations', True, 'Enable bulk operations for devices and IPs')
    ]
    
    for feature_key, enabled, description in default_features:
        cursor.execute('SELECT id FROM FeatureFlags WHERE feature_key = %s', (feature_key,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO FeatureFlags (feature_key, enabled, description) VALUES (%s, %s, %s)',
                          (feature_key, enabled, description))
    
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
        
        # Tag permissions
        ('view_tags', 'View tags', 'Tag'),
        ('add_tag', 'Add new tag', 'Tag'),
        ('edit_tag', 'Edit tag', 'Tag'),
        ('delete_tag', 'Delete tag', 'Tag'),
        ('assign_device_tag', 'Assign tag to device', 'Tag'),
        ('remove_device_tag', 'Remove tag from device', 'Tag'),
        
        # Custom Fields permissions
        ('view_custom_fields', 'View custom fields', 'Custom Fields'),
        ('manage_custom_fields', 'Manage custom fields (add, edit, delete)', 'Custom Fields'),
        
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
        'add_device_type', 'edit_device_type', 'delete_device_type',
        'view_tags', 'add_tag', 'edit_tag', 'delete_tag', 'assign_device_tag', 'remove_device_tag',
        'view_custom_fields', 'manage_custom_fields'
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
        'view_dhcp', 'view_help', 'view_tags', 'view_custom_fields'
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
    
    # Generate API keys for users that don't have one
    cursor.execute('SELECT id FROM User WHERE api_key IS NULL')
    users_without_api_key = cursor.fetchall()
    for (user_id,) in users_without_api_key:
        api_key = generate_api_key()
        cursor.execute('UPDATE User SET api_key = %s WHERE id = %s', (api_key, user_id))
    
    cursor.execute('SELECT COUNT(*) FROM User')
    if cursor.fetchone()[0] == 0:
        api_key = generate_api_key()
        cursor.execute('''INSERT INTO User (name, email, password, role_id, api_key) VALUES (%s, %s, %s, %s, %s)''',
            ('admin', 'admin@example.com', hash_password('password'), admin_role_id, api_key))
    
    # Create indexes for performance optimization
    logging.info("Creating database indexes for performance...")
    
    def create_index_if_not_exists(cursor, index_name, table_name, columns):
        """Helper function to create index if it doesn't exist"""
        try:
            # Check if index exists
            cursor.execute('''
                SELECT COUNT(*) FROM information_schema.statistics 
                WHERE table_schema = DATABASE() 
                AND table_name = %s 
                AND index_name = %s
            ''', (table_name, index_name))
            if cursor.fetchone()[0] == 0:
                cursor.execute(f'CREATE INDEX {index_name} ON {table_name}({columns})')
                logging.info(f"Created index {index_name}")
            else:
                logging.debug(f"Index {index_name} already exists")
        except mysql.connector.Error as e:
            logging.warning(f"Could not create index {index_name}: {e}")
    
    # IPAddress table indexes
    create_index_if_not_exists(cursor, 'idx_ipaddress_subnet_id', 'IPAddress', 'subnet_id')
    create_index_if_not_exists(cursor, 'idx_ipaddress_hostname', 'IPAddress', 'hostname')
    create_index_if_not_exists(cursor, 'idx_ipaddress_ip', 'IPAddress', 'ip')
    create_index_if_not_exists(cursor, 'idx_ipaddress_subnet_hostname', 'IPAddress', 'subnet_id, hostname')
    create_index_if_not_exists(cursor, 'idx_ipaddress_notes', 'IPAddress', 'notes(255)')
    
    # DeviceIPAddress table indexes
    create_index_if_not_exists(cursor, 'idx_deviceipaddress_device_id', 'DeviceIPAddress', 'device_id')
    create_index_if_not_exists(cursor, 'idx_deviceipaddress_ip_id', 'DeviceIPAddress', 'ip_id')
    create_index_if_not_exists(cursor, 'idx_deviceipaddress_device_ip', 'DeviceIPAddress', 'device_id, ip_id')
    
    # AuditLog table indexes
    create_index_if_not_exists(cursor, 'idx_auditlog_timestamp', 'AuditLog', 'timestamp')
    create_index_if_not_exists(cursor, 'idx_auditlog_user_id', 'AuditLog', 'user_id')
    create_index_if_not_exists(cursor, 'idx_auditlog_subnet_id', 'AuditLog', 'subnet_id')
    create_index_if_not_exists(cursor, 'idx_auditlog_action', 'AuditLog', 'action')
    create_index_if_not_exists(cursor, 'idx_auditlog_user_timestamp', 'AuditLog', 'user_id, timestamp')
    create_index_if_not_exists(cursor, 'idx_auditlog_subnet_timestamp', 'AuditLog', 'subnet_id, timestamp')
    
    # Subnet table indexes
    create_index_if_not_exists(cursor, 'idx_subnet_site', 'Subnet', 'site')
    create_index_if_not_exists(cursor, 'idx_subnet_site_name', 'Subnet', 'site, name')
    
    # DeviceTag table indexes
    create_index_if_not_exists(cursor, 'idx_devicetag_device_id', 'DeviceTag', 'device_id')
    create_index_if_not_exists(cursor, 'idx_devicetag_tag_id', 'DeviceTag', 'tag_id')
    
    # DHCPPool table indexes
    create_index_if_not_exists(cursor, 'idx_dhcppool_subnet_id', 'DHCPPool', 'subnet_id')
    
    # RackDevice table indexes
    create_index_if_not_exists(cursor, 'idx_rackdevice_rack_id', 'RackDevice', 'rack_id')
    create_index_if_not_exists(cursor, 'idx_rackdevice_device_id', 'RackDevice', 'device_id')
    create_index_if_not_exists(cursor, 'idx_rackdevice_rack_side', 'RackDevice', 'rack_id, side')
    
    # Device table indexes
    create_index_if_not_exists(cursor, 'idx_device_device_type_id', 'Device', 'device_type_id')
    
    # User table indexes (api_key already has UNIQUE index)
    create_index_if_not_exists(cursor, 'idx_user_role_id', 'User', 'role_id')
    
    # CustomFieldDefinition table indexes
    create_index_if_not_exists(cursor, 'idx_customfield_entity_type', 'CustomFieldDefinition', 'entity_type')
    create_index_if_not_exists(cursor, 'idx_customfield_field_key', 'CustomFieldDefinition', 'field_key')
    create_index_if_not_exists(cursor, 'idx_customfield_entity_order', 'CustomFieldDefinition', 'entity_type, display_order')
    
    logging.info("Database indexes created successfully")
    conn.commit()
    conn.close()
