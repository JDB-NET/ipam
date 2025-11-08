from flask import render_template, request, redirect, url_for, send_from_directory, send_file, session, abort, jsonify
from db import init_db, hash_password, get_db_connection, verify_password, generate_api_key
from ipaddress import ip_network
from functools import wraps
import os
import csv
from io import StringIO, BytesIO
import logging
import mysql.connector

app = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def has_permission(permission_name, user_id=None, conn=None):
    """Check if a user has a specific permission"""
    if user_id is None:
        user_id = session.get('user_id')
    if not user_id:
        return False
    
    close_conn = False
    if conn is None:
        from flask import current_app
        conn = get_db_connection(current_app)
        close_conn = True
    
    try:
        cursor = conn.cursor()
        # Get user's role
        cursor.execute('SELECT role_id FROM User WHERE id = %s', (user_id,))
        role_result = cursor.fetchone()
        if not role_result or not role_result[0]:
            return False
        
        role_id = role_result[0]
        
        # Check if role has the permission
        cursor.execute('''
            SELECT COUNT(*) FROM RolePermission rp
            JOIN Permission p ON rp.permission_id = p.id
            WHERE rp.role_id = %s AND p.name = %s
        ''', (role_id, permission_name))
        result = cursor.fetchone()
        return result[0] > 0 if result else False
    finally:
        if close_conn:
            conn.close()

def permission_required(permission_name):
    """Decorator to require a specific permission"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not has_permission(permission_name):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_from_api_key(api_key):
    """Get user from API key"""
    from flask import current_app
    with get_db_connection(current_app) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, email, role_id FROM User WHERE api_key = %s', (api_key,))
        result = cursor.fetchone()
        if result:
            return {
                'id': result[0],
                'name': result[1],
                'email': result[2],
                'role_id': result[3]
            }
    return None

def api_auth_required(f):
    """Decorator for API authentication using API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = None
        # Check for API key in header
        if 'X-API-Key' in request.headers:
            api_key = request.headers['X-API-Key']
        # Check for API key in query parameter
        elif 'api_key' in request.args:
            api_key = request.args.get('api_key')
        # Check for API key in Authorization header (Bearer token)
        elif 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                api_key = auth_header[7:]
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = get_user_from_api_key(api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Store user info in request context
        request.api_user = user
        return f(*args, **kwargs)
    return decorated_function

def api_permission_required(permission_name):
    """Decorator to require a specific permission for API endpoints"""
    def decorator(f):
        @wraps(f)
        @api_auth_required
        def decorated_function(*args, **kwargs):
            if not has_permission(permission_name, user_id=request.api_user['id']):
                return jsonify({'error': 'Permission denied'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def add_audit_log(user_id, action, details=None, subnet_id=None, conn=None):
    import datetime
    close_conn = False
    if conn is None:
        from flask import current_app
        conn = get_db_connection(current_app)
        close_conn = True
    cursor = conn.cursor()
    utc_now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    cursor.execute('''INSERT INTO AuditLog (user_id, action, details, subnet_id, timestamp) VALUES (%s, %s, %s, %s, %s)''',
                   (user_id, action, details, subnet_id, utc_now))
    if close_conn:
        conn.commit()
        conn.close()

def register_routes(app):
    logging.basicConfig(level=logging.INFO)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            from flask import current_app
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, password FROM User WHERE email = %s', (email,))
                user = cursor.fetchone()
            if user and verify_password(password, user[1]):
                session['logged_in'] = True
                session['user_id'] = user[0]
                logging.info(f"User {email} logged in successfully.")
                return redirect(url_for('index'))
            else:
                logging.info(f"Failed login attempt for email: {email}")
                error = 'Invalid email or password.'
        return render_with_user('login.html', error=error)

    @app.route('/logout')
    def logout():
        user_name = get_current_user_name()
        logging.info(f"User {user_name} logged out.")
        session.clear()
        return redirect(url_for('login'))

    @app.route('/')
    @permission_required('view_index')
    def index():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = cursor.fetchall()
        sites_subnets = {}
        for subnet in subnets:
            site = subnet[3] or 'Unassigned'
            if site not in sites_subnets:
                sites_subnets[site] = []
            sites_subnets[site].append({'id': subnet[0], 'name': subnet[1], 'cidr': subnet[2]})
        return render_with_user('index.html', sites_subnets=sites_subnets)

    @app.route('/devices')
    @permission_required('view_devices')
    def devices():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT Device.id, Device.name, DeviceType.icon_class FROM Device LEFT JOIN DeviceType ON Device.device_type_id = DeviceType.id''')
            devices = cursor.fetchall()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = cursor.fetchall()
            cursor.execute('SELECT DeviceIPAddress.device_id, IPAddress.id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id')
            device_ips = {}
            for row in cursor.fetchall():
                device_ips.setdefault(row[0], []).append((row[1], row[2]))
            sites_devices = {}
            for device in devices:
                cursor.execute('''SELECT Subnet.site FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id JOIN Subnet ON IPAddress.subnet_id = Subnet.id WHERE DeviceIPAddress.device_id = %s LIMIT 1''', (device[0],))
                site = cursor.fetchone()
                site = site[0] if site else 'Unassigned'
                if site not in sites_devices:
                    sites_devices[site] = []
                sites_devices[site].append({'id': device[0], 'name': device[1], 'icon_class': device[2]})
        return render_with_user('devices.html', sites_devices=sites_devices, device_ips=device_ips)

    @app.route('/add_device', methods=['GET', 'POST'])
    @permission_required('add_device')
    def add_device():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
        if request.method == 'POST':
            name = request.form['device_name']
            device_type_id = int(request.form['device_type'])
            user_name = get_current_user_name()
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO Device (name, device_type_id) VALUES (%s, %s)', (name, device_type_id))
                conn.commit()
            logging.info(f"User {user_name} added device '{name}' (type {device_type_id}).")
            return redirect(url_for('devices'))
        return render_with_user('add_device.html', device_types=device_types)

    @app.route('/device/<int:device_id>')
    @permission_required('view_device')
    def device(device_id):
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, description, device_type_id FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            cursor.execute('SELECT id, name FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = [dict(id=row[0], name=row[1], cidr=row[2], site=row[3]) for row in cursor.fetchall()]
            cursor.execute('''SELECT DeviceIPAddress.id as device_ip_id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id WHERE DeviceIPAddress.device_id = %s''', (device_id,))
            device_ips = [{'device_ip_id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
            available_ips_by_subnet = {}
            for subnet in subnets:
                cursor.execute('SELECT id, ip FROM IPAddress WHERE subnet_id = %s AND id NOT IN (SELECT ip_id FROM DeviceIPAddress)', (subnet['id'],))
                ips = [{'id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
                cursor.execute('SELECT start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s', (subnet['id'],))
                dhcp_row = cursor.fetchone()
                if dhcp_row:
                    start_ip, end_ip, excluded_ips = dhcp_row
                    excluded_list = [ip for ip in (excluded_ips or '').replace(' ', '').split(',') if ip]
                    in_range = False
                    filtered_ips = []
                    for ip_obj in ips:
                        ip = ip_obj['ip']
                        if ip == start_ip:
                            in_range = True
                        if ip in excluded_list or not (in_range and ip not in excluded_list):
                            filtered_ips.append(ip_obj)
                        if ip == end_ip:
                            in_range = False
                    ips = filtered_ips
                available_ips_by_subnet[subnet['id']] = ips
        return render_with_user('device.html', device={'id': device[0], 'name': device[1], 'description': device[2], 'device_type_id': device[3]}, subnets=subnets, device_ips=device_ips, available_ips_by_subnet=available_ips_by_subnet, device_types=device_types)

    @app.route('/update_device_type', methods=['POST'])
    @permission_required('edit_device')
    def update_device_type():
        device_id = request.form['device_id']
        device_type_id = request.form['device_type_id']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE Device SET device_type_id = %s WHERE id = %s', (device_type_id, device_id))
            conn.commit()
        logging.info(f"User {user_name} updated device {device_id} to type {device_type_id}.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/add_ip', methods=['POST'])
    @permission_required('add_device_ip')
    def device_add_ip(device_id):
        subnet_id = request.form['subnet_id']
        ip_id = request.form['ip_id']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, ip FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            all_ip_rows = cursor.fetchall()
            cursor.execute('SELECT ip_id FROM DeviceIPAddress')
            assigned_ip_ids = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
            dhcp_row = cursor.fetchone()
            if dhcp_row:
                start_ip, end_ip, excluded_ips = dhcp_row
                excluded_list = [x for x in (excluded_ips or '').replace(' ', '').split(',') if x]
                cursor.execute('SELECT ip, hostname FROM IPAddress WHERE id = %s', (ip_id,))
                ip_row = cursor.fetchone()
                if not ip_row:
                    raise Exception("The selected IP address is no longer available. Please refresh and try again.")
                ip = ip_row[0]
                hostname = ip_row[1]
                cursor.execute('SELECT start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
                dhcp_row = cursor.fetchone()
                if dhcp_row:
                    start_ip, end_ip, excluded_ips = dhcp_row
                    excluded_list = [x for x in (excluded_ips or '').replace(' ', '').split(',') if x]
                    if ip not in excluded_list:
                        cursor.execute('SELECT ip FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                        all_ips = [row[0] for row in cursor.fetchall()]
                        in_range = False
                        reserved_for_dhcp = False
                        for candidate_ip in all_ips:
                            if candidate_ip == start_ip:
                                in_range = True
                            if in_range and candidate_ip == ip:
                                reserved_for_dhcp = True
                                break
                            if candidate_ip == end_ip:
                                in_range = False
                        if reserved_for_dhcp:
                            raise Exception("This IP is reserved for DHCP and cannot be assigned to a device.")
            cursor.execute('INSERT INTO DeviceIPAddress (device_id, ip_id) VALUES (%s, %s)', (device_id, ip_id))
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device_name = cursor.fetchone()[0]
            cursor.execute('UPDATE IPAddress SET hostname = %s WHERE id = %s', (device_name, ip_id))
            cursor.execute('SELECT ip, subnet_id FROM IPAddress WHERE id = %s', (ip_id,))
            ip, subnet_id_val = cursor.fetchone()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id_val,))
            subnet_name, subnet_cidr = cursor.fetchone()
            details = f"Assigned IP {ip} ({subnet_name} {subnet_cidr}) to device {device_name}"
            add_audit_log(session['user_id'], 'device_add_ip', details, subnet_id_val, conn=conn)
            conn.commit()
        logging.info(f"User {user_name} assigned IP {ip} to device {device_id}.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/delete_ip', methods=['POST'])
    @permission_required('remove_device_ip')
    def device_delete_ip(device_id):
        device_ip_id = request.form['device_ip_id']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE id = %s', (device_ip_id,))
            ip_id = cursor.fetchone()[0]
            cursor.execute('SELECT ip, subnet_id FROM IPAddress WHERE id = %s', (ip_id,))
            ip, subnet_id_val = cursor.fetchone()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id_val,))
            subnet_name, subnet_cidr = cursor.fetchone()
            cursor.execute('SELECT device_id FROM DeviceIPAddress WHERE id = %s', (device_ip_id,))
            device_id_val = cursor.fetchone()[0]
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id_val,))
            device_name = cursor.fetchone()[0]
            details = f"Removed IP {ip} ({subnet_name} {subnet_cidr}) from device {device_name}"
            add_audit_log(session['user_id'], 'device_delete_ip', details, subnet_id_val, conn=conn)
            cursor.execute('DELETE FROM DeviceIPAddress WHERE id = %s', (device_ip_id,))
            cursor.execute('UPDATE IPAddress SET hostname = NULL WHERE id = %s', (ip_id,))
            conn.commit()
        logging.info(f"User {user_name} removed IP {ip} from device {device_id}.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/delete_device', methods=['POST'])
    @permission_required('delete_device')
    def delete_device():
        device_id = request.form['device_id']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device_row = cursor.fetchone()
            if device_row:
                device_name = device_row[0]
                add_audit_log(session['user_id'], 'delete_device', f"Deleted device {device_name}", conn=conn)
                cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
                ip_ids = [row[0] for row in cursor.fetchall()]
                if ip_ids:
                    cursor.executemany('UPDATE IPAddress SET hostname = NULL WHERE id = %s', [(ip_id,) for ip_id in ip_ids])
                cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
                cursor.execute('DELETE FROM Device WHERE id = %s', (device_id,))
                conn.commit()
        logging.info(f"User {user_name} deleted device '{device_name}'.")
        return redirect(url_for('devices'))

    @app.route('/subnet/<int:subnet_id>')
    @permission_required('view_subnet')
    def subnet(subnet_id):
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            cursor.execute('SELECT * FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_addresses = cursor.fetchall()
            cursor.execute('SELECT id, name, description FROM Device')
            devices = cursor.fetchall()
            device_name_map = {name.lower(): (id, description) for id, name, description in devices}
            ip_addresses_with_device = []
            for ip in ip_addresses:
                hostname = ip[2]
                device_id = None
                device_description = None
                if hostname:
                    match = device_name_map.get(hostname.lower())
                    if match:
                        device_id, device_description = match
                ip_addresses_with_device.append((ip[0], ip[1], hostname, device_id, device_description))
        return render_with_user('subnet.html', subnet={'id': subnet[0], 'name': subnet[1], 'cidr': subnet[2]}, ip_addresses=ip_addresses_with_device)

    @app.route('/add_subnet', methods=['POST'])
    @permission_required('add_subnet')
    def add_subnet():
        name = request.form['name']
        cidr = request.form['cidr']
        site = request.form['site']
        user_name = get_current_user_name()
        try:
            network = ip_network(cidr, strict=False)
            if network.prefixlen < 24:
                return render_with_user('admin.html', subnets=[], error='Subnet must be /24 or smaller (e.g., /24, /25, ... /32)')
        except Exception as e:
            return render_with_user('admin.html', subnets=[], error='Invalid CIDR format.')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Subnet (name, cidr, site) VALUES (%s, %s, %s)', (name, cidr, site))
            subnet_id = cursor.lastrowid
            ip_rows = [(str(ip), subnet_id) for ip in network.hosts()]
            cursor.executemany('INSERT INTO IPAddress (ip, subnet_id) VALUES (%s, %s)', ip_rows)
            add_audit_log(session['user_id'], 'add_subnet', f"Added subnet {name} ({cidr})", subnet_id, conn=conn)
            conn.commit()
        logging.info(f"User {user_name} added subnet '{name}' ({cidr}) at site '{site}'.")
        return redirect(url_for('admin'))

    @app.route('/edit_subnet', methods=['POST'])
    @permission_required('edit_subnet')
    def edit_subnet():
        subnet_id = request.form['subnet_id']
        name = request.form['name']
        cidr = request.form['cidr']
        site = request.form['site']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            old_subnet = cursor.fetchone()
            if old_subnet:
                old_name, old_cidr = old_subnet
                cursor.execute('UPDATE Subnet SET name = %s, cidr = %s, site = %s WHERE id = %s', (name, cidr, site, subnet_id))
                add_audit_log(session['user_id'], 'edit_subnet', f"Edited subnet from {old_name} ({old_cidr}) to {name} ({cidr}) at site {site}", subnet_id, conn=conn)
                conn.commit()
        logging.info(f"User {user_name} edited subnet {subnet_id}.")
        return redirect(url_for('admin'))

    @app.route('/delete_subnet', methods=['POST'])
    @permission_required('delete_subnet')
    def delete_subnet():
        subnet_id = request.form['subnet_id']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            add_audit_log(session['user_id'], 'delete_subnet', f"Deleted subnet {subnet[0]} ({subnet[1]})", subnet_id, conn=conn)
            cursor.execute('SELECT id FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_ids = [row[0] for row in cursor.fetchall()]
            if ip_ids:
                cursor.executemany('DELETE FROM DeviceIPAddress WHERE ip_id = %s', [(ip_id,) for ip_id in ip_ids])
                cursor.executemany('UPDATE AuditLog SET subnet_id=NULL WHERE subnet_id = %s', [(subnet_id,) for _ in ip_ids])
            cursor.execute('DELETE FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('DELETE FROM Subnet WHERE id = %s', (subnet_id,))
            conn.commit()
        logging.info(f"User {user_name} deleted subnet {subnet_id}.")
        return redirect(url_for('admin'))

    @app.route('/admin', methods=['GET', 'POST'])
    @permission_required('view_admin')
    def admin():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet ORDER BY site, name')
            subnets = [dict(id=row[0], name=row[1], cidr=row[2], site=row[3] or 'Unassigned') for row in cursor.fetchall()]
        return render_with_user('admin.html', subnets=subnets, 
                               can_add_subnet=has_permission('add_subnet'),
                               can_edit_subnet=has_permission('edit_subnet'),
                               can_delete_subnet=has_permission('delete_subnet'))

    @app.route('/users', methods=['GET', 'POST'])
    @permission_required('view_users')
    def users():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            error = None
            if request.method == 'POST':
                action = request.form['action']
                user_name = get_current_user_name()
                
                # User management actions
                if action == 'add_user':
                    if not has_permission('manage_users', conn=conn):
                        error = 'You do not have permission to add users.'
                    else:
                        name = request.form['name']
                        email = request.form['email']
                        password = hash_password(request.form['password'])
                        role_id = request.form.get('role_id')
                        if role_id:
                            api_key = generate_api_key()
                            cursor.execute('INSERT INTO User (name, email, password, role_id, api_key) VALUES (%s, %s, %s, %s, %s)', (name, email, password, role_id, api_key))
                        else:
                            api_key = generate_api_key()
                            cursor.execute('INSERT INTO User (name, email, password, api_key) VALUES (%s, %s, %s, %s)', (name, email, password, api_key))
                        logging.info(f"User {user_name} added user '{name}' ({email}).")
                        conn.commit()
                elif action == 'edit_user':
                    if not has_permission('manage_users', conn=conn):
                        error = 'You do not have permission to edit users.'
                    else:
                        user_id = request.form['user_id']
                        name = request.form['name']
                        email = request.form['email']
                        password = request.form.get('password', '')
                        role_id = request.form.get('role_id')
                        if password:
                            password = hash_password(password)
                            if role_id:
                                cursor.execute('UPDATE User SET name=%s, email=%s, password=%s, role_id=%s WHERE id=%s', (name, email, password, role_id, user_id))
                            else:
                                cursor.execute('UPDATE User SET name=%s, email=%s, password=%s WHERE id=%s', (name, email, password, user_id))
                        else:
                            if role_id:
                                cursor.execute('UPDATE User SET name=%s, email=%s, role_id=%s WHERE id=%s', (name, email, role_id, user_id))
                            else:
                                cursor.execute('UPDATE User SET name=%s, email=%s WHERE id=%s', (name, email, user_id))
                        logging.info(f"User {user_name} edited user {user_id}.")
                        conn.commit()
                elif action == 'delete_user':
                    if not has_permission('manage_users', conn=conn):
                        error = 'You do not have permission to delete users.'
                    else:
                        user_id = request.form['user_id']
                        cursor.execute('UPDATE User SET name=%s WHERE id=%s', ('Deleted User', user_id))
                        cursor.execute('UPDATE AuditLog SET user_id=NULL WHERE user_id=%s', (user_id,))
                        cursor.execute('DELETE FROM User WHERE id=%s', (user_id,))
                        logging.info(f"User {user_name} deleted user {user_id}.")
                        conn.commit()
                
                # Role management actions
                elif action == 'add_role':
                    if not has_permission('manage_roles', conn=conn):
                        error = 'You do not have permission to add roles.'
                    else:
                        role_name = request.form['role_name'].strip()
                        role_description = request.form.get('role_description', '').strip()
                        if not role_name:
                            error = 'Role name is required.'
                        else:
                            try:
                                cursor.execute('INSERT INTO Role (name, description) VALUES (%s, %s)', (role_name, role_description))
                                role_id = cursor.lastrowid
                                # Get selected permissions
                                permission_ids = request.form.getlist('permissions')
                                for perm_id in permission_ids:
                                    cursor.execute('INSERT INTO RolePermission (role_id, permission_id) VALUES (%s, %s)', (role_id, perm_id))
                                conn.commit()
                                logging.info(f"User {user_name} added role '{role_name}'.")
                            except mysql.connector.IntegrityError as e:
                                if e.errno == 1062:  # Duplicate entry
                                    error = f"Role '{role_name}' already exists."
                                else:
                                    raise
                elif action == 'edit_role':
                    if not has_permission('manage_roles', conn=conn):
                        error = 'You do not have permission to edit roles.'
                    else:
                        role_id = request.form['role_id']
                        role_name = request.form['role_name'].strip()
                        role_description = request.form.get('role_description', '').strip()
                        if not role_name:
                            error = 'Role name is required.'
                        else:
                            try:
                                cursor.execute('UPDATE Role SET name=%s, description=%s WHERE id=%s', (role_name, role_description, role_id))
                                # Update permissions
                                cursor.execute('DELETE FROM RolePermission WHERE role_id=%s', (role_id,))
                                permission_ids = request.form.getlist('permissions')
                                for perm_id in permission_ids:
                                    cursor.execute('INSERT INTO RolePermission (role_id, permission_id) VALUES (%s, %s)', (role_id, perm_id))
                                conn.commit()
                                logging.info(f"User {user_name} edited role {role_id}.")
                            except mysql.connector.IntegrityError as e:
                                if e.errno == 1062:  # Duplicate entry
                                    error = f"Role '{role_name}' already exists."
                                else:
                                    raise
                elif action == 'delete_role':
                    if not has_permission('manage_roles', conn=conn):
                        error = 'You do not have permission to delete roles.'
                    else:
                        role_id = request.form['role_id']
                        # Check if any users are using this role
                        cursor.execute('SELECT COUNT(*) FROM User WHERE role_id = %s', (role_id,))
                        user_count = cursor.fetchone()[0]
                        if user_count > 0:
                            cursor.execute('SELECT name FROM Role WHERE id = %s', (role_id,))
                            role_name = cursor.fetchone()[0]
                            error = f"Cannot delete role '{role_name}' because {user_count} user(s) are using it."
                        else:
                            cursor.execute('SELECT name FROM Role WHERE id = %s', (role_id,))
                            role_name = cursor.fetchone()[0]
                            cursor.execute('DELETE FROM Role WHERE id = %s', (role_id,))
                            conn.commit()
                            logging.info(f"User {user_name} deleted role '{role_name}'.")
                elif action == 'regenerate_api_key':
                    if not has_permission('manage_users', conn=conn):
                        error = 'You do not have permission to regenerate API keys.'
                    else:
                        user_id = request.form['user_id']
                        new_api_key = generate_api_key()
                        cursor.execute('UPDATE User SET api_key = %s WHERE id = %s', (new_api_key, user_id))
                        conn.commit()
                        logging.info(f"User {user_name} regenerated API key for user {user_id}.")
            
            # Get users with their roles and API keys
            cursor.execute('''
                SELECT u.id, u.name, u.email, r.id as role_id, r.name as role_name, u.api_key
                FROM User u
                LEFT JOIN Role r ON u.role_id = r.id
                ORDER BY u.name
            ''')
            users = cursor.fetchall()
            
            # Get all roles
            cursor.execute('SELECT id, name, description FROM Role ORDER BY name')
            roles = cursor.fetchall()
            
            # Get all permissions grouped by category
            cursor.execute('SELECT id, name, description, category FROM Permission ORDER BY category, name')
            permissions = cursor.fetchall()
            
            # Get permissions for each role
            role_permissions = {}
            for role in roles:
                role_id = role[0]
                cursor.execute('''
                    SELECT permission_id FROM RolePermission WHERE role_id = %s
                ''', (role_id,))
                role_permissions[role_id] = [row[0] for row in cursor.fetchall()]
        
        return render_with_user('users.html', users=users, roles=roles, permissions=permissions, role_permissions=role_permissions, error=error, 
                               can_manage_users=has_permission('manage_users'), can_manage_roles=has_permission('manage_roles'))

    @app.route('/audit')
    @permission_required('view_audit')
    def audit():
        PER_PAGE = 25
        page = int(request.args.get('page', 1))
        offset = (page - 1) * PER_PAGE
        user_id = request.args.get('user_id')
        subnet_id = request.args.get('subnet_id')
        action = request.args.get('action')
        device_name = request.args.get('device_name')
        query = '''SELECT AuditLog.id, COALESCE(User.name, 'Deleted User'), AuditLog.action, AuditLog.details, Subnet.name, AuditLog.timestamp FROM AuditLog LEFT JOIN User ON AuditLog.user_id = User.id LEFT JOIN Subnet ON AuditLog.subnet_id = Subnet.id WHERE 1=1'''
        params = []
        if user_id:
            query += ' AND AuditLog.user_id = %s'
            params.append(user_id)
        if subnet_id:
            query += ' AND AuditLog.subnet_id = %s'
            params.append(subnet_id)
        if action:
            query += ' AND AuditLog.action = %s'
            params.append(action)
        if device_name:
            query += ' AND AuditLog.details LIKE %s'
            params.append(f'%{device_name}%')
        count_query = 'SELECT COUNT(*) FROM (' + query + ') AS count_subquery'
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(count_query, params)
            total_logs = cursor.fetchone()[0]
            query += ' ORDER BY AuditLog.timestamp DESC LIMIT %s OFFSET %s'
            cursor.execute(query, params + [PER_PAGE, offset])
            logs = cursor.fetchall()
            cursor.execute('SELECT id, name FROM User')
            users = cursor.fetchall()
            cursor.execute('SELECT id, name FROM Subnet')
            subnets = cursor.fetchall()
            cursor.execute('SELECT DISTINCT action FROM AuditLog')
            actions = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT name FROM Device ORDER BY name')
            devices = cursor.fetchall()
        query_args = request.args.to_dict()
        total_pages = (total_logs + PER_PAGE - 1) // PER_PAGE
        return render_with_user('audit.html', logs=logs, users=users, subnets=subnets, actions=actions, devices=devices, page=page, total_pages=total_pages, query_args=query_args)

    @app.route('/get_available_ips')
    @permission_required('view_device')
    def get_available_ips():
        subnet_id = request.args.get('subnet_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT id, ip FROM IPAddress WHERE subnet_id = %s AND id NOT IN (SELECT ip_id FROM DeviceIPAddress) AND (hostname IS NULL OR hostname != 'DHCP')''', (subnet_id,))
            available_ips = [{'id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
        return {'available_ips': available_ips}

    @app.route('/rename_device', methods=['POST'])
    @permission_required('edit_device')
    def rename_device():
        device_id = request.form['device_id']
        new_name = request.form['new_name']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            old_name = cursor.fetchone()[0]
            cursor.execute('UPDATE Device SET name = %s WHERE id = %s', (new_name, device_id))
            cursor.execute('UPDATE IPAddress SET hostname = %s WHERE hostname = %s', (new_name, old_name))
            conn.commit()
            add_audit_log(session['user_id'], 'rename_device', f"Renamed device '{old_name}' to '{new_name}'", conn=conn)
        logging.info(f"User {user_name} renamed device {device_id} from '{old_name}' to '{new_name}'.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/update_device_description', methods=['POST'])
    @permission_required('edit_device')
    def update_device_description():
        device_id = request.form['device_id']
        description = request.form['description']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE Device SET description = %s WHERE id = %s', (description, device_id))
            conn.commit()
        logging.info(f"User {user_name} updated description for device {device_id}.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/subnet/<int:subnet_id>/export_csv')
    @permission_required('export_subnet_csv')
    def export_subnet_csv(subnet_id):
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            if not subnet:
                return 'Subnet not found', 404
            cursor.execute('SELECT * FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_addresses = cursor.fetchall()
            cursor.execute('SELECT id, name, description FROM Device')
            devices = cursor.fetchall()
            device_name_map = {name.lower(): (id, description) for id, name, description in devices}
            ip_addresses_with_device = []
            for ip in ip_addresses:
                hostname = ip[2]
                device_id = None
                device_description = None
                if hostname:
                    match = device_name_map.get(hostname.lower())
                    if match:
                        device_id, device_description = match
                ip_addresses_with_device.append((ip[0], ip[1], hostname, device_id, device_description))
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP Address', 'Hostname', 'Description'])
        for ip in ip_addresses_with_device:
            ip_addr = ip[1] or ''
            hostname = ip[2] or ''
            description = (ip[4] or '').split('\n')[0] if ip[4] else ''
            writer.writerow([ip_addr, hostname, description])
        csv_bytes = output.getvalue().encode('utf-8')
        output_bytes = BytesIO(csv_bytes)
        output_bytes.seek(0)
        filename = f"{subnet[1]}_{subnet[2]}_subnet.csv".replace(' ', '_')
        return send_file(
            output_bytes,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )

    @app.route('/subnet/<int:subnet_id>/dhcp', methods=['GET', 'POST'])
    @permission_required('view_dhcp')
    def dhcp_pool(subnet_id):
        error = None
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            dhcp_pool = None
            cursor.execute('''SELECT start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s''', (subnet_id,))
            row = cursor.fetchone()
            if row:
                dhcp_pool = {'start_ip': row[0], 'end_ip': row[1], 'excluded_ips': row[2] if len(row) > 2 else ''}
            if request.method == 'POST':
                if not has_permission('configure_dhcp', conn=conn):
                    error = 'You do not have permission to configure DHCP pools.'
                else:
                    user_name = get_current_user_name()
                    if 'remove' in request.form:
                        cursor.execute('DELETE FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
                        cursor.execute('UPDATE IPAddress SET hostname=NULL WHERE subnet_id=%s AND hostname="DHCP"', (subnet_id,))
                        conn.commit()
                        dhcp_pool = None
                        add_audit_log(session['user_id'], 'dhcp_pool_remove', f"Removed DHCP pool for subnet {subnet[1]} ({subnet[2]})", subnet_id, conn=conn)
                    else:
                        start_ip = request.form['start_ip']
                        end_ip = request.form['end_ip']
                        excluded_ips = request.form.get('excluded_ips', '').replace(' ', '')
                        excluded_list = [ip for ip in excluded_ips.split(',') if ip]
                        cursor.execute('SELECT ip FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                        all_ips = [row[0] for row in cursor.fetchall()]
                        if start_ip not in all_ips or end_ip not in all_ips:
                            error = 'Start and End IP must be within the subnet.'
                        else:
                            cursor.execute('UPDATE IPAddress SET hostname=NULL WHERE subnet_id=%s AND hostname="DHCP"', (subnet_id,))
                            if dhcp_pool:
                                cursor.execute('''UPDATE DHCPPool SET start_ip = %s, end_ip = %s, excluded_ips = %s WHERE subnet_id = %s''', (start_ip, end_ip, excluded_ips, subnet_id))
                                action = 'dhcp_pool_update'
                                details = f"Updated DHCP pool for subnet {subnet[1]} ({subnet[2]}): {start_ip} - {end_ip}, excluded: {excluded_ips}"
                            else:
                                cursor.execute('''INSERT INTO DHCPPool (subnet_id, start_ip, end_ip, excluded_ips) VALUES (%s, %s, %s, %s)''', (subnet_id, start_ip, end_ip, excluded_ips))
                                action = 'dhcp_pool_create'
                                details = f"Created DHCP pool for subnet {subnet[1]} ({subnet[2]}): {start_ip} - {end_ip}, excluded: {excluded_ips}"
                            in_range = False
                            for ip in all_ips:
                                if ip == start_ip:
                                    in_range = True
                                if in_range and ip not in excluded_list:
                                    cursor.execute('UPDATE IPAddress SET hostname="DHCP" WHERE subnet_id=%s AND ip=%s', (subnet_id, ip))
                                if ip == end_ip:
                                    break
                            conn.commit()
                            dhcp_pool = {'start_ip': start_ip, 'end_ip': end_ip, 'excluded_ips': excluded_ips}
                            add_audit_log(session['user_id'], action, details, subnet_id, conn=conn)
            return render_with_user('dhcp.html', subnet={'id': subnet[0], 'name': subnet[1]}, dhcp_pool=dhcp_pool, error=error)

    @app.route('/device_type_stats')
    @permission_required('view_device_type_stats')
    def device_type_stats():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DeviceType.name, DeviceType.icon_class, COUNT(Device.id) as count
                FROM DeviceType
                LEFT JOIN Device ON Device.device_type_id = DeviceType.id
                GROUP BY DeviceType.id, DeviceType.name, DeviceType.icon_class
                ORDER BY DeviceType.name
            ''')
            stats = cursor.fetchall()
        return render_with_user('device_type_stats.html', stats=stats)

    @app.route('/device_types', methods=['GET', 'POST'])
    @permission_required('view_device_types')
    def device_types():
        from flask import current_app
        error = None
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            if request.method == 'POST':
                action = request.form['action']
                user_name = get_current_user_name()
                if action == 'add':
                    if not has_permission('add_device_type', conn=conn):
                        error = 'You do not have permission to add device types.'
                    else:
                        name = request.form['name'].strip()
                        icon_class = request.form['icon_class'].strip()
                        if not name:
                            error = 'Device type name is required.'
                        elif not icon_class:
                            error = 'Icon class is required.'
                        else:
                            try:
                                cursor.execute('INSERT INTO DeviceType (name, icon_class) VALUES (%s, %s)', (name, icon_class))
                                conn.commit()
                                logging.info(f"User {user_name} added device type '{name}' with icon '{icon_class}'.")
                            except mysql.connector.IntegrityError as e:
                                if e.errno == 1062:  # Duplicate entry
                                    error = f"Device type '{name}' already exists."
                                else:
                                    raise
                elif action == 'edit':
                    if not has_permission('edit_device_type', conn=conn):
                        error = 'You do not have permission to edit device types.'
                    else:
                        device_type_id = request.form['device_type_id']
                        name = request.form['name'].strip()
                        icon_class = request.form['icon_class'].strip()
                        if not name:
                            error = 'Device type name is required.'
                        elif not icon_class:
                            error = 'Icon class is required.'
                        else:
                            try:
                                cursor.execute('UPDATE DeviceType SET name = %s, icon_class = %s WHERE id = %s', (name, icon_class, device_type_id))
                                conn.commit()
                                logging.info(f"User {user_name} edited device type {device_type_id} to '{name}' with icon '{icon_class}'.")
                            except mysql.connector.IntegrityError as e:
                                if e.errno == 1062:  # Duplicate entry
                                    error = f"Device type '{name}' already exists."
                                else:
                                    raise
                elif action == 'delete':
                    if not has_permission('delete_device_type', conn=conn):
                        error = 'You do not have permission to delete device types.'
                    else:
                        device_type_id = request.form['device_type_id']
                        # Check if any devices are using this device type
                        cursor.execute('SELECT COUNT(*) FROM Device WHERE device_type_id = %s', (device_type_id,))
                        device_count = cursor.fetchone()[0]
                        if device_count > 0:
                            cursor.execute('SELECT name FROM DeviceType WHERE id = %s', (device_type_id,))
                            device_type_name = cursor.fetchone()[0]
                            error = f"Cannot delete device type '{device_type_name}' because {device_count} device(s) are using it."
                        else:
                            cursor.execute('SELECT name FROM DeviceType WHERE id = %s', (device_type_id,))
                            device_type_name = cursor.fetchone()[0]
                            cursor.execute('DELETE FROM DeviceType WHERE id = %s', (device_type_id,))
                            conn.commit()
                            logging.info(f"User {user_name} deleted device type '{device_type_name}'.")
            cursor.execute('SELECT id, name, icon_class FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
        return render_with_user('device_types.html', device_types=device_types, error=error)

    @app.route('/devices/type/<device_type>')
    @permission_required('view_devices_by_type')
    def devices_by_type(device_type):
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, icon_class FROM DeviceType WHERE name = %s', (device_type,))
            row = cursor.fetchone()
            if not row:
                return f"Device type '{device_type}' not found", 404
            device_type_id, icon_class = row
            cursor.execute('''
                SELECT DISTINCT Device.id, Device.name, Device.description, Subnet.site
                FROM Device
                LEFT JOIN DeviceIPAddress ON Device.id = DeviceIPAddress.device_id
                LEFT JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id
                LEFT JOIN Subnet ON IPAddress.subnet_id = Subnet.id
                WHERE Device.device_type_id = %s
            ''', (device_type_id,))
            devices = cursor.fetchall()
            seen_ids = set()
            site_devices = {}
            for device_id, name, description, site in devices:
                if device_id in seen_ids:
                    continue
                seen_ids.add(device_id)
                site = site or 'Unassigned'
                if site not in site_devices:
                    site_devices[site] = []
                site_devices[site].append({'id': device_id, 'name': name, 'description': description})
        return render_with_user('devices_by_type.html', device_type=device_type, icon_class=icon_class, site_devices=site_devices)

    @app.route('/racks')
    @permission_required('view_racks')
    def racks():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM Rack')
            racks = cursor.fetchall()
            rack_ids = [rack['id'] for rack in racks]
            usage = {rack_id: 0 for rack_id in rack_ids}
            if rack_ids:
                format_strings = ','.join(['%s'] * len(rack_ids))
                cursor.execute(f'SELECT rack_id, COUNT(*) as used FROM RackDevice WHERE rack_id IN ({format_strings}) AND side = %s GROUP BY rack_id', tuple(rack_ids) + ('front',))
                for row in cursor.fetchall():
                    usage[row['rack_id']] = row['used']
            for rack in racks:
                rack['used_u'] = usage.get(rack['id'], 0)
                rack['percent_full'] = int((rack['used_u'] / rack['height_u']) * 100) if rack['height_u'] else 0
        return render_with_user('racks.html', racks=racks)

    @app.route('/rack/add', methods=['GET', 'POST'])
    @permission_required('add_rack')
    def add_rack():
        from flask import current_app
        if request.method == 'POST':
            name = request.form['name']
            site = request.form['site']
            height_u = int(request.form['height_u'])
            user_name = get_current_user_name()
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO Rack (name, site, height_u) VALUES (%s, %s, %s)', (name, site, height_u))
                rack_id = cursor.lastrowid
                add_audit_log(session['user_id'], 'add_rack', f"Added rack '{name}' at site '{site}' ({height_u}U)", conn=conn)
                conn.commit()
            logging.info(f"User {user_name} added rack '{name}' at site '{site}' ({height_u}U).")
            return redirect(url_for('racks'))
        return render_with_user('add_rack.html')

    @app.route('/rack/<int:rack_id>')
    @permission_required('view_rack')
    def rack(rack_id):
        from flask import current_app, request
        side = request.args.get('side', 'front')
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return 'Rack not found', 404
            cursor.execute('SELECT * FROM RackDevice WHERE rack_id = %s', (rack_id,))
            rack_devices = cursor.fetchall()
            device_ids = [rd['device_id'] for rd in rack_devices if rd['device_id']]
            device_names = {}
            if device_ids:
                format_strings = ','.join(['%s'] * len(device_ids))
                cursor.execute(f'SELECT id, name FROM Device WHERE id IN ({format_strings})', tuple(device_ids))
                for row in cursor.fetchall():
                    device_names[row['id']] = row['name']
            for rd in rack_devices:
                if rd['device_id']:
                    rd['device_name'] = device_names.get(rd['device_id'], 'Unknown')
                else:
                    rd['device_name'] = rd['nonnet_device_name']
            cursor.execute('''
                SELECT DISTINCT Device.id, Device.name, Device.device_type_id, Device.description
                FROM Device
                JOIN DeviceIPAddress ON Device.id = DeviceIPAddress.device_id
                JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id
                JOIN Subnet ON IPAddress.subnet_id = Subnet.id
                WHERE Device.device_type_id NOT IN (2, 6)
                  AND Subnet.site = %s
            ''', (rack['site'],))
            site_devices = cursor.fetchall()
        return render_with_user('rack.html', rack=rack, rack_devices=rack_devices, site_devices=site_devices, current_side=side)

    @app.route('/rack/<int:rack_id>/add_device', methods=['POST'])
    @permission_required('add_device_to_rack')
    def rack_add_device(rack_id):
        device_id = int(request.form['device_id'])
        position_u = int(request.form['position_u'])
        side = request.form['side']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT height_u FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return 'Rack not found', 404
            if position_u < 1 or position_u > rack['height_u']:
                cursor.execute('SELECT * FROM RackDevice WHERE rack_id = %s', (rack_id,))
                rack_devices = cursor.fetchall()
                device_ids = [rd['device_id'] for rd in rack_devices]
                device_names = {}
                if device_ids:
                    format_strings = ','.join(['%s'] * len(device_ids))
                    cursor.execute(f'SELECT id, name FROM Device WHERE id IN ({format_strings})', tuple(device_ids))
                    for row in cursor.fetchall():
                        device_names[row['id']] = row['name']
                for rd in rack_devices:
                    rd['device_name'] = device_names.get(rd['device_id'], 'Unknown')
                cursor.execute('SELECT id, name, device_type_id FROM Device')
                all_devices = cursor.fetchall()
                site_devices = [d for d in all_devices if d['device_type_id'] not in (2, 6)]
                error = f"Invalid U position: {position_u}. Rack is {rack['height_u']}U tall."
                return render_with_user('rack.html', rack=rack, rack_devices=rack_devices, site_devices=site_devices, current_side=side, error=error)
            cursor.execute('SELECT COUNT(*) FROM RackDevice WHERE rack_id = %s AND position_u = %s AND side = %s', (rack_id, position_u, side))
            if cursor.fetchone()['COUNT(*)'] > 0:
                cursor.execute('SELECT * FROM RackDevice WHERE rack_id = %s', (rack_id,))
                rack_devices = cursor.fetchall()
                device_ids = [rd['device_id'] for rd in rack_devices]
                device_names = {}
                if device_ids:
                    format_strings = ','.join(['%s'] * len(device_ids))
                    cursor.execute(f'SELECT id, name FROM Device WHERE id IN ({format_strings})', tuple(device_ids))
                    for row in cursor.fetchall():
                        device_names[row['id']] = row['name']
                for rd in rack_devices:
                    rd['device_name'] = device_names.get(rd['device_id'], 'Unknown')
                cursor.execute('SELECT id, name, device_type_id FROM Device')
                all_devices = cursor.fetchall()
                site_devices = [d for d in all_devices if d['device_type_id'] not in (2, 6)]
                error = f"U{position_u} on the {side} is already occupied."
                return render_with_user('rack.html', rack=rack, rack_devices=rack_devices, site_devices=site_devices, current_side=side, error=error)
            cursor.execute('INSERT INTO RackDevice (rack_id, device_id, position_u, side) VALUES (%s, %s, %s, %s)', (rack_id, device_id, position_u, side))
            cursor2 = conn.cursor()
            cursor2.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device_name = cursor2.fetchone()
            cursor2.execute('SELECT name FROM Rack WHERE id = %s', (rack_id,))
            rack_name = cursor2.fetchone()
            add_audit_log(session['user_id'], 'rack_add_device', f"Assigned device '{device_name[0] if device_name else device_id}' to rack '{rack_name[0] if rack_name else rack_id}' U{position_u} ({side})", conn=conn)
            conn.commit()
        logging.info(f"User {user_name} assigned device {device_id} to rack {rack_id} at U{position_u} ({side}).")
        return redirect(url_for('rack', rack_id=rack_id))

    @app.route('/rack/<int:rack_id>/add_nonnet_device', methods=['POST'])
    @permission_required('add_nonnet_device_to_rack')
    def rack_add_nonnet_device(rack_id):
        device_name = request.form['device_name']
        position_u = int(request.form['position_u'])
        side = request.form['side']
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT height_u FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return 'Rack not found', 404
            if position_u < 1 or position_u > rack['height_u']:
                error = f"Invalid U position: {position_u}. Rack is {rack['height_u']}U tall."
                cursor.execute('SELECT * FROM RackDevice WHERE rack_id = %s', (rack_id,))
                rack_devices = cursor.fetchall()
                device_ids = [rd['device_id'] for rd in rack_devices if rd['device_id']]
                device_names = {}
                if device_ids:
                    format_strings = ','.join(['%s'] * len(device_ids))
                    cursor.execute(f'SELECT id, name FROM Device WHERE id IN ({format_strings})', tuple(device_ids))
                    for row in cursor.fetchall():
                        device_names[row['id']] = row['name']
                for rd in rack_devices:
                    if rd['device_id']:
                        rd['device_name'] = device_names.get(rd['device_id'], 'Unknown')
                    else:
                        rd['device_name'] = rd['nonnet_device_name']
                cursor.execute('SELECT id, name, device_type_id FROM Device WHERE device_type_id NOT IN (2, 6)')
                site_devices = cursor.fetchall()
                return render_with_user('rack.html', rack=rack, rack_devices=rack_devices, site_devices=site_devices, current_side=side, error=error)
            cursor.execute('SELECT COUNT(*) FROM RackDevice WHERE rack_id = %s AND position_u = %s AND side = %s', (rack_id, position_u, side))
            if cursor.fetchone()['COUNT(*)'] > 0:
                error = f"U{position_u} on the {side} is already occupied."
                cursor.execute('SELECT * FROM RackDevice WHERE rack_id = %s', (rack_id,))
                rack_devices = cursor.fetchall()
                device_ids = [rd['device_id'] for rd in rack_devices if rd['device_id']]
                device_names = {}
                if device_ids:
                    format_strings = ','.join(['%s'] * len(device_ids))
                    cursor.execute(f'SELECT id, name FROM Device WHERE id IN ({format_strings})', tuple(device_ids))
                    for row in cursor.fetchall():
                        device_names[row['id']] = row['name']
                for rd in rack_devices:
                    if rd['device_id']:
                        rd['device_name'] = device_names.get(rd['device_id'], 'Unknown')
                    else:
                        rd['device_name'] = rd['nonnet_device_name']
                cursor.execute('SELECT id, name, device_type_id FROM Device WHERE device_type_id NOT IN (2, 6)')
                site_devices = cursor.fetchall()
                return render_with_user('rack.html', rack=rack, rack_devices=rack_devices, site_devices=site_devices, current_side=side, error=error)
            cursor.execute('INSERT INTO RackDevice (rack_id, device_id, position_u, side, nonnet_device_name) VALUES (%s, NULL, %s, %s, %s)', (rack_id, position_u, side, device_name))
            add_audit_log(session['user_id'], 'rack_add_nonnet_device', f"Added non-networked device '{device_name}' to rack '{rack_id}' U{position_u} ({side})", conn=conn)
            conn.commit()
        logging.info(f"User {user_name} added non-networked device '{device_name}' to rack {rack_id} at U{position_u} ({side}).")
        return redirect(url_for('rack', rack_id=rack_id))

    @app.route('/rack/<int:rack_id>/remove_device', methods=['POST'])
    @permission_required('remove_device_from_rack')
    def rack_remove_device(rack_id):
        rack_device_id = int(request.form['rack_device_id'])
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT device_id, nonnet_device_name, position_u, side FROM RackDevice WHERE id = %s', (rack_device_id,))
            rd = cursor.fetchone()
            if rd['device_id']:
                cursor.execute('SELECT name FROM Device WHERE id = %s', (rd['device_id'],))
                device_name_row = cursor.fetchone()
                device_label = device_name_row['name'] if device_name_row and 'name' in device_name_row else rd['device_id']
            else:
                device_label = rd['nonnet_device_name']
            cursor.execute('SELECT name FROM Rack WHERE id = %s', (rack_id,))
            rack_name_row = cursor.fetchone()
            rack_label = rack_name_row['name'] if rack_name_row and 'name' in rack_name_row else rack_id
            add_audit_log(session['user_id'], 'rack_remove_device', f"Removed device '{device_label}' from rack '{rack_label}' U{rd['position_u']} ({rd['side']})", conn=conn)
            cursor.execute('DELETE FROM RackDevice WHERE id = %s', (rack_device_id,))
            conn.commit()
        logging.info(f"User {user_name} removed device '{device_label}' from rack {rack_label} at U{rd['position_u']} ({rd['side']}).")
        return redirect(url_for('rack', rack_id=rack_id))

    @app.route('/rack/<int:rack_id>/delete', methods=['POST'])
    @permission_required('delete_rack')
    def delete_rack(rack_id):
        user_name = get_current_user_name()
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Rack WHERE id = %s', (rack_id,))
            rack_name = cursor.fetchone()
            cursor.execute('DELETE FROM Rack WHERE id = %s', (rack_id,))
            add_audit_log(session['user_id'], 'delete_rack', f"Deleted rack '{rack_name[0] if rack_name else rack_id}'", conn=conn)
            conn.commit()
        logging.info(f"User {user_name} deleted rack {rack_id}.")
        return redirect(url_for('racks'))

    @app.route('/rack/<int:rack_id>/export_csv')
    @permission_required('export_rack_csv')
    def export_rack_csv(rack_id):
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return 'Rack not found', 404
            cursor.execute('SELECT * FROM RackDevice WHERE rack_id = %s', (rack_id,))
            rack_devices = cursor.fetchall()
            device_ids = [rd['device_id'] for rd in rack_devices]
            device_names = {}
            if device_ids:
                format_strings = ','.join(['%s'] * len(device_ids))
                cursor.execute(f'SELECT id, name FROM Device WHERE id IN ({format_strings})', tuple(device_ids))
                for row in cursor.fetchall():
                    device_names[row['id']] = row['name']
            for rd in rack_devices:
                rd['device_name'] = device_names.get(rd['device_id'], 'Unknown')
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([f"Rack: {rack['name']} ({rack['height_u']}U, {rack['site']})"])
            writer.writerow([])
            for side in ['front', 'back']:
                writer.writerow([side.capitalize()])
                writer.writerow(['U', 'Device'])
                for u in range(rack['height_u'], 0, -1):
                    found = False
                    for rd in rack_devices:
                        if rd['position_u'] == u and rd['side'] == side:
                            writer.writerow([u, rd['device_name']])
                            found = True
                            break
                    if not found:
                        writer.writerow([u, ''])
                writer.writerow([])
            csv_bytes = output.getvalue().encode('utf-8')
            output_bytes = BytesIO(csv_bytes)
            output_bytes.seek(0)
            filename = f"{rack['name']}_rack.csv".replace(' ', '_')
            return send_file(
                output_bytes,
                mimetype='text/csv',
                as_attachment=True,
                download_name=filename
            )

    @app.route('/help')
    @permission_required('view_help')
    def help():
        return render_with_user('help.html')

    # ========== API ROUTES ==========
    
    @app.route('/api/v1/info', methods=['GET'])
    @api_auth_required
    def api_info():
        """Get API information and authenticated user info"""
        return jsonify({
            'api_version': '1.0',
            'user': {
                'id': request.api_user['id'],
                'name': request.api_user['name'],
                'email': request.api_user['email']
            }
        })
    
    # Devices API
    @app.route('/api/v1/devices', methods=['GET'])
    @api_permission_required('view_devices')
    def api_devices():
        """Get all devices"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT d.id, d.name, d.description, dt.name as device_type, dt.icon_class
                FROM Device d
                LEFT JOIN DeviceType dt ON d.device_type_id = dt.id
                ORDER BY d.name
            ''')
            devices = cursor.fetchall()
            for device in devices:
                cursor.execute('''
                    SELECT ip.id, ip.ip, ip.hostname, s.id as subnet_id, s.name as subnet_name, s.cidr, s.site
                    FROM DeviceIPAddress dia
                    JOIN IPAddress ip ON dia.ip_id = ip.id
                    JOIN Subnet s ON ip.subnet_id = s.id
                    WHERE dia.device_id = %s
                ''', (device['id'],))
                device['ip_addresses'] = cursor.fetchall()
        return jsonify({'devices': devices})
    
    @app.route('/api/v1/devices/<int:device_id>', methods=['GET'])
    @api_permission_required('view_device')
    def api_device(device_id):
        """Get a specific device"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT d.id, d.name, d.description, dt.name as device_type, dt.icon_class
                FROM Device d
                LEFT JOIN DeviceType dt ON d.device_type_id = dt.id
                WHERE d.id = %s
            ''', (device_id,))
            device = cursor.fetchone()
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            cursor.execute('''
                SELECT ip.id, ip.ip, ip.hostname, s.id as subnet_id, s.name as subnet_name, s.cidr, s.site
                FROM DeviceIPAddress dia
                JOIN IPAddress ip ON dia.ip_id = ip.id
                JOIN Subnet s ON ip.subnet_id = s.id
                WHERE dia.device_id = %s
            ''', (device_id,))
            device['ip_addresses'] = cursor.fetchall()
        return jsonify(device)
    
    @app.route('/api/v1/devices', methods=['POST'])
    @api_permission_required('add_device')
    def api_add_device():
        """Create a new device"""
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Device name is required'}), 400
        
        name = data['name']
        description = data.get('description', '')
        device_type_id = data.get('device_type_id', 1)
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Device (name, description, device_type_id) VALUES (%s, %s, %s)',
                          (name, description, device_type_id))
            device_id = cursor.lastrowid
            add_audit_log(request.api_user['id'], 'add_device', f"Added device {name}", conn=conn)
            conn.commit()
        return jsonify({'id': device_id, 'name': name, 'description': description, 'device_type_id': device_type_id}), 201
    
    @app.route('/api/v1/devices/<int:device_id>', methods=['PUT'])
    @api_permission_required('edit_device')
    def api_update_device(device_id):
        """Update a device"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, description, device_type_id FROM Device WHERE id = %s', (device_id,))
            current = cursor.fetchone()
            if not current:
                return jsonify({'error': 'Device not found'}), 404
            current_name, current_description, current_device_type = current
            
            updates = []
            values = []
            rename = False
            new_name = current_name
            if 'name' in data:
                new_name = data['name']
                if new_name != current_name:
                    updates.append('name = %s')
                    values.append(new_name)
                    rename = True
            if 'description' in data and data['description'] != current_description:
                updates.append('description = %s')
                values.append(data['description'])
            if 'device_type_id' in data and data['device_type_id'] != current_device_type:
                updates.append('device_type_id = %s')
                values.append(data['device_type_id'])
            
            if not updates:
                return jsonify({'error': 'No changes to apply'}), 400
            
            values.append(device_id)
            cursor.execute(f'UPDATE Device SET {", ".join(updates)} WHERE id = %s', values)
            
            if rename:
                cursor.execute('UPDATE IPAddress SET hostname = %s WHERE hostname = %s', (new_name, current_name))
                add_audit_log(request.api_user['id'], 'rename_device', f"Renamed device '{current_name}' to '{new_name}'", conn=conn)
            
            conn.commit()
        return jsonify({'message': 'Device updated successfully', 'device': {'id': device_id, 'name': new_name}})
    
    @app.route('/api/v1/devices/<int:device_id>', methods=['DELETE'])
    @api_permission_required('delete_device')
    def api_delete_device(device_id):
        """Delete a device"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            device_name = device[0]
            cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
            ip_ids = [row[0] for row in cursor.fetchall()]
            if ip_ids:
                cursor.executemany('UPDATE IPAddress SET hostname = NULL WHERE id = %s', [(ip_id,) for ip_id in ip_ids])
            cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
            cursor.execute('DELETE FROM Device WHERE id = %s', (device_id,))
            add_audit_log(request.api_user['id'], 'delete_device', f"Deleted device {device_name}", conn=conn)
            conn.commit()
        return jsonify({'message': 'Device deleted successfully', 'device': {'id': device_id, 'name': device_name}})
    
    @app.route('/api/v1/devices/<int:device_id>/ips', methods=['POST'])
    @api_permission_required('add_device_ip')
    def api_add_device_ip(device_id):
        """Add an IP address to a device"""
        data = request.get_json()
        if not data or 'ip_id' not in data:
            return jsonify({'error': 'ip_id is required'}), 400
        
        ip_id = data['ip_id']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name FROM Device WHERE id = %s', (device_id,))
            device_row = cursor.fetchone()
            if not device_row:
                return jsonify({'error': 'Device not found'}), 404
            device_name = device_row[1]

            cursor.execute('SELECT ip, subnet_id FROM IPAddress WHERE id = %s', (ip_id,))
            ip_row = cursor.fetchone()
            if not ip_row:
                return jsonify({'error': 'IP address not found'}), 404
            ip, subnet_id = ip_row

            cursor.execute('SELECT id FROM DeviceIPAddress WHERE ip_id = %s', (ip_id,))
            if cursor.fetchone():
                return jsonify({'error': 'IP address already assigned to a device'}), 400

            cursor.execute('SELECT start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
            dhcp_row = cursor.fetchone()
            if dhcp_row:
                start_ip, end_ip, excluded_ips = dhcp_row
                excluded_list = [x for x in (excluded_ips or '').replace(' ', '').split(',') if x]
                if ip not in excluded_list:
                    cursor.execute('SELECT ip FROM IPAddress WHERE subnet_id = %s ORDER BY ip', (subnet_id,))
                    all_ips = [row[0] for row in cursor.fetchall()]
                    in_range = False
                    reserved_for_dhcp = False
                    for candidate_ip in all_ips:
                        if candidate_ip == start_ip:
                            in_range = True
                        if in_range and candidate_ip == ip:
                            reserved_for_dhcp = True
                            break
                        if candidate_ip == end_ip:
                            if candidate_ip == ip:
                                reserved_for_dhcp = True
                            in_range = False
                    if reserved_for_dhcp:
                        return jsonify({'error': 'This IP is reserved for DHCP and cannot be assigned to a device'}), 400

            cursor.execute('INSERT INTO DeviceIPAddress (device_id, ip_id) VALUES (%s, %s)', (device_id, ip_id))
            cursor.execute('UPDATE IPAddress SET hostname = %s WHERE id = %s', (device_name, ip_id))
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet_row = cursor.fetchone()
            if subnet_row:
                subnet_name, subnet_cidr = subnet_row
                details = f"Assigned IP {ip} ({subnet_name} {subnet_cidr}) to device {device_name}"
            else:
                details = f"Assigned IP {ip} to device {device_name}"
            add_audit_log(request.api_user['id'], 'device_add_ip', details, subnet_id, conn=conn)
            conn.commit()
        return jsonify({'message': 'IP address added to device successfully', 'ip_id': ip_id}), 201
    
    @app.route('/api/v1/devices/<int:device_id>/ips/<int:ip_id>', methods=['DELETE'])
    @api_permission_required('remove_device_ip')
    def api_remove_device_ip(device_id, ip_id):
        """Remove an IP address from a device"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ip.ip, ip.subnet_id, d.name
                FROM DeviceIPAddress dia
                JOIN IPAddress ip ON dia.ip_id = ip.id
                JOIN Device d ON dia.device_id = d.id
                WHERE dia.device_id = %s AND dia.ip_id = %s
            ''', (device_id, ip_id))
            row = cursor.fetchone()
            if not row:
                return jsonify({'error': 'IP address not found on device'}), 404
            ip, subnet_id, device_name = row
            cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = %s AND ip_id = %s', (device_id, ip_id))
            cursor.execute('UPDATE IPAddress SET hostname = NULL WHERE id = %s', (ip_id,))
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet_row = cursor.fetchone()
            if subnet_row:
                subnet_name, subnet_cidr = subnet_row
                details = f"Removed IP {ip} ({subnet_name} {subnet_cidr}) from device {device_name}"
            else:
                details = f"Removed IP {ip} from device {device_name}"
            add_audit_log(request.api_user['id'], 'device_delete_ip', details, subnet_id, conn=conn)
            conn.commit()
        return jsonify({'message': 'IP address removed from device successfully', 'ip_id': ip_id})
    
    # Subnets API
    @app.route('/api/v1/subnets', methods=['GET'])
    @api_permission_required('view_subnet')
    def api_subnets():
        """Get all subnets"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, cidr, site FROM Subnet ORDER BY site, name')
            subnets = cursor.fetchall()
            for subnet in subnets:
                cursor.execute('SELECT COUNT(*) as total, COUNT(CASE WHEN hostname IS NOT NULL THEN 1 END) as used FROM IPAddress WHERE subnet_id = %s', (subnet['id'],))
                stats = cursor.fetchone()
                subnet['total_ips'] = stats['total']
                subnet['used_ips'] = stats['used']
                subnet['available_ips'] = stats['total'] - stats['used']
        return jsonify({'subnets': subnets})
    
    @app.route('/api/v1/subnets/<int:subnet_id>', methods=['GET'])
    @api_permission_required('view_subnet')
    def api_subnet(subnet_id):
        """Get a specific subnet with IP addresses"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, cidr, site FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            if not subnet:
                return jsonify({'error': 'Subnet not found'}), 404
            cursor.execute('''
                SELECT ip.id, ip.ip, ip.hostname, d.id as device_id, d.name as device_name
                FROM IPAddress ip
                LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                LEFT JOIN Device d ON dia.device_id = d.id
                WHERE ip.subnet_id = %s
                ORDER BY ip.ip
            ''', (subnet_id,))
            subnet['ip_addresses'] = cursor.fetchall()
        return jsonify(subnet)
    
    @app.route('/api/v1/subnets', methods=['POST'])
    @api_permission_required('add_subnet')
    def api_add_subnet():
        """Create a new subnet"""
        data = request.get_json()
        if not data or 'name' not in data or 'cidr' not in data:
            return jsonify({'error': 'Name and CIDR are required'}), 400
        
        name = data['name']
        cidr = data['cidr']
        site = data.get('site', '')
        
        try:
            network = ip_network(cidr, strict=False)
            if network.prefixlen < 24:
                return jsonify({'error': 'Subnet must be /24 or smaller'}), 400
        except Exception:
            return jsonify({'error': 'Invalid CIDR format'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Subnet (name, cidr, site) VALUES (%s, %s, %s)', (name, cidr, site))
            subnet_id = cursor.lastrowid
            ip_rows = [(str(ip), subnet_id) for ip in network.hosts()]
            cursor.executemany('INSERT INTO IPAddress (ip, subnet_id) VALUES (%s, %s)', ip_rows)
            add_audit_log(request.api_user['id'], 'add_subnet', f"Added subnet {name} ({cidr})", subnet_id, conn=conn)
            conn.commit()
        return jsonify({'id': subnet_id, 'name': name, 'cidr': cidr, 'site': site}), 201
    
    @app.route('/api/v1/subnets/<int:subnet_id>', methods=['PUT'])
    @api_permission_required('edit_subnet')
    def api_update_subnet(subnet_id):
        """Update a subnet"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr, site FROM Subnet WHERE id = %s', (subnet_id,))
            old_subnet = cursor.fetchone()
            if not old_subnet:
                return jsonify({'error': 'Subnet not found'}), 404
            old_name, old_cidr, old_site = old_subnet
            
            new_name = data.get('name', old_name)
            new_cidr = data.get('cidr', old_cidr)
            new_site = data.get('site', old_site)
            
            updates = []
            values = []
            if new_name != old_name:
                updates.append('name = %s')
                values.append(new_name)
            if new_cidr != old_cidr:
                updates.append('cidr = %s')
                values.append(new_cidr)
            if new_site != old_site:
                updates.append('site = %s')
                values.append(new_site)
            
            if not updates:
                return jsonify({'error': 'No changes to apply'}), 400
            
            values.append(subnet_id)
            cursor.execute(f'UPDATE Subnet SET {", ".join(updates)} WHERE id = %s', values)
            add_audit_log(
                request.api_user['id'],
                'edit_subnet',
                f"Edited subnet from {old_name} ({old_cidr}) to {new_name} ({new_cidr}) at site {new_site or 'Unassigned'}",
                subnet_id,
                conn=conn
            )
            conn.commit()
        return jsonify({'message': 'Subnet updated successfully', 'subnet': {'id': subnet_id, 'name': new_name, 'cidr': new_cidr, 'site': new_site}})
    
    @app.route('/api/v1/subnets/<int:subnet_id>', methods=['DELETE'])
    @api_permission_required('delete_subnet')
    def api_delete_subnet(subnet_id):
        """Delete a subnet"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            if not subnet:
                return jsonify({'error': 'Subnet not found'}), 404
            subnet_name, subnet_cidr = subnet
            cursor.execute('SELECT id FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_ids = [row[0] for row in cursor.fetchall()]
            if ip_ids:
                cursor.executemany('DELETE FROM DeviceIPAddress WHERE ip_id = %s', [(ip_id,) for ip_id in ip_ids])
            cursor.execute('DELETE FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('UPDATE AuditLog SET subnet_id = NULL WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('DELETE FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('DELETE FROM Subnet WHERE id = %s', (subnet_id,))
            add_audit_log(request.api_user['id'], 'delete_subnet', f"Deleted subnet {subnet_name} ({subnet_cidr})", subnet_id, conn=conn)
            conn.commit()
        return jsonify({'message': 'Subnet deleted successfully', 'subnet': {'id': subnet_id, 'name': subnet_name, 'cidr': subnet_cidr}})
    
    # Racks API
    @app.route('/api/v1/racks', methods=['GET'])
    @api_permission_required('view_racks')
    def api_racks():
        """Get all racks"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, site, height_u FROM Rack ORDER BY site, name')
            racks = cursor.fetchall()
            for rack in racks:
                cursor.execute('SELECT COUNT(*) as used FROM RackDevice WHERE rack_id = %s AND side = %s', (rack['id'], 'front'))
                usage_row = cursor.fetchone()
                rack['used_u'] = usage_row['used'] if usage_row and 'used' in usage_row else 0
                rack['percent_full'] = int((rack['used_u'] / rack['height_u']) * 100) if rack['height_u'] else 0
                cursor.execute('''
                    SELECT rd.id, rd.position_u, rd.side, rd.device_id, rd.nonnet_device_name,
                           d.name as device_name
                    FROM RackDevice rd
                    LEFT JOIN Device d ON rd.device_id = d.id
                    WHERE rd.rack_id = %s
                    ORDER BY rd.position_u, rd.side
                ''', (rack['id'],))
                rack['devices'] = cursor.fetchall()
        return jsonify({'racks': racks})
    
    @app.route('/api/v1/racks/<int:rack_id>', methods=['GET'])
    @api_permission_required('view_rack')
    def api_rack(rack_id):
        """Get a specific rack"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, site, height_u FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return jsonify({'error': 'Rack not found'}), 404
            cursor.execute('''
                SELECT rd.id, rd.position_u, rd.side, rd.device_id, rd.nonnet_device_name,
                       d.name as device_name
                FROM RackDevice rd
                LEFT JOIN Device d ON rd.device_id = d.id
                WHERE rd.rack_id = %s
                ORDER BY rd.position_u, rd.side
            ''', (rack_id,))
            rack['devices'] = cursor.fetchall()
        return jsonify(rack)
    
    @app.route('/api/v1/racks', methods=['POST'])
    @api_permission_required('add_rack')
    def api_add_rack():
        """Create a new rack"""
        from flask import current_app
        data = request.get_json()
        if not data or 'name' not in data or 'site' not in data or 'height_u' not in data:
            return jsonify({'error': 'Name, site, and height_u are required'}), 400
        
        name = data['name']
        site = data['site']
        height_u = data['height_u']
        try:
            height_u = int(height_u)
        except (TypeError, ValueError):
            return jsonify({'error': 'height_u must be an integer'}), 400
        if height_u <= 0:
            return jsonify({'error': 'height_u must be greater than zero'}), 400
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Rack (name, site, height_u) VALUES (%s, %s, %s)', (name, site, height_u))
            rack_id = cursor.lastrowid
            add_audit_log(request.api_user['id'], 'add_rack', f"Added rack '{name}' at site '{site}' ({height_u}U)", conn=conn)
            conn.commit()
        return jsonify({'id': rack_id, 'name': name, 'site': site, 'height_u': height_u}), 201
    
    @app.route('/api/v1/racks/<int:rack_id>', methods=['DELETE'])
    @api_permission_required('delete_rack')
    def api_delete_rack(rack_id):
        """Delete a rack"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return jsonify({'error': 'Rack not found'}), 404
            rack_name = rack[0]
            cursor.execute('DELETE FROM Rack WHERE id = %s', (rack_id,))
            add_audit_log(request.api_user['id'], 'delete_rack', f"Deleted rack '{rack_name}'", conn=conn)
            conn.commit()
        return jsonify({'message': 'Rack deleted successfully', 'rack': {'id': rack_id, 'name': rack_name}})
    
    @app.route('/api/v1/racks/<int:rack_id>/devices', methods=['POST'])
    @api_permission_required('add_device_to_rack')
    def api_add_device_to_rack(rack_id):
        """Add a device to a rack"""
        from flask import current_app
        data = request.get_json()
        if not data or 'position_u' not in data or 'side' not in data:
            return jsonify({'error': 'position_u and side are required'}), 400
        
        position_u = data['position_u']
        side = data['side']
        device_id = data.get('device_id')
        nonnet_device_name = data.get('nonnet_device_name')
        
        if device_id is None and not nonnet_device_name:
            return jsonify({'error': 'Either device_id or nonnet_device_name is required'}), 400
        
        try:
            position_u = int(position_u)
        except (TypeError, ValueError):
            return jsonify({'error': 'position_u must be an integer'}), 400
        side = str(side).lower()
        if side not in ('front', 'back'):
            return jsonify({'error': "side must be either 'front' or 'back'"}), 400
        if device_id is not None:
            try:
                device_id = int(device_id)
            except (TypeError, ValueError):
                return jsonify({'error': 'device_id must be an integer'}), 400
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT name, height_u FROM Rack WHERE id = %s', (rack_id,))
            rack = cursor.fetchone()
            if not rack:
                return jsonify({'error': 'Rack not found'}), 404
            if position_u < 1 or position_u > rack['height_u']:
                return jsonify({'error': f'Invalid U position: {position_u}. Rack is {rack["height_u"]}U tall.'}), 400
            
            cursor.execute('SELECT COUNT(*) as occupied_count FROM RackDevice WHERE rack_id = %s AND position_u = %s AND side = %s', (rack_id, position_u, side))
            occupied = cursor.fetchone()
            if occupied and occupied['occupied_count'] > 0:
                return jsonify({'error': f'U{position_u} on the {side} is already occupied.'}), 400
            
            if device_id is not None:
                cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
                device_row = cursor.fetchone()
                if not device_row:
                    return jsonify({'error': 'Device not found'}), 404
                device_name = device_row['name']
                cursor.execute(
                    'INSERT INTO RackDevice (rack_id, device_id, position_u, side, nonnet_device_name) VALUES (%s, %s, %s, %s, NULL)',
                    (rack_id, device_id, position_u, side)
                )
                action = 'rack_add_device'
                details = f"Assigned device '{device_name}' to rack '{rack['name']}' U{position_u} ({side})"
            else:
                nonnet_device_name = (nonnet_device_name or '').strip()
                if not nonnet_device_name:
                    return jsonify({'error': 'nonnet_device_name is required when device_id is not provided'}), 400
                cursor.execute(
                    'INSERT INTO RackDevice (rack_id, device_id, position_u, side, nonnet_device_name) VALUES (%s, NULL, %s, %s, %s)',
                    (rack_id, position_u, side, nonnet_device_name)
                )
                device_name = nonnet_device_name
                action = 'rack_add_nonnet_device'
                details = f"Added non-networked device '{device_name}' to rack '{rack['name']}' U{position_u} ({side})"
            
            rack_device_id = cursor.lastrowid
            add_audit_log(request.api_user['id'], action, details, conn=conn)
            conn.commit()
        return jsonify({
            'message': 'Device added to rack successfully',
            'rack_device': {
                'id': rack_device_id,
                'rack_id': rack_id,
                'device_id': device_id,
                'nonnet_device_name': device_name if device_id is None else None,
                'device_name': device_name,
                'position_u': position_u,
                'side': side
            }
        }), 201
    
    @app.route('/api/v1/racks/<int:rack_id>/devices/<int:rack_device_id>', methods=['DELETE'])
    @api_permission_required('remove_device_from_rack')
    def api_remove_device_from_rack(rack_id, rack_device_id):
        """Remove a device from a rack"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT rd.device_id, rd.nonnet_device_name, rd.position_u, rd.side,
                       d.name AS device_name, r.name AS rack_name
                FROM RackDevice rd
                JOIN Rack r ON rd.rack_id = r.id
                LEFT JOIN Device d ON rd.device_id = d.id
                WHERE rd.id = %s AND rd.rack_id = %s
            ''', (rack_device_id, rack_id))
            rd = cursor.fetchone()
            if not rd:
                return jsonify({'error': 'Device not found in rack'}), 404
            if rd['device_id']:
                device_label = rd['device_name'] or str(rd['device_id'])
            else:
                device_label = rd['nonnet_device_name']
            cursor.execute('DELETE FROM RackDevice WHERE id = %s AND rack_id = %s', (rack_device_id, rack_id))
            add_audit_log(
                request.api_user['id'],
                'rack_remove_device',
                f"Removed device '{device_label}' from rack '{rd['rack_name']}' U{rd['position_u']} ({rd['side']})",
                conn=conn
            )
            conn.commit()
        return jsonify({'message': 'Device removed from rack successfully', 'rack_device_id': rack_device_id})
    
    # Device Types API
    @app.route('/api/v1/device-types', methods=['GET'])
    @api_permission_required('view_device_types')
    def api_device_types():
        """Get all device types"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, icon_class FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
        return jsonify({'device_types': device_types})
    
    # DHCP API
    @app.route('/api/v1/subnets/<int:subnet_id>/dhcp', methods=['GET'])
    @api_permission_required('view_dhcp')
    def api_get_dhcp(subnet_id):
        """Get DHCP pools for a subnet"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
            pools = cursor.fetchall()
        return jsonify({'pools': pools})
    
    @app.route('/api/v1/subnets/<int:subnet_id>/dhcp', methods=['POST'])
    @api_permission_required('configure_dhcp')
    def api_configure_dhcp(subnet_id):
        """Configure DHCP pools for a subnet"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            if not subnet:
                return jsonify({'error': 'Subnet not found'}), 404
            subnet_name, subnet_cidr = subnet
            
            if data.get('remove'):
                cursor.execute('DELETE FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
                cursor.execute('UPDATE IPAddress SET hostname = NULL WHERE subnet_id = %s AND hostname = %s', (subnet_id, 'DHCP'))
                add_audit_log(
                    request.api_user['id'],
                    'dhcp_pool_remove',
                    f"Removed DHCP pool for subnet {subnet_name} ({subnet_cidr})",
                    subnet_id,
                    conn=conn
                )
                conn.commit()
                return jsonify({'message': 'DHCP pool removed successfully'})
            
            pools = data.get('pools')
            if not pools or not isinstance(pools, list):
                return jsonify({'error': 'pools array is required'}), 400
            pool = pools[0]
            start_ip = pool.get('start_ip')
            end_ip = pool.get('end_ip')
            if not start_ip or not end_ip:
                return jsonify({'error': 'start_ip and end_ip are required'}), 400
            excluded_ips = pool.get('excluded_ips', [])
            if not isinstance(excluded_ips, list):
                return jsonify({'error': 'excluded_ips must be a list of IP strings'}), 400
            excluded_list = [ip.strip() for ip in excluded_ips if ip.strip()]
            excluded_str = ','.join(excluded_list)
            
            cursor.execute('SELECT ip FROM IPAddress WHERE subnet_id = %s ORDER BY ip', (subnet_id,))
            all_ips = [row[0] for row in cursor.fetchall()]
            if start_ip not in all_ips or end_ip not in all_ips:
                return jsonify({'error': 'start_ip and end_ip must be addresses within the subnet'}), 400
            
            cursor.execute('SELECT id FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
            existing = cursor.fetchone()
            cursor.execute('UPDATE IPAddress SET hostname = NULL WHERE subnet_id = %s AND hostname = %s', (subnet_id, 'DHCP'))
            if existing:
                cursor.execute(
                    'UPDATE DHCPPool SET start_ip = %s, end_ip = %s, excluded_ips = %s WHERE subnet_id = %s',
                    (start_ip, end_ip, excluded_str, subnet_id)
                )
                action = 'dhcp_pool_update'
                details = f"Updated DHCP pool for subnet {subnet_name} ({subnet_cidr}): {start_ip} - {end_ip}, excluded: {excluded_str}"
            else:
                cursor.execute(
                    'INSERT INTO DHCPPool (subnet_id, start_ip, end_ip, excluded_ips) VALUES (%s, %s, %s, %s)',
                    (subnet_id, start_ip, end_ip, excluded_str)
                )
                action = 'dhcp_pool_create'
                details = f"Created DHCP pool for subnet {subnet_name} ({subnet_cidr}): {start_ip} - {end_ip}, excluded: {excluded_str}"
            
            in_range = False
            for candidate_ip in all_ips:
                if candidate_ip == start_ip:
                    in_range = True
                if in_range and candidate_ip not in excluded_list:
                    cursor.execute('UPDATE IPAddress SET hostname = %s WHERE subnet_id = %s AND ip = %s', ('DHCP', subnet_id, candidate_ip))
                if candidate_ip == end_ip:
                    break
            
            add_audit_log(request.api_user['id'], action, details, subnet_id, conn=conn)
            conn.commit()
        return jsonify({'message': 'DHCP pools configured successfully', 'pool': {'start_ip': start_ip, 'end_ip': end_ip, 'excluded_ips': excluded_list}})
    
    # Audit Log API
    @app.route('/api/v1/audit', methods=['GET'])
    @api_permission_required('view_audit')
    def api_audit():
        """Get audit log entries"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)
            cursor.execute('''
                SELECT al.id, al.user_id, u.name as user_name, al.action, al.details, al.subnet_id, al.timestamp
                FROM AuditLog al
                LEFT JOIN User u ON al.user_id = u.id
                ORDER BY al.timestamp DESC
                LIMIT %s OFFSET %s
            ''', (limit, offset))
            logs = cursor.fetchall()
        return jsonify({'logs': logs})
    
    # Users API (admin only)
    @app.route('/api/v1/users', methods=['GET'])
    @api_permission_required('view_users')
    def api_users():
        """Get all users (admin only)"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT u.id, u.name, u.email, r.id as role_id, r.name as role_name
                FROM User u
                LEFT JOIN Role r ON u.role_id = r.id
                ORDER BY u.name
            ''')
            users = cursor.fetchall()
            # Don't return API keys in list
            for user in users:
                user.pop('api_key', None)
        return jsonify({'users': users})
    
    # Roles API (admin only)
    @app.route('/api/v1/roles', methods=['GET'])
    @api_permission_required('view_users')
    def api_roles():
        """Get all roles (admin only)"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, description FROM Role ORDER BY name')
            roles = cursor.fetchall()
            for role in roles:
                cursor.execute('''
                    SELECT p.id, p.name, p.description, p.category
                    FROM RolePermission rp
                    JOIN Permission p ON rp.permission_id = p.id
                    WHERE rp.role_id = %s
                ''', (role['id'],))
                role['permissions'] = cursor.fetchall()
        return jsonify({'roles': roles})

    def get_current_user_name():
        user_id = session.get('user_id')
        if not user_id:
            return ''
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM User WHERE id = %s', (user_id,))
            row = cursor.fetchone()
            return row[0] if row else ''

    def render_with_user(*args, **kwargs):
        if 'current_user_name' not in kwargs:
            kwargs['current_user_name'] = get_current_user_name()
        return render_template(*args, **kwargs)

    app.add_url_rule('/login', 'login', login, methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', logout)
    app.add_url_rule('/', 'index', index)
    app.add_url_rule('/devices', 'devices', devices)
    app.add_url_rule('/add_device', 'add_device', add_device, methods=['GET', 'POST'])
    app.add_url_rule('/device/<int:device_id>', 'device', device)
    app.add_url_rule('/device/<int:device_id>/add_ip', 'device_add_ip', device_add_ip, methods=['POST'])
    app.add_url_rule('/device/<int:device_id>/delete_ip', 'device_delete_ip', device_delete_ip, methods=['POST'])
    app.add_url_rule('/delete_device', 'delete_device', delete_device, methods=['POST'])
    app.add_url_rule('/subnet/<int:subnet_id>', 'subnet', subnet)
    app.add_url_rule('/add_subnet', 'add_subnet', add_subnet, methods=['POST'])
    app.add_url_rule('/edit_subnet', 'edit_subnet', edit_subnet, methods=['POST'])
    app.add_url_rule('/delete_subnet', 'delete_subnet', delete_subnet, methods=['POST'])
    app.add_url_rule('/admin', 'admin', admin, methods=['GET', 'POST'])
    app.add_url_rule('/users', 'users', users, methods=['GET', 'POST'])
    app.add_url_rule('/audit', 'audit', audit)
    app.add_url_rule('/get_available_ips', 'get_available_ips', get_available_ips)
    app.add_url_rule('/rename_device', 'rename_device', rename_device, methods=['POST'])
    app.add_url_rule('/update_device_description', 'update_device_description', update_device_description, methods=['POST'])
    app.add_url_rule('/subnet/<int:subnet_id>/export_csv', 'export_subnet_csv', export_subnet_csv)
    app.add_url_rule('/subnet/<int:subnet_id>/dhcp', 'dhcp_pool', dhcp_pool, methods=['GET', 'POST'])
    app.add_url_rule('/device_type_stats', 'device_type_stats', device_type_stats)
    app.add_url_rule('/device_types', 'device_types', device_types, methods=['GET', 'POST'])
    app.add_url_rule('/devices/type/<device_type>', 'devices_by_type', devices_by_type)
    app.add_url_rule('/racks', 'racks', racks)
    app.add_url_rule('/rack/add', 'add_rack', add_rack, methods=['GET', 'POST'])
    app.add_url_rule('/rack/<int:rack_id>', 'rack', rack)
    app.add_url_rule('/rack/<int:rack_id>/add_device', 'rack_add_device', rack_add_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/add_nonnet_device', 'rack_add_nonnet_device', rack_add_nonnet_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/remove_device', 'rack_remove_device', rack_remove_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/delete', 'delete_rack', delete_rack, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/export_csv', 'export_rack_csv', export_rack_csv)
    app.add_url_rule('/help', 'help', help)
    
    # API key regeneration route
    @app.route('/regenerate_api_key', methods=['POST'])
    @permission_required('manage_users')
    def regenerate_api_key():
        user_id = request.form['user_id']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            new_api_key = generate_api_key()
            cursor.execute('UPDATE User SET api_key = %s WHERE id = %s', (new_api_key, user_id))
            conn.commit()
        return redirect(url_for('users'))
