from flask import render_template, request, redirect, url_for, send_from_directory, send_file, session
from db import init_db, hash_password, get_db_connection, verify_password
import sqlite3
from ipaddress import ip_network
from functools import wraps
import os
import csv
from io import StringIO, BytesIO

app = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def add_audit_log(user_id, action, details=None, subnet_id=None, conn=None):
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO AuditLog (user_id, action, details, subnet_id) VALUES (?, ?, ?, ?)''',
                   (user_id, action, details, subnet_id))
    if close_conn:
        conn.commit()
        conn.close()

def register_routes(app):
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, password FROM User WHERE email = ?', (email,))
                user = cursor.fetchone()
            if user and verify_password(password, user[1]):
                session['logged_in'] = True
                session['user_id'] = user[0]
                return redirect(url_for('index'))
            else:
                error = 'Invalid email or password.'
        return render_with_user('login.html', error=error)

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.route('/')
    @login_required
    def index():
        with get_db_connection() as conn:
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
    @login_required
    def devices():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name FROM Device')
            devices = cursor.fetchall()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = cursor.fetchall()
            cursor.execute('SELECT DeviceIPAddress.device_id, IPAddress.id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id')
            device_ips = {}
            for row in cursor.fetchall():
                device_ips.setdefault(row[0], []).append((row[1], row[2]))
            sites_devices = {}
            for device in devices:
                cursor.execute('''SELECT Subnet.site FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id JOIN Subnet ON IPAddress.subnet_id = Subnet.id WHERE DeviceIPAddress.device_id = ? LIMIT 1''', (device[0],))
                site = cursor.fetchone()
                site = site[0] if site else 'Unassigned'
                if site not in sites_devices:
                    sites_devices[site] = []
                sites_devices[site].append({'id': device[0], 'name': device[1]})
        return render_with_user('devices.html', sites_devices=sites_devices, device_ips=device_ips)

    @app.route('/add_device', methods=['GET', 'POST'])
    @login_required
    def add_device():
        if request.method == 'POST':
            name = request.form['device_name']
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO Device (name) VALUES (?)', (name,))
                conn.commit()
            return redirect(url_for('devices'))
        return render_with_user('add_device.html')

    @app.route('/device/<int:device_id>')
    @login_required
    def device(device_id):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, description FROM Device WHERE id = ?', (device_id,))
            device = cursor.fetchone()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = [dict(id=row[0], name=row[1], cidr=row[2], site=row[3]) for row in cursor.fetchall()]
            cursor.execute('''SELECT DeviceIPAddress.id as device_ip_id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id WHERE DeviceIPAddress.device_id = ?''', (device_id,))
            device_ips = [{'device_ip_id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
        return render_with_user('device.html', device={'id': device[0], 'name': device[1], 'description': device[2]}, subnets=subnets, device_ips=device_ips)

    @app.route('/device/<int:device_id>/add_ip', methods=['POST'])
    @login_required
    def device_add_ip(device_id):
        subnet_id = request.form['subnet_id']
        ip_id = request.form['ip_id']
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO DeviceIPAddress (device_id, ip_id) VALUES (?, ?)', (device_id, ip_id))
            cursor.execute('SELECT name FROM Device WHERE id = ?', (device_id,))
            device_name = cursor.fetchone()[0]
            cursor.execute('UPDATE IPAddress SET hostname = ? WHERE id = ?', (device_name, ip_id))
            cursor.execute('SELECT ip, subnet_id FROM IPAddress WHERE id = ?', (ip_id,))
            ip, subnet_id_val = cursor.fetchone()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = ?', (subnet_id_val,))
            subnet_name, subnet_cidr = cursor.fetchone()
            details = f"Assigned IP {ip} ({subnet_name} {subnet_cidr}) to device {device_name}"
            add_audit_log(user_id, 'device_add_ip', details, subnet_id_val, conn=conn)
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/delete_ip', methods=['POST'])
    @login_required
    def device_delete_ip(device_id):
        device_ip_id = request.form['device_ip_id']
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE id = ?', (device_ip_id,))
            ip_id = cursor.fetchone()[0]
            cursor.execute('SELECT ip, subnet_id FROM IPAddress WHERE id = ?', (ip_id,))
            ip, subnet_id_val = cursor.fetchone()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = ?', (subnet_id_val,))
            subnet_name, subnet_cidr = cursor.fetchone()
            cursor.execute('SELECT device_id FROM DeviceIPAddress WHERE id = ?', (device_ip_id,))
            device_id_val = cursor.fetchone()[0]
            cursor.execute('SELECT name FROM Device WHERE id = ?', (device_id_val,))
            device_name = cursor.fetchone()[0]
            details = f"Removed IP {ip} ({subnet_name} {subnet_cidr}) from device {device_name}"
            add_audit_log(user_id, 'device_delete_ip', details, subnet_id_val, conn=conn)
            cursor.execute('DELETE FROM DeviceIPAddress WHERE id = ?', (device_ip_id,))
            cursor.execute('UPDATE IPAddress SET hostname = NULL WHERE id = ?', (ip_id,))
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/delete_device', methods=['POST'])
    @login_required
    def delete_device():
        device_id = request.form['device_id']
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = ?', (device_id,))
            device_name = cursor.fetchone()[0]
            add_audit_log(user_id, 'delete_device', f"Deleted device {device_name}", conn=conn)
            cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = ?', (device_id,))
            cursor.execute('DELETE FROM Device WHERE id = ?', (device_id,))
            conn.commit()
        return redirect(url_for('devices'))

    @app.route('/subnet/<int:subnet_id>')
    @login_required
    def subnet(subnet_id):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = ?', (subnet_id,))
            subnet = cursor.fetchone()
            cursor.execute('SELECT * FROM IPAddress WHERE subnet_id = ?', (subnet_id,))
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
    @login_required
    def add_subnet():
        name = request.form['name']
        cidr = request.form['cidr']
        site = request.form['site']
        user_id = session.get('user_id')
        try:
            network = ip_network(cidr, strict=False)
            if network.prefixlen < 24:
                return render_with_user('admin.html', subnets=[], error='Subnet must be /24 or smaller (e.g., /24, /25, ... /32)')
        except Exception as e:
            return render_with_user('admin.html', subnets=[], error='Invalid CIDR format.')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Subnet (name, cidr, site) VALUES (?, ?, ?)', (name, cidr, site))
            subnet_id = cursor.lastrowid
            ip_rows = [(str(ip), subnet_id) for ip in network.hosts()]
            cursor.executemany('INSERT INTO IPAddress (ip, subnet_id) VALUES (?, ?)', ip_rows)
            add_audit_log(user_id, 'add_subnet', f"Added subnet {name} ({cidr})", subnet_id, conn=conn)
            conn.commit()
        return redirect(url_for('admin'))

    @app.route('/delete_subnet', methods=['POST'])
    @login_required
    def delete_subnet():
        subnet_id = request.form['subnet_id']
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = ?', (subnet_id,))
            subnet = cursor.fetchone()
            add_audit_log(user_id, 'delete_subnet', f"Deleted subnet {subnet[0]} ({subnet[1]})", subnet_id, conn=conn)
            cursor.execute('SELECT id FROM IPAddress WHERE subnet_id = ?', (subnet_id,))
            ip_ids = [row[0] for row in cursor.fetchall()]
            if ip_ids:
                cursor.executemany('DELETE FROM DeviceIPAddress WHERE ip_id = ?', [(ip_id,) for ip_id in ip_ids])
                cursor.executemany('UPDATE AuditLog SET subnet_id=NULL WHERE subnet_id = ?', [(subnet_id,) for _ in ip_ids])
            cursor.execute('DELETE FROM IPAddress WHERE subnet_id = ?', (subnet_id,))
            cursor.execute('DELETE FROM Subnet WHERE id = ?', (subnet_id,))
            conn.commit()
        return redirect(url_for('admin'))

    @app.route('/admin', methods=['GET', 'POST'])
    @login_required
    def admin():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet')
            subnets = [dict(id=row[0], name=row[1], cidr=row[2]) for row in cursor.fetchall()]
        return render_with_user('admin.html', subnets=subnets)

    @app.route('/download_db')
    @login_required
    def download_db():
        return send_file('db/subnets.db', as_attachment=True)

    @app.route('/users', methods=['GET', 'POST'])
    @login_required
    def users():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            if request.method == 'POST':
                action = request.form['action']
                if action == 'add':
                    name = request.form['name']
                    email = request.form['email']
                    password = hash_password(request.form['password'])
                    cursor.execute('INSERT INTO User (name, email, password) VALUES (?, ?, ?)', (name, email, password))
                elif action == 'edit':
                    user_id = request.form['user_id']
                    name = request.form['name']
                    email = request.form['email']
                    password = request.form['password']
                    if password:
                        password = hash_password(password)
                        cursor.execute('UPDATE User SET name=?, email=?, password=? WHERE id=?', (name, email, password, user_id))
                    else:
                        cursor.execute('UPDATE User SET name=?, email=? WHERE id=?', (name, email, user_id))
                elif action == 'delete':
                    user_id = request.form['user_id']
                    cursor.execute('UPDATE User SET name=? WHERE id=?', ('Deleted User', user_id))
                    cursor.execute('UPDATE AuditLog SET user_id=NULL WHERE user_id=?', (user_id,))
                    cursor.execute('DELETE FROM User WHERE id=?', (user_id,))
                conn.commit()
            cursor.execute('SELECT id, name, email FROM User')
            users = cursor.fetchall()
        return render_with_user('users.html', users=users)

    @app.route('/audit')
    @login_required
    def audit():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            user_id = request.args.get('user_id')
            subnet_id = request.args.get('subnet_id')
            action = request.args.get('action')
            device_name = request.args.get('device_name')
            query = '''SELECT AuditLog.id, COALESCE(User.name, 'Deleted User'), AuditLog.action, AuditLog.details, Subnet.name, AuditLog.timestamp FROM AuditLog LEFT JOIN User ON AuditLog.user_id = User.id LEFT JOIN Subnet ON AuditLog.subnet_id = Subnet.id WHERE 1=1'''
            params = []
            if user_id:
                query += ' AND AuditLog.user_id = ?'
                params.append(user_id)
            if subnet_id:
                query += ' AND AuditLog.subnet_id = ?'
                params.append(subnet_id)
            if action:
                query += ' AND AuditLog.action = ?'
                params.append(action)
            if device_name:
                query += ' AND AuditLog.details LIKE ?'
                params.append(f'%{device_name}%')
            query += ' ORDER BY AuditLog.timestamp DESC'
            cursor.execute(query, params)
            logs = cursor.fetchall()
            cursor.execute('SELECT id, name FROM User')
            users = cursor.fetchall()
            cursor.execute('SELECT id, name FROM Subnet')
            subnets = cursor.fetchall()
            cursor.execute('SELECT DISTINCT action FROM AuditLog')
            actions = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT name FROM Device ORDER BY name')
            devices = cursor.fetchall()
        return render_with_user('audit.html', logs=logs, users=users, subnets=subnets, actions=actions, devices=devices)

    @app.route('/get_available_ips')
    @login_required
    def get_available_ips():
        subnet_id = request.args.get('subnet_id')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT id, ip FROM IPAddress WHERE subnet_id = ? AND id NOT IN (SELECT ip_id FROM DeviceIPAddress)''', (subnet_id,))
            available_ips = [{'id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
        return {'available_ips': available_ips}

    @app.route('/rename_device', methods=['POST'])
    @login_required
    def rename_device():
        device_id = request.form['device_id']
        new_name = request.form['new_name']
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = ?', (device_id,))
            old_name = cursor.fetchone()[0]
            cursor.execute('UPDATE Device SET name = ? WHERE id = ?', (new_name, device_id))
            cursor.execute('UPDATE IPAddress SET hostname = ? WHERE hostname = ?', (new_name, old_name))
            conn.commit()
            add_audit_log(user_id, 'rename_device', f"Renamed device '{old_name}' to '{new_name}'", conn=conn)
        return redirect(url_for('device', device_id=device_id))

    @app.route('/update_device_description', methods=['POST'])
    @login_required
    def update_device_description():
        device_id = request.form['device_id']
        description = request.form['description']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE Device SET description = ? WHERE id = ?', (description, device_id))
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/subnet/<int:subnet_id>/export_csv')
    @login_required
    def export_subnet_csv(subnet_id):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = ?', (subnet_id,))
            subnet = cursor.fetchone()
            if not subnet:
                return 'Subnet not found', 404
            cursor.execute('SELECT * FROM IPAddress WHERE subnet_id = ?', (subnet_id,))
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

    def get_current_user_name():
        user_id = session.get('user_id')
        if not user_id:
            return ''
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM User WHERE id = ?', (user_id,))
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
    app.add_url_rule('/delete_subnet', 'delete_subnet', delete_subnet, methods=['POST'])
    app.add_url_rule('/admin', 'admin', admin, methods=['GET', 'POST'])
    app.add_url_rule('/download_db', 'download_db', download_db)
    app.add_url_rule('/users', 'users', users, methods=['GET', 'POST'])
    app.add_url_rule('/audit', 'audit', audit)
    app.add_url_rule('/get_available_ips', 'get_available_ips', get_available_ips)
    app.add_url_rule('/rename_device', 'rename_device', rename_device, methods=['POST'])
    app.add_url_rule('/update_device_description', 'update_device_description', update_device_description, methods=['POST'])
    app.add_url_rule('/subnet/<int:subnet_id>/export_csv', 'export_subnet_csv', export_subnet_csv)
