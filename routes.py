from flask import render_template, request, redirect, url_for, send_from_directory, send_file, session
from db import init_db, hash_password, get_db_connection, verify_password
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
    @login_required
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
    @login_required
    def add_device():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
        if request.method == 'POST':
            name = request.form['device_name']
            device_type_id = int(request.form['device_type'])
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO Device (name, device_type_id) VALUES (%s, %s)', (name, device_type_id))
                conn.commit()
            return redirect(url_for('devices'))
        return render_with_user('add_device.html', device_types=device_types)

    @app.route('/device/<int:device_id>')
    @login_required
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
    @login_required
    def update_device_type():
        device_id = request.form['device_id']
        device_type_id = request.form['device_type_id']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE Device SET device_type_id = %s WHERE id = %s', (device_type_id, device_id))
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/add_ip', methods=['POST'])
    @login_required
    def device_add_ip(device_id):
        subnet_id = request.form['subnet_id']
        ip_id = request.form['ip_id']
        user_id = session.get('user_id')
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
            add_audit_log(user_id, 'device_add_ip', details, subnet_id_val, conn=conn)
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/delete_ip', methods=['POST'])
    @login_required
    def device_delete_ip(device_id):
        device_ip_id = request.form['device_ip_id']
        user_id = session.get('user_id')
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
            add_audit_log(user_id, 'device_delete_ip', details, subnet_id_val, conn=conn)
            cursor.execute('DELETE FROM DeviceIPAddress WHERE id = %s', (device_ip_id,))
            cursor.execute('UPDATE IPAddress SET hostname = NULL WHERE id = %s', (ip_id,))
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/delete_device', methods=['POST'])
    @login_required
    def delete_device():
        device_id = request.form['device_id']
        user_id = session.get('user_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device_row = cursor.fetchone()
            if device_row:
                device_name = device_row[0]
                add_audit_log(user_id, 'delete_device', f"Deleted device {device_name}", conn=conn)
                cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
                ip_ids = [row[0] for row in cursor.fetchall()]
                if ip_ids:
                    cursor.executemany('UPDATE IPAddress SET hostname = NULL WHERE id = %s', [(ip_id,) for ip_id in ip_ids])
                cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
                cursor.execute('DELETE FROM Device WHERE id = %s', (device_id,))
                conn.commit()
        return redirect(url_for('devices'))

    @app.route('/subnet/<int:subnet_id>')
    @login_required
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
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Subnet (name, cidr, site) VALUES (%s, %s, %s)', (name, cidr, site))
            subnet_id = cursor.lastrowid
            ip_rows = [(str(ip), subnet_id) for ip in network.hosts()]
            cursor.executemany('INSERT INTO IPAddress (ip, subnet_id) VALUES (%s, %s)', ip_rows)
            add_audit_log(user_id, 'add_subnet', f"Added subnet {name} ({cidr})", subnet_id, conn=conn)
            conn.commit()
        return redirect(url_for('admin'))

    @app.route('/delete_subnet', methods=['POST'])
    @login_required
    def delete_subnet():
        subnet_id = request.form['subnet_id']
        user_id = session.get('user_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            add_audit_log(user_id, 'delete_subnet', f"Deleted subnet {subnet[0]} ({subnet[1]})", subnet_id, conn=conn)
            cursor.execute('SELECT id FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_ids = [row[0] for row in cursor.fetchall()]
            if ip_ids:
                cursor.executemany('DELETE FROM DeviceIPAddress WHERE ip_id = %s', [(ip_id,) for ip_id in ip_ids])
                cursor.executemany('UPDATE AuditLog SET subnet_id=NULL WHERE subnet_id = %s', [(subnet_id,) for _ in ip_ids])
            cursor.execute('DELETE FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('DELETE FROM Subnet WHERE id = %s', (subnet_id,))
            conn.commit()
        return redirect(url_for('admin'))

    @app.route('/admin', methods=['GET', 'POST'])
    @login_required
    def admin():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr FROM Subnet')
            subnets = [dict(id=row[0], name=row[1], cidr=row[2]) for row in cursor.fetchall()]
        return render_with_user('admin.html', subnets=subnets)

    @app.route('/users', methods=['GET', 'POST'])
    @login_required
    def users():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            if request.method == 'POST':
                action = request.form['action']
                if action == 'add':
                    name = request.form['name']
                    email = request.form['email']
                    password = hash_password(request.form['password'])
                    cursor.execute('INSERT INTO User (name, email, password) VALUES (%s, %s, %s)', (name, email, password))
                elif action == 'edit':
                    user_id = request.form['user_id']
                    name = request.form['name']
                    email = request.form['email']
                    password = request.form['password']
                    if password:
                        password = hash_password(password)
                        cursor.execute('UPDATE User SET name=%s, email=%s, password=%s WHERE id=%s', (name, email, password, user_id))
                    else:
                        cursor.execute('UPDATE User SET name=%s, email=%s WHERE id=%s', (name, email, user_id))
                elif action == 'delete':
                    user_id = request.form['user_id']
                    cursor.execute('UPDATE User SET name=%s WHERE id=%s', ('Deleted User', user_id))
                    cursor.execute('UPDATE AuditLog SET user_id=NULL WHERE user_id=%s', (user_id,))
                    cursor.execute('DELETE FROM User WHERE id=%s', (user_id,))
                conn.commit()
            cursor.execute('SELECT id, name, email FROM User')
            users = cursor.fetchall()
        return render_with_user('users.html', users=users)

    @app.route('/audit')
    @login_required
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
    @login_required
    def get_available_ips():
        subnet_id = request.args.get('subnet_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT id, ip FROM IPAddress WHERE subnet_id = %s AND id NOT IN (SELECT ip_id FROM DeviceIPAddress) AND (hostname IS NULL OR hostname != 'DHCP')''', (subnet_id,))
            available_ips = [{'id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
        return {'available_ips': available_ips}

    @app.route('/rename_device', methods=['POST'])
    @login_required
    def rename_device():
        device_id = request.form['device_id']
        new_name = request.form['new_name']
        user_id = session.get('user_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            old_name = cursor.fetchone()[0]
            cursor.execute('UPDATE Device SET name = %s WHERE id = %s', (new_name, device_id))
            cursor.execute('UPDATE IPAddress SET hostname = %s WHERE hostname = %s', (new_name, old_name))
            conn.commit()
            add_audit_log(user_id, 'rename_device', f"Renamed device '{old_name}' to '{new_name}'", conn=conn)
        return redirect(url_for('device', device_id=device_id))

    @app.route('/update_device_description', methods=['POST'])
    @login_required
    def update_device_description():
        device_id = request.form['device_id']
        description = request.form['description']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE Device SET description = %s WHERE id = %s', (description, device_id))
            conn.commit()
        return redirect(url_for('device', device_id=device_id))

    @app.route('/subnet/<int:subnet_id>/export_csv')
    @login_required
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
    @login_required
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
                user_id = session.get('user_id')
                if 'remove' in request.form:
                    cursor.execute('DELETE FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
                    cursor.execute('UPDATE IPAddress SET hostname=NULL WHERE subnet_id=%s AND hostname="DHCP"', (subnet_id,))
                    conn.commit()
                    dhcp_pool = None
                    add_audit_log(user_id, 'dhcp_pool_remove', f"Removed DHCP pool for subnet {subnet[1]} ({subnet[2]})", subnet_id, conn=conn)
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
                        add_audit_log(user_id, action, details, subnet_id, conn=conn)
            return render_with_user('dhcp.html', subnet={'id': subnet[0], 'name': subnet[1]}, dhcp_pool=dhcp_pool, error=error)

    @app.route('/device_type_stats')
    @login_required
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

    @app.route('/devices/type/<device_type>')
    @login_required
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
    @login_required
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
    @login_required
    def add_rack():
        from flask import current_app
        if request.method == 'POST':
            name = request.form['name']
            site = request.form['site']
            height_u = int(request.form['height_u'])
            user_id = session.get('user_id')
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO Rack (name, site, height_u) VALUES (%s, %s, %s)', (name, site, height_u))
                rack_id = cursor.lastrowid
                add_audit_log(user_id, 'add_rack', f"Added rack '{name}' at site '{site}' ({height_u}U)", conn=conn)
                conn.commit()
            return redirect(url_for('racks'))
        return render_with_user('add_rack.html')

    @app.route('/rack/<int:rack_id>')
    @login_required
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
    @login_required
    def rack_add_device(rack_id):
        device_id = int(request.form['device_id'])
        position_u = int(request.form['position_u'])
        side = request.form['side']
        user_id = session.get('user_id')
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
            add_audit_log(user_id, 'rack_add_device', f"Assigned device '{device_name[0] if device_name else device_id}' to rack '{rack_name[0] if rack_name else rack_id}' U{position_u} ({side})", conn=conn)
            conn.commit()
        return redirect(url_for('rack', rack_id=rack_id))

    @app.route('/rack/<int:rack_id>/add_nonnet_device', methods=['POST'])
    @login_required
    def rack_add_nonnet_device(rack_id):
        device_name = request.form['device_name']
        position_u = int(request.form['position_u'])
        side = request.form['side']
        user_id = session.get('user_id')
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
            add_audit_log(user_id, 'rack_add_nonnet_device', f"Added non-networked device '{device_name}' to rack '{rack_id}' U{position_u} ({side})", conn=conn)
            conn.commit()
        return redirect(url_for('rack', rack_id=rack_id))

    @app.route('/rack/<int:rack_id>/remove_device', methods=['POST'])
    @login_required
    def rack_remove_device(rack_id):
        rack_device_id = int(request.form['rack_device_id'])
        user_id = session.get('user_id')
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
            add_audit_log(user_id, 'rack_remove_device', f"Removed device '{device_label}' from rack '{rack_label}' U{rd['position_u']} ({rd['side']})", conn=conn)
            cursor.execute('DELETE FROM RackDevice WHERE id = %s', (rack_device_id,))
            conn.commit()
        return redirect(url_for('rack', rack_id=rack_id))

    @app.route('/rack/<int:rack_id>/delete', methods=['POST'])
    @login_required
    def delete_rack(rack_id):
        user_id = session.get('user_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Rack WHERE id = %s', (rack_id,))
            rack_name = cursor.fetchone()
            cursor.execute('DELETE FROM Rack WHERE id = %s', (rack_id,))
            add_audit_log(user_id, 'delete_rack', f"Deleted rack '{rack_name[0] if rack_name else rack_id}'", conn=conn)
            conn.commit()
        return redirect(url_for('racks'))

    @app.route('/rack/<int:rack_id>/export_csv')
    @login_required
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
    app.add_url_rule('/devices/type/<device_type>', 'devices_by_type', devices_by_type)
    app.add_url_rule('/racks', 'racks', racks)
    app.add_url_rule('/rack/add', 'add_rack', add_rack, methods=['GET', 'POST'])
    app.add_url_rule('/rack/<int:rack_id>', 'rack', rack)
    app.add_url_rule('/rack/<int:rack_id>/add_device', 'rack_add_device', rack_add_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/add_nonnet_device', 'rack_add_nonnet_device', rack_add_nonnet_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/remove_device', 'rack_remove_device', rack_remove_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/delete', 'delete_rack', delete_rack, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/export_csv', 'export_rack_csv', export_rack_csv)
