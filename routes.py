from flask import render_template, request, redirect, url_for, send_from_directory, send_file, session, abort, jsonify
from db import init_db, hash_password, get_db_connection, verify_password, generate_api_key
from ipaddress import ip_network
from functools import wraps
import os
import csv
from io import StringIO, BytesIO
import logging
import mysql.connector
import requests
import subprocess
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename
from cache import cache
import json
import re
from ipaddress import ip_address, IPv4Address, IPv6Address
from urllib.parse import urlparse

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
        
        # Execute the function
        response = f(*args, **kwargs)
        
        # Log API usage to audit log
        try:
            api_path = request.path
            http_method = request.method
            user_name = user.get('name', 'Unknown')
            
            # Get response status code if available
            status_code = None
            if hasattr(response, 'status_code'):
                status_code = response.status_code
            elif isinstance(response, tuple) and len(response) > 1:
                status_code = response[1]
            
            # Build details string with status if available
            if status_code:
                details = f"API call: {http_method} {api_path} (Status: {status_code})"
            else:
                details = f"API call: {http_method} {api_path}"
            
            add_audit_log(
                user_id=user['id'],
                action='api_usage',
                details=details,
                subnet_id=None
            )
        except Exception as e:
            # Don't fail the request if logging fails
            logging.error(f"Failed to log API usage: {e}")
        
        return response
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

def invalidate_cache_for_device(device_id):
    """Invalidate all cache entries related to a device"""
    cache.invalidate_device(device_id)
    cache.clear('devices')

def get_ip_history_from_audit_logs(device_id=None, ip_address=None, conn=None):
    """
    Extract IP assignment history from audit logs.
    Returns a list of history entries sorted by timestamp (newest first).
    Each entry contains: ip, action, device_name, subnet_name, subnet_cidr, user_name, timestamp
    """
    import re
    close_conn = False
    if conn is None:
        from flask import current_app
        conn = get_db_connection(current_app)
        close_conn = True
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get device name if filtering by device_id
        device_name = None
        if device_id:
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device_result = cursor.fetchone()
            if device_result:
                device_name = device_result['name']
            else:
                # Device doesn't exist, return empty history
                return []
        
        # Build query to get relevant audit log entries
        query = '''
            SELECT al.id, al.action, al.details, al.timestamp, 
                   COALESCE(u.name, 'Deleted User') as user_name,
                   s.name as subnet_name, s.cidr as subnet_cidr
            FROM AuditLog al
            LEFT JOIN User u ON al.user_id = u.id
            LEFT JOIN Subnet s ON al.subnet_id = s.id
            WHERE (al.action = 'device_add_ip' OR al.action = 'device_delete_ip')
        '''
        params = []
        
        if ip_address:
            query += ' AND al.details LIKE %s'
            params.append(f'%IP {ip_address}%')
        
        query += ' ORDER BY al.timestamp DESC'
        
        cursor.execute(query, params)
        logs = cursor.fetchall()
        
        history = []
        # Pattern to extract IP, subnet info, and device name from audit log details
        # Format: "Assigned IP 192.168.1.1 (SubnetName 192.168.1.0/24) to device DeviceName"
        # Format: "Removed IP 192.168.1.1 (SubnetName 192.168.1.0/24) from device DeviceName"
        ip_pattern = r'IP\s+([\d\.]+)'
        device_pattern = r'(?:to|from)\s+device\s+([^\s]+)'
        
        for log in logs:
            details = log['details'] or ''
            
            # Extract IP address
            ip_match = re.search(ip_pattern, details)
            if not ip_match:
                continue
            
            extracted_ip = ip_match.group(1)
            
            # If filtering by specific IP, skip if it doesn't match
            if ip_address and extracted_ip != ip_address:
                continue
            
            # Extract device name
            device_match = re.search(device_pattern, details)
            extracted_device_name = device_match.group(1) if device_match else 'Unknown'
            
            # If filtering by device_id, verify device name matches
            if device_id and device_name:
                if extracted_device_name != device_name:
                    continue
            
            history.append({
                'ip': extracted_ip,
                'action': 'assigned' if log['action'] == 'device_add_ip' else 'removed',
                'device_name': extracted_device_name,
                'subnet_name': log['subnet_name'] or 'Unknown',
                'subnet_cidr': log['subnet_cidr'] or '',
                'user_name': log['user_name'],
                'timestamp': log['timestamp']
            })
        
        return history
    finally:
        if close_conn:
            conn.close()

def invalidate_cache_for_subnet(subnet_id):
    """Invalidate all cache entries related to a subnet"""
    cache.invalidate_subnet(subnet_id)
    cache.clear('index')
    cache.clear('admin')

def validate_custom_field_value(field_def, value):
    """
    Validate a custom field value against its field definition.
    Returns (is_valid, error_message)
    """
    if value is None or value == '':
        if field_def.get('required', False):
            return False, f"{field_def.get('name', 'Field')} is required"
        return True, None
    
    field_type = field_def.get('field_type', 'text')
    validation_rules = field_def.get('validation_rules')
    
    # Parse validation rules if it's a JSON string
    if isinstance(validation_rules, str):
        try:
            validation_rules = json.loads(validation_rules)
        except json.JSONDecodeError:
            validation_rules = {}
    elif validation_rules is None:
        validation_rules = {}
    
    # Type-specific validation
    if field_type == 'ip_address':
        try:
            ip_address(value)
        except ValueError:
            return False, f"Invalid IP address format: {value}"
    
    elif field_type == 'email':
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, value):
            return False, f"Invalid email format: {value}"
    
    elif field_type == 'url':
        try:
            result = urlparse(value)
            if not all([result.scheme, result.netloc]):
                return False, f"Invalid URL format: {value}"
        except Exception:
            return False, f"Invalid URL format: {value}"
    
    elif field_type == 'date':
        try:
            datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            return False, f"Invalid date format. Expected YYYY-MM-DD: {value}"
    
    elif field_type == 'datetime':
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return False, f"Invalid datetime format. Expected ISO format: {value}"
    
    elif field_type == 'number':
        try:
            int(value)
        except ValueError:
            return False, f"Invalid integer: {value}"
        if 'min_value' in validation_rules:
            if int(value) < validation_rules['min_value']:
                return False, f"Value must be at least {validation_rules['min_value']}"
        if 'max_value' in validation_rules:
            if int(value) > validation_rules['max_value']:
                return False, f"Value must be at most {validation_rules['max_value']}"
    
    elif field_type == 'decimal':
        try:
            float(value)
        except ValueError:
            return False, f"Invalid decimal number: {value}"
        if 'min_value' in validation_rules:
            if float(value) < validation_rules['min_value']:
                return False, f"Value must be at least {validation_rules['min_value']}"
        if 'max_value' in validation_rules:
            if float(value) > validation_rules['max_value']:
                return False, f"Value must be at most {validation_rules['max_value']}"
    
    elif field_type == 'boolean':
        if value not in [True, False, 'true', 'false', '1', '0', 1, 0]:
            return False, f"Invalid boolean value: {value}"
    
    elif field_type == 'select':
        if 'select_options' in validation_rules:
            if value not in validation_rules['select_options']:
                return False, f"Value must be one of: {', '.join(validation_rules['select_options'])}"
    
    # Text length validation (applies to text, textarea, and string-based types)
    if field_type in ['text', 'textarea', 'ip_address', 'email', 'url']:
        if 'min_length' in validation_rules:
            if len(str(value)) < validation_rules['min_length']:
                return False, f"Value must be at least {validation_rules['min_length']} characters"
        if 'max_length' in validation_rules:
            if len(str(value)) > validation_rules['max_length']:
                return False, f"Value must be at most {validation_rules['max_length']} characters"
    
    # Regex pattern validation
    if 'regex_pattern' in validation_rules:
        try:
            if not re.match(validation_rules['regex_pattern'], str(value)):
                return False, f"Value does not match required pattern"
        except re.error:
            # Invalid regex pattern, skip validation
            pass
    
    return True, None

def parse_custom_field_value(field_type, raw_value):
    """Parse and normalize a custom field value based on its type"""
    if raw_value is None or raw_value == '':
        return None
    
    if field_type == 'number':
        try:
            return int(raw_value)
        except ValueError:
            return None
    elif field_type == 'decimal':
        try:
            return float(raw_value)
        except ValueError:
            return None
    elif field_type == 'boolean':
        if isinstance(raw_value, bool):
            return raw_value
        if str(raw_value).lower() in ['true', '1', 'yes']:
            return True
        if str(raw_value).lower() in ['false', '0', 'no']:
            return False
        return None
    elif field_type in ['date', 'datetime']:
        # Return as string, validation ensures format
        return str(raw_value)
    else:
        # text, textarea, ip_address, email, url, select
        return str(raw_value)

def validate_vlan_id(vlan_id_str):
    """
    Validate VLAN ID. Must be integer between 1-4094 (standard VLAN range).
    Returns (is_valid, error_message, vlan_id_int)
    """
    if vlan_id_str is None or vlan_id_str == '':
        return True, None, None
    
    try:
        vlan_id = int(vlan_id_str)
        if vlan_id < 1 or vlan_id > 4094:
            return False, "VLAN ID must be between 1 and 4094", None
        return True, None, vlan_id
    except ValueError:
        return False, "VLAN ID must be a valid integer", None

def get_custom_fields_for_entity(entity_type, entity_id, conn=None):
    """
    Retrieve custom field definitions with their values for an entity.
    Returns list of dicts with field definition and current value.
    """
    close_conn = False
    if conn is None:
        from flask import current_app
        conn = get_db_connection(current_app)
        close_conn = True
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get field definitions for this entity type
        cursor.execute('''
            SELECT id, entity_type, name, field_key, field_type, required, 
                   default_value, help_text, display_order, validation_rules, searchable
            FROM CustomFieldDefinition
            WHERE entity_type = %s
            ORDER BY display_order, name
        ''', (entity_type,))
        field_defs = cursor.fetchall()
        
        # Get current values from entity table
        table_name = 'Device' if entity_type == 'device' else 'Subnet'
        cursor.execute(f'SELECT custom_fields FROM {table_name} WHERE id = %s', (entity_id,))
        result = cursor.fetchone()
        
        current_values = {}
        if result and result.get('custom_fields'):
            try:
                current_values = json.loads(result['custom_fields'])
            except (json.JSONDecodeError, TypeError):
                current_values = {}
        
        # Merge definitions with values
        fields_with_values = []
        for field_def in field_defs:
            field_key = field_def['field_key']
            current_value = current_values.get(field_key)
            
            # Use default value if no current value
            if current_value is None and field_def.get('default_value'):
                current_value = field_def['default_value']
            
            # Parse validation_rules if it's a JSON string
            validation_rules = field_def.get('validation_rules')
            if isinstance(validation_rules, str):
                try:
                    validation_rules = json.loads(validation_rules)
                except (json.JSONDecodeError, TypeError):
                    validation_rules = {}
            elif validation_rules is None:
                validation_rules = {}
            
            field_def['current_value'] = current_value
            field_def['validation_rules'] = validation_rules
            fields_with_values.append(field_def)
        
        return fields_with_values
    finally:
        if close_conn:
            conn.close()

def prewarm_cache(app):
    """Pre-warm cache in background by loading all data"""
    import threading
    import time
    
    def _prewarm():
        """Background function to pre-warm cache"""
        # Wait a bit for app to fully initialize
        time.sleep(2)
        
        try:
            with app.app_context():
                from flask import current_app
                conn = get_db_connection(current_app)
                try:
                    cursor = conn.cursor()
                    
                    # Pre-warm index page (all subnets with utilization)
                    logging.info("Pre-warming cache: Loading all subnets for index page...")
                    cursor.execute('SELECT id, name, cidr, site FROM Subnet')
                    subnets = cursor.fetchall()
                    sites_subnets = {}
                    for subnet in subnets:
                        site = subnet[3] or 'Unassigned'
                        if site not in sites_subnets:
                            sites_subnets[site] = []
                        
                        subnet_id = subnet[0]
                        cursor.execute('SELECT COUNT(*) FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                        total_ips = cursor.fetchone()[0]
                        
                        cursor.execute('''
                            SELECT COUNT(*) FROM IPAddress ip
                            WHERE ip.subnet_id = %s AND ip.id IN (SELECT ip_id FROM DeviceIPAddress)
                        ''', (subnet_id,))
                        assigned_ips = cursor.fetchone()[0]
                        
                        cursor.execute('''
                            SELECT COUNT(*) FROM IPAddress ip
                            WHERE ip.subnet_id = %s AND ip.hostname = 'DHCP' AND ip.id NOT IN (SELECT ip_id FROM DeviceIPAddress)
                        ''', (subnet_id,))
                        dhcp_ips = cursor.fetchone()[0]
                        
                        used_ips = assigned_ips + dhcp_ips
                        utilization_percent = (used_ips / total_ips * 100) if total_ips > 0 else 0
                        
                        sites_subnets[site].append({
                            'id': subnet[0],
                            'name': subnet[1],
                            'cidr': subnet[2],
                            'utilization': round(utilization_percent, 1)
                        })
                    cache.set('index', sites_subnets, ttl=10800)
                    logging.info(f"Pre-warmed index cache with {len(subnets)} subnets")
                    
                    # Pre-warm admin page
                    logging.info("Pre-warming cache: Loading admin page data...")
                    cursor.execute('SELECT id, name, cidr, site FROM Subnet ORDER BY site, name')
                    subnet_rows = cursor.fetchall()
                    admin_subnets = []
                    for row in subnet_rows:
                        subnet_id = row[0]
                        cursor.execute('SELECT COUNT(*) FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                        total_ips = cursor.fetchone()[0]
                        
                        cursor.execute('''
                            SELECT COUNT(*) FROM IPAddress ip
                            WHERE ip.subnet_id = %s AND ip.id IN (SELECT ip_id FROM DeviceIPAddress)
                        ''', (subnet_id,))
                        assigned_ips = cursor.fetchone()[0]
                        
                        cursor.execute('''
                            SELECT COUNT(*) FROM IPAddress ip
                            WHERE ip.subnet_id = %s AND ip.hostname = 'DHCP' AND ip.id NOT IN (SELECT ip_id FROM DeviceIPAddress)
                        ''', (subnet_id,))
                        dhcp_ips = cursor.fetchone()[0]
                        
                        available_ips = total_ips - assigned_ips - dhcp_ips
                        used_ips = assigned_ips + dhcp_ips
                        utilization_percent = (used_ips / total_ips * 100) if total_ips > 0 else 0
                        
                        admin_subnets.append({
                            'id': row[0],
                            'name': row[1],
                            'cidr': row[2],
                            'site': row[3] or 'Unassigned',
                            'utilization': {
                                'percent': round(utilization_percent, 1),
                                'assigned': assigned_ips,
                                'used': used_ips,
                                'total': total_ips
                            }
                        })
                    # Cache with same structure as admin route expects
                    admin_result = {
                        'subnets': admin_subnets,
                        'can_add_subnet': True,  # Will be checked at render time
                        'can_edit_subnet': True,  # Will be checked at render time
                        'can_delete_subnet': True  # Will be checked at render time
                    }
                    cache.set('admin', admin_result, ttl=10800)
                    logging.info(f"Pre-warmed admin cache with {len(admin_subnets)} subnets")
                    
                    # Pre-warm all subnet detail pages
                    logging.info("Pre-warming cache: Loading all subnet detail pages...")
                    for subnet in subnets:
                        subnet_id = subnet[0]
                        try:
                            cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
                            subnet_row = cursor.fetchone()
                            if subnet_row:
                                cursor.execute('SELECT id, ip, hostname, notes FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                                ip_addresses = cursor.fetchall()
                                
                                cursor.execute('SELECT COUNT(*) FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                                total_ips = cursor.fetchone()[0]
                                
                                cursor.execute('''
                                    SELECT COUNT(*) FROM IPAddress ip
                                    WHERE ip.subnet_id = %s AND ip.id IN (SELECT ip_id FROM DeviceIPAddress)
                                ''', (subnet_id,))
                                assigned_ips = cursor.fetchone()[0]
                                
                                cursor.execute('''
                                    SELECT COUNT(*) FROM IPAddress ip
                                    WHERE ip.subnet_id = %s AND ip.hostname = 'DHCP' AND ip.id NOT IN (SELECT ip_id FROM DeviceIPAddress)
                                ''', (subnet_id,))
                                dhcp_ips = cursor.fetchone()[0]
                                
                                available_ips = total_ips - assigned_ips - dhcp_ips
                                used_ips = assigned_ips + dhcp_ips
                                utilization_percent = (used_ips / total_ips * 100) if total_ips > 0 else 0
                                
                                utilization_stats = {
                                    'total': total_ips,
                                    'assigned': assigned_ips,
                                    'dhcp': dhcp_ips,
                                    'available': available_ips,
                                    'percent': round(utilization_percent, 1)
                                }
                                
                                cursor.execute('SELECT id, name, description FROM Device')
                                devices = cursor.fetchall()
                                device_name_map = {name.lower(): (id, description) for id, name, description in devices}
                                ip_addresses_with_device = []
                                for ip in ip_addresses:
                                    ip_id = ip[0]
                                    ip_address = ip[1]
                                    hostname = ip[2]
                                    ip_notes = ip[3] if len(ip) > 3 else None
                                    device_id = None
                                    device_description = None
                                    if hostname:
                                        match = device_name_map.get(hostname.lower())
                                        if match:
                                            device_id, device_description = match
                                    ip_addresses_with_device.append((ip_id, ip_address, hostname, device_id, device_description, ip_notes))
                                
                                subnet_dict = {'id': subnet_row[0], 'name': subnet_row[1], 'cidr': subnet_row[2]}
                                result = {
                                    'subnet': subnet_dict,
                                    'ip_addresses': ip_addresses_with_device,
                                    'utilization': utilization_stats
                                }
                                cache.set(f'subnet:{subnet_id}', result, ttl=10800)
                        except Exception as e:
                            logging.error(f"Error pre-warming subnet {subnet_id}: {e}")
                    logging.info(f"Pre-warmed {len(subnets)} subnet detail pages")
                    
                    # Pre-warm all device detail pages
                    logging.info("Pre-warming cache: Loading all device detail pages...")
                    cursor.execute('SELECT id FROM Device')
                    device_ids = [row[0] for row in cursor.fetchall()]
                    for device_id in device_ids:
                        try:
                            cursor.execute('SELECT id, name, description, device_type_id FROM Device WHERE id = %s', (device_id,))
                            device = cursor.fetchone()
                            if device:
                                cursor.execute('SELECT id, name FROM DeviceType ORDER BY name')
                                device_types = cursor.fetchall()
                                cursor.execute('SELECT id, name, cidr, site FROM Subnet')
                                subnets = [dict(id=row[0], name=row[1], cidr=row[2], site=row[3]) for row in cursor.fetchall()]
                                cursor.execute('''SELECT DeviceIPAddress.id as device_ip_id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id WHERE DeviceIPAddress.device_id = %s''', (device_id,))
                                device_ips = [{'device_ip_id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
                                
                                cursor.execute('''
                                    SELECT t.id, t.name, t.color
                                    FROM DeviceTag dt
                                    JOIN Tag t ON dt.tag_id = t.id
                                    WHERE dt.device_id = %s
                                    ORDER BY t.name
                                ''', (device_id,))
                                device_tags = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
                                
                                cursor.execute('SELECT id, name, color FROM Tag ORDER BY name')
                                all_tags = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
                                
                                available_ips_by_subnet = {}
                                for subnet in subnets:
                                    cursor.execute('''
                    SELECT ip.id, ip.ip FROM IPAddress ip
                    LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                    WHERE ip.subnet_id = %s AND dia.ip_id IS NULL
                ''', (subnet['id'],))
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
                                
                                result_data = {
                                    'device': {'id': device[0], 'name': device[1], 'description': device[2], 'device_type_id': device[3]},
                                    'subnets': subnets,
                                    'device_ips': device_ips,
                                    'available_ips_by_subnet': available_ips_by_subnet,
                                    'device_types': device_types,
                                    'device_tags': device_tags,
                                    'all_tags': all_tags,
                                    'can_assign_device_tag': True,  # Will be checked at render time
                                    'can_remove_device_tag': True   # Will be checked at render time
                                }
                                cache.set(f'device:{device_id}', result_data, ttl=10800)
                        except Exception as e:
                            logging.error(f"Error pre-warming device {device_id}: {e}")
                    logging.info(f"Pre-warmed {len(device_ids)} device detail pages")
                    
                    logging.info("Cache pre-warming completed successfully")
                except Exception as e:
                    logging.error(f"Error during cache pre-warming: {e}")
                finally:
                    conn.close()
        except Exception as e:
            logging.error(f"Error in cache pre-warming thread: {e}")
    
    # Start pre-warming in background thread
    thread = threading.Thread(target=_prewarm, daemon=True)
    thread.start()
    logging.info("Started background cache pre-warming thread")

def register_routes(app, limiter=None):
    logging.basicConfig(level=logging.INFO)
    
    # Helper function to apply rate limiting if limiter is available
    def rate_limit(limit_str):
        """Apply rate limiting decorator if limiter is available"""
        if limiter:
            return limiter.limit(limit_str)
        else:
            # Return a no-op decorator if limiter is not available
            def noop_decorator(f):
                return f
            return noop_decorator

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # If already logged in, redirect to index
        if session.get('logged_in'):
            return redirect(url_for('index'))
        
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
                user_id = user[0]
                # Check if user's role requires 2FA
                with get_db_connection(current_app) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT u.totp_enabled, u.two_fa_setup_complete, r.require_2fa
                        FROM User u
                        LEFT JOIN Role r ON u.role_id = r.id
                        WHERE u.id = %s
                    ''', (user_id,))
                    result = cursor.fetchone()
                    totp_enabled = result[0] if result else False
                    setup_complete = result[1] if result else False
                    role_requires_2fa = result[2] if result else False
                
                # If role requires 2FA but user hasn't set it up, redirect to setup
                if role_requires_2fa and not setup_complete:
                    session['pending_user_id'] = user_id
                    session['pending_email'] = email
                    return redirect(url_for('setup_2fa'))
                
                # If 2FA is enabled, require verification
                if totp_enabled:
                    session['pending_user_id'] = user_id
                    session['pending_email'] = email
                    return redirect(url_for('verify_2fa'))
                
                # Normal login - no 2FA required
                session['logged_in'] = True
                session['user_id'] = user_id
                session.modified = True  # Ensure session is saved
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
    
    @app.route('/setup-2fa', methods=['GET', 'POST'])
    def setup_2fa():
        from totp_utils import generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp, generate_backup_codes, format_backup_codes
        from flask import current_app
        import json
        
        # If already logged in, redirect to index
        if session.get('logged_in'):
            return redirect(url_for('index'))
        
        pending_user_id = session.get('pending_user_id')
        if not pending_user_id:
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'generate':
                # Generate new TOTP secret
                secret = generate_totp_secret()
                session['temp_totp_secret'] = secret
                with get_db_connection(current_app) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT email FROM User WHERE id = %s', (pending_user_id,))
                    email = cursor.fetchone()[0]
                
                totp_uri = get_totp_uri(secret, email)
                qr_code = generate_qr_code(totp_uri)
                return render_with_user('setup_2fa.html', secret=secret, qr_code=qr_code, email=email, step='verify')
            
            elif action == 'verify':
                code = request.form.get('code', '').strip()
                secret = session.get('temp_totp_secret')
                
                if not secret:
                    return render_with_user('setup_2fa.html', error='Session expired. Please start over.', step='generate')
                
                if verify_totp(secret, code):
                    # Save TOTP secret and generate backup codes
                    backup_codes = generate_backup_codes()
                    backup_codes_json = json.dumps(backup_codes)
                    
                    with get_db_connection(current_app) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            UPDATE User 
                            SET totp_secret = %s, totp_enabled = TRUE, backup_codes = %s, two_fa_setup_complete = TRUE
                            WHERE id = %s
                        ''', (secret, backup_codes_json, pending_user_id))
                    
                    session.pop('temp_totp_secret', None)
                    session['logged_in'] = True
                    session['user_id'] = pending_user_id
                    session.pop('pending_user_id', None)
                    session.pop('pending_email', None)
                    session.modified = True  # Ensure session is saved
                    
                    formatted_codes = format_backup_codes(backup_codes)
                    logging.info(f"User {pending_user_id} enabled 2FA successfully.")
                    return render_with_user('setup_2fa.html', backup_codes=formatted_codes, step='backup_codes')
                else:
                    return render_with_user('setup_2fa.html', error='Invalid code. Please try again.', secret=secret, step='verify')
        
        return render_with_user('setup_2fa.html', step='generate')
    
    @app.route('/verify-2fa', methods=['GET', 'POST'])
    def verify_2fa():
        from totp_utils import verify_totp, verify_backup_code
        from flask import current_app
        
        # If already logged in, redirect to index
        if session.get('logged_in'):
            return redirect(url_for('index'))
        
        pending_user_id = session.get('pending_user_id')
        if not pending_user_id:
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            code = request.form.get('code', '').strip()
            use_backup = request.form.get('use_backup') == 'true'
            
            if not code:
                return render_with_user('verify_2fa.html', error='Please enter a verification code.')
            
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT totp_secret, backup_codes FROM User WHERE id = %s', (pending_user_id,))
                result = cursor.fetchone()
                if not result:
                    return render_with_user('verify_2fa.html', error='User not found.')
                
                totp_secret, backup_codes_json = result
                
                # CRITICAL: Ensure TOTP secret exists before attempting verification
                if not totp_secret:
                    return render_with_user('verify_2fa.html', error='2FA is not properly configured for this account.')
                
                if use_backup:
                    # Verify backup code
                    if not backup_codes_json:
                        return render_with_user('verify_2fa.html', error='No backup codes available.')
                    
                    valid, updated_codes = verify_backup_code(backup_codes_json, code)
                    if valid:
                        # Update backup codes in database
                        cursor.execute('UPDATE User SET backup_codes = %s WHERE id = %s', 
                                     (updated_codes, pending_user_id))
                        conn.commit()
                        session['logged_in'] = True
                        session['user_id'] = pending_user_id
                        session.pop('pending_user_id', None)
                        session.pop('pending_email', None)
                        session.modified = True  # Ensure session is saved
                        logging.info(f"User {pending_user_id} logged in with backup code.")
                        return redirect(url_for('index'))
                    else:
                        return render_with_user('verify_2fa.html', error='Invalid backup code.')
                else:
                    # Verify TOTP code - ensure code is exactly 6 digits
                    if len(code) != 6 or not code.isdigit():
                        return render_with_user('verify_2fa.html', error='Invalid code format. Please enter a 6-digit code.')
                    
                    if verify_totp(totp_secret, code):
                        session['logged_in'] = True
                        session['user_id'] = pending_user_id
                        session.pop('pending_user_id', None)
                        session.pop('pending_email', None)
                        session.modified = True  # Ensure session is saved
                        logging.info(f"User {pending_user_id} logged in with 2FA.")
                        return redirect(url_for('index'))
                    else:
                        return render_with_user('verify_2fa.html', error='Invalid code. Please try again.')
        
        return render_with_user('verify_2fa.html')

    @app.route('/')
    @permission_required('view_index')
    def index():
        cache_key = 'index'
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return render_with_user('index.html', sites_subnets=cached_result)
        
        from flask import current_app
        conn = get_db_connection(current_app)
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = cursor.fetchall()
            sites_subnets = {}
            for subnet in subnets:
                site = subnet[3] or 'Unassigned'
                if site not in sites_subnets:
                    sites_subnets[site] = []
                
                # Calculate utilization for each subnet
                subnet_id = subnet[0]
                cursor.execute('SELECT COUNT(*) FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                total_ips = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM IPAddress ip
                    INNER JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                    WHERE ip.subnet_id = %s
                ''', (subnet_id,))
                assigned_ips = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM IPAddress ip
                    LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                    WHERE ip.subnet_id = %s AND ip.hostname = 'DHCP' AND dia.ip_id IS NULL
                ''', (subnet_id,))
                dhcp_ips = cursor.fetchone()[0]
                
                used_ips = assigned_ips + dhcp_ips
                utilization_percent = (used_ips / total_ips * 100) if total_ips > 0 else 0
                
                sites_subnets[site].append({
                    'id': subnet[0],
                    'name': subnet[1],
                    'cidr': subnet[2],
                    'utilization': round(utilization_percent, 1)
                })
            # Cache for 3 hours
            cache.set(cache_key, sites_subnets, ttl=10800)
            return render_with_user('index.html', sites_subnets=sites_subnets)
        finally:
            conn.close()

    @app.route('/devices')
    @permission_required('view_devices')
    def devices():
        from flask import current_app
        tag_filter = request.args.get('tag')
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            
            # Base device query
            if tag_filter:
                cursor.execute('''
                    SELECT DISTINCT d.id, d.name, dt.icon_class 
                    FROM Device d 
                    LEFT JOIN DeviceType dt ON d.device_type_id = dt.id
                    JOIN DeviceTag dtag ON d.id = dtag.device_id
                    JOIN Tag t ON dtag.tag_id = t.id
                    WHERE t.name = %s
                    ORDER BY d.name
                ''', (tag_filter,))
            else:
                cursor.execute('''SELECT Device.id, Device.name, DeviceType.icon_class FROM Device LEFT JOIN DeviceType ON Device.device_type_id = DeviceType.id ORDER BY Device.name''')
            
            devices = cursor.fetchall()
            
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = cursor.fetchall()
            cursor.execute('SELECT DeviceIPAddress.device_id, IPAddress.id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id')
            device_ips = {}
            for row in cursor.fetchall():
                device_ips.setdefault(row[0], []).append((row[1], row[2]))
            
            # Get tags for each device
            device_tags = {}
            for device in devices:
                cursor.execute('''
                    SELECT t.id, t.name, t.color
                    FROM DeviceTag dt
                    JOIN Tag t ON dt.tag_id = t.id
                    WHERE dt.device_id = %s
                    ORDER BY t.name
                ''', (device[0],))
                device_tags[device[0]] = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
            
            # Get all available tags for filtering
            cursor.execute('SELECT DISTINCT name FROM Tag ORDER BY name')
            all_tag_names = [row[0] for row in cursor.fetchall()]
            
            # Optimize: Get device sites in a single query instead of N+1
            sites_devices = {}
            device_sites = {}
            if devices:
                device_ids = [device[0] for device in devices]
                placeholders = ','.join(['%s'] * len(device_ids))
                cursor.execute(f'''
                    SELECT DISTINCT DeviceIPAddress.device_id, Subnet.site
                    FROM DeviceIPAddress
                    JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id
                    JOIN Subnet ON IPAddress.subnet_id = Subnet.id
                    WHERE DeviceIPAddress.device_id IN ({placeholders})
                ''', tuple(device_ids))
                for row in cursor.fetchall():
                    device_sites[row[0]] = row[1] or 'Unassigned'
            
            for device in devices:
                site = device_sites.get(device[0], 'Unassigned')
                if site not in sites_devices:
                    sites_devices[site] = []
                sites_devices[site].append({'id': device[0], 'name': device[1], 'icon_class': device[2]})
        
        return render_with_user('devices.html', sites_devices=sites_devices, device_ips=device_ips, 
                               device_tags=device_tags, all_tag_names=all_tag_names, 
                               current_tag_filter=tag_filter)

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
            # Invalidate cache
            cache.clear('devices')
            cache.clear('device_list')
            logging.info(f"User {user_name} added device '{name}' (type {device_type_id}).")
            return redirect(url_for('devices'))
        return render_with_user('add_device.html', device_types=device_types)

    @app.route('/device/<int:device_id>')
    @permission_required('view_device')
    def device(device_id):
        cache_key = f'device:{device_id}'
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            # Verify device still exists before using cached result
            from flask import current_app
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM Device WHERE id = %s', (device_id,))
                if not cursor.fetchone():
                    # Device was deleted, clear cache and redirect
                    cache.delete(cache_key)
                    return redirect(url_for('devices'))
                # Get custom fields for device (not cached)
                custom_fields = get_custom_fields_for_entity('device', device_id, conn=conn)
                cached_result['custom_fields'] = custom_fields
                cached_result['can_edit_device'] = has_permission('edit_device')
            return render_with_user('device.html', **cached_result)
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, description, device_type_id FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                # Device doesn't exist, redirect to devices page
                return redirect(url_for('devices'))
            
            cursor.execute('SELECT id, name FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet')
            subnets = [dict(id=row[0], name=row[1], cidr=row[2], site=row[3]) for row in cursor.fetchall()]
            cursor.execute('''SELECT DeviceIPAddress.id as device_ip_id, IPAddress.ip FROM DeviceIPAddress JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id WHERE DeviceIPAddress.device_id = %s''', (device_id,))
            device_ips = [{'device_ip_id': row[0], 'ip': row[1]} for row in cursor.fetchall()]
            
            # Get device tags
            cursor.execute('''
                SELECT t.id, t.name, t.color
                FROM DeviceTag dt
                JOIN Tag t ON dt.tag_id = t.id
                WHERE dt.device_id = %s
                ORDER BY t.name
            ''', (device_id,))
            device_tags = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
            
            # Get all available tags
            cursor.execute('SELECT id, name, color FROM Tag ORDER BY name')
            all_tags = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
            available_ips_by_subnet = {}
            for subnet in subnets:
                cursor.execute('''
                    SELECT ip.id, ip.ip FROM IPAddress ip
                    LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                    WHERE ip.subnet_id = %s AND dia.ip_id IS NULL
                ''', (subnet['id'],))
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
            
            # Get custom fields for device
            custom_fields = get_custom_fields_for_entity('device', device_id, conn=conn)
            
            # Get IP history for this device
            ip_history = get_ip_history_from_audit_logs(device_id=device_id, conn=conn)
        
        return render_with_user('device.html', 
                               device={'id': device[0], 'name': device[1], 'description': device[2], 'device_type_id': device[3]}, 
                               subnets=subnets, device_ips=device_ips, available_ips_by_subnet=available_ips_by_subnet, 
                               device_types=device_types, device_tags=device_tags, all_tags=all_tags,
                               can_assign_device_tag=has_permission('assign_device_tag'),
                               can_remove_device_tag=has_permission('remove_device_tag'),
                               ip_history=ip_history,
                               custom_fields=custom_fields,
                               can_edit_device=has_permission('edit_device'))

    @app.route('/api/device/<int:device_id>/ip_history')
    @permission_required('view_device')
    def device_ip_history(device_id):
        """Get IP history for a device as JSON"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            ip_history = get_ip_history_from_audit_logs(device_id=device_id, conn=conn)
        return jsonify({'history': ip_history})
    
    @app.route('/api/ip/<ip_address>/history')
    @permission_required('view_subnet')
    def ip_address_history(ip_address):
        """Get IP history for a specific IP address as JSON"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            ip_history = get_ip_history_from_audit_logs(ip_address=ip_address, conn=conn)
        return jsonify({'history': ip_history, 'ip': ip_address})
    
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
        # Invalidate cache
        invalidate_cache_for_device(device_id)
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
        # Invalidate cache
        invalidate_cache_for_device(device_id)
        cache.invalidate_subnet(subnet_id_val)
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
        # Invalidate cache
        invalidate_cache_for_device(device_id)
        cache.invalidate_subnet(subnet_id_val)
        logging.info(f"User {user_name} removed IP {ip} from device {device_id}.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/assign_tag', methods=['POST'])
    @permission_required('assign_device_tag')
    def device_assign_tag(device_id):
        tag_id = request.form['tag_id']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return redirect(url_for('devices'))
            device_name = device[0]
            
            cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
            tag = cursor.fetchone()
            if not tag:
                return redirect(url_for('device', device_id=device_id))
            tag_name = tag[0]
            
            cursor.execute('SELECT id FROM DeviceTag WHERE device_id = %s AND tag_id = %s', (device_id, tag_id))
            if cursor.fetchone():
                return redirect(url_for('device', device_id=device_id))  # Already assigned
            
            cursor.execute('INSERT INTO DeviceTag (device_id, tag_id) VALUES (%s, %s)', (device_id, tag_id))
            add_audit_log(session['user_id'], 'assign_device_tag', f"Assigned tag '{tag_name}' to device '{device_name}'", conn=conn)
            conn.commit()
            # Invalidate cache
            invalidate_cache_for_device(device_id)
            cache.clear('devices')
        return redirect(url_for('device', device_id=device_id))

    @app.route('/device/<int:device_id>/remove_tag', methods=['POST'])
    @permission_required('remove_device_tag')
    def device_remove_tag(device_id):
        tag_id = request.form['tag_id']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return redirect(url_for('devices'))
            device_name = device[0]
            
            cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
            tag = cursor.fetchone()
            if not tag:
                return redirect(url_for('device', device_id=device_id))
            tag_name = tag[0]
            
            cursor.execute('DELETE FROM DeviceTag WHERE device_id = %s AND tag_id = %s', (device_id, tag_id))
            add_audit_log(session['user_id'], 'remove_device_tag', f"Removed tag '{tag_name}' from device '{device_name}'", conn=conn)
            conn.commit()
            # Invalidate cache
            invalidate_cache_for_device(device_id)
            cache.clear('devices')
        return redirect(url_for('device', device_id=device_id))

    @app.route('/delete_device', methods=['POST'])
    @permission_required('delete_device')
    def delete_device():
        device_id = request.form['device_id']
        user_name = get_current_user_name()
        from flask import current_app
        subnet_ids_to_invalidate = set()
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device_row = cursor.fetchone()
            if device_row:
                device_name = device_row[0]
                add_audit_log(session['user_id'], 'delete_device', f"Deleted device {device_name}", conn=conn)
                # Get subnet IDs for all IPs assigned to this device before deleting
                cursor.execute('''
                    SELECT DISTINCT ip.subnet_id 
                    FROM DeviceIPAddress dia
                    JOIN IPAddress ip ON dia.ip_id = ip.id
                    WHERE dia.device_id = %s
                ''', (device_id,))
                subnet_ids_to_invalidate = {row[0] for row in cursor.fetchall()}
                
                cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
                ip_ids = [row[0] for row in cursor.fetchall()]
                if ip_ids:
                    cursor.executemany('UPDATE IPAddress SET hostname = NULL WHERE id = %s', [(ip_id,) for ip_id in ip_ids])
                cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
                cursor.execute('DELETE FROM Device WHERE id = %s', (device_id,))
                conn.commit()
        # Invalidate cache
        invalidate_cache_for_device(device_id)
        cache.clear('devices')
        # Invalidate subnet caches for all subnets that had IPs assigned to this device
        for subnet_id in subnet_ids_to_invalidate:
            cache.invalidate_subnet(subnet_id)
        logging.info(f"User {user_name} deleted device '{device_name}'.")
        return redirect(url_for('devices'))

    @app.route('/subnet/<int:subnet_id>')
    @permission_required('view_subnet')
    def subnet(subnet_id):
        cache_key = f'subnet:{subnet_id}'
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            from flask import current_app
            with get_db_connection(current_app) as conn:
                custom_fields = get_custom_fields_for_entity('subnet', subnet_id, conn=conn)
                # Ensure VLAN fields are in cached subnet dict
                subnet_dict = cached_result['subnet']
                if 'vlan_id' not in subnet_dict:
                    cursor = conn.cursor()
                    cursor.execute('SELECT vlan_id, vlan_description, vlan_notes FROM Subnet WHERE id = %s', (subnet_id,))
                    vlan_row = cursor.fetchone()
                    if vlan_row:
                        subnet_dict['vlan_id'] = vlan_row[0]
                        subnet_dict['vlan_description'] = vlan_row[1]
                        subnet_dict['vlan_notes'] = vlan_row[2]
            return render_with_user('subnet.html', subnet=subnet_dict, 
                                  ip_addresses=cached_result['ip_addresses'], 
                                  utilization=cached_result['utilization'],
                                  custom_fields=custom_fields,
                                  can_edit_subnet=has_permission('edit_subnet'))
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr, vlan_id, vlan_description, vlan_notes FROM Subnet WHERE id = %s', (subnet_id,))
            subnet = cursor.fetchone()
            cursor.execute('SELECT id, ip, hostname, notes FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_addresses = cursor.fetchall()
            
            # Calculate utilization stats
            cursor.execute('SELECT COUNT(*) FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            total_ips = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM IPAddress ip
                WHERE ip.subnet_id = %s AND ip.id IN (SELECT ip_id FROM DeviceIPAddress)
            ''', (subnet_id,))
            assigned_ips = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM IPAddress ip
                WHERE ip.subnet_id = %s AND ip.hostname = 'DHCP' AND ip.id NOT IN (SELECT ip_id FROM DeviceIPAddress)
            ''', (subnet_id,))
            dhcp_ips = cursor.fetchone()[0]
            
            available_ips = total_ips - assigned_ips - dhcp_ips
            used_ips = assigned_ips + dhcp_ips
            utilization_percent = (used_ips / total_ips * 100) if total_ips > 0 else 0
            
            utilization_stats = {
                'total': total_ips,
                'assigned': assigned_ips,
                'dhcp': dhcp_ips,
                'available': available_ips,
                'percent': round(utilization_percent, 1)
            }
            
            # Get custom fields for subnet
            custom_fields = get_custom_fields_for_entity('subnet', subnet_id, conn=conn)
            
            cursor.execute('SELECT id, name, description FROM Device')
            devices = cursor.fetchall()
            device_name_map = {name.lower(): (id, description) for id, name, description in devices}
            ip_addresses_with_device = []
            for ip in ip_addresses:
                ip_id = ip[0]
                ip_address = ip[1]
                hostname = ip[2]
                ip_notes = ip[3] if len(ip) > 3 else None
                device_id = None
                device_description = None
                if hostname:
                    match = device_name_map.get(hostname.lower())
                    if match:
                        device_id, device_description = match
                ip_addresses_with_device.append((ip_id, ip_address, hostname, device_id, device_description, ip_notes))
            
            subnet_dict = {
                'id': subnet[0], 
                'name': subnet[1], 
                'cidr': subnet[2],
                'vlan_id': subnet[3] if len(subnet) > 3 else None,
                'vlan_description': subnet[4] if len(subnet) > 4 else None,
                'vlan_notes': subnet[5] if len(subnet) > 5 else None
            }
            result = {
                'subnet': subnet_dict,
                'ip_addresses': ip_addresses_with_device,
                'utilization': utilization_stats
            }
            # Cache for 3 hours
            cache.set(cache_key, result, ttl=10800)
            return render_with_user('subnet.html', subnet=subnet_dict, 
                                  ip_addresses=ip_addresses_with_device, 
                                  utilization=utilization_stats,
                                  custom_fields=custom_fields,
                                  can_edit_subnet=has_permission('edit_subnet'))

    @app.route('/add_subnet', methods=['POST'])
    @permission_required('add_subnet')
    def add_subnet():
        name = request.form['name']
        cidr = request.form['cidr']
        site = request.form['site']
        vlan_id_str = request.form.get('vlan_id', '').strip()
        vlan_description = request.form.get('vlan_description', '').strip()
        vlan_notes = request.form.get('vlan_notes', '').strip()
        user_name = get_current_user_name()
        
        # Validate VLAN ID if provided
        if vlan_id_str:
            is_valid, error_msg, vlan_id = validate_vlan_id(vlan_id_str)
            if not is_valid:
                return render_with_user('admin.html', subnets=[], error=error_msg)
        else:
            vlan_id = None
        
        try:
            network = ip_network(cidr, strict=False)
            if network.prefixlen < 24:
                return render_with_user('admin.html', subnets=[], error='Subnet must be /24 or smaller (e.g., /24, /25, ... /32)')
        except Exception as e:
            return render_with_user('admin.html', subnets=[], error='Invalid CIDR format.')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Subnet (name, cidr, site, vlan_id, vlan_description, vlan_notes) VALUES (%s, %s, %s, %s, %s, %s)', 
                          (name, cidr, site, vlan_id, vlan_description if vlan_description else None, vlan_notes if vlan_notes else None))
            subnet_id = cursor.lastrowid
            ip_rows = [(str(ip), subnet_id) for ip in network.hosts()]
            cursor.executemany('INSERT INTO IPAddress (ip, subnet_id) VALUES (%s, %s)', ip_rows)
            vlan_info = f" (VLAN {vlan_id})" if vlan_id else ""
            add_audit_log(session['user_id'], 'add_subnet', f"Added subnet {name} ({cidr}){vlan_info}", subnet_id, conn=conn)
            conn.commit()
        # Invalidate cache
        cache.clear('index')
        cache.clear('admin')
        cache.clear('subnet_list')
        # Note: subnet_id is new, so no need to invalidate specific subnet cache
        logging.info(f"User {user_name} added subnet '{name}' ({cidr}) at site '{site}'.")
        return redirect(url_for('admin'))

    @app.route('/edit_subnet', methods=['POST'])
    @permission_required('edit_subnet')
    def edit_subnet():
        subnet_id = request.form['subnet_id']
        name = request.form['name']
        cidr = request.form['cidr']
        site = request.form['site']
        vlan_id_str = request.form.get('vlan_id', '').strip()
        vlan_description = request.form.get('vlan_description', '').strip()
        vlan_notes = request.form.get('vlan_notes', '').strip()
        user_name = get_current_user_name()
        
        # Validate VLAN ID if provided
        if vlan_id_str:
            is_valid, error_msg, vlan_id = validate_vlan_id(vlan_id_str)
            if not is_valid:
                return render_with_user('admin.html', subnets=[], error=error_msg)
        else:
            vlan_id = None
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
            old_subnet = cursor.fetchone()
            if old_subnet:
                old_name, old_cidr = old_subnet
                cursor.execute('UPDATE Subnet SET name = %s, cidr = %s, site = %s, vlan_id = %s, vlan_description = %s, vlan_notes = %s WHERE id = %s', 
                              (name, cidr, site, vlan_id, vlan_description if vlan_description else None, vlan_notes if vlan_notes else None, subnet_id))
                vlan_info = f" (VLAN {vlan_id})" if vlan_id else ""
                add_audit_log(session['user_id'], 'edit_subnet', f"Edited subnet from {old_name} ({old_cidr}) to {name} ({cidr}) at site {site}{vlan_info}", subnet_id, conn=conn)
                conn.commit()
        # Invalidate cache
        invalidate_cache_for_subnet(subnet_id)
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
            # Set subnet_id to NULL in audit logs (foreign key will handle this, but doing it explicitly for clarity)
            cursor.execute('UPDATE AuditLog SET subnet_id=NULL WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('DELETE FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            cursor.execute('DELETE FROM Subnet WHERE id = %s', (subnet_id,))
            conn.commit()
        # Invalidate cache
        invalidate_cache_for_subnet(subnet_id)
        logging.info(f"User {user_name} deleted subnet {subnet_id}.")
        return redirect(url_for('admin'))

    @app.route('/admin', methods=['GET', 'POST'])
    @permission_required('view_admin')
    def admin():
        cache_key = 'admin'
        cached_result = cache.get(cache_key)
        
        # Check if cached data has VLAN fields (for backward compatibility)
        if cached_result is not None:
            # Verify cached subnets have VLAN fields, if not, refresh cache
            if cached_result.get('subnets') and len(cached_result['subnets']) > 0:
                sample_subnet = cached_result['subnets'][0]
                if 'vlan_id' not in sample_subnet:
                    # Cache is stale, clear it and regenerate
                    cache.clear(cache_key)
                    cached_result = None
        
        if cached_result is not None:
            return render_with_user('admin.html', **cached_result)
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, cidr, site, vlan_id, vlan_description, vlan_notes FROM Subnet ORDER BY site, name')
            subnet_rows = cursor.fetchall()
            subnets = []
            for row in subnet_rows:
                subnet_id = row[0]
                # Calculate utilization for each subnet
                cursor.execute('SELECT COUNT(*) FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                total_ips = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM IPAddress ip
                    INNER JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                    WHERE ip.subnet_id = %s
                ''', (subnet_id,))
                assigned_ips = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM IPAddress ip
                    LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                    WHERE ip.subnet_id = %s AND ip.hostname = 'DHCP' AND dia.ip_id IS NULL
                ''', (subnet_id,))
                dhcp_ips = cursor.fetchone()[0]
                
                available_ips = total_ips - assigned_ips - dhcp_ips
                used_ips = assigned_ips + dhcp_ips
                utilization_percent = (used_ips / total_ips * 100) if total_ips > 0 else 0
                
                subnets.append({
                    'id': row[0],
                    'name': row[1],
                    'cidr': row[2],
                    'site': row[3] or 'Unassigned',
                    'vlan_id': row[4] if len(row) > 4 and row[4] is not None else None,
                    'vlan_description': row[5] if len(row) > 5 and row[5] is not None else None,
                    'vlan_notes': row[6] if len(row) > 6 and row[6] is not None else None,
                    'utilization': {
                        'percent': round(utilization_percent, 1),
                        'assigned': assigned_ips,
                        'used': used_ips,
                        'total': total_ips
                    }
                })
        result_data = {
            'subnets': subnets,
            'can_add_subnet': has_permission('add_subnet'),
            'can_edit_subnet': has_permission('edit_subnet'),
            'can_delete_subnet': has_permission('delete_subnet')
        }
        # Cache for 3 hours
        cache.set(cache_key, result_data, ttl=10800)
        return render_with_user('admin.html', **result_data)

    @app.route('/api-docs')
    @permission_required('view_admin')
    def api_docs():
        # Get current user's API key
        from flask import current_app
        api_key = None
        if 'user_id' in session:
            with get_db_connection(current_app) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT api_key FROM User WHERE id = %s', (session['user_id'],))
                result = cursor.fetchone()
                if result:
                    api_key = result[0]
        return render_with_user('api_docs.html', api_key=api_key)

    @app.route('/account', methods=['GET'])
    @login_required
    def account_settings():
        from totp_utils import format_backup_codes
        from flask import current_app
        import json
        
        user_id = session.get('user_id')
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.totp_enabled, u.backup_codes, r.require_2fa
                FROM User u
                LEFT JOIN Role r ON u.role_id = r.id
                WHERE u.id = %s
            ''', (user_id,))
            result = cursor.fetchone()
            totp_enabled = result[0] if result else False
            backup_codes_json = result[1] if result else None
            role_requires_2fa = result[2] if result else False
        
        backup_codes = None
        if backup_codes_json:
            try:
                codes = json.loads(backup_codes_json)
                backup_codes = format_backup_codes(codes)
            except (json.JSONDecodeError, TypeError):
                pass
        
        return render_with_user('account_settings.html', 
                              totp_enabled=totp_enabled,
                              backup_codes=backup_codes,
                              role_requires_2fa=role_requires_2fa)
    
    @app.route('/account/enable-2fa', methods=['GET', 'POST'])
    @login_required
    def enable_2fa():
        from totp_utils import generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp, generate_backup_codes, format_backup_codes
        from flask import current_app
        import json
        
        user_id = session.get('user_id')
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'generate':
                secret = generate_totp_secret()
                session['temp_totp_secret'] = secret
                with get_db_connection(current_app) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT email FROM User WHERE id = %s', (user_id,))
                    email = cursor.fetchone()[0]
                
                totp_uri = get_totp_uri(secret, email)
                qr_code = generate_qr_code(totp_uri)
                return render_with_user('enable_2fa.html', secret=secret, qr_code=qr_code, email=email, step='verify')
            
            elif action == 'verify':
                code = request.form.get('code', '').strip()
                secret = session.get('temp_totp_secret')
                
                if not secret:
                    return render_with_user('enable_2fa.html', error='Session expired. Please start over.', step='generate')
                
                if verify_totp(secret, code):
                    backup_codes = generate_backup_codes()
                    backup_codes_json = json.dumps(backup_codes)
                    
                    with get_db_connection(current_app) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            UPDATE User 
                            SET totp_secret = %s, totp_enabled = TRUE, backup_codes = %s, two_fa_setup_complete = TRUE
                            WHERE id = %s
                        ''', (secret, backup_codes_json, user_id))
                    
                    session.pop('temp_totp_secret', None)
                    formatted_codes = format_backup_codes(backup_codes)
                    logging.info(f"User {user_id} enabled 2FA.")
                    return render_with_user('enable_2fa.html', backup_codes=formatted_codes, step='backup_codes')
                else:
                    return render_with_user('enable_2fa.html', error='Invalid code. Please try again.', secret=secret, step='verify')
        
        return render_with_user('enable_2fa.html', step='generate')
    
    @app.route('/account/disable-2fa', methods=['POST'])
    @login_required
    def disable_2fa():
        from flask import current_app
        
        user_id = session.get('user_id')
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE User 
                SET totp_secret = NULL, totp_enabled = FALSE, backup_codes = NULL, two_fa_setup_complete = FALSE
                WHERE id = %s
            ''', (user_id,))
        
        logging.info(f"User {user_id} disabled 2FA.")
        return redirect(url_for('account_settings', success='2FA has been disabled.'))
    
    @app.route('/account/regenerate-backup-codes', methods=['POST'])
    @login_required
    def regenerate_backup_codes():
        from totp_utils import generate_backup_codes, format_backup_codes
        from flask import current_app
        import json
        
        user_id = session.get('user_id')
        backup_codes = generate_backup_codes()
        backup_codes_json = json.dumps(backup_codes)
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE User SET backup_codes = %s WHERE id = %s', (backup_codes_json, user_id))
        
        formatted_codes = format_backup_codes(backup_codes)
        logging.info(f"User {user_id} regenerated backup codes.")
        return render_with_user('regenerate_backup_codes.html', backup_codes=formatted_codes)
    
    @app.route('/account/change-password', methods=['POST'])
    @login_required
    def change_password():
        from flask import current_app
        
        user_id = session.get('user_id')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            return redirect(url_for('account_settings', error='New passwords do not match.'))
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM User WHERE id = %s', (user_id,))
            result = cursor.fetchone()
            if not result or not verify_password(current_password, result[0]):
                return redirect(url_for('account_settings', error='Current password is incorrect.'))
            
            hashed_password = hash_password(new_password)
            cursor.execute('UPDATE User SET password = %s WHERE id = %s', (hashed_password, user_id))
        
        logging.info(f"User {user_id} changed password.")
        return redirect(url_for('account_settings', success='Password changed successfully.'))
    
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
                        require_2fa = request.form.get('require_2fa') == 'on'
                        if not role_name:
                            error = 'Role name is required.'
                        else:
                            try:
                                cursor.execute('INSERT INTO Role (name, description, require_2fa) VALUES (%s, %s, %s)', (role_name, role_description, require_2fa))
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
                        require_2fa = request.form.get('require_2fa') == 'on'
                        if not role_name:
                            error = 'Role name is required.'
                        else:
                            try:
                                cursor.execute('UPDATE Role SET name=%s, description=%s, require_2fa=%s WHERE id=%s', (role_name, role_description, require_2fa, role_id))
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
            cursor.execute('SELECT id, name, description, require_2fa FROM Role ORDER BY name')
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

    @app.route('/tags', methods=['GET', 'POST'])
    @permission_required('view_tags')
    def tags():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            error = None
            
            if request.method == 'POST':
                action = request.form['action']
                
                if action == 'add_tag':
                    if not has_permission('add_tag', conn=conn):
                        error = 'You do not have permission to add tags.'
                    else:
                        name = request.form['name'].strip()
                        color = request.form.get('color', '#6B7280')
                        description = request.form.get('description', '').strip()
                        
                        if not name:
                            error = 'Tag name is required.'
                        else:
                            try:
                                cursor.execute('INSERT INTO Tag (name, color, description) VALUES (%s, %s, %s)', 
                                             (name, color, description))
                                add_audit_log(session['user_id'], 'add_tag', f"Added tag '{name}'", conn=conn)
                                conn.commit()
                                # Invalidate device caches since they contain tags
                                cache.clear('device:')
                                cache.clear('devices')
                            except mysql.connector.IntegrityError:
                                error = 'Tag name already exists.'
                
                elif action == 'edit_tag':
                    if not has_permission('edit_tag', conn=conn):
                        error = 'You do not have permission to edit tags.'
                    else:
                        tag_id = request.form['tag_id']
                        name = request.form['name'].strip()
                        color = request.form.get('color', '#6B7280')
                        description = request.form.get('description', '').strip()
                        
                        if not name:
                            error = 'Tag name is required.'
                        else:
                            try:
                                cursor.execute('UPDATE Tag SET name = %s, color = %s, description = %s WHERE id = %s', 
                                             (name, color, description, tag_id))
                                add_audit_log(session['user_id'], 'edit_tag', f"Updated tag '{name}'", conn=conn)
                                conn.commit()
                                # Invalidate device caches since they contain tags
                                cache.clear('device:')
                                cache.clear('devices')
                            except mysql.connector.IntegrityError:
                                error = 'Tag name already exists.'
                
                elif action == 'delete_tag':
                    if not has_permission('delete_tag', conn=conn):
                        error = 'You do not have permission to delete tags.'
                    else:
                        tag_id = request.form['tag_id']
                        cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
                        tag_name = cursor.fetchone()[0]
                        cursor.execute('DELETE FROM Tag WHERE id = %s', (tag_id,))
                        add_audit_log(session['user_id'], 'delete_tag', f"Deleted tag '{tag_name}'", conn=conn)
                        conn.commit()
                        # Invalidate device caches since they contain tags
                        cache.clear('device:')
                        cache.clear('devices')
            
            # Get all tags with device counts
            cursor.execute('''
                SELECT t.id, t.name, t.color, t.description, t.created_at,
                       COUNT(dt.device_id) as device_count
                FROM Tag t
                LEFT JOIN DeviceTag dt ON t.id = dt.tag_id
                GROUP BY t.id, t.name, t.color, t.description, t.created_at
                ORDER BY t.name
            ''')
            tags = [dict(id=row[0], name=row[1], color=row[2], description=row[3], 
                        created_at=row[4], device_count=row[5]) for row in cursor.fetchall()]
            
        return render_with_user('tags.html', tags=tags, error=error,
                               can_add_tag=has_permission('add_tag'),
                               can_edit_tag=has_permission('edit_tag'),
                               can_delete_tag=has_permission('delete_tag'))

    @app.route('/custom_fields', methods=['GET', 'POST'])
    @permission_required('view_custom_fields')
    def custom_fields():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            error = None
            
            if request.method == 'POST':
                action = request.form.get('action')
                
                if action == 'add_field':
                    if not has_permission('manage_custom_fields', conn=conn):
                        error = 'You do not have permission to add custom fields.'
                    else:
                        entity_type = request.form.get('entity_type', '').strip()
                        # Debug logging
                        logging.info(f"Received entity_type: '{entity_type}' (type: {type(entity_type)})")
                        logging.info(f"Form data keys: {list(request.form.keys())}")
                        if not entity_type or entity_type not in ['device', 'subnet']:
                            # Try to get from form data directly
                            entity_type_raw = request.form.get('entity_type')
                            logging.error(f"Invalid entity_type received: '{entity_type}' (raw: '{entity_type_raw}')")
                            # Show more helpful error
                            error = f'Invalid entity type: "{entity_type}". Must be "device" or "subnet". Please try again.'
                        else:
                            name = request.form['name'].strip()
                            field_key = request.form.get('field_key', '').strip()
                            field_type = request.form['field_type']
                            required = 'required' in request.form
                            default_value = request.form.get('default_value', '').strip()
                            help_text = request.form.get('help_text', '').strip()
                            display_order = int(request.form.get('display_order', 0))
                            searchable = 'searchable' in request.form
                            
                            # Generate field_key from name if not provided
                            if not field_key:
                                field_key = re.sub(r'[^a-z0-9_]+', '_', name.lower()).strip('_')
                            
                            # Build validation_rules JSON
                            validation_rules = {}
                            if field_type in ['text', 'textarea']:
                                if request.form.get('min_length'):
                                    validation_rules['min_length'] = int(request.form['min_length'])
                                if request.form.get('max_length'):
                                    validation_rules['max_length'] = int(request.form['max_length'])
                                if request.form.get('regex_pattern'):
                                    validation_rules['regex_pattern'] = request.form['regex_pattern']
                            elif field_type in ['number', 'decimal']:
                                if request.form.get('min_value'):
                                    validation_rules['min_value'] = float(request.form['min_value'])
                                if request.form.get('max_value'):
                                    validation_rules['max_value'] = float(request.form['max_value'])
                            elif field_type == 'select':
                                options = request.form.get('select_options', '').strip()
                                if options:
                                    validation_rules['select_options'] = [opt.strip() for opt in options.split(',') if opt.strip()]
                            
                            validation_rules_json = json.dumps(validation_rules) if validation_rules else None
                            
                            if not name:
                                error = 'Field name is required.'
                            elif not field_key:
                                error = 'Field key is required.'
                            else:
                                try:
                                    cursor.execute('''
                                        INSERT INTO CustomFieldDefinition 
                                        (entity_type, name, field_key, field_type, required, default_value, 
                                         help_text, display_order, validation_rules, searchable)
                                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                    ''', (entity_type, name, field_key, field_type, required, default_value,
                                          help_text, display_order, validation_rules_json, searchable))
                                    add_audit_log(session['user_id'], 'add_custom_field', 
                                                f"Added custom field '{name}' for {entity_type}", conn=conn)
                                    conn.commit()
                                    # Redirect to preserve tab state
                                    return redirect(url_for('custom_fields', tab=entity_type))
                                except mysql.connector.IntegrityError:
                                    error = f'Field key "{field_key}" already exists.'
                
                elif action == 'edit_field':
                    if not has_permission('manage_custom_fields', conn=conn):
                        error = 'You do not have permission to edit custom fields.'
                    else:
                        field_id = request.form['field_id']
                        name = request.form['name'].strip()
                        field_type = request.form['field_type']
                        required = 'required' in request.form
                        default_value = request.form.get('default_value', '').strip()
                        help_text = request.form.get('help_text', '').strip()
                        display_order = int(request.form.get('display_order', 0))
                        searchable = 'searchable' in request.form
                        
                        # Build validation_rules JSON
                        validation_rules = {}
                        if field_type in ['text', 'textarea']:
                            if request.form.get('min_length'):
                                validation_rules['min_length'] = int(request.form['min_length'])
                            if request.form.get('max_length'):
                                validation_rules['max_length'] = int(request.form['max_length'])
                            if request.form.get('regex_pattern'):
                                validation_rules['regex_pattern'] = request.form['regex_pattern']
                        elif field_type in ['number', 'decimal']:
                            if request.form.get('min_value'):
                                validation_rules['min_value'] = float(request.form['min_value'])
                            if request.form.get('max_value'):
                                validation_rules['max_value'] = float(request.form['max_value'])
                        elif field_type == 'select':
                            options = request.form.get('select_options', '').strip()
                            if options:
                                validation_rules['select_options'] = [opt.strip() for opt in options.split(',') if opt.strip()]
                        
                        validation_rules_json = json.dumps(validation_rules) if validation_rules else None
                        
                        if not name:
                            error = 'Field name is required.'
                        else:
                            # Get entity_type of the field being edited
                            cursor.execute('SELECT entity_type FROM CustomFieldDefinition WHERE id = %s', (field_id,))
                            field_row = cursor.fetchone()
                            entity_type = field_row['entity_type'] if field_row else 'device'
                            
                            cursor.execute('''
                                UPDATE CustomFieldDefinition 
                                SET name = %s, field_type = %s, required = %s, default_value = %s,
                                    help_text = %s, display_order = %s, validation_rules = %s, searchable = %s
                                WHERE id = %s
                            ''', (name, field_type, required, default_value, help_text, 
                                  display_order, validation_rules_json, searchable, field_id))
                            add_audit_log(session['user_id'], 'edit_custom_field', 
                                        f"Updated custom field '{name}'", conn=conn)
                            conn.commit()
                            # Redirect to preserve tab state
                            return redirect(url_for('custom_fields', tab=entity_type))
                
                elif action == 'delete_field':
                    if not has_permission('manage_custom_fields', conn=conn):
                        error = 'You do not have permission to delete custom fields.'
                    else:
                        field_id = request.form['field_id']
                        cursor.execute('SELECT name, entity_type FROM CustomFieldDefinition WHERE id = %s', (field_id,))
                        field = cursor.fetchone()
                        if field:
                            field_name = field['name']
                            entity_type = field['entity_type']
                            cursor.execute('DELETE FROM CustomFieldDefinition WHERE id = %s', (field_id,))
                            add_audit_log(session['user_id'], 'delete_custom_field', 
                                        f"Deleted custom field '{field_name}'", conn=conn)
                            conn.commit()
                            # Redirect to preserve tab state
                            return redirect(url_for('custom_fields', tab=entity_type))
                
                elif action == 'reorder':
                    if not has_permission('manage_custom_fields', conn=conn):
                        error = 'You do not have permission to reorder custom fields.'
                    else:
                        entity_type = request.form['entity_type']
                        field_orders = json.loads(request.form['field_orders'])
                        for field_id, order in field_orders.items():
                            cursor.execute('UPDATE CustomFieldDefinition SET display_order = %s WHERE id = %s AND entity_type = %s',
                                         (order, field_id, entity_type))
                        conn.commit()
                        # Redirect to preserve tab state
                        return redirect(url_for('custom_fields', tab=entity_type))
                        # Redirect to preserve tab state
                        return redirect(url_for('custom_fields', tab=entity_type))
            
            # Get all custom fields grouped by entity type
            cursor.execute('''
                SELECT id, entity_type, name, field_key, field_type, required, 
                       default_value, help_text, display_order, validation_rules, searchable
                FROM CustomFieldDefinition
                ORDER BY entity_type, display_order, name
            ''')
            all_fields = cursor.fetchall()
            
            # Parse validation_rules JSON strings to objects
            for field in all_fields:
                if field['validation_rules']:
                    try:
                        field['validation_rules'] = json.loads(field['validation_rules'])
                    except (json.JSONDecodeError, TypeError):
                        field['validation_rules'] = {}
                else:
                    field['validation_rules'] = {}
            
            device_fields = [f for f in all_fields if f['entity_type'] == 'device']
            subnet_fields = [f for f in all_fields if f['entity_type'] == 'subnet']
            
            # Get active tab from query parameter
            active_tab = request.args.get('tab', 'device')
            if active_tab not in ['device', 'subnet']:
                active_tab = 'device'
            
        return render_with_user('custom_fields.html', 
                               device_fields=device_fields,
                               subnet_fields=subnet_fields,
                               error=error,
                               can_manage=has_permission('manage_custom_fields'),
                               active_tab=active_tab)

    @app.route('/custom_fields/<entity_type>')
    @permission_required('view_custom_fields')
    def custom_fields_by_type(entity_type):
        """Get custom fields for a specific entity type"""
        if entity_type not in ['device', 'subnet']:
            abort(404)
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, entity_type, name, field_key, field_type, required, 
                       default_value, help_text, display_order, validation_rules, searchable
                FROM CustomFieldDefinition
                WHERE entity_type = %s
                ORDER BY display_order, name
            ''', (entity_type,))
            fields = cursor.fetchall()
        
        return jsonify({'fields': fields})

    @app.route('/audit')
    @permission_required('view_audit')
    def audit():
        PER_PAGE = 25
        page = int(request.args.get('page', 1))
        offset = (page - 1) * PER_PAGE
        
        # Get filter parameters
        user_ids = request.args.getlist('user_ids')  # Multiple users
        subnet_id = request.args.get('subnet_id')
        action = request.args.get('action')
        device_name = request.args.get('device_name')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        search_query = request.args.get('search', '').strip()
        
        query = '''SELECT AuditLog.id, COALESCE(User.name, 'Deleted User'), AuditLog.action, AuditLog.details, Subnet.name, AuditLog.timestamp FROM AuditLog LEFT JOIN User ON AuditLog.user_id = User.id LEFT JOIN Subnet ON AuditLog.subnet_id = Subnet.id WHERE 1=1'''
        params = []
        
        # Multiple user filtering
        if user_ids:
            placeholders = ','.join(['%s'] * len(user_ids))
            query += f' AND AuditLog.user_id IN ({placeholders})'
            params.extend(user_ids)
        
        if subnet_id:
            query += ' AND AuditLog.subnet_id = %s'
            params.append(subnet_id)
        
        if action:
            query += ' AND AuditLog.action = %s'
            params.append(action)
        
        if device_name:
            query += ' AND AuditLog.details LIKE %s'
            params.append(f'%{device_name}%')
        
        # Date range filtering
        if date_from:
            query += ' AND AuditLog.timestamp >= %s'
            params.append(date_from)
        
        if date_to:
            query += ' AND AuditLog.timestamp <= %s'
            params.append(date_to + ' 23:59:59')
        
        # Search query (searches in details, user name, action, subnet name)
        if search_query:
            query += ' AND (AuditLog.details LIKE %s OR COALESCE(User.name, \'\') LIKE %s OR AuditLog.action LIKE %s OR COALESCE(Subnet.name, \'\') LIKE %s)'
            search_pattern = f'%{search_query}%'
            params.extend([search_pattern, search_pattern, search_pattern, search_pattern])
        
        count_query = 'SELECT COUNT(*) FROM (' + query + ') AS count_subquery'
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(buffered=True)
            cursor.execute(count_query, params)
            total_logs = cursor.fetchone()[0]
            query += ' ORDER BY AuditLog.timestamp DESC LIMIT %s OFFSET %s'
            cursor.execute(query, params + [PER_PAGE, offset])
            logs = cursor.fetchall()
            cursor.execute('SELECT id, name FROM User ORDER BY name')
            users = cursor.fetchall()
            cursor.execute('SELECT id, name FROM Subnet ORDER BY name')
            subnets = cursor.fetchall()
            cursor.execute('SELECT DISTINCT action FROM AuditLog ORDER BY action')
            actions = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT name FROM Device ORDER BY name')
            devices = cursor.fetchall()
        query_args = request.args.to_dict()
        total_pages = (total_logs + PER_PAGE - 1) // PER_PAGE
        return render_with_user('audit.html', logs=logs, users=users, subnets=subnets, actions=actions, devices=devices, page=page, total_pages=total_pages, query_args=query_args, selected_user_ids=user_ids, date_from=date_from, date_to=date_to, search_query=search_query)

    @app.route('/audit/export_csv')
    @permission_required('view_audit')
    def export_audit_csv():
        """Export audit logs to CSV with current filters applied"""
        # Get filter parameters (same as audit route)
        user_ids = request.args.getlist('user_ids')
        subnet_id = request.args.get('subnet_id')
        action = request.args.get('action')
        device_name = request.args.get('device_name')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        search_query = request.args.get('search', '').strip()
        
        query = '''SELECT COALESCE(User.name, 'Deleted User'), AuditLog.action, AuditLog.details, COALESCE(Subnet.name, 'N/A'), AuditLog.timestamp FROM AuditLog LEFT JOIN User ON AuditLog.user_id = User.id LEFT JOIN Subnet ON AuditLog.subnet_id = Subnet.id WHERE 1=1'''
        params = []
        
        # Apply same filters as audit route
        if user_ids:
            placeholders = ','.join(['%s'] * len(user_ids))
            query += f' AND AuditLog.user_id IN ({placeholders})'
            params.extend(user_ids)
        
        if subnet_id:
            query += ' AND AuditLog.subnet_id = %s'
            params.append(subnet_id)
        
        if action:
            query += ' AND AuditLog.action = %s'
            params.append(action)
        
        if device_name:
            query += ' AND AuditLog.details LIKE %s'
            params.append(f'%{device_name}%')
        
        if date_from:
            query += ' AND AuditLog.timestamp >= %s'
            params.append(date_from)
        
        if date_to:
            query += ' AND AuditLog.timestamp <= %s'
            params.append(date_to + ' 23:59:59')
        
        if search_query:
            query += ' AND (AuditLog.details LIKE %s OR COALESCE(User.name, \'\') LIKE %s OR AuditLog.action LIKE %s OR COALESCE(Subnet.name, \'\') LIKE %s)'
            search_pattern = f'%{search_query}%'
            params.extend([search_pattern, search_pattern, search_pattern, search_pattern])
        
        query += ' ORDER BY AuditLog.timestamp DESC'
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            logs = cursor.fetchall()
        
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['User', 'Action', 'Details', 'Subnet', 'Timestamp'])
        
        for log in logs:
            writer.writerow(log)
        
        csv_bytes = output.getvalue().encode('utf-8')
        output_bytes = BytesIO(csv_bytes)
        
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'audit_logs_{timestamp}.csv'
        
        return send_file(
            output_bytes,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )

    @app.route('/check_update')
    @login_required
    def check_update():
        """Check for available updates from GitHub (cached for 3 hours)"""
        cache_key = 'check_update'
        
        # Check cache first
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return jsonify(cached_result)
        
        try:
            # Get current version
            version_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VERSION')
            current_version = 'unknown'
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    current_version = f.read().strip()
            
            # Fetch latest release from GitHub
            response = requests.get('https://api.github.com/repos/JDB-NET/ipam/releases/latest', timeout=5)
            if response.status_code != 200:
                return jsonify({'error': 'Failed to fetch release information'}), 500
            
            release_data = response.json()
            latest_version = release_data.get('tag_name', '').lstrip('v')
            
            # Compare versions using semantic versioning
            result = {'update_available': False}
            if latest_version and latest_version != current_version:
                # Simple semantic version comparison
                def version_tuple(v):
                    """Convert version string to tuple for comparison"""
                    parts = v.split('.')
                    return tuple(int(x) if x.isdigit() else 0 for x in parts[:3])
                
                try:
                    current_tuple = version_tuple(current_version)
                    latest_tuple = version_tuple(latest_version)
                    # Only show update if latest is actually newer
                    if latest_tuple > current_tuple:
                        result = {
                            'update_available': True,
                            'current_version': current_version,
                            'latest_version': latest_version,
                            'release_url': release_data.get('html_url', '')
                        }
                except (ValueError, AttributeError):
                    # Fallback to string comparison if parsing fails
                    if latest_version != current_version:
                        result = {
                            'update_available': True,
                            'current_version': current_version,
                            'latest_version': latest_version,
                            'release_url': release_data.get('html_url', '')
                        }
            
            # Cache result for 3 hours (10800 seconds)
            cache.set(cache_key, result, ttl=10800)
            return jsonify(result)
                
        except requests.RequestException as e:
            logging.error(f"Error checking for updates: {e}")
            return jsonify({'error': 'Failed to check for updates'}), 500
        except Exception as e:
            logging.error(f"Unexpected error checking for updates: {e}")
            return jsonify({'error': 'Failed to check for updates'}), 500

    @app.route('/backup')
    @permission_required('view_admin')
    def backup():
        """Backup and restore page"""
        from flask import current_app
        
        # Ensure backups directory exists
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        os.makedirs(backups_dir, exist_ok=True)
        
        # List available backups
        backups = []
        if os.path.exists(backups_dir):
            for filename in os.listdir(backups_dir):
                if filename.endswith('.sql'):
                    filepath = os.path.join(backups_dir, filename)
                    file_stat = os.stat(filepath)
                    backups.append({
                        'filename': filename,
                        'size': file_stat.st_size,
                        'created': datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return render_with_user('backup.html', backups=backups)

    @app.route('/backup/create', methods=['POST'])
    @permission_required('view_admin')
    def create_backup():
        """Create a database backup"""
        from flask import current_app
        
        try:
            backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
            os.makedirs(backups_dir, exist_ok=True)
            
            # Generate backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'ipam_backup_{timestamp}.sql'
            filepath = os.path.join(backups_dir, filename)
            
            # Get database configuration
            db_host = current_app.config['MYSQL_HOST']
            db_user = current_app.config['MYSQL_USER']
            db_password = current_app.config['MYSQL_PASSWORD']
            db_name = current_app.config['MYSQL_DATABASE']
            
            # Create backup using mysqldump
            cmd = [
                'mysqldump',
                f'--host={db_host}',
                f'--user={db_user}',
                f'--password={db_password}',
                '--skip-ssl',
                '--single-transaction',
                '--routines',
                '--triggers',
                db_name
            ]
            
            with open(filepath, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                os.remove(filepath)
                return jsonify({'error': f'Backup failed: {result.stderr}'}), 500
            
            # Log the backup creation
            with get_db_connection(current_app) as conn:
                add_audit_log(session.get('user_id'), 'create_backup', f'Created backup: {filename}', conn=conn)
            
            return jsonify({'success': True, 'filename': filename, 'message': 'Backup created successfully'})
            
        except Exception as e:
            logging.error(f"Error creating backup: {e}")
            return jsonify({'error': f'Failed to create backup: {str(e)}'}), 500

    @app.route('/backup/download/<filename>')
    @permission_required('view_admin')
    def download_backup(filename):
        """Download a backup file"""
        from flask import current_app
        
        # Security: ensure filename is safe
        filename = secure_filename(filename)
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        filepath = os.path.join(backups_dir, filename)
        
        if not os.path.exists(filepath) or not filename.endswith('.sql'):
            abort(404)
        
        return send_file(filepath, as_attachment=True, download_name=filename)

    @app.route('/backup/restore', methods=['POST'])
    @permission_required('view_admin')
    def restore_backup():
        """Restore database from backup"""
        from flask import current_app
        
        try:
            backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
            os.makedirs(backups_dir, exist_ok=True)
            
            # Check if file was uploaded or if using existing file
            if 'backup_file' in request.files:
                # Handle file upload
                file = request.files['backup_file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                if not file.filename.endswith('.sql'):
                    return jsonify({'error': 'Invalid file type. Only .sql files are allowed'}), 400
                
                # Save uploaded file
                filename = secure_filename(file.filename)
                filepath = os.path.join(backups_dir, filename)
                file.save(filepath)
                
            elif 'backup_filename' in request.form:
                # Use existing backup file
                filename = secure_filename(request.form['backup_filename'])
                filepath = os.path.join(backups_dir, filename)
                
                if not os.path.exists(filepath):
                    return jsonify({'error': 'Backup file not found'}), 404
            else:
                return jsonify({'error': 'No backup file specified'}), 400
            
            # Get database configuration
            db_host = current_app.config['MYSQL_HOST']
            db_user = current_app.config['MYSQL_USER']
            db_password = current_app.config['MYSQL_PASSWORD']
            db_name = current_app.config['MYSQL_DATABASE']
            
            # Close any existing database connections before restore
            # This is important to avoid connection conflicts during restore
            try:
                # Try to close any open connections
                pass
            except:
                pass
            
            # Restore database using mysql command
            cmd = [
                'mysql',
                f'--host={db_host}',
                f'--user={db_user}',
                f'--password={db_password}',
                '--skip-ssl',
                db_name
            ]
            
            with open(filepath, 'r', encoding='utf-8') as f:
                result = subprocess.run(cmd, stdin=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                return jsonify({'error': f'Restore failed: {result.stderr}'}), 500
            
            # Log the restore
            with get_db_connection(current_app) as conn:
                add_audit_log(session.get('user_id'), 'restore_backup', f'Restored backup: {filename}', conn=conn)
            
            return jsonify({'success': True, 'message': 'Database restored successfully'})
            
        except Exception as e:
            logging.error(f"Error restoring backup: {e}")
            return jsonify({'error': f'Failed to restore backup: {str(e)}'}), 500

    @app.route('/backup/delete/<filename>', methods=['POST'])
    @permission_required('view_admin')
    def delete_backup(filename):
        """Delete a backup file"""
        from flask import current_app
        
        # Security: ensure filename is safe
        filename = secure_filename(filename)
        backups_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        filepath = os.path.join(backups_dir, filename)
        
        if not os.path.exists(filepath) or not filename.endswith('.sql'):
            return jsonify({'error': 'Backup file not found'}), 404
        
        try:
            os.remove(filepath)
            
            # Log the deletion
            with get_db_connection(current_app) as conn:
                add_audit_log(session.get('user_id'), 'delete_backup', f'Deleted backup: {filename}', conn=conn)
            
            return jsonify({'success': True, 'message': 'Backup deleted successfully'})
        except Exception as e:
            logging.error(f"Error deleting backup: {e}")
            return jsonify({'error': f'Failed to delete backup: {str(e)}'}), 500

    @app.route('/get_available_ips')
    @permission_required('view_device')
    def get_available_ips():
        subnet_id = request.args.get('subnet_id')
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ip.id, ip.ip FROM IPAddress ip
                LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                WHERE ip.subnet_id = %s AND dia.ip_id IS NULL AND (ip.hostname IS NULL OR ip.hostname != 'DHCP')
            ''', (subnet_id,))
            available_ips = cursor.fetchall()
            
            # Filter out DHCP pool IPs
            cursor.execute('SELECT start_ip, end_ip, excluded_ips FROM DHCPPool WHERE subnet_id = %s', (subnet_id,))
            dhcp_row = cursor.fetchone()
            if dhcp_row:
                start_ip, end_ip, excluded_ips = dhcp_row
                excluded_list = [x for x in (excluded_ips or '').replace(' ', '').split(',') if x]
                in_range = False
                filtered_ips = []
                for ip_obj in available_ips:
                    ip = ip_obj[1]
                    if ip == start_ip:
                        in_range = True
                    if ip in excluded_list or not (in_range and ip not in excluded_list):
                        filtered_ips.append(ip_obj)
                    if ip == end_ip:
                        in_range = False
                available_ips = filtered_ips
            
            available_ips = [{'id': row[0], 'ip': row[1]} for row in available_ips]
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
            # Invalidate cache
            invalidate_cache_for_device(device_id)
            cache.clear('subnet:')  # Invalidate all subnet caches since hostnames changed
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
        # Invalidate cache
        invalidate_cache_for_device(device_id)
        logging.info(f"User {user_name} updated description for device {device_id}.")
        return redirect(url_for('device', device_id=device_id))

    @app.route('/ip/<int:ip_id>/update_notes', methods=['POST'])
    @permission_required('edit_subnet')
    def update_ip_notes(ip_id):
        from flask import jsonify
        user_name = get_current_user_name()
        from flask import current_app
        
        # Get notes from request (can be JSON or form data)
        if request.is_json:
            notes = request.json.get('notes', '')
        else:
            notes = request.form.get('notes', '')
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            # Get subnet_id for cache invalidation and audit log
            cursor.execute('SELECT subnet_id, ip FROM IPAddress WHERE id = %s', (ip_id,))
            ip_result = cursor.fetchone()
            if not ip_result:
                return jsonify({'success': False, 'error': 'IP address not found'}), 404
            
            subnet_id, ip_address = ip_result
            
            # Update notes
            cursor.execute('UPDATE IPAddress SET notes = %s WHERE id = %s', (notes, ip_id))
            conn.commit()
            
            # Add audit log
            add_audit_log(
                session['user_id'],
                'update_ip_notes',
                f"Updated notes for IP {ip_address}",
                subnet_id,
                conn=conn
            )
        
        # Invalidate subnet cache
        invalidate_cache_for_subnet(subnet_id)
        
        logging.info(f"User {user_name} updated notes for IP {ip_address} (ID: {ip_id}).")
        return jsonify({'success': True, 'message': 'Notes updated successfully'})

    @app.route('/device/<int:device_id>/update_custom_fields', methods=['POST'])
    @permission_required('edit_device')
    def update_device_custom_fields(device_id):
        """Update custom field values for a device"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get all field definitions for devices
            cursor.execute('''
                SELECT id, field_key, field_type, required, validation_rules
                FROM CustomFieldDefinition
                WHERE entity_type = 'device'
            ''')
            field_defs = {f['field_key']: f for f in cursor.fetchall()}
            
            # Get current custom fields
            cursor.execute('SELECT custom_fields FROM Device WHERE id = %s', (device_id,))
            result = cursor.fetchone()
            current_values = {}
            if result and result.get('custom_fields'):
                try:
                    current_values = json.loads(result['custom_fields'])
                except (json.JSONDecodeError, TypeError):
                    current_values = {}
            
            # Process submitted values
            new_values = {}
            errors = []
            
            for field_key, field_def in field_defs.items():
                submitted_value = request.form.get(f'custom_field_{field_key}', '')
                
                # Parse validation rules
                validation_rules = field_def.get('validation_rules')
                if isinstance(validation_rules, str):
                    try:
                        validation_rules = json.loads(validation_rules)
                    except json.JSONDecodeError:
                        validation_rules = {}
                elif validation_rules is None:
                    validation_rules = {}
                field_def['validation_rules'] = validation_rules
                
                # Validate value
                if submitted_value == '' and not field_def.get('required'):
                    # Optional field left empty - remove from values
                    continue
                
                is_valid, error_msg = validate_custom_field_value(field_def, submitted_value)
                if not is_valid:
                    errors.append(error_msg)
                else:
                    parsed_value = parse_custom_field_value(field_def['field_type'], submitted_value)
                    if parsed_value is not None:
                        new_values[field_key] = parsed_value
            
            if errors:
                return jsonify({'error': 'Validation errors', 'errors': errors}), 400
            
            # Update custom_fields JSON
            custom_fields_json = json.dumps(new_values)
            cursor.execute('UPDATE Device SET custom_fields = %s WHERE id = %s', (custom_fields_json, device_id))
            add_audit_log(session['user_id'], 'update_device_custom_fields', 
                         f"Updated custom fields for device {device_id}", conn=conn)
            conn.commit()
            invalidate_cache_for_device(device_id)
        
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': True, 'message': 'Custom fields updated successfully'})
        return redirect(url_for('device', device_id=device_id))

    @app.route('/subnet/<int:subnet_id>/update_custom_fields', methods=['POST'])
    @permission_required('edit_subnet')
    def update_subnet_custom_fields(subnet_id):
        """Update custom field values for a subnet"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get all field definitions for subnets
            cursor.execute('''
                SELECT id, field_key, field_type, required, validation_rules
                FROM CustomFieldDefinition
                WHERE entity_type = 'subnet'
            ''')
            field_defs = {f['field_key']: f for f in cursor.fetchall()}
            
            # Get current custom fields
            cursor.execute('SELECT custom_fields FROM Subnet WHERE id = %s', (subnet_id,))
            result = cursor.fetchone()
            current_values = {}
            if result and result.get('custom_fields'):
                try:
                    current_values = json.loads(result['custom_fields'])
                except (json.JSONDecodeError, TypeError):
                    current_values = {}
            
            # Process submitted values
            new_values = {}
            errors = []
            
            # Handle both form data and JSON requests
            if request.is_json:
                submitted_data = request.json
            else:
                submitted_data = request.form
            
            for field_key, field_def in field_defs.items():
                if request.is_json:
                    submitted_value = submitted_data.get(f'custom_field_{field_key}', '')
                else:
                    submitted_value = submitted_data.get(f'custom_field_{field_key}', '')
                
                # Parse validation rules
                validation_rules = field_def.get('validation_rules')
                if isinstance(validation_rules, str):
                    try:
                        validation_rules = json.loads(validation_rules)
                    except json.JSONDecodeError:
                        validation_rules = {}
                elif validation_rules is None:
                    validation_rules = {}
                field_def['validation_rules'] = validation_rules
                
                # Validate value
                if submitted_value == '' and not field_def.get('required'):
                    # Optional field left empty - remove from values
                    continue
                
                is_valid, error_msg = validate_custom_field_value(field_def, submitted_value)
                if not is_valid:
                    errors.append(error_msg)
                else:
                    parsed_value = parse_custom_field_value(field_def['field_type'], submitted_value)
                    if parsed_value is not None:
                        new_values[field_key] = parsed_value
            
            if errors:
                return jsonify({'error': 'Validation errors', 'errors': errors}), 400
            
            # Update custom_fields JSON
            custom_fields_json = json.dumps(new_values)
            cursor.execute('UPDATE Subnet SET custom_fields = %s WHERE id = %s', (custom_fields_json, subnet_id))
            add_audit_log(session['user_id'], 'update_subnet_custom_fields', 
                         f"Updated custom fields for subnet {subnet_id}", conn=conn)
            conn.commit()
            invalidate_cache_for_subnet(subnet_id)
        
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': True, 'message': 'Custom fields updated successfully'})
        return redirect(url_for('subnet', subnet_id=subnet_id))

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
            cursor.execute('SELECT id, ip, hostname, notes FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
            ip_addresses = cursor.fetchall()
            cursor.execute('SELECT id, name, description FROM Device')
            devices = cursor.fetchall()
            device_name_map = {name.lower(): (id, description) for id, name, description in devices}
            ip_addresses_with_device = []
            for ip in ip_addresses:
                ip_id = ip[0]
                ip_address = ip[1]
                hostname = ip[2]
                ip_notes = ip[3] if len(ip) > 3 else None
                device_id = None
                device_description = None
                if hostname:
                    match = device_name_map.get(hostname.lower())
                    if match:
                        device_id, device_description = match
                ip_addresses_with_device.append((ip_id, ip_address, hostname, device_id, device_description, ip_notes))
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP Address', 'Hostname', 'Description'])
        for ip in ip_addresses_with_device:
            ip_addr = ip[1] or ''
            hostname = ip[2] or ''
            device_desc = ip[4] or ''
            ip_notes = ip[5] if len(ip) > 5 and ip[5] else ''
            # Combine device description and IP notes
            combined_desc = ''
            if device_desc:
                combined_desc = device_desc
            if ip_notes:
                if combined_desc:
                    combined_desc = combined_desc + '\n' + ip_notes
                else:
                    combined_desc = ip_notes
            writer.writerow([ip_addr, hostname, combined_desc])
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
                        # Invalidate subnet cache and related caches
                        cache.invalidate_subnet(subnet_id)
                        cache.clear('index')
                        cache.clear('admin')
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
                            # Invalidate subnet cache and related caches
                            cache.invalidate_subnet(subnet_id)
                            cache.clear('index')
                            cache.clear('admin')
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
                                # Invalidate all device caches since they contain device_types list
                                cache.clear('device:')
                                cache.clear('devices')
                                cache.clear('device_list')
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
                                cache.clear('device:')
                                cache.clear('devices')
                                cache.clear('device_list')
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
                            # Invalidate all device caches since they contain device_types list
                            cache.clear('device:')
                            cache.clear('devices')
                            cache.clear('device_list')
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

    @app.route('/devices/tag/<int:tag_id>')
    @permission_required('view_devices')
    def devices_by_tag(tag_id):
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, color FROM Tag WHERE id = %s', (tag_id,))
            row = cursor.fetchone()
            if not row:
                return f"Tag not found", 404
            tag_id_db, tag_name, tag_color = row
            cursor.execute('''
                SELECT DISTINCT Device.id, Device.name, Device.description, Subnet.site
                FROM Device
                JOIN DeviceTag ON Device.id = DeviceTag.device_id
                LEFT JOIN DeviceIPAddress ON Device.id = DeviceIPAddress.device_id
                LEFT JOIN IPAddress ON DeviceIPAddress.ip_id = IPAddress.id
                LEFT JOIN Subnet ON IPAddress.subnet_id = Subnet.id
                WHERE DeviceTag.tag_id = %s
            ''', (tag_id,))
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
        return render_with_user('devices_by_tag.html', tag_name=tag_name, tag_color=tag_color, site_devices=site_devices)

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

    @app.route('/search')
    @login_required
    def search():
        query = request.args.get('q', '').strip()
        results = {
            'subnets': [],
            'ips': [],
            'devices': [],
            'tags': [],
            'racks': [],
            'sites': []
        }
        
        if query:
            from flask import current_app
            conn = get_db_connection(current_app)
            try:
                cursor = conn.cursor()
                search_pattern = f'%{query}%'
                
                # Search Subnets (name, cidr, site)
                cursor.execute('''
                    SELECT id, name, cidr, site 
                    FROM Subnet 
                    WHERE name LIKE %s OR cidr LIKE %s OR site LIKE %s
                    ORDER BY site, name
                ''', (search_pattern, search_pattern, search_pattern))
                results['subnets'] = [{'id': row[0], 'name': row[1], 'cidr': row[2], 'site': row[3] or 'Unassigned'} 
                                     for row in cursor.fetchall()]
                
                # Search IP Addresses (ip, hostname, notes)
                cursor.execute('''
                    SELECT ip.id, ip.ip, ip.hostname, ip.subnet_id, s.name, s.cidr, s.site
                    FROM IPAddress ip
                    JOIN Subnet s ON ip.subnet_id = s.id
                    WHERE ip.ip LIKE %s OR ip.hostname LIKE %s OR ip.notes LIKE %s
                    ORDER BY ip.ip
                ''', (search_pattern, search_pattern, search_pattern))
                results['ips'] = [{'id': row[0], 'ip': row[1], 'hostname': row[2], 
                                  'subnet_id': row[3], 'subnet_name': row[4], 
                                  'subnet_cidr': row[5], 'site': row[6] or 'Unassigned'} 
                                 for row in cursor.fetchall()]
                
                # Search Devices (name, description)
                cursor.execute('''
                    SELECT id, name, description 
                    FROM Device 
                    WHERE name LIKE %s OR description LIKE %s
                    ORDER BY name
                ''', (search_pattern, search_pattern))
                results['devices'] = [{'id': row[0], 'name': row[1], 'description': row[2] or ''} 
                                     for row in cursor.fetchall()]
                
                # Search Tags (name, description)
                cursor.execute('''
                    SELECT id, name, description 
                    FROM Tag 
                    WHERE name LIKE %s OR description LIKE %s
                    ORDER BY name
                ''', (search_pattern, search_pattern))
                results['tags'] = [{'id': row[0], 'name': row[1], 'description': row[2] or ''} 
                                  for row in cursor.fetchall()]
                
                # Search Racks (name, site)
                cursor.execute('''
                    SELECT id, name, site, height_u 
                    FROM Rack 
                    WHERE name LIKE %s OR site LIKE %s
                    ORDER BY site, name
                ''', (search_pattern, search_pattern))
                results['racks'] = [{'id': row[0], 'name': row[1], 'site': row[2], 'height_u': row[3]} 
                                   for row in cursor.fetchall()]
                
                # Get unique sites from subnets and racks
                all_sites = set()
                for subnet in results['subnets']:
                    all_sites.add(subnet['site'])
                for rack in results['racks']:
                    all_sites.add(rack['site'])
                for ip in results['ips']:
                    all_sites.add(ip['site'])
                
                # Filter sites that match the query
                matching_sites = [site for site in all_sites if query.lower() in site.lower()]
                results['sites'] = sorted(matching_sites)
                
            finally:
                conn.close()
        
        return render_with_user('search.html', query=query, results=results)

    @app.route('/help')
    @permission_required('view_help')
    def help():
        return render_with_user('help.html')

    # ========== API ROUTES ==========
    
    @app.route('/api/v1/info', methods=['GET'])
    @rate_limit("100 per minute")
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
    @rate_limit("100 per minute")
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
                cursor.execute('''
                    SELECT t.id, t.name, t.color
                    FROM DeviceTag dt
                    JOIN Tag t ON dt.tag_id = t.id
                    WHERE dt.device_id = %s
                    ORDER BY t.name
                ''', (device['id'],))
                device['tags'] = cursor.fetchall()
                # Get custom fields
                cursor.execute('SELECT custom_fields FROM Device WHERE id = %s', (device['id'],))
                cf_result = cursor.fetchone()
                if cf_result and cf_result.get('custom_fields'):
                    try:
                        device['custom_fields'] = json.loads(cf_result['custom_fields'])
                    except (json.JSONDecodeError, TypeError):
                        device['custom_fields'] = {}
                else:
                    device['custom_fields'] = {}
        return jsonify({'devices': devices})
    
    @app.route('/api/v1/devices/<int:device_id>', methods=['GET'])
    @rate_limit("100 per minute")
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
            cursor.execute('''
                SELECT t.id, t.name, t.color
                FROM DeviceTag dt
                JOIN Tag t ON dt.tag_id = t.id
                WHERE dt.device_id = %s
                ORDER BY t.name
            ''', (device_id,))
            device['tags'] = cursor.fetchall()
            # Get custom fields
            cursor.execute('SELECT custom_fields FROM Device WHERE id = %s', (device_id,))
            cf_result = cursor.fetchone()
            if cf_result and cf_result.get('custom_fields'):
                try:
                    device['custom_fields'] = json.loads(cf_result['custom_fields'])
                except (json.JSONDecodeError, TypeError):
                    device['custom_fields'] = {}
            else:
                device['custom_fields'] = {}
        return jsonify(device)
    
    @app.route('/api/v1/devices', methods=['POST'])
    @rate_limit("50 per minute")
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
    @rate_limit("50 per minute")
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
    @rate_limit("50 per minute")
    @api_permission_required('delete_device')
    def api_delete_device(device_id):
        """Delete a device"""
        from flask import current_app
        subnet_ids_to_invalidate = set()
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            device_name = device[0]
            # Get subnet IDs for all IPs assigned to this device before deleting
            cursor.execute('''
                SELECT DISTINCT ip.subnet_id 
                FROM DeviceIPAddress dia
                JOIN IPAddress ip ON dia.ip_id = ip.id
                WHERE dia.device_id = %s
            ''', (device_id,))
            subnet_ids_to_invalidate = {row[0] for row in cursor.fetchall()}
            
            cursor.execute('SELECT ip_id FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
            ip_ids = [row[0] for row in cursor.fetchall()]
            if ip_ids:
                cursor.executemany('UPDATE IPAddress SET hostname = NULL WHERE id = %s', [(ip_id,) for ip_id in ip_ids])
            cursor.execute('DELETE FROM DeviceIPAddress WHERE device_id = %s', (device_id,))
            cursor.execute('DELETE FROM Device WHERE id = %s', (device_id,))
            add_audit_log(request.api_user['id'], 'delete_device', f"Deleted device {device_name}", conn=conn)
            conn.commit()
        invalidate_cache_for_device(device_id)
        # Invalidate subnet caches for all subnets that had IPs assigned to this device
        for subnet_id in subnet_ids_to_invalidate:
            cache.invalidate_subnet(subnet_id)
        return jsonify({'message': 'Device deleted successfully', 'device': {'id': device_id, 'name': device_name}})
    
    @app.route('/api/v1/devices/<int:device_id>/ips', methods=['POST'])
    @rate_limit("50 per minute")
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
    @rate_limit("50 per minute")
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
    @rate_limit("100 per minute")
    @api_permission_required('view_subnet')
    def api_subnets():
        """Get all subnets"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, cidr, site, vlan_id, vlan_description, vlan_notes FROM Subnet ORDER BY site, name')
            subnets = cursor.fetchall()
            for subnet in subnets:
                cursor.execute('SELECT COUNT(*) as total, COUNT(CASE WHEN hostname IS NOT NULL THEN 1 END) as used FROM IPAddress WHERE subnet_id = %s', (subnet['id'],))
                stats = cursor.fetchone()
                subnet['total_ips'] = stats['total']
                subnet['used_ips'] = stats['used']
                subnet['available_ips'] = stats['total'] - stats['used']
                # Get custom fields
                cursor.execute('SELECT custom_fields FROM Subnet WHERE id = %s', (subnet['id'],))
                cf_result = cursor.fetchone()
                if cf_result and cf_result.get('custom_fields'):
                    try:
                        subnet['custom_fields'] = json.loads(cf_result['custom_fields'])
                    except (json.JSONDecodeError, TypeError):
                        subnet['custom_fields'] = {}
                else:
                    subnet['custom_fields'] = {}
        return jsonify({'subnets': subnets})
    
    @app.route('/api/v1/subnets/<int:subnet_id>', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_subnet')
    def api_subnet(subnet_id):
        """Get a specific subnet with IP addresses"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, cidr, site, vlan_id, vlan_description, vlan_notes FROM Subnet WHERE id = %s', (subnet_id,))
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
            # Get custom fields
            cursor.execute('SELECT custom_fields FROM Subnet WHERE id = %s', (subnet_id,))
            cf_result = cursor.fetchone()
            if cf_result and cf_result.get('custom_fields'):
                try:
                    subnet['custom_fields'] = json.loads(cf_result['custom_fields'])
                except (json.JSONDecodeError, TypeError):
                    subnet['custom_fields'] = {}
            else:
                subnet['custom_fields'] = {}
        return jsonify(subnet)
    
    @app.route('/api/v1/subnets/<int:subnet_id>/next_free_ip', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_subnet')
    def api_subnet_next_free_ip(subnet_id):
        """Get the next free IP address in a subnet"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            # First check if subnet exists
            cursor.execute('SELECT id FROM Subnet WHERE id = %s', (subnet_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'Subnet not found'}), 404
            
            # Find the first IP in the subnet that is not assigned to any device
            cursor.execute('''
                SELECT ip.id, ip.ip
                FROM IPAddress ip
                LEFT JOIN DeviceIPAddress dia ON ip.id = dia.ip_id
                WHERE ip.subnet_id = %s AND dia.ip_id IS NULL
                ORDER BY INET_ATON(ip.ip)
                LIMIT 1
            ''', (subnet_id,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'No free IP addresses available in this subnet'}), 404
            
            return jsonify({'id': result['id'], 'ip': result['ip']})
    
    @app.route('/api/v1/subnets', methods=['POST'])
    @rate_limit("50 per minute")
    @api_permission_required('add_subnet')
    def api_add_subnet():
        """Create a new subnet"""
        data = request.get_json()
        if not data or 'name' not in data or 'cidr' not in data:
            return jsonify({'error': 'Name and CIDR are required'}), 400
        
        name = data['name']
        cidr = data['cidr']
        site = data.get('site', '')
        vlan_id_str = str(data.get('vlan_id', '')).strip() if data.get('vlan_id') else ''
        vlan_description = data.get('vlan_description', '').strip() if data.get('vlan_description') else ''
        vlan_notes = data.get('vlan_notes', '').strip() if data.get('vlan_notes') else ''
        
        # Validate VLAN ID if provided
        if vlan_id_str:
            is_valid, error_msg, vlan_id = validate_vlan_id(vlan_id_str)
            if not is_valid:
                return jsonify({'error': error_msg}), 400
        else:
            vlan_id = None
        
        try:
            network = ip_network(cidr, strict=False)
            if network.prefixlen < 24:
                return jsonify({'error': 'Subnet must be /24 or smaller'}), 400
        except Exception:
            return jsonify({'error': 'Invalid CIDR format'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Subnet (name, cidr, site, vlan_id, vlan_description, vlan_notes) VALUES (%s, %s, %s, %s, %s, %s)', 
                          (name, cidr, site, vlan_id, vlan_description if vlan_description else None, vlan_notes if vlan_notes else None))
            subnet_id = cursor.lastrowid
            ip_rows = [(str(ip), subnet_id) for ip in network.hosts()]
            cursor.executemany('INSERT INTO IPAddress (ip, subnet_id) VALUES (%s, %s)', ip_rows)
            vlan_info = f" (VLAN {vlan_id})" if vlan_id else ""
            add_audit_log(request.api_user['id'], 'add_subnet', f"Added subnet {name} ({cidr}){vlan_info}", subnet_id, conn=conn)
            conn.commit()
        return jsonify({
            'id': subnet_id, 
            'name': name, 
            'cidr': cidr, 
            'site': site,
            'vlan_id': vlan_id,
            'vlan_description': vlan_description if vlan_description else None,
            'vlan_notes': vlan_notes if vlan_notes else None
        }), 201
    
    @app.route('/api/v1/subnets/<int:subnet_id>', methods=['PUT'])
    @rate_limit("50 per minute")
    @api_permission_required('edit_subnet')
    def api_update_subnet(subnet_id):
        """Update a subnet"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, cidr, site, vlan_id, vlan_description, vlan_notes FROM Subnet WHERE id = %s', (subnet_id,))
            old_subnet = cursor.fetchone()
            if not old_subnet:
                return jsonify({'error': 'Subnet not found'}), 404
            old_name, old_cidr, old_site, old_vlan_id, old_vlan_desc, old_vlan_notes = old_subnet
            
            new_name = data.get('name', old_name)
            new_cidr = data.get('cidr', old_cidr)
            new_site = data.get('site', old_site)
            
            # Handle VLAN fields
            vlan_id_str = str(data.get('vlan_id', '')).strip() if data.get('vlan_id') is not None else ''
            new_vlan_description = data.get('vlan_description', '').strip() if data.get('vlan_description') else ''
            new_vlan_notes = data.get('vlan_notes', '').strip() if data.get('vlan_notes') else ''
            
            # Validate VLAN ID if provided
            if vlan_id_str:
                is_valid, error_msg, new_vlan_id = validate_vlan_id(vlan_id_str)
                if not is_valid:
                    return jsonify({'error': error_msg}), 400
            elif 'vlan_id' in data and data['vlan_id'] is None:
                new_vlan_id = None
            else:
                new_vlan_id = old_vlan_id
            
            # Use old values if not provided in request
            if 'vlan_description' not in data:
                new_vlan_description = old_vlan_desc if old_vlan_desc else ''
            if 'vlan_notes' not in data:
                new_vlan_notes = old_vlan_notes if old_vlan_notes else ''
            
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
            if new_vlan_id != old_vlan_id:
                updates.append('vlan_id = %s')
                values.append(new_vlan_id)
            if new_vlan_description != (old_vlan_desc or ''):
                updates.append('vlan_description = %s')
                values.append(new_vlan_description if new_vlan_description else None)
            if new_vlan_notes != (old_vlan_notes or ''):
                updates.append('vlan_notes = %s')
                values.append(new_vlan_notes if new_vlan_notes else None)
            
            if not updates:
                return jsonify({'error': 'No changes to apply'}), 400
            
            values.append(subnet_id)
            cursor.execute(f'UPDATE Subnet SET {", ".join(updates)} WHERE id = %s', values)
            vlan_info = f" (VLAN {new_vlan_id})" if new_vlan_id else ""
            add_audit_log(
                request.api_user['id'],
                'edit_subnet',
                f"Edited subnet from {old_name} ({old_cidr}) to {new_name} ({new_cidr}) at site {new_site or 'Unassigned'}{vlan_info}",
                subnet_id,
                conn=conn
            )
            conn.commit()
        return jsonify({
            'message': 'Subnet updated successfully', 
            'subnet': {
                'id': subnet_id, 
                'name': new_name, 
                'cidr': new_cidr, 
                'site': new_site,
                'vlan_id': new_vlan_id,
                'vlan_description': new_vlan_description if new_vlan_description else None,
                'vlan_notes': new_vlan_notes if new_vlan_notes else None
            }
        })
    
    @app.route('/api/v1/subnets/<int:subnet_id>', methods=['DELETE'])
    @rate_limit("50 per minute")
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
    @rate_limit("100 per minute")
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
    @rate_limit("100 per minute")
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
    @rate_limit("50 per minute")
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
    @rate_limit("50 per minute")
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
    @rate_limit("50 per minute")
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
    @rate_limit("50 per minute")
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
    
    # Custom Fields API
    @app.route('/api/v1/custom_fields/<entity_type>', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_custom_fields')
    def api_custom_fields_by_type(entity_type):
        """Get custom field definitions for a specific entity type"""
        if entity_type not in ['device', 'subnet']:
            return jsonify({'error': 'Invalid entity type. Must be "device" or "subnet"'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, entity_type, name, field_key, field_type, required, 
                       default_value, help_text, display_order, validation_rules, searchable
                FROM CustomFieldDefinition
                WHERE entity_type = %s
                ORDER BY display_order, name
            ''', (entity_type,))
            fields = cursor.fetchall()
            # Parse validation_rules JSON strings
            for field in fields:
                if field.get('validation_rules'):
                    try:
                        field['validation_rules'] = json.loads(field['validation_rules'])
                    except (json.JSONDecodeError, TypeError):
                        field['validation_rules'] = {}
        return jsonify({'fields': fields})
    
    @app.route('/api/v1/custom_fields', methods=['POST'])
    @rate_limit("50 per minute")
    @api_permission_required('manage_custom_fields')
    def api_add_custom_field():
        """Create a new custom field definition"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        required_fields = ['entity_type', 'name', 'field_key', 'field_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        entity_type = data['entity_type']
        if entity_type not in ['device', 'subnet']:
            return jsonify({'error': 'Invalid entity_type. Must be "device" or "subnet"'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                validation_rules = data.get('validation_rules', {})
                validation_rules_json = json.dumps(validation_rules) if validation_rules else None
                
                cursor.execute('''
                    INSERT INTO CustomFieldDefinition 
                    (entity_type, name, field_key, field_type, required, default_value, 
                     help_text, display_order, validation_rules, searchable)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (entity_type, data['name'], data['field_key'], data['field_type'],
                      data.get('required', False), data.get('default_value'),
                      data.get('help_text'), data.get('display_order', 0),
                      validation_rules_json, data.get('searchable', False)))
                field_id = cursor.lastrowid
                add_audit_log(request.api_user['id'], 'add_custom_field',
                            f"Added custom field '{data['name']}' for {entity_type}", conn=conn)
                conn.commit()
                return jsonify({'id': field_id, 'message': 'Custom field created successfully'}), 201
            except mysql.connector.IntegrityError:
                return jsonify({'error': f'Field key "{data["field_key"]}" already exists'}), 400
    
    @app.route('/api/v1/custom_fields/<int:field_id>', methods=['PUT'])
    @rate_limit("50 per minute")
    @api_permission_required('manage_custom_fields')
    def api_update_custom_field(field_id):
        """Update a custom field definition"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id FROM CustomFieldDefinition WHERE id = %s', (field_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'Custom field not found'}), 404
            
            updates = []
            values = []
            
            if 'name' in data:
                updates.append('name = %s')
                values.append(data['name'])
            if 'field_type' in data:
                updates.append('field_type = %s')
                values.append(data['field_type'])
            if 'required' in data:
                updates.append('required = %s')
                values.append(data['required'])
            if 'default_value' in data:
                updates.append('default_value = %s')
                values.append(data['default_value'])
            if 'help_text' in data:
                updates.append('help_text = %s')
                values.append(data['help_text'])
            if 'display_order' in data:
                updates.append('display_order = %s')
                values.append(data['display_order'])
            if 'validation_rules' in data:
                validation_rules_json = json.dumps(data['validation_rules']) if data['validation_rules'] else None
                updates.append('validation_rules = %s')
                values.append(validation_rules_json)
            if 'searchable' in data:
                updates.append('searchable = %s')
                values.append(data['searchable'])
            
            if not updates:
                return jsonify({'error': 'No changes to apply'}), 400
            
            values.append(field_id)
            cursor.execute(f'UPDATE CustomFieldDefinition SET {", ".join(updates)} WHERE id = %s', values)
            add_audit_log(request.api_user['id'], 'edit_custom_field',
                         f"Updated custom field {field_id}", conn=conn)
            conn.commit()
        return jsonify({'message': 'Custom field updated successfully'})
    
    @app.route('/api/v1/custom_fields/<int:field_id>', methods=['DELETE'])
    @rate_limit("50 per minute")
    @api_permission_required('manage_custom_fields')
    def api_delete_custom_field(field_id):
        """Delete a custom field definition"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT name FROM CustomFieldDefinition WHERE id = %s', (field_id,))
            field = cursor.fetchone()
            if not field:
                return jsonify({'error': 'Custom field not found'}), 404
            
            cursor.execute('DELETE FROM CustomFieldDefinition WHERE id = %s', (field_id,))
            add_audit_log(request.api_user['id'], 'delete_custom_field',
                         f"Deleted custom field '{field['name']}'", conn=conn)
            conn.commit()
        return jsonify({'message': 'Custom field deleted successfully'})
    
    # Device Types API
    @app.route('/api/v1/device-types', methods=['GET'])
    @rate_limit("100 per minute")
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
    @rate_limit("100 per minute")
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
    @rate_limit("50 per minute")
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
                # Invalidate subnet cache and related caches
                cache.invalidate_subnet(subnet_id)
                cache.clear('index')
                cache.clear('admin')
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
        # Invalidate subnet cache and related caches
        cache.invalidate_subnet(subnet_id)
        cache.clear('index')
        cache.clear('admin')
        return jsonify({'message': 'DHCP pools configured successfully', 'pool': {'start_ip': start_ip, 'end_ip': end_ip, 'excluded_ips': excluded_list}})
    
    # Tags API
    @app.route('/api/v1/tags', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_tags')
    def api_tags():
        """Get all tags"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, color, description, created_at FROM Tag ORDER BY name')
            tags = cursor.fetchall()
            for tag in tags:
                cursor.execute('SELECT COUNT(*) as device_count FROM DeviceTag WHERE tag_id = %s', (tag['id'],))
                tag['device_count'] = cursor.fetchone()['device_count']
        return jsonify({'tags': tags})
    
    @app.route('/api/v1/tags', methods=['POST'])
    @rate_limit("50 per minute")
    @api_permission_required('add_tag')
    def api_add_tag():
        """Create a new tag"""
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Tag name is required'}), 400
        
        name = data['name'].strip()
        if not name:
            return jsonify({'error': 'Tag name cannot be empty'}), 400
        
        color = data.get('color', '#6B7280')
        description = data.get('description', '')
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO Tag (name, color, description) VALUES (%s, %s, %s)', (name, color, description))
                tag_id = cursor.lastrowid
                add_audit_log(request.api_user['id'], 'add_tag', f"Added tag '{name}'", conn=conn)
                conn.commit()
                # Invalidate device caches since they contain tags
                cache.clear('device:')
                cache.clear('devices')
                return jsonify({'id': tag_id, 'name': name, 'color': color, 'description': description}), 201
            except mysql.connector.IntegrityError:
                return jsonify({'error': 'Tag name already exists'}), 400
    
    @app.route('/api/v1/tags/<int:tag_id>', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_tags')
    def api_tag(tag_id):
        """Get a specific tag"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name, color, description, created_at FROM Tag WHERE id = %s', (tag_id,))
            tag = cursor.fetchone()
            if not tag:
                return jsonify({'error': 'Tag not found'}), 404
            cursor.execute('''
                SELECT d.id, d.name, d.description, dt.name as device_type
                FROM DeviceTag dtag
                JOIN Device d ON dtag.device_id = d.id
                LEFT JOIN DeviceType dt ON d.device_type_id = dt.id
                WHERE dtag.tag_id = %s
                ORDER BY d.name
            ''', (tag_id,))
            tag['devices'] = cursor.fetchall()
        return jsonify(tag)
    
    @app.route('/api/v1/tags/<int:tag_id>', methods=['PUT'])
    @rate_limit("50 per minute")
    @api_permission_required('edit_tag')
    def api_update_tag(tag_id):
        """Update a tag"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, color, description FROM Tag WHERE id = %s', (tag_id,))
            current = cursor.fetchone()
            if not current:
                return jsonify({'error': 'Tag not found'}), 404
            
            current_name, current_color, current_description = current
            updates = []
            values = []
            
            if 'name' in data and data['name'].strip() != current_name:
                new_name = data['name'].strip()
                if not new_name:
                    return jsonify({'error': 'Tag name cannot be empty'}), 400
                updates.append('name = %s')
                values.append(new_name)
            
            if 'color' in data and data['color'] != current_color:
                updates.append('color = %s')
                values.append(data['color'])
            
            if 'description' in data and data['description'] != current_description:
                updates.append('description = %s')
                values.append(data['description'])
            
            if not updates:
                return jsonify({'error': 'No changes to apply'}), 400
            
            values.append(tag_id)
            try:
                cursor.execute(f'UPDATE Tag SET {", ".join(updates)} WHERE id = %s', values)
                add_audit_log(request.api_user['id'], 'edit_tag', f"Updated tag '{current_name}'", conn=conn)
                conn.commit()
                # Invalidate device caches since they contain tags
                cache.clear('device:')
                cache.clear('devices')
                return jsonify({'message': 'Tag updated successfully'})
            except mysql.connector.IntegrityError:
                return jsonify({'error': 'Tag name already exists'}), 400
    
    @app.route('/api/v1/tags/<int:tag_id>', methods=['DELETE'])
    @rate_limit("50 per minute")
    @api_permission_required('delete_tag')
    def api_delete_tag(tag_id):
        """Delete a tag"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
            tag = cursor.fetchone()
            if not tag:
                return jsonify({'error': 'Tag not found'}), 404
            tag_name = tag[0]
            cursor.execute('DELETE FROM Tag WHERE id = %s', (tag_id,))
            add_audit_log(request.api_user['id'], 'delete_tag', f"Deleted tag '{tag_name}'", conn=conn)
            conn.commit()
        # Invalidate device caches since they contain tags
        cache.clear('device:')
        cache.clear('devices')
        return jsonify({'message': 'Tag deleted successfully'})
    
    @app.route('/api/v1/devices/<int:device_id>/tags', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_device')
    def api_device_tags(device_id):
        """Get tags for a specific device"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, name FROM Device WHERE id = %s', (device_id,))
            if not cursor.fetchone():
                return jsonify({'error': 'Device not found'}), 404
            cursor.execute('''
                SELECT t.id, t.name, t.color, t.description, dt.created_at
                FROM DeviceTag dt
                JOIN Tag t ON dt.tag_id = t.id
                WHERE dt.device_id = %s
                ORDER BY t.name
            ''', (device_id,))
            tags = cursor.fetchall()
        return jsonify({'tags': tags})
    
    @app.route('/api/v1/devices/<int:device_id>/tags', methods=['POST'])
    @rate_limit("50 per minute")
    @api_permission_required('assign_device_tag')
    def api_assign_device_tag(device_id):
        """Assign a tag to a device"""
        data = request.get_json()
        if not data or 'tag_id' not in data:
            return jsonify({'error': 'tag_id is required'}), 400
        
        tag_id = data['tag_id']
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            device_name = device[0]
            
            cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
            tag = cursor.fetchone()
            if not tag:
                return jsonify({'error': 'Tag not found'}), 404
            tag_name = tag[0]
            
            cursor.execute('SELECT id FROM DeviceTag WHERE device_id = %s AND tag_id = %s', (device_id, tag_id))
            if cursor.fetchone():
                return jsonify({'error': 'Tag already assigned to device'}), 400
            
            cursor.execute('INSERT INTO DeviceTag (device_id, tag_id) VALUES (%s, %s)', (device_id, tag_id))
            add_audit_log(request.api_user['id'], 'assign_device_tag', f"Assigned tag '{tag_name}' to device '{device_name}'", conn=conn)
            conn.commit()
        invalidate_cache_for_device(device_id)
        cache.clear('devices')
        return jsonify({'message': 'Tag assigned successfully'})
    
    @app.route('/api/v1/devices/<int:device_id>/tags/<int:tag_id>', methods=['DELETE'])
    @rate_limit("50 per minute")
    @api_permission_required('remove_device_tag')
    def api_remove_device_tag(device_id, tag_id):
        """Remove a tag from a device"""
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            device_name = device[0]
            
            cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
            tag = cursor.fetchone()
            if not tag:
                return jsonify({'error': 'Tag not found'}), 404
            tag_name = tag[0]
            
            cursor.execute('SELECT id FROM DeviceTag WHERE device_id = %s AND tag_id = %s', (device_id, tag_id))
            if not cursor.fetchone():
                return jsonify({'error': 'Tag not assigned to device'}), 404
            
            cursor.execute('DELETE FROM DeviceTag WHERE device_id = %s AND tag_id = %s', (device_id, tag_id))
            add_audit_log(request.api_user['id'], 'remove_device_tag', f"Removed tag '{tag_name}' from device '{device_name}'", conn=conn)
            conn.commit()
        invalidate_cache_for_device(device_id)
        cache.clear('devices')
        return jsonify({'message': 'Tag removed successfully'})
    
    @app.route('/api/v1/devices/by-tag/<tag_identifier>', methods=['GET'])
    @rate_limit("100 per minute")
    @api_permission_required('view_devices')
    def api_devices_by_tag(tag_identifier):
        """Get devices by tag name or ID. Use ?format=simple for simplified response."""
        from flask import current_app
        simple_format = request.args.get('format') == 'simple'
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor(dictionary=True)
            
            # Check if tag_identifier is numeric (tag ID) or string (tag name)
            try:
                tag_id = int(tag_identifier)
                # Query by tag ID
                if simple_format:
                    cursor.execute('''
                        SELECT d.id, d.name
                        FROM DeviceTag dtag
                        JOIN Device d ON dtag.device_id = d.id
                        WHERE dtag.tag_id = %s
                        ORDER BY d.name
                    ''', (tag_id,))
                else:
                    cursor.execute('''
                        SELECT d.id, d.name, d.description, dt.name as device_type, dt.icon_class
                        FROM DeviceTag dtag
                        JOIN Device d ON dtag.device_id = d.id
                        LEFT JOIN DeviceType dt ON d.device_type_id = dt.id
                        WHERE dtag.tag_id = %s
                        ORDER BY d.name
                    ''', (tag_id,))
                # Get tag name for response
                cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
                tag_result = cursor.fetchone()
                if not tag_result:
                    return jsonify({'error': 'Tag not found'}), 404
                tag_name = tag_result['name']
            except ValueError:
                # Query by tag name
                tag_name = tag_identifier
                if simple_format:
                    cursor.execute('''
                        SELECT d.id, d.name
                        FROM DeviceTag dtag
                        JOIN Device d ON dtag.device_id = d.id
                        JOIN Tag t ON dtag.tag_id = t.id
                        WHERE t.name = %s
                        ORDER BY d.name
                    ''', (tag_name,))
                else:
                    cursor.execute('''
                        SELECT d.id, d.name, d.description, dt.name as device_type, dt.icon_class
                        FROM DeviceTag dtag
                        JOIN Device d ON dtag.device_id = d.id
                        JOIN Tag t ON dtag.tag_id = t.id
                        LEFT JOIN DeviceType dt ON d.device_type_id = dt.id
                        WHERE t.name = %s
                        ORDER BY d.name
                    ''', (tag_name,))
            
            devices = cursor.fetchall()
            
            if not devices:
                return jsonify({'devices': [], 'tag_name': tag_name, 'count': 0})
            
            if simple_format:
                # Simple format: just name and first IP as clean array
                simple_devices = []
                for device in devices:
                    cursor.execute('''
                        SELECT ip.ip
                        FROM DeviceIPAddress dia
                        JOIN IPAddress ip ON dia.ip_id = ip.id
                        WHERE dia.device_id = %s
                        ORDER BY ip.ip
                        LIMIT 1
                    ''', (device['id'],))
                    ip_result = cursor.fetchone()
                    first_ip = ip_result['ip'] if ip_result else None
                    
                    # Only include devices that have an IP address
                    if first_ip:
                        simple_devices.append({
                            'device': device['name'],
                            'ip': first_ip
                        })
                    
                return jsonify(simple_devices)
            else:
                # Full format: complete device information
                for device in devices:
                    cursor.execute('''
                        SELECT ip.id, ip.ip, ip.hostname, s.id as subnet_id, s.name as subnet_name, s.cidr, s.site
                        FROM DeviceIPAddress dia
                        JOIN IPAddress ip ON dia.ip_id = ip.id
                        JOIN Subnet s ON ip.subnet_id = s.id
                        WHERE dia.device_id = %s
                    ''', (device['id'],))
                    device['ip_addresses'] = cursor.fetchall()
                    
                    cursor.execute('''
                        SELECT t.id, t.name, t.color
                        FROM DeviceTag dtag
                        JOIN Tag t ON dtag.tag_id = t.id
                        WHERE dtag.device_id = %s
                        ORDER BY t.name
                    ''', (device['id'],))
                    device['tags'] = cursor.fetchall()
                    
                return jsonify({'devices': devices, 'tag_name': tag_name, 'count': len(devices)})
    
    # Audit Log API
    @app.route('/api/v1/audit', methods=['GET'])
    @rate_limit("100 per minute")
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
    @rate_limit("100 per minute")
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
    @rate_limit("100 per minute")
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

    # Bulk Operations
    @app.route('/bulk', methods=['GET'])
    @permission_required('view_devices')
    def bulk_operations():
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name FROM Device ORDER BY name')
            devices = cursor.fetchall()
            cursor.execute('SELECT id, name, cidr, site FROM Subnet ORDER BY site, name')
            subnets = cursor.fetchall()
            cursor.execute('SELECT id, name FROM Tag ORDER BY name')
            tags = cursor.fetchall()
            cursor.execute('SELECT id, name FROM DeviceType ORDER BY name')
            device_types = cursor.fetchall()
        return render_with_user('bulk_operations.html', 
                               devices=devices, 
                               subnets=subnets, 
                               tags=tags,
                               device_types=device_types,
                               can_add_device_ip=has_permission('add_device_ip'),
                               can_add_device=has_permission('add_device'),
                               can_assign_device_tag=has_permission('assign_device_tag'),
                               can_export_subnet_csv=has_permission('export_subnet_csv'))
    
    @app.route('/bulk/assign_ips', methods=['POST'])
    @permission_required('add_device_ip')
    def bulk_assign_ips():
        device_id = request.form['device_id']
        ip_ids = request.form.getlist('ip_ids[]')
        user_name = get_current_user_name()
        results = {'success': [], 'failed': []}
        
        from flask import current_app
        subnet_ids_to_invalidate = set()
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
            device = cursor.fetchone()
            if not device:
                return jsonify({'success': [], 'failed': [{'ip_id': 'all', 'reason': 'Device not found'}]})
            
            device_name = device[0]
            
            for ip_id in ip_ids:
                try:
                    cursor.execute('SELECT ip, subnet_id FROM IPAddress WHERE id = %s', (ip_id,))
                    ip_row = cursor.fetchone()
                    if not ip_row:
                        results['failed'].append({'ip_id': ip_id, 'reason': 'IP not found'})
                        continue
                    
                    ip, subnet_id = ip_row[0], ip_row[1]
                    subnet_ids_to_invalidate.add(subnet_id)
                    
                    # Check if IP is already assigned
                    cursor.execute('SELECT id FROM DeviceIPAddress WHERE ip_id = %s', (ip_id,))
                    if cursor.fetchone():
                        results['failed'].append({'ip_id': ip_id, 'ip': ip, 'reason': 'IP already assigned'})
                        continue
                    
                    # Check if IP is in DHCP pool (using exact same logic as device_add_ip)
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
                                results['failed'].append({'ip_id': ip_id, 'ip': ip, 'reason': 'IP is reserved for DHCP'})
                                continue
                    
                    cursor.execute('INSERT INTO DeviceIPAddress (device_id, ip_id) VALUES (%s, %s)', (device_id, ip_id))
                    cursor.execute('UPDATE IPAddress SET hostname = %s WHERE id = %s', (device_name, ip_id))
                    cursor.execute('SELECT name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
                    subnet = cursor.fetchone()
                    subnet_name, subnet_cidr = subnet[0], subnet[1]
                    add_audit_log(session['user_id'], 'add_device_ip', 
                                f"Assigned IP {ip} ({subnet_name} {subnet_cidr}) to device {device_name}", 
                                subnet_id, conn=conn)
                    results['success'].append({'ip_id': ip_id, 'ip': ip})
                except Exception as e:
                    results['failed'].append({'ip_id': ip_id, 'reason': str(e)})
            
            conn.commit()
        
        # Invalidate device and subnet caches
        invalidate_cache_for_device(device_id)
        for subnet_id in subnet_ids_to_invalidate:
            cache.invalidate_subnet(subnet_id)
        return jsonify(results)
    
    @app.route('/bulk/create_devices', methods=['POST'])
    @permission_required('add_device')
    def bulk_create_devices():
        device_names = request.form.get('device_names', '').strip().split('\n')
        device_type_id = int(request.form.get('device_type', 1))
        user_name = get_current_user_name()
        results = {'success': [], 'failed': []}
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            for name in device_names:
                name = name.strip()
                if not name:
                    continue
                try:
                    cursor.execute('INSERT INTO Device (name, device_type_id) VALUES (%s, %s)', (name, device_type_id))
                    device_id = cursor.lastrowid
                    add_audit_log(session['user_id'], 'add_device', f"Added device {name}", conn=conn)
                    results['success'].append({'name': name, 'id': device_id})
                except Exception as e:
                    results['failed'].append({'name': name, 'reason': str(e)})
            conn.commit()
        
        # Invalidate devices cache
        cache.clear('devices')
        cache.clear('device_list')
        logging.info(f"User {user_name} bulk created {len(results['success'])} devices.")
        return jsonify(results)
    
    @app.route('/bulk/assign_tags', methods=['POST'])
    @permission_required('assign_device_tag')
    def bulk_assign_tags():
        device_ids = request.form.getlist('device_ids[]')
        tag_ids = request.form.getlist('tag_ids[]')
        user_name = get_current_user_name()
        results = {'success': [], 'failed': []}
        
        from flask import current_app
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            for device_id in device_ids:
                cursor.execute('SELECT name FROM Device WHERE id = %s', (device_id,))
                device = cursor.fetchone()
                if not device:
                    results['failed'].append({'device_id': device_id, 'reason': 'Device not found'})
                    continue
                device_name = device[0]
                
                for tag_id in tag_ids:
                    try:
                        cursor.execute('SELECT name FROM Tag WHERE id = %s', (tag_id,))
                        tag = cursor.fetchone()
                        if not tag:
                            continue
                        tag_name = tag[0]
                        
                        cursor.execute('SELECT id FROM DeviceTag WHERE device_id = %s AND tag_id = %s', (device_id, tag_id))
                        if cursor.fetchone():
                            continue  # Already assigned
                        
                        cursor.execute('INSERT INTO DeviceTag (device_id, tag_id) VALUES (%s, %s)', (device_id, tag_id))
                        add_audit_log(session['user_id'], 'assign_device_tag', 
                                    f"Assigned tag '{tag_name}' to device '{device_name}'", conn=conn)
                        results['success'].append({'device_id': device_id, 'device_name': device_name, 'tag_id': tag_id, 'tag_name': tag_name})
                    except Exception as e:
                        results['failed'].append({'device_id': device_id, 'tag_id': tag_id, 'reason': str(e)})
            conn.commit()
        
        # Invalidate device caches for all affected devices
        for device_id in device_ids:
            invalidate_cache_for_device(device_id)
        cache.clear('devices')
        logging.info(f"User {user_name} bulk assigned tags to {len(device_ids)} devices.")
        return jsonify(results)
    
    @app.route('/bulk/export_subnets', methods=['POST'])
    @permission_required('export_subnet_csv')
    def bulk_export_subnets():
        subnet_ids = request.form.getlist('subnet_ids[]')
        from flask import current_app
        output = StringIO()
        writer = csv.writer(output)
        
        with get_db_connection(current_app) as conn:
            cursor = conn.cursor()
            for subnet_id in subnet_ids:
                cursor.execute('SELECT id, name, cidr FROM Subnet WHERE id = %s', (subnet_id,))
                subnet = cursor.fetchone()
                if not subnet:
                    continue
                
                writer.writerow([f"Subnet: {subnet[1]} ({subnet[2]})"])
                writer.writerow(['IP Address', 'Hostname', 'Description'])
                
                cursor.execute('SELECT * FROM IPAddress WHERE subnet_id = %s', (subnet_id,))
                ip_addresses = cursor.fetchall()
                cursor.execute('SELECT id, name, description FROM Device')
                devices = cursor.fetchall()
                device_name_map = {name.lower(): (id, description) for id, name, description in devices}
                
                for ip in ip_addresses:
                    hostname = ip[2]
                    device_description = None
                    if hostname:
                        match = device_name_map.get(hostname.lower())
                        if match:
                            device_description = match[1]
                    writer.writerow([ip[1] or '', hostname or '', device_description or ''])
                
                writer.writerow([])  # Empty row between subnets
        
        output.seek(0)
        return send_file(BytesIO(output.getvalue().encode('utf-8')), 
                        mimetype='text/csv',
                        as_attachment=True,
                        download_name='bulk_subnet_export.csv')
    
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

    app.add_url_rule('/login', 'login', login, methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', logout)
    app.add_url_rule('/', 'index', index)
    app.add_url_rule('/devices', 'devices', devices)
    app.add_url_rule('/add_device', 'add_device', add_device, methods=['GET', 'POST'])
    app.add_url_rule('/device/<int:device_id>', 'device', device)
    app.add_url_rule('/device/<int:device_id>/add_ip', 'device_add_ip', device_add_ip, methods=['POST'])
    app.add_url_rule('/device/<int:device_id>/delete_ip', 'device_delete_ip', device_delete_ip, methods=['POST'])
    app.add_url_rule('/device/<int:device_id>/assign_tag', 'device_assign_tag', device_assign_tag, methods=['POST'])
    app.add_url_rule('/device/<int:device_id>/remove_tag', 'device_remove_tag', device_remove_tag, methods=['POST'])
    app.add_url_rule('/delete_device', 'delete_device', delete_device, methods=['POST'])
    app.add_url_rule('/subnet/<int:subnet_id>', 'subnet', subnet)
    app.add_url_rule('/add_subnet', 'add_subnet', add_subnet, methods=['POST'])
    app.add_url_rule('/edit_subnet', 'edit_subnet', edit_subnet, methods=['POST'])
    app.add_url_rule('/delete_subnet', 'delete_subnet', delete_subnet, methods=['POST'])
    app.add_url_rule('/admin', 'admin', admin, methods=['GET', 'POST'])
    app.add_url_rule('/users', 'users', users, methods=['GET', 'POST'])
    app.add_url_rule('/tags', 'tags', tags, methods=['GET', 'POST'])
    app.add_url_rule('/audit', 'audit', audit)
    app.add_url_rule('/get_available_ips', 'get_available_ips', get_available_ips)
    app.add_url_rule('/rename_device', 'rename_device', rename_device, methods=['POST'])
    app.add_url_rule('/update_device_description', 'update_device_description', update_device_description, methods=['POST'])
    app.add_url_rule('/subnet/<int:subnet_id>/export_csv', 'export_subnet_csv', export_subnet_csv)
    app.add_url_rule('/subnet/<int:subnet_id>/dhcp', 'dhcp_pool', dhcp_pool, methods=['GET', 'POST'])
    app.add_url_rule('/device_type_stats', 'device_type_stats', device_type_stats)
    app.add_url_rule('/device_types', 'device_types', device_types, methods=['GET', 'POST'])
    app.add_url_rule('/devices/type/<device_type>', 'devices_by_type', devices_by_type)
    app.add_url_rule('/devices/tag/<int:tag_id>', 'devices_by_tag', devices_by_tag)
    app.add_url_rule('/racks', 'racks', racks)
    app.add_url_rule('/rack/add', 'add_rack', add_rack, methods=['GET', 'POST'])
    app.add_url_rule('/rack/<int:rack_id>', 'rack', rack)
    app.add_url_rule('/rack/<int:rack_id>/add_device', 'rack_add_device', rack_add_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/add_nonnet_device', 'rack_add_nonnet_device', rack_add_nonnet_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/remove_device', 'rack_remove_device', rack_remove_device, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/delete', 'delete_rack', delete_rack, methods=['POST'])
    app.add_url_rule('/rack/<int:rack_id>/export_csv', 'export_rack_csv', export_rack_csv)
    app.add_url_rule('/search', 'search', search)
    app.add_url_rule('/help', 'help', help)
    app.add_url_rule('/backup', 'backup', backup, methods=['GET', 'POST'])
    app.add_url_rule('/backup/create', 'create_backup', create_backup, methods=['POST'])
    app.add_url_rule('/backup/download/<filename>', 'download_backup', download_backup)
    app.add_url_rule('/backup/restore', 'restore_backup', restore_backup, methods=['POST'])
    app.add_url_rule('/backup/delete/<filename>', 'delete_backup', delete_backup, methods=['POST'])
    app.add_url_rule('/backup/create', 'create_backup', create_backup, methods=['POST'])
    app.add_url_rule('/backup/download/<filename>', 'download_backup', download_backup)
    app.add_url_rule('/backup/restore', 'restore_backup', restore_backup, methods=['POST'])
    app.add_url_rule('/backup/delete/<filename>', 'delete_backup', delete_backup, methods=['POST'])