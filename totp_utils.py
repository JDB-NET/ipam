import pyotp
import qrcode
import secrets
import json
import base64
from io import BytesIO
from flask import current_app

def generate_totp_secret():
    """Generate a new TOTP secret"""
    return pyotp.random_base32()

def get_totp_uri(secret, email, issuer_name="IPAM"):
    """Generate TOTP URI for QR code"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name=issuer_name
    )

def generate_qr_code(uri):
    """Generate QR code image from URI"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def verify_totp(secret, code):
    """Verify a TOTP code"""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # Allow 1 time step window for clock skew
    except Exception:
        return False

def generate_backup_codes(count=10):
    """Generate backup codes for 2FA"""
    return [secrets.token_urlsafe(8).upper() for _ in range(count)]

def verify_backup_code(backup_codes_json, code):
    """Verify a backup code and remove it if valid"""
    if not backup_codes_json or not code:
        return False, None
    
    try:
        codes = json.loads(backup_codes_json)
        code_upper = code.upper().strip()
        if code_upper in codes:
            codes.remove(code_upper)
            return True, json.dumps(codes) if codes else None
        return False, None
    except (json.JSONDecodeError, AttributeError):
        return False, None

def format_backup_codes(codes):
    """Format backup codes for display (group in pairs)"""
    formatted = []
    for i in range(0, len(codes), 2):
        if i + 1 < len(codes):
            formatted.append(f"{codes[i]}  {codes[i+1]}")
        else:
            formatted.append(codes[i])
    return formatted

