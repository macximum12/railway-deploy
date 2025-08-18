from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session, flash
import sqlite3
from datetime import datetime, timedelta
import csv
import io
# Force Railway deployment - Updated template icons
from functools import wraps
import os
import time
import hashlib
import secrets
import ipaddress
import bcrypt

app = Flask(__name__)
# Use environment variable for secret key in production, fallback for development
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.permanent_session_lifetime = timedelta(minutes=5)  # Session expires in 5 minutes

# SECURITY: Add security headers to all responses
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to protect against various attacks"""
    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS filtering in browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # More permissive CSP for development while maintaining core security
    # In production, this should be more restrictive
    is_development = app.debug or not (request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https')
    
    if is_development:
        # Development CSP - more permissive for styling and scripts
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; "
            "style-src 'self' 'unsafe-inline' https: data:; "
            "font-src 'self' https: data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
    else:
        # Production CSP - more restrictive
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
    
    response.headers['Content-Security-Policy'] = csp_policy
    
    # Referrer Policy - control information sent in referrer header
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Only add HTTPS headers if we detect HTTPS
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        # Enforce HTTPS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    return response

# Active sessions tracking (in production, use Redis or database)
ACTIVE_SESSIONS = {}

# Track password change attempts to prevent loops
PASSWORD_CHANGE_ATTEMPTS = {}

# SECURITY: Brute force protection
LOGIN_ATTEMPTS = {}  # Track failed login attempts per IP
ACCOUNT_LOCKOUTS = {}  # Track locked accounts
SUSPICIOUS_IPS = {}  # Track IPs with suspicious activity
RATE_LIMITS = {}  # Track rate limiting per IP

# Security configuration
SECURITY_CONFIG = {
    'max_login_attempts': 5,  # Max failed attempts before lockout
    'lockout_duration': 900,  # 15 minutes lockout
    'rate_limit_window': 60,  # 1 minute window
    'max_requests_per_window': 30,  # Max requests per minute
    'progressive_delay': True,  # Enable progressive delay
    'suspicious_threshold': 10,  # Mark IP as suspicious after X failed attempts
    'max_suspicious_duration': 3600,  # 1 hour suspension for suspicious IPs
    'csrf_token_expiry': 3600  # CSRF tokens expire in 1 hour
}

# Role definitions with permissions and password requirements
ROLES = {
    'Administrator': {
        'permissions': ['create', 'read', 'update', 'delete', 'manage_users', 'admin_settings', 'security_monitor'],
        'password_requirements': {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True, 
            'require_numbers': True,
            'require_special': False,  # Admin convenience
            'description': 'Minimum 8 characters with uppercase, lowercase, and numbers'
        }
    },
    'Content Manager': {
        'permissions': ['create', 'read', 'update', 'delete', 'bulk_operations'],
        'password_requirements': {
            'min_length': 10,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'description': 'Minimum 10 characters with uppercase, lowercase, numbers, and special characters'
        }
    },
    'Contributor': {
        'permissions': ['create', 'read', 'update_own'],
        'password_requirements': {
            'min_length': 10,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'description': 'Minimum 10 characters with uppercase, lowercase, numbers, and special characters'
        }
    },
    'Viewer': {
        'permissions': ['read'],
        'password_requirements': {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'description': 'Minimum 12 characters with uppercase, lowercase, numbers, and special characters'
        }
    }
}

# Password requirements (legacy support)
PASSWORD_REQUIREMENTS = {role.lower().replace(' ', '_'): data['password_requirements'] for role, data in ROLES.items()}

# Default admin credentials (in production, use a proper user database)
DEFAULT_ADMIN = {
    'username': 'admin',
    'password': 'admin'  # In production, use hashed passwords!
}

# PASSWORD HASHING FUNCTIONS
def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    """Verify a password against its hash"""
    try:
        # Handle both hashed and plain text passwords for migration
        if hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$'):
            # This is a bcrypt hash
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        else:
            # Legacy plain text password - verify and update
            if password == hashed_password:
                return True
    except Exception as e:
        print(f"Password verification error: {e}")
        return False
    return False

def migrate_user_password(username, password):
    """Migrate a user's plain text password to hashed password"""
    try:
        conn = sqlite3.connect('audit_findings.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Hash the password
        hashed_password = hash_password(password)
        
        # Update the database
        cursor.execute('''
            UPDATE users 
            SET password = ?, updated_at = ? 
            WHERE username = ?
        ''', (hashed_password, datetime.now().isoformat(), username))
        
        conn.commit()
        conn.close()
        
        print(f"Password migrated to hash for user: {username}")
        return True
    except Exception as e:
        print(f"Error migrating password for {username}: {e}")
        return False

def generate_temporary_password():
    """Generate a secure temporary password"""
    # Use a mix of uppercase, lowercase, numbers, and special characters
    import string
    import random
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    numbers = string.digits
    special_chars = "!@#$%^&*"
    
    # Ensure at least one character from each set
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(numbers),
        random.choice(special_chars)
    ]
    
    # Fill the rest with random choices from all sets
    all_chars = uppercase + lowercase + numbers + special_chars
    for _ in range(8):  # Total length will be 12 characters
        password.append(random.choice(all_chars))
    
    # Shuffle to avoid predictable patterns
    random.shuffle(password)
    
    return ''.join(password)

def reset_user_password(username, admin_username):
    """Reset user password to a temporary password and mark for forced change"""
    try:
        # Generate temporary password
        temp_password = generate_temporary_password()
        
        # Hash the temporary password
        hashed_temp_password = hash_password(temp_password)
        
        conn = sqlite3.connect('audit_findings.db')
        cursor = conn.cursor()
        
        # Update user with temporary password and force change flag
        cursor.execute('''
            UPDATE users 
            SET password = ?, 
                must_change_password = 1,
                updated_at = ?
            WHERE username = ?
        ''', (hashed_temp_password, datetime.now().isoformat(), username))
        
        if cursor.rowcount == 0:
            conn.close()
            return None, "User not found"
        
        conn.commit()
        conn.close()
        
        # Log the password reset activity
        log_activity('PASSWORD_RESET', f'Password reset for user {username} by admin {admin_username}')
        
        return temp_password, None
        
    except Exception as e:
        print(f"Error resetting password for {username}: {e}")
        return None, f"Error resetting password: {str(e)}"

# SECURITY FUNCTIONS
def get_client_ip():
    """Get client IP address, handling proxies and load balancers"""
    # Check for forwarded IP (common with proxies/load balancers)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP if multiple are present
        return forwarded_for.split(',')[0].strip()
    
    # Check for real IP (some proxies use this)
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fallback to remote address
    return request.remote_addr or 'unknown'

def is_rate_limited(ip):
    """Check if IP is rate limited"""
    current_time = time.time()
    window_start = current_time - SECURITY_CONFIG['rate_limit_window']
    
    if ip not in RATE_LIMITS:
        RATE_LIMITS[ip] = []
    
    # Clean old requests outside the window
    RATE_LIMITS[ip] = [req_time for req_time in RATE_LIMITS[ip] if req_time > window_start]
    
    # Check if limit exceeded
    if len(RATE_LIMITS[ip]) >= SECURITY_CONFIG['max_requests_per_window']:
        return True
    
    # Add current request
    RATE_LIMITS[ip].append(current_time)
    return False

def is_ip_suspicious(ip):
    """Check if IP is marked as suspicious"""
    if ip not in SUSPICIOUS_IPS:
        return False
    
    current_time = time.time()
    suspicious_until = SUSPICIOUS_IPS[ip].get('until', 0)
    
    if current_time > suspicious_until:
        # Suspension expired, remove from suspicious list
        del SUSPICIOUS_IPS[ip]
        return False
    
    return True

def mark_ip_suspicious(ip, reason="Multiple failed login attempts"):
    """Mark IP as suspicious with temporary suspension"""
    current_time = time.time()
    SUSPICIOUS_IPS[ip] = {
        'marked_at': current_time,
        'until': current_time + SECURITY_CONFIG['max_suspicious_duration'],
        'reason': reason,
        'attempts': SUSPICIOUS_IPS.get(ip, {}).get('attempts', 0) + 1
    }
    
    print(f"🚨 SECURITY: Marked IP {ip} as suspicious - {reason}")

def is_account_locked(username):
    """Check if account is locked due to failed attempts"""
    if username not in ACCOUNT_LOCKOUTS:
        return False
    
    current_time = time.time()
    locked_until = ACCOUNT_LOCKOUTS[username].get('until', 0)
    
    if current_time > locked_until:
        # Lockout expired, remove from locked accounts
        del ACCOUNT_LOCKOUTS[username]
        return False
    
    return True

def lock_account(username, ip):
    """Lock account temporarily after failed attempts"""
    current_time = time.time()
    lockout_duration = SECURITY_CONFIG['lockout_duration']
    
    ACCOUNT_LOCKOUTS[username] = {
        'locked_at': current_time,
        'until': current_time + lockout_duration,
        'ip': ip,
        'attempts': ACCOUNT_LOCKOUTS.get(username, {}).get('attempts', 0) + 1
    }
    
    print(f"🔒 SECURITY: Account '{username}' locked until {datetime.fromtimestamp(current_time + lockout_duration)}")

def record_failed_login(username, ip):
    """Record failed login attempt and apply security measures"""
    current_time = time.time()
    
    # Initialize tracking for this IP if not exists
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    
    # Add failed attempt
    LOGIN_ATTEMPTS[ip].append({
        'timestamp': current_time,
        'username': username
    })
    
    # Clean old attempts (older than 1 hour)
    hour_ago = current_time - 3600
    LOGIN_ATTEMPTS[ip] = [attempt for attempt in LOGIN_ATTEMPTS[ip] if attempt['timestamp'] > hour_ago]
    
    # Count recent failed attempts
    recent_attempts = len(LOGIN_ATTEMPTS[ip])
    
    # Apply progressive security measures
    if recent_attempts >= SECURITY_CONFIG['suspicious_threshold']:
        mark_ip_suspicious(ip, f"Too many failed login attempts ({recent_attempts})")
    elif recent_attempts >= SECURITY_CONFIG['max_login_attempts']:
        lock_account(username, ip)
    
    return recent_attempts

def calculate_progressive_delay(attempts):
    """Calculate delay based on number of attempts (exponential backoff)"""
    if not SECURITY_CONFIG['progressive_delay']:
        return 0
    
    # Progressive delays: 1s, 2s, 4s, 8s, 16s, capped at 30s
    delay = min(2 ** (attempts - 1), 30)
    return delay

def apply_security_delay(attempts):
    """Apply progressive delay to slow down brute force attempts"""
    if attempts > 1:
        delay = calculate_progressive_delay(attempts)
        if delay > 0:
            print(f"⏳ SECURITY: Applying {delay}s delay after {attempts} failed attempts")
            time.sleep(delay)

def log_security_event(event_type, details, severity="INFO"):
    """Log security events with enhanced details"""
    try:
        conn = get_db_connection()
        ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        username = session.get('username', 'Anonymous')
        
        # Enhanced security logging
        security_details = f"IP: {ip} | Event: {event_type} | Details: {details} | Severity: {severity}"
        
        conn.execute("""
            INSERT INTO activity_logs (username, action, details, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, f'SECURITY_{event_type}', security_details, ip, user_agent, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        print(f"🛡️  SECURITY LOG [{severity}]: {username} - {event_type} - {details}")
    except Exception as e:
        print(f"❌ Failed to log security event: {e}")

def security_check_decorator(f):
    """Decorator to apply security checks before processing requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = get_client_ip()
        
        # Check if IP is suspicious
        if is_ip_suspicious(ip):
            log_security_event('BLOCKED_SUSPICIOUS_IP', f'Blocked request from suspicious IP: {ip}', 'WARNING')
            flash('Access temporarily restricted. Please try again later.', 'error')
            return render_template('login.html', error='Access temporarily restricted', current_year=datetime.now().year), 429
        
        # Check rate limiting
        if is_rate_limited(ip):
            log_security_event('RATE_LIMIT_EXCEEDED', f'Rate limit exceeded for IP: {ip}', 'WARNING')
            flash('Too many requests. Please slow down.', 'error')
            return render_template('login.html', error='Rate limit exceeded', current_year=datetime.now().year), 429
        
        return f(*args, **kwargs)
    return decorated_function

# CSRF PROTECTION FUNCTIONS
def generate_csrf_token():
    """Generate a secure CSRF token"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
        session['_csrf_token_time'] = time.time()
    return session['_csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    if '_csrf_token' not in session or '_csrf_token_time' not in session:
        return False
    
    # Check if token matches
    if not secrets.compare_digest(session.get('_csrf_token', ''), token):
        return False
    
    # Check if token is expired
    token_age = time.time() - session.get('_csrf_token_time', 0)
    if token_age > SECURITY_CONFIG['csrf_token_expiry']:
        return False
    
    return True

def csrf_protect(f):
    """Decorator to protect routes with CSRF tokens"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token', '')
            
            if not validate_csrf_token(token):
                ip = get_client_ip()
                log_security_event('CSRF_TOKEN_INVALID', 
                                 f'Invalid or missing CSRF token from IP: {ip} for route: {request.endpoint}', 
                                 'WARNING')
                flash('Security token invalid. Please try again.', 'error')
                return redirect(request.url)
        
        return f(*args, **kwargs)
    return decorated_function

# Make CSRF token available to all templates
@app.context_processor
def csrf_token():
    return {'csrf_token': generate_csrf_token}

# Database setup
def init_db():
    conn = sqlite3.connect('audit_findings.db')
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_reference TEXT,
        audit_report TEXT,
        observations TEXT,
        observation_details TEXT,
        report_date TEXT,
        priority TEXT,
        recommendation TEXT,
        management_response TEXT,
        target_date TEXT,
        revised_target_date TEXT,
        completion_date TEXT,
        person_responsible TEXT,
        department TEXT,
        status TEXT,
        validated TEXT,
        testing_procedures TEXT,
        comments TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
    )
    """)
    
    # Create activity logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        session_id TEXT
    )
    """)
    
    # Create users table for password management
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'Viewer',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT,
        is_active BOOLEAN DEFAULT 1,
        must_change_password BOOLEAN DEFAULT 0,
        temp_password BOOLEAN DEFAULT 0,
        created_by TEXT
    )
    """)
    
    # Insert default admin user if not exists
    cursor.execute("""
    INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)
    """, (DEFAULT_ADMIN['username'], DEFAULT_ADMIN['password'], 'Administrator'))
    
    # Only attempt role migration if no constraints prevent it
    try:
        # Test if we can insert a new role
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ('test_migration', 'test', 'Administrator'))
        cursor.execute("DELETE FROM users WHERE username = 'test_migration'")
        
        # If successful, migrate existing roles
        cursor.execute("UPDATE users SET role = 'Administrator' WHERE role = 'admin'")
        cursor.execute("UPDATE users SET role = 'Content Manager' WHERE role = 'editor'")  
        cursor.execute("UPDATE users SET role = 'Viewer' WHERE role = 'viewer'")
        print("✅ User roles migrated successfully")
    except sqlite3.IntegrityError:
        print("⚠️ Role migration skipped due to existing constraints - will handle via fallback logic")
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('audit_findings.db')
    conn.row_factory = sqlite3.Row
    return conn

# Activity logging functions
def log_activity(action, details=None):
    """Log user activity to the database"""
    try:
        conn = get_db_connection()
        username = session.get('username', 'Anonymous')
        session_id = session.get('session_id', 'N/A')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.now().isoformat()
        
        conn.execute("""
            INSERT INTO activity_logs (username, action, details, ip_address, user_agent, timestamp, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, action, details, ip_address, user_agent, timestamp, session_id))
        
        conn.commit()
        conn.close()
        print(f"📝 Activity logged: {username} - {action}")
    except Exception as e:
        print(f"❌ Failed to log activity: {e}")

def get_user_from_db(username):
    """Get user from database"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user:
        # Convert sqlite3.Row to dictionary for easier access
        return dict(user)
    return None

def update_user_password(username, new_password):
    """Update user password in database with hashing"""
    conn = get_db_connection()
    hashed_password = hash_password(new_password)
    conn.execute("""
        UPDATE users SET password = ?, updated_at = ?, must_change_password = 0, temp_password = 0 WHERE username = ?
    """, (hashed_password, datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def create_user(username, temp_password, role, created_by):
    """Create a new user with temporary password (hashed)"""
    try:
        conn = get_db_connection()
        hashed_password = hash_password(temp_password)
        conn.execute("""
            INSERT INTO users (username, password, role, created_by, must_change_password, temp_password, created_at)
            VALUES (?, ?, ?, ?, 1, 1, ?)
        """, (username, hashed_password, role, created_by, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists

def get_all_users():
    """Get all users for admin management"""
    try:
        conn = get_db_connection()
        users = conn.execute("""
            SELECT id, username, role, is_active, must_change_password, temp_password, created_at, created_by
            FROM users ORDER BY created_at DESC
        """).fetchall()
        conn.close()
        
        # Convert sqlite3.Row objects to dictionaries and handle role compatibility
        user_list = []
        for user in users:
            user_dict = dict(user)
            # Map legacy roles for template compatibility
            original_role = user_dict['role']
            if original_role == 'admin':
                user_dict['role'] = 'Administrator'
                print(f"📝 Mapped role 'admin' -> 'Administrator' for user {user_dict['username']}")
            elif original_role == 'editor':
                user_dict['role'] = 'Content Manager'
                print(f"📝 Mapped role 'editor' -> 'Content Manager' for user {user_dict['username']}")
            elif original_role == 'viewer':
                user_dict['role'] = 'Viewer'
                print(f"📝 Mapped role 'viewer' -> 'Viewer' for user {user_dict['username']}")
            else:
                print(f"📝 Role '{original_role}' for user {user_dict['username']} - no mapping needed")
            user_list.append(user_dict)
        
        return user_list
    except Exception as e:
        print(f"❌ Error fetching users: {e}")
        return []

def validate_password_requirements(password, role):
    """Validate password based on industry standards (NIST/OWASP)"""
    # Map legacy roles to current role names for validation
    role_mapping = {
        'admin': 'administrator',
        'editor': 'content_manager', 
        'viewer': 'viewer'
    }
    
    # If role is a legacy role, map it to the new format
    if role in role_mapping:
        role_key = role_mapping[role]
    else:
        # Convert current role format to key format
        role_key = role.lower().replace(' ', '_')
    
    # Get requirements with fallback to viewer
    requirements = PASSWORD_REQUIREMENTS.get(role_key, PASSWORD_REQUIREMENTS['viewer'])
    errors = []
    
    print(f"🔍 Validating password for role '{role}' -> key '{role_key}'")
    
    # Check minimum length
    if len(password) < requirements['min_length']:
        errors.append(f"Password must be at least {requirements['min_length']} characters long")
    
    # Check for uppercase letters
    if requirements['require_uppercase'] and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Check for lowercase letters  
    if requirements['require_lowercase'] and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    # Check for numbers
    if requirements['require_numbers'] and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    # Check for special characters
    if requirements['require_special']:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)")
    
    # Check for common weak patterns
    weak_patterns = ['123', 'abc', 'password', 'admin', 'user', '000', '111', '999']
    password_lower = password.lower()
    for pattern in weak_patterns:
        if pattern in password_lower:
            errors.append(f"Password should not contain common patterns like '{pattern}'")
            break
    
    if errors:
        return False, " | ".join(errors)
    return True, requirements['description']

def deactivate_user(username):
    """Deactivate a user account"""
    conn = get_db_connection()
    conn.execute("""
        UPDATE users SET is_active = 0, updated_at = ? WHERE username = ?
    """, (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def activate_user(username):
    """Activate a user account"""
    conn = get_db_connection()
    conn.execute("""
        UPDATE users SET is_active = 1, updated_at = ? WHERE username = ?
    """, (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def is_admin(username):
    """Check if user is admin (legacy support)"""
    user = get_user_from_db(username)
    if not user:
        return False
    # Handle both legacy and current role formats
    return user['role'] in ['Administrator', 'admin']

def has_permission(username, permission):
    """Check if user has a specific permission"""
    user = get_user_from_db(username)
    if not user or not user.get('is_active', 1):
        return False
    
    user_role = user.get('role')
    if user_role not in ROLES:
        # Handle legacy roles or default to basic permissions
        print(f"⚠️ User {username} has invalid role: {user_role}. Checking legacy permissions.")
        if user_role == 'admin':
            user_role = 'Administrator'
        elif user_role == 'editor':
            user_role = 'Content Manager'
        elif user_role == 'viewer':
            user_role = 'Viewer'
        else:
            return False  # Unknown role
    
    return permission in ROLES[user_role]['permissions']

def requires_permission(permission):
    """Decorator to check if user has required permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            username = session.get('username')
            if not username:
                return redirect(url_for('login'))
            
            if not has_permission(username, permission):
                flash('You do not have permission to access this resource.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_role_info(username):
    """Get user role and permissions information"""
    user = get_user_from_db(username)
    if not user:
        return None
    
    role = user.get('role')
    if role not in ROLES:
        # Fallback for users with old/invalid roles
        print(f"⚠️ User {username} has invalid role: {role}. Defaulting to Viewer.")
        role = 'Viewer'
    
    return {
        'role': role,
        'permissions': ROLES[role]['permissions'],
        'password_requirements': ROLES[role]['password_requirements']
    }

# Session management functions
def generate_session_id():
    """Generate a unique session ID"""
    import uuid
    return str(uuid.uuid4())

def invalidate_previous_sessions(username):
    """Invalidate all previous sessions for a user"""
    global ACTIVE_SESSIONS
    sessions_to_remove = []
    for session_id, session_data in ACTIVE_SESSIONS.items():
        if session_data.get('username') == username:
            sessions_to_remove.append(session_id)
    
    for session_id in sessions_to_remove:
        del ACTIVE_SESSIONS[session_id]
        print(f"🚫 Invalidated previous session: {session_id[:8]}...")

def is_session_valid(username, session_id):
    """Check if the current session is the active one for the user"""
    return (session_id in ACTIVE_SESSIONS and 
            ACTIVE_SESSIONS[session_id].get('username') == username)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or 'session_id' not in session:
            # Special handling for force password change to prevent loops
            if request.endpoint == 'force_password_change':
                session.clear()
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))
            return redirect(url_for('login', next=request.url))
        
        username = session.get('username')
        session_id = session.get('session_id')
        
        # Check for session timeout
        if check_session_timeout():
            print(f"⏰ Session timed out for user: {username}")
            session.clear()
            # Special handling for force password change to prevent loops
            if request.endpoint == 'force_password_change':
                flash('Session expired during password change. Please log in again.', 'error')
                return redirect(url_for('login'))
            flash('Your session has expired due to inactivity. Please log in again.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        # Check if this is the active session for the user
        if not is_session_valid(username, session_id):
            print(f"⚠️ Session terminated for user: {username} (login from another location)")
            session.clear()
            # Special handling for force password change to prevent loops
            if request.endpoint == 'force_password_change':
                flash('Session terminated. Please log in again.', 'error')
                return redirect(url_for('login'))
            flash('Your session has been terminated due to login from another location.', 'info')
            return redirect(url_for('login', next=request.url))
        
        # Update last activity timestamp
        update_session_activity()
        
        # CRITICAL SECURITY: Check if user must change password and restrict access
        user = get_user_from_db(username)
        if user and user['must_change_password']:
            # Only allow access to force_password_change, logout, and reset_password_loop
            allowed_endpoints = {'force_password_change', 'logout', 'reset_password_loop'}
            
            if request.endpoint not in allowed_endpoints:
                print(f"🔒 Access denied for user {username} - must change password first (attempted: {request.endpoint})")
                log_activity('UNAUTHORIZED_ACCESS_ATTEMPT', f'User tried to access {request.endpoint} without changing mandatory password')
                flash('You must change your password before accessing other parts of the system.', 'warning')
                return redirect(url_for('force_password_change'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator for administrator-only access"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        if not has_permission(username, 'admin_settings'):
            flash('Access denied. Administrator privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def check_session_timeout():
    """Check if session has timed out"""
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(minutes=5):
            return True
    return False

def update_session_activity():
    """Update last activity timestamp"""
    session['last_activity'] = datetime.now().isoformat()

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
@security_check_decorator
def login():
    ip = get_client_ip()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember')
        
        # Input validation
        if not username or not password:
            log_security_event('LOGIN_ATTEMPT', f'Empty credentials provided from IP: {ip}', 'WARNING')
            flash('Username and password are required', 'error')
            return render_template('login.html', error='Invalid input', current_year=datetime.now().year)
        
        # Check if account is locked
        if is_account_locked(username):
            locked_until = ACCOUNT_LOCKOUTS[username]['until']
            remaining_time = int(locked_until - time.time())
            log_security_event('LOGIN_BLOCKED', f'Attempt to access locked account "{username}" from IP: {ip}', 'WARNING')
            flash(f'Account temporarily locked. Try again in {remaining_time//60} minutes.', 'error')
            return render_template('login.html', error='Account locked', current_year=datetime.now().year)
        
        # Get user from database
        user = get_user_from_db(username)
        
        # Enhanced authentication with security logging
        if user and verify_password(password, user['password']) and user['is_active']:
            # Migrate plain text password to hashed if needed
            if not (user['password'].startswith('$2b$') or user['password'].startswith('$2a$')):
                migrate_user_password(username, password)
            
            # Successful login - clear any failed attempts for this IP
            if ip in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[ip]
            if username in ACCOUNT_LOCKOUTS:
                del ACCOUNT_LOCKOUTS[username]
            
            # Invalidate any previous sessions for this user
            invalidate_previous_sessions(username)
            
            # Generate new session ID
            new_session_id = generate_session_id()
            
            # Store session data
            session['logged_in'] = True
            session['username'] = username
            session['session_id'] = new_session_id
            session['user_role'] = user['role']
            update_session_activity()  # Set initial activity timestamp
            
            # Track active session globally
            ACTIVE_SESSIONS[new_session_id] = {
                'username': username,
                'login_time': datetime.now().isoformat(),
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'ip_address': request.remote_addr
            }
            
            # Make session permanent if "Remember me" is checked
            if remember:
                session.permanent = True
            else:
                session.permanent = False
            
            # Log successful login
            log_activity('LOGIN', f'Successful login from {request.remote_addr}')
            
            print(f"✅ User '{username}' logged in successfully (Session: {new_session_id[:8]}...)")
            
            # Check if user must change password (temporary password)
            if user['must_change_password']:
                # Extra safety check: ensure password change is actually required
                fresh_user_check = get_user_from_db(username)
                if fresh_user_check and fresh_user_check['must_change_password']:
                    flash('You must change your temporary password before continuing.', 'warning')
                    return redirect(url_for('force_password_change'))
                else:
                    # Flag was cleared, proceed normally
                    print(f"🔄 Password change flag cleared for user {username} during login")
            
            flash('Login successful!', 'success')
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            # Prevent redirect loops to force-password-change
            if next_page and 'force-password-change' in next_page:
                next_page = None
            redirect_url = next_page if next_page else url_for('index')
            return redirect(redirect_url)
        else:
            # SECURITY: Enhanced failed login handling
            failed_attempts = record_failed_login(username, ip)
            
            # Apply progressive delay to slow down brute force attempts
            apply_security_delay(failed_attempts)
            
            # Enhanced security logging
            log_security_event('LOGIN_FAILED', 
                             f'Failed login attempt for user "{username}" from IP: {ip} (Attempt #{failed_attempts})', 
                             'WARNING')
            
            # Log failed login attempt to activity logs
            try:
                conn = get_db_connection()
                conn.execute("""
                    INSERT INTO activity_logs (username, action, details, ip_address, user_agent, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, 'LOGIN_FAILED', f'Failed login attempt #{failed_attempts} from {ip}', 
                      ip, request.headers.get('User-Agent', 'Unknown'), 
                      datetime.now().isoformat()))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Failed to log login attempt: {e}")
            
            # Generic error message (don't reveal if username exists)
            flash('Invalid username or password', 'error')
            return render_template('login.html', error='Invalid username or password', current_year=datetime.now().year)
    
    return render_template('login.html', current_year=datetime.now().year)

@app.route('/logout')
def logout():
    # Log logout activity before clearing session
    log_activity('LOGOUT', 'User logged out')
    
    # Clean up session tracking
    session_id = session.get('session_id')
    username = session.get('username')
    
    if session_id and session_id in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[session_id]
        print(f"🚫 Removed session {session_id[:8]}... for user: {username}")
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/admin/sessions')
@login_required
def view_sessions():
    """Admin route to view active sessions (for debugging)"""
    log_activity('VIEW_SESSIONS', 'Accessed active sessions page')
    return jsonify({
        'active_sessions': len(ACTIVE_SESSIONS),
        'sessions': {
            sid[:8] + '...': {
                'username': data['username'],
                'login_time': data['login_time'],
                'ip_address': data.get('ip_address', 'Unknown')
            }
            for sid, data in ACTIVE_SESSIONS.items()
        }
    })

@app.route('/admin/security-status')
@admin_required
def security_status():
    """Admin route to view security status and threats"""
    log_activity('VIEW_SECURITY_STATUS', 'Accessed security status page')
    
    current_time = time.time()
    
    # Prepare security status data
    security_data = {
        'suspicious_ips': {},
        'account_lockouts': {},
        'recent_failed_attempts': {},
        'security_config': SECURITY_CONFIG,
        'total_suspicious_ips': len(SUSPICIOUS_IPS),
        'total_locked_accounts': len(ACCOUNT_LOCKOUTS),
        'timestamp': datetime.now().isoformat()
    }
    
    # Format suspicious IPs data
    for ip, data in SUSPICIOUS_IPS.items():
        remaining_time = max(0, int(data['until'] - current_time))
        security_data['suspicious_ips'][ip] = {
            'reason': data['reason'],
            'marked_at': datetime.fromtimestamp(data['marked_at']).isoformat(),
            'remaining_minutes': remaining_time // 60,
            'attempts': data['attempts']
        }
    
    # Format account lockouts data
    for username, data in ACCOUNT_LOCKOUTS.items():
        remaining_time = max(0, int(data['until'] - current_time))
        security_data['account_lockouts'][username] = {
            'locked_at': datetime.fromtimestamp(data['locked_at']).isoformat(),
            'remaining_minutes': remaining_time // 60,
            'ip': data['ip'],
            'attempts': data['attempts']
        }
    
    # Format recent failed attempts (last hour)
    hour_ago = current_time - 3600
    for ip, attempts in LOGIN_ATTEMPTS.items():
        recent_attempts = [a for a in attempts if a['timestamp'] > hour_ago]
        if recent_attempts:
            security_data['recent_failed_attempts'][ip] = {
                'count': len(recent_attempts),
                'last_attempt': datetime.fromtimestamp(recent_attempts[-1]['timestamp']).isoformat(),
                'usernames_attempted': list(set(a['username'] for a in recent_attempts))
            }
    
    return jsonify(security_data)

@app.route('/admin/unblock-ip/<ip>', methods=['POST'])
@admin_required
@csrf_protect
def unblock_ip(ip):
    """Admin route to manually unblock a suspicious IP"""
    try:
        # Validate IP format
        ipaddress.ip_address(ip)
        
        # Remove from suspicious IPs
        if ip in SUSPICIOUS_IPS:
            del SUSPICIOUS_IPS[ip]
            log_security_event('IP_UNBLOCKED', f'Admin manually unblocked IP: {ip}', 'INFO')
            flash(f'IP {ip} has been unblocked', 'success')
        else:
            flash(f'IP {ip} was not blocked', 'info')
            
        # Remove from login attempts
        if ip in LOGIN_ATTEMPTS:
            del LOGIN_ATTEMPTS[ip]
            
        # Remove from rate limits
        if ip in RATE_LIMITS:
            del RATE_LIMITS[ip]
            
    except Exception as e:
        log_security_event('UNBLOCK_FAILED', f'Failed to unblock IP {ip}: {str(e)}', 'ERROR')
        flash(f'Failed to unblock IP: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('security_status'))

@app.route('/admin/unlock-account/<username>', methods=['POST'])
@admin_required
@csrf_protect
def unlock_account(username):
    """Admin route to manually unlock an account"""
    try:
        if username in ACCOUNT_LOCKOUTS:
            del ACCOUNT_LOCKOUTS[username]
            log_security_event('ACCOUNT_UNLOCKED', f'Admin manually unlocked account: {username}', 'INFO')
            flash(f'Account {username} has been unlocked', 'success')
        else:
            flash(f'Account {username} was not locked', 'info')
            
    except Exception as e:
        log_security_event('UNLOCK_FAILED', f'Failed to unlock account {username}: {str(e)}', 'ERROR')
        flash(f'Failed to unlock account: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('security_status'))

@app.route('/activity-logs')
@login_required
def activity_logs():
    """View activity logs"""
    log_activity('VIEW_ACTIVITY_LOGS', 'Accessed activity logs page')
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Show 50 logs per page
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    
    # Get total count for pagination
    total_count = conn.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0]
    
    # Get logs for current page
    logs = conn.execute('''
        SELECT * FROM activity_logs 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()
    
    conn.close()
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('activity_logs.html', 
                         logs=logs, 
                         page=page, 
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         total_count=total_count)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@csrf_protect
def settings():
    """User settings page"""
    username = session.get('username')
    user = get_user_from_db(username)
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    # Create template-safe password requirements structure
    template_password_requirements = {}
    for role, data in ROLES.items():
        key = role.lower().replace(' ', '_')
        template_password_requirements[key] = data['password_requirements']
        # Also add the role name as key for direct access
        template_password_requirements[role] = data['password_requirements']
        # Add legacy role mappings
        if role == 'Administrator':
            template_password_requirements['admin'] = data['password_requirements']
        elif role == 'Content Manager':
            template_password_requirements['editor'] = data['password_requirements']
        elif role == 'Viewer':
            template_password_requirements['viewer'] = data['password_requirements']
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required', 'error')
            return render_template('settings.html', user=user, password_requirements=template_password_requirements)
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('settings.html', user=user, password_requirements=template_password_requirements)
        
        # Validate password requirements based on role
        is_valid, message = validate_password_requirements(new_password, user['role'])
        if not is_valid:
            flash(message, 'error')
            return render_template('settings.html', user=user, password_requirements=template_password_requirements)
        
        # Verify current password
        if not user or not verify_password(current_password, user['password']):
            flash('Current password is incorrect', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', 'Incorrect current password provided')
            return render_template('settings.html', user=user, password_requirements=template_password_requirements)
        
        # Update password
        update_user_password(username, new_password)
        log_activity('PASSWORD_CHANGED', 'Password successfully changed')
        flash('Password changed successfully!', 'success')
        
        return redirect(url_for('settings'))
    
    log_activity('VIEW_SETTINGS', 'Accessed settings page')
    return render_template('settings.html', user=user, password_requirements=template_password_requirements)

@app.route('/force-password-change', methods=['GET', 'POST'])
@login_required
@csrf_protect
@security_check_decorator
def force_password_change():
    """Force password change for users with temporary passwords"""
    username = session.get('username')
    session_id = session.get('session_id')
    
    # Loop detection: track attempts per session
    if session_id not in PASSWORD_CHANGE_ATTEMPTS:
        PASSWORD_CHANGE_ATTEMPTS[session_id] = {'count': 0, 'timestamp': datetime.now()}
    
    # Check for excessive attempts (potential loop)
    attempts = PASSWORD_CHANGE_ATTEMPTS[session_id]
    if attempts['count'] > 10:  # More than 10 attempts indicates a problem
        time_diff = datetime.now() - attempts['timestamp']
        if time_diff.total_seconds() < 300:  # Within 5 minutes
            print(f"🚨 Potential password change loop detected for user {username} (session: {session_id[:8]}...)")
            log_activity('PASSWORD_CHANGE_LOOP_DETECTED', f'Excessive password change attempts: {attempts["count"]}')
            session.clear()
            if session_id in PASSWORD_CHANGE_ATTEMPTS:
                del PASSWORD_CHANGE_ATTEMPTS[session_id]
            flash('Too many password change attempts detected. Please contact your administrator for assistance.', 'error')
            return redirect(url_for('login'))
    
    # Increment attempt counter
    PASSWORD_CHANGE_ATTEMPTS[session_id]['count'] += 1
    
    user = get_user_from_db(username)
    
    # Safety check: If user doesn't exist or is inactive, clear session and redirect to login
    if not user or not user['is_active']:
        session.clear()
        if session_id in PASSWORD_CHANGE_ATTEMPTS:
            del PASSWORD_CHANGE_ATTEMPTS[session_id]
        flash('Account not found or inactive. Please contact administrator.', 'error')
        return redirect(url_for('login'))
    
    # If user doesn't need to change password, redirect to dashboard and clean up
    if not user['must_change_password']:
        if session_id in PASSWORD_CHANGE_ATTEMPTS:
            del PASSWORD_CHANGE_ATTEMPTS[session_id]
        flash('Password change not required. Redirecting to dashboard.', 'info')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required', 'error')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Validate password requirements based on role
        is_valid, message = validate_password_requirements(new_password, user['role'])
        if not is_valid:
            flash(message, 'error')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # CRITICAL SECURITY: Prevent reuse of temporary password
        if verify_password(new_password, user['password']):
            flash('New password cannot be the same as your current temporary password. You must choose a different password.', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', 'Attempted to reuse temporary password as new password')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Verify current password (temporary password)
        if not verify_password(current_password, user['password']):
            flash('Current temporary password is incorrect', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', 'Incorrect temporary password provided')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Update password and remove temporary flag
        try:
            update_user_password(username, new_password)
            log_activity('PASSWORD_CHANGED', 'Temporary password successfully changed')
            
            # Double-check that the flags were properly updated
            updated_user = get_user_from_db(username)
            if updated_user and not updated_user['must_change_password']:
                # Clean up tracking
                if session_id in PASSWORD_CHANGE_ATTEMPTS:
                    del PASSWORD_CHANGE_ATTEMPTS[session_id]
                print(f"✅ Password successfully changed for user {username}, flags cleared")
                flash('Password changed successfully! You can now use the system normally.', 'success')
                return redirect(url_for('index'))
            else:
                # If there was an issue with updating, log it and try again
                print(f"⚠️ Warning: Password flags not properly updated for user {username}")
                flash('Password updated but there was a system issue. Please try logging in again.', 'warning')
                session.clear()
                if session_id in PASSWORD_CHANGE_ATTEMPTS:
                    del PASSWORD_CHANGE_ATTEMPTS[session_id]
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"❌ Error updating password for user {username}: {e}")
            flash('An error occurred while updating your password. Please try again.', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', f'System error during password update: {str(e)}')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
    
    return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)

@app.route('/reset-password-loop')
def reset_password_loop():
    """Emergency route to break password change loops"""
    # Clear session and provide clean login
    session.clear()
    flash('Password change session has been reset. Please log in again.', 'info')
    print(f"🔄 Password change loop reset requested from IP: {request.remote_addr}")
    return redirect(url_for('login'))

@app.route('/admin/users')
@admin_required
def manage_users():
    """Admin page to manage users"""
    try:
        users = get_all_users()
        log_activity('VIEW_USER_MANAGEMENT', 'Accessed user management page')
        
        # Ensure password requirements structure matches template expectations
        template_password_requirements = {}
        for role, data in ROLES.items():
            key = role.lower().replace(' ', '_')
            template_password_requirements[key] = data['password_requirements']
        
        return render_template('admin/manage_users.html', 
                             users=users, 
                             password_requirements=template_password_requirements, 
                             roles=ROLES)
    except Exception as e:
        print(f"❌ Error in manage_users: {e}")
        import traceback
        print(f"Full error traceback: {traceback.format_exc()}")
        flash('Error loading user management page. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def add_user():
    """Admin page to add new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        temp_password = request.form.get('temp_password', '').strip()
        role = request.form.get('role', 'Viewer')
        
        # Validate inputs
        if not username or not temp_password:
            flash('Username and temporary password are required', 'error')
            return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)
        
        if role not in ROLES:
            flash('Invalid role selected', 'error')
            return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)
        
        # Get role-specific password requirements
        role_key = role.lower().replace(' ', '_')
        
        # Validate temporary password requirements  
        is_valid, message = validate_password_requirements(temp_password, role_key)
        if not is_valid:
            flash(f"Temporary password error: {message}", 'error')
            return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)
        
        # Create user
        created_by = session.get('username')
        if create_user(username, temp_password, role, created_by):
            log_activity('CREATE_USER', f'Created new user: {username} with role: {role}')
            flash(f'User "{username}" created successfully with temporary password. They must change it on first login.', 'success')
            return redirect(url_for('manage_users'))
        else:
            flash('Username already exists', 'error')
    
    return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS, roles=ROLES)

@app.route('/admin/users/<username>/toggle-status', methods=['POST'])
@admin_required
@csrf_protect
def toggle_user_status(username):
    """Toggle user active/inactive status"""
    user = get_user_from_db(username)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('manage_users'))
    
    # Prevent admin from deactivating themselves
    current_user = session.get('username')
    if username == current_user:
        flash('You cannot deactivate your own account', 'error')
        return redirect(url_for('manage_users'))
    
    if user['is_active']:
        deactivate_user(username)
        log_activity('DEACTIVATE_USER', f'Deactivated user: {username}')
        flash(f'User "{username}" has been deactivated', 'info')
    else:
        activate_user(username)
        log_activity('ACTIVATE_USER', f'Activated user: {username}')
        flash(f'User "{username}" has been activated', 'success')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<username>/reset-password', methods=['POST'])
@admin_required
@csrf_protect  
def admin_reset_password(username):
    """Admin function to reset user password to temporary password"""
    # Prevent admin from resetting their own password this way
    current_user = session.get('username')
    if username == current_user:
        flash('You cannot reset your own password through admin panel. Use account settings instead.', 'error')
        return redirect(url_for('manage_users'))
    
    # Check if user exists
    user = get_user_from_db(username)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('manage_users'))
    
    # Generate and set temporary password
    temp_password, error = reset_user_password(username, current_user)
    
    if error:
        flash(f'Error resetting password: {error}', 'error')
    else:
        flash(f'Password reset successful! Temporary password for "{username}": <strong>{temp_password}</strong><br>'
              f'<small>Please share this securely with the user. They must change it on next login.</small>', 'success')
        log_activity('ADMIN_PASSWORD_RESET', f'Admin {current_user} reset password for user {username}')
    
    return redirect(url_for('manage_users'))

@app.route('/')
@login_required
def index():
    log_activity('VIEW_DASHBOARD', 'Accessed main dashboard')
    username = session.get('username')
    
    # Get user role info with fallback
    user_role_info = get_user_role_info(username)
    if not user_role_info:
        # Fallback for users with problematic roles
        user_role_info = {
            'role': 'Viewer',
            'permissions': ROLES['Viewer']['permissions'],
            'password_requirements': ROLES['Viewer']['password_requirements']
        }
    
    conn = get_db_connection()
    
    # Filter findings based on permissions
    try:
        if has_permission(username, 'read'):
            # Can see all findings
            findings = conn.execute('''
                SELECT id, audit_reference, audit_report, status, priority, 
                       target_date, person_responsible, created_at, created_by
                FROM audit_findings 
                ORDER BY created_at DESC
            ''').fetchall()
        else:
            # Can only see their own findings (shouldn't happen with current roles, but future-proof)
            findings = conn.execute('''
                SELECT id, audit_reference, audit_report, status, priority, 
                       target_date, person_responsible, created_at, created_by
                FROM audit_findings 
                WHERE created_by = ?
                ORDER BY created_at DESC
            ''', (username,)).fetchall()
    except Exception as e:
        print(f"❌ Error fetching findings: {e}")
        findings = []
    
    conn.close()
    return render_template('index.html', findings=findings, user_role_info=user_role_info)

@app.route('/dashboard')
@login_required  
def dashboard():
    """Dashboard route alias for index"""
    return redirect(url_for('index'))

@app.route('/findings')
@login_required
def findings():
    conn = get_db_connection()
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible 
        FROM audit_findings 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('findings.html', findings=findings)

@app.route('/add', methods=['GET', 'POST'])
@login_required
@requires_permission('create')
@csrf_protect
def add_finding():
    if request.method == 'POST':
        conn = get_db_connection()
        now = datetime.now().isoformat()
        
        # Handle conditional audit report field
        audit_reference = request.form.get('audit_reference', '').strip()
        if audit_reference in ['24-07', '25-05']:
            audit_report = request.form.get('audit_report_custom', '').strip()
        else:
            audit_report = request.form.get('audit_report', '').strip()
        
        # Get other required fields
        observations = request.form.get('observations', '').strip()
        
        # Validate required fields
        error_message = None
        if not audit_reference:
            error_message = "Audit Reference is required"
        elif not audit_report:
            error_message = "Audit Report is required"
        elif not observations:
            error_message = "Observations are required"
        
        if error_message:
            conn.close()
            return render_template('add_finding.html', error=error_message)
        
        # Get target_date and clear it if status is Completed
        target_date = request.form.get('target_date', '').strip()
        status = request.form.get('status', '').strip()
        if status == 'Completed':
            target_date = None  # Clear target date for completed findings
        
        conn.execute('''
            INSERT INTO audit_findings (
                audit_reference, audit_report, observations, observation_details,
                report_date, priority, recommendation, management_response,
                target_date, revised_target_date, completion_date,
                person_responsible, department, status, validated,
                testing_procedures, comments, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit_reference,
            audit_report,
            observations,
            request.form.get('observation_details', ''),
            request.form.get('report_date', ''),
            request.form.get('priority', ''),
            request.form.get('recommendation', ''),
            request.form.get('management_response', ''),
            target_date,
            request.form.get('revised_target_date', ''),
            request.form.get('completion_date', ''),
            request.form.get('person_responsible', ''),
            request.form.get('department', ''),
            status,
            request.form.get('validated', ''),
            request.form.get('testing_procedures', ''),
            request.form.get('comments', ''),
            now
        ))
        conn.commit()
        conn.close()
        
        # Log the activity
        log_activity('ADD_FINDING', f'Added new finding: {audit_reference} - {audit_report[:50]}...')
        
        return redirect(url_for('index'))
    
    log_activity('VIEW_ADD_FORM', 'Accessed add finding form')
    return render_template('add_finding.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@csrf_protect
def edit_finding(id):
    conn = get_db_connection()
    username = session.get('username')
    
    # Check permissions
    can_update_all = has_permission(username, 'update')
    can_update_own = has_permission(username, 'update_own')
    
    if not (can_update_all or can_update_own):
        flash('You do not have permission to edit findings.', 'error')
        return redirect(url_for('dashboard'))
    
    # If user can only update their own, verify ownership
    if can_update_own and not can_update_all:
        finding = conn.execute('SELECT created_by FROM audit_findings WHERE id = ?', (id,)).fetchone()
        if not finding or finding['created_by'] != username:
            flash('You can only edit findings you created.', 'error')
            return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        now = datetime.now().isoformat()
        
        # Handle conditional audit report field
        audit_reference = request.form.get('audit_reference', '')
        if audit_reference in ['24-07', '25-05']:
            audit_report = request.form.get('audit_report_custom', '')
        else:
            audit_report = request.form.get('audit_report', '')
        
        # Process status and target date - clear target date if status is Completed
        status = request.form.get('status', '')
        target_date = request.form.get('target_date', '')
        if status == 'Completed':
            target_date = ''
        
        conn.execute('''
            UPDATE audit_findings SET
                audit_reference=?, audit_report=?, observations=?, observation_details=?,
                report_date=?, priority=?, recommendation=?, management_response=?,
                target_date=?, revised_target_date=?, completion_date=?,
                person_responsible=?, department=?, status=?, validated=?,
                testing_procedures=?, comments=?, updated_at=?
            WHERE id=?
        ''', (
            audit_reference,
            audit_report,
            request.form.get('observations', ''),
            request.form.get('observation_details', ''),
            request.form.get('report_date', ''),
            request.form.get('priority', ''),
            request.form.get('recommendation', ''),
            request.form.get('management_response', ''),
            target_date,
            request.form.get('revised_target_date', ''),
            request.form.get('completion_date', ''),
            request.form.get('person_responsible', ''),
            request.form.get('department', ''),
            status,
            request.form.get('validated', ''),
            request.form.get('testing_procedures', ''),
            request.form.get('comments', ''),
            now,
            id
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    finding = conn.execute('SELECT * FROM audit_findings WHERE id = ?', (id,)).fetchone()
    conn.close()
    return render_template('edit_finding.html', finding=finding)

@app.route('/delete/<int:id>')
@login_required
def delete_finding(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM audit_findings WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export_csv():
    conn = get_db_connection()
    findings = conn.execute('SELECT * FROM audit_findings').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Audit Reference', 'Audit Report', 'Observations', 'Observation Details',
        'Report Date', 'Priority', 'Recommendation', 'Management Response',
        'Target Date', 'Revised Target Date', 'Completion Date',
        'Person Responsible', 'Department', 'Status', 'Validated',
        'Testing Procedures', 'Comments', 'Created At', 'Updated At'
    ])
    
    # Write data
    for finding in findings:
        writer.writerow(finding)
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=audit_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/import', methods=['GET', 'POST'])
@login_required
@csrf_protect
def import_findings():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        
        if file and file.filename.endswith('.csv'):
            # Process the CSV file
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            
            # Skip header row
            next(csv_input)
            
            conn = get_db_connection()
            imported_count = 0
            errors = []
            
            for row_num, row in enumerate(csv_input, start=2):
                if len(row) < 14:  # Ensure minimum required columns
                    errors.append(f"Row {row_num}: Insufficient columns")
                    continue
                
                try:
                    # Map CSV columns to database columns
                    # Your CSV: Audit Reference Number,Audit Report,Observations,Observation Details,Report Date,Priority,Recommendation,Management Response,Target Date,Revised Target Date,Completion Date,Person Responsible,Department of Person Responsible,Status,Validated,Testing Procedures,Comments
                    audit_reference = row[0].strip() if row[0] else ''
                    audit_report = row[1].strip() if row[1] else ''
                    observations = row[2].strip() if row[2] else ''
                    observation_details = row[3].strip() if row[3] else ''
                    report_date = row[4].strip() if row[4] else ''
                    priority = row[5].strip() if row[5] else ''
                    recommendation = row[6].strip() if row[6] else ''
                    management_response = row[7].strip() if row[7] else ''
                    target_date = row[8].strip() if row[8] else ''
                    revised_target_date = row[9].strip() if row[9] else ''
                    completion_date = row[10].strip() if row[10] else ''
                    person_responsible = row[11].strip() if row[11] else ''
                    department = row[12].strip() if row[12] else ''
                    status = row[13].strip() if row[13] else 'In-Progress'
                    validated = row[14].strip() if len(row) > 14 and row[14] else 'No'
                    testing_procedures = row[15].strip() if len(row) > 15 and row[15] else ''
                    comments = row[16].strip() if len(row) > 16 and row[16] else ''
                    
                    # Validate date fields - reject words, only accept proper dates or empty values
                    def validate_date(date_str, field_name):
                        if not date_str:
                            return ''
                        # Reject common non-date words
                        invalid_words = ['complete', 'na', 'n/a', 'pending', 'tbd', 'unknown']
                        if date_str.lower().strip() in invalid_words:
                            return ''  # Convert invalid words to empty string
                        # Check if it contains only date-like characters
                        if not all(c in '0123456789-/' for c in date_str):
                            raise ValueError(f"Invalid {field_name}: '{date_str}' contains non-date characters")
                        # Try parsing common date formats
                        try:
                            if '/' in date_str:
                                datetime.strptime(date_str, '%m/%d/%Y')
                            elif '-' in date_str:
                                if len(date_str.split('-')[0]) == 4:
                                    datetime.strptime(date_str, '%Y-%m-%d')
                                else:
                                    datetime.strptime(date_str, '%d-%b-%y')
                            return date_str
                        except ValueError:
                            raise ValueError(f"Invalid {field_name} format: '{date_str}'")
                    
                    # Clean person responsible field
                    def clean_person_responsible(person_str):
                        if not person_str:
                            return ''
                        # Take only the first line and first name/title
                        lines = person_str.split('\n')
                        first_line = lines[0].strip()
                        # If there's a comma, take only the part before the first comma
                        if ',' in first_line:
                            return first_line.split(',')[0].strip()
                        return first_line
                    
                    # Validate dates
                    target_date = validate_date(target_date, 'target date')
                    revised_target_date = validate_date(revised_target_date, 'revised target date')
                    completion_date = validate_date(completion_date, 'completion date')
                    report_date = validate_date(report_date, 'report date')
                    
                    # Clean person responsible field
                    person_responsible = clean_person_responsible(person_responsible)
                    
                    # Validate required fields
                    if not audit_reference.strip():
                        errors.append(f"Row {row_num}: Audit Reference is required")
                        continue
                    if not audit_report.strip():
                        errors.append(f"Row {row_num}: Audit Report is required")
                        continue
                    if not observations.strip():
                        errors.append(f"Row {row_num}: Observations are required")
                        continue
                    
                    # If status is Completed, target date is optional; otherwise it should be provided
                    if status.lower() != 'completed' and not target_date:
                        errors.append(f"Row {row_num}: Target date is required for non-completed findings")
                        continue
                    
                    # Insert into database
                    conn.execute('''
                        INSERT INTO audit_findings (
                            audit_reference, audit_report, observations, observation_details,
                            report_date, priority, recommendation, management_response,
                            target_date, revised_target_date, completion_date,
                            person_responsible, department, status, validated,
                            testing_procedures, comments, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        audit_reference, audit_report, observations, observation_details,
                        report_date, priority, recommendation, management_response,
                        target_date, revised_target_date, completion_date,
                        person_responsible, department, status, validated,
                        testing_procedures, comments, datetime.now().isoformat()
                    ))
                    imported_count += 1
                    
                except Exception as e:
                    errors.append(f"Row {row_num}: {str(e)}")
            
            conn.commit()
            conn.close()
            
            if errors:
                error_msg = f"Imported {imported_count} records with {len(errors)} errors: " + "; ".join(errors[:5])
                if len(errors) > 5:
                    error_msg += f" and {len(errors) - 5} more errors..."
                return render_template('import.html', message=error_msg, message_type='warning')
            else:
                return render_template('import.html', message=f"Successfully imported {imported_count} records!", message_type='success')
    
    return render_template('import.html')

@app.route('/api/chart-data/<int:year>')
@login_required
def get_chart_data(year):
    """API endpoint to get chart data for a specific year"""
    conn = get_db_connection()
    
    # Get all findings and filter by year in Python since date formats are inconsistent
    findings = conn.execute('''
        SELECT status, report_date, created_at
        FROM audit_findings 
    ''').fetchall()
    
    conn.close()
    
    # Initialize data structure
    data = {
        'Completed': 0,
        'In-Progress': 0,
        'Delayed': 0,
        'Closed': 0
    }
    
    from datetime import datetime
    import re
    
    # Function to extract year from various date formats
    def extract_year(date_str):
        if not date_str or date_str.strip() == '':
            return None
        
        # Handle formats like "17-Oct-24", "14-Jul-25", "8-May-24"
        date_patterns = [
            r'(\d{1,2})-(\w{3})-(\d{2})',  # 17-Oct-24
            r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # 17/10/24 or 17/10/2024
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-10-17
        ]
        
        for pattern in date_patterns:
            match = re.match(pattern, date_str)
            if match:
                if pattern == date_patterns[0]:  # DD-MMM-YY format
                    year_str = match.group(3)
                    # Convert 2-digit year to 4-digit
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:  # 20-99 -> 2020-2099
                            return 2000 + year_int
                        else:  # 00-19 -> 2000-2019
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[1]:  # MM/DD/YY or MM/DD/YYYY
                    year_str = match.group(3)
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:
                            return 2000 + year_int
                        else:
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[2]:  # YYYY-MM-DD
                    return int(match.group(1))
        
        return None
    
    # Filter findings by year
    for finding in findings:
        # Try to get year from report_date first
        finding_year = extract_year(finding['report_date'])
        
        # If report_date doesn't give us a year, use created_at
        if finding_year is None:
            try:
                # Extract year from created_at (ISO format)
                if finding['created_at']:
                    finding_year = int(finding['created_at'][:4])
            except:
                finding_year = None
        
        # If this finding belongs to the requested year, count it
        if finding_year == year and finding['status'] in data:
            data[finding['status']] += 1
    
    return jsonify(data)

@app.route('/api/findings-by-status/<status>/<int:year>')
@login_required
def get_findings_by_status(status, year):
    """API endpoint to get findings by status and year"""
    conn = get_db_connection()
    
    # Get all findings with the specified status
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible, created_at, report_date
        FROM audit_findings 
        WHERE status = ?
        ORDER BY created_at DESC
    ''', (status,)).fetchall()
    
    conn.close()
    
    from datetime import datetime
    import re
    
    # Function to extract year from various date formats
    def extract_year(date_str):
        if not date_str or date_str.strip() == '':
            return None
        
        # Handle formats like "17-Oct-24", "14-Jul-25", "8-May-24"
        date_patterns = [
            r'(\d{1,2})-(\w{3})-(\d{2})',  # 17-Oct-24
            r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # 17/10/24 or 17/10/2024
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-10-17
        ]
        
        for pattern in date_patterns:
            match = re.match(pattern, date_str)
            if match:
                if pattern == date_patterns[0]:  # DD-MMM-YY format
                    year_str = match.group(3)
                    # Convert 2-digit year to 4-digit
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:  # 20-99 -> 2020-2099
                            return 2000 + year_int
                        else:  # 00-19 -> 2000-2019
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[1]:  # MM/DD/YY or MM/DD/YYYY
                    year_str = match.group(3)
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:
                            return 2000 + year_int
                        else:
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[2]:  # YYYY-MM-DD
                    return int(match.group(1))
        
        return None
    
    # Filter findings by year and convert to list of dictionaries
    findings_list = []
    for finding in findings:
        # Try to get year from report_date first
        finding_year = extract_year(finding['report_date'])
        
        # If report_date doesn't give us a year, use created_at
        if finding_year is None:
            try:
                # Extract year from created_at (ISO format)
                if finding['created_at']:
                    finding_year = int(finding['created_at'][:4])
            except:
                finding_year = None
        
        # If this finding belongs to the requested year, include it
        if finding_year == year:
            findings_list.append({
                'id': finding['id'],
                'audit_reference': finding['audit_reference'],
                'audit_report': finding['audit_report'],
                'status': finding['status'],
                'priority': finding['priority'],
                'target_date': finding['target_date'],
                'person_responsible': finding['person_responsible'],
                'created_at': finding['created_at']
            })
    
    return jsonify(findings_list)

@app.route('/api/finding/<int:finding_id>')
@login_required
def get_finding_details(finding_id):
    conn = get_db_connection()
    finding = conn.execute('''
        SELECT * FROM audit_findings WHERE id = ?
    ''', (finding_id,)).fetchone()
    conn.close()
    
    if finding:
        finding_dict = {
            'id': finding['id'],
            'audit_reference': finding['audit_reference'],
            'audit_report': finding['audit_report'],
            'observations': finding['observations'],
            'observation_details': finding['observation_details'],
            'report_date': finding['report_date'],
            'priority': finding['priority'],
            'recommendation': finding['recommendation'],
            'management_response': finding['management_response'],
            'target_date': finding['target_date'],
            'revised_target_date': finding['revised_target_date'],
            'completion_date': finding['completion_date'],
            'person_responsible': finding['person_responsible'],
            'department': finding['department'],
            'status': finding['status'],
            'validated': finding['validated'],
            'testing_procedures': finding['testing_procedures'],
            'comments': finding['comments'],
            'created_at': finding['created_at'],
            'updated_at': finding['updated_at']
        }
        return jsonify(finding_dict)
    else:
        return jsonify({'error': 'Finding not found'}), 404

# Context processor to make variables available to all templates
@app.context_processor
def inject_template_vars():
    """Inject template variables available to all templates"""
    context = {}
    
    # Check if current user must change password
    try:
        if 'username' in session:
            user = get_user_from_db(session['username'])
            if user:
                context['user_must_change_password'] = user.get('must_change_password', False)
            else:
                context['user_must_change_password'] = False
        else:
            context['user_must_change_password'] = False
    except RuntimeError:
        # Handle case where we're outside request context
        context['user_must_change_password'] = False
    
    return context

# Production error handlers
@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    import traceback
    error_trace = traceback.format_exc()
    print(f"❌ Internal Server Error: {error_trace}")
    
    # Log to a file if possible
    try:
        with open('error.log', 'a') as f:
            f.write(f"{datetime.now()}: {error_trace}\n")
    except:
        pass
    
    return render_template('error.html', 
                         error_message="Internal server error occurred. Please try again."), 500

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('error.html', 
                         error_message="Page not found."), 404

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    return render_template('error.html', 
                         error_message="Access forbidden."), 403

# Initialize database when module is imported (for production deployment)
init_db()

if __name__ == '__main__':
    print("🚀 Starting Internal Audit Tracker...")
    print("📊 Database initialized successfully!")
    
    # Get port from environment variable (Railway/Heroku) or default to 5000
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    if debug:
        print(f"🌐 Server running at: http://127.0.0.1:{port}")
        print("Press CTRL+C to stop the server")
        app.run(debug=True, host='127.0.0.1', port=port)
    else:
        print(f"🌐 Production server starting on port {port}")
        app.run(debug=False, host='0.0.0.0', port=port)
