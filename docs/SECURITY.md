# Security Guide - Internal Audit Tracker

This document outlines the security features, best practices, and configuration options for the Internal Audit Tracker.

## 🔒 Security Overview

The Internal Audit Tracker is built with security as a primary concern, implementing enterprise-grade security measures suitable for handling sensitive audit data.

## 🛡️ Built-in Security Features

### Authentication & Session Management
- **Secure Sessions**: Flask-Session with secure cookie configuration
- **Session Timeout**: Configurable timeout (default: 5 minutes)
- **Session Invalidation**: Automatic cleanup of expired sessions
- **CSRF Protection**: Built-in Cross-Site Request Forgery protection
- **Secure Cookies**: HTTPOnly and SameSite cookie attributes

### Password Security
- **Strong Password Requirements**: Configurable complexity rules
- **Password Hashing**: Werkzeug PBKDF2 SHA256 hashing
- **Password History**: Prevention of password reuse
- **Password Expiry**: Configurable password aging (default: 90 days)
- **Account Lockout**: Protection against brute force attacks

### Access Control
- **Role-Based Access Control (RBAC)**: 4-tier permission system
- **Principle of Least Privilege**: Users only have necessary permissions
- **Admin Override**: Emergency access capabilities
- **Session Tracking**: Monitor active user sessions

### Rate Limiting & Abuse Protection
- **Flask-Limiter Integration**: Configurable rate limiting
- **Brute Force Protection**: Account lockout after failed attempts
- **IP-based Rate Limiting**: Prevent automated attacks
- **Request Throttling**: General API rate limiting

## ⚙️ Security Configuration

### Environment Variables

```bash
# Required Security Settings
SECRET_KEY=your-super-secret-key-minimum-32-characters-long
FLASK_ENV=production

# Optional Security Settings
SESSION_TIMEOUT=1800  # 30 minutes in seconds
PASSWORD_EXPIRY_DAYS=90
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900  # 15 minutes in seconds
```

### Password Requirements Configuration

```python
# In main.py - customize password requirements by role
PASSWORD_REQUIREMENTS = {
    'admin': {
        'min_length': 12,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True,
        'require_special': False,
        'description': 'Minimum 12 characters with uppercase, lowercase, and numbers'
    },
    'user': {
        'min_length': 8,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True,
        'require_special': True,
        'description': 'Minimum 8 characters with uppercase, lowercase, numbers, and special characters'
    }
}
```

### Session Configuration

```python
# Flask app configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,        # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',       # CSRF protection
    SESSION_COOKIE_SECURE=True,          # HTTPS only (production)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)
```

### Rate Limiting Configuration

```python
# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],
    storage_uri="memory://"  # Use Redis in production
)

# Specific endpoint rate limiting
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter limit for login
def login():
    # Login logic
```

## 🔐 Production Security Checklist

### Essential Security Steps

#### 1. Environment Configuration
- [ ] Set strong `SECRET_KEY` (minimum 32 characters)
- [ ] Set `FLASK_ENV=production`
- [ ] Configure secure database credentials
- [ ] Enable HTTPS/TLS encryption
- [ ] Set secure cookie flags

#### 2. User Management
- [ ] Change default admin password immediately
- [ ] Create multiple admin accounts
- [ ] Implement regular password rotation
- [ ] Review and audit user accounts
- [ ] Remove unused accounts

#### 3. Network Security
- [ ] Configure firewall rules
- [ ] Restrict database access
- [ ] Use VPN for remote access
- [ ] Implement IP whitelisting if needed
- [ ] Enable fail2ban or similar

#### 4. Database Security
- [ ] Regular database backups
- [ ] Encrypt database files
- [ ] Restrict file permissions
- [ ] Use dedicated database user
- [ ] Enable database logging

#### 5. Application Security
- [ ] Regular security updates
- [ ] Monitor security logs
- [ ] Implement log rotation
- [ ] Regular security audits
- [ ] Penetration testing

## 🚨 Security Incident Response

### Immediate Response Steps

1. **Identify the Incident**
   - Monitor application logs
   - Check failed login attempts
   - Review unusual activity patterns

2. **Contain the Incident**
   - Disable affected accounts
   - Block suspicious IP addresses
   - Isolate affected systems

3. **Investigate**
   - Review audit logs
   - Check database integrity
   - Analyze attack vectors

4. **Recover**
   - Restore from clean backups
   - Update passwords
   - Apply security patches

5. **Learn**
   - Document the incident
   - Update security procedures
   - Implement preventive measures

### Log Monitoring

```python
# Key security events to monitor
security_events = [
    'Failed login attempts',
    'Account lockouts',
    'Password changes',
    'Admin access',
    'User role changes',
    'Data exports',
    'Configuration changes'
]
```

## 🔍 Security Auditing

### Built-in Audit Trail

The application automatically logs:
- All user actions (create, update, delete)
- Login/logout events
- Failed authentication attempts
- Administrative actions
- Data import/export activities
- Configuration changes

### Audit Log Review

```python
# Regular audit log analysis
def analyze_security_logs():
    # Check for suspicious patterns
    # Monitor failed login attempts
    # Review admin activities
    # Identify unusual access patterns
```

## 🌐 Deployment Security

### HTTPS/TLS Configuration

```nginx
# Nginx configuration example
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Cloud Deployment Security

#### Railway/Heroku
```bash
# Set environment variables securely
railway variables set SECRET_KEY="your-secret-key"
railway variables set FLASK_ENV="production"

# For Heroku
heroku config:set SECRET_KEY="your-secret-key"
heroku config:set FLASK_ENV="production"
```

#### Docker Security
```dockerfile
# Dockerfile security best practices
FROM python:3.9-slim

# Create non-root user
RUN useradd -m -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership to appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "main.py"]
```

## 🔧 Advanced Security Configuration

### Database Encryption

```python
# SQLite encryption (requires sqlcipher)
DATABASE_URL = 'sqlite+pysqlcipher://:password@/path/to/database.db'
```

### Redis Session Storage

```python
# Production session storage with Redis
app.config.update(
    SESSION_TYPE='redis',
    SESSION_REDIS=redis.from_url('redis://localhost:6379'),
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_KEY_PREFIX='audit_tracker:'
)
```

### Content Security Policy

```python
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

## 📋 Security Testing

### Manual Security Testing

1. **Authentication Testing**
   - Test password requirements
   - Verify account lockout
   - Check session timeout
   - Test password reset

2. **Authorization Testing**
   - Verify role-based access
   - Test privilege escalation
   - Check direct object references
   - Validate admin functions

3. **Input Validation Testing**
   - Test SQL injection
   - Check XSS vulnerabilities
   - Verify file upload restrictions
   - Test parameter tampering

### Automated Security Testing

```bash
# Install security testing tools
pip install bandit safety

# Run security scans
bandit -r main.py
safety check
```

## 📞 Security Support

### Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security issues to:
- 📧 **Email**: security@audit-tracker.com
- 🔒 **PGP Key**: Available on request
- 🕐 **Response Time**: 24-48 hours

### Security Updates

- Subscribe to security notifications
- Apply updates promptly
- Test updates in staging environment
- Monitor security advisories

---

**Remember**: Security is an ongoing process, not a one-time setup. Regularly review and update your security configuration to protect against evolving threats.
