# Troubleshooting Guide - Internal Audit Tracker

This guide helps you diagnose and fix common issues with the Internal Audit Tracker.

## 🚨 Quick Fixes

### Application Won't Start

**Symptoms**: Error when running `python main.py`

**Solutions**:
```bash
# 1. Check Python version
python --version  # Should be 3.8+

# 2. Verify dependencies
pip install -r requirements.txt

# 3. Check if port is available
netstat -an | findstr :5000  # Windows
lsof -i :5000                # Linux/Mac

# 4. Run in debug mode
export FLASK_ENV=development
python main.py
```

### Database Issues

**Symptoms**: Database errors, missing tables, data not saving

**Solutions**:
```bash
# 1. Delete and recreate database
rm audit_findings.db  # Linux/Mac
del audit_findings.db  # Windows

# 2. Restart application (database will auto-create)
python main.py

# 3. Check file permissions
ls -la audit_findings.db  # Linux/Mac
icacls audit_findings.db  # Windows

# 4. Verify SQLite installation
python -c "import sqlite3; print(sqlite3.sqlite_version)"
```

### Login Problems

**Symptoms**: Cannot login, password not working, account locked

**Solutions**:
```bash
# 1. Use default admin credentials
Username: admin
Password: admin123

# 2. Reset admin password (delete database)
rm audit_findings.db && python main.py

# 3. Check if account is locked (wait 15 minutes)
# Or restart application to clear lockouts

# 4. Check browser cookies
# Clear cookies for localhost:5000
```

## 🔧 Common Issues

### 1. ModuleNotFoundError

**Error**: `ModuleNotFoundError: No module named 'flask_limiter'`

**Cause**: Missing dependencies

**Solution**:
```bash
# Install missing packages
pip install Flask-Limiter==3.5.0
pip install -r requirements.txt

# Verify installation
pip list | grep -i flask
```

### 2. Permission Denied

**Error**: `PermissionError: [Errno 13] Permission denied: 'audit_findings.db'`

**Cause**: Database file permissions

**Solution**:
```bash
# Linux/Mac
chmod 666 audit_findings.db
chown $USER:$USER audit_findings.db

# Windows (run as administrator)
icacls audit_findings.db /grant Everyone:F
```

### 3. Port Already in Use

**Error**: `OSError: [Errno 48] Address already in use`

**Cause**: Port 5000 is occupied

**Solution**:
```bash
# Find and kill process using port 5000
# Linux/Mac
lsof -ti:5000 | xargs kill -9

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Or use a different port
export PORT=5001
python main.py
```

### 4. Session Issues

**Error**: Users getting logged out immediately

**Cause**: Session configuration problems

**Solution**:
```bash
# Check SECRET_KEY is set
echo $SECRET_KEY

# Set a proper secret key
export SECRET_KEY="your-long-secret-key-minimum-32-characters"

# Clear browser cache and cookies
```

### 5. Excel Import Failing

**Error**: Import process fails or no data imported

**Cause**: File format or column mismatch

**Solution**:
1. Check Excel file format (should be .xlsx or .xls)
2. Verify column headers match expected format
3. Check file permissions
4. Try with a smaller file first

**Expected Columns**:
```
Finding ID, Description, Risk Level, Status, Assigned To, 
Target Date, Completion Date, Recommendation
```

### 6. Static Files Not Loading

**Error**: CSS/JavaScript not working, page looks broken

**Cause**: Missing static files or incorrect paths

**Solution**:
```bash
# Check if static directory exists
ls -la static/

# Create static directories if missing
mkdir -p static/css static/js

# Check Flask static file serving
curl http://localhost:5000/static/css/style.css
```

### 7. High Memory Usage

**Symptoms**: Application using too much memory

**Cause**: Large datasets, memory leaks

**Solution**:
```bash
# Monitor memory usage
top -p $(pgrep -f "python main.py")

# Reduce session timeout
export SESSION_TIMEOUT=300  # 5 minutes

# Restart application periodically
```

## 🌐 Deployment Issues

### Railway Deployment

**Error**: "Application failed to respond"

**Diagnosis**:
```bash
# Check Railway logs
railway logs

# Verify environment variables
railway variables

# Check if PORT is configured
railway variables set PORT=5000
```

**Solutions**:
1. Ensure `main.py` uses `PORT` environment variable
2. Bind to `0.0.0.0`, not `127.0.0.1`
3. Set `FLASK_ENV=production`
4. Check `Procfile` exists: `web: python main.py`

### Heroku Deployment

**Error**: Application crashes on startup

**Diagnosis**:
```bash
# Check Heroku logs
heroku logs --tail -a your-app-name

# Check dyno status
heroku ps -a your-app-name
```

**Solutions**:
1. Verify `Procfile`: `web: python main.py`
2. Set config vars: `heroku config:set SECRET_KEY=your-key`
3. Check Python version in `runtime.txt`
4. Ensure all dependencies in `requirements.txt`

### Docker Issues

**Error**: Container won't start or crashes

**Diagnosis**:
```bash
# Check container logs
docker logs <container-id>

# Run interactively for debugging
docker run -it audit-tracker:latest /bin/bash
```

**Solutions**:
1. Check `Dockerfile` syntax
2. Verify base image compatibility
3. Ensure all dependencies installed
4. Check file permissions

## 🔍 Debugging Techniques

### Enable Debug Mode

```python
# In main.py, temporarily enable debug mode
app.run(debug=True, host='0.0.0.0', port=5000)
```

### Check Application Logs

```python
# Add logging to main.py
import logging
logging.basicConfig(level=logging.DEBUG)

# Log specific events
print(f"Database path: {os.path.abspath('audit_findings.db')}")
print(f"Current user: {session.get('username', 'None')}")
```

### Database Debugging

```bash
# Connect to database directly
sqlite3 audit_findings.db

# Check tables
.tables

# Check user table
SELECT * FROM users;

# Check findings table  
SELECT COUNT(*) FROM findings;

# Exit
.quit
```

### Network Debugging

```bash
# Test if application is responding
curl -I http://localhost:5000/

# Check if port is open
telnet localhost 5000

# Test with different browser/incognito mode
```

## 🛠️ Performance Issues

### Slow Page Loading

**Causes**: Large datasets, inefficient queries

**Solutions**:
1. Add pagination to findings list
2. Optimize database queries
3. Add database indexes
4. Enable browser caching

### Database Performance

```sql
-- Add indexes for better performance
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_date ON findings(target_date);
CREATE INDEX idx_activity_logs_date ON activity_logs(timestamp);
```

### Memory Optimization

```python
# In main.py, optimize session handling
app.config['SESSION_COOKIE_MAXSIZE'] = 4093
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
```

## 🔒 Security Issues

### Locked Out of Admin Account

**Solution 1 - Reset Database**:
```bash
# Delete database (loses all data)
rm audit_findings.db
python main.py
# Use admin/admin123 to login
```

**Solution 2 - Direct Database Access**:
```bash
sqlite3 audit_findings.db
UPDATE users SET failed_attempts = 0 WHERE username = 'admin';
UPDATE users SET must_change_password = 0 WHERE username = 'admin';
.quit
```

### Session Problems

**Symptoms**: Constant re-login required

**Solutions**:
1. Check system clock accuracy
2. Verify SECRET_KEY is consistent
3. Clear browser cookies
4. Check session timeout settings

### CSRF Token Errors

**Error**: CSRF token missing or invalid

**Solutions**:
1. Clear browser cache
2. Check if cookies are enabled
3. Verify HTTPS configuration
4. Restart application

## 📞 Getting Help

### Self-Help Checklist

Before asking for help, please:
- [ ] Check this troubleshooting guide
- [ ] Review application logs
- [ ] Try basic solutions (restart, clear cache)
- [ ] Check environment variables
- [ ] Verify dependencies are installed

### Reporting Issues

When reporting issues, please include:

1. **System Information**
   ```bash
   python --version
   pip --version
   uname -a  # Linux/Mac
   systeminfo  # Windows
   ```

2. **Application Logs**
   ```bash
   # Capture full error output
   python main.py > app.log 2>&1
   ```

3. **Configuration**
   ```bash
   # Environment variables (remove sensitive data)
   env | grep -i flask
   ```

4. **Steps to Reproduce**
   - What you were doing
   - What you expected to happen  
   - What actually happened
   - Screenshots if helpful

### Support Channels

- 🐛 **GitHub Issues**: [Report bugs](https://github.com/macximum12/audit-logger/issues)
- 💬 **Discussions**: [Get help](https://github.com/macximum12/audit-logger/discussions)
- 📧 **Email**: support@audit-tracker.com

## 🔄 Maintenance

### Regular Maintenance Tasks

```bash
# Weekly
# 1. Backup database
cp audit_findings.db backup_$(date +%Y%m%d).db

# 2. Check for updates
git pull origin main
pip install -r requirements.txt

# 3. Review logs
tail -n 100 app.log

# Monthly  
# 1. Review user accounts
# 2. Check disk space
# 3. Update dependencies
# 4. Security review
```

### Health Checks

```bash
# Create a health check script
#!/bin/bash
# health-check.sh

echo "Checking application health..."

# Check if application is running
if curl -f http://localhost:5000/ > /dev/null 2>&1; then
    echo "✅ Application is responding"
else
    echo "❌ Application not responding"
    exit 1
fi

# Check database
if [ -f "audit_findings.db" ]; then
    echo "✅ Database file exists"
else
    echo "❌ Database file missing"
    exit 1
fi

echo "Health check passed!"
```

---

**Still having issues?** Don't hesitate to reach out! We're here to help make your Internal Audit Tracker work perfectly.
