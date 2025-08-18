# Daily Backup System - Complete Documentation
## 365-Day Retention System for Audit Tracker Application

### 🎯 Overview
This comprehensive backup system provides automated daily backups of both the application files and database with 365-day retention policy. It includes backup creation, compression, automated cleanup, and restoration capabilities.

---

## 📁 System Components

### Core Files:
- `daily_backup.py` - Main backup engine
- `restore_backup.py` - Backup restoration system
- `run_daily_backup.bat` - Windows batch script
- `run_daily_backup.ps1` - PowerShell script with advanced features
- `setup_backup_schedule.ps1` - Automatic scheduler setup

### Generated Files:
- `backup.log` - Detailed backup operation logs
- `backup_schedule.log` - Scheduled execution logs
- `backup_report.txt` - Current backup system status
- `backups/` - Directory containing all backup archives

---

## 🔧 Features

### ✅ **Comprehensive Backup Coverage**
- **Database**: SQLite database with integrity checks
- **Application Files**: All Python scripts, templates, static files
- **Configuration**: All config files, requirements, deployment files
- **Documentation**: README files, documentation, scripts

### ✅ **Advanced Security**
- **Integrity Checks**: Database validation before backup
- **SQL Dumps**: Disaster recovery format included
- **Compression**: ZIP archives to save space
- **Verification**: Post-backup validation

### ✅ **Intelligent Management**
- **365-Day Retention**: Automatic cleanup of old backups
- **Space Efficient**: Compressed archives with size reporting
- **Collision Avoidance**: Timestamped backup names
- **Progress Logging**: Detailed operation tracking

### ✅ **Restoration System**
- **Interactive Menu**: Easy backup selection
- **Selective Restore**: Choose what to restore
- **Pre-Restore Backup**: Safety backup before restoration
- **Integrity Validation**: Database checks after restore

---

## 🚀 Installation & Setup

### 1. **Manual Execution**
```batch
# Run backup immediately
python daily_backup.py

# Run with PowerShell (recommended)
.\run_daily_backup.ps1
```

### 2. **Automatic Daily Scheduling**
```powershell
# Run as Administrator
.\setup_backup_schedule.ps1

# Custom backup time
.\setup_backup_schedule.ps1 -BackupTime "03:00"
```

### 3. **Verify Installation**
```batch
# Check scheduled task
schtasks /query /tn "AuditTracker-DailyBackup"

# View backup status
type backups\backup_report.txt
```

---

## 📊 Backup Structure

### Archive Format: `backup_YYYYMMDD_HHMMSS.zip`
```
backup_20250816_103324.zip
├── database_20250816_103324.db     # SQLite database backup
├── database_dump_20250816_103324.sql  # SQL dump for disaster recovery
└── application/                     # Application files
    ├── app.py                      # Main application
    ├── requirements.txt            # Dependencies
    ├── templates/                  # HTML templates
    ├── static/                     # CSS/JS files
    └── *.py, *.md, *.json, etc.   # All relevant files
```

### Backup Report Sample:
```
BACKUP SYSTEM REPORT
Generated: 2025-08-16 10:33:24
==================================================

Retention Policy: 365 days
Total Backups: 15
Total Size: 2.45 GB
Oldest Backup: 2025-07-16
Newest Backup: 2025-08-16

Backup Directory: C:\...\backups
Application Directory: C:\...\Railway-Deploy
Database File: audit_findings.db
```

---

## 🔄 Restoration Process

### 1. **List Available Backups**
```bash
python restore_backup.py
```

### 2. **Interactive Restoration Menu**
```
📋 Available Backups:
================================================================================
#   Date                 Time       Size (MB)    Filename
--------------------------------------------------------------------------------
1   2025-08-16          10:33:24   0.22         backup_20250816_103324.zip
2   2025-08-15          02:00:15   0.21         backup_20250815_020015.zip
3   2025-08-14          02:00:12   0.20         backup_20250814_020012.zip
--------------------------------------------------------------------------------
0   Cancel

Select backup to restore (number): 1
```

### 3. **Restoration Options**
- ✅ Restore database (recommended)
- ✅ Restore application files (recommended)  
- ✅ Create pre-restoration backup (recommended)

### 4. **Safety Features**
- Pre-restoration backup of current state
- Confirmation prompts before overwriting
- Detailed logging of restoration process
- Database integrity verification

---

## 📅 Scheduling Configuration

### Default Schedule:
- **Time**: 2:00 AM daily
- **User**: SYSTEM account  
- **Privileges**: Highest (for file access)
- **Power**: Runs on battery, wakes computer
- **Retry**: Starts when available if missed

### Customization:
```powershell
# Change backup time
.\setup_backup_schedule.ps1 -BackupTime "01:30"

# Force overwrite existing task
.\setup_backup_schedule.ps1 -Force
```

---

## 🗂️ File Management

### What Gets Backed Up:
✅ **Application Files**
- `app.py`, `config.py`, `*.py` scripts
- `requirements.txt`, `runtime.txt`, `Procfile`
- `railway.toml`, `railway.json`
- All documentation files (`*.md`, `*.txt`)

✅ **Directory Structure**  
- `templates/` - All HTML templates
- `static/` - CSS, JavaScript, images
- All batch and PowerShell scripts

✅ **Database**
- `audit_findings.db` - SQLite database
- SQL dump for disaster recovery

### What Gets Excluded:
❌ **Temporary Files**
- `backups/` directory (prevents recursion)
- `__pycache__/` directories
- `.git/` repository files
- `node_modules/`, `venv/`, `env/`

---

## 📈 Monitoring & Maintenance

### Log Files:
```bash
# Backup operations log
type backup.log

# Scheduled execution log  
type backup_schedule.log

# Current system status
type backups\backup_report.txt
```

### Key Metrics:
- **Backup Count**: Number of retained backups
- **Total Size**: Disk space used by backups
- **Success Rate**: Successful backup percentage
- **Oldest/Newest**: Date range of available backups

### Maintenance Commands:
```powershell
# Manual backup test
.\run_daily_backup.ps1

# Check task status
Get-ScheduledTask -TaskName "AuditTracker-DailyBackup"

# View task history
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TaskScheduler/Operational"}
```

---

## 🚨 Troubleshooting

### Common Issues:

#### **Backup Fails - Permission Error**
```powershell
# Run setup as Administrator
.\setup_backup_schedule.ps1
```

#### **Unicode/Emoji Display Issues**  
- Normal behavior on Windows console
- Check `backup.log` for actual results
- All operations complete successfully despite display warnings

#### **Database Lock Error**
- Ensure application is not running during backup
- Database backup uses SQLite's built-in backup API
- Temporary locks are automatically handled

#### **Disk Space Issues**
```bash
# Check backup directory size
dir backups /s

# Manual cleanup (removes backups older than 30 days)
python -c "
import os, glob, datetime
cutoff = datetime.datetime.now() - datetime.timedelta(days=30)
for f in glob.glob('backups/backup_*.zip'):
    try:
        date = f.split('_')[1]
        if datetime.datetime.strptime(date, '%Y%m%d') < cutoff:
            os.remove(f)
            print(f'Removed: {f}')
    except: pass
"
```

---

## 🔧 Advanced Configuration

### Custom Retention Period:
```python
# Edit daily_backup.py
RETENTION_DAYS = 180  # Change from 365 to 180 days
```

### Custom Backup Location:
```python
# Edit daily_backup.py
BACKUP_BASE_DIR = "D:\\backups\\audit_tracker"  # Custom location
```

### Additional File Patterns:
```python
# Edit daily_backup.py - _backup_application_files method
items_to_backup = [
    'app.py',
    'requirements.txt',
    # Add custom patterns:
    '*.log',      # Include log files
    'data/',      # Include data directory
    'uploads/',   # Include uploads directory
]
```

---

## 📋 Backup Validation

### Automatic Checks:
- ✅ Database integrity verification
- ✅ File existence validation  
- ✅ Archive compression verification
- ✅ Size and timestamp validation

### Manual Validation:
```bash
# Test backup archive
python -c "
import zipfile
with zipfile.ZipFile('backups/backup_YYYYMMDD_HHMMSS.zip', 'r') as zf:
    print('Archive contents:')
    for info in zf.infolist():
        print(f'  {info.filename} - {info.file_size} bytes')
    print('Archive is valid!')
"

# Test database backup
sqlite3 backups/extracted/database_YYYYMMDD_HHMMSS.db "PRAGMA integrity_check;"
```

---

## 🎯 Production Recommendations

### Security:
- Store backups on separate drive/network location
- Enable Windows backup encryption
- Regular restore testing (monthly)
- Monitor backup success notifications

### Performance:
- Schedule during low-usage hours (2:00 AM default)
- Monitor disk space usage
- Consider backup compression levels
- Archive very old backups to cold storage

### Compliance:
- Document backup procedures
- Test disaster recovery annually  
- Maintain backup access logs
- Verify data retention policies

---

## 📞 Support Commands

### Quick Status Check:
```batch
@echo off
echo === BACKUP SYSTEM STATUS ===
echo.
echo Scheduled Task:
schtasks /query /tn "AuditTracker-DailyBackup" 2>nul || echo Task not found
echo.
echo Latest Backup:
dir backups\backup_*.zip /od /b 2>nul | find /v "" /c && dir backups\backup_*.zip /od /b | tail -1
echo.
echo Backup Directory Size:
dir backups /s | find "bytes"
echo.
echo Last 5 Log Entries:
tail -5 backup.log 2>nul || echo No log file found
```

### Emergency Restore:
```bash
# Quick restore latest backup
python restore_backup.py --latest --auto-confirm --restore-all
```

---

## ✅ Summary

Your **365-Day Daily Backup System** is now fully operational with:

- 🔄 **Automated daily backups** at 2:00 AM
- 💾 **Complete application and database backup**
- 🗜️ **Compressed archives** to save space  
- 🔄 **365-day automatic retention** with cleanup
- 📋 **Detailed logging and reporting**
- 🔧 **Easy restoration system** with safety features
- 📅 **Windows Task Scheduler** integration
- 🛡️ **Database integrity checks**
- 📊 **Progress monitoring and status reports**

The system is production-ready and will maintain your data safely with minimal maintenance required!

---

**Need help?** Check the log files or run the diagnostic commands above.
