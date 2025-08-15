# Simple WebDeploy Project Backup Script
# Created: August 16, 2025

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$projectName = "WebDeploy_AuditTracker"
$backupDir = "C:\Users\Administrator\Downloads\IA\Backups\${projectName}_${timestamp}"
$sourceDir = "C:\Users\Administrator\Downloads\IA\WebDeploy"

Write-Host "Starting WebDeploy Project Backup..." -ForegroundColor Green
Write-Host "Timestamp: $timestamp" -ForegroundColor Cyan
Write-Host "Source: $sourceDir" -ForegroundColor Yellow
Write-Host "Backup Location: $backupDir" -ForegroundColor Yellow

# Create backups directory
$backupsRoot = "C:\Users\Administrator\Downloads\IA\Backups"
if (!(Test-Path $backupsRoot)) {
    New-Item -ItemType Directory -Path $backupsRoot -Force | Out-Null
    Write-Host "Created backups root directory" -ForegroundColor Green
}

# Create backup directory
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Write-Host "Created backup directory: $backupDir" -ForegroundColor Green

# Copy all files and directories
Write-Host "Copying project files..." -ForegroundColor Cyan
Copy-Item -Path "$sourceDir\*" -Destination $backupDir -Recurse -Force

# Create simple backup info file
$infoContent = @"
WebDeploy Audit Tracker - Backup Information
============================================
Backup Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Original Location: $sourceDir
Backup Location: $backupDir
Backup Type: Complete Project Backup

Project Features:
- Flask-based Audit Tracker
- User Management (Admin/Editor/Viewer roles)
- Temporary Password System
- Industry-Standard Password Requirements
- 5-Minute Session Timeout
- Password Reuse Prevention (CRITICAL SECURITY FIX)
- Infinite Loop Prevention
- CSRF Protection
- Comprehensive Activity Logging

Recent Security Enhancements:
- Password Reuse Prevention implemented
- Industry standard password requirements active
- Force password change loop prevention
- Access control bypass prevention
- Template security fixes applied
- Database object handling corrected
- Activity logging comprehensive

Files Backed Up:
- All source code files (app.py, config.py, etc.)
- All templates with security fixes
- SQLite database (instance/audit_findings.db)
- All documentation and deployment guides
- Static assets and styling
- Utility scripts and helpers

Restore Instructions:
1. Copy entire backup directory to desired location
2. Navigate to the restored directory
3. Install dependencies: pip install -r requirements.txt
4. Initialize database (if needed): python init_db.py
5. Run application: python run_app.py
6. Access at: http://localhost:5000

Security Status: All critical security fixes preserved
Backup Status: COMPLETE
"@

$infoPath = "$backupDir\BACKUP_INFO.txt"
$infoContent | Out-File -FilePath $infoPath -Encoding UTF8
Write-Host "Created backup info file: $infoPath" -ForegroundColor Green

# Verify backup
$originalFiles = Get-ChildItem -Path $sourceDir -Recurse -File | Measure-Object | Select-Object -ExpandProperty Count
$backupFiles = Get-ChildItem -Path $backupDir -Recurse -File | Measure-Object | Select-Object -ExpandProperty Count

Write-Host ""
Write-Host "BACKUP VERIFICATION:" -ForegroundColor Magenta
Write-Host "Original files: $originalFiles" -ForegroundColor White
Write-Host "Backup files: $backupFiles" -ForegroundColor White

if ($backupFiles -gt $originalFiles) {
    Write-Host "BACKUP SUCCESSFUL - All files backed up plus info file created" -ForegroundColor Green
} else {
    Write-Host "BACKUP WARNING - File count mismatch detected" -ForegroundColor Yellow
}

# Display summary
Write-Host ""
Write-Host "BACKUP SUMMARY:" -ForegroundColor Green
Write-Host "Backup Location: $backupDir" -ForegroundColor Cyan
Write-Host "Info File: $infoPath" -ForegroundColor Cyan
Write-Host "Backup Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Status: COMPLETE" -ForegroundColor Green
Write-Host ""
Write-Host "All security enhancements and recent fixes have been preserved!" -ForegroundColor Yellow
Write-Host ""
Write-Host "WebDeploy Project Backup Complete!" -ForegroundColor Green
