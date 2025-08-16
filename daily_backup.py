#!/usr/bin/env python3
"""
Daily Backup System with 365-Day Retention
Backs up entire application and database with automated cleanup
"""
import os
import shutil
import sqlite3
import zipfile
import datetime
import glob
import logging
import sys

# Configuration
BACKUP_BASE_DIR = "backups"
RETENTION_DAYS = 365
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_FILE = "audit_findings.db"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class BackupManager:
    def __init__(self):
        self.backup_dir = os.path.join(APP_DIR, BACKUP_BASE_DIR)
        self.today = datetime.datetime.now()
        self.backup_timestamp = self.today.strftime("%Y%m%d_%H%M%S")
        self.daily_backup_dir = os.path.join(self.backup_dir, f"backup_{self.backup_timestamp}")
        
        # Ensure backup directory exists
        os.makedirs(self.backup_dir, exist_ok=True)
        
    def create_daily_backup(self):
        """Create a complete daily backup of application and database"""
        try:
            logging.info("🚀 Starting daily backup process...")
            
            # Create today's backup directory
            os.makedirs(self.daily_backup_dir, exist_ok=True)
            
            # 1. Backup database
            self._backup_database()
            
            # 2. Backup application files
            self._backup_application_files()
            
            # 3. Create compressed archive
            self._create_compressed_backup()
            
            # 4. Cleanup old backups
            self._cleanup_old_backups()
            
            # 5. Generate backup report
            self._generate_backup_report()
            
            logging.info("✅ Daily backup completed successfully!")
            return True
            
        except Exception as e:
            logging.error(f"❌ Backup failed: {str(e)}")
            return False
    
    def _backup_database(self):
        """Backup SQLite database with integrity check"""
        logging.info("📊 Backing up database...")
        
        db_path = os.path.join(APP_DIR, DATABASE_FILE)
        if not os.path.exists(db_path):
            logging.warning("⚠️  Database file not found, skipping database backup")
            return
        
        # Create database backup with integrity check
        backup_db_path = os.path.join(self.daily_backup_dir, f"database_{self.backup_timestamp}.db")
        
        try:
            # Perform integrity check first
            conn = sqlite3.connect(db_path)
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result[0] != "ok":
                logging.warning(f"⚠️  Database integrity check failed: {result[0]}")
            else:
                logging.info("✅ Database integrity check passed")
            
            # Create backup using SQLite backup API
            backup_conn = sqlite3.connect(backup_db_path)
            conn.backup(backup_conn)
            backup_conn.close()
            conn.close()
            
            logging.info(f"✅ Database backup created: {backup_db_path}")
            
            # Also create a SQL dump for disaster recovery
            sql_dump_path = os.path.join(self.daily_backup_dir, f"database_dump_{self.backup_timestamp}.sql")
            self._create_sql_dump(db_path, sql_dump_path)
            
        except Exception as e:
            logging.error(f"❌ Database backup failed: {str(e)}")
            raise
    
    def _create_sql_dump(self, db_path, dump_path):
        """Create SQL dump of database for disaster recovery"""
        try:
            conn = sqlite3.connect(db_path)
            with open(dump_path, 'w') as f:
                for line in conn.iterdump():
                    f.write('%s\n' % line)
            conn.close()
            logging.info(f"✅ SQL dump created: {dump_path}")
        except Exception as e:
            logging.error(f"❌ SQL dump creation failed: {str(e)}")
    
    def _backup_application_files(self):
        """Backup all application files"""
        logging.info("📁 Backing up application files...")
        
        # Files and directories to backup
        items_to_backup = [
            'app.py',
            'requirements.txt',
            'runtime.txt',
            'Procfile',
            'railway.toml',
            'railway.json',
            'config.py',
            'templates/',
            'static/',
            '*.py',
            '*.md',
            '*.txt',
            '*.json',
            '*.toml',
            '*.bat',
            '*.ps1',
            '*.sh'
        ]
        
        # Directories to exclude from backup
        exclude_dirs = {
            'backups',
            '__pycache__',
            '.git',
            'node_modules',
            '.vscode',
            'venv',
            'env'
        }
        
        app_backup_dir = os.path.join(self.daily_backup_dir, "application")
        os.makedirs(app_backup_dir, exist_ok=True)
        
        copied_files = 0
        
        # Copy individual files matching patterns
        for pattern in items_to_backup:
            if '/' in pattern:  # Directory
                src_dir = os.path.join(APP_DIR, pattern.rstrip('/'))
                if os.path.exists(src_dir) and os.path.isdir(src_dir):
                    dest_dir = os.path.join(app_backup_dir, pattern.rstrip('/'))
                    shutil.copytree(src_dir, dest_dir, ignore=shutil.ignore_patterns('__pycache__'))
                    copied_files += len([f for f in os.listdir(dest_dir) if os.path.isfile(os.path.join(dest_dir, f))])
                    logging.info(f"✅ Copied directory: {pattern}")
            else:  # File pattern
                for file_path in glob.glob(os.path.join(APP_DIR, pattern)):
                    if os.path.isfile(file_path):
                        rel_path = os.path.relpath(file_path, APP_DIR)
                        dest_path = os.path.join(app_backup_dir, rel_path)
                        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                        shutil.copy2(file_path, dest_path)
                        copied_files += 1
        
        logging.info(f"✅ Application backup completed: {copied_files} files copied")
    
    def _create_compressed_backup(self):
        """Create compressed archive of the backup"""
        logging.info("🗜️  Creating compressed backup archive...")
        
        archive_path = f"{self.daily_backup_dir}.zip"
        
        try:
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.daily_backup_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_name = os.path.relpath(file_path, self.backup_dir)
                        zipf.write(file_path, arc_name)
            
            # Get archive size
            archive_size = os.path.getsize(archive_path)
            archive_size_mb = archive_size / (1024 * 1024)
            
            logging.info(f"✅ Compressed backup created: {archive_path} ({archive_size_mb:.2f} MB)")
            
            # Remove uncompressed backup directory to save space
            shutil.rmtree(self.daily_backup_dir)
            logging.info("✅ Temporary backup directory cleaned up")
            
        except Exception as e:
            logging.error(f"❌ Compression failed: {str(e)}")
            raise
    
    def _cleanup_old_backups(self):
        """Remove backups older than retention period"""
        logging.info(f"🧹 Cleaning up backups older than {RETENTION_DAYS} days...")
        
        cutoff_date = self.today - datetime.timedelta(days=RETENTION_DAYS)
        deleted_count = 0
        
        try:
            # Find and delete old backup files
            backup_pattern = os.path.join(self.backup_dir, "backup_*.zip")
            for backup_file in glob.glob(backup_pattern):
                try:
                    # Extract date from filename
                    filename = os.path.basename(backup_file)
                    date_str = filename.split('_')[1]  # backup_20230816_123456.zip -> 20230816
                    backup_date = datetime.datetime.strptime(date_str, "%Y%m%d")
                    
                    if backup_date < cutoff_date:
                        os.remove(backup_file)
                        deleted_count += 1
                        logging.info(f"🗑️  Deleted old backup: {filename}")
                        
                except (ValueError, IndexError) as e:
                    logging.warning(f"⚠️  Could not parse backup date from {filename}: {e}")
                    continue
            
            logging.info(f"✅ Cleanup completed: {deleted_count} old backups removed")
            
        except Exception as e:
            logging.error(f"❌ Cleanup failed: {str(e)}")
    
    def _generate_backup_report(self):
        """Generate backup status report"""
        logging.info("📋 Generating backup report...")
        
        try:
            # Count current backups
            backup_pattern = os.path.join(self.backup_dir, "backup_*.zip")
            backup_files = glob.glob(backup_pattern)
            backup_count = len(backup_files)
            
            # Calculate total backup size
            total_size = sum(os.path.getsize(f) for f in backup_files)
            total_size_gb = total_size / (1024 * 1024 * 1024)
            
            # Find oldest and newest backups
            if backup_files:
                backup_dates = []
                for backup_file in backup_files:
                    try:
                        filename = os.path.basename(backup_file)
                        date_str = filename.split('_')[1]
                        backup_date = datetime.datetime.strptime(date_str, "%Y%m%d")
                        backup_dates.append(backup_date)
                    except:
                        continue
                
                if backup_dates:
                    oldest_backup = min(backup_dates)
                    newest_backup = max(backup_dates)
                else:
                    oldest_backup = newest_backup = None
            else:
                oldest_backup = newest_backup = None
            
            # Generate report
            report_path = os.path.join(self.backup_dir, "backup_report.txt")
            with open(report_path, 'w') as f:
                f.write(f"BACKUP SYSTEM REPORT\n")
                f.write(f"Generated: {self.today.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"=" * 50 + "\n\n")
                f.write(f"Retention Policy: {RETENTION_DAYS} days\n")
                f.write(f"Total Backups: {backup_count}\n")
                f.write(f"Total Size: {total_size_gb:.2f} GB\n")
                if oldest_backup:
                    f.write(f"Oldest Backup: {oldest_backup.strftime('%Y-%m-%d')}\n")
                if newest_backup:
                    f.write(f"Newest Backup: {newest_backup.strftime('%Y-%m-%d')}\n")
                f.write(f"\nBackup Directory: {self.backup_dir}\n")
                f.write(f"Application Directory: {APP_DIR}\n")
                f.write(f"Database File: {DATABASE_FILE}\n")
            
            logging.info(f"📋 Backup report saved: {report_path}")
            logging.info(f"📊 Backup Summary: {backup_count} backups, {total_size_gb:.2f} GB total")
            
        except Exception as e:
            logging.error(f"❌ Report generation failed: {str(e)}")

def main():
    """Main backup function"""
    print("🔄 Daily Backup System Starting...")
    print("=" * 50)
    
    backup_manager = BackupManager()
    success = backup_manager.create_daily_backup()
    
    if success:
        print("✅ Backup completed successfully!")
        return 0
    else:
        print("❌ Backup failed!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
