#!/usr/bin/env python3
"""
Backup Restoration System
Restore application and database from daily backups
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
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_FILE = "audit_findings.db"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('restore.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class RestoreManager:
    def __init__(self):
        self.backup_dir = os.path.join(APP_DIR, BACKUP_BASE_DIR)
        self.restore_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def list_available_backups(self):
        """List all available backup files"""
        backup_pattern = os.path.join(self.backup_dir, "backup_*.zip")
        backup_files = glob.glob(backup_pattern)
        
        backups = []
        for backup_file in backup_files:
            try:
                filename = os.path.basename(backup_file)
                date_str = filename.split('_')[1]
                time_str = filename.split('_')[2].replace('.zip', '')
                backup_date = datetime.datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
                size = os.path.getsize(backup_file)
                
                backups.append({
                    'file': backup_file,
                    'filename': filename,
                    'date': backup_date,
                    'size': size,
                    'size_mb': size / (1024 * 1024)
                })
            except (ValueError, IndexError):
                continue
        
        # Sort by date (newest first)
        backups.sort(key=lambda x: x['date'], reverse=True)
        return backups
    
    def show_backup_menu(self):
        """Show interactive backup selection menu"""
        backups = self.list_available_backups()
        
        if not backups:
            print("❌ No backup files found!")
            return None
        
        print("\n📋 Available Backups:")
        print("=" * 80)
        print(f"{'#':<3} {'Date':<20} {'Time':<10} {'Size (MB)':<12} {'Filename'}")
        print("-" * 80)
        
        for i, backup in enumerate(backups):
            date_str = backup['date'].strftime("%Y-%m-%d")
            time_str = backup['date'].strftime("%H:%M:%S")
            print(f"{i+1:<3} {date_str:<20} {time_str:<10} {backup['size_mb']:<12.2f} {backup['filename']}")
        
        print("-" * 80)
        print("0   Cancel")
        print()
        
        while True:
            try:
                choice = input("Select backup to restore (number): ").strip()
                if choice == '0':
                    return None
                
                choice_num = int(choice) - 1
                if 0 <= choice_num < len(backups):
                    return backups[choice_num]
                else:
                    print("❌ Invalid selection. Please try again.")
            except ValueError:
                print("❌ Please enter a valid number.")
    
    def create_pre_restore_backup(self):
        """Create a backup of current state before restoration"""
        logging.info("🔄 Creating pre-restoration backup...")
        
        try:
            pre_backup_dir = f"pre_restore_backup_{self.restore_timestamp}"
            os.makedirs(pre_backup_dir, exist_ok=True)
            
            # Backup current database
            if os.path.exists(DATABASE_FILE):
                shutil.copy2(DATABASE_FILE, os.path.join(pre_backup_dir, f"current_{DATABASE_FILE}"))
                logging.info(f"✅ Current database backed up")
            
            # Backup critical files
            critical_files = ['app.py', 'requirements.txt', 'config.py']
            for file in critical_files:
                if os.path.exists(file):
                    shutil.copy2(file, pre_backup_dir)
            
            logging.info(f"✅ Pre-restoration backup created: {pre_backup_dir}")
            return pre_backup_dir
            
        except Exception as e:
            logging.error(f"❌ Pre-restoration backup failed: {str(e)}")
            return None
    
    def restore_from_backup(self, backup_info, restore_options):
        """Restore application from selected backup"""
        try:
            logging.info(f"🔄 Starting restoration from {backup_info['filename']}")
            
            # Create pre-restore backup
            if restore_options.get('create_pre_backup', True):
                pre_backup_dir = self.create_pre_restore_backup()
                if not pre_backup_dir:
                    logging.warning("⚠️  Pre-restoration backup failed, continuing anyway...")
            
            # Extract backup archive
            extract_dir = f"restore_temp_{self.restore_timestamp}"
            os.makedirs(extract_dir, exist_ok=True)
            
            logging.info("📦 Extracting backup archive...")
            with zipfile.ZipFile(backup_info['file'], 'r') as zipf:
                zipf.extractall(extract_dir)
            
            # Find the backup directory in extracted files
            backup_content_dir = None
            for item in os.listdir(extract_dir):
                if item.startswith('backup_') and os.path.isdir(os.path.join(extract_dir, item)):
                    backup_content_dir = os.path.join(extract_dir, item)
                    break
            
            if not backup_content_dir:
                raise Exception("Could not find backup content in archive")
            
            # Restore database
            if restore_options.get('restore_database', True):
                self._restore_database(backup_content_dir)
            
            # Restore application files
            if restore_options.get('restore_application', True):
                self._restore_application_files(backup_content_dir)
            
            # Cleanup temporary files
            shutil.rmtree(extract_dir)
            
            logging.info("✅ Restoration completed successfully!")
            return True
            
        except Exception as e:
            logging.error(f"❌ Restoration failed: {str(e)}")
            return False
    
    def _restore_database(self, backup_content_dir):
        """Restore database from backup"""
        logging.info("📊 Restoring database...")
        
        # Find database backup file
        db_files = glob.glob(os.path.join(backup_content_dir, "database_*.db"))
        if not db_files:
            raise Exception("No database backup found in archive")
        
        db_backup_file = db_files[0]  # Use the first one found
        
        # Restore database
        if os.path.exists(DATABASE_FILE):
            backup_current = f"{DATABASE_FILE}.restore_backup"
            shutil.move(DATABASE_FILE, backup_current)
            logging.info(f"📋 Current database backed up to: {backup_current}")
        
        shutil.copy2(db_backup_file, DATABASE_FILE)
        
        # Verify database integrity
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result[0] == "ok":
                logging.info("✅ Database restored and integrity check passed")
            else:
                logging.warning(f"⚠️  Database integrity check failed: {result[0]}")
            conn.close()
        except Exception as e:
            logging.warning(f"⚠️  Could not verify database integrity: {str(e)}")
    
    def _restore_application_files(self, backup_content_dir):
        """Restore application files from backup"""
        logging.info("📁 Restoring application files...")
        
        app_backup_dir = os.path.join(backup_content_dir, "application")
        if not os.path.exists(app_backup_dir):
            raise Exception("No application backup found in archive")
        
        restored_count = 0
        
        # Restore files
        for root, dirs, files in os.walk(app_backup_dir):
            for file in files:
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, app_backup_dir)
                dest_path = os.path.join(APP_DIR, rel_path)
                
                # Create destination directory if needed
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                # Backup existing file if it exists
                if os.path.exists(dest_path):
                    backup_path = f"{dest_path}.restore_backup"
                    shutil.copy2(dest_path, backup_path)
                
                # Copy restored file
                shutil.copy2(src_path, dest_path)
                restored_count += 1
        
        logging.info(f"✅ Application files restored: {restored_count} files")

def main():
    """Main restoration function"""
    print("🔄 Backup Restoration System")
    print("=" * 50)
    
    restore_manager = RestoreManager()
    
    # Show available backups
    selected_backup = restore_manager.show_backup_menu()
    if not selected_backup:
        print("Operation cancelled.")
        return 0
    
    print(f"\n📋 Selected backup: {selected_backup['filename']}")
    print(f"   Date: {selected_backup['date'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Size: {selected_backup['size_mb']:.2f} MB")
    
    # Restoration options
    print("\n⚙️  Restoration Options:")
    restore_database = input("Restore database? (Y/n): ").lower() not in ['n', 'no']
    restore_application = input("Restore application files? (Y/n): ").lower() not in ['n', 'no']
    create_pre_backup = input("Create pre-restoration backup? (Y/n): ").lower() not in ['n', 'no']
    
    restore_options = {
        'restore_database': restore_database,
        'restore_application': restore_application,
        'create_pre_backup': create_pre_backup
    }
    
    # Confirmation
    print(f"\n⚠️  WARNING: This will overwrite current files!")
    if restore_options['create_pre_backup']:
        print("   (Current state will be backed up first)")
    
    confirm = input("\nProceed with restoration? (y/N): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return 0
    
    # Perform restoration
    print("\n🔄 Starting restoration...")
    success = restore_manager.restore_from_backup(selected_backup, restore_options)
    
    if success:
        print("✅ Restoration completed successfully!")
        print("\n💡 Next steps:")
        print("   1. Restart the application")
        print("   2. Test all functionality")
        print("   3. Check restore.log for details")
        return 0
    else:
        print("❌ Restoration failed!")
        print("   Check restore.log for details")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
