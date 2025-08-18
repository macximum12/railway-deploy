#!/usr/bin/env python3
"""
Password Migration Script
Migrates all plain text passwords to bcrypt hashes
"""

import sqlite3
import bcrypt
from datetime import datetime

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def is_already_hashed(password):
    """Check if password is already hashed"""
    return password.startswith('$2b$') or password.startswith('$2a$')

def migrate_passwords():
    """Migrate all plain text passwords to hashes"""
    try:
        conn = sqlite3.connect('audit_findings.db')
        cursor = conn.cursor()
        
        # Get all users with their current passwords
        users = cursor.execute('SELECT username, password FROM users').fetchall()
        
        migrations = 0
        for username, password in users:
            if not is_already_hashed(password):
                print(f"Migrating password for user: {username}")
                hashed_password = hash_password(password)
                
                cursor.execute('''
                    UPDATE users 
                    SET password = ?, updated_at = ? 
                    WHERE username = ?
                ''', (hashed_password, datetime.now().isoformat(), username))
                
                migrations += 1
            else:
                print(f"Password already hashed for user: {username}")
        
        conn.commit()
        print(f"\n✅ Successfully migrated {migrations} passwords to bcrypt hashes")
        
        # Verify the migration
        print("\n🔍 Verification - Updated passwords:")
        users_after = cursor.execute('SELECT username, password FROM users').fetchall()
        for username, password in users_after:
            is_hashed = is_already_hashed(password)
            status = "✅ HASHED" if is_hashed else "❌ PLAIN TEXT"
            print(f"  {username}: {status} ({password[:20]}...)")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error migrating passwords: {e}")

if __name__ == "__main__":
    print("🔐 PASSWORD MIGRATION SCRIPT")
    print("=" * 40)
    migrate_passwords()
