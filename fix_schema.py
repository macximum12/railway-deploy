#!/usr/bin/env python3
"""
Fix database schema and update user roles
"""

import sqlite3

def fix_database_schema():
    # Connect to database
    conn = sqlite3.connect('audit_findings.db')
    cursor = conn.cursor()
    
    print('Current users:')
    users = cursor.execute('SELECT username, role FROM users').fetchall()
    for user in users:
        print(f'  {user[0]}: {user[1]}')
    
    print('\nFixing database schema...')
    
    # Create new users table without role constraints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users_new (
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
    ''')
    
    # Copy data to new table with updated roles
    cursor.execute('''
        INSERT INTO users_new (id, username, password, role, created_at, updated_at, is_active, must_change_password, temp_password, created_by)
        SELECT id, username, password,
               CASE 
                   WHEN role = 'admin' THEN 'Administrator'
                   WHEN role = 'editor' THEN 'Content Manager' 
                   WHEN role = 'viewer' THEN 'Viewer'
                   ELSE role
               END as role,
               created_at, updated_at, is_active, must_change_password, temp_password, created_by
        FROM users
    ''')
    
    # Drop old table and rename new one
    cursor.execute('DROP TABLE users')
    cursor.execute('ALTER TABLE users_new RENAME TO users')
    
    conn.commit()
    
    print('\nUpdated users:')
    users = cursor.execute('SELECT username, role FROM users').fetchall()
    for user in users:
        print(f'  {user[0]}: {user[1]}')
    
    conn.close()
    print('\n✅ Database schema fixed and roles updated!')

if __name__ == "__main__":
    fix_database_schema()
