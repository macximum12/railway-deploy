#!/usr/bin/env python3
"""
Fix database roles
"""

import sqlite3
from datetime import datetime

def fix_roles():
    # Connect to database
    conn = sqlite3.connect('audit_findings.db')
    cursor = conn.cursor()
    
    print('Before update:')
    users = cursor.execute('SELECT username, role FROM users').fetchall()
    for user in users:
        print(f'  {user[0]}: {user[1]}')
    
    # Update roles
    cursor.execute('UPDATE users SET role = ? WHERE username = ? AND role = ?', ('Administrator', 'admin', 'admin'))
    cursor.execute('UPDATE users SET role = ? WHERE username = ? AND role = ?', ('Content Manager', 'test01', 'editor'))
    
    conn.commit()
    
    print('\nAfter update:')
    users = cursor.execute('SELECT username, role FROM users').fetchall()
    for user in users:
        print(f'  {user[0]}: {user[1]}')
    
    conn.close()
    print('\n✅ Database updated successfully!')

if __name__ == "__main__":
    fix_roles()
