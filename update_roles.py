#!/usr/bin/env python3
"""
Update user roles in database
"""

import sqlite3

def update_user_roles():
    # Connect and update database
    conn = sqlite3.connect('audit_findings.db')
    cursor = conn.cursor()
    
    print('Current users:')
    users = cursor.execute('SELECT username, role FROM users').fetchall()
    for user in users:
        print(f'  {user[0]}: {user[1]}')
    
    print('\nUpdating roles...')
    # Assign admin -> Administrator
    cursor.execute('UPDATE users SET role = ? WHERE username = ?', ('Administrator', 'admin'))
    # Assign test01 -> Content Manager  
    cursor.execute('UPDATE users SET role = ? WHERE username = ?', ('Content Manager', 'test01'))
    
    conn.commit()
    
    print('\nUpdated users:')
    users = cursor.execute('SELECT username, role FROM users').fetchall()
    for user in users:
        print(f'  {user[0]}: {user[1]}')
    
    conn.close()
    print('\n✅ Database roles updated!')

if __name__ == "__main__":
    update_user_roles()
