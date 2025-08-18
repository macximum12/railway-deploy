#!/usr/bin/env python3
"""
Test Admin User Management Visibility
"""
import requests
import sqlite3

def test_admin_user_management():
    print("🔍 TESTING ADMIN USER MANAGEMENT")
    print("=" * 40)
    
    # First check database to confirm admin user role
    print("1. Checking database for admin user role...")
    try:
        conn = sqlite3.connect('audit_findings.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, role FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        conn.close()
        
        if admin_user:
            print(f"   Admin user found: {admin_user[0]} with role: {admin_user[1]}")
            if admin_user[1] == 'Administrator':
                print("   ✅ Admin role is correctly set to 'Administrator'")
            else:
                print(f"   ❌ Admin role is '{admin_user[1]}', should be 'Administrator'")
        else:
            print("   ❌ Admin user not found in database")
    except Exception as e:
        print(f"   ❌ Database error: {e}")
    
    # Test login and check navigation
    print("\n2. Testing login and navigation visibility...")
    session = requests.Session()
    
    try:
        # Login as admin
        login_response = session.post('http://127.0.0.1:5000/login',
                                    data={'username': 'admin', 'password': 'admin'},
                                    allow_redirects=True)
        
        if login_response.status_code == 200:
            print("   ✅ Login successful")
            
            # Check if user management link is present
            if 'manage_users' in login_response.text or '/admin/users' in login_response.text:
                print("   ✅ User management link found in navigation")
            else:
                print("   ❌ User management link NOT found in navigation")
            
            # Check if Users button is visible
            if 'Users</span>' in login_response.text:
                print("   ✅ Users button visible")
            else:
                print("   ⚠️  Users button may not be visible")
            
            # Check role display
            if 'Administrator</span>' in login_response.text:
                print("   ✅ Administrator role displayed correctly")
            else:
                print("   ⚠️  Administrator role may not be displaying")
                
        else:
            print(f"   ❌ Login failed: {login_response.status_code}")
            return
        
        # Test direct access to user management
        print("\n3. Testing direct access to user management...")
        users_response = session.get('http://127.0.0.1:5000/admin/users')
        
        if users_response.status_code == 200:
            print("   ✅ User management page accessible")
            if 'Manage Users' in users_response.text:
                print("   ✅ User management page loaded correctly")
        else:
            print(f"   ❌ User management page not accessible: {users_response.status_code}")
        
        print(f"\n🎉 ADMIN USER MANAGEMENT TEST COMPLETE!")
        
    except Exception as e:
        print(f"❌ Test error: {e}")

if __name__ == "__main__":
    test_admin_user_management()
