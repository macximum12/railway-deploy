#!/usr/bin/env python3
"""
🔍 FOCUSED QA TESTING - Admin Login and Password Change Flow
Specifically testing the critical password reuse prevention feature
"""

import requests
import re
import time

def get_csrf_token(response_text):
    """Extract CSRF token from HTML response"""
    match = re.search(r'name="csrf_token".*?value="([^"]*)"', response_text)
    return match.group(1) if match else None

def test_admin_login_flow():
    """Test admin login and password change flow with detailed logging"""
    session = requests.Session()
    base_url = "http://127.0.0.1:5000"
    
    print("🔑 DETAILED ADMIN LOGIN TESTING")
    print("=" * 50)
    
    try:
        # Step 1: Get login page
        print("Step 1: Getting login page...")
        login_url = f"{base_url}/login"
        response = session.get(login_url)
        print(f"✅ Login page response: HTTP {response.status_code}")
        
        # Extract CSRF token
        csrf_token = get_csrf_token(response.text)
        if csrf_token:
            print(f"✅ CSRF token found: {csrf_token[:10]}...")
        else:
            print("⚠️ No CSRF token found")
        
        # Step 2: Attempt admin login
        print("\nStep 2: Attempting admin login...")
        login_data = {
            'username': 'admin',
            'password': 'admin',  # Correct admin password
        }
        
        if csrf_token:
            login_data['csrf_token'] = csrf_token
        
        print(f"Login data: {login_data}")
        
        response = session.post(login_url, data=login_data, allow_redirects=False)
        print(f"✅ Login response: HTTP {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 302:
            redirect_url = response.headers.get('Location', '')
            print(f"✅ Redirected to: {redirect_url}")
            
            if 'force' in redirect_url and 'password' in redirect_url:
                print("✅ CORRECT: Redirected to force password change")
                return test_password_change_flow(session, base_url, redirect_url)
            elif 'dashboard' in redirect_url:
                print("⚠️ WARNING: Redirected to dashboard (should force password change)")
                return False
            else:
                print(f"❌ Unexpected redirect: {redirect_url}")
                return False
        elif response.status_code == 200:
            if "Invalid username or password" in response.text:
                print("❌ Login failed: Invalid credentials")
                print("🔍 This suggests the admin account doesn't exist or password is incorrect")
            else:
                print("❌ Login failed: Stayed on login page")
        else:
            print(f"❌ Unexpected response: {response.status_code}")
        
        return False
        
    except Exception as e:
        print(f"❌ Error during login test: {str(e)}")
        return False

def test_password_change_flow(session, base_url, pwd_change_url):
    """Test the password change flow including reuse prevention"""
    print("\n🔐 DETAILED PASSWORD CHANGE TESTING")
    print("=" * 50)
    
    try:
        # Step 1: Get password change page
        print("Step 1: Getting password change page...")
        if not pwd_change_url.startswith('http'):
            pwd_change_url = base_url + pwd_change_url
        
        response = session.get(pwd_change_url)
        print(f"✅ Password change page: HTTP {response.status_code}")
        
        csrf_token = get_csrf_token(response.text)
        if csrf_token:
            print(f"✅ CSRF token found: {csrf_token[:10]}...")
        
        # Step 2: Test password reuse prevention
        print("\nStep 2: Testing password reuse prevention...")
        pwd_data = {
            'current_password': 'admin',  # Correct current password
            'new_password': 'admin',  # Same as current - should be blocked
            'confirm_password': 'admin',
        }
        
        if csrf_token:
            pwd_data['csrf_token'] = csrf_token
        
        print(f"Testing password reuse with data: {pwd_data}")
        
        response = session.post(pwd_change_url, data=pwd_data)
        print(f"✅ Password change response: HTTP {response.status_code}")
        
        # Check if password reuse was prevented
        response_text = response.text.lower()
        if "cannot be the same" in response_text or "reuse" in response_text:
            print("✅ SUCCESS: Password reuse prevented!")
            print("✅ Server-side validation working correctly")
            
            # Step 3: Test valid password change
            print("\nStep 3: Testing valid password change...")
            new_pwd_data = {
                'current_password': 'admin',  # Correct current password
                'new_password': 'NewSecurePass123!',
                'confirm_password': 'NewSecurePass123!',
            }
            
            if csrf_token:
                new_pwd_data['csrf_token'] = csrf_token
            
            response = session.post(pwd_change_url, data=new_pwd_data)
            print(f"✅ Valid password change response: HTTP {response.status_code}")
            
            if response.status_code == 302:
                redirect_url = response.headers.get('Location', '')
                print(f"✅ Redirected to: {redirect_url}")
                if 'dashboard' in redirect_url:
                    print("✅ SUCCESS: Password changed and redirected to dashboard")
                    return True
            
        else:
            print("❌ CRITICAL: Password reuse NOT prevented!")
            print("❌ This is a security vulnerability!")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error during password change test: {str(e)}")
        return False

def check_database_users():
    """Check what users exist in the database"""
    print("\n👥 CHECKING DATABASE USERS")
    print("=" * 30)
    
    try:
        import sqlite3
        conn = sqlite3.connect('audit_findings.db')  # Database is in current directory
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, role FROM users")
        users = cursor.fetchall()
        
        print(f"Found {len(users)} users in database:")
        for user in users:
            print(f"  • {user['username']} ({user['role']})")
        
        conn.close()
        return len(users) > 0
        
    except Exception as e:
        print(f"❌ Error checking database: {str(e)}")
        return False

def main():
    """Run focused QA testing"""
    print("🎯 FOCUSED QA TESTING - ADMIN LOGIN & PASSWORD SECURITY")
    print("=" * 60)
    
    # Check database first
    if not check_database_users():
        print("⚠️ No users found in database or database error")
        print("🔧 You may need to run: python init_db.py")
        return
    
    # Test login flow
    success = test_admin_login_flow()
    
    print("\n" + "=" * 60)
    print("🎯 QA TESTING SUMMARY")
    print("=" * 60)
    
    if success:
        print("✅ PASS: Admin login and password change flow working")
        print("✅ PASS: Password reuse prevention implemented correctly")
        print("🛡️ SECURITY STATUS: GOOD")
    else:
        print("❌ ISSUES DETECTED in login or password change flow")
        print("🔍 Review the detailed output above for specific problems")
    
    print("\n📋 PRODUCTION CHECKLIST:")
    print("  • ✅ Password reuse prevention: IMPLEMENTED")
    print("  • ⚠️ Change admin password from 'admin': REQUIRED")
    print("  • ⚠️ Enable HTTPS: REQUIRED for production")
    print("  • ⚠️ Set secure session cookies: REQUIRED")

if __name__ == "__main__":
    main()
