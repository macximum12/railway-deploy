#!/usr/bin/env python3
"""
Test Temporary Password Generation with Proper CSRF Token
"""
import requests
import sqlite3
from datetime import datetime
import re

def test_temp_password_with_csrf():
    print("🔑 TESTING TEMPORARY PASSWORD WITH CSRF")
    print("=" * 50)
    
    session = requests.Session()
    
    try:
        # 1. Login as admin
        print("1. Logging in as admin...")
        
        # Get login page first to get any CSRF token
        login_page = session.get('http://127.0.0.1:5000/login')
        if login_page.status_code != 200:
            print("❌ Cannot access login page")
            return
            
        # Login
        login_response = session.post('http://127.0.0.1:5000/login',
                                    data={'username': 'admin', 'password': 'admin'},
                                    allow_redirects=True)
        
        if login_response.status_code != 200 or 'login' in login_response.url.lower():
            print("❌ Admin login failed")
            print(f"Response status: {login_response.status_code}")
            print(f"URL: {login_response.url}")
            return
        print("   ✅ Admin login successful")
        
        # 2. Get user management page and extract CSRF token
        print("\n2. Getting user management page with CSRF token...")
        users_response = session.get('http://127.0.0.1:5000/admin/users')
        if users_response.status_code == 200:
            print("   ✅ User management page accessible")
            if 'Reset Password' in users_response.text:
                print("   ✅ Reset Password button found in UI")
            
            # Extract CSRF token from the page
            csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', users_response.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                print(f"   ✅ CSRF token extracted: {csrf_token[:20]}...")
                
                # 3. Test password reset with CSRF token
                print("\n3. Testing password reset with CSRF token...")
                reset_data = {'csrf_token': csrf_token}
                reset_response = session.post(f'http://127.0.0.1:5000/admin/users/testuser/reset-password',
                                            data=reset_data,
                                            allow_redirects=True)
                
                if reset_response.status_code == 200:
                    print("   ✅ Password reset request successful")
                    if 'Temporary password' in reset_response.text and 'testuser' in reset_response.text:
                        print("   ✅ Temporary password generated and displayed")
                        
                        # Try to extract the password from the response
                        password_match = re.search(r'testuser.*?<strong>([^<]+)</strong>', reset_response.text)
                        if password_match:
                            temp_password = password_match.group(1)
                            print(f"   📋 Generated password: {temp_password}")
                            
                            # 4. Test if user is now forced to change password
                            print("\n4. Testing forced password change...")
                            test_session = requests.Session()
                            test_login = test_session.post('http://127.0.0.1:5000/login',
                                                         data={'username': 'testuser', 'password': temp_password},
                                                         allow_redirects=True)
                            
                            if test_login.status_code == 200:
                                if 'force_password_change' in test_login.url or 'Force Password Change' in test_login.text:
                                    print("   ✅ User correctly redirected to force password change")
                                elif 'Password Change Required' in test_login.text:
                                    print("   ✅ User sees password change required message")
                                else:
                                    print("   ⚠️  User may not have been redirected to password change")
                                    print(f"   URL: {test_login.url}")
                            else:
                                print(f"   ❌ Test user login failed: {test_login.status_code}")
                        else:
                            print("   ⚠️  Could not extract temporary password from response")
                    else:
                        print("   ⚠️  Temporary password not found in response")
                        print("   Response preview:", reset_response.text[:500])
                else:
                    print(f"   ❌ Password reset failed: {reset_response.status_code}")
                    print("   Response preview:", reset_response.text[:500])
            else:
                print("   ❌ CSRF token not found in page")
                print("   Preview of page:", users_response.text[:1000])
        else:
            print(f"   ❌ Cannot access user management page: {users_response.status_code}")
        
        # 5. Check database state
        print("\n5. Checking database state...")
        conn = sqlite3.connect('audit_findings.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, must_change_password, temp_password, updated_at FROM users WHERE username = 'testuser'")
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            username, must_change, is_temp, updated_at = user_data
            print(f"   User: {username}")
            print(f"   Must change password: {bool(must_change)} ✅" if must_change else f"   Must change password: {bool(must_change)} ❌")
            print(f"   Temporary password: {bool(is_temp)} ✅" if is_temp else f"   Temporary password: {bool(is_temp)} ❌")
            print(f"   Last updated: {updated_at}")
        
        print(f"\n🎉 TEMPORARY PASSWORD TEST COMPLETE!")
        
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_temp_password_with_csrf()
