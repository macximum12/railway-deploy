#!/usr/bin/env python3
"""
Test Temporary Password Generation Feature
"""
import requests
import sqlite3
from datetime import datetime

def test_temp_password_feature():
    print("🔑 TESTING TEMPORARY PASSWORD GENERATION")
    print("=" * 50)
    
    session = requests.Session()
    
    try:
        # 1. Login as admin
        print("1. Logging in as admin...")
        login_response = session.post('http://127.0.0.1:5000/login',
                                    data={'username': 'admin', 'password': 'admin'},
                                    allow_redirects=True)
        
        if login_response.status_code != 200:
            print("❌ Admin login failed")
            return
        print("   ✅ Admin login successful")
        
        # 2. Check current user list
        print("\n2. Checking current users...")
        users_response = session.get('http://127.0.0.1:5000/admin/users')
        if users_response.status_code == 200:
            print("   ✅ User management page accessible")
            if 'Reset Password' in users_response.text:
                print("   ✅ Reset Password button found in UI")
            else:
                print("   ⚠️  Reset Password button not visible")
        
        # 3. Test password reset for testuser
        print("\n3. Testing password reset for testuser...")
        reset_response = session.post('http://127.0.0.1:5000/admin/users/testuser/reset-password',
                                    allow_redirects=True)
        
        if reset_response.status_code == 200:
            print("   ✅ Password reset request successful")
            if 'Temporary password' in reset_response.text and 'testuser' in reset_response.text:
                print("   ✅ Temporary password generated and displayed")
                # Try to extract the password from the response
                import re
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
                        else:
                            print("   ⚠️  User may not have been redirected to password change")
                    else:
                        print(f"   ❌ Test user login failed: {test_login.status_code}")
            else:
                print("   ⚠️  Temporary password not found in response")
        else:
            print(f"   ❌ Password reset failed: {reset_response.status_code}")
        
        # 5. Check database state
        print("\n5. Checking database state...")
        conn = sqlite3.connect('audit_findings.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, must_change_password, temp_password FROM users WHERE username = 'testuser'")
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            username, must_change, is_temp = user_data
            print(f"   User: {username}")
            print(f"   Must change password: {bool(must_change)} ✅" if must_change else f"   Must change password: {bool(must_change)} ❌")
            print(f"   Temporary password: {bool(is_temp)} ✅" if is_temp else f"   Temporary password: {bool(is_temp)} ❌")
        
        print(f"\n🎉 TEMPORARY PASSWORD TEST COMPLETE!")
        
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_temp_password_feature()
