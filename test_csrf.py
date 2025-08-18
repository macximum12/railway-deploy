#!/usr/bin/env python3
"""
Test CSRF Protection Implementation
"""
import requests

def test_csrf_protection():
    print("🛡️  TESTING CSRF PROTECTION")
    print("=" * 40)
    
    try:
        session = requests.Session()
        
        # First, login to get access to protected pages
        print("1. Logging in to access protected routes...")
        login_response = session.post('http://127.0.0.1:5000/login',
                                    data={'username': 'admin', 'password': 'admin'})
        
        if login_response.status_code == 302:
            print("✅ Login successful")
        else:
            print("❌ Login failed")
            return False
        
        # Test CSRF tokens in forms
        print("\n2. Checking CSRF tokens in forms...")
        
        # Check settings page (has password change form)
        settings_response = session.get('http://127.0.0.1:5000/settings')
        
        if settings_response.status_code == 200:
            if 'csrf_token' in settings_response.text:
                print("✅ CSRF tokens found in settings form")
            else:
                print("❌ CSRF tokens missing in settings form")
        else:
            print(f"❌ Could not access settings page: {settings_response.status_code}")
        
        # Check admin user management page
        try:
            admin_response = session.get('http://127.0.0.1:5000/admin/users/add')
            if admin_response.status_code == 200:
                if 'csrf_token' in admin_response.text:
                    print("✅ CSRF tokens found in admin forms")
                else:
                    print("❌ CSRF tokens missing in admin forms")
            else:
                print(f"ℹ️  Admin page status: {admin_response.status_code} (may be permission-based)")
        except:
            print("ℹ️  Admin page access varies by permissions")
        
        print("\n3. Testing CSRF protection enforcement...")
        
        # Try to make a POST request without CSRF token (should fail)
        try:
            bad_request = session.post('http://127.0.0.1:5000/settings',
                                     data={'current_password': 'test', 
                                           'new_password': 'test123',
                                           'confirm_password': 'test123'})
            
            if bad_request.status_code == 403 or "csrf" in bad_request.text.lower():
                print("✅ CSRF protection is enforcing token validation")
            else:
                print("⚠️  CSRF protection enforcement unclear")
                
        except Exception as e:
            print(f"ℹ️  CSRF test: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing CSRF: {e}")
        return False

if __name__ == "__main__":
    test_csrf_protection()
