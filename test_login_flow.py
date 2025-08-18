#!/usr/bin/env python3
"""
Test Login/Logout Flow to Verify Fix
"""
import requests

def test_login_logout_flow():
    print("🔄 TESTING LOGIN/LOGOUT FLOW")
    print("=" * 40)
    
    session = requests.Session()
    
    try:
        # Test 1: Check login page loads correctly
        print("1. Testing login page loading...")
        login_response = session.get('http://127.0.0.1:5000/login')
        
        if login_response.status_code == 200:
            # Check for duplicate content
            audit_tracker_count = login_response.text.count('Audit Tracker')
            form_count = login_response.text.count('<form')
            
            print(f"   Login page status: ✅ 200 OK")
            print(f"   'Audit Tracker' occurrences: {audit_tracker_count}")
            print(f"   Form count: {form_count}")
            
            if audit_tracker_count == 1 and form_count == 1:
                print("   ✅ No duplicate content detected")
            else:
                print("   ❌ Duplicate content still present")
        else:
            print(f"   ❌ Login page failed to load: {login_response.status_code}")
            return
        
        # Test 2: Login
        print("\n2. Testing login...")
        login_post = session.post('http://127.0.0.1:5000/login',
                                data={'username': 'admin', 'password': 'admin'},
                                allow_redirects=False)
        
        if login_post.status_code == 302:
            print("   ✅ Login successful")
        else:
            print(f"   ❌ Login failed: {login_post.status_code}")
            return
        
        # Test 3: Access dashboard
        print("3. Testing dashboard access...")
        dashboard = session.get('http://127.0.0.1:5000/')
        
        if dashboard.status_code == 200:
            print("   ✅ Dashboard accessible")
        else:
            print(f"   ⚠️  Dashboard status: {dashboard.status_code}")
        
        # Test 4: Logout
        print("4. Testing logout...")
        logout = session.get('http://127.0.0.1:5000/logout', allow_redirects=False)
        
        if logout.status_code == 302:
            print("   ✅ Logout successful")
        else:
            print(f"   ⚠️  Logout status: {logout.status_code}")
        
        # Test 5: Check login page after logout
        print("5. Testing login page after logout...")
        login_after_logout = session.get('http://127.0.0.1:5000/login')
        
        if login_after_logout.status_code == 200:
            audit_tracker_count = login_after_logout.text.count('Audit Tracker')
            form_count = login_after_logout.text.count('<form')
            
            print(f"   Login page status: ✅ 200 OK")
            print(f"   'Audit Tracker' occurrences: {audit_tracker_count}")
            print(f"   Form count: {form_count}")
            
            if audit_tracker_count == 1 and form_count == 1:
                print("   ✅ LOGIN PAGE FIXED - No duplicate content!")
            else:
                print("   ❌ Duplicate content still present")
        
        print(f"\n🎉 LOGIN/LOGOUT FLOW TEST COMPLETE!")
        
    except Exception as e:
        print(f"❌ Test error: {e}")

if __name__ == "__main__":
    test_login_logout_flow()
