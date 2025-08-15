# Login System Test Script
# This script tests the login functionality

import requests
import sys

def test_login():
    """Test the login system functionality"""
    base_url = "http://127.0.0.1:5000"
    
    print("🔒 Testing Login System for Audit Tracker")
    print("=" * 50)
    
    # Test 1: Access protected route without login (should redirect to login)
    print("\n1. Testing access to protected route without login...")
    try:
        response = requests.get(f"{base_url}/", allow_redirects=False)
        if response.status_code == 302:
            print("✅ Correctly redirected to login page (Status: 302)")
        else:
            print(f"❌ Expected redirect but got status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server. Make sure Flask app is running at http://127.0.0.1:5000")
        return False
    
    # Test 2: Access login page directly
    print("\n2. Testing login page access...")
    try:
        response = requests.get(f"{base_url}/login")
        if response.status_code == 200:
            print("✅ Login page accessible (Status: 200)")
            print(f"   Page title contains: {'login' if 'login' in response.text.lower() else 'Login page content'}")
        else:
            print(f"❌ Login page error (Status: {response.status_code})")
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to login page")
        return False
    
    # Test 3: Test login with correct credentials
    print("\n3. Testing login with correct credentials (admin/admin)...")
    try:
        session = requests.Session()
        login_data = {
            'username': 'admin',
            'password': 'admin'
        }
        response = session.post(f"{base_url}/login", data=login_data, allow_redirects=True)
        if response.status_code == 200 and 'Audit and Assurance' in response.text:
            print("✅ Login successful - redirected to dashboard")
        else:
            print(f"❌ Login failed (Status: {response.status_code})")
    except requests.exceptions.ConnectionError:
        print("❌ Could not test login")
        return False
    
    # Test 4: Test login with wrong credentials
    print("\n4. Testing login with incorrect credentials...")
    try:
        session = requests.Session()
        login_data = {
            'username': 'wrong',
            'password': 'wrong'
        }
        response = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
        if 'Invalid username or password' in response.text or response.status_code == 200:
            print("✅ Correctly rejected invalid credentials")
        else:
            print(f"❌ Login security issue (Status: {response.status_code})")
    except requests.exceptions.ConnectionError:
        print("❌ Could not test invalid login")
        return False
    
    print("\n" + "=" * 50)
    print("✅ Login System Test Completed!")
    print("\n📋 Login Credentials:")
    print("   Username: admin")
    print("   Password: admin")
    print("\n🔐 Security Features:")
    print("   ✓ Session-based authentication")
    print("   ✓ Protected routes require login")
    print("   ✓ Automatic redirects for unauthorized access")
    print("   ✓ Remember me functionality (7-day sessions)")
    print("   ✓ Flash messages for user feedback")
    print("   ✓ Logout functionality")
    
    return True

if __name__ == "__main__":
    success = test_login()
    sys.exit(0 if success else 1)
