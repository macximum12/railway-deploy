import requests

s = requests.Session()
print("Testing login with hashed passwords...")
r = s.post('http://127.0.0.1:5000/login', 
           data={'username': 'admin', 'password': 'admin'}, 
           timeout=10, allow_redirects=False)

print(f"Status: {r.status_code}")
if r.status_code == 302:
    print("✅ LOGIN SUCCESS - Password hashing works!")
    location = r.headers.get('Location', 'Unknown')
    print(f"Redirected to: {location}")
elif r.status_code == 200:
    if "Invalid username or password" in r.text:
        print("❌ LOGIN FAILED - Incorrect credentials")
    elif "Account locked" in r.text:
        print("⚠️ LOGIN BLOCKED - Account locked")
    elif "login" in r.text.lower():
        print("🔄 STILL ON LOGIN PAGE - Check credentials or errors")
    else:
        print("❓ UNKNOWN RESPONSE")
    
    # Check for specific error messages
    if "error" in r.text.lower():
        import re
        errors = re.findall(r'<[^>]*error[^>]*>([^<]+)', r.text, re.IGNORECASE)
        if errors:
            print(f"Error messages found: {errors}")
else:
    print(f"Unexpected status: {r.status_code}")
