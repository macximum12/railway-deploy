import requests

s = requests.Session()
print("Testing login with hashed passwords...")
r = s.post('http://127.0.0.1:5000/login', 
           data={'username': 'admin', 'password': 'admin'}, 
           timeout=10)

print(f"Status: {r.status_code}")
if r.status_code == 302:
    print("✅ LOGIN SUCCESS - Password hashing works!")
    print(f"Redirected to: {r.headers.get('Location', 'Unknown')}")
elif "Invalid username or password" in r.text:
    print("❌ LOGIN FAILED - Check password hashing")
else:
    print(f"Response: {r.text[:100]}...")
