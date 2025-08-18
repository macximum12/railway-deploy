#!/usr/bin/env python3
"""
Test Security Headers Implementation
"""
import requests

def test_security_headers():
    print("🛡️  TESTING SECURITY HEADERS")
    print("=" * 40)
    
    try:
        response = requests.get('http://127.0.0.1:5000/login', timeout=10)
        
        # Expected security headers
        expected_headers = {
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'X-XSS-Protection': 'XSS Filter Protection', 
            'Content-Security-Policy': 'Content Security Policy',
            'Referrer-Policy': 'Referrer Policy'
        }
        
        print(f"Response Status: {response.status_code}")
        print("\nSecurity Headers Check:")
        
        all_present = True
        for header, description in expected_headers.items():
            if header in response.headers:
                value = response.headers[header]
                print(f"✅ {header}: {value}")
            else:
                print(f"❌ {header}: MISSING")
                all_present = False
        
        # Check for HTTPS-specific headers (won't be present in HTTP)
        if 'Strict-Transport-Security' in response.headers:
            print(f"✅ Strict-Transport-Security: {response.headers['Strict-Transport-Security']}")
        else:
            print("ℹ️  Strict-Transport-Security: Not present (expected for HTTP)")
        
        print(f"\nOverall Security Headers: {'✅ ALL PRESENT' if all_present else '❌ SOME MISSING'}")
        
        return all_present
        
    except Exception as e:
        print(f"❌ Error testing headers: {e}")
        return False

if __name__ == "__main__":
    test_security_headers()
