#!/usr/bin/env python3
"""
Test UI and CSS Loading
"""
import requests

def test_ui_loading():
    print("🎨 TESTING UI AND CSS LOADING")
    print("=" * 40)
    
    try:
        # Test main login page
        response = requests.get('http://127.0.0.1:5000/login', timeout=10)
        
        print(f"Login Page Status: {response.status_code}")
        
        if response.status_code == 200:
            # Check for Tailwind CSS indicators
            if 'tailwindcss.com' in response.text:
                print("✅ Tailwind CSS script tag found")
            else:
                print("❌ Tailwind CSS script tag missing")
            
            # Check for basic styling elements
            styling_indicators = [
                'class="',  # CSS classes present
                'tailwind.config',  # Tailwind config
                'bg-',  # Background classes
                'text-',  # Text classes
            ]
            
            found_styling = 0
            for indicator in styling_indicators:
                if indicator in response.text:
                    found_styling += 1
            
            print(f"Styling indicators found: {found_styling}/{len(styling_indicators)}")
            
            # Check for specific CSS framework elements
            if 'animate-' in response.text or 'transition' in response.text:
                print("✅ Animation/transition classes detected")
            else:
                print("⚠️  Limited animation classes detected")
            
            # Check security headers are still present
            headers_check = [
                'X-Frame-Options',
                'Content-Security-Policy',
                'X-Content-Type-Options'
            ]
            
            headers_present = 0
            for header in headers_check:
                if header in response.headers:
                    headers_present += 1
            
            print(f"Security headers present: {headers_present}/{len(headers_check)}")
            
            if headers_present == len(headers_check) and found_styling >= 3:
                print("✅ UI LOADING SUCCESS - Security headers + styling working")
            elif headers_present == len(headers_check):
                print("⚠️  Security headers working, styling may have issues")
            else:
                print("❌ Issues detected")
        
        else:
            print(f"❌ Failed to load login page: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing UI: {e}")

if __name__ == "__main__":
    test_ui_loading()
