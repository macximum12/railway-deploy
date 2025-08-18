#!/usr/bin/env python3
"""
CSS and Styling Verification Test
"""
import requests

def verify_css_styling():
    print("🎨 CSS AND STYLING VERIFICATION")
    print("=" * 40)
    
    try:
        response = requests.get('http://127.0.0.1:5000/login')
        
        if response.status_code != 200:
            print(f"❌ Failed to load page: {response.status_code}")
            return
        
        content = response.text
        
        # Check for CSS/styling indicators
        print("Checking for styling elements:")
        
        checks = [
            ("Tailwind CSS CDN", "cdn.tailwindcss.com" in content),
            ("CSS Classes", 'class="' in content and ('bg-' in content or 'text-' in content)),
            ("Inline Styles", 'style="' in content or '<style>' in content),
            ("Tailwind Config", 'tailwind.config' in content),
            ("Animation Classes", 'animate-' in content or 'transition' in content),
            ("Grid/Flex Layout", 'grid' in content or 'flex' in content),
            ("Color Classes", 'text-blue' in content or 'bg-blue' in content or 'text-white' in content),
            ("Responsive Classes", 'md:' in content or 'lg:' in content or 'sm:' in content),
        ]
        
        passed = 0
        for check_name, result in checks:
            status = "✅" if result else "❌"
            print(f"  {status} {check_name}")
            if result:
                passed += 1
        
        print(f"\nStyling Score: {passed}/{len(checks)} ({passed/len(checks)*100:.1f}%)")
        
        # Check Content Security Policy
        csp = response.headers.get('Content-Security-Policy', '')
        if 'unsafe-inline' in csp and 'https:' in csp:
            print("✅ CSP allows inline styles and HTTPS resources")
        else:
            print("⚠️  CSP may be too restrictive for some styling")
        
        # Overall assessment
        if passed >= 6:
            print("\n✅ CSS STYLING: EXCELLENT - All major styling elements present")
        elif passed >= 4:
            print("\n✅ CSS STYLING: GOOD - Most styling elements working")
        else:
            print("\n⚠️  CSS STYLING: NEEDS ATTENTION - Some styling issues detected")
            
        return passed >= 4
        
    except Exception as e:
        print(f"❌ Error checking styling: {e}")
        return False

if __name__ == "__main__":
    verify_css_styling()
