#!/usr/bin/env python3

import requests
import re
import json
from urllib.parse import urljoin
from datetime import datetime

def extract_versions(url):
    """
    Extract version information from JavaScript files on the page.
    """
    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'versions': [],
        'files_checked': []
    }
    
    try:
        # Get the main page
        resp = requests.get(url)
        
        # Find all JavaScript files
        js_files = re.findall(r'src="([^"]+\.js)"', resp.text)
        
        for js_file in js_files:
            full_url = urljoin(url, js_file)
            results['files_checked'].append(full_url)
            
            try:
                js_content = requests.get(full_url).text
                
                # Look for version patterns
                version_patterns = [
                    (r'version["\']?\s*[:=]\s*["\']([^"\']+)', 'Generic Version'),
                    (r'react@([0-9.]+)', 'React'),
                    (r'next@([0-9.]+)', 'Next.js'),
                    (r'node@([0-9.]+)', 'Node.js')
                ]
                
                for pattern, name in version_patterns:
                    matches = re.finditer(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        results['versions'].append({
                            'component': name,
                            'version': match.group(1),
                            'file': js_file
                        })
                        
            except Exception as e:
                print(f"Error processing {full_url}: {str(e)}")
                
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        
    return results

def main():
    # Test the WHOOP website
    url = "https://www.whoop.com"
    results = extract_versions(url)
    
    # Save results
    with open('version_disclosure_results.json', 'w') as f:
        json.dump(results, f, indent=4)
        
    # Print summary
    print("\nVersion Information Disclosure PoC Results")
    print("=========================================")
    print(f"URL tested: {url}")
    print(f"Files checked: {len(results['files_checked'])}")
    print(f"Versions found: {len(results['versions'])}")
    print("\nDetailed findings:")
    
    for version in results['versions']:
        print(f"\nComponent: {version['component']}")
        print(f"Version: {version['version']}")
        print(f"File: {version['file']}")

if __name__ == '__main__':
    main() 