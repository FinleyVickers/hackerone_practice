#!/usr/bin/env python3
"""
NBA Security Headers Checker

This script checks for security headers on NBA domains and identifies potential
security issues based on missing or misconfigured headers.

Usage:
    python security_headers_check.py

Note: This script should only be used with proper authorization as part of
a bug bounty program. Unauthorized scanning may violate terms of service.
"""

import requests
import argparse
import json
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Default domains to check
DEFAULT_DOMAINS = [
    "www.nba.com",
    "api.nba.com",
    "data.nba.com",
    "stats.nba.com",
    "developerportal.nba.com",
    "status.nba.com",
    "store.nba.com",
    "watch.nba.com",
    "tickets.nba.com",
    "account.nba.com",
]

# Security headers to check for
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "severity": "Medium"
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "recommendation": "Set a restrictive CSP to prevent XSS attacks",
        "severity": "High"
    },
    "X-Content-Type-Options": {
        "description": "X-Content-Type-Options",
        "recommendation": "nosniff",
        "severity": "Low"
    },
    "X-Frame-Options": {
        "description": "X-Frame-Options",
        "recommendation": "DENY or SAMEORIGIN",
        "severity": "Medium"
    },
    "X-XSS-Protection": {
        "description": "X-XSS-Protection",
        "recommendation": "1; mode=block",
        "severity": "Medium"
    },
    "Referrer-Policy": {
        "description": "Referrer Policy",
        "recommendation": "strict-origin-when-cross-origin",
        "severity": "Low"
    },
    "Permissions-Policy": {
        "description": "Permissions Policy",
        "recommendation": "Set appropriate permissions",
        "severity": "Low"
    },
    "Cache-Control": {
        "description": "Cache Control",
        "recommendation": "no-store, max-age=0",
        "severity": "Low"
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS Allow Origin",
        "recommendation": "Should be specific, not wildcard (*)",
        "severity": "Medium"
    },
    "Access-Control-Allow-Credentials": {
        "description": "CORS Allow Credentials",
        "recommendation": "Should be carefully reviewed if true",
        "severity": "Medium"
    },
    "Server": {
        "description": "Server header",
        "recommendation": "Should be removed or generic",
        "severity": "Info"
    },
    "X-Powered-By": {
        "description": "X-Powered-By header",
        "recommendation": "Should be removed",
        "severity": "Info"
    }
}

def check_domain_headers(domain, timeout=5, verify=True, user_agent=None):
    """Check security headers for a domain."""
    url = f"https://{domain}"
    headers = {}
    
    if user_agent:
        headers["User-Agent"] = user_agent
    
    try:
        response = requests.get(url, timeout=timeout, verify=verify, headers=headers)
        
        result = {
            "domain": domain,
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "issues": []
        }
        
        # Check for missing security headers
        for header, info in SECURITY_HEADERS.items():
            if header not in response.headers:
                result["issues"].append({
                    "header": header,
                    "issue": "Missing header",
                    "description": info["description"],
                    "recommendation": info["recommendation"],
                    "severity": info["severity"]
                })
            elif header == "Strict-Transport-Security":
                # Check if HSTS max-age is too short
                hsts = response.headers[header]
                if "max-age=" in hsts:
                    try:
                        max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                        if max_age < 31536000:  # Less than 1 year
                            result["issues"].append({
                                "header": header,
                                "issue": "HSTS max-age too short",
                                "description": "HSTS max-age should be at least 1 year (31536000 seconds)",
                                "recommendation": info["recommendation"],
                                "severity": info["severity"]
                            })
                    except (ValueError, IndexError):
                        pass
            elif header == "Access-Control-Allow-Origin" and response.headers[header] == "*":
                # Check if CORS Allow Origin is a wildcard
                result["issues"].append({
                    "header": header,
                    "issue": "Wildcard CORS Allow Origin",
                    "description": "Wildcard CORS Allow Origin can lead to security issues",
                    "recommendation": info["recommendation"],
                    "severity": info["severity"]
                })
            elif header == "Access-Control-Allow-Credentials" and response.headers[header].lower() == "true":
                # Check if CORS Allow Credentials is true
                result["issues"].append({
                    "header": header,
                    "issue": "CORS Allow Credentials is true",
                    "description": "CORS Allow Credentials should be carefully reviewed",
                    "recommendation": info["recommendation"],
                    "severity": info["severity"]
                })
        
        return result
    except requests.exceptions.RequestException as e:
        return {
            "domain": domain,
            "url": url,
            "error": str(e),
            "status_code": 0,
            "headers": {},
            "issues": []
        }

def check_domains(domains, threads=5, timeout=5, verify=True, user_agent=None):
    """Check security headers for multiple domains concurrently."""
    results = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            futures.append(
                executor.submit(check_domain_headers, domain, timeout, verify, user_agent)
            )
        
        for future in futures:
            result = future.result()
            results.append(result)
            
            # Print result immediately
            if "error" in result:
                print(f"Error: {result['url']} - {result['error']}")
            else:
                print(f"{result['status_code']} - {result['url']} - {len(result['issues'])} issues found")
    
    return results

def save_results(results, output_file):
    """Save scan results to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="NBA Security Headers Checker")
    parser.add_argument("--domains", nargs="+", default=DEFAULT_DOMAINS, help="Domains to check")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("--output", default="security_headers_results.json", help="Output file for results")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", help="User agent string")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()
    
    print(f"NBA Security Headers Checker")
    print(f"Domains to check: {len(args.domains)}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout} seconds")
    print(f"Output file: {args.output}")
    print(f"SSL verification: {not args.no_verify}")
    print("Starting scan...\n")
    
    results = check_domains(
        args.domains,
        threads=args.threads,
        timeout=args.timeout,
        verify=not args.no_verify,
        user_agent=args.user_agent
    )
    
    # Save results to file
    save_results(results, args.output)
    
    # Print summary
    total_issues = sum(len(result.get("issues", [])) for result in results)
    
    print("\nScan complete!")
    print(f"Total domains checked: {len(results)}")
    print(f"Total issues found: {total_issues}")
    
    # Print issues by severity
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for result in results:
        for issue in result.get("issues", []):
            severity_counts[issue["severity"]] = severity_counts.get(issue["severity"], 0) + 1
    
    print("Issues by severity:")
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")
    
    print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main() 