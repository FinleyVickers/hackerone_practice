#!/usr/bin/env python3
"""
NBA API Endpoint Scanner

This script attempts to discover API endpoints by testing common paths
against the NBA API domain. It's designed for use in bug bounty research
to identify potentially vulnerable endpoints.

Usage:
    python api_endpoint_scanner.py

Note: This script should only be used with proper authorization as part of
a bug bounty program. Unauthorized scanning may violate terms of service.
"""

import requests
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Default settings
DEFAULT_BASE_URL = "https://api.nba.com"
DEFAULT_WORDLIST = [
    # Common API paths
    "/v1/status",
    "/v2/status",
    "/health",
    "/ping",
    "/api/status",
    "/api/v1/status",
    "/api/v2/status",
    
    # NBA-specific paths
    "/stats/scoreboard",
    "/stats/players",
    "/stats/teams",
    "/stats/games",
    "/data/players",
    "/data/teams",
    "/data/games",
    "/data/standings",
    "/data/schedule",
    
    # Common API resources
    "/users",
    "/teams",
    "/players",
    "/games",
    "/schedule",
    "/standings",
    "/stats",
    "/scores",
    "/highlights",
    "/videos",
    
    # Authentication endpoints
    "/auth",
    "/login",
    "/oauth",
    "/oauth/token",
    "/oauth/authorize",
    "/api/auth",
    "/api/login",
    
    # Admin/internal paths
    "/admin",
    "/internal",
    "/dev",
    "/test",
    "/beta",
    "/staging",
    "/debug",
    
    # Documentation
    "/docs",
    "/swagger",
    "/openapi",
    "/api-docs",
    "/swagger-ui",
    "/redoc",
    
    # Version info
    "/version",
    "/api/version",
    "/v1/version",
    "/v2/version",
]

def check_endpoint(base_url, endpoint, timeout=5, verify=True, user_agent=None):
    """Check if an API endpoint exists and return its status code and headers."""
    url = f"{base_url}{endpoint}"
    headers = {}
    
    if user_agent:
        headers["User-Agent"] = user_agent
    
    try:
        response = requests.get(url, timeout=timeout, verify=verify, headers=headers)
        return {
            "endpoint": endpoint,
            "url": url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "server": response.headers.get("Server", ""),
            "content_length": len(response.content),
            "location": response.headers.get("Location", ""),
            "response_time": response.elapsed.total_seconds(),
        }
    except requests.exceptions.RequestException as e:
        return {
            "endpoint": endpoint,
            "url": url,
            "error": str(e),
            "status_code": 0,
        }

def scan_endpoints(base_url, endpoints, threads=5, timeout=5, verify=True, user_agent=None):
    """Scan multiple endpoints concurrently."""
    results = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for endpoint in endpoints:
            futures.append(
                executor.submit(check_endpoint, base_url, endpoint, timeout, verify, user_agent)
            )
        
        for future in futures:
            result = future.result()
            results.append(result)
            
            # Print result immediately
            if "error" in result:
                print(f"Error: {result['url']} - {result['error']}")
            else:
                print(f"{result['status_code']} - {result['url']} - {result.get('location', '')}")
    
    return results

def save_results(results, output_file):
    """Save scan results to a file."""
    with open(output_file, "w") as f:
        f.write("Status,URL,Content-Type,Server,Content-Length,Location,Response-Time\n")
        for result in results:
            if "error" not in result:
                f.write(f"{result['status_code']},{result['url']},{result['content_type']},{result['server']},{result['content_length']},{result['location']},{result['response_time']}\n")

def main():
    parser = argparse.ArgumentParser(description="NBA API Endpoint Scanner")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Base URL to scan")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("--output", default="api_scan_results.csv", help="Output file for results")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", help="User agent string")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()
    
    print(f"NBA API Endpoint Scanner")
    print(f"Base URL: {args.base_url}")
    print(f"Endpoints to scan: {len(DEFAULT_WORDLIST)}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout} seconds")
    print(f"Output file: {args.output}")
    print(f"SSL verification: {not args.no_verify}")
    print("Starting scan...\n")
    
    start_time = time.time()
    results = scan_endpoints(
        args.base_url,
        DEFAULT_WORDLIST,
        threads=args.threads,
        timeout=args.timeout,
        verify=not args.no_verify,
        user_agent=args.user_agent
    )
    end_time = time.time()
    
    # Save results to file
    save_results(results, args.output)
    
    # Print summary
    status_counts = {}
    for result in results:
        status = result.get("status_code", 0)
        status_counts[status] = status_counts.get(status, 0) + 1
    
    print("\nScan complete!")
    print(f"Total time: {end_time - start_time:.2f} seconds")
    print("Status code distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main() 