# NBA Bug Bounty Reconnaissance

This repository contains the results of reconnaissance for the NBA Public Bug Bounty program on HackerOne. The goal is to identify potential security vulnerabilities that could be submitted as part of the bug bounty program.

## Disclaimer

This research is intended for educational purposes and for legitimate bug bounty submissions. Always ensure you have proper authorization before testing any systems. Unauthorized testing may violate terms of service and laws.

## Repository Structure

- `scope/`: Information about the program scope and target assets
- `findings/`: Analysis of potential vulnerabilities and targets
- `tools/`: Custom tools for testing specific vulnerabilities

## Key Findings

1. **Developer Portal CORS Misconfiguration**: The developer portal has CORS headers that allow credentials from localhost, which could potentially be exploited.

2. **Insufficient Security Headers**: The main NBA website lacks important security headers like Content-Security-Policy.

3. **API Authentication**: The API endpoints return 401 Unauthorized and redirect to the developer portal, suggesting a potential target for authentication bypass.

4. **Restricted Access Resources**: Several endpoints return 403 Forbidden, indicating potential targets for access control bypass testing.

5. **Custom Infrastructure**: The presence of custom headers suggests custom infrastructure that may contain unique vulnerabilities.

## High-Value Targets

1. **Developer Portal**: https://developerportal.nba.com/
2. **API Endpoints**: https://api.nba.com/
3. **Data Subdomain**: https://data.nba.com/
4. **Status Subdomain**: https://status.nba.com/

## Tools

### CORS Test

The `tools/cors_test.html` file contains a simple HTML page that can be used to test for CORS vulnerabilities in the NBA Developer Portal. To use it:

1. Run a local web server on port 3000 (e.g., `python -m http.server 3000`)
2. Open the HTML file in a browser at http://127.0.0.1:3000/cors_test.html
3. Log in to the NBA Developer Portal in another tab
4. Return to the CORS test page and click "Test CORS"
5. If the request succeeds, it demonstrates a CORS vulnerability

### API Endpoint Scanner

The `tools/api_endpoint_scanner.py` script can be used to discover API endpoints by testing common paths against the NBA API domain. To use it:

```bash
# Install dependencies
pip install requests

# Run the scanner
python api_endpoint_scanner.py --base-url https://api.nba.com
```

Options:
- `--base-url`: Base URL to scan (default: https://api.nba.com)
- `--threads`: Number of concurrent threads (default: 5)
- `--timeout`: Request timeout in seconds (default: 5)
- `--output`: Output file for results (default: api_scan_results.csv)
- `--user-agent`: Custom user agent string
- `--no-verify`: Disable SSL verification

### Security Headers Checker

The `tools/security_headers_check.py` script checks for security headers on NBA domains and identifies potential security issues based on missing or misconfigured headers. To use it:

```bash
# Install dependencies
pip install requests

# Run the checker
python security_headers_check.py
```

Options:
- `--domains`: List of domains to check (default: 10 NBA domains)
- `--threads`: Number of concurrent threads (default: 5)
- `--timeout`: Request timeout in seconds (default: 5)
- `--output`: Output file for results (default: security_headers_results.json)
- `--user-agent`: Custom user agent string
- `--no-verify`: Disable SSL verification

The script checks for the following security headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cache-Control
- Access-Control-Allow-Origin
- Access-Control-Allow-Credentials

## Recommended Testing Approach

1. **Authentication & Authorization Testing**
   - Test for OAuth implementation flaws
   - Look for authentication bypass in API endpoints
   - Check for improper session management

2. **API Security Testing**
   - Analyze JavaScript files for exposed API endpoints and keys
   - Test for parameter manipulation vulnerabilities
   - Check for rate limiting issues

3. **Information Disclosure Testing**
   - Look for sensitive information in HTTP headers
   - Check for directory listing vulnerabilities
   - Analyze source code for developer comments

4. **Web Application Testing**
   - Test for XSS vulnerabilities
   - Check for CSRF vulnerabilities
   - Test for SSRF vulnerabilities

5. **Mobile Application Testing**
   - Decompile the NBA mobile apps to look for hardcoded credentials
   - Test the security of API endpoints used by mobile apps

## Reports

Detailed reports can be found in the `findings/` directory:

- `bug_bounty_assessment.md`: Overall assessment of the bug bounty program
- `subdomain_analysis.md`: Analysis of NBA subdomains
- `vulnerability_targets.md`: Specific vulnerability targets
- `final_report.md`: Summary of findings and recommendations

## Next Steps

Before beginning active testing, it's recommended to join the HackerOne program to get the official scope and rules to ensure all testing is compliant with the program's guidelines. 