# Bug Bounty Testing Framework

A comprehensive framework for conducting security assessments on public bug bounty programs, with specific implementations for WHOOP and NBA targets.

## Overview

This repository contains tools, methodologies, and findings for security testing conducted as part of public bug bounty programs. The framework is designed to systematically identify, exploit, and document security vulnerabilities across web applications, APIs, and mobile endpoints.

## Repository Structure

```
/
├── whoop/              # WHOOP bug bounty testing
│   ├── tools/          # Custom testing tools
│   ├── reports/        # Vulnerability reports
│   ├── vulnerabilities/# Discovered vulnerabilities
│   └── endpoints.txt   # API endpoints for testing
│
└── nba-recon/          # NBA bug bounty testing
    ├── tools/          # Custom testing tools
    ├── findings/       # Vulnerability findings
    ├── scope/          # Target scope definition
    └── reports/        # Final reports
```

## Tools

### Common Testing Tools

- **API Testers**: Automated tools that test API endpoints for common vulnerabilities like CORS misconfigurations, authentication bypasses, and rate limiting issues.
- **Security Header Checkers**: Tools that verify proper implementation of security headers.
- **Vulnerability Scanners**: Custom scanners for specific vulnerability types.

### WHOOP-specific Tools

- `api_tester.py`: Tests WHOOP API endpoints for various vulnerabilities.
- `subscription_tester.py`: Specifically tests subscription and payment flow vulnerabilities.
- `graphql_tester.py`: Tests GraphQL endpoints for authorization issues and data exposure.
- `mobile_api_tester.py`: Tests mobile API endpoints for authentication and data manipulation issues.

### NBA-specific Tools

- `api_endpoint_scanner.py`: Scans NBA API endpoints for vulnerabilities.
- `cors_tester.py`: Tests for CORS misconfigurations.
- `security_headers_check.py`: Verifies proper security headers implementation.

## Usage

### WHOOP Testing

1. **API Testing**:
   ```
   cd whoop
   python tools/api_tester.py -u https://api.whoop.com -e endpoints.txt -o vulnerabilities/api_findings.json
   ```

2. **Subscription Testing**:
   ```
   python tools/subscription_tester.py
   ```

3. **GraphQL Testing**:
   ```
   python tools/graphql_tester.py
   ```

4. **Mobile API Testing**:
   ```
   python tools/mobile_api_tester.py
   ```

### NBA Testing

1. **API Endpoint Scanning**:
   ```
   cd nba-recon
   python tools/api_endpoint_scanner.py --base-url https://api.nba.com
   ```

2. **CORS Testing**:
   ```
   python tools/cors_tester.py
   ```

3. **Security Headers Check**:
   ```
   python tools/security_headers_check.py
   ```

## Key Findings

### WHOOP

- **Information Disclosure**: Debug and version information disclosed in JavaScript files
- **Missing Security Headers**: Several pages lack important security headers like X-Frame-Options, X-XSS-Protection, and Referrer-Policy
- **API Testing**: Comprehensive testing of authentication, authorization, and business logic

### NBA

- **API Authentication**: API endpoints return 401 Unauthorized and redirect to the developer portal
- **Subdomain Analysis**: Multiple subdomains identified with varying levels of security
- **Security Headers**: Missing security headers on several public-facing pages

## Methodology

Our testing methodology follows a structured approach:

1. **Reconnaissance**: Identifying subdomains, endpoints, and entry points
2. **Vulnerability Scanning**: Automated scanning for common vulnerabilities
3. **Manual Testing**: In-depth testing of authentication, authorization, and business logic
4. **Proof of Concept**: Creating exploits to demonstrate impact
5. **Documentation**: Detailed reporting of findings with severity ratings

## Ethics and Compliance

All testing was conducted in accordance with the scope and rules of the respective bug bounty programs. No sensitive data was accessed or exfiltrated during testing.

## License

This project is for educational purposes only. Use responsibly and only against targets where you have explicit permission to test. 