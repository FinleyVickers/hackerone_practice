# WHOOP Bug Bounty Scope

## In-Scope Assets
- WHOOP web applications
- WHOOP mobile applications
- WHOOP APIs and backend services
- Member data handling systems

## Out of Scope
- Support Systems (Live Chat, Web Forms, Iterable, Intercom, Salesforce)
- Social engineering attacks
- DoS/DDoS attacks
- MITM attacks
- Physical device attacks
- Known vulnerable libraries without PoC
- Non-impactful findings:
  - Clickjacking without sensitive actions
  - Unauthenticated CSRF
  - XSS without impact
  - Dangling DNS without impact
  - Subdomain takeover without impact
  - CSV injection without vulnerability demonstration
  - Missing SSL/TLS best practices
  - Content spoofing without HTML/CSS modification

## Testing Approach
1. Reconnaissance
   - Domain enumeration
   - API endpoint discovery
   - Technology stack identification
   - Public information gathering

2. Vulnerability Assessment
   - Authentication mechanisms
   - Authorization controls
   - Data handling
   - API security
   - Mobile app security
   - Web security

3. Impact Demonstration
   - Focus on CIA triad impacts
   - Clear PoC development
   - Documentation of exploitation steps

## Priority Areas
1. Member data privacy
2. Authentication systems
3. API security
4. Payment systems
5. Health data handling 