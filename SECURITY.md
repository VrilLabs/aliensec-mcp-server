# Security Policy

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

To report a security vulnerability in AlienSec MCP Server, please send an email to the maintainers with the following information:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Impact assessment (CVSS score if known)
- Any relevant proof-of-concept or exploit code (share privately)
- Your contact information (optional)

### Email Contact

Please send vulnerability reports to: **security@aliensec.dev** (if available) or contact the repository maintainers directly.

### Response Time

We will acknowledge your report within **48 hours** and provide a more detailed response within **7 days**.

### Security Advisory Process

1. **Triage**: The security team will verify the vulnerability and assess its impact
2. **Remediation**: A fix will be developed and tested
3. **Disclosure**: A security advisory will be published with:
   - CVE assignment (if applicable)
   - Detailed description of the vulnerability
   - Impact assessment
   - Mitigation steps
   - Credits to the reporter (if desired)
4. **Release**: Patched versions will be released with the fix

## Security Features

### API Key Security

- All API keys (AlienVault OTX, VirusTotal) are **never logged** or exposed in error messages
- Keys are validated on startup and rejected if missing
- Sensitive strings are **hashed (SHA-256)** before storage in database tables

### Network Security

- All external API communication uses **HTTPS with TLS certificate validation**
- Circuit breakers prevent cascading failures from API issues
- Rate limiting prevents overwhelming external APIs
- Custom User-Agent headers identify the server version

### Data Protection

- SQLite database supports **optional encryption at rest**
- Use `DATABASE_ENCRYPTION_KEY` environment variable to enable encryption
- API keys are **never persisted** in plain text

### Rate Limiting & Circuit Breaker

- **VirusTotal Rate Limiting**: Token bucket algorithm with configurable limits
- **Circuit Breaker**: Automatically blocks failing API keys after 5 consecutive failures
- **Reset Timeout**: 5 minutes (configurable) before circuit breaker resets
- **Half-Open State**: Tests with 1 request before fully reopening

### VirusTotal ToS Compliance

- Multiple API keys are used for **redundancy only**, not for bypassing rate limits
- Each API key respects individual rate limits (4 requests/minute default)
- Circuit breaker prevents rapid retries on failures
- Daily request counting prevents quota exhaustion

## Security Best Practices

### For Users

1. **Use HTTPS**: Always use HTTPS for all communications
2. **Secure API Keys**: Store API keys in environment variables, not in code
3. **Network Isolation**: Run the server in a secure network environment
4. **Database Encryption**: Enable database encryption with `DATABASE_ENCRYPTION_KEY`
5. **Regular Updates**: Keep dependencies updated with `npm audit`

### For Deployments

1. **Environment Variables**: Use a secure secrets manager for production deployments
2. **Container Security**: If using containers, run as non-root user
3. **Resource Limits**: Set appropriate CPU and memory limits
4. **Monitoring**: Monitor server logs for suspicious activity
5. **Firewall**: Restrict network access to trusted sources only

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported | End of Life |
|---------|-----------|-------------|
| 1.0.x   | Yes       | TBD         |

## Security Advisories

All security advisories are published in the [GitHub Security Advisories](https://github.com/VrilLabs/aliensec-mcp-server/security/advisories) section.

## Credits

We appreciate all security researchers who responsibly disclose vulnerabilities to us. Contributors who report valid security issues will be acknowledged in our [Security Hall of Fame](#) (when established).

---

*Last updated: August 11, 2026*
