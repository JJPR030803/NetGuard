# Dependencies to Watch for Security Vulnerabilities

This document lists dependencies that require regular security monitoring due to their history of vulnerabilities or their critical role in the application's security posture.

## High-Risk Dependencies

### Cryptographic Libraries
- **cryptography**: Core cryptographic operations library
  - Common issues: Implementation flaws, algorithm vulnerabilities
  - Monitor: [PyUp Safety DB](https://pyup.io/safety/), [GitHub Security Advisories](https://github.com/pyca/cryptography/security/advisories)

- **passlib**: Password hashing library
  - Common issues: Outdated hashing algorithms, implementation flaws
  - Monitor: [PyUp Safety DB](https://pyup.io/safety/), [GitHub Issues](https://github.com/glic3rinu/passlib/issues)

### Network Libraries
- **scapy**: Packet manipulation library
  - Common issues: Memory leaks, parsing vulnerabilities
  - Monitor: [GitHub Security Advisories](https://github.com/secdev/scapy/security/advisories)

- **uvicorn**: ASGI server
  - Common issues: DoS vulnerabilities, HTTP parsing issues
  - Monitor: [GitHub Security Advisories](https://github.com/encode/uvicorn/security/advisories)

### Web Framework
- **fastapi**: API framework
  - Common issues: Security middleware bugs, validation bypasses
  - Monitor: [GitHub Security Advisories](https://github.com/tiangolo/fastapi/security/advisories)

- **starlette**: ASGI framework (FastAPI dependency)
  - Common issues: Security middleware bugs
  - Monitor: [GitHub Security Advisories](https://github.com/encode/starlette/security/advisories)

### Data Processing
- **sqlalchemy**: SQL toolkit and ORM
  - Common issues: SQL injection vulnerabilities
  - Monitor: [GitHub Security Advisories](https://github.com/sqlalchemy/sqlalchemy/security/advisories)

## Medium-Risk Dependencies

### Data Processing Libraries
- **pandas**: Data analysis library
  - Common issues: Memory vulnerabilities with untrusted data
  - Monitor: [GitHub Security Advisories](https://github.com/pandas-dev/pandas/security/advisories)

- **numpy**: Numerical computing library
  - Common issues: Buffer overflows, memory issues
  - Monitor: [GitHub Security Advisories](https://github.com/numpy/numpy/security/advisories)

### HTTP Libraries
- **requests**: HTTP client library
  - Common issues: TLS validation issues, redirect vulnerabilities
  - Monitor: [GitHub Security Advisories](https://github.com/psf/requests/security/advisories)

- **httpx**: HTTP client library
  - Common issues: TLS validation issues, redirect vulnerabilities
  - Monitor: [GitHub Security Advisories](https://github.com/encode/httpx/security/advisories)

## Previously Removed Vulnerable Dependencies

The following dependencies were previously removed due to security vulnerabilities:

- **python-jose**: JWT implementation
  - Vulnerabilities: JWT bomb (CVE-2024-33664), algorithm confusion (CVE-2024-33663)
  - Alternative: `authlib` or `pyjwt`

- **ecdsa**: Elliptic Curve Digital Signature Algorithm implementation
  - Vulnerabilities: Minerva attack (CVE-2024-23342), side-channel attacks (PVE-2024-64396)
  - Alternative: `cryptography` library's ECC implementation

## Monitoring Recommendations

1. **Regular Scanning**:
   - Run `make security` weekly to check for new vulnerabilities
   - Configure GitHub Dependabot alerts for the repository

2. **Update Strategy**:
   - Prioritize security updates for high-risk dependencies
   - Test thoroughly after updating cryptographic libraries
   - Consider pinning versions of critical security dependencies

3. **Dependency Minimization**:
   - Regularly audit dependencies to remove unused ones
   - Consider security implications before adding new dependencies

4. **Vulnerability Response Plan**:
   - Assess impact of reported vulnerabilities
   - Determine if vulnerable code paths are in use
   - Prioritize updates based on CVSS score and exploitation likelihood
   - Document remediation steps in SECURITY_NOTES.md
