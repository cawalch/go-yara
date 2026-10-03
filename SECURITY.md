# Security Policy

`go-yara` takes security seriously. This document describes our security policy, supported versions, and the process for reporting vulnerabilities.

## Supported Versions

Only the latest release of `go-yara` receives security updates.

| Version | Supported |
| :--- | :--- |
| Latest release (`v0.x` / `v1.x`) | :white_check_mark: |
| Older releases | :x: |

We recommend always running the latest published version of `go-yara`.

## Reporting a Vulnerability

If you discover a security vulnerability in `go-yara`, please disclose it responsibly. **Do not open a public GitHub issue.**

### Preferred Method: GitHub Private Vulnerability Reporting

Please report vulnerabilities using GitHub's built-in private advisory system:

1. Navigate to the [Security Advisories](https://github.com/cawalch/go-yara/security/advisories) tab.
2. Click **Report a vulnerability**.
3. Provide a detailed description of the issue.

### Alternative Method: Email

If you cannot use GitHub Advisories, email **cawalch@pm.me** with the subject line `[SECURITY] go-yara Vulnerability Report`.

### What to Include in Your Report

To help us triage and resolve the issue quickly, please include:
- A clear description of the vulnerability and its potential security impact.
- Step-by-step instructions or a minimal proof-of-concept (POC) YARA rule and input sample.
- The `go-yara` version or git commit hash used.
- Your Go environment details (`go version`, OS, architecture).
- Any proposed remediation or patch if available.

## Response Process and Timeline

- **Acknowledgment**: We aim to acknowledge receipt of vulnerability reports within 48 hours.
- **Assessment**: We will evaluate the report, verify the impact, and coordinate a fix in a private branch.
- **Remediation**: Once verified, a security patch will be prepared and published in a new release.
- **Credit**: If desired, we will credit you in the security advisory and release notes.
