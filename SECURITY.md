# Security Policy

## Supported Versions

The following versions of NetMCP currently receive security updates:

| Version   | Supported          |
|-----------|--------------------|
| 0.1.x     | :white_check_mark: |
| < 0.1.0   | :x:                |

As NetMCP is in active development (pre-1.0), only the latest minor version receives security patches. Users are strongly encouraged to stay on the most recent release.

## Reporting a Vulnerability

We take the security of NetMCP seriously. If you discover a security vulnerability, please follow these steps:

### Do

1. **Use [GitHub Security Advisories](https://github.com/luxvtz/netmcp/security/advisories/new)** to privately report the vulnerability. This creates a confidential channel between you and the maintainers.
2. **Provide detailed information** including:
   - A clear description of the vulnerability
   - Steps to reproduce the issue
   - Affected versions and components
   - Any proof-of-concept code or screenshots
   - Potential impact assessment
3. **Allow time for response.** We aim to acknowledge reports within 48 hours and provide a resolution timeline within 7 days.

### Do Not

- **Do not open a public issue** on the issue tracker for security vulnerabilities.
- **Do not disclose the vulnerability publicly** before we have had a reasonable time to investigate and release a fix.
- **Do not test the vulnerability** against production systems or networks that you do not own.

### What Not to Report

The following should be reported via regular GitHub Issues, not Security Advisories:

- General questions about using NetMCP
- Feature requests
- Non-security bugs (crashes, incorrect output, etc.)
- Already known and publicly documented issues
- Dependency vulnerabilities in transitive dependencies (unless they directly affect NetMCP's security posture)

## Security Response Process

When a vulnerability is reported, we follow this process:

1. **Acknowledge** (within 48 hours) — Confirm receipt of the report and assign a tracking ID.
2. **Investigate** (within 7 days) — Reproduce the vulnerability and assess impact.
3. **Fix** (within 14 days) — Develop and test a patch.
4. **Release** — Publish a patched version and update the security advisory.
5. **Disclose** — After users have had reasonable time to update (typically 30 days), publish a public advisory.

### Severity Classification

We classify vulnerabilities using the following severity levels:

| Level     | Description                                      | Response Time |
|-----------|--------------------------------------------------|---------------|
| Critical  | Remote code execution, credential exposure       | 48 hours      |
| High      | Authentication bypass, data leakage              | 7 days        |
| Medium    | Denial of service, information disclosure        | 14 days       |
| Low       | Minor information leak, non-critical misconfig   | 30 days       |

## Security Best Practices for Users

NetMCP interacts with network traffic and external services. Follow these guidelines to use it securely:

- **Run with least privilege:** Use Linux capabilities (`CAP_NET_RAW`) instead of running as root.
- **Keep dependencies updated:** Regularly run `pip install --upgrade` for all dependencies.
- **Secure your MCP client:** Ensure your MCP client (Claude Desktop, Cursor, etc.) is configured with appropriate access controls.
- **Review network data carefully:** Captured network traffic may contain sensitive information. Handle pcap files and analysis results accordingly.
- **Use trusted networks:** Only capture traffic on networks you are authorized to monitor.
- **Validate inputs:** When using threat intelligence or scanning features, ensure targets are within your scope of authorization.

## Acknowledgments

We thank the following individuals and organizations for responsibly reporting security issues:

<!-- Add names here as vulnerabilities are responsibly disclosed -->

*This list will be updated as security researchers responsibly disclose vulnerabilities.*

## Contact

For security-related questions that do not involve a vulnerability report, open a [Discussion](https://github.com/luxvtz/netmcp/discussions) or email the maintainers.

---

This security policy is adapted from the [OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/) for open source projects.
