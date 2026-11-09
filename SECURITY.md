# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities through GitHub's private vulnerability reporting
("Security" tab -> "Report a vulnerability"). Do not open public issues for security problems
and do not include confidential information in reports.

## Supported Versions

| Version     | Supported |
|-------------|-----------|
| 0.1.x (dev) | Yes       |

## Security Design

AegisChain analyses **untrusted** repository metadata and artifacts:

- repository code is never executed, imported or installed;
- symbolic links are never followed and credential-like files are never opened;
- archive uploads are extracted with zip-slip, link, size and member-count protection;
- every external lookup that fails yields `INDETERMINATE`, never `PASS`;
- signature cryptography is delegated to the official Sigstore client.

See `docs/security/threat-model.md` and `docs/security/limitations.md` for the full model
and the known residual risks.
