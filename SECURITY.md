# Security Policy

## Supported versions

Until v1.0.0 is released, only the current default branch receives security fixes. After release, the latest v1 minor release is supported; older releases should be upgraded before a report is assessed.

## Reporting a vulnerability

The project owner must publish a private vulnerability contact before the first public release. No private contact has been provided in this repository, so a release is blocked until that requirement is satisfied. Do not send sensitive details or raw logs to a public issue, pull request, discussion, chat, or commit.

Once the owner publishes the contact, include the affected version, a minimal synthetic reproducer, impact, and suggested mitigation. Never attach production logs, sanitizer keys, cookies, credentials, database dumps, or a customer workspace.

The project targets acknowledgement and coordinated remediation within 90 days. Disclosure timing may be shortened for active exploitation or extended by mutual agreement when users need migration time.

## Sensitive data

Treat raw access logs, IP addresses, query values, cookies, User-Agent strings, full referers, HMAC keys, sanitized bundles, workspaces, simulation sidecars, and generated configurations as sensitive. Sanitized output is pseudonymized, not anonymous.

## Threat boundaries

CrawlLedger validates untrusted files, limits resource use, normalizes before persistence, and never applies generated configuration. It cannot protect against a hostile local administrator, a compromised operating system, process-memory inspection, disclosure of the HMAC key, or replacement of unsigned artifacts before their manifest is verified.
