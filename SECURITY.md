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

The offline `analyze`, `sanitize`, and `policy` workflows validate untrusted
files, limit resource use, normalize before persistence, and never apply
generated configuration.

Experimental Nginx protection deliberately adds a separate privilege boundary.
`protect run` is dry-run by default. In live mode an unprivileged watcher owns
the private desired-state file and holds a root-created state lock. Its sudoers
grant must permit only the exact root-owned CrawlLedger binary, `protect apply`,
and one exact root-owned config path. The root child accepts only a bounded
method/path projection that must equal the locked state; it never accepts raw
logs, IP addresses, detector evidence, or arbitrary Nginx text. Managed files
are root-owned, opened without symlinks on Linux, tested before reload, and
restored on failure. Setup, sudoers, systemd, and Nginx includes are always
installed manually.

Protection is not a WAF, crawler authenticator, or network DDoS control. A
route-level limiter can reject legitimate traffic above its emergency rate.
It cannot protect bandwidth, connection tables, TLS, attacks that prevent log
delivery, unrelated low-rate shapes, excluded paths, or dynamically rewritten
paths. Incorrect Nginx real-IP configuration makes distinct-client estimates
unreliable. Location-level `limit_req` directives can shadow the inherited
server limiter.

CrawlLedger cannot protect against a hostile local administrator, a
compromised operating system, process-memory inspection, disclosure of an HMAC
key, malicious Nginx configuration, or replacement of unsigned artifacts before
their manifest is verified.
