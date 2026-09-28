# Security Policy

SOCMind is a defensive Blue Team project and may process sensitive security telemetry.

## Supported release

The current supported release line is **1.6.x**.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue before a fix is available. Use GitHub's private vulnerability reporting/security advisory workflow for this repository when available.

Include:

- affected SOCMind version
- operating system and Python version
- reproduction steps
- impact
- logs or minimal sanitized evidence
- suggested mitigation if known

Never include real credentials, API keys, production tokens, customer telemetry, or confidential incident evidence.

## Secure defaults

SOCMind is designed with these defaults:

- web server binds to `127.0.0.1`
- remote binds require an API token unless an explicit unsafe lab override is used
- `SOCMIND_API_TOKEN` is preferred over command-line secrets
- live connector TLS verification is enabled by default
- `--insecure` is opt-in and intended only for controlled labs
- SQL user values use parameterized queries
- web responses include CSP, anti-framing, no-sniff, no-referrer and no-store headers
- credentials for Wazuh, Elastic, MISP and OpenCTI are read from environment variables
- telemetry is not uploaded by default

## Production boundary

SOCMind 1.5 adds an enterprise foundation with RBAC, trusted-proxy identity, PostgreSQL case storage, tamper-evident audit, backup, and retention tooling.

A production deployment should still provide organization-specific:

- identity-aware reverse proxy backed by SSO/OIDC/SAML
- TLS termination
- secrets management
- centralized immutable/WORM audit storage
- PostgreSQL replication/backups/failover
- legal-hold-aware retention
- host hardening
- network segmentation
- monitoring and patch management
- load/soak validation for the intended analyst and telemetry scale

The built-in local API token is intended for local/small deployments. Trusted-proxy mode requires a correctly secured authenticating proxy and shared signing secret. The proxy must strip client-supplied `X-SOCMind-*` identity headers, generate fresh timestamped signatures, and keep the signing secret out of analyst browsers.
