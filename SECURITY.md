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

SOCMind 1.6 supports RBAC, native OIDC, trusted-proxy identity, PostgreSQL case storage, integrity verification and explicit analyst-controlled workflows.

A production deployment should still provide organization-specific:

- a configured OIDC provider or a secured identity-aware reverse proxy
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

## OIDC and evidence controls

OIDC uses Authorization Code with PKCE, state/nonce validation and verified ID
tokens. Cookie-authenticated mutations require the Origin configured by the
public redirect URI. Discovery/token endpoint redirects are refused. Sessions
are signed, HttpOnly and bounded by token expiry (maximum eight hours); they
have no central per-session revocation or IdP back-channel logout. Rotate the
session secret to invalidate all sessions. Test group mappings with your IdP.

Local CLI actor/role options are operator assertions within the OS-account trust
boundary, not remote authentication. Restrict CLI and database access accordingly.
Evidence directories must be service-owned. Artifacts are limited to 64 MiB,
content-addressed and conditionally created; object endpoints require HTTPS.
Conditional-write support is required from S3-compatible servers. Storage admins
can still alter objects: verification detects changes, but is not WORM or trusted
custody proof. Back up metadata and evidence together. Registration failures may
leave unreferenced objects; SOCMind does not silently delete evidence.
