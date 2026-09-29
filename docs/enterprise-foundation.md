# SOCMind v1.5 — Enterprise Foundation

SOCMind v1.5 moves the project from a local analyst workbench toward a team-ready enterprise architecture while preserving the local SQLite workflow for demos and single-analyst use.

## What v1.5 adds

- role-based access control (RBAC)
- signed trusted-proxy identity mode
- PostgreSQL-backed case operations
- tamper-evident append-only enterprise audit chain
- consistent SQLite backup command
- retention preview/apply tooling
- PostgreSQL schema initialization and readiness checks
- enterprise deployment/help documentation

## Roles

SOCMind ships with these built-in roles:

### viewer

Read-only access to cases, SOC Lead views, and reasoning.

### analyst

Viewer permissions plus:

- acknowledge cases
- add notes

### senior-analyst

Analyst permissions plus:

- assign cases
- transition case state
- review detection changes

### lead

Senior analyst permissions plus:

- read enterprise audit status

### admin

All permissions.

Inspect the permission matrix:

```bash
socmind enterprise-info
socmind enterprise-info --json
```

## Authentication modes

### Local token

The existing local-token mode remains supported:

```bash
export SOCMIND_API_TOKEN='strong-random-token'

socmind web events.jsonl \
  --api-token-role senior-analyst \
  --host 0.0.0.0
```

The token maps to a configured SOCMind role.

### Trusted proxy

For team deployments, SOCMind can trust identity headers only when they include an HMAC signature produced by a trusted reverse proxy / identity-aware gateway.

Configure:

```bash
export SOCMIND_TRUSTED_PROXY_SECRET='shared-secret'
```

Launch:

```bash
socmind web events.jsonl \
  --auth-mode trusted-proxy \
  --host 0.0.0.0
```

Expected headers:

```text
X-SOCMind-User
X-SOCMind-Role
X-SOCMind-Timestamp
X-SOCMind-Signature
```

The signature covers the subject, role, and Unix timestamp. Signatures older than the configured short validity window are rejected to reduce replay risk.

Generate a signature for lab/integration testing:

```bash
socmind trusted-sign \
  --subject analyst@example.com \
  --role analyst
```

This is a **trusted reverse-proxy integration mode**, not a replacement for an identity provider. Production environments may continue using it when identity is terminated upstream.

The proxy must strip any client-supplied `X-SOCMind-*` identity headers and generate fresh signed headers itself. The signing secret must never be exposed to analyst browsers.

### Native OIDC / SSO

SOCMind also supports a native generic OpenID Connect mode using Authorization Code + PKCE S256.

Required environment variables:

```bash
export SOCMIND_OIDC_ISSUER='https://idp.example.com/tenant/v2.0'
export SOCMIND_OIDC_CLIENT_ID='socmind-client-id'
export SOCMIND_OIDC_REDIRECT_URI='https://socmind.example.com/auth/callback'
export SOCMIND_OIDC_SESSION_SECRET='replace-with-at-least-32-random-characters'
```

For confidential clients, provide the client secret only through the environment:

```bash
export SOCMIND_OIDC_CLIENT_SECRET='...'
```

Role mapping is a JSON object whose keys are claim values and whose values are SOCMind roles:

```bash
export SOCMIND_OIDC_ROLE_CLAIM='groups'
export SOCMIND_OIDC_ROLE_MAP='{
  "SOC-T1":"analyst",
  "SOC-T2":"senior-analyst",
  "SOC-Leads":"lead",
  "SOC-Admins":"admin"
}'
```

Launch:

```bash
socmind web events.jsonl \
  --auth-mode oidc \
  --host 0.0.0.0
```

SOCMind discovers the provider endpoints from the configured issuer and validates the ID token signature via JWKS plus issuer, audience, expiry and nonce. The browser receives only a bounded HttpOnly SOCMind session cookie after validation.

HTTPS is required for issuer, provider endpoints and callback URI. `--oidc-allow-insecure-http` only permits loopback HTTP for local development.

The implementation is generic and designed for standards-compatible providers such as Microsoft Entra ID, Keycloak and Okta. CI validates protocol behavior with cryptographic local fixtures; it does not claim live interoperability testing against a specific tenant/provider without provider credentials.

## PostgreSQL case store

Install enterprise support:

```bash
pip install -e ".[enterprise,web,sigma]"
```

Configure a DSN:

```bash
export SOCMIND_POSTGRES_DSN='postgresql://socmind:password@db:5432/socmind'
```

Initialize:

```bash
socmind postgres-init
```

Check readiness:

```bash
socmind postgres-health
```

The PostgreSQL backend supports:

- cases
- notes
- audit events
- assignment
- acknowledgement
- lifecycle transitions
- queue metrics
- SLA / MTTA / MTTR
- evidence-linked historical similarity

Launch the Web Workspace using PostgreSQL:

```bash
socmind web events.jsonl \
  --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
  --auth-mode trusted-proxy \
  --enterprise-audit /var/log/socmind/enterprise-audit.jsonl \
  --host 0.0.0.0
```

If both `--postgres-dsn` and `--command-db` are configured, PostgreSQL is the active case store.

SQLite remains supported for local/demo workflows.

## Tamper-evident enterprise audit

SOCMind can write security-sensitive web actions to a separate hash-chained JSONL journal.

Each record includes:

- sequence
- timestamp
- case ID
- actor
- action
- detail
- previous entry hash
- current entry hash

Enable it:

```bash
socmind web events.jsonl \
  --command-db socmind.db \
  --enterprise-audit enterprise-audit.jsonl
```

Verify:

```bash
socmind audit-verify enterprise-audit.jsonl
```

A modified historical record breaks the chain and causes verification to fail.

This provides tamper evidence. It is not a substitute for sending audit logs to immutable/WORM storage or a centralized logging platform in production.

## Backup

For the local SQLite store:

```bash
socmind backup socmind.db \
  -o backups/socmind-$(date +%F).db
```

SOCMind uses SQLite's backup API so WAL-backed databases are snapshotted consistently.

For PostgreSQL, use the organization's normal PostgreSQL backup tooling such as managed snapshots or `pg_dump`; SOCMind does not attempt to replace database-native disaster-recovery tooling.

## Retention

Preview first:

```bash
socmind retention ./exports --days 90
```

Apply deliberately:

```bash
socmind retention ./exports --days 90 --apply
```

Retention defaults to dry-run and targets exported JSON/JSONL/Markdown artifacts.

Organizations should map this to their incident-response, privacy, legal-hold, and regulatory requirements before enabling deletion.

## Enterprise health

Useful commands:

```bash
socmind postgres-health
socmind security-check
socmind audit-verify enterprise-audit.jsonl
socmind doctor
```

The web `/health` response reports the selected case-store backend and whether enterprise audit is enabled.

## Production architecture

Recommended shape:

```text
Analyst Browser
      |
Identity-Aware Reverse Proxy / SSO
      |
SOCMind Web
      |
      +---- PostgreSQL
      |
      +---- Central / immutable audit destination
      |
      +---- Wazuh / Elastic / MISP / OpenCTI
```

## What v1.5 does not claim

v1.5 is an enterprise **foundation**, not a complete production platform for every organization.

Still organization-dependent:

- native OIDC/SAML login flow
- automated IdP group-to-role mapping
- Kubernetes/HA deployment
- PostgreSQL replication/failover
- centralized secrets manager integration
- WORM/SIEM audit shipping
- legal-hold-aware retention
- disaster-recovery orchestration
- ServiceNow/Jira/SOAR workflows
- load and soak testing at a specific enterprise scale

These should be implemented according to the deployment environment instead of hidden behind unrealistic generic defaults.

## CI validation

v1.5 adds a real PostgreSQL service test. CI initializes PostgreSQL, runs health checks, exercises PostgreSQL case CRUD, validates RBAC through the Web API, and verifies the enterprise audit chain.
