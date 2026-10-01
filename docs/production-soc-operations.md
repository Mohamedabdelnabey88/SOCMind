# SOCMind v1.6.0 — Production SOC Operations

The release connects alert orchestration to governed case, evidence and detection operations:

```text
Wazuh / Elastic Alert
        ↓
Normalize alert identity
        ↓
Duplicate check
        ↓
Active-case correlation
        ↓
NEW CASE or CORRELATED CASE
        ↓
Evidence window collection
        ↓
Case priority escalation
        ↓
Auditable alert chain
```

## Alert orchestration

SQLite/local team mode:

```bash
socmind alert-orchestrate wazuh tests/fixtures/wazuh-alerts.jsonl \
  --database socmind.db \
  --evidence wazuh-normalized.jsonl \
  --evidence-dir socmind-evidence \
  --json
```

PostgreSQL/team mode:

```bash
export SOCMIND_POSTGRES_DSN='postgresql://socmind:password@db:5432/socmind'

socmind alert-orchestrate elastic elastic-alerts.ndjson \
  --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
  --evidence normalized.jsonl \
  --evidence-dir /var/lib/socmind/evidence \
  --json
```

## Live alert ingestion

SOCMind can pull active alerts directly from an Elasticsearch-compatible search API and immediately feed them into the same idempotent orchestration pipeline used by file ingestion.

### Elastic Security

```bash
export ELASTIC_API_KEY='...'

socmind alert-live elastic https://elastic.internal:9200 \
  .alerts-security.alerts-default \
  --database socmind.db \
  --evidence-dir socmind-evidence \
  --json
```

The parser understands current Elastic Security alert metadata including `kibana.alert.rule.*`, `kibana.alert.severity`, `kibana.alert.risk_score`, and ATT&CK technique metadata.

### Wazuh Indexer

```bash
export WAZUH_INDEXER_USER='...'
export WAZUH_INDEXER_PASSWORD='...'

socmind alert-live wazuh-indexer https://wazuh-indexer.internal:9200 \
  'wazuh-alerts*' \
  --database socmind.db \
  --evidence-dir socmind-evidence \
  --json
```

`WAZUH_INDEXER_JWT` is also supported. Wazuh Indexer credentials are isolated from Elastic credentials.

The live command requires no temporary export file. Returned search hits are normalized in memory and passed directly through duplicate detection, explainable correlation, case creation/attachment, priority escalation and evidence-window collection.

TLS verification is enabled by default. `--insecure` is intended only for controlled lab environments.

## Correlation model

SOCMind currently scores explainable alert overlap using:

- same host: +30
- same user: +20
- same process: +15
- same source IP: +15
- same destination IP: +10
- same rule: +10
- same ATT&CK technique: +15

Default merge threshold: `55`.

The score alone does not trigger an automatic merge. Same-host correlation also requires shared user, process, source IP, or destination IP context; cross-host correlation requires multiple shared context anchors. Rule/ATT&CK similarity can strengthen a score but cannot justify automatic merging by itself.

Candidate lookup is bounded by the correlation time window and shared context before scoring, so unrelated alert floods do not hide relevant active cases.

Default correlation time window: `15 minutes`.

Both are configurable:

```bash
--correlation-window 20
--correlation-threshold 65
```

The score is deterministic correlation evidence. It is **not attacker attribution** and it is not a probability that two alerts share a root cause.

## Outcomes

### NEW CASE

No active case met the configured correlation threshold.

SOCMind creates a deterministic case ID from the alert source and source alert ID. Reprocessing the same alert therefore does not create a second case.

### CORRELATED

The alert matched an existing active case.

The case stores:

- alert ID
- source
- title
- timestamp
- severity
- rule ID
- ATT&CK technique when available
- correlation score
- each reason that contributed to the score

A more severe correlated alert can raise the case priority.

### DUPLICATE

The exact source alert ID was previously ingested.

The operation is idempotent and does not create another case-alert link.

## Evidence collection

SOCMind collects evidence around the alert using a configurable time window:

```bash
--evidence-before 15
--evidence-after 15
```

Events are selected when they match useful investigation context such as:

- host
- user
- source IP
- destination IP

Evidence is merged into the case evidence file with event deduplication.

Local evidence writes are protected by a per-case cross-platform file lock to reduce lost updates from concurrent ingestion workers.

## Concurrency

### SQLite

The correlation/create/link decision uses `BEGIN IMMEDIATE`.

This serializes competing alert decisions so two related alerts arriving together do not independently create two cases.

### PostgreSQL

The orchestration decision uses a PostgreSQL transaction advisory lock.

The complete duplicate-check → correlation → case creation → alert linking decision is serialized transactionally.

CI contains concurrent-ingestion regression tests for both stores.

## Case workspace

Case detail includes **Correlated Alerts**.

An analyst can review every linked alert and the exact reasons it was associated with the case.

This keeps correlation explainable and auditable instead of becoming an opaque grouping engine.

## Production boundaries

The release does not include streaming webhooks, Kafka ingestion or endpoint
agents. Live collection queries a configured SIEM API. Operators must validate
provider permissions, retention, availability and deployment-specific scale.

## Detection Rule Lifecycle

SOCMind supports a governed detection lifecycle:

```text
experimental
  ↓
testing
  ↓
approved
  ↓
production
  ↓
deprecated
  ↓
retired
```

A rule lifecycle record stores:

- rule ID and source path
- semantic version
- owner
- created/updated timestamps
- status
- change notes
- ATT&CK mapping
- syntax validation status
- regression fixture status
- confirmed-incident replay results
- false-positive history
- coverage delta history
- auditable lifecycle history

The registry uses cross-platform file locking and atomic replacement. Registry targets and rule sources that are symlinks are rejected for mutation-sensitive operations.

Approval is gated. A rule cannot enter `approved` or `production` until SOCMind has recorded:

1. syntax validation PASS
2. regression fixture PASS
3. at least one confirmed-incident replay
4. at least one false-positive observation
5. at least one coverage delta measurement

Senior analysts may manage validation evidence. Lead/Admin authority is required for approval, deprecation and retirement, and Lead/Admin promotion authority is required for `production`.

SOCMind never auto-promotes a detection rule.

Example:

```bash
socmind rule-register rule-registry.json detections/windows/suspicious-powershell.yml \
  --owner detection-team --actor tier2@example.com --role senior-analyst

socmind rule-transition rule-registry.json socmind-win-powershell-hidden \
  --state testing --actor tier2@example.com --role senior-analyst \
  --note "Begin validation"
```

The local CLI role is an explicit operator policy assertion, not an identity provider. Web authentication supports native OIDC as described below.


## Live Evidence Collector

SOCMind can now use the alerts already linked to a case to build an auditable live evidence query against an Elasticsearch-compatible backend.

Supported provider modes:

- `elastic`
- `wazuh-indexer` (Elasticsearch/OpenSearch-compatible Wazuh Indexer API)

The collector derives:

- earliest/latest linked-alert timestamp
- configurable before/after collection window
- hosts
- users
- processes
- source IPs
- destination IPs

It then builds a bounded query and merges normalized results into the case evidence package.

### Elastic

```bash
export ELASTIC_API_KEY='...'

socmind case-collect-evidence INC-2026-001 \
  elastic \
  https://elastic.internal:9200 \
  'logs-*' \
  --database socmind.db \
  --evidence-dir evidence
```

PostgreSQL:

```bash
export SOCMIND_POSTGRES_DSN='postgresql://socmind:password@db:5432/socmind'
export ELASTIC_API_KEY='...'

socmind case-collect-evidence INC-2026-001 \
  elastic \
  https://elastic.internal:9200 \
  'logs-*' \
  --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
  --evidence-dir /var/lib/socmind/evidence
```

### Wazuh Indexer

```bash
export WAZUH_INDEXER_USER='socmind'
export WAZUH_INDEXER_PASSWORD='...'

socmind case-collect-evidence INC-2026-001 \
  wazuh-indexer \
  https://wazuh-indexer.internal:9200 \
  'wazuh-alerts-*' \
  --database socmind.db \
  --evidence-dir evidence
```

TLS verification is on by default. `--insecure` is intended only for controlled lab environments using self-signed certificates.

### Collection journal

Every live collection records:

- collection ID
- case ID
- provider
- source index/pattern
- exact time window
- exact generated query
- started/completed timestamps
- status
- event count
- provider error, if any

Collection success/failure also appears in the case audit trail and the unified case timeline.

Provider failure is never silently treated as an empty successful result.

### Query semantics

SOCMind uses the linked alerts as investigation context rather than issuing an unbounded search.

The query always filters by the case alert time window and, when available, requires at least one matching identity signal from:

- `host.name`
- `user.name`
- `process.name`
- `process.executable`
- `source.ip`
- `destination.ip`

This is evidence collection for investigation context. It is not an attribution engine and does not automatically determine case disposition.

## Evidence integrity

Every case evidence JSONL package written by alert orchestration or the live evidence collector now receives a sidecar manifest:

```text
<case-id>.jsonl.manifest.json
```

The manifest records:

- manifest format version
- case ID
- evidence file name
- SHA-256 digest
- file size in bytes
- collected timestamp
- source/provider
- event count

Manifest generation happens while the per-case evidence lock is still held, so concurrent writers cannot silently leave a stale digest/event count after a completed merge.

Verify a package with:

```bash
socmind evidence-verify socmind-evidence/INC-2026-001.jsonl
```

JSON output:

```bash
socmind evidence-verify socmind-evidence/INC-2026-001.jsonl --json
```

A mismatch in SHA-256, size, event count, file name, or manifest version returns an invalid result and the CLI exits non-zero.

Case detail also exposes integrity state through:

```text
GET /api/cases/{case_id}
GET /api/cases/{case_id}/evidence-integrity
```

The web Case Workspace surfaces the same state as `VALID`, `INVALID`, manifest missing, or unavailable.

This provides tamper detection for the stored evidence package. It does **not** provide cryptographic signing, trusted timestamping, immutable/WORM storage, or proof of custody outside SOCMind; those require separate controls.

## Milestone 3 — Evidence Requirements

Validation gaps and unresolved investigation questions can now be promoted into explicit operational Evidence Requirements instead of being treated as contradictions.

Requirement states:

```text
required
  -> requested
  -> received

required/requested
  -> unavailable

required/requested/unavailable
  -> waived
```

An unavailable requirement can be requested again later when a source becomes available. `received` and `waived` are terminal states.

SOCMind currently derives deterministic suggestions for common gaps such as:

- IdP authentication / MFA context
- VPN and remote-access history
- parent-process / execution ancestry
- host scope
- change-control / automation context
- persistence creator / approval context

Generation is analyst-triggered. SOCMind does not auto-waive, auto-close, or convert missing evidence into contradicting evidence.

### Integrity and audit rules

- `received` requires an evidence reference/URI.
- `unavailable` requires a documented reason.
- `waived` requires a documented reason and the `evidence.waive` permission.
- creation and status changes are written to the case audit trail.
- duplicate open requirements with the same case/key collapse to the existing requirement.
- SQLite uses a partial unique index and conflict-safe insert semantics.
- PostgreSQL uses the equivalent partial unique index with `ON CONFLICT DO NOTHING`.
- open and overdue requirement counts are visible in the Command Center.

### Permission model

- viewer: read
- analyst: read + create/request
- senior analyst: read + create/request + manage received/unavailable
- lead/admin: all above + waive

Case detail includes `evidence_requirements`, and the web Case Workspace provides generated/manual requirement controls.

## Milestone 4 — Unified Case Timeline

SOCMind now builds a single deterministic operational timeline for each case from persisted case state plus linked investigation evidence.

Every entry exposes:

```text
timestamp
type
source
actor
detail
```

The timeline currently normalizes:

- evidence-event
- detection-event
- alert-received
- case-created
- alert-correlated
- evidence-collected / evidence-collection-failed
- analyst-acknowledged
- assignment
- note
- evidence-requirement / evidence-requirement-updated
- state-transition
- containment
- resolution / false-positive disposition
- escalation
- detection-feedback
- fallback case-action for auditable operations that do not yet have a dedicated type

Case creation vs alert correlation is determined from the persisted `alert-linked` audit payload rather than inferred from a score. Detection timestamps are derived from the last evidence event required to complete the finding.

Analyst escalation and detection feedback are explicit persisted case activities. They are not inferred from exported files:

- escalation requires `case.transition`
- detection feedback requires `detection.review`

Read the normalized timeline directly:

```text
GET /api/cases/{case_id}/timeline
```

The existing case-detail response also includes the same timeline under `case_timeline`.

Entries are sorted in UTC-aware chronological order. Malformed legacy timestamps are handled safely instead of crashing the workspace. The legacy `kind` and `title` fields remain available for compatibility while `type/source/actor/detail` are the canonical operational fields.

## Structured state history

Operational case transitions now expose a dedicated `state_history` payload with:

- from_state
- to_state
- actor
- timestamp
- reason
- original audit detail

The audit trail remains the source of record. The structured history is a normalized read model for analysts and API consumers.

## Advanced case lifecycle

SOCMind now supports a fuller operational lifecycle:

```text
new
  -> triage
  -> investigating
  -> waiting-for-evidence
  -> waiting-for-user
  -> contained
  -> monitoring
  -> resolved / false-positive
```

Allowed transitions are intentionally constrained rather than permitting arbitrary state changes. Waiting cases can return to triage/investigating, move to monitoring when appropriate, or close when the investigation is complete. Contained cases can return to investigating if containment is not sufficient.

### SLA pause/resume

The operational SLA clock pauses only in:

- `waiting-for-evidence`
- `waiting-for-user`

SOCMind persists both the active pause start and accumulated paused seconds. Moving between the two waiting states does not reset the pause. Leaving a waiting state atomically adds the elapsed pause interval to the accumulated total and resumes the SLA clock.

This behavior is implemented consistently for:

- standalone case JSON
- SQLite Command Center
- PostgreSQL enterprise case store
- CLI SLA output
- web Command Center / Case Workspace

Existing SQLite/PostgreSQL stores are migrated in place with nullable/defaulted lifecycle columns. Older case JSON files remain loadable with zero accumulated pause.

Waiting and monitoring cases remain active for alert correlation. Only `resolved` and `false-positive` cases are excluded from new alert attachment.

The Command Center exposes both SLA breach count and paused-SLA count. A case that breached before entering a waiting state remains visibly `BREACHED · PAUSED`; pausing never erases a prior breach.

## Object evidence snapshots

Working evidence packages retain their existing manifest workflow. Before merging
new events, SOCMind now verifies an existing manifest and refuses to re-baseline
modified data. An interrupted evidence/manifest update fails closed and requires
investigation; it is not silently accepted as valid.

Immutable snapshots are a separate artifact API backed by SQLite or PostgreSQL
metadata and a vendor-independent storage protocol. Register and verify:

```bash
socmind artifact-register CASE evidence.jsonl --database socmind.db \
  --evidence-dir objects --source wazuh
socmind artifact-verify CASE --database socmind.db --evidence-dir objects
```

For S3-compatible storage, install `socmind[storage]`, configure credentials using
the SDK credential chain, then replace `--evidence-dir` with `--bucket BUCKET
--endpoint https://objects.example --storage-id production-objects`. The core
only depends on the put/get protocol. The optional adapter uses conditional
writes to prevent overwriting an existing content key. Custom endpoints must
use HTTPS and TLS verification stays enabled. MinIO requires compatible
conditional-write support. No real provider deployment is claimed by unit tests.

Metadata records SHA-256, size, original name, collection timestamp, collector,
source, case and storage identifier. Verification reports verified, mismatch,
missing or unavailable and exits nonzero on failed checks. Each artifact is
limited to 64 MiB. Service-owned directories are required; symlinks are rejected.
A failed metadata transaction may leave an unreferenced immutable object; no
object is silently deleted. Verification detects byte changes, not an attacker
who controls both the database and evidence store. Artifact registration is
explicit and does not replace existing working-file investigation paths.

## Reproducible scenario and load validation

`examples/production-scenarios/manifest.json` describes six synthetic exercises:
password spray/account compromise, Office/PowerShell/C2, Linux SSH/privilege
escalation, scheduled-task persistence, benign administration and a multi-alert
incident. Run `pytest -q tests/test_production_scenarios.py`. Tests exercise
Wazuh/Elastic promotion, idempotency, correlation, evidence collection, findings,
ATT&CK (where findings exist), contradiction review, quality gaps, assignments,
notes, analyst-triggered escalation/disposition/feedback and artifact integrity.
Missing quality items stay visible. Synthetic analyst actions are not automatic
production closure or proof of real-world detection coverage. In particular,
the spray scenario includes a targeted brute-force sequence; the current engine
finds that sequence and does not claim a dedicated distributed-spray detector.

Run `python scripts/benchmark_production_ops.py` from the repository root for
local synthetic analysis and SQLite queue benchmarks. Measured output is in
`docs/validation/production-ops-load-linux.json`, including CPU time, process
peak RSS, 10k/100k/1M events, 100/1k/10k cases, in-process API latency and eight
concurrent workers. API timing excludes networking/TLS; these are not production
capacity guarantees or PostgreSQL scale measurements.

### Alert identity upgrade

Alert identity is now scoped by source. Wazuh and Elastic may use identical
provider IDs without collapsing into one alert. New rows use an internal
SHA-256 storage key and preserve `source_alert_id`; case detail still displays
the provider's original ID. Legacy rows remain readable and idempotent after
an additive schema upgrade. Fallback IDs hash complete normalized event context
instead of only rule plus second. New deterministic case IDs use a 128-bit
suffix. Existing case IDs are not rewritten. Unknown placeholder context does
not justify automatic correlation, and eligible candidates take precedence over
higher-scoring candidates that fail the contextual-anchor policy.

## Native OIDC / SSO

Use `socmind web --auth-mode oidc` with the issuer, client ID and public callback
URI options listed by `socmind web --help`. Supply client and session secrets
through `SOCMIND_OIDC_CLIENT_SECRET` and `SOCMIND_OIDC_SESSION_SECRET`. Configure
claim-to-role mapping explicitly, for example SOC-T1 to analyst, SOC-T2 to
senior-analyst, SOC-Leads to lead and SOC-Admins to admin. Unmapped identities
default to viewer. Local-token and signed trusted-proxy modes remain available.

The implementation verifies signatures, issuer, audience, expiry, nonce and
PKCE/state, uses signed HttpOnly cookies and requires the configured public
Origin for mutations. Tokens are not stored in the repository. Discovery/token/JWKS
redirects are rejected. Sessions expire with the ID token or within eight hours;
central revocation/back-channel logout is not implemented. Generic protocol
and cryptographic tests do not certify a live Entra ID, Keycloak or Okta tenant.

## Upgrade and validation

Back up databases, working evidence, immutable objects and the rule registry
before upgrading. SQLite and PostgreSQL apply additive schema upgrades; legacy
alert IDs and case IDs remain readable. Initialize PostgreSQL with
`socmind postgres-init` before artifact operations. The CLI assumes trusted OS
access; web roles are derived from the configured authentication mode.

CI runs Windows/Ubuntu Python 3.11/3.12, Kali Rolling, PostgreSQL 16, a built
wheel, and an isolated real MinIO server over verified HTTPS. The MinIO fixture
is pinned to upstream commit `7aac2a2c5b7c882e68c1ce017d8256be2feea27f`, which
contains the conditional-create fix missing in the September 2025 release.
Deployments need an equivalent compatible implementation; SOCMind never falls
back to unconditional evidence overwrite.
