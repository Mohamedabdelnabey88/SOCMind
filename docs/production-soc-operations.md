# SOCMind v1.6 — Production SOC Operations (Milestone 1)

This milestone introduces the first production-style alert orchestration path:

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

## Live alert pull

Elastic Security alert alias:

```bash
export ELASTIC_API_KEY='...'

socmind alert-live elastic https://elastic:9200 \
  .alerts-security.alerts-default \
  --database socmind.db \
  --evidence-dir socmind-evidence \
  --json
```

Wazuh Indexer:

```bash
export WAZUH_INDEXER_USERNAME='...'
export WAZUH_INDEXER_PASSWORD='...'

socmind alert-live wazuh-indexer https://wazuh-indexer:9200 \
  'wazuh-alerts*' \
  --database socmind.db \
  --evidence-dir socmind-evidence \
  --json
```

JWT is also supported through `WAZUH_INDEXER_JWT`.

The live path queries the search API and feeds returned hits directly into the same duplicate/correlation/case/evidence pipeline used by file orchestration. No temporary export file is required.

TLS certificate verification is enabled by default. `--insecure` is intended only for controlled lab systems with self-signed certificates.

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

The score alone does not trigger an automatic merge. SOCMind also applies a conservative context-anchor policy:

- same host must be accompanied by at least one shared user, process, source IP, or destination IP; or
- cross-host correlation requires at least two shared context anchors among user, process, source IP, and destination IP.

Rule/technique similarity can strengthen a correlation score, but by itself it cannot justify automatic case merging. This intentionally prefers a false split over a false merge when evidence is weak.

Default correlation time window: `15 minutes`.

Both are configurable:

```bash
--correlation-window 20
--correlation-threshold 65
```

The score is deterministic correlation evidence. It is **not attacker attribution** and it is not a probability that two alerts share a root cause.

Candidate lookup is bounded by both the correlation time window and shared context anchors before scoring. This avoids a global “last N alerts” scan and keeps relevant cases discoverable during unrelated alert floods.

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

Case detail now includes an **Alert Chain**.

An analyst can review every linked alert and the exact reasons it was associated with the case.

This keeps correlation explainable and auditable instead of becoming an opaque grouping engine.

## Production boundaries

This milestone does not yet claim:

- streaming webhook receivers
- Kafka/queue ingestion
- remote evidence collection from endpoints
- object-storage evidence backend
- native OIDC
- full detection-rule lifecycle

Those are subsequent v1.6 production-operations milestones.

The current milestone establishes the case-orchestration core they can safely build on.

## Advanced lifecycle (in progress)

The existing lifecycle now includes `waiting-for-evidence`, `waiting-for-user`,
and `monitoring`. Waiting states return to triage/investigation; containment
can progress to monitoring or return to investigation. Terminal states remain
terminal. Waiting and monitoring require a nonempty reason. Existing transitions
remain compatible with older CLI clients; the workspace requests a reason for
all transitions. State audit entries retain actor, timestamp, old/new state and
supplied reason in the same transaction as the update. SQLite uses BEGIN
IMMEDIATE and PostgreSQL uses a row lock. Case detail advertises allowed next
states; the workspace only offers those states.

Use `socmind command-transition DB CASE --state waiting-for-evidence --reason
"IdP logs requested" --actor lead` after triage. Timeline entries expose type,
source and actor; timezone offsets are normalized to UTC for ordering.

This increment does not complete the remaining v1.6 milestones or authorize a
final release. PostgreSQL regressions run in the PostgreSQL 16 CI job.

## Evidence requirements API

`GET/POST /api/cases/{case_id}/requirements` lists or creates requirements.
Creation accepts `label` and `origin`; repeated identical requirements are
idempotent. `POST /api/cases/{case_id}/requirements/{requirement_id}` takes
`state`, `reason`, optional `expected_state`, and `evidence_reference` when
receiving evidence. States are required, requested, received, unavailable and
waived. A waiver requires case.transition permission; ordinary requests require
case.note. Missing/unavailable evidence is not fed into contradiction scoring.
The Python `requirements_from_quality` adapter creates requirements from
applicable, incomplete quality items. References are analyst assertions, not
automatically verified artifact records. All changes are transactionally audited.

## Immutable evidence artifacts (initial implementation)

`socmind evidence-register CASE path --database socmind.db --evidence-dir objects
--source IdP` copies a regular file into a content-addressed local store and
records SHA-256, byte count, original name, collection time, collector, source,
case and storage identifier. Repeated registration is idempotent. Original files
are not overwritten. `socmind evidence-verify CASE --database socmind.db
--evidence-dir objects` reports verified, mismatch, missing or unavailable and
returns exit code 1 on failed verification. Both accept `--postgres-dsn`.

Artifacts are limited to 64 MiB per file. Local roots must be service-owned;
symlinks are rejected. These hashes detect content changes, not a malicious
administrator rewriting both metadata and data. The mutable orchestration
working file remains separate; explicit registration creates an immutable
snapshot. A failed metadata transaction can leave an unreferenced object;
objects are never automatically deleted.

The SDK-independent EvidenceStore protocol includes local and injected-client
S3 adapters. The S3 adapter requires conditional PutObject (`IfNoneMatch=*`),
which prevents overwriting existing keys. Its unit tests use a simulated client;
real S3/MinIO integration and deployment configuration remain release gates.
