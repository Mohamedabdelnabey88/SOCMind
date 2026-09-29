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


## Milestone 2 — Live Evidence Collector

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
