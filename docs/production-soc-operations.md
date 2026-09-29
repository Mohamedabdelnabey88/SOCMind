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


## Milestone 2 — Evidence Requests & Advanced Case Lifecycle

SOCMind now turns investigation validation gaps into operational evidence work.

```text
Validation Gap
      ↓
Evidence Suggestion
      ↓
Tracked Evidence Request
      ↓
Assigned Team / Due Time
      ↓
Pending → In Progress → Fulfilled
      ↓
Evidence Reference + Response Summary
      ↓
Investigation Re-evaluation
```

Generate suggestions from normalized case evidence:

```bash
socmind evidence-suggest examples/attack_chain.jsonl --json
```

The web case workspace can create suggested requests automatically. Open requests are idempotent per case/key, so repeatedly generating suggestions does not create duplicate work items.

Request states:

- `pending`
- `in-progress`
- `fulfilled`
- `cancelled`

Terminal requests cannot be reopened.

Case lifecycle now includes:

- `waiting-for-evidence`
- `waiting-for-user`
- `monitoring`

The Command Center reports open and overdue evidence requests at both shift and case level.

Evidence requests are supported in SQLite and PostgreSQL, are RBAC protected, and create case-audit events. Fulfilled requests can record a response summary and evidence URI/reference.
