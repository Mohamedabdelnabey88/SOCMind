# Changelog

## Unreleased — v1.6 Native OIDC / SSO

- add generic OpenID Connect Authorization Code flow with PKCE S256
- discover authorization/token/JWKS endpoints from the configured issuer
- verify ID-token signature, issuer, audience, expiry, nonce and authorized-party semantics
- map a configurable claim (for example groups/roles) to SOCMind RBAC roles
- issue HMAC-signed HttpOnly SOCMind sessions with bounded lifetime and issuer binding
- add native login/callback/logout routes while preserving local-token and trusted-proxy modes
- require HTTPS by default; permit HTTP only for explicit loopback development
- read OIDC client/session secrets from environment variables rather than repository config
- add cryptographic RSA JWT tests and end-to-end FastAPI OIDC session tests
- provider-specific live validation remains deployment-dependent and is not claimed by CI

## Unreleased — v1.6 Detection Rule Lifecycle

- add governed rule states: experimental / testing / approved / production / deprecated / retired
- persist rule version, owner, timestamps, change notes and ATT&CK mapping in an atomic registry
- record syntax validation, regression fixture results, confirmed-incident replay, false-positive observations and coverage deltas
- require all validation evidence before approval or production promotion
- require Lead/Admin authority for approve/deprecate/retire and Lead/Admin promotion authority for production
- keep promotion entirely human-controlled; no automatic approval or production promotion
- add cross-platform file locking, atomic registry writes and symlink guards
- add CLI operations for registration, validation, replay, FP history, coverage, versioning and transitions
- add concurrency, RBAC and promotion-gate regression tests

## Unreleased — v1.6 Unified Case Timeline

- add one normalized operational timeline across detections, evidence, alerts and analyst actions
- standardize every timeline entry with timestamp, type, source, actor and detail
- distinguish alert received, case created and alert correlated events using persisted orchestration audit data
- derive detection-event timestamps from the evidence that completed each finding
- classify acknowledgement, assignment, state transition, containment and resolution events
- persist permission-controlled escalation and detection-feedback activities
- add a read-only case timeline API endpoint
- expose normalized source/actor/type fields in the Case Workspace
- preserve backward-compatible kind/title fields and alert correlation detail
- add deterministic ordering, malformed-timestamp safety and duplicate-note regression tests
- validate SQLite, PostgreSQL and trusted-proxy RBAC paths

## Unreleased — v1.6 Evidence Requirements

- convert validation gaps and unresolved questions into explicit Evidence Requirements
- add requirement lifecycle: required / requested / received / unavailable / waived
- keep missing evidence separate from contradicting evidence
- require an evidence reference before marking a requirement received
- require documented rationale before unavailable or waived disposition
- add permission-controlled request/manage/waive operations
- persist requirements in SQLite and PostgreSQL with open-requirement idempotency
- expose open/overdue requirement counts in the Command Center
- add Case Workspace controls for generated and manual requirements
- add structured state history with actor, timestamp, from/to state and reason
- validate requirement concurrency, lifecycle, RBAC, SQLite and PostgreSQL paths

## Unreleased — v1.6 Advanced Case Lifecycle

- add waiting-for-evidence, waiting-for-user and monitoring operational states
- enforce explicit lifecycle transition rules across file, SQLite and PostgreSQL case flows
- pause SLA time only while waiting on evidence or user input
- accumulate pause duration across waiting-state changes and resume atomically
- preserve prior SLA breach visibility while paused
- add migration-safe SQLite/PostgreSQL lifecycle columns and legacy JSON compatibility
- keep waiting/monitoring cases eligible for active alert correlation
- expose paused-SLA status and KPI in CLI and web Command Center
- add lifecycle, migration, pause/resume, web and correlation regression tests
- harden CI dependency installs against transient package-download failures

## Unreleased — v1.6 Evidence Integrity

- generate atomic SHA-256 sidecar manifests for case evidence packages
- record case ID, evidence filename, digest, size, collection timestamp, source and event count
- generate manifests while the per-case evidence lock remains held
- verify evidence with `socmind evidence-verify` and non-zero exit on mismatch
- expose evidence integrity through case details and a dedicated read-only API endpoint
- surface VALID/INVALID/missing-manifest state in the Case Workspace
- add tamper-detection tests and cross-platform CI exercise

## Unreleased — v1.6 Live Alert Ingestion

- pull Elastic Security alerts directly into the case-orchestration pipeline
- pull Wazuh Indexer `wazuh-alerts*` hits directly without temporary exports
- support current Elastic Security `kibana.alert.*` rule, severity, risk and ATT&CK metadata
- preserve Wazuh MITRE technique metadata from indexed alerts
- isolate Elastic and Wazuh Indexer authentication environments
- use provider-specific timestamp sorting
- validate live HTTP search → normalization → case creation end to end
- expand correlation/evidence boundary regression coverage


## Unreleased — v1.6 Live Evidence Collector

- derive live evidence queries from alerts already linked to a case
- collect surrounding telemetry from Elastic or Wazuh Indexer/OpenSearch-compatible APIs
- normalize live search hits through the same ECS adapter used for offline ingestion
- merge live results into the existing case evidence package
- journal provider, source index, time window, generated query, status and event count
- preserve provider failures as explicit failed collection records
- surface collection history in case detail and the unified operational timeline
- support SQLite and PostgreSQL case stores
- keep TLS verification enabled by default and credentials in environment variables


## 1.6.0 — Production SOC Operations — Milestone 1

- Wazuh/Elastic alert promotion into operational SOC cases
- deterministic source-alert IDs and idempotent duplicate handling
- explainable alert correlation with configurable threshold/window
- automatic case creation or active-case attachment
- case priority escalation from higher-severity correlated alerts
- contextual evidence-window collection and event deduplication
- concurrent-safe orchestration for SQLite and PostgreSQL
- per-case evidence file locking
- PostgreSQL alert/case-correlation schema
- Alert Chain in web case detail with exact correlation reasons
- CLI workflow: `socmind alert-orchestrate`
- CI coverage across Windows, Ubuntu, Kali, packaged wheel and PostgreSQL 16


## Unreleased — Feature Maturity Upgrade

- per-technique detection timing and visibility in Investigation Replay
- explainable rule contribution metrics
- applicability-aware Investigation Quality Gate
- explicit analyst-confirmation markers
- normalized historical similarity across comparable evidence dimensions
- similarity confidence bands and evidence-breadth reporting
- provenance for contradiction / alternative-context evidence
- detection-health sample sufficiency and Wilson FP-rate confidence intervals
- SOC Lead health states: stable / watch / noisy / insufficient-data
- web UI surfaces maturity and uncertainty signals directly


## Unreleased — Professional Readiness Audit

- keep IRE replay/quality/reasoning usable when RBAC denies Detection What-If
- add short-lived timestamped trusted-proxy signatures to reduce replay risk
- serialize tamper-evident audit writes across concurrent workers
- prevent retention from following symlinked artifacts outside its root
- prevent SQLite backup self-overwrite
- serialize PostgreSQL and SQLite case-state transitions
- restrict live integration URLs to HTTP/HTTPS
- normalize low-level socket failures into SOCMind HTTP client errors
- remove obsolete client-supplied actor/author fields from web mutations
- add regression tests for concurrency, proxy replay, URL schemes and retention boundaries


## 1.5.0 — Enterprise Foundation

- role-based access control for viewer/analyst/senior-analyst/lead/admin
- signed trusted-proxy identity mode
- PostgreSQL-backed case operations
- PostgreSQL initialization and readiness CLI
- tamper-evident hash-chained enterprise audit
- consistent SQLite backup using the native backup API
- retention dry-run/apply tooling
- enterprise deployment documentation
- real PostgreSQL CI validation


## 1.4.0 — Evidence Contradiction & Case Similarity

- explicit contradiction/alternative-context review
- separate validation gaps from contradicting evidence
- unresolved analyst questions per hypothesis
- deterministic historical case fingerprints
- explainable weighted case similarity
- ATT&CK/event/process/IOC overlap explanations
- no-attribution interpretation guardrails
- web reasoning panels and APIs
- guided CLI help for evidence reasoning


## 1.3.0 — Investigation Replay Engine

- step-by-step investigation replay
- deterministic hypothesis-confidence deltas
- incident-specific detection replay
- first-detection-step measurement
- blind-step analysis
- incident visibility percentage
- current-vs-proposed detection What-If comparison
- investigation quality gate
- case-to-detection regression package generator
- experimental candidate-rule generation with validation checklist
- IRE web dashboard and APIs
- regression test preventing duplicate PowerShell findings from network events


## 1.2.0 — Hardening & Portfolio Release

- secure remote-bind guard
- HTTP security headers
- SQLite WAL/busy-timeout reliability settings
- input bounds for analyst actions
- `security-check` CLI
- repeatable `benchmark` CLI
- packaging/release validation
- security policy and contribution guide
- final portfolio/release documentation

## 1.1.0 — Live Integrations & Guided CLI

- task-oriented `socmind help`
- `socmind doctor`
- Wazuh Server API connectivity and agents
- Elasticsearch live search/export
- MISP live IOC enrichment
- OpenCTI GraphQL transport
- TLS verification by default

## 1.0.0 — Real SOC Workspace

- interactive multi-case web workspace
- search and filters
- case acknowledgement/assignment/transitions
- notes and persistent audit trail
- evidence-linked cases
- optional API token
- ready-to-run demo

## 0.9.0 — SOC Lead & Detection Health

- TP/FP ratios
- noisy-rule detection
- ATT&CK coverage
- shift brief
- SOC Lead dashboard

## 0.8.0 — Multi-Case Command Center

- queue, SLA, workload, MTTA and MTTR

## 0.7.0 — Web Investigation Dashboard

- browser workbench and interactive evidence graph
- real SOC case workflow and investigation packages

### v1.6 continuation (unreleased)

- Reconcile the production-operations branch with the OIDC, rule-lifecycle,
  timeline, requirements and lifecycle work already merged into main.
- Add immutable local/S3-compatible artifact storage with SQLite/PostgreSQL
  metadata, SHA-256 verification and explicit collector provenance.
- Refuse to merge new evidence over a working file that fails its recorded hash.
- Add six synthetic SOC workflow scenarios and reproducible local load results.
- Display host, user, process and priority in correlated-alert details.
