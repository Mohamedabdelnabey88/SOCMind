# Changelog

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
