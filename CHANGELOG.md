# Changelog

## 1.6.0 — Professional Feature Maturity

- technique-aligned Detection Replay with per-technique blind-time metrics
- distinguish static ATT&CK coverage from rules that actually triggered
- operational investigation readiness states: READY / NEEDS_REVIEW / BLOCKED
- explicit analyst sign-off for scope, contradictions, IOC review, persistence and handoff
- per-case quality checklist persistence in SQLite and PostgreSQL
- optional closure enforcement that blocks resolved transitions when required investigation work is incomplete
- explainable case-similarity component scores, thresholds and strength labels
- normalized similarity weights across available evidence dimensions
- case queue filtering and pagination in CLI/Web
- detection rule-pack audit for duplicate IDs, metadata, ATT&CK tags and supported conditions
- Detection What-If now requires rule packs with no audit errors
- SOC Lead web view surfaces rule-pack quality


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
