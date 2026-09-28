# SOCMind

![CI](https://github.com/Mohamedabdelnabey88/SOCMind/actions/workflows/ci.yml/badge.svg)

**SOCMind** is an open-source, cross-platform SOC Tier 1 / Tier 2 investigation and detection-engineering workbench for **Windows, Linux, and Kali Linux**.

It connects the SOC lifecycle end to end:

```text
Telemetry / SIEM
      ↓
Normalization
      ↓
Detection
      ↓
T1 Triage
      ↓
T2 Investigation
      ↓
Enrichment / Notes / Handoff
      ↓
Disposition
      ↓
Coverage / Gap Analysis / Tuning
```

> **v1.6 — Professional Feature Maturity**

SOCMind is not a SIEM replacement. It is an analyst investigation, escalation, and detection-quality layer.

## Platforms

SOCMind is continuously validated on:

- Windows + Python 3.11 / 3.12
- Ubuntu + Python 3.11 / 3.12
- **Kali Linux Rolling** inside the official `kalilinux/kali-rolling` container
- Web dashboard smoke-tested on Kali Linux CI

## Kali Linux quick start

Modern Kali protects the system Python environment, so do **not** use `sudo pip install`.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
cd SOCMind

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[all]"
```

Verify:

```bash
socmind --help
pytest -q
```

Run a full Kali investigation:

```bash
socmind analyze examples/linux_attack_chain.jsonl \
  --timeline \
  --iocs \
  --graph \
  --hypotheses \
  --case-output kali-case.json \
  --case-id KALI-DEMO-001
```

Detailed guide: [Running SOCMind on Kali Linux](docs/kali-linux.md)

## v1.6 Professional Feature Maturity

v1.6 deepens existing SOCMind workflows instead of adding disconnected features.

### Detection Replay is now incident-aware

SOCMind now separates:

- `detected` — a technique-mapped rule actually matched relevant evidence
- `covered-not-triggered` — a rule exists for the technique but did not fire on this incident
- `gap` — no local rule covers the observed technique

It also reports first observed/detected steps, blind seconds per ATT&CK technique, and time to first meaningful detection.

### Investigation quality now controls closure

The Quality Gate now returns:

```text
READY
NEEDS_REVIEW
BLOCKED
```

Quality sign-off is stored **per case** with the authenticated actor and timestamp in SQLite or PostgreSQL.

Optional enforcement:

```bash
socmind web events.jsonl \
  --command-db socmind.db \
  --enforce-quality-on-close
```

When enabled, `resolved` is rejected until required investigation checks pass.

### Historical similarity is explainable

```bash
socmind similar-cases events.jsonl \
  --database socmind.db \
  --min-score 40 \
  --limit 10
```

Results expose component scores for ATT&CK, event IDs, processes and IOCs, plus weak/moderate/strong match strength.

### Case Queue pagination

```bash
socmind command-center socmind.db \
  --priority P1 \
  --limit 25 \
  --offset 0
```

The Web Workspace has previous/next queue navigation and matched-result counts.

### Detection Rule Pack Audit

```bash
socmind rule-pack-audit --rules detections
```

The audit checks duplicate IDs, metadata, ATT&CK tag syntax, false-positive documentation, logsource and supported condition structure. Detection What-If refuses rule packs containing audit errors.

Detailed guide: [Professional Feature Maturity](docs/professional-feature-maturity.md)

## v1.5 Enterprise Foundation

SOCMind now supports a team-oriented enterprise foundation while preserving SQLite for local/demo use.

### RBAC

Built-in roles:

- viewer
- analyst
- senior-analyst
- lead
- admin

Inspect them:

```bash
socmind enterprise-info
```

### PostgreSQL case store

```bash
pip install -e ".[enterprise,web,sigma]"

export SOCMIND_POSTGRES_DSN='postgresql://socmind:password@db:5432/socmind'

socmind postgres-init
socmind postgres-health
```

The Web Workspace can run its case queue, notes, assignments, lifecycle transitions, SLA/MTTA/MTTR and evidence-linked similarity on PostgreSQL:

```bash
socmind web events.jsonl \
  --postgres-dsn "$SOCMIND_POSTGRES_DSN"
```

### Trusted enterprise identity

SOCMind can run behind an authenticating reverse proxy / identity-aware gateway using signed headers:

```bash
export SOCMIND_TRUSTED_PROXY_SECRET='shared-secret'

socmind web events.jsonl \
  --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
  --auth-mode trusted-proxy \
  --enterprise-audit enterprise-audit.jsonl \
  --host 0.0.0.0
```

Identity is mapped to RBAC roles and mutating actions use the authenticated subject as the audit actor. Trusted-proxy signatures include a short-lived timestamp; the authenticating proxy must strip client-supplied `X-SOCMind-*` identity headers and generate fresh signed headers itself.

### Tamper-evident audit

```bash
socmind audit-verify enterprise-audit.jsonl
```

### Backup and retention

```bash
socmind backup socmind.db -o backups/socmind.db
socmind retention ./exports --days 90
socmind retention ./exports --days 90 --apply
```

Retention is dry-run by default.

Detailed guide: [Enterprise Foundation](docs/enterprise-foundation.md)

## v1.4 Evidence Contradiction & Case Similarity

SOCMind now adds an analyst reasoning layer designed to reduce confirmation bias and reuse prior investigation knowledge.

Review supporting evidence, explicit alternative context, validation gaps, and unresolved questions separately:

```bash
socmind contradictions examples/attack_chain.jsonl
```

Find explainable historical cases:

```bash
socmind similar-cases examples/attack_chain.jsonl \
  --database socmind-demo/socmind-demo.db \
  --limit 5
```

Case similarity is based on deterministic overlap across:

- ATT&CK techniques
- event IDs
- processes
- IOC values

A similarity score means evidence/behavior overlap. It does **not** claim the same attacker, campaign, malware, or root cause.

Detailed guide: [Evidence Contradiction & Case Similarity](docs/evidence-contradiction-case-similarity.md)

## v1.3 Investigation Replay Engine (IRE)

SOCMind now closes the loop between incident investigation and detection engineering.

```text
Incident
  ↓
Investigation
  ↓
Investigation Replay
  ↓
Detection Replay
  ↓
Blind-Spot Analysis
  ↓
Detection What-If
  ↓
Regression Package
  ↓
Improved Detection Pack
  ↺
```

Replay how evidence changed the investigation:

```bash
socmind replay examples/attack_chain.jsonl
```

Measure when the current detection pack first gained visibility:

```bash
socmind detection-replay examples/attack_chain.jsonl --rules detections
```

Compare the same incident against a proposed pack:

```bash
socmind what-if examples/attack_chain.jsonl \
  --current-rules detections \
  --proposed-rules examples/proposed-rules
```

Review investigation completeness without scoring the analyst:

```bash
socmind case-review examples/attack_chain.jsonl \
  --checklist examples/quality-checklist.json
```

Turn a confirmed case into a reusable detection regression package:

```bash
socmind learn-from-case examples/attack_chain.jsonl \
  --rules detections \
  --case-id INC-001 \
  -o regression-pack
```

The IRE web tab shows first detection, blind steps, incident visibility, gaps, What-If improvements, quality-gate results, and the reasoning replay timeline.

Detailed guide: [Investigation Replay Engine](docs/investigation-replay-engine.md)

## v1.2 Hardening & Release Quality

The final planned portfolio stage adds operational hardening and release validation:

- remote web binds are refused without API protection by default
- `SOCMIND_API_TOKEN` is the preferred way to provide the local API token
- CSP, anti-framing, no-sniff, no-referrer and no-store web headers
- SQLite WAL mode, busy timeout and concurrency-friendly settings
- bounded analyst input fields
- `socmind security-check`
- deterministic `socmind benchmark`
- wheel/package installation validation in CI
- SECURITY, CONTRIBUTING and CHANGELOG documents

Security posture:

```bash
socmind security-check
socmind help security
```

Performance comparison:

```bash
socmind benchmark --events 5000
socmind benchmark --events 10000 --json
socmind help performance
```

For remote binding, prefer an environment variable so the token is not exposed in the process command line:

```bash
export SOCMIND_API_TOKEN='replace-with-a-strong-token'

socmind web examples/attack_chain.jsonl \
  --command-db socmind-demo/socmind-demo.db \
  --host 0.0.0.0
```

Detailed release guide: [SOCMind 1.2 Hardened Portfolio Release](docs/release-v1.2.md)

## v1.1 Live Integrations & Guided CLI

SOCMind can now connect to live SOC infrastructure while keeping credentials out of command-line password arguments.

### Guided help

```bash
socmind help
socmind help getting-started
socmind help triage
socmind help case-workflow
socmind help integrations
socmind help detection-engineering
socmind help kali
socmind help demo
```

Every command also has command-specific help:

```bash
socmind elastic-pull --help
socmind wazuh-agents --help
```

Check the local installation:

```bash
socmind doctor
```

### Wazuh live API

```bash
export WAZUH_API_USER=soc-analyst
export WAZUH_API_PASSWORD='...'

socmind wazuh-check https://wazuh-manager:55000
socmind wazuh-agents https://wazuh-manager:55000 --limit 50
```

### Elastic live search

```bash
export ELASTIC_API_KEY='...'

socmind elastic-pull https://elastic:9200 'logs-*' \
  -o elastic.ndjson \
  --size 500
```

### MISP

```bash
export MISP_API_KEY='...'
socmind misp-enrich normalized.jsonl https://misp.internal
```

### OpenCTI

```bash
export OPENCTI_TOKEN='...'
socmind opencti-check https://opencti.internal
```

TLS verification is enabled by default. Use `--insecure` only for controlled self-signed lab environments.

Detailed guide: [Live Integrations & CLI Help](docs/live-integrations.md)

## v1.0 Real SOC Workspace

v1.0 turns SOCMind into an interactive local SOC workspace rather than a read-only dashboard.

### Interactive operations

- search/filter the multi-case queue
- open a case from the queue
- inspect linked evidence
- acknowledge a case
- assign/reassign an analyst
- transition case state
- write analyst notes
- review the audit trail
- preserve MTTA/MTTR/SLA metrics
- optional API token protection

### Fast recruiter / interview demo

```bash
socmind demo-init -o socmind-demo
```

Then launch:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id DEMO-P1-001 \
  --command-db socmind-demo/socmind-demo.db \
  --rules detections \
  --dispositions examples/dispositions.jsonl
```

Open:

```text
http://127.0.0.1:8765
```

The demo creates three realistic cases: active P1, unassigned P2, and a resolved P3, with linked Windows/Linux evidence and analyst notes.

### Optional API protection

For a protected local/API demo:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id DEMO-P1-001 \
  --command-db socmind-demo/socmind-demo.db \
  --api-token "change-this-token"
```

Use the **API Token** button in the UI to enter the token. The token is kept only in browser session storage.

Detailed guide: [v1.0 Real SOC Workspace](docs/v1-real-soc-workspace.md)

## Web Investigation Dashboard

SOCMind now includes a local browser-based investigation workbench with:

- executive investigation metrics
- prioritized T1/T2 findings
- evidence-based hypotheses
- interactive draggable evidence graph
- event timeline
- extracted IOCs
- observed MITRE ATT&CK techniques
- local FastAPI endpoint for future integrations

Install:

```bash
pip install -e ".[web]"
```

Launch:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id DEMO-001
```

Then open:

```text
http://127.0.0.1:8765
```

Kali Linux:

```bash
source .venv/bin/activate
pip install -e ".[all]"

socmind web examples/linux_attack_chain.jsonl \
  --case-id KALI-DEMO-001
```

The dashboard binds to `127.0.0.1` by default so investigation data is not exposed to the network accidentally.

Detailed guide: [Web Investigation Dashboard](docs/web-dashboard.md)

## SIEM integrations

### Wazuh

```bash
socmind ingest wazuh alerts.jsonl -o normalized.jsonl
```

### Elastic ECS

```bash
socmind ingest elastic events.ndjson -o normalized.jsonl
```

Both feed the same normalized investigation pipeline.

## Threat Intelligence enrichment

v0.6 introduces a provider interface. The included provider is offline/local so demos do not require API keys:

```bash
socmind enrich normalized.jsonl \
  --local-intel examples/local-intel.json
```

This clean separation lets future providers integrate VirusTotal, MISP, OpenCTI, AbuseIPDB, or internal intelligence without coupling them to the investigation engine.

## Analyst notes and dispositions

```bash
socmind note analyst-notes.jsonl \
  --case-id INC-2026-001 \
  --author analyst1 \
  --text "Validated source IP against VPN inventory." \
  --disposition needs-review
```

Notes are append-only JSONL so they remain transparent, portable, and easy to integrate later.

## Tier 2 / IR escalation package

```bash
socmind escalate normalized.jsonl \
  --case-id INC-2026-001 \
  -o escalation.md
```

The Markdown handoff package includes:

- executive summary
- findings and scores
- P1/P2/P3 context
- ATT&CK techniques
- IOC list
- investigation hypotheses
- recommended handoff actions

## Existing investigation capabilities

- Windows EVTX/XML
- Linux auth.log / secure
- journald
- auditd
- Wazuh JSON alerts
- Elastic ECS NDJSON
- Windows authentication correlation
- SSH authentication correlation
- suspicious PowerShell analysis
- Windows/Linux persistence analysis
- MITRE ATT&CK mapping
- IOC extraction
- process ancestry
- evidence timeline
- investigation graph
- hypothesis model
- reusable playbooks
- structured case JSON

## Real SOC operations

SOCMind now models the operational work around an investigation, not only the technical detection.

### Case lifecycle

```text
New → Triage → Investigating → Contained → Resolved
                 └────────────→ False Positive
```

Create and assign a case:

```bash
socmind case-init case.json \
  --case-id INC-2026-001 \
  --priority P1 \
  --owner analyst1

socmind case-transition case.json --state triage
socmind case-assign case.json --owner tier2-analyst
```

Check SLA:

```bash
socmind sla case.json
```

Fingerprint evidence:

```bash
socmind evidence normalized.jsonl
```

Create a shift handoff:

```bash
socmind handoff normalized.jsonl \
  --case-id INC-2026-001 \
  -o shift-handoff.md
```

Record analyst actions:

```bash
socmind audit analyst-audit.jsonl \
  --case-id INC-2026-001 \
  --actor tier2-analyst \
  --action investigated \
  --detail "Validated authentication, process, and network evidence."
```

These workflows demonstrate ownership, escalation discipline, SLA awareness, evidence provenance, shift continuity, and analyst accountability — the operational skills expected in a production SOC.

Detailed guide: [Real SOC Workflow Model](docs/real-soc-workflow.md)

## Multi-Case SOC Command Center

SOCMind now adds the shift-level view expected in a real SOC:

- case queue across multiple investigations
- P1 visibility
- SLA breach tracking
- unassigned-case detection
- analyst workload
- MTTA (Mean Time To Acknowledge)
- MTTR (Mean Time To Resolve)

Register and acknowledge a case:

```bash
socmind command-register socmind.db case.json \
  --source wazuh \
  --title "Authentication followed by suspicious execution"

socmind command-ack socmind.db INC-2026-001
socmind command-center socmind.db
```

Launch the dashboard with the queue:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id INC-2026-001 \
  --command-db socmind.db
```

Detailed guide: [SOC Command Center](docs/soc-command-center.md)

## SOC Lead & Detection Health

SOCMind now adds a shift-lead view focused on the quality of detections and the health of the SOC workflow:

- ATT&CK coverage for observed techniques
- TP / FP ratios from analyst dispositions
- noisy detection identification
- explainable per-rule health score
- top users and hosts by event concentration
- shift brief combining operations + detection health

CLI:

```bash
socmind lead-health examples/attack_chain.jsonl \
  --rules detections \
  --dispositions examples/dispositions.jsonl

socmind shift-brief socmind.db examples/attack_chain.jsonl \
  --rules detections \
  --dispositions examples/dispositions.jsonl \
  -o shift-brief.md
```

Web:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id INC-2026-001 \
  --command-db socmind.db \
  --rules detections \
  --dispositions examples/dispositions.jsonl
```

Detailed guide: [SOC Lead & Detection Health](docs/soc-lead-detection-health.md)

## Detection engineering

SOCMind also includes:

- Sigma-style YAML rule loading
- rule execution against normalized events
- ATT&CK coverage matrix
- detection-gap finder
- rule regression fixtures
- analyst-disposition-based tuning feedback

Examples:

```bash
socmind detect detections/windows/suspicious-powershell.yml \
  tests/fixtures/rule-events.jsonl

socmind coverage examples/attack_chain.jsonl --rules detections

socmind gaps examples/attack_chain.jsonl --rules detections

socmind tune examples/dispositions.jsonl
```

## One-command investigation workspace

For a realistic analyst workflow, SOCMind can build a complete investigation package from normalized telemetry:

```bash
socmind investigate examples/attack_chain.jsonl \
  -o demo-case \
  --case-id DEMO-001 \
  --priority P1 \
  --owner mohamed
```

The workspace contains:

```text
demo-case/
├── case-state.json
├── case.json
├── escalation.md
├── shift-handoff.md
├── evidence-provenance.json
└── workspace-summary.json
```

This is useful for both real analyst handoff and a portfolio demonstration because it shows the complete path from telemetry to a documented, attributable investigation.

## Full investigation workflow

```bash
socmind analyze normalized.jsonl \
  --timeline \
  --iocs \
  --graph \
  --process-tree \
  --hypotheses \
  --case-output case.json \
  --case-id INC-2026-001
```

## Documentation

- [Architecture](docs/architecture.md)
- [Tier 2 Workbench](docs/tier2-workbench.md)
- [Detection Engineering](docs/detection-engineering.md)
- [SOC Integrations](docs/soc-integrations.md)
- [Kali Linux](docs/kali-linux.md)
- [Case 001](docs/cases/case-001-authentication-to-persistence.md)
- [Real SOC Workflow](docs/real-soc-workflow.md)
- [Portfolio / Interview Story](docs/portfolio-story.md)
- [SOC Command Center](docs/soc-command-center.md)
- [SOC Lead & Detection Health](docs/soc-lead-detection-health.md)
- [v1.0 Real SOC Workspace](docs/v1-real-soc-workspace.md)
- [Live Integrations & CLI Help](docs/live-integrations.md)
- [CLI Reference](docs/cli-reference.md)
- [1.2 Hardened Portfolio Release](docs/release-v1.2.md)
- [Investigation Replay Engine](docs/investigation-replay-engine.md)
- [Evidence Contradiction & Case Similarity](docs/evidence-contradiction-case-similarity.md)
- [Enterprise Foundation](docs/enterprise-foundation.md)
- [Professional Feature Maturity](docs/professional-feature-maturity.md)

## CI quality gate

Every pull request validates:

- package installation
- compilation
- automated tests
- Windows investigation workflow
- Linux investigation workflow
- Wazuh parsing
- Elastic ECS parsing
- threat-intel enrichment
- analyst notes
- escalation package generation
- Sigma-style detection rules
- rule regression tests
- ATT&CK coverage and gaps
- false-positive tuning
- **Kali Rolling installation and execution**

## Roadmap

The initial portfolio roadmap is complete through **v1.2**. **v1.3** adds SOCMind's signature investigation-to-detection feedback loop. **v1.4** adds contradiction-aware reasoning and explainable historical case reuse.

v1.5 adds the enterprise foundation: RBAC, trusted-proxy identity, PostgreSQL case storage, tamper-evident audit, backup and retention tooling.

v1.6 matures the existing investigation, detection and case-operation features with per-case quality enforcement, technique-aligned replay, explainable similarity, queue pagination and rule-pack audit.

Future expansion remains organization-specific:

- native OIDC/SAML login and automated IdP group mapping
- Kubernetes/HA deployment and PostgreSQL failover
- centralized immutable audit shipping
- secrets-manager integrations
- ticketing and SOAR connectors
- larger detection packs and regression corpus

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Safety

SOCMind is a defensive Blue Team project. Samples use documentation-only IP ranges and contain no real credentials, malware, or production customer data.

## License

MIT
