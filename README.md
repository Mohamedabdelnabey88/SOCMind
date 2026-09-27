# SOCMind

**SOCMind** is an open-source, cross-platform workbench for **SOC Tier 1 / Tier 2 analysts** on Windows and Linux.

It connects the operational SOC loop end to end:

```text
Telemetry
   ↓
Detection
   ↓
T1 Triage
   ↓
T2 Investigation
   ↓
Disposition
   ↓
Detection Feedback
   ↓
Rule Test / Coverage / Tuning
```

> **v0.5 — Detection Engineering Feedback Loop**

SOCMind is not a SIEM replacement. It is an analyst investigation and detection-quality layer.

## Core capabilities

### T1 / T2 investigation
- Windows EVTX/XML, Sysmon-shaped events and PowerShell
- Linux auth.log, journald and auditd
- evidence correlation
- P1/P2/P3 triage
- MITRE ATT&CK mapping
- IOC extraction
- evidence timeline
- process ancestry
- investigation graph
- evidence-based hypotheses
- reusable playbooks
- portable case JSON

### Detection engineering
- Sigma-style YAML rule loading
- normalized-event rule execution
- ATT&CK coverage matrix
- detection-gap analysis
- repeatable rule fixtures
- false-positive tuning suggestions from analyst dispositions

See:
- [Architecture](docs/architecture.md)
- [Tier 2 Workbench](docs/tier2-workbench.md)
- [Detection Engineering](docs/detection-engineering.md)
- [Case 001](docs/cases/case-001-authentication-to-persistence.md)

## Sigma interoperability

SOCMind v0.5 supports a deliberately documented Sigma-compatible subset.

Supported modifiers:
- `contains`
- `startswith`
- `endswith`

Supported conditions:
- one named selection
- simple `selection_a and selection_b`
- simple `selection_a or selection_b`

Unsupported syntax fails explicitly instead of being silently interpreted.

Install Sigma YAML support:

```bash
pip install -e ".[sigma]"
```

Evaluate a rule:

```bash
socmind detect detections/windows/suspicious-powershell.yml \
  tests/fixtures/rule-events.jsonl
```

## Detection coverage and gap finder

SOCMind compares ATT&CK techniques observed during an investigation with ATT&CK tags in the local rule pack.

```bash
socmind coverage examples/attack_chain.jsonl --rules detections
```

Example concept:

```text
Technique     Observed  Covered
T1059.001     yes       yes
T1053.005     yes       yes
T1110         yes       no
T1078         yes       no
```

Show only uncovered observed techniques:

```bash
socmind gaps examples/attack_chain.jsonl --rules detections
```

A reported gap means **the local rule pack does not currently cover that observed ATT&CK technique**. It is not proof the technique cannot be detected.

## Rule tests

Detection behavior is locked to sanitized fixtures.

```bash
socmind rule-test \
  detections/windows/suspicious-powershell.yml \
  tests/fixtures/powershell-rule-test.json
```

The command exits non-zero when the expected match count changes, making it suitable for CI.

## False-positive tuning feedback

Analyst decisions can be supplied as JSONL:

```bash
socmind tune examples/dispositions.jsonl
```

SOCMind requires a minimum evidence threshold before suggesting tuning. It recommends scoped exclusions based on repeated benign context instead of globally suppressing the behavior.

## Full investigation

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

## Telemetry ingestion

Linux auth:

```bash
socmind ingest linux-auth /var/log/auth.log \
  --host web-01 --year 2026 -o normalized.jsonl
```

journald:

```bash
journalctl -o json > journal.jsonl
socmind ingest journald journal.jsonl -o normalized.jsonl
```

auditd:

```bash
socmind ingest auditd /var/log/audit/audit.log \
  --host web-01 -o normalized.jsonl
```

Windows XML:

```powershell
socmind ingest windows-xml .\security-events.xml -o .\normalized.jsonl
```

Native EVTX:

```bash
pip install -e ".[evtx]"
```

```powershell
socmind ingest windows-evtx .\Security.evtx -o .\normalized.jsonl
```

Install all optional features:

```bash
pip install -e ".[all]"
```

## Included portfolio rules

```text
detections/
├── windows/
│   ├── suspicious-powershell.yml
│   └── scheduled-task.yml
└── linux/
    └── suspicious-useradd.yml
```

These are intentionally small and testable; the repository will grow as coverage cases are added.

## CI quality gate

Every push and pull request is validated on:

- Ubuntu / Python 3.11
- Ubuntu / Python 3.12
- Windows / Python 3.11
- Windows / Python 3.12

CI now validates both the investigation workflow **and** the detection-engineering loop:

- package installation
- compilation
- automated tests
- Windows/Linux investigation demos
- Sigma-style rule evaluation
- rule fixture tests
- ATT&CK coverage
- gap analysis
- disposition-based tuning

## Roadmap

### v0.6 — SOC integrations
- threat-intelligence enrichment providers
- SIEM adapters
- analyst notes and dispositions
- ticket/case connector interfaces
- rule-pack expansion

### v0.7 — detection maturity
- richer Sigma condition support
- detection coverage dashboards
- rule metadata quality checks
- regression corpus
- detection health scoring

### v1.0
- web investigation workspace
- interactive graph
- case management
- pluggable SIEM/SOAR integrations

## Safety

SOCMind is a defensive Blue Team project. Samples use documentation-only IP ranges and contain no real credentials, malware, or production customer data.

## License

MIT
