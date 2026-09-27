# SOCMind

**SOCMind** is an open-source, cross-platform investigation workbench for **SOC Tier 1 / Tier 2 analysts** on **Windows and Linux**.

It turns raw security telemetry into **explainable triage, evidence correlation, process ancestry, IOC pivots, investigation graphs, hypotheses, playbooks, MITRE ATT&CK context, and portable case packages**.

> **v0.4 — Tier 2 Investigation Workbench**
>
> SOCMind is not a SIEM replacement. It is an analyst workflow and investigation layer.

## Why SOCMind?

Most security tools answer **"what matched?"**. SOCMind is being built to help answer:

- Why did this alert fire?
- What evidence supports it?
- What should Tier 1 validate next?
- When should it escalate to Tier 2?
- What happened before and after the alert?
- Which users, hosts, processes and IPs are connected?
- What competing hypotheses fit the evidence?
- What evidence is still missing?
- Can the same investigation workflow operate across Windows and Linux?

## Cross-platform investigation architecture

```text
Windows                                      Linux
├── Native EVTX                              ├── auth.log / secure
├── Event Viewer XML                         ├── journald
├── Sysmon telemetry                         ├── auditd
└── PowerShell                               └── systemd / cron
        │                                           │
        └────────────────┬──────────────────────────┘
                         ▼
               Normalized Event Model
                         ▼
                  Detection Engine
                         ▼
               Evidence Correlation
          ┌──────────────┼───────────────┐
          ▼              ▼               ▼
       Timeline        IOC pivots     Process tree
          └──────────────┼───────────────┘
                         ▼
                 Investigation Graph
                         ▼
                Explainable T1 Triage
                         ▼
                P1 / P2 / P3 Decision
                         ▼
                 Tier 2 Workbench
              ┌──────────┴───────────┐
              ▼                      ▼
         Hypotheses              Playbooks
              └──────────┬───────────┘
                         ▼
                  Case JSON Export
```

See:
- [Architecture](docs/architecture.md)
- [Tier 2 Workbench](docs/tier2-workbench.md)
- [Case 001](docs/cases/case-001-authentication-to-persistence.md)

## Supported telemetry

### Windows
- Native `.evtx` (optional dependency)
- Event Viewer XML
- Security events
- Sysmon-shaped normalized events
- PowerShell telemetry

### Linux
- `auth.log` / `secure`
- systemd `journald`
- `auditd`
- SSH
- sudo
- systemd / cron persistence indicators

## Current detections

### Windows
- Repeated `4625` failures followed by `4624` success
- suspicious PowerShell command-line behavior
- PowerShell followed by outbound network activity
- Scheduled Task persistence (`4698`)
- Windows Service persistence (`7045`)

### Linux
- repeated SSH failures followed by successful login
- suspicious privileged `sudo` commands
- systemd persistence-related activity
- cron persistence model

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
cd SOCMind
python -m venv .venv
```

Linux:

```bash
source .venv/bin/activate
pip install -e .
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Native EVTX support:

```bash
pip install -e ".[evtx]"
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

Windows EVTX:

```powershell
socmind ingest windows-evtx .\Security.evtx -o .\normalized.jsonl
```

## Full Tier 1 / Tier 2 investigation

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

This produces:

- detection findings
- P1/P2/P3 triage
- escalation guidance
- analyst next steps
- MITRE ATT&CK mapping
- evidence timeline
- IOC list
- Mermaid investigation graph
- process ancestry
- evidence-based hypotheses
- portable case JSON

## Investigation Graph

SOCMind builds relationships such as:

```text
User ──authenticated/on-host──> Host
Parent Process ──spawned──────> Child Process
Process ──executed-on─────────> Host
Process ──connected-to────────> IP
Host ──persistence────────────> Scheduled Task
Host ──service-change─────────> Service
```

Mermaid output can be embedded directly into GitHub Markdown or analyst documentation:

```bash
socmind graph normalized.jsonl
```

## Hypothesis-driven investigation

SOCMind explicitly separates **observations** from **hypotheses**.

Example:

```text
Potential account compromise | confidence=85%

Supporting:
+ Authentication failures were followed by a successful session.
+ Suspicious post-authentication execution was observed.
+ Persistence-related activity followed.

Validation gaps:
- Successful authentication may still be legitimate.
- MFA / identity-provider context is required.
```

The confidence score is an explainable heuristic, **not a probability of guilt or malicious intent**.

## Reusable SOC Playbooks

Findings map to procedural investigation phases:

```text
Validate
   ↓
Scope
   ↓
Investigate / Decode
   ↓
Escalate or Document
```

This helps Tier 1 and Tier 2 analysts perform consistent investigations without replacing analyst judgment.

## Case export

```bash
socmind case normalized.jsonl -o case.json --case-id INC-2026-001
```

The case package contains:

- case metadata
- findings
- triage decisions
- recommended playbook steps
- hypotheses
- IOCs
- entity graph

This structure is intended for future SIEM, SOAR, ticketing, and web-workspace integrations.

## Safe demo investigations

```bash
socmind analyze examples/attack_chain.jsonl \
  --timeline --iocs --graph --process-tree --hypotheses

socmind analyze examples/linux_attack_chain.jsonl \
  --timeline --iocs --graph --hypotheses
```

## CI quality gate

Every push and pull request is tested on:

- Ubuntu / Python 3.11
- Ubuntu / Python 3.12
- Windows / Python 3.11
- Windows / Python 3.12

CI validates installation, compilation, automated tests, full Windows investigation workflow, Linux investigation workflow, graph generation, hypotheses, and case export.

## Roadmap

### v0.5 — Detection Engineering
- Sigma interoperability
- rule-test fixtures
- detection-gap analysis
- false-positive tuning feedback
- coverage matrix

### v0.6 — SOC integrations
- IOC enrichment provider interface
- SIEM adapters
- ticket/case integration interface
- analyst dispositions and notes

### v1.0
- web investigation workspace
- interactive graph
- case management
- pluggable SIEM/SOAR integrations

## Safety

SOCMind is a defensive Blue Team project. Samples use documentation-only IP ranges and contain no real credentials, malware, or production customer data.

## License

MIT
