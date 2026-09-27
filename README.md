# SOCMind

**SOCMind** is an open-source, cross-platform investigation workbench for **SOC Tier 1 / Tier 2 analysts** on **Windows and Linux**.

It is designed around a simple idea: an alert should not end at a rule match. SOCMind turns telemetry into **explainable triage, evidence correlation, investigation timelines, MITRE ATT&CK context, escalation guidance, and analyst-ready reporting**.

> **v0.2 — ingestion + explainable triage**
>
> SOCMind is not a SIEM replacement. It is an analyst workflow and investigation layer.

## What makes it different

Most log tools answer **"what matched?"**. SOCMind is being built to answer:

- **Why did this alert fire?**
- **What evidence supports it?**
- **What should Tier 1 validate next?**
- **When should it escalate to Tier 2?**
- **What happened before and after the alert?**
- **Which ATT&CK techniques are represented?**
- **Can the same investigation logic work across Windows and Linux?**

## Cross-platform architecture

```text
Windows                                  Linux
├── Security Event XML                   ├── auth.log / secure
├── Sysmon                               ├── journald
└── PowerShell                           ├── auditd (roadmap)
        │                                └── systemd / cron
        └──────────────┬────────────────────────┘
                       ▼
             Normalized Event Model
                       ▼
                Detection Engine
                       ▼
             Evidence Correlation
                       ▼
          Explainable Tier-1 Triage
                       ▼
                 P1 / P2 / P3
                       ▼
             Tier-2 Investigation
               ┌───────┴────────┐
               ▼                ▼
        MITRE ATT&CK        Timeline
               └───────┬────────┘
                       ▼
               Analyst Report
```

See [Architecture](docs/architecture.md).

## Current detections

### Windows

- Repeated `4625` failures followed by `4624` success.
- Suspicious PowerShell command-line behavior.
- PowerShell followed by outbound network activity.
- Scheduled Task persistence (`4698`).
- Windows Service persistence (`7045`).

### Linux

- Repeated SSH failures followed by successful login.
- Suspicious privileged `sudo` commands.
- systemd persistence-related activity.
- cron persistence model.

## Raw telemetry ingestion

### Linux auth.log / secure

```bash
socmind ingest linux-auth /var/log/auth.log \
  --host web-01 --year 2026 -o normalized.jsonl

socmind analyze normalized.jsonl --timeline
```

### systemd journal

```bash
journalctl -o json > journal.jsonl
socmind ingest journald journal.jsonl -o normalized.jsonl
socmind analyze normalized.jsonl
```

### Windows Event Viewer XML

Export selected events as XML, then:

```powershell
socmind ingest windows-xml .\security-events.xml -o .\normalized.jsonl
socmind analyze .\normalized.jsonl --timeline
```

Native binary `.evtx` support is on the next ingestion milestone; XML support keeps the current core dependency-free and cross-platform.

## Explainable triage

A finding is not just a severity label. SOCMind provides:

```text
HIGH | score=75 | Suspicious PowerShell execution

Priority: P2
Disposition: needs-review
Escalation: Tier 1 validate; escalate if unexplained

Why it fired:
  - PowerShell profile loading disabled
  - PowerShell window configured as hidden
  - outbound connection followed execution

Recommended next steps:
  1. Inspect parent and child process ancestry.
  2. Review PowerShell Script Block logs.
  3. Extract domains, IPs, URLs and hashes.
  4. Check persistence and outbound connections.

MITRE:
T1059.001 PowerShell
```

The recommendation is intentionally **analyst-in-the-loop**. SOCMind does not automatically declare an incident malicious or close a case.

## Investigation case

The repository ships with a portfolio case that expresses one incident pattern across both operating systems:

**Case 001 — Authentication to Persistence**

```text
Windows:
4625 → 4624 → PowerShell → Network → Scheduled Task / Service

Linux:
SSH Failures → SSH Success → sudo → systemd / cron
```

See [Case 001](docs/cases/case-001-authentication-to-persistence.md).

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

Run the safe sample investigations:

```bash
socmind analyze examples/attack_chain.jsonl --timeline
socmind analyze examples/linux_attack_chain.jsonl --timeline
```

## CI quality gate

Every push and pull request is tested on:

- Ubuntu / Python 3.11
- Ubuntu / Python 3.12
- Windows / Python 3.11
- Windows / Python 3.12

CI validates package installation, byte-code compilation, automated tests, and both Windows/Linux demo investigations.

## Roadmap

### v0.3 — deeper telemetry

- Native EVTX parser
- Sysmon-specific normalization
- Linux auditd parser
- process ancestry
- DNS / network IOC extraction
- IOC enrichment provider interface

### v0.4 — Tier 2 workbench

- investigation graph
- cross-source timeline reconstruction
- reusable playbooks
- case JSON export
- hypothesis / confidence model
- analyst notes and dispositions

### v0.5 — detection engineering

- Sigma interoperability
- detection-gap analysis
- rule-test fixtures
- false-positive tuning feedback

### v1.0

- web investigation workspace
- SIEM adapters
- case export
- investigation playbook engine

## Safety

SOCMind is a defensive Blue Team project. Repository samples are sanitized and use documentation-only IP ranges. No real credentials, malware, or production customer data are included.

## License

MIT
