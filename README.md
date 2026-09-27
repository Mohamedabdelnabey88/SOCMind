# SOCMind

**SOCMind** is an open-source, cross-platform investigation workbench for **SOC Tier 1 / Tier 2 analysts** on **Windows and Linux**.

It is designed around a simple idea: an alert should not end at a rule match. SOCMind turns telemetry into **explainable triage, evidence correlation, investigation timelines, MITRE ATT&CK context, IOC extraction, escalation guidance, and analyst-ready reporting**.

> **v0.3 — deeper telemetry + IOC workflow**
>
> SOCMind is not a SIEM replacement. It is an analyst workflow and investigation layer.

## What makes it different

Most log tools answer **"what matched?"**. SOCMind is being built to answer:

- **Why did this alert fire?**
- **What evidence supports it?**
- **What should Tier 1 validate next?**
- **When should it escalate to Tier 2?**
- **What happened before and after the alert?**
- **Which indicators should the analyst pivot on?**
- **Can the same investigation logic work across Windows and Linux?**

## Cross-platform architecture

```text
Windows                                      Linux
├── Native EVTX (optional)                   ├── auth.log / secure
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
                   ┌─────┴─────┐
                   ▼           ▼
            IOC Extraction   Timeline
                   └─────┬─────┘
                         ▼
            Explainable T1 Triage
                         ▼
                   P1 / P2 / P3
                         ▼
                T2 Investigation
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

## Telemetry ingestion

### Linux auth.log / secure

```bash
socmind ingest linux-auth /var/log/auth.log \
  --host web-01 --year 2026 -o normalized.jsonl
```

### systemd journal

```bash
journalctl -o json > journal.jsonl
socmind ingest journald journal.jsonl -o normalized.jsonl
```

### Linux auditd

```bash
socmind ingest auditd /var/log/audit/audit.log \
  --host web-01 -o normalized.jsonl
```

### Windows Event Viewer XML

```powershell
socmind ingest windows-xml .\security-events.xml -o .\normalized.jsonl
```

### Native Windows EVTX

The base installation stays dependency-free. Native EVTX is an optional extra:

```bash
pip install -e ".[evtx]"
```

Then:

```powershell
socmind ingest windows-evtx .\Security.evtx -o .\normalized.jsonl
```

The EVTX adapter reuses the same tested Windows normalizer, so binary EVTX and exported XML feed one event model.

## Investigation workflow

```bash
socmind analyze normalized.jsonl --timeline --iocs
```

A finding includes:

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

The recommendation is deliberately **analyst-in-the-loop**. SOCMind does not autonomously close cases or label users malicious.

## IOC extraction

SOCMind can pivot from normalized evidence to investigation indicators without requiring an external intelligence service:

```bash
socmind iocs normalized.jsonl
socmind iocs normalized.jsonl --json
```

Currently extracted:
- IPv4 indicators with scope classification
- domains
- HTTP/HTTPS URLs
- MD5
- SHA-1
- SHA-256

This is the first stage of the future enrichment pipeline; reputation lookups remain separate from evidence extraction.

## Investigation case

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
socmind analyze examples/attack_chain.jsonl --timeline --iocs
socmind analyze examples/linux_attack_chain.jsonl --timeline --iocs
```

## CI quality gate

Every push and pull request is tested on:
- Ubuntu / Python 3.11
- Ubuntu / Python 3.12
- Windows / Python 3.11
- Windows / Python 3.12

CI validates installation, byte-code compilation, automated tests, and Windows/Linux demo investigations.

## Roadmap

### v0.4 — Tier 2 workbench
- Sysmon-specific enrichment
- process ancestry graph
- DNS and network correlation
- reusable investigation playbooks
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
- IOC enrichment providers
- case export
- investigation playbook engine

## Safety

SOCMind is a defensive Blue Team project. Repository samples are sanitized and use documentation-only IP ranges. No real credentials, malware, or production customer data are included.

## License

MIT
