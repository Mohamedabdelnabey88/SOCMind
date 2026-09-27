# SOCMind

**SOCMind** is an open-source, cross-platform SOC Tier 1 / Tier 2 investigation toolkit for **Windows and Linux** focused on alert triage, evidence correlation, attack-story reconstruction, MITRE ATT&CK mapping, and analyst-ready reporting.

> Status: **v0.1 — foundation release**. SOCMind is intentionally designed as an analyst workflow engine, not another SIEM.

## Why SOCMind?

SOC analysts routinely pivot across authentication events, endpoint telemetry, PowerShell, SSH, privilege escalation, persistence, network activity, and threat intelligence. SOCMind turns those disconnected observations into a structured investigation while keeping the final decision with the analyst.

## Cross-platform design

SOCMind uses one normalized event model and OS-specific adapters:

```text
Windows telemetry ─┐
  Security EVTX    │
  Sysmon           ├──> Normalization ──> T1 Triage ──> T2 Correlation ──> Report
  PowerShell       │
                   │
Linux telemetry ───┤
  auth.log / SSH   │
  journald         │
  auditd           │
  systemd / cron ──┘
```

The analysis engine itself is platform-neutral Python and runs on both Windows and Linux.

## Current v0.1 capabilities

### Windows
- Detect repeated failed logons (`4625`) followed by successful authentication (`4624`).
- Identify suspicious PowerShell behaviors and correlate near-term outbound network activity.
- Surface persistence-related activity such as Scheduled Task (`4698`) and Service creation (`7045`).

### Linux
- Detect repeated SSH authentication failures followed by a successful login.
- Flag high-interest privileged `sudo` commands for analyst review.
- Surface persistence-related systemd service and cron activity.

### Shared SOC workflow
- Map findings to MITRE ATT&CK techniques.
- Produce investigation findings with evidence, rationale, severity, and risk score.
- Ship with sanitized Windows and Linux sample telemetry.
- Run automated tests on both Ubuntu and Windows through GitHub Actions.

## Quick start

```bash
python -m venv .venv
```

Linux:

```bash
source .venv/bin/activate
pip install -e .
socmind analyze examples/attack_chain.jsonl
socmind analyze examples/linux_attack_chain.jsonl
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e .
socmind analyze examples\attack_chain.jsonl
socmind analyze examples\linux_attack_chain.jsonl
```

## Analyst workflow

```text
Alert / Telemetry
      ↓
Normalization
      ↓
Tier-1 Triage
      ↓
Evidence Correlation
      ↓
Tier-2 Investigation
      ↓
MITRE ATT&CK Mapping
      ↓
Escalation / Closure Report
```

## Roadmap

### v0.2 — Tier 1 ingestion
- Native Windows EVTX adapter
- Sysmon XML adapter
- Linux auth.log / secure parser
- systemd-journald JSON adapter
- auditd parser
- IOC extraction and enrichment interface
- phishing triage playbook
- analyst disposition: TP / FP / benign-positive / escalate

### v0.3 — Tier 2 investigation
- investigation graph
- process ancestry correlation
- Windows + Linux lateral movement heuristics
- cross-source timeline reconstruction
- hypothesis + confidence model
- reusable investigation playbooks

### v0.4 — Detection engineering
- Sigma interoperability
- detection-gap analysis
- rule-test fixtures
- false-positive tuning feedback

### v1.0
- Web investigation workspace
- case export
- pluggable SIEM adapters
- investigation playbook engine

## Portfolio goal

SOCMind is built to demonstrate practical SOC Tier 1 and Tier 2 engineering skills: triage, log analysis, correlation, threat investigation, MITRE ATT&CK mapping, detection logic, and incident documentation across Windows and Linux environments.

## Safety and scope

SOCMind is a defensive security project. Sample telemetry uses reserved documentation IP ranges and contains no real credentials, malware, or production data.

## License

MIT
