# SOCMind v1.0 — Real SOC Workspace

SOCMind v1.0 is designed as a local, analyst-driven SOC workspace that demonstrates the complete path from telemetry to triage, investigation, case operations, detection feedback, and shift-lead awareness.

## Quick demo

Create a ready-to-run demo:

```bash
socmind demo-init -o socmind-demo
```

Launch the workspace:

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

## What the demo contains

- **DEMO-P1-001** — active P1 Windows investigation, assigned and acknowledged, with linked evidence and analyst note
- **DEMO-P2-002** — unassigned P2 Linux SSH investigation
- **DEMO-P3-003** — resolved P3 administrative activity review

## Case queue

The Command Center supports:

- search by case ID, title, or source
- priority filters
- state filters
- SLA visibility
- analyst workload
- MTTA
- MTTR

Click a case row to open its workspace.

## Case workspace actions

From the browser an analyst can:

1. acknowledge the case
2. assign or reassign an owner
3. transition the case through the approved lifecycle
4. add investigation notes
5. review the append-only audit trail
6. inspect linked evidence summary

All actions persist to the local SQLite database.

## Evidence linking

Register a case and associate normalized evidence:

```bash
socmind command-register socmind.db case.json \
  --source wazuh \
  --title "Authentication followed by suspicious execution" \
  --events normalized.jsonl
```

The web workspace can then load the linked evidence and show finding/event/risk counts inside the case detail panel.

## CLI case operations

```bash
socmind command-ack socmind.db INC-001

socmind command-assign socmind.db INC-001 \
  --owner tier2-analyst \
  --actor shift-lead

socmind command-transition socmind.db INC-001 \
  --state triage \
  --actor tier2-analyst

socmind command-note socmind.db INC-001 \
  --author tier2-analyst \
  --text "Validated source identity and process ancestry." \
  --disposition needs-review

socmind command-show socmind.db INC-001
```

## Optional API token

SOCMind remains loopback-only by default. If API protection is desired:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id INC-001 \
  --command-db socmind.db \
  --api-token "replace-with-a-strong-local-token"
```

The investigation and command-center API routes then require the `X-SOCMind-Token` header.

The browser UI provides an **API Token** button and stores the value only in session storage.

## API surface

```text
GET  /health
GET  /api/case
GET  /api/command-center
GET  /api/cases/{case_id}
POST /api/cases/{case_id}/acknowledge
POST /api/cases/{case_id}/assign
POST /api/cases/{case_id}/transition
POST /api/cases/{case_id}/notes
GET  /api/lead-health
GET  /api/docs
```

## Security boundaries

- default web bind is `127.0.0.1`
- optional API token uses constant-time comparison
- user-supplied values are escaped by the browser UI before HTML insertion
- SQLite queries use parameters instead of string interpolation for user values
- case state transitions are validated against the state machine
- evidence files are referenced locally; SOCMind does not upload telemetry by default

This token mechanism is appropriate for the local portfolio/workbench model. A production multi-user deployment should integrate organizational identity, TLS, RBAC, secrets management, and centralized audit infrastructure.

## Kali Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
cd SOCMind
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"

socmind demo-init -o socmind-demo

socmind web examples/linux_attack_chain.jsonl \
  --case-id DEMO-P2-002 \
  --command-db socmind-demo/socmind-demo.db \
  --rules detections \
  --dispositions examples/dispositions.jsonl
```

## Portfolio demonstration

A concise interview demonstration should show:

1. Command Center and SLA pressure
2. opening a P1 case
3. linked evidence and findings
4. assignment and acknowledgement
5. analyst note + audit trail
6. Evidence Graph / Timeline / ATT&CK
7. SOC Lead Detection Health
8. detection gap or noisy-rule feedback

That demonstrates technical investigation, operational discipline, detection engineering, and SOC workflow awareness in one coherent project.
