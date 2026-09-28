# SOCMind 1.2 — Hardened Portfolio Release

SOCMind 1.2 is the final planned portfolio release in the initial roadmap.

It combines:

- Windows / Linux / Kali telemetry
- Wazuh and Elastic integration
- MISP and OpenCTI connectivity
- Tier 1 triage
- Tier 2 investigation
- evidence graph and timeline
- IOC extraction and enrichment
- MITRE ATT&CK mapping
- case lifecycle and audit trail
- SLA / MTTA / MTTR
- multi-case command center
- detection health and tuning feedback
- SOC Lead shift brief
- interactive web workspace
- guided CLI help
- security diagnostics and benchmark tools

## First five minutes

```bash
git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
cd SOCMind

python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"

socmind doctor
socmind security-check
socmind demo-init -o socmind-demo
```

Launch:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id DEMO-P1-001 \
  --command-db socmind-demo/socmind-demo.db \
  --rules detections \
  --dispositions examples/dispositions.jsonl
```

## CLI discovery

Start with:

```bash
socmind help
socmind help getting-started
```

Operational topics:

```bash
socmind help triage
socmind help case-workflow
socmind help integrations
socmind help detection-engineering
socmind help security
socmind help performance
socmind help kali
socmind help demo
```

Every command also provides `--help`.

## Hardening

1.2 adds:

- remote-bind refusal without authentication
- environment-based API token support
- HTTP Content Security Policy
- anti-framing and no-sniff headers
- no-store response policy
- SQLite WAL mode and busy timeout
- input-size bounds
- parameterized SQL
- TLS verification by default for live integrations
- security posture diagnostics

## Performance diagnostics

```bash
socmind benchmark --events 5000
socmind benchmark --events 10000 --json
```

The benchmark is deterministic and is intended for comparing the same host/environment across changes. It is not presented as a universal capacity claim.

## Quality gates

The repository validates:

- Windows Python 3.11 and 3.12
- Ubuntu Python 3.11 and 3.12
- Kali Linux Rolling
- complete pytest suite
- CLI workflows
- web/API workflows
- integration transports through local mock services
- package/wheel installation
- static web assets from the built wheel

## Production boundary

SOCMind is intentionally positioned as a local/open-source analyst workbench and portfolio project.

Enterprise multi-user deployment still requires organization-specific:

- SSO and RBAC
- TLS ingress/reverse proxy
- secret management
- centralized durable audit logs
- backup/recovery policy
- infrastructure monitoring
- data retention and privacy controls
