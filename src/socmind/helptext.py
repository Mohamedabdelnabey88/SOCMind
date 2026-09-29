from __future__ import annotations

TOPICS = {
    "getting-started": """SOCMind Getting Started

1) Install:
   pip install -e ".[all]"

2) Verify:
   socmind --version
   socmind doctor

3) Run the ready demo:
   socmind demo-init -o socmind-demo
   socmind web examples/attack_chain.jsonl --case-id DEMO-P1-001 --command-db socmind-demo/socmind-demo.db --rules detections --dispositions examples/dispositions.jsonl

4) Analyze one normalized file:
   socmind analyze examples/attack_chain.jsonl --timeline --iocs --graph --hypotheses
""",
    "triage": """SOCMind Triage Workflow

Normalize telemetry:
  socmind ingest linux-auth /var/log/auth.log --host endpoint-1 --year 2026 -o events.jsonl
  socmind ingest wazuh alerts.jsonl -o events.jsonl
  socmind ingest elastic exported.ndjson -o events.jsonl

Investigate:
  socmind analyze events.jsonl --timeline --iocs --graph --hypotheses

Create analyst package:
  socmind investigate events.jsonl -o case-workspace --case-id INC-001 --priority P1 --owner analyst1
""",
    "case-workflow": """SOCMind Case Workflow

Create:
  socmind case-init case.json --case-id INC-001 --priority P1

Register with linked evidence:
  socmind command-register socmind.db case.json --source wazuh --title "Authentication anomaly" --events events.jsonl

Operate:
  socmind command-ack socmind.db INC-001
  socmind command-assign socmind.db INC-001 --owner tier2 --actor shift-lead
  socmind command-transition socmind.db INC-001 --state triage --actor tier2
  socmind command-note socmind.db INC-001 --author tier2 --text "Validated source identity."
  socmind command-show socmind.db INC-001
""",
    "integrations": """SOCMind Live Integrations

Environment variables:
  WAZUH_API_USER / WAZUH_API_PASSWORD
  ELASTIC_API_KEY
  MISP_API_KEY
  OPENCTI_TOKEN

Wazuh:
  socmind wazuh-check https://wazuh-manager:55000
  socmind wazuh-agents https://wazuh-manager:55000 --limit 50

Elastic:
  socmind elastic-pull https://elastic:9200 'logs-*' -o elastic.ndjson --size 500

MISP enrichment:
  socmind misp-enrich events.jsonl https://misp.local --json

OpenCTI connectivity:
  socmind opencti-check https://opencti.local

TLS verification is ON by default. Use --insecure only in a controlled lab with self-signed certificates.
""",
    "detection-engineering": """SOCMind Detection Engineering

Run a rule:
  socmind detect detections/windows/suspicious-powershell.yml tests/fixtures/rule-events.jsonl

Regression test:
  socmind rule-test detections/windows/suspicious-powershell.yml tests/fixtures/powershell-rule-test.json

Coverage and gaps:
  socmind coverage examples/attack_chain.jsonl --rules detections
  socmind gaps examples/attack_chain.jsonl --rules detections

Tuning feedback:
  socmind tune examples/dispositions.jsonl
  socmind lead-health examples/attack_chain.jsonl --rules detections --dispositions examples/dispositions.jsonl
""",
    "kali": """SOCMind on Kali Linux

Recommended:
  sudo apt update
  sudo apt install -y git python3 python3-venv python3-pip
  git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
  cd SOCMind
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[all]"
  socmind doctor

Do not use sudo pip install into Kali's system Python.
""",
    "security": """SOCMind Security / Hardening

Check runtime posture:
  socmind security-check
  SOCMIND_API_TOKEN='strong-local-token' socmind security-check --host 0.0.0.0

Safe web defaults:
  socmind web examples/attack_chain.jsonl

Remote bind requires authentication:
  export SOCMIND_API_TOKEN='strong-local-token'
  socmind web examples/attack_chain.jsonl --host 0.0.0.0

Use --allow-unsafe-remote only in an isolated lab.
""",
    "performance": """SOCMind Performance

Run a repeatable local benchmark:
  socmind benchmark
  socmind benchmark --events 10000
  socmind benchmark --events 10000 --json

This benchmark is for comparing the same machine/environment over time; it is not a universal production capacity guarantee.
""",
    "ire": """SOCMind Investigation Replay Engine (IRE)

Replay how the investigation evolved:
  socmind replay examples/attack_chain.jsonl

Replay the same incident against the current rule pack:
  socmind detection-replay examples/attack_chain.jsonl --rules detections

Compare current vs proposed detections:
  socmind what-if examples/attack_chain.jsonl \
    --current-rules detections \
    --proposed-rules examples/proposed-rules

Review investigation completeness:
  socmind case-review examples/attack_chain.jsonl \
    --checklist examples/quality-checklist.json

Turn a confirmed incident into detection-engineering artifacts:
  socmind learn-from-case examples/attack_chain.jsonl \
    --rules detections \
    --case-id INC-001 \
    -o regression-pack

IRE is designed to close the loop:
incident -> investigation -> blind spots -> detection change -> regression.
""",
    "reasoning": """SOCMind Evidence Reasoning & Case Similarity

Review supporting, contradicting and unresolved evidence:
  socmind contradictions examples/attack_chain.jsonl

Find similar historical evidence-linked cases:
  socmind similar-cases examples/attack_chain.jsonl \
    --database socmind-demo/socmind-demo.db \
    --limit 5

Interpretation:
- contradiction review highlights alternative/benign context and validation gaps
- similarity is evidence/behavior overlap, not attacker attribution
- neither command replaces analyst judgment
""",
    "enterprise": """SOCMind Enterprise Foundation

Install enterprise support:
  pip install -e ".[enterprise,web,sigma]"

Inspect roles and permissions:
  socmind enterprise-info

PostgreSQL:
  export SOCMIND_POSTGRES_DSN='postgresql://user:pass@db:5432/socmind'
  socmind postgres-init
  socmind postgres-health

Trusted reverse-proxy identity:
  export SOCMIND_TRUSTED_PROXY_SECRET='shared-secret'
  socmind trusted-sign --subject analyst@example.com --role analyst
  # prints X-SOCMind-User / Role / Timestamp / Signature test headers

Tamper-evident audit:
  socmind audit-verify enterprise-audit.jsonl

Backup local SQLite:
  socmind backup socmind.db -o backups/socmind.db

Retention preview:
  socmind retention ./exports --days 90
  socmind retention ./exports --days 90 --apply

Enterprise web example:
  export SOCMIND_POSTGRES_DSN='postgresql://user:pass@db:5432/socmind'
  export SOCMIND_TRUSTED_PROXY_SECRET='shared-secret'
  socmind web events.jsonl --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
    --auth-mode trusted-proxy --enterprise-audit enterprise-audit.jsonl \
    --host 0.0.0.0

The trusted-proxy mode is designed for deployment behind an authenticating reverse proxy / identity-aware gateway. The proxy must strip client-supplied X-SOCMind-* identity headers and generate fresh signed headers.
""",
    "production-ops": """SOCMind Production SOC Operations

Promote Wazuh alerts into the SOC case queue:
  socmind alert-orchestrate wazuh alerts.jsonl \
    --database socmind.db \
    --evidence normalized.jsonl \
    --evidence-dir evidence

Use PostgreSQL instead:
  export SOCMIND_POSTGRES_DSN='postgresql://user:pass@db:5432/socmind'
  socmind alert-orchestrate elastic alerts.ndjson \
    --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
    --evidence normalized.jsonl \
    --evidence-dir evidence

Tuning:
  --correlation-window 15
  --correlation-threshold 55
  --evidence-before 15
  --evidence-after 15

Outcomes:
- NEW CASE: no active case met the correlation threshold
- CORRELATED: alert was linked to an existing active case with explainable reasons
- DUPLICATE: the same source alert ID was already ingested

Live alert ingestion:
  socmind alert-live elastic https://elastic:9200 .alerts-security.alerts-default \
    --database socmind.db --json

  export WAZUH_INDEXER_USER='...'
  export WAZUH_INDEXER_PASSWORD='...'
  socmind alert-live wazuh-indexer https://wazuh-indexer:9200 'wazuh-alerts*' \
    --database socmind.db --json

Elastic uses ELASTIC_API_KEY / ELASTIC_BEARER_TOKEN / ELASTIC_USER+PASSWORD.
Wazuh Indexer uses WAZUH_INDEXER_JWT or WAZUH_INDEXER_USER+PASSWORD.
TLS verification is enabled by default.

Correlation is deterministic and auditable. It does not claim attacker attribution.

Collect live case evidence from Elastic:
  export ELASTIC_API_KEY='...'
  socmind case-collect-evidence INC-2026-001 elastic https://elastic:9200 'logs-*' \
    --database socmind.db \
    --evidence-dir evidence

Collect from Wazuh Indexer / OpenSearch:
  export WAZUH_INDEXER_USER='...'
  export WAZUH_INDEXER_PASSWORD='...'
  socmind case-collect-evidence INC-2026-001 wazuh-indexer https://indexer:9200 'wazuh-alerts-*' \
    --database socmind.db \
    --evidence-dir evidence

The collector derives its time window and identity context from the case's linked alerts,
merges normalized events into the case evidence package, and journals every collection.
TLS verification is enabled by default.
""",
    "demo": """SOCMind Portfolio Demo

  socmind demo-init -o socmind-demo

  socmind web examples/attack_chain.jsonl \
    --case-id DEMO-P1-001 \
    --command-db socmind-demo/socmind-demo.db \
    --rules detections \
    --dispositions examples/dispositions.jsonl

Open http://127.0.0.1:8765
""",
}

OVERVIEW = """SOCMind CLI Help

Use:
  socmind help <topic>
  socmind <command> --help

Topics:
  getting-started
  triage
  case-workflow
  integrations
  detection-engineering
  kali
  security
  performance
  ire
  reasoning
  enterprise
  production-ops
  demo

Common first commands:
  socmind doctor
  socmind demo-init -o socmind-demo
  socmind analyze examples/attack_chain.jsonl --timeline --iocs --hypotheses
"""


def render_help(topic: str | None = None) -> str:
    if not topic:
        return OVERVIEW
    if topic not in TOPICS:
        available = ", ".join(sorted(TOPICS))
        raise ValueError(f"Unknown help topic: {topic}. Available: {available}")
    return TOPICS[topic]
