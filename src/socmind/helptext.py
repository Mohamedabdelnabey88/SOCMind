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
