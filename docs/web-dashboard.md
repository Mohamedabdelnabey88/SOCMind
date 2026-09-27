# SOCMind Web Investigation Dashboard

The web dashboard is a local analyst workspace built on top of the same SOCMind investigation engine used by the CLI.

## Install

```bash
pip install -e ".[web]"
```

For every optional feature:

```bash
pip install -e ".[all]"
```

## Start the dashboard

```bash
socmind web examples/attack_chain.jsonl \
  --case-id DEMO-001
```

Open:

```text
http://127.0.0.1:8765
```

The default bind address is loopback-only so investigation data is not exposed to the network accidentally.

## Kali Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
cd SOCMind

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"

socmind web examples/linux_attack_chain.jsonl \
  --case-id KALI-CASE-001
```

Then browse to:

```text
http://127.0.0.1:8765
```

## Current dashboard views

- executive investigation metrics
- prioritized findings
- P1/P2/P3 triage context
- evidence-based hypotheses
- interactive entity graph
- chronological evidence timeline
- extracted IOCs
- observed MITRE ATT&CK techniques

## Interactive Evidence Graph

Entities include:

- users
- hosts
- processes
- source/destination IPs
- services
- persistence artifacts

Nodes can be dragged in the browser. Clicking a node shows its type, label, and relationship count.

## API

The UI is backed by a small local API:

```text
GET /health
GET /api/case
GET /api/docs
```

The API layer is intentionally separated from the frontend so future case management, Wazuh/Elastic live connectors, and authentication can be added without rewriting the investigation engine.

## Security model

The web command binds to `127.0.0.1` by default.

Only bind to `0.0.0.0` when you understand the network exposure and have placed SOCMind behind suitable access controls. The current dashboard does not implement multi-user authentication and should not be exposed directly to the public Internet.
