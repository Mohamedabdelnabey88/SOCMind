# SOCMind Multi-Case SOC Command Center

The Command Center adds the operational view a SOC analyst or shift lead needs across multiple investigations.

## What it tracks

- active cases
- P1 active cases
- unassigned cases
- SLA breaches
- analyst workload
- resolved cases
- MTTR for resolved cases
- per-case state, priority, source and ownership

The backing store is local SQLite and uses only the Python standard library.

## Register a case

Create a case:

```bash
socmind case-init case-001.json \
  --case-id INC-001 \
  --priority P1 \
  --owner analyst1
```

Register it in the command center:

```bash
socmind command-register socmind.db case-001.json \
  --source wazuh \
  --title "Authentication followed by suspicious execution"
```

## View the queue in the terminal

```bash
socmind command-center socmind.db
```

Machine-readable output:

```bash
socmind command-center socmind.db --json
```

## Use it in the web dashboard

```bash
socmind web examples/attack_chain.jsonl \
  --case-id INC-001 \
  --command-db socmind.db
```

Open:

```text
http://127.0.0.1:8765
```

The Command Center page shows queue state, SLA pressure and workload alongside the detailed investigation views.

## Operational value

This feature demonstrates that SOCMind is not limited to one alert at a time. It models the shift-level questions a real SOC needs:

- Which P1 cases need attention now?
- Which cases have breached SLA?
- Which investigations are unassigned?
- Which analyst is carrying the most active cases?
- How quickly are cases being resolved?

The default SLA targets in the portfolio are examples and should be replaced by the organization’s actual SLA policy in production.
