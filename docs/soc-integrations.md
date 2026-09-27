# SOC Integrations

SOCMind v0.6 introduces integration points without binding the core engine to one vendor.

## SIEM adapters

### Wazuh

Wazuh alert JSONL can be normalized into the same event model used by Windows/Linux raw telemetry.

```bash
socmind ingest wazuh alerts.jsonl -o normalized.jsonl
```

### Elastic ECS

ECS-shaped NDJSON can be normalized using:

```bash
socmind ingest elastic events.ndjson -o normalized.jsonl
```

## Threat intelligence enrichment

SOCMind uses a provider interface. v0.6 ships with an offline local provider so enrichment can be tested without API keys or external data leakage.

```bash
socmind enrich normalized.jsonl --local-intel examples/local-intel.json
```

External providers can later implement the same interface.

## Analyst notes

Notes and dispositions can be appended to a case journal:

```bash
socmind note analyst-notes.jsonl \
  --case-id INC-001 \
  --author analyst1 \
  --text "Validated source IP against VPN inventory." \
  --disposition needs-review
```

## Escalation package

A Markdown handoff package can be generated for Tier 2 / IR escalation:

```bash
socmind escalate normalized.jsonl \
  --case-id INC-001 \
  -o escalation.md
```

The package includes findings, risk, ATT&CK techniques, IOCs, hypotheses and handoff recommendations.
