# SOC Lead & Detection Health

SOCMind v0.9 adds a shift-lead view focused on detection quality and operational awareness.

## Metrics

- loaded detection rules
- observed MITRE ATT&CK techniques
- ATT&CK coverage percentage for observed techniques
- TP / FP ratios from analyst dispositions
- noisy-rule identification
- per-rule health score
- top users by event concentration
- top hosts by event concentration

The rule health score is intentionally explainable. It is derived from disposition history and sample size. It is **not** a machine-learning confidence score.

## CLI

```bash
socmind lead-health examples/attack_chain.jsonl \
  --rules detections \
  --dispositions examples/dispositions.jsonl
```

JSON output:

```bash
socmind lead-health examples/attack_chain.jsonl \
  --rules detections \
  --dispositions examples/dispositions.jsonl \
  --json
```

## Shift brief

Combine case operations with detection health:

```bash
socmind shift-brief socmind.db examples/attack_chain.jsonl \
  --rules detections \
  --dispositions examples/dispositions.jsonl \
  -o shift-brief.md
```

The brief includes:

- active/P1/SLA/unassigned case counts
- MTTA and MTTR
- ATT&CK coverage
- noisy detections
- priority queue
- top users
- top hosts

## Web dashboard

```bash
socmind web examples/attack_chain.jsonl \
  --case-id INC-001 \
  --command-db socmind.db \
  --rules detections \
  --dispositions examples/dispositions.jsonl
```

The **SOC Lead** page shows detection quality and coverage next to the Command Center and detailed investigation views.

## Interpretation

A high false-positive ratio means a rule deserves review; it does not automatically mean the rule should be disabled. SOCMind deliberately preserves analyst judgment and recommends scoped tuning rather than global suppression.
