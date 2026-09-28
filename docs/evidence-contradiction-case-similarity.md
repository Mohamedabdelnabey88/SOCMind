# SOCMind v1.4 — Evidence Contradiction & Case Similarity

v1.4 extends SOCMind's reasoning layer in two directions:

1. **Evidence Contradiction Review** — makes alternative/benign context and missing validation explicit instead of only showing supporting evidence.
2. **Historical Case Similarity** — finds prior evidence-linked cases with explainable behavioral overlap.

Neither feature makes attribution claims or replaces analyst judgment.

## Evidence Contradiction Review

Run:

```bash
socmind contradictions examples/attack_chain.jsonl
```

JSON:

```bash
socmind contradictions examples/attack_chain.jsonl --json
```

For each hypothesis, SOCMind separates:

- supporting evidence
- explicit contradicting / alternative context
- validation gaps
- unresolved analyst questions

This distinction matters. Missing MFA context is **not** treated as contradicting evidence. A recorded successful MFA session from a managed device can be presented as explicit alternative context.

Recognized context fields include examples such as:

- `mfa_result`
- `device_trust`
- `change_approved`
- `change_ticket`
- `admin_approved`
- `signature_status`
- `known_scanner` / `authorized_scanner`

These fields are optional contextual telemetry. SOCMind does not invent them.

## Historical Case Similarity

Register historical cases with evidence paths:

```bash
socmind command-register socmind.db old-case.json \
  --source wazuh \
  --title "Historical compromise" \
  --events historical.jsonl
```

Compare a new investigation:

```bash
socmind similar-cases current.jsonl \
  --database socmind.db \
  --limit 5
```

To exclude the current case:

```bash
socmind similar-cases current.jsonl \
  --database socmind.db \
  --exclude-case-id INC-001
```

## Similarity model

The score is deterministic and explainable:

- 40% ATT&CK technique overlap
- 20% event-ID overlap
- 20% process overlap
- 20% IOC overlap

Each component uses Jaccard similarity.

Host overlap is retained in the fingerprint for future analysis but is intentionally not used in the score so cases are not ranked highly merely because they occurred on the same endpoint.

The output explains the shared evidence:

- shared ATT&CK techniques
- shared processes
- shared IOCs
- shared event IDs

A high score means **evidence/behavior similarity**. It does **not** mean:

- same attacker
- same campaign
- same root cause
- same malware family

Those conclusions still require analyst validation.

## Web workspace

The Investigation Replay tab now includes:

- Evidence Contradictions
- Similar Historical Cases

Similarity is enabled when the workspace is launched with a Command Center database containing evidence-linked cases:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id CURRENT-001 \
  --command-db socmind-demo/socmind-demo.db \
  --rules detections \
  --proposed-rules examples/proposed-rules \
  --quality-checklist examples/quality-checklist.json
```

## Practical SOC value

Contradiction review helps reduce confirmation bias.

Historical similarity helps an analyst answer:

- Have we investigated something behaviorally similar before?
- Which ATT&CK techniques overlapped?
- Were the same processes or IOC values involved?
- What prior case should I read before restarting the investigation from zero?

This is designed as analyst decision support, not automated attribution.
