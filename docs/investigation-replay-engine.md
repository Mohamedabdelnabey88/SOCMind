# SOCMind v1.3 — Investigation Replay Engine (IRE)

The Investigation Replay Engine is SOCMind's signature feedback-loop capability.

Instead of stopping at alert triage or case closure, IRE reconstructs how the investigation evolved, replays the incident against detection rules, identifies blind spots, compares proposed rule packs, reviews investigation completeness, and turns a confirmed incident into reusable detection-engineering artifacts.

## Why IRE exists

Traditional SOC workflows often separate incident investigation from detection engineering:

```text
Alert -> Investigation -> Closure
```

IRE closes the loop:

```text
Incident
  ↓
Investigation
  ↓
Investigation Replay
  ↓
Detection Replay
  ↓
Blind-Spot Analysis
  ↓
What-If Rule Comparison
  ↓
Regression Package
  ↓
Improved Detection Pack
  ↺
```

The goal is not to replace analyst judgment. The goal is to make the reasoning and detection feedback measurable and repeatable.

## 1. Investigation Replay

Replay how findings and hypotheses emerged as evidence arrived:

```bash
socmind replay examples/attack_chain.jsonl
```

Machine-readable:

```bash
socmind replay examples/attack_chain.jsonl --json
```

Each step shows:

- event timestamp/source/ID/host
- newly visible findings
- current hypotheses
- confidence change from the previous step

This creates a transparent record of *when* the investigation changed direction.

## 2. Detection Replay

Run the same incident against the current detection pack:

```bash
socmind detection-replay examples/attack_chain.jsonl \
  --rules detections
```

IRE reports:

- first detection step
- meaningful attack-chain steps
- detected vs blind steps
- blind steps before first detection
- event-level detection visibility
- observed ATT&CK techniques
- covered ATT&CK techniques
- detection gaps

This is different from a static ATT&CK coverage matrix: it measures visibility against the evidence sequence of a concrete incident.

## 3. Detection What-If

Compare the same incident against current and proposed rule packs:

```bash
socmind what-if examples/attack_chain.jsonl \
  --current-rules detections \
  --proposed-rules examples/proposed-rules
```

The comparison reports:

- current first detection step
- proposed first detection step
- how many stages earlier detection occurs
- visibility delta
- blind-step reduction
- newly covered ATT&CK techniques

The included proposed demo pack adds an early authentication-failure signal while retaining the current PowerShell and scheduled-task detections.

The CI test requires this pack to detect the demo chain earlier and add T1110 coverage. If it does not, the v1.3 quality gate fails.

## 4. Investigation Quality Gate

Evaluate whether the *investigation* is complete enough for closure/handoff:

```bash
socmind case-review examples/attack_chain.jsonl
```

Use an analyst-confirmed checklist:

```bash
socmind case-review examples/attack_chain.jsonl \
  --checklist examples/quality-checklist.json
```

The review covers:

- evidence availability
- timeline reconstruction
- process ancestry
- IOC review
- ATT&CK mapping
- hypotheses
- contradicting evidence / validation gaps
- persistence validation
- scope validation
- detection feedback
- handoff readiness

Important: this is **not an analyst performance score**. It is an investigation-completeness gate.

Items that require analyst validation are not auto-marked complete just because telemetry exists.

## 5. Learn From Case

Turn a confirmed incident into a detection-engineering package:

```bash
socmind learn-from-case examples/attack_chain.jsonl \
  --rules detections \
  --case-id INC-001 \
  -o regression-pack
```

Output:

```text
regression-pack/
├── attack-chain.json
├── regression-events.jsonl
├── regression-fixture.json
├── coverage-before.json
├── candidate-detection.yml
├── validation-checklist.md
└── tuning-notes.md
```

The candidate rule is intentionally marked **experimental**. SOCMind does not silently promote generated rules into production.

The generated checklist requires benign testing, ATT&CK validation, false-positive review, and What-If comparison before promotion.

## 6. Web IRE Dashboard

Launch with current and proposed rule packs:

```bash
socmind web examples/attack_chain.jsonl \
  --case-id DEMO-P1-001 \
  --command-db socmind-demo/socmind-demo.db \
  --rules detections \
  --proposed-rules examples/proposed-rules \
  --quality-checklist examples/quality-checklist.json \
  --dispositions examples/dispositions.jsonl
```

The **Investigation Replay** tab shows:

- first detection step
- blind steps before detection
- visibility percentage
- detection gaps
- investigation completeness
- current vs proposed improvements
- the step-by-step reasoning timeline

## Interpretation boundaries

IRE metrics are intentionally narrow and explainable:

- **Visibility** means the percentage of incident evidence steps associated with observed ATT&CK techniques that matched at least one local rule.
- **Blind step** means a meaningful evidence step with no local rule match.
- **First detection step** is the earliest event in the replay matched by a local rule.
- **Coverage** means the local rule pack has a rule tagged for an observed ATT&CK technique.
- **Confidence** in replay hypotheses is SOCMind's deterministic heuristic, not a probability of guilt or compromise.

These metrics are useful for comparing the same incident and rule packs. They should not be treated as universal SOC maturity scores.

## Portfolio explanation

A concise interview explanation:

> SOCMind closes the loop between investigation and detection engineering. A confirmed incident can be replayed against the current detection pack to show exactly when the SOC first gained visibility, which attack stages were blind, and whether a proposed rule set would have detected the same chain earlier. The case can then be converted into a regression package for future detection validation.

That is the core distinction of the Investigation Replay Engine.
