# SOCMind v1.6 — Professional Feature Maturity

v1.6 focuses on deepening existing SOCMind capabilities instead of adding disconnected features.

The goal is to make investigation, detection engineering and case operations behave like professional workflow components rather than portfolio-only demonstrations.

## 1. Detection Replay maturity

Detection Replay now distinguishes three states per observed ATT&CK technique:

- `detected` — a rule tagged for the technique actually matched relevant evidence
- `covered-not-triggered` — the rule pack contains a technique mapping, but no matching rule fired on the observed evidence
- `gap` — no local rule is mapped to the observed technique

It also reports:

- first observed step
- first detected step
- first observed timestamp
- first detected timestamp
- blind seconds until detection
- matched rule IDs
- tagged rule IDs
- time to first meaningful detection

This avoids treating static ATT&CK coverage as equivalent to actual detection.

## 2. Investigation Quality Gate maturity

The quality gate now returns an operational readiness state:

- `READY`
- `NEEDS_REVIEW`
- `BLOCKED`

Each check is classified as:

- required
- conditional
- advisory

The output includes:

- blockers
- warnings
- closure_allowed
- completion percentage
- evidence supporting every quality item

Checks that require analyst judgment are no longer inferred from telemetry alone. Scope validation, contradiction review, IOC review, persistence validation and handoff status require explicit analyst sign-off when applicable.

## 3. Per-case quality sign-off

Quality sign-off is now stored per case in both SQLite and PostgreSQL.

Each record stores:

- checklist values
- authenticated actor
- update timestamp

The Web Workspace exposes the checklist directly inside the Case Workspace.

With:

```bash
socmind web events.jsonl \
  --command-db socmind.db \
  --enforce-quality-on-close
```

or PostgreSQL:

```bash
socmind web events.jsonl \
  --postgres-dsn "$SOCMIND_POSTGRES_DSN" \
  --enforce-quality-on-close
```

a transition to `resolved` is rejected when the linked investigation does not pass the required quality checks.

This makes the quality gate part of the case lifecycle instead of a passive dashboard.

## 4. Historical Case Similarity maturity

Case similarity now includes:

- weighted component scores
- independent evidence-dimension count
- match strength: weak / moderate / strong
- minimum score threshold
- overlap counts
- transparent explanations

Default weighting:

- ATT&CK techniques: 40%
- event IDs: 20%
- processes: 20%
- IOC values: 20%

Weights are normalized across evidence dimensions actually available to the compared cases.

This prevents a missing evidence class from being treated as disagreement.

A high numeric similarity based on only one evidence dimension remains a weak match.

CLI:

```bash
socmind similar-cases current.jsonl \
  --database socmind.db \
  --min-score 40 \
  --limit 10
```

## 5. Professional case queue

The Command Center now supports:

- query
- priority filter
- state filter
- owner filter
- limit
- offset
- matched-result count
- previous/next page metadata

CLI example:

```bash
socmind command-center socmind.db \
  --priority P1 \
  --state investigating \
  --limit 25 \
  --offset 0
```

The browser workspace provides previous/next controls and displays the current result range.

## 6. Detection Rule Pack Audit

A detection file is no longer considered sufficient merely because it parses.

Run:

```bash
socmind rule-pack-audit --rules detections
```

The audit checks:

- duplicate rule IDs
- title and ID presence
- supported severity level
- rule status vocabulary
- logsource metadata
- false-positive documentation
- ATT&CK tag syntax
- ATT&CK mapping presence
- selection structure
- condition references
- compatibility with SOCMind's portable Sigma subset

JSON:

```bash
socmind rule-pack-audit --rules detections --json
```

The command exits non-zero when the pack contains audit errors.

Warnings remain visible without falsely blocking a pack for documentation-only gaps.

## 7. SOC Lead workspace

The SOC Lead page now shows Rule Pack Audit status alongside:

- detection health
- TP / FP ratios
- ATT&CK coverage
- noisy rules
- top users
- top hosts

This separates:

- whether a rule exists
- whether it is structurally healthy
- whether it actually triggered on an incident
- whether analysts later marked its alerts useful or noisy

## Professional boundary

These improvements make existing SOCMind workflows more operationally credible, but they do not change the product boundary:

SOCMind remains an investigation, case-operations and detection-engineering layer alongside the organization's SIEM/EDR.

Enterprise HA, native IdP login, centralized evidence object storage and organization-specific DR remain deployment architecture concerns.
