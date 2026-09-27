# Detection Engineering in SOCMind

SOCMind v0.5 connects Tier 2 investigations back to detection quality.

## Sigma interoperability

SOCMind loads standard Sigma-style YAML metadata and a deliberately small, documented matching subset against the normalized event model.

Supported field modifiers:

- `contains`
- `startswith`
- `endswith`

Supported conditions:

- one named selection
- simple `selection_a and selection_b`
- simple `selection_a or selection_b`

This is **not** a claim of full Sigma specification compatibility. Unsupported conditions or modifiers fail explicitly instead of being silently misinterpreted.

## Coverage Matrix

SOCMind compares ATT&CK techniques observed during an investigation with ATT&CK tags in the local rule pack.

This answers two separate questions:

1. What behavior did the investigation observe?
2. Do we have a detection rule covering that technique?

A missing rule is reported as a **detection gap**, not proof that the technique was undetectable.

## Rule Tests

Rule behavior can be locked to sanitized event fixtures. Each fixture declares the expected number of matches. CI can then catch a rule that becomes too broad or stops matching after a change.

## False-positive tuning

SOCMind accepts analyst dispositions and only suggests tuning after a minimum evidence threshold. A repeated benign pattern may justify a scoped exclusion, but SOCMind intentionally recommends preserving the underlying behavior rather than globally suppressing it.

This models a healthy SOC feedback loop:

```text
Alert
  ↓
Investigation
  ↓
Disposition
  ↓
Detection feedback
  ↓
Rule test
  ↓
Safer tuning
```
