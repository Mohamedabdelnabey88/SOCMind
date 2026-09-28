# SOCMind Feature Maturity Upgrade

This upgrade focuses on making existing SOCMind capabilities operationally trustworthy rather than simply adding more features.

## Detection Replay maturity

Detection Replay now reports both incident-level and technique-level visibility.

For each observed ATT&CK technique SOCMind records:

- first observed step
- first detected step
- detection delay in replay steps
- number of observed evidence steps
- number of detected evidence steps
- technique-specific visibility percentage
- contributing detection rules

It also reports rule contribution:

- first matching step
- number of matched replay steps
- ATT&CK techniques declared by the rule

### Interpretation

A rule matching one event does not imply that every technique attached to that event was detected by that rule. Technique contribution is only credited when the rule itself declares the corresponding ATT&CK technique.

`visibility_percent` remains incident-specific. It is not a universal detection-quality score.

## Investigation Quality Gate maturity

The Quality Gate now distinguishes:

- complete
- incomplete
- not applicable
- analyst confirmation required

Checks that are irrelevant to the current evidence no longer lower investigation completeness.

Examples:

- If no IOC exists in the evidence, IOC review is N/A rather than failed.
- Persistence validation is only applicable when persistence is observed.
- Missing analyst validation is separated from automatically observable evidence.
- Contradiction review is separate from unresolved validation gaps.

The Quality Gate evaluates investigation completeness, not analyst performance.

## Historical Case Similarity maturity

Similarity is now normalized only across evidence dimensions that are actually comparable.

Dimensions:

- ATT&CK techniques — 40% nominal weight
- Event IDs — 20%
- Processes — 20%
- IOC values — 20%

If both cases have no IOC evidence, the absent IOC dimension is excluded from the denominator instead of automatically reducing the score.

Each result also reports:

- matched evidence dimensions
- comparable evidence dimensions
- confidence band: high / moderate / limited

### Confidence meaning

Confidence describes the breadth of evidence supporting the similarity result.

It is not attribution.

It does not estimate the probability of:

- a common attacker
- a common campaign
- a common malware family
- a common root cause

## Evidence Contradiction maturity

Alternative or contradicting context now preserves provenance:

- source event index
- timestamp
- event ID
- host

This allows an analyst to move directly from a reasoning statement back to the evidence that produced it.

Validation gaps remain separate from explicit contradicting evidence.

## Detection Health maturity

Rule-health results now include:

- total disposition sample size
- classified sample size
- unclassified sample size
- TP rate
- FP rate
- Wilson 95% interval for FP rate
- sample sufficiency
- health status
- explainable health score

Sample sufficiency:

- fewer than 5 classified dispositions: `insufficient`
- 5–19: `limited`
- 20+: `established`

Health status:

- `insufficient-data`
- `stable`
- `watch`
- `noisy`

This prevents very small samples from being presented with the same confidence as mature detection telemetry.

## Web workspace

The web interface exposes these maturity signals directly:

- per-technique replay timing
- blind meaningful steps
- rule contributors
- Quality Gate N/A states
- analyst-confirmation markers
- similarity confidence and evidence breadth
- detection-health confidence intervals and sample sufficiency

## Design principle

SOCMind should prefer an explainable incomplete answer over an overconfident score.

The maturity work therefore prioritizes:

1. evidence provenance
2. applicability
3. sample sufficiency
4. uncertainty visibility
5. analyst decision support
6. stable regression-tested semantics
