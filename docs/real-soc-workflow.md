# Real SOC Workflow Model

SOCMind is designed to demonstrate more than alert parsing. It models the operational responsibilities expected from a Tier 1 / Tier 2 SOC analyst.

## Case lifecycle

```text
New
 ↓
Triage
 ↓
Investigating
 ↓
Contained
 ↓
Resolved
```

Alternative terminal states include `false-positive` and justified direct resolution from triage/investigation.

## Ownership

Cases can be assigned to an analyst. Ownership is explicit so a handoff does not depend on tribal knowledge.

## SLA

Default response targets:

- P1: 15 minutes
- P2: 30 minutes
- P3: 120 minutes

These values are examples for the portfolio project and should be configured to match an organization's actual SOC SLA.

## Analyst audit trail

Material actions can be logged with:

- actor
- timestamp
- action
- detail
- case ID

This supports accountability and reconstructing analyst decisions during review.

## Evidence provenance

Imported evidence can be SHA-256 fingerprinted to preserve a verifiable reference to the exact file reviewed by the analyst.

## Shift handoff

SOCMind can create a compact handoff containing:

- current priority
- findings
- investigation progress
- next analyst actions
- outstanding validation gaps

This is deliberately operational: another analyst should be able to continue the investigation without restarting from the alert.
