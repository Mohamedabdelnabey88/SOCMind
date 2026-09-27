# Case 001 — Authentication to Persistence

## Scenario

A user account receives repeated failed authentication attempts. A successful authentication follows, then privileged or persistence-related behavior appears on the endpoint.

## Tier 1 objectives

- Validate whether the source is expected.
- Determine whether a successful session followed the failures.
- Establish the affected identity and endpoint.
- Review MFA / identity-provider context where available.
- Escalate when post-authentication activity is unexplained.

## Tier 2 objectives

- Reconstruct the post-authentication timeline.
- Identify process, privilege, persistence, and network changes.
- Hunt the same source, account, or artifact across peer systems.
- Map confirmed behavior to MITRE ATT&CK.
- Document evidence supporting containment recommendations.

## Windows evidence path

`4625 → 4624 → PowerShell → network → 4698 / 7045`

## Linux evidence path

`SSH failures → SSH success → sudo → systemd / cron`

## What SOCMind demonstrates

This case intentionally expresses the same investigation concept across Windows and Linux rather than treating operating systems as separate products. The analyst sees one investigation workflow with source-specific evidence.
