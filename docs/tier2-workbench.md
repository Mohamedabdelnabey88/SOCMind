# Tier 2 Investigation Workbench

SOCMind v0.4 introduces a structured Tier 2 workflow on top of the Tier 1 triage engine.

## Investigation Graph

The graph pivots around observable entities:

- users
- hosts
- processes
- source/destination IPs
- persistence artifacts
- services

It emits Mermaid syntax so an analyst can paste the output directly into GitHub, Markdown tooling, or documentation systems.

## Hypothesis Model

SOCMind separates an observed fact from an analyst hypothesis.

Each hypothesis contains:

- a descriptive name
- confidence score
- supporting observations
- contradicting evidence / validation gaps

Confidence is heuristic and explainable. It is not a probability of guilt, compromise, or malicious intent.

## Reusable Playbooks

Findings map to repeatable investigation phases:

1. Validate
2. Scope
3. Investigate / Decode
4. Escalate or Document

Playbooks are deliberately procedural. They help Tier 1/Tier 2 analysts remain consistent without replacing analyst judgment.

## Case Export

A case JSON package contains:

- case metadata
- finding summaries
- triage recommendations
- playbook steps
- hypotheses
- IOCs
- investigation graph

This makes a SOCMind investigation portable for future UI, SIEM, SOAR, or ticketing integrations.
