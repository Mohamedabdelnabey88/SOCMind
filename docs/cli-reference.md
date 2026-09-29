# SOCMind CLI Reference

SOCMind is organized by analyst task rather than by implementation module.

## Discover

```bash
socmind --help
socmind --version
socmind help
socmind help <topic>
socmind doctor
socmind security-check
```

## Ingest / pull telemetry

```text
ingest
elastic-pull
wazuh-check
wazuh-agents
```

## Investigate

```text
analyze
timeline
iocs
graph
case
investigate
evidence
enrich
misp-enrich
opencti-check
```

## Case operations

```text
case-init
case-assign
case-transition
sla
note
audit
handoff
escalate
command-register
command-ack
command-assign
command-transition   # supports --reason for auditable state-change context
command-note
command-show
command-center
shift-brief
```

## Investigation Replay Engine

```text
replay
detection-replay
what-if
case-review
learn-from-case
```

Workflow help:

```bash
socmind help ire
```

## Evidence reasoning

```text
contradictions
similar-cases
```

Workflow help:

```bash
socmind help reasoning
```

## Detection engineering

```text
detect
rule-test
coverage
gaps
tune
lead-health

rule-register
rule-syntax
rule-lifecycle-test
rule-replay-record
rule-fp-record
rule-coverage-record
rule-version
rule-transition
rule-show
rule-list
```

Governed lifecycle example:

```bash
socmind rule-register rule-registry.json detections/windows/suspicious-powershell.yml \
  --owner detection-team --actor tier2@example.com --role senior-analyst

socmind rule-transition rule-registry.json socmind-win-powershell-hidden \
  --state testing --actor tier2@example.com --role senior-analyst \
  --note "Begin controlled validation"

socmind rule-lifecycle-test rule-registry.json socmind-win-powershell-hidden \
  tests/fixtures/powershell-rule-test.json \
  --actor tier2@example.com --role senior-analyst

socmind rule-replay-record rule-registry.json socmind-win-powershell-hidden \
  tests/fixtures/rule-events.jsonl --case-id CONFIRMED-001 \
  --actor tier2@example.com --role senior-analyst

socmind rule-fp-record rule-registry.json socmind-win-powershell-hidden \
  --sample-size 20 --false-positives 1 \
  --note "Representative admin activity" \
  --actor tier2@example.com --role senior-analyst

socmind rule-coverage-record rule-registry.json socmind-win-powershell-hidden \
  --visibility-delta 12.5 --new-technique T1059.001 \
  --actor tier2@example.com --role senior-analyst

socmind rule-transition rule-registry.json socmind-win-powershell-hidden \
  --state approved --actor lead@example.com --role lead \
  --note "Validation evidence reviewed"

socmind rule-transition rule-registry.json socmind-win-powershell-hidden \
  --state production --actor lead@example.com --role lead \
  --note "Lead-authorized production promotion"
```

Approval and production promotion are never automatic.

## Production SOC operations

```text
alert-orchestrate
alert-live
case-collect-evidence
```

Workflow help:

```bash
socmind help production-ops
```

## Enterprise operations

```text
enterprise-info
trusted-sign
audit-verify
backup
retention
postgres-schema
postgres-init
postgres-health
```

Workflow help:

```bash
socmind help enterprise
```

## Workspace / demo

```text
web
demo-init
benchmark
```

For exact flags:

```bash
socmind <command> --help
```

For workflow guidance:

```bash
socmind help triage
socmind help case-workflow
socmind help integrations
```
