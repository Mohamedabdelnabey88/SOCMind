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
command-transition
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
```

## Production SOC operations

```text
alert-orchestrate
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
