# How SOCMind Demonstrates SOC Tier 1 / Tier 2 Skill

SOCMind is intentionally structured to demonstrate practical analyst judgment and operational discipline.

## Tier 1 skills demonstrated

- alert triage
- Windows and Linux authentication analysis
- IOC extraction
- severity and priority classification
- escalation criteria
- evidence documentation
- false-positive handling
- SIEM-normalized workflow using Wazuh and Elastic exports

## Tier 2 skills demonstrated

- cross-source evidence correlation
- process ancestry
- attack timeline reconstruction
- hypothesis-driven investigation
- MITRE ATT&CK mapping
- persistence analysis
- escalation package creation
- shift handoff quality
- detection gap analysis
- Sigma-style rule testing and tuning

## SOC engineering skills demonstrated

- normalized telemetry architecture
- cross-platform Windows/Linux/Kali support
- automated CI quality gates
- SIEM adapters
- evidence provenance
- case state machine
- analyst audit trail
- SLA tracking
- detection regression tests
- web investigation dashboard

## Interview demo flow

A strong live demonstration is:

```bash
socmind investigate examples/attack_chain.jsonl \
  -o demo-case \
  --case-id DEMO-001 \
  --priority P1 \
  --owner mohamed

socmind web examples/attack_chain.jsonl \
  --case-id DEMO-001
```

Then explain:

1. what triggered the findings
2. how the evidence is correlated
3. why the alert is escalated
4. what evidence is still missing
5. which ATT&CK techniques are observed
6. where local detection coverage is missing
7. how the next analyst receives the case
8. how evidence integrity is preserved

The value of the project is not the number of alerts it can detect. The value is that it models how a disciplined SOC analyst turns telemetry into a defensible investigation.
