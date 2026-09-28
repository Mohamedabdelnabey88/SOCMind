# SOCMind v1.1 — Live Integrations

SOCMind keeps the investigation engine vendor-neutral while adding live connectors for common SOC infrastructure.

## Security defaults

- TLS certificate verification is enabled by default.
- Credentials are read from environment variables instead of command-line password arguments.
- `--insecure` must be explicitly selected for controlled labs using self-signed certificates.
- Live connector tests use local mock HTTP servers; CI does not require or expose real credentials.

## Wazuh Server API

Wazuh uses JWT authentication. SOCMind authenticates with the configured API user and password, then uses the bearer token for subsequent calls.

```bash
export WAZUH_API_USER=soc-analyst
export WAZUH_API_PASSWORD='...'

socmind wazuh-check https://wazuh-manager:55000
socmind wazuh-agents https://wazuh-manager:55000 --limit 50
```

For a self-signed lab only:

```bash
socmind wazuh-check https://wazuh-manager:55000 --insecure
```

## Elasticsearch live search

Authentication options are read from environment variables, in this order:

- `ELASTIC_API_KEY`
- `ELASTIC_BEARER_TOKEN`
- `ELASTIC_USERNAME` + `ELASTIC_PASSWORD`

Pull live hits:

```bash
export ELASTIC_API_KEY='...'

socmind elastic-pull https://elastic:9200 'logs-*' \
  -o elastic.ndjson \
  --size 500
```

Use a Query DSL file:

```json
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h"
      }
    }
  }
}
```

```bash
socmind elastic-pull https://elastic:9200 'logs-*' \
  -o last-hour.ndjson \
  --query-file query.json \
  --size 1000
```

The exported NDJSON can be normalized with:

```bash
socmind ingest elastic last-hour.ndjson -o normalized.jsonl
```

## MISP IOC enrichment

```bash
export MISP_API_KEY='...'

socmind misp-enrich normalized.jsonl https://misp.internal
```

JSON output:

```bash
socmind misp-enrich normalized.jsonl https://misp.internal --json
```

SOCMind performs exact IOC-value matching and reports match count/tags. A MISP match is evidence for analyst review, not an automatic malicious verdict.

## OpenCTI connectivity

```bash
export OPENCTI_TOKEN='...'
socmind opencti-check https://opencti.internal
```

The connector uses the OpenCTI GraphQL endpoint with bearer authentication. v1.1 exposes connectivity and a reusable GraphQL client; organization-specific enrichment queries can be layered on top without coupling the core engine to one OpenCTI schema/version.

## Guided CLI help

```bash
socmind help
socmind help getting-started
socmind help triage
socmind help case-workflow
socmind help integrations
socmind help detection-engineering
socmind help kali
socmind help demo
```

Every command also supports argparse help:

```bash
socmind elastic-pull --help
socmind wazuh-agents --help
```

## Installation diagnostics

```bash
socmind doctor
```

Machine-readable form:

```bash
socmind doctor --json
```
