# Contributing to SOCMind

SOCMind accepts defensive Blue Team improvements that preserve analyst transparency and cross-platform quality.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[all]" pytest httpx
pytest -q
```

## Before opening a pull request

Run:

```bash
python -m compileall -q src
pytest -q
socmind doctor
socmind security-check
socmind benchmark --events 5000
```

Changes should:

- preserve Windows, Ubuntu and Kali compatibility
- avoid embedding credentials or real incident data
- include tests for new behavior
- keep detection reasoning explainable
- avoid automatic destructive containment actions
- document new CLI commands in `socmind help` and the relevant docs

## Detection contributions

New detection rules should include:

- clear title and rationale
- ATT&CK mapping where justified
- sanitized fixture
- positive regression test
- false-positive considerations

## Security-sensitive changes

Authentication, remote networking, evidence handling and audit changes require dedicated tests.
