# Running SOCMind on Kali Linux

SOCMind is tested in CI inside the official `kalilinux/kali-rolling` container.

## Important: do not use sudo pip install

Modern Kali protects the system Python environment. Use an isolated virtual environment or pipx.

## Recommended development install

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/Mohamedabdelnabey88/SOCMind.git
cd SOCMind

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[all]"
```

Verify:

```bash
socmind --help
pytest -q
```

Run a Linux investigation:

```bash
socmind analyze examples/linux_attack_chain.jsonl \
  --timeline \
  --iocs \
  --graph \
  --hypotheses \
  --case-output kali-case.json \
  --case-id KALI-DEMO-001
```

## CLI-only install with pipx

For users who only want the command line application:

```bash
sudo apt update
sudo apt install -y pipx git
pipx ensurepath
pipx install "git+https://github.com/Mohamedabdelnabey88/SOCMind.git"
```

Open a new shell, then:

```bash
socmind --help
```

Optional extras can be injected into the pipx environment when needed.

## Kali telemetry examples

Authentication logs:

```bash
socmind ingest linux-auth /var/log/auth.log \
  --host kali-lab --year 2026 -o normalized.jsonl
```

journald:

```bash
journalctl -o json > journal.jsonl
socmind ingest journald journal.jsonl -o normalized.jsonl
```

auditd:

```bash
socmind ingest auditd /var/log/audit/audit.log \
  --host kali-lab -o normalized.jsonl
```

Then:

```bash
socmind analyze normalized.jsonl --timeline --iocs --graph --hypotheses
```

## What CI proves

The Kali job creates a fresh isolated Python environment inside `kalilinux/kali-rolling`, installs SOCMind, runs the test suite, executes a Linux investigation, exports a case, and runs ATT&CK coverage analysis.
