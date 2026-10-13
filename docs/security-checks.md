# SOCMind security checks

SOCMind runs a dedicated GitHub Actions security workflow in addition to its functional and integration CI.

## Automated checks

- **Dependency audit:** installs the project with every declared optional extra (`.[all]`) and runs `pip-audit` against the installed environment. Known vulnerabilities fail the job so they can be triaged and resolved.
- **Static analysis:** runs Bandit against `src/socmind` and fails on high-severity findings with at least medium confidence.
- **Schedule:** the workflow runs on pushes to `main`, pull requests, manual dispatch, and weekly on Monday. Scheduled scans help detect newly disclosed dependency vulnerabilities even when application code has not changed.
- **Reports:** JSON reports are uploaded as workflow artifacts for 14 days, including when a scan fails and a report was produced.

## Review and response

1. Open the failed job and download its report artifact.
2. Confirm each finding against the affected dependency or code path; distinguish exploitable issues from false positives with written reasoning.
3. Upgrade or constrain vulnerable dependencies where compatible, or patch the affected code. Prefer a supported upstream fix over suppressions.
4. If a finding is not applicable, document the evidence and narrow scope of the exception in a reviewed change. Do not silently suppress findings or expose secrets in logs.
5. Re-run the workflow and the existing functional/integration CI before merging.

## Scope and limitations

These checks are a baseline, not a complete security certification. They do not replace secret scanning, code review, threat modeling, penetration testing, hardened runner/action policies, deployment-specific identity-provider validation, or production monitoring. The dependency audit checks the environment resolved by CI; production images and separately managed deployment dependencies must also be audited. Review GitHub Actions permissions and pin third-party actions to verified commit SHAs as part of release hardening.
