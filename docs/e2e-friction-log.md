# v0.7 Agent E2E Friction Log

This is a record of friction found while exercising the copy-paste Agent
workflow with safe temporary projects. It is intentionally separate from
scanner findings: the entries below describe product usability or test
environment behavior, not vulnerabilities in a user's application.

## Resolved

| Area | Friction | Resolution |
| --- | --- | --- |
| CLI verification | `verify` referenced the verification function from the agent metadata module instead of the existing server verification API. | The CLI now loads the existing `verifyFinding` implementation at command time; targeted verification is covered by the v0.7 E2E flow. |
| Release gate vs process state | A completed audit with blocking findings was reported as a failed command, which made agent interpretation ambiguous. | JSON now reports `status: COMPLETED` for a completed assessment while `releaseGate.label` remains `DO NOT DEPLOY`. Operational scanner failures remain exit 1. |
| Agent contracts | JSON responses did not have one explicit top-level contract marker. | Agent-facing JSON now includes `schemaVersion: 1.0` and `workflowVersion: 0.7.0`. |

## Environment-specific

| Severity | Area | Observation | Handling |
| --- | --- | --- | --- |
| P2 | Local Dashboard in a restricted sandbox | The test environment can deny loopback `127.0.0.1` binding with `EPERM`. | The E2E test is loopback-only and must be run with local networking permitted. This is not permission to bind publicly. |
| P2 | Global tool freshness | The real workstation may report Semgrep, ZAP content, Trivy DB, Nuclei templates, or OSV status as degraded. | v0.7 never upgrades or reinstalls scanners to make tests green. It preserves and reports the external state. |
| P2 | First install | The installer does not edit shell startup files, so a launcher may not be on `PATH` immediately. | Agents must use the returned absolute `localEntrypoints.pathHint` or ask the user to add it to `PATH` explicitly. |

## v0.7.1 real-scanner validation

| Severity | Area | Observation | Handling |
| --- | --- | --- | --- |
| P2 | Semgrep local execution | The installed Semgrep process may try to write its normal log under a non-writable HOME, and remote registry/CA access is not reliable in a restricted environment. | The real core validation uses a repository-local pinned synthetic rule, a temporary HOME, and explicit CA/metrics settings. The limitation is reported rather than treated as a clean remote-rule result. |
| P2 | OSV-Scanner | `api.osv.dev` was unavailable; a real dependency run could not complete its external query. | Classify OSV as `BLOCKED_BY_ENVIRONMENT` and keep the dependency release gate conservative. No refresh or retry loop is hidden. |
| P2 | Trivy database | The local DB is readable and schema-compatible but its freshness window is expired. | Run deterministic local checks with `--skip-db-update`; report DB freshness separately as DEGRADED and never equate it with a current database. |
| P2 | Checkov path output | Checkov emitted a project Dockerfile as `/Dockerfile`, which originally prevented a stable scope fingerprint. | The adapter now maps a leading-slash project-relative path only after proving the file is a regular file inside the authorized project root; outside paths remain outside. |
| P3 | Checkov guideline lookup | External guideline mapping lookup failed while local checks still returned structured findings. | Preserve local findings and report the external mapping limitation separately. |
| P3 | TruffleHog synthetic coverage | The safe repository-owned token used for the Gitleaks chain was not detected by TruffleHog. | Record real execution and parsing as partial coverage; never claim TruffleHog detection was proven by this fixture. |
| P3 | ZAP/Nuclei real detection | A safe active runtime finding was not required or completed in v0.7.1. | Keep active scanning scoped to localhost/authorized targets and classify launcher/loopback smoke as partial only. |

## Known limitations

- **P2:** The committed fixtures are safe synthetic projects. They are not a claim of
  support for every framework version or a replacement for testing a real
  application.
- **P2:** The E2E harness uses mock scanner executables so that CI is deterministic and
  offline. A separate workstation run is still required to validate the real
  independently installed toolchain.
- **P2:** Runtime E2E remains limited to localhost, local Docker, or an exact target
  explicitly authorized by the documented configuration.
- **P3:** No real external AI provider, autonomous fixer, Strix run, telemetry, or
  public-target scan is part of v0.7.
