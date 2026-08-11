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

| Area | Observation | Handling |
| --- | --- | --- |
| Local Dashboard in a restricted sandbox | The test environment can deny loopback `127.0.0.1` binding with `EPERM`. | The E2E test is loopback-only and must be run with local networking permitted. This is not permission to bind publicly. |
| Global tool freshness | The real workstation may report Semgrep, ZAP content, Trivy DB, Nuclei templates, or OSV status as degraded. | v0.7 never upgrades or reinstalls scanners to make tests green. It preserves and reports the external state. |
| First install | The installer does not edit shell startup files, so a launcher may not be on `PATH` immediately. | Agents must use the returned absolute `localEntrypoints.pathHint` or ask the user to add it to `PATH` explicitly. |

## Known limitations

- The committed fixtures are safe synthetic projects. They are not a claim of
  support for every framework version or a replacement for testing a real
  application.
- The E2E harness uses mock scanner executables so that CI is deterministic and
  offline. A separate workstation run is still required to validate the real
  independently installed toolchain.
- Runtime E2E remains limited to localhost, local Docker, or an exact target
  explicitly authorized by the documented configuration.
- No real external AI provider, autonomous fixer, Strix run, telemetry, or
  public-target scan is part of v0.7.
