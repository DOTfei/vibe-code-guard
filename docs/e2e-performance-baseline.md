# v0.7 E2E Performance Baseline

The baseline is intentionally measured with synthetic projects and mock
scanner executables. It is a regression signal for orchestration overhead, not
a promise about the speed of real upstream scanners or network-backed data.

On the current macOS Apple Silicon development path, the isolated v0.7 Agent
E2E suite completed in approximately 5 seconds including process startup,
Dashboard startup, lifecycle transitions, and three verification paths. The
full Node test suite includes the same harness and should remain within normal
local development time.

The baseline checks these operations without setting a hard wall-clock claim:

- quick change-aware planning;
- full relevant mock audit and correlation;
- targeted verification for clean, still-detected, and incomplete coverage;
- Dashboard startup and `/api/state` response; and
- large-project safety through bounded filesystem traversal and ignored
  `node_modules`, `dist`, `vendor`, and build-style directories.

When real scanners are used, report their durations separately. A slow or
unavailable vulnerability database, registry, rule source, or template source
must be reported as an external degraded state rather than hidden in this
baseline.

## v0.7.1 real-scanner observations

The following measurements came from disposable local fixtures on the same
macOS Apple Silicon development path. They are observations, not promises:

| Operation | Recorded duration |
| --- | ---: |
| Gitleaks finding audit | 14 ms |
| TruffleHog finding audit | 430 ms |
| Semgrep local-rule audit | 1,114 ms |
| Trivy dependency audit | 64 ms |
| Checkov Docker audit | 1,206 ms |
| Trivy config audit | 333 ms |
| OSV-Scanner blocked query | 20,885 ms |
| Gitleaks targeted verify | 10 ms |
| Checkov targeted verify | 1,128 ms |
| Trivy targeted verify | 321 ms |

The OSV duration reflects external/environmental unavailability and must not be
hidden inside a green performance claim. Dashboard startup and active ZAP/Nuclei
scans are not included in this real-scanner table.
