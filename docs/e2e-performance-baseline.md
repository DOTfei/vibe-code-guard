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
