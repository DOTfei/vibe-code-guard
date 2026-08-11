# Public Beta Readiness — v0.7

Vibe Code Guard remains an early-alpha, local-first security workflow. This
checklist describes what v0.7 validates and what it deliberately does not
promise.

## User path validated by the E2E harness

```text
INSTALL (dry-run / isolated plan)
  → DOCTOR
  → STACK DETECTION
  → CHANGE-AWARE AUDIT
  → RAW OBSERVATIONS
  → UNIFIED / CORRELATED FINDINGS
  → RELEASE GATE
  → LOCAL DASHBOARD
  → AUTHORIZED FIX
  → TARGETED VERIFY
```

The harness uses temporary directories, synthetic fixtures, mock scanner
executables, and loopback-only Dashboard checks. It never mutates the real
global scanner installation.

## Release checklist

| Area | v0.7 position |
| --- | --- |
| Install | `./install.sh --dry-run` is the safe preview; `--yes` applies only its fixed plan. No `curl | sh`, arbitrary scripts, shell startup edits, or OS security-control changes. |
| Uninstall | Removes only Vibe Code Guard-owned launchers/metadata and preserves upstream scanners and unrelated files. |
| Doctor | Reports `READY`, `DEGRADED`, or `BROKEN`; binary health and external content/update freshness remain distinguishable. |
| Audit | `vibe-code-guard audit . --profile auto|quick|full|release --json`; the agent need not call eight scanners individually. |
| Dashboard | Binds to `127.0.0.1` only, has no cloud account, telemetry, analytics, or source upload, and exposes real persisted run data. |
| Fix/verify | Only an authorized external agent changes application code. Verification requires the relevant scanner coverage, known versions, valid structured output, stable scope, and a successful rescan. |
| Updater | `vibe-code-guard update` manages only Vibe Code Guard launchers. Scanner updates are one-tool, official-source, explicit, validated lifecycle operations. |
| Ownership | Upstream scanners are independently installed, not bundled, not modified, not relicensed, and not claimed as Vibe Code Guard work. Review downloaded rules, templates, databases, add-ons, and plugins separately. |
| Privacy | Normal Vibe Code Guard operations are local-only. v0.4 advisory AI is disabled by default; no real provider is included in v0.7. |
| Scope | ZAP/Nuclei require localhost, local Docker, or exact explicit authorization. `0.0.0.0` and arbitrary public targets are rejected. |

## Validated fixture matrix

| Fixture | Stack signal | Main path exercised | Safety boundary |
| --- | --- | --- | --- |
| React/Vite | Node.js, React, Vite | UI/source + dependency selection | No build or server |
| Node API | Node.js | secrets/static/dependency selection, correlation, fix/verify | API code is never launched |
| Python | Python | Python stack detection and static selection | No interpreter or package install |
| Supabase-style | Supabase | database/policy classification | SQL is never applied |
| Docker | Node.js, Docker | container/IaC selection | Image is never built or run |
| Terraform | Terraform | IaC selection and Checkov mapping | Terraform is never initialized/applied |

Expected findings are stored beside each fixture in `expected-results.json`.
They are synthetic test contracts, not real credentials or production data.

## Platform support matrix

| Platform | Status | Validation statement |
| --- | --- | --- |
| macOS Apple Silicon | SUPPORTED | Primary development path; Homebrew-oriented installation and loopback Dashboard flow validated. |
| macOS Intel | PARTIAL | Node/CLI design is portable, but the complete scanner installation path is not validated here. |
| Linux | PARTIAL | CLI/config contracts are intended to work; complete distribution-specific scanner installation is not claimed. |
| Windows | NOT SUPPORTED | No native Windows installer or path/runtime validation is claimed. |
| WSL | PARTIAL | Linux-oriented use may work, but WSL path, scanner, and Dashboard behavior is not validated. |

## Stable agent contracts

All agent-facing JSON uses `schemaVersion: 1.0` and `workflowVersion: 0.7.0`.
Exit codes are:

- `0`: requested command completed; inspect `releaseGate` for deployment
  readiness;
- `1`: operational failure or `STILL_DETECTED` targeted verification;
- `2`: degraded or incomplete external state, including
  `VERIFICATION_INCOMPLETE`.

A completed audit can therefore return `0` while correctly reporting
`releaseGate: DO NOT DEPLOY`; this prevents a coding agent from confusing
“the workflow executed” with “the project is safe to release.”

## Explicit limitations

Vibe Code Guard does not promise complete vulnerability coverage, a secure
result, autonomous penetration testing, professional pentesting replacement,
automatic fixing, public-target attack automation, or current upstream
intelligence when the machine is offline. Skipped, failed, missing, stale, and
unknown dependencies remain visible to the user and to the agent.

See [`docs/agent-integration.md`](agent-integration.md),
[`docs/installation.md`](installation.md), and
[`docs/e2e-friction-log.md`](e2e-friction-log.md) for operational details.
