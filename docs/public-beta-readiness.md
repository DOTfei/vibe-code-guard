# Public Beta Readiness — v0.8

Vibe Code Guard is a local-first public beta security workflow for AI coding
agents and vibe coders. This checklist describes the v0.8 Dashboard and
packaging experience on top of the v0.7/v0.7.1 evidence boundary. It does not
upgrade partial real-scanner evidence into a broader security claim.

## Status vocabulary

- `PASS`: the named product contract is covered by deterministic tests or the
  stated local evidence.
- `DEGRADED`: the workflow remains usable, but tool, content, platform, or
  environment coverage has a documented limitation.
- `BLOCKED`: the requested validation depends on an unavailable external or
  host capability and must not be presented as a clean result.
- `NOT_TESTED`: the validation dimension was not performed. It is not a
  failure and is not an implied pass.

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
  → REAL SCANNER VALIDATION
```

The harness uses temporary directories, synthetic fixtures, mock scanner
executables, and loopback-only Dashboard checks. It never mutates the real
global scanner installation.

## Release checklist

| Area | Status | Evidence class | v0.8 position |
| --- | --- | --- | --- |
| Install | PASS | Real dry-run + isolated tests | `./install.sh --dry-run` is the safe preview; missing/prerequisite/conflict states are tested without host mutation. |
| Uninstall | PASS | Existing deterministic tests | Removes only Vibe Code Guard-owned launchers/metadata and preserves upstream scanners and unrelated files. |
| Doctor | DEGRADED | Real toolchain health | Reports `READY`, `DEGRADED`, or `BROKEN`; this machine remains degraded because Semgrep/ZAP version paths and content freshness require review. |
| Audit | PASS | Mock E2E; real smoke separate | `vibe-code-guard audit . --profile auto|quick|full|release --json`; the agent need not call eight scanners individually. |
| Dashboard | PASS | Mock E2E + loopback smoke | Binds to `127.0.0.1` only, has no cloud account, telemetry, analytics, or source upload, and exposes real persisted run data. |
| Fix/verify | PASS | Mock E2E + real disposable fixtures | Only an authorized external agent changes application code. Verification requires relevant coverage, known versions, valid structured output, stable scope, and a successful rescan. Real Gitleaks/TruffleHog-family and Checkov/Trivy-config chains completed; real still-detected and incomplete-coverage paths were also exercised. |
| Updater | PASS | Dry-run + lifecycle tests | `vibe-code-guard update` manages only Vibe Code Guard launchers. Scanner updates are one-tool, official-source, explicit, validated lifecycle operations. |
| Ownership | PASS | Documentation/metadata review | Upstream scanners are independently installed, not bundled, not modified, not relicensed, and not claimed as Vibe Code Guard work. |
| Privacy | PASS | Static review + regression tests | Normal Vibe Code Guard operations are local-only. v0.4 advisory AI is disabled by default; no real provider is included in v0.8. |
| Scope | PASS | Runtime/security tests + real Nuclei localhost smoke | ZAP/Nuclei require localhost, local Docker, or exact explicit authorization. `0.0.0.0` and arbitrary public targets are rejected. |
| Findings | PASS | Canonical JSON + Dashboard view-model tests | The Dashboard reads correlated findings, keeps raw evidence available, prioritizes release attention, and preserves historical v0.2 data. |
| Fix lifecycle | PASS | Canonical lifecycle + UI regression tests | `FIXED` is displayed as not verified; `VERIFIED` is displayed only when the canonical lifecycle says so. |
| Targeted verify | PASS | Existing v0.6/v0.7 contracts | Dashboard exposes verification state and next action without marking a finding verified itself. |
| Release gate | PASS | Canonical gate + presentation tests | Human labels distinguish `SAFE TO DEPLOY`, `DO NOT DEPLOY`, `REVIEW REQUIRED`, and `INCOMPLETE SECURITY COVERAGE`; the canonical gate remains authoritative. |
| Degraded behavior | PASS | View-model + toolchain contract tests | Skipped, stale, missing, degraded, and unknown coverage remains visible and is not rendered as green completion. |
| README onboarding | PASS | Documentation review | The first screen gives one copy-paste agent prompt and explains the install → doctor → audit → Dashboard path. |
| Agent onboarding | PASS | AGENTS/CLAUDE/docs contract | Agents use CLI/JSON; humans use the Dashboard; both consume the same canonical state. |
| Demo flow | PASS | Safe synthetic fixture instructions | The maintainer demo uses local temporary data only; it does not package or launch a vulnerable public service. |
| Real scanner validation | DEGRADED | v0.7.1 real-scanner report | Gitleaks, Checkov, and the tested Trivy config path are `REAL_VALIDATED`; partial, blocked, and not-tested dimensions remain documented below. |
| Privacy/local-first | PASS | Static review + regression tests | No cloud backend, account, telemetry, analytics, source upload, or public-target default active scanning was added. |
| Attribution/licenses | PASS | Documentation/metadata review | Upstream tools remain independently installed, attributed, and separately licensed. Downloaded rules, templates, databases, plugins, add-ons, and other artifacts may have separate terms. |
| Support matrix | DEGRADED | Platform and fixture evidence | macOS Apple Silicon is the primary supported path; other platforms remain partial or not supported as stated below. |
| Limitations | PASS | Public-beta documentation review | The release does not promise complete vulnerability coverage, professional pentesting replacement, or a secure result. |

## Real scanner smoke boundary

These checks were run read-only against the committed fixtures or a disposable
localhost target. They are deliberately separate from the mock E2E result.

The real-scanner taxonomy uses exactly four states: `REAL_VALIDATED` for a
completed tested workflow, `REAL_PARTIAL` for real execution with an untested
dimension, `BLOCKED_BY_ENVIRONMENT` for an unavailable external dependency, and
`NOT_TESTED` for a validation dimension not performed. `NOT_TESTED` is not a
failure result.

| Scanner | Status | Fixture/target | Evidence and limitation |
| --- | --- | --- | --- |
| Gitleaks | REAL_VALIDATED | Disposable Node API + local synthetic rule | Real 8.30.1 finding was normalized, fixed, rescanned, and returned `VERIFIED`. |
| TruffleHog | REAL_PARTIAL | Disposable Node API | Real JSONL scan and secret-family coverage completed safely with no synthetic match; no network verification was enabled. |
| Semgrep | REAL_PARTIAL | Node API + repository-local rule | Real 1.172.0 produced a structured local-rule finding. A real Semgrep finding → fix → targeted verify chain was `NOT_TESTED`; temporary HOME/CA settings were required. |
| Trivy | REAL_VALIDATED | Dockerfile config path | Real 0.73.0 returned config findings with `--skip-db-update` and completed the Checkov + Trivy config verification chain. Dependency finding → fix → targeted verify was `NOT_TESTED`; the local DB was usable but expired. |
| OSV-Scanner | BLOCKED_BY_ENVIRONMENT | Node API package-lock | Real scanner started but external `api.osv.dev` access was unavailable; no false clean result was reported. |
| Checkov | REAL_VALIDATED | Disposable Dockerfile | Real 3.3.0 returned `CKV_DOCKER_2` / `CKV_DOCKER_3`; after remediation, Checkov + Trivy targeted verification returned `VERIFIED`. |
| Nuclei | REAL_PARTIAL | Disposable `127.0.0.1` server | Real localhost invocation completed with no finding; active Nuclei finding detection is explicitly `NOT_TESTED`. No template update was performed. |
| OWASP ZAP | REAL_PARTIAL | Temporary HOME version smoke | Real ZAP 2.17.0 launcher/version path was exercised; active ZAP finding detection is explicitly `NOT_TESTED`. No add-on update was performed. |

`PASS` in this table means the named smoke check completed. It does not mean
the scanner is current, that every project path is covered, or that the
project is secure.

## v0.7.1 real-scanner acceptance

The real validation used only disposable fixtures and loopback boundaries. It
completed two real fix → targeted rescan → `VERIFIED` chains:

- Gitleaks + TruffleHog family for a synthetic secret finding;
- Checkov + Trivy config scanning for a synthetic Dockerfile finding.

The real validator also demonstrated `STILL_DETECTED` with exit 1,
`VERIFICATION_INCOMPLETE` with exit 2 when a scanner was unavailable, and
`VERIFICATION_INCOMPLETE` when scanner scope was changed with an ignore file.
The local Dashboard persisted the same `VERIFIED` state and scanner versions as
the CLI result. See [`docs/real-scanner-validation.md`](real-scanner-validation.md)
for commands, versions, durations, and limitations.

The explicit `NOT_TESTED` dimensions remain limited to the report's stated
boundaries; they are not converted into failures or implied passes.

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

The v0.7.1 real-scanner run does not claim complete real-world proof. OSV
dependency intelligence is blocked by the current external network
environment; the Trivy database is usable but expired; Semgrep's normal
HOME/log path and ZAP content freshness remain environment-sensitive; and
active ZAP/Nuclei finding detection was not completed.

## Dashboard and agent acceptance

The human first screen is organized around project status, release decision,
important issues, verification, coverage/toolchain health, and recent activity.
Scanner names and raw observations remain available as technical details.

The Dashboard does not become an agent API. A coding agent should use:

```text
vibe-code-guard doctor --json
vibe-code-guard audit . --profile auto --json
vibe-code-guard dashboard --json
```

The Dashboard and CLI read the same run state. The Dashboard is a presentation
layer: it cannot change severity, lifecycle, scanner evidence, verification,
or the release gate. The copy prompt contains finding IDs, severity, titles,
and locations only; it does not copy raw evidence or secret values.
