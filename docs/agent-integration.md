# Agent Integration

Vibe Code Guard is a security toolkit and workflow layer for external coding
agents such as Codex, Claude Code, Gemini CLI, Cursor agents, and similar
tools. The external agent supplies project understanding, explanation, and
authorized code changes. Vibe Code Guard supplies the repeatable local
security workflow.

## Product boundary

The upstream scanners provide the detection engines. Vibe Code Guard does not
claim their work, does not bundle their binaries, and does not relicense their
licenses. It provides:

- safe dependency/toolchain bootstrap and health status;
- change-aware project discovery and scanner selection;
- raw Unified Findings and correlated findings;
- lifecycle and release-gate persistence;
- structured JSON for agents;
- a localhost-only Dashboard; and
- explicit skip reasons for checks that were not authorized or applicable.

The v0.4 AI Review Framework remains optional, advisory, and disabled by
default. It is not a Vibe Code Guard assistant and v0.5 adds no real AI
provider.

## Canonical workflow contract

```text
INSTALL
  → DOCTOR
  → TOOL CHECK
  → PROJECT_DISCOVERY
  → THREAT_MODEL
  → SCAN
  → NORMALIZE
  → CORRELATE
  → RELEASE_GATE
  → DASHBOARD
  → EXPLAIN

Optional after explicit user approval:
FIX → TARGETED RESCAN → VERIFY
```

The external agent must preserve this authority order. It may explain a
finding, but only the deterministic scanner/lifecycle workflow can establish
that a finding is verified.

## Canonical commands

From a checkout of this repository:

```bash
./install.sh --dry-run
./install.sh --yes
vibe-code-guard doctor --json
vibe-code-guard audit . --profile auto --json
vibe-code-guard dashboard --json
```

Installation and security readiness are reported separately. A successful
launcher installation may return `INSTALLED_WITH_ACTION_REQUIRED` when a
required scanner database or runtime is not ready. Read the doctor's
`lifecycle.tools[*].readiness.recovery` field, explain any mutation to the
user, run the supplied Vibe Code Guard command explicitly, then run doctor
again before auditing. Do not invent a database or use scanner-specific
random installation instructions.

When a third-party binary is missing, the install plan is the authority. It
uses the fixed manifest identity and supported installation method, reports
`sourceType: OFFICIAL_UPSTREAM`, applies the `LATEST_STABLE_COMPATIBLE` policy,
and sets `requiresAuthorization: true`. If the official stable release cannot
be checked or is outside the compatibility policy, no install action is
generated. Agents must explain that plan and obtain authorization; they must
not search GitHub or invent a package source.

If the launcher is not installed yet, use the local equivalent:

```bash
node bin/vibe-code-guard.js doctor --json
node bin/vibe-code-guard.js audit . --profile auto --json
```

The package also exposes `security-check` as a compatibility alias. An
existing unrelated global `security-check` is never overwritten; use the
unambiguous `vibe-code-guard` command when a name conflict is reported.

## Agent-readable status

`vibe-code-guard doctor --json` returns a machine-readable contract:

```json
{
  "schemaVersion": "1.0",
  "workflowVersion": "0.7.0",
  "status": "READY",
  "version": "0.8.0-beta",
  "toolchain": {
    "gitleaks": {
      "status": "READY",
      "binaryPath": "/path/to/gitleaks",
      "version": "...",
      "installMethod": "brew"
    }
  },
  "dashboard": {
    "status": "READY",
    "host": "127.0.0.1",
    "localOnly": true
  },
  "capabilities": {
    "audit": "READY",
    "activeRuntimeScanning": "AUTHORIZED_TARGET_REQUIRED",
    "externalAI": "NOT_INCLUDED"
  }
}
```

Overall states are `READY`, `DEGRADED`, or `BROKEN`. A missing or unusable
required scanner is not silently treated as ready. Network/database
limitations are reported as degraded where the local binary remains usable.
When a tool is `DEGRADED`, the agent may continue known-good deterministic
checks that do not depend on the unavailable capability, but must call out the
missing coverage and must not describe the audit as complete or secure. A
`BROKEN` required tool blocks the workflow until the local failure is resolved.
For example, a present Trivy binary with missing DB content is represented as
an installed launcher plus a blocking content recovery action:

```text
vibe-code-guard tools refresh-data trivy
```

This command is a plan by default and requires explicit confirmation and the
existing official-source trust checks before mutating scanner content.

Every JSON response from the agent-facing CLI includes `schemaVersion: "1.0"`
and `workflowVersion: "0.7.0"`. The stable command contract is:

- `0`: the requested command completed. A completed audit may still have a
  `DO NOT DEPLOY` release gate; agents must read that gate rather than infer
  security from the process code alone;
- `1`: an operational command failure, or targeted verification reports
  `STILL_DETECTED`;
- `2`: `DEGRADED`, `VERIFICATION_INCOMPLETE`, or another incomplete external
  dependency state.

This contract preserves the v0.5/v0.6 behavior while making release-gate state,
tool health, and process execution state explicit separately.

## Audit profiles and output

The user normally chooses only a profile:

- `auto`: change-aware selection from the existing orchestration policy;
- `quick`: fast local secrets, static, and dependency checks;
- `full`: complete relevant deterministic checks, including IaC where present;
- `release`: full checks with the release gate and authorized runtime checks.

The command returns JSON like:

```json
{
  "status": "COMPLETED",
  "profile": "full",
  "runId": "20260810153000-a1b2c3",
  "project": "/path/to/project",
  "releaseGate": {
    "label": "DO NOT DEPLOY",
    "reason": "1 unresolved correlated Critical/High finding."
  },
  "issues": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "total": 3
  },
  "dashboardUrl": "http://127.0.0.1:4317"
}
```

Agents should use correlated findings as the issue count, while retaining raw
Unified Findings and scanner observations as evidence. They must report
skipped, failed, and not-applicable checks rather than converting them into
passes.

## Runtime authorization

ZAP and Nuclei are active scanners. They run only for localhost (`localhost`,
`127.0.0.1`, or `::1`) by default. An exact non-local test/staging URL may be
authorized through `VIBE_CODE_GUARD_AUTHORIZED_TARGETS`; a project config target
must match that exact value. If scope is unclear, omit the target and explain
that runtime checks were skipped.

## Project configuration

An optional `.vibe-code-guard.json` is supported:

```json
{
  "profile": "full",
  "runtimeTargets": ["http://127.0.0.1:3000"],
  "ignoredPaths": ["dist/", "vendor/"]
}
```

Only these fields are accepted. Paths must be relative and traversal-free.
The file cannot execute commands, change scanner arguments, disable security
controls, or authorize a public target by itself.

## Fix and rescan guidance

When the user asks for a fix, the agent should:

1. identify the correlated finding and its scanner observations;
2. inspect the evidence and determine the smallest safe remediation;
3. avoid blanket ignores, rule deletion, and weakened security controls;
4. make the authorized code change;
5. mark the correlated finding `FIXING` or `FIXED` through the lifecycle
   workflow; do not edit the persisted index directly;
6. run targeted verification through
   `vibe-code-guard verify <finding-id> <project> --json` (or the Dashboard
   **Verify fix** action); and
7. report whether the finding became `VERIFIED`, was `STILL_DETECTED`, or was
   `VERIFICATION_INCOMPLETE`.

Targeted verification selects the scanner family that produced the correlated
finding. Secrets use Gitleaks and TruffleHog, dependency findings use OSV and
Trivy, static findings use Semgrep, IaC findings use Checkov and Trivy, and
runtime findings use ZAP/Nuclei only when an authorized runtime target is in
scope. A skipped, failed, degraded, or out-of-scope relevant scanner cannot
establish `VERIFIED`.

Verification also compares a bounded fingerprint of project scanner configs,
ignore files, the target-file boundary, and any runtime target before and
after the rescan. A scope/config change, malformed structured output, unknown
scanner version, unreachable runtime target, or missing observation history
returns `VERIFICATION_INCOMPLETE`; suppressing a rule is not remediation.

The activity trail records the verification request, selected scanners,
coverage, result, and lifecycle transition. `FALSE_POSITIVE` and
`ACCEPTED_RISK` remain user-controlled and are never changed by verification.

## Upstream tool lifecycle

Before an important release audit, the agent may run:

```bash
vibe-code-guard tools status --json
vibe-code-guard tools check-updates --json
vibe-code-guard tools update --dry-run --json
```

The update workflow checks fixed official sources, preserves installation
provenance, updates one scanner at a time, runs validation, and never runs
silently as part of `audit`. Engine versions and vulnerability databases,
rules, templates, and add-ons are reported separately. See
[`docs/tool-lifecycle.md`](tool-lifecycle.md) for the state model and offline
behavior.

Never label a finding `FALSE_POSITIVE` or `ACCEPTED_RISK` without an explicit
user decision and reason.

## Manual fallback

Humans can use the same interface without an agent:

```bash
./install.sh --dry-run
vibe-code-guard doctor
vibe-code-guard audit . --profile full
vibe-code-guard verify VCG-CORR-... . --json
vibe-code-guard dashboard
```

## Privacy and ownership

All normal operations are local-only and there is no cloud account, analytics,
telemetry, or source-code upload. Upstream tools may contact their own
vulnerability databases, registries, rule sources, or template sources; their
network behavior and license terms remain separate. The installer manages
only Vibe Code Guard-owned launchers and metadata by default. It never removes
upstream scanners during uninstall.

## v0.7 validation

The repository includes safe fixtures and an E2E harness under
[`test/e2e`](../test/e2e). The harness uses temporary roots and mock scanner
executables to exercise the production CLI/server contracts; it does not call
real AI providers, start vulnerable services, use real credentials, upgrade
scanners, or scan public targets. Fixture projects are test inputs, not claims
that the corresponding applications are secure.
