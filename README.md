# Security Orchestrator

**Status: Early Alpha / Active Development**
**Release line: `v0.1.0-alpha`**
**Tested platform: macOS**

Security Orchestrator is an open-source, local-first security orchestration
layer for AI-assisted and “vibe-coded” software development. It coordinates
existing security tools, applies deterministic policies to changed code, and
provides a local dashboard for evidence and run history.

It is not a replacement for, and does not claim authorship of, Gitleaks,
TruffleHog, Semgrep, Trivy, OSV-Scanner, Checkov, OWASP ZAP, Nuclei, or Strix.
Those projects are invoked as independently installed upstream tools. Their
licenses and attribution requirements are recorded in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`third-party/tools.json`](third-party/tools.json).

## Current capabilities

- Global toolkit health checks through `security-tools doctor`.
- Synthetic scanner regression checks through `security-tools self-test`.
- `security-check quick`, `full`, `secrets`, `static`, `dependencies`, `infra`,
  `web`, and `report` modes.
- Security Orchestrator v1 with deterministic Git/file-change classification.
- LOW/MEDIUM/HIGH change-risk classification.
- Mandatory policy evaluation and applicability decisions.
- Automatic selection of relevant scanners for an auditable execution plan.
- Explicit skip and not-applicable reasons rather than silent omission.
- JSONL execution events and sanitized scan history.
- A local Dashboard showing real scanner execution state, findings, history,
  rescan behavior, and a release-gate summary.
- Optional Strix metadata and recommended-status handling. Strix is not a core
  tool, is not installed by this repository, and is never started implicitly.

The existing global CLI remains usable without the Dashboard. The Dashboard
invokes only predefined actions and does not expose arbitrary shell execution.

## Roadmap / Not yet complete

This repository is intentionally not presented as a finished security product.
The following are planning milestones, not promises:

- **v0.1 — Security Orchestrator:** current early-alpha orchestration layer.
- **v0.2 — Unified Findings:** richer normalized finding representation.
- **v0.3 — Correlation + Coverage:** cross-tool correlation and coverage
  visibility.
- **v0.4 — AI Fix Loop:** controlled fix, regression-test, and rescan flow.
- **v0.5 — Code Quality + Reliability:** non-security quality and reliability
  checks.
- **v1.0 — Stable public release:** only after broader testing and review.

Richer Git diff analysis, a Unified Finding Schema, Finding Correlation, a
Security Coverage Engine, an AI fix/rescan loop, Strix deep-audit execution,
automatic disposable runtime environments, hardened toolchain update/rollback,
and expanded integration tests are not complete yet.

## Security and privacy boundaries

No scanner or combination of scanners can guarantee that software is
vulnerability-free. This project provides checks and visibility; it is not a
security warranty and must not be described as “100% secure” or as detecting
all vulnerabilities.

The Dashboard defaults to:

- binding to `127.0.0.1`;
- no project-specific telemetry or analytics;
- no account requirement;
- no source-code or scan-result upload by the Dashboard;
- no cloud database requirement; and
- local, append-only run history.

External scanners may contact their upstream services to obtain vulnerability
databases, rules, templates, or add-ons. Review each tool's behavior and
network policy for your environment. Optional Strix use may send source,
findings, or execution context to an external LLM provider when explicitly
configured and authorized; it is not enabled by default.

ZAP, Nuclei, and Strix can perform active testing. Use runtime or penetration-
testing features only against systems you own or are explicitly authorized to
test. Automatic web behavior remains localhost-focused and does not use random
public websites as examples or defaults.

## Prerequisites

The current supported/tested setup is macOS:

- Node.js 18 or newer;
- the global toolkit installed at `$HOME/security-toolkit` (or configured with
  `SECURITY_TOOLKIT_HOME`);
- the eight core tools installed through their official channels;
- Docker only if you intentionally use a tool or optional Strix workflow that
  requires it; and
- a local disposable application only for authorized ZAP/Nuclei testing.

This repository does not automatically install security tools. Use the official
installation instructions for each upstream project. A typical Homebrew setup
for commonly available CLI packages is:

```bash
brew install gitleaks trufflehog semgrep trivy osv-scanner nuclei
brew install --cask owasp-zap
```

Install Checkov using its official Python packaging instructions (for example,
an isolated `pipx` environment). Confirm the actual installation with the
global toolkit commands below; do not assume that a package-manager install
means the scanner is healthy.

## Install this project

```bash
git clone <repository-url>
cd <repository-directory>
npm install
npm test
```

Install the Orchestrator modules into the global toolkit when you want the
`security-check auto` command to use this repository's current source:

```bash
npm run install:orchestrator
```

The installer copies only this project's JavaScript modules to
`$SECURITY_TOOLKIT_HOME/orchestrator` (default: `$HOME/security-toolkit/orchestrator`).
It does not install scanners, templates, databases, credentials, or binaries.

## Run the checks

Run these from any project directory that you are authorized to review:

```bash
security-tools doctor
security-tools self-test

security-check quick .
security-check full .
security-check auto .
```

Use `quick` during normal development. It focuses on fast source, secret, and
dependency checks. Use `full` before release for broader static, dependency,
secret, and infrastructure coverage; active web stages still require an
explicit authorized localhost/test target. Use `auto` when you want the
Orchestrator to classify the change and record why each scanner ran, skipped,
or was not applicable.

The release gate is deliberately conservative: a quick scan or a scan with
unresolved high-severity findings, tool errors, or skipped manual review will
not be reported as ready to deploy.

## Start the local Dashboard

```bash
npm start
```

Open [http://127.0.0.1:4567](http://127.0.0.1:4567). Optional configuration:

```bash
PORT=4567
SECURITY_TOOLKIT_HOME="$HOME/security-toolkit"
SECURITY_DASHBOARD_DATA_DIR="$HOME/security-toolkit/runs"
# Optional: prepend a custom directory containing scanner binaries
SECURITY_TOOL_PATHS="$HOME/bin"
# Optional: map allowlisted tool names to absolute binaries when not on PATH
SECURITY_TOOL_BINARIES='{"zap":"/path/to/zap.sh"}'
```

Run data is sanitized and stored locally. If the configured global run
directory is not writable, development runs fall back to the repository's
ignored `runs/` directory. Do not commit generated reports or run artifacts.

## Strix is optional

Strix is registered as an optional active-testing layer, separate from the
eight-tool core health gate. The Strix Codex skills are pinned outside this
repository; the Strix CLI is not installed or invoked automatically.

When using Strix, ask for an explicit authorized local assessment and review
the exact target, command, Docker impact, and external LLM data flow before
execution. Never use a third-party or public target without written
authorization.

## Repository layout

```text
orchestrator/       deterministic change, policy, risk, and tool selection
public/             local Dashboard assets
test/               unit tests and safe orchestration fixtures
scripts/            installation helpers
third-party/        portable upstream integration metadata
```

The repository intentionally does not contain scanner binaries, vulnerability
databases, secret rules, Nuclei templates, ZAP sessions, or private project
data.

## Contributing and reporting issues

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development expectations and
[`SECURITY.md`](SECURITY.md) for private vulnerability reporting. Please do
not publish credentials, sensitive logs, private source, or exploit details in
public issues.

## License

Original code in this repository is licensed under the Apache License 2.0;
see [`LICENSE`](LICENSE). The Apache-2.0 choice applies to this project's
original orchestration/dashboard code and provides a permissive copyright and
patent grant suitable for an external-CLI integration layer. It does not
relicense upstream scanners or their dependencies. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for those separate terms.
