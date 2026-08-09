# Vibe Code Guard

**Local-first security orchestration for AI-assisted software.**

`v0.1.0-alpha` · Early Alpha / Active Development · macOS tested

> AI writes code fast. Security review needs to keep up.

Vibe Code Guard is the local-first safety layer for AI-assisted and
“vibe-coded” software. It sees what changed, chooses the checks that matter,
runs real open-source scanners locally, and explains what needs attention.

<p align="center">
  <img src="diagrams/vibe-code-guard-flow-next-ai-drawio.svg" alt="Animated Vibe Code Guard flow exported by Next AI Draw.io: detect changes, choose checks, scan locally, explain findings, fix, and rescan" width="1100" />
</p>

Animation fallback: [view the GIF version](diagrams/vibe-code-guard-overview.gif).

<details>
<summary>Open the editable architecture diagrams</summary>

- [Compact overview: GIF](diagrams/vibe-code-guard-overview.gif) ·
  [Mermaid](diagrams/vibe-code-guard-overview.mmd) ·
  [Excalidraw](diagrams/vibe-code-guard-overview.excalidraw)
- [Detailed flow: GIF](diagrams/vibe-code-guard-flow.gif) ·
  [Next AI Draw.io animated SVG](diagrams/vibe-code-guard-flow-next-ai-drawio.svg) ·
  [SVG source](diagrams/vibe-code-guard-flow-animated.svg) ·
  [draw.io](diagrams/vibe-code-guard-flow.drawio) ·
  [Mermaid](diagrams/vibe-code-guard-flow.mmd) ·
  [Excalidraw](diagrams/vibe-code-guard-flow.excalidraw)

The diagrams are generated from this repository's own architecture. The
draw.io-compatible source can be refined in tools such as
[Next AI Draw.io](https://github.com/DayuanJiang/next-ai-draw-io); no upstream
source code or service dependency is bundled here. The detailed draw.io source
uses animated connectors (flowAnimation=1) and was checked with the upstream
project's MCP loader/validator.
</details>

## What it does now

- **Understands the change:** deterministic Git/file inspection, risk levels,
  mandatory policies, and applicability decisions.
- **Runs the right checks:** quick, full, or change-aware `auto` plans using the
  existing local security toolkit.
- **Shows the evidence:** real scanner state, findings, skip reasons, history,
  and a conservative release-gate summary in the local Dashboard.
- **Keeps active testing bounded:** ZAP and Nuclei stay localhost/test-focused;
  Strix remains optional and requires explicit approval.

It is an orchestration layer, not a new scanner. Upstream tools keep their own
licenses and attribution; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

<details>
<summary>Which upstream tools are involved?</summary>

Gitleaks, TruffleHog, Semgrep, Trivy, OSV-Scanner, Checkov, OWASP ZAP, Nuclei,
and optional Strix are invoked as independently installed upstream tools. This
repository does not bundle their binaries, source, rules, templates, or
databases. See [`third-party/tools.json`](third-party/tools.json) for the
portable integration record.
</details>

## Three ways to use it

| When | Command | What it does |
| --- | --- | --- |
| While coding | `security-check quick .` | Fast secrets, static, and dependency checks |
| Before release | `security-check full .` | Broader code, dependency, and infrastructure checks |
| When the change matters | `security-check auto .` | Classifies the change and explains every run/skip decision |

The local Dashboard shows the same real execution state, findings, history, and
release-gate result in a browser. It does not expose arbitrary shell execution.

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

## Safety by default

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

External scanners may contact upstream services for vulnerability databases,
rules, templates, or add-ons. Review their network behavior for your
environment.

ZAP, Nuclei, and Strix can perform active testing.
Use them only against systems you own or are explicitly authorized to test.
Automatic web behavior remains localhost-focused.

<details>
<summary>External data and active testing details</summary>

Optional Strix use may send source, findings, or execution context to an
external LLM provider when explicitly configured and authorized. It is not
enabled by default. The project never uses random public websites as default
targets.
</details>

## Quick start

The tested setup is macOS with Node.js 18 or newer and the global toolkit at
`$HOME/security-toolkit` (or `SECURITY_TOOLKIT_HOME`). This repository does not
auto-install scanners.

<details>
<summary>Install the external toolkit</summary>

Use each upstream project's official installation instructions. A typical
Homebrew setup for commonly available CLI packages is:

```bash
brew install gitleaks trufflehog semgrep trivy osv-scanner nuclei
brew install --cask owasp-zap
```

Install Checkov using its official Python packaging instructions, such as an
isolated `pipx` environment. Then verify the installation with `doctor`.
</details>

<details>
<summary>Install and connect this repository</summary>

```bash
git clone https://github.com/DOTfei/vibe-code-guard
cd vibe-code-guard
npm install
npm test
npm run install:orchestrator
```

The installer copies only this project's JavaScript modules to
`$SECURITY_TOOLKIT_HOME/orchestrator` (default: `$HOME/security-toolkit/orchestrator`).
It does not install scanners, templates, databases, credentials, or binaries.
</details>

Run the health checks once, then scan any project you are authorized to review:

```bash
security-tools doctor
security-tools self-test
security-check quick .
```

Use `full` before release. Use `auto` when you want the Orchestrator to explain
why each scanner ran, skipped, or was not applicable. The release gate stays
conservative: a quick scan, unresolved high-severity findings, tool errors, or
skipped manual review will not be reported as ready to deploy.

## Local Dashboard

```bash
npm start
```

Open [http://127.0.0.1:4567](http://127.0.0.1:4567). Optional configuration:

```bash
PORT=4567
SECURITY_TOOLKIT_HOME="$HOME/security-toolkit"
SECURITY_DASHBOARD_DATA_DIR="$HOME/security-toolkit/runs"
SECURITY_TOOL_PATHS="$HOME/bin"
SECURITY_TOOL_BINARIES='{"zap":"/path/to/zap.sh"}'
```

Run data is sanitized and stored locally. If the global run directory is not
writable, development runs fall back to the ignored `runs/` directory.

<details>
<summary>Strix is optional</summary>

Strix is separate from the eight-tool core health gate. Its CLI is not
installed or invoked automatically. Any Strix assessment requires explicit
authorization, a reviewed target and command, and a decision about Docker and
external LLM data flow. Never use a public or third-party target without
written authorization.
</details>

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
