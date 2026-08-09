# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

delegated: a dependency-free Node.js standard-library server with vanilla HTML, CSS, and JavaScript, so the dashboard remains local, small, and easy to audit.

## Users

One developer using Codex and AI coding agents to build local projects. The user needs a clear view of what the security workflow is doing without needing deep AppSec knowledge.

## Product Purpose

Provide a local-only observability layer for the user's global security toolkit. The dashboard shows real scanner execution state, sanitized findings, scan history, release-gate status, and toolchain health. It must never replace scanners or manufacture progress.

## Positioning

It connects the existing `security-check` / `security-tools` workflow to a plain-language visual audit trail while keeping source code, scan metadata, and sanitized outputs on the Mac.

Strix is an explicit optional agentic pentesting layer, not part of the deterministic core scanner set. It remains separately invoked because it can execute dynamic tests and exploit-validation workflows inside Docker and may send prompts or source context to a configured LLM provider. It is never started implicitly by `quick` or `full`.

## Operating Context

The dashboard is used on the same Mac as `~/security-toolkit/`. It watches quick and full audits of local repositories, Docker-backed local applications, and explicitly authorized localhost/staging targets. It is primarily watched by one developer during AI-assisted development and before release.

## Capabilities and Constraints

- Bind only to `127.0.0.1`; never bind to `0.0.0.0`.
- No accounts, cloud database, telemetry, analytics, source upload, or result upload.
- Only predefined local actions are exposed: quick scan, full scan, rescan, stop scan, open report, doctor, and self-test.
- The orchestrator adds an explicit `auto` action without changing the existing quick/full behavior.
- Project paths must be local and validated; arbitrary shell commands and arbitrary external URLs are forbidden.
- Active web scanning is restricted to localhost, local Docker, or explicitly configured authorized test targets.
- Keep append-only local run metadata and sanitized scanner outputs; never store source-code copies or complete credentials.
- V1 pages: Dashboard, Findings, History, and Toolkit Health.
- Release wording must say "No known Critical/High findings detected by the performed assessment" rather than claiming perfect security.
- Scan history preserves prior findings so a later clean rescan can show a finding as verified fixed.

## Brand Commitments

The interface should feel calm, direct, and operational: large state signals, plain-language explanations, minimal navigation, and no enterprise SOC theatrics. Visual details not specified by the brief are implementation assumptions.

## Evidence on Hand

- Existing global toolkit expected at `~/security-toolkit/`.
- Existing commands: `security-check` and `security-tools`.
- Installed scanners: Gitleaks, TruffleHog, Semgrep, Trivy, OSV-Scanner, Checkov, OWASP ZAP, and Nuclei.
- The current workspace is a new empty repository; no incumbent interface or assets need preservation.

## Product Principles

- Show evidence, never theater.
- Make the current stage obvious within seconds.
- Keep the safe path easier than the risky path.
- Preserve an auditable history of every scan.
- Explain security findings in language a developer can act on.

## Accessibility & Inclusion

Use semantic HTML, keyboard-visible focus, sufficient color contrast, text labels alongside color/state marks, reduced-motion support, and responsive layouts for laptop and narrow screens.
