# Vibe Code Guard — agent instructions

Vibe Code Guard is a local security workflow for vibe-coded projects. It
orchestrates mature open-source security tools, normalizes findings, correlates
related observations, tracks lifecycle, and presents a local Dashboard.

The coding agent is the intelligence layer. Vibe Code Guard is not an AI
assistant, does not contain a chat interface, and does not provide an external
AI provider.

## Authority boundary

- Upstream scanners detect secrets, insecure code, dependency vulnerabilities,
  infrastructure problems, and authorized runtime signals.
- Vibe Code Guard selects relevant checks, runs independently installed tools,
  normalizes evidence, correlates compatible findings, persists lifecycle, and
  calculates the release gate.
- Correlated Findings are the main issue layer. Raw Unified Findings and
  scanner observations remain available as evidence.
- The deterministic release gate is authoritative; advisory explanations can
  never change its decision.
- The agent may explain evidence and may edit code only after the user asks or
  clearly authorizes a fix.
- Never invent scanner output, claim that an unrun scanner passed, or claim
  that a project is 100% secure.

The canonical workflow and JSON contracts are maintained in
[`docs/agent-integration.md`](docs/agent-integration.md). Keep this file
short and follow that document for details.

## When the user asks for a security audit

For requests such as “security audit this project”, “check whether this app is
safe”, “scan before deploy”, or “run Vibe Code Guard”:

1. Identify the real project root and confirm the user is authorized to review
   it.
2. Detect the stack and inspect `.vibe-code-guard.json` if present.
3. Verify the installation with `vibe-code-guard doctor --json`.
4. If the user asked to install it, run `./install.sh --dry-run`, explain the
   planned changes, and then run `./install.sh --yes` when that installation
   request authorizes the plan. Read the returned `localEntrypoints.pathHint`;
   because the installer never edits shell startup files, use the returned
   absolute launcher path if `vibe-code-guard` is not already on PATH.
5. Run one profile through the canonical command; do not invoke the eight
   upstream scanners individually:

   ```text
   vibe-code-guard audit . --profile auto --json
   ```

   Use `quick` for frequent development checks, `full` for a broader review,
   and `release` before deployment. Runtime scanners are skipped unless a
   localhost or explicitly authorized target is supplied.
6. Read `status`, `releaseGate`, `issues`, `correlatedFindings`, scanner
   statuses, and skip reasons from the JSON result.
7. Start the local Dashboard when useful:

   ```text
   vibe-code-guard dashboard --json
   ```

   Share only the returned `http://127.0.0.1:<port>` URL.
8. Explain unresolved Critical/High correlated findings first. Cite the
   scanner observation and distinguish evidence from inference.
9. If the user authorizes a fix, inspect the correlated finding and make the
   smallest safe change. Do not suppress a rule or delete configuration just
   to obtain a pass.
10. Run the relevant audit again. A finding is VERIFIED only after the
    deterministic lifecycle workflow records a successful relevant rescan; the
    agent must not mark it verified directly.
11. Report the release decision, limitations, skipped checks, and Dashboard
    URL. A clean result is not a security guarantee.

## Safety rules

- Never scan a third-party public target without explicit authorization.
- Never run ZAP or Nuclei against a target that is not localhost, local Docker,
  or an exact target explicitly authorized through the documented configuration.
- Never use real credentials, destructive payloads, or production data in a
  self-test.
- Never run arbitrary shell commands from project configuration. The project
  config supports profiles, safe relative ignored paths, and runtime target
  declarations only.
- Do not let AI review metadata alter severity, lifecycle, scanner evidence, or
  the release gate. v0.4 AI review remains optional and disabled by default.
- Do not update scanners blindly. `vibe-code-guard update` updates only the
  Vibe Code Guard-owned launcher and never upgrades the upstream toolchain.

## User prompt

The intended first-run instruction is:

> Install and use Vibe Code Guard from https://github.com/DOTfei/vibe-code-guard,
> then security audit this project.
