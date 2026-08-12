# Claude Code instructions

Use the canonical Vibe Code Guard agent workflow in
[`docs/agent-integration.md`](docs/agent-integration.md) and the repository
rules in [`AGENTS.md`](AGENTS.md).

Installation can finish with `INSTALLED_WITH_ACTION_REQUIRED`: inspect doctor
JSON recovery actions, explain explicit content/runtime refreshes, run only the
supplied Vibe Code Guard command after authorization, then re-run doctor before
auditing.
Missing scanners must be handled through the VCG-provided install plan. Use
its fixed official source, supported method, compatibility policy, and
validation metadata; never search GitHub or invent an installation command.

When the user says “Use Vibe Code Guard to audit this project”, run the
agent-readable workflow:

```text
vibe-code-guard doctor --json
vibe-code-guard tools status --json
vibe-code-guard audit . --profile auto --json
vibe-code-guard dashboard --json
```

Do not invoke individual scanners when the canonical command is available.
Respect the authorization boundary for ZAP/Nuclei, never fabricate findings,
and only modify application code when the user explicitly asks for a fix. After
an authorized fix, use `vibe-code-guard verify <finding-id> <project> --json`
for targeted scanner verification; do not mark findings verified manually.
An ignore/configuration/scope change is not a fix, and incomplete scanner
coverage must remain `VERIFICATION_INCOMPLETE`. Check official tool lifecycle
status before important release audits, but never silently update scanners.
