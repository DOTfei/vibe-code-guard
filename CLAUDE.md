# Claude Code instructions

Use the canonical Vibe Code Guard agent workflow in
[`docs/agent-integration.md`](docs/agent-integration.md) and the repository
rules in [`AGENTS.md`](AGENTS.md).

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
