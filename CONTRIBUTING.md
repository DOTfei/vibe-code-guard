# Contributing

Vibe Code Guard is an early-alpha, local-first project. Contributions
that improve correctness, transparency, portability, and safe defaults are
welcome.

## Development setup

The currently tested development platform is macOS with Node.js 18 or newer.
Install the external tools described in the README, then run:

```bash
npm install
npm test
node --check server.js
node --check orchestrator/cli.js
```

Do not assume the repository installs scanners automatically. Changes to
scanner adapters should be tested with the relevant locally installed tool and
should document version or output-format assumptions.

## Pull requests

- Keep changes focused and explain security-relevant behavior.
- Add or update tests for policy, classification, parsing, and safety-boundary
  changes.
- Do not commit credentials, real targets, scanner databases, ZAP sessions,
  generated reports, or private project data.
- Use synthetic local fixtures for scanner tests.
- Preserve the localhost-only default for active web scanning.
- Do not silently weaken a policy because a scanner reports inconvenient
  findings.
- Update attribution and third-party metadata when integration boundaries or
  upstream dependencies change.

Before opening a pull request, run `npm test`, `security-tools doctor`, and
`security-tools self-test` when the global toolkit is available.
