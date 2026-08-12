# Public Beta Demo

This is a maintainer demo for Vibe Code Guard's local public-beta experience.
It uses the repository's safe synthetic fixtures and mock scanners. It is not
an end-user security assessment and it does not require a public target.

## Run the isolated demo

From the repository root:

```bash
npm test -- test/dashboard-ux.test.js
node bin/vibe-code-guard.js dashboard --dry-run --json
```

The deterministic tests exercise the important presentation states without
writing to a user's real toolchain. For a full isolated agent walkthrough, use
the existing `test/e2e` harness; it creates temporary projects and loopback
targets and uses mock scanner executables.

## What to show

The Dashboard is designed to make these states understandable:

1. no audit yet — the user sees the canonical first-use prompt;
2. an open Critical/High issue — the release decision and next action are
   prominent;
3. `FIXED` — shown as “Fix applied · not verified”;
4. `VERIFIED` — shown only after relevant scanner coverage succeeds;
5. `STILL_DETECTED` — shown as an issue that returned;
6. `VERIFICATION_INCOMPLETE` — shown as incomplete coverage, not success; and
7. degraded toolchain — shown as a limitation, not a green pass.

The CLI/JSON response remains the machine contract for Codex, Claude Code, and
other coding agents. The Dashboard is the human view of the same persisted
state. Do not edit HTML or seed fake findings to create a screenshot.

## Safety boundary

Do not add real credentials, real production data, destructive payloads, or
public/third-party targets to this demo. ZAP and Nuclei remain restricted to
localhost, local Docker, or an explicitly authorized test target. Do not
upgrade or reinstall upstream scanners just to make the demo appear healthy.
