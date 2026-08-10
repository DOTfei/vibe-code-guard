# AI Security Review

Vibe Code Guard v0.4 adds an advisory AI layer around the deterministic v0.3
security workflow.

```text
scanners → Unified Findings → Correlated Findings → lifecycle/release gate
                                      ↓
                         optional AI explanation and guidance
```

The scanners, correlation engine, lifecycle engine, and release gate remain the
source of truth. AI may explain evidence, suggest remediation priority, ask
questions, and identify uncertainty. AI cannot create a security finding or
change severity, category, fingerprint, correlation key, lifecycle status, or
release-gate state.

## Default privacy behavior

AI review is disabled by default. Vibe Code Guard does not automatically call a
cloud model and does not upload a repository when no provider is configured.

The review context is deliberately small and is built from one Correlated
Finding, selected scanner observation metadata, redacted evidence summaries,
the finding location, project stack, lifecycle and release-gate context, and a
code snippet only when explicitly supplied and explicitly allowed.

It excludes plaintext secrets, `.env` contents, credentials, tokens, private
keys, unrelated files, and unnecessary repository content. Context is bounded,
redacted, and accompanied by an input hash, included-file list, and redaction
count.

If an external provider is configured in a future adapter, the Dashboard must
show that selected redacted context may leave the machine. The product must not
describe that configuration as fully local.

## Provider abstraction

The provider contract is intentionally generic:

```text
provider.name
provider.model
provider.availability()
provider.reviewFinding(context)
provider.reviewRunSummary(context)
```

Supported modes are:

- `disabled` — the default; returns `NOT_GENERATED` without a network call;
- `local` — reserved for a future local model adapter; currently reports an
  unavailable provider safely;
- `mock` — deterministic synthetic provider for tests and local demonstrations;
- `external` — reserved for an explicitly configured provider adapter and does
  not upload anything in this release.

For local testing only:

```bash
SECURITY_AI_PROVIDER=mock npm start
```

The mock provider is not a security scanner and its text is not evidence.

## AI Review object

Finding reviews use a versioned `schemaVersion: "1.0"` object containing:

- summary and plain-language explanation;
- why the issue matters;
- advisory impact and AI confidence;
- suggested `P0`–`P3` priority;
- conservative remediation and verification advice;
- false-positive likelihood with `requiresUserDecision: true`;
- uncertainties and questions; and
- optional evidence references validated against actual scanners, files, and
  vulnerability IDs.

AI confidence is separate from scanner confidence. A finding can have HIGH
scanner confidence and MEDIUM AI explanation confidence at the same time.

## Validation safeguards

Provider output is parsed and validated before storage. It is rejected as an AI
review failure if it is not valid structured JSON, uses an unsupported schema,
references a scanner/file/vulnerability ID absent from the supplied evidence,
invents a CVE identifier, attempts to set deterministic or lifecycle fields, or
fails the false-positive user-control requirement.

Secret-shaped strings are redacted before validation and persistence. A failed
AI review is stored as `FAILED` advisory metadata, never as a security finding.
AI failure does not fail the scan, change lifecycle state, or change the
release gate.

## Status and caching

AI review status is independent of scanner and lifecycle status:

```text
NOT_GENERATED → GENERATING → READY
                         ↘ FAILED
READY + changed evidence → STALE
```

Reviews are stored separately in the local project index directory:

```text
<security-dashboard-data>/projects/<project-id>/ai-reviews.json
```

The cache uses a deterministic review input hash. Identical evidence can reuse
an existing review. Changed deterministic evidence marks the prior review
`STALE`; it is never silently reused as current.

## User-controlled findings

AI may say that a finding appears to be a possible false positive. It may list
evidence to check, but it cannot set `FALSE_POSITIVE` or `ACCEPTED_RISK`.
Those transitions remain explicit user actions in the deterministic v0.3
lifecycle engine.

AI remediation guidance never edits files, runs arbitrary commands, generates
exploit payloads, starts public-target scanning, or performs a fix→rescan
transition.

## Dashboard and CLI

The Dashboard does not auto-run AI when a page opens. Users explicitly choose
`Generate AI Review` for one Correlated Finding, `Review run`, or `Explain
release decision`.

The equivalent safe local CLI command is:

```bash
npm run ai-review -- \
  --run-dir "$SECURITY_DASHBOARD_DATA_DIR/<run-id>" \
  --finding VCG-CORR-...
```

The command reads an existing local run and never executes arbitrary shell
commands. With no provider configured it reports `NOT_GENERATED`.

## Non-goals for v0.4

This release does not add GitHub PR review, automatic code fixing,
fix→rescan automation, Strix integration, new scanners, cloud telemetry, or
automatic source-code upload.
