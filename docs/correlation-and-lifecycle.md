# Correlation and Finding Lifecycle

Vibe Code Guard v0.3 keeps upstream scanner output intact and adds a deterministic project-level view over it.

## Four layers

### Scanner Finding

A single result emitted by one upstream scanner adapter. These objects remain in each run's `findings.json` and are not replaced by correlation data.

### Unified Finding

The v0.2 normalized representation shared by all eight adapters. It provides stable fields such as severity, category, fingerprint, location, and redacted evidence.

### Finding Observation

A safe record that a scanner observed a Unified Finding during a particular run. It stores scanner identity, scanner finding ID, fingerprint, rule ID, run ID, location metadata, and deterministic identity metadata. It never stores or compares plaintext secrets.

### Correlated Finding

One Vibe Code Guard issue that groups compatible observations from one or more scanners. The project-level index is stored locally at `runs/projects/<project-id>/findings-index.json`; it contains correlation state and safe observation metadata, not source code.

## Conservative correlation

The correlation engine returns `EXACT`, `HIGH`, `MEDIUM`, or `NONE` confidence.

- `EXACT`: the same scanner reported the same stable fingerprint.
- `HIGH`: different scanners agree on deterministic evidence such as a normalized location plus secret family, vulnerability/package identity, rule family and code location, or runtime endpoint and finding family.
- `MEDIUM`: location and category overlap, but a deterministic identity is incomplete. These remain separate and are exposed as relationship suggestions.
- `NONE`: there is not enough evidence to relate the findings.

Equal severity, similar titles, or similar scanner names are never sufficient by themselves. Secret correlation uses only safe family/location metadata. Dependency correlation requires vulnerability identity and package identity. Static findings remain separate when their code locations differ. Runtime findings include normalized endpoint, method, parameter, and rule family where available.

## Lifecycle states

| State | Meaning |
| --- | --- |
| `OPEN` | A current issue needs attention. |
| `FIXING` | A user-authorized external agent is actively addressing the issue. |
| `FIXED` | A user explicitly marked that a fix was attempted. |
| `VERIFIED` | A later relevant scan ran successfully and no matching observation was reported. |
| `REOPENED` | A previously verified finding was observed again. |
| `FALSE_POSITIVE` | A user explicitly classified the finding as not applicable; a reason is required. |
| `ACCEPTED_RISK` | A user explicitly accepted the risk; a reason is required. |

The normal path is `OPEN → FIXING → FIXED → VERIFIED`. A current observation
keeps an open issue open, returns an attempted fix to `OPEN`, and changes
`VERIFIED → REOPENED`.

`FALSE_POSITIVE` and `ACCEPTED_RISK` never change automatically. A later explicit local action is required to reclassify them.

## Verification eligibility

Absence is not proof of a fix. A finding is eligible for verification only when every relevant scanner represented by its observations completed with status `PASS`, was selected to run, and covered the relevant scope. Runtime observations additionally require a successful web stage and an authorized target.

v0.6 records the scanner version used for each observation and targeted
verification. It also requires valid structured output and an unchanged
scanner-scope fingerprint covering project config, ignore files, target-file
existence, and the authorized runtime target. If that scope changes, the
result is `VERIFICATION_INCOMPLETE`, not `VERIFIED`.

If a scanner is skipped, fails, or the target is unavailable, the finding remains in its current state and the lifecycle history records that verification was deferred.

v0.6 targeted verification runs only the relevant scanner family. Use
`vibe-code-guard verify <finding-id> <project> --json` after an authorized
external-agent fix; a missing or failed relevant scanner produces
`VERIFICATION_INCOMPLETE` rather than `VERIFIED`.

## History and compatibility

Every lifecycle change is recorded with an event, timestamp, run ID, previous status, new status, and reason. A skipped or failed relevant scanner records `VERIFICATION_DEFERRED` instead of silently treating absence as a fix. New runs write a versioned `correlation.json` beside the original scanner findings and update the project-level index atomically.

Older v0.2 runs without correlation data are opened safely by deriving an in-memory correlation view. Historical run files are not rewritten or silently migrated.

## Release gate

The release gate counts Correlated Findings, not scanner observations. `OPEN`, `FIXED`, and `REOPENED` Critical/High issues block by default. `VERIFIED` and `FALSE_POSITIVE` do not block. `ACCEPTED_RISK` remains visible and produces a warning rather than being silently treated as clean.
