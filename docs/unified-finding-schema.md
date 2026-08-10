# Unified Finding Schema v1.0

Vibe Code Guard v0.2 converts scanner-specific results into one stable object
before they are shown in the Dashboard, written to a run, counted in a
summary, or rendered in `security-report.md`.

The schema belongs to the orchestration layer. It does not replace the
upstream scanners or change their native output files.

## Shape

```json
{
  "schemaVersion": "1.0",
  "id": "VCG-SEMGREP-EXAMPLE",
  "fingerprint": "stable-sha256-without-run-data",
  "scanner": {
    "id": "semgrep",
    "name": "Semgrep",
    "ruleId": "fixture.sql-injection"
  },
  "severity": "HIGH",
  "confidence": "MEDIUM",
  "category": "INJECTION",
  "title": "Synthetic input validation issue",
  "location": {
    "type": "file",
    "file": "src/query.js",
    "line": 12,
    "column": 3,
    "endpoint": null
  },
  "explanation": {
    "technical": "A synthetic rule reported an unsafe input flow.",
    "simple": "Input may reach a sensitive operation without enough checking.",
    "whyItMatters": "A reachable issue can increase unauthorized access or data exposure risk."
  },
  "evidence": {
    "summary": "Semgrep reported a sanitized fixture match.",
    "redacted": true
  },
  "remediation": {
    "summary": "Validate input at the security boundary."
  },
  "status": "OPEN",
  "firstSeen": "2026-08-10T00:00:00.000Z",
  "lastSeen": "2026-08-10T00:01:00.000Z",
  "source": {
    "runId": "20260810000000-abcdef",
    "rawResultReference": null
  }
}
```

## Field contract

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Unified schema version. v0.2 writes `1.0`. |
| `id` | Stable scanner-scoped display identifier. |
| `fingerprint` | Deterministic identity material for future cross-tool correlation. |
| `scanner` | Scanner `id`, display `name`, and optional upstream `ruleId`. |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `UNKNOWN`. |
| `confidence` | `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`. |
| `category` | Conservative category enum; unmapped values become `UNKNOWN`. |
| `title` | Short sanitized description of the finding. |
| `location` | Typed file or endpoint location with optional line/column. |
| `explanation` | Technical, plain-language, and impact explanations. |
| `evidence` | Sanitized summary. `redacted` is always `true`. |
| `remediation` | Sanitized remediation summary, or `null` when upstream provides none. |
| `status` | Lifecycle value. v0.2 actively creates `OPEN`; later lifecycle work will use the other values. |
| `firstSeen` / `lastSeen` | ISO timestamps for the observation history. |
| `source` | Current run identifier and optional safe reference to a raw artifact. |

Supported statuses are `OPEN`, `FIXING`, `FIXED`, `VERIFIED`, `REOPENED`,
`FALSE_POSITIVE`, and `ACCEPTED_RISK`.

Supported categories are `SECRET_EXPOSURE`, `INJECTION`, `ACCESS_CONTROL`,
`AUTHENTICATION`, `DEPENDENCY_VULNERABILITY`, `MISCONFIGURATION`,
`CRYPTOGRAPHY`, `DATA_EXPOSURE`, `XSS`, `SSRF`, `FILE_UPLOAD`,
`INFRASTRUCTURE`, `RUNTIME`, and `UNKNOWN`.

## Adapter boundary

The adapters in [`core/findings/adapters`](../core/findings/adapters) translate
the current output formats for Gitleaks, TruffleHog, Semgrep, Trivy,
OSV-Scanner, Checkov, OWASP ZAP, and Nuclei. The adapter boundary is the only
place that knows scanner-native field names. The rest of the application reads
the Unified Finding shape.

Malformed, empty, unsupported, or unknown output produces no finding rather
than an invented result. Every adapter output is validated before it is
accepted by the run.

## Fingerprints and redaction

Fingerprints use scanner rule identity, normalized category/title, normalized
file or endpoint location, and line information. They deliberately exclude
timestamps, run IDs, random values, and raw evidence so a later run can refer
to the same underlying signal. The scanner identifier is kept in `id`, while
the fingerprint remains suitable for future cross-tool correlation.

Evidence is sanitized before it can be persisted. Credential-shaped values,
private keys, authorization headers, and fields such as `match`, `raw`,
`token`, and `value` are redacted. Synthetic self-tests must never use real
credentials.

## Persistence and compatibility

Each run records Unified Findings in `findings.json`; that file contains only
the v1 objects. Run metadata, `tool-status.json`, and `summary.json` also carry
`schemaVersion`. The Markdown report, Dashboard, and summary counts all use
the same in-memory objects.

Older run files with the previous flat finding shape are normalized when read.
They remain readable without being silently treated as new scanner output.
