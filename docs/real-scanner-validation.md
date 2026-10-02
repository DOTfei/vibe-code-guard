# Real Scanner Validation

## Post-review repairs: 2026-10-03 (Asia/Kuala_Lumpur)

Review of PR #15 found four defects that the first capture did not exercise:

1. Correcting a historical dependency category changed its fingerprint. A
   still-present advisory could become a separate finding while the old FIXED
   entry incorrectly became VERIFIED. Correlation now preserves the old ID
   across this transition only when scanner, advisory ID, file, package,
   installed version, and compatible/inferred ecosystem match. Regression
   tests require STILL_DETECTED or REOPENED and reject different identities.
2. Abruptly killing an outer wrapper left its detached scanner alive.
   Cancellation now propagates through wrappers and waits for child closure;
   the leaf launcher terminates the scanner process group it owns. A harmless
   nested-process test includes a scanner that ignores SIGTERM and asserts no
   surviving test scanner after cancellation.
3. Inherited SEMGREP_SETTINGS_FILE/LOG_FILE/VERSION_CACHE_PATH could bypass
   temporary HOME. These paths are explicitly redirected inside the run's
   temporary root. A mock-only test verifies inherited paths are not used.
4. OSV exit 1 is a supported findings exit code; malformed JSON at that exit
   was incorrectly classified as environmental degradation. Successful scanner
   exit codes 0/1 now require a structured dependency result array; malformed,
   null, or wrong-shape output is a validation failure, returning overall 1.

The [post-repair capture](real-scanner-evidence-2026-10-03.json) completed at
`2026-10-02T16:01:51.885Z` (2026-10-03 locally). All four real VCG remediation
chains and the direct localhost Nuclei/ZAP checks still passed. There were no
assertion failures; the overall manual exit remains **2** because TruffleHog
detection and Trivy DB freshness remain REAL_PARTIAL, and TruffleHog-originated
remediation/runtime-family targeted verification remain NOT_TESTED.

`npm test`: **103/103 PASS**. Legacy-state and interruption repairs are proved
by synthetic/mock regressions; this is not a claim of migrating real user
history or completing additional runtime verification. Monitored host files
were unchanged. No global tool/content update or configuration repair occurred.
The earlier captures below remain dated evidence, not overwritten claims.

### Second review corrections (2026-10-03)

The second review also corrected these evidence/verification boundaries:

- The category correction is now limited to explicit dependency categories.
  Applying it to all categories changed historical Nuclei fingerprints and
  could verify an unchanged runtime finding. Other categories retain their
  previous normalization; unchanged runtime evidence stays STILL_DETECTED.
- Timeout/overflow cleanup terminates the owned process group before clearing
  escalation, even when its parent already closed and a descendant ignores TERM.
- The existing configuration-family mapping omitted the canonical
  MISCONFIGURATION category. It now requires Checkov and Trivy even when only
  one scanner originally observed the issue; a missing peer cannot verify it.
- Historical OSV advisories are not restricted to CVE/GHSA/OSV prefixes.
  Matching still requires the same scanner, rule, file, package, installed
  version, and ecosystem; PYSEC-style IDs retain dependency coverage and identity.
- Authoritative Semgrep/Trivy/OSV execution also requires its expected JSON
  result array, not merely parseable JSON. The normal targeted-verification
  integration rejects null/empty-object/wrong-root output as incomplete.
- A missing required peer scanner or unknown version blocks a manual
  remediation chain before expected-detection assertions. It remains an
  environmental limitation (overall 2), not an assertion failure (overall 1).

These final guards are validated by mock findings and harmless Node processes.
The dated real captures above preceded these guards; no additional real
runtime-family verification or global freshness validation is claimed.

## Follow-up: 2026-10-02

This follow-up supplements, rather than rewrites, the dated v0.7.1 record
below. It validates specific fixture behaviors, not complete security coverage,
legal compliance, or freedom from bugs. The same four evidence states apply:
`REAL_VALIDATED`, `REAL_PARTIAL`, `BLOCKED_BY_ENVIRONMENT`, `NOT_TESTED`.

### Repeatable manual validation

```sh
node scripts/validate-real-scanners.js --json
```

This is deliberately **not** part of `npm test`. It uses existing installed
scanners, temporary synthetic projects, isolated HOME/cache/output directories,
and one disposable `127.0.0.1` server. It does not install the historical
dependency, build the Dockerfile, use real credentials, or scan public targets.
OSV queries send synthetic dependency metadata to the scanner's upstream query
service; credential verification and external interaction services are disabled.
No tool upgrades or global database/rule/template refreshes are requested.

Each run retains `summary.json` and sanitized command traces in its printed
temporary evidence directory. These record resolved binary paths, versions,
arguments, exit codes, duration, bounded stdout/stderr, expected findings,
normalization, and verification results. Temporary fixtures and copied caches
remain there for inspection; remove only that exact run directory when done.
Missing tools/content, scan timeouts, and unknown versions remain limitations.

The checked-in [compact evidence capture](real-scanner-evidence-2026-10-02.json)
records the run completed at `2026-10-02T14:54:35.257Z`, including actual paths,
versions, commands, timings, exit codes, redacted output excerpts, and canonical
verification states. Long output excerpts are explicitly truncated and hashed;
they do not replace the full temporary traces. Installed versions were Gitleaks
8.30.1, TruffleHog 3.97.0, Semgrep 1.172.0, Trivy 0.73.0, OSV-Scanner 2.5.0,
Checkov 3.3.0, ZAP 2.17.0, and Nuclei 3.11.1.

The manual script's exit codes are separate from the existing CLI contract:

- `0`: every planned evidence dimension is `REAL_VALIDATED`.
- `1`: an assertion, expected detection, or structured parsing failed.
- `2`: no assertion failure, but partial, blocked, or untested dimensions remain.

### Current evidence by dimension

| Dimension | Evidence state | Proven behavior and boundary |
| --- | --- | --- |
| Gitleaks-originated secret workflow | `REAL_VALIDATED` | Synthetic local-rule finding → removal → targeted `VERIFIED`; restoring it gives `STILL_DETECTED`. Both Gitleaks and TruffleHog must complete secret-family coverage. This does not prove a TruffleHog detector match. |
| Semgrep local-rule workflow | `REAL_VALIDATED` | Existing repository-local rule produces a structured finding, VCG normalizes it, and fixture remediation passes the normal targeted verification workflow. No registry download. |
| Checkov + Trivy Dockerfile workflow | `REAL_VALIDATED` | Real missing USER/HEALTHCHECK findings; both scanners complete before the selected finding becomes `VERIFIED`. No container is built or started. |
| Trivy + OSV dependency workflow | `REAL_VALIDATED` | Historical lodash 4.17.11 / CVE-2021-23337 finding → lockfile-only change to 4.17.21 → targeted verification requiring both scanners → restoration detected. This proves remediation of the selected advisory, not that 4.17.21 or the entire project is clean. |
| Trivy dependency detection/normalization | `REAL_VALIDATED` | Actual advisory metadata parsed from the existing copied DB; nonempty expected lodash findings required. |
| Trivy DB freshness | `REAL_PARTIAL` | Schema 2 DB usable, but NextUpdate `2026-08-11T06:54:30.95190594Z` is expired. It was not refreshed. Detection success does not make the DB current. |
| OSV query and normalization | `REAL_VALIDATED` | The controlled synthetic dependency query succeeded in this run. The historical network blocker below was not reproduced; this is not a permanent host-health guarantee. |
| TruffleHog detector execution | `REAL_PARTIAL` | Safe JSONL execution with no verification/update succeeded; the deliberately invalid synthetic credential pattern emitted zero findings. Empty output is not a detection success. |
| TruffleHog-originated finding → fix → verify | `NOT_TESTED` | No reliable deterministic detector match was obtained. |
| Nuclei direct localhost detection/normalization | `REAL_VALIDATED` | Existing signed official git-config template detected a harmless synthetic exposed config; removing the response stopped that finding. Signing controls retained, no templates downloaded. |
| ZAP direct localhost detection/normalization | `REAL_VALIDATED` | Disposable HTML page produced structured missing CSP/clickjacking header alerts through the existing adapter. No add-ons installed or refreshed. |
| VCG runtime-family finding → targeted verify | `NOT_TESTED` | Direct ZAP/Nuclei evidence is not proof of this workflow. VCG's normal tech-template selection was not redesigned to force exposure detection. |

For each of the four VCG remediation chains, the harness asserts
`STILL_DETECTED` before remediation, `PASSED`/`VERIFIED` after remediation,
`STILL_DETECTED` after restoration, and `VERIFICATION_INCOMPLETE` after either
an ignore-scope change or a missing required scanner. Dashboard API and CLI
must agree on lifecycle, verification, and the canonical release gate. Existing
regression tests also cover failed/skipped scans and unknown scanner versions.

### Minimal safety fixes justified by execution

- Ordinary, automatic, and targeted TruffleHog calls now share
  `--no-verification --no-update --no-color --json`.
- All corresponding Nuclei calls disable Interactsh and update checks. These
  flags do not change target authorization or normal template selection.
- The real Trivy advisory title contained "command injection". Category
  normalization incorrectly overrode its explicit dependency category, which
  could select Semgrep instead of required OSV coverage. Explicit dependency
  categories now take precedence. Legacy dependency observations identified by
  scanner/advisory ID retain the dependency scanner family during verification.
  A regression test ensures clean Trivy/Semgrep cannot substitute for OSV.

The release-gate algorithm is unchanged. Required coverage is not weakened.
Resolved paths establish which installed binary ran, not independent signature
verification or installation-source attestation. Monitored host binary/content
files were unchanged; this is not an exhaustive filesystem audit.

## Historical v0.7.1 record

Validation date: 2026-08-11

This report records a read-only validation of Vibe Code Guard against the
security scanners installed on the development Mac. The tests used disposable
temporary projects, synthetic findings, and loopback-only runtime checks. No
production data, real credentials, public targets, scanner upgrades, database
refreshes, template refreshes, add-on installs, or global configuration changes
were performed.

## Starting health

The host was captured before validation:

- Global `security-tools doctor`: `HEALTHY`.
- Global `security-tools self-test --json`: `6/8 PASS`, `2 DEGRADED`, `0 FAIL`.
- Trivy's local vulnerability database was readable but expired; its schema was
  usable and the core validation used `--skip-db-update` to avoid an implicit
  network refresh.
- OSV-Scanner could not reach its external query service in this environment.
- The Vibe Code Guard doctor remained environment-sensitive for Semgrep's
  normal home/log path and ZAP's normal home/content freshness. Temporary HOME
  was used only for the local validation process where required.

These conditions were preserved and reported. They were not changed to force a
green result.

## Scanner matrix

## Validation taxonomy

Use these four states exactly:

- `REAL_VALIDATED`: the tested scanner workflow executed against a safe local
  fixture, produced structured output, and the claimed behavior was validated.
- `REAL_PARTIAL`: real local execution was validated, but one or more important
  detection, remediation, freshness, or targeted-verification dimensions were
  not completed.
- `BLOCKED_BY_ENVIRONMENT`: the workflow could not complete because an external
  environment dependency, such as network access, was unavailable.
- `NOT_TESTED`: a specific validation dimension was not performed in this
  milestone. This is not a failure result and must not be treated as one.

These states describe the tested evidence only. They do not mean a scanner
covers every project or that its external intelligence is current.

| Scanner | State | Version / binary / provenance | Real fixture and command | Result | Limitation |
| --- | --- | --- | --- | --- | --- |
| Gitleaks | `REAL_VALIDATED` | 8.30.1; `/opt/homebrew/bin/gitleaks`; Homebrew-installed upstream project | Disposable Node API fixture with a repository-owned synthetic token and a local validation rule; `gitleaks detect --source <fixture> --config <fixture>/.gitleaks.toml --no-git --redact --report-format json --report-path <report>` | Exit 1 with one structured finding; Vibe Code Guard normalized it, tracked it, and completed a real fix → targeted verify → `VERIFIED` chain | The token was synthetic and never externally verified |
| TruffleHog | `REAL_PARTIAL` | 3.96.0; `/opt/homebrew/bin/trufflehog`; Homebrew-installed upstream project | `trufflehog filesystem <fixture> --no-verification --no-update --no-color --json` | Real local JSON scan completed and participated in the secret-family verification; no finding was emitted for the repository-owned synthetic token | This fixture did not prove a TruffleHog detection rule match; no network verification was enabled |
| Semgrep | `REAL_PARTIAL` | 1.172.0; `/opt/homebrew/bin/semgrep`; Homebrew-installed upstream project | Node API fixture plus repository-local rule `test/real-scanner/semgrep/vcg-real-static.yml`; `semgrep scan --metrics=off --config <local-rule> <fixture> --json` with temporary HOME and CA settings | Exit 0 with one structured result; rule ID, severity, location, version, and finding were normalized by Vibe Code Guard | Normal HOME/log permissions and remote registry access are environment-sensitive; a real Semgrep finding → fix → targeted verify chain was not tested in this milestone |
| Trivy | `REAL_VALIDATED` | 0.73.0; `/opt/homebrew/bin/trivy`; Homebrew-installed upstream project | Dockerfile fixture; `trivy fs --scanners config --skip-db-update --format json --quiet <fixture>` | Returned real `DS-0002` / `DS-0026` findings; the config path completed a real Checkov + Trivy `VERIFIED` chain | Dependency findings were observed separately, but a Trivy dependency finding → fix → targeted verify chain was not tested. The local vulnerability DB was expired and remains a freshness limitation |
| OSV-Scanner | `BLOCKED_BY_ENVIRONMENT` | 2.5.0; `/opt/homebrew/bin/osv-scanner`; Homebrew-installed upstream project | `osv-scanner scan source --recursive --format json <fixture>` | The scanner started, but external OSV query access was unavailable; Vibe Code Guard preserved the incomplete dependency assessment | No database or network refresh was attempted; this remains a blocker for a complete OSV-backed dependency assessment |
| Checkov | `REAL_VALIDATED` | 3.3.0; `/opt/homebrew/bin/checkov`; pipx/Homebrew environment, upstream project | Dockerfile fixture; `checkov -d <fixture> --output json --quiet` | Exit 1 with structured `CKV_DOCKER_2` and `CKV_DOCKER_3`; after adding a non-root `USER` and local `HEALTHCHECK`, targeted verification with Checkov + Trivy returned `PASSED` / `VERIFIED` | External guideline mapping lookup was unavailable, but local checks and JSON parsing worked |
| OWASP ZAP | `REAL_PARTIAL` | 2.17.0; `/Applications/ZAP.app/Contents/Java/zap.sh`; official application installation | Temporary HOME version/launcher smoke; no active target was supplied | Real launcher health/version path was exercised without scanning a target | Active ZAP finding detection is `NOT_TESTED`; no add-ons were refreshed |
| Nuclei | `REAL_PARTIAL` | 3.11.1; `/opt/homebrew/bin/nuclei`; Homebrew-installed upstream project | Disposable loopback server with `nuclei -u http://127.0.0.1:<port> -tags tech -jsonl -silent -no-interactsh -timeout 3 -retries 0` | Real localhost invocation completed safely with structured empty output | Active Nuclei finding detection is `NOT_TESTED`; official templates were not refreshed |

## Validation dimensions not tested

These are explicit `NOT_TESTED` dimensions, not failures:

| Scanner or workflow | State | Boundary |
| --- | --- | --- |
| Semgrep real finding → fix → targeted verify chain | `NOT_TESTED` | Only local rule execution and normalization were validated |
| TruffleHog deterministic real finding match | `NOT_TESTED` | Safe local JSONL execution completed, but the synthetic token was not detected |
| Trivy dependency finding → fix → targeted verify chain | `NOT_TESTED` | Dependency findings were observed with a usable but stale DB; no dependency remediation chain was claimed |
| OWASP ZAP active real finding detection | `NOT_TESTED` | Only launcher/version smoke was performed |
| Nuclei active real finding detection | `NOT_TESTED` | Only safe localhost invocation with empty output was performed |

## Real fix and verification chains

### Secret chain: Gitleaks + TruffleHog

1. A full Vibe Code Guard audit found a synthetic Gitleaks token and recorded
   Gitleaks 8.30.1 and TruffleHog 3.96.0 in the scanner observations.
2. The synthetic token was removed after an authorized fixture remediation.
3. `vibe-code-guard verify <finding-id> <fixture> --json` ran both relevant
   scanners, parsed both outputs, preserved the stable scope, and returned:
   `PASSED`, lifecycle `VERIFIED`, exit 0.
4. Restoring the synthetic token returned `STILL_DETECTED`, lifecycle
   `REOPENED`, exit 1.

The verification command never marked a finding verified merely because one
scanner was clean: both scanners were required to execute successfully with
known versions and valid structured output.

### Container/IaC chain: Checkov + Trivy

1. A real Dockerfile audit found Checkov `CKV_DOCKER_2` / `CKV_DOCKER_3` and
   Trivy `DS-0002` / `DS-0026`.
2. The smallest safe synthetic remediation added `USER node` and a local
   `HEALTHCHECK`; no image was built or started.
3. Targeted verification ran Checkov 3.3.0 and Trivy 0.73.0 with Trivy config
   scanning and `--skip-db-update`.
4. Both returned valid empty result sets and the command returned `PASSED`,
   lifecycle `VERIFIED`, exit 0.

During this chain, Checkov's `/Dockerfile` output exposed an adapter defect:
the path lacked a usable project scope fingerprint. The adapter now resolves a
leading-slash project-relative path only when it can prove that the resulting
regular file is inside the authorized project root. The regression test also
confirms that an outside path such as `/etc/passwd` is not reinterpreted as a
project file.

## Negative and safety checks

| Check | Observed result |
| --- | --- |
| Real still-detected finding | `STILL_DETECTED`, lifecycle `REOPENED`, exit 1 |
| Missing real scanner binary | `VERIFICATION_INCOMPLETE`, exit 2; no `VERIFIED` state |
| Added `.gitleaksignore` after the finding | `VERIFICATION_INCOMPLETE`, `scopeUnchanged: false`; no `VERIFIED` state |
| Skipped/failed external dependency | Release gate remained `DO NOT DEPLOY` |
| Dashboard vs CLI | Local Dashboard persisted `PASSED` / `VERIFIED` and the same scanner versions and stable scope as the machine-readable CLI result |
| Runtime scope | ZAP/Nuclei were not run without an authorized localhost/test target |

## Performance observations

These are observations from the disposable validation run, not performance
guarantees. Vibe Code Guard recorded approximately:

| Operation | Duration |
| --- | ---: |
| Gitleaks finding audit | 14 ms |
| TruffleHog finding audit | 430 ms |
| Semgrep local-rule audit | 1,114 ms |
| Trivy dependency audit | 64 ms |
| Checkov Docker audit | 1,206 ms |
| Trivy config audit | 333 ms |
| OSV-Scanner blocked query | 20,885 ms |
| Gitleaks targeted verify | 10 ms |
| Checkov targeted verify | 1,128 ms |
| Trivy targeted verify | 321 ms |

The OSV delay is external/environmental and is intentionally visible rather
than hidden in the normal baseline.

## Conclusion

The minimum v0.7.1 real-validation target was met:

- a complete real secret/static-style chain was completed through Gitleaks and
  the TruffleHog family;
- a second scanner family completed through Checkov and Trivy config scanning;
- real `STILL_DETECTED`, incomplete coverage, and scope-cheating protections
  were exercised;
- Dashboard and machine-readable state agreed; and
- no global scanner or security-toolkit configuration was changed.

This is not a claim of complete real-world security coverage. OSV remains
blocked by external access, Trivy freshness remains degraded, Semgrep and ZAP
remain environment-sensitive, and active ZAP/Nuclei detection was not claimed.
