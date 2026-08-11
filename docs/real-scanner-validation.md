# v0.7.1 Real Scanner Validation

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

`REAL_VALIDATED` means the installed scanner executed against a safe fixture,
produced structured output, and its relevant behavior was validated. It does
not mean the scanner covers every project or that its external intelligence is
current.

| Scanner | State | Version / binary / provenance | Real fixture and command | Result | Limitation |
| --- | --- | --- | --- | --- | --- |
| Gitleaks | `REAL_VALIDATED` | 8.30.1; `/opt/homebrew/bin/gitleaks`; Homebrew-installed upstream project | Disposable Node API fixture with a repository-owned synthetic token and a local validation rule; `gitleaks detect --source <fixture> --config <fixture>/.gitleaks.toml --no-git --redact --report-format json --report-path <report>` | Exit 1 with one structured finding; Vibe Code Guard normalized it, tracked it, and completed a real fix → targeted verify → `VERIFIED` chain | The token was synthetic and never externally verified |
| TruffleHog | `REAL_PARTIAL` | 3.96.0; `/opt/homebrew/bin/trufflehog`; Homebrew-installed upstream project | `trufflehog filesystem <fixture> --no-verification --no-update --no-color --json` | Real local JSON scan completed and participated in the secret-family verification; no finding was emitted for the repository-owned synthetic token | This fixture did not prove a TruffleHog detection rule match; no network verification was enabled |
| Semgrep | `REAL_VALIDATED` | 1.172.0; `/opt/homebrew/bin/semgrep`; Homebrew-installed upstream project | Node API fixture plus repository-local rule `test/real-scanner/semgrep/vcg-real-static.yml`; `semgrep scan --metrics=off --config <local-rule> <fixture> --json` with temporary HOME and CA settings | Exit 0 with one structured result; rule ID, severity, location, version, and finding were normalized by Vibe Code Guard | Normal HOME/log permissions and remote registry access are environment-sensitive; the core validation used a local rule and did not depend on `semgrep.dev` |
| Trivy | `REAL_VALIDATED` with freshness limitation | 0.73.0; `/opt/homebrew/bin/trivy`; Homebrew-installed upstream project | Dependency and Dockerfile fixtures; `trivy fs --scanners vuln --skip-db-update --format json --quiet <fixture>` and `trivy fs --scanners config --skip-db-update --format json --quiet <fixture>` | Returned real lodash CVEs for the dependency fixture and real `DS-0002` / `DS-0026` findings for the Docker fixture; config findings completed a real Checkov + Trivy `VERIFIED` chain | The local vulnerability DB was expired. This is a real result from a usable stale DB, not a freshness PASS |
| OSV-Scanner | `BLOCKED_BY_ENVIRONMENT` | 2.5.0; `/opt/homebrew/bin/osv-scanner`; Homebrew-installed upstream project | `osv-scanner scan source --recursive --format json <fixture>` | The scanner started, but external OSV query access was unavailable; Vibe Code Guard preserved the incomplete dependency assessment | No database or network refresh was attempted; this remains a blocker for a complete OSV-backed dependency assessment |
| Checkov | `REAL_VALIDATED` | 3.3.0; `/opt/homebrew/bin/checkov`; pipx/Homebrew environment, upstream project | Dockerfile fixture; `checkov -d <fixture> --output json --quiet` | Exit 1 with structured `CKV_DOCKER_2` and `CKV_DOCKER_3`; after adding a non-root `USER` and local `HEALTHCHECK`, targeted verification with Checkov + Trivy returned `PASSED` / `VERIFIED` | External guideline mapping lookup was unavailable, but local checks and JSON parsing worked |
| OWASP ZAP | `REAL_PARTIAL` | 2.17.0; `/Applications/ZAP.app/Contents/Java/zap.sh`; official application installation | Temporary HOME version/launcher smoke; no active target was supplied | Real launcher health/version path was exercised without scanning a target | No active ZAP finding or targeted verification was claimed; no add-ons were refreshed |
| Nuclei | `REAL_PARTIAL` | 3.11.1; `/opt/homebrew/bin/nuclei`; Homebrew-installed upstream project | Disposable loopback server with `nuclei -u http://127.0.0.1:<port> -tags tech -jsonl -silent -no-interactsh -timeout 3 -retries 0` | Real localhost invocation completed safely with structured empty output | No deterministic template finding was claimed; official templates were not refreshed |

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
