# Upstream tool lifecycle

Vibe Code Guard does not publish, bundle, modify, or relicense the upstream
scanners. It discovers their local state, uses fixed official project sources
for informational update checks, invokes the installation method already in
use where supported, and validates one tool at a time.

## Engine and security content are separate

The lifecycle model keeps these values independent:

- Vibe Code Guard version and workflow version;
- scanner engine version and installation provenance;
- latest stable upstream engine version, when it can be verified;
- vulnerability databases, rule packs, templates, and add-on freshness; and
- the last known-good validation and update attempt.

For example, a current Trivy executable with an expired local vulnerability
database is reported as `engine current` and `content stale`; it is not shown
as completely current. Nuclei CLI and official Nuclei Templates are also
tracked separately.

## Commands

```bash
vibe-code-guard tools status --json
vibe-code-guard tools check-updates --json
vibe-code-guard tools update --dry-run --json
vibe-code-guard tools update semgrep --dry-run --json
vibe-code-guard tools refresh-data trivy --dry-run --json
```

`status` is local and uses cached information. `check-updates` may contact
the fixed official release source for each project and has a bounded timeout.
When that source is unavailable, the result is
`UPDATE_CHECK_UNAVAILABLE`; it is never interpreted as `CURRENT`.
Cached release metadata has a finite TTL. Once stale, status reports
`CACHE_STALE` until a manual official check refreshes it; corrupt cache data is
discarded safely and never executed.

The default scan path never mutates the scanner toolchain. Dashboard startup
also never updates tools. Any mutating command requires a single named scanner
and explicit `--yes` confirmation after the release notes and official
security-advisories review has been acknowledged with `--security-reviewed`;
`--dry-run` is the default for update and content-refresh plans.
Content refresh also requires `--security-reviewed` before `--yes` can mutate
local data. The acknowledgement confirms that the named official content
source and trust policy were reviewed; it is not an automated advisory check.
The localhost HTTP mutation endpoints additionally require JSON and an
explicit confirmation header so a third-party webpage cannot submit a simple
cross-origin update request.

## Official sources and provenance

The trusted source and compatibility policy are repository-controlled in
[`config/toolchain.json`](../config/toolchain.json). Project-local
`.vibe-code-guard.json` cannot override an upstream repository, installer,
binary path, or update command.

The lifecycle records whether the installed binary appears to have come from
Homebrew, a Homebrew cask, pipx/pip, or an unknown source. Supported updates
normally use that same provenance. Vibe Code Guard does not silently convert
a pipx installation to Homebrew, downgrade a healthy newer version, execute a
release-page asset, use a random mirror, disable TLS verification, or run a
shell command supplied by a project.

Unknown or ambiguous provenance returns `MANUAL_REVIEW_REQUIRED`; cached state
cannot turn an unrecognized executable into a trusted Homebrew, pipx, or uv
installation. Release metadata is data only. Redirects, prerelease or
malformed tags, incomplete versions, and unexpectedly long version strings
are rejected and never become executable commands.

## Update safety

The intended update sequence is:

```text
CHECK official source
→ PLAN one scanner
→ UPDATE through its existing official channel
→ VERIFY binary and version
→ RUN that scanner's self-test
→ PROMOTE only after validation
```

If validation fails, the new version is not promoted as known-good. The local
state records the attempt and reports `DEGRADED` or `BROKEN`. Package-manager
rollback is not assumed to be available; when it cannot be performed safely,
the previous known-good metadata and diagnostics are preserved for manual
recovery.

Scanner mutation, security-content refresh, and targeted verification share a
local operation lock. An overlapping request returns `BUSY` rather than
changing a binary while verification is using it. Verification records the
actual scanner versions it ran; an unknown version cannot establish
`VERIFIED`.

The state file is VCG-owned machine state under the configured toolkit home:
`vibe-code-guard/security-toolchain.state.json`. It contains versions,
provenance, update checks, validation, and content freshness metadata only;
it must never contain credentials.

## Content refresh

Independent refresh plans are available where the upstream tool supports them:

- Trivy: official vulnerability database refresh;
- Nuclei: official template refresh with upstream verification controls; and
- OWASP ZAP: the official add-on mechanism only; VCG does not accept arbitrary
  add-on URLs or silently install community marketplace content.

Other tools report engine-coupled or network-backed content when a portable
local freshness value is not available. An expired but readable database is
`STALE`/`DEGRADED`; missing or corrupt required content is not a false pass.
Supported external content with unknown freshness remains `DEGRADED` rather
than making the overall lifecycle appear fully current.

## First-run recovery

The Vibe Code Guard launcher installation is separate from upstream scanner
readiness. A present Trivy binary with no local database is reported with
`content.state: MISSING` and a structured recovery action:

```text
vibe-code-guard tools refresh-data trivy
```

The command is a plan by default. Applying it requires explicit confirmation,
the existing lifecycle lock, and the official-source trust review. Agents
should explain the action, obtain authorization, run it, and re-run doctor.
ZAP or network-backed readiness that cannot be verified remains degraded or
manual-review-required; it is never silently promoted to ready.

## Offline behavior

Audits and targeted rescans use installed scanners without requiring a
successful latest-version lookup. If the network is unavailable, the agent
should report the installed known-good version, the unavailable update check,
and any known stale intelligence separately.
