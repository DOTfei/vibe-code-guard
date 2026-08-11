# Installation

Vibe Code Guard can be used from a checkout or installed as a small set of
Vibe Code Guard-owned launchers under `$SECURITY_TOOLKIT_HOME` (default:
`$HOME/security-toolkit`). Upstream scanners remain independent installations.

## Platform support

v0.6 is intentionally conservative about platform claims:

| Platform | Status | Notes |
| --- | --- | --- |
| macOS Apple Silicon | SUPPORTED | Primary tested path; Homebrew and the documented ZAP cask are supported. |
| macOS Intel | PARTIAL | The Node/launcher workflow is portable, but the exact Homebrew formulas and ZAP installation must be verified on the host. |
| Linux | PARTIAL | The command/config/agent contracts are portable; this release does not provide a Linux package installer and official channels must be installed manually. |
| Windows / WSL | NOT YET SUPPORTED | No Windows-specific installer or path/runtime validation is claimed. |

`doctor --json` reports the actual local state. A platform is not considered
ready merely because the launcher starts; every required scanner and its
version/configuration checks must be usable.

## Safe first run

```bash
git clone https://github.com/DOTfei/vibe-code-guard.git
cd vibe-code-guard
./install.sh --dry-run
```

The dry run detects OS, architecture, existing binaries, Homebrew/pipx
availability, and conflicts. It prints the exact fixed installer actions. It
does not modify the machine.

After reviewing the plan:

```bash
./install.sh --yes
```

The installer:

- preserves healthy and newer user-installed tools;
- uses Homebrew for supported macOS packages and pipx for Checkov when
  available;
- never uses `curl | sh`, random mirrors, or arbitrary remote scripts;
- never disables Gatekeeper, SIP, firewall, XProtect, or other security
  controls;
- does not change shell startup files;
- creates only Vibe Code Guard-owned launchers and metadata; and
- runs doctor and the existing security-toolkit self-test after changes.

The launcher directory is returned as `localEntrypoints.pathHint` in JSON and
printed in human-readable output. It is not automatically added to PATH, since
the installer does not edit shell startup files. An agent can invoke the
returned absolute `vibe-code-guard` launcher directly, or a human can add that
directory to PATH explicitly after reviewing it.

If a supported installer is unavailable, the result is `DEGRADED` or
`FAILED` with an explanation. It is never presented as ready.

## Prerequisites and limits

- Node.js 18 or newer is required for the Vibe Code Guard CLI and Dashboard.
- Homebrew is the supported automatic dependency channel on macOS.
- `pipx` is recommended for an isolated Checkov installation; without it,
  Checkov must be installed manually through its official instructions.
- Java is required by the local OWASP ZAP installation/runtime.
- Docker is optional and is only relevant when a user explicitly provides a
  local Docker test target.

The agent should report missing prerequisites instead of silently installing
unrelated runtimes, changing system policy, or claiming that the toolkit is
ready.

## Existing toolchain behavior

The toolchain manifest is [`config/toolchain.json`](../config/toolchain.json).
It records candidates, version commands, supported minimum version ranges,
installation method, official source, doctor behavior, and the global
`security-tools self-test --json` expectation for each scanner. The manifest is
metadata; it does not bundle or relicense upstream projects.

Use:

```bash
vibe-code-guard doctor --json
security-tools doctor
security-tools self-test --json
```

Vibe Code Guard does not blindly upgrade scanners. The v0.6 lifecycle commands
use fixed official sources, preserve installation provenance, update one named
scanner at a time, and validate before promotion. `vibe-code-guard update`
only refreshes Vibe Code Guard-owned launchers from the current checkout.

```bash
vibe-code-guard tools status --json
vibe-code-guard tools check-updates --json
vibe-code-guard tools update semgrep --dry-run --json
vibe-code-guard tools refresh-data trivy --dry-run --json
```

Latest-version checks are informational and bounded. Offline or unavailable
official sources are reported as unknown/degraded rather than current. Engine
versions and databases, rules, templates, or add-ons are reported separately.

## Install states

The machine-readable contract uses:

- `READY`: required binaries and local workflow are usable;
- `DEGRADED`: a binary exists but an external/configuration dependency is
  unavailable or stale;
- `BROKEN`: a required binary or local dependency cannot execute; and
- `NOT_INSTALLED`: a component is absent.

## Uninstall

```bash
vibe-code-guard uninstall --dry-run
vibe-code-guard uninstall --yes
```

Uninstall removes only launchers and metadata recorded in the Vibe Code Guard
installation manifest. It preserves Gitleaks, TruffleHog, Semgrep, Trivy,
OSV-Scanner, Checkov, OWASP ZAP, Nuclei, their databases, and their templates.
Unrelated files and command-name conflicts are preserved.
