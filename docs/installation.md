# Installation

Vibe Code Guard can be used from a checkout or installed as a small set of
Vibe Code Guard-owned launchers under `$SECURITY_TOOLKIT_HOME` (default:
`$HOME/security-toolkit`). Upstream scanners remain independent installations.

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

If a supported installer is unavailable, the result is `DEGRADED` or
`FAILED` with an explanation. It is never presented as ready.

## Existing toolchain behavior

The toolchain manifest is [`config/toolchain.json`](../config/toolchain.json).
It records candidates, version commands, installation method, official source,
and whether the scanner is required. The manifest is metadata; it does not
bundle or relicense upstream projects.

Use:

```bash
vibe-code-guard doctor --json
security-tools doctor
security-tools self-test --json
```

Vibe Code Guard does not blindly upgrade scanners. Scanner updates remain in
the controlled global security-toolkit lifecycle. `vibe-code-guard update`
only refreshes Vibe Code Guard-owned launchers from the current checkout.

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
