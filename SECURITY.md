# Security Policy

Vibe Code Guard is early-alpha software. It is not a vulnerability-free
guarantee, and it should not be used as the sole security control for a
production system.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's GitHub
Security tab using **Report a vulnerability** / a private Security Advisory.
Once the repository is published, open its Security tab to access that form.
Do not publish credentials, exploit details, private source, or sensitive logs
in a public issue or pull request.

Include the affected version or commit, a concise impact description, safe
reproduction steps, and any suggested mitigation. Please allow time for
validation and coordinated disclosure.

## Scope and safe testing

The scope is the orchestration layer, dashboard, policy handling, output
parsing, local storage, and installation scripts in this repository. Test only
systems you own or are explicitly authorized to assess. Do not use the project
to scan third-party targets while reporting an issue.

Upstream scanner vulnerabilities should also be reported to their respective
maintainers; their links and licenses are listed in
`THIRD_PARTY_NOTICES.md`.
