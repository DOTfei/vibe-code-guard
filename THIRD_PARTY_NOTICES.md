# Third-Party Notices

This repository contains original orchestration, dashboard, policy, and test
code. It does not bundle or modify the security scanners listed below. The
toolkit invokes locally installed command-line tools or applications through
explicit adapters and allowlists. Each upstream project retains its own
copyright, trademarks, and license.

The machine-specific binary paths and local installation details are
intentionally excluded from this public notice. See `third-party/tools.json`
and `security-toolchain.lock` for portable integration metadata.

| Tool | Upstream project | License | Integration boundary |
| --- | --- | --- | --- |
| Gitleaks | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT | External CLI; not bundled or modified |
| TruffleHog | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | GNU AGPL v3 — see upstream LICENSE | External CLI; not bundled or modified |
| Semgrep | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 | External CLI; not bundled or modified |
| Trivy | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | External CLI; not bundled or modified |
| OSV-Scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | External CLI; not bundled or modified |
| Checkov | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | External CLI; not bundled or modified |
| OWASP ZAP | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | Apache-2.0 | External application/CLI; not bundled or modified |
| Nuclei | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT | External CLI; not bundled or modified |
| Nuclei Templates | [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | External detection content; not bundled or modified |
| Strix | [usestrix/strix](https://github.com/usestrix/strix) | Apache-2.0 | Optional external/agent integration; not bundled |
| Next AI Draw.io | [DayuanJiang/next-ai-draw-io](https://github.com/DayuanJiang/next-ai-draw-io) | Apache-2.0 | External documentation/diagram tool; not bundled or modified |

## License review notes

The license names above were checked against the corresponding upstream
repositories' license files. TruffleHog is described conservatively as GNU AGPL
v3 with reference to its upstream LICENSE; its SPDX expression should not be
inferred beyond that record. Semgrep's LGPL-2.1 also requires particular care
if this project ever bundles, links to, modifies, or redistributes that
project. The current design only invokes independently installed tools and does
not copy their source, binaries, rules, templates, or libraries into this
repository. Re-review licensing before distributing a combined binary,
container image, installer, or linked library.

Nuclei Templates are a separate upstream repository and detection-content
artifact. The Nuclei binary's MIT license does not automatically describe all
templates, custom content, or other downloaded artifacts used with it. Review
the applicable template repository and artifact terms separately.

Next AI Draw.io is listed because it was used to edit/export the README
architecture diagram. It is not a runtime dependency of this repository.

This notice is an attribution record, not legal advice. Upstream notices and
dependencies distributed by each tool remain governed by that tool's own
distribution terms.
