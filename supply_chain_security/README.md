# Supply Chain Security Track

A comprehensive deep-research track covering the full spectrum of software supply chain security—from threat taxonomy and attack analysis to defensive frameworks and future trends.

## Overview

This track provides an in-depth examination of software supply chain security, spanning the complete lifecycle from threat landscape analysis through practical hardening to emerging technologies and regulations. Each chapter is designed for security researchers, software engineers, DevSecOps practitioners, and security leaders who need deep technical understanding of supply chain attacks and defenses.

## Prerequisites

- Familiarity with package managers (npm, pip, cargo, Maven)
- Understanding of CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins)
- Basic knowledge of cryptography (X.509, code signing, hash functions)
- Experience with at least one programming language (JavaScript, Python, Rust, or Go)
- Understanding of containerization (Docker, Kubernetes)

## Reading Order

### Core Path (Recommended)

1. **[01_supply_chain_threat_landscape](docs/01_supply_chain_threat_landscape.md)** — Start here. Establishes the taxonomy of supply chain attacks, threat actors, and ecosystem scale.

2. **[02_dependency_attacks](docs/02_dependency_attacks.md)** — The most common attack vector. Covers dependency confusion, typosquatting, install script abuse, and dependency hijacking.

3. **[03_build_pipeline_security](docs/03_build_pipeline_security.md)** — CI/CD attack surface, poisoned pipeline execution, self-hosted runner abuse, and GitHub Actions security.

4. **[04_malicious_packages](docs/04_malicious_packages.md)** — Detection techniques, malware patterns (DNS exfiltration, environmental keying, obfuscation), and major case studies.

5. **[05_sbom_vulnerability_management](docs/05_sbom_vulnerability_management.md)** — SBOM formats, generation tools, vulnerability scanning, VEX, and automated dependency updates.

6. **[06_code_signing_integrity](docs/06_code_signing_integrity.md)** — Code signing architecture, Sigstore/cosign, transparency logs, stolen key incidents, and reproducible builds.

7. **[07_slsa_framework_attestation](docs/07_slsa_framework_attestation.md)** — SLSA levels 0-4, provenance format, verification, and adoption roadmap.

8. **[08_supply_chain_case_studies](docs/08_supply_chain_case_studies.md)** — SolarWinds, Codecov, XZ Utils, Log4Shell, ua-parser-js, 3CX, and other major incidents.

9. **[09_supply_chain_hardening](docs/09_supply_chain_hardening.md)** — Practical hardening guide with SLSA adoption roadmap, dependency pinning, vulnerability scanning, and zero-trust supply chain.

10. **[10_supply_chain_future](docs/10_supply_chain_future.md)** — AI-assisted analysis, WebAssembly supply chain, SBOM regulations, quantum-resistant signing, in-toto, and GUAC.

### Deep-Dive Path (For Practitioners)

If you are actively implementing supply chain security measures:

1. Read chapters 01-03 for threat context
2. Skip to **[09_supply_chain_hardening](docs/09_supply_chain_hardening.md)** for implementation guidance
3. Use **[CHEATSHEET.md](CHEATSHEET.md)** for quick reference
4. Read remaining chapters for depth in specific areas

### Incident Response Path (For Security Teams)

If you are responding to a supply chain incident:

1. Read **[08_supply_chain_case_studies](docs/08_supply_chain_case_studies.md)** for comparable incidents
2. Read **[04_malicious_packages](docs/04_malicious_packages.md)** for detection techniques
3. Use **[CHEATSHEET.md](CHEATSHEET.md)** for quick scanning commands
4. Read **[09_supply_chain_hardening](docs/09_supply_chain_hardening.md)** for remediation guidance

## Synthesis

- **[SUPPLY_CHAIN_FINAL_REPORT.md](SUPPLY_CHAIN_FINAL_REPORT.md)** — Comprehensive synthesis report covering the entire track, with unified threat analysis, defensive framework assessment, and strategic recommendations.

## Quick Reference

- **[CHEATSHEET.md](CHEATSHEET.md)** — Quick-reference cheat sheet with SBOM generation commands, SLSA level requirements, code signing commands, vulnerability scanning tools, dependency confusion indicators, malicious package indicators, and key CVE references.

## Cross-References

### Key CVEs Referenced

| CVE | Chapter | Description |
|-----|---------|-------------|
| CVE-2024-3094 | 01, 08 | XZ Utils backdoor |
| CVE-2021-44228 | 05, 08 | Log4Shell (Apache Log4j RCE) |
| CVE-2020-10148 | 08 | SolarWinds SUNBURST |
| CVE-2018-16492 | 04, 08 | event-stream compromise |

### Tools Referenced

| Tool | Chapter | Purpose |
|------|---------|---------|
| Syft | 05, 09 | SBOM generation |
| Trivy | 05, 09 | Vulnerability scanning |
| Grype | 05, 09 | Vulnerability scanning |
| cosign | 06, 09 | Container signing |
| slsa-verifier | 07, 09 | SLSA provenance verification |
| osv-scanner | 05 | Vulnerability scanning |
| diffoscope | 06 | Build comparison |
| reprotest | 06 | Reproducibility testing |
| Scorecard | 09 | Security assessment |
| GUAC | 10 | Supply chain graph analysis |

### Standards Referenced

| Standard | Chapter | Purpose |
|----------|---------|---------|
| SLSA v1.0 | 03, 07, 09 | Supply chain levels |
| SPDX 2.3 | 05 | SBOM format |
| CycloneDX 1.5 | 05 | SBOM format |
| in-toto | 10 | Supply chain verification |
| SBOM (NTIA) | 05, 09 | Minimum elements |
| VEX | 05 | Vulnerability exploitability |
| EO 14028 | 05, 10 | US SBOM mandate |
| EU CRA | 05, 10 | EU SBOM mandate |

## Chapter Word Counts

| Chapter | Topic | Approximate Words |
|---------|-------|-------------------|
| 01 | Supply Chain Threat Landscape | 3,200 |
| 02 | Dependency Attacks | 3,400 |
| 03 | Build Pipeline Security | 3,300 |
| 04 | Malicious Packages | 3,500 |
| 05 | SBOM & Vulnerability Management | 3,300 |
| 06 | Code Signing & Integrity | 3,200 |
| 07 | SLSA Framework & Attestation | 3,400 |
| 08 | Supply Chain Case Studies | 3,800 |
| 09 | Supply Chain Hardening | 3,500 |
| 10 | Supply Chain Future | 3,400 |
| — | **Final Report** | **4,200** |
| — | **Cheat Sheet** | **1,800** |

## Contributing

This track is part of the deep-researcher project. To suggest corrections or additions, please refer to the project's contribution guidelines.

## License

This track is provided for educational and professional development purposes. The content references publicly available vulnerabilities, CVEs, and security research with appropriate attribution.

## References

1. SLSA Specification v1.0. "Supply-chain Levels for Software Artifacts." https://slsa.dev/spec/v1.0/
2. OpenSSF. "Securing the Software Supply Chain." https://openssf.org/
3. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
4. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
5. CISA. "Software Bill of Materials (SBOM)." https://www.cisa.gov/sbom
6. Sonatype. "2023 State of the Software Supply Chain Report." https://www.sonatype.com/state-of-the-software-supply-chain
7. Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
8. Freund, A. "Backdoor in xz/liblzma." OpenWall oss-security mailing list, March 2024. https://www.openwall.com/lists/oss-security/2024/03/29/4
9. Microsoft. "Analyzing the SolarWinds Compromise." December 2020. https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
10. Mandiant. "Highly Evasive Attacker Leverages SolarWinds Supply Chain." December 2020. https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
11. CycloneDX Specification v1.5. OWASP. https://cyclonedx.org/
12. SPDX Specification v2.3. Linux Foundation. https://spdx.github.io/spdx-spec/
13. Sigstore. "Cosign: Container Signing." https://docs.sigstore.dev/cosign/signing/signing_with_containers/
14. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
15. OpenSSF Scorecard. https://github.com/ossf/scorecard
16. GUAC. "Graph for Understanding Artifact Composition." https://github.com/guacsec/guac

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-10894: Nx build-system 's1ngularity' npm compromise** *(2025-09)* — Beginning August 26, 2025, attackers exploited a vulnerable GitHub Actions workflow in the Nx monorepo build-system repository to steal an npm publishing token and publish trojanized versions of Nx and several plugins. The malware scanned local filesystems, exfiltrated credentials, and uploaded them to attacker-created GitHub repositories under compromised accounts; it was also notable for abusing local AI CLI tools to aid reconnaissance. Red Hat assigned CVSS 3.1 base score 9.6 (Critical); published September 24, 2025. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-10894)

### Incidents & In-the-Wild Exploitation

- **Shai-Hulud: First self-replicating npm worm (CISA alert, Sept 2025)** *(2025-09)* — In September 2025 a self-propagating worm dubbed Shai-Hulud compromised hundreds of npm packages (starting with @ctrl/tinycolor) by stealing maintainer npm tokens and GitHub/cloud credentials, then automatically publishing malicious versions of any packages the stolen tokens could access. CISA issued a public alert on the widespread npm compromise, and a far larger 'Shai-Hulud 2.0' campaign in November 2025 affected tens of thousands of GitHub repositories. This is the first large-scale worm-style attack on an open-source package ecosystem and is not in the current track. [[source]](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- **Chalk/debug crypto-clipper attack via Qix maintainer phishing (Sept 8, 2025)** *(2025-09)* — On September 8, 2025, attackers phished npm maintainer Josh Junon ('Qix-') with a fake 2FA-reset email from the spoofed domain npmjs.help and, within ~16 minutes, pushed malicious versions of foundational packages including chalk, debug, ansi-regex, strip-ansi and color-convert (collectively over 2 billion weekly downloads). The injected payload was a browser crypto-clipper that hooked fetch(), XMLHttpRequest and window.ethereum to swap cryptocurrency wallet addresses. Malicious versions were live ~2.5 hours, with a potential blast radius covering roughly 34% of the npm ecosystem. [[source]](https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk)

### Techniques

- **GitHub announces mandatory npm publishing hardening after 2025 attacks** *(2025)* — In response to the Shai-Hulud and Qix account-takeover attacks, GitHub published a plan to restrict npm publishing to three methods: local publishing with mandatory 2FA, granular tokens with a maximum seven-day lifetime, and OIDC-based trusted publishing. Classic tokens and TOTP-based 2FA are being deprecated in favor of FIDO/WebAuthn, and token-bypass options for local publishing are being removed. This is a structural ecosystem defense change not reflected in the current track. [[source]](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)

### Standards & Frameworks

- **SLSA v1.2 adds the Source Track (Nov 2025)** *(2025-11)* — Announced November 24, 2025, SLSA v1.2 introduces the Source Track, extending the framework beyond build provenance to address threats in source code authoring, review, and management. It maintains backward compatibility with v1.1 (itself approved April 21, 2025), and the community is now developing Build Environment and Dependency tracks. The track currently documents only SLSA v1.0, so v1.1 and the v1.2 Source Track are new. [[source]](https://slsa.dev/blog/2025/11/announce-slsa-v1.2)
- **CISA 2025 SBOM Minimum Elements draft revision** *(2025-08)* — In August 2025 CISA released a public-comment draft updating the SBOM Minimum Elements (superseding the 2021 NTIA baseline) to reflect maturing tooling and implementation. It adds four new data fields (Component Hash, License, Tool Name, and Generation Context), removes the separate Access Controls element by folding it into Distribution and Delivery, and refines fields such as Software Producer and Software Identifiers. This updates the SBOM/regulatory guidance referenced in chapters 05 and 10. [[source]](https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom)
