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
9. Microsoft. "Analyzing the SolarWinds Compromise." December 2020. https://msrc.microsoft.com/blog/2020/12/analyzing-the-solarwinds-compromise/
10. Mandiant. "Highly Evasive Attacker Leverages SolarWinds Supply Chain." December 2020. https://msrc.microsoft.com/blog/2020/12/analyzing-the-solarwinds-compromise/
11. CycloneDX Specification v1.5. OWASP. https://cyclonedx.org/
12. SPDX Specification v2.3. Linux Foundation. https://spdx.github.io/spdx-spec/
13. Sigstore. "Cosign: Container Signing." https://docs.sigstore.dev/cosign/signing/signing_with_containers/
14. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
15. OpenSSF Scorecard. https://github.com/ossf/scorecard
16. GUAC. "Graph for Understanding Artifact Composition." https://github.com/guacsec/guac