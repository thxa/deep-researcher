# Supply Chain Security: Final Report

## Executive Summary

The software supply chain has become the primary attack surface for sophisticated threat actors ranging from nation-state groups to organized criminal enterprises. The cascading nature of supply chain compromise—where a single vulnerability or malicious insertion can affect thousands of downstream organizations—makes supply chain security an existential concern for every organization that develops, deploys, or consumes software.

This report synthesizes the findings from the Supply Chain Security deep-research track, covering the full spectrum of supply chain attacks, defenses, and emerging trends. The core findings are:

1. **Supply chain attacks are increasing exponentially**—from 245,000+ malicious packages identified in 2023 to a projected continuing growth trajectory, with documented increases of 742% between 2019 and 2022.

2. **The attack surface is vast and growing**—the average JavaScript project has 683 transitive dependencies, each representing a trust relationship with an unknown maintainer. New packaging ecosystems (WebAssembly, AI models) are expanding the attack surface further.

3. **Regulatory pressure is intensifying**—US Executive Order 14028, the EU Cyber Resilience Act, and similar legislation worldwide are making supply chain transparency (particularly SBOMs) a legal requirement, not merely a best practice.

4. **Technology is catching up**—frameworks like SLSA, tools like Sigstore, and platforms like GUAC are providing the technical infrastructure needed to verify supply chain integrity at scale.

5. **Human factors remain the weakest link**—from the XZ Utils backdoor's years-long social engineering campaign to the routine compromise of maintainer accounts through credential theft, the human element in supply chain security remains the most difficult to address.

6. **Detection is getting harder**—environmental keying, obfuscated payloads, and AI-generated malicious code make traditional detection methods less effective. The XZ Utils backdoor was detected by a performance anomaly, not a security tool, demonstrating that novel detection approaches are needed.

7. **The regulatory landscape is shifting rapidly**—organizations that do not implement SBOM generation, vulnerability management, and supply chain transparency face increasing legal liability under US Executive Order 14028, the EU Cyber Resilience Act, and similar legislation worldwide.

---

## The Threat Landscape: A Unified View

### Attack Vector Taxonomy

The research track identified seven primary categories of supply chain attacks, each with distinct attack vectors, detection challenges, and mitigation strategies:

**Dependency Attacks** target the package resolution process. Dependency confusion (exploiting registry priority), typosquatting (exploiting developer mistakes), and star-jacking (exploiting social proof) all exploit the trust that package managers place in registry metadata. These attacks are uniquely dangerous because they require no compromise of any target system—a misconfigured package manager is sufficient for remote code execution.

**Build Pipeline Attacks** target the CI/CD systems that transform source code into deployable artifacts. Poisoned Pipeline Execution (PPE), self-hosted runner abuse, and secrets exfiltration through CI logs represent a broad attack surface that most organizations have not adequately secured. The SolarWinds SUNBURST attack demonstrated that compromising the build system is more devastating than compromising the source code, because source-level defenses (code review, static analysis) are bypassed entirely.

**Malicious Package Attacks** target the contents of packages themselves. From the event-stream cryptostealer that targeted Copay wallets to the ua-parser-js cryptominer that compromised millions of weekly downloads, malicious packages exploit the inherent trust that developers place in their dependencies. Environmental keying—the practice of activating malicious payloads only in specific environments—makes detection extremely difficult.

**Code Signing Attacks** target the cryptographic infrastructure that underpins supply chain trust. Stolen signing keys (NVIDIA, Samsung, Lenovo, D-Link) demonstrate that code signing certificates, once compromised, cannot be effectively revoked. The fundamental assumption of code signing—that the signer is trustworthy—is increasingly challenged by these incidents.

**Social Engineering Attacks** target the human element of the supply chain. The XZ Utils backdoor represents the gold standard of supply chain social engineering: a patient, multi-year campaign to gain maintainer status and insert a backdoor that would have compromised SSH globally. The event-stream compromise and the 3CX double supply chain attack both employed social engineering as primary vectors.

**Protestware and Intentional Sabotage** represent a growing category where maintainers intentionally break or compromise their own packages. The colors.js/faker.js incident and the left-pad removal demonstrate that maintainer intent—whether ideological protest or simple burnout—can have systemic consequences.

**Regulatory and Compliance Gaps** represent an emerging category where organizations fail to meet legal requirements for supply chain transparency. As SBOM mandates become law, organizations that cannot produce SBOMs for their software face legal liability.

### Threat Actor Analysis

The research track documented four primary categories of threat actors:

**Nation-state actors** represent the most sophisticated threat. APT29's SolarWinds operation demonstrated patience, operational security, and selectivity that few other actors can match. DPRK's Lazarus Group focuses on financially motivated supply chain attacks targeting cryptocurrency. APT41 operates across both espionage and financially motivated campaigns. These actors have the resources and patience to execute multi-year campaigns.

**Organized criminal groups** focus on financially motivated supply chain attacks. Access brokers compromise maintainer accounts and sell publishing access. Ransomware operators increasingly target supply chains as force multipliers—compromising a single build pipeline can deploy ransomware across thousands of organizations simultaneously.

**Ideologically motivated actors** include protestware authors (colors.js/faker.js) and hacktivists. While their motivations differ from criminal actors, the impact on downstream consumers is identical—their software breaks.

**Opportunistic actors** include typosquatters, cryptominer operators, and credential thieves who target specific packages or ecosystems for quick financial gain. These actors are the most numerous but typically the least sophisticated.

### Ecosystem-Specific Vulnerabilities

Each package ecosystem has unique vulnerability characteristics:

- **npm**: The largest and most attacked ecosystem, with 683 average transitive dependencies, install script execution, and namespace confusion risks. The `postinstall` script mechanism is the single most exploited attack vector in the npm ecosystem.

- **PyPI**: The `setup.py` code execution model and flat namespace create persistent attack surfaces. Python's flexible package index configuration (`--extra-index-url`) creates dependency confusion risks.

- **Maven Central**: The Java ecosystem's deep cultural reliance on dependency management (Log4Shell demonstrated that a single vulnerability in a transitive dependency can affect millions of applications) and the hierarchical group ID namespace (which is not verified) create unique risks.

- **crates.io**: While Rust's type safety provides some guarantees, `build.rs` and procedural macros execute arbitrary code during compilation, creating a different but equally dangerous attack surface.

- **Go modules**: The decentralized model (no central registry) and the checksum database provide some protection, but typosquatting on module paths and `replace` directive abuse remain viable attacks.

---

## Defensive Frameworks: What Works

### SLSA Framework

The SLSA framework provides the most comprehensive model for supply chain integrity, defining four progressive levels of supply chain security:

- **SLSA Level 1** (Provenance exists): Generating and publishing provenance metadata for all release artifacts. This is the minimum viable defense and should be achievable by any organization within months.

- **SLSA Level 2** (Hosted build): Running all builds on a hosted CI/CD platform that generates signed provenance. This provides cryptographic proof that an artifact was built by the expected CI/CD system.

- **SLSA Level 3** (Non-falsifiable provenance): Hardening the build pipeline so that provenance cannot be forged, even by maintainers with write access. This requires careful configuration of branch protection, permissions, and build triggers.

- **SLSA Level 4** (Reproducible builds): Implementing hermetic builds, two-party review, and reproducible build verification. This is the gold standard and requires significant investment.

The research track demonstrated that SLSA adoption is accelerating. GitHub Actions provides SLSA Level 3 provenance for npm packages, Google Cloud Binary Authorization enforces SLSA policies, and the slsa-github-generator enables SLSA Level 3 provenance generation for any GitHub Actions workflow.

### SBOM and Vulnerability Management

SBOMs provide the foundational inventory that enables vulnerability management. The track demonstrated that SBOM generation (using tools like Syft and Trivy), vulnerability scanning (using Grype, Trivy, and OSV Scanner), and VEX integration create a comprehensive vulnerability management workflow:

1. **Generate**: SBOMs are generated during the CI/CD pipeline for every release artifact
2. **Scan**: SBOMs are scanned against vulnerability databases (NVD, OSV, CVE) to identify known vulnerabilities
3. **Enrich**: VEX documents provide context about which vulnerabilities are actually exploitable in a specific deployment
4. **Remediate**: Automated tools (Dependabot, Renovate) create PRs to update vulnerable dependencies
5. **Verify**: SBOMs are verified against policy (no critical vulnerabilities, no GPL dependencies, etc.)

The track demonstrated that regulatory requirements (US Executive Order 14028, EU Cyber Resilience Act) are making SBOMs a legal obligation. Organizations that do not implement SBOM generation and vulnerability management face both security risk and regulatory non-compliance.

### Code Signing and Integrity Verification

The track demonstrated that code signing is necessary but not sufficient. Stolen signing keys (NVIDIA, Samsung, Lenovo, D-Link) prove that traditional X.509 code signing has fundamental weaknesses:

1. **Key compromise**: Once a signing key is compromised, it cannot be effectively revoked because most verification systems do not perform real-time revocation checks
2. **Timestamp attacks**: Expired certificates can still be used to sign malware if the signature is timestamped before the expiration date
3. **Trust on first use**: Code signing verifies the identity of the signer, not the trustworthiness of the code

Sigstore's keyless signing model and transparency logs (Rekor) address these weaknesses by:
- Using ephemeral signing keys tied to OIDC identity (not long-lived private keys)
- Recording all signing events in a public, append-only transparency log
- Enabling real-time verification of signing identity and provenance

The track demonstrated that Sigstore/cosign is now the standard for container image signing, and npm provenance signing is becoming standard for npm package signing.

### Detection and Analysis

The track documented the full spectrum of malicious package detection techniques:

- **Static analysis**: Examining package contents without execution, looking for known malware patterns (obfuscated code, environment variable access, network operations)
- **Dynamic sandboxing**: Installing packages in isolated environments and monitoring behavior (network connections, file operations, process spawning)
- **Heuristic analysis**: Using metadata signals (package age, maintainer history, download velocity) to identify suspicious packages
- **AI-assisted detection**: Using large language models to analyze code for malicious patterns that static analysis tools miss

The track demonstrated that environmental keying—the practice of activating malicious payloads only in specific environments—makes both static and dynamic analysis difficult. The best detection approach combines multiple techniques: static analysis for known patterns, dynamic analysis for behavioral signals, heuristics for metadata anomalies, and AI for novel patterns.

---

## Case Study Synthesis

The eight major case studies documented in this track provide a comprehensive view of supply chain attacks across multiple dimensions:

**Scale varies dramatically**: From the left-pad incident (breaking builds through accidental removal of an 11-line package) to the SolarWinds SUNBURST attack (compromising 18,000 organizations through build system compromise), supply chain attacks range from accidental to nation-state-level.

**Attack vectors are diverse**: The case studies document dependency confusion (Birsan), build system compromise (SolarWinds, XZ Utils), maintainer account compromise (ua-parser-js), build script modification (Codecov), Git server compromise (PHP), dependency vulnerability (Log4Shell), and intentional sabotage (colors.js/faker.js). No single defense addresses all of these vectors.

**Detection methods vary**: SolarWinds was detected through behavioral analysis (anomalous DNS traffic), XZ Utils was detected through performance analysis (500ms SSH latency), ua-parser-js was detected through npm monitoring, and Codecov was detected through technical analysis of the modified script. The diversity of detection methods underscores the need for defense in depth.

**Impact cascades**: The 3CX supply chain attack demonstrated that supply chain attacks can cascade—a compromise of Trading Technologies led to a compromise of 3CX, which led to compromises of 3CX's 600,000+ customers. Supply chain attacks are force multipliers because they compromise not a single target but the entire downstream ecosystem.

**The human element is critical**: The XZ Utils backdoor represents the most sophisticated social engineering attack in the history of open-source software. The attacker spent two years building trust before inserting the backdoor. This demonstrates that technical defenses alone are insufficient—social and governance mechanisms (two-party review, maintainer governance) are essential.

---

## Recommendations

### For Organizations

1. **Implement SLSA Level 2 provenance within 3 months and SLSA Level 3 within 6 months.** The slsa-github-generator makes this achievable for any organization using GitHub Actions.

2. **Generate SBOMs for all release artifacts.** Use Syft or Trivy to generate CycloneDX or SPDX SBOMs and attach them to releases as signed attestations.

3. **Implement vulnerability scanning in CI/CD.** Use Trivy, Grype, or OSV Scanner to scan for vulnerabilities at every build. Block deployments with critical or high vulnerabilities.

4. **Sign all release artifacts with Sigstore/cosign.** Use keyless signing (Sigstore) for simplicity, and verify signatures at deployment time.

5. **Deploy private registries with dependency control.** Use Artifactory, Nexus, or Verdaccio to control which packages are available to developers, and configure correct registry priority.

6. **Pin all dependencies with hash verification.** Use lock files with integrity hashes (`npm ci`, `pip install --require-hashes`, `cargo install --locked`) and never allow unverified dependency resolution in production.

7. **Enable 2FA on all maintainer accounts.** Use hardware security keys (YubiKey) for maximum security, and require 2FA for all publish operations.

8. **Implement dependency review in CI/CD.** Use `dependency-review-action` or equivalent to review all dependency changes in pull requests.

9. **Use OpenSSF Scorecard to evaluate dependencies.** Reject dependencies that score below a threshold (e.g., 5 out of 10).

10. **Establish an incident response plan for supply chain attacks.** The plan should include: detecting malicious packages, revoking compromised signing keys, rotating CI/CD secrets, and communicating with downstream consumers.

### Implementation Priorities and Timeline

Based on the analysis throughout this track, organizations should prioritize supply chain security investments as follows:

**Immediate (0-30 days):**
- Enable 2FA on all maintainer and CI/CD accounts
- Pin all dependencies to exact versions with integrity hashes
- Switch from `npm install` to `npm ci` in all CI/CD pipelines
- Configure correct registry priority (private first, then public)
- Begin vulnerability scanning in CI/CD (Trivy or Grype)
- Enable branch protection and required reviews on all repositories

**Short-term (1-3 months):**
- Deploy a private registry (Artifactory, Nexus, or Verdaccio)
- Generate SBOMs for all release artifacts using Syft
- Implement dependency review in all pull requests
- Sign all release artifacts with Sigstore/cosign
- Generate SLSA Level 2 provenance for all release artifacts
- Implement automated dependency updates (Dependabot or Renovate)

**Medium-term (3-6 months):**
- Achieve SLSA Level 3 provenance for critical artifacts
- Deploy vulnerability scanning for all container images in production
- Implement Kubernetes admission control for signed images
- Establish OpenSSF Scorecard thresholds for all dependencies
- Implement SBOM attestation and verification in deployment pipelines
- Create and test supply chain incident response plans

**Long-term (6-12 months):**
- Achieve SLSA Level 4 for the most critical artifacts
- Implement reproducible builds for critical components
- Deploy in-toto for supply chain verification
- Implement VEX for vulnerability management
- Begin post-quantum code signing migration planning
- Establish organizational supply chain security governance

### For Open-Source Maintainers

1. **Enable 2FA on all accounts** (npm, PyPI, GitHub, etc.) using hardware security keys.

2. **Enable npm provenance signing** for all published packages.

3. **Implement branch protection** and require reviews for all changes.

4. **Sign all Git commits and tags** with GPG or SSH keys.

5. **Publish SBOMs** alongside all releases.

6. **Establish a security policy** (SECURITY.md) with a vulnerability disclosure process.

7. **Limit the number of maintainers** with publish access, and audit publish access regularly.

8. **Use scoped registries** if publishing internal packages.

9. **Monitor for typosquatting** and dependency confusion targeting your packages.

10. **Apply for OpenSSF funding** if your project is critical infrastructure.

---

## Emerging Threats and Detection Challenges

### AI-Generated Attacks

The emergence of large language models has fundamentally changed the landscape of supply chain attacks. While AI provides powerful defensive capabilities (malicious code detection, dependency risk scoring), it also enables new attack vectors that were previously impractical:

**Automated package generation at scale.** An attacker can now prompt an LLM to generate dozens or hundreds of malicious packages, each targeting a different dependency pattern, with realistic README files, documentation, and test suites. This makes typosquatting and dependency confusion attacks scalable in ways that were not previously possible.

**Contextual social engineering.** The XZ Utils backdoor demonstrated that patient social engineering is effective, but it required a human attacker to build trust over years. LLMs can now generate convincing contributor profiles, pull requests, and communications that are tailored to specific open-source communities, making social engineering attacks faster and more scalable.

**Obfuscation and evasion.** LLMs can generate malware that uses novel obfuscation techniques, environmental keying, and anti-debugging measures that evade existing static analysis tools. The arms race between AI-generated attacks and AI-powered detection is just beginning.

**Detection countermeasures.** Organizations should implement AI-powered malicious package detection alongside traditional static and dynamic analysis. However, AI detection tools should complement, not replace, human review—the XZ Utils backdoor demonstrates that even the most sophisticated attacks can be detected by attentive humans.

### The Double Supply Chain Problem

The 3CX supply chain attack (2023) introduced a new concept: the double supply chain compromise, where attacking one supply chain enables the compromise of another. In the 3CX case, the attacker first compromised Trading Technologies (a financial platform), then used the compromised Trading Technologies software to compromise a 3CX employee's personal computer, which enabled the compromise of 3CX's build system.

This creates a recursion problem: even if an organization secures its own supply chain, it is only as secure as the supply chains of its dependencies, which are only as secure as the supply chains of their dependencies, and so on. This recursive dependency creates an effectively infinite attack surface.

**Mitigation strategies for recursive supply chain risk:**
1. Map your full dependency tree (using SBOMs) to understand the depth and breadth of your supply chain
2. Implement SLSA provenance verification at every level of the dependency tree
3. Use private registries with curated allowlists to limit the dependency surface
4. Monitor upstream dependencies for security incidents
5. Implement circuit breakers that automatically disable dependencies when vulnerabilities are disclosed

### Environmental Keying and Detection Evasion

Modern supply chain malware increasingly uses environmental keying—activating only under specific conditions—to evade detection in sandboxed environments:

- **CI/CD detection**: Checking for `CI=true`, `GITHUB_ACTIONS=true`, or `JENKINS_URL` environment variables
- **Production detection**: Checking for production-specific environment variables, hostnames, or IP address ranges
- **Time bombs**: Activating after a specific date or after a delay (hours, days, or months) from installation
- **Geo-fencing**: Activating only when running in specific countries or regions
- **Target profiling**: Activating only when specific software is installed (e.g., only targeting Copay wallets, as in the event-stream attack)

The fundamental challenge is that detection tools operate in sandboxed environments that may not match the target environment. A package that is benign in a researcher's sandbox may be malicious in a production CI/CD pipeline. This is why hermetic, deterministic analysis (reproducing the exact installation conditions) is critical for effective detection.

### Supply Chain as a Service

The commoditization of supply chain attacks is a growing trend. Access brokers now sell pre-positioned access to software build pipelines, maintainer accounts, and signing keys. Organizations tracked as "supply chain access brokers" offer:
- Compromised maintainer accounts for popular npm, PyPI, and Maven packages
- Pre-positioned access to CI/CD pipelines with deployment credentials
- Stolen code signing certificates for various platforms
- Zero-day vulnerabilities in build tools and package managers

This commoditization lowers the barrier to entry for supply chain attacks, making them accessible to a wider range of threat actors who may lack the technical sophistication of APT29 or the DPRK's Lazarus Group.

### For the Ecosystem

1. **Adopt SLSA Level 2+ provenance** as the default for all package registries. npm provenance signing is a good model.

2. **Implement dependency confusion prevention** by default (scoped registries, correct priority).

3. **Require 2FA for package publishing** on all major registries.

4. **Implement package name verification** to prevent typosquatting and namespace confusion.

5. **Invest in reproducible builds infrastructure** for major package ecosystems.

6. **Fund critical open-source infrastructure** (package registries, signing infrastructure, vulnerability databases).

7. **Develop and deploy AI-powered malicious package detection** to complement static analysis.

8. **Standardize SBOM formats** (CycloneDX or SPDX) across ecosystems.

9. **Implement transparency logs** (Rekor) for all package signing operations.

10. **Establish industry-wide supply chain incident response** protocols and information sharing.

### Key Metrics for Supply Chain Security Programs

Organizations should track the following metrics to measure the effectiveness of their supply chain security programs:

**Coverage Metrics:**
- Percentage of projects with lock files and hash verification enabled
- Percentage of CI/CD pipelines with vulnerability scanning
- Percentage of releases with SLSA provenance
- Percentage of releases with SBOMs
- Percentage of releases with signed artifacts

**Risk Metrics:**
- Mean time to detect (MTTD) a supply chain vulnerability
- Mean time to remediate (MTTR) a supply chain vulnerability
- Number of known vulnerabilities in production dependencies (by severity)
- Number of unpatched critical vulnerabilities
- Transitive dependency depth (average and maximum)

**Compliance Metrics:**
- Percentage of projects compliant with SLSA Level 2+
- Percentage of projects with SBOMs that meet NTIA minimum elements
- Percentage of projects passing OpenSSF Scorecard at threshold (e.g., 7/10)
- Number of regulatory findings related to supply chain security

### The Cost of Inaction

History provides stark data on the cost of supply chain insecurity:

- **SolarWinds (2020)**: $100M+ in direct costs to SolarWinds; billions in total economic impact across 18,000+ affected organizations.
- **Log4Shell (2021)**: Estimated $4.5B in total remediation costs across the Java ecosystem. Many organizations took 30+ days to identify all affected systems.
- **3CX (2023)**: 600,000+ customers potentially affected through a double supply chain compromise.
- **XZ Utils (2024)**: Would have compromised SSH globally if not detected by Andres Freund's observant investigation.
- **Codecov (2021)**: Hundreds of CI/CD environments exposed, requiring complete secret rotation across affected organizations.

The cost of implementing the defenses recommended in this report (SLSA provenance, SBOM generation, vulnerability scanning, code signing) is a fraction of the cost of a single supply chain incident. A typical organization can implement SLSA Level 2 provenance for less than $50,000 in engineering time, while the cost of a SolarWinds-class incident exceeds $100M.

---

## Conclusion

The software supply chain is under attack from sophisticated threat actors who exploit the inherent trust model of open-source ecosystems. The attacks documented in this track—from SolarWinds to XZ Utils—demonstrate that supply chain compromise is not a theoretical risk but an active, ongoing threat.

The defense technologies are maturing. SLSA provides a framework for progressive improvement. Sigstore provides keyless signing at scale. SBOM standards provide the inventory needed for vulnerability management. In-toto provides supply chain verification. GUAC provides graph-based analysis of supply chain relationships.

But technology alone is not enough. The XZ Utils backdoor was detected not by any automated tool but by a curious developer who noticed that SSH was taking 500ms longer than expected. The colors.js protestware was not prevented by any technical control but by npm's administrative intervention. The Codecov bash uploader compromise was not detected by any security scanner but by a monitoring system that noticed unusual outbound connections.

Supply chain security requires a combination of technical controls, human vigilance, organizational policy, and ecosystem cooperation. The recommendations in this report provide a roadmap for progressive improvement, from the immediate (enable 2FA, pin dependencies, scan for vulnerabilities) to the aspirational (SLSA Level 4, reproducible builds, zero-trust supply chain).

The future of supply chain security will be shaped by three converging forces: regulatory mandates that make SBOMs and provenance a legal requirement, technological innovation that makes supply chain verification scalable and automated, and evolving threat actors who will continue to find new ways to exploit the trust relationships that underpin modern software development.

The most important lesson from the case studies in this track is that supply chain security is not a problem that can be solved once and forgotten. It is a continuous process of identifying risks, implementing controls, verifying their effectiveness, and adapting to new threats. The XZ Utils backdoor was not a failure of any single control—it was a failure of the entire ecosystem's vigilance. The lesson is clear: we must be as persistent and patient in our defense as attackers are in their offense.

The time to act is now. Every day without SLSA provenance, without SBOM generation, without vulnerability scanning, and without code signing is a day that your organization is exposed to supply chain attacks. The question is not whether you will be targeted, but whether you will be prepared when you are.

## References

1. SLSA Specification v1.0. "Supply-chain Levels for Software Artifacts." https://slsa.dev/spec/v1.0/
2. OpenSSF. "Securing the Software Supply Chain." https://openssf.org/
3. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
4. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
5. CISA. "Software Bill of Materials (SBOM)." https://www.cisa.gov/sbom
6. Sonatype. "2023 State of the Software Supply Chain Report." https://www.sonatype.com/state-of-the-software-supply-chain
7. Mandiant. "Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims." December 2020. https://msrc.microsoft.com/blog/2020/12/analyzing-the-solarwinds-compromise/
8. Microsoft. "Analyzing the SolarWinds Compromise." December 2020. https://msrc.microsoft.com/blog/2020/12/analyzing-the-solarwinds-compromise/
9. CISA. "Emergency Directive 21-01: SolarWinds Orion Compromise." December 2020. https://www.cisa.gov/news-events/cybersecurity-advisories
10. Freund, A. "Backdoor in xz/liblzma." OpenWall oss-security mailing list, March 2024. https://www.openwall.com/lists/oss-security/2024/03/29/4
11. Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
12. Ladisa, P., et al. "SoK: Taxonomy of Supply Chain Attacks." IEEE Symposium on Security and Privacy, 2023. https://doi.org/10.1109/SP46215.2023.10179316
13. NVD. "CVE-2024-3094: XZ Utils Backdoor." https://nvd.nist.gov/vuln/detail/CVE-2024-3094
14. NVD. "CVE-2021-44228: Log4Shell." https://nvd.nist.gov/vuln/detail/CVE-2021-44228
15. NVD. "CVE-2018-16492: event-stream Compromise." https://nvd.nist.gov/vuln/detail/CVE-2018-16492
16. CycloneDX Specification v1.5. OWASP. https://cyclonedx.org/
17. SPDX Specification v2.3. Linux Foundation. https://spdx.github.io/spdx-spec/
18. Sigstore. "Cosign: Container Signing." https://docs.sigstore.dev/cosign/signing/signing_with_containers/
19. OpenSSF. "Scorecard: Automated Security Assessment." https://github.com/ossf/scorecard
20. OpenSSF. "S2C2F: Supply-chain Secure Supply Chain Consumption Framework." https://github.com/ossf/s2c2f
21. GUAC. "Graph for Understanding Artifact Composition." https://github.com/guacsec/guac
22. EU Cyber Resilience Act. https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
23. Zimerman, T. "It's a (Supply Chain) War." USENIX Security Symposium, 2023.
24. Ohm, M., et al. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks." DIMVA, 2020.