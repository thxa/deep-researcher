# Supply Chain Threat Landscape

## The Modern Software Supply Chain

The software supply chain encompasses every component, tool, process, and human actor involved in developing, building, distributing, and maintaining software. From the moment a developer imports a dependency to the point an end user executes a binary, every link in this chain represents an attack surface that adversaries can—and do—exploit. The 2023 Sonatype State of the Software Supply Chain report documented over 245,000 malicious packages published across public registries, a 130% year-over-year increase. Open-source dependencies now constitute 70–90% of the code in modern applications, making supply chain compromise not merely a theoretical concern but an existential risk.

The supply chain threat landscape has evolved from opportunistic attacks on individual packages to sophisticated, multi-stage campaigns orchestrated by nation-state actors. Understanding this landscape requires a rigorous taxonomy of attack vectors, an appreciation for the ecosystem scale, and a clear mapping of adversary capabilities and motivations.

---

## Taxonomy of Supply Chain Attacks

### 1. Dependency Confusion

Dependency confusion exploits the way package managers resolve dependencies across multiple registries. When an organization uses both public registries (npm, PyPI) and private registries (internal Artifactory, Verdaccio) with the same package name, a malicious actor can publish a higher-versioned package to the public registry. The package manager, configured to prefer the highest version, pulls the malicious public package rather than the intended private one.

Alex Birsan's 2021 research demonstrated this against Apple, Microsoft, PayPal, Shopify, Netflix, and others, earning over $130,000 in bug bounties. The attack requires no interaction with the target's infrastructure—it merely requires knowledge of internal package names, often discoverable through JavaScript bundles, Python stack traces, or leaked configuration files.

**Key characteristics:**
- Requires no compromise of any target system
- Exploits package manager default resolution behavior
- Affects npm, PyPI, NuGet, RubyGems, and Maven
- Works even when private registries are correctly configured if priority isn't set

### 2. Typosquatting

Typosquatting preys on developer mistakes during package installation. An attacker publishes a package with a name closely resembling a popular package, hoping a developer will mistype the install command. The 2017 `crossenv` incident is a canonical example: an attacker published packages named similarly to 42 popular npm packages, each containing a postinstall script that exfiltrated environment variables to a remote server.

**Variants:**
- **Character substitution**: `pythan-requests` for `python-requests`
- **Transposition**: `pytohn-requests`
- **Omission**: `pythonrequest`
- **Prefix/suffix abuse**: `python3-dateutil` (the real package is `python-dateutil`)
- **Homoglyph attacks**: using Unicode characters that look identical to ASCII ( Cyrillic 'а' for Latin 'a')

### 3. Maintainer Compromise

Direct compromise of a package maintainer's account gives an attacker the ability to publish malicious versions of legitimate, trusted packages. This vector is particularly devastating because it undermines the trust model entirely—the package looks legitimate, comes from the legitimate publisher, and is signed with legitimate credentials.

**Attack surfaces for maintainer accounts:**
- Stolen credentials (phishing, credential stuffing, breached databases)
- Compromised email accounts (account recovery, npm email verification)
- Compromised CI/CD tokens with publish permissions
- Social engineering of maintainers
- Tyranny of the blank page: maintainers abandoning packages, allowing attacker takeover via npm's dispute process

The 2022 `ua-parser-js` compromise exemplified this: the maintainer's npm account was compromised (reportedly via stolen email credentials), and the attacker published versions 0.7.29, 0.8.0, and 0.8.1 with cryptominer payloads.

### 4. Build System Compromise

Compromising the build system that produces release artifacts allows an attacker to inject malicious code into the build output without modifying the source code at all. This is the attack vector employed in the SolarWinds SUNBURST incident—perhaps the most consequential supply chain attack in history.

This vector is especially pernicious because:
- Source code audit cannot detect the backdoor
- Code review of the repository shows nothing malicious
- The compromise lives entirely in the build pipeline
- Builds that are not reproducible cannot be verified against the source

**Build system attack surfaces:**
- Compromised build servers (on-premise or cloud)
- Malicious build plugins or extensions
- Tampered compiler toolchains (Ken Thompson's "Reflections on Trusting Trust")
- Compromised CI/CD service provider infrastructure
- Poisoned pipeline execution through PR manipulation

### 5. Compromised CI/CD Pipelines

CI/CD systems represent a convergence point where source code, secrets, and infrastructure credentials intersect. Compromising a CI/CD pipeline grants access to deployment credentials, signing keys, production environment variables, and the ability to inject malicious code into any artifact the pipeline produces.

The Codecov bash uploader compromise (April 2021) demonstrated how a modest modification to a CI script—the addition of a single line that exfiltrated CI environment variables—could compromise thousands of downstream users. The attacker modified Codecov's `bashuploader.sh` to send environment variables (including credentials, API keys, and tokens) to an attacker-controlled server.

**CI/CD-specific attack vectors:**
- Script injection via pull request payloads (GitHub Actions `github.event` injection)
- Self-hosted runner abuse (persistent compromise of runner infrastructure)
- Poisoned pipeline execution (PPE) via malicious workflow files in PRs
- Secrets exposure in build logs
- Compromised CI/CD plugin or action
- Tampered base images or build containers

### 6. Stolen Signing Keys

Code signing keys are the foundation of trust in the software supply chain. When these keys are compromised, an attacker can sign malicious software with the same level of trust as the legitimate publisher. Multiple high-profile incidents have demonstrated this:

- **NVIDIA (2022)**: The Lapsus$ group leaked NVIDIA code signing certificates, which were subsequently used to sign malware. The certificates were valid and would have been trusted by Windows Driver Signature Enforcement.
- **Samsung (2022)**: Lapsus$ also leaked Samsung's code signing certificates.
- **Lenovo (2019)**: Lenovo's certificate authority key was compromised, allowing attackers to sign malicious software as if it came from Lenovo.
- **D-Link (2020)**: D-Link's code signing certificate was leaked on a public server.

The fundamental problem is that X.509 code signing certificates, once compromised, cannot be meaningfully revoked in practice because most verification systems do not perform real-time certificate revocation checks.

### 7. Malicious Forks and Dependency Substitution

An attacker may fork a legitimate project, introduce subtle backdoors, and then attempt to replace the original dependency through social engineering, typosquatting, or direct substitution. The XZ Utils backdoor (CVE-2024-3094, 2024) represents the most sophisticated known instance: the attacker, operating under the pseudonym "Jia Tan," gradually gained maintainer status on the legitimate xz project over approximately two years before injecting a backdoor into the build system that targeted OpenSSH's systemd integration.

This vector also includes:
- **Brandjacking**: Creating packages that appear to be official (e.g., `facebook` instead of `fb`)
- **Depend-on-proxy attacks**: Publishing a benign package that later adds malicious dependencies
- **Isomorphic packaging**: Repackaging legitimate packages with subtle modifications

---

## Historical Scope and Scale

The frequency and severity of supply chain attacks have grown dramatically:

| Year | Notable Incident | Impact |
|------|-----------------|--------|
| 2016 | left-pad removal | Broke millions of builds |
| 2017 | crossenv typosquatting | 42 malicious npm packages |
| 2018 | event-stream compromise | Cryptostealer in npm package with 2M weekly downloads |
| 2019 | Lenovo CA key compromise | Stolen code signing key |
| 2020 | SolarWinds SUNBURST | 18,000+ organizations compromised |
| 2021 | Codecov bash uploader | Thousands of CI environments exposed |
| 2021 | PHP git server compromise | PHP source code tampered with |
| 2021 | Dependency confusion research | Apple, Microsoft, PayPal compromised |
| 2021 | Log4Shell (CVE-2021-44228) | Millions of Java applications vulnerable |
| 2022 | ua-parser-js compromise | Cryptominer injected via npm |
| 2022 | colors.js/faker.js protestware | Intentional breaking of dependent projects |
| 2022 | NVIDIA certificate leak | Valid signing certificates used by Lapsus$ |
| 2023 | 3CX supply chain attack | Trojaned desktop app via compromised trading platform |
| 2024 | XZ Utils backdoor (CVE-2024-3094) | Backdoor targeting sshd via xz build system |

The economic impact is staggering. SolarWinds alone cost the company over $100M in direct response costs, and the total economic impact across affected organizations is estimated in the billions. The 2023 State of the Software Supply Chain report found that supply chain attacks targeting open-source projects increased by 742% between 2019 and 2022.

---

## Threat Actors

### Nation-State Actors

#### APT29 (Cozy Bear) — SolarWinds SUNBURST

APT29, attributed to Russia's Foreign Intelligence Service (SVR), executed the SolarWinds compromise beginning in at least 2019. The attackers gained access to SolarWinds' build environment and injected the SUNBURST backdoor into the Orion network monitoring platform's update mechanism. The backdoor was digitally signed with SolarWinds' legitimate certificate and distributed to approximately 18,000 organizations through the normal update channel.

**Operational characteristics:**
- Months-long supply chain preparation
- Highly targeted second-stage exploitation
- Excellent operational security (custom malware, DNS tunneling via avsvmcloud.com)
- Selective activation targeting specific organizational profiles
- CVE-2020-10148 (SolarWinds Orion API authentication bypass)

#### DPRK (Lazarus Group)

North Korea's Lazarus Group has conducted multiple supply chain-adjacent campaigns:
- **2020**: Cryptocurrency supply chain attacks via compromised npm packages tied to cryptocurrency wallets
- **2022**: Trojaned DeFi applications through compromised developer accounts
- **2023**: Social engineering of maintainers to gain package access for cryptocurrency.wallet packages
- Multiple campaigns targeting npm and PyPI packages related to cryptocurrency trading

The DPRK's focus on financially motivated supply chain attacks (primarily targeting cryptocurrency) represents a distinct operational model from the espionage-focused Russian and Chinese APTs.

#### APT41 (Double Dragon)

Chinese APT41 has conducted supply chain compromises targeting various sectors, using compromised software updates as an attack vector. Their operations span both espionage and financially motivated campaigns, making them a versatile threat actor in the supply chain space.

### Criminal Actors

#### Access Brokers

Access brokers specialize in compromising organizations and selling that access to other threat actors. In the supply chain context, they may:
- Compromise maintainer accounts and sell publishing access
- Steal CI/CD secrets and pipeline access
- Leak code signing certificates for use by ransomware operators
- Provide initial access through compromised dependency ecosystems

The Lapsus$ group's 2022 campaigns (NVIDIA, Samsung, Okta) demonstrated how access brokers could obtain and weaponize code signing certificates, creating cascading supply chain risks.

#### Ransomware Operators

Ransomware operators increasingly leverage supply chain compromise as a force multiplier. Rather than attacking individual organizations, compromising a supply chain allows simultaneous deployment across all downstream consumers. The Kaseya VSA attack (CVE-2021-30116, 2021), while technically a vulnerability rather than a supply chain attack, demonstrated this principle: approximately 1,500 businesses were encrypted through a single compromise.

---

## The Packaged Ecosystem

### npm (Node.js)

npm is the world's largest software registry with over 2.1 million packages and approximately 50 billion weekly downloads. Its size makes it both the most valuable and most attacked ecosystem.

**Key statistics:**
- 2.1M+ packages (2023)
- ~50B weekly downloads
- 17M+ developers
- Average JavaScript project has 683 dependencies (transitive)
- 10% of npm packages have at least one known vulnerability

**Attack surface characteristics:**
- `postinstall` and `preinstall` scripts execute arbitrary code on installation
- Namespace is global and unvalidated (no verified publisher requirement)
- Dependency trees are deep (683 transitive dependencies on average)
- Package name similarity is easy to exploit
- `.npmrc` configuration allows complex registry priority that can be misconfigured
- npm scope packages (`@scope/name`) have verified ownership but do not prevent confusion with unscoped names

### PyPI (Python)

PyPI hosts over 500,000 projects and serves billions of downloads monthly. The Python packaging ecosystem has several unique attack surfaces:

**Key statistics:**
- 500K+ projects (2023)
- ~10B monthly downloads
- setup.py execution on installation (arbitrary code execution)
- Multiple package index sources (pip.conf) enable dependency confusion
- Name normalization (underscores vs hyphens) creates typosquatting opportunities

**Attack surface characteristics:**
- `setup.py` is a Python script executed during installation—full code execution
- `requirements.txt` doesn't support integrity hashes by default
- `pip install --extra-index-url` enables dependency confusion
- Package name normalization (`python-dateutil` ≡ `python_dateutil`) creates namespace ambiguity
- Entry point scripts can modify `PATH` or execute arbitrary code

### crates.io (Rust)

crates.io is the Rust package registry. While Rust's type system provides some safety guarantees, the packaging layer remains vulnerable:

**Key statistics:**
- 140K+ crates (2023)
- ~30B total downloads
- Average Rust project has 100+ transitive dependencies

**Attack surface characteristics:**
- `build.rs` scripts execute arbitrary code during compilation
- Procedural macros execute arbitrary code during compilation
- Cargo features can conditionally include vulnerable code paths
- Cargo lock files support integrity verification but it's optional

### Maven Central (Java)

Maven Central, now the Central Portal, hosts over 12 million artifacts and serves billions of downloads monthly. The Java ecosystem's dependency management has unique characteristics:

**Key statistics:**
- 12M+ artifacts
- ~100B annual downloads
- Log4Shell (CVE-2021-44228) demonstrated the devastating impact of dependency vulnerabilities

**Attack surface characteristics:**
- Group ID + Artifact ID namespace is hierarchical but not verified
- POM files can reference external repositories
- Classpath manipulation through transitive dependencies
- JNDI lookups and other runtime resolution mechanisms (Log4Shell)
- Gradle's `resolutionStrategy` and Maven's `dependencyManagement` are often misconfigured

### RubyGems (Ruby)

RubyGems hosts over 180,000 gems. The ecosystem has seen significant supply chain incidents:

**Key statistics:**
- 180K+ gems
- ~6B monthly downloads
- Bundler provides lock file support with checksum verification

**Attack surface characteristics:**
- Gem `post_install_message` and `extensions` can execute code
- `gem install` without bundler doesn't verify checksums
- Ruby's `require` can load remote code via HTTPS URLs
- Multiple gem sources in Gemfile enable dependency confusion

### Go Modules

Go modules use a decentralized model without a central registry, which provides different trade-offs:

**Key statistics:**
- 300K+ modules on proxy.golang.org
- ~1.5B daily proxy requests
- Checksum database (sum.golang.org) provides integrity verification

**Attack surface characteristics:**
- Module paths are URLs, enabling typosquatting on domain names
- `go.mod` doesn't support integrity hashes natively (checksums are in `go.sum`)
- `go get -u` can update to malicious versions if the module path is compromised
- The Go checksum database provides strong integrity guarantees but can be bypassed with `GONOSUMCHECK` or `GOFLAGS=-insecure`
- `replace` directives in go.mod can redirect dependencies

---

## Ecosystem-Wide Vulnerability Statistics

The scale of the attack surface isdifficult to overstate:

- **Transitive dependency depth**: The average JavaScript project depends on 683 transitive dependencies. A Python project averages 100+. A Rust project averages 100+. Each transitive dependency is an attack surface.
- **Maintainer trust surface**: The average JavaScript project trusts approximately 100 distinct maintainers through its dependency tree. Each maintainer account is a potential entry point.
- **Update velocity**: npm packages publish approximately 2 million new versions per month. The velocity of updates makes manual review of all changes impossible.
- **Vulnerability prevalence**: According to Snyk's 2023 State of Open Source Security report, 84% of codebases contain at least one known open-source vulnerability. The average time to fix a vulnerability in a direct dependency is 36 days; for transitive dependencies, it's 255 days.

---

## Attack Vector Mapping to Ecosystem

| Vector | npm | PyPI | crates.io | Maven | RubyGems | Go |
|--------|-----|------|-----------|-------|----------|-----|
| Dependency confusion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Typosquatting | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Install script abuse | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| Maintainer compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Build system compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Star-jacking | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Namespace confusion | ✓ | ✓ | ✗ | ✗ | ✓ | ✗ |
| Lockfile manipulation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Emerging Threats

### AI-Assisted Attack Generation

Large language models enable attackers to generate convincing malicious packages at scale. An attacker can prompt an LLM to generate dozens of packages with obfuscated install scripts, each targeting a different dependency pattern. The bar for creating sophisticated supply chain attacks has lowered dramatically.

### Supply Chain as a Service

Criminal organizations now offer supply chain compromise as an outsourced capability. Organizations like DRB Control and groups tracked as "supply chain access brokers" sell pre-positioned access to software build pipelines, maintainer accounts, and signing keys.

### Dependency-on-Dependency Attacks

Rather than attacking a directly-used package, an attacker targets a deep transitive dependency that is relied upon by many popular packages. This amplifies the blast radius dramatically. The event-stream compromise (2018) targeted an indirect dependency used by many popular frameworks.

### Cryptographic Infrastructure Attacks

Attacks targeting the cryptographic infrastructure of package registries—key servers, certificate authorities, and transparency logs—represent a systemic risk. A successful attack on npm's signing infrastructure or PyPI's package signing key could compromise the entire ecosystem's trust model.

---

## The Trust Problem

At its core, the supply chain threat landscape exposes a fundamental trust problem. Modern software development requires trusting:
- Every direct dependency maintainer
- Every transitive dependency maintainer
- The registry infrastructure (npm, PyPI, etc.)
- The build system that produced the artifact
- The CDN that delivered the package
- The DNS infrastructure that resolved the registry hostname
- The TLS certificate infrastructure that authenticated the connection
- The code signing infrastructure that verified the artifact

Each trust relationship is a potential attack surface. The challenge of supply chain security is reducing these trust relationships to a manageable, verifiable set while maintaining the velocity that modern development requires. The SLSA framework, SBOM standards, and code signing initiatives discussed in subsequent chapters represent our best current approaches to this fundamental problem.

---

## References

1. Sonatype. "2023 State of the Software Supply Chain Report." https://www.sonatype.com/state-of-the-software-supply-chain
2. Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
3. Synopsys. "2023 Open Source Security and Risk Analysis (OSSRA)." https://www.synopsys.com/software-integrity/resources/analyst-reports/open-source-security-risk-analysis.html
4. CISA. "Software Bill of Materials (SBOM)." https://www.cisa.gov/sbom
5. Google. "Supply Chain Attacks." SLSA Threat Model. https://slsa.dev/spec/v1.0/threats
6. Ladisa, P., et al. "SoK: Taxonomy of Supply Chain Attacks." IEEE Symposium on Security and Privacy, 2023. https://doi.org/10.1109/SP46215.2023.10179316
7. Zimerman, T. "It's a (Supply Chain) War." USENIX Security Symposium, 2023.
8. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
9. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
10. Ohm, M., et al. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks." DIMVA, 2020.
11. npm Documentation. "npm Registry Statistics." https://www.npmjs.com/
12. PyPI Documentation. "Python Package Index." https://pypi.org/
13. Freund, A. "Backdoor in xz/liblzma." OpenWall oss-security mailing list, March 2024. https://www.openwall.com/lists/oss-security/2024/03/29/4
14. Mandiant. "Highly Evasive Attacker Leverages SolarWinds Supply Chain." December 2020. https://msrc.microsoft.com/blog/2020/12/analyzing-the-solarwinds-compromise/
15. Microsoft. "Analyzing the SolarWinds Compromise." December 2020. https://msrc.microsoft.com/blog/2020/12/analyzing-the-solarwinds-compromise/
16. NVD. "CVE-2024-3094: XZ Utils Backdoor." https://nvd.nist.gov/vuln/detail/CVE-2024-3094
17. NVD. "CVE-2020-10148: SolarWinds Orion API Authentication Bypass." https://nvd.nist.gov/vuln/detail/CVE-2020-10148
18. NVD. "CVE-2021-44228: Log4Shell." https://nvd.nist.gov/vuln/detail/CVE-2021-44228
19. CISA. "Defending Against Software Supply Chain Attacks." https://www.cisa.gov/sbom