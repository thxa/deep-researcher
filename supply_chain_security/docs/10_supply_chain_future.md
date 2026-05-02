# The Future of Supply Chain Security

## Emerging Technologies and Evolving Threats

The software supply chain security landscape is evolving rapidly. New technologies, regulatory requirements, and threat actors are reshaping how we think about, implement, and enforce supply chain security. This chapter examines the technologies, regulations, and trends that will define supply chain security in the coming years.

---

## AI-Assisted Dependency Analysis

### Large Language Models for Dependency Review

Large language models (LLMs) are being applied to supply chain security in several novel ways. While AI introduces new attack vectors (discussed later), it also offers powerful defensive capabilities:

**Malicious code detection:**

LLMs can analyze package source code for malicious patterns that traditional static analysis tools miss:

```python
# AI-powered dependency review tool
import openai
import json

def analyze_package_with_llm(package_source_code: str) -> dict:
    """Use an LLM to analyze a package for malicious patterns."""
    
    prompt = f"""
    Analyze the following package source code for malicious patterns.
    Look for:
    1. Environment variable exfiltration (process.env, os.environ)
    2. Network connections to suspicious domains
    3. Obfuscated code (hex encoding, base64, eval)
    4. File system operations on sensitive paths (/etc/passwd, ~/.ssh)
    5. Command execution (child_process, subprocess, os.system)
    6. Anti-debugging or anti-analysis techniques
    7. Cryptocurrency mining patterns
    8. DNS exfiltration patterns
    9. Conditional execution based on environment (environmental keying)
    
    Package source code:
    ```
    {package_source_code}
    ```
    
    Return a JSON object with:
    - "risk_level": "critical" | "high" | "medium" | "low" | "safe"
    - "findings": list of specific concerns
    - "recommendation": "block" | "review" | "allow"
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )
    
    return json.loads(response.choices[0].message.content)
```

**Dependency risk scoring:**

LLMs can evaluate the risk of adding a new dependency by analyzing multiple signals:

```python
def score_dependency_risk(package_name: str, version: str) -> dict:
    """
    Score a dependency for risk using multiple signals:
    - Maintainer history and activity
    - Package age and download count
    - Known vulnerabilities
    - Code quality and complexity
    - License compatibility
    - Transitive dependency count
    """
    
    # Gather package metadata
    metadata = fetch_package_metadata(package_name, version)
    
    # Gather maintainer information
    maintainer_info = fetch_maintainer_info(metadata['maintainers'])
    
    # Analyze transitive dependencies
    dep_tree = analyze_dependency_tree(package_name, version)
    
    # Score each factor
    risk_scores = {
        'maintainer_risk': score_maintainer_risk(maintainer_info),
        'package_risk': score_package_risk(metadata),
        'dependency_risk': score_dependency_risk(dep_tree),
        'vulnerability_risk': score_vulnerability_risk(package_name, version),
        'license_risk': score_license_risk(metadata['license']),
    }
    
    return {
        'overall_risk': aggregate_scores(risk_scores),
        'risk_breakdown': risk_scores,
        'recommendation': generate_recommendation(risk_scores),
    }
```

### Automated Supply Chain Attack Detection

AI models are being trained to detect supply chain attacks in real-time:

- **Anomaly detection**: Models that learn the baseline behavior of package registries and flag anomalies (e.g., a maintainer publishing 50 packages in 24 hours)
- **Typo detection**: ML models that identify packages with names suspiciously similar to popular packages
- **Behavioral analysis**: Models that analyze package behavior during installation and flag suspicious activity
- **Code similarity**: Models that detect packages with code suspiciously similar to known malware but with minor modifications

### AI-Generated Supply Chain Attacks (New Threat)

LLMs also enable new attack vectors:

- **Automated typo squatting**: LLMs can generate plausible misspellings of popular package names at scale
- **Malicious code generation**: LLMs can generate obfuscated, environment-aware malicious code that evades static analysis
- **Social engineering at scale**: LLMs can generate convincing contributor profiles, pull requests, and communications to build trust in open-source communities
- **Automated vulnerability discovery**: LLMs can analyze dependency trees for previously unknown vulnerability patterns

```python
# An attacker could use an LLM to generate malicious snippets:
# WARNING: This is for educational purposes only.

# Hypothetical prompt an attacker might use:
"""
Generate a Node.js postinstall script that:
1. Checks if the environment is a CI/CD system (GITHUB_ACTIONS, JENKINS_URL, etc.)
2. If so, exfiltrates CI environment variables via DNS
3. Otherwise, silently exits
4. Uses obfuscation to avoid detection by static analysis tools
5. Includes a time bomb that activates after 30 days
"""
```

**Defensive recommendations:**
- Never trust LLM-generated code without review
- Use AI analysis tools to complement (not replace) human review
- Monitor package registries for AI-generated suspicious patterns
- Implement rate limiting and behavioral analysis on package registries

---

## WebAssembly Supply Chain

### The WebAssembly Threat Model

WebAssembly (Wasm) is increasingly used for plugin systems, edge computing, and browser-based applications. The WebAssembly supply chain introduces new security considerations:

**WebAssembly-specific risks:**

1. **Black-box binaries**: WebAssembly modules are binary format, making source code review difficult
2. **Sandbox escape**: WebAssembly's sandboxing is not perfect; side-channel attacks and Spectre-class vulnerabilities are concerns
3. **Unauthorized imports**: WebAssembly modules can import functions from the host environment, potentially accessing privileged operations
4. **Memory isolation**: WebAssembly's linear memory model can be exploited for data leakage
5. **Supply chain through Wasm registries**: Wasm package registries (wapm.io, wasmpkg.dev) are subject to the same dependency confusion and typo squatting risks as other registries

**Wasm supply chain security:**

```toml
# wapm.toml - WebAssembly package manifest
[package]
name = "my-wasm-plugin"
version = "1.0.0"
description = "A WebAssembly plugin"

[dependencies]
# Pin exact versions with integrity hashes
"wasm-image-processor" = "1.2.3"
"wasm-json-parser" = "0.5.0"

[package.metadata.wasm]
# Specify required capabilities (least privilege)
allowed_exports = ["process_image"]
allowed_imports = ["wasi_snapshot_preview1.fd_write"]

# Verify module integrity
[[module]]
name = "my-wasm-plugin"
source = "target/my-wasm-plugin.wasm"
integrity = "sha256-abc123def456..."
```

**WebAssembly capability-based security:**

```rust
// Rust WebAssembly module with explicit capabilities
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn process_image(data: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Only process image data, no network or filesystem access
    let img = image::load_from_memory(data)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let processed = img.resize(256, 256, image::FilterType::Lanczos3);
    
    let mut output = Vec::new();
    processed.write_to(&mut output, image::ImageFormat::Png)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    Ok(output)
}
```

---

## SBOM as Legal Requirement

### US Executive Order 14028

Executive Order 14028, "Improving the Nation's Cybersecurity," was signed on May 12, 2021. Section 4, "Enhancing Software Supply Chain Security," mandates:

> "The procurement of software shall include... a Software Bill of Materials (SBOM) for each product directly or by reference..."

**Key requirements:**
1. Software sold to the federal government must include an SBOM
2. SBOMs must follow the NTIA minimum elements format
3. Agencies must use SBOMs for vulnerability management
4. Software providers must notify agencies of known vulnerabilities

**NTIA minimum elements for SBOM:**

| Element | Description |
|---------|-------------|
| Author | Name of the entity that created the SBOM |
| Timestamp | Date and time of SBOM creation |
| Component Name | Full name of each component |
| Component Version | Version string of each component |
| Dependency Relationship | How components relate to each other |
| Author of Component | Name of the entity that authored each component |
| Unique Identifiers | PURL, CPE, or other identifier for each component |

**CISA SBOM implementation:**

CISA has published guidance on SBOM implementation, including:
- **SBOM types**: "Design" SBOM (created during development), "Build" SBOM (created during build), "Deployed" SBOM (created during deployment), "Runtime" SBOM (captured at runtime)
- **SBOM delivery**: SBOMs must be machine-readable (SPDX or CycloneDX format)
- **SBOM quality**: SBOMs must be accurate, complete, and generated automatically

### EU Cyber Resilience Act

The EU Cyber Resilience Act (CRA), adopted in 2024, introduces mandatory cybersecurity requirements for products with digital elements sold in the EU:

**Key SBOM-related requirements:**
1. Manufacturers must produce an SBOM for all products with digital elements
2. SBOMs must be maintained and updated throughout the product lifecycle
3. SBOMs must be provided to national authorities upon request
4. Vulnerabilities in components listed in the SBOM must be reported and remediated

**CRA timeline:**
- 2024: Regulation adopted
- 2026: Requirements begin applying to manufacturers
- 2027: Full enforcement with penalties for non-compliance

### Other Regulatory Requirements

- **FDA Pre-market Guidance (2023)**: Requires SBOMs for medical devices
- **NIST SP 800-218 (Secure Software Development Framework)**: Requires SBOMs for federal software
- **DoD Software Bill of Materials (2023)**: Requires SBOMs for all DoD software
- **Japan's Software Supply Chain Guidelines (2023)**: Recommends SBOMs for critical infrastructure
- **UK Product Security and Telecommunications Infrastructure Act (2022)**: Requires vulnerability management for consumer products

---

## Package Ecosystem Verification

### npm Package Verification

npm has implemented several verification mechanisms:

**npm provenance (2023):**
```bash
# Publish with provenance
npm publish --provenance

# Verify provenance
npm view my-package --json | jq '.provenance'

# Audit signatures
npm audit signatures
```

**npm package signing:**
- npm signs all packages published with provenance using Sigstore
- Signatures can be verified with `npm audit signatures`
- The signature links the package to a specific source repository commit and GitHub Actions workflow

### PyPI Package Verification

PyPI has implemented several verification mechanisms:

**Trusted publishers (2023):**
```yaml
# .github/workflows/publish.yml
name: Publish to PyPI
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for trusted publishing
    environment: pypi
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: python -m build
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        # No API token needed - uses OIDC for authentication
```

**PyPI digest verification:**
```bash
# Verify digests when installing
pip install --require-hashes -r requirements.txt
```

### RubyGems Package Verification

RubyGems has implemented signing and verification:

```bash
# Sign a gem
gem sign my-gem-1.0.0.gem

# Verify a gem signature
gem verify my-gem-1.0.0.gem
```

---

## Reproducible Builds: Going Mainstream

### Current State of Reproducible Builds

The Reproducible Builds project has made significant progress:

- **Debian**: 95%+ of packages in Debian are reproducible
- **Arch Linux**: Reproducible builds are a core distribution goal
- **NixOS**: All packages in NixOS are built reproducibly
- **Guix**: GNU Guix provides bit-for-bit reproducible builds
- **F-Droid**: Android app repository with reproducible builds

**Tools supporting reproducible builds:**

```bash
# diffoscope: Compare two build outputs
diffoscope build1/my-app build2/my-app

# reprotest: Test a package for reproducibility
reprotest 'make build' 'build/my-app'

# SOURCE_DATE_EPOCH: Set deterministic timestamps
export SOURCE_DATE_EPOCH=1700000000
make build

# strip-nondeterminism: Remove non-deterministic metadata from files
strip-nondeterminism build/
```

### Reproducible Builds as a Supply Chain Control

As reproducible builds become mainstream, they will become a critical supply chain security control:

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Builder A   │     │   Builder B   │     │   Builder C   │
│(Organization) │     │  (Independent │     │  (Verifier)   │
│               │     │   Auditor)    │     │               │
│ Build from    │     │ Build from    │     │ Build from    │
│ source        │     │ source        │     │ source        │
└───────┬───────┘     └───────┬───────┘     └───────┬───────┘
        │                     │                     │
        │ sha256:abc...      │ sha256:abc...      │ sha256:abc...
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                     ┌────────▼────────┐
                     │   Consensus:     │
                     │   Reproducible ✓ │
                     └─────────────────┘
```

If Builder A, B, and C all produce the same hash from the same source, we have high confidence that the build is reproducible and has not been tampered with.

---

## Supply Chain Transparency Laws

### Current and Emerging Legislation

| Region | Legislation | Status | SBOM Requirement |
|--------|-----------|--------|-------------------|
| United States | Executive Order 14028 | Active (2021) | Required for federal software |
| European Union | Cyber Resilience Act | Adopted (2024) | Required for digital products |
| European Union | NIS2 Directive | Active (2023) | Risk management including supply chain |
| United Kingdom | PSTI Act | Active (2022) | Vulnerability management |
| Japan | Software Supply Chain Guidelines | Active (2023) | Recommended |
| Australia | Critical Infrastructure Act | Active (2023) | Required for critical infrastructure |

### Practical Compliance

Organizations must prepare for these regulatory requirements:

```yaml
# SBOM compliance checklist
compliance:
  us_executive_order_14028:
    - "Generate SBOMs for all products (SPDX or CycloneDX)"
    - "Provide SBOMs to federal customers upon request"
    - "Implement vulnerability disclosure process"
    - "Report vulnerabilities within 72 hours of confirmation"
    - "Use NIST SSDF for secure development"
  
  eu_cyber_resilience_act:
    - "Generate SBOMs for all products with digital elements"
    - "Maintain SBOMs throughout product lifecycle"
    - "Provide SBOMs to national authorities upon request"
    - "Remediate vulnerabilities within defined timelines"
    - "Report actively exploited vulnerabilities within 24 hours"
  
  fda_premarket_guidance:
    - "Generate SBOMs for all medical device software"
    - "Maintain SBOMs throughout device lifecycle"
    - "Implement vulnerability management program"
    - "Report vulnerabilities to FDA"
```

---

## Quantum-Resistant Code Signing

### The Quantum Threat to Code Signing

Current code signing relies on RSA and ECDSA algorithms, which are vulnerable to quantum computing attacks. A sufficiently powerful quantum computer running Shor's algorithm could break RSA-2048 and ECDSA-P256, compromising all code signing based on these algorithms.

**Timeline estimates:**
- NIST estimates that quantum computers capable of breaking RSA-2048 could exist by 2030-2040
- The "harvest now, decrypt later" attack means encrypted or signed data today could be compromised in the future
- Code signing certificates have validity periods of 1-3 years, but the artifacts they sign may be trusted for decades

### NIST Post-Quantum Cryptography Standards

In 2024, NIST finalized three post-quantum cryptography standards:

| Algorithm | Type | Use Case | Key Size |
|-----------|------|----------|----------|
| ML-DSA (CRYSTALS-Dilithium) | Digital Signature | Code signing, authentication | 2,560 bytes (public key) |
| ML-KEM (CRYSTALS-Kyber) | Key Encapsulation | Key exchange, encryption | 1,568 bytes (public key) |
| SLH-DSA (SPHINCS+) | Digital Signature | Code signing (hash-based) | 64 bytes (public key) |

**Migrating code signing to post-quantum algorithms:**

```bash
# Generate a post-quantum signing key with OpenSSL 3.5+
openssl genpkey -algorithm ML-DSA-65 -out pq-signing-key.pem

# Sign an artifact with post-quantum algorithm
openssl cms -sign \
  -in artifact.tar.gz \
  -signer pq-signing-key.pem \
  -outform DER \
  -out artifact.tar.gz.pq-sig

# Verify a post-quantum signature
openssl cms -verify \
  -in artifact.tar.gz.pq-sig \
  -inform DER \
  -content artifact.tar.gz \
  -CAfile pq-ca-bundle.crt

# Use post-quantum algorithm with cosign
cosign sign --key pq-signing-key.pem registry.example.com/my-app:v1.2.3
```

**Hybrid signing approach:**

During the transition period, organizations should use hybrid signing (both classical and post-quantum):

```bash
# Sign with both RSA and ML-DSA
openssl cms -sign \
  -in artifact.tar.gz \
  -signer rsa-signing-key.pem \
  -signer pq-signing-key.pem \
  -outform DER \
  -out artifact.tar.gz.hybrid-sig
```

This ensures that the signature remains valid even if one algorithm is compromised.

---

## In-Toto Specification Adoption

### In-Toto Framework

In-toto is a framework for ensuring the integrity of the software supply chain by verifying that each step in the chain was performed as intended and by authorized personnel:

```
┌───────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐
│  Define    │    │  Execute  │    │  Record   │    │  Verify   │
│  Layout    │───▶│  Steps    │───▶│  Links    │───▶│  Layout   │
│            │    │            │    │           │    │           │
│  Who does  │    │  Each step │    │  Signed   │    │  Verify   │
│  what,     │    │  produces  │    │  metadata │    │  metadata │
│  in what   │    │  a link    │    │  for each │    │  against  │
│  order     │    │  metadata  │    │  step     │    │  layout   │
└───────────┘    └───────────┘    └───────────┘    └───────────┘
```

**In-toto layout example:**

```python
# in-toto layout (supply chain definition)
{
    "_type": "layout",
    "keys": {
        "maintainer_key": {
            "keyid": "abc123...",
            "keytype": "rsa",
            "keyval": {
                "public": "-----BEGIN PUBLIC KEY-----\n..."
            }
        },
        "reviewer_key": {
            "keyid": "def456...",
            "keytype": "rsa",
            "keyval": {
                "public": "-----BEGIN PUBLIC KEY-----\n..."
            }
        }
    },
    "steps": [
        {
            "name": "clone",
            "threshold": 1,
            "expected_command": ["git", "clone"],
            "expected_materials": [],
            "expected_products": [
                ["CREATE", "src/"]
            ],
            "pubkeys": ["abc123..."]
        },
        {
            "name": "review",
            "threshold": 1,
            "expected_command": ["git", "review"],
            "expected_materials": [
                ["MATCH", "src/*", "WITH", "products", "FROM", "clone"]
            ],
            "expected_products": [
                ["MODIFY", "review-status.txt"]
            ],
            "pubkeys": ["def456..."]
        },
        {
            "name": "build",
            "threshold": 1,
            "expected_command": ["make", "build"],
            "expected_materials": [
                ["MATCH", "src/*", "WITH", "products", "FROM", "clone"]
            ],
            "expected_products": [
                ["CREATE", "build/my-app"]
            ],
            "pubkeys": ["abc123..."]
        }
    ],
    "inspect": [
        {
            "name": "verify-no-vulnerabilities",
            "expected_materials": [],
            "expected_products": [],
            "run": ["trivy", "fs", "--severity", "HIGH,CRITICAL", "--exit-code", "1", "."]
        }
    ]
}
```

**In-toto in practice:**

```bash
# Record a supply chain step
in-toto-record start \
  --step-name clone \
  --key maintainer \
  --materials src/

in-toto-record stop \
  --step-name clone \
  --key maintainer \
  --products src/

# Verify the complete supply chain
in-toto-verify \
  --layout supply-chain.layout \
  --layout-keys maintainer.pub \
  --link-dir .
```

### In-Toto + SLSA Integration

In-toto and SLSA are complementary: SLSA defines what guarantees a supply chain should provide, and in-toto provides a mechanism to verify those guarantees:

```
SLSA Level    In-Toto Control
─────────    ──────────────────────────────────────────
Level 1      Layout defines expected steps and records link metadata for each step
Level 2      Layout requires signed link metadata from each step
Level 3      Layout requires specific functionaries (builders) for each step
Level 4      Layout requires threshold verification (multi-party signing) for each step
```

---

## GUAC (Graph for Understanding Artifact Composition)

### What is GUAC?

GUAC is an OpenSSF incubation project that aggregates software supply chain metadata into a queryable graph database. It ingests SBOMs, SLSA provenance, VEX documents, vulnerability data, and other supply chain metadata to create a comprehensive view of the supply chain:

```bash
# Install GUAC
go install github.com/guacsec/guac/cmd/guaccollect@latest
go install github.com/guacsec/guac/cmd/guacone@latest

# Ingest SBOMs
guacone collect files sbom1.cdx.json sbom2.cdx.json

# Ingest SLSA provenance
guacone collect files provenance1.intoto.jsonl

# Ingest VEX documents
guacone collect files vex1.json

# Ingest vulnerability data
guacone collect csaf

# Query GUAC
guacone query vulnerability CVE-2021-44228

# Query: What packages are affected by Log4Shell?
# Result: All packages that contain log4j-core < 2.17.1

# Query: What is the blast radius of a vulnerability in package X?
guacone query blastradius pkg:npm/lodash@4.17.20
```

**GUAC architecture:**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   SBOMs     │    │   SLSA      │    │    VEX      │    │  OSV/NVD   │
│ (SPDX, CDX) │    │ Provenance  │    │  Documents  │    │ Vuln Data  │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       └──────────────────┴──────────────────┴──────────────────┘
                                  │
                         ┌────────▼────────┐
                         │  GUAC Ingestion  │
                         │  (Parse & Index)  │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │  GUAC Graph DB    │
                         │  (Neo4j/ArangoDB) │
                         └────────┬─────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
       ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
       │  Query API  │    │  Policy     │    │  Dashboard  │
       │  (GraphQL)  │    │  Engine     │    │  (Visual)    │
       └─────────────┘    └─────────────┘    └─────────────┘
```

**GUAC use cases:**

1. **Blast radius analysis**: When a vulnerability is disclosed, GUAC can immediately identify all affected packages and their dependents
2. **Policy enforcement**: GUAC can enforce supply chain policies (e.g., "no package with a CRITICAL vulnerability in production")
3. **Compliance verification**: GUAC can verify that all packages have valid SBOMs, provenance, and VEX documents
4. **Supply chain visualization**: GUAC provides a visual representation of the supply chain graph

---

## OpenSSF Initiatives

### S2C2F (Supply-chain Secure Supply Chain Consumption Framework)

S2C2F is an OpenSSF project (originally from Microsoft) that provides a framework for securely consuming open-source software:

**S2C2F practices:**

| Level | Practice | Description |
|-------|----------|-------------|
| 1 | Inventory | Maintain an inventory of all OSS dependencies |
| 1 | Scan | Scan all OSS dependencies for known vulnerabilities |
| 1 | Update | Keep all OSS dependencies up to date |
| 2 | Verify | Verify the integrity of all OSS dependencies (hash/signature verification) |
| 2 | Secure Build | Build OSS dependencies in a secure, isolated environment |
| 2 | Provenance | Require SLSA provenance for all OSS dependencies |
| 3 | Review | Review the source code of all OSS dependencies |
| 3 | Test | Test all OSS dependencies for vulnerabilities |
| 3 | SBOM | Generate and maintain SBOMs for all OSS dependencies |

### Alpha-Omega

Alpha-Omega is an OpenSSF project that aims to improve the security of critical open-source projects:

- **Alpha**: Provides security expertise and tooling to the most critical open-source projects (Linux kernel, OpenSSL, Python, etc.)
- **Omega**: Applies automated security analysis at scale across the top 10,000 open-source projects

**Alpha-Omega activities:**
- Funding security audits of critical projects
- Providing security engineers to critical projects
- Implementing fuzzing and static analysis for critical projects
- Improving SLSA levels for critical projects

### OpenSSF Security Scorecard

The OpenSSF Scorecard continues to evolve with new checks and improved scoring:

- **New checks**: Binary artifacts in source, CI/CD security, SLSA level verification
- **Improved scoring**: Weighted scoring that reflects actual risk
- **Integration**: Scorecard is integrated into Dependabot, Renovate, and other update tools
- **Policy enforcement**: Scorecard can be used as a policy gate in CI/CD

```yaml
# .github/workflows/scorecard.yml
name: Scorecard
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  scorecard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2
        with:
          results_file: scorecard-results.json
          results_format: json
          publish_results: true
          repo_token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Check score
        run: |
          SCORE=$(jq '.score' scorecard-results.json)
          if [ "$SCORE" -lt "7" ]; then
            echo "Score $SCORE is below threshold of 7"
            exit 1
          fi
```

---

## Emerging Threat Models

### AI-Generated Malicious Packages

As LLMs become more accessible, attackers are using them to generate malicious packages at scale:

- **Automated package generation**: LLMs can generate hundreds of packages with obfuscated malicious code, each targeting a different dependency pattern
- **Realistic metadata**: LLMs can generate convincing README files, documentation, and test suites for malicious packages
- **Contextual targeting**: LLMs can analyze a target organization's public codebase and generate packages specifically designed to be attractive to that organization

### Deep供应链 (Deep Supply Chain) Attacks

Supply chain attacks that target multiple layers simultaneously:

- **Triple supply chain compromise**: Compromise a build tool, a CI/CD system, and a package registry simultaneously
- **Compromise of security tooling**: Targeting the security tools themselves (vulnerability scanners, SBOM generators, signing infrastructure)
- **Trust infrastructure compromise**: Targeting CA infrastructure, transparency logs, or key management systems

### Nation-State Supply Chain Operations

Nation-state actors are increasingly targeting the supply chain as a strategic vector:

- **Pre-positioned access**: Compromising supply chains to gain persistent access to target organizations
- **Selective activation**: Using environmental keying to activate only in specific target environments
- **Cross-organization compromise**: Using a single supply chain compromise to access multiple target organizations (as seen in SolarWinds)

---

## The Road Ahead

### Immediate (2024-2025)

1. **SBOM adoption**: Regulatory mandates will drive universal SBOM adoption
2. **SLSA Level 2 adoption**: Major ecosystems will implement SLSA Level 2 provenance by default
3. **Sigstore adoption**: Keyless signing will become the standard for container and package signing
4. **Private registries**: Organizations will standardize on private registries with dependency control
5. **AI-powered scanning**: AI-assisted vulnerability and malicious package detection will become mainstream

### Medium-Term (2025-2027)

1. **Reproducible builds**: Will become a standard practice for critical infrastructure
2. **Post-quantum migration**: Organizations will begin hybrid classical/post-quantum code signing
3. **Supply chain transparency**: Laws will require public disclosure of supply chain practices
4. **In-toto adoption**: Will become a standard framework for supply chain verification
5. **GUAC maturity**: Supply chain graph databases will enable real-time policy enforcement

### Long-Term (2027-2030)

1. **Quantum-resistant code signing**: Post-quantum signatures will be standard
2. **Zero-trust supply chain**: Cryptographic verification at every step will be the norm
3. **AI-driven supply chain security**: AI will proactively identify and mitigate supply chain risks
4. **Global regulatory harmonization**: International standards for supply chain security will emerge
5. **Supply chain as infrastructure**: Supply chain security will be treated as critical infrastructure

---

## References

- NIST. "Post-Quantum Cryptography Standards." https://csrc.nist.gov/projects/post-quantum-cryptography
- CISA. "Software Bill of Materials." https://www.cisa.gov/sbom
- EU. "Cyber Resilience Act." https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- OpenSSF. "GUAC: Graph for Understanding Artifact Composition." https://github.com/guacsec/guac
- OpenSSF. "S2C2F: Supply-chain Secure Supply Chain Consumption Framework." https://github.com/ossf/s2c2f
- OpenSSF. "Alpha-Omega." https://github.com/ossf/alpha-omega
- Reproducible Builds. https://reproducible-builds.org/
- In-Toto. "Software Supply Chain Security Framework." https://in-toto.io/
- ML-DSA (CRYSTALS-Dilithium). https://csrc.nist.gov/projects/post-quantum-cryptography