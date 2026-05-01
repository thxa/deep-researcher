# Supply Chain Security Cheat Sheet

## SBOM Generation Commands

### Syft (CycloneDX / SPDX)
```bash
# Container image → CycloneDX JSON
syft my-registry/my-app:latest -o cyclonedx-json > sbom.cdx.json

# Container image → SPDX JSON
syft my-registry/my-app:latest -o spdx-json > sbom.spdx.json

# Directory → CycloneDX JSON
syft dir:./my-project -o cyclonedx-json > sbom.cdx.json

# Lockfile → CycloneDX JSON
syft package-lock.json -o cyclonedx-json > sbom.cdx.json
```

### Trivy
```bash
# Container image → SPDX JSON
trivy image --format spdx-json my-registry/my-app:latest > sbom.spdx.json

# Container image → CycloneDX JSON
trivy image --format cyclonedx-json my-registry/my-app:latest > sbom.cdx.json

# Filesystem → SPDX JSON
trivy fs --format spdx-json ./my-project > sbom.spdx.json

# Scan existing SBOM for vulnerabilities
trivy sbom sbom.cdx.json
```

### cyclonedx-cli
```bash
# Validate SBOM
cyclonedx-cli validate --input-format json --input-version v1_5 sbom.cdx.json

# Convert formats
cyclonedx-cli convert --input-format json --output-format xml sbom.cdx.json > sbom.cdx.xml

# Merge SBOMs
cyclonedx-cli merge --input-format json sbom1.json sbom2.json > merged.json
```

### npm
```bash
# Generate SBOM from package-lock.json
npm sbom --sbom-type cyclonedx --sbom-format json > sbom.cdx.json
```

---

## SLSA Level Requirements

| Level | Source Req | Build Req | Provenance Req | Key Controls |
|-------|-----------|-----------|----------------|--------------|
| **0** | None | None | None | No guarantees |
| **1** | Version controlled | Provenance exists | Self-reported | Provenance metadata generated |
| **2** | Verified history | Hosted build | Signed provenance | Provenance signed by build platform |
| **3** | Two-person review (source) | Non-falsifiable | Verified provenance | Hardened builder, branch protection |
| **4** | Two-person review | Hermetic + reproducible | Maximum trust | Independent verification, reproducibility |

### SLSA GitHub Actions Generator
```yaml
# SLSA Level 3 provenance for generic artifacts
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
  with:
    base64-subjects: ${{ steps.build.outputs.digest }}
    upload-assets: true

# SLSA Level 3 provenance for container images
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
  with:
    image: my-registry/my-app
    digest: ${{ steps.build.outputs.digest }}
```

### SLSA Verification
```bash
# Verify artifact provenance
slsa-verifier verify-artifact my-app \
  --provenance-path my-app.intoto.jsonl \
  --source-uri github.com/myorg/my-repo

# Verify container image provenance
slsa-verifier verify-image my-registry/my-app:v1.2.3 \
  --source-uri github.com/myorg/my-repo
```

---

## Code Signing Commands

### Sigstore / Cosign
```bash
# Keyless signing (uses OIDC identity)
cosign sign registry.example.com/my-app:v1.2.3

# Key-based signing
cosign sign --key cosign.key registry.example.com/my-app:v1.2.3

# Verify keyless signature
cosign verify registry.example.com/my-app:v1.2.3 \
  --certificate-identity=my-ci@mycompany.iam.gserviceaccount.com \
  --certificate-oidc-issuer=https://accounts.google.com

# Verify key-based signature
cosign verify --key cosign.pub registry.example.com/my-app:v1.2.3

# Sign and attach SBOM
cosign attest --predicate sbom.cdx.json --type cyclonedx registry.example.com/my-app:v1.2.3

# Verify SBOM attestation
cosign verify-attestation --type cyclonedx registry.example.com/my-app:v1.2.3

# Attach SBOM to image
cosign attach sbom --sbom sbom.cdx.json registry.example.com/my-app:v1.2.3
```

### npm Provenance
```bash
# Publish with provenance
npm publish --provenance --access public

# Verify provenance
npm view my-package --json | jq '.provenance'

# Audit signatures
npm audit signatures
```

### Git Signing
```bash
# Configure Git signing
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global user.signingkey ABCDEF1234567890

# Sign a commit
git commit -S -m "Signed commit"

# Sign a tag
git tag -s v1.0.0 -m "Signed release v1.0.0"

# Verify a commit
git verify-commit HEAD

# Verify a tag
git verify-tag v1.0.0
```

### Windows Authenticode
```bash
# Sign a Windows executable
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f code-signing.pfx application.exe

# Verify a signature
signtool verify /pa /all application.exe
```

---

## Vulnerability Scanning Tools

### Trivy
```bash
# Scan container image
trivy image --severity HIGH,CRITICAL my-registry/my-app:latest

# Scan filesystem
trivy fs --severity HIGH,CRITICAL ./my-project

# Scan SBOM
trivy sbom sbom.cdx.json

# Scan Kubernetes cluster
trivy k8s --namespace production all

# Output as JSON
trivy image --format json my-registry/my-app:latest > vulns.json

# Output as SARIF (for GitHub)
trivy image --format sarif my-registry/my-app:latest > results.sarif
```

### Grype
```bash
# Scan container image
grype my-registry/my-app:latest

# Scan SBOM
grype sbom:./sbom.cdx.json

# Scan directory
grype dir:./my-project

# Only show fixed vulnerabilities
grype --only-fixed my-registry/my-app:latest

# Fail on severity
grype --fail-on high my-registry/my-app:latest
```

### OSV Scanner
```bash
# Scan directory
osv-scanner scan ./my-project

# Scan lockfile
osv-scanner scan --lockfile=requirements.txt

# Scan Docker image
osv-scanner scan --docker my-registry/my-app:latest

# Output as JSON
osv-scanner scan --format json ./my-project
```

### npm audit
```bash
# Run audit
npm audit

# Fix vulnerabilities
npm audit fix

# Fix including breaking changes
npm audit fix --force

# Audit production dependencies only
npm audit --production

# Specific severity
npm audit --audit-level=high
```

### pip-audit
```bash
# Audit installed packages
pip-audit

# Audit requirements file
pip-audit -r requirements.txt

# Output as JSON
pip-audit --format json

# Use specific vulnerability database
pip-audit --vulnerability-db https://osv.dev
```

### cargo audit
```bash
# Audit Cargo.lock
cargo audit

# Output as JSON
cargo audit --json

# Ignore specific vulnerabilities (with documented reason)
cargo audit --ignore RUSTSEC-2021-0139
```

---

## Dependency Confusion Indicators

### High-Risk .npmrc Configurations
```ini
# VULNERABLE: Public registry checked first
registry=https://registry.npmjs.org/
# Internal packages will fall back to public registry if not found

# VULNERABLE: Extra index checked for all packages
registry=https://registry.npmjs.org/
//npm.company.com/:_authToken=${NPM_AUTH_TOKEN}
# No scoping means public registry is primary
```

### Secure .npmrc Configurations
```ini
# SECURE: Scoped registry for internal packages
@company:registry=https://npm.company.com/
//npm.company.com/:_authToken=${NPM_AUTH_TOKEN}
registry=https://registry.npmjs.org/
```

### Detection Script
```bash
# Check for dependency confusion risks
# Look for internal package names in public registries
for pkg in $(grep -oP '(?<=from ")[@a-zA-Z0-9/-]+(?=")' src/**/*.js | sort -u); do
  # Check if package exists on public npm
  if npm view "$pkg" version &>/dev/null; then
    if [[ ! "$pkg" =~ ^@ ]]; then
      echo "RISK: Internal package '$pkg' also exists on public npm"
    fi
  fi
done
```

### pip.conf Secure Configuration
```ini
# SECURE: Internal index as primary
[global]
index-url = https://internal.pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# Most secure: hash verification
require-hashes = true
```

---

## Malicious Package Indicators

### npm Red Flags
- `postinstall`, `preinstall`, or `install` scripts in `package.json`
- Hex-encoded strings: `Buffer.from('...', 'hex')`
- Base64-encoded commands: `atob('...')` or `Buffer.from('...', 'base64')`
- `process.env` access in install scripts
- DNS resolution: `require('dns')` in install scripts
- `child_process` in install scripts
- Network connections to unfamiliar domains
- Single maintainer with no other packages
- Package created within last 24-48 hours
- Name similar to a popular package (typosquatting)

### PyPI Red Flags
- Arbitrary code execution in `setup.py`
- `os.system()`, `subprocess.call()`, or `subprocess.Popen()` in `setup.py`
- Network connections in `setup.py`
- Environment variable access in `setup.py`
- Package name differs from legitimate package by one character
- `setup_requires` with unfamiliar packages
- Obfuscated code in `setup.py`
- Package created recently with high version number

### Rust Red Flags
- `build.rs` that executes arbitrary commands
- Procedural macros that access the network
- Dependencies on unknown crates in `Cargo.toml`
- Similar name to a popular crate

### Detection Commands
```bash
# Check npm package for install scripts
npm view <package> scripts

# Inspect npm package contents
npm pack <package> && tar -xzf <package>-<version>.tgz && cat package/package.json

# Check install scripts before installing
npm install --ignore-scripts --dry-run <package>

# Extract and review PyPI package
pip download <package> && unzip <package>-<version>.whl

# Check Python package for malicious setup.py
pip download <package> && tar -xzf <package>-<version>.tar.gz && cat <package>-<version>/setup.py
```

---

## Key Supply Chain CVEs Reference

| CVE | Year | Component | Type | CVSS | Description |
|-----|------|-----------|------|------|-------------|
| CVE-2020-10148 | 2020 | SolarWinds Orion | Auth bypass | 8.8 | SolarWinds Orion API authentication bypass |
| CVE-2021-44228 | 2021 | Log4j | RCE | 10.0 | Log4Shell: JNDI lookup RCE in Apache Log4j |
| CVE-2021-45105 | 2021 | Log4j | DoS | 7.5 | Log4j recursive lookup DoS |
| CVE-2022-0778 | 2022 | OpenSSL | DoS | 7.5 | Infinite loop in certificate verification |
| CVE-2022-1388 | 2022 | F5 BIG-IP | RCE | 9.8 | Unauthenticated RCE in iControl REST |
| CVE-2022-26134 | 2022 | Confluence | RCE | 10.0 | OGNL injection in Confluence Server |
| CVE-2022-29217 | 2022 | PyJWT | Auth bypass | 7.4 | Key confusion attack in PyJWT |
| CVE-2023-4966 | 2023 | NetScaler | Info disclosure | 7.5 | Citrix Bleed: session hijacking |
| CVE-2024-3094 | 2024 | XZ Utils | Backdoor | 10.0 | Backdoor in liblzma targeting sshd |
| CVE-2021-42550 | 2021 | Logback | RCE | 9.8 | JNDI lookup in Logback |
| CVE-2021-42340 | 2021 | Apache Tomcat | Info leak | 7.5 | HTTP/2 header handling |
| CVE-2023-44487 | 2023 | HTTP/2 | DoS | 7.5 | HTTP/2 Rapid Reset attack |
| CVE-2018-16492 | 2018 | event-stream | Cryptostealer | 9.8 | Malicious dependency in event-stream |

---

## Quick Reference: Dependency Pinning

```bash
# npm: Use npm ci (strict lock file adherence)
npm ci --ignore-scripts

# Python: Use --require-hashes
pip install --require-hashes -r requirements.txt

# Rust: Use --locked
cargo install --locked

# Go: Use go.sum verification
go mod verify

# Ruby: Use frozen string mode
bundle install --deployment --frozen

# Docker: Pin image digest
FROM my-registry/my-app@sha256:abc123def456...
```

## Quick Reference: Registry Security

```ini
# .npmrc - Secure configuration
@company:registry=https://npm.company.com/
//npm.company.com/:_authToken=${NPM_AUTH_TOKEN}
registry=https://registry.npmjs.org/
ignore-scripts=false

# pip.conf - Secure configuration
[global]
index-url = https://internal.pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# Maven settings.xml - Secure configuration
<settings>
  <mirrors>
    <mirror>
      <id>company-mirror</id>
      <mirrorOf>*</mirrorOf>
      <url>https://maven.company.com/repository/public/</url>
    </mirror>
  </mirrors>
</settings>
```

## Quick Reference: CI/CD Security Checklist

- [ ] Use `pull_request_target` carefully (never checkout PR code with write permissions)
- [ ] Set `permissions: contents: read` as default
- [ ] Pin action versions to SHA (not tags)
- [ ] Use environment variables instead of template expressions in `run:` blocks
- [ ] Never use self-hosted runners for public repositories
- [ ] Use OIDC for cloud authentication (not static secrets)
- [ ] Enable branch protection and required reviews
- [ ] Sign commits and tags with GPG/SSH
- [ ] Use `npm ci` not `npm install` in CI
- [ ] Generate SBOMs for all releases
- [ ] Scan for vulnerabilities at every build
- [ ] Verify artifact signatures at deployment

## References

1. SLSA Specification v1.0. "Supply-chain Levels for Software Artifacts." https://slsa.dev/spec/v1.0/
2. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
3. OpenSSF. "Scorecard: Automated Security Assessment." https://github.com/ossf/scorecard
4. Anchore. "Syft: SBOM Generator." https://github.com/anchore/syft
5. Aqua Security. "Trivy: Vulnerability Scanner." https://aquasecurity.github.io/trivy/
6. Sigstore. "Cosign: Container Signing." https://docs.sigstore.dev/cosign/signing/signing_with_containers/
7. CycloneDX Specification v1.5. OWASP. https://cyclonedx.org/specification/
8. SPDX Specification v2.3. Linux Foundation. https://spdx.github.io/spdx-spec/
9. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
10. SLSA GitHub Generator. https://github.com/slsa-framework/slsa-github-generator
11. Birsan, A. "Dependency Confusion." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
12. CISA. "Defending Against Software Supply Chain Attacks." https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_0.pdf
13. GitHub. "Security hardening for GitHub Actions." https://docs.github.com/en/actions/security-guides
14. NVD. "CVE-2024-3094: XZ Utils Backdoor." https://nvd.nist.gov/vuln/detail/CVE-2024-3094
15. NVD. "CVE-2021-44228: Log4Shell." https://nvd.nist.gov/vuln/detail/CVE-2021-44228