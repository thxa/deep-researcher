# Supply Chain Hardening

## A Practical Guide to Securing Your Software Supply Chain

Securing a software supply chain is not a single action but a continuous process of identifying risks, implementing controls, and verifying their effectiveness. This chapter provides a comprehensive, actionable guide to hardening your organization's supply chain against the attack vectors documented in previous chapters.

---

## SLSA Adoption Roadmap

### Phase 1: SLSA Level 1 (Months 1-2)

**Goal:** Generate and publish provenance for all release artifacts.

```yaml
# Step 1.1: Generate provenance in CI/CD
name: Build with Provenance
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build artifact
        run: |
          make build
          sha256sum build/my-app > build/my-app.sha256
      
      - name: Create provenance
        run: |
          cat > provenance.json << 'EOF'
          {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "my-app", "digest": {"sha256": "$(cat build/my-app.sha256 | cut -d' ' -f1)"}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
              "builder": {"id": "https://github.com/myorg/my-repo/.github/workflows/release.yml"},
              "buildType": "https://github.com/actions/workflow",
              "invocation": {
                "configSource": {
                  "uri": "https://github.com/myorg/my-repo/blob/main/.github/workflows/release.yml",
                  "digest": {"sha1": "${{ github.sha }}"}
                }
              }
            }
          }
          EOF
```

**Step 1.2: Publish provenance alongside artifacts.**

```bash
# Upload provenance with the release
gh release upload v1.2.3 provenance.json
```

### Phase 2: SLSA Level 2 (Months 3-4)

**Goal:** Move to a hosted build platform and generate signed provenance.

```yaml
# Step 2.1: Use SLSA GitHub Generator
name: Release with SLSA Provenance
on:
  release:
    types: [published]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      attestations: write
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Build
        id: build
        run: |
          make build
          echo "digest=$(sha256sum build/my-app | cut -d' ' -f1)" >> $GITHUB_OUTPUT
      
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
        with:
          base64-subjects: ${{ steps.build.outputs.digest }}
          upload-assets: true
```

### Phase 3: SLSA Level 3 (Months 5-8)

**Goal:** Implement non-falsifiable provenance and harden the build pipeline.

```yaml
# Step 3.1: Hardened release workflow
name: Hardened Release (SLSA Level 3)
on:
  release:
    types: [published]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      attestations: write
    
    # CRITICAL: Only run on release events, not on PRs
    steps:
      # CRITICAL: Checkout the release tag, not PR code
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.release.tag_name }}
      
      - name: Build
        id: build
        run: |
          make build
          echo "digest=$(sha256sum build/my-app | cut -d' ' -f1)" >> $GITHUB_OUTPUT
      
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
        with:
          base64-subjects: ${{ steps.build.outputs.digest }}
```

**Step 3.2: Implement branch protection.**

```bash
# Enable branch protection via GitHub API
gh api repos/myorg/my-repo/branches/main/protection \
  --method PUT \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci/test", "security/scan"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 2
  },
  "restrictions": null,
  "required_signatures": true
}
EOF
```

### Phase 4: SLSA Level 4 (Months 9-12+)

**Goal:** Implement two-party review, hermetic builds, and reproducible build verification.

```yaml
# Step 4.1: Two-party review enforcement
# CODEOWNERS file
* @myorg/security-team @myorg/senior-developers

/.github/ @myorg/security-team @myorg/infra-team
/Dockerfile @myorg/security-team @myorg/infra-team
/src/ @myorg/senior-developers

# Step 4.2: Reproducible build verification
name: Reproducible Build Verification
on:
  release:
    types: [published]

jobs:
  build-1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - run: sha256sum build/my-app > build1.sha256
      - uses: actions/upload-artifact@v4
        with:
          name: build1
          path: build/my-app

  build-2:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - run: sha256sum build/my-app > build2.sha256
      - uses: actions/upload-artifact@v4
        with:
          name: build2
          path: build/my-app

  verify:
    needs: [build-1, build-2]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build1
          path: build1/
      - uses: actions/download-artifact@v4
        with:
          name: build2
          path: build2/
      - name: Verify reproducibility
        run: |
          if diff <(sha256sum build1/my-app) <(sha256sum build2/my-app); then
            echo "Builds are reproducible"
          else
            echo "Builds are NOT reproducible"
            diffoscope build1/my-app build2/my-app || true
            exit 1
          fi
```

---

## Dependency Pinning

### Lock Files

Lock files pin exact versions and integrity hashes for all dependencies:

```bash
# npm: Use npm ci (not npm install) in CI
npm ci --frozen-lockfile

# Python: Use pip with hash verification
pip install --require-hashes -r requirements.txt

# Rust: Use Cargo.lock (committed to version control)
cargo install --locked

# Go: Use go.sum for integrity verification
go mod verify

# Ruby: Use Bundler with deploy mode
bundle install --deployment --frozen

# Maven: Use maven-lockfile or dependabot version pins
mvn dependency:lock
```

**npm lock file integrity:**

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
      "integrity": "sha512-ve3upC1xf_arPS7mD7a2O3D4j/KnqN/9f3rX4P3P4P4P4P4P4P44=...",
      "requires": {}
    }
  }
}
```

### Hash Verification

```bash
# npm: Verify integrity hashes
npm cache verify

# Python: Generate hashes for requirements
pip-compile --generate-hashes requirements.in > requirements.txt

# Python: Install with hash verification
pip install --require-hashes -r requirements.txt

# Go: Verify module checksums
go mod verify
GONOSUMCHECK="" GOFLAGS="" go mod verify

# Rust: Verify Cargo.lock integrity
cargo generate-lockfile
cargo fetch --locked

# Docker: Verify image digest
docker pull my-registry/my-app@sha256:abc123def456

# Docker: Verify with cosign
cosign verify my-registry/my-app:v1.2.3
```

**Python requirements.txt with hashes:**

```text
django==4.2.1 \
    --hash=sha256:28acbd18affe8fac815daf103aab9581a3949300a636ca486e8e15b7c0b05e7a \
    --hash=sha256:c6e93b2319c49a0e5b6b6ebe43e25a5a0885d4a8f5b7fc9f0a5a8a5
django-rest-framework==3.14.0 \
    --hash=sha256:3b784e2b4a5e7c91e3c8e6e6d1e6e6d1e6e6d1e6e6d1e6e6d1e6e6d1e6e6d1e
```

### Dependency Pinning Policies

```yaml
# .github/renovate.json - Dependency pinning policy
{
  "extends": ["config:base"],
  "packageRules": [
    {
      "matchPackagePatterns": ["*"],
      "rangeStrategy": "pin",
      "semanticCommitType": "deps",
      "semanticCommitScope": "pin"
    },
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true
    },
    {
      "matchDepTypes": ["devDependencies"],
      "automerge": true
    }
  ],
  "lockFileMaintenance": {
    "enabled": true,
    "schedule": ["before 5am on Monday"]
  },
  "prConcurrentLimit": 10,
  "prHourlyLimit": 2
}
```

---

## Vulnerability Scanning in CI

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Dependency review for PRs
      - name: Review dependencies
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0
          vulnerability-check: true
      
      # Trivy vulnerability scan
      - name: Trivy FS scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'
      
      # npm audit
      - name: npm audit
        run: npm audit --audit-level=high
      
      # Snyk vulnerability scan (if using Snyk)
      - name: Snyk test
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build container
        run: docker build -t my-app:${{ github.sha }} .
      
      - name: Trivy container scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-app:${{ github.sha }}'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'
      
      - name: Docker Scout scan
        run: |
          docker scout cves my-app:${{ github.sha }} \
            --exit-code --severity high,critical

  sbom-generation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: my-app:${{ github.sha }}
          format: cyclonedx-json
      
      - name: Scan SBOM for vulnerabilities
        run: |
          grype sbom:./sbom.cdx.json --fail-on high
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

trivy-fs-scan:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy fs --severity HIGH,CRITICAL --exit-code 1 .
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

trivy-image-scan:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy image --severity HIGH,CRITICAL --exit-code 1 $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'

sbom-generate:
  stage: security
  image: anchore/syft:latest
  script:
    - syft dir:./ --output cyclonedx-json > sbom.cdx.json
    - grype sbom:./sbom.cdx.json --fail-on high
  artifacts:
    paths:
      - sbom.cdx.json
```

---

## SBOM Generation and Verification

### CI/CD SBOM Generation

```yaml
# .github/workflows/sbom.yml
name: Generate SBOM
on:
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          image: my-registry/my-app:${{ github.ref_name }}
          format: cyclonedx-json
          output-file: sbom.cdx.json
      
      - name: Sign SBOM
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign-blob sbom.cdx.json \
            --key env://COSIGN_PRIVATE_KEY \
            --output sbom.cdx.json.sig
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
      
      - name: Upload SBOM and signature
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.cdx.json
            sbom.cdx.json.sig
      
      - name: Scan SBOM for vulnerabilities
        run: |
          grype sbom:./sbom.cdx.json --fail-on high
```

### SBOM Verification by Consumers

```bash
# Verify SBOM signature
cosign verify-blob sbom.cdx.json \
  --signature sbom.cdx.json.sig \
  --key cosign.pub

# Scan SBOM for vulnerabilities
grype sbom:./sbom.cdx.json

# Verify SBOM completeness
syft dir:./my-project -o cyclonedx-json > current-sbom.json
diff <(jq -S '.components | sort_by(.name)' baseline-sbom.json) \
     <(jq -S '.components | sort_by(.name)' current-sbom.json)

# Validate SBOM format
cyclonedx-cli validate --input-format json --input-version v1_5 sbom.cdx.json
```

---

## Code Signing Enforcement

### Policy as Code: Sigstore/cosign

```yaml
# .github/workflows/enforce-signing.yml
name: Enforce Code Signing
on:
  pull_request:
    paths:
      - 'Dockerfile'
      - 'k8s/**'

jobs:
  verify-signatures:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Verify container image signature
        uses: sigstore/cosign-installer@v3
      - run: |
          # Verify the image is signed by the expected identity
          cosign verify my-registry/my-app:${{ github.sha }} \
            --certificate-identity=https://github.com/myorg/my-repo/.github/workflows/release.yml \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com
      
      - name: Verify SLSA provenance
        run: |
          slsa-verifier verify-image my-registry/my-app:${{ github.sha }} \
            --source-uri github.com/myorg/my-repo \
            --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml
      
      - name: Verify SBOM attestation
        run: |
          cosign verify-attestation \
            --type cyclonedx \
            --certificate-identity=https://github.com/myorg/my-repo/.github/workflows/release.yml \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
            my-registry/my-app:${{ github.sha }}
```

### Kubernetes Admission Control

```yaml
# Kubernetes admission policy: Require signed images
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: require-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Images must be signed with cosign"
        foreach:
          - list: "request.object.spec.containers"
            element: "e"
          - list: "request.object.spec.initContainers"
            element: "e"
          - list: "request.object.spec.ephemeralContainers"
            element: "e"
        pattern:
          e:
            image: "my-registry.com/*"
            # Verify cosign signature
            # (Requires kyverno with cosign verification)
```

**Gatekeeper policy for image signing:**

```yaml
# OPA Gatekeeper constraint template for image signing
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredcosign
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredCosign
      validation:
        openAPIV3Schema:
          type: object
          properties:
            image:
              type: string
            key:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredcosign
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not verify_signature(container.image, input.parameters.key)
          msg := sprintf("Image %v is not signed", [container.image])
        }
```

---

## Dependency Review

### npm dependency-review-action

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review
on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
      - 'requirements.txt'
      - 'Pipfile.lock'
      - 'Cargo.toml'

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0, SSPL-1.0
          vulnerability-check: true
          license-check: true
          allow-dependencies-licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.sha }}
```

### PyPI Safety

```bash
# Install and run pip-audit
pip install pip-audit
pip-audit -r requirements.txt

# Run safety check
pip install safety
safety check --json

# Check specific severity
pip-audit -r requirements.txt --desc --ignore-vuln PYSEC-2023-123

# Generate hash-pinned requirements
pip-compile --generate-hashes requirements.in > requirements.txt
pip install --require-hashes -r requirements.txt
```

### Private Registry Policies

**npm Verdaccio (private registry):**

```yaml
# Verdaccio configuration for dependency control
packages:
  # Internal packages: published internally, not from npm
  '@mycompany/*':
    access: $authenticated
    publish: $authenticated
    unpublish: admin
    storage: internal

  # Approved packages: allow from npm
  'express':
    access: $authenticated
    publish: admin
    proxy: npm

  # Block all other packages by default
  '**':
    access: admin
    publish: admin
    proxy: npm

# Security settings
security:
  api:
    jwt:
      sign:
        expiresIn: 15m
  web:
    sign:
      expiresIn: 7d

# Require 2FA for publish
auth:
  type: auth-plugin
  # Custom auth plugin that enforces 2FA
```

**Artifactory (enterprise private registry):**

```yaml
# Artifactory security policies
security_policies:
  - name: "Vulnerability blocking"
    rules:
      - action: block_download
        filters:
          min_severity: high
          cve:
            - CVE-2021-44228  # Log4Shell
            - CVE-2024-3094   # XZ Utils
    applies_to:
      - "npm-repo"
      - "pypi-repo"
      - "maven-repo"

  - name: "License compliance"
    rules:
      - action: block_download
        filters:
          license:
            - GPL-3.0
            - AGPL-3.0
            - SSPL-1.0
```

**Nexus Repository (enterprise private registry):**

```yaml
# Nexus security configuration
security:
  realms:
    - npm-bearer-token-realm
    - docker-bearer-token-realm

  content_selectors:
    - name: approved-npm-packages
      description: "Approved npm packages"
      expression: "format = 'npm' and path = '/express/-/express-4.18.2.tgz' or path = '/lodash/-/lodash-4.17.21.tgz'"

  privileges:
    - name: npm-read-approved
      type: repository-content-selector
      actions: [read]
      contentSelector: approved-npm-packages
      repository: npm-proxy
```

---

## Zero-Trust Supply Chain

### Principles

A zero-trust supply chain applies the zero-trust security model to the software supply chain:

1. **Never trust, always verify**: Verify every artifact, dependency, and pipeline
2. **Least privilege**: Grant minimum necessary permissions to every component
3. **Assume breach**: Design the supply chain assuming any component may be compromised
4. **Verify explicitly**: Cryptographically verify every step in the supply chain
5. **Continuous verification**: Don't just verify at deployment; verify continuously

### Implementation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Zero-Trust Supply Chain                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐ │
│  │  Source   │───▶│  Build    │───▶│  Sign &  │───▶│ Publish  │ │
│  │  Control  │    │  System   │    │  Attest  │    │ & Store  │ │
│  │  ┌──────┐│    │  ┌──────┐│    │  ┌──────┐│    │  ┌──────┐│ │
│  │  │Signed││    │  │SLSA  ││    │  │Cosign││    │  │SBOM  ││ │
│  │  │commits││    │  │Level ││    │  │/Sig  ││    │  │stored││ │
│  │  └──────┘│    │  │ 3+   ││    │  └──────┘│    │  └──────┘│ │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘ │
│       │               │               │               │        │
│       ▼               ▼               ▼               ▼        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Verification & Policy Engine                 │  │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐        │  │
│  │  │Source  │  │Build   │  │Signing │  │SBOM &  │        │  │
│  │  │Verify  │  │Proven. │  │Verify  │  │Vuln    │        │  │
│  │  │        │  │Verify  │  │        │  │Scan    │        │  │
│  │  └────────┘  └────────┘  └────────┘  └────────┘        │  │
│  └──────────────────────────────────────────────────────────┘  │
│       │               │               │               │        │
│       ▼               ▼               ▼               ▼        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Deployment Gate                              │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  Policy: Only deploy if...                         │  │  │
│  │  │  - Source is signed and reviewed                   │  │  │
│  │  │  - Build has SLSA Level 3 provenance              │  │  │
│  │  │  - Artifact is signed by expected identity         │  │  │
│  │  │  - SBOM has no critical/high vulnerabilities      │  │  │
│  │  │  - SBOM has no GPL/AGPL dependencies              │  │  │
│  │  │  - VEX has no unmitigated vulnerabilities          │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## OpenSSF Scorecard

OpenSSF Scorecard is an automated tool that assesses open-source projects against a set of security best practices:

```bash
# Install scorecard
go install github.com/ossf/scorecard/v5/cmd/scorecard@latest

# Run scorecard on a repository
scorecard --repo=github.com/myorg/my-repo

# Run with specific checks
scorecard --repo=github.com/myorg/my-repo \
  --checks=Code-Review,Branch-Protection,Signed-Releases,Token-Permissions

# Output in JSON format
scorecard --repo=github.com/myorg/my-repo --format json

# Run in CI
scorecard --repo=github.com/${{ github.repository }} \
  --commit=${{ github.sha }} \
  --format json > scorecard-results.json
```

**Scorecard checks:**

| Check | Description | Risk Level |
|-------|-------------|------------|
| Binary-Artifacts | Are there binaries committed to the source? | High |
| Branch-Protection | Are branches protected? | High |
| Code-Review | Are changes reviewed before merge? | High |
| Dangerous-Workflow | Are there dangerous GitHub Actions patterns? | Critical |
| Dependency-Update-Tool | Is there an automated dependency update tool? | Medium |
| Fuzzing | Is the project fuzzed? | Medium |
| License | Does the project have a license? | Low |
| Maintained | Is the project actively maintained? | Medium |
| Pinned-Dependencies | Are dependencies pinned to specific versions? | High |
| Security-Policy | Does the project have a security policy? | Medium |
| Signed-Releases | Are releases signed? | High |
| Token-Permissions | Are GitHub Actions tokens minimal? | High |
| Vulnerabilities | Are there known vulnerabilities? | Critical |

### OpenSSF Best Practices Badge

The OpenSSF Best Practices Badge recognizes open-source projects that follow security best practices:

```bash
# Check a project's badge status
curl -s https://bestpractices.coreinfrastructure.org/en/projects/${PROJECT_ID} | jq '.badge_level'
```

**Badge levels:**
- **Passing**: Meets all required criteria
- **Silver**: Meets all passing criteria plus additional criteria
- **Gold**: Meets all silver criteria plus the most stringent criteria

---

## Securing Maintainer Accounts

### Two-Factor Authentication

```bash
# Enable 2FA on npm
npm profile enable-2fa

# Enable 2FA on PyPI
# Go to https://pypi.org/manage/account/ and enable 2FA

# Enable 2FA on GitHub
# Go to https://github.com/settings/security and enable 2FA

# Enable 2FA on RubyGems
# Go to https://rubygems.org/profile/edit and enable 2FA
```

### Hardware Security Keys

For maximum security, use hardware security keys (FIDO2/WebAuthn) for 2FA:

```bash
# Register a YubiKey with GitHub
# Go to https://github.com/settings/security
# Click "Add a security key"
# Follow the instructions to register your YubiKey

# Use YubiKey for npm publish
# Store npm tokens in YubiKey's OTP slot
# Configure npm to require 2FA for publish
npm config set //registry.npmjs.org/:_authToken ${NPM_TOKEN}
npm profile enable-2fa --auth-type=otp
```

### Git Commit Signing with Hardware Keys

```bash
# Configure Git to use YubiKey for signing
gpg --card-status  # Verify YubiKey is detected

# Configure Git signing
git config --global user.signingkey ABCDEF1234567890!
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.program gpg

# Sign a commit
git commit -S -m "Signed commit"

# Sign a tag
git tag -s v1.0.0 -m "Signed release v1.0.0"

# Verify a commit
git verify-commit HEAD

# Verify a tag
git verify-tag v1.0.0
```

### npm Publish Security

```bash
# Use hardware keys for npm publish
# 1. Enable 2FA on npm account
npm profile enable-2fa --auth-type=otp

# 2. Use provenance for publish
npm publish --provenance --access public

# 3. Use npm provenance signing in CI
# See the Build Pipeline Security chapter for CI configuration

# 4. Revoke compromised tokens immediately
npm token revoke <token-id>

# 5. Use short-lived tokens for CI
npm token create --read-only --cidr-whitelist=203.0.113.0/24
```

---

## Private Registries

### Verdaccio (npm Private Registry)

```yaml
# verdaccio configuration
storage: ./storage
plugins: ./plugins

auth:
  htpasswd:
    file: ./htpasswd
    max_users: -1

# Upstream configuration
uplinks:
  npmjs:
    url: https://registry.npmjs.org/
    # Cache packages from npm
    cache: true
    # Maximum timeout for upstream requests
    timeout: 30s

packages:
  # Internal packages: published only in Verdaccio
  '@mycompany/*':
    access: $authenticated
    publish: $authenticated
    unpublish: admin

  # Approved external packages: proxied from npm
  'express':
    access: $authenticated
    publish: admin
    proxy: npmjs

  'lodash':
    access: $authenticated
    publish: admin
    proxy: npmjs

  # Block all other packages
  '**':
    access: admin
    publish: admin
    proxy: npmjs

# Security settings
security:
  api:
    jwt:
      sign:
        expiresIn: 15m
  web:
    sign:
      expiresIn: 7d

# Rate limiting
limits:
  max_uplinks: 3
  max_body_size: 10mb
```

### Artifactory (Enterprise Private Registry)

```bash
# Configure npm to use Artifactory
npm config set registry https://mycompany.jfrog.io/artifactory/api/npm/npm/

# Configure scoped registries
npm config set @mycompany:registry https://mycompany.jfrog.io/artifactory/api/npm/npm-internal/

# Configure PyPI
pip config set global.index-url https://mycompany.jfrog.io/artifactory/api/pypi/pypi-virtual/simple

# Configure Docker
docker login mycompany.jfrog.io
```

---

## Hardening Checklist

### Critical (Implement Immediately)

- [ ] Enable 2FA on all maintainer accounts (npm, PyPI, GitHub, etc.)
- [ ] Pin all dependencies to exact versions with hash verification
- [ ] Use `npm ci` (not `npm install`) in CI/CD
- [ ] Enable branch protection and required reviews
- [ ] Implement vulnerability scanning in CI (Trivy, Grype, pip-audit)
- [ ] Configure correct registry priority (private first, then public)
- [ ] Generate SBOMs for all releases
- [ ] Sign all release artifacts with Sigstore/cosign

### High (Implement Within 3 Months)

- [ ] Implement SLSA Level 2 provenance for all releases
- [ ] Deploy private registries (Verdaccio, Artifactory, Nexus)
- [ ] Implement dependency review in CI (npm dependency-review-action)
- [ ] Enable OpenSSF Scorecard on all repositories
- [ ] Configure OpenSSF Best Practices Badge
- [ ] Implement automated dependency updates (Dependabot, Renovate)
- [ ] Sign all Git commits and tags
- [ ] Implement SBOM attestation with cosign

### Medium (Implement Within 6 Months)

- [ ] Achieve SLSA Level 3 provenance for all releases
- [ ] Implement Kubernetes admission control for signed images
- [ ] Implement VEX for vulnerability management
- [ ] Deploy zero-trust supply chain policies
- [ ] Implement reproducible builds for critical artifacts
- [ ] Implement dependency confusion prevention (scoped registries)
- [ ] Establish security response process for supply chain incidents
- [ ] Implement hardware security keys for maintainer accounts

### Low (Implement Within 12 Months)

- [ ] Achieve SLSA Level 4 for critical artifacts
- [ ] Implement reproducible build verification
- [ ] Deploy in-toto framework for build chain verification
- [ ] Implement GUAC for supply chain graph analysis
- [ ] Achieve OpenSSF Best Practices Gold Badge
- [ ] Implement supply chain attack detection and response automation

---

## References

1. OpenSSF. "Scorecard: Automated Security Assessment." https://github.com/ossf/scorecard
2. OpenSSF. "Best Practices Badge." https://bestpractices.coreinfrastructure.org/
3. CISA. "Securing the Software Supply Chain: Guide for Developers." https://www.cisa.gov/sites/default/files/publications/Securing%20the%20Software%20Supply%20Chain%20for%20Developers.pdf
4. SLSA Specification v1.0. "Supply-chain Levels for Software Artifacts." https://slsa.dev/spec/v1.0/
5. Sigstore. "Cosign: Container Signing." https://docs.sigstore.dev/cosign/signing/signing_with_containers/
6. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
7. Anchore. "Syft: SBOM Generator." https://github.com/anchore/syft
8. Aqua Security. "Trivy: Vulnerability Scanner." https://aquasecurity.github.io/trivy/
9. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
10. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
11. Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
12. CISA. "Software Bill of Materials (SBOM)." https://www.cisa.gov/sbom
13. CycloneDX Specification v1.5. OWASP. https://cyclonedx.org/specification/
14. SPDX Specification v2.3. Linux Foundation. https://spdx.github.io/spdx-spec/
15. OpenSSF. "S2C2F: Supply-chain Secure Supply Chain Consumption Framework." https://github.com/ossf/s2c2f
16. SLSA GitHub Generator. https://github.com/slsa-framework/slsa-github-generator