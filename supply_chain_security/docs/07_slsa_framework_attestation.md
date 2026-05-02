# SLSA Framework and Attestation

## SLSA: Supply-chain Levels for Software Artifacts

SLSA (pronounced "salsa") is a security framework that provides a checklist of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure. Rather than a binary "secure/insecure" classification, SLSA defines a series of progressively stricter levels that provide increasing confidence in the integrity of the software supply chain.

The framework addresses a fundamental question: **How do we know that the software artifact we received was actually built from the source code we expect, by the build system we trust, and hasn't been modified since?**

---

## SLSA Levels Overview

SLSA defines four levels, each adding progressively stronger guarantees:

| Level | Description | Trust Model | Key Control |
|-------|-------------|-------------|-------------|
| SLSA 0 | No guarantees | No provenance | Any artifact accepted |
| SLSA 1 | Documented build process | Provenance exists but is self-reported | Provenance metadata generated |
| SLSA 2 | Hosted build platform | Provenance is tamper-resistant | Signed provenance from hosted builder |
| SLSA 3 | Non-falsifiable provenance | Provenance is trustworthy | Hardened builder with provenance |
| SLSA 4 | Two-party review | Maximum trust | Reproducible builds, hermetic builds |

### SLSA Level 0: No Guarantees

SLSA Level 0 is the default state. There are no provenance requirements and no integrity guarantees. An artifact at Level 0 could have been produced by anyone, from any source, using any build process. The vast majority of software today is at Level 0.

**What this means in practice:**
- An npm package published without provenance
- A Docker image pushed without signing
- A binary distributed without any attestation
- A GitHub release built on a developer's local machine

**Risk:** A consumer at Level 0 has no way to verify the artifact's origin. They must trust the publisher entirely, with no cryptographic guarantees.

### SLSA Level 1: Documented Build Process

SLSA Level 1 requires that provenance metadata exists, but that provenance is self-reported by the build system and is not verifiable. Level 1 provides documentation but not security guarantees.

**Requirements:**
- **Provenance exists**: The build system generates a provenance document describing how the artifact was produced
- **Provenance format**: The provenance follows the SLSA provenance format (or equivalent)
- **No tamper resistance**: The provenance is not signed and could be forged

**Example provenance (Level 1):**

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "my-app",
      "digest": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/build-type/v1",
    "builder": {
      "id": "https://github.com/myorg/my-repo/.github/workflows/ci.yml"
    },
    "invocation": {
      "configSource": {
        "uri": "https://github.com/myorg/my-repo/blob/main/.github/workflows/ci.yml",
        "digest": {
          "sha1": "abc123"
        },
        "entryPoint": "build"
      }
    },
    "materials": [
      {
        "uri": "https://github.com/myorg/my-repo",
        "digest": {
          "sha1": "def456"
        }
      }
    ]
  }
}
```

**What Level 1 provides:**
- Documentation of the build process for auditing
- A standardized format for build metadata
- A foundation for higher SLSA levels
- No security guarantees (provenance could be forged)

### SLSA Level 2: Hosted Build Platform

SLSA Level 2 requires that the build runs on a hosted build platform and the provenance is signed by the platform. This prevents the provenance from being tampered with after the fact.

**Requirements:**
- All Level 1 requirements
- **Hosted build platform**: The build must run on a hosted, multi-tenant build service (GitHub Actions, GitLab CI, Google Cloud Build, etc.)
- **Signed provenance**: The provenance must be signed by the build platform using a key that the consumer can verify
- **Provenance authentication**: The build platform must be identified in the provenance and the consumer must trust that platform

**Example: GitHub Actions SLSA Level 2 provenance**

When you use GitHub Actions to generate SLSA provenance, GitHub signs the provenance with its own key:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      attestations: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Build artifact
        run: |
          make build
          sha256sum build/my-app > build/my-app.sha256
      
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
        with:
          base64-subjects: ${{ steps.build.outputs.sha256 }}
          upload-assets: true
```

The provenance is signed using GitHub's OIDC identity, and the signature can be verified using GitHub's Sigstore integration:

```bash
# Verify SLSA Level 2 provenance generated by GitHub Actions
slsa-verifier verify-artifact my-app \
  --provenance-path my-app.intoto.jsonl \
  --source-uri github.com/myorg/my-repo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml
```

**What Level 2 provides:**
- Cryptographic proof that the artifact was built on the specified platform
- Assurance that the provenance was generated by the build platform (not forged)
- Traceability from artifact back to source code
- No guarantee that the build platform itself wasn't compromised

### SLSA Level 3: Non-Falsifiable Provenance

SLSA Level 3 adds protections against the build platform itself being compromised. The provenance must be non-falsifiable, meaning it accurately represents the build that actually occurred, even if a maintainer or adversary has write access to the repository.

**Requirements:**
- All Level 2 requirements
- **Non-falsifiable provenance**: The build platform must be hardened such that maintainers cannot cause the provenance to be incorrect
- **Isolated build**: The build must be isolated from other builds and from the maintainer
- **No ephemeral credentials**: Build credentials must not be exposed to the build process

**What Level 3 provides:**
- Assurance that the provenance accurately reflects what was built, even against a malicious maintainer
- Protection against the maintainer injecting code or modifying the build process
- Protection against the maintainer modifying provenance after the build

**GitHub Actions at SLSA Level 3:**

GitHub Actions can provide SLSA Level 3 provenance when configured correctly:

```yaml
# SLSA Level 3 GitHub Actions workflow
name: Release (SLSA Level 3)
on:
  release:
    types: [published]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write      # Required for keyless signing (Fulcio)
      contents: read
      attestations: write
    # CRITICAL: Do not allow checkout of PR code with elevated permissions
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.release.tag_name }}  # Checkout release tag, not PR code
      
      - name: Build
        run: make build
      
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
```

**Key requirements for SLSA Level 3 on GitHub Actions:**
1. The workflow must be triggered by release events (not push events to arbitrary branches)
2. The workflow must check out the release tag, not PR code
3. The `permissions` block must only request necessary permissions
4. The provenance must be generated by the SLSA GitHub generator, not custom code
5. Self-hosted runners must not be used (they can be compromised)

### SLSA Level 4: Two-Party Review + Reproducibility

SLSA Level 4 is the highest level, requiring two-party review of all changes and hermetic, reproducible builds:

**Requirements:**
- All Level 3 requirements
- **Two-party review**: Every change to the source must be reviewed and approved by at least one trusted person who is not the author
- **Hermetic build**: The build must be isolated from the network and from any non-deterministic inputs
- **Reproducible build**: The build must produce bit-for-bit identical output when run twice
- **Verified provenance**: Provenance must include enough information to reproduce the build independently

**What Level 4 provides:**
- Maximum confidence in the supply chain
- Protection against single-person compromise (requires collusion)
- Independent verification of build integrity
- Protection against compromised build infrastructure

**Example: SLSA Level 4 build with Bazel**

```python
# Bazel build configuration for SLSA Level 4
# WORKSPACE
load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
bazel_skylib_workspace()

# Hermetic build rule
load("@rules_elf//toolchain:toolchain.bzl", "elf_toolchain")
elf_toolchain(
    name = "hermetic_toolchain",
    compiler = "@llvm_toolchain//:clang",
    # All dependencies explicitly specified, no network access
)

# BUILD.bazel
load("@rules_pkg//:pkg.bzl", "pkg_tar")

# Build with hermetic settings
cc_binary(
    name = "my-app",
    srcs = glob(["src/**/*.cc"]),
    deps = [
        "@openssl//:openssl",
        "@zlib//:zlib",
    ],
    # Enable reproducibility
    features = ["deterministic"],
    copts = [
        "-fno-randomize-layout",  # Disable random layout
        "-Wl,--build-id=sha1",     # Deterministic build ID
    ],
)

# Strip timestamps from output
pkg_tar(
    name = "my-app-package",
    srcs = [":my-app"],
    package_dir = "/usr/local/bin",
    # Deterministic timestamps
    mtime = 1700000000,
    owner_name = "0",
    owner_number = "0",
)
```

---

## SLSA Provenance Format

The SLSA provenance format is defined in the in-toto attestation specification. It provides a standardized, machine-readable description of how an artifact was built:

### Provenance Format v1.0

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:docker/my-registry/my-app@sha256:abc123",
      "digest": {
        "sha256": "abc123def456..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/actions/workflow/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/myorg/my-repo",
          "path": ".github/workflows/release.yml"
        },
        "inputs": {
          "tag": "v1.2.3"
        }
      },
      "internalParameters": {
        "github_actor": "maintainer",
        "github_run_id": "12345678",
        "github_run_number": "42"
      },
      "resolvedDependencies": [
        {
          "uri": "https://github.com/myorg/my-repo",
          "digest": {
            "sha1": "abc123def456..."
          }
        },
        {
          "uri": "https://github.com/actions/checkout",
          "digest": {
            "sha256": "3ba5ab..."
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"
      },
      "buildInvocation": {
        "configSource": {
          "uri": "https://github.com/myorg/my-repo/blob/main/.github/workflows/release.yml",
          "digest": {
            "sha1": "abc123..."
          }
        },
        "startTime": "2024-01-15T00:00:00Z",
        "finishTime": "2024-01-15T00:10:00Z"
      },
      "metadata": {
        "invocationId": "https://github.com/myorg/my-repo/actions/runs/12345678",
        "startedOn": "2024-01-15T00:00:00Z",
        "finishedOn": "2024-01-15T00:10:00Z"
      }
    }
  }
}
```

### SLSA Source Requirements

SLSA also defines requirements for the source code that feeds into the build:

| Level | Source Requirement | Description |
|-------|-------------------|-------------|
| Source Level 0 | No requirements | Source may be anywhere |
| Source Level 1 | Version controlled | Every change tracked in VCS |
| Source Level 2 | Verified history | Signed commits, immutable refs |
| Source Level 3 | Two-person review | Changes require approval from a second person |

**Source Level 1 Implementation:**

```bash
# Verify all commits are signed
git log --format='%H %G?' --no-merges | \
  while read hash signature; do
    case $signature in
      G|N|S) ;; # Good signature
      *) echo "Unsigned commit: $hash" ;;
    esac
  done

# Configure Git to require signed commits
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

**Source Level 2 Implementation:**

```yaml
# .github/workflows/verify-source.yml
name: Verify Source Level 2
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history
      
      - name: Verify all commits are signed
        run: |
          git log --format='%H %G?' --no-merges origin/main..HEAD | \
          while read hash signature; do
            case $signature in
              G|N|S) ;;
              *) echo "FAIL: Unsigned commit $hash"; exit 1 ;;
            esac
          done
      
      - name: Verify branch protection
        uses: octokit/request-action@v2.x
        with:
          route: GET /repos/{owner}/{repo}/branches/main/protection
          owner: myorg
          repo: my-repo
```

**Source Level 3 Implementation (two-person review):**

```yaml
# .github/workflows/verify-source-level-3.yml
name: Verify Source Level 3
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Verify PR has required approvals
        uses: octokit/request-action@v2.x
        with:
          route: GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Verify code owner approval
        uses: octokit/request-action@v2.x
        with:
          route: GET /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers
```

---

## SLSA Verification

### slsa-verifier

The `slsa-verifier` tool verifies SLSA provenance for artifacts:

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/cmd/slsa-verifier@latest

# Verify a GitHub Actions-built artifact
slsa-verifier verify-artifact my-app \
  --provenance-path my-app.intoto.jsonl \
  --source-uri github.com/myorg/my-repo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml

# Verify a container image
slsa-verifier verify-image registry.example.com/my-app:v1.2.3 \
  --source-uri github.com/myorg/my-repo

# Verify with specific builder
slsa-verifier verify-artifact my-app \
  --provenance-path my-app.intoto.jsonl \
  --source-uri github.com/myorg/my-repo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml \
  --builder-version v1.9.0

# Verify with expected source tag or branch
slsa-verifier verify-artifact my-app \
  --provenance-path my-app.intoto.jsonl \
  --source-uri github.com/myorg/my-repo \
  --expected-tag v1.2.3

# Verify and print provenance details
slsa-verifier verify-artifact my-app \
  --provenance-path my-app.intoto.jsonl \
  --source-uri github.com/myorg/my-repo \
  --print-provenance
```

**Verification checks performed by slsa-verifier:**

1. **Signature verification**: Provenance signature is valid and from the expected builder
2. **Source URI match**: The source URI in the provenance matches the expected repository
3. **Builder ID match**: The builder ID matches the expected builder
4. **Tag/branch match**: The source tag or branch matches expectations (if specified)
5. **Subject digest match**: The artifact digest matches the subject in the provenance

---

## VSA (Verification Summary Attestation)

A Verification Summary Attestation (VSA) is an attestation that summarizes the results of verifying an artifact's SLSA provenance. Rather than every consumer verifying provenance independently, a trusted verifier can produce a VSA that consumers can trust:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "my-app",
      "digest": {
        "sha256": "abc123def456..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/verification_summary/v0.1",
  "predicate": {
    "verifier": {
      "id": "https://mycompany.com/verification-service"
    },
    "timeVerified": "2024-01-15T00:30:00Z",
    "resourceUri": "registry.example.com/my-app:v1.2.3",
    "policy": {
      "slsaSourceLevel": 3,
      "slsaBuildLevel": 3
    },
    "verifiedAt": "2024-01-15T00:30:00Z",
    "verificationResult": "PASSED",
    "verifiedLevels": ["SLSA_BUILD_LEVEL_3", "SLSA_SOURCE_LEVEL_3"]
  }
}
```

**VSA use cases:**
1. **Consumer verification**: Instead of verifying provenance directly, consumers verify the VSA from a trusted verifier
2. **Policy enforcement**: Organizations can define SLSA level policies and verify compliance
3. **Supply chain auditing**: VSAs provide an audit trail of verification decisions
4. **Transitive verification**: VSAs can verify the provenance of dependencies without access to their original provenance

---

## SAI (Supply-chain Artifact Integrity)

Supply-chain Artifact Integrity (SAI) is a related concept that focuses on the integrity of individual artifacts in the supply chain. While SLSA provides an overall framework, SAI provides specific controls for artifact integrity:

**SAI controls:**
1. **Software artifacts are signed**: All release artifacts are cryptographically signed
2. **Signing is authenticated**: Signing keys are authenticated and access-controlled
3. **Artifacts are verified**: Consumers verify signatures before trusting artifacts
4. **Artifact provenance is recorded**: The provenance of each artifact is recorded and verifiable
5. **Artifact integrity is maintained**: Artifacts are protected from tampering from build through deployment

---

## SLSA Adoption in Major Projects

### Google

Google initiated the SLSA framework and applies it internally to all production services. Google's internal build system (Borg) provides SLSA Level 3 provenance for all artifacts, and Google is working toward SLSA Level 4 for critical infrastructure.

**Google's SLSA practices:**
- All production binaries are built on Google's internal build system with SLSA Level 3 provenance
- Google contributes to the SLSA framework and slsa-github-generator
- Google Cloud Build supports SLSA provenance generation
- Google's Binary Authorization for GKE enforces SLSA policies

### GitHub

GitHub has implemented SLSA Level 3 provenance for npm packages and GitHub Actions artifacts:

```bash
# npm provenance (SLSA Level 2-3)
npm publish --provenance

# GitHub Actions artifact attestation (SLSA Level 3)
gh attestation verify my-app \
  --owner myorg \
  --repo my-repo
```

### npm

npm's provenance feature provides SLSA Level 2 provenance for packages published from GitHub Actions:

```javascript
// package.json with provenance verification
{
  "name": "my-package",
  "version": "1.0.0",
  "scripts": {
    "prepublishOnly": "npm run build && npm run test",
    "publish": "npm publish --provenance --access public"
  }
}
```

**Verification of npm provenance:**

```bash
# Verify npm provenance
npm audit signatures

# Check provenance for a specific package
npm view my-package provenance --json

# Verify npm package signature
npm cache verify
```

### Cloud Providers

**Google Cloud Binary Authorization:**

```yaml
# Binary Authorization policy (SLSA Level 3)
apiVersion: cloudplatform.googleapis.com/v1
kind: Policy
spec:
  admissionWhitelistPatterns:
    - namePattern: "registry.example.com/my-org/*"
  requirements:
    - attestors:
        - attestor: my-attestor
      attestations:
        - slsaProvenance:
            builder:
              id: "https://github.com/slsa-framework/slsa-github-generator"
            sourceUri: "github.com/my-org/my-repo"
            slsaLevel: 3
```

**AWS Signer and Config Rule:**

```bash
# Sign a container image with AWS Signer
aws signer sign-image \
  --profile my-signing-profile \
  --image-uri registry.example.com/my-app:v1.2.3

# Verify signature
aws signer verify-image \
  --profile my-signing-profile \
  --image-uri registry.example.com/my-app:v1.2.3
```

**Azure Policy for container signing:**

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.ContainerInstance/containerGroups"
  },
  "then": {
    "effect": "deny",
    "details": {
      "message": "Container images must be signed with SLSA provenance",
      "requiredSignatures": [
        {
          "type": "SLSA",
          "level": 3
        }
      ]
    }
  }
}
```

---

## Moving from SLSA Level 0 to 4

### Phase 1: Level 0 → Level 1 (Document Your Build)

**Steps:**
1. Generate provenance for all release artifacts
2. Adopt the SLSA provenance format for provenance metadata
3. Publish provenance alongside artifacts

```yaml
# Generate basic provenance (Level 1)
name: Build with Provenance
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build
        run: make build
      
      - name: Generate SHA256
        run: sha256sum build/my-app > build/my-app.sha256
      
      - name: Generate Provenance v1
        run: |
          cat > provenance.json << 'EOF'
          {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
              {
                "name": "my-app",
                "digest": {
                  "sha256": "$(cat build/my-app.sha256 | cut -d' ' -f1)"
                }
              }
            ],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
              "builder": {
                "id": "https://github.com/myorg/my-repo/.github/workflows/ci.yml"
              },
              "buildType": "https://github.com/actions/workflow",
              "invocation": {
                "configSource": {
                  "uri": "https://github.com/myorg/my-repo/blob/main/.github/workflows/ci.yml",
                  "digest": {
                    "sha1": "${{ github.sha }}"
                  }
                }
              },
              "materials": [
                {
                  "uri": "https://github.com/myorg/my-repo",
                  "digest": {
                    "sha1": "${{ github.sha }}"
                  }
                }
              ]
            }
          }
          EOF
```

### Phase 2: Level 1 → Level 2 (Hosted Build)

**Steps:**
1. Move builds to a hosted, multi-tenant build platform
2. Use the SLSA GitHub Generator or equivalent to generate signed provenance
3. Configure the build platform to sign provenance with a platform-managed key

```yaml
# Use SLSA GitHub Generator for Level 2 provenance
name: Build with SLSA Level 2
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

### Phase 3: Level 2 → Level 3 (Non-Falsifiable Provenance)

**Steps:**
1. Harden the build workflow to prevent provenance forgery
2. Use release-only triggers (not push events)
3. Restrict GitHub Actions permissions to minimum necessary
4. Prevent self-hosted runner usage
5. Implement branch protection and required reviews

```yaml
# SLSA Level 3 build workflow
name: Release (SLSA Level 3)
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
    steps:
      # CRITICAL: Checkout the release tag, not arbitrary code
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

**Branch protection rules for SLSA Level 3:**

```yaml
# Branch protection configuration (via GitHub API)
# Equivalent to enabling these settings in the GitHub UI:
# - Require pull request reviews (1 required reviewer)
# - Require status checks to pass before merging
# - Require signed commits
# - Require linear history
# - Include administrators
# - Restrict who can push to matching branches
```

### Phase 4: Level 3 → Level 4 (Two-Party Review + Reproducibility)

**Steps:**
1. Implement two-party review for all changes (CODEOWNERS, required reviews)
2. Make builds reproducible (deterministic timestamps, hermetic builds)
3. Implement independent build verification (two independent builders)
4. Verify that both builds produce identical output

```yaml
# CODEOWNERS file - Two-party review
# All changes require review from the security team
* @myorg/security-team

# Infrastructure changes require review from both security and ops
/.github/ @myorg/security-team @myorg/ops-team
/infrastructure/ @myorg/security-team @myorg/ops-team
/Dockerfile @myorg/security-team

# Source code changes require review from at least one developer
/src/ @myorg/senior-developers
```

```dockerfile
# Reproducible Dockerfile
FROM debian:bookworm-slim

# Set deterministic build environment
ENV SOURCE_DATE_EPOCH=1700000000
ENV TZ=UTC
ENV LC_ALL=C
ENV DEBIAN_FRONTEND=noninteractive

# Install exact package versions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc=12.2.0-14 \
    make=4.3-4.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ ./src/
COPY Makefile .

# Build with deterministic flags
RUN make CC=gcc LDFLAGS="-Wl,--build-id=sha1" CFLAGS="-fno-randomize-layout"

# Set deterministic timestamps
RUN find /app -exec touch -d "2024-01-01T00:00:00Z" {} \;
```

---

## SLSA Level Requirements Summary

```
SLSA Level 4: Hermetic + Reproducible + Two-Party Review
    │
SLSA Level 3: Non-Falsifiable Provenance + Hardened Builder
    │
SLSA Level 2: Signed Provenance + Hosted Build Platform
    │
SLSA Level 1: Provenance Exists (Self-Reported)
    │
SLSA Level 0: No Provenance
```

| Requirement | L0 | L1 | L2 | L3 | L4 |
|-------------|----|----|----|----|-----|
| Provenance exists | | ✓ | ✓ | ✓ | ✓ |
| Provenance is signed | | | ✓ | ✓ | ✓ |
| Provenance is non-falsifiable | | | | ✓ | ✓ |
| Build on hosted platform | | | ✓ | ✓ | ✓ |
| Build is isolated | | | | ✓ | ✓ |
| Build is hermetic | | | | | ✓ |
| Build is reproducible | | | | | ✓ |
| Two-party review | | | | | ✓ |
| Source is version controlled | | ✓ | ✓ | ✓ | ✓ |
| Source has verified history | | | ✓ | ✓ | ✓ |
| Source has two-party review | | | | | ✓ |

---

## References

1. SLSA Specification v1.0. "Supply-chain Levels for Software Artifacts." https://slsa.dev/spec/v1.0/
2. SLSA Provenance Format v1. https://slsa.dev/provenance/v1
3. SLSA GitHub Generator. https://github.com/slsa-framework/slsa-github-generator
4. slsa-verifier. https://github.com/slsa-framework/slsa-verifier
5. in-toto Attestation Framework. https://github.com/in-toto/attestation
6. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
7. Google. "SLSA: A Framework for Supply Chain Integrity." June 2021. https://security.googleblog.com/2021/06/introducing-slsa.html
8. OpenSSF. "S2C2F: Supply-chain Secure Supply Chain Consumption Framework." https://github.com/ossf/s2c2f
9. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
10. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
11. CISA. "Securing the Software Supply Chain: Guide for Developers." https://www.cisa.gov/sbom
12. OpenSSF. "Scorecard: Automated Security Assessment." https://github.com/ossf/scorecard
13. Google Cloud. "Binary Authorization." https://cloud.google.com/binary-authorization
14. Sigstore. "Cosign: Container Signing." https://docs.sigstore.dev/cosign/signing/signing_with_containers/