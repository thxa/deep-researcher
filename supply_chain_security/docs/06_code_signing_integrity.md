# Code Signing and Integrity Verification

## Code Signing Architecture

Code signing is the process of digitally signing executables, scripts, and software artifacts to confirm the author and guarantee that the code has not been altered or corrupted since it was signed. In the supply chain security context, code signing provides a cryptographic guarantee that an artifact was produced by a trusted entity and has not been tampered with during distribution.

The fundamental challenge of code signing is: who signs the code, how are signing keys protected, and how do consumers verify the signatures? Each of these questions has been the site of significant real-world attacks.

---

## X.509 Code Signing Infrastructure

### Certificate Architecture

Code signing certificates are X.509 digital certificates that follow the PKIX profile (RFC 5280). They bind an identity (organization or individual) to a public key and are issued by Certificate Authorities (CAs) that are trusted by operating systems and verification tools.

**X.509 Code Signing Certificate Structure:**

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1234567890abcdef
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=DigiCert SHA2 Assured ID Code Signing CA, O=DigiCert, C=US
        Validity:
            Not Before: Jan 01 00:00:00 2024 GMT
            Not After : Dec 31 23:59:59 2025 GMT
        Subject: CN=MyCompany Inc., O=MyCompany Inc., L=San Francisco, ST=CA, C=US
        Subject Public Key Info:
            Algorithm: rsaEncryption
            RSA Public-Key: (4096 bit)
        X509v3 extensions:
            X509v3 Key Usage: Digital Signature, Non-Repudiation
            X509v3 Extended Key Usage: Code Signing
            X509v3 Basic Constraints: CA:FALSE
            X509v3 Authority Key Identifier: 
                keyid:AB:CD:EF:12:34:56:78:90...
            X509v3 Subject Key Identifier: 
                12:34:56:78:90:AB:CD:EF...
            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.4.1 (EV Code Signing)
```

**Key differences from TLS certificates:**
- Extended Key Usage (EKU) must include `codeSigning` (OID 1.3.6.1.5.5.7.3.3)
- Key Usage must include `digitalSignature` and may include `nonRepudiation`
- No `keyEncipherment` or `keyAgreement` usage
- EV code signing certificates require stricter identity validation

### PKCS#7 and Authenticode

**PKCS#7 (CMS - Cryptographic Message Syntax)**

PKCS#7, now standardized as CMS (RFC 5652), is the format used to bundle signatures with signed content. It supports:

- **Detached signatures**: The signature is separate from the signed content
- **Enveloped signatures**: The content is embedded within the signature structure
- **Multiple signers**: Multiple parties can sign the same content
- **Timestamping**: Signatures can include a trusted timestamp from a TSA (Time Stamp Authority)

```bash
# Create a PKCS#7 detached signature
openssl cms -sign \
  -in artifact.tar.gz \
  -signer code-signing.pem \
  -inkey code-signing.key \
  -outform DER \
  -out artifact.tar.gz.sig \
  -binary

# Verify a PKCS#7 detached signature
openssl cms -verify \
  -in artifact.tar.gz.sig \
  -inform DER \
  -content artifact.tar.gz \
  -CAfile ca-bundle.crt \
  -out /dev/null
```

**Authenticode (Windows PE Signing)**

Microsoft's Authenticode format signs Windows executable files (PE, MSI, CAB) using PKCS#7 embedded signatures:

```bash
# Sign a Windows executable with signtool
signtool sign \
  /fd SHA256 \
  /tr http://timestamp.digicert.com \
  /td SHA256 \
  /a \
  /f code-signing.pfx \
  /p password \
  application.exe

# Verify a Authenticode signature
signtool verify /pa /all application.exe

# Sign with EV certificate on a hardware token
signtool sign \
  /fd SHA256 \
  /tr http://timestamp.digicert.com \
  /td SHA256 \
  /sha1 ABCDEF0123456789... \
  application.exe
```

**Linux Package Signing (RPM and DEB)**

```bash
# Sign an RPM package
rpmsign --addsign my-package-1.0.0-1.x86_64.rpm

# Verify an RPM signature
rpm --checksig my-package-1.0.0-1.x86_64.rpm

# Sign a DEB package (using dpkg-sig)
dpkg-sig -k security@mycompany.com --sign builder my-package_1.0.0_amd64.deb

# Verify a DEB signature
dpkg-sig --verify my-package_1.0.0_amd64.deb

# Create an APT repository with signed metadata
aptly publish repo -gpg-key=security@mycompany.com my-repo
```

---

## Key Management Best Practices

### HSM-Based Signing

Hardware Security Modules (HSMs) provide the highest level of protection for code signing private keys. The private key never leaves the HSM; all signing operations are performed within the tamper-resistant hardware:

```python
# Signing with AWS CloudHSM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
import boto3

# Key is generated and stored in CloudHSM
# Private key NEVER leaves the HSM
kms_client = boto3.client('kms')

# Sign a hash using the KMS key (backed by CloudHSM)
import hashlib
artifact_hash = hashlib.sha256(artifact_bytes).digest()

response = kms_client.sign(
    KeyId='arn:aws:kms:us-east-1:123456789012:key/abcd-1234',
    Message=artifact_hash,
    MessageType='DIGEST',
    SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
)

signature = response['Signature']
```

**HSM options for code signing:**

| Provider | Product | FIPS Level | Notes |
|----------|---------|------------|-------|
| AWS | CloudHSM | Level 3 | Pay-per-use, integrated with KMS |
| Azure | Dedicated HSM | Level 3 | Thales LunaNetwork HSM 7 |
| Google | Cloud HSM | Level 3 | Backed by Thales HSM |
| Thales | Luna Network HSM 7 | Level 3 | On-premise, market leader |
| YubiKey | YubiKey 5 | Level 2 | USB/NFC, cost-effective for individuals |
| Nitrokey | Nitrokey HSM 2 | Level 3 | USB, open-source firmware |

### Key Rotation Policy

```yaml
# Key rotation policy
code_signing:
  key_rotation:
    # Rotate signing keys annually
    rotation_period: 365 days
    
    # Grace period: old key remains valid for 90 days after rotation
    overlap_period: 90 days
    
    # Key lengths
    rsa: 4096 bits minimum
    ecdsa: P-384 or P-521
    ed25519: 256 bits
    
    # Certificate validity
    certificate_validity: 3 years (maximum)
    timestamp_validity: 10 years (minimum)
    
    # Revocation
    revocation_check: OCSP stapling + CRL
    revocation_provider: DigiCert/Sectigo
```

### Key Storage and Access Control

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Access Architecture                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │ Developer    │     │ CI/CD System │                       │
│  │ Workstation  │     │ (GitHub,     │                       │
│  │              │     │  GitLab,     │                       │
│  │ ┌──────────┐│     │  Jenkins)    │                       │
│  │ │YubiKey   ││     │              │                       │
│  │ │(Release  ││     │ ┌──────────┐ │                       │
│  │ │ Signing) ││     │ │ Service  │ │                       │
│  │ └──────────┘│     │ │ Account  │ │                       │
│  └──────────────┘     │ │ (HSM)    │ │                       │
│                       │ └──────────┘ │                       │
│  ┌──────────────┐     │              │                       │
│  │ Release      │     │ ┌──────────┐ │                       │
│  │ Manager      │     │ │OIDC Token│ │                       │
│  │ (Approval)  │────▶│ │(Temp)    │ │                       │
│  └──────────────┘     │ └──────────┘ │                       │
│                       └──────┬───────┘                       │
│                              │                                │
│                       ┌──────▼───────┐                       │
│                       │     HSM      │                        │
│                       │ (Signing Key)│                        │
│                       └──────────────┘                       │
│                                                              │
│  Access Controls:                                            │
│  - MFA required for key access                               │
│  - Quorum: 2-of-3 approval for production signing            │
│  - Audit logging for all signing operations                  │
│  - Rate limiting on signing operations                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Stolen Signing Key Incidents

### NVIDIA Code Signing Certificate Leak (2022)

In March 2022, the Lapsus$ group breached NVIDIA and leaked two code signing certificates:

- **Certificate 1**: `NVIDIA Windows GPU Display Driver` (expired 2014, but trusted by Windows Driver Signature Enforcement)
- **Certificate 2**: `NVIDIA Windows GPU Display Driver` (expired 2018, similarly trusted)

Despite the certificates being expired, Windows allows the installation of drivers signed with expired certificates if the timestamp within the signature predates the expiration date. This means the certificates could still be used to sign malware that would bypass Windows Driver Signature Enforcement:

```bash
# Signing malware with the leaked NVIDIA certificate
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f nvidia_cert.pfx malware.sys

# Windows Driver Signature Enforcement would accept this signature
# because the timestamp predates the certificate expiration
```

**Impact:** The leaked certificates were used in the wild to sign rootkits, bootkits, and other kernel-level malware. Malware families like **Aleither** and **Swell** were observed using the NVIDIA certificate.

**Lessons:**
1. Expired certificates can still be valid for signature verification if timestamped before expiration
2. Code signing certificates must be properly protected and monitored
3. Certificate revocation checking is not reliably performed by most operating systems
4. HSM-based key storage should be mandatory for code signing

### Samsung Code Signing Certificate Leak (2022)

The same Lapsus$ group also leaked Samsung's code signing certificates:

- **Certificate**: `Samsung Electronics Co., Ltd.` (expired 2019)
- **Usage**: Samsung mobile device firmware signing
- **Impact**: The certificate could be used to sign Android APKs that would bypass Samsung's verification

### Lenovo CA Key Compromise (2019)

Lenovo's Certificate Authority key was compromised, allowing attackers to issue certificates that would be trusted by any system that trusted the Lenovo CA:

- **Certificate Authority**: `Lenovo Ltd.`
- **Impact**: An attacker with the CA key could issue code signing certificates, TLS certificates, or any other type of certificate trusted by systems with the Lenovo CA in their trust store
- **Root cause**: The CA key was stored in a location that was not properly secured
- **Remediation**: Lenovo had to push updates to revoke the CA certificate across all Lenovo systems

### D-Link Code Signing Certificate (2020)

D-Link's code signing certificate was found on a publicly accessible server:

- **Certificate**: D-Link Systems, Inc. code signing certificate
- **Discovery**: Found by researchers on a public-facing server without password protection
- **Impact**: Could be used to sign malicious software that would appear to come from D-Link
- **D-Link's response**: Revoked the certificate, but as with all certificate revocation, the effectiveness depends on the revocation checking behavior of the verifying system

---

## Transparency Logs

### Certificate Transparency (RFC 6962)

Certificate Transparency (CT) is a framework for monitoring and auditing TLS certificate issuance. CT logs are append-only, cryptographically verifiable logs of all certificates issued by participating CAs:

```bash
# Query CT logs for certificates issued for a domain
curl "https://crt.sh/?q=%.example.com&output=json" | \
  jq '.[] | {issuer: .issuer_name, not_before: .not_before, not_after: .not_after}'

# Monitor CT logs for unauthorized certificates
# (Using certstream)
certstream --output json | jq 'select(.data.issuer.Org != "MyCompany")'
```

While CT was designed for TLS certificates, the same principles apply to code signing certificates. Certificate Authorities that issue code signing certificates should log them in CT logs, allowing organizations to monitor for unauthorized certificates issued in their name.

### Rekor (Sigstore Transparency Log)

Rekor is Sigstore's transparency log for signing events. It records all signature operations performed with Sigstore, creating an immutable, auditable log:

```bash
# Search Rekor for entries related to an image
rekor-cli search --artifact my-app.tar.gz

# Search by hash
rekor-cli search --sha abc123def456...

# Verify an entry in the transparency log
rekor-cli verify --artifact my-app.tar.gz --signature my-app.tar.gz.sig \
  --public-key rekor.pub

# Get entry details
rekor-cli get --uuid 1234567890abcdef...

# List entries by certificate issuer
rekor-cli search --issuer https://accounts.google.com
```

**Rekor entry structure:**

```json
{
  "attestation": {
    "type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://slsa.dev/provenance/v0.2",
    "subject": [
      {
        "name": "registry.npmjs.org/my-package/1.0.0",
        "digest": {
          "sha256": "abc123..."
        }
      }
    ],
    "predicate": {
      "builder": {
        "id": "https://github.com/actions/runner"
      },
      "buildType": "https://github.com/actions/workflow",
      "invocation": {
        "configSource": {
          "uri": "https://github.com/myorg/my-repo/blob/main/.github/workflows/ci.yml",
          "digest": {"sha1": "def456..."}
        }
      }
    }
  },
  "signature": {
    "keyid": "",
    "sig": "MEUCIQD..."
  },
  "integratedTime": 1700000000,
  "logIndex": 12345678,
  "logID": "c0d23d6..."
}
```

---

## Sigstore and Cosign

### Sigstore Architecture

Sigstore is an open-source project that provides keyless code signing and transparency logging. It eliminates the need for developers to manage signing keys by using OIDC (OpenID Connect) identity tokens for authentication:

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Developer  │────▶│    Fulcio     │────▶│    Rekor     │
│   (Signer)   │     │   (CA/Signer) │     │   (Log)      │
│              │     │               │     │              │
│  1. Auth via │     │  2. Issue     │     │  3. Record   │
│     OIDC     │     │     certificate│    │     entry    │
│              │     │               │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                      │
                            ▼                      ▼
                     ┌──────────────────────────────────┐
                     │     Verification Bundle          │
                     │  (certificate + signature +      │
                     │   transparency log entry)         │
                     └──────────────────────────────────┘
```

### Cosign for Container Signing

Cosign is the primary tool in the Sigstore ecosystem for container image signing:

```bash
# Keyless signing with Sigstore (uses OIDC identity)
cosign sign registry.example.com/my-app:v1.2.3

# Key-based signing
cosign sign --key cosign.key registry.example.com/my-app:v1.2.3

# Sign with a specific identity
cosign sign --identity-token $OIDC_TOKEN registry.example.com/my-app:v1.2.3

# Verify a keyless signature
cosign verify registry.example.com/my-app:v1.2.3 \
  --certificate-identity=my-ci@mycompany.iam.gserviceaccount.com \
  --certificate-oidc-issuer=https://accounts.google.com

# Verify a key-based signature
cosign verify --key cosign.pub registry.example.com/my-app:v1.2.3

# Sign and attach an SBOM
cosign sign registry.example.com/my-app:v1.2.3
syft registry.example.com/my-app:v1.2.3 -o cyclonedx-json | \
  cosign attach sbom --sbom - registry.example.com/my-app:v1.2.3

# Verify SBOM attachment
cosign verify-blob-attachment --attachment sbom registry.example.com/my-app:v1.2.3
```

### Signing in CI/CD

```yaml
# .github/workflows/sign-and-publish.yml
name: Sign and Publish
on:
  release:
    types: [published]

jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # Required for OIDC/Sigstore
      contents: read
    steps:
      - uses: actions/checkout@v4
      
      - name: Build container image
        run: |
          docker build -t registry.example.com/my-app:${{ github.ref_name }} .
          docker push registry.example.com/my-app:${{ github.ref_name }}
      
      - name: Sign container image
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
            registry.example.com/my-app:${{ github.ref_name }}
      
      - name: Generate and sign SBOM
        run: |
          syft registry.example.com/my-app:${{ github.ref_name }} -o cyclonedx-json > sbom.json
          cosign attest --yes \
            --predicate sbom.json \
            --type cyclonedx \
            registry.example.com/my-app:${{ github.ref_name }}
      
      - name: Sign artifacts with SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
        with:
          image: registry.example.com/my-app
          digest: ${{ steps.build.outputs.digest }}
```

---

## npm Provenance Signing

### How npm Provenance Works

npm provenance linking was introduced in 2023 to provide a verifiable link between a published npm package and its source code and build process:

```bash
# Publish with provenance
npm publish --provenance --access public

# Verify provenance for an installed package
npm view my-package --json | jq '.provenance'

# Audit signatures
npm audit signatures
```

**Provenance attestation contents:**

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "pkg:npm/my-package@1.0.0",
      "digest": {
        "sha512": "abc123..."
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
        "uri": "https://github.com/myorg/my-repo/blob/main/.github/workflows/publish.yml",
        "digest": {
          "sha1": "def456..."
        },
        "entryPoint": "publish"
      },
      "environment": {
        "github_actor": "maintainer",
        "github_run_id": "12345678",
        "github_sha": "abc123..."
      }
    },
    "materials": [
      {
        "uri": "https://github.com/myorg/my-repo",
        "digest": {
          "sha1": "abc123..."
        }
      }
    ]
  }
}
```

---

## PGP Key Verification Challenges

### The PGP Web of Trust Problem

PGP/GPG signing is used for Git commit signing, package signing (particularly in the Linux ecosystem), and email verification. However, the PGP web of trust model has fundamental challenges:

1. **Key discovery**: There is no reliable mechanism to discover which PGP key belongs to which developer
2. **Key verification**: Verifying the authenticity of a PGP key requires manual fingerprint verification or trusting a web of trust
3. **Key rotation**: When a developer's PGP key is compromised, there is no reliable mechanism to revoke the key across all consumers
4. **Keyserver attacks**: PGP keyservers are vulnerable to certificate spamming, making them unreliable

### GPG Keyserver Attacks

The SKS (Synchronizing Key Server) network, which was the primary PGP keyserver infrastructure, was taken offline in 2019 after a sustained certificate flooding attack:

- An attacker uploaded millions of forged PGP certificates to the keyservers
- These certificates were larger than normal and consumed disproportionate storage and bandwidth
- The SKS reconciliation protocol caused the flooding to propagate across all keyservers
- The keyservers could not be cleaned without wiping all data

**Remediation for PGP key verification:**

```bash
# Instead of using keyservers, use verified key sources
# 1. Download keys from the developer's website over HTTPS
curl -O https://example.com/developer.asc

# 2. Verify the key fingerprint manually
gpg --show-keys developer.asc

# 3. Sign the key locally
gpg --sign-key developer@example.com

# 4. Use keys.openpgp.org (HKPS keyserver with verification)
gpg --keyserver hkps://keys.openpgp.org --recv-keys ABCDEF12

# 5. For Git commit signing verification
git log --show-signature
git verify-commit HEAD
git verify-tag v1.0.0
```

### Git Commit Signing

```bash
# Configure Git to sign commits
git config --global commit.gpgsign true
git config --global gpg.program gpg
git config --global user.signingkey ABCDEF1234567890

# Sign a commit
git commit -S -m "Signed commit"

# Sign a tag
git tag -s v1.0.0 -m "Signed release v1.0.0"

# Verify a commit
git verify-commit HEAD

# Verify a tag
git verify-tag v1.0.0

# Configure GitHub to show commit verification status
# GitHub automatically verifies GPG-signed commits against keys uploaded to user accounts
```

---

## Reproducible Builds

### Debian Reproducible Builds

The Debian Reproducible Builds project has been working since 2013 to ensure that Debian packages can be reproduced bit-for-bit from source:

```bash
# Install reproducible build tools
apt install diffoscope reprotest

# Compare two build outputs
diffoscope build1/mypackage.deb build2/mypackage.deb

# Test a package build for reproducibility
reprotest 'dpkg-buildpackage -uc -us' '../mypackage_1.0.0-1_amd64.deb'

# Build with deterministic timestamps
export SOURCE_DATE_EPOCH=$(date +%s)
export TZ=UTC
export LC_ALL=C
dpkg-buildpackage -uc -us
```

**Common sources of non-reproducibility in Debian:**

| Source | Mitigation |
|--------|-----------|
| Build timestamps | `SOURCE_DATE_EPOCH` environment variable |
| Filesystem ordering | `LC_ALL=C` for deterministic sorting |
| Locale-dependent output | `LC_ALL=C`, `TZ=UTC` |
| GCC build ID | `--build-id=sha1` for deterministic build IDs |
| Python `.pyc` files | `SOURCE_DATE_EPOCH` for timestamp |
| Documentation generation | Fixed date/time in man page generation |

### Arch Linux Reproducible Builds

Arch Linux has also implemented reproducible builds:

```bash
# Build a package reproducibly
makepkg --syncdeps --rmdeps --cleanbuild

# Verify reproducibility
makepkg --verifysource

# Compare with official package
diffoscope mypackage-1.0.0-1-x86_64.pkg.tar.zst \
  official/mypackage-1.0.0-1-x86_64.pkg.tar.zst
```

### Reproducible Build Verification Architecture

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Builder A   │     │   Builder B   │     │   Builder C   │
│   (Debian)    │     │   (Arch)      │     │   (NixOS)     │
│               │     │               │     │               │
│  Build from   │     │  Build from   │     │  Build from   │
│  source       │     │  source       │     │  source       │
└───────┬───────┘     └───────┬───────┘     └───────┬───────┘
        │                     │                     │
        │  Artifact hash     │  Artifact hash      │  Artifact hash
        │  sha256:abc...     │  sha256:abc...      │  sha256:abc...
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                     ┌────────▼────────┐
                     │   Verification  │
                     │   Service       │
                     │                 │
                     │  If hashes      │
                     │  match:         │
                     │  ✓ Reproducible │
                     │                 │
                     │  If hashes      │
                     │  differ:        │
                     │  ✗ Investigate  │
                     └─────────────────┘
```

### Reproducibility in Practice: Example

```dockerfile
# Non-reproducible Dockerfile
FROM node:20
WORKDIR /app
COPY . .
RUN npm install
RUN npm run build
# Problem: timestamps, random values, locale-dependent sorting

# Reproducible Dockerfile
FROM node:20-slim

# Set deterministic environment
ENV SOURCE_DATE_EPOCH=1700000000
ENV TZ=UTC
ENV LC_ALL=C
ENV NODE_OPTIONS=--max-old-space-size=4096

WORKDIR /app

# Copy only necessary files with deterministic order
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY src/ ./src/
COPY tsconfig.json ./

# Build with deterministic settings
RUN npm run build

# Strip timestamps from output
RUN find /app/dist -exec touch -d "2024-01-01T00:00:00Z" {} \;

# Verify reproducibility (compare hash)
RUN sha256sum /app/dist/main.js > /app/dist/main.js.sha256
```

---

## Supply Chain Integrity Through Signing

### The Signing and Verification Chain

```
Source Code → Build → Sign → Attest → Publish → Verify → Deploy

1. Source: Git commit (signed with GPG/Sigstore)
2. Build: CI/CD pipeline (recorded in provenance)
3. Sign: Sign artifact with Sigstore/HSM key
4. Attest: Create attestation (SBOM, provenance, VEX)
5. Publish: Push to registry with attached signatures and attestations
6. Verify: Consumer verifies signature, provenance, and attestation
7. Deploy: Only deploy verified artifacts
```

**Implementation:**

```yaml
# .github/workflows/release.yml - Complete signing pipeline
name: Release with Supply Chain Integrity
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      
      - name: Build
        run: make build
      
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: my-app:${{ github.ref_name }}
          format: cyclonedx-json
      
      - name: Sign container image
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes registry.example.com/my-app:${{ github.ref_name }}
      
      - name: Attach SBOM attestation
        run: |
          cosign attest --yes \
            --predicate sbom.cdx.json \
            --type cyclonedx \
            registry.example.com/my-app:${{ github.ref_name }}
      
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
```

**Verification by consumer:**

```bash
# Verify the complete supply chain
cosign verify \
  --certificate-identity=https://github.com/myorg/my-repo/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  registry.example.com/my-app:v1.2.3

# Verify SBOM attestation
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity=https://github.com/myorg/my-repo/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  registry.example.com/my-app:v1.2.3

# Verify SLSA provenance
slsa-verifier verify-image registry.example.com/my-app:v1.2.3 \
  --source-uri github.com/myorg/my-repo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml
```

---

## References

1. Sigstore. "Cosign: Container Signing." https://github.com/sigstore/cosign
2. Sigstore. "Rekor: Transparency Log." https://github.com/sigstore/rekor
3. Sigstore. "Fulcio: Certificate Authority." https://github.com/sigstore/fulcio
4. SLSA Specification v1.0. "Provenance Format." https://slsa.dev/provenance/
5. npm Documentation. "Provenance." https://docs.npmjs.com/generating-provenance-statements
6. Debian Reproducible Builds Project. https://reproducible-builds.org/
7. CISA. "Securing the Software Supply Chain: Code Signing." https://www.cisa.gov/sbom
8. Microsoft. "Code Signing Best Practices." https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
9. NIST SP 800-218. "Secure Software Development Framework (SSDF)." https://csrc.nist.gov/publications/detail/sp/800-218/final
10. RFC 6962. "Certificate Transparency." https://datatracker.ietf.org/doc/html/rfc6962
11. RFC 5652. "Cryptographic Message Syntax (CMS)." https://datatracker.ietf.org/doc/html/rfc5652
12. NVIDIA Security Advisory. "NVIDIA Code Signing Certificate Leak." 2022. https://nvidia.custhelp.com/app/answers/detail/a_id/5333
13. Lapsus$. "Samsung and NVIDIA Data Leak." 2022.
14. D-Link Advisory. "Code Signing Certificate Found on Public Server." 2020.