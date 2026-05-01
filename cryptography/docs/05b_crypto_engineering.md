# Applied Crypto Engineering

> Engineering practices for deploying cryptographic systems safely: key management lifecycles, HSM architecture, envelope encryption, certificate lifecycle, CSPRNG pitfalls, threshold cryptography, secret sharing, zero-knowledge proofs, homomorphic encryption, and secure multi-party computation.

---

## Table of Contents

1. [Key Management Lifecycle](#1-key-management-lifecycle)
2. [HSM Architecture](#2-hsm-architecture)
3. [Key Rotation Strategies](#3-key-rotation-strategies)
4. [Envelope Encryption](#4-envelope-encryption)
5. [Certificate Lifecycle Management](#5-certificate-lifecycle-management)
6. [CSPRNG Implementation Dangers](#6-csprng-implementation-dangers)
7. [Threshold Cryptography](#7-threshold-cryptography)
8. [Secret Sharing](#8-secret-sharing)
9. [Zero-Knowledge Proofs](#9-zero-knowledge-proofs)
10. [Homomorphic Encryption](#10-homomorphic-encryption)
11. [Secure Multi-Party Computation](#11-secure-multi-party-computation)

---

## 1. Key Management Lifecycle

### 1.1 Key States

A cryptographic key progresses through the following lifecycle states:

```
Generation → Activation → Use → Deactivation → Destruction
                ↕              ↕
            Suspension     Archive
```

1. **Generation**: The key is created using a CSPRNG. The key's properties (algorithm, length, purpose, expiry) are defined in a key policy.

2. **Activation**: The key is made available for cryptographic operations (encryption, signing, etc.). The key may be distributed to other parties or wrapped under a key encryption key (KEK).

3. **Use**: The key is actively used for cryptographic operations. The key's usage count or time-in-use is tracked against the key policy's maximum usage limits.

4. **Deactivation**: The key is no longer used for new operations but remains available for decryption/verification of data encrypted/signed during the activation period. This is the "rollover" state.

5. **Archive**: The key is stored long-term for regulatory compliance or disaster recovery. Archived keys should be stored in a separate, access-controlled location (e.g., an offline HSM or air-gapped storage).

6. **Destruction**: The key is permanently erased. All copies of the key (in memory, on disk, in backups) must be destroyed. NIST SP 800-88 provides guidance on media sanitization.

### 1.2 Key Hierarchy

A well-designed key management system uses a hierarchy of keys:

```
Master Key (MK) — HSM-protected, never leaves the HSM
  ├── Key Encryption Key (KEK) — encrypts data keys
  │     ├── Data Encryption Key (DEK) — encrypts application data
  │     ├── DEK — encrypts application data
  │     └── DEK — encrypts application data
  ├── Signing Key (SK) — signs certificates and audit logs
  └── Transport Key (TK) — encrypts keys in transit between systems
```

The **master key** is the root of trust. It is generated inside the HSM and never exported. All other keys are derived from or encrypted under the master key.

### 1.3 Key Policy

Each key has a policy that defines:

- **Algorithm and key length**: e.g., AES-256-GCM, RSA-4096, ML-KEM-1024.
- **Purpose**: encryption, signing, key wrapping, authentication. Keys should not be used for multiple purposes (see §01a: key separation).
- **Maximum usage**: Maximum number of operations (encryptions, signatures) before mandatory rotation.
- **Maximum lifetime**: Maximum time the key can be in the "Active" state.
- **Rotation schedule**: How often the key must be rotated and the overlap period (the time during which both the old and new keys are active for decryption).
- **Access control**: Who can use the key, who can export the key, who can destroy the key.
- **Backup policy**: Whether and how the key is backed up (e.g., split across two HSMs, stored in an offline safe).

### 1.4 Key Derivation and Key Separation

Keys for different purposes should be derived from a master secret using a KDF with purpose-specific info parameters:

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_keys(master_secret):
    """Derive purpose-specific keys from a master secret."""
    # Key encryption key
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'key-encryption-v1',
        info=b'kek'
    ).derive(master_secret)
    
    # Data encryption key
    dek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'data-encryption-v1',
        info=b'dek'
    ).derive(master_secret)
    
    # MAC key
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'mac-v1',
        info=b'mac'
    ).derive(master_secret)
    
    return kek, dek, mac_key
```

**Key separation principle**: Never use the same key for encryption and authentication, or for key wrapping and data encryption. Using a key for multiple purposes can lead to devastating attacks (e.g., using an AES encryption key as an HMAC key may allow a related-key attack).

---

## 2. HSM Architecture

### 2.1 HSM Form Factors

| Form Factor | Typical Use | Key Storage | Performance | Tamper Resistance |
|---|---|---|---|---|
| PCIe card | Server co-processing | Internal NVRAM | 10,000 RSA-2048/s | FIPS 140-2 Level 3 |
| Network HSM | Enterprise key management | Encrypted on SSD | 5,000 RSA-2048/s | FIPS 140-2 Level 3 |
| Cloud HSM | Cloud-native | Cloud provider managed | 3,000 RSA-2048/s | FIPS 140-2 Level 3 |
| USB token | Individual user | Smart card chip | 50 RSA-2048/s | FIPS 140-2 Level 2 |
| Embedded SE | IoT/phone | Secure element die | 10 RSA-2048/s | FIPS 140-2 Level 4 (eval) |

### 2.2 HSM Security Architecture

An HSM's security architecture consists of multiple layers:

1. **Physical tamper detection**: The HSM enclosure contains tamper detection circuits that sense voltage, temperature, and physical intrusion. When a tamper event is detected, the HSM zeroizes all keys in NVRAM within milliseconds.

2. **Cryptographic boundary**: All cryptographic operations occur within the HSM's protected boundary. Keys never leave the HSM in plaintext — they are generated inside the HSM, used inside the HSM, and destroyed inside the HSM.

3. **Access control**: HSM access is controlled through role-based authentication:
   - **Security Officer (SO)**: Manages the HSM, creates compartments, sets policies.
   - **Crypto Officer (CO)**: Manages keys within a compartment.
   - **Crypto User (CU)**: Uses keys for cryptographic operations (sign, encrypt, decrypt).
   
   Access to key material is restricted by key policy: some keys can only be used for specific operations (sign-only, decrypt-only).

4. **Audit logging**: All HSM operations are logged to an internal audit trail that cannot be modified or deleted. The audit log includes timestamps, user IDs, operation types, and key handles.

### 2.3 PKCS#11 and HSM APIs

PKCS#11 (Cryptoki) is the standard API for interacting with HSMs. Key concepts:

- **Slot**: A logical reader that may contain a token (HSM).
- **Token**: A logical device that stores objects (keys, certificates, data).
- **Session**: A connection to a token. Sessions can be public (read-only) or private (read-write, requires authentication).
- **Object**: A PKCS#11 object with attributes (type, class, key type, value, etc.).

```c
// PKCS#11 key generation example
CK_SESSION_HANDLE hSession;
CK_OBJECT_HANDLE hKey;
CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, NULL_PTR, 0};
CK_ULONG keyLength = 32;  // AES-256

CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &keyClass, sizeof(keyClass)},
    {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)},
    {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
    {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
    {CKA_EXTRACTABLE, &bFalse, sizeof(bFalse)},  // Key cannot be exported
    {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},       // Key is sensitive
};

CK_RV rv = pFunctionList->C_GenerateKey(hSession, &mechanism, template, 
                                          sizeof(template)/sizeof(CK_ATTRIBUTE), 
                                          &hKey);
```

**PKCS#11 security considerations**:
- Set `CKA_EXTRACTABLE = false` on all sensitive keys to prevent export.
- Set `CKA_SENSITIVE = true` on all keys preventing `C_GetAttributeValue` from revealing key material.
- Use `CKA_TRUSTED = true` only on keys explicitly authorized for key wrapping.
- Never use `CKA_WRAP_WITH_TRUSTED = false` on keys that should only be wrapped by trusted keys.
- Use `CKA_NEVER_EXTRACTABLE = true` on master keys to prevent extraction even by the SO.

---

## 3. Key Rotation Strategies

### 3.1 Key Rotation Approaches

**In-place rotation**: Generate a new key and update the key metadata (key version, activation date) without changing the key identifier. The old key is marked as "deactivated" but remains available for decryption of existing data.

**Dual-key rotation**: During the rotation period, both the old key and the new key are active for decryption, but only the new key is used for encryption. This requires a "grace period" during which the old key can decrypt data that was encrypted before the rotation.

**Re-encryption**: After rotation, all data encrypted under the old key is re-encrypted under the new key. This is computationally expensive for large datasets but ensures that the old key can be safely destroyed.

**Hybrid rotation**: A combination of dual-key and re-encryption. New data is encrypted under the new key, and a background process re-encrypts old data under the new key. The old key is destroyed once all data has been re-encrypted.

### 3.2 Automatic Key Rotation

AWS KMS, Google Cloud KMS, and Azure Key Vault all support automatic key rotation:

- **AWS KMS**: Automatic key rotation generates a new key material annually while preserving the key ID. The old key material remains available for decryption. Key policies control who can use each version.
- **Google Cloud KMS**: Automatic key rotation at configurable intervals (90 days, 1 year). Key versions are immutable; new versions are created automatically.
- **Azure Key Vault**: Automatic key rotation with configurable lifetime and overlap period. Supports both automatic and manual rotation.

### 3.3 Key Rotation for Different Cryptographic Uses

| Use Case | Rotation Frequency | Method | Rationale |
|---|---|---|---|
| Data encryption keys (DEK) | Per-object or daily | KEK-wrapped, envelope encryption | Limit impact of key compromise |
| Key encryption keys (KEK) | Annually | HSM-protected, dual-key | KEK compromise affects all DEKs |
| TLS certificate keys | 90 days (Let's Encrypt) or 1 year | Certificate reissuance | Browser trust store requirements |
| Code signing keys | 1–3 years | HSM-protected, offline CA | Long-lived, high-value |
| Root CA keys | 10–25 years | Offline HSM, ceremony-based | Extremely long-lived, high-value |
| SSH host keys | At OS install or annually | Manual or configuration management | Host identity |
| SSH user keys | 1 year or per-project | Agent-forwarded, FIDO-protected | User identity |

---

## 4. Envelope Encryption

### 4.1 The Envelope Encryption Model

Envelope encryption is the standard model for cloud-scale key management, used by AWS KMS, Google Cloud KMS, and Azure Key Vault:

1. **Data Encryption Key (DEK)**: A symmetric key (typically AES-256) generated for each encryption operation or object. The DEK encrypts the plaintext data.

2. **Key Encryption Key (KEK)**: A long-lived symmetric key stored in the KMS/HSM. The KEK encrypts the DEK (wrapping it in an "envelope").

3. **Envelope**: The encrypted data is stored alongside the encrypted DEK:
```
Stored object = IV || ciphertext || encrypted_DEK || tag
```
where `ciphertext = AES-GCM(DEK, plaintext, IV, AAD)` and `encrypted_DEK = AES-GCM(KEK, DEK)`.

### 4.2 AWS KMS Envelope Encryption

AWS KMS implements envelope encryption as follows:

1. The client calls `GenerateDataKey` with a KMS key ID. KMS generates a DEK and returns both the plaintext DEK and the encrypted DEK (wrapped under the KMS key).
2. The client encrypts the data using the plaintext DEK and discards the plaintext DEK from memory.
3. The client stores the encrypted data alongside the encrypted DEK.
4. To decrypt, the client calls `Decrypt` with the encrypted DEK. KMS decrypts the DEK (after checking IAM permissions) and returns the plaintext DEK.
5. The client decrypts the data using the plaintext DEK.

**Key benefits**:
- The KMS key (KEK) never leaves the HSM. Only the DEK is transmitted, and only the encrypted DEK is stored.
- The DEK is short-lived (generated per encryption, discarded after use). Compromise of the DEK affects only the data encrypted under that specific DEK.
- The KMS key can be rotated without re-encrypting existing data. New data is encrypted under the new key version, but old data remains encrypted under the original key version (which is still available for decryption).

### 4.3 Key Hierarchies in Practice

```
Root CA Key (offline HSM)
  ├── Intermediate CA Key (online HSM)
  │     ├── TLS Certificate Key (server)
  │     ├── TLS Certificate Key (server)
  │     └── TLS Certificate Key (server)
  └── Master KEK (KMS HSM)
        ├── DEK (object 1)
        ├── DEK (object 2)
        └── DEK (object 3)
```

The root CA key is stored in an offline HSM (air-gapped, in a safe) and used only for signing intermediate CA certificates during ceremonies. The intermediate CA key is stored in an online HSM and used for daily certificate issuance. The master KEK rotates annually; old key versions are retained for decryption.

---

## 5. Certificate Lifecycle Management

### 5.1 Certificate Lifecycle

A certificate progresses through the following states:

1. **Request**: The subject generates a key pair and submits a Certificate Signing Request (CSR) to a CA. The CSR contains the subject's public key, distinguished name, and requested extensions.

2. **Issuance**: The CA validates the CSR (domain ownership via ACME, organizational identity via EV/OV) and issues a certificate signed by the CA's private key.

3. **Deployment**: The certificate and private key are deployed to the target system (web server, API gateway, load balancer, etc.).

4. **Monitoring**: The certificate's validity is monitored. Approaching expiration triggers a renewal workflow.

5. **Renewal**: A new key pair is generated, and a new certificate is issued. The old and new certificates may coexist during the overlap period (grace period).

6. **Revocation**: If the certificate's private key is compromised or the certificate is no longer needed, it is revoked by the CA. Revocation is published via CRL and OCSP (see §03b).

7. **Expiration**: The certificate passes its `notAfter` date and is no longer valid.

### 5.2 ACME Protocol

The Automated Certificate Management Environment (ACME, RFC 8555) is the standard protocol for automated certificate issuance. Let's Encrypt uses ACME to issue certificates to millions of domains.

**ACME challenge types**:
- **HTTP-01**: Place a file at `http://domain/.well-known/acme-challenge/<token>`. The ACME server verifies the file's content.
- **DNS-01**: Create a TXT record at `_acme-challenge.domain` with the challenge value. The ACME server verifies the DNS record.
- **TLS-ALPN-01**: Serve a self-signed certificate with the ACME OID in the ALPN extension. The ACME server verifies the certificate.

**ACME security considerations** (see §03b for detailed analysis):
- **HTTP-01**: Vulnerable to network-level MITM (the attacker can intercept HTTP requests and answer the challenge). Mitigated by requiring HTTPS for the challenge file (RFC 8737).
- **DNS-01**: Vulnerable to DNS hijacking or spoofing. Mitigated by DNSSEC and DNS-over-HTTPS.
- **TLS-ALPN-01**: Vulnerable to TLS MITM (the attacker can present a self-signed certificate with the ACME OID). Mitigated by requiring the certificate to be signed by a trusted CA.

### 5.3 Certificate Monitoring and Alerting

Large organizations manage thousands of certificates across hundreds of systems. Certificate management tools (Venafi, HashiCorp Vault, AWS Certificate Manager, cert-manager for Kubernetes) provide:

- **Certificate discovery**: Scan the network for TLS certificates, identify expiring or misconfigured certificates.
- **Automated renewal**: Automatically renew certificates before expiration using ACME or internal CA APIs.
- **Policy enforcement**: Require specific key sizes, algorithms, and extensions. Flag certificates that violate policy (e.g., SHA-1 signing, 1024-bit RSA, wildcard certificates).
- **Revocation checking**: Monitor CRLs and OCSP for certificate revocation. Alert on revoked certificates.

---

## 6. CSPRNG Implementation Dangers

### 6.1 Dual_EC_DRBG (CVE-2007-6755)

Dual_EC_DRBG was one of four DRBGs standardized in NIST SP 800-90 (2006). It was designed by NSA with a backdoor: the algorithm uses two elliptic curve points $P$ and $Q$ on NIST P-256, and if the adversary knows the discrete logarithm $d = \log_P(Q)$ (i.e., $Q = [d]P$), they can predict the DRBG's output from a single 30-byte sample.

**The backdoor**: The DRBG's state transition is:

$$s_{i+1} = \phi_x([s_i]P), \quad o_i = \phi_x([s_i]Q)$$

where $\phi_x$ extracts the x-coordinate from the point. If the adversary knows $d$ such that $Q = [d]P$, then:

$$o_i = \phi_x([s_i]Q) = \phi_x([d \cdot s_i]P)$$

Given $o_i$ (the output), the adversary can try all possible values for the 16 unknown bits of $s_{i+1}$ (the output is 30 bytes = 240 bits, but the state is 256 bits, leaving 16 unknown bits). For each candidate, they compute $o_{i+1} = \phi_x([s_{i+1}]Q)$ and check whether it matches the observed output. This requires only $2^{16}$ operations — trivially feasible.

**Disclosure**: The backdoor was disclosed by Microsoft researchers Dan Shumow and Niels Ferguson at Crypto 2007. The Snowden leaks (2013) confirmed that NSA had paid RSA Security $10M to make Dual_EC_DRBG the default DRBG in BSAFE.

**Affidavit**: The points $P$ and $Q$ were chosen by NSA and not generated in a verifiable way. There is no known method to choose $P$ and $Q$ such that $Q = [d]P$ for a known $d$ unless they were generated in the order $P$ first, then $d$, then $Q = [d]P$ (or vice versa).

**Mitigation**: NIST removed Dual_EC_DRBG from SP 800-90A Rev. 1 (2015). All implementations should use HMAC-DRBG, CTR-DRBG, or Hash-DRBG instead.

### 6.2 Debian OpenSSL Bug (CVE-2007-4995)

In 2006, a Debian maintainer removed the "uninitialized variable" warning from OpenSSL's `ssleay_rand_add()` function by commenting out the line that mixed `/dev/urandom` output into the PRNG state:

```c
// Before (OpenSSL 0.9.8c):
MD_Update(&m,buf,j);        /* mix in the data */
// After (Debian patch):
// MD_Update(&m,buf,j);     /* removed: valgrind complained about uninitialized data */
```

The removed line was the **only source of entropy** in the PRNG seeding. Without it, the PRNG was seeded only with the process ID (PID), which is a 15-bit value (range 0–32768).

**Impact**: All SSH and TLS keys generated on Debian and Ubuntu systems between September 2006 and May 2008 were effectively chosen from a set of $2^{16} = 65{,}536$ possible keys for each key size. This made all such keys trivially breakable by exhaustive search.

**Discovery**: The bug was discovered in May 2008 by Luciano Bello, a Debian developer, who noticed that SSH keys generated on his system were suspiciously weak.

**Recovery**: The Debian project released an advisory and a tool to check whether a key was generated with the vulnerable OpenSSL version. All affected keys had to be regenerated. Ubuntu and Debian posted lists of vulnerable keys for SSH, SSL/TLS, OpenVPN, and DNSSEC.

**Lessons**:
1. **Never mix security code with debugging tools**: The Valgrind warning that prompted the patch was a false positive (the uninitialized data was intentional entropy mixing). Security code should be reviewed by security experts, not general developers.
2. **CSPRNGs must have strong entropy sources**: Relying on a single entropy source (PID) is catastrophic. Use `/dev/urandom`, `getrandom(2)`, or OS-provided CSPRNGs.
3. **Test CSPRNG output**: Statistical tests (NIST SP 800-22, Dieharder) would have detected the severely limited entropy, but they were not run on the Debian-patched version.

### 6.3 Android Java CSPRNG Bug (CVE-2013-4787)

The Apache Harmony implementation of `java.security.SecureRandom` on Android had a bug where the PRNG state was not properly initialized when the seed was set. The `setSeed()` method did not mix the new seed into the existing state; instead, it replaced the state, discarding any previously accumulated entropy.

This affected Bitcoin wallets on Android: the PRNG generated weak ECDSA nonces, enabling private key recovery from two signatures with the same nonce (see §02a: ECDSA nonce reuse).

**Impact**: Multiple Bitcoin wallets on Android were compromised, with attackers stealing the private keys and draining the wallets.

**Fix**: Android 4.2 patched `SecureRandom` to properly mix new seeds into the existing state. The recommended workaround for pre-4.2 devices was:

```java
// Workaround for Android SecureRandom bug
SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
sr.setSeed(System.nanoTime());  // Add additional entropy
// On Android < 4.2, always re-seed before each use
```

### 6.4 Best Practices for CSPRNG Usage

1. **Use the OS CSPRNG**: On Linux, use `getrandom(2)` or `/dev/urandom`. On Windows, use `BCryptGenRandom`. On macOS/iOS, use `SecRandomCopyBytes`. Never implement your own PRNG.

2. **Never use `rand()`, `random()`, or `Math.random()` for cryptographic purposes**: These are not CSPRNGs and are trivially predictable.

3. **Reseed from the OS CSPRNG after fork()**: After a `fork()`, the child process inherits the parent's PRNG state, leading to duplicate output. Reseed immediately after forking.

4. **Use constant-time comparison for tokens**: When comparing tokens (session IDs, CSRF tokens, API keys), use constant-time comparison to prevent timing attacks.

5. **Handle entropy starvation gracefully**: On embedded systems with limited entropy sources, block until sufficient entropy is available rather than generating weak randomness.

---

## 7. Threshold Cryptography

### 7.1 Threshold Secret Sharing

Threshold secret sharing (see §8 for details) splits a secret into $n$ shares such that any $k$ shares ($k \leq n$) can reconstruct the secret, but fewer than $k$ shares reveal nothing about the secret. This is denoted as a $(k, n)$-threshold scheme.

### 7.2 Threshold Signatures

Threshold signatures distribute the private signing key across $n$ parties, requiring $k$ parties to collaborate to produce a valid signature. No single party (or coalition of fewer than $k$ parties) can produce a valid signature alone.

**Threshold ECDSA** (Gennaro and Goldfeder, 2018): The ECDSA private key $x$ is split into $n$ shares $x_1, x_2, \ldots, x_n$ such that $\sum_{i \in S} \lambda_i x_i = x$ for any subset $S$ of size $k$, where $\lambda_i$ are Lagrange coefficients.

**Signing protocol** (3-round, for $k=3, n=5$):
1. **Round 1**: Each party $i$ generates a random nonce $k_i$ and commits to its public share $R_i = [k_i]G$ using a Feldman VSS.
2. **Round 2**: Each party opens its commitment. The signers compute the aggregate nonce $R = \sum k_i \cdot \lambda_i G$ and the aggregate public share $R_x$ (the x-coordinate of $R$).
3. **Round 3**: Each party computes its signature share $s_i = k_i \cdot m + R_x \cdot \lambda_i \cdot x_i \mod n$, where $m$ is the message hash. The signature shares are combined: $s = \sum s_i \mod n$.

The final signature $(R_x, s)$ is a standard ECDSA signature that can be verified by any party with the public key $Q = [x]G$.

**Key refresh**: To prevent gradual key compromise, the shares should be periodically refreshed. Each party generates a random refresh share $\delta_i$ and distributes it to all other parties. The new share is $x_i' = x_i + \sum_{j=1}^{n} \delta_j \cdot \lambda_j$. This refreshes the shares without changing the underlying key $x$.

**Applications**:
- **Cryptocurrency custody**: Multi-party approval for large transactions (e.g., 3-of-5 threshold for withdrawals).
- **Certificate authority key protection**: The CA's private key is split across multiple HSMs in different locations.
- **Code signing**: Multiple developers must approve a release before the code is signed.

### 7.3 Threshold Encryption

Threshold encryption splits the decryption key across $n$ parties. To decrypt, $k$ parties must collaborate. Each party produces a decryption share, and the shares are combined to produce the plaintext.

**Threshold ElGamal** (Paillier threshold variant): The Paillier cryptosystem supports $(k, n)$-threshold decryption. The private key $\lambda = \text{lcm}(p-1, q-1)$ is split into $n$ shares using Shamir's secret sharing. Each party computes a decryption share, and $k$ shares are combined using Lagrange interpolation to recover the plaintext.

---

## 8. Secret Sharing

### 8.1 Shamir's Secret Sharing

Shamir's Secret Sharing (SSS, 1979) is a $(k, n)$-threshold scheme based on polynomial interpolation over a finite field.

**Sharing**: Given a secret $s$:
1. Choose a random polynomial $f(x) = a_0 + a_1 x + a_2 x^2 + \cdots + a_{k-1} x^{k-1}$ over $\mathbb{F}_p$ where $a_0 = s$ and $a_1, \ldots, a_{k-1}$ are random.
2. Compute $n$ shares: $(x_i, f(x_i))$ for $x_i = 1, 2, \ldots, n$.
3. Distribute share $(x_i, f(x_i))$ to party $i$.

**Reconstruction**: Given any $k$ shares $(x_{i_1}, f(x_{i_1})), \ldots, (x_{i_k}, f(x_{i_k}))$, reconstruct $f(x)$ using Lagrange interpolation:

$$f(x) = \sum_{j=1}^{k} f(x_{i_j}) \prod_{\substack{m=1 \\ m \neq j}}^{k} \frac{x - x_{i_m}}{x_{i_j} - x_{i_m}}$$

The secret is $s = f(0) = \sum_{j=1}^{k} f(x_{i_j}) \prod_{\substack{m=1 \\ m \neq j}}^{k} \frac{x_{i_m}}{x_{i_j} - x_{i_m}}$

**Properties**:
- **Perfect secrecy**: Any $k-1$ shares reveal nothing about the secret $s$ (they are uniformly random over $\mathbb{F}_p$).
- **Information-theoretic security**: The security holds against computationally unbounded adversaries.
- **Minimal size**: Each share is exactly the size of the secret ($\log_2 p$ bits).

### 8.2 Additive Secret Sharing

Additive secret sharing splits a secret $s$ into $n$ shares such that $\sum_{i=1}^{n} s_i = s \pmod{p}$. To share $s$:
1. Generate $n-1$ random shares $s_1, s_2, \ldots, s_{n-1} \leftarrow \mathbb{F}_p$.
2. Compute $s_n = s - \sum_{i=1}^{n-1} s_i \pmod{p}$.

Any single share reveals nothing about $s$ (it is uniformly random given the other shares are unknown). All $n$ shares are required for reconstruction.

**Advantages over Shamir**:
- Simpler reconstruction (addition instead of polynomial interpolation).
- No field arithmetic required (just addition modulo $p$).
- Naturally supports additive operations on shared secrets: if $s = \sum s_i$ and $t = \sum t_i$, then $s + t = \sum (s_i + t_i)$ without any communication.

**Disadvantages**:
- Requires all $n$ shares for reconstruction (not a $(k, n)$-threshold scheme). For threshold schemes, use replicated additive sharing or Shamir's scheme.
- Does not support multiplication on shared secrets without communication.

### 8.3 Verifiable Secret Sharing (VSS)

Feldman VSS (1987) allows shareholders to verify that their shares are consistent with the secret without revealing the secret. The dealer commits to the polynomial coefficients by posting $C_j = g^{a_j} \pmod{p}$ for $j = 0, 1, \ldots, k-1$, where $g$ is a generator of a cyclic group.

Each shareholder $i$ can verify their share $(x_i, f(x_i))$ by checking:
$$g^{f(x_i)} = \prod_{j=0}^{k-1} C_j^{x_i^j} \pmod{p}$$

If this check fails, shareholder $i$ can complain, and the dealer must reveal $f(x_i)$ to prove that the share is correct. If the dealer refuses, the protocol aborts.

---

## 9. Zero-Knowledge Proofs

### 9.1 ZK Definition

A zero-knowledge proof (ZKP) is a protocol between a prover $P$ and a verifier $V$ where $P$ convinces $V$ of a statement's truth without revealing any information beyond the statement itself.

**Three properties**:
1. **Completeness**: If the statement is true, an honest prover can convince an honest verifier.
2. **Soundness**: If the statement is false, no cheating prover can convince an honest verifier (except with negligible probability).
3. **Zero-knowledge**: The verifier learns nothing beyond the statement's truth. Formally, there exists a simulator $S$ that can produce transcripts indistinguishable from real protocol transcripts without knowing the witness.

### 9.2 SNARKs (Succinct Non-Interactive Arguments of Knowledge)

SNARKs are zero-knowledge proofs that are:
- **Succinct**: The proof size is constant (typically a few hundred bytes), regardless of the computation size.
- **Non-interactive**: The proof is a single message from the prover to the verifier, with no back-and-forth communication.
- **Argument of knowledge**: The prover must know a valid witness (the proof is "extractable").

**Construction**: SNARKs are typically built from:
1. An arithmetic circuit representation of the computation.
2. A rank-1 constraint system (R1CS) that encodes the circuit.
3. A polynomial commitment scheme (KZG, FRI, or IPA) that allows the prover to commit to polynomials and later prove evaluations at specific points.
4. A common reference string (CRS) that contains structured reference strings derived from a trusted setup.

**Groth16** (2016): The most widely deployed SNARK, used by Zcash and Filecoin. Proof size is 3 group elements (~192 bytes for BN254 curves). Verification time is constant (~5 ms). Requires a circuit-specific trusted setup.

**Plonk** (2019): A universal SNARK that supports any circuit with a single trusted setup (universal setup). Proof size is ~500 bytes. Slightly slower verification than Groth16 but supports circuit updates without new setups.

### 9.3 STARKs (Scalable Transparent Arguments of Knowledge)

STARKs are zero-knowledge proofs that are:
- **Transparent**: No trusted setup. The CRS is generated from public randomness.
- **Scalable**: Prover time is quasi-linear in the computation size; verifier time is logarithmic (poly-logarithmic in the full STARK specification).

**Construction**: STARKs use the FRI (Fast Reed-Solomon IOP of Proximity) protocol to commit to polynomials via Merkle trees. The proof consists of:
1. A Merkle root committing to the polynomial evaluations.
2. FRI layers that recursively halve the polynomial degree.
3.-opening proofs for the verifier to check specific evaluations.

**Properties**:
- Proof size: ~100–200 KB (much larger than SNARKs).
- Verification time: ~10 ms (slightly slower than SNARKs).
- No trusted setup (transparent).
- Post-quantum resistance (based on hash functions, not elliptic curves).

### 9.4 Bulletproofs

Bulletproofs (Bünz et al., 2018) are short zero-knowledge proofs that:
- Require no trusted setup (transparent).
- Are based on the Pedersen commitment scheme and inner product arguments.
- Produce proofs of ~1 KB for range proofs (proving that a committed value is in a range $[0, 2^{64}]$).
- Support aggregation: multiple range proofs can be aggregated into a single proof of ~1 KB (regardless of the number of proofs, up to a practical limit).

**Applications**:
- **Confidential transactions**: Prove that transaction inputs equal outputs without revealing the amounts.
- **Mimblewimble/Grin**: Use Bulletproofs for range proofs in confidential transactions.
- **Monero**: Adopted Bulletproofs for transaction privacy.

---

## 10. Homomorphic Encryption

### 10.1 Definition and Levels

Homomorphic encryption (HE) allows computation on encrypted data without decryption. The result, when decrypted, matches the result of the same computation on the plaintext.

**Three levels**:
1. **Partially Homomorphic Encryption (PHE)**: Supports a single operation (addition or multiplication) on ciphertexts.
   - **Additively HE**: Paillier ($E(m_1) \cdot E(m_2) = E(m_1 + m_2)$).
   - **Multiplicatively HE**: ElGamal, RSA ($E(m_1) \cdot E(m_2) = E(m_1 \cdot m_2)$ for RSA with multiplicative homomorphism).

2. **Somewhat Homomorphic Encryption (SHE)**: Supports a limited number of both additions and multiplications. The BGV scheme (Brakerski-Gentry-Vaikuntanathan, 2012) and the BFV scheme (Brakerski/Fan-Vercauteren, 2012) support limited-depth circuits.

3. **Fully Homomorphic Encryption (FHE)**: Supports arbitrary computations (unlimited additions and multiplications) on encrypted data. First constructed by Gentry (2009) using a bootstrapping technique.

### 10.2 CKKS (Cheon-Kim-Kim-Song, 2017)

CKKS is an approximate FHE scheme optimized for real-number arithmetic. It is the most practical FHE scheme for machine learning and statistical applications.

**Key operations**:
- **Encode**: Map a vector of real numbers $\mathbf{m} = (m_1, \ldots, m_{N/2})$ to a polynomial in the ring $\mathbb{Z}[X]/(X^N + 1)$ using canonical embedding.
- **Encrypt**: Encode the polynomial, add noise, and encrypt under the public key.
- **Add**: Ciphertext addition corresponds to plaintext addition.
- **Multiply**: Ciphertext multiplication corresponds to plaintext multiplication (with increased noise).
- **Rescale**: After multiplication, rescale the ciphertext to reduce the scale factor and noise level.
- **Bootstrapping**: When the noise level exceeds the decryption threshold, refresh the ciphertext by homomorphically evaluating the decryption circuit.

**Parameters** (for 128-bit security):
- Ring dimension $N$: 8192–65536 (depending on the circuit depth).
- Modulus $Q$: $2^{438}$–$2^{1560}$ (logarithmic, for 128-bit security).
- Scale $\Delta$: $2^{40}$ (precision for fixed-point arithmetic).

**Performance** (2024, on a modern desktop):
- Single CKKS multiplication: ~10 ms.
- Bootstrapping: ~100–500 ms (depending on parameters).
- Full circuit (logistic regression inference): ~1-5 seconds.

### 10.3 BGV and BFV

BGV and BFV are exact FHE schemes (integer arithmetic, no approximation error) used for applications requiring precise results (e.g., voting, database queries, integer arithmetic).

**BGV** (2012): Uses a leveled approach where each multiplication increases the noise level. After a certain depth, the noise exceeds the decryption threshold, and bootstrapping is required. BGV is slightly more efficient than BFV for deep circuits.

**BFV** (2012): Similar to BGV but with a different noise management strategy. BFV is easier to implement and has wider library support (Microsoft SEAL implements BFV).

### 10.4 Applications

- **Private database queries**: Query an encrypted database without revealing the query or the result to the server.
- **Private machine learning**: Train or infer on encrypted data without revealing the model or the data.
- **Private set intersection**: Compute the intersection of two sets without revealing either set (using homomorphic comparison).
- **Medical data analysis**: Perform statistical analysis on encrypted medical records without decrypting them.
- **Financial analytics**: Compute risk metrics, fraud detection, and portfolio analysis on encrypted financial data.

---

## 11. Secure Multi-Party Computation

### 11.1 Definition

Secure Multi-Party Computation (MPC) allows $n$ parties to jointly compute a function $f(x_1, x_2, \ldots, x_n)$ over their private inputs $x_i$, such that:
1. **Privacy**: No party learns anything about the other parties' inputs beyond what can be inferred from their own input and the function output.
2. **Correctness**: The output is correct even if some parties are malicious.

**Security models**:
- **Semi-honest (passive)**: Parties follow the protocol but try to learn information from the transcript.
- **Malicious (active)**: Parties may deviate from the protocol in any way (send incorrect messages, abort early, collude with other parties).

### 11.2 Yao's Garbled Circuits

Yao's Garbled Circuit protocol (1986) is a 2-party MPC protocol for the semi-honest model:

1. **Garbling**: Party $A$ (the garbler) creates a "garbled circuit" by encrypting each gate's truth table. For each wire $w_i$, $A$ generates two random labels $k_i^0, k_i^1$ (corresponding to 0 and 1). For each gate $g(a, b) = c$, $A$ encrypts the output label $k_c^{g(a,b)}$ under both input labels: $H(k_a^a \| k_b^b) \oplus k_c^{g(a,b)}$.

2. **Oblivious transfer**: Party $B$ (the evaluator) learns the labels corresponding to their input bits through oblivious transfer (OT), without $A$ learning $B$'s input.

3. **Evaluation**: $B$ evaluates the garbled circuit gate-by-gate, decrypting each gate's truth table entry using the input labels. $B$ obtains the output labels (which encode the output bits) and sends them to $A$.

4. **Output**: $A$ translates the output labels to bits and sends the results to $B$.

**Cost**: For an $n$-gate circuit, the garbled circuit has size $O(n)$ (4 ciphertexts per gate for standard garbling, 2 per gate with the point-and-permute optimization). The OT cost is $O(|B|)$ where $|B|$ is the number of $B$'s input bits. OT extension reduces the cost to $O(\lambda \cdot |B| + n)$ where $\lambda$ is the security parameter.

### 11.3 Secret Sharing-Based MPC

In secret sharing-based MPC (BGW protocol, 1988), each party secret-shares their input among all $n$ parties using Shamir's secret sharing. The parties then compute the function circuit gate-by-gate:

- **Addition gates**: Each party locally adds their shares: $(a + b)_i = a_i + b_i$.
- **Multiplication gates**: Each party multiplies their shares: $(a \cdot b)_i = a_i \cdot b_i$. The result is a degree-$2(k-1)$ polynomial (instead of degree $k-1$), so the parties must perform a degree-reduction step using Lagrange interpolation.

**Cost**: For $n$ parties and a circuit of size $|C|$, the communication cost is $O(n^2 \cdot |C|)$ field elements. For honest-majority ($n \geq 2k-1$), the protocol is secure against $k-1$ corrupt parties.

### 11.4 Practical MPC Applications

- **Private set intersection (PSI)**: Two parties compute the intersection of their sets without revealing non-intersecting elements. Used in advertising (measuring ad conversion without revealing user identities), password breach detection (checking if a user's password is in a leaked database without revealing the password), and clinical trials (matching patients across institutions).
- **Threshold ECDSA signing**: Used by cryptocurrency custody solutions (Fireblocks, ZenGo) to split the private key across multiple parties (see §7).
- **Private benchmarking**: Companies compare their performance metrics (revenue, costs, efficiency) without revealing individual data. MPC computes aggregate statistics (mean, median, percentile) across all parties.
- **Secure auction**: Vickrey auctions where the second-highest bid is revealed without revealing any individual bid. MPC computes the maximum and second-maximum values.

---

## Cross-References

- **§01a** — Cryptographic fundamentals: symmetric/asymmetric encryption, KDFs, CSPRNGs
- **§02a** — RSA/ECC attacks: key generation weaknesses (Debian OpenSSL), ROCA (TPM)
- **§02b** — Hash/MAC attacks: HMAC, KDF security properties
- **§03a** — TLS attacks: key exchange, certificate validation, CSPRNG weaknesses
- **§04a** — Side-channel attacks: constant-time programming, blinding, masking
- **§04b** — Hardware attacks: HSM architecture, TPM vulnerabilities, JTAG extraction
- **§05a** — Post-quantum cryptography: PQC algorithms, hybrid deployment, crypto agility
- **§06** — Case studies: Debian OpenSSL, Dual_EC_DRBG, HSM key management failures

## References

1. NIST, "Recommendation for Key Management — Part 1: General," SP 800-57 Part 1 Rev. 5, May 2020.
2. NIST, "Recommendation for Key Management — Part 2: Best Practices for Key Management Organizations," SP 800-57 Part 2 Rev. 1, November 2019.
3. NIST, "Recommendation for Key Management — Part 3: Application-Specific Key Management Guidance," SP 800-57 Part 3 Rev. 1, November 2019.
4. RFC 3394, "Advanced Encryption Standard (AES) Key Wrap Algorithm," September 2002.
5. RFC 5649, "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm," September 2009.
6. RFC 8017, "PKCS #1: RSA Cryptography Specifications Version 2.2," November 2016.
7. AWS, "Envelope Encryption," AWS Key Management Service Developer Guide, 2024.
8. Google, "Envelope Encryption," Cloud Key Management Service Documentation, 2024.
9. NIST, "Secure Hash Standard (SHS)," FIPS 180-4, August 2015.
10. NIST, "Digital Signature Standard (DSS)," FIPS 186-5, February 2023.
11. Shamir, A., "How to Share a Secret," Communications of the ACM, 1979.
12. Feldman, P., "A Practical Scheme for Non-Interactive Verifiable Secret Sharing," FOCS 1987.
13. Pedersen, T.P., "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing," CRYPTO 1991.
14. Ben-Or, M., Goldwasser, S., Wigderson, A., "Completeness Theorems for Non-Cryptographic Fault-Tolerant Distributed Computation," STOC 1988.
15. Cramer, R., Damgård, I., Nielsen, J.B., "Secure Multiparty Computation and Secret Sharing," Cambridge University Press, 2015.
16. Goldwasser, S., Micali, S., Rackoff, C., "The Knowledge Complexity of Interactive Proof Systems," SIAM Journal on Computing, 1989.
17. Ben-Sasson, E., Chiesa, A., et al., "SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge," CRYPTO 2013.
18. Gentry, C., "A Fully Homomorphic Encryption Scheme," PhD Thesis, Stanford University, 2009.
19. Brakerski, Z., "Fully Homomorphic Encryption without Modulus Switching from Classical GapSVP," CRYPTO 2012.
20. NIST, "Recommendation for Random Number Generation Using Deterministic Random Bit Generators," SP 800-90A Rev. 1, June 2015.
21. CVE-2007-4995, "Debian OpenSSL Predictable Random Number Generator," 2007.