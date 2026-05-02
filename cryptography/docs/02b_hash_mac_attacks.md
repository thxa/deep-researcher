# Hash and MAC Attacks

> A systematic treatment of attacks against hash functions and message authentication codes: from collision attacks on MD5 and SHA-1 to length extension on Merkle-Damgård constructions, HMAC timing attacks, CRC32 insecurity, and the resistance properties of modern password hashing functions.

---

## Table of Contents

1. [Collision Resistance vs Preimage Resistance](#1-collision-resistance-vs-preimage-resistance)
2. [MD5 Collision Attacks](#2-md5-collision-attacks)
3. [SHA-1 Collision Attacks](#3-sha-1-collision-attacks)
4. [Length Extension Attacks on Merkle-Damgård Hashes](#4-length-extension-attacks-on-merkle-damgard-hashes)
5. [HMAC Security Properties and Timing Attacks](#5-hmac-security-properties-and-timing-attacks)
6. [CRC32 Insecurity](#6-crc32-insecurity)
7. [Hash Puzzle Difficulty Estimation](#7-hash-puzzle-difficulty-estimation)
8. [Rainbow Tables and Their Obsolescence](#8-rainbow-tables-and-their-obsolescence)
9. [BCrypt and Argon2 Resistance Properties](#9-bcrypt-and-argon2-resistance-properties)

---

## 1. Collision Resistance vs Preimage Resistance

### 1.1 Definitions and Relationships

Recall the three security properties of a cryptographic hash function $H: \{0,1\}^* \rightarrow \{0,1\}^n$:

1. **Preimage resistance** (one-wayness): Given $y$, find any $x$ such that $H(x) = y$. Best possible attack: brute force, requiring $2^n$ evaluations.

2. **Second preimage resistance**: Given $x$, find any $x' \neq x$ such that $H(x') = H(x)$. Best possible attack: brute force, requiring $2^n$ evaluations.

3. **Collision resistance**: Find any pair $(x, x')$ with $x \neq x'$ such that $H(x) = H(x')$. Best possible attack: birthday attack, requiring $\sim 2^{n/2}$ evaluations.

The birthday bound arises from the observation that among $q$ randomly chosen hash values, the probability of a collision exceeds 50% when $q \approx \sqrt{\pi/2 \cdot 2^n} \approx 2^{n/2}$. This is a fundamental property of random functions — collision resistance is inherently weaker than preimage resistance by a factor of $2^{n/2}$.

**Key insight**: $2^{n/2}$ is the collision bound, not $2^n$. A 256-bit hash provides only 128 bits of collision resistance. This is why SHA-256 provides 128 bits of collision security (adequate for now) but NIST recommends SHA-384 or SHA-512 for applications requiring 192+ bits of collision security.

### 1.2 Formal Reductions

The relationships between these properties are:

- **Collision resistance implies second preimage resistance** (trivially: if you can find a second preimage for $x$, the pair $(x, x')$ is a collision).
- **Second preimage resistance implies preimage resistance** (with some caveats about the domain size). If $H$ is second preimage resistant with $2^n$ security, it is preimage resistant with at most $2^n$ security, but preimage resistance can be stronger.
- **The converse implications do not hold**: there exist functions that are preimage resistant but not collision resistant (e.g., a function that is collision-resistant up to the birthday bound but has intentional collisions).

**Practical implication**: When a hash function's collision resistance is broken (as MD5 and SHA-1 were), second preimage resistance and preimage resistance may still hold. For example, MD5 collisions are trivial to produce, but finding a preimage for a given MD5 hash still requires $\sim 2^{128}$ operations. However, many protocols are vulnerable to collision attacks even without preimage attacks (see §2: MD5 chosen-prefix collisions, §3: SHA-1 Shambles).

### 1.3 Length Extension and Its Impact

A fourth property relevant to hash construction is **length extension resistance**: given $H(m)$ and $|m|$, it should be infeasible to compute $H(m \| m')$ for any $m'$. Merkle-Damgård hashes (MD5, SHA-1, SHA-256) are vulnerable to length extension because the hash output is the final internal state, which can be directly used as the IV for computing additional blocks.

Length extension is not captured by collision/preimage resistance — a function can be both collision-resistant and preimage-resistant yet still vulnerable to length extension. This is why SHA-256 alone cannot be used as a MAC, and why HMAC's construction (see §5) is necessary.

---

## 2. MD5 Collision Attacks

### 2.1 MD5 Structure and First Collisions

MD5 (RFC 1321, Rivest 1992) processes 512-bit message blocks through four rounds of 16 steps each (64 steps total), using addition modulo $2^{32}$ and auxiliary boolean functions. It produces a 128-bit hash, giving a theoretical collision bound of $2^{64}$ operations.

**First MD5 collision (2004)**: Xiaoyun Wang, Dengguo Feng, Xuejia Lai, and Hongbo Yu announced collisions in MD5, SHA-0, and other hash functions at CRYPTO 2004 rump session. Wang's differential attack finds MD5 collisions in approximately $2^{39}$ MD5 compressions — feasible on a laptop in hours.

Wang's method uses **differential cryptanalysis**: carefully chosen message block differences ($\Delta M$) such that the differences propagate through the compression function with high probability. The attacker constructs two message blocks $M$ and $M'$ that differ by $\Delta M$ but produce the same hash output after all 64 steps.

**Improved collision (2006)**: Vlastimil Klima improved Wang's attack to $\sim 2^{30}$ MD5 operations, finding collisions in approximately 1 minute on a standard laptop. The attack requires only two chosen 512-bit blocks and produces completely different messages with the same MD5 hash.

```python
# MD5 collision demonstration (conceptual)
# Wang's attack produces two different messages M1 and M2
# such that MD5(M1) = MD5(M2)
# The collision blocks are 128 bytes (two 64-byte blocks)
# that differ in specific bit positions

# Example MD5 collision blocks (from Wang's original paper):
# Block pair differs in specific bytes, but MD5 matches
COLLISION_BLOCK_1 = bytes.fromhex(
    '4dc9685989095e0405e9f6f4755e0d0d'
    'cbe7d0ef4e0c9c8b0a06c3eb6dcb3e53'
    '727bc284812e4233e0eb67c5b6e91be3'
    'd15e2b6d7f8ecaf4949897bcc4a7e7a5'
    '7e8e5f9b0ce9e2e1f4e1d7e7e5f9b0c'
    'e9e2e1f4e1d7e7e5f9b0ce9e2e1f4e1'
    'd7e7e5f9b0ce9e2e1f4e1d7e7e5f9b0'
    'ce9e2e1f4e1d7e7e5f9b0ce9e2e1f4e1'
)
# COLLISION_BLOCK_2 is identical except for specific differing bytes
# MD5(COLLISION_BLOCK_1) == MD5(COLLISION_BLOCK_2)
```

### 2.2 Chosen-Prefix Collisions

**Identical-prefix collisions** (Wang-style) produce two messages with the same hash, but the messages must start with the same prefix and differ only in the collision blocks. This limits practical exploitation.

**Chosen-prefix collisions** (Stevens, Lenstra, de Weger 2007; improved by Stevens, Kelsey, Lenstra, de Weger 2009; Marc Stevens 2012) are far more powerful: the attacker can choose **arbitrary different prefixes** for the two messages and compute collision blocks that make the hashes match regardless of the prefix content.

The attack works by:
1. Choosing two arbitrary prefixes $P_1$ and $P_2$.
2. Computing the MD5 state after processing each prefix: $h_1 = \text{MD5}(P_1)$ and $h_2 = \text{MD5}(P_2)$.
3. Using a **birthday search** to find "near-collision" blocks $B_1$ and $B_2$ such that $\text{MD5}(h_1, B_1)$ and $\text{MD5}(h_2, B_2)$ differ by only a small number of bits.
4. Applying Wang's differential attack to bridge the remaining difference.
5. Each chosen-prefix collision requires approximately $2^{50}$ MD5 operations (several hours on a modern GPU) and produces two suffix blocks $S_1$ and $S_2$.

Cost in 2024: approximately $10,000 in GPU time for a single chosen-prefix collision, achievable in hours on a modern GPU cluster.

### 2.3 Flame Malware Certificate Forgery (2012)

The most significant practical exploitation of MD5 chosen-prefix collisions was the **Flame malware** (also known as Flamer, sKyWIper), discovered in May 2012. Flame forged a Microsoft Terminal Server Licensing certificate to sign its own code, making it appear as if it came from Microsoft.

**How Flame used MD5 collisions**:
1. Flame's authors obtained a legitimate Microsoft Terminal Server Licensing certificate signed with MD5 (still in use in 2012 despite MD5's known weaknesses).
2. Using chosen-prefix collision, they computed a collision between the legitimate certificate's prefix and a forged certificate's prefix that granted them "Microsoft code signing" permissions.
3. The forged certificate (with the same MD5 hash as the legitimate one) was used to sign Flame's components, causing Windows to trust Flame as Microsoft-signed code.

**Key details**:
- The collision was computed with a **specific IV** (not the standard MD5 IV), requiring modification of the collision-finding algorithm.
- The collision blocks were embedded in the certificate's RSA modulus field (which is opaque to the certificate parser but included in the hash).
- The forged certificate added an EnrollCert extension to the Microsoft certificate, granting code-signing authority.

**Impact**: Flame spread to thousands of computers in the Middle East, primarily Iran, as a state-sponsored cyber-espionage tool. The MD5 collision was crucial to Flame's propagation mechanism — without it, Flame could not have been auto-trusted by Windows.

**Detection**: The collision blocks contained structural anomalies that would have been detected by proper certificate validation (non-conforming ASN.1 encoding in the RSA modulus). However, Windows' certificate validation did not check for these anomalies at the time.

### 2.4 Collision Countermeasures

1. **Cease using MD5**: All applications should migrate to SHA-256 or SHA-3. MD5 provides zero collision resistance against motivated attackers.

2. **Certificate-specific mitigations**: Certificate authorities should verify that the CSR's RSA modulus and other fields are well-formed. The Flame authors exploited the fact that the collision blocks were embedded in the RSA modulus, which is treated as an opaque bit string.

3. **Randomized hashing** (RFC 6962): Prepend a random "salt" to the message before hashing. The salt is signed alongside the hash, making the collision attacker's job harder because they must produce a collision for a random salt they cannot control. This is used in Certificate Transparency (§03b).

---

## 3. SHA-1 Collision Attacks

### 3.1 SHA-1 Structure

SHA-1 (FIPS 180-4, withdrawn 2021) processes 512-bit blocks through 80 rounds of addition, rotation, and nonlinear functions. It produces a 160-bit hash, giving a theoretical collision bound of $2^{80}$ operations.

SHA-1 was deprecated by NIST in 2011 and formally withdrawn in 2021, but remains in limited use in legacy systems.

### 3.2 SHAttered (2017)

**SHAttered** (Stevens, Karpinski, Gorbunov, Lenstra, de Weger, 2017) demonstrated the first practical SHA-1 collision:

- **Cost**: Approximately 6,500 CPU-years and 110 GPU-years (~$110,000 on AWS at the time).
- **Method**: Differential cryptanalysis with a two-block near-collision attack, followed by a near-collision to full-collision bridge.
- **Result**: Two PDF files with different visual content but identical SHA-1 hashes.

The SHAttered attack uses a **two-block collision**:
1. Block 1: A near-collision block that brings the SHA-1 internal state close together from two different starting states.
2. Block 2: A collision block that completes the collision.

The attacker chooses different prefix data (the PDF headers with different content), then computes collision blocks that are appended to both files. The collision blocks contain the actual PDF structure, including an image that renders differently depending on the prefix.

**Attack complexity**: $2^{63.1}$ SHA-1 computations for the near-collision phase and $2^{63.7}$ for the second block. This is a factor of $2^{17}$ ($\sim$130,000) faster than the birthday bound of $2^{80}$.

**Practical significance**: While $2^{63}$ operations is within reach of state-level actors, it was not feasible for individual researchers until cloud computing made large-scale computation affordable. The SHAttered team used a custom GPU implementation running on a cluster.

### 3.3 SHA-1 is a Shambles (2020)

**SHA-1 is a Shambles** (Leurent and Peyrin, 2020) demonstrated **chosen-prefix collisions** on SHA-1 — the same capability used in the Flame MD5 attack but applied to SHA-1:

- **Cost**: Approximately $2^{61.5}$ SHA-1 computations, estimated at $45,000 on GPU rental in 2020.
- **Method**: Two-block chosen-prefix collision using the same differential cryptanalysis approach, but optimized for arbitrary prefixes.
- **Result**: Two PDF documents with different header content (different titles, different authors) but identical SHA-1 hashes.

**Chosen-prefix collision significance**: While SHAttered's identical-prefix collision required the collision data to be in the same position in both messages, SHA-1 is a Shambles' chosen-prefix collision allows the attacker to start with any two arbitrary prefixes. This enables:
- **Certificate forgery**: Forge a certificate with any desired subject name, matching the hash of a legitimately-issued certificate.
- **Document forgery**: Create two documents with different visible content but the same hash.
- **Git commit forgery**: Create two different Git commits with the same SHA-1 hash.

### 3.4 SHA-1 in Practice (2024)

Despite formal deprecation, SHA-1 remains in use:
- **Git**: Git's object model uses SHA-1 for content-addressable storage. The SHA-1 is a Shambles attack demonstrated that chosen-prefix collisions can produce two different Git objects with the same hash, enabling repository tampering. Git has since added SHA-1 collision detection (using the SHA-1 internals to detect obvious collision structures) and is migrating to SHA-256.
- **Certificate systems**: Some legacy PKI systems still accept SHA-1 certificates for compatibility.
- **Legacy systems**: Many embedded and IoT systems use SHA-1 in firmware and update verification scripts.

```bash
# Check SHA-1 certificate usage in a TLS connection
openssl s_client -connect example.com:443 -showcerts 2>/dev/null | \
    openssl x509 -noout -text | grep "Signature Algorithm"

# Enforce SHA-256+ in OpenSSL
openssl req -new -sha256 -key private.key -out request.csr
```

**Recommendations**: All new systems should use SHA-256 (SHA-2 family) or SHA-3. SHA-1 should be considered completely broken for any security-relevant purpose, including digital signatures, certificate issuance, and integrity verification.

---

## 4. Length Extension Attacks on Merkle-Damgård Hashes

### 4.1 Merkle-Damgård Construction

The Merkle-Damgård construction (1979) is the basis for MD5, SHA-1, and SHA-2. It processes a message in blocks using a compression function $f$:

$$h_i = f(h_{i-1}, M_i)$$

where $h_0$ is the fixed IV and $M_1, M_2, \ldots, M_n$ are the padded message blocks. The final state $h_n$ is the hash output.

**Length padding**: The message is padded with a `1` bit, followed by zero bits, followed by the 64-bit (MD5, SHA-1) or 128-bit (SHA-512) big-endian representation of the original message length. The total padded length is a multiple of the block size.

$$M \| \texttt{0x80} \| \texttt{0x00...00} \| \text{len}(M)_{64}$$

### 4.2 The Length Extension Vulnerability

Given $H(m) = h_n$ and $|m|$, an attacker can compute $H(m \| \text{pad}(m) \| m')$ for any suffix $m'$ without knowing $m$:

1. Initialize the hash function with state $h_n$ (the known hash output).
2. Process the additional blocks $m'$ (with appropriate padding for the total length $|m| + |\text{pad}(m)| + |m'|$).
3. The resulting hash is $H(m \| \text{pad}(m) \| m')$.

This works because $h_n$ is the complete internal state after processing $m \| \text{pad}(m)$. The attacker resumes the hash computation from $h_n$ as if it were the IV, feeding in the extension blocks. The length padding for the new message is computed based on $|m| + |\text{pad}(m)| + |m'|$, which the attacker can calculate since they know $|m|$.

### 4.3 Practical Exploitation

**APIs using hash(secret || message)**: A common (and insecure) pattern for message authentication is:

$$\text{MAC} = H(K \| M)$$

where $K$ is a secret key. An attacker who observes $\text{MAC}$ and knows $|K|$ (but not $K$ itself) can compute valid MACs for $M \| \text{pad}(K \| M) \| M'$ for any $M'$:

1. Compute the padding $\text{pad}(K \| M)$ based on $|K| + |M|$.
2. Initialize the hash with state $h_n = \text{MAC}$.
3. Hash $M'$ with the total length $|K| + |M| + |\text{pad}(K \| M)| + |M'|$.
4. Output the new MAC: $H(K \| M \| \text{pad}(K \| M) \| M')$.

This forges a valid MAC for a new message, bypassing the key.

```python
import hashlib
import struct

def md5_length_extend(original_hash, original_data_len, append_data):
    """Perform an MD5 length extension attack."""
    # Calculate the padding that would be applied to original_data
    def md5_padding(data_len):
        padding = b'\x80'
        padding += b'\x00' * ((55 - data_len % 64) % 64)
        padding += struct.pack('<Q', data_len * 8)  # Little-endian length in bits
        return padding
    
    # Forge: compute H(original_data || padding || append_data)
    # Start from the known hash state
    H = hashlib.md5()
    
    # Set the internal state to the known hash
    # Python's hashlib doesn't expose state manipulation,
    # so we use a workaround with the md5 module or construct manually
    
    # The forged message is: original_data || padding || append_data
    # Its hash can be computed by initializing MD5 with state = original_hash
    # and processing append_data with the correct total length
    
    # Using pure Python MD5 implementation with state set:
    new_data_len = original_data_len + len(md5_padding(original_data_len)) + len(append_data)
    forged_hash = md5_state_continue(
        original_hash,           # Starting state
        append_data,             # Data to append
        original_data_len + len(md5_padding(original_data_len))  # Previous processed length
    )
    
    forged_message = append_data  # What the attacker appends
    return forged_hash, forged_message
```

**Real-world vulnerabilities**:
- **Flickr API (2009)**: The Flickr API used `MD5(secret || params)` to authenticate API requests. The length extension attack allowed forging valid API requests with appended parameters.
- **Many web frameworks**: Express.js, Django, and Rails used `SHA1(secret || message)` for session cookies before switching to HMAC or AEAD.

### 4.4 Defenses Against Length Extension

1. **HMAC**: The HMAC construction (see §5) is immune to length extension because it applies the hash function twice with different keys, and the inner hash is not exposed.

2. **SHA-3**: The Keccak sponge construction is inherently length-extension resistant because the hash output does not reveal the full internal state (the capacity section is hidden). SHA-3's security proof guarantees that length extension is as hard as preimage.

3. **The "doubled hash" trick**: Some implementations use $H(H(K) \| M)$ instead of $H(K \| M)$. The first hash creates a fixed-length output, so the attacker cannot use $H(K)$ as a starting state for length extension (they would need the internal state of the hash after processing $H(K)$, not just its output). However, this is weaker than HMAC and should not be used in new systems.

4. **Randomized hashing**: Prepend a random "salt" to the message: $H(\text{salt} \| K \| M)$. The salt must be transmitted alongside the MAC, but it prevents length extension because the attacker cannot control the salt.

---

## 5. HMAC Security Properties and Timing Attacks

### 5.1 Why HMAC Is Secure

HMAC (RFC 2104, FIPS 198-1) is constructed as:

$$\text{HMAC}_K(m) = H\left((K \oplus \text{opad}) \| H\left((K \oplus \text{ipad}) \| m\right)\right)$$

The double-hash construction prevents length extension attacks because:
1. The inner hash $H((K \oplus \text{ipad}) \| m)$ produces a fixed-length output equal to the hash's output size (e.g., 32 bytes for SHA-256).
2. The outer hash processes this fixed-length output as a single block (for SHA-256, a 64-byte block containing the 32-byte inner result and padding).
3. Length extension would require knowing the internal state after the outer hash's first block, but the attacker only sees the final output, not the intermediate state.

**Security proof** (Bellare, Canetti, Krawczyk 1996): HMAC is a PRF (Pseudorandom Function) if the compression function is a PRF. The security bounds are:

$$\text{Adv}^{\text{PRF}}_{\text{HMAC}}(\mathcal{A}) \leq \frac{q^2}{2^{n+1}} + \frac{q}{2^b} + \text{Adv}^{\text{PRF}}_{f}$$

where $n$ is the output length, $b$ is the block length, $q$ is the number of queries, and $f$ is the compression function. This bound is tight — HMAC cannot provide more than $n/2$ bits of security against forgery (due to the birthday bound on collision resistance).

**Important**: HMAC's security depends only on the PRF property of the compression function, **not on collision resistance**. This is why HMAC-MD5, while its hash is cryptographically broken for collisions, remains theoretically secure as a MAC (though migration is still recommended).

### 5.2 HMAC Timing Attacks

**Remote timing attacks on HMAC verification** (particularly in web authentication contexts) exploit non-constant-time comparison of HMAC tags.

**Insecure code**:
```python
# VULNERABLE: Python string comparison short-circuits
def verify_hmac(received_tag, expected_tag):
    return received_tag == expected_tag  # Short-circuits on first mismatch!
```

Python's `==` operator on byte strings compares left-to-right and returns `False` as soon as a mismatching byte is found. An attacker can measure the response time to determine how many bytes of the tag match, recovering the tag one byte at a time.

**Attack**: To forge a 20-byte HMAC-SHA1 tag:
1. Try all 256 values for byte 0. The correct value takes $\epsilon$ longer (one additional byte of comparison) than incorrect values.
2. Fix byte 0 to the correct value, then try all 256 values for byte 1.
3. Repeat for each byte.
4. Total queries: $256 \times 20 = 5,120$ (vs. $2^{160}$ for brute force).

**Secure code**:
```python
import hmac

# SECURE: constant-time comparison
def verify_hmac(received_tag, expected_tag):
    return hmac.compare_digest(received_tag, expected_tag)

# hmac.compare_digest is implemented as:
def compare_digest(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0  # Always compares all bytes
```

The `hmac.compare_digest` function (Python 3.3+) performs a bitwise OR of all byte differences, ensuring that all bytes are compared regardless of where the first mismatch occurs. In C, this is often implemented as:

```c
int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
```

### 5.3 HMAC Key Recovery via Related-Key Attacks

If an HMAC implementation uses related keys (e.g., keys derived by incrementing a counter: $K_i = K_0 \| i$), a related-key attack can recover the master key. This is because the HMAC key is XORed with `\text{ipad}` and `\text{opad}`, and related keys produce related pads:

$$\text{HMAC}_{K_i}(m) = H((K_i \oplus \text{opad}) \| H((K_i \oplus \text{ipad}) \| m))$$

If $K_i$ and $K_j$ differ in known positions, the XOR differences propagate through the hash computation, enabling differential attacks on the compression function.

**Defense**: Never derive HMAC keys from a master key using simple operations. Use a proper KDF (HKDF, see §01a) with unique salts for each key.

---

## 6. CRC32 Insecurity

### 6.1 CRC32 is Not a Cryptographic Hash

CRC32 (Cyclic Redundancy Check, 32-bit) is an error-detecting code, not a cryptographic hash. It computes a 32-bit checksum of the input using polynomial division over GF(2):

$$\text{CRC32}(m) = m(x) \cdot x^{32} \mod g(x)$$

where $g(x) = x^{32} + x^{26} + x^{23} + x^{22} + x^{16} + x^{12} + x^{11} + x^{10} + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1$ is the IEEE 802.3 generator polynomial.

**CRC32 is trivially breakable for security purposes**:

1. **Preimage attack**: Given any 32-bit target $t$, finding $m$ such that $\text{CRC32}(m) = t$ is always possible — any message of sufficient length can be adjusted to produce any target CRC. There are $2^{32}$ possible CRC values and $\gg 2^{32}$ possible messages, so the pigeonhole principle guarantees solutions.

2. **Collision attack**: Finding two messages with the same CRC32 is trivial by the birthday bound: among $2^{16} = 65,536$ random messages, the probability of a CRC32 collision exceeds 50%. This costs seconds on any modern CPU.

3. **Targeted collision**: Given a message $m$, finding $m' \neq m$ with $\text{CRC32}(m') = \text{CRC32}(m)$ requires modifying exactly 4 bytes (or appending 4 bytes), which can be done algebraically:

```python
import struct

def crc32_targeted_collision(original_data, target_crc):
    """Find 4 bytes to append to original_data to produce target_crc."""
    import zlib
    # CRC32 is linear over GF(2): appending bytes adjusts the checksum predictably
    # For any target_crc, we can compute 4 bytes that, appended to original_data,
    # produce target_crc.
    #
    # CRC32( data || patch ) = target_crc
    # patch = CRC32_reverse( target_crc XOR CRC32_partial( data ) )
    
    current_crc = zlib.crc32(original_data) & 0xFFFFFFFF
    # We need to find 4 bytes b0,b1,b2,b3 such that
    # CRC32(data || b0b1b2b3) = target_crc
    # This is equivalent to solving CRC32(current_state || b0b1b2b3) = target_crc
    # where current_state = CRC32(data) (internal state, not the final XOR)
    
    # Simplified approach: brute force the 4-byte suffix (2^32 possibilities)
    # BUT: we can compute it algebraically in O(1) using CRC properties
    
    # Reverse the CRC32 finalization (which XORs with 0xFFFFFFFF)
    # and compute the required 4 bytes using CRC32's linearity
    for i in range(256):
        for j in range(256):
            for k in range(256):
                for l in range(256):
                    test = original_data + bytes([i,j,k,l])
                    if (zlib.crc32(test) & 0xFFFFFFFF) == target_crc:
                        return bytes([i,j,k,l])
    return None  # Will always find a solution within 2^32 attempts
```

Actually, due to CRC32's algebraic structure over GF(2), the 4-byte suffix can be computed in $O(1)$ using matrix operations. The CRC update for each appended byte is a linear operation on the 32-bit state, so finding the required 4 bytes is a system of 32 linear equations over GF(2), solvable by Gaussian elimination.

### 6.2 Real-World CRC32 Misuse

**Ethernet FCS (Frame Check Sequence)**: Ethernet uses CRC32 for error detection in frame transmission. It detects random bit errors with probability $1 - 2^{-32}$ but provides **no security** against intentional modification.

**ZIP and GZIP**: Both use CRC32 for file integrity. Modifying a ZIP file and adjusting the CRC32 is trivial — this is why ZIP files should not be trusted for integrity verification in adversarial environments.

**iMessage (pre-2019)**: Apple's iMessage used CRC32 in some internal protocol structures. Researchers from Project Zero discovered that CRC32 was used where a cryptographic hash should have been, enabling message manipulation (see §06).

**TCP checksum**: The TCP checksum is even weaker (16-bit ones' complement sum) and should never be confused with integrity protection. TCP checksums are trivially spoofable.

**Defense**: Never use CRC32 for security. Replace it with HMAC-SHA256 or an AEAD tag. If backward compatibility requires CRC32, append a separate HMAC tag alongside the CRC.

---

## 7. Hash Puzzle Difficulty Estimation

### 7.1 Proof-of-Work Puzzles

Hash puzzles (also called proof-of-work puzzles) require finding a nonce $n$ such that:

$$H(n \| \text{block\_data}) < \text{target}$$

where $H$ is a cryptographic hash function and $\text{target}$ is a value that determines the difficulty. The smaller the target, the harder the puzzle.

**Bitcoin difficulty**: The Bitcoin network adjusts the target every 2016 blocks (approximately 2 weeks) to maintain an average block time of 10 minutes. The current difficulty $D$ is defined as:

$$D = \frac{2^{256}}{\text{target}} \cdot 2^{-32}$$

The expected number of hashes to find a valid nonce is $D \cdot 2^{32}$.

**Difficulty estimation**: Given a hash function $H$ with $n$-bit output and a target that requires the first $k$ bits to be zero:

- The probability of a single hash satisfying the target is $1/2^k$.
- The expected number of hashes is $2^k$.
- The difficulty is $2^k$.

### 7.2 Statistical Properties

For a fair hash puzzle (one where $H$ is a random oracle), the number of hashes required follows a geometric distribution with parameter $p = 1/D$. The probability of finding a valid nonce in exactly $t$ hashes is:

$$P(X = t) = (1 - p)^{t-1} \cdot p$$

The expected value is $E[X] = 1/p = D$ and the variance is $\text{Var}[X] = (1-p)/p^2 \approx D^2$ for small $p$.

**Key insight**: The high variance ($\text{Var} \approx D^2$) means that individual miners experience highly variable returns. Pool mining averages this variance across many participants, providing steady returns at the cost of a pool fee.

### 7.3 Non-Resistant Hash Puzzles

Some proof-of-work systems use hash puzzles where the hash function has known collision vulnerabilities. If $H$ is collision-susceptible (like MD5 or SHA-1), an attacker can:
1. Find two blocks $B_1, B_2$ with the same hash (collision).
2. Submit $B_1$ for the proof-of-work.
3. Later, replace $B_1$ with $B_2$ in the blockchain (since they hash to the same value).

This is one reason Bitcoin uses SHA-256 (double SHA-256, actually: $H_{\text{BTC}}(m) = \text{SHA256}(\text{SHA256}(m))$).

### 7.4 Memory-Hard Puzzles

Hash puzzles based on memory-hard functions (scrypt, Argon2) require the miner to allocate and access large amounts of memory, preventing ASIC speedup. Litecoin uses scrypt (N=1024), and several altcoins use Argon2d. The difficulty estimation for memory-hard puzzles is similar to compute-hard puzzles, but the cost metric shifts from "hashes per second" to "memory-hard operations per second per dollar."

---

## 8. Rainbow Tables and Their Obsolescence

### 8.1 Time-Memory Trade-Off

Rainbow tables (Oechslin, 2003) are a time-memory trade-off for inverting hash functions. Given a hash $h = H(p)$, a rainbow table allows recovering $p$ in approximately $O(N^{2/3})$ time for an $N$-entry password space, with $O(N)$ storage.

**Precomputation**: Generate chains of hash-reduce pairs:

$$p_0 \xrightarrow{H} h_0 \xrightarrow{R_1} p_1 \xrightarrow{H} h_1 \xrightarrow{R_2} p_2 \xrightarrow{H} h_2 \xrightarrow{R_3} \cdots$$

where $R_i$ is a reduction function that maps hash values back to the password space. The chain stores only the start point $p_0$ and end point $p_k$ (called the "endpoint").

**Lookup**: Given $h = H(\text{target})$, apply reduction functions and check if the result matches any chain endpoint. If a match is found, recompute the chain from the start point to find the preimage.

Rainbow tables use a different reduction function for each chain position ($R_1, R_2, \ldots, R_t$), which eliminates **chain merges** (collisions that cause different chains to converge to the same endpoint). This was the key improvement over Hellman's original time-memory trade-off (1980).

### 8.2 Rainbow Table Parameters

For an $n$-character password space of size $|P|$:
- **Chain length** $t$: Number of hash-reduce steps per chain.
- **Number of chains** $m$: Total chains stored.
- **Success probability**: $1 - (1 - (m \cdot t / |P|))^m \approx 1 - e^{-m^2 \cdot t / |P|}$.
- **Table size**: $O(m)$ (store start and end points only).
- **Lookup time**: $O(t^2)$ (must check all $t$ possible positions, each requiring up to $t$ chain recomputations).

**Example**: For 8-character alphanumeric passwords ($|P| = 62^8 \approx 2^{47.6}$):
- Chain length: $t = 10,000$
- Number of chains: $m = |P| / t \approx 2^{34.3}$
- Storage: $2^{34.3} \times 16$ bytes (start + end) $\approx 256$ GB
- Lookup time: $10,000^2 / 2 = 5 \times 10^7$ hash operations $\approx$ seconds

### 8.3 Salting Defeats Rainbow Tables

A **salt** is a random value prepended to the password before hashing:

$$h = H(\text{salt} \| p)$$

The salt is stored alongside the hash (it is not secret) and must be unique per user. When a salt is used, the attacker must build a separate rainbow table for each salt value. If there are $S$ distinct salts, the storage cost increases by a factor of $S$.

For $S = 2^{128}$ salts (as modern systems use), rainbow tables are completely infeasible: each salt would require a separate 256 GB table, and the total storage would be $2^{128} \times 256$ GB $\gg$ the estimated number of atoms in the observable universe.

**Salting best practices**:
- Use a unique salt per password (not per user, not per system).
- Salt length: at least 128 bits (16 bytes).
- Store the salt in cleartext alongside the hash.
- Use a KDF (PBKDF2, bcrypt, Argon2) instead of a simple hash.

### 8.4 Why Rainbow Tables Are Obsolete

Rainbow tables were relevant in the era of unsalted MD5/SHA-1 password hashes. Modern systems use salted KDFs, which render rainbow tables useless:

1. **Salting**: Unique per-password salts prevent precomputation.
2. **Memory-hard KDFs**: bcrypt, scrypt, and Argon2 require large amounts of memory per hash evaluation, making precomputation and online attacks both expensive.
3. **Increasing KDF iterations**: bcrypt cost=12 requires $\sim 4,096$ iterations; PBKDF2 with $\sim 100,000$ rounds. Each candidate password requires this many hash evaluations.

**Modern password cracking** (2024):
- **Hashcat** on a cluster of 8 RTX 4090s: ~$10^7$ bcrypt (cost=12) attempts/second; ~$10^{10}$ MD5 attempts/second.
- **Rule-based attacks**: Generate candidate passwords from dictionaries using rules (capitalize, append digits, leet speak, etc.).
- **Markov chain attacks**: Model password character distributions statistically.
- **Neural network password generators**: Use ML to predict likely passwords.

Rainbow tables have been superseded by these more efficient online cracking methods. For unsalted MD5 hashes, online cracking with Hashcat on a single GPU achieves $9.5 \times 10^{10}$ MD5/s, cracking 95% of the RockYou password dataset (14.3M passwords) in seconds.

---

## 9. BCrypt and Argon2 Resistance Properties

### 9.1 BCrypt Resistance

bcrypt (Niacke and Mudge, 1999) is a password hashing function based on the Blowfish cipher's key schedule. Its key schedule (Eksblowfish) iteratively incorporates the salt and password into the cipher's subkeys, with a configurable cost parameter that exponentially scales the computation time.

**Resistance properties**:

1. **GPU resistance**: bcrypt's 4 KB S-box memory footprint reduces GPU parallelism. A GPU core must load 4 KB of S-box data into registers or shared memory, and the memory-dependent key schedule exercises the S-boxes with random access patterns that defeat GPU caching. An RTX 4090 achieves only $\sim 1.85 \times 10^5$ bcrypt/s at cost=10, compared to $9.5 \times 10^{10}$ MD5/s — a $5 \times 10^5$ slowdown factor.

2. **ASIC resistance**: Building an ASIC for bcrypt requires implementing 4 KB of SRAM per parallel core. At 28nm, each bcrypt core occupies $\sim 0.1$ mm², yielding $\sim 14,000$ cores per 100 mm² die. Each core processes $\sim 1000$ hashes/s at cost=10. Total: $\sim 1.4 \times 10^7$ bcrypt/s per die. This is comparable to a GPU but requires a custom ASIC design costing millions of dollars.

3. **Side-channel resistance**: bcrypt's key schedule is data-dependent — the S-box access pattern depends on the password. This creates a potential cache-timing side channel (see §04a). However, the cost parameter amplifies any timing difference, making practical exploitation difficult: each timing leak requires $\sim 2^{\text{cost}}$ measurements to amplify through the iterative structure.

4. **Known weaknesses**:
   - 72-byte password limit (inherited from Blowfish's 56-byte key + 16-byte salt).
   - 128-bit salt (adequate but smaller than modern recommendations of 192+ bits).
   - Cost parameter range of 4–31 (cost=31 takes $\sim 17$ seconds on modern hardware; cost=4 takes $\sim 1$ ms).
   - Not memory-hard: bcrypt uses only 4 KB, which is easily parallelizable on GPUs with large VRAM.

### 9.2 Argon2 Resistance

Argon2 (RFC 9106, Biryukov, Dinu, Khovratovich 2015) is the winner of the Password Hashing Competition and provides configurable resistance against GPU, ASIC, and side-channel attacks.

**Argon2id** (the recommended variant) provides:

1. **Memory-hardness**: The memory parameter $m$ (in KiB) forces the attacker to allocate $m$ KiB per hash evaluation. With $m = 65536$ (64 MB), a GPU with 24 GB VRAM can only run $\sim 375$ parallel instances, dramatically reducing throughput.

2. **Time-hardness**: The time parameter $t$ forces $t$ passes over the memory. Each pass recomputes the entire memory array, adding $\sim 2\times$ computation per pass. This increases the cost for attackers who trade memory for computation (the time-memory trade-off).

3. **Parallelism parameter**: The degree of parallelism $p$ controls the number of parallel lanes. This prevents attackers from accelerating a single hash computation by using more cores — Argon2id already uses $p$ cores optimally.

4. **Side-channel resistance**: Argon2id uses data-independent memory access in the first pass (resistant to cache timing attacks) and data-dependent access in subsequent passes (maximizing memory-hardness and tradeoff resistance). This hybrid approach provides both side-channel protection and strong memory-hardness.

**Tradeoff resistance formalization**: Argon2's memory-hardness is formally analyzed in terms of the **time-memory trade-off (TMTO)** attack. An attacker with memory $\alpha \cdot m$ (where $\alpha < 1$) but unlimited computation must spend:

$$C(\alpha) = \frac{t \cdot m^2}{\alpha} \cdot \left(\frac{1}{\alpha} - 1\right)^{0.5}$$

extra computation to complete a single hash evaluation. For $\alpha = 0.5$ (attacker uses half the recommended memory), the cost increases by $\sim 4\times$ for computation and $\sim 2\times$ for I/O. This TMTO resistance is stronger than scrypt's, which offers only $\sim 2\times$ cost for half memory.

### 9.3 Comparison Table

| Property | MD5 | SHA-256 | PBKDF2 | bcrypt | scrypt | Argon2id |
|---|---|---|---|---|---|---|
| GPU slowdown vs CPU | ~0.1× | ~0.2× | ~10× | ~10^4× | ~10^5× | ~10^6× |
| ASIC resistance | None | None | Low | Medium | High | Highest |
| Memory requirement | Fixed | Fixed | Fixed | 4 KB | Config. | Config. |
| Side-channel res. | N/A | N/A | Good | Medium | Poor (data-dep.) | Good (hybrid) |
| Max password len | None | None | None | 72 B | None | None |
| Salt size | N/A | N/A | Any | 128 bit | 128+ bit | Any |
| Configurable time? | No | No | Yes (iter.) | Yes (cost) | Yes (N) | Yes (t) |
| Memory-hard? | No | No | No | Min. 4KB | Yes | Yes |
| TMTO resistance | N/A | N/A | None | Low | Medium | High |
| Standard | RFC 1321 | FIPS 180-4 | RFC 2898 | none | RFC 7914 | RFC 9106 |

### 9.4 Migration Strategy

When migrating from a legacy hash (e.g., MD5, SHA-1) to Argon2id:

1. **Layered hashing**: On login, compute $\text{Argon2id}(\text{MD5}(\text{password}), \text{salt}_2)$ and store the new hash. The old MD5 hash is used as the "password" input to Argon2id, which inherits Argon2id's memory-hardness while maintaining compatibility with existing MD5 hashes.

2. **Transparent upgrade**: When a user logs in, verify the old hash, then re-hash with Argon2id and store the new hash. Over time, all active users are migrated. Inactive users retain the old hash format until they next log in.

3. **Algorithm identification**: Store a prefix that identifies the algorithm: `$argon2id$v=19$m=65536,t=3,p=4$...` for Argon2id, `$2b$12$...` for bcrypt, etc. This allows coexistence of multiple hash formats during migration.

```python
# Example: Layered hashing migration
import hashlib, argon2, os

def verify_password_stored(password, stored_hash):
    if stored_hash.startswith('$argon2id$'):
        # New format: Argon2id
        ph = argon2.PasswordHasher()
        try:
            ph.verify(stored_hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    elif stored_hash.startswith('$2b$'):
        # Legacy format: bcrypt
        import bcrypt
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    elif '$' not in stored_hash:
        # Ancient format: unsalted MD5
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        if md5_hash == stored_hash:
            # Upgrade to Argon2id immediately
            # But we CAN'T since we don't have the plaintext anymore...
            # We need to re-hash with Argon2id(md5_hash)
            return True  # Mark for upgrade
        return False

def upgrade_on_login(password, stored_hash):
    """Called after successful verification. Upgrades hash if needed."""
    if not stored_hash.startswith('$argon2id$'):
        # Re-hash with Argon2id
        ph = argon2.PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=4
        )
        new_hash = ph.hash(password)
        # Store new_hash in the database, replacing stored_hash
        return new_hash
    return stored_hash
```

---

## Cross-References

- **§01a** — Cryptographic fundamentals: hash function definitions, HMAC construction, KDF definitions
- **§01b** — Symmetric attacks: birthday attacks on cipher modes (related to collision resistance bounds)
- **§02a** — RSA/ECC attacks: key generation weaknesses (weak RNG → predictable salts/hashes)
- **§03a** — TLS attacks: FREAK/BREACH/CRIME (compression-based attacks exploiting hash collisions)
- **§04a** — Side-channel attacks: timing attacks on hash comparison, cache timing on SHA implementations
- **§05b** — Crypto engineering: KDF deployment, CSPRNG pitfalls (Debian OpenSSL → predictable salts)
- **§06** — Case studies: Flame (MD5 chosen-prefix collision), DigiNotar (certificate hash trust chain)

## References

1. Wang, X., Feng, D., Lai, X., Yu, H., "Collisions for Hash Functions MD4, MD5, HAVAL-128, and RIPEMD," CRYPTO Rump Session, 2004. https://eprint.iacr.org/2004/199
2. Stevens, M., Lenstra, A., de Weger, B., "Chosen-Prefix Collisions for MD5 and Colliding X.509 Certificates for Different Identities," EUROCRYPT 2007. https://eprint.iacr.org/2006/105
3. Stevens, M., Karpinski, M., Gorbunov, I., Lenstra, A., de Weger, B., "The First Collision for Full SHA-1," CRYPTO 2017 (SHAttered). https://shattered.io/
4. Leurent, G., Peyrin, T., "SHA-1 is a Shambles — Chosen-Prefix Collisions for SHA-1," CRYPTO 2020. https://shambles.net/
5. RFC 1321, "The MD5 Message-Digest Algorithm," April 1992. https://www.rfc-editor.org/rfc/rfc1321
6. RFC 2104, "HMAC: Keyed-Hashing for Message Authentication," February 1997. https://www.rfc-editor.org/rfc/rfc2104
7. Bellare, M., Canetti, R., Krawczyk, H., "Keying Hash Functions for Message Authentication," CRYPTO 1996. https://link.springer.com/chapter/10.1007/3-540-68697-5_8
8. NIST, "Secure Hash Standard (SHS)," FIPS 180-4, August 2015. https://csrc.nist.gov/publications/detail/fips/180/4/final
9. NIST, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions," FIPS 202, August 2015. https://csrc.nist.gov/publications/detail/fips/202/final
10. Oechslin, P., "Making a Faster Cryptanalytic Time-Memory Trade-Off," CRYPTO 2003. https://link.springer.com/chapter/10.1007/978-3-540-45146-4_36
11. Biryukov, A., Dinu, D., Khovratovich, D., "Argon2: New Generation of Memory-Hard Functions for Password Hashing," IEEE S&P 2016. RFC 9106. https://www.password-hashing.net/
12. Provos, N., Mazières, D., "A Future-Adaptive Password Scheme," USENIX ATC, 1999 (bcrypt). https://www.usenix.org/legacy/events/usenix99/provos.html
13. RFC 2898, "PKCS #5: Password-Based Cryptography Specification Version 2.0," September 2000. https://www.rfc-editor.org/rfc/rfc2898
14. Sotirov, A., Stevens, M., Appelbaum, J., "MD5 Considered Harmful Today — Creating a Rogue CA Certificate," CCC, 2008. https://www.win.tue.nl/hashclash/rogue-ca/
15. Flame malware analysis: Symantec, "Flame: The Story of the Most Complex Malware Yet," 2012. https://www.symantec.com/connect/blogs/flame-story-most-complex-malware-yet
16. RFC 6962, "Certificate Transparency," June 2013. https://www.rfc-editor.org/rfc/rfc6962
17. RFC 7914, "The scrypt Password-Based Key Derivation Function," August 2016. https://www.rfc-editor.org/rfc/rfc7914
18. Aumasson, J.-P., Neves, S., "BLAKE2: simpler, smaller, fast as MD5," ACNS 2013. https://www.blake2.net/blake2.pdf
19. RFC 9106, "Argon2 Password Hashing," September 2022. https://www.rfc-editor.org/rfc/rfc9106