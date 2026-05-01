# Cryptographic Fundamentals

> A rigorous treatment of symmetric and asymmetric cryptography, hash functions, message authentication, key derivation, entropy, and authenticated encryption — with emphasis on security properties, formal definitions, and implementation pitfalls that lead to real-world vulnerabilities.

---

## Table of Contents

1. [Symmetric Encryption](#1-symmetric-encryption)
2. [Asymmetric Encryption](#2-asymmetric-encryption)
3. [Hash Functions](#3-hash-functions)
4. [HMAC and Message Authentication](#4-hmac-and-message-authentication)
5. [Key Derivation Functions](#5-key-derivation-functions)
6. [Entropy and Randomness](#6-entropy-and-randomness)
7. [Block Cipher Modes of Operation](#7-block-cipher-modes-of-operation)
8. [Authenticated Encryption with Associated Data (AEAD)](#8-authenticated-encryption-with-associated-data-aead)

---

## 1. Symmetric Encryption

Symmetric encryption uses a single shared key for both encryption and decryption. The sender and receiver must establish the key through a secure channel before communication begins. The security of symmetric encryption rests on **Kerckhoffs's principle**: the system should be secure even if everything about the algorithm is public, with security residing solely in the key.

### 1.1 Formal Definitions

A **symmetric encryption scheme** is a triple of algorithms $\mathcal{SE} = (\mathcal{K}, \mathcal{E}, \mathcal{D})$:

- **Key generation** $\mathcal{K}$: On input security parameter $1^\lambda$, outputs key $k \leftarrow \mathcal{K}(1^\lambda)$.
- **Encryption** $\mathcal{E}$: Takes key $k$ and plaintext $m \in \{0,1\}^*$, outputs ciphertext $c \leftarrow \mathcal{E}_k(m)$.
- **Decryption** $\mathcal{D}$: Takes key $k$ and ciphertext $c$, outputs $m' = \mathcal{D}_k(c)$ such that $\mathcal{D}_k(\mathcal{E}_k(m)) = m$ for all valid $m$.

The fundamental security notion is **IND-CPA** (Indistinguishability under Chosen-Plaintext Attack): an adversary $\mathcal{A}$ given oracle access to $\mathcal{E}_k(\cdot)$ cannot distinguish encryptions of two chosen messages with non-negligible advantage. Formally:

$$\text{Adv}_{\mathcal{SE},\mathcal{A}}^{\text{ind-cpa}} = \left|\Pr\left[\mathcal{A}^{\mathcal{E}_k(\cdot)}(1^\lambda) = 1 \mid b=1\right] - \Pr\left[\mathcal{A}^{\mathcal{E}_k(\cdot)}(1^\lambda) = 1 \mid b=0\right]\right| \leq \text{negl}(\lambda)$$

A stronger notion, **IND-CCA** (Indistinguishability under Chosen-Ciphertext Attack), grants the adversary a decryption oracle as well (with the restriction that it cannot decrypt the challenge ciphertext). This is the gold standard for symmetric encryption security.

### 1.2 Advanced Encryption Standard (AES)

AES (FIPS 197, NIST 2001) is a substitution-permutation network operating on a $4 \times 4$ byte state matrix. It supports key sizes of 128, 192, and 256 bits, with 10, 12, and 14 rounds respectively.

Each round applies four transformations:

1. **SubBytes**: Non-linear byte substitution using the S-box $S: \{0,1\}^8 \rightarrow \{0,1\}^8$, defined as $S(a) = a^{-1} \cdot M \oplus c$ over $\mathbb{F}_{2^8}$, where $M$ is an invertible matrix and $c = \mathtt{0x63}$.
2. **ShiftRows**: Cyclic left shift of row $i$ by $i$ positions: row 0 unchanged, row 1 shifted by 1, row 2 by 2, row 3 by 3.
3. **MixColumns**: Matrix multiplication over $\mathbb{F}_{2^8}$: each column is multiplied by the fixed matrix:

$$\begin{pmatrix} 2 & 3 & 1 & 1 \\ 1 & 2 & 3 & 1 \\ 1 & 1 & 2 & 3 \\ 3 & 1 & 1 & 2 \end{pmatrix}$$

4. **AddRoundKey**: XOR with the round key derived via the key schedule.

The key schedule expands the cipher key $k$ into $N_r + 1$ round keys, each 128 bits. For AES-128:

```
RoundKey[i] = W[4*i] || W[4*i+1] || W[4*i+2] || W[4*i+3]
W[i] = W[i-Nk] ⊕ SubWord(RotWord(W[i-1])) ⊕ Rcon[i/Nk]   (if i % Nk == 0)
W[i] = W[i-Nk] ⊕ W[i-1]                                   (otherwise)
```

**AES-NI Instruction Set**: Modern x86 processors (Intel Westmere+, AMD Bulldozer+) implement AES rounds in hardware via `AESENC`, `AESDEC`, `AESKEYGENASSIST` instructions. This eliminates timing side channels from table-based implementations and provides ~10x throughput improvement. A single AES-NI round executes in ~1 cycle, yielding throughput >4 cycles/byte for AES-128 in CBC mode and ~1.3 cycles/byte in CTR mode with pipelining.

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = os.urandom(32)  # AES-256
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(b'sixteen byte blk') + encryptor.finalize()
```

**AES security**: The best known attack on full AES is the biclique attack (Bogdanov, Knudsen, Leander 2011) which reduces AES-128 complexity to $2^{126.1}$, AES-192 to $2^{190.3}$, and AES-256 to $2^{254.4}$. These are marginal improvements over brute force and do not threaten practical security. Related-key attacks on the full AES-256 key schedule reduce complexity to $2^{99.5}$, but the related-key model is generally considered unrealistic.

### 1.3 ChaCha20

ChaCha20 (Bernstein, 2008) is an ARX-based stream cipher derived from Salsa20. It operates on a 4×4 matrix of 32-bit words, performing 20 rounds of quarter-round operations. Each quarter-round operates on four words $a, b, c, d$:

$$a \mathrel{+}= b;\quad d \oplus= a;\quad d \lll 16$$
$$c \mathrel{+}= d;\quad b \oplus= c;\quad b \lll 12$$
$$a \mathrel{+}= b;\quad d \oplus= a;\quad d \lll 8$$
$$c \mathrel{+}= d;\quad b \oplus= c;\quad b \lll 7$$

where $+=$ is addition mod $2^{32}$, $\oplus=$ is XOR, and $\lll$ is left rotation.

The initial state is:

```
cccccccc  cccccccc  cccccccc  cccccccc   (constant "expand 32-byte k")
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk   (key words 0-3)
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk   (key words 4-7)
bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn   (counter || nonce)
```

ChaCha20 is preferred over AES in software on platforms without AES-NI (ARM Cortex-A8, older embedded processors). Google selected ChaCha20-Poly1305 as the default TLS cipher for Android and Chrome on mobile. Its constant-time nature (no data-dependent memory access) makes it inherently resistant to cache timing attacks — a property AES table-based implementations lack.

---

## 2. Asymmetric Encryption

Asymmetric (public-key) cryptography uses mathematically related key pairs: a public key for encryption/verification and a private key for decryption/signing. Security relies on computational hardness assumptions.

### 2.1 RSA

RSA (Rivest, Shamir, Adleman, 1977) security rests on the **Integer Factorization Problem (IFP)**: given $n = p \cdot q$ where $p, q$ are large primes, computing $p$ and $q$ is infeasible.

**Key generation**:
1. Generate two random primes $p, q$ of equal bit length.
2. Compute $n = p \cdot q$ and $\lambda(n) = \text{lcm}(p-1, q-1)$.
3. Select public exponent $e$, typically $e = 65537 = 2^{16} + 1$.
4. Compute private exponent $d = e^{-1} \mod \lambda(n)$.

**Encryption**: $c = m^e \mod n$

**Decryption**: $m = c^d \mod n$

Correctness follows from Euler's theorem: $c^d = (m^e)^d = m^{ed} = m^{1 + k\lambda(n)} = m \cdot (m^{\lambda(n)})^k \equiv m \cdot 1^k = m \pmod{n}$.

The choice of $e = 65537$ balances security and efficiency: it's a prime with only two 1-bits in binary (0b10000000000000001), making modular exponentiation require only 17 multiplications. Low exponents ($e = 3$) are vulnerable to Coppersmith attacks (see §02a).

**Key size recommendations** (NIST SP 800-57 Part 1, Rev 5):
| Security Level | RSA Minimum | ECDH/ECDSA Curve |
|---|---|---|
| 112 bits | 2048 bits | P-224 |
| 128 bits | 3072 bits | P-256 |
| 192 bits | 7680 bits | P-384 |
| 256 bits | 15360 bits | P-521 |

The asymptotic number field sieve (GNFS) complexity for factoring $n$-bit RSA moduli is approximately $L_n[1/3, (64/9)^{1/3}] \approx \exp\left((1.923 + o(1))(\ln n)^{1/3}(\ln \ln n)^{2/3}\right)$.

### 2.2 Elliptic Curve Cryptography (ECC)

ECC operates on the algebraic structure of elliptic curves over finite fields. An elliptic curve $E$ over $\mathbb{F}_p$ is defined by the Weierstrass equation:

$$E: y^2 = x^3 + ax + b \pmod{p}$$

where $4a^3 + 27b^2 \not\equiv 0 \pmod{p}$ (non-singularity).

The **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: given points $P$ and $Q = [k]P$ on the curve, find $k$. For well-chosen curves, the best known attack remains Pollard's rho with complexity $O(\sqrt{n})$ where $n$ is the curve order. This means a 256-bit curve provides ~128-bit security — vastly more compact than RSA's 3072-bit modulus for equivalent security.

**Point addition** is the group operation. Given points $P = (x_1, y_1)$ and $Q = (x_2, y_2)$ with $P \neq Q$:

$$\lambda = \frac{y_2 - y_1}{x_2 - x_1} \pmod{p}, \qquad x_3 = \lambda^2 - x_1 - x_2 \pmod{p}, \qquad y_3 = \lambda(x_1 - x_3) - y_1 \pmod{p}$$

**Scalar multiplication** $[k]P = P + P + \cdots + P$ ($k$ times) is computed efficiently via double-and-add or more sophisticated methods (e.g., Montgomery ladder for constant-time operation).

**Standard curves**:
| Curve | Prime (bits) | Security Level | Notes |
|---|---|---|---|
| NIST P-256 (secp256r1) | 256 | ~128 | Widely deployed; constant seed raised trust concerns |
| NIST P-384 (secp384r1) | 384 | ~192 | Common in government/tls |
| Curve25519 | 255 | ~128 | Bernstein; Montgomery form; constant-time by design |
| Curve448 | 448 | ~224 | Bernstein; Goldilocks curve |
| secp256k1 | 256 | ~128 | Used by Bitcoin; Koblitz curve |

Curve25519 (Montgomery form: $y^2 = x^3 + 486662x^2 + x$) deserves special attention because its Montgomery ladder enables **constant-time** scalar multiplication without conditional branches — eliminating timing side channels by construction. The x-coordinate-only Diffie-Hellman function `X25519` (RFC 7748) operates in 3.2μs on a modern x86 core, compared to ~1ms for RSA-2048 decryption.

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ECDH on Curve25519
alice_private = X25519PrivateKey.generate()
bob_private = X25519PrivateKey.generate()
alice_shared = alice_private.exchange(bob_private.public_key())
bob_shared = bob_private.exchange(alice_private.public_key())
assert alice_shared == bob_shared

# EdDSA (Ed25519) signatures
signing_key = Ed25519PrivateKey.generate()
signature = signing_key.sign(b'message to sign')
verify_key = signing_key.public_key()
verify_key.verify(signature, b'message to sign')
```

### 2.3 Diffie-Hellman Key Exchange

Diffie-Hellman (DH, 1976) enables two parties to establish a shared secret over an insecure channel. In the finite field setting:

1. Public parameters: large prime $p$, generator $g$ of a subgroup of $\mathbb{Z}_p^*$.
2. Alice picks random $a$, sends $A = g^a \mod p$.
3. Bob picks random $b$, sends $B = g^b \mod p$.
4. Shared secret: $s = B^a = A^b = g^{ab} \mod p$.

Security depends on the **Computational Diffie-Hellman (CDH)** assumption: given $g, g^a, g^b$, computing $g^{ab}$ is hard. The stronger **Decisional Diffie-Hellman (DDH)** assumption: given $g, g^a, g^b, g^c$, distinguishing $g^c = g^{ab}$ from random is hard.

**Logjam attack (2015)**: Adrian et al. demonstrated that 1024-bit DH groups can be factored using NFS with ~$100M in computation (amortized per prime). Since many TLS implementations used hardcoded primes (e.g., Oakley Group 2: `modp1024`), a single precomputation enables decrypting all connections using that prime. This motivated the transition to ECDH (see §03a).

**Elliptic Curve Diffie-Hellman (ECDH)** replaces modular exponentiation with scalar multiplication on elliptic curves, providing equivalent security at much smaller key sizes. X25519 (RFC 7748) is the modern standard.

---

## 3. Hash Functions

### 3.1 Properties and Definitions

A cryptographic hash function $H: \{0,1\}^* \rightarrow \{0,1\}^n$ must satisfy:

1. **Preimage resistance (one-wayness)**: Given $y$, it is computationally infeasible to find any $x$ such that $H(x) = y$. Formally, for any PPT adversary $\mathcal{A}$:
$$\Pr[\mathcal{A}(H(x)) = x'] \leq \text{negl}(n) \text{ where } H(x') = H(x)$$

2. **Second preimage resistance**: Given $x$, it is infeasible to find $x' \neq x$ such that $H(x') = H(x)$.

3. **Collision resistance**: It is infeasible to find *any* pair $(x, x')$ with $x \neq x'$ such that $H(x) = H(x')$.

By the birthday paradox, collision resistance implies an upper bound on security at $n/2$ bits for an $n$-bit hash. Preimage resistance is bounded at $n$ bits. Therefore, **collision resistance is always the weaker property**.

### 3.2 SHA-2 Family

SHA-2 (FIPS 180-4) comprises SHA-224, SHA-256, SHA-384, and SHA-512, producing 224, 256, 384, and 512-bit digests respectively. SHA-256 and SHA-512 are the workhorses of modern cryptography.

SHA-256 processes 512-bit message blocks through 64 rounds. Each round applies:

$$\text{Ch}(E,F,G) = (E \wedge F) \oplus (\neg E \wedge G)$$
$$\text{Maj}(A,B,C) = (A \wedge B) \oplus (A \wedge C) \oplus (B \wedge C)$$
$$\Sigma_0(A) = \text{ROTR}^2(A) \oplus \text{ROTR}^{13}(A) \oplus \text{ROTR}^{22}(A)$$
$$\Sigma_1(E) = \text{ROTR}^6(E) \oplus \text{ROTR}^{11}(E) \oplus \text{ROTR}^{25}(E)$$
$$T_1 = H + \Sigma_1(E) + \text{Ch}(E,F,G) + K_t + W_t$$
$$T_2 = \Sigma_0(A) + \text{Maj}(A,B,C)$$

where $K_t$ are the round constants (first 32 bits of fractional parts of cube roots of first 64 primes), and $W_t$ are the message schedule words derived via the $\sigma$ functions from the input block.

**Intel SHA Extensions** (Icelake+, Zen+): The `sha256rnds2` instruction accelerates SHA-256 rounds in hardware, providing ~3x throughput improvement over software-only implementations. This is critical for Proof-of-Work systems and TLS handshakes.

### 3.3 SHA-3 (Keccak)

SHA-3 (FIPS 202) is based on the Keccak sponge construction, selected through the NIST SHA-3 competition (2007–2012). Unlike Merkle-Damgård hashes, the sponge construction provides:

- **Indifferentiability from a random oracle** — proving security in the random oracle model carries over to the sponge.
- **Built-in resistance to length extension attacks** — the sponge's capacity section absorbs output influence, preventing the extension attack that afflicts MD hashes.

The Keccak-$f[b]$ permutation operates on a $5 \times 5 \times 64$-bit state (for $b = 1600$), organized as a 3D array of lanes. It consists of 24 rounds, each applying five transformations ($\theta$, $\rho$, $\pi$, $\chi$, $\iota$):

- $\theta$: Column parity mixing
- $\rho$: Lane rotation offsets (offsets defined by a specific sequence)
- $\pi$: Lane position permutations (position transposition)
- $\chi$: Non-linear row mixing (the only non-linear step)
- $\iota$: Round constant XOR

The sponge rate/capacity split determines security: for SHA3-256, rate $r = 1088$ and capacity $c = 512$, giving collision resistance of $\min(256, c/2) = 256$ bits and preimage resistance of $\min(256, c) = 256$ bits. **Important**: SHA-3's collision resistance is 128 bits for SHA3-256 when measured by the birthday bound on the *output*, but the capacity argument gives $\min(2^{256}, 2^{256}) = 2^{256}$ for preimage and $\min(2^{128}, 2^{256}) = 2^{128}$ for collision.

```python
import hashlib

# SHA-3 variants
sha3_256 = hashlib.sha3_256(b'data').hexdigest()
sha3_512 = hashlib.sha3_512(b'data').hexdigest()

# SHAKE128/256 (extendable output functions)
shake128 = hashlib.shake_128(b'data').hexdigest(64)  # 512-bit output
shake256 = hashlib.shake_256(b'data').hexdigest(128)  # 1024-bit output
```

### 3.4 BLAKE2 and BLAKE3

**BLAKE2** (Aumasson, Neves, 2012) is a successor to BLAKE (a SHA-3 finalist), optimized for software speed. BLAKE2b (64-bit, up to 512-bit output) processes data at 3.08 cycles/byte on Intel Haswell — faster than SHA-256 (11.9 c/b) and even MD5 (5.6 c/b with collision risk). BLAKE2s targets 32-bit platforms with up to 256-bit output.

BLAKE2 uses a ChaCha-like ARX core with a simplified parameter block. Key features:
- **Keyed mode**: BLAKE2 can be used as a MAC with a key of up to 64 bytes, without needing HMAC construction.
- **Salt and personalization**: Built-in parameters for domain separation.
- **Tree hashing**: Parallel mode for multi-core processing.

**BLAKE3** (2020) further optimizes by:
- Using a Merkle tree structure that enables verifiable parallelism.
- Replacing the ChaCha round function with a smaller 16-word permutation.
- tree_hash enables O(n/cores) hashing on multi-core systems.
- Built-in keyed mode, key derivation mode (KDF), and PRF mode.

```python
import blake2b  # or use hashlib.blake2b
h = hashlib.blake2b(key=b'secret_key', digest_size=32)
h.update(b'data')
digest = h.hexdigest()

# BLAKE3 (requires blake3 package)
from blake3 import blake3 as blake3_hash
h = blake3_hash()
h.update(b'data')
digest = h.hexdigest(digest_size=32)
```

---

## 4. HMAC and Message Authentication

### 4.1 HMAC Construction

HMAC (RFC 2104, FIPS 198-1) computes a MAC using any iterated hash function $H$:

$$\text{HMAC}_K(m) = H\left((K' \oplus \text{opad}) \| H\left((K' \oplus \text{ipad}) \| m\right)\right)$$

where:
- $K' = H(K)$ if $|K| > B$ (block size), else $K'$ is $K$ padded with zeros to $B$ bytes.
- $\text{ipad} = \mathtt{0x36}$ repeated $B$ times.
- $\text{opad} = \mathtt{0x5C}$ repeated $B$ times.

**Security properties**: HMAC's security proof (Bellare, Canetti, Krawczyk 1996) reduces to the collision resistance of the compression function in the PRF model. Crucially, HMAC remains secure even if the underlying hash function's collision resistance is broken — this is why HMAC-MD5, while its hash is cryptbroken for collisions, remains adequate for MAC purposes (though migration is still recommended).

The security bound for HMAC is:

$$\text{Adv}^{\text{PRF}}_{H}(\mathcal{A}) \leq \frac{q^2}{2^{n+1}} + \frac{q}{2^b} + \text{Adv}^{\text{PRF}}_{f}$$

where $n$ is the output length, $b$ is the block length, $q$ is the number of queries, and $f$ is the compression function. For HMAC-SHA256 with $n=256$, an adversary making $2^{80}$ queries has advantage at most $2^{80}/2^{257} + 2^{80}/2^{512} + \epsilon \approx \epsilon$, which is negligible.

### 4.2 HMAC Timing Side Channels

Naive comparison of MAC tags is vulnerable to timing attacks:

```python
# VULNERABLE: short-circuit comparison
def verify(mac_provided, mac_expected):
    return mac_provided == mac_expected

# SECURE: constant-time comparison
import hmac
def verify(mac_provided, mac_expected):
    return hmac.compare_digest(mac_provided, mac_expected)
```

A timing attack on string comparison leaks 1 bit per comparison by measuring response time differences. Over $n$ character positions, this recovers the entire MAC tag in $256 \times n$ queries (worst case), reducing the effective security from $2^n$ to $O(n)$.

**CVE-2013-0169** (Lucky13, see §03a) is a timing side channel on CBC padding verification in TLS that requires the same constant-time comparison discipline.

### 4.3 AEAD MAC vs HMAC

Modern protocols prefer AEAD modes (AES-GCM, ChaCha20-Poly1305) where the MAC is an integral part of the cipher mode, not a separate HMAC construction. AEAD MACs use GHASH (GCM) or Poly1305 (ChaCha20-Poly1305) — both much faster than HMAC-SHA256. However, AEAD MACs are fundamentally different from HMAC:

- **HMAC** is a PRF — it can be used for key derivation, challenge-response, and message authentication.
- **GHASH/Poly1305** are universal hash functions — they are one-time MACs that require a unique nonce for security. Reusing a nonce with AES-GCM reveals the authentication key and allows forgery (see §01b).

---

## 5. Key Derivation Functions

### 5.1 PBKDF2

PBKDF2 (RFC 2898, NIST SP 800-132) applies a pseudorandom function (typically HMAC-SHA256) iteratively:

$$DK = \text{PBKDF2}(PRF, P, S, c, dkLen) = T_1 \| T_2 \| \cdots \| T_{\lceil dkLen/hLen \rceil}$$

where $T_i = F(P, S, c, i) = U_1 \oplus U_2 \oplus \cdots \oplus U_c$, with $U_1 = PRF(P, S \| i)$ and $U_j = PRF(P, U_{j-1})$.

PBKDF2's iterative hashing increases the cost for an attacker attempting brute force: each password guess requires $c$ PRF evaluations. However, PBKDF2's computational hardness is **CPU-bound** — it can be efficiently parallelized on GPUs and ASICs. Bitcoin mining hardware (which computes SHA-256) demonstrates that ASICs can achieve $\sim10^{14}$ SHA-256/s, making PBKDF2's CPU cost negligible against determined attackers with specialized hardware.

### 5.2 bcrypt

bcrypt (Niacke, 1999) is based on Blowfish's key schedule with the **Eksblowfish** algorithm:

1. Generate 128-bit salt $S$.
2. Eksblowfish setup: Expand key $K$ and salt $S$ through $2^{\text{cost}}$ rounds of Blowfish key expansion. The cost parameter (4–31) scales exponentially.
3. Encrypt "OrpheanBeholderScryDoubt" (192 bits) 64 times with the resulting key.
4. Output: `$2b$cost$salt+hash` (60 characters).

bcrypt's key schedule is intentionally memory-hard relative to simple iterated hashing — each round of key expansion reads from the S-boxes and P-array, requiring 4 KB of state that must be maintained across iterations. This makes GPU/ASIC implementation less efficient than for PBKDF2, because GPUs favor compute-heavy but memory-light operations.

bcrypt's 56-byte key length limit (inherited from Blowfish) and 72-character password limit are its main weaknesses. Passwords exceeding 72 bytes are silently truncated.

### 5.3 scrypt

scrypt (RFC 7914, 2016) introduces **memory-hardness** as the primary defense against ASIC/GPU attacks:

$$\text{scrypt}(P, S, N, r, p, dkLen)$$

Parameters:
- $N$: CPU/memory cost parameter (power of 2). Must be $< 2^{32}$.
- $r$: Block size factor. Each block is $128r$ bytes.
- $p$: Parallelization parameter. Controls the number of independent PBKDF2 chains.

Algorithm:
1. $B_0 = \text{PBKDF2-HMAC-SHA256}(P, S, 1, p \cdot 128r)$
2. For $i = 0, \ldots, p-1$: $B_i = \text{ROMix}(B_i, N)$, where ROMix (read-write memory mixing) fills a vector $V$ of $N$ blocks of $128r$ bytes each, then pseudo-randomly reads from $V$.
3. $DK = \text{PBKDF2-HMAC-SHA256}(P, B_0 \| B_1 \| \cdots \| B_{p-1}, 1, dkLen)$

The ROMix loop is designed so that the optimal trade-off between memory and computation is $O(N)$ space and $O(N)$ time — an attacker with less memory must recompute values, increasing time cost quadratically.

### 5.4 Argon2

Argon2 (Biryukov, Dinu, Khovratovich, 2015) won the Password Hashing Competition (PHC) and is standardized as RFC 9106. It comes in three variants:

| Variant | Description | Use Case |
|---|---|---|
| **Argon2d** | Data-dependent memory access | Resists GPU cracking; vulnerable to side-channel timing |
| **Argon2i** | Data-independent memory access | Resists side-channel attacks; weaker against tradeoff attacks |
| **Argon2id** | Hybrid: data-independent first pass, data-dependent subsequent | **Recommended default**; best tradeoff |

Parameters:
- **Time cost** $t$: Number of iterations over the memory.
- **Memory cost** $m$: KiB of memory to use.
- **Parallelism** $p$: Degree of parallelism (number of lanes).
- **Output length** $dkLen$: Desired output hash length.

Argon2id with $m = 65536$ (64 MB), $t = 3$, $p = 4$ is recommended for general use (as of 2024). For threat models involving stateful adversaries, increase $m$ to 2–4 GiB.

```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)
hash_str = ph.hash("password123")

# Verification (constant-time internally)
try:
    ph.verify(hash_str, "password123")
except argon2.exceptions.VerifyMismatchError:
    print("Invalid password")
```

Argon2's memory-hardness is formally analyzed: the algorithm fills an $m$-block array $B$ where block $B[i]$ depends on $B[\phi(i)]$ for some data-dependent or data-independent index function $\phi$. The block compression function $G(X, Y)$ combines two 1024-byte blocks via a Blake2b-based mixing function, producing a single 1024-byte output.

**Security comparison** (assuming 8-character alphanumeric passwords):

| KDF | GPU hashrate (RTX 4090) | Time to crack (est.) |
|---|---|---|
| MD5 | ~95 GH/s | <1 second |
| SHA-256 | ~2.8 GH/s | ~2 hours |
| PBKDF2-SHA256 (100K iter) | ~28 KH/s | ~6 years |
| bcrypt (cost=12) | ~6 KH/s | ~30 years |
| scrypt (N=2^17, r=8, p=1) | ~2 KH/s | ~90 years |
| Argon2id (m=64MB, t=3, p=4) | ~0.5 KH/s* | ~360 years* |

*GPU performance severely degraded by memory requirements; Argon2id with 64MB per hash limits GPU parallelism to ~24 concurrent instances on a 16GB GPU.

---

## 6. Entropy and Randomness

### 6.1 The Role of Entropy in Cryptography

Entropy is the fundamental input to all cryptographic operations. Key generation, nonce creation, IV selection, and seed material for KDFs all require **cryptographically strong random numbers**. The gap between true randomness and pseudo-randomness is the source of some of the most devastating cryptographic failures (see §01b: Debian OpenSSL bug, §06: case studies).

A **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)** must satisfy:
1. **Next-bit test**: Given the first $k$ bits of output, no polynomial-time algorithm can predict bit $k+1$ with probability significantly greater than $1/2$.
2. **State compromise extension**: If the state is compromised at time $t$, it should be infeasible to reconstruct prior outputs (forward secrecy) and future outputs should be unpredictable until the generator is reseeded.

### 6.2 Entropy Sources

| Source | Platform | Entropy Rate | Quality |
|---|---|---|---|
| `/dev/random` | Linux | Blocking; varies | Collects from hardware/kernel events |
| `/dev/urandom` | Linux | Non-blocking; ~infinite | SHA-1/ChaCha20-based DRBG; sufficient for all purposes |
| `getrandom(2)` | Linux ≥ 3.17 | Non-blocking after init | Preferred API; avoids FD exhaustion |
| `RDRAND`/`RDSEED` | x86 (Ivy Bridge+) | ~8 GB/s | Hardware RNG; may composited with software |
| `ARMv8.5-RNG` | ARMv8.5+ | Variable | `mrs` instruction for RNDR/RNDRRS |
| `CryptGenRandom` / `BCryptGenRandom` | Windows | Non-blocking | Well-seeded CNG-based |
| `SecRandomCopyBytes` | macOS/iOS | Non-blocking | Yarrow-based → Fortuna → ChaCha20 |

**Modern recommendation**: Use the operating system's CSPRNG directly (via `getrandom(2)` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes` on macOS). Do not implement custom PRNGs. Do not read from `/dev/random` (it blocks unnecessarily and provides no security benefit over `/dev/urandom`).

```python
import os
import secrets

# Python recommended approach
key = secrets.token_bytes(32)    # 256-bit random key
nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
salt = secrets.token_bytes(16)   # 128-bit salt for KDF

# NEVER do this:
import random
key = bytes([random.randint(0, 255) for _ in range(32)])  # Mersenne Twister: NOT crypto-safe
```

### 6.3 DRBG Constructions

NIST SP 800-90A Rev. 1 defines three Deterministic Random Bit Generator (DRBG) constructions:

1. **Hash DRBG**: Based on a hash function (SHA-256, SHA-512). Uses a counter-mode construction. Security proof in the random oracle model.
2. **HMAC DRBG**: Based on HMAC. Internally maintains two state values: $V$ (value) and $K$ (key). Each request updates $K$ and $V$ via HMAC with reseeding after $2^{48}$ requests. **Preferred by many implementations** due to simplicity and security proof.
3. **CTR DRBG**: Based on AES in counter mode. Uses AES-256 to encrypt an incrementing counter. Requires reseeding after $2^{48}$ requests. Used by Windows CNG and many HSMs.

**HMAC DRBG** pseudocode (simplified):

```
Initialize(seed):
  K = 0x00...00 (32 bytes)
  V = 0x01...01 (32 bytes)
  Update(seed)

Update(provided_data):
  K = HMAC(K, V || 0x00 || provided_data)
  V = HMAC(K, V)
  if provided_data != null:
    K = HMAC(K, V || 0x01 || provided_data)
    V = HMAC(K, V)

Generate(requested_bits):
  if reseed_counter > reseed_interval:
    return reseed_required
  temp = empty
  while len(temp) < requested_bits:
    V = HMAC(K, V)
    temp = temp || V
  Update(null)
  reseed_counter++
  return leftmost_bits(temp, requested_bits)
```

### 6.4 Dual_EC_DRBG Backdoor

Dual_EC_DRBG was one of the four DRBGs in the original NIST SP 800-90 (2006). It is based on elliptic curve point multiplication and was **secretly designed by NSA** to contain a backdoor. The algorithm uses two fixed points $P$ and $Q$ on NIST P-256. If an adversary knows the discrete logarithm $d = \log_P(Q)$ (i.e., $Q = [d]P$), they can predict future outputs from a single 30-byte output sample:

Given output $s_2$, the adversary computes the internal state $s_2$ by trying $\sim 2^{16}$ candidates for the 30 unknown bits, then verifies each candidate. This reduces the security from 128 bits to approximately 16 bits of effort.

This backdoor was disclosed by Microsoft researchers (Shumow, Ferguson 2007) and confirmed by the Snowden leaks (2013). NIST removed Dual_EC_DRBG from SP 800-90A Rev. 1 (2015). See §06 for full case study.

---

## 7. Block Cipher Modes of Operation

### 7.1 Electronic Codebook (ECB)

$$C_i = E_K(P_i)$$

ECB encrypts each block independently. **This is catastrophically insecure**: identical plaintext blocks produce identical ciphertext blocks, leaking structural information about the plaintext. The classic demonstration is encrypting an image where the block-level structure of the original remains visible.

ECB provides **no semantic security** (IND-CPA): encrypting the same message twice under the same key gives the same ciphertext. Worse, an attacker can reorder, delete, or replay ciphertext blocks without detection.

**ECB should never be used for data longer than one block.** The only legitimate use is encrypting exactly one block (e.g., key wrapping where the key fits in a single block).

### 7.2 Cipher Block Chaining (CBC)

$$C_i = E_K(P_i \oplus C_{i-1}), \quad C_0 = IV$$
$$P_i = D_K(C_i) \oplus C_{i-1}$$

CBC chains each ciphertext block into the encryption of the next, achieving IND-CPA security when the IV is random and unpredictable. **Critical requirement**: the IV must be unpredictable — if the IV is predictable, CBC is vulnerable to the BEAST attack (see §03a). The IV does not need to be secret, only unpredictable.

**Padding**: CBC requires plaintext to be a multiple of the block size. PKCS#7 padding appends $n$ bytes of value $n$, where $n$ is the number of padding bytes needed. This padding creates a vulnerability to padding oracle attacks (see §01b).

**Parallelism**: CBC encryption is inherently sequential (each block depends on the previous ciphertext). Decryption is parallelizable since all ciphertext blocks are known. This asymmetry makes CBC encryption slower than CTR/GCM modes on multi-core systems.

### 7.3 Counter Mode (CTR)

$$C_i = P_i \oplus E_K(\text{nonce} \| \text{counter}_i)$$

CTR mode turns a block cipher into a stream cipher. The keystream is generated by encrypting incrementing counters (starting from a nonce), and plaintext is XORed with this keystream.

**Properties**:
- **IND-CPA secure** if the nonce is never reused with the same key.
- **Fully parallelizable** for both encryption and decryption.
- **Random access**: any block can be decrypted independently.
- **No padding required**: ciphertext length equals plaintext length.

**Critical vulnerability**: nonce reuse is catastrophic. If two messages $m_1, m_2$ are encrypted with the same nonce $n$:

$$C_1 = m_1 \oplus E_K(n \| 0), \quad C_2 = m_2 \oplus E_K(n \| 0)$$
$$C_1 \oplus C_2 = m_1 \oplus m_2$$

This XOR of ciphertexts equals the XOR of plaintexts, enabling known-plaintext and crib-dragging attacks. Prepend a known header (e.g., HTTP headers, file magic bytes) and you can recover the keystream, then decrypt all messages using that nonce.

### 7.4 Galois/Counter Mode (GCM)

GCM (NIST SP 800-38D) combines CTR mode encryption with GHASH authentication:

**Encryption**: Same as CTR mode, with the first counter value reserved for the authentication tag.

**Authentication**: GHASH is a universal hash function over $\mathbb{F}_{2^{128}}$ (Galois field with irreducible polynomial $x^{128} + x^7 + x^2 + x + 1$):

$$S = \sum_{i=1}^{m} (C_i \cdot H^{i}) + (A_{\text{len}} \| C_{\text{len}}) \cdot H^{m+1}$$

where $H = E_K(0^{128})$ is the hash key, and $A_{\text{len}}, C_{\text{len}}$ are the bit lengths of associated data and ciphertext.

$$\text{Tag} = E_K(\text{nonce} \| 0^{31}1) \oplus S$$

**Properties**:
- **IND-CCA secure** (AEAD: authenticated encryption with associated data).
- **Parallelizable**: both encryption (CTR) and authentication (GHASH carry-less multiplication) are parallelizable.
- **Hardware acceleration**: Intel PCLMULQDQ instruction (Westmere+) and ARM PMULL instruction accelerate GHASH to ~1 cycle/carry-less multiplication.

**GCM nonce reuse is catastrophic**: reusing a nonce with the same key reveals $H = E_K(0^{128})$, allowing arbitrary tag forgeries. This is because two messages with the same nonce produce tags $T_1 = S_1 \oplus E_K(J_0)$ and $T_2 = S_2 \oplus E_K(J_0)$, and XORing them cancels $E_K(J_0)$, revealing the GHASH key $H$. See §01b for detailed exploitation.

**GCM tag length**: Short tags (≤64 bits) are subject to forgery attacks with $2^{t/2}$ queries. NIST requires a minimum tag length of 96 bits for general use. Short tags are only acceptable in constrained protocols with strict query limits.

### 7.5 XTS Mode

XTS-AES (IEEE P1619, NIST SP 800-38E) is designed for disk encryption, where ciphertext must be the same length as plaintext and sector-level operations are needed.

$$C_i = E_{K_2}(E_{K_1}(P_i \oplus \alpha^i \cdot E_{K_2}(T))) \oplus \alpha^i \cdot E_{K_2}(T)$$

where $T$ is the sector number (tweak), $\alpha$ is a primitive element of $\mathbb{F}_{2^{128}}$, and $K_1, K_2$ are two independent AES keys.

XTS is a **narrow-block** mode — each 16-byte block is encrypted independently within a sector. This means it provides **no diffusion across blocks**: an adversary who flips a bit in ciphertext flips exactly one bit in plaintext (in the same location within the block). This is acceptable for disk encryption where the attacker can only observe ciphertext and cannot perform chosen-plaintext attacks at the block level, but XTS does not provide authenticated encryption.

**Why not GCM for disk encryption?** GCM produces an authentication tag that must be stored alongside the ciphertext, requiring additional space. For disk encryption, any space overhead is unacceptable. Additionally, GCM cannot decrypt a random-access block without processing all previous blocks (for authentication), making it incompatible with sector-level random access.

---

## 8. Authenticated Encryption with Associated Data (AEAD)

### 8.1 The AEAD Definition

AEAD (RFC 5116) provides three guarantees:
1. **Confidentiality**: IND-CPA security for the plaintext.
2. **Integrity**: Any modification of ciphertext or associated data is detected.
3. **Authenticity**: The ciphertext was produced by a party knowing the key.

Formally, an AEAD scheme $\Pi = (\mathcal{K}, \mathcal{S}, \mathcal{D})$ with encryption $\mathcal{S}_K^N,A(M)$ and decryption $\mathcal{D}_K^N,A(C,T)$ where $N$ is a nonce, $A$ is associated data, $M$ is plaintext, $C$ is ciphertext, and $T$ is tag, satisfies:

$$\Pr\left[\mathcal{D}_K^{N,A}(C^*, T^*) \neq \bot\right] \leq \frac{q}{2^t} + \text{negl}(\lambda)$$

for any adversary making $q$ decryption queries, where $t$ is the tag length. This bound is tight: an attacker can forge a tag with probability $\sim q/2^t$ by random guessing, and better attacks cannot exceed this by much.

### 8.2 AEAD Modes Comparison

| Mode | Cipher | Auth | Parallel Enc | Parallel Dec | Nonce Misuse | Patents |
|---|---|---|---|---|---|---|
| AES-GCM | AES | GHASH | Yes | Yes | Catastrophic | Expired |
| AES-CCM | AES | CBC-MAC | No | No | Transient | None |
| ChaCha20-Poly1305 | ChaCha20 | Poly1305 | Yes | Yes | Transient | None |
| AES-SIV | AES | CMAC | No | No | **Nonce-misuse resistant** | None |
| AES-GCM-SIV | AES | Polyval | Yes | Yes | **Nonce-misuse resistant** | None |
| OCB3 | AES | Internal | Yes | Yes | Catastrophic | Expired |

**Nonce-misuse resistant** modes (SIV, GCM-SIV) guarantee that even if nonces are reused, the only consequence is that identical messages produce identical ciphertexts — the deterministic encryption property. No key material is leaked and no forgeries become possible. This is formally called **MRAE** (Misuse-Resistant Authenticated Encryption).

### 8.3 AEAD in Practice

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# AES-GCM
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce; DO NOT reuse with same key
ct = aesgcm.encrypt(nonce, b'secret message', b'associated data')
pt = aesgcm.decrypt(nonce, ct, b'associated data')

# ChaCha20-Poly1305
key = ChaCha20Poly1305.generate_key(bit_length=256)
cipher = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = cipher.encrypt(nonce, b'secret message', b'associated data')
pt = cipher.decrypt(nonce, ct, b'associated data')
```

**Nonce management** is the hardest part of AEAD deployment. Recommended strategies:
1. **Counter-based**: Maintain a persistent counter as the nonce. Requires state synchronization. Risk: counter resets on restart.
2. **Random nonce**: Generate a 96-bit random nonce for each message. With $2^{32}$ messages, collision probability is $< 2^{-32}$ (by birthday bound). For GCM, this is acceptable; for CTR, this is catastrophic if collisions occur.
3. **Nonce-misuse resistant modes**: Use AES-GCM-SIV or AES-SIV if nonce uniqueness cannot be guaranteed. These modes have ~1.5x overhead compared to standard GCM but provide MRAE security.

**OpenSSL command-line AEAD**:
```bash
# AES-256-GCM encryption
openssl enc -aes-256-gcm -in plaintext.txt -out ciphertext.bin \
    -K $(openssl rand -hex 32) -iv $(openssl rand -hex 12)

# Key generation
openssl rand -hex 32  # 256-bit key
openssl rand -hex 12   # 96-bit nonce for GCM
```

### 8.4 Composing AEAD from Primitives

A common mistake is constructing AEAD by concatenating encryption and MAC (Encrypt-and-MAC, MAC-then-Encrypt, Encrypt-then-MAC). Only **Encrypt-then-MAC** is provably secure:

- **Encrypt-and-MAC** ($C = E_K(m), T = \text{MAC}_{K'}(m)$): Leaks information because the MAC is over plaintext.
- **MAC-then-Encrypt** ($C = E_K(m \| T)$): Vulnerable to padding oracle attacks (see TLS 1.0/1.1 CBC, §03a).
- **Encrypt-then-MAC** ($C = E_K(m), T = \text{MAC}_{K'}(C)$): Provably IND-CCA secure if both primitives are secure. **Always use this composition** if you must compose primitives manually. Or better: use an AEAD mode.

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes

def encrypt_then_mac(key_enc, key_mac, nonce, plaintext, aad):
    # Encrypt
    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # MAC over nonce + aad + ciphertext
    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(nonce + aad + ciphertext)
    tag = h.finalize()
    
    return ciphertext, tag
```

The AEAD composition theorem (Bellare & Namprempre 2000) shows that Encrypt-then-MAC with a PRF-secure MAC and IND-CPA-secure encryption yields an IND-CCA-secure scheme. This is the theoretical foundation for why TLS 1.2+ and TLS 1.3 use AEAD modes rather than composition.

---

## Cross-References

- **§01b** — Symmetric crypto attacks that exploit the weaknesses described here (ECB patterns, CBC bit-flipping, padding oracles, nonce reuse)
- **§02a** — RSA and ECC attacks targeting the asymmetric primitives described here
- **§02b** — Hash and MAC attacks subverting the hash functions and HMAC constructions here
- **§03a** — TLS protocol attacks that compose the primitive-level attacks into protocol-level exploits
- **§04a** — Side-channel attacks that recover keys from timing, power, and cache behavior of the implementations here
- **§04b** — Hardware attacks targeting the physical realization of these cryptographic primitives
- **§05a** — Post-quantum replacements for RSA and ECC
- **§05b** — Crypto engineering practices for safely deploying these primitives
- **Chromium Architecture** track — V8's Crypto API, Chromium's TLS/BoringSSL implementation
- **Linux Kernel** track — kernel CSPRNG (/dev/urandom, getrandom), AF_ALG crypto API, dm-crypt/XTS

## References

1. NIST, "Advanced Encryption Standard (AES)," FIPS 197, November 2001. https://csrc.nist.gov/publications/detail/fips/197/final
2. NIST, "Secure Hash Standard (SHS)," FIPS 180-4, August 2015. https://csrc.nist.gov/publications/detail/fips/180/4/final
3. NIST, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions," FIPS 202, August 2015. https://csrc.nist.gov/publications/detail/fips/202/final
4. NIST, "Recommendation for Key Management — Part 1: General," SP 800-57 Part 1 Rev. 5, May 2020. https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
5. NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," SP 800-38D, November 2007. https://csrc.nist.gov/publications/detail/sp/800-38d/final
6. NIST, "Recommendation for Block Cipher Modes of Operation: XTS-AES," SP 800-38E, January 2010. https://csrc.nist.gov/publications/detail/sp/800-38e/final
7. NIST, "Recommendation for Password-Based Key Derivation — Part 1: Storage Applications," SP 800-132, December 2010. https://csrc.nist.gov/publications/detail/sp/800-132/final
8. NIST, "Recommendation for Random Number Generation Using Deterministic Random Bit Generators," SP 800-90A Rev. 1, June 2015. https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
9. Rivest, R., "The MD5 Message-Digest Algorithm," RFC 1321, April 1992. https://www.rfc-editor.org/rfc/rfc1321
10. Krawczyk, H., Bellare, M., Canetti, R., "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, February 1997. https://www.rfc-editor.org/rfc/rfc2104
11. Barker, E., Roginsky, A., "Transitioning the Use of Cryptographic Algorithms and Key Lengths," SP 800-131A Rev. 2, March 2019. https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
12. Bernstein, D.J., "ChaCha, a variant of Salsa20," Workshop Record of SASC, 2008. https://cr.yp.to/chacha/chacha-20080128.pdf
13. Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z., "BLAKE2: simpler, smaller, fast as MD5," Proceedings of ACNS, 2013. https://www.blake2.net/blake2.pdf
14. Biryukov, A., Dinu, D., Khovratovich, D., "Argon2: the memory-hard function for password hashing and other applications," CS2CO Workshop, 2015. https://www.password-hashing.net/argon2.html
15. Bogdanov, A., Knudsen, L.R., Leander, G., "Biclique Cryptanalysis of the Full AES," ASIACRYPT 2011. https://eprint.iacr.org/2011/498
16. Barker, E., "Recommendation for Key Management: Transition Planning," SP 800-131A, 2011. https://csrc.nist.gov/publications/detail/sp/800-131a/final
17. Bellare, M., Canetti, R., Krawczyk, H., "Keying Hash Functions for Message Authentication," CRYPTO 1996. https://link.springer.com/chapter/10.1007/3-540-68697-5_8
18. McGrew, D., Igoe, K., "AES-GCM and AES-CCM Authenticated Encryption for Secure RTP," RFC 7714, 2015. https://www.rfc-editor.org/rfc/rfc7714
19. Langley, A., Hamburg, M., "ChaCha20-Poly1305 Cipher Suites for TLS," RFC 7905, 2016. https://www.rfc-editor.org/rfc/rfc7905
20. Nir, Y., Langley, A., "ChaCha20 and Poly1305 for IETF Protocols," RFC 8439, June 2018. https://www.rfc-editor.org/rfc/rfc8439
21. Shumow, D., Ferguson, N., "On the Possibility of a Back Door in the NIST SP 800-90 Dual EC PRNG," CRYPTO Rump Session, 2007. https://rump2007.cr.yp.to/15-shumow.pdf
22. Percival, C., "Scrypt: A Password-Based Key Derivation Function," RFC 7914, August 2016. https://www.rfc-editor.org/rfc/rfc7914
23. NIST, "Password-Based Key Stretching," SP 800-132, 2010. https://csrc.nist.gov/publications/detail/sp/800-132/final