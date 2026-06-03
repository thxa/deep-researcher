# Post-Quantum Cryptography

> A comprehensive treatment of the quantum threat to classical cryptography, the NIST PQC standardization process, lattice-based cryptography, code-based cryptography, hash-based signatures, isogeny-based cryptography (and SIKE's failure), hybrid deployment strategies, and the migration timeline for quantum-resistant systems.

---

## Table of Contents

1. [The Quantum Threat](#1-the-quantum-threat)
2. [NIST PQC Standardization](#2-nist-pqc-standardization)
3. [Lattice-Based Cryptography](#3-lattice-based-cryptography)
4. [Code-Based Cryptography](#4-code-based-cryptography)
5. [Hash-Based Signatures](#5-hash-based-signatures)
6. [Isogeny-Based Cryptography](#6-isogeny-based-cryptography)
7. [Hybrid Deployment Strategies](#7-hybrid-deployment-strategies)
8. [Crypto Agility](#8-crypto-agility)

---

## 1. The Quantum Threat

### 1.1 Shor's Algorithm

Peter Shor's 1994 algorithm solves the integer factorization and discrete logarithm problems in polynomial time on a quantum computer. For an $n$-bit integer, Shor's algorithm requires $O(n^3)$ quantum gates and $O(n)$ qubits, compared to the best classical algorithms:
- Integer factorization: $O(\exp(n^{1/3}))$ (GNFS)
- Discrete logarithm: $O(\exp(n^{1/3}))$ (various index calculus methods)

**Shor's algorithm for factoring**: Given $N = pq$, find $p$ and $q$:
1. Choose a random $a < N$ with $\gcd(a, N) = 1$.
2. Find the order $r$ of $a$ modulo $N$, i.e., the smallest $r$ such that $a^r \equiv 1 \pmod{N}$.
3. If $r$ is even and $a^{r/2} \not\equiv -1 \pmod{N}$, then $\gcd(a^{r/2} - 1, N)$ is a non-trivial factor of $N$.
4. The order-finding step is where quantum computing provides exponential speedup.

The quantum order-finding subroutine uses the **Quantum Fourier Transform (QFT)** to find the period $r$ of the function $f(x) = a^x \mod N$. The QFT maps a periodic quantum state to a frequency-domain representation, extracting the period in polynomial time.

**Impact**: Shor's algorithm completely breaks:
- **RSA**: Integer factorization becomes easy, so all RSA key sizes are broken.
- **ECC**: Discrete logarithm on elliptic curves becomes easy, so all ECC key sizes are broken.
- **DH**: Discrete logarithm on finite fields becomes easy, so all DH parameters are broken.
- **DSA/ECDSA**: Discrete logarithm-based signatures are broken.

### 1.2 Grover's Algorithm

Lov Grover's 1996 algorithm provides a quadratic speedup for unstructured search. Given a function $f: \{0,1\}^n \rightarrow \{0,1\}$ that marks a single solution, Grover's algorithm finds the solution in $O(\sqrt{2^n}) = O(2^{n/2})$ quantum operations, compared to the classical $O(2^n)$.

**Impact on symmetric cryptography**:
- **AES-128**: Security reduced from 128 bits to 64 bits. Still considered secure against Grover's algorithm (a 64-bit search is infeasible for the foreseeable future on any quantum computer).
- **AES-256**: Security reduced from 256 bits to 128 bits. Considered quantum-safe.
- **SHA-256**: Preimage resistance reduced from 256 bits to 128 bits. Still considered quantum-safe for most applications.
- **SHA-3-256**: Same as SHA-256 — 128-bit post-quantum preimage security.

**Recommendation**: For symmetric cryptography, doubling the key size provides adequate protection against Grover's algorithm. AES-256 and SHA-3-256 provide 128-bit post-quantum security, which is sufficient for most applications. NIST SP 800-208 recommends AES-256 for long-term quantum-resistant security.

### 1.3 Quantum Threat Timeline

When will a cryptographically relevant quantum computer (CRQC) be available?

| Year | Number of Qubits | Key Quantum Milestones |
|---|---|---|
| 2019 | 53 (Google Sycamore) | Quantum supremacy claim |
| 2020 | 65 (IBM Hummingbird) | |
| 2021 | 127 (IBM Eagle) | First >100-qubit processor |
| 2022 | 433 (IBM Osprey) | |
| 2023 | 1,121 (IBM Condor) | First >1000-qubit processor |
| 2024 | ~1,000 (various) | Error rates still too high |
| 2030 (projected) | ~10,000+ logical qubits | CRQC potentially feasible |
| 2040 (projected) | Millions of logical qubits | Shor's algorithm on 4096-bit RSA |

**Key point**: The number of **logical qubits** (error-corrected qubits) required for Shor's algorithm to factor a 2048-bit RSA modulus is estimated at $\sim 4{,}000$ logical qubits. Each logical qubit requires $\sim 1{,}000$ physical qubits for error correction (using surface code with code distance $d \approx 30$). Therefore, $\sim 4{,}000{,}000$ physical qubits are needed.

Current quantum computers have $\sim 1{,}000$ physical qubits with error rates of $\sim 10^{-3}$. A reduction in error rates of $\sim 10^6$ (to $\sim 10^{-9}$ per gate) is needed for practical fault-tolerant quantum computing. This may take 10–20 years.

**"Harvest now, decrypt later" threat**: Even if a CRQC doesn't exist today, adversaries can record encrypted traffic today and decrypt it in the future when a CRQC becomes available. Data with confidentiality requirements of 10+ years (government secrets, medical records, financial data) is already at risk. This motivates the urgency of PQC migration.

---

## 2. NIST PQC Standardization

### 2.1 Competition Overview

NIST initiated the Post-Quantum Cryptography Standardization Process in 2016, with the goal of selecting quantum-resistant public-key algorithms for standardization.

**Timeline**:
- **December 2016**: Call for proposals.
- **November 2017**: 82 submissions received; 69 accepted for Round 1.
- **January 2019**: 26 candidates advance to Round 2.
- **July 2020**: 7 finalists and 8 alternates advance to Round 3.
- **July 2022**: 4 algorithms selected for standardization (1 KEM, 3 signatures).
- **August 2023**: Draft standards published for public comment.
- **August 2024**: Final standards published (FIPS 203, FIPS 204, FIPS 205).
- **Future**: Additional standards for DERK and code-based signatures.

### 2.2 Selected Algorithms

| Algorithm | FIPS | Category | Based On | Key Size (pk/sk) | Ciphertext/Signature Size | Security Level |
|---|---|---|---|---|---|---|
| **ML-KEM** (Kyber) | FIPS 203 | KEM | Module-LWE | 1,184 B / 2,400 B | 1,088 B | Level 1/3/5 |
| **ML-DSA** (Dilithium) | FIPS 204 | Signature | Module-LWE/LWR | 1,312 B / 2,528 B pk | 2,420 B | Level 2/3/5 |
| **SLH-DSA** (SPHINCS+) | FIPS 205 | Signature | Hash | 32 B / 64 B | 7,856–49,856 B | Level 1/3/5 |
| **FN-DSA** (Falcon) | Draft | Signature | NTRU lattice | 1,561 B / 2,668 B | 666 B | Level 1/5 |

**ML-KEM (Kyber)**: Module-Lattice-Based Key Encapsulation Mechanism. The primary KEM for general use. Three security levels: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5). ML-KEM-768 is the recommended default.

**ML-DSA (Dilithium)**: Module-Lattice-Based Digital Signature Algorithm. Three security levels: ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), ML-DSA-87 (Level 5). ML-DSA-65 is the recommended default.

**SLH-DSA (SPHINCS+)**: Stateless Hash-Based Digital Signature Algorithm. Uses only hash functions (SHA-256 or SHAKE-256) as hardness assumptions. Much larger signatures (7,856–49,856 B) but minimal public key size (32 B). Recommended as a backup to ML-DSA.

**FN-DSA (Falcon)**: Fast-Fourier Lattice-Based Compact Signature over NTRU. Compact signatures (666 B) but complex implementation (requires floating-point arithmetic with precise rounding). Still in draft standardization due to implementation complexity.

### 2.3 Rejected Algorithms

Several Round 3 candidates were not selected for standardization:

- **Classic McEliece**: Code-based KEM with extremely large public keys (1 MB). Not selected as a primary standard due to key size, but still being considered for niche applications (e.g., satellite communication, where large key exchanges are feasible but long-term security is paramount).
- **BIKE**: Code-based KEM based on QC-MDPC codes. Not selected due to insufficient security analysis of the decoding algorithm's failure rate.
- **SIKE**: Isogeny-based KEM. Broken by Castryck and Decru in July 2022 (see §6). Not selected (obviously).
- **NTRU**: Lattice-based KEM. Similar to Kyber but based on a different lattice structure. Not selected because Kyber had better performance and a simpler design.
- **SABER**: Lattice-based KEM based on Module-LWR. Not selected because Kyber performed better on all benchmarks.

---

## 3. Lattice-Based Cryptography

### 3.1 Lattice Fundamentals

A **lattice** $\Lambda$ is a discrete subgroup of $\mathbb{R}^n$ generated by integer linear combinations of $n$ linearly independent vectors $\mathbf{b}_1, \mathbf{b}_2, \ldots, \mathbf{b}_n$:

$$\Lambda = \left\{ \sum_{i=1}^{n} a_i \mathbf{b}_i \mid a_i \in \mathbb{Z} \right\}$$

The matrix $B = [\mathbf{b}_1 | \mathbf{b}_2 | \cdots | \mathbf{b}_n]$ is called a **basis** for $\Lambda$. The same lattice can have many bases; the goal of lattice reduction is to find a "short" basis (one with short, nearly orthogonal basis vectors).

**Key lattice problems**:

1. **Shortest Vector Problem (SVP)**: Given a lattice $\Lambda$, find the shortest non-zero vector $\mathbf{v} \in \Lambda$:
$$\lambda_1(\Lambda) = \min_{\mathbf{v} \in \Lambda \setminus \{\mathbf{0}\}} \|\mathbf{v}\|$$

2. **Closest Vector Problem (CVP)**: Given a lattice $\Lambda$ and a target point $\mathbf{t} \in \mathbb{R}^n$, find the lattice point $\mathbf{v} \in \Lambda$ closest to $\mathbf{t}$:
$$\mathbf{v} = \arg\min_{\mathbf{v}' \in \Lambda} \|\mathbf{v}' - \mathbf{t}\|$$

3. **Learning With Errors (LWE)**: Given pairs $(\mathbf{a}_i, b_i)$ where $\mathbf{a}_i \leftarrow \mathbb{Z}_q^n$ and $b_i = \langle \mathbf{a}_i, \mathbf{s} \rangle + e_i \pmod{q}$, find the secret vector $\mathbf{s} \in \mathbb{Z}_q^n$. The error terms $e_i$ are drawn from a small distribution (typically discrete Gaussian with standard deviation $\sigma \approx 3$).

**Worst-case to average-case reduction**: Regev (2005) proved that solving LWE on average is as hard as solving approximation problems on arbitrary lattices in the worst case. This is the key theoretical result that justifies LWE-based cryptography: even if the specific lattice instances used in practice turn out to be easier than worst-case instances, breaking LWE requires solving hard lattice problems for all lattices, not just the ones used in the scheme.

### 3.2 Module-LWE and ML-KEM (Kyber)

ML-KEM (Kyber) is based on **Module-LWE (MLWE)**, which generalizes LWE to module lattices over polynomial rings. The secret is a vector of polynomials in $\mathbb{Z}_q[x]/(x^{256}+1)$ rather than a vector of integers modulo $q$.

**ML-KEM-768 parameters**:
- Ring: $R = \mathbb{Z}_{3329}[x]/(x^{256}+1)$
- Secret vector dimension: $k = 3$ (polynomials)
- Modulus: $q = 3329$
- Error distribution: CBD (Centered Binomial Distribution) with $\eta = 2$
- Public key size: 1,184 bytes
- Ciphertext size: 1,088 bytes
- Shared secret size: 32 bytes

**Key Encapsulation**:
1. **KeyGen**: Alice generates a secret $\mathbf{s} \leftarrow \text{CBD}_\eta$ and computes $\mathbf{t} = A\mathbf{s} + \mathbf{e}$ where $A$ is a public matrix (derived from a seed) and $\mathbf{e}$ is a small error vector.
2. **Encaps**: Bob generates a random message $m$, derives coins $\delta$ and $r$ from $m$, computes $\mathbf{u} = A^T\mathbf{r} + \mathbf{e}_1$ and $v = \mathbf{t}^T\mathbf{r} + e_2 + m$, where $\mathbf{r}, \mathbf{e}_1, e_2$ are derived from $\delta$. The ciphertext is $(\mathbf{u}, v)$.
3. **Decaps**: Alice computes $m' = v - \mathbf{s}^T\mathbf{u}$, re-derives coins from $m'$, and re-encrypts to verify the ciphertext. If verification fails, Alice returns a hash of the secret key (to avoid decapsulation failure attacks).

### 3.3 NTRU and FN-DSA (Falcon)

Falcon (FN-DSA) is based on **NTRU lattices**, which have a specific structure that enables very compact signatures.

**NTRU lattice**: An NTRU lattice is defined by a pair of polynomials $f, g \in \mathbb{Z}_q[x]/(x^n+1)$ where $f$ is a short polynomial and $g$ is chosen such that $f \cdot h \equiv g \pmod{q}$ for a public polynomial $h$. The NTRU lattice is:

$$\Lambda_{NTRU} = \begin{pmatrix} \mathbf{I}_n & \mathbf{H} \\ \mathbf{0} & q\mathbf{I}_n \end{pmatrix} \mathbb{Z}^{2n}$$

where $\mathbf{H}$ is the circulant matrix of $h$.

**Falcon signing**: Uses the Fast Fourier nearest-plane algorithm to find a short vector in the NTRU lattice that corresponds to the message hash. The signature is this short vector, which has norm $\leq \sigma \sqrt{n}$ where $\sigma$ is the Gaussian sampler's standard deviation.

Falcon's compact signatures (666 bytes for Level 1, 1,280 bytes for Level 5) make it suitable for applications where bandwidth is constrained (e.g., TLS certificates, DNSSEC).

---

## 4. Code-Based Cryptography

### 4.1 McEliece Cryptosystem

The McEliece cryptosystem (1978) is based on the hardness of decoding a general linear code. It uses binary Goppa codes, which have efficient decoding algorithms but appear random when the code's structure is hidden.

**Key generation**:
1. Choose a binary Goppa code $\mathcal{C}$ with parameters $[n, k, d]$ (length $n$, dimension $k$, minimum distance $d$). The code can correct up to $t = \lfloor (d-1)/2 \rfloor$ errors.
2. Generate the generator matrix $G \in \mathbb{F}_2^{k \times n}$ for $\mathcal{C}$.
3. Choose a random invertible matrix $S \in \mathbb{F}_2^{k \times k}$ (scrambling matrix) and a random permutation matrix $P \in \mathbb{F}_2^{n \times n}$.
4. Compute the public generator matrix $\hat{G} = SGP$.
5. Public key: $(\hat{G}, t)$. Private key: $(S, G, P)$.

**Encryption**: Given plaintext $\mathbf{m} \in \mathbb{F}_2^k$:
1. Compute $\mathbf{c}' = \mathbf{m}\hat{G}$.
2. Add a random error vector $\mathbf{e}$ of weight $\leq t$: $\mathbf{c} = \mathbf{c}' + \mathbf{e}$.

**Decryption**:
1. Compute $\mathbf{c}P^{-1} = \mathbf{m}SG + \mathbf{e}P^{-1}$.
2. Decode $\mathbf{c}P^{-1}$ using the Goppa code's decoding algorithm to recover $\mathbf{m}S$.
3. Compute $\mathbf{m} = \mathbf{m}S \cdot S^{-1}$.

**Security**: The best known attack is Information Set Decoding (ISD), which has complexity:
$$T_{\text{ISD}}(n, k, t) = \tilde{O}\left(2^{(n-k)\log_2(t/n) + o(1)}\right)$$

For Classic McEliece parameters ($n = 3488, k = 2720, t = 64$), ISD complexity is $\sim 2^{264}$, well above the Level 5 security target of $2^{256}$.

**Drawback**: The public key size is enormous — Classic McEliece's public key is $\sim 1$ MB (compared to $\sim 1$ KB for ML-KEM-768). This makes it impractical for most internet protocols but suitable for niche applications where key exchange is infrequent (e.g., satellite links, firmware updates).

### 4.2 Classic McEliece NIST Submission

Classic McEliece is the NIST submission of the original McEliece cryptosystem with modern parameter sets:

|Parameter Set|$n$|$k$|$t$|Public Key Size|Ciphertext Size|Security Level|
|---|---|---|---|---|---|---|
|mceliece348864|3488|2720|64|261 KB|128 B|Level 1|
|mceliece460896|4608|3968|96|524 KB|188 B|Level 3|
|mceliece6688128|6688|5024|128|1,044 KB|240 B|Level 5|
|mceliece6960119|6960|5413|119|1,044 KB|226 B|Level 5|
|mceliece8192128|8192|6414|128|1,357 KB|295 B|Level 5|

The ciphertext sizes (128–295 bytes) are smaller than ML-KEM's (768–1,088 bytes), but the public key sizes make Classic McEliece impractical for most applications.

---

## 5. Hash-Based Signatures

### 5.1 One-Time Signatures (Lamport-Diffie)

A Lamport-Diffie one-time signature (OTS) uses a hash function $H: \{0,1\}^* \rightarrow \{0,1\}^n$ to construct a signature scheme for a single message:

**Key generation**:
1. Generate $2n$ random values $x_{i,b} \leftarrow \{0,1\}^n$ for $i \in [n], b \in \{0,1\}$.
2. Compute the public key $pk_{i,b} = H(x_{i,b})$ for all $i, b$.
3. Secret key: $\{x_{i,b}\}$. Public key: $\{pk_{i,b}\}$.

**Signing**: For a message $m = m_1 m_2 \cdots m_n \in \{0,1\}^n$:
$$\sigma = \{x_{i,m_i}\}_{i=1}^n$$

**Verification**: Check that $H(\sigma_i) = pk_{i,m_i}$ for all $i$.

**Security**: Signing one message is secure (one-time). Signing two messages reveals $x_{i,0}$ and $x_{i,1}$ for at least one $i$, allowing the attacker to forge signatures for messages that differ from the two signed messages at that position.

### 5.2 Winternitz OTS (WOTS)

Winternitz OTS (WOTS) generalizes Lamport-Diffie to support variable trade-offs between signature size and computation time. WOTS uses a chain function $c^w(x) = H(c^{w-1}(x)) = H(H(\cdots H(x) \cdots))$ (w iterations of H).

**Key generation**: For each chunk $i$ of the message (divided into $w$-bit chunks), generate a random seed $x_i$ and compute $pk_i = c^{2^w-1}(x_i)$.

**Signing**: For message chunk $m_i$, the signature element is $\sigma_i = c^{m_i}(x_i)$.

**Verification**: Compute $c^{2^w-1-m_i}(\sigma_i)$ and check that it equals $pk_i$.

WOTS+ (used in XMSS and SPHINCS+) adds a bitmask to each chain iteration, preventing multi-target attacks.

### 5.3 XMSS (eXtended Merkle Signature Scheme)

XMSS uses a Merkle tree to allow $2^h$ one-time signatures from a single key pair. The tree leaves are WOTS+ one-time signature public keys, and internal nodes are hashes of their children.

**Parameters**:
- $h$: Tree height (maximum number of signatures is $2^h$).
- $n$: Hash output length (32 bytes for SHA-256, 64 bytes for SHA-512).
- $w$: Winternitz parameter (16 or 256).

**Key generation**:
1. Generate $2^h$ WOTS+ key pairs $(sk_i, pk_i)$.
2. Build a Merkle tree where leaf $i$ is $H(pk_i)$.
3. The XMSS public key is the Merkle root.

**Signing** (message $m$ using leaf index $i$):
1. Sign $m$ with WOTS+ using $sk_i$: $\sigma_{\text{WOTS+}} = \text{WOTS+.Sign}(sk_i, m)$.
2. Include the Merkle authentication path from leaf $i$ to the root: $\text{auth}_i = (h_{i,0}, h_{i,1}, \ldots, h_{i,h-1})$.
3. The XMSS signature is $(i, \sigma_{\text{WOTS+}}, \text{auth}_i)$.

**Verification**:
1. Verify the WOTS+ signature: compute $pk_i' = \text{WOTS+.Verify}(\sigma_{\text{WOTS+}}, m)$.
2. Compute the Merkle root from $pk_i'$ and the authentication path.
3. Check that the computed root equals the XMSS public key.

**XMSS is stateful**: Each leaf can be used only once. If a leaf is used twice, the WOTS+ one-time property is violated, and an attacker can forge signatures. Managing state (keeping track of which leaves have been used) is XMSS's main operational challenge.

**Parameter sets** (NIST SP 800-208):
| Parameter Set | $h$ | Max Signatures | Sig Size | Security Level |
|---|---|---|---|---|
| XMSS-SHA256_10 | 10 | $2^{10} = 1024$ | ~2.5 KB | Level 1 |
| XMSS-SHA256_16 | 16 | $2^{16} = 65536$ | ~2.8 KB | Level 1 |
| XMSS-SHA256_20 | 20 | $2^{20} \approx 10^6$ | ~3.0 KB | Level 1 |
| XMSS-SHA512_10 | 10 | 1024 | ~5.0 KB | Level 3 |

### 5.4 LMS (Leighton-Micali Signatures)

LMS (RFC 8554, NIST SP 800-208) is similar to XMSS but uses a different one-time signature scheme (LMS-OTS instead of WOTS+) and a slightly different Merkle tree construction. It has the same stateful property as XMSS.

LMS is approved for use in US government systems (via NIST SP 800-208) and is recommended for firmware signing, code signing, and other applications where the number of signatures is bounded and known in advance.

### 5.5 SPHINCS+ (SLH-DSA)

SPHINCS+ (now SLH-DSA, FIPS 205) is a **stateless** hash-based signature scheme. Unlike XMSS and LMS, SPHINCS+ does not require keeping track of which one-time signatures have been used. Instead, it uses a hyper-tree (a tree of Merkle trees) and randomizes the leaf selection for each signature.

**Key insight**: SPHINCS+ uses a FORS (Forest of Random Subsets) one-time signature for the bottom layer and XMSS trees for the upper layers. The FORS signature allows multiple signatures from the same key pair with negligible collision probability (the probability of using the same FORS key twice is $\sim 2^{-256}$ for the recommended parameters).

**Signature size**: SPHINCS+ signatures are larger than XMSS/LMS because the hyper-tree structure and FORS require more authentication paths. The smallest SLH-DSA parameter set produces 7,856-byte signatures (compared to ~2,500 bytes for XMSS).

| SLH-DSA Parameter Set | Sig Size | pk Size | Security Level |
|---|---|---|---|
| SLH-DSA-SHA2-128s | 7,856 B | 32 B | Level 1 |
| SLH-DSA-SHA2-128f | 17,088 B | 32 B | Level 1 (fast) |
| SLH-DSA-SHA2-192s | 16,224 B | 48 B | Level 3 |
| SLH-DSA-SHA2-256s | 29,792 B | 64 B | Level 5 |
| SLH-DSA-SHAKE-128s | 7,856 B | 32 B | Level 1 |

The `-s` variants have smaller signatures but slower verification; the `-f` variants have larger signatures but faster verification.

---

## 6. Isogeny-Based Cryptography

### 6.1 Isogeny Fundamentals

An **isogeny** is a morphism between elliptic curves that preserves the group structure. Formally, an isogeny $\phi: E_1 \rightarrow E_2$ is a non-constant rational map that sends the point at infinity on $E_1$ to the point at infinity on $E_2$.

Given an elliptic curve $E$ over $\mathbb{F}_q$ and a finite subgroup $S \subset E$, there exists a unique (up to isomorphism) isogeny $\phi: E \rightarrow E'$ whose kernel is $S$. The curve $E'$ is the codomain, and $\phi$ maps points from $E$ to $E'$ in a way that "factors out" the subgroup $S$.

**Isogeny-based key exchange**: Alice and Bob each choose a random subgroup $S_A, S_B \subset E$ and compute the corresponding isogenies $\phi_A: E \rightarrow E_A$ and $\phi_B: E \rightarrow E_B$. They then compute the curves $E_{AB} = E / \langle S_A, S_B \rangle$ and $E_{BA} = E / \langle S_B, S_A \rangle$, which are isomorphic (by the commutativity of the isogeny diagram).

### 6.2 SIDH/SIKE

**Supersingular Isogeny Diffie-Hellman (SIDH)** was proposed by Jao and De Feo in 2011. It uses supersingular elliptic curves over $\mathbb{F}_{p^2}$ where $p = 2^{e_A}3^{e_B} - 1$. The large primes $2^{e_A}$ and $3^{e_B}$ ensure that the isogeny graphs are expander graphs with good mixing properties.

**SIDH key exchange**:
1. **Setup**: Public supersingular curve $E: y^2 = x^3 + x$ over $\mathbb{F}_{p^2}$. Points $P_A, Q_A$ of order $2^{e_A}$ and $P_B, Q_B$ of order $3^{e_B}$ on $E$.
2. **Alice**: Chooses random $s_A \leftarrow \mathbb{Z}_{2^{e_A}}$, computes $R_A = [s_A]P_A + [s_A]Q_A$ and the isogeny $\phi_A: E \rightarrow E_A = E/\langle R_A \rangle$. Publishes $(E_A, \phi_A(P_B), \phi_A(Q_B))$.
3. **Bob**: Chooses random $s_B \leftarrow \mathbb{Z}_{3^{e_B}}$, computes $R_B = [s_B]P_B + [s_B]Q_B$ and the isogeny $\phi_B: E \rightarrow E_B = E/\langle R_B \rangle$. Publishes $(E_B, \phi_B(P_A), \phi_B(Q_A))$.
4. **Shared secret**: Alice computes $E_{AB} = E_A/\langle [s_A]\phi_A(P_B) + [s_A]\phi_A(Q_B) \rangle$. Bob computes $E_{BA} = E_B/\langle [s_B]\phi_B(P_A) + [s_B]\phi_B(Q_A) \rangle$. $E_{AB}$ and $E_{BA}$ are isomorphic (same j-invariant).

### 6.3 The Break: Castryck-Decru Attack (2022)

In July 2022, Wouter Castryck and Thomas Decru published a polynomial-time attack on SIDH that breaks all SIDH/SIKE parameter sets in hours. The attack exploits the auxiliary points $(\phi_A(P_B), \phi_A(Q_B))$ published as part of the SIDH protocol.

**Key insight**: The auxiliary points allow the attacker to construct a genus-2 curve $C$ that is $(2^n, 2^n)$-isogenous to a product of elliptic curves. By computing the $(2^n, 2^n)$-isogeny from $C$ to its Jacobian, the attacker recovers Alice's secret isogeny $\phi_A$.

**Attack complexity**: $O(p^{1/2})$ for the original Castryck-Decru attack, later improved to $O(\text{poly}(\log p))$ by Robert and others. For SIKEp434 (Level 1), the attack takes minutes on a laptop. For SIKEp751 (Level 5), the attack takes hours.

**Impact**: SIKE (Supersingular Isogeny Key Encapsulation), which was a Round 3 alternate candidate in the NIST PQC competition, is completely broken. All isogeny-based schemes that publish auxiliary points are vulnerable. This includes SIDH, SIKE, and B-SIDH.

**Isogeny-based schemes that survive**: CSIDH (Commutative SIDH) does not publish auxiliary points and is not affected by the Castryck-Decru attack. However, CSIDH has its own vulnerabilities (Subexponential attack by Delfs-Galbraith, and the Kuperberg algorithm for quantum attacks).

---

## 7. Hybrid Deployment Strategies

### 7.1 Why Hybrid?

PQC algorithms are new and have not undergone decades of cryptanalysis. There may be undiscovered attacks (as demonstrated by the SIKE break). **Hybrid key exchange** combines a classical algorithm (e.g., X25519) with a PQC algorithm (e.g., ML-KEM-768) so that the connection is secure as long as at least one algorithm remains unbroken.

**Hybrid KEM** (X25519 + ML-KEM-768):
1. Generate an X25519 key pair $(pk_X, sk_X)$ and an ML-KEM-768 key pair $(pk_K, sk_K)$.
2. Send the concatenated public key $pk = pk_X \| pk_K$.
3. Encapsulate: generate shared secrets $ss_X = \text{X25519.KEM}(pk_X)$ and $(ss_K, ct_K) = \text{ML-KEM-768.Encaps}(pk_K)$. Send $ct = ct_X \| ct_K$.
4. Derive the final shared secret using a KDF: $SS = \text{KDF}(ss_X \| ss_K)$.

If X25519 is broken (by a quantum computer), $ss_X$ is compromised, but $ss_K$ remains secure. If ML-KEM-768 is broken (by a future cryptanalytic attack), $ss_K$ is compromised, but $ss_X$ remains secure (against classical attackers).

### 7.2 Hybrid Key Exchange in TLS

**X25519MLKEM768** (draft-kwiatkowski-tls-ecdhe-mlkem-00): The IETF is standardizing a TLS 1.3 key exchange group that combines X25519 and ML-KEM-768:

```
KeyShareEntry:
  group: 0x4588 (x25519_mlkem768)
  key_exchange: x25519_pubkey || mlkem768_pubkey

ServerHello KeyShare:
  key_exchange: x25519_pubkey || mlkem768_ciphertext
```

The shared secret is derived as:
$$SS = \text{HKDF-Extract}(0, \text{X25519}(sk_A, pk_B) \| \text{ML-KEM-768.Decaps}(ct, sk_K))$$

This hybrid key exchange is supported by Chrome 124+, Firefox 128+, and Cloudflare (as of 2024).

**Hybrid in X.509 certificates**: TLS endpoints can include multiple public keys in their certificate (one classical, one PQC) using the `composite` extension (draft-ounsworth-pq-composite-keys). The certificate contains both an ECDSA and a ML-DSA signature, and the TLS handshake verifies both.

### 7.3 Migration Strategy

NIST recommends a three-phase migration:

**Phase 1 (2024–2026)**: Inventory and assessment.
- Inventory all cryptographic assets (keys, certificates, protocols).
- Identify systems that use RSA, ECC, DH, or other quantum-vulnerable algorithms.
- Assess the risk and impact of quantum attacks on each system.
- Begin testing PQC algorithms in non-production environments.

**Phase 2 (2026–2030)**: Hybrid deployment.
- Deploy hybrid key exchange (X25519 + ML-KEM) in TLS, SSH, VPN, and other protocols.
- Deploy hybrid signatures (ECDSA + ML-DSA) in code signing, certificate signing, and document signing.
- Deploy hybrid certificates (combined RSA/ECDSA + ML-DSA).
- Monitor PQC algorithm performance and compatibility.

**Phase 3 (2030+)**: Full PQC deployment.
- Once PQC algorithms have undergone sufficient analysis, transition to PQC-only deployment.
- Maintain hybrid deployment for high-value, long-lived assets until quantum computers are demonstrated to be capable of breaking RSA/ECC.

---

## 8. Crypto Agility

### 8.1 What Is Crypto Agility?

Crypto agility is the ability to quickly and seamlessly transition from one cryptographic algorithm to another in response to vulnerabilities, compliance requirements, or technology changes. It is the principle that no single algorithm should be permanently embedded in a system.

**Why crypto agility matters for PQC**:
- PQC algorithms may be broken (as SIKE was in 2022).
- New PQC algorithms may be standardized (e.g., code-based KEMs, isogeny-based signatures).
- Regulatory requirements may mandate specific algorithms (e.g., CNSA 2.0 Suite requires ML-KEM-1024 for US national security systems).
- Performance characteristics may favor different algorithms on different platforms.

### 8.2 Designing for Crypto Agility

**Algorithm identifiers**: Use standard algorithm identifiers (OIDs, code points) in all protocols. Never hardcode a specific algorithm.

```python
# BAD: Hardcoded algorithm
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP256R1())  # Locked to P-256

# GOOD: Algorithm identification
algorithm = config.get('kem_algorithm', 'ML-KEM-768')
key = kem.generate_key(algorithm)  # Can be changed via configuration
```

**Protocol negotiation**: Support algorithm negotiation in all protocols (like TLS cipher suites, SSH key exchange methods, IPsec proposals). This allows peers to agree on the best mutually supported algorithm.

**Key separation**: Derive separate keys for each algorithm from a master secret using a KDF. Never reuse a key across algorithms.

```python
def derive_hybrid_key(master_secret):
    x25519_key = HKDF(master_secret, info=b'x25519', length=32)
    mlkem_key = HKDF(master_secret, info=b'ml-kem-768', length=2400)
    return x25519_key, mlkem_key
```

**Cryptographic library abstraction**: Use a cryptographic library that exposes algorithm-independent interfaces (key generation, encapsulation, signing, verification) and allows runtime algorithm selection.

**Certificate agility**: Support multiple signature algorithms in X.509 certificates (via the SubjectPublicKeyInfo algorithm identifier and the signature algorithm identifier). This enables hybrid certificates (ECDSA + ML-DSA) and algorithm migration.

### 8.3 Protocol-Specific Agility

**TLS 1.3**: Already supports algorithm negotiation via key share extensions and cipher suites. Adding PQC requires:
- New hybrid key share groups (X25519+ML-KEM-768, P-256+ML-KEM-768, etc.).
- New signature algorithms (ML-DSA-65, SLH-DSA-SHA2-128s) in the CertificateVerify message.
- Larger ClientHello messages (PQC public keys are 1–5 KB, exceeding the typical 512-byte limit). This requires the `client_hello_compression` extension or the `key_share` extension with a HelloRetryRequest.

**SSH**: SSH already supports algorithm negotiation. Adding PQC requires:
- New key exchange method names (e.g., `mlkem768x25519-sha256`).
- New host key types (e.g., `ml-dsa-65`).
- Handling larger keys and signatures in the SSH binary protocol.

**S/MIME and PGP**: Email encryption requires algorithm agility for both the key exchange and the signature. PQC algorithms produce larger ciphertexts and signatures, which may exceed email size limits. Hybrid encryption (ML-KEM + X25519 for key encapsulation, AES-256-GCM for bulk encryption) is the standard approach.

---

## Cross-References

- **§01a** — Cryptographic fundamentals: symmetric/asymmetric crypto, hash functions, AEAD
- **§02a** — RSA/ECC attacks: Shor's algorithm breaks RSA and ECC entirely
- **§05b** — Crypto engineering: key management, HSM architecture, hybrid deployment
- **§06** — Case studies: SIKE break (Castryck-Decru), ROCA (lattice-based key generation weakness in TPMs)
- **Chromium track** — Chrome's PQC deployment (X25519+ML-KEM-768 hybrid key exchange)
- **Linux Kernel track** — Kernel crypto API, AF_ALG, PQC module loading

## References

1. Shor, P., "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer," SIAM Journal on Computing, 1997. https://doi.org/10.1137/S0097539795293172
2. Grover, L.K., "A Fast Quantum Mechanical Algorithm for Database Search," STOC 1996. https://doi.org/10.1145/237814.237866
3. Chen, L., et al., "Report on Post-Quantum Cryptography," NIST IR 8105, April 2016. https://csrc.nist.gov/publications/detail/nistir/8105/final
4. NIST, "Post-Quantum Cryptography Standardization Process," FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), August 2024. https://csrc.nist.gov/projects/post-quantum-cryptography
5. Ajtai, M., "Generating Hard Instances of Lattice Problems," STOC 1996. https://doi.org/10.1145/237814.237838
6. Regev, O., "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography," STOC 2005.
7. Lyubashevsky, V., Peikert, C., Regev, O., "On Ideal Lattices and Learning with Errors over Rings," EUROCRYPT 2010. https://eprint.iacr.org/2012/230
8. McEliece, R.J., "A Public-Key Cryptosystem Based on Algebraic Coding Theory," DSN Progress Report, 1978. https://doi.org/10.1109/TIT.1978.1055875
9. Bernstein, D.J., Hopwood, D., Hülsing, A., et al., "SPHINCS+: Practical Stateless Hash-Based Signatures," 2019. FIPS 205. https://sphincs.org/
10. Castryck, W., Decru, T., "An Efficient Key Recovery Attack on SIDH," EUROCRYPT 2023. https://eprint.iacr.org/2022/975
11. Jao, D., De Feo, L., "Towards Quantum-Resistant Cryptosystems from Supersingular Elliptic Curve Isogenies," PQCrypto 2011. https://eprint.iacr.org/2011/506
12. NIST, "Transition to Quantum-Resistant Cryptographic Algorithms," Draft SP 800-227, 2024. https://csrc.nist.gov/pubs/fips/203/final
13. Barker, E., "Recommendation for Key Management — Part 1: General," SP 800-57 Rev. 5, 2020. https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
14. RFC 9180, "Hybrid Public Key Encryption," February 2022. https://www.rfc-editor.org/rfc/rfc9180
15. Aviram, N., et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice," CCS 2015. https://weakdh.org/
16. Westerbaan, B., "X25519+ML-KEM-768 Hybrid Key Exchange in Chrome," Chromium Blog, August 2024. https://blog.chromium.org/2024/08/hybrid-post-quantum-key-exchange-in-chrome.html
17. Provos, N., "Deploying Post-Quantum Cryptography in TLS," Google Security Blog, 2023. https://security.googleblog.com/2023/08/post-quantum-cryptography-in-tls.html
18. CNSA 2.0 Suite, "Quantum-Resistant Requirements for National Security Systems," NSA, 2022. https://www.nsa.gov/Cybersecurity/Advisories/quantum-resistant-algorithms/