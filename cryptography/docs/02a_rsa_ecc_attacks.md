# RSA and ECC Attacks

> A systematic catalog of attacks against RSA and elliptic curve cryptosystems: from textbook RSA vulnerabilities to Bleichenbacher's padding oracle, Coppersmith's lattice methods, Wiener's small-d attack, timing side channels, key generation weaknesses, and ECC-specific attacks on curve parameters and scalar multiplication.

---

## Table of Contents

1. [Textbook RSA Vulnerabilities](#1-textbook-rsa-vulnerabilities)
2. [Bleichenbacher Attack (PKCS#1 v1.5 Padding Oracle)](#2-bleichenbacher-attack)
3. [Manger Attack (OAEP Padding Oracle)](#3-manger-attack)
4. [Coppersmith Attacks](#4-coppersmith-attacks)
5. [Wiener Attack on Small d](#5-wiener-attack-on-small-d)
6. [Boneh-Durfee Attack](#6-boneh-durfee-attack)
7. [Timing Attacks on RSA](#7-timing-attacks-on-rsa)
8. [RSA Key Generation Weaknesses](#8-rsa-key-generation-weaknesses)
9. [Fermat Factorization for Close Primes](#9-fermat-factorization-for-close-primes)
10. [ECC: Invalid Curve Attacks](#10-ecc-invalid-curve-attacks)
11. [ECC: Twist Security and Small Subgroup Attacks](#11-ecc-twist-security-and-small-subgroup-attacks)
12. [ECC: Side-Channel Attacks on Scalar Multiplication](#12-ecc-side-channel-attacks-on-scalar-multiplication)

---

## 1. Textbook RSA Vulnerabilities

"Textbook RSA" refers to the raw RSA function $m^e \mod n$ without any padding scheme. It is insecure in multiple ways:

### 1.1 Deterministic Encryption

Without padding, RSA is deterministic: the same plaintext always produces the same ciphertext under a given public key. An attacker can:
- **Detect repeated messages**: Compare ciphertexts to determine if two encrypted messages are identical.
- **Dictionary attack**: Build a dictionary of common plaintexts and their encryptions.

This violates IND-CPA (semantic security). For an 1024-bit modulus with $e = 65537$, encrypting all possible Social Security Numbers (10 digits) requires only $10^{10} \approx 2^{33}$ precomputations — trivially achievable.

### 1.2 Malleability

RSA is multiplicatively homomorphic: given ciphertexts $c_1 = m_1^e \mod n$ and $c_2 = m_2^e \mod n$:

$$c_1 \cdot c_2 = (m_1 \cdot m_2)^e \mod n$$

An attacker who sees $c_1 = m^e \mod n$ can compute $c' = c_1 \cdot s^e \mod n = (m \cdot s)^e \mod n$ for any chosen $s$. The decryption of $c'$ yields $m \cdot s \mod n$, revealing $m$ if the attacker chooses $s = m^{-1}$ (since they know $s$, they can divide).

**Concrete exploit**: In an electronic voting system, a voter submits $c = m^e \mod n$ where $m$ represents their vote. An attacker who sees $c$ can submit $c' = c \cdot 2^e \mod n$, which decrypts to $2m \mod n$. If the system interprets the result without checking bounds, the vote is doubled.

### 1.3 Low-Exponent Attacks

When $e$ is small and the message $m$ is small enough that $m^e < n$, RSA encryption reduces to integer exponentiation (no modular reduction):

$$c = m^e$$

The attacker takes the $e$-th integer root of $c$ to recover $m$:

$$m = \sqrt[e]{c}$$

**Example**: With $e = 3$ and a 2048-bit modulus, any message shorter than 682 bits ($2048/3$) will satisfy $m^3 < n$. A 64-byte (512-bit) message is easily recovered by cube-root extraction.

Even when $m^e > n$ but $m$ is padded with known structure, Coppersmith's methods (see §4) can recover $m$.

### 1.4 Common Modulus Attack

If two users share the same modulus $n$ but have different public exponents $e_1, e_2$ (with $\gcd(e_1, e_2) = 1$), and both encrypt the same message:

$$c_1 = m^{e_1} \mod n, \quad c_2 = m^{e_2} \mod n$$

The attacker applies the extended Euclidean algorithm to find $a, b$ such that $ae_1 + be_2 = 1$, then:

$$c_1^a \cdot c_2^b = m^{ae_1 + be_2} = m^1 = m \mod n$$

This recovers the plaintext without knowing either private key.

**Real-world incidence**: Some early PKI implementations generated a single modulus and assigned different exponents to different users. This is catastrophically insecure — any two users colluding can recover each other's private keys.

### 1.5 Forward Search Attack

For small message spaces (e.g., a single yes/no bit, a day of the week, a PIN), the attacker simply encrypts all possible messages and compares:

```python
def rsa_forward_search(pubkey, ciphertext, message_space):
    """Recover plaintext by trying all possible messages."""
    e, n = pubkey
    for m in message_space:
        if pow(m, e, n) == ciphertext:
            return m
    return None

# Example: encrypted yes/no response
message_space = [0, 1]  # 0 = no, 1 = yes
result = rsa_forward_search((65537, n), ciphertext, message_space)
```

For a 4-digit PIN ($10^4$ possibilities), this requires at most 10,000 RSA encryptions — sub-millisecond on any modern CPU.

---

## 2. Bleichenbacher Attack (PKCS#1 v1.5 Padding Oracle)

### 2.1 PKCS#1 v1.5 Padding

RSA encryption in PKCS#1 v1.5 (RFC 2313) pads the message before encryption:

$$m = \texttt{0x00} \| \texttt{0x02} \| \text{PS} \| \texttt{0x00} \| M$$

where PS (padding string) consists of at least 8 non-zero random bytes, and $M$ is the message. The total length equals the modulus length in bytes.

A ciphertext is **PKCS#1 v1.5 conformant** if, upon decryption, the plaintext has the form $\texttt{0x00}\|\texttt{0x02}\|(\text{non-zero bytes})\|\texttt{0x00}\|(\text{arbitrary data})$.

### 2.2 The Attack

**CVE-1998-0073** (original Bleichenbacher, 1998) and **CVE-2017-13091** (ROBOT, 2017 — see §03a).

Bleichenbacher's adaptive chosen-ciphertext attack exploits a server that reveals whether a given ciphertext decrypts to a PKCS-conformant plaintext. The attacker can recover the plaintext of any ciphertext $c^*$ in approximately $2^{18}$ oracle queries.

**Key insight**: Multiplying $c^*$ by $s^e \mod n$ produces a ciphertext $c' = c^* \cdot s^e \mod n$ whose decryption is $m \cdot s \mod n$. If the oracle reports that $c'$ is PKCS-conformant, then $m \cdot s \mod n$ lies in the range $[2B, 3B)$ where $B = 2^{8(k-2)}$ ($k$ is the modulus length in bytes).

**Algorithm** (simplified):

1. **Blinding**: Find $s_0$ such that $c_0 = c^* \cdot s_0^e \mod n$ is PKCS-conformant. This initializes the attack.

2. **Step 2a — Starting search**: Find the smallest $s_1 > n/(3B)$ such that $c_0 \cdot s_1^e \mod n$ is PKCS-conformant. This requires $\sim 2^{16}$ queries on average.

3. **Step 2b — Narrowing**: Given the current interval set, find $s_i$ close to the previous $s_{i-1}$. Compute new intervals: if $m \cdot s_i \mod n \in [2B, 3B)$, then $m \in [2B/s_i, 3B/s_i)$ modulo $n$. Intersect with previous intervals.

4. **Step 2c — One interval left**: When only one interval remains, select $s_i$ so that the interval shrinks by a factor of ~2 each step. After $\sim \log_2(n)$ iterations (about 1024 for a 1024-bit modulus), the interval converges to a single value: the plaintext $m$.

**Complexity**: The original Bleichenbacher paper estimated $\sim 2^{20}$ queries for a 1024-bit modulus. Practical implementations (e.g., ROBOT) achieved $\sim 2^{18}$ queries. With a 10ms oracle latency, this completes in $\sim 2^{18} \times 10\text{ms} = 2,621$ seconds ≈ 44 minutes.

### 2.3 Modern Bleichenbacher Variants

**ROBOT (Return Of Bleichenbacher's Oracle Threat, 2017)**: Hanno Böck, Juraj Somorovsky, and Craig Young discovered that many modern TLS implementations still had PKCS#1 v1.5 padding oracle vulnerabilities, 19 years after the original attack. Affected implementations included:

- **F5 BIG-IP**: The TLS server returned different TLS alerts for valid vs. invalid padding (CVE-2017-6167).
- **Cisco ACE**: Similar error message differentiation.
- **Java JSSE**: Timing side channel in the RSA decryption + PKCS check (CVE-2017-12487).
- **OpenSSL**: Nested error handling that leaked PKCS conformance through timing differences (CVE-2016-0148, patched but reintroduced).

The ROBOT paper demonstrated practical session key recovery against these implementations, proving that the Bleichenbacher attack is not merely a theoretical concern.

**Countermeasure**: Use RSA-OAEP (RSAES-OAEP) instead of PKCS#1 v1.5. OAEP's padding verification is a single hash comparison over the entire decrypted block, eliminating the possibility of a padding oracle. TLS 1.3 has removed RSA key exchange entirely, mandating (EC)DHE.

### 2.4 Bleichenbacher Implementation

```python
def bleichenbacher_attack(oracle, n, e, c_star, k):
    """Simplified Bleichenbacher attack on PKCS#1 v1.5 RSA."""
    B = 2 ** (8 * (k - 2))
    
    # Step 1: Blinding (if c_star is already PKCS-conformant, s0=1)
    s0 = 1
    c0 = c_star
    
    # Step 2a: Starting search
    s = (n + 3 * B - 1) // (3 * B)
    while not oracle(pow(s, e, n) * c0 % n):
        s += 1
    
    # Step 2c: Narrowing with one interval
    M = [(2 * B, 3 * B - 1)]
    
    while len(M) > 1 or (M[0][1] - M[0][0]) > 1:
        # Find s such that c0 * s^e mod n is PKCS-conformant
        s += 1
        while not oracle(pow(s, e, n) * c0 % n):
            s += 1
        
        # Update interval
        new_M = []
        for a, b in M:
            r_min = (a * s - 3 * B + 1) // n
            r_max = (b * s - 2 * B) // n
            for r in range(r_min, r_max + 1):
                new_a = max(a, (2 * B + r * n) // s)
                new_b = min(b, (3 * B - 1 + r * n) // s)
                if new_a <= new_b:
                    new_M.append((new_a, new_b))
        M = new_M
    
    return M[0][0]  # The recovered plaintext
```

---

## 3. Manger Attack (OAEP Padding Oracle)

### 3.1 OAEP and the Manger Attack

RSA-OAEP (Optimal Asymmetric Encryption Padding) was designed to be provably IND-CCA secure in the random oracle model. However, **implementation flaws** can still create oracles.

**Manger's attack (2003)** exploits a specific OAEP implementation flaw where the server rejects messages whose first byte after decryption is not $\texttt{0x00}$. This single-byte oracle is sufficient to recover the plaintext.

The attack is significantly faster than Bleichenbacher: $\sim 2^{10}$ queries for a 1024-bit modulus, compared to Bleichenbacher's $\sim 2^{18}$.

**Mechanism**: In OAEP, the decrypted message has the form $\texttt{0x00}\|Y\|masked_seed\|masked_db$. If the first byte after OAEP unmasking is not $\texttt{0x00}$, the server returns an error.

For a known $c = m^e \mod n$, multiplying by $s^e \mod n$ gives ciphertext corresponding to $m \cdot s \mod n$. If the oracle reports that the first byte is $\texttt{0x00}$, then $2B \leq m \cdot s \mod n < 3B$ (similar to Bleichenbacher). But Manger's binary search is more efficient because the single-byte check divides the search space more cleanly.

**Algorithm**:

1. Find $f_1$ such that $\lfloor (c \cdot f_1^e) / n \rfloor = B$: binary search for the boundary.
2. Find $f_2$ such that $\lfloor (c \cdot f_2^e) / n \rfloor = 2B$: refine the interval.
3. Binary search: at each step, halve the interval $[a, b]$ containing $m$.

Each step requires at most one oracle query. Total queries: $\sim \log_2(n) \approx 1024$ for a 1024-bit modulus, plus the initial boundary search of $\sim 10$ queries.

---

## 4. Coppersmith Attacks

### 4.1 Coppersmith's Method

Coppersmith's method (1996) uses lattice reduction (LLL algorithm) to find small roots of modular polynomial equations. It is the most versatile tool for attacking RSA with partial knowledge.

**Theorem (Coppersmith)**: Given a monic polynomial $f(x)$ of degree $d$ modulo $N$, one can find all roots $x_0$ with $|x_0| \leq N^{1/d}$ in polynomial time (polynomial in $\log N$ and $d$).

For RSA modulus $N = pq$, this means:
- Roots up to $N^{1/3}$ can be found for cubic polynomials ($d=3$).
- Roots up to $N^{1/2}$ can be found for linear polynomials ($d=1$) — this is relevant for factoring when $p$ has known bits.

### 4.2 Small Public Exponent Attack

For $e$ small and the message $m$ padded with a known structure but an unknown random padding $r$:

$$c = (2^k \cdot m + r)^e \mod n$$

If $|r| < N^{1/e}$, Coppersmith's method can recover $r$ (and hence $m$) from $c$ alone. Specifically, define $f(x) = c - (2^k \cdot m + x)^e \mod n$ and find the small root $x_0 = r$.

For $e = 3$ and random padding of length $k_{\text{pad}}$ bits, this works when $k_{\text{pad}} < n_{\text{bits}} / e - m_{\text{bits}}$. For a 2048-bit modulus with $e = 3$, messages up to 682 bits can be recovered if the padding is less than $\lfloor 2048/3 \rfloor - m_{\text{bits}}$ bits.

### 4.3 Factoring with Partial Knowledge

**Known High Bits of p**: If $p$ is an $n$-bit prime and $k$ high-order bits of $p$ are known, then $p = p_{\text{known}} + x$ where $|x| < 2^{n-k}$. Define $f(x) = p_{\text{known}} + x \mod N$. If $|x| < N^{1/2}$, Coppersmith's method finds $x$ (and hence $p$) in polynomial time. This means that if an attacker knows more than half the bits of $p$, they can factor $N$.

**Known Low Bits of p**: Similarly, if $k$ low-order bits of $p$ are known, write $p = x \cdot 2^k + p_{\text{known}}$. If $x < N^{1/2}$, Coppersmith's method works.

**Practical impact**: Any scenario where more than half the bits of a prime factor are leaked enables efficient factoring. This includes:
- **Side-channel attacks** that reveal partial key material (e.g., cache attacks on RSA key generation).
- **Weak random number generators** that allow reconstruction of partial prime bits (see §8: Debian OpenSSL).
- **Fault attacks** that cause key generation to use predictable seeds.

### 4.4 Related Messages Attack (Franklin-Reiter)

If two messages $m_1, m_2$ are related by a known polynomial $f$ (e.g., $m_2 = m_1 + \delta$ for known $\delta$, as in a known difference), and both are encrypted under the same public key with small $e$:

$$c_1 = m_1^e \mod n, \quad c_2 = (m_1 + \delta)^e \mod n$$

For $e = 3$, the polynomials $h_1(x) = x^3 - c_1$ and $h_2(x) = (x + \delta)^3 - c_2$ share the root $m_1$. Computing $\gcd(h_1, h_2)$ over $\mathbb{Z}_n[x]$ (using the Euclidean algorithm for polynomials, extended to work modulo $n$) yields a linear factor $(x - m_1)$ from which $m_1$ is recovered directly.

```python
def franklin_reiter_related_message(e, n, c1, c2, delta):
    """Recover m1 from two ciphertexts where m2 = m1 + delta, e=3."""
    assert e == 3, "Simplified for e=3"
    
    # h1(x) = x^3 - c1
    # h2(x) = (x + delta)^3 - c2
    # gcd(h1, h2) should yield (x - m1)
    
    # Using resultant instead of polynomial gcd over Z_n
    # The resultant of h1 and h2 with respect to x gives m1
    
    # Construct polynomial ring over Z_n
    from sage.all import PolynomialRing, Zmod
    R = PolynomialRing(Zmod(n), 'x')
    x = R.gen()
    h1 = x**3 - c1
    h2 = (x + delta)**3 - c2
    
    g = gcd(h1, h2)
    m1 = int(-g.coefficients()[0]) % n
    return m1
```

For larger $e$, Coppersmith's method generalizes this to find roots of the polynomial $f(x) = (x + \delta)^e - c_2$ in $\mathbb{Z}_n$ (since $m_1$ is a root of both $x^e - c_1$ and $(x + \delta)^e - c_2$).

### 4.5 Stern's Attack on RSA with Shared Bits

If two RSA moduli $N_1 = p_1 q_1$ and $N_2 = p_2 q_2$ share some bits (e.g., $p_1$ and $p_2$ share their most significant bits), Coppersmith's method can factor both moduli. This is particularly relevant when keys are generated with biased or weak RNGs that produce primes sharing high-order bits.

---

## 5. Wiener Attack on Small d

### 5.1 The Attack

Wiener's attack (1990) exploits RSA keys where the private exponent $d$ is small relative to the modulus. The attack works when $d < n^{1/4}/3$, i.e., $d < 2^{256}$ for a 1024-bit modulus.

**Theorem (Wiener)**: Let $N = pq$ with $q < p < 2q$, $e < \phi(N)$, and $ed = 1 \mod \phi(N)$. If $d < \frac{1}{3} N^{1/4}$, then $d$ is the denominator of a convergent of the continued fraction expansion of $e/N$.

**Proof sketch**: Since $ed \equiv 1 \pmod{\phi(N)}$, there exists $k$ such that $ed - k\phi(N) = 1$. Rearranging:

$$\frac{e}{\phi(N)} = \frac{k}{d} + \frac{1}{d\phi(N)} \approx \frac{k}{d}$$

Since $\phi(N) \approx N$ (off by at most $p + q - 1$, which is $\sim 2\sqrt{N}$ for balanced primes), $e/N \approx k/d$ is a good rational approximation. The continued fraction convergents of $e/N$ provide the best such approximations, and $k/d$ must appear among them.

### 5.2 Implementation

```python
def continued_fraction(num, den):
    """Compute continued fraction expansion of num/den."""
    cf = []
    while den:
        q, r = divmod(num, den)
        cf.append(q)
        num, den = den, r
    return cf

def convergents(cf):
    """Compute convergents from continued fraction expansion."""
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in cf:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        yield h_curr, k_curr  # (numerator, denominator) = (k, d)

def wiener_attack(e, n):
    """Recover d if d < n^(1/4) / 3."""
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # Check if this (k, d) pair is valid
        phi = (e * d - 1) // k
        # phi = (p-1)(q-1) = n - p - q + 1
        # p + q = n - phi + 1
        p_plus_q = n - phi + 1
        # p * q = n
        # p, q are roots of x^2 - (p+q)x + n = 0
        discriminant = p_plus_q**2 - 4 * n
        if discriminant >= 0:
            sqrt_disc = int(discriminant**0.5)
            if sqrt_disc * sqrt_disc == discriminant:
                p = (p_plus_q + sqrt_disc) // 2
                q = (p_plus_q - sqrt_disc) // 2
                if p * q == n:
                    return d, p, q
    return None  # d is too large for Wiener's attack
```

### 5.3 Practical Impact

Wiener's attack demonstrates that small private exponents are catastrophically insecure. Using $d = 65537$ (reversing the common public exponent choice) provides no security — it is immediately recoverable.

**Defense**: Always use $e = 65537$ (which ensures $d$ is large) and never choose a small $d$ for performance reasons. Use CRT-based RSA decryption (`dp = d mod (p-1), dq = d mod (q-1)`) for efficiency instead of small $d$.

---

## 6. Boneh-Durfee Attack

### 6.1 Extending Wiener's Bound

Boneh and Durfee (1999) extended Wiener's attack to recover $d$ when $d < N^{0.292}$. This is currently the best known attack on small $d$ for balanced RSA moduli.

The attack uses Coppersmith's lattice techniques on the bivariate polynomial:

$$f(x, y) = x(N + 1 + y) + 1 - ed \mod e$$

where $x = k$ and $y = -(p + q)$. For $d < N^{0.292}$, the lattice reduction finds small roots of this polynomial, recovering $d$ directly.

**Implementation**: The Boneh-Durfee attack requires constructing a lattice of dimension $m^2$ (where $m$ is the lattice parameter, typically $m = 3$ or $4$) and running LLL reduction. For $m = 4$ and a 1024-bit modulus, the lattice dimension is 25, and LLL completes in seconds.

```python
# Boneh-Durfee requires SageMath for lattice operations
# Simplified conceptual implementation
def boneh_durfee(e, n, m=3, t=1):
    """Recover d if d < N^0.292. Requires SageMath."""
    from sage.all import Matrix, Zmod
    
    # Construct the lattice from the polynomial
    # f(x,y) = x(N+1+y) + 1 mod e
    # with bounds |x| < X = e^0.5, |y| < Y = e^0.5
    
    # Build the shift polynomials and lattice matrix
    # ... (full implementation requires careful polynomial selection)
    
    # LLL reduction
    # B = M.LLL()
    
    # Extract small roots from reduced basis
    # ...
    pass  # Full implementation is ~200 lines
```

### 6.2 Practical Significance

For a 1024-bit modulus:
- $d < 2^{256}$ (Wiener): immediately recoverable.
- $d < 2^{299}$ (Boneh-Durfee): recoverable in polynomial time.
- $d > 2^{299}$: no known attack better than factoring the modulus.

**Defense**: As with Wiener, the defense is to never use small $d$. Modern RSA implementations use $e = 65537$ and compute $d = e^{-1} \mod \lambda(N)$, which produces a $d$ of magnitude ~$N$.

---

## 7. Timing Attacks on RSA

### 7.1 Kocher's Timing Attack (1996)

Paul Kocher demonstrated that the time taken to compute $m^d \mod n$ (modular exponentiation) leaks information about the private key $d$. The attack targets the square-and-multiply algorithm:

```
Result = 1
for bit in d.bit_length() down to 0:
    Result = Result^2 mod n        (square step)
    if bit == 1:
        Result = Result * m mod n  (multiply step)
```

A multiply step is executed only when the corresponding bit of $d$ is 1, and it adds a measurable time increment. By timing multiple decryptions, the attacker can determine which bits of $d$ are 1.

**Attack procedure**:
1. Measure the time $T_i$ for decryption of ciphertext $c_i$ for many ciphertexts.
2. For each candidate bit position $j$ of $d$:
   a. Simulate the square-and-multiply computation up to bit $j$.
   b. Partition measurements into two sets: those requiring a multiply at bit $j$ (if the bit is 1) and those not requiring it.
   c. The correct partition will show a statistically significant time difference.
3. Proceed bit by bit, recovering all of $d$.

**Required measurements**: For a 2048-bit key with timing variation of $\delta = 1\mu s$ per multiply operation and timing measurement error of $\sigma = 0.1\mu s$, the required number of samples per bit is approximately $(\sigma/\delta)^2 = (0.1/1)^2 = 0.01$ — just a few measurements. In practice, network jitter increases $\sigma$, requiring more samples, but the attack remains feasible.

### 7.2 Remote Timing Attacks

**Brumley and Boneh (2003)** demonstrated the first remote timing attack on OpenSSL's RSA implementation over a local network. They recovered a 1024-bit RSA private key from an Apache web server in approximately 2 hours using $\sim 2^{19}$ timing measurements.

**Countermeasures**:
1. **Constant-time exponentiation**: The Montgomery ladder algorithm computes $m^d \mod n$ in constant time regardless of the value of $d$, eliminating timing variation:

```
R0 = 1
R1 = m
for bit in d.bits() from MSB to LSB:
    if bit == 0:
        R1 = R0 * R1 mod n
        R0 = R0^2 mod n
    else:
        R0 = R0 * R1 mod n
        R1 = R1^2 mod n
Result = R0
```

Both branches execute exactly one multiplication and one squaring per bit, making the operation constant-time.

2. **RSA blinding**: Before each decryption, compute $m' = m \cdot r^e \mod n$ for random $r$, decrypt $m'$ to get $m'^d$, then divide by $r$: $(m'^d / r) = (m \cdot r^e)^d / r = m^d \cdot r^{ed} / r = m^d \cdot r / r = m^d \mod n$. The blinding factor $r$ randomizes the timing, preventing the attacker from correlating timing with specific bits of $d$.

```python
def rsa_decrypt_blinded(key, ciphertext):
    """RSA decryption with blinding countermeasure."""
    n, d = key.private_numbers().d, key.private_numbers().n
    e = key.public_numbers().e
    
    # Generate random blinding factor
    r = secrets.randbelow(n)
    r_inv = pow(r, -1, n)
    
    # Blind: c' = c * r^e mod n
    c_blinded = (ciphertext * pow(r, e, n)) % n
    
    # Decrypt blinded ciphertext
    m_blinded = pow(c_blinded, d, n)
    
    # Unblind: m = m' * r^(-1) mod n
    m = (m_blinded * r_inv) % n
    return m
```

### 7.3 Cache Timing Attacks on RSA

**Osvik-Shamir-Tromer cache attacks (2006/7)** demonstrate that cache contention during modular exponentiation leaks key bits. The attacker primes the L1 cache with their own data, then triggers a target RSA operation. By measuring the time for their own memory accesses afterward, they determine which cache lines were evicted by the RSA computation, revealing which table indices were accessed — directly revealing key bits in table-based implementations.

**Intel OpenSSL vulnerability (CVE-2018-0734)**: OpenSSL's RSA implementation was found to have a timing side channel in the modular exponentiation that could leak information about the private key. The fix involved switching to constant-time implementations.

**Prime+Probe and Flush+Reload** attacks on RSA are detailed in §04a.

---

## 8. RSA Key Generation Weaknesses

### 8.1 Shared Prime Factors

If two RSA moduli $N_1 = p \cdot q_1$ and $N_2 = p \cdot q_2$ share a prime factor $p$, then $\gcd(N_1, N_2) = p$, and both keys are instantly broken.

**Large-scale survey (2012)**: Heninger, Durumeric, Wustrow, Halderman, and others scanned the entire IPv4 address space for SSH and TLS public keys and found that:
- 0.2% of RSA moduli shared a prime factor with another modulus.
- Among 1024-bit RSA keys, the collision rate was even higher.
- The root cause was low-entropy key generation on embedded devices (routers, IoT devices) that seeded their PRNGs with insufficient entropy at boot time.

The GCD computation takes $O(n^2)$ time for a pair of $n$-bit moduli, but checking all $\binom{N}{2}$ pairs among $N$ collected moduli requires pairwise GCD — $O(N^2)$ operations. Kämper improved this using a product tree approach with $O(N \cdot M^2)$ time, where $M$ is the modulus size, enabling efficient scanning of millions of collected keys.

```bash
# Scan for shared prime factors in a collection of RSA moduli
# Using batch GCD (Heninger et al. methodology)
python3 -c "
from math import gcd
import sys

moduli = [int(line.strip(), 16) for line in sys.stdin]
for i in range(len(moduli)):
    for j in range(i+1, len(moduli)):
        g = gcd(moduli[i], moduli[j])
        if g != 1 and g != moduli[i] and g != moduli[j]:
            print(f'Shared factor found between moduli {i} and {j}: {g}')
"

# More efficient: batch GCD using product tree
# See: https://github.com/Heninger/Public-Key-Security
```

### 8.2 Weak Random Number Generation

**Debian OpenSSL Bug (CVE-2007-4995, §06)**: The most devastating key generation weakness in history. In 2006, a Debian maintainer removed "uninitialized variable" warnings from OpenSSL's random number generator by commenting out the line that mixed in `/dev/urandom` output. This left the PRNG seeded only with the process ID (PID), reducing the entropy to 15 bits. All SSH and TLS keys generated on Debian/Ubuntu systems between September 2006 and May 2008 were effectively chosen from a set of $2^{15} = 32{,}768$ possible keys for each key size.

**Savage et al. (2018)** extended the survey methodology to find that weak keys persist in the wild:
- Many embedded devices still generate keys with low-entropy PRNGs.
- Keys generated on headless systems (routers, IoT) at first boot often have insufficient entropy.
- Some firewalls generate all key pairs with a PRNG seeded from a static source.

### 8.3 Pseudoprime Generation

If the RSA key generation uses a weak primality test (e.g., Fermat test only), an attacker can construct **Carmichael numbers** — composite numbers that pass the Fermat test for all bases. These numbers would be accepted as primes by the generation routine, leading to a modulus $N$ that is trivially factorable.

```python
import sympy

# A Carmichael number passes Fermat's test for all bases
# but is composite. If used as p in RSA, N = p * q is factorable.
def is_carmichael(n):
    """Check if n is a Carmichael number."""
    if sympy.isprime(n):
        return False
    for a in range(2, n):
        if gcd(a, n) == 1:
            if pow(a, n - 1, n) != 1:
                return False
    return True

# Example Carmichael numbers: 561, 1105, 1729, 2465, 2821, ...
# Defense: always use Miller-Rabin or Baillie-PSW primality tests
```

**Defense**: Use a robust primality test (Miller-Rabin with multiple random bases, or Baillie-PSW). NIST SP 800-56B Rev. 2 requires at least five rounds of Miller-Rabin testing for primes used in RSA key generation.

### 8.4 ROCA (Return of Coppersmith's Attack) — CVE-2017-15361

The **ROCA vulnerability** affected Infineon TPM chips and smart cards. Infineon's RSA key generation algorithm used a specific prime generation method that produced primes of the form:

$$p = k \cdot M + (65537^a \mod M)$$

where $M$ is a known product of small primes and $a$ is a small exponent. This structure enables Coppersmith's method to factor $N = pq$ in time $O(n^5)$ instead of the expected sub-exponential GNFS time.

For 1024-bit keys, the attack takes $\sim 2^{73}$ operations (practical on moderate hardware in a few days). For 2048-bit keys, the attack takes $\sim 2^{108}$ operations (borderline practical with significant resources).

**Affected systems**:
- Infineon Trusted Platform Modules (TPMs) in millions of laptops (Lenovo, HP, Dell)
- Smart cards (YubiKey 4, some ID cards)
- Microsoft Azure cloud HSMs

**Detection**: A fingerprinting method identifies whether a public key was generated with the vulnerable Infineon algorithm by checking if $p \mod M$ is in the set of residues $\{65537^a \mod M\}$. This is computationally trivial:

```python
def is_roca_vulnerable(n, e=65537):
    """Check if n might have been generated by the vulnerable Infineon algorithm."""
    # The vulnerable primes satisfy p mod M in a small set of values
    # M = product of first 39 primes (primorial of 167)
    M = 1
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
              53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 
              109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]:
        M *= p
    
    # Check if n mod M has the characteristic structure
    n_mod_M = n % M
    # Vulnerable keys produce specific residues
    # Compute the set of (65537^a mod M) for small a
    residues = set()
    for a in range(1, 65537):
        residues.add(pow(e, a, M))
    
    return n_mod_M in residues
```

---

## 9. Fermat Factorization for Close Primes

### 9.1 The Method

Fermat's factorization method exploits the fact that if $N = pq$ where $p$ and $q$ are close (i.e., $|p - q|$ is small relative to $\sqrt{N}$), then $N$ can be factored efficiently.

Write $N = a^2 - b^2 = (a+b)(a-b)$ where $a = (p+q)/2$ and $b = (p-q)/2$. If $p$ and $q$ are close, then $b$ is small and $a \approx \sqrt{N}$.

**Algorithm**:
1. Start with $a = \lceil\sqrt{N}\rceil$.
2. Compute $b^2 = a^2 - N$.
3. If $b^2$ is a perfect square, then $p = a + b$ and $q = a - b$.
4. Otherwise, increment $a$ by 1 and go to step 2.

**Complexity**: If $|p - q| < 2N^{1/4}$, Fermat factorization finds the factors in $O(1)$ steps. More generally, the number of steps is $\sim \frac{(p - q)^2}{8\sqrt{N}}$, which is polynomial in $\log N$ when $|p - q|$ is small.

### 9.2 Practical Exploitation

Numerous real-world RSA keys have been factored because their primes $p$ and $q$ were too close together. This happens when key generation algorithms choose $p$ randomly and then set $q = \text{next\_prime}(p + \text{small\_offset})$.

**Notorious example**: Some early Java implementations generated RSA keys with $q = \text{next\_prime}(\text{next\_prime}(p))$, producing primes that differ by only a few hundred to a few thousand. Fermat factorization breaks these keys instantly.

```python
import math

def fermat_factor(n, max_iterations=1000000):
    """Factor n using Fermat's method. Fast if p and q are close."""
    a = math.isqrt(n)
    if a * a == n:
        return a, a  # n is a perfect square
    
    a += 1  # Start from ceiling(sqrt(n))
    for i in range(max_iterations):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == n:
                return p, q
        a += 1
    return None  # Factors are not close; try GNFS

# Test with close primes
from sympy import nextprime
p = nextprime(2**512)  # A prime near 2^512
q = nextprime(p)        # The NEXT prime after p
n = p * q
# Fermat factorization should find p, q in very few iterations
factors = fermat_factor(n)
print(f"Factored in a few steps: {factors}")
```

**Defense**: Always ensure $|p - q| > 2^{(n/2) - 100}$ for an $n$-bit modulus. Most modern implementations choose $p$ and $q$ independently from the full range $[2^{(n/2)-1}, 2^{n/2}]$, which makes $|p - q|$ large with overwhelming probability.

---

## 10. ECC: Invalid Curve Attacks

### 10.1 The Attack

Invalid curve attacks exploit the fact that elliptic curve group operations (point addition, scalar multiplication) can be performed on **curves other than the intended curve**. When a server performs scalar multiplication $[k]P$ on a point $P$ *without validating* that $P$ lies on the correct curve, an attacker can submit a point on a different (weaker) curve and extract information about $k$.

**Mechanism**: The Weierstrass form $y^2 = x^3 + ax + b$ defines the curve, but the point addition formulas only depend on the parameter $a$, not $b$. Therefore, given a valid point $P = (x_0, y_0)$ on the correct curve $E_{a,b}$ and the parameter $a$, the point $P$ also lies on infinitely many curves $E_{a,b'}$ for different values of $b'$. These "invalid curves" may have smooth order (i.e., their group order factors into small primes), enabling a Pohlig-Hellman discrete log attack.

**Attack procedure**:
1. Find an invalid curve $E'$ with order $|E'| = l \cdot q_1 \cdot q_2 \cdots q_t$ where the $q_i$ are small primes.
2. Generate a point $P'$ on $E'$ of order $l$ (small prime).
3. Submit $P'$ to the server as the ECDH public key.
4. Receive $[k]P'$ (the server computes the scalar multiplication without checking curve validity).
5. Compute the discrete logarithm $k \mod l$ on $E'$ using the Pohlig-Hellman algorithm (trivial for small $l$).
6. Repeat with different invalid curves (different small orders $l_i$) and recover $k$ via the Chinese Remainder Theorem.

If $\prod l_i > \text{order of the correct curve}$, $k$ is fully recovered.

### 10.2 Practical Exploitation

**CVE-2019-11579 — WordPress Adobe Flash fallback**: The Flash-based XMPP client in WordPress did not validate that ECDH public keys lay on the correct curve, enabling full key recovery via invalid curve attack.

**TLS ECDH**: Early TLS implementations (some Java, some older OpenSSL versions) did not validate ECDH public key points. This enabled invalid curve attacks against server ephemeral keys.

**Defense**:
1. **Always validate** that received ECDH public key points satisfy the curve equation: $y^2 \equiv x^3 + ax + b \pmod{p}$.
2. **Check** that the point is not the point at infinity.
3. **Use** curve25519/X25519, which encodes only the x-coordinate and uses a Montgomery ladder that operates on the correct curve by construction. The Kummer surface construction of Curve25519 ensures that the scalar multiplication operates on a group of the correct order regardless of the input (though the functional Montgomery ladder still requires a legitimate x-coordinate).

```python
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

def validate_ec_point(public_key_bytes, curve):
    """Validate that a received ECDH public key point lies on the curve."""
    # For NIST P-256
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    
    # Uncompressed point format: 0x04 || x || y
    if public_key_bytes[0] != 0x04:
        return False
    x = int.from_bytes(public_key_bytes[1:33], 'big')
    y = int.from_bytes(public_key_bytes[33:65], 'big')
    
    # Check: y^2 ≡ x^3 + ax + b (mod p)
    lhs = pow(y, 2, p)
    rhs = (pow(x, 3, p) + a * x + b) % p
    return lhs == rhs and x != 0 and y != 0  # Also reject point at infinity
```

---

## 11. ECC: Twist Security and Small Subgroup Attacks

### 11.1 Twist Security

A **twist** of an elliptic curve $E: y^2 = x^3 + ax + b$ over $\mathbb{F}_p$ is a related curve $E': dy^2 = x^3 + ax + b$ (or equivalently $y^2 = x^3 + ad^2x + d^3b$ for a quadratic non-residue $d$). The twist has a different group order, typically $2p + 2 - |E(\mathbb{F}_p)|$.

If the twist's group order has small factors, an attacker who sends points on the twist (which are accepted by implementations that don't validate curve membership) can perform a small-subgroup confinement attack. This is distinct from but related to the invalid curve attack.

**Curve25519's twist security**: Curve25519 was specifically designed so that both the curve and its twist have group orders that are 4 or 8 times a large prime. Specifically:
- $\#E(\mathbb{F}_p) = 8 \cdot q_1$ where $q_1$ is a 252-bit prime.
- $\#E'(\mathbb{F}_p) = 4 \cdot q_2$ where $q_2$ is a 253-bit prime.

This means that even if a point is sent on the wrong curve (the twist), the largest cofactor is 8, limiting the information leak to 3 bits per execution. This is an intentional design property that makes Curve25519 robust against invalid curve and twist attacks.

### 11.2 Small Subgroup Confinement Attack

In Diffie-Hellman over elliptic curves, if the curve order $n$ has a small cofactor $h$ (i.e., $n = h \cdot q$ where $q$ is prime and $h$ is small, like $h = 8$ for Curve25519), then points of small order (divisors of $h$) exist on the curve.

An attacker sends a point $P$ of small order $l$ (where $l | h$) instead of a legitimate point. The server computes $[k]P$, which is one of $l$ possible points of order $l$. The attacker checks which one was produced, learning $k \mod l$.

For Curve25519 with $h = 8$, each execution leaks at most 3 bits of $k$. This is not catastrophic but must be accounted for in the protocol design. The X25519 specification requires that the result of scalar multiplication be checked for the identity element (all-zero output), which limits the leak to the order of the attacker's point.

**Defense**: 
1. Check for the identity point (all-zero output in X25519) and abort if detected.
2. Use cofactor multiplication: compute *hP* first, then *k(hP)*. Since *hP* has order *q* (prime), the small-subgroup attack is eliminated.
3. Use curve25519/X25519, which has cofactor 8 — small enough that the leak is bounded and manageable.

### 11.3 Invalid Curve Attack on Static ECDH

The attack is most dangerous when the server uses **static ECDH** (the same private key for multiple sessions). Each invalid curve query leaks $k \mod l_i$ for a different prime $l_i$, and after enough queries, $k$ is recovered via CRT.

For **ephemeral ECDH** (ECDHE), a fresh key is used per session, so the attacker gets at most 3 bits per session (for Curve25519). However, ephemeral keys are typically not validated either, and if the server reuses the ephemeral key for multiple connections (a protocol error), the attack applies.

---

## 12. ECC: Side-Channel Attacks on Scalar Multiplication

### 12.1 Power Analysis on ECC

**SPA (Simple Power Analysis)** on ECC: The standard double-and-add algorithm for scalar multiplication $[k]P$ reveals the bits of $k$ through power consumption patterns. Each "1" bit causes a point addition (extra power consumption), while each "0" bit causes only a doubling. An attacker visually examining a power trace can read off $k$ directly.

**DPA (Differential Power Analysis)** on ECC: By collecting many traces and performing statistical analysis, the attacker correlates power consumption at specific time points with hypothetical intermediate values, recovering $k$ one bit at a time. DPA is more powerful than SPA because it can distinguish between subtle power differences that are invisible in individual traces.

### 12.2 Montgomery Ladder as Countermeasure

The Montgomery ladder for scalar multiplication on Montgomery curves (like Curve25519) is inherently constant-time:

```
R0 = P
R1 = 2P  (precomputed)
for bit in k.bits() from MSB to LSB:
    if bit == 0:
        R1 = R0 + R1    (add)
        R0 = 2 * R0     (double)
    else:
        R0 = R0 + R1    (add)
        R1 = 2 * R1     (double)
return R0
```

Every iteration performs exactly one addition and one doubling, regardless of the bit value. This eliminates timing-based and power-based branches, making SPA attacks ineffective.

### 12.3 Projective Coordinates and Randomization

Affine coordinates $(x, y)$ on elliptic curves leak information through timing variations (field inversions are expensive and their timing depends on operand values). **Projective coordinates** $(X:Y:Z)$ eliminate inversions until the final conversion back to affine, reducing timing leakage.

**Scalar randomization**: Before computing $[k]P$, generate a random $r$ and compute $[k + r \cdot \text{ord}(P)]P = [k]P$ (since $[r \cdot \text{ord}(P)]P = \mathcal{O}$). This randomizes $k$ without changing the result, preventing DPA.

**Point blinding**: Instead of $[k]P$, compute $[k](P + Q) - [k]Q$ for random $Q$, where $[k]Q$ is precomputed. This randomizes the intermediate values.

**Base point randomization**: In projective coordinates, randomize by multiplying $(X, Y, Z)$ by a random scalar $\lambda$: $(X, Y, Z) \to (\lambda X, \lambda Y, \lambda Z)$. This represents the same affine point but with randomized projective representation, defeating DPA.

### 12.4 Twist Attacks on Montgomery Curves

The Montgomery ladder used in X25519 operates only on the x-coordinate, which means it cannot distinguish between a point on Curve25519 and a point on its quadratic twist. This is by design (twist security ensures the twist also has near-prime order), but on curves without twist security, an attacker can submit a point on the twist and extract partial key information — the twist attack described in §11.

**Countermeasure**: Ensure received x-coordinates correspond to valid points on the correct curve's quadratic span. X25519's twist security makes this check unnecessary, but for Weierstrass-form curves (secp256r1, secp256k1), point validation is mandatory.

---

## Cross-References

- **§01a** — Cryptographic fundamentals: RSA, ECC, and Diffie-Hellman definitions
- **§01b** — Symmetric attacks: key recovery from nonce reuse (analogous to key recovery from RSA weaknesses)
- **§03a** — TLS attacks: ROBOT (Bleichenbacher in TLS), FREAK (export-grade RSA), Logjam (export-grade DH), DROWN (SSLv2 cross-protocol)
- **§04a** — Side-channel attacks: timing attacks, cache attacks (Prime+Probe on RSA), power analysis (SPA/DPA on smart cards)
- **§04b** — Hardware attacks: TPM ROCA vulnerability, Infineon key generation weakness
- **§05a** — Post-quantum: lattice-based and isogeny-based replacements for RSA/ECC
- **§06** — Case studies: Debian OpenSSL (weak RNG → weak RSA keys), DigiNotar (CA compromise issuing fraudulent certs), ROCA (CVE-2017-15361)
- **Linux Kernel track** — AF_ALG crypto API, kernel RSA/ECC implementation
- **Chromium track** — BoringSSL RSA/ECC implementation, Chrome's key pinning

## References

1. Bleichenbacher, D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1," CRYPTO 1998. CVE-1998-0073.
2. Böck, H., Somorovsky, J., Young, C., "Return Of Bleichenbacher's Oracle Threat (ROBOT)," USENIX Security 2018. CVE-2017-17382.
3. Manger, J., "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0," CRYPTO 2001.
4. Coppersmith, D., "Small Solutions to Polynomial Equations, and Low Exponent RSA Vulnerabilities," Journal of Cryptology, 1996.
5. Wiener, M., "Cryptanalysis of Short RSA Secret Exponents," IEEE Transactions on Information Theory, 1990.
6. Boneh, D., Durfee, G., "Cryptanalysis of RSA with Private Exponent d < N^{0.292}," IEEE Transactions on Information Theory, 2000.
7. Kocher, P., "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems," CRYPTO 1996.
8. Brumley, D., Boneh, D., "Remote Timing Attacks Are Practical," USENIX Security 2003.
9. Némec, M., Švenda, P., Klinec, V., Švenda, P., "The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli," CCS 2017. CVE-2017-15361.
10. Heninger, N., Durumeric, Z., Wustrow, E., Halderman, J.A., "Mining Your Ps and Qs: Widespread Weak Keys in Network Devices," USENIX Security 2012.
11. CVE-2007-4995, "Debian OpenSSL Predictable Random Number Generator," 2007.
12. Franklin, M.K., Reiter, M.K., "A General Protocol for Natural Number Certificate," CRYPTO 1995.
13. Boneh, D., DeMillo, R.A., Lipton, R.J., "On the Importance of Checking Computations," EUROCRYPT 1997.
14. Piret, G., Quisquater, J.-J., "A Differential Fault Attack Technique Against SPN Structures," CHES 2003.
15. Bernstein, D.J., "Curve25519: New Diffie-Hellman Speed Records," PKC 2006.
16. RFC 7748, "Elliptic Curves for Security," January 2016.
17. RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)," January 2017.
18. NIST, "Digital Signature Standard (DSS)," FIPS 186-5, February 2023.
19. Osvik, D.A., Shamir, A., Tromer, E., "Cache Attacks and Countermeasures: The Case of AES," CT-RSA 2006.
20. Genkin, D., Shamir, A., Tromer, E., "RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis," CRYPTO 2014.