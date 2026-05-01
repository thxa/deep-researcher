# Cryptography & Crypto Attacks — Quick Reference

## AES Mode Comparison

| Mode | Encryption | Parallelizable | IV/Nonce | Error Propagation | Authentication | Security Properties |
|------|-----------|---------------|----------|-------------------|----------------|---------------------|
| **ECB** | Block-by-block | ✅ Encrypt+Decrypt | None | Single block | ❌ | Deterministic; leaks patterns; **NEVER USE** |
| **CBC** | Chained (C_i = P_i ⊕ C_{i-1}) | ✅ Decrypt only | 16B IV | Full after error | ❌ | Requires unpredictable IV; padding oracle if PKCS#7 |
| **CTR** | Stream (keystream XOR) | ✅ Encrypt+Decrypt | 16B nonce+ctr | None | ❌ | Malleable; nonce reuse catastrophic; no padding needed |
| **GCM** | CTR + GHASH tag | ✅ Encrypt+Decrypt | 12B nonce | None | ✅ 128-bit tag | Authenticated encryption; **nonce reuse is catastrophic** (H leak); standard for TLS 1.2/1.3 |
| **XTS** | Tweakable (sector-based) | ✅ Encrypt+Decrypt | 16B tweak | Sector-level | ❌ | Designed for disk encryption; narrow-block; no authentication |
| **CCM** | CTR + CBC-MAC | ❌ | 12B nonce | Full | ✅ 128-bit tag | Authenticated; lower throughput; used in 802.11/WPA2 |
| **SIV** | Synthetic IV | ✅ Decrypt | None (derived) | None | ✅ 128-bit tag | Misuse-resistant; nonce reuse reveals encryption is repeated, nothing more |
| **OCB** | Offset CodeBook | ✅ Encrypt+Decrypt | 12B nonce | None | ✅ 128-bit tag | Fast AEAD; patent-encumbered (now royalty-free) |

**Key rules**: Never use ECB. Never reuse nonces with CTR/GCM. Always authenticate (encrypt-then-MAC or AEAD). Prefer GCM or ChaCha20-Poly1305 for TLS. Use XTS only for disk encryption.

## RSA Attack Reference

| Attack | Requirement | Complexity | Result | Reference |
|--------|-------------|------------|--------|-----------|
| **Bleichenbacher (PKCS#1 v1.5)** | Oracle returns PKCS conformant/no | O(n log² n) queries | RSA plaintext recovery | Bleichenbacher 1998; DROWN, ROBOT variants |
| **Manger (OAEP)** | Oracle returns < 2^160 | ~2^20 queries | RSA-OAEP plaintext recovery | Manger 2001 |
| **Coppersmith (low exponent)** | e·|p₀| ≤ N^(1/e) (MSBs known) | LLL lattice reduction | Factor N given partial information | Coppersmith 1996 |
| **Coppersmith (small e, related messages)** | e small, messages related linearly | Polynomial GCD | Recover messages | Franklin-Reiter related message attack |
| **Wiener** | d < N^0.25 | O(1) continued fraction | Recover d from (N, e) | Wiener 1990 |
| **Boneh-Durfee** | d < N^0.292 | LLL lattice | Recover d from (N, e) | Boneh-Durfee 1999 |
| **Fermat factorization** | p, q close (∆ < N^0.25) | O((p-q)/√N) iterations | Factor N | Fermat; check if N = a² - b² |
| **Håstad (broadcast)** | Same message to e recipients with e_i = e (>1) | CRT + e-th root | Recover m | Håstad 1989; works for e=3, 3 recipients |
| **Common modulus** | Same N, different e | GCD attack | Factor N or decrypt | If gcd(e₁,e₂)=1, recover m via CRT |
| **Shared factor** | Two moduli N₁, N₂ share p | GCD(N₁, N₂) | Factor both moduli | O(log N) Euclidean GCD |
| **Timing (Kocher)** | Decryption timing varies with d | Statistical | Recover d bit-by-bit | Kocher 1996; mitigated by blinding |
| **ROCA** | Infineon RSA key gen uses pattern | O(n^2) per prime | Factor N from public key only | Némec et al. 2017; CVE-2017-15361 |

### Bleichenbacher Attack Template

```python
import os, math

def bleichenbacher(oracle, ciphertext, e, n):
    """PKCS#1 v1.5 padding oracle attack on RSA.
    
    Oracle returns True if decrypted value has valid PKCS#1 v1.5 padding:
    0x00 0x02 [8+ non-zero bytes] 0x00 [message]
    """
    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))  # lower bound for valid plaintext
    
    # Step 2a: Find initial s
    # ... (finding first conformant s > n/B)
    
    # Step 2b/c: Narrow M_i intervals
    # ... (update intervals using oracle responses)
    
    # Step 4: Solve for plaintext when M has one interval
    # ... (m ~ (lo + hi) // 2, refine)
    
    # Full implementation: ~150 lines; see docs/02b_rsa_attacks.md
    pass

# Quick check: does N have close factors?
def fermat_factor(n):
    a = math.isqrt(n) + 1
    b2 = a*a - n
    while not math.isqrt(b2)**2 == b2:
        a += 1
        b2 = a*a - n
    return a - math.isqrt(b2), a + math.isqrt(b2)

# Quick check: do two moduli share a factor?
from math import gcd
def shared_factor(n1, n2):
    p = gcd(n1, n2)
    if 1 < p < n1:
        return p, n1 // p, n2 // p
    return None

# Wiener's attack (small d)
def wiener(e, n):
    """Recover d when d < N^0.25 using continued fractions."""
    cf = continued_fraction(e, n)  # convergents of e/n
    for k, d in convergents(cf):
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # check: x^2 - (n - phi + 1)*x + n = 0 has integer roots
        s = n - phi + 1
        disc = s*s - 4*n
        if disc >= 0 and math.isqrt(disc)**2 == disc:
            return d
    return None
```

## TLS Version & Cipher Suite Security

| TLS Version | RFC | Status | Key Exchange | Cipher | PRF | Security |
|-------------|-----|--------|--------------|--------|-----|----------|
| **SSL 3.0** | 6101 | 🔴 Broken | RSA, DH | RC4, 3DES, AES | MD5/SHA-1 | POODLE; RC4 biases; **DISABLE** |
| **TLS 1.0** | 2246 | 🔴 Broken | RSA, DH | RC4, 3DES, AES | MD5/SHA-1 | BEAST; no AEAD; **DISABLE** |
| **TLS 1.1** | 4346 | 🔴 Broken | RSA, DH | 3DES, AES | MD5/SHA-1 | No AEAD; **DISABLE** |
| **TLS 1.2** | 5246 | 🟡 Supported | RSA, DHE, ECDHE | 3DES, AES-CBC, AES-GCM, ChaCha20 | SHA-256 | CBC padding oracle (Lucky13); prefer AEAD |
| **TLS 1.3** | 8446 | 🟢 Recommended | ECDHE, X25519, P-256 | AES-GCM, ChaCha20-Poly1305 | HKDF-SHA256 | No negotiation; no RSA key exchange; 0-RTT replay caveat |

### Cipher Suite Priority (TLS 1.2)

```
# Strong preference — AEAD first, AECDHE > DHE > RSA, ECDHE > DHE
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256

# NEVER enable
TLS_RSA_WITH_RC4_128_SHA              # RC4 insecure
TLS_RSA_WITH_3DES_EDE_CBC_SHA         # 3DES weak (64-bit block, SWEET32)
TLS_RSA_WITH_AES_128_CBC_SHA          # CBC padding oracle (Lucky13)
TLS_RSA_EXPORT_WITH_RC4_40_SHA        # Export-grade (FREAK)
TLS_DHE_EXPORT_WITH_DES40_CBC_SHA     # Export-grade (FREAK/Logjam)
```

### TLS 1.3 Key Schedule

```
             0
             |
             v
   HKDF-Extract
             |
             v
   Early Secret ----[derive_secret]----> early traffic keys (0-RTT)
             |
             v
   HKDF-Extract
             |
             v
   Handshake Secret --[derive_secret]--> handshake traffic keys
             |
             v
   HKDF-Extract = Chaining Key
             |                        +--> client application traffic secret
             +--[derive_secret]------+
             |                        +--> server application traffic secret
             v
   Master Secret
             |
             v
   [derive_secret] --> exporter master secret
   [derive_secret] --> resumption master secret
```

## Hash Function Comparison

| Hash | Output | Block Size | Construction | Collision | Preimage | Speed | Security Notes |
|------|--------|-----------|--------------|-----------|----------|-------|----------------|
| **MD5** | 128b | 512b | Merkle-Damgård | 🔴 2^18 (practical) | 🟡 2^123 | Fast | **BROKEN**; chosen-prefix collision trivial |
| **SHA-1** | 160b | 512b | Merkle-Damgård | 🔴 2^63 (practical, SHAttered) | 🟡 2^159 | Medium | **BROKEN**; SHA-1 deprecation complete in browsers |
| **SHA-256** | 256b | 512b | Merkle-Damgård | 🟢 2^128 (theoretical) | 🟢 2^256 | Medium | Standard; length-extension vulnerable without HMAC |
| **SHA-512** | 512b | 1024b | Merkle-Damgård | 🟢 2^256 | 🟢 2^512 | Fast (64-bit) | 64-bit performance advantage over SHA-256 |
| **SHA-3-256** | 256b | 1088b | Sponge (Keccak) | 🟢 2^128 | 🟢 2^256 | Medium | No length extension; different design philosophy |
| **SHA-3-512** | 512b | 576b | Sponge (Keccak) | 🟢 2^256 | 🟢 2^512 | Slow | Maximum security margin |
| **BLAKE2b** | 512b | 1024b | HAIFA (ChaCha-based) | 🟢 2^256 | 🟢 2^512 | **Fastest** | No length extension; tree hashing; used in ZFS |
| **BLAKE2s** | 256b | 512b | HAIFA (ChaCha-based) | 🟢 2^128 | 🟢 2^256 | Fast | Compact; optimal for 32-bit platforms |
| **BLAKE3** | 256b | 1024b | Merkle tree + ChaCha | 🟢 2^128 | 🟢 2^256 | **Fastest** | Parallel; incremental; verified hashing |

### Length Extension Attack

```python
# H(secret || message) can be extended to H(secret || message || padding || suffix)
# WITHOUT knowing secret, given only H(secret || message) and len(secret || message)

import struct, hashlib

def md_length_extend(original_hash, original_len, suffix, hash_func=hashlib.sha256):
    """Extend MD-based hash without knowing the prefix.
    
    Works on: MD5, SHA-1, SHA-256, SHA-512 (all Merkle-Damgård)
    Does NOT work on: SHA-3, BLAKE2/3 (resistant by design)
    """
    block_size = hash_func().block_size  # 64 for SHA-256, 128 for SHA-512
    
    # Step 1: Compute padding that would be applied to original message
    padded_len = original_len + 1  # +1 for 0x80
    padded_len += (block_size - padded_len % block_size)  # round up to block
    
    # Step 2: Initialize hash state from original digest
    # For SHA-256: decompose 32-byte hash into 8 x 32-bit words
    # (simplified; real impl uses internal state reconstruction)
    
    # Step 3: Hash suffix with state set to original_hash
    # Result: hash_func(original_message + padding + suffix)
    # This is the forged hash value
    pass
```

## Key Size Recommendations

### Classical Key Sizes

| Algorithm | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **AES** | 128-bit | 256-bit | 128-bit secure; 256 for quantum margin |
| **RSA** | 2048-bit | 4096-bit | 2048 ≈ 112-bit security; 3072 ≈ 128-bit |
| **ECDSA/ECDH** | P-256 | P-384 or P-521 | P-256 ≈ 128-bit; Prefer Curve25519 (128-bit) |
| **Ed25519** | 255-bit | 255-bit | 128-bit security level; Ed448 for 224-bit |
| **DH (finite field)** | 2048-bit | 3072+ | Prefer ECDH; FF DH deprecated |
| **HMAC** | Hash output ≥ hash output | SHA-256+ | Key ≥ hash output length |

### Post-Quantum Key Sizes (NIST Standards)

| Algorithm | Type | Security Level | Public Key | Ciphertext/Signature | NIST Standard |
|-----------|------|---------------|------------|---------------------|----------------|
| **ML-KEM-512** | Lattice KEM | Level 1 (128-bit) | 688 B | 768 B (ct) | FIPS 203 |
| **ML-KEM-768** | Lattice KEM | Level 3 (192-bit) | 1184 B | 1088 B (ct) | FIPS 203 |
| **ML-KEM-1024** | Lattice KEM | Level 5 (256-bit) | 1568 B | 1568 B (ct) | FIPS 203 |
| **ML-DSA-44** | Lattice DSA | Level 2 | 1312 B | 2420 B (sig) | FIPS 204 |
| **ML-DSA-65** | Lattice DSA | Level 3 | 1952 B | 3308 B (sig) | FIPS 204 |
| **ML-DSA-87** | Lattice DSA | Level 5 | 2592 B | 4627 B (sig) | FIPS 204 |
| **SLH-DSA-SHA2-128s** | Hash DSA | Level 1 | 32 B | 7856 B (sig) | FIPS 205 |
| **SLH-DSA-SHA2-256f** | Hash DSA | Level 5 | 64 B | 29792 B (sig) | FIPS 205 |
| **FN-DSA-512** | NTRU Lattice | Level 1 | 897 B | 768 B (ct) | FIPS 206 (draft) |
| **Classic McEliece** | Code KEM | Level 1 | 261,120 B | 128 B (ct) | Round 4; **huge keys** |

**Comparison impact**: RSA-2048 public key = 256 B, ML-KEM-768 = 1184 B (~4.6× larger). TLS ClientHello grows significantly; careful with MTU/TCP.

## OpenSSL Command Reference

### Key Generation

```bash
# RSA
openssl genrsa -aes256 -out rsa_private.pem 4096
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
openssl rsa -in rsa_private.pem -text -noout          # inspect key

# ECDSA
openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem
openssl ecparam -name secp384r1 -genkey -noout -out ec384_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
openssl ecparam -list_curves                            # list available curves

# Ed25519
openssl genpkey -algorithm ED25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem

# X25519 (ECDH)
openssl genpkey -algorithm X25519 -out x25519_private.pem
openssl pkey -in x25519_private.pem -pubout -out x25519_public.pem

# DH parameters (avoid unless required)
openssl dhparam -out dhparams.pem 2048                  # slow; prefer ECDH
```

### Certificate Operations

```bash
# Self-signed CA
openssl req -x509 -new -nodes -newkey rsa:4096 -keyout ca.key -sha256 \
    -days 3650 -out ca.crt -subj "/CN=My CA/O=Test/C=US"

# CSR from existing key
openssl req -new -key server.key -out server.csr \
    -subj "/CN=example.com/O=Test/C=US"

# Sign CSR with CA (simulate real CA)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365 -sha256 \
    -extfile <(echo "subjectAltName=DNS:example.com,DNS:www.example.com")

# Inspect certificate
openssl x509 -in server.crt -text -noout
openssl x509 -in server.crt -noout -subject -issuer -dates
openssl x509 -in server.crt -noout -ext subjectAltName

# Verify certificate chain
openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt

# Convert formats
openssl x509 -in cert.pem -outform DER -out cert.der     # PEM → DER
openssl x509 -in cert.der -inform DER -out cert.pem       # DER → PEM
openssl pkcs12 -export -out cert.p12 -inkey key.pem \    # PEM → PKCS#12
    -in cert.pem -certfile ca.crt
openssl pkcs12 -in cert.p12 -nodes -out all.pem           # PKCS#12 → PEM
```

### Testing & Debugging

```bash
# TLS connection testing
openssl s_client -connect example.com:443 -tls1_3 -servername example.com
openssl s_client -connect example.com:443 -tls1_2 -cipher ECDHE+AESGCM

# Check certificate chain and verify
openssl s_client -connect example.com:443 -showcerts </dev/null 2>/dev/null

# Test specific cipher suites
openssl s_client -connect example.com:443 -tls1_2 \
    -cipher 'ECDHE-ECDSA-AES256-GCM-SHA384'

# Check OCSP stapling
openssl s_client -connect example.com:443 -status </dev/null

# Extract TLS certificate info
echo | openssl s_client -connect example.com:443 2>/dev/null | \
    openssl x509 -noout -text

# Generate hash collision test (MD5)
echo "Testing MD5 weakness — only for verification:"
echo -n "test" | openssl md5

# Sign and verify with RSA
echo "message" | openssl dgst -sha256 -sign rsa_private.pem -out sig.bin
echo "message" | openssl dgst -sha256 -verify rsa_public.pem -signature sig.bin

# Sign and verify with ECDSA
echo "message" | openssl dgst -sha256 -sign ec_private.pem -out sig.bin
echo "message" | openssl dgst -sha256 -verify ec_public.pem -signature sig.bin

# Benchmark crypto performance
openssl speed aes-256-gcm
openssl speed ecdhp256
openssl speed rsa2048
openssl speed x25519
```

### Post-Quantum Testing (OQS OpenSSL fork)

```bash
# With oqsprovider (OpenSSL 3.x + liboqs)
openssl list -providers                    # check OQS provider loaded
openssl list -kem-algorithms               # list PQ KEMs
openssl list -signature-algorithms          # list PQ signature algos

# Generate ML-KEM (Kyber) keypair
openssl genpkey -algorithm ml-kem-768 -out mlkem_private.pem
openssl pkey -in mlkem_private.pem -pubout -out mlkem_public.pem

# Generate ML-DSA (Dilithium) keypair
openssl genpkey -algorithm ml-dsa-65 -out mldsa_private.pem

# TLS with hybrid PQ KEM (e.g., X25519+ML-KEM-768)
openssl s_client -connect example.com:443 \
    -groups x25519_mlkem768
```

## Padding Oracle Attack Template

```python
#!/usr/bin/env python3
"""Generic padding oracle attack against CBC mode encryption.
Adapts to any oracle that reveals whether PKCS#7 padding is valid.
"""

import os, sys
from binascii import hexlify

BLOCK_SIZE = 16

def padding_oracle(ciphertext: bytes) -> bool:
    """Replace with your oracle — returns True if padding is valid.
    
    Examples:
    - HTTP 200 vs HTTP 500
    - Specific error message vs generic
    - Timing difference (>2x variance)
    """
    raise NotImplementedError("Implement your oracle function")

def attack_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Recover plaintext of target_block using prev_block as IV."""
    intermediate = bytearray(BLOCK_SIZE)
    
    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_index  # expected padding byte
        
        # Build crafted previous block
        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_index + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ padding_value
        #crafted[byte_index] will be brute-forced
        
        found = False
        for guess in range(256):
            crafted[byte_index] = guess
            test_ct = bytes(crafted) + target_block
            
            if padding_oracle(test_ct):
                # For the last byte, verify it's not a false positive
                if byte_index == BLOCK_SIZE - 1:
                    # Flip a prior byte; if padding still valid, we got lucky
                    verify = bytearray(crafted)
                    verify[byte_index - 1] ^= 1
                    if not padding_oracle(bytes(verify) + target_block):
                        continue
                
                intermediate[byte_index] = guess ^ padding_value
                found = True
                break
        
        if not found:
            raise RuntimeError(f"Failed to find byte at position {byte_index}")
    
    # Recover plaintext: P = intermediate XOR original previous block
    plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(BLOCK_SIZE))
    return plaintext

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Full attack: recover entire CBC ciphertext plaintext."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b""
    
    for i in range(1, len(blocks)):
        print(f"[*] Attacking block {i}/{len(blocks)-1}...", file=sys.stderr)
        pt_block = attack_block(blocks[i-1], blocks[i])
        plaintext += pt_block
    
    # Remove PKCS#7 padding
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    return plaintext

if __name__ == "__main__":
    # Example: ct = bytes.fromhex(sys.argv[1])
    # result = padding_oracle_attack(ct)
    # print(result.decode())
    pass
```

## Side-Channel Attack Checklist

### Timing Attack Checklist

- [ ] Secret-dependent branches in crypto code (if/else on key bits)
- [ ] Secret-dependent memory access patterns (table lookups indexed by key material)
- [ ] Variable-time arithmetic (division, modular exponentiation with early exit)
- [ ] RSA: Is CRT blinding enabled? (openssl `RSA_BLINDING`)
- [ ] ECC: Is scalar multiplication constant-time? (check for Montgomery ladder)
- [ ] AES: Is a constant-time implementation used? (bitslicing, VAES, AES-NI)
- [ ] Comparison: Secret string comparison using `memcmp` instead of constant-time `CT_MEMEQ`
- [ ] Database/API: Password hash comparison using non-constant-time compare

### Cache Attack Checklist (Flush+Reload / Prime+Probe)

- [ ] Shared last-level cache (LLC) between attacker and victim (cloud co-location)
- [ ] AES T-table implementation (not AES-NI) enables cache-timed key recovery
- [ ] RSA modular exponentiation using sliding-window with table lookups
- [ ] ECC scalar multiplication using windowed method with precomputed points
- [ ] SGX/TEE enclave co-located on same physical core as attacker
- [ ] Hyper-threading enabled on cores processing crypto operations

### Power/EM Analysis Checklist

- [ ] DPA: Collect ≥1,000 traces for Hamming-weight leakage on key bits
- [ ] CPA: Correlate power traces with hypothetical intermediate values
- [ ] Template attack: Profile device power consumption per key byte
- [ ] Countermeasure: Evaluate masking (Boolean/arithmetic) order
- [ ] Countermeasure: Evaluate shuffling and random delays effectiveness
- [ ] Countermeasure: Evaluate power noise injection or dual-rail logic

### Fault Injection Checklist

- [ ] Clock glitching: Identify target instruction for DFA on AES/GCM
- [ ] EM glitch: Inject faults at specific round boundaries
- [ ] Laser: Target specific SRAM cells for key bit flipping
- [ ] Voltage: Under-voltage to cause computation errors
- [ ] DFA on AES: Check if last-round state difference recoverable
- [ ] Bellcore attack: Check if RSA-CRT error reveals factorization
- [ ] Countermeasure: Evaluate redundant computation and result checking

## Microarchitectural Attack Checklist

| Attack | Target | Prerequisite | Leaked Data | Mitigation |
|--------|--------|--------------|-------------|------------|
| **Spectre v1** (Bounds Check) | Conditional branches | Mistrained branch predictor | Out-of-bounds memory | LFENCE; index masking; retpoline |
| **Spectre v2** (Branch Target) | Indirect branches | Poisoned BTB | Kernel memory | Retpoline; IBRS; RSB fill |
| **Meltdown** (Rogue Data Cache Load) | User/Kernel boundary | No SMAP/SMEP/KPTI | Kernel memory | KPTI; KPTI is the fix |
| **Foreshadow** (L1 Terminal Fault) | SGX enclave | L1D cache access | SGX enclave memory | L1D flush; microcode update |
| **Microscope** | SGX enclaving | Cache side channel | Enclave memory | Enclaved page fault mitigation |
| **ZombieLoad** (MDS) | Line fill buffers | Hyper-threading or transient | Arbitrary memory | MDS buffers cleared; disable HT |
| **Fallout** (Store Buffer) | Store buffer | Transient store forwarding | Written data | Store buffer cleared on exception |
| **RIDL** (Port / Ring Bus) | Internal buffers | Transient execution | Arbitrary cross-VM | Clear microarchitectural buffers |
| **CacheOut** | L3 cache eviction | Transient execution | Cross-core data | Updated microcode; L1D flush |
| **SGAxe** | SGX attestation | Cache side channel | SGX sealing key | Rotate sealing keys |

## Post-Quantum Algorithm Comparison

| Algorithm | Category | Key Gen | Encaps/Sign | Decaps/Verify | Ciphertext | Sig Size | PK Size | Security |
|-----------|----------|---------|-------------|---------------|------------|----------|---------|----------|
| **ML-KEM-768** (Kyber) | Lattice KEM | 26 µs | 35 µs | 28 µs | 1088 B | — | 1184 B | Level 3 |
| **ML-KEM-1024** (Kyber) | Lattice KEM | 44 µs | 56 µs | 48 µs | 1568 B | — | 1568 B | Level 5 |
| **X25519** | Classical ECDH | 30 µs | 45 µs | 45 µs | 32 B | — | 32 B | ~128-bit |
| **ML-DSA-65** (Dilithium) | Lattice DSA | 90 µs | 119 µs | 23 µs | — | 3308 B | 1952 B | Level 3 |
| **ML-DSA-87** (Dilithium) | Lattice DSA | 150 µs | 210 µs | 38 µs | — | 4627 B | 2592 B | Level 5 |
| **SLH-DSA-SHA2-128s** | Hash DSA | 2 ms | 13 ms | 1.5 ms | — | 7856 B | 32 B | Level 1 |
| **SLH-DSA-SHA2-256f** | Hash DSA | 150 ms | 52 ms | 140 ms | — | 29792 B | 64 B | Level 5 |
| **Ed25519** | Classical DSA | 50 µs | 65 µs | 190 µs | — | 64 B | 32 B | ~128-bit |
| **RSA-2048** | Classical | 200 ms | — | 50 µs (verify) | — | 256 B | 256 B | ~112-bit |
| **Classic McEliece** | Code KEM | 300 ms | 30 µs | 300 µs | 128 B | — | 261KB | Level 1 |

*Performance figures are approximate on modern x86 (single core). Actual performance varies by platform.*

### Hybrid Key Exchange (TLS)

```
# TLS hybrid key exchange groups (RFC 9180 + draft-ietf-tls-hybrid-design)
# Client sends: classical_pk || pq_pk
# Server sends: classical_ct || pq_ct
# Shared secret: HKDF(combine(classical_ss, pq_ss))

# Recommended combinations:
X25519Kyber768Draft00     # 32+1184 = 1216 B client key share
X25519MLKEM768            # 32+1184 = 1216 B client key share (NIST final)
P256MLKEM768              # 65+1184 = 1249 B client key share (FIPS-friendly)
SecP256r1MLKEM768         # Same as above, IETF naming
```

## Key Crypto CVE Quick Reference

| CVE | Year | Component | Vulnerability | Impact | CVSS |
|-----|------|-----------|---------------|--------|------|
| **CVE-2014-0160** | 2014 | OpenSSL | Heartbleed — buffer over-read in TLS heartbeat | Remote memory disclosure (64KB/read) | 7.5 |
| **CVE-2016-0800** | 2016 | OpenSSL | DROWN — Bleichenbacher on SSLv2 | Full RSA decryption via SSLv2 oracle | 9.2 |
| **CVE-2015-0204** | 2015 | OpenSSL | FREAK — export-grade RSA (512-bit) | Man-in-the-middle forces weak export cipher | 7.5 |
| **CVE-2015-4000** | 2015 | Diffie-Hellman | Logjam — 512-bit export DH | MITM downgrade; discrete log attack | 7.5 |
| **CVE-2016-0702** | 2016 | OpenSSL | Cachebleed — RSA key via cache side channel | Full RSA-2048 key recovery via HT | 5.9 |
| **CVE-2017-15361** | 2017 | Infineon TPM | ROCA — weak RSA key generation | Factor 2048-bit RSA from public key only | 9.1 |
| **CVE-2018-0737** | 2018 | OpenSSL | RSA key generation timing side channel | Small-RSA-key generation leak | 5.3 |
| **CVE-2018-12433** | 2018 | OpenSSL | Side-channel in ECDSA signature | Potential nonce recovery | 5.9 |
| **CVE-2020-0601** | 2020 | Windows CryptoAPI | CurveBall — ECC cert spoofing | Fakes trusted certs for any website | 8.1 |
| **CVE-2020-1967** | 2020 | OpenSSL | SIGalgorithms DoS | CPU denial of service via malicious signature | 5.3 |
| **CVE-2021-3449** | 2021 | OpenSSL | Signature algorithms crash | DoS via malformed SM2 cert | 5.3 |
| **CVE-2021-3711** | 2021 | OpenSSL | SM2 decryption buffer overflow | Potential RCE | 9.8 |
| **CVE-2021-40436** | 2021 | OpenSSL | CMS/S/MIME verify crash | DoS via malformed CMS | 5.3 |
| **CVE-2022-0778** | 2022 | OpenSSL | Infinite loop in certificate verification | DoS via crafted cert with invalid elliptic curve | 7.5 |
| **CVE-2022-1292** | 2022 | OpenSSL | c_rehash command injection | Arbitrary code execution | 9.8 |
| **CVE-2022-2068** | 2022 | OpenSSL | Same root as CVE-2022-1292 | Incomplete fix | 9.8 |
| **CVE-2022-2274** | 2022 | OpenSSL | AES-OCB buffer over-read | Heap memory disclosure | 9.1 |
| **CVE-2023-0286** | 2023 | OpenSSL | X.400 + buffer over-read in PKCS7 | Potential memory disclosure | 7.5 |
| **CVE-2023-2650** | 2023 | OpenSSL | DH key check bypass | Small subgroup attack potential | 5.3 |
| **CVE-2023-3817** | 2023 | OpenSSL | Excessive AES-GCM resource consumption | DoS via crafted ciphertext | 5.3 |
| **CVE-2023-5678** | 2023 | OpenSSL | Key generation timing side channel | Potential key recovery | 5.3 |
| **CVE-2024-0727** | 2024 | OpenSSL | PKCS#12 + PBKDF1 weakness | Potential downgrade | 5.3 |
| **CVE-2024-2511** | 2024 | OpenSSL | Unbounded quic stream DoS | Resource exhaustion | 7.5 |
| **CVE-2024-6119** | 2024 | OpenSSL | RFC9260 (SCTP) cert verify DoS | Denial of service | 7.5 |
| **CVE-2015-7547** | 2015 | glibc | getaddrinfo stack buffer overflow | RCE via DNS response | 9.8 |
| **CVE-2008-0166** | 2008 | Debian OpenSSL | Weak RNG — predictable keys | All SSH/DNS keys generated in 2006-2008 | 9.3 |

## Hash Attack Quick Reference

| Attack | Target | Complexity | Condition | Mitigation |
|--------|--------|-----------|-----------|------------|
| **Birthday attack** | Any hash | O(2^(n/2)) | n = hash output bits | Use n/2-bit security minimum (SHA-256 = 128-bit) |
| **MD5 chosen-prefix** | MD5 | 2^18 | Identical prefix collision | **Deprecate MD5**; use SHA-256+ |
| **SHA-1 chosen-prefix** | SHA-1 | 2^63 | SHAttered (practical 2017) | **Deprecate SHA-1**; use SHA-256+ |
| **Length extension** | MD hashes | O(1) | Known H(m) and len(m) | Use HMAC or SHA-3/BLAKE2; never H(k‖m) |
| **Double-hash collision** | H(H(m)) | Same as birthday | If H is collision-resistant | For Merkle trees: use H(0x01‖left‖right) |
| **Duplicate certificate** | MD5 | Practical | Rogue CA via chosen-prefix | Certificate Transparency; SHA-256 CSP |
| **Nostradamus** | Any hash | O(2^n) | Precommit to hash, find later | Not mitigated by stronger hash alone |

## Key Exchange & Authentication Quick Reference

| Protocol | Key Exchange | Forward Secrecy | Quantum-Safe | Status |
|----------|-------------|-----------------|-------------|--------|
| TLS 1.2 RSA | RSA key transport | ❌ | ❌ | Deprecated |
| TLS 1.2 DHE | Finite-field DH | ✅ | ❌ | Use ≥2048-bit |
| TLS 1.2 ECDHE | P-256, P-384 | ✅ | ❌ | Standard; prefer X25519 |
| TLS 1.3 | X25519, P-256, P-384 | ✅ (mandatory) | ❌ | Current standard |
| TLS 1.3 hybrid | X25519+ML-KEM-768 | ✅ | ✅ (hybrid) | Emerging; Chrome/Firefox deploying |
| Signal X3DH | Curve25519 | ✅ | ❌ | Deployed |
| WireGuard | Curve25519 | ✅ | ❌ | Deployed |
| IPSec (IKEv2) | DH, ECDH | ✅ | ❌ (hybrid draft) | Add ML-KEM for hybrid |
| SSH | Curve25519, ECDH | ✅ | ❌ | Hybrid draft in progress |

## References

1. Katz, J., Lindell, Y., "Introduction to Modern Cryptography," 3rd edition, CRC Press, 2020. https://www.cs.umd.edu/~jkatz/imc.html
2. NIST FIPS 197, "Advanced Encryption Standard (AES)," November 2001. https://csrc.nist.gov/publications/detail/fips/197/final
3. NIST FIPS 180-4, "Secure Hash Standard (SHS)," August 2015. https://csrc.nist.gov/publications/detail/fips/180/4/final
4. NIST FIPS 202, "SHA-3 Standard," August 2015. https://csrc.nist.gov/publications/detail/fips/202/final
5. NIST FIPS 203, "ML-KEM," August 2024. https://csrc.nist.gov/publications/detail/fips/203/final
6. NIST FIPS 204, "ML-DSA," August 2024. https://csrc.nist.gov/publications/detail/fips/204/final
7. NIST FIPS 205, "SLH-DSA," August 2024. https://csrc.nist.gov/publications/detail/fips/205/final
8. Bleichenbacher, D., "Chosen Ciphertext Attacks Against Protocols Based on RSA Encryption Standard PKCS #1," CRYPTO 1998. https://link.springer.com/chapter/10.1007/BFb0055716
9. Kocher, P., "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems," CRYPTO 1996. https://link.springer.com/chapter/10.1007/3-540-68697-5_6
10. RFC 8446, "TLS 1.3," August 2018. https://www.rfc-editor.org/rfc/rfc8446
11. RFC 5246, "TLS 1.2," August 2008. https://www.rfc-editor.org/rfc/rfc5246
12. OpenSSL Documentation. https://www.openssl.org/docs/
13. NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)," November 2007. https://csrc.nist.gov/publications/detail/sp/800-38d/final
14. NIST SP 800-57 Part 1 Rev. 5, "Recommendation for Key Management," May 2020. https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
15. RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols," June 2018. https://www.rfc-editor.org/rfc/rfc8439
16. Stevens, M., et al., "The First Collision for Full SHA-1," CRYPTO 2017. https://shattered.io/
17. Wang, X., et al., "Collisions for Hash Functions MD4, MD5, HAVAL-128, and RIPEMD," CRYPTO Rump Session, 2004. https://eprint.iacr.org/2004/199