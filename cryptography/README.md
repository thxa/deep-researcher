# Cryptography & Crypto Attacks

A comprehensive track covering the full spectrum of cryptographic attacks — from symmetric cipher cryptanalysis and RSA/ECC exploitation through hash collisions, TLS protocol weaknesses, side-channel analysis, hardware attaks, and post-quantum transitions. Modern security depends on correct cryptographic implementation far more than on algorithmic novelty, and this track maps the entire attack surface where theory meets deployed reality.

- **Difficulty**: 🔴 Advanced
- **Estimated reading time**: ~14 hours (~235,000 words across 20 documents)
- **Prerequisites**: Discrete mathematics, modular arithmetic, probability theory, linear algebra, basic group/field theory; working knowledge of C/Python; familiarity with network protocols and TLS

## Reading Order

| # | File | Topic | Est. Time |
|---|------|-------|-----------|
| 01a | [01a_symmetric_crypto.md](docs/01a_symmetric_crypto.md) | Symmetric cryptography fundamentals — block ciphers, stream ciphers, modes of operation, key schedule | ~45 min |
| 01b | [01b_symmetric_attacks.md](docs/01b_symmetric_attacks.md) | Symmetric attacks — differential/linear cryptanalysis, meet-in-the-middle, related-key, slide, padding oracle, Lucky13 | ~50 min |
| 02a | [02a_rsa.md](docs/02a_rsa.md) | RSA internals — key generation, OAEP, CRT optimization, PKCS#1 v1.5, textbook RSA vulnerabilities | ~50 min |
| 02b | [02b_rsa_attacks.md](docs/02b_rsa_attacks.md) | RSA attacks — Bleichenbacher, Coppersmith, Wiener, Fermat, Hastad, CCA, timing, share cracking | ~55 min |
| 03a | [03a_ecc.md](docs/03a_ecc.md) | Elliptic curve cryptography — group law, Weierstrass/Edwards curves, point compression, ECDSA/EdDSA, key exchange | ~50 min |
| 03b | [03b_ecc_attacks.md](docs/03b_ecc_attacks.md) | ECC attacks — invalid curve, twist security, subgroup confinement, side channels, Bitcoin nonce bias, Curve25519 validation | ~50 min |
| 04a | [04a_hash_functions.md](docs/04a_hash_functions.md) | Hash functions — Merkle-Damgård, sponge construction, SHA-2/SHA-3/BLAKE2, length extension, HMAC | ~45 min |
| 04b | [04b_hash_attacks.md](docs/04b_hash_attacks.md) | Hash attacks — birthday, collision, preimage, MD5/SHA-1 chosen-prefix, length extension, Merkle tree collisions, duplicate certificate | ~50 min |
| 05a | [05a_tls_protocol.md](docs/05a_tls_protocol.md) | TLS protocol — handshake, record layer, cipher suites, key schedule (TLS 1.2/1.3), extensions, session resumption | ~55 min |
| 05b | [05b_tls_attacks.md](docs/05b_tls_attacks.md) | TLS attacks — BEAST, CRIME, Lucky13, POODLE, FREAK, Logjam, Heartbleed, RC4 biases, downgrade, 0-RTT | ~55 min |
| 06a | [06a_pki.md](docs/06a_pki.md) | PKI & certificate infrastructure — X.509, chain validation, CRL/OCSP, CT, certificate authorities, trust anchors | ~45 min |
| 06b | [06b_pki_attacks.md](docs/06b_pki_attacks.md) | PKI attacks — fraudulent CA (DigiNotar), cross-signing abuse, OCSP stapling bypass, CT evasion, sub-CA compromise, name constraints | ~45 min |
| 07a | [07a_side_channels.md](docs/07a_side_channels.md) | Side-channel attacks — timing, cache (Flush+Reload, Prime+Probe), power, EM, acoustic, port contention | ~50 min |
| 07b | [07b_microarchitectural.md](docs/07b_microarchitectural.md) | Microarchitectural attacks — Spectre, Meltdown, Foreshadow, Microscope, SGX vulnerabilities, transient execution | ~50 min |
| 08a | [08a_hardware_attacks.md](docs/08a_hardware_attacks.md) | Hardware attacks — fault injection (glitch, EM, laser), power analysis (SPA/DPA), probing, cold boot, JTAG/SWD | ~45 min |
| 08b | [08b_implementation_attacks.md](docs/08b_implementation_attacks.md) | Implementation attacks — ROCA, Coppersmith in practice, key wrap, constant-time failures, RNG disasters (Dual EC, Debian) | ~45 min |
| 09a | [09a_post_quantum.md](docs/09a_post_quantum.md) | Post-quantum cryptography — lattice-based (Kyber/ML-KEM, Dilithium/ML-DSA), code-based, hash-based (SPHINCS+), isogeny (SIDH fall) | ~55 min |
| 09b | [09b_pqc_migration.md](docs/09b_pqc_migration.md) | PQC migration — NIST standards, hybrid deployment, key size/latency/performance tradeoffs, crypto-agile architecture | ~45 min |
| 10a | [10a_crypto_engineering.md](docs/10a_crypto_engineering.md) | Crypto engineering — libcrypto APIs, key management, HSMs, threshold crypto, secure enclaves, fuzzing, constant-time verification | ~50 min |
| 10b | [10b_case_studies.md](docs/10b_case_studies.md) | Case studies — Enigma, Dual EC DRBG, ROCA, SolarWinds, DigiNotar, Signal Double Ratchet, Intel SGX, Cloudflare nonce-m69 | ~55 min |

## Prerequisites

### Required
- **Number theory**: modular arithmetic, Euler's theorem, CRT, finite fields
- **Probability & statistics**: birthday bound, Bayes' theorem, statistical distributions
- **Linear algebra**: matrix operations, vector spaces over GF(2)
- **Programming**: C (for constant-time analysis), Python (for cryptanalysis scripts)

### Recommended
- **Algebra**: group theory, ring theory, elliptic curves over finite fields
- **Information theory**: entropy, Shannon's theorem, channel capacity
- **Network protocols**: TCP/IP, X.509, ASN.1, DER encoding

## Learning Paths

### Crypto Engineer
Focus on correct implementation and deployment: 01a → 01b → 04a → 05a → 06a → 08b → 09a → 09b → 10a → 10b
*Goal*: Build and ship cryptographic systems that resist real-world attacks.

### Security Auditor
Focus on finding vulnerabilities in deployed crypto: 01b → 02b → 03b → 04b → 05b → 06b → 07a → 08a → 08b → CHEATSHEET
*Goal*: Audit cryptographic implementations for known attack classes and misconfigurations.

### CTF Player
Focus on exploitable weaknesses and practical attacks: 01b → 02a → 02b → 03b → 04b → 05b → 07a → 08b → CHEATSHEET
*Goal*: Solve crypto CTF challenges using classical and modern attack techniques.

### Researcher
Focus on novel cryptography and emerging threats: 01a → 02a → 03a → 04a → 07b → 08a → 09a → 09b → 10a → 10b
*Goal*: Contribute to cryptographic research, PQC, and next-generation protocol design.

## Related Tracks

- **Chromium Architecture & Vulnerability** — [../Chromium_Architecture_and_Vulnerability/](../Chromium_Architecture_and_Vulnerability/) — Chromium's TLS stack (BoringSSL), certificate verification, and HPKP implementation
- **macOS** — [../MacOS/](../MacOS/) — Apple Secure Enclave, Keychain Services, and Apple's PQC migration strategy
- **Linux Kernel** — [../linux_kernel/](../linux_kernel/) — Kernel TLS (kTLS), AF_ALG crypto API, and kernel-side implementation of AES-NI/SHA-NI
- **Web Security** — [../web_security/](../web_security/) — TLS in browsers, mixed content, HSTS, CSP, and web PKI
- **Network Security** — [../network_security/](../network_security/) — IPsec, WireGuard, TLS interception, and network-layer cryptographic protocols
- **IoT Security** — [../iot_security/](../iot_security/) — Embedded crypto hardware, lightweight ciphers, and constrained-device key management
- **Supply Chain Security** — [../supply_chain_security/](../supply_chain_security/) — Code-signing PKI, SBOM integrity, and package signature verification

## References

1. Katz, J., Lindell, Y., "Introduction to Modern Cryptography," 3rd edition, CRC Press, 2020. https://www.cs.umd.edu/~jkatz/imc.html
2. NIST FIPS 180-4, "Secure Hash Standard (SHS)," August 2015. https://csrc.nist.gov/publications/detail/fips/180/4/final
3. NIST FIPS 197, "Advanced Encryption Standard (AES)," November 2001. https://csrc.nist.gov/publications/detail/fips/197/final
4. NIST FIPS 202, "SHA-3 Standard," August 2015. https://csrc.nist.gov/publications/detail/fips/202/final
5. NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)," August 2024. https://csrc.nist.gov/pubs/fips/203/final
6. NIST FIPS 204, "Module-Lattice-Based Digital Signature Algorithm (ML-DSA)," August 2024. https://csrc.nist.gov/pubs/fips/204/final
7. NIST FIPS 205, "Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)," August 2024. https://csrc.nist.gov/pubs/fips/205/final
8. Bleichenbacher, D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1," CRYPTO 1998. https://link.springer.com/chapter/10.1007/BFb0055716
9. Kocher, P., "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems," CRYPTO 1996. https://link.springer.com/chapter/10.1007/3-540-68697-5_6
10. RFC 8446, "The Transport Layer Security (TLS) Protocol Version 1.3," August 2018. https://www.rfc-editor.org/rfc/rfc8446
11. OpenSSL Documentation. https://www.openssl.org/docs/
12. Stevens, M., et al., "The First Collision for Full SHA-1," CRYPTO 2017 (SHAttered). https://shattered.io/
13. Carlini, N., Wagner, D., "Towards Evaluating the Robustness of Neural Networks," IEEE S&P 2017. https://arxiv.org/abs/1608.04644
14. Goodfellow, I., et al., "Explaining and Harnessing Adversarial Examples," ICLR 2015. https://arxiv.org/abs/1412.6572
15. NIST SP 800-57 Part 1 Rev. 5, "Recommendation for Key Management," May 2020. https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-9231: SM2 timing side-channel in OpenSSL allows private-key recovery on 64-bit ARM** *(2025-09)* — Disclosed September 30, 2025, CVE-2025-9231 (CVSS 6.5) is a timing side-channel in SM2 signature computations on 64-bit ARM platforms in OpenSSL 3.0 through 3.5 that could allow an attacker to recover the private key. It was fixed alongside CVE-2025-9230 (CMS PWRI out-of-bounds read/write) and CVE-2025-9232; FIPS modules are unaffected since SM2 is not FIPS-approved. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-9231)

### Incidents & In-the-Wild Exploitation

- **Post-quantum key agreement crosses 50% of human web traffic (Cloudflare 2025 state-of-PQ)** *(2025-10)* — Per Cloudflare's October 28, 2025 report, over half of human-initiated TLS connections to its network now use hybrid post-quantum key agreement (X25519MLKEM768), and 39% of the top 100,000 domains support post-quantum connections, while only 3.7% of origin servers do. Milestones cited include Chrome enabling PQC by default on desktop and Android, OpenSSL enabling it by default (April 2025), and Apple beginning rollout with iOS/macOS 26 (October 2025); PQC certificates/signatures remain the major unsolved migration challenge. [[source]](https://blog.cloudflare.com/pq-2025/)

### Techniques

- **Signal Triple Ratchet / Sparse Post-Quantum Ratchet (SPQR) adds continuous PQC to the message ratchet** *(2025-10)* — On October 2, 2025, Signal announced the Sparse Post-Quantum Ratchet (SPQR), which runs alongside the existing Double Ratchet to form a Triple Ratchet that provides continuous post-quantum forward secrecy and post-compromise security throughout a conversation, using ML-KEM-768 with a bandwidth-saving 'ML-KEM Braid' chunking technique. This goes beyond the earlier PQXDH upgrade (handshake-only) already in the knowledge base, and was built on research published at Eurocrypt 2025 and USENIX Security 2025. [[source]](https://signal.org/blog/spqr/)

### Research

- **SLAP and FLOP: speculative side-channel attacks on Apple Silicon load predictors** *(2025-01)* — Researchers from Georgia Tech and Ruhr University Bochum disclosed SLAP (exploiting the Load Address Predictor, M2/A15 and later) and FLOP (exploiting the Load Value Predictor, M3/A17 and later) in January 2025. The attacks break browser site-isolation under speculative execution, enabling cross-origin data recovery demonstrated end-to-end against Safari (e.g. recovering email content). SLAP appeared at IEEE S&P 2025 and FLOP at USENIX Security 2025. [[source]](https://predictors.fail/)

### Tools

- **OpenSSL 3.5.0 LTS ships native ML-KEM, ML-DSA and SLH-DSA with PQC hybrid TLS by default** *(2025-04)* — OpenSSL 3.5.0, released April 8-9, 2025 as a long-term support release (supported until April 2030), is the first OpenSSL to add native implementations of the NIST PQC standards ML-KEM, ML-DSA and SLH-DSA. It changes the default TLS keyshares to offer X25519MLKEM768 and X25519, enabling hybrid post-quantum key agreement by default, and also adds server-side QUIC (RFC 9000) support. [[source]](https://openssl-library.org/post/2025-04-08-openssl-35-final-release/)

### Standards & Frameworks

- **NIST selects HQC as fifth PQC algorithm (code-based KEM backup to ML-KEM)** *(2025-03)* — On March 11, 2025, NIST selected HQC (Hamming Quasi-Cyclic) as a fifth post-quantum standard, a code-based key encapsulation mechanism to serve as a backup for the lattice-based ML-KEM (FIPS 203) in case lattice cryptography is broken. NIST plans a draft standard around 2026 with a finalized standard expected in 2027. This is a distinct mathematical foundation (error-correcting codes) from the lattice-based standards already documented in the knowledge base. [[source]](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption)
