# TLS Protocol Attacks In Depth

> A comprehensive catalog of attacks against the TLS protocol from its earliest versions through 1.3, covering cryptographic protocol flaws, implementation bugs, and downgrade attacks that have shaped the modern TLS landscape.

---

## Table of Contents

1. [BEAST — CBC IV Prediction](#1-beast--cbc-iv-prediction)
2. [CRIME and BREACH — Compression Side Channels](#2-crime-and-breach--compression-side-channels)
3. [Lucky13 — Timing on CBC Padding](#3-lucky13--timing-on-cbc-padding)
4. [Heartbleed — CVE-2014-0160](#4-heartbleed--cve-2014-0160)
5. [POODLE — SSLv3 CBC Padding](#5-poodle--sslv3-cbc-padding)
6. [FREAK — Export-Grade RSA](#6-freak--export-grade-rsa)
7. [Logjam — Export-Grade DH](#7-logjam--export-grade-dh)
8. [DROWN — SSLv2 Cross-Protocol Attack](#8-drown--sslv2-cross-protocol-attack)
9. [Sweet32 — 64-bit Block Cipher Collision](#9-sweet32--64-bit-block-cipher-collision)
10. [ROBOT — Return of Bleichenbacher's Oracle Threat](#10-robot--return-of-bleichenbachers-oracle-threat)
11. [GoldenRSA — ASLR Bypass via RSA Timing](#11-goldenrsa--aslr-bypass-via-rsa-timing)

---

## 1. BEAST — CBC IV Prediction

### 1.1 The Vulnerability

**CVE-2011-3389** — BEAST (Browser Exploit Against SSL/TLS) was demonstrated by Thai Duong and Juliano Rizzo in 2011, based on earlier theoretical work by Möglen and Kocher.

In TLS 1.0, the IV for each CBC-encrypted record is the last ciphertext block of the previous record. This is **predictable** — the attacker knows the IV before choosing the plaintext for the next record. This violates the IND-CPA requirement that the IV be unpredictable.

**Attack model**: The attacker controls some of the plaintext in a request (e.g., via a malicious JavaScript in the victim's browser) and observes the ciphertext. The victim's browser sends HTTPS requests to a target server, and the attacker has a network position to observe the encrypted traffic.

**CBC encryption** in TLS 1.0:

$$C_i = E_K(P_i \oplus C_{i-1})$$

where $C_{i-1}$ is the last ciphertext block of the previous record (predictable IV) and $P_i$ is the plaintext of the current record.

### 1.2 The Attack

The attacker knows $C_{i-1}$ (the IV) before choosing $P_i$. To guess a plaintext byte $g$ at position $j$:

1. Construct $P_i$ such that the target byte at position $j$ is XORed with a known value.
2. Specifically, set $P_i[j] = g \oplus C_{i-1}[j] \oplus C'_{i-1}[j]$, where $C'_{i-1}$ is a chosen reference block.
3. Encrypt $P_i$ and check if the resulting ciphertext matches the expected pattern.

The attacker uses a **chosen-plaintext** vector: they inject JavaScript into the victim's browser that crafts HTTP requests with specific content. By aligning the target secret (e.g., a session cookie) at a predictable block boundary and using the known IV, the attacker can test one byte of the secret per request.

**Complexity**: The attack requires $\sim 2^{12}$ requests per byte (for a 16-byte block cipher) and an average of 128 requests per byte to confirm a guess. For a typical session cookie of 16–32 bytes, the attack requires $\sim 2^4 \times 128 = 2,048$ to $4,096$ requests, achievable in seconds on a modern browser with WebSocket or XHR.

### 1.3 Mitigation

**TLS 1.1+ (RFC 4346, 2006)**: Requires explicit random IVs for each CBC record, breaking the predictability. The IV is prepended to each record as the first 16 bytes, and a fresh random IV is generated for every record.

**1/n-1 split**: A workaround for TLS 1.0 proposed by OpenSSL and adopted by browsers. The first byte of each record is encrypted with the predictable IV, and the remaining $n-1$ bytes are encrypted with a fresh random IV hidden in the first block. This effectively splits the first block into a sacrificial byte and the rest of the plaintext:

```
Record: [random_byte] [plaintext_block_minus_first_byte] [padding]
         ← encrypted with known IV →
                ← encrypted with new IV (from first block) →
```

The attacker can only recover the first byte (which is random), while the remaining bytes are protected by the random IV.

**AEAD modes**: TLS 1.2 with AES-GCM or ChaCha20-Poly1305 eliminates CBC entirely. TLS 1.3 mandates AEAD and removes CBC mode support.

---

## 2. CRIME and BREACH — Compression Side Channels

### 2.1 CRIME (CVE-2012-4929)

CRIME (Compression Ratio Info-leak Made Easy) exploits TLS-level compression (RFC 3749, DEFLATE) to recover secret data (typically session cookies) from encrypted HTTPS traffic.

**Mechanism**: DEFLATE compression works by replacing repeated byte sequences with back-references. If the attacker can control part of the request (e.g., via JavaScript that sets request headers or query parameters), they can observe the compressed size of the encrypted data. If the attacker's controlled data matches part of the secret (e.g., the cookie), the compressed size will be smaller because DEFLATE can back-reference the matching bytes.

**Attack procedure**:
1. The attacker's JavaScript causes the browser to send HTTPS requests to the target site.
2. Each request includes the attacker-controlled string (e.g., `Cookie: session=AAAAA`) alongside the actual cookie.
3. The attacker observes the ciphertext length (which reveals the compressed plaintext length).
4. By varying the attacker-controlled string byte by byte (e.g., `Cookie: session=A`, `Cookie: session=B`, ...), the attacker identifies which value produces the shortest ciphertext, indicating a match with the secret.
5. Repeat for each byte of the secret.

**Compression ratio**: DEFLATE achieves 2:1 to 10:1 compression on typical HTTP data. A single matching byte reduces the compressed size by 1–2 bytes (the back-reference costs 2–3 bits, saving 1–2 bytes). The attacker detects this difference through TLS record length.

**Complexity**: Recovery of a 16-byte cookie requires approximately $128 \times 16 = 2,048$ requests (256 candidate bytes per position, but on average 128 due to ASCII constraints). The entire attack completes in under 2 minutes on a modern browser.

### 2.2 BREACH (CVE-2013-3587)

BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext) extends CRIME to HTTP-level compression (gzip), which is far more widely deployed than TLS-level compression. HTTP responses are compressed with gzip/DEFLATE, and the attacker can manipulate request parameters that appear in the response (e.g., CSRF tokens in HTML forms).

**Key differences from CRIME**:
- CRIME targets TLS compression (rarely enabled; disabled by most browsers after CRIME).
- BREACH targets HTTP compression (enabled by 70%+ of servers for performance).
- BREACH cannot be mitigated by disabling TLS compression alone.

**BREACH attack variants**:
1. **Direct length oracle**: Observe the compressed response length to determine if the secret is in the response.
2. **Distinguishing oracle**: Use two requests — one with the guess and one without — and compare lengths.
3. **Error-based oracle**: Trigger compression differences between valid and invalid secret values (e.g., and-oracle attack where the server echoes the token in an error message).

**Mitigations** (in order of effectiveness):
1. **Disable HTTP compression for responses containing secrets**: Add `Cache-Control: no-transform` or use separate compression for static vs. dynamic content.
2. **Mask secrets**: XOR or randomly prepend/pad secrets with random data before including them in responses.
3. **Length hiding**: Add random padding to responses to obscure the true compressed length.
4. **Rate limiting**: Slow down the attack by limiting request frequency (mitigation, not prevention).

---

## 3. Lucky13 — Timing on CBC Padding

### 3.1 The Attack

Lucky13 (CVE-2013-0169, AlFardan and Paterson, 2013) is a timing side-channel attack on TLS CBC-mode decryption that combines the padding oracle (§01b) with timing analysis.

In TLS 1.0–1.2 with CBC-mode ciphersuites, the server processes a decrypted record in two steps:
1. **Padding check**: Verify PKCS#7 padding validity.
2. **MAC check**: Verify the HMAC over the plaintext (excluding padding).

If the padding is invalid, the server returns a `DECRYPTION_FAILED` alert. If the padding is valid but the MAC is invalid, the server returns a `BAD_RECORD_MAC` alert. Different alert types leak different information about the padding validity — creating a **padding oracle**. Even if the alert types are unified (as mandated by TLS 1.1+, which sends `BAD_RECORD_MAC` for both cases), timing differences remain:

- Invalid padding: The server rejects after the padding check (fast path).
- Valid padding, invalid MAC: The server performs the padding check AND the MAC computation before rejecting (slow path).

The timing difference between these two paths is on the order of microseconds (the time to compute HMAC-SHA256 over the record). Lucky13 amplifies this difference using statistical techniques:

1. Send $\sim 2^{20}$ crafted ciphertexts, varying only the last byte.
2. For each ciphertext, measure the server's response time with nanosecond precision.
3. Histogram the times: ciphertexts with valid padding (but invalid MAC) take longer by $\sim 1\mu s$.
4. Use the timing difference to identify which byte value produces valid padding.
5. This is the Bleichenbacher/Vaudenay padding oracle attack, but using timing instead of error messages.

### 3.2 Practical Impact

For a 16-byte block cipher (AES), recovering one byte requires distinguishing a ~1μs timing difference. With sufficient samples ($\sim 2^{13}$ per byte position), Lucky13 can recover a full TLS record in $\sim 2^{17}$ queries and $\sim 2^{23}$ total timing samples, achievable in hours over a LAN.

**Mitigation**: The correct mitigation is to use constant-time padding and MAC verification:

```c
// VULNERABLE: check padding, then check MAC
int pad_len = plaintext[last_byte];
if (pad_len < 0 || pad_len > block_size) return FAIL;
for (int i = 0; i < pad_len; i++) {
    if (plaintext[total_len - 1 - i] != pad_len) return FAIL;
}
// MAC check (only reached if padding is valid)
return verify_hmac(plaintext, mac_key);

// SECURE: check both padding and MAC in constant time
int pad_len = plaintext[last_byte];
int pad_diff = 0;
int mac_diff = 0;
for (int i = 0; i <= block_size; i++) {
    // Check padding: compare each potential padding position
    pad_diff |= (i < pad_len) ? (plaintext[total_len - 1 - i] ^ pad_len) : 0;
}
// Always compute MAC, even if padding is invalid
mac_diff = compute_hmac(plaintext, mac_key) ^ expected_mac;
// Combine results: if either fails, result is non-zero
return (pad_diff | mac_diff) == 0 ? SUCCESS : FAIL;
```

**OpenSSL mitigation**: OpenSSL implemented the "Lucky13 fix" in versions 1.0.1e+ and 0.9.8y+. The fix adds dummy HMAC computations when padding is invalid, ensuring that both code paths take the same time. However, the implementation is complex and error-prone — several later patches were needed to address residual timing differences (see CVE-2014-0076, CVE-2016-0702).

---

## 4. Heartbleed — CVE-2014-0160

### 4.1 The Bug

Heartbleed is a buffer over-read vulnerability in OpenSSL's TLS heartbeat extension (RFC 6520). The heartbeat extension allows a client and server to exchange "keep-alive" messages without renegotiating the full TLS handshake.

**Heartbeat request format**:
```
Message Type: 1 byte (0x01 = request, 0x02 = response)
Payload Length: 2 bytes (claimed length of the payload)
Payload: variable length (actual data)
Padding: minimum 16 bytes
```

**The bug**: OpenSSL's `dtls1_process_heartbeat()` (and `tls1_process_heartbeat()`) trusted the claimed payload length without verifying it against the actual received data:

```c
// Vulnerable code (OpenSSL 1.0.1–1.0.1f)
unsigned int payload_length = 0;
n2s(pl, payload_length);  // Read claimed length from packet
// BUG: No check that payload_length <= actual received data length
unsigned char *pl = &s->s3->rrec.data[0];  // Pointer to heartbeat data
// ...
buffer = OPENSSL_malloc(1 + 2 + payload_length + padding);
// Copy payload_length bytes starting from pl — may read beyond the buffer
memcpy(buffer, pl, payload_length);  // OVER-READ: reads up to 64KB of memory
```

An attacker sends a heartbeat request with `payload_length = 65535` (0xFFFF) but an actual payload of only 1 byte. OpenSSL copies 65,535 bytes starting from the heartbeat buffer, which includes:
- The 1-byte actual payload
- 65,534 bytes of adjacent process memory

This memory may contain:
- TLS private keys (RSA, ECDSA)
- Session keys
- TLS session tickets
- User passwords transmitted in HTTP headers
- Other applications' data from adjacent heap memory

### 4.2 Exploitation

A single Heartbleed request returns up to 64 KB of memory. By sending repeated requests, an attacker can dump large portions of the process heap:

```python
import socket, struct

def heartbleed_attack(target_ip, target_port):
    """Send a malicious heartbeat request to dump server memory."""
    # Construct TLS ClientHello with heartbeat extension
    # ... (omitted for brevity: standard TLS handshake)
    
    # Malicious heartbeat request: type=1, claimed_length=65535, actual_payload=1 byte
    heartbeat_type = b'\x01'
    payload = b'\x41'  # Single byte: 'A'
    claimed_length = struct.pack('>H', 65535)  # Claim 64KB payload
    heartbeat_request = heartbeat_type + claimed_length + payload
    
    # After completing TLS handshake with heartbeat extension:
    sock.send(tls_record(content_type=24, data=heartbeat_request))
    response = sock.recv(65535 + 5)
    
    # Response contains 64KB of server memory
    leaked_memory = response[5:]  # Skip TLS record header
    return leaked_memory
```

### 4.3 Impact and Aftermath

- **Affected**: OpenSSL 1.0.1 through 1.0.1f. Approximately 17% of HTTPS servers (roughly 500,000) were vulnerable at the time of disclosure (April 7, 2014).
- **Private key theft**: Multiple researchers demonstrated that Heartbleed could extract TLS private keys from server memory. CloudFlare ran a challenge to prove this was possible.
- **Data theft**: Yahoo! reported that user passwords were leaked via Heartbleed. Many other services forced password resets.
- **Financial cost**: Estimated $500M–$1B in patching, key rotation, and certificate revocation costs.

**Patch**: OpenSSL 1.0.1g added a bounds check:

```c
// Fixed code
if (1 + 2 + payload_length + 16 > s->s3->rrec.length) {
    // Invalid: claimed length exceeds actual data
    return 0;  // Silently discard
}
```

**Lesson**: Heartbleed demonstrates why bounds checking is critical in security-critical code. The bug was a simple missing validation — one `if` statement — but its impact was enormous. It also highlighted the risks of monolithic, unchecked C code in security-critical libraries (see the LibreSSL and BoringSSL forks that emerged from this).

---

## 5. POODLE — SSLv3 CBC Padding

### 5.1 The Vulnerability

**CVE-2014-3566** — POODLE (Padding Oracle On Downgraded Legacy Encryption) exploits SSLv3's CBC padding for a downgrade attack combined with a padding oracle.

SSLv3's CBC padding structure is:

$$\text{padding} = \underbrace{0x00 \| 0x00 \| \cdots \| 0x00}_{\text{padding\_length - 1 bytes}} \| \text{padding\_length}$$

The critical weakness: **SSLv3 does not verify the non-final padding bytes**. The padding check only validates the last byte (which indicates the padding length) and ignores whether the preceding bytes are all zeros. This creates a 1-in-256 padding oracle:

1. The attacker sends a crafted ciphertext to the server.
2. If the server accepts the decryption (valid padding), the last byte of the decrypted plaintext equals the padding length (or the MAC check failed with a different error).
3. If the server rejects, the padding is invalid.

### 5.2 Downgrade Attack

Modern clients support TLS 1.0+, but many servers still accept SSLv3 for backward compatibility. The attacker performs a protocol downgrade:

1. The client sends a TLS 1.2 ClientHello.
2. A man-in-the-middle modifies the ClientHello to offer only SSLv3.
3. The server, supporting SSLv3, responds with an SSLv3 ServerHello.
4. The client, falling back to SSLv3, negotiates a weak cipher suite.

### 5.3 Exploitation

The attacker combines the padding oracle with known plaintext (HTTP headers) to recover one byte of the session cookie per 256 requests:

1. The attacker's JavaScript on the victim's browser sends HTTPS requests to the target site.
2. Each request includes a known path (`/`) and the secret session cookie.
3. The attacker manipulates the request path length to align the target cookie byte at the last position of a CBC block.
4. The attacker modifies the ciphertext (CBC bit-flip) so that the decrypted last byte is tested as the padding length.
5. If the server accepts, the last byte decrypted to the padding length, revealing the XOR relationship with the known target byte.

**Complexity**: $256 \times \text{cookie\_length}$ requests. For a 16-byte cookie, this is $\sim 4,096$ requests, achievable in minutes.

**Mitigation**: Disable SSLv3 entirely. Modern browsers (Chrome 40+, Firefox 34+, IE 11+) no longer support SSLv3. Servers should send `ssl_protocols = TLSv1.2 TLSv1.3;` (nginx) or `SSLProtocol -All +TLSv1.2 +TLSv1.3` (Apache).

---

## 6. FREAK — Export-Grade RSA

### 6.1 The Vulnerability

**CVE-2015-0204** — FREAK (Factoring RSA Export Keys) exploits RSA key exchange with export-grade key lengths mandated by 1990s US cryptography export restrictions.

During the Cold War, the US government classified strong cryptography as a munition and restricted its export. Servers outside the US could only use "export-grade" cryptography: RSA with 512-bit keys (and symmetric ciphers with 40-bit keys like RC4-40).

When the export restrictions were lifted (2000), many servers continued to support export cipher suites for backward compatibility:
- `TLS_RSA_EXPORT_WITH_RC4_40_MD5` (512-bit RSA, 40-bit RC4)
- `TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5` (512-bit RSA, 40-bit RC2)

### 6.2 The Attack

A man-in-the-middle forces the client to negotiate an export cipher suite:

1. The client sends a ClientHello with only strong cipher suites.
2. The MITM modifies the ClientHello to include export cipher suites.
3. The server, supporting export suites, responds with a 512-bit RSA key in the ServerKeyExchange.
4. The client, accepting the export key, encrypts the premaster secret with the 512-bit RSA key.
5. The MITM intercepts the encrypted premaster secret and factors the 512-bit RSA key.

**512-bit RSA factoring**: In 2015, factoring a 512-bit RSA modulus required $\sim 7$ days on a cluster of 80 EC2 instances (cost: $\sim \$100$). In 2024, a single server can factor a 512-bit modulus in $\sim 4$ hours using CADO-NFS.

**Client vulnerability**: Many TLS clients (OpenSSL, Apple's SecureTransport, Microsoft's SChannel) accepted export cipher suites even when the client only offered strong suites. The MITM simply added export suites to the ClientHello, and the server's response triggered a fallback to export-grade negotiation.

**Affected**: ~36% of browser connections (as measured in 2015) were vulnerable, including Chrome, Safari, and the default Android browser.

**Mitigation**: Disable all export cipher suites. Use `SSL_OP_NO_EXPORT` in OpenSSL. Modern TLS libraries (OpenSSL 1.0.2+, BoringSSL) reject export cipher suites by default.

---

## 7. Logjam — Export-Grade DH

### 7.1 The Vulnerability

**CVE-2015-4000** — Logjam (Adrian et al., 2015) exploits Diffie-Hellman key exchange with export-grade groups (512-bit DH parameters), similar to FREAK but targeting Diffie-Hellman instead of RSA.

US export restrictions limited DH to 512-bit groups (`TLS_DHE_EXPORT_WITH_DES40_CBC_SHA`). After the restrictions were lifted, many servers continued to accept export DH.

### 7.2 The Attack

**Phase 1: Precomputation**: The attacker precomputes the discrete log for a 512-bit DH group. Using the Number Field Sieve (NFS), this requires $\sim 10^4$ core-hours (achievable in days on a cluster).

After precomputation, individual discrete logs can be computed in $\sim 10$ seconds (the "descent" phase).

**Phase 2: Active MITM**: The attacker performs a downgrade attack:

1. Client sends ClientHello with strong DHE cipher suites.
2. MITM modifies ClientHello to include export DHE suites.
3. Server sends ServerKeyExchange with a 512-bit DH group (from the preinstalled `modp512` group).
4. Client accepts the 512-bit group and sends ClientKeyExchange.
5. MITM computes the discrete log (using precomputation) and derives the session key.

**Impact**: The same precomputation works for all servers using the same 512-bit DH group. Since most servers used the standard `modp512` group (from RFC 2409), a single precomputation enabled attacks against millions of servers.

### 7.3 The 1024-bit Dilemma

Logjam also highlighted the vulnerability of 1024-bit DH groups. The NFS precomputation for a 1024-bit group was estimated at $\sim 10^9$ core-hours (achievable by a nation-state with $\sim \$100$M in resources). After this one-time precomputation, individual discrete logs cost $\sim 10^4$ core-hours.

Since many servers used the same standard 1024 DH groups (`modp1024`, `modp2048`, Oakley Group 2), a single precomputation enables attacks against all servers using that group. The authors estimated that a nation-state could have precomputed `modp1024` by 2015.

**Recommendation**: Use 2048-bit or larger DH groups, or switch to ECDH with Curve25519. Generate unique DH groups per server (or use well-vetted standard groups like those in RFC 7919).

```nginx
# Nginx: Use 2048-bit DH group (minimum)
ssl_dhparam /etc/ssl/dhparam-2048.pem;

# Preferred: Use ECDH with Curve25519
ssl_ecdh_curve X25519:secp384r1;
```

---

## 8. DROWN — SSLv2 Cross-Protocol Attack

### 8.1 The Vulnerability

**CVE-2016-0800** — DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) exploits SSLv2 to attack TLS connections.

Many servers disabled SSLv3 and TLS 1.0 for POODLE and BEAST mitigation but **left SSLv2 enabled** for backward compatibility with very old clients. SSLv2 has fundamental weaknesses:
- No integrity protection on the handshake (enabling active MITM).
- Export-grade cipher suites (40-bit symmetric, 512-bit RSA).
- No certificate chain validation requirements.
- MAC-then-Encrypt instead of Encrypt-then-MAC.

DROWN exploits the fact that the **same RSA key** is used for both SSLv2 and TLS. The attacker uses Bleichenbacher's padding oracle on the SSLv2 side to recover the TLS premaster secret.

### 8.2 General DROWN Attack

**Step 1**: The attacker observes a TLS 1.2 connection using RSA key exchange, capturing the encrypted premaster secret $c = m^e \mod n$.

**Step 2**: The attacker connects to the same server using SSLv2 and submits ciphertexts derived from $c$. SSLv2's weak padding scheme creates a Bleichenbacher-type padding oracle:

- SSLv2 PKCS padding is: $\texttt{0x00} \| \texttt{0x02} \| \text{PKCS\_padding}$ (similar to PKCS#1 v1.5).
- SSLv2 servers respond differently to valid and invalid padding (some return `SSL_PE_NO_CIPHER` vs `SSL_PE_BAD_MAC`).
- Even if the error messages are unified, the SSLv2 handshake timing differs for valid vs. invalid padding.

**Step 3**: Using the Bleichenbacher adaptive chosen-ciphertext attack (see §02a), the attacker recovers $m$ (the TLS premaster secret) in $\sim 2^{20}$ queries.

**Step 4**: With $m$, the attacker derives all session keys and decrypts the TLS traffic.

**Complexity**: $\sim 2^{20}$ SSLv2 connections and $\sim 2^{20}$ TLS connections, achievable in hours on a fast network. The "special DROWN" variant (for servers supporting SSLv2 with export ciphersuites) requires only $\sim 2^{15}$ connections.

**Impact**: DROWN affected 33% of HTTPS servers (including those that had disabled SSLv2 on their main HTTPS port but had a separate SSLv2-enabled service using the same certificate).

**Mitigation**: Disable SSLv2 entirely on all servers and services. Generate separate RSA keys for legacy protocols if SSLv2 cannot be disabled.

```nginx
# Nginx: Disable SSLv2 and SSLv3
ssl_protocols TLSv1.2 TLSv1.3;
```

---

## 9. Sweet32 — 64-bit Block Cipher Collision

### 9.1 The Vulnerability

**CVE-2016-2183** — Sweet32 (Bhargavan and Leurent, 2016) exploits the birthday bound on 64-bit block ciphers (3DES, Blowfish, etc.) in CBC or CTR mode.

For a block cipher with block size $b$ bits, the birthday bound gives a 50% collision probability after encrypting approximately $2^{b/2}$ blocks. For 64-bit block ciphers ($b = 64$):

$$\Pr[\text{collision after } n \text{ blocks}] \approx 1 - e^{-n(n-1)/(2 \cdot 2^b)} \approx 1 - e^{-n^2/2^{65}}$$

For 3DES ($b = 64$), a collision becomes likely after $2^{32}$ blocks $\approx 32$ GB of data. A long-lived TLS connection (e.g., a VPN tunnel) can easily transfer 32 GB.

### 9.2 The Attack

When two ciphertext blocks in CBC mode collide ($C_i = C_j$), the attacker learns:

$$C_i = E_K(P_i \oplus C_{i-1}) = C_j = E_K(P_j \oplus C_{j-1})$$
$$P_i \oplus C_{i-1} = P_j \oplus C_{j-1}$$
$$P_i \oplus P_j = C_{i-1} \oplus C_{j-1}$$

Since $C_{i-1}$ and $C_{j-1}$ are known (they're in the ciphertext), the attacker learns the XOR of two plaintext blocks. For structured data (HTTP, VPN traffic with known headers), this enables statistical plaintext recovery.

**Concrete attack**: An attacker observing a long-lived 3DES TLS connection:
1. Collects $\sim 2^{32}$ ciphertext blocks ($\sim 32$ GB, transferable over a 1 Gbps connection in $\sim 5$ minutes).
2. Identifies collisions (blocks that appear more than once).
3. XORs the preceding blocks to compute $P_i \oplus P_j$ for each collision.
4. Uses known plaintext (HTTP headers, protocol framing) to recover unknown bytes.

**For HTTP over TLS**: The attacker knows the start of each HTTP request (method, path, host header) and can use this as a crib to decrypt additional bytes. Each collision provides 16 bytes of XOR plaintext, and with sufficient known plaintext, the entire plaintext can be recovered.

**Mitigation**: 
- Disable 3DES and all 64-bit block ciphers.
- If 3DES must be used, limit the amount of data encrypted under a single key to $2^{20}$ blocks (16 MB, as recommended by NIST SP 800-38A). After 16 MB, rekey.
- OpenSSL 1.1.0+ automatically renegotiates after `2^20` blocks with 3DES.

---

## 10. ROBOT — Return of Bleichenbacher's Oracle Threat

### 10.1 The Vulnerability

**CVE-2017-17382** (and multiple CVEs) — ROBOT (Return Of Bleichenbacher's Oracle Threat) demonstrated that 19 years after the original Bleichenbacher attack (1998), many TLS implementations still had PKCS#1 v1.5 padding oracle vulnerabilities in their RSA key exchange.

The ROBOT team (Böck, Somorovsky, Young, 2017) tested 170 HTTPS servers and found 11 vulnerable implementations, including:
- **F5 BIG-IP**: Different TLS alert codes for valid vs. invalid PKCS padding (CVE-2017-6167).
- **Cisco ACE**: Error message timing differential.
- **Java JSSE**: Timing side channel in `RSACipher` (CVE-2017-12487).
- **OpenSSL (some versions)**: Nested error handling that leaked padding validity.
- **Citrix NetScaler**: Error code differentiation.
- **FortiGate**: Similar to F5, different alerts for valid vs. invalid padding.

### 10.2 The Attack Variants

ROBOT identified multiple oracle types:

**Type 1 — Direct oracle**: The server returns different TLS alert codes for valid vs. invalid padding. This is the classic Bleichenbacher oracle.

**Type 2 — Timing oracle**: The server takes measurably different time for valid vs. invalid padding. The timing difference can be as small as $10\mu s$ but is amplifiable.

**Type 3 — Side-channel oracle**: The server's behavior differs in other observable ways (e.g., closing the connection, resetting the TCP stream, sending an application-level error).

**Type 4 — Weak oracle**: The oracle has a low signal-to-noise ratio, requiring more queries ($2^{20}+$ instead of $2^{18}$).

For each type, the ROBOT team implemented an optimized Bleichenbacher attack:
1. Batch queries in parallel to reduce wall-clock time.
2. Use statistical amplification for timing-based oracles.
3. Adaptive filtering to eliminate false positives in the padding oracle.

**Results**: The ROBOT team successfully recovered session keys from vulnerable servers in 2–4 hours for a 2048-bit RSA key, using $\sim 2^{18}–2^{20}$ TLS connections.

### 10.3 Why Bleichenbacher Keeps Returning

The root cause of the recurring Bleichenbacher vulnerability is the **complexity of constant-time PKCS#1 v1.5 padding verification**. The correct implementation requires:

1. Constant-time comparison of the padding bytes.
2. Constant-time MAC verification even when padding is invalid.
3. Uniform error codes and timing regardless of whether the padding or MAC failed.

OpenSSL's attempts to implement this produced subtle bugs in 2006, 2014, and 2016, each introducing a different timing side channel. The fundamental problem is that PKCS#1 v1.5 requires embedding padding validation within the TLS record processing, which interacts with error handling, state machines, and timing in complex ways.

**The definitive solution**: Use RSA-OAEP (RSAES-OAEP) for RSA encryption, which performs a single hash comparison over the entire decrypted block. OAEP's padding verification is inherently constant-time because it rejects invalid padding in one step, with no conditional branching that depends on the padding content. TLS 1.3 removed RSA key exchange entirely, mandating (EC)DHE key establishment.

---

## 11. GoldenRSA — ASLR Bypass via RSA Timing

### 11.1 The Vulnerability

**GoldenRSA** (Yarom, Genkin, Heninger, 2016) is not a cryptographic attack per se but demonstrates how RSA timing side channels can be used for ASLR (Address Space Layout Randomization) bypass, enabling further exploitation.

The attack exploits timing variations in OpenSSL's RSA modular exponentiation implementation. Even with blinding countermeasures (see §02a), the Montgomery multiplication algorithm has data-dependent timing modulo the RSA modulus, which leaks information about the modulus's alignment in memory and the exponent's Hamming weight.

### 11.2 ASLR Deobfuscation via RSA

ASLR randomizes the base addresses of shared libraries, stack, and heap. The entropy per 64-bit Linux system is:
- Stack: 22 bits of randomness ($2^{22}$ possible positions).
- Heap: 13 bits.
- Shared libraries (via PIE): 28 bits.

GoldenRSA shows that RSA modular exponentiation timing (measured over the network) leaks the modulus's memory alignment. Since the modulus is stored in a fixed offset within the OpenSSL `RSA` structure, and the `RSA` structure is allocated on the heap, the modulus's alignment reveals the heap base address — effectively reducing ASLR entropy.

**Attack procedure**:
1. Measure RSA decryption time for many ciphertexts.
2. The timing varies based on the number of Montgomery reduction steps, which depends on the modulus's byte alignment.
3. Statistical analysis of timing distributions reveals the modulus's alignment modulo 16 bytes.
4. This alignment constrains the heap address space, reducing the ASLR entropy from 13 bits to $\sim 9$ bits.
5. Brute-force the remaining 512 possible heap positions.

### 11.3 Relations to Other Attacks

GoldenRSA is not an isolated technique — it's part of a broader class of timing-based deobfuscation attacks:
- **Cache timing attacks** (Prime+Probe, Flush+Reload) on AES and RSA recover key material and ASLR information.
- **TLB timing attacks** reveal memory page offsets.
- **Branch prediction timing** leaks control flow information.

These side channels are particularly dangerous in cloud environments where virtual machines share physical hardware. Cross-VM timing attacks can recover RSA keys (see §04a) and ASLR offsets from neighboring VMs.

---

## Cross-References

- **§01a** — Cryptographic fundamentals: CBC mode, GCM, CTR mode definitions
- **§01b** — Symmetric attacks: CBC bit-flipping, padding oracle (Vaudenay), nonce reuse in CTR/GCM, birthday attacks
- **§02a** — RSA/ECC attacks: Bleichenbacher (applied to TLS in ROBOT, DROWN), timing attacks on RSA
- **§02b** — Hash/MAC attacks: collision attacks (MD5 in TLS certificate chains)
- **§03b** — PKI/certificate attacks: CA compromise, certificate chain validation failures
- **§04a** — Side-channel attacks: cache timing (Flush+Reload on AES), power analysis on RSA
- **§04b** — Hardware attacks: TPM vulnerabilities, HSM side channels
- **§06** — Case studies: Heartbleed, DROWN, ROBOT

## References

1. RFC 8446, "The Transport Layer Security (TLS) Protocol Version 1.3," August 2018. https://www.rfc-editor.org/rfc/rfc8446
2. RFC 5246, "The Transport Layer Security (TLS) Protocol Version 1.2," August 2008. https://www.rfc-editor.org/rfc/rfc5246
3. Duong, T., Rizzo, J., "Here Come The ⊕ Ninjas," 2011 (BEAST). CVE-2011-3389. https://www.beastAttack.com/
4. Rizzo, J., Duong, T., "The CRIME Attack," 2012. CVE-2012-4929. https://www.ieee-security.org/
5. AlFardan, N., Paterson, K.G., "Lucky Thirteen: Breaking the TLS and DTLS Protocols," IEEE S&P 2013. CVE-2013-0169. https://www.ieee-security.org/TC/SP2013/papers/4977a026.pdf
6. CVE-2014-0160, "OpenSSL Heartbeat Information Disclosure (Heartbleed)," April 2014. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
7. Möller, B., Duong, T., Kotowicz, K., "This POODLE Bites: Exploiting the SSLv3 Fallback," 2014. CVE-2014-3566. https://www.openssl.org/~bodo/ssl-poodle.pdf
8. Beurdouche, B., Bhargavan, K., Delignat-Lavaud, A., "FREAK: Factoring RSA_EXPORT Keys," 2015. CVE-2015-0204. https://freakAttack.com/
9. Adrian, D., Bhargavan, K., Durumeric, Z., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice," CCS 2015. CVE-2015-4000. https://weakdh.org/
10. Aviram, N., Schinzel, S., "DROWN: Breaking TLS with SSLv2," USENIX Security 2016. CVE-2016-0800. https://drownAttack.com/
11. Bhargavan, K., Leurent, G., "On the Practical (In-) Security of 64-bit Block Ciphers," CCS 2016. CVE-2016-2183. https://sweet32.info/
12. Böck, H., Somorovsky, J., Young, C., "Return Of Bleichenbacher's Oracle Threat (ROBOT)," USENIX Security 2018. https://robotAttack.com/
13. Bleichenbacher, D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1," CRYPTO 1998. https://link.springer.com/chapter/10.1007/BFb0055716
14. Yarom, Y., Genkin, G., Heninger, N., "CacheBleed: A Last-Level Cache Side-Channel Attack," 2016. https://cachebleedAttack.com/
15. RFC 4346, "The Transport Layer Security (TLS) Protocol Version 1.1," April 2006. https://www.rfc-editor.org/rfc/rfc4346
16. RFC 6101, "The Secure Sockets Layer (SSL) Protocol Version 3.0," August 2011. https://www.rfc-editor.org/rfc/rfc6101