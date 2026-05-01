# PKI and Certificate Attacks

> A systematic analysis of vulnerabilities in Public Key Infrastructure: from certificate chain validation failures and CA compromise to CRL/OCSP weaknesses, certificate pinning bypass, and the emerging landscape of Certificate Transparency and encrypted client hello.

---

## Table of Contents

1. [Certificate Chain Validation Failures](#1-certificate-chain-validation-failures)
2. [CRL and OCSP Vulnerabilities](#2-crl-and-ocsp-vulnerabilities)
3. [Certificate Pinning Bypass](#3-certificate-pinning-bypass)
4. [Cross-Signing Attacks](#4-cross-signing-attacks)
5. [CA Compromise — DigiNotar](#5-ca-compromise--diginotar)
6. [Subdomain Takeover via Certificate Misissuance](#6-subdomain-takeover-via-certificate-misissuance)
7. [ACME Protocol Security and Let's Encrypt Issues](#7-acme-protocol-security-and-lets-encrypt-issues)
8. [Self-Signed Certificate Trust](#8-self-signed-certificate-trust)
9. [Certificate Transparency and Its Failures](#9-certificate-transparency-and-its-failures)
10. [SNI Leakage, ESNI, and ECH](#10-sni-leakage-esni-and-ech)

---

## 1. Certificate Chain Validation Failures

### 1.1 The Certificate Chain Model

X.509 PKI establishes trust through **certificate chains**. A certificate chain starts with a **root CA** (self-signed and trusted by the client) and extends through **intermediate CAs** to the **end-entity (leaf) certificate**. Each certificate in the chain is signed by the issuer of the certificate above it:

```
Root CA (self-signed, trusted)
  └── Intermediate CA (signed by Root CA)
        └── Server Certificate (signed by Intermediate CA)
```

Validation requires:
1. **Chain building**: Construct a chain from the leaf certificate to a trusted root.
2. **Signature verification**: Verify each certificate's signature against its issuer's public key.
3. **Validity period**: Check that each certificate is within its `notBefore`/`notAfter` dates.
4. **Purpose (EKU)**: Verify that each certificate's Extended Key Usage allows the intended purpose (e.g., TLS server authentication).
5. **Revocation**: Check that no certificate in the chain is revoked (CRL or OCSP).
6. **Name constraints**: Verify that the certificate's subject name matches the requested identity.

Failures at any of these steps can lead to catastrophic trust failures.

### 1.2 Common Validation Failures

**Failure to verify the full chain**: Many implementations verify the leaf certificate's signature against the intermediate CA's key, but fail to verify the intermediate's signature against the root's key. This allows an attacker to present a self-signed "intermediate CA" certificate that the client accepts.

**CVE-2002-0862 (Microsoft CryptoAPI)**: Windows' `WinVerifyTrust` function skipped revocation checking if the certificate chain could not be built to a trusted root. An attacker could present an untrusted root and bypass revocation entirely.

**CVE-2013-0726 (Java JSSE)**: Java's `X509TrustManager` in some versions did not verify the `basicConstraints` extension of intermediate certificates. An attacker could create a leaf certificate that also functioned as a CA, issuing rogue certificates for any domain.

**CVE-2008-5161 (OpenSSL)**: OpenSSL did not properly handle a `NULL` character in the Common Name (CN) field of a certificate. For example, `www.paypal.com\0.evil.com` would match against `www.paypal.com` in some validation routines. The `\0` (null byte) terminated the string comparison, making the certificate appear to be for `www.paypal.com`.

```python
# Demonstration of NULL byte injection in CN
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Craft a certificate with NULL byte in CN
name = x509.Name([
    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 
                       "www.paypal.com\x00.evil.com")
])
# Some C libraries (older OpenSSL) would compare this as "www.paypal.com"
```

**Flaw in name validation**: Many TLS implementations performed name matching incorrectly:
- Checking only the Common Name (CN) instead of the Subject Alternative Name (SAN) field. RFC 6125 mandates that the SAN is the authoritative field, and CN should be checked only if SAN is absent.
- Matching against wildcard certificates incorrectly. `*.example.com` should match `sub.example.com` but NOT `sub.sub.example.com` and NOT `example.com`. Many implementations accepted `example.com` as a match for `*.example.com`.
- Case-insensitive matching failures. Domain names are case-insensitive (RFC 4343), but some implementations performed case-sensitive comparison.

### 1.3 The Chain of Trust Problem

The fundamental issue with X.509 PKI is that **any trusted root CA can issue certificates for any domain**. There are over 100 trusted root CAs in most browser trust stores, and each can delegate to intermediate CAs, creating hundreds of potential issuers. This creates a large attack surface:

- Any CA can issue a certificate for `google.com`, even though Google has no relationship with most CAs.
- A compromise of any CA (or any of its intermediates) enables issuance of trusted certificates for any domain.
- National CAs (e.g., China Internet Network Information Center — CNNIC, TurkTrust) are trusted by all browsers but operate under different legal and security regimes.

**CVE-2011-0611 (Comodo HMAC CA)**: In March 2011, an affiliate of Comodo (a trusted CA) was compromised, and the attacker issued fraudulent certificates for `google.com`, `login.live.com`, `mail.google.com`, `addons.mozilla.org`, and `login.skype.com`. The certificates were detected and revoked within hours, but the incident highlighted the systemic risk of having many trusted CAs.

---

## 2. CRL and OCSP Vulnerabilities

### 2.1 Certificate Revocation Lists (CRLs)

CRLs (RFC 5280) are signed lists of revoked certificate serial numbers, published by CAs at regular intervals. Clients download the CRL and check whether the presented certificate's serial number appears in the list.

**Problems with CRLs**:
1. **Latency**: CRLs are published on a schedule (hourly, daily, or weekly). A revoked certificate remains trusted until the next CRL update.
2. **Size**: CRLs grow monotonically. A large CA (e.g., Symantec) may have millions of revoked certificates, producing CRLs of 50+ MB.
3. **Availability**: If the CRL distribution point is unreachable, clients must decide whether to fail open (accept the certificate) or fail closed (reject it). Most implementations fail open, rendering CRLs ineffective.
4. **Privacy**: Downloading a CRL from the CA reveals which CA the client trusts, leaking information about the client's browsing.
5. **Caching**: CRLs are cached locally with a `nextUpdate` timestamp. If the cache is stale, the client may accept a recently revoked certificate.

### 2.2 OCSP (Online Certificate Status Protocol)

OCSP (RFC 6960) allows clients to query the CA in real-time for the revocation status of a specific certificate. The client sends the certificate's serial number to an OCSP responder, which returns a signed response: `good`, `revoked`, or `unknown`.

**Problems with OCSP**:

1. **OCSP responder availability**: If the responder is down, the client must fail open or closed. Most browsers fail open (hard-fail is considered too disruptive).

2. **Privacy**: OCSP queries reveal the website the client is visiting to the CA (the serial number identifies the certificate, and the OCSP responder URL identifies the CA). This is a significant privacy concern.

3. **OCSP latency**: Adding an RTT to the OCSP responder for each TLS connection adds 50–200ms, degrading performance.

4. **OCSP replay attacks**: An attacker who intercepts an OCSP `good` response can replay it after the certificate is revoked. The response includes a `nextUpdate` timestamp, but implementations may accept stale responses.

5. **OCSP Stapling (TLS Certificate Status Request extension, RFC 6066)**: The server includes the OCSP response in the TLS handshake, eliminating the client's need to query the OCSP responder separately. This addresses the latency and privacy issues. However, stapling is optional, and many servers do not support it.

6. **Must-Staple (RFC 7633)**: A certificate extension that requires the server to staple an OCSP response. If a client encounters a Must-Staple certificate without a stapled OCSP response, it MUST reject the connection. This prevents downgrade attacks where an attacker prevents the server from stapling.

```nginx
# Enable OCSP stapling in Nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
```

### 2.3 Soft-Fail vs Hard-Fail

**Soft-fail** (current browser behavior): If the OCSP responder is unreachable, accept the certificate. This makes revocation ineffective — an attacker can simply block the OCSP responder (e.g., via DNS poisoning or network filtering) to prevent revocation checks.

**Hard-fail** (theoretically correct but impractical): If the OCSP responder is unreachable, reject the certificate. This makes revocation effective but causes breakage when OCSP responders have outages (which happens regularly).

**Chrome's CRLSet approach**: Chrome maintains a locally-cached, push-updated list of revoked certificates (CRLSet), distributed via Chrome's update mechanism. CRLSets contain a subset of all revoked certificates (primarily high-severity revocations) and are limited to ~5 MB. This provides best-effort revocation checking without network latency, but it's not comprehensive — most revoked certificates are not in the CRLSet.

**Mozilla's OneCRL and Intermediate Preload**: Firefox maintains OneCRL (a blocklist of revoked intermediate CA certificates) and an Intermediate Certificate Preload list (a set of intermediates verified by Mozilla). Revocation checking is performed via OCSP stapling or CRLSet-like mechanisms, not real-time OCSP queries.

---

## 3. Certificate Pinning Bypass

### 3.1 What Is Certificate Pinning?

Certificate pinning (or public key pinning) restricts the set of CAs that are trusted to issue certificates for a specific domain. Instead of trusting all root CAs, the client pins one or more specific certificates or public keys.

**Types of pinning**:
- **SubjectPublicKeyInfo (SPKI) pin**: Pin the hash of a specific public key (most common).
- **Certificate pin**: Pin the hash of a specific X.509 certificate.
- **CA pin**: Pin the CA's public key, restricting which CAs can issue certificates for the domain.

**HTTP Public Key Pinning (HPKP, RFC 7469)**: Deprecated in 2018, HPKP was an HTTP header that specified which public keys were trusted for a domain:

```
Public-Key-Pins: pin-sha256="base64=="; pin-sha256="base64=="; max-age=5184000
```

HPKP was deprecated because it caused more harm than good (see §3.2).

### 3.2 HPKP Failures

**Self-induced DoS**: If a CA's key is rotated (a normal operational event) and the HPKP header hasn't been updated, legitimate certificates are rejected. This happened to multiple high-traffic websites that set long `max-age` values and then changed CAs.

**Hostile pinning**: An attacker with the ability to inject HPKP headers (via XSS, MITM, or compromised CDN) could pin a domain to their own key, making the legitimate site unreachable after the `max-age` expires.

**Irrecoverable lockout**: If all pinned keys are lost (e.g., due to hardware failure or natural disaster), the domain becomes permanently inaccessible until the `max-age` expires. There is no recovery mechanism in the HPKP specification.

HPKP was removed from Chrome in Chrome 72 (2019) and deprecated in Firefox. No modern browser supports it.

### 3.3 Android Certificate Pinning Bypass

Android supports certificate pinning via the `Network Security Configuration` XML file (API 24+) and programmatically via `OkHttp CertificatePinner`.

**Bypass techniques**:

1. **Frida hooking**: Use Frida to hook the SSL verification methods and bypass pinning checks:

```javascript
// Frida script to bypass OkHttp certificate pinning
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
            // Do nothing — bypass pinning
            console.log('[+] Bypassed pinning for: ' + hostname);
        };
});
```

2. **SSLUnpinning module**: The `frida-ssl-unpinning` tool automatically hooks common pinning implementations (OkHttp, TrustManager, X509TrustManager) across multiple Android versions.

3. **Custom trust store**: On rooted devices, modify the system trust store by adding the attacker's CA certificate to `/system/etc/security/cacerts/`.

4. **APK modification**: Decompile the APK, remove or modify the pinning configuration in `network_security_config.xml`, recompile, and reinstall.

5. **Binary patching**: Use tools like `apktool` to decompile, `jadx` to locate the pinning code, and `smali` to patch the verification methods to always return `true`.

### 3.4 iOS Certificate Pinning Bypass

iOS applications can implement pinning via `URLSession` delegate methods or third-party libraries (Alamofire, TrustKit):

1. **SSL Kill Switch 2**: A Cydia Substrate extension that hooks `SSLSetSessionOption` and `SSLCreateContext` to disable certificate validation system-wide.

2. **Frida hooking on iOS**:
```javascript
// Bypass iOS pinning
if (ObjC.available) {
    var validExtensions = ['trustKit', 'aoInsecureSite'];
    // Hook TrustKit initializer
    var TrustKit = ObjC.classes.TSKTrustKitConfig;
    if (TrustKit) {
        // Override the pinning enforcement
        Interceptor.replace(TrustKit['- init'].implementation, function() {
            return null; // Disable TrustKit
        });
    }
}
```

3. **Binary patching**: Use `objdump` and `ldid` to modify the application binary, patching out the certificate validation calls.

4. **Network Extension proxy**: On jailbroken devices, install a VPN profile that routes traffic through a proxy with a custom CA, bypassing the app's pinning at the OS level.

---

## 4. Cross-Signing Attacks

### 4.1 Cross-Signing Model

A **cross-sign** occurs when two CAs issue certificates for each other's public keys. If Root CA A and Root CA B both sign Root CA B's key, then certificates issued by B are trusted through both A's and B's trust stores:

```
Root CA A (trusted)        Root CA B (trusted)
      |                            |
      v                            v
Cross-signed B-by-A          Cross-signed A-by-B
      |                            |
      v                            v
Intermediate CA B             Intermediate CA A
      |                            |
      v                            v
Server Certificate             Server Certificate
```

This enables interoperability between trust stores and smooth CA transitions. However, it also creates **trust path confusion** and increases the attack surface.

### 4.2 Trust Path Complications

When a certificate has multiple valid trust paths, the client must choose one. Different clients may choose different paths, leading to:

1. **Revocation gaps**: Path A may be revoked while Path B is not. If the client validates Path A, it rejects the certificate; if it validates Path B, it accepts. The certificate's validity depends on which path the client chooses.

2. **Policy differences**: Path A may enforce different EKU (Extended Key Usage) constraints than Path B. A certificate valid for TLS server authentication through Path A may be invalid through Path B.

3. **Name constraint differences**: Path A's root may have name constraints restricting issuance to `*.example.com`, while Path B's root has no constraints. A certificate for `other.com` would be invalid through Path A but valid through Path B.

**CVE-2018-1000001 (OpenSSL)**: OpenSSL's path building algorithm could select a trust path with weaker constraints, allowing certificates that should have been rejected. This was a logic error in the X.509 chain building code.

### 4.3 Cross-Prefix Attack

A **cross-prefix attack** exploits the fact that a CA root certificate is identified by its Subject and Key, not by its Issuer. Two root CAs with the same Subject DN but different keys can both sign the same intermediate certificate, creating two trust paths with different trust anchors.

This is particularly dangerous when:
- A malicious CA creates a root with the same Subject DN as a trusted CA.
- The malicious CA's root is not trusted by the client.
- However, the malicious CA's root can issue certificates that, when validated through the legitimate trust path, appear valid.

This attack is prevented by including the Authority Key Identifier (AKI) extension in certificates, which binds the certificate to a specific issuer key. Without AKI, the client has no way to determine which root key signed the intermediate.

---

## 5. CA Compromise — DigiNotar

### 5.1 The Attack

**DigiNotar CA compromise (August–September 2011)** is the most significant CA compromise in history. An attacker (attributed to Iranian state actors) compromised DigiNotar, a Dutch CA trusted by all major browsers, and issued fraudulent certificates for hundreds of domains.

**Timeline**:
- **June 2011**: Attacker compromises DigiNotar's CA infrastructure.
- **July 2011**: Fraudulent certificates are issued for `*.google.com`, `*.google.nl`, `*.microsoft.com`, `*.mozilla.org`, `*.wordpress.org`, and many others.
- **August 2011**: Google detects unauthorized certificates for `*.google.com` in the wild (used for MITM attacks on Iranian citizens accessing Gmail).
- **August 30, 2011**: DigiNotar acknowledges the compromise.
- **September 2011**: All major browsers remove DigiNotar from their trust stores. DigiNotar files for bankruptcy.

**Attack details**:
- The attacker gained root access to DigiNotar's CA servers through an unpatched IIS vulnerability.
- Over 500 fraudulent certificates were issued, including wildcard certificates for major domains.
- The certificates were used for MITM attacks against Iranian citizens, redirecting HTTPS traffic to servers controlled by the attacker.
- DigiNotar's OCSP responder was also compromised, returning `good` status for the fraudulent certificates (defeating revocation checking).

### 5.2 Impact and Lessons

- **Trust store removal**: DigiNotar was removed from all browser trust stores within days — the nuclear option for a CA compromise. This invalidated not only the fraudulent certificates but also all legitimate DigiNotar certificates, causing significant disruption to DigiNotar's customers.
- **OCSP/CRL failure**: The fact that DigiNotar's OCSP responder was also compromised demonstrates that revocation checking is not a reliable defense against CA compromise. If the CA controls its own OCSP responder, an attacker who compromises the CA can also compromise the responder.
- **Iranian MITM**: The fraudulent certificates were actively used for surveillance of Iranian citizens accessing Gmail, Yahoo, and other services. This is the first confirmed case of CA-compromise-enabled mass surveillance.
- **Certificate Transparency response**: The DigiNotar incident accelerated the adoption of Certificate Transparency (CT, see §9), which provides a public, append-only log of all issued certificates, enabling detection of unauthorized certificates.

### 5.3 Other CA Compromises

| Year | CA | Incident | Impact |
|---|---|---|---|
| 2011 | DigiNotar | Full CA compromise, 500+ fraudulent certificates | CA removed from trust stores; bankruptcy |
| 2011 | Comodo (affiliate) | RA compromise, 9 fraudulent certificates | Rapid detection and revocation |
| 2012 | Trustwave | Issued subordinate CA for MITM inspection | CA policy violation; sub-CA revoked |
| 2013 | TurkTrust | Issued subordinate CA to a customer | Sub-CA used to issue fraudulent certificates |
| 2015 | MCS Holdings (CNNIC sub-CA) | Issued unconstrained intermediate CA | CNNIC root distrusted by Chrome |
| 2016 | WoSign/StartCom | Multiple issues: misissuance, backdating, algorithm downgrade | Distrusted by browsers in 2017 |
| 2017 | Symantec | Systematic misissuance over years | Distrusted by Chrome; sold CA business to DigiCert |

---

## 6. Subdomain Takeover via Certificate Misissuance

### 6.1 The Attack

Subdomain takeover occurs when a domain owner creates a DNS record pointing to an external service (e.g., `app.example.com CND app.herokuapp.com`) but later abandons the external service without removing the DNS record. An attacker can claim the abandoned external service and receive traffic intended for `app.example.com`.

**Certificate misissuance angle**: To complete the takeover, the attacker often needs a valid TLS certificate for the subdomain. If the subdomain's TXT record for domain validation still exists (e.g., `_acme-challenge.app.example.com`), the attacker can use ACME (Let's Encrypt) to obtain a certificate via DNS-01 validation, even though they don't own the domain.

### 6.2 ACME DNS-01 Validation Considerations

The ACME DNS-01 challenge requires the applicant to create a TXT record at `_acme-challenge.subdomain.example.com` with a specific value. If the applicant controls the DNS zone, they can create this record. But what if:

1. **Stale TXT records**: The domain owner created a TXT record for ACME validation and never removed it. The attacker can reuse the validation mechanism.
2. **CNAME delegation**: If `_acme-challenge` is delegated via CNAME to an external DNS provider, the external provider's security determines who can obtain certificates.

**Mitigation**: 
- Remove DNS records for abandoned services immediately.
- Use `CAA` (Certification Authority Authorization, RFC 8659) records to restrict which CAs can issue certificates for your domain: `example.com. IN CAA 0 issue "letsencrypt.org"`.

---

## 7. ACME Protocol Security and Let's Encrypt Issues

### 7.1 ACME Protocol

The Automatic Certificate Management Environment (ACME, RFC 8555) is the protocol used by Let's Encrypt and other CAs for automated certificate issuance. ACME provides domain validation through challenges:

1. **HTTP-01**: Place a specific file at `http://domain/.well-known/acme-challenge/<token>`.
2. **DNS-01**: Create a TXT record at `_acme-challenge.domain` containing the validation value.
3. **TLS-ALPN-01**: Serve a specific self-signed certificate via TLS with the ACME extension.

### 7.2 ACME Vulnerabilities

**HTTP-01 challenge risks**:
- An attacker who can respond to HTTP requests on the target domain (e.g., via an open redirect, SSRF, or path traversal) can complete the challenge and obtain a certificate.
- IPv4/IPv6 inconsistency: if the domain resolves to different IPs on IPv4 and IPv6, an attacker who controls one address can complete the challenge.
- Shared hosting: on servers hosting multiple domains, a vulnerability in one site's `.well-known` path can be leveraged to obtain a certificate for another site on the same server.

**DNS-01 challenge risks**:
- DNS zone delegation: if `_acme-challenge` is delegated to an external service (e.g., a cloud DNS provider), compromise of that service enables certificate issuance.
- DNS cache poisoning: an attacker who can poison the DNS resolver used by the ACME server can complete the DNS-01 challenge.

### 7.3 Let's Encrypt Incidents

**CVE-2022-0460 — Let's Encrypt bypass of CAA rechecking**: Let's Encrypt issues certificates with 90-day validity. During the issuance process, the CA checks CAA records. However, between the initial CAA check and the actual issuance, CAA records could change. If a domain's CAA record changes from authorizing Let's Encrypt to authorizing a different CA, Let's Encrypt would still issue the certificate based on the stale CAA check. This was resolved by re-checking CAA records shortly before issuance.

**CVE-2022-3602 — X.509 Email Address Buffer Overflow**: A stack buffer overflow in OpenSSL's X.509 email address field handling (4-byte overflow in `ossl_punycode_decode`) could cause a crash or, in theory, remote code execution. While this is an OpenSSL bug rather than a Let's Encrypt bug, it affected Let's Encrypt's infrastructure and highlighted the importance of X.509 parsing security.

**Rate limiting bypass (2020)**: Researchers discovered that Let's Encrypt's rate limits (5 certificates per week per domain, 50 per week per account) could be bypassed by creating multiple accounts. Let's Encrypt responded by implementing additional anti-abuse measures (IP-based rate limiting, domain-based rate limiting).

### 7.4 Short-Lived Certificates

Let's Encrypt's 90-day certificate lifetime is a deliberate security feature: short-lived certificates reduce the window of exposure if a private key is compromised or a certificate is misissued. Revocation is less critical because the certificate expires rapidly.

However, 90-day lifetimes require automated renewal (via ACME), which introduces operational complexity:
- Renewal failures: If the ACME client or server is down during renewal, the certificate expires and the service becomes unavailable.
- Clock skew: If the server's clock is incorrect, it may reject valid certificates or accept expired ones.
- Rate limiting: Frequent renewal failures can exhaust the rate limit, preventing re-issuance.

---

## 8. Self-Signed Certificate Trust

### 8.1 The Trust Problem

Self-signed certificates are signed by their own key rather than a trusted CA. They provide encryption (the TLS handshake negotiates a secure channel) but not authentication (there is no third-party vouching for the identity).

**Self-signed certificate attacks**:
1. **MITM with self-signed certificate**: An attacker presents a self-signed certificate for `bank.com`. The user's browser warns "Connection is not secure." If the user clicks through the warning, the attacker can decrypt and modify all traffic.
2. **Trust on first use (TOFU)**: In TOFU, the client accepts the first self-signed certificate it sees and pins it. This is vulnerable to an active attacker on the first connection (the "first contact" problem).
3. **Self-signed trust injection**: Malware can install self-signed root CA certificates in the system trust store, enabling MITM attacks on all HTTPS connections.

**Defenses**:
- Never accept self-signed certificates in production. Use Let's Encrypt for free certificates.
- If self-signed certificates must be used (internal services, IoT devices), pin the certificate fingerprint via a separate channel (configuration management, SSO token).
- Implement TOFU with pinning: store the certificate hash on first connection and reject changes.

---

## 9. Certificate Transparency and Its Failures

### 9.1 Certificate Transparency (CT) Architecture

Certificate Transparency (CT, RFC 6962, RFC 9162) is a public, append-only log of all issued certificates. CAs submit certificates to CT logs, which return a Signed Certificate Timestamp (SCT). Browsers require SCTs in all certificates (Chrome requires 2+ SCTs from different logs).

**CT log structure**:
- **Log**: An append-only Merkle tree of certificates. Each entry is a `(timestamp, certificate)` pair.
- **Signed Tree Head (STH)**: A signed hash of the Merkle tree root, published periodically.
- **SCT**: A signed promise to include the certificate in the log within a Maximum Merge Delay (MMD, typically 24 hours).
- **Monitor**: A service that watches CT logs for unauthorized certificates for monitored domains.
- **Auditor**: A service that verifies the consistency of CT logs (that new STHs are extensions of previous STHs, that all SCTs are fulfilled).

### 9.2 CT Failures and Attacks

**Pre-certification**: CAs can submit "pre-certificates" (certificates with a poison extension that prevents them from being used) to CT logs before issuing the final certificate. This ensures the certificate is logged before it's valid. However, pre-certificates can also be submitted for legitimate certificates, creating false entries in the log.

**Domain owners not monitoring**: CT is only effective if domain owners monitor the logs for unauthorized certificates. Google monitors for `*.google.com`, but smaller organizations often do not. A misissued certificate for `smallbusiness.com` may go undetected for months if no one is monitoring.

**Log operator trust**: CT logs are operated by organizations (Google, Cloudflare, DigiCert, Sectigo). If a log operator colludes with a CA, they could omit unauthorized certificates from the log, preventing detection. The multi-log requirement (Chrome requires 2+ SCTs from different log operators) mitigates this.

**Maximum Merge Delay (MMD) violations**: If a log fails to include a certificate within its MMD, the SCT is invalid. In practice, logs often experience transient failures (rate limiting, infrastructure issues), and browsers often accept slightly stale SCTs.

**SCT embedding options**:
1. **In the certificate**: The SCT is embedded as an X.509 extension. Requires CA cooperation.
2. **In a TLS extension**: The SCT is sent in a TLS extension during the handshake. Requires server configuration.
3. **In an OCSP response**: The SCT is stapled alongside the OCSP response. Requires OCSP stapling support.

### 9.3 CT and DigiNotar

If CT had been in place in 2011, the DigiNotar compromise would have been detected within hours. The fraudulent certificates for `*.google.com` would have appeared in CT logs, and Google's CT monitor would have alerted them. This is the primary motivation for CT — rapid detection of unauthorized certificates.

---

## 10. SNI Leakage, ESNI, and ECH

### 10.1 Server Name Indication (SNI) Leakage

TLS's SNI extension (RFC 6066) sends the target hostname in cleartext during the TLS handshake. This is necessary because a single IP address may host multiple TLS servers (virtual hosting), and the server needs the hostname to select the correct certificate.

However, SNI leaks the hostname to any network observer (ISP, nation-state, coffee shop Wi-Fi). This is a significant privacy concern:

1. **Censorship**: Governments and ISPs can block specific domains by observing SNI in real-time.
2. **Surveillance**: Network observers can build profiles of all TLS connections a user makes.
3. **Targeted attacks**: An attacker observing SNI can tailor attacks to the specific service.

### 10.2 Encrypted SNI (ESNI)

**Encrypted Server Name Indication (ESNI)** (draft-ietf-tls-esni-08) encrypts the SNI using a public key published in the server's DNS record:

```
_https._esni.example.com IN TXT "esni=...base64-encoded-ESNIKeys..."
```

The ESNIKeys structure contains:
- Public key for ESNI encryption (typically an X25519 key)
- Cipher suite for ESNI (typically AES-GCM or ChaCha20-Poly1305)
- The ESNI version and lifetime

The client encrypts the SNI using the server's ESNI public key and sends the encrypted SNI in the ClientHello. The server decrypts the SNI and selects the appropriate certificate.

**ESNI weaknesses**:
1. **DNS leakage**: The ESNIKeys are published in DNS, which is itself unencrypted. An attacker observing DNS queries can learn the hostname even if SNI is encrypted. DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) partially mitigates this.
2. **Blocking by IP**: ESNI does not hide the server's IP address. If `example.com` resolves to a known IP, the attacker can block the IP regardless of SNI.
3. **ESNI key rotation**: The ESNI public key changes periodically (typically every 24 hours). If the client has a stale key, the ESNI handshake fails, and the client must fall back to plaintext SNI or re-fetch the key via DNS.
4. **China's ESNI blocking**: In 2020, China began blocking TLS connections that use ESNI, detecting the encrypted SNI by the presence of the ESNI extension in the ClientHello. This demonstrates that ESNI is observable even though the SNI is encrypted — the extension itself is a fingerprint.

### 10.3 Encrypted Client Hello (ECH)

**Encrypted Client Hello (ECH)** (draft-ietf-tls-esni-13, now merged into TLS 1.3 extension) extends ESNI by encrypting the entire ClientHello, not just the SNI. ECH addresses ESNI's weaknesses:

1. **Full ClientHello encryption**: ECH encrypts all sensitive ClientHello parameters (SNI, ALPN, supported groups, etc.) into an `encrypted_client_hello` extension. The outer ClientHello contains only generic parameters (TLS version, cipher suite) and the ECH extension.
2. **Grease ECH**: Clients that support ECH send a "grease" (dummy) ECH extension even when connecting to servers that don't support ECH. This prevents attackers from distinguishing ECH-capable clients from non-ECH clients.
3. **HTTPS DNS record**: ECH public keys are published in HTTPS-type DNS records (SVCB/HTTPS RR type 65), providing a more flexible key distribution mechanism than ESNI's TXT records.

```dns
; ECH configuration in DNS
example.com. IN HTTPS 1 . ech=AEX+DQB...base64...
```

**ECH status (2024)**: ECH is supported by Chrome 117+ and Firefox 118+, with Cloudflare and other CDN providers supporting it on the server side. Adoption is growing but still early.

**Remaining challenges**:
- **DNS leakage**: DNS queries for the ECH configuration still reveal the domain. DoH/DoT mitigates this.
- **IP blocking**: ECH does not hide the server's IP address.
- **Widespread deployment**: CDN and hosting provider support is required for most websites. Only Cloudflare, Google, and a few others currently support ECH.
- **Config rotation**: ECH configurations require periodic rotation (like ESNI), creating operational complexity.

---

## Cross-References

- **§02a** — RSA/ECC attacks: Bleichenbacher padding oracle (applied in ROBOT, DROWN)
- **§02b** — Hash/MAC attacks: MD5 collision (Flame certificate), SHA-1 collision
- **§03a** — TLS attacks: FREAK (export-grade RSA certificates), Logjam (export-grade DH)
- **§04b** — Hardware attacks: TPM key generation vulnerabilities, HSM CA key storage
- **§05b** — Crypto engineering: certificate lifecycle management, key rotation strategies
- **§06** — Case studies: DigiNotar (CA compromise), Flame (MD5 collision certificate forgery)
- **Chromium track** — Chrome's CT enforcement, CRLSet, and certificate verification
- **Linux Kernel track** — kernel TLS (kTLS), AF_ALG certificate verification

## References

1. RFC 5280, "Internet X.509 Public Key Infrastructure Certificate and CRL Profile," May 2008.
2. RFC 6960, "Online Certificate Status Protocol (OCSP)," June 2013.
3. RFC 6962, "Certificate Transparency," June 2013.
4. RFC 8555, "Automatic Certificate Management Environment (ACME)," March 2019.
5. RFC 7633, "TLS Feature Extension (Must-Staple)," October 2015.
6. RFC 8659, "Certification Authority Authorization (CAA) DNS Resource Record," November 2019.
7. CVE-2013-0726, "Java JSSE basicConstraints Validation Bypass," 2013.
8. CVE-2008-5161, "OpenSSL NULL Character in CN Certificate Name," 2008.
9. DigiNotar CA Compromise Incident, "Dutch Government TNO Report," September 2011.
10. Comodo CA Fraudulent Certificate Incident, March 2011.
11. Stevens, M., Lenstra, A., de Weger, B., "Chosen-Prefix Collisions for MD5 and Colliding X.509 Certificates," EUROCRYPT 2007.
12. RFC 6066, "TLS Extensions Including SNI and OCSP Stapling," January 2011.
13. IETF Draft, "Encrypted Client Hello (ECH)," draft-ietf-tls-esni-13.
14. Sheffer, Y., Saint-Andre, P., "Summarizing Known Attacks on TLS," RFC 7457, February 2015.
15. Clark, J., van Oorschot, P.C., "SoK: SSL and HTTPS: Revisiting Past Challenges and Looking at the Future," ACM CCS, 2013.
16. CVE-2018-1000001, "OpenSSL Path Building Algorithm Weakness," 2018.
17. Apple, "iMessage Key Transparency," Security Research, 2023.