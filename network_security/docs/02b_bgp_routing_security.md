# BGP Routing Security

## BGP Fundamentals

Border Gateway Protocol (BGP) is the routing protocol that holds the Internet together. It operates on trust — a fundamental design flaw that enables route hijacking and traffic interception at global scale.

```
┌──────────────────────────────────────────────────────────────┐
│                    BGP OPERATIONS MODEL                        │
│                                                               │
│  ┌─────┐            ┌─────┐            ┌─────┐            │
│  │AS64511────────────AS64512─────────────AS64513            │
│  │(Comcast)          │(Level3)          │(Telefonica)      │
│  └───────────────────┴──────────────────┴─────────────────  │
│         │                  │                    │            │
│         │  BGP UPDATE      │  BGP UPDATE        │            │
│         │  NLRI: 203.0.113.0/24                 │            │
│         │  AS_PATH: 64513 64512                  │            │
│         │  NEXT_HOP: 198.51.100.1                │            │
│         │                                         │            │
│                                                               │
│  BGP Message Types:                                           │
│  ┌─────────┬─────────────────────────────────────────┐       │
│  │ Type    │ Purpose                                  │       │
│  ├─────────┼─────────────────────────────────────────┤       │
│  │ OPEN    │ Establish BGP session, negotiate params │       │
│  │ UPDATE  │ Advertise/withdraw routes               │       │
│  │ NOTIFICATION │ Error handling, session teardown   │       │
│  │ KEEPALIVE │ Maintain session alive                │       │
│  │ ROUTE-REFRESH │ Request re-advertisement          │       │
│  └─────────┴─────────────────────────────────────────┘       │
│                                                               │
│  UPDATE Message Structure:                                    │
│  ┌─────────────────────────────────────────────────┐         │
│  │ Withdrawn Routes (length + prefixes)             │         │
│  ├─────────────────────────────────────────────────┤         │
│  │ Path Attributes:                                 │         │
│  │   ORIGIN (IGP/EGP/INCOMPLETE)                   │         │
│  │   AS_PATH (sequence of AS numbers)               │         │
│  │   NEXT_HOP (gateway IP)                          │         │
│  │   MED (multi-exit discriminator)                 │         │
│  │   LOCAL_PREF (internal preference)              │         │
│  │   COMMUNITY (tagging, 32-bit)                   │         │
│  │   ATOMIC_AGGREGATE / AGGREGATOR                  │         │
│  ├─────────────────────────────────────────────────┤         │
│  │ NLRI (Network Layer Reachability Information)    │         │
│  │   Prefix/Length pairs                            │         │
│  └─────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────┘
```

### BGP Path Selection Algorithm

```
┌──────────────────────────────────────────────────────────────┐
│              BGP DECISION PROCESS (Simplified)                │
│                                                               │
│  1. Highest LOCAL_PREF (policy-driven, internal)              │
│  2. Shortest AS_PATH                                          │
│  3. Lowest ORIGIN type (IGP < EGP < INCOMPLETE)              │
│  4. Lowest MED (Multi-Exit Discriminator)                    │
│  5. eBGP over iBGP (prefer external routes)                  │
│  6. Lowest IGP metric to NEXT_HOP                             │
│  7. Oldest route (longest-established)                        │
│  8. Lowest router ID (tiebreaker)                             │
│  9. Shortest cluster list length                               │
│ 10. Lowest neighbor address (final tiebreaker)                │
│                                                               │
│  SECURITY NOTE: Shortest AS_PATH is step 2!                   │
│  Attacker prepending fewer AS numbers = preferred route       │
│  This is the foundation of BGP hijacking attacks              │
└──────────────────────────────────────────────────────────────┘
```

### BGP Session Establishment

```
┌──────────────────────────────────────────────────────────────┐
│              BGP SESSION ESTABLISHMENT (FSM)                   │
│                                                               │
│  Router A (AS 64511)                    Router B (AS 64512)   │
│       │                                       │               │
│       │ ──── TCP SYN ────────────────────────► │               │
│       │ ◄─── TCP SYN+ACK ─────────────────── │               │
│       │ ──── TCP ACK ────────────────────────► │               │
│       │                                       │               │
│       │ ──── BGP OPEN ──────────────────────► │               │
│       │      Version, AS, HoldTime, RouterID  │               │
│       │      Opt Parm Len, Capabilities        │               │
│       │ ◄─── BGP OPEN ─────────────────────── │               │
│       │                                       │               │
│       │ ──── KEEPALIVE ─────────────────────► │               │
│       │ ◄─── KEEPALIVE ────────────────────── │               │
│       │                                       │               │
│       │ ══════ BGP Session Established ═══════ │               │
│       │                                       │               │
│       │ ──── UPDATE (prefixes) ──────────────► │               │
│       │ ◄─── UPDATE (prefixes) ────────────── │               │
│                                                               │
│  Optional Capabilities (RFC 3392):                            │
│  - Multiprotocol Extensions (MP-BGP)                          │
│  - Route Refresh                                             │
│  - 4-byte AS numbers                                         │
│  - Extended Next Hop                                         │
│  - Graceful Restart                                          │
│  - ADD_PATH (path signaling)                                 │
│  - BGPsec (security extension)                               │
└──────────────────────────────────────────────────────────────┘
```

## Route Hijacking

### Prefix Hijacking

Prefix hijacking occurs when an AS announces a prefix it does not originate:

```
┌──────────────────────────────────────────────────────────────┐
│                 PREFIX HIJACKING                               │
│                                                               │
│  Legitimate Announcement:                                     │
│  AS64512 announces 203.0.113.0/24                            │
│  AS_PATH: 64512                                               │
│  → Internet routes traffic to AS64512                         │
│                                                               │
│  Hijack Scenario 1: Exact Prefix Hijack                       │
│  AS64599 announces 203.0.113.0/24 (same prefix)              │
│  AS_PATH: 64599                                               │
│  → Routers choose shorter AS_PATH or lower Router ID         │
│  → Traffic diverted to AS64599                                │
│                                                               │
│  Hijack Scenario 2: More Specific Prefix Hijack              │
│  AS64599 announces 203.0.113.0/25 (more specific!)           │
│  AS_PATH: 64599                                               │
│  → More specific route always wins                            │
│  → 100% of traffic to 203.0.113.0/25 goes to AS64599         │
│                                                               │
│  ┌──────────────────────────────────────────────┐            │
│  │  ROUTING TABLE BEFORE HIJACK                 │            │
│  │  203.0.113.0/24 → AS64512                    │            │
│  │                                               │            │
│  │  ROUTING TABLE AFTER HIJACK                   │            │
│  │  203.0.113.0/24 → AS64512  (still exists)    │            │
│  │  203.0.113.0/25 → AS64599  (more specific!) │            │
│  │                                               │            │
│  │  Traffic to .0-.127 → AS64599 (HIJACKED)      │            │
│  │  Traffic to .128-.255 → AS64512 (original)   │            │
│  └──────────────────────────────────────────────┘            │
│                                                               │
│  Impact: Traffic interception, DDoS, data theft, surveillance│
└──────────────────────────────────────────────────────────────┘
```

### AS Path Manipulation

```
┌──────────────────────────────────────────────────────────────┐
│              AS PATH MANIPULATION                              │
│                                                               │
│  Normal AS_PATH: 64511 64500 64512                            │
│  (Origin AS is 64512, passed through 64500, received by 64511)│
│                                                               │
│  Attack 1: AS Path Prepending (make path shorter)             │
│  Attacker removes AS numbers: → 64599 64512                   │
│  Now shorter path → preferred                                 │
│                                                               │
│  Attack 2: AS Path Shortening                                 │
│  Normal: 64511 64500 64501 64502 64512                        │
│  Hijack: 64599 64512  (fabricated short path)                 │
│                                                               │
│  Attack 3: AS Path Forgery                                    │
│  Attacker inserts legitimate AS numbers:                      │
│  64599 64511 64500 64512                                      │
│  → Appears as if traffic passes through legitimate ASNs        │
│  → Harder to detect by BGP collectors                         │
│                                                               │
│  Attack 4: AS Path.loop Detection Bypass                      │
│  AS_PATH: 64599 64512 64599  ← Contains own AS (loop)        │
│  Normal: Router drops updates containing its own AS           │
│  Bypass: Remove own AS before forwarding                      │
│  Or: Use allowas-in configuration                             │
└──────────────────────────────────────────────────────────────┘
```

### Route Leaking

Route leaking occurs when a route is announced beyond its intended scope:

```
┌──────────────────────────────────────────────────────────────┐
│                  ROUTE LEAKING                                 │
│                                                               │
│  Internet routing uses a tiered model:                        │
│                                                               │
│  Tier 1 (Transit-Free): Connected to entire Internet          │
│     │                                                          │
│  Tier 2 (Transit + Peer): Pays Tier 1 for transit             │
│     │                                                          │
│  Tier 3 (Stub / Customer): Pays for all transit               │
│                                                               │
│  Valley-Free Principle:                                        │
│  A route should follow: Customer → Provider → Peer           │
│  It should NOT go: Customer → Provider → Customer → Provider  │
│                         ^^^ VALLEY (route leak)               │
│                                                               │
│  ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐              │
│  │AS 100│────│AS 200│────│AS 300│────│AS 400│              │
│  │(cust)│    │(prov)│    │(peer)│    │(dest)│              │
│  └──────┘    └──┬───┘    └──────┘    └──────┘              │
│                 │                                              │
│  ┌──────┐      │      ┌──────┐                               │
│  │AS 150│──────┘──────│AS 350│                               │
│  │(leak)│             │(cust)│                               │
│  └──────┘             └──────┘                               │
│                                                               │
│  AS 200 announces AS 100 routes to AS 350 (customer)         │
│  AS 350 announces them to AS 300 (provider)                  │
│  AS 300 sees route via AS 200 → AS 350 → AS 100             │
│  This creates a valley → Route Leak!                          │
│                                                               │
│  Impact:                                                      │
│  - Traffic follows unintended path (possibly through hostile AS)│
│  - Increased latency                                         │
│  - Potential for traffic interception                         │
│  - Cost shifting (transit provider bears cost of leaked traffic)│
└──────────────────────────────────────────────────────────────┘
```

## BGP Hijacking for Traffic Interception

### Pakistan YouTube Hijack (2008)

```
┌──────────────────────────────────────────────────────────────┐
│         PAKISTAN YOUTUBE HIJACK (February 24, 2008)          │
│                                                               │
│  Context: Pakistan Telecom ordered YouTube block             │
│                                                               │
│  What happened:                                                │
│  1. Pakistan Telecom (AS17557) announced                     │
│     208.65.153.0/24 (YouTube prefix)                         │
│     with AS_PATH: 17557                                        │
│                                                               │
│  2. This /24 was MORE SPECIFIC than YouTube's /24            │
│     Wait — it was the SAME prefix, but Pakistan Telecom's    │
│     route was propagated internationally via PCCW (AS3491)   │
│                                                               │
│  3. PCCW forwarded the announcement globally                 │
│                                                               │
│  4. Global routers prefer shorter AS_PATH                    │
│     Pakistan Telecom's AS_PATH was shorter than legitimate  │
│                                                               │
│  5. ALL YouTube traffic worldwide → Pakistan Telecom          │
│     YouTube knocked offline for ~2 hours                     │
│                                                               │
│  Timeline:                                                    │
│  18:48 UTC - Pakistan Telecom starts announcing /24           │
│  18:50 UTC - Route propagates via PCCW                        │
│  19:05 UTC - YouTube routes globally hijacked                │
│  19:30 UTC - YouTube announces /25 (more specific!)           │
│  20:00 UTC - PCCW withdraws route                             │
│  20:15 UTC - YouTube fully restored                           │
│                                                               │
│  Key lessons:                                                 │
│  - BGP has NO authentication of prefix ownership              │
│  - upstream provider must filter customer announcements      │
│  - More specific routes always win over shorter AS_PATHs     │
│  - YouTube mitigated by advertising /25s (more specific)       │
│                                                               │
│  BGP Announcement (simplified):                               │
│  UPDATE: 208.65.153.0/24, AS_PATH: 3491 17557                 │
│  Origin: IGP, Next Hop: PCCW router                            │
└──────────────────────────────────────────────────────────────┘
```

### China Telecom Route Hijacking

```
┌──────────────────────────────────────────────────────────────┐
│    CHINA TELECOM ROUTE HIJACKING INCIDENTS                    │
│                                                               │
│  Multiple incidents observed (2010s-2020s) where China        │
│  Telecom (AS4134, AS4809) announced prefixes belonging to    │
│  other ASes, diverting traffic through China.                │
│                                                               │
│  Notable incidents:                                            │
│  - 2010: 15% of Internet routes through China (Renesys)      │
│  - 2013: US government traffic rerouted                       │
│  - 2016: Traffic from Canada, US, Korea diverted              │
│  - 2017: Massive route leak affecting NA networks             │
│  - 2020: New incidents observed in April                      │
│                                                               │
│  Attack pattern:                                               │
│  1. Announce more specific routes for target prefixes         │
│  2. Let traffic transit through Chinese routers               │
│  3. Observe/intercept traffic                                  │
│  4. Withdraw routes (minutes to hours later)                 │
│                                                               │
│  Often attributed to "routing misconfiguration" by China Telecom│
│  but scale and selectivity suggest intentional action          │
│                                                               │
│  Detection:                                                   │
│  - Monitor BGP updates (Route Views, RIPE RIS)                │
│  - Alert on unexpected AS_PATH changes                        │
│  - Alert on new more-specific prefixes                        │
│  - Track MOAS (Multiple Origin AS) events                     │
└──────────────────────────────────────────────────────────────┘
```

### BGP Hijacking for Cryptocurrency Theft

```
┌──────────────────────────────────────────────────────────────┐
│    BGP HIJACKING FOR CRYPTOCURRENCY THEFT                     │
│                                                               │
│  Attack Vector: DNS hijacking via BGP to redirect             │
│  cryptocurrency exchange traffic                               │
│                                                               │
│  Example: MyEtherWallet (April 2018)                          │
│  1. Attacker (AS395507) announced 216.117.2.0/24             │
│     (more specific than legitimate /23)                       │
│  2. Traffic to MyEtherWallet.com DNS servers intercepted     │
│  3. DNS resolved to attacker's server (fake MEW page)        │
│  4. Users entered private keys on fake site                   │
│  5. Estimated $152,000 in ETH stolen                         │
│                                                               │
│  Example: Celer Network (2021)                                │
│  - BGP hijack of AWS IP range                                │
│  - Intercepted DNS for celer.network                          │
│  - Redirected to phishing page                                │
│                                                               │
│  Attack chain:                                                 │
│  BGP Hijack → DNS Interception → Phishing → Key Theft        │
│                                                               │
│  Why DNS + BGP is devastating:                                │
│  - DNS resolvers cache based on TTL                           │
│  - Hijacked DNS server returns attacker IPs                   │
│  - TLS helps, but...                                         │
│  - Attacker can get valid TLS cert via ACME (HTTP-01)        │
│  - if they control the IP serving the validation page         │
│  - This is why DNSSEC matters (see 02a_dns_security.md)      │
│                                                               │
│  Mitigation:                                                  │
│  - RPKI (Resource Public Key Infrastructure)                  │
│  - BGPsec (cryptographic validation)                          │
│  - DNSSEC (prevent DNS spoofing even after BGP hijack)        │
│  - Multiple diverse DNS servers                                │
│  - Extended DNS provider diversity                            │
└──────────────────────────────────────────────────────────────┘
```

## BGPsec

BGPsec (RFC 8205) adds cryptographic signatures to BGP announcements:

```
┌──────────────────────────────────────────────────────────────┐
│                    BGPsec ARCHITECTURE                          │
│                                                               │
│  Ordinary BGP UPDATE:                                        │
│  AS_PATH: 64512 64500 64511                                   │
│  (No way to verify this path is authentic)                    │
│                                                               │
│  BGPsec UPDATE:                                               │
│  AS_PATH: 64512 64500 64511                                   │
│  + Signature by AS64512 over {prefix, 64512, 64500}           │
│  + Signature by AS64500 over {prefix, 64500, 64511, sig64512} │
│  + Signature by AS64511 over {prefix, 64511, sig64500}       │
│                                                               │
│  Each AS in the path signs:                                   │
│  - The prefix being announced                                 │
│  - The AS number of the next hop                              │
│  - The previous signature                                     │
│                                                               │
│  Validation chain:                                            │
│  ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐        │
│  │Origin  │───►│AS64512 │───►│AS64500 │───►│AS64511 │        │
│  │AS       │    │signs   │    │signs   │    │signs   │        │
│  └────────┘    └────────┘    └────────┘    └────────┘       │
│                  │               │               │            │
│              RPKI cert      RPKI cert       RPKI cert        │
│              validates      validates        validates         │
│              64512's key    64500's key      64511's key      │
│                                                               │
│  Limitations:                                                  │
│  1. Only validates AS_PATH, not prefix authorization          │
│     (RPKI handles that)                                       │
│  2. Requires all ASes on path to support BGPsec                │
│  3. Increases BGP message size significantly                   │
│  4. Key management complexity (SKR, RTR)                      │
│  5. Computational overhead for signature verification         │
│  6. Partial deployment provides limited benefit               │
│  7. Does NOT protect payload (prefix, NLRI)                   │
└──────────────────────────────────────────────────────────────┘
```

### BGPsec Attack Surface

```
┌──────────────────────────────────────────────────────────────┐
│               BGPsec SECURITY CONSIDERATIONS                   │
│                                                               │
│  1. AS PATH INTEGRITY (SOLVED):                               │
│     Cannot forge or modify AS_PATH without breaking signatures│
│                                                               │
│  2. PREFIX ORIGIN AUTHORIZATION (NOT SOLVED):                  │
│     BGPsec does NOT verify that origin AS is authorized        │
│     to announce the prefix. Use RPKI for this.                │
│                                                               │
│  3. ROUTE LEAKS (PARTIALLY ADDRESSED):                         │
│     BGPsec doesn't prevent a provider from leaking a customer │
│     route. Need RPKI + local policies.                         │
│                                                               │
│  4. KEY COMPROMISE:                                            │
│     If an AS's private key is compromised, attacker can sign  │
│     arbitrary BGPsec announcements as that AS.                │
│     Key rollover is complex and must be carefully managed.     │
│                                                               │
│  5. DELAY / DENIAL OF SERVICE:                                 │
│     BGPsec validation requires checking signature chain.       │
│     Slow validation = delayed routing = potential DoS.         │
│                                                               │
│  6. DEPLOYMENT ECONOMICS:                                     │
│     Until critical mass of ASes support BGPsec,               │
│     unsigned paths may be preferred (shorter, less overhead)  │
│     → Negative deployment incentive                            │
│                                                               │
│  Current deployment status:                                    │
│  - Limited production deployment as of 2024                    │
│  - Most networks still rely on RPKI alone                     │
│  - BGPsec requiring full path validation remains aspirational │
└──────────────────────────────────────────────────────────────┘
```

## RPKI (Resource Public Key Infrastructure)

RPKI provides cryptographic validation of IP address allocation:

```
┌──────────────────────────────────────────────────────────────┐
│                     RPKI ARCHITECTURE                          │
│                                                               │
│  Trust Anchors:                                               │
│  ┌──────────────────────────────────────────────────┐         │
│  │  IANA (Root)                                      │         │
│  │  Holds: All IP space + AS numbers                  │         │
│  │  Delegates: To RIRs                                │         │
│  └──────────────┬───────────────────────────────────┘         │
│                 │                                              │
│  ┌──────────────┼────────────────────────────────────┐        │
│  │              │  Regional Internet Registries        │        │
│  │  ┌──────┐ ┌──┴───┐ ┌──────┐ ┌──────┐ ┌──────┐  │        │
│  │  │ARIN  │ │RIPE  │ │APNIC │ │LACNIC│ │AFRINIC│  │        │
│  │  │      │ │NCC   │ │      │ │      │ │      │  │        │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘  │        │
│  └─────┼────────┼────────┼────────┼────────┼──────┘        │
│        │        │        │        │        │                 │
│  ┌─────┴────┐   │   ┌────┴───┐   │   ┌────┴───┐            │
│  │ISPs/LIRs │   │   │ISPs    │   │   │ISPs    │            │
│  │(Local    │   │   │        │   │   │        │            │
│  │Internet  │   │   │        │   │   │        │            │
│  │Registries│   │   │        │   │   │        │            │
│  └─────┬────┘   │   └────┬───┘   │   └────┬───┘            │
│        │        │        │       │        │                   │
│  ┌─────┴────┐   │   ┌────┴───┐   │   ┌────┴───┐            │
│  │End Users │   │   │End User│   │   │End User│            │
│  └──────────┘   │   └────────┘   │   └────────┘            │
│                                                               │
│  RPKI Objects:                                                │
│  ┌──────────────────────────────────────────────────┐         │
│  │ ROA (Route Origin Authorization):                 │         │
│  │   AS 64512 is authorized to announce             │         │
│  │   203.0.113.0/24 with maxLength /24              │         │
│  │                                                   │         │
│  │ Certificate: X.509 RPKI certificate              │         │
│  │   Proves holder controls IP resources             │         │
│  │                                                   │         │
│  │ Manifest: List of all objects in the repository   │         │
│  │ CRL: Certificate Revocation List                  │         │
│  │                                                   │         │
│  │ ROA Format (JSON):                                │         │
│  │ {                                                 │         │
│  │   "prefix": "203.0.113.0/24",                    │         │
│  │   "maxLength": 24,                               │         │
│  │   "asn": "AS64512",                               │         │
│  │   "ta": "ripe"                                    │         │
│  │ }                                                 │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Validation States:                                           │
│  ┌──────────┬──────────────────────────────────────┐         │
│  │ Valid    │ Route matches a valid ROA              │         │
│  │ Invalid │ Route does NOT match ANY valid ROA     │         │
│  │          │ or matches a ROA with different AS     │         │
│  │ NotFound │ No ROA exists for this prefix          │         │
│  └──────────┴──────────────────────────────────────┘         │
│                                                               │
│  Example:                                                     │
│  ROA: 203.0.113.0/24 → AS64512, maxLen 24                    │
│                                                               │
│  Announcement: 203.0.113.0/24, origin AS64512 → VALID          │
│  Announcement: 203.0.113.0/24, origin AS64599 → INVALID        │
│  Announcement: 203.0.113.0/25, origin AS64512 → INVALID        │
│  (maxLength is /24, /25 is more specific and not authorized)    │
│  Announcement: 198.51.100.0/24, origin AS64512 → NOT FOUND      │
│  (No ROA for this prefix)                                     │
└──────────────────────────────────────────────────────────────────┘
```

### RPKI Deployment Challenges

```python
# RPKI validation with Routinator
# Install: cargo install routinator

# Run RPKI validator
# routinator server --http 127.0.0.1:9556

# Query RPKI state
# curl http://127.0.0.1:9556/api/v1/validity/203.0.113.0/24/64512

# RTR protocol: Feed validated ROAs to routers
# RTR session between validator and router

# RPKI deployment statistics (2024):
# ~50% of Internet routes have ROAs
# ~80% of routes are RPKI Valid or NotFound
# Major providers (Cloudflare, Google, Amazon) fully deployed

# Known RPKI issues:
# 1. ROA misconfigurations cause legitimate route drops
#    - 2019: Google routes accidentally dropped by Telia
#    - 2020: Microsoft Azure routes dropped
# 2. maxLength too permissive (e.g., maxLen /24 for /24 = OK,
#    but maxLen /16 for /24 = allows /16 through /24 hijacks)
# 3. No revocation mechanism for ROAs (CRL only for certificates)
# 4. Relying party software complexity
```

## MANRS (Mutual Agreed Norms for Routing Security)

```
┌──────────────────────────────────────────────────────────────┐
│                    MANRS INITIATIVE                            │
│                                                               │
│  MANRS provides four actions for network operators:           │
│                                                               │
│  Action 1: FILTERING                                          │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Ensure correctness of customer announcements       │        │
│  │ - Filter based on RPKI                           │        │
│  │ - Filter based on IRR (Routing Registry)         │        │
│  │ - Implement maximum prefix length limits          │        │
│  │ - Drop bogon prefixes                             │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  Action 2: ANTI-SPOOFING                                      │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Prevent IP spoofing from your network             │        │
│  │ - Implement BCP 38 (source address validation)   │        │
│  │ - uRPF (Unicast Reverse Path Forwarding)          │        │
│  │ - ACLs on edge routers                           │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  Action 3: COORDINATION                                      │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Facilitate communication between operators         │        │
│  │ - Publish contact information in WHOIS             │        │
│  │ - Maintain up-to-date RADB/IRR objects             │        │
│  │ - Participate in NOCs                             │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  Action 4: GLOBAL VALIDATION                                   │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Deploy RPKI-based route origin validation         │        │
│  │ - Sign your routes with ROAs                      │        │
│  │ - Validate routes using RPKI                      │        │
│  │ - Drop Invalid routes (reject RPKI Invalid)       │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  MANRS Observatory: https://observatory.manrs.org/            │
│  Tracks routing hygiene metrics across participating networks │
└──────────────────────────────────────────────────────────────┘
```

### BGP Monitoring and Detection Tools

```bash
# BGP monitoring toolkit

# RIPE Stat API - check RPKI validation
curl "https://stat.ripe.net/data/rpki-validation/data.json?resource=203.0.113.0/24&asn=64512"

# BGP Stream (real-time monitoring)
# https://bgpstream.caida.org/

# Route Views (historical BGP data)
# http://archive.routeviews.org/

# BGP Hijack detection tools
# 1. ARTEMIS (Automated Real-Time Exhaustive Monitoring of InterneT Signals)
#    Open-source BGP hijack detection and mitigation
#    https://github.com/FORTH-ICS-INSPIRE/artemis

# 2. BGPmon (now part of Cisco Umbrella)
#    Commercial BGP monitoring

# 3. BGPKIT (Rust-based BGP toolkit)
cargo install bgpkit-bgpkit-parser

# 4. PyBGPStream (Python interface)
pip install pybgpstream

# Check for MOAS (Multiple Origin AS) conflicts
bgpstream = pybgpstream.BGPStream(
    from_time="2024-01-01", until_time="2024-01-02",
    collectors=["rrc00"], record_type="updates"
)

for record in bgpstream:
    for element in record:
        # Check for AS_PATH anomalies
        # Check for more-specific announcements
        pass

# RPKI monitoring
# Cloudflare RPKI portal: https://rpki.cloudflare.com/
# RIPE RPKI Validator: https://rpki-validator.ripe.net/
```

### Network Operator Defense Guide

```
┌──────────────────────────────────────────────────────────────┐
│          BGP HARDENING CHECKLIST                                │
│                                                               │
│  1. PREFIX FILTERING                                          │
│     □ Filter customer announcements to allocated prefixes     │
│     □ Implement maximum prefix length (/24 for IPv4)          │
│     □ Apply IRR-based filters                                  │
│     □ Deploy RPKI-based origin validation                     │
│     □ Drop RPKI Invalid routes                               │
│     □ Drop bogon prefixes                                     │
│                                                               │
│  2. ANTI-SPOOFING                                             │
│     □ Implement uRPF (strict or loose)                        │
│     □ Apply BCP 38 ingress filters                           │
│     □ Filter RFC 1918 / bogon source addresses                │
│                                                               │
│  3. SESSION SECURITY                                          │
│     □ Enable BGP MD5 authentication                           │
│     □ Migrate to BGP TCP-AO (RFC 5925)                      │
│     □ Use GTSM (Generalized TTL Security Mechanism)           │
│     □ Limit BGP to specific neighbors (ACLs)                 │
│     □ Enable BGP graceful restart                            │
│                                                               │
│  4. MONITORING                                                │
│     □ Deploy BGP monitoring (ARTEMIS, BGPStream)              │
│     □ Monitor for MOAS conflicts                              │
│     □ Alert on more-specific prefix announcements             │
│     □ Log all BGP updates                                    │
│     □ Subscribe to MANRS                                     │
│                                                               │
│  5. RPKI                                                      │
│     □ Publish ROAs for all allocated prefixes                 │
│     □ Deploy RPKI relying party (Routinator/FORT)            │
│     □ Drop RPKI Invalid in routing policy                    │
│     □ Monitor RPKI for accidental ROA errors                 │
│                                                               │
│  6. DOCUMENTATION                                             │
│     □ Register all ASNs in WHOIS                             │
│     □ Register all prefixes in WHOIS                          │
│     □ Maintain IRR objects (route/route6)                     │
│     □ Publish contact information (RDAP/WHOIS)                │
└──────────────────────────────────────────────────────────────┘
```

```cisco
! Cisco IOS BGP hardening
router bgp 64512
 !
 ! Prefix filtering
 neighbor 198.51.100.1 prefix-list CUSTOMER-IN in
 neighbor 198.51.100.1 prefix-list CUSTOMER-OUT out
 !
 ! Maximum prefix limit
 neighbor 198.51.100.1 maximum-prefix 1000 90 warning-only
 !
 ! BGP authentication
 neighbor 198.51.100.1 password 7 <hashed-password>
 !
 ! GTSM (TTL check)
 neighbor 198.51.100.1 ttl-security hops 1
 !
 ! BGP timers
 neighbor 198.51.100.1 timers 30 90
 !
 ! Route origin validation (RPKI)
 bgp rpki server tcp 127.0.0.1 port 8323 refresh 600
 bgp bestpath prefix-validate allow-all
 !
 ! Logging
 bgp log-neighbor changes
!
! Prefix lists
ip prefix-list CUSTOMER-IN seq 5 permit 203.0.113.0/24 le 24
ip prefix-list BOGONS seq 5 deny 0.0.0.0/8 le 32
ip prefix-list BOGONS seq 10 deny 10.0.0.0/8 le 32
ip prefix-list BOGONS seq 15 deny 127.0.0.0/8 le 32
ip prefix-list BOGONS seq 20 deny 169.254.0.0/16 le 32
! ... etc for all bogon prefixes
```

**Cross-references**: See `02a_dns_security.md` for DNS infrastructure attacks that complement BGP hijacking, `04a_network_attacks_mitm.md` for ARP/DHCP attacks at Layer 2 that parallel BGP attacks at Layer 3, and Cloud Security track for cloud provider BGP security.

## References

1. RFC 4271 — A Border Gateway Protocol 4 (BGP-4). Y. Rekhter, T. Li, S. Hares, IETF, January 2006.
2. RFC 8205 — BGPsec Protocol Specification. M. Lepinski, K. Sriram, IETF, September 2017.
3. RFC 6480 — The Resource Public Key Infrastructure (RPKI). M. Lepinski, S. Kent, IETF, February 2012.
4. RFC 6482 — A Profile for Route Origin Authorizations (ROAs). M. Lepinski, S. Kent, D. Kong, IETF, February 2012.
5. NIST IR 8329 — BGP Monitoring and Analysis: What's Needed for Internet Infrastructure Security. NIST, 2022.
6. Mutually Agreed Norms for Routing Security (MANRS). Internet Society, 2024. https://www.manrs.org/
7. Pakistan Telecom YouTube Hijack — Renesys/BGPmon Analysis, February 2008.
8. Demchuk, M. et al. — BGP Hijacking for Cryptocurrency Theft. THN, April 2018.
9. Naeem, A. — China Telecom Route Leaks and BGP Hijacking. US Naval War College, 2020.
10. SVCoin — Celer Network BGP Hijack Analysis. Various security blogs, 2021.
11. Murphy, S. — BGP Security Vulnerabilities Analysis. RFC 4272, IETF, January 2006.
12. RFC 5925 — The TCP Authentication Option. J. Touch et al., IETF, June 2010.
13. RFC 5082 — The Generalized TTL Security Mechanism (GTSM). E. Vyncke et al., IETF, October 2007.
14. Gilad, Y. et al. — Are We There Yet? On RPKI's Deployment and Security. NDSS, 2017.
15. Marder, T. — ARTEMIS: Automated Real-Time Exhaustive Monitoring of Internet Signals. IEEE S&P, 2019.
16. BGPstream — Real-Time BGP Monitoring Toolkit. CAIDA, UC San Diego. https://bgpstream.caida.org/
17. RIPE NCC — RPKI Validator. https://rpki-validator.ripe.net/
18. Cloudflare — RPKI Portal. https://rpki.cloudflare.com/
19. RFC 8210 — The RPKI-to-Router Protocol, Version 1. R. Bush, R. Austein, IETF, September 2017.
20. Lepinski, M., Turner, S. — An Overview of BGP Security. RFC 8205, IETF, September 2017.