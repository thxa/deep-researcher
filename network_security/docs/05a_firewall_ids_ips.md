# Firewall and IDS/IPS Architecture

## Firewall Architecture

### Stateful vs Stateless Inspection

```
┌──────────────────────────────────────────────────────────────┐
│           STATEFUL vs STATELESS INSPECTION                      │
│                                                               │
│  STATELESS FIREWALL (Packet Filter):                          │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ Matches each packet independently against rules:        │     │
│  │ - Source IP, Destination IP                              │     │
│  │ - Source Port, Destination Port                          │     │
│  │ - Protocol (TCP/UDP/ICMP)                                │     │
│  │ - Interface                                              │     │
│  │                                                          │     │
│  │ Rule example:                                            │     │
│  │ ALLOW src=10.0.0.0/8 dst=any proto=tcp dport=443       │     │
│  │ DENY src=any dst=any proto=any any                      │     │
│  │                                                          │     │
│  │ Pros: Fast, minimal memory, simple                      │     │
│  │ Cons: No connection tracking, can't detect             │     │
│  │       return traffic, easily bypassed                   │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  STATEFUL FIREWALL (Connection Tracking):                     │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ Maintains connection state table:                        │     │
│  │                                                          │     │
│  │ ┌────────┬────────┬────────┬────────┬────────┬──────┐ │     │
│  │ │ Src IP │ Dst IP │ Src Pt │ Dst Pt │ Proto  │State │ │     │
│  │ ├────────┼────────┼────────┼────────┼────────┼──────┤ │     │
│  │ │10.0.0.5│93.184.216│54321 │ 443   │ TCP    │ ESTAB│ │     │
│  │ │10.0.0.5│93.184.216│54322 │ 443   │ TCP    │ ESTAB│ │     │
│  │ │10.0.0.5│8.8.8.8 │ 54323 │ 53    │ UDP    │ INIT │ │     │
│  │ └────────┴────────┴────────┴────────┴────────┴──────┘ │     │
│  │                                                          │     │
│  │ Automatically allows RETURN traffic for established      │     │
│  │ connections. Tracks:                                     │     │
│  │ - TCP flags (SYN, ACK, FIN, RST)                        │     │
│  │ - Sequence numbers                                       │     │
│  │ - Connection state (SYN_SENT, ESTABLISHED, CLOSE_WAIT)  │     │
│  │ - UDP "connections" (timeout-based)                     │     │
│  │ - ICMP associations (query/reply pairing)               │     │
│  │                                                          │     │
│  │ Pros: Understands connection context, allows return      │     │
│  │       traffic automatically, detects invalid packets     │     │
│  │ Cons: Memory for state table, vulnerable to state        │     │
│  │       exhaustion (SYN flood), can't inspect payload     │     │
│  └──────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

```bash
# Linux conntrack (connection tracking) - stateful firewall
# View connection table
conntrack -L
conntrack -L -s 10.0.0.5  # Filter by source
conntrack -L -p tcp --dport 443  # Filter by port

# Connection states
# NEW: SYN packet (new connection)
# ESTABLISHED: ACK packet (connection established)
# RELATED: Connection related to existing (e.g., FTP data, ICMP error)
# INVALID: No matching connection
# UNTRACKED: Explicitly excluded from tracking

# iptables stateful rules
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 443 -j ACCEPT

# nftables stateful rules
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input ct state invalid drop
nft add rule inet filter input ct state new tcp dport 443 accept
```

### Next-Generation Firewall (NGFW)

```
┌──────────────────────────────────────────────────────────────┐
│                  NGFW ARCHITECTURE                              │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │              NEXT-GENERATION FIREWALL                   │     │
│  │                                                          │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   │     │
│  │  │  Packet      │  │  Stateful   │  │  Application │   │     │
│  │  │  Filtering   │  │  Inspection │  │  Awareness   │   │     │
│  │  │  (L3/L4)     │  │  (L4 State) │  │  (L7 DPI)   │   │     │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │     │
│  │         │                │                 │            │     │
│  │  ┌──────┴────────────────┴─────────────────┴──────┐    │     │
│  │  │              Unified Policy Engine              │    │     │
│  │  │  (Identity-based, contextual, threat-intel)    │    │     │
│  │  └──────────────────────┬─────────────────────────┘    │     │
│  │                         │                               │     │
│  │  ┌─────────────┐  ┌─────┴────┐  ┌──────────────┐     │     │
│  │  │  IPS/IDS    │  │  URL      │  │  SSL/TLS     │     │     │
│  │  │  Engine     │  │  Filter   │  │  Inspection  │     │     │
│  │  └─────────────┘  └──────────┘  └──────────────┘     │     │
│  │                                                          │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   │     │
│  │  │  Anti-Malware│  │  Sandbox   │  │  Cloud       │   │     │
│  │  │  Engine      │  │  Analysis  │  │  Management  │   │     │
│  │  └─────────────┘  └─────────────┘  └──────────────┘   │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  NGFW Capabilities Beyond Traditional Firewalls:               │
│  ┌──────────────────────────────────────────────────┐         │
│  │ 1. Application Identification (App-ID)            │         │
│  │    - Identify applications regardless of port       │         │
│  │    - Detect applications over non-standard ports    │         │
│  │    - Block Facebook even on port 443               │         │
│  │ 2. User Identification (User-ID)                    │         │
│  │    - Bind IP to user identity (AD, LDAP, RADIUS)   │         │
│  │    - Policy based on user, not IP                   │         │
│  │    - "Allow marketing team to social media"         │         │
│  │ 3. Content Inspection (Content-ID)                 │         │
│  │    - File type blocking                           │         │
│  │    - Data loss prevention (DLP)                   │         │
│  │    - Anti-malware scanning                        │         │
│  │ 4. Threat Prevention                               │         │
│  │    - Intrusion prevention (IPS)                    │         │
│  │    - URL filtering                                │         │
│  │    - DNS sinkholing                               │         │
│  │    - Wildfire/sandbox analysis                    │         │
│  │ 5. SSL/TLS Inspection                              │         │
│  │    - Decrypt, inspect, re-encrypt                 │         │
│  │    - Certificate pinning bypass                    │         │
│  │    - Privacy and legal implications                │         │
│  └──────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────┘
```

### WAF Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  WAF (WEB APPLICATION FIREWALL)                 │
│                                                               │
│  ┌──────┐          ┌──────┐          ┌──────┐               │
│  │Client│─────────►│ WAF  │─────────►│Server│               │
│  └──────┘          └──────┘          └──────┘               │
│      │                │                     │                  │
│      │           ┌────┴────┐               │                  │
│      │           │Rule Match│               │                  │
│      │           └────┬────┘               │                  │
│      │        ┌───────┴───────┐            │                  │
│      │        │   ▼           │            │                  │
│      │  ┌─────┴─────┐ ┌─────┴─────┐      │                  │
│      │  │ ALLOW      │ │ BLOCK     │      │                  │
│      │  │ (pass to   │ │ (return   │      │                  │
│      │  │  server)   │ │  403)     │      │                  │
│      │  └───────────┘ └───────────┘      │                  │
│                                                               │
│  WAF Detection Methods:                                        │
│  1. Signature-based (pattern matching)                        │
│     - Regex patterns for known attacks                       │
│     - OWASP Top 10 patterns                                  │
│     - "union select" → SQL injection                         │
│     - "<script>" → XSS                                       │
│                                                               │
│  2. Anomaly-based (behavioral)                                │
│     - Learn normal traffic patterns                           │
│     - Detect deviations                                      │
│     - Higher false positive rate                              │
│                                                               │
│  3. Positive security model (whitelist)                        │
│     - Define allowed input patterns                           │
│     - Reject anything not matching                            │
│     - Lower false positive rate                               │
│                                                               │
│  Common WAF Bypass Techniques:                                │
│  ┌──────────────────────────────────────────────────┐        │
│  │ SQL Injection:                                    │        │
│  │ - Case variation: UNION SELECT → UnIoN SeLeCt    │        │
│  │ - Comments: UNION/**/SELECT                      │        │
│  │ - Alternative encoding: %55NION (hex)             │        │
│  │ - HPP: ?id=1&id=UNION SELECT                     │        │
│  │ - JSON/XML injection: {"id":"1 UNION SELECT"}    │        │
│  │                                                   │        │
│  │ XSS:                                              │        │
│  │ - Event handlers: <img onerror=alert(1)>          │        │
│  │ - Encoding: &#x61;lert (HTML entity)              │        │
│  │ - JavaScript pseudo-protocol: javascript:alert(1) │        │
│  │ - SVG: <svg onload=alert(1)>                      │        │
│  │                                                   │        │
│  │ General:                                          │        │
│  │ - HTTP parameter pollution (HPP)                  │        │
│  │ - Content-Type confusion                          │        │
│  │ - Request smuggling (CL/TE)                       │        │
│  │ - Chunked encoding                                │        │
│  └──────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

## IDS/IPS Systems

### Snort

```
┌──────────────────────────────────────────────────────────────┐
│                    SNORT IDS/IPS                                │
│                                                               │
│  Snort Architecture:                                           │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Packet Capture (libpcap)                          │         │
│  │       │                                            │         │
│  │  ┌────▼────┐   ┌───────────┐   ┌───────────────┐ │         │
│  │  │Decoder  │──►│Preprocessor│──►│ Detection    │ │         │
│  │  │         │   │  Engine   │   │ Engine       │ │         │
│  │  └─────────┘   │(frag,stream│   │ (rules)      │ │         │
│  │                │ http_inspect)│   └──────┬───────┘ │         │
│  │                └───────────┘          │          │         │
│  │                               ┌───────▼───────┐  │         │
│  │                               │ Output/Logging │  │         │
│  │                               │ (alert,syslog) │  │         │
│  │                               └───────────────┘  │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Snort Rule Syntax:                                            │
│  [action] [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port]│
│    ([rule_options])                                            │
│                                                               │
│  Alert on SQL injection:                                       │
│  alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \                 │
│    (msg:"SQL Injection - UNION SELECT"; \                     │
│     flow:to_server,established; \                              │
│     content:"UNION"; nocase; \                                 │
│     content:"SELECT"; nocase; distance:0; \                   │
│     pcre:"/union[\s\/\*]+select/i"; \                         │
│     sid:1000001; rev:1;)                                       │
│                                                               │
│  Alert on SMB exploit:                                       │
│  alert tcp $EXTERNAL_NET any -> $HOME_NET 445 \                │
│    (msg:"ET EXPLOIT SMB MS17-010"; \                          │
│     flow:established,to_server; \                              │
│     content:"|FF|SMB|00 00 00 00|"; \                          │
│     content:"|00 00 00 00 00 00|"; offset:70; depth:6; \      │
│     reference:cve,2017-0144; \                                │
│     classtype:attempted-admin; sid:2024298; rev:1;)           │
│                                                               │
│  Preprocessors:                                               │
│  preprocessor frag3_global                                    │
│  preprocessor frag3_engine: policy bsd                         │
│  preprocessor stream5_global: track tcp, sessions 65536       │
│  preprocessor stream5_tcp: policy bsd, overlap_type diff      │
│  preprocessor http_inspect: global \                           │
│    iis_unicode_map unicode.map 1252                            │
│  preprocessor http_inspect_server: server default \            │
│    ports { 80 8080 8443 } \                                   │
│    no iis_unicode                                              │
└──────────────────────────────────────────────────────────────┘
```

### Suricata

```
┌──────────────────────────────────────────────────────────────┐
│                  SURICATA IDS/IPS                               │
│                                                               │
│  Suricata is a modern, multi-threaded IDS/IPS/NSM:             │
│                                                               │
│  Key advantages over Snort:                                    │
│  - Multi-threaded packet processing                            │
│  - Native IPv6 support                                        │
│  - Built-in file extraction                                   │
│  - App-layer protocol detection (HTTP, TLS, DNS, SMTP, etc.)  │
│  - JA3/JA3S TLS fingerprinting                                │
│  - Lua scripting support                                      │
│  - TLS certificate logging                                    │
│  - EVE JSON output format                                     │
│                                                               │
│  Suricata Configuration (suricata.yaml):                       │
│  - af-packet: native packet capture                            │
│  - dpdk: high-performance capture                             │
│  - outputs: EVE JSON, syslog, file extraction                  │
│  - app-layer: protocol detection configuration                 │
│  - stream: reassembly configuration                            │
│                                                               │
│  Suricata Rule Examples:                                        │
│                                                               │
│  # Detect DNS tunnel (high entropy subdomains)                 │
│  alert dns any any -> any 53 (msg:"DNS Tunnel Suspected"; \   │
│    dns.query; content:"."; distance:0; \                       │
│    pcre:"/([a-z0-9]{20,}\.){2,}/i"; \                         │
│    classtype:trojan-activity; sid:2024001; rev:1;)             │
│                                                               │
│  # Detect JA3 fingerprint (known malware)                     │
│  alert tls any any -> any 443 (msg:"Known MALWARE JA3"; \     │
│    ja3.hash; content:"a0f23e2afeb02c91ee3a188b23f5914a"; \     │
│    classtype:trojan-activity; sid:2024002; rev:1;)             │
│                                                               │
│  # Detect SSH brute force                                      │
│  alert ssh any any -> $HOME_NET 22 (msg:"SSH Brute Force"; \  │
│    flow:established,to_server; \                               │
│    ssh.software; content:"OpenSSH"; \                          │
│    threshold:type threshold, track by_src, count 5, seconds 60;\│
│    classtype:attempted-admin; sid:2024003; rev:1;)             │
│                                                               │
│  # Detect HTTP suspicious user-agent                            │
│  alert http any any -> $HOME_NET any (msg:"Suspicious UA"; \   │
│    http.user_agent; content:"curl"; \                           │
│    classtype:bad-unknown; sid:2024004; rev:1;)                 │
│                                                               │
│  # Suricata file extraction                                    │
│  # In suricata.yaml:                                           │
│  # - file-store:                                                │
│  #     enabled: yes                                            │
│  #     dir: /var/log/suricata/files                            │
│  # Rule to extract all executables                              │
│  alert http any any -> any any (msg:"EXE Download"; \          │
│    fileext:"exe"; noalert; sid:2024005; rev:1;)                │
└──────────────────────────────────────────────────────────────┘
```

### Zeek (formerly Bro)

```
┌──────────────────────────────────────────────────────────────┐
│                    ZEEK (BRO) NSM                               │
│                                                               │
│  Zeek is a Network Security Monitor — NOT an IPS              │
│  Focuses on DEEP ANALYSIS and LOGGING, not blocking            │
│                                                               │
│  Zeek Architecture:                                            │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ Packet Capture (libpcap/PF_RING/AF_PACKET)           │     │
│  │       │                                                │     │
│  │  ┌────▼────┐   ┌───────────────┐   ┌─────────────┐  │     │
│  │  │  Event   │──►│  Script Layer │──►│ Logging     │  │     │
│  │  |  Engine  │   │  (Zeek scripts│   │ Framework   │  │     │
│  │  │          │   │   .zeek files)│   │             │  │     │
│  │  └──────────┘   └───────────────┘   └──────┬──────┘  │     │
│  │       │                                     │          │     │
│  │  ┌────▼──────────────────┐    ┌─────────────▼────┐  │     │
│  │  │ Protocol Analyzers:      │    │ Log Outputs:      │  │     │
│  │  │ HTTP, DNS, SSL, SSH,     │    │ JSON, TSV,        │  │     │
│  │  │ SMTP, FTP, DHCP, CIFS,   │    │ Elasticsearch,    │  │     │
│  │  │ DNS, LDAP, MQTT, ...     │    │ Kafka, etc.        │  │     │
│  │  └─────────────────────────┘    └──────────────────┘  │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  Zeek Script Example — Detect DNS Tunneling:                  │
│                                                               │
│  @load base/protocols/dns/main                                │
│                                                               │
│  event dns_request(c: connection, msg: dns_msg,               │
│                     query: dns_query, transport: string)       │
│      {                                                         │
│      local qname = query$name;                                │
│      # Check for long subdomains (potential tunnel)            │
│      if (|split_string(qname, /\./)| > 5 ||                   │
│          |split_string1(query$name, /[a-z0-9]{20,}/)| > 0)   │
│          {                                                     │
│          NOTICE($note=DNS::ExcessiveSubdomains,                │
│                  $msg=fmt("DNS tunnel suspected: %s", qname),│
│                  $conn=c,                                      │
│                  $sub=qname);                                  │
│          }                                                     │
│      }                                                         │
│                                                               │
│  Zeek Log Types:                                               │
│  - conn.log: Connection summaries                              │
│  - dns.log: DNS queries and responses                         │
│  - http.log: HTTP requests and responses                       │
│  - ssl.log: TLS handshakes and certificates                    │
│  - ssh.log: SSH connections                                    │
│  - files.log: File transfers over any protocol                │
│  - notice.log: Zeek alerts                                    │
│  - weird.log: Protocol anomalies                               │
│                                                               │
│  Key Zeek Capabilities:                                        │
│  - Connection-level state tracking                            │
│  - Application-layer protocol analysis                        │
│  - File extraction and hashing                                 │
│  - JA3/JA3S TLS fingerprinting                                │
│  - Intelligence framework (threat intel feeds)                 │
│  - Notice framework (alerting)                                │
│  - Summary statistics (every connection)                       │
│  - Extensible scripting language                               │
└──────────────────────────────────────────────────────────────┘
```

## Network Segmentation Patterns

### DMZ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     DMZ ARCHITECTURE                              │
│                                                                   │
│  Internet ──────[External FW]────── DMZ ──────[Internal FW]── LAN │
│                       │              │                │            │
│                  ┌────▼────┐   ┌────▼────┐    ┌─────▼──────┐    │
│                  │Web Proxy│   │Web Server│    │App Server  │    │
│                  │WAF      │   │Mail Relay│    │DB Server   │    │
│                  │IDS/IPS  │   │DNS Auth  │    │File Server │    │
│                  └─────────┘   └─────────┘    └────────────┘    │
│                                                                   │
│  DMZ Rules:                                                       │
│  ┌──────────────────────────────────────────────────┐            │
│  │ External FW:                                      │            │
│  │   Internet → DMZ: Allow 80, 443, 25, 53 only     │            │
│  │   DMZ → Internet: Allow established+related       │            │
│  │   Internet → LAN: DENY ALL                        │            │
│  │                                                   │            │
│  │ Internal FW:                                       │            │
│  │   LAN → DMZ: Allow specific app ports             │            │
│  │   DMZ → LAN: Allow established+related            │            │
│  │   DMZ → LAN (new): Allow specific DB ports only   │            │
│  │   LAN → Internet: Allow via proxy only            │            │
│  │                                                   │            │
│  │ DMZ → LAN (direct):                                │            │
│  │   Web Server → DB Server: Allow 3306, 5432       │            │
│  │   Web Server → App Server: Allow 8080, 8443      │            │
│  │   ALL OTHER DMZ → LAN: DENY                       │            │
│  └──────────────────────────────────────────────────┘            │
│                                                                   │
│  Dual DMZ (more secure):                                          │
│  Internet ──[FW1]── External DMZ ──[FW2]── Internal DMZ ──[FW3]── LAN│
│  (Web, DNS)           (App, API)           (DB, Core)              │
└──────────────────────────────────────────────────────────────────┘
```

### Micro-Segmentation

```
┌──────────────────────────────────────────────────────────────┐
│               MICRO-SEGMENTATION PATTERNS                       │
│                                                               │
│  Traditional: Ring-based security (castle model)              │
│  ┌─────────────────────────────────────────────┐              │
│  │ Outer Ring: Internet → DMZ (firewall)        │              │
│  │ Middle Ring: DMZ → Internal (firewall)        │              │
│  │ Inner Ring: Internal → Core (firewall)       │              │
│  │                                                │              │
│  │ Problem: Once inside inner ring, free movement│              │
│  │ Lateral movement is easy within the ring     │              │
│  └─────────────────────────────────────────────┘              │
│                                                               │
│  Micro-Segmentation: Workload-level security                  │
│  ┌──────┐ ┌──────┐ ┌──────┐                                 │
│  │ App  │ │ App  │ │ App  │ ← Each workload has              │
│  │  A   │ │  B   │ │  C   │   its own firewall policy        │
│  │[FW-A]│ │[FW-B]│ │[FW-C]│                                 │
│  └──┬───┘ └──┬───┘ └──┬───┘                                 │
│     │        │        │                                       │
│     │ A→B:✓ │        │                                       │
│     │ A→C:✗ │ C→B:✗ │                                       │
│     │        │        │                                       │
│  Implementation Technologies:                                 │
│  ┌──────────────────────────────────────────┐                 │
│  │ Host-based: iptables/nftables per server │                 │
│  │ Hypervisor: VMware NSX, Hyper-V Switch  │                 │
│  │ Cloud-native: AWS SG, Azure NSG, GCP FW │                 │
│  │ Container: Cilium (eBPF), Calico, Istio │                 │
│  │ SDN: Cisco ACI, Juniper Contrail         │                 │
│  │ Zero-trust: Zscaler, Illumio, Guardicore │                 │
│  └──────────────────────────────────────────┘                 │
│                                                               │
│  Micro-segmentation policy example (Cilium/eBPF):             │
│  apiVersion: cilium.io/v2                                     │
│  kind: CiliumNetworkPolicy                                    │
│  metadata:                                                    │
│    name: app-a-to-app-b                                       │
│  spec:                                                        │
│    endpointSelector:                                          │
│    matchLabels:                                               │
│      app: app-a                                               │
│    egress:                                                    │
│    - toEndpoints:                                             │
│      matchLabels:                                             │
│        app: app-b                                             │
│      toPorts:                                                 │
│      - ports:                                                 │
│        - port: "8443"                                         │
│          protocol: TCP                                        │
└──────────────────────────────────────────────────────────────┘
```

## Zero-Trust Network Architecture (BeyondCorp)

```
┌──────────────────────────────────────────────────────────────┐
│           ZERO-TRUST NETWORK ARCHITECTURE                       │
│           (NIST SP 800-207 / Google BeyondCorp)                  │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │                  ZERO TRUST MODEL                      │     │
│  │                                                        │     │
│  │  ┌────────────┐                              ┌────────┐│     │
│  │  │  Subject    │                              │Resource││     │
│  │  │(User/Device)│                              │(App/  │││     │
│  │  └─────┬──────┘                              │Data)  │││     │
│  │        │                                      └───┬────┘│     │
│  │        │         ┌──────────────┐                │      │     │
│  │        ├────────►│   Policy      │───────────────►│      │     │
│  │        │         │  Decision     │                │      │     │
│  │        │         │  Point (PDP)  │                │      │     │
│  │        │         └──────┬───────┘                │      │     │
│  │        │                │                         │      │     │
│  │  ┌─────┴──────┐   ┌────▼─────┐   ┌──────────┐  │      │     │
│  │  │ Identity    │   │  Policy  │   │ Activity │  │      │     │
│  │  │ Provider    │   │  Engine  │   │  Logger  │  │      │     │
│  │  │(IdP/MFA)   │   │ (Rules)  │   │(SIEM)    │  │      │     │
│  │  └────────────┘   └──────────┘   └──────────┘  └──────┘     │
│  │                                                        │     │
│  │  ┌────────────┐   ┌──────────────┐                     │     │
│  │  │ Policy      │   │  Data Store  │                     │     │
│  │  │ Enforcement │   │  (Asset DB)  │                     │     │
│  │  │ Point (PEP) │   └──────────────┘                     │     │
│  │  └────────────┘                                         │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  BeyondCorp Google Implementation:                             │
│  1. Device inventory and certificate trust                    │
│  2. User authentication via SSO/MFA                           │
│  3. Context-aware access policies (device trust + user role)  │
│  4. Per-request authorization (continuous verification)      │
│  5. End-to-end encryption (Access Proxy → Backend)            │
│  6. No VPN required (all access through proxy)                │
│                                                               │
│  SASE (Secure Access Service Edge):                           │
│  ┌──────────────────────────────────────────────┐              │
│  │ SASE combines:                                 │              │
│  │ - SD-WAN (software-defined WAN)               │              │
│  │ - SWG (Secure Web Gateway)                    │              │
│  │ - CASB (Cloud Access Security Broker)         │              │
│  │ - FWaaS (Firewall as a Service)               │              │
│  │ - Zero Trust Network Access (ZTNA)            │              │
│  │ - DLP (Data Loss Prevention)                  │              │
│  │ Delivered as cloud service                    │              │
│  └──────────────────────────────────────────────┘              │
│                                                               │
│  SASE Providers:                                               │
│  - Zscaler (ZIA + ZPA)                                        │
│  - Cloudflare (Access + Gateway)                               │
│  - Palo Alto (Prisma Access)                                   │
│  - Cato Networks (SASE Cloud)                                 │
│  - Netskope (SASE platform)                                   │
└──────────────────────────────────────────────────────────────┘
```

## Firewall Rule Analysis and Optimization

```python
"""
Firewall rule analysis and optimization tool
Identifies shadowed, redundant, and conflicting rules
"""

class FirewallRule:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, 
                 protocol, action, rule_id):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.action = action
        self.rule_id = rule_id

def is_subset(rule_a, rule_b):
    """Check if rule_a is a subset of rule_b (shadowed)"""
    return (is_ip_subset(rule_a.src_ip, rule_b.src_ip) and
            is_port_subset(rule_a.src_port, rule_b.src_port) and
            is_ip_subset(rule_a.dst_ip, rule_b.dst_ip) and
            is_port_subset(rule_a.dst_port, rule_b.dst_port) and
            is_proto_subset(rule_a.protocol, rule_b.protocol))

def analyze_firewall_rules(rules):
    """Analyze firewall rules for issues"""
    issues = []
    
    for i, rule_a in enumerate(rules):
        for j, rule_b in enumerate(rules):
            if i >= j:
                continue
            
            # Shadowed rule: rule_b is shadowed by rule_a
            # (rule_a comes first and matches same or broader traffic)
            if (is_subset(rule_b, rule_a) and 
                rule_a.action != rule_b.action):
                issues.append({
                    'type': 'SHADOWED',
                    'rule': rule_b.rule_id,
                    'shadowed_by': rule_a.rule_id,
                    'description': f'Rule {rule_b.rule_id} is shadowed by '
                                  f'rule {rule_a.rule_id} and will never match'
                })
            
            # Redundant rule: rule_b matches same traffic as rule_a
            if (is_subset(rule_b, rule_a) and 
                is_subset(rule_a, rule_b) and
                rule_a.action == rule_b.action):
                issues.append({
                    'type': 'REDUNDANT',
                    'rule': rule_b.rule_id,
                    'redundant_with': rule_a.rule_id,
                    'description': f'Rule {rule_b.rule_id} is redundant with '
                                  f'rule {rule_a.rule_id}'
                })
            
            # Conflicting rules: same match, different actions
            if (is_subset(rule_b, rule_a) and 
                is_subset(rule_a, rule_b) and
                rule_a.action != rule_b.action):
                issues.append({
                    'type': 'CONFLICTING',
                    'rule': rule_b.rule_id,
                    'conflicts_with': rule_a.rule_id,
                    'description': f'Rule {rule_b.rule_id} conflicts with '
                                  f'rule {rule_a.rule_id} '
                                  f'({rule_a.action} vs {rule_b.action})'
                })
    
    # Find overly permissive rules
    for rule in rules:
        if rule.src_ip == '0.0.0.0/0' and rule.src_port == 'any':
            if rule.dst_port != 'any' and rule.action == 'allow':
                issues.append({
                    'type': 'OVERLYLY_PERMISSIVE',
                    'rule': rule.rule_id,
                    'description': f'Rule {rule.rule_id} allows any source '
                                  f'to {rule.dst_port}'
                })
    
    return issues
```

### Firewall Evasion Techniques

```
┌──────────────────────────────────────────────────────────────┐
│            FIREWALL EVASION TECHNIQUES                          │
│                                                               │
│  1. PROTOCOL TUNNELING                                       │
│  - Tunnel any protocol over allowed protocol                  │
│  - DNS tunneling (see 02a)                                    │
│  - ICMP tunneling (icmptunnel, ptunnel)                       │
│  - HTTP tunneling (CONNECT method)                            │
│  - QUIC tunneling (UDP:443)                                  │
│                                                               │
│  2. FRAGMENTATION                                             │
│  - IP fragmentation to split malicious payload               │
│  - Tiny fragments (8-byte first fragment)                    │
│  - Overlapping fragments (see 04b)                            │
│  - TTL-based evasion                                         │
│                                                               │
│  3. APPLICATION-LAYER EVASION                                │
│  - URL encoding: /admin → /%61dmin                           │
│  - Double encoding: /admin → /%2561dmin                     │
│  - Unicode normalization: /admin → /%c0%af%d1%a0            │
│  - HTTP pipelining                                            │
│  - HTTP/2 binary framing                                     │
│  - WebSocket upgrade                                         │
│                                                               │
│  4. COVERT CHANNELS                                           │
│  - Steganography in protocol headers                         │
│  - Timing channels (inter-packet delays encode data)         │
│  - Size channels (packet sizes encode data)                  │
│  - Acoustic channels (CPU-generated sounds)                   │
│                                                               │
│  5. SOURCE ROUTING                                            │
│  - IP options: LSRR (Loose Source Route Record)               │
│  - IP options: SSRR (Strict Source Route Record)             │
│  - Most firewalls drop source-routed packets                 │
│                                                               │
│  6. PROXY ABUSE                                              │
│  - HTTP CONNECT to any port                                  │
│  - SOCKS proxy to tunnel any protocol                        │
│  - DNS-over-HTTPS to bypass DNS filtering                    │
│                                                               │
│  iptables/nftables evasion examples:                          │
│                                                               │
│  # Block source routing                                      │
│  iptables -A INPUT -m ipv4header --header "lsrr,ssrr" -j DROP│
│                                                               │
│  # Block_fragment overlapped packets                          │
│  nft add rule inet filter input ip frag-off != 0 counter drop│
│                                                               │
│  # Block known covert channels                               │
│  iptables -A INPUT -p icmp --icmp-type echo-reply -m length \│
│    --length 128:65535 -j DROP  # Unusually large ICMP       │
└──────────────────────────────────────────────────────────────┘
```

## Cloud-Native Firewall

### AWS Network Firewall

```yaml
# AWS Network Firewall configuration
# Stateful rule group for detecting malicious traffic
StatefulRuleGroup:
  RuleGroup:
    RulesSource:
      StatefulRules:
        - Action: DROP
          Header:
            Protocol: TCP
            Source: Any
            SourcePort: Any
            Destination: !Ref VpcCidr
            DestinationPort: 22
            Direction: ANY
          RuleOptions:
            - Keyword: sid
              Settings: ['1000001']
        - Action: DROP
          Header:
            Protocol: IP
            Source: Any
            SourcePort: Any
            Destination: Any
            DestinationPort: Any
            Direction: ANY
          RuleOptions:
            - Keyword: content
              Settings: ['"|00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; depth:16;']
            - Keyword: sid
              Settings: ['1000002']

# Suricata-compatible IPS rules in AWS
StatefulRule:
  Action: DROP
  Header:
    Protocol: TCP
    Source: Any
    SourcePort: Any
    Destination: "10.0.0.0/8"
    DestinationPort: "443"
    Direction: ANY
  RuleOptions:
    - Keyword: tls.sni
      Settings: ['"malware-c2.example.com"']
    - Keyword: sid
      Settings: ['1000003']
```

### Azure Firewall

```json
{
  "type": "Microsoft.Network/firewallPolicies",
  "properties": {
    "threatIntelMode": "AlertAndBlock",
    "dnsSettings": {
      "servers": ["168.63.129.16"],
      "enableProxy": true
    },
    "firewallPolicy": {
      "ruleCollectionGroups": [
        {
          "ruleCollections": [
            {
              "name": "Allow-Web-Traffic",
              "priority": 100,
              "action": "Allow",
              "rules": [
                {
                  "name": "Allow-HTTPS",
                  "protocols": [{"port": "443", "type": "Https"}],
                  "targetFqdns": ["*.example.com"],
                  "sourceAddresses": ["10.0.0.0/16"]
                }
              ]
            }
          ]
        }
      ]
    }
  }
}
```

**Cross-references**: See `05b_network_hardening_zero_trust.md` for hardening configurations, `04a_network_attacks_mitm.md` for attacks that firewalls must prevent, `01b_tls_ssl_crypto_protocols.md` for TLS inspection challenges, `03b_vpn_tunnel_security.md` for VPN firewall rules, and Cloud Security track for cloud-native firewall configurations.

## References

1. NIST SP 800-41 Rev. 1 — Guidelines for Firewall and Firewall Policy. K. Scarfone, P. Hoffman, NIST, September 2009.
2. RFC 4949 — Internet Security Glossary, Version 2. R. Shirey, IETF, August 2007.
3. NIST SP 800-207 — Zero Trust Architecture. S. Rose et al., NIST, August 2020.
4. RFC 7944 — Problem Statement for the Creation of a WSDL Extension for the NETCONF. IETF, August 2016.
5.OWASP — Web Application Firewall Evaluation Criteria. OWASP Foundation, 2023.
6. Roesch, M. — Snort: Lightweight Intrusion Detection for Networks. LISA, 1999.
7. OISF — Suricata: A High Performance IDS/IPS/NSM Engine. https://suricata.io/
8. Paxson, V. — Bro: A System for Detecting Network Intruders in Real-Time. USENIX Security, 1998.
9. RFC 3514 — IPv4 Evil Bit. S. Bellovin, IETF, April 2003.
10. AlSharif, H. et al. — HTTP Request Smuggling. DEF CON 27, 2019.
11. Lin, Z. et al. — TCP Splitting: Breaking the TCP Splitting Defense. USENIX Security, 2022.
12. CVE-2021-44228 — Log4Shell: Apache Log4j RCE. NVD, 2021.
13. CVE-2017-0144 — EternalBlue: SMB RCE (MS17-010). NVD, 2017.
14. JA3/JA3S — TLS Fingerprinting for Malware Detection. SalesForce/John Althouse et al., 2017.
15. RFC 8482 — Providing Minimal Responses to ANY DNS Queries. M. Nottingham, IETF, January 2019.
16. RFC 3411 — An Architecture for Describing SNMP Management Frameworks. D. Harrington et al., IETF, December 2002.
17. NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems. K. Scarfone, P. Mell, NIST, February 2007.
18. NSS Labs — Next-Generation Firewall Comparative Report. Various years.
19. Gartner — Magic Quadrant for Network Firewalls. Gartner, 2023.
20. Cloudflare — The QUIC ATTACK: HTTP/3 Flood Disrupts Cloud Infrastructure. Cloudflare Blog, 2023.