# Network Hardening and Zero Trust

## CIS Network Device Benchmarks

### Router Hardening (CIS Benchmark)

```
┌──────────────────────────────────────────────────────────────┐
│          CIS ROUTER HARDENING BENCHMARK (ABBREVIATED)         │
│                                                               │
│  1. MANAGEMENT PLANE SECURITY                                  │
│                                                               │
│  1.1 Secure Management Access                                  │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ # Disable unused management protocols                 │     │
│  │ no ip http server           # Disable HTTP            │     │
│  │ no ip http secure-server    # Disable HTTPS (use dedicated)│
│  │ no ip finger                # Disable finger          │     │
│  │ no service config           # Disable auto-config    │     │
│  │ no service pad              # Disable PAD service    │     │
│  │ no service udp-small-servers # Disable echo/discard │     │
│  │ no service tcp-small-servers # Disable echo/discard │     │
│  │ no ip bootp server          # Disable BOOTP          │     │
│  │                                                             │     │
│  │ # SSH configuration (v2 only)                          │     │
│  │ ip domain-name example.com                            │     │
│  │ crypto key generate rsa modulus 4096                  │     │
│  │ ip ssh version 2                                      │     │
│  │ ip ssh time-out 60                                    │     │
│  │ ip ssh authentication-retries 3                       │     │
│  │ line vty 0 4                                         │     │
│  │   transport input ssh          # SSH only, no telnet  │     │
│  │   access-class MGMT-ACL in     # Restrict by ACL     │     │
│  │   login local                  # Local authentication │     │
│  │                                                             │     │
│  │ # Console security                                    │     │
│  │ line con 0                                           │     │
│  │   login local                                        │     │
│  │   exec-timeout 10 0          # 10 minute timeout     │     │
│  │                                                             │     │
│  │ # Enable secret (not enable password)                 │     │
│  │ enable secret <strong_password>              # SHA-256 │     │
│  │ service password-encryption          # Encrypt passwords│     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  1.2 Authentication, Authorization, Accounting (AAA)          │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ # TACACS+ for device administration                    │     │
│  │ aaa new-model                                         │     │
│  │ aaa authentication login default group tacacs+ local   │     │
│  │ aaa authentication enable default group tacacs+ enable │     │
│  │ aaa authorization exec default group tacacs+ local     │     │
│  │ aaa authorization commands 0 default group tacacs+     │     │
│  │ aaa authorization commands 15 default group tacacs+   │     │
│  │ aaa accounting exec default start-stop group tacacs+  │     │
│  │ aaa accounting commands 15 default start-stop group tacacs+│
│  │                                                             │     │
│  │ tacacs-server host 10.0.0.100                         │     │
│  │ tacacs-server key <shared_secret>                     │     │
│  │ ip tacacs source-interface Loopback0                  │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  2. CONTROL PLANE SECURITY                                     │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ # Control Plane Policing (CoPP)                        │     │
│  │ class-map match-any CONTROL-PLANE-CRITICAL            │     │
│  │   match access-group name ACL-OSPF                    │     │
│  │   match access-group name ACL-BGP                     │     │
│  │ class-map match-any CONTROL-PLANE-NORMAL               │     │
│  │   match access-group name ACL-SSH                     │     │
│  │   match access-group name ACL-SNMP                   │     │
│  │ class-map match-any CONTROL-PLANE-EXCESSIVE            │     │
│  │   match access-group name ACL-ICMP                   │     │
│  │                                                             │     │
│  │ policy-map CONTROL-PLANE-POLICY                        │     │
│  │   class CONTROL-PLANE-CRITICAL                         │     │
│  │     police 1000000 10000 conform-action transmit       │     │
│  │       exceed-action drop                               │     │
│  │   class CONTROL-PLANE-NORMAL                           │     │
│  │     police 500000 5000 conform-action transmit         │     │
│  │       exceed-action drop                               │     │
│  │   class CONTROL-PLANE-EXCESSIVE                        │     │
│  │     police 100000 1000 conform-action transmit         │     │
│  │       exceed-action drop                               │     │
│  │                                                             │     │
│  │ control-plane                                           │     │
│  │   service-policy input CONTROL-PLANE-POLICY            │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  3. DATA PLANE SECURITY                                        │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ # Infrastructure ACLs (iACL)                          │     │
│  │ ip access-list extended INFRASTRUCTURE-IN              │     │
│  │   permit tcp 10.0.0.0/8 host 10.0.0.1 eq 22          │     │
│  │   permit udp 10.0.0.0/8 host 10.0.0.1 eq snmp        │     │
│  │   permit tcp 10.0.0.0/8 host 10.0.0.1 eq bgp         │     │
│  │   permit icmp any any echo                             │     │
│  │   deny ip any any log                                 │     │
│  │                                                             │     │
│  │ interface GigabitEthernet0/0                             │     │
│  │   ip access-group INFRASTRUCTURE-IN in                │     │
│  └──────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

### SNMPv3 Configuration

```
┌──────────────────────────────────────────────────────────────┐
│                  SNMP SECURITY                                  │
│                                                               │
│  SNMPv1/v2c: Community string in cleartext — NEVER USE        │
│  SNMPv3: Authentication, encryption, access control            │
│                                                               │
│  # SNMPv3 configuration (Cisco IOS)                           │
│  # Define views (what MIB objects are accessible)             │
│  snmp-server view READONLY iso included                       │
│  snmp-server view READONLY internet included                 │
│  snmp-server view READONLY ifMIB included                    │
│                                                               │
│  # Define user groups                                         │
│  snmp-server group ADMIN-GROUP v3 auth priv read READONLY\    │
│    write READONLY notify READONLY                             │
│  snmp-server group MONITOR-GROUP v3 auth noauth read READONLY│
│                                                               │
│  # Define users                                               │
│  snmp-server user admin ADMIN-GROUP v3 auth sha <auth_pass>\│
│    priv aes 256 <priv_pass>                                   │
│  snmp-server user monitor MONITOR-GROUP v3 auth sha <pass>   │
│                                                               │
│  # Disable SNMPv1/v2c                                         │
│  no snmp-server community public RO                           │
│  no snmp-server community private RW                         │
│                                                               │
│  # SNMPv3 security levels:                                    │
│  # noAuthNoPriv: No authentication, no encryption (INSECURE) │
│  # authNoPriv:  Authentication (SHA/MD5), no encryption      │
│  # authPriv:    Authentication (SHA) + encryption (AES)      │
│                                                               │
│  # SNMPv3 engine ID (important for key localization)           │
│  snmp-server engineID local 80001234567890ABCDEF              │
│                                                               │
│  # Restrict SNMP access by ACL                                │
│  snmp-server group ADMIN-GROUP v3 auth priv access SNMP-ACL  │
│  ip access-list standard SNMP-ACL                             │
│    permit 10.0.0.0 0.0.0.255                                  │
│    deny any log                                                │
└──────────────────────────────────────────────────────────────┘
```

### NTP Authentication

```
┌──────────────────────────────────────────────────────────────┐
│                  NTP AUTHENTICATION                             │
│                                                               │
│  NTP is critical for logging and certificate validation        │
│  Unauthenticated NTP enables time-based attacks:              │
│  - Certificate validation bypass (set time before expiry)    │
│  - Log manipulation (correlate wrong timestamps)             │
│  - Kerberos ticket manipulation (time-skew attacks)          │
│  - OTP token desynchronization                                │
│                                                               │
│  # NTP authentication (Cisco IOS)                              │
│  ntp authenticate                                              │
│  ntp authentication-key 1 md5 <ntp_secret>                    │
│  ntp authentication-key 2 md5 <ntp_secret_2>                  │
│  ntp trusted-key 1                                            │
│  ntp trusted-key 2                                            │
│  ntp server 10.0.0.100 key 1 prefer                           │
│  ntp server 10.0.0.101 key 2                                  │
│  ntp source Loopback0                                          │
│                                                               │
│  # NTP authentication (Linux chrony)                           │
│  # /etc/chrony/chrony.conf                                    │
│  server ntp1.example.com iburst key 1                         │
│  server ntp2.example.com iburst key 2                         │
│  commandkey 1                                                 │
│  localkey 1                                                    │
│  keyfile /etc/chrony/chrony.keys                              │
│                                                               │
│  # /etc/chrony/chrony.keys                                    │
│  1 SHA256:<base64_key_1>                                       │
│  2 SHA256:<base64_key_2>                                       │
│                                                               │
│  # NTP hardening (Linux)                                      │
│  # Bind to specific interface                                  │
│  bindaddress 10.0.0.1                                          │
│  # Deny NTP from untrusted networks                           │
│  deny 0.0.0.0/0                                               │
│  allow 10.0.0.0/8                                              │
│  # Rate limiting                                               │
│  ratelimit interval 1 burst 16                                │
│  # Wait for NTP sync before starting services                 │
│  cmdallow 127.0.0.1                                            │
│  ntsport 4460  # NTS (Network Time Security) port            │
└──────────────────────────────────────────────────────────────┘
```

## 802.1X/NAC

```
┌──────────────────────────────────────────────────────────────┐
│                802.1X / NAC DEEP DIVE                           │
│                                                               │
│  802.1X Port-Based Network Access Control (IEEE 802.1X):     │
│                                                               │
│  ┌───────────┐        ┌────────────────┐    ┌────────┐      │
│  │ Supplicant│──────►│ Authenticator  │───►│Auth    │      │
│  │  (Client) │ EAPOL │   (Switch/AP)  │RADIUS│Server  │      │
│  └───────────┘        └────────────────┘    └────────┘      │
│                                                               │
│  EAPOL (EAP over LAN) Frame:                                  │
│  ┌─────────┬──────────┬───────────┬────────────────────┐   │
│  │ Dest:   │ Src:     │ EtherType │ EAPOL Packet        │   │
│  │01:80:c2│switch MAC│ 0x888e    │ (EAP encapsulated)  │   │
│  │:00:03   │          │           │                      │   │
│  └─────────┴──────────┴───────────┴────────────────────┘   │
│                                                               │
│  EAP Methods:                                                  │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Method       │ Security  │ Use Case                │        │
│  ├──────────────────────────────────────────────────┤        │
│  │ EAP-TLS      │ Strongest │ Certificate-based       │        │
│  │              │ (mutual)  │ Enterprise, IoT          │        │
│  │ EAP-TTLS     │ Strong    │ Server cert + user PW   │        │
│  │              │           │ (Phase 2 auth)           │        │
│  │ PEAP         │ Strong    │ Server cert + MSCHAPv2  │        │
│  │              │           │ Most common enterprise   │        │
│  │ EAP-FAST     │ Moderate  │ PAC-based, Cisco        │        │
│  │ EAP-MSCHAPv2 │ Weak     │ Inside PEAP only         │        │
│  │ EAP-MD5      │ Broken   │ No mutual auth, no TLS  │        │
│  │ LEAP         │ Broken   │ Cisco proprietary,      │        │
│  │              │          │ crackable with asleap    │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  802.1X with MAB (MAC Authentication Bypass):                │
│  For devices that don't support 802.1X (printers, IoT):     │
│  1. Switch sends EAP Identity Request                         │
│  2. No EAP response (timeout)                                │
│  3. Fallback to MAB: use MAC as identity                     │
│  4. RADIUS authenticates MAC address                         │
│  ⚠ MAB is NOT security (MAC is easily spoofed)                │
│                                                               │
│  Dynamic VLAN Assignment:                                     │
│  RADIUS returns VLAN in Access-Accept:                        │
│  Tunnel-Type: 13 (VLAN)                                      │
│  Tunnel-Medium-Type: 6 (802)                                 │
│  Tunnel-Private-Group-Id: 100 (VLAN ID)                     │
│                                                               │
│  # Cisco switch 802.1X configuration                          │
│  aaa new-model                                                │
│  aaa authentication dot1x default group radius                │
│  aaa authorization network default group radius               │
│  radius server radius1                                        │
│   address ipv4 10.0.0.100 auth-port 1812 acct-port 1813     │
│   key <radius_secret>                                         │
│  !                                                             │
│  dot1x system-auth-control                                    │
│  !                                                             │
│  interface GigabitEthernet0/1                                 │
│   switchport mode access                                      │
│   authentication port-control auto                            │
│   dot1x pae authenticator                                     │
│   authentication fallback MAB                                 │
│   mab                                                          │
│   access-session closed                                       │
│   timeoutperiodic 300                                         │
└──────────────────────────────────────────────────────────────┘
```

## VLAN ACLs and Private VLANs

```
┌──────────────────────────────────────────────────────────────┐
│              VLAN ACLs AND PRIVATE VLANS                        │
│                                                               │
│  VLAN Access Control Lists (VACL):                             │
│  Apply ACL to traffic within a VLAN (not between VLANs)       │
│                                                               │
│  # Cisco VACL configuration                                   │
│  ip access-list extended RESTRICTED-SUBNET                    │
│    permit ip 10.0.10.0 0.0.0.255 10.0.20.0 0.0.0.255       │
│    deny ip 10.0.10.0 0.0.0.255 any log                       │
│                                                               │
│  vlan access-map RESTRICTED-MAP 10                            │
│    match ip address RESTRICTED-SUBNET                          │
│    action forward                                              │
│  vlan access-map RESTRICTED-MAP 20                            │
│    match ip address any                                        │
│    action drop                                                 │
│  vlan filter RESTRICTED-MAP vlan-list 10                      │
│                                                               │
│  Private VLANs (PVLAN):                                       │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Primary VLAN 100 (10.0.100.0/24)                 │         │
│  │ ┌────────────────────────────────────────────┐   │         │
│  │ │  Community VLAN 101: Can talk within + promo│   │         │
│  │ │  ┌──────┐ ┌──────┐                        │   │         │
│  │ │  │Host A│ │Host B│ ← Can talk to each      │   │         │
│  │ │  └──────┘ └──────┘    other + promiscuous  │   │         │
│  │ │  Community VLAN 102: Separate community     │   │         │
│  │ │  ┌──────┐ ┌──────┐                        │   │         │
│  │ │  │Host C│ │Host D│ ← Can talk to each      │   │         │
│  │ │  └──────┘ └──────┘    other + promiscuous  │   │         │
│  │ └────────────────────────────────────────────┘   │         │
│  │  Isolated VLAN 103: Cannot talk to any other    │         │
│  │  ┌──────┐ ┌──────┐                              │         │
│  │  │Host E│ │Host F│ ← CANNOT talk to each other │         │
│  │  └──────┘ └──────┘   Can only talk to promisc  │         │
│  │                                                   │         │
│  │  Promiscuous port (router/firewall)              │         │
│  │  ┌──────┐                                         │         │
│  │  │ RTR  │ ← Can talk to ALL PVLAN ports          │         │
│  │  └──────┘                                         │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  # Cisco PVLAN configuration                                  │
│  vlan 100                                                     │
│   private-vlan primary                                        │
│   private-vlan association 101,102,103                        │
│  vlan 101                                                     │
│   private-vlan community                                      │
│  vlan 102                                                     │
│   private-vlan community                                      │
│  vlan 103                                                     │
│   private-vlan isolated                                       │
│  !                                                             │
│  interface GigabitEthernet0/1                                 │
│   switchport mode private-vlan promiscuous                    │
│   switchport private-vlan mapping 100 101-103                  │
│  interface GigabitEthernet0/2                                 │
│   switchport mode private-vlan host                           │
│   switchport private-vlan host-association 100 101            │
└──────────────────────────────────────────────────────────────┘
```

## DHCP Snooping and Dynamic ARP Inspection

```
┌──────────────────────────────────────────────────────────────┐
│         DHCP SNOOPING AND DYNAMIC ARP INSPECTION               │
│                                                               │
│  DHCP SNOOPING:                                                │
│  Builds binding table of legitimate DHCP assignments           │
│  Drops DHCP packets from untrusted ports                       │
│                                                               │
│  ┌──────────────────────────────────────────────────┐         │
│  │ DHCP Snooping Binding Table                       │         │
│  │ MAC          │ IP          │ VLAN │ Lease │ Port │         │
│  │──────────────│─────────────│──────│───────│─────│         │
│  │ aa:bb:cc:dd │ 10.0.1.100 │  10  │ 86400 │ Gi0/1│         │
│  │ ee:ff:00:11 │ 10.0.1.101 │  10  │ 86400 │ Gi0/2│         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  # Cisco DHCP snooping configuration                          │
│  ip dhcp snooping                                              │
│  ip dhcp snooping vlan 10,20                                   │
│  ip dhcp snooping verify mac-address                           │
│  !                                                             │
│  interface GigabitEthernet0/1   ! Trusted (DHCP server)        │
│   ip dhcp snooping trust                                       │
│  !                                                             │
│  interface GigabitEthernet0/2   ! Untrusted (client)           │
│   ip dhcp snooping limit rate 10    ! 10 DHCP pps max          │
│  !                                                             │
│  # Option 82 insertion (adds switch port info)                 │
│  ip dhcp snooping information option                           │
│                                                               │
│  DYNAMIC ARP INSPECTION (DAI):                                  │
│  Uses DHCP snooping table to validate ARP packets              │
│  Drops ARP packets where MAC/IP don't match binding table     │
│                                                               │
│  # Cisco DAI configuration                                     │
│  ip arp inspection vlan 10,20                                  │
│  !                                                             │
│  interface GigabitEthernet0/1   ! Trusted                     │
│   ip arp inspection trust                                      │
│  !                                                             │
│  # For static IPs (not DHCP):                                  │
│  ip arp inspection filter arp-acl vlan 10                      │
│  !                                                             │
│  ip access-list extended ARP-ACL                               │
│   permit ip host 10.0.1.200 mac host aabb.ccdd.eeff           │
│  !                                                             │
│  # Logging                                                    │
│  ip arp inspection log-buffer entries 1024                     │
│  ip arp inspection log-buffer logs 10 interval 60              │
│                                                               │
│  # Linux equivalent (ebtables/arpwatch)                        │
│  # ARP monitoring                                              │
│  arpwatch -i eth0                                             │
│  # Dynamic ARP protection with arptables                      │
│  arptables -A INPUT -s 10.0.1.0/24 --source-mac ! \          │
│    00:11:22:33:44:55 -j DROP                                  │
└──────────────────────────────────────────────────────────────┘
```

## Port Security, BPDU Guard, Root Guard

```
┌──────────────────────────────────────────────────────────────┐
│     PORT SECURITY, BPDU GUARD, AND ROOT GUARD                  │
│                                                               │
│  PORT SECURITY:                                                │
│  Limit MAC addresses per switch port                           │
│                                                               │
│  # Cisco port security configuration                           │
│  interface GigabitEthernet0/1                                 │
│   switchport mode access                                      │
│   switchport port-security                                    │
│   switchport port-security maximum 2        ! Max 2 MACs     │
│   switchport port-security mac-address sticky ! Learn and save│
│   switchport port-security violation restrict ! Drop excess   │
│   ! Violation modes:                                         │
│   ! protect - silently drop excess frames                    │
│   ! restrict - drop and log                                  │
│   ! shutdown - err-disable port (common default)             │
│   !                                                             │
│   switchport port-security aging time 60     ! 60 min aging  │
│   switchport port-security aging type inactivity             │
│                                                               │
│  # Recovery from err-disable                                  │
│  errdisable recovery cause psecure-violation                  │
│  errdisable recovery interval 300    ! Auto-recover after 5m │
│                                                               │
│  BPDU GUARD:                                                  │
│  Prevent unauthorized switches from sending BPDUs             │
│  err-disables port if BPDU received                           │
│                                                               │
│  interface GigabitEthernet0/1                                 │
│   spanning-tree portfast            ! Enable portfast          │
│   spanning-tree portfast bpduguard ! BPDU guard on portfast  │
│  ! In global config:                                          │
│  spanning-tree portfast bpduguard default ! Enable globally   │
│  ! Recovery:                                                 │
│  errdisable recovery cause bpduguard                          │
│  errdisable recovery interval 300                             │
│                                                               │
│  ROOT GUARD:                                                  │
│  Prevent superior BPDUs from being accepted                   │
│  Places port in root-inconsistent state if superior BPDU seen │
│                                                               │
│  interface GigabitEthernet0/24    ! Trunk to access layer     │
│   spanning-tree guard root        ! Root guard enabled       │
│  ! When root guard triggers:                                  │
│  ! Port enters "root-inconsistent" state (blocks)              │
│  ! Recovers when superior BPDUs stop                          │
│  !                                                             │
│  ! Use on ports toward:                                       │
│  ! - Access layer switches                                    │
│  ! - Partner networks                                         │
│  ! - Untrusted spanning-tree participants                     │
│                                                               │
│  BPDU FILTER:                                                 │
│  ! DANGEROUS: Stops sending AND receiving BPDUs               │
│  ! Only use on PORTFAST edge ports where no switch expected   │
│  interface GigabitEthernet0/1                                 │
│   spanning-tree bpdufilter enable                              │
│  ! ⚠ Using bpdufilter can cause loops!                        │
│  ! Prefer bpduguard over bpdufilter                          │
│                                                               │
│  UNIDIRECTIONAL LINK DETECTION (UDLD):                        │
│  ! Detect broken fiber links where one direction fails         │
│  udld enable                    ! Global enable               │
│  interface GigabitEthernet0/1                                 │
│   udld port aggressive          ! Aggressive mode            │
│  ! Aggressive: err-disable after 8 failed probes              │
│  ! Normal: Log warning only                                    │
└──────────────────────────────────────────────────────────────┘
```

## Zero Trust Implementation — NIST SP 800-207

```
┌──────────────────────────────────────────────────────────────┐
│     ZERO TRUST IMPLEMENTATION (NIST SP 800-207)                │
│                                                               │
│  Zero Trust Architecture Components:                           │
│                                                               │
│  ┌───────────────┐  ┌──────────────────────────────┐        │
│  │   Policy       │  │     Policy Engine            │        │
│  │   Decision     │◄─┤     (PDP)                    │        │
│  │   Point        │  │                               │        │
│  │   (PDP)        │  │  Inputs:                      │        │
│  │                │  │  ┌──────────────────────────┐ │        │
│  └───────┬────────┘  │  │ Enterprise Compliance    │ │        │
│          │            │  │ Identity & Credential    │ │        │
│  ┌───────▼────────┐  │  │ Risk Assessment         │ │        │
│  │   Policy        │  │  │ Threat Intelligence      │ │        │
│  │   Enforcement   │  │  │ SIEM/Data Analytics      │ │        │
│  │   Points (PEPs) │  │  │ Activity Logs            │ │        │
│  │                 │  │  └──────────────────────────┘ │        │
│  │  ┌───────────┐  │  └──────────────────────────────┘        │
│  │  │ Gateway/  │  │                                         │
│  │  │ Proxy     │  │  ┌──────────────────────────────┐        │
│  │  └───────────┘  │  │     Trust Algorithm            │        │
│  │  ┌───────────┐  │  │                               │        │
│  │  │ Micro-seg  │  │  │  Score = f(identity, device,  │        │
│  │  │ Agent      │  │  │    context, risk, behavior)   │        │
│  │  └───────────┘  │  │                               │        │
│  │  ┌───────────┐  │  │  If score >= threshold:       │        │
│  │  │ Endpoint   │  │  │    → Allow                    │        │
│  │  │ Agent      │  │  │  Else:                        │        │
│  │  └───────────┘  │  │    → Deny / Step-up auth      │        │
│  └─────────────────┘  └──────────────────────────────┘        │
│                                                               │
│  Tenets of Zero Trust (NIST SP 800-207):                      │
│  1. All data sources and computing services are resources     │
│  2. All communication is secured regardless of network location│
│  3. Access to resources is granted on a per-session basis     │
│  4. Access to resources is determined by dynamic policy        │
│  5. Enterprise monitors all owned and associated assets        │
│  6. All resource authentication/authorization is dynamic       │
│  7. Enterprise collects as much info as possible for security  │
│  8. All data flows are explicitly authorized                   │
│  9. Non-enterprise infrastructure is treated as hostile       │
│  10. Every flow is encrypted, authenticated, authorized        │
└──────────────────────────────────────────────────────────────┘
```

### Micro-Segmentation with Identity Context

```
┌──────────────────────────────────────────────────────────────┐
│     MICRO-SEGMENTATION WITH IDENTITY CONTEXT                   │
│                                                               │
│  Traditional: Network-based segmentation only                  │
│  Identity-aware: Network + Identity + Context + Risk          │
│                                                               │
│  ┌─────────────────────────────────────────────────┐         │
│  │         TRUST EVALUATION                          │         │
│  │                                                    │         │
│  │  Input Signals:                                    │         │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐          │         │
│  │  │ Identity │ │  Device  │ │  Context  │          │         │
│  │  │ (Who)    │ │  (What)  │ │ (Where/  │          │         │
│  │  │          │ │          │ │  When)   │          │         │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘          │         │
│  │       │             │             │                  │         │
│  │  ┌────▼─────────────▼─────────────▼────────────┐  │         │
│  │  │            TRUST SCORE                        │  │         │
│  │  │  Identity:  User role, group, MFA status    │  │         │
│  │  │  Device:    Posture, compliance, cert status │  │         │
│  │  │  Context:   Location, time, behavior, risk   │  │         │
│  │  └────────────────┬────────────────────────────┘  │         │
│  │                    │                                │         │
│  │  ┌─────────────────▼─────────────────────────────┐│         │
│  │  │          POLICY DECISION                        ││         │
│  │  │  Trust Score >= 80 → Allow                     ││         │
│  │  │  Trust Score 60-79 → Allow with restrictions  ││         │
│  │  │  Trust Score 40-59 → Step-up MFA              ││         │
│  │  │  Trust Score < 40 → Deny                       ││         │
│  │  └───────────────────────────────────────────────┘│         │
│  └─────────────────────────────────────────────────┘         │
│                                                               │
│  Implementation Technologies:                                 │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Technology          │ Identity-Aware Capability   │         │
│  ├──────────────────────┼────────────────────────────┤         │
│  │ VMware NSX           │ Group-based micro-seg      │         │
│  │ Cisco ACI            │ Contract-based with EPGs    │         │
│  │ Illumio              │ Application dependency map │         │
│  │ Guardicore           │ Process-level segmentation │         │
│  │ Cilium (eBPF)        │ Identity-aware network pol │         │
│  │ AWS Security Groups │ EC2 instance-level          │         │
│  │ Azure NSG + JIT     │ VM-level + JIT access       │         │
│  │ GCP VPC Firewall    │ Tag-based network policies  │         │
│  │ Istio (service mesh)│ mTLS + authorization policy │         │
│  │ SPIFFE/SPIRE         │ Workload identity framework │         │
│  │ Zscaler ZPA          │ Per-app zero-trust access   │         │
│  └──────────────────────┴────────────────────────────┘         │
└──────────────────────────────────────────────────────────────┘
```

### Network Access Control Evolution

```
┌──────────────────────────────────────────────────────────────┐
│           NETWORK ACCESS CONTROL EVOLUTION                      │
│                                                               │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Generation 1: MAC-based (early 2000s)              │         │
│  │ - Port security / MAC whitelisting                 │         │
│  │ - Easily spoofed                                   │         │
│  │ - No identity context                               │         │
│  │ - Manual management                                 │         │
│  └──────────────────────────────────────────────────┘         │
│                        │                                       │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Generation 2: 802.1X-based (mid-2000s)            │         │
│  │ - RADIUS authentication                            │         │
│  │ - Certificate or credential-based                  │         │
│  │ - Dynamic VLAN assignment                          │         │
│  │ - Limited device profiling                          │         │
│  │ - IoT/MAB fallback (weak)                          │         │
│  └──────────────────────────────────────────────────┘         │
│                        │                                       │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Generation 3: Context-aware (2010s)                │         │
│  │ - Posture assessment (OS version, AV, patch level)│         │
│  │ - Profiling (device type, OS detection)            │         │
│  │ - BYOD onboarding                                   │         │
│  │ - Guest management                                  │         │
│  │ - Cisco ISE, Aruba ClearPass, Forescout             │         │
│  └──────────────────────────────────────────────────┘         │
│                        │                                       │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Generation 4: Zero-trust (2020s)                   │         │
│  │ - Identity + device + context = trust score         │         │
│  │ - Continuous assessment                             │         │
│  │ - Software-defined perimeter (SDP)                 │         │
│  │ - Agent-based ZTNA                                  │         │
│  │ - Cloud-native (Zscaler, Cloudflare, Palo Alto)   │         │
│  │ - No network-level access (app-level only)         │         │
│  │ - Continuous trust evaluation                      │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Key NAC Vendors and Capabilities:                             │
│  ┌──────────────────────────────────────────────────┐         │
│  │ Cisco ISE: 802.1X, MAB, Posture, Profiling, pxGrid│         │
│  │ Aruba ClearPass: 802.1X, Posture, Onboard, Guest │         │
│  │ Forescout: Agentless NAC, Device visibility        │         │
│  │ Portnox: Cloud-native NAC, Zero-trust              │         │
│  │ Zscaler ZPA: Zero-trust, no VPN, per-app access  │         │
│  │ Cloudflare Access: Identity-based, no VPN         │         │
│  │ BeyondTrust: PAM + Zero-trust                     │         │
│  └──────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────┘
```

### Linux Network Hardening with nftables

```bash
#!/bin/bash
# Comprehensive Linux network hardening with nftables

# Create nftables ruleset
nft flush ruleset

# Define tables
nft add table inet filter
nft add table inet security
nft add table ip nat

# ============================================
# MAIN FIREWALL RULESET
# ============================================

nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop ; }'
nft add chain inet filter forward '{ type filter hook forward priority 0 ; policy drop ; }'
nft add chain inet filter output '{ type filter hook output priority 0 ; policy accept ; }'

# Loopback
nft add rule inet filter input iif lo accept
nft add rule inet filter output oif lo accept

# Conntrack (stateful)
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input ct state invalid drop
nft add rule inet filter forward ct state established,related accept
nft add rule inet filter forward ct state invalid drop

# NEW connections - rate limiting
nft add rule inet filter input ct state new ct timeout tcp established 600s
nft add rule inet filter input ct state new meter syn_flood \{ ip saddr limit rate 10/second \} accept
nft add rule inet filter input ct state new tcp flags syn drop

# ICMP
nft add rule inet filter input icmp type echo-request limit rate 5/second accept
nft add rule inet filter input icmp type { destination-unreachable, time-exceeded, parameter-problem } accept

# SSH with brute force protection
nft add rule inet filter input tcp dport 22 ct state new meter ssh_flood \{ ip saddr limit rate 3/minute \} accept

# Services
nft add rule inet filter input tcp dport { 80, 443 } accept
nft add rule inet filter input udp dport 51820 accept  # WireGuard

# Drop everything else with logging
nft add rule inet filter input log prefix "nftables-drop: " drop

# ============================================
# SECURITY HARDENING (System Parameters)
# ============================================

# Disable IP forwarding unless needed
sysctl -w net.ipv4.ip_forward=0

# Reverse path filtering (BCP 38)
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Disable source routing
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0

# Disable ICMP redirects
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

# Disable ICMP redirects for IPv6
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0

# Log martians (packets from impossible addresses)
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1

# SYN cookies (SYN flood protection)
sysctl -w net.ipv4.tcp_syncookies=1

# Disable IP source routing
sysctl -w net.ipv4.conf.all.accept_source_route=0

# TCP hardening
sysctl -w net.ipv4.tcp_rfc1337=1  # TIME_WAIT assassination protection
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2

# Disable unused protocols
sysctl -w net.ipv6.conf.all.disable_ipv6=1  # If IPv6 not used

# Bogon filtering (private/unroutable addresses on external interfaces)
nft add set inet filter bogons '{ type ipv4_addr ; flags interval ; }'
nft add element inet filter bogons { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, \
  127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, \
  192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, \
  224.0.0.0/4, 240.0.0.0/4 }
nft add rule inet filter input iifname "eth0" ip saddr @bogons drop
```

**Cross-references**: See `01a_network_architecture_security.md` for network architecture fundamentals, `04a_network_attacks_mitm.md` for attacks that these hardening measures prevent, `05a_firewall_ids_ips.md` for firewall architecture, and `03b_vpn_tunnel_security.md` for VPN hardening. Linux Kernel track covers eBPF-based network security (Cilium, XDP), and Cloud Security track covers cloud-specific network hardening.

## References

1. NIST SP 800-207 — Zero Trust Architecture. S. Rose, O. Borchert, S. Mitchell, S. Connelly, NIST, August 2020.
2. NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations. NIST, September 2020.
3. NIST SP 800-124 Rev. 2 — Guidelines for Managing the Security of Mobile Devices in the Enterprise. NIST, February 2023.
4. CIS Benchmarks — Center for Internet Security. https://www.cisecurity.org/cis-benchmarks/
5. RFC 8446 — TLS Protocol Version 1.3. E. Rescorla, IETF, August 2018.
6. RFC 6239 — Suitability of RFC 2401bis for Mobile IPv6. J. Arkko et al., IETF, May 2011.
7. RFC 4941 — Privacy Extensions for Stateless Address Autoconfiguration in IPv6. T. Narten et al., IETF, September 2007.
8. RFC 8200 — IPv6 Specification. S. Deering, R. Hinden, IETF, July 2017.
9. CVE-2019-11510 — Pulse Secure VPN arbitrary file read. NVD, 2019.
10. CVE-2021-22893 — Pulse Secure VPN auth bypass. NVD, 2021.
11. CVE-2024-21762 — FortiOS out-of-bounds write (SSL VPN). NVD, 2024.
12. BeyondCorp — A New Approach to Enterprise Security. D. Beyer et al., Google, 2014.
13. NIST SP 800-41 Rev. 1 — Guidelines for Firewall and Firewall Policy. K. Scarfone, P. Hoffman, NIST, September 2009.
14. RFC 7512 — PKCS #12: Personal Information Exchange Syntax. NIST/ICG, April 2015.
15. IEEE 802.1X — Port-Based Network Access Control. IEEE, 2010.
16. RFC 3748 — Extensible Authentication Protocol (EAP). B. Aboba et al., IETF, June 2004.
17. Cilium — eBPF-based Networking, Observability, Security. https://cilium.io/
18. Falco — Cloud Native Runtime Security. https://falco.org/
19. NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management. NIST, June 2017.
20. RFC 7616 — HTTP Digest Access Authentication. R. Shekh-Yusef et al., IETF, September 2015.