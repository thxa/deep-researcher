# VPN and Tunnel Security

## IPsec: Architecture and Security

### IPsec Overview

IPsec (Internet Protocol Security) provides security at the IP layer:

```
┌──────────────────────────────────────────────────────────────┐
│                   IPsec ARCHITECTURE                           │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │                 APPLICATION LAYER                     │     │
│  └─────────────────────┬───────────────────────────────┘     │
│  ┌─────────────────────▼───────────────────────────────┐     │
│  │                 TCP / UDP                             │     │
│  └─────────────────────┬───────────────────────────────┘     │
│  ┌─────────────────────▼───────────────────────────────┐     │
│  │           IPsec PROCESSING                           │     │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────────────┐   │     │
│  │  │   AH    │  │   ESP   │  │  IKE (Key Mgmt)   │   │     │
│  │  │(Auth)   │  │(Enc+Auth)│  │  UDP/500, UDP/4500│   │     │
│  │  └─────────┘  └─────────┘  └──────────────────┘   │     │
│  └─────────────────────┬───────────────────────────────┘     │
│  ┌─────────────────────▼───────────────────────────────┐     │
│  │                   IP LAYER                            │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  IPsec Modes:                                                  │
│                                                               │
│  Transport Mode: Original IP header + IPsec payload           │
│  ┌────────┬───────────┬──────────┐                           │
│  │ Orig IP│ IPsec Hdr │ IPsec    │                           │
│  │ Header │ (AH/ESP) │ Payload  │                           │
│  └────────┴───────────┴──────────┘                           │
│ Protects: Payload only                                        │
│  Use: End-to-end, host-to-host                                │
│                                                               │
│  Tunnel Mode: New IP header + entire original packet          │
│  ┌────────┬───────────┬────────┬──────────┐                 │
│  │ New IP │ IPsec Hdr │ Orig IP│ IPsec     │                 │
│  │ Header │ (AH/ESP) │ Header │ Payload   │                 │
│  └────────┴───────────┴────────┴──────────┘                 │
│  Protects: Entire original packet (headers + payload)         │
│  Use: Gateway-to-gateway, site-to-site VPNs                   │
└──────────────────────────────────────────────────────────────┘
```

### AH vs ESP

```
┌──────────────────────────────────────────────────────────────┐
│           AH (AUTHENTICATION HEADER) - RFC 4302               │
│                                                               │
│  ┌──────┬──────┬────────┬─────────────────┬──────────┐       │
│  │ Next │ Payload│ Reserved │ SPI            │ Sequence  │       │
│  │ Header│ Len   │         │ (32-bit)       │ Number    │       │
│  ├──────┴──────┴────────┴─────────────────┴──────────┤       │
│  │           Integrity Check Value (ICV)              │       │
│  └────────────────────────────────────────────────────┘       │
│                                                               │
│  Provides: Authentication, Integrity, Anti-replay              │
│  Does NOT provide: Confidentiality (no encryption)            │
│  Authenticate: IP header (immutable fields) + payload          │
│  Protocol: 51                                                 │
│                                                               │
│  ESP (ENCAPSULATING SECURITY PAYLOAD) - RFC 4303             │
│                                                               │
│  ┌──────┬──────────┬─────────┬────────┬────────┬────────┐    │
│  │ SPI  │ Sequence  │ IV      │ Payload│ Padding│ Next   │    │
│  │      │ Number   │         │ Data   │        │ Header │    │
│  ├──────┴──────────┴─────────┴────────┴────────┴────────┤    │
│  │           Integrity Check Value (ICV)                  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                               │
│  Provides: Authentication, Integrity, Anti-replay,             │
│            Confidentiality (encryption)                        │
│  Protocol: 50                                                 │
│                                                               │
│  Modern IPsec: ESP only (AH rarely used, no encryption)       │
│  ESP with authentication (AEAD) provides both                  │
│  AH is redundant with ESP-AUTH                                │
└──────────────────────────────────────────────────────────────┘
```

### IKEv1 vs IKEv2

```
┌──────────────────────────────────────────────────────────────┐
│                   IKEv1 (RFC 2409)                              │
│                                                               │
│  Phase 1: Establish ISAKMP SA (Main Mode or Aggressive Mode) │
│  Phase 2: Establish IPsec SA (Quick Mode)                    │
│                                                               │
│  Main Mode (6 messages):                                      │
│  Initiator                     Responder                      │
│  ──── MM1 (SA proposals) ────►                              │
│  ◄─── MM2 (SA choice) ───────                               │
│  ──── MM3 (KE, nonce) ──────►                               │
│  ◄─── MM4 (KE, nonce) ───────                               │
│  ──── MM5 (ID*, hash) ──────►                                │
│  ◄─── MM6 (ID*, hash) ───────                               │
│  * Encrypted after MM4                                       │
│                                                               │
│  Aggressive Mode (3 messages):                                │
│  ──── AM1 (SA, KE, nonce, ID) ──►                          │
│  ◄─── AM2 (SA, KE, nonce, ID, hash) ──                     │
│  ──── AM3 (hash) ───────────────►                           │
│  ⚠ ID sent in cleartext!                                     │
│  ⚠ Reveals identity before authentication                    │
│                                                               │
│  Phase 2 (Quick Mode - 3 messages):                          │
│  ──── QM1 (hash, SA, nonce, ID) ──►                         │
│  ◄─── QM2 (hash, SA, nonce, ID) ──                          │
│  ──── QM3 (hash) ────────────────►                          │
│                                                               │
│  IKEv1 Vulnerabilities:                                       │
│  - Aggressive mode leaks identity (CVE-2002-1628)            │
│  - Dictionary attacks on PSK (ikecrack)                      │
│  - No DPD (Dead Peer Detection) standard                     │
│  - Complex state machine, many implementation bugs           │
│  - No NAT-T standardization (draft only)                     │
│  - No EAP support (XAUTH is non-standard)                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                   IKEv2 (RFC 7296)                              │
│                                                               │
│  Simplified to 4 messages (IKE_SA_INIT + IKE_AUTH):          │
│                                                               │
│  Initiator                     Responder                      │
│  ──── IKE_SA_INIT ──────────►                                │
│       (SAi1, KEi, Ni)                                         │
│  ◄─── IKE_SA_INIT ──────────                                │
│       (SAr1, KEr, Nr, [CERTREQ])                             │
│  ──── IKE_AUTH ─────────────►                                │
│       (IDi, [CERT], [CERTREQ],                                │
│        [IDr], AUTH, SAi2,                                     │
│        TSi, TSr)                                              │
│  ◄─── IKE_AUTH ──────────────                                │
│       (IDr, [CERT], AUTH,                                     │
│        SAr2, TSi, TSr)                                        │
│                                                               │
│  All messages after IKE_SA_INIT are encrypted                 │
│  Identity protected (never in cleartext)                      │
│  Built-in NAT-T (encapsulate in UDP 4500)                    │
│  Built-in DPD (informational exchanges)                      │
│  EAP support (EAP-TLS, EAP-MSCHAPv2, etc.)                  │
│  Mobility and Multihoming (MOBIKE, RFC 4555)                  │
│  Cookie mechanism for DoS protection                          │
│                                                               │
│  IKEv2 Security Improvements over IKEv1:                      │
│  ✓ Identity protection in all modes                          │
│  ✓ Simpler state machine (4 messages vs 6+3)                 │
│  ✓ Mandatory DH exchange (forward secrecy)                    │
│  ✓ Built-in NAT traversal                                    │
│  ✓ EAP authentication support                                │
│  ✓ Cookie DoS protection (RFC 5996)                          │
│  ✓ SA lifetimes and rekeying are cleaner                      │
│  ✓ Informational exchanges are acknowledged                  │
│  ✓ MOBIKE for IP address changes                             │
└──────────────────────────────────────────────────────────────┘
```

### IPsec Common Vulnerabilities

```
┌──────────────────────────────────────────────────────────────┐
│             IPsec VULNERABILITIES                               │
│                                                               │
│  1. IKE Aggressive Mode PSK cracking:                        │
│     - PSK hash can be offline-cracked                        │
│     - ike-scan / ikecrack tools                               │
│     # ike-scan --aggressive --id=vpn --pskcrack=wordlist target│
│     ⚠ Never use Aggressive Mode with PSK                     │
│                                                               │
│  2. ESP replay attacks:                                       │
│     - 32-bit sequence number wraps at 2^32                   │
│     - Extended Sequence Numbers (ESN) mitigates this         │
│                                                               │
│  3. IKE fragmentation attacks:                                │
│     - IKEv1 fragmentation can bypass firewalls (CVE-2016-5361)│
│     - Send IKE fragments to bypass inspection                │
│                                                               │
│  4. Dead Peer Detection (DPD) DoS:                            │
│     - Forge DPD notifications to tear down tunnels            │
│                                                               │
│  5. NAT-T vulnerabilities:                                    │
│     - UDP encapsulation can be inspected/filtered             │
│     - Keepalive spoofing to keep NAT mappings                  │
│                                                               │
│  6. IPsec SA expiration attacks:                              │
│     - Force rekey at specific intervals                       │
│     - Downgrade during rekey (if rekey method permits)       │
│                                                               │
│  CVE-2019-14879: Libreswan IKEv1 state machine flaw           │
│  CVE-2023-38408: OpenSSH (see below)                         │
└──────────────────────────────────────────────────────────────┘
```

## OpenVPN Security Model

```
┌──────────────────────────────────────────────────────────────┐
│                   OPENVPN ARCHITECTURE                          │
│                                                               │
│  ┌──────────────────────────────────────────────────┐        │
│  │ TLS Control Channel                               │        │
│  │  - Certificates, TLS negotiation                  │        │
│  │  - Key exchange (RSA or ECDHE)                    │        │
│  │  - Authentication (certs, PSK, user/pass)        │        │
│  │  - Runs over TCP or UDP                           │        │
│  └──────────────────────┬───────────────────────────┘        │
│                          │ derives                             │
│  ┌──────────────────────▼───────────────────────────┐        │
│  │ Data Channel (Encrypted Tunnel)                    │        │
│  │  - AES-256-GCM (default) or ChaCha20-Poly1305    │        │
│  │  - HMAC-SHA256 for control channel integrity      │        │
│  │  - Separate keys per direction                    │        │
│  │  - Key renegotiation at configurable interval     │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  OpenVPN Security Properties:                                 │
│  ✓ Forward secrecy (with ECDHE)                               │
│  ✓ Certificate-based authentication                          │
│  ✓ Multiple authentication methods (cert, PSK, user/pass)    │
│  ✓ Flexible cryptography (via OpenSSL/mbed TLS)               │
│  ✓ Runs on any port (TCP/UDP) — hard to block               │
│  ✓ NAT traversal built-in                                     │
│  ✓ Replay protection (sequence numbers)                       │
│                                                               │
│  Weaknesses:                                                  │
│  ✗ Single-threaded control channel (performance)              │
│  ✗ No standard for multi-peer (requires /30 subnet per peer) │
│  ✗ Certificate management overhead                             │
│  ✗ UDP mode can be blocked by DPI                             │
│  ✗ L2 mode (TAP) exposes Layer 2 attacks                     │
└──────────────────────────────────────────────────────────────┘
```

### OpenVPN Configuration Hardening

```bash
# OpenVPN server hardening configuration
server 10.8.0.0 255.255.255.0

# TLS configuration
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# Data channel encryption
cipher AES-256-GCM
auth SHA384

# Certificates
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none  # Not needed with ECDHE

# Diffie-Hellman parameters (use ECDHE instead)
dh /etc/openvpn/dh.pem

# Hardening
tls-auth /etc/openvpn/ta.key 0  # HMAC firewall (shared secret)
key-direction 0
tls-crypt /etc/openvpn/tls-crypt.key  # Encrypt control channel

# Replay protection
replay-window 64 15

# Key renegotiation (forward secrecy)
reneg-sec 3600

# Drop privileges after initialization
user nobody
group nogroup

# Persistence
persist-key
persist-tun

# Logging
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

# Prevent DNS leaks
push "dhcp-option DNS 10.8.0.1"
push "block-outside-dns"  # Windows: prevent DNS leak
push "redirect-gateway def1"  # Route all traffic through VPN

# Security limits
max-clients 50
keepalive 10 120
```

## WireGuard Architecture and Security

```
┌──────────────────────────────────────────────────────────────┐
│                  WIREGUARD ARCHITECTURE                        │
│                                                               │
│  WireGuard is a modern VPN protocol designed for simplicity    │
│  and security (formally verified):                             │
│                                                               │
│  ┌───────────┐                              ┌───────────┐    │
│  │  Peer A    │                              │  Peer B    │    │
│  │ PrivKey_A │                              │ PrivKey_B │    │
│  │ PubKey_A  │                              │ PubKey_B  │    │
│  └─────┬─────┘                              └─────┬─────┘    │
│        │                                          │          │
│        │ ──── Noise_IKpsk2 handshake ──────────► │          │
│        │      (1 round trip)                      │          │
│        │                                          │          │
│        │ ══════ Encrypted tunnel ══════════════ │          │
│        │    ChaCha20-Poly1305                     │          │
│        │    (AEAD, no separate HMAC)              │          │
│                                                               │
│  Cryptographic Ingredients:                                    │
│  - Noise protocol framework (Noise_IKpsk2 pattern)          │
│  - Curve25519 (ECDH key exchange)                             │
│  - ChaCha20-Poly1305 (AEAD encryption)                       │
│  - BLAKE2s (hashing, HMAC)                                   │
│  - HKDF (key derivation)                                     │
│                                                               │
│  WireGuard vs OpenVPN vs IPsec:                              │
│  ┌──────────────┬──────────┬──────────┬──────────┐           │
│  │ Property     │ WireGuard│ OpenVPN  │ IPsec    │           │
│  ├──────────────┼──────────┼──────────┼──────────┤           │
│  │ Code lines   │ ~4,000   │ ~100,000 │ ~600,000 │           │
│  │ Crypto       │ ChaCha20 │ OpenSSL  │ Multiple │           │
│  │ Key exchange │ Curve25519│ RSA/ECDHE│ DH/RSA   │           │
│  │ Authentication│ Public key│ Cert/PSK│ PSK/Cert │           │
│  │ Handshake    │ 1-RTT    │ 2-RTT+   │ 2 exchanges│          │
│  │ Stealth     │ Silent   │ Visible  │ Visible  │           │
│  │ Kernel space │ Yes      │ No       │ Yes      │           │
│  │ Fwd secrecy  │ Always   │ Optional │ Optional │           │
│  │ Formal verify│ Yes      │ No       │ Partial  │           │
│  └──────────────┴──────────┴──────────┴──────────┘           │
│                                                               │
│  WireGuard Interface Configuration:                          │
│  [Interface]                                                  │
│  PrivateKey = <private_key_base64>                            │
│  Address = 10.0.0.1/24                                       │
│  ListenPort = 51820                                           │
│  DNS = 1.1.1.1                                                │
│                                                               │
│  [Peer]                                                       │
│  PublicKey = <peer_public_key_base64>                         │
│  PresharedKey = <optional_psk_base64>                         │
│  AllowedIPs = 10.0.0.2/32                                     │
│  Endpoint = peer.example.com:51820                             │
│  PersistentKeepalive = 25                                     │
│                                                               │
│  WireGuard Pre-shared Key (PSK):                              │
│  Adds symmetric key on top of Curve25519 DH                  │
│  Provides quantum resistance fallback                         │
│  If Curve25519 is broken, attacker still needs PSK            │
│  PSK is exchanged out-of-band (recommended)                   │
│                                                               │
│  WireGuard Stealth:                                            │
│  - No response to unauthenticated packets                    │
│  - Random source port per session                             │
│  - Silent dropping = no handshake if keys don't match         │
│  - Indistinguishable from random UDP traffic                  │
│  - Port scanning reveals nothing                              │
└──────────────────────────────────────────────────────────────┘
```

### WireGuard Security Analysis

```
┌──────────────────────────────────────────────────────────────┐
│              WIREGUARD SECURITY ANALYSIS                       │
│                                                               │
│  Strengths:                                                    │
│  1. Minimal attack surface (~4,000 LOC vs ~600,000 for IPsec)│
│  2. Formally verified (Tamarin prover)                         │
│  3. Always forward secret (new DH per session)                 │
│  4. AEAD-only (no separate MAC to get wrong)                  │
│  5. No backward compatibility (no legacy crypto)                │
│  6. Rejects unauthenticated packets (stealth)                  │
│  7. Constant-time crypto (no timing side channels)             │
│  8. No code paths for downgrade                               │
│                                                               │
│  Limitations and Concerns:                                     │
│  1. No identity hiding: Responder learns initiator identity    │
│     before authentication (addressed in RFC with cookie mode)  │
│  2. No user authentication: Public keys = identity             │
│     Need external auth (e.g., SSO, OTP) for user-level access │
│  3. IP roaming: Attacker can sniff session and replay from     │
│     different IP (attack window = REKEY_AFTER_TIME)            │
│  4. No obfuscation: WireGuard packets have identifiable        │
│     structure (4-byte message type at offset)                 │
│  5. IPv6 extension headers not fragmented properly (fixed)     │
│  6. No TCP mode: WireGuard is UDP-only, can be blocked        │
│  7. Key management: Manual key distribution (no PKI/certs)    │
│     Need external orchestration (e.g., Kubernetes, Ansible)    │
│  8. No traffic analysis resistance: Packet sizes/timing leak   │
│     information (all VPNs have this issue)                    │
└──────────────────────────────────────────────────────────────┘
```

## GRE Tunnel Security

```
┌──────────────────────────────────────────────────────────────┐
│               GRE TUNNEL SECURITY                               │
│                                                               │
│  GRE (Generic Routing Encapsulation) - RFC 2784               │
│                                                               │
│  GRE Header:                                                  │
│  ┌────┬────┬──────┬────────┬────────┬─────────┐              │
│  │ C  │ K  │  Seq │  Checksum │ Offset │  Key    │              │
│  │flag│flag│  Num │ (optional) │(opt)   │(optional)│              │
│  └────┴────┴──────┴────────┴────────┴─────────┘              │
│                                                               │
│  Security Issues:                                              │
│  1. GRE is NOT encrypted — plain text encapsulation            │
│  2. GRE key is NOT cryptographic — it's a plaintext identifier│
│  3. GRE checksum is NOT integrity-checked — simple 16-bit     │
│  4. No authentication — anyone can inject GRE packets          │
│  5. GRE over Internet is completely visible                    │
│                                                               │
│  Attack vectors:                                               │
│  - GRE tunnel interception ( sniff unencrypted traffic)        │
│  - GRE tunnel injection ( inject packets into tunnel)         │
│  - GRE tunnel DoS (flood tunnel endpoint)                     │
│  - GRE key brute force (32-bit key space, easily cracked)     │
│  - MTU exploitation (fragmentation attacks)                   │
│                                                               │
│  Secure GRE deployment:                                        │
│  - GRE over IPsec (IPsec provides encryption + auth)          │
│  - GRE over IPSec vs IPSec over GRE ordering matters:          │
│    IPsec over GRE: Inner packet protected, GRE header visible │
│    GRE over IPsec: Entire GRE packet protected                │
│                                                               │
│  # Cisco GRE over IPsec configuration                         │
│  interface Tunnel0                                             │
│   ip address 10.0.0.1 255.255.255.252                          │
│   tunnel source GigabitEthernet0/0                             │
│   tunnel destination 203.0.113.2                              │
│   tunnel mode gre ip                                           │
│   tunnel protection ipsec profile GRE-IPSEC                   │
│  !                                                             │
│  crypto ipsec profile GRE-IPSEC                                │
│   set transform-set ESP-AES256-SHA                             │
│   set pfs group14                                              │
│   set security-association lifetime seconds 3600               │
└──────────────────────────────────────────────────────────────┘
```

## SSH Tunneling

```
┌──────────────────────────────────────────────────────────────┐
│                 SSH TUNNELING                                   │
│                                                               │
│  SSH provides multiple tunneling modes:                        │
│                                                               │
│  1. Local Port Forwarding (-L):                                 │
│  ssh -L 8080:internal_server:80 user@ssh_server                │
│  ┌──────┐    SSH tunnel    ┌──────────┐    Clear-text    ┌───────┐│
│  │Client├─────────────────►SSH Server├─────────────────►│Target ││
│  │:8080 │  (encrypted)    │          │  (from server)   │ :80   ││
│  └──────┘                  └──────────┘                   └───────┘│
│                                                               │
│  2. Remote Port Forwarding (-R):                               │
│  ssh -R 9090:internal_server:80 user@ssh_server                │
│  ┌──────────┐    Clear-text    ┌──────┐   SSH tunnel   ┌───────┐│
│  │Remote    ├─────────────────►│Client├────────────────►│Target ││
│  │:9090     │  (from server)   │      │  (encrypted)   │ :80   ││
│  └──────────┘                  └──────┘                   └───────┘│
│                                                               │
│  3. Dynamic Port Forwarding (-D) (SOCKS proxy):                │
│  ssh -D 1080 user@ssh_server                                   │
│  Creates SOCKS proxy on port 1080                              │
│  All traffic routed through SOCKS → SSH tunnel                │
│                                                               │
│  4. VPN over SSH (-w):                                         │
│  ssh -w 0:0 user@ssh_server                                   │
│  Creates TUN interface, full IP tunnel over SSH               │
│  ⚠ Performance is poor compared to WireGuard/IPsec            │
│  ⚠ Not designed for VPN use (TCP over TCP problem)            │
│                                                               │
│  SSH Security Best Practices:                                  │
│  - Disable password auth: PasswordAuthentication no            │
│  - Use Ed25519 keys: ssh-keygen -t ed25519                    │
│  - Disable root login: PermitRootLogin no                     │
│  - Use AllowUsers / AllowGroups                                │
│  - Set MaxAuthTries 3                                          │
│  - Use 2FA (keyboard-interactive + PAM)                       │
│  - Use certificate-based authentication (ssh-ca)               │
│  - Disable Agent forwarding: AllowAgentForwarding no          │
│  - Disable X forwarding unless needed                          │
│  - Use jump hosts: ProxyJump / -J                              │
│  - Set LoginGraceTime 30                                       │
│  - Use Cryptography: chacha20-poly1305, aes256-gcm            │
│  - MACs: hmac-sha2-512-etm@openssh.com                        │
│  - Kex: curve25519-sha256, diffie-hellman-group16-sha512      │
└──────────────────────────────────────────────────────────────┘
```

### CVE-2023-38408 — OpenSSH Agent Forwarding

```
┌──────────────────────────────────────────────────────────────┐
│         CVE-2023-38408: OPENSSH AGENT FORWARDING               │
│                                                               │
│  Vulnerability: Double-free in OpenSSH PKCS#11 integration    │
│  when SSH agent forwarding is enabled                         │
│                                                               │
│  Attack scenario:                                             │
│  1. User enables SSH agent forwarding (-A flag)               │
│  2. User connects through compromised jump host               │
│  3. Attacker on jump host can use forwarded agent socket      │
│  4. Double-free in PKCS#11 module handling → RCE             │
│                                                               │
│  Impact: Remote code execution on SSH client machine          │
│  when PKCS#11 provider is in use with agent forwarding         │
│                                                               │
│  Affected: OpenSSH 9.3p1 and earlier                          │
│  Fixed: OpenSSH 9.3p2                                         │
│                                                               │
│  Mitigation:                                                  │
│  - Disable agent forwarding unless explicitly needed           │
│  - In sshd_config: AllowAgentForwarding no                    │
│  - In ssh_config: ForwardAgent no                             │
│  - Use ProxyJump (-J) instead of agent forwarding             │
│  - Use ssh-keygen -D to list loaded keys (audit)             │
└──────────────────────────────────────────────────────────────┘
```

## SSTP and L2TP

```
┌──────────────────────────────────────────────────────────────┐
│                    SSTP / L2TP SECURITY                        │
│                                                               │
│  SSTP (Secure Socket Tunneling Protocol):                    │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Protocol: PPP over SSL/TLS (HTTPS/443)            │        │
│  │ Certificate: Server certificate required          │        │
│  │ Client auth: MS-CHAPv2, EAP-TLS, or certificate  │        │
│  │ NAT traversal: Built-in (uses HTTPS)              │        │
│  │ Firewall bypass: Looks like normal HTTPS traffic   │        │
│  │ Platform: Primarily Windows                        │        │
│  │ Security: Relies on TLS security                  │        │
│  │ Vulnerabilities: Same as TLS (see 01b track)      │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  L2TP (Layer 2 Tunneling Protocol):                          │
│  ┌──────────────────────────────────────────────────┐        │
│  │ L2TP: Tunneling only (NO encryption!)              │        │
│  │ Must be combined with IPsec for encryption        │        │
│  │ L2TP/IPsec: L2TP tunnel + IPsec encryption       │        │
│  │                                                   │        │
│  │ L2TP/IPsec double encapsulation:                  │        │
│  │ ┌────┬────┬──────────┬──────┬──────────┐        │        │
│  │ │ IP │ UDP│ L2TP      │ PPP  │ Payload   │        │        │
│  │ │    │1701│ Header    │Frame │           │        │        │
│  │ │    │    │           │      │           │        │        │
│  │ └────┴────┴──────────┴──────┴──────────┘        │        │
│  │ Entire packet wrapped in IPsec ESP              │        │
│  │                                                   │        │
│  │ L2TP/IPsec vulnerabilities:                        │        │
│  │ 1. IPsec PSK vulnerable to offline cracking       │        │
│  │ 2. L2TP has no integrity check without IPsec     │        │
│  │ 3. Double encapsulation = poor performance       │        │
│  │ 4. L2TP control messages not encrypted            │        │
│  │ 5. UDP 1701 exposed to enumeration              │        │
│  │ 6. IPsec IKEv1 aggressive mode + PSK = broke     │        │
│  │ 7. MS-CHAPv2 vulnerabilities (if used for auth)  │        │
│  │                                                   │        │
│  │ L2TP is NOT RECOMMENDED for new deployments      │        │
│  │ Use WireGuard or IKEv2/IPsec instead              │        │
│  └──────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

## VPN Fingerprinting and Blocking

```
┌──────────────────────────────────────────────────────────────┐
│             VPN FINGERPRINTING AND BLOCKING                    │
│                                                               │
│  DPI (Deep Packet Inspection) Signatures:                     │
│                                                               │
│  ┌──────────────┬──────────────────────────────────┐        │
│  │ VPN Protocol  │ Fingerprint Characteristics        │        │
│  ├──────────────┼──────────────────────────────────┤        │
│  │ OpenVPN      │ UDP/TCP on 1194; TLS handshake;    │        │
│  │              │ P_CONTROL_V1 header byte 0x20;    │        │
│  │              │ P_ACK_V1 byte 0x28; Certificate     │        │
│  │              │ exchange visible in cleartext TLS   │        │
│  ├──────────────┼──────────────────────────────────┤        │
│  │ WireGuard    │ UDP on 51820; 148-byte init msg;  │        │
│  │              │ 4-byte type 0x01 at offset 0;      │        │
│  │              │ 32-byte classifier; Curve25519 DH  │        │
│  │              │ MAC is deterministic over public key│        │
│  ├──────────────┼──────────────────────────────────┤        │
│  │ IPsec/IKE   │ UDP 500/4500; IKE header pattern;  │        │
│  │              │ ESP header (SPI, sequence number);  │        │
│  │              │ NAT-T on 4500 with non-ESP marker  │        │
│  ├──────────────┼──────────────────────────────────┤        │
│  │ SSTP         │ HTTPS on 443; SSTP specific HTTP   │        │
│  │              │ headers; SSTP_MSG_CALL_CONNECT_REQ │        │
│  │              │ recognizable framing              │        │
│  └──────────────┴──────────────────────────────────┘        │
│                                                               │
│  Evading VPN Fingerprinting:                                  │
│  1. Obfsproxy / obfs4 (Tor project)                          │
│  2. Shadowsocks (designed for censorship circumvention)        │
│  3. V2Ray / VMess (proxy protocol with encryption)            │
│  4. Stunnel (SSL-encrypt any protocol)                        │
│  5. Cloaking (WireGuard + random padding + obfuscation)      │
│  6. Xray / XTLS (reduces TLS fingerprinting)                  │
│  7. Domain fronting (use front domain over CDN)                │
│  8. QUIC-based VPN (blends with HTTPS/3 traffic)              │
│                                                               │
│  # WireGuard with obfuscation                                 │
│  # udp2raw - obfuscate WireGuard as UDP-over-TCP              │
│  udp2raw -s -l0.0.0.0:12345 -r127.0.0.1:51820 --cipher-mode xor│
│  # Or use AmneziaWG (WireGuard fork with obfuscation)        │
│                                                               │
│  VPN Blocking Methods:                                         │
│  1. IP blocking (block known VPN server IPs)                  │
│  2. Port blocking (block common VPN ports)                   │
│  3. DPI (deep packet inspection of handshake)                 │
│  4. TLS SNI filtering (block known VPN domains)               │
│  5. Statistical traffic analysis (flow duration, volume)      │
│  6. Active probing (connect to suspected VPN, verify)         │
│  7. DNS filtering (block VPN domain resolution)               │
│  8. Bandwidth throttling (slow down VPN-like traffic)         │
└──────────────────────────────────────────────────────────────┘
```

## Split Tunneling Security

```
┌──────────────────────────────────────────────────────────────┐
│            SPLIT TUNNELING SECURITY RISKS                       │
│                                                               │
│  Full Tunnel: All traffic through VPN                          │
│  Split Tunnel: Only specific traffic through VPN              │
│                                                               │
│  ┌──────────────────────────────────────────────────┐        │
│  │ FULL TUNNEL:                                      │        │
│  │                                                   │        │
│  │  Client ──── All Traffic ────► VPN Gateway ────► │        │
│  │                                 └──► Internet     │        │
│  │                                                   │        │
│  │  Security: ✅ All traffic encrypted and inspected │        │
│  │  Performance: ❌ All traffic goes through VPN     │        │
│  │  DNS Leak: ✅ DNS through VPN only               │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  ┌──────────────────────────────────────────────────┐        │
│  │ SPLIT TUNNEL:                                     │        │
│  │                                                   │        │
│  │  Client ──── Corporate Traffic ────► VPN GW ────► │        │
│  │  Client ──── Internet Traffic ────► Direct ────► │        │
│  │                                                   │        │
│  │  Security: ❌ Corporate traffic on same host       │        │
│  │             as potentially compromised internet   │        │
│  │  Performance: ✅ Only corporate traffic tunneled  │        │
│  │  DNS Leak: ❌ DNS may bypass VPN                  │        │
│  │                                                   │        │
│  │  Risks:                                           │        │
│  │  1. Malware on internet side can pivot to VPN     │        │
│  │  2. Reverse path from VPN to internet route       │        │
│  │  3. DNS leaks reveal browsing activity           │        │
│  │  4. IP address leaks via WebRTC/JavaScript       │        │
│  │  5. Routing table conflicts                      │        │
│  │  6. VPN traffic accessible from internet path    │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  Attack: Internet-side malware accesses VPN resources          │
│                                                               │
│  Mitigation for split tunneling:                               │
│  - Host-based firewall blocking cross-route traffic            │
│  - DNS resolution through VPN only                             │
│  - Micro-segmentation between VPN and internet interfaces      │
│  - Network-level policy enforcement (No SIPT)                  │
│  - Zero-trust: Don't trust VPN, verify each request           │
│  - Extended detection (XDR) on endpoint                        │
└──────────────────────────────────────────────────────────────┘
```

## VPN Bypass Techniques

```
┌──────────────────────────────────────────────────────────────┐
│             VPN BYPASS TECHNIQUES                               │
│                                                               │
│  1. IPv6 Bypass (Most Common):                                 │
│  VPN handles IPv4 only, IPv6 traffic leaks directly            │
│  # Test: curl -6 https://ifconfig.co                           │
│  # Fix: Disable IPv6 or route IPv6 through VPN                 │
│  sysctl -w net.ipv6.conf.all.disable_ipv6=1                   │
│                                                               │
│  2. DNS Leak:                                                  │
│  DNS queries bypass VPN tunnel                                │
│  # Test: nslookup leaktest.com                                │
│  # Fix push "dhcp-option DNS 10.8.0.1" in OpenVPN             │
│  # Fix: block-outside-dns (Windows)                            │
│  # Fix: iptables -A OUTPUT -p udp --dport 53 !-d 10.8.0.1 -j DROP│
│                                                               │
│  3. WebRTC Leak (browser):                                    │
│  JavaScript WebRTC reveals real IP                             │
│  # Test: https://browserleaks.com/webrtc                      │
│  # Fix: Disable WebRTC in browser or use VPN with WebRTC block │
│                                                               │
│  4. Route Manipulation:                                        │
│  Add route that overrides VPN:                                 │
│  ip route add 0.0.0.0/1 via <default_gw>                      │
│  # More specific route takes precedence                       │
│                                                               │
│  5. MTU Discovery Attack:                                     │
│  Send packets larger than VPN MTU → fragmentation              │
│  Fragmented packets may bypass VPN inspection                  │
│                                                               │
│  6. DHCP Option Override:                                      │
│  Rogue DHCP server pushes routes that bypass VPN              │
│  # Classless static route option (121, 249)                   │
│  # Fix: Block DHCP from untrusted sources                     │
│                                                               │
│  7. Application-Level Bypass:                                  │
│  Some applications ignore system routing table                 │
│  - P2P clients with bind-to-interface                         │
│  - Games using raw sockets                                    │
│  - VPN client's own update traffic (chicken-and-egg)          │
│                                                               │
│  Comprehensive VPN leak testing:                               │
│  # IP leak test                                               │
│  curl -4 https://api.ipify.org                                │
│  curl -6 https://api.ipify.org                                │
│  # DNS leak test                                              │
│  nslookup whoami.ds.akahelp.net                               │
│  # WebRTC test                                                │
│  # Browser: https://browserleaks.com                          │
│  # Torrent IP test                                            │
│  # Check: https://torrentip.io                                │
└──────────────────────────────────────────────────────────────┘
```

```bash
# iptables rules to prevent VPN bypass
# Block all traffic NOT going through VPN tunnel
iptables -A OUTPUT ! -o tun0 -m owner --uid-owner $(id -u vpn-user) -j DROP
iptables -A OUTPUT -o tun0 -j ACCEPT
iptables -A OUTPUT -d <vpn_server_ip> -p udp --dport 1194 -j ACCEPT
iptables -A OUTPUT -d <vpn_server_ip> -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -j DROP

# nftables equivalent
nft add table ip vpn
nft add chain ip vpn output { type filter hook output priority 0 \; }
nft add rule ip vpn output oifname "tun0" accept
nft add rule ip vpn output ip daddr <vpn_server_ip> udp dport 1194 accept
nft add rule ip vpn output oifname "lo" accept
nft add rule ip vpn output drop
```

## Recent VPN Vulnerabilities

```
┌──────────────────────────────────────────────────────────────┐
│             RECENT VPN VULNERABILITIES                          │
│                                                               │
│  CVE-2019-14879: Libreswap IKEv1 state machine flaw            │
│  - Auth bypass in IKEv1 aggressive mode                       │
│  - Allowed unauthenticated access to IPsec SA                  │
│  - Fixed in Libreswan 3.29                                    │
│                                                               │
│  CVE-2020-15078: WireGuard Windows kernel panic                │
│  - Race condition in WireGuard Windows driver                  │
│  - Kernel panic on unexpected packet                          │
│                                                               │
│  CVE-2021-3618: OpenVPN key material leak                       │
│  - Key material leaked to log files                            │
│  - Info disclosure in OpenVPN 2.5.x                            │
│                                                               │
│  CVE-2021-41824: OpenVPN Access Server RCE                     │
│  - Auth bypass in OpenVPN AS web interface                     │
│  - Leads to unauthenticated RCE                               │
│                                                               │
│  CVE-2022-46200: OpenVPN Access Server SQL injection           │
│  - SQL injection in web interface                              │
│  - Allows auth bypass and data exfiltration                    │
│                                                               │
│  CVE-2023-38408: OpenSSH agent forwarding RCE                  │
│  - Double-free in PKCS#11 integration                         │
│  - RCE when agent forwarding is used with PKCS#11             │
│                                                               │
│  Notable VPN vendor vulnerabilities:                            │
│  - Pulse Secure (CVE-2019-11510): RCE, arbitrary file read   │
│  - Fortinet (CVE-2018-13379): Path traversal, credential leak│
│  - Palo Alto GlobalProtect (CVE-2020-2040): Auth bypass      │
│  - Cisco AnyConnect (CVE-2020-3545): Local privilege escalation│
│  - Citrix ADC (CVE-2019-19781): RCE via directory traversal  │
│  - Ivanti Connect Secure (CVE-2021-22893): RCE              │
│  - Ivanti Policy Secure (CVE-2023-46805): Auth bypass        │
│  - Ivanti (CVE-2024-21893): SSRF to RCE                      │
└──────────────────────────────────────────────────────────────┘
```

**Cross-references**: See `01b_tls_ssl_crypto_protocols.md` for TLS security foundational to VPN protocols, `04a_network_attacks_mitm.md` for MITM attacks against VPN tunnels, `05a_firewall_ids_ips.md` for VPN inspection in firewall architectures, and Cloud Security track for cloud VPN gateway configurations.

## References

1. RFC 4302 — IP Authentication Header (AH). S. Kent, IETF, December 2005.
2. RFC 4303 — IP Encapsulating Security Payload (ESP). S. Kent, IETF, December 2005.
3. RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2). C. Kaufman et al., IETF, October 2014.
4. RFC 2409 — The Internet Key Exchange (IKE). D. Harkins, D. Carrel, IETF, November 1998.
5. RFC 4555 — IKEv2 Mobility and Multihoming (MOBIKE). P. Eronen, IETF, June 2006.
6. Donenfeld, J.A. — WireGuard: Next Generation Kernel Network Tunnel. NDSS, 2017.
7. NIST SP 800-77 Rev. 1 — Guide to IPsec VPNs. W. Barker et al., NIST, July 2020.
8. CVE-2023-38408 — OpenSSH PKCS#11 agent forwarding double-free. NVD, 2023.
9. CVE-2019-11510 — Pulse Secure VPN arbitrary file read. NVD, 2019.
10. CVE-2021-22893 — Pulse Secure VPN auth bypass. NVD, 2021.
11. CVE-2024-21762 — FortiOS out-of-bounds write (SSL VPN). NVD, 2024.
12. CVE-2023-27997 — FortiGate SSL VPN heap overflow. NVD, 2023.
13. RFC 2661 — A Layer 2 Tunneling Protocol (L2TP). W. Townsley et al., IETF, August 1999.
14. RFC 2784 — Generic Routing Encapsulation (GRE). D. Farinacci et al., IETF, March 2000.
15. WireGuard whitepaper — https://www.wireguard.com/papers/wireguard.pdf
16. RFC 5925 — The TCP Authentication Option (TCP-AO). J. Touch et al., IETF, June 2010.
17. RFC 8446 — TLS 1.3 (foundational to modern VPN security). E. Rescorla, IETF, August 2018.
18. CVE-2016-5361 — IKE fragmentation bypass. NVD, 2016.
19. CVE-2019-14879 — Libreswan IKEv1 state machine flaw. NVD, 2019.
20. NIST SP 800-41 Rev. 1 — Guidelines for Firewall and Firewall Policy. K. Scarfone, P. Hoffman, NIST, September 2009.