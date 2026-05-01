# WiFi and Bluetooth Security

## WEP Cryptanalysis

### WEP Architecture and Flaws

Wired Equivalent Privacy (802.11b) was the original WiFi encryption standard, now completely broken:

```
┌──────────────────────────────────────────────────────────────┐
│                    WEP ARCHITECTURE                            │
│                                                               │
│  WEP uses RC4 stream cipher with 24-bit IV (Initialization   │
│  Vector) prepended to the key:                                │
│                                                               │
│  Per-Packet Key = IV (24-bit) || WEP Key (40/104-bit)        │
│  Keystream = RC4(Per-Packet Key)                              │
│  Ciphertext = Plaintext XOR Keystream                        │
│  ICV = CRC32(Plaintext)                                      │
│  ICV encrypted with same keystream                            │
│                                                               │
│  WEP Frame:                                                  │
│  ┌────┬─────┬────────────────────────────────┬─────┐         │
│  │ IV │ Pad │     Encrypted Payload          │ ICV │         │
│  │24b │6bit │                                 │32b │         │
│  └────┴─────┴────────────────────────────────┴─────┘         │
│                                                               │
│  Critical Flaws:                                              │
│  1. 24-bit IV space = only 16,777,216 possible IVs           │
│  2. IV is transmitted in cleartext                            │
│  3. CRC32 is linear (not cryptographically strong)           │
│  4. Key reuse: Same IV + same key = same keystream           │
│  5. No replay protection                                      │
│  6. No key management (single shared key for all stations)    │
└──────────────────────────────────────────────────────────────┘
```

### FMS Attack (Fluhrer, Mantin, Shamir — 2001)

```
┌──────────────────────────────────────────────────────────────┐
│                    FMS ATTACK                                  │
│                                                               │
│  RC4 Key Scheduling Algorithm (KSA) vulnerability:            │
│                                                               │
│  For IVs of form (A + 3, N + ff, X) where:                   │
│  - A = first byte of IV                                       │
│  - N = second byte of IV (specific value)                     │
│  - X = any value                                              │
│                                                               │
│  These "resolved" or "weak" IVs leak information about      │
│  the key bytes through the first output byte of RC4.         │
│                                                               │
│  Algorithm:                                                   │
│  1. Collect packets with weak IVs                              │
│  2. For each weak IV, compute key byte probability            │
│  3. Statistical analysis reveals key bytes                     │
│  4. ~5 million packets for 128-bit key (practical)            │
│  5. ~1-5 million packets for 64-bit key (a few hours)         │
│                                                               │
│  Weak IV pattern: (3, 255, X), (7, 255, X), etc.             │
│  Approximately 9,000 weak IVs per 128-bit key byte             │
│                                                               │
│  Detection: Large number of packets with weak IVs              │
│  Mitigation (historical): Block weak IVs in firmware          │
│  True mitigation: Use WPA2/WPA3 (AES-CCMP/ GCMP)             │
└──────────────────────────────────────────────────────────────┘
```

### PTW Attack (Pyshkin, Tews, Weinmann — 2007)

PTW improved on FMS dramatically, requiring far fewer packets:

```python
# PTW Attack reduces packet requirement to ~40,000 packets
# for 104-bit WEP key (128-bit WEP)
#
# Key insight: Uses Klein's correlation between RC4 KSA
# and key bytes across ALL IVs (not just "weak" ones)
#
# PTW Attack Steps:
# 1. Capture ~40,000 ARP packets (use ARP replay to accelerate)
# 2. For each captured packet, compute key byte candidates
# 3. Use Klein's attack to determine key bytes with high probability
# 4. Variance analysis: correct key byte has lowest variance
#
# Practical attack time: 1-5 minutes with ARP replay

# Aircrack-ng PTW attack
# Step 1: Start monitor mode
airmon-ng start wlan0

# Step 2: Capture packets
airodump-ng --channel 6 --write wep_capture wlan0mon

# Step 3: Accelerate with ARP replay
aireplay-ng --arpreplay -b <AP_MAC> -h <Client_MAC> wlan0mon

# Step 4: Crack with PTW (default in aircrack-ng)
aircrack-ng -b <AP_MAC> wep_capture-01.cap
# Typically cracks with ~40,000 IVs
```

## WPA/WPA2 4-Way Handshake

### 4-Way Handshake Protocol

```
┌──────────────────────────────────────────────────────────────┐
│              WPA2 4-WAY HANDSHAKE                              │
│                                                               │
│  Station (STA)                     Access Point (AP)          │
│       │                                  │                    │
│       │ PMK = PBKDF2(PSK, SSID, 4096)   │                    │
│       │ Both derive PMK independently    │                    │
│       │                                  │                    │
│       │ ──── Message 1 ───────────────► │                    │
│       │      ANonce (AP nonce)           │                    │
│       │      Key Data: empty             │                    │
│       │                                  │                    │
│       │ PTK = PRF(PMK, "Pairwise key expansion",              │
│       │          min(AA,SPA) || max(AA,SPA) ||                │
│       │          min(ANonce,SNonce) || max(ANonce,SNonce))    │
│       │                                  │                    │
│       │ ◄─── Message 2 ──────────── │                    │
│       │      SNonce (STA nonce)          │                    │
│       │      MIC (over EAPOL frame)      │                    │
│       │      Key Data: RSN IE            │                    │
│       │                                  │                    │
│       │ ──── Message 3 ───────────────► │                    │
│       │      ANonce (confirm)            │                    │
│       │      MIC                         │                    │
│       │      Key Data: Encrypted GTK     │                    │
│       │      "Install PTK" flag          │                    │
│       │                                  │                    │
│       │ ◄─── Message 4 ──────────── │                    │
│       │      MIC                         │                    │
│       │      "Install keys" confirmation │                    │
│       │                                  │                    │
│       │ ══════ Keys Installed ═════════ │                    │
│       │ ══════ Encrypted Traffic ═══════ │                    │
│                                                               │
│  Key Hierarchy:                                               │
│  PSK (Passphrase)                                             │
│    └── PMK = PBKDF2-SHA1(PSK, SSID, 4096 iterations)       │
│        └── PTK = PRF-512(PMK, "Pairwise key expansion", ...) │
│            ├── EAPOL-KCK (Key Confirmation Key, 128-bit)     │
│            ├── EAPOL-KEK (Key Encryption Key, 128-bit)       │
│            └── TK (Temporal Key, 128/256-bit)                │
│                                                               │
│  GTK (Group Temporal Key)                                     │
│    └── Derived by AP, distributed in Message 3                │
│        └── GTK = PRF(GMK, "Group key expansion", ...)        │
└──────────────────────────────────────────────────────────────┘
```

### Dictionary Attack on WPA2 Handshake

```python
# WPA2 passphrase cracking methodology
# 
# 1. Capture 4-way handshake
# 2. Extract: SSID, AP MAC, STA MAC, ANonce, SNonce, MIC, EAPOL frame
# 3. For each candidate passphrase:
#    a. Derive PMK = PBKDF2-SHA1(passphrase, SSID, 4096)
#    b. Derive PTK from PMK + handshake parameters
#    c. Compute MIC using PTK's KCK
#    d. Compare computed MIC with captured MIC
#    e. If match: passphrase found

import hashlib
import hmac
from pbkdf2 import PBKDF2

def derive_ptk(pmk, aa, spa, anonce, snonce):
    """Derive PTK from PMK and handshake parameters"""
    # Concatenate addresses and nonces (min/max ordering)
    if aa < spa:
        ptk_input = aa + spa + anonce + snonce
    else:
        ptk_input = spa + aa + snonce + anonce
    
    ptk = hmac.new(pmk, 
                   b"Pairwise key expansion" + ptk_input,
                   hashlib.sha1).digest()
    return ptk[:48]  # KCK(16) + KEK(16) + TK(16)

def crack_wpa2(ssid, ap_mac, sta_mac, anonce, snonce, captured_mic):
    """Dictionary attack on WPA2 handshake"""
    wordlist = open("wordlist.txt", "r")
    
    for passphrase in wordlist:
        passphrase = passphrase.strip()
        
        # Derive PMK
        pmk = PBKDF2(passphrase, ssid, 4096, hmac_sha1).read(32)
        
        # Derive PTK
        ptk = derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
        
        # Extract KCK (first 16 bytes of PTK)
        kck = ptk[:16]
        
        # Compute MIC
        computed_mic = hmac.new(kck, eapol_frame, hashlib.md5).digest()
        
        if computed_mic == captured_mic:
            print(f"Passphrase found: {passphrase}")
            return passphrase
    
    return None

# In practice, use hashcat or aircrack-ng for GPU-accelerated cracking
# hashcat -m 22000 handshake.hc22000 wordlist.txt
# aircrack-ng -w wordlist.txt handshake.cap
```

### PMKID Attack (CVE-2019-9483?)

```
┌──────────────────────────────────────────────────────────────┐
│                   PMKID ATTACK                                │
│                                                               │
│  PMKID = HMAC-SHA1(PMK, "PMK Name" || AA || SPA)            │
│                                                               │
│  Sent by AP in EAPOL frame during RSN IE (Robust Security     │
│  Network Information Element) in first message of 4-way      │
│  handshake or via Association frame.                           │
│                                                               │
│  Attack:                                                      │
│  1. Send association request to AP                             │
│  2. AP responds with PMKID in EAPOL-Key frame                 │
│  3. PMKID can be directly compared with PMK candidates        │
│  4. No need to wait for full 4-way handshake!                │
│  5. No need for a connected client on the network             │
│                                                               │
│  Advantage over traditional handshake capture:                │
│  - Don't need a client connected to the network               │
│  - Don't need to wait for handshake                           │
│  - Can trigger PMKID from AP at any time                      │
│  - Much faster capture                                        │
│                                                               │
│  Only works on APs that send PMKID (most modern APs do)      │
│                                                               │
│  # hcxdumptool to capture PMKID                               │
│  hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=3   │
│                                                               │
│  # Convert to hashcat format                                  │
│  hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng                 │
│                                                               │
│  # Crack with hashcat                                         │
│  hashcat -m 22000 pmkid.hc22000 wordlist.txt                  │
└──────────────────────────────────────────────────────────────┘
```

## KRACK Attacks (CVE-2017-13077 through CVE-2017-13088)

### Key Reinstallation Attacks

KRACK exploits a vulnerability in the 4-way handshake's key installation process:

```
┌──────────────────────────────────────────────────────────────┐
│                    KRACK ATTACK                                 │
│                                                               │
│  Normal Message 3 → Message 4:                                │
│  AP ──── Msg3 (ANonce, Install PTK) ────► STA              │
│  STA installs PTK, sends Msg4                              │
│  AP receives Msg4, installs PTK                              │
│                                                               │
│  KRACK: Force reinstalls of the already-in-use key           │
│                                                               │
│  Attack on Client (STA):                                      │
│  AP ──── Msg3 ────► [BLOCKED by attacker]                   │
│  STA never receives Msg3, doesn't install PTK                │
│  STA sends Msg4 (using PTK from Msg2)                       │
│  Attacker blocks Msg3, retransmits Msg3                     │
│  STA reinstalls PTK with same nonce → nonce reuse!           │
│                                                               │
│  Impact of nonce reuse:                                       │
│  - Same nonce + same key = same keystream                     │
│  - For CCMP (AES-CTR): packet number resets → replay        │
│  - For TKIP: RC4 key reuse → keystream recovery              │
│  - For GCMP: nonce reuse → authentication key leakage        │
│                                                               │
│  CVE Assignments:                                             │
│  CVE-2017-13077: Reinstallation of PTK in 4-way handshake    │
│  CVE-2017-13078: Reinstallation of GTK in 4-way handshake   │
│  CVE-2017-13079: Reinstallation of Integrity Group Key       │
│  CVE-2017-13080: Reinstallation of PTK in Fast BSS Transition│
│  CVE-2017-13081: Reinstallation of GTK in group handshake    │
│  CVE-2017-13082: Accepting retransmitted Msg3                │
│  CVE-2017-13084: Reinstallation of PTK in PeerKey handshake │
│  CVE-2017-13086: Reinstallation of PTK in TDLS handshake    │
│  CVE-2017-13087: Reinstallation of PTK in IBSS              │
│  CVE-2017-13088: Reinstallation of GTK in IBSS              │
│                                                               │
│  Most severe: Android and Linux clients                       │
│  (wpa_supplicant reinstalled all-zero key on block 3)         │
│  → No encryption at all!                                      │
└──────────────────────────────────────────────────────────────┘
```

```python
# KRACK-specific: TKIP nonce reset attack
# 
# When nonce is reset (via Message 3 retransmission):
# 1. Client reinstalls PTK with old nonce
# 2. Packets are encrypted with same nonce as before
# 3. For TKIP: Same RC4 key + same IV = same keystream
# 4. XOR two packets encrypted with same keystream:
#    P1 XOR P2 = C1 XOR C2 (XORing ciphertexts reveals plaintext XOR)
#
# Practical impact for CCMP (AES-CTR):
# - Packet counter resets → frames with reused IV
# - Can replay previously sent frames
# - Can decrement packet counter for selective replay
#
# For GCMP (used in 60 GHz Wi-Fi / WiGig):
# - Nonce reuse reveals authentication key
# - GCMP uses same key for encryption AND authentication
# - This is CATASTROPHIC: complete key recovery

# Mitigation: Update wpa_supplicant/hostapd, apply patches
# Key: Only install PTK once, ignore retransmissions
```

## WPA3/SAE

```
┌──────────────────────────────────────────────────────────────┐
│                 WPA3 / SAE (SIMULTANEOUS AUTHENTICATION       │
│                          OF EQUALS)                           │
│                                                               │
│  WPA3 replaces PSK with SAE (Dragonfly Key Exchange)          │
│                                                               │
│  SAE Protocol:                                               │
│  STA                                       AP                │
│   │                                         │                │
│   │ ──── Commit (element, scalar) ────────► │                │
│   │ ◄─── Commit (element, scalar) ──────── │                │
│   │                                         │                │
│   │ Both compute: PWE = hash(password)       │                │
│   │ K = scalar1 * element2 + scalar2 * ...   │                │
│   │ PMK = KDF(K, "SAE PMK", ...)            │                │
│   │                                         │                │
│   │ ──── Confirm (token) ──────────────────► │                │
│   │ ◄─── Confirm (token) ───────────────── │ │                │
│   │                                         │                │
│   │ ═══ Shared PMK established ════════════ │                │
│   │ ═══ Then 4-way handshake (same as WPA2) │                │
│                                                               │
│  SAE Security Properties:                                     │
│  1. Dictionary attack resistant: Each SAE exchange produces  │
│     different Commit values (random element per attempt)      │
│  2. Offline attack impossible: Cannot verify password guess  │
│     without interacting with AP (no passive capture cracking) │
│  3. Forward secrecy: Compromising passphrase does not reveal │
│     past session keys                                         │
│  4. KRACK resistant: SAE-derived PMK is fresh per exchange  │
│                                                               │
│  WPA3 Modes:                                                  │
│  - WPA3-Personal: SAE with 128-bit encryption               │
│  - WPA3-Personal (192-bit): SAE with 192-bit suite (mandatory│
│    for government use)                                        │
│  - WPA3-Enterprise: 192-bit suite with EAP                   │
│                                                               │
│  WPA3 Additional Protections:                                │
│  - Protected Management Frames (PMF): Mandatory              │
│  - OCSP stapling for enterprise mode                          │
│  - Transition mode: WPA2/WPA3 dual support                  │
│  - Forward secrecy on all connections                         │
└──────────────────────────────────────────────────────────────┘
```

### Dragonfly (SAE) Attack Surface

```
┌──────────────────────────────────────────────────────────────┐
│              DRAGONFLY / SAE VULNERABILITIES                   │
│                                                               │
│  Dragonblood (CVE-2019-9494, CVE-2019-9495, etc.):          │
│                                                               │
│  1. DOWNGRADE ATTACK:                                        │
│     Force WPA3-SAE client to use WPA2-PSK (transition mode)  │
│     Then capture WPA2 handshake → dictionary attack          │
│     CVE-2019-9494                                             │
│                                                               │
│  2. TIMING ATTACK:                                            │
│     SAE password element derivation leaks timing              │
│     Number of iterations reveals password characteristics    │
│     CVE-2019-9494                                             │
│     (Fixed by using constant-time hash-to-curve)             │
│                                                               │
│  3. SIDE-CHANNEL ATTACK:                                      │
│     Cache-based side channel in PWE derivation                │
│     CVE-2019-9495                                             │
│                                                               │
│  4. GROUP DOWNGRADE:                                          │
│     Force weaker ECC group (e.g., P-256 instead of P-521)    │
│     Reduces security level of the exchange                    │
│                                                               │
│  Mitigation:                                                  │
│  - Disable WPA3 transition mode (WPA2/WPA3)                  │
│  - Use mandatory PMF                                          │
│  - Constant-time implementations                              │
│  - Disable downgrade to WPA2 in WPA3-only mode                │
└──────────────────────────────────────────────────────────────┘
```

## Enterprise WiFi (WPA3-Enterprise, EAP)

```
┌──────────────────────────────────────────────────────────────┐
│             EAP METHODS FOR ENTERPRISE WIFI                    │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │                EAP AUTHENTICATION FLOW                │     │
│  │                                                       │     │
│  │  STA ──► AP ──► RADIUS Server ──► Identity Store     │     │
│  │   │       │         │                │               │     │
│  │   │  EAPOL-   EAP messages   RADIUS   │               │     │
│  │   │  Start    (encapsulated)  Auth    │               │     │
│  │   │                                       │               │     │
│  │   │  ┌─────────────────────────────────┐ │               │     │
│  │   │  │ EAP-TLS (Cert-based, strongest) │ │               │
│  │   │  │ EAP-TTLS (Tunneled TLS)          │ │               │
│  │   │  │ PEAP (Protected EAP)             │ │               │
│  │   │  │ EAP-FAST (Flexible Auth via TLS) │ │               │
│  │   │  │ LEAP (Cisco, BROKEN)             │ │               │
│  │   │  └─────────────────────────────────┘ │               │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  EAP-TLS (Strongest):                                        │
│  - Both client and server certificates                       │
│  - Most secure EAP method                                    │
│  - Certificate management overhead                            │
│  - mTLS established before MSK derivation                     │
│                                                               │
│  PEAP/MSCHAPv2 (Most Common):                                │
│  - Server cert + username/password                            │
│  - Phase 1: TLS tunnel (server cert)                        │
│  - Phase 2: MSCHAPv2 inside tunnel                            │
│  - Vulnerable if server cert not validated (rogue AP)        │
│  - MSCHAPv2 inside tunnel is still challenge/response        │
│                                                               │
│  EAP-FAST (Flexible Auth via Secure Tunneling):              │
│  - Uses PAC (Protected Access Credential)                    │
│  - Can operate without server certificate                    │
│  - Vulnerable to PAC provisioning attacks                     │
│  - Cisco-proprietary                                          │
│                                                               │
│  LEAP (Lightweight EAP):                                     │
│  - BROKEN: MSCHAPv2 challenge/response in cleartext          │
│  - Trivial to crack with asleap                              │
│  │ asleap -r leap_capture.cap -w wordlist.txt               │
│  - Should NEVER be used                                       │
└──────────────────────────────────────────────────────────────┘
```

### Evil Twin Attacks

```
┌──────────────────────────────────────────────────────────────┐
│                  EVIL TWIN ATTACK                              │
│                                                               │
│  Attacker creates a clone of legitimate AP:                    │
│                                                               │
│  ┌────────────┐          ┌────────────┐                       │
│  │ Legit AP   │          │ Evil Twin  │                       │
│  │ SSID: Corp │          │ SSID: Corp │                       │
│  │ BSSID:AA:BB│          │ BSSID:CC:DD│                       │
│  │ Ch: 6      │          │ Ch: 6 ✗(1)│                       │
│  │ Signal: -50│          │ Signal: -30│ (stronger!)           │
│  └────────────┘          └────────────┘                       │
│       ▲                        │                              │
│       │                        ▼                              │
│  ┌────────────┐          ┌──────────┐                        │
│  │  Client    │◄─────────│ Captures │                        │
│  │            │  stronger │ credentials│                       │
│  └────────────┘  signal  └──────────┘                        │
│                                                               │
│  Attack Flow:                                                 │
│  1. Attacker creates AP with same SSID                       │
│  2. Deauth legitimate clients (see deauth attack)             │
│  3. Clients reconnect to stronger signal (evil twin)         │
│  4. Capture handshake, credentials, or redirect to phishing  │
│                                                               │
│  Enterprise WiFi Evil Twin:                                   │
│  - Clone corporate SSID                                       │
│  - Offer weaker EAP method (e.g., PEAP without cert check)  │
│  - Client may accept without verifying server cert            │
│  - Capture MSCHAPv2 challenge/response → crack offline       │
│                                                               │
│  Tools:                                                       │
│  - hostapd-wpe (Wireless Pwnage Edition)                      │
│  - eaphammer                                                  │
│  - WiFi-Pumpkin                                               │
│                                                               │
│  # hostapd-wpe configuration                                 │
│  interface=wlan0                                              │
│  ssid=CorporateWiFi                                           │
│  channel=6                                                    │
│  eap_server=1                                                 │
│  eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user          │
│  ca_cert=/etc/hostapd-wpe/ca.pem                              │
│  server_cert=/etc/hostapd-wpe/server.pem                      │
│  private_key=/etc/hostapd-wpe/server.key                      │
│  # Logs MSCHAPv2 challenge/response to file                  │
│                                                               │
│  Mitigation:                                                  │
│  - Verify server certificates (EAP-TLS preferred)           │
│  - Use certificate pinning for EAP methods                    │
│  - WPA3-SAE prevents captive portal phishing                 │
│  - Wireless IDS (WIDS) to detect evil twins                  │
│  - 802.11r/fast BSS transition reduces reassociation time    │
└──────────────────────────────────────────────────────────────┘
```

### Deauthentication Frame Attacks

```
┌──────────────────────────────────────────────────────────────┐
│            DEAUTHENTICATION FRAME ATTACKS                      │
│                                                               │
│  802.11 deauth frames are MANAGEMENT frames, sent unencrypted │
│  (even in WPA2!), making them trivially forgeable             │
│                                                               │
│  Deauthentication Frame:                                      │
│  ┌──────────┬──────────┬──────────┬──────────┬─────────┐   │
│  │ Frame    │ Duration │  DA       │  SA      │ BSSID   │   │
│  │ Control  │          │          │          │         │   │
│  ├──────────┼──────────┼──────────┼──────────┼─────────┤   │
│  │ Seq Ctrl │ Reason   │          │          │         │   │
│  │          │ Code     │          │          │         │   │
│  └──────────┴──────────┴──────────┴──────────┴─────────┘   │
│                                                               │
│  Reason Codes:                                                │
│  1 = Unspecified reason                                       │
│  2 = Previous authentication no longer valid                 │
│  4 = Disassociated due to inactivity                          │
│  7 = Class 3 frame received from nonassociated station       │
│                                                               │
│  Attack:                                                      │
│  1. Forge deauth frame with AP's MAC as sender               │
│  2. Send to client (or broadcast)                            │
│  3. Client disconnects and reconnects                         │
│  4. Capture 4-way handshake during reconnect                  │
│                                                               │
│  This is why PMF (Protected Management Frames) is critical  │
│                                                               │
│  # Deauthentication attack with aireplay-ng                   │
│  aireplay-ng --deauth 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon│
│                                                               │
│  # Broadcast deauth (all clients)                             │
│  aireplay-ng --deauth 5 -a <AP_MAC> wlan0mon                  │
│                                                               │
│  Mitigation: Protected Management Frames (PMF)               │
│  - 802.11w adds integrity check to management frames          │
│  - Mandatory in WPA3                                          │
│  - Optional in WPA2 (wf = Management Frame Protection)       │
└──────────────────────────────────────────────────────────────┘
```

## Bluetooth Security

### BlueBorne (CVE-2017-0781 through CVE-2017-0785)

```
┌──────────────────────────────────────────────────────────────┐
│              BLUEBORNE ATTACK SURFACE                          │
│                                                               │
│  BlueBorne: 8 vulnerabilities across all major platforms      │
│  Affects: Linux, Android, iOS, Windows                       │
│  ~5.3 billion devices at risk (2017)                         │
│                                                               │
│  Attack Vector: No pairing required!                          │
│  Attacker only needs to be within Bluetooth range             │
│                                                               │
│  CVE-2017-0781: Android Information Disclosure                 │
│  - SDP server memory leak reveals heap data                   │
│  - No authentication required                                 │
│                                                               │
│  CVE-2017-0782: Android Remote Code Execution                 │
│  - Stack-based buffer overflow in BNEP service                │
│  - L2CAP payload parsed with incorrect length check          │
│  - Full RCE on Android < September 2017 patch                 │
│  - Attack: Craft BNEP packet with oversized payload           │
│                                                               │
│  CVE-2017-0783: Android Remote Code Execution                 │
│  - Heap-based buffer overflow in BNEP                         │
│  - Different overflow vector than CVE-2017-0782               │
│                                                               │
│  CVE-2017-0784: Android Information Disclosure                 │
│  - PAN profile memory disclosure                              │
│                                                               │
│  CVE-2017-0785: Linux Remote Code Execution                   │
│  - Stack-based buffer overflow in L2CAP configuration         │
│  - Affects Linux kernel Bluetooth stack                       │
│  - No pairing required                                        │
│  - Attack: Crafted L2CAP configuration request                │
│                                                               │
│  CVE-2017-14316: Laird serial port overflow                   │
│                                                               │
│  BlueBorne Attack Chain:                                      │
│  1. Recon: Scan for Bluetooth devices (SDP inquiry)          │
│  2. Probe: Determine device type and Bluetooth stack           │
│  3. Exploit: Send crafted BNEP/L2CAP packets                 │
│  4. Control: Full device takeover                             │
│                                                               │
│  # Detection: Monitor for unexpected L2CAP frames             │
│  # Mitigation: Update Bluetooth stack, disable when unused    │
└──────────────────────────────────────────────────────────────┘
```

### BLE Security and Attack Tools

```
┌──────────────────────────────────────────────────────────────┐
│              BLUETOOTH LOW ENERGY (BLE) SECURITY                │
│                                                               │
│  BLE Pairing Methods:                                         │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Just Works: No authentication, vulnerable          │        │
│  │ Passkey Entry: 6-digit PIN, vulnerable to MITM     │        │
│  │ Numeric Comparison: Both devices show number      │        │
│  │ Out-of-Band (OOB): Uses NFC/QR for key exchange  │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  BLE Pairing Phases:                                          │
│  Phase 1: Pairing Feature Exchange                            │
│  Phase 2: Short-Term Key (STK) Generation                    │
│  Phase 3: Transport-Specific Key Distribution                 │
│                                                               │
│  BLE Security Modes:                                          │
│  - LE Secure Connections (BLE 4.2+): ECDH, AES-CCM          │
│  - LE Legacy Pairing: Short-term key from TK/SK               │
│    Vulnerable to: passkey brute force, eavesdropping          │
│                                                               │
│  Attack Tools:                                                │
│                                                               │
│  BtleJack: BLE sniffing and hijacking framework               │
│  # btlejack -s -c 37,38,39  # Sniff all advertising channels │
│  # btlejack -s -t <MAC>     # Sniff specific device           │
│  # btlejack -f -t <MAC>     # Follow connection              │
│                                                               │
│  GATTacker: BLE MITM framework                                │
│  # Clone BLE device's GATT server                            │
│  # Collect advertisements → create fake device                │
│  # Intercept and modify BLE communications                    │
│                                                               │
│  Btlejuice: BLE MITM proxy                                    │
│  # Intercept BLE communication between device and app        │
│  # Modify GATT characteristics on the fly                    │
│                                                               │
│  nRF Connect: Mobile BLE analysis tool                        │
│  # Read/write/notify BLE characteristics                      │
│  # Scan for services and characteristics                       │
└──────────────────────────────────────────────────────────────┘
```

### KNOB Attack (CVE-2019-9506)

```
┌──────────────────────────────────────────────────────────────┐
│                    KNOB ATTACK                                 │
│               (Key Negotiation Of Bluetooth)                  │
│                                                               │
│  Vulnerability: Bluetooth allows entropy negotiation           │
│  for the encryption key, and the minimum is 1 byte (8 bits)!  │
│                                                               │
│  Attack:                                                      │
│  1. During pairing, negotiate minimum key entropy (1 byte)    │
│  2. Both devices agree (spec allows this!)                    │
│  3. Brute-force 8-bit key: only 256 possible values          │
│  4. Decrypt all Bluetooth traffic                              │
│                                                               │
│  Affected: Bluetooth BR/EDR (Classic Bluetooth)               │
│  Works on: All Bluetooth versions up to 5.1                  │
│                                                               │
│  Attack Flow:                                                 │
│  Device A ──── LMP_encryption_key_size_req(1) ────► Device B │
│  Device B ◄─── LMP_encryption_key_size_req(1) ────── Device A │
│  (Both agree on 1-byte key = 8 bits of entropy)              │
│                                                               │
│  8-bit key → 256 brute-force attempts                        │
│  Average: 128 attempts to find correct key                    │
│                                                               │
│  CVE-2019-9506                                                 │
│  Fixed: Bluetooth Core Specification 5.2 sets minimum to 7     │
│  bytes (56 bits)                                              │
│  Mitigation: Reject key sizes below 7 bytes                   │
└──────────────────────────────────────────────────────────────┘
```

### BLURtooth (CVE-2020-15802)

```
┌──────────────────────────────────────────────────────────────┐
│               BLURTOOTH (Cross-Transport Key Derivation)      │
│                                                               │
│  CVE-2020-15802: Cross-transport key derivation flaw          │
│                                                               │
│  Bluetooth supports dual-mode: BR/EDR + BLE                  │
│  Cross-transport key derivation allows:                       │
│  - BLE pairing key → used for BR/EDR connection               │
│  - BR/EDR pairing key → used for BLE connection               │
│                                                               │
│  Attack:                                                      │
│  1. Pair via BLE (weaker security, Just Works possible)       │
│  2. Derived key is used for BR/EDR (Classic Bluetooth)        │
│  3. If BLE used Just Works → no MITM protection              │
│  4. Key downgraded strength is carried to BR/EDR             │
│  5. Attacker exploits the weaker security of BLE pairing      │
│                                                               │
│  Impact:                                                      │
│  - Bypass BR/EDR authentication via BLE                       │
│  - Impersonate BLE device on BR/EDR                           │
│  - Decrypt traffic on both transports                          │
│                                                               │
│  Mitigation:                                                  │
│  - Disable cross-transport key derivation                      │
│  - Use separate keys per transport                             │
│  - Bluetooth 5.2 removes cross-transport key derivation       │
└──────────────────────────────────────────────────────────────┘
```

### WiFi and Bluetooth Hardening

```bash
# Linux WiFi security configuration
# Hostapd WPA3 configuration
interface=wlan0
ssid=SecureNetwork
channel=36
hw_mode=a
ieee80211w=2              # PMF required
wpa=2
wpa_passphrase=<strong-passphrase>
rsn_pairwise=CCMP         # Use only CCMP (AES)
wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE
sae_group=19              # ECC group P-256
sae_pwe=2                 # Hunting-and-pecking method

# Bluetooth hardening
# Disable Bluetooth when not in use
sudo rfkill block bluetooth

# Set Bluetooth to non-discoverable, non-connectable
sudo hciconfig hci0 noscan
sudo hciconfig hci0 noauth

# Enable Bluetooth encryption (if supported)
sudo hciconfig hci0 encrypt

# Linux kernel Bluetooth parameters
# /etc/modprobe.d/bluetooth.conf
options bluetooth disable_esco=1  # Disable eSCO if not needed
options bnep max_rx_frames=10    # Rate limit BNEP
```

**Cross-references**: See `04a_network_attacks_mitm.md` for MITM techniques applicable to WiFi, `05a_firewall_ids_ips.md` for wireless IDS/IPS, `03b_vpn_tunnel_security.md` for VPN over WiFi considerations, and macOS track for AirDrop/Bluetooth framework security.

## References

1. IEEE 802.11 — Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications. IEEE, 2021.
2. IEEE 802.11w — Management Frame Protection. IEEE, 2009.
3. Fluhrer, S., Mantin, I., Shamir, A. — Weaknesses in the Key Scheduling Algorithm of RC4. SAC 2001.
4. Tews, E., Weinmann, R.P., Pyshkin, A. — Breaking 104 Bit WEP in Less Than 60 Seconds. SAC 2007.
5. CVE-2017-13077 through CVE-2017-13088 — KRACK: Key Reinstallation Attacks Against WPA2. NVD, 2017.
6. Vanhoef, M., Piessens, F. — Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2. ACM CCS, 2017.
7. Wi-Fi Alliance — WPA3 Specification: Simultaneous Authentication of Equals (SAE). Wi-Fi Alliance, 2018.
8. CVE-2019-9494 — Dragonblood: WPA3-SAE downgrade and timing attacks. NVD, 2019.
9. CVE-2019-9495 — Dragonblood: WPA3-SAE side-channel attack. NVD, 2019.
10. CVE-2017-0781 through CVE-2017-0785 — BlueBorne: Bluetooth remote code execution. NVD, 2017.
11. Armis Labs — BlueBorne: The Dangers of Bluetooth Vulnerabilities. Whitepaper, September 2017.
12. CVE-2019-9506 — KNOB Attack: Key Negotiation of Bluetooth. NVD, 2019.
13. Biham, E., Neumann, L. — The KNOB Attack: Exploit and Mitigation. USENIX WOOT, 2019.
14. CVE-2020-15802 — BLURtooth: Cross-transport key derivation vulnerability. NVD, 2020.
15. Bluetooth SIG — Bluetooth Core Specification Version 5.2. Bluetooth SIG, December 2019.
16. CVE-2011-3325 — OSPF LSA injection vulnerability. NVD, 2011.
17. Vanhoef, M. — Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd. IEEE S&P, 2020.
18. RFC 7664 — Dragonfly Key Exchange. D. Harkins, IETF, November 2015.
19. Ryan, M. — Bluetooth: With Low Energy Comes Low Security. USENIX WOOT, 2013.
20. Ryan, M. — SweynTooth: Unleashing Mayhem Over Bluetooth Low Energy. USENIX Asia CCS, 2020.