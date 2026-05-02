# Protocol Reverse Engineering

> Comprehensive methodology for reverse engineering network protocols, binary protocols, CAN bus, Bluetooth, game protocols, and proprietary communication reconstruction.

---

## Table of Contents

1. [Protocol RE Methodology](#1-protocol-re-methodology)
2. [Binary Protocol Analysis](#2-binary-protocol-analysis)
3. [Custom Protocol Identification](#3-custom-protocol-identification)
4. [Field Mapping Techniques](#4-field-mapping-techniques)
5. [Protocol Fuzzing After RE](#5-protocol-fuzzing-after-re)
6. [CAN Bus RE for Automotive](#6-can-bus-re-for-automotive)
7. [Bluetooth Protocol RE](#7-bluetooth-protocol-re)
8. [Game Protocol RE](#8-game-protocol-re)

---

## 1. Protocol RE Methodology

Protocol reverse engineering follows a systematic approach from observation to reconstruction:

```
Protocol RE Process:
┌─────────────────────────────────────────────────────────┐
│ 1. CAPTURE                                                 │
│    Capture traffic (pcap, serial, CAN)                    │
│    Multiple sessions, various inputs                      │
├─────────────────────────────────────────────────────────┤
│ 2. IDENTIFY                                                │
│    Identify protocol characteristics                      │
│    Delimiters, fixed fields, variable fields             │
│    Encoding, endianness, checksums                        │
├─────────────────────────────────────────────────────────┤
│ 3. MAP FIELDS                                              │
│    Map known values to protocol fields                   │
│    Use controlled inputs to identify field mappings       │
│    Determine field sizes, types, and semantics            │
├─────────────────────────────────────────────────────────┤
│ 4. VERIFY                                                  │
│    Verify reconstructed protocol spec                     │
│    Implement reference implementation (Scapy, Python)     │
│    Test against live system                                │
├─────────────────────────────────────────────────────────┤
│ 5. DOCUMENT                                                │
│    Write formal protocol specification                    │
│    Publish RFC-style document                             │
│    Create dissector for Wireshark                         │
└─────────────────────────────────────────────────────────┘
```

### 1.1 Capture Methodology

```bash
# Network protocol capture
# Full capture with all metadata
tcpdump -i any -w capture.pcap -s 0 'port 443 or port 8080'

# Capture with specific BPF filters
tcpdump -i eth0 -w capture.pcap 'host 192.168.1.100 and port 8080'

# SSL/TLS capture (with key logging)
# Set SSLKEYLOGFILE environment variable before starting browser
export SSLKEYLOGFILE=/tmp/ssl_keys.log
# Then in Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename

# Serial port capture (for IoT/embedded)
# Using socat to capture and forward
socat -x -v PTY,link=/tmp/ttyV0,raw,echo=0 \
    FILE:/tmp/serial_capture.log,create,append

# CAN bus capture (automotive)
# Using can-utils
candump -l can0   # Log CAN frames to file

# Bluetooth capture
# HCI snoop log (Android): /data/misc/bluetooth/logs/btsnoop_hci.log
# Linux: btmon -w bluetooth_capture.pcap
# macOS: tcpdump -i Bluetooth -w bluetooth_capture.pcap
```

---

## 2. Binary Protocol Analysis

### 2.1 Protocol Structure Identification

```python
# Binary protocol analysis framework
import struct
from collections import Counter

class BinaryProtocolAnalyzer:
    """Analyze binary protocol structure from captured packets."""
    
    def __init__(self):
        self.packets = []
        self.field_candidates = []
    
    def add_packet(self, data):
        """Add a captured packet for analysis."""
        self.packets.append(data)
    
    def find_fixed_bytes(self):
        """Find bytes that are the same across all packets (magic numbers, headers)."""
        if not self.packets:
            return {}
        
        fixed = {}
        min_len = min(len(p) for p in self.packets)
        
        for offset in range(min_len):
            byte_values = [p[offset] for p in self.packets]
            if len(set(byte_values)) == 1:
                fixed[offset] = byte_values[0]
        
        # Group consecutive fixed bytes
        groups = []
        offsets = sorted(fixed.keys())
        if not offsets:
            return {}
        
        start = offsets[0]
        end = offsets[0]
        for i in range(1, len(offsets)):
            if offsets[i] == end + 1:
                end = offsets[i]
            else:
                groups.append({
                    'offset': start,
                    'length': end - start + 1,
                    'value': bytes([fixed[j] for j in range(start, end + 1)])
                })
                start = offsets[i]
                end = offsets[i]
        groups.append({
            'offset': start,
            'length': end - start + 1,
            'value': bytes([fixed[j] for j in range(start, end + 1)])
        })
        
        return groups
    
    def find_length_fields(self):
        """Find fields that correlate with packet length."""
        length_fields = []
        
        for offset in range(8):  # Check first 8 bytes
            for size in [1, 2, 4]:  # Try 8-bit, 16-bit, 32-bit
                fmt = {1: 'B', 2: 'H', 4: 'I'}[size]
                
                values = []
                lengths = []
                for p in self.packets:
                    if offset + size <= len(p):
                        value = struct.unpack(fmt, p[offset:offset+size])[0]
                        values.append(value)
                        lengths.append(len(p))
                
                # Check if value correlates with packet length
                if len(values) == len(self.packets) and values:
                    # Direct correlation: value == packet length
                    if all(v == l for v, l in zip(values, lengths)):
                        length_fields.append({
                            'offset': offset,
                            'size': size,
                            'type': 'total_length',
                        })
                    # Partial correlation: value == packet_length - offset
                    elif all(v == l - offset - size for v, l in zip(values, lengths)):
                        length_fields.append({
                            'offset': offset,
                            'size': size,
                            'type': 'payload_length',
                        })
                    # Value == packet length - constant
                    elif len(set(l - v for v, l in zip(values, lengths))) == 1:
                        constant = list(set(l - v for v, l in zip(values, lengths)))[0]
                        length_fields.append({
                            'offset': offset,
                            'size': size,
                            'type': 'total_length_minus_constant',
                            'constant': constant,
                        })
        
        return length_fields
    
    def find_checksum_fields(self):
        """Find fields that might be checksums."""
        checksum_fields = []
        
        for size in [1, 2, 4]:
            offset = -size  # Checksums are usually at the end
            for p in self.packets:
                if len(p) < size:
                    continue
                
                checksum_bytes = p[offset:]
                payload = p[:offset] if offset != 0 else p
                
                # Try common checksum algorithms
                # CRC8
                if size == 1:
                    pass  # Implement CRC8 check
                
                # CRC16
                if size == 2:
                    import crcmod
                    for poly in [0x1021, 0x8005, 0x3D65, 0x8BB7]:
                        try:
                            crc_func = crcmod.mkCrcFun(poly, initCrc=0, xorOut=0)
                            computed = crc_func(payload)
                            stored = struct.unpack('H', checksum_bytes)[0]
                            if computed == stored:
                                checksum_fields.append({
                                    'offset': offset,
                                    'size': size,
                                    'algorithm': f'CRC16-0x{poly:04X}',
                                })
                        except Exception:
                            pass
                
                # Simple checksum (sum of bytes)
                if size == 1:
                    computed = sum(payload) & 0xFF
                    stored = checksum_bytes[0]
                    if computed == stored:
                        checksum_fields.append({
                            'offset': offset,
                            'size': size,
                            'algorithm': 'sum8',
                        })
        
        return checksum_fields
    
    def analyze(self):
        """Run full protocol analysis."""
        print("=== Fixed Bytes (Magic/Headers) ===")
        fixed = self.find_fixed_bytes()
        for group in fixed:
            print(f"  Offset {group['offset']:3d}, Length {group['length']}: "
                  f"{group['value'].hex()} ({group['value']})")
        
        print("\n=== Length Fields ===")
        lengths = self.find_length_fields()
        for field in lengths:
            print(f"  Offset {field['offset']}, Size {field['size']} bytes: {field['type']}")
        
        print("\n=== Checksum Fields ===")
        checksums = self.find_checksum_fields()
        for field in checksums:
            print(f"  Offset {field['offset']}, Size {field['size']} bytes: {field['algorithm']}")
```

### 2.2 Wireshark Protocol Dissection

```lua
-- Wireshark dissector for a custom binary protocol
-- Save as custom_protocol.lua and load in Wireshark

-- Define protocol
custom_proto = Proto("custom", "Custom Binary Protocol")

-- Define fields
local f_magic = ProtoField.bytes("custom.magic", "Magic", base.NONE)
local f_version = ProtoField.uint8("custom.version", "Version", base.DEC)
local f_type = ProtoField.uint8("custom.type", "Type", base.HEX)
local f_length = ProtoField.uint16("custom.length", "Length", base.DEC)
local f_seq = ProtoField.uint16("custom.seq", "Sequence Number", base.DEC)
local f_flags = ProtoField.uint8("custom.flags", "Flags", base.HEX)
local f_payload = ProtoField.bytes("custom.payload", "Payload", base.NONE)
local f_checksum = ProtoField.uint16("custom.checksum", "Checksum", base.HEX)

custom_proto.fields = {f_magic, f_version, f_type, f_length, f_seq, f_flags, f_payload, f_checksum}

-- Message types
local msg_types = {
    [0x01] = "HELLO",
    [0x02] = "AUTH",
    [0x03] = "DATA",
    [0x04] = "ACK",
    [0x05] = "ERROR",
    [0xFF] = "GOODBYE",
}

-- Dissector function
function custom_proto.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len < 12 then return 0 end  -- Minimum header size
    
    -- Set protocol column
    pinfo.cols.protocol = "CUSTOM"
    
    -- Create subtree
    local subtree = tree:add(custom_proto, buffer(), "Custom Protocol Data")
    
    -- Parse header
    local offset = 0
    
    -- Magic bytes (4 bytes)
    subtree:add(f_magic, buffer(offset, 4))
    offset = offset + 4
    
    -- Version (1 byte)
    subtree:add(f_version, buffer(offset, 1))
    offset = offset + 1
    
    -- Type (1 byte)
    local type_val = buffer(offset, 1):uint()
    local type_item = subtree:add(f_type, buffer(offset, 1))
    type_item:append_text(" (" .. (msg_types[type_val] or "Unknown") .. ")")
    offset = offset + 1
    
    -- Length (2 bytes, big-endian)
    local length_val = buffer(offset, 2):uint()
    subtree:add(f_length, buffer(offset, 2))
    offset = offset + 2
    
    -- Sequence number (2 bytes)
    subtree:add(f_seq, buffer(offset, 2))
    offset = offset + 2
    
    -- Flags (1 byte)
    subtree:add(f_flags, buffer(offset, 1))
    offset = offset + 1
    
    -- Info column
    pinfo.cols.info = string.format("%s seq=%d len=%d", 
        msg_types[type_val] or "Unknown", buffer(offset-3, 2):uint(), length_val)
    
    -- Payload (variable length)
    local payload_len = length_val - offset
    if payload_len > 0 then
        subtree:add(f_payload, buffer(offset, payload_len))
        offset = offset + payload_len
    end
    
    -- Checksum (2 bytes, last)
    subtree:add(f_checksum, buffer(offset, 2))
    
    return buf_len
end

-- Register dissector on custom port
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(9999, custom_proto)
```

### 2.3 Scapy Protocol Implementation

```python
# Reconstruct a custom protocol using Scapy
from scapy.all import *
from scapy.fields import *

class CustomProtocol(Packet):
    """Custom binary protocol implementation."""
    name = "CustomProtocol"
    
    fields_desc = [
        # Header
        XIntField("magic", 0x43555354),      # "CUST" magic
        ByteField("version", 1),
        ByteEnumField("type", 0, {
            0x01: "HELLO",
            0x02: "AUTH",
            0x03: "DATA",
            0x04: "ACK",
            0x05: "ERROR",
            0xFF: "GOODBYE",
        }),
        FieldLenField("length", None, fmt=">H", length_of="payload"),
        ShortField("seq", 0),
        BitField("reserved", 0, 5),
        BitField("compressed", 0, 1),
        BitField("encrypted", 0, 1),
        BitField("priority", 0, 1),
        
        # Payload
        ConditionalField(
            StrLenField("payload", b"", length_from=lambda p: p.length),
            lambda p: p.type in [0x02, 0x03]  # Only AUTH and DATA have payload
        ),
        
        # Auth fields (when type == AUTH)
        ConditionalField(
            StrFixedLenField("username", b"", length=32),
            lambda p: p.type == 0x02
        ),
        ConditionalField(
            StrFixedLenField("auth_token", b"", length=16),
            lambda p: p.type == 0x02
        ),
        
        # Checksum
        XShortField("checksum", 0),
    ]
    
    def post_build(self, pkt, pay):
        """Calculate and add checksum after building."""
        if self.checksum == 0:
            # Calculate CRC16 over the entire packet (excluding checksum field)
            pkt_without_checksum = pkt[:-2] + pay
            checksum = crc16(pkt_without_checksum)
            pkt = pkt_without_checksum + struct.pack(">H", checksum)
        return pkt

bind_layers(TCP, CustomProtocol, dport=9999)

# Usage
pkt = CustomProtocol(type=0x03, seq=1, payload=b"Hello World") / Raw(b"extra")
send(pkt, dst="192.168.1.100")
```

---

## 3. Custom Protocol Identification

### 3.1 Protocol Fingerprinting

```python
# Protocol fingerprinting from captured traffic

def identify_protocol(packets):
    """Attempt to identify a protocol from captured traffic."""
    
    for packet in packets:
        data = packet  # Assuming raw bytes
        
        # Check for known protocol magic bytes
        magic_bytes = {
            b'\x03\x00': 'SSL/TLS',
            b'\x16\x03': 'SSL/TLS (handshake)',
            b'\x15\x03': 'SSL/TLS (alert)',
            b'\x17\x03': 'SSL/TLS (application)',
            b'RTSP': 'RTSP',
            b'HTTP': 'HTTP',
            b'GET ': 'HTTP GET',
            b'POST': 'HTTP POST',
            b'HELO': 'SMTP',
            b'EHLO': 'SMTP',
            b'\x00\x00\x00': 'Likely length-prefixed protocol',
            b'\xff\xfe': 'UTF-16 LE BOM',
            b'\xfe\xff': 'UTF-16 BE BOM',
        }
        
        for magic, protocol in magic_bytes.items():
            if data.startswith(magic):
                print(f"Possible protocol: {protocol}")
                continue
        
        # Heuristic checks
        # Check for length-prefixed protocols
        if len(data) >= 4:
            length = struct.unpack('>I', data[:4])[0]
            if length == len(data) - 4:
                print(f"Likely length-prefixed protocol (4-byte big-endian header)")
            elif length == len(data):
                print(f"Likely length-prefixed protocol (4-byte length incl. header)")
        
        # Check for text-based protocols
        printable_ratio = sum(1 for b in data if 32 <= b <= 126) / len(data)
        if printable_ratio > 0.9:
            print(f"Likely text-based protocol ({printable_ratio:.1%} printable)")
        
        # Check for fixed header structure
        if len(data) >= 8:
            # Look for magic bytes in first 4 bytes
            first_4 = data[:4]
            print(f"First 4 bytes (possible magic): {first_4.hex()}")
            
            # Look for possible version field
            if data[4] in range(1, 5) and data[5] == 0:
                print(f"Possible version field: {data[4]}.{data[5]}")
            
            # Look for possible length field
            for size in [1, 2, 4]:
                fmt = {1: 'B', 2: 'H', 4: 'I'}[size]
                val = struct.unpack(fmt, data[4:4+size])[0]
                if val == len(data) or val == len(data) - 4 - size:
                    print(f"Possible length field at offset 4, "
                          f"size={size}, value={val}")
    
    return None
```

### 3.2 Differential Analysis

```python
def differential_analysis(packets_by_input):
    """Compare packets generated by different inputs to identify fields."""
    
    # Group packets by input type
    # packets_by_input = {
    #     'login_success': [pkt1, pkt2, ...],
    #     'login_failure': [pkt1, pkt2, ...],
    #     'command_A': [pkt1, pkt2, ...],
    #     'command_B': [pkt1, pkt2, ...],
    # }
    
    # For each byte position, determine:
    # 1. Does it vary across different inputs? → Data/payload field
    # 2. Is it the same within same-input packets? → Sequence/counter field
    # 3. Is it always the same? → Magic/version/header field
    
    all_positions = set()
    for packets in packets_by_input.values():
        for packet in packets:
            all_positions.update(range(len(packet)))
    
    field_analysis = {}
    for pos in sorted(all_positions):
        same_across_all = True
        varies_by_input = False
        
        reference_packets = list(packets_by_input.values())[0]
        reference_value = reference_packets[0][pos] if pos < len(reference_packets[0]) else None
        
        for input_type, packets in packets_by_input.items():
            for packet in packets:
                if pos < len(packet):
                    if packet[pos] != reference_value:
                        varies_by_input = True
                else:
                    same_across_all = False
        
        field_analysis[pos] = {
            'varies_by_input': varies_by_input,
            'same_across_all': same_across_all,
        }
    
    # Print analysis results
    print("Byte Position Analysis:")
    print(f"{'Pos':>4s} {'Varies':>8s} {'Fixed':>8s} {'Probable Field':>20s}")
    print("-" * 48)
    
    for pos in sorted(field_analysis.keys()):
        analysis = field_analysis[pos]
        varies = analysis['varies_by_input']
        fixed = analysis['same_across_all']
        
        if fixed:
            probable = "Magic/Header"
        elif varies:
            probable = "Data/Command"
        else:
            probable = "Unknown"
        
        print(f"{pos:4d} {str(varies):>8s} {str(fixed):>8s} {probable:>20s}")
    
    return field_analysis
```

---

## 4. Field Mapping Techniques

### 4.1 Controlled Input Mapping

```python
# Field mapping by sending controlled inputs and observing output

def map_protocol_fields(target_host, target_port):
    """Map protocol fields by sending controlled inputs."""
    import socket
    
    results = []
    
    # Test 1: Send same input multiple times
    # If a field changes, it's likely a sequence number or timestamp
    print("=== Test 1: Sequence/Timestamp Detection ===")
    test_payload = b'\x41' * 16
    
    responses = []
    for i in range(5):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_host, target_port))
        s.send(test_payload)
        response = s.recv(4096)
        responses.append(response)
        s.close()
    
    # Compare responses
    varying_bytes = set()
    for pos in range(min(len(r) for r in responses)):
        values = set(r[pos] for r in responses if pos < len(r))
        if len(values) > 1:
            varying_bytes.add(pos)
    
    print(f"Varying byte positions: {sorted(varying_bytes)}")
    
    # Test 2: Send incrementing values
    # If a field mirrors our input, it's likely an echo/acknowledgment
    print("\n=== Test 2: Echo Detection ===")
    for i in range(3):
        payload = bytes([i] * 16)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_host, target_port))
        s.send(payload)
        response = s.recv(4096)
        if payload in response:
            print(f"Input echoed in response at offset: {response.index(payload)}")
        s.close()
    
    # Test 3: Send boundary values
    # 0xFF, 0x00, 0x7F, 0x80, 0xFFFF, etc.
    print("\n=== Test 3: Boundary Value Testing ===")
    boundary_payloads = [
        bytes([0] * 16),       # All zeros
        bytes([0xFF] * 16),    # All 0xFF
        bytes([0x7F] * 16),   # All 0x7F (max signed byte)
        bytes([0x80] * 16),   # All 0x80 (min signed byte + 1)
        bytes(range(16)),      # Sequential values
    ]
    
    for payload in boundary_payloads:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_host, target_port))
        s.send(payload)
        response = s.recv(4096)
        results.append({'input': payload.hex(), 'output': response.hex()})
        s.close()
    
    # Test 4: Length field testing
    # Send packets of different lengths to identify length field
    print("\n=== Test 4: Length Field Identification ===")
    for length in [16, 32, 64, 128]:
        payload = bytes([0x41] * length)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_host, target_port))
        s.send(payload)
        response = s.recv(4096)
        print(f"Input length: {length}, Response length: {len(response)}")
        results.append({'input_length': length, 'response': response.hex()})
        s.close()
    
    return results
```

### 4.2 Frida for Protocol Hooking

```javascript
// Frida script for hooking network functions to capture protocol data
// Usage: frida -U -l protocol_hook.js -f com.target.app

// Hook send() and recv() to capture protocol data
var send_func = Module.findExportByName(null, "send");
var recv_func = Module.findExportByName(null, "recv");
var connect_func = Module.findExportByName(null, "connect");
var SSL_write = Module.findExportByName(null, "SSL_write");
var SSL_read = Module.findExportByName(null, "SSL_read");

var connections = {};

// Track connect() to map socket to address
Interceptor.attach(connect_func, {
    onEnter: function(args) {
        this.sockfd = args[0].toInt32();
        this.addr = args[1];
        this.addrlen = args[2].toInt32();
        
        // Parse sockaddr_in
        var family = this.addr.readU16();
        if (family === 2) { // AF_INET
            var port = (this.addr.add(2).readU8() << 8) | this.addr.add(3).readU8();
            var ip = this.addr.add(4).readU8() + "." + 
                     this.addr.add(5).readU8() + "." + 
                     this.addr.add(6).readU8() + "." + 
                     this.addr.add(7).readU8();
            connections[this.sockfd] = ip + ":" + port;
        }
    }
});

// Hook send()
Interceptor.attach(send_func, {
    onEnter: function(args) {
        this.sockfd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var dest = connections[this.sockfd] || "unknown";
        var data = this.buf.readByteArray(this.len);
        send({
            type: 'send',
            dest: dest,
            sockfd: this.sockfd,
            length: this.len,
            data: Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('')
        });
    }
});

// Hook recv()
Interceptor.attach(recv_func, {
    onEnter: function(args) {
        this.sockfd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var received = retval.toInt32();
        if (received > 0) {
            var dest = connections[this.sockfd] || "unknown";
            var data = this.buf.readByteArray(received);
            send({
                type: 'recv',
                src: dest,
                sockfd: this.sockfd,
                length: received,
                data: Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('')
            });
        }
    }
});

// Hook SSL_write() and SSL_read() for HTTPS
if (SSL_write) {
    Interceptor.attach(SSL_write, {
        onEnter: function(args) {
            this.ssl = args[0];
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            var written = retval.toInt32();
            if (written > 0) {
                var data = this.buf.readByteArray(written);
                send({
                    type: 'ssl_write',
                    length: written,
                    data: Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('')
                });
            }
        }
    });
}

if (SSL_read) {
    Interceptor.attach(SSL_read, {
        onEnter: function(args) {
            this.ssl = args[0];
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            var read = retval.toInt32();
            if (read > 0) {
                var data = this.buf.readByteArray(read);
                send({
                    type: 'ssl_read',
                    length: read,
                    data: Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('')
                });
            }
        }
    });
}
```

---

## 5. Protocol Fuzzing After RE

```python
# After reconstructing a protocol, fuzz it to find vulnerabilities

# Using Scapy for protocol fuzzing
from scapy.all import *
from scapy.fields import *
import random
import struct

class FuzzedCustomProtocol(Packet):
    """Custom protocol with fuzzable fields."""
    name = "FuzzedCustomProtocol"
    
    fields_desc = [
        XIntField("magic", 0x43555354),
        ByteField("version", 1),
        FuzzByteField("type", 0x01),       # Fuzzable type field
        FieldLenField("length", None, fmt=">H", length_of="payload"),
        FuzzShortField("seq", 0),          # Fuzzable sequence field
        ByteField("flags", 0),
        FuzzStrField("payload", b"AAAA"),  # Fuzzable payload
        XShortField("checksum", 0),
    ]

# Fuzz mutations
def fuzz_byte(value):
    """Generate fuzzed byte values."""
    mutations = [
        value,              # Original value
        0x00,               # Zero
        0xFF,               # Max value
        0x01,               # One
        0x7F,               # Max signed
        0x80,               # Min signed + 1
        value + 1,          # Off-by-one
        value - 1,          # Off-by-one
        random.randint(0, 255),  # Random
    ]
    return mutations

def fuzz_int(value):
    """Generate fuzzed 32-bit integer values."""
    mutations = [
        value,
        0x00000000,
        0xFFFFFFFF,
        0x00000001,
        0x7FFFFFFF,
        0x80000000,
        value + 1,
        value - 1,
        random.randint(0, 0xFFFFFFFF),
    ]
    return mutations

def fuzz_string(value):
    """Generate fuzzed string values."""
    mutations = [
        value,
        b"",
        b"A" * 65536,       # Very long string
        b"A" * 256,          # Long string
        b"\x00",             # NULL byte
        b"\xff" * 16,        # High bytes
        b"%s%s%s%s%s",       # Format string
        b"\xfe\xff" + b"A" * 100,  # UTF-16 marker + padding
    ]
    return mutations

# Main fuzzing loop
def fuzz_protocol(target_host, target_port, iterations=1000):
    """Fuzz the custom protocol implementation."""
    import socket
    
    for i in range(iterations):
        # Generate fuzzed packet
        type_vals = fuzz_byte(0x03)
        seq_vals = fuzz_byte(0)
        payload_vals = fuzz_string(b"TEST")
        
        msg_type = random.choice(type_vals)
        seq = random.choice(seq_vals)
        payload = random.choice(payload_vals)
        
        # Build packet
        pkt = CustomProtocol(
            type=msg_type,
            seq=seq,
            payload=payload,
        )
        
        # Send and check response
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_host, target_port))
            s.send(bytes(pkt))
            
            try:
                response = s.recv(4096)
                # Parse response and check for anomalies
            except socket.timeout:
                pass  # No response is sometimes interesting
            
            s.close()
        except Exception as e:
            print(f"[!] Connection error: {e}")
            # Target might have crashed — investigate!
```

---

## 6. CAN Bus RE for Automotive

### 6.1 CAN Bus Fundamentals

```
CAN Frame Structure (Classic CAN):
┌───────────────────────────────────────────────────┐
│ SOF (1 bit) │ Arb ID (11/29 bits) │ RTR (1) │    │
│ IDE (1) │ DLC (4 bits) │ Data (0-8 bytes) │      │
│ CRC (15) │ CRC Del (1) │ ACK (1) │ ACK Del (1) │ │
│ EOF (7) │ IFS (3) │                                    │
└───────────────────────────────────────────────────┘

Arbitration ID: Identifies the message (like a "topic" in MQTT)
DLC: Data Length Code (0-8 bytes)
Data: Payload (up to 8 bytes for Classic CAN, 64 for CAN FD)
```

```bash
# CAN bus setup on Linux
# Install can-utils
apt install can-utils

# Set up virtual CAN interface for testing
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up

# Set up real CAN interface (e.g., SocketCAN on Raspberry Pi)
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# CAN bus capture
candump can0                          # Capture all CAN frames
candump can0 -t a                     # With absolute timestamps
candump can0 -l                       # Log to file (ASC format)
candump can0,123:7FF                  # Filter: IDs 0x123-0x7FF
candump can0,100:1FF                  # Filter: IDs 0x100-0x1FF

# CAN bus replay
canplayer -I can_log.log can0        # Replay captured frames

# Send CAN frame
cansend can0 123#0102030405060708    # ID=0x123, 8 data bytes

# CAN bus statistics
canstats can0                         # Statistics
```

### 6.2 CAN Bus Reverse Engineering

```python
# CAN bus protocol reverse engineering
import can
import time
from collections import defaultdict

class CANProtocolRe:
    def __init__(self, interface='can0'):
        self.bus = can.interface.Bus(interface, bustype='socketcan')
        self.messages = defaultdict(list)
        self.field_map = {}
    
    def capture(self, duration=60):
        """Capture CAN messages for analysis."""
        start = time.time()
        while time.time() - start < duration:
            msg = self.bus.recv(timeout=1)
            if msg:
                self.messages[msg.arbitration_id].append({
                    'data': msg.data,
                    'timestamp': msg.timestamp,
                    'dlc': msg.dlc,
                })
        print(f"Captured {sum(len(v) for v in self.messages.values())} messages")
        print(f"Across {len(self.messages)} arbitration IDs")
    
    def find_steering_messages(self):
        """Find CAN messages related to steering."""
        # Method: Turn steering wheel while capturing
        # Compare messages before/during/after steering input
        
        steering_candidates = {}
        
        for arb_id, messages in self.messages.items():
            # Check each byte position for correlation with steering
            for byte_pos in range(8):
                values = [m['data'][byte_pos] if byte_pos < len(m['data']) else 0 
                          for m in messages]
                
                # If values change significantly, this byte may be steering-related
                value_range = max(values) - min(values)
                if value_range > 10:  # Threshold for "significant" change
                    if arb_id not in steering_candidates:
                        steering_candidates[arb_id] = {}
                    steering_candidates[arb_id][byte_pos] = {
                        'min': min(values),
                        'max': max(values),
                        'range': value_range,
                    }
        
        return steering_candidates
    
    def find_speed_messages(self):
        """Find CAN messages related to vehicle speed."""
        # Method: Drive at constant speed, then accelerate, then brake
        # Compare byte values at different speeds
        
        speed_candidates = {}
        
        for arb_id, messages in self.messages.items():
            for byte_pos in range(8):
                values = [m['data'][byte_pos] if byte_pos < len(m['data']) else 0
                          for m in messages]
                
                # Speed should have smooth, incremental changes
                # Check if values correlate with a counter that increases/decreases
                
                # Heuristic: 16-bit value that scales with speed
                if byte_pos < 7:
                    # Check 16-bit value (big-endian and little-endian)
                    for endian in ['big', 'little']:
                        if endian == 'big':
                            vals_16 = [(m['data'][byte_pos] << 8) | m['data'][byte_pos+1]
                                      for m in messages if byte_pos+1 < len(m['data'])]
                        else:
                            vals_16 = [m['data'][byte_pos] | (m['data'][byte_pos+1] << 8)
                                      for m in messages if byte_pos+1 < len(m['data'])]
                        
                        if vals_16:
                            # Check if values are in speed range (0-300 km/h * 100)
                            if 0 <= min(vals_16) <= 30000 and max(vals_16) <= 30000:
                                speed_candidates[f"{arb_id:#x}:byte{byte_pos}-{byte_pos+1}({endian})"] = {
                                    'min': min(vals_16),
                                    'max': max(vals_16),
                                    'likely_unit': 'km/h * 100' if max(vals_16) > 3000 else 'km/h',
                                }
        
        return speed_candidates

# CAN bus attack testing (authorized testing only!)
# WARNING: Only perform on closed courses or with explicit authorization

def can_fuzz(arb_id, bus):
    """Fuzz CAN message data bytes."""
    for data_byte in range(256):
        for data_pos in range(8):
            data = [0] * 8
            data[data_pos] = data_byte
            msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)
            bus.send(msg)
```

---

## 7. Bluetooth Protocol RE

### 7.1 Bluetooth Capture and Analysis

```bash
# HCI snoop capture (Android)
# Enable Bluetooth HCI snoop log: Developer Options → Enable Bluetooth HCI snoop log
# Log location: /data/misc/bluetooth/logs/btsnoop_hci.log
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log

# Linux Bluetooth capture
btmon -w bluetooth_capture.pcap
# Or:
hcidump -w bluetooth_capture.pcap

# Wireshark Bluetooth analysis
# Open .btsnoop or .pcap file in Wireshark
# Filter by BT profile: bthci_acl, bthci_cmd, bthci_evt, btatt, btl2cap

# BLE (Bluetooth Low Energy) scanning
bluetoothctl
[bluetooth]# scan on
[bluetooth]# devices
[bluetooth]# info <MAC_ADDRESS>

# BLE GATT service exploration using gatttool
gatttool -b <MAC> -I
[gatttool]# connect
[gatttool]# primary        # List primary services
[gatttool]# characteristics # List characteristics
[gatttool]# char-read-uuid <UUID>  # Read characteristic by UUID
[gatttool]# char-write-uuid <UUID> <VALUE>  # Write characteristic
```

### 7.2 GATT Service Reverse Engineering

```python
# BLE GATT service exploration and reverse engineering
import asyncio
from bleak import BleakClient, BleakScanner

# Known BLE service UUIDs
BLE_SERVICES = {
    '00001800-0000-1000-8000-00805f9b34fb': 'Generic Access',
    '00001801-0000-1000-8000-00805f9b34fb': 'Generic Attribute',
    '0000180d-0000-1000-8000-00805f9b34fb': 'Heart Rate',
    '0000180a-0000-1000-8000-00805f9b34fb': 'Device Information',
    '0000180f-0000-1000-8000-00805f9b34fb': 'Battery Service',
    '0000ffe0-0000-1000-8000-00805f9b34fb': 'Custom Service (common)',
    '0000ffe1-0000-1000-8000-00805f9b34fb': 'Custom Characteristic (common)',
}

async def explore_gatt(device_address):
    """Explore all GATT services and characteristics of a BLE device."""
    async with BleakClient(device_address) as client:
        print(f"Connected to {device_address}")
        
        # Enumerate all services
        services = await client.get_services()
        
        for service in services:
            print(f"\nService: {service.uuid}")
            if service.uuid in BLE_SERVICES:
                print(f"  Name: {BLE_SERVICES[service.uuid]}")
            else:
                print(f"  Name: Unknown (custom service)")
            
            for char in service.characteristics:
                print(f"\n  Characteristic: {char.uuid}")
                print(f"  Properties: {', '.join(char.properties)}")
                
                # Read the characteristic if readable
                if 'read' in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(f"  Value: {value.hex()}")
                        print(f"  Value (ASCII): {value.decode('utf-8', errors='replace')}")
                    except Exception as e:
                        print(f"  Read error: {e}")
                
                # Enumerate descriptors
                for descriptor in char.descriptors:
                    try:
                        desc_value = await client.read_gatt_descriptor(descriptor.uuid)
                        print(f"    Descriptor: {descriptor.uuid} = {desc_value.hex()}")
                    except Exception as e:
                        print(f"    Descriptor: {descriptor.uuid} (read error: {e})")
        
        # Subscribe to all notifiable characteristics
        for service in services:
            for char in service.characteristics:
                if 'notify' in char.properties:
                    print(f"\nSubscribing to {char.uuid}...")
                    await client.start_notify(char.uuid, 
                        lambda x, y: print(f"  Notification from {x}: {y.hex()}"))
                    await asyncio.sleep(2)  # Wait for notifications
                    await client.stop_notify(char.uuid)
```

---

## 8. Game Protocol RE

### 8.1 Game Protocol Analysis

```python
# Game protocol reverse engineering framework
# Games often use custom binary protocols over TCP or UDP

class GameProtocolAnalyzer:
    def __init__(self):
        self.packets = []
        self.known_fields = {}
    
    def load_pcap(self, pcap_file):
        """Load packets from pcap file."""
        from scapy.all import rdpcap
        packets = rdpcap(pcap_file)
        
        for pkt in packets:
            if pkt.haslayer('TCP'):
                payload = bytes(pkt['TCP'].payload)
                if payload:
                    self.packets.append({
                        'data': payload,
                        'src': f"{pkt['IP'].src}:{pkt['TCP'].sport}",
                        'dst': f"{pkt['IP'].dst}:{pkt['TCP'].dport}",
                        'direction': 'C→S' if pkt['TCP'].sport > pkt['TCP'].dport else 'S→C',
                    })
            elif pkt.haslayer('UDP'):
                payload = bytes(pkt['UDP'].payload)
                if payload:
                    self.packets.append({
                        'data': payload,
                        'src': f"{pkt['IP'].src}:{pkt['UDP'].sport}",
                        'dst': f"{pkt['IP'].dst}:{pkt['UDP'].dport}",
                        'direction': 'C→S' if pkt['UDP'].sport > pkt['UDP'].dport else 'S→C',
                    })
    
    def find_packet_ids(self):
        """Find the packet ID/type field."""
        # Heuristic: first 1-2 bytes that determine packet structure
        # ID field should have limited unique values and appear at consistent offset
        
        from collections import Counter
        
        # Try different offsets and sizes for packet ID
        for offset in [0, 1, 2]:
            for size in [1, 2]:
                id_counter = Counter()
                valid = True
                
                for pkt in self.packets:
                    data = pkt['data']
                    if len(data) <= offset + size:
                        continue
                    
                    if size == 1:
                        pkt_id = data[offset]
                    else:
                        pkt_id = int.from_bytes(data[offset:offset+size], 'big')
                    
                    id_counter[pkt_id] += 1
                
                # Good packet ID candidate: few unique values, consistent offset
                if 5 <= len(id_counter) <= 50:
                    print(f"Possible packet ID at offset {offset}, size {size}:")
                    for pid, count in id_counter.most_common(10):
                        print(f"  ID 0x{pid:04x}: {count} packets")
                    print()
    
    def find_encryption(self):
        """Detect if the protocol uses encryption."""
        # High entropy suggests encryption
        import math
        from collections import Counter
        
        for pkt in self.packets[:100]:
            data = pkt['data']
            counter = Counter(data)
            entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in counter.values())
            
            if entropy > 7.5:
                print(f"High entropy ({entropy:.2f}): Likely encrypted")
            elif entropy > 6.0:
                print(f"Medium entropy ({entropy:.2f}): Possibly compressed")
            else:
                print(f"Low entropy ({entropy:.2f}): Likely plaintext")
            break  # Just check first packet

# mitmproxy for game protocol interception
# Save as game_proxy.py
"""
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Intercept HTTP game API calls
    if '/api/' in flow.request.pretty_url:
        print(f"[REQ] {flow.request.method} {flow.request.pretty_url}")
        if flow.request.content:
            print(f"  Body: {flow.request.content[:200].hex()}")

def response(flow: http.HTTPFlow) -> None:
    # Intercept HTTP game API responses
    if '/api/' in flow.request.pretty_url:
        print(f"[RESP] {flow.response.status_code}")
        if flow.response.content:
            print(f"  Body: {flow.response.content[:200].hex()}")

# Run: mitmproxy -s game_proxy.py -p 8080
# Or: mitmdump -s game_proxy.py -p 8080
"""
```

> **Cross-reference**: See [02b_dynamic_analysis.md](02b_dynamic_analysis.md) for debugging and tracing techniques used during protocol RE. See [05a_binary_exploitation_re.md](05a_binary_exploitation_re.md) for protocol exploitation. See the [iot_security track](../iot_security/) for IoT-specific protocol analysis. See the [network_security track](../network_security/) for network protocol security.

---

*This document is part of the Deep Researcher Reverse Engineering track. Protocol RE should only be performed on systems you are authorized to test. Respect terms of service and applicable laws.*

## References

1. Wireshark documentation, https://www.wireshark.org/docs/
2. Scapy documentation, https://scapy.readthedocs.io/
3. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
4. Dennis Yurichev, "Reverse Engineering for Beginners," https://yurichev.com/writings/RE_for_beginners-en.pdf
5. SANS Institute, "Network Forensics" (SEC573), https://www.sans.org/
6. CAN bus specification, Robert Bosch GmbH, "CAN Specification 2.0," 1991.
7. Bluetooth SIG, "Core Specification," https://www.bluetooth.com/specifications/
8. DEF CON and Black Hat conference proceedings on protocol RE.
9. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
10. RFC Editor, various protocol RFCs, https://www.rfc-editor.org/