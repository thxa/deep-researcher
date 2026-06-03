# IoT Firmware Analysis

## 1. Firmware Acquisition

### Vendor Downloads

Many IoT manufacturers publish firmware updates on their support pages. This is the easiest acquisition method.

**Common firmware sources**:
- Vendor support/download pages (TP-Link, Netgear, D-Link, Hikvision, Dahua)
- OEM firmware repositories (OpenWrt download mirrors, MTK SDKs)
- FTP servers: `ftp://ftp.vendor.com/firmware/` (often indexed)
- Auto-update URLs intercepted from the device or mobile app

**Firmware URL patterns**:
```
https://www.tp-link.com/en/support/download/ARCHER-C7/
https://dlcdnets.asus.com/pub/ASUS/wireless/RT-AC68U/FW_RT_AC68U_300438643604.zip
https://supportproductregistration.dlink.com/
https://security-camera-ip.com/firmware/IPC_FW_2.600.0000.0.bin
```

**URL hunting techniques**:
```bash
# Google dorking
site:vendor.com filetype:bin firmware
site:vendor.com filetype:img firmware update
site:vendor.com intitle:"firmware" intitle:"download"

# Wayback Machine
waybackurls vendor.com | grep -i firmware

# Craling support pages
wget -r -l2 -A.bin,.img,.zip https://support.vendor.com/

# Shodan for update servers
shodan search "HTTP/1.1 200" "firmware" port:80,443 org:"Vendor Inc"
```

### OTA Update Interception

Intercept over-the-air updates between the device and the update server.

**Methods**:
1. **DNS hijacking**: Redirect the device's update domain to a server you control
2. **MITM proxy**: Set up a transparent proxy (Burp Suite, mitmproxy) and configure the device to use it
3. **ARP spoofing**: If the device doesn't use certificate pinning, ARP spoof to intercept
4. ** wlan分流**: Set up a fake AP with the same SSID; the device connects and requests updates

```bash
# mitmproxy for OTA interception
mitmproxy --mode transparent --set block_global=false

# Or with specific host filter
mitmproxy --mode regular -p 8080 --set view_filter="~d update.vendor.com"

# If the device validates SSL, use SSL stripping
ettercap -T -q -i eth0 -M arp:remote /target_ip// /gateway_ip//
```

### Hardware Extraction

When firmware is not available online, extract it directly from the device:

**Method 1: UART console**
```bash
# Connect via UART, interrupt boot, access U-Boot
=> mdw 0x9f000000 0x100000   # Memory dump
=> tftpboot 0x80000000 dump.bin && mdw 0x80000000 0x100000

# Or from Linux:
cat /dev/mtd0 > /dev/ttyS0    # Send flash over serial (slow)
# Better: set up network and use tftp/nc
cat /dev/mtd0 | nc 192.168.1.100 9999  # From device
nc -l -p 9999 > mtd0.bin             # From host
```

**Method 2: SPI flash extraction** (see 02_hardware_interfaces_attacks.md)

**Method 3: eMMC extraction** (see 02_hardware_interfaces_attacks.md)

## 2. Filesystem Identification and Extraction

### Initial Analysis

```bash
# File type identification
file firmware.bin
# Output: firmware.bin: data

# Check for known signatures with binwalk
binwalk firmware.bin

# Entropy analysis to identify compressed/encrypted regions
binwalk -E firmware.bin

# Scan for known signatures (detailed)
binwalk -Y firmware.bin   # YARA signature scan
```

### Binwalk — The Swiss Army Knife

**Basic extraction**:
```bash
# Extract all identified filesystems and signatures
binwalk -e firmware.bin

# Extract with specific run path
binwalk -e -C output_dir/ firmware.bin

# Recursive extraction (for nested archives)
binwalk -Me firmware.bin

# Manual extraction at specific offset
binwalk -dd 'squashfs:1:squashfs' firmware.bin

# Extract specific filesystem
binwalk --signature firmware.bin | grep "Squashfs"
binwalk -e --squashfs-offset 0x12345 firmware.bin
```

**Common firmware structures**:
```
+0x00000:  U-Boot bootloader (raw binary)
+0x20000:  U-Boot environment
+0x40000:  Kernel (gzip-compressed)
+0x1A0000: SquashFS root filesystem
+0xE00000: JFFS2 user config
+0xF80000: TRX header (some vendors)
```

### Firmware-Mod-Kit

For filesystems that binwalk can't handle:

```bash
# Install firmware-mod-kit
git clone https://github.com/rampageX/firmware-mod-kit
cd firmware-mod-kit/src

# Extract firmware
./extract-firmware.sh firmware.bin

# Or individual filesystems:
# SquashFS (all variants)
./unsquashfs_all.sh firmware.bin  squashfs-root/

# CramFS
uncramfs_all.sh firmware.bin cramfs-root/

# UBIFS (from NAND image)
./ubireader_extract_files firmware.bin

# YAFFS2
./unyaffs2 firmware.bin yaffs-root/
```

### Jefferson (JFFS2 Extraction)

```bash
# Install jefferson
pip3 install jefferson

# Extract JFFS2 filesystem
jefferson firmware.bin -d jffs2_output/

# From extracted NAND image with JFFS2
jefferson mtd_partition.bin -d jffs2_output/
```

### Sasquatch (Enhanced SquashFS)

```bash
# Install sasquatch (supports all LZMA/XZ compression variants)
git clone https://github.com/devttys0/sasquatch.git
cd sasquatch && ./build.sh

# Extract SquashFS
sasquatch -d squashfs-root/ firmware.bin

# For LZ4-compressed SquashFS
sasquatch -d squashfs-root/ -f firmware.bin
```

### UBIFS Extraction (NAND-based devices)

```bash
# Install UBIFS tools
apt install mtd-utils uboot-mtd-utils

# Extract from UBI image
ubireader_extract_info firmware.bin
ubireader_extract_files firmware.bin

# Manual extraction (if ubireader fails)
# 1. Create NAND emulation:
modprobe nandsim first_id_byte=0x2c second_id_byte=0xac third_id_byte=0x00 fourth_id_byte=0x15
# 2. Attach UBI:
ubiattach -m 0 -d 0
# 3. Mount:
mount -t ubifs ubi0_0 /mnt/nand
```

### TRX / CFE / Firmware Header Formats

**TRX header** (used by Broadcom/ASUS):
```
Offset  Size  Field
0x00    4     Magic: 0x30524448 ("HDR0")
0x04    4     Length (total TRX size)
0x08    4     CRC32 (over offset 16 to end)
0x0C    4     Flags
0x10    4     Partition 0 offset (kernel)
0x14    4     Partition 1 offset (rootfs)
0x18    4     Partition 2 offset (optional)
```

**Parsing TRX**:
```bash
# Extract TRX partitions manually
dd if=firmware.bin bs=1 skip=$((0x10)) count=4 | xxd  # Partition offsets
dd if=firmware.bin bs=1 skip=$((0x10000)) of=kernel.bin   # Kernel
dd if=firmware.bin bs=1 skip=$((0x80000)) of=rootfs.bin   # Rootfs
```

## 3. Static Analysis of Firmware Binaries

### Binary Format Identification

```bash
# Identify binary format
file bin/httpd
# ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0

# Check for hardening features
checksec --file=bin/httpd
# RELRO        STACK CANARY  NX          PIE         RPATH       RUNPATH     Symbols
# Partial RELRO No canary    NX enabled  No PIE      /lib        No RUNPATH   80 Symbols

# ARM architecture specifics
readelf -A bin/httpd | grep -i arm
# Tag_CPU_name: "ARMv7"
# Tag_CPU_arch: v7
```

### Disassembly and Decompilation

**Ghidra** (NSA, free): Best for embedded firmware analysis. Supports ARM, MIPS, Xtensa, RISC-V.

```
# Ghidra headless analysis
analyzeHeadless /tmp/project firmware -import bin/httpd -postScript find_vulns.py

# Ghidra scripts for IoT:
# - FindStrings: Extract strings from binary
# - FindBufferOverflows: Pattern-based vulnerability detection
# - FindCrypto: Identify crypto constants and functions
```

**IDA Pro** (Hex-Rays): Commercial, best decompilation quality. ARM/MIPS/IISC processors.

```python
# IDA Python script: Find memcpy calls with user-controlled size
import idautils
import idc

for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    if func_name in ['memcpy', 'strcpy', 'sprintf', 'strcat']:
        for xref in idautils.XrefsTo(func_ea):
            print(f"Call to {func_name} at 0x{xref.frm:08X}")
```

**Binary Ninja**: Modern, scriptable disassembler with good ARM/MIPS support.

### String Analysis

```bash
# Extract all strings
strings -n 8 bin/httpd > strings_output.txt

# Find interesting patterns
strings bin/httpd | grep -iE '(password|passwd|pwd|secret|key|token|admin|root|login|cmd|exec|system|popen|shell)'
strings bin/httpd | grep -iE '(http://|https://|ftp://|\.cgi|\.php|\.lua)'
strings bin/httpg | grep -E '/dev/|/tmp/|/var/|/etc/'

# Find potential format strings
strings bin/httpd | grep -E '%[0-9]*[sdxfcn]'

# Find crypto constants (AES, DES, RSA)
strings bin/httpd | grep -iE '(AES|DES|RSA|SHA|MD5|HMAC|ECDSA)'
# Also search for crypto constants in binary:
python3 -c "
import struct
with open('bin/httpd','rb') as f:
    data = f.read()
    # AES S-box constant
    if b'\\x63\\x7c\\x77\\x7b' in data:
        print('Found AES S-box')
    # SHA-256 initial hash values
    for v in [0x6a09e667, 0xbb67ae85]:
        if struct.pack('<I', v) in data:
            print(f'Found SHA-256 constant: {hex(v)}')
"
```

### Symbolic Execution with Angr

```python
import angr
import claripy

# Load binary
proj = angr.Project('bin/httpd', auto_load_libs=False)

# Find path to "command injection" sink
target_addr = 0x00401234  # Address of system() or popen() call
avoid_addr = 0x00401200    # Address of "invalid input" handler

# Create symbolic input
input_data = claripy.BVS('input', 8 * 256)

# Create initial state at the request handler
state = proj.factory.call_state(0x00401000, input_data)

# Run symbolic execution
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target_addr, avoid=avoid_addr)

if simgr.found:
    found = simgr.found[0]
    input_solution = found.solver.eval(input_data, cast_to=bytes)
    print(f"Found input: {input_solution}")
```

## 4. QEMU Emulation of IoT Firmware

### Setting Up QEMU for Firmware Emulation

**ARM (little-endian) emulation** — common for routers, cameras:

```bash
# Install QEMU
apt install qemu-system-arm qemu-system-mips qemu-user-static

# ARM firmware emulation (e.g., DVIA - Damn Vulnerable IoT App)
# First, extract root filesystem
binwalk -e dvia_firmware.bin

# Copy QEMU static binary into chroot
cp /usr/bin/qemu-arm-static squashfs-root/usr/bin/

# Chroot into firmware filesystem
sudo chroot squashfs-root/ /bin/sh
# If successful, you now have a shell running the firmware's userspace

# Run specific binaries
sudo chroot squashfs-root/ /usr/bin/qemu-arm-static /bin/httpd
```

**Full system emulation** (Linux kernel + rootfs):

```bash
# ARM emulation with custom kernel and rootfs
# First, extract kernel and rootfs from firmware
binwalk -e firmware.bin

# ARM ( versatile express )
qemu-system-arm -M versatilepb \
    -kernel vmlinux \
    -drive file=rootfs.ext2,if=sd \
    -append "root=/dev/mmcblk0 console=ttyAMA0" \
    -nographic \
    -net nic -net user,hostfwd=tcp::8080-:80

# MIPS big-endian (common in routers)
qemu-system-mips -M malta \
    -kernel vmlinux \
    -drive file=rootfs.ext2,format=raw \
    -append "root=/dev/sda1 console=ttyS0" \
    -nographic \
    -net nic -net user,hostfwd=tcp::8080-:80

# MIPS little-endian (some routers, e.g., NETGEAR)
qemu-system-mipsel -M malta \
    -kernel vmlinux \
    -drive file=rootfs.ext2,format=raw \
    -append "root=/dev/sda1 console=ttyS0" \
    -nographic
```

### Handling NVRAM Emulation

Many IoT firmware binaries (especially routers) depend on NVRAM for configuration. QEMU doesn't have NVRAM, so we need to emulate it:

**Firmadyne / FirmAE**: Automated framework that handles NVRAM, network, and kernel emulation.

```bash
# Install FirmAE (improved version of Firmadyne)
git clone https://github.com/pr0v3rbs/FirmAE.git
cd FirmAE
./install.sh

# Extract and emulate firmware
./sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk "firmware.bin" images

# Run emulation
./scratch/run.sh -a Netgear 1

# Access emulated device
# Web interface: http://192.168.1.1
# SSH/Telnet: ssh/telnet 192.168.1.1
```

**Manual NVRAM emulation**:
```c
// nvram_faker.c - LD_PRELOAD library to emulate NVRAM
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define MAX_ENTRIES 4096
static struct { char key[64]; char value[256]; } nvram[MAX_ENTRIES];
static int nvram_count = 0;

char *nvram_get(const char *key) {
    for (int i = 0; i < nvram_count; i++) {
        if (strcmp(nvram[i].key, key) == 0)
            return nvram[i].value;
    }
    return NULL;  // Most firmware handles NULL gracefully
}

int nvram_set(const char *key, const char *value) {
    for (int i = 0; i < nvram_count; i++) {
        if (strcmp(nvram[i].key, key) == 0) {
            strncpy(nvram[i].value, value, sizeof(nvram[i].value));
            return 0;
        }
    }
    if (nvram_count < MAX_ENTRIES) {
        strncpy(nvram[nvram_count].key, key, sizeof(nvram[nvram_count].key));
        strncpy(nvram[nvram_count].value, value, sizeof(nvram[nvram_count].value));
        nvram_count++;
        return 0;
    }
    return 1;
}

// Compile:
// arm-linux-gnueabi-gcc -shared -fPIC -o nvram_faker.so nvram_faker.c -ldl
// Then: LD_PRELOAD=./nvram_faker.so ./httpd
```

### Common QEMU Emulation Issues and Solutions

1. **Binary expects specific hardware**: Patch binary to skip hardware detection, or provide `/dev` entries.
2. **NVRAM not found**: Use nvram_faker or Firmadyne's NVRAM emulation.
3. **Network interface mismatch**: Change binary's expected interface name or create a VLAN.
4. **Missing shared libraries**: Copy from firmware rootfs or use `LD_LIBRARY_PATH`.
5. **Kernel panic**: Ensure correct kernel command line, root device, and console.

## 5. Dynamic Analysis in Emulated Environments

### Web Interface Testing

```bash
# Start emulated firmware
# FirmAE: ./scratch/run.sh -a Brand image_id

# Discover web server and CGI
find / -name "*.cgi" -o -name "httpd" -o -name "lighttpd" | head -20
find / -name "*.lua" | head -20

# Enumerate CGI endpoints
strings bin/httpd | grep -E '\.(cgi|php|asp|lua)' | sort -u

# Active scan with Nikto
nikto -h http://192.168.1.1

# Active scan with OWASP ZAP (automated)
# Or manual fuzzing:
ffuf -u http://192.168.1.1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt
ffuf -u http://192.168.1.1/cgi-bin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Binary Analysis with GDB

```bash
# GDB multiarch
apt install gdb-multiarch

# Start QEMU with GDB stub
qemu-system-arm -M versatilepb -kernel vmlinux -drive file=rootfs.ext2 \
    -append "root=/dev/sda1 console=ttyAMA0" -nographic \
    -S -gdb tcp::1234

# Connect GDB
gdb-multiarch
(gdb) set architecture arm
(gdb) target remote :1234
(gdb) continue

# For user-mode emulation:
# Terminal 1: Run binary under QEMU user-mode
qemu-arm-static -g 1234 /path/to/httpd
# Terminal 2: Connect GDB
gdb-multiarch /path/to/httpd
(gdb) target remote :1234
```

### Network Traffic Analysis

```bash
# Capture all traffic on emulated device interface
tcpdump -i any -w capture.pcap host 192.168.1.1

# Replay and modify traffic
# Using tcpreplay
tcpreplay -i eth0 capture.pcap

# Using scapy for custom packet crafting
python3 -c "
from scapy.all import *
pkt = Ether()/IP(dst='192.168.1.1')/TCP(dport=80)/Raw(load='GET /cgi-bin/test;id HTTP/1.0\r\n\r\n')
sendp(pkt, iface='tap0')
"
```

## 6. Firmware Diff Analysis

Comparing two firmware versions reveals security patches and vulnerabilities.

```bash
# Extract both firmware versions
binwalk -e firmware_v1.bin -C v1/
binwalk -e firmware_v2.bin -C v2/

# Diff the root filesystems
diff -rq v1/squashfs-root/ v2/squashfs-root/ | grep "differ"
# Files differing |  sort | uniq

# BinDiff or Diaphora for binary diffing (Ghidra/IDA plugins)
# Install Diaphora for Ghidra:
# 1. Export both binaries from Ghidra as SQLite databases
# 2. Run Diaphora comparison

# Quick function-level diff
# Extract function names from both
arm-linux-gnueabi-nm v1/squashfs-root/bin/httpd > v1_symbols.txt
arm-linux-gnueabi-nm v2/squashfs-root/bin/httpd > v2_symbols.txt
diff v1_symbols.txt v2_symbols.txt

# Patchdiff (IDA Pro plugin) — identifies patched functions
# Bindiff (Zynamics/Google) — graph-based binary diffing
```

**What to look for in firmware diffs**:
- Changed strings (new command patterns, removed error messages)
- New functions (security checks added)
- Modified functions (buffer size changes, input validation added)
- Removed functions (insecure features eliminated)
- Changed constants (key lengths, buffer sizes, timeouts)

## 7. Backdoor Identification

### Signature-Based Detection

```bash
# Search for known backdoor patterns
strings -n 8 bin/httpd | grep -iE '(telnetd|dropbear|sshd|busybox.*sh|/bin/sh.*-i)'
strings -n 8 bin/httpd | grep -E '6666|8888|31337|12345|54321'  # Unusual port numbers

# Known IoT backdoor passwords
strings -n 8 bin/httpd | grep -iE '(OxdhbodZy|zc3vabmz|f8ev4kaG|WmoPS4dL)'
# These are hashed default passwords found in various botnets

# Search for reverse shell patterns
strings -n 8 bin/httpd | grep -iE '(nc\s+-l|nc\s+-e|/dev/tcp|bash.*-i|socat.*fork|openssl.*s_client)'

# Search for DNS tunneling
strings -n 8 bin/httpd | grep -iE '(dnscat|iodine|dns2tcp)'

# Search for known malicious IP ranges
strings -n 8 bin/httpd | grep -E '(5\.188\.86|185\.220\.101|91\.215\.85)'
```

### Behavioral Analysis

```python
# Run firmware in QEMU and monitor system calls
strace -f -e trace=network,execve,open,write,connect ./httpd

# Monitor network connections from emulated firmware
ss -tulnp | grep httpd

# DNS requests from firmware
tcpdump -i any port 53 -A | grep -v "localdomain"

# Unexpected outbound connections (C2 check-in)
# Look for:
# - Long-lived connections to unknown IPs
# - Periodic DNS queries to DGA-like domains
# - HTTP requests with unusual headers (custom C2 protocol)
# - Connections on unusual ports (4444, 6666, 8888, 6667 for IRC)
```

### Known IoT Backdoors

| Backdoor | Description | Indicator |
|----------|-------------|-----------|
| Mirai | Telnet brute force botnet | Binary downloads from `mirai.local` or hardcoded IPs |
| VPNFilter | Stage 1 bootloader filter | Modifies `/dev/mtd0`, hooks `httpd` functions |
| Hajime | P2P botnet | Uses BitTorrent DHT for C2, `irofoqkbiwwbsrmk.onion` |
| Hide 'N Seek | Multi-architecture botnet | Echo-disabling: `echo -e '\x5b\x3d\x5b'` |
| Persirai | Camera botnet | Targets port 81, exploits Realtek SDK CGI |
| Nyx | Router infostealer | Uses Tor for C2, targets MIPS/ARM |
| Echobot | Mirai variant | 100K+ hardcoded IPs, exploits TR-069 |

## 8. Hardcoded Credential Detection

### Automated Detection

```bash
# Find hardcoded passwords in configuration files
grep -rn "password\|passwd\|pwd\|secret\|key\|token" \
    squashfs-root/etc/ squashfs-root/var/ squashfs-root/usr/ \
    --include="*.conf" --include="*.cfg" --include="*.ini" --include="*.xml" \
    --include="*.json" --include="*.properties" --include="*.yaml"

# Common default credential files
find squashfs-root/ -name "passwd" -o -name "shadow" -o -name "htpasswd" \
    -o -name ".htpasswd" -o -name "credentials" -o -name "accounts"

# Crack hashes (if found)
john --format=md5crypt hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 500 hashes.txt /usr/share/wordlists/rockyou.txt

# Find credentials in binaries
strings -n 8 bin/* | grep -E '^\w+:\w+$' | sort -u | head -50
# Filter for common default credentials
strings -n 8 bin/* | grep -iE '(admin|root|guest|user|support):.{3,20}'

# Search PHP/Lua/Shell scripts
find squashfs-root/ -name "*.php" -o -name "*.lua" -o -name "*.sh" | \
    xargs grep -lE '(mysqli_connect|mysql_connect|PDO.*connect|os\.execute|io\.popen)'
```

### Known Default Credentials Database

| Vendor | Username | Password | Service |
|--------|----------|----------|---------|
| Ubiquiti | ubnt | ubnt | Web/Telnet |
| TP-Link | admin | admin | Web |
| Netgear | admin | password | Web |
| D-Link | admin | (blank) | Web |
| Dahua | admin | admin | RTSP/Web |
| Hikvision | admin | 12345 | Web |
| Huawei | admin | admin | Web |
| MikroTik | admin | (blank) | Winbox/Web |
| Axis | root | root | Web/SSH |
| Grandstream | admin | admin | Web |
| Xiongmai | admin | (blank) | Web |
| Vacron | admin | 888888 | Web |

## 9. Certificate and Key Extraction from Firmware

### SSL/TLS Certificate Extraction

```bash
# Find PEM-encoded certificates
find squashfs-root/ -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der"

# Extract certificates from any file
for f in $(find squashfs-root/ -type f); do
    openssl x509 -in "$f" -inform DER -noout 2>/dev/null && echo "DER cert in: $f"
    openssl x509 -in "$f" -inform PEM -noout 2>/dev/null && echo "PEM cert in: $f"
done

# Check certificate validity and properties
openssl x509 -in cert.pem -text -noout

# Find private keys
find squashfs-root/ -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks"
grep -rn "PRIVATE KEY" squashfs-root/
grep -rn "BEGIN RSA" squashfs-root/
grep -rn "BEGIN EC" squashfs-root/
```

### Hardcoded Encryption Keys

```bash
# Search for AES key patterns (32 hex chars = 128-bit key)
strings -n 16 bin/httpd | grep -E '^[0-9a-fA-F]{16,64}$'

# Search for common key derivation patterns
strings bin/httpd | grep -iE '(aes_|des_|rsa_|hmac_|sha256_)key.*=|"key".*:"

# Search for crypto constants
r2 -q -c 'iz~AES' bin/httpd  # radare2 string search for AES references

# Use Lazarus (Python tool) for crypto key extraction
pip3 install lazaru
lazarus bin/httpd
```

### Certificate Pinning Bypass

For mobile companion apps that pin server certificates:

```bash
# Frida bypass for Android
frida -U -f com.vendor.iotapp -l ssl_pinning_bypass.js --no-pause

# Objection (automated Frida)
objection -g com.vendor.iotapp explore
android sslpinning disable

# For iOS:
# Install SSL Kill Switch 2 via Cydia/Substitute
# Or use Frida:
frida -U -f com.vendor.iotapp -l ios_ssl_pinning_bypass.js
```

### Firmware Encryption and Obfuscation

Some manufacturers encrypt firmware images to prevent analysis:

```bash
# Identify encryption
binwalk firmware.bin
# Output may show: "Encrypted data" or unknown compression

# Check for XOR encryption (common in cheap devices)
# XOR entire firmware with common keys (0xFF, 0xAA, 0x55)
python3 -c "
with open('firmware.bin', 'rb') as f:
    data = bytearray(f.read())
for key in [0xFF, 0xAA, 0x55, 0xCC]:
    decrypted = bytes([b ^ key for b in data])
    if decrypted[:4] in [b'\\x7fELF', b'\\x1f\\x8b', b'hsqs', b'KDWM']:
        print(f'XOR key found: 0x{key:02X}')
"

# Check for AES encryption by looking for signature at known offsets after AES-ECB decryption
# (Requires knowing the key from another binary or the bootloader)
```

**Common firmware encryption schemes**:
1. **XOR with vendor key**: Simple obscuration. Key is often found in the bootloader or update script.
2. **AES-ECB**: Common on routers. Key is often derived from the device serial number or MAC address.
3. **AES-CBC**: More secure, but IV is often hardcoded or prepended to the image.
4. **Custom compression + encryption**: Some vendors (e.g., Huawei) use custom LZMA + AES schemes. Key extraction requires analyzing the bootloader.

## 10. References

- *Practical IoT Hacking* by Fotios Chantzis et al. (No Starch Press)
- *The IoT Hacker's Handbook* by Aditya Gupta
- Firmadyne: https://github.com/firmadyne/firmadyne
- FirmAE: https://github.com/pr0v3rbs/FirmAE
- binwalk: https://github.com/ReFirmLabs/binwalk
- AttifyOS: https://github.com/adi0x90/attifyos
- OWASP Firmware Analysis: https://owasp.org/www-project-top-ten/
- *QEMU Emulation of ARM Firmware* — embeddedbits.org
- *A Survey of IoT Firmware Analysis Techniques* — Anju et al. (2023)

## References

1. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021). ISBN: 978-1-7185-0119-7.
2. *The IoT Hacker's Handbook* by Aditya Gupta. Apress (2019). ISBN: 978-1-4842-4299-8.
3. Firmadyne: Towards Autonomous Dynamic Analysis of IoT Firmware. Chen, D. et al. (2016). https://github.com/firmadyne/firmadyne
4. FirmAE: Towards Large-Scale Emulation of IoT Firmware. Kim, M. et al. (2021). https://github.com/pr0v3rbs/FirmAE
5. binwalk: Firmware Analysis Tool. ReFirmLabs. https://github.com/ReFirmLabs/binwalk
6. AttifyOS: IoT Penetration Testing Distribution. https://github.com/adi0x90/attifyos
7. OWASP Firmware Analysis. https://owasp.org/www-project-top-ten/
8. *QEMU Emulation of ARM Firmware* — embeddedbits.org
9. *A Survey of IoT Firmware Analysis Techniques* — Anju et al. (2023).
10. CVE-2017-17562: GoAhead LD_PRELOAD Remote Code Execution. NVD.
11. CVE-2021-42342: GoAhead Authenticated Remote Code Execution. NVD.
12. NIST SP 800-183: Networks of Things. National Institute of Standards and Technology.
13. IEC 62443: Industrial Communication Networks — Network and System Security.
14. OWASP IoT Top 10. https://owasp.org/www-project-top-ten/
15. DEF CON IoT Village Presentations. https://iotvillage.org/
16. Ghidra: NSA Reverse Engineering Framework. https://ghidra-sre.org/
17. IDA Pro: Hex-Rays Disassembler. https://hex-rays.com/
18. Angr: Binary Analysis Platform. https://angr.io/
19. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).
20. FDA Premarket Cybersecurity Guidance (2023). U.S. Food and Drug Administration.