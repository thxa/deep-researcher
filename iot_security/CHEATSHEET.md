# IoT & Embedded Security Cheatsheet

## UART Pinout Identification

```
4-Pin Header:            3-Pin Header:
┌───┬───┬───┬───┐       ┌───┬───┬───┐
│VCC│TX │RX │GND│       │TX │RX │GND│
└───┴───┴───┴───┘       └───┴───┴───┘

Typical Voltages (DON'T connect VCC to UART adapter!):
VCC: 3.3V or 5V (steady)
TX:  3.3V or 5V (idle high, data bursts during boot)
RX:  0V or 3.3V (idle low or high)
GND: 0V (continuity to board ground)
```

**Quick identification**:
1. Multimeter continuity → find GND (0Ω to USB port shell)
2. Voltage check → VCC (3.3V/5V steady), TX (3.3V/5V idle), RX (0V/3.3V)
3. Logic analyzer → decode baud rate

**Common baud rates**: 9600, 19200, 38400, 57600, 115200, 230400

```bash
# Connect UART
# RX adapter → TX target, TX adapter → RX target, GND → GND
screen /dev/ttyUSB0 115200

# Auto-detect baud rate
for rate in 9600 19200 38400 57600 115200 230400; do
    stty -F /dev/ttyUSB0 $rate raw -echo -clocal
    timeout 3 cat /dev/ttyUSB0 &
    sleep 3; kill %1 2>/dev/null
done
```

## JTAG/SWD Pinout

```
ARM SWD (2-pin + ground):
┌───┬───┬───┐
│SWD│SWC│GND│
│IO │LK│   │
└───┴───┴───┘

ARM JTAG (5-pin standard):
┌───┬───┬───┬───┬───┬───┐
│VCC│TDI│TDO│TCK│TMS│GND│
└───┴───┴───┴───┴───┴───┘

ARM 10-pin Cortex Debug:
Pin 1: VCC    Pin 2: TMS/SWDIO
Pin 3: GND    Pin 4: TCK/SWCLK
Pin 5: GND    Pin 6: TDO/SWO
Pin 7: GND    Pin 8: TDI
Pin 9: GND    Pin 10: nRESET

ARM 20-pin JTAG:
Pin 1: VCC    Pin 2: VCC
Pin 3: TRST   Pin 4: GND
Pin 5: TDI    Pin 6: GND
Pin 7: TMS    Pin 8: GND
Pin 9: TCK    Pin 10: GND
Pin 11: TDO   Pin 12: GND
Pin 13: nRESET Pin 14: GND
Pin 15: DBGRQ Pin 16: GND
Pin 17: DBGACK Pin 18: GND
Pin 19: NC    Pin 20: GND
```

## Common IoT Default Credentials

```
Vendor          | Username  | Password    | Service
--------------- | --------- | ----------- | -------
Ubiquiti        | ubnt      | ubnt        | Web/SSH
TP-Link         | admin     | admin       | Web
Netgear         | admin     | password    | Web
D-Link          | admin     | (blank)     | Web
Dahua           | admin     | admin       | RTSP/Web
Hikvision       | admin     | 12345       | Web
Huawei          | admin     | admin       | Web
MikroTik        | admin     | (blank)     | Winbox
Axis            | root      | root        | Web/SSH
Grandstream     | admin     | admin       | Web
Xiongmai        | admin     | (blank)     | Web
Vacron          | admin     | 888888      | Web
Samsung DVR     | admin     | 4321        | Web
Bose SoundTouch | (none)    | (none)      | API
LG TV           | (none)    | (none)      | Web OS
Raspberry Pi    | pi        | raspberry   | SSH
Arduino Yún     | root      | doghunter   | SSH
OpenWrt         | root      | (blank)     | SSH/Web
DD-WRT          | root      | admin       | Web
Mosquitto       | (none)    | (none)      | MQTT
PostgreSQL      | postgres  | postgres    | DB
MySQL           | root      | (blank)     | DB
Redis           | (none)    | (none)      | DB

Mirai Credentials (62 entries — most effective subset):
root:root  root:admin  root:password  root:1234  root:12345
root:123456  admin:admin  admin:password  admin:1234  admin:12345
admin:123456  admin:default  admin:888888  user:user  guest:guest
support:support  root:vizxv  root:xc3511  root:54321  root:Zte521
supervisor:supervisor  admin:OxdhbodZy  admin:f8ev4kaG
```

## Binwalk / Firmware-Mod-Kit Commands

```bash
# Binwalk — firmware analysis
binwalk firmware.bin                    # Scan for signatures
binwalk -e firmware.bin                 # Extract all filesystems
binwalk -Me firmware.bin                # Recursive extraction
binwalk -E firmware.bin                  # Entropy analysis
binwalk -Y firmware.bin                 # YARA scan

# Common filesystem extraction
binwalk -e --squashfs-offset 0x12345 firmware.bin  # Specific offset

# Sasquatch (enhanced SquashFS)
sasquatch -d squashfs-root/ firmware.bin

# Jefferson (JFFS2)
jefferson firmware.bin -d jffs2_output/

# UBIFS
ubireader_extract_files firmware.bin

# CramFS
cramfsck -x cramfs_root/ firmware.bin

# Entropy analysis (identify encrypted regions)
binwalk -E firmware.bin
# High entropy across entire image = likely encrypted
# Low entropy at start, high entropy after = compressed kernel + encrypted rootfs

# File type identification
file firmware.bin
file extracted/*
readelf -h bin/httpd              # ELF headers
checksec --file=bin/httpd         # Security features

# String analysis
strings -n 8 bin/httpd | grep -iE '(password|secret|key|token|admin|root|cmd|exec)'
strings -n 8 bin/httpd | grep -E 'http://|https://|\.cgi|\.lua'

# Compare two firmware versions
binwalk -e firmware_v1.bin -C v1/
binwalk -e firmware_v2.bin -C v2/
diff -rq v1/squashfs-root/ v2/squashfs-root/
```

## QEMU Emulation Commands

```bash
# ARM user-mode emulation (for static binaries)
qemu-arm-static ./httpd

# ARM full system
qemu-system-arm -M versatilepb \
    -kernel vmlinux \
    -drive file=rootfs.ext2,if=sd \
    -append "root=/dev/mmcblk0 console=ttyAMA0" \
    -nographic \
    -net nic -net user,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22

# MIPS big-endian full system
qemu-system-mips -M malta \
    -kernel vmlinux \
    -drive file=rootfs.ext2,format=raw \
    -append "root=/dev/sda1 console=ttyS0" \
    -nographic \
    -net nic -net user,hostfwd=tcp::8080-:80

# MIPS little-endian full system
qemu-system-mipsel -M malta \
    -kernel vmlinux \
    -drive file=rootfs.ext2,format=raw \
    -append "root=/dev/sda1 console=ttyS0" \
    -nographic

# Chroot emulation (ARM)
cp /usr/bin/qemu-arm-static squashfs-root/usr/bin/
sudo chroot squashfs-root/ /usr/bin/qemu-arm-static /bin/sh

# GDB debugging with QEMU
# Terminal 1:
qemu-arm-static -g 1234 ./httpd
# Terminal 2:
gdb-multiarch ./httpd
(gdb) target remote :1234
(gdb) break system
(gdb) continue

# FirmAE (automated firmware emulation)
git clone https://github.com/pr0v3rbs/FirmAE.git
cd FirmAE && ./install.sh
./sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk "firmware.bin" images
./scratch/run.sh -a Netgear 1
```

## Wireless Attack Tool Reference

### Zigbee

```bash
# KillerBee framework
pip3 install killerbee

# Scan for Zigbee networks
zbstumbler -i apiMote -c 11

# Capture Zigbee traffic
zbdump -i apiMote -c 15 -w capture.pcap

# Replay captured traffic
zbreplay -i apiMote -c 15 -r capture.pcap

# Extract network key during joining
zbsniff -i apiMote -c 15
```

### Z-Wave

```bash
# Z-Wave tools: Z-Wave PC Controller, Razberry, Z-Shaver
# Z-Shaver (S2 downgrade attack)
python3 zshaver.py -d /dev/ttyACM0 -a  # Attack S2 downgrade
```

### BLE

```bash
# BLE enumeration
gatttool -b <MAC> -t random -I
[LE]> connect
[LE]> primary
[LE]> characteristics

# Bettercap BLE
bettercap -T <MAC>
ble.recon on
ble.show

# Ubertooth BLE sniffing
ubertooth-btle -f -t <MAC> -c capture.pcap

# BLEah (automated enumeration)
bleah -t <MAC> -e
```

### Sub-GHz (433/868 MHz)

```bash
# Flipper Zero sub-GHz
# Sub-GHz → Read → Auto or Manual frequency

# HackRF capture and replay
hackrf_transfer -r capture.raw -f 433920000 -s 8000000 -l 32 -g 30
hackrf_transfer -t capture.raw -f 433920000 -s 8000000 -x 30

# YardStick One (custom protocol)
# rfcat -r 1
# >>> d.setRFConfig(MCRMCFG_433MHZ_MOD_2FSK_4800bps)
# >>> d.RFxmit(payload_data)
# >>> d.RFrecv()
```

### Wi-Fi

```bash
# PMKID capture
hcxdumptool -i wlan0 -o capture.pcapng --enable_status=3
hcxpcapngtool -o pmkid_hash.txt capture.pcapng
hashcat -m 22000 pmkid_hash.txt rockyou.txt

# WPS attack
reaver -i wlan0 -b <BSSID> -vv

# Deauth capture (for WPA handshake)
aireplay-ng -0 5 -a <BSSID> -c <CLIENT> wlan0
```

### RFID/NFC

```bash
# Proxmark3
hf search                          # Identify RFID tag
hf mf mifare                       # MIFARE Classic attack
hf mf nested 1 A known_key         # Nested attack
hf mf hardnested 1 A known_key     # Hardnested attack
hf mf dump                          # Dump all sectors
lf search                          # Identify LF tag
lf hid read                        # Read HID Prox
lf em4x read                       # Read EM4100
```

## CAN Bus Quick Reference

```bash
# Setup CAN interface
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# Monitor CAN traffic
candump can0
candump -ta can0                    # With timestamps
candump can0,123:7FF                # Filter by CAN ID

# Send CAN frame
cansend can0 123#0102030405060708   # ID=0x123, 8 data bytes

# Replay CAN log
canplayer -I capture.log

# Generate random CAN traffic
cangen can0 -g 1 -I 1 -i -D 8 -d 1 -L 8

# OBD-II requests (CAN ID 0x7E0)
cansend can0 7E0#010D              # Request: Vehicle Speed
cansend can0 7E0#010C              # Request: Engine RPM
cansend can0 7E0#0902              # Request: VIN

# ELM327 commands
AT Z          # Reset
AT SP 6       # Protocol 6 (CAN 500K)
AT MA         # Monitor all
AT SH 7E0     # Set header (OBD-II request)
01 00          # List supported PIDs
01 0D          # Vehicle Speed
01 0C          # Engine RPM
09 02          # VIN
```

## Medical Device Quick Reference

```
FDA Safety Communication Channels:
- MedWatch: fda.gov/medwatch
- CDRH Pre-market: fda.gov/medical-devices/premarket-submissions
- ICS-CERT: cisa.gov/uscert

Medical Device Network Ports:
- DICOM: 104 (TCP)
- HL7v2: 2575 (TCP)
- IEEE 11073: 20755-20757 (UDP/TCP)
- Proprietary: 5000, 8080, 8443 (common device web UIs)

Common Vulnerabilities:
- Default credentials (admin:admin, service:service)
- Unencrypted communication (RTSP, DICOM, HL7)
- No network segmentation
- Unpatched OS (Windows XP, Windows 7)
- Exposed SSH/Telnet/FTP
```

## IoT Testing Methodology Checklist

### Reconnaissance

- [ ] Search Shodan, ZoomEye, Censys for target devices
- [ ] Identify device model, firmware version, manufacturer
- [ ] Search CVE databases for known vulnerabilities
- [ ] Download firmware from vendor website
- [ ] Analyze mobile companion app (APK/IPA)
- [ ] Identify cloud APIs and endpoints
- [ ] Search GitHub for leaked credentials or source code

### Hardware Assessment

- [ ] Identify UART pins (TX, RX, GND, VCC)
- [ ] Identify JTAG/SWD pins
- [ ] Extract firmware via UART bootloader (U-Boot)
- [ ] Extract firmware via SPI flash programmer
- [ ] Extract firmware via eMMC desoldering
- [ ] Map GPIO pins for boot mode selection
- [ ] Check for debug LEDs, test points, unpopulated headers
- [ ] Measure power consumption (side-channel setup)
- [ ] Identify SoC, flash, RAM, radio chips

### Firmware Analysis

- [ ] Identify firmware structure (TRX, partitions, headers)
- [ ] Extract filesystem (SquashFS, JFFS2, UBIFS, CramFS)
- [ ] Identify binary format (ELF, ARM, MIPS, Xtensa)
- [ ] Check binary hardening (checksec: RELRO, canary, NX, PIE)
- [ ] Search for hardcoded credentials
- [ ] Search for backdoor patterns (reverse shells, suspicious IPs)
- [ ] Search for crypto keys (PEM, DER, hardcoded keys)
- [ ] Emulate firmware in QEMU
- [ ] Fuzz web interfaces (CGI, Lua, GoAhead)
- [ ] Diff firmware versions to find patches

### Network Assessment

- [ ] Port scan (TCP/UDP top 1000 + IoT ports: 23, 80, 443, 554, 1883, 5683, 7547, 8080, 8443, 8883)
- [ ] Identify UPnP services (SSDP discovery)
- [ ] Test MQTT broker (anonymous access, wildcard subscriptions)
- [ ] Test CoAP endpoints (/.well-known/core)
- [ ] Test TR-069/TR-064 (port 7547)
- [ ] Intercept OTA updates (DNS hijacking, MITM)
- [ ] Test cloud API authentication and authorization
- [ ] Test mDNS/ZeroConf services
- [ ] Test DNS rebinding (same-origin policy bypass)

### Wireless Assessment

- [ ] Identify radio protocols (Wi-Fi, BLE, Zigbee, Z-Wave, Sub-GHz)
- [ ] Wi-Fi: WPS attack, PMKID capture, KRACK, deauth
- [ ] BLE: GATT enumeration, KNOB attack, pairing analysis
- [ ] Zigbee: Network key sniffing during joining, Touchlink
- [ ] Z-Wave: S0 key sniffing, S2 downgrade (Z-Shaver)
- [ ] Sub-GHz: Replay attack, rolling code analysis
- [ ] Test companion mobile app (Frida, objection, SSL bypass)

### Exploitation

- [ ] Command injection in CGI/Lua/web interface
- [ ] UPnP exploitation (AddPortMapping, TR-064)
- [ ] MQTT topic ACL bypass
- [ ] Buffer overflow in binary services
- [ ] Default credential brute force
- [ ] Path traversal in web server
- [ ] SSRF against internal services
- [ ] CSRF against device management
- [ ] DNS rebinding for internal access
- [ ] Binary exploitation (ROP, ret2libc on ARM/MIPS)

### Post-Exploitation

- [ ] Check for debug shells
- [ ] Extract more credentials from config files
- [ ] Enumerate connected devices and services
- [ ] Check for lateral movement (other devices on network)
- [ ] Persist access (crontab, init.d, firmware modification)
- [ ] Extract crypto keys and certificates
- [ ] Document cloud API tokens and endpoints
- [ ] Check for data exfiltration paths

### Reporting

- [ ] Document all findings with CVE references
- [ ] Rate each finding with CVSS 3.1 score
- [ ] Provide step-by-step reproduction instructions
- [ ] Include remediation recommendations
- [ ] Categorize by OWASP IoT Top 10
- [ ] Include firmware version and device model
- [ ] Responsible disclosure timeline (90 days)
- [ ] Verify fixes before public disclosure

## References

1. OWASP IoT Top 10 (2014, 2024 drafts). Open Web Application Security Project. https://owasp.org/www-project-top-ten/
2. NIST SP 800-183: Networks of Things. Boyes, M. et al. (2016). National Institute of Standards and Technology.
3. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).
4. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
5. ARM Debug Architecture Specification (ARM IHI 0031). ARM Limited.
6. IEEE 1149.1: Standard for Test Access Port and Boundary-Scan Architecture. IEEE.
7. ChipWhisperer Documentation. NewAE Technology. https://chipwhisperer.readthedocs.io/
8. KillerBee: IEEE 802.15.4/Zigbee Security Research Framework. River Loop Security. https://github.com/riverloopsec/killerbee
9. Proxmark3 Repository. RfidResearchGroup. https://github.com/RfidResearchGroup/proxmark3
10. Bluetooth SIG. Bluetooth Core Specification Version 5.4. https://www.bluetooth.com/
11. Zigbee Alliance. Zigbee 3.0 Specification (05-3474-22). Connectivity Standards Alliance.
12. IEC 62443: Industrial Communication Networks — Network and System Security. International Electrotechnical Commission.
13. ISO 11898: Road Vehicles — Controller Area Network (CAN). International Organization for Standardization.
14. ISO 14229: Unified Diagnostic Services (UDS). International Organization for Standardization.
15. FDA. Content of Premarket Submissions for Management of Cybersecurity Risks in Medical Devices (2023). U.S. Food and Drug Administration.
16. Mirai Source Code. MalwareMustDie. https://malwaremustdie.org/
17. DEF CON IoT Village. https://iotvillage.org/
18. *Car Hacker's Handbook* by Craig Smith. No Starch Press (2016).