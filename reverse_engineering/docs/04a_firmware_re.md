# Firmware Reverse Engineering

> Comprehensive guide to firmware acquisition, extraction, analysis, and modification for IoT devices, embedded systems, and UEFI/BIOS firmware.

---

## Table of Contents

1. [Firmware RE Overview](#1-firmware-re-overview)
2. [Firmware Acquisition](#2-firmware-acquisition)
3. [Root Filesystem Extraction](#3-root-filesystem-extraction)
4. [Bootloader Analysis](#4-bootloader-analysis)
5. [Embedded Linux Analysis](#5-embedded-linux-analysis)
6. [MIPS/ARM Disassembly Challenges](#6-mipsarm-disassembly-challenges)
7. [Cross-Compilation Analysis](#7-cross-compilation-analysis)
8. [IoT Firmware Signature Verification Bypass](#8-iot-firmware-signature-verification-bypass)
9. [Firmware Modification & Re-Flashing](#9-firmware-modification--re-flashing)
10. [Binary Diff Analysis](#10-binary-diff-analysis)

---

## 1. Firmware RE Overview

Firmware reverse engineering targets the embedded software that controls hardware devices. This ranges from simple microcontrollers running bare-metal code to complex Linux-based IoT devices:

```
Firmware Complexity Spectrum:

Simple MCU           RTOS-based           Embedded Linux        Complex IoT
(Bare metal)         (FreeRTOS, VxWorks)  (BusyBox, OpenWrt)    (Android)
┌──────────┐         ┌──────────┐         ┌──────────┐          ┌──────────┐
│ Flash    │         │ Bootloader│         │ U-Boot   │          │ U-Boot   │
│ ┌──────┐ │         │ ┌──────┐ │         │ Kernel   │          │ Kernel   │
│ │Reset │ │         │ │App   │ │         │ Root FS  │          │ Root FS  │
│ │Vector│ │         │ │Image │ │         │ ┌──────┐ │          │ ┌──────┐ │
│ ├──────┤ │         │ ├──────┤ │         │ │Apps  │ │          │ │Apps  │ │
│ │Code  │ │         │ │RTOS  │ │         │ │Libs  │ │          │ │Libs  │ │
│ ├──────┤ │         │ ├──────┤ │         │ ├──────┤ │          │ ├──────┤ │
│ │Const │ │         │ │FS    │ │         │ │Shell │ │          │ │ART   │ │
│ └──────┘ │         │ └──────┘ │         │ └──────┘ │          │ └──────┘ │
└──────────┘         └──────────┘         └──────────┘          └──────────┘
ARM Cortex-M         MIPS/ARM SOC         MIPS/ARM SoC          ARM SoC
8KB-1MB Flash        1-32MB Flash         8-256MB Flash         128MB-8GB eMMC
```

---

## 2. Firmware Acquisition

### 2.1 UART Extraction

UART (Universal Asynchronous Receiver-Transmitter) provides serial console access to embedded devices:

```bash
# Step 1: Identify UART pins on the PCB
# Look for 4-5 pin headers labeled: TX, RX, VCC, GND
# Or unpopulated through-holes in a row
# Use multimeter to identify:
#   - GND: continuity to ground plane
#   - VCC: 3.3V or 5V (usually marked)
#   - TX: data from device (transmit)
#   - RX: data to device (receive)

# Step 2: Connect UART adapter
# USB-TTL serial adapter (3.3V logic!)
# Connect: TX -> RX, RX -> TX, GND -> GND
# DO NOT connect VCC unless powering from adapter

# Step 3: Determine baud rate
# Common baud rates: 9600, 19200, 38400, 57600, 115200
# Use baudrate scanning tool:
python3 -m serial.tools.miniterm /dev/ttyUSB0 115200

# Or use baudrate detection:
for rate in 9600 19200 38400 57600 115200 230400 460800; do
    echo "Trying $rate..."
    stty -F /dev/ttyUSB0 $rate raw -echo
    timeout 3 cat /dev/ttyUSB0 > /tmp/uart_$rate.txt 2>/dev/null &
    sleep 3
    kill %1 2>/dev/null
    if [ -s /tmp/uart_$rate.txt ]; then
        echo "Baud rate found: $rate"
        cat /tmp/uart_$rate.txt
        break
    fi
done

# Step 4: Access bootloader console
# Power-cycle device and press key to interrupt boot
# Common keys: Ctrl+C, Space, Enter, any key
# U-Boot: press any key during "Hit any key to stop autoboot"

# Step 5: Extract firmware from U-Boot
# Read flash to memory, then dump memory
=> md 0x9f070000 0x1000     # Dump memory at address
=> nand read 0x82000000 0x0 0x400000  # Read NAND flash to RAM
=> tftpboot 0x82000000 firmware.bin     # Or TFTP transfer

# Using UART for binary transfer (XMODEM):
# From device:
=> loadx 0x82000000
# Then use XMODEM from host to send file
```

### 2.2 JTAG Extraction

JTAG (Joint Test Action Group) provides low-level hardware debug access:

```bash
# JTAG Pin Identification
# Standard JTAG has 4 mandatory signals:
#   TCK — Test Clock
#   TMS — Test Mode Select
#   TDI — Test Data In
#   TDO — Test Data Out
# Plus optional:
#   TRST — Test Reset
#   VREF — Reference Voltage

# Common JTAG pin headers: 2x5, 2x10, 1x10, ARM 20-pin

# Step 1: Identify JTAG interface
# Look for unpopulated headers near the SoC
# Use JTAGulator to identify pinout:
# https://github.com/grandideastudio/jtagulator

# Step 2: Connect JTAG adapter
# Popular adapters:
#   - Segger J-Link (commercial, excellent support)
#   - Olimex ARM-USB-OCD (affordable)
#   - FLOSS JTAG (open source)
#   - Bus Blaster (open source)

# Step 3: Access JTAG with OpenOCD
# Create OpenOCD config file for your target

# openocd.cfg for MIPS (common in routers)
source [find interface/ftdi/olimex-arm-usb-ocd.cfg]
source [find target/mips_m4k.cfg]

adapter_khz 1000

init
halt

# Step 4: Read flash via JTAG
# Dump entire flash memory
flash read_bank 0 firmware.bin 0 0x1000000

# Or read specific addresses
mdw 0xbf000000 0x1000  # Memory dump

# Step 5: Extract firmware
# Read all of flash memory into a file
# openocd -f openocd.cfg -c "init; halt; flash read_bank 0 firmware.bin; exit"
```

### 2.3 SPI Flash Extraction

Most IoT devices use SPI NOR flash chips that can be directly read:

```bash
# Step 1: Identify flash chip
# Common chips: Winbond W25Qxx, Macronix MX25Lxx, Micron N25Qxx
# Read chip markings on the flash chip package

# Step 2: Set up flashrom
# flashrom is the standard tool for reading/writing flash chips
# Supported programmers: buspirate, ch341a, ft2232, linux_spi

# Using CH341A USB programmer (cheap, widely available)
flashrom -p ch341a_spi -r firmware_dump.bin

# Using Bus Pirate
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware_dump.bin

# Using Raspberry Pi SPI (linux_spi)
flashrom -p linux_spi:dev=/dev/spidev0.0,spimaxhz=1000 -r firmware_dump.bin

# Step 3: Verify the dump
flashrom -p ch341a_spi -r verify.bin
diff firmware_dump.bin verify.bin
# If identical, dump is good

# Step 4: Read chip info
flashrom -p ch341a_spi --flash-size
# Output: "Found Winbond W25Q128.V flash chip (16384 kB)"

# Step 5: In-circuit reading (chip stays on PCB)
# Use chip clip (Pomona 5250 or similar) connected to SOIC-8 package
# WARNING: Ensure target board is powered OFF or in known state
# Some boards may need to be powered for proper flash access

# Common flash sizes:
# W25Q16 = 2MB, W25Q32 = 4MB, W25Q64 = 8MB, W25Q128 = 16MB
# MX25L1606 = 2MB, MX25L3206 = 4MB, MX25L6406 = 8MB, MX25L12806 = 16MB
```

---

## 3. Root Filesystem Extraction

### 3.1 Binwalk Analysis

```bash
# Binwalk is the primary tool for firmware analysis and extraction
# Install: apt install binwalk (or pip install binwalk)

# Step 1: Scan firmware image
binwalk firmware.bin

# Common output:
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             U-Boot boot loader
# 131072        0x20000         Linux kernel ARM boot image
# 262144        0x40000         Squashfs filesystem
# 1835008       0x1C0000        JFFS2 filesystem
# 3276800       0x320000        Cramfs filesystem

# Step 2: Extract all identified filesystems
binwalk -e firmware.bin
# Creates _firmware.bin.extracted/ with extracted components

# Step 3: Recursive extraction (firmware within firmware)
binwalk -Me firmware.bin
# Extracts nested images

# Step 4: Scan for specific signatures
binwalk -y squashfs firmware.bin     # Only squashfs
binwalk -y uimage firmware.bin       # Only U-Boot images
binwalk -y cpio firmware.bin         # Only CPIO archives

# Step 5: Entropy analysis
binwalk -E firmware.bin
# Shows entropy graph — helps identify compressed/encrypted regions

# Step 6: Detailed comparison
binwalk -W firmware_v1.bin firmware_v2.bin
# Compares two firmware images
```

### 3.2 Filesystem Types

```python
# Common embedded filesystems and how to extract them

FILESYSTEM_TYPES = {
    'SquashFS': {
        'command': 'unsquashfs -d rootfs firmware.squashfs',
        'description': 'Most common compressed read-only FS in embedded Linux',
        'variants': ['squashfs-le', 'squashfs-be', 'squashfs-v4', 'squashfs-v3'],
        'extraction': 'unsquashfs -d <output_dir> <squashfs_image>',
        'note': 'May need to specify endianness: unsquashfs -le or unsquashfs -be',
    },
    'JFFS2': {
        'command': 'jefferson firmware.jffs2',
        'description': 'Journaling Flash File System v2 (MTD-based)',
        'variants': ['jffs2-big-endian', 'jffs2-little-endian'],
        'extraction': 'jefferson <jffs2_image> -d <output_dir>',
        'note': 'Older tool: jffs2dump; Jefferson handles more edge cases',
    },
    'YAFFS': {
        'command': 'python3 yaffshiv.py -f firmware.yaffs',
        'description': 'Yet Another Flash File System (NAND flash)',
        'extraction': 'python3 yaffshiv.py -f <yaffs_image> -d <output_dir>',
        'note': 'YAFFS2 is common in Android devices',
    },
    'CramFS': {
        'command': 'mount -t cramfs firmware.cramfs /mnt/cramfs',
        'description': 'Compressed ROM filesystem (older devices)',
        'extraction': 'mount -t cramfs <image> <mountpoint> -o loop',
        'note': 'Read-only; copy files after mounting',
    },
    'UBIFS/UBI': {
        'command': 'ubireader_extract_images firmware.ubi',
        'description': 'UBI/UBIFS (Unsorted Block Image, NAND flash)',
        'extraction': 'ubireader_extract_images <ubi_image>',
        'note': 'UBI is a volume management layer; UBIFS is the filesystem',
    },
    'CPIO': {
        'command': 'cpio -idmv < firmware.cpio',
        'description': 'Copy In/Out (initial RAM disk)',
        'extraction': 'mkdir rootfs && cd rootfs && cpio -idmv < <cpio_image>',
        'note': 'Usually initramfs (initial RAM filesystem for kernel boot)',
    },
    'ext2/3/4': {
        'command': 'mount -o loop,ro firmware.ext4 /mnt/ext4',
        'description': 'Extended filesystem (common in IoT Linux)',
        'extraction': 'mount -o loop,ro <image> <mountpoint>',
        'note': 'May need e2fsck first if image is corrupted',
    },
    'FAT16/32': {
        'command': 'mount -o loop,ro firmware.fat /mnt/fat',
        'description': 'FAT filesystem (common in UEFI)',
        'extraction': 'mount -o loop,ro <image> <mountpoint>',
        'note': 'UEFI firmware volumes often use FAT for EFI System Partition',
    },
}
```

### 3.3 firmware-mod-kit

```bash
# firmware-mod-kit (FMK) — for extracting and rebuilding firmware
# https://github.com/mirror/firmware-mod-kit

# Extract firmware
./extract-firmware.sh firmware.bin
# Creates: firmware.bin.extracted/ rootfs/ kernel/ etc.

# Modify extracted firmware
# Edit rootfs files:
vim firmware.bin.extracted/rootfs/etc/passwd
vim firmware.bin.extracted/rootfs/etc/shadow

# Add debugging tools (dropbear SSH server)
cp /usr/bin/dropbear firmware.bin.extracted/rootfs/usr/bin/
cp dropbearkey firmware.bin.extracted/rootfs/usr/bin/

# Modify init scripts
vim firmware.bin.extracted/rootfs/etc/init.d/S50dropbear

# Rebuild firmware
./build-firmware.sh firmware.bin.extracted/
# Creates: firmware.bin.modified

# Flash modified firmware:
flashrom -p ch341a_spi -w firmware.bin.modified
```

### 3.4 Manual Firmware Unpacking

```bash
# When binwalk fails — manual firmware unpacking

# Step 1: Identify firmware structure with hex editor
xxd firmware.bin | head -100

# Step 2: Search for known headers
# U-Boot: search for "U-Boot" string
strings -t x firmware.bin | grep "U-Boot"

# Linux kernel: search for ARM/PowerPC boot header (0x27051956 for ARM)
xxd firmware.bin | grep "2705 1956"

# SquashFS: search for "hsqs" (0x73617371 in LE, 0x73717368 in BE)
xxd firmware.bin | grep -i "7371 7368"
# Or: "sqsh" magic
xxd firmware.bin | grep -i "7371 7368"

# Step 3: Extract at known offsets
dd if=firmware.bin bs=1 skip=262144 of=kernel.bin
dd if=firmware.bin bs=1 skip=393216 of=rootfs.bin

# Step 4: Verify extracted components
file kernel.bin      # Linux kernel ARM boot image
file rootfs.bin       # Squashfs filesystem

# Step 5: Extract filesystem
unsquashfs rootfs.bin
```

---

## 4. Bootloader Analysis

### 4.1 U-Boot Analysis

```bash
# U-Boot is the most common bootloader in embedded Linux

# Step 1: Access U-Boot console
# Connect UART, power-cycle, press any key during "Hit any key to stop autoboot"

# Step 2: Explore U-Boot environment
=> printenv
# Shows all environment variables:
# bootcmd=bootm 0x9f070000
# bootargs=console=ttyS0,115200 root=31:03 rootfstype=squashfs
# baudrate=115200
# ipaddr=192.168.1.1
# serverip=192.168.1.100

# Step 3: Extract U-Boot image
# U-Boot images start with uImage header (64 bytes)
# Magic: 0x27051956

# Parse U-Boot image header
python3 << 'EOF'
import struct

with open('u-boot.bin', 'rb') as f:
    header = f.read(64)

# uImage header structure:
magic = struct.unpack('>I', header[0:4])[0]
hcrc = struct.unpack('>H', header[4:6])[0]
time = struct.unpack('>I', header[8:12])[0]
size = struct.unpack('>I', header[12:16])[0]
load = struct.unpack('>I', header[16:20])[0]
entry = struct.unpack('>I', header[20:24])[0]
dcrc = struct.unpack('>I', header[24:28])[0]
os = header[28]
arch = header[29]
itype = header[30]
comp = header[31]
name = header[32:64].decode('utf-8', errors='replace').rstrip('\x00')

print(f"Magic: 0x{magic:08x} ({'OK' if magic == 0x27051956 else 'INVALID'})")
print(f"Image size: {size} bytes ({size/1024:.1f} KB)")
print(f"Load address: 0x{load:08x}")
print(f"Entry point: 0x{entry:08x}")
print(f"OS: {os} (1=Linux, 2=NetBSD, 3=FreeBSD, 4=OpenBSD)")
print(f"Architecture: {arch} (2=ARM, 5=MIPS, 6=PowerPC, 7=x86)")
print(f"Type: {itype} (1=Kernel, 2=Ramdisk, 3=Standalone)")
print(f"Compression: {comp} (0=none, 1=gzip, 2=bzip2, 3=lzma, 4=lzo)")
print(f"Name: {name}")
EOF

# Step 4: Extract kernel from U-Boot image
# Skip 64-byte header, decompress if needed
dd if=firmware.bin bs=1 skip=64 of=kernel.gz

# Decompress kernel
gunzip kernel.gz  # If gzip compressed
# Or:
lzma -d kernel.lzma kernel  # If LZMA compressed
```

### 4.2 UEFI Analysis

```python
# UEFI firmware analysis using UEFITool and CHIPSEC

# UEFI firmware structure:
# Flash → FV (Firmware Volume) → FFS (Firmware File System) → Sections → PE/COFF

# Step 1: Extract UEFI firmware
# Get firmware image from:
#   - Vendor update packages
#   - SPI flash dump (flashrom)
#   - BIOS region extraction (Chipsec)

# Step 2: Analyze with UEFITool
# https://github.com/LongSoft/UEFITool
UEFITool firmware.bin
# GUI tool for navigating UEFI firmware structure
# Can extract individual modules, view NVAR variables, diff firmware

# Step 3: Extract EFI modules
# In UEFITool, right-click → Extract Body → Save as .efi

# Step 4: Analyze EFI modules
# EFI modules are PE/COFF executables
file module.efi
# PE32+ executable (DLL) (EFI application)

# Analyze with standard PE tools:
python3 << 'EOF'
import pefile

pe = pefile.PE('module.efi')
print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
print(f"Sections: {pe.FILE_HEADER.NumberOfSections}")
print(f"Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")

# EFI-specific: look for EFI protocols and GUIDs
for section in pe.sections:
    name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
    print(f"  Section: {name}")

# EFI boot services
efi_apis = ['gBS->', 'gST->', 'gRT->', 'EfiBootServices', 'EfiRuntimeServices']
EOF

# Step 5: Analyze with Chipsec (firmware security)
# https://github.com/chipsec/chipsec
chipsec_main.py -m tools.uefi.s3sleepscript   # S3 sleep script analysis
chipsec_main.py -m common.bios.smi            # SMI handler analysis
chipsec_main.py -m common.secureboot           # Secure Boot status
```

---

## 5. Embedded Linux Analysis

### 5.1 Root Filesystem Analysis

```bash
# After extracting the root filesystem, analyze its contents

# Check for default/weak credentials
cat rootfs/etc/passwd
cat rootfs/etc/shadow
# Common issues:
#   root::0:0:root:/root:/bin/sh       (empty password!)
#   root:$1$xyz$:hash::0:0:root:/root:/bin/sh  (MD5 hash, crackable)
#   admin:admin::0:0:admin:/admin:/bin/sh       (default credentials)

# Check for hardcoded credentials
grep -r "password" rootfs/etc/ --include="*.conf" --include="*.cfg"
grep -r "username" rootfs/etc/ --include="*.conf" --include="*.cfg"
grep -r "secret" rootfs/etc/ --include="*.conf" --include="*.cfg"

# Check for web server and CGI scripts
find rootfs/ -name "*.cgi" -o -name "*.php" -o -name "*.lua"
cat rootfs/etc/httpd.conf  # BusyBox httpd config
find rootfs/ -path "*/www/*" -type f  # Web content

# Check for running services
cat rootfs/etc/inetd.conf    # inetd services
cat rootfs/etc/xinetd.conf   # xinetd services
cat rootfs/etc/init.d/*      # Init scripts
ls rootfs/etc/rc.d/          # Runlevel scripts

# Check for network services
grep -r "listen" rootfs/etc/ --include="*.conf"
cat rootfs/etc/services      # Service definitions

# Check for debug interfaces
grep -r "telnetd" rootfs/etc/init.d/
grep -r "sshd" rootfs/etc/init.d/
grep -r "dropbear" rootfs/etc/init.d/

# Check kernel command line
cat rootfs/etc/cmdline
cat rootfs/proc/cmdline       # Runtime (if accessible)

# Check for crypto keys
find rootfs/ -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "*.p12"
grep -r "BEGIN RSA" rootfs/
```

### 5.2 Binary Analysis in Rootfs

```bash
# Analyze binaries in the root filesystem

# Check architecture of binaries
file rootfs/bin/busybox
# Example: ELF 32-bit MSB executable, MIPS, MIPS32 version 1 (SYSV)

# List all binaries and their architectures
find rootfs/ -type f -executable | while read f; do
    arch=$(file "$f" | grep -oP 'ELF \K\d+-bit')
    if [ -n "$arch" ]; then
        echo "$arch $f"
    fi
done | sort | uniq -c | sort -rn

# Check for stripped binaries
find rootfs/ -type f -name "*.so" -o -name "*" -executable | while read f; do
    if file "$f" | grep -q "not stripped"; then
        echo "NOT STRIPPED: $f"
    fi
done

# Check for vulnerable binaries
# Look for BusyBox version (common target)
strings rootfs/bin/busybox | grep "BusyBox"
# BusyBox v1.24.1 (2020-01-15 10:30:00 UTC)

# Check for known vulnerable services
strings rootfs/usr/sbin/httpd | grep -i "version\|httpd"
strings rootfs/usr/bin/wpa_supplicant | grep -i "version"

# Check for dangerous functions (no bounds checking)
for bin in rootfs/bin/* rootfs/usr/bin/* rootfs/usr/sbin/*; do
    if file "$bin" | grep -q ELF; then
        dangerous=$(strings "$bin" | grep -cE 'strcpy|strcat|sprintf|gets|scanf')
        if [ "$dangerous" -gt 0 ]; then
            echo "DANGEROUS: $bin ($dangerous dangerous function calls)"
        fi
    fi
done
```

---

## 6. MIPS/ARM Disassembly Challenges

### 6.1 MIPS Disassembly

```asm
; MIPS disassembly challenges

; Challenge 1: Branch delay slots
; In MIPS, the instruction after a branch is ALWAYS executed (delay slot)
; This means:
    bnez    $t0, target       ; Branch if not zero
    nop                       ; ← This executes BEFORE the branch takes effect
                             ; (delay slot)
    ; The delay slot instruction is part of the preceding branch
    ; Disassemblers that don't account for this will produce incorrect CFGs

; Challenge 2: PIC (Position-Independent Code) patterns
; MIPS PIC code uses a GOT-like pattern:
    lui     $t0, %hi(_gp_disp)
    addiu   $t0, $t0, %lo(_gp_disp)
    ; $t0 now contains the GOT offset

; Challenge 3: Uncleared delay slots after relocations
; Some MIPS firmware has uncleared delay slots:
    lw      $t9, %call16(func)($gp)
    jalr    $t9
    nop                       ; Sometimes this is not a NOP but valid code

; Challenge 4: MIPS32 vs MIPS16 vs microMIPS
; MIPS16: 16-bit instruction encoding (compressed)
; microMIPS: Mixed 16/32-bit encoding
; Same binary may contain different ISA modes

; Challenge 5: Endianness
; MIPS can be big-endian or little-endian
; Big-endian (most network equipment): bytes are stored in network order
; Little-endian (some SoCs): bytes reversed
; Wrong endianness setting = complete gibberish disassembly
```

```python
# Setting up MIPS cross-compilation and analysis environment

# Install MIPS toolchain
sudo apt install gcc-mips-linux-gnu gcc-mipsel-linux-gnu
# mips-linux-gnu-gcc      — Big-endian MIPS compiler
# mipsel-linux-gnu-gcc    — Little-endian MIPS compiler

# Install MIPS emulator
sudo apt install qemu-user-static qemu-system-mips

# Run MIPS binary on x86
qemu-mips-static -L /usr/mips-linux-gnu ./mips_binary
qemu-mipsel-static -L /usr/mipsel-linux-gnu ./mipsel_binary

# Run with strace equivalent
qemu-mips-static -strace -L /usr/mips-linux-gnu ./mips_binary

# Debug with GDB
qemu-mips-static -g 1234 -L /usr/mips-linux-gnu ./mips_binary &
mips-linux-gnu-gdb ./mips_binary
(gdb) target remote :1234

# Ghidra: Set language to MIPS:BE:32 (big-endian) or MIPS:LE:32 (little-endian)
# IDA: Processor type = MIPS, set endianness in load options
```

### 6.2 ARM Disassembly

```asm
; ARM disassembly challenges

; Challenge 1: ARM vs Thumb mode switching
; ARM instructions are 32-bit, Thumb are 16-bit (or mixed 16/32)
; The processor can switch between modes using BX/BLX instructions
    .arm
    mov     r0, #1
    bx      r1               ; Branch and exchange
    ; If r1 bit 0 = 1: switch to Thumb mode
    ; If r1 bit 0 = 0: stay in ARM mode

    .thumb
    movs    r0, #1           ; 16-bit Thumb instruction
    blx     arm_function     ; Switch to ARM mode for function call

; Challenge 2: IT blocks (Thumb-2 conditional execution)
; IT (If-Then) blocks allow conditional execution of up to 4 Thumb instructions
    ittee   eq               ; If EQ: first two Thumb; else: next two Thumb
    moveq   r0, #1           ; Execute if EQ
    addeq   r0, r0, #1       ; Execute if EQ
    movne   r0, #0           ; Execute if NE
    addne   r0, r0, #2       ; Execute if NE
    ; Disassemblers must track IT state for correct disassembly

; Challenge 3: VFP/NEON instructions
; Vector Floating Point (VFP) and NEON SIMD instructions
; vadd.f32 s0, s1, s2       ; VFP single-precision add
; vadd.f64 d0, d1, d2       ; VFP double-precision add
; vld1.8 {d0-d3}, [r0]      ; NEON load 32 bytes

; Challenge 4: ARM64/AArch64 differences
; AArch64 has:
;   - 31 general-purpose registers (x0-x30, sp, pc is not directly accessible)
;   - No conditional execution of most instructions (no IT blocks)
;   - New addressing modes
;   - Different instruction encoding
    mov     x0, #0x41        ; 64-bit register
    str     x0, [x1, #8]!    ; Pre-indexed store
    ldr     x2, [x1], #8     ; Post-indexed load
```

---

## 7. Cross-Compilation Analysis

### 7.1 Identifying Cross-Compiled Binaries

```bash
# Identify the target architecture of firmware binaries
file rootfs/bin/busybox
# ELF 32-bit MSB executable, MIPS, MIPS32 version 1 (SYSV)

# Check all binaries in firmware
find rootfs/ -type f | file -f - | grep ELF

# Check shared library dependencies
mips-linux-gnu-readelf -d rootfs/lib/libc.so.0 | grep NEEDED
# NEEDED: ld-uClibc.so.0
# NEEDED: libgcc_s.so.1

# Check for specific libc implementations
strings rootfs/lib/libc.so.0 | grep -E "uClibc|glibc|musl|diet"
# "uClibc 0.9.33.2" — very common in embedded Linux

# Check GCC version used for compilation
strings rootfs/bin/busybox | grep "GCC"
# "GCC: (Buildroot 2020.02) 8.3.0"

# Check for build system signatures
strings rootfs/bin/* | grep -iE "buildroot|openwrt|yocto|ptx|broadcom| Qualcomm"
```

### 7.2 Cross-Architecture Debugging

```bash
# Set up cross-architecture debugging environment

# ARM debugging
# Terminal 1: Start QEMU with GDB stub
qemu-arm-static -g 1234 -L /usr/arm-linux-gnueabi ./arm_binary

# Terminal 2: Connect with cross-architecture GDB
arm-linux-gnueabi-gdb ./arm_binary
(gdb) set sysroot /usr/arm-linux-gnueabi
(gdb) target remote :1234
(gdb) break main
(gdb) continue

# MIPS debugging
qemu-mips-static -g 1234 -L /usr/mips-linux-gnu ./mips_binary

mips-linux-gnu-gdb ./mips_binary
(gdb) set sysroot /usr/mips-linux-gnu
(gdb) target remote :1234

# Full system emulation with QEMU
# Create disk image from firmware:
qemu-img create -f qcow2 disk.qcow2 256M
# Boot with kernel and rootfs:
qemu-system-arm -M vexpress-a9 -kernel zImage \
    -dtb vexpress-v2p-ca9.dtb \
    -drive file=disk.qcow2,if=sd \
    -append "console=ttyAMA0 root=/dev/sda1" \
    -nographic -serial stdio
```

---

## 8. IoT Firmware Signature Verification Bypass

### 8.1 Firmware Signature Verification

IoT devices often verify firmware signatures before applying updates:

```
Firmware Update Flow:
┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│ Download │────>│ Verify       │────>│ Flash       │────>│ Reboot   │
│ Firmware │     │ Signature    │  NO │ Firmware    │     │ Device   │
└──────────┘     └──────┬───────┘     └──────────────┘     └──────────┘
                        │ YES
                        v
                 ┌──────────────┐
                 │ Reject Update │
                 └──────────────┘
```

Bypass techniques:

```python
# Technique 1: Patch the signature verification function
# Find the verification function (usually in bootloader or update daemon)
# Common function names: verify_signature, check_update, validate_firmware
# Pattern: function returns 0 (success) or 1 (failure)
# Patch: change conditional branch after verification to always succeed

# In MIPS assembly:
# Original:
    addiu   $v0, $zero, 0     ; $v0 = 0 (success)
    bnez    $v0, fail_branch   ; if $v0 != 0, branch to fail
    ; ... success path ...

# Patched:
    addiu   $v0, $zero, 0     ; $v0 = 0 (success)
    nop                       ; replaced bnez with nop (always succeed)
    ; ... success path ...

# Technique 2: Replace the public key
# If the device uses RSA signature verification with an embedded public key,
# replace the embedded key with our own key pair
# 1. Generate new RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 2. Find the embedded public key in the firmware
# Search for DER-encoded RSA public key (starts with 0x30 0x82 ...)
# Or PEM-encoded key

# 3. Replace the public key in the firmware binary
# Same size replacement is easiest
python3 << 'EOF'
with open('firmware.bin', 'rb') as f:
    data = f.read()

# Find the public key
old_key_start = data.find(b'-----BEGIN PUBLIC KEY-----')
if old_key_start == -1:
    # Try DER-encoded key
    old_key_start = data.find(b'\x30\x82')  # ASN.1 SEQUENCE

with open('new_public_key.der', 'rb') as f:
    new_key = f.read()

# Replace (assuming same size or we pad/trim)
if len(new_key) <= data[old_key_start:].find(b'\x00\x00\x00'):
    patched = data[:old_key_start] + new_key + b'\x00' * (2048 - len(new_key)) + data[old_key_start + 2048:]
    with open('firmware_patched.bin', 'wb') as f:
        f.write(patched)
EOF

# Technique 3: Hook signature verification at runtime
# Using Frida to hook the verification function
# Note: requires device access (UART, shell)

# Technique 4: Exploit buffer overflow in update mechanism
# The update URL parsing, filename handling, or version string parsing
# may have buffer overflows that allow code execution

# Technique 5: Downgrade attack
# If older firmware versions are accepted and have known vulnerabilities,
# downgrade to a version with weaker signature verification
```

---

## 9. Firmware Modification & Re-Flashing

### 9.1 Modifying Firmware

```bash
# Step 1: Extract firmware components
binwalk -e firmware.bin

# Step 2: Modify the root filesystem
cd _firmware.bin.extracted/squashfs-root/

# Add SSH access (dropbear)
cp /usr/bin/dropbear usr/bin/
cp /usr/bin/dropbearkey usr/bin/

# Add backdoor account
echo "backdoor::0:0:root:/root:/bin/sh" >> etc/passwd

# Add init script
cat > etc/init.d/S99backdoor << 'EOF'
#!/bin/sh
# Start dropbear SSH server
/usr/bin/dropbearkey -t rsa -f /etc/dropbear_host_key -s 2048
/usr/bin/dropbear -r /etc/dropbear_host_key -p 22
EOF
chmod +x etc/init.d/S99backdoor

# Step 3: Rebuild squashfs filesystem
# Important: Use the same squashfs version as the original
# Check original squashfs parameters:
unsquashfs -s ../squashfs-root.img
# Output includes: version, block_size, compression, endianness

# Rebuild with matching parameters
mksquashfs squashfs-root/ new_rootfs.bin -comp xz -b 262144 -no-xattrs

# Step 4: Rebuild firmware image
# This varies by vendor — need to know the firmware format
# Replace rootfs in original firmware:
dd if=firmware.bin of=new_firmware.bin bs=1 count=<kernel_end_offset>
dd if=new_rootfs.bin of=new_firmware.bin bs=1 seek=<rootfs_start_offset> conv=notrunc

# Step 5: Calculate and update checksums
# Many firmware formats have checksums/MACs that must be recalculated
python3 << 'EOF'
import struct, hashlib

with open('new_firmware.bin', 'rb') as f:
    data = bytearray(f.read())

# Common checksum locations:
# - Last 4 bytes: CRC32 checksum
# - Header checksum field: typically at offset 0x10-0x14
# - HMAC at the end of the image

# Calculate CRC32 of everything except the checksum field
import zlib
crc = zlib.crc32(bytes(data[:-4])) & 0xFFFFFFFF
struct.pack_into('<I', data, len(data) - 4, crc)

with open('new_firmware_with_checksum.bin', 'wb') as f:
    f.write(data)
EOF
```

### 9.2 Re-Flashing

```bash
# Method 1: SPI flash programming (most reliable)
# Requires physical access and flash programmer (CH341A, Bus Pirate, etc.)
flashrom -p ch341a_spi -w new_firmware.bin

# Method 2: Vendor update mechanism
# Many devices accept firmware updates via web interface or TFTP

# Method 3: U-Boot TFTP update
# 1. Set up TFTP server
# 2. In U-Boot console:
=> setenv serverip 192.168.1.100
=> setenv ipaddr 192.168.1.1
=> tftpboot 0x82000000 new_firmware.bin
=> erase 0x9f070000 +0x${filesize}
=> cp.b 0x82000000 0x9f070000 0x${filesize}
=> bootm 0x9f070000

# Method 4: U-Boot serial update (for small images)
# 1. Load via YMODEM or Kermit
=> loady 0x82000000
# Then send file via YMODEM protocol from terminal

# Method 5: MTD write from Linux (if running)
# Find MTD partition
cat /proc/mtd
# mtd0: 00020000 00010000 "u-boot"
# mtd1: 00120000 00010000 "kernel"
# mtd2: 006c0000 00010000 "rootfs"

# Write to MTD
mtd write new_kernel.bin kernel
mtd write new_rootfs.bin rootfs

# Method 6: LPC/Firmware update via vendor CLI
# Many routers accept firmware via CLI:
# sysupgrade -n new_firmware.bin
# Or vendor-specific:
# fw update new_firmware.bin
```

---

## 10. Binary Diff Analysis

### 10.1 Comparing Firmware Versions

```bash
# Binary diff analysis between firmware versions reveals:
# - Security patches (vulnerability fixes)
# - New features
# - Configuration changes
# - Backdoors

# Diffing with BinDiff (IDA Pro) or Diaphora (Ghidra)

# Diffing root filesystems
diff -r rootfs_v1/ rootfs_v2/ --brief

# Diffing specific binaries
# First, extract same binary from both firmware versions
bindiff -o diff.html binary_v1 binary_v2

# Quick content diff (strings)
strings binary_v1 | sort > strings_v1.txt
strings binary_v2 | sort > strings_v2.txt
diff strings_v1.txt strings_v2.txt

# Symbol diff (if symbols available)
nm binary_v1 | sort > symbols_v1.txt
nm binary_v2 | sort > symbols_v2.txt
diff symbols_v1.txt symbols_v2.txt

# Patch diffing — identify security fixes
# Security patches often: add bounds checks, replace unsafe functions,
# add validation, modify error handling

# Common patch patterns:
#   strcpy → strncpy (buffer overflow fix)
#   sprintf → snprintf (buffer overflow fix)
#   malloc(N) → malloc(N+1) (off-by-one fix)
#   Addition of NULL checks (deref fix)
#   Changes to authentication (auth bypass fix)
```

### 10.2 Automated Firmware Diffing

```python
#!/usr/bin/env python3
"""Automated firmware diff analysis."""

import hashlib
import subprocess
import os

def analyze_firmware_diff(fw_v1, fw_v2):
    """Compare two firmware versions and identify changes."""
    
    # Step 1: Extract both firmware images
    os.system(f"binwalk -e {fw_v1}")
    os.system(f"binwalk -e {fw_v2}")
    
    # Step 2: Diff root filesystems
    result = subprocess.run(
        ['diff', '-rq', f'_{fw_v1}.extracted/squashfs-root/', 
         f'_{fw_v2}.extracted/squashfs-root/'],
        capture_output=True, text=True
    )
    
    changes = {
        'added_files': [],
        'removed_files': [],
        'modified_files': [],
    }
    
    for line in result.stdout.splitlines():
        if 'Files' in line and 'differ' in line:
            # Modified file
            path = line.split()[1]
            changes['modified_files'].append(path)
        elif 'Only in' in line:
            parts = line.split(': ')
            if len(parts) == 2:
                dir_path = parts[0].replace('Only in ', '')
                file_path = parts[1]
                full_path = os.path.join(dir_path, file_path)
                if fw_v1.split('.')[0] in dir_path:
                    changes['removed_files'].append(full_path)
                else:
                    changes['added_files'].append(full_path)
    
    # Step 3: For modified binaries, run BinDiff or similar
    for mod_file in changes['modified_files']:
        v1_file = mod_file.replace(fw_v2.split('.')[0], fw_v1.split('.')[0])
        v2_file = mod_file
        
        if os.path.exists(v1_file) and os.path.exists(v2_file):
            # Check if files are ELF
            result = subprocess.run(['file', v1_file], capture_output=True, text=True)
            if 'ELF' in result.stdout:
                print(f"[BINARY DIFF] {mod_file}")
    
    # Step 4: Check for new/removed vulnerabilities
    security_keywords = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
                         'system', 'popen', 'exec', 'memcpy']
    
    for mod_file in changes['modified_files']:
        v1_file = mod_file.replace(fw_v2.split('.')[0], fw_v1.split('.')[0])
        result = subprocess.run(['strings', v1_file if os.path.exists(v1_file) else ''],
                               capture_output=True, text=True)
        v1_strings = result.stdout
        
        result = subprocess.run(['strings', mod_file], capture_output=True, text=True)
        v2_strings = result.stdout
        
        for keyword in security_keywords:
            v1_count = v1_strings.count(keyword)
            v2_count = v2_strings.count(keyword)
            if v1_count != v2_count:
                change = "REMOVED" if v2_count < v1_count else "ADDED"
                print(f"[SECURITY] {keyword}: {change} in {mod_file} "
                      f"(v1={v1_count}, v2={v2_count})")
    
    return changes

analyze_firmware_diff('firmware_v1.bin', 'firmware_v2.bin')
```

> **Cross-reference**: See [03a_malware_analysis.md](03a_malware_analysis.md) for IoT malware analysis techniques. See [05b_protocol_re.md](05b_protocol_re.md) for IoT protocol RE. See the [iot_security track](../iot_security/) for IoT security methodology. See the [Linux Kernel track](../linux_kernel/) for UEFI and kernel-level analysis.

---

*This document is part of the Deep Researcher Reverse Engineering track. Always obtain proper authorization before extracting or modifying firmware on devices you do not own.*

## References

1. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
2. Ghidra documentation, https://ghidra-sre.org/
3. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
4. binwalk documentation, https://github.com/ReFirmLabs/binwalk
5. UEFI Specification, https://uefi.org/specifications
6. NIST, "SP 800-147B: BIOS Protection Guidelines," 2023.
7. Dennis Yurichev, "Reverse Engineering for Beginners," https://begin.reversing.info/
8. DEF CON conference proceedings, https://www.defcon.org/
9. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
10. MITRE, "Hardware and Firmware Security," https://www.mitre.org/