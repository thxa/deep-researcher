# Android Security Research Cheatsheet

## Android Security Components

| Component | Definition |
|-----------|-----------|
| **SELinux (SEAndroid)** | Mandatory access control enforcing type-based policy on all processes and resources since Android 5.0 |
| **seccomp-BPF** | Syscall filtering reducing kernel attack surface by ~71%; blocks ~271 of ~380 syscalls for apps |
| **Verified Boot (AVB)** | Boot chain integrity via dm-verity Merkle trees, signed vbmeta, and RPMB rollback protection |
| **GKI (Generic Kernel Image)** | Unified kernel with stable KMI allowing Google to ship kernel patches independently of SoC vendors |
| **Project Treble** | HAL/framework separation via HIDL/AIDL interfaces, enabling faster OS updates |
| **Project Mainline** | 30+ APEX modules updatable via Play Store, bypassing OEM update cycles |
| **Binder IPC** | Android's primary IPC mechanism; enforces caller UID/PID and SELinux policy on every transaction |
| **Application Sandbox** | Per-app UID (10000–19999) + process isolation + seccomp-BPF + SELinux domain confinement |
| **dm-verity** | Merkle-tree-based integrity verification of read-only partitions on every block read |
| **FBE (File-Based Encryption)** | Dual-encryption scheme: CE (Credential Encrypted) and DE (Device Encrypted) storage |
| **PAC/BTI** | ARM hardware features: Pointer Authentication signs pointers crypto-graphically; Branch Target Identification marks valid indirect branch targets |
| **MTE (Memory Tagging Extension)** | ARMv8.5+ hardware memory tagging detecting UAF and buffer overflows at runtime |
| **CFI (Control-Flow Integrity)** | Clang/kCFI enforcement restricting indirect call targets to valid type-matching functions |
| **SCS (Shadow Call Stack)** | Stores return addresses in a separate stack (x18 register on ARM64) defeating return address overwrites |
| **Scudo Allocator** | Hardened Bionic heap allocator with quarantine, guard pages, and chunk header validation |
| **Play Integrity API** | Hardware-backed device attestation replacing SafetyNet for integrity verification |
| **kCFI** | Kernel-level CFI using embedded type hashes validated at indirect call sites (Linux 6.1+) |

## Top CVEs in This Track

| CVE | Component | Summary |
|-----|-----------|---------|
| CVE-2015-1538 | libstagefright | Zero-click MMS RCE via integer overflow in media parsing (~950M devices) |
| CVE-2016-5195 | Kernel (mm/gup.c) | Dirty COW: write to read-only pages via COW race; widely used for rooting |
| CVE-2019-2215 | Binder | UAF via epoll/Binder interaction; confirmed NSO Group Pegasus exploit |
| CVE-2020-0041 | Binder | OOB write in Binder transaction handling |
| CVE-2020-0069 | MediaTek CMDQ | MediaTek-SU: OOB write in cmdq_core.c; 14-month patch gap, hundreds of millions affected |
| CVE-2022-0847 | Kernel (pipe) | Dirty Pipe: stale PIPE_BUF_FLAG_CAN_MERGE allows arbitrary file write |
| CVE-2022-20421 | Binder | UAF in binder_thread_release |
| CVE-2022-38181 | ARM Mali GPU | UAF in Mali JM/CSF; exploited in the wild |
| CVE-2023-0266 | Kernel (ALSA) | UAF in ALSA PCM sound timer; exploited by spyware vendors |
| CVE-2023-21036 | Pixel Markup | aCropalypse: cropped screenshots leaked original image data |
| CVE-2023-21273 | Bluetooth | Zero-click Bluetooth RCE |
| CVE-2023-4211 | ARM Mali GPU | UAF in Mali GPU memory processing; exploited in the wild |
| CVE-2023-33063 | Qualcomm Adreno | UAF in Adreno DSI handler; exploited in the wild |
| CVE-2023-33107 | Qualcomm Adreno | Integer overflow in Adreno GPU driver; exploited in the wild |
| CVE-2024-43047 | Qualcomm KGSL | UAF in DMA-buf refcount; CISA KEV listed |
| CVE-2024-36971 | Kernel (net) | UAF in network route management; actively exploited |
| CVE-2025-54957 | Dolby Unified Decoder | Zero-click RCE via audio decoder in Google Messages |
| CVE-2025-36934 | Pixel BigWave driver | UAF/kernel arbitrary RW via /dev/bigwave AV1 accelerator |

## ADB / Fastboot Commands for Security Research

```bash
# Device info
adb shell getprop ro.build.fingerprint          # Full build fingerprint
adb shell getprop ro.build.version.security_patch # Security patch level
adb shell getprop ro.boot.verifiedbootstate      # Boot state: green/yellow/orange/red
adb shell getprop ro.boot.vbmeta.device_state    # vbmeta lock state

# SELinux
adb shell getenforce                             # Check SELinux mode
adb shell sestatus                               # Detailed SELinux status
adb logcat -b events -d | grep avc              # AVC denial logs
adb shell cat /sys/fs/selinux/policy_capabilities # Policy capabilities

# Seccomp
adb shell cat /proc/self/status | grep Seccomp   # Seccomp filter status

# Security paths
adb shell ls /sys/kernel/security/               # LSM securityfs entries
adb shell cat /proc/self/attr/current            # Current SELinux context
adb shell cat /proc/self/attr/prev               # Previous SELinux context
adb shell cat /proc/self/attr/exec               # SELinux exec transition
adb shell cat /proc/self/attr/fscreate           # SELinux fscreate label
adb shell ls /sys/fs/selinux/                    # SELinux policy files
adb shell cat /sys/fs/selinux/enforce            # SELinux enforcement (1=enforcing)

# Process inspection
adb shell ps -eZ                                 # List all processes with SELinux contexts
adb shell cat /proc/<pid>/attr/current           # Process SELinux domain
adb shell cat /proc/<pid>/maps                   # Process memory map
adb shell cat /proc/<pid>/status                 # UID/GID/capabilities
adb shell cat /proc/<pid>/syscall                # Seccomp syscall filter

# Boot / Verified Boot
fastboot oem device-info                          # Bootloader lock state
fastboot oem lock                                  # Lock bootloader
fastboot flashing lock                             # Lock bootloader (newer devices)
adb shell dm-verity-status                         # dm-verity verification status
adbshell cat /proc/cmdline                         # Kernel boot args (verify vbmeta state)

# Packages & permissions
adb shell pm list packages -3                      # Third-party packages
adb shell dumpsys package <pkg>                    # Package permissions & info
adb shell pm grant <pkg> <perm>                    # Grant a permission
adb shell pm revoke <pkg> <perm>                   # Revoke a permission

# Network security
adb shell dumpsys connectivity                     # Network state
adb shell dumpsys netstats                         # Network statistics
adb shell iptables -L -n -v                        # iptables rules (requires root)

# Logging & debugging
adb logcat -b all -d                               # All log buffers
adb logcat -s SELinux                              # SELinux-specific logs
adb shell dmesg                                    # Kernel ring buffer (if accessible)
adb shell bugreportz                                # Generate bug report

# Network tracing
adb shell tcpdump -i any -w /sdcard/capture.pcap   # Packet capture (requires root)
adb shell ss -tlnp                                 # Listening TCP sockets
```

## Android Security File Paths

| Path | Purpose |
|------|---------|
| `/sys/kernel/security/` | Securityfs: SELinux policy, IMA, lockdown state |
| `/sys/fs/selinux/` | SELinux policy files, enforce flag, booleans |
| `/proc/self/attr/current` | Current process SELinux security context |
| `/proc/self/attr/exec` | SELinux context for next exec transition |
| `/proc/self/attr/fscreate` | SELinux label for newly created files |
| `/proc/self/attr/prev` | Previous SELinux context (before last transition) |
| `/proc/self/status` | UID, GID, groups, Seccomp mode, capabilities |
| `/proc/self/maps` | Process virtual memory map |
| `/data/system/packages.xml` | Package permissions, UIDs, GIDs |
| `/data/misc/user/0/` | Per-user app data roots |
| `/data/app/` | APK install directories |
| `/data/dalvik-cache/` | DEX/OAT compilation cache |
| `/dev/binder` | Framework Binder IPC device |
| `/dev/hwbinder` | HAL Binder IPC device |
| `/dev/vndbinder` | Vendor Binder IPC device |
| `/dev/kgsl-3d0` | Qualcomm Adreno GPU device |
| `/dev/mali0` | ARM Mali GPU device |
| `/dev/ion` | ION memory allocator device |
| `/dev/dma_heap/` | DMA-BUF heap devices |
| `/data/adb/` | Magisk/root ADB persistent scripts |
| `/data/local/tmp/` | World-writable temp dir (common exploit staging) |
| `/vendor/etc/sepolicy/` | Vendor SELinux policy |
| `/system/etc/sepolicy/` | System SELinux policy |
| `/proc/version` | Kernel version string |
| `/proc/cmdline` | Kernel boot parameters |

## Mitigation Features & Kernel Config Names

| Mitigation | Kernel Config | Notes |
|-----------|---------------|-------|
| KASLR | `CONFIG_RANDOMIZE_BASE` | 13–21 bits entropy on arm64; bypassed by info leaks |
| Stack Canaries | `CONFIG_CC_STACKPROTECTOR` / `CONFIG_STACKPROTECTOR_STRONG` | Random canary per function; defeated by info leak |
| CFI (userspace) | Clang `-fsanitize=cfi` | Forward-edge indirect call protection in userspace |
| kCFI (kernel) | `CONFIG_CFI_CLANG` | Type-hash-based kernel CFI (Linux 6.1+) |
| Shadow Call Stack | `CONFIG_SHADOW_CALL_STACK` | Return address protection via x18 register on ARM64 |
| MTE | `CONFIG_ARM64_MEMORY_TAGGING` / ARMv8.5+ | Hardware memory tagging; UAF/buffer overflow detection |
| PAC | `CONFIG_ARM64_PTR_AUTH` / ARMv8.3+ | Cryptographic pointer signing; 7–16 bit authentication codes |
| BTI | `CONFIG_ARM64_BTI` / ARMv8.5+ | Hardware branch target identification |
| Harden Usercopy | `CONFIG_HARDENED_USERCOPY` | Bounds checking on copy_from_user/copy_to_user |
| SLUB Freelist Hardening | `CONFIG_SLAB_FREELIST_HARDENED` | XOR-encoded freelist pointers in SLUB allocator |
| SLUB Randomization | `CONFIG_SLAB_FREELIST_RANDOM` | Random order of objects within slab pages |
| Kernel Lockdown | `CONFIG_LOCK_DOWN_KERNEL` | Restricts root from modifying running kernel |
| Init on Alloc | `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | Zeroes newly allocated pages |
| Init on Free | `CONFIG_INIT_ON_FREE_DEFAULT_ON` | Zeroes freed pages (memory sanitization) |
| seccomp-BPF | `CONFIG_SECCOMP` / `CONFIG_SECCOMP_FILTER` | Syscall filtering; Android blocks ~271/~380 syscalls for apps |
| ptrace restriction | `CONFIG_SECURITY_PTRACE_RESTRICT` | Limits ptrace scope |
| dmesg restrict | `CONFIG_SECURITY_DMESG_RESTRICT` | Blocks unprivileged dmesg access |
| kptr restrict | `CONFIG_SECURITY_KPTR_RESTRICT` | Hides kernel pointers from userspace |
| dm-verity | `CONFIG_DM_VERITY` | Merkle-tree verified read-only partitions |
| dm-default-key | `CONFIG_DM_DEFAULT_KEY` | FBE inline encryption key management |
| PAGE_POISONING | `CONFIG_PAGE_POISONING` | Fills freed pages with poison pattern (0xaa) for UAF detection |
| IntSan / UBSan | `-fsanitize=integer` / `-fsanitize=undefined` | Integer overflow detection in production; aborts on overflow |

## Android Attack Surfaces Checklist

- [ ] **Binder IPC** (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`) — Most-exercised kernel driver
- [ ] **GPU drivers** — Adreno (`/dev/kgsl-3d0`), Mali (`/dev/mali0`), PowerVR — primary kernel LPE vector
- [ ] **ION/DMA-BUF** (`/dev/ion`, `/dev/dma_heap/`) — Shared memory allocator; UAF/double-free prone
- [ ] **Filesystems** — ext4, f2fs, FUSE; crafted images trigger mount-time bugs
- [ ] **Network stack** — TCP/IP, nf_tables (reachable via user namespaces on some configs)
- [ ] **Bluetooth** — L2CAP, SMP, BNEP; zero-click proximity RCE
- [ ] **WiFi** — Broadcom bcmdhd firmware (Broadpwn), wpa_supplicant EAP/P2P parsing
- [ ] **USB gadget** — configfs descriptors; attack surface when connected to hostile host
- [ ] **Media codecs** — libstagefright, mediaserver/mediaextractor; MMS zero-click
- [ ] **ALSA/sound** — PCM timer UAF (CVE-2023-0266); reachable from sandbox
- [ ] **Baseband** — Qualcomm, Samsung Shannon, MediaTek RTOS; cellular zero-click RCE
- [ ] **NFC** — NDEF parsing, Android Beam (deprecated); tap-proximity attacks
- [ ] **WebView** — JavaScript interface RCE, universal XSS; app-embedded attack vector
- [ ] **Content Providers** — SQL injection, path traversal in exported providers
- [ ] **PendingIntent** — Mutable implicit PendingIntents enable privilege escalation
- [ ] **Accessibility Services** — Screen reading, credential capture, automated UI actions
- [ ] **io_uring** — Disabled on Android due to excessive attack surface
- [ ] **HAL processes** — HIDL/AIDL interfaces; stepping stones from framework to kernel
- [ ] **TEE/TrustZone** — Keymaster, Gatekeeper; targeted via side-channels and fault injection
- [ ] **Bootloader** — EDL/Download mode; forensic extraction and bypass vector