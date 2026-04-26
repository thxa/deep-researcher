# macOS Security Cheatsheet

## XNU Kernel Key Components

| Component | Origin | Role |
|-----------|--------|------|
| **Mach** | CMU Mach 3.0 microkernel | IPC ports, VM, task/thread scheduling, capability-based security |
| **BSD** | FreeBSD 4.4BSD | POSIX process model (`struct proc`), VFS, networking (`sysent[]`, 540+ syscalls), kqueue |
| **IOKit** | Apple/NeXT | C++ driver framework (`OSObject`/`IOService`), device registry, `IOUserClient` external methods |

### Mach IPC Primitives
- **Port** = kernel-managed unidirectional message queue; rights: `SEND`, `RECEIVE`, `SEND_ONCE`
- **Task** (`task_t`) = resource container (VM space, port namespace, threads); BSD wraps with `proc`
- **Message** (`mach_msg` / trap #31) = inline data + OOL descriptors + port right transfers
- **MIG** = Mach Interface Generator; auto-generates RPC stubs from `.defs`; recurring bug source

### Key XNU Entry Points
| Surface | Mechanism | Bug Classes |
|---------|-----------|-------------|
| Mach traps | ~100 traps, `mach_trap_table[]` | Port UAF, OOL descriptor bugs, voucher overflow |
| BSD syscalls | 540+ via `sysent[]` | Stack/heap overflow, integer overflow, TOCTOU |
| IOKit | `IOConnectCallMethod()` external methods | Type confusion, unchecked bounds, vtable hijack |
| MIG interfaces | Auto-generated RPC stubs | Lifetime errors, type confusion, missing bounds checks |
| Networking | TCP/IP, Bluetooth, AWDL | Remote heap overflow, mbuf corruption |

---

## macOS Security Mechanisms

| Mechanism | Introduced | Enforcement Layer | What It Protects |
|-----------|------------|-------------------|------------------|
| **SIP** | 10.11 (2015) | Kernel (`csr_check()`) | Filesystem paths, kext loading, runtime (`task_for_pid`, `DYLD_INSERT`) |
| **AMFI** | 10.x | Kernel (MACF hook) | Code signing enforcement, entitlement validation, library validation |
| **TCC** | 10.14+ expansion | `tccd` daemon + SQLite DB | Camera, mic, Full Disk Access, accessibility, screen recording |
| **Sandbox (Seatbelt)** | 10.5+ | `sandbox.kext` (MACF) | Syscall-level confinement via SBPL-compiled profiles |
| **Gatekeeper** | 10.7+ | `syspolicyd` | Quarantine → signature → notarization → XProtect pipeline |
| **XProtect** | 10.6+ | YARA engine + Remediator | Signature-based detection and periodic remediation scans |
| **KPP/KTRR** | A10+ | Hardware (memory controller) | Immutable kernel text after boot |
| **PPL** | A12+ | Hardware (APRR) | Page table integrity, W^X enforcement from within EL1 |
| **PAC** | A12+ (arm64e) | Hardware (QARMA) | Return addresses, vtables, function pointers, ObjC caches |
| **kCFI** | 13.0 (2022) | Software (kernel) | Forward-edge CFI via 32-bit type hash before function entry |
| **kalloc.type** | 14.0 (2023) | Kernel zone allocator | Type-segregated kernel heap preventing cross-type confusion |
| **SSV** | 11.0 (2020) | APFS Merkle tree | Cryptographic sealing of entire system volume |
| **Lockdown Mode** | 13.0 (2022) | Software (multiple) | Disables JIT, blocks attachments/profiles/USB, extreme hardening |
| **Hardened Runtime** | 10.14+ | Kernel + AMFI | Library validation, no RWX, DYLD restrictions |

### SIP CSR Flags (`csr-active-config` NVRAM bitmask)
| Flag | Value | Effect |
|------|-------|--------|
| `CSR_ALLOW_UNTRUSTED_KEXTS` | 0x01 | Allow unsigned kexts |
| `CSR_ALLOW_UNRESTRICTED_FS` | 0x02 | Disable filesystem protection |
| `CSR_ALLOW_TASK_FOR_PID` | 0x04 | Allow `task_for_pid` on protected procs |
| `CSR_ALLOW_UNRESTRICTED_DTRACE` | 0x20 | Allow DTrace on restricted procs |
| `CSR_ALLOW_UNRESTRICTED_NVRAM` | 0x40 | Allow NVRAM modification |

### TCC Databases
- **User:** `~/Library/Application Support/com.apple.TCC/TCC.db`
- **System:** `/Library/Application Support/com.apple.TCC/TCC.db`
- Schema: `access` table with `service`, `client`, `client_type`, `auth_value` (0=denied, 2=allowed)

### Private Entitlements (Apple-signed only)
| Entitlement | Effect |
|-------------|--------|
| `com.apple.private.security.no-sandbox` | Exempt from sandbox enforcement |
| `com.apple.private.tcc.allow` | Bypass TCC for specified services |
| `com.apple.rootless.install` | Modify SIP-protected paths |
| `com.apple.rootless.storage.TCC` | Direct access to TCC.db |
| `com.apple.private.amfi.can-load-cdhash` | Load code by cdhash without full signature |

---

## macOS Exploitation Techniques

### Heap Exploitation
| Target | Allocator | Key Feature |
|--------|-----------|-------------|
| Userland | magazine malloc (libmalloc) | Tiny (1–1008B), Small (1009B–127KB), Large (>'127KB); per-CPU magazines; out-of-line freelist bitmaps |
| Kernel | `kalloc` zone allocator | Bucket zones: kalloc.16, kalloc.32 ... kalloc.32768; `kalloc_type` segregates by C type signature (macOS 14+) |

**Heap feng shui:** Drain freelists → create controlled holes → trigger vulnerable allocation into prepared hole → control adjacent object data.

**Kernel UAF pattern:** Spray target zone → trigger free → reclaim with controlled data (IOSurface/pipe buffer) → use dangling pointer.

### IPC Port Exploitation
- Forge `ipc_port` structure in controlled kernel memory
- Matching `ip_kobject` pointer redirects task port → full process compromise
- `mach_voucher_extract_attr_recipe_trap` (CVE-2019-6225) — integer overflow → OOB write
- TOCTOU on voucher attributes (CVE-2021-1782) — race condition → UAF

### IOKit Attack Surface
- `IOServiceOpen()` → `IOConnectCallMethod()` passes attacker scalars/structs directly to kernel
- Unchecked selector bounds, missing struct size validation, object lifecycle UAF (`retain`/`release` mismatches)
- Race between concurrent `open()`/`close()` and method dispatch
- Post-kCFI: vtable corruption only works if type hash matches; data-only attacks preferred

### Kernel Exploit Chain
```
vulnerability → info leak (KASLR defeat) → arbitrary read → arbitrary write
                                                    ↓
                          credential overwrite (uid→0) / SIP disable / sandbox escape
```

**Read primitives:** IOSurface property abuse, `OSUnserializeBinary` parsing bugs, MIG info leaks  
**Write primitives:** Pipe buffer corruption, IOKit object field corruption, fake IPC port forging  
**KASLR defeat:** Timing side channels, uninitialized MIG reply data, heap pointer disclosure

### PAC Bypass Strategies
1. **Signing oracles** — kernel paths that sign attacker-controlled values
2. **Context collisions** — different types sharing same PAC key+context
3. **Data-only attacks** — target unsigned data pointers (credentials, sandbox labels)
4. **PACMAN** — speculative execution side-channel to brute-force PAC values (MIT, 2022)

---

## Notable macOS CVEs

| CVE | Year | Type | Component | Impact |
|-----|------|------|-----------|--------|
| CVE-2016-4656 | 2016 | Type confusion | IOKit/OSUnserializeBinary | Kernel R/W (Pegasus) |
| CVE-2018-4407 | 2018 | Heap overflow | ICMP/networking | Remote crash |
| CVE-2019-6225 | 2019 | Integer overflow | Mach vouchers | Kernel code execution |
| CVE-2019-8605 | 2019 | UAF | BSD networking (SockPuppet) | Full jailbreak |
| CVE-2020-27950 | 2020 | Info leak | mach_msg OOL | KASLR bypass (in-the-wild) |
| CVE-2020-9906 | 2020 | Heap overflow | AWDL WiFi | Zero-click RCE |
| CVE-2021-1782 | 2021 | Race/UAF | Mach vouchers | Kernel privesc (in-the-wild) |
| CVE-2021-30860 | 2021 | Integer overflow | CoreGraphics JBIG2 | FORCEDENTRY zero-click |
| CVE-2021-30883 | 2021 | Type confusion | IOMobileFrameBuffer | Kernel code exec (in-the-wild) |
| CVE-2021-30892 | 2021 | Logic | system_installd (Shrootless) | SIP bypass |
| CVE-2022-32894 | 2022 | OOB write | XNU kernel | Arbitrary kernel exec (in-the-wild) |
| CVE-2023-32434 | 2023 | Integer overflow | Kernel VM | Op Triangulation chain |
| CVE-2023-38606 | 2023 | MMIO abuse | SoC GPU coprocessor | PPL/KTRR bypass (undocumented HW) |
| CVE-2024-23222 | 2024 | Type confusion | Kernel | Kernel code exec (in-the-wild) |
| CVE-2024-44133 | 2024 | Logic | Safari TCC (HM Surf) | TCC bypass |

### Notable Malware Families
| Malware | Type | Notable For |
|---------|------|-------------|
| OSX.Flashback | Worm | 600K+ infections via Java CVE-2012-0507, DGA C2 |
| Shlayer | Adware | Most prevalent; first notarized macOS malware |
| Lazarus/AppleJeus | APT (DPRK) | Cryptocurrency targeting, reflective Mach-O loading |
| OceanLotus | APT (Vietnam) | Multi-stage backdoor, AES-256-CBC, anti-VM |
| Pegasus/FORCEDENTRY | APT (NSO Group) | Zero-click iMessage → JBIG2 decoder → BlastDoor escape → kernel |
| Atomic Stealer (AMOS) | Infostealer | Stealer-as-a-service ($1K/mo), credential exfiltration |
| XCSSET | Malware | Developer targeting via Xcode projects, TCC zero-day |
| KeRanger | Ransomware | First functional macOS ransomware (2016) |
| LockBit (arm64) | Ransomware | Early arm64 build (2023) |
| Banshee | Infostealer | macOS-native stealer, sold as MaaS |

---

## Debugging & Research Tools

### Debugging
| Tool | Usage |
|------|-------|
| `lldb` | Primary debugger; `lldb -p <pid>` or `lldb <binary>`; Python scripting via `lldb` module |
| `DYLD_INSERT_LIBRARIES` | LD_PRELOAD equivalent; blocked by hardened runtime/SIP |
| `DYLD_PRINT_LIBRARIES` | Log library loading order |
| `dyld_shared_cache_util` | Extract dyld shared cache for gadget analysis |
| `csrutil` | Query/modify SIP state (recoveryOS only) |
| `spctl --assess` | Manual Gatekeeper assessment |
| `codesign -dvvv` | Inspect code signature, entitlements, cdhash |
| `xattr -p com.apple.quarantine` | Read quarantine metadata |
| `tccutil reset` | Reset TCC database entries |
| `ioreg -l` | Dump IOKit device registry |
| `launchctl list` | List loaded launch agents/daemons |

### Analysis
| Tool | Usage |
|------|-------|
| Ghidra / Hopper / radare2 | Reverse engineering Mach-O binaries |
| `kmutil` | Inspect KernelCollections, list kexts |
| `security` CLI | Keychain operations (`security dump-keychain -d`) |
| `log show` | Query unified logging (forensic artifacts) |
| `sysctl kern.boot_args` | Kernel boot arguments (KASLR slide info) |
| Xcode Instruments | Performance profiling, system tracing |
| Objective-See suite | BlockBlock (persistence), LuLu (firewall), KnockKnock (persistence audit), RansomWhere |
| `osquery` | SQL-based endpoint visibility |
| Santa (Google) | Binary allowlisting/denylisting |

### Kernel Debugging (Apple Silicon)
- Two-machine debug via `lldb` over USB/Thunderbolt with development kernel
- `csrutil enable --without debug` to allow `task_for_pid` on development systems
- KDK (Kernel Debug Kit) from Apple Developer portal for symbols

---

## Key Security Config Paths & Plist Locations

| Path | Purpose |
|------|---------|
| `/System/Library/Kernels/kernel` | XNU kernel binary (Intel) |
| `/System/Library/Sandbox/Profiles/` | Built-in SBPL sandbox profiles |
| `/Library/Apple/System/Library/CoreServices/XProtect.bundle/` | XProtect YARA rules |
| `~/Library/Application Support/com.apple.TCC/TCC.db` | User TCC database |
| `/Library/Application Support/com.apple.TCC/TCC.db` | System TCC database |
| `/Library/LaunchDaemons/` | System-level launch daemons (root) |
| `~/Library/LaunchAgents/` | User-level launch agents |
| `/Library/LaunchAgents/` | System-wide launch agents (all users) |
| `/var/db/cryptexes/` | Rapid Security Response (Cryptex) overlays |
| `/System/Volumes/Data/` | Data volume (separate from sealed system volume) |
| `~/Library/Containers/<bundle-id>/` | App Sandbox container directories |
| `/etc/periodic/` | Cron-like periodic scripts (daily/weekly/monthly) |
| `/var/root/Library/Preferences/com.apple.loginwindow.plist` | LoginHook/LogoutHook config |
| `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` | BTM database |
| `NVRAM: csr-active-config` | SIP configuration bitmask |

---

## Key XNU Structures & Security Relevance

| Structure | Header | Security Relevance |
|-----------|--------|--------------------|
| `struct proc` | `bsd/sys/proc_internal.h` | BSD process; wraps Mach `task_t`, carries `ucred` credentials, file descriptor table |
| `struct kauth_cred` | `bsd/kern/kauth.h` | Process credentials (uid, gid, groups); target for credential overwrite exploits |
| `struct ipc_port` | `osfmk/ipc/ipc_port.h` | Mach port object; `ip_kobject` field targets for port faking exploits |
| `struct ipc_space` | `osfmk/ipc/ipc_space.h` | Per-task port namespace; capability model enforcement |
| `struct task` | `osfmk/kern/task.h` | Mach task; task port grants full control (VM R/W, thread manipulation) |
| `struct uthread` | `bsd/kern/thread.h` | BSD thread state; audit token, thread credential |
| `struct vnode` | `bsd/sys/vnode_internal.h` | VFS node; MAC hooks on VNOP operations enforce sandbox/SIP |
| `struct mount` | `bsd/sys/mount.h` | Filesystem mount; flags (nosuid, nodev, read-only) and SSV seal enforcement |
| `struct cs_blob` | `bsd/kern/cs_blob.h` | Code signature blob; cdhash validation, entitlement extraction |
| `struct zone` | `osfmk/kern/zalloc.h` | Kernel zone allocator; type-segregated heaps (`kalloc_type`), poisoning, freelist bitmaps |
| `struct IOService` | IOKit framework | Base driver class; matching/probing lifecycle, power management |
| `struct IOUserClient` | IOKit framework | User-kernel interface; external method dispatch — primary attack surface |
| `struct mac_policy_conf` | `security/mac_policy.h` | MACF policy registration; hook insertion points for Sandbox, AMFI, TMSafetyNet |

---

## Exploit Chain Quick Reference

```
Complete macOS compromise (typical chain):
  1. Initial access     → Safari/WebKit JIT bug, iMessage parser, Electron RCE
  2. Sandbox escape     → XPC service validation flaw, IOKit external method bug
  3. Kernel LPE         → Mach port UAF, IOKit type confusion, integer overflow
  4. SIP bypass         → Exploit heritable entitlement (Shrootless), mount manipulation
  5. Persistence        → LaunchAgent/Daemon, dylib hijack, cron (avoid BTM-monitored paths)
  6. TCC bypass         → Confused deputy, inject into TCC-granted app, $HOME manipulation
```

```
Operation Triangulation (Kaspersky, 2023):
  iMessage (zero-click) → CVE-2023-32434 (integer overflow, kernel VM)
                       → CVE-2023-38606 (undocumented SoC MMIO regs bypass PPL/KTRR)
  Most sophisticated publicly known Apple exploit chain
```

```
FORCEDENTRY (NSO Group, 2021):
  iMessage (zero-click) → CVE-2021-30860 (JBIG2 decoder integer overflow)
                       → BlastDoor sandbox escape
                       → kernel exploit → full device compromise
```