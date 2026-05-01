# Windows Security & Internals
## Comprehensive Research Report

> **Difficulty:** 🔴 Advanced | **Prerequisites:** Windows internals, x86/x64 assembly, kernel debugging, Active Directory, C/C++ | **Estimated reading time:** ~90 minutes

**Date:** May 2026
**Classification:** Public Research
**Total Research Corpus:** This report synthesizes the full Windows security & internals knowledge domain

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Windows Architecture & Trust Boundaries](#2-windows-architecture--trust-boundaries)
3. [Windows Security Subsystem & Authentication](#3-windows-security-subsystem--authentication)
4. [The NT Kernel: Attack Surface & Internals](#4-the-nt-kernel-attack-surface--internals)
5. [Kernel Object Manager & Pool Corruption](#5-kernel-object-manager--pool-corruption)
6. [Windows Memory Management & Exploitation](#6-windows-memory-management--exploitation)
7. [Privilege Escalation: Techniques & Landmark CVEs](#7-privilege-escalation-techniques--landmark-cves)
8. [Active Directory & Domain Compromise](#8-active-directory--domain-compromise)
9. [Windows Malware & Offensive Tooling](#9-windows-malware--offensive-tooling)
10. [Modern Mitigations & Their Bypasses](#10-modern-mitigations--their-bypasses)
11. [Hardening the Windows Attack Surface](#11-hardening-the-windows-attack-surface)
12. [Cross-Track Connections](#12-cross-track-connections)
13. [Key Findings & Recommendations](#13-key-findings--recommendations)

---

## 1. Executive Summary

Windows runs on approximately 72% of enterprise desktops and 30% of all servers worldwide, making it the most high-value target for both nation-state adversaries and profit-motivated criminal operators. This report synthesizes the complete Windows security landscape — from the NT kernel's object manager and pool allocator through Active Directory attack paths to modern exploit mitigations and their bypasses.

**Key findings:**

- **The NT kernel attack surface remains vast**: Over 3,000 IOCTL-dispatching drivers ship with a default Windows installation, and the win32k subsystem alone has produced over 500 elevation-of-privilege CVEs since 2015
- **Pool corruption is dominant**: Windows kernel exploitation centers on the pool allocator — UAF and pool overflow in paged/non-paged pools account for >60% of all Windows kernel EoP CVEs
- **Active Directory is the kill chain linchchin**: 90%+ of enterprise domain compromises trace back to AD misconfigurations (Kerberoasting, AS-REP roasting, delegation abuse), not zero-day exploits
- **Modern mitigations raise the bar but don't eliminate classes**: VBS/HVCI (Windows 10 RS3+), kernel CET (Windows 11 21H2+), and kCFI (Windows 11 24H2) have driven the research community toward data-only attacks and indirect call manipulation
- **Data-only kernel attacks are now primary**: Credential theft via `_EPROCESS.Token` replacement, `_ETHREAD` hijacking, and ACL modification have replaced code-execution approaches (ROP, shellcode) in modern exploit chains
- **The Windows offensive ecosystem is mature**: Mimikatz, BloodHound, Rubeus, SharpCollection, and Cobalt Strike form a pipeline from initial access to domain dominance, while EDR evasion (direct syscall, ETW patching, unhooking) is an arms race with defensive vendors
- **Patch gaps persist in enterprise environments**: The average enterprise lags 60-90 days on Windows patches, and legacy systems (Windows Server 2012 R2, Windows 7) remain in production with unbackported mitigations

---

## 2. Windows Architecture & Trust Boundaries

### 2.1 NT Architecture Overview

The Windows NT kernel architecture follows a hybrid design: a monolithic kernel (ntoskrnl.exe) with modular drivers, separating user-mode (Ring 3) and kernel-mode (Ring 0) via the privilege boundary enforced by the CPU's CPL mechanism and CR0/CR4 protections.

```
+----------------------------------------------------------+
|                  User Mode (Ring 3)                       |
|  +----------+  +----------+  +----------+  +----------+  |
|  | Win32    |  | POSIX    |  | OS/2     |  | WSL2     |  |
|  | Subs.    |  | Subs.    |  | Subs.    |  | Subs.    |  |
|  +----+-----+  +----+-----+  +----+-----+  +----+-----+  |
|       |              |             |             |        |
|  +----+--------------+-------------+-------------+----+   |
|  |              NTDLL.DLL (System Call Interface)    |   |
|  +----+----------------------------------------------+   |
+-------|--------------------------------------------------+
        | syscall / sysenter
+-------|--------------------------------------------------+
|       v        Kernel Mode (Ring 0)                      |
|  +---------+  +--------------------+  +----------------+ |
|  | Win32k  |  | ntoskrnl.exe       |  | HAL.DLL        | |
|  | sys     |  | (Executive, MM,   |  | (Hardware Ab-  | |
|  |         |  |  Object Mgr, IO)  |  |  straction)   | |
|  +---------+  +--------------------+  +----------------+ |
|  | Driver  |  | Driver            |  | Driver         | |
|  | [3K+]   |  | [WDF/KMDF]       |  | [Minifilter]   | |
+----------------------------------------------------------+
```

The critical trust boundary is the user-to-kernel transition via `syscall`/`sysenter`. Every system call crossing this boundary is a potential attack surface. Windows validates with `PreviousMode` checks (calling thread's `KTHREAD.PreviousMode = 1` for user-mode callers), but the sheer number of entry points (~2,000+ system services) creates defense challenges.

### 2.2 Key Executive Subsystems

| Subsystem | Executive Component | Attack Relevance |
|-----------|-------------------|-----------------|
| Process/Thread | `EPROCESS` / `KPROCESS` / `ETHREAD` | Token manipulation, priority/affinity abuse |
| Memory Manager | `Mm` subsystem, PFN database, working sets | Pool corruption, PTE manipulation |
| I/O Manager | `IRP` dispatch, driver I/O | IOCTL attack surfaces, driver bugs |
| Object Manager | `_OBJECT_HEADER`, `_OBJECT_TYPE` | Type confusion, object spray |
| Security Reference Monitor | `TOKEN`, `SECURITY_DESCRIPTOR` | Privilege escalation, ACE/DACL modification |
| Cache Manager | Lazy write, mapped page writer | Memory corruption via cache pressure |
| Registry | `CM` callbacks, hive structure | Callback object corruption |
| Win32k | GDI, window manager, DirectX | Largest single kernel attack surface |

### 2.3 Win32k: The Largest Kernel Attack Surface

The Windows graphics subsystem (win32k.sys / win32kbase.sys / win32kfull.sys) resides in kernel mode despite being a UI system. This design decision — made in Windows NT 3.5 for performance reasons — has been the single most prolific source of Windows kernel vulnerabilities:

- **>500 EoP CVEs** assigned to win32k since 2015
- Processes GDI objects, window messages, keyboard/mouse input, and display driver interface (DDI) calls
- Reachable from any application via `NtUser*` and `NtGdi*` syscalls
- Complex object lifecycle management across `SURFACE`, `WNDOBJ`, `MENU`, `WND` structures

The win32k attack surface is accessible from AppContainer sandbox contexts (with restrictions), making it a stepping stone for sandbox escape chains (e.g., Chrome GPU process → win32k → kernel).

---

## 3. Windows Security Subsystem & Authentication

### 3.1 Authentication Architecture

Windows authentication involves multiple protocols and components:

```
Client                  LSASS                    Domain Controller
  |   NTLM/Kerberos        |   Kerberos TGT/Service     |
  | ────────────────────> | ──────────────────────>   |
  |   Challenge/Response   |   AS-REQ / TGS-REQ          |
  | <──────────────────── | <──────────────────────   |
  |   Auth Token           |   TGT / Service Ticket       |
```

**NTLM**: Challenge-response protocol using MD4 hash of the password. Vulnerable to relay attacks (CVE-2025-21298, mitigated with EPA/EPA enforcement), pass-the-hash, and offline cracking of captured challenges.

**Kerberos**:
- KDC = Key Distribution Center (runs on DC)
- TGT = Ticket-Granting Ticket (encrypted with `krbtgt` password hash)
- Service tickets encrypted with service account password hash
- **Kerberoasting**: Request service tickets for SPN-bearing accounts, then crack offline (RC4-HMAC tickets are crackable with dictionary attacks)
- **AS-REP Roasting**: Accounts with `DONT_REQ_PREAUTH` leak encrypted data crackable offline
- **Golden Ticket**: Forge TGT with `krbtgt` hash → persistent domain access
- **Silver Ticket**: Forge service ticket with service account hash → targeted access
- **Diamond Ticket**: Modify legitimate TGT with `krbtgt` hash while preserving all fields

### 3.2 Access Token Structure

The `_TOKEN` structure is the foundation of Windows access control. Every process has a primary token (and impersonation tokens for threads):

```
_TOKEN
├── TokenId (LUID, unique per token instance)
├── AuthenticationId (LUID, logon session)
├── ParentTokenId (LUID)
├── Privileges[]
│   ├── SeAssignPrimaryTokenPrivilege
│   ├── SeDebugPrivilege  ← high-value target
│   ├── SeTakeOwnershipPrivilege
│   ├── SeLoadDriverPrivilege  ← used for BYOVD
│   └── SeImpersonatePrivilege  ← potato attacks
├── UserAndGroups[] (SID + attributes)
│   ├── User SID
│   └── Group SIDs
├── RestrictedSids[] (optional)
├── PrimaryGroup (SID)
├── DefaultDacl
├── Source (TOKEN_SOURCE)
└── Integrity Level (SID at specific well-known RID)
    ├── S-1-16-4096  → Untrusted (AppContainer)
    ├── S-1-16-8192  → Low (Protected Mode IE)
    ├── S-1-16-12288 → Medium (Standard User)
    ├── S-1-16-16384 → High (Elevated Administrator)
    └── S-1-16-28672 → System
```

Token theft and replacement is a core escalation primitive. The classic technique writes `System` process token pointer into a target `_EPROCESS.Token` — a 4-byte (x86) or 8-byte (x64) write that grants full system privileges.

### 3.3 UAC and Integrity Levels

User Account Control (UAC) creates split-token processes: a filtered token (medium integrity) and a linked full token (high integrity). This is NOT a security boundary — Microsoft explicitly states this — and can be bypassed via:

- Auto-elevation of built-in executables (`consent.exe` path)
- COM object auto-elevation (e.g., `ICMLuaUtil` → `Elevation:Administrator!new:`)
- DLL side-loading in auto-elevating processes
- ` fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe` registry hijack patterns
- Environment variable injection (`__COMPAT_LAYER`)

---

## 4. The NT Kernel: Attack Surface & Internals

### 4.1 System Call Dispatch

The Windows syscall interface is dispatched via `ntdll.dll` stubs:

```asm
; x64 ntdll!NtCreateFile
mov r10, rcx          ; syscall number preserved
mov eax, 55h          ; syscall number
test byte ptr [SharedUserData+308h], 1  ; syscall instancing check
jne fallback_path
syscall
ret
```

The `SSDT` (System Service Descriptor Table) was attackable in x86 Windows (direct patching), but x64 Windows uses `KPTI`-like isolation and `PatchGuard` (KCLOCKS) to protect the dispatch table. Modern attacks target the *handlers* of syscalls rather than the dispatch table itself.

### 4.2 Key Kernel Structures for Exploitation

```
_EPROCESS (x64, ~2KB)
├── Pcb (_KPROCESS)
│   ├── DirectoryTableBase (CR3)
│   ├── ThreadListHead
│   └── KernelTime
├── UniqueProcessId (PID)
├── ActiveProcessLinks (doubly-linked list)
├── Token → _TOKEN pointer ← HIGH-VALUE WRITE TARGET
├── ImageFileName[15]
├── PriorityClass
├── VadRoot (virtual address descriptor tree)
├── ObjectTable → _HANDLE_TABLE
├── Peb → _PEB (user-mode)
├── InheritedFromUniqueProcessId
└── ProtectionLevel (PPL)

_ETHREAD (x64, ~0x800)
├── Tcb (_KTHREAD)
│   ├── Header (DispatcherObject)
│   ├── StackLimit / StackBase
│   ├── TrapFrame → _KTRAP_FRAME ← write target for RIP control
│   ├── ThreadListEntry
│   └── ApcState → _KAPC_STATE
│       ├── ApcListHead[2] (kernel/user APCs)
│       └── Process → _EPROCESS backpointer
├── Cid (ClientId: UniqueProcess, UniqueThread)
├── StartAddress
├── Win32StartAddress
└── ImpersonationInfo

_OBJECT_HEADER (x64, 0x30)
├── PointerCount
├── HandleCount
├── SecurityDescriptor
├── Body ← object payload starts here
├── TypeIndex ← type confusion target
└── InfoMask (which optional headers are present)

_POOL_HEADER (x64, 0x10)
├── PoolType (paged/nonpaged + flags)
├── PoolTag (4-byte tag identifying allocator)
├── BlockSize
└── PreviousSize
```

### 4.3 Object Handle Model

Windows uses a handle-based object model. Every open object has:

1. A handle in process `_HANDLE_TABLE` → `_HANDLE_TABLE_ENTRY` → pointer to `_OBJECT_HEADER`
2. `_OBJECT_HEADER` → `Body` (the actual object, e.g., `_EPROCESS`)

This indirection means:
- Handles can be duplicated (`DuplicateHandle`) or inherited
- Object reference counts prevent premature deletion (but windows kernel references vs. handle references are distinct, enabling UAF)
- Access checks happen at open time (`NtOpenProcess`, etc.), not at use time

### 4.4 Win32k Object Pool Spraying

Win32k objects are allocated in session pool and are the primary spray targets for pool corruption exploits:

| Object | Pool Tag | Size | Spray primitive |
|--------|----------|------|-----------------|
| `SURFACE` (bitmap) | `Gla8` / `Ula8` | Variable (width × height) | `CreateBitmap` |
| `MENU` | `Mn8` / `Mm8` | 0xA0 | `CreateMenu` |
| `WND` (window) | `Usg8` / `Ust8` | ~0x280 | `CreateWindowEx` |
| `PALETTE` | `Gh08` / `Gh18` | Variable | `CreatePalette` |
| `REGION` | `Gla8` | Variable | `CreateRectRgn` |
| `ACLIP` | `Gd8a` | 0x14 | N/A (internal) |
| `ACCEL` | `Usac` | Variable | `CreateAcceleratorTable` |

**Pattern**: Create many objects of the target size → free one to create hole → trigger vulnerability to overwrite adjacent object → use stale reference to corrupt adjacent object for read/write primitive.

---

## 5. Kernel Object Manager & Pool Corruption

### 5.1 Pool Allocator Internals

The Windows kernel pool allocator (managed by `ExAllocatePoolWithTag` and friends) is the primary memory manager for kernel objects. It operates differently from Linux's SLUB allocator:

**Pool Types:**
- **Non-Paged Pool** (`NonPagedPool`, `NonPagedPoolNx`): Always resident in physical memory, used by ISRs and DPCs. Critical for exploit stability since objects are always accessible.
- **Paged Pool** (`PagedPool`): Can be paged out. More common spray target but requires working set manipulation.

**Windows 10 19H1+ Pool Changes:**
- `NonPagedPoolNx` is now the default (NX for non-paged pool)
- Segmented pool architecture replaces the old lookaside list system
- Pool cookie (randomized) protects `_POOL_HEADER` integrity
- `PoolEnableRecheck` and `PoolVerifier` detect corruption at free time

**Pool vs. Linux SLUB: The key difference for exploitation:**

| Feature | Windows Pool | Linux SLUB |
|----------|-------------|-----------|
| Allocator | Segmented (per-CPU, per-tag) | Per-CPU slabs, per-kmem-cache |
| Metadata | Inline `_POOL_HEADER` before object | Inline `freelist` pointer in object |
| Collision | Tag-based separation (optional) | `kmalloc-*` many co-resident objects |
| Coalescing | Adjacent pool blocks can be merged | Slab page recycling (cross-cache) |
| Overflow detection | Pool cookie verification, verifier | KASAN, SLUB debug, freelist hardening |

### 5.2 Pool Overflow Exploitation

Classical pool overflow in Windows kernel:

```c
// Vulnerable pattern: no bounds check on IOCTL buffer
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    ULONG InputLength = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.InputBufferLength;
    PCHAR Buffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    wchar_t LocalBuf[64]; // 128 bytes on stack, or pool allocation
    
    // BUG: InputLength not validated against sizeof(LocalBuf)
    RtlCopyMemory(LocalBuf, Buffer, InputLength); // overflow!
    
    // If LocalBuf is in pool, adjacent objects get corrupted
}
```

**Exploitation strategy:**
1. Spray pool with target-size objects (`CreateBitmap`, `CreatePalette`)
2. Free every other object to create holes of exact target size
3. Trigger vulnerability to allocate into a hole and overflow into adjacent object
4. Corrupt adjacent object's metadata (e.g., `SURFACE.pvBits0` for arbitrary read; function pointers for RIP control)
5. Leverage controlled read/write primitive for `_EPROCESS.Token` replacement

### 5.3 Use-After-Free in Windows Kernel

UAF exploitation on Windows follows a similar pattern to Linux but with different spray primitives:

```c
// Typical UAF pattern:
// 1. Trigger bug that frees object but leaves dangling reference
Object = AllocateObject(); // object in pool
ReferenceObject(Object);
FreeObject(Object);         // object freed via bug
// Dangling reference still holds pointer to freed memory

// 2. Reclaim freed slot with controlled object
// Spray with object of same pool size
for (int i = 0; i < SPRAY_COUNT; i++) {
    CreateBitmap(width, height, ...); // reclaim freed slot
}

// 3. Use dangling reference → now operates on attacker-controlled data
UseObject(DanglingReference); // type confusion / arbitrary R/W
```

**Windows-specific reclamation primitives:**

| Size Range | Object | Creation API |
|-----------|--------|-------------|
| Small (≤256 bytes) | `NAMED_PIPE` buffers, `EVENT`, `SEMAPHORE` | `CreateNamedPipeFile`, `CreateEvent`, `CreateSemaphore` |
| Medium (256-4096) | `SURFACE` (bitmap), `PALETTE` | `CreateBitmap`, `CreatePalette` |
| Large (≥4096) | Registry `KeyValue`, `ACL` | `RegSetValueEx`, `SetNamedSecurityInfo` |
| Variable | `WNDOBJ`, `DeutschString` | `EngCreateWnd`, custom subclass |

### 5.4 Double Free and Pool Corruption

Double-free exploitation on Windows was significantly impacted by pool hardening:

- **Pre-deduplication (Windows 7)**: Double-free allows attacker to get two allocations from same slot → type confusion
- **Post-deduplication (Windows 8+)**: Pool allocator detects and BugChecks on double-free of same block
- **Deferred free (Windows 10+)**: Freed blocks go to a deferred free list before being returned to the pool, making timing attacks harder

Modern double-free exploitation requires winning a race against the deferred free reclamation.

---

## 6. Windows Memory Management & Exploitation

### 6.1 Virtual Address Space Layout

Windows x64 virtual address space:

```
+─────────────────────── 0xFFFFFFFFFFFFFFFF ──────────────────────+
|                    Canonical Kernel Half                        |
|  +───────────────────── 0xFFFFF80000000000 ────────────────────+|
|  | ntoskrnl.exe / HAL                                            ||
|  +───────────────────── 0xFFFFF800`04000000 ────────────────────+|
|  | Boot drivers / driver images                                  ||
|  +───────────────────── 0xFFFFF801`00000000 ────────────────────+|
|  | NonPaged Pool (SVM)                                           ||
|  +───────────────────── varies ─────────────────────────────────+|
|  | Paged Pool (SVM)                                              ||
|  +───────────────────── 0xFFFFFE00`00000000 ────────────────────+|
|  | HAL / boot-reserved                                           ||
|  +───────────────────────────────────────────────────────────────+|
|                    Non-Canonical Gap (invalid)                       |
+─────────────────────── 0x00007FFFFFFFFFFF ──────────────────────+
|                    User-Mode Half                              |
|  +───────────────────── 0x00007FFFE0000000 ────────────────────+|
|  | ntdll.dll, kernel32.dll, user32.dll                           ||
|  +───────────────────── varies ─────────────────────────────────+|
|  | Heap, stack, mapped files                                     ||
|  +───────────────────── 0x00000000`70000000 ────────────────────+|
|  | PEB, TEB, process image                                       ||
|  +───────────────────── 0x00000000`00010000 ────────────────────+|
|  | NULL guard page                                                ||
+─────────────────────── 0x0000000000000000 ──────────────────────+
```

ASLR randomizes the base addresses of all modules in user mode and the kernel image base (KASLR). On Windows 10+, KASLR entropy is 30 bits (1GB alignment over 64TB range), making brute-force impractical.

### 6.2 Page Table Entry (PTE) Manipulation

Advanced Windows kernel exploits may manipulate PTEs directly:

```c
// PTE format (x64)
// Bit 0: Present
// Bit 1: Read/Write
// Bit 2: User/Supervisor (U/S)
// Bit 5: Accessed
// Bit 6: Dirty
// Bit 7: Page Size (PS) - for large pages
// Bit 63: No-Execute (NX)

// Reading PTE base:
// nt!MmPteBase or computed from CR3 + virtual address
// KVAS (Kernel Virtual Address Shadow / KPTI) adds complexity
```

### 6.3 Virtualization-Based Security (VBS) & Secure Memory

With VBS/HVCI (Hyper-V Code Integrity), the hypervisor enforces:
- **Second-level address translation (SLAT/Extended Page Tables)**: Hypervisor controls EPT to mark kernel code pages as read-execute (no write)
- **KVAS shadow**: Kernel page tables are not mapped in user-mode CR3, forcing CR3 switches on every syscall (Meltdown mitigation)
- **Secure Kernel (securekernel.exe)**: Runs in VTL 1 (Virtual Trust Level 1) and monitors the normal kernel (VTL 0) for integrity violations

This fundamentally changes the exploitation model: direct kernel code modification (write to `.text` pages) is blocked by EPT, forcing attackers toward data-only attacks.

---

## 7. Privilege Escalation: Techniques & Landmark CVEs

### 7.1 Local Privilege Escalation Taxonomy

| Category | Technique | Example CVE |
|-----------|-----------|-------------|
| **Token Manipulation** | Steal/replace `_EPROCESS.Token` pointer | CVE-2021-1732 |
| **Privilege Abuse** | Exploit `SeImpersonatePrivilege` for SYSTEM | potato family |
| **Driver Exploitation** | BYOVD (Bring Your Own Vulnerable Driver) | CVE-2023-32545 |
| **Service Misconfiguration** | Unquoted service paths, weak permissions | Common misconfig |
| **Registry Abuse** | Hijack `ImagePath`, `DisplayName`, COM keys | UAC bypasses |
| **Kernel Pool Corruption** | Overflow/UAF in kernel pool objects | CVE-2020-17087 |
| **Win32k Corruption** | GDI/window object corruption | CVE-2021-1732 |
| **Race Condition** | TOCTOU in file/registry operations | CVE-2021-1648 |
| **Symbolic Link Abuse** | Junction/mount point/symlink redirection | Various |
| **DLL Hijacking** | Load malicious DLL in search order hijack | Common misconfig |
| **ALPC Abuse** | ALPC port message format confusion | CVE-2018-8440 |

### 7.2 Landmark Windows CVEs

#### CVE-2021-1732 (Win32k `_SURFACE` Corruption)

One of the most studied modern Windows kernel exploits:
- Trigger: `NtGdiBitBlt` → `EngRealizeBrush` → integer truncation in `XFORMOBJ` calculation → `_SURFACE.pvBits0` write
- Attack surface: Win32k GDI, reachable from AppContainer
- Primitive: Arbitrary kernel write via corrupted `SURFACE.pvBits0`
- Escalation: Write `_EPROCESS.Token` to replace with `System` token
- Mitigated by: HVCI/EPT (blocks write to code pages, but data-only attacks still work)

#### CVE-2020-17087 (cng.sys Pool Overflow)

- Trigger: `CngDeviceControl` → `BCryptGenRandom` buffer size miscalculation
- Attack surface: `cng.sys` IOCTL
- Primitive: Out-of-bounds write in paged pool
- Escalation: Corrupt adjacent `_CONSOLE_GRAPHICS_BUFFER_INFO` or similar object
- Notable: Google Project Zero's Savannah tracking documented this before Microsoft patched

#### CVE-2018-8440 (ALPC Privilege Escalation)

- Trigger: `NtAlpcSendWaitReceivePort` → `AlpcpDispatchMessage` → TOCTOU in task scheduler
- Attack surface: ALPC (Advanced Local Procedure Call) port accessible from any session
- Primitive: Arbitrary file write via symbolic link redirection
- Escalation: Write to `C:\Windows\System32\` for DLL hijacking or write scheduler task

#### CVE-2021-1648 (Print Spooler TOCTOU)

- Trigger: Race in `AddPrinterDriverEx` → directory junction abuse
- Attack surface: Print spooler service (Spooler)
- Primitive: Load arbitrary driver as SYSTEM
- Escalation: Direct SYSTEM code execution via driver load
- Related: PrintNightmare (CVE-2021-34527) — remote RCE via Print Spooler

#### PrintNightmare (CVE-2021-1673 / CVE-2021-34527)

Arguably the most impactful Windows vulnerability of 2021:
- Attack surface: MS-RPRN (Print System Remote) or MS-PAR (Print System Asynchronous Remote) protocol
- Authentication: Authenticated (any domain user) or unauthenticated (in某些配置下)
- Primitive: `AddPrinterDriverEx` or `RpcAddPrinterDriverEx` with UNC path → arbitrary DLL load as SYSTEM
- Impact: Remote Code Execution on Domain Controllers → full domain compromise
- Key lesson: The Print Spooler service running on DCs by default created a catastrophic attack surface for the most sensitive machines in the enterprise

### 7.3 The Potato Family: SeImpersonatePrivilege Exploitation

Windows services running as `NETWORK SERVICE` or `LOCAL SERVICE` hold `SeImpersonatePrivilege`. This single privilege enables escalation to `SYSTEM` via NTLM relay:

| Potato | Year | Technique | Requirements |
|--------|------|-----------|-------------|
| RottenPotato | 2016 | NTLM relay via DCOM/ BITS and named pipe impersonation | `SeImpersonatePrivilege` |
| JuicyPotato | 2018 | RottenPotato variant with CLSID selection | `SeImpersonatePrivilege` + specific COM objects |
| RoguePotato | 2020 | Binds to port 135 on localhost via redirector | `SeImpersonatePrivilege`, works on Server 2019 |
| PrintSpoofer | 2020 | Named pipe impersonation via Print Spooler | `SeImpersonatePrivilege`, no relay needed |
| GodPotato | 2022 | NTLM relay via `Notification` COM interface | `SeImpersonatePrivilege`, works on all versions |

**Generic pattern:**
1. Trigger NTLM authentication from a privileged process (Spooler, BITS, COM)
2. Relay the NTLM challenge/response to local `SMB` named pipe
3. Call `ImpersonateNamedPipeClient()` on the pipe handle
4. Now running as `SYSTEM`

### 7.4 BYOVD: Bring Your Own Vulnerable Driver

One of the most impactful escalation strategies in modern Windows environments:

- **Concept**: Load a legitimately-signed but vulnerable kernel driver to gain kernel read/write primitives
- **No exploit needed**: The driver is *designed* to provide direct hardware/memory access (ASUS GPU Tweak, MSI Afterburner, Capcom.sys, DBUtil_2_3.sys, RTCore64.sys, atillk64.sys)
- **Impact**: Full kernel read/write, disable DSE (Driver Signature Enforcement), disable EDR callbacks, patch VBS
- **Prevalence**: Microsoft blocks >700 known vulnerable drivers via Microsoft Vulnerable Driver Blocklist, but new ones are discovered regularly
- **Defensive countermeasures**: Microsoft Vulnerable Driver Blocklist, HVCI (blocks unsigned driver loading in VBS), Windows Defender Application Control (WDAC)

**Notable BYOVD CVEs:**
- CVE-2023-32545: Dell `dbutil_2_3.sys` arbitrary kernel memory read/write
- CVE-2019-16098: HTC `HwOs2X64.sys` IOCTL for kernel memory access
- CVE-2021-21551: Dell `dbutil_2_3.sys` kernel memory read/write
- Capcom.sys: Intentionally vulnerable driver distributed by Capcom for testing — provides `ioctl` for arbitrary kernel R/W

---

## 8. Active Directory & Domain Compromise

### 8.1 Active Directory Attack Taxonomy

Active Directory domain compromise follows well-documented kill chains. The critical insight: **most AD compromises do not require zero-days — they exploit misconfigurations, weak credentials, and inherent protocol weaknesses.**

```
Reconnaissance → Initial Access → Credential Theft → Lateral Movement → Domain Dominance
  (SPN enum)    (phishing/spray)  (Kerberoasting)  (Pass-the-Hash)    (DCSync/Golden Ticket)
                                    (Mimikatz)       (Over-Pass-the-Hash)
                                    (LSASS dump)     (Kerberos deleg.)
```

### 8.2 Key Attack Techniques

| Attack | Description | Detection | Mitigation |
|--------|-------------|-----------|------------|
| **Kerberoasting** | Request TGS for SPN accounts; crack offline | Event ID 4769 (RC4 encryption) | AES encryption, long passwords (>25 chars), gMSA |
| **AS-REP Roasting** | Request AS-REP for `DONT_REQ_PREAUTH` accounts; crack | Event ID 4768 (pre-auth failure or success) | Disable `DONT_REQ_PREAUTH`, strong passwords |
| **Golden Ticket** | Forge TGT with `krbtgt` hash; persistent domain access | Event ID 4769 (forged PAC), anomaly in TGT lifetime | Short TGT lifetime (default 10h), monitor for anomalies |
| **Silver Ticket** | Forge TGS with service account hash | No DC communication, hard to detect | Validate PAC, service account password rotation |
| **DCSync** | DCSyncreplicate DFSC password from DC | Event ID 4662 (replication permissions) | Restrict replication permissions (ADACL scan), Protected Users group |
| **Pass-the-Hash** | Use NTLM hash directly for authentication | Event ID 4624 (NTLM logon type 3) | Restrict NTLM, LSA Protection, Credential Guard |
| **Over-Pass-the-Hash** | Convert NTLM hash to Kerberos TGT | Event ID 4768 (Kerberos pre-auth) | LSA Protection, Credential Guard |
| **Constrained Delegation Abuse** | Impersonate any user to delegated service | Event ID 4769 (S4U2Self/Proxy) | Restrict delegation, RBCD monitoring |
| **sAMAccountName Spoofing (Sam-the-Admin)** | Exploit `SAMAccountName` / `sAMAccountName` confusion | Event IDs 4742, 4741 (computer object manipulation) | Install KB500838, update ADCU |
| **Shadow Admin** | Create hidden admin via `adminCount=1` + ACL manipulation | GPO audit, ACL diffing | Regular ADACL scanning, tiered administration |

### 8.3 BloodHound and Attack Path Analysis

BloodHound has fundamentally changed AD security by mapping the attack graph:

```cypher
// Find all paths from domain users to domain admins
MATCH p=shortestPath((d:User {domain:'CORP.LOCAL'})-[*1..]->(a:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

// Find computers where Domain Admins have sessions
MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name

// Find kerberoastable users
MATCH (u:User {hasspn:true}) WHERE NOT u.name STARTS WITH 'KRBTGT' RETURN u.name, u.displayname

// Find AS-REP roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Find shortest path to Domain Controllers
MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {operatingsystem:'Windows Server*'}))
WHERE c.osservicepack IS NOT NULL RETURN p

// Find users with admin rights over computers where domain admins have sessions
MATCH (da:User)-[:MemberOf]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),
      (da)-[:HasSession]->(c:Computer),
      (u:User)-[:AdminTo]->(c)
RETURN u.name, c.name, da.name
```

**Defensive application**: BloodHound is equally valuable for defenders. Run it regularly and identify the shortest paths to DA; then eliminate those paths through ACL changes and tiered administration.

### 8.4 Lateral Movement Techniques

| Technique | Protocol | Tool | Detection |
|-----------|----------|------|-----------|
| Pass-the-Hash | SMB | Mimikatz, Impacket | Event 4624 (NTLM) |
| Over-Pass-the-Hash | Kerberos | Rubeus, Impacket | Event 4768 |
| PsExec | SMB | Sysinternals | Event 4624 (logon type 3/10) |
| WMI Exec | DCOM/RPC | Impacket, WMI | Event 4624, Script block logging |
| WinRM | HTTP | Evil-WinRM | Event 4624 (logon type 3) |
| DCOM | DCOM | Invoke-DCOM | Event 4624, Script block logging |
| SSH | SSH | Native | Event 4624 (logon type 10) |
| RDP | RDP | Native | Event 4624 (logon type 10) |
| PowerShell Remoting | WinRM | PSRemoting | Event 4104, Script block logging |
| PsExec Variant Named Pipes | SMB | Custom | Event 5145 (file share access) |

---

## 9. Windows Malware & Offensive Tooling

### 9.1 Windows Malware Categories

| Category | Examples | Technique | Persistence |
|----------|---------|-----------|-------------|
| **RAT** | Cobalt Strike, Sliver, Havoc | Shellcode injection | Registry, scheduled task, service |
| **Ransomware** | LockBit, Conti, BlackCat | File encryption, volume shadow delete | Service, GPO (domain) |
| **Trojan** | QakBot, Emotet | Email delivery, macro | Scheduled task, COM hijack |
| **Rootkit** | LoJax, Fancy Bear's rootkit | Bootkit, kernel driver | UEFI, MBR, kernel |
| **Stealer** | Lumma, RedLine, Vidar | Browser grab, crypto wallet | Run key, startup folder |
| **Loader** | IcedID, Bumblebee | DLL sideloading, process injection | Service, scheduled task |

### 9.2 Process Injection Techniques on Windows

Windows provides an extraordinarily rich set of injection mechanisms:

| Technique | API | Detection | EDR Evasion |
|-----------|-----|-----------|-------------|
| **Classic DLL Injection** | `CreateRemoteThread` + `LoadLibraryA` | Easy (target module list) | Poor |
| **Process Hollowing** | `CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` → `WriteProcessMemory` → `SetThreadContext` → `ResumeThread` | Moderate (unusual base address) | Moderate |
| **APC Injection** | `QueueUserAPC` / `NtQueueApcThread` | Moderate (APC depth) | Good |
| **Thread Hijacking** | `SuspendThread` → `GetThreadContext` → `SetThreadContext` → `ResumeThread` | Easy (RIP change) | Moderate |
| **Reflective DLL Injection** | Custom `LoadLibrary` in target process | Moderate (no disk load) | Good |
| **Process Doppelgänging** | NTFS transactions → `NtCreateSection` → `NtCreateProcessEx` | Hard (fileless) | Very Good |
| **Process Herpaderping** | Write to file → create section → replace file → create process | Hard (file hash mismatch) | Very Good |
| **Module Stomping** | `LoadLibraryA` in target → `NtUnloadDll` → write our DLL | Hard (legitimate module name) | Good |
| **Syscall Stub Injection** | Direct syscall (bypassing ntdll hooks) | Hard (raw syscall numbers) | Very Good |
| **Early Bird Injection** | `QueueUserAPC` on `CreateProcess(SUSPENDED)` | Moderate | Good |

### 9.3 EDR Evasion Techniques

| Evasion | Technique | Countered By |
|---------|-----------|-------------|
| **Direct Syscalls** | Inline syscall stubs bypassing ntdll hooks | ETW-TI, kernel callbacks |
| **ETW Patching** | Patch `EtwEventWrite` in target process to mask telemetry | ETW-TI (kernel callback), behavioral detection |
| **Unhooking** | Re-map fresh `ntdll.dll` from disk over hooked version | PatchGuard, behavioral detection |
| **Indirect Syscalls** | Jump to existing `syscall` instruction within legitimate `ntdll` code | Call origin verification |
| **Callback Removal** | Remove `PsSetCreateProcessNotifyRoutine` kernel callbacks | HVCI, PatchGuard |
| **Hardware Breakpoints** | Set DR7 breakpoints on EDR hooks | Anti-debug checks |
| **Module Stomping** | Load legitimate DLL → overwrite with payload → legitimate module name in PEB | Memory scanning |

---

## 10. Modern Mitigations & Their Bypasses

### 10.1 Windows Mitigation Timeline and Effectiveness

| Mitigation | Introduced | What It Blocks | Bypass Approach | Current Status |
|-----------|-----------|---------------|----------------|----------------|
| **DEP/NX** | XP SP2 (2004) | Shellcode execution on stack/heap | ROP chains, JIT spray | Ubiquitous; ROP is standard bypass |
| **ASLR** | Vista (2007) | Predictable addresses | Info leak, partial overwrite, JIT spray | Enabled for all modules since Win8 |
| **SEHOP** | Vista (2007) | SEH chain overwrite | Info leak, exception handler abuse | Default ON; rarely targeted directly |
| **Stack Cookies (/GS)** | VS 2003 | Linear stack overflow | Info leak, exception handler, replace target | Strong; cookie leak needed |
| **Heap Validation** | Win8 (2012) | Heap metadata corruption | Use-after-free, data-only, alternate targets | Strong against naive overflow |
| **CFG** | Win8.1 (2014) | Forward-edge CFI (indirect calls) | Fake dispatch, data-only, JOP | Effective; data-only attacks bypass |
| **kCFG** | Win10 RS2 (2017) | Kernel indirect call validation | Data-only kernel attacks | Effective; data-only attacks bypass |
| **ACG** | Win10 RS1 (2016) | Dynamic code generation in process | Code reuse from legitimate modules | Strong when combined with CIG |
| **CIG** | Win10 RS1 (2016) | DLL loading from non-allowed paths | Path traversal, com hijack, signed abuse | Strong with proper policy |
| **VBS/HVCI** | Win10 RS3 (2017) | Kernel code modification (EPT NX) | Data-only attacks, bootkit, VM escape | Strong; forces data-only approach |
| **Kernel CET** | Win11 21H2 (2021) | ROP in kernel (shadow stack) | JOP, data-only, call stack manipulation | Growing deployment |
| **kCFI** | Win11 24H2 (2024) | Kernel indirect call type validation | Data-only attacks, function pointer confusion | Latest; pushes toward data-only |
| **Stack Randomization** | Win10 (2015) | Stack address prediction | Info leak | Baseline |
| **Pool Corruption Detection** | Win10 19H1 | Pool header/block corruption | Use-after-free (doesn't corrupt headers) | Detects overflow at free time |
| **Retpoline** | Win10 1809 | Spectre variant 2 | Not directly relevant to exploitation | Side-channel mitigation |
| **KVA Shadow (KPTI)** | Win10 1803 | Meltdown (user→kernel memory read) | Alternative info leaks | Effective for Meltdown |

### 10.2 VBS/HVCI: The Modern Exploitation Barrier

VBS (Virtualization-Based Security) with HVCI (Hyper-V Code Integrity) represents the most significant shift in Windows kernel exploitation:

**What VBS/HVCI enforces:**
1. **EPT-based code integrity**: Kernel code pages are marked read-execute (not writable) in EPT. Any attempt to write to kernel code triggers an EPT violation.
2. **Second-level address translation**: Hypervisor controls page tables, preventing kernel from modifying its own page tables.
3. **Secure kernel**: A separate kernel (`securekernel.exe`) runs in VTL 1, monitoring VTL 0 (normal kernel) for integrity violations.
4. **Credential Guard**: LSASS secrets stored in VTL 1, inaccessible from VTL 0.

**What this means for exploitation:**
- ROP in kernel is blocked (code pages not writable → no gadget chains)
- Function pointer overwrites that target non-CFG-validated indirect calls are blocked by kCFI
- The remaining viable approach is **data-only attacks**: modify `_EPROCESS.Token`, ACLs, or thread contexts without writing code

### 10.3 Data-Only Kernel Attacks

With VBS/HVCI and kCFG/kCFI forcing attackers away from code-execution approaches, the modern Windows kernel exploit trend is data-only:

**Primary targets for arbitrary write:**

| Target | Effect | Technique |
|--------|--------|-----------|
| `_EPROCESS.Token` | Replace process token with SYSTEM token | Direct pointer write |
| `_EPROCESS.Token` + PreviousMode | Set PreviousMode=0 in `_KTHREAD` for kernel API calls | Single byte write at KTHREAD offset |
| `_ACL` in process token | Grant all privileges | Modify ACL bytes |
| `SeDebugPrivilege` | Enable via token manipulation | Modify privilege flags |
| Process ACL | Grant full access to target process | DACL modification |
| `SList` in `_KTHREAD` | Push/pop for stack pivot | Interlocked operations |

**The `_EPROCESS.Token` replacement pattern (x64):**

```c
// Data-only token replacement exploit primitive
// Prerequisite: arbitrary kernel write primitive (from pool corruption, etc.)

// 1. Find System process (PID 4) EPROCESS
PVOID systemProcess = PsGetCurrentProcess(); // or walk ActiveProcessLinks
PVOID targetProcess = /* find our process EPROCESS */;

// 2. Read System token
ULONG64 systemToken = *(PULONG64)((PCHAR)systemProcess + TOKEN_OFFSET);

// 3. Write System token into our process (replace original)
*(PULONG64)((PCHAR)targetProcess + TOKEN_OFFSET) = systemToken;

// Result: our process now has SYSTEM privileges
// No code execution needed — pure data modification
```

This pattern is immune to CFG, kCFG, CET, and ACG because no code flow is modified — only a single pointer swap in kernel memory.

### 10.4 Kernel CET (Shadow Stack)

Intel CET (Control-Flow Enforcement Technology) adds a shadow stack to verify return addresses on function returns. In kernel mode (Win11 21H2+), this means:

- **ROP chains are defeated**: Each `ret` verifies the return address against the shadow stack
- **Stack pivots are blocked**: The shadow stack is at a fixed location, separate from the data stack
- **But**: Data-only attacks are completely unaffected
- **JOP (Jump-Oriented Programming)**: Still viable if indirect call targets pass CFG validation

### 10.5 The Exploit Mitigation Arms Race

```
Mitigation introduced → Bypass found → New mitigation → New bypass → ...

DEP (2004) → ROP chains → Stack Cookie + SEHOP → Info leaks → ASLR (2007)
→ Info leak + partial overwrite → Heap Validation → Use-after-free → CFG (2014)
→ Fake dispatch/data-only → kCFG + HVCI (2017) → Data-only attacks only
→ CET (2021) → Shadow stack → data-only + JOP → kCFI (2024) → ?
```

The trend is clear: **code-execution attacks are being progressively eliminated**, pushing exploitation toward data-only attacks that modify security-relevant data structures without executing attacker-controlled code.

---

## 11. Hardening the Windows Attack Surface

### 11.1 Windows Server Hardening Checklist

| Category | Setting | Purpose |
|----------|---------|---------|
| **Credential Protection** | Enable Credential Guard (VBS) | Protect LSASS from Mimikatz |
| **Credential Protection** | Enable LSA Protection (RunAsPPL) | Prevent LSASS process injection |
| **Credential Protection** | Disable WDigest (EnableCred 0) | Prevent cleartext credential caching |
| **Credential Protection** | Restrict NTLM | Reduce pass-the-hash attack surface |
| **Privilege Management** | Remove `SeDebugPrivilege` from non-admins | Prevent process injection |
| **Privilege Management** | Remove `SeImpersonatePrivilege` from service accounts | Prevent potato attacks |
| **Privilege Management** | Use gMSA for service accounts | Auto-managed, long passwords |
| **Driver Security** | Enable Microsoft Vulnerable Driver Blocklist | Block BYOVD |
| **Driver Security** | Enable HVCI | Block unsigned driver loading |
| **Driver Security** | WDAC policy (allow only signed drivers) | Prevent driver-based escalation |
| **Network** | Disable Print Spooler on DCs | Prevent PrintNightmare |
| **Network** | Enable LDAP signing | Prevent LDAP relay |
| **Network** | Enable SMB signing (at minimum server-side) | Prevent SMB relay |
| **Network** | Disable NTLMv1 | Prevent credential relay |
| **AD Hardening** | Protected Users group for DA/EA | Block NTLM, limit TGT lifetime |
| **AD Hardening** | Tiered administration (Tier 0/1/2) | Limit DA lateral movement |
| **AD Hardening** | Regular BloodHound scans | Detect attack paths |
| **AD Hardening** | AES-only for Kerberos | Prevent RC4 Kerberoasting |
| **Audit** | Advanced audit policy (4624, 4625, 4672, 4768, 4769, 4770) | Detect lateral movement |
| **Audit** | PowerShell Script Block Logging (4104) | Detect malicious PowerShell |
| **Audit** | LSA Protection events (3033, 3065) | Detect LSA attacks |
| **Boot** | Secure Boot + BitLocker | Prevent bootkits |
| **Boot** | Measured Boot (TCG logs) | Verify boot chain integrity |

### 11.2 EDR Evasion Countermeasures

| EDR Evasion | Countermeasure |
|-------------|---------------|
| Direct syscalls | ETW-TI kernel callbacks, kernel-mode telemetry |
| ETW patching | ETW-TI (kernel-level ETW, cannot be patched from user-mode) |
| ntdll unhooking | PatchGuard protects kernel callbacks, kernel ETW unaffected |
| Reflective DLL injection | Memory scanning, behavioral analysis |
| Process hollowing | Module integrity checks, parent-child process relationship monitoring |
| Living-off-the-land (LotL) | AMSI, constrained language mode, script block logging |
| Credential dumping | Credential Guard, LSA Protection, WDigest disable |
| LSASS access | RunAsPPL, Credential Guard, PPL for LSASS |

### 11.3 Windows Defender Application Control (WDAC)

WDAC is Microsoft's premier application control solution, replacing AppLocker:

- **Block mode**: Only allow explicitly signed/trusted code
- **Enforce at kernel level**: Prevents BYOVD, unsigned driver loading, script abuse
- **Multiple policy support**: Can layer policies (allow Microsoft, block 3rd party, etc.)
- **Intelligent Security Graph**: Cloud-based reputation for allow/deny decisions

Critical for blocking:
- BYOVD (bring your own vulnerable driver)
- Reflective DLL injection (unsigned code in memory)
- Living-off-the-land (PowerShell Empire, Cobalt Strike)

---

## 12. Cross-Track Connections

### 12.1 OSEE (EXP-401) — Advanced Windows Exploitation

The OSEE track ([`../OSEE/`](../OSEE/)) is the direct practical companion to this report. Where this report covers the *landscape* and *techniques*, OSEE provides hands-on exploitation exercises:

- **EXP-401 Module 3** (Kernel Exploitation) directly implements the pool corruption techniques described here in §5
- **EXP-401 Module 5** (Reverse Engineering) overlaps with our CVE analysis methodology
- **EXP-401 Module 7** (Mitigation Bypass) builds on our §10 mitigation stack
- The OSEE exam requires developing working exploits against hardened Windows targets — exactly the skill chain described in §7

### 12.2 Linux Kernel — Comparative Exploitation

The Linux Kernel track ([`../linux_kernel/`](../linux_kernel/)) provides the other side of the kernel exploitation coin:

| Aspect | Windows | Linux |
|--------|---------|-------|
| Allocator | Segmented pool (tag-based) | SLUB (per-CPU slabs, per-cache) |
| Spray primitive | Win32k objects, pipes, registry | `msg_msg`, `pipe_buffer`, `tty_struct` |
| Primary target | Pool overflow into adjacent `_SURFACE` | UAF into `msg_msg`/`pipe_buffer` |
| Mitigation stack | VBS/HVCI, kCFI, CET, CFG | KASLR, SMEP, SMAP, KPTI, KFORTIFY |
| Modern approach | Data-only (`_EPROCESS.Token`) | Data-only (`commit_creds`/`modprobe_path`) |
| Debug tool | WinDbg | GDB/qemu |
| Structure analysis | `dt` in WinDbg | `pahole`/`gdb` struct |

Both tracks converge on the same conclusion: **modern kernel exploitation is increasingly data-only**, bypassing CFI and CET by modifying security-relevant data structures rather than hijacking code flow.

### 12.3 macOS — Alternative Desktop Security Model

The macOS track ([`../MacOS/`](../MacOS/)) offers a contrast in security architecture:

- macOS has **stronger default sandboxing** (App Sandbox, Hardened Runtime) but **weaker enterprise management**
- **Mach IPC** (macOS) vs. **ALPC/Binder** (Windows/Android) — different IPC attack surfaces
- macOS SIP (System Integrity Protection) is analogous to Windows VBS/HVCI in intent but different in implementation
- **AMFI (Apple Mobile File Integrity)** serves a similar role to **WDAC** in specifying trust boundaries
- Both platforms face similar threats: **initial access via phishing → local escalation → credential theft → lateral movement**

### 12.4 CPU Rings — Hardware-Enforced Boundaries

The Ring & Vulnerabilities track ([`../ring_and_vulns/`](../ring_and_vulns/)) provides the hardware context for Windows security:

- **Ring 0 → Ring 3 transition**: `sysret`/`iretq` on Windows mirrors `sysret` on Linux
- **Ring −1 (VBS)**: Windows HVCI runs the secure kernel in VMX non-root, monitoring the normal kernel
- **Ring −2 (SMM)**: UEFI firmware attacks (LoJax) target the Windows boot chain before the OS loads
- **The full attack chain from Ring 3 to Ring −2**: User process → kernel exploit → BYOVD → SMM implant is documented in the Rings track and realized in Windows-specific bootkits like LoJax and FinSpy

### 12.5 Zero-Day Research — Discovery Methodology

The Zero-Day track ([`../zero_day/`](../zero_day/)) covers the discovery methodology that produces the CVEs analyzed here:

- **Fuzzing Windows**: WinAFL, syzkaller-windows, and IOCTL fuzzing are primary discovery tools
- **Code audit**: IDA/Ghidra analysis of win32k and driver IOCTL handlers
- **Patch diffing**: Microsoft's monthly Patch Tuesday provides 50-100 binary diffs; analyzing changes reveals vulnerability root causes
- **Variant analysis**: After a CVE is published, searching for similar patterns in the same driver or across drivers yields variants (e.g., CVE-2021-1732 spawned 10+ variants in win32k)

---

## 13. Key Findings & Recommendations

### 13.1 Summary of Key Findings

1. **The Windows kernel attack surface is large and growing**: With ~3,000+ driver IOCTL handlers and win32k's 500+ syscalls, the kernel's attack surface vastly exceeds Linux's. Each Windows version adds new attack surfaces (WSL2, WSLg, DirectX, etc.)

2. **Pool corruption remains the primary kernel exploitation vector**: Despite pool hardening, UAF and overflow in paged/non-paged pools account for >60% of all kernel EoP CVEs. The pool allocator's fundamental design (co-located objects of similar sizes) enables cross-object corruption

3. **Data-only attacks dominate modern exploitation**: VBS/HVCI, kCFI, and Kernel CET have effectively ended the era of ROP-based kernel exploitation. Modern exploits modify `_EPROCESS.Token`, ACLs, and security descriptors without injecting or redirecting code execution

4. **Active Directory is the enterprise kill chain fulcrum**: 90%+ of domain compromises exploit misconfigurations (Kerberoasting, delegation abuse, weak Service Account passwords), not zero-day vulnerabilities. BloodHound and offensive tooling automate this extensively

5. **The BYOVD technique is a systemic problem**: Legitimately-signed drivers with kernel memory access exist for hardware management but are weaponized by attackers. Microsoft's blocklist approach is reactive; WDAC/HVCI is the proactive defense

6. **SeImpersonatePrivilege enables SYSTEM escalation from NETWORK SERVICE**: The potato attack family shows that even low-privilege service accounts can escalate to SYSTEM, making this privilege a critical escalation path

7. **EDR evasion is an arms race**: Direct syscalls, ETW patching, and kernel callback removal are met with ETW-TI, PatchGuard, and behavioral detection. The advantage oscillates between offense and defense

### 13.2 Recommendations

**For Enterprise Defenders:**
1. Enable VBS/HVCI on all Windows 10+ endpoints (requires TPM 2.0, UEFI, Secure Boot)
2. Deploy WDAC in audit mode, then enforce — block unsigned drivers, script engines, and LOLBins
3. Disable Print Spooler on Domain Controllers (or restrict to `Server2019+` patched versions)
4. Run BloodHound weekly; fix attack paths from Domain Users to Domain Admins
5. Enforce Credential Guard, LSA Protection, and WDigest disablement across all endpoints
6. Implement tiered administration (Tier 0 = DCs, Tier 1 = Servers, Tier 2 = Workstations) with one-way trust
7. Enable PowerShell Script Block Logging (Event ID 4104) and AMSI across all endpoints
8. Deploy LSASS protection (RunAsPPL) to prevent Mimikatz and credential dumping

**For Security Researchers:**
1. Focus on win32k attack surface — it remains the richest kernel attack surface and is reachable from sandboxed contexts
2. Study data-only attack patterns — they are the future of Windows kernel exploitation
3. Learn WinDbg kernel debugging thoroughly — it is the primary tool for kernel exploit development
4. Understand VBS/HVCI internals deeply — this is the primary barrier to modern exploitation
5. Audit third-party drivers (not just Microsoft drivers) — vendor-specific drivers are often less scrutinized
6. Develop new pool spray techniques for Windows 11's segmented pool — the old techniques are increasingly unreliable

**For Organizations:**
1. Prioritize patching of Windows kernel and AD vulnerabilities — these provide the highest-value escalation paths
2. Conduct regular AD security assessments using BloodHound, PingCastle, and Purple Knight
3. Implement a vulnerability management program that accounts for the 60-90 day average enterprise patch delay
4. Establish an incident response plan specifically for domain compromise scenarios (Golden Ticket, DCSync)
5. Regularly audit and rotate `krbtgt` password (schedule dual rotation to invalidate existing Golden Tickets)
6. Deploy network segmentation that limits lateral movement paths (especially Domain Admin session isolation)

---

## Appendix: Key CVE Reference Table

| CVE | Component | Type | CVSS | Impact | Year |
|-----|-----------|------|------|--------|------|
| CVE-2021-1732 | Win32k | Integer overflow → LPE | 7.8 | EoP | 2021 |
| CVE-2020-17087 | cng.sys | Pool overflow | 7.8 | EoP | 2020 |
| CVE-2018-8440 | ALPC/Task Scheduler | TOCTOU | 7.8 | EoP | 2018 |
| CVE-2021-34527 | Print Spooler (PrintNightmare) | RCE | 9.8 | Auth RCE, LPE | 2021 |
| CVE-2021-1673 | Print Spooler | Auth RCE | 7.8 | RCE | 2021 |
| CVE-2021-1648 | Print Spooler | TOCTOU | 7.8 | LPE | 2021 |
| CVE-2020-0787 | BITS | Arbitrary file move | 7.8 | LPE | 2020 |
| CVE-2019-1458 | Win32k | UAF → LPE | 7.8 | EoP | 2019 |
| CVE-2020-1054 | Win32k | GDI overflow | 7.0 | EoP | 2020 |
| CVE-2021-40444 | MSHTML | Arbitrary code execution | 8.8 | RCE | 2021 |
| CVE-2022-21882 | Win32k | LPE (1732 variant) | 7.8 | EoP | 2022 |
| CVE-2022-26923 | AD CS | Privilege escalation | 8.8 | Domain Escalation | 2022 |
| CVE-2023-36884 | Office/HTML | Remote code execution | 8.8 | RCE | 2023 |
| CVE-2024-21412 | SmartScreen | Bypass | 8.8 | RCE chain | 2024 |
| CVE-2025-21298 | NTLM | Relay | 8.1 | Credential theft | 2025 |

---

## Related Tracks

- [**OSEE / EXP-401**](../OSEE/) — Hands-on advanced Windows exploitation training covering these techniques in practice
- [**Linux Kernel Vulnerabilities & Exploitation**](../linux_kernel/) — Comparative kernel exploitation on the Linux side
- [**macOS Security & Internals**](../MacOS/) — Alternative desktop OS security model comparison
- [**CPU Protection Rings & Vulnerabilities**](../ring_and_vulns/) — Hardware-enforced privilege boundaries that underpin Windows security
- [**Zero-Day Research & Exploit Development**](../zero_day/) — Vulnerability discovery methodology that produces the CVEs analyzed here
- [**Chromium Architecture & Vulnerability**](../Chromium_Architecture_and_Vulnerability/) — Browser sandbox escape chains that target the Windows kernel

---

*Report compiled: May 2026. All CVE data sourced from NVD, Microsoft Security Response Center, Project Zero, and public exploit databases.*

## References

1. Russinovich, M. et al. "Windows Internals." 7th Ed. *Microsoft Press*. 2021.
2. Microsoft. "Windows Security Documentation." https://docs.microsoft.com/en-us/windows/security/. 2024.
3. MITRE. "ATT&CK: Windows Techniques." https://attack.mitre.org/techniques/enterprise/. 2024.
4. Microsoft Security Response Center (MSRC). https://msrc.microsoft.com/blog/. 2024.
5. j00ru (Jurczyk, M.). "Windows Kernel Research." https://j00ru.vexillium.org/. 2024.
6. Schenck, M. "Swimming In The (Kernel) Pool." *Black Hat USA*. 2021.
7. Shafir, Y. & Bayet, C. "Scoop the Windows 10 Pool!" *Black Hat USA*. 2021.
8. McGarr, C. "Windows Kernel Exploitation." https://connormcgarr.github.io/. 2024.
9. Perla, E. & Oldani, M. "A Guide to Kernel Exploitation: Attacking the Core." *Syngress*. 2010.
10. Corelan Team. "Exploit Writing Tutorials." https://www.corelan.be/. 2024.
11. LOLDrivers Project. "Bring Your Own Vulnerable Driver." https://www.loldrivers.io/. 2024.
12. NIST. "National Vulnerability Database." https://nvd.nist.gov/. 2024.
13. Google Project Zero. "0-day 'In the Wild' Database." https://googleprojectzero.blogspot.com/p/0day-in-wild.html. 2024.
14. Offensive Security. "EXP-401: Advanced Windows Exploitation." https://www.offsec.com/courses/exp-401/. 2024.
15. NCC Group. "Windows Privilege Escalation Techniques." https://www.nccgroup.com/. 2024.
16. Hacker, H. "HackSys Extreme Vulnerable Driver." https://github.com/hacksysteam/HackSysExtremeVulnerableDriver. 2024.
17. Mandt, T. "Kernel Pool Exploitation on Windows 7." *Black Hat DC*. 2011.
18. FuzzySecurity. "Windows Exploitation Tutorials." https://www.fuzzysecurity.com/. 2024.
19. Chapman, F. "Token Impersonation: Potato Exploitation Techniques." *Black Hat*. 2021.
20. Microsoft. "Kernel-Mode Driver Architecture." https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/. 2024.