# Advanced Windows Exploit Mitigations & Modern Bypass Techniques

> **Context**: OSEE (Offensive Security Exploitation Expert) — Advanced Windows kernel
> and user-mode exploitation. This document covers the mitigation landscape from
> Windows 10 19H1 through Windows 11 24H2 and the corresponding state of bypass
> research as of early 2026.

---

## Table of Contents

1. [Kernel-Mode Mitigations](#1-kernel-mode-mitigations)
   - [1.1 SMEP — Supervisor Mode Execution Prevention](#11-smep--supervisor-mode-execution-prevention)
   - [1.2 SMAP — Supervisor Mode Access Prevention](#12-smap--supervisor-mode-access-prevention)
   - [1.3 Kernel DEP and NonPagedPoolNx](#13-kernel-dep-and-nonpagedpoolnx)
   - [1.4 KDP — Kernel Data Protection](#14-kdp--kernel-data-protection)
   - [1.5 HVCI — Hypervisor-Protected Code Integrity](#15-hvci--hypervisor-protected-code-integrity)
   - [1.6 VBS — Virtualization-Based Security](#16-vbs--virtualization-based-security)
2. [Heap Mitigations](#2-heap-mitigations)
   - [2.1 Low Fragmentation Heap (LFH) Randomization](#21-low-fragmentation-heap-lfh-randomization)
   - [2.2 Segment Heap Security Features](#22-segment-heap-security-features)
   - [2.3 Heap Guard Pages](#23-heap-guard-pages)
   - [2.4 Encoded Heap Pointers and Headers](#24-encoded-heap-pointers-and-headers)
   - [2.5 Pool Hardening in Modern Windows](#25-pool-hardening-in-modern-windows)
3. [Advanced Bypass Techniques](#3-advanced-bypass-techniques)
   - [3.1 Data-Only Attacks and JIT-ROP](#31-data-only-attacks-and-jit-rop)
   - [3.2 WARP Techniques](#32-warp-techniques)
   - [3.3 BYOVD — Bring Your Own Vulnerable Driver](#33-byovd--bring-your-own-vulnerable-driver)
   - [3.4 PTE Manipulation for SMEP/SMAP Bypass](#34-pte-manipulation-for-smepsmap-bypass)
   - [3.5 Page Table Manipulation Techniques](#35-page-table-manipulation-techniques)
   - [3.6 Token Manipulation Without Code Execution](#36-token-manipulation-without-code-execution)
4. [Emerging Mitigations — Windows 11+](#4-emerging-mitigations--windows-11)
   - [4.1 Kernel CET and Shadow Stacks](#41-kernel-cet-and-shadow-stacks)
   - [4.2 Secured-Core PC Features](#42-secured-core-pc-features)
   - [4.3 Smart App Control](#43-smart-app-control)
   - [4.4 Enhanced Hardware Security Features](#44-enhanced-hardware-security-features)
5. [The Arms Race — How Mitigations Shape OSEE](#5-the-arms-race--how-mitigations-shape-osee)

---

## 1. Kernel-Mode Mitigations

### 1.1 SMEP — Supervisor Mode Execution Prevention

**What it is.**
SMEP is a CPU feature (Intel: CR4 bit 20, introduced Ivy Bridge 2012; AMD: from Zen)
that prevents Ring 0 code from executing pages whose page-table entries (PTEs) have
the User/Supervisor bit set to User. In practical terms, if kernel code attempts to
`CALL` or `JMP` to a virtual address that the page tables mark as a user-mode page,
the processor raises a #PF (page fault) and the OS bugchecks (`ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`
or `KERNEL_DATA_INPAGE_ERROR` depending on context).

**Why it matters.**
Before SMEP, the classic kernel exploit primitive was:

1. Obtain an arbitrary kernel write (or controlled call target).
2. Allocate an executable user-mode page containing shellcode (e.g., token-stealing
   payload).
3. Redirect kernel execution to the user-mode page.

SMEP closes this entire class. Any attempt to execute user-mode shellcode from Ring 0
now faults.

**Windows integration.**
Windows enables SMEP unconditionally on supported hardware since Windows 8 (NT 6.2).
The kernel sets CR4.SMEP during early boot in `KiSystemStartup` → `KiInitializeBootStructures`.
There is no documented API to disable SMEP at runtime, and any attempt to clear
CR4.SMEP while HVCI is enabled will be intercepted by the hypervisor.

**Verification in WinDbg:**

```
kd> r cr4
cr4=00000000003506f8
```

Bit 20 (0x100000) set → SMEP active. Alternatively:

```
kd> !cpuinfo
...
FeatureFlags: ... SMEP ...
```

**Known bypass vectors (pre-hardening):**

| Technique | Description | Current Status |
|-----------|-------------|----------------|
| CR4 flip | Write to CR4 to clear bit 20 | Blocked by HVCI |
| PTE manipulation | Remap user-mode page as supervisor | Viable (see §3.4) |
| ROP to `KiConfigureDynamicProcessor` | Abuse legitimate CR4 writes | Patched |
| Data-only / ROP in kernel space | Never leaves supervisor pages | Viable |

---

### 1.2 SMAP — Supervisor Mode Access Prevention

**What it is.**
SMAP (Intel: CR4 bit 21, Broadwell 2014; AMD: Zen) extends SMEP to cover *reads and
writes*. When SMAP is active, any Ring 0 instruction that reads from or writes to a
user-mode page (U/S = User) causes a #PF, unless the EFLAGS.AC flag is explicitly
set (via `STAC`/`CLAC` instruction pairs).

**Why it matters.**
Without SMAP, kernel exploits commonly:

- Read data structures from user-controlled allocations (fake objects in user space).
- Use user-mode memory as scratch space visible to the kernel.
- Place fake vtables, function pointers, or other structures in user space.

SMAP forces all data referenced by kernel code to reside in kernel virtual address
space, dramatically increasing exploit complexity.

**Windows integration.**
Windows 10 RS1 (1607) and later enable SMAP on supported hardware. The kernel uses
`STAC`/`CLAC` bracketing around legitimate user-mode memory accesses (e.g.,
`ProbeForRead`/`ProbeForWrite`, `MmCopyVirtualMemory`). The `STAC` instruction sets
`EFLAGS.AC`, temporarily allowing user-mode access; `CLAC` clears it.

**Implications for exploit development:**

- Fake kernel objects can no longer live in user space. They must be sprayed into
  kernel pools or other kernel-mapped regions.
- Increases reliance on kernel heap spray and pool grooming.
- Combined with SMEP, eliminates the simplest class of kernel exploits entirely.

**SMAP bypass considerations:**

- SMAP, like SMEP, is enforced per-PTE. PTE manipulation can mark a user-mode page
  as supervisor, bypassing both SMEP and SMAP simultaneously.
- If the attacker has an arbitrary write but not code execution, SMAP does not directly
  impede data-only attacks against kernel structures.
- HVCI protects CR4 writes, preventing runtime SMAP disable.

---

### 1.3 Kernel DEP and NonPagedPoolNx

**Kernel DEP (NX for kernel stacks and code).**
Since Windows 8, the kernel enforces NX (No-Execute) bit on kernel stacks, pool
allocations, and data sections. This prevents the classic technique of placing
shellcode directly into a kernel buffer and executing it.

Key enforcement points:

- **Kernel stacks**: Marked NX. Stack buffer overflows cannot execute shellcode directly.
- **NonPagedPool**: Legacy pool type that was RWX. Still exists for backward compatibility
  but **deprecated**.
- **NonPagedPoolNx**: Introduced in Windows 8. All new kernel pool allocations should
  use `NonPagedPoolNx` (or `POOL_FLAG_NON_PAGED` in the modern `ExAllocatePool2` API),
  which is backed by NX pages.
- **Module code sections**: Mapped RX (not RWX). Data sections are RW (not RWX).

**`ExAllocatePool2` (Windows 10 2004+):**
The modern pool allocation API defaults to NX. The legacy `ExAllocatePoolWithTag`
with `NonPagedPool` type still allocates RWX memory but is deprecated and triggers
static analysis warnings. HVCI-compatible drivers must never use RWX pool memory.

**Impact on exploitation:**

```
Old world:   alloc = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'Hack');
             memcpy(alloc, shellcode, sizeof(shellcode));
             ((void(*)())alloc)();  // RWX — works

New world:   alloc = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'Hack');
             // NX — executing this page faults
```

Exploiters must now use ROP/JOP within existing RX kernel code (ntoskrnl, drivers)
or manipulate page tables to create RWX mappings.

---

### 1.4 KDP — Kernel Data Protection

**What it is.**
KDP (Kernel Data Protection), introduced in Windows 10 20H1 (2004), uses VBS to
make selected kernel data structures **read-only at the hypervisor level**. Even code
running in Ring 0 cannot modify KDP-protected memory — the Second Level Address
Translation (SLAT/EPT) tables managed by the hypervisor mark the backing physical
pages as read-only.

**Two flavors:**

1. **Static KDP**: Entire data sections of the kernel or drivers can be marked
   read-only after initialization via `MmProtectDriverSection`.
2. **Dynamic KDP**: Individual allocations from a "secure pool" can be made read-only
   after initialization via `ExAllocatePool3` with `POOL_FLAG_SECURE_ALLOCATION`
   (internally uses VBS secure pool).

**Protected structures (examples):**

- `ci.dll` global policy variables (Code Integrity configuration)
- Parts of `PsProtectedSigner` tables
- `SeTokenPrivileges` on protected process tokens (on some configurations)
- Driver-specific security policies

**Impact on exploitation:**

- Classic kernel exploits that overwrite CI policy variables to disable Driver
  Signature Enforcement (DSE) are defeated.
- Token privilege manipulation may be blocked for certain protected tokens.
- Attackers must find data structures that are *not* KDP-protected.
- KDP does not protect dynamically allocated objects like `TOKEN` structures in the
  general pool — those remain writable from Ring 0 (absent additional protections).

---

### 1.5 HVCI — Hypervisor-Protected Code Integrity

**What it is.**
HVCI (also called Memory Integrity) uses VBS to enforce W^X (Write XOR Execute) at
the hypervisor level for all kernel-mode code. The hypervisor's SLAT/EPT tables
ensure that no physical page is simultaneously writable and executable.

**Enforcement model:**

| Operation | HVCI Behavior |
|-----------|---------------|
| Execute kernel code page | Allowed (page is RX in EPT) |
| Write to kernel code page | Blocked (#VMEXIT → bugcheck) |
| Execute kernel data page | Blocked (#VMEXIT → bugcheck) |
| Allocate RWX kernel memory | Blocked by `MmAllocateIndependentPages` and pool APIs |
| Load unsigned driver | Blocked by Code Integrity |
| Modify CR4 (clear SMEP/SMAP) | Intercepted by hypervisor |
| Modify MSRs (LSTAR, etc.) | Intercepted by hypervisor |

**Technical implementation:**

1. During boot, `hvloader.efi` loads the hypervisor (`hvix64.exe` or `hvax64.exe`)
   before the Windows kernel.
2. The hypervisor creates a Virtual Trust Level 1 (VTL 1) environment running
   `securekernel.exe` (Secure Kernel).
3. The normal kernel runs in VTL 0 — it has *lower* privilege than VTL 1.
4. The hypervisor manages EPT for VTL 0 and enforces W^X. Any attempt by VTL 0 code
   to make a page both writable and executable is denied.
5. Page table modifications in VTL 0 are validated — the hypervisor ensures the VTL 0
   kernel cannot create executable mappings for arbitrary physical pages.

**HVCI bypass considerations:**

- **Legitimate RWX mappings**: Some legacy drivers require RWX memory. HVCI denies
  this; non-compliant drivers are blocked from loading.
- **PTE remapping**: Under HVCI, the hypervisor validates PTE changes. Direct PTE
  writes to mark a page executable are caught (see §3.5 for nuances).
- **Data-only attacks**: HVCI does not prevent data-only attacks. If the attacker can
  corrupt kernel data (tokens, security descriptors, etc.) without needing code
  execution, HVCI is irrelevant.
- **ROP chains**: HVCI allows execution of existing RX code. ROP chains using
  gadgets in `ntoskrnl.exe` or loaded drivers remain viable.
- **JIT-ROP in kernel**: Theoretically possible if there's a kernel read primitive,
  but the kernel address space is relatively static (no JIT engine), making traditional
  ROP more practical.

---

### 1.6 VBS — Virtualization-Based Security

**Architecture overview.**
VBS is the umbrella technology that enables HVCI, Credential Guard, KDP, and other
hypervisor-backed security features. It creates an isolated execution environment
(VTL 1) that is inaccessible from the normal OS kernel (VTL 0).

```
┌─────────────────────────────────────────────────────┐
│                   Hardware (CPU + IOMMU)             │
├─────────────────────────────────────────────────────┤
│              Hypervisor (hvix64.exe)                 │
│         Manages EPT, VTL transitions, MSRs          │
├──────────────────────┬──────────────────────────────┤
│      VTL 1           │         VTL 0                │
│  Secure Kernel       │    Normal NT Kernel          │
│  (securekernel.exe)  │    (ntoskrnl.exe)            │
│  Credential Guard    │    Normal drivers            │
│  (lsaiso.exe)        │    User-mode apps            │
│  Secure policies     │                              │
└──────────────────────┴──────────────────────────────┘
```

**VTL 0 → VTL 1 boundary:**

- VTL 0 cannot read or write VTL 1 memory (EPT enforced).
- VTL 0 communicates with VTL 1 via secure hypercalls and shared mailbox pages.
- Even with full kernel compromise (VTL 0 Ring 0), the attacker cannot:
  - Dump LSASS credentials if Credential Guard is enabled.
  - Modify KDP-protected data.
  - Create RWX kernel pages if HVCI is enabled.
  - Tamper with VTL 1 policies or code.

**VBS attack surface:**

- **Hypercall interface**: The VTL 0 → hypervisor hypercall surface is small but
  has been audited and occasionally yields vulnerabilities.
- **Shared memory regions**: Mailbox pages are potential attack surface for VTL 1
  if input validation is insufficient.
- **Firmware/UEFI**: VBS trust is rooted in Secure Boot. Compromising the boot
  chain (e.g., via a bookit or UEFI vulnerability) can disable VBS entirely.
- **Hardware attacks**: DMA attacks via PCIe devices can potentially bypass VBS if
  IOMMU (VT-d) is not properly configured or has vulnerabilities.
- **Hypervisor vulnerabilities**: Rare but catastrophic — a hypervisor escape
  effectively defeats all VBS protections.

**Practical note for OSEE:**
Many OSEE target environments may not have VBS enabled (especially older hardware
or VMs without nested virtualization). However, understanding VBS is critical because:

1. Modern Windows 11 enables VBS by default on new installations.
2. HVCI-aware exploit chains are increasingly required for real-world applicability.
3. The OSEE exam may test understanding of VBS constraints even if the lab
   environment doesn't enforce all VBS features.

---

## 2. Heap Mitigations

### 2.1 Low Fragmentation Heap (LFH) Randomization

**Background.**
The NT Heap (used by most user-mode Win32 allocations) employs the Low Fragmentation
Heap (LFH) as a front-end allocator for frequently-used size classes. Prior to
hardening, LFH allocations were deterministic — given the same allocation sequence,
chunks would be placed at predictable addresses. This made heap spray and use-after-free
exploitation trivial.

**Randomization (Windows 8+):**

Starting with Windows 8, Microsoft introduced randomization to the LFH:

1. **Bucket order randomization**: When a size class activates LFH, the order in
   which free chunks are returned is randomized using a per-heap seed.
2. **Subsegment randomization**: New LFH subsegments (groups of chunks) have a
   randomized starting offset within their memory region.
3. **Bitmap randomization**: The LFH free bitmap uses randomized scanning, so
   `RtlpLowFragHeapAllocFromContext` does not return chunks in sequential order.

**Impact on exploitation:**

- **Heap spray**: Still works for probability-based attacks (fill enough of the heap
  and a dangling pointer is likely to hit controlled data), but precise chunk
  placement is unreliable.
- **Adjacent chunk overwrites**: Harder because the attacker cannot guarantee which
  chunk is adjacent to the overflowed buffer.
- **Use-after-free**: The replacement allocation may not land in the same slot as
  the freed object. Requires multiple attempts or large-scale spraying.

**LFH internals relevant to exploitation:**

```
HEAP
 └── LFH (front-end)
      └── Bucket[size_class]
           └── Subsegment (UserBlocks)
                ├── _HEAP_USERDATA_HEADER
                │    ├── EncodedOffsets (XOR-encoded)
                │    └── BusyBitmap
                └── UserBlock[0..N] (randomized order)
                     └── _HEAP_ENTRY (encoded header)
```

Each `_HEAP_ENTRY` header is XOR-encoded with a per-heap random cookie (see §2.4).

---

### 2.2 Segment Heap Security Features

**What is Segment Heap?**
Segment Heap is the modern heap allocator used by:

- All UWP/Windows Store apps (since Windows 10 1709).
- System processes (`svchost.exe`, `csrss.exe`, etc.).
- Any process opted-in via Image File Execution Options or manifest.
- **Default for all processes** on Windows 11 (progressively rolled out).

It replaces the NT Heap front-end/back-end architecture with a unified design
consisting of:

1. **Variable Size (VS) allocations**: Small allocations (< 16,368 bytes typically
   go through VS segments with a free-tree based allocator).
2. **Low Fragmentation Heap (LFH) backend**: Activates for hot size classes (similar
   concept to NT Heap LFH but different implementation).
3. **Large blocks**: Backed directly by `NtAllocateVirtualMemory`.
4. **Backend**: Segment-based allocator for medium allocations.

**Security features:**

| Feature | Description |
|---------|-------------|
| **Guard pages** | Random guard pages inserted between segments (see §2.3) |
| **Fast fail on corruption** | Aggressive validation; calls `__fastfail(FAST_FAIL_HEAP_METADATA_CORRUPTION)` on inconsistency — this is **not catchable** by SEH |
| **Encoded free lists** | Free list pointers are XOR-encoded with a per-heap random key |
| **Randomized LFH** | Same LFH randomization as NT Heap, plus additional entropy |
| **No coalescing exploitation** | VS allocator uses a red-black tree instead of linked lists for free chunks, eliminating classic unlink attacks |
| **Block padding** | Allocations include random padding bytes, preventing precise size-based heap shaping |

**Exploitation challenges with Segment Heap:**

1. **Free list corruption**: Encoded pointers mean blind overwrites cause crashes
   (fast fail) rather than arbitrary write primitives.
2. **No classic unlink**: The tree-based free chunk management doesn't have the
   simple `Flink`/`Blink` write-what-where primitive.
3. **Metadata validation**: The allocator aggressively validates chunk metadata
   on every operation.
4. **Less deterministic layout**: More randomness in where allocations land.

**What still works:**

- Overwriting *application data* in adjacent allocations (not heap metadata).
- Large-scale spraying to win probabilistic layout.
- Type confusion / use-after-free with matching size classes.
- Abusing non-heap memory (stack, mapped files, etc.) instead of heap corruption.

---

### 2.3 Heap Guard Pages

**NT Heap guard pages:**

The NT Heap has historically used guard pages (PAGE_NOACCESS) at the end of heap
segments to catch out-of-bounds access. However, these were only at segment
boundaries, leaving large gaps where linear overflows between chunks were undetected.

**Segment Heap guard pages (Windows 10+):**

The Segment Heap inserts guard pages more aggressively:

1. **Between VS segments**: Virtual memory regions allocated for VS segments have
   guard pages at boundaries.
2. **Random insertion within LFH subsegments**: With some probability, LFH
   subsegments include guard pages within the chunk array, limiting how far a
   linear overflow can travel.
3. **Large block guard pages**: Large allocations (backed by `VirtualAlloc`) have
   guard pages before and after the allocation.

**Page Heap (full/standard):**

For debugging and testing, Windows provides Page Heap (enabled via `gflags.exe` or
Application Verifier):

- **Full Page Heap**: Every allocation gets its own page(s) with a guard page
  immediately after. Catches single-byte overflows instantly. Very high memory
  overhead.
- **Standard Page Heap**: Adds guard pages with lower granularity. Less memory
  overhead but may miss small overflows.

Page Heap is not enabled in production, but understanding it is important because:

- OSEE lab machines may have it enabled for specific processes.
- It changes heap layout dramatically and can break exploits designed for normal
  heap behavior.

**Impact on exploitation:**

- Linear heap buffer overflows have a chance of hitting a guard page and causing an
  immediate access violation, rather than silently corrupting adjacent data.
- Exploitation reliability decreases because the attacker cannot predict guard page
  placement.
- Large overflows are more likely to hit a guard page than small overflows.

---

### 2.4 Encoded Heap Pointers and Headers

**NT Heap encoding (`_HEAP_ENTRY` encoding):**

Every NT Heap chunk has a `_HEAP_ENTRY` header (8 bytes on x86, 16 bytes on x64).
Since Windows Vista, this header is XOR-encoded with a per-heap random value
stored in `HEAP.Encoding`:

```
Encoded_Header = Raw_Header XOR HEAP.Encoding
```

This means:

- An attacker who overwrites a `_HEAP_ENTRY` header with arbitrary bytes will
  produce a garbage header after decoding.
- The heap manager validates the decoded header's checksum and triggers a fast-fail
  if it doesn't match.
- To forge a valid header, the attacker needs to leak `HEAP.Encoding` first.

**Specific encoded fields:**

| Field | Purpose | Encoding |
|-------|---------|----------|
| `Size` | Chunk size in allocation units | XOR with `Encoding` |
| `Flags` | BUSY, EXTRA_PRESENT, etc. | XOR with `Encoding` |
| `SmallTagIndex` | Checksum for validation | XOR with `Encoding` |
| `PreviousSize` | Size of previous chunk | XOR with `Encoding` |
| `UnusedBytes` | Padding/unused byte count | XOR with `Encoding` |

**LFH UserData header encoding:**

LFH `_HEAP_USERDATA_HEADER.EncodedOffsets` encodes the subsegment pointer and
other metadata with a separate key. Corruption here is detected during free operations.

**Segment Heap encoding:**

Segment Heap uses a different encoding scheme:

- Free list nodes in the VS allocator encode `Flink`/`Blink` equivalents in the
  red-black tree with a per-heap key.
- LFH block headers use a similar XOR-based encoding.
- The `_SEGMENT_HEAP` structure itself contains the encoding keys; leaking the heap
  base is a prerequisite for forging metadata.

**Exploitation implication:**

To reliably exploit heap metadata corruption, the attacker typically needs:

1. An information leak to obtain the heap base address (which contains encoding keys).
2. Knowledge of the target's heap allocator (NT Heap vs. Segment Heap).
3. Ability to calculate valid encoded headers for forged metadata.

This raises the bar significantly compared to pre-encoding exploitation, where
blind overwrites could achieve arbitrary write primitives.

---

### 2.5 Pool Hardening in Modern Windows

**Kernel pool evolution:**

| Windows Version | Pool Allocator | Key Change |
|-----------------|----------------|------------|
| Windows 7 | Lookaside + pool | Minimal protections |
| Windows 8 | Lookaside + pool | Pool header cookies, NX pool introduced |
| Windows 10 1809 | Lookaside + pool | Safe unlinking for pool free lists |
| Windows 10 2004 | Segment pool begins | `ExAllocatePool2` API; Segment Heap for kernel pool |
| Windows 11 | Full segment pool | NT pool allocator fully replaced by segment pool |

**Modern kernel pool (Segment Pool) hardening:**

1. **Pool header encoding**: `_POOL_HEADER` values (PoolTag, BlockSize, PoolType,
   PreviousSize) are XOR-encoded with a random per-pool cookie. Blind corruption
   is detected on free.

2. **Safe unlinking**: Free list operations validate `Flink->Blink == Entry` and
   `Blink->Flink == Entry` before performing unlink. Corruption triggers
   `BAD_POOL_HEADER` (bugcheck 0x19) or `SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION`
   (bugcheck 0xC1).

3. **Pool quota pointer protection**: The `ProcessBilled` field (used for quota
   tracking) is encoded. Corrupting this field no longer provides arbitrary
   decrement primitives.

4. **Delayed free**: Freed pool blocks are not immediately returned to the free list.
   Instead, they go through a "pending free" list and are eventually coalesced.
   This adds temporal randomness to UAF exploitation:

   ```
   ExFreePoolWithTag(ptr, tag)
     → ExpInsertPoolTracker (deferred)
     → Block added to pending-free list
     → Eventually freed by pool trim thread
   ```

5. **NonPagedPoolNx enforcement**: `ExAllocatePool2` with `POOL_FLAG_NON_PAGED`
   always allocates from NX pool. The old `ExAllocatePoolWithTag(NonPagedPool, ...)`
   still works but allocates from the legacy (potentially executable) pool — drivers
   using this are flagged by WHQL and blocked under HVCI.

6. **Special Pool**: Can be enabled per-tag via `gflags` or Driver Verifier. Places
   each allocation on its own page with a guard page. Catches overflows and
   use-after-free. Very high overhead — testing only.

7. **CRT pool allocations in drivers**: Modern WDF drivers can use `WdfMemoryCreate`
   which internally uses `ExAllocatePool2` with appropriate flags, ensuring NX and
   pool hardening by default.

**Kernel pool spray in the modern era:**

Despite hardening, pool spray remains a critical exploitation technique because:

- The attacker controls *data content* of pool allocations (not just metadata).
- Objects sprayed into adjacent chunks allow overwriting application data fields
  (function pointers, object references, security descriptors).
- Named pipe attributes, I/O completion ports, and `NtCreateEvent` objects are
  common spray primitives that remain effective.
- The pool hardening protects *metadata* (headers, free lists) but not *object data*.

---

## 3. Advanced Bypass Techniques

### 3.1 Data-Only Attacks and JIT-ROP

**Data-only attacks.**

Data-only attacks modify program data (not code, not control flow metadata) to achieve
the attacker's objective without ever diverting execution. Because they don't corrupt
return addresses, function pointers, vtable entries, or other CFI-relevant data,
they bypass:

- DEP/NX (no shellcode execution needed)
- SMEP/SMAP (no user-mode code/data access needed)
- CFI/CET (no control-flow hijack)
- HVCI (no page permission changes)
- Stack canaries (no stack corruption)

**Common data-only targets in Windows kernel:**

| Target | Data Modified | Effect |
|--------|---------------|--------|
| `TOKEN.Privileges` | `_SEP_TOKEN_PRIVILEGES.Enabled` bitmap | Grant all privileges to attacker process |
| `TOKEN.TokenId` / `TOKEN.AuthenticationId` | LUID values | Impersonate SYSTEM token |
| `EPROCESS.Token` | `_EX_FAST_REF` pointer | Replace process token with SYSTEM token |
| `EPROCESS.UniqueProcessId` | PID value | Confuse security tooling |
| `EPROCESS.Protection` | `_PS_PROTECTION` | Elevate process to PPL |
| `ACL/SecurityDescriptor` | ACE entries | Grant access to privileged objects |
| `OBJECT_HEADER.SecurityDescriptor` | SD pointer | Replace security descriptor on any object |

**Example — Token privilege escalation (data-only):**

```
1. Leak address of current process EPROCESS (e.g., via NtQuerySystemInformation)
2. Read EPROCESS.Token (EX_FAST_REF — mask low 4 bits for RefCnt)
3. At TOKEN + offset_of(Privileges.Present): write 0xFFFFFFFFFFFFFFFF
4. At TOKEN + offset_of(Privileges.Enabled): write 0xFFFFFFFFFFFFFFFF
5. Now current process has all privileges (SeDebugPrivilege, SeTcbPrivilege, etc.)
6. Open SYSTEM process, duplicate its token, impersonate → full SYSTEM
```

No code execution. No control flow corruption. No ROP chain. This defeats every
mitigation except integrity-level checks and KDP (if the token is KDP-protected,
which is not the default).

**JIT-ROP (Just-In-Time Return-Oriented Programming):**

JIT-ROP is a technique for constructing ROP chains at runtime by:

1. Obtaining a memory read primitive.
2. Scanning loaded modules in memory to discover gadget locations on-the-fly.
3. Building the ROP chain dynamically, defeating ASLR without a static info leak.

In the **Windows kernel context**, JIT-ROP means:

1. Use a kernel read primitive to locate `ntoskrnl.exe` base (scan for MZ/PE header).
2. Parse the export table or scan code sections for useful gadgets.
3. Construct a ROP chain in a kernel-accessible buffer (pool allocation, stack).
4. Trigger the chain via a controlled function pointer or stack pivot.

This bypasses ASLR/kASLR effectively because the attacker discovers addresses at
runtime. However, it requires a **reliable kernel read primitive**, which is itself
a significant capability.

**JIT-ROP under HVCI:**

HVCI does not block JIT-ROP because:
- ROP gadgets are in legitimate RX code pages.
- No new executable pages are created.
- The hypervisor cannot distinguish between legitimate returns and ROP gadgets.

Only CET/Shadow Stacks (§4.1) can mitigate ROP, and even then only the `RET`-based
variant (JOP/COP chains may still work).

---

### 3.2 WARP Techniques

**Windows Address Resolution Protocol (WARP)** is a research term used to describe
techniques for resolving kernel virtual addresses from user mode, effectively
defeating kASLR. WARP techniques exploit various information disclosure paths that
leak kernel pointers to user mode.

**Historical WARP vectors (many now patched):**

| Vector | Description | Patched? |
|--------|-------------|----------|
| `NtQuerySystemInformation(SystemModuleInformation)` | Returns kernel module base addresses | Restricted (Admin only since RS4) |
| `NtQuerySystemInformation(SystemBigPoolInformation)` | Returns pool allocation addresses | Patched (sanitized) |
| `NtQuerySystemInformation(SystemHandleInformation)` | Returns kernel object addresses | Restricted (non-low-IL) |
| `EnumDeviceDrivers()` / `GetDeviceDriverBaseNameA()` | Returns driver base addresses | Restricted |
| `HEVD`-style info leak | Driver-specific bugs that leak stack/pool addresses | Bug-dependent |
| Timer resolution side channel | Timing side channels to infer kernel addresses | Partially mitigated |
| TSX side channels | Intel TSX-based side channels for kASLR defeat | Intel disabled TSX (microcode) |
| Prefetch side channels | CPU prefetch timing to detect kernel page mappings | Partially mitigated |
| Exception-based probing | Use page faults to map kernel address space layout | Mitigated by KVAS |

**Still viable (as of 2025-2026):**

1. **Admin-level `NtQuerySystemInformation`**: If the attacker has local admin, most
   `SystemInformation` classes still return kernel pointers. Since OSEE scenarios
   typically start with some level of local access, this remains relevant.

2. **Driver-specific info leaks**: Vulnerable drivers (especially third-party) may
   leak kernel addresses through IOCTLs, output buffers, or error paths.

3. **Pool tag scanning**: With a kernel read primitive at a known address (e.g., from
   a partial leak), scanning for pool tags can locate specific kernel objects.

4. **GDI/User object kernel addresses**: Historically, `GdiSharedHandleTable` exposed
   kernel addresses for GDI objects. This is largely patched since RS4, but some
   residual leaks may exist in specific configurations.

5. **ETW (Event Tracing for Windows)**: Certain ETW providers emit kernel addresses
   in event payloads. Requires appropriate group membership.

**Practical approach for OSEE:**

```
Phase 1: Enumerate available info leak surfaces
  → Check NtQuerySystemInformation access
  → Scan for vulnerable IOCTLs in loaded drivers
  → Check for uninitialized memory in output buffers

Phase 2: Leak kernel base / target object addresses
  → ntoskrnl base for ROP gadget resolution
  → EPROCESS address for token manipulation
  → Pool addresses for heap spray validation

Phase 3: Use leaked addresses to construct exploit
  → Calculate offsets to target structures
  → Build data-only payload or ROP chain
```

---

### 3.3 BYOVD — Bring Your Own Vulnerable Driver

**Concept.**
BYOVD is a technique where the attacker loads a legitimate, signed, but vulnerable
kernel driver to gain kernel read/write/execute primitives. Because the driver is
validly signed by Microsoft or a third party, it passes Driver Signature Enforcement
(DSE), HVCI code integrity checks, and most endpoint protection.

**Why BYOVD is powerful:**

1. **Bypasses DSE**: The driver has a valid Authenticode signature.
2. **Bypasses HVCI**: HVCI allows loading signed, WHQL-certified drivers. Many
   vulnerable drivers meet this bar.
3. **Provides kernel primitives**: The driver's vulnerability (arbitrary
   read/write/execute via IOCTL) becomes the attacker's kernel primitive.
4. **Persistent and reliable**: No exploitation of OS bugs needed. The driver's
   bug *is* the exploitation primitive.

**Common BYOVD drivers (public examples):**

| Driver | Vendor | Vulnerability |
|--------|--------|---------------|
| `RTCore64.sys` | MSI/Micro-Star | Arbitrary physical memory R/W via IOCTL |
| `DBUtil_2_3.sys` | Dell | Arbitrary physical memory R/W |
| `AsIO64.sys` | ASUS | Arbitrary physical memory R/W |
| `gdrv.sys` | GIGABYTE | Arbitrary physical memory R/W |
| `MsIo64.sys` | MSI | Arbitrary physical memory R/W via mapped physical memory |
| `cpuz141.sys` | CPUID | Physical memory read |
| `WinRing0x64.sys` | OpenLibSys | Port I/O, MSR, physical memory access |
| `ene.sys` | ENE Technology | Arbitrary physical memory R/W |
| `HW.sys` | Passmark | Physical memory R/W, Port I/O |

**Typical BYOVD exploitation flow:**

```
1. Drop vulnerable driver to disk (e.g., RTCore64.sys)
2. Create/start kernel service to load the driver
   sc create evil binPath= C:\path\RTCore64.sys type= kernel
   sc start evil
3. Open device handle (\\.\RTCore64)
4. Use IOCTL to read/write kernel memory:
   a. Read ntoskrnl base address
   b. Locate current EPROCESS
   c. Copy SYSTEM token to current process
5. Profit: Current process now runs as SYSTEM
6. (Optional) Unload driver and clean up
```

**Mitigations against BYOVD:**

1. **Microsoft Vulnerable Driver Blocklist**: Microsoft maintains a blocklist of
   known-vulnerable drivers (`Microsoft.Vulnerable.Driver.Blocklist`). Enforced via
   WDAC (Windows Defender Application Control) or HVCI. Updated periodically but
   lags behind new discoveries.

2. **HVCI driver compatibility requirements**: HVCI blocks drivers that:
   - Allocate RWX pool memory.
   - Map executable user-mode memory.
   - Exploit deprecated pool APIs unsafely.
   However, HVCI does **not** block drivers that simply expose arbitrary physical
   memory R/W via IOCTLs — this is a "feature" of the driver, not a code integrity
   violation.

3. **WDAC policies**: Enterprises can deploy strict WDAC policies that only allow
   a whitelist of known-good drivers. This is the most effective mitigation but
   operationally complex.

4. **Attestation Signing**: Since Windows 10 1607, new kernel drivers must be
   submitted to Microsoft for attestation signing. However, this does not catch
   vulnerabilities — only ensures the driver was submitted by an identified developer.

**OSEE relevance:**
BYOVD is a real-world technique used by APT groups (Lazarus, FIN7, Turla,
RobinHood ransomware, BlackByte, Cuba ransomware, etc.). Understanding it is critical
for OSEE because:

- It demonstrates that kernel exploitation doesn't always require a 0-day.
- It bypasses most mitigations in a single step.
- Defensive teams must understand the technique to detect and block it.
- The exam may involve scenarios where driver-level access is the initial vector.

---

### 3.4 PTE Manipulation for SMEP/SMAP Bypass

**Core concept.**
Page Table Entries (PTEs) control memory permissions (R/W/X) and the User/Supervisor
bit that SMEP and SMAP enforce. If an attacker can modify PTEs, they can:

1. **Mark a user-mode page as Supervisor**: Bypasses both SMEP (execution) and
   SMAP (access) because the CPU now sees the page as kernel memory.
2. **Mark a kernel data page as Executable**: Bypasses kernel DEP/NX, allowing
   shellcode execution from a pool allocation or stack buffer.
3. **Create arbitrary virtual-to-physical mappings**: Map any physical address into
   the kernel's virtual address space with any permissions.

**x64 page table structure:**

```
CR3 (PML4 base)
 └── PML4E (Page Map Level 4 Entry)     — bits 47:39 of VA
      └── PDPTE (Page Directory Pointer Table Entry) — bits 38:30 of VA
           └── PDE (Page Directory Entry)             — bits 29:21 of VA
                └── PTE (Page Table Entry)            — bits 20:12 of VA
                     └── Physical page + permissions
```

**PTE bit layout (x64):**

```
Bit(s)  Name              SMEP/SMAP relevance
0       Present (P)       Must be set for valid mapping
1       Read/Write (R/W)  Write permission
2       User/Supervisor   0 = Supervisor; 1 = User ← SMEP/SMAP key bit
3       PWT               Page write-through
4       PCD               Page cache disable
5       Accessed (A)      Set by CPU on access
6       Dirty (D)         Set by CPU on write
7       PAT/PS            Page size (for PDE: 2MB page)
11:8    Available          Software use
12      (part of PFN)
51:12   Page Frame Number  Physical address >> 12
62:52   Available          Software use
63      NX (No Execute)   1 = not executable ← DEP key bit
```

**SMEP bypass via PTE U/S bit flip:**

```
Given: User-mode shellcode page at VA 0x000001234000
       PTE for this VA is at kernel VA 0xFFFFF680xxxx (self-referencing PTE base)

Attack:
1. Locate PTE for the shellcode page:
   PTE_VA = PTE_BASE + (VA >> 12) * 8
   (PTE_BASE is at a fixed offset relative to the PML4 self-reference entry)

2. Read current PTE value (using kernel read primitive):
   old_pte = *(ULONG64*)PTE_VA
   // old_pte has bit 2 set (User) and bit 63 clear (executable)

3. Clear U/S bit (bit 2) to mark as Supervisor:
   new_pte = old_pte & ~(1ULL << 2)  // Clear User bit → Supervisor

4. Write modified PTE (using kernel write primitive):
   *(ULONG64*)PTE_VA = new_pte

5. Flush TLB for the page:
   // Either trigger a context switch or use INVLPG
   // Or: write CR3 with its current value (flushes entire TLB)

6. Execute shellcode:
   // Redirect kernel execution to 0x000001234000
   // CPU sees Supervisor page → SMEP allows execution
```

**Finding the PTE base address:**

In older Windows versions (pre-RS1), the PTE base was at a fixed address
(`0xFFFFF68000000000`). Since Windows 10 RS1, the PTE base is **randomized at
boot time**.

Techniques to find the PTE base:

1. **Leak via `MiGetPteAddress`**: The kernel function `MiGetPteAddress` contains
   a hardcoded reference to the PTE base. Disassembling this function (with a kernel
   read primitive) reveals the base:

   ```asm
   MiGetPteAddress:
     mov rax, rcx
     shr rax, 9
     mov rcx, 0x7FFFFFFFF8  ; mask
     and rax, rcx
     mov rcx, 0xFFFFA48000000000  ; ← PTE base (randomized)
     add rax, rcx
     ret
   ```

2. **Scan for PML4 self-reference entry**: Walk the PML4 table (base = CR3 physical
   address) looking for an entry that points back to the PML4's own physical page.
   The index of this entry determines the PTE base.

3. **`NtQuerySystemInformation(SystemPteInformation)`**: On some versions, this
   leaks relevant PTE information to admin callers.

**HVCI complication:**

Under HVCI, the hypervisor validates PTE modifications. Specifically:

- The hypervisor intercepts writes to page tables that would create new executable
  mappings for pages that were not previously marked executable by the secure kernel.
- Clearing the NX bit on a data page is **blocked**.
- Clearing the U/S bit may or may not be blocked depending on the specific HVCI
  implementation and Windows version. Research has shown inconsistencies in
  enforcement — the hypervisor primarily watches for *executable* permission
  changes, not necessarily *supervisor/user* changes.

**Practical note:**
PTE manipulation remains one of the most powerful bypass techniques. Even under
HVCI, combining PTE manipulation with data-only attacks (where no new executable
pages are needed) is effective. The PTE manipulation itself serves as a building
block for mapping arbitrary physical memory, which enables full kernel memory access.

---

### 3.5 Page Table Manipulation Techniques

Beyond the basic SMEP bypass, page table manipulation enables several advanced
attack primitives:

**3.5.1 Physical memory mapping (arbitrary read/write):**

By creating new PTEs that map arbitrary physical pages into the kernel virtual
address space, the attacker gains a **physical memory read/write primitive**. This
is equivalent to what BYOVD drivers like `RTCore64.sys` provide.

```
Attack flow:
1. Find a free PTE slot (or overwrite an existing mapping).
2. Compute the PTE value for the target physical page:
   new_pte = (target_physical_address & ~0xFFF) | PTE_VALID | PTE_RW | PTE_DIRTY
3. Write the PTE value using a kernel write primitive.
4. Access the corresponding virtual address — now maps to target_physical_address.
5. Repeat for any physical address.
```

This effectively gives the attacker DMA-like access to all of physical memory from
a kernel write primitive.

**3.5.2 Self-referencing PML4 abuse:**

Windows uses a self-referencing PML4 entry to provide access to the page table
hierarchy itself. The self-reference entry is the PML4 entry that points to the
PML4 page's own physical address. This creates a recursive virtual address mapping:

```
PTE_BASE          = 0xFFFFA48000000000  (randomized)
PDE_BASE          = PTE_BASE + (PTE_BASE >> 12) * 8
PDPTE_BASE        = PTE_BASE + (PDE_BASE >> 12) * 8
PML4_BASE         = PTE_BASE + (PDPTE_BASE >> 12) * 8
```

If the attacker finds PTE_BASE (by leaking MiGetPteAddress), they can compute the
virtual address of any page table entry at any level and modify it.

**3.5.3 Creating "shadow" kernel mappings:**

An attacker can create additional mappings for the same physical page with different
permissions. For example:

1. Find the physical page backing a kernel code page (RX).
2. Create a new PTE mapping the same physical page as RW (no NX bit issue because
   the new mapping is data-only — the attacker writes to it but doesn't execute
   from the new mapping).
3. Modify the code via the RW mapping.
4. Execute the modified code via the original RX mapping.

This bypasses W^X enforcement at the PTE level because the attacker uses two
different virtual addresses with different permissions for the same physical page.

**HVCI defense**: The hypervisor maintains its own SLAT/EPT which tracks physical
page permissions independently. If HVCI sees a physical page as RX in the EPT, all
VTL 0 mappings of that page are RX — the shadow mapping technique fails under HVCI.

**3.5.4 Cross-process page table manipulation:**

By modifying another process's page tables, the attacker can:

- Map kernel memory into user-mode address space (for user-mode access to kernel data).
- Map one process's memory into another process.
- Create shared memory regions without using section objects.

This is useful for inter-process attacks where the attacker has kernel write but
wants to interact with user-mode code (e.g., injecting into a target process).

---

### 3.6 Token Manipulation Without Code Execution

**Overview.**
Token manipulation is the most common endgame for Windows kernel privilege
escalation exploits. A `TOKEN` object controls the security context of a process:
its privileges, group memberships, integrity level, and session information.

**Key TOKEN fields (offsets vary by Windows build):**

```
struct _TOKEN {
    ...
    +0x040  _LUID             TokenId;
    +0x048  _LUID             AuthenticationId;
    +0x050  _LUID             ParentTokenId;
    +0x058  _LARGE_INTEGER    ExpirationTime;
    +0x060  _ERESOURCE*       TokenLock;
    +0x068  _SEP_TOKEN_PRIVILEGES  Privileges;    // ← Target for privilege escalation
    +0x080  _SEP_AUDIT_POLICY AuditPolicy;
    +0x098  ULONG             SessionId;
    +0x09C  ULONG             UserAndGroupCount;
    +0x0A0  ULONG             RestrictedSidCount;
    +0x0A4  ULONG             VariableLength;
    +0x0A8  ULONG             DynamicCharged;
    +0x0AC  ULONG             DynamicAvailable;
    +0x0B0  ULONG             DefaultOwnerIndex;
    +0x0B8  _SID_AND_ATTRIBUTES* UserAndGroups;   // ← Target for group membership
    ...
    +0x0D0  _SID*             PrimaryGroup;
    +0x0D8  ULONG*            DynamicPart;
    +0x0E0  _ACL*             DefaultDacl;
    +0x0E8  _TOKEN_TYPE       TokenType;
    +0x0EC  ULONG             ImpersonationLevel; // ← SecurityDelegation = 3
    ...
    +0x4B8  _SID_AND_ATTRIBUTES* Capabilities;
    +0x4C8  _SID*             TrustLevelSid;
    ...
};
```

**Technique 1 — Privilege bitmap overwrite:**

The `_SEP_TOKEN_PRIVILEGES` structure contains three bitmaps:

```
struct _SEP_TOKEN_PRIVILEGES {
    ULONG64 Present;     // Which privileges exist in the token
    ULONG64 Enabled;     // Which privileges are currently enabled
    ULONG64 EnabledByDefault;  // Which are enabled by default
};
```

Setting all three to `0xFFFFFFFFFFFFFFFF` grants every possible privilege. With
`SeDebugPrivilege`, the attacker can open any process. With `SeTcbPrivilege`, the
attacker can set any token on a thread.

**Requirements:** Kernel write primitive of at least 24 bytes (3 × ULONG64) at a
known address. No code execution needed.

**Technique 2 — Token swapping (EPROCESS.Token overwrite):**

```
EPROCESS.Token is an EX_FAST_REF:
  token_value = actual_TOKEN_pointer | reference_count (low 4 bits)

Attack:
1. Leak SYSTEM process EPROCESS address (PID 4, always present).
2. Read SYSTEM EPROCESS.Token value.
3. Read current process EPROCESS address.
4. Overwrite current EPROCESS.Token with SYSTEM's token value.
5. Current process now runs with SYSTEM token.

Complication: Reference counting. The old token leaks a reference, and the new
token gains an extra reference. For a one-shot privilege escalation, this is
acceptable (the system won't crash immediately).
```

**Technique 3 — SID manipulation:**

Modify the `UserAndGroups` array entries to add the current user to privileged
groups (Administrators, SYSTEM, etc.). Requires knowing the SID structure layout
in memory.

**Technique 4 — Integrity level manipulation:**

The `TOKEN.IntegrityLevelIndex` points to a `SID_AND_ATTRIBUTES` entry that
determines the process's integrity level. Changing the SID to the SYSTEM integrity
SID (`S-1-16-16384`) bypasses mandatory integrity controls.

**Why these techniques are powerful:**

- **No code execution**: Pure data modification.
- **No control flow hijack**: CFI, CET, and shadow stacks are irrelevant.
- **No executable page needed**: DEP, SMEP, HVCI don't apply.
- **Minimal footprint**: Only a few bytes of kernel memory are modified.
- **Hard to detect**: No anomalous code execution patterns; the token change
  looks like a normal kernel operation at the instruction level.

**Mitigations that can help:**

- **KDP**: If the token is protected by Kernel Data Protection, the physical page
  is read-only in the EPT and cannot be modified from VTL 0. However, general-purpose
  token allocations are typically not KDP-protected.
- **Token integrity checks**: Some security products periodically validate token
  consistency (check for impossible privilege combinations, SID mismatches, etc.).
- **Protected Process Light (PPL)**: PPL processes have tokens that are subject to
  additional validation, but the token itself is still writable from Ring 0.
- **Credential Guard**: Protects credential-related secrets in VTL 1, but not
  the token structure in VTL 0 pool memory.

---

## 4. Emerging Mitigations — Windows 11+

### 4.1 Kernel CET and Shadow Stacks

**What is CET?**
Intel Control-flow Enforcement Technology (CET) consists of two components:

1. **Shadow Stacks (SS)**: A second, read-only (from software perspective) stack
   that stores only return addresses. On every `CALL`, the CPU pushes the return
   address to both the regular stack and the shadow stack. On every `RET`, the CPU
   pops from both and compares — a mismatch triggers `#CP` (Control Protection
   Exception), which the OS converts to a bugcheck or process termination.

2. **Indirect Branch Tracking (IBT)**: On indirect `JMP` or `CALL`, the CPU
   expects the target to be an `ENDBRANCH` (`ENDBR64`/`ENDBR32`) instruction.
   If the target is not `ENDBRANCH`, a `#CP` is raised. This is a coarse-grained
   forward-edge CFI.

**Windows implementation:**

- **User-mode CET**: Available since Windows 10 2004 for user-mode processes
  (opt-in via `SetProcessMitigationPolicy` or image header flags). Hardware
  enforcement on supported Intel (Tiger Lake+) and AMD (Zen 3+) CPUs.

- **Kernel-mode CET**: Windows 11 22H2+ supports kernel shadow stacks on compatible
  hardware. The Secure Kernel (VTL 1) manages shadow stack pages, ensuring VTL 0
  code cannot modify them.

**Shadow stack details:**

```
Regular stack:              Shadow stack:
┌──────────────┐           ┌──────────────┐
│ local vars   │           │              │
│ saved RBP    │           │              │
│ return addr  │ ←──must──→│ return addr  │  ← CPU compares on RET
│ arguments    │  match    │              │
└──────────────┘           └──────────────┘
```

Shadow stack pages:
- Use a new page table bit (Dirty=1, Writable=0) that the CPU interprets as
  "shadow stack page."
- Normal `MOV` instructions **cannot** write to shadow stack pages.
- Only `CALL`, `RET`, `RSTORSSP`, and `SAVEPREVSSP` can modify shadow stacks.
- Under VBS, VTL 1 protects shadow stack PTEs from VTL 0 modification.

**Impact on exploitation:**

| Technique | CET Impact |
|-----------|------------|
| Classic ROP (`RET`-based) | **Blocked** — shadow stack mismatch on each `RET` |
| JOP (Jump-Oriented Programming) | **Partially mitigated** — IBT requires `ENDBR64` targets |
| COP (Call-Oriented Programming) | **Partially mitigated** — must target `ENDBR64` functions |
| Data-only attacks | **Not affected** — no control flow hijack |
| Sigreturn-oriented | **Blocked** — `RSTORSSP` can't freely position shadow stack |
| Stack pivot + ROP | **Blocked** — shadow stack doesn't pivot with regular stack |
| Kernel callback abuse | **Not affected** if kernel legitimately calls the function |

**CET bypass research (active area):**

1. **`ENDBR64` gadgets**: IBT only checks that the target starts with `ENDBR64`.
   Any function in the kernel that starts with `ENDBR64` (which is most of them
   post-CET compilation) is a valid indirect call target. This is coarse-grained
   CFI and allows calling any function with controlled arguments.

2. **Counterfeit Objects / COOP**: Create fake C++ objects with vtables pointing
   to legitimate `ENDBR64` functions. Chain virtual calls to achieve arbitrary
   computation. Each call is to a valid `ENDBR64` entry, so IBT allows it. Each
   return goes back to the legitimate call site, so shadow stack is satisfied.

3. **Signal/Exception frame manipulation**: If the attacker can corrupt the saved
   context (e.g., `CONTEXT` structure) used by exception handlers, they can set
   `RIP` to an arbitrary value when the context is restored. The shadow stack
   may be restored from the token as well, but research is ongoing regarding
   edge cases.

4. **`RSTORSSP` misuse**: The `RSTORSSP` instruction restores a shadow stack
   pointer from a "restore token" in memory. If the attacker can forge a valid
   restore token, they can redirect the shadow stack.

---

### 4.2 Secured-Core PC Features

**What is Secured-Core PC?**
Secured-Core PC is a Microsoft specification for enterprise hardware that mandates
a comprehensive set of security features. It goes beyond standard Windows security
by requiring hardware and firmware protections.

**Required features:**

| Feature | Description |
|---------|-------------|
| **DRTM (Dynamic Root of Trust for Measurement)** | Intel TXT or AMD SKINIT — establishes a trusted execution environment without relying on BIOS/UEFI firmware integrity |
| **VBS and HVCI** | Mandatory — must be enabled and enforced |
| **System Guard Secure Launch** | Measures firmware and boot components via DRTM; detects firmware tampering |
| **Kernel DMA Protection** | IOMMU (VT-d / AMD-Vi) enabled by default; blocks DMA attacks from Thunderbolt/PCIe devices |
| **Firmware protection** | UEFI firmware must support Secure Boot with strict policy, firmware update authentication, and flash write protection |
| **SMM isolation** | System Management Mode is isolated/measured to prevent SMM-based attacks |
| **Credential Guard** | Enabled by default |
| **BitLocker** | Hardware-backed encryption with TPM 2.0 |

**Impact on exploitation:**

1. **Eliminates firmware-level attacks**: DRTM-based secure launch means even a
   compromised UEFI cannot tamper with the measured boot path. Bootkits are
   detected.

2. **Blocks physical attacks**: Kernel DMA Protection (IOMMU enforcement) blocks
   DMA attacks via Thunderbolt/PCIe, which were previously a reliable way to
   bypass all software mitigations.

3. **Hardens the boot chain**: System Guard Secure Launch provides attestation
   evidence that the system booted cleanly. Tampered systems can be detected by
   management infrastructure (Intune, SCCM).

4. **Forces software-only exploitation**: On a Secured-Core PC, the attacker
   must exploit a software vulnerability (kernel bug, driver bug, or privilege
   escalation chain) without hardware assistance.

---

### 4.3 Smart App Control

**What it is.**
Smart App Control (SAC), introduced in Windows 11 22H2, is a cloud-backed code
integrity system that blocks untrusted applications and scripts. It operates in
two modes:

1. **Evaluation mode**: Monitors application launches silently to assess
   compatibility impact.
2. **Enforcement mode**: Blocks execution of:
   - Applications without a reputation score (unknown to Microsoft's cloud service).
   - Applications with known-bad reputation.
   - Scripts (PowerShell, VBScript, JavaScript) that are not properly signed or
     have unknown reputation.
   - MSI installers without established reputation.

**Technical implementation:**

- SAC is a Windows Defender Application Control (WDAC) policy with cloud-based
  intelligence.
- It uses the Code Integrity (CI) subsystem (`ci.dll`, `CiValidateImageHeader`)
  to evaluate executables before loading.
- For scripts, it hooks Windows Script Host and PowerShell's AMSI (Antimalware
  Scan Interface) integration.
- The reputation database is maintained by Microsoft's Intelligent Security
  Graph (ISG), which aggregates telemetry from billions of Windows endpoints.

**Impact on exploitation:**

- **Blocks exploit delivery**: An attacker cannot simply drop and run an unsigned
  exploit binary. The executable must either have a valid signature from a trusted
  publisher or must have accumulated sufficient reputation.
- **Limits living-off-the-land**: Restricts script execution, reducing the
  effectiveness of PowerShell-based exploit chains.
- **Not a kernel mitigation**: SAC does not protect against kernel exploits that
  don't require launching a new user-mode executable (e.g., kernel exploits
  triggered via IOCTLs from a signed application).
- **Bypassable in evaluation mode**: SAC in evaluation mode does not block anything.
- **Bypass via signed executables**: Using legitimate, signed executables as exploit
  delivery vehicles (e.g., signed Python interpreter loading an exploit script)
  remains viable.

---

### 4.4 Enhanced Hardware Security Features

**Intel and AMD security features relevant to Windows 11+:**

**4.4.1 Intel Processor Enhancements:**

| Feature | Description | Windows Integration |
|---------|-------------|---------------------|
| **CET (SS + IBT)** | Shadow stacks and indirect branch tracking | Kernel CET in Win11 22H2+ |
| **TME (Total Memory Encryption)** | AES encryption of all DRAM contents | Transparent to OS; mitigates cold boot attacks |
| **TME-MK (Multi-Key)** | Per-VM or per-domain memory encryption keys | Used by Hyper-V for VM isolation |
| **TDX (Trust Domain Extensions)** | Hardware-isolated VM execution | Azure confidential computing |
| **HLAT (Hardware Linear Address Translation)** | Hardware-enforced supervisor-mode paging restrictions | Accelerates SMAP/SMEP-like enforcement |
| **LAM (Linear Address Masking)** | Allows metadata in pointer upper bits | Not yet security-relevant; may affect exploitation pointer layout |

**4.4.2 AMD Processor Enhancements:**

| Feature | Description | Windows Integration |
|---------|-------------|---------------------|
| **Shadow Stacks** | AMD's CET-compatible implementation (Zen 3+) | Same as Intel CET |
| **SEV (Secure Encrypted Virtualization)** | Memory encryption for VMs | Azure confidential computing |
| **SEV-SNP** | SEV with integrity protection (Secure Nested Paging) | Prevents hypervisor tampering with VM memory |
| **SME (Secure Memory Encryption)** | Full DRAM encryption | Similar to Intel TME |

**4.4.3 ARM64 (Windows on ARM):**

Windows 11 on ARM64 (Qualcomm Snapdragon, Apple M-series via compatibility layer)
introduces a different mitigation landscape:

| Feature | Description |
|---------|-------------|
| **Pointer Authentication (PAC)** | Cryptographic MAC on pointers (return addresses, function pointers) — corrupted pointers fail authentication |
| **Branch Target Identification (BTI)** | ARM's equivalent of Intel IBT — restricts indirect branch targets |
| **Memory Tagging Extension (MTE)** | Hardware memory tagging — detects use-after-free, out-of-bounds access with low overhead |
| **TrustZone** | ARM's hardware security enclave (similar role to VBS/VTL 1) |

**PAC is particularly noteworthy** because it provides per-pointer cryptographic
integrity. Unlike shadow stacks (which only protect return addresses on the stack),
PAC can protect any pointer stored anywhere in memory. This makes data-only attacks
on function pointers significantly harder — each pointer has a cryptographic tag
that must be valid for the pointer to be used.

---

## 5. The Arms Race — How Mitigations Shape OSEE

### 5.1 Evolution of OSEE-Relevant Exploitation

The OSEE certification (formerly AWE — Advanced Windows Exploitation) has evolved
to track the changing mitigation landscape:

**Era 1 — Pre-Mitigation (Windows XP/2003):**
- Stack buffer overflows → direct shellcode execution
- Heap overflows → unlink arbitrary write → overwrite function pointer
- No DEP, no ASLR, no SMEP
- OSEE content (AWE era): Focus on reliable exploitation mechanics

**Era 2 — Early Mitigations (Windows 7/8):**
- DEP → ROP chains
- ASLR → Information leaks
- SMEP → PTE manipulation or kernel ROP
- Heap hardening → Application data corruption instead of metadata
- OSEE content: Heavy focus on ROP chain construction, info leak techniques

**Era 3 — Modern Mitigations (Windows 10/11):**
- HVCI → Data-only attacks or ROP-only exploitation
- CET → Data-only attacks, COOP, or ENDBR64-constrained gadgets
- VBS → Exploitation limited to VTL 0 scope
- Pool hardening → Refined spray techniques, new pool primitives
- KDP → Target non-KDP-protected structures
- kASLR hardening → Driver-specific info leaks, timing side channels
- OSEE content: Data-only attacks, BYOVD, advanced pool manipulation

### 5.2 The "Primitive Pyramid"

Modern Windows exploitation follows a layered approach where each mitigation forces
the attacker up the complexity pyramid:

```
                    ╱╲
                   ╱  ╲
                  ╱Goal╲         ← SYSTEM shell, arbitrary code execution,
                 ╱      ╲          persistence, etc.
                ╱────────╲
               ╱ Token    ╲      ← Data-only: Modify token, SID, privileges
              ╱ Manip.     ╲       (bypasses HVCI, CET, CFI)
             ╱──────────────╲
            ╱ Arbitrary R/W  ╲   ← Kernel memory read + write primitive
           ╱                  ╲    (needed for ASLR bypass + data-only attack)
          ╱────────────────────╲
         ╱ Controlled Write     ╲ ← OOB write, use-after-free, pool overflow
        ╱ (relative or arbitrary)╲  (often the initial vulnerability primitive)
       ╱────────────────────────────╲
      ╱ Information Leak              ╲ ← Kernel address disclosure
     ╱ (kASLR bypass, object address)  ╲  (NtQuerySystemInformation, driver bug)
    ╱────────────────────────────────────╲
   ╱ Vulnerability Trigger                ╲ ← Bug in kernel or driver
  ╱ (OOB, UAF, type confusion, race cond.) ╲
 ╱──────────────────────────────────────────────╲
╱ Access / Attack Surface                         ╲ ← Local user, network service,
╱ (IOCTL, syscall, file format, network protocol)  ╲  browser renderer, etc.
╱────────────────────────────────────────────────────╲
```

### 5.3 Key Trends Shaping Future OSEE Content

**1. Data-only attacks are the new default.**
As CET and HVCI become ubiquitous, code-reuse attacks (ROP, JOP) become harder or
impossible. Data-only attacks — modifying kernel data structures to escalate
privileges — bypass all code-integrity and control-flow mitigations. OSEE
increasingly emphasizes understanding kernel object internals over shellcode writing.

**2. The "info leak" is the hardest part.**
Modern mitigations assume the attacker has code execution capability and focus on
preventing it. But all data-only attacks require knowing *where* to write. With
kASLR hardening, finding kernel addresses becomes the primary challenge. Expect OSEE
to emphasize creative information disclosure techniques.

**3. Pool spray is evolving, not dying.**
Kernel pool hardening makes metadata corruption impractical, but data-content
corruption via adjacent allocations remains viable. The spray primitives change
(new objects, new APIs) but the fundamental technique persists. OSEE must track
which spray objects work on which Windows versions.

**4. BYOVD is the "easy mode" that defenders must understand.**
In real-world operations, attackers often skip 0-day exploitation entirely by loading
a known-vulnerable signed driver. OSEE may increasingly test the candidate's ability
to use (and defend against) BYOVD as a practical primitive.

**5. Hypervisor-level attacks become relevant.**
As VBS raises the bar for VTL 0 exploitation, advanced attackers will target the
hypervisor itself. Hypervisor escape is an emerging topic — though likely beyond
current OSEE scope, awareness is essential.

**6. Hardware diversity complicates exploitation.**
With Windows running on x64 (Intel + AMD) and ARM64, exploits may need to account
for different hardware security features (CET vs. PAC/BTI, TME vs. SME). OSEE
currently focuses on x64, but ARM-specific techniques may eventually appear.

### 5.4 Practical Mitigation Bypass Matrix

**Given a kernel write primitive on modern Windows 11 with all mitigations enabled,
what can the attacker still do?**

| Mitigation | Status | Attacker's Path |
|------------|--------|-----------------|
| SMEP | Enabled | Don't execute user-mode code; use kernel ROP or data-only |
| SMAP | Enabled | Don't access user-mode data; spray kernel pool instead |
| Kernel DEP/NX | Enabled | Don't write shellcode; use ROP or data-only |
| HVCI | Enabled | Don't create RWX pages; use ROP or data-only |
| kASLR | Enabled | Need info leak; use WARP technique or driver bug |
| CET Shadow Stacks | Enabled | Don't use ROP; use data-only exclusively |
| CET IBT | Enabled | If calling functions, target ENDBR64 entries |
| KDP | Partial | Target non-KDP-protected structures (most TOKEN objects) |
| Pool hardening | Enabled | Corrupt object data, not metadata |
| Driver blocklist | Partial | Use a driver not (yet) on the blocklist |

**The surviving attack chain (fully hardened system):**

```
1. Trigger vulnerability     → Controlled out-of-bounds write in kernel pool
2. Info leak                 → Leak kernel object address via driver IOCTL side channel
3. Pool spray                → Place target TOKEN object adjacent to overflow
4. Data-only overwrite       → Modify TOKEN.Privileges to grant all privileges
5. Profit                    → Process now has SeDebugPrivilege → full SYSTEM
```

No code execution. No ROP. No PTE manipulation. No SMEP/SMAP/HVCI/CET bypass
needed. Pure data corruption. This is the future of Windows kernel exploitation and
the direction OSEE is heading.

---

## Appendix A — Quick Reference: Mitigation Verification Commands

```
:: Check VBS/HVCI status
msinfo32  → Look for "Virtualization-based security" = Running
powershell: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

:: Check SMEP/SMAP in WinDbg
kd> r cr4
kd> .formats cr4_value   (check bits 20 and 21)

:: Check CET support
kd> !cpuinfo            (look for CET_SS, CET_IBT flags)
:: Or from user mode:
powershell: (Get-ComputerInfo).CsPCSystemType  (limited info)

:: Check kernel pool allocator
kd> !poolused           (shows pool tag usage)
kd> dt nt!_SEGMENT_HEAP (verify segment heap structures exist)

:: Check loaded driver signing
driverquery /v | findstr /i "signed"

:: Check WDAC/Smart App Control policy
powershell: Get-CimInstance -ClassName MSFT_WDACPolicy -Namespace root\Microsoft\Windows\CI

:: Check Secured-Core features
msinfo32 → System Summary → "System Guard" entries
```

## Appendix B — Key Structures and Offsets (Windows 11 23H2 x64)

> **Warning**: Offsets change between Windows builds. Always verify with
> `dt nt!_EPROCESS`, `dt nt!_TOKEN`, etc., in WinDbg for the specific target build.

```
_EPROCESS:
  +0x440  UniqueProcessId
  +0x448  ActiveProcessLinks (_LIST_ENTRY)
  +0x4B8  Token (_EX_FAST_REF)
  +0x548  ImageFileName (15 bytes)
  +0x87A  Protection (_PS_PROTECTION)

_TOKEN:
  +0x040  TokenId (_LUID)
  +0x048  AuthenticationId (_LUID)
  +0x068  Privileges (_SEP_TOKEN_PRIVILEGES)
        +0x068  Present (ULONG64)
        +0x070  Enabled (ULONG64)
        +0x078  EnabledByDefault (ULONG64)
  +0x098  SessionId (ULONG)
  +0x0D0  IntegrityLevelIndex (ULONG)

_SEP_TOKEN_PRIVILEGES:
  +0x000  Present (ULONG64)
  +0x008  Enabled (ULONG64)
  +0x010  EnabledByDefault (ULONG64)
```

## Appendix C — References and Further Reading

1. **Microsoft: Virtualization-based Security** — https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs
2. **Microsoft: Kernel Data Protection** — https://www.microsoft.com/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
3. **Microsoft: Secured-Core PC** — https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure
4. **Intel CET Specification** — https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html
5. **Alex Ionescu: Windows Internals, Part 1 & 2** (7th Edition) — Essential reference for kernel structures
6. **Connor McGarr: Exploit Development Research** — HVCI bypass, PTE manipulation techniques
7. **Morten Schenk: "Taking Windows 10 Kernel Exploitation to the Next Level"** — kASLR bypass, PTE base randomization
8. **j00ru (Mateusz Jurczyk): Windows kernel security research** — Pool internals, heap hardening
9. **Microsoft: HVCI and VBS** — https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard
10. **Project Zero: Windows kernel vulnerability research** — Various blog posts on NT kernel bug classes

---

*Document version: 1.0 — April 2026*
*Applicable to: Windows 10 21H2 through Windows 11 24H2*
*OSEE Exam Relevance: High — covers all major mitigation bypass strategies tested in current curriculum*
