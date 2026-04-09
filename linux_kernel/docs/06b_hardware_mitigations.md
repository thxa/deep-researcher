# 6b. Kernel Mitigation Mechanisms: Hardware Mitigations and CONFIG Options

## Table of Contents

1. [Intel CET: Shadow Stacks and Indirect Branch Tracking (IBT)](#1-intel-cet-control-flow-enforcement-technology)
2. [ARM Pointer Authentication (PAC) and Branch Target Identification (BTI)](#2-arm-pointer-authentication-pac-and-branch-target-identification-bti)
3. [ARM Memory Tagging Extension (MTE)](#3-arm-memory-tagging-extension-mte)
4. [x86 SMEP/SMAP Hardware Implementation](#4-x86-smepsmap-hardware-implementation)
5. [Intel PKS (Protection Keys for Supervisor)](#5-intel-pks-protection-keys-for-supervisor)
6. [The Lockdown LSM and Kernel Lockdown Mode](#6-the-lockdown-lsm-and-kernel-lockdown-mode)
7. [Kernel Config Hardening Options](#7-kernel-config-hardening-options)
8. [GCC/Clang Kernel Hardening Plugins](#8-gccclang-kernel-hardening-plugins)
9. [Mitigation Comparison Matrix](#9-mitigation-comparison-matrix)
10. [Distribution-Specific Kernel Hardening](#10-distribution-specific-kernel-hardening)

---

## 1. Intel CET: Control-flow Enforcement Technology

Intel Control-flow Enforcement Technology (CET) is a hardware-based defense against
control-flow hijacking attacks such as Return-Oriented Programming (ROP) and
Jump-Oriented Programming (JOP). CET consists of two independent sub-features:
**Shadow Stacks** and **Indirect Branch Tracking (IBT)**.

### 1.1 Shadow Stacks

A shadow stack is a secondary, hardware-managed stack that stores only return
addresses. The CPU maintains this stack in parallel with the traditional software
stack.

**Operational Mechanism:**

1. On a `CALL` instruction, the processor pushes the return address onto **both**
   the normal stack and the shadow stack.
2. On a `RET` instruction, the processor pops the return address from the shadow
   stack and compares it with the value popped from the normal stack.
3. If the two addresses **differ**, the processor raises a **Control-Protection
   Fault (`#CP`, vector 21)**, which the OS handles as a security violation.

**Shadow Stack Page Table Properties:**

Shadow stack memory pages have a unique combination of page-table bits: they are
marked as **read-only** (`R/W=0`) and **dirty** (`D=1`). This otherwise-invalid
combination is repurposed by the hardware to identify shadow stack pages. Any
attempt to write to these pages via normal store instructions is blocked; only
shadow-stack-specific instructions (`CALL`, `RET`, `WRSS`, `RSTORSSP`, etc.) can
modify them.

**Linux Kernel Support:**

- **Kconfig**: `CONFIG_X86_USER_SHADOW_STACK` — enables userspace shadow stack support.
- **Kernel-space shadow stacks** are not yet supported in the upstream kernel as of
  6.x; only userspace shadow stacks are available.
- Shadow stack can be disabled at boot with `nousershstk`.
- An application's shadow stack is allocated at a fixed size of
  `MIN(RLIMIT_STACK, 4 GB)`.
- Shadow stack PTEs are copied on `fork()` with the dirty bit cleared in both
  parent and child, triggering copy-on-write on the next shadow stack access.
- On `exec()`, shadow stack features are disabled by the kernel, and userspace
  (typically the dynamic linker) re-enables them via `arch_prctl()`.

**Userspace API:**

```c
arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK);   // Enable shadow stack
arch_prctl(ARCH_SHSTK_DISABLE, ARCH_SHSTK_SHSTK);  // Disable shadow stack
arch_prctl(ARCH_SHSTK_LOCK, features_mask);         // Lock features
arch_prctl(ARCH_SHSTK_STATUS, &status);             // Query status
```

Status can be inspected at runtime:
- `/proc/cpuinfo`: look for `user_shstk`
- `/proc/<PID>/status`: shows `x86_Thread_features: shstk wrss`

**Signal Handling:**

When a signal is delivered, the pre-signal shadow stack pointer (SSP) is pushed
onto the shadow stack in a special **token format** with bit 63 set. On
`sigreturn`, the kernel verifies and restores this token, preventing attackers
from using signal handlers to bypass shadow stack protections.

**WRSS (Write to Shadow Stack):**

The `WRSS` instruction allows explicit writes to shadow stack memory. This is
needed for certain runtime operations (e.g., longjmp, coroutines). `WRSS` can
only be enabled when shadow stacks are active and is automatically disabled if
shadow stacks are disabled.

**Build Requirements:**

- Binutils >= 2.29 or LLVM >= 6.0
- Hardware: Intel 12th Gen (Alder Lake) and later processors

### 1.2 Indirect Branch Tracking (IBT)

IBT protects against JOP/COP attacks by ensuring that indirect `CALL` and `JMP`
instructions can only land on **intended targets** marked with the `ENDBR64`
(or `ENDBR32`) instruction.

**Operational Mechanism:**

1. When IBT is enabled, the processor enters a special **WAIT_FOR_ENDBRANCH**
   state after executing an indirect `CALL` or `JMP`.
2. If the next instruction executed is **not** `ENDBR64`/`ENDBR32`, the processor
   raises a `#CP` fault.
3. `ENDBR` instructions are encoded in the `NOP` space, so they are
   backward-compatible — older CPUs simply treat them as no-ops.

**Linux Kernel Support:**

- **Kconfig**: `CONFIG_X86_KERNEL_IBT` — enables IBT for the kernel itself.
- The kernel is compiled with `-fcf-protection=branch` (or equivalent Clang flags).
- The compiler inserts `ENDBR64` at the beginning of every function and at
  every address-taken code location.

**FineIBT (Fine-Grained IBT):**

Linux v6.2+ introduced FineIBT, which combines IBT with Clang's kCFI (kernel
Control Flow Integrity) to create a more fine-grained forward-edge CFI scheme:

- Each indirect call site embeds a **type hash** before the call.
- Each valid target starts with an `ENDBR64` followed by a hash-comparison
  sequence.
- If the caller's type hash does not match the callee's expected hash, execution
  is halted.
- Boot parameter: `cfi=fineibt` (auto-detected when IBT hardware is present).
- `cfi=paranoid` adds caller-side hash verification under FRED (Flexible Return
  and Event Delivery).

**Boot Parameters:**

```
cfi=auto       # Use FineIBT if IBT available, otherwise kCFI (default)
cfi=off        # Disable CFI entirely
cfi=kcfi       # Use kCFI only (disable FineIBT)
cfi=fineibt    # Force FineIBT even without IBT hardware
cfi=norand     # Disable hash randomization
cfi=warn       # Don't enforce, only warn
```

### 1.3 Security Impact for Exploit Development

| Attack Type | Shadow Stack | IBT/FineIBT |
|---|---|---|
| Classic ROP (overwrite return address) | **Blocked** | Not applicable |
| JOP/COP (indirect call/jmp hijack) | Not applicable | **Blocked** |
| ROP with info leak to read shadow stack | Shadow stack is not readable via normal loads | N/A |
| Overwriting shadow stack directly | Requires `WRSS`; pages are hardware-protected | N/A |
| Landing on any `ENDBR` gadget | N/A | Possible (coarse-grained); FineIBT restricts further |

**Bypass Considerations:**

- Shadow stacks fundamentally prevent classic ROP by making return address
  corruption detectable. An attacker would need a separate write primitive
  targeting the shadow stack pages, which requires `WRSS`-capable code or a
  kernel vulnerability that can manipulate page tables.
- IBT alone is coarse-grained: any `ENDBR64` instruction is a valid target.
  FineIBT significantly narrows this by adding type-based validation.
- Combining shadow stacks (backward-edge) with FineIBT (forward-edge) provides
  comprehensive CFI coverage.

---

## 2. ARM Pointer Authentication (PAC) and Branch Target Identification (BTI)

### 2.1 Pointer Authentication (PAC)

Introduced in ARMv8.3, Pointer Authentication adds hardware-enforced integrity
checks to pointers using cryptographic **Pointer Authentication Codes (PACs)**.

**Architecture Overview:**

- A PAC is a cryptographic signature computed from three inputs:
  1. The pointer value itself
  2. A 64-bit **context value** (typically the stack pointer or zero)
  3. A 128-bit **secret key** held in system registers
- The PAC is stored in the **upper unused bits** of the pointer (the bits between
  the virtual address size and bit 55 for userspace, or to bit 63 for kernel).
- PAC width = 55 - VA_SIZE bits. With a 48-bit VA, PAC is 7 bits wide. With a
  39-bit VA, PAC is 16 bits wide.

**Five Hardware Keys:**

| Key | Purpose | Instructions |
|---|---|---|
| APIAKey | Instruction address auth (A key) | PACIA, AUTIA, RETAA |
| APIBKey | Instruction address auth (B key) | PACIB, AUTIB, RETAB |
| APDAKey | Data address auth (A key) | PACDA, AUTDA |
| APDBKey | Data address auth (B key) | PACDB, AUTDB |
| APGAKey | Generic authentication | PACGA |

**Signing and Verification Flow:**

```
Function Prologue:   PACIASP        ; Sign LR with SP as context using IA key
                                    ; PAC bits inserted into upper bits of LR
... function body ...
Function Epilogue:   AUTIASP        ; Verify PAC on LR
                     RET            ; Return (faults if PAC was invalid)
```

If `AUTIASP` fails verification, it flips bits in the pointer to create an
invalid address, causing a **Data Abort** or **Instruction Abort** on the
subsequent dereference.

**Linux Kernel Support:**

- **Kconfig**: `CONFIG_ARM64_PTR_AUTH` — enables PAC support for userspace.
- **Kconfig**: `CONFIG_ARM64_PTR_AUTH_KERNEL` — compiles the kernel with PAC
  instructions in HINT space, protecting function returns.
- Keys are randomly assigned to each process at `exec()` time.
- Keys are shared across all threads within a process and preserved across `fork()`.
- Keys can be re-randomized via `prctl(PR_PAC_RESET_KEYS, mask)`.
- Individual keys can be disabled via `prctl(PR_PAC_SET_ENABLED_KEYS, ...)`.
- Presence advertised via `HWCAP_PACA` (address auth) and `HWCAP_PACG` (generic auth).
- Boot parameter: `arm64.nopauth` disables PAC unconditionally.

**HINT-Space Encoding:**

PAC instructions used in the kernel (`PACIASP`, `AUTIASP`, etc.) are allocated
from the ARM **HINT encoding space**. On processors without PAC support, these
instructions execute as **NOPs**, providing transparent backward compatibility.
This means a PAC-compiled kernel runs correctly (but without protection) on
older hardware.

**Security Properties:**

- PAC transforms control-flow hijacking into a probabilistic attack. An attacker
  must either:
  - Guess the correct PAC value (probability depends on PAC width: 2^-7 with
    48-bit VA to 2^-16 with 39-bit VA).
  - Leak the secret key (stored in `APIAKeyLo_EL1`/`APIAKeyHi_EL1` system
    registers, accessible only at EL1+).
  - Find a PAC signing oracle (code that signs attacker-controlled data with the
    correct key and context).
- The use of the SP as context for `PACIASP` prevents cross-stack PAC reuse.

### 2.2 Branch Target Identification (BTI)

Introduced in ARMv8.5, BTI is the ARM equivalent of Intel IBT — a forward-edge
control-flow integrity mechanism.

**Operational Mechanism:**

1. Memory pages can be mapped with the **GP (Guarded Page)** attribute via the
   page table entries (the `GP` bit in the PTE Block/Page descriptor).
2. On guarded pages, indirect branches (`BR`, `BLR`) must land on a **BTI
   instruction** (`BTI c`, `BTI j`, `BTI jc`, or `BTI`).
3. If an indirect branch lands on a non-BTI instruction on a guarded page, the
   processor generates a **Branch Target Exception**.
4. BTI instructions are encoded in the HINT space and execute as NOPs on hardware
   without BTI support.

**BTI Variants:**

| Instruction | Valid landing for |
|---|---|
| `BTI c` | `BLR` (call via register) |
| `BTI j` | `BR` (jump via register) |
| `BTI jc` | Both `BLR` and `BR` |
| `BTI` | No indirect branches (only explicit `BTI` checks) |

**Linux Kernel Support:**

- **Kconfig**: `CONFIG_ARM64_BTI_KERNEL` — builds the kernel with BTI.
- The kernel text pages are mapped with the GP bit set.
- GCC/Clang use `-mbranch-protection=bti` or `-mbranch-protection=standard`
  (which enables both BTI and PAC).
- Boot parameter: `arm64.nobti` disables BTI unconditionally.
- For userspace, the ELF `GNU_PROPERTY_AARCH64_FEATURE_1_BTI` flag indicates
  BTI compatibility; the dynamic linker maps such binaries with GP-enabled pages.

### 2.3 ARM Guarded Control Stack (GCS)

ARMv9.4-A introduces **Guarded Control Stack (GCS)**, ARM's equivalent of Intel
shadow stacks. GCS provides hardware-enforced return address protection:

- A separate hardware-managed stack stores return addresses.
- `BL` (branch-with-link) pushes the return address to both the regular stack
  (LR) and the GCS.
- `RET` compares the GCS entry with LR; a mismatch triggers a GCS Data Abort.
- GCS pages have a dedicated memory type and are not writable by normal stores.
- **Kconfig**: `CONFIG_ARM64_GCS` — enables GCS support.
- Boot parameter: `arm64.nogcs` disables GCS unconditionally.

---

## 3. ARM Memory Tagging Extension (MTE)

### 3.1 Architecture Overview

MTE, introduced in ARMv8.5, is a hardware memory safety mechanism that detects
**use-after-free**, **buffer overflow**, and other spatial/temporal memory safety
bugs at runtime with low overhead.

MTE extends ARM's existing **Top Byte Ignore (TBI)** feature. TBI allows the
top byte of a 64-bit virtual address to carry metadata while still being used
for address translation. MTE uses **4 bits** (bits 59-56) of this top byte as
a **logical tag**.

**Key Concepts:**

- **Logical Tag**: 4-bit tag embedded in a pointer (bits 59-56). Set by software
  using dedicated instructions.
- **Allocation Tag**: 4-bit tag associated with each aligned **16-byte granule**
  of physical memory. Stored in dedicated tag storage (separate from the data
  memory, using ~3.125% additional memory).
- **Tag Check**: On every memory access, the hardware compares the logical tag
  in the pointer with the allocation tag of the accessed memory granule.
- **Tag Granule**: 16 bytes — the minimum alignment and size for tagged memory
  regions.

**MTE Instructions:**

| Instruction | Purpose |
|---|---|
| `IRG Xd, Xn` | Insert Random Tag — generates a random 4-bit tag |
| `STG Xt, [Xn]` | Store Allocation Tag — sets the tag for a 16-byte granule |
| `LDG Xt, [Xn]` | Load Allocation Tag — reads the tag for a granule |
| `ADDG/SUBG` | Add/subtract with tag generation |
| `ST2G` | Store tag for 2 consecutive granules (32 bytes) |
| `STZ2G` | Store tag and zero 2 consecutive granules |
| `STZG` | Store tag and zero 1 granule |

### 3.2 Tag Check Fault Modes

MTE supports three configurable modes for handling tag mismatches, selectable
per-thread:

| Mode | Behavior | Performance | Use Case |
|---|---|---|---|
| **Synchronous** | Immediate `SIGSEGV` (`SEGV_MTESERR`) with precise fault address | Highest overhead (~1-16%) | Debugging, development |
| **Asynchronous** | Deferred `SIGSEGV` (`SEGV_MTEAERR`), address unknown | Lowest overhead (~1-3%) | Production, security hardening |
| **Asymmetric** | Sync for reads, async for writes | Middle ground | Balanced deployment |

**Configuration via prctl:**

```c
// Enable synchronous mode
prctl(PR_SET_TAGGED_ADDR_CTRL,
      PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
      (0xfffe << PR_MTE_TAG_SHIFT),  // Allow all non-zero tags
      0, 0, 0);
```

**Per-CPU Preferred Mode:**

System administrators can set a preferred tag-checking mode per CPU:
```
echo sync > /sys/devices/system/cpu/cpu0/mte_tcf_preferred
```

When a task requests multiple modes (e.g., both sync and async), the kernel
selects the CPU's preferred mode if it's in the task's set, otherwise falls back
in order: async > asymm > sync.

### 3.3 Kernel Integration

**Memory Mapping:**

- Userspace allocates tagged memory via `mmap()` or `mprotect()` with the
  `PROT_MTE` flag.
- Only `MAP_ANONYMOUS` and RAM-backed file mappings (`tmpfs`, `memfd`) support
  `PROT_MTE`.
- Allocation tags are initialized to 0 on first mapping and preserved on
  copy-on-write.
- The `PROT_MTE` attribute **cannot** be removed by `mprotect()` once set.

**KASAN Integration (HW_TAGS Mode):**

MTE serves as the hardware backend for **Hardware Tag-Based KASAN**
(`CONFIG_KASAN_HW_TAGS`). This mode:

- Uses MTE instructions to tag slab, page_alloc, and vmalloc allocations.
- Assigns random tags on allocation and sets a reserved tag (`0xFE`) on free.
- Detects use-after-free and out-of-bounds accesses with hardware checking.
- Has significantly lower overhead than software KASAN modes (~5% CPU, ~5% memory).
- Is suitable for **production use** as a security mitigation.
- Boot parameters: `kasan=on/off`, `kasan.mode=sync/async/asymm`.

**Debugging Support:**

- `PTRACE_PEEKMTETAGS` / `PTRACE_POKEMTETAGS` allow a debugger to read/write
  allocation tags in a tracee's address space.
- Tags are represented as one 4-bit tag per byte in the tracer's buffer, with
  each tag corresponding to a 16-byte granule.
- Core dumps include `PT_AARCH64_MEMTAG_MTE` segments containing allocation tags.

### 3.4 Security Implications

**Strengths:**

- Detects heap buffer overflows at granularity of 16 bytes.
- Detects use-after-free when freed memory is re-tagged.
- Probabilistic detection: 4-bit tag = 1/16 chance of false negative per access.
  Combined with tag randomization over many allocations, the probability of
  undetected exploitation drops rapidly.
- In async mode, overhead is low enough for production deployment on
  Android/ChromeOS (typically 1-3% CPU overhead).

**Limitations:**

- 16-byte granularity means overflows of fewer than 16 bytes within the same
  granule are undetectable.
- 4-bit tags provide only 16 distinct values; collisions are possible.
- In-band metadata: an attacker who can forge pointers with arbitrary tags
  can bypass the check (requires control of the top byte).
- Async mode does not provide a precise fault address, complicating debugging.
- Only ARM processors with MTE support (Cortex-A/X series from ~2021+, though
  production silicon availability has been limited).

---

## 4. x86 SMEP/SMAP Hardware Implementation

### 4.1 Supervisor Mode Execution Prevention (SMEP)

SMEP prevents the kernel (ring 0) from executing code located in user-space
(ring 3) memory pages.

**Hardware Implementation:**

- Controlled by **bit 20 of CR4** (`CR4.SMEP`).
- When enabled, any attempt to fetch instructions from a page with the **User
  (U/S=1)** bit set while running at supervisor privilege level (CPL < 3)
  generates a **Page Fault (`#PF`)** with a specific error code.
- Introduced in Intel Ivy Bridge (3rd Gen Core) processors (2012).
- Also supported on AMD processors starting with Zen (2017).

**Page Fault Error Code:**

When SMEP triggers, the page fault error code has:
- Bit 4 (I/D) = 1 (instruction fetch)
- Bit 2 (U/S) = 1 (user-mode page)
- Bit 0 (P) = 1 (page present)

**Linux Kernel Support:**

- Enabled by default when hardware support is detected.
- The kernel checks CPUID leaf 7, subleaf 0, EBX bit 7 for SMEP support.
- `setup_smep()` in `arch/x86/kernel/cpu/common.c` sets `CR4.SMEP`.
- SMEP can be disabled (for debugging) via the `nosmep` boot parameter.
- `CONFIG_X86_SMEP` is not a separate Kconfig option — SMEP is enabled
  unconditionally on supporting hardware.

**Security Impact:**

Before SMEP, the canonical exploit technique was:
1. Corrupt a kernel function pointer to point to user-space memory.
2. Map shellcode at that user-space address.
3. Trigger the corrupted pointer, executing attacker-controlled code in ring 0.

SMEP completely eliminates this class of attack by preventing instruction fetch
from user pages while in kernel mode.

### 4.2 Supervisor Mode Access Prevention (SMAP)

SMAP prevents the kernel from **reading or writing** user-space memory except
through designated accessor functions (`copy_to_user()`, `copy_from_user()`,
`get_user()`, `put_user()`).

**Hardware Implementation:**

- Controlled by **bit 21 of CR4** (`CR4.SMAP`).
- When enabled, any data access (read or write) to a page with `U/S=1` from
  CPL < 3 generates a `#PF`, **unless** the **AC (Alignment Check) flag** in
  EFLAGS is set.
- The `STAC` (Set AC Flag) and `CLAC` (Clear AC Flag) instructions provide
  fast toggling of SMAP enforcement.
- Introduced in Intel Broadwell (5th Gen Core) processors (2014).
- Also supported on AMD Zen and later.

**Kernel Access Pattern:**

```
# In copy_from_user() implementation:
STAC                    ; Temporarily disable SMAP (set AC flag)
... perform user memory access ...
CLAC                    ; Re-enable SMAP (clear AC flag)
```

The kernel wraps all legitimate user-memory accesses with `STAC`/`CLAC` pairs.
The `STAC`/`CLAC` instructions are privileged — they can only be executed at
CPL 0, so user-space cannot disable SMAP.

**Linux Kernel Support:**

- Enabled by default when hardware support is detected.
- Detected via CPUID leaf 7, subleaf 0, EBX bit 20.
- Can be disabled via `nosmap` boot parameter.
- All user-access primitives (`get_user`, `put_user`, `copy_to_user`,
  `copy_from_user`, `__uaccess_begin`/`__uaccess_end`) are instrumented with
  `STAC`/`CLAC`.

**Security Impact:**

SMAP prevents exploitation techniques where an attacker places crafted data
structures in user-space memory and tricks the kernel into treating them as
kernel data:

- Prevents kernel from reading fake structures from controlled user memory.
- Prevents kernel from writing to user memory outside of explicit copy operations.
- Combined with SMEP, ensures that user-space memory is fully isolated from
  unintended kernel access.

### 4.3 ARM Equivalents: PXN and PAN

| x86 Feature | ARM Equivalent | Description |
|---|---|---|
| SMEP | PXN (Privileged Execute Never) | Prevents EL1 execution of EL0-mapped pages |
| SMAP | PAN (Privileged Access Never) | Prevents EL1 data access to EL0-mapped pages |

- PXN: Controlled via page table descriptor bits. Present since ARMv7.
- PAN: Introduced in ARMv8.1. Controlled via `PSTATE.PAN` bit. The `AT` and
  `LDTR`/`STTR` instructions bypass PAN for legitimate user access.
- Software PAN emulation existed for ARMv8.0 via domain-based access controls.
- `CONFIG_ARM64_PAN` enables PAN support in the kernel.

---

## 5. Intel PKS (Protection Keys for Supervisor)

### 5.1 Overview

Protection Keys for Supervisor (PKS) extends Intel's Memory Protection Keys
architecture to supervisor-mode (ring 0) memory. It provides a fast, per-CPU
mechanism to restrict kernel access to specific memory regions without modifying
page tables.

PKS builds on the existing **Protection Keys for Userspace (PKU/MPK)** feature
(introduced in Skylake) but applies to supervisor-mode pages.

### 5.2 Hardware Mechanism

**Page Table Integration:**

- Each page table entry (PTE) for supervisor pages contains a 4-bit **protection
  key** field (bits 62:59 of the PTE), providing 16 possible key domains
  (PKey 0-15).
- PKey 0 is the default key and typically carries no additional restrictions.

**PKRS Register:**

- The **IA32_PKRS MSR** (MSR 0x6E1) is a per-CPU 32-bit register containing
  two bits (Access Disable, Write Disable) for each of the 16 protection key
  domains.
- Format: `[AD15][WD15]...[AD1][WD1][AD0][WD0]`
  - AD (Access Disable): When set, any read or write using a pointer to a page
    with this pkey triggers a `#PF`.
  - WD (Write Disable): When set, writes are blocked but reads are allowed.
- The `WRMSR`/`RDMSR` instructions are used to modify PKRS (unlike PKU which
  uses the fast `WRPKRU` instruction).

**Enforcement Flow:**

1. The MMU performs normal page-table-based access checks.
2. If the access passes normal checks and the page is a supervisor page, the
   MMU extracts the 4-bit pkey from the PTE.
3. The MMU checks the corresponding AD/WD bits in the PKRS register.
4. If the access violates the PKRS policy, a `#PF` is generated with a
   protection-key-violation error code (bit 5 set in the PF error code).

### 5.3 Use Cases in the Linux Kernel

**Intended Applications:**

1. **Protecting sensitive kernel data structures**: Memory holding cryptographic
   keys, credential structures, or security-critical data can be assigned a
   dedicated pkey and have access disabled by default. Access is enabled only
   in the specific code paths that need it.

2. **Hardening the slab allocator**: Sensitive slab caches can use PKS-protected
   pages, with access gated per-CPU.

3. **Reducing the blast radius of kernel vulnerabilities**: Even if an attacker
   gains arbitrary write capability, they cannot access PKS-protected regions
   unless they also control the PKRS MSR.

**Kernel Integration Status:**

- PKS support patches have been posted by Intel developers (primarily by Ira Weiny
  and Rick Edgecombe).
- The base infrastructure for PKS (`CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS`) has
  been integrated into recent kernel versions.
- `pks_mk_noaccess(pkey)` / `pks_mk_readonly(pkey)` / `pks_mk_readwrite(pkey)`
  provide the kernel API for managing supervisor pkey access.

### 5.4 Comparison: PKU vs PKS

| Feature | PKU (User) | PKS (Supervisor) |
|---|---|---|
| Protects | User-mode pages | Supervisor-mode pages |
| Control Register | PKRU (via WRPKRU — ~20 cycle) | IA32_PKRS (via WRMSR — ~100 cycle) |
| Accessible from | Ring 3 (user-space can modify!) | Ring 0 only |
| Key space | 16 keys (4-bit pkey in PTE) | 16 keys (4-bit pkey in PTE) |
| Security model | Application self-sandboxing (not a security boundary vs. malicious code) | Kernel-internal compartmentalization |

**Critical difference**: PKU is not a security boundary because user-space code
can freely call `WRPKRU` to change its own permissions. PKS uses `WRMSR`, which
is a privileged instruction, making it a true security enforcement mechanism.

---

## 6. The Lockdown LSM and Kernel Lockdown Mode

### 6.1 Overview

The **Lockdown LSM** is a Linux Security Module that restricts kernel functionality
to prevent a privileged user (including root) from modifying the running kernel
or extracting confidential kernel data. It defends against scenarios where a
compromised root account attempts to install rootkits, tamper with kernel code,
or exfiltrate sensitive kernel memory.

### 6.2 Lockdown Modes

Lockdown has two levels, selectable at boot or enforced by the UEFI Secure Boot
chain:

**Integrity Mode** (`lockdown=integrity`):

Prevents modification of the running kernel. Blocks:
- Loading unsigned kernel modules (when `CONFIG_MODULE_SIG_FORCE` is active)
- Writing to `/dev/mem`, `/dev/kmem`, `/dev/port`
- Access to ioperm/iopl
- Raw access to PCI BARs via sysfs
- Use of kexec to load unsigned kernels (`kexec_load()` is blocked;
  `kexec_file_load()` with signature verification is allowed)
- Writing to MSRs via `/dev/cpu/*/msr`
- Modifying ACPI tables via `acpi_rsdp=` or custom ACPI table overrides
- Direct hardware access via `pcmcia_socket` CIS overrides
- Writing to debugfs

**Confidentiality Mode** (`lockdown=confidentiality`):

Includes all integrity protections plus blocks information leaks:
- Reading `/dev/mem`, `/dev/kmem`
- Reading kernel memory via `/proc/kcore`
- Reading physical memory via `/dev/port`
- BPF reads of kernel memory
- Perf event access to kernel addresses
- Kprobes/ftrace access that could leak kernel data
- Raw PCI config space reads via sysfs

### 6.3 Activation Mechanisms

1. **Boot parameter**: `lockdown=integrity` or `lockdown=confidentiality`
2. **UEFI Secure Boot**: When the system boots via UEFI Secure Boot, the kernel
   can automatically enter integrity mode if `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT`
   is enabled.
3. **Sysfs interface**: `/sys/kernel/security/lockdown` can be written to escalate
   (but not de-escalate) the lockdown level at runtime.
4. **LSM stacking**: Lockdown operates as an LSM that can be stacked with other
   security modules (SELinux, AppArmor, etc.).

### 6.4 Kconfig Options

```
CONFIG_SECURITY_LOCKDOWN_LSM=y           # Enable lockdown LSM
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y     # Enable lockdown before init
CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y   # Auto-lockdown with Secure Boot
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y    # Always integrity mode
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y  # Always confidentiality mode
```

### 6.5 Security Implications

**What Lockdown Prevents (from an attacker's perspective):**

- Loading a malicious kernel module as root (requires signed modules)
- Using `/dev/mem` to patch kernel code at runtime
- Using kexec to boot a tampered kernel
- Using eBPF, perf, or kprobes to read kernel secrets
- Modifying MSRs to disable security features (e.g., clearing CR4.SMEP)

**What Lockdown Does NOT Prevent:**

- Exploitation of kernel vulnerabilities from user-space
- Privilege escalation within the kernel's own code paths
- Attacks that do not require loading code or reading kernel memory

**Relationship to Secure Boot:**

Lockdown is the kernel-side enforcement that completes the UEFI Secure Boot
chain of trust. Without lockdown, Secure Boot only ensures the kernel image
itself is signed — root can still modify the kernel at runtime via `/dev/mem`,
module loading, or kexec.

---

## 7. Kernel Config Hardening Options

### 7.1 RANDSTRUCT (`CONFIG_RANDSTRUCT`)

Randomizes the layout of selected kernel structures at **compile time** to make
exploits dependent on a specific structure layout non-portable between builds.

**Mechanism:**

- A GCC plugin or Clang pass reorders the fields of structures annotated with
  `__randomize_layout`.
- A per-build random seed determines the layout; different builds produce
  different layouts.
- Performance-sensitive structures use `__randomize_layout` selectively.
- `__no_randomize_layout` opts out specific structures.

**Key Structures Randomized:**

Structures historically critical for exploitation are randomized:
- `task_struct`
- `cred`
- `file_operations`, `inode_operations`
- Various net, filesystem, and driver operation structures

**Kconfig:**

```
CONFIG_RANDSTRUCT=y         # Full randomization (GCC plugin or Clang)
CONFIG_RANDSTRUCT_PERFORMANCE=y  # Performance-aware randomization
                                  # (groups types that pack well together)
```

**Impact on Exploitation:**

- An exploit that relies on knowing the offset of `cred->uid` within
  `struct cred` will break across different kernel builds.
- Forces attackers to either develop info-leak primitives to discover the layout
  or target specific binary builds.
- Does not protect against attacks that do not depend on structure offsets.

### 7.2 FORTIFY_SOURCE (`CONFIG_FORTIFY_SOURCE`)

Compile-time and runtime buffer overflow detection for common memory and string
functions.

**Mechanism:**

- At compile time, the compiler calculates the known sizes of destination buffers.
- Calls to `memcpy()`, `memset()`, `strcpy()`, `strncpy()`, `strlcpy()`,
  `strcat()`, `sprintf()`, `snprintf()`, and other string/memory functions are
  replaced with fortified versions.
- If the compiler can **prove** the copy will overflow at compile time, it
  generates a **build error**.
- If the sizes are only known at runtime, a runtime check is inserted that
  calls `__fortify_panic()` on overflow.

**Kconfig:**

```
CONFIG_FORTIFY_SOURCE=y
```

**Kernel-Specific Enhancements:**

The kernel's FORTIFY_SOURCE implementation (`include/linux/fortify-string.h`) goes
beyond the glibc version:
- Distinguishes between `p`-level (pointer-based size) and `s`-level
  (structure-based size) checks.
- Handles `memcpy()` across flexible array members.
- Detects reads beyond the end of source buffers (not just destination overflows).
- Works with `__builtin_object_size()` at multiple levels.

### 7.3 UBSAN (`CONFIG_UBSAN`)

The **Undefined Behavior Sanitizer** detects undefined behavior at runtime via
compiler instrumentation.

**Detected Conditions:**

- Integer overflow (signed and unsigned)
- Shift operations exceeding type width
- Out-of-bounds array access (static size only)
- Misaligned pointer access
- Null pointer dereference
- Unreachable code execution
- Load of invalid boolean/enum values

**Kconfig:**

```
CONFIG_UBSAN=y
CONFIG_UBSAN_TRAP=y          # Abort on UB instead of just logging
CONFIG_UBSAN_ALIGNMENT=n     # Disabled by default on aligned arches
CONFIG_UBSAN_SIGNED_WRAP=y   # Detect signed integer wrap (v6.8+)
```

**Performance:**

UBSAN adds approximately 5-10% overhead in instrumented code. Individual files
or directories can be excluded:
```
UBSAN_SANITIZE_main.o := n   # Exclude specific file
UBSAN_SANITIZE := n          # Exclude entire directory
```

### 7.4 KASAN (`CONFIG_KASAN`)

The **Kernel Address Sanitizer** is a dynamic memory safety error detector.
Three modes are available:

**Generic KASAN (`CONFIG_KASAN_GENERIC`):**

- Uses **shadow memory** (1/8th of kernel memory) to track accessibility of
  each 8-byte aligned memory granule.
- Compiler inserts calls to `__asan_load*()` / `__asan_store*()` before every
  memory access.
- Detects: out-of-bounds (slab, stack, global), use-after-free, double-free.
- Overhead: ~2-3x CPU, ~1/8 additional memory.
- Uses a **quarantine** to delay reuse of freed objects.
- Supported on: x86_64, arm, arm64, powerpc, riscv, s390, xtensa, loongarch.

**Software Tag-Based KASAN (`CONFIG_KASAN_SW_TAGS`):**

- Uses ARM64 TBI to store a random tag in the top byte of pointers.
- Shadow memory tracks per-16-byte granule tags (1/16th of kernel memory).
- Detects the same classes of bugs as Generic KASAN with lower memory overhead.
- Only supported on arm64.
- Suitable for testing with real workloads on memory-constrained devices.

**Hardware Tag-Based KASAN (`CONFIG_KASAN_HW_TAGS`):**

- Uses ARM MTE hardware for tagging — no compiler instrumentation for checks.
- Low overhead: suitable for **production** security use.
- Only works on arm64 CPUs with MTE support.
- Boot parameters: `kasan=off|on`, `kasan.mode=sync|async|asymm`,
  `kasan.write_only=on|off`.
- Supports sampling to further reduce overhead:
  `kasan.page_alloc.sample=<N>`.

### 7.5 KFENCE (`CONFIG_KFENCE`)

**Kernel Electric Fence** is a low-overhead sampling-based memory safety detector
designed for production use:

- Periodically intercepts allocations and places them in a **guarded pool** with
  surrounding guard pages.
- Detects out-of-bounds access and use-after-free via page faults on guard pages.
- Very low overhead (~0.1% CPU) due to sampling — only a small fraction of
  allocations are guarded.
- Complements KASAN: KFENCE is for production; KASAN (generic) is for development.

### 7.6 Stack Protections

```
CONFIG_STACKPROTECTOR=y         # -fstack-protector: canary for functions
                                # with char arrays >= 8 bytes
CONFIG_STACKPROTECTOR_STRONG=y  # -fstack-protector-strong: canary for all
                                # functions with local arrays or address-taken vars
CONFIG_VMAP_STACK=y             # Place stacks in vmalloc space with guard pages
CONFIG_KSTACK_ERASE=y           # Clear kernel stack on syscall return
CONFIG_THREAD_INFO_IN_TASK=y    # Move thread_info out of the stack
CONFIG_SHADOW_CALL_STACK=y      # Clang Shadow Call Stack (arm64)
```

### 7.7 Additional Security Options

```
CONFIG_STRICT_KERNEL_RWX=y       # W^X for kernel text/rodata
CONFIG_STRICT_MODULE_RWX=y       # W^X for module text/rodata
CONFIG_DEBUG_RODATA=y            # Mark kernel rodata read-only
CONFIG_SET_FS=n                  # Removed set_fs() (eliminates KERNEL_DS attacks)
CONFIG_STATIC_USERMODEHELPER=y   # Restrict usermodehelper paths
CONFIG_SECURITY_DMESG_RESTRICT=y # Restrict dmesg to CAP_SYSLOG
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y # Zero-fill heap on allocation
CONFIG_INIT_ON_FREE_DEFAULT_ON=y  # Zero-fill heap on free
CONFIG_PAGE_POISONING=y          # Poison freed pages with patterns
CONFIG_SLAB_FREELIST_RANDOM=y    # Randomize slab freelist order
CONFIG_SLAB_FREELIST_HARDENED=y  # Mangle freelist pointers (XOR with random)
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y  # Randomize page allocator free lists
CONFIG_RANDOMIZE_BASE=y          # KASLR
CONFIG_RANDOMIZE_KSTACK_OFFSET=y # Per-syscall kernel stack offset randomization
CONFIG_REFCOUNT_FULL=y           # Full reference count overflow protection
                                 # (now default and non-optional)
CONFIG_HARDENED_USERCOPY=y       # Validate usercopy sizes against slab/stack
CONFIG_FORTIFY_SOURCE=y          # Buffer overflow checks
CONFIG_LIST_HARDENED=y           # Integrity checks for linked lists
CONFIG_BUG_ON_DATA_CORRUPTION=y  # Panic on detected data corruption
```

---

## 8. GCC/Clang Kernel Hardening Plugins

The Linux kernel supports a **GCC plugin infrastructure** (`CONFIG_GCC_PLUGINS`)
and corresponding Clang built-in features that implement security hardening at
compile time.

### 8.1 randstruct Plugin

**Plugin**: `scripts/gcc-plugins/randomize_layout_plugin.so`

**Function**: Randomizes the field order of structures marked with
`__randomize_layout` at compile time, using a per-build seed.

**Details:**
- The seed is generated at build time and stored in
  `scripts/gcc-plugins/randomize_layout_seed.h`.
- This file should be kept secret; leaking it reveals structure layouts.
- Two modes:
  - **Full randomization**: Completely random field reordering.
  - **Performance mode** (`CONFIG_RANDSTRUCT_PERFORMANCE`): Groups fields by
    size to maintain cache-line locality while still randomizing within groups.
- Clang has native `randstruct` support since Clang 15 via
  `CONFIG_RANDSTRUCT=y` (no plugin needed).

**Structures Protected:**
```c
struct cred {
    ...
} __randomize_layout;

// Opt out:
struct performance_critical {
    ...
} __no_randomize_layout;
```

### 8.2 latent_entropy Plugin

**Plugin**: `scripts/gcc-plugins/latent_entropy_plugin.so`

**Kconfig**: `CONFIG_GCC_PLUGIN_LATENT_ENTROPY`

**Function**: Supplements the kernel's entropy pool during early boot when
hardware RNG and interrupt-based entropy are scarce.

**Mechanism:**

- Instruments functions marked with `__latent_entropy` to accumulate
  "computational entropy" — a hash of the code's execution path.
- At each instrumented function entry and branch point, the plugin inserts
  arithmetic operations that mix the function's address and branch choices
  into a per-CPU entropy variable.
- This variable is periodically mixed into the kernel's entropy pool.
- Also initializes static variables marked with `__latent_entropy` with
  random compile-time values.

**Security Value:**

- Does not provide cryptographic-quality entropy, but provides early-boot
  defense against entropy starvation attacks.
- Helps randomize values that depend on the entropy pool during initialization.

### 8.3 stackleak Plugin

**Plugin**: `scripts/gcc-plugins/stackleak_plugin.so`

**Kconfig**: `CONFIG_GCC_PLUGIN_STACKLEAK`

**Function**: Erases the kernel stack on every return to user-space, defending
against:
- Kernel stack information leaks (e.g., uninitialized stack variables)
- Stack clash attacks
- Uninitialized stack variable exploitation

**Mechanism:**

1. At function entry for functions with large stack frames, the plugin inserts
   a call to `stackleak_check_alloca()` to track the lowest stack pointer
   reached during the syscall.
2. On return to user-space (via the `stackleak_erase()` function called from
   the syscall exit path), the kernel overwrites all stack memory between the
   current SP and the lowest SP reached with a **poison value**
   (`STACKLEAK_POISON = 0xBAAAAAAD` or similar).
3. This ensures no residual kernel data remains on the stack for the next
   syscall to potentially leak.

**Runtime Control:**

- `/sys/kernel/debug/stackleak` provides debug information.
- Overhead: approximately 1-3% depending on workload, due to stack clearing.

### 8.4 structleak Plugin

**Plugin**: `scripts/gcc-plugins/structleak_plugin.so` (older kernels) / now
replaced by compiler features.

**Kconfig**: `CONFIG_GCC_PLUGIN_STRUCTLEAK` / `CONFIG_INIT_STACK_ALL_ZERO`

**Function**: Initializes all stack variables to zero (or a pattern) to prevent
information leaks from uninitialized stack memory.

**Evolution:**

- Original `structleak` plugin only zeroed structures passed by reference to
  other functions.
- `CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL` extended this to all structures.
- Modern kernels use `CONFIG_INIT_STACK_ALL_ZERO` with
  `-ftrivial-auto-var-init=zero` (GCC 12+ / Clang 16+), replacing the plugin
  entirely.
- The compiler-based approach is faster and more comprehensive than the plugin.

### 8.5 Clang-Specific Hardening Features

**Shadow Call Stack (SCS):**

- **Kconfig**: `CONFIG_SHADOW_CALL_STACK` (arm64 only)
- Maintains a separate, hidden stack containing only return addresses.
- Uses a dedicated register (`x18`) as the SCS pointer.
- Software-based forward-edge protection complementary to PAC.
- Lower overhead than full KASAN but provides return-address integrity.

**kCFI (Kernel Control Flow Integrity):**

- **Kconfig**: `CONFIG_CFI_CLANG`
- Forward-edge CFI that validates indirect call targets against their expected
  type signatures.
- Uses type hashes embedded before each function and checked at each indirect
  call site.
- A type mismatch triggers a fault (configurable: panic or warn via
  `cfi=warn`).

**Integer overflow sanitization:**

- Clang's `-fsanitize=unsigned-integer-overflow` and
  `-fsanitize=signed-integer-overflow` can be enabled for the kernel.
- `CONFIG_UBSAN_SIGNED_WRAP` provides signed integer wrap detection.

---

## 9. Mitigation Comparison Matrix

### 9.1 Attack Class vs. Mitigation Mapping

| Attack Class | Relevant Mitigations | Hardware | Software |
|---|---|---|---|
| **Stack buffer overflow** | Stack canary, Shadow Stack/GCS, SCS, PAC | CET-SS, GCS | STACKPROTECTOR, SHADOW_CALL_STACK |
| **Return address corruption (ROP)** | Shadow Stack, PAC, SCS | CET-SS, GCS, PAC | SHADOW_CALL_STACK, stackleak |
| **Indirect call/jmp hijack (JOP/COP)** | IBT, FineIBT, BTI, kCFI | CET-IBT, BTI | CFI_CLANG, FineIBT |
| **Heap buffer overflow** | MTE, KASAN, KFENCE, FORTIFY_SOURCE | MTE | KASAN, KFENCE, FORTIFY_SOURCE, SLAB_FREELIST_HARDENED |
| **Use-after-free** | MTE, KASAN, KFENCE, page poisoning | MTE | KASAN, KFENCE, INIT_ON_FREE, PAGE_POISONING |
| **Kernel address leak** | KASLR, kptr_restrict, SECURITY_DMESG_RESTRICT | — | RANDOMIZE_BASE, RANDSTRUCT |
| **Ret2usr (kernel exec user code)** | SMEP, PXN | SMEP, PXN | — |
| **Ret2usr (kernel read user data)** | SMAP, PAN | SMAP, PAN | — |
| **Uninitialized variable leak** | structleak, INIT_STACK_ALL_ZERO, KMSAN | — | INIT_STACK_ALL_ZERO, KMSAN |
| **Integer overflow** | UBSAN, REFCOUNT_FULL | — | UBSAN, REFCOUNT, FORTIFY_SOURCE |
| **Format string** | FORTIFY_SOURCE | — | FORTIFY_SOURCE |
| **Structure layout dependency** | RANDSTRUCT | — | RANDSTRUCT |
| **Arbitrary kernel r/w from root** | Lockdown LSM, PKS | PKS | LOCKDOWN_LSM, MODULE_SIG_FORCE |
| **Kernel code modification** | W^X, Lockdown | — | STRICT_KERNEL_RWX, LOCKDOWN |
| **Double-free** | KASAN, SLAB_FREELIST_HARDENED | MTE | KASAN, SLAB_FREELIST_HARDENED |

### 9.2 Overhead Comparison

| Mitigation | CPU Overhead | Memory Overhead | Suitability |
|---|---|---|---|
| CET Shadow Stack | ~0% (hardware) | ~4KB per thread | Production |
| CET IBT | ~0% (hardware) | ~0% | Production |
| FineIBT | ~1% | ~0% | Production |
| PAC | <1% | 0% | Production |
| BTI | <1% | 0% | Production |
| MTE (async) | 1-3% | ~3% (tag storage) | Production |
| MTE (sync) | 5-16% | ~3% | Development/dogfood |
| SMEP/SMAP | ~0% | 0% | Production (always-on) |
| KASAN (generic) | 200-300% | 12.5% (shadow) | Development only |
| KASAN (HW_TAGS) | 3-5% | ~3% | Production (arm64+MTE) |
| KFENCE | <0.1% | ~1MB fixed | Production |
| UBSAN | 5-10% | ~5% (code size) | Development/CI |
| FORTIFY_SOURCE | ~0-1% | ~1% (code size) | Production |
| STACKPROTECTOR | <1% | 0% | Production (always-on) |
| RANDSTRUCT | 0% (compile time only) | 0% | Production |
| stackleak | 1-3% | 0% | Production (some distros) |
| INIT_STACK_ALL_ZERO | 1-2% | 0% | Production |
| LOCKDOWN_LSM | 0% | 0% | Production |

### 9.3 Protection Coverage by Architecture

| Mitigation | x86_64 | arm64 | riscv | s390 |
|---|---|---|---|---|
| Shadow Stack / GCS | CET-SS (user) | GCS (v9.4+) | Zicfiss (proposal) | — |
| IBT / BTI | CET-IBT (kernel) | BTI | Zicfilp (proposal) | — |
| PAC | — | PAC (v8.3+) | — | — |
| MTE | — | MTE (v8.5+) | — | — |
| SMEP/PXN | SMEP | PXN | — | — |
| SMAP/PAN | SMAP | PAN | — | — |
| PKS/PKU | PKS (kernel) | — | — | — |
| KASAN (generic) | Yes | Yes | Yes | Yes |
| KASAN (SW_TAGS) | — | Yes | — | — |
| KASAN (HW_TAGS) | — | Yes (MTE) | — | — |
| kCFI/FineIBT | FineIBT | kCFI | kCFI | — |
| SCS | — | Yes (x18) | Yes | — |
| KASLR | Yes | Yes | Yes | Yes |

---

## 10. Distribution-Specific Kernel Hardening

### 10.1 Ubuntu

Ubuntu ships kernels with extensive hardening enabled by default:

**Compile-Time Hardening:**
- `CONFIG_FORTIFY_SOURCE=y`
- `CONFIG_STACKPROTECTOR_STRONG=y`
- `CONFIG_STRICT_KERNEL_RWX=y`
- `CONFIG_STRICT_MODULE_RWX=y`
- `CONFIG_RANDOMIZE_BASE=y` (KASLR)
- `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y`
- `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`
- `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` (since 22.04)
- `CONFIG_INIT_STACK_ALL_ZERO=y` (since 22.04)
- `CONFIG_SLAB_FREELIST_RANDOM=y`
- `CONFIG_SLAB_FREELIST_HARDENED=y`
- `CONFIG_HARDENED_USERCOPY=y`
- `CONFIG_VMAP_STACK=y`
- `CONFIG_GCC_PLUGIN_STACKLEAK=y` (some architectures)

**AppArmor + Lockdown:**
- AppArmor is the default LSM.
- `CONFIG_SECURITY_LOCKDOWN_LSM=y`
- `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y` — kernel enters integrity lockdown
  mode when booted via UEFI Secure Boot.

**Module Signing:**
- `CONFIG_MODULE_SIG=y`
- `CONFIG_MODULE_SIG_ALL=y`
- `CONFIG_MODULE_SIG_SHA512=y`
- Modules are signed during the package build process.
- For Secure Boot systems, unsigned/out-of-tree modules cannot be loaded without
  enrolling a Machine Owner Key (MOK).

**Kernel Hardening Patchset:**
- Ubuntu has historically carried out-of-tree hardening patches, including
  additional symlink/hardlink restrictions (`fs.protected_symlinks`,
  `fs.protected_hardlinks` — now upstream).
- `kernel.yama.ptrace_scope=1` — restricts ptrace to parent-child relationships.
- `kernel.kptr_restrict=1` — hides kernel pointers from unprivileged users.
- `kernel.dmesg_restrict=1` — restricts dmesg access.

### 10.2 Fedora / Red Hat Enterprise Linux (RHEL)

Fedora serves as the proving ground for RHEL, and both share similar hardening
configurations:

**Security Features:**
- SELinux is the default MAC framework, running in **enforcing** mode.
- `CONFIG_SECURITY_LOCKDOWN_LSM=y`
- `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y`
- `CONFIG_MODULE_SIG_FORCE=y` (RHEL; Fedora uses `CONFIG_MODULE_SIG=y`)
- `CONFIG_FORTIFY_SOURCE=y`
- `CONFIG_STACKPROTECTOR_STRONG=y`
- `CONFIG_RANDOMIZE_BASE=y`
- `CONFIG_HARDENED_USERCOPY=y`
- `CONFIG_SLAB_FREELIST_RANDOM=y`
- `CONFIG_SLAB_FREELIST_HARDENED=y`
- `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`

**Fedora-Specific Hardening:**
- Fedora Rawhide/39+ enables `CONFIG_CFI_CLANG=y` on arm64 builds.
- `CONFIG_INIT_STACK_ALL_ZERO=y` (Fedora 38+).
- `CONFIG_RANDSTRUCT=y` (enabled by default since Fedora 38).
- Builds with Clang/LLVM option for some architectures, gaining access to
  kCFI and other Clang-specific hardening features.

**RHEL-Specific:**
- RHEL 9 ships with `lockdown=integrity` enforced on UEFI Secure Boot systems.
- Kernel live patching (kpatch) is supported for security fixes without reboot.
- FIPS 140-3 certified kernel crypto module.
- `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` — restricts BPF to root.

### 10.3 Android Generic Kernel Image (GKI)

Android's **Generic Kernel Image (GKI)** initiative standardizes the kernel
across Android devices, enforcing a unified set of hardening configurations:

**GKI Kernel Hardening (Android 12+ / kernel 5.10+):**

**Control Flow Integrity:**
- `CONFIG_CFI_CLANG=y` — Clang kCFI is mandatory in GKI.
- `CONFIG_SHADOW_CALL_STACK=y` — Shadow Call Stack using x18 register.
- These provide comprehensive forward-edge (kCFI) and backward-edge (SCS)
  CFI for the kernel on arm64.

**Memory Safety:**
- `CONFIG_KASAN_HW_TAGS=y` — Hardware Tag-Based KASAN (on MTE-capable devices).
- `CONFIG_ARM64_MTE=y` — MTE enabled in GKI for devices that support it.
- `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` — zero-fill heap allocations.
- `CONFIG_INIT_STACK_ALL_ZERO=y` — zero-initialize all stack variables.
- `CONFIG_SLAB_FREELIST_RANDOM=y`
- `CONFIG_SLAB_FREELIST_HARDENED=y`

**Pointer Authentication:**
- `CONFIG_ARM64_PTR_AUTH=y` — enabled for userspace.
- `CONFIG_ARM64_PTR_AUTH_KERNEL=y` — kernel compiled with PAC instructions.

**Branch Target Identification:**
- `CONFIG_ARM64_BTI_KERNEL=y` — kernel compiled with BTI.

**Access Controls:**
- `CONFIG_STRICT_KERNEL_RWX=y`
- `CONFIG_STRICT_MODULE_RWX=y`
- `CONFIG_HARDENED_USERCOPY=y`
- `CONFIG_FORTIFY_SOURCE=y`
- `CONFIG_STACKPROTECTOR_STRONG=y`
- Modules are signed and verified.
- SELinux is enforcing by default on all Android devices.

**GKI Module Architecture:**
- The GKI kernel is a single signed binary shared across OEMs.
- Vendor-specific functionality is loaded as signed kernel modules.
- `CONFIG_MODVERSIONS=y` — module ABI versioning.
- `CONFIG_MODULE_SIG=y` — module signature verification.
- The `vendor_boot` partition carries vendor modules, separate from the GKI
  boot image.

**Android-Specific Hardening Beyond GKI:**
- `CONFIG_SECURITY_SELINUX=y` with neverallow rules in the Android platform policy.
- `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` — unprivileged BPF disabled.
- `CONFIG_DEFAULT_MMAP_MIN_ADDR=32768` — prevent null-deref exploitation.
- dm-verity for system partition integrity.
- Verified Boot (AVB) chain covering bootloader, kernel, and system images.
- Monthly Android Security Bulletin patches backported to GKI branches.

### 10.4 Comparison Matrix: Distribution Hardening

| Feature | Ubuntu 24.04 | Fedora 41 | RHEL 9 | Android GKI (15) |
|---|---|---|---|---|
| Default LSM | AppArmor | SELinux | SELinux | SELinux |
| Lockdown (Secure Boot) | Integrity | Integrity | Integrity | N/A (Verified Boot) |
| KASLR | Yes | Yes | Yes | Yes |
| STACKPROTECTOR_STRONG | Yes | Yes | Yes | Yes |
| FORTIFY_SOURCE | Yes | Yes | Yes | Yes |
| RANDSTRUCT | Yes | Yes | Yes (Clang) | Limited |
| INIT_STACK_ALL_ZERO | Yes | Yes | Yes | Yes |
| INIT_ON_ALLOC | Yes | Yes | Yes | Yes |
| CFI (forward-edge) | Partial | kCFI (arm64) | Partial | kCFI (mandatory) |
| Shadow Call Stack | No (x86) | arm64 only | No | Yes (arm64) |
| Module Signing | Required (SB) | Required | Enforced | Enforced |
| PAC (arm64) | Yes (if arm64) | Yes (if arm64) | Yes (if arm64) | Yes (mandatory) |
| BTI (arm64) | Yes (if arm64) | Yes (if arm64) | Yes (if arm64) | Yes (mandatory) |
| MTE/HW_TAGS KASAN | If available | If available | If available | If available |
| HARDENED_USERCOPY | Yes | Yes | Yes | Yes |
| SLAB_FREELIST_HARDENED | Yes | Yes | Yes | Yes |
| VMAP_STACK | Yes | Yes | Yes | Yes |
| stackleak | Some arches | No | No | No |
| BPF restrictions | Partial | Yes | Yes | Yes |
| dmesg_restrict | Yes | Yes | Yes | Yes |

---

## Summary

Modern Linux kernel hardening relies on a **defense-in-depth** strategy that
combines multiple layers of hardware and software mitigations:

1. **Hardware CFI** (CET Shadow Stacks, IBT, PAC, BTI, GCS) protects
   control-flow integrity at near-zero overhead, making ROP/JOP attacks
   significantly harder.

2. **Hardware memory safety** (MTE, SMAP/SMEP, PAN/PXN) enforces memory
   access boundaries and isolation in silicon, preventing entire classes of
   exploitation techniques like ret2usr and spatial/temporal memory corruption.

3. **Kernel CONFIG hardening** (FORTIFY_SOURCE, HARDENED_USERCOPY, STACKPROTECTOR,
   SLAB_FREELIST_HARDENED, etc.) provides software-level safety nets that catch
   bugs that hardware doesn't cover.

4. **Compiler plugins and features** (randstruct, stackleak, kCFI,
   INIT_STACK_ALL_ZERO) address vulnerability classes at the build stage,
   eliminating bugs before they can be exploited.

5. **Policy enforcement** (Lockdown LSM, module signing, SELinux/AppArmor)
   restricts what even privileged users can do to the running kernel.

6. **Runtime detection tools** (KASAN, KFENCE, UBSAN) find bugs during
   development and testing, with hardware-accelerated modes (HW_TAGS KASAN)
   suitable for production deployment.

No single mitigation is sufficient. Effective kernel security requires enabling
multiple overlapping protections — hardware features provide the foundation with
minimal performance impact, software mitigations fill the gaps, and policy
controls limit the attack surface available to adversaries.

For exploit developers, the practical impact is that modern hardened kernels
require **chaining multiple vulnerability primitives**: an information leak to
defeat KASLR and RANDSTRUCT, a write primitive that can bypass SMAP/PAN and
shadow stacks, and a code execution technique that survives IBT/BTI and kCFI
checks — all while avoiding detection by KASAN/KFENCE and operating within
lockdown constraints.

---

*Sources: Linux kernel documentation (docs.kernel.org), Intel SDM, ARM Architecture
Reference Manual, kernel source (security/, arch/x86/, arch/arm64/), Android
Open Source Project documentation, distribution kernel config files.*
