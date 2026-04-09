# 6a. Kernel Mitigation Mechanisms: Software Mitigations

## Table of Contents

1. [KASLR — Kernel Address Space Layout Randomization](#1-kaslr--kernel-address-space-layout-randomization)
2. [SMEP and SMAP — Supervisor Mode Execution/Access Prevention](#2-smep-and-smap--supervisor-mode-executionaccess-prevention)
3. [Stack Canaries — CONFIG_STACKPROTECTOR](#3-stack-canaries--config_stackprotector)
4. [KPTI — Kernel Page Table Isolation](#4-kpti--kernel-page-table-isolation)
5. [CONFIG_HARDENED_USERCOPY](#5-config_hardened_usercopy)
6. [Slab Allocator Hardening](#6-slab-allocator-hardening)
7. [Control Flow Integrity (CFI)](#7-control-flow-integrity-cfi)
8. [SELinux, AppArmor, and the LSM Framework](#8-selinux-apparmor-and-the-lsm-framework)
9. [seccomp-BPF — Reducing Syscall Attack Surface](#9-seccomp-bpf--reducing-syscall-attack-surface)
10. [CONFIG_INIT_STACK_ALL — Stack Variable Zero-Initialization](#10-config_init_stack_all--stack-variable-zero-initialization)

---

## 1. KASLR — Kernel Address Space Layout Randomization

### 1.1 Overview

KASLR (`CONFIG_RANDOMIZE_BASE`) randomizes the virtual and physical base address of the kernel at boot time. The goal is to make the location of kernel code, data, and internal structures non-deterministic, so that an attacker who has found a memory corruption vulnerability cannot simply hardcode known addresses of functions like `commit_creds()` or `prepare_kernel_cred()` to achieve privilege escalation.

KASLR was originally proposed by Dan Rosenberg in 2011 and brought to mainline by Kees Cook. It was merged for x86-64 in Linux 3.14 (2014) and for 32-bit x86 as well. ARM64 KASLR arrived in Linux 4.6.

### 1.2 Implementation Details

At boot, the kernel decompressor (in `arch/x86/boot/compressed/`) determines the randomized load offset:

1. **Identify safe regions**: The decompressor walks the e820 memory map to identify physically contiguous regions large enough to hold the kernel image.
2. **Count available slots**: Because the kernel must be aligned on a 2 MB boundary (due to page table constraints with huge pages), the available physical address space is divided into 2 MB-aligned slots.
3. **Select a random slot**: The best available entropy source is queried — `RDRAND` instruction if available, RDTSC (time stamp counter) low bits, or timer I/O port values. A slot is selected uniformly at random.
4. **Decompress and relocate**: The kernel is decompressed into the chosen physical location and all relocations are applied.
5. **Virtual randomization**: A separate virtual-address offset is applied to the kernel's virtual mapping, independent of the physical offset.

The decompressor code lives in `arch/x86/boot/compressed/kaslr.c`.

### 1.3 Entropy and Slot Count

On x86-64, the original kernel virtual address space layout reserved 512 MB for the kernel text and 1.5 GB for modules. Kees Cook's patches reduced the module space to 1 GB and increased the kernel text region to 1 GB, yielding:

| Architecture | Alignment | Available Space | Theoretical Slots |
|---|---|---|---|
| x86-64 | 2 MB | 1 GB | 512 |
| x86-32 | 2 MB | 512 MB | 256 |
| ARM64 | 2 MB | varies | varies (up to ~512) |

In practice, the actual number of slots is lower due to reserved memory regions, BIOS holes, and other constraints. The effective entropy is roughly **9 bits** on x86-64 (512 positions), which is modest but sufficient to make blind brute-force impractical — a wrong guess crashes the kernel rather than silently failing.

### 1.4 Additional Randomization Dimensions

KASLR is not limited to kernel text randomization. The kernel self-protection model identifies several additional areas:

- **Module base randomization**: Kernel modules are loaded at a randomized offset within the module region, separate from the core kernel text base. Even systems that load the same set of modules in the same order will not share module addresses.
- **Stack base randomization**: Per-process and per-syscall stack offsets add entropy to the stack layout, making stack-based targets harder to locate.
- **Dynamic memory base randomization**: The bases of `kmalloc`, `vmalloc`, and direct-mapped regions are randomized between boots.
- **Structure layout randomization** (`CONFIG_RANDSTRUCT`): Per-build randomization of sensitive structure layouts (e.g., `struct task_struct`, `struct cred`). Attacks must be tuned to a specific build or require an info-leak to discover the layout.

### 1.5 Limitations and Bypass Techniques

KASLR is a **probabilistic** defense. Its effectiveness depends entirely on preventing information leaks:

- **Kernel pointer leaks**: Any kernel address leaked to userspace (via `/proc/kallsyms`, dmesg, `/proc/modules`, or kernel log files) defeats KASLR. Mitigations include `kptr_restrict` (hashing pointers in `%pK` output), `dmesg_restrict`, and restricting access to `/proc/kallsyms`.
- **Side channels**: Timing-based side channels (e.g., TSX-based probing, prefetch side channels, and CPU cache-based attacks) can infer kernel mapping layout. The INET_DIAG socket API historically leaked kernel pointers as opaque handles.
- **Format string specifiers**: Since kernel 4.15, the `%p` format specifier hashes kernel addresses before printing. Only `%px` prints raw addresses, and files using it should be readable only by privileged processes.
- **Single leak defeats all**: Because KASLR applies a single global offset to the kernel text, leaking any one kernel address reveals the offset for all symbols.

**Key point for exploitation**: KASLR raises the bar but does not eliminate the need for other defenses. In contained environments (containers, seccomp-sandboxed processes, Chrome renderer processes), KASLR is quite effective because the info-leak surface is minimal. On unconfined systems with local untrusted users, it provides limited value without additional hardening.

---

## 2. SMEP and SMAP — Supervisor Mode Execution/Access Prevention

### 2.1 Overview

SMEP and SMAP are **hardware features** (present on Intel CPUs since Ivy Bridge/Broadwell and AMD since Zen) that the kernel enables and configures via software. They are controlled through CR4 register bits.

- **SMEP** (Supervisor Mode Execution Prevention, CR4.SMEP): Prevents the CPU from executing code located in user-space pages while running in kernel mode (ring 0). Any attempt to fetch instructions from a page marked as user-accessible triggers a page fault.
- **SMAP** (Supervisor Mode Access Prevention, CR4.SMAP): Prevents the CPU from reading or writing user-space pages while in kernel mode, unless explicitly permitted via the `STAC`/`CLAC` instructions.

ARM equivalents are PXN (Privileged Execute Never) and PAN (Privileged Access Never).

### 2.2 Implementation in the Kernel

The kernel enables SMEP and SMAP during early boot in `arch/x86/kernel/cpu/common.c`. The feature bits are detected from CPUID and the corresponding CR4 bits are set.

For SMAP, the kernel must explicitly bracket legitimate user-space memory accesses with `STAC` (Set AC flag) and `CLAC` (Clear AC flag) instructions. These are used in:

- `copy_to_user()` / `copy_from_user()`
- `get_user()` / `put_user()`
- Other explicit user-space access paths

The `stac()` and `clac()` inline assembly wrappers are defined in `arch/x86/include/asm/smap.h`.

### 2.3 Security Impact

**Before SMEP/SMAP**, a classic kernel exploitation technique was:

1. Find a kernel vulnerability (NULL pointer dereference, arbitrary write, etc.)
2. Place shellcode in user-space memory at a controlled address
3. Redirect kernel execution (e.g., via corrupted function pointer) to the user-space shellcode
4. The shellcode calls `commit_creds(prepare_kernel_cred(NULL))` to gain root

**With SMEP**, step 3 fails — the CPU faults when attempting to execute user-space code from kernel context. This forces attackers to use **ROP (Return-Oriented Programming)** or **JOP (Jump-Oriented Programming)** chains composed entirely of existing kernel code gadgets.

**With SMAP**, even reading attacker-controlled data from user-space requires finding kernel gadgets that include `STAC` instructions or exploiting legitimate `copy_from_user()` paths. This dramatically complicates the construction of fake kernel structures (e.g., fake `struct tty_operations`) in user-space.

### 2.4 Bypass Techniques

- **ROP chains**: SMEP forces a pivot to kernel ROP, but with sufficient gadgets this is achievable. Common techniques include finding a gadget that flips the CR4.SMEP bit (e.g., `mov cr4, rdi` gadgets), though modern kernels pin CR4 bits.
- **CR4 pinning**: Recent kernels write-protect CR4 SMEP/SMAP bits using `native_write_cr4()` with a bitmask check, killing the trivial CR4-flip bypass.
- **Kernel heap spraying**: Instead of placing fake structures in user-space, attackers spray them onto the kernel heap, bypassing SMAP entirely.
- **STAC/CLAC gadgets**: If an attacker can find ROP gadgets that include STAC, SMAP can be temporarily disabled within the ROP chain.

---

## 3. Stack Canaries — CONFIG_STACKPROTECTOR

### 3.1 Overview

Stack canaries (`CONFIG_STACKPROTECTOR` and `CONFIG_STACKPROTECTOR_STRONG`) place a secret random value ("canary") between stack-allocated local variables and the saved return address in each function's stack frame. Before the function returns, the canary is compared against its expected value. If a sequential stack buffer overflow has overwritten the return address, the canary will have been corrupted first, and the check detects the attack.

### 3.2 Implementation

The compiler (GCC's `-fstack-protector` or `-fstack-protector-strong`) instruments function prologues and epilogues:

**Prologue** (simplified x86-64):
```asm
mov    rax, gs:[0x28]       ; Load per-CPU canary from segment register
mov    [rbp-0x8], rax       ; Store canary on stack
```

**Epilogue**:
```asm
mov    rax, [rbp-0x8]       ; Load stored canary
xor    rax, gs:[0x28]       ; Compare with expected value
jne    __stack_chk_fail     ; If mismatch, call panic handler
```

The canary value is stored in the per-CPU data area, accessible via the `gs` segment register on x86-64 (or `__stack_chk_guard` on other architectures). It is initialized early in boot from the kernel's random number generator.

### 3.3 CONFIG_STACKPROTECTOR vs CONFIG_STACKPROTECTOR_STRONG

| Option | Functions Protected | Coverage |
|---|---|---|
| `CONFIG_STACKPROTECTOR` | Functions with `char` arrays or calls to `alloca()` | ~20% of kernel functions |
| `CONFIG_STACKPROTECTOR_STRONG` | Functions with any local arrays, address-taken local variables, or local struct/union with arrays | ~65-75% of kernel functions |

`CONFIG_STACKPROTECTOR_STRONG` (introduced in GCC 4.9) significantly expands coverage with minimal performance impact (typically <1% overhead) and is the recommended option for production kernels.

### 3.4 Canary Entropy and Refresh

- The canary is a full pointer-width value (64 bits on x86-64), with the lowest byte forced to `0x00` as a string terminator to prevent canary leakage via string operations. This gives effectively **56 bits of entropy** on 64-bit systems.
- Per-CPU canary values are initialized from the kernel CRNG during boot. On task fork, each new task receives the canary value from its parent CPU.
- There is no periodic canary refresh — the value remains constant for the life of the boot. If leaked via an info-leak vulnerability, all stack frames become vulnerable.

### 3.5 Limitations

- **Non-sequential overwrites**: Stack canaries only detect **linear** buffer overflows. An arbitrary write primitive (write-what-where) can skip over the canary and directly overwrite the return address.
- **Canary leaks**: Information disclosure vulnerabilities that can read the canary value (e.g., format string bugs, out-of-bounds reads) allow an attacker to include the correct canary in their overflow payload.
- **Incomplete coverage**: Even with `_STRONG`, some functions may not be instrumented. Notably, functions with no local arrays or address-taken variables are unprotected.
- **No protection of other stack data**: Function pointers, local variables used in security decisions, and other non-return-address data on the stack are not protected by canaries.

### 3.6 Complementary: Shadow Call Stack

ARM64 kernels support **Shadow Call Stack** (`CONFIG_SHADOW_CALL_STACK`), which stores return addresses in a separate, hidden stack pointed to by a dedicated register (x18). This provides **deterministic** backward-edge CFI protection rather than the probabilistic protection of canaries. Shadow Call Stack is immune to canary leaks and protects against arbitrary write attacks targeting return addresses.

---

## 4. KPTI — Kernel Page Table Isolation

### 4.1 Overview

KPTI (Kernel Page Table Isolation), originally called KAISER (Kernel Address Isolation to have Side-channels Efficiently Removed), is the primary software mitigation for the **Meltdown vulnerability** (CVE-2017-5754). Meltdown allows unprivileged user-space code to read kernel memory through speculative execution side channels on vulnerable Intel processors.

KPTI was merged into Linux 4.15 (January 2018) on an emergency fast-track, with preparatory patches merged after the 4.15-rc4 release — a period when normally only critical fixes are allowed. An equivalent ARM64 implementation followed shortly.

### 4.2 The Problem KPTI Solves

In kernels before KPTI, a single set of page tables mapped both user-space and kernel-space memory. The kernel region was marked with the supervisor bit (U/S=0) in page table entries, preventing direct user-space access. However, the Meltdown attack showed that:

1. A speculative load from a kernel address succeeds transiently before the permission check retires.
2. The speculatively loaded data modifies microarchitectural state (cache lines).
3. A subsequent cache timing measurement recovers the data byte-by-byte.

Because the kernel pages were **mapped** (just not accessible), the speculative load could fetch data from the L1 cache.

### 4.3 Implementation

KPTI fundamentally changes kernel memory management by maintaining **two sets of page tables** per process:

1. **Kernel PGD**: Used when running in kernel mode. Maps the full address space — both kernel and user memory. This is the traditional page table.
2. **User PGD**: Used when running in user mode. Maps user-space memory normally but includes only a **minimal kernel mapping** — just enough to handle the transition into kernel mode (entry trampolines, interrupt handlers, per-CPU data).

The page table structure on x86-64 is hierarchical: PGD → P4D → PUD → PMD → PTE (with 5-level paging inserting P4D). KPTI allocates a second PGD per process. When switching to user mode, `CR3` is loaded with the user PGD. On entry to the kernel (syscall, interrupt, exception), a small trampoline in the minimal mapping switches `CR3` back to the kernel PGD.

**Key implementation details** (from Thomas Gleixner, Peter Zijlstra, Andy Lutomirski, Hugh Dickins):

- **Entry/exit trampolines**: Small code stubs mapped in both PGDs handle the `CR3` switch. These must be extremely carefully written to avoid touching any kernel memory before the switch.
- **Per-CPU entry stacks**: Each CPU has a small trampoline stack mapped in both PGDs, used during the initial phase of kernel entry.
- **LDT handling**: The x86 Local Descriptor Table must be accessible in both PGDs. KPTI reserves an entire PGD entry for LDT mappings and marks them read-only.
- **User-space marked NX in kernel PGD**: As a safety measure, user-space pages are marked non-executable in the kernel PGD. If the kernel accidentally returns to user-space without switching page tables, the process immediately crashes rather than silently running with full kernel access.
- **PCID optimization**: On CPUs supporting Process Context Identifiers (PCID/ASID), the TLB can retain entries from both PGDs simultaneously, tagged with different PCIDs. This dramatically reduces the performance cost of KPTI by avoiding full TLB flushes on every kernel entry/exit.

### 4.4 Performance Impact

The primary cost of KPTI is the overhead of switching `CR3` on every kernel entry and exit. Without PCID, this triggers a full TLB flush, which is expensive for syscall-heavy workloads.

| Workload Type | Overhead (without PCID) | Overhead (with PCID) |
|---|---|---|
| Syscall-heavy (e.g., `getpid()`) | 20-30% | 1-5% |
| I/O heavy (database, file serving) | 5-15% | 1-5% |
| Compute-bound | ~0% | ~0% |

Most modern Intel CPUs (Haswell and later) support PCID, limiting the practical impact to 1-5% for typical workloads.

### 4.5 Configuration and Runtime Control

- **Boot parameter**: `nopti` disables KPTI at boot time.
- **CPU bug flag**: `X86_BUG_CPU_MELTDOWN` indicates vulnerable CPUs. KPTI is automatically disabled on CPUs not affected (e.g., AMD processors, future Intel processors with hardware fixes).
- **Runtime status**: `/sys/devices/system/cpu/vulnerabilities/meltdown` reports current mitigation status.

### 4.6 Relation to Other Mitigations

KPTI specifically addresses Meltdown (rogue data cache load). Other speculative execution vulnerabilities have separate mitigations:

- **Spectre v1** (bounds check bypass): Mitigated by speculation barriers (`lfence`, array index masking).
- **Spectre v2** (branch target injection): Mitigated by retpoline, IBRS/IBPB, eIBRS.
- **L1TF** (L1 Terminal Fault): Mitigated by PTE inversion and L1D cache flushing on VM entry.

---

## 5. CONFIG_HARDENED_USERCOPY

### 5.1 Overview

`CONFIG_HARDENED_USERCOPY` adds runtime validation to `copy_to_user()` and `copy_from_user()` (and related functions) to ensure that kernel-side buffer arguments are valid and bounded. It prevents both information leaks (over-reading kernel memory to user-space) and memory corruption (over-writing kernel memory from user-space).

The feature originated from PaX's `PAX_USERCOPY`, was ported by Casey Schaufler, and refined by Kees Cook for mainline inclusion in Linux 4.8 (2016).

### 5.2 Checks Performed

When `copy_to_user()` or `copy_from_user()` is called, the hardened usercopy code validates the **kernel-side pointer and length**:

1. **Address wrap check**: The kernel address range `[ptr, ptr+len)` must not wrap past the end of the address space.
2. **NULL check**: The kernel-side pointer must not be NULL.
3. **Zero-length allocation check**: The pointer must not refer to a `ZERO_SIZE_PTR` (the result of `kmalloc(0)`).
4. **Kernel text rejection**: The address range must not overlap the kernel text (code) segment, preventing code leaks.
5. **Slab object bounds check**: If the pointer falls within a slab-allocated page (detected via `PageSlab()`), the copy must fit entirely within the allocated slab object. An allocator-specific callback determines the object boundaries.
6. **Stack bounds check**: If the pointer falls within the current task's kernel stack, the copy must fit within the stack boundaries. On architectures with stack frame identification (x86), the copy must fit within a single stack frame.
7. **Page span check**: For non-slab memory, the copy must not span independently allocated pages (it must stay within a single or compound page allocation).

### 5.3 What It Catches

This mitigation catches a critical class of vulnerabilities: cases where a kernel subsystem passes an incorrect length to a usercopy function, or where an attacker can influence the length argument:

```c
/* Bug: user controls 'len' which may exceed the buffer size */
char buf[64];
copy_to_user(user_buf, buf, user_controlled_len);  /* Caught by stack frame check */

/* Bug: object is 128 bytes but len is unchecked */
obj = kmalloc(128, GFP_KERNEL);
copy_from_user(obj, user_buf, user_controlled_len);  /* Caught by slab bounds check */
```

### 5.4 Performance Impact

Kees Cook reported no measurable performance impact during kernel builds and hackbench testing. The checks add a small amount of code to each usercopy path, but the overhead is dwarfed by the cost of the actual memory copy and the user/kernel transition. The feature is enabled by default in many distribution kernels.

### 5.5 Limitations

- **Does not validate user-side pointers beyond existing checks**: The existing `access_ok()` checks remain the primary validation for user-space addresses.
- **Cannot detect all overflows**: If a buffer is over-allocated (e.g., `kmalloc(4096)` for a 64-byte structure), an overflow within the 4096-byte slab object is not detected.
- **Whitelisting mechanism**: Some kernel subsystems legitimately copy data that spans multiple allocations or does not fit cleanly into slab objects. These paths require whitelisting via `__check_object_size()` overrides, which can create gaps.

---

## 6. Slab Allocator Hardening

### 6.1 CONFIG_SLAB_FREELIST_RANDOM

#### Purpose

When objects are freed back to the slab allocator, they are placed onto per-slab freelists. By default, these freelists have a predictable order — typically LIFO (last-in, first-out). An attacker who can control allocation and deallocation timing can predict which address a new allocation will receive, enabling precise heap grooming for exploitation.

`CONFIG_SLAB_FREELIST_RANDOM` (merged in Linux 4.7) randomizes the initial order of objects within each slab page when the slab is first created. Instead of objects being arranged sequentially in memory, they are shuffled using a Fisher-Yates algorithm seeded from the kernel CRNG.

#### Implementation

When a new slab page is allocated and populated with objects, the initialization code generates a random permutation of the object indices. The freelist is then constructed according to this permutation. This means that the first allocation from a fresh slab does not return the first object in the page, and subsequent allocations follow the randomized order.

#### Effectiveness

- Makes heap layout **non-deterministic** between boots and between slab page allocations.
- Complicates heap grooming techniques that depend on predictable adjacency of objects.
- **Does not prevent** heap spraying in general — an attacker who can perform many allocations of the same size will still fill slabs and achieve statistical control over layout.
- The randomization applies **only to the initial ordering** within a slab page; once objects are freed and re-allocated, the freelist order depends on the free/alloc pattern.

### 6.2 CONFIG_SLAB_FREELIST_HARDENED

#### Purpose

`CONFIG_SLAB_FREELIST_HARDENED` (merged in Linux 4.14) protects the integrity of the freelist pointers themselves. In the SLUB allocator, free objects contain an inline pointer to the next free object (the freelist is a singly-linked list threaded through the free objects). If an attacker achieves a use-after-free or heap overflow, they can overwrite this freelist pointer to redirect a future allocation to an arbitrary address — the classic "freelist poisoning" or "unlink" attack.

#### Implementation

Freelist hardening applies two protections:

1. **Pointer mangling (XOR obfuscation)**: Each freelist pointer is XOR'd with a per-cache random value and the address of the pointer's location:
   ```c
   mangled_ptr = ptr ^ cache->random ^ ptr_addr;
   ```
   This means that an attacker who overwrites a freelist pointer with a raw address will cause a crash (or incorrect demangling) rather than a successful redirect, unless they know both the random value and the pointer location.

2. **Double-free detection**: On `kfree()`, the allocator checks whether the object being freed is already on the freelist. This catches the simplest form of double-free vulnerability, which is a common precursor to use-after-free exploitation.

#### Effectiveness

- **Raises the bar significantly** for freelist poisoning attacks. The attacker must leak both the per-cache random value and understand the XOR encoding.
- **Catches double-frees** at the allocator level rather than allowing silent corruption.
- Does **not** prevent all use-after-free attacks — only those that depend on freelist pointer corruption. Type confusion via cross-cache attacks, for example, is unaffected.
- Performance overhead is minimal (a few XOR operations per alloc/free).

### 6.3 Additional Slab Hardening

Other slab-related hardening features include:

- **`CONFIG_SLAB_FREELIST_HARDENED` red-zoning**: Optional red zones around slab objects to detect out-of-bounds writes (primarily a debugging feature, enabled via `CONFIG_SLUB_DEBUG`).
- **`CONFIG_RANDOM_KMALLOC_CACHES`** (Linux 6.6+): Creates multiple copies of each `kmalloc` cache with random selection, making cross-cache attacks harder by distributing same-sized allocations across different physical slab pages.
- **`CONFIG_SLAB_VIRTUAL`** (proposed): Virtualizes slab memory to prevent direct physical adjacency assumptions.

---

## 7. Control Flow Integrity (CFI)

### 7.1 Overview

Control Flow Integrity is a security property that restricts the targets of indirect branches (calls, jumps, returns) to only those that are valid according to the program's static control flow graph. CFI addresses the fundamental exploitation technique of hijacking indirect branches — corrupted function pointers, vtable pointers, or return addresses — to redirect execution to attacker-chosen locations.

CFI is divided into two categories:

- **Forward-edge CFI**: Protects indirect calls and jumps (function pointers, virtual calls).
- **Backward-edge CFI**: Protects return addresses (function returns).

### 7.2 Forward-Edge: kCFI

The Linux kernel uses **kCFI** (`-fsanitize=kcfi`), a Clang-based scheme specifically designed for kernel code. Unlike Clang's general CFI (`-fsanitize=cfi-icall`), kCFI:

- Does **not** require Link-Time Optimization (LTO), making it practical for the kernel build system.
- Does **not** replace function pointer values with jump table entries, preserving function pointer identity.
- Never breaks cross-DSO (cross-module) function address equality.

#### How kCFI Works

1. **Type hash generation**: The compiler computes a hash of each function's prototype (return type and parameter types). This hash is embedded as a 32-bit constant immediately before the function's entry point in the `.text` section.
2. **Call-site checks**: At each indirect call site, the compiler inserts a check that loads the 32-bit value at `[target - 4]` and compares it against the expected hash for the function type at that call site.
3. **Violation handling**: If the hashes don't match, a trap is raised (typically `ud2` on x86), killing the process or panicking the kernel.

```
; Memory layout for a kCFI-protected function:
    .long 0xDEADBEEF          ; Type hash (4 bytes before entry)
function_entry:
    push rbp                  ; Actual function code
    mov rbp, rsp
    ...

; At an indirect call site:
    mov eax, [rcx - 4]        ; Load hash before target
    cmp eax, 0xDEADBEEF       ; Compare with expected hash
    jne .Lcfi_failure          ; Trap on mismatch
    call rcx                   ; Proceed with call
```

kCFI was merged in Linux 6.1 and is enabled on ARM64 and x86-64.

### 7.3 Forward-Edge: FineIBT

**FineIBT** (Fine-grained Indirect Branch Tracking) is an x86-specific enhancement that combines Intel's hardware **IBT** (Indirect Branch Tracking, via `ENDBR64` instructions) with software type checking, providing a two-layer defense:

1. **Hardware layer (IBT)**: The CPU ensures every indirect branch target begins with an `ENDBR64` instruction. This is a coarse-grained check — any `ENDBR64` is valid.
2. **Software layer (FineIBT)**: The `ENDBR64` instruction is followed by a type-hash comparison (similar to kCFI), providing fine-grained type checking.

FineIBT is configured via the `cfi=` kernel parameter:
- `cfi=auto`: Use FineIBT if IBT is available, otherwise fall back to kCFI (default).
- `cfi=kcfi`: Force kCFI only.
- `cfi=fineibt`: Force FineIBT.
- `cfi=paranoid`: Add caller hash checking (bidirectional verification).
- `cfi=off`: Disable CFI entirely.

### 7.4 Backward-Edge: Shadow Call Stack

For backward-edge protection (protecting return addresses), the kernel uses:

- **Shadow Call Stack** (`CONFIG_SHADOW_CALL_STACK`) on ARM64: Maintains a parallel stack of return addresses in a separate memory region pointed to by a dedicated register (x18). On function entry, the return address is pushed to both the regular stack and the shadow stack. On return, the shadow stack value is used, making stack buffer overflow attacks against return addresses ineffective.

- **Stack canaries** (discussed in Section 3) provide probabilistic backward-edge protection on all architectures.

- **x86 CET Shadow Stack**: Intel's Control-flow Enforcement Technology provides hardware-backed shadow stacks. Support is being integrated into the kernel (Linux 6.6+ for user-space, kernel shadow stack support is ongoing).

### 7.5 Effectiveness and Limitations

- **kCFI reduces the ROP/JOP gadget surface dramatically**. An attacker can no longer redirect an indirect call to an arbitrary address — only to functions with a matching type signature.
- **Hash collisions**: The 32-bit hash space means collisions exist. Two functions with different purposes but identical prototypes (e.g., both take `(struct foo *, int)` and return `int`) are interchangeable from CFI's perspective.
- **Direct calls are not checked**: CFI only validates indirect branches. Corruption of direct branch targets (e.g., patching JIT code or live-patched functions) is outside CFI's scope.
- **JIT code**: BPF JIT and other JIT engines require special handling to ensure emitted code has valid CFI metadata.

---

## 8. SELinux, AppArmor, and the LSM Framework

### 8.1 The Linux Security Module (LSM) Framework

The LSM framework provides a generic hook-based mechanism for security policy enforcement in the kernel. It inserts **security hooks** at critical kernel decision points — file access, process creation, network operations, IPC, capability checks, and more.

Key design properties:

- **Not loadable modules**: Despite the name, LSMs are compiled into the kernel at build time (`CONFIG_DEFAULT_SECURITY`, `CONFIG_LSM`).
- **Hook-based**: Over 200 hooks are defined in `include/linux/lsm_hooks.h`. Each hook is called at a security-relevant kernel operation.
- **Stacking**: The kernel supports stacking multiple LSMs. The capabilities module is always first, followed by "minor" modules (e.g., Yama, LoadPin, Lockdown), and at most one "major" module (SELinux, AppArmor, or Smack).
- **Boot configuration**: The active LSM stack is configured via the `CONFIG_LSM` build option or the `security=` boot parameter. Active modules are listed in `/sys/kernel/security/lsm`.

### 8.2 SELinux (Security-Enhanced Linux)

SELinux implements **mandatory access control** (MAC) based on the Flask security architecture, originally developed by the NSA. It enforces a comprehensive, system-wide security policy that is independent of and superior to traditional DAC (discretionary access control).

#### Core Concepts

- **Security contexts (labels)**: Every process, file, socket, IPC object, and other kernel object is assigned a security context of the form `user:role:type:level` (e.g., `system_u:system_r:httpd_t:s0`).
- **Type Enforcement (TE)**: The primary mechanism — policy rules define which types can access which other types and how (read, write, execute, etc.). Example: `allow httpd_t httpd_config_t:file { read open };`
- **Role-Based Access Control (RBAC)**: Roles group types and control which types a user can transition to.
- **Multi-Level Security (MLS)**: Optional Bell-LaPadula-style sensitivity levels for classified data handling.
- **Policy language**: Policies are written in a declarative language, compiled with `checkpolicy`, and loaded into the kernel via `/sys/fs/selinux/`.

#### Kernel Exploitation Relevance

SELinux can limit the impact of kernel exploits by:
- **Restricting process capabilities**: Even after a privilege escalation, the exploited process may be confined to its original SELinux domain, limiting what it can access.
- **Preventing unauthorized transitions**: Policy controls which domains can execute which binaries and transition to which new domains.
- **Limiting file access**: Even root processes in a confined domain cannot access files outside their policy allowances.

**Limitations**: SELinux cannot prevent a kernel-level exploit that disables SELinux itself by modifying kernel data structures (e.g., zeroing `selinux_enforcing`). It is a defense-in-depth layer, not a standalone kernel protection.

### 8.3 AppArmor

AppArmor implements **path-based MAC** with a simpler model than SELinux. It confines programs based on profiles that specify what files, capabilities, and network access a program may use.

#### Key Properties

- **Path-based** (rather than label-based): Policies reference file paths directly (e.g., `/etc/passwd r,`), making profiles more intuitive to write but less robust against hard links and mount manipulation.
- **Profile modes**: `enforce` (deny and log violations) and `complain` (log but allow).
- **Per-program profiles**: Each confined program has its own profile. Unconfined programs run with standard DAC permissions.
- **No filesystem labeling**: Unlike SELinux, AppArmor does not require extended attributes on every file, simplifying deployment.

AppArmor is the default MAC system on Ubuntu, SUSE, and Debian.

### 8.4 LSMs as Defense Layers Against Exploitation

From an exploitation perspective, LSMs provide:

1. **Reduced blast radius**: Even a successful kernel exploit's impact may be limited by MAC policy that restricts what the compromised process can access.
2. **Seccomp complement**: Combined with seccomp-BPF (Section 9), LSMs and syscall filtering create layered confinement.
3. **Kernel lockdown** (`CONFIG_SECURITY_LOCKDOWN_LSM`): A special LSM that restricts operations that could modify the running kernel — loading unsigned modules, accessing `/dev/mem`, `kexec` of unsigned images, writing to MSRs, etc. This directly protects against post-exploitation persistence.

**Critical caveat**: All LSM-based protections operate within the kernel. A kernel exploit that achieves arbitrary code execution in ring 0 can disable any LSM by modifying kernel data structures. LSMs are defense-in-depth, not a hard security boundary against kernel-level attackers.

---

## 9. seccomp-BPF — Reducing Syscall Attack Surface

### 9.1 Overview

seccomp-BPF (Secure Computing with filters) allows a process to install a BPF (Berkeley Packet Filter) program that filters system calls based on the syscall number and arguments. By restricting which system calls a process can make, seccomp-BPF reduces the **attack surface** of the kernel — if a vulnerability exists in a syscall that the process cannot invoke, it cannot be exploited.

seccomp-BPF was introduced in Linux 3.5 (2012), building on the original `seccomp` strict mode (which only allowed `read()`, `write()`, `exit()`, and `sigreturn()`).

### 9.2 Architecture

A seccomp filter is a classic BPF program that operates on a `struct seccomp_data`:

```c
struct seccomp_data {
    int   nr;                    /* System call number */
    __u32 arch;                  /* AUDIT_ARCH_* value */
    __u64 instruction_pointer;   /* CPU instruction pointer */
    __u64 args[6];               /* System call arguments */
};
```

The BPF program examines these fields and returns one of (in precedence order):

| Return Value | Effect |
|---|---|
| `SECCOMP_RET_KILL_PROCESS` | Kill the entire process (SIGSYS) |
| `SECCOMP_RET_KILL_THREAD` | Kill the calling thread |
| `SECCOMP_RET_TRAP` | Send SIGSYS to the thread |
| `SECCOMP_RET_ERRNO` | Return an error to the caller |
| `SECCOMP_RET_USER_NOTIF` | Notify a supervisor process |
| `SECCOMP_RET_TRACE` | Notify a ptrace tracer |
| `SECCOMP_RET_LOG` | Allow but log the call |
| `SECCOMP_RET_ALLOW` | Allow the call |

### 9.3 Installation

Filters are installed via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` or the `seccomp()` syscall. Prerequisites:

- The process must have called `prctl(PR_SET_NO_NEW_PRIVS, 1)` (to prevent a filter from being used to escalate privileges via setuid binaries) **or** hold `CAP_SYS_ADMIN`.
- Filters are inherited across `fork()` and `execve()`.
- Filters can be layered — additional filters further restrict (never expand) the allowed set.

### 9.4 Security Properties

**Strengths**:

- **TOCTOU-safe**: BPF operates on a snapshot of register values at syscall entry. It cannot dereference user-space pointers, preventing time-of-check-time-of-use attacks.
- **Composable**: Multiple filters can be layered, and the most restrictive return value wins.
- **Widely deployed**: Used by Chrome/Chromium (renderer sandboxing), Docker/containers, systemd services, Firefox, QEMU/KVM, Android's Zygote, and many others.

**Kernel attack surface reduction**:

A typical server process might use only 40-60 unique system calls. A seccomp filter that allows only these calls blocks the remaining ~300+ syscalls from being reachable, eliminating entire vulnerability classes. For example:

- Blocking `mount()`, `umount2()`, `swapon()` prevents exploitation of filesystem-related kernel bugs.
- Blocking `ptrace()` prevents escaping sandboxes via debugging interfaces.
- Blocking `ioctl()` (or specific ioctl commands) eliminates a vast class of driver vulnerabilities.
- Blocking `bpf()` prevents loading of BPF programs that might be used in exploits.

### 9.5 User Notification Mechanism

`SECCOMP_RET_USER_NOTIF` (Linux 5.0) allows a supervisor process to intercept and handle blocked syscalls on behalf of the filtered process. This is used by container runtimes to emulate syscalls like `mount()` without actually granting the capability. The supervisor receives the syscall details via an ioctl on a notification file descriptor and can inject a response (or even inject file descriptors into the target process).

### 9.6 Limitations

- **Argument inspection is limited**: BPF can inspect syscall argument register values but **cannot dereference pointers**. This means it cannot filter based on file paths, ioctl command data, or other memory-resident arguments.
- **Architecture must be checked**: A filter that checks syscall numbers without verifying `seccomp_data.arch` is vulnerable to exploitation via alternative calling conventions (e.g., 32-bit syscalls on a 64-bit kernel) where syscall numbers may overlap with different semantics.
- **vDSO bypass**: Some syscalls (e.g., `clock_gettime()`) may be handled entirely in user-space via the vDSO, bypassing seccomp filters entirely.
- **Not a sandbox by itself**: seccomp-BPF is a syscall filter, not a complete sandbox. It should be combined with namespaces, capabilities dropping, LSMs, and other mechanisms for comprehensive confinement.

---

## 10. CONFIG_INIT_STACK_ALL — Stack Variable Zero-Initialization

### 10.1 Overview

`CONFIG_INIT_STACK_ALL_ZERO` (and its predecessor `CONFIG_INIT_STACK_ALL_PATTERN`) eliminates **uninitialized stack variable** vulnerabilities by having the compiler automatically initialize all local variables to zero (or a pattern) at function entry.

Uninitialized stack variables are a significant source of both information leaks and control flow hijacks:

- **Information leaks**: A local variable that is partially filled and then copied to user-space leaks stale stack contents (which may include kernel pointers, canary values, or other sensitive data).
- **Use of uninitialized memory**: If a local variable is used in a security decision before being initialized, the stale stack value may be attacker-influenced (e.g., by prior syscall stack frames).

### 10.2 History and Evolution

The kernel has gone through several approaches:

| Version | Config Option | Mechanism |
|---|---|---|
| Pre-5.2 | Manual `memset()`/`= {0}` | Developer responsibility |
| 5.2 | `CONFIG_INIT_STACK_ALL` | GCC plugin (`structleak`) with pattern init |
| 5.9 | `CONFIG_INIT_STACK_ALL_ZERO` | Compiler built-in `-ftrivial-auto-var-init=zero` |
| 5.9 | `CONFIG_INIT_STACK_ALL_PATTERN` | `-ftrivial-auto-var-init=pattern` |

The GCC plugin approach (from Kees Cook, based on PaX's STRUCTLEAK) was a stopgap until compiler-native support arrived. Clang added `-ftrivial-auto-var-init=zero` in Clang 11 and GCC added it in GCC 12.

### 10.3 Implementation Details

When `CONFIG_INIT_STACK_ALL_ZERO` is enabled, the compiler inserts initialization code at the beginning of each function to zero all local variables that are not explicitly initialized by the source code. This applies to:

- Scalar variables (`int`, `long`, pointers, etc.)
- Arrays
- Structures and unions (including padding holes)
- Compiler-generated temporaries

The compiler is smart enough to eliminate redundant initializations where it can prove a variable is definitely assigned before use (via standard dead store elimination optimization), minimizing performance impact.

### 10.4 Zero vs. Pattern Initialization

Two modes are available:

- **Zero initialization** (`CONFIG_INIT_STACK_ALL_ZERO`): All uninitialized variables are set to 0. This is the **preferred mode** because:
  - Zero is already the most common intended default value.
  - NULL pointers, false booleans, and empty structures are all-zeros.
  - Reduces information leak severity (leaked zeros are not interesting).
  - Many bugs become "fail-closed" — uninitialized function pointers are NULL rather than stale values, causing a NULL dereference (caught by guard pages) rather than arbitrary code execution.

- **Pattern initialization** (`CONFIG_INIT_STACK_ALL_PATTERN`): Fills with a recognizable pattern (typically `0xAA` or similar). This is better for **bug detection** during development — the distinctive pattern makes it obvious when an uninitialized variable is used — but worse for production security because the non-zero pattern may be a valid pointer on some architectures.

### 10.5 Performance Impact

Benchmarks by Kees Cook and others have shown overhead in the range of **0.5-2%** for typical workloads with zero initialization. The compiler's optimization passes eliminate many initializations that are provably unnecessary, and on modern hardware the cost of a few extra `xor` or `mov` instructions per function is minimal.

The overhead is considered acceptable for the security benefit, and `CONFIG_INIT_STACK_ALL_ZERO` is enabled by default in hardened distribution kernels (Android, Chrome OS, Ubuntu, etc.).

### 10.6 Complementary Features

- **`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`**: Zero-fills heap allocations from the slab and page allocators on allocation, eliminating uninitialized heap variables.
- **`CONFIG_INIT_ON_FREE_DEFAULT_ON`**: Zero-fills memory on free, preventing use-after-free data leaks.
- **`CONFIG_KSTACK_ERASE`** (Linux 5.15): Erases the kernel stack residue on return from syscalls, preventing cross-syscall stack data leakage.

Together with `CONFIG_INIT_STACK_ALL_ZERO`, these features eliminate the entire class of uninitialized memory vulnerabilities and greatly reduce the value of information leaks from kernel memory.

---

## Summary: Defense-in-Depth Matrix

| Mitigation | Attack Class Addressed | Deterministic? | Bypassable With |
|---|---|---|---|
| KASLR | Fixed-address exploitation | No (probabilistic) | Info leak |
| SMEP/SMAP | ret2usr, user data access | Yes (hardware) | ROP to flip CR4 (patched), heap spraying |
| Stack canaries | Linear stack overflow | No (probabilistic) | Canary leak, non-linear write |
| KPTI | Meltdown (speculative read of kernel) | Yes | N/A (mitigates specific HW vuln) |
| Hardened usercopy | Kernel buffer over-read/write to user | Yes | Over-allocated objects |
| Slab freelist random | Heap layout prediction | No (probabilistic) | Large-scale heap spraying |
| Slab freelist hardened | Freelist pointer corruption | Yes (with secret) | Leak of per-cache random |
| kCFI/FineIBT | Indirect call hijacking | Yes (type-based) | Hash collisions, direct calls |
| Shadow Call Stack | Return address corruption | Yes (hardware-backed) | Info leak of shadow stack ptr |
| SELinux/AppArmor | Post-exploitation actions | Yes (policy-based) | Kernel code execution disables LSM |
| seccomp-BPF | Syscall attack surface | Yes (filter-based) | Allowed syscalls still exploitable |
| INIT_STACK_ALL_ZERO | Uninitialized stack variables | Yes | N/A (eliminates the bug class) |

The key principle is **defense in depth**: no single mitigation is sufficient, but their combination forces an attacker to chain multiple primitives — an info leak to bypass KASLR, a ROP chain to bypass SMEP, heap spraying to bypass SMAP, type-compatible gadgets to bypass CFI — making successful exploitation dramatically more difficult, expensive, and fragile.

---

## References

1. Linux Kernel Documentation — Kernel Self-Protection. https://www.kernel.org/doc/html/latest/security/self-protection.html
2. Cook, K. — "Kernel Address Space Layout Randomization." Linux Security Summit 2013. LWN.net, October 2013. https://lwn.net/Articles/569635/
3. Corbet, J. — "The Current State of Kernel Page-Table Isolation." LWN.net, December 2017. https://lwn.net/Articles/741878/
4. Edge, J. — "Hardened Usercopy." LWN.net, August 2016. https://lwn.net/Articles/695991/
5. Linux Kernel Documentation — Linux Security Module Usage. https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html
6. Linux Kernel Documentation — Seccomp BPF. https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
7. Clang Documentation — Control Flow Integrity. https://clang.llvm.org/docs/ControlFlowIntegrity.html
8. Linux Kernel Documentation — L1TF Mitigation. https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html
9. Cook, K. — Kernel Self Protection Project. https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project
10. Linux kernel source: `arch/x86/boot/compressed/kaslr.c`, `arch/x86/include/asm/smap.h`, `mm/usercopy.c`, `mm/slub.c`, `kernel/seccomp.c`
