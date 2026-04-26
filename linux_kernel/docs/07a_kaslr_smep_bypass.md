# Section 7A: Mitigation Bypass Techniques -- KASLR, SMEP, SMAP, and Beyond

## Table of Contents

1. [Overview of the Mitigation Landscape](#1-overview-of-the-mitigation-landscape)
2. [KASLR Bypass Techniques](#2-kaslr-bypass-techniques)
   - 2.1 [Information Leaks via /proc, dmesg, and sysfs](#21-information-leaks-via-proc-dmesg-and-sysfs)
   - 2.2 [Kernel Info-Leak Vulnerabilities](#22-kernel-info-leak-vulnerabilities)
   - 2.3 [EntryBleed (CVE-2022-4543)](#23-entrybleed-cve-2022-4543)
   - 2.4 [Timing-Based KASLR Bypasses](#24-timing-based-kaslr-bypasses)
   - 2.5 [Transient Execution Attacks Against KASLR](#25-transient-execution-attacks-against-kaslr)
   - 2.6 [Weak Entropy and Misconfiguration](#26-weak-entropy-and-misconfiguration)
3. [SMEP Bypass Techniques](#3-smep-bypass-techniques)
   - 3.1 [Understanding SMEP](#31-understanding-smep)
   - 3.2 [ROP-Based SMEP Bypass](#32-rop-based-smep-bypass)
   - 3.3 [CR4 Bit-Flipping (Historical)](#33-cr4-bit-flipping-historical)
   - 3.4 [Stack Pivot Techniques](#34-stack-pivot-techniques)
4. [SMAP Bypass Techniques](#4-smap-bypass-techniques)
   - 4.1 [Understanding SMAP](#41-understanding-smap)
   - 4.2 [Kernel-to-Kernel Copy Strategies](#42-kernel-to-kernel-copy-strategies)
   - 4.3 [addr_limit Overwrite (set_fs bypass)](#43-addr_limit-overwrite-set_fs-bypass)
   - 4.4 [Using Kernel Objects as Pivots](#44-using-kernel-objects-as-pivots)
5. [KPTI Bypass Considerations](#5-kpti-bypass-considerations)
   - 5.1 [KPTI Architecture](#51-kpti-architecture)
   - 5.2 [Mapped Kernel Pages in User Page Tables](#52-mapped-kernel-pages-in-user-page-tables)
   - 5.3 [KPTI and Returning to Userspace](#53-kpti-and-returning-to-userspace)
   - 5.4 [The cpu_entry_area and Non-Randomized Stacks](#54-the-cpu_entry_area-and-non-randomized-stacks)
6. [Bypassing Stack Canaries](#6-bypassing-stack-canaries)
   - 6.1 [Canary Architecture in the Linux Kernel](#61-canary-architecture-in-the-linux-kernel)
   - 6.2 [Information Leak + Overflow](#62-information-leak--overflow)
   - 6.3 [Brute-Forcing Stack Canaries](#63-brute-forcing-stack-canaries)
   - 6.4 [Forking Servers and Canary Reuse](#64-forking-servers-and-canary-reuse)
7. [Bypassing CONFIG_HARDENED_USERCOPY](#7-bypassing-config_hardened_usercopy)
   - 7.1 [What HARDENED_USERCOPY Enforces](#71-what-hardened_usercopy-enforces)
   - 7.2 [Bypass Strategies](#72-bypass-strategies)
8. [Ret2dir: Bypassing SMEP/SMAP via the Physmap](#8-ret2dir-bypassing-smepsmap-via-the-physmap)
   - 8.1 [The Direct Mapping of Physical Memory](#81-the-direct-mapping-of-physical-memory)
   - 8.2 [Ret2dir Attack Methodology](#82-ret2dir-attack-methodology)
   - 8.3 [Constructing Ret2dir Exploits](#83-constructing-ret2dir-exploits)
   - 8.4 [Defenses Against Ret2dir](#84-defenses-against-ret2dir)
9. [Combined Bypass Chains](#9-combined-bypass-chains)
10. [References](#10-references)

---

## 1. Overview of the Mitigation Landscape

The Linux kernel employs a layered defense-in-depth approach against exploitation. Each mitigation addresses a specific class of attack, but attackers have historically been able to chain bypasses to defeat multiple protections simultaneously. The primary mitigations on x86-64 Linux include:

| Mitigation | Type | Purpose |
|---|---|---|
| **KASLR** | Software | Randomize kernel text base address at boot |
| **SMEP** | Hardware (CR4.SMEP) | Prevent kernel from executing userspace pages |
| **SMAP** | Hardware (CR4.SMAP) | Prevent kernel from reading/writing userspace pages |
| **KPTI** | Software (page tables) | Isolate user/kernel page tables to mitigate Meltdown |
| **Stack Canaries** | Compiler | Detect stack buffer overflows before return |
| **HARDENED_USERCOPY** | Software | Validate `copy_to/from_user` bounds against slab/stack |
| **KASLR (memory)** | Software | Randomize physmap, vmalloc, vmemmap regions |

A modern kernel exploit on a fully-hardened x86-64 system typically must bypass **KASLR + SMEP + SMAP + KPTI + Stack Canaries** at minimum. This section provides step-by-step methodologies for each.

---

## 2. KASLR Bypass Techniques

### Background: How KASLR Works

Kernel Address Space Layout Randomization (`CONFIG_RANDOMIZE_BASE`) was introduced for x86 in Linux v3.14 (2013) and enabled by default in v4.12. At boot, the kernel selects a random offset from a set of possible slots:

- **x86-64**: Kernel text is loaded within `0xffffffff80000000` - `0xffffffffc0000000` (1 GiB range), 2 MiB aligned, yielding **512 possible positions**.
- **x86-32**: 256 possible positions.
- **arm64**: Added in v4.6, with separate randomization of the kernel image and linear map.

`CONFIG_RANDOMIZE_MEMORY` (x86-64, since v4.8) additionally randomizes the physmap (direct mapping), vmalloc area, and vmemmap.

KASLR is a **statistical defense**: all kernel symbols maintain fixed offsets relative to the kernel base. A single leaked kernel pointer defeats it completely.

### 2.1 Information Leaks via /proc, dmesg, and sysfs

The most straightforward KASLR bypasses exploit information leaked through system interfaces.

#### /proc/kallsyms

Before `kptr_restrict`, `/proc/kallsyms` directly exposed all kernel symbol addresses:

```
$ cat /proc/kallsyms | head -3
ffffffff81000000 T startup_64
ffffffff81000030 T secondary_startup_64
ffffffff810000e0 T verify_cpu
```

**Mitigation**: `kernel.kptr_restrict`:
- `0`: Kernel pointers exposed to all users (default on older kernels)
- `1`: Kernel pointers hidden from unprivileged users (shown as `0000000000000000`)
- `2`: Kernel pointers hidden from all users including root

Modern distributions set `kptr_restrict=1` by default. However, reading `/proc/kallsyms` as root still reveals the full layout.

#### dmesg / Kernel Log

The kernel message ring buffer (`dmesg`) frequently contains raw kernel pointers from boot messages, driver initialization, and oops traces:

```
[    0.000000] Memory: 2047804K/2096696K available (12300K kernel code, ...)
[    0.000000] virtual kernel memory layout:
[    0.000000]     fixmap  : 0xfff1000000000000 - 0xfff1800000000000   (...)
[    0.000000]     vmalloc : 0xffffc90000000000 - 0xffffe8ffffffffff   (...)
[    0.000000]   .text : 0xffffffff81000000 - 0xffffffff81c04ea7
```

These lines directly reveal the KASLR base. Boot messages about memory regions, driver addresses, and timer handler pointers all leak information.

**Mitigation**: `kernel.dmesg_restrict=1` prevents unprivileged users from reading `dmesg`. This is enabled by default on modern hardened distributions.

**Residual risk**: System log files (e.g., `/var/log/dmesg`, `/var/log/kern.log`) may store boot messages. On Debian/Ubuntu, users in the `adm` group have read access to these files. Additionally, an initscript bug (Debian #867747, 2017-2019) caused `/var/log/dmesg` to be world-readable (`0644`).

#### /proc and /sys Information Leaks

Several `/proc` and `/sys` entries have historically leaked kernel pointers:

| Source | Info Leaked | Status |
|---|---|---|
| `/proc/kallsyms` | All kernel symbols | Gated by `kptr_restrict` |
| `/proc/modules` | Module base addresses | Gated by `kptr_restrict` |
| `/proc/net/tcp` et al. | Socket kernel addresses | Used as opaque handles |
| `/sys/kernel/debug/*` | Various kernel pointers | Restricted since v3.7-rc1 |
| `/proc/PID/stat` | `wchan` (wait channel) | Obfuscated since v4.3 |
| INET_DIAG socket API | Kernel object addresses used as handles | Not fully fixed |

The `%pK` printk format was introduced to gate kernel pointer display on `kptr_restrict`, but many kernel subsystems historically used `%p` (unhashed) or `%px` (explicit raw pointer):

```c
// Safe: respects kptr_restrict
printk("%pK\n", ptr);

// Unsafe: always shows real address (pre-v4.15 hashing)
printk("%p\n", ptr);
```

Since v4.15, `%p` hashes the pointer by default to prevent leaks. However, `%px` still prints raw pointers and exists throughout the kernel source.

#### Triggered Kernel Oops Backtraces

Bugs that trigger a kernel oops (without `panic_on_oops`) dump full backtraces with kernel addresses to `dmesg`:

```
[  213.352742] BUG: unable to handle kernel paging request at 00000000deadbeef
[  213.355689]  [<ffffffff8155372b>] ? panic+0xa7/0x179
[  213.355927]  [<ffffffff810665b3>] ? __wake_up+0x53/0x70
```

These backtraces reveal KASLR-offset addresses of kernel functions. An attacker who can trigger a non-fatal oops (e.g., via crafted syscall arguments exploiting an edge case) and read `dmesg` can trivially derive the kernel base.

### 2.2 Kernel Info-Leak Vulnerabilities

Beyond interfaces, actual kernel bugs frequently leak pointer values. These are regularly discovered and patched:

**Uninitialized stack/heap memory**: When the kernel copies data to userspace from stack or heap buffers that were not fully initialized, stale kernel pointers may be included. Examples:

- **CVE-2020-10732**: Uninitialized heap memory in ELF core dumps. `fill_thread_core_info()` allocated regset buffers with `kmalloc()` without zeroing, leaking several KiB of kernel heap data (potentially containing pointers) into core files readable by unprivileged users.

- **CVE-2017-18344**: Arbitrary read via the timer subsystem. `timer_create` failed to validate `sigevent->sigev_notify`, allowing out-of-bounds access in `show_timer()` (triggered via `/proc/$PID/timers`). This was exploitable to read arbitrary kernel (and physical) memory, defeating KASLR and leaking `/etc/shadow`.

- **CVE-2017-1000380**: `snd_timer_user_read` disclosed uninitialized kernel heap memory through ALSA timer interface.

**Structure padding leaks**: C structures with padding bytes between members may leak uninitialized kernel memory if the padding is not explicitly zeroed before copying to userspace.

**Remote leaks**: CVE-2019-10639 demonstrated that the Linux IP ID generation algorithm used a kernel address as input, allowing remote attackers to infer KASLR offsets from observed IP packet headers.

**msg_msg arbitrary read**: A common modern exploitation technique uses the `msg_msg` kernel structure to achieve arbitrary read. After gaining a use-after-free or heap corruption primitive, an attacker can craft `msg_msg` headers to read out-of-bounds kernel memory, leaking pointers that reveal the KASLR base. This technique was used in exploits for CVE-2021-22555, CVE-2021-26708, and CVE-2021-43267.

### 2.3 EntryBleed (CVE-2022-4543)

EntryBleed is a particularly significant KASLR bypass because it defeats KPTI (which was specifically designed to prevent microarchitectural side-channel KASLR breaks) and works as an unprivileged local attack on Intel systems.

#### Background: KPTI and the Syscall Entry Point

KPTI (Kernel Page Table Isolation) splits user and kernel page tables. The user page tables contain only a minimal set of kernel pages needed for the user-to-kernel transition (syscall/interrupt entry handlers). When the CPU transitions to kernel mode, one of the first instructions switches CR3 to the full kernel page tables.

The critical insight: `entry_SYSCALL_64` -- the 64-bit syscall entry handler -- **must be mapped in user page tables** at its KASLR-randomized virtual address because it executes before the CR3 switch:

```asm
; arch/x86/entry/entry_64.S
ENTRY(entry_SYSCALL_64)
    swapgs
    ; ... a few instructions execute before:
    movq    %rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
    SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp    ; <-- CR3 switch happens here
    ; ...
```

The `entry_SYSCALL_64` symbol resides at a fixed offset from the kernel base (deterministic per kernel build). Its page has the **global bit** set in the page table entry, which protects it from TLB invalidation on CR3 writes.

#### The Attack

The attack leverages the **prefetch side channel** discovered by Daniel Gruss et al. (2016). The x86 `PREFETCHNTA`/`PREFETCHT2` instructions load addresses into the CPU cache. A prefetch completes quickly if the target address is present in the TLB (Translation Lookaside Buffer), but slowly if a page table walk is needed.

**Step-by-step methodology**:

1. **Ensure TLB caching**: Execute a syscall to force `entry_SYSCALL_64` into the instruction TLB. The global bit on this page preserves the TLB entry across CR3 switches.

2. **Scan the address range**: The kernel is guaranteed to reside within `0xffffffff80000000` - `0xffffffffc0000000`. At 1 MiB granularity (`STEP = 0x100000`), this is only 1024 addresses to scan.

3. **Time prefetch instructions**: For each candidate address at offset `entry_SYSCALL_64_offset`:
   ```c
   // Timing the prefetch:
   mfence; rdtscp;   // serialize and read timestamp
   lfence;
   prefetchnta [addr];
   prefetcht2 [addr];
   lfence; rdtscp;   // read timestamp again
   // delta = t_after - t_before
   ```

4. **Identify the minimum**: The address with the lowest average prefetch time corresponds to the page that is **present in the TLB** -- i.e., the page containing `entry_SYSCALL_64`.

5. **Calculate KASLR base**: `kaslr_base = leaked_address - entry_SYSCALL_64_offset`

#### Proof of Concept (simplified)

```c
#define KERNEL_LOWER_BOUND  0xffffffff80000000ull
#define KERNEL_UPPER_BOUND  0xffffffffc0000000ull
#define STEP                0x100000ull
#define ITERATIONS          100

uint64_t sidechannel(uint64_t addr) {
    uint64_t a, b, c, d;
    asm volatile (
        "mfence; rdtscp;"
        "mov %0, rax; mov %1, rdx;"
        "lfence;"
        "prefetchnta qword ptr [%4];"
        "prefetcht2 qword ptr [%4];"
        "lfence; rdtscp;"
        "mov %2, rax; mov %3, rdx; mfence;"
        : "=r"(a), "=r"(b), "=r"(c), "=r"(d) : "r"(addr)
        : "rax", "rbx", "rcx", "rdx");
    return ((d << 32) | c) - ((b << 32) | a);
}

uint64_t leak_syscall_entry(void) {
    uint64_t data[ARR_SIZE] = {0};
    for (int i = 0; i < ITERATIONS; i++) {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++) {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(SYS_getpid);  // prime TLB
            data[idx] += sidechannel(test);
        }
    }
    // Find index with minimum average time
    uint64_t min = ~0ULL, addr = ~0ULL;
    for (int i = 0; i < ARR_SIZE; i++) {
        data[i] /= ITERATIONS;
        if (data[i] < min) { min = data[i]; addr = SCAN_START + i * STEP; }
    }
    return addr;
}
```

#### Key Properties

- **Works with KPTI enabled** (the whole point of the CVE)
- **~100% accuracy** with 100 iterations on tested Intel CPUs
- Tested on: i5-8265U, i7-8750H, i7-9700F, i7-9750H, Xeon E5-2640
- Works across kernel versions: Arch hardened 6.0.12, Ubuntu 5.15, Manjaro 6.0.12, Debian 5.10
- Works in KVM guests (with `-cpu host`)
- Uses `lfence` instead of `cpuid` for VM compatibility (cpuid is emulated)

**Fix status**: As of 2023, a complete fix is difficult because the fundamental issue is that entry handlers must be mapped in user page tables at KASLR-derived addresses. Proposed mitigations include randomizing the virtual address of entry handlers independently of the kernel base, or placing them at a fixed address unrelated to `startup_64`.

### 2.4 Timing-Based KASLR Bypasses

#### Prefetch Side Channel (Gruss et al., 2016)

The foundational work behind EntryBleed. On systems **without KPTI** (or with it disabled), **all** kernel pages remain mapped in user page tables. The prefetch instruction can probe the entire kernel address range:

```
Mapped kernel page   -> fast prefetch (TLB hit after prior kernel execution)
Unmapped address     -> slow prefetch (page table walk, faults silently)
```

This is the technique Google Project Zero used in their CVE-2022-42703 exploit on systems where KPTI was disabled because the CPU had in-silicon Meltdown mitigations.

**Key detail**: Modern CPUs with hardware Meltdown mitigations (e.g., Intel 10th gen+) often boot with `pti=off` since KPTI is "unnecessary." This re-enables the original prefetch attack on the entire kernel address space.

#### Intel TSX (DrK Attack, Jang et al., 2016)

Intel Transactional Synchronization Extensions (TSX) provide hardware transactional memory. The **DrK** (Derandomizing Kernel ASLR) attack exploits the fact that TSX transactions abort differently depending on whether an accessed address is mapped or unmapped:

1. **Begin a TSX transaction** (`xbegin`)
2. **Access a kernel address** inside the transaction
3. **Observe the abort reason**:
   - If the page is mapped: page fault suppressed, transaction aborts with a specific code
   - If the page is unmapped: different abort behavior/timing

The timing difference between these two cases reveals the kernel memory layout. This works even with KPTI because TSX suppresses page faults.

**Status**: Intel disabled TSX by default on many newer CPUs via microcode updates due to MDS (Microarchitectural Data Sampling) vulnerabilities. However, older systems remain vulnerable.

#### Branch Target Buffer (BTB) Attacks (Evtyushkin et al., 2016)

The Branch Target Buffer (BTB) caches branch target predictions. The **Jump Over ASLR** attack exploits BTB aliasing:

1. **Train the BTB** from userspace by executing branches at specific virtual addresses
2. **Trigger kernel execution** at addresses that alias with the training addresses in the BTB
3. **Measure timing** to detect whether the kernel branch targets matched predictions

Since BTB indexing depends on virtual addresses, this reveals the kernel's virtual address layout.

### 2.5 Transient Execution Attacks Against KASLR

#### Meltdown (CVE-2017-5754)

Meltdown exploits out-of-order execution on Intel CPUs to read kernel memory from userspace. Even though the access is architecturally forbidden (generates a fault), the transiently accessed data leaves traces in the CPU cache that can be recovered via Flush+Reload:

```c
// Simplified Meltdown gadget:
char *probe_array;  // 256 * PAGE_SIZE, flushed from cache
char kernel_byte = *(char*)kernel_addr;  // faults, but transiently executes
char dummy = probe_array[kernel_byte * PAGE_SIZE];  // encodes byte in cache
// Flush+Reload probe_array to recover kernel_byte
```

**Mitigation**: KPTI (removes kernel mappings from user page tables) + in-silicon fixes on newer Intel CPUs.

#### ZombieLoad, RIDL, Fallout (MDS Attacks)

Microarchitectural Data Sampling attacks leak data from internal CPU buffers (line fill buffers, store buffers, load ports). These can be used to leak kernel addresses being processed by other hyperthreads or during speculative execution:

- **ZombieLoad**: Samples data from the line fill buffer
- **RIDL**: Exploits rogue in-flight data loads
- **Fallout**: Leaks from the store buffer

All of these can be used to break KASLR by leaking kernel pointers observed during kernel execution.

#### RETBLEED (CVE-2022-29900/29901)

RETBLEED exploits speculative execution through return instructions on AMD and Intel CPUs. Return instructions can be mispredicted to speculatively execute at attacker-chosen addresses, leaking information through cache side channels. This can be used to infer kernel addresses.

### 2.6 Weak Entropy and Misconfiguration

#### Limited Slot Count

On x86-64 with the default 1 GiB `RANDOMIZE_BASE_MAX_OFFSET` and 2 MiB alignment, KASLR has only **512 possible positions** -- approximately **9 bits of entropy**. This is far below the 28+ bits recommended for effective ASLR.

#### Boot-Time Entropy Failures

On arm64, if `get_kaslr_seed()` fails (e.g., no hardware RNG available), KASLR may silently be disabled. Seth Jenkins (Project Zero, 2025) demonstrated that on Google Pixel devices, the bootloader loads the kernel at a static physical address, making kernel virtual addresses fully predictable even with KASLR enabled because the arm64 linear map is not independently randomized when memory hotplug is supported.

#### FG-KASLR (Function Granular KASLR)

FG-KASLR patches (proposed 2020, not yet merged as of 2026) would randomize individual function positions within the kernel text, making a single pointer leak insufficient to derive all function addresses. However:
- Symbols before `__startup_secondary_64` are not randomized
- Kernel data (e.g., `modprobe_path`, `core_pattern`) remains at fixed offsets from the base
- Module functions are randomized independently

---

## 3. SMEP Bypass Techniques

### 3.1 Understanding SMEP

Supervisor Mode Execution Prevention (SMEP), introduced in Intel Ivy Bridge (2012), prevents the kernel (CPL 0) from executing pages that have the User bit set in their page table entries. SMEP is controlled by bit 20 of the CR4 register:

```
CR4.SMEP (bit 20) = 1  -->  kernel cannot execute user pages
```

Before SMEP, the classic **ret2usr** attack was trivial: corrupt a kernel function pointer to point to shellcode mapped in userspace. With SMEP, attempting to execute userspace memory from kernel mode triggers a page fault:

```
BUG: unable to handle kernel paging request at 00000000004014c4
Oops: 0011 [#1] SMP
```

The error code `0x11` decodes to: `PF_PROT | PF_INSTR` (protection fault during instruction fetch, in kernel mode, from a user-accessible page).

### 3.2 ROP-Based SMEP Bypass

The primary modern technique for bypassing SMEP is **Return-Oriented Programming (ROP)** using gadgets from the kernel text itself. Since the kernel text is in kernel-mode pages, executing it does not violate SMEP.

#### Step 1: Obtain a Stack Overflow or Control of the Stack

A stack buffer overflow in the kernel (e.g., in a syscall handler) allows overwriting the return address. Alternatively, control of a function pointer can be combined with a **stack pivot** to redirect RSP to attacker-controlled data in kernel memory.

#### Step 2: Construct a ROP Chain

Common ROP chain goals:

**Option A: Disable SMEP via CR4 write** (see Section 3.3)

**Option B: Elevate privileges directly via ROP**:
```
// ROP chain to call commit_creds(prepare_kernel_cred(0)):
pop rdi; ret;        // gadget 1: set RDI = 0
0x0000000000000000   // NULL argument
<prepare_kernel_cred> // call prepare_kernel_cred(NULL)
mov rdi, rax; ret;   // gadget 2: move result to RDI
<commit_creds>        // call commit_creds(new_cred)
<kpti_trampoline>     // return to userspace cleanly
```

**Option C: Overwrite modprobe_path**:
If an arbitrary write primitive exists (even a constrained one), overwriting `modprobe_path` to point to an attacker-controlled script is simpler than a full ROP chain. The kernel will execute the script as root when an unknown binary format is encountered:
```c
// In exploit: trigger AAW to write "/tmp/pwn\0" to modprobe_path
// Then: execve("/tmp/trigger")  where trigger has header 0xFFFFFFFF
// Kernel runs: /tmp/pwn as root
```

#### Step 3: Return to Userspace

After privilege escalation, the ROP chain must cleanly return to userspace. On KPTI-enabled systems, this requires using the kernel's own return-to-user trampoline (the `swapgs_restore_regs_and_return_to_usermode` path) rather than a raw `iretq`, because KPTI requires switching back to user page tables via CR3.

### 3.3 CR4 Bit-Flipping (Historical)

On older kernels without CR4 pinning, a ROP chain could disable SMEP by clearing CR4 bit 20:

```asm
; ROP gadget sequence to disable SMEP:
pop rdi              ; load desired CR4 value (with SMEP bit cleared)
mov cr4, rdi         ; write to CR4 -- SMEP disabled
ret                  ; continue to userspace shellcode
```

The attacker would:
1. Read the current CR4 value (often `0x1407f0` or similar)
2. Clear bit 20: `new_cr4 = old_cr4 & ~(1 << 20)`
3. Write it via a `mov cr4, rdi` gadget

**Mitigation**: Modern kernels (v4.0+) implement **CR4 pinning** via `native_write_cr4()` which checks for and restores critical bits:

```c
void native_write_cr4(unsigned long val)
{
    unsigned long bits_changed = val ^ cr4_read_shadow();
    // Warn and restore if SMEP/SMAP bits were changed
    if (unlikely(bits_changed & CR4_PINNED_MASK)) {
        bits_changed &= ~CR4_PINNED_MASK;
        val = (val & ~CR4_PINNED_MASK) | (cr4_read_shadow() & CR4_PINNED_MASK);
    }
    __write_cr4(val);
}
```

However, if the attacker can find a **raw `mov cr4, rdi` gadget** (a `0f 22 e7` byte sequence) anywhere in the kernel text that was not generated by the `native_write_cr4` wrapper, the pinning check is bypassed. Such "unintended" gadgets can occur within multi-byte instructions that happen to contain the right byte sequence. Tools like ROPgadget and ropper can search for these.

With modern kernels and CONFIG_STATIC_CALL, finding usable raw CR4 gadgets has become harder but remains theoretically possible.

### 3.4 Stack Pivot Techniques

When the initial vulnerability provides control of a function pointer (e.g., via use-after-free or type confusion on a vtable) but not direct stack control, a **stack pivot** is needed to redirect RSP to attacker-controlled memory containing the ROP chain.

Common pivot gadgets:
```asm
xchg rax, rsp; ret       ; swap RSP with RAX (if RAX is controlled)
mov rsp, [rdi+0x...]; ret ; dereference controlled pointer
leave; ret                ; mov rsp, rbp; pop rbp; ret
                          ; (if RBP points to attacker data)
```

The challenge is that the pivot destination must be in **kernel memory** (SMAP prevents using userspace). Common targets:

- **Pipe buffer pages**: `splice()` / `pipe()` can be used to place attacker-controlled data in kernel pages (allocated via the page allocator)
- **msg_msg / msg_msgseg**: Messages sent via `msgsnd()` place attacker data in kernel heap objects
- **Physmap (ret2dir)**: See Section 8
- **cpu_entry_area stacks**: Non-randomized kernel stacks at known addresses (See Section 5.4)

---

## 4. SMAP Bypass Techniques

### 4.1 Understanding SMAP

Supervisor Mode Access Prevention (SMAP), introduced in Intel Broadwell (2014), prevents the kernel from **reading or writing** user-mode pages unless explicitly permitted. SMAP is controlled by CR4 bit 21 and temporarily toggled via the AC flag in EFLAGS:

```
CR4.SMAP = 1       --> kernel cannot read/write user pages
EFLAGS.AC = 1      --> temporarily allow access (used by copy_to/from_user)
stac                --> Set AC flag (allow access)
clac                --> Clear AC flag (deny access)
```

The `copy_to_user()` and `copy_from_user()` functions bracket their actual memory copy with `stac`/`clac` to temporarily permit access to user pages.

SMAP is a much stronger defense than SMEP because it prevents the kernel from **reading** attacker-controlled data in userspace, not just executing it. This blocks:
- Placing fake kernel structures (vtables, function pointers) in userspace
- Placing ROP chains in userspace for stack pivots
- Using userspace as a data staging area

### 4.2 Kernel-to-Kernel Copy Strategies

With SMAP, all attacker-controlled data for exploitation must reside in **kernel memory**. Techniques to place controlled data in kernel space:

#### Pipe Buffers
```c
int pipes[2];
pipe(pipes);
write(pipes[1], payload, sizeof(payload));
// payload is now in a kernel page (pipe_buffer)
```
Pipe buffer pages are allocated from the page allocator. By spraying many pipes, an attacker can fill known slab caches and influence page allocator behavior.

#### msg_msg Spray
```c
struct msgbuf {
    long mtype;
    char mtext[SIZE];
};
struct msgbuf msg;
msg.mtype = 1;
memset(msg.mtext, 'A', SIZE);
// Place controlled bytes at specific offsets:
*(uint64_t*)(msg.mtext + OFFSET) = gadget_addr;
msgsnd(qid, &msg, SIZE, 0);
// Data now in a kernel msg_msg or msg_msgseg object
```

#### Add-Key / keyctl
```c
// add_key places data in kernel keyring objects
add_key("user", "description", payload, payload_len, KEY_SPEC_PROCESS_KEYRING);
```

#### userfaultfd / FUSE
`userfaultfd` and FUSE can be used to **stall kernel execution** at precise points during `copy_from_user`, allowing the attacker to race and manipulate kernel state while the kernel is waiting for the user page. This is critical for many heap exploitation techniques.

### 4.3 addr_limit Overwrite (set_fs bypass)

On older kernels (pre-v5.10), each thread had an `addr_limit` field in `thread_info` (later moved to `task_struct`) that bounded the valid range for `copy_to/from_user`. For user tasks, `addr_limit` was set to `USER_DS` (`0x00007ffffffff000`). Setting it to `KERNEL_DS` (`0xffffffffffffffff`) allowed syscalls to read/write arbitrary kernel memory:

```c
// If we can corrupt addr_limit to KERNEL_DS:
set_fs(KERNEL_DS);  // addr_limit = 0xffffffffffffffff

// Now copy_to_user / copy_from_user accept kernel addresses:
// read kernel memory:
read(fd, kernel_addr, len);  // copy_to_user with kernel addr as "user" ptr
// write kernel memory:
write(fd, kernel_addr, len); // copy_from_user with kernel addr as "user" ptr
```

This effectively gave **arbitrary kernel read/write** through normal syscalls. Many exploits (2015-2020 era) targeted `addr_limit` corruption because:
1. Its location was deterministic (relative to the kernel stack pointer)
2. A single overwrite defeated both SMAP (software) and KASLR (via reading `init_task` and walking structures)

**Mitigation**: `addr_limit` / `set_fs()` was removed in v5.10+ (2020). The kernel now uses `access_ok()` checks that don't depend on a per-thread variable, and `uaccess_begin`/`uaccess_end` toggle hardware SMAP directly.

### 4.4 Using Kernel Objects as Pivots

With SMAP preventing userspace data access, modern exploits use kernel objects at known (or leaked) addresses as pivots:

1. **Spray kernel objects** with controlled content (msg_msg, pipe buffers, keyctl)
2. **Leak the address** of one such object (via info leak or relative offset calculation)
3. **Redirect control flow** (function pointer overwrite, ROP) to use the kernel object as a "fake" structure or ROP chain staging area

This is significantly more complex than pre-SMAP exploitation but is the standard approach in modern kernel exploitation.

---

## 5. KPTI Bypass Considerations

### 5.1 KPTI Architecture

Kernel Page Table Isolation (KPTI, formerly KAISER) was introduced in Linux 4.15 (January 2018) primarily to mitigate Meltdown. KPTI maintains **two sets of page tables** per process:

| Page Table Set | Contents | When Active |
|---|---|---|
| **Kernel page tables** | Full kernel + user mappings | During kernel execution |
| **User page tables** | User mappings + minimal kernel stubs | During userspace execution |

The user page tables contain only:
- Syscall/interrupt entry points (`entry_SYSCALL_64`, IDT handlers)
- The per-CPU entry trampoline code
- The per-CPU `cpu_entry_area` (including exception stacks)
- GDT, IDT, TSS
- A few other essential pages

Switching between page tables is done by writing to CR3. The KPTI implementation uses the PCID (Process-Context Identifier) feature or bit 12 of CR3 to select between the two tables without full TLB flush.

### 5.2 Mapped Kernel Pages in User Page Tables

The minimal kernel pages mapped in user page tables are the primary attack surface for microarchitectural side channels (as demonstrated by EntryBleed). Key mapped regions:

- `entry_SYSCALL_64` at its KASLR-randomized address (the EntryBleed target)
- Interrupt handlers
- NMI/debug exception handlers
- The `cpu_entry_area` (fixed virtual address, pre-v5.x; see below)

### 5.3 KPTI and Returning to Userspace

KPTI introduces a critical constraint for kernel exploits: **you cannot simply `iretq` back to userspace** because the kernel page tables are active and user pages may not be fully set up. The exploit must use the kernel's own KPTI-aware return path:

```asm
; The KPTI return trampoline (swapgs_restore_regs_and_return_to_usermode):
;   1. Restores general purpose registers from pt_regs on the stack
;   2. Switches CR3 to user page tables
;   3. Executes swapgs
;   4. Executes iretq
```

Exploit ROP chains targeting KPTI systems must end by jumping to this trampoline with a properly constructed `pt_regs` frame on the stack:

```
[RSP+0x00] -> RIP (user return address)
[RSP+0x08] -> CS  (user code segment, usually 0x33)
[RSP+0x10] -> RFLAGS
[RSP+0x18] -> RSP (user stack pointer)
[RSP+0x20] -> SS  (user stack segment, usually 0x2b)
```

The address of the KPTI trampoline (`swapgs_restore_regs_and_return_to_usermode`) must be known, requiring a KASLR leak.

### 5.4 The cpu_entry_area and Non-Randomized Stacks

A critical observation by Seth Jenkins (Google Project Zero, CVE-2022-42703 exploit) is that the `cpu_entry_area` (CEA) -- containing exception and syscall entry stacks -- is mapped at a **static, non-randomized virtual address**:

```
cpu_entry_area mapping: 0xfffffe0000000000 - 0xfffffe7fffffffff
```

Each CPU has its own entry area containing:
- **DB (debug) exception stack**: Used when hardware breakpoints fire
- **NMI stack**, **DF (double fault) stack**, etc.
- **Entry stack**: Used for initial syscall/interrupt handling

**Exploitation technique (Jenkins, 2022)**:

1. **Set a hardware breakpoint** (via `ptrace`) at a known user address accessed during `copy_to_user`
2. When the kernel hits the breakpoint during `copy_to_user`, it switches to the **DB exception stack** at the known CEA address
3. The kernel saves general-purpose registers (including RCX, which holds the copy length) onto this stack
4. Use an **arbitrary write primitive** to corrupt the saved RCX value at the known stack address
5. When the kernel returns from the exception, it restores the corrupted RCX, causing `copy_to_user` to copy too much data -- **leaking kernel stack contents** (including return addresses and the stack canary)
6. **Invert the technique**: corrupt `copy_from_user` length to cause a **stack buffer overflow**, bypassing canaries (already leaked) and overwriting the return address

This technique works without knowing KASLR because the CEA stacks are at fixed addresses. Combined with the stack leak, it provides both KASLR defeat and a stack overflow -- a complete exploit primitive.

**Proposed mitigation**: Randomize the per-CPU `cpu_entry_area` location. However, this is insufficient against local attackers who can use prefetch side channels to locate the randomized CEA (as demonstrated by Jenkins).

---

## 6. Bypassing Stack Canaries

### 6.1 Canary Architecture in the Linux Kernel

The Linux kernel uses **stack canaries** (also called stack cookies or stack protectors) to detect stack buffer overflows. Controlled by `CONFIG_STACKPROTECTOR` and `CONFIG_STACKPROTECTOR_STRONG`, the compiler inserts canary checks around functions that use stack buffers:

```c
void vulnerable_function(void) {
    unsigned long canary = __stack_chk_guard;  // load canary
    char buf[64];
    // ... function body ...
    if (canary != __stack_chk_guard)           // check canary
        __stack_chk_fail();                    // panic / kill
}
```

On x86-64 Linux, the canary value is stored in the per-CPU area, accessed via the GS segment:

```asm
mov rax, gs:[0x28]        ; load canary from per-CPU data
mov [rsp+0x...], rax      ; store on stack (canary slot)
; ... function body ...
xor rax, [rsp+0x...]      ; compare with stored value
jne __stack_chk_fail      ; branch to failure handler if mismatch
```

The canary is:
- **Per-task**: Stored in `task_struct->stack_canary` (or per-CPU, depending on configuration)
- **Generated at boot or fork**: Randomized when new tasks are created
- **64 bits wide** on x86-64 (with the low byte typically 0x00 to stop string operations)

### 6.2 Information Leak + Overflow

The most reliable canary bypass is to **leak the canary value** before performing the overflow:

#### Method 1: Arbitrary Read Primitive
If the exploit has an arbitrary read (e.g., from a use-after-free with `msg_msg`), the canary can be read directly from the kernel stack or per-CPU area.

#### Method 2: Stack Data Leak via CEA (Jenkins Technique)
As described in Section 5.4, corrupting `copy_to_user` length via the non-randomized CEA DB exception stack causes excessive data to be copied to userspace, including the stack canary.

#### Method 3: Sequential/Partial Overwrite
In some vulnerability scenarios (e.g., off-by-one, partial overwrite), the canary may be partially preserved or the overflow can be precisely controlled to not disturb it.

#### Method 4: Format String Leaks
If a kernel format string vulnerability exists (rare in modern kernels), `%p` specifiers can be used to read stack values including the canary.

Once the canary value is known, the overflow payload simply includes the correct canary at the expected stack offset:

```
[buffer padding] [correct canary] [saved RBP] [ROP chain / return address]
```

### 6.3 Brute-Forcing Stack Canaries

Brute-forcing a 64-bit canary is computationally infeasible in most scenarios because an incorrect guess crashes the kernel. However, in specific circumstances:

#### Byte-at-a-Time Brute Force (Forking Servers)
In user-space forking servers (where children inherit the parent's canary), each child can guess one byte at a time. The kernel analog does not directly apply because:
- Kernel canaries are per-task (re-randomized on fork in modern kernels)
- A wrong guess causes a kernel panic or oops, not just a child crash

#### Known-Configuration Brute Force
With only 512 KASLR slots and knowledge of the canary generation algorithm, an attacker with repeated boot access (e.g., VM restart loops) could potentially brute-force both KASLR and the canary. This is primarily a threat model for KCTF-style environments.

### 6.4 Forking Servers and Canary Reuse

In user-space programs, `fork()` creates a child with the **same canary** as the parent. This enables byte-at-a-time brute forcing (sending 256 guesses per byte, 2048 attempts total for a 64-bit canary).

In the kernel context, this property is relevant when:
- Kernel threads are created via `kernel_thread()`/`kthread_create()` and inherit stack canary values
- Containerized workloads restart after crashes, potentially reusing the same canary if the container runtime doesn't trigger a full kernel restart

---

## 7. Bypassing CONFIG_HARDENED_USERCOPY

### 7.1 What HARDENED_USERCOPY Enforces

`CONFIG_HARDENED_USERCOPY` (merged in v4.8, 2016) adds runtime checks to `copy_to_user()` and `copy_from_user()` to ensure the kernel buffer:

1. **Is within a valid slab allocation** (not overflowing into adjacent objects)
2. **Is within the current task's kernel stack** (if a stack buffer)
3. **Does not span multiple slab objects** (cross-cache checks)
4. **Is not in the kernel text segment** (prevents leaking `.text`)

The checks are implemented in `__check_object_size()`:

```c
void __check_object_size(const void *ptr, unsigned long n, bool to_user)
{
    // Check if ptr is in the kernel text
    if (is_kernel_rodata(ptr))
        usercopy_abort("rodata", ...);

    // Check if within a slab object
    if (is_slab_page(virt_to_head_page(ptr))) {
        check_slab_object(ptr, n);
        return;
    }

    // Check if within the current stack
    check_stack_object(ptr, n);
}
```

### 7.2 Bypass Strategies

#### Exploit Primitives That Avoid copy_to/from_user
Many modern exploitation techniques avoid `copy_to/from_user` entirely:
- **Direct kernel object manipulation**: Corrupt kernel structures via heap overflow or UAF without going through usercopy
- **modprobe_path overwrite**: Only requires an arbitrary write to a kernel data symbol
- **msg_msg**: Reading data via `msgrcv()` uses internal kernel copy functions, not `copy_to_user` in the hardened sense

#### Use Objects Within the Same Slab
`HARDENED_USERCOPY` validates that the copy stays within a single slab object. Exploits that corrupt **within** a slab object (e.g., overflowing a field within the same allocated structure) are not caught.

#### Cross-Cache Attacks Post-Slab-Freeing
After freeing a slab object and reclaiming the underlying page with a different allocation, `HARDENED_USERCOPY` checks against the **new** slab metadata. If the reclaiming allocation is larger, the check may pass for a larger region.

#### Exploit Timing Windows
If the kernel checks object validity at one point but the state changes before the actual copy (TOCTOU), the check can be bypassed. This is rare in practice due to the checks being inline with the copy.

#### CONFIG_HARDENED_USERCOPY_FALLBACK
Some distributions enable `CONFIG_HARDENED_USERCOPY_FALLBACK`, which only warns (rather than kills) on violations -- providing no actual protection.

---

## 8. Ret2dir: Bypassing SMEP/SMAP via the Physmap

### 8.1 The Direct Mapping of Physical Memory

The Linux kernel maintains a **direct mapping (physmap)** of all physical memory into the kernel's virtual address space. On x86-64:

```
Direct mapping of physical memory:
  ffff888000000000 - ffffc87fffffffff  (64 TiB)    [default]
```

With `CONFIG_RANDOMIZE_MEMORY`, the physmap base is randomized but remains within a known range. The physmap identity-maps physical RAM:

```
physmap_base + phys_addr  ==  kernel virtual address
```

**Critical property**: When a userspace process allocates memory (e.g., via `mmap`), the physical page frames backing that memory are **also accessible through the physmap**. The same physical page has two virtual addresses:
- A userspace virtual address (mapped via the process's page tables)
- A kernel virtual address in the physmap (mapped via the kernel's direct mapping)

### 8.2 Ret2dir Attack Methodology

The **ret2dir** (return-to-direct-mapped memory) attack, published by Kemerlis et al. (USENIX Security 2014), exploits this dual mapping to bypass **all** userspace execution/access prevention mechanisms simultaneously:

**SMEP bypass**: Instead of redirecting kernel execution to a userspace virtual address (blocked by SMEP), redirect it to the **physmap alias** of the same physical page. The physmap is in kernel virtual address space with supervisor-mode page table entries, so SMEP does not apply.

**SMAP bypass**: Similarly, instead of reading attacker data from userspace addresses (blocked by SMAP), the kernel reads the same data via its physmap address.

**Also bypasses**: KERNEXEC, UDEREF, PXN (ARM), and kGuard.

#### Step-by-Step Attack

1. **Allocate userspace memory** with the desired payload (shellcode or fake structures):
   ```c
   void *payload = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
   memcpy(payload, shellcode, shellcode_len);
   ```

2. **Determine the physical address** of the userspace page. Methods include:
   - Reading `/proc/self/pagemap` (requires `CAP_SYS_ADMIN` since v4.0)
   - Exploiting a kernel info leak that reveals physical addresses
   - **Spraying**: Allocating large amounts of userspace memory to probabilistically cover the physical address space, then guessing physmap offsets

3. **Calculate the physmap virtual address**:
   ```c
   uint64_t physmap_base = 0xffff888000000000;  // default, or leaked
   uint64_t physmap_addr = physmap_base + physical_address;
   ```

4. **Redirect kernel execution/data access** to the physmap address:
   - For code execution: Set a corrupted function pointer to `physmap_addr`
   - For fake data structures: Set a corrupted data pointer to `physmap_addr`

5. **The kernel accesses the physmap address**, which maps to the same physical page as the attacker's userspace allocation. The payload executes or the fake structure is used -- all in "kernel" virtual address space, bypassing SMEP/SMAP.

### 8.3 Constructing Ret2dir Exploits

#### Physmap Spray (Without /proc/self/pagemap)

When the physical address cannot be directly determined, the attacker **sprays userspace memory** to cover a large portion of the physical address space:

```c
#define SPRAY_SIZE (256 * 1024 * 1024)  // 256 MiB
#define PAGE_SIZE 4096

void *spray = mmap(NULL, SPRAY_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);

// Fill every page with a NOP sled + payload
for (size_t i = 0; i < SPRAY_SIZE; i += PAGE_SIZE) {
    // NOP sled
    memset(spray + i, 0x90, PAGE_SIZE - shellcode_len);
    // Shellcode at end of page
    memcpy(spray + i + PAGE_SIZE - shellcode_len, shellcode, shellcode_len);
}
```

By spraying hundreds of MiB, the attacker ensures that **some** physmap address will map to a sprayed page. The exploit then "guesses" physmap addresses (with the spray improving odds to near-certainty for large sprays).

#### Determining Physmap Base

With `CONFIG_RANDOMIZE_MEMORY`, the physmap base is randomized. Methods to determine it:
- **Leak `page_offset_base`**: A kernel global variable holding the physmap base
- **Kernel info leak**: Any leaked physmap pointer reveals the offset
- **Brute force**: The randomization has limited entropy (9-10 bits for physmap), making spraying feasible

### 8.4 Defenses Against Ret2dir

#### Exclusive Page Frame Ownership (XPFO)

Kemerlis et al. proposed **XPFO** -- an exclusive page frame ownership scheme that prevents simultaneous mapping of physical pages in both userspace and the physmap:

- When a page is allocated to userspace, it is **unmapped from the physmap**
- When the page is freed back to the kernel, it is **remapped in the physmap**

This fundamentally breaks ret2dir by eliminating the dual mapping. However, XPFO has not been merged into mainline Linux due to performance concerns (TLB shootdowns for every page allocation/free).

#### CONFIG_RANDOMIZE_MEMORY

Randomizing the physmap base adds uncertainty to physmap address calculation, but the limited entropy (10-12 bits) is overcome by large sprays.

#### KFENCE, KASAN

Kernel address sanitizers can detect some out-of-bounds accesses that would be used to set up ret2dir conditions, but they don't prevent the physmap mapping itself.

---

## 9. Combined Bypass Chains

Modern kernel exploits on fully hardened systems (KASLR + SMEP + SMAP + KPTI + Canaries) typically require chaining multiple bypasses:

### Example Chain 1: Heap Vulnerability on Modern x86-64

```
1. TRIGGER:   Use-after-free or heap overflow in kernel subsystem
2. KASLR:     Leak kernel base via msg_msg arbitrary read
                (or EntryBleed prefetch side channel)
3. CANARY:    Leak stack canary via msg_msg read of task stack
                (or via CEA DB exception stack corruption)
4. SMAP:      Place ROP chain in kernel memory via pipe buffer spray
5. SMEP:      Execute ROP chain using kernel gadgets (no user code)
6. ESCALATE:  ROP to commit_creds(prepare_kernel_cred(0))
                or overwrite modprobe_path
7. KPTI:      Return via swapgs_restore_regs_and_return_to_usermode
8. CLEANUP:   Repair corrupted kernel state to avoid crashes
```

### Example Chain 2: Stack Overflow via CEA (Jenkins, 2022)

```
1. TRIGGER:   CVE-2022-42703 UAF -> arbitrary write via down_read_trylock
2. KASLR:     Prefetch side channel (no KPTI on modern CPUs)
3. WRITE:     Corrupt saved RCX on DB exception stack (known address in CEA)
4. LEAK:      copy_to_user overread leaks stack canary + return addresses
5. OVERFLOW:  Corrupt copy_from_user length -> stack buffer overflow
6. SMEP+CANARY: ROP chain with known canary
7. ESCALATE:  ROP chain for privilege escalation
```

### Example Chain 3: Ret2dir (Legacy but Effective)

```
1. TRIGGER:   Kernel pointer corruption via heap vulnerability
2. KASLR:     Leak physmap base (page_offset_base) or kernel pointer
3. SMEP+SMAP: Spray userspace memory, redirect kernel to physmap alias
4. EXECUTE:   Shellcode runs from physmap address (kernel virtual space)
5. ESCALATE:  commit_creds(prepare_kernel_cred(0)) from shellcode
6. RETURN:    iretq / KPTI trampoline back to userspace
```

---

## 10. References

### KASLR

1. Cook, K. "Kernel address space layout randomization." Linux Security Summit, 2013. https://lwn.net/Articles/569635/
2. bcoles. "KASLD: Kernel Address Space Layout Derandomization." https://github.com/bcoles/kasld
3. grsecurity. "KASLR: An Exercise in Cargo Cult Security." 2013. https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
4. Jenkins, S. "Defeating KASLR by Doing Nothing at All." Project Zero, 2025.

### EntryBleed

5. Liu, W. "EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)." https://www.willsroot.io/2022/12/entrybleed.html
6. Liu, W., Ravichandran, J., Yan, M. "EntryBleed: A Universal KASLR Bypass against KPTI on Linux." HASP 2023 (Best Paper Award). https://dl.acm.org/doi/pdf/10.1145/3623652.3623669

### Prefetch and Timing Side Channels

7. Gruss, D., Maurice, C., Fogh, A. "Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR." CCS 2016. https://gruss.cc/files/prefetch.pdf
8. Jang, Y., Lee, S., Kim, T. "Breaking Kernel Address Space Layout Randomization with Intel TSX." CCS 2016 (DrK).
9. Evtyushkin, D., Ponomarev, D., Abu-Ghazaleh, N. "Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR." MICRO 2016.

### Transient Execution

10. Lipp, M. et al. "Meltdown: Reading Kernel Memory from User Space." USENIX Security 2018.
11. Kocher, P. et al. "Spectre Attacks: Exploiting Speculative Execution." IEEE S&P 2019.
12. van Schaik, S. et al. "RIDL: Rogue In-Flight Data Load." IEEE S&P 2019.
13. Schwarz, M. et al. "ZombieLoad: Cross-Privilege-Boundary Data Sampling." CCS 2019.
14. Wikner, J., Razavi, K. "RETBLEED: Arbitrary Speculative Code Execution with Return Instructions." USENIX Security 2022.
15. Lipp, M., Gruss, D., Schwarz, M. "AMD Prefetch Attacks through Power and Time." USENIX Security 2022.

### SMEP/SMAP Bypass

16. Kemerlis, V.P., Polychronakis, M., Keromytis, A.D. "ret2dir: Rethinking Kernel Isolation." USENIX Security 2014.
17. Fabretti, N. "CVE-2017-11176: A step-by-step Linux Kernel exploitation (part 4/4)." Lexfo, 2018. https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part4.html

### KPTI / cpu_entry_area

18. Jenkins, S. "Exploiting CVE-2022-42703 - Bringing back the stack attack." Project Zero, 2022. https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html
19. Linux Kernel Documentation. "Kernel Self-Protection." https://www.kernel.org/doc/html/latest/security/self-protection.html

### Stack Canaries

20. Hund, R., Willems, C., Holz, T. "Practical Timing Side Channel Attacks Against Kernel Space ASLR." IEEE S&P 2013.

### modprobe_path and Exploitation Techniques

21. sam4k. "Kernel Exploitation Techniques: modprobe_path." https://sam4k.com/like-techniques-modprobe_path/
22. Konovalov, A. "CVE-2017-18344: Exploiting an arbitrary-read vulnerability in the Linux kernel timer subsystem." 2018. https://xairy.io/articles/cve-2017-18344
23. willsroot. "CVE-2022-0185 - Winning a $31337 Bounty after Pwning Ubuntu and Escaping Google's KCTF Containers." 2022.
24. Popov, A. "Four Bytes of Power: Exploiting CVE-2021-26708 in the Linux kernel." 2021.

### HARDENED_USERCOPY

25. Cook, K. "CONFIG_HARDENED_USERCOPY." Kernel commit, 2016.

### General Kernel Exploitation

26. Nikolenko, V. "Linux Kernel Exploitation." DUASYNT training materials.
27. Canella, C. "Hardening the Kernel Against Unprivileged Attacks." PhD thesis, TU Graz, 2022.
28. Canella, C., Schwarz, M., Haubenwallner, M. "KASLR: Break It, Fix It, Repeat." AsiaCCS 2020.

---

*This document is part of a comprehensive research report on Linux kernel vulnerability classes and exploitation techniques. All techniques described are for authorized security research and educational purposes only.*
