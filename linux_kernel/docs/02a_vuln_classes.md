# Common Linux Kernel Vulnerability Classes

## Classification, Taxonomy, and Exploitation Characteristics

---

## Table of Contents

1. [Taxonomy of Kernel Vulnerabilities](#1-taxonomy-of-kernel-vulnerabilities)
2. [Buffer Overflows in Kernel Context](#2-buffer-overflows-in-kernel-context)
3. [Use-After-Free Vulnerabilities](#3-use-after-free-vulnerabilities)
4. [Integer Overflows and Underflows](#4-integer-overflows-and-underflows)
5. [NULL Pointer Dereferences](#5-null-pointer-dereferences)
6. [Type Confusion Vulnerabilities](#6-type-confusion-vulnerabilities)
7. [Information Disclosure and KASLR Defeats](#7-information-disclosure-and-kaslr-defeats)
8. [Race Conditions](#8-race-conditions)
9. [Logic Bugs and Privilege Escalation](#9-logic-bugs-and-privilege-escalation)
10. [CVE Statistics and Vulnerability Trends](#10-cve-statistics-and-vulnerability-trends)

---

## 1. Taxonomy of Kernel Vulnerabilities

Linux kernel vulnerabilities can be organized into a hierarchical taxonomy based on their
root cause, the memory region affected, and the exploitation primitive they provide. Unlike
userland vulnerabilities, kernel bugs operate in a single shared address space with full
hardware privileges, making every vulnerability class potentially more dangerous.

### 1.1 Top-Level Classification

| Category | Description | CWE Family |
|---|---|---|
| **Memory Safety Bugs** | Violations of spatial or temporal memory safety | CWE-119, CWE-416, CWE-415 |
| **Logic Bugs** | Incorrect program logic leading to security violations | CWE-840, CWE-863 |
| **Information Leaks** | Unintended disclosure of kernel memory contents | CWE-200, CWE-401 |
| **Race Conditions** | Concurrency bugs violating atomicity or ordering | CWE-362, CWE-367 |
| **Input Validation Failures** | Improper sanitization of userland-supplied data | CWE-20, CWE-190 |

### 1.2 Memory Safety Sub-Classification

Memory safety bugs represent the dominant vulnerability class in the Linux kernel and
can be further subdivided:

**Spatial Safety Violations** -- accessing memory outside the bounds of an allocated object:
- Stack buffer overflows
- Heap buffer overflows (slab/SLUB)
- Out-of-bounds reads (information leaks)
- Off-by-one errors

**Temporal Safety Violations** -- accessing memory after its lifetime has ended or before
it has begun:
- Use-after-free (UAF)
- Double-free
- Uninitialized memory use

**Type Safety Violations** -- treating an object as a type it is not:
- Type confusion
- Invalid cast / incorrect container_of() usage

### 1.3 Kernel-Specific Considerations

Several factors make kernel vulnerability classification distinct from userland:

1. **Shared Address Space**: The kernel is a single monolithic address space shared across
   all processes. A vulnerability in any subsystem can compromise the entire system.

2. **No ASLR Re-randomization**: Unlike userland processes that get fresh ASLR on each
   exec(), the kernel's layout is fixed at boot time until the next reboot.

3. **Slab Allocator Semantics**: Kernel heap management through SLAB/SLUB allocators
   creates different exploitation dynamics than glibc malloc/free.

4. **Concurrency Model**: The kernel is inherently concurrent -- preemption, interrupts,
   and SMP create race condition opportunities that rarely exist in single-threaded
   userland programs.

5. **Privilege Boundary**: Every kernel vulnerability potentially crosses the
   user/kernel privilege boundary, meaning even a "minor" bug can lead to full
   system compromise.

---

## 2. Buffer Overflows in Kernel Context

Buffer overflows (CWE-120, CWE-787) remain one of the most well-understood vulnerability
classes, yet they continue to appear in kernel code. The kernel's C codebase, which relies
heavily on manual memory management, raw pointer arithmetic, and fixed-size buffers,
provides a fertile environment for these bugs.

### 2.1 Stack Buffer Overflows

Stack overflows in the kernel differ from their userland counterparts in critical ways:

**Fixed Stack Size**: Each kernel thread receives a fixed-size stack (typically 8 KiB on
x86 historically, now 16 KiB on x86-64 with `THREAD_SIZE`). There is no guard page
between the stack and other kernel memory in older kernels, meaning an overflow can
silently corrupt adjacent memory.

**No Stack Cookies (Historically)**: The kernel did not use stack canaries (`-fstack-protector`)
by default until relatively recently. `CONFIG_STACKPROTECTOR` and
`CONFIG_STACKPROTECTOR_STRONG` are now standard but were not always enabled.

**Return Address Overwrites**: Like userland, the attacker's goal is often to overwrite
the saved return address on the stack. In kernel context, this means redirecting
execution while already at ring 0, making the impact immediate and complete.

**Example -- CVE-2010-2963 (v4l compat ioctl)**:
A stack buffer overflow in the Video4Linux compatibility ioctl handler allowed a local
user to overwrite the return address. The 32-bit compatibility layer failed to properly
validate sizes when copying ioctl arguments from userspace, leading to a classic
stack smash in kernel context.

### 2.2 Heap Buffer Overflows (Slab Overflows)

Kernel heap overflows target objects allocated through the SLAB/SLUB allocator, and
exploitation differs substantially from userland heap overflows:

**Slab Allocator Structure**: Unlike glibc's malloc, which uses inline metadata (chunk
headers with size and prev_size fields), SLUB stores freelist metadata out-of-line
in the `struct page` (or within the free object itself in the "freelist pointer" area).
This means there are no immediately adjacent metadata fields to corrupt as with
traditional heap exploitation (e.g., unsafe unlink in glibc).

**Cache Isolation and Merging**: Objects of the same size are grouped into slab caches
(`kmalloc-32`, `kmalloc-64`, etc.). Exploitation depends on whether the vulnerable
object and the target object share the same cache. Since kernel 4.16, general-purpose
`kmalloc` caches are no longer merged with special-purpose caches (a side effect of
`CONFIG_HARDENED_USERCOPY`'s `usersize` field), significantly restricting cross-cache
overflow exploitation.

**Heap Feng Shui**: Attackers use "heap feng shui" or "heap grooming" techniques to
arrange slab objects in a predictable layout:

1. Exhaust the target cache to force allocation of new slabs
2. Fill new slabs with target objects in a controlled pattern
3. Free specific objects to create "holes"
4. Trigger the vulnerable allocation to land adjacent to a target object
5. Overflow into the target

**`CONFIG_SLAB_FREELIST_RANDOM`** (introduced in kernel 4.8): Randomizes the order
of object allocation within a new slab. When a new slab is created, a pre-computed
random sequence (Fisher-Yates shuffle) determines allocation order, preventing the
deterministic placement that heap feng shui relies on. However, this mitigation only
affects fresh slabs -- refills from the freelist still follow LIFO order.

**Example -- CVE-2020-17087 (Windows cng.sys, conceptual analog)**:
Google Project Zero documented a pool buffer overflow in the Windows CNG driver's
IOCTL handler. The analogous pattern exists in Linux kernel drivers: an IOCTL
handler accepts a user-controlled size, allocates a slab object, and copies data
without proper bounds checking.

**Example -- CVE-2022-2294 (heap overflow in WebRTC)**:
While a browser vulnerability, it demonstrates the exploitation pattern applicable
to kernel heap overflows: crafting input to control both the size and content of an
overflow to corrupt adjacent objects in a predictable way.

### 2.3 Kernel-Specific Mitigations

| Mitigation | Kernel Config | Effect |
|---|---|---|
| Stack Protector | `CONFIG_STACKPROTECTOR_STRONG` | Canary-based stack overflow detection |
| Hardened Usercopy | `CONFIG_HARDENED_USERCOPY` | Bounds checking on copy_to/from_user |
| Freelist Randomization | `CONFIG_SLAB_FREELIST_RANDOM` | Randomize slab object allocation order |
| Freelist Pointer Hardening | `CONFIG_SLAB_FREELIST_HARDENED` | XOR freelist pointers with random value |
| KASAN | `CONFIG_KASAN` | Runtime memory error detector (debug) |
| `CONFIG_FORTIFY_SOURCE` | N/A | Compile-time and runtime buffer overflow checks |

---

## 3. Use-After-Free Vulnerabilities

Use-after-free (UAF) bugs (CWE-416) have become the single most exploited vulnerability
class in the Linux kernel. They occur when a kernel object is freed but a dangling
pointer to it remains, and that pointer is subsequently dereferenced.

### 3.1 UAF Mechanics in the SLUB Allocator

When an object is freed in SLUB, the memory is returned to the freelist but the
physical pages are not immediately released. The freed memory may contain:

1. **Freelist pointer**: SLUB stores a pointer to the next free object within the
   freed object's memory. With `CONFIG_SLAB_FREELIST_HARDENED`, this pointer is
   XOR'd with a random per-cache value and the object's address.

2. **Stale data**: Remaining bytes from the freed object persist in memory until
   the slot is reallocated and overwritten.

UAF exploitation follows a general pattern:

1. **Trigger the free** while retaining a reference (the dangling pointer)
2. **Reclaim the freed slot** with a controlled allocation of the same size
   (the "replacement object")
3. **Trigger the dangling pointer dereference** to interact with the replacement
   object as if it were the original type

### 3.2 The Binder UAF (CVE-2019-2215) -- A Canonical Example

This vulnerability, discovered by Maddie Stone of Google Project Zero and found
exploited in the wild, is a textbook kernel UAF:

**Root Cause**: The `binder_thread` struct in `drivers/android/binder.c` contains
a `wait_queue_head_t wait` member. When `BINDER_THREAD_EXIT` is called via ioctl,
`binder_thread_release()` frees the `binder_thread` struct. However, if `epoll`
had been set up on that thread, the `epoll` subsystem still holds a pointer to
the `wait` queue inside the now-freed `binder_thread`.

**Trigger**: As simple as:
```c
fd = open("/dev/binder", O_RDONLY);
epfd = epoll_create(1000);
epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
ioctl(fd, BINDER_THREAD_EXIT, NULL);
```

**Exploitation Primitive**: The UAF in `remove_wait_queue()` provides an
unlink primitive via `list_del()`, which can be used to achieve arbitrary
kernel read/write, typically by overwriting the `addr_limit` in the
current task's `task_struct`.

**Impact**: This vulnerability was actively exploited in the wild and affected
all Android devices released before Fall 2019. It was originally reported
by syzkaller in November 2017, patched upstream in February 2018, but
never included in an Android Security Bulletin until October 2019 --
demonstrating the "patch gap" problem.

### 3.3 Double-Free Vulnerabilities

Double-free (CWE-415) is a special case of UAF where the same object is freed
twice. In SLUB, this corrupts the freelist: the freed object appears on the
freelist twice, causing two subsequent allocations to return the same memory
address. This gives an attacker two pointers to the same physical memory,
with one pointer believing it owns an object of type A and the other believing
it owns an object of type B.

`CONFIG_SLAB_FREELIST_HARDENED` includes a double-free detection check that
validates the freelist pointer before adding a freed object, mitigating many
(but not all) double-free scenarios.

### 3.4 Cross-Cache UAF Exploitation

When the vulnerable object resides in a dedicated (non-merged) slab cache,
the attacker cannot directly reclaim the freed slot with an arbitrary object
type. The cross-cache technique works as follows:

1. Spray the target cache until entire slab pages are fully allocated
2. Free the vulnerable object, then free all other objects on the same slab page
3. The slab page is returned to the page allocator
4. Re-acquire the page through a different cache (e.g., by spraying `pipe_buffer`
   structs or `msg_msg` objects of matching page order)
5. The dangling pointer now references an object in the new cache

This technique, documented extensively by duasynt.com researchers, is less
reliable than same-cache exploitation but has been used successfully against
`SLAB_ACCOUNT`-protected caches like `cred_jar` (since kernel 4.4).

---

## 4. Integer Overflows and Underflows

Integer overflow and underflow bugs (CWE-190, CWE-191) are particularly dangerous in
the kernel because they often occur in size calculations that feed directly into memory
allocation or copy operations.

### 4.1 Kernel-Specific Impact

In the kernel, integer issues commonly manifest in:

**Allocation Size Calculations**: When user-supplied values are multiplied to compute
a buffer size, an overflow can wrap to a small value:
```c
/* Vulnerable pattern */
size_t total = count * elem_size;  /* wraps if count is large */
buf = kmalloc(total, GFP_KERNEL);
/* Copies count * elem_size bytes into undersized buffer */
copy_from_user(buf, user_ptr, count * elem_size);
```
After the overflow, `kmalloc()` allocates a small buffer, but the subsequent copy
uses the unwrapped (large) value, causing a heap overflow.

**Loop Bounds**: An underflow in a signed-to-unsigned conversion can turn a bounds
check into a no-op:
```c
int user_len = ...; /* user-controlled, can be negative */
if (user_len > MAX_SIZE) return -EINVAL;
/* If user_len is negative, this check passes */
memcpy(dst, src, (unsigned)user_len);
/* Cast to unsigned makes negative value very large */
```

**Reference Counting**: Integer overflow in reference counters (`atomic_t`) can wrap
from `INT_MAX` back to zero, causing premature freeing and a UAF. The `refcount_t`
type (introduced in kernel 4.11) addresses this with saturation arithmetic --
it refuses to increment past `REFCOUNT_SATURATED` or decrement below zero.

### 4.2 Real-World Examples

**CVE-2016-0728 (keyring refcount overflow)**: The `keyctl` system call allowed an
unprivileged user to repeatedly increment the reference counter on a key object.
After ~2^32 iterations, the 32-bit `atomic_t` counter wrapped to zero, triggering
a premature free and creating a UAF. This was the vulnerability that motivated the
introduction of `refcount_t`.

**CVE-2023-33107 (Qualcomm Adreno GPU `KGSL_IOCTL_GPUOBJ_IMPORT`)**: An integer
overflow in the Qualcomm GPU driver's IOCTL handler allowed an attacker to bypass
size checks, leading to an out-of-bounds write. Documented in Google Project Zero's
0-day root cause analyses.

### 4.3 Compiler and Kernel Mitigations

- **`refcount_t`**: Saturation-based reference counting that prevents wrap-around.
  Replaces `atomic_t` for reference counts.
- **`CONFIG_UBSAN`**: Undefined Behavior Sanitizer catches signed integer overflows
  at runtime (debug builds).
- **`check_add_overflow()` / `check_mul_overflow()`**: Safe arithmetic macros
  in `include/linux/overflow.h` that return an error on overflow.
- **`struct_size()` / `array_size()`**: Helper macros for computing allocation sizes
  with overflow checking.
- **`-fwrapv`**: GCC flag used by the kernel build system that defines signed integer
  overflow as two's complement wrapping (rather than undefined behavior), preventing
  the compiler from optimizing away overflow checks.

---

## 5. NULL Pointer Dereferences

NULL pointer dereferences (CWE-476) were historically one of the most reliably
exploitable kernel vulnerability classes, though modern mitigations have substantially
reduced their impact.

### 5.1 Historical Exploitability (Pre-2009)

In early Linux kernels, the virtual address zero (the "zero page") could be
mapped by userspace processes using `mmap()`. This meant that a NULL pointer
dereference in the kernel did not cause a fault -- instead, it accessed attacker-
controlled data at address 0x0 in the process's virtual address space.

The exploitation technique was straightforward:

1. Map a page at virtual address 0 with `mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)`
2. Place controlled data (e.g., a fake function pointer table) at address 0
3. Trigger a kernel code path that dereferences a NULL pointer
4. The kernel reads/writes/calls through the attacker's fake data at address 0
5. Gain arbitrary kernel code execution

### 5.2 The TUN Driver NULL Pointer Exploit (CVE-2009-1897)

This exploit by Brad Spengler is a landmark example, documented in detail by
LWN.net, demonstrating a remarkable chain of failures:

1. **The Bug**: Herbert Xu's patch to the TUN driver added `struct sock *sk = tun->sk;`
   *before* the `if (!tun) return POLLERR;` NULL check in `tun_chr_poll()`.

2. **GCC Optimization**: Since `tun` was already dereferenced, GCC concluded it
   could not be NULL and *removed the NULL check entirely* as dead code.

3. **`mmap_min_addr` Bypass**: The `mmap_min_addr` sysctl was supposed to prevent
   zero-page mappings, but when `CONFIG_SECURITY` was enabled, the enforcement was
   delegated to the security module. SELinux's default policy *allowed* zero-page
   mappings.

4. **Exploitation**: With the zero page mapped, the attacker used the NULL `tun`
   pointer to reach `sock_writeable(sk)`, which provided a bit-setting primitive.
   This was used to change a NULL function pointer in the TUN driver's
   `file_operations` struct to the value 1, which fell within the attacker-controlled
   zero page. Calling `mmap()` on the TUN device then jumped to address 1,
   executing attacker shellcode.

### 5.3 Modern Mitigations

| Mitigation | Mechanism | Introduced |
|---|---|---|
| `mmap_min_addr` | Prevents mapping pages below a configurable address (default: 65536) | ~2007 |
| `vm.mmap_min_addr` sysctl | Runtime configuration of minimum mmap address | 2.6.23 |
| SMEP (Supervisor Mode Execution Prevention) | CPU refuses to execute userspace pages while in ring 0 | Intel Ivy Bridge (2012) |
| SMAP (Supervisor Mode Access Prevention) | CPU refuses to read/write userspace pages while in ring 0 | Intel Broadwell (2014) |
| `CONFIG_DEFAULT_MMAP_MIN_ADDR=65536` | Compile-time default for mmap minimum | Standard |
| `-fno-delete-null-pointer-checks` | Prevents GCC from optimizing away NULL checks | Added to kernel build |

With SMEP and SMAP, even if an attacker can map the zero page, the kernel cannot
execute or access it. This has reduced NULL pointer dereferences from reliable
arbitrary code execution to mostly denial-of-service (kernel oops/panic).

However, NULL dereferences remain relevant:

- As **denial-of-service** vectors against availability
- In combination with other bugs (e.g., a NULL deref provides a partial primitive
  that chains with an information leak)
- On embedded systems or older hardware without SMEP/SMAP
- On architectures (like some ARM configurations) where userspace shares the same
  virtual address range as the kernel

---

## 6. Type Confusion Vulnerabilities

Type confusion (CWE-843) occurs when the kernel treats a memory region as one data
type when it actually contains another. This is particularly prevalent in complex
kernel subsystems with polymorphic data structures.

### 6.1 Mechanisms in the Kernel

**Incorrect `container_of()` Usage**: The `container_of()` macro computes the address
of a containing struct from a pointer to one of its members. If the member pointer
actually belongs to a different struct type, the resulting pointer points to an
incorrect location, and all field accesses are at wrong offsets.

**Union Mishandling**: Kernel data structures frequently use unions to represent
variant types (e.g., `struct sockaddr` can be `sockaddr_in`, `sockaddr_in6`, etc.).
If the discriminant (type field) is not checked or can be manipulated, accessing the
wrong union member constitutes type confusion.

**Socket Type Confusion**: The networking subsystem dispatches operations through
`proto_ops` function pointer tables indexed by socket type. If an attacker can
manipulate the socket type after creation, operations are dispatched to the wrong
handler, which interprets the socket's private data according to the wrong structure
layout.

**Win32k-style Type Confusion in Kernel Subsystems**: Google Project Zero's root
cause analyses have documented type confusion in the Windows `win32k` subsystem
(CVE-2022-21882, CVE-2022-41033), and analogous patterns exist in Linux. For
example, the `io_uring` subsystem's complex state machines have been a source
of type confusion bugs where request objects are processed by the wrong handler.

### 6.2 Exploitation Pattern

Type confusion is valuable because it typically provides a "type punning" primitive:

1. Object A of type X is created and initialized
2. A bug causes object A to be treated as type Y
3. Field F_Y at offset N in type Y overlaps with field F_X at a different offset
   in type X, or with a field of a different semantic meaning
4. Reading/writing F_Y through the confused reference actually accesses F_X with
   attacker-advantageous semantics

For example, if a function pointer in type Y overlaps with a user-controlled data
field in type X, the type confusion immediately gives arbitrary kernel code execution.

### 6.3 Real-World Example: CVE-2022-21882 (Win32k Window Object)

While this is a Windows kernel vulnerability, the pattern is directly applicable to
Linux. The bug involved creating a window object and then using a race condition to
change its type between two window classes that have different field layouts. The
kernel then used the wrong type's layout to access a field, interpreting a
user-controlled value as a kernel pointer. This same pattern can occur in any
kernel subsystem that uses polymorphic objects (netfilter, filesystem operations,
device drivers).

---

## 7. Information Disclosure and KASLR Defeats

Information disclosure vulnerabilities (CWE-200) in the kernel reveal sensitive
kernel memory contents to unprivileged userspace processes. Their primary
exploitation value is defeating Kernel Address Space Layout Randomization (KASLR).

### 7.1 KASLR Overview

KASLR, merged into the Linux kernel in version 3.14 (March 2014), randomizes
where the kernel code is placed at boot time. On x86-64, the kernel text is
placed at a random 2MiB-aligned offset within a ~1GiB region, providing approximately
512 possible positions (9 bits of entropy). With Function Granular KASLR (FGKASLR),
individual functions can be reordered, significantly increasing entropy.

KASLR is a **statistical defense** -- it makes exploitation harder by requiring
the attacker to guess or leak the kernel's base address. An incorrect guess
crashes the kernel (unlike userland ASLR where only the process crashes),
making brute force attacks highly visible.

### 7.2 Information Leak Sources

**Uninitialized Memory Disclosure**: Kernel stack or heap memory allocated with
`kmalloc()` (not `kzalloc()`) may contain residual data from previous use.
If this data is copied to userspace without full initialization, it can contain
kernel pointers.

```c
/* Vulnerable pattern */
struct response resp;
resp.field_a = value_a;
/* resp.field_b not initialized -- contains stale kernel pointer */
copy_to_user(user_buf, &resp, sizeof(resp));
```

**`/proc` and `/sys` Leaks**: The kernel exposes addresses through various
proc and sysfs interfaces:
- `/proc/kallsyms` -- symbol addresses (restricted by `kptr_restrict`)
- `/proc/modules` -- module load addresses
- `/sys/kernel/debug/` -- debugfs entries with kernel pointers
- `dmesg` / kernel log -- often contains raw addresses (restricted by
  `dmesg_restrict`)

**Format String Leaks**: The `%p` format specifier in `printk()` was changed
to hash kernel pointers by default (since kernel 4.15). `%pK` respects
`kptr_restrict`, while `%px` explicitly prints raw pointers and should only
be used in debugging code.

**INET_DIAG Socket Handles**: As noted by Kees Cook in his KASLR presentation,
the `INET_DIAG` socket API historically used raw kernel object addresses as
opaque handles passed to userspace. While semantically opaque, the values
were real kernel pointers that directly reveal the kernel's address layout.

**Side-Channel Attacks**: Hardware-based side channels can defeat KASLR without
any software vulnerability:
- **Prefetch timing attacks**: Timing differences in the CPU prefetch
  instruction reveal whether a virtual address is mapped
- **Branch Target Buffer (BTB) attacks**: Collisions in the branch predictor
  leak information about kernel addresses (Jump Over ASLR, Evtyushkin et al. 2016)
- **TLB timing attacks**: Page table walk timing reveals mapped addresses
- **Intel TSX attacks** (DrK): Transactional memory aborts leak whether a
  kernel address is mapped (Jang et al., CCS 2016)

### 7.3 KASLR Effectiveness Debate

KASLR's effectiveness has been controversial in the security community.
Brad Spengler (grsecurity) has argued that KASLR is "completely useless"
given the abundance of information leak paths. Kees Cook has acknowledged
that KASLR is most effective in *confined environments* (containers,
seccomp-sandboxed processes) where access to `/proc`, `dmesg`, and
timing oracles is restricted.

Key limitations:
- Only ~9 bits of entropy for kernel text on x86-64
- No re-randomization after boot (one leak compromises KASLR for the
  entire uptime)
- Kernel modules are loaded at predictable offsets relative to the kernel base
- Many side-channel leak vectors exist in hardware

Kernel Page Table Isolation (KPTI/KAISER), introduced in late 2017 primarily
to mitigate Meltdown (CVE-2017-5754), also helps KASLR by unmapping most of
the kernel address space from userspace page tables. This prevents memory-
mapping-based timing side channels when KPTI is active.

### 7.4 Countermeasures Summary

| Countermeasure | Effect |
|---|---|
| `kptr_restrict=2` | Hide all kernel pointers from all users |
| `dmesg_restrict=1` | Restrict dmesg to privileged users |
| KPTI (Kernel Page Table Isolation) | Unmap kernel pages from user page tables |
| `%p` hashing (kernel 4.15+) | Hash kernel pointers in printk output |
| `CONFIG_GRKERNSEC_HIDESYM` | grsecurity's more aggressive symbol hiding |
| FGKASLR | Function-granular randomization (increases entropy) |

---

## 8. Race Conditions

Race conditions (CWE-362) are among the most subtle and dangerous kernel vulnerability
classes. The kernel's inherently concurrent execution model -- with preemption,
interrupts, softirqs, multiple CPUs, and workqueues -- creates extensive opportunities
for time-of-check-to-time-of-use (TOCTOU) and other concurrency bugs.

### 8.1 Dirty COW (CVE-2016-5195) -- The Canonical Kernel Race

Dirty COW is perhaps the most famous Linux kernel race condition vulnerability.
It existed in the kernel from version 2.6.22 (September 2007) through 4.8.3,
affecting virtually every Linux system and Android device for nearly a decade.

**Root Cause**: A race condition in the copy-on-write (COW) mechanism of the kernel's
memory management subsystem. The `get_user_pages()` function, which resolves virtual
addresses to physical pages, could be raced between its COW fault handling and the
`madvise(MADV_DONTNEED)` system call:

1. Thread A calls `write()` on a `mmap()`'d read-only file, triggering a COW fault
2. The kernel allocates a private copy of the page and begins to write to it
3. Thread B calls `madvise(MADV_DONTNEED)`, discarding the private copy
4. Thread A's write lands on the *original* page (the file-backed mapping),
   bypassing the COW protection

**Impact**: An unprivileged local user could write to any file they could read,
including setuid binaries, `/etc/passwd`, and the kernel image itself. Combined
with remote access, this trivially yields root.

**Historical Context**: Linus Torvalds acknowledged that this was an old bug he
had attempted to fix eleven years prior. The fix had been reverted because it
caused regressions on s390 architecture.

### 8.2 Categories of Kernel Race Conditions

**TOCTOU (Time-of-Check-to-Time-of-Use)**: The most common pattern. A security
check is performed on a resource, but the resource changes between the check and
its use. Common in syscall handlers that validate userspace pointers or permissions.

**Reference Count Races**: Concurrent increment/decrement of reference counts
without proper locking. If a refcount drops to zero and the object is freed
while another thread is incrementing it, a UAF results.

**Lock Ordering Violations / Deadlocks**: While not directly exploitable for
privilege escalation, these can cause denial of service and sometimes expose
windows for other races.

**Signal/Interrupt Races**: Kernel code that is interrupted by a signal or
hardware interrupt at a critical point, leaving data structures in an
inconsistent state.

### 8.3 CVE-2021-0920 (sk_buff UAF in Linux)

Documented in Google Project Zero's 0-day root cause analyses and exploited in
the wild on Android, this race condition in the Linux networking stack's
`sk_buff` handling created a use-after-free. The race existed between the
garbage collection of Unix domain sockets and the normal socket close path,
allowing a `sk_buff` to be used after being freed by the garbage collector.

### 8.4 Exploitation Challenges

Race conditions are inherently probabilistic. Exploitation reliability depends on:

- **Race window size**: How many instructions exist between the check and the use
- **CPU topology**: More CPUs increase concurrency and thus the probability of
  winning a race
- **Scheduling control**: Techniques like CPU pinning (`sched_setaffinity()`),
  userfaultfd, and FUSE can widen race windows by stalling one side of the race
  at a controlled point

**userfaultfd**: This mechanism allows userspace to handle page faults, effectively
pausing the kernel at any point where it accesses a user-provided page. This is
an extremely powerful exploitation primitive for widening race windows and has been
restricted to privileged users (`vm.unprivileged_userfaultfd=0`) in newer kernels.

---

## 9. Logic Bugs and Privilege Escalation

Logic bugs represent a diverse class of vulnerabilities where the code does not
have a memory safety violation per se, but implements incorrect security logic.
These bugs are particularly challenging to detect with automated tools because the
code is "correct" from a memory safety perspective.

### 9.1 Permission Check Bypasses

**Capability Check Errors**: The kernel's capability system (`CAP_SYS_ADMIN`,
`CAP_NET_RAW`, etc.) is the primary mechanism for fine-grained privilege control.
Logic bugs in capability checks -- missing checks, wrong capability tested,
checks performed in the wrong order -- directly enable privilege escalation.

**Namespace Escapes**: Linux namespaces (user, network, PID, mount, etc.) provide
the isolation foundation for containers. Logic bugs that allow actions in one
namespace to affect another constitute container escapes. For example, a bug
where a `user_namespace` root is incorrectly granted capabilities in the
initial namespace.

**seccomp Bypasses**: Logic bugs in system call filtering can allow a sandboxed
process to invoke prohibited system calls. This is particularly relevant for
browser sandbox escapes.

### 9.2 Misuse of Kernel APIs

**`copy_from_user()` / `copy_to_user()` Size Errors**: Passing an incorrect size
to these functions can read/write kernel memory beyond the intended buffer.
While this overlaps with buffer overflows, the root cause is a logic error in
the size calculation rather than missing bounds checking.

**Incorrect `ioctl()` Dispatch**: Complex driver ioctl handlers with switch/case
statements may have missing `break` statements, fall-through to unintended
cases, or fail to validate the ioctl command number against the driver's
supported set.

**Unchecked Return Values**: Kernel functions frequently return error codes.
Ignoring these can lead to use of invalid objects:
```c
struct resource *r = request_region(...);
/* BUG: r might be NULL, but is used directly */
r->start = ...;
```

### 9.3 Real-World Logic Bug Examples

**CVE-2022-24521 (Windows CLFS Logical Error)**: Documented in Project Zero's
RCAs, this was a pure logic bug in the Common Log File System driver. An
inconsistency in how base log record blocks were validated allowed an attacker
to craft a malicious log file that, when processed, corrupted internal state
to achieve privilege escalation. No memory corruption was involved.

**Android Parcel/Unparcel Mismatches (CVE-2023-20963)**: The `WorkSource`
object in Android's Parcel serialization framework was serialized (parceled)
and deserialized (unparceled) with different logic, creating a discrepancy.
An attacker could craft a Parcel that passed validation during unparceling
but contained hidden data that was interpreted differently by downstream
consumers -- a "confused deputy" attack enabling privilege escalation.

**CVE-2022-41073 (Windows Activation Contexts EoP)**: A logic bug in how
Windows handled activation contexts for privileged processes, allowing an
unprivileged process to manipulate the execution context of a privileged
service. Similar patterns exist in Linux's handling of environment variables,
file descriptors, and other inherited state across privilege boundaries.

### 9.4 Detection Challenges

Logic bugs resist automated detection:
- **Fuzzers** like syzkaller can find crashes (memory corruption) but not
  silent privilege escalations
- **Static analyzers** can find missing NULL checks but not incorrect
  permission semantics
- **Formal verification** is the most promising approach but is too expensive
  for the entire kernel
- **Manual code audit** remains the primary method for finding logic bugs

---

## 10. CVE Statistics and Vulnerability Trends

### 10.1 Vulnerability Distribution by Type

Analysis of Linux kernel CVEs from NVD and Project Zero's 0-day tracking data
reveals consistent patterns in vulnerability type distribution:

| Vulnerability Class | Approximate Share of Kernel CVEs | CWE IDs |
|---|---|---|
| Use-After-Free | ~25-30% | CWE-416 |
| Out-of-Bounds Write (Heap Overflow) | ~15-20% | CWE-787 |
| Out-of-Bounds Read (Info Leak) | ~10-15% | CWE-125 |
| NULL Pointer Dereference | ~10-15% | CWE-476 |
| Race Condition | ~5-10% | CWE-362 |
| Integer Overflow/Underflow | ~5-8% | CWE-190, CWE-191 |
| Type Confusion | ~3-5% | CWE-843 |
| Improper Input Validation | ~5-10% | CWE-20 |
| Other (Logic, Permissions, etc.) | ~10-15% | Various |

*Note: Percentages are approximate and based on aggregated data from multiple
sources including NVD, Google Project Zero's 0-day tracking spreadsheet, and
academic analyses. Exact numbers vary by year and counting methodology.*

### 10.2 Trends Over Time

**2010-2015**: NULL pointer dereferences and stack overflows were the dominant
exploited classes. Introduction of `mmap_min_addr`, SMEP, and stack protector
drove attackers toward heap-based exploitation.

**2016-2020**: Use-after-free became the dominant exploit vector, comprising
the majority of in-the-wild kernel exploits. Race conditions (Dirty COW)
also gained prominence. Heap exploitation matured with techniques for
cross-cache attacks and slab manipulation.

**2021-Present**: Continued dominance of UAF with increasing focus on complex
subsystems (io_uring, eBPF, netfilter) where logic bugs and memory safety
issues intersect. Growing importance of logic bugs as memory safety mitigations
improve. Google Project Zero's 0-day in-the-wild tracking shows:
- UAF remains the #1 kernel exploit vector
- Type confusion is growing, especially via complex subsystems
- Logic bugs in Android-specific components (Binder, Parcel) are actively
  exploited
- Many in-the-wild exploits target known, patched vulnerabilities in
  unpatched devices ("n-day" exploitation)

### 10.3 Subsystem Analysis

The most vulnerability-dense kernel subsystems, based on CVE data:

| Subsystem | Common Bug Classes | Notes |
|---|---|---|
| **Networking (net/)** | UAF, race conditions, OOB | Largest attack surface, most complex |
| **Filesystem (fs/)** | UAF, integer overflows, info leaks | Exposure to malicious disk images |
| **Drivers (drivers/)** | Buffer overflows, integer issues | Massive codebase, variable code quality |
| **Memory Management (mm/)** | Race conditions, logic bugs | Dirty COW class of bugs |
| **io_uring** | UAF, type confusion, logic | Complex new subsystem, rapidly evolving |
| **eBPF** | Logic bugs, bounds check bypass | JIT compiler bugs, verifier bypasses |
| **Netfilter (nf_tables)** | UAF, double-free, OOB | Rich attack surface via unprivileged namespaces |
| **USB** | Buffer overflows, UAF | Exposure to malicious hardware |

### 10.4 Google Project Zero 0-Day In-the-Wild Data

Google Project Zero maintains a tracking spreadsheet of all known 0-day exploits
detected in the wild. From their root cause analyses (RCAs) of kernel/OS-level
0-days (2019-2024):

**Dominant Bug Classes in Actively Exploited 0-Days:**
- Use-after-free: CVE-2019-2215 (Binder), CVE-2021-0920 (sk_buff),
  CVE-2021-1048 (file refcount), CVE-2023-4211 (Mali GPU), CVE-2024-44068
  (Samsung driver)
- Integer overflow: CVE-2023-33107 (Qualcomm GPU), CVE-2023-6345 (Skia)
- Logic bugs: CVE-2021-1048 (refcount on mid-destruction file),
  CVE-2022-22706 (Mali read-only page bypass)
- Out-of-bounds write: CVE-2023-33106 (Qualcomm GPU)

**Key Observations from Project Zero:**
1. Many kernel 0-days target vendor-specific drivers (Qualcomm, Samsung, ARM Mali)
   rather than mainline Linux, because these drivers receive less scrutiny
2. "Patch gap" exploitation is common: vulnerabilities patched upstream but not
   yet shipped to devices
3. Known exploit techniques (e.g., `addr_limit` overwrite, `pipe_buffer` spray)
   are repeatedly reused across different vulnerabilities
4. Structural improvements (e.g., removing `addr_limit` from `task_struct`,
   `CONFIG_DEBUG_LIST`) can break entire classes of exploit techniques

### 10.5 Impact of Mitigations on Exploitation Trends

The progressive deployment of kernel hardening measures has shaped the evolution
of exploitation techniques:

| Year | Key Mitigation | Effect on Exploitation |
|---|---|---|
| 2007 | `mmap_min_addr` | Reduced NULL deref exploitability |
| 2012 | SMEP (hardware) | Prevented ret2user with kernel code exec |
| 2014 | KASLR (kernel 3.14) | Required address leak for reliable exploitation |
| 2014 | SMAP (hardware) | Prevented ret2user data access |
| 2016 | `refcount_t` (kernel 4.11) | Reduced integer overflow to UAF conversions |
| 2017 | KPTI / KAISER | Mitigated Meltdown, helped KASLR |
| 2018 | Hardened usercopy (side effect) | Broke general/special cache merging |
| 2020 | `CONFIG_INIT_STACK_ALL_ZERO` | Reduced uninitialized variable bugs |
| 2022+ | CFI (`CONFIG_CFI_CLANG`) | Control Flow Integrity limits function pointer abuse |

Each mitigation has not eliminated exploitation but has raised the bar, forcing
attackers to develop more sophisticated techniques (cross-cache attacks, data-only
attacks, JIT spraying) and target increasingly complex subsystems where the
mitigations are less effective.

---

## References

### Academic and Technical Sources

- CWE-120: Buffer Copy without Checking Size of Input. MITRE Corporation, CWE v4.19.1.
- Google Project Zero. "Root Cause Analyses for 0-day In-the-Wild Exploits." 2020-2024.
  https://googleprojectzero.github.io/0days-in-the-wild/rca.html
- Google Project Zero. "0-day In-the-Wild Tracking Spreadsheet."
  https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY
- Maddie Stone. "CVE-2019-2215: Android use-after-free in Binder." Project Zero RCA, 2020.
- Michael S, Vitaly Nikolenko. "Linux kernel heap feng shui in 2022." duasynt.com, May 2022.
- Jake Edge. "Kernel address space layout randomization." LWN.net, October 2013.
- Jonathan Corbet. "Fun with NULL pointers, part 1." LWN.net, July 2009.
- Wikipedia. "Dirty COW." CVE-2016-5195.
- Wikipedia. "Address space layout randomization."

### Kernel Documentation

- The Linux Kernel. "KASAN: KernelAddressSanitizer." Documentation/dev-tools/kasan.rst.
- The Linux Kernel. "Handling regressions." Documentation/process/handling-regressions.rst.
- Kees Cook. KASLR implementation and Linux Security Summit presentations.

### Exploit Technique References

- Brad Spengler. TUN driver NULL pointer exploit (CVE-2009-1897). grsecurity.net, 2009.
- Jann Horn. Various Linux kernel exploit techniques. Google Project Zero.
- Evtyushkin, Ponomarev, Abu-Ghazaleh. "Jump Over ASLR: Attacking Branch Predictors
  to Bypass ASLR." MICRO 2016.
- Jang, Lee, Kim. "Breaking Kernel Address Space Layout Randomization with Intel TSX."
  CCS 2016.
