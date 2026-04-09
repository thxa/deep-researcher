# 7b. Advanced Mitigation Bypass Techniques

## Linux Kernel Exploitation: Defeating Modern Defenses

> **Classification**: Technical Research Document
> **Last Updated**: April 2026
> **Scope**: Bypass techniques for kernel CFI, SLAB hardening, RANDSTRUCT, seccomp, per-cache isolation, and page-level heap exploitation

---

## Table of Contents

1. [Bypassing Kernel CFI (Control Flow Integrity)](#1-bypassing-kernel-cfi)
2. [Bypassing SLAB_FREELIST_HARDENED](#2-bypassing-slab_freelist_hardened)
3. [Bypassing SLAB_FREELIST_RANDOM](#3-bypassing-slab_freelist_random)
4. [Defeating CONFIG_RANDSTRUCT](#4-defeating-config_randstruct)
5. [Bypassing seccomp Filters](#5-bypassing-seccomp-filters)
6. [Cross-Cache Attacks](#6-cross-cache-attacks)
7. [Page-Level Exploitation Techniques](#7-page-level-exploitation-techniques)
8. [Elastic Objects Technique](#8-elastic-objects-technique)
9. [State of the Art (2024-2026)](#9-state-of-the-art-2024-2026)

---

## 1. Bypassing Kernel CFI

Control Flow Integrity (CFI) restricts indirect branch targets to valid function entry points. The Linux kernel supports two primary CFI implementations: Clang's forward-edge CFI (kCFI, merged in Linux 6.1) and backward-edge protections (shadow call stacks on ARM64). Understanding both edges is critical to evaluating exploit feasibility.

### 1.1 Forward-Edge CFI (kCFI)

kCFI enforces that indirect calls target functions whose prototype matches the call site. The compiler emits a 32-bit type hash immediately before each function entry and instruments each indirect call site with a comparison against the expected hash.

**How kCFI works at the instruction level (x86_64):**

```asm
; Before function entry:
    .long 0xDEADBEEF      ; type hash for this function prototype

my_function:
    push rbp
    mov  rbp, rsp
    ...

; At the indirect call site:
    mov  eax, [target - 4]         ; load the hash before the target
    cmp  eax, 0xDEADBEEF           ; compare against expected hash
    je   .call_ok
    ud2                            ; trap on mismatch
.call_ok:
    call target
```

**Bypass Techniques:**

#### a) Type-Matching Target Reuse

kCFI only validates that the target function's type signature matches the expected signature at the call site. It does not validate *which* specific function of that type is called. The kernel contains thousands of functions with identical prototypes. For example, many functions have the signature `int (*)(struct file *, unsigned int, unsigned long)` (the unlocked_ioctl prototype). An attacker who can corrupt a function pointer to point at *any* function with a matching type hash achieves a valid forward-edge transfer.

**Workflow:**
1. Identify the prototype expected at the corrupted indirect call site
2. Enumerate all kernel functions with that same prototype (same kCFI hash)
3. Select a useful "gadget function" --- one that provides an exploitable primitive (e.g., arbitrary write, arbitrary free, or calls to further useful functions)
4. Overwrite the function pointer to this gadget function

This is analogous to "whole-function reuse" in userspace CFI bypass research. The large kernel codebase ensures an abundance of type-compatible targets.

#### b) Data-Only Attacks (Bypassing CFI Entirely)

The most reliable approach to defeating CFI is to avoid hijacking control flow altogether. Data-only attacks modify non-code-pointer kernel data to achieve privilege escalation:

- **Overwriting `struct cred` fields**: Set `uid`, `euid`, `gid`, `egid` to 0 directly
- **Overwriting `modprobe_path`**: Change the path to a user-controlled script (note: partially mitigated by `CONFIG_STATIC_USERMODEHELPER` since 5.x)
- **Overwriting `core_pattern`**: Redirect core dump processing to an attacker-controlled program
- **Overwriting `init_nsproxy` / namespace pointers**: Manipulate namespace references to escape containers
- **Overwriting `selinux_state.enforcing`**: Disable SELinux enforcement

Data-only attacks require arbitrary kernel read/write but do not trigger any CFI check, making them the preferred escalation path in CFI-hardened environments.

#### c) JIT Code and BPF

eBPF JIT-compiled code resides in executable kernel memory but is generated at runtime, potentially outside the scope of CFI instrumentation. While modern kernels restrict unprivileged BPF (`kernel.unprivileged_bpf_disabled=1`), environments where BPF is accessible offer potential bypass paths through BPF map manipulation or JIT spray techniques.

#### d) Targeting Co-Processors / DCP

As demonstrated by the in-the-wild exploit analyzed by Google Project Zero (CVE-2021-25370 chain), Apple's Display Co-Processor (DCP) --- and analogous coprocessors on other platforms --- run firmware without the mitigation stack present on the application processor. By exploiting a vulnerability in the coprocessor firmware (which lacks CFI, ASLR, PAC, etc.), attackers gain the ability to request arbitrary kernel memory mappings through the coprocessor's RPC interface to the AP. This entirely sidesteps AP-side CFI enforcement.

### 1.2 Backward-Edge CFI (Shadow Call Stack)

ARM64 kernels support Shadow Call Stack (SCS), which stores return addresses in a separate, hidden stack. On x86_64, backward-edge protection is less mature --- stack canaries remain the primary defense.

**Bypass Techniques:**

- **Stack canary leaks**: On x86_64, if an information disclosure primitive exists (e.g., uninitialized stack variables, out-of-bounds read), the canary can be leaked and included in the overflow payload. This was demonstrated in CVE-2021-26708 (Alexander Popov's vsock exploit) where a kernel warning leaked register contents including stack addresses.

- **SCS pointer corruption (ARM64)**: The shadow call stack pointer is stored in a dedicated register (`x18` on ARM64). If an attacker can corrupt the SCS pointer or the SCS memory region itself (e.g., via an arbitrary write to the SCS pages), return addresses can be forged.

- **Non-return control flow**: Techniques that modify execution flow without returning (e.g., corrupting exception handlers, modifying longjmp buffers, or manipulating kernel thread function pointers) bypass SCS entirely.

---

## 2. Bypassing SLAB_FREELIST_HARDENED

`SLAB_FREELIST_HARDENED` (enabled by default in most distributions) obfuscates freelist pointers stored in freed slab objects using an XOR-based scheme:

```c
// Encoding a freelist pointer:
encoded = ptr ^ random_value ^ swab(location_address)

// In SLUB (simplified):
// freelist_ptr = free_ptr XOR slab->random XOR ptr_addr
```

The `random` value is per-cache and generated at cache creation. The `location_address` is the address where the freelist pointer is stored (the address of the freed object itself plus the freelist offset).

### 2.1 Bypass via Information Leak

If an attacker can read an encoded freelist pointer AND knows the address of the object containing it, the random value can be recovered:

```
random_value = encoded_ptr ^ known_next_ptr ^ swab(object_address)
```

**Practical approach (from CVE-2021-26708 exploit):**

1. Use a UAF to read the contents of a freed object, obtaining the encoded freelist pointer
2. The "next" pointer for an empty freelist is typically NULL (0x0), or deterministic if the slab layout is known
3. If the object address is known (e.g., from a separate infoleak), compute: `random = encoded ^ 0 ^ swab(obj_addr)`
4. With `random` recovered, craft arbitrary encoded pointers: `fake_encoded = target_addr ^ random ^ swab(obj_addr)`
5. Write this fake pointer into the freelist to redirect the next allocation to `target_addr`

As noted in grsecurity's AUTOSLAB evaluation by Zhenpeng Lin: *"In practice, the implementation of freelist pointer obfuscation in upstream is weak; the attacker with an overread ability can bypass this hardening without knowing the random value and heap address of the object."*

The key insight is that if a UAF provides both read and write to the same freed object, the attacker can:
- Read the encoded freelist pointer
- Free the next object to make it NULL
- Compute `random ^ swab(addr) = encoded ^ 0`
- Then forge arbitrary pointers

### 2.2 Bypass via Partial Overwrite

If the vulnerability provides only a partial overwrite (e.g., 1-2 bytes), the encoded pointer can be partially modified. Since the lower bytes of kernel heap addresses have low entropy (slab objects are aligned, pages are 4KB-aligned), a partial overwrite of the encoded pointer may redirect the freelist to a nearby object or a controlled location without needing to know the full random value.

### 2.3 Bypass via Cross-Cache / Page-Level Attacks

Freelist hardening only protects within a single slab cache. Cross-cache and page-level attacks (described in Sections 6 and 7) operate at the page allocator level, entirely bypassing freelist pointer checks.

---

## 3. Bypassing SLAB_FREELIST_RANDOM

`SLAB_FREELIST_RANDOM` randomizes the initial ordering of free objects within a newly created slab page. Instead of objects being laid out sequentially (0, 1, 2, 3...), they follow a random permutation (e.g., 5, 2, 7, 0...).

### 3.1 Heap Grooming

The classic bypass, documented extensively by will's root, duasynt, and others:

**Workflow:**
1. **Drain the target cache**: Allocate many objects from the target slab cache until existing partial slabs are full and new slabs must be allocated
2. **Allocate "filler" objects**: Fill one or more slabs completely
3. **Create holes**: Free specific objects in a controlled pattern, creating predictable freelist entries
4. **Allocate the vulnerable object**: It occupies one of the freed slots
5. **Allocate the victim object**: It occupies the adjacent freed slot

Since the attacker controls which objects are freed and in what order, the LIFO (SLUB) or FIFO (SLAB) freelist behavior means the allocation order after freeing is deterministic, regardless of the initial random ordering.

```
Initial random layout: [5, 2, 7, 0, 3, 1, 6, 4]
After draining and refilling, all slots occupied.
Free slots 3 and 4 (adjacent in memory):
Freelist: 4 -> 3 (LIFO)
Allocate vuln_obj -> slot 4
Allocate victim_obj -> slot 3  (adjacent to vuln_obj!)
```

### 3.2 Slab Layout Oracle

Some vulnerabilities provide the ability to probe whether a specific object has been corrupted (e.g., a partial overwrite that changes a checkable field). This allows the attacker to:
1. Allocate many objects
2. Perform a small overflow
3. Check each object to determine which was corrupted
4. Build a map of the slab layout

This technique is particularly relevant in AUTOSLAB/dedicated-cache environments where the attacker must determine which object is at the end of a slab page for cross-cache overflows.

### 3.3 Per-CPU Freelist Exploitation

SLUB maintains per-CPU freelists for performance. On multi-core systems, pinning the exploit thread to a specific CPU (via `sched_setaffinity()`) ensures all allocations and frees target the same per-CPU freelist, dramatically reducing noise from other cores.

---

## 4. Defeating CONFIG_RANDSTRUCT

`CONFIG_RANDSTRUCT` (originally from grsecurity, upstreamed in a limited form) randomizes the layout of designated kernel structures at compile time. Critical structures like `task_struct`, `file_operations`, `cred`, etc., have their member offsets shuffled.

### 4.1 Information Leak-Based Approach

With an arbitrary kernel read primitive, an attacker can empirically determine structure layouts by:

1. **Fingerprinting known values**: Locate fields with predictable contents (e.g., `cred->usage` refcount is typically a small integer, `file_operations` function pointers point to kernel text)
2. **Correlating offsets**: By reading a structure and identifying known values at various offsets, build a map of the randomized layout

### 4.2 Per-Boot Randomization Limitation

The randomization seed is fixed at compile time, meaning all systems running the same kernel binary have the same structure layout. Attackers targeting a specific distribution version only need to determine the layout once (by obtaining the kernel binary or vmlinux with debug symbols).

### 4.3 Upstream vs. grsecurity

The upstream implementation (`CONFIG_RANDSTRUCT_FULL`) only randomizes structures containing function pointers. The grsecurity version is more comprehensive. Additionally, the upstream version uses a randomization seed derivable from the kernel binary itself, weakening the protection for anyone with access to the binary.

### 4.4 Bypassing with Data-Only Structures

Many exploitable structures do not contain function pointers and are therefore not randomized by the upstream implementation:
- `struct msg_msg`: Used extensively for heap spray and arbitrary read/write
- `struct pipe_buffer` (partially): The `pipe_buf_operations` pointer is in a fixed position
- `struct cred`: While it may be randomized, the fields (uid/gid/etc.) are all the same type (`kuid_t`/`kgid_t`), so overwriting the entire credential region with zeros achieves privilege escalation regardless of layout

---

## 5. Bypassing seccomp Filters

seccomp-BPF restricts the system calls available to a process, significantly constraining kernel attack surface. However, several bypass techniques exist:

### 5.1 Permitted Syscall Exploitation

seccomp filters are per-syscall. Vulnerabilities in *permitted* syscalls (e.g., `read`, `write`, `ioctl`, `mmap`, `close`) provide full kernel exploitation capability. Many kernel vulnerabilities exist in code reachable through commonly permitted syscalls.

### 5.2 Namespace Escape

If `clone`/`unshare` with namespace flags is permitted, the attacker can create new user namespaces where they have `CAP_SYS_ADMIN`, enabling:
- Access to otherwise restricted interfaces (e.g., `PACKET_TX_RING` for page-level spraying)
- Mounting of filesystems
- Loading of eBPF programs (if unprivileged BPF is disabled but namespace root has access)

### 5.3 Kernel Exploitation Below seccomp

seccomp operates at the syscall entry point. Once an attacker achieves arbitrary kernel code execution or arbitrary kernel write, seccomp is irrelevant --- the attacker can:
- Modify the seccomp filter pointer in `task_struct` to NULL
- Directly modify credentials without returning through seccomp
- Use `commit_creds(prepare_kernel_cred(0))` via ROP (which operates entirely in kernel context)

### 5.4 io_uring as Bypass Surface

`io_uring` (introduced in 5.1) provides an alternative syscall dispatch mechanism. Historically, many io_uring operations were not covered by seccomp filters, providing access to kernel functionality that the seccomp policy intended to block. While this has been partially addressed (io_uring can now be restricted via seccomp), it remains an active area of concern.

### 5.5 Race Conditions and TOCTOU

seccomp evaluates syscall arguments at entry. If a kernel path reads arguments from user memory multiple times, a TOCTOU (time-of-check-time-of-use) race can bypass argument filtering. Techniques like `userfaultfd` (where available) or `FUSE` can reliably win such races.

---

## 6. Cross-Cache Attacks

Cross-cache attacks bypass per-cache isolation (including dedicated caches created by `kmem_cache_create()` and grsecurity's AUTOSLAB) by operating at the page allocator level.

### 6.1 Fundamental Mechanism

The kernel's slab allocator obtains memory from the buddy allocator in page-sized (or larger) chunks. When a slab is empty (all objects freed), the slab page is returned to the buddy allocator. A subsequent allocation from a *different* cache can then reclaim the same physical page.

**Core workflow:**

```
1. Slab Cache A has objects on page P
2. Free ALL objects in Cache A on page P
   -> Page P is returned to buddy allocator
3. Trigger allocation in Slab Cache B
   -> Cache B requests a page from buddy allocator
   -> Gets page P (same physical memory)
4. Objects in Cache B now overlap with where Cache A objects were
5. Dangling pointer to Cache A object now points into Cache B object
```

### 6.2 Practical Cross-Cache Overflow (will's root, corCTF 2022)

Demonstrated against isolated `cred_jar` allocations:

**Phase 1 --- Drain cred_jar:**
```c
// Fork many times to exhaust existing cred_jar partial slabs
for (int i = 0; i < 100; i++) {
    if (!fork()) { just_wait(); }
}
```

**Phase 2 --- Page-level massage:**
```c
// Allocate order-0 pages using PACKET_TX_RING
for (int i = 0; i < 1000; i++) {
    send_spray_cmd(ALLOC_PAGE, i);
}
// Free alternating pages to prevent coalescing
for (int i = 1; i < 1000; i += 2) {
    send_spray_cmd(FREE_PAGE, i);
}
```

**Phase 3 --- Spray cred objects into freed pages:**
```c
// Clone with reduced noise flags
for (int i = 0; i < 320; i++) {
    __clone(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND,
            &check_and_wait);
}
```

**Phase 4 --- Free remaining held pages and spray vulnerable objects:**
```c
for (int i = 0; i < 1000; i += 2) {
    send_spray_cmd(FREE_PAGE, i);
}
// Spray vulnerable 512-byte objects adjacent to cred pages
for (int i = 0; i < 50; i++) {
    alloc_vuln_page(fd, isolation_pages, i);
    edit_vuln_page(fd, isolation_pages, i, evil, 512);
}
```

**Phase 5 --- Cross-cache overflow overwrites cred:**
```c
// Overflow payload: set usage=1, uid=0, gid=0
*(uint32_t*)&evil[512 - 6] = 1;  // Keep cred->usage valid
// Remaining 2 bytes zero out uid
```

This achieves a **leakless, data-only** privilege escalation against isolated cred objects.

### 6.3 DirtyCred (BlackHat 2022)

DirtyCred extends cross-cache concepts to credential structures using UAF/double-free/arbitrary-free primitives:

1. Use a UAF to free a normal-user `cred` object
2. Trigger a privileged operation (e.g., from a root-owned process) that allocates a new `cred` into the freed slot
3. The dangling reference from the original task now points to privileged credentials

This works because `cred_jar` serves all credential allocations regardless of privilege level.

### 6.4 Countermeasures and Their Limitations

**AUTOSLAB (grsecurity)**: Isolates each `kmalloc` call site into a dedicated cache, making in-cache type confusion impossible. However, cross-cache attacks at the page level still work, though with added difficulty from:
- Random offset at the beginning of slab pages (misaligns objects across caches)
- Invalid-free detection (prevents freeing the middle of objects)
- Freed pages go to tail of buddy freelist (reduces predictability)
- Dynamic slab page order increases (forces higher memory pressure for grooming)

---

## 7. Page-Level Exploitation Techniques

Page-level techniques operate below the slab allocator, directly manipulating the buddy allocator to achieve memory layout control.

### 7.1 Page Spray via PACKET_TX_RING / PACKET_RX_RING

The `PACKET_TX_RING` setsockopt option allocates pages directly from the buddy allocator:

```c
int alloc_pages_via_sock(uint32_t size, uint32_t n) {
    struct tpacket_req req;
    int socketfd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);

    int version = TPACKET_V1;
    setsockopt(socketfd, SOL_PACKET, PACKET_VERSION,
               &version, sizeof(version));

    req.tp_block_size = size;      // Must be page-aligned
    req.tp_block_nr = n;           // Number of pages
    req.tp_frame_size = 4096;
    req.tp_frame_nr = (size * n) / 4096;

    setsockopt(socketfd, SOL_PACKET, PACKET_TX_RING,
               &req, sizeof(req));
    return socketfd;
}

// Allocate order-0 pages: alloc_pages_via_sock(4096, 1)
// Free them: close(socketfd)
```

This requires `CAP_NET_RAW` or an unprivileged user namespace with `CLONE_NEWNET`.

### 7.2 Buddy Allocator Manipulation

The buddy allocator maintains freelists for each order (order-0 = 4KB, order-1 = 8KB, etc.). Key properties:

- **Page splitting**: When order-n is empty, order-(n+1) is split into two order-n pages
- **Page coalescing**: When an order-n page is freed and its buddy is also free, they merge into order-(n+1)
- **Anti-coalescing**: By holding one page of each buddy pair, the attacker prevents coalescing, maintaining order-0 pages in a controlled state

**Anti-coalescing spray pattern:**
```
Allocate: P0, P1, P2, P3, P4, P5, P6, P7...
Free alternating: P1, P3, P5, P7...
Result: P0[held] P1[free] P2[held] P3[free]...
Free pages cannot coalesce (buddies P0, P2 still held)
```

### 7.3 VMAlloc Exploitation

`vmalloc` allocates virtually contiguous but physically discontiguous pages. Kernel thread stacks (16KB, 4 order-0 pages) are allocated via `vmalloc`, consuming pages from the buddy allocator. This is relevant for cross-cache because:

1. Each `fork()`/`clone()` allocates a kernel stack (4 order-0 pages via vmalloc)
2. These pages come from the same buddy allocator pool
3. After process exit, pages return to the buddy allocator
4. A subsequent slab allocation can reclaim them

---

## 8. Elastic Objects Technique

"Elastic objects" are kernel objects whose size is variable and controlled by the user, allowing allocation into arbitrary slab caches. They are the backbone of modern heap exploitation.

### 8.1 msg_msg (The Most Versatile Elastic Object)

`struct msg_msg` (48 bytes header) followed by up to `PAGE_SIZE - 48` bytes of user data. Total allocation size is `sizeof(msg_msg) + min(user_data_len, DATALEN_MSG)`.

- **Size range**: 64 bytes to 4096 bytes (kmalloc-64 through kmalloc-4k)
- **Segments**: Messages larger than one page use `msg_msgseg` linked list segments
- **User-controlled content**: Message body is fully user-controlled
- **Read-back**: `msgrcv()` copies data back to userspace
- **Preserving reads**: `MSG_COPY` flag reads without freeing (requires `CONFIG_CHECKPOINT_RESTORE`)

**Exploitation primitives from msg_msg corruption:**

#### a) Out-of-Bounds Read (OOB Read)
By corrupting `msg_msg.m_ts` (message size field) to a larger value:
```
Corrupted msg_msg:  [m_list.next | m_list.prev | m_type=1 | m_ts=0x2000 | next=NULL | security]
                    [  user data (0x10 bytes)  ][ ADJACENT OBJECT DATA LEAKED... ]
```
When `msgrcv()` is called, it copies `m_ts` bytes, reading beyond the message into adjacent memory.

#### b) Arbitrary Read
By corrupting both `m_ts` and `msg_msg.next` (segment pointer):
```
Corrupted msg_msg:  [m_list | m_type | m_ts=0x2000 | next=TARGET_ADDR | security]
```
`store_msg()` follows the `next` pointer and copies data from `TARGET_ADDR`, achieving arbitrary kernel read.

#### c) Arbitrary Free
By corrupting `msg_msg.security` to point at a target object, then receiving the message:
```
msg_msg.security = target_address
msgrcv(qid, ...) -> free_msg() -> security_msg_msg_free() -> kfree(msg->security)
```
This frees the object at `target_address`.

#### d) Arbitrary Write
Combine arbitrary free with heap spray to reclaim the freed target with controlled data.

### 8.2 Other Important Elastic Objects

| Object | Size Range | Control | Notes |
|--------|-----------|---------|-------|
| `msg_msg` | 64 - 4096 | Full body | Primary spray object |
| `msg_msgseg` | 8 - 4096 | Full body | Segment of msg_msg |
| `sk_buff` data | Variable | Full body | Network packet data |
| `setxattr` buffer | Arbitrary | Full content | Temporary; combined with userfaultfd |
| `pipe_buffer` array | 40 * nr_bufs | Partial | Contains `pipe_buf_operations` pointer |
| `add_key` payload | Variable | Full content | User keyring data |
| `sendmsg` control | Variable | Full content | Socket control messages |
| `io_uring` SQE buffer | Variable | Full content | Registered buffer data |

### 8.3 setxattr + userfaultfd Technique

`setxattr()` allocates a kernel buffer of user-specified size, copies user data into it, then frees it. By using `userfaultfd` to stall the copy mid-way:

1. Map two adjacent pages; register the second page with userfaultfd
2. Place spray payload at the boundary: last N bytes of page 1, first bytes of page 2
3. Call `setxattr()` with pointer to end of page 1
4. Kernel allocates kmalloc buffer, begins `copy_from_user()`
5. Copy stalls at page boundary (userfaultfd fault on page 2)
6. Kernel buffer is allocated and partially filled --- attacker has a controlled allocation that persists until the userfaultfd fault is resolved
7. Perform exploit operations while the buffer exists
8. Resolve the fault to complete or abort the setxattr

**Note**: `userfaultfd` is restricted on many systems (`sysctl vm.unprivileged_userfaultfd=0`). Alternatives include `FUSE` filesystems.

---

## 9. State of the Art (2024-2026)

### 9.1 In-the-Wild Exploit Analysis (2022-2025)

Recent in-the-wild exploits demonstrate the sophistication of modern kernel exploitation:

**CVE-2023-0266 + CVE-2023-26083 (Android, Dec 2022)**:
Analyzed by Google Project Zero (Seth Jenkins), this chain used:
- A race condition in the ALSA 32-bit compatibility layer (missing locks)
- Mali GPU driver features for heap spray (REQ_SOFT_JIT_FREE jobs for temporally indefinite, variable-size, controllable heap spray)
- Mali tlstream facility for placing controlled data at known kernel addresses (16 bytes at a time)
- Type confusion via `file_operations` replacement: overwrote `ashmem_misc.fops` to redirect future `open("/dev/ashmem")` calls through a forged fops table combining `configfs_read_file`/`configfs_write_file` with ashmem operations
- This created a stable arbitrary read/write primitive from the unreliable initial write

**CVE-2024-1086 (nf_tables, Linux universal)**:
A double-free in netfilter's nf_tables achieved universal local privilege escalation on most Linux distributions. The exploit:
- Used page-level grooming to achieve cross-cache exploitation
- Targeted page table entries for arbitrary physical memory access
- Achieved near-100% reliability on tested distributions

### 9.2 Emerging Bypass Themes

#### a) Coprocessor/Firmware Exploitation
As documented by Project Zero's analysis of the Samsung DCP exploit chain, attackers increasingly target coprocessors that share memory with the main kernel but lack its mitigation stack. The DCP exploit achieved kernel read/write by:
1. Exploiting a heap overflow in the DCP firmware (no ASLR, no CFI, no PAC)
2. Corrupting a C++ vtable on the coprocessor
3. Using the DCP-to-AP RPC interface to request arbitrary DART (IOMMU) mappings
4. Reading and writing kernel memory through these mappings

#### b) Kernel Oops Exploitation
Seth Jenkins (Project Zero) demonstrated that kernel oops (non-fatal crashes) can be weaponized for exploitation. When a null-dereference triggers an oops:
- The faulting thread is killed, but held resources (locks, refcounts) are not released
- `mm_users` refcount (using non-saturating `atomic_t`) can be overflowed by triggering ~2^32 oopses
- Once overflowed to 0, `mmput()` triggers UAF on the `mm_struct`
- Concurrent `exit_aio()` calls on the UAF'd mm achieve double-free of `mm->ioctx_table`

The kernel now has an oops limit (`CONFIG_PANIC_ON_OOPS_VALUE`) that panics after too many oopses, but this must be backported to all LTS releases.

#### c) Reviving modprobe_path
Theori (March 2025) published research on reviving the `modprobe_path` overwrite technique after the upstream kernel patched `search_binary_handler()` to prevent triggering via dummy files. Their new approach demonstrates that the underlying primitive remains viable with modified trigger mechanisms.

#### d) RCU Race Exploitation
CVE-2024-27394 (TCP-AO UAF) demonstrated exploitation of races in RCU (Read-Copy-Update) API usage. Improper RCU lifecycle management creates temporal windows where freed objects are still accessible, providing UAF primitives in highly concurrent kernel subsystems.

### 9.3 Defense Evolution

| Mitigation | Status (6.x) | Bypass Difficulty |
|-----------|--------------|-------------------|
| KASLR | Universal | Low (many leak vectors; EntryBleed CVE-2022-4543 bypasses KPTI) |
| SMEP/SMAP | Universal | Medium (ROP/JOP required; no direct userspace execution/access) |
| KPTI | Universal | Low (KPTI trampoline in ROP chain) |
| Stack Canaries | Universal | Medium (requires infoleak) |
| kCFI (forward) | Opt-in (Clang) | Medium (type-compatible reuse; data-only attacks) |
| Shadow Call Stack | ARM64 opt-in | High (dedicated register, separate memory) |
| SLAB_FREELIST_HARDENED | Default | Medium (requires leak of random + address) |
| SLAB_FREELIST_RANDOM | Default | Low (heap grooming defeats it) |
| CONFIG_RANDSTRUCT | Opt-in | Medium (per-binary; inference attacks) |
| AUTOSLAB (grsecurity) | Proprietary | High (cross-cache still possible but harder) |
| MTE (ARM) | Hardware, emerging | Unknown (tag bypass research ongoing) |
| Kernel oops limit | 6.2+ | N/A (DoS tradeoff) |

### 9.4 The Exploit Developer's Modern Workflow

A typical 2024-2026 kernel exploit follows this general pattern:

```
1. VULNERABILITY TRIGGER
   |
   v
2. HEAP GROOMING (drain caches, shape buddy allocator)
   |
   v
3. PRIMITIVE UPGRADE
   UAF/overflow -> cross-cache -> type confusion
   OR: UAF -> msg_msg corruption -> arbitrary read
   |
   v
4. INFORMATION LEAK
   Read kernel pointers (defeat KASLR)
   Read stack canary / task_struct / cred address
   |
   v
5. ARBITRARY WRITE CONSTRUCTION
   Corrupted msg_msg segment pointer, or
   Forged file_operations (configfs trick), or
   Pipe buffer corruption, or
   Page table manipulation
   |
   v
6. PRIVILEGE ESCALATION
   Data-only: overwrite cred->uid/euid/gid/egid = 0
   OR: overwrite modprobe_path/core_pattern
   OR (if no CFI): ROP to commit_creds(prepare_kernel_cred(0))
   |
   v
7. CLEANUP
   Fix corrupted data structures to prevent crash
   Restore msg_msg lists, refcounts, etc.
```

The trend is clearly toward **data-only attacks** that avoid control flow hijacking entirely, combined with **cross-cache / page-level techniques** that defeat per-cache isolation. As hardware memory tagging (ARM MTE) matures, the next frontier will likely involve tag oracle attacks, tag bypass via speculative execution, and further exploitation of coprocessor/firmware attack surfaces that exist outside the memory safety boundary.

---

## References

1. Project Zero, "A Very Powerful Clipboard: Samsung in-the-wild exploit chain" (2022)
2. Project Zero, "Analyzing a Modern In-the-wild Android Exploit" (Seth Jenkins, 2023)
3. Project Zero, "Exploiting null-dereferences in the Linux kernel" (Seth Jenkins, 2023)
4. Project Zero, "The curious tale of a fake Carrier.app" (Ian Beer, 2022) - DCP exploitation
5. will's root, "Reviving Exploits Against Cred Structs - Cross Cache Overflow" (2022)
6. Alexander Popov, "Four Bytes of Power: Exploiting CVE-2021-26708" (2021)
7. grsecurity, "How AUTOSLAB Changes the Memory Unsafety Game" (Zhenpeng Lin, 2021)
8. D3v17/syst3mfailure, "Wall of Perdition: msg_msg Exploitation Toolkit" (corCTF 2021)
9. Google Security Research, CVE-2021-22555 "2 bytes to $20,000" (Andy Nguyen, 2021)
10. Zhenpeng Lin et al., "ELOISE: Exploiting Linux Objects with Isolated Slabs" (IEEE S&P)
11. will's root, "EntryBleed: Breaking KASLR under KPTI with Prefetch" (CVE-2022-4543, 2022)
12. Theori, "Reviving the modprobe_path Technique" (2025)
13. Theori, "Deep Dive into RCU Race Condition: CVE-2024-27394" (2024)
14. DirtyCred, "Cautious: A New Exploitation Method" (BlackHat USA 2022)
15. duasynt, "Linux Kernel Heap Feng Shui 2022"
16. StarLabs, "All Roads Lead to GKE's Host" (DEF CON 2022) - Cross-cache depth
