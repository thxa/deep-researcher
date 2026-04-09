# 2b. Common Kernel Vulnerability Classes: Specific Vulnerability Patterns

## Table of Contents

1. [copy_from_user/copy_to_user Misuse Patterns](#1-copy_from_usercopy_to_user-misuse-patterns)
2. [Missing or Incorrect Bounds Checking in Syscall Handlers](#2-missing-or-incorrect-bounds-checking-in-syscall-handlers)
3. [Slab Allocator Vulnerabilities](#3-slab-allocator-vulnerabilities-kmalloc-slubslab-specific-issues)
4. [Reference Counting Bugs Leading to Use-After-Free](#4-reference-counting-bugs-kref-refcount_t-leading-to-use-after-free)
5. [Double-Free Vulnerabilities](#5-double-free-vulnerabilities-and-their-kernel-manifestations)
6. [Off-by-One Errors in Kernel Code](#6-off-by-one-errors-in-kernel-code)
7. [Uninitialized Memory/Variable Vulnerabilities](#7-uninitialized-memoryvariable-vulnerabilities-info-leaks-from-stackheap)
8. [Signedness Bugs and Their Exploitation Potential](#8-signedness-bugs-and-their-exploitation-potential)

---

## 1. copy_from_user/copy_to_user Misuse Patterns

### 1.1 Overview

The `copy_from_user()` and `copy_to_user()` family of functions are the primary mechanism by which the Linux kernel safely transfers data between kernel space and user space. Their prototypes are:

```c
unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
```

Both functions return the **number of bytes that could NOT be copied** -- a return value of zero indicates complete success. A common and critical class of bugs arises from mishandling these functions.

### 1.2 Unchecked Return Values

The most elementary misuse is ignoring the return value. If `copy_from_user()` fails partway through a copy, the kernel buffer will contain partially initialized data -- potentially leading to logic errors or information leaks.

**Vulnerable Pattern:**
```c
/* BAD: return value ignored */
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct my_request req;
    copy_from_user(&req, (void __user *)arg, sizeof(req));
    /* 'req' may be partially uninitialized if copy failed */
    process_request(&req);
    return 0;
}
```

**Correct Pattern:**
```c
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct my_request req;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    process_request(&req);
    return 0;
}
```

### 1.3 Incorrect Size Arguments

A subtle but dangerous error occurs when the size parameter does not match the actual buffer size. This can lead to heap or stack buffer overflows in kernel space.

**Vulnerable Pattern:**
```c
struct header {
    u32 type;
    u32 length;
};

static int handle_message(void __user *ubuf)
{
    struct header hdr;
    char data[256];

    if (copy_from_user(&hdr, ubuf, sizeof(hdr)))
        return -EFAULT;

    /* BUG: user controls hdr.length, which may exceed sizeof(data) */
    if (copy_from_user(data, ubuf + sizeof(hdr), hdr.length))
        return -EFAULT;

    /* Stack buffer overflow if hdr.length > 256 */
    process_data(data, hdr.length);
    return 0;
}
```

### 1.4 TOCTOU (Time-of-Check-Time-of-Use) Races

When the kernel copies a value from user space, validates it, and then copies again from the same user space address, a race condition exists. A concurrent thread can modify the user space memory between the two copies.

**Vulnerable Pattern:**
```c
struct cmd {
    u32 opcode;
    u32 size;
    u64 data_ptr;
};

static int vuln_ioctl(unsigned long arg)
{
    struct cmd c;
    struct cmd __user *ucmd = (struct cmd __user *)arg;

    /* First copy: validate */
    if (copy_from_user(&c, ucmd, sizeof(c)))
        return -EFAULT;

    if (c.size > MAX_SIZE)
        return -EINVAL;

    /* Second copy: the user may have changed c.size since validation */
    if (copy_from_user(&c, ucmd, sizeof(c)))  /* BUG: TOCTOU */
        return -EFAULT;

    buf = kmalloc(c.size, GFP_KERNEL);  /* Now c.size might be > MAX_SIZE */
    /* ... */
}
```

**Mitigation:** Always copy user data to kernel memory exactly once, then validate the kernel-side copy. Never re-read from user space after validation.

### 1.5 copy_to_user Information Leaks

When copying data to user space, if kernel buffers are not fully initialized (e.g., struct padding holes, union members), kernel stack or heap data can leak to an unprivileged user. This is covered in more depth in [Section 7](#7-uninitialized-memoryvariable-vulnerabilities-info-leaks-from-stackheap).

### 1.6 Hardened Usercopy (CONFIG_HARDENED_USERCOPY)

Introduced in Linux 4.8 (based on PaX/grsecurity's `PAX_USERCOPY`), hardened usercopy adds runtime checks to `copy_*_user()` to verify:

- The kernel pointer is not NULL and does not point to a zero-length allocation.
- The address range does not wrap past the end of memory.
- The address range does not overlap the kernel text segment.
- If the kernel address points into a slab-allocated object, the copy fits within the allocated object size.
- Stack copies fit within the current process's stack (and, on x86, within a single stack frame).

These checks detect exploits that try to read or write beyond the bounds of a kernel buffer via corrupted user copy parameters. A violation triggers a `BUG()`, killing the offending process.

---

## 2. Missing or Incorrect Bounds Checking in Syscall Handlers

### 2.1 Overview

System call handlers are the primary entry point for unprivileged user space code to interact with the kernel. Every parameter accepted from user space is attacker-controlled and must be rigorously validated. Failure to do so can lead to out-of-bounds memory access, integer overflows, and privilege escalation.

### 2.2 Array Index Without Bounds Check

A recurring pattern occurs when a user-supplied integer is used directly as an array index without bounds validation.

**Vulnerable Pattern:**
```c
#define MAX_ENTRIES 64
static struct entry entries[MAX_ENTRIES];

SYSCALL_DEFINE2(my_get_entry, int, index, struct entry __user *, uentry)
{
    /* BUG: no bounds check on 'index' */
    if (copy_to_user(uentry, &entries[index], sizeof(struct entry)))
        return -EFAULT;
    return 0;
}
```

A negative `index` or one >= `MAX_ENTRIES` leads to an out-of-bounds read. Since `index` is `int`, negative values cause reads at addresses below the `entries` array.

**Correct Pattern:**
```c
SYSCALL_DEFINE2(my_get_entry, int, index, struct entry __user *, uentry)
{
    if (index < 0 || index >= MAX_ENTRIES)
        return -EINVAL;
    if (copy_to_user(uentry, &entries[index], sizeof(struct entry)))
        return -EFAULT;
    return 0;
}
```

### 2.3 Integer Overflow in Size Calculations

Open-coded arithmetic in allocator arguments is a well-documented vulnerability class. The Linux kernel's deprecated interfaces document explicitly warns against patterns like `count * size` in allocator calls because they can overflow silently.

**Vulnerable Pattern:**
```c
/* BAD: integer overflow if count is large */
buf = kmalloc(count * elem_size, GFP_KERNEL);
if (!buf)
    return -ENOMEM;
if (copy_from_user(buf, ubuf, count * elem_size))
    /* ... */
```

If `count * elem_size` wraps around to a small value, `kmalloc()` allocates a tiny buffer, but the subsequent `copy_from_user()` writes far beyond it.

**Correct Pattern:**
```c
buf = kmalloc_array(count, elem_size, GFP_KERNEL);
/* or */
if (check_mul_overflow(count, elem_size, &total))
    return -EOVERFLOW;
buf = kmalloc(total, GFP_KERNEL);
```

The kernel provides `kmalloc_array()`, `kcalloc()`, `struct_size()`, `array_size()`, `size_mul()`, `size_add()`, and `size_sub()` helpers that saturate to `SIZE_MAX` on overflow, causing allocation failure rather than corruption.

### 2.4 Real-World Example: CVE-2010-3904 (RDS Protocol)

The Reliable Datagram Sockets (RDS) protocol had a vulnerability where `rds_page_copy_user()` failed to properly validate that a user-supplied offset and length would not exceed page boundaries. An unprivileged local user could trigger a write to arbitrary kernel memory, enabling privilege escalation to root.

### 2.5 ioctl Command Validation Gaps

Many kernel vulnerabilities exist in `ioctl` handlers where the `cmd` or `arg` parameter is insufficiently validated. Drivers frequently assume that only their intended user space library will call their ioctls, but any process with access to the device file can pass arbitrary values.

```c
static long drv_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case DRV_CMD_SET_PARAM:
        /* arg assumed to be a valid pointer to a known struct --
         * but what if an attacker passes cmd=DRV_CMD_SET_PARAM
         * with a malicious arg? */
        return set_param((struct drv_param __user *)arg);
    /* Missing default: case -- unknown cmds silently accepted */
    }
    return 0;  /* BUG: should return -ENOTTY for unknown commands */
}
```

---

## 3. Slab Allocator Vulnerabilities (kmalloc, SLUB/SLAB Specific Issues)

### 3.1 Overview

The Linux kernel's slab allocators (SLAB, SLUB, SLOB) manage dynamically allocated kernel objects. SLUB is the default on most modern distributions. Vulnerabilities in how kernel code interacts with the slab allocator -- and in the allocator's internal metadata -- are critical to both bug manifestation and exploitation.

### 3.2 Heap Buffer Overflows (Linear Overflows)

A linear overflow in a slab-allocated object overwrites adjacent data within the same slab page. Because SLUB packs objects contiguously (without inter-object redzone by default in production kernels), overflowing one object corrupts the next.

**Exploitation technique -- Cross-cache attacks:** When vulnerable and target objects live in different `kmem_cache`s, attackers can use cross-cache techniques. These involve:

1. Draining a slab page so it returns to the page allocator.
2. Reallocating the page for a different `kmem_cache` containing the target object type.

This is facilitated by SLUB's slab merging behavior: `find_mergeable()` may merge different caches with matching object size, alignment, and flags into one, making same-cache attacks more straightforward. On Debian's default kernel, for example, `struct pid`, `struct seq_file`, and `struct epitem` are commonly merged into the same 128-byte cache.

### 3.3 Freelist Pointer Corruption

SLUB stores a freelist pointer in the first 8 bytes of each freed object (as of Linux 5.7, the offset is randomized within the object). With `CONFIG_SLAB_FREELIST_HARDENED`, this pointer is XOR-obfuscated:

```c
/* Simplified SLUB freelist pointer encoding */
static inline void *freelist_ptr(const struct kmem_cache *s,
                                  void *ptr, unsigned long ptr_addr)
{
    return (void *)((unsigned long)ptr ^ s->random ^ swab(ptr_addr));
}
```

Despite this hardening, an attacker with a heap overflow that can overwrite a freed object's freelist pointer may be able to redirect allocations to arbitrary addresses. Bypassing the XOR encoding requires either:
- A known `s->random` value (leaked via info disclosure), or
- A partial overwrite that preserves most of the encoded pointer.

### 3.4 SLUB Metadata and Page-Level Attacks

SLUB stores per-slab metadata in `struct slab` (formerly in `struct page`), not inline with object data. This means corrupting the freelist pointer of one object does not directly corrupt allocator metadata as it would in classic glibc heap exploits. However, the `page->freelist` pointer, per-cpu freelists, and partial slab lists are all potential targets if an attacker can gain write access to `struct page` metadata.

### 3.5 Use-After-Free via Slab Reuse

When a slab object is freed and its cache slot is reused for a new object of a different type (or same type with different state), a dangling pointer to the original object now accesses the new one. This is the fundamental mechanism behind slab-level UAF exploitation.

**Exploitation primitive -- "elastic objects":** Research by Zhenpeng Lin et al. (2020) identified "elastic objects" -- kernel objects whose size can be controlled by user space. These are valuable because an attacker can allocate them at the exact size needed to land in the same slab cache as the freed victim. Common elastic objects include:

- `msg_msg` (System V messages, size controllable via `msgsnd()`)
- `sk_buff` data (network packet data, size controllable via `sendmsg()`)
- `setxattr` buffers (temporary heap allocations of controllable size)
- `add_key` payloads (keyring subsystem)
- `pipe_buffer` arrays

### 3.6 kmalloc Overflow Arithmetic

As documented in the kernel's deprecated interfaces guide, open-coded arithmetic like `kmalloc(count * size, GFP_KERNEL)` is dangerous because the multiplication can silently overflow to a small value:

```c
/* VULNERABLE: if count = 0x100000001 and size = 0x100,
 * on 64-bit: count * size = 0x10000000100, no overflow, large alloc.
 * But if size is larger, or on 32-bit with size_t overflow... */
foo = kmalloc(count * size, GFP_KERNEL);
```

The replacement helpers `kmalloc_array()` and `kcalloc()` use `check_mul_overflow()` internally:

```c
static inline __alloc_size(1, 2) void *kmalloc_array(size_t n, size_t size,
                                                       gfp_t flags)
{
    size_t bytes;
    if (unlikely(check_mul_overflow(n, size, &bytes)))
        return NULL;
    if (__builtin_constant_p(n) && __builtin_constant_p(size))
        return kmalloc(bytes, flags);
    return __kmalloc(bytes, flags);
}
```

For structures with flexible array members, `struct_size()` should be used:
```c
/* Instead of: kmalloc(sizeof(*hdr) + count * sizeof(*hdr->items), ...) */
hdr = kmalloc(struct_size(hdr, items, count), GFP_KERNEL);
```

---

## 4. Reference Counting Bugs (kref, refcount_t) Leading to Use-After-Free

### 4.1 Overview

Reference counting is pervasive in the Linux kernel for lifecycle management of dynamically allocated objects. When a reference count reaches zero, the object is freed. Bugs in reference counting -- either incrementing too much (overflow) or decrementing too much (underflow) -- lead directly to use-after-free or memory leaks, with the former being reliably exploitable for privilege escalation.

### 4.2 Reference Counting Primitives

The kernel has evolved through several reference counting mechanisms:

| Primitive | Overflow Protection | Underflow Protection | Introduced |
|-----------|-------------------|---------------------|------------|
| `atomic_t` | None | None | Original |
| `kref` (wraps `refcount_t`) | Yes | Yes | 2.6.x / hardened 4.11 |
| `refcount_t` | Saturates at `REFCOUNT_SATURATED` | Warns/saturates | 4.11 |

The `refcount_t` API was introduced to provide hardened reference counting. When `CONFIG_REFCOUNT_FULL` is enabled (default since 5.x), all operations check for overflow and underflow:

```c
/* refcount_t increment with saturation */
void refcount_inc(refcount_t *r)
{
    if (refcount_inc_not_zero(r))
        return;
    /* Already zero -- WARN and saturate */
    WARN_ONCE(true, "refcount_t: increment on 0; use-after-free.\n");
    refcount_set(r, REFCOUNT_SATURATED);
}
```

When the refcount reaches `REFCOUNT_SATURATED` (approximately `INT_MAX/2`), it becomes "pinned" -- further increments and decrements are silently ignored, preventing the object from ever being freed. This neutralizes overflow-based attacks.

### 4.3 Classic Vulnerability: Excessive Decrement (Double put)

The most common reference counting bug is performing an extra decrement without a corresponding increment. This often occurs in error-handling paths.

**CVE-2017-11176: mq_notify double sock_put()** is a canonical example. The vulnerability was in the POSIX message queue notification syscall:

```c
/* Simplified vulnerable code from ipc/mqueue.c */
SYSCALL_DEFINE2(mq_notify, mqd_t, mqdes,
                const struct sigevent __user *, u_notification)
{
    struct sock *sock;
    /* ... */
    sock = NULL;
retry:
    filp = fget(notification.sigev_signo);
    if (!filp) {
        ret = -EBADF;
        goto out;       /* BUG: sock is not NULL on retry, triggers extra put */
    }
    sock = netlink_getsockbyfilp(filp);  /* Takes reference on sock */
    fput(filp);
    /* ... */
    ret = netlink_attachskb(sock, nc, &timeo, NULL);
    if (ret == 1)
        goto retry;     /* BUG: sock not set to NULL; ref already dropped */
    /* ... */
out:
    if (sock)
        netlink_detachskb(sock, nc);  /* Drops reference again -- DOUBLE PUT */
    return ret;
}
```

The fix was a single line: setting `sock = NULL` before `goto retry`.

**Attack scenario:**
1. Thread 1 enters `mq_notify()`, `netlink_attachskb()` returns 1 (retry), dropping the sock reference.
2. Thread 2 calls `close()` on the file descriptor, dropping the last file reference, which in turn drops the last sock reference -- the sock is freed.
3. Thread 1 resumes at `retry`. `fget()` fails (fd was closed). `goto out` with non-NULL `sock`.
4. `netlink_detachskb()` calls `sock_put()` on freed memory -- **use-after-free**.

### 4.4 Overflow-Based Attacks (CVE-2016-0728)

If an attacker can trigger enough increments to a 32-bit reference counter, it will overflow from `INT_MAX` to 0, causing a premature free while references still exist.

**CVE-2016-0728** exploited the keyring subsystem's `key->usage` reference counter (which used `atomic_t`). By repeatedly calling `keyctl(KEYCTL_JOIN_SESSION_KEYRING, ...)`, an attacker could increment the counter ~2^32 times, overflowing it to zero, freeing the key while retaining dangling references. The freed key object was then reallocated with attacker-controlled data for privilege escalation.

This attack class was neutralized by:
1. Converting `atomic_t` reference counters to `refcount_t` (which saturates instead of overflowing).
2. PaX/grsecurity's `PAX_REFCOUNT` feature, which added overflow detection to `atomic_t` operations.

### 4.5 Subtle Pattern: Reference in Error Paths

```c
int some_operation(struct my_obj *obj)
{
    my_obj_get(obj);   /* Take reference */

    ret = do_step_one(obj);
    if (ret)
        goto err;      /* BUG: reference not dropped */

    ret = do_step_two(obj);
    if (ret)
        goto err_put;

    /* Success path */
    return 0;

err_put:
    my_obj_put(obj);
err:
    /* Missing my_obj_put(obj) for do_step_one failure */
    return ret;
}
```

Such bugs are insidious because error paths are rarely exercised in normal testing. Tools like `syzkaller` (continuous kernel fuzzer) are effective at discovering them by exhaustively exploring error conditions.

---

## 5. Double-Free Vulnerabilities and Their Kernel Manifestations

### 5.1 Overview

A double-free occurs when `kfree()` (or a cache-specific free function like `kmem_cache_free()`) is called twice on the same pointer. In the kernel's slab allocator, this corrupts the freelist, potentially allowing an attacker to control future allocations.

CWE-415 classifies double-free as a variant of "Operation on Resource in Wrong Phase of Lifetime." In kernel context, double-frees are frequently the result of confused cleanup logic, race conditions, or reference counting errors (as discussed in Section 4).

### 5.2 SLUB Allocator Behavior on Double-Free

With `CONFIG_SLAB_FREELIST_HARDENED` (enabled by default in modern kernels), SLUB detects simple double-frees by verifying that the object being freed is not already at the head of the freelist:

```c
/* In SLUB's set_freepointer() with CONFIG_SLAB_FREELIST_HARDENED */
static inline void set_freepointer(struct kmem_cache *s,
                                    void *object, void *fp)
{
    unsigned long freeptr_addr = (unsigned long)object + s->offset;
    BUG_ON(object == fp);  /* Detect immediate double-free */
    *(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
}
```

However, this check only catches the case where the same object is freed twice consecutively. If another object is freed in between (an ABA pattern), the detection is bypassed:

```
kfree(A);    /* A is at freelist head */
kfree(B);    /* B is at freelist head, A is second */
kfree(A);    /* A != B (head), check passes -- DOUBLE FREE */
```

After this sequence, the freelist contains: A -> B -> A -> ... This creates a cycle. The next three allocations return A, B, A -- meaning two different users both hold pointers to A, enabling type confusion and memory corruption.

### 5.3 Race Condition Induced Double-Frees

Many kernel double-frees arise from race conditions where two code paths independently decide to free the same object. This is structurally similar to the reference counting bugs in Section 4 -- indeed, a double `put` that decrements a refcount to zero twice is mechanistically a double-free.

**CVE-2021-25370 (Samsung DPU driver)** demonstrated a UAF/double-free pattern in a device driver:

```c
/* Simplified from Samsung DECON driver */
static int decon_set_win_config(struct decon_device *decon,
                                 struct decon_win_config_data *win_data)
{
    struct sync_file *sync_file;
    /* ... */
    win_data->retire_fence = decon_create_fence(decon, &sync_file);
    /* ... */

    /* BUG: fd_install transfers ownership to userspace.
     * User can immediately close() the fd, freeing sync_file->file */
    fd_install(win_data->retire_fence, sync_file->file);

    /* sync_file->file may already be freed here */
    decon_create_release_fences(decon, win_data, sync_file);
    /* ^^^ This function accesses sync_file->file -- USE AFTER FREE */
}
```

The fix moved `fd_install()` to after all kernel-side references to `sync_file->file` were complete.

### 5.4 Preventing Double-Frees

- **Set pointers to NULL after free.** While not always practical in kernel code (multiple references may exist), it prevents the simplest double-free patterns.
- **Use `refcount_t` instead of `atomic_t`** for object lifecycle management.
- **KASAN (Kernel Address Sanitizer):** Detects double-frees at runtime during development/testing by maintaining quarantine zones for freed objects.
- **SLUB debug mode (`slub_debug=F`):** Enables full freelist validation, catching non-consecutive double-frees at the cost of significant performance overhead.

---

## 6. Off-by-One Errors in Kernel Code

### 6.1 Overview

Off-by-one errors in the kernel are particularly dangerous because they often corrupt adjacent slab objects or critical metadata. Even a single byte of overflow can be sufficient for exploitation.

### 6.2 Loop Boundary Errors

```c
/* VULNERABLE: writes one element past end of buffer */
static int parse_options(char *options, char **tokens, int max_tokens)
{
    int i;
    char *p = options;
    for (i = 0; i <= max_tokens; i++) {  /* BUG: should be < max_tokens */
        tokens[i] = strsep(&p, ",");
        if (!tokens[i])
            break;
    }
    return i;
}
```

### 6.3 String Termination Errors

The `strncpy()` function does not guarantee NUL termination when the source length equals or exceeds the destination size. The kernel's deprecated interfaces document explicitly warns about this, recommending `strscpy()` as the replacement:

```c
/* VULNERABLE: no NUL terminator if src >= 256 bytes */
char name[256];
strncpy(name, user_input, sizeof(name));
/* name may not be NUL-terminated, leading to read overflows later */
```

```c
/* CORRECT */
char name[256];
strscpy(name, user_input, sizeof(name));
/* strscpy() always NUL-terminates, returns -E2BIG on truncation */
```

### 6.4 Fence-Post Errors in Size Calculations

```c
/* Allocate space for a string plus NUL terminator */
size_t len = strlen(input);
buf = kmalloc(len, GFP_KERNEL);  /* BUG: need len + 1 for '\0' */
memcpy(buf, input, len);
buf[len] = '\0';  /* Writes one byte past allocation */
```

This single-byte overflow can corrupt the freelist pointer of the next slab object (if the object is freed) or critical data in the adjacent live object.

### 6.5 Exploitation of Single-Byte Overflows

In SLUB, objects are packed contiguously within a slab page. A one-byte overflow from object N corrupts the first byte of object N+1. If object N+1 is freed, that first byte is part of the (potentially XOR-encoded) freelist pointer. If object N+1 is live, the first byte of its data is corrupted.

For structures where the first byte is part of a pointer, function pointer, or size field, this can be devastating:

```
| Object N (overflowed) | Object N+1 (corrupted) |
| ...................\x00 | [first byte corrupted] |
```

Specific exploitation depends on what structure occupies object N+1. If it's a `struct seq_operations` (which begins with a function pointer), a NUL-byte overflow changes the pointer's least significant byte, potentially redirecting execution.

---

## 7. Uninitialized Memory/Variable Vulnerabilities (Info Leaks from Stack/Heap)

### 7.1 Overview

When the kernel copies data to user space without fully initializing it, residual kernel memory contents leak to an attacker. This commonly occurs through:

- **Struct padding holes:** C compilers insert padding between struct members for alignment. This padding is not zeroed by member-wise initialization.
- **Union members:** Only one member of a union is initialized, but the full union size is copied.
- **Partial initialization:** A buffer is allocated but only partially written before being copied to user space.
- **Stack reuse:** Local variables inherit whatever data was on the stack from previous function calls.

### 7.2 Struct Padding Leaks

```c
struct my_info {
    u8  type;           /* offset 0, size 1 */
    /* 3 bytes padding (uninitialized) */
    u32 value;          /* offset 4, size 4 */
    u16 flags;          /* offset 8, size 2 */
    /* 6 bytes padding (uninitialized) */
    u64 timestamp;      /* offset 16, size 8 */
};  /* total size: 24 bytes, but only 15 bytes explicitly initialized */

static int get_info(struct my_info __user *uinfo)
{
    struct my_info info;

    /* BUG: padding bytes contain stale stack data */
    info.type = current_type;
    info.value = current_value;
    info.flags = current_flags;
    info.timestamp = ktime_get_ns();

    /* Copies 24 bytes including 9 bytes of uninitialized padding */
    if (copy_to_user(uinfo, &info, sizeof(info)))
        return -EFAULT;
    return 0;
}
```

**Fix:** Use `memset(&info, 0, sizeof(info))` before member initialization, or use a designated initializer: `struct my_info info = {};`

### 7.3 Heap Info Leaks

When kernel heap objects are reused (via the slab allocator), a newly allocated object may contain remnants of previously freed objects. If this object is copied to user space before being fully initialized, those remnants leak.

```c
static int read_entry(int idx, void __user *ubuf)
{
    struct entry *e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return -ENOMEM;

    /* BUG: only some fields initialized, rest contain slab remnants */
    e->id = idx;
    e->status = get_status(idx);
    /* e->data[] not initialized -- contains old heap data */

    if (copy_to_user(ubuf, e, sizeof(*e))) {
        kfree(e);
        return -EFAULT;
    }
    kfree(e);
    return 0;
}
```

**Fix:** Use `kzalloc()` instead of `kmalloc()` when the object will be exposed to user space.

### 7.4 Stack Variable Info Leaks via Targeted Stack Spraying

Research by Kangjie Lu et al. (2017, "Unleashing Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying") demonstrated that uninitialized stack variables are not merely passive info leaks -- they can be actively exploited. By calling specific syscalls that deposit attacker-controlled values on the kernel stack, and then calling the vulnerable syscall that reads those stack locations without initialization, an attacker can control the "uninitialized" value.

**Exploitation flow:**
1. Call a "spray" syscall that writes attacker-controlled data to specific kernel stack offsets.
2. The spray syscall returns, leaving the data on the stack.
3. Call the vulnerable syscall. Its local variable occupies the same stack location and reads the sprayed value.

### 7.5 Kernel Mitigations

| Mitigation | Effect |
|-----------|--------|
| `CONFIG_INIT_STACK_ALL_ZERO` | Compiler initializes all stack variables to zero |
| `CONFIG_GCC_PLUGIN_STRUCTLEAK` | Initializes structures passed by reference |
| `CONFIG_KSTACK_ERASE` | Erases kernel stack on syscall return |
| `CONFIG_KMALLOC_ZEROING` (proposed) | Zero all kmalloc allocations |
| `memset()` / `kzalloc()` | Manual zeroing (developer responsibility) |

Since kernel 5.x, `CONFIG_INIT_STACK_ALL_ZERO` has been widely adopted, and modern GCC/Clang support `-ftrivial-auto-var-init=zero` to zero-initialize all automatic variables. This effectively eliminates the entire class of stack-based info leak vulnerabilities with minimal performance impact (typically < 1%).

### 7.6 Real-World Impact

Information leaks are frequently the first step in a multi-stage exploit chain. The Samsung in-the-wild exploit (CVE-2021-25369) used a `WARN_ON` triggered in the Mali GPU driver to leak the `task_struct` and `sys_call_table` addresses from the kernel stack backtrace via Samsung's custom `/data/log/sec_log.log` file. The leaked addresses were used to defeat KASLR and compute the `addr_limit` pointer for subsequent arbitrary kernel read/write.

---

## 8. Signedness Bugs and Their Exploitation Potential

### 8.1 Overview

The C language's implicit integer conversion rules are a frequent source of kernel vulnerabilities. When a signed value is used where an unsigned value is expected (or vice versa), the result can bypass security checks, create enormous allocation sizes, or enable out-of-bounds access.

### 8.2 Signed/Unsigned Comparison

```c
static int read_data(int offset, int length, char __user *ubuf)
{
    char kbuf[4096];

    /* BUG: if length is negative (attacker-controlled, passed via ioctl),
     * this check passes because -1 < 4096 is true for signed comparison */
    if (length > sizeof(kbuf))
        return -EINVAL;

    /* When length is implicitly converted to size_t (unsigned) for
     * copy_to_user, -1 becomes 0xFFFFFFFF (or 0xFFFFFFFFFFFFFFFF),
     * causing a massive read */
    if (copy_to_user(ubuf, &kbuf[offset], length))
        return -EFAULT;

    return 0;
}
```

The comparison `length > sizeof(kbuf)` compares a signed `int` with an unsigned `size_t`. Due to C's implicit conversion rules, when `sizeof()` returns `size_t` (unsigned), the signed `length` is converted to unsigned. If `length` is negative:

- On the comparison: `-1 > 4096` evaluates as `0xFFFFFFFF > 4096` which is TRUE -- **but only if both operands are promoted to the same unsigned type**. However, if `sizeof(kbuf)` fits in `int`, the comparison may actually be performed as signed (implementation-defined edge case). The actual behavior depends on the types involved.

The safer pattern:

```c
/* CORRECT: explicit unsigned type and >= 0 check */
if (length < 0 || (unsigned int)length > sizeof(kbuf))
    return -EINVAL;
```

### 8.3 Signed Index Used as Array Subscript

```c
/* User-controlled 'index' is int (signed) */
static int get_slot(int index)
{
    if (index >= MAX_SLOTS)
        return -EINVAL;
    /* BUG: negative index passes the check but accesses
     * memory before the array */
    return slots[index];
}
```

The check `index >= MAX_SLOTS` does not catch negative values. The fix requires either:
- Using `unsigned int` for the index type, or
- Adding an explicit `index < 0` check.

### 8.4 Truncation Bugs

When a 64-bit value is assigned to a 32-bit variable, the upper bits are silently discarded:

```c
static int allocate_buffer(unsigned long user_size)
{
    /* BUG on 64-bit: if user_size = 0x100000010, size = 0x10 */
    unsigned int size = user_size;

    char *buf = kmalloc(size, GFP_KERNEL);  /* Allocates only 16 bytes */
    if (!buf)
        return -ENOMEM;

    /* But later operations may use the original user_size */
    if (copy_from_user(buf, ubuf, user_size))  /* Copies 4GB+ into 16 bytes */
        /* ... */
}
```

### 8.5 The `int` vs `size_t` Mismatch

Many older kernel interfaces use `int` for sizes and lengths, while the underlying memory operations use `size_t` (unsigned, pointer-width). This creates opportunities for:

1. **Negative sizes passing validation:** An `int` length of -1 passes `if (len > MAX)` but becomes a huge value when cast to `size_t`.
2. **Sign extension:** A negative 32-bit `int` sign-extends to a 64-bit `size_t` with all upper bits set (`0xFFFFFFFF` -> `0xFFFFFFFFFFFFFFFF`).

### 8.6 Real-World Example: CVE-2013-2094

The perf subsystem had a vulnerability where a user-supplied `u64` value was assigned to a signed `int`:

```c
/* perf_swevent_init */
int event_id = event->attr.config;  /* u64 to int truncation */
```

An attacker could set `event->attr.config` to a value whose lower 32 bits, when interpreted as a signed integer, produced a negative array index. This bypassed the bounds check and enabled an out-of-bounds write into kernel memory, leading to privilege escalation.

### 8.7 Mitigations

- **Use unsigned types** (`unsigned int`, `size_t`, `u32`, `u64`) for sizes, lengths, counts, and indices wherever possible.
- **Explicit range checks** that validate both lower and upper bounds: `if (val < 0 || val > MAX)`.
- **Compiler warnings:** `-Wsign-compare`, `-Wconversion` can catch many signedness issues, though the Linux kernel does not enable all of these due to noise.
- **Coccinelle scripts:** The kernel community uses Coccinelle semantic patches to systematically find and fix signedness issues across the codebase.
- **Static analysis:** Tools like `sparse` (with `__attribute__((bitwise))`) and Coverity can detect many signedness conversion issues.

---

## Summary: Vulnerability Pattern Relationships

These eight vulnerability classes frequently interact and chain together in real-world exploits:

```
  Signedness Bug -----> Bounds Check Bypass -----> Heap Overflow
        |                                               |
        v                                               v
  Integer Overflow --> kmalloc undersized alloc --> Slab Corruption
                                                        |
  copy_from_user                                        v
  misuse -----------> Stack/Heap Buffer Overflow -> Adjacent Object Corruption
        |                                               |
        v                                               v
  Uninitialized       Off-by-one (freelist       Freelist Pointer
  Memory Leak ------> pointer corruption) -----> Hijack / UAF
        |                                               |
        v                                               v
  KASLR Defeat        Refcount Bug --------------> Use-After-Free
                            |                           |
                            v                           v
                      Double-Free                  Object Reuse / Type Confusion
                            |                           |
                            +--------> Privilege Escalation <--------+
```

A typical kernel exploit chain might:
1. Use an **info leak** (Section 7) to defeat KASLR.
2. Trigger a **signedness bug** (Section 8) to bypass a **bounds check** (Section 2).
3. Cause a **heap overflow** (Section 3) or **reference counting error** (Section 4).
4. Achieve **use-after-free** or **double-free** (Section 5) on a target object.
5. Use **slab manipulation** (Section 3) to reallocate the freed object with controlled data.
6. Gain arbitrary kernel read/write or code execution.

Understanding each pattern in isolation and their composition is essential for both vulnerability discovery and the development of effective mitigations.

---

## References

1. Linux Kernel Documentation: "Deprecated Interfaces, Language Features, Attributes, and Conventions" -- https://www.kernel.org/doc/html/latest/process/deprecated.html
2. Linux Kernel Documentation: "Kernel Self-Protection" -- https://www.kernel.org/doc/html/latest/security/self-protection.html
3. LWN.net: "Hardened usercopy" (2016) -- https://lwn.net/Articles/695991/
4. LWN.net: "Two approaches to reference count hardening" (2016) -- https://lwn.net/Articles/693038/
5. Jann Horn, Project Zero: "How a simple Linux kernel memory corruption bug can lead to complete system compromise" (2021) -- https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html
6. Maddie Stone, Project Zero: "A Very Powerful Clipboard: Analysis of a Samsung in-the-wild exploit chain" (2022) -- https://googleprojectzero.blogspot.com/2022/11/a-very-powerful-clipboard-samsung-in-the-wild-exploit-chain.html
7. Nicolas Fabretti, Lexfo: "CVE-2017-11176: A step-by-step Linux Kernel exploitation" (2018) -- https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
8. CWE-415: Double Free -- https://cwe.mitre.org/data/definitions/415.html
9. Andrey Konovalov: "SLUB Internals for Exploit Developers" (LSS EU 2024)
10. Zhenpeng Lin et al.: "A Systematic Study of Elastic Objects in Kernel Exploitation" (CCS 2020)
11. Kangjie Lu et al.: "Unleashing Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying" (NDSS 2017)
12. Cho et al.: "Exploiting Uses of Uninitialized Stack Variables in Linux Kernels to Leak Kernel Pointers" (WOOT 2020)
13. Andrey Konovalov: "Linux Kernel Exploitation" -- https://github.com/xairy/linux-kernel-exploitation
14. Patroklos Argyroudis: "The Linux kernel memory allocators from an exploitation perspective" (2012)
