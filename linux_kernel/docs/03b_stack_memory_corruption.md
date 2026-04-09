# Section 3b: Memory Corruption Vulnerabilities — Stack Exploitation and Beyond

## Table of Contents

1. [Kernel Stack Layout and Architecture](#1-kernel-stack-layout-and-architecture)
2. [Stack Buffer Overflows in Kernel Context](#2-stack-buffer-overflows-in-kernel-context)
3. [Stack Canaries in the Kernel (CONFIG_STACKPROTECTOR)](#3-stack-canaries-in-the-kernel)
4. [Kernel Stack Pivoting Techniques](#4-kernel-stack-pivoting-techniques)
5. [Out-of-Bounds Read/Write on the Kernel Stack](#5-out-of-bounds-readwrite-on-the-kernel-stack)
6. [The Transition from 8KB to 16KB Kernel Stacks](#6-the-transition-from-8kb-to-16kb-kernel-stacks)
7. [Return Address Overwriting and Control Flow Hijacking](#7-return-address-overwriting-and-control-flow-hijacking)
8. [Global Variable Corruption and Data-Only Attacks](#8-global-variable-corruption-and-data-only-attacks)
9. [DMA-Based Attacks and Physical Memory Corruption](#9-dma-based-attacks-and-physical-memory-corruption)

---

## 1. Kernel Stack Layout and Architecture

### 1.1 Per-Thread Kernel Stacks

Every task (thread) in the Linux kernel is assigned its own dedicated kernel stack. When a
user-space process issues a system call, triggers an exception, or is interrupted, the CPU
transitions from user mode (ring 3) to kernel mode (ring 0) and begins executing on that
thread's kernel stack. This is fundamentally different from the user-space stack (typically
8 MB, governed by `ulimit -s`), which is managed by virtual memory with guard pages and
on-demand page allocation.

The kernel stack is allocated at thread creation time (during `clone()` / `fork()` / 
`kernel_thread()`) and freed when the thread exits. The allocation is performed via
`alloc_thread_stack_node()`, and the resulting memory is referenced by the `task_struct->stack`
pointer.

```
struct task_struct {
    // ...
    void                *stack;        // Pointer to the base of the kernel stack
    // ...
    const struct cred   *cred;         // Process credentials
    struct mm_struct    *mm;           // Memory address space
    struct files_struct *files;        // Open file table
    // ...
};
```

### 1.2 Stack Size by Architecture

Kernel stack sizes are defined by `THREAD_SIZE` and `THREAD_SIZE_ORDER` and vary by
architecture:

| Architecture     | Stack Size | THREAD_SIZE_ORDER | Notes                                  |
|------------------|-----------|-------------------|----------------------------------------|
| x86 (32-bit)     | 8 KB      | 1 (2 pages)       | Historical default                     |
| x86_64 (64-bit)  | 16 KB     | 2 (4 pages)       | Expanded in Linux 3.15                 |
| ARM (32-bit)     | 8 KB      | 1 (2 pages)       |                                        |
| ARM64 (AArch64)  | 16 KB     | 2 (4 pages)       |                                        |
| RISC-V           | 16 KB     | 2 (4 pages)       |                                        |
| PowerPC (64-bit) | 16 KB or 32 KB | Variable    | CONFIG dependent                       |

These are fixed sizes allocated as physically contiguous pages -- there is no dynamic
growth. If the stack overflows, it silently corrupts adjacent memory.

### 1.3 Historical Stack Layout: thread_info at the Stack Base

In early Linux kernels, the `thread_info` structure was placed at the bottom (lowest
address) of the kernel stack allocation. Since stacks grow downward on most architectures
(toward lower addresses), a stack overflow would directly overwrite `thread_info`:

```
+-------------------+  High address (stack top)
|                   |
|   Stack frames    |  <- Stack grows downward
|   (grows down)    |
|                   |
+-------------------+
| Stack canary      |  <- STACK_END_MAGIC (0x57AC6E9D)
+-------------------+
| thread_info       |  <- Sensitive: flags, cpu, task pointer, addr_limit
+-------------------+  Low address (stack base)
```

The `thread_info` structure contained critical fields:

```c
struct thread_info {
    unsigned long       flags;          // TIF_NEED_RESCHED, TIF_SIGPENDING, etc.
    __u32               status;         // Thread synchronous flags
    __u32               cpu;            // Current CPU
    mm_segment_t        addr_limit;     // Address space limit (USER_DS vs KERNEL_DS)
    struct restart_block restart_block;  // System call restart info
    // ...
};
```

The `addr_limit` field was of particular interest to attackers. If overwritten from
`USER_DS` (0x00007FFFFFFFF000 on x86_64) to `KERNEL_DS` (0xFFFFFFFFFFFFFFFF), the
`copy_to_user()` and `copy_from_user()` functions would allow reading and writing arbitrary
kernel memory from user space, since the address-limit check would be bypassed.

### 1.4 Modern Stack Layout: CONFIG_THREAD_INFO_IN_TASK

Starting with Linux 4.9 (x86_64), the kernel began moving `thread_info` out of the
kernel stack and into `task_struct` itself, controlled by `CONFIG_THREAD_INFO_IN_TASK`:

```c
struct task_struct {
    struct thread_info  thread_info;    // Embedded at the very start
    // ...
    void               *stack;
    // ...
};
```

This was a deliberate security hardening measure. With `thread_info` no longer on the
stack, a simple stack overflow cannot directly overwrite the `addr_limit`, `flags`, or
`restart_block` fields. The `current` macro, which previously masked the stack pointer to
find `thread_info`, was changed to use a per-CPU variable or the GS segment register
on x86_64:

```c
// Old: derived from stack pointer
static inline struct thread_info *current_thread_info(void)
{
    return (struct thread_info *)(current_stack_pointer & ~(THREAD_SIZE - 1));
}

// New (x86_64): per-CPU variable accessed via GS segment
DECLARE_PER_CPU(struct task_struct *, current_task);
#define current get_current()
static __always_inline struct task_struct *get_current(void)
{
    return this_cpu_read_stable(current_task);
}
```

### 1.5 Virtually Mapped Kernel Stacks (CONFIG_VMAP_STACK)

Introduced in Linux 4.9 by Andy Lutomirski (building on ideas from grsecurity's
`GRKERNSEC_KSTACKOVERFLOW`), `CONFIG_VMAP_STACK` allocates kernel stacks from the
vmalloc area instead of the direct-mapped region. This provides two major benefits:

1. **Guard pages**: Non-accessible pages are placed below the stack. If the stack 
   overflows, it hits the guard page, triggering a page fault that is caught and reported
   as a clean oops rather than silent memory corruption.

2. **No physical contiguity requirement**: Individual pages are mapped into contiguous
   virtual addresses but need not be physically contiguous. This eliminates allocation
   failures due to memory fragmentation, which was a real problem with order-2 (16 KB)
   allocations on x86_64.

```
+-------------------+  High virtual address
|   Stack frames    |
|   (grows down)    |
+-------------------+
| STACK_END_MAGIC   |
+-------------------+
| Guard page        |  <- PAGE_NONE permissions, triggers fault on access
+-------------------+  Low virtual address
```

The trade-off is a small performance cost: vmalloc allocations are slower than direct-mapped
allocations, and the use of 4 KB page table entries (instead of huge pages) for the stack
region can increase TLB pressure. Linus Torvalds initially insisted on per-CPU caching of
pre-allocated stacks to mitigate the performance impact on `clone()` workloads.

**Important constraint**: Memory in the vmalloc range cannot be used for DMA I/O because
DMA controllers require physically contiguous memory and the `virt_to_phys()` translation
does not work for vmalloc addresses. Code that performs DMA from stack buffers had to be
fixed before this feature could be widely enabled. Such code was already problematic (DMA
from the stack is fragile regardless of VMAP_STACK), but its existence delayed adoption.

### 1.6 Interrupt and Exception Stacks (x86_64)

On x86_64, the kernel maintains several additional stacks beyond the per-thread kernel
stack, used for handling specific events:

- **Interrupt stack (IRQ stack)**: A per-CPU 16 KB stack used for hardware interrupt
  handling. When an interrupt fires, the CPU switches to this stack via `irq_stack_union`.
  This prevents deep interrupt handler chains from overflowing the thread's kernel stack.

- **IST (Interrupt Stack Table) stacks**: x86_64 provides up to 7 IST entries in the TSS
  (Task State Segment), each pointing to a dedicated stack. Linux uses these for:
  - **#DF (Double Fault)**: IST 1 -- Used when a fault occurs during fault handling.
    Essential for detecting stack overflows (a page fault on a guard page can itself
    cause a stack overflow if handled on the same stack).
  - **#NMI (Non-Maskable Interrupt)**: IST 2 -- NMIs can arrive at any time, including
    during stack switches.
  - **#DB (Debug)**: IST 3 -- Debug exceptions.
  - **#MCE (Machine Check Exception)**: IST 4 -- Hardware error handling.

These stacks ensure that critical exception handlers always have a known-good stack to
execute on, even when the thread's kernel stack is corrupted or exhausted.

### 1.7 Stack Randomization

As part of KASLR (Kernel Address Space Layout Randomization), the kernel can randomize the
base address of kernel stacks. Additionally, `CONFIG_RANDOMIZE_KSTACK_OFFSET` (introduced
in Linux 5.13) adds a per-syscall random offset to the stack pointer at the entry of each
system call. This makes it significantly harder for an attacker to predict the exact
location of stack variables, return addresses, or canaries across syscall invocations:

```c
// Simplified concept from arch/x86/entry/common.c
void do_syscall_64(struct pt_regs *regs, int nr)
{
    add_random_kstack_offset();  // Shift SP by random amount (< 1024 bytes)
    // ... handle syscall ...
}
```

---

## 2. Stack Buffer Overflows in Kernel Context

### 2.1 Nature of Kernel Stack Overflows

A kernel stack buffer overflow occurs when a function writes beyond the bounds of a 
stack-allocated buffer (an automatic/local variable), overwriting adjacent stack data. In
the kernel, this is particularly dangerous because:

1. **Privilege level**: Code runs at ring 0. Control-flow hijacking leads directly to
   arbitrary kernel code execution.
2. **No stack guard page (historically)**: Prior to `CONFIG_VMAP_STACK`, there was no
   hardware-enforced boundary at the bottom of the stack.
3. **Overwrite targets**: Adjacent data includes saved frame pointers, return addresses,
   other local variables, the stack canary, and (historically) `thread_info`.

### 2.2 Classic Vulnerability Pattern

The classic pattern involves an unbounded or insufficiently bounded `memcpy()`,
`copy_from_user()`, `sprintf()`, or similar operation into a fixed-size stack buffer:

```c
// Hypothetical vulnerable kernel code
static ssize_t vuln_write(struct file *filp, const char __user *buf,
                          size_t count, loff_t *ppos)
{
    char tmp[128];    // Fixed-size stack buffer

    // BUG: no bounds check on 'count'
    if (copy_from_user(tmp, buf, count))
        return -EFAULT;

    // ... process tmp ...
    return count;
}
```

An attacker providing `count > 128` overwrites past `tmp` on the stack. The stack layout
for this function (on x86_64) would be approximately:

```
+---------------------------+  Higher addresses
|  Return address (RIP)     |  <- Overwrite target
+---------------------------+
|  Saved RBP                |
+---------------------------+
|  Stack canary             |  <- Must be preserved or known
+---------------------------+
|  Alignment padding        |
+---------------------------+
|  tmp[127]                 |
|  ...                      |  <- Overflow direction (toward higher addresses)
|  tmp[0]                   |
+---------------------------+  Lower addresses (toward stack growth)
```

### 2.3 Stack Depth Overflows (Stack Exhaustion)

A distinct class of kernel stack overflow is the stack depth overflow, where deeply nested
function calls (recursion, deep call chains) exhaust the fixed-size kernel stack. Unlike
a buffer overflow that overwrites specific locations, a depth overflow gradually consumes
the entire stack and writes into whatever memory lies below it.

A landmark example was Jann Horn's 2016 exploit of recursive page faults through ecryptfs
stacked on procfs (Project Zero Issue #836). By creating a chain of processes where:

- Process A maps a decrypted ecryptfs view of Process B's `/proc/$B/environ`
- Process B maps a decrypted ecryptfs view of Process C's `/proc/$C/environ`
- And so on...

A page fault in one process triggers a `kernel_read()` into the next, causing another
page fault, leading to unbounded recursion:

```
handle_mm_fault()
  __do_fault()
    ecryptfs_readpage()
      ecryptfs_decrypt_page()
        ecryptfs_read_lower()
          kernel_read()
            vfs_read()
              environ_read()
                access_remote_vm()
                  __get_user_pages()
                    handle_mm_fault()     // Recursive!
                      __do_fault()
                        ecryptfs_readpage()
                          ...             // Stack exhaustion
```

Each recursion level consumed approximately 480 bytes of stack space. With a 16 KB stack,
roughly 34 levels of recursion would exhaust the stack and begin overwriting the allocation
below it.

**Mitigations against stack depth overflows**:

- `FILESYSTEM_MAX_STACK_DEPTH`: Limits filesystem stacking to 2 layers.
- `CONFIG_VMAP_STACK`: Guard pages catch the overflow.
- `CONFIG_THREAD_INFO_IN_TASK`: Removes `thread_info` from the overflow path.
- `CONFIG_SCHED_STACK_END_CHECK`: Places a `STACK_END_MAGIC` canary (0x57AC6E9D)
  at the lowest address of the stack and verifies it during scheduler invocations.

### 2.4 Variable Length Arrays (VLAs) -- Eliminated

VLAs (Variable Length Arrays) were once permitted in kernel code and represented a
significant risk for stack overflows. A VLA's size is determined at runtime, meaning a
sufficiently large size could exhaust the stack or create a buffer that overflows into
adjacent stack data. The Linux kernel deprecated and removed VLAs entirely by Linux 4.20
(2018), driven by Kees Cook's effort:

> "Dynamic growth of a stack array may exceed the remaining memory in the stack segment.
> This could lead to a crash, possible overwriting sensitive contents at the end of the
> stack (when built without CONFIG_THREAD_INFO_IN_TASK=y), or overwriting memory adjacent
> to the stack (when built without CONFIG_VMAP_STACK=y)."
>
> -- Kernel documentation, Deprecated Interfaces

The kernel now builds with `-Wvla` to prevent their reintroduction.

---

## 3. Stack Canaries in the Kernel

### 3.1 CONFIG_STACKPROTECTOR and CONFIG_STACKPROTECTOR_STRONG

The kernel implements GCC's `-fstack-protector` feature via two Kconfig options:

- **CONFIG_STACKPROTECTOR** (formerly CONFIG_CC_STACKPROTECTOR): Instruments functions
  that have `char` arrays of 8 bytes or more on the stack.
- **CONFIG_STACKPROTECTOR_STRONG**: Instruments all functions that have any local array
  (regardless of type or size), or take the address of a local variable. This provides
  much broader coverage.

When a function is instrumented, the compiler inserts a **canary value** (also called a
"stack cookie") between the local variables and the saved return address. The canary is
loaded from a per-CPU (or per-task) secret at function entry and verified against the
stored copy just before the function returns. If the values differ, it indicates a stack
buffer overflow occurred, and the kernel calls `__stack_chk_fail()`, which triggers a
kernel panic.

### 3.2 Implementation Details

On x86_64, the stack canary is stored in the per-CPU area and accessed via the GS
segment register:

```asm
; Function prologue -- load canary
mov    rax, QWORD PTR gs:0x28     ; Read canary from per-CPU data
mov    QWORD PTR [rbp-0x8], rax   ; Store on stack

; ... function body ...

; Function epilogue -- verify canary
mov    rax, QWORD PTR [rbp-0x8]   ; Read stored canary
xor    rax, QWORD PTR gs:0x28     ; Compare with original
jne    __stack_chk_fail            ; If different, overflow detected
```

The canary value has specific properties:
- It is generated at boot time using high-entropy randomness from the kernel's CRNG.
- The least significant byte is always 0x00 (a null terminator), which helps prevent
  string-based overflows from reading past the canary.
- The value is 8 bytes on 64-bit systems, 4 bytes on 32-bit.

### 3.3 Per-Task Stack Canaries

The kernel self-protection documentation emphasizes:

> "It is critical that the secret values used must be separate (e.g. different canary per
> stack) and high entropy (e.g. is the RNG actually working?) in order to maximize their
> success."

The kernel uses per-task canary values stored in `task_struct->stack_canary` (when
`CONFIG_STACKPROTECTOR` is enabled). On task creation, a new random canary is generated:

```c
// In kernel/fork.c, during copy_process()
tsk->stack_canary = get_random_canary();
```

### 3.4 Bypassing Stack Canaries

Stack canaries are a probabilistic defense -- they can be bypassed if the attacker can:

1. **Leak the canary value**: If an information disclosure vulnerability (e.g., an
   out-of-bounds read on the stack, an uninitialized stack variable, or a format string
   bug) reveals the canary, the attacker can include the correct value in the overflow
   payload. This is the most common bypass technique.

   Example from CTF/research contexts:
   ```c
   // Vulnerable read function leaks stack data to userspace
   char tmp[32];
   // ... populate tmp ...
   copy_to_user(user_buf, tmp, user_requested_count);  // If count > 32, leaks canary
   ```

   In the hxp CTF 2020 kernel-rop challenge, the `hackme_read` function allowed reading
   up to 0x1000 bytes from a 32-byte stack array, directly leaking the canary at a known
   offset (index 16 in the 8-byte integer array, at offset `rbp-0x18`).

2. **Overwrite without touching the canary**: If the overflow allows writing to
   non-contiguous memory (e.g., an arbitrary write primitive, or a write that skips over
   the canary), the canary check can be avoided entirely.

3. **Brute-force (impractical)**: The canary has 56 bits of entropy on 64-bit systems
   (the LSB is 0x00). Brute-forcing requires an average of 2^55 attempts, each causing
   a kernel panic. This is not practical against kernel canaries.

4. **Fork-based attacks (not applicable in kernel)**: In user-space, forked processes
   inherit the parent's canary, enabling byte-by-byte brute-force. This does not apply
   to kernel canaries, which are per-task.

### 3.5 CONFIG_KSTACK_ERASE

`CONFIG_KSTACK_ERASE` (introduced in Linux 5.10) erases the kernel stack contents on
each return to user space. This prevents information leakage from one syscall's stack
frames to the next. Without this, a subsequent syscall might be able to read residual
data (including canary values, kernel pointers, or sensitive data) left on the stack by
a previous syscall. When enabled, the region of the stack used during the syscall is
overwritten with a poison value before returning to user space.

---

## 4. Kernel Stack Pivoting Techniques

### 4.1 What is Stack Pivoting?

Stack pivoting is a technique where an attacker redirects the stack pointer (RSP on
x86_64) to a memory region under their control. This is typically used when:

- The amount of overwritable stack space is insufficient for a full ROP chain.
- The attacker has an arbitrary write primitive but limited control over the original
  stack.
- The attacker wants to use a pre-constructed fake stack in a controlled memory region.

### 4.2 Pivoting via ROP Gadgets

The most common approach uses a `xchg <reg>, rsp; ret` or `mov rsp, <reg>; ret` gadget:

```asm
; Example pivot gadget
xchg   rax, rsp    ; Swap RSP with RAX (which the attacker controls)
ret                 ; Pop new return address from the fake stack
```

The attacker needs:
1. Control over a register (e.g., RAX) that points to the fake stack.
2. A single overwrite of the return address to the pivot gadget.
3. A pre-populated fake stack at the controlled address.

On modern kernels with SMEP (Supervisor Mode Execution Prevention) and SMAP (Supervisor
Mode Access Prevention), the fake stack **cannot** be in user-space memory. SMEP prevents
executing user-space code in kernel mode, and SMAP prevents accessing user-space data
(including using it as a stack). The attacker must therefore place the fake stack in
kernel memory.

### 4.3 Stack Pivoting in Real Exploits

**Jann Horn's ecryptfs/procfs exploit (2016)**: Rather than traditional stack pivoting,
this exploit overflowed the kernel stack into a physically adjacent allocation (a pipe
page buffer). The process was paused in FUSE (the page fault handler transferred control
to user space via FUSE), and the attacker then wrote controlled data to the pipe buffer,
effectively creating a new "fake" stack at the overflow location. The key innovation was:

1. Using buddy allocator determinism to place a pipe page buffer immediately before the
   stack allocation.
2. Carefully controlling the recursion depth to avoid overwriting critical fields
   (`thread_info`, `STACK_END_MAGIC`).
3. Using FUSE to pause execution while the stack pointer was inside the adjacent
   allocation.
4. Writing a fake stack via pipe writes, controlling the saved RIP.

**Alexander Popov's CVE-2021-26708 exploit**: When exploiting the vsock race condition
on Fedora 33, Popov encountered the problem of needing to perform an arbitrary write
with very constrained primitives. He noted:

> "I couldn't find a stack pivoting gadget in vmlinuz-5.10.11-200.fc33.x86_64 that would
> work with my constraints... so I performed arbitrary write in one shot."

Instead of pivoting, he used a single ROP gadget (`mov rdx, [rdi + 8]; mov [rdx + rcx*8],
rsi; ret`) to perform a targeted arbitrary write, demonstrating that stack pivoting is not
always necessary if a sufficiently powerful single gadget exists.

### 4.4 ret2dir: Bypassing SMEP/SMAP for Pivoting

The **ret2dir** technique (Kemerlis et al., USENIX Security 2014) exploits the fact that
the kernel's direct-mapped region (physmap) provides a kernel-space mapping of all physical
memory, including physical pages that also back user-space virtual addresses. An attacker
can:

1. Allocate a user-space buffer containing a fake stack / ROP chain.
2. Find the corresponding kernel virtual address in the physmap 
   (typically at `0xffff888000000000` + physical\_offset on x86_64).
3. Pivot to this kernel-space address, bypassing SMEP/SMAP since the access is through
   a kernel mapping.

This technique was mitigated by KASLR (randomizing the physmap base), and by removing
the 1:1 identity mapping or restricting physmap permissions in some hardened configurations.

---

## 5. Out-of-Bounds Read/Write on the Kernel Stack

### 5.1 OOB Read: Information Disclosure

Out-of-bounds reads on the kernel stack are a critical primitive for exploit development
because the kernel stack contains high-value secrets:

- **Stack canary values**: Enable bypassing `CONFIG_STACKPROTECTOR`.
- **Kernel code pointers**: Return addresses and saved function pointers reveal kernel
  text addresses, defeating KASLR.
- **Kernel data pointers**: Pointers to `task_struct`, `cred` structures, or other kernel
  objects enable targeted memory corruption.
- **User-space register state**: The `pt_regs` structure at the top of the kernel stack
  (pushed during syscall entry) contains the user's register values.

Common sources of stack OOB reads:

1. **Oversized `copy_to_user()`**: A function copies more data to user space than the
   stack buffer contains (as in the hxp CTF 2020 `hackme_read` example).
2. **Uninitialized stack variables**: Structure padding holes or incompletely initialized
   buffers may be copied to user space, leaking residual stack data. The kernel
   self-protection documentation notes: "Memory copied to userspace must always be fully
   initialized."
3. **Format string vulnerabilities**: Though rare in the kernel, improper use of
   `printk()` or `seq_printf()` with user-controlled format strings could read stack data.

### 5.2 OOB Write: Control-Flow Hijacking

An out-of-bounds write on the kernel stack can target:

- **Return addresses**: Hijack control flow to ROP gadgets.
- **Saved frame pointers (RBP)**: Corrupt the frame chain, potentially causing subsequent
  functions to read/write at attacker-controlled addresses.
- **Function pointers on the stack**: Any function pointer stored as a local variable.
- **Other local variables**: Alter control flow indirectly by changing variables that
  influence branch decisions, array indices, or pointer arithmetic.
- **pt_regs**: The register save area at the stack top. Overwriting the saved instruction
  pointer or segment registers can redirect execution when the kernel returns to user
  space.

### 5.3 Mitigations for OOB Stack Access

- **CONFIG_FORTIFY_SOURCE**: Compile-time and runtime detection of buffer overflows in
  common functions (`memcpy()`, `strcpy()`, `sprintf()`, etc.). When the compiler can
  determine the size of a destination buffer, it replaces the call with a bounds-checked
  version that panics on overflow.
- **`-Warray-bounds` and `-Wzero-length-bounds`**: Compiler warnings for provably
  out-of-bounds accesses.
- **Shadow stacks (CONFIG_X86_USER_SHADOW_STACK / CET)**: Intel Control-flow Enforcement
  Technology provides a hardware shadow stack that stores a copy of return addresses. On
  function return, the hardware compares the return address on the regular stack with the
  shadow stack copy. A mismatch triggers a #CP (control protection) exception. While
  primarily deployed for user space as of Linux 6.6+, kernel shadow stacks are under
  development.
- **Clang CFI (CONFIG_CFI_CLANG)**: Control Flow Integrity validates indirect call
  targets at runtime, preventing many forms of control-flow hijacking even if a function
  pointer is overwritten.

---

## 6. The Transition from 8KB to 16KB Kernel Stacks

### 6.1 Historical Context: 4KB and 8KB Stacks

Early Linux kernels on x86 used small kernel stacks:

- **i386 (32-bit)**: 4 KB (one page) was attempted in Linux 2.6 but caused widespread
  stability issues. 8 KB (two pages, order-1 allocation) became the standard.
- **x86_64**: Initially used 8 KB stacks as well.

The small size was driven by memory constraints -- each thread in the system requires its
own kernel stack, and with thousands of threads, the cumulative memory impact is
significant. However, the small size created a constant tension between functionality
and safety: kernel developers had to be extremely careful about stack-allocated variables
and call chain depth.

### 6.2 The Expansion to 16KB (Linux 3.15)

In 2014, the x86_64 kernel stack was doubled from 8 KB to 16 KB via commit
`6538b8ea886e` (by Minchan Kim). The primary motivation was stability, not security:

- The storage subsystem, where filesystems, block devices, and networking code can be
  stacked to arbitrary depths, was particularly prone to stack overflows.
- Deep call chains through dm (device mapper), LVM, network-backed storage, and
  filesystem encryption regularly pushed the stack to its limits.
- Adding a single large stack allocation (e.g., `struct sockaddr_storage` at 128 bytes)
  in the wrong function could trigger overflows.

The expansion came at a cost: each thread now required an order-2 (4 contiguous pages)
allocation instead of order-1. On systems with fragmented memory, finding 4 contiguous
free pages could fail, leading to thread creation failures. This was a significant factor
in the subsequent adoption of `CONFIG_VMAP_STACK`.

### 6.3 Security Implications

The stack size increase had both positive and negative security implications:

**Positive**:
- Stack depth overflows became harder to trigger -- an attacker now needs approximately
  twice the recursion depth or stack consumption.
- More headroom for legitimate kernel code reduces the frequency of unintentional
  overflows that could be exploited.
- The larger stack provides more "haystack" for stack-smashing canary-protected functions.

**Negative**:
- A larger stack means more space for attacker-controlled data to survive across
  syscalls (mitigated by `CONFIG_KSTACK_ERASE`).
- The doubled memory footprint per thread (from ~8 KB to ~16 KB) was a concern for
  memory-constrained systems.
- The order-2 allocation requirement increased fragmentation pressure, making stack
  allocation failures more likely under memory pressure (largely resolved by VMAP_STACK).

### 6.4 grsecurity's Prior Art

The grsecurity patch set implemented `GRKERNSEC_KSTACKOVERFLOW` several years before
the mainline kernel adopted `CONFIG_VMAP_STACK`. As noted by PaX Team in 2014:

> "The very new GRKERNSEC_KSTACKOVERFLOW feature solves this without breaking up huge
> pages. Throw in our 3-year-old move of thread_info off the kstack and we've got a
> winner!"

grsecurity also moved `thread_info` out of the kernel stack years before the mainline
kernel adopted `CONFIG_THREAD_INFO_IN_TASK`. This history underscores that hardened
kernel distributions were often ahead of mainline in addressing stack-related
vulnerabilities.

---

## 7. Return Address Overwriting and Control Flow Hijacking

### 7.1 The Fundamental Technique

On x86_64, the `CALL` instruction pushes the return address (address of the instruction
after the CALL) onto the stack. The `RET` instruction pops it into RIP and transfers
execution there. By overwriting this saved return address, an attacker redirects execution
to an arbitrary address:

```
Before overflow:           After overflow:
+------------------+       +------------------+
| Return addr (RIP)|       | 0xdeadbeefcafe   | <- Attacker-controlled
+------------------+       +------------------+
| Saved RBP        |       | 0x4141414141414141|
+------------------+       +------------------+
| Canary           |       | <leaked canary>  | <- Correct canary value
+------------------+       +------------------+
| Local vars       |       | AAAAAAAAAAAAA... | <- Overflow data
+------------------+       +------------------+
```

### 7.2 ret2usr (Return to User Space)

The simplest exploitation technique is to redirect execution to a user-space function:

```c
// In user-space exploit
void privesc(void) {
    commit_creds(prepare_kernel_cred(0));  // Become root
    // Return to user mode via swapgs + iretq
}
// Overwrite return address with address of privesc()
```

This directly calls kernel functions from user-space code mapped into the process's
address space. The attack is blocked by **SMEP** (Supervisor Mode Execution Prevention),
which prevents the CPU from executing code at user-space addresses when in kernel mode
(ring 0). SMEP has been enabled by default on supported hardware since Linux 3.7+.

### 7.3 Kernel ROP (Return-Oriented Programming)

With SMEP preventing ret2usr, attackers chain together short sequences of existing kernel
code called "gadgets" -- each ending with a `RET` instruction. By carefully constructing
a chain of return addresses on the stack, the attacker can perform arbitrary computation:

```c
// Example ROP chain for privilege escalation
payload[off++] = pop_rdi_ret;              // Gadget: pop rdi; ret
payload[off++] = 0x0;                      // Argument: NULL (uid 0)
payload[off++] = prepare_kernel_cred;      // Call prepare_kernel_cred(0)
payload[off++] = mov_rdi_rax_ret;          // Move return value to RDI
payload[off++] = commit_creds;             // Call commit_creds(new_cred)
payload[off++] = swapgs_restore_and_ret;   // Return to user mode
payload[off++] = 0;                        // Padding
payload[off++] = 0;                        // Padding
payload[off++] = (unsigned long)shell;     // User RIP
payload[off++] = user_cs;                  // User CS
payload[off++] = user_rflags;              // RFLAGS
payload[off++] = user_sp;                  // User RSP
payload[off++] = user_ss;                  // User SS
```

The chain ends with the `swapgs_restore_regs_and_return_to_usermode` trampoline (part
of the kernel's KPTI implementation), which correctly switches page tables and returns
to user mode.

### 7.4 Returning to User Mode: KPTI Considerations

With **KPTI** (Kernel Page-Table Isolation) enabled, the kernel and user-space use
separate page tables. Even if the ROP chain successfully escalates privileges, simply
executing `swapgs; iretq` will crash because the user-space code pages are not mapped
in the kernel page tables. Solutions include:

1. **KPTI trampoline**: Use the kernel's own
   `swapgs_restore_regs_and_return_to_usermode` function, which handles the page table
   switch. This is the cleanest approach.

2. **Signal handler**: Register a `SIGSEGV` handler before triggering the exploit. When
   the return to user space faults (due to wrong page tables), the signal handler catches
   it and the escalated privileges are already in effect.

3. **User Mode Helper (UMH) hijacking**: Instead of returning to user space at all,
   overwrite `modprobe_path` or `core_pattern` with the path to an attacker-controlled
   script. Trigger the helper (e.g., execute a file with an unknown binary format for
   modprobe, or crash a process for core_pattern). The kernel executes the script as
   root.

### 7.5 Bypassing KASLR for ROP

Kernel ROP requires knowing the addresses of gadgets. KASLR randomizes the kernel's
base address at boot, but can be defeated by:

- **Information leaks**: Reading kernel pointers from stack data, `/proc/kallsyms`
  (if accessible), or kernel log messages.
- **Side channels**: Hardware side channels (TSX-based, branch predictor-based) have
  been demonstrated to break KASLR.
- **Stack data leaks**: As demonstrated in multiple CTF challenges and real exploits,
  leaking stack data reveals return addresses which contain kernel `.text` pointers,
  allowing the KASLR offset to be computed.

**FG-KASLR** (Function Granular KASLR) further randomizes individual function positions
within the kernel text, but has known weaknesses:
- The `.text` section's functions are not randomized by FG-KASLR, only by KASLR.
- The `__ksymtab` section has a fixed offset from the kernel base.
- The `.data` section (including `modprobe_path`, `core_pattern`) has a fixed offset.
- Gadgets from the early portion of the kernel image (before FG-KASLR's randomization
  boundary) remain at predictable offsets from the kernel base.

### 7.6 Shadow Stacks and CFI

Modern defenses against return address corruption include:

- **Intel CET Shadow Stack**: Maintains a hardware-managed secondary stack containing
  only return addresses. `RET` validates the return address against the shadow stack;
  mismatches cause a `#CP` exception. Kernel support is under active development.
- **ARM Pointer Authentication (PAC)**: ARMv8.3-A adds cryptographic authentication
  to return addresses stored on the stack. The `PACIASP`/`AUTIASP` instructions sign
  and verify the return address using a per-task key. Corrupting the return address
  without knowing the key produces an invalid signature, causing an authentication
  failure. Linux supports this for kernel code via `CONFIG_ARM64_PTR_AUTH_KERNEL`.
- **Clang CFI**: Validates indirect call/jump targets at runtime, complementing return
  address protection.

---

## 8. Global Variable Corruption and Data-Only Attacks

### 8.1 Beyond Control-Flow Hijacking

Data-only attacks modify kernel data structures to achieve privilege escalation without
ever altering control flow. This is significant because they bypass:

- Stack canaries (no return address overwrite)
- CFI (no indirect call/jump target corruption)
- Shadow stacks (no return address modification)
- SMEP/SMAP (no execution of or access to user-space memory)

### 8.2 modprobe_path Overwrite

The most widely used data-only attack in modern kernel exploitation targets the global
variable `modprobe_path`:

```c
// In kernel/kmod.c
char modprobe_path[KMOD_PATH_LEN] = "/sbin/modprobe";
```

When the kernel encounters an executable file with an unknown binary format (an unknown
magic number), it invokes `modprobe_path` as root to load the appropriate module. An
attacker who can overwrite this string to point to their own script achieves root code
execution:

```c
// Attacker's ROP chain (or arbitrary write):
// Overwrite modprobe_path with "/tmp/evil"
pop_rax_ret                          // Gadget
0x6c6976652f706d742f                 // "/tmp/evil" in little-endian
pop_rdi_ret                          // Gadget
modprobe_path_addr                   // Target address
write_rax_to_rdi_ret                 // Gadget: mov [rdi], rax; ret
```

Then trigger it from user space:
```bash
echo -ne '\xff\xff\xff\xff' > /tmp/dummy    # Unknown magic bytes
chmod +x /tmp/dummy
/tmp/dummy                                   # Triggers modprobe via kernel
```

This technique is extremely popular because:
- `modprobe_path` is in the `.data` section at a fixed offset from the kernel base
  (only randomized by KASLR, not FG-KASLR).
- The write is only 14 bytes (the length of a path string).
- It does not require corrupting any control-flow data.

### 8.3 core_pattern Overwrite

Similarly, the `core_pattern` kernel variable controls how core dumps are handled:

```c
// In fs/coredump.c
char core_pattern[CORENAME_MAX_SIZE] = "core";
```

If the first character is `|`, the kernel pipes the core dump to the specified program:

```c
// Attacker overwrites core_pattern to "|/tmp/evil"
// Then triggers a core dump:
kill(getpid(), SIGSEGV);
```

This was demonstrated in Jann Horn's ecryptfs exploit:
```c
char *core_handler = "|/tmp/crash_to_root";
kernel_write(0xffffffff81e87a60, core_handler, strlen(core_handler)+1);
```

### 8.4 Credential Structure Manipulation

The `struct cred` contains the process's security credentials:

```c
struct cred {
    atomic_t    usage;
    kuid_t      uid;        // Real UID
    kgid_t      gid;        // Real GID
    kuid_t      suid;       // Saved UID
    kgid_t      sgid;       // Saved GID
    kuid_t      euid;       // Effective UID  <- Target
    kgid_t      egid;       // Effective GID  <- Target
    kuid_t      fsuid;      // Filesystem UID
    kgid_t      fsgid;      // Filesystem GID
    // ... capabilities, keyrings, SELinux context, etc.
};
```

If an attacker can locate the current process's `cred` structure in memory and overwrite
`uid`/`euid`/`gid`/`egid` to 0, the process becomes root. The standard kernel API for
this is:

```c
commit_creds(prepare_kernel_cred(NULL));
```

`prepare_kernel_cred(NULL)` creates a new credential structure with root privileges
(uid=0, full capabilities), and `commit_creds()` applies it to the current task. This
is the canonical privilege escalation primitive used in nearly all kernel exploits.

In Popov's CVE-2021-26708 exploit, instead of calling these functions via ROP, he used
a single gadget to directly zero-write the `euid`/`egid` fields in the `cred` structure,
demonstrating a pure data-only approach to credential manipulation.

### 8.5 addr_limit Overwrite (Historical)

Before `thread_info` was moved out of the kernel stack and `addr_limit` was removed (it
was replaced by different mechanisms in recent kernels), overwriting `addr_limit` to
`KERNEL_DS` was a powerful data-only attack. With `addr_limit` set to `KERNEL_DS`,
the `copy_to_user()` and `copy_from_user()` functions would operate on kernel addresses,
giving the attacker arbitrary kernel memory read/write from user space:

```c
// With addr_limit = KERNEL_DS:
void kernel_write(unsigned long addr, char *buf, size_t len) {
    int pipefds[2];
    pipe(pipefds);
    write(pipefds[1], buf, len);
    close(pipefds[1]);
    read(pipefds[0], (char*)addr, len);  // read() into kernel address!
    close(pipefds[0]);
}
```

This technique is now dead on modern kernels where `addr_limit` has been removed or
replaced with explicit `access_ok()` enforcement and `uaccess_begin()`/`uaccess_end()`
bracketing.

### 8.6 SELinux and LSM Data Corruption

The `cred->security` pointer holds LSM (Linux Security Module) data, including SELinux
security context. Overwriting this pointer can bypass mandatory access controls. In
Popov's CVE-2021-26708 exploit, the `msg_msg.security` pointer was corrupted as a side
effect of the race condition's 4-byte write, which was then leveraged to achieve arbitrary
free.

### 8.7 Function Pointer Tables (VFTs)

While technically a control-flow attack, corrupting virtual function tables (VFTs) in
kernel objects is another major exploitation strategy. Many kernel structures contain
`struct *_operations` pointers (e.g., `file_operations`, `proto_ops`, `vm_operations`).
Overwriting these pointer-to-pointer-to-function fields redirects subsequent kernel
operations to attacker-controlled code or ROP gadgets.

The kernel mitigates this by marking operation structures as `const` (placing them in
`.rodata`) and using `__ro_after_init` for structures that are initialized once at boot
time and never modified.

---

## 9. DMA-Based Attacks and Physical Memory Corruption

### 9.1 Direct Memory Access (DMA) Fundamentals

DMA allows peripheral devices (network cards, storage controllers, GPUs) to read and
write system memory directly, without CPU involvement. This is essential for high-
performance I/O but creates a fundamental security problem: a malicious or compromised
peripheral can read/write arbitrary physical memory, bypassing all software-based
security mechanisms (page table permissions, SMEP, SMAP, etc.).

DMA operates on **physical addresses**, not virtual addresses. A DMA-capable device with
knowledge of the physical memory layout can:

- Read encryption keys, passwords, and other secrets from memory.
- Overwrite kernel code or data structures.
- Inject code into running processes.
- Modify page tables to gain access to arbitrary virtual address ranges.

### 9.2 The IOMMU: Hardware-Based DMA Protection

The Input/Output Memory Management Unit (IOMMU) provides address translation and access
control for DMA, analogous to the MMU for CPU memory accesses:

- **Intel VT-d** (Virtualization Technology for Directed I/O)
- **AMD-Vi** (AMD I/O Virtualization Technology)
- **ARM SMMU** (System Memory Management Unit)

When properly configured, the IOMMU restricts each device to accessing only the physical
memory pages explicitly mapped for it by the operating system. The kernel uses the DMA
API (`dma_map_*()` / `dma_unmap_*()`) to manage these mappings.

However, as the Thunderclap research demonstrated, IOMMU protection is insufficient in
practice for several reasons:

1. **IOMMU disabled by default**: Many systems did not enable the IOMMU by default.
   Linux required `intel_iommu=on` on the kernel command line until relatively recently.
   
2. **Performance trade-offs**: Strict IOMMU usage (mapping/unmapping pages for every
   DMA operation) has a measurable performance cost due to IOTLB flushes and page table
   walks. Historically, OS developers traded security for performance.
   
3. **Shared memory regions**: Operating systems often map large, shared memory windows
   for device communication. These shared regions may contain sensitive data beyond what
   the device legitimately needs.

4. **ATS (Address Translation Services)**: PCI Express ATS allows devices to cache
   IOMMU translations, and a malicious device can abuse this to access memory outside
   its intended mapping.

### 9.3 Thunderbolt/PCIe Hotplug Attacks

Modern Thunderbolt 3/4 ports (over USB-C) provide PCIe hotplug capability, meaning an
external device can be granted DMA access simply by being plugged in. The Thunderclap
research (Markettos et al., NDSS 2019) demonstrated:

- **Network card impersonation**: An FPGA-based device masquerades as an Intel 82574L
  Ethernet adapter. The OS loads drivers, grants DMA access, and exposes shared memory
  buffers. The device then reads beyond its allocated buffers to access passwords,
  encryption keys, and other sensitive data.

- **Cross-platform impact**: Vulnerabilities were demonstrated on macOS, Windows, Linux,
  and FreeBSD.

- **Malicious chargers/projectors**: Since Thunderbolt 3 shares the USB-C port with
  power delivery and video output, a seemingly innocuous charger or projector could
  contain a DMA attack payload.

Attack scenario:
```
1. Attacker plugs malicious Thunderbolt device into target laptop
2. Device presents as a legitimate NIC/storage controller
3. OS loads drivers, grants DMA access
4. Device reads/writes arbitrary physical memory
5. Attacker extracts credentials or escalates privileges
```

### 9.4 DMA from the Kernel Stack

A subtler DMA-related vulnerability class involves kernel code that passes stack buffer
addresses to DMA operations. Since DMA requires physical addresses and the DMA API
expects memory that will remain mapped for the duration of the transfer:

1. **VMAP_STACK incompatibility**: Stack memory in the vmalloc range cannot be used for
   DMA because `virt_to_phys()` does not work for vmalloc addresses and the pages are
   not physically contiguous. Code that performs DMA from stack buffers breaks when
   `CONFIG_VMAP_STACK` is enabled.

2. **Temporal issues**: Stack memory is reused across function calls. If a DMA operation
   completes after the function returns, it writes to memory that may now contain
   unrelated data -- including return addresses or canaries of subsequent function calls.

The kernel has been progressively auditing and fixing DMA-from-stack patterns. The DMA
API can optionally warn when stack addresses are passed (`CONFIG_DMA_API_DEBUG`).

### 9.5 Firewire (IEEE 1394) DMA Attacks

Before Thunderbolt, the Firewire interface provided DMA access and was a well-known
attack vector. Tools like `inception` (formerly `winlockpwn`) could read/write arbitrary
physical memory via Firewire, enabling:

- Screen lock bypass
- Full disk encryption key extraction
- Arbitrary code execution

These attacks worked because Firewire DMA was typically not restricted by an IOMMU.

### 9.6 BIOS/UEFI and SMM Attacks via DMA

DMA attacks can also target System Management Mode (SMM) memory and UEFI runtime
services. A compromised device could:

- Overwrite SMM handlers to install persistent rootkits that survive OS reinstallation.
- Modify UEFI variables to alter boot configuration.
- Access memory regions that the OS considers protected.

### 9.7 Mitigations for DMA Attacks

| Mitigation | Description |
|------------|-------------|
| IOMMU enforcement | Enable VT-d/AMD-Vi and restrict per-device DMA mappings |
| Thunderbolt access control | Prompt users before allowing DMA from new devices (Windows/Linux) |
| Kernel DMA Protection | Modern Intel/AMD platforms support firmware-level DMA protection pre-boot |
| `CONFIG_STRICT_DEVMEM` | Restricts `/dev/mem` access to prevent user-space DMA mapping |
| Device whitelisting | macOS maintains a whitelist of approved Thunderbolt devices |
| SWIOTLB (bounce buffering) | Forces DMA through intermediate buffers, isolating device access |
| Disabling Thunderbolt | The most effective mitigation, but often impractical |
| `CONFIG_DMA_API_DEBUG` | Warns about improper DMA usage, including stack DMA |

### 9.8 Physical Memory Corruption via Software

Beyond peripheral-based DMA, physical memory corruption can occur through software
interfaces:

- **/dev/mem**: On permissive configurations, provides direct access to physical memory.
  `CONFIG_STRICT_DEVMEM` restricts this to I/O regions only.
  
- **/dev/kmem**: Direct access to kernel virtual memory. Typically disabled in modern
  kernels (`CONFIG_DEVKMEM=n`).

- **ACPI tables**: Corrupted or malicious ACPI tables can specify memory regions that
  the kernel will read/write, potentially leading to memory corruption.

- **Rowhammer**: A hardware vulnerability where rapid reads to specific DRAM rows cause
  bit flips in adjacent rows. While not a traditional DMA attack, it achieves physical
  memory corruption from software. The kernel mitigates this partially through memory
  allocation patterns and by blacklisting vulnerable memory regions.

---

## Summary of Mitigations and Their Effectiveness

| Vulnerability Class | Key Mitigations | Bypass Difficulty |
|---------------------|----------------|-------------------|
| Stack buffer overflow | CONFIG_STACKPROTECTOR_STRONG, CONFIG_FORTIFY_SOURCE | Moderate (requires info leak for canary) |
| Stack depth overflow | CONFIG_VMAP_STACK (guard pages), FILESYSTEM_MAX_STACK_DEPTH | High (requires deep recursion primitive) |
| thread_info overwrite | CONFIG_THREAD_INFO_IN_TASK | Eliminated (structure moved off stack) |
| Return address hijacking | Stack canaries, Shadow stacks (CET), ARM PAC | High with all mitigations enabled |
| KASLR bypass | CONFIG_RANDOMIZE_BASE, CONFIG_RANDOMIZE_KSTACK_OFFSET, %p hashing | Moderate (many info leak sources) |
| Data-only attacks | __ro_after_init, const VFTs, CONFIG_STATIC_USERMODEHELPER | Low (many writable targets remain) |
| DMA attacks | IOMMU (VT-d/AMD-Vi), Thunderbolt access control, SWIOTLB | Varies (IOMMU bypass possible) |
| Uninitialized stack data | CONFIG_KSTACK_ERASE, CONFIG_INIT_STACK_ALL_ZERO | Moderate |

## Key Historical CVEs Involving Stack and Memory Corruption

| CVE | Year | Type | Description |
|-----|------|------|-------------|
| Project Zero #836 | 2016 | Stack depth overflow | ecryptfs/procfs recursive page fault, exploited with pipe buffer overlap |
| CVE-2017-11176 | 2017 | Use-after-free (refcount) | mq_notify double sock_put(), race condition in retry logic |
| CVE-2017-2636 | 2017 | Race condition / double free | n_hdlc driver, exploited via use-after-free on sk_buff |
| CVE-2019-2215 | 2019 | Use-after-free | Android Binder UAF, exploited in the wild |
| CVE-2021-26708 | 2021 | Race condition / WAF | vsock transport race, 4-byte write-after-free escalated to full root |
| CVE-2022-0185 | 2022 | Heap buffer overflow | legacy_parse_param integer underflow, container escape |
| CVE-2023-0386 | 2023 | OverlayFS privilege escalation | SUID file creation via overlayfs |

## References

1. Linux Kernel Self-Protection Documentation:
   https://www.kernel.org/doc/html/latest/security/self-protection.html
2. LWN: Virtually Mapped Kernel Stacks (2016):
   https://lwn.net/Articles/692208/
3. Jann Horn, Project Zero: "Exploiting Recursion in the Linux Kernel" (2016):
   https://googleprojectzero.blogspot.com/2016/06/exploiting-recursion-in-linux-kernel_20.html
4. Alexander Popov: "Four Bytes of Power: Exploiting CVE-2021-26708" (2021):
   https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html
5. Lexfo: "CVE-2017-11176: A step-by-step Linux Kernel exploitation":
   https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
6. Thunderclap: Exploring Vulnerabilities in OS IOMMU Protection (NDSS 2019):
   https://thunderclap.io/
7. Vitaly Nikolenko: "Linux Kernel universal heap spray" (2018):
   https://duasynt.com/blog/linux-kernel-heap-spray
8. Kemerlis et al.: "ret2dir: Rethinking Kernel Isolation" (USENIX Security 2014)
9. Linux Kernel Deprecated Interfaces Documentation:
   https://www.kernel.org/doc/html/latest/process/deprecated.html
10. Jon Oberheide: "The Stack is Back" (Infiltrate 2012)
11. LWN: Expanding the Kernel Stack (2014):
    https://lwn.net/Articles/600644/
12. hxp CTF 2020 kernel-rop walkthrough:
    https://blog.wohin.me/posts/linux-kernel-pwn-01/
13. Linux Kernel Defence Map (Alexander Popov):
    https://github.com/a13xp0p0v/linux-kernel-defence-map

---

*This document is part of a comprehensive Linux kernel security research report.
All information is provided for educational and defensive security research purposes.*
