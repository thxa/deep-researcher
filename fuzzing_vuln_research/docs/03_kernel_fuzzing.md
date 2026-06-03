# Kernel Fuzzing

## 1. syzkaller Architecture

### 1.1 Overview

syzkaller is a coverage-guided kernel fuzzer developed by Dmitry Vyukov at Google. It systematically generates system calls with varying arguments and sequences, using kernel coverage feedback to guide exploration toward new code paths. Since its introduction in 2015, syzkaller has discovered thousands of kernel bugs, including hundreds of security-relevant vulnerabilities.

### 1.2 Core Components

```
┌──────────────────────────────────────────────────────┐
│  syzkaller (Host)                                    │
│                                                      │
│  ┌───────────┐  ┌───────────┐  ┌──────────────┐   │
│  │ Corpus    │  │ Mutation  │  │ Minimization │   │
│  │ Manager   │  │ Engine    │  │ & Triaging   │   │
│  └─────┬─────┘  └─────┬─────┘  └──────┬───────┘   │
│        │               │                │            │
│        └───────────────┼────────────────┘            │
│                        ↓                             │
│  ┌─────────────────────────────────────────┐        │
│  │           RPC Interface                  │        │
│  └───────────────────┬─────────────────────┘        │
│                      ↓                               │
│  ┌─────────────────────────────────────────┐        │
│  │  VM Manager (QEMU/GCE/Android)         │        │
│  └───────────────────┬─────────────────────┘        │
└──────────────────────┼──────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────┐
│  Target VM (Guest)                                   │
│                                                      │
│  ┌───────────┐  ┌───────────┐  ┌──────────────┐   │
│  │ syz-exec  │  │ syz-exec  │  │ KCOV/KASAN   │   │
│  │ utor (F)  │  │ utor (C)  │  │ Instrument.  │   │
│  └───────────┘  └───────────┘  └──────────────┘   │
│                                                      │
│  Kernel with KCOV + KASAN/KMSAN                     │
└──────────────────────────────────────────────────────┘
```

**Key components:**

1. **Fuzzer**: The main loop that selects programs from the corpus, mutates them, sends them to the executor, and processes coverage/crash results
2. **Executor**: A minimal user-space program running inside the VM that receives syscall sequences from the fuzzer and executes them
3. **VM Manager**: Manages VM lifecycle (boot, snapshot, reboot after crash)
4. **Corpus Manager**: Stores and retrieves test programs (system call sequences)
5. **Minimizer**: Reduces crashing programs to the minimal sequence that still triggers the bug

### 1.3 Operation Flow

1. **Boot VM**: Start a fresh QEMU/GCE/Android instance with the instrumented kernel
2. **Initialize**: The executor connects to the fuzzer via RPC
3. **Select program**: The fuzzer selects a program from the corpus
4. **Mutate program**: Apply mutation operators (insert/remove/change syscalls and arguments)
5. **Execute program**: The executor runs the syscall sequence in the VM
6. **Collect coverage**: KCOV reports covered PCs to the fuzzer
7. **Check for crashes**: The executor checks for kernel panics, hangs, and KASAN reports
8. **Update corpus**: If new coverage was discovered, add the program to the corpus
9. **If crash**: Save the program, reboot the VM, continue fuzzing

## 2. System Call Description Language

### 2.1 Overview

syzkaller's most innovative feature is its **syscall description language** (syzlang). This declarative language defines the structure, arguments, and relationships of system calls, enabling the fuzzer to generate semantically meaningful sequences.

### 2.2 Description Syntax

```syzlang
# Resource types (represent kernel objects like file descriptors)
resource fd[int32]

# System call definitions
openat$foo(fd const[AT_FDCWD], file ptr[in, filename], flags flags[open_flags], mode const[0]) fd
read$foo(fd fd, buf buffer[out], count len[buf]) intptr
write$foo(fd fd, buf buffer[in], count len[buf]) intptr
close$foo(fd fd) intptr

# Struct definitions
filename {
    dir    const[0]
    file   filename_content
}

filename_content {
    name   string["test.txt", "input.bin", "config.cfg"]
}

# Flag definitions
open_flags = O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC, O_APPEND

# Union types (the fuzzer picks one variant)
ipv4_addr {
    loc   ipv4_addr_loc
    rem   ipv4_addr_rem
}

# Const/flags for arguments
mmap$anon(addr vma, len len[vma], prot flags[mmap_prot], flags flags[mmap_flags_anon], fd const[-1], offset const[0]) vma
```

### 2.3 Resource Lifecycle Modeling

syzkaller models the lifecycle of kernel resources (file descriptors, sockets, memory mappings) using its resource system. When a syscall creates a resource (e.g., `openat` returns an `fd`), subsequent syscalls can use that resource:

```syzlang
socket$inet(domain const[AF_INET], type const[SOCK_STREAM], proto const[0]) sock
connect$inet(fd sock, addr ptr[in, sockaddr_in], addrlen len[addr]) intptr
sendto$inet(fd sock, buf buffer[in], len len[buf], flags flags[send_flags], addr ptr[in, sockaddr_in], addrlen len[addr]) intptr
recvfrom$inet(fd sock, buf buffer[out], len len[buf], flags flags[recv_flags], addr ptr[out, sockaddr_in], addrlen ptr[out, int32]) intptr
close$inet(fd sock) intptr
```

This enables the fuzzer to generate sequences like:
```
r0 = socket(AF_INET, SOCK_STREAM, 0)
connect(r0, &addr, sizeof(addr))
sendto(r0, "hello", 5, 0, &addr, sizeof(addr))
recvfrom(r0, buf, 1024, 0, 0, 0)
close(r0)
```

### 2.4 Argument Types

| Type | Description | Example |
|------|-------------|---------|
| `const[N]` | Constant value | `const[AT_FDCWD]` |
| `flags[...]` | Bitwise OR of named flags | `flags[O_CREAT\|O_TRUNC]` |
| `ptr[in, T]` | Pointer to input data | `ptr[in, sockaddr_in]` |
| `ptr[out, T]` | Pointer to output buffer | `ptr[out, int32]` |
| `buffer[in]` | Input buffer | `buffer[in]` |
| `buffer[out]` | Output buffer | `buffer[out]` |
| `len[T]` | Length of another argument | `len[buf]` |
| `vma` | Virtual memory area | `vma` |
| `filename` | Path name | `filename` |
| `string[...]` | String from a set | `string["test.txt"]` |
| `proc[N, M, T]` | Per-process value | `proc[1, 4, int32]` |
| `range[N, M]` | Integer range | `range[0, 1024]` |
| `resource` | Kernel resource (fd, etc.) | `fd`, `sock` |

### 2.5 Generating Syzkaller Descriptions

For new kernel subsystems, writing descriptions by hand is time-consuming. syzkaller provides tools to extract descriptions from kernel headers:

```bash
# Generate descriptions from kernel headers
make extract ARCH=amd64 SOURCES=./linux/
```

This parses kernel header files and generates initial syzlang descriptions that can be manually refined.

## 3. Coverage Collection with KCOV

### 3.1 Overview

KCOV is a kernel feature that records the basic blocks executed by a specific thread. It's the coverage feedback mechanism that enables coverage-guided kernel fuzzing.

### 3.2 KCOV API

```c
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define KCOV_ENABLE     _IO('c', 100)
#define KCOV_DISABLE    _IO('c', 101)
#define KCOV_INIT_TRACE _IOW('c', 1, unsigned long)

struct kcov {
    unsigned long mode;
    unsigned long count;
    unsigned long entries[];
};

int main() {
    // Open KCOV device
    int fd = open("/sys/kernel/debug/kcov", O_RDWR);
    
    // Initialize trace buffer
    unsigned long size = 1 << 20; // 1M entries
    ioctl(fd, KCOV_INIT_TRACE, size);
    
    // Map trace buffer
    unsigned long *cover = mmap(NULL, size * sizeof(unsigned long),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    
    // Enable coverage (KCOV_MODE_TRACE_PC for PC coverage)
    ioctl(fd, KCOV_ENABLE, 0 /* KCOV_MODE_TRACE_PC */);
    
    // --- Code to trace ---
    syscall(SYS_openat, AT_FDCWD, "/tmp/test", O_RDONLY, 0);
    // --- End of traced code ---
    
    // Read coverage
    unsigned long count = cover[0]; // Number of PCs recorded
    for (unsigned long i = 0; i < count; i++) {
        printf("PC: 0x%lx\n", cover[i + 1]);
    }
    
    // Disable coverage
    ioctl(fd, KCOV_DISABLE, 0);
    close(fd);
    return 0;
}
```

### 3.3 KCOV Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `KCOV_MODE_TRACE_PC` | Record program counter (PC) values | syzkaller primary mode |
| `KCOV_MODE_TRACE_CMP` | Record comparison operands | Constraint solving (CmpLog analog) |
| `KCOV_MODE_TRACE_BRANCH` | Record branch edges | More precise than PC mode |

### 3.4 Kernel Configuration for KCOV

```makefile
# Required kernel config options
CONFIG_KCOV=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_INFO=y
CONFIG_KASAN=y          # For bug detection
CONFIG_KMSAN=y          # For uninitialized read detection (x86 only)
CONFIG_KASAN_INLINE=y   # Inline instrumentation (faster)
CONFIG_DEBUG_KMEMLEAK=y # Memory leak detection
CONFIG_UBSAN=y          # Undefined behavior sanitizer
```

## 4. KASAN/KMSAN for Bug Detection

### 4.1 KASAN (Kernel AddressSanitizer)

KASAN detects memory safety violations in kernel code:
- **Out-of-bounds access** (slab, stack, global)
- **Use-after-free**
- **Double-free**
- **Invalid free**

**Kernel configuration:**
```makefile
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y    # Software mode (most compatible)
# or
CONFIG_KASAN_SW_TAGS=y    # Software tag-based mode (ARM64, lower overhead)
# or
CONFIG_KASAN_HW_TAGS=y    # Hardware tag-based mode (ARM MTE)
```

**KASAN report example:**
```
BUG: KASAN: slab-out-of-bounds in parse_packet+0x123/0x200
Read of size 4 at addr ffff88800a345678 by task syz-executor/1234

CPU: 0 PID: 1234 Comm: syz-executor Tainted: G    B
Call Trace:
 dump_stack+0x7d/0xa0
 print_report+0x2d4/0x310
 kasan_report+0xb2/0x120
 __kasan_check_read+0x1d/0x30
 parse_packet+0x123/0x200
 netif_receive_skb+0x45/0x60
 ...

Allocated by task 1234:
 kasan_save_stack+0x1b/0x40
 kmem_cache_alloc+0x92/0x1a0
 create_packet+0x56/0x80
 ...

The buggy address belongs to the object at ffff88800a345000
 which belongs to the cache sk_buff_head of size 232
```

### 4.2 KMSAN (Kernel MemorySanitizer)

KMSAN detects **uninitialized memory** reads in the kernel, a particularly dangerous class of bugs because uninitialized data can leak kernel heap/stack contents to userspace.

```makefile
CONFIG_KMSAN=y
```

KMSAN has high overhead (~3x slowdown) and is only available on x86_64. It's extremely valuable for finding information leaks:
- CVE-2022-1012: Uninitialized netlink socket data leak (found by syzkaller + KMSAN)
- CVE-2022-3223: Uninitialized bpf data leak (found by syzkaller + KMSAN)

### 4.3 KCSAN (Kernel ConcurrencySanitizer)

KCSAN detects **data races** in kernel code—a class of bugs that can lead to use-after-free, double-free, and other memory corruption.

```makefile
CONFIG_KCSAN=y
CONFIG_KCSAN_STRICT=y
CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n
```

### 4.4 Kernel UBSAN

Kernel UBSAN detects undefined behavior:
- Signed integer overflow
- Shift exponent out of bounds
- Division by zero
- Null pointer dereference
- Misaligned access

```makefile
CONFIG_UBSAN=y
CONFIG_UBSAN_SANITIZE_ALL=y
```

## 5. Environment Setup

### 5.1 QEMU Setup

The standard syzkaller setup uses QEMU for VM management:

```json
{
    "target": "linux/amd64",
    "http":   ":56741",
    "workdir": "/home/user/syzkaller/workdir",
    "kernel_obj": "/home/user/linux/",
    "image":  "/home/user/syzkaller/disk.img",
    "syzkaller": "/home/user/syzkaller",
    "type": "qemu",
    "vm": {
        "count":  4,
        "cpu":    2,
        "mem":    2048,
        "kernel": "/home/user/linux/arch/x86/boot/bzImage",
        "initrd": "/home/user/syzkaller/initrd.img",
        "cmdline": "console=ttyS0 root=/dev/sda1 debug kasan_multi_shot=1",
        "image": "/home/user/syzkaller/disk.img"
    },
    "reproduce": true,
    "sandbox": "none",
    "cover": true
}
```

### 5.2 GCE Setup

For large-scale fuzzing, syzkaller can use Google Compute Engine:

```json
{
    "type": "gce",
    "vm": {
        "count": 20,
        "cpu": 4,
        "mem": 8192,
        "machine_type": "n1-highcpu-4"
    }
}
```

### 5.3 Android AVD Setup

For Android kernel fuzzing:

```json
{
    "type": "android",
    "vm": {
        "count": 2,
        "cpu": 4,
        "mem": 8192,
        "image": "/path/to/android-system.img",
        "kernel": "/path/to/android-kernel/bzImage",
        "sdk": "/path/to/android-sdk"
    }
}
```

### 5.4 Building the Instrumented Kernel

```bash
# Clone kernel
git clone --depth 1 https://github.com/torvalds/linux.git

# Configure kernel with fuzzing support
cd linux
make defconfig
scripts/config --enable CONFIG_KCOV
scripts/config --enable CONFIG_KASAN
scripts/config --enable CONFIG_KCOV_ENABLE_COMPARISONS
scripts/config --enable CONFIG_DEBUG_FS
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --disable CONFIG_RANDOMIZE_BASE  # For easier debugging
scripts/config --enable CONFIG_KASAN_GENERIC
scripts/config --enable CONFIG_UBSAN

# Build
make -j$(nproc) bzImage
```

## 6. Netlink Fuzzing

### 6.1 Overview

Netlink is the primary IPC mechanism in the Linux kernel, used for network configuration, SELinux, audit, and many other subsystems. syzkaller has extensive netlink descriptions that have discovered hundreds of bugs.

### 6.2 Netlink Description Example

```syzlang
resource netlink_socket[fd]

socket$netlink(domain const[AF_NETLINK], type const[SOCK_RAW], protocol const[NETLINK_ROUTE]) netlink_socket

sendmsg$netlink(fd netlink_socket, msg ptr[in, netlink_message], f flags[send_flags]) intptr
recvmsg$netlink(fd netlink_socket, msg ptr[out, netlink_message], f flags[recv_flags]) intptr

netlink_message {
    nlh     nlmsghdr
    payload netlink_payload
}

nlmsghdr {
    len     len[parent, int32]
    type    flags[netlink_message_types]
    flags   flags[netlink_flags]
    seq     proc[1, 4, int32]
    pid     proc[1, 4, int32]
}

netlink_payload [
    ifinfomsg       netlink_route_ifinfomsg
    rtmsg           netlink_route_rtmsg
    ndmsg           netlink_route_ndmsg
    addrmsg         netlink_route_addrmsg
]
```

### 6.3 Notable Netlink Bugs

- **CVE-2016-9793**: `sock_setsockopt` integer overflow in `SO_SNDBUF` handling, leading to heap overflow. Found by syzkaller.
- **CVE-2017-8824**: Netlink `tipc_nl_compat_doit` double-free. Found by syzkaller.
- **CVE-2021-43267**: Netlink `tipc_msg_validate` out-of-bounds read in TIPC subsystem. Found by syzkaller.

## 7. io_uring Fuzzing

### 7.1 Overview

io_uring is a high-performance asynchronous I/O interface added in Linux 5.1. Its complexity (shared ring buffers, fixed buffers, file registration, link chains) makes it a rich fuzzing target. syzkaller has found numerous bugs in io_uring.

### 7.2 io_uring Description

```syzlang
io_uring_setup$enter(entries int32, params ptr[inout, io_uring_params]) fd

io_uring_params {
    sq_entries      int32
    cq_entries      int32
    flags           flags[io_uring_setup_flags]
    sq_thread_cpu   int32
    sq_thread_idle  int32
    features        int32
    resv1           const[0, int32]
    resv2           const[0, int64]
    sq_off          io_sqring_offsets
    cq_off          io_cqring_offsets
}

io_uring_register$files(fd fd, opcode const[IORING_REGISTER_FILES], arg ptr[in, array[int32]], nr_args len[arg]) intptr
io_uring_register$buffers(fd fd, opcode const[IORING_REGISTER_BUFFERS], arg ptr[in, array[iovec]], nr_args len[arg]) intptr

io_uring_enter(fd fd, to_submit int32, min_complete int32, flags flags[io_uring_enter_flags], sig ptr[inout, sigset_t]) intptr
```

### 7.3 Notable io_uring Bugs

- **CVE-2021-4159**: io_uring `io_sqe_files_register` use-after-free. Found by syzkaller.
- **CVE-2022-2327**: io_uring OOB write in `io_uring_remove_buffers`. Found by syzkaller.
- **CVE-2022-4280**: io_uring double free in `io_sqe_buffers_register`. Found by syzkaller.

## 8. eBPF Verifier Fuzzing

### 8.1 Overview

The eBPF verifier is one of the most security-critical components of the Linux kernel. It validates eBPF programs before they're loaded into the kernel, ensuring they don't access out-of-bounds memory, don't leak kernel data, and don't crash the system. Bugs in the verifier can be exploited to load malicious eBPF programs that bypass security checks.

### 8.2 eBPF Description

```syzlang
bpf$PROG_LOAD(prog_type const[BPF_PROG_TYPE_SOCKET_FILTER], insn_cnt len[insns], insns ptr[in, array[bpf_insn]], license ptr[in, string["GPL"]], log_buf buffer[out], log_size len[log_buf], log_level const[1], kern_version const[0]) fd

bpf_insn {
    code    flags[bpf_insn_code]
    dst_reg flags[bpf_reg]
    src_reg flags[bpf_reg]
    off     int16
    imm     int32
}
```

### 8.3 Notable eBPF Verifier Bugs

- **CVE-2021-3490**: eBPF verifier incorrect bounds computation for `mov64` with `AND` immediate. Led to out-of-bounds read/write. Found by syzkaller. Exploitable for privilege escalation.
- **CVE-2023-2163**: eBPF verifier incorrect tracking of scalar vs pointer types. Found by syzkaller.
- **CVE-2024-1086**: eBPF verifier incorrect handling of `atomic_fetch_add` with 64-bit values. Led to use-after-free. Found by syzkaller. Actively exploited in the wild.

## 9. Filesystem Fuzzing

### 9.1 Overview

Filesystem fuzzing targets the VFS layer and individual filesystem implementations. syzkaller can fuzz filesystems by:
1. Creating filesystem images with corrupted structures
2. Mounting them and performing file operations
3. Checking for kernel panics, KASAN violations, and lockups

### 9.2 Filesystem Description

```syzlang
mount$ext4(src ptr[in, string["/dev/sda1"]], dst ptr[in, filename], type ptr[in, string["ext4"]], flags flags[mount_flags], opts ptr[in, ext4_mount_opts]) intptr

ext4_mount_opts {
    data_mode   string["journal", "ordered", "writeback"]
    errors      string["continue", "remount-ro", "panic"]
    commit      string["1", "10", "100"]
    max_mnt_cnt string["1", "10", "100"]
}
```

### 9.3 fs-fuzz (Filesystem Fuzzer)

In addition to syzkaller's syscall-level fuzzing, specialized filesystem fuzzers operate at the disk image level:

- **fs-fuzz**: Mutates filesystem images (ext4, btrfs, xfs) and mounts them
- **fsck-fuzz**: Mutates filesystem images, runs fsck, and checks for discrepancies
- **JANUS**: Coverage-guided filesystem image mutation (S&P 2023)

## 10. Android Kernel Fuzzing

### 10.1 Overview

Android kernel fuzzing with syzkaller targets Android-specific kernel subsystems: Binder driver, wakelocks, ion memory allocator, and vendor-specific additions.

### 10.2 Binder Driver Fuzzing

Binder is Android's primary IPC mechanism. It's the backbone of Android's security model and a historically bug-rich surface:

```syzlang
binder$ioctl(fd fd, cmd const[BINDER_WRITE_READ], arg ptr[inout, binder_write_read]) intptr

binder_write_read {
    write_size     len[write_buffer, int64]
    write_consumed int64
    write_buffer   ptr[in, array[binder_cmd]]
    read_size      len[read_buffer, int64]
    read_consumed  int64
    read_buffer    ptr[out, array[binder_cmd]]
}

binder_cmd [
    binder_transaction       binder_transaction_data
    binder_reply              binder_transaction_data
    binder_acquire            binder_ptr_cookie
    binder_release            binder_ptr_cookie
    binder_INCREFS            binder_ptr_cookie
    binder_DECREFS            binder_ptr_cookie
    binder_enter_looper       void
    binder_exit_looper        void
    binder_request_death      binder_ptr_cookie
    binder_clear_death        binder_ptr_cookie
    binder_dead_binder_acquire binder_ptr_cookie
    binder_dead_binder_release binder_ptr_cookie
    binder_dead_binder_notify binder_ptr_cookie
]
```

### 10.3 Notable Android Kernel Bugs

- **CVE-2019-2215**: Binder use-after-free in `binder_thread_read`. Found by syzkaller. Exploited by NSO Group's Pegasus spyware. The bug was introduced by a commit that removed a `binder_free_buffer` call.
- **CVE-2020-0041**: Binder race condition leading to use-after-free. Found by syzkaller.
- **CVE-2022-20421**: Binder out-of-bounds write in `binder_alloc_new_buf_locked`. Found by syzkaller.

### 10.4 Android-Specific Setup

```json
{
    "target": "linux/arm64",
    "type": "android",
    "vm": {
        "count": 4,
        "image": "/path/to/aosp-system.img",
        "kernel": "/path/to/android-kernel/bzImage",
        "sdk": "/path/to/android-sdk"
    },
    "sandbox": "android",
    "enable_syscalls": [
        "binder$ioctl",
        "binder$ioctl32",
        "openat$binder",
        "mmap$binder"
    ]
}
```

## 11. Crash Detection and Minimization

### 11.1 Crash Detection

syzkaller detects kernel crashes through multiple mechanisms:

1. **Kernel panic**: The VM crashes, QEMU detects the exit
2. **KASAN report**: KASAN prints a report to the kernel log
3. **Hang detection**: The executor doesn't respond within the timeout
4. **BUG_ON() / WARN_ON()**: Kernel assertion failures
5. **rcu stalls**: RCU stall detection indicates lockups
6. **general protection fault**: GPF from invalid memory access

### 11.2 Minimization

When a crash is detected, syzkaller minimizes the reproducer:
1. **Remove unnecessary syscalls**: Try removing each syscall; if the crash persists, keep it removed
2. **Remove arguments**: Replace arguments with simpler values (0, -1, etc.)
3. **Shrink buffers**: Reduce buffer sizes to the minimum needed

```bash
# Minimize a crash reproducer
./syz-repro -config=syzkaller.cfg -crash=crash.log
```

### 11.3 Reproducibility

Kernel bugs are often **non-deterministic** (races, timing-dependent). syzkaller addresses this by:
- Replaying the reproducer multiple times (default: 100)
- Reporting the reproduction rate (e.g., "reproduces 50/100 times")
- Using `syz-repro` for manual reproduction with different kernel configs

## 12. Case Studies: syzkaller-Discovered CVEs

### 12.1 CVE-2016-9793: `sock_setsockopt` Integer Overflow

**Bug**: `sock_setsockopt` in `net/core/sock.c` allows setting `SO_SNDBUF` and `SO_RCVBUF` to values that overflow integer arithmetic, leading to a heap buffer overflow.

**Root cause**: The kernel computed `sk->sk_sndbuf = val * 2` without checking for overflow. A userspace program could set `SO_SNDBUF` to `INT_MAX/2 + 1`, causing the multiplication to overflow to a small positive value, then overflow again on subsequent additions.

**Discovery**: syzkaller generated a program that called `setsockopt` with extreme values for `SO_SNDBUF`, triggering KASAN reports.

**Fix**: Added overflow checks before the multiplication.

### 12.2 CVE-2019-2215: Binder Use-After-Free

**Bug**: In `binder_thread_read`, a `binder_free_buffer` call was missing, causing a freed buffer to remain on the thread's stack and be double-freed.

**Root cause**: Commit `7b5b4288` ("binder: remove deferred_free path") removed a `binder_free_buffer` call that was actually necessary in certain error paths.

**Discovery**: syzkaller generated a sequence of Binder ioctl calls that triggered the error path.

**Impact**: Exploited by NSO Group's Pegasus spyware for targeted surveillance. The exploit chain used the UAF to gain code execution in the kernel, then disabled SELinux and installed a persistent rootkit.

### 12.3 CVE-2021-3490: eBPF Verifier Bounds Check Bypass

**Bug**: The eBPF verifier incorrectly computed the bounds of a register after a `mov64` instruction with `AND` immediate. This allowed an eBPF program to pass verification but then perform out-of-bounds memory access at runtime.

**Root cause**: In `adjust_scalar_min_max_vals`, the case `BPF_AND` with an immediate value incorrectly set the `umin_value` and `umax_value` of the destination register. Specifically, for `dst_reg &= imm`, the verifier computed `umax = min(umax, imm)` but failed to account for cases where `imm` had a smaller bit width than the register.

**Discovery**: syzkaller generated an eBPF program that used this pattern to bypass the verifier's bounds check, then performed an OOB read confirmed by KASAN.

**Impact**: Privilege escalation. The exploit loaded a malicious eBPF program that could read and write arbitrary kernel memory, bypassing all eBPF security checks.

### 12.4 CVE-2024-1086: eBPF nf_tables Use-After-Free

**Bug**: A use-after-free in the `nf_tables` netfilter subsystem, triggered through eBPF operations. The bug was in the `nft_verdict_init` function, which incorrectly handled verdict objects during set element destruction.

**Root cause**: When a set element with a verdict was destroyed, the `nft_verdict_init` function could decrement the reference count of a chain object below zero, leading to premature freeing and subsequent use-after-free.

**Discovery**: syzkaller generated a sequence of netfilter netlink commands combined with eBPF operations that triggered the UAF.

**Impact**: Privilege escalation from unprivileged user to root. Actively exploited in the wild. The exploit was publicly available within weeks of the CVE being published.

## References

[1] Vyukov, D. (2015). *syzkaller: Kernel Fuzzer*. https://github.com/google/syzkaller

[2] Vyukov, D. (2016). *Coverage-Guided Kernel Fuzzing*. https://lwn.net/

[3] Corbet, J. (2016). *KCOV: Kernel Code Coverage*. https://lwn.net/Articles/671640/

[4] Google. *syzbot: Automated Kernel Bug Reporting*. https://syzkaller.appspot.com/

[5] Wiktor, M. & Kwiatkowski, D. (2024). *CVE-2024-1086 Exploitation*. https://pwning.tech/nftables/

[6] Miller, B.P., Fredriksen, L., & So, B. (1990). *An Empirical Study of the Reliability of UNIX Utilities*. Communications of the ACM, 33(12). DOI: 10.1145/96267.96279

[7] Serebryany, K., Bruening, D., Potapenko, A., & Vyukov, D. (2012). *AddressSanitizer: A Fast Address Sanity Checker*. USENIX ATC.

[8] Ryabinin, A. (2015). *KASAN: Kernel AddressSanitizer*. https://lwn.net/Articles/619945/

[9] Ryabinin, A. & Nesterenko, D. (2021). *KMSAN: Kernel MemorySanitizer*. Linux Kernel Documentation. https://www.kernel.org/doc/html/latest/dev-tools/kmsan.html

[10] Elver, M. (2020). *KCSAN: Kernel Concurrency Sanitizer*. Linux Kernel Documentation. https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html

[11] CVE-2016-9793. *sock_setsockopt Integer Overflow*. https://nvd.nist.gov/vuln/detail/CVE-2016-9793

[12] CVE-2019-2215. *Binder Use-After-Free*. https://nvd.nist.gov/vuln/detail/CVE-2019-2215

[13] CVE-2021-3490. *eBPF Verifier Bounds Check Bypass*. https://nvd.nist.gov/vuln/detail/CVE-2021-3490

[14] CVE-2024-1086. *nf_tables Use-After-Free*. https://nvd.nist.gov/vuln/detail/CVE-2024-1086

[15] Google. *syzkaller Documentation*. https://github.com/google/syzkaller/#syzlang-description-format

[16] Tar tourism. *syzkaller: Android Kernel Fuzzing*. https://source.android.com/docs/security/enhancements
