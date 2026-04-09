# 9a. Kernel Fuzzing & Vulnerability Discovery: Fuzzing Techniques

## Table of Contents

1. [Syzkaller: Architecture and Operation](#1-syzkaller-architecture-and-operation)
2. [Writing Syzkaller Syscall Descriptions (Syzlang)](#2-writing-syzkaller-syscall-descriptions-syzlang)
3. [Syzkaller's Track Record](#3-syzkallers-track-record)
4. [kAFL: Hardware-Assisted Kernel Fuzzing with Intel PT](#4-kafl-hardware-assisted-kernel-fuzzing-with-intel-pt)
5. [HEALER: Improved Kernel Fuzzing with Relation Learning](#5-healer-improved-kernel-fuzzing-with-relation-learning)
6. [Trinity: Syscall Fuzzer](#6-trinity-syscall-fuzzer)
7. [Custom Kernel Fuzzers and Targeting Specific Subsystems](#7-custom-kernel-fuzzers-and-targeting-specific-subsystems)
8. [Kernel Sanitizers as Bug Detectors During Fuzzing](#8-kernel-sanitizers-as-bug-detectors-during-fuzzing)
9. [Setting Up a Kernel Fuzzing Lab](#9-setting-up-a-kernel-fuzzing-lab)
10. [Reproducing and Triaging Kernel Crashes from Fuzzers](#10-reproducing-and-triaging-kernel-crashes-from-fuzzers)

---

## 1. Syzkaller: Architecture and Operation

### 1.1 Overview

Syzkaller (pronounced "sys-caller") is Google's coverage-guided kernel fuzzer and the most prolific
automated Linux kernel vulnerability discovery tool ever built. It generates sequences of system
calls ("programs") based on declarative descriptions of syscall interfaces, executes them inside
virtual machines, collects kernel code coverage feedback, and uses that coverage to guide the
generation and mutation of future test programs. Syzkaller has found thousands of kernel bugs since
its public introduction around 2015, and its continuous fuzzing infrastructure (syzbot) runs 24/7
against upstream Linux kernels.

### 1.2 Process Architecture

Syzkaller's architecture is a multi-process, manager-executor model:

```
                  +-----------+
                  | syz-manager |  (host machine)
                  +------+------+
                         |
              +----------+----------+
              |          |          |
          +---v---+  +---v---+  +---v---+
          |  VM1  |  |  VM2  |  |  VM3  |  ...  (QEMU/KVM instances)
          +---+---+  +---+---+  +---+---+
              |          |          |
          +---v---+  +---v---+  +---v---+
          |syz-   |  |syz-   |  |syz-   |
          |executor| |executor| |executor|
          +---+---+  +---+---+  +---+---+
              |          |          |
        [transient C++ subprocesses per input]
```

**`syz-manager`** (runs on the host) is responsible for:
- Starting, restarting, and monitoring VM instances
- The actual fuzzing logic: program generation, mutation, minimization, and triage
- Persistent corpus storage (in `corpus.db`)
- Crash storage and deduplication (in `workdir/crashes/`)
- Serving a web dashboard (HTTP interface for monitoring coverage, crashes, and statistics)
- Communicating with `syz-executor` instances via RPC

**`syz-executor`** (runs inside each VM):
- Receives programs from `syz-manager` over RPC
- Spawns transient subprocesses to execute each program (sequence of syscalls)
- Collects code coverage via KCOV and reports results (coverage PCs, error status) back to the manager
- Each transient subprocess is a simple, statically compiled C++ binary that executes a single
  input using shared memory for communication, designed to be as minimal as possible to avoid
  interfering with the fuzzing target

### 1.3 Coverage-Guided Fuzzing

Syzkaller uses KCOV (Kernel COVerage) for collecting code coverage. KCOV relies on compiler
instrumentation (via Clang's SanitizerCoverage or GCC equivalent) in tracing mode to record which
basic blocks or CFG edges are hit during execution.

The coverage feedback loop works as follows:

1. **Generate** a program (sequence of syscalls with concrete arguments) based on syscall descriptions
2. **Execute** the program inside a VM via `syz-executor`
3. **Collect** coverage PCs from the KCOV shared memory buffer
4. **Evaluate**: If the program triggered new coverage (previously unseen code paths), add it to the corpus
5. **Mutate** existing corpus programs to try to discover more new coverage
6. **Minimize** programs that trigger crashes or new coverage to their smallest form

Coverage is collected per-thread using the `/sys/kernel/debug/kcov` interface. Each coverage point
generally represents a basic block (GCC) or a CFG edge (Clang). KCOV also supports comparison
operand collection (`KCOV_TRACE_CMP`), which allows the fuzzer to learn comparison values used in
conditional branches -- critical for overcoming magic-byte checks.

### 1.4 Corpus Management

The corpus is the set of programs that have collectively achieved the current code coverage. Key
aspects:

- **Storage**: Programs are stored in `corpus.db` in the working directory, using a serialized
  text representation
- **Deduplication**: Programs are deduplicated based on the set of coverage signals they contribute
- **Minimization**: When a new program is added to the corpus, syzkaller attempts to minimize it --
  removing unnecessary syscalls and simplifying arguments -- while preserving the coverage signal
- **Persistence**: The corpus survives restarts; `syz-manager` loads it on startup
- **Rotation**: Programs that no longer contribute unique coverage may be evicted
- **Sharing**: In multi-instance setups, corpus programs can be shared across managers via
  `syz-hub`

### 1.5 Program Representation

Syzkaller uses three representations of programs:

1. **In-memory AST**: A tree of `Call` and `Arg` values (defined in `prog/prog.go`) used for
   analysis, generation, mutation, minimization, and validation
2. **Text representation**: Human-readable serialization stored in corpus and crash logs:
   ```
   r0 = open(&(0x7f0000000000)="./file0", 0x3, 0x9)
   read(r0, &(0x7f0000000000), 42)
   close(r0)
   ```
3. **Binary `exec` representation**: A simplified, type-erased binary format used by the executor
   for actual syscall invocation -- compact and fast to interpret

### 1.6 Crash Handling

When syzkaller detects a kernel crash (panic, KASAN report, hang, etc.), it:

1. Saves the crash info under `workdir/crashes/<hash>/`
2. Extracts a description using regex-based parsers in `pkg/report`
3. Deduplicates crashes by their description string
4. Saves up to 100 `logN`/`reportN` pairs per unique crash
5. Attempts automated reproduction via `syz-repro`
6. Generates both a syz-format reproducer and (if possible) a standalone C reproducer

Three special crash types indicate infrastructure issues:
- `no output from test machine` -- VM produced no output
- `lost connection to test machine` -- SSH connection dropped
- `test machine is not executing programs` -- VM alive but stalled

---

## 2. Writing Syzkaller Syscall Descriptions (Syzlang)

### 2.1 The Syzlang Language

Syzlang (`[si:z'laeng]`) is the declarative description language used to tell syzkaller about
syscall interfaces. Descriptions define syscall signatures, argument types, structures, flags,
resources (inter-syscall dependencies), and more. All descriptions live in `sys/$OS/*.txt` files.

### 2.2 Basic Syntax

A syscall description specifies the name, arguments with types, and return type:

```
syscallname(arg1 type1, arg2 type2, ...) return_type
```

Example:

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf])
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

### 2.3 Core Type System

| Type | Description |
|------|-------------|
| `const[val, intN]` | Integer constant |
| `intN` / `intptr` | Integer of N bits / pointer-sized integer |
| `flags[name]` | Set of flag values (bitwise OR combinations or enums) |
| `array[type, N]` | Fixed or variable-length array |
| `ptr[dir, type]` | Pointer to object (dir = in/out/inout) |
| `string[vals]` | Zero-terminated string buffer |
| `len[field]` | Length of another field |
| `bytesize[field]` | Size in bytes of another field |
| `vma` | Pointer to set of pages (for mmap-family calls) |
| `proc[start, per_proc]` | Per-process integer range (avoid interference) |
| `text[type]` | Machine code (x86_real, x86_64, arm64, etc.) |
| `void` | Zero-size type, useful in templates and varlen unions |
| `fmt[format, val]` | String representation of an integer |
| `compressed_image` | Zlib-compressed disk image for filesystem fuzzing |

### 2.4 Resources: Modeling Inter-Syscall Dependencies

Resources model values that flow between syscalls (e.g., file descriptors). They are the primary
mechanism for expressing temporal dependencies:

```
resource fd[int32]: 0xffffffffffffffff, AT_FDCWD, 1000000
resource sock[fd]
resource sock_unix[sock]

socket(...) sock
accept(fd sock, ...) sock
listen(fd sock, backlog int32)
```

Resources support inheritance (e.g., `sock` inherits from `fd`). Special values (like `-1` for
"invalid fd") can be specified after the colon. Each resource type must have at least one producer
(output) and one consumer (input).

### 2.5 Structs and Unions

Structs support field-level direction attributes, conditional fields, overlays for separate
input/output layouts, and packing/alignment attributes:

```
header_fields {
    magic       const[0xabcd, int16]
    version     int8
} [packed]

my_union [
    opt1    int32
    opt2    array[int8, 16]
] [varlen]
```

### 2.6 Conditional Fields

Fields can be conditionally included based on the values of other fields:

```
packet {
    header  header_fields
    payload int64  (if[value[header:has_payload] == 0x1])
    body    array[int8]
} [packed]
```

### 2.7 Type Templates

Templates allow parametric types:

```
type nlattr[TYPE, PAYLOAD] {
    nla_len     len[parent, int16]
    nla_type    const[TYPE, int16]
    payload     PAYLOAD
} [align[4]]
```

### 2.8 Call Attributes

Syscall descriptions can be annotated with attributes:

| Attribute | Effect |
|-----------|--------|
| `disabled` | Exclude from fuzzing |
| `timeout[N]` | Extra execution timeout in ms |
| `ignore_return` | Don't use return value for feedback |
| `breaks_returns` | Ignore all subsequent return values |
| `no_generate` | Only use seed programs, don't auto-generate |
| `no_minimize` | Don't modify when minimizing crashers |

### 2.9 Description Compilation Pipeline

1. **`syz-extract`**: Extracts constant values from kernel headers by generating small C programs
   that print the values. Results stored in `.const` files per architecture
2. **`syz-sysgen`**: Translates `.txt` descriptions + `.const` files into Go code (instantiations
   of `Syscall` and `Type` objects in `prog/types.go`) and C metadata for the executor

```bash
make extract TARGETOS=linux SOURCEDIR=$KSRC   # Step 1: extract constants
make generate                                   # Step 2: generate Go code
make                                            # Step 3: rebuild binaries
```

### 2.10 Best Practices

- **Use kernel names**: Follow existing kernel naming conventions for structs, flags, enums
- **Only specify valid values**: Don't add artificial magic values like `-1` or `INT_MAX` to flag
  sets; the fuzzer handles invalid values on its own via mutation
- **Declare in order of importance**: Put syscalls first, then types, then flags (opposite of C)
- **Test descriptions**: Write test programs in `sys/linux/test/` to verify the "main successful
  scenario" works
- **Use `enable_syscalls`**: When testing new descriptions, restrict fuzzing to just those calls

---

## 3. Syzkaller's Track Record

### 3.1 Scale of Bug Discovery

Syzkaller is the single most productive kernel bug-finding tool in history. Through the syzbot
continuous fuzzing infrastructure (https://syzkaller.appspot.com), it has found and reported an
extraordinary number of bugs:

- **5,000+ bugs** reported to the Linux kernel as of 2024, with the number continuing to grow
- Active continuous fuzzing against multiple kernel trees: mainline (Linus), linux-next, stable
  branches, and specialized trees (Android, ChromeOS)
- Syzbot automatically files bug reports to relevant mailing lists, tracks fixes, and detects
  regressions
- Many bugs are automatically reproduced with both syz-format and C reproducers

### 3.2 Types of Bugs Found

Syzkaller, combined with kernel sanitizers, finds a wide spectrum of bug classes:

| Bug Class | Detection Mechanism | Examples |
|-----------|-------------------|----------|
| **Use-after-free** | KASAN | Slab UAF, page UAF, RCU UAF |
| **Out-of-bounds access** | KASAN | Slab OOB read/write, stack OOB, global OOB |
| **Null pointer dereference** | Kernel OOPS | Null deref in various subsystems |
| **Uninitialized memory use** | KMSAN | Info leaks to userspace, uninitialized stack/heap |
| **Data races** | KCSAN | Concurrent unsynchronized accesses |
| **Undefined behavior** | UBSAN | Shift overflows, integer overflow, alignment |
| **Deadlocks** | Lockdep (LOCKDEP) | ABBA deadlocks, recursive locking |
| **Memory leaks** | Kmemleak | Unreferenced heap allocations |
| **Kernel panics/BUGs** | Direct detection | BUG_ON triggers, assertion failures |
| **Hangs/infinite loops** | Timeout detection | Soft lockups, RCU stalls |
| **WARNING splats** | Console monitoring | WARN_ON triggers indicating logic bugs |
| **Double-free** | KASAN | Freeing already-freed memory |

### 3.3 Subsystems Most Affected

Based on syzbot data, the kernel subsystems where syzkaller finds the most bugs include:

- **Networking stack** (net/, net/ipv4/, net/ipv6/, net/netfilter/): The largest single source of
  bugs due to the complexity of socket options, packet processing, netfilter rules, and protocol
  implementations
- **Filesystem layer** (fs/, including ext4, btrfs, XFS, FUSE, overlayfs): Complex state machines
  triggered by filesystem images and mount operations
- **USB subsystem** (drivers/usb/): Exposed through gadget emulation and USB device fuzzing
- **Bluetooth** (net/bluetooth/): Protocol parsing and state management
- **Sound subsystem** (sound/): ALSA device ioctls
- **Media subsystem** (drivers/media/): V4L2 interfaces
- **BPF subsystem** (kernel/bpf/): Verifier bugs, JIT bugs
- **Memory management** (mm/): mmap, mremap, madvise edge cases
- **io_uring** (io_uring/): Complex async I/O interface

### 3.4 Notable Security Vulnerabilities

Syzkaller has been responsible for discovering numerous CVE-worthy security vulnerabilities,
including privilege escalation bugs, container escapes, and remotely exploitable networking
issues. Many high-profile Linux kernel CVEs since 2017 were first found by syzkaller/syzbot.

### 3.5 The Syzbot Infrastructure

Syzbot (https://syzkaller.appspot.com) provides:

- **Automated bug reporting**: Files reports with reproducer, config, crash log to LKML
- **Automated bisection**: `git bisect` to find the offending commit
- **Fix tracking**: Monitors kernel commits for fixes, verifies they resolve the bug
- **Regression detection**: Alerts when a previously fixed bug reappears
- **Dashboard**: Real-time view of open/fixed/invalid bugs per kernel tree
- **Assets**: Downloadable disk images, vmlinux, kernel images for each report

---

## 4. kAFL: Hardware-Assisted Kernel Fuzzing with Intel PT

### 4.1 Overview

kAFL (kernel-AFL) is a hardware-assisted feedback fuzzer for x86 virtual machines, developed by
Intel Labs. Unlike syzkaller, which uses compiler-instrumented software coverage (KCOV), kAFL
leverages Intel Processor Trace (Intel PT) to collect coverage feedback from unmodified binary
targets running inside QEMU/KVM guests. This makes it suitable for fuzzing closed-source kernels,
firmware, and hypervisors where source-code instrumentation is not possible.

### 4.2 Architecture and Key Technologies

kAFL builds on several Intel hardware features:

- **Intel PT (Processor Trace)**: Hardware feature available since Skylake (6th gen) that traces
  branch execution in a compressed binary format with minimal performance overhead (~5%). Intel PT
  records taken/not-taken branch decisions, allowing reconstruction of the exact execution path
  without software instrumentation
- **Intel VT (Virtualization Technology)**: KVM-based VM execution for the fuzz target
- **Intel PML (Page Modification Logging)**: Efficient tracking of dirty pages for fast snapshot
  restore between fuzzing iterations

### 4.3 Nyx Integration

Modern kAFL is built on top of the Nyx fuzzing framework, which provides:

- **Fast VM snapshots**: Snapshot/restore of full VM state in microseconds using dirty page
  tracking (PML). This eliminates the need to reboot between iterations
- **Hypercall-based agent interface**: A small agent in the guest communicates with the fuzzer
  via hypercalls (`KAFL_HYPERCALL_*`) to signal input buffer location, coverage area, crash
  events, etc.
- **Parallel execution**: Multiple QEMU instances run in parallel, each as a separate fuzzer
  worker

### 4.4 Workflow

1. **Target preparation**: Install a small kAFL agent/harness in the target (kernel module,
   firmware hook, or driver wrapper) that defines where fuzz input is consumed
2. **Snapshot**: Boot the VM to the point of interest and take a snapshot
3. **Fuzzing loop**:
   - Restore snapshot
   - Inject mutated input via shared memory
   - Resume execution with Intel PT tracing enabled
   - Decode PT trace to extract edge coverage bitmap
   - If new coverage found, save input to corpus
   - If crash detected, save crashing input
4. **Corpus management**: AFL-like queue management with favored inputs

### 4.5 Mutation Strategies

kAFL integrates several advanced mutation strategies:

- **Radamsa**: General-purpose grammar-aware mutator
- **Redqueen**: Extracts comparison operands from conditional branches via VM introspection,
  enabling automatic bypass of magic-byte checks without source code access
- **Grimoire**: Identifies keywords and structural patterns in inputs to generate syntax-aware
  mutations
- **IJON**: Annotation-based guidance for human-in-the-loop fuzzing of complex state machines

### 4.6 Successful Targets

kAFL has been successfully applied to:

- **Linux kernel**: Kernel modules, drivers, filesystem implementations
- **Confidential Computing**: Linux guest hardening for Intel TDX, SGX enclaves
- **UEFI firmware**: TDVF, OVMF firmware validation
- **Windows drivers and userspace**: Via agent in Windows guest
- **Hypervisors**: Fuzzing the VMM/hypervisor from a guest
- **Mozilla Firefox IPC**: Application-level fuzzing at VM speed
- **Intel SGX enclaves**: In-enclave code via special agent

### 4.7 Requirements

- Intel Skylake or newer CPU (for Intel PT support)
- Custom patched host kernel (KVM modifications for PT and PML support)
- ~2GB RAM per parallel fuzzing instance
- Recent Debian/Ubuntu host

### 4.8 Advantages Over Software-Instrumented Fuzzing

| Aspect | kAFL (Intel PT) | Syzkaller (KCOV) |
|--------|----------------|-----------------|
| Source code required | No | Yes (for instrumentation) |
| Coverage accuracy | Hardware-precise branch tracing | Compiler-inserted coverage points |
| Overhead | ~5% (hardware) | ~10-30% (software instrumentation) |
| Target flexibility | Any x86 code (OS, firmware, hypervisor) | Source-instrumented kernels only |
| Snapshot speed | Microseconds (PML-based) | VM reboot or ssh-based recovery |
| Semantic understanding | Treats input as byte buffer | Syscall-aware, structured input |

---

## 5. HEALER: Improved Kernel Fuzzing with Relation Learning

### 5.1 Overview

HEALER is a kernel fuzzer inspired by syzkaller, developed as a research prototype (published at
SOSP 2021). Written in Rust, it addresses a key limitation of syzkaller: the reliance on an
empirically derived, static "choice table" for deciding which syscalls to combine in a program.
HEALER instead dynamically learns the influence relationships between syscalls at runtime.

### 5.2 Core Innovation: Dynamic Relation Learning

Syzkaller uses a static priority table (`prog/prio.go`) that encodes the likelihood that one
syscall's output should feed into another syscall's input. This table is derived from type
compatibility (resource types) but is essentially heuristic.

HEALER's key insight is to **dynamically detect** influence relationships between syscalls:

1. When a minimized program produces new coverage, HEALER iteratively **removes individual
   syscalls** from the sequence
2. It **observes coverage changes** after each removal
3. If removing syscall A causes syscall B to lose coverage, this implies A *influences* B
   (e.g., A creates a resource that B needs)
4. These learned relations are used to guide future program generation and mutation, making the
   fuzzer more likely to generate productive syscall sequences

### 5.3 Architecture

Unlike syzkaller's Go-based multi-process design, HEALER uses a different architecture:

- Written in **Rust** for memory safety and performance
- Reuses syzkaller's **syzlang descriptions** (builds syzkaller as a dependency to parse them)
- Reuses syzkaller's **syz-executor** for syscall execution inside VMs
- Uses QEMU/KVM for virtualization with SSH-based communication
- Supports parallel fuzzing via multiple threads and VM instances

### 5.4 Results

In the SOSP 2021 paper evaluation, HEALER demonstrated:

- Higher code coverage than syzkaller in the same time budget
- Discovery of previously unknown kernel bugs
- More efficient exploration of deep kernel code paths due to better syscall ordering

### 5.5 Limitations

- Archived research prototype (repository archived December 2023)
- Does not implement all of syzkaller's features (e.g., automated reproduction, bisection,
  crash deduplication at syzbot scale)
- Many important features were noted as unpublished

---

## 6. Trinity: Syscall Fuzzer

### 6.1 Overview

Trinity is one of the oldest Linux syscall fuzzers, created by Dave Jones (kernelslacker). First
publicly released around 2010, it predates coverage-guided fuzzing and takes a different approach:
it uses **knowledge-based, semi-intelligent argument generation** rather than coverage feedback.

As of recent updates, Trinity is considered largely abandonware by its original author and has been
partly maintained by an LLM for experimental purposes. For active kernel fuzzing, syzkaller is
the recommended tool.

### 6.2 Approach: Knowledge-Based Argument Generation

Trinity's core innovation was moving beyond purely random argument generation:

1. **Type-aware arguments**: If a syscall expects a file descriptor, Trinity provides an actual
   fd (from /dev, /sys, /proc, or network sockets). On startup, it walks `/dev`, `/sys`, `/proc`
   to build a pool of valid file descriptors
2. **Flag awareness**: For arguments that accept flags (like `open()` flags), Trinity knows the
   valid flag values and usually provides valid combinations, occasionally bit-flipping one to
   test edge cases
3. **Range awareness**: For arguments that accept ranges, values are biased to fit within the
   valid range
4. **Socket protocol coverage**: Creates sockets for many network protocols to provide valid
   socket fds for network-related syscalls
5. **Ioctl coverage**: Extensive per-device ioctl definitions in the `ioctls/` directory

### 6.3 Architecture

- Written in **C**, runs directly on the target system (no VM isolation by default)
- Spawns multiple child processes, each making random syscall sequences
- Each child selects a random syscall, generates semi-intelligent arguments, and invokes it
- Supports filtering: `-c` to test specific syscalls, `-x` to exclude syscalls, `-g` for
  syscall groups (vm, vfs)
- Monitors kernel taint flags to detect issues

### 6.4 Key Differences from Syzkaller

| Feature | Trinity | Syzkaller |
|---------|---------|-----------|
| Coverage guidance | No (random/knowledge-based) | Yes (KCOV-based) |
| VM isolation | Runs on bare metal | Runs inside VMs |
| Syscall descriptions | C code per syscall | Syzlang declarative language |
| Inter-syscall dependencies | Limited (fd passing) | Rich resource model |
| Crash reproduction | Manual | Automated (syz-repro) |
| Continuous fuzzing | No | Yes (syzbot) |
| Active maintenance | Minimal (LLM-maintained) | Very active (Google) |

### 6.5 Historical Significance

Despite its limitations compared to modern fuzzers, Trinity:

- Found hundreds of kernel bugs over its lifetime
- Demonstrated the value of semi-intelligent syscall argument generation
- Pioneered the concept of per-syscall argument specifications
- Influenced the design of later kernel fuzzers including syzkaller

---

## 7. Custom Kernel Fuzzers and Targeting Specific Subsystems

### 7.1 Why Build Custom Fuzzers?

While syzkaller is a general-purpose kernel fuzzer, custom fuzzers can outperform it for specific
subsystems by:

- Providing deeper domain knowledge about protocol state machines
- Generating inputs that reach deep code paths faster
- Handling subsystem-specific input formats (filesystem images, network packets, USB descriptors)
- Testing internal kernel APIs that aren't directly exposed via syscalls

### 7.2 Filesystem Fuzzing

Filesystem implementations are a rich target because they parse complex on-disk structures:

**Approach 1: Image-based fuzzing**
- Generate or mutate filesystem images
- Mount them inside a VM and exercise the filesystem
- Syzkaller supports this via `compressed_image` type and `syz_mount_image` pseudo-syscall

**Approach 2: Targeted ioctl fuzzing**
- Focus on filesystem-specific ioctls (e.g., btrfs ioctls, ext4 ioctls)
- Write syzlang descriptions for the specific subsystem

**Tools:**
- **syzkaller** with filesystem descriptions
- **AFL/libFuzzer** harnesses for userspace filesystem tools (e.g., fsck, mkfs)
- **kAFL** for fuzzing filesystem code in a VM with image mutation

### 7.3 Network Protocol Fuzzing

Kernel network stack fuzzing targets protocol parsers and state machines:

- **Packet injection**: Syzkaller's `syz_emit_ethernet` pseudo-syscall injects raw packets
- **Socket option fuzzing**: Extensive syzlang descriptions for `setsockopt`/`getsockopt`
  across all protocol families
- **Netfilter/nftables**: Fuzzing rule creation, packet matching, connection tracking
- **Custom harnesses**: Tools like Scapy can be used to craft protocol-specific packets for
  injection into a VM via a bridge or tap device

### 7.4 USB Subsystem Fuzzing

USB fuzzing is particularly productive due to the massive attack surface of USB device drivers:

- **Syzkaller's USB fuzzing**: Uses `syz_usb_connect`/`syz_usb_disconnect` pseudo-syscalls with
  gadget emulation to present fake USB devices to the kernel
- **KCOV remote coverage**: USB hub event handlers are kernel background tasks; KCOV's remote
  coverage API allows collecting coverage from these
- **USBFuzz**: Specialized USB fuzzer using device emulation

### 7.5 Device Driver Fuzzing

- **ioctl fuzzing**: Most drivers expose functionality through `ioctl()` calls. Write syzlang
  descriptions for the device's ioctl interface
- **DRM/GPU**: Complex subsystem with many ioctls; syzkaller has extensive DRM descriptions
- **Device files**: Open, read, write, mmap on `/dev/*` entries
- **sysfs/procfs**: Writing to sysfs/procfs entries can trigger driver code

### 7.6 BPF Verifier Fuzzing

The BPF subsystem has a complex verifier that checks safety of user-supplied programs:

- Syzkaller generates BPF programs (sequences of BPF instructions) and submits them via `bpf()`
- Custom fuzzers like **buzzer** (Google) specifically target the BPF verifier
- Focus areas: verifier bypass, JIT bugs, helper function interactions

### 7.7 Building a Custom Kernel Fuzzer

A typical custom kernel fuzzer involves:

```
1. Define the target interface (syscall, ioctl, file, etc.)
2. Implement a harness:
   - In-VM: C program that exercises the interface
   - Or: kernel module with a fuzzing entry point
3. Choose coverage mechanism:
   - KCOV for syscall-level coverage
   - Intel PT via kAFL for binary-level coverage
   - gcov for offline coverage analysis
4. Implement mutation strategy:
   - Structure-aware mutation based on input format
   - Or: byte-level mutation with AFL-style strategies
5. Implement feedback loop:
   - Execute input, collect coverage, add interesting inputs to corpus
6. Implement crash detection:
   - Monitor dmesg/console for KASAN/KMSAN/UBSAN/BUG/OOPS
   - Monitor for VM hangs/disconnects
```

### 7.8 Extending Syzkaller for Custom Targets

The most efficient approach is often to extend syzkaller rather than build from scratch:

1. Add new syzlang descriptions in `sys/linux/`
2. Implement pseudo-syscalls in `executor/common_linux.h` for complex setup sequences
3. Use `enable_syscalls` config to focus on your target
4. Monitor coverage via the web dashboard

---

## 8. Kernel Sanitizers as Bug Detectors During Fuzzing

Fuzzing finds bugs by triggering them, but many bugs (memory corruption, races, undefined
behavior) have no immediately visible symptoms. Kernel sanitizers are the critical detection
layer that turns silent corruption into loud, actionable crash reports.

### 8.1 KASAN: Kernel Address Sanitizer

**Purpose**: Detects out-of-bounds and use-after-free memory access bugs.

**How it works**: KASAN uses shadow memory to track the validity of each byte of kernel memory.
For every 8 bytes of kernel memory, 1 byte of shadow memory records whether the region is
accessible. Compiler instrumentation inserts checks (`__asan_load*`/`__asan_store*`) before every
memory access.

**Three modes**:

| Mode | Config | Platform | Overhead | Use Case |
|------|--------|----------|----------|----------|
| Generic | `CONFIG_KASAN_GENERIC` | x86_64, arm, arm64, ppc, riscv, s390, xtensa, loongarch | High (~2-3x slowdown, 1/8 memory overhead) | Debugging, fuzzing |
| SW Tag-Based | `CONFIG_KASAN_SW_TAGS` | arm64 only | Moderate | Dogfooding, testing |
| HW Tag-Based | `CONFIG_KASAN_HW_TAGS` | arm64 with MTE | Low | Production security |

**What it detects**:
- Slab out-of-bounds (read and write)
- Stack out-of-bounds
- Global variable out-of-bounds
- Use-after-free (slab, page)
- Double-free
- Use-after-scope (for stack variables)

**Quarantine**: Generic KASAN delays reuse of freed objects (quarantine in `mm/kasan/quarantine.c`)
to increase the window for detecting use-after-free bugs.

**Configuration for fuzzing**:
```
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y        # For maximum detection on x86_64
CONFIG_KASAN_INLINE=y         # Faster than outline, but larger binary
CONFIG_STACKTRACE=y           # Include alloc/free stack traces in reports
CONFIG_PAGE_OWNER=y           # Track page allocation stacks
```

**Example report header**:
```
BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc
Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
```

### 8.2 KMSAN: Kernel Memory Sanitizer

**Purpose**: Detects uses of uninitialized memory, preventing info-leak vulnerabilities.

**How it works**: KMSAN tracks initialization state via shadow memory (1 byte shadow per 1 byte
kernel memory) and origin tracking (4 bytes per 4 bytes to record where the uninitialized data
originated). Compiler instrumentation (Clang only, version 14.0.6+) propagates taint through
operations.

**What it detects**:
- Use of uninitialized stack variables
- Use of uninitialized heap allocations (allocated without `__GFP_ZERO`)
- Copy of uninitialized data to userspace (`copy_to_user` of uninit data = info leak)
- Use of uninitialized data in conditions, pointer dereferences, and function arguments

**Shadow states**:
- `0x00`: Initialized (safe)
- `0xff`: Uninitialized (poisoned)
- Intermediate values track partial initialization (e.g., bitwise OR of init and uninit values)

**Configuration**:
```
CONFIG_KMSAN=y                # Requires Clang 14.0.6+
                              # Only supports x86_64
                              # Cannot coexist with KASAN
```

**Overhead**: Significantly increases kernel memory footprint (~3x memory) and slows the system.
Not for production use; intended for testing and fuzzing.

### 8.3 KCSAN: Kernel Concurrency Sanitizer

**Purpose**: Detects data races -- concurrent unsynchronized memory accesses where at least one
is a write and at least one is a plain (unmarked) access.

**How it works**: KCSAN uses a watchpoint-based sampling approach:

1. For each instrumented memory access, check if a matching watchpoint exists (another CPU set one)
2. Periodically, set up a watchpoint on an access and stall for a small delay
3. If another CPU triggers the watchpoint during the delay, a race is detected
4. Also detects value-change races by comparing before/after values

**What it detects**:
- Data races between plain reads and writes
- Missing memory barriers (with `CONFIG_KCSAN_WEAK_MEMORY=y`, models load/store buffering)
- ASSERT_EXCLUSIVE_WRITER/ASSERT_EXCLUSIVE_ACCESS violations

**Configuration**:
```
CONFIG_KCSAN=y                # Requires GCC 11+ or Clang 11+
CONFIG_KCSAN_STRICT=y         # Strictest LKMM-following rules
CONFIG_KCSAN_WEAK_MEMORY=y    # Detect missing memory barriers
```

**Performance**: ~2.8-5x slowdown. Uses software "soft watchpoints" (no hardware debug
registers), making it portable and flexible.

### 8.4 UBSAN: Undefined Behavior Sanitizer

**Purpose**: Detects undefined behavior as defined by the C standard.

**How it works**: Compiler instrumentation inserts checks before operations that could cause UB.
If a check fails, `__ubsan_handle_*` functions are called to report the violation.

**What it detects**:
- Signed integer overflow
- Unsigned integer overflow (with specific config)
- Shift exponent out of bounds (too large for type)
- Out-of-bounds array indexing
- Misaligned pointer access (controlled by `CONFIG_UBSAN_ALIGNMENT`)
- Null pointer dereference (redundant with hardware, but catches some cases earlier)
- Unreachable code execution
- Invalid boolean/enum values

**Configuration**:
```
CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y         # Array bounds checking
CONFIG_UBSAN_SHIFT=y          # Shift bounds checking
CONFIG_UBSAN_DIV_ZERO=y       # Division by zero
CONFIG_UBSAN_BOOL=y           # Invalid bool values
CONFIG_UBSAN_ENUM=y           # Invalid enum values
# Note: CONFIG_UBSAN_ALIGNMENT is off by default on architectures
# with efficient unaligned access to avoid excessive reports
```

### 8.5 Additional Detection Mechanisms

| Mechanism | Config | What it Detects |
|-----------|--------|----------------|
| **KFENCE** | `CONFIG_KFENCE=y` | Lightweight sampling-based OOB/UAF detector for production |
| **Kmemleak** | `CONFIG_DEBUG_KMEMLEAK=y` | Memory leaks (unreferenced allocations) |
| **LOCKDEP** | `CONFIG_PROVE_LOCKING=y` | Deadlocks, lock ordering violations |
| **DEBUG_LIST** | `CONFIG_DEBUG_LIST=y` | Linked list corruption |
| **DEBUG_ATOMIC_SLEEP** | `CONFIG_DEBUG_ATOMIC_SLEEP=y` | Sleeping in atomic context |
| **DEBUG_SG** | `CONFIG_DEBUG_SG=y` | Scatter-gather list corruption |
| **KMEMLEAK** | `CONFIG_DEBUG_KMEMLEAK=y` | Kernel memory leaks |
| **Fault injection** | `CONFIG_FAULT_INJECTION=y` | Tests error handling paths |

### 8.6 Recommended Sanitizer Configuration for Fuzzing

For maximum bug detection during fuzzing, enable as many sanitizers as possible (noting that
KASAN and KMSAN are mutually exclusive):

**Primary configuration (KASAN-based)**:
```
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_KCSAN=y            # Note: some overhead interaction with KASAN
CONFIG_UBSAN=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_STACKTRACE=y
CONFIG_FAULT_INJECTION=y
CONFIG_FAILSLAB=y
CONFIG_FAIL_PAGE_ALLOC=y
```

**Alternative configuration (KMSAN-based)** for finding info-leak bugs:
```
CONFIG_KMSAN=y            # Mutually exclusive with KASAN
CONFIG_UBSAN=y
```

---

## 9. Setting Up a Kernel Fuzzing Lab

### 9.1 Hardware Requirements

A practical kernel fuzzing lab requires:

- **CPU**: Modern x86_64 with VT-x (all recent Intel/AMD CPUs). For kAFL, Intel Skylake or
  newer (for Intel PT). More cores = more parallel fuzzing instances
- **RAM**: Minimum 2GB per fuzzing VM instance. For KASAN-enabled kernels, VMs need more memory
  (2-4GB each). A 64GB host can run ~16-20 parallel instances
- **Storage**: SSD strongly recommended. Corpus and crash data can grow to many GB. Fast I/O
  reduces VM boot time
- **Network**: Fuzzing is CPU-bound; network requirements are minimal

### 9.2 Software Prerequisites

```bash
# Essential packages (Debian/Ubuntu)
sudo apt-get install -y \
    build-essential gcc g++ make \
    git subversion \
    golang-go \
    qemu-system-x86 \
    debootstrap \
    flex bison libssl-dev libelf-dev \
    clang llvm \
    gdb crash \
    python3 python3-pip

# For syzkaller specifically
go install github.com/google/syzkaller/...@latest
# Or clone and build:
git clone https://github.com/google/syzkaller.git
cd syzkaller && make
```

### 9.3 Building a Fuzz-Ready Kernel

**Step 1: Get the kernel source**
```bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux
```

**Step 2: Configure for fuzzing**

Start from a known config and enable required features:

```bash
make defconfig               # Or use a specific config
# Then enable fuzzing-critical options:
./scripts/config -e KCOV
./scripts/config -e KCOV_INSTRUMENT_ALL
./scripts/config -e KCOV_ENABLE_COMPARISONS
./scripts/config -e DEBUG_FS
./scripts/config -e DEBUG_INFO_DWARF4
./scripts/config -e KASAN
./scripts/config -e KASAN_GENERIC
./scripts/config -e KASAN_INLINE
./scripts/config -e CONFIGFS_FS
./scripts/config -e SECURITYFS
./scripts/config -e CMDLINE_BOOL
./scripts/config --set-str CMDLINE "net.ifnames=0"
./scripts/config -e FAULT_INJECTION
./scripts/config -e FAULT_INJECTION_DEBUG_FS
./scripts/config -e FAILSLAB
./scripts/config -e FAIL_PAGE_ALLOC
./scripts/config -e FAIL_FUTEX
./scripts/config -e FAIL_IO_TIMEOUT
./scripts/config -e FAIL_MAKE_REQUEST
./scripts/config -e LOCKDEP
./scripts/config -e PROVE_LOCKING
./scripts/config -e DEBUG_ATOMIC_SLEEP
./scripts/config -e DEBUG_LIST
./scripts/config -e UBSAN
./scripts/config -e UBSAN_BOUNDS
./scripts/config -e NAMESPACES
./scripts/config -e USER_NS
./scripts/config -e NET_NS
./scripts/config -e KCSAN     # Optional: data race detection
make olddefconfig
```

**Step 3: Build**
```bash
make -j$(nproc) CC=clang     # Clang recommended for best KCOV/sanitizer support
```

### 9.4 Creating a Disk Image

Syzkaller requires a disk image with SSH access for its VMs.

**Option 1: Buildroot image (recommended for syzbot compatibility)**
```bash
# Download pre-built
wget https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz
gunzip buildroot_amd64_2024.09.gz
```

**Option 2: Debian-based image with debootstrap**
```bash
# Using syzkaller's create-image.sh script
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
chmod +x create-image.sh
./create-image.sh
# Creates stretch.img and stretch.id_rsa
```

**Option 3: Minimal custom image**
```bash
# Create sparse image
dd if=/dev/zero of=rootfs.img bs=1M seek=2048 count=0
mkfs.ext4 rootfs.img
mkdir -p /tmp/mount
sudo mount -o loop rootfs.img /tmp/mount
sudo debootstrap --include=openssh-server,curl,gcc,make \
    bookworm /tmp/mount http://deb.debian.org/debian
# Configure SSH keys, root login, etc.
sudo umount /tmp/mount
```

### 9.5 QEMU Configuration

**Testing the kernel manually**:
```bash
qemu-system-x86_64 \
    -m 2G \
    -smp 2 \
    -kernel linux/arch/x86/boot/bzImage \
    -drive file=stretch.img,format=raw \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -net nic,model=e1000 \
    -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 \
    -enable-kvm \
    -nographic \
    -snapshot
```

### 9.6 Syzkaller Configuration

Create a configuration file (`syz-manager.cfg`):

```json
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "/path/to/workdir",
    "kernel_obj": "/path/to/linux",
    "image": "/path/to/stretch.img",
    "sshkey": "/path/to/stretch.id_rsa",
    "syzkaller": "/path/to/syzkaller",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": 4,
        "kernel": "/path/to/linux/arch/x86/boot/bzImage",
        "cpu": 2,
        "mem": 2048
    },
    "enable_syscalls": [
        "open", "read", "write", "close", "mmap",
        "ioctl$*"
    ]
}
```

**Start fuzzing**:
```bash
./bin/syz-manager -config syz-manager.cfg
```

**Monitor**: Open `http://127.0.0.1:56741` in a browser to see the dashboard with coverage
statistics, corpus size, crash reports, and per-subsystem coverage details.

### 9.7 Coverage Analysis

Syzkaller's web interface provides detailed coverage visualization:

- **Directory view**: Coverage percentage per kernel source directory
- **File view**: Coverage percentage per source file
- **Source view**: Color-coded source with coverage status:
  - **Black**: All PCs for this line are covered (with hit count)
  - **Orange**: Some PCs covered, some not
  - **Red**: Line is uncovered but function is executed
  - **Grey**: Function never executed or non-instrumented code

**Raw coverage export**:
```bash
# Download raw coverage data
wget http://localhost:56741/rawcover

# Generate HTML report
./bin/syz-cover --config syz-manager.cfg ./rawcover

# Export function coverage as CSV
./bin/syz-cover --config syz-manager.cfg --exports funccover ./rawcover

# Export line coverage as JSON
./bin/syz-cover --config syz-manager.cfg --exports json ./rawcover
```

---

## 10. Reproducing and Triaging Kernel Crashes from Fuzzers

### 10.1 Crash Artifacts

When a fuzzer finds a crash, the following artifacts are typically available:

| Artifact | Description |
|----------|-------------|
| **Console log** | Full kernel console output including crash dump |
| **Crash report** | Symbolized, post-processed crash report (e.g., KASAN report) |
| **Syz reproducer** | Syzkaller program in syz-format that triggers the crash |
| **C reproducer** | Standalone C program (if auto-generation succeeded) |
| **Kernel config** | `.config` used to build the crashing kernel |
| **Kernel commit** | Git commit hash of the kernel version |
| **Compiler info** | Exact compiler version used |

### 10.2 Automated Reproduction with syz-repro

Syzkaller's `syz-repro` tool automates crash reproduction:

```bash
./bin/syz-repro -config syz-manager.cfg crash-log-file
```

It performs:
1. **Program identification**: Tries each program from the crash log
2. **Minimization**: Removes unnecessary syscalls and simplifies arguments
3. **Mode reduction**: Tests if the crash needs threading/colliding
4. **C generation**: Converts the minimized syz program to standalone C code

### 10.3 Manual Reproduction

**Using a C reproducer from syzbot**:

```bash
# 1. Build the exact kernel
git checkout <commit-hash>
wget -O .config '<config-url>'
make CC=clang LD=ld.lld olddefconfig && make CC=clang LD=ld.lld -j$(nproc)

# 2. Get the disk image
wget https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz
gunzip buildroot_amd64_2024.09.gz

# 3. Build the reproducer
wget -O repro.c '<repro-url>'
gcc repro.c -lpthread -static -o repro

# 4. Boot VM
qemu-system-x86_64 -m 2G -smp 2,sockets=2,cores=1 \
    -drive file=buildroot_amd64_2024.09,format=raw \
    -net nic,model=e1000 \
    -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 \
    -enable-kvm -nographic -snapshot \
    -machine pc-q35-7.1

# 5. Copy and run reproducer
scp -P 10022 ./repro root@127.0.0.1:/root/
ssh -p 10022 root@127.0.0.1 'chmod +x ./repro && ./repro'
```

**Using a syz reproducer**:

```bash
# Copy syzkaller binaries and reproducer to VM
scp -P 10022 syzkaller/bin/linux_amd64/* repro.syz root@127.0.0.1:/root/

# Run with syz-execprog
ssh -p 10022 root@127.0.0.1 \
    './syz-execprog -enable=all -repeat=0 -procs=6 ./repro.syz'
```

Key `syz-execprog` flags:
- `-threaded`: Execute each syscall in a separate thread (default: true)
- `-procs N`: Number of parallel processes (default: 1)
- `-repeat N`: Repeat execution N times (0 = infinite)
- `-sandbox`: Sandboxing mode (none/setuid/namespace)
- `-debug`: Show detailed execution trace

### 10.4 Manual Crash Minimization

When `syz-repro` fails, minimize manually:

1. **Identify the crashing program**: Extract individual programs from the crash log and test each
   ```bash
   ./syz-execprog -executor=./syz-executor -repeat=0 -procs=8 -cover=0 crash-log.txt
   ```

2. **Remove syscalls**: Comment out individual lines with `#` and re-test

3. **Simplify arguments**: Replace complex data with `nil`:
   ```
   # Before:
   write(r0, &(0x7f0000001000)="73656c660041424300", 0x9)
   # After:
   write(r0, &(0x7f0000001000)=nil, 0x0)
   ```

4. **Coalesce mmap calls**: Merge multiple `mmap` calls into one that maps the whole required area

5. **Test without threading**: Try `-threaded=0` to simplify

6. **Convert to C**: Use `syz-prog2c` on the minimized program
   ```bash
   ./bin/syz-prog2c -prog repro.syz -enable=all > repro.c
   gcc repro.c -lpthread -static -o repro
   ```

### 10.5 Crash Triage Process

**Step 1: Classify the bug type**

Read the crash report and identify the category:

| Report Header | Bug Type | Severity |
|---------------|----------|----------|
| `BUG: KASAN: slab-out-of-bounds` | Out-of-bounds access | High |
| `BUG: KASAN: use-after-free` | Use-after-free | Critical |
| `BUG: KMSAN: uninit-value` | Uninitialized memory use | Medium-High |
| `BUG: KCSAN: data-race` | Data race | Medium |
| `UBSAN: shift exponent too large` | Undefined behavior | Low-Medium |
| `BUG: kernel NULL pointer dereference` | Null deref | Medium-High |
| `general protection fault` | Invalid memory access | High |
| `BUG: unable to handle page fault` | Invalid page access | High |
| `kernel BUG at ...` | BUG_ON assertion failure | High |
| `WARNING: ...` | WARN_ON trigger | Low-Medium |

**Step 2: Analyze the stack trace**

- Identify the function where the bug occurs
- Trace the call chain to understand how the code was reached
- Check if the bug is in a syscall handler, interrupt context, or worker thread
- Note the subsystem (from the file paths in the stack trace)

**Step 3: Determine exploitability**

Key questions for security assessment:
- Is the bug reachable from unprivileged userspace?
- Does it require specific namespace/capability?
- Is it a write primitive (OOB write, UAF write)?
- Can the attacker control the out-of-bounds offset or the use-after-free timing?
- Does it affect slab objects with useful kernel structures nearby?

**Step 4: Bisect to the introducing commit**

```bash
# Automated bisection (syzkaller provides syz-bisect)
./bin/syz-bisect -config syz-manager.cfg -crash crash-dir/

# Manual bisection
git bisect start
git bisect bad <crashing-commit>
git bisect good <known-good-commit>
# Build, boot, test reproducer, mark good/bad, repeat
```

**Step 5: Root cause analysis**

- Read the buggy function source code carefully
- Identify the specific code path triggered by the reproducer
- Understand the data flow: how does user input reach the vulnerable operation?
- Check for missing bounds checks, missing locks, missing refcount increments, etc.
- Consider whether the fix should be in the specific subsystem or in a shared infrastructure

### 10.6 Crash Deduplication

Syzkaller deduplicates crashes using crash description strings extracted by regex-based parsers.
However, duplicates can still occur:

- Same bug triggered via different code paths
- Different bugs with similar crash signatures
- Same root cause manifesting as different bug types (e.g., a missing lock causing both a data
  race and a use-after-free)

Manual deduplication involves:
- Comparing the crashing function and call stack
- Checking if the same source line is involved
- Testing if one fix resolves multiple crash reports

### 10.7 Using ktest for Automated Reproduction

The `ktest` tool automates the entire reproduction process for syzbot bugs:

```bash
git clone git://evilpiepirate.org/ktest.git
cd ktest
sudo ./root_image init && sudo ./root_image create
cargo install --path .

# Reproduce a syzbot bug by its ID
cd ~/linux
git checkout <kernel-commit>
ktest/build-test-kernel run ktest/tests/syzbot-repro.ktest <bug-id>
```

Where `<bug-id>` is extracted from the syzbot dashboard link (e.g., `2159cbb522b02847c053`).

### 10.8 Common Pitfalls in Crash Reproduction

| Issue | Cause | Solution |
|-------|-------|----------|
| Crash doesn't reproduce | Race condition / timing dependent | Increase `-procs`, run longer, add stress-ng |
| Crash only in threaded mode | Inter-thread dependency | Keep `-threaded=1`, try different `-procs` values |
| Crash only with KASAN | Bug is memory corruption caught by sanitizer | Must use KASAN-enabled kernel |
| Different crash on reproduction | Original bug masked another | Analyze both crashes separately |
| Crash requires specific hardware | Hardware-dependent code path | Use appropriate QEMU device emulation flags |
| VM hangs instead of crashing | Kernel deadlock or infinite loop | Use NMI watchdog, add `-no-reboot` to QEMU |
| Only syz repro available | C conversion failed | Use `syz-execprog` directly, or manually convert |

---

## References

### Tools and Projects
- **Syzkaller**: https://github.com/google/syzkaller
- **Syzbot Dashboard**: https://syzkaller.appspot.com
- **kAFL**: https://github.com/IntelLabs/kAFL
- **kAFL Documentation**: https://intellabs.github.io/kAFL/
- **HEALER**: https://github.com/SunHao-0/healer
- **Trinity**: https://github.com/kernelslacker/trinity
- **Nyx Fuzzing Framework**: https://nyx-fuzz.com

### Kernel Documentation
- **KCOV**: https://www.kernel.org/doc/html/latest/dev-tools/kcov.html
- **KASAN**: https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
- **KMSAN**: https://www.kernel.org/doc/html/latest/dev-tools/kmsan.html
- **KCSAN**: https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html
- **UBSAN**: https://www.kernel.org/doc/html/latest/dev-tools/ubsan.html
- **KFENCE**: https://www.kernel.org/doc/html/latest/dev-tools/kfence.html

### Academic Papers
- Vyukov, D. "Syzkaller: Linux Kernel Fuzzer" -- Google, 2015+
- Schumilo, S. et al. "kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels" -- USENIX Security 2017
- Schumilo, S. et al. "Nyx: Greybox Hypervisor Fuzzing using Fast Snapshots and Affine Types" -- USENIX Security 2021
- Sun, H. et al. "HEALER: Relation Learning Guided Kernel Fuzzing" -- SOSP 2021
- Aschermann, C. et al. "Redqueen: Fuzzing with Input-to-State Correspondence" -- NDSS 2019
- Pailoor, S. et al. "MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation" -- USENIX Security 2018
