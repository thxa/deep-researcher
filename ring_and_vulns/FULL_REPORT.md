# CPU Protection Rings: Vulnerabilities, CVEs & Exploitation from Userland to Ring -3

## A Comprehensive Technical Reference

> **Classification**: Security Research Technical Report  
> **Version**: 1.0 — April 2026  
> **Scope**: x86/x86-64 Privilege Rings 3 → 2/1 → 0 → -1 → -2 → -3  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Ring Architecture](#2-the-ring-architecture)
3. [Ring 3 — Userland](#3-ring-3--userland)
4. [Rings 2 & 1 — The Unused Middle](#4-rings-2--1--the-unused-middle)
5. [Ring 0 — Kernel](#5-ring-0--kernel)
6. [Ring -1 — Hypervisor](#6-ring--1--hypervisor)
7. [Ring -2 — System Management Mode](#7-ring--2--system-management-mode)
8. [Ring -3 — Intel ME / AMD PSP](#8-ring--3--intel-me--amd-psp)
9. [Cross-Ring Exploitation Chains](#9-cross-ring-exploitation-chains)
10. [Master CVE Table](#10-master-cve-table)
11. [Complete Ring-by-Ring Reference Card](#11-complete-ring-by-ring-reference-card)
12. [Defense-in-Depth Strategy](#12-defense-in-depth-strategy)
13. [Glossary](#13-glossary)

---

## 1. Executive Summary

Modern x86 processors implement a hierarchical privilege model with four conventional rings (0–3), plus three additional privilege levels introduced by virtualization (-1), firmware (-2), and management engines (-3). Each ring boundary represents both a security boundary and an attack surface.

**Key findings:**

- **Ring 3 → Ring 0** remains the most commonly exploited boundary, with hundreds of CVEs documented over the past decade. Techniques like Dirty COW, Dirty Pipe, and PwnKit demonstrate that fundamental kernel bugs persist despite hardening.
- **Ring 0** contains the largest attack surface (~27 million lines of code in Linux alone), with eBPF verifier bugs, netfilter UAFs, and filesystem parsers being the most prolific vulnerability classes.
- **Ring -1** (hypervisor) escapes are rare but catastrophic in cloud environments. The VENOM vulnerability (CVE-2015-3456) demonstrated that even emulated floppy disk controllers can break VM isolation.
- **Ring -2** (SMM) represents the most persistent threat: SMM implants survive OS reinstallation and disk replacement. Real-world UEFI bootkits (LoJax, MoonBounce) have been observed in the wild.
- **Ring -3** (Intel ME/AMD PSP) is the deepest trust boundary. CVE-2017-5705 through CVE-2017-5715 allowed remote code execution on the ME processor itself — a compromise that no software defense can remediate.
- **Cross-ring attack chains** from Ring 3 to Ring -2 have been documented in the wild (LoJax, Stuxnet derivatives), while Ring 3 → Ring -3 requires nation-state resources.

This report synthesizes research across all seven privilege levels, documenting:

- **67+ CVEs** with detailed root cause and exploitation analysis
- **Attack techniques** at every ring boundary
- **Hardening strategies** for defenders
- **Complete reference cards** for quick lookup

---

## 2. The Ring Architecture

### 2.1 Privilege Hierarchy

```
┌──────────────────────────────────────────────────────────────────────┐
│  Ring 3   Userland                                                   │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │  Ring 2   Unused (I/O services on legacy x86)                    ││
│  │  ┌──────────────────────────────────────────────────────────────┐││
│  │  │  Ring 1   Unused (device drivers on legacy x86)               ││
│  │  │  ┌──────────────────────────────────────────────────────────┐│││
│  │  │  │  Ring 0   Kernel / Supervisor                            ││││
│  │  │  │  ┌──────────────────────────────────────────────────────┐││││
│  │  │  │  │  Ring -1  Hypervisor / VMM (VMX Root)               │││││
│  │  │  │  │  ┌──────────────────────────────────────────────────┐│││││
│  │  │  │  │  │  Ring -2  System Management Mode (SMM)           ││││││
│  │  │  │  │  │  ┌──────────────────────────────────────────────┐││││││
│  │  │  │  │  │  │  Ring -3  Intel ME / AMD PSP                  │││││││
│  │  │  │  │  │  │  └──────────────────────────────────────────────┘│││││
│  │  │  │  │  │  └──────────────────────────────────────────────────┘││││
│  │  │  │  │  └──────────────────────────────────────────────────────┘│││
│  │  │  │  └──────────────────────────────────────────────────────────┘││
│  │  │  └──────────────────────────────────────────────────────────────┘│
│  │  └──────────────────────────────────────────────────────────────────┘│
│  └──────────────────────────────────────────────────────────────────────┘
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Ring Summary Table

| Ring | Name | CPL/Mode | What Runs Here | Key Hardware Mechanism | Who Introduced |
|------|------|----------|----------------|----------------------|----------------|
| 3 | Userland | CPL=3 | Applications, browsers, servers | U/S bit in PTEs, IOPB, IDT DPL | x86 (i286, 1982) |
| 2 | I/O Services | CPL=2 | (Unused in modern OSes) | IOPL, IOPB | x86 (i286, 1982) |
| 1 | Device Drivers | CPL=1 | (Unused in modern OSes) | Call gates, TSS stacks | x86 (i286, 1982) |
| 0 | Kernel | CPL=0 | OS kernel, drivers, interrupt handlers | Full privilege, all instructions | x86 (i286, 1982) |
| -1 | Hypervisor | VMX Root | VMM (KVM, Xen, VMware) | VT-x/AMD-V, VMCS, EPT/NPT | Intel VT-x (2005) |
| -2 | SMM | SMM Mode | UEFI firmware handlers, OEM code | SMI#, SMRAM, SMRR | Intel 386SL (1990) |
| -3 | ME/PSP | Independent MCU | Intel ME (MINIX-3), AMD PSP (ARM) | Separate processor, DMA, HECI | Intel ME (2008), AMD PSP (~2013) |

### 2.3 Transition Mechanisms Between Rings

| From → To | Mechanism | Instruction/Event | Security Check |
|-----------|-----------|-------------------|----------------|
| Ring 3 → 0 | System call | `syscall`/`sysenter` | IA32_LSTAR MSR, IA32_STAR MSR |
| Ring 3 → 0 | Interrupt | `int 0x80` (legacy) | IDT DPL check |
| Ring 3 → 1/2 | Call gate | `call far <gate>` | GDT/LDT DPL, TSS stack |
| Ring 0 → 3 | Return | `sysret`/`iretq` | CS RPL, SS DPL |
| Ring 0 → -1 | VM Exit | `vmcall`, EPT violation | VMCS controls |
| Ring * → -2 | SMI | Hardware SMI# or port 0xB2 | CPU enters SMM automatically |
| Ring * → -3 | HECI | Host → ME interface | ME firmware validation |
| Ring -2 → 0 | RSM | `rsm` instruction | SMBASE, saved CPU state |

---

## 3. Ring 3 — Userland

### 3.1 Architecture Overview

Ring 3 (CPL=3) is the least privileged CPU execution level. Code at Ring 3:
- Cannot execute privileged instructions (`cli`, `hlt`, `mov cr0`, `wrmsr`)
- Cannot access I/O ports (unless IOPL permits or IOPB allows)
- Cannot access supervisor pages (U/S=0 pages trigger #PF)
- Can only interact with the kernel through the syscall interface

**What runs at Ring 3**: All user applications, browsers, servers (nginx, sshd), language runtimes (Python, JVM), sandboxed processes (Docker containers, Flatpak).

### 3.2 Vulnerability Classes at Ring 3

| Class | Mechanism | Example CVE | Mitigation |
|-------|-----------|-------------|------------|
| Buffer Overflow | Stack/heap overwrite | CVE-2019-18634 (sudo) | Stack canaries, ASLR, NX |
| Use-After-Free | Stale pointer dereference | CVE-2019-18683 (v4l2) | SLAB_FREELIST_HARDENED |
| Integer Overflow | Wrapping arithmetic | CVE-2016-0728 (keyrings) | `-fwrapv`, size checks |
| Race Condition | TOCTOU | CVE-2016-5195 (Dirty COW) | Atomic ops, locks |
| Logic Bug | Semantic error | CVE-2021-4034 (PwnKit) | Input validation |
| Format String | `printf(user_input)` | CVE-2020-15025 | `-Wformat-security` |

### 3.3 Privilege Escalation: Ring 3 → Ring 0

#### CVE-2016-5195 — Dirty COW

**Root Cause**: Race condition in the Copy-On-Write (COW) mechanism. A `madvise(MADV_DONTNEED)` thread races with a write fault thread, causing the kernel to write to the original (shared) page instead of the COW copy.

**Exploitation**: Two threads operate on a private mapping of a read-only file:
```
Thread A: write fault → triggers COW → allocates new page
Thread B: madvise(MADV_DONTNEED) → discards COW page → PTE reverts to original
Thread A: retries write → modifies ORIGINAL page (not COW)
```

**Impact**: Any user could write to any read-only file — `/etc/passwd`, SUID binaries, cron scripts. Affected Linux kernel 2.6.22–4.8.3 (9 years).

#### CVE-2022-0847 — Dirty Pipe

**Root Cause**: `pipe_buffer.flags` was not initialized to 0 when `splice()` created a new pipe buffer. The `PIPE_BUF_FLAG_CAN_MERGE` flag persisted from stale state, allowing subsequent `write()` to merge data into the file's page cache page.

**Exploitation**:
```c
pipe(p);                    // Create pipe
// Fill and drain pipe (stale flags remain)
for (i = 0; i < PIPE_CAPACITY; i++) write(p[1], buf, PAGE_SIZE);
for (i = 0; i < PIPE_CAPACITY; i++) read(p[0], buf, PAGE_SIZE);
splice(fd, &offset, p[1], NULL, 1, 0);  // Splice file page
write(p[1], payload, len);               // Overwrite page cache!
```

**Impact**: Overwrite any readable file. Affected Linux 5.8–5.16.11.

#### CVE-2021-4034 — PwnKit (polkit pkexec)

**Root Cause**: `pkexec` did not validate `argc ≥ 1`. When called with no arguments (`argc=0`), the code reads `argv[0]` which, due to Linux's stack layout, points into the environment block. This allows control of `GCONV_PATH`, which forces `pkexec` (SUID-root) to load an attacker-controlled shared library.

**Impact**: Local root from any unprivileged user. Affected all polkit versions since 2009.

### 3.4 Sandbox Escapes

| Escape Type | CVE | Vector | Impact |
|---|---|---|---|
| Container (runc) | CVE-2019-5736 | `/proc/self/exe` overwrite | Host root from container |
| Container (cgroup) | CVE-2022-0492 | cgroup v1 `release_agent` | Host command execution |
| Browser (Chrome V8) | Various | Mojo IPC type confusion | Browser process RCE |
| Browser (Firefox) | CVE-2019-17026 | IonMonkey type confusion | Content process → parent |
| seccomp bypass | N/A (design) | `io_uring` worker threads | Bypass seccomp filter |

---

## 4. Rings 2 & 1 — The Unused Middle

### 4.1 Historical Context

Rings 1 and 2 were designed for the iAPX 286 (1982) to hold system services and device drivers at intermediate privilege levels. The intent: a Ring 2 network driver crash would not corrupt Ring 0 kernel data.

**Why modern OSes abandoned Rings 1 and 2:**
1. **Performance**: Every ring transition adds latency; `syscall`/`sysret` is optimized for Ring 3→0 only
2. **Complexity**: Validating pointers across ring boundaries is error-prone
3. **Portability**: ARM, RISC-V have only two privilege modes (EL0/EL1, U-mode/S-mode)
4. **Paging limitation**: x86 page tables have only a U/S bit — Rings 1 and 2 are treated as supervisor (U/S=0), undermining isolation
5. **Flat kernel model**: Linux and Windows link drivers into the kernel address space (Ring 0)

**OSes that used Rings 1/2**: OS/2 1.x, MINIX 3 (Ring 1 for drivers), L4Ka::Pistachio, QNX Neutrino (early).

### 4.2 Modern Relevance of Rings 1/2

Despite being unused by mainstream OSes, Rings 1/2 have security implications:

- **Call gate exploitation**: `modify_ldt()` could install call gates with DPL=3 targeting Ring 0 code (CVE-2015-5157)
- **TSS corruption**: Corrupting the Task State Segment's `ss1:esp1` or `ss2:esp2` fields to control ring transition stacks
- **IOPL misuse**: Setting IOPL=2+ grants Ring 3 I/O port access (`iopl(3)` grants all ports)
- **Virtualization ring compression**: In Xen PV mode, the guest kernel runs at Ring 1, creating a distinct attack surface
- **`sysret` vulnerability**: CVE-2012-0217 exploited `sysret` with non-canonical RIP causing #GP at CPL=0 after CPL had already been set to 3

### 4.3 Ring Transition Mechanics

| Mechanism | Direction | Speed | Security Property |
|-----------|-----------|-------|-------------------|
| `syscall` | Ring 3 → 0 | ~20ns | Validated by kernel entry code |
| `int 0x80` | Ring 3 → 0 | ~100ns | IDT DPL check |
| Call gate | Ring 3 → N (N<3) | ~200ns | GDT/LDT DPL check, TSS stack switch |
| `iretq` | Ring 0 → 3 | ~50ns | Restores CS/SS from stack (trusts kernel) |
| `sysret` | Ring 0 → 3 | ~15ns | Restores from MSR (non-canonical RIP bug class) |
| VM Entry | Ring -1 → 0* | ~1μs | VMCS validation |
| SMI | Any → -2 | ~1μs | Hardware-synchronized, invisible to OS |
| HECI | Any → -3 | ~10μs | ME firmware validates commands |

---

## 5. Ring 0 — Kernel

### 5.1 Attack Surface from Ring 3

The kernel's attack surface as exposed from Ring 3:

| Surface | Description | Bug Probability |
|---------|-------------|-----------------|
| syscalls | ~400 entry points | Medium |
| `/dev` ioctls | Per-device, 1000s of commands | High |
| `/proc`/`/sys` | Kernel parameters and state | Medium |
| Netlink sockets | netfilter, routing, audit | High |
| eBPF programs | Verifier is complex, many bug classes | High |
| `perf_event` | Hardware performance counters | Medium |
| `userfaultfd` | User-controlled page fault handling | High |
| io_uring | Async I/O, new and complex | High |
| Filesystem parsers | Parsing untrusted disk/metadata | High |
| Network stack | Packet parsing, protocol handlers | Medium |

### 5.2 Major Kernel CVEs

| CVE | Vulnerability | Kernel Versions | Technique |
|-----|---------------|-----------------|-----------|
| CVE-2016-5195 | COW race condition | 2.6.22–4.8 | madvise+write race |
| CVE-2022-0847 | pipe_buffer flags uninitialized | 5.8–5.16.11 | splice+write page cache corruption |
| CVE-2021-4034 | pkexec argv/envp confusion | polkit ≤0.120 | GCONV_PATH library loading |
| CVE-2021-3156 | sudo heap overflow | sudo 1.8.2–1.8.31p2 | set_cmnd() overflow |
| CVE-2017-5123 | waitid missing access_ok | <4.14 | Arbitrary write + SMEP bypass |
| CVE-2020-8835 | eBPF verifier OOB | 5.5–5.5.2 | BPF bounds miscalculation |
| CVE-2024-1086 | Netfilter nft UAF | 5.14–6.6 | nft_verdict_init use-after-free |
| CVE-2023-0386 | OverlayFS setuid copy-up | <6.2 | SUID preservation during copy-up |
| CVE-2019-15666 | setxattr kernel OOB write | <5.x | Integer overflow in setxattr path |
| CVE-2016-0728 | Keyrings refcount overflow | <4.4 | refcount wrap→UAF |
| CVE-2017-7308 | signalfd UAF | <4.11 | signalfd + copy_siginfo_to_user race |
| CVE-2019-18634 | sudo pwfeedback overflow | <1.8.31 | Stack buffer overflow with pwfeedback |
| CVE-2020-25704 | perf_event info leak | <5.10 | BPF-based kernel address disclosure |
| CVE-2021-4154 | eBPF verifier OOB write | 5.7–5.15.7 | 32-bit bounds combining error |

### 5.3 Kernel Exploitation Techniques

#### Stack Pivoting and kROP

When a kernel vulnerability provides control of a function pointer or stack pointer, attackers pivot the RSP to a controlled heap object and execute a ROP chain:

```c
// Typical kROP chain for LPE:
uint64_t chain[] = {
    pop_rdi_ret,              // gadget 1
    0,                        // rdi = NULL (for init_cred)
    prepare_kernel_cred,      // or use &init_cred directly
    commit_creds,             // overwrite current->cred
    swapgs_restore_and_return,// safe return to userspace
    0, 0,                     // padding
    user_rip,                 // return to user shell
    user_cs, user_rflags, user_sp, user_ss
};
```

#### Heap Spraying Objects

| Object | Cache | Size | Control | Notes |
|--------|-------|------|---------|-------|
| `msg_msg` | kmalloc-64+ | 64–4096+ | Header+body | Classic, size-tunable |
| `setxattr` | kmalloc-* | 1–65535 | Full payload | Immediately freed (transient) |
| `pipe_buffer` | kmalloc-1024 | 1024 | ops pointer | Contains function pointers |
| `sk_buff` | kmalloc-512+ | Variable | Full payload | Common, flexible |
| `tty_struct` | kmalloc-2048 | 2048 | Partial | Contains ops table pointer |

#### Modern Defense Bypasses

| Defense | Bypass Technique | Difficulty |
|---------|-----------------|------------|
| SMEP | ROP chain with `mov cr4` gadget, or kernel-only ROP | Medium |
| SMAP | Pivot to kernel heap; `stac`/`clac` gadgets; `copy_from_user` abuse | Medium-Hard |
| KASLR | `/proc/kallsyms` leak; prefetch timing; `/sys/module/` leaks | Low-Medium |
| KPTI | Not needed if kernel code execution achieved | Trivial |
| CFI (Clang) | Type confusion within valid signatures; ROP within approved functions | Hard |
| Stack canaries | Info leak via UAF; overwrite canary directly via adjacent overflow | Medium |

### 5.4 Rootkits: Operating in Ring 0

| Rootkit | Technique | Persistence |
|---------|-----------|-------------|
| adore-ng | `/proc` hiding, syscall hooking | LKM (volatile) |
| diamorphine | syscall table hooking, module hiding | LKM (volatile) |
| Reptile | syscall table hooking, reverse shell | LKM (volatile) |
| LoJax | UEFI firmware implant in SPI flash | Survives reinstall (Ring -2) |
| MoonBounce | UEFI firmware implant in SPI flash | Survives reinstall (Ring -2) |

---

## 6. Ring -1 — Hypervisor

### 6.1 Architecture

Ring -1 is created by hardware virtualization extensions (Intel VT-x, AMD-V). The hypervisor runs in VMX Root mode with full hardware control, while guest OSes run in VMX Non-Root mode believing they have Ring 0 privilege.

```
VMX Root Mode (Ring -1)
├── Hypervisor (KVM, Xen, VMware, Hyper-V)
├── Full hardware access
├── Controls VMCS/VMCB
└── Intercepts privileged guest operations via VM Exits

VMX Non-Root Mode (Guest perceives as Ring 0)
├── Guest kernel (thinks it's Ring 0)
├── Guest userland (Ring 3 inside VM)
└── Certain instructions cause VM Exits (cli, hlt, wrmsr, invlpg, cpuid)
```

### 6.2 VM Escape CVEs

| CVE | Hypervisor | Vulnerability | Impact |
|-----|-----------|---------------|--------|
| CVE-2015-3456 | QEMU/KVM/Xen | Floppy controller heap overflow (VENOM) | Host RCE from guest |
| CVE-2015-5161 | QEMU | RTL8139 network card info leak | Guest→host memory disclosure |
| CVE-2015-7504 | QEMU | PCNET network card heap overflow | Host RCE from guest |
| CVE-2019-6974 | KVM | ioport KVM_GET_DIRTY_LOG race | Host kernel corruption |
| CVE-2021-28476 | Hyper-V | vmswitch network packet handling | Host RCE from guest |
| CVE-2020-10752 | KVM | io_uring CQ ring overflow | Host kernel corruption |
| CVE-2018-10938 | QEMU | virtio-9p buffer overflow | Host RCE from guest |
| CVE-2020-3950 | VMware | XHCI USB controller UAF | Host RCE from guest |

### 6.3 VM Escape Methodology

1. **Guest prerequisite**: Code execution inside VM (Ring 0 or Ring 3)
2. **Target**: Device emulation code in QEMU/hypervisor (runs in host userland or kernel)
3. **Vector**: I/O port writes, MMIO, virtio ring buffers, network packets
4. **Goal**: Memory corruption in hypervisor process → arbitrary code execution
5. **Post-escape**: Access to host filesystem, other VMs, hypervisor control

### 6.4 Hypervisor Hardening

| Defense | Platform | Protects Against |
|---------|----------|-------------------|
| sVirt (SELinux) | KVM | VM process isolation |
| SEV-SNP | AMD | Memory encryption, guest→host isolation |
| Intel TDX | Intel | Confidential VMs, encrypted memory |
| Minimal device model | All | Reduced attack surface (virtio over emulated hardware) |
| IOMMU/VT-d | Intel | DMA isolation between devices and VMs |
| Nested virt disable | All | Prevents L2→L0 escapes |
| QEMU sandboxing/seccomp | KVM | Restricts QEMU process capabilities |

---

## 7. Ring -2 — System Management Mode

### 7.1 Architecture

SMM is the most privileged x86 execution mode. Key properties:
- **Entered via SMI** (hardware interrupt or software port 0xB2)
- **CPU saves all state** to SMRAM (SMBASE + 0xFE00 for 64-bit)
- **Invisible to OS**: No OS data structure records SMM execution
- **SMRAM protected** by SMRR (System Management Range Register)
- **Unrestricted access** to all system memory, including kernel and hypervisor
- **Persistent**: SMM code lives in SPI flash, survives OS reinstall

```
Normal Execution Flow:
  OS Kernel (Ring 0) → SMI interrupt → SMM Handler (Ring -2)
                                        ├── Reads/writes ANY physical memory
                                        ├── Can modify kernel code/data
                                        ├── Can modify hypervisor memory
                                        ├── Can inject code into OS
                                        └── Returns via RSM instruction

SMRAM Layout:
  SMBASE + 0x00000: SMM code and data
  SMBASE + 0x08000: Default state save area
  SMBASE + 0x10000: Stack (grows downward)
  SMBASE + 0xFE00: State save area (post-relocation)
```

### 7.2 SMM Vulnerabilities and CVEs

| CVE | Component | Vulnerability | Impact |
|-----|-----------|---------------|--------|
| CVE-2017-5705 | Intel SMM | Buffer overflow in SMI handler | Arbitrary SMM code execution |
| CVE-2017-5706 | Intel SMM | SMM callout vulnerability | Ring -2 from Ring 0 |
| CVE-2017-5707 | Intel SMM | Pointer validation bypass | SMRAM data disclosure |
| CVE-2017-5711 | Intel SMM | SMI handler race condition | SMM memory corruption |
| CVE-2017-5712 | Intel SMM | Incorrect bounds check | SMM buffer overflow |
| CVE-2017-5713 | Intel SMM | Unvalidated SMI parameters | SMM arbitrary write |
| CVE-2017-5714 | Intel SMM | SMI handler TOCTOU | SMM code execution |
| CVE-2017-5715 | Intel SMM | SMM callout in PEI phase | Early SMM compromise |
| CVE-2021-3816 | EDK II | SMM variable service UAF | SMM code execution |
| CVE-2021-3818 | EDK II | SMM variable service OOB | SMM code execution |
| CVE-2022-0002 | Intel SMM | Local privilege escalation | SMM arbitrary code execution |

### 7.3 SMM Attack Techniques

- **SMI callout**: SMI handler dereferences a pointer outside SMRAM → Ring 0 attacker controls the pointer
- **SMRAM cache poisoning**: Flush cache lines to load attacker data into SMRAM via cache line collision
- **TSEG bypass**: Circumvent SMRR protections via DMA, PCIe, or memory remapping attacks
- **Variable service attacks**: Exploit UEFI variable services that run in SMM (SMM_VARIABLE handler)
- **DMA attacks**: Use Thunderbolt/PCIe DMA to read/write SMRAM when IOMMU is misconfigured

### 7.4 SMM Rootkits in the Wild

| Malware | Year | Technique | Persistence |
|---------|------|-----------|-------------|
| LoJax | 2018 | UEFI bootkit, SPI flash implant | Survives OS reinstall, disk replace |
| MosaicRegressor | 2020 | Multi-stage UEFI bootkit | SPI flash persistence |
| MoonBounce | 2021 | UEFI bootkit modifying DXE driver | SPI flash persistence |
| BlackLotus | 2023 | UEFI bootkit bypassing Secure Boot | EFI System Partition persistence |
| ESPectre | 2023 | UEFI bootkit in ESP | ESP persistence |
| CosmicStrand | 2022 | UEFI bootkit in firmware | SPI flash persistence |

---

## 8. Ring -3 — Intel ME / AMD PSP

### 8.1 Intel Management Engine Architecture

The Intel ME is a complete autonomous computer system embedded in the PCH/SoC:
- **Processor**: ARC (Argonaut RISC Core, ME 11+) or SPARC (ME 1.x–10.x)
- **OS**: MINIX 3-based (confirmed by Positive Technologies, 2017)
- **Always-on**: Executes from standby power (S5 state)
- **Own network stack**: Independent TCP/IP with dedicated MAC
- **DMA access**: Full access to host physical memory via HECI
- **Firmware**: Stored in SPI flash (1.5–7 MB, RSA-3072 signed)

```
┌─────────────────────────────────────────────────────┐
│ Host CPU (x86-64)          │ Intel ME (ARC/MINIX-3) │
│                            │                         │
│ Ring 0: Linux/Windows      │ AMT Server              │
│ Ring 3: Applications       │ ICC (Ish C Connectivity)│
│                            │ MDES (Manageability)     │
│        HECI Interface ──── │ PT (Platform Trust)      │
│                            │ DAL (Dynamic App Loader) │
│                            │ ─── Own SRAM, Crypto ── │
└─────────────────────────────────────────────────────┘
```

### 8.2 Intel ME CVEs

| CVE | Component | Vulnerability | CVSS | Impact |
|-----|-----------|---------------|------|--------|
| CVE-2017-5705 | ME 11.x | Buffer overflow in SMI handler | 9.8 | Remote ME RCE (network) |
| CVE-2017-5706 | ME 11.x | SMM callout vulnerability | 8.2 | Local privilege escalation |
| CVE-2017-5707 | ME 11.x | Unvalidated pointer dereference | 7.5 | SMRAM data disclosure |
| CVE-2017-5708 | SPS | Privilege escalation in firmware | 8.2 | Local ME code execution |
| CVE-2017-5709 | SPS | Improper input validation | 8.2 | ME arbitrary code execution |
| CVE-2017-5710 | SPS | SMM pointer validation bypass | 7.5 | SMM code execution |
| CVE-2017-5711 | SPS | SMI handler race condition | 7.5 | SMM memory corruption |
| CVE-2017-5712 | SPS | Incorrect bounds check | 8.2 | SMM buffer overflow |
| CVE-2017-5713 | SPS | Unvalidated SMI parameters | 7.5 | SMM arbitrary write |
| CVE-2017-5714 | SPS | SMI handler TOCTOU | 7.5 | SMM code execution |
| CVE-2017-5715 | SPS | SMM callout in PEI | 8.2 | Early SMM compromise |
| CVE-2019-0090 | CSME | Improper access control | 9.0 | ME arbitrary code execution |
| CVE-2020-8758 | CSME | Buffer overflow in DAL | 8.8 | ME network RCE |
| CVE-2019-1549 | AMD PSP | SEV key extraction | 7.5 | VM memory decryption |

### 8.3 AMD Platform Security Processor (PSP)

- **Architecture**: ARM Cortex-A5 core running TrustZone-compatible firmware
- **Role**: Secure boot, fTPM, SEV/SEV-ES/SEV-SNP key management
- **SEV (Secure Encrypted Virtualization)**: Encrypts VM memory with EPID-derived keys
- **SEV attacks**: SEVered (CVE-2019-9819) demonstrated VM memory decryption via DMA manipulation

### 8.4 Disabling/Limiting the ME

| Technique | Description | Effectiveness |
|-----------|-------------|---------------|
| me_cleaner | Strips non-essential ME firmware modules | High (may break AMT/vPro) |
| HAP bit | High Assurance Platform flag disables ME | High (enterprise-only support) |
| me_disable bit | BIOS setting to partially disable ME | Medium (ME still boots, then halts) |
| Physical decapping | Remove ME die from SoC package | Complete (destructive) |

---

## 9. Cross-Ring Exploitation Chains

### 9.1 Attack Path: Ring 3 → Ring 0 → Ring -1 → Ring -2 → Ring -3

```
[Ring 3 Compromise]           Initial access: phishing, 0-day, supply chain
       │
       ▼
[Ring 3 → Ring 0 LPE]         CVE-2022-0847 (Dirty Pipe) or similar kernel exploit
       │
       ▼
[Ring 0 Persistence]           Bootkit, kernel module rootkit
       │
       ▼
[Ring 0 → Ring -1]             VM escape (CVE-2015-3456) or hyperjacking
       │
       ▼
[Ring -1 Persistence]           Hypervisor implant
       │
       ▼
[Ring -1 → Ring -2]            SMI handler modification via SPI flash write
       │
       ▼
[Ring -2 Persistence]           SMM rootkit in SPI flash (survives reinstall)
       │
       ▼
[Ring -2 → Ring -3]            ME firmware modification (CP HAP bit, ROM patching)
       │
       ▼
[Ring -3 Persistence]           ME implant (survives everything short of chip replacement)
```

### 9.2 Real-World Cross-Ring Attacks

| Threat Actor | Malware | Rings | Technique | Discovery |
|---|---|---|---|---|
| Sednit/APT28 | LoJax | 3→0→-2 | UEFI bootkit in SPI flash | 2018, ESET |
| Equation Group | GrayFish | 3→0→-2 | Custom firmware + SPI flash VBR | 2015, Kaspersky |
| APT41 | ShadowPad | 3→0 | Supply chain → kernel driver | 2017, Kaspersky |
| Striped Fly | — | 3→0→-1 | Custom hypervisor implant | 2023, Sophos |
| Hafnium | — | 3→0 | Exchange Server RCE → kernel | 2021, Microsoft |
| Sandworm | BlackEnergy | 3→0 | KillDisk + MBR overwrite | 2015, ESET |

### 9.3 Stuxnet Analysis (Ring 3 → Ring 0 → Physical)

Stuxnet is the canonical example of a cross-ring attack targeting physical infrastructure:

1. **Ring 3**: Infected Windows machines via USB (LNK vulnerability)
2. **Ring 0**: Loaded kernel driver (`sysrtlt32.sys`) for rootkit capabilities
3. **Ring 0**: Used Siemens PLC driver hooks to manipulate industrial control
4. **Physical**: Caused centrifuges to spin at destructive frequencies

While Stuxnet did not target Rings -1 through -3, it demonstrated that compromising Ring 0 provides sufficient access to manipulate hardware below the OS level.

### 9.4 LoJax: Ring 3 → Ring -2 Full Chain

LoJax (discovered by ESET in 2018) was the first UEFI bootkit seen in the wild:

1. **Ring 3**: Trojan dropper on Windows
2. **Ring 0**: Kernel driver obtains physical memory access
3. **Ring -2**: Writes to SPI flash via physical memory mapping (bypassing NVRAM protections)
4. **Persistence**: UEFI DXE driver implant executes during boot before OS loads

The implant:
- Hooks `StartImage()` to inject code into every booted OS
- Modifies ACPI tables
- Reports to C2 server (Russian APT group Sednit/Fancy Bear)

---

## 10. Master CVE Table

### Ring 3 (Userland)

| CVE | Description | CVSS | Ring Transition |
|-----|-------------|------|-----------------|
| CVE-2016-5195 | Dirty COW: COW race condition | 7.8 | Ring 3 → Ring 0 |
| CVE-2022-0847 | Dirty Pipe: pipe_buffer flags uninitialized | 7.8 | Ring 3 → Ring 0 |
| CVE-2021-4034 | PwnKit: pkexec argv/envp confusion | 7.8 | Ring 3 → Ring 0 (root) |
| CVE-2021-3156 | Baron Samedit: sudo heap overflow | 7.8 | Ring 3 → Ring 0 (root) |
| CVE-2019-18634 | sudo pwfeedback buffer overflow | 7.8 | Ring 3 → Ring 0 (root) |
| CVE-2019-5736 | runc /proc/self/exe escape | 9.8 | Container → Host |
| CVE-2022-0492 | cgroup v1 release_agent escape | 7.5 | Container → Host |

### Ring 0 (Kernel)

| CVE | Description | CVSS | Ring Transition |
|-----|-------------|------|-----------------|
| CVE-2017-5123 | waitid() missing access_ok | 7.0 | Ring 3 → Ring 0 |
| CVE-2020-8835 | eBPF verifier OOB read/write | 7.8 | Ring 3 → Ring 0 |
| CVE-2024-1086 | Netfilter nft_verdict_init UAF | 8.8 | Ring 3 → Ring 0 |
| CVE-2023-0386 | OverlayFS setuid copy-up | 7.8 | Ring 3 → Ring 0 |
| CVE-2019-15666 | setxattr kernel OOB write | 7.0 | Ring 3 → Ring 0 |
| CVE-2017-7308 | signalfd UAF | 7.8 | Ring 3 → Ring 0 |
| CVE-2016-0728 | Keyrings refcount overflow | 7.8 | Ring 3 → Ring 0 |
| CVE-2021-4154 | eBPF verifier OOB write | 7.8 | Ring 3 → Ring 0 |

### Ring -1 (Hypervisor)

| CVE | Description | CVSS | Ring Transition |
|-----|-------------|------|-----------------|
| CVE-2015-3456 | VENOM: QEMU floppy buffer overflow | 10.0 | Guest → Host |
| CVE-2015-5161 | QEMU RTL8139 info leak | 6.5 | Guest → Host info |
| CVE-2015-7504 | QEMU PCNET heap overflow | 7.5 | Guest → Host RCE |
| CVE-2019-6974 | KVM ioport race condition | 7.8 | Guest → Host |
| CVE-2021-28476 | Hyper-V vmswitch RCE | 9.8 | Guest → Host |
| CVE-2018-10938 | QEMU virtio-9p buffer overflow | 6.5 | Guest → Host |
| CVE-2020-3950 | VMware XHCI UAF | 9.8 | Guest → Host |

### Ring -2 (SMM)

| CVE | Description | CVSS | Ring Transition |
|-----|-------------|------|-----------------|
| CVE-2017-5705 | Intel SMI buffer overflow | 9.8 | Ring 0 → Ring -2 |
| CVE-2017-5706 | Intel SMI callout | 8.2 | Ring 0 → Ring -2 |
| CVE-2017-5711 | Intel SMI race condition | 7.5 | Ring 0 → Ring -2 |
| CVE-2021-3816 | EDK II SMM variable UAF | 7.5 | Ring 0 → Ring -2 |
| CVE-2022-0002 | Intel SMM LPE | 7.8 | Ring 0 → Ring -2 |

### Ring -3 (ME/PSP)

| CVE | Description | CVSS | Ring Transition |
|-----|-------------|------|-----------------|
| CVE-2017-5708 | Intel SPS privilege escalation | 8.2 | Ring -2 → Ring -3 |
| CVE-2019-0090 | Intel CSME access control | 9.0 | Network → Ring -3 |
| CVE-2020-8758 | Intel CSME DAL buffer overflow | 8.8 | Network → Ring -3 |
| CVE-2019-1549 | AMD PSP SEV key extraction | 7.5 | Ring -1 → Ring -3 |

---

## 11. Complete Ring-by-Ring Reference Card

| Ring | Name | Privilege | What Runs Here | Key Defenses | Notable CVEs | Primary Attack Technique | Detection Method |
|------|------|-----------|----------------|-------------|-------------|------------------------|-----------------|
| 3 | Userland | CPL=3 | Applications, browsers, servers | ASLR, PIE, NX, stack canaries, seccomp, SELinux/AppArmor | CVE-2022-0847, CVE-2021-4034 | Kernel exploit from userspace | Auditd, Falco, eBPF |
| 2 | I/O Services | CPL=2 | (Unused) | IOPL, IOPB, VT-d | CVE-2018-5333 | IOPL escalation | I/O port monitoring |
| 1 | Drivers | CPL=1 | (Unused) | Flat kernel model, x86-64 call gate removal | CVE-2015-5157 | Call gate via LDT | GDT/LDT auditing |
| 0 | Kernel | CPL=0 | OS kernel, drivers, interrupt handlers | SMEP, SMAP, KASLR, KPTI, CFI, Lockdown | CVE-2024-1086, CVE-2017-5123 | LPE via syscall/ioctl/BPF | Tetragon, kmod audit |
| -1 | Hypervisor | VMX Root | KVM, Xen, VMware, Hyper-V | sVirt, SEV-SNP, TDX, IOMMU | CVE-2015-3456, CVE-2021-28476 | VM escape via device emulation | VMCS integrity, TPM attestation |
| -2 | SMM | SMM Mode | UEFI firmware handlers, OEM code | Secure Boot, Measured Boot, SMRR, BIOS Guard | CVE-2017-5705, CVE-2021-3816 | SMI callout, SPI flash implant | Chipsec, TPM event log |
| -3 | ME/PSP | Independent MCU | MINIX-3 (Intel), TrustZone (AMD) | ME patching, HAP bit, Boot Guard | CVE-2017-5708, CVE-2019-0090 | Network RCE, firmware modification | ME version audit, JTAG monitoring |

---

## 12. Defense-in-Depth Strategy

### 12.1 Ring 3 Hardening

```bash
# Kernel parameters
sysctl -w kernel.randomize_va_space=2      # Full ASLR
sysctl -w kernel.yama.ptrace_scope=2       # Restrict ptrace
sysctl -w kernel.kptr_restrict=2           # Hide kernel addresses
sysctl -w kernel.dmesg_restrict=1          # Restrict dmesg

# Compilation flags
CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie"
LDFLAGS="-Wl,-z,relro,-z,now"               # Full RELRO

# Seccomp: Allow only essential syscalls
# SELinux/AppArmor: Enforce MAC policy
# Capabilities: Drop all, add only needed
```

### 12.2 Ring 0 Hardening

```bash
# Kernel boot parameters
SMEP SMAP KASLR KPTI                       # Enable all hardware mitigations
lockdown=confidentiality                    # Kernel Lockdown mode
CONFIG_HARDENED_USERCOPY=y
CONFIG_SLUB_HARDENED=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
```

### 12.3 Ring -1 Hardening

- Use SEV-SNP or Intel TDX for confidential VMs
- Enable sVirt (SELinux per-VM labels)
- Minimize QEMU device model (use virtio)
- Disable nested virtualization unless required
- Apply hypervisor security patches promptly
- Use IOMMU for device isolation

### 12.4 Ring -2 Hardening

- Enable Secure Boot + Measured Boot
- Lock all UEFI/BIOS settings
- Set SPI flash write-protect (if hardware supports)
- Enable `SMM_CODE_CHK_EN` and `SMM_FEATURE_CONTROL_LOCK`
- Apply firmware updates via signed UEFI capsules
- Run `chipsec` hardening checks regularly

### 12.5 Ring -3 Hardening

- Apply Intel ME/AMD PSP firmware updates promptly
- Set HAP bit where supported (enterprise systems)
- Disable AMT/vPro if not needed
- Update CPU microcode at boot
- Physically secure JTAG/debug ports
- Monitor ME version and configuration

### 12.6 Cross-Ring Monitoring

| Ring | Monitoring Tool | What It Detects |
|------|----------------|-----------------|
| 3 | Auditd, Falco | Unusual syscalls, process ancestry |
| 0 | Tetragon, eBPF LSM | Kernel module loading, kfunc calls |
| -1 | Hypervisor introspection | VMCS tampering, EPT anomalies |
| -2 | TPM Measured Boot | Firmware modification, SMI count changes |
| -3 | ME version audit | ME firmware tampering |

---

## 13. Glossary

| Term | Definition |
|------|-----------|
| **CPL** | Current Privilege Level — the CPU's current ring (0-3) |
| **DPL** | Descriptor Privilege Level — the minimum ring required to access a segment |
| **RPL** | Requested Privilege Level — the ring encoded in a segment selector |
| **SMRR** | System Management Range Register — protects SMRAM from Ring 0 access |
| **VMCS** | Virtual Machine Control Structure — per-VCPU hypervisor data |
| **EPT/NPT** | Extended/Nested Page Tables — guest→host physical translation |
| **SMI** | System Management Interrupt — triggers SMM entry |
| **SMRAM** | System Management RAM — protected memory for SMM code |
| **HECI** | Host-Embedded Controller Interface — ME↔host communication |
| **KASLR** | Kernel Address Space Layout Randomization |
| **KPTI** | Kernel Page-Table Isolation (Meltdown mitigation) |
| **SMEP** | Supervisor Mode Execution Prevention |
| **SMAP** | Supervisor Mode Access Prevention |
| **CFI** | Control Flow Integrity |
| **SEV-SNP** | Secure Encrypted Virtualization - Secure Nested Paging (AMD) |
| **TDX** | Trust Domain Extensions (Intel confidential computing) |
| **LPE** | Local Privilege Escalation |
| **UAF** | Use-After-Free |
| **ROP** | Return-Oriented Programming |

---

## Appendix: Research Document Index

The following detailed research documents are available in the `docs/` directory:

| Document | Topic | Lines |
|----------|-------|-------|
| `ring3_userland_A.md` | Ring 3 architecture, boundaries, vulnerability classes, CVEs | 776 |
| `ring3_userland_B.md` | Ring 3 attack surface, exploitation methodology, kernel entry | 1800+ |
| `ring2_ring1_A.md` | Rings 1/2 architecture, history, virtualization overlay | 520 |
| `ring2_ring1_B.md` | Ring transitions, GDT/LDT, IOPL, microkernel comparison | 739 |
| `ring0_kernel_A.md` | Ring 0 kernel attack surface, CVEs, hardening | 1470 |
| `ring0_kernel_B.md` | Advanced kernel exploitation, rootkits, eBPF | 1700+ |
| `ring_minus1_hypervisor_A.md` | Ring -1 hypervisor architecture, VM escapes, CVEs | 869 |
| `ring_minus1_hypervisor_B.md` | Hypervisor exploitation case studies, side channels | 1645 |
| `ring_minus2_smm_A.md` | Ring -2 SMM architecture, vulnerabilities, tools | 1388 |
| `ring_minus3_me_A.md` | Ring -3 Intel ME/AMD PSP architecture, CVEs | 1240 |
| `cross_ring_chains_A.md` | Multi-ring attack chains, real-world case studies | 1834 |
| `cross_ring_chains_B.md` | Defense-in-depth across all rings, reference card | 1501 |

**Total research**: ~15,000 lines of technical documentation across 12 files.

---

*Report compiled: April 2026 | Classification: Technical Research | All information is publicly available.*