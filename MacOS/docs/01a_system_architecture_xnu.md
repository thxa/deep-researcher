# macOS System Architecture — XNU Kernel and Darwin Foundation

## 1. Darwin and XNU Overview

macOS is built on **Darwin**, an open-source POSIX-compliant operating system that Apple releases under the APSL (Apple Public Source License). Darwin provides the kernel, core C library (`libSystem`), a POSIX shell environment, and the foundational frameworks upon which macOS, iOS, iPadOS, watchOS, and tvOS are constructed. Darwin itself can be compiled and run independently of Apple's proprietary frameworks — it constitutes the complete lower half of every Apple OS.

At the center of Darwin is **XNU** — "X is Not Unix" — a hybrid kernel that fuses three distinct subsystems into a single address space:

| Component | Origin | Role |
|-----------|--------|------|
| **Mach** | Carnegie Mellon Mach 3.0 microkernel | IPC, virtual memory, task/thread scheduling, port-based security model |
| **BSD** | FreeBSD (4.4BSD lineage) | POSIX process model, VFS, networking stack, syscall interface, kqueue |
| **IOKit** | Apple (NeXT heritage) | Object-oriented C++ driver framework, device tree registry, user-kernel communication |

XNU is technically a hybrid kernel: it adopts the microkernel abstraction of Mach (tasks, threads, ports, message passing) but runs the BSD subsystem and drivers in the same kernel address space for performance — avoiding the IPC overhead of a pure microkernel design. The Mach layer provides the low-level primitives; the BSD layer provides the POSIX-compatible personality that applications actually interact with through system calls; IOKit handles hardware abstraction and driver management.

The kernel source (when released) lives in the `xnu` repository. A built XNU kernel ships as the Mach-O executable at `/System/Library/Kernels/kernel` (Intel) or embedded inside a KernelCollection on Apple Silicon.

---

## 2. Mach Layer

### Mach Ports — Fundamental IPC Abstraction

The Mach port is the central primitive in XNU. A port is a **kernel-managed unidirectional message queue** protected by a capability-based security model. Ports are not identified by global names — each task maintains a private **IPC space** (`ipc_space_t`) mapping local port names (`mach_port_name_t`, a 32-bit integer) to kernel port objects (`ipc_port_t`). This indirection means one task cannot forge references to another task's ports.

Ports carry typed rights:

- **Receive right** (`MACH_PORT_RIGHT_RECEIVE`): Exactly one holder. The receiver dequeues messages from the port. Owning a receive right implies ownership of the port itself — destroying the receive right destroys the port.
- **Send right** (`MACH_PORT_RIGHT_SEND`): Grants the ability to enqueue messages. Multiple tasks may hold send rights to the same port. Send rights are reference-counted in the kernel.
- **Send-once right** (`MACH_PORT_RIGHT_SEND_ONCE`): A one-shot send right that is consumed after a single message. Used for reply ports in RPC-style transactions.

Rights can be **transferred** inside Mach messages using out-of-line port descriptors. When a task sends a message containing a port right, the kernel moves or copies the right from the sender's IPC space into the receiver's IPC space. This capability transfer mechanism is the foundation of all service registration: `launchd` holds receive rights for registered service ports and hands out send rights to clients via `bootstrap_look_up()`.

### Task and Thread Abstractions

Mach defines two key execution abstractions:

- **Task** (`task_t`): A container for resources — a virtual address space, a port namespace, and a set of threads. A Mach task is *not* a process; the BSD layer wraps a Mach task with a `proc` structure to create a POSIX process. Every task has a **task port** (a send right to the task's kernel control port) that grants full control: the ability to read/write its memory (`mach_vm_read`/`mach_vm_write`), manipulate its threads, and modify its port space. Obtaining another task's task port is equivalent to full compromise of that process.
- **Thread** (`thread_t`): A single execution context within a task. Each thread has its own register state, kernel stack, and scheduling parameters. The Mach scheduler (located in `osfmk/kern/sched_*`) supports multiple scheduling policies and manages threads across physical CPUs.

### Message Passing — `mach_msg`

All Mach IPC occurs through `mach_msg()` (trap number 31, `mach_msg_trap` in the `mach_trap_table`). A single `mach_msg` call can both send and receive in one operation (combined send-receive). The message structure (`mach_msg_header_t`) includes:

```
msgh_bits        — encoding of port right transfer types for local/remote ports
msgh_size        — total message size
msgh_remote_port — destination port (send or send-once right)
msgh_local_port  — reply port (typically a send-once right)
msgh_voucher_port — voucher port for resource accounting
msgh_id          — application-defined message ID (used by MIG)
```

Messages can contain **inline data** (following the header) and **out-of-line (OOL) descriptors** for large payloads or port right transfers. OOL memory is mapped copy-on-write from the sender's address space into the receiver's, avoiding physical copies for large buffers. The `MACH_MSG_OOL_DESCRIPTOR` type handles memory regions; `MACH_MSG_PORT_DESCRIPTOR` handles port rights.

### Mach Traps

Mach system calls enter the kernel through the **mach trap table** (`mach_trap_table[]`), defined in `osfmk/kern/syscall_sw.c`. Each entry maps a negative trap number to a kernel function. Key traps include:

| Trap | Function |
|------|----------|
| -26 | `mach_reply_port` — create a reply port |
| -28 | `task_self_trap` — return the calling task's port |
| -29 | `host_self_trap` — return the host port |
| -31 | `mach_msg_trap` — send/receive messages |
| -36 | `semaphore_wait_trap` |
| -100 | `mk_timer_create_trap` |

On ARM64, Mach traps are dispatched through the same `svc` instruction as BSD syscalls, differentiated by the syscall number sign (negative = Mach, positive = BSD). On x86_64, they use `syscall` with the same convention.

### MIG — Mach Interface Generator

MIG is a compiler that reads `.defs` interface definition files and generates C stubs for both client (sender) and server (receiver) sides of a Mach RPC. MIG definitions specify message IDs, parameter types, and port right transfer semantics. For example, `task.defs` defines the interface for `task_threads()`, `task_info()`, and other task manipulation routines.

The generated server-side code includes a `demux` function that dispatches incoming messages by `msgh_id` to the appropriate handler. MIG-generated routines are pervasive in the kernel and system daemons. Security-relevant bugs frequently occur in MIG handlers where input validation on message size or port types is insufficient, or where the generated stubs make assumptions about struct layout that can be violated by crafted messages.

---

## 3. BSD Layer

### POSIX Compatibility and Process Model

The BSD layer provides the POSIX personality that userland applications interact with. It wraps Mach tasks with the `proc` structure (`struct proc`, defined in `bsd/sys/proc_internal.h`), which adds:

- **PID namespace**: Unique process identifiers, parent-child relationships, process groups, and sessions.
- **Credential management**: `kauth_cred_t` credentials carrying UID, GID, supplementary groups, POSIX.1e capabilities, and macOS-specific audit tokens.
- **Signal handling**: POSIX signal delivery, signal masks, and signal actions.
- **Resource limits**: `rlimit` enforcement, file descriptor tables, and accounting.
- **File descriptor table**: Mapping integer file descriptors to kernel `fileproc` structures, each pointing to a `fileglob` with an associated `fileops` vector (read, write, ioctl, select, close).

The BSD syscall interface is defined in the `sysent[]` table (`bsd/kern/syscalls.master`). Each entry maps a positive syscall number to a kernel function, along with argument count and type information. macOS supports approximately 540+ syscalls (the exact count varies by version). The table includes standard POSIX calls (`open`, `read`, `write`, `fork`, `execve`) alongside Apple-specific additions (`csops` for code-signing queries, `kas_info` for KASLR slide retrieval, `shared_region_map_and_slide_2_np` for shared cache management).

### VFS — Virtual File System

XNU's VFS layer, derived from FreeBSD, provides a filesystem-agnostic interface through **vnode** objects. A `vnode` represents any filesystem entity (file, directory, symlink, device) and carries a `vnodeop_desc` vector dispatching operations to the underlying filesystem implementation:

- `VNOP_OPEN`, `VNOP_READ`, `VNOP_WRITE`, `VNOP_CLOSE` — standard I/O operations
- `VNOP_LOOKUP` — name-to-vnode translation within a directory
- `VNOP_GETATTR`, `VNOP_SETATTR` — metadata (permissions, timestamps, extended attributes)
- `VNOP_MMAP` — memory-mapping support

The VFS mount table tracks mounted filesystems. APFS (Apple File System) is the primary filesystem, registered through the VFS as a `vfsops` structure providing `vfs_mount`, `vfs_unmount`, `vfs_root`, and `vfs_sync` operations. APFS features — clones, snapshots, space sharing, encryption — are implemented below the vnode layer.

A `mount` structure ties a filesystem instance to a mount point and carries mount-specific data, flags (read-only, nosuid, nodev), and the root vnode for the mounted volume.

### Networking Stack

XNU's networking stack descends from the BSD socket layer. The `socket` structure is the kernel object behind `AF_INET`/`AF_INET6`/`AF_UNIX` file descriptors. The stack follows the classic BSD layered model:

- **Socket layer**: `sosend()` / `soreceive()` operating on socket buffers (`struct sockbuf`)
- **Protocol layer**: TCP (`tcp_input`, `tcp_output`), UDP, ICMP, with protocol switch tables (`struct protosw`)
- **Interface layer**: Network interface structures (`struct ifnet`) abstracting hardware NICs and virtual interfaces

Apple extends the BSD stack with **Network Kernel Extensions (NKEs)** and the newer **NetworkExtension** framework for packet filtering, content filtering, and VPN tunneling. The `pf` packet filter (from OpenBSD) operates at the interface layer.

### kqueue/kevent Event Notification

`kqueue` is the BSD event notification mechanism, analogous to Linux's `epoll`. A kqueue is a kernel object (represented by a file descriptor) that aggregates events from diverse sources:

- `EVFILT_READ` / `EVFILT_WRITE` — socket and pipe readiness
- `EVFILT_VNODE` — filesystem changes (delete, write, extend, rename, attrib)
- `EVFILT_PROC` — process events (fork, exec, exit)
- `EVFILT_SIGNAL` — signal delivery
- `EVFILT_MACHPORT` — Mach port message arrival
- `EVFILT_TIMER` — timer expiration

The `kevent64` and `kevent_qos` syscalls register filters and harvest events. Grand Central Dispatch (`libdispatch`) uses kqueue internally for its event-driven dispatch source mechanism, making kqueue the backbone of all asynchronous I/O in macOS userland.

---

## 4. IOKit Driver Framework

### Architecture and Runtime

IOKit is an object-oriented driver framework built on a restricted C++ runtime called **libkern**. Libkern provides `OSObject` (base class with reference counting), `OSDictionary`, `OSArray`, `OSString`, `OSNumber`, and other container types — but notably excludes exceptions, RTTI (using its own `OSMetaClass` system instead), and the C++ standard library. Drivers inherit from `IOService`, which participates in a matching and probing lifecycle.

### Provider/Client Model and Device Tree

IOKit organizes the system as a directed acyclic graph of **IORegistryEntry** objects forming the **IORegistry** — a live, in-memory representation of the device tree. The registry is structured into multiple **planes** (Provider, Service, Power, USB, Audio), each showing different relationship hierarchies.

The **provider/client** model governs driver stacking:

1. **Nubs** (provider objects) represent discoverable resources — a PCI slot, a USB port, a disk partition.
2. **Drivers** (client objects) attach to nubs by matching on a **matching dictionary** (properties like `IOProviderClass`, `IONameMatch`, `IOPropertyMatch`).
3. The `probe()` method allows a driver to verify hardware compatibility and assign a match score. The highest-scoring driver wins.
4. `start()` initializes the driver; `stop()` tears it down.

The `ioreg` command-line tool dumps the registry. Example hierarchy: `IOPlatformExpertDevice → AppleARMPE → IOPlatformDevice → AppleT811xIO → AppleS5L8960XDWI2C → ...`

### User-Kernel Communication

Userland communicates with IOKit drivers through **IOUserClient** subclasses. The kernel-side flow:

1. A driver's `newUserClient()` method instantiates an `IOUserClient` subclass.
2. The user client registers **external methods** via `getTargetAndMethodForIndex()` or the newer `externalMethod()` dispatch table (`IOExternalMethodDispatch` structures defining input/output scalar and struct counts).
3. Userland calls `IOConnectCallMethod()` (or the struct variant `IOConnectCallStructMethod()`) specifying a selector index and input/output buffers.
4. The kernel validates input counts against the dispatch table, then invokes the registered function.

This is a historically significant attack surface. Bugs in external method implementations — missing bounds checks on scalar inputs, type confusion on struct inputs, race conditions in shared memory mappings — have been exploited extensively for kernel code execution. Apple has increasingly migrated drivers to **DriverKit** (user-space IOKit equivalent) to reduce this kernel attack surface.

---

## 5. Memory Architecture

### Virtual Memory Layout

XNU uses a split virtual address space:

- **ARM64** (Apple Silicon): `TTBR0_EL1` maps the lower address range (user space, `0x0` through `0x0000_FFFF_FFFF_FFFF` with typical 39-bit or 42-bit VA width). `TTBR1_EL1` maps the upper range (kernel space, addresses above `0xFFFF_FF80_0000_0000` or similar, depending on VA bits). Context switches update `TTBR0` while `TTBR1` remains constant.
- **x86_64** (Intel): User space occupies the lower canonical half (up to `0x0000_7FFF_FFFF_FFFF`); kernel space occupies the upper canonical half (from `0xFFFF_8000_0000_0000`). Both halves are covered by a single `CR3` page table root; kernel pages are marked supervisor-only.

### KASLR and ASLR

**KASLR** (Kernel Address Space Layout Randomization) randomizes the base virtual address of the kernel text, data, and linked kernel extensions at boot. The slide is generated early in the boot chain (by iBoot on Apple Silicon) and applied when mapping the kernel. User-space processes cannot directly determine the slide without a kernel information leak. The `kas_info` syscall (restricted by entitlement) and the `vm.kernel_page_size` sysctl have historically leaked information about kernel layout.

**ASLR** randomizes the base addresses of the main executable, dynamic libraries (dyld shared cache), stack, heap, and mmap regions for each user-space process. On modern macOS, the dyld shared cache is mapped at a randomized address chosen at boot time and shared across all processes.

### Zone Allocator

XNU's primary kernel heap allocator is the **zone allocator** (`zalloc`/`zfree`). A zone is a pool of fixed-size elements:

- **kalloc zones** handle general-purpose allocations in power-of-two sizes (`kalloc.16`, `kalloc.32`, `kalloc.48`, `kalloc.64`, ... `kalloc.16384` and larger). `kalloc()` selects the smallest zone that fits the requested size.
- **Custom zones** are created for specific kernel structures (e.g., `ipc_ports` zone for `ipc_port_t`, `vnodes` zone for `vnode` objects). This segregation limits cross-object type confusion in exploitation.

Modern XNU includes hardening features in the zone allocator:

- **Zone poisoning**: Freed elements are filled with `0xDEADBEEF` patterns and verified on reallocation.
- **Sequential allocation** (`Z_CALLOCP_SEQ`): Certain zones allocate sequentially to prevent use-after-free from reusing recently freed slots.
- **Zone metadata separation**: Zone metadata is stored separately from zone elements, preventing metadata corruption from linear overflows.
- **kheap segregation**: Kernel heaps are segregated by subsystem (default, kext, data buffers) so that an overflow in one heap cannot corrupt objects in another.

### Page Tables

On **ARM64**, XNU uses a 4-level page table structure (with 16KB granules on Apple Silicon, unlike the typical 4KB on other ARM64 platforms):

- Level 0 (L0) → Level 1 (L1) → Level 2 (L2) → Level 3 (L3) page table entries
- 16KB pages yield 14-bit page offsets; each table level resolves additional VA bits
- Page table entries include AP (Access Permission) bits, PXN/UXN (Privileged/Unprivileged Execute Never), and memory attribute indices

On **x86_64**, XNU uses the standard 4-level page table (PML4 → PDPT → PD → PT) with 4KB pages. SMEP (Supervisor Mode Execution Prevention) and SMAP (Supervisor Mode Access Prevention) bits in CR4 prevent the kernel from executing or accessing user-space memory.

---

## 6. Boot Process

### Apple Silicon Boot Chain

The Apple Silicon boot process is a strictly verified chain of trust:

1. **BootROM** (SecureROM): Immutable code burned into the SoC at fabrication. Initializes core hardware, loads and verifies the next stage from NOR flash. The BootROM contains Apple's root of trust — the hardware root CA public key. It is not updatable; vulnerabilities here (e.g., `checkm8` on A5–A11) are permanent.

2. **LLB** (Low-Level Bootloader): Loaded from NOR, verified by BootROM. Performs further hardware initialization (DRAM training, display initialization). Loads iBoot from the Preboot volume.

3. **iBoot**: The primary bootloader. Loads and verifies the kernelcache (KernelCollection), device tree, and ramdisk. iBoot enforces the **LocalPolicy** — a per-OS signing policy stored in the Secure Enclave that determines the boot security level (Full Security, Reduced Security, Permissive Security). iBoot generates the KASLR slide, initializes the kernel's physical memory map, and transfers control to the XNU entry point.

4. **XNU Kernel**: Takes over from iBoot, initializes the Mach and BSD subsystems, mounts the root filesystem, and launches `launchd` (PID 1).

### Intel Boot Chain

1. **EFI Firmware**: UEFI-compliant firmware initializes hardware and provides boot services. The firmware locates `boot.efi` on the EFI System Partition.

2. **boot.efi**: Apple's EFI boot loader. Verifies and loads the kernel and kernel extensions, applies KASLR, constructs the boot arguments structure, and transitions from EFI boot services to the XNU kernel.

3. **XNU Kernel**: Same kernel initialization as Apple Silicon from this point forward.

### KernelCollections

Modern macOS (11+) replaces the legacy prelinked kernel with **KernelCollections** — Mach-O based images that bundle the kernel and extensions:

- **Boot KernelCollection (Boot KC)**: Contains XNU and essential boot-time kexts (APFS, platform drivers, core IOKit families). Loaded by iBoot / boot.efi. On Apple Silicon, it is signed by Apple and verified against the LocalPolicy.
- **System KernelCollection (System KC)**: Contains Apple's first-party system kexts. Loaded by the kernel after boot.
- **Auxiliary KernelCollection (Auxiliary KC)**: Contains third-party kexts. Only available at Reduced Security or below. Requires explicit user approval via `bputil` or Startup Security Utility.

KernelCollections are built by `kmutil` (which replaced `kextcache`) and are stored on the Preboot volume.

### Signed System Volume (SSV)

macOS 11+ employs a **Signed System Volume** to protect the integrity of the system partition. The entire system volume is verified using a **Merkle tree** — a hash tree where each leaf node is the hash of a filesystem block, and each internal node is the hash of its children. The root hash (the **seal**) is signed by Apple and stored alongside the volume metadata.

At mount time, the kernel verifies the seal against Apple's signing certificate. During runtime, individual blocks are verified against the Merkle tree on demand as they are paged in. Any modification to the system volume — even a single byte — invalidates the hash chain and renders the volume unmountable in a fully sealed state. This replaces the file-level protection of earlier SIP implementations with a cryptographically complete volume integrity guarantee.

The SSV means that even with root access and SIP disabled, directly modifying the system volume is no longer straightforward — the volume must be re-sealed (or booted unsealed at Permissive Security) for changes to take effect.

---

## Summary

XNU's hybrid architecture — Mach's capability-based IPC and VM primitives, BSD's battle-tested POSIX layer, and IOKit's object-oriented driver model — creates a complex kernel with multiple interacting subsystems. Each boundary between these subsystems (Mach trap handlers, BSD syscall entries, IOKit external methods, MIG-generated dispatch routines) represents a distinct attack surface with its own class of potential vulnerabilities. Understanding the architecture at this level is a prerequisite for both defending and auditing macOS at the kernel level.
