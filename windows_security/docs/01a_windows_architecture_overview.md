# Windows NT Architecture Overview — Kernel Mode, Executive Subsystems & Internal Mechanisms

> A deep-technical reference on the Windows NT architecture: kernel/user boundary, executive subsystems, HAL, Object Manager, I/O Manager, Memory Manager, Process/Thread Manager, NT namespace, NTAPI, critical sections, APCs, and DPCs. Written for security researchers, exploit developers, and OSEE candidates.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Kernel Mode vs User Mode](#2-kernel-mode-vs-user-mode)
3. [Executive Subsystems](#3-executive-subsystems)
4. [The Kernel & HAL](#4-the-kernel--hal)
5. [Object Manager](#5-object-manager)
6. [I/O Manager & Driver Architecture](#6-io-manager--driver-architecture)
7. [Memory Manager](#7-memory-manager)
8. [Process & Thread Manager](#8-process--thread-manager)
9. [NT Namespace & NTAPI](#9-nt-namespace--ntapi)
10. [APCs — Asynchronous Procedure Calls](#10-apcs--asynchronous-procedure-calls)
11. [DPCs — Deferred Procedure Calls](#11-dpcs--deferred-procedure-calls)
12. [Critical Sections & Synchronization Primitives](#12-critical-sections--synchronization-primitives)
13. [Security Research Implications](#13-security-research-implications)

---

## 1. Architecture Overview

Windows NT (NT — originally "New Technology") is a preemptive multitasking, multi-processor operating system with a hybrid kernel architecture. Unlike microkernel designs (Mach, L4) or pure monolithic kernels (Linux), NT places significant functionality in kernel-mode executive subsystems while maintaining modular separation through clearly defined internal interfaces. The architecture follows a layered design with strict privilege boundaries enforced by hardware ring transitions (x86/x64 Ring 0 for kernel, Ring 3 for user).

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER MODE (Ring 3)                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐│
│  │ Win32    │ │ POSIX     │ │ OS/2     │ │  Windows          ││
│  │ Subsystem│ │ Subsystem │ │ Subsystem│ │  Subsystem (WOW64) ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬──────────┘│
│       │             │             │                │           │
│  ┌────┴─────────────┴─────────────┴────────────────┘           │
│  │              Subsystem DLLs (ntdll.dll, kernel32.dll,       ││
│  │              advapi32.dll, user32.dll, gdi32.dll)          ││
│  └────────────────────────┬───────────────────────────────────┘│
│                           │ Syscall (syscall/sysenter)         │
├───────────────────────────┼────────────────────────────────────┤
│                      KERNEL MODE (Ring 0)                      │
│  ┌────────────────────────┴───────────────────────────────────┐│
│  │                    NT Kernel & Executive                   ││
│  │  ┌────────────────────────────────────────────────────────┐││
│  │  │ Executive Subsystems                                  │││
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │││
│  │  │  │ Object   │ │ I/O      │ │ Memory   │ │ Process  │ │││
│  │  │  │ Manager  │ │ Manager  │ │ Manager  │ │ Manager  │ │││
│  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │││
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │││
│  │  │  │ Security │ │ Config   │ │ Local    │ │ Cache    │ │││
│  │  │  │ Ref Mon  │ │ Manager │ │ Proc Call│ │ Manager  │ │││
│  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │││
│  │  └────────────────────────────────────────────────────────┘││
│  │  ┌────────────────────────────────────────────────────────┐││
│  │  │ Microkernel (Scheduler, Interrupts, Trap Handling)     │││
│  │  └────────────────────────────────────────────────────────┘││
│  │  ┌────────────────────────────────────────────────────────┐││
│  │  │ Hardware Abstraction Layer (HAL)                       │││
│  │  └────────────────────────────────────────────────────────┘││
│  │  ┌────────────────────────────────────────────────────────┐││
│  │  │ Device Drivers (Filesystem, Network, Display, etc.)    │││
│  │  └────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                    ┌──────────────────┐
                    │   Hardware       │
                    │   (CPU, MMU,     │
                    │    Devices)      │
                    └──────────────────┘
```

The NT architecture is documented primarily through the Windows Internals book series (Russinovich, Solomon, Ionescu), the Windows Driver Kit (WDK) headers, and reverse engineering via WinDBG, IDA, and Ghidra. Microsoft does not publish the source code, unlike the Linux kernel or XNU — making the NT internals domain one where reverse engineering is a core competency (see `→ OSEE` track for methodology).

**Key design principles:**

- **Object-based**: Nearly every kernel resource is represented as an object managed by the Object Manager, enabling uniform security, naming, and reference counting.
- **Message-based IPC**: Local Procedure Call (LPC) / Advanced LPC (ALPC) provides fast inter-process communication, forming the backbone of the subsystem architecture.
- **Layered driver model**: The I/O Manager orchestrates a stackable driver architecture where IRPs (I/O Request Packets) flow through driver layers.
- **Hardware abstraction**: The HAL isolates the kernel from platform-specific hardware details, enabling a single kernel binary to run on different hardware platforms.

---

## 2. Kernel Mode vs User Mode

### 2.1 Privilege Boundary

The fundamental security boundary in Windows is the Ring 0/Ring 3 transition enforced by the CPU's privilege levels. On x64 systems:

- **User Mode (Ring 3)**: All user applications execute here. The virtual address space is divided: the lower half (0x00000000'00000000 through 0x00007FFF'FFFFFFFF on default configurations) belongs to the current process; the upper half (0xFFFF0800'00000000 through 0xFFFFFFFF'FFFFFFFF) is reserved for kernel mode and is identical across all processes.

- **Kernel Mode (Ring 0)**: The NT kernel, executive subsystems, HAL, and all device drivers execute in this privileged mode. Kernel code has unrestricted access to all physical memory, hardware devices, and CPU control registers (CR0-CR4, CR8, MSRs).

```
Virtual Address Space Layout (x64, Windows 10/11 default):
═══════════════════════════════════════════════════════════════
Kernel Mode  0xFFFFFFFFFFFFFFFF ┌─────────────────────┐
             0xFFFFFFFFFFFFF000 │ Hardware-mapped page │
             0xFFFFF80000000000 │ Kernel address space │
                               │ - ntoskrnl.exe      │
                               │ - HAL (hal.dll)     │
                               │ - Win32k.sys        │
                               │ - Drivers (.sys)    │
                               │ - Non-paged pool    │
                               │ - Paged pool        │
                               │ - System caches     │
                               │ - System PTEs       │
             0xFFFF080000000000 │ Start of kernel VA  │
───────────────────────────────┼─────────────────────┤ User/Kernel boundary
User Mode    0x00007FFFFFFFFFFF │ User address space  │
                               │ - Stack             │
                               │ - Heap              │
                               │ - Code/Data         │
                               │ - DLLs              │
                               │ - TEB/PEB           │
             0x0000000000000000 │ NULL (unmapped)     │
═══════════════════════════════════════════════════════════════
```

### 2.2 Syscall Interface

The transition from user mode to kernel mode occurs through the syscall/sysenter instruction (x64) or the legacy `int 0x2E` (x86). The syscall number is placed in a register (EAX on x86, R10 on x64 — note that the Windows x64 syscall convention uses R10 for the first argument rather than RCX, as `syscall` clobbers RCX with the return address). The actual dispatch occurs through the `KiSystemCallShadow` / `KiSystemCall64` / `KiSystemService` entry point in `ntoskrnl.exe`.

The system service dispatch table (SSDT) is a two-level structure:

```
KeServiceDescriptorTable[]
┌──────────┬──────────┬──────────┬──────────┐
│  Main    │  Shadow  │  (unused)│  (unused)│
│  Table   │  Table   │          │          │
│  (NT)    │  (Win32k)│          │          │
└──────────┴──────────┴──────────┴──────────┘
     │              │
     ▼              ▼
 Nt* services   NtGdi/NtUser services
 (ntoskrnl)     (win32k.sys)
```

The `KeServiceDescriptorTable` (frequently referenced by rootkits and security tools) contains the base of the main syscall table. On modern Windows (since Vista), the SSDT is no longer directly writable due to PatchGuard (KPP — Kernel Patch Protection), which verifies kernel code integrity via a periodic `KECHECKENTRY` timer DPC.

Each SSDT entry maps a syscall number to an offset (`KiServiceTable[index] >> 4 + KiServiceTable`). The number of entries varies per Windows version — approximately 400+ NT syscalls and 2000+ Win32k syscalls.

### 2.3 KPTI (Kernel Page Table Isolation)

Since the Meltdown (CVE-2017-5754) vulnerability demonstrated that Ring 3 code could read kernel memory through speculative execution, Windows implemented KPTI (also called "Kernel Virtual Address Shadow" in Windows terminology). With KPTI enabled:

- While executing in user mode, only a minimal subset of kernel pages is mapped (system call entry/exit trampolines, the KVA shadow region).
- The full kernel page tables are only loaded when the CPU transitions to Ring 0.
- This creates a performance penalty on every syscall due to CR3 reloads and TLB flushes.

```c
// Simplified KVA Shadow trampoline layout (ntoskrnl.exe)
// When KPTI is active, user-mode page tables lack most kernel mappings
KiSystemCallShadow:
    swapgs                    ; Load kernel GS base
    mov  gs:[0x10], rsp       ; Save user stack pointer
    mov  rsp, gs:[0x1A8]      ; Load kernel stack from KPCR
    push 0x1B                 ; User CS
    push qword ptr gs:[0x10]  ; User RSP
    push r11                  ; User RFLAGS
    push 0x23                 ; User SS
    ; ... CR3 swap to kernel page tables ...
    jmp  KiSystemServiceCopy
```

> **Cross-reference**: The Meltdown/KPTI story is further detailed in `→ ring_and_vulns` track's CPU microarchitectural attacks section.

---

## 3. Executive Subsystems

The NT Executive (`ntoskrnl.exe`) is a collection of semi-independent subsystems that implement the core OS functionality. Each subsystem has a well-defined internal interface, though these are not formally published — they are discovered through reverse engineering and WDK header analysis.

### 3.1 Executive Components

| Component | Purpose | Key Internal Structures |
|-----------|---------|------------------------|
| **Object Manager** (`ob`) | Namespace management, object lifecycle, security descriptor enforcement | `OBJECT_HEADER`, `OBJECT_TYPE`, `OB_DUPLICATE_OBJECT_STATE` |
| **I/O Manager** (`io`) | Device/driver management, IRP processing, async I/O | `IRP`, `DEVICE_OBJECT`, `DRIVER_OBJECT`, `IO_STACK_LOCATION` |
| **Memory Manager** (`mm`) | Virtual memory, paging, section objects, working sets | `VAD` (Virtual Address Descriptor), `MMVAD`, `MMPTE`, `MMPFN` |
| **Process/Thread Manager** (`ps`) | Process/thread creation, termination, scheduling | `EPROCESS`, `ETHREAD`, `KPROCESS`, `KTHREAD` |
| **Security Reference Monitor** (`se`) | Access checks, token management, privilege enforcement | `TOKEN`, `SECURITY_DESCRIPTOR`, `SID` |
| **Cache Manager** (`cc`) | File caching via virtual address space | `VACB`, `SHARED_CACHE_MAP` |
| **Configuration Manager** (`cm`) | Registry implementation, hive management | `CMHIVE`, `HCELL`, `KEY_NODE` |
| **Local Procedure Call** (`alpc`) | Fast IPC between processes/subsystems | `ALPC_PORT`, `ALPC_MESSAGE` |
| **Power Manager** (`po`) | Power policy, sleep states, wake events | `POP_IDLE_HANDLER` |
| **Kernel Transaction Manager** (`tm`) | Transactional registry and filesystem operations | `KTRANSACTION` |

Each executive component exports functions prefixed with its two-letter abbreviation (e.g., `ObReferenceObjectByHandle`, `IoAllocateIrp`, `MmCopyVirtualMemory`, `PsCreateSystemThread`, `SeAccessCheck`). These internal function prefixes are crucial for reverse engineering — they map directly to subsystem boundaries.

### 3.2 Executive Object Architecture

All kernel objects share a common structure. Every object starts with an `OBJECT_HEADER`, followed by an optional `OBJECT_CREATE_INFORMATION`, followed by the object body:

```c
// Simplified OBJECT_HEADER (ntoskrnl!_OBJECT_HEADER)
// Actual structure varies by Windows version; offsets from WinDBG
typedef struct _OBJECT_HEADER {
    LONG_PTR               PointerCount;       // +0x00 Reference count
    union {
        LONG_PTR           HandleCount;        // +0x08 Handle count
        struct {
            USHORT          Attributes;        // +0x08 OBJ_* flags
        };
    };
    struct _OBJECT_TYPE    *Type;              // +0x10 Pointer to OBJECT_TYPE
    UCHAR                  NameInfoOffset;      // +0x18 Offset to OBJECT_NAME_INFO
    UCHAR                  HandleInfoOffset;   // +0x19 Offset to OBJECT_HANDLE_INFO
    UCHAR                  QuotaInfoOffset;    // +0x1A Offset to OBJECT_QUOTA_INFO
    UCHAR                  Flags;              // +0x1B OB_FLAG_*
    // ... security descriptor, creator info, etc.
} OBJECT_HEADER, *POBJECT_HEADER;

// Object body immediately follows the header
// Given an object pointer, OBJECT_HEADER = (POBJECT_HEADER)(object - BODY_TO_HEADER_OFFSET)
// The macro OBJECT_TO_OBJECT_HEADER(obj) computes this
```

The `OBJECT_TYPE` structure contains type-specific information including:

```c
typedef struct _OBJECT_TYPE {
    struct _LIST_ENTRY     TypeList;           // +0x00 List of all objects of this type
    UNICODE_STRING          Name;               // +0x10 Type name (e.g., "Process")
    VOID                   *DefaultObject;      // +0x20 Default event object
    UCHAR                   Index;              // +0x28 Type index
    ULONG                   TotalNumberOfObjects; // +0x2C Statistics
    ULONG                   TotalNumberOfHandles;
    ULONG                   HighWaterNumberOfObjects;
    ULONG                   HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;           // +0x38 Type-specific callbacks
    // ... pool type, valid access mask, generic mapping
} OBJECT_TYPE, *POBJECT_TYPE;
```

The `TypeInfo` field is particularly interesting for security research — it contains function pointers for type-specific operations like `DumpProcedure`, `OpenProcedure`, `CloseProcedure`, `DeleteProcedure`, `ParseProcedure`, `SecurityProcedure`, and `QueryNameProcedure`. Manipulating these callbacks is a classic rootkit technique, and verifying their integrity is a PatchGuard check.

---

## 4. The Kernel & HAL

### 4.1 The Microkernel

The NT microkernel (`ntoskrnl.exe` — the same binary contains both the kernel and executive) implements the lowest-level hardware abstraction and scheduling:

- **Thread scheduling**: Priority-based, preemptive scheduling with 32 priority levels (0-31). Real-time priorities (16-31) are reserved for system use in user mode and require `SeIncreaseBasePriorityPrivilege`.
- **Interrupt dispatching**: The Interrupt Dispatch Table (IDT) routes hardware interrupts to ISRs (Interrupt Service Routines). The IDT is per-processor, stored at `KPCR.IDT`.
- **Trap handling**: The kernel handles traps (exceptions and interrupts) through architecture-specific entry points (`KiInterruptDispatch`, `KiTrap*`).
- **Multiprocessor synchronization**: Spinlocks (`KSPIN_LOCK`), queued spinlocks, push locks, and executive resources provide synchronization primitives.
- **DPC mechanism**: See Section 11.

The kernel maintains per-processor state in the `KPCR` (Kernel Processor Control Region) structure on x86, and in the `KPRCB` (Kernel Processor Control Block) which is embedded within it. On x64, the GS segment register points to the current processor's KPCR:

```c
// KPCR layout (x64, simplified)
typedef struct _KPCR {
    struct _KPROCESSOR_STATE ProcessorState; // +0x000
    ULONG                   CurrentIrql;     // +0x???
    struct _KPRCB          *PrcbData;         // Current KPRCB
    // ... many fields
    KIRQL                   Irql;             // Current IRQL
    // ...
} KPCR, *PKPCR;

// Access pattern in kernel code:
// mov gs:[0x184], rbx   ; access KPRCB fields via GS segment
```

### 4.2 Hardware Abstraction Layer (HAL)

The HAL (`hal.dll` or `halacpi.dll`) isolates the kernel from hardware-specific details. It provides:

- **Interrupt controller management**:映射 APIC/PIC interrupts to IRQ levels
- **Timer management**: System tick, profile timer
- **DMA controller access**: Adapter objects for bus-master DMA
- **I/O port and register access**: `READ_PORT.Buffer*`, `WRITE_PORT.Buffer*`
- **BIOS/firmware interface**: UEFI variable access, ACPI table parsing

The HAL is loaded as a separate DLL and exports functions that the kernel calls through a dispatch table. On modern systems, `hal.dll` is relatively small as most hardware-specific code has moved into individual drivers.

From a security perspective, the HAL is interesting because:
- It runs at PASSIVE_LEVEL IRQL (same as other kernel code)
- It has direct hardware access
- Early bootkit/rootkits replaced or patched the HAL to gain execution before PatchGuard initialized

---

## 5. Object Manager

The Object Manager (`ob`) is arguably the most fundamental NT executive subsystem. It provides a unified namespace, name resolution, security descriptor enforcement, and lifecycle management for all kernel objects.

### 5.1 NT Namespace

The Object Manager maintains a hierarchical namespace accessible through the `\??` (or `\DosDevices`) prefix from user mode. The full NT namespace includes:

```
\                   (root)
├── ??              (symbolic links to DosDevices — user-accessible paths)
│   ├── C:          → \Device\HarddiskVolume3
│   ├── COM1        → \Device\Serial0
│   └── NUL         → \Device\Null
├── DosDevices      (same as \?? on modern Windows)
├── Device          (device objects)
│   ├── HarddiskVolume3
│   ├── Tcp         (network stack)
│   ├── Afd         (Winsock helper)
│   ├── ConDrv      (console driver)
│   └── Cng         (cryptography)
├── Driver          (driver objects)
│   ├── FileSystem
│   └── Disk
├── ObjectTypes     (object type directory)
│   ├── Process
│   ├── Thread
│   ├── File
│   ├── Key
│   ├── Event
│   ├── Mutex
│   └── ...
├── KnownDlls       (mapped DLL sections)
├── BaseNamedObjects(symlinks to session namespaces)
├── RpcControl      (RPC endpoints)
├── Security        (security descriptors for namespace)
└── KernelObjects   (system-wide objects)
    ├── SystemTime
    ├── InitialProcess
    └── NtSecure
```

From user mode, the NT namespace is accessed via the `\??\` prefix (translated through `DosDevices`). The `ObReferenceObjectByHandle` function resolves handles to kernel objects, performing access checks against the object's security descriptor using `SeAccessCheck`.

### 5.2 Object Naming and Symlinks

Objects can be named or unnamed. Named objects are placed in the namespace hierarchy. Symbolic links (`OBJECT_TYPE "SymbolicLink"`) resolve one name to another, enabling the DOS device namespace mapping:

```powershell
# Exploring the NT namespace with WinObj (Sysinternals) or programmatically:
# Using NtQueryDirectoryObject to enumerate \?? (DosDevices)
[System.IO.Directory]::GetFiles("\\.\??\")  # PowerShell approach (limited)

# Using NtQueryObject for detailed information:
Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public class NtApi {
    [DllImport("ntdll.dll")]
    public static extern int NtQueryDirectoryObject(
        IntPtr Handle, IntPtr Buffer, uint Length,
        bool RestartScan, bool ReturnSingleEntry,
        ref uint Context, ref uint ReturnLength);
}
"@
```

### 5.3 Object Reference Counting

Every kernel object maintains a reference count (`OBJECT_HEADER.PointerCount`) and a handle count. The reference count tracks kernel-internal references (e.g., a thread referencing a process object), while the handle count tracks user-visible handles. An object is freed only when its reference count drops to zero. This dual-count system is the source of many vulnerabilities:

- **Use-after-free via reference count underflow**: If `ObfDereferenceObject` is called one too many times, the object may be freed while a dangling reference persists.
- **Handle vs reference count mismatches**: A process with zero handles but non-zero reference count is kept alive by kernel references (e.g., `EPROCESS.ActiveThreads`).

```c
// Object reference counting in kernel:
// ObReferenceObject(ptr)          → increments PointerCount
// ObfDereferenceObject(ptr)       → decrements PointerCount
// ObReferenceObjectByHandle(h, ...) → increments PointerCount, returns object pointer
// ObCloseHandleTableEntry(...)    → decrements HandleCount
```

> **Cross-reference**: Object reference count attacks are detailed in `→ 02b_nt_kernel_vulnerabilities` and `→ 04b_advanced_kernel_exploitation`. The Linux equivalent (kref/kobj) is discussed in `→ linux_kernel` track.

---

## 6. I/O Manager & Driver Architecture

### 6.1 IRP-Based I/O Model

All I/O in Windows is routed through the I/O Manager via IRPs (I/O Request Packets). An IRP is a semi-opaque structure allocated by the I/O Manager that describes an I/O operation:

```c
typedef struct _IRP {
    CSHORT                  Type;               // IO_TYPE_IRP (0x0F / 15)
    USHORT                  Size;               // sizeof(IRP)
    struct _MDL            *MdlAddress;         // Memory Descriptor List
    ULONG                   Flags;              // IRP_* flags
    union {
        struct _IO_STATUS_BLOCK *UserIosb;     // User-mode I/O status block
    } Overlay;
    volatile ULONG          CurrentLocation;     // Current stack location index
    UCHAR                   StackCount;         // Number of IO_STACK_LOCATIONs
    UCHAR                   SizeOfStackLocation;// sizeof(IO_STACK_LOCATION)
    ...
    IO_STATUS_BLOCK         IoStatus;           // Final I/O status
    PIO_STACK_LOCATION      CurrentStackLocation; // Pointer to current IO_STACK_LOCATION
    // ... many more fields
} IRP, *PIRP;
```

Each driver in the device stack processes the IRP through its `IO_STACK_LOCATION`:

```c
typedef struct _IO_STACK_LOCATION {
    UCHAR                   MajorFunction;      // IRP_MJ_* (e.g., IRP_MJ_READ = 3)
    UCHAR                   MinorFunction;      // IRP_MN_* sub-function
    UCHAR                   Flags;              // SL_* flags
    UCHAR                   Control;            // SL_* control flags
    union {
        struct {                                // Parameters for IRP_MJ_READ
            ULONG   Length;                     //     Number of bytes to read
            ULONG   Key;                        //     File key for locked bytes
            LARGE_INTEGER ByteOffset;           //     Starting byte offset
        } Read;
        struct {                                // Parameters for IRP_MJ_WRITE
            ULONG   Length;
            ULONG   Key;
            LARGE_INTEGER ByteOffset;
        } Write;
        struct {                                // Parameters for IRP_MJ_DEVICE_CONTROL
            ULONG   OutputBufferLength;
            ULONG   InputBufferLength;
            ULONG   IoControlCode;             // IOCTL code
            PVOID   Type3InputBuffer;          //METHOD_NEITHER input buffer
        } DeviceIoControl;
        // ... many more union members for each major function
    } Parameters;
    PDRIVER_CANCEL          CancelRoutine;
    PDEVICE_OBJECT          DeviceObject;
    PFILE_OBJECT            FileObject;
    PIRP                    Irp;                // Pointer back to parent IRP
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
```

### 6.2 Driver Loading and Layering

Device drivers in Windows are PE executables (.sys files) loaded by the Service Control Manager (SCM) and the kernel loader. The I/O Manager creates `DRIVER_OBJECT` and `DEVICE_OBJECT` structures:

```
Application (user-mode)
     │
     │ CreateFile("\??\MyDevice") → NtCreateFile()
     │
     ▼
I/O Manager (ntoskrnl.exe)
     │
     │ Creates IRP with IRP_MJ_CREATE
     │ Routes to top of device stack
     ▼
┌──────────────────────┐
│ Upper-edge filter    │  ← Optional filter driver (e.g., antivirus)
├──────────────────────┤
│ Function driver       │  ← Bus or class driver (e.g., disk class)
├──────────────────────┤
│ Lower-edge filter    │  ← Optional filter
├──────────────────────┤
│ Bus driver            │  ← Enumerates child devices (PCI, ACPI)
└──────────────────────┘
     │
     ▼
Hardware (via HAL)
```

Each driver in the stack has its own `IO_STACK_LOCATION` in the IRP. `IoCallDriver` advances to the next stack location and calls the next driver's dispatch routine. This layered architecture is the foundation for filter drivers (used by antivirus, encryption, and monitoring software) and is also a source of vulnerabilities when filter drivers mishandle IRP parameters.

### 6.3 IOCTL Dispatching

User-mode applications communicate with drivers through `DeviceIoControl` (mapped to `NtDeviceIoControlFile`):

```c
// IOCTL code format (4 bytes, split into bit fields):
//   Bits 31-16: Device Type  (FILE_DEVICE_*)
//   Bits 15-14: Required Access (FILE_ANY_ACCESS, FILE_READ, FILE_WRITE)
//   Bits 13-2:  Function Code (driver-defined or system-assigned)
//   Bits 1-0:   Transfer Type (METHOD_BUFFERED, METHOD_IN_DIRECT,
//                                METHOD_OUT_DIRECT, METHOD_NEITHER)
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
```

The method field determines how buffer pointers are interpreted:

| Method | Input Buffer | Output Buffer | Security Implications |
|--------|--------------|---------------|----------------------|
| `METHOD_BUFFERED` | `AssociatedIrp.SystemBuffer` | Same buffer | Safest; I/O Manager copies to/from kernel pool |
| `METHOD_IN_DIRECT` | `SystemBuffer`, MDL for output | MDL-locked pages | Output pages directly from user space |
| `METHOD_OUT_DIRECT` | `SystemBuffer`, MDL for output | MDL-locked pages | Similar to IN_DIRECT |
| `METHOD_NEITHER` | `Parameters.DeviceIoControl.Type3InputBuffer` | `Irp->UserBuffer` | Most dangerous; raw user pointers in kernel |

`METHOD_NEITHER` is the most common source of driver IOCTL vulnerabilities because the kernel directly dereferences user-mode pointers without validation, enabling TOCTOU attacks and arbitrary read/write primitives.

> **Cross-reference**: Linux kernel's equivalent is the `ioctl` interface with `_IOR`, `_IOW`, `_IOWR` macros. See `→ linux_kernel` track for comparison.

---

## 7. Memory Manager

### 7.1 Virtual Address Space Management

The Windows Memory Manager (`mm`) implements demand-paged virtual memory with per-process address spaces. The core tracking structure is the **Virtual Address Descriptor (VAD)** tree:

```
EPROCESS
    │
    └── VadRoot (balanced binary tree of MMVAD structures)
         │
         ├── MMVAD (StartingVpn=0x100, EndingVpn=0x200, Protection=PAGE_READWRITE)
         │     │
         │     └── Represents memory region [0x100000 - 0x200FFF]
         │
         ├── MMVAD (StartingVpn=0x300, EndingVpn=0x400, Protection=PAGE_EXECUTE_READ)
         │     │
         │     └── Represents memory region [0x300000 - 0x400FFF]
         └── ...
```

Each `MMVAD` node describes a contiguous range of virtual pages with uniform protection and commit state. The VAD tree is a balanced splay tree or AVL tree (depending on Windows version) used to quickly resolve page faults and handle `VirtualQuery` calls.

### 7.2 Page Tables and PTEs

Windows uses the x64 four-level page table structure:

```
Virtual Address (48-bit canonical)
┌───────────┬───────────┬───────────┬───────────┬───────────────┐
│ PML4 Index│ PDPT Index│ PD Index  │ PT Index  │ Byte Offset   │
│ (bits 47-39)│(bits 38-30)│(bits 29-21)│(bits 20-12)│(bits 11-0)  │
└───────────┴───────────┴───────────┴───────────┴───────────────┘

Page Table Entry (PTE) format (64-bit):
┌───┬────┬──┬─────┬───┬───┬───┬───┬───┬────┬───┬─────────────────┐
│NX │Rsvd│G │PS   │D  │A  │PCD│PWT│U/S│R/W│P  │Page Frame Number│
│63 │    │  │     │   │   │   │   │   │   │   │                 │
└───┴────┴──┴─────┴───┴───┴───┴───┴───┴───┴───┴─────────────────┘
```

The Memory Manager maintains prototype PTEs for shared/section-mapped pages and creates working set entries (`MMPFN` structures) for pages resident in physical memory.

### 7.3 Pool Allocation

Kernel-mode memory allocation uses two primary pool types (detailed extensively in `→ 03b_pool_corruption_exploitation`):

- **Paged Pool**: Allocatable at `PASSIVE_LEVEL` IRQL only. Can be paged out. Used for larger, less critical allocations. Backed by the system page file.
- **Non-Paged Pool**: Always resident in physical memory. Required at `DISPATCH_LEVEL` IRQL or above. Used for critical kernel structures, DPC data, and interrupt handler contexts.

```c
// Kernel pool allocation patterns:
PVOID buffer = ExAllocatePoolWithTag(PagedPool, size, 'tAmN');  // Non-paged: NonPagedPool
ExFreePoolWithTag(buffer, 'tAmN');

// LFH (Low Fragmentation Heap) bucket sizes for paged/non-paged pool:
// Pool allocations < 4096 bytes are handled by the LFH
// Pool allocations >= 4096 bytes go through the segment heap (Windows 10+) or VM allocator
```

### 7.4 Working Sets and Page Frame Number Database

The `MMPFN` database is a contiguous array that maps physical page frame numbers to their metadata. Each physical page has a corresponding `MMPFN` entry:

```c
typedef struct _MMPFN {
    union {
        ULONG_PTR   PteAddress;        // Pointer to PTE that maps this page
        ULONG_PTR   NonPagedPoolTag;   // Pool tag for non-paged pool
    } u1;
    union {
        struct {
            USHORT      ReferenceCount;
            USHORT      PageLocation;   // Free, Zeroed, Modified, Standby, etc.
        };
    } u2;
    struct _MMPFN     *PteFrame;        // PFN of page table page
    // ...
} MMPFN, *PMMPFN;
```

The PFN database is crucial for understanding physical memory layout and is used in multiple exploitation techniques, particularly for calculating physical addresses from virtual addresses (important for DMA attacks and hypervisor escapes).

---

## 8. Process & Thread Manager

### 8.1 EPROCESS and ETHREAD

The `EPROCESS` structure is the kernel representation of a process. It contains (among hundreds of fields):

```c
// Simplified EPROCESS (varies by Windows version; offsets from WinDBG)
typedef struct _EPROCESS {
    KPROCESS            Pcb;                // +0x000  Embedded KPROCESS
    EX_RUNDOWN_REF      ProcessLock;        // +0x???  Process-wide lock
    LARGE_INTEGER       CreateTime;         // +0x???  Process creation time
    LARGE_INTEGER       ExitTime;           // +0x???  Process exit time
    struct _EX_RUNDOWN_REF RundownProtect; // +0x???  Prevent cross-process access during rundown
    PVOID               DebugPort;          // +0x???  Debug port (for user-mode debugging)
    PVOID               ExceptionPort;      // +0x???  Exception notification port
    struct _EPROCESS    *InheritedFromUniqueProcessId; // Parent PID
    PVOID               ObjectTable;        // +0x???  Process handle table
    PACCESS_TOKEN       Token;              // +0x???  Primary access token (EX_FAST_REF)
    ULONG               ActiveProcessLinks; // +0x???  Doubly-linked list of all EPROCESS
    // ... hundreds more fields
    struct _MMDEREFERENCE_STRUCTURE MmDereferenceInfo;
    ULONG               ProcessFlags;       // PS_PROCESS_FLAGS_*
    ULONG               CreatorPid;        // PID that created this process
    // ... VAD root, working set, section object, image filename ...
} EPROCESS, *PEPROCESS;
```

The `KPROCESS` embedded within `EPROCESS` contains scheduler-related fields:

```c
typedef struct _KPROCESS {
    DISPATCHER_HEADER   Header;             // +0x000  Object header
    LIST_ENTRY          ProfileListHead;    // +0x010
    ULONG               DirectoryTableBase;// +0x028  CR3 value (page table root)
    ULONGLONG           CycleTime;          // +0x030  CPU cycle time
    ULONG               ReadyListHead;      // +0x???  Ready thread list
    LIST_ENTRY          ThreadListHead;     // +0x???  All threads in process
    SCHAR               BasePriority;       // +0x???  Process base priority
    UCHAR               QuantumReset;      // +0x???  Time quantum
    // ... scheduling state, ideal node, etc.
} KPROCESS, *PKPROCESS;
```

The `ETHREAD` structure wraps `KTHREAD` with additional process-specific data:

```c
typedef struct _ETHREAD {
    KTHREAD             Tcb;                // +0x000  Embedded KTHREAD
    LARGE_INTEGER       CreateTime;         // +0x???  Thread creation time
    union {
        LARGE_INTEGER   ExitTime;           // +0???   Thread exit time
    };
    PVOID               Win32StartAddress;  // +0x???  Actual start address (after thunk)
    PVOID               StartAddress;       // +0x???  Start address passed to CreateThread
    struct _EPROCESS    *Process;           // +0x???  Back-pointer to EPROCESS
    // ... TLS, impersonation token, APC state ...
} ETHREAD, *PETHREAD;
```

### 8.2 Process Creation Internals

Windows process creation follows a complex sequence:

```
NtCreateUserProcess (or NtCreateProcessEx for native processes)
    │
    ├── 1. Allocate EPROCESS from non-paged pool
    ├── 2. Initialize KPROCESS (DirectoryTableBase, etc.)
    ├── 3. Create primary access token (duplicate parent or specified)
    ├── 4. Set up VAD root and initial memory mappings (image, NTDLL, PEB)
    ├── 5. Create initial thread (ETHREAD)
    ├── 6. Allocate kernel stack and user stack
    ├── 7. Initialize thread context (start address = KiStartUserThread)
    ├── 8. Map ntdll.dll and set up LDR structures
    ├── 9. Create PEB (Process Environment Block) in user space
    ├── 10. Insert process into ActiveProcessLinks list
    ├── 11. Signal process creation (PsProcessType notification)
    └── 12. Resume initial thread → begins executing at KiStartUserThread
                                  → calls NtProcessStartup in ntdll
                                  → calls process entry point
```

Notably, the Windows process creation model uses a section-based approach: the executable image is mapped as a section object (`SECTION`), and the initial thread begins execution in kernel mode before transitioning to user mode at `KiStartUserThread`. This contrasts with the Unix fork/exec model and has significant security implications (e.g., process vacating, process hollowing, and token replacement attacks — see `→ 04a_windows_exploitation_techniques`).

---

## 9. NT Namespace & NTAPI

### 9.1 NTAPI — The Native API

The Native API (`ntdll.dll`) is the lowest-level user-mode interface to the NT kernel. Every Win32, POSIX, or other subsystem API eventually calls into `ntdll.dll` which transitions to kernel mode via `syscall`. The NTAPI is not officially documented by Microsoft (though many functions are documented through the WDK and有的 through the SDK). Key categories include:

```c
// NTAPI function naming convention:
// Nt*  → functions callable from user mode
// Zw*  → kernel-mode entry points (identical implementation, different IRQL handling)
//
// Key NTAPI categories:
NtCreateProcess / NtOpenProcess           // Process management
NtCreateThread / NtOpenThread             // Thread management
NtAllocateVirtualMemory / NtFreeVirtualMemory  // Memory management
NtReadVirtualMemory / NtWriteVirtualMemory    // Cross-process memory access
NtCreateFile / NtReadFile / NtWriteFile   // I/O
NtCreateKey / NtSetValueKey / NtQueryValueKey  // Registry
NtCreateSection / NtMapViewOfSection     // Shared memory
NtCreateEvent / NtSetEvent / NtWaitForSingleObject // Synchronization
NtConnectPort / NtRequestWaitReplyPort   // LPC/ALPC
NtQuerySystemInformation                 // System-wide queries
NtQueryInformationProcess / NtSetInformationProcess  // Process info
NtQueryInformationToken / NtSetInformationToken      // Token manipulation
NtAccessCheck / NtAccessCheckAndAuditAlarm  // Security
```

The `Zw*` functions are the kernel-mode equivalents. When called from kernel mode, they bypass access checks (since the previous mode is `KernelMode`) and skip security descriptor validation. This distinction is crucial: calling `NtCreateFile` from kernel mode validates access based on the caller's token, while `ZwCreateFile` uses the system token — a common source of privilege escalation vulnerabilities in drivers.

### 9.2 NT Namespace Security

The Object Manager enforces security on namespace operations. When a user-mode process calls `NtCreateFile(L"\\Device\\MyDevice", ...)`, the Object Manager:

1. Parses the path through the namespace tree
2. Looks up the named object
3. Calls `SeAccessCheck` with the caller's token against the object's security descriptor
4. Creates a handle with granted access mask

The security check occurs at handle creation time. Once a handle is opened, the granted access is cached in the handle table entry and no further access checks are performed unless the handle is used in specific operations (e.g., `NtSetSecurityObject`).

This has a critical implication: if a process can obtain a handle to a high-privilege object (e.g., through handle inheritance, duplication, or direct open with excessive access), the security boundary is permanently crossed for that handle's lifetime.

---

## 10. APCs — Asynchronous Procedure Calls

### 10.1 APC Architecture

Asynchronous Procedure Calls (APCs) are the NT kernel's primary mechanism for executing code in the context of a specific thread, at a specific IRQL, potentially in a different address space. APCs are essential for:

- **I/O completion**: Overlapped I/O uses kernel APCs to deliver completion notifications
- **Thread termination**: `NtTerminateThread` queues a kernel APC to force thread exit
- **Thread suspension**: `NtSuspendThread` queues an APC that enters a wait
- **User-mode callbacks**: Win32k uses user-mode APCs to deliver window messages
- **DLL injection**: `QueueUserAPC` can force a thread to execute code in user mode

There are three APC modes corresponding to three IRQL levels:

| APC Mode | IRQL | Can be Interrupted By | Typical Use |
|----------|------|----------------------|-------------|
| **Kernel APC** | `APC_LEVEL` | DISPATCH_LEVEL interrupts | I/O completion, thread suspension |
| **Special Kernel APC** | `APC_LEVEL` (delivered even when kernel APCs disabled) | DISPATCH_LEVEL interrupts | Critical kernel operations |
| **User APC** | `PASSIVE_LEVEL` | All kernel APCs | `QueueUserAPC`, thread pool callbacks |

### 10.2 APC Internals

```c
typedef struct _KAPC {
    UCHAR               Type;               // APC object type
    UCHAR               SpareByte1;
    UCHAR               Size;               // Size of KAPC structure
    ULONG               SpareLong;
    struct _KTHREAD     *Thread;            // Target thread
    LIST_ENTRY          ApcListEntry;       // Entry in target thread's APC list
    PVOID               KernelRoutine;      // Called at APC_LEVEL before NormalRoutine
    PVOID               RundownRoutine;     // Called if thread is terminated
    PVOID               NormalRoutine;      // Main APC routine (kernel or user mode)
    PVOID               NormalContext;      // Context for NormalRoutine
    PVOID               SystemArgument1;    // Additional args
    PVOID               SystemArgument2;
    CCHAR               ApcStateIndex;      // Which APC list (OriginalApcEnvironment, etc.)
    UCHAR               ApcMode;            // KernelMode or UserMode
    BOOLEAN             Inserted;           // Whether APC is on a list
} KAPC, *PKAPC;
```

APCs are stored in the target thread's `KTHREAD.ApcState.ApcListHead[KernelMode]` and `KTHREAD.ApcState.ApcListHead[UserMode]`. The kernel delivers pending APCs when the thread returns to the target mode from kernel mode (at `KiDeliverApc`).

### 10.3 APC Exploitation

APCs are a powerful tool for both legitimate kernel programming and exploitation:

- **User APC injection**: `NtQueueApcThread` can force a thread in another process to execute code at `PASSIVE_LEVEL` in user mode. This is used for DLL injection and is monitored by EDR products.
- **Kernel APC hijacking**: Modifying the `KernelRoutine` or `NormalRoutine` function pointers in a queued KAPC redirects execution. This is a classic rootkit technique.
- **APC delivery race conditions**: If an APC is queued between a security check and the operation it guards, the security check result may be invalidated. This pattern is seen in multiple Windows vulnerabilities (e.g., CVE-2020-0787 — Windows Background Intelligent Transfer Service EoP).
- **Special user APC**: `NtQueueApcThreadEx` with `USER_APC_OPTION` allows queuing a user APC that will wake a thread even in an alertable wait — used for thread hijacking and injection.

> **Cross-reference**: APC-based exploitation is discussed in `→ 04a_windows_exploitation_techniques` and `→ 04b_advanced_kernel_exploitation`. The Linux equivalent is tasklet/softirq mechanism (`→ linux_kernel` track).

---

## 11. DPCs — Deferred Procedure Calls

### 11.1 DPC Architecture

Deferred Procedure Calls (DPCs) provide a mechanism to defer interrupt-related processing from `DIRQL` (Device IRQL) to `DISPATCH_LEVEL`. This is essential because ISRs must complete quickly — they run at high IRQL where other interrupts are blocked. DPCs allow the ISR to schedule deferred work:

```c
typedef struct _KDPC {
    UCHAR               Type;               // DPC object type
    UCHAR               Importance;         // LowImportance, MediumImportance, HighImportance
    LIST_ENTRY          DpcListEntry;        // Entry in per-processor DPC queue
    PVOID               DeferredRoutine;     // Function to call at DISPATCH_LEVEL
    PVOID               DeferredContext;    // Context for DeferredRoutine
    PVOID               SystemArgument1;    // Additional args
    PVOID               SystemArgument2;
    struct _KDPC       *DpcData;            // Pointer to DPC data structure
} KDPC, *PKDPC;
```

DPCs execute at `DISPATCH_LEVEL` on the target processor in FIFO order. The scheduler runs DPCs when IRQL drops from `DIRQL` to `DISPATCH_LEVEL`, or when the system timer fires. Because DPCs run at `DISPATCH_LEVEL`, they cannot be preempted by normal thread scheduling — this makes DPCs suitable for time-critical operations but also creates a potential for priority inversion and starvation.

### 11.2 Timer DPCs and Expiration

Timer objects (`KTIMER`) use DPCs for expiration notification:

```c
// When a timer expires, the kernel queues the associated DPC:
KeInitializeTimerEx(&Timer, NotificationTimer);
KeInitializeDpc(&Dpc, TimerCallback, Context);
KeSetTimerEx(&Timer, DueTime, Period, &Dpc);  // Period=0 for one-shot
```

Timer DPCs are critical security targets because:
- They run at `DISPATCH_LEVEL` (no thread context, no preemption)
- They can be used to implement periodic execution without a driver-visible thread
- PatchGuard uses timer DPCs to verify kernel integrity

### 11.3 DPC Security Implications

- **DPC queue manipulation**: Rootkits can insert custom DPCs into a processor's DPC queue to gain execution at `DISPATCH_LEVEL`. PatchGuard detects unauthorized DPC modifications.
- **DPC race conditions**: Since DPCs run at `DISPATCH_LEVEL`, they can preempt `PASSIVE_LEVEL` code. If a `PASSIVE_LEVEL` operation holds a lock that a DPC also acquires, the system deadlocks (since `DISPATCH_LEVEL` preempts the lock holder but the DPC can't wait for the lock to be released). This is a common source of kernel deadlocks.

---

## 12. Critical Sections & Synchronization Primitives

### 12.1 Kernel Synchronization

NT provides multiple synchronization mechanisms, each with different IRQL constraints and properties:

| Primitive | IRQL Requirement | Mode | Wait | Use Case |
|-----------|-----------------|------|------|----------|
| Spin Lock (`KSPIN_LOCK`) | `DISPATCH_LEVEL` | Kernel | No | Short critical sections in ISR/DPC |
| Queued Spin Lock (`KSPIN_LOCK_QUEUE`) | `DISPATCH_LEVEL` | Kernel | No | Scalable spin lock for multi-processor |
| Fast Mutex (`FAST_MUTEX`) | `PASSIVE_LEVEL` or `APC_LEVEL` | Kernel | Yes | Mutual exclusion with Paged Pool |
| Guarded Mutex (`KGUARDED_MUTEX`) | `PASSIVE_LEVEL` | Kernel | Yes | Optimized mutex (Guarded IRQL) |
| Executive Resource (`ERESOURCE`) | `PASSIVE_LEVEL` | Kernel | Yes | Read-write lock with recursion |
| Push Lock (`EX_PUSH_LOCK`) | `PASSIVE_LEVEL` | Kernel | Yes | Lightweight read-write lock |
| Kernel Event (`KEVENT`) | Any | Kernel | Yes | Notification/synchronization |
| Kernel Semaphore (`KSEMAPHORE`) | `PASSIVE_LEVEL` | Kernel | Yes | Counted resource management |
| Kernel Mutex (`KMUTEX`) | `PASSIVE_LEVEL` | Kernel | Yes | Heavyweight mutual exclusion |
| Critical Section (`RTL_CRITICAL_SECTION`) | `PASSIVE_LEVEL` | User | Yes | User-mode mutual exclusion |

### 12.2 User-Mode Critical Sections

User-mode critical sections (`CRITICAL_SECTION`) are the Win32 equivalent of kernel mutexes, optimized for intra-process synchronization:

```c
typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;  // +0x00  Debug info
    LONG                   LockCount;       // +0x08  -1 = unowned
    LONG                   RecursionCount;  // +0x0C  Recursion depth
    HANDLE                 OwningThread;    // +0x10  Thread ID of owner
    HANDLE                 LockSemaphore;   // +0x14  Kernel event (allocated on contention)
    ULONG                  SpinCount;       // +0x18  Spin count before wait
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
```

Key details:
- `LockCount` starts at -1 (unowned). On `EnterCriticalSection`, it's incremented. If the result is >= 0, another thread owns it and the caller waits on `LockSemaphore`.
- `OwningThread` stores the thread ID, not a thread handle.
- `LockSemaphore` is a lazily-allocated kernel event object (created on first contention) — this is why initializing a critical section never fails.
- `SpinCount` (set via `InitializeCriticalSectionAndSpinCount`) controls how many iterations the thread spins before blocking. On single-processor systems, this is ignored.

Critical sections are important for security research because:
- They are not cross-process (unlike mutexes), so they cannot be used for inter-process synchronization
- They are vulnerable to lock-ordering deadlocks (two threads acquiring two critical sections in opposite order)
- The `LockSemaphore` handle can be enumerated via `NtQueryInformationProcess` — process handle scanning tools use this

### 12.3 Interlocked Operations and Memory Barriers

NT provides atomic operations through the `Interlocked*` family and compiler barriers:

```c
// Kernel-mode atomic operations:
InterlockedIncrement(&count);           // ++count (atomic)
InterlockedDecrement(&count);           // --count (atomic)
InterlockedCompareExchange(&target, newval, expected);  // CAS
InterlockedExchangePointer(&ptr, newptr);  // Atomic pointer swap

// Memory barriers:
KeMemoryBarrier();          // Full barrier (compiler + CPU)
KeMemoryBarrierWithoutFence(); // Compiler barrier only
_ReadWriteBarrier();         // MSVC compiler barrier
```

On x64, all stores are release-ordered and all loads are acquire-ordered by default (strong memory model), but explicit barriers are still needed for:
- Lock-free data structure access in multi-processor systems
- Ensuring store visibility before flag checks (the store-buffer drain must complete)
- Interaction with device registers (MMIO)

---

## 13. Security Research Implications

### 13.1 Attack Surface Mapping

Understanding the NT architecture is essential for mapping the Windows attack surface:

| Attack Surface | Entry Point | Typical Vulnerability Classes |
|---------------|-------------|------------------------------|
| NT syscalls | `ntdll.dll` → `syscall` | TOCTOU, race conditions, input validation |
| Win32k syscalls | `win32k.sys` → `NtUser*`/`NtGdi*` | Type confusion, UAF, pool corruption |
| Driver IOCTLs | `NtDeviceIoControlFile` | Buffer validation, METHOD_NEITHER issues |
| ALPC ports | `NtConnectPort`, `NtRequestWaitReplyPort` | Message validation, port impersonation |
| Registry | `NtCreateKey`, `NtSetValueKey` | Symbolic link attacks, ACL bypass |
| Named objects | Object Manager namespace | Symlink attacks, DACL misconfiguration |
| Process/thread | `NtCreateProcess`, `NtCreateThread` | Token substitution, handle inheritance |

### 13.2 Kernel Debugging Prerequisites

Security research on Windows requires setting up a kernel debugging environment:

```
Recommended Setup:
1. Host: Windows 11 Pro/Enterprise + WinDBG Preview (from Microsoft Store)
2. Target: Windows 10/11 VM (Hyper-V, VMware, or VirtualBox)
3. Connection: Network debugging (KDNET) or Serial (COM1)
4. Symbols: .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
5. Extensions: .load kdexts, .load win32kext (for Win32k debugging)

WinDBG commands for architecture exploration:
!process 0 0                    List all processes
!thread                         Current thread info
!object \??\C:                  Object Manager namespace
!pool <address>                 Pool header analysis
!pte <address>                  Page table entry
!apc                            APC list analysis
!drvobj <driver>                Driver object info
!devobj <device>                Device object info
```

### 13.3 Key Research Tools

| Tool | Purpose | Source |
|------|---------|--------|
| **WinDBG / cdb** | Kernel/user debugging | Microsoft |
| **IDA Pro / Ghidra** | Static analysis of `ntoskrnl.exe`, `win32k.sys`, drivers | Hex-Rays / NSA |
| **SystemTap / ETW** | Dynamic tracing | Microsoft |
| **PoolMon** | Pool tag monitoring | Sysinternals |
| **WinObj** | Object Manager namespace viewer | Sysinternals |
| **AccessChk** | ACL analysis | Sysinternals |
| **Process Monitor** | Syscall/file/registry monitoring | Sysinternals |
| **OSR Driver Loader** | Test driver loading | OSR Online |

---

> **Cross-references**: This document provides the foundation for the entire Windows Security track. The architecture described here is exploited throughout subsequent documents:
> - Security model → `→ 01b_windows_security_architecture`
> - Win32k attack surface → `→ 02a_win32k_kernel_attack_surface`
> - Kernel vulnerability patterns → `→ 02b_nt_kernel_vulnerabilities`
> - Memory protections → `→ 03a_windows_memory_protections`
> - Pool corruption → `→ 03b_pool_corruption_exploitation`
> - Exploitation techniques → `→ 04a_windows_exploitation_techniques` and `→ 04b_advanced_kernel_exploitation`
> - OSEE preparation → `→ OSEE` track
> - Linux comparison → `→ linux_kernel` track
> - CPU-level implications → `→ ring_and_vulns` track

---

## References

1. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 1*, 7th Edition. Microsoft Press, 2017. — Chapters 1–3: System Architecture, System Mechanisms, and Executive Subsystems.
2. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 2*, 7th Edition. Microsoft Press, 2021. — Memory Manager, I/O Manager, and Cache Manager internals.
3. Microsoft Learn. "Windows NT Architecture." <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/architecture-portal>
4. Yason, M. "Windows Heap Exploitation." *Black Hat USA*, 2019. — Pool allocator internals and segment heap architecture.
5. Ionescu, A. "What Is It Like to Work on Windows?" *Recon*, 2019. — Executive subsystem design rationale.
6. Dullien, H. "Windows NT Syscall Interface." *Black Hat Europe*, 2018. — NTAPI system call dispatch and SDT structure.
7. MITRE ATT&CK. "Windows Management Instrumentation — T1047." <https://attack.mitre.org/techniques/T1047/>
8. National Vulnerability Database. CVE-2021-1675. "Windows Print Spooler EoP." <https://nvd.nist.gov/vuln/detail/CVE-2021-1675>
9. Nagy, D. "Object Manager Internals." *OpenRCE*, 2015. — Object Manager namespace, handle tables, and security descriptor logic.
10. Microsoft Learn. "Asynchronous Procedure Calls (APCs)." <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs>
11. Probert, D. "Inside Windows: A Look at the NT Architecture." *USENIX*, 1998. — Foundational NT layered architecture paper.
12. Microsoft Security Response Center (MSRC) Blog. <https://msrc.microsoft.com/blog/> — Ongoing NT kernel vulnerability disclosures.
13. Johnson, R. "Windows DPC Architecture and Implications." *Microsoft Docs*, 2020. — DPC queue, priority, and real-time implications.
14. Finally, A. "ReactOS: Open-Source Windows NT Clone Architecture Documentation." <https://reactos.org/wiki/Architecture> — Public documentation of NT architecture derived from reverse engineering.