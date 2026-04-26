# OSEE Skill-Building Roadmap: From Intermediate to Expert

## A Detailed Technical Preparation Guide for the OffSec Exploitation Expert (OSEE) Certification

---

## Table of Contents

1. [Overview and Context](#1-overview-and-context)
2. [Phase 1: Foundations](#2-phase-1-foundations-months-1-3)
3. [Phase 2: Basic Exploitation](#3-phase-2-basic-exploitation-months-4-6)
4. [Phase 3: Intermediate Exploitation](#4-phase-3-intermediate-exploitation-months-7-10)
5. [Phase 4: Advanced Exploitation](#5-phase-4-advanced-exploitation-months-11-15)
6. [Phase 5: Expert-Level Mastery](#6-phase-5-expert-level-mastery-months-16-20)
7. [Practice Exercises by Phase](#7-practice-exercises-by-phase)
8. [Tool Mastery Checklist](#8-tool-mastery-checklist)
9. [Self-Assessment and Readiness Criteria](#9-self-assessment-and-readiness-criteria)
10. [Time and Financial Investment](#10-time-and-financial-investment)
11. [Recommended Study Resources](#11-recommended-study-resources)

---

## 1. Overview and Context

### What is OSEE?

The OffSec Exploitation Expert (OSEE) is the most advanced certification offered by OffSec (formerly Offensive Security). It is earned by passing the exam associated with EXP-401: Advanced Windows Exploitation (AWE), a course delivered exclusively through in-person, hands-on training due to the extensive learner-instructor interaction required.

### Exam Format

- **Duration**: 71 hours and 45 minutes of active exam time
- **Format**: Proctored, remote lab environment accessed via VPN
- **Objectives**: Two assignments, each worth up to 50 points (25 for partial, 50 for full completion)
- **Passing score**: 75 out of 100 points
- **Deliverable**: Comprehensive penetration test report in PDF format, due within 24 hours of exam end
- **Reverts**: 50 total machine reverts allowed during the exam

### Course Topics (EXP-401)

According to OffSec's official materials, EXP-401 covers:

- Bypass and evasion of user mode security mitigations
- Advanced heap manipulations
- Disarming WDEG (Windows Defender Exploit Guard) mitigations and creating version independence
- Bypass of kernel mode security mitigations

### Prerequisites (Per OffSec)

- Experience developing Windows exploits
- Proficiency with a debugger (particularly WinDbg)
- Familiarity with x86_64 assembly
- Familiarity with IDA Pro
- Basic C/C++ programming ability
- Completion of 300-level OffSec certifications is recommended (OSED/OSEP/OSWE)

### Who This Roadmap Is For

This roadmap assumes you are an intermediate-level security professional who has some programming experience and a basic understanding of how computers work at a low level, but has not yet written exploits for modern Windows systems. It takes you from that starting point through to exam readiness.

---

## 2. Phase 1: Foundations (Months 1-3)

**Goal**: Build the core knowledge base that every subsequent phase depends on.

### 2.1 x86 and x86_64 Assembly Language

You must be able to read and write assembly fluently. This is non-negotiable for OSEE.

#### Key Concepts to Master

- Registers (general purpose, segment, flags, instruction pointer)
- x86 vs x86_64 differences (register extensions, calling conventions, additional registers R8-R15)
- Stack operations: PUSH, POP, CALL, RET, LEAVE
- Arithmetic and logic: ADD, SUB, AND, OR, XOR, SHL, SHR, ROL, ROR
- Memory access: MOV, LEA, effective addressing modes
- Control flow: JMP, Jcc (conditional jumps), LOOP, CMP, TEST
- String operations: REP MOVSB, REP STOSB, SCASB
- System-level: INT, SYSCALL, SYSENTER
- x64 calling convention (Windows): RCX, RDX, R8, R9 for first four integer arguments; shadow space
- x86 calling conventions: stdcall, cdecl, fastcall, thiscall

#### Exercises

1. **Disassembly reading**: Take 10 small C programs, compile them with MSVC (both Debug and Release, x86 and x64), and read the disassembly in IDA or WinDbg. Map each C construct to its assembly equivalent.
2. **Handwritten assembly**: Write the following in NASM or MASM:
   - A function that computes Fibonacci numbers
   - A function that copies memory (your own memcpy)
   - A function that searches for a byte pattern in a buffer
   - A program that calls Windows API functions (MessageBoxA, ExitProcess) via direct assembly
3. **Calling convention drill**: Write a C program with functions using different calling conventions. Step through in WinDbg and verify register/stack state at each CALL and RET.

#### Milestone

You can look at a disassembly listing of a function you have never seen before and accurately describe what it does within 5 minutes.

### 2.2 C/C++ Programming

Exploit development at this level is inseparable from C/C++ fluency.

#### Key Concepts to Master

- Pointers, pointer arithmetic, double pointers, function pointers
- Memory layout: stack frames, heap allocations, global/static data, code segments
- Dynamic memory: malloc/free, new/delete, HeapAlloc/HeapFree
- Structures, unions, bitfields, alignment, and padding
- Type casting, integer promotion rules, integer truncation
- Linked lists, trees, and hash tables implemented in C
- Buffer operations: memcpy, memset, strcpy and their security implications
- Preprocessor macros, function-like macros, conditional compilation
- C++ specifics: vtables, virtual function dispatch, object layout, RTTI, exceptions

#### Exercises

1. Implement a singly-linked list in C with insert, delete, search, and free operations. Run under Application Verifier to check for memory errors.
2. Write a C program that deliberately contains:
   - A stack buffer overflow
   - A heap buffer overflow
   - A use-after-free
   - An integer overflow leading to a small allocation
   - A format string vulnerability
   Then compile each and analyze the crash in WinDbg.
3. Write a simple TCP client/server in C using Winsock2. Have the server parse a binary protocol with length-prefixed fields (this mirrors real-world vulnerability patterns).
4. Study the layout of a C++ object with virtual functions. Use WinDbg to dump the vtable pointer and trace virtual function dispatch.

#### Milestone

You can write a working Windows C program from scratch that uses Winsock, file I/O, and heap allocations, compile it, and debug it in WinDbg without referencing documentation for basic operations.

### 2.3 Windows API and Internals Fundamentals

#### Key Concepts to Master

- Process and thread creation: CreateProcess, CreateThread, NtCreateThreadEx
- Memory management: VirtualAlloc, VirtualProtect, VirtualQuery, NtAllocateVirtualMemory
- Heap API: HeapCreate, HeapAlloc, HeapFree, RtlAllocateHeap, the NT Heap vs Segment Heap
- File and registry operations
- DLL loading: LoadLibrary, GetProcAddress, DLL search order
- Handles and kernel objects
- Structured Exception Handling (SEH): _try/_except, exception dispatcher chain
- Vectored Exception Handling (VEH)
- Token and privilege model: access tokens, SIDs, integrity levels
- User mode vs kernel mode transitions (syscalls, SSDT)
- PEB (Process Environment Block) and TEB (Thread Environment Block) structures
- PE file format: DOS header, PE header, sections, imports, exports, relocations

#### Exercises

1. Write a program that enumerates all loaded modules in a target process by walking the PEB->Ldr->InMemoryOrderModuleList.
2. Write a program that resolves API addresses by hash (the technique used in shellcode).
3. Write a program that creates a remote thread in another process (basic DLL injection).
4. Parse a PE file from disk: print all sections, their RVAs, sizes, and characteristics. Print the import table and export table.
5. Write a program that uses VirtualAlloc to allocate RWX memory, copies shellcode into it, and executes it.

#### Milestone

You can explain the journey of a function call from user mode (e.g., `CreateFile`) through ntdll.dll, into the kernel (via syscall), and back, identifying every major structure and transition point.

### 2.4 Phase 1 Study Resources

| Resource | Topic | Type |
|----------|-------|------|
| *Windows Internals, 7th Ed.* (Russinovich, Solomon, Ionescu) — Part 1 & Part 2 | Windows OS internals | Book |
| *Programming Windows, 5th Ed.* (Petzold) or Microsoft Learn docs | Windows API programming | Book/Docs |
| *Intel 64 and IA-32 Architectures Software Developer Manuals* (Volumes 1-3) | x86/x64 ISA reference | Manual |
| *Practical Malware Analysis* (Sikorski, Honig) — Chapters 1-7 | Assembly reading, PE format, IDA basics | Book |
| OpenSecurityTraining2: Architecture 1001 (x86-64) | x86_64 assembly | Free online course |
| *The C Programming Language* (K&R) | C fundamentals | Book |
| FuzzySecurity: Intel Syntax Reference Guide | x86 assembly quick ref | Web tutorial |

---

## 3. Phase 2: Basic Exploitation (Months 4-6)

**Goal**: Develop the ability to discover and exploit classic memory corruption vulnerabilities on Windows.

### 3.1 Stack Buffer Overflows

#### Key Concepts to Master

- Overwriting saved return pointer (EIP/RIP control)
- Determining offset to EIP (pattern_create/pattern_offset, or cyclic patterns)
- Finding and using JMP ESP / CALL ESP gadgets
- Bad character analysis
- Controlling execution flow with shellcode
- Differences between x86 and x64 exploitation

#### Exercises

1. **Corelan Tutorial Series** (Parts 1-2): Work through Peter Van Eeckhoutte's classic exploit writing tutorials:
   - Part 1: Stack Based Overflows
   - Part 2: Jumping to Shellcode
2. **Exploit Education — Phoenix**: Complete Stack Zero through Stack Six
3. **Exploit Education — Protostar**: Complete Stack Zero through Stack Seven (overlaps with Phoenix but uses a different environment)
4. **Custom exercise**: Find 3 old CVEs for Windows applications with known stack overflow vulnerabilities (pre-DEP/ASLR era). Set up the vulnerable application in a Windows XP or 7 VM and reproduce the exploit from scratch:
   - Suggested: Ability FTP Server (CVE-2004-1626), Easy File Sharing Web Server, WarFTPD 1.65
5. Write your own minimal vulnerable server in C (listens on a TCP port, has a strcpy-based overflow). Exploit it.

#### Milestone

Given an unknown Windows application with a simple stack overflow, you can independently identify the vulnerability, determine the offset, find a usable instruction pointer redirect, and achieve code execution within 4 hours.

### 3.2 SEH-Based Exploits

#### Key Concepts to Master

- How the Windows exception dispatcher walks the SEH chain
- Overwriting the SEH handler and next SEH pointer
- POP/POP/RET technique
- Short jump from nSEH to shellcode
- SafeSEH and how to find non-SafeSEH modules
- SEHOP (SEH Overwrite Protection) and its validation logic

#### Exercises

1. **Corelan Tutorial Series** (Parts 3, 3b): SEH Based Exploits
2. **Corelan Tutorial Series** (Part 6): Bypassing Stack Cookies, SafeSEH, SEHOP
3. Reproduce at least 2 real SEH-based CVE exploits:
   - Suggested: Soritong MP3 Player, DVD X Player, Winamp (various old versions)
4. Write a vulnerable application that triggers an exception after a buffer overflow. Exploit it via SEH overwrite.

#### Milestone

You understand exactly why POP/POP/RET works in the context of the exception dispatcher, and you can exploit SEH overflows even when some modules are compiled with SafeSEH.

### 3.3 Basic Return-Oriented Programming (ROP)

#### Key Concepts to Master

- What DEP (Data Execution Prevention) is and why direct shellcode execution fails
- The concept of gadgets (instruction sequences ending in RET)
- Building a ROP chain to call VirtualProtect or VirtualAlloc to make memory executable
- Using mona.py to find ROP gadgets
- Stack pivoting basics
- Differences in ROP between x86 (stack-based arguments) and x64 (register-based arguments)

#### Exercises

1. **Corelan Tutorial Series** (Part 10): Chaining DEP with ROP — the Rubik's Cube
2. Take one of your stack overflow exploits from 3.1 and re-exploit it with DEP enabled, using ROP to bypass DEP.
3. **FuzzySecurity Tutorial Part 7**: Return Oriented Programming
4. Write a ROP chain from scratch (without mona.py's auto-generation) for a simple application. You should manually find gadgets, understand alignment, and chain them.
5. **Practice CVE**: Reproduce a ROP-based exploit for a publicly documented vulnerability:
   - Suggested: Various Foxit Reader vulnerabilities, older Adobe Reader versions

#### Milestone

You can build a working ROP chain from scratch to call `VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READWRITE, &old)` on an application where you manually located all gadgets.

### 3.4 Egg Hunters and Staged Payloads

#### Key Concepts to Master

- When and why egg hunters are needed (small buffer constraints)
- NTAccessCheckAndAuditAlarm-based egg hunter
- SEH-based egg hunters
- WoW64 considerations for egg hunters
- Multi-stage shellcode delivery

#### Exercises

1. **Corelan Tutorial Series** (Part 8): Win32 Egg Hunting
2. **Corelan**: WoW64 Egghunter
3. Take an exploit with limited buffer space and implement an egg hunter solution.

#### Milestone

You know when to reach for an egg hunter vs. other approaches, and can implement one from memory.

### 3.5 Phase 2 Study Resources

| Resource | Topic | Type |
|----------|-------|------|
| Corelan Exploit Writing Tutorials (Parts 1-10) | Full exploit development progression | Web tutorials |
| FuzzySecurity Windows Exploit Dev Series (Parts 1-9) | Windows exploit development | Web tutorials |
| Exploit Education: Phoenix and Protostar | Stack, format string, heap basics | VM-based labs |
| *Hacking: The Art of Exploitation, 2nd Ed.* (Erickson) | Foundational exploitation concepts | Book |
| *The Shellcoder's Handbook* (Anley et al.) | Exploit development reference | Book |
| mona.py documentation (corelan.be) | ROP gadget finding, exploit dev automation | Tool docs |

---

## 4. Phase 3: Intermediate Exploitation (Months 7-10)

**Goal**: Master heap exploitation, custom shellcode development, and achieve deep proficiency with WinDbg.

### 4.1 Heap Exploitation on Windows

This is a critical area for OSEE. The exam explicitly tests "advanced heap manipulations."

#### Key Concepts to Master

- **Windows Heap Architecture**:
  - NT Heap (Front-end: LFH — Low Fragmentation Heap; Back-end: free lists, segment heap)
  - Segment Heap (Windows 10+): Variable size, LFH, Large blocks, VS subsegment
  - Heap metadata structures: _HEAP, _HEAP_ENTRY, _HEAP_SEGMENT, _LFH_HEAP, _HEAP_BUCKET
  - Encoding/decoding of heap chunk headers
- **Heap Overflow Exploitation**:
  - Overwriting adjacent heap metadata
  - Overwriting adjacent application data (more common in modern heaps)
  - Heap grooming / heap feng shui: controlling allocation layout
- **Use-After-Free (UAF)**:
  - Understanding object lifetime bugs
  - Heap spray to reclaim freed objects
  - Type confusion via UAF
  - Controlling allocation sizes to ensure reclamation
- **Heap Spray Techniques**:
  - JavaScript-based heap spraying (for browser targets)
  - Precise heap spray (DEPS technique from Corelan)
  - LFH determinism for reliable exploitation
- **Double Free and related corruption**

#### Exercises

1. **FuzzySecurity**: "Heap Overflows For Humans" series (Parts 101-103.5) by mr_me
2. **Corelan**: "Heap Spraying Demystified" (Part 11)
3. **Corelan**: "DEPS - Precise Heap Spray on Firefox and IE10"
4. **Corelan**: "Heap Layout Visualization with mona.py and WinDBG"
5. **Corelan**: "Windows 10 x86/wow64 Userland heap"
6. **Hands-on heap grooming**: Write a C program that makes many allocations of various sizes, frees some, and allocates again. Use WinDbg `!heap` commands to observe layout. Practice predicting where new allocations will land.
7. **HEVD (HackSys Extreme Vulnerable Driver)** — User-mode heap exercises:
   - Pool Buffer Overflow (NonPagedPool)
   - Pool Buffer Overflow (NonPagedPoolNx)
   - Pool Buffer Overflow (PagedPoolSession)
   - Use After Free (NonPagedPool)
   - Use After Free (NonPagedPoolNx)
8. **CVE Reproduction**: Reproduce a heap-based UAF exploit:
   - Suggested: IE UAF CVEs (e.g., CVE-2014-1776), older Firefox UAFs
   - Study the BlackHat EU 2013 talk: "Advanced Heap Manipulation in Windows 8"

#### Milestone

Given a UAF in an application, you can determine the object size, groom the heap to reclaim the freed slot with controlled data, and redirect execution. You can explain the difference between NT Heap and Segment Heap exploitation constraints.

### 4.2 Shellcoding

#### Key Concepts to Master

- Position-independent code (PIC) principles
- Finding kernel32.dll base via PEB->Ldr
- Resolving API addresses by walking export tables
- Hash-based API resolution (ROR13 hash and variants)
- Writing null-free shellcode
- Alphanumeric and unicode-safe encoding
- x64 shellcode: register calling convention, alignment requirements
- Shellcode for specific tasks: reverse shell, bind shell, file download, staged payloads
- Encoded/encrypted shellcode with decoder stubs
- Kernel-mode shellcode: token stealing payload

#### Exercises

1. **Corelan Tutorial Series** (Part 9): Introduction to Win32 Shellcoding
2. **FuzzySecurity** (Part 6): Writing W32 shellcode
3. Write the following shellcodes from scratch (no frameworks):
   - x86 WinExec("calc.exe", 0) — null-free
   - x64 WinExec("calc.exe", 0) — null-free
   - x86 reverse TCP shell using WSAStartup/WSASocketA/connect/CreateProcessA
   - x64 reverse TCP shell
   - Token stealing payload (x64): copy SYSTEM token to current process (this is needed for kernel exploitation)
4. Write an XOR encoder/decoder stub that decodes your shellcode at runtime.
5. Test all shellcodes by injecting them into a host process via VirtualAlloc + CreateRemoteThread.

#### Milestone

You can write a working reverse shell shellcode for x64 Windows from memory (no reference materials) in under 2 hours.

### 4.3 WinDbg Mastery

WinDbg is the primary debugger for OSEE. You must be fast and fluent.

#### Key Concepts to Master

- **Setup**: Kernel debugging via serial/network, user-mode debugging, symbol configuration
- **Navigation**: Module listing, function resolution, source-level vs assembly-level stepping
- **Memory inspection**: Reading memory in all formats, searching for patterns
- **Breakpoint types**: Software (bp/bu/bm), hardware (ba), conditional breakpoints, breakpoint commands
- **Heap analysis**: !heap extension commands
- **Kernel debugging specifics**: !process, !thread, !pool, !object, !token, !pte, !irql
- **Scripting**: MASM expressions, C++ expressions, JavaScript/DX extensions, WinDbg scripting for automation
- **Extensions**: mona.py (via WinDbg), !exploitable, !address, !vprot, !drvobj, !devobj

See [Section 8: Tool Mastery Checklist](#8-tool-mastery-checklist) for the complete WinDbg command reference.

#### Exercises

1. **Kernel debug setup**: Configure a Windows 10/11 VM for kernel debugging via network (bcdedit commands, WinDbg connection). Verify you can break in, inspect kernel state, and continue.
2. **Heap exploration lab**: Load a process in WinDbg, use `!heap -s`, `!heap -a`, `!heap -flt s [size]`, `dt _HEAP`, `dt _HEAP_ENTRY` to manually decode heap entries.
3. **Breakpoint mastery**: Set a conditional breakpoint that only fires when a specific function is called with a particular argument value. Log the call stack each time.
4. **Automated analysis**: Write a WinDbg script (using `.printf`, `.if`, `.for`, `.foreach`) that walks the SEH chain and prints each handler address with its module name.
5. **Pool analysis**: In kernel debug mode, use `!pool`, `!poolused`, `!poolfind` to understand kernel pool allocations.
6. **Crash triage**: Given 5 crash dumps (create them yourself by writing buggy programs), use WinDbg to determine the root cause of each crash within 10 minutes per crash.

#### Milestone

You can efficiently triage a crash, navigate between user/kernel mode context, set complex conditional breakpoints, and use heap inspection commands without referencing documentation.

### 4.4 Phase 3 Study Resources

| Resource | Topic | Type |
|----------|-------|------|
| *Windows Internals, 7th Ed.* — Chapter 5 (Memory Management) | Heap internals, pool allocator | Book |
| Corelan heap-related tutorials (Parts 8-9, 11, DEPS) | Windows heap exploitation | Web tutorials |
| FuzzySecurity "Heap Overflows For Humans" | Heap concepts | Web tutorials |
| Alex Ionescu's talks on Windows heap/pool changes | Modern heap architecture | Conference talks |
| WinDbg documentation (Microsoft Learn) | Debugger commands | Docs |
| *A Guide to Kernel Exploitation* (Perla, Oldani) | Kernel concepts | Book |
| Chris Eagle's *The IDA Pro Book, 2nd Ed.* | IDA Pro mastery | Book |

---

## 5. Phase 4: Advanced Exploitation (Months 11-15)

**Goal**: Master kernel exploitation, mitigation bypass, and driver analysis — the core of OSEE.

### 5.1 Kernel Exploitation Fundamentals

#### Key Concepts to Master

- **Kernel memory layout**: System address space, session space, paged pool, non-paged pool, special pool
- **Kernel pool allocator**: Pool types (NonPaged, NonPagedNx, Paged, Session), pool chunk headers, pool tagging
- **Process and thread structures**: EPROCESS, ETHREAD, KPROCESS, KTHREAD, token pointer offsets
- **I/O model**: IRP dispatch, DeviceIoControl, IOCTL codes, METHOD_BUFFERED vs METHOD_NEITHER vs METHOD_IN_DIRECT/OUT_DIRECT
- **Driver architecture**: DriverEntry, dispatch routines, device objects, symbolic links
- **Token stealing**: Copying the SYSTEM process token to the current process for privilege escalation
- **System call interface**: SSDT, KiSystemCall64, shadow SSDT (win32k.sys)

#### Exercises

1. **HEVD — Stack Overflow** (FuzzySecurity Part 10 / wetw0rk series):
   - Load HEVD on Windows 7 x86 (mitigations off)
   - Trigger the stack overflow via DeviceIoControl
   - Redirect execution to a token stealing payload
   - Elevate a cmd.exe process to SYSTEM
2. **HEVD — Arbitrary Write (Write-What-Where)** (FuzzySecurity Part 11):
   - Understand the write-what-where primitive
   - Overwrite HalDispatchTable+0x8 to redirect NtQueryIntervalProfile
   - Execute token stealing shellcode
3. **HEVD — Null Pointer Dereference** (FuzzySecurity Part 12):
   - Map the zero page (on older Windows) or use alternative technique
   - Place shellcode/controlled data at the null page
4. **HEVD — Uninitialized Stack Variable** (FuzzySecurity Part 13)
5. **HEVD — Integer Overflow** (FuzzySecurity Part 14)
6. **HEVD — Use After Free (NonPagedPool)** (FuzzySecurity Part 15)
7. **HEVD — Pool Overflow** (FuzzySecurity Part 16)
8. **HEVD — Type Confusion**
9. **HEVD — Double Fetch** (race condition)
10. **HEVD — Write NULL**
11. **HEVD — Arbitrary Increment**
12. **HEVD — Memory Disclosure (NonPagedPool / NonPagedPoolNx)**
13. **HEVD — Insecure Kernel Resource Access**

Complete all HEVD vulnerability types on **both x86 and x64**, first on Windows 7, then on Windows 10.

#### Milestone

You can exploit every HEVD vulnerability type on Windows 7 x64 without referencing walkthroughs. You have working token stealing payloads for both x86 and x64.

### 5.2 Kernel Mitigation Bypass

This is the heart of OSEE. Modern Windows has extensive kernel security mitigations.

#### Key Concepts to Master

- **SMEP (Supervisor Mode Execution Prevention)**: Prevents the kernel from executing code in user-mode pages
  - Bypass: Flip the 20th bit of CR4, use ROP in kernel space, or use data-only attacks
- **SMAP (Supervisor Mode Access Prevention)**: Prevents kernel from reading/writing user-mode pages
  - Bypass: Must use kernel-space data or ROP to copy data from user mode
- **kASLR (Kernel Address Space Layout Randomization)**: Randomizes kernel base and driver load addresses
  - Info leak requirements: NtQuerySystemInformation (SystemModuleInformation, SystemBigPoolInformation, etc.) — note progressive lockdowns in newer Windows builds
  - EnumDeviceDrivers, kernel pointer leaks
- **KASLR + Medium/Low IL restrictions**: Windows 10 1607+ restricts kernel address leaks from non-admin processes
- **kCFG (Kernel Control Flow Guard)**: Validates indirect call targets
  - Only validated call targets are allowed
- **kCET (Kernel Control-flow Enforcement Technology)**: Hardware-enforced shadow stacks
- **VBS (Virtualization-Based Security) / HVCI (Hypervisor-Protected Code Integrity)**:
  - Kernel code pages are marked read-only by the hypervisor
  - Cannot allocate new executable memory in the kernel
  - Cannot modify existing kernel code
  - Must use data-only attacks
- **Kernel pool hardening**: Safe unlinking, pool quota cookie validation
- **Non-executable pool (NonPagedPoolNx)**: Default since Windows 8
- **WDEG (Windows Defender Exploit Guard)**: Various exploit protections

#### Exercises

1. **SMEP Bypass on HEVD** (Connor McGarr's blog / FuzzySecurity Part 17):
   - Take your HEVD stack overflow exploit for Windows 10 x64
   - Build a kernel ROP chain to disable SMEP (flip CR4 bit)
   - Execute token stealing shellcode after SMEP is disabled
2. **kASLR Info Leak exercise**:
   - Write a program that uses NtQuerySystemInformation to leak kernel module base addresses
   - Test on Windows 7, 10 1607, 10 1809, and observe which info classes get restricted
   - Practice leaking pool addresses via SystemBigPoolInformation, SystemHandleInformation
3. **HEVD on Windows 10 RS2+ with all mitigations** (FuzzySecurity Parts 17-18):
   - GDI Bitmap Abuse technique (pre-RS3)
   - Bitmap Necromancy / palette object abuse (RS2)
   - Understand why these techniques were patched and what replaced them
4. **PTE overwrite technique** (Connor McGarr):
   - Study page table entry exploitation as an alternative to traditional techniques
   - Implement on HEVD
5. **Data-only attacks**:
   - Practice attacks that manipulate kernel data structures (token pointers, ACLs) without executing kernel shellcode
   - These are essential for VBS/HVCI environments
6. **CVE Reproduction — Kernel**:
   - CVE-2021-21551 (Dell dbutil_2_3.sys) — follow Connor McGarr's writeup
   - Capcom.sys rootkit PoC (FuzzySecurity)
   - Study logic bugs in third-party drivers (FuzzySecurity Part 19: Razer rzpnk.sys)

#### Milestone

You can exploit a kernel vulnerability on Windows 10 (post-RS3) with SMEP enabled, using kernel ROP to pivot the stack and bypass SMEP, then execute a token stealing payload. You understand why each mitigation exists and at least one bypass technique for each.

### 5.3 Driver Analysis and Vulnerability Research

#### Key Concepts to Master

- Loading drivers in IDA Pro: identifying DriverEntry, dispatch routines, IOCTL handlers
- Finding IOCTL dispatch switch/case tables
- Identifying input validation flaws (buffer sizes, ProbeForRead/ProbeForWrite checks)
- Recognizing pool allocation patterns
- Identifying race conditions (TOCTOU)
- Using BinDiff/Diaphora for patch diffing kernel binaries

#### Exercises

1. **IDA Pro driver analysis**: Load 5 different real-world drivers (not HEVD) in IDA and identify:
   - The DriverEntry function
   - All registered dispatch routines
   - The IRP_MJ_DEVICE_CONTROL handler
   - All IOCTL code paths
   - Any input validation (or lack thereof)
2. **Patch diffing exercise**:
   - Download two versions of a Windows kernel binary (ntoskrnl.exe or win32k.sys) — one from before a Patch Tuesday and one from after
   - Use BinDiff or Diaphora to identify changed functions
   - Analyze the change to understand what vulnerability was patched
   - Suggested: Pick any Patch Tuesday win32k.sys fix and diff it
3. **Fuzzing exercise (optional but valuable)**:
   - Set up kAFL or a simple IOCTL fuzzer (using DeviceIoControl with random data/sizes)
   - Fuzz HEVD to rediscover its vulnerabilities
   - Understanding fuzzing helps you understand how vulnerabilities are found in real targets

#### Milestone

Given an unknown driver binary, you can identify all attack surfaces (IOCTLs, input parsing), assess them for common vulnerability patterns, and prioritize targets for deeper analysis — all within a few hours.

### 5.4 Phase 4 Study Resources

| Resource | Topic | Type |
|----------|-------|------|
| HEVD + all exploit repositories listed on GitHub | Kernel exploit practice | Lab + code |
| FuzzySecurity kernel exploit series (Parts 10-19) | Progressive kernel exploitation | Web tutorials |
| Connor McGarr's blog (connormcgarr.github.io) | Modern kernel exploitation, PTE overwrites, HVCI/VBS | Blog |
| wetw0rk's HEVD series (0x00 through 0x09) | Modern HEVD exploitation | Blog |
| *Windows Internals, 7th Ed.* — Chapters 5, 8, 12 | Memory management, I/O system, kernel security | Book |
| Alex Ionescu / Yarden Shafir talks on pool internals | Windows 10/11 pool changes | Conference talks |
| j00ru (Mateusz Jurczyk) research on win32k | Windows kernel attack surface | Papers/talks |

---

## 6. Phase 5: Expert-Level Mastery (Months 16-20)

**Goal**: Achieve the ability to chain multiple primitives, bypass modern mitigations in combination, and conduct original vulnerability research — the level required for OSEE.

### 6.1 Complex Exploit Chains

Real OSEE exam targets are large enterprise applications, not simple CTF challenges. Exploiting them requires chaining multiple techniques.

#### Key Concepts to Master

- **Multi-stage exploitation**: Using an info leak → heap corruption → code execution chain
- **Arbitrary read/write primitives**: Converting limited bugs into powerful read/write primitives
- **Relative read/write**: When you can only corrupt adjacent memory
- **Leveraging application-specific objects**: Finding useful objects of the right size for heap manipulation
- **Version-independent exploits**: Making exploits work across multiple Windows versions by dynamically resolving offsets
- **Large codebase reverse engineering**: Navigating millions of lines of compiled code efficiently

#### Exercises

1. **Full chain exercise**: Choose a real-world application with a publicly documented vulnerability chain (e.g., a browser exploit chain) and reproduce every stage:
   - Information disclosure (ASLR bypass)
   - Memory corruption (heap overflow or UAF)
   - Code execution (ROP + shellcode)
   - Sandbox escape (if applicable)
2. **Version independence exercise**: Take your best HEVD exploit and make it work on Windows 10 1809, 1903, 1909, 2004, 21H1, 21H2, and 22H2 without modification. This requires dynamically resolving structure offsets.
3. **Large target analysis**: Pick a complex application (e.g., Adobe Reader, Microsoft Office component, a large enterprise VPN client) and spend a week reverse engineering its input parsing. Document the attack surface even if you don't find a vulnerability — the analysis process is the skill.

#### Milestone

You can take a raw vulnerability advisory (with minimal details) and independently develop a working exploit for a complex application, handling all mitigations present on the target system.

### 6.2 Modern Mitigation Bypass Combinations

In modern Windows (10/11), mitigations are layered. You need to defeat them in combination.

#### Key Concepts to Master

- **ASLR + DEP + CFG bypass**: The common modern user-mode mitigation combination
  - CFG bypass techniques: corrupting CFG bitmap, calling valid targets that have useful side effects, targeting unprotected indirect calls
  - ACG (Arbitrary Code Guard): blocks dynamic code generation (VirtualProtect to RWX)
  - Must use pure ROP or JIT-based techniques in ACG environments
- **Kernel: kASLR + SMEP + kCFG + NonPagedPoolNx**:
  - Chain: info leak → pool corruption → data-only attack or ROP in kernel
  - Modern approach: avoid executing shellcode entirely; manipulate data structures
- **WDEG bypass**:
  - Export Address Filtering (EAF) / Import Address Filtering (IAF)
  - ROP mitigation bypass
  - Stack pivot detection evasion
  - Callee validation bypass
- **Heap hardening bypass**:
  - Modern LFH (Low Fragmentation Heap) randomization
  - Segment Heap randomization in Windows 10+
  - Achieving deterministic allocation despite randomization
  - Timing-based or probabilistic approaches

#### Exercises

1. **CFG bypass lab**: Compile a vulnerable application with CFG enabled. Attempt to exploit it and observe the CFG check failure. Then research and implement a CFG bypass:
   - Corrupt the CFG bitmap
   - Use a valid-target trampoline (find a CFG-valid function that gives useful primitives)
   - Call SetProcessValidCallTargets to mark your target as valid (requires write primitive)
2. **Full mitigation stack exercise**: Exploit HEVD on Windows 10 21H2+ with:
   - kASLR enabled
   - SMEP enabled
   - NonPagedPoolNx
   - VBS/HVCI enabled (if you want maximum difficulty)
   Document every mitigation you encounter and your bypass.
3. **WDEG bypass study**: Enable WDEG's Exploit Protection features on an application and attempt to exploit it. Document which features block your exploit and research bypasses.

#### Milestone

You can enumerate all active mitigations on a target system/application and formulate a bypass strategy for each one. You know which mitigation combinations make certain attack vectors infeasible and can identify alternative approaches.

### 6.3 Custom Vulnerability Research

While the OSEE exam tests against "unknown vulnerabilities" in a controlled lab, the skill of finding vulnerabilities is implicit.

#### Key Concepts to Master

- **Code auditing methodology**: Input tracing, data flow analysis, constraint tracking
- **Patch diffing workflow**: Identifying patched vulnerabilities, understanding root cause, writing exploits for the pre-patch version
- **Fuzzing**: Setting up and running fuzzers (WinAFL, AFL++, libFuzzer) against Windows targets
- **Root cause analysis**: Given a crash, determining the exact sequence of events that leads to corruption
- **Variant analysis**: After finding one bug, looking for similar patterns elsewhere in the codebase

#### Exercises

1. **Patch diff 5 Patch Tuesday vulnerabilities**:
   - Download pre-patch and post-patch binaries for 5 different CVEs
   - Use BinDiff/Diaphora to identify the fix
   - Write a root cause analysis for each
   - For at least 2, write a PoC that triggers the vulnerability on the pre-patch version
   - Suggested targets: win32k.sys, ntoskrnl.exe, CLFS.sys, HTTP.sys CVEs
2. **CVE reproduction from advisory only**:
   - Pick 3 CVEs where you have only the advisory (no public exploit)
   - Reproduce the vulnerability using only the advisory + patch diff + your analysis
   - This is the closest simulation to what the OSEE exam requires
3. **Research exercise**: Pick a Windows component or third-party application and conduct a structured vulnerability audit:
   - Map the attack surface
   - Identify all input vectors
   - Trace input handling code
   - Look for common vulnerability patterns
   - Document findings even if no vulnerabilities are found

#### Milestone

You can take a Patch Tuesday advisory, obtain pre/post-patch binaries, identify the patched function, understand the vulnerability, and write a working PoC — all within 48 hours.

### 6.4 Phase 5 Study Resources

| Resource | Topic | Type |
|----------|-------|------|
| Connor McGarr: "No Code Execution? No Problem!" (HVCI/VBS/kCFG) | Modern kernel mitigations | Blog |
| Connor McGarr: Kernel Mode Shadow Stacks on Windows | kCET | Blog |
| Project Zero blog (googleprojectzero.blogspot.com) | World-class vulnerability research writeups | Blog |
| MSRC blog (msrc-blog.microsoft.com) | Microsoft's perspective on vulnerabilities | Blog |
| Yarden Shafir's pool exploitation research | Modern pool exploitation | Blog/talks |
| *A Guide to Kernel Exploitation* (Perla, Oldani) | Cross-platform kernel exploitation | Book |
| OffCon conference talks (various) | Advanced Windows exploitation techniques | Videos |
| BlackHat / DEF CON exploit development talks | Cutting-edge techniques | Videos |

---

## 7. Practice Exercises by Phase

### 7.1 Exploit Education Challenges

| Challenge Set | Phase | Focus |
|---------------|-------|-------|
| Phoenix: Stack Zero - Stack Six | Phase 2 | Stack overflows, shellcode injection |
| Phoenix: Format Zero - Format Four | Phase 2-3 | Format string vulnerabilities |
| Phoenix: Heap Zero - Heap Three | Phase 3 | Heap exploitation fundamentals |
| Phoenix: Net Zero - Net Two | Phase 2 | Network-based exploitation |
| Phoenix: Final Zero - Final Two | Phase 3 | Combined techniques |
| Fusion: Level 00 - Level 05 | Phase 3 | Exploitation with modern mitigations (Linux) |
| Fusion: Level 06 - Level 14 | Phase 4 | Advanced exploitation techniques |
| Protostar: All levels | Phase 2 | Legacy but good for fundamentals |

**Note**: Exploit Education challenges are Linux-based. They build transferable exploitation intuition, but you must separately practice all techniques on Windows.

### 7.2 HEVD (HackSys Extreme Vulnerable Driver) — Complete Progression

HEVD is the single most important practice tool for OSEE kernel exploitation preparation.

#### Tier 1: Basic Kernel Exploitation (Phase 4 start)

Target: Windows 7 SP1 x86, no mitigations

| # | Vulnerability | Learning Objective |
|---|---------------|--------------------|
| 1 | Stack Buffer Overflow | Basic kernel buffer overflow, token stealing |
| 2 | Arbitrary Overwrite (Write-What-Where) | HalDispatchTable overwrite |
| 3 | Null Pointer Dereference | Null page mapping, controlled dispatch |
| 4 | Type Confusion | Object type manipulation |
| 5 | Integer Overflow (Arithmetic) | Small allocation via integer wrap |
| 6 | Uninitialized Stack Variable | Controlling uninitialized data |

#### Tier 2: Intermediate Kernel Exploitation (Phase 4 mid)

Target: Windows 7 SP1 x64

| # | Vulnerability | Learning Objective |
|---|---------------|--------------------|
| 7 | Stack Buffer Overflow (x64) | x64 kernel exploitation differences |
| 8 | Use After Free (NonPagedPool) | Pool object replacement |
| 9 | Pool Buffer Overflow (NonPagedPool) | Adjacent pool chunk corruption |
| 10 | Uninitialized Heap Variable (NonPagedPool) | Pool spray for controlled data |
| 11 | Double Fetch (Race Condition) | TOCTOU exploitation |
| 12 | Write NULL | Limited write primitive |

#### Tier 3: Advanced Kernel Exploitation (Phase 4 end / Phase 5)

Target: Windows 10 x64 (various builds, mitigations enabled)

| # | Vulnerability | Learning Objective |
|---|---------------|--------------------|
| 13 | Stack Overflow with GS (Stack Cookie) | Bypassing /GS on x64 |
| 14 | Pool Overflow (NonPagedPoolNx) | NX pool exploitation |
| 15 | Use After Free (NonPagedPoolNx) | Modern UAF technique |
| 16 | Memory Disclosure (NonPagedPool) | Info leak for kASLR bypass |
| 17 | Memory Disclosure (NonPagedPoolNx) | NX pool info leak |
| 18 | Arbitrary Increment | Limited primitive escalation |
| 19 | Insecure Kernel Resource Access | Access control bypass |
| 20 | All above with SMEP enabled | ROP to bypass SMEP |
| 21 | All above with kCFG | Data-only attacks |

#### HEVD External Exploit Repositories for Reference

After you have attempted each exercise independently, compare your solution:

- FuzzySecurity/HackSysTeam-PSKernelPwn (PowerShell-based)
- GradiusX/HEVD-Python-Solutions
- wetw0rk/Exploit-Development (comprehensive, with blog series)
- mgeeky/HEVD_Kernel_Exploit
- w4fz5uck5/3XPL01t5/OSEE_Training

### 7.3 Windows Exploit Development Challenges

| Challenge | Phase | Description |
|-----------|-------|-------------|
| Vulnserver (thegreycorner.com) | Phase 2 | Windows TCP server with multiple vulnerability types |
| dostackbufferoverflowgood | Phase 2 | Guided stack overflow tutorial application |
| Brainpan (VulnHub) | Phase 2 | Linux/Windows overflow CTF |
| FuzzySecurity tutorial exercises | Phase 2-4 | Follow along with each tutorial |
| Corelan tutorial exercises | Phase 2-3 | Follow along with each exploit writing tutorial |
| Old vulnerable applications (search Exploit-DB) | Phase 2-3 | Real-world application exploitation |
| Custom OSED-style challenges | Phase 3 | Build and share challenges with study partners |

### 7.4 Real CVE Reproduction Exercises

#### Phase 2: Classic CVEs

| CVE | Application | Vulnerability Type |
|-----|-------------|--------------------|
| CVE-2004-1626 | Ability FTP Server | Stack overflow |
| CVE-2009-1437 | WinAmp | Stack overflow |
| CVE-2010-1297 | Adobe Flash Player | Memory corruption |
| Various | Easy File Sharing Web Server | Multiple overflow types |
| Various | WarFTPD | Stack overflow |

#### Phase 3: Heap and Modern CVEs

| CVE | Application | Vulnerability Type |
|-----|-------------|--------------------|
| CVE-2014-1776 | Internet Explorer | UAF (use-after-free) |
| CVE-2012-4792 | Internet Explorer | UAF |
| CVE-2016-0189 | Internet Explorer (VBScript) | Type confusion |
| CVE-2021-21224 | Chrome V8 | Type confusion |
| Various | Firefox (pre-2020 UAFs) | Use-after-free |

#### Phase 4-5: Kernel CVEs

| CVE | Component | Vulnerability Type |
|-----|-----------|-------------------|
| CVE-2021-21551 | Dell dbutil_2_3.sys | Arbitrary write in kernel driver |
| CVE-2020-0986 | splwow64 | Arbitrary pointer dereference |
| CVE-2021-1732 | win32k.sys | Type confusion / privilege escalation |
| CVE-2022-21882 | win32k.sys | Type confusion |
| CVE-2023-28252 | CLFS.sys | Heap overflow / privilege escalation |
| CVE-2024-21338 | appid.sys | Arbitrary kernel read/write |
| Various | Capcom.sys | Insecure function call (practice target) |

### 7.5 Patch Diffing Exercises

| Exercise | Description | Tools |
|----------|-------------|-------|
| Monthly Patch Tuesday diff | Every month, pick 1-2 kernel CVEs from Patch Tuesday and diff the patches | BinDiff, Diaphora, IDA |
| win32k.sys historical diffs | Diff 5 different win32k.sys patches from the last 2 years | BinDiff, IDA |
| ntoskrnl.exe pool hardening | Diff ntoskrnl.exe across Windows 10 builds to see pool security improvements | BinDiff, IDA |
| User-mode application patches | Diff patches for Adobe Reader, Chrome, or Firefox to see application-level fixes | BinDiff, Ghidra |
| Third-party driver patches | Find a driver that issued a security update and diff the versions | BinDiff, IDA |

---

## 8. Tool Mastery Checklist

### 8.1 WinDbg Commands Every OSEE Candidate Must Know

#### Essential Navigation

| Command | Purpose |
|---------|---------|
| `lm` | List loaded modules |
| `lm m <pattern>` | List modules matching pattern |
| `x <module>!<symbol>` | Examine/search for symbols |
| `.sympath` / `.symfix` | Configure symbol path |
| `.reload /f` | Force reload symbols |
| `u <addr>` / `uf <function>` | Disassemble at address / unassemble function |
| `ub <addr>` | Disassemble backwards |
| `.process /i <addr>` followed by `g` | Switch to process context (kernel mode) |
| `.thread <addr>` | Switch to thread context |

#### Memory Inspection

| Command | Purpose |
|---------|---------|
| `db/dw/dd/dq <addr>` | Display bytes/words/dwords/qwords |
| `da/du <addr>` | Display ASCII/Unicode string |
| `dps <addr>` | Display pointer-sized values with symbols |
| `dp <addr>` | Display pointer values |
| `dt <type> <addr>` | Display typed structure |
| `dt -r <type> <addr>` | Display structure recursively |
| `s -b <start> L<length> <pattern>` | Search memory for bytes |
| `s -a <start> L<length> "string"` | Search for ASCII string |
| `!address <addr>` | Display memory region info |
| `!vprot <addr>` | Display virtual memory protection |
| `dds/dqs <addr>` | Display dwords/qwords with symbols |

#### Breakpoints

| Command | Purpose |
|---------|---------|
| `bp <addr>` | Set software breakpoint |
| `bu <symbol>` | Set unresolved breakpoint (survives reload) |
| `bm <pattern>` | Set breakpoints on pattern match |
| `ba r/w/e <size> <addr>` | Hardware breakpoint (read/write/execute) |
| `bp <addr> ".if (poi(@rcx)==0x41414141) {} .else {gc}"` | Conditional breakpoint |
| `bp <addr> "kb; gc"` | Breakpoint with logging command |
| `bl` | List breakpoints |
| `bc <num>` / `bc *` | Clear breakpoint / clear all |
| `bd/be <num>` | Disable/enable breakpoint |

#### Execution Control

| Command | Purpose |
|---------|---------|
| `g` | Continue execution |
| `p` | Step over |
| `t` | Step into |
| `pt` | Step to next return |
| `pc` | Step to next call |
| `gu` | Go up (execute until return) |
| `gh` | Go with exception handled |
| `gn` | Go with exception not handled |

#### Heap Analysis

| Command | Purpose |
|---------|---------|
| `!heap -s` | Heap summary |
| `!heap -a <heap_addr>` | Detailed heap info |
| `!heap -flt s <size>` | Find allocations of specific size |
| `!heap -p -a <addr>` | Page heap info for allocation |
| `!heap -l` | Detect heap leaks |
| `dt _HEAP <addr>` | Heap structure |
| `dt _HEAP_ENTRY <addr>` | Heap chunk header |
| `dt _LFH_HEAP <addr>` | LFH heap structure |
| `!heap -p -h <heap>` | Full page heap dump |

#### Kernel Debugging

| Command | Purpose |
|---------|---------|
| `!process 0 0` | List all processes |
| `!process <addr> 7` | Detailed process info |
| `!thread <addr>` | Thread info |
| `!pool <addr>` | Pool allocation info for address |
| `!poolused 2 <tag>` | Pool usage by tag |
| `!poolfind <tag>` | Find pool allocations by tag |
| `!token <addr>` | Display token info |
| `!object <addr>` | Display object header |
| `!pte <addr>` | Page table entry info |
| `!irql` | Current IRQL |
| `!drvobj <name>` | Driver object info |
| `!devobj <addr>` | Device object info |
| `!idt` | Interrupt descriptor table |
| `r cr4` | Read CR4 (check SMEP bit) |
| `vertarget` | Target system version info |
| `.trap <addr>` | Set trap frame context |
| `!analyze -v` | Verbose crash analysis |

#### Scripting and Expressions

| Command | Purpose |
|---------|---------|
| `? <expression>` | Evaluate MASM expression |
| `?? <expression>` | Evaluate C++ expression |
| `poi(<addr>)` | Dereference pointer |
| `.printf` | Formatted output |
| `.for / .foreach / .if / .else` | Control flow in scripts |
| `$$>a< <script.txt>` | Run script from file |
| `dx <LINQ expression>` | Data model (DX) queries |
| `.scriptload <file.js>` | Load JavaScript extension |

#### Key Extensions

| Extension | Purpose |
|-----------|---------|
| `!mona` | mona.py for exploit development (ROP, patterns, etc.) |
| `!exploitable` | Assess crash exploitability |
| `!ext.call` | Various extension commands |
| `.load jsprovider.dll` | Load JavaScript provider |

### 8.2 IDA Pro Shortcuts and Analysis Techniques

#### Essential Shortcuts

| Shortcut | Action |
|----------|--------|
| `G` | Go to address |
| `N` | Rename symbol/variable |
| `X` | Cross-references to/from |
| `Space` | Toggle graph/text view |
| `F5` | Decompile (Hex-Rays) |
| `Tab` | Switch between pseudocode and disassembly |
| `/` | Add comment (in pseudocode) |
| `;` / `:` | Add comment (repeatable / non-repeatable) |
| `D` | Change data type (byte/word/dword/qword) |
| `A` | Convert to ASCII string |
| `U` | Undefine |
| `C` | Convert to code |
| `P` | Create function |
| `Y` | Change type declaration |
| `T` | Apply structure |
| `M` | Apply enum member |
| `H` | Toggle hex/decimal |
| `Alt+T` | Text search |
| `Alt+B` | Binary search |
| `Ctrl+X` | Cross-references to selected item |
| `Ctrl+J` | Cross-references from selected item |
| `Ctrl+S` | Segment list |
| `Ctrl+P` | Function parameter adjustment |

#### Analysis Techniques for Exploit Development

1. **Driver analysis workflow**:
   - Find DriverEntry (usually the entry point)
   - Identify IoCreateDevice calls (device name)
   - Trace MajorFunction array assignments (IRP_MJ_DEVICE_CONTROL = 0xE)
   - In the IOCTL handler, identify the switch/case on IoControlCode
   - For each IOCTL: trace SystemBuffer usage, check ProbeForRead/ProbeForWrite calls, identify buffer size validation

2. **Identifying vulnerability patterns**:
   - Search for memcpy/RtlCopyMemory where size comes from user input
   - Look for missing ProbeForRead/ProbeForWrite before accessing user buffers in METHOD_NEITHER IOCTLs
   - Check for integer overflow in size calculations (multiplication before allocation)
   - Identify TOCTOU: separate validation and usage of user-mode pointers

3. **Type reconstruction**:
   - Import Windows kernel type libraries (ntddk, wdm)
   - Use "Local Types" to define custom structures
   - Apply structures to function parameters for readability
   - Use Hex-Rays structure recovery features

4. **Binary diffing setup**:
   - Export IDA databases (.idb/.i64) for both old and new versions
   - Use BinDiff or Diaphora plugin to compare
   - Focus on functions with "changed" status (not "identical" or "unmatched")
   - Read the diff to understand what validation was added

### 8.3 Python Scripting for Exploit Development

#### Essential Libraries

| Library | Purpose |
|---------|---------|
| `struct` | Packing/unpacking binary data (struct.pack, struct.unpack) |
| `ctypes` | Calling Windows API functions, defining C structures in Python |
| `socket` | Network communication for remote exploits |
| `pwntools` (pwnlib) | Exploit development framework (also works on Windows to some extent) |
| `keystone-engine` | Runtime assembly (assembling shellcode from Python) |
| `capstone` | Disassembly engine |
| `unicorn` | CPU emulation (testing shellcode without execution) |
| `pefile` | PE file parsing |
| `winappdbg` | Windows application debugging from Python |
| `comtypes` / `pythoncom` | COM automation (useful for Office/IE exploit testing) |

#### Essential Patterns

```python
# 1. Structure packing (critical for exploit buffers)
import struct

# Pack a 32-bit value
buf = struct.pack("<I", 0x41414141)   # Little-endian unsigned int
buf = struct.pack("<Q", 0xdeadbeefcafebabe)  # Little-endian unsigned long long (64-bit)

# 2. DeviceIoControl from Python (for kernel exploit development)
import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Open handle to device
handle = kernel32.CreateFileW(
    "\\\\.\\HackSysExtremeVulnerableDriver",
    0xC0000000,  # GENERIC_READ | GENERIC_WRITE
    0,
    None,
    0x3,  # OPEN_EXISTING
    0,
    None
)

# Send IOCTL
in_buf = ctypes.create_string_buffer(b"A" * 0x1000)
bytes_returned = wintypes.DWORD(0)
kernel32.DeviceIoControl(
    handle,
    0x222003,  # IOCTL code
    in_buf,
    len(in_buf),
    None,
    0,
    ctypes.byref(bytes_returned),
    None
)

# 3. NtQuerySystemInformation for kernel address leak
import ctypes
from ctypes import wintypes

ntdll = ctypes.windll.ntdll

SystemModuleInformation = 11
buf_size = 0x100000
buf = ctypes.create_string_buffer(buf_size)
ret_len = wintypes.DWORD(0)

status = ntdll.NtQuerySystemInformation(
    SystemModuleInformation,
    buf,
    buf_size,
    ctypes.byref(ret_len)
)

# Parse the output to extract kernel base address
# First 8 bytes (x64) = number of modules
num_modules = struct.unpack("<Q", buf[:8])[0]
# Each module entry follows...

# 4. Token stealing payload assembly with keystone
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

CODE = """
    mov rax, gs:[0x188]       ; Get KTHREAD from GS
    mov rax, [rax + 0x220]    ; Get EPROCESS
    mov rbx, rax              ; Save current EPROCESS
    
find_system:
    mov rax, [rax + 0x448]    ; ActiveProcessLinks.Flink
    sub rax, 0x448            ; Back to EPROCESS base
    cmp dword ptr [rax + 0x440], 4  ; UniqueProcessId == 4 (System)?
    jne find_system
    
    mov rcx, [rax + 0x4B8]    ; SYSTEM token
    and cl, 0xF0              ; Clear token ref count bits
    mov [rbx + 0x4B8], rcx    ; Overwrite current process token
    
    ; Return cleanly
    xor rax, rax
    ret
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
shellcode = bytes(encoding)
```

#### Exploit Template

```python
#!/usr/bin/env python3
"""
Exploit template for Windows kernel driver exploitation via IOCTL.
"""
import ctypes
import struct
import sys
from ctypes import wintypes

# ============================================================
# Configuration
# ============================================================
DEVICE_NAME = "\\\\.\\HackSysExtremeVulnerableDriver"
IOCTL_CODE  = 0x222003  # Target IOCTL

# ============================================================
# Windows API Setup
# ============================================================
kernel32 = ctypes.windll.kernel32
ntdll    = ctypes.windll.ntdll

GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
OPEN_EXISTING   = 0x3
INVALID_HANDLE  = -1

MEM_COMMIT      = 0x1000
MEM_RESERVE     = 0x2000
PAGE_EXECUTE_RW = 0x40

def open_device():
    """Open handle to the vulnerable driver."""
    handle = kernel32.CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, None, OPEN_EXISTING, 0, None
    )
    if handle == INVALID_HANDLE:
        print(f"[-] Failed to open device: {ctypes.GetLastError()}")
        sys.exit(1)
    print(f"[+] Device handle: {handle:#x}")
    return handle

def send_ioctl(handle, ioctl_code, in_buf, in_size, out_buf=None, out_size=0):
    """Send IOCTL to driver."""
    bytes_returned = wintypes.DWORD(0)
    result = kernel32.DeviceIoControl(
        handle, ioctl_code,
        in_buf, in_size,
        out_buf, out_size,
        ctypes.byref(bytes_returned), None
    )
    return result

def leak_kernel_base():
    """Leak kernel base address via NtQuerySystemInformation."""
    SystemModuleInformation = 11
    buf = ctypes.create_string_buffer(0x100000)
    ret_len = wintypes.DWORD(0)
    ntdll.NtQuerySystemInformation(
        SystemModuleInformation, buf, len(buf), ctypes.byref(ret_len)
    )
    # Parse first module (ntoskrnl)
    num_modules = struct.unpack("<I", buf[0:4])[0]
    # Module base is at offset 0x18 in the first entry (after count)
    base = struct.unpack("<Q", buf[16:24])[0]  # Adjust offsets per Windows version
    print(f"[+] Kernel base: {base:#018x}")
    return base

def alloc_shellcode(shellcode_bytes):
    """Allocate executable memory and copy shellcode."""
    addr = kernel32.VirtualAlloc(
        None, len(shellcode_bytes),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_RW
    )
    if not addr:
        print("[-] VirtualAlloc failed")
        sys.exit(1)
    ctypes.memmove(addr, shellcode_bytes, len(shellcode_bytes))
    print(f"[+] Shellcode at: {addr:#018x}")
    return addr

def main():
    print("[*] Opening device...")
    handle = open_device()
    
    print("[*] Leaking kernel base...")
    kbase = leak_kernel_base()
    
    print("[*] Preparing exploit buffer...")
    # TODO: Build exploit-specific buffer
    
    print("[*] Sending IOCTL...")
    # TODO: send_ioctl(handle, IOCTL_CODE, buf, len(buf))
    
    print("[*] Spawning elevated shell...")
    # TODO: os.system("cmd.exe") or CreateProcess

if __name__ == "__main__":
    main()
```

### 8.4 Debugging Setup Proficiency

You must be able to set up these environments from scratch quickly.

#### Kernel Debugging Setup Checklist

- [ ] Windows 10/11 VM configured for network kernel debugging (bcdedit /dbgsettings net)
- [ ] WinDbg Preview connected to kernel debugger
- [ ] Symbols configured (.symfix; .reload)
- [ ] Can break into debugger and resume
- [ ] Can load and unload drivers (sc create / sc start / sc stop)
- [ ] HEVD driver loaded and responding to IOCTLs
- [ ] Can set breakpoints in driver code
- [ ] Can inspect pool allocations
- [ ] Second VM (debugger host) has stable connection

#### User-Mode Debugging Setup Checklist

- [ ] WinDbg attached to target process
- [ ] Application Verifier / Page Heap enabled for target
- [ ] Symbols configured for target application + OS
- [ ] Can set breakpoints on module load
- [ ] Can analyze crash dumps (.dump /ma)
- [ ] GFlags configured for heap debugging

#### Environment Requirements (Per OffSec EXP-401 FAQ)

- Windows 10 host (only supported host OS for the course)
- VMware Workstation 15+
- 64-bit CPU with at least 4 cores
- CPU supporting: NX, SMEP, VT-d/IOMMU, VT-x/EPT
- Minimum 160 GB free disk space
- At least 16 GB RAM
- Must be able to run three VMs simultaneously

---

## 9. Self-Assessment and Readiness Criteria

### 9.1 How to Know If You're Ready for OSEE

Use the following assessment framework. Rate yourself honestly on each skill area.

#### Readiness Matrix

| Skill Area | Not Ready (1) | Developing (2) | Competent (3) | Ready (4) | Expert (5) |
|------------|---------------|-----------------|---------------|-----------|-------------|
| x86/x64 Assembly | Cannot read disassembly | Can read simple functions | Can read complex functions fluently | Can write assembly and debug it | Can optimize assembly and spot compiler-specific patterns |
| C/C++ | Basic syntax only | Can write programs with pointers | Deep understanding of memory layout, UB, structures | Can analyze compiled C/C++ and understand object layout | Can reverse vtable dispatch, exception handling, template instantiation |
| Windows Internals | Know user/kernel mode exists | Understand processes, threads, memory | Deep understanding of PEB, TEB, heap internals, drivers | Can navigate kernel structures in debugger | Expert-level understanding of pool allocator, scheduler, I/O manager |
| WinDbg | Can set breakpoints and step | Comfortable with memory inspection | Can do heap analysis, conditional breakpoints, scripting | Fast and fluent, including kernel debugging | Can write complex scripts, use DX/LINQ, debug anything efficiently |
| IDA Pro | Can open and navigate | Can use xrefs, rename, comment | Can analyze drivers, identify vulnerability patterns | Can efficiently audit large codebases | Can use IDAPython, custom plugins, BinDiff workflow |
| Stack Exploitation | Understand the concept | Can exploit simple overflows | Can exploit with DEP bypass (ROP) | Can exploit with ASLR+DEP+CFG considerations | Can exploit in heavily mitigated environments |
| Heap Exploitation | Know heap exists | Understand basic heap overflow | Can exploit UAF, groom the heap | Can exploit on modern Windows heap (LFH, Segment Heap) | Can exploit complex multi-step heap scenarios under full mitigations |
| Kernel Exploitation | Know ring 0 exists | Can exploit HEVD on Win7 (no mitigations) | Can exploit HEVD on Win10 with SMEP bypass | Can exploit arbitrary kernel vulnerabilities on modern Windows | Can bypass VBS/HVCI with data-only techniques |
| Shellcoding | Can use msfvenom | Can modify existing shellcode | Can write basic shellcode from scratch | Can write complex shellcode (kernel token steal, reverse shell) | Can write size-optimized, encoded, version-independent shellcode |
| Vulnerability Research | Can use existing exploits | Can reproduce exploits from writeups | Can patch diff and understand fixes | Can find variants and write PoCs from advisories only | Can find 0days through code audit or fuzzing |

**Minimum readiness for OSEE**: Score of 3-4 in ALL areas, with at least 4 in Heap Exploitation, Kernel Exploitation, and WinDbg.

### 9.2 Skills Gap Analysis Framework

Perform this self-assessment every 4-6 weeks during preparation:

1. **Timed challenge**: Give yourself 8 hours to exploit HEVD's pool overflow on Windows 10 x64 with SMEP enabled. Did you succeed? How long did it take?

2. **Blind CVE reproduction**: Pick a CVE you have not studied before. Given only the advisory and access to pre/post-patch binaries, can you write a working PoC in 48 hours?

3. **Unknown driver audit**: Download a random Windows driver (from a vendor's website or DriverStore). Can you fully map its attack surface and identify any suspicious code patterns in 4 hours?

4. **Explain-it test**: Can you explain the following to a colleague without referencing notes?
   - How the Windows LFH works and why it makes exploitation harder
   - How SMEP works at the hardware level and three different bypass techniques
   - The full lifecycle of a kernel pool allocation from ExAllocatePoolWithTag to ExFreePoolWithTag
   - How kCFG validates indirect calls
   - The difference between token stealing and ACL manipulation for privilege escalation
   - How VBS/HVCI changes the exploitation landscape

5. **Endurance test**: Simulate a 24-hour exploit development session. Start with a vulnerability you have not worked on before and work continuously (with normal breaks). Can you maintain focused analysis for extended periods?

### 9.3 Practice Exam Simulation

Since there are no official OSEE practice exams, construct your own:

#### Simulation Setup

1. **Duration**: 72 hours (match exam duration)
2. **Target 1** (User-mode, 50 points):
   - Find a complex application with a known CVE (but one you haven't exploited before)
   - Set up the vulnerable version in a VM
   - Your goal: achieve code execution, bypassing DEP + ASLR + CFG
   - Write a full report with screenshots
3. **Target 2** (Kernel-mode, 50 points):
   - Load a different HEVD vulnerability type than one you've practiced extensively
   - Or use a third-party vulnerable driver (e.g., old version of a vendor driver with a known CVE)
   - Your goal: achieve SYSTEM privileges on Windows 10 with mitigations enabled
   - Write a full report with screenshots
4. **Rules**:
   - No looking at existing writeups or exploit code for your specific targets
   - Reference documentation (MSDN, Intel manuals, WinDbg help) is allowed
   - Time yourself; take breaks but track total working time
   - Write your report using the official OSEE exam report template

#### Evaluation Criteria

- Did you achieve full exploitation of both targets? (75+ simulated points)
- Is your report detailed enough for someone else to reproduce your exploit?
- Did you finish within 72 hours?
- Did your exploits work reliably (not just once)?

---

## 10. Time and Financial Investment

### 10.1 Course Cost and What's Included

**EXP-401 (AWE) is an in-person-only course.** It is not available as a self-paced online course.

| Item | Details |
|------|---------|
| **Course format** | In-person, 5 days (Mon-Fri), intensive hands-on |
| **Course delivery** | Through OffSec authorized training partners and at OffSec events |
| **What's included** | Course materials (provided in-class, not online), VMs (distributed via USB), hands-on labs, 1 exam attempt |
| **Exam attempt** | Included with course registration |
| **Exam retakes** | Available for purchase via OffSec support ticket |
| **Course cost** | Varies by training partner and location; typically **$5,000 - $8,000+ USD** for the 5-day course |
| **Travel** | You must be physically present at the training venue — budget for airfare, hotel, meals |

**Important notes from the EXP-401 FAQ**:
- The course does NOT include online content
- VMs are distributed in-class via USB drives
- Recommended reading materials are sent before the training
- You must bring your own laptop meeting specific requirements

### 10.2 Additional Tool Costs

| Tool | Cost | Notes |
|------|------|-------|
| **IDA Pro** (Professional) | ~$1,400 - $2,600/year (named license) | Essential for binary analysis. IDA Free or Ghidra can substitute for learning, but IDA Pro is standard |
| **IDA Pro + Hex-Rays Decompiler** | ~$2,700 - $5,200/year | x86 + x64 decompiler is strongly recommended |
| **Ghidra** | Free (NSA) | Viable free alternative to IDA for learning; less polished but capable |
| **Binary Ninja** | $299 (personal) - $2,499 (commercial) | Another alternative to IDA |
| **VMware Workstation Pro** | Free for personal use (since Nov 2024) | Required by the course. VMware Workstation 15 or higher |
| **Windows 10/11 Pro licenses** | $0 - $200 | Evaluation VMs are free from Microsoft; full licenses for long-term use |
| **Windows SDK / WDK** | Free | Required for kernel development / debugging symbols |
| **WinDbg Preview** | Free (Microsoft Store) | Primary debugger |
| **Visual Studio Community** | Free | For compiling test programs, drivers (need WDK) |
| **BinDiff** | Free (Google) | Binary diffing |
| **Python 3** | Free | Scripting |
| **keystone-engine / capstone / unicorn** | Free (open source) | Assembly/disassembly/emulation |

**Estimated minimum tool budget**: $0 (using Ghidra + free tools) to $5,000+ (IDA Pro with decompiler)

**Recommended budget**: ~$1,500-3,000 for IDA Pro license (if employer does not provide)

### 10.3 Time Commitment Estimates

| Phase | Duration | Hours/Week | Total Hours |
|-------|----------|------------|-------------|
| Phase 1: Foundations | 3 months | 15-20 | 180-240 |
| Phase 2: Basic Exploitation | 3 months | 15-20 | 180-240 |
| Phase 3: Intermediate | 4 months | 20-25 | 320-400 |
| Phase 4: Advanced | 5 months | 20-25 | 400-500 |
| Phase 5: Expert | 5 months | 25-30 | 500-600 |
| **Total** | **~20 months** | — | **~1,580-1,980** |

**Adjustments based on starting level**:

| Your Starting Point | Skip Phases | Estimated Prep Time |
|---------------------|-------------|---------------------|
| Complete beginner in exploit dev | None | 18-24 months |
| OSED certified | Phase 1, most of Phase 2 | 12-16 months |
| OSED + OSEP certified | Phases 1-2, partial Phase 3 | 10-14 months |
| Active exploit developer (user-mode) | Phases 1-3 partially | 8-12 months |
| Active kernel exploit developer | Phase 1-3, partial Phase 4 | 4-8 months |

### 10.4 Total Estimated Financial Investment

| Category | Low Estimate | High Estimate |
|----------|-------------|---------------|
| EXP-401 Course | $5,000 | $8,000 |
| Travel (airfare + hotel + meals, 7 days) | $1,000 | $4,000 |
| Exam retake (if needed) | $0 | $800+ |
| IDA Pro + Hex-Rays | $0 (Ghidra) | $5,200 |
| VMware Workstation | $0 | $0 |
| Hardware upgrade (if needed) | $0 | $2,000 |
| Books and training materials | $100 | $500 |
| **Total** | **~$6,100** | **~$20,500** |

### 10.5 Lab and Exam Policies

- **Lab access**: Course labs are only available during the in-person training (5 days). There is no post-course lab access.
- **Exam scheduling**: You receive an exam attempt with course registration. Coordinate scheduling through OffSec.
- **Exam retakes**: Contact OffSec support (submit a request) to purchase retake attempts.
- **Exam results**: Delivered within 10 business days of report submission.
- **Report template**: Available at the URL provided in the exam guide (AWE-Exam-Report.docx).

---

## 11. Recommended Study Resources

### 11.1 Books (Priority Order)

| # | Title | Author(s) | Focus |
|---|-------|-----------|-------|
| 1 | *Windows Internals, 7th Ed.* (Parts 1 & 2) | Russinovich, Solomon, Ionescu | Windows OS internals — the bible |
| 2 | *The Shellcoder's Handbook, 2nd Ed.* | Anley, Heasman, Lindner, Richarte | Exploit development techniques |
| 3 | *A Guide to Kernel Exploitation* | Perla, Oldani | Kernel exploitation methodology |
| 4 | *The IDA Pro Book, 2nd Ed.* | Eagle | Reverse engineering with IDA |
| 5 | *Practical Malware Analysis* | Sikorski, Honig | Binary analysis, PE format, debugging |
| 6 | *Hacking: The Art of Exploitation, 2nd Ed.* | Erickson | Foundational exploitation |
| 7 | *Intel SDM Volumes 1-3* | Intel | x86/x64 architecture reference |
| 8 | *Windows Kernel Programming* | Yosifovich | Windows driver development |
| 9 | *Practical Reverse Engineering* | Dang, Gazet, Bachaalany | RE with focus on Windows/x86 |

### 11.2 Online Tutorial Series

| Resource | URL | Focus |
|----------|-----|-------|
| Corelan Exploit Writing Tutorials | corelan.be | Parts 1-11: stack, SEH, ROP, shellcode, heap spray |
| FuzzySecurity Exploit Dev Series | fuzzysecurity.com/tutorials.html | Parts 1-19: user-mode through kernel exploitation |
| FuzzySecurity Heap Overflows for Humans | fuzzysecurity.com | Heap exploitation fundamentals |
| wetw0rk's HEVD Series | wetw0rk.github.io | 0x00-0x09: Modern HEVD exploitation |
| Connor McGarr's Blog | connormcgarr.github.io | Modern kernel exploitation, PTE overwrites, HVCI, shadow stacks, kCFG |
| Kristal-G HEVD Series | kristal-g.github.io | HEVD on Windows 10 RS5 x64 |

### 11.3 Conference Talks and Presentations

| Talk | Speaker | Topic |
|------|---------|-------|
| "One Bit to Rule a System" | Various | Modern kernel exploitation primitives |
| "Kernel Pool Exploitation on Modern Windows" | Alex Ionescu / Yarden Shafir | Pool allocator changes and exploitation |
| "A New Era of Kernel Exploitation" | Various | Post-mitigation kernel attacks |
| BlackHat EU 2013: "Advanced Heap Manipulation in Windows 8" | Various | Heap exploitation evolution |
| Various OffCon / BlueHat talks on VBS/HVCI | Various | Cutting-edge mitigation technology |

### 11.4 Practice Platforms

| Platform | URL | Focus |
|----------|-----|-------|
| HEVD | github.com/hacksysteam/HackSysExtremeVulnerableDriver | Kernel exploitation (primary practice target) |
| Exploit Education (Phoenix/Fusion) | exploit.education | Memory corruption fundamentals |
| Vulnserver | thegreycorner.com | Windows user-mode exploitation |
| OffSec Proving Grounds | offsec.com/products/proving-grounds | Various practice targets |
| Hack The Box (retired machines) | hackthebox.com | Some exploit dev relevant boxes |

### 11.5 Prerequisite Certifications (Recommended Path)

OffSec recommends completing 300-level certifications before attempting OSEE:

| Certification | Course | Why It Helps |
|---------------|--------|--------------|
| **OSED** | EXP-301: Windows User Mode Exploit Development | User-mode exploitation, ROP, DEP/ASLR bypass, custom shellcode, format strings — directly foundational for OSEE |
| **OSEP** | PEN-300: Evasion Techniques and Breaching Defenses | Process injection, AV evasion, understanding of defensive technologies |
| **OSWE** | WEB-300: Advanced Web Attacks and Exploitation | Less directly relevant but builds code audit skills |
| **OSCP** | PEN-200: Penetration Testing with Kali Linux | Baseline offensive security skills |

The most relevant prerequisite is **OSED (EXP-301)**, which covers user-mode Windows exploit development and is essentially the direct precursor to EXP-401.

---

## Summary: The Path to OSEE

```
Month 1-3:   PHASE 1 — Foundations
             Assembly | C/C++ | Windows API | PE Format
                              |
                              v
Month 4-6:   PHASE 2 — Basic Exploitation
             Stack overflows | SEH | Basic ROP | Egg hunters
                              |
                              v
Month 7-10:  PHASE 3 — Intermediate
             Heap exploitation | Shellcoding | WinDbg mastery
                              |
                              v
Month 11-15: PHASE 4 — Advanced
             Kernel exploitation | SMEP bypass | Driver analysis | HEVD
                              |
                              v
Month 16-20: PHASE 5 — Expert
             Exploit chains | Modern mitigations | Vulnerability research
                              |
                              v
             ATTEND EXP-401 (5-day in-person course)
                              |
                              v
             OSEE EXAM (72 hours)
```

The OSEE is widely regarded as the most difficult offensive security certification available. There are no shortcuts. The path requires deep technical understanding, thousands of hours of practice, and the ability to think creatively under extreme time pressure. But the skills you develop along this roadmap are genuinely world-class, and the certification represents a level of expertise recognized across the industry.

Start with Phase 1. Do every exercise. Build every exploit. Break every HEVD vulnerability. When you can exploit unknown vulnerabilities on modern, fully-mitigated Windows systems — you're ready.

---

*Last updated: April 2026*
*Note: Course pricing, exam policies, and technical details may change. Always verify current information with OffSec directly at offsec.com.*
