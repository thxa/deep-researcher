# OSEE Prerequisites and Preparation Guide

## EXP-401: Advanced Windows Exploitation -- What It Takes and How to Get There

The OffSec Exploitation Expert (OSEE) is the most demanding certification offered by OffSec. It culminates in a 72-hour proctored exam requiring discovery and exploitation of unknown vulnerabilities in live Windows targets. The training course (EXP-401) is only delivered in-person at live events, and the exam tests not only course content but lateral thinking and adaptability under extreme time pressure.

This guide covers everything you need to know before registering: the prerequisite knowledge, the preparation path, the study resources, the lab setup, and the community that can help you get there.

---

## Table of Contents

1. [Required Background Knowledge](#1-required-background-knowledge)
2. [Recommended Preparation Path](#2-recommended-preparation-path)
3. [Essential Study Resources](#3-essential-study-resources)
4. [Lab Setup for Practice](#4-lab-setup-for-practice)
5. [Community Resources](#5-community-resources)
6. [Exam Overview and Logistics](#6-exam-overview-and-logistics)

---

## 1. Required Background Knowledge

EXP-401 is a 400-level course. OffSec explicitly states: *"We recommend completing the 300-level certifications before registering for this course."* The FAQ is equally direct: this course is **not suitable for beginners**.

### 1.1 Programming Skills

You need working proficiency -- not just familiarity -- in the following:

**C and C++**
- Read and understand C/C++ source code, particularly code involving pointers, memory allocation (`malloc`, `HeapAlloc`, `VirtualAlloc`), type casting, and structures.
- Understand how C code compiles down to assembly: function prologues/epilogues, calling conventions (`__stdcall`, `__fastcall`, x64 calling convention), stack frame layout.
- Write small C programs that interact with the Windows API (file I/O, process creation, memory manipulation, IOCTL communication with drivers via `DeviceIoControl`).

**x86 and x64 Assembly**
- Read disassembly fluently. You should be able to follow control flow, recognize common compiler patterns, and identify vulnerability-relevant constructs (unchecked `memcpy`, integer truncation, etc.) in raw disassembly.
- Understand x64 register conventions (`rcx`, `rdx`, `r8`, `r9` for first four integer arguments; XMM registers for floating point), shadow space, and the differences from x86.
- Write shellcode from scratch: system call stubs, position-independent code, encoder stubs. The OSED course (EXP-301) covers this in depth and is considered prerequisite knowledge.

**Python**
- Automate exploit development workflows: crafting input buffers, packing/unpacking binary structures (`struct` module), socket communication, interacting with debugger APIs.
- Write ROP chain generators, heap spray scripts, and automated exploit delivery tools.
- Use `ctypes` or `pywintypes` to call Windows API functions directly from Python.

### 1.2 Prior Certifications Recommended

OffSec's own guidance is to complete the 300-level certifications first. In practice, the following path is strongly recommended:

| Certification | Course | Why It Matters |
|---|---|---|
| **OSCP** (PEN-200) | Penetration Testing | Baseline offensive methodology, comfort with CTF-style labs, report writing |
| **OSED** (EXP-301) | Windows User Mode Exploit Development | Stack overflows, SEH exploits, DEP/ASLR bypass, ROP chains, custom shellcode, reverse engineering with IDA Pro -- this is the **direct prerequisite** for EXP-401 |
| **OSEP** (PEN-300) | Evasion Techniques and Breaching Defenses | Advanced Windows post-exploitation, antivirus evasion, process injection -- helpful context |
| **OSCE3** | Combination of OSED + OSEP + OSWE | The full 300-level offensive trifecta; demonstrates breadth |

**OSED is the single most important stepping stone.** EXP-301 covers stack buffer overflows, SEH-based exploits, DEP bypass via ROP, ASLR bypass, format string vulnerabilities, custom shellcode development, and reverse engineering -- all of which EXP-401 assumes you already know and builds upon with significantly greater complexity.

### 1.3 Windows Internals Knowledge

EXP-401 covers 64-bit kernel exploitation and advanced heap manipulation. You need a solid foundation in:

**Memory Management**
- Virtual memory, page tables, PTE/PDE structure, kernel vs. user address space split
- Windows memory manager internals: pool allocator (NonPaged pool, PagedPool, session pool), segment heap, LFH (Low Fragmentation Heap), VS (Variable Size) heap
- SLAT/EPT and how virtualization-based security (VBS) affects exploitation

**Process and Thread Architecture**
- `EPROCESS`, `ETHREAD`, `KPROCESS`, `KTHREAD` structures
- Token structures and privilege escalation via token stealing/manipulation
- System call dispatch: `SSDT`, `KiSystemCall64`, the transition from user mode to kernel mode
- Process and thread creation internals

**Windows Kernel Architecture**
- Kernel object types, object manager, handle table
- Driver architecture: `DRIVER_OBJECT`, `DEVICE_OBJECT`, IRP dispatch, IOCTL handling
- Interrupt handling: IDT, IRQL levels, DPC
- How the kernel pool allocator works: pool chunks, pool headers, lookaside lists, pool tags

**Security Mitigations (You Must Understand These to Bypass Them)**
- **User mode**: DEP/NX, ASLR, Stack Cookies (GS), SafeSEH, SEHOP, CFG (Control Flow Guard), CET (Control-flow Enforcement Technology), ACG (Arbitrary Code Guard)
- **Kernel mode**: SMEP (Supervisor Mode Execution Prevention), SMAP (Supervisor Mode Access Prevention), kASLR, NonPagedPoolNx, kernel CFG, HVCI (Hypervisor-protected Code Integrity), KDP (Kernel Data Protection)
- **WDEG (Windows Defender Exploit Guard)**: understanding and disarming these mitigations is an explicit EXP-401 topic

### 1.4 Debugging Experience

You must be proficient -- not just familiar -- with kernel debugging before attending EXP-401.

**WinDbg (Required)**
- Set up kernel debugging over network, serial, or named pipe
- Navigate kernel structures: `!process`, `!thread`, `!pool`, `!pte`, `dt nt!_EPROCESS`, etc.
- Set breakpoints on kernel functions, trace IOCTL dispatch, analyze pool allocations
- Use WinDbg scripting and extensions for automated analysis
- Read and interpret crash dumps (minidumps, kernel dumps)
- Understand and use the `!analyze -v` command for crash triage

**IDA Pro (Required)**
- Static analysis of large binaries and kernel drivers
- Navigate cross-references, identify vulnerability patterns
- Use the decompiler (Hex-Rays) to accelerate understanding of complex code
- Annotate and rename to build understanding of unfamiliar codebases
- The EXP-401 FAQ explicitly lists IDA Pro as a recommended tool

**Supplementary debuggers and tools**
- x64dbg for user-mode debugging
- Process Monitor, Process Explorer, WinObj for runtime system analysis
- Volatility for memory forensics (helpful for understanding kernel structures)
- Binary Ninja or Ghidra as alternatives/supplements to IDA Pro

### 1.5 Networking and Protocol Knowledge

While EXP-401 focuses on local exploitation (kernel drivers, heap manipulation), you should understand:

- TCP/IP fundamentals sufficient to interact with remote targets over VPN
- RDP for connecting to exam machines (the exam provides RDP access to Windows targets)
- SMB and named pipes (relevant to some Windows exploitation scenarios)
- How network-facing services map to kernel-mode drivers and filter drivers

---

## 2. Recommended Preparation Path

### 2.1 OffSec's Own Prerequisites

From the official EXP-401 FAQ:

> *"Learners should have experience in developing Windows exploits and be proficient in operating a debugger. Familiarity with tools such as WinDBG, x86_64 assembly, IDA Pro, and basic C/C++ programming is highly recommended. A strong willingness to work and dedicate real effort will greatly aid in success in this security training course."*

And from the course page:

> *"As the most complex course we offer, the EXP-401 requires a significant time investment. Learners need to commit to reading case studies and reviewing the provided reading material each evening. We recommend completing the 300-level certifications before registering for this course."*

### 2.2 The Preparation Ladder

Here is a realistic progression path from intermediate to OSEE-ready:

#### Phase 1: Foundations (3-6 months)

**Goal**: Get comfortable with basic exploit development and Windows internals.

- Complete OSCP (PEN-200) if you haven't already
- Work through Corelan's free exploit writing tutorials (parts 1-11) at https://www.corelan.be/
  - Part 1: Stack Based Overflows
  - Part 2: Jumping to Shellcode
  - Part 3/3b: SEH Based Exploits
  - Part 6: Bypassing Stack Cookies, SafeSEH, DEP, ASLR
  - Part 9: Introduction to Win32 Shellcoding
  - Part 10: Chaining DEP with ROP
  - Part 11: Heap Spraying Demystified
- Read "Windows Internals, Part 1" (Chapters 1-5, focusing on system architecture, processes/threads, and memory management)
- Practice basic kernel debugging: set up a two-VM kernel debug environment, load a simple driver, set breakpoints, inspect structures

#### Phase 2: Intermediate Exploit Development (4-8 months)

**Goal**: Achieve OSED-level proficiency. This is the critical gate.

- Complete EXP-301 (OSED) -- **this is the single most important preparatory step**
  - Stack overflows with modern mitigations
  - Reverse engineering with IDA Pro and debuggers
  - Custom shellcode development
  - DEP bypass via ROP chain construction
  - ASLR bypass techniques
  - Format string vulnerabilities
- Begin "The Shellcoder's Handbook" (focus on Windows chapters)
- Start practicing with HEVD (HackSys Extreme Vulnerable Driver) -- basic vulnerabilities first:
  - Stack Buffer Overflow
  - Arbitrary Write (Write-What-Where)
  - Type Confusion
  - Null Pointer Dereference
  - Integer Overflow

#### Phase 3: Advanced Windows Exploitation (6-12 months)

**Goal**: Build kernel exploitation and advanced heap manipulation skills.

- Complete advanced HEVD challenges:
  - Pool Buffer Overflow (NonPagedPool, NonPagedPoolNx, PagedPoolSession)
  - Use-After-Free (NonPagedPool, NonPagedPoolNx)
  - Double Fetch (race conditions)
  - Uninitialized Memory (Stack and Pool)
  - Memory Disclosure / Info Leak
- Study Windows kernel pool internals in depth (pool headers, pool alignment, pool coalescing, allocation strategies on different Windows versions)
- Learn SMEP, SMAP, and kASLR bypass techniques
- Study real-world kernel exploits (CVE write-ups, Project Zero blog posts)
- Consider attending Corelan's professional training:
  - **Corelan Stack** (bootcamp on stack-based exploitation)
  - **Corelan Heap** (heap exploitation deep-dive)
- Read "A Guide to Kernel Exploitation" (Perla & Oldani)
- Read "Windows Internals, Part 2" (especially I/O system, kernel-mode drivers)
- Practice writing kernel exploits that work on Windows 10/11 with modern mitigations enabled

#### Phase 4: Pre-Course Preparation (1-3 months before EXP-401)

**Goal**: Sharpen skills to exam readiness.

- Review all HEVD solutions, especially on modern Windows 10/11 with SMEP/kASLR enabled
- Study advanced heap manipulation: heap feng shui, pool grooming, spray techniques for kernel pools
- Practice 64-bit kernel exploitation specifically (EXP-401 focuses on 64-bit)
- Study WDEG (Windows Defender Exploit Guard) mitigations and bypass techniques
- Review CFG bypass techniques
- Ensure you can set up a full kernel debugging environment from scratch quickly
- Practice writing detailed exploitation reports (the exam requires a comprehensive report)

### 2.3 Timeline Estimates

| Starting Point | Estimated Time to OSEE-Ready |
|---|---|
| OSCP holder with basic exploit dev experience | 18-30 months |
| OSED holder with kernel debugging exposure | 8-14 months |
| OSCE3 holder with kernel exploitation experience | 4-8 months |
| Professional exploit developer / vulnerability researcher | 2-4 months |

These are rough estimates. The actual timeline depends heavily on how many hours per week you dedicate and your aptitude for low-level systems work. OSEE is not a certification you rush toward.

---

## 3. Essential Study Resources

### 3.1 Books

#### Tier 1: Must-Read

| Book | Authors | Why |
|---|---|---|
| **Windows Internals, Part 1** (7th ed.) | Mark Russinovich, David Solomon, Alex Ionescu, Andrea Allievi | Definitive reference on Windows architecture, processes, threads, memory management. Chapters on memory management and system mechanisms are essential. |
| **Windows Internals, Part 2** (7th ed.) | Same | I/O system, kernel-mode drivers, security -- directly relevant to driver exploitation. |
| **The Shellcoder's Handbook** (2nd ed.) | Chris Anley, John Heasman, Felix Lindner, Gerardo Richarte | Foundational exploit development text covering stack/heap overflows, format strings, shellcoding, Windows-specific techniques. |
| **A Guide to Kernel Exploitation** | Enrico Perla, Massimiliano Oldani | Covers kernel exploitation on multiple OS's with strong Windows coverage: pool overflows, race conditions, kernel object abuse. |

#### Tier 2: Highly Recommended

| Book | Authors | Why |
|---|---|---|
| **Windows Kernel Programming** (2nd ed.) | Pavel Yosifovich | Practical guide to writing Windows drivers -- understanding driver architecture is essential for exploiting drivers. |
| **The Art of Software Security Assessment** | Mark Dowd, John McDonald, Justin Schuh | Vulnerability discovery methodology, code auditing techniques, Windows-specific vulnerability classes. |
| **Practical Reverse Engineering** | Bruce Dang, Alexandre Gazet, Elias Bachaalany | x86/x64 reverse engineering, Windows kernel internals from a reversing perspective, WinDbg usage. |
| **The IDA Pro Book** (2nd ed.) | Chris Eagle | Mastering IDA Pro for static analysis -- essential for reverse engineering targets in EXP-401. |
| **Rootkits: Subverting the Windows Kernel** | Greg Hoglund, Jamie Butler | Kernel-level techniques, hooking, DKOM -- provides attacker perspective on kernel manipulation. |

#### Tier 3: Supplementary

| Book | Authors | Why |
|---|---|---|
| **Hacking: The Art of Exploitation** (2nd ed.) | Jon Erickson | Good general foundations if your exploit dev background is weak. |
| **Intel 64 and IA-32 Architectures Software Developer's Manual** | Intel Corporation | Reference for x86/x64 architecture, paging, segmentation, privilege levels. Free from Intel. |
| **Attacking Network Protocols** | James Forshaw | Understanding protocol-level attack surfaces. |

### 3.2 Online Courses and Training

#### OffSec Courses (Primary Path)

| Course | Code | Relevance |
|---|---|---|
| Windows User Mode Exploit Development | **EXP-301 (OSED)** | **Direct prerequisite** -- stack exploits, ROP, ASLR bypass, custom shellcode, IDA Pro |
| Evasion Techniques and Breaching Defenses | **PEN-300 (OSEP)** | Windows evasion, process injection, AV bypass |
| Penetration Testing with Kali Linux | **PEN-200 (OSCP)** | Foundational offensive security |

#### Third-Party Training

| Provider | Course | Relevance |
|---|---|---|
| **Corelan Training** | Corelan Stack + Corelan Heap | Peter Van Eeckhoutte's legendary exploit development classes. Covers stack and heap exploitation on modern Windows with hands-on labs. Taught in-person. Widely regarded as some of the best exploit development training available. |
| **HackSys Team** | Windows Kernel Exploitation workshops | The creators of HEVD; their workshops walk through kernel exploitation from basics to advanced. |
| **Connor McGarr** | Blog/talks on kernel exploitation | Modern Windows kernel exploitation techniques, SMEP/SMAP bypass, page table manipulation |
| **Alex Ionescu / Pavel Yosifovich** | Windows Internals training | Deep-dive Windows internals training from the book authors |

#### Free/Self-Paced Online Resources

| Resource | URL | Topics |
|---|---|---|
| Corelan Exploit Writing Tutorials | https://www.corelan.be/index.php/articles/ | 11-part exploit writing tutorial series, heap spraying, ROP, mona.py |
| FuzzySecurity Tutorials | https://www.fuzzysecurity.com/tutorials.html | Exploit development tutorials including kernel exploitation with HEVD (parts 14-20) |
| wetw0rk Kernel Exploitation Series | https://wetw0rk.github.io/ | Comprehensive HEVD walkthrough series covering stack overflow, UAF, pool overflow, type confusion, race conditions, and modern mitigations |
| Kristal-G HEVD Write-ups | https://kristal-g.github.io/ | HEVD exploitation on Windows 10 RS5 x64 with modern mitigations |
| OSR Online | https://www.osr.com/ | Windows driver development resources, articles, and webinars |

### 3.3 Blog Posts and Write-Ups from OSEE Holders and Researchers

These blog series and posts cover topics directly relevant to EXP-401 content:

**Kernel Exploitation**
- Connor McGarr's blog: Exploiting Windows kernel, SMEP bypass, page table manipulation, ROP in kernel context
  - https://connormcgarr.github.io/
- j00ru (Mateusz Jurczyk / Google Project Zero): Windows kernel vulnerability research, pool exploitation
  - https://j00ru.vexillium.org/
- Alex Ionescu's blog: Windows internals research
  - https://www.alex-ionescu.com/
- Hacker House blog: Various Windows kernel exploitation write-ups
- k0shl (CVE write-ups for Windows kernel vulnerabilities)

**Heap Exploitation**
- Corelan: "Windows 10 x86/wow64 Userland heap" (2016)
- Corelan: "Heap Layout Visualization with mona.py and WinDBG"
- Chris Valasek's Windows heap research papers
- Ben Hawkes: "Attacking the Windows 7/8 Heap" (papers and talks)

**Mitigation Bypasses**
- j00ru: "A Story of a One-Byte Kernel Buffer Overflow" 
- Google Project Zero blog: Multiple posts on Windows mitigation bypass
- Microsoft Security Response Center (MSRC) blog posts on mitigation design

### 3.4 Practice Targets

#### HackSys Extreme Vulnerable Driver (HEVD)

**The single most important practice target for OSEE preparation.**

- Repository: https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- Pre-built releases available; also buildable with Visual Studio + WDK
- Implements the following vulnerability classes:
  - Stack Buffer Overflow (with and without GS)
  - Pool Buffer Overflow (NonPagedPool, NonPagedPoolNx, PagedPoolSession)
  - Use-After-Free (NonPagedPool, NonPagedPoolNx)
  - Type Confusion
  - Integer Overflow (Arithmetic)
  - Arbitrary Write / Write-What-Where
  - Null Pointer Dereference
  - Double Fetch (race condition)
  - Uninitialized Memory (Stack and Pool)
  - Memory Disclosure / Info Leak
  - Arbitrary Increment
  - Insecure Kernel Resource Access
  - Write NULL

**Recommended HEVD progression:**

1. Stack Buffer Overflow on Windows 7 x86 (no mitigations) -- understand the basics
2. Stack Buffer Overflow on Windows 10 x64 with SMEP -- learn SMEP bypass
3. Arbitrary Write on Windows 7 x86 -- token stealing via HalDispatchTable
4. Arbitrary Write on Windows 10 x64 -- modern techniques
5. Pool Overflow (NonPagedPool) -- pool grooming, pool spray, adjacent object corruption
6. Pool Overflow (NonPagedPoolNx) -- dealing with NX pools
7. Use-After-Free -- object lifecycle, dangling pointers, pool feng shui
8. Type Confusion -- type checking failures, vtable hijacking
9. Double Fetch -- race conditions, thread scheduling exploitation
10. Memory Disclosure / Info Leak -- building read primitives

#### Exploit Development Solutions and References for HEVD

- https://github.com/wetw0rk/Exploit-Development/tree/master/HEVD-Exploits
- https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn
- https://github.com/FULLSHADE/Windows-Kernel-Exploitation-HEVD
- https://github.com/tekwizz123/HEVD-Exploit-Solutions
- https://github.com/sizzop/HEVD-Exploits
- https://github.com/GradiusX/HEVD-Python-Solutions
- https://github.com/theevilbit/exploits/tree/master/HEVD
- https://github.com/w4fz5uck5/3XPL01t5/tree/master/OSEE_Training
- https://github.com/badd1e/bug-free-adventure

#### Other Practice Targets

| Target | Description |
|---|---|
| **Vulnerable-by-design kernel drivers** | Write your own simple vulnerable driver to understand driver architecture from the inside |
| **Old CVEs with PoC code** | Reproduce published kernel CVEs (e.g., CVE-2014-4113, CVE-2016-7255, CVE-2020-0796) in controlled lab environments |
| **User-mode exploit development** | Vulnserver, SLMail, various OffSec Proving Grounds targets for maintaining user-mode exploit dev skills |
| **Kernel CTF challenges** | Google's kernelCTF, various CTF kernel pwn challenges |

### 3.5 Exploit Development CTF Challenges

- **pwn.college** -- kernel exploitation modules
- **Google kernelCTF** -- https://google.github.io/security-research/kernelctf/
- **Hack The Box** -- some machines and challenges involve Windows exploit development
- **OffSec Proving Grounds** -- practice targets for maintaining OSCP-level skills
- **CTFtime.org** -- search for kernel pwn challenges from major CTFs (HITCON, 0CTF, Google CTF)

---

## 4. Lab Setup for Practice

### 4.1 Hardware Requirements

From the official EXP-401 FAQ, the course laptop requirements are:

- **OS**: Windows 10 (only supported host OS for the course)
- **Hypervisor**: VMware Workstation 15 or higher
- **CPU**: 64-bit, minimum 4 cores, with NX, SMEP, VT-d/IOMMU, and VT-x/EPT support
- **Disk**: Minimum 160 GB free
- **RAM**: At least 16 GB (32 GB strongly recommended for comfortable kernel debugging with multiple VMs)

For your personal practice lab, aim higher:

- **RAM**: 32 GB or more (you will regularly run 2-3 VMs simultaneously)
- **CPU**: 6-8+ cores with full hardware virtualization support
- **Disk**: SSD strongly recommended (NVMe preferred); kernel debugging involves constant disk I/O for symbol loading
- **Hypervisor**: VMware Workstation Pro (preferred for kernel debugging features) or Hyper-V

### 4.2 Virtual Machine Setup for Kernel Debugging

**The Debugging Setup (Two-VM Method):**

```
[Host Machine]
    |
    |-- [Debugger VM] - Windows 10/11, runs WinDbg, IDA Pro
    |       |
    |       |-- Named Pipe / Network debug connection
    |       |
    |-- [Debuggee VM] - Windows 10/11 (Target), runs vulnerable drivers
```

**Step-by-step setup:**

1. **Create the Debuggee (Target) VM**
   - Install Windows 10 or Windows 11 (match the version you want to practice on)
   - Enable test signing: `bcdedit /set testsigning on`
   - Disable Secure Boot in VM settings
   - Enable kernel debugging: `bcdedit /debug on`
   - Configure debug transport:
     - **Network**: `bcdedit /dbgsettings net hostip:<debugger_ip> port:50000 key:<your_key>` (fastest)
     - **Serial/Named Pipe**: `bcdedit /dbgsettings serial debugport:1 baudrate:115200` (most compatible)
   - Disable Driver Signature Enforcement for loading test drivers:
     - Boot with `bcdedit /set nointegritychecks on` or
     - Boot to Advanced Startup Options and select "Disable driver signature enforcement"
   - Install vulnerable drivers (HEVD, custom test drivers)

2. **Create the Debugger VM (or use host)**
   - Install Windows 10/11 with development tools
   - Install WinDbg (WinDbg Preview from Microsoft Store, or classic WinDbg from Windows SDK)
   - Configure WinDbg to connect to the debuggee (File > Kernel Debug > choose transport)
   - Set symbol path: `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`
   - Configure source path if you have source for the target drivers

3. **Verify connectivity**
   - Start WinDbg kernel debugger, then boot the debuggee VM
   - Confirm you can break in (`Ctrl+Break` or `Debug > Break`)
   - Verify symbols load: `lm` should show loaded modules with symbols

**Alternative: Single-VM with local kernel debugging**
- `bcdedit /debug on` with local debugging in WinDbg (`File > Kernel Debug > Local`)
- Limited but useful for quick inspections -- you cannot set breakpoints or step through code

### 4.3 Essential Tools to Install and Master

#### Debuggers

| Tool | Purpose | Notes |
|---|---|---|
| **WinDbg / WinDbg Preview** | Kernel debugging, crash dump analysis | The primary tool. Learn the command set deeply. |
| **x64dbg** | User-mode debugging | Excellent for user-mode exploit development |
| **GDB** | Linux kernel debugging (if studying comparative approaches) | Useful for understanding concepts cross-platform |

#### Disassemblers / Decompilers

| Tool | Purpose | Notes |
|---|---|---|
| **IDA Pro** (with Hex-Rays decompiler) | Static analysis, reverse engineering | Industry standard. Explicitly required by OffSec for EXP-301 and EXP-401. |
| **Ghidra** | Free alternative disassembler/decompiler | NSA's tool, very capable, good for budget-constrained practice |
| **Binary Ninja** | Alternative disassembler | Clean UI, good API for scripting |

#### System Inspection Tools

| Tool | Purpose |
|---|---|
| **Process Monitor (ProcMon)** | Real-time file system, registry, process/thread activity monitoring |
| **Process Explorer** | Advanced task manager, process tree, handle/DLL inspection |
| **WinObj** | Windows Object Manager namespace browser |
| **PoolMon** | Kernel pool allocation monitor (comes with WDK) |
| **Driver Verifier** | Detect driver bugs, monitor pool usage |
| **OSR Driver Loader** | Load/unload test-signed kernel drivers |
| **DbgView (DebugView)** | Capture kernel debug output (`DbgPrint`) |
| **AccessChk** | Check security descriptors on objects, services, drivers |

#### Development Tools

| Tool | Purpose |
|---|---|
| **Visual Studio 2019/2022** | Building drivers and exploit PoCs |
| **Windows Driver Kit (WDK)** | Required for building and testing kernel drivers |
| **Windows SDK** | Headers, libraries, tools (including classic WinDbg) |
| **NASM / MASM** | Assemblers for writing shellcode |
| **Python 3** | Exploit scripting, automation |
| **mona.py** | Immunity Debugger / WinDbg plugin for exploit development automation |

#### Exploit Development Utilities

| Tool | Purpose |
|---|---|
| **ROPgadget / ropper** | ROP gadget finding |
| **pwntools** | Exploit development framework (primarily Linux but concepts transfer) |
| **Capstone** | Disassembly framework (Python bindings) |
| **Keystone** | Assembler framework (Python bindings) |
| **Unicorn** | CPU emulator framework for testing shellcode |

### 4.4 Recommended VM Inventory

Maintain multiple target VMs to test exploits across Windows versions:

| VM | Purpose |
|---|---|
| **Windows 7 SP1 x86** | Legacy practice -- fewer mitigations, easier to learn fundamentals |
| **Windows 7 SP1 x64** | Bridge between 32/64-bit exploitation |
| **Windows 10 1607 (RS1)** | Early Windows 10, some mitigations but not all |
| **Windows 10 1809 (RS5)** | Common target for HEVD write-ups with modern mitigations |
| **Windows 10 21H2/22H2** | Modern mitigations including segment heap changes |
| **Windows 11** | Latest mitigations -- final test for exploit reliability |
| **Windows Server 2016/2019** | Server variants may have different pool behavior and mitigations |

**Tip**: Use VMware snapshots extensively. Take clean snapshots after initial OS install, after tool installation, and before each exploitation attempt.

---

## 5. Community Resources

### 5.1 Forums and Discord Servers

| Community | Platform | Notes |
|---|---|---|
| **OffSec Discord** | https://discord.com/invite/offsec | Official OffSec community. Has channels for EXP-301, AWE/EXP-401 discussion. Students helping students. |
| **Corelan Discord** | https://www.corelan.be/index.php/discord/ | Community around Corelan's exploit writing tutorials and training |
| **HackSys Team Discord** | https://discord.com/invite/ns32uNhaq7 | HEVD creators' community -- ask questions about kernel exploitation practice |
| **InfoSec Prep Discord** | Various | Multiple Discord servers focused on OffSec certification prep |
| **r/oscp / r/OffSec** | Reddit | Community discussion, experience reports, study tips |

### 5.2 Conference Talks

These talks cover topics directly relevant to EXP-401 preparation:

**Kernel Exploitation**
- **"Windows Kernel Exploitation Techniques"** -- various presenters at Black Hat, DEF CON, OffensiveCon
- **"One Bit to Rule a System"** -- Niklas Baumstark, Project Zero -- kernel exploit techniques
- **"Kernel Pool Exploitation on Windows 7"** -- Tarjei Mandt -- foundational pool exploitation research
- **"Sheep Year Kernel Heap Fengshui on Windows"** -- research on modern pool spraying techniques
- **"Scoop the Windows 10 Pool!"** -- Yarden Shafir / Alex Ionescu -- pool internals on modern Windows
- **"Zero Day Zen Garden: Windows Exploit Development"** -- various at DEF CON workshops

**Heap Exploitation**
- **"Attacking the Windows Kernel Pool"** -- Tarjei Mandt (BH DC 2011)
- **"Advanced Heap Manipulation in Windows 8"** -- Zhenhua Liu (Black Hat EU 2013)
- **"The Slab Allocator / Pool Allocator Internals"** -- various talks on allocator internals

**Mitigation Bypass**
- **"Bypassing SMEP by Example"** -- various talks showing SMEP bypass chains
- **"Windows 10 Mitigations Improvements"** -- Matt Miller (Microsoft) -- understand what you're bypassing
- **"Demystifying Kernel Exploitation by Abusing GDI Objects"** -- various presenters

### 5.3 GitHub Repositories for Practice and Study

| Repository | Content |
|---|---|
| **hacksysteam/HackSysExtremeVulnerableDriver** | The primary practice driver for kernel exploitation |
| **FULLSHADE/Windows-Kernel-Exploitation-HEVD** | Comprehensive HEVD solutions collection |
| **wetw0rk/Exploit-Development** | HEVD exploits and general exploit development resources |
| **FuzzySecurity/HackSysTeam-PSKernelPwn** | PowerShell-based HEVD exploitation |
| **connormcgarr/Kernel-Exploits** | Connor McGarr's kernel exploit collection |
| **w4fz5uck5/3XPL01t5/OSEE_Training** | OSEE-specific training exploits |
| **GradiusX/HEVD-Python-Solutions** | Python-based HEVD solutions |
| **sam-b/windows_kernel_resources** | Curated list of Windows kernel exploitation resources |
| **SecWiki/windows-kernel-exploits** | Collection of Windows kernel exploit CVE PoCs |
| **corelan/mona** | mona.py exploit development assistant for debuggers |

### 5.4 Key Researchers to Follow

These researchers regularly publish content relevant to OSEE-level exploitation:

| Researcher | Platform | Focus Area |
|---|---|---|
| **Mateusz Jurczyk (j00ru)** | Blog, Project Zero | Windows kernel vulnerability research |
| **Alex Ionescu** | Blog, Twitter/X | Windows internals authority |
| **Connor McGarr** | Blog, GitHub | Windows kernel exploitation, SMEP bypass |
| **Peter Van Eeckhoutte (corelanc0d3r)** | Corelan.be | Exploit development tutorials, mona.py |
| **b33f (FuzzySecurity)** | FuzzySecurity.com | Windows exploit dev tutorials including HEVD |
| **Ashfaq Ansari** | HackSys.io | HEVD creator, Windows kernel exploitation |
| **Tarjei Mandt** | Research papers | Windows kernel pool exploitation research |
| **Yarden Shafir** | Blog, talks | Modern Windows kernel pool internals |

---

## 6. Exam Overview and Logistics

### 6.1 Exam Format

From the official OSEE Exam Guide:

- **Duration**: 71 hours and 45 minutes (approximately 72 hours)
- **Format**: Proctored, remote, over VPN
- **Access**: RDP to target Windows machines in the exam lab
- **Objectives**: Two assignments; each worth up to 50 points (25 for partial, 50 for full completion)
- **Passing score**: 75 out of 100 points
- **Report deadline**: 24 hours after exam ends to upload documentation
- **Report format**: PDF in .7z archive, using the OffSec-provided template
- **Machine reverts**: Up to 50 total reverts via student control panel

### 6.2 What the Exam Tests

The exam evaluates:

1. **Vulnerability discovery** -- finding unknown vulnerabilities in provided software
2. **Exploit development** -- crafting working exploits that bypass modern mitigations
3. **Lateral thinking** -- adapting techniques to new and unfamiliar targets
4. **Documentation** -- detailed, reproducible reports with screenshots, commands, code, and explanations

The exam explicitly tests beyond the course material. You must demonstrate the ability to **adapt and combine techniques creatively**, not just replay course exercises.

### 6.3 Exam Preparation Tips

- **Practice report writing early.** The documentation requirements are strict. Missing screenshots or insufficient detail results in zero points for that section.
- **Build reliable exploits.** Your exploit code must work when the OffSec team reproduces it. Fragile exploits that only work some of the time will cost you.
- **Manage your time.** 72 hours sounds like a lot, but you need to sleep. Budget time for rest -- exhaustion leads to mistakes in complex kernel exploitation.
- **Prepare your environment in advance.** Have your debugging tools, scripts, and templates ready before the exam starts.
- **Take notes in real time.** Document every step as you go rather than trying to reconstruct your work later.

### 6.4 Course Logistics

- **EXP-401 is only available as in-person, live training** (typically 5 days)
- Training events are held at various locations worldwide through OffSec and authorized training partners
- Upcoming events are listed at https://www.offsec.com/events/training/
- The course involves case studies based on large, real-world enterprise applications
- Students are expected to read case studies and review materials each evening during the course
- The course does **not** include online content -- all materials are distributed in-class via USB

---

## Summary: The OSEE Readiness Checklist

Before registering for EXP-401, verify you can answer "yes" to all of these:

- [ ] I can write a working stack buffer overflow exploit with DEP/ASLR bypass on a modern Windows target
- [ ] I can write custom shellcode (not just use msfvenom)
- [ ] I can construct ROP chains manually using gadgets from target binaries
- [ ] I can reverse engineer a binary to locate a vulnerability using IDA Pro
- [ ] I can set up and operate a kernel debugging environment with WinDbg
- [ ] I understand Windows kernel architecture: drivers, IRPs, IOCTL dispatch
- [ ] I can explain how SMEP, SMAP, kASLR, NonPagedPoolNx, and kernel CFG work
- [ ] I have exploited at least 5 different vulnerability types in HEVD on Windows 10 x64
- [ ] I understand pool allocation internals well enough to perform pool grooming/spray
- [ ] I can write a kernel exploit that achieves privilege escalation via token stealing
- [ ] I can write a clear, detailed exploitation report that someone else could reproduce
- [ ] I have OSED (or equivalent exploit development experience)
- [ ] I am prepared to dedicate 72+ continuous hours of focused effort in the exam

If you have gaps, use the resources in this guide to close them systematically. OSEE rewards deep understanding over breadth -- focus on truly mastering each topic rather than superficially covering many.

---

*This guide was compiled from official OffSec documentation (EXP-401 course page, EXP-401 FAQ, OSEE Exam Guide), Corelan training resources, the HEVD project, and community knowledge. All URLs and references were verified at time of writing.*
