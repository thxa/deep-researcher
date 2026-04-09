# EXP-401: Advanced Windows Exploitation (AWE) - Comprehensive Curriculum Reference

## Course Overview

**Course:** EXP-401 - Advanced Windows Exploitation (AWE)  
**Certification:** OffSec Exploitation Expert (OSEE)  
**Level:** 400 (OffSec's highest tier)  
**Format:** In-person only, instructor-led live training  
**Duration:** 5 days (typically Monday-Friday, full days ~8-10 hours each)  
**Exam:** 72-hour proctored practical exam (71 hours 45 minutes + 24 hours for documentation)  
**Passing Score:** 75 out of 100 points (2 assignments, each worth up to 50 points with 25 for partial completion)

EXP-401 is OffSec's most challenging and advanced course, designed for experienced exploit developers who are ready to tackle complex Windows exploitation at the highest level. The course applies advanced techniques against large, widely-used enterprise applications and the Windows kernel itself. It is delivered exclusively in-person due to the significant learner-instructor interaction required.

---

## Prerequisites

### Required Knowledge
- Proficiency in developing Windows exploits (not an introductory course)
- Strong experience with WinDbg and debugger operation
- Competency in x86 and x86_64 assembly language
- Familiarity with IDA Pro for static analysis
- Basic to intermediate C/C++ programming ability
- Understanding of Windows internals fundamentals
- OffSec strongly recommends completing all 300-level certifications (OSED, OSEP, OSWE) before registering

### Hardware Requirements
- 64-bit laptop/desktop running Windows 11 Professional or above (Home editions will not work)
- Minimum 16 GB RAM, 4 CPU cores
- Minimum 200 GB free disk space
- CPU must support: **SMEP**, **VT-d/IOMMU**, and **VT-x/EPT** (verify via SysInternals CoreInfo)
- Hyper-V enabled on the host OS with Hyper-V Manager installed
- USB port for VM distribution
- Wired and wireless network support
- A Kali Linux 64-bit VM (Hyper-V image from kali.org)

---

## Official Topics Covered (from OffSec)

OffSec lists the following four high-level topic areas for EXP-401:

1. **Bypass and evasion of user mode security mitigations**
2. **Advanced heap manipulations**
3. **Disarming WDEG mitigations and creating version independence**
4. **Bypass of kernel mode security mitigations**

---

## Detailed Course Syllabus / Module Breakdown

The EXP-401 course is structured into major thematic modules that build progressively from user-mode exploitation through kernel-mode exploitation. Based on publicly available information, conference presentations by AWE instructors, recommended reading materials, and the official topic listing, the following represents the curriculum structure.

### Module 1: Advanced Heap Exploitation in User Mode

This opening module addresses one of the most complex areas of modern Windows exploitation: heap manipulation.

**Topics include:**
- Deep dive into the Windows heap manager internals (NT Heap and Segment Heap)
- Understanding the Low Fragmentation Heap (LFH) and its exploitation implications
- Heap metadata corruption techniques and their modern constraints
- Heap spraying and heap grooming/shaping (feng shui) on modern Windows
- Use-after-free (UAF) vulnerability exploitation
- Type confusion vulnerabilities and their exploitation
- Achieving reliable heap layouts for deterministic exploitation
- Heap-based information disclosure techniques
- Practical exploitation of heap vulnerabilities in real-world enterprise software (e.g., browsers, document renderers)

**Key concepts:**
- The evolution from Windows XP's trivially-corruptible heap to the hardened Windows 10/11 heap
- How LFH randomization affects exploitation and how to work around it
- Bucket sizing, allocation patterns, and predictability in the Segment Heap
- Constructing reliable UAF exploitation primitives

### Module 2: Bypass and Evasion of User-Mode Security Mitigations

This module is the heart of the user-mode portion, covering the extensive layered defenses in modern Windows.

#### 2a: Foundational Mitigation Bypasses

**Data Execution Prevention (DEP) / NX:**
- Review of DEP enforcement mechanisms (hardware NX bit, software DEP)
- Return-Oriented Programming (ROP) chain construction on 64-bit Windows
- Stack pivot techniques
- VirtualProtect / VirtualAlloc based ROP payloads
- Challenges of ROP in ASLR-enabled environments

**Address Space Layout Randomization (ASLR):**
- ASLR implementation details on Windows (image randomization, heap randomization, stack randomization)
- Information leakage techniques for defeating ASLR
- Partial overwrites and relative addressing strategies
- Heap spray as an ASLR workaround (spraying known addresses)
- Abusing non-ASLR modules (when available) and why this is increasingly infeasible

#### 2b: Advanced Mitigation Bypasses (WDEG / Windows Defender Exploit Guard)

**Control Flow Guard (CFG):**
- Understanding CFG implementation: bitmap validation of indirect call targets
- Valid call target enumeration and analysis
- CFG bypass techniques:
  - Abusing CFG-valid functions that provide useful primitives
  - Overwriting the CFG bitmap
  - Corrupting the stack (return addresses are not protected by CFG)
  - Targeting longjmp / exception handler dispatch flows
  - Using JIT-compiled code regions

**Arbitrary Code Guard (ACG):**
- ACG prevents dynamic code generation (no RWX pages, no modifying executable pages)
- Impact on traditional shellcode injection and ROP-to-VirtualProtect chains
- ACG bypass strategies:
  - Out-of-process code generation (exploiting JIT server architecture in Edge/Chromium)
  - Abusing existing executable content
  - Return-oriented approaches that avoid VirtualProtect
  - Process-level ACG scope limitations

**Code Integrity Guard (CIG) / Module Signature Enforcement:**
- CIG restricts loading of DLLs to Microsoft-signed binaries only
- Impact on DLL injection techniques
- Bypasses involving already-loaded modules and pure data-oriented approaches

**Child Process Restriction / Process Mitigation Policies:**
- Preventing spawning of child processes from compromised applications
- Impact on traditional exploitation chains that spawn cmd.exe or powershell.exe
- Techniques to work within these restrictions

#### 2c: Creating Version Independence

- Writing exploits that function across multiple Windows versions/builds
- Handling structure offset differences between Windows versions
- Dynamic resolution of offsets and addresses
- Techniques for robust, portable exploit code

### Module 3: Browser/Application Exploitation Case Study

The user-mode modules are typically grounded in real vulnerability case studies against major enterprise software, historically including:

**Vulnerability classes studied:**
- Type confusion vulnerabilities (particularly in scripting engines / JavaScript engines)
- Use-after-free vulnerabilities in complex C++ codebases
- Integer overflow/underflow leading to heap corruption
- Logic vulnerabilities enabling info leaks

**Likely target applications (based on public information and recommended readings):**
- Microsoft Edge (pre-Chromium EdgeHTML engine) or Chromium-based Edge
- Internet Explorer's Chakra/Jscript9 engine (historical)
- Other major Windows enterprise software

**Exploitation flow:**
1. Analyze the vulnerability and understand root cause
2. Achieve controlled memory corruption
3. Convert corruption into an information leak (bypass ASLR)
4. Build a read/write primitive
5. Bypass CFG, ACG, CIG, and other mitigations
6. Achieve code execution despite all mitigations
7. Achieve reliable, version-independent exploitation

### Module 4: Custom Shellcode Development

**Topics include:**
- 64-bit Windows shellcode fundamentals
- Position-independent shellcode construction
- Windows API resolution (PEB walking, hash-based function lookup)
- Syscall-based shellcode to avoid API hooking
- Shellcode for constrained environments (size optimization, character restrictions)
- Egg hunters and staged shellcode for limited buffer scenarios
- Token stealing and privilege manipulation shellcode
- Shellcode that interacts with kernel structures
- Encoding and obfuscation techniques

### Module 5: Sandbox Escapes

Modern browsers and many applications use sandboxing to contain exploitation. This module covers breaking out of these sandboxes.

**Topics include:**
- Windows sandbox architecture (job objects, restricted tokens, integrity levels, appcontainers)
- Chromium/Edge sandbox architecture and broker process communication
- Inter-Process Communication (IPC) attack surface analysis
- Exploiting broker process vulnerabilities for sandbox escape
- Win32k lockdown bypass techniques
- Using kernel vulnerabilities for sandbox escape
- Chaining user-mode exploit with sandbox escape for full compromise

### Module 6: Windows Kernel Exploitation

The kernel exploitation module represents the course's pinnacle of difficulty.

#### 6a: Kernel Exploitation Fundamentals (64-bit)
- Windows kernel architecture review on x64
- Kernel debugging setup and methodology (WinDbg with kernel debug connection)
- Kernel memory layout and important structures (EPROCESS, ETHREAD, KPCR, etc.)
- 64-bit specific considerations: canonical addresses, expanded address space, calling conventions
- Token structures and privilege escalation via token manipulation
- Kernel pool internals (pool types, pool headers, lookaside lists)

#### 6b: Kernel Pool Exploitation
- Windows kernel pool allocator internals
- Pool spray / pool grooming techniques for deterministic layouts
- Pool overflow exploitation
- Pool use-after-free exploitation
- Kernel pool header corruption and its limitations on modern Windows
- Pool-based information disclosure

#### 6c: Kernel-Mode Mitigation Bypasses

**Supervisor Mode Execution Prevention (SMEP):**
- SMEP prevents kernel from executing code in user-mode pages
- SMEP bypass techniques:
  - Kernel ROP chains
  - Flipping the SMEP bit in CR4 via ROP
  - Using existing kernel-mode code gadgets
  - Page table manipulation to remap user pages as kernel pages

**Supervisor Mode Access Prevention (SMAP):**
- SMAP prevents kernel from reading/writing user-mode pages
- Impact on exploitation (can't use user-mode data structures)
- Bypass via controlled kernel stack pivots and kernel-space data

**Kernel Address Space Layout Randomization (KASLR):**
- KASLR implementation on Windows
- Kernel information leak techniques (NtQuerySystemInformation, driver-specific leaks)
- Leveraging low-integrity information disclosure

**Kernel Control Flow Integrity (kCFI) / kCFG:**
- Kernel-mode CFG implementation
- Techniques for operating within or around kCFG constraints

**Virtualization-Based Security (VBS) / Hypervisor-enforced Code Integrity (HVCI):**
- Understanding VBS architecture and Secure Kernel
- HVCI prevents unsigned code in kernel mode
- Impact on exploitation (no kernel shellcode execution, no modification of kernel code pages)
- Data-only attacks as the path forward under HVCI
- Token manipulation without code execution

#### 6d: Driver Exploitation
- Windows driver architecture (WDM, KMDF, filter drivers)
- IOCTL handler vulnerability analysis
- Common driver vulnerability classes:
  - Stack buffer overflows in IOCTL handlers
  - Arbitrary memory read/write via IOCTLs
  - Race conditions (TOCTOU) in driver code
  - Pool buffer overflows in drivers
  - Use-after-free in driver object management
- Third-party driver exploitation as an attack vector
- Bring Your Own Vulnerable Driver (BYOVD) concepts

#### 6e: Putting It All Together - Kernel Exploit Chain
- Combining information leak + code execution + mitigation bypass
- Achieving SYSTEM/Administrator from a sandboxed low-privilege process
- Complete exploitation chains: browser vulnerability -> sandbox escape -> kernel exploit -> SYSTEM
- Writing reliable, weaponized kernel exploits

---

## Day-by-Day Course Structure (5-Day Intensive)

The course runs over 5 full days (historically at conferences like Black Hat, now via OffSec partner events). Evening study is strongly recommended.

### Day 1: Foundations and Heap Exploitation
- Course introduction, lab environment setup, VM distribution
- Review of 64-bit Windows architecture and debugging with WinDbg
- Deep dive into Windows heap internals (NT Heap, Segment Heap, LFH)
- Introduction to the primary user-mode target application and vulnerability
- Heap exploitation fundamentals: spraying, grooming, UAF basics
- **Evening:** Review heap allocator documentation; study recommended reading on DEP/ASLR bypass

### Day 2: User-Mode Exploitation and Mitigation Bypass (Part 1)
- Advanced heap manipulation techniques for reliable exploitation
- Type confusion and UAF exploitation in practice
- Constructing information leak primitives
- ASLR bypass through controlled information disclosure
- Building read/write primitives from heap corruption
- DEP bypass via ROP on 64-bit
- Introduction to CFG and initial bypass strategies
- **Evening:** Review CFG bypass research papers; study WDEG mitigation documentation

### Day 3: User-Mode Exploitation and Mitigation Bypass (Part 2)
- Advanced CFG bypass techniques
- ACG bypass strategies and out-of-process exploitation
- CIG bypass and module loading restrictions
- Combining all bypasses into a complete user-mode exploit chain
- Custom shellcode development for 64-bit Windows
- Sandbox architecture analysis
- Sandbox escape techniques
- Version-independent exploit development
- **Evening:** Review kernel exploitation fundamentals; study x64 virtual memory and SMEP

### Day 4: Kernel Exploitation
- Windows kernel architecture and debugging setup
- Kernel memory layout and critical structures
- Kernel vulnerability analysis (target driver/kernel component)
- Kernel pool exploitation techniques
- SMEP bypass (ROP in kernel mode, CR4 manipulation, PTE overwrite)
- KASLR bypass via information leakage
- Kernel-mode exploit development
- **Evening:** Review kernel exploit; prepare for Day 5 advanced topics

### Day 5: Advanced Kernel Exploitation and Full Chains
- Advanced kernel mitigation bypasses (SMAP, kCFG, VBS/HVCI awareness)
- Data-only kernel attacks
- Driver exploitation techniques
- Building complete exploitation chains (user-mode -> sandbox escape -> kernel -> SYSTEM)
- Exploit reliability and version independence techniques
- Course wrap-up, exam preparation guidance, and Q&A
- Distribution of slide deck and code used in class

> **Note:** The exact day-by-day breakdown varies between offerings. Instructors may adjust pacing based on class progress. The above represents a typical structure derived from the known topic coverage and course duration.

---

## Lab Environment

### Distributed Materials
- **VMware/Hyper-V Virtual Machines** distributed via USB at the start of class, containing:
  - Target Windows machines with vulnerable applications installed
  - Debugging VMs with WinDbg and analysis tools pre-configured
  - Kernel debugging environments with debug-enabled Windows targets
- **Physical course book** (printed; not distributed digitally per OffSec policy)
- **Post-course access to:**
  - Slide deck used by trainers during class
  - All code and scripts demonstrated during the course

### Tools Used
| Tool | Purpose |
|------|---------|
| **WinDbg** (WinDbg Preview / WinDbg classic) | Primary debugger for user-mode and kernel-mode debugging |
| **IDA Pro** | Static analysis, disassembly, and decompilation of target binaries |
| **Visual Studio** | Compiling exploit code, shellcode, and driver interaction tools |
| **Python 3** | Exploit scripting, automation, and helper tool development |
| **NASM / ml64** | Assembly / shellcode compilation |
| **Kali Linux VM** | Network connectivity, VPN to exam environment, auxiliary tools |
| **SysInternals Suite** | Process Monitor, Process Explorer, and other system analysis tools |
| **HyperDbg / VirtualKD / kdnet** | Kernel debugging acceleration and connectivity |
| **Hex editors / binary tools** | Raw binary analysis and manipulation |
| **Custom OffSec tools/scripts** | Provided as part of the course materials |

### Lab Architecture
- Hyper-V based virtualization on the student's Windows 11 host
- Kernel debugging typically via network (kdnet) or named pipe between VMs
- Target VMs represent vulnerable Windows 10/11 configurations
- Isolated network environment for exploit testing

---

## Vulnerability Classes and CVE Case Studies

The AWE course is built around real-world CVEs in major software. While OffSec does not publicly enumerate every CVE covered, the following vulnerability classes and representative CVEs are relevant based on the course's recommended reading, public instructor presentations, and the stated topic areas.

### Vulnerability Classes Covered

| Class | Description | Context |
|-------|-------------|---------|
| **Type Confusion** | Object type mismatch leading to memory corruption | Browser scripting engines (JavaScript/JScript) |
| **Use-After-Free** | Accessing freed memory, enabling heap-based exploitation | Browser DOM, kernel pool objects, driver objects |
| **Heap Overflow** | Writing beyond allocated heap buffer boundaries | Application heap, kernel pool |
| **Integer Overflow/Underflow** | Arithmetic errors leading to undersized allocations | Size calculations in parsers and allocators |
| **Pool Corruption** | Kernel pool metadata/adjacent allocation corruption | Windows kernel, third-party drivers |
| **Race Conditions** | TOCTOU and concurrency bugs in drivers/kernel | IOCTL handlers, file system drivers |
| **Logic Vulnerabilities** | Incorrect assumptions enabling information leaks | Sandbox broker, IPC mechanisms |

### Representative CVEs and Research Areas

The recommended reading list and historical course content reference the following areas:

- **CVE-2015-0336** and similar type confusion vulnerabilities (referenced directly in recommended reading)
- **Edge/Chakra JIT vulnerabilities** (Google Project Zero research on bypassing Edge mitigations is recommended reading)
- **Win32k kernel vulnerabilities** (historically a major source of Windows EoP bugs; relevant to sandbox escape)
- **Browser renderer process exploitation** leading to sandbox escape chains
- **WDEG/CFG bypass research** from Improsec (directly referenced in recommended reading)

> **Note:** Specific CVEs used in the current course offering are not publicly disclosed by OffSec to maintain the integrity of the lab exercises. The course is periodically updated to incorporate modern targets and mitigations.

---

## Progression of Difficulty

The course follows a steep, structured difficulty curve:

```
Difficulty
    ^
    |                                              +-----------+
    |                                         +----| Day 5:    |
    |                                    +----| Full chains,|
    |                               +----| Day 4:    | HVCI,     |
    |                          +----| Kernel     | data-only  |
    |                     +----| Day 3:    | exploit,   | attacks    |
    |                +----| ACG/CIG,  | SMEP/KASLR | & driver   |
    |           +----| Day 2:    | sandbox,  | bypass     | exploitation|
    |      +----| Heap UAF, | shellcode |            |            |
    | +----| Day 1:    | ASLR/DEP, |           |            |            |
    | | Setup,    | info leak,| CFG bypass|           |            |            |
    | | Heap      | ROP x64   |           |           |            |            |
    | | internals |           |           |           |            |            |
    +-+----------+----------+-----------+-----------+------------+------------+-->
                                                                          Time
```

### Phase 1: Foundation Building (Day 1)
- Establishing the debugging environment and workflow
- Understanding heap internals at a deep level
- First exposure to the target vulnerability
- Complexity: **High** (assumes strong pre-existing knowledge)

### Phase 2: User-Mode Exploitation (Days 2-3)
- Building exploitation primitives from heap corruption
- Chaining multiple mitigation bypasses (ASLR -> DEP -> CFG -> ACG -> CIG)
- Each bypass adds another layer of complexity
- Sandbox escape combines all prior techniques
- Complexity: **Very High** (multiple interacting mitigations, requires creative chaining)

### Phase 3: Kernel Exploitation (Days 4-5)
- Complete context switch to kernel-mode exploitation
- Different debugging methodology, different memory model, different constraints
- Kernel mitigations (SMEP, SMAP, kCFG, KASLR) on top of everything else
- Building end-to-end chains from user-mode through kernel
- Complexity: **Extreme** (combines all course knowledge into unified exploitation chains)

---

## The OSEE Exam

### Exam Structure
- **Duration:** 71 hours 45 minutes for exploitation + 24 hours for documentation
- **Format:** Proctored, remote access to exam VPN and target machines via RDP
- **Challenges:** 2 assignments, each worth up to 50 points (25 for partial, 50 for full)
- **Passing:** 75 points required
- **Machine reverts:** 50 total allowed
- **Connection:** Kali Linux via OpenVPN to exam network
- **Tools:** No restrictions on tools (use your own Kali + provided Windows exam targets)

### Exam Expectations
- Discover and exploit **unknown** vulnerabilities in the provided targets
- The exam tests the ability to **think laterally and adapt to new challenges** (not just replay course material)
- Reliable, working exploit code must be provided
- Comprehensive documentation that enables step-by-step reproduction is mandatory
- Exploit code must be submitted as text within the PDF report

### Documentation Requirements
- Use the official OffSec OSEE exam report template
- Document all steps, commands, and console output
- Include screenshots and proof files (proof.txt from Administrator desktops)
- Insufficient documentation results in reduced or zero points
- Submit as PDF within a .7z archive to upload.offsec.com
- MD5 hash verification required upon submission

---

## Recommended Pre-Course Reading

OffSec officially recommends the following reading materials:

| Topic | Resource |
|-------|----------|
| DEP Bypass | [Uninformed - Bypassing DEP](http://uninformed.org/?v=2&a=4) |
| Advanced DEP Bypass | [The Geometry of Innocent Flesh on the Bone](http://cseweb.ucsd.edu/~hovav/dist/geometry.pdf) |
| ASLR Bypass | [The Info Leak Era - Black Hat US 2012 (Fermin Serna)](https://media.blackhat.com/bh-us-12/Briefings/Serna/BH_US_12_Serna_Leak_Era_Slides.pdf) |
| Sandboxing | [Wikipedia: Sandbox (computer security)](https://en.wikipedia.org/wiki/Sandbox_(computer_security)) |
| Windows 10 Mitigations | [Windows 10 Mitigation Improvements - Black Hat US 2016 (Matt Miller, David Weston)](https://www.blackhat.com/docs/us-16/materials/us-16-Weston-Windows-10-Mitigation-Improvements.pdf) |
| Edge Mitigations | [Mitigating Arbitrary Native Code Execution in Edge](https://blogs.windows.com/msedgedev/2017/02/23/mitigating-arbitrary-native-code-execution/) |
| CFG Bypass | [Bypassing Control Flow Guard in Windows 10 (Improsec)](https://blog.improsec.com/tech-blog/bypassing-control-flow-guard-in-windows-10) |
| Edge Mitigation Bypass | [Bypassing Mitigations by Attacking JIT Server (Google Project Zero)](https://googleprojectzero.blogspot.dk/2018/05/bypassing-mitigations-by-attacking-jit.html) |
| Type Confusion | [Understanding Type Confusion Vulnerabilities - CVE-2015-0336 (Microsoft)](https://cloudblogs.microsoft.com/microsoftsecure/2015/06/17/understanding-type-confusion-vulnerabilities-cve-2015-0336/) |
| Kernel Exploitation | [Uninformed - Kernel Exploitation](http://www.uninformed.org/?v=3&a=4&t=pdf) |
| x64 Architecture | [Wikipedia: x86-64](http://en.wikipedia.org/wiki/X86-64) |
| x64 Architecture (MSDN) | [MSDN x64 Architecture](http://msdn.microsoft.com/en-us/library/windows/hardware/ff561499(v=vs.85).aspx) |
| Virtual Memory | [Virtual Memory and Address Translation (UT Austin)](http://www.cs.utexas.edu/users/witchel/372/lectures/15.VirtualMemory.pdf) |
| SMEP Bypass | [Windows SMEP Bypass (Core Security)](https://www.coresecurity.com/corelabs-research/publications/windows-smep-bypass-us) |

---

## Course Materials Summary

| Material | Format | When Received | Restrictions |
|----------|--------|---------------|-------------|
| Course book | Physical printed copy | At class (Day 1) | Must not be shared digitally |
| Lab VMs | Hyper-V images via USB | At class (Day 1) | Personal use |
| Slide deck | Digital (post-class) | After class completion | Study reference |
| Class code/scripts | Digital (post-class) | After class completion | Study reference |
| Discord channel access | Private class channel | Upon registration | Class-specific support |

---

## Key Takeaways

1. **EXP-401 is not an introductory course.** It assumes significant prior exploitation experience and builds upon 300-level knowledge.

2. **The course is exclusively in-person** because the material requires continuous instructor interaction and real-time guidance through extremely complex exploitation chains.

3. **The central challenge is mitigation bypass stacking.** Modern Windows has numerous independent mitigations that must each be defeated, often requiring novel combinations of techniques.

4. **The exam tests adaptability, not memorization.** Candidates face unknown vulnerabilities and must demonstrate the ability to apply course methodology to new targets.

5. **Evening study is expected and necessary.** The pace is extremely aggressive; students who don't review material each evening will fall behind.

6. **Complete exploitation chains are the goal.** The course builds toward combining user-mode exploitation, sandbox escapes, and kernel exploitation into end-to-end attack chains achieving SYSTEM privileges from an unprivileged starting point.

---

*Document compiled from official OffSec course pages, exam guides, FAQ materials, and publicly available information about the AWE/EXP-401 course curriculum. Specific CVEs and detailed lab contents may differ between course offerings as OffSec periodically updates the material.*
