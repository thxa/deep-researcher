# Security Research Glossary

Comprehensive reference for specialized terms, abbreviations, and jargon used across this repository's eight research tracks.

## Table of Contents

- [A](#a) | [B](#b) | [C](#c) | [D](#d) | [E](#e) | [F](#f) | [G](#g) | [H](#h)
- [I](#i) | [J](#j) | [K](#k) | [L](#l) | [M](#m) | [N](#n) | [O](#o) | [P](#p)
- [Q](#q) | [R](#r) | [S](#s) | [T](#t) | [U](#u) | [V](#v) | [W](#w) | [X](#x)
- [Y](#y) | [Z](#z)

---

## A

**AAPT** — Android Asset Packaging Tool; compiles resources and DEX into APK packages. *Track: Android*

**ACG** — Arbitrary Code Guard; Windows mitigation that prevents creation of new executable memory in a process, blocking shellcode injection. *See also: [CIG](#c), [DEP](#d), [CFG](#c)* • *Track: OSEE/EXP-401*

**ACPI** — Advanced Configuration and Power Interface; specification for device configuration and power management, enumerable from Ring 0. *See also: [SMM](#s), [SMI](#s)* • *Track: CPU Protection Rings*

**adb** — Android Debug Bridge; command-line tool for device communication, debugging, and shell access. *See also: [fastboot](#f)* • *Track: Android*

**AFL** — American Fuzzy Lop; pioneering coverage-guided fuzzer by Michał Zalewski; the original codebase that AFL++ extends. *See also: [AFL++](#a), [coverage-guided](#c)* • *Track: Fuzzing*

**AFL++** — Community-driven fork of AFL with enhanced instrumentation, cmplog, custom mutators, and persistent-mode improvements. *See also: [AFL](#a), [libFuzzer](#l), [cmplog](#c)* • *Track: Fuzzing*

**AIDL** — Android Interface Definition Language; defines IPC interfaces between Android components, the successor to HIDL for Treble. *See also: [HIDL](#h), [Binder](#b)* • *Track: Android*

**AMFI** — Apple Mobile File Integrity; macOS/iOS kernel extension enforcing code signing and entitlement checks at exec time. *See also: [SIP](#s), [code signing](#c), [entitlements](#e)* • *Track: macOS/XNU*

**AMD PSP** — Platform Security Processor; an ARM-based secure coprocessor embedded in AMD processors, analogous to Intel ME. *See also: [Intel ME](#i), [SMM](#s)* • *Track: CPU Protection Rings*

**AMD-V** — AMD's hardware virtualization extension (SVM); enables efficient virtual machine execution on AMD processors. *See also: [VT-x](#v), [SVM](#s), [VMCB](#v)* • *Track: CPU Protection Rings*

**AMT** — Active Management Technology; Intel ME subsystem providing remote management (KVM, IDE-R, SOL); widely targeted in firmware attacks. *See also: [Intel ME](#i), [HAP](#h)* • *Track: CPU Protection Rings*

**AOSP** — Android Open Source Project; the reference codebase for the Android operating system maintained by Google. *See also: [GKI](#g), [Treble](#t)* • *Track: Android*

**APIC** — Advanced Programmable Interrupt Controller; x86 interrupt controller replacing the legacy PIC, supporting multi-CPU interrupt distribution. *See also: [PIC](#p), [IDT](#i)* • *Track: CPU Protection Rings*

**APEX** — Android Pony EXpress; a modular delivery format for updatable system components (e.g., runtime, media), introduced in Android 10. *See also: [GKI](#g), [Treble](#t)* • *Track: Android*

**AppArmor** — Linux MAC implementation using path-based profiles to confine programs; default in Ubuntu. *See also: [SELinux](#s), [TOMOYO](#t), [Smack](#s), [MAC](#m)* • *Track: Linux Kernel Security*

**APT** — Advanced Persistent Threat; a threat actor that maintains long-term, covert access to target networks, typically nation-state sponsored. *See also: [APT28](#a), [APT29](#a), [Lazarus](#l)* • *Track: Zero-Day Research*

**APT28** — Russian GRU-linked APT group (aka Fancy Bear, Sofacy); known for zero-day and exploit kit deployment. *See also: [APT29](#a), [Equation Group](#e)* • *Track: Zero-Day Research*

**APT29** — Russian FSB-linked APT group (aka Cozy Bear, The Dukes); attributed to SolarWinds supply-chain compromise. *See also: [APT28](#a), [Lazarus](#l)* • *Track: Zero-Day Research*

**arb read** — Arbitrary read; a vulnerability primitive allowing an attacker to read memory at any address. *See also: [arb write](#a), [primitive](#p)* • *Track: Exploitation*

**arb write** — Arbitrary write; a vulnerability primitive allowing an attacker to write to any memory address, often the goal post-OOB. *See also: [arb read](#a), [primitive](#p), [modprobe_path](#m)* • *Track: Exploitation*

**ART** — Android Runtime; the ahead-of-time compiled runtime replacing Dalvik, using dex2oat to produce native code. *See also: [dalvik](#d), [dex2oat](#d)* • *Track: Android*

**ASan** — AddressSanitizer; compiler instrumentation detecting heap/stack/global buffer overflows, use-after-free, and double-free bugs. *See also: [MSan](#m), [UBSan](#u), [TSan](#t), [LSan](#l), [KASAN](#k)* • *Track: Fuzzing*

**ASLR** — Address Space Layout Randomization; defense that randomizes the base addresses of stack, heap, libraries, and executable at load time. *See also: [KASLR](#k), [PIE](#p), [DEP](#d)* • *Track: Mitigation & Defense*

**auditd** — Linux audit daemon; records systemcall-based security events per rules defined in audit policy, used for intrusion detection. *See also: [SELinux](#s), [MAC](#m)* • *Track: Linux Kernel Security*

---

## B

**BC_FREE_BUFFER** — Binder command to release a transaction buffer back to the kernel; failure to invoke can leak Binder memory. *See also: [BR_TRANSACTION](#b), [binder_proc](#b)* • *Track: CVE-2023-20938*

**Binder** — Android's primary IPC mechanism; a kernel subsystem enabling synchronous and asynchronous transaction-based communication between processes. *See also: [Binder IPC](#b), [binder_proc](#b), [binder_node](#b)* • *Track: Android*

**Binder IPC** — The inter-process communication protocol built on the Binder kernel driver; all Android system services communicate via Binder. *See also: [Binder](#b), [Parcel](#p), [AIDL](#a)* • *Track: Android*

**binder_node** — Kernel structure representing a Binder object reference in a process; tracks refcount and is central to the UAF in CVE-2023-20938. *See also: [binder_proc](#b), [binder_thread](#b), [UAF](#u)* • *Track: CVE-2023-20938*

**binder_proc** — Kernel structure representing a process that has opened the Binder device; holds lists of threads, nodes, and references. *See also: [binder_thread](#b), [binder_node](#b), [BC_FREE_BUFFER](#b)* • *Track: CVE-2023-20938*

**binder_thread** — Kernel structure representing a single thread performing Binder transactions; contains stack-like todo list for incoming work. *See also: [binder_proc](#b), [BR_TRANSACTION](#b)* • *Track: CVE-2023-20938*

**Blink** — Chromium's rendering engine; handles layout, paint, and DOM; sandboxed in the renderer process. *See also: [V8](#v), [Mojo](#m), [renderer sandbox](#r)* • *Track: Chromium*

**BOF** — Buffer Overflow; classic vulnerability where data written past the end of a buffer overwrites adjacent memory, enabling code execution. *See also: [stack buffer overflow](#s), [heap overflow](#h)* • *Track: CTF & Exploit Dev*

**bootstrap server** — Mach IPC bootstrap server that registers and distributes service port names at system startup, parent of launchd. *See also: [Mach port](#m), [Mach IPC](#m), [launchd](#l)* • *Track: macOS/XNU*

**BR_TRANSACTION** — Binder driver reply indicating an incoming transaction to the target process; enqueued on the binder_proc's todo list. *See also: [BC_FREE_BUFFER](#b), [binder_thread](#b)* • *Track: CVE-2023-20938*

**broker** — Chromium's privileged process that handles sandbox escape requests (e.g., file access) on behalf of sandboxed renderers. *See also: [renderer sandbox](#r), [Mojo IPC](#m)* • *Track: Chromium*

**bug bounty** — Programs run by vendors (Google, Apple, Microsoft, etc.) that pay researchers for responsibly disclosed vulnerabilities. *See also: [responsible disclosure](#r), [CVE](#c)* • *Track: Zero-Day Research*

---

## C

**Candiru** — Israeli cyber-intelligence firm creating mercenary spyware; linked to zero-click mobile exploits sold to governments. *See also: [NSO Group](#n), [Intellexa](#i), [exploit-as-a-service](#e)* • *Track: Zero-Day Research*

**CET** — Control-flow Enforcement Technology; Intel's hardware feature combining Shadow Stack and IBT to harden against ROP/COP. *See also: [Shadow Stack](#s), [IBT](#i), [CFG](#c)* • *Track: Mitigation & Defense*

**CFI** — Control Flow Integrity; enforcement that indirect branches can only target valid call targets; blocks ROP/JOP style attacks. *See also: [kCFI](#k), [kCFI](#k), [CFG](#c), [BTI](#b)* • *Track: Mitigation & Defense*

**cfg** — 1) Control Flow Guard; Windows CFI implementation using a bitmap of valid indirect-branch targets. 2) Control Flow Graph in compiler analysis. *See also: [CFI](#c), [ACG](#a), [XFG](#x)* • *Track: OSEE/EXP-401*

**chain** — A sequence of exploited vulnerabilities or gadgets that, when linked together, achieves a full privilege escalation or code execution. *See also: [ROP chain](#r), [primitive](#p), [gadget](#g)* • *Track: Exploitation*

**Chaft** — APT group linked to Iranian state interests; active in zero-day deployment against Middle Eastern and Central Asian targets. *See also: [APT28](#a), [APT29](#a)* • *Track: Zero-Day Research*

**Chrome IPC** — Legacy Chromium IPC (now deprecated except for some legacy message types); replaced by Mojo for most inter-process communication. *See also: [Mojo IPC](#m), [Mojo](#m)* • *Track: Chromium*

**CIG** — Code Integrity Guard; Windows mitigation that only allows DLLs signed by specific publishers to be loaded, blocking DLL injection. *See also: [ACG](#a), [CFG](#c)* • *Track: OSEE/EXP-401*

**cgroups** — Linux Control Groups; kernel feature limiting, accounting for, and isolating resource usage (CPU, memory, I/O) of process groups. *See also: [namespaces](#n), [seccomp](#s)* • *Track: Linux Kernel Security*

**code signing** — Cryptographic signature of a binary that verifies its integrity and provenance; enforced at runtime by AMFI/SIP on macOS. *See also: [entitlements](#e), [AMFI](#a), [SIP](#s)* • *Track: macOS/XNU*

**codesign** — macOS command-line utility for signing and verifying code signatures on Mach-O binaries, frameworks, and bundles. *See also: [codesign_allocate](#c), [code signing](#c)* • *Track: macOS/XNU*

**codesign_allocate** — macOS utility that prepares Mach-O binaries for code signing by allocating space for signature data in __LINKEDIT. *See also: [codesign](#c), [Mach-O](#m)* • *Track: macOS/XNU*

**commit_creds** — Linux kernel function that installs a new cred struct on the current task; a common post-exploitation target for privilege escalation. *See also: [prepare_kernel_cred](#p), [cred](#c), [task_struct](#t)* • *Track: Linux Kernel Security*

**completion** — Linux kernel synchronization primitive; a task blocks on wait_for_completion() and is woken by complete(), simpler than semaphore for one-shot events. *See also: [wait queue](#w), [mutex](#m)* • *Track: Linux Kernel Security*

**ContentProvider** — Android app component that encapsulates data storage and exposes a standard interface for cross-process data sharing via Binder. *See also: [Intent](#i), [Binder](#b)* • *Track: Android*

**cop** — Call-Oriented Programming; exploitation technique chaining sequences of call instructions ending in a controlled jmp, similar to ROP but using call gadgets. *See also: [ROP](#r), [JOP](#j), [CFI](#c)* • *Track: Exploitation*

**core_pattern** — Linux kernel sysctl defining how core dumps are handled; overwriting it to `/tmp/pwn` with appropriate privileges enables post-exploitation command execution. *See also: [modprobe_path](#m), [commit_creds](#c)* • *Track: Linux Kernel Security*

**corpus** — A curated set of seed inputs for a fuzzer; high-quality corpora accelerate coverage discovery and crash finding. *See also: [seed](#s), [fuzz target](#f), [coverage](#c)* • *Track: Fuzzing*

**CR0** — x86 control register 0; contains flags including WP (write protect) bit and PE (protection enable) bit. *See also: [CR4](#c), [WP bit](#w), [MSR](#m)* • *Track: CPU Protection Rings*

**CR2** — x86 control register 2; holds the linear address that caused the last page fault, used by the page fault handler. *See also: [CR3](#c), [page fault](#p)* • *Track: CPU Protection Rings*

**CR3** — x86 control register 3; holds the physical address of the current page directory (PGD), the root of the page table hierarchy. *See also: [pgd](#p), [CR0](#c), [KPTI](#k)* • *Track: CPU Protection Rings*

**CR4** — x86 control register 4; contains SMEP, SMAP, and SMEP enable bits; commonly targeted for clearing in kernel exploits. *See also: [SMEP](#s), [SMAP](#s), [native_write_cr4](#n)* • *Track: CPU Protection Rings*

**crash** — A test case from fuzzing that triggers an abnormal program termination; crashes are triaged for exploitability. *See also: [sanitizer](#s), [ASan](#a), [corpus](#c)* • *Track: Fuzzing*

**cred** — Linux kernel structure holding process credential information (UID, GID, capabilities); the target of commit_creds() for privilege escalation. *See also: [task_struct](#t), [commit_creds](#c), [prepare_kernel_cred](#p)* • *Track: Linux Kernel Security*

**CWE** — Common Weakness Enumeration; a community-developed taxonomy of software weakness types maintained by MITRE. *See also: [CVE](#c), [CVSS](#c)* • *Track: Zero-Day Research*

**CVSS** — Common Vulnerability Scoring System; standardized framework for rating vulnerability severity (0.0–10.0). *See also: [CVE](#c), [EPSS](#e), [CWE](#c)* • *Track: Zero-Day Research*

---

## D

**DAC** — Discretionary Access Control; access control model where object owners define permissions (standard Unix rwx). *See also: [MAC](#m), [capability](#c), [SELinux](#s)* • *Track: Linux Kernel Security*

**dalvik** — Android's legacy register-based virtual machine and bytecode format; replaced by ART in Android 5.0+. *See also: [ART](#a), [dex2oat](#d)* • *Track: Android*

**DEP** — Data Execution Prevention; Windows mitigation marking memory pages as non-executable (NX bit) to prevent shellcode execution. *See also: [NX](#n), [W^X](#w), [ASLR](#a)* • *Track: Mitigation & Defense*

**dex2oat** — Android tool that compiles DEX bytecode to native OAT format for execution on ART; runs at install time or OTA. *See also: [ART](#a), [dalvik](#d)* • *Track: Android*

**DKF** — Darwin Kernel Framework; XNU's internal framework for structured kernel object management; not widely documented. *See also: [XNU](#x), [KEXT](#k)* • *Track: macOS/XNU'

**DKL** — Dynamic Kernel Loader; Android mechanism for post-boot kernel module loading on GKI kernels without rebuilding the boot image. *See also: [GKI](#g), [APEX](#a)* • *Track: Android*

**DMAR** — DMA Remapping; Intel VT-d feature that translates device DMA addresses, preventing rogue DMA from privileged devices. *See also: [IOMMU](#i), [VT-d](#v)* • *Track: CPU Protection Rings'

**dm-verity** — Android verified boot mechanism that checks a cryptographic hash tree of each block read from a read-only partition. *See also: [verified boot](#v), [APEX](#a)* • *Track: Android*

**double-fetch** — A race-condition class where kernel code reads user data twice; if the user modifies it between reads, a TOCTOU bug is triggered. *See also: [TOCTOU](#t), [race condition](#r)* • *Track: Linux Kernel Security*

**double-free** — Memory corruption bug where the same allocation is freed twice, allowing allocator metadata manipulation and code execution. *See also: [UAF](#u), [heap overflow](#h), [tcache poisoning](#t)* • *Track: Exploitation*

**dyld** — Dynamic linker for macOS/iOS; loads shared libraries and resolves symbols at process startup; target of DYLD_INSERT_LIBRARIES attacks. *See also: [DYLD_INSERT_LIBRARIES](#d), [Mach-O](#m)* • *Track: macOS/XNU*

**DYLD_INSERT_LIBRARIES** — Environment variable that forces dyld to load additional libraries, similar to LD_PRELOAD; blocked on hardened runtimes. *See also: [dyld](#d), [Hardened Runtime](#h), [SIP](#s)* • *Track: macOS/XNU*

---

## E

**edge coverage** — Fuzzing metric counting the number of basic-block edges (branches) executed; the primary feedback signal for coverage-guided fuzzers. *See also: [coverage](#c), [path coverage](#p), [AFL++](#a)* • *Track: Fuzzing*

**egg hunter** — A small stub of shellcode that searches process memory for a larger payload marked by a unique "egg" (tag bytes). *See also: [staged payload](#s), [stager](#s), [shellcode](#s)* • *Track: Exploitation*

**EM64T** — Intel's original branding for the x86-64 instruction set extension; now universally called Intel 64. *Track: CPU Protection Rings*

**entitlements** — macOS/iOS key-value pairs in a code signature granting specific privileges (e.g., com.apple.security.cs.allow-unsigned-executable-memory). *See also: [code signing](#c), [AMFI](#a), [SIP](#s)* • *Track: macOS/XNU'

**EPT** — Extended Page Tables; Intel VT-x hardware feature enabling nested (second-level) address translation for virtual machines. *See also: [NPT](#n), [SLAT](#s), [VMCS](#v)* • *Track: CPU Protection Rings*

**EPSS** — Exploit Prediction Scoring System; data-driven estimate of the probability that a given CVE will be exploited in the wild within 30 days. *See also: [CVSS](#c), [CVE](#c)* • *Track: Zero-Day Research*

**Equation Group** — Highly sophisticated APT linked to the NSA; source code disclosed in the Shadow Brokers leak. *See also: [Shadow Brokers](#s), [APT28](#a)* • *Track: Zero-Day Research*

**exploit-as-a-service** — Business model where exploit vendors sell zero-click or one-click exploits as hosted services rather than raw code. *See also: [NSO Group](#n), [broker](#b), [0-day](#zero-day)* • *Track: Zero-Day Research*

**exploit kit** — A toolkit packaging one or more exploits, typically delivered via drive-by download, that selects an appropriate exploit based on victim browser/plugin. *See also: [0-day](#zero-day), [N-day](#n), [broker](#b)* • *Track: Zero-Day Research*

---

## F

**FairPlay** — Apple's DRM system for App Store/iTunes content; its obfuscation has been reverse-engineered for pirated content distribution. *See also: [code signing](#c), [AppleMobileFileIntegrity](#a)* • *Track: macOS/XNU'

**fairfuzz** — AFL++ scheduling mode that gives more energy to rare branches, improving discovery of deep paths. *See also: [AFL++](#a), [coverage-guided](#c)* • *Track: Fuzzing*

**fastbin attack** — Glibc heap exploitation technique leveraging singly-linked fastbin freelist to write a forged chunk at an arbitrary address. *See also: [tcache poisoning](#t), [heap feng shui](#h), [house of spirit](#h)* • *Track: CTF & Exploit Dev'

**fastboot** — Android bootloader protocol for flashing partitions and booting images; used in device provisioning and recovery. *See also: [adb](#a), [verified boot](#v)* • *Track: Android'

**FML** — Firmware Management Lock; macOS T2/M-series mechanism preventing unauthorized firmware updates, part of the secure boot chain. *See also: [SSV](#s), [KTRR](#k)* • *Track: macOS/XNU'

**format string** — Vulnerability class where user-controlled data is passed directly to printf-style functions, enabling memory reads, writes, and code execution. *See also: [arb read](#a), [arb write](#a), [GOT overwrite](#g)* • *Track: Exploitation'

**fork server** — AFL++ mode that forks the target once at init, then reuses the forked process per test case, reducing exec overhead. *See also: [persistent mode](#p), [AFL++](#a)* • *Track: Fuzzing'

**framework** — The Android framework layer (packages, services, managers) running in SystemServer; provides Java APIs above the HAL and Binder. *See also: [SystemServer](#s), [Binder](#b), [AIDL](#a)* • *Track: Android'

**Full RELRO** — Relocation Read-Only with BIND_NOW; resolves all GOT entries at load time and marks GOT as read-only, preventing GOT overwrites. *See also: [Partial RELRO](#p), [RELRO](#r), [GOT overwrite](#g)* • *Track: Mitigation & Defense'

**fuzz target** — A function or program entry point specifically written to be called by a fuzzer with arbitrary input data. *See also: [harness](#h), [corpus](#c), [AFL++](#a)* • *Track: Fuzzing'

---

## G

**Gadget** — A short sequence of instructions ending in a return (for ROP), jump (for JOP), or call (for COP), found in existing code. *See also: [ROP chain](#r), [JOP](#j), [ropper](#r)* • *Track: Exploitation'

**Gatekeeper** — macOS security feature that blocks unsigned or unauthorized apps from launching by default; first introduced in Mountain Lion. *See also: [SIP](#s), [XProtect](#x), [Quarantine](#q)* • *Track: macOS/XNU'

**GDT** — Global Descriptor Table; x86 data structure in memory defining segment descriptors for the CPU; base for segmentation in protected mode. *See also: [LDT](#l), [IDT](#i), [TSS](#t)* • *Track: CPU Protection Rings'

**Ghidra** — NSA's free reverse-engineering framework; supports decompilation, scripting, and collaborative analysis. *See also: [IDA](#i), [radare2](#r), [pwndbg](#p)* • *Track: CTF & Exploit Dev'

**GKI** — Generic Kernel Image; Android's standardized kernel binary for a given architecture, enabling module-based vendor customizations via DKL. *See also: [DKL](#d), [APEX](#a), [Treble](#t)* • *Track: Android'

**GOT overwrite** — Hijacking the Global Offset Table entry for a libc function to redirect execution to attacker-controlled code. *See also: [PLT hijack](#p), [RELRO](#r), [Full RELRO](#f)* • *Track: CTF & Exploit Dev'

**GPU sandbox** — Chromium's sandbox for the GPU process; limits access to graphics hardware and driver interfaces. *See also: [renderer sandbox](#r), [broker](#b), [Mojo](#m)* • *Track: Chromium'

**grammar-based** — Fuzzing strategy using grammar rules (e.g., RFC ABNF) to generate syntactically valid inputs for structured protocols. *See also: [structure-aware](#s), [coverage-guided](#c)* • *Track: Fuzzing'

**grsecurity** — Linux kernel hardening patch set providing RBAC, PaX memory protections, and other security features; licensing moved to proprietary in 2017. *See also: [PaX](#p), [RAP](#r), [RANDEXIT](#r)* • *Track: Linux Kernel Security'

**GDB** — GNU Debugger; standard debugger for Unix-like systems with extensive extension support for exploit development (see pwndbg, GEF). *See also: [pwndbg](#p), [radare2](#r), [Ghidra](#g)* • *Track: CTF & Exploit Dev'

---

## H

**HAL** — Hardware Abstraction Layer; Android interface defining how the OS communicates with vendor hardware, standardized by Project Treble. *See also: [Treble](#t), [HIDL](#h), [AIDL](#a)* • *Track: Android'

**HAP** — Hardware Assisted Partitioning; a documented Intel ME feature intended for partitioning ME resources; also referenced in ME disabling research. *See also: [Intel ME](#i), [AMT](#a)* • *Track: CPU Protection Rings'

**Hardened Runtime** — macOS security feature restricting dynamic code generation, DYLD_INSERT_LIBRARIES, and invalid library loading for signed apps. *See also: [SIP](#s), [AMFI](#a), [DYLD_INSERT_LIBRARIES](#d)* • *Track: macOS/XNU'

**harness** — Wrapper program that connects a fuzz target to a fuzzer's input interface, handling initialization and test case delivery. *See also: [fuzz target](#f), [corpus](#c), [persistent mode](#p)* • *Track: Fuzzing'

**heap feng shui** — Technique for shaping the heap into a predictable state by allocating and freeing objects to create controllable adjacency. *See also: [UAF](#u), [tcache poisoning](#t), [fastbin attack](#f)* • *Track: CTF & Exploit Dev'

**heap overflow** — Writing past the boundaries of a heap-allocated buffer; can corrupt heap metadata or adjacent objects to achieve code execution. *See also: [UAF](#u), [double-free](#d), [pool corruption](#p)* • *Track: Exploitation'

**heap scan** — Chromium's UAF-prevention technique that scans the heap looking for dangling pointers before freeing objects, used in MiraclePtr. *See also: [MiraclePtr](#m), [RawPtr](#r), [UAF prevention](#u)* • *Track: Chromium'

**honggfuzz** — Feedback-guided fuzzer by Google supporting hardware-based edge coverage (Intel PT) and software-based coverage. *See also: [AFL++](#a), [libFuzzer](#l), [syzkaller](#s)* • *Track: Fuzzing'

**House of Force** — Glibc heap exploitation technique corrupting the top chunk size to service a malloc at an arbitrary address. *See also: [house of orange](#h), [house of spirit](#h), [tcache poisoning](#t)* • *Track: CTF & Exploit Dev'

**House of Orange** — Glibc heap exploitation technique leveraging the FILE structure and vtable to gain code execution without freeing chunks. *See also: [house of force](#h), [house of spirit](#h)* • *Track: CTF & Exploit Dev'

**House of Spirit** — Glibc heap exploitation technique where an attacker writes a forged chunk into memory and frees it to enter a freelist. *See also: [fastbin attack](#f), [house of force](#h)* • *Track: CTF & Exploit Dev'

---

## I

**IBT** — Indirect Branch Tracking; CET sub-feature that verifies indirect branch targets land on ENDBR64/ENDBR32 instructions, breaking JOP/ROP. *See also: [CET](#c), [Shadow Stack](#s), [BTI](#b)* • *Track: Mitigation & Defense'

**IDA** — Interactive Disassembler; industry-standard commercial reverse-engineering tool by Hex-Rays with decompiler support. *See also: [Ghidra](#g), [radare2](#r)* • *Track: CTF & Exploit Dev'

**IDT** — Interrupt Descriptor Table; x86 data structure mapping interrupt/exception vectors to handler addresses; target of TSS-based attacks. *See also: [GDT](#g), [TSS](#t), [PIC](#p)* • *Track: CPU Protection Rings'

**initialization-to-zero** — Vulnerability pattern where uninitialized stack or heap memory is used without zeroing, leaking pointers or enabling information disclosure. *See also: [KASAN](#k), [MSan](#m), [UBSan](#u)* • *Track: Exploitation'

**integer overflow** — Arithmetic overflow when the result of an integer operation exceeds the type's maximum value, leading to wrapping and logic bugs. *See also: [integer truncation](#i), [sign extension](#s), [heap overflow](#h)* • *Track: Exploitation'

**integer truncation** — Vulnerability where a wider integer type is implicitly narrowed, discarding upper bits; commonly occurs in kernel ioctls. *See also: [integer overflow](#i), [sign extension](#s), [OOB read/write](#o)* • *Track: Exploitation'

**Intent** — Android messaging object describing an action to perform; delivered via Binder IPC and central to Android's component interaction model. *See also: [Binder](#b), [ContentProvider](#c)* • *Track: Android'

**Intel ME** — Intel Management Engine; an autonomous Minix-based subprocessor inside Intel chipsets with Ring -3 privilege; widely studied for firmware exploitation. *See also: [AMD PSP](#a), [AMT](#a), [HAP](#h), [SMM](#s)* • *Track: CPU Protection Rings'

**Intellexa** — Spyware vendor (formerly associated with NSO Group) behind the Predator surveillance tool. *See also: [NSO Group](#n), [Candiru](#c), [exploit-as-a-service](#e)* • *Track: Zero-Day Research*

**IOKit** — XNU kernel framework for device driver development; provides C++-based object model, registry, and matched driver loading. *See also: [IOKitUserClient](#i), [KEXT](#k), [XNU](#x)* • *Track: macOS/XNU'

**IOKitUserClient** — User-space interface to IOKit services; creates a Mach port connection enabling in-kernel driver interaction; frequent attack surface. *See also: [IOKit](#i), [Mach port](#m), [Mach IPC](#m)* • *Track: macOS/XNU'

**IOMMU** — Input-Output Memory Management Unit; hardware unit translating device DMA addresses and isolating devices from system memory. *See also: [VT-d](#v), [DMAR](#d), [AMD-V](#a)* • *Track: CPU Protection Rings'

**ipc_entry** — XNU Mach IPC structure mapping a Mach port name (integer) to its corresponding ipc_port in a process's port namespace. *See also: [ipc_port](#i), [Mach port](#m), [Mach IPC](#m)* • *Track: macOS/XNU'

**ipc_port** — XNU kernel representation of a Mach port; holds receiver, sender rights, and message queue; the fundamental IPC object. *See also: [ipc_entry](#i), [Mach port](#m), [task_t](#t)* • *Track: macOS/XNU'

---

## J

**JDWP** — Java Debug Wire Protocol; protocol used by Android's debuggable processes; can be exploited to inject code if left exposed. *See also: [adb](#a), [ART](#a)* • *Track: Android'

**JOP** — Jump-Oriented Programming; exploitation technique chaining indirect jump gadgets instead of return gadgets, bypassing some ROP-specific defenses. *See also: [ROP](#r), [COP](#c), [CFI](#c)* • *Track: Exploitation'

---

## K

**kalloc** — XNU's primary kernel memory allocator; provides sized allocations from zones; counterpart to Linux's kmalloc. *See also: [kalloc_type](#k), [zone allocator](#z), [kmalloc](#k)* • *Track: macOS/XNU'

**kalloc_type** — XNU's typed kernel memory allocator introduced in macOS 13; kalloc_type allocations are segregated by type to limit UAF blast radius. *See also: [kalloc](#k), [zone allocator](#z), [UAF](#u)* • *Track: macOS/XNU'

**KASAN** — Kernel Address Sanitizer; Linux kernel memory error detector that catches out-of-bounds and use-after-free bugs at runtime. *See also: [ASan](#a), [UBSan](#u), [KASLR](#k)* • *Track: Linux Kernel Security'

**kCFI** — Kernel Control Flow Integrity; Linux kernel hardening (merged 2023) that verifies indirect branch targets against a per-function hash. *See also: [CFI](#c), [CFG](#c), [BTI](#b)* • *Track: Linux Kernel Security'

**KEXT** — Kernel Extension; macOS mechanism for loading third-party code into the XNU kernel; increasingly restricted by SIP and Apple. *See also: [IOKit](#i), [SIP](#s), [XNU](#x)* • *Track: macOS/XNU'

**__kmalloc** — Core Linux kernel slab allocation function called by kmalloc(); target for cross-cache UAF and heap overflow exploits. *See also: [kmalloc](#k), [slub](#s), [kfree](#k)* • *Track: Linux Kernel Security'

**kmalloc** — Linux kernel's primary generic memory allocator; allocates from slab caches (SLUB) and is a frequent target for heap shaping. *See also: [__kmalloc](#k), [kfree](#k), [kalloc](#k), [slub](#s)* • *Track: Linux Kernel Security'

**KPP** — Kernel Patch Protection; Apple's mechanism detecting unauthorized XNU kernel code modifications at runtime (aka KPP/rootless). *See also: [KTRR](#k), [PPL](#p), [SIP](#s)* • *Track: macOS/XNU'

**KPTI** — Kernel Page Table Isolation; Linux mitigation that unmapped kernel pages from user-space page tables to mitigate Meltdown-class attacks. *See also: [KASLR](#k), [CR3](#c), [Meltdown](#m)* • *Track: Linux Kernel Security'

**KTRR** — Kernel Text Read-Only Region; Apple hardware-enforced read-only protection for XNU kernel text using memory controller registers. *See also: [KPP](#k), [PPL](#p), [SIP](#s)* • *Track: macOS/XNU'

---

## L

**launchd** — macOS init system and service manager; the first userspace process launched by the kernel; handles Mach bootstrap registration. *See also: [bootstrap server](#b), [Mach IPC](#m)* • *Track: macOS/XNU'

**Lazarus** — North Korean state-sponsored APT group infamous for cryptocurrency heists, supply-chain attacks, and zero-day deployment. *See also: [APT](#a), [APT28](#a)* • *Track: Zero-Day Research*

**libFuzzer** — In-process, coverage-guided fuzzer engine integrated into LLVM/Clang; commonly used with ASan/MSan for vulnerability discovery. *See also: [AFL++](#a), [fuzz target](#f), [sanitizer](#s)* • *Track: Fuzzing'

**LOCKDOWN** — Linux kernel security lockdown mode that restricts userspace from modifying running kernel code/data even with root, preventing some exploit techniques. *See also: [KASLR](#k), [SMEP](#s), [KPTI](#k)* • *Track: Linux Kernel Security'

**LSan** — LeakSanitizer; detects memory leaks at program exit, commonly paired with ASan in fuzzing workflows. *See also: [ASan](#a), [MSan](#m), [sanitizer](#s)* • *Track: Fuzzing'

**LDT** — Local Descriptor Table; per-task x86 segment descriptor table; minimal role in long mode but present in 64-bit for compatibility. *See also: [GDT](#g), [TSS](#t), [IDT](#i)* • *Track: CPU Protection Rings'

**ltrace** — Linux diagnostic tool tracing dynamic library calls (malloc, free, open, etc.) made by a process; useful for understanding runtime behavior. *See also: [strace](#s), [GDB](#g)* • *Track: CTF & Exploit Dev'

---

## M

**MAC** — Mandatory Access Control; security model where the system (not users) enforces access policies; implemented by SELinux, AppArmor, etc. *See also: [DAC](#d), [SELinux](#s), [AppArmor](#a)* • *Track: Linux Kernel Security'

**Mach** — The microkernel core of XNU; provides tasks, threads, ports, IPC, and scheduling primitives underlying macOS userspace and IOKit. *See also: [XNU](#x), [Mach port](#m), [Mach IPC](#m), [Mach-O](#m)* • *Track: macOS/XNU'

**Mach IPC** — XNU's inter-process communication mechanism built on Mach ports, enabling synchronous/asynchronous message passing between tasks. *See also: [Mach port](#m), [bootstrap server](#b), [task_t](#t)* • *Track: macOS/XNU'

**Mach port** — XNU's fundamental IPC endpoint; each port has receive/send rights and carries messages between kernel and userspace tasks. *See also: [Mach IPC](#m), [ipc_port](#i), [ipc_entry](#i)* • *Track: macOS/XNU'

**Mach-O** — Mach Object file format; the executable and library format for macOS/iOS, defining segments, sections, and load commands for dyld. *See also: [Mach](#m), [dyld](#d), [codesign](#c)* • *Track: macOS/XNU'

**memory tagging** — Hardware-based memory safety technique that assigns tags to memory regions and pointers; dereferences of mistagged pointers trap. *See also: [MTE](#m), [UAF](#u)* • *Track: Mitigation & Defense'

**MiraclePtr** — Chromium's smart pointer system backing RawPtr with backup pointers for UAF detection and mitigation. *See also: [RawPtr](#r), [UAF prevention](#u), [heap scan](#h)* • *Track: Chromium'

**modprobe_path** — Linux kernel global string Path to modprobe executable; overwritten by attackers to achieve root command execution after triggering an unknown binary format. *See also: [core_pattern](#c), [commit_creds](#c)* • *Track: Linux Kernel Security'

**Mojo** — Chromium's IPC system replacing Chrome IPC; provides typed interface definitions with bindings for C++, Java, and JavaScript. *See also: [Mojo IPC](#m), [V8](#v), [Blink](#b)* • *Track: Chromium'

**Mojo IPC** — The wire protocol layer of Mojo; defines message serialization, endpoint routing, and security boundaries between Chromium processes. *See also: [Mojo](#m), [Chrome IPC](#c), [RenderProcessHost](#r)* • *Track: Chromium'

**MSan** — MemorySanitizer; Clang/LLVM instrumentation detecting reads of uninitialized memory; essential for finding information-leak bugs. *See also: [ASan](#a), [TSan](#t), [UBSan](#u), [LSan](#l)* • *Track: Fuzzing'

**MSR** — Model-Specific Register; x86 registers for CPU-specific configuration (e.g., SYSENTER CS, LSTAR, SPEC_CTRL); accessed via RDMSR/WRMSR. *See also: [CR0](#c), [CR4](#c), [CR3](#c)* • *Track: CPU Protection Rings'

**msg_msg** — Linux kernel structure for System V message queue messages; commonly used as a cross-cache UAF target for heap exploitation. *See also: [kmalloc](#k), [pipe_buffer](#p), [slub](#s)* • *Track: Linux Kernel Security'

**mutex** — Mutual exclusion lock; Linux kernel sleeping lock allowing only one holder; suitable for long critical sections. *See also: [spinlock](#s), [rw_semaphore](#r)* • *Track: Linux Kernel Security'

**mutation-based** — Fuzzing strategy that starts with valid seed inputs and applies transformations (bit flips, byte deletes, crossover) to generate new inputs. *See also: [coverage-guided](#c), [grammar-based](#g), [corpus](#c)* • *Track: Fuzzing'

**MRT** — Malware Removal Tool; Apple's background tool that scans for and removes known macOS malware; runs silently after OS updates. *See also: [XProtect](#x), [Gatekeeper](#g)* • *Track: macOS/XNU'

**MTE** — Memory Tagging Extension; ARMv8.5 feature enabling hardware memory tagging; tags on pointers and allocations must match for access. *See also: [memory tagging](#m), [PAC](#p), [UAF](#u)* • *Track: Mitigation & Defense'

---

## N

**NaCl** — Native Client; deprecated Chromium sandboxing technology that ran compiled C/C++ code in the browser with restricted syscalls; succeeded by WebAssembly. *See also: [PPAPI](#p), [renderer sandbox](#r)* • *Track: Chromium'

**namespaces** — Linux kernel feature isolating process views of global resources (PID, net, mount, user, etc.); foundation for containers. *See also: [cgroups](#c), [seccomp](#s), [capability](#c)* • *Track: Linux Kernel Security'

**native_write_cr4** — Linux kernel function that writes to x86 CR4 register; attackers use it to disable SMEP/SMAP bits during kernel exploitation. *See also: [CR4](#c), [SMEP](#s), [SMAP](#s)* • *Track: Linux Kernel Security'

**1-day** — A vulnerability that has been patched but for which an exploit is still valuable because not all targets are updated. *See also: [0-day](#zero-day), [N-day](#n)* • *Track: Zero-Day Research*

**N-day** — A vulnerability with a known patch that is actively exploited in the wild; distinct from 0-day (unpatched) and 1-day (recently patched). *See also: [0-day](#zero-day), [1-day](#n), [exploit kit](#e)* • *Track: Zero-Day Research*

**NDR** — Network Data Representation; used in some exploit documentation as a data serialization format; contextual in DCE/RPC. *Track: OSEE/EXP-401*

**NDK** — Native Development Kit; Android toolkit for writing performance-critical code in C/C++ that runs directly on the device CPU. *See also: [AOSP](#a), [JDWP](#j)* • *Track: Android'

**NPT** — Nested Page Tables; AMD's equivalent of Intel EPT for second-level address translation in virtualization. *See also: [EPT](#e), [SLAT](#s), [VMCB](#v)* • *Track: CPU Protection Rings'

**NSO Group** — Israeli cyber-intelligence firm known for Pegasus spyware; most prominent exploit-as-a-service vendor targeting mobile devices. *See also: [Candiru](#c), [Intellexa](#i), [exploit-as-a-service](#e)* • *Track: Zero-Day Research*

**NX** — No-eXecute; CPU feature (XD bit on Intel) marking memory pages as non-executable; the hardware basis of DEP. *See also: [DEP](#d), [W^X](#w), [XN](#x)* • *Track: Mitigation & Defense'

**NVD** — National Vulnerability Database; NIST's repository of CVE records with analysis, scoring, and vendor advisories. *See also: [CVE](#c), [CVSS](#c)* • *Track: Zero-Day Research*

---

## O

**OOB read** — Out-of-bounds read; a memory safety bug reading past an allocation, enabling information disclosure (leak of pointers, canaries, heap data). *See also: [OOB write](#o), [arb read](#a), [ASLR](#a)* • *Track: Exploitation'

**OOB write** — Out-of-bounds write; a memory safety bug writing past an allocation, enabling corruption of adjacent data structures and code execution. *See also: [OOB read](#o), [arb write](#a), [heap overflow](#h)* • *Track: Exploitation'

**Oilpan** — Blink's garbage-collected heap for C++ objects; manages object lifetimes across the renderer process using precise GC. *See also: [PartitionAlloc](#p), [Blink](#b)* • *Track: Chromium'

**OOPIF** — Out-of-Process Iframe; Chromium architecture placing cross-site iframes in separate renderer processes, key to site isolation. *See also: [Site Isolation](#s), [RenderFrameHost](#r)* • *Track: Chromium'

**OTAs** — Over-The-Air updates; Android's mechanism for delivering full or incremental system updates wirelessly. *See also: [dm-verity](#d), [verified boot](#v)* • *Track: Android'

---

## P

**PAC** — Pointer Authentication Codes; ARMv8.3 feature that cryptographically signs pointers to detect corruption of return addresses and vtable pointers. *See also: [BTI](#b), [MTE](#m), [CFI](#c)* • *Track: Mitigation & Defense'

**page** — The basic unit of memory management (typically 4 KiB); kernel page tables map virtual pages to physical frames. *See also: [pgd](#p), [pte](#p), [CR3](#c)* • *Track: Linux Kernel Security'

**PaX** — Groundbreaking Linux kernel hardening patch set introducing non-executable pages, ASLR, and other protections; foundation for grsecurity. *See also: [grsecurity](#g), [RAP](#r), [VMA mirroring](#v), [RANDEXIT](#r)* • *Track: Linux Kernel Security'

**Parcel** — Android's serialization container for data sent over Binder IPC; supports typed reads/writes and is used for all Binder transactions. *See also: [Binder](#b), [Binder IPC](#b)* • *Track: Android'

**Partial RELRO** — Relocation Read-Only with partial protection; marks the GOT header as read-only but leaves GOT entries writable. *See also: [Full RELRO](#f), [RELRO](#r)* • *Track: Mitigation & Defense'

**PartitionAlloc** — Chromium's memory allocator providing partitioned heaps with type isolation; reduces the blast radius of UAF and OOB bugs. *See also: [Oilpan](#o), [UAF prevention](#u), [MiraclePtr](#m)* • *Track: Chromium'

**path coverage** — Fuzzing metric counting unique execution paths (sequences of basic blocks); more granular than edge or block coverage. *See also: [edge coverage](#e), [coverage](#c)* • *Track: Fuzzing'

**persistent mode** — AFL++ and libFuzzer mode where the fuzz target is re-entered from a loop inside the process, avoiding fork+exec overhead per test case. *See also: [fork server](#f), [fuzz target](#f)* • *Track: Fuzzing'

**pgd** — Page Global Directory; the top-level page table entry in Linux's four-level paging scheme; pointed to by CR3. *See also: [pud](#p), [pmd](#p), [pte](#p), [CR3](#c)* • *Track: Linux Kernel Security'

**PIC** — Position-Independent Code; code compiled to execute correctly regardless of its load address; prerequisite for PIE and ASLR effectiveness. *See also: [PIE](#p), [ASLR](#a), [ROP](#r)* • *Track: Exploitation'

**PIE** — Position-Independent Executable; a binary compiled as PIC with a dynamic base, enabling ASLR to randomize its load address. *See also: [ASLR](#a), [PIC](#p), [KASLR](#k)* • *Track: Mitigation & Defense'

**pipe_buffer** — Linux kernel structure representing a single page in a pipe; exploited via UAF in DirtyPipe (CVE-2022-0847) for arbitrary file writes. *See also: [msg_msg](#m), [seq_operations](#s), [kmalloc](#k)* • *Track: Linux Kernel Security'

**pivot** — Stack pivot; exploitation technique that changes the stack pointer (RSP) to an attacker-controlled address, enabling ROP chain execution. *See also: [stack pivot](#s), [ROP chain](#r), [gadget](#g)* • *Track: Exploitation'

**PLT hijack** — Redirecting execution through the Procedure Linkage Table by overwriting GOT entries or corrupting PLT stub pointers. *See also: [GOT overwrite](#g), [RET2PLT](#r), [Full RELRO](#f)* • *Track: CTF & Exploit Dev'

**pmd** — Page Middle Directory; second-level page table entry in Linux's four-level paging scheme; points to PTE tables. *See also: [pgd](#p), [pud](#p), [pte](#p)* • *Track: Linux Kernel Security'

**pool corruption** — Windows kernel pool overflow or misuse leading to adjacent pool header/data overwrite; Windows equivalent of Linux slab corruption. *See also: [heap overflow](#h), [UAF](#u)* • *Track: OSEE/EXP-401'

**PPAPI** — Pepper Plugin API; deprecated Chromium interface for browser plugins (replaced by NaCl then WebAssembly); historical attack surface. *See also: [NaCl](#n), [renderer sandbox](#r)* • *Track: Chromium'

**prepare_kernel_cred** — Linux kernel function that creates a new cred struct with full root privileges; commonly called after obtaining arbitrary execution. *See also: [commit_creds](#c), [cred](#c), [task_struct](#t)* • *Track: Linux Kernel Security'

**primitive** — A capability gained through exploitation (e.g., arb read primitive, arb write primitive, free primitive); the building blocks of a chain. *See also: [arb read](#a), [arb write](#a), [chain](#c)* • *Track: Exploitation'

**procfs** — Linux process filesystem (/proc); exposes kernel and per-process information as virtual files; a frequent source of information leaks. *See also: [sysfs](#s), [tracefs](#t)* • *Track: Android*

**PPL** — Page Protection Layer; Apple's hardware-backed XNU protection that prevents even kernel-level code from modifying specific memory regions (e.g., page tables). *See also: [KTRR](#k), [KPP](#k), [SIP](#s)* • *Track: macOS/XNU'

**pwntools** — Python exploit development library providing ELF parsing, ROP chain building, shellcraft, and remote I/O for CTFs and security research. *See also: [pwndbg](#p), [ROPgadget](#r), [one_gadget](#o)* • *Track: CTF & Exploit Dev'

**pwndbg** — GDB plugin adding exploit-development helpers (heap visualization, context display, ROP search); built on top of GDB's Python API. *See also: [GDB](#g), [pwntools](#p), [radare2](#r)* • *Track: CTF & Exploit Dev'

**pud** — Page Upper Directory; third-level page table entry in Linux's five-level paging scheme (with P4D layer); points to PMD tables. *See also: [pgd](#p), [pmd](#p), [pte](#p)* • *Track: Linux Kernel Security'

---

## Q

No entries for Q.

---

## R

**race condition** — A bug where the outcome depends on the interleaving of concurrent operations; exploited by winning a timing window to corrupt state. *See also: [TOCTOU](#t), [double-fetch](#d), [RCU](#r)* • *Track: Exploitation'

**radare2** — Free and open-source reverse-engineering framework with disassembly, analysis, patching, and scripting capabilities (renamed to rizin in the fork). *See also: [Ghidra](#g), [IDA](#i), [pwndbg](#p)* • *Track: CTF & Exploit Dev'

**RAP** — PaX RAP (RAP - Return Address Protection); grsecurity feature that verifies function return addresses against a hash, preventing ROP. *See also: [PaX](#p), [grsecurity](#g), [CFI](#c)* • *Track: Linux Kernel Security'

**RANDEXIT** — PaX feature that randomizes the addresses of kernel functions at each boot, increasing uncertainty for kernel exploitation. *See also: [PaX](#p), [grsecurity](#g), [KASLR](#k)* • *Track: Linux Kernel Security'

**RawPtr** — Chromium's smart pointer wrapper that integrates with MiraclePtr for backup-pointer-based UAF mitigation; replacement for raw C++ pointers. *See also: [MiraclePtr](#m), [UAF prevention](#u)* • *Track: Chromium'

**RCU** — Read-Copy-Update; Linux kernel synchronization mechanism allowing lock-free reads while updates create copies; critical in kernel concurrency design. *See also: [spinlock](#s), [mutex](#m), [race condition](#r)* • *Track: Linux Kernel Security'

**renderer sandbox** — Chromium's sandbox for the renderer process; limits syscalls, file access, and network via seccomp-BPF and namespaces. *See also: [GPU sandbox](#g), [broker](#b), [seccomp](#s)* • *Track: Chromium'

**RELRO** — Relocation Read-Only; ELF hardening that marks parts or all of the GOT as read-only after symbol resolution. *See also: [Full RELRO](#f), [Partial RELRO](#p), [GOT overwrite](#g)* • *Track: Mitigation & Defense'

**RenderFrameHost** — Chromium browser-side object managing a single frame's lifecycle, IPC (via Mojo), and navigation in the browser process. *See also: [RenderProcessHost](#r), [Mojo](#m), [Site Isolation](#s)* • *Track: Chromium'

**RenderProcessHost** — Chromium browser-side host managing a renderer process; each hosts multiple RenderFrameHosts and a single sandboxed process. *See also: [RenderFrameHost](#r), [renderer sandbox](#r)* • *Track: Chromium'

**responsible disclosure** — Practice of reporting vulnerabilities to the vendor and allowing a reasonable time for patching before public disclosure. *See also: [full disclosure](#f), [bug bounty](#b), [CVE](#c)* • *Track: Zero-Day Research*

**ret2csu** — Return-to-\_\_libc\_csu\_init; technique using the \_\_libc\_csu\_init gadget pair in x86-64 ELF binaries for ROP when few gadgets are available. *See also: [ret2libc](#r), [ROP chain](#r), [ret2plt](#r)* • *Track: Exploitation'

**ret2libc** — Return-to-libc; exploitation technique redirecting execution to libc functions (e.g., system()) instead of injecting shellcode, bypassing DEP/NX. *See also: [ROP](#r), [DEP](#d), [NX](#n), [ret2plt](#r)* • *Track: Exploitation'

**ret2plt** — Return-to-PLT; technique redirecting execution through the Procedure Linkage Table to call libc functions without knowing their address. *See also: [ret2libc](#r), [PLT hijack](#p), [GOT overwrite](#g)* • *Track: Exploitation'

**ret2win** — CTF challenge pattern where the goal is to redirect execution to a specific "win" function by overflowing a return address. *See also: [ROP chain](#r), [BOF](#b)* • *Track: CTF & Exploit Dev'

**Ring 0** — CPU protection ring for kernel/supervisor mode; the most privileged software execution level in x86; all kernel code runs here. *See also: [Ring 3](#r), [Ring -1](#r), [SMEP](#s)* • *Track: CPU Protection Rings'

**Ring -1** — Virtualization hypervisor mode (VMX root); more privileged than Ring 0; where VMMs like KVM and VMware operate. *See also: [Ring 0](#r), [Ring -2](#r), [VMX](#v)* • *Track: CPU Protection Rings'

**Ring -2** — SMM (System Management Mode) execution level; the most privileged x86 mode, invisible to the OS; entered via SMI. *See also: [SMM](#s), [SMRAM](#s), [SMI](#s)* • *Track: CPU Protection Rings'

**Ring -3** — Management Engine mode (Intel ME / AMD PSP); autonomous subsystem running independent of the main CPU with full hardware access. *See also: [Intel ME](#i), [AMD PSP](#a), [SMM](#s)* • *Track: CPU Protection Rings'

**Ring 3** — CPU protection ring for user/supervisor mode; the least privileged level where applications run; enforced by CPL field in CS. *See also: [Ring 0](#r), [SMEP](#s), [SMAP](#s)* • *Track: CPU Protection Rings'

**ROP** — Return-Oriented Programming; exploitation technique chaining short instruction sequences ("gadgets") ending in ret to perform arbitrary computation. *See also: [ROP chain](#r), [JOP](#j), [COP](#c), [gadget](#g)* • *Track: Exploitation'

**ROP chain** — A linked sequence of ROP gadgets constructed on the stack to perform arbitrary operations; the payload of a ROP-based exploit. *See also: [ROP](#r), [gadget](#g), [stack pivot](#s)* • *Track: Exploitation'

**ROPgadget** — Tool for searching binary files for ROP gadgets; outputs addresses and instructions suitable for building exploit chains. *See also: [ropper](#r), [pwntools](#p), [one_gadget](#o)* • *Track: CTF & Exploit Dev'

**ropper** — ROP gadget search tool that finds gadgets in ELF/PE/Mach-O binaries with constraint-based filtering. *See also: [ROPgadget](#r), [pwntools](#p)* • *Track: CTF & Exploit Dev'

**rw_semaphore** — Linux kernel reader-writer lock allowing concurrent readers but exclusive writers; yields to waiters. *See also: [mutex](#m), [spinlock](#s), [RCU](#r)* • *Track: Linux Kernel Security'

---

## S

**sandbox** — Isolation mechanism restricting a process's system call and resource access (filesystem, network); uses seccomp, namespaces, and/or chroot. *See also: [seccomp](#s), [renderer sandbox](#r), [namespaces](#n)* • *Track: Mitigation & Defense*

**sanitizer** — Compiler instrumentation tool detecting undefined behavior at runtime (e.g., ASan for memory errors, TSan for data races). *See also: [ASan](#a), [MSan](#m), [UBSan](#u), [TSan](#t)* • *Track: Fuzzing'

**Secure Enclave** — Apple's dedicated coprocessor (SE chip) handling biometric data, key material, and secure boot measurements; isolated from the main CPU. *See also: [SIP](#s), [KTRR](#k)* • *Track: macOS/XNU*

**seccomp** — Linux kernel feature restricting the system calls a process can make; seccomp-BPF allows fine-grained syscall filtering. *See also: [seccomp-BPF](#s), [namespaces](#n), [cgroups](#c)* • *Track: Linux Kernel Security*

**seccomp-BPF** — Extended seccomp mode using BPF programs to filter system calls by number, arguments, and return values. *See also: [seccomp](#s), [renderer sandbox](#r), [sandbox](#s)* • *Track: Linux Kernel Security*

**seed** — Initial input file used by a fuzzer as the starting point for mutation and coverage discovery. *See also: [corpus](#c), [fuzz target](#f)* • *Track: Fuzzing'

**SELinux** — Security-Enhanced Linux; MAC implementation using label-based policies enforcing fine-grained access rules; default on Android and RHEL. *See also: [AppArmor](#a), [sepolicy](#s), [MAC](#m)* • *Track: Linux Kernel Security*

**sepolicy** — SELinux policy configuration; on Android, defines all allowed inter-process and file access rules for the entire system. *See also: [SELinux](#s), [MAC](#m)* • *Track: Android'

**seq_operations** — Linux kernel structure for seq_file iteration; commonly used as a UAF target since it contains a function pointer. *See also: [msg_msg](#m), [pipe_buffer](#p), [kmalloc](#k)* • *Track: Linux Kernel Security'

**SEV** — Secure Encrypted Virtualization; AMD feature encrypting VM memory with a key invisible to the hypervisor. *See also: [SEV-SNP](#s), [SGX](#s), [TXT](#t)* • *Track: Mitigation & Defense'

**SEV-SNP** — SEV Secure Nested Paging; AMD enhancement adding integrity protection and replay protection to SEV, preventing hypervisor tampering of VM memory. *See also: [SEV](#s), [EPT](#e), [NPT](#n)* • *Track: Mitigation & Defense'

**SGX** — Software Guard Extensions; Intel feature creating isolated "enclaves" for code and data; even the OS cannot read enclave memory. *See also: [SEV](#s), [TXT](#t), [Secure Enclave](#s)* • *Track: Mitigation & Defense'

**Shadow Brokers** — Group that leaked Equation Group tools and exploits (including EternalBlue) in 2016-2017; one of the most impactful cybersecurity events. *See also: [Equation Group](#e), [exploit kit](#e)* • *Track: Zero-Day Research*

**Shadow Stack** — CET hardware feature that maintains a separate copy of return addresses on a dedicated shadow stack, detecting ROP overwrites. *See also: [CET](#c), [IBT](#i), [stack canary](#s)* • *Track: Mitigation & Defense'

**shellcode** — Position-independent machine code injected and executed by an exploit; traditionally opens a shell but can implement arbitrary functionality. *See also: [PIC](#p), [staged payload](#s), [stager](#s), [egg hunter](#e)* • *Track: Exploitation'

**sign extension** — Bug where a narrower signed integer is widened, propagating the sign bit and producing an unexpectedly large value; common in kernel ioctls. *See also: [integer overflow](#i), [integer truncation](#i)* • *Track: Exploitation'

**Site Isolation** — Chromium security architecture ensuring different sites use different renderer processes, preventing cross-site data leaks via Spectre-like attacks. *See also: [OOPIF](#o), [renderer sandbox](#r), [Mojo](#m)* • *Track: Chromium'

**slab** — Linux kernel slab allocator; manages memory in caches of fixed-size objects; legacy predecessor to SLUB. *See also: [slub](#s), [slob](#s), [kmalloc](#k)* • *Track: Linux Kernel Security'

**slob** — Simple List of Blocks; a minimalist Linux kernel allocator for embedded systems; lacks per-CPU caches and debug features. *See also: [slab](#s), [slub](#s)* • *Track: Linux Kernel Security'

**SLAT** — Second Level Address Translation; generic term for hardware page table nesting used in virtualization (EPT on Intel, NPT on AMD). *See also: [EPT](#e), [NPT](#n), [VMCS](#v)* • *Track: CPU Protection Rings'

**Smack** — Simplified Mandatory Access Control Kernel; Linux MAC using labels on processes and objects for network-centric policies. *See also: [SELinux](#s), [AppArmor](#a), [MAC](#m)* • *Track: Linux Kernel Security'

**SMEP** — Supervisor Mode Execution Prevention; x86 CR4 bit preventing kernel mode from executing user-space pages, blocking ret2user attacks. *See also: [SMAP](#s), [CR4](#c), [native_write_cr4](#n)* • *Track: Mitigation & Defense*

**SMAP** — Supervisor Mode Access Prevention; x86 CR4 bit preventing kernel mode from accessing user-space pages, blocking kernel info leaks and data corruption. *See also: [SMEP](#s), [CR4](#c), [KPTI](#k)* • *Track: Mitigation & Defense'

**SMI** — System Management Interrupt; hardware interrupt that triggers entry into SMM, suspending normal OS execution; can be exploited for Ring -2. *See also: [SMM](#s), [SMRAM](#s), [TCO](#t)* • *Track: CPU Protection Rings'

**SMM** — System Management Mode; x86 execution mode more privileged than Ring 0 (Ring -2); entered via SMI; operates on isolated SMRAM. *See also: [SMRAM](#s), [SMI](#s), [Ring -2](#r)* • *Track: CPU Protection Rings'

**SMRAM** — System Management RAM; memory region reserved for SMM code and data; inaccessible to Ring 0 under normal conditions. *See also: [SMM](#s), [SMI](#s)* • *Track: CPU Protection Rings'

**snapshot** — Fuzzing optimization that saves and restores VM/process state, avoiding slow initialization per test case. *See also: [fork server](#f), [persistent mode](#p)* • *Track: Fuzzing'

**spinlock** — Linux kernel busy-wait lock; the holder loops checking for availability; used in interrupt context where sleeping is forbidden. *See also: [mutex](#m), [RCU](#r), [rw_semaphore](#r)* • *Track: Linux Kernel Security*

**SSP** — Stack Smashing Protector; GCC/Clang feature inserting a random canary value before the return address to detect stack buffer overflows. *See also: [stack canary](#s), [Shadow Stack](#s), [DEP](#d)* • *Track: Mitigation & Defense'

**SSV** — Signed System Volume; macOS cryptographically sealed system volume that prevents modification of OS files; enforced by the Secure Enclave. *See also: [SIP](#s), [dm-verity](#d), [KTRR](#k)* • *Track: macOS/XNU'

**stack buffer overflow** — Writing past the end of a stack-allocated buffer, overwriting saved return addresses or canaries to hijack control flow. *See also: [BOF](#b), [stack canary](#s), [SSP](#s)* • *Track: Exploitation'

**stack canary** — Random value placed on the stack between local variables and the saved return address; overwritten during overflow, causing SSP to abort. *See also: [SSP](#s), [Shadow Stack](#s), [stack buffer overflow](#s)* • *Track: Mitigation & Defense'

**stack pivot** — Exploitation technique that moves the stack pointer to an attacker-controlled location (heap, .bss, etc.) by overwriting saved RBP or using an xchg gadget. *See also: [pivot](#p), [ROP chain](#r), [gadget](#g)* • *Track: Exploitation'

**staged payload** — Multi-stage exploit payload where a small initial stager downloads and executes a larger second-stage payload. *See also: [stager](#s), [egg hunter](#e), [shellcode](#s)* • *Track: Exploitation'

**stager** — The first, minimal stage of a staged payload; its sole purpose is to establish communication and receive the second stage. *See also: [staged payload](#s), [shellcode](#s)* • *Track: Exploitation'

**strace** — Linux diagnostic tool tracing system calls and signals received by a process; essential for understanding kernel interaction. *See also: [ltrace](#l), [GDB](#g)* • *Track: CTF & Exploit Dev'

**structure-aware** — Fuzzing approach that understands the input format's grammar and generates structurally valid mutations (e.g., protobuf, protobuf mutators). *See also: [grammar-based](#g), [fuzz target](#f), [AFL++](#a)* • *Track: Fuzzing'

**subprocess_info** — Linux kernel structure used by call_usermodehelper to set up user-space process execution from kernel context; target for modprobe_path-style exploits. *See also: [modprobe_path](#m), [core_pattern](#c), [commit_creds](#c)* • *Track: Linux Kernel Security*

**SVM** — Secure Virtual Machine; AMD's hardware virtualization extension enabling efficient virtual machine execution. *See also: [VMX](#v), [VMCB](#v), [AMD-V](#a)* • *Track: CPU Protection Rings'

**SVG crawl** — Chromatism's site-isolation test that enumerates cross-origin resource loads for side-channel benchmarking. *Track: Chromium*

**syzkaller** — Google's coverage-guided kernel fuzzer using syscall descriptions to generate structure-aware inputs for Linux and other kernels. *See also: [AFL++](#a), [coverage-guided](#c), [fuzz target](#f)* • *Track: Fuzzing'

**SystemServer** — Android system process running core services (ActivityManager, PackageManager, etc.); runs in the Zygote fork tree. *See also: [Zygote](#z), [Binder](#b), [framework](#f)* • *Track: Android'

---

## T

**task_struct** — Linux kernel structure representing a process or thread; holds PID, cred, mm_struct, and scheduling information. *See also: [cred](#c), [mm_struct](#m), [commit_creds](#c)* • *Track: Linux Kernel Security*

**task_t** — XNU Mach task structure representing a process; holds port namespace, address map, and thread list; Mach-level equivalent of task_struct. *See also: [thread_act](#t), [Mach port](#m), [ipc_port](#i)* • *Track: macOS/XNU*

**TCO** — Timer Control Offset; Intel ICH/LPC register that can trigger system reset; used in SMM research for forced resets and watchdog management. *See also: [SMM](#s), [SMI](#s)* • *Track: CPU Protection Rings'

**tcache poisoning** — Glibc heap exploitation technique corrupting the per-thread tcache freelist to return an arbitrary address from malloc. *See also: [fastbin attack](#f), [heap feng shui](#h), [house of force](#h)* • *Track: CTF & Exploit Dev'

**TCC** — Transparency, Consent, and Control; macOS framework managing application permissions (camera, microphone, files, screen recording). *See also: [SIP](#s), [AMFI](#a), [Hardened Runtime](#h)* • *Track: macOS/XNU'

**thread_act** — XNU Mach thread act structure representing a schedulable unit within a task; contains architecture-specific register state. *See also: [task_t](#t), [Mach IPC](#m)* • *Track: macOS/XNU'

**TLB** — Translation Lookaside Buffer; CPU cache for recent virtual-to-physical address translations; TLB flushes are a cost of KPTI and context switches. *See also: [CR3](#c), [pgd](#p), [KPTI](#k)* • *Track: CPU Protection Rings'

**TOCTOU** — Time-of-Check to Time-of-Use; race condition where a condition is verified but changes before the checked value is used. *See also: [race condition](#r), [double-fetch](#d)* • *Track: Exploitation'

**TOMOYO** — Linux MAC implementation using path-based access control with automatic policy learning; less common than SELinux. *See also: [SELinux](#s), [AppArmor](#a), [MAC](#m)* • *Track: Linux Kernel Security'

**tracefs** — Linux virtual filesystem (/sys/kernel/tracing) exposing kernel tracing infrastructure (ftrace, kprobes); used for debugging and rootkit detection. *See also: [procfs](#p), [sysfs](#s)* • *Track: Android'

**Treble** — Project Treble; Android architectural change separating the vendor implementation (HAL) from the OS framework via HIDL/AIDL interfaces. *See also: [HIDL](#h), [AIDL](#a), [HAL](#h)* • *Track: Android'

**TSan** — ThreadSanitizer; Clang/LLVM tool detecting data races between concurrent threads; indispensable for finding race conditions. *See also: [ASan](#a), [MSan](#m), [race condition](#r)* • *Track: Fuzzing*

**TSS** — Task State Segment; x86 data structure holding the kernel stack pointer and I/O permission bitmap for the current task. *See also: [GDT](#g), [IDT](#i), [LDT](#l)* • *Track: CPU Protection Rings'

**tty_struct** — Linux kernel structure representing a TTY device; contains ops function pointers and is a target for kernel heap exploitation. *See also: [msg_msg](#m), [pipe_buffer](#p), [kmalloc](#k)* • *Track: Linux Kernel Security*

**TXT** — Trusted Execution Technology; Intel's set of hardware extensions for establishing a measured launch environment (MLE) using TPM. *See also: [SGX](#s), [SEV](#s)* • *Track: Mitigation & Defense'

**type confusion** — Vulnerability where an object of one type is treated as another, allowing access to fields or vtable entries of the wrong type. *See also: [V8](#v), [UAF](#u), [CFI](#c)* • *Track: Exploitation'

---

## U

**UAF** — Use-After-Free; vulnerability where a dangling pointer to freed memory is dereferenced, potentially leading to code execution. *See also: [double-free](#d), [type confusion](#t), [UAF prevention](#u)* • *Track: Exploitation'

**UAF prevention** — Chromium's suite of mitigation strategies for use-after-free bugs, including MiraclePtr, backup pointers, and PartitionAlloc isolation. *See also: [MiraclePtr](#m), [RawPtr](#r), [heap scan](#h)* • *Track: Chromium'

**UBSan** — UndefinedBehaviorSanitizer; Clang/LLVM instrumentation detecting undefined behavior (integer overflow, null dereference, shift, etc.). *See also: [ASan](#a), [MSan](#m), [KASAN](#k)* • *Track: Fuzzing'

**UMWAP** — User-Mode Wireless Access Point; a Windows user-mode component for Wi-Fi direct; referenced in some exploitation research as a target. *Track: OSEE/EXP-401*

**unsorted bin attack** — Glibc heap exploitation technique corrupting the unsorted bin fd/bk pointers to write a large value at an arbitrary address. *See also: [fastbin attack](#f), [tcache poisoning](#t), [house of force](#h)* • *Track: CTF & Exploit Dev'

**URLLoaderFactory** — Chromium Mojo interface for creating network URL loaders; key IPC boundary between renderer and browser/network processes. *See also: [Mojo](#m), [Mojo IPC](#m), [RenderProcessHost](#r)* • *Track: Chromium'

**use-after-scope** — Vulnerability where a reference to a stack variable persists after its enclosing scope ends, creating an effective UAF on the stack. *See also: [UAF](#u), [stack buffer overflow](#s)* • *Track: Exploitation'

---

## V

**V8** — Chromium's JavaScript and WebAssembly engine; just-in-time compiled with TurboFan/TurboShaft pipeline; historically a frequent exploit target. *See also: [Blink](#b), [type confusion](#t), [Mojo](#m)* • *Track: Chromium'

**VEP** — Vulnerabilities Equities Process; the US government's framework for deciding whether to disclose or retain knowledge of vulnerabilities. *See also: [0-day](#zero-day), [responsible disclosure](#r)* • *Track: Zero-Day Research*

**verified boot** — Android boot chain security feature verifying each stage's cryptographic signature before execution (bootloader → kernel → dm-verity). *See also: [dm-verity](#d), [APEX](#a), [fastboot](#f)* • *Track: Android'

**Vestige** — Chromium infrastructure for detecting UAF via temporal memory safety; complements MiraclePtr with additional protection for freed objects. *See also: [MiraclePtr](#m), [UAF prevention](#u), [heap scan](#h)* • *Track: Chromium'

**VMA mirroring** — PaX technique mirroring the VMA list into a separate read-only copy, making kernel VMA Corruption detectable and recoverable. *See also: [PaX](#p), [grsecurity](#g)* • *Track: Linux Kernel Security'

**vm_area_struct** — Linux kernel structure describing a contiguous virtual memory area (VMA) in a process; holds start, end, permissions, and backing file. *See also: [mm_struct](#m), [page](#p), [task_struct](#t)* • *Track: Linux Kernel Security'

**VMCS** — Virtual Machine Control Structure; Intel VMX data structure holding guest/host state and execution controls for virtualization. *See also: [VMX](#v), [EPT](#e), [VMCB](#v)* • *Track: CPU Protection Rings'

**VMCB** — Virtual Machine Control Block; AMD SVM data structure holding guest/host state and execution controls, analogous to VMCS. *See also: [SVM](#s), [NPT](#n), [VMCS](#v)* • *Track: CPU Protection Rings'

**VMX** — Virtual Machine Extensions; Intel's hardware virtualization instruction set enabling VMM operation (VM entry, VM exit, etc.). *See also: [SVM](#s), [VMCS](#v), [VT-x](#v)* • *Track: CPU Protection Rings'

**VT-d** — Intel Virtualization Technology for Directed I/O; provides IOMMU functionality (DMA remapping, interrupt remapping) for device isolation. *See also: [IOMMU](#i), [DMAR](#d), [VT-x](#v)* • *Track: CPU Protection Rings'

**VT-x** — Intel Virtualization Technology for x86; provides hardware support for virtualization (VMX operation modes). *See also: [VMX](#v), [VT-d](#v), [AMD-V](#a)* • *Track: CPU Protection Rings'

---

## W

**wait queue** — Linux kernel data structure allowing processes to sleep until a condition is met; awakened by corresponding wake_up() calls. *See also: [completion](#c), [mutex](#m), [spinlock](#s)* • *Track: Linux Kernel Security'

**W^X** — Write XOR Execute; security policy ensuring no memory page is simultaneously writable and executable; implemented by DEP/NX. *See also: [DEP](#d), [NX](#n), [ASLR](#a)* • *Track: Mitigation & Defense'

**WP bit** — Write Protect bit in CR0; when set, prevents Ring 0 from writing to read-only pages; disabled by some exploits for /dev/mem writes. *See also: [CR0](#c), [SMEP](#s), [SMAP](#s)* • *Track: CPU Protection Rings'

---

## X

**XFG** — eXtended Flow Guard; Microsoft's improved CFG providing indirect call target validation using type-specific context, harder to bypass than CFG. *See also: [CFG](#c), [CFI](#c), [ACG](#a)* • *Track: OSEE/EXP-401'

**XNU** — X is Not Unix; Apple's hybrid kernel (Mach + BSD + IOKit + DSP) powering macOS, iOS, tvOS, and watchOS. *See also: [Mach](#m), [IOKit](#i), [KEXT](#k)* • *Track: macOS/XNU'

**XProtect** — Apple's built-in malware detection system for macOS that checks downloaded apps against a database of known malware signatures. *See also: [Gatekeeper](#g), [MRT](#m), [SIP](#s)* • *Track: macOS/XNU'

---

## Y

No entries for Y.

---

## Z

**Zygote** — Android initialization process that forks all app processes; preloads shared classes and resources to speed up app startup. *See also: [SystemServer](#s), [ART](#a), [framework](#f)* • *Track: Android'

**zone allocator** — XNU's kernel heap allocator that segregates allocations by type/size into zones, per-object metadata enables UAF detection. *See also: [kalloc](#k), [kalloc_type](#k), [zone_gc](#z)* • *Track: macOS/XNU'

**zone_gc** — XNU zone garbage collector that reclaims free zones and can detect some forms of zone corruption; scheduled periodically or under memory pressure. *See also: [zone allocator](#z), [kalloc](#k)* • *Track: macOS/XNU'

**zone_map** — XNU kernel virtual memory region backing all zone allocator allocations; its limits can be a bottleneck for kernel memory exhaustion. *See also: [zone allocator](#z), [kalloc](#k)* • *Track: macOS/XNU'

---

## Numbers & Symbols

<a id="zero-day"></a>
**0-day** — A vulnerability unknown to the vendor with no available patch; the most valuable type in the exploit market. *See also: [1-day](#n), [N-day](#n), [VEP](#v), [broker](#b)* • *Track: Zero-Day Research*

**COP** — See [COP](#c) under C.

**CVE** — Common Vulnerabilities and Exposures; standardized identifier for publicly known security vulnerabilities, maintained by MITRE. *See also: [NVD](#n), [CVSS](#c), [CWE](#c)* • *Track: Zero-Day Research*

**CVSS** — See [CVSS](#c) under C.

**KASLR** — Kernel Address Space Layout Randomization; Linux mitigation randomizing the base address of the kernel text, data, and modules at boot. *See also: [ASLR](#a), [PIE](#p), [KPTI](#k)* • *Track: Linux Kernel Security'

---

*Last updated: 2026-04-26 | 295 entries*