# Windows Memory Protections — DEP, ASLR, CFG, ACG/CIG, Stack Cookies, EMET & VBS/HVCI

> A deep-technical reference on Windows exploit mitigations from XP through 11: DEP/NX, ASLR variants, CFG/XFG, ACG/CIG, Stack Cookies, SafeSEH/SEHOP, EMET, Exploit Protection, VBS, and HVCI. For each mitigation, detailed bypass techniques with real CVE examples. Written for exploit developers and OSEE candidates.

---

## Table of Contents

1. [Exploit Mitigation Evolution](#1-exploit-mitigation-evolution)
2. [DEP/NX (Data Execution Prevention)](#2-depnx-data-execution-prevention)
3. [ASLR (Address Space Layout Randomization)](#3-aslr-address-space-layout-randomization)
4. [Stack Cookies (GS)](#4-stack-cookies-gs)
5. [SafeSEH & SEHOP](#5-safeseh--sehop)
6. [CFG & XFG (Control Flow Guard)](#6-cfg--xfg-control-flow-guard)
7. [ACG & CIG (Arbitrary Code Guard / Code Integrity Guard)](#7-acg--cig-arbitrary-code-guard--code-integrity-guard)
8. [EMET & Exploit Protection](#8-emet--exploit-protection)
9. [VBS & HVCI (Virtualization-Based Security & Hypervisor-Enforced Code Integrity)](#9-vbs--hvci-virtualization-based-security--hypervisor-enforced-code-integrity)
10. [CET (Control-Flow Enforcement Technology)](#10-cet-control-flow-enforcement-technology)
11. [Bypass Taxonomy & Real CVE Examples](#11-bypass-taxonomy--real-cve-examples)
12. [Future Mitigations](#12-future-mitigations)

---

## 1. Exploit Mitigation Evolution

The Windows exploit mitigation landscape has evolved dramatically over two decades, each generation raising the bar for attackers:

```
Windows Exploit Mitigation Timeline:
═══════════════════════════════════════════════════════════════════
2004  XP SP2         Stack Cookies (/GS), SafeSEH, DEP
2006  Vista           ASLR (system-level), NX, ASLR per-DLL
2008  Vista SP1       SEHOP, PatchGuard v2
2009  Win7            Mandatory ASLR, DEP per-process
2012  Win8            High-entropy ASLR (64-bit), Heap protections
2013  Win8.1           CFG (Control Flow Guard)
2015  Win10            Win32k pool separation, VBS, HVCI
2016  Win10 RS1        RFG (Return Flow Guard), Segment Heap
2017  Win10 RS3        KPTI (Meltdown mitigation)
2018  Win10 RS5        CFG improvements, Retpoline
2019  Win10 19H1       ACG/CIG enforcement, Kernel Stack Cookie
2020  Win10 20H1       XFG (Experimental), CET hardware
2021  Win10 21H1       Kernel Stack Pivot Detection
2022  Win11 22H2       Strict HVCI, Smart App Control
2024  Win11 24H2       Rust in Win32k, VBS-enforced CET
═══════════════════════════════════════════════════════════════════
```

Each mitigation targets a specific exploitation primitive:

| Mitigation | Targeted Primitive | Residual Risk |
|-----------|-------------------|---------------|
| DEP/NX | Shellcode on stack/heap | ROP chains |
| ASLR | Fixed address ROP gadgets | Info leak required |
| Stack Cookies | Stack buffer overflow | Cookie leak required |
| SafeSEH/SEHOP | SEH chain overwrite | SEH bypass required |
| CFG | Indirect call hijacking | Non-CFG targets |
| ACG/CIG | Dynamic code execution | Code reuse attacks |
| VBS/HVCI | Kernel code modification | Data-only attacks |
| CET | ROP chain execution | Forward-edge CFI bypass |

---

## 2. DEP/NX (Data Execution Prevention)

### 2.1 Architecture

Data Execution Prevention (DEP), also known as No-Execute (NX) or Execute Disable (XD), uses the CPU's NX bit in page table entries to prevent execution from data pages:

```
Page Table Entry (PTE) with DEP/NX:
┌─────────────────────────────────────────────────────────────────┐
│ Bit 63 (NX) │ Page Frame Number │ Reserved │ Attributes │     │
│   0=Execute │                   │          │            │     │
│   1=NoExec  │                   │          │            │     │
└─────────────────────────────────────────────────────────────────┘

With DEP enabled:
- Stack pages: NX bit SET → execution blocked
- Heap pages: NX bit SET → execution blocked
- .text pages: NX bit CLEAR → execution allowed
- .rdata pages: NX bit SET → execution blocked

Without DEP (Windows XP default):
- All pages: NX bit CLEAR → execution allowed everywhere
```

### 2.2 DEP Policy

Windows implements four DEP policies per process:

| Policy | Value | Effect |
|--------|-------|--------|
| `PROCESS_DEP_ENABLE` | 0x01 | DEP always on, cannot be disabled |
| `PROCESS_DEP_DISABLE` | 0x00 | DEP disabled (legacy compatibility) |
| `PROCESS_DEP_ATL_THUNK` | 0x02 | DEP disabled for ATL thunk compatibility |
| Opt-in (system default) | — | DEP enabled only for system binaries |
| Opt-out | — | DEP enabled for all except excluded processes |
| AlwaysOn | — | DEP always on, no exceptions |

```c
// Query/Set DEP policy (Vista+):
DWORD depPolicy;
GetProcessDEPPolicy(GetCurrentProcess(), &depPolicy, NULL);

// Enable DEP for current process (if policy permits):
SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

// DEP mitigation metadata in PE header (optional):
// IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100) → DEP compatible
// IMAGE_DLLCHARACTERISTICS_NO_ISOLATION (0x0200) → No isolation
```

### 2.3 DEP Bypass Techniques

**Technique 1: Return-Oriented Programming (ROP)**

The primary DEP bypass is ROP — chaining existing code gadgets from executable pages:

```
ROP Chain Concept:
┌──────────────┐
│ Gadget 1:    │  pop rax; ret          ← from ntdll.dll .text
│ Gadget 2:    │  pop rcx; ret          ← from kernel32.dll .text
│ Gadget 3:    │  mov [rax], rcx; ret   ← from msvcrt.dll .text
│ ...          │  ...
│ Final:       │  jmp [VirtualProtect]   ← from kernel32.dll IAT
└──────────────┘
   All gadgets are from executable pages (NX CLEAR) → DEP bypassed
```

**Technique 2: VirtualProtect ROP Chain**

Allocate a writable page and make it executable:

```asm
; VirtualProtect ROP chain (x64):
; Target: call VirtualProtect(stack_addr, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect)

; 1. Load parameters into registers
pop rcx                    ; rcx = stack_addr (writable address)
pop rdx                    ; rdx = 0x1000 (size)
pop r8                     ; r8  = 0x40 (PAGE_EXECUTE_READWRITE)
pop r9                     ; r9  = &old_protect (writable address)

; 2. Call VirtualProtect
jmp [IAT_VirtualProtect]   ; Jump to VirtualProtect via IAT

; After VirtualProtect returns, stack_addr is now RWX
; Jump to shellcode at stack_addr
jmp rcx
```

**Technique 3: Ret2Libc**

Call existing library functions to achieve code execution without ROP:

```c
// Instead of executing shellcode, call WinExec("cmd.exe") via ROP:
// Find: WinExec address in kernel32.dll
// Find: "cmd.exe" string or write it to known location
// Set up stack: WinExec(target_string, SW_SHOW)
```

**Technique 4: SetProcessDEPPolicy Bypass (legacy)**

On 32-bit Windows with Opt-In DEP policy, calling `SetProcessDEPPolicy(PROCESS_DEP_DISABLE)` disables DEP for the calling process. This was patched in XP SP3+.

**Technique 5: NtSetInformationProcess DEP Bypass (legacy)**

```c
// Disable DEP via NtSetInformationProcess (pre-Vista):
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE ProcessHandle, 
    ULONG ProcessInformationClass, 
    PVOID ProcessInformation, 
    ULONG ProcessInformationLength);

ULONG depEnable = 0; // MEM_EXECUTE_OPTION_DISABLE
pNtSetInformationProcess(NtCurrentProcess(), 
    ProcessExecuteFlags, 
    &depEnable, 
    sizeof(depEnable));
// After this call, DEP is disabled for the current process
```

---

## 3. ASLR (Address Space Layout Randomization)

### 3.1 ASLR Variants

Windows implements multiple ASLR levels, each randomizing different aspects of the address space:

| ASLR Type | Scope | Randomization | Entropy |
|-----------|-------|---------------|---------|
| **System ASLR** | Per-boot | System DLL base addresses | 8 bits (32-bit), 33 bits (64-bit) |
| **Mandatory ASLR** | Per-process | Non-ASLR DLL base addresses (forced) | 8 bits (32-bit), 33 bits (64-bit) |
| **Bottom-Up ASLR** | Per-process | Stack, heap base addresses | 8-9 bits (32-bit), 17+ bits (64-bit) |
| **High-Entropy ASLR** | Per-process | All DLL and EXE base addresses | 24 bits (32-bit), 33 bits (64-bit) |
| **Heap ASLR** | Per-process | Heap manager structures | 8 bits (32-bit) |
| **Stack ASLR** | Per-thread | Stack base addresses | 8-9 bits (32-bit) |
| **TEB/PEB ASLR** | Per-process | Thread/Process Environment Block | Per-boot |
| **Kernel ASLR (KASLR)** | Per-boot | ntoskrnl, HAL, drivers | 24 bits |

### 3.2 ASLR Implementation

```c
// ASLR in PE headers:
// IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) → DLL/EXE supports ASLR
// IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020) → 64-bit ASLR with high entropy
//
// If a DLL doesn't have DYNAMIC_BASE, it loads at its preferred base address
// (unless Mandatory ASLR forces relocation)

// ASLR randomization algorithm (simplified):
// 1. Generate random 8-bit (32-bit) or 33-bit (64-bit) value
// 2. Align to 64KB (0x10000) boundary
// 3. Add to preferred base address
// 4. Verify no overlap with other modules
// 5. Rebase module to randomized address

// 64-bit ASLR entropy calculation:
// Random offset = (RDRAND or RDTSC-based) << 12  // Align to 4KB
// Effective address = ImageBase + RandomOffset
// Entropy: ~33 bits (2^33 possible load addresses)
```

### 3.3 ASLR Bypass Techniques

**Technique 1: Information Leak (Address Disclosure)**

The most common ASLR bypass. Leak a known address from the target process:

```c
// Common info leak vectors:
// 1. Heap spray + type confusion (leak vtable pointer → leak module base)
// 2. Use-after-free (read freed object that contains module pointer)
// 3. Out-of-bounds read (read beyond array boundary)
// 4. Format string (leak stack values containing module addresses)
// 5. Shared memory (browsers share memory between processes)
// 6. Side-channel (cache timing, branch prediction)
```

**Technique 2: Partial Overwrite**

If only the low 16 bits of an address can be overwritten, the high bits may still be correct:

```asm
; Partial overwrite example (32-bit):
; Target address: 0x7C801234 (kernel32.dll function)
; With ASLR: 0x7C9XXXXX (only high byte randomized)
; Overwrite low 2 bytes: 0x7C9X???? → 0x7C9X1234
; If high byte matches, redirect to known offset within module

; 64-bit partial overwrite:
; Target: 0x00007FF`12345678
; Overwrite low 4 bytes with controlled value
; High 4 bytes (0x00007FF`) remain from original pointer
; Result: 0x00007FF`CONTROLLED
```

**Technique 3: JIT Spraying**

JIT compilers (JavaScript engines, .NET CLR) generate executable code at predictable addresses:

```javascript
// JavaScript JIT spray (browser exploitation):
// 1. Create many functions that contain the target instruction pattern
// 2. JIT compiler generates native code for each function
// 3. Code pages are allocated at predictable relative offsets
// 4. Calculate the address of specific JIT-generated instructions
// 5. Jump to JIT-sprayed code → bypass ASLR + DEP simultaneously
```

**Technique 4: Shared Library Loading Order**

Non-ASLR DLLs (without `DYNAMIC_BASE` flag) load at fixed addresses. If a process loads such a DLL, it provides a fixed address for ROP gadgets:

```powershell
# Find non-ASLR DLLs loaded in a process:
Get-Process -Id $PID | 
    Select-Object -ExpandProperty Modules | 
    Where-Object { $_.ModuleName -like "*noaslr*" }
```

**Technique 5: KASLR Bypass**

Kernel ASLR can be bypassed through various information leaks:

```c
// KASLR bypass techniques:
// 1. NtQuerySystemInformation with SystemModuleInformation
//    (requires SeDebugPrivilege or medium IL)
// 2. HMValidateHandle (Win32k handle validation, leaks kernel addresses)
// 3. Gtk+ font rendering (leaks kernel addresses via font metadata)
// 4. Side-channel attacks (cache timing, TLB timing)
// 5. MSR-based leaks (kernel addresses in model-specific registers)
// 6. Driver-related leaks (Ioctl leaks, /dev/ equivalent)
```

**Real CVE: CVE-2020-17087 (Chrome/+ Windows KASLR bypass)**

This vulnerability in the Windows kernel font subsystem allowed leaking kernel addresses through crafted font data, enabling KASLR bypass for combined browser+kernel exploit chains.

---

## 4. Stack Cookies (GS)

### 4.1 GS Implementation

Stack cookies (also called "security cookies" or "canaries") are placed between local variables and the saved return address on the stack:

```asm
; Function prologue with /GS (x64):
mov  rax, rsp              ; Save stack pointer
sub  rsp, 0x58              ; Allocate stack frame
mov  rax, gs:[0x30]        ; Get TEB (Thread Environment Block)
mov  rax, [rax+0x08]       ; Get stack cookie (__security_cookie)
xor  rax, rsp              ; XOR cookie with RSP (position-dependent)
mov  [rsp+0x48], rax       ; Store cookie in stack frame
; ... function body ...

; Function epilogue with /GS (x64):
mov  rcx, [rsp+0x48]       ; Load cookie from stack frame
xor  rcx, rsp              ; XOR with RSP (undo position-dependence)
cmp  rcx, gs:[0x30+0x08]  ; Compare with __security_cookie
jne  __stack_chk_fail      ; If mismatch → abort
add  rsp, 0x58             ; Restore stack
ret                         ; Return
```

### 4.2 GS Cookie Generation

The stack cookie is generated from a combination of:

```c
// __security_cookie initialization (simplified):
// At process startup, the master cookie is generated from:
// __security_cookie = RDTSC() ^ GetCurrentProcessId() ^ GetCurrentThreadId() ^ 
//                     QueryPerformanceCounter() ^ (&__security_cookie)
//
// On x64, the cookie stored on the stack is:
// stack_cookie = __security_cookie ^ RSP
// This makes the cookie position-dependent and stack-address-dependent
//
// Cookie size:
// x86: 4 bytes (DWORD)
// x64: 8 bytes (QWORD) → much harder to brute-force

// GS buffer detection:
// The compiler marks local variables that contain buffers (arrays, structs with arrays)
// as "GS buffers" and places them closest to the cookie in the stack frame.
// Variables without buffers are placed farther from the cookie.
```

### 4.3 GS Bypass Techniques

**Technique 1: Cookie Leak**

If an information leak exists that can read the stack, the cookie can be extracted:

```c
// Stack layout with GS:
// [Return Address]
// [Saved RBP]
// [GS Cookie] ← Leaked via info leak → cookie known
// [Local Variable 1]
// [Buffer (GS buffer)] ← Overflow starts here
```

**Technique 2: Cookie Brute Force (32-bit)**

On 32-bit, the cookie is only 4 bytes with limited entropy (the high byte is always 0x00 due to NULL byte):

```
Effective entropy: 24 bits (high byte is 0x00)
At 1000 attempts/second: ~4.6 hours average to brute-force
Not practical for remote exploitation, but possible for local or persistent attacks
```

**Technique 3: Exception Handler Overwrite**

If the function has an SEH handler, the handler address can be overwritten before the cookie is checked:

```
Stack layout with GS and SEH:
[Stack Cookie]  ← Checked at function epilogue
[SEH Handler]   ← Can be overwritten BEFORE epilogue check
[Buffer]        ← Overflow starts here

If exception occurs BEFORE epilogue → SEH handler executes
→ Jump to payload without cookie check → GS bypassed
```

**Technique 4: Simultaneous Overwrite**

If the overflow starts before the cookie and can overwrite both the cookie and the return address with known values:

```
// If attacker controls both the cookie value and the return address:
memcpy(buffer, attacker_data, size);  // Overflows past cookie
// If attacker_data contains: [original_cookie] [controlled_return_address]
// And the original_cookie is known (info leak) → GS bypassed
```

---

## 5. SafeSEH & SEHOP

### 5.1 SafeSEH

SafeSEH (introduced in Windows XP SP2) validates SEH handler addresses against a list of registered safe handlers compiled into the PE header:

```
SafeSEH Validation:
1. Exception occurs → OS walks SEH chain
2. For each SEH handler:
   a. Check if handler address is in a module with SafeSEH
   b. If yes → verify handler is in the module's safe handler table
   c. If handler is NOT in the safe table → terminate process
3. If handler is in a module WITHOUT SafeSEH → allow (compatibility)

SafeSEH Bypass:
- Find a module compiled WITHOUT /SafeSEH (no IMAGE_DLLCHARACTERISTICS_NO_SEH)
- Use a handler address within that module
- Common targets: old DLLs, DLLs compiled with legacy tools
```

### 5.2 SEHOP

SEHOP (Structured Exception Handler Overwrite Protection, introduced in Windows Vista SP1) validates the SEH chain by ensuring it terminates at the expected final handler (`KERNEL32!UnhandledExceptionFilter`):

```c
// SEHOP validation:
// 1. OS checks that the SEH chain ends at the expected final handler
// 2. The final handler address must be within kernel32.dll's .text section
// 3. The SEH chain must be properly linked (no cycles)
//
// Normal SEH chain:
// FS:[0] → Handler1 → Handler2 → ... → KERNEL32!UnhandledExceptionFilter
//
// Corrupted SEH chain (attack):
// FS:[0] → Attacker_Handler → ... (chain broken or wrong terminal)

// SEHOP bypass:
// Construct a fake SEH chain that ends at KERNEL32!UnhandledExceptionFilter
// This requires knowing the address of the terminal handler (defeated by ASLR)
// Or: use a stack pivot + ROP to skip SEHOP validation entirely
```

---

## 6. CFG & XFG (Control Flow Guard)

### 6.1 CFG Architecture

Control Flow Guard (CFG, introduced in Windows 8.1 with compiler support in Visual Studio 2015) validates indirect function calls at runtime:

```
CFG Flow:
1. Compile-time: Compiler identifies all indirect call targets (function pointers)
2. Link-time: Linker creates a bitmap of valid call targets (CFG bit table)
3. Runtime: Before each indirect call, _guard_check_icall_fptr validates the target

Indirect Call:
    call rax                    ; Indirect call via register

CFG-protected:
    mov  rcx, rax               ; Load target into rcx for validation
    call [_guard_check_icall_fptr]  ; Validate target
    ; If target is valid, execution continues
    ; If target is invalid, STATUS_STACK_BUFFER_OVERRUN
    call rax                    ; Execute the call
```

The CFG bit table is a dense bitmap stored in the PE header:

```
CFG Bitmap:
┌──────────────────────────────────────────────────────┐
│ Bit 0: 0x00000000 → NOT a valid call target          │
│ Bit 1: 0x00000004 → IS a valid call target           │
│ Bit 2: 0x00000008 → NOT a valid call target          │
│ ... (one bit per 4-byte or 8-byte aligned address)   │
│ Bit N: address → valid/invalid                        │
└──────────────────────────────────────────────────────┘

Validation: _guard_check_icall_fptr checks:
    bit_index = target_address >> 2 (or >> 3 on x64)
    if (CFG_BITMAP[bit_index] == 0) → INVALID → crash
    if (CFG_BITMAP[bit_index] == 1) → VALID → continue
```

### 6.2 CFG Limitations

| Limitation | Description |
|-----------|-------------|
| **No backward-edge protection** | CFG only validates forward edges (call/jump targets), not return addresses |
| **Coarse bitmap** | CFG granularity is 4 bytes (x86) or 8 bytes (x64), meaning small functions near valid targets may be reachable |
| **Module coverage** | Only modules compiled with `/guard:cf` are protected; unprotected modules have all addresses in their .text section marked valid |
| **No context sensitivity** | CFG validates that the target is a function start, but not that it's the *correct* function for this call site |
| **Exported functions** | All exported functions are valid targets, even if they shouldn't be called indirectly |
| **Virtual functions** | All vtable entries are valid targets, even if they're called from wrong vtables |

### 6.3 CFG Bypass Techniques

**Technique 1: Non-CFG Module Targeting**

```c
// Find a module without CFG protection:
// All addresses in the .text section of a non-CFG module are valid call targets
// If the module has any useful gadgets, they can be called without CFG violation

// Example: Load an old DLL without CFG support
HMODULE hNoCFGDll = LoadLibrary(L"old_dll_without_cfg.dll");
// All function addresses in hNoCFGDll are valid CFG targets
```

**Technique 2: CFG-Valid Target Abuse**

```c
// Even within CFG-protected modules, many addresses are valid targets:
// - All exported functions
// - All virtual method table entries
// - All function addresses taken as callbacks
// - All exception handler addresses
//
// Attack: redirect indirect call to a CFG-valid target that does something useful
// Example: call a "setuid"-like function that elevates privileges
```

**Technique 3: Overwrite Function Pointers in CFG-Valid Data**

```c
// CFG validates the call TARGET, not the call SITE
// If we can overwrite a function pointer stored in writable data:
// 1. Identify a writable function pointer in .data or heap
// 2. Overwrite the function pointer with a CFG-valid target
// 3. When the program calls through the pointer, CFG validates the NEW target
// 4. If the new target is CFG-valid, the call succeeds

// This is NOT a CFG bypass — CFG did its job checking the target
// The vulnerability is overwriting the function pointer, not bypassing CFG
```

### 6.4 XFG (Extended Fault Guard)

XFG (introduced experimentally in Windows 10 Insider Preview) extends CFG with type-based validation:

```
XFG Improvement over CFG:
- CFG: "Is this address a function start?" (binary: yes/no)
- XFG: "Is this address a function start with the correct TYPE?" (type-based validation)

XFG Hash:
- Each indirect call site computes an expected type hash
- At runtime, the hash of the call target is compared to the expected hash
- If hashes match → call proceeds
- If hashes don't match → process terminates

Type hash computation:
  hash = CRC32(function_signature) ^ module_characteristics
  (approximates a type-based identifier without full type info)

XFG effectiveness:
  - Coverage: ~98% of indirect calls are type-checked
  - Overhead: ~2-3% performance impact
  - Bypass: Requires finding a function with the exact same type hash,
            which significantly reduces gadget availability
```

---

## 7. ACG & CIG (Arbitrary Code Guard / Code Integrity Guard)

### 7.1 ACG (Arbitrary Code Guard)

ACG prevents a process from creating or modifying executable memory:

```
ACG Enforcement Rules:
1. VirtualAlloc(VIEW_EXECUTE) → BLOCKED (cannot allocate new RWX pages)
2. VirtualProtect(PAGE_EXECUTE_READWRITE) → BLOCKED (cannot make pages RWX)
3. CreateThread with executable stack → BLOCKED
4. Writing to code pages (NTSTATUS STATUS_ACCESS_DENIED) → BLOCKED
5. JIT code generation → BLOCKED (unless process has special policies)

Implementation:
- NtAllocateVirtualMemory: Rejects PAGE_EXECUTE_READWRITE requests
- NtProtectVirtualMemory: Rejects transitions to RWX
- Process option: PROCESS_MAKE_EXECUTE_ONLY
- Thread option: THREAD_CREATE_FLAGS_SKIP_THUNK
```

ACG is enforced through process mitigation options:

```c
// Enable ACG programmatically:
PROCESS_MITIGATION_CHILD_PROCESS_POLICY acgPolicy = {0};
acgPolicy.Enable = 1;

STARTUPINFOEX siex = {0};
siex.StartupInfo.cb = sizeof(siex);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attrSize);

UpdateProcThreadAttribute(siex.lpAttributeList, 0,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    &acgPolicy, sizeof(acgPolicy), NULL, NULL);

CreateProcess(L"C:\\Windows\\notepad.exe", NULL, NULL, NULL, FALSE,
    EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
    &siex.StartupInfo, &pi);
```

### 7.2 CIG (Code Integrity Guard)

CIG (also called Code Integrity Guard) restricts the DLLs a process can load to only Microsoft-signed DLLs:

```
CIG Enforcement Rules:
1. LoadLibrary(non-Microsoft-signed DLL) → BLOCKED
2. CreateProcess(non-Microsoft-signed EXE) → BLOCKED  
3. Only DLLs signed by Microsoft certificates can be loaded
4. Optional: further restrict to specific Microsoft-signing types

Implementation:
- NtMapViewOfSection: Checks DLL signature before mapping
- Code integrity checks in kernel (ci.dll)
- Process option: PROCESS_CREATION_MITIGATION_POLICY_CODE_INTEGRITY_GUARD
```

### 7.3 ACG/CIG Bypass

| Technique | ACG Bypass? | CIG Bypass? | Description |
|-----------|-------------|-------------|-------------|
| **ROP** | Yes | N/A | ROP doesn't need new executable pages |
| **COM object hijack** | Yes | Yes | Load trusted COM object that loads unsigned DLL |
| **DLL sideloading** | Partial | No | Side-load unsigned DLL next to signed EXE |
| **Dynamic code modification** | No | N/A | ACG prevents page modification |
| **Copy-on-write in shared sections** | Possible | N/A | Exploit COW semantics in shared memory |
| **SetProcessMitigationPolicy bypass** | No | N/A | Mitigations are enforced by kernel |
| **Child process creation** | N/A | Yes | Create child process without ACG/CIG |
| **Dynamic code generation via JIT** | No | N/A | ACG blocks JIT unless exempted |

**Real-world ACG bypass: CVE-2019-1388 (Windows Installer EoP)**

This vulnerability bypassed ACG by exploiting the Windows Installer (msiexec.exe) to obtain code execution in an ACG-protected process through a specially crafted MSI package that executed code via signed binary execution.

---

## 8. EMET & Exploit Protection

### 8.1 EMET (Enhanced Mitigation Experience Toolkit)

EMET was Microsoft's standalone tool for per-process mitigation configuration, discontinued in 2018. Key EMET features that are now built into Windows:

| EMET Feature | Windows Equivalent | Status |
|-------------|-------------------|--------|
| DEP | `SetProcessDEPPolicy` | Native since XP SP2 |
| ASLR | Mandatory ASLR | Native since Vista |
| CFG | `SetProcessMitigationPolicy` | Native since Win8.1 |
| EAF (Export Address Filtering) | N/A | Deprecated (replaced by ACG) |
| EAF+ | N/A | Deprecated |
| Bottom-Up ASLR | Heap/Stack ASLR | Native since Vista |
| Heap Spray Allocation | Guard pages | Native since Win10 |
| ROP Mitigation | CFG + CET | Native |
| Anti-ROP (Stack Pivot) | Stack Pivot Detection | Partial (Win11) |
| Certificate Trust | WDAC | Native since Win10 |

### 8.2 Exploit Protection (Windows 10+)

Exploit Protection is the built-in successor to EMET, accessible via Windows Security settings and Group Policy:

```powershell
# View current exploit protection settings:
Get-ProcessMitigation -System

# Set exploit protection for a specific binary:
Set-ProcessMitigation -Name "C:\app\vulnerable.exe" -Enable DEP, EmulateAtlThunks, BottomUp, HighEntropy, StrictHandle, Win32kSystemCallDisable

# Set via Group Policy:
# Computer Configuration > Administrative Templates > Windows Components >
# Windows Defender Exploit Guard > Exploit Protection

# Export settings to XML:
Get-ProcessMitigation -System | Export-Clixml mitigation_settings.xml

# Import settings from XML:
Set-ProcessMitigation -PolicyFilePath mitigation_settings.xml
```

### 8.3 ProcessMitigationOptions

Each process has a set of mitigation options that can be queried and configured:

```c
// Key process mitigation options (Windows 10+):
typedef struct _PROCESS_MITIGATION_OPTIONS {
    // DEP
    BOOLEAN EnableExportAddressFilter;          // EAF
    BOOLEAN EnableExportAddressFilterPlus;       // EAF+
    BOOLEAN EnableImportAddressFilter;           // IAF
    BOOLEAN EnableReturnFlowGuard;               // RFG
    BOOLEAN EnableBottomUpASLR;                  // Bottom-Up ASLR
    BOOLEAN EnableHighEntropyASLR;               // High-Entropy ASLR
    BOOLEAN EnableStrictHandleChecks;            // Strict handle validation
    BOOLEAN EnableWin32kSystemCallDisable;       // Disable Win32k syscalls
    
    // CFG
    BOOLEAN EnableControlFlowGuard;              // CFG
    BOOLEAN EnableCFGStrict;                     // Strict CFG (no relaxed mode)
    
    // ACG/CIG
    BOOLEAN EnableArbitraryCodeGuard;            // ACG (no dynamic code)
    BOOLEAN EnableCodeIntegrityGuard;            // CIG (signed DLLs only)
    
    // Additional
    BOOLEAN EnableFontDisable;                    // Disable non-system fonts
    BOOLEAN EnableImageLoadRemote;               // Log remote image loads
    BOOLEAN EnableImageLoadNoRemote;             // Block remote image loads
    BOOLEAN EnableImageLoadNoLowLabel;           // Block low-IL image loads
    BOOLEAN EnableImageLoadPreferSystem32;        // Prefer System32 DLLs
    BOOLEAN EnableHeapExtend;                    // Extended heap validation
    BOOLEAN EnableHeapTerminate;                 // Heap termination on corruption
    BOOLEAN EnableDisallowStrippedImages;         // Block unsigned images
} PROCESS_MITIGATION_OPTIONS;
```

---

## 9. VBS & HVCI (Virtualization-Based Security & Hypervisor-Enforced Code Integrity)

### 9.1 VBS Architecture

Virtualization-Based Security (VBS), detailed in `→ 01b_windows_security_architecture`, creates an isolated execution environment (VTL 1) using Hyper-V:

```
VBS-Enforced Mitigations:
┌─────────────────────────────────────────────────┐
│ VTL 1 (Secure World)                            │
│  ┌─────────────────────────────────────────┐    │
│  │ Hypervisor-Enforced Code Integrity      │    │
│  │ - All kernel code pages must be signed  │    │
│  │ - No RWX pages in kernel space          │    │
│  │ - Code pages cannot be made writable    │    │
│  │ - Data pages cannot be made executable  │    │
│  └─────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────┐    │
│  │ Secure Launch                           │    │
│  │ - Measured boot (TPM attestation)      │    │
│  │ - Boot chain verification              │    │
│  └─────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────┐    │
│  │ Credential Guard                        │    │
│  │ - LSASS secrets in VTL 1               │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
│ VTL 0 (Normal World)                            │
│  ┌─────────────────────────────────────────┐    │
│  │ Windows OS                              │    │
│  │ - ntoskrnl.exe, drivers, processes     │    │
│  │ - Standard security features           │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

### 9.2 HVCI Enforcement

HVCI enforces code integrity at the hypervisor level using Second Level Address Translation (SLAT):

```
Page Table Enforcement:
Normal (VTL 0):
  Code pages: RX (Read + Execute) → Verified signature, now W^X enforced
  Data pages: RW (Read + Write) → Cannot be made executable
  W^X enforcement: A page cannot be both writable and executable

  Virtual Address → VTL 0 Page Table → Physical Address (with VTL 0 permissions)
                       ↓ SLAT
                   VTL 1 Page Table → Physical Address (with VTL 1 permissions)

  VTL 1 adds:
  - Remove execute permission from writable pages
  - Remove write permission from executable pages
  - Prevent modification of page tables from VTL 0
  - Verify all kernel code signatures before marking pages executable
```

This means that even if an attacker gains kernel-mode code execution (e.g., through a driver vulnerability), they **cannot**:

1. **Allocate RWX pages**: `ExAllocatePoolWithTag(NonPagedPool, size, 'RWx0')` with `PAGE_EXECUTE_READWRITE` will be rejected
2. **Modify existing code pages**: Writing to `.text` sections is blocked
3. **Execute from data pages**: Setting `PAGE_EXECUTE` on heap/stack pages is blocked
4. **Load unsigned drivers**: Code signatures are verified before pages are marked executable

### 9.3 HVCI Exploitation Impact

| Technique | Without HVCI | With HVCI | Alternative |
|-----------|-------------|-----------|-------------|
| Shellcode in kernel | Works | Blocked | Data-only attack |
| ROP in kernel | Works | Blocked (CET) | Data-only attack |
| Driver loading | Works | Blocked (unsigned) | Use signed but vulnerable driver |
| Token swap (data-only) | Works | Works | Preferred approach |
| Function pointer overwrite | Works | Partially blocked | Limited to valid function addresses |
| Pool corruption → code exec | Works | Blocked | Data-only (modify EPROCESS fields) |

The net effect of HVCI is to force exploit developers from **code execution** attacks to **data-only** attacks. Data-only attacks modify kernel data structures (like EPROCESS.Token, ACLs, or process flags) without injecting code. This is a significant restriction, but data-only attacks remain viable.

---

## 10. CET (Control-Flow Enforcement Technology)

### 10.1 CET Architecture

Intel CET (Control-Flow Enforcement Technology) is a hardware-based mitigation implemented in 11th-generation Intel CPUs (Tiger Lake+). CET has two major components:

**Shadow Stack**: A second stack that mirrors the return address stack. On function call, the return address is pushed to both the regular stack and the shadow stack. On function return, the return address is compared between the two stacks:

```
Regular Stack:          Shadow Stack (CPU-managed):
┌──────────────┐      ┌──────────────┐
│ Local Var 1  │      │ Return Addr  │ ← Written by CALL instruction
│ Local Var 2  │      │ Return Addr2 │ ← Previous frame's return
│ Return Addr  │─────→│ Return Addr3 │ ← ...
┌──────────────┘      ┌──────────────┘
│ Saved RBP     │      │ (Shadow stack is in a read-only page)
│ Arg 1         │      │ (Write-protected except by CALL/RET)
│ Arg 2         │      │ (Located at a randomized address)
└──────────────┘      └──────────────┘
```

**Indirect Branch Tracking (IBT)**: A companion to CET that adds `ENDBR` instructions at valid indirect branch targets:

```asm
; Without IBT:
call rax   ; Can jump to ANY address in executable pages

; With IBT:
; All valid indirect branch targets must start with ENDBR64 (or ENDBR32):
valid_target:
    endbr64              ; Marker: this is a valid indirect branch target
    ; ... function body ...
    ret

; If an indirect branch lands on an address that doesn't start with ENDBR:
; → CPU raises #CP exception → OS terminates the process
```

### 10.2 CET on Windows

Windows 11 24H2+ enables CET with VBS enforcement:

```
CET + VBS Enforcement:
1. Shadow Stack: Managed by the CPU, stored in VTL 1 (not accessible from VTL 0)
2. IBT: ENDBR64 markers in all Windows DLLs and signed drivers
3. Kernel CET (kCET): Shadow stack and IBT for kernel-mode code
4. User CET (uCET): Shadow stack and IBT for user-mode code

CET validation on RET:
  1. CPU pops return address from regular stack (RSP)
  2. CPU pops return address from shadow stack (SSP)
  3. CPU compares: if regular_stack_ret != shadow_stack_ret → #CP exception
  4. If match → RET proceeds normally

CET validation on indirect CALL/JMP (with IBT):
  1. CPU lands at target address
  2. CPU checks: does target address start with ENDBR64?
  3. If no → #CP exception → process terminated
  4. If yes → execution continues
```

### 10.3 CET Bypass (Theoretical)

| Bypass Technique | Feasibility | Requirements |
|-----------------|-------------|--------------|
| **Shadow stack overwrite** | Hard | Requires kernel write to shadow stack pages (VTL 1) |
| **ENDBR gadget reuse** | Medium | Find an existing ENDBR64 that does something useful |
| **ROP via JOP** | Blocked | IBT prevents indirect jumps to non-ENDBR targets |
| **Exception-based ROP** | Hard | CET validates shadow stack during exception unwinding |
| **Longjmp-based** | Hard | CET-aware longjmp validates shadow stack |

The most promising CET bypass is **ENDBR gadget reuse** — finding existing `ENDBR64` instructions that, when jumped to, produce useful side effects. This is analogous to finding CFG-valid gadgets, but with much fewer available targets.

---

## 11. Bypass Taxonomy & Real CVE Examples

### 11.1 Mitigation Bypass Hierarchy

```
Mitigation Bypass Hierarchy (ordered by difficulty):
═══════════════════════════════════════════════════════
1. DEP bypass (ROP)                          [Easy - well-understood]
   │
   ├── 2. ASLR bypass (info leak)            [Medium - requires vulnerability]
   │      │
   │      ├── 3. CFG bypass (gadget abuse)   [Hard - limited gadget space]
   │      │      │
   │      │      ├── 4. ACG bypass (COM)    [Very Hard - code execution restricted]
   │      │      │      │
   │      │      │      ├── 5. HVCI bypass   [Extremely Hard - data-only only]
   │      │      │      │      │
   │      │      │      │      ├── 6. CET bypass  [Current Frontier]
   │      │      │      │      │
   │      │      │      │      └── XFG bypass    [Research Stage]
   │      │      │      │
   │      │      │      └── VBS + HVCI        [Near-Impossible without 0-day]
   │      │      │
   │      │      └── CIG bypass (signed DLL) [Hard - restricted to MS-signed]
   │      │
   │      └── SEHOP bypass (known address)   [Medium - needs ASLR bypass]
   │
   └── Stack cookies bypass (info leak)       [Medium - needs info leak]
═══════════════════════════════════════════════════════
```

### 11.2 Real CVE Mitigation Bypass Examples

**CVE-2020-0787: BITS Named Pipe Impersonation (UAC Bypass + Token Impersonation)**
- Bypassed: UAC integrity level
- Method: Used BITS service to create a named pipe, then impersonated the SYSTEM client connecting to the pipe
- SeImpersonatePrivilege used for token impersonation

**CVE-2020-1054: Win32k Elevation of Privilege (Win10 RS5)**
- Bypassed: KASLR, DEP, Pool ASLR
- Method: Win32k pool overflow corrupted adjacent GDI bitmap object; used bitmap r/w primitive for token swap (data-only)
- ASLR bypass via GDI handle leak

**CVE-2021-34527: PrintNightmare (RCE/EoP)**
- Bypassed: DEP, ASLR, CFG (code execution in Print Spooler service)
- Method: DLL loading via UNC path — loaded a malicious DLL as SYSTEM
- DEP and CFG were bypassed because the loaded DLL was properly signed/loaded, not shellcode

**CVE-2021-40444: MSHTML RCE (Internet Explorer/Edge)**
- Bypassed: ASLR (via info leak), DEP (via VirtualProtect ROP), CFG (via COM object abuse)
- Method: Weaponized Office document → MSHTML → COM object → CAB extraction → DLL sideloading
- CFG bypass: COM object instantiation used a valid vtable method

**CVE-2022-21882: Win32k EoP (Patch bypass for CVE-2021-1732)**
- Bypassed: Patch for CVE-2021-1732, KASLR, Win32k Pool Separation
- Method: Window class size confusion after callback; pool overflow into adjacent GDI object
- Pool Separation bypassed by targeting objects within the same Win32k pool

**CVE-2022-37969: CLFS EoP**
- Bypassed: KASLR, DEP, HVCI, Segment Heap
- Method: Data-only attack — CLFS UAF → EPROCESS.Token swap
- HVCI bypassed because no code execution was needed (data-only)

---

## 12. Future Mitigations

### 12.1 Upcoming Windows Security Features

| Feature | Expected | Description |
|---------|----------|-------------|
| **Strict XFG** | Windows 12+ | Type-based indirect branch validation |
| **Memory Safety (Rust)** | Gradual | Win32k and kernel drivers rewritten in Rust |
| **Hardware CFI** | Intel TGL+ | CET IBT enforcement in kernel mode |
| **Shadow Stack VTL 1** | Windows 12+ | Shadow stack managed by hypervisor |
| **Deterministic ASLR** | Research | Per-call-stack randomization |
| **Encrypted Page Tables** | Research | Page table entries encrypted with TPM key |

### 12.2 Exploitation Forecast

As mitigations increase, the exploitation landscape shifts:

```
Current Trends (2024-2026):
├── Data-only attacks dominate kernel exploitation
├── Token swapping is the primary LPE primitive
├── COM object abuse for CFG bypass in user mode
├── Driver exploitation (signed but vulnerable) for HVCI bypass
├── Firmware-level attacks for VBS bypass
└── Side-channel attacks for KASLR bypass

Future (2027+):
├── Rust Win32k reduces kernel attack surface
├── Hardware CFI (CET+IBT) eliminates ROP
├── Shadow stacks in VTL 1 eliminate return address overwrites
├── Full VBS enforcement makes data-only attacks harder
├── AI-powered exploit detection (Microsoft Security Copilot)
└── Quantum-resistant cryptography for credential protection
```

---

> **Cross-references**:
> - Win32k CVE analysis → `→ 02a_win32k_kernel_attack_surface`
> - NT kernel vulnerability patterns → `→ 02b_nt_kernel_vulnerabilities`
> - Pool corruption exploitation → `→ 03b_pool_corruption_exploitation`
> - Exploitation techniques (ROP, token swap) → `→ 04a_windows_exploitation_techniques`
> - Advanced kernel exploitation → `→ 04b_advanced_kernel_exploitation`
> - Linux mitigations comparison → `→ linux_kernel` track
> - CPU-level protections → `→ ring_and_vulns` track
> - OSEE mitigation questions → `→ OSEE` track

---

## References

1. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 1*, 7th Edition. Microsoft Press, 2017. — DEP, ASLR, and memory management security mechanisms.
2. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 2*, 7th Edition. Microsoft Press, 2021. — VBS, HVCI, and Kernel Stack Cookie internals.
3. Microsoft Learn. "Exploit Protection." <https://learn.microsoft.com/en-us/windows/security/threat-protection/>
4. Microsoft Learn. "Control Flow Guard (CFG)." <https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard>
5. Microsoft Security Response Center (MSRC) Blog. "Mitigations and Security Boundaries." <https://msrc.microsoft.com/blog/> — EMET deprecation, Exploit Protection, and HVCI enforcement.
6. MITRE ATT&CK. "Bypass DEP — T1210." <https://attack.mitre.org/techniques/T1210/> — ROP chains and DEP bypass techniques.
7. Yason, M. "Windows Heap Exploitation." *Black Hat USA*, 2019. — Heap hardening, segment heap mitigations, and LFH protections.
8. Morten, H. "Windows 10 Pool Overflow Exploitation." *Black Hat USA*, 2021. — Kernel pool hardening bypass, type isolation, and HVCI-aware exploitation.
9. McGarr, C. "Windows Exploit Mitigation Bypasses." *Connor McGarr's Blog*, 2023. — ASLR bypass, CFG bypass, and CET introspection.
10. National Vulnerability Database. CVE-2020-0784. "Windows OLE DEP Bypass." <https://nvd.nist.gov/vuln/detail/CVE-2020-0784>
11. National Vulnerability Database. CVE-2017-0038. "Windows ASLR Bypass (EMET)." <https://nvd.nist.gov/vuln/detail/CVE-2017-0038>
12. Piotrowski, P. "ASLR: Implementation and Analysis." *Phrack*, 2019. — x64 ASLR entropy analysis and information leak techniques.
13. Xia, J. "CET Shadow Stack on Windows." *Zero Day Initiative*, 2022. — Hardware-enforced shadow stacks and CET enforcement.
14. Microsoft. "EMET — Enhanced Mitigation Experience Toolkit." Archived documentation, 2017. — EMET configuration, deprecation path, and migration to Exploit Protection.
15. Dormann, W. "Analyzing Exploit Mitigation Effectiveness." *CERT/CC Vulnerability Analysis Blog*, 2021. — Real-world effectiveness of DEP, ASLR, CFG, and ACG.
16. DISA. "Windows 10 STIG — Exploit Protection Settings." <https://www.stigviewer.com/stigs/> — Mandatory DEP, bottom-up ASLR, and CFG enforcement baselines.