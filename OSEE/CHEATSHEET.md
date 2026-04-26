# OSEE / EXP-401 Cheat Sheet

## Certification Quick Facts

| Detail | Value |
|--------|-------|
| Full name | Offensive Security Exploitation Expert |
| Course | EXP-401 (formerly AWE — Advanced Windows Exploitation) |
| Exam duration | 72 hours (3 days), proctored |
| Format | Practical — develop working exploits against hardened targets |
| Prerequisite cert | OSFE or equivalent experience recommended |
| Pass criteria | Working exploit demonstrating control over hardened target |
| Delivery | Live training (formerly Black Hat USA only, now broader) |

## Windows Kernel Exploitation — Key Structures

| Structure | Size (x64) | Exploitation Relevance |
|-----------|-----------|----------------------|
| `_EPROCESS` | ~2KB | Process token manipulation, ACL bypass |
| `_ETHREAD` | ~0x800 | Thread hijacking, APC injection |
| `_OBJECT_HEADER` | ~0x30 | Type confusion, object sprays |
| `_TOKEN` | ~0x40 | Privilege escalation via token replacement |
| `_KPROCESS` | ~0x2F0 | Kernel process manipulation |
| `_HEAP` / `_HEAP_ENTRY` | varies | Pool corruption, heap feng shui |
| `_MDL` | 0x30 | Arbitrary read/write via MDL manipulation |
| `_CM_CALLBACK_ENTRY` | varies | Registry callback object corruption |

## Exploitation Primitives (Windows)

| Primitive | Technique | Mitigations Bypassed |
|-----------|-----------|---------------------|
| Pool corruption | Overflow into adjacent object | Pool validation (partial) |
| UAF → Object Reuse | Free + reallocate with controlled object | None directly |
| Type Confusion | Swap vtable pointer to fake object | CFG (requires additional bypass) |
| Integer Overflow → Heap Overflow | Size miscalc → overflow | DEP (no impact on heap) |
| Race Condition | Double-fetch / TOCTOU | Varies |
| Stack Overflow → ROP | Pivot + ROP chain | DEP |
| Token Replacement | Overwrite `_TOKEN` privileges | None (inherent kernel prim) |
| Arbitrary Write →码 Overwrite | Write to `_EPROCESS.Token` | None (if write prim exists) |

## Key WinDbg Commands

```
!process 0 0                List all processes
!process 0 7 <name>         Detailed process info
!thread                     Current thread info
!object <addr>              Object info
dt nt!_EPROCESS <addr>      Dump EPROCESS structure
dt nt!_TOKEN <addr>         Dump TOKEN structure
.pool /v                    Pool allocation info
!poolfind <tag>             Find pool allocations by tag
!verifier                   Driver verifier status
.breakin                    Break into target (kernel debugger)
ed <addr> <value>           Write dword (exploit primitive)
!handle <addr>              Handle table info
!irp <addr>                 IRP info
k                           Stack trace
!exploitable                Assess crash exploitability
```

## Mitigation Bypass Techniques

| Mitigation | Introduced | Bypass Approaches |
|------------|-----------|------------------|
| DEP (NX) | XP SP2 | ROP chains, ret2libc, JIT spraying |
| ASLR | Vista | Information leak, partial overwrite, JIT spray |
| CFG | Win8.1+ | Fake dispatch, indirect call abuse, JIT mitigation |
| ACG | Win10 RS1 | Code reuse from legit modules, legitimate JIT abuse |
| CIG | Win10 RS1 | Local process injection, extendexisting code |
| Stack Cookie | MSVC /GS | Information leak, exception handler overwrite |
| SEHOP | Vista | Information leak, structured exception handling abuse |
| Heap Validation | Win10 | Pool corruption alternative primitives |
| VBS/HVCI | Win10 RS3 | BootKit, EFI runtime exploitation |
| Kernel CET | Win10 21H2 | ROP alternatives (JOP, data-only) |

## EXP-401 Course Modules (High-Level)

1. **Advanced Stack Exploitation** — modern ROP,-stack pivoting, DEP bypass
2. **Heap Exploitation** — pool feng shui, pool corruption, pool overflow
3. **Kernel Exploitation** — Win driver attack surfaces, elevating to Ring 0
4. **Mitigation Bypass** — CFG, ACG, VBS/HVCI bypass techniques
5. **Reverse Engineering** — IDA/Ghidra-driven vuln discovery
6. **Shellcode Development** — position-independent code for constrained environments

## OSEE Exam Strategy

| Phase | Time | Goal |
|-------|------|------|
| Recon & Setup | 0–4h | Understand targets, configure VMs, identify low-hanging fruit |
| First Exploit | 4–16h | Get a working exploit against the easiest target |
| Second Exploit | 16–36h | Tackle harder targets, apply lessons from #1 |
| Third Exploit | 36–56h | Most challenging target |
| Hardening & Documentation | 56–72h | Verify stability, document all exploits, prepare report |

## Common Win32 API for Exploitation

```c
// Debugging
DebugActiveProcess(pid)           // Attach debugger
CreateProcess(..., DEBUG_ONLY, …) // Create under debug

// Memory
VirtualAlloc()                    // Allocate RWX pages
VirtualProtect()                   // Change page permissions
NtAllocateVirtualMemory()         // Native allocation

// Synchronization (for races)
CreateEvent() / SetEvent()        // Race condition triggers
CreateMutex()                     // Synchronization primitives

// Process/Thread
CreateRemoteThread()              // Thread injection
NtCreateThreadEx()                // Native thread creation
WriteProcessMemory()              // Memory writing
```

## Quick Reference: OffSec Certification Hierarchy

```
OSCP ──→ OSEP ──→ OSED ──→ OSEE
  │        │        │         │
  │        │        │         └── EXP-401: Advanced Windows Exploitation
  │        │        └─────────── EXP-301: Windows User-Mode Exploit Development
  │        └──────────────────── PEN-300: Advanced Evasion & Breaching
  └───────────────────────────── PEN-200: Foundations of Penetration Testing
```