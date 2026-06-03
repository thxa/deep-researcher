# Dynamic Analysis Techniques & Debugging

> Comprehensive reference on dynamic analysis methodologies, debuggers, hooking, tracing, and anti-debugging bypass for reverse engineering.

---

## Table of Contents

1. [Dynamic Analysis Overview](#1-dynamic-analysis-overview)
2. [Debuggers: GDB, WinDBG, x64dbg, LLDB](#2-debuggers-gdb-windbg-x64dbg-lldb)
3. [Breakpoint Types](#3-breakpoint-types)
4. [Watchpoints and Memory Access Breakpoints](#4-watchpoints-and-memory-access-breakpoints)
5. [Trace-Based Analysis](#5-trace-based-analysis)
6. [Call Tracing](#6-call-tracing)
7. [Coverage-Guided Dynamic Analysis](#7-coverage-guided-dynamic-analysis)
8. [API Monitoring](#8-api-monitoring)
9. [Hooking Techniques](#9-hooking-techniques)
10. [Memory Forensics During Debugging](#10-memory-forensics-during-debugging)
11. [Anti-Debugging Detection and Bypass](#11-anti-debugging-detection-and-bypass)

---

## 1. Dynamic Analysis Overview

Dynamic analysis observes program behavior during execution. Unlike static analysis, which examines all possible paths, dynamic analysis reveals the actual execution path taken, runtime values, and real system interactions.

```
Dynamic Analysis Stack:
┌──────────────────────────────┐
│     Hooking & Instrumentation │  ← Frida, Detours, PIN
├──────────────────────────────┤
│     API Monitoring            │  ← API Monitor, Procmon
├──────────────────────────────┤
│     Debugging                 │  ← GDB, WinDBG, x64dbg, LLDB
├──────────────────────────────┤
│     System Call Tracing       │  ← strace, ltrace, Procmon
├──────────────────────────────┤
│     Network Monitoring        │  ← Wireshark, mitmproxy
├──────────────────────────────┤
│     Sandbox Execution         │  ← Cuckoo, CAPE, ANY.RUN
└──────────────────────────────┘
```

**When to use dynamic analysis**:

- Static analysis is insufficient (obfuscated/packed binary)
- You need to observe specific runtime values (crypto keys, decrypted data)
- You need to understand network protocols (actual request/response)
- You need to identify the exact code path for a specific input
- Anti-analysis techniques block static analysis

---

## 2. Debuggers: GDB, WinDBG, x64dbg, LLDB

### 2.1 GDB (GNU Debugger)

GDB is the primary debugger on Linux and is essential for kernel and userspace RE:

```bash
# Starting GDB
gdb ./target                          # Debug local binary
gdb -p <PID>                          # Attach to running process
gdb ./target core                     # Analyze core dump
gdb ./target -x commands.gdb          # Execute command file on startup

# Essential GDB commands
(gdb) info files                      # Show target file info
(gdb) info sharedlibrary              # Show loaded shared libraries
(gdb) info functions                  # List functions (if symbols exist)
(gdb) info variables                  # List global/static variables

# Execution control
(gdb) run                             # Start execution
(gdb) run < input.txt                 # Run with input file
(gdb) run $(python -c 'print("A"*100)')  # Run with crafted input
(gdb) continue                        # Continue execution
(gdb) step                            # Step into function
(gdb) next                            # Step over function
(gdb) finish                          # Run until current function returns
(gdb) stepi                           # Step one machine instruction (into)
(gdb) nexti                           # Step one machine instruction (over)
(gdb) until 0x401234                  # Run until address reached

# Breakpoints
(gdb) break main                      # Break at function name
(gdb) break *0x401234                  # Break at address
(gdb) break file.c:42                 # Break at source line
(gdb) break *0x401234 if $rax == 5    # Conditional breakpoint
(gdb) tbreak main                     # Temporary breakpoint (one-shot)
(gdb) hbreak *0x401234                # Hardware breakpoint
(gdb) info breakpoints                # List breakpoints
(gdb) delete 1                        # Delete breakpoint #1
(gdb) disable 2                       # Disable breakpoint #2
(gdb) enable 2                        # Re-enable breakpoint #2
(gdb) condition 1 $rdi == 0x41414141 # Add condition to existing bp

# Watchpoints (data breakpoints)
(gdb) watch global_var                # Break when variable is written
(gdb) rwatch global_var               # Break when variable is read
(gdb) awatch global_var               # Break when variable is read/written
(gdb) watch *(int*)0x7fffffff1234    # Watch specific memory address

# Examination
(gdb) x/10x $rsp                     # Examine 10 hex values at stack pointer
(gdb) x/20i $rip                     # Examine 20 instructions at IP
(gdb) x/s 0x401234                   # Examine as string
(gdb) x/10x 0x401234                 # Examine 10 hex values at address
(gdb) print $rax                      # Print register value
(gdb) print/x $rax                    # Print in hex
(gdb) print *(struct_name*)0x12345678 # Print struct at address
(gdb) print/x *(long*)($rsp+8)       # Print value at stack+8

# Register manipulation
(gdb) info registers                  # Show all registers
(gdb) set $rax = 0x41414141          # Set register value
(gdb) set $rip = 0x401234             # Change instruction pointer
(gdb) set $eflags = $eflags & ~0x100 # Clear TF (trap flag)

# Memory manipulation
(gdb) set {long}0x401234 = 0xDEAD     # Write to memory
(gdb) set *(char*)$rsp = 'A'          # Write byte to stack

# Call functions during debugging
(gdb) call (int)puts("test")          # Call function in target
(gdb) call (void*)malloc(100)         # Allocate memory
```

**GDB Python scripting** (powerful automation):

```python
# Save as gdb_script.py, run with: gdb -x gdb_script.py
import gdb

class DumpDecryptedMemory(gdb.Command):
    """Dump memory region after decryption breakpoint.
    Usage: dump_decrypted <start_addr> <size> <filename>
    """
    def __init__(self):
        super().__init__("dump_decrypted", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        args = gdb.parse_and_eval(arg)
        start = int(args[0])
        size = int(args[1])
        filename = str(args[2])
        
        inferior = gdb.selected_inferior()
        mem = inferior.read_memory(start, size)
        
        with open(filename, 'wb') as f:
            f.write(bytes(mem))
        print(f"Dumped {size} bytes from 0x{start:x} to {filename}")

DumpDecryptedMemory()

class BreakOnCryptoCall(gdb.Command):
    """Set breakpoints on common crypto functions."""
    def __init__(self):
        super().__init__("break_crypto", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        crypto_funcs = [
            'AES_set_encrypt_key', 'AES_encrypt', 'AES_decrypt',
            'EVP_EncryptInit_ex', 'EVP_EncryptUpdate', 'EVP_EncryptFinal_ex',
            'EVP_DecryptInit_ex', 'EVP_DecryptUpdate', 'EVP_DecryptFinal_ex',
            'MD5_Init', 'MD5_Update', 'MD5_Final',
            'SHA1_Init', 'SHA256_Init', 'SHA512_Init',
            'RSA_public_encrypt', 'RSA_private_decrypt',
        ]
        for func in crypto_funcs:
            try:
                gdb.execute(f"break {func}")
                print(f"  Breakpoint set: {func}")
            except gdb.error:
                pass  # Function not found in this binary

BreakOnCryptoCall()

# Auto-execute: set breakpoint on decryption, dump when hit
class AutoDumpBreakpoint(gdb.Breakpoint):
    def __init__(self, spec, dump_addr_reg, dump_size_reg, filename):
        super().__init__(spec)
        self.dump_addr_reg = dump_addr_reg
        self.dump_size_reg = dump_size_reg
        self.filename = filename
    
    def stop(self):
        addr = int(gdb.parse_and_eval(f"${self.dump_addr_reg}"))
        size = int(gdb.parse_and_eval(f"${self.dump_size_reg}"))
        
        inferior = gdb.selected_inferior()
        mem = inferior.read_memory(addr, size)
        
        with open(self.filename, 'wb') as f:
            f.write(bytes(mem))
        print(f"Auto-dumped {size} bytes from 0x{addr:x} to {self.filename}")
        return False  # Continue execution

# Usage: auto-dump after decryption completes
# bp = AutoDumpBreakpoint("AES_decrypt", "rdi", "rsi", "decrypted.bin")
```

### 2.2 GDB Enhanced Features (GEF/pwndbg)

```bash
# GEF (GDB Enhanced Features) — recommended for RE
# Install:
pip install gef
# Or:
wget -qO- https://github.com/hugsy/gef/raw/main/scripts/gef.sh | sh

# Key GEF commands:
gef➤  hexdump $rsp 0x40              # Hex dump at stack pointer
gef➤  telescope $rsp 20              # Dereference chain from stack
gef➤  pattern create 200            # Create cyclic pattern
gef➤  pattern offset $rip            # Find pattern offset
gef➤  checksec                       # Check security features
gef➤  vmmap                          # Memory map
gef➤  proc-info                      # Process information
gef➤  assemble                       # Inline assembly

# pwndbg — alternative GDB enhancement
# Install:
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Key pwndbg commands:
pwndbg> context                       # Show registers, stack, disassembly
pwndbg> nearpc 10                     # Disassemble near PC
pwndbg> stack 20                      # Show stack contents
pwndbg> checksec                      # Binary security features
```

### 2.3 WinDBG

WinDBG is the primary debugger for Windows kernel and user-mode debugging:

```
# Starting WinDBG
windbg target.exe                    # Local user-mode debugging
windbg -p <PID>                     # Attach to process
windbg -I target.exe                # Post-mortem debugging (set as default)
windbg -k net:port=50000,key=1.2.3.4  # Kernel debugging over network
windbg -b -k com:port=\\.\pipe\com_1,baud=115200,pipe  # Kernel debugging via pipe

# Essential commands
!peb                                # Process Environment Block
!teb                                # Thread Environment Block
!process 0 0                        # List all processes (kernel mode)
!process 0 7 target.exe             # Find target process (kernel mode)
!thread                             # Current thread info
lm                                  # List loaded modules
lm v m target                       # Verbose module info
!dh target                          # Dump PE headers
!address                            # Memory map summary
!address 0x401000                   # Address info
Vertarget                           # Target OS version

# Breakpoints
bp kernel32!CreateFileW             # Break on API call
bp 0x401234                         # Break at address
bu target!main                      # Break at module!function (unresolved)
bm target!Crypt*                    # Break on pattern match
ba w4 0x403000                      # Hardware breakpoint: write 4 bytes
ba e1 0x401234                      # Hardware breakpoint: execute 1 byte

# Conditional breakpoints
bp 0x401234 ".if (@rax == 0n5) {} .else {gc}"
# Break only when RAX == 5

# Examination
dq rsp L20                           # Dump 20 qwords at stack
dd esp L20                           # Dump 20 dwords at stack
du @rdi                              # Dump Unicode string at RDI
da @rdi                              # Dump ASCII string at RDI
u . L20                              # Disassemble 20 instructions from current IP
ub . L20                             # Disassemble backwards
dt nt!_EPROCESS                      # Display EPROCESS type
dt nt!_EPROCESS -y ImageFileName @rax  # Display specific field

# Memory
!heap -s                             # Heap summary
!heap -stat -h <heap_addr>           # Heap statistics
!address -summary                    # Memory ranges summary
.writemem d:\dump.bin 0x401000 L1000  # Write memory to file

# Scripting WinDBG
$$ Script example: log all CreateFileW calls
bp kernel32!CreateFileW ".printf \"%mu\\n\", @rcx; .printf \"Return: %p\\n\", @ra; gc"
```

### 2.4 x64dbg

x64dbg is the open-source successor to OllyDbg for Windows user-mode debugging:

```
# x64dbg Features
# - GUI-based debugging
# - Plugin support (ScyllaHide for anti-anti-debug)
# - Scripting support (x64dbg scripting)
# - Trace recording and playback

# Key shortcuts
F2        — Toggle breakpoint
F7        — Step into
F8        — Step over
F9        — Run
Ctrl+F9   — Run until return
Ctrl+G    — Go to address
Ctrl+B    — Search for pattern
Ctrl+F    — Search for command

# Commands
bp CreateFileW                    — Break on API
bph 0x401234,x                   — Hardware execute breakpoint
bpm 0x403000,w,4                 — Memory write breakpoint
SetCondition bp0, "rax==0x5"     — Conditional breakpoint
log "RAX={rax}"                  — Log register value

# Scripting (x64dbg scripting language)
// Auto-dump after WriteFile
bp kernel32!WriteFile
SetBreakpointCondition kernel32!WriteFile, 0
SetBreakpointLog kernel32!WriteFile, "WriteFile(hFile={arg1}, lpBuffer={arg2}, nNumberOfBytesToWrite={arg3})"
SetBreakpointCommand kernel32!WriteFile, "savedata C:\\dumps\\writefile_{arg1}.bin, {arg2}, {arg3}"
```

### 2.5 LLDB

LLDB is the debugger for macOS and LLVM-based environments:

```bash
# Starting LLDB
lldb ./target                      # Debug local binary
lldb -p <PID>                      # Attach to process
lldb -c core target                 # Analyze core dump
lldb -- remote deported.sock        # Remote debugging

# Execution control
(lldb) run                          # Start execution
(lldb) run < input.txt              # Run with input
(lldb) continue                     # Continue
(lldb) step                         # Step into
(lldb) next                         # Step over
(lldb) finish                       # Step out
(lldb) si                           # Step instruction
(lldb) ni                           # Next instruction

# Breakpoints
(lldb) b main                       # Break at function
(lldb) b 0x401234                   # Break at address
(lldb) b file.c:42                  # Break at source line
(lldb) b -r "Crypto.*"              # Regex breakpoint
(lldb) b -f target.c -l 42 -c 'i == 5'  # Conditional

# ARM64-specific (iOS/macOS)
(lldb) p/x $x0                     # Print x0 in hex
(lldb) dis -c 20                    # Disassemble 20 instructions
(lldb) register read                # Read all registers
(lldb) register write x0 0x41414141 # Write register

# Swift-aware debugging
(lldb) frame variable              # Show local variables (Swift)
(lldb) po someSwiftObject           # Print Swift object description
(lldb) image lookup -r -n ".*Crypto.*"  # Find Swift symbols by regex
```

---

## 3. Breakpoint Types

### 3.1 Software Breakpoints

Software breakpoints work by replacing the instruction at the target address with an interrupt instruction:

```
x86/x64:  INT3 (0xCC) — 1-byte interrupt
ARM/ARM64: BRK #0 (0xD4200000) or UDF #0 (0xD7A00000)
MIPS:      BREAK (0x0007000D) or TNE $zero, $zero, 0x1

Mechanism:
  1. Debugger saves original byte at target address
  2. Debugger writes breakpoint instruction (0xCC for x86)
  3. When CPU executes the breakpoint, INT3 fires
  4. OS delivers SIGTRAP (or EXCEPTION_BREAKPOINT on Windows)
  5. Debugger catches signal, restores original byte
  6. Debugger reports breakpoint hit to user
```

Detection of software breakpoints:

```python
# Anti-debugging: detect software breakpoints by checking for 0xCC bytes
def check_software_breakpoints(debugger_pid, target_pid):
    """Check if software breakpoints are set in target process."""
    import ctypes
    
    # Read process memory
    kernel32 = ctypes.windll.kernel32
    
    PROCESS_ALL_ACCESS = 0x1F0FFF
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
    
    # Scan .text section for 0xCC (INT3) bytes
    # In practice, this requires knowing the .text section bounds
    # and checking for INT3 at code locations
    
    kernel32.CloseHandle(h_process)

# x86 assembly to detect INT3:
# check_for_int3:
#     mov eax, target_address
#     cmp byte [eax], 0xCC    ; Compare with INT3 opcode
#     je debugger_detected     ; If equal, debugger is present
#     ; If not equal, not a software breakpoint at this address
```

### 3.2 Hardware Breakpoints

Hardware breakpoints use CPU debug registers (x86/x64) and don't modify code:

```
x86/x64 Debug Registers:
  DR0 — Address of breakpoint #1
  DR1 — Address of breakpoint #2
  DR2 — Address of breakpoint #3
  DR3 — Address of breakpoint #4
  DR4 — Reserved (was DR6, now obsolete)
  DR5 — Reserved (was DR7, now obsolete)
  DR6 — Debug Status Register (which breakpoint triggered)
  DR7 — Debug Control Register (enable/conditions for DR0-DR3)

DR7 bit layout:
  Bits 0,2,4,6 — Local enable for DR0-DR3 (cleared on task switch)
  Bits 1,3,5,7 — Global enable for DR0-DR3 (NOT cleared on task switch)
  Bits 16-17 — Condition for DR0: 00=execute, 01=write, 11=read/write
  Bits 18-19 — Length for DR0: 00=1byte, 01=2byte, 11=4byte (10=8byte for x64)
  ... (same pattern for DR1, DR2, DR3)

Limitations:
  - Only 4 hardware breakpoints simultaneously
  - No 8-byte write breakpoints on x86 (can do on x64)
  - Can detect hardware breakpoints by reading DR6/DR7
```

Setting hardware breakpoints in GDB:

```bash
# GDB hardware breakpoints
(gdb) hbreak *0x401234         # Hardware execute breakpoint
(gdb) rwatch 0x403000          # Hardware read breakpoint
(gdb) watch 0x403000           # Hardware write breakpoint
(gdb) awatch 0x403000          # Hardware access (read/write) breakpoint

# Show hardware breakpoint status
(gdb) info breakpoints
```

### 3.3 Conditional Breakpoints

Conditional breakpoints stop execution only when a specified condition is true:

```bash
# GDB conditional breakpoints
(gdb) break *0x401234 if $rax == 0x41414141
(gdb) break main if argc > 1
(gdb) break process_request if strcmp(request->type, "EXEC") == 0

# Complex GDB conditions
(gdb) break *0x401234 if (*(int*)($rsp+0x10)) == 5
(gdb) break *0x401500 if $rsi != 0 && ((char*)$rsi)[0] == 'A'

# Logging breakpoints (don't stop, just log)
(gdb) break *0x401234 if 1
(gdb) commands 1
> printf "Called with rdi=%p rsi=%p\n", $rdi, $rsi
> continue
> end

# WinDBG conditional breakpoints
bp 0x401234 ".if (@rax == 0n5) {} .else {gc}"
bp kernel32!WriteFile ".printf \"%mu\\n\", @rcx; gc"

# x64dbg conditional breakpoints
SetBreakpointCondition 0x401234, "rax == 0x41414141"
```

### 3.4 Memory Access Breakpoints

Memory breakpoints monitor read/write access to specific memory regions:

```bash
# GDB watchpoints
(gdb) watch global_buffer         # Break when global_buffer is written
(gdb) rwatch global_buffer        # Break when global_buffer is read
(gdb) awatch global_buffer        # Break on read OR write

# Watch specific memory address
(gdb) watch *(char*)0x403000      # Watch 1 byte
(gdb) watch *(short*)0x403000     # Watch 2 bytes
(gdb) watch *(int*)0x403000       # Watch 4 bytes

# Conditional watchpoints
(gdb) watch global_counter if global_counter > 100

# Set memory breakpoint on entire region (GDB)
# This uses hardware breakpoints, so limited to 4 simultaneous
(gdb) hbreak *0x401000
(gdb) watch *(int*)0x401000
```

---

## 4. Watchpoints and Memory Access Breakpoints

### 4.1 Advanced Watchpoint Usage

```python
# GDB Python: Set watchpoints on all entries of an array
import gdb

def watch_array(base_addr, element_size, count):
    """Set watchpoints on each element of an array."""
    for i in range(count):
        addr = base_addr + i * element_size
        if element_size == 1:
            gdb.execute(f"watch *(char*){addr}")
        elif element_size == 4:
            gdb.execute(f"watch *(int*){addr}")
        elif element_size == 8:
            gdb.execute(f"watch *(long*){addr}")

# Example: Watch all entries of a vtable
# vtable_array(0x403000, 8, 20)

# Track malloc/free by watching heap management structures
def track_heap_allocations():
    """Set breakpoints on malloc/free to trace allocations."""
    gdb.execute("break malloc")
    gdb.execute("break free")
    gdb.execute("break calloc")
    gdb.execute("break realloc")
    
    # Log allocation sizes and pointers
    gdb.execute('break malloc')
    gdb.execute('commands')
    gdb.execute('printf "malloc(%p) = ", $rdi')  # Size argument
    gdb.execute('finish')
    gdb.execute('printf "%p\\n", $rax')  # Return value
    gdb.execute('continue')
    gdb.execute('end')
```

### 4.2 Memory Breakpoint Bypass Techniques

Some anti-debugging techniques check for hardware breakpoints by reading DR registers. Bypass methods:

```python
# Approach 1: ScyllaHide plugin (x64dbg) — patches anti-debug checks
# Automatically hooks: IsDebuggerPresent, NtQueryInformationProcess, etc.

# Approach 2: Manual DR register manipulation
# Before the check:
(gdb) set $dr7 = 0     # Disable all hardware breakpoints
# ... anti-debug check runs ...
(gdb) set $dr7 = 0x55  # Re-enable breakpoints (DR0 local, DR1 local, etc.)

# Approach 3: Use PAGE_GUARD instead of hardware breakpoints
# Set the PAGE_GUARD flag on the memory page, then handle the exception
# This doesn't use debug registers

import ctypes

def set_page_guard(process_handle, address):
    """Set PAGE_GUARD on a memory page as an alternative to watchpoints."""
    kernel32 = ctypes.windll.kernel32
    old_protect = ctypes.c_ulong()
    
    # Get page-aligned address
    page_address = address & ~0xFFF  # 4KB alignment
    
    success = kernel32.VirtualProtectEx(
        process_handle,
        page_address,
        0x1000,
        0x100,  # PAGE_GUARD
        ctypes.byref(old_protect)
    )
    return success, old_protect.value
```

---

## 5. Trace-Based Analysis

### 5.1 System Call Tracing (strace)

```bash
# Basic system call tracing
strace ./target                      # Trace all syscalls
strace -f ./target                   # Follow forks
strace -ff -o trace.log ./target     # Separate log per child process
strace -p <PID>                      # Attach to running process

# Filter specific syscalls
strace -e trace=network ./target     # Trace network syscalls only
strace -e trace=file ./target        # Trace file operations only
strace -e trace=process ./target     # Trace process operations only
strace -e trace=signal ./target      # Trace signals only
strace -e open,openat,read,write ./target  # Specific syscalls

# Network tracing
strace -e trace=socket,connect,bind,listen,accept,sendto,recvfrom ./target

# File descriptor tracing
strace -e trace=read,write -e abbrev=none ./target  # Full read/write data

# Timing information
strace -T ./target                   # Show time spent in each syscall
strace -tt ./target                  # Show timestamps with microseconds

# Output formatting
strace -x ./target                   # Print strings in hex
strace -s 1024 ./target              # Print up to 1024 bytes per string
strace -v ./target                   # Don't abbreviate structures

# Common RE patterns
# Find where a specific file is accessed:
strace -e trace=open,openat -f ./target 2>&1 | grep "config"

# Find network connections:
strace -e trace=socket,connect -f ./target 2>&1 | grep "sin_addr"

# Find memory allocation patterns:
strace -e trace=mmap,munmap,brk,malloc,free -f ./target
```

### 5.2 Library Call Tracing (ltrace)

```bash
# Basic library call tracing
ltrace ./target                      # Trace all library calls
ltrace -f ./target                   # Follow forks
ltrace -p <PID>                      # Attach to process

# Filter specific calls
ltrace -e malloc+free+realloc ./target     # Trace memory functions
ltrace -e fopen+fread+fwrite+fclose ./target  # Trace file I/O
ltrace -e SSL_read+SSL_write+SSL_connect ./target  # Trace SSL calls

# Output formatting
ltrace -S ./target                   # Include syscalls (like strace)
ltrace -c ./target                   # Call statistics
ltrace -n 2 ./target                 # Indent nested calls
ltrace -s 256 ./target               # Print up to 256 chars per string

# Example: trace crypto function parameters
ltrace -e AES_*+EVP_* -s 256 ./target
```

### 5.3 Process Monitor (Windows)

```bash
# Process Monitor (Procmon) — comprehensive Windows event monitor
# Monitors: file system, registry, process/thread, network

# Key filters for RE:
# 1. Filter by process name
Process Name is target.exe

# 2. Filter by operation
Operation is CreateFile
Operation is RegSetValue
Operation is TCP Connect
Operation is TCP Send

# 3. Filter by path
Path contains \Device\
Path contains SOFTWARE\
Path starts with HKEY_LOCAL_MACHINE\SOFTWARE\

# 4. Save configuration for offline analysis
# File → Save → Export to PML file

# Command-line Procmon alternative: procmon64.exe /AcceptEula /Minimized /Quiet
# No UI, logs to default PML file

# Sysmon — System Monitor (more stealthy than Procmon)
# Install: sysmon -i -accepteula
# Config: sysmon -c config.xml

# Key Sysmon event IDs:
# 1 — Process Create
# 3 — Network Connection
# 5 — Process Terminate
# 6 — Driver Loaded
# 7 — Image Loaded (DLL)
# 8 — CreateRemoteThread
# 9 — RawAccessRead
# 10 — ProcessAccess
# 11 — FileCreate
# 12 — RegistryAddOrDelete
# 13 — RegistrySet
# 17 — PipeEvent
# 25 — Process Tampering
```

---

## 6. Call Tracing

### 6.1 Function Call Tracing with PIN

Intel PIN is a dynamic binary instrumentation framework for comprehensive call tracing:

```cpp
// PIN tool: trace_calls.cpp
// Compile: pin -t obj-intel64/trace_calls.so -- ./target

#include "pin.H"
#include <fstream>
#include <iostream>

ofstream TraceFile;

// Analysis function called before every call
VOID RecordCall(ADDRINT target, ADDRINT from) {
    TraceFile << "CALL  0x" << hex << from << " → 0x" << target << dec << endl;
}

// Analysis function called before every return
VOID RecordReturn(ADDRINT target, ADDRINT from) {
    TraceFile << "RET   0x" << hex << from << " → 0x" << target << dec << endl;
}

// Instrumentation function called for each instruction
VOID Instruction(INS ins, VOID *v) {
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, BEFORE, AFUNPTR(RecordCall),
                       IARG_ADDRINT, INS_Category(ins) == XED_CATEGORY_CALL_NEAR 
                                     ? INS_OperandMemoryBaseReg(ins, 0) : INS_OperandReg(ins, 0),
                       IARG_ADDRINT, INS_Address(ins),
                       IARG_END);
    }
    
    if (INS_IsRet(ins)) {
        INS_InsertCall(ins, BEFORE, AFUNPTR(RecordReturn),
                       IARG_ADDRINT, INS_Address(ins),
                       IARG_END);
    }
}

// Fini function called when target exits
VOID Fini(INT32 code, VOID *v) {
    TraceFile.close();
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    
    if (PIN_Init(argc, argv)) {
        cerr << "Usage: pin -t trace_calls.so -- ./target" << endl;
        return -1;
    }
    
    TraceFile.open("call_trace.txt");
    
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    return 0;
}
```

### 6.2 Lightweight Call Tracing with gdb

```python
# GDB Python script for call tracing
import gdb

class CallTracer:
    def __init__(self):
        self.call_stack = []
        self.trace_file = open("call_trace.log", "w")
    
    def trace_function(self, func_name):
        """Set a breakpoint that logs entry/exit of a function."""
        gdb.execute(f"break {func_name}")
        
        # Log entry
        gdb.execute(f"commands {func_name}")
        gdb.execute(f'  printf "ENTER {func_name}("')
        # Log arguments based on calling convention
        gdb.execute(f'  printf ")\\n"')
        gdb.execute(f'  continue')
        gdb.execute(f'end')
    
    def trace_all_imports(self):
        """Set breakpoints on all imported functions."""
        # List all imported functions and set breakpoints
        result = gdb.execute("info functions", to_string=True)
        for line in result.splitlines():
            if "import" in line.lower():
                parts = line.split()
                if parts:
                    self.trace_function(parts[-1])

tracer = CallTracer()
# tracer.trace_all_imports()
```

---

## 7. Coverage-Guided Dynamic Analysis

### 7.1 Code Coverage Measurement

```bash
# LLVM SanitizerCoverage — compile-time instrumentation
# Compile with coverage:
clang -fsanitize=coverage=trace-pc-guard,edge-coverage=1 target.c -o target_cov

# Run the binary; coverage data is written to a file
./target_cov

# Process coverage data with llvm-cov
llvm-cov report target_cov -instr-profile=coverage.profdata

# AFL — American Fuzzy Lop (coverage-guided fuzzing)
# Compile target with AFL instrumentation:
afl-gcc -o target_afl target.c
# Or for source-available targets:
afl-clang-fast -o target_afl target.c

# Create seed corpus
mkdir -p seeds
echo "sample_input" > seeds/seed1.txt

# Run AFL
afl-fuzz -i seeds -o output -m 500 -- ./target_afl @@

# Analyze coverage
afl-showmap -o coverage.map -- ./target_afl < input.txt
```

### 7.2 Dynamic Binary Instrumentation Coverage

```python
# Frida-based coverage collection
import frida
import json

COVERAGE_SCRIPT = """
var coverage = {};

Interceptor.attach(Module.findExportByName(null, 'target_function'), {
    onEnter: function(args) {
        // Record which basic blocks are hit
        var pc = this.context.pc;
        if (!coverage[pc]) {
            coverage[pc] = 0;
        }
        coverage[pc]++;
        send({type: 'coverage', address: pc.toString(), count: coverage[pc]});
    }
});

// Hook multiple functions for broader coverage
var functions_to_hook = [
    'malloc', 'free', 'open', 'read', 'write', 'close',
    'socket', 'connect', 'send', 'recv'
];

functions_to_hook.forEach(function(fname) {
    var addr = Module.findExportByName(null, fname);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                send({type: 'api_call', function: fname, args: [
                    args[0].toString(),
                    args[1].toString(),
                    args[2].toString()
                ]});
            }
        });
    }
});
"""

def collect_coverage(binary_path, input_data):
    session = frida.spawn(binary_path)
    script = session.create_script(COVERAGE_SCRIPT)
    
    coverage_data = []
    
    def on_message(message, data):
        if message['type'] == 'send':
            coverage_data.append(message['payload'])
    
    script.on('message', on_message)
    script.load()
    
    # Resume and send input
    frida.resume(session)
    
    # Wait for execution to complete
    import time
    time.sleep(5)
    
    session.detach()
    return coverage_data
```

---

## 8. API Monitoring

### 8.1 API Monitor (Windows)

API Monitor is the most comprehensive Windows API monitoring tool:

```
# Setup:
# 1. Download API Monitor from http://www.rohitab.com/apimonitor
# 2. Configure API filter (select which APIs to monitor)

# Key API categories for RE:
# - Kernel32: CreateFile, ReadFile, WriteFile, VirtualAlloc, CreateProcess
# - Advapi32: RegOpenKey, RegSetValue, CryptEncrypt
# - Ws2_32: socket, connect, send, recv, WSAStartup
# - Ntdll: NtCreateFile, NtReadFile, NtWriteFile, NtCreateProcess
# - Crypt32: CryptEncrypt, CryptDecrypt, CertOpenStore

# Monitoring patterns:
# File operations: CreateFileW, WriteFile, ReadFile, DeleteFileW
# Registry: RegOpenKeyExW, RegSetValueExW, RegCreateKeyExW
# Network: connect, send, recv, WSASend, WSARecv
# Process: CreateProcessW, ShellExecuteW, WinExec
# Memory: VirtualAlloc, VirtualProtect, CreateRemoteThread
# Crypto: CryptEncrypt, CryptDecrypt, BCryptEncrypt, BCryptDecrypt

# Output includes:
# - Function name and parameters
# - Return value and error code
# - Call stack at time of call
# - Thread ID and timestamp
```

### 8.2 API Monitoring with Frida

```javascript
// Frida script: comprehensive Windows API monitor
// Usage: frida -l api_monitor.js -p <PID>

var logFile = new File("/tmp/api_monitor.log", "w");

function logApi(module, func, args, retval) {
    var timestamp = new Date().toISOString();
    var logLine = timestamp + " | " + module + "!" + func + " | ";
    
    // Format args
    for (var i = 0; i < args.length; i++) {
        logLine += "arg" + i + "=" + args[i] + " ";
    }
    logLine += "| ret=" + retval + "\n";
    
    logFile.write(logLine);
    console.log(logLine);
}

// Monitor file operations
Interceptor.Attach(Module.findExportByName("kernel32.dll", "CreateFileW"), {
    onEnter: function(args) {
        this.filename = args[0].readUtf16String();
        this.access = args[1].toInt32();
        this.mode = args[5].toInt32();
    },
    onLeave: function(retval) {
        logApi("kernel32", "CreateFileW", 
               [this.filename, this.access.toString(16), this.mode.toString(16)],
               retval.toString(16));
    }
});

// Monitor network operations
Interceptor.Attach(Module.findExportByName("ws2_32.dll", "connect"), {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            var ip = sockaddr.add(4).readU8() + "." + 
                     sockaddr.add(5).readU8() + "." + 
                     sockaddr.add(6).readU8() + "." + 
                     sockaddr.add(7).readU8();
            logApi("ws2_32", "connect", [ip + ":" + port], retval);
        }
    }
});

// Monitor VirtualAlloc (shellcode allocation)
Interceptor.Attach(Module.findExportByName("kernel32.dll", "VirtualAlloc"), {
    onEnter: function(args) {
        this.size = args[1].toInt32();
        this.protect = args[3].toInt32();
        if (this.protect === 0x40) { // PAGE_EXECUTE_READWRITE
            console.log("[!] VirtualAlloc with RWX protection! Size: " + this.size);
        }
    },
    onLeave: function(retval) {
        logApi("kernel32", "VirtualAlloc", 
               ["size=" + this.size, "protect=0x" + this.protect.toString(16)],
               retval.toString(16));
    }
});

// Monitor registry operations
Interceptor.Attach(Module.findExportByName("advapi32.dll", "RegOpenKeyExW"), {
    onEnter: function(args) {
        this.subkey = args[1].readUtf16String();
        this.sam = args[3].toInt32();
    },
    onLeave: function(retval) {
        logApi("advapi32", "RegOpenKeyExW", [this.subkey], retval.toString(16));
    }
});
```

---

## 9. Hooking Techniques

### 9.1 Inline Hooking (Detours/Patching)

Inline hooking replaces the first bytes of a function with a jump to a hook function:

```c
// Inline hook implementation (x86-64)
// Original function prologue:
//   push rbp       (1 byte: 0x55)
//   mov  rbp, rsp  (3 bytes: 0x48 0x89 0xE5)
//   sub  rsp, 0x20 (4 bytes: 0x48 0x83 0xEC 0x20)
//   Total: 8 bytes — enough for a 14-byte absolute jump on x64

// Hook trampoline:
//   ff 25 00 00 00 00    ; jmp qword [rip+0]     (6 bytes)
//   xx xx xx xx xx xx xx xx ; address (8 bytes)
//   Total: 14 bytes

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

struct hook_info {
    void *original_func;
    void *hook_func;
    void *trampoline;
    uint8_t original_bytes[32];  // Saved original bytes
    size_t patch_size;
};

int install_hook(void *target, void *hook, struct hook_info *info) {
    // Calculate the patch size (must cover complete instructions)
    size_t patch_size = 14;  // Minimum for x64 absolute jump
    
    // Save original bytes
    memcpy(info->original_bytes, target, patch_size);
    info->patch_size = patch_size;
    info->original_func = target;
    info->hook_func = hook;
    
    // Allocate trampoline (with original bytes + jump back)
    info->trampoline = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    // Copy original prologue to trampoline
    memcpy(info->trampoline, info->original_bytes, patch_size);
    
    // Add jump from trampoline back to original function (after patch)
    uint8_t *jmp_back = (uint8_t *)info->trampoline + patch_size;
    jmp_back[0] = 0xFF;  // jmp [rip+0]
    jmp_back[1] = 0x25;
    jmp_back[2] = 0x00;
    jmp_back[3] = 0x00;
    jmp_back[4] = 0x00;
    jmp_back[5] = 0x00;
    uint64_t orig_continue = (uint64_t)target + patch_size;
    memcpy(jmp_back + 6, &orig_continue, 8);
    
    // Make target page writable
    long page_size = sysconf(_SC_PAGESIZE);
    void *page = (void *)((uintptr_t)target & ~(page_size - 1));
    mprotect(page, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    
    // Write jump to hook at target
    uint8_t *patch = (uint8_t *)target;
    patch[0] = 0xFF;  // jmp [rip+0]
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    uint64_t hook_addr = (uint64_t)hook;
    memcpy(patch + 6, &hook_addr, 8);
    
    // NOP any remaining bytes (if we overwrote more than 14)
    for (size_t i = 14; i < patch_size; i++) {
        patch[i] = 0x90;  // NOP
    }
    
    return 0;
}
```

### 9.2 IAT Hooking (Import Address Table)

IAT hooking replaces function pointers in the Import Address Table:

```c
// IAT hook implementation (Windows)
#include <windows.h>
#include <stdio.h>

// Original function pointer
static FARPROC original_MessageBoxW = NULL;

// Hook function
INT WINAPI hook_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    printf("[HOOK] MessageBoxW called!\n");
    printf("[HOOK] Text: %ls\n", lpText);
    printf("[HOOK] Caption: %ls\n", lpCaption);
    printf("[HOOK] Type: %u\n", uType);
    
    // Call original function
    return original_MessageBoxW(hWnd, L"[HOOKED]", lpCaption, uType);
}

int iat_hook(HMODULE hModule, const char *target_func, void *hook_func, void **original) {
    // Get the import directory
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)hModule;
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)hModule + dos_header->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *import_desc = (IMAGE_IMPORT_DESCRIPTOR *)
        ((BYTE *)hModule + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    // Walk import descriptors
    while (import_desc->Name) {
        const char *dll_name = (const char *)((BYTE *)hModule + import_desc->Name);
        
        // Walk thunks (IAT entries)
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)
            ((BYTE *)hModule + import_desc->FirstThunk);
        
        while (thunk->u1.Function) {
            FARPROC *iat_entry = (FARPROC *)&thunk->u1.Function;
            
            if (*iat_entry == GetProcAddress(GetModuleHandleA(dll_name), target_func)) {
                // Found the target! Replace in IAT
                DWORD old_protect;
                VirtualProtect(iat_entry, sizeof(FARPROC), PAGE_READWRITE, &old_protect);
                *original = *iat_entry;  // Save original
                *iat_entry = (FARPROC)hook_func;  // Hook!
                VirtualProtect(iat_entry, sizeof(FARPROC), old_protect, &old_protect);
                return 1;  // Success
            }
            thunk++;
        }
        import_desc++;
    }
    return 0;  // Not found
}

// Usage
int main() {
    iat_hook(GetModuleHandle(NULL), "MessageBoxW", hook_MessageBoxW, &original_MessageBoxW);
    MessageBoxW(NULL, L"Hello", L"Test", MB_OK);
    return 0;
}
```

### 9.3 Frida Dynamic Hooking

```javascript
// Frida: the most versatile dynamic hooking framework
// Install: pip install frida-tools

// Basic function hooking
frida -U -f com.target.app -l hook.js

// hook.js contents:
Java.perform(function() {
    // Hook Android Java method
    var SecretClass = Java.use("com.target.SecretClass");
    SecretClass.decrypt.implementation = function(key, data) {
        console.log("[*] SecretClass.decrypt called");
        console.log("    key: " + key);
        console.log("    data: " + data);
        var result = this.decrypt(key, data);
        console.log("    result: " + result);
        return result;
    };
});

// Hook native function
Interceptor.attach(Module.findExportByName("libtarget.so", "validate_license"), {
    onEnter: function(args) {
        console.log("[*] validate_license called");
        console.log("    arg0: " + args[0].readUtf8String());
        console.log("    arg1: " + args[1].readUtf8String());
        this.arg0 = args[0];
    },
    onLeave: function(retval) {
        console.log("[*] validate_license returned: " + retval);
        // Force return true
        retval.replace(1);
    }
});

// Hook SSL read/write to intercept HTTPS
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_read"), {
    onEnter: function(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var bytesRead = retval.toInt32();
        if (bytesRead > 0) {
            console.log("[SSL_READ] " + this.buf.readUtf8String(bytesRead));
        }
    }
});

// Memory scanning
var pattern = "63 7C 77 7B F2 6B 6F C5"; // AES S-box start
var matches = Memory.scanSync(Module.findBaseAddress("libtarget.so"), 
                               Module.findModuleByName("libtarget.so").size,
                               pattern);
matches.forEach(function(match) {
    console.log("[*] Pattern found at: " + match.address);
});

// Dump decrypted buffer
function dumpMemory(addr, size, label) {
    console.log("[*] " + label + " @ " + addr);
    console.log(hexdump(addr, {length: size}));
}

// Trace class methods dynamically
Java.enumerateLoadedClasses({
    onMatch: function(className) {
        if (className.indexOf("crypto") !== -1 || 
            className.indexOf("Crypto") !== -1) {
            console.log("[*] Found crypto class: " + className);
        }
    },
    onComplete: function() {
        console.log("[*] Class enumeration complete");
    }
});
```

---

## 10. Memory Forensics During Debugging

### 10.1 Memory Dumping

```bash
# GDB memory dumping
(gdb) dump memory /tmp/dump.bin 0x401000 0x402000    # Dump memory range
(gdb) dump binary value /tmp/value.bin *(long*)0x403000 # Dump specific value
(gdb) dump binary memory /tmp/mem.bin 0x7f000000 0x7f001000 # Binary dump

# Dump all mapped memory regions
(gdb) info proc mappings
# Then dump each region:
(gdb) dump memory /tmp/region1.bin <start> <end>

# WinDBG memory dumping
.writemem d:\full_dump.bin 0x0 L?0x1000000     # Dump 16MB from address 0x0

# Dump entire process (create minidump)
.dump /ma d:\full_dump.dmp

# Process dump on Linux (gcore)
gcore <PID>      # Create core dump of process
gcore -o output <PID>  # Specify output filename

# Dump specific process memory regions
cat /proc/<PID>/maps   # View memory mappings
# For each readable region:
dd if=/proc/<PID>/mem bs=1 skip=$((start)) count=$((size)) of=region.bin
```

### 10.2 Runtime Decryption Detection

Many packers and protectors decrypt code at runtime. Detecting when decryption completes and dumping the decrypted binary is essential:

```python
# GDB Python: automatically dump memory when encryption marker changes
import gdb

class DecryptWatcher(gdb.Breakpoint):
    """Watch a memory location for decryption completion."""
    
    def __init__(self, addr, expected_value, dump_addr, dump_size, filename):
        spec = f"*(int*){addr}"
        super().__init__(spec, gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.expected_value = expected_value
        self.dump_addr = dump_addr
        self.dump_size = dump_size
        self.filename = filename
        self.decrypted = False
    
    def stop(self):
        current = int(gdb.parse_and_eval(f"*(int*){self.addr}"))
        if current == self.expected_value:
            # Decryption complete, dump memory
            inferior = gdb.selected_inferior()
            mem = inferior.read_memory(self.dump_addr, self.dump_size)
            with open(self.filename, 'wb') as f:
                f.write(bytes(mem))
            print(f"[+] Dumped {self.dump_size} bytes to {self.filename}")
            self.decrypted = True
            return True  # Stop execution
        return False  # Continue execution

# Usage:
# watcher = DecryptWatcher(0x403000, 0x90909090, 0x401000, 0x10000, "decrypted.bin")
```

---

## 11. Anti-Debugging Detection and Bypass

### 11.1 Anti-Debugging Techniques

| Technique | Platform | Detection Method | Bypass |
|-----------|----------|-----------------|--------|
| `IsDebuggerPresent` | Windows | PEB.BeingDebugged | Set to 0 |
| `CheckRemoteDebuggerPresent` | Windows | ProcessDebugPort | Hook to return 0 |
| `NtQueryInformationProcess` | Windows | ProcessDebugPort, ProcessDebugObjectHandle | Return STATUS_PORT_NOT_SET |
| `GetTickCount`/`QueryPerformanceCounter` | Both | Timing between instructions | Adjust time delta |
| `rdtsc` instruction | x86 | Timing using CPU timestamp counter | Hook or patch timing check |
| `INT3` detection | x86 | Check for 0xCC bytes at expected code | Use hardware breakpoints |
| Hardware breakpoint detection | x86 | Read DR0-DR7 registers | Clear DR7 before check |
| `ptrace(PTRACE_TRACEME)` | Linux | Only one tracer allowed | Patch call, use kernel module |
| `/proc/self/status` | Linux | Check TracerPid field | Patch /proc handler |
| `OutputDebugString` | Windows | Returns non-zero if debugger attached | Hook to always return 0 |
| `NtClose` with invalid handle | Windows | Raises exception only with debugger | Catch and handle exception |
| `CreateFileA("\\\\.\\Ntdll\\...")` | Windows | Opens debug port object | Hook to return INVALID_HANDLE_VALUE |

### 11.2 Comprehensive Anti-Debug Bypass with ScyllaHide

```bash
# ScyllaHide — anti-anti-debug plugin for x64dbg
# Install: copy ScyllaHide.x64.dll and ScyllaHide.x32.dll to x64dbg plugins/

# Features:
# - Patches IsDebuggerPresent, CheckRemoteDebuggerPresent
# - Patches NtQueryInformationProcess (ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags)
# - Patches GetTickCount, QueryPerformanceCounter (timing)
# - Patches OutputDebugString (exception-based detection)
# - Hides hardware breakpoints (clears DR registers on check)
# - Patches GetProcAddress for anti-hook detection

# Usage in x64dbg:
# 1. Open target binary in x64dbg
# 2. Click ScyllaHide in the menu
# 3. Select options:
#    - NtSetInformationThread (hide thread from debugger)
#    - OutputDebugString (patch)
#    - GetTickCount (patch)
#    - QueryPerformanceCounter (patch)
# 4. Press "Apply Patches"
# 5. Run the target

# Linux equivalent: LD_PRELOAD-based hooks
cat > anti_debug_hook.c << 'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <sys/ptrace.h>

// Bypass ptrace(PTRACE_TRACEME) check
long ptrace(enum __ptrace_request request, ...) {
    return 0;  // Always succeed
}

// Bypass /proc/self/status TracerPid check
FILE *fopen(const char *path, const char *mode) {
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    
    if (path && strstr(path, "/proc/") && strstr(path, "/status")) {
        // Redirect to a fake status file
        return real_fopen("/tmp/fake_status", mode);
    }
    return real_fopen(path, mode);
}
EOF

gcc -shared -fPIC -o anti_debug_hook.so anti_debug_hook.c -ldl
LD_PRELOAD=./anti_debug_hook.so ./target
```

### 11.3 Anti-Debug Detection Script

```python
# Comprehensive anti-debugging detection scanner
import struct
import sys

def detect_anti_debug_pe(filename):
    """Scan PE binary for anti-debugging API calls and patterns."""
    import pefile
    
    pe = pefile.PE(filename)
    
    anti_debug_apis = {
        # Windows anti-debug APIs
        'IsDebuggerPresent': 'PEB.BeingDebugged check',
        'CheckRemoteDebuggerPresent': 'ProcessDebugPort check',
        'NtQueryInformationProcess': 'ProcessDebugPort/ProcessDebugObjectHandle/ProcessDebugFlags',
        'GetTickCount': 'Timing check',
        'QueryPerformanceCounter': 'Timing check (high precision)',
        'OutputDebugString': 'Exception-based debug detection',
        'ZwQuerySystemInformation': 'SystemDebuggerInformation check',
        'CreateToolhelp32Snapshot': 'Process enumeration check',
        'FindWindowA': 'Window name detection (OllyDbg, IDA)',
        'FindWindowW': 'Window name detection',
        'EnumWindows': 'Window enumeration detection',
        'GetWindowThreadProcessId': 'Process ID detection',
        'LoadLibraryA': 'Module load detection (SbieDll.dll, dbghelp.dll)',
        'GetProcAddress': 'Dynamic API resolution (anti-debug)',
        
        # Linux anti-debug
        'ptrace': 'PTRACE_TRACEME detection',
        'prctl': 'PR_SET_DUMPABLE control',
    }
    
    print("=== Anti-Debugging Detection ===\n")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='replace')
                    if func_name in anti_debug_apis:
                        print(f"[!] {func_name:40s} ({dll_name}) — {anti_debug_apis[func_name]}")
    
    # Scan for anti-debug assembly patterns
    data = pe.__data__
    
    patterns = {
        b'\x64\xA1\x30\x00\x00\x00': 'FS:[30] — PEB access (x86)',
        b'\x65\x48\x8B\x04\x25\x60\x00\x00\x00': 'GS:[60h] — PEB access (x64)',
        b'\x0F\xB6\x40\x02': 'MOVZX EAX, BYTE PTR [EAX+2] — Read BeingDebugged',
        b'\xCC': 'INT3 — Software breakpoint (manual scan needed)',
        b'\xEB\xFE': 'JMP $ — Infinite loop (timing check)',
    }
    
    print("\n=== Pattern Scan ===\n")
    for pattern, description in patterns.items():
        offset = 0
        count = 0
        while True:
            offset = data.find(pattern, offset)
            if offset == -1:
                break
            count += 1
            offset += 1
        if count > 0:
            print(f"[!] {description}: {count} occurrence(s)")

detect_anti_debug_pe(sys.argv[1])
```

> **Cross-reference**: See [04b_anti_tamper_obfuscation.md](04b_anti_tamper_obfuscation.md) for comprehensive anti-tamper and obfuscation techniques and their bypasses. See [03a_malware_analysis.md](03a_malware_analysis.md) for malware-specific anti-debugging techniques. See the [Windows Security track](../windows_security/) for kernel-level debugging and the [Linux Kernel track](../linux_kernel/) for kernel debugging with KGDB.

---

*This document is part of the Deep Researcher Reverse Engineering track. Dynamic analysis complements static analysis — always use both.*

## References

1. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
2. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
3. GDB documentation, https://sourceware.org/gdb/documentation/
4. Frida documentation, https://frida.re/docs/home/
5. WinDbg documentation, https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
6. Dennis Yurichev, "Reverse Engineering for Beginners," https://yurichev.com/writings/RE_for_beginners-en.pdf
7. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
8. Cuckoo Sandbox documentation, https://github.com/cuckoosandbox/cuckoo
9. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
10. SANS Institute, "Reverse Engineering Malware" (FOR610), https://www.sans.org/