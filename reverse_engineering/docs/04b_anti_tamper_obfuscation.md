# Anti-Tamper & Obfuscation Techniques

> Comprehensive reference on code obfuscation, anti-debugging, anti-dumping, anti-disassembly, DRM/anti-cheat, and deobfuscation techniques for reverse engineering.

---

## Table of Contents

1. [Obfuscation Overview](#1-obfuscation-overview)
2. [Control Flow Flattening](#2-control-flow-flattening)
3. [Opaque Predicates & Bogus Control Flow](#3-opaque-predicates--bogus-control-flow)
4. [Junk Code Insertion](#4-junk-code-insertion)
5. [String Encryption](#5-string-encryption)
6. [Code Virtualization](#6-code-virtualization)
7. [Anti-Debugging Techniques](#7-anti-debugging-techniques)
8. [Anti-Dumping Techniques](#8-anti-dumping-techniques)
9. [Anti-Disassembly Techniques](#9-anti-disassembly-techniques)
10. [DRM & Anti-Cheat Analysis](#10-drm--anti-cheat-analysis)
11. [Deobfuscation Tools & Techniques](#11-deobfuscation-tools--techniques)

---

## 1. Obfuscation Overview

Obfuscation transforms code to make it harder to understand and analyze while preserving its original functionality. The goal is to increase the analysis cost beyond the value of the information gained.

```
Obfuscation Techniques by Complexity:
┌────────────────────────────┐
│ Level 1: Basic              │ String encryption, symbol stripping
│                              │ simple renaming, packer compression
├────────────────────────────┤
│ Level 2: Intermediate        │ Control flow flattening, opaque predicates,
│                              │ junk code insertion, function outlining
├────────────────────────────┤
│ Level 3: Advanced            │ Code virtualization, anti-debugging,
│                              │ self-modifying code, encoded constants
├────────────────────────────┤
│ Level 4: State-of-the-Art   │ Full VM obfuscation (VMProtect/Themida),
│                              │ cryptographic obfuscation, homomorphic
│                              │ computation, secure enclaves
└────────────────────────────┘
```

The obfuscation arms race:

```
Obfuscator                          Deobfuscator
──────────                          ────────────
String encryption                   → Pattern matching + decryption
Symbol stripping                    → Symbol recovery heuristics
Control flow flattening            → CFG reconstruction
Opaque predicates                  → SAT/SMT solving
Junk code insertion                 → Dead code elimination
Code virtualization                 → Devirtualization (hard)
Self-modifying code                 → Memory dump + trace analysis
```

---

## 2. Control Flow Flattening

Control flow flattening (CFF) transforms a function's natural control flow into a single-loop switch structure where each basic block is a `case` in the switch:

```c
// Original code:
void process(int input) {
    if (input > 0) {
        result = input * 2;
    } else {
        result = -input;
    }
    printf("Result: %d\n", result);
}

// After control flow flattening:
void process_obfuscated(int input) {
    int state = 1;  // Initial state
    int result;
    
    while (1) {
        switch (state) {
            case 1:  // Entry
                if (input > 0) {
                    state = 2;
                } else {
                    state = 3;
                }
                break;
            case 2:  // Positive path
                result = input * 2;
                state = 4;
                break;
            case 3:  // Negative path
                result = -input;
                state = 4;
                break;
            case 4:  // Merge and output
                printf("Result: %d\n", result);
                state = 5;  // Exit
                break;
            case 5:  // Exit
                return;
            default:
                state = 1;
                break;
        }
    }
}
```

### 2.1 OLLVM Control Flow Flattening

```bash
# OLLVM (Obfuscator-LLVM) provides CFF as a compilation pass
# Build OLLVM:
git clone https://github.com/heroims/obfuscator.git
cd obfuscator
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_INCLUDE_TESTS=OFF ..
make -j$(nproc)

# Compile with CFF:
./bin/clang -mllvm -fla -mllvm -bcf_loop=3 source.c -o source_flattened
# -fla: enable control flow flattening
# -bcf_loop=N: apply bogus control flow N times
# -sub: enable instruction substitution
# -bcf: enable bogus control flow

# Combined obfuscation:
./bin/clang -mllvm -fla -mllvm -sub -mllvm -bcf -mllvm -bcf_loop=3 source.c -o source_obfuscated
```

### 2.2 Deflattening Technique

The key insight for deflattening: the state variable and dispatch block are always identifiable. The approach:

```python
# Deflattening approach (conceptual)
# 1. Identify the state variable (usually a stack variable or register)
# 2. Identify the dispatch block (the switch statement header)
# 3. For each case, determine:
#    a. The predecessor state (which case transitions to this one)
#    b. The successor state (which case this transitions to)
# 4. Reconstruct the original CFG by connecting blocks based on state transitions
# 5. Replace switch dispatch with direct control flow

# Demo in IDAPython:
def identify_flattened_function(func_ea):
    """Identify control flow flattened functions."""
    import idautils
    import idc
    import idaapi
    
    func = idaapi.get_func(func_ea)
    if not func:
        return None
    
    # Heuristic: flattened functions have a dominant block (the dispatcher)
    # that references all other blocks
    
    # Build basic block list
    blocks = []
    for block in idautils.FlowChart(func):
        blocks.append({
            'start': block.start_ea,
            'end': block.end_ea,
            'succs': [s.start_ea for s in block.succs()],
            'preds': [p.start_ea for p in block.preds()],
        })
    
    # Find the dispatcher block (one block with many successors)
    for block in blocks:
        if len(block['succs']) > 5:  # Dispatcher has many cases
            print(f"Suspected flattening dispatcher at 0x{block['start']:x}")
            print(f"  Successors: {[hex(s) for s in block['succs']]}")
            return block
    
    return None
```

> **Cross-reference**: D-810 is an IDA Pro plugin for deflattening. See section 11 for detailed deobfuscation tool workflows.

---

## 3. Opaque Predicates & Bogus Control Flow

### 3.1 Opaque Predicates

An opaque predicate is a conditional expression whose value is always known at compile time but is computationally difficult for an analyzer to determine:

```c
// Example opaque predicates (always evaluate to TRUE)
// OP1: x * (x + 1) is always even (for integer x)
if ((input * (input + 1)) % 2 == 0) {
    // ALWAYS taken (real code path)
} else {
    // NEVER taken (junk code / dead code)
}

// OP2: x² - x is always divisible by 2  
if ((input * input - input) % 2 == 0) {
    // ALWAYS taken
}

// OP3: If y = 7x + 5, then y² - 1 ≡ 0 (mod 4)
// Because y ≡ 1 or 3 (mod 4) → y² ≡ 1 (mod 4) → y² - 1 ≡ 0 (mod 4)

// OP4: (x + 1)³ - x³ - 3x² - 3x ≡ 1 (always true)
// Because (x+1)³ = x³ + 3x² + 3x + 1

// In assembly, opaque predicates create false branches:
//   mov  eax, [input]
//   imul eax, eax        ; eax² 
//   add  eax, [input]   ; eax² + input
//   and  eax, 1          ; is (eax² + input) odd?
//   jnz  real_code       ; always taken (input² + input is always even)
//   ; junk code never reached
```

### 3.2 Bogus Control Flow (BCF)

OLLVM's Bogus Control Flow pass adds fake branches:

```c
// Original:
if (x > 0) {
    result = x * 2;
}

// After BCF:
int opaque_true = (x * (x + 1)) % 2; // Always 0
if (opaque_true == 0) {
    if (x > 0) {        // First copy (real)
        result = x * 2;
    }
} else {
    if (x > 0) {        // Second copy (never reached)
        result = x * 2; // Identical code, but this path is unreachable
    } else {
        result = 0;     // Bogus path
    }
}
```

In assembly:

```asm
; BCF in assembly creates two identical-looking basic blocks
; with an opaque predicate choosing the real one

; Block A (real path):
    mov  eax, [ebp+var_x]
    imul eax, eax        ; x²
    add  eax, [ebp+var_x] ; x² + x
    and  eax, 1          ; (x² + x) % 2 — always 0
    jnz  block_B         ; Never taken
    ; Real code continues here
    mov  eax, [ebp+var_x]
    cmp  eax, 0
    jle  skip
    shl  eax, 1
    mov  [ebp+var_result], eax
skip:
    jmp  after_bcf

; Block B (bogus path — never reached):
block_B:
    ; Identical-looking code but with different semantics
    ; or completely junk code
    mov  ecx, [ebp+var_x]
    imul ecx, ecx
    add  ecx, [ebp+var_x]
    and  ecx, 1
    jnz  block_A         ; Loop back (never reached from here either)
    ; More junk code...
after_bcf:
```

### 3.3 Defeating Opaque Predicates

```python
# Approaches to defeat opaque predicates:

# 1. Symbolic execution
#    Use angr or KLEE to evaluate predicates symbolically
#    If a predicate is always true/false, symbolic execution will determine it

import angr
proj = angr.Project('target_binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
# ... symbolic execution to prove predicate values

# 2. Pattern matching
#    Known opaque predicate patterns:
OPAQUE_PATTERNS = [
    # (x * (x + 1)) % 2 == 0   
    ('imul', 'add', 'and 1'),     # Always even
    # x² - x ≡ 0 (mod 2)
    ('imul', 'sub', 'and 1'),     # x² - x even
    # Always-false patterns
    ('cmp', 'sete', 'test'),       # Compare with known constant
]

# 3. Z3 SMT solver
from z3 import *

x = Int('x')
# Prove: x * (x + 1) is always even
prove(Implies(True, (x * (x + 1)) % 2 == 0))
# This will return "proved" if the predicate is always true

# 4. Dynamic analysis
#    Execute the predicate with various inputs
#    If the result is always the same, it's likely opaque

def test_predicate(func_addr, num_tests=100):
    """Test if a predicate is opaque by evaluating it with random inputs."""
    results = set()
    for _ in range(num_tests):
        result = evaluate_at(func_addr, random_input())
        results.add(result)
        if len(results) > 1:
            return False  # Not opaque (different outcomes)
    return True  # Likely opaque (same outcome every time)
```

---

## 4. Junk Code Insertion

Junk code insertion adds instructions that don't affect program behavior:

```asm
; Before junk code insertion:
    mov  eax, [ebp+arg1]
    add  eax, 10
    ret

; After junk code insertion:
    push ebp                 ; Junk
    mov  ebp, esp            ; Junk
    sub  esp, 0x10           ; Junk (allocate stack)
    mov  eax, [ebp+arg1]
    push ecx                ; Junk (save register)
    xor  ecx, ecx           ; Junk (zero ecx)
    add  eax, 10
    pop  ecx                ; Junk (restore register)
    mov  esp, ebp            ; Junk
    pop  ebp                 ; Junk
    ret

; More aggressive junk code:
    mov  eax, [ebp+arg1]
    pushfd                   ; Junk
    pop  edx                ; Junk
    push edx                ; Junk
    popfd                   ; Junk
    call $+5                 ; Junk (call to next instruction)
    add  eax, 10
    ret
```

Dead code elimination techniques:

```python
# Dead code elimination in IDAPython
def eliminate_dead_code(func_ea):
    """Remove junk code using reaching definitions analysis."""
    import idaapi
    import idautils
    
    func = idaapi.get_func(func_ea)
    if not func:
        return
    
    # Build control flow graph
    blocks = list(idautils.FlowChart(func))
    
    dead_instructions = []
    
    # Identify patterns of junk code:
    # 1. push/pop pairs that cancel out
    # 2. mov reg, reg (no-op)
    # 3. xor reg, reg followed by test (always zero)
    # 4. call $+5 followed by add esp, 4 (no-op call)
    
    for block in blocks:
        ea = block.start_ea
        while ea < block.end_ea:
            mnem = idc.print_insn_mnem(ea)
            
            # Pattern: push X / pop X (cancel out)
            if mnem == 'push':
                next_ea = idc.next_head(ea)
                next_mnem = idc.print_insn_mnem(next_ea)
                if next_mnem == 'pop':
                    # Check if same register
                    op0 = idc.print_operand(ea, 0)
                    next_op0 = idc.print_operand(next_ea, 0)
                    if op0 == next_op0:
                        dead_instructions.extend([ea, next_ea])
                        ea = idc.next_head(next_ea)
                        continue
            
            # Pattern: mov reg, reg (no-op)
            if mnem == 'mov':
                op0 = idc.print_operand(ea, 0)
                op1 = idc.print_operand(ea, 1)
                if op0 == op1:
                    dead_instructions.append(ea)
            
            ea = idc.next_head(ea)
    
    return dead_instructions
```

---

## 5. String Encryption

String encryption prevents static string analysis by encrypting strings at compile time and decrypting them at runtime:

```c
// OLLVM string encryption example:
// Original:
printf("Hello, World!\n");

// After string encryption:
// Encrypted string is stored as a byte array
// Decrypted at runtime via XOR loop
unsigned char encrypted_str[] = {0x2a, 0x07, 0x1b, 0x05, 0x2f, 0x68, 0x28, 0x0c,
                                  0x2c, 0x72, 0x3c, 0x2f, 0x1b, 0x00};
// Key derived at runtime from context
for (int i = 0; encrypted_str[i]; i++) {
    encrypted_str[i] ^= (key[i % key_len] ^ (i & 0xFF));
}
printf((char *)encrypted_str);
```

### 5.1 String Decryption Techniques

```python
# Technique 1: Runtime string extraction (dump after decryption)
# Use debugger to set breakpoint after decryption loop, dump strings

# Technique 2: Emulate the decryption function
def emulate_string_decryption(binary_data, decrypt_func_addr):
    """Emulate the string decryption function to recover all strings."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
    
    # Set up Unicorn emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    
    # Map memory and load binary
    BASE = 0x100000
    STACK = 0x800000
    mu.mem_map(BASE, 4 * 1024 * 1024)
    mu.mem_map(STACK, 0x10000)
    
    # Load binary data
    mu.mem_write(BASE, binary_data)
    
    # Set stack pointer
    mu.reg_write(UC_X86_REG_ESP, STACK + 0x8000)
    
    # Execute decryption function
    mu.emu_start(decrypt_func_addr, decrypt_func_addr + 0x100)
    
    # Read decrypted strings from memory
    # ...

# Technique 3: Pattern-based string recovery
def find_xor_decryption_patterns(binary_data):
    """Find XOR decryption loops in binary data."""
    patterns = []
    
    # Pattern: loop with XOR operation
    # x86: xor [addr], key ; often in a loop with inc/dec
    for i in range(len(binary_data) - 10):
        # Look for XOR byte [reg+off], immediate
        if binary_data[i] == 0x80:  # XOR [mem], imm8
            # Check context for loop structure
            patterns.append({
                'offset': i,
                'type': 'xor_mem_imm8',
                'key': binary_data[i+2] if i+2 < len(binary_data) else 0,
            })
    
    return patterns

# Technique 4: Frida-based runtime string extraction
FRIDA_STRING_SCRIPT = """
var decrypt_calls = [];

// Hook common string decryption functions
var funcs_to_hook = [
    Module.findExportByName(null, 'sub_XXXXX'),  // Replace with actual address
];

funcs_to_hook.forEach(function(addr) {
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.arg0 = args[0]; // Save input
            },
            onLeave: function(retval) {
                // Read decrypted string
                try {
                    var decrypted = Memory.readUtf8String(retval);
                    if (decrypted && decrypted.length > 3) {
                        send({type: 'decrypted_string', string: decrypted});
                    }
                } catch (e) {}
            }
        });
    }
});
"""

# Run with: frida -U -l strings.js -f com.target.app
```

---

## 6. Code Virtualization

Code virtualization converts native code into bytecode for a custom virtual machine:

```
Normal Execution:                Virtualized Execution:
┌───────────────┐                ┌────────────────┐
│  x86 Code     │                │ VM Bytecode     │
│  (native)     │                │ (custom format) │
└───────┬───────┘                └───────┬────────┘
        │                                │
        │ CPU executes                   │ VM Interpreter executes
        ▼                                ▼
    Registers: EAX,EBX...           Virtual Registers: v0,v1,v2...
    Stack: x86 stack                 Virtual Stack
    Memory: Process memory           Same process memory
```

### 6.1 VMProtect Architecture

VMProtect creates a custom virtual machine for each protected function:

```asm
; VMProtect entry point (before virtualization):
call protected_function

; After virtualization:
jmp  vmp_handler_table      ; Jump to VM interpreter
; The original function code has been replaced with:
push vmp_encrypted_bytecode  ; Push VM bytecode offset
jmp  vmp_entry               ; Jump to VM dispatcher

; VM interpreter structure:
vmp_entry:
    pusha                     ; Save all registers
    pushf                     ; Save flags
    mov  esi, bytecode_ptr    ; ESI = instruction pointer
    mov  edi, vmp_stack       ; EDI = virtual stack pointer
    
vmp_dispatcher:
    movzx eax, byte [esi]    ; Fetch opcode
    jmp  [handler_table + eax*4]  ; Dispatch to handler

; Sample VM handlers:
handler_push_reg:
    mov  ebx, [esi+1]        ; Get register index from bytecode
    push [vmp_regs + ebx*4]  ; Push virtual register value
    add  esi, 5               ; Advance instruction pointer
    jmp  vmp_dispatcher
    
handler_add:
    pop  ebx                 ; Pop source operand
    pop  eax                 ; Pop destination operand
    add  eax, ebx             ; Perform addition
    push eax                 ; Push result
    add  esi, 1               ; Advance instruction pointer
    jmp  vmp_dispatcher

; VMProtect generates unique handler tables for each binary,
; making pattern recognition difficult
```

### 6.2 Devirtualization Approach

```
Devirtualization Steps:
1. Identify the VM entry point and dispatcher
2. Map all VM opcodes to their handlers
3. Extract bytecode from the protected function
4. Trace execution through the VM for each handler
5. Reconstruct the original control flow from bytecode
6. Regenerate native code from the reconstructed logic

Tools for devirtualization:
- VMHunt: LLVM-based VM handler identification
- VTIL: Virtual Translation Intermediate Language
- D-810: IDA Pro plugin for deobfuscation
- Manual analysis: most reliable but time-consuming
```

---

## 7. Anti-Debugging Techniques

### 7.1 Windows Anti-Debugging

```c
// === PEB.BeingDebugged ===
// The most basic anti-debug check on Windows
// PEB is at FS:[0x30] (x86) or GS:[0x60] (x64)

// C equivalent:
BOOL IsDebuggerPresent(void) {
    return NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged;
}

// Assembly (x86):
    mov eax, fs:[0x30]     ; PEB address
    movzx eax, byte [eax+2] ; BeingDebugged at PEB+2
    test eax, eax
    jnz debugger_detected

// Assembly (x64):
    mov rax, gs:[0x60]     ; PEB address (x64)
    movzx eax, byte [rax+2] ; BeingDebugged
    test eax, eax
    jnz debugger_detected

// Bypass: Set BeingDebugged to 0
// In gdb: set *(char*)PEB_ADDR+2 = 0
// In WinDBG: eb PEB_ADDR+2 0

// === NtQueryInformationProcess ===
// Checks ProcessDebugPort (7), ProcessDebugObjectHandle (30), ProcessDebugFlags (31)

// C equivalent:
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

BOOL CheckDebugger() {
    DWORD_PTR debugPort = 0;
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
    
    // Check ProcessDebugPort
    NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
    if (debugPort != 0) return TRUE;  // Debugger present
    
    // Check ProcessDebugObjectHandle
    DWORD_PTR debugObject = 0;
    NtQIP(GetCurrentProcess(), 30, &debugObject, sizeof(debugObject), NULL);
    if (debugObject != 0) return TRUE;  // Debugger present
    
    return FALSE;
}

// Bypass: Hook NtQueryInformationProcess to return STATUS_PORT_NOT_SET
// Or use ScyllaHide plugin

// === CheckRemoteDebuggerPresent ===
// Remote version of IsDebuggerPresent
BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    // Internally calls NtQueryInformationProcess with ProcessDebugPort
}

// Bypass: Same as NtQueryInformationProcess

// === Timing Checks ===
// Measure time between instructions to detect debugger stepping

void TimingCheck() {
    DWORD t1, t2;
    
    t1 = GetTickCount();
    // ... some code ...
    t2 = GetTickCount();
    
    if (t2 - t1 > 100) {  // Threshold (100ms)
        // Debugger detected (single-stepping causes delays)
    }
}

// Assembly using RDTSC:
    rdtsc                    ; Read timestamp counter
    mov  ebx, eax            ; Save low 32 bits
    ; ... some code ...
    rdtsc                    ; Read again
    sub  eax, ebx            ; Calculate delta
    cmp  eax, 0x1000000      ; Threshold (~16M cycles)
    ja   debugger_detected

// Bypass: Hook GetTickCount/RDTSC to return consistent values
// Or: set RDTSC to constant via debugger script

// === Exception-based Detection ===
// Uses structured exception handling (SEH) to detect debuggers

void ExceptionCheck() {
    __try {
        DebugBreak();  // INT3 triggers exception
        // If we reach here, no debugger is handling exceptions
        // (debugger caught it means debugger is present)
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception handler caught it — debugger might be present
        // because the debugger intercepts exceptions before SEH
    }
}

// Bypass: Pass exception to application (configure debugger to not catch first-chance exceptions)

// === Hardware Breakpoint Detection ===
// Reading debug registers DR0-DR7

void CheckHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            // Hardware breakpoints detected
        }
    }
}

// Assembly directly:
    mov  rax, dr0           ; Read DR0
    test rax, rax
    jnz  hw_bp_detected     ; Non-zero = hardware breakpoint set
    
    mov  rax, dr7           ; Read DR7 (debug control)
    test rax, rax
    jnz  hw_bp_detected     ; Non-zero = hardware breakpoints enabled

// Bypass: Clear DR registers before the check
// Or use ScyllaHide which hooks GetThreadContext
```

### 7.2 Linux Anti-Debugging

```c
// === ptrace Detection ===
// Only one tracer can attach to a process at a time
// If the process is already being debugged, PTRACE_TRACEME fails

#include <sys/ptrace.h>

int anti_debug_ptrace(void) {
    // If already being traced, this will fail
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;  // Debugger detected
    }
    return 0;  // No debugger
}

// Bypass: Hook ptrace to always return 0
// Or: use LD_PRELOAD with a fake ptrace

// === /proc/self/status TracerPid ===
int anti_debug_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid != 0;  // Non-zero = debugger attached
        }
    }
    
    fclose(f);
    return 0;
}

// Bypass: Patch /proc/self/status or use mount namespace
// Or: hook fopen to redirect reads

// === /proc/self/maps Analysis ===
// Check for debugger-related memory mappings
int anti_debug_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    
    while (fgets(line, sizeof(line), f)) {
        // Look for debugger libraries
        if (strstr(line, "ltrace") || strstr(line, "strace") ||
            strstr(line, "frida") || strstr(line, "libinject")) {
            fclose(f);
            return 1;  // Debugger detected
        }
    }
    
    fclose(f);
    return 0;
}

// === Signal-based Detection ===
#include <signal.h>

void sigtrap_handler(int sig) {
    // SIGTRAP received without debugger — normal execution
    anti_debug_flag = 0;  // No debugger
}

int anti_debug_signal(void) {
    struct sigaction sa = {0};
    sa.sa_handler = sigtrap_handler;
    sigaction(SIGTRAP, &sa, NULL);
    
    anti_debug_flag = 1;  // Assume debugger
    raise(SIGTRAP);         // If no handler, process crashes
    
    // If handler ran, anti_debug_flag is 0
    return anti_debug_flag;
}
```

---

## 8. Anti-Dumping Techniques

### 8.1 PE Header Erasure

```c
// Anti-dumping: erase PE header from memory after loading
void anti_dump_erase_header(void) {
    DWORD old_protect;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    
    // Make PE header writable and erase it
    VirtualProtect(dos_header, 0x1000, PAGE_READWRITE, &old_protect);
    SecureZeroMemory(dos_header, 0x1000);
    VirtualProtect(dos_header, 0x1000, old_protect, &old_protect);
    
    // Now tools like ProcDump can't find the PE header to dump
}

// Bypass: Reconstruct PE header from file on disk
// Or: capture dump before header is erased
// Or: use a tool that can reconstruct headers (Scylla, PE-sieve)
```

### 8.2 Size-of-Image Modification

```c
// Anti-dumping: modify SizeOfImage to prevent proper dumping
void anti_dump_size modification(void) {
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(
        (BYTE *)GetModuleHandle(NULL) + 
        ((PIMAGE_DOS_HEADER)GetModuleHandle(NULL))->e_lfanew
    );
    
    // Set SizeOfImage to a very large value
    // This causes dumper tools to allocate too much memory
    nt_headers->OptionalHeader.SizeOfImage = 0x7FFFFFFF;
    
    // Or set it to 0, causing dumper to fail
    nt_headers->OptionalHeader.SizeOfImage = 0;
}

// Bypass: Manually calculate and correct SizeOfImage
// SizeOfImage = last_section_VA + last_section_VirtualSize aligned to SectionAlignment
```

### 8.3 Debug Port Manipulation

```c
// Anti-dumping: clear the debug port to prevent debuggers from attaching
// This also prevents minidump creation

typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

void anti_dump_debug_port(void) {
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll"), "NtSetInformationProcess");
    
    // ProcessDebugFlags (31) - set to 1 to clear debug object handle
    ULONG debug_flags = 1;
    NtSetInformationProcess(GetCurrentProcess(), 31, &debug_flags, sizeof(debug_flags));
    
    // ProcessDebugPort (7) - set to 0 to clear debug port
    ULONG debug_port = 0;
    NtSetInformationProcess(GetCurrentProcess(), 7, &debug_port, sizeof(debug_port));
}
```

---

## 9. Anti-Disassembly Techniques

### 9.1 Ambiguous Instructions

```asm
; Technique 1: Conditional jumps with opposite conditions
    jz   real_code
    jnz  real_code
    ; The above two jumps always execute real_code
    ; But a disassembler may try to disassemble the fall-through

; Technique 2: Call/pop pattern
    call $+5            ; Push next instruction address
    pop  eax            ; Pop it — eax now holds current address
    ; Disassembler might not handle overlap correctly
    
; Technique 3: Overlapping instructions (x86 CISC encoding)
    ; At offset 0: EB 01         jmp short skip
    ; At offset 2: 68             ; This byte is part of the next instruction
    ; But if jumped into at offset 2:
    ; At offset 2: 68 XX XX XX XX push 0xXXXXXXXX
    
; Technique 4: RET as a jump
    push target_address    ; Push target onto stack
    ret                     ; "Return" to target_address — effectively a jump
    ; Disassemblers often don't follow ret-based control flow

; Technique 5: SEH-based control flow
    ; Set up Structured Exception Handler
    ; Trigger exception (division by zero, access violation)
    ; Execution continues at the SEH handler
    ; Disassemblers that don't follow exceptions will miss this path

; Technique 6: Stack-based indirect jumps
    ; Push multiple return addresses, then use ret for dispatch
    push handler_1
    push handler_2
    push handler_3
    ret                 ; Jumps to handler_3 (last pushed)
```

### 9.2 Self-Modifying Code

```c
// Self-modifying code: the binary modifies its own instructions at runtime

void self_modifying_example(void) {
    // Original code at this location: return 0
    unsigned char *code = (unsigned char *)self_modifying_example;
    
    // Unlock memory page for writing
    DWORD old_protect;
    VirtualProtect(code, 4096, PAGE_READWRITE, &old_protect);
    
    // Modify the first instruction to: mov eax, 1
    // B8 01 00 00 00    mov eax, 1
    code[0] = 0xB8;  // mov eax, imm32 opcode
    code[1] = 0x01;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    
    // Re-lock memory
    VirtualProtect(code, 4096, old_protect, &old_protect);
    
    // Flush instruction cache (necessary on some architectures)
    FlushInstructionCache(GetCurrentProcess(), code, 4096);
    
    // Now calling self_modifying_example returns 1 instead of 0
}

// Detection and Handling:
// 1. Use memory breakpoints on executable pages
// 2. Dump from memory AFTER modifications have been applied
// 3. Trace execution to see the final instruction stream
// 4. Use page-level write-protect breakpoints (PAGE_GUARD)
```

---

## 10. DRM & Anti-Cheat Analysis

### 10.1 Denuvo Anti-Tamper

Denuvo is a popular DRM/anti-tamper system used in video games:

```
Denuvo Architecture:
1. Game code is encrypted with unique per-hardware key
2. Runtime decryption triggers specific to game events
3. Steam/API authentication before decryption keys are provided
4. Periodic re-verification with online servers
5. Anti-debugging and anti-dumping measures

Key characteristics:
- Performance impact from encryption/decryption overhead
- Not outright cracked but bypassed by removing triggers
- Takes increasingly longer to bypass with each version
- Denuvo v1-v3: cracked relatively quickly
- Denuvo v4+: significantly harder, months to years

Analysis approach:
1. Identify Denuvo modules (usually DRM.dll or similar)
2. Find trigger functions (calls that verify/decrypt)
3. Patch trigger functions to return success
4. This avoids full deobfuscation of Denuvo's VM
```

### 10.2 EAC (Easy Anti-Cheat) & BattlEye

```
EAC Architecture:
1. Kernel-mode driver (EasyAntiCheat.sys)
2. User-mode service
3. Integrity checks of game code
4. Memory scanning for known cheats
5. Detection of debugging/monitoring tools

BattlEye Architecture:
1. Kernel-mode driver (BEDaisy.sys)
2. User-mode shell code injected into game
3. CRC checks of game memory sections
4. Process and thread enumeration
5. Driver signature enforcement

Anti-Cheat Detection Methods:
- Scan process list for known cheat processes
- Enumerate loaded modules for suspicious DLLs
- Check for hardware breakpoints (DR0-DR3)
- Monitor file system for cheat files
- Verify game memory integrity (checksums)
- Detect memory modification (ReadProcessMemory from external processes)
- Scan for code caves (unexpected executable regions)
- Monitor keyboard/mouse input for automation
- Verify driver signatures

Analysis approach for security research:
1. Load driver in test environment
2. Use WinDBG with kernel debugging to analyze driver
3. Reverse the communication protocol between user-mode and kernel-mode
4. Identify detection heuristics and thresholds
5. Document all detection vectors
```

---

## 11. Deobfuscation Tools & Techniques

### 11.1 D-810 (IDA Pro Deobfuscation Plugin)

```
D-810 is an IDA Pro plugin that applies deobfuscation rules at the 
microcode level, effectively removing obfuscation in-place.

Supported deobfuscation patterns:
- Control flow flattening (CFF) removal
- Opaque predicate elimination
- Dead code removal
- Expression simplification
- Redundant instruction removal
- Math identity application (x * 1 = x, x + 0 = x, etc.)

Installation:
1. Download D-810 from https://gitlab.com/eshard/d810
2. Copy d810.py and d810 directory to IDA plugins folder
3. Restart IDA
4. Edit → Plugins → D-810

Usage:
1. Load obfuscated binary in IDA
2. Wait for initial auto-analysis
3. Enable D-810 deobfuscation passes
4. The deobfuscated code appears in the disassembly
```

### 11.2 OLLVM Deobfuscation

```bash
# OLLVM deobfuscation workflow

# Step 1: Symbolic execution to identify opaque predicates
# Using angr
python3 << 'EOF'
import angr
import claripy

proj = angr.Project('obfuscated_binary', auto_load_libs=False)

# Find the function to deobfuscate
cfg = proj.analyses.CFGFast()

# Symbolic execution to prove predicates
for func_addr in cfg.kb.functions:
    func = cfg.kb.functions[func_addr]
    # Check each branch condition
    # If one side is always true/false, it's an opaque predicate
    # Remove the false branch
EOF

# Step 2: CFG simplification
# After opaque predicate removal, dead code elimination
# Control flow simplification

# Step 3: Control flow deflattening
# Using tool: https://github.com/cq674350529/deflat
# Or manual approach in IDA:
# 1. Identify the state variable (typically on stack or in register)
# 2. Remove the switch/dispatch structure
# 3. Reconnect basic blocks based on state transitions
# 4. Remove the state variable assignments

# Step 4: String decryption
# Run in emulator or debugger, dump strings after decryption
python3 << 'EOF'
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

mu = Uc(UC_ARCH_X86, UC_MODE_32)
# ... set up memory, load binary ...
# ... emulate decryption function ...
# ... read decrypted strings from memory ...
EOF
```

### 11.3 Binary Deobfuscation with Unicorn

```python
# Using Unicorn emulator for code deobfuscation
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn import UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EIP

def deobfuscate_function(binary_data, func_addr, arch='x86'):
    """Emulate obfuscated function and extract simplified behavior."""
    
    if arch == 'x86':
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        BASE = 0x10000000
        STACK = 0x20000000
        
        # Map memory
        uc.mem_map(BASE, 10 * 1024 * 1024)
        uc.mem_map(STACK, 0x100000)
        
        # Load binary
        uc.mem_write(BASE, binary_data)
        
        # Set up stack
        uc.reg_write(UC_X86_REG_ESP, STACK + 0x8000)
        
        # Emulate function
        try:
            uc.emu_start(BASE + func_addr, BASE + func_addr + 0x1000)
        except Exception as e:
            print(f"Emulation error: {e}")
        
        # Get return value and side effects
        ret_val = uc.reg_read(UC_X86_REG_EAX)
        
        # Read memory writes (need to hook first)
        return ret_val
    
    return None
```

### 11.4 Comprehensive Deobfuscation Pipeline

```bash
# Complete deobfuscation pipeline for OLLVM-protected binary

# 1. Binary triage
file target_binary
strings target_binary | head -100
readelf -h target_binary

# 2. Load into Ghidra
# Import binary, set correct architecture
# Run initial analysis

# 3. Identify obfuscation patterns
# Control flow flattening: look for switch-based dispatchers
# Opaque predicates: look for always-true/false conditions
# String encryption: look for XOR loops, RC4, AES calls

# 4. Remove control flow flattening
# Option A: Use D-810 plugin (IDA Pro)
# Option B: Manual deflattening in Ghidra
# Option C: Use deflat.py (angr-based deflattener)

# 5. Remove opaque predicates
# Use symbolic execution to prove always-true/false conditions
# Patch conditional jumps to unconditional jumps or NOP them

# 6. Decrypt strings
# Option A: Set breakpoint after decryption, dump
# Option B: Emulate decryption functions
# Option C: Write Frida script to hook decryption and log results

# 7. Remove junk code
# Dead code elimination (push/pop pairs, redundant movs)
# Use IDA/Ghidra decompilation which automatically removes some junk

# 8. Rename recovered symbols
# Apply recovered function names, variable names, and comments

# 9. Generate clean report
# Document all obfuscation techniques found
# Document all deobfuscation steps taken
# Provide cleaned binary or analysis project
```

> **Cross-reference**: See [02b_dynamic_analysis.md](02b_dynamic_analysis.md) for anti-debugging bypass techniques. See [03a_malware_analysis.md](03a_malware_analysis.md) for malware anti-analysis techniques. See [06_re_tooling_workflow.md](06_re_tooling_workflow.md) for tool setup details.

---

*This document is part of the Deep Researcher Reverse Engineering track. Deobfuscation and anti-tamper bypass should only be performed on binaries you are authorized to analyze.*

## References

1. Dennis Yurichev, "Reverse Engineering for Beginners," https://yurichev.com/writings/RE_for_beginners-en.pdf
2. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
3. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
4. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
5. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
6. Phrack Magazine, various issues, http://phrack.org/
7. DEF CON conference proceedings, https://www.defcon.org/
8. SANS Institute, "Reverse Engineering Malware" (FOR610), https://www.sans.org/
9. Control Flow Flattening research, "Obfuscating C++ via Control Flow Flattening," Laszlo & Kiss, 2009.
10. Tigress C obfuscator, https://tigress.wtf/