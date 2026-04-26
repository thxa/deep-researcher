# Vulnerability Discovery Methodology — Code Audit & Reverse Engineering

> A comprehensive technical reference for security researchers, CTF competitors, and vulnerability analysts.

---

## Table of Contents

1. [Source Code Auditing](#1-source-code-auditing)
2. [Binary Reverse Engineering](#2-binary-reverse-engineering)
3. [Kernel Binary Analysis](#3-kernel-binary-analysis)
4. [Practical CTF RE Scenarios](#4-practical-ctf-re-scenarios)
5. [Patch Diffing & Variant Analysis](#5-patch-diffing--variant-analysis)

---

## 1. Source Code Auditing

### 1.1 Systematic Approach to Auditing Large Codebases

Auditing a large codebase without methodology yields missed bugs and wasted time. The disciplined approach follows a top-down funnel:

**Phase 1 — Reconnaissance & Architecture Understanding**

```
1. Identify the attack surface:
   - Network-facing entry points (sockets, HTTP handlers, RPC)
   - File parsers (images, documents, archives, media)
   - IPC boundaries (D-Bus, Unix sockets, shared memory)
   - Privilege boundaries (setuid, sandbox escapes, syscall interfaces)

2. Map trust boundaries:
   - Where does untrusted data enter?
   - Where is it consumed by privileged code?
   - What sanitization occurs between entry and consumption?

3. Build a function call graph frominput sources to dangerous sinks.
```

**Phase 2 — Entry Point Enumeration**

```bash
# Find network-facing entry points
rg -n "socket\(|bind\(|listen\(|accept\(" --type c
rg -n "recv\(|recvfrom\(|recvmsg\(" --type c

# Find file parsers
rg -n "fopen\|fread\|mmap\|open\s*\(" --type c

# Find IOCTL handlers
rg -n "\.unlocked_ioctl\s*=|\.ioctl\s*=" --type c

# Find syscall handlers (Linux kernel)
rg -n "SYSCALL_DEFINE|COMPAT_SYSCALL_DEFINE" --type c
```

**Phase 3 — Taint Tracking**

Trace data flow from each entry point to every sink. For each path, verify:

| Check | What to Verify |
|-------|---------------|
| Bounds validation | Is every array index, `memcpy` size, `strlen` result checked before use? |
| Integer overflow | Can arithmetic on sizes/lengths wrap around? |
| Type confusion | Can attacker-controlled data influence type casts? |
| Use-after-free | Are freed objects truly unreachable from all paths? |
| TOCTOU | Is there a race window between check and use? |

**Phase 4 — Focus on High-Value Targets**

Prioritize code that runs with elevated privileges, handles untrusted input, or processes complex data formats.

### 1.2 Finding Dangerous Patterns

#### 1.2.1 Classic Dangerous Function Calls

**Buffer Operations — Missing or Incorrect Size Checks:**

```c
// DANGEROUS: No bounds checking at all
char buf[256];
gets(buf);                    // Never use gets()
strcpy(buf, input);           // No length check
sprintf(buf, "%s/%s", a, b);  // Concatenation can overflow
strcat(buf, suffix);          // Appends without bounds

// DANGEROUS: Size from attacker or incorrect
char buf[256];
memcpy(buf, src, attacker_len);  // Len from untrusted source
snprintf(buf, sizeof(buf), ...); // OK for buf, but check truncation
strncpy(buf, src, n);             // No NUL termination if src >= n

// SUBTLE: Off-by-one
char buf[N];
memcpy(buf, src, N);  // OK if N is exact capacity
buf[N] = '\0';        // Wait — is buf sized N or N+1?
```

**Systematic grep for dangerous patterns:**

```bash
# Dangerous function calls
rg -n "memcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?!sizeof)" --type c
rg -n "strcpy\s*\(|sprintf\s*\(\s*\w+\s*,(?![^%]*%ld)" --type c
rg -n "gets\s*\(" --type c

# Integer issues
rg -n "unsigned.*\+|unsigned.*\*|size_t.*\+" --type c
rg -n "kmalloc\s*\(\s*\w+\s*\*\s*\w+" --type c  # Potential integer overflow in alloc

# Format string
rg -n "printf\s*\(\s*\w+\s*\)" --type c       # printf(user_input) = format string
rg -n "syslog\s*\(\s*LOG_\w+\s*,\s*\w+\s*\)" --type c
```

#### 1.2.2 Integer Issues

```c
// INTEGER OVERFLOW in allocation
// If count and elem_size are attacker-controlled:
size_t total = count * elem_size;  // Can overflow!
buf = malloc(total);              // Allocates small buffer
// Then memcpy(buf, data, count * elem_size) overflows

// UNDERFLOW
unsigned int size = hdr->len - OFFSET;
// If hdr->len < OFFSET, size wraps to ~4 billion

// SIGNED/UNSIGNED MISMATCH
int len = get_length();       // Can be negative
if (len < MAX_SIZE)           // Signed comparison
    memcpy(buf, data, len);   // Implicit cast to size_t → huge

// TRUNCATION
uint64_t big_len = ...;
uint32_t small_len = big_len;  // Truncation on 64-bit → attacker-controlled
```

**Audit pattern — always check size computations before allocations:**

```c
// SAFE pattern
if (count > 0 && elem_size > SIZE_MAX / count)
    return -EINVAL;
total = count * elem_size;
```

#### 1.2.3 Use-After-Free and Double Free

```c
// USE-AFTER-FREE
object = lookup(id);
if (!object) return -ENOENT;
mutex_unlock(&lock);
free_object(object);     // Freed
// Another thread can reallocate this memory
use(object->field);      // UAF!
```

```bash
# Find potential UAF patterns
rg -n "kfree\s*\(|free\s*\(" --type c -A2 | rg "->[a-zA-Z_]"
rg -n "put_device\s*\(|kobject_put\s*\(" --type c -A2 | rg "->[a-zA-Z_]"
```

#### 1.2.4 TOCTOU (Time-of-Check-to-Time-of-Use)

```c
// Classic TOCTOU in kernel copy_from_user
if (len > MAX_SIZE)
    return -EINVAL;
// Attacker can modify 'len' in userspace between check and copy
copy_from_user(kernel_buf, user_ptr, len);  // RACE!

// SAFE: Use an atomic copy
if (copy_from_user(&len, user_ptr, sizeof(len)))
    return -EFAULT;
if (len > MAX_SIZE)
    return -EINVAL;
```

### 1.3 Kernel Code Audit Methodology

#### 1.3.1 Syscall Handlers

```bash
# Locate all syscall definitions
rg -n "SYSCALL_DEFINE[0-9]\(" --type c -l

# For each syscall, check:
# 1. Does it copy_from_user? Is the size validated?
# 2. Are there privileged operations without capability checks?
# 3. Are error paths cleaned up properly (no leaked references)?
# 4. Are there race conditions (missing locking)?
```

Key checks for every syscall handler:

```
┌─────────────────────────────────────────────────────────────────┐
│ SYSCALL AUDIT CHECKLIST                                         │
├─────────────────────────────────────────────────────────────────┤
│ □ All copy_from_user sizes validated before use                 │
│ □ No double fetch from userspace (TOCTOU)                       │
│ □ Capability checks (capable(), ns_capable())                   │
│ □ Proper reference counting (get/put pairs)                     │
│ □ Lock ordering consistent (no ABBA deadlocks)                  │
│ □ All error paths free resources (no mem/fd leaks)              │
│ □ Integer overflow on size calculations                         │
│ □ Signal/pfault handling correct                                │
│ □ Bounds checked on all array accesses                          │
│ □ No info leaks (memset structs before copy_to_user)            │
└─────────────────────────────────────────────────────────────────┘
```

#### 1.3.2 IOCTL Handlers

```c
// Typical vulnerable pattern
static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct user_data data;
    // No capability check!
    // No Switch default: return -ENOTTY!
    switch (cmd) {
    case CMD_WRITE:
        // copy_from_user with unchecked size
        if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
            return -EFAULT;
        process_data(&data);  // Kernel processing without validation
        break;
    }
    return 0;
}
```

IOCTL audit focus areas:
- **Missing `capable()` checks**: Can unprivileged users invoke this?
- **Missing `copy_from_user` / `copy_to_user`**: Direct user pointer dereference in kernel
- **Missing command validation**: Default case must return `-ENOTTY`
- **Size mismatches**: `sizeof(struct)` differs between kernel and user (compat/ioctl32)
- **Command structure**: ioctls should use `_IOR/_IOW/_IOWR` macros with proper size encoding

#### 1.3.3 /proc and /sys Handlers

```bash
# Find proc/sysfs show/store functions
rg -n "\.show\s*=|\.store\s*=" --type c
rg -n "proc_create|proc_create_data" --type c
rg -n "sysfs_create_file|device_create_file" --type c
```

Common bugs in `/proc` handlers:
- `seq_read` buffer overflow from large output
- `proc_write` with insufficient input validation
- Information leak from kernel stack (uninitialized padding)
- Race between `proc_write` and `proc_read`

### 1.4 Diff Auditing — Finding 1-Days and Related Vulnerabilities

When a security fix is published, the fix itself often reveals where similar bugs exist.

**Step-by-step diff auditing:**

```bash
# Clone the repo and identify the fix commit
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux

# Find security-related commits (e.g., from oss-sec)
git log --all --oneline --grep="CVE-" --since="2024-01-01"

# View the actual fix
git show <commit-hash>

# See what changed in context
git show --stat <commit-hash>
git diff <commit-hash>^..<commit-hash>
```

**What to look for in a diff:**

```
1. THE FIX PATTERN:
   If the fix adds a bounds check, search the ENTIRE codebase for
   the same missing check pattern.

2. THE VULNERABLE FUNCTION:
   Find all callers of the patched function. Might the same
   vulnerable pattern exist in sibling functions?

3. THE DATA STRUCTURE:
   If a struct field is the issue, find all places that struct
   is handled similarly.

4. CONCURRENT FIXES:
   Often, security researchers only report one instance. The
   developer might fix related cases — check the same author's
   recent commits.
```

**Example — The Drama of `sock_diag` Bugs:**

When CVE-2013-1763 was found (an overflow in `sock_diag_netsk`, a `__u8` was used to index an array but came from an `enum` that could exceed 255), the fix added a bounds check. Auditors then searched for similar patterns:
- Found that `SOCK_DIAG_BY_FAMILY` lacked proper validation
- Found `sock_diag_rcv_msg` had the same `__u8` cast issue
- This led to 3 additional CVEs from variant analysis

### 1.5 Static Analysis Tools

#### 1.5.1 CodeQL

```bash
# Install CodeQL CLI
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
export PATH="$PWD/codeql:$PATH"

# Create a database for a C project
codeql database create myproject-db --language=c --source-root=/path/to/src

# Run built-in security queries
codeql database analyze myproject-db \
    codeql/cpp-queries:Security/CWE-022 \
    codeql/cpp-queries:Security/CWE-119 \
    codeql/cpp-queries:Security/CWE-190 \
    codeql/cpp-queries:Security/CWE-416 \
    --format=csv --output=results.csv
```

**Custom CodeQL query for finding unchecked `copy_from_user`:**

```ql
/**
 * @name Unchecked copy_from_user size
 * @description Finds copy_from_user calls where the size
 *              parameter is not validated before use.
 * @kind problem
 * @problem.severity error
 * @id cpp/unchecked-copy-from-user
 */
import cpp

from FunctionCall fc, VariableAccess va
where
    fc.getTarget().getName() = "copy_from_user" and
    va = fc.getArgument(2).getAUse() and
    not exists(GuardCondition gc |
        gc.controls(va.getBasicBlock()) and
        gc.getCondition().(RelationalOperation).getAnOperand() = va
    )
select fc, "copy_from_user with unchecked size parameter"
```

#### 1.5.2 Semgrep

```bash
# Install
pip install semgrep

# Run community rules + custom
semgrep --config auto /path/to/src

# Run specific security rules
semgrep --config p/cwe-top-25 /path/to/src
semgrep --config p/security-audit /path/to/src
```

**Custom Semgrep rule for kernel `copy_from_user` race:**

```yaml
rules:
  - id: kernel-double-fetch
    patterns:
      - pattern: |
          copy_from_user($VAR, $PTR, sizeof($TYPE));
          ...
          copy_from_user($VAR, $PTR, sizeof($TYPE));
    message: "Potential double-fetch from userspace — TOCTOU vulnerability"
    severity: ERROR
    languages: [c]

  - id: unchecked-ioctl-size
    patterns:
      - pattern: |
          case $CMD:
              copy_from_user($VAR, (void __user *)$ARG, $SIZE);
    pattern-not: |
          case $CMD:
              if ($SIZE > $LIMIT) return -EINVAL;
              copy_from_user($VAR, (void __user *)$ARG, $SIZE);
    message: "IOCTL copies from user without size validation"
    severity: WARNING
    languages: [c]
```

#### 1.5.3 Coccinelle

Coccinelle excels at semantic patch matching — finding code patterns that are structurally similar even when variable names differ.

```bash
# Install
apt install coccinelle

# Run a semantic patch
spatch --sp-file find_memcpy_overflow.cocci --dir linux/
```

**Finding `memcpy` with unchecked size:**

```c
// find_memcpy_overflow.cocci
@@
expression dest, src, len;
statement S;
@@
* memcpy(dest, src, len);
  ... when != if (len > ...) S
```

**Finding missing `NULL` checks after `kmalloc`:**

```c
// find_missing_null_check.cocci
@@
type T;
T *ptr;
expression E;
@@
  ptr = kmalloc(E, GFP_KERNEL);
+ if (!ptr) return -ENOMEM;
  ... when != ptr == NULL
      when != !ptr
```

#### 1.5.4 Sparse — Kernel-Specific Checker

```bash
# Build kernel with sparse
make C=2 W=1 drivers/some_driver/

# Common sparse warnings:
# - __user pointer dereference without copy_from_user
# - incorrect address space annotations
# - endianness mismatches
# - locking context violations
```

### 1.6 Code Review Checklist for Memory Safety

```
╔═══════════════════════════════════════════════════════════════════╗
║                   MEMORY SAFETY AUDIT CHECKLIST                  ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ BUFFER OVERFLOWS                                                  ║
║  □ All array indexes within bounds                                ║
║  □ All memcpy/memmove sizes validated                             ║
║  □ No gets() usage                                                ║
║  □ snprintf/snprintf truncation handled                           ║
║  □ Off-by-one in loop bounds (<= vs <)                           ║
║                                                                   ║
║ INTEGER ISSUES                                                    ║
║  □ Multiplication overflow in size calculations                   ║
║  □ Signed/unsigned mismatch in comparisons                       ║
║  □ Cast truncation (64→32 bit)                                   ║
║  □ Underflow in subtraction (unsigned wrap)                      ║
║                                                                   ║
║ USE-AFTER-FREE                                                    ║
║  □ No access after free/kfree                                     ║
║  □ Reference counting correct (get/put paired)                    ║
║  □ Lock protects object lifetime                                  ║
║  □ No dangling references in lists/trees                          ║
║                                                                   ║
║ RACE CONDITIONS                                                   ║
║  □ Lock held during shared data access                            ║
║  □ No TOCTOU (check-then-use patterns)                           ║
║  □ Atomic operations where needed                                 ║
║  □ No double-fetch from userspace                                 ║
║                                                                   ║
║ INFO LEAKS                                                        ║
║  □ Structs zeroed before copy_to_user                             ║
║  □ No kernel pointers leaked to userspace                         ║
║  □ Padding fields don't contain data                              ║
║                                                                   ║
║ ERROR HANDLING                                                    ║
║  □ All allocation failures handled                                ║
║  □ All error paths free resources (no leaks)                      ║
║  □ No consumed references on error paths                          ║
║  □ goto cleanup pattern used consistently                         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 2. Binary Reverse Engineering

### 2.1 Static Analysis Workflow with Ghidra

**Initial Setup:**

```bash
# Launch Ghidra headless analyzer
analyzeHeadless /tmp/ghidra_project target_binary \
    -import binary \
    -postScript AnalyzeDangerousCalls.java \
    -scriptPath /path/to/scripts
```

**Workflow:**

```
┌─────────────────────────────────────────────────────────────┐
│                  GHIDRA RE WORKFLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. IMPORT & INITIAL ANALYZE                                  │
│     → Auto-analysis (on by default)                           │
│     → Check "Decompiler Parameter ID" in analysis options     │
│                                                               │
│  2. HIGH-LEVEL OVERVIEW                                       │
│     → Window → Function Call Graph                            │
│     → Search → For Strings                                    │
│     → Symbols Tree → Exports                                  │
│                                                               │
│  3. ENTRY POINTS IDENTIFICATION                               │
│     → main(), WinMain(), DllMain()                            │
│     → Registered callbacks (atexit, signal handlers)          │
│     → vtable entries (constructors)                           │
│                                                               │
│  4. Taint FROM INPUTS                                         │
│     → Network: recv(), read(), fread()                        │
│     → Files: open(), fopen()                                  │
│     → Arguments: argv, getenv()                               │
│     → Trace forward through calls/data flow                   │
│                                                               │
│  5. ANNOTATE AS YOU GO                                        │
│     → Rename functions (right-click → Rename Function)         │
│     → Rename variables in decompiler                          │
│     → Add bookmarks for interesting locations                  │
│     → Define structures (Data → Create Structure)             │
│                                                               │
│  6. VULNERABILITY PATTERN SEARCH                              │
│     → See Section 2.3                                         │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### 2.2 Function Identification and Naming Conventions

**Identifying library functions:**

Ghidra's signature matching (Function ID) identifies known library functions. For stripped binaries:

```bash
# Use Ghidra's FID (Function ID) analyzer
# Edit → Analyze → Function ID Search

# For custom signatures, use:
# Window → Function ID Classifier
```

**Manual function identification heuristics:**

| Pattern | Likely Function |
|---------|----------------|
| `call malloc; test rax,rax; jz <exit>` | Allocator wrapper |
| `call malloc; call memset/rclear` | `calloc` / `zcalloc` |
| `call printf; call exit` | Error handler (`errx`, `die`) |
| Loop with `*dst++ = *src++` until `\0` | `strcpy` inline |
| `xor eax,eax; rep stosb` | `memset(,0,)` |
| `cmp [reg+offset], 0; jg/jl <loop>` | Bounds-checked copy |
| Call with `(void (*)(void*))fn_ptr` | Callback dispatcher |
| Vtable pattern: `*[reg+offset]` then `call rax` | Virtual dispatch |

**Naming conventions for RE annotations:**

```
FUN_00401234           → Unknown, not yet analyzed
FUN_00401234_parse_hdr → Partially analyzed
parse_request_header   → Fully understood
parse_request_header_VULN → Contains vulnerability
```

### 2.3 Recognizing Vulnerable Patterns in Compiled Code

**Stack Buffer Overflow Signatures:**

```c
// Source:
char buf[64];
strcpy(buf, input);

// Decompiled (Ghidra):
void vuln(char *input) {
    char local_48 [64];
    strcpy(local_48, input);  // No bounds check!
}
```

In assembly, look for:
- `rep movsb/movsq` with length from unknown source
- Calls to `strcpy`/`sprintf`/`gets` with stack destination
- Large stack allocations (`sub rsp, 0x200`) with unbounded copies

**Heap Overflow / Use-After-Free:**

```c
// Source:
obj = malloc(sizeof(struct DATA));
free(obj);
obj->callback();  // UAF

// Decompiled:
pvVar1 = malloc(0x20);
free(pvVar1);
(*pvVar1->callback)(pvVar1);  // Use after free!
```

**Format String:**

```c
// Source:
printf(user_input);

// Decompiled:
printf(param_1);  // param_1 is user-controlled → format string bug!
```

**Integer Overflow:**

```c
// Source:
buf = malloc(count * elem_size);

// Decompiled:
iVar1 = param_2 * param_3;    // 32-bit multiply can overflow
pvVar1 = malloc(iVar1);        // Small allocation
memcpy(pvVar1, src, param_2 * param_3);  // Large copy → heap overflow
```

### 2.4 Cross-Referencing and Data Flow Analysis

**Ghidra cross-references (XREFs):**

```
1. In Decompiler view, right-click a variable → "Find References"
2. In Listing view, right-click an address → "References → Find References To"
3. Use the XREF window: Window → References →х

Key XREF types:
- DATA ref:  Address is read/written as data
- CALL ref:  Address is called as a function
- JUMP ref:  Address is a branch target
- READ ref:  Address is read
- WRITE ref: Address is written
```

**Data flow analysis — tracking attacker input:**

```
1. Identify entry: recv(fd, buf, len, 0)
2. Find XREFs to 'buf'
3. Follow through each function that reads 'buf'
4. At each point, check: Does size validation happen before use?
5. Build a mental (or written) data flow graph:

   recv(fd, user_buf, len, 0)
     → parse_header(user_buf)
       → memcpy(local_buf, user_buf + 8, hdr_len)  ← OVERFLOW!
```

### 2.5 Scripting Ghidra with Python/Java for Batch Analysis

**Python 3 (Jython) Script — Find All Dangerous Function Calls:**

```python
# @category Security
# @runtime Python 3

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompileOptions, DecompInterface

DANGEROUS = {
    'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf',
    'scanf', 'fscanf', 'sscanf',
    'memcpy', 'memmove',  # Context-dependent
    'system', 'popen', 'execve', 'execl', 'execlp',
    'free',              # Double-free / UAF focus
}

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 60)
print("DANGEROUS FUNCTION CALL ANALYSIS")
print("=" * 60)

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

for func_name in DANGEROUS:
    symbols = currentProgram.getSymbolTable().getSymbols(func_name)
    for sym in symbols:
        addr = sym.getAddress()
        refs = getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            caller = fm.getFunctionContaining(from_addr)
            caller_name = caller.getName() if caller else "unknown"

            # Decompile the caller for context
            results = decompiler.decompileFunction(caller, 60, monitor)
            if results and results.getDecompiledFunction():
                code = results.getDecompiledFunction().getC()

            print(f"[!] {func_name} called in {caller_name} at {from_addr}")
            print(f"    XREF: {ref}")

print("\n" + "=" * 60)
print("STACK BUFFER ANALYSIS (large allocations + strcpy)")
print("=" * 60)

for func in fm.getFunctions(True):
    body = func.getBody()
    # Check for large stack allocations
    for block in body:
        size = block.getMax().subtract(block.getMin())
        if size > 256:  # Large stack frame
            results = decompiler.decompileFunction(func, 60, monitor)
            if results and results.getDecompiledFunction():
                code = results.getDecompiledFunction().getC()
                if any(d in code for d in ['strcpy', 'sprintf', 'gets']):
                    print(f"[!!!] {func.getName()} at {func.getEntryPoint()}: "
                          f"Large stack ({size}) + dangerous function")

decompiler.dispose()
```

**Java Script — Find All `malloc` + `strcpy` Patterns:**

```java
// @category Security
// Find malloc-then-strcpy patterns (heap overflow risk)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FindMallocStrcpy extends GhidraScript {
    @Override
    public void run() throws Exception {
        var decompiler = new ghidra.app.decompiler.DecompInterface();
        decompiler.openProgram(currentProgram);

        var fm = currentProgram.getFunctionManager();

        for (var func : fm.getFunctions(true)) {
            var results = decompiler.decompileFunction(func, 30, monitor);
            if (results == null || results.getDecompiledFunction() == null)
                continue;

            String code = results.getDecompiledFunction().getC();
            if (code.contains("malloc") && code.contains("strcpy")) {
                printf("[!] %s at %s: malloc + strcpy pattern\n",
                    func.getName(), func.getEntryPoint());
            }
        }
        decompiler.dispose();
    }
}
```

### 2.6 Radare2 for Quick RE Tasks

```bash
# Quick analysis pipeline
r2 -AA binary          # Load with full analysis

# Information gathering
iI                     # Binary info (arch, bits, endian)
iS                     # Sections
is                     # Symbols
ii                     # Imports
iz                     # Strings

# Function analysis
afl                    # List all functions
afn main sym.func_001  # Rename function
afv                    # List local variables
pdf @ sym.main         # Disassemble function

# Cross-references
axt @ sym.printf       # Find calls to printf
axf @ 0x00401000       # Find references FROM address

# Seek and analyze
s sym.main             # Seek to main
VV                     # Visual mode (graph view)
pds                    # Print function summary (decompiled-like)

# Pattern search
/w malloc              # Search for strings
/x 90909090            # Search for byte pattern (NOP sled)

# Scripting with r2pipe
pip install r2pipe
```

**Python r2pipe script — Batch function call graph:**

```python
import r2pipe
import json

r2 = r2pipe.open("./target_binary")
r2.cmd("aaa")  # Full analysis

functions = json.loads(r2.cmd("aflj"))

dangerous_imports = [
    "sym.imp.strcpy", "sym.imp.sprintf", "sym.imp.gets",
    "sym.imp.system", "sym.imp.execve", "sym.imp.popen"
]

for imp in dangerous_imports:
    xrefs = json.loads(r2.cmd(f"axtj @ {imp}"))
    for xref in xrefs:
        caller = xref.get('fcn_name', 'unknown')
        print(f"[!] {imp} called from {caller} at {xref.get('from', '???')}")

r2.quit()
```

### 2.7 IDA Pro Tips for Advanced Analysis

**IDAPython — Find vulnerable patterns:**

```python
import idautils
import idc
import idaapi

# Find all calls to dangerous functions
dangerous = ['strcpy', 'sprintf', 'gets', 'system', 'execve']

for name in dangerous:
    addr = idc.get_name_ea_simple(name)
    if addr == idc.BADADDR:
        # Try with underscore prefix (Windows)
        addr = idc.get_name_ea_simple(f"_{name}")
    if addr != idc.BADADDR:
        for xref in idautils.XrefsTo(addr):
            caller = idc.get_func_name(xref.frm)
            print(f"[!] {name} called from {caller} at {hex(xref.frm)}")

# Find large stack allocations (potential overflow)
for func_ea in idautils.Functions():
    frame = idaapi.get_frame(func_ea)
    if frame:
        frame_size = idc.get_struc_size(frame)
        if frame_size > 0x200:  # Large stack frame
            func_name = idc.get_func_name(func_ea)
            print(f"[!] Large stack frame ({hex(frame_size)}) in {func_name}")

# Find XOR loops (potential decode routines)
for seg_ea in idautils.Segments():
    for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
        if idc.print_insn_mnem(head) == 'xor':
            op1 = idc.print_operand(head, 0)
            op2 = idc.print_operand(head, 1)
            if op1 != op2:  # Not zeroing (xor eax,eax)
                func = idc.get_func_name(head)
                print(f"[?] XOR at {hex(head)} in {func}: {op1} ^ {op2}")
```

**Hex-Rays microcode analysis (advanced):**

```
1. View → Open subviews → Hex-Rays Microcode (M-Code)
2. Strip higher-level optimizations to see raw operations
3. Useful for identifying:
   - Compiler-inserted security checks (canary verification)
   - Optimized integer operations that eliminate overflow checks
   - Hidden control flow obscured by optimization
```

---

## 3. Kernel Binary Analysis

### 3.1 Analyzing Kernel Modules (.ko Files)

```bash
# Extract information from a kernel module
file driver.ko                    # File type
modinfo driver.ko                 # Module metadata
readelf -h driver.ko              # ELF header
readelf -S driver.ko              # Section headers
readelf -s driver.ko              # Symbol table (if not stripped)
readelf --debug-dump=info driver.ko  # DWARF debug info

# Key sections to examine
readelf -S driver.ko | grep -E "__param|__modver|__versions"

# Find module parameters (attack surface!)
strings driver.ko | grep -E "parm:|__param"
# Parameters are user-controllable input to the module

# Find IOCTL handlers
strings driver.ko | grep -i "ioctl"
# Or disassemble and search for unlocked_ioctl/fops structures

# Extract the kernel version compatibility
strings driver.ko | grep "vermagic"
```

**Loading a .ko into Ghidra:**

```
1. File → Import → select .ko file
2. Set language: x86:LE:64:default (or appropriate arch)
3. After auto-analysis, check:
   - __param section for module parameters
   - init_module / cleanup_module functions
   - file_operations structures (.unlocked_ioctl, .read, .write)
   - platform_driver / pci_driver registration
4. Create structures for detected vtables
```

### 3.2 Understanding Kernel Symbols and Exports

```bash
# System map — maps addresses to symbol names
# Usually at /boot/System.map-$(uname -r)
grep "T$" /boot/System.map-$(uname -r) | head    # Text (code) symbols
grep " D " /boot/System.map-$(uname -r) | head    # Data symbols
grep " B " /boot/System.map-$(uname -r) | head    # BSS (uninitialized)

# /proc/kallsyms — runtime kernel symbols (requires root or kptr_restrict=0)
cat /proc/kallsyms | grep "T sys_"    # Syscall entry points
cat /proc/kallsyms | grep "T vfs_"   # VFS functions
cat /proc/kallsyms | grep "D "       # Data symbols

# Module symbols
cat /proc/modules                    # Loaded modules with sizes
cat /proc/kallsyms | grep "\[driver\]"  # Symbols from specific module

# Exported symbols (available for modules to use)
cat /proc/kallsyms | grep " T " | wc -l    # Count exported symbols
grep EXPORT_SYMBOL /path/to/kernel/src/*.c  # Find what kernel exports
```

**Key symbol patterns for vulnerability research:**

```bash
# Symlink/hardlink creation (potential TOCTOU)
grep -rn "symlink\|link\|rename" --include="*.c" kernel/

# Capability checks
grep -rn "capable\|ns_capable\|has_capability" --include="*.c" kernel/

# User space access
grep -rn "copy_from_user\|copy_to_user\|get_user\|put_user" --include="*.c" kernel/

# Reference counting (UAF indicators)
grep -rn "kref_\|kobject_get\|kobject_put\|refcount_" --include="*.c" kernel/

# Lock primitives (concurrency bugs)
grep -rn "mutex_lock\|spin_lock\|rwlock\|rcu_read_lock" --include="*.c" kernel/
```

### 3.3 Linux Kernel Source Navigation

**Elixir Cross Referencer (https://elixir.bootlin.com):**

```
Navigation workflow:
1. Search for a function name → jumps to definition
2. Click function name → see all callers (XREF)
3. Use "Identifiers" to see all definitions and declarations
4. Browse by subdirectory (e.g., kernel/, fs/, drivers/)
```

**Local kernel source navigation:**

```bash
# Use ctags + cscope for Vim-based navigation
cd linux
make tags cscope

# Or use ripgrep for fast searching
rg -n "SYSCALL_DEFINE.*mmap" --type c
rg -n "SYSCALL_DEFINE.*ioctl" --type c
rg -n "SYSCALL_DEFINE.*bpf" --type c

# Generate call graph for a function
# (requires Graphviz)
cscope -d -L2 -f "function_name" | dot -Tpng -o callgraph.png
```

### 3.4 Tracing Kernel Code

#### 3.4.1 ftrace

```bash
# Enable function tracing for specific functions
echo function > /sys/kernel/debug/tracing/current_tracer
echo do_sys_open > /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/tracing_on

# Read trace output
cat /sys/kernel/debug/tracing/trace

# Function graph tracer (shows call hierarchy)
echo function_graph > /sys/kernel/debug/tracing/current_tracer
echo do_sys_openat2 > /sys/kernel/debug/tracing/set_graph_function

# Trace specific process
echo <PID> > /sys/kernel/debug/tracing/set_ftrace_pid

# Trace events (e.g., syscall entry/exit)
echo sys_enter_openat > /sys/kernel/debug/tracing/set_event
echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable
```

#### 3.4.2 perf

```bash
# Record system-wide kernel trace
sudo perf record -a -g -e syscalls:sys_enter_ioctl

# Record for specific process
sudo perf record -a -g -p <PID> -- sleep 5

# Analyze recorded data
sudo perf report

# Hardware breakpoint on memory address
sudo perf record -e mem:0xffff888000000000:r
```

#### 3.4.3 eBPF

```bash
# bpftrace — one-liners for kernel tracing

# Trace all open syscall
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s: %s\n", comm, str(args->filename)); }'

# Trace ioctl with arguments
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_ioctl { printf("%s: fd=%d cmd=0x%x arg=0x%x\n", comm, args->fd, args->cmd, args->arg); }'

# Trace specific kernel function
sudo bpftrace -e 'kprobe:do_sys_openat2 { printf("%s: %s\n", comm, str(args->filename)); }'

# Trace function return values
sudo bpftrace -e 'kretprobe:do_sys_openat2 { printf("ret=%d\n", retval); }'

# Trace slab allocation (UAF monitoring)
sudo bpftrace -e '
kprobe:kmem_cache_alloc { @alloc[comm] = count(); }
kprobe:kmem_cache_free { @free[comm] = count(); }
'

# Trace specific struct field access (potential UAF)
sudo bpftrace -e '
kprobe:vfs_read /pid == <TARGET_PID>/ {
    printf("file=%p f_count=%d\n", arg0, ((struct file *)arg0)->f_count.counter);
}
'
```

### 3.5 Reading Oops/Panic Messages

```
Typical kernel oops message:
BUG: unable to handle page fault for address: ffff888006234000
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page
PGD 0 P4D 0
Oops: 0000 [#1] SMP NOPTI
CPU: 3 PID: 1234 Comm: exploit Not tainted 6.1.0
RIP: 0010:vuln_ioctl+0x45/0x80 [vuln_driver]
Code: 48 8b 47 08 83 e0 01 48 8b 40 10 <48> 8b 00 48 89 c7
     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     The faulting instruction (marked with <>)
RSP: 0018:ffffc90000307e80 EFLAGS: 00010246
RAX: dead000000000100 RBX: ffff888006234000 RCX: 0000000000000000
                                     ^^^^^^^^^^^^^^^^
                                     Freed/poisoned object pointer!
```

**Decoding the oops:**

```bash
# Decode oops with addr2line (if you have vmlinux with debug symbols)
addr2line -e vmlinux -i ffffffff81001234

# Use the kernel oops decoder script
./scripts/decodecode < oops.txt

# Map RIP offset to source line
# RIP: 0010:vuln_ioctl+0x45/0x80 [vuln_driver]
# → Function vuln_ioctl, offset 0x45, function size 0x80
# → Module: vuln_driver

# Getting the module base address from /proc/modules
cat /proc/modules | grep vuln_driver
# vuln_driver 20480 0 - Loading 0xffffffffc0200000 (O+)

# Then: objdump -d --adjust-vma=0xffffffffc0200000 vuln_driver.ko
```

**Poison values for identifying bugs:**

| Value | Meaning |
|-------|---------|
| `0x6b6b6b6b` | `POISON_FREE` — kmalloc freed memory |
| `0xdead000000000100` | `LIST_POISON1` — freed list node `next` |
| `0xdead000000000200` | `LIST_POISON2` — freed list node `prev` |
| `0xa5a5a5a5` | Stack canary padding (some configs) |
| `0x00000000` | NULL pointer dereference |
| `0xcccccccc` | GPLv1 stack buffer overflow padding |

---

## 4. Practical CTF RE Scenarios

### 4.1 Step-by-Step Methodology for RE Challenges

```
╔══════════════════════════════════════════════════╗
║          CTF RE CHALLENGE WORKFLOW               ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║  PHASE 1: TRIAGE                                 ║
║  ├── file binary                                 ║
║  ├── checksec binary (or pwn checksec)           ║
║  ├── strings binary | sort -u                    ║
║  ├── Identify: stripped? statically linked?      ║
║  └── Run binary briefly, observe behavior        ║
║                                                  ║
║  PHASE 2: DEEPER STATIC ANALYSIS                 ║
║  ├── Load into Ghidra/IDA/r2                     ║
║  ├── Identify main() and entry point             ║
║  ├── Map out functions (rename as you go)        ║
║  ├── Identify crypto/validation routines          ║
║  └── Note anti-re techniques                     ║
║                                                  ║
║  PHASE 3: DYNAMIC ANALYSIS                       ║
║  ├── Run under strace/ltrace                     ║
║  ├── Debug with GDB (break on key functions)     ║
║  ├── Set breakpoints on comparisons              ║
║  └── Patch anti-debug if needed                  ║
║                                                  ║
║  PHASE 4: SOLVE                                  ║
║  ├── If crypto: identify algorithm, extract key  ║
║  ├── If validation: reverse the check             ║
║  ├── If obfuscation: deobfuscate or emulate      ║
║  └── Script the solution                          ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

**Detailed triage commands:**

```bash
# Step 1: What is this binary?
file challenge_binary

# Step 2: Security features
checksec --file=challenge_binary
# Or with pwntools:
python3 -c "from pwn import *; e = ELF('./challenge_binary'); print(e.checksec())"

# Step 3: Quick string scan
strings -n 8 challenge_binary | grep -iE "flag|key|pass|secret|correct|wrong|error|input"
strings -n 8 challenge_binary | grep -E "^[A-Za-z0-9+/=]{20,}$"  # Base64

# Step 4: Library dependencies
ldd challenge_binary

# Step 5: Dynamic analysis
strace ./challenge_binary 2>&1 | head -50
ltrace ./challenge_binary 2>&1 | head -50

# Step 6: Hex dump interesting sections
xxd challenge_binary | grep -i flag
```

### 4.2 Common CTF Binary Patterns and Anti-RE Techniques

| Pattern | Description | Bypass |
|---------|-------------|--------|
| `ptrace(PTRACE_TRACEME)` | Anti-debug (detects debugger) | Patch `ptrace` call to `nop`; or `LD_PRELOAD` fake `ptrace` |
| `clock_gettime` timing | Detects single-stepping | Patch timing check; or use hardware breakpoints |
| `__asm__ volatile(".byte 0xcc")` | Software breakpoint trap | Replace with NOP |
| XOR loop | Simple string encryption | Extract loop, run in Python |
| Base85/Base64 table | Custom encoding | Find table, decode |
| vtable dispatch | Control flow obfuscation | Resolve vtable entries statically |
| `jmp -0` / infinite loop | Anti-disassembly | Manual analysis; fix memory map |
| String on stack | `mov` byte-by-byte onto stack | Ghidra decompilation handles this |
| Opaque predicates | Always true/false branches | Symbolic execution (angr) |
| Flatten CFG | dispatcher loop (OLLVM) | deflat.py; D-810 Ghidra plugin |

**Bypassing anti-debugging — LD_PRELOAD trick:**

```c
// fake_ptrace.c
int ptrace(int req, ...) { return 0; }
// gcc -shared -fPIC -o fake_ptrace.so fake_ptrace.c
// LD_PRELOAD=./fake_ptrace.so ./challenge_binary
```

**Bypassing anti-debugging — GDB hook:**

```gdb
# In .gdbinit or at GDB prompt
break ptrace
commands
  return 0
  continue
end
```

### 4.3 Automatically Extracting Logic from Obfuscated Binaries

**angr — Symbolic execution for automated analysis:**

```python
import angr
import claripy

proj = angr.Project('./challenge_binary', auto_load_libs=False)

# Find the "correct" path (e.g., "Correct!" string address)
find_addr = 0x00401234  # Address of success branch
avoid_addr = 0x00401200  # Address of failure branch

# Create symbolic state
state = proj.factory.entry_state()

# If input format is known, constrain it
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(32)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# Set up stdin with symbolic flag
state.posix.stdout = angr.SimFile('/dev/stdout')
simfd = state.posix.stdin
simfd.write(flag)
simfd.seek(0)

# For each character, constrain to printable ASCII
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Explore to find/avoid paths
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=find_addr, avoid=avoid_addr)

if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(flag, cast_to=bytes)
    print(f"Flag: {solution.decode()}")
else:
    print("No solution found")
```

**Z3 — SMT solver for constraint solving:**

```python
from z3 import *

s = Solver()

# Define symbolic variables (e.g., a 32-character flag)
flag = [BitVec(f'f{i}', 8) for i in range(32)]

# Constrain to printable ASCII
for i, c in enumerate(flag):
    s.add(c >= 0x20, c <= 0x7e)

# Add constraints extracted from binary
# Example: flag[0] + flag[1] == 0xAB
s.add(flag[0] + flag[1] == 0xAB)

# Example: flag[i] ^ flag[i+1] == some_value
s.add(flag[0] ^ flag[1] == 0x42)

# ... add more constraints from disassembly ...

if s.check() == sat:
    m = s.model()
    result = bytes([m[c].as_long() for c in flag])
    print(f"Flag: {result}")
```

### 4.4 Angr/Z3 for Symbolic Execution — Advanced

**Symbolic memory modeling:**

```python
import angr

proj = angr.Project('./challenge_binary', auto_load_libs=False)
state = proj.factory.entry_state()

# Symbolic heap modeling
# Allocate symbolic buffer
buf_size = 64
buf = state.solver.BVV(0, buf_size * 8)  # Symbolic buffer

# Constrain specific bytes (from known format)
# e.g., flag format is "CTF{...}"
state.solver.add(state.memory.load(buf_addr, 4) == int.from_bytes(b'CTF{', 'big'))

# Explore with symbolic memory
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target_addr)

# Extract symbolic constraints
for v in found_state.solver.variables:
    print(f"Variable: {v}")
    print(f"  Value: {found_state.solver.eval(v)}")
```

**When symbolic execution struggles:**

- **Path explosion**: Use `avoid` addresses aggressively; use `depth` limits
- **Complex library calls**: Hook with SimProcedures (`angr.SIM_PROCEDURES['libc']['strcpy']`)
- **Floating point**: Enable `state.options.FLOATS`; or patch out FP operations
- **Unsupported syscalls**: Add custom SimProcedures or use `auto_load_libs=True`

---

## 5. Patch Diffing & Variant Analysis

### 5.1 How to Diff Security Patches

Patch diffing reveals what was fixed — and by extension, what was vulnerable — by comparing the binary before and after a security patch.

**Workflow:**

```
┌─────────────────────────────────────────────────────────────┐
│                    PATCH DIFFING WORKFLOW                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. OBTAIN UNPATCHED AND PATCHED BINARIES                    │
│     ├── From vendor (update packages)                        │
│     ├── From different OS versions                           │
│     └── Build from source at different commits               │
│                                                              │
│  2. LOAD BOTH INTO DIFFING TOOL                              │
│     ├── BinDiff (IDA plugin)                                  │
│     ├── Diaphora (Ghidra/IDA plugin)                         │
│     └── BSim (Ghidra built-in)                               │
│                                                              │
│  3. IDENTIFY CHANGED FUNCTIONS                                │
│     ├── Look for confidence < 100% (changed)                 │
│     ├── Look for "no match" (added/removed)                  │
│     └── Focus on changes in non-trivial functions             │
│                                                              │
│  4. ANALYZE DIFF IN DECOMPILER                               │
│     ├── What validation was added?                            │
│     ├── What bounds check was inserted?                       │
│     ├── What type change occurred?                            │
│     └── What locking was added?                               │
│                                                              │
│  5. UNDERSTAND THE VULNERABILITY                              │
│     ├── The removed code IS the vulnerability                 │
│     ├── The added code IS the fix                             │
│     └── Now search for SIMILAR vulnerable patterns            │
│                                                              │
│  6. VARIANT ANALYSIS                                          │
│     ├── Search the ENTIRE codebase for the same pattern       │
│     ├── Check similar functions for the same omission         │
│     └── Look in DIFFERENT drivers/modules for similar code   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 5.1.1 BinDiff (IDA Pro)

```bash
# BinDiff workflow
1. Open unpatched binary in IDA
2. Run analysis
3. File → BinDiff → Compare to...
4. Select patched binary IDB
5. BinDiff matches functions by structural similarity
6. Review "Unmatched" and "Confident < 100%" entries
7. Double-click to see side-by-side flow graphs

# Key metrics:
# - Confidence: How similar the functions are (0-1.0)
#   1.0 = identical, 0.9+ = minor changes, <0.5 = major changes
# - Similarity: Structural similarity
# Focus on functions with high confidence but NOT 1.0 → these changed
```

#### 5.1.2 Diaphora (Ghidra/IDA)

```bash
# Install Diaphora
pip install diaphora

# Or use Ghidra plugin version:
# https://github.com/joxeankoret/diaphora

# Export databases from both binaries
# In Ghidra: Diaphora → Export database
# Or with IDA: File → Produce file → Create DIF file

# Run diff
python3 diaphora.py unpatched.dba patched.dba

# Review results in the Diaphora UI
# Key tabs:
# - "Best matches": Functions with partial changes
# - "Partial matches": Functions with significant changes
# - "Unreliable matches": Low-confidence matches
# Focus on "Best matches" with < 1.0 similarity
```

#### 5.1.3 Source-Level Diffing

```bash
# When source is available
git diff v5.4..v5.4.1 -- drivers/gpu/drm/ > patch.diff

# Analyze the diff
# Key things to look for:
# 1. "if (condition)" blocks added → New validation
# 2. Type changes (int → u64) → Integer overflow fix
# 3. Lock additions → Race condition fix
# 4. kfree/free moved → UAF fix
# 5. copy_from_user sizes changed → Buffer overflow fix

# Example analysis of a real kernel security patch:
git log --oneline --since="2024-01-01" --grep="CVE" linux/
# Pick a commit
git show abc1234
```

### 5.2 Finding Similar Bugs — Variant Analysis

Once you understand a vulnerability pattern, systematically search for variants:

**Method 1: Pattern-Based Search**

```bash
# If the vulnerability was: missing bounds check on copy_from_user size
# Search for the same pattern everywhere:

rg -n "copy_from_user" --type c -A3 | rg -v "if.*>" | rg -v "if.*<"
# Find copy_from_user calls NOT preceded by a bounds check

# If the vulnerability was: integer overflow in size arithmetic
# Search for multiplication in allocation:
rg -n "kmalloc\s*\([^)]*\*" --type c
rg -n "vmalloc\s*\([^)]*\*" --type c
rg -n "malloc\s*\([^)]*\*" --type c

# If the fix added: if (size > MAX) return -EINVAL;
# Search for functions that DON'T have this check:
rg -n "SYSCTL.*proc_dointvec" --type c -l
# For each file, check if write handler validates the range
```

**Method 2: Semantic Search with CodeQL/Semgrep**

```ql
// Find all functions matching the vulnerable pattern
// Example: Functions that take a size parameter from userspace
// and use it in a kmalloc without overflow check

import cpp

from FunctionCall kmalloc, FunctionCall memcpy, VariableAccess size
where
    kmalloc.getTarget().getName() = "kmalloc" and
    memcpy.getTarget().getName() = "memcpy" and
    size = kmalloc.getArgument(0).getAUse() and
    size = memcpy.getArgument(2).getAUse() and
    not exists(GuardCondition gc |
        gc.controls(size.getBasicBlock()) and
        gc.getCondition().(RelationalOperation).getAnOperand() = size
    )
select kmalloc, "kmalloc with same unchecked size used in memcpy"
```

**Method 3: Call Graph Analysis**

```
Given a vulnerability in function F:
1. Find all callers of F → they might pass unchecked data
2. Find all functions with similar signatures → same bug
3. Find all functions that operate on the same data type → same type confusion or misuse
4. Find all users of the same struct → same field misuse
```

### 5.3 Real Examples: How Patch Diffing Led to Zero-Days

#### 5.3.1 Android Kernel — Qualcomm Driver Variants

A security patch fixed an ioctl handler in a Qualcomm display driver that lacked proper bounds checking on `copy_from_user`. The fix added:

```c
if (data_size > MAX_DATA_SIZE)
    return -EINVAL;
```

**Variant analysis** revealed that:
- Three other ioctl handlers in the same driver had the same missing check
- Two other Qualcomm drivers (camera, sensor) used similar patterns
- This resulted in **5 additional CVEs** from the same root cause

#### 5.3.2 Linux Kernel — io_uring UAF Variants

When CVE-2023-2598 (io_uring use-after-free) was patched, the fix added proper reference counting. Diff analysis showed:

1. The patch added `req->flags |= REQ_F_REFCOUNT` and `io_put_req()` in error paths
2. Searching `io_uring/io_uring.c` for similar patterns revealed **3 additional UAF paths** where requests were freed without proper reference counting
3. Each was a distinct code path triggered by different racing conditions

**Key lesson**: When a reference counting fix is applied, audit ALL reference acquisition/release points in the same subsystem.

#### 5.3.3 Windows — Print Spooler Variants (PrintNightmare)

The original CVE-2021-34527 (PrintNightmare) was a DLL injection via the Print Spooler's `RpcAddPrinterDriverEx`. The patch added driver path validation.

Variant analysis approach:
1. Diff the patched `spoolsv.exe` — identified new path validation
2. Search for similar RPC endpoints in the same binary
3. Found `RpcAddPrinterDriver` (without `Ex`) — same vulnerability, different function
4. Found `RpcAddPrintProcessor` — similar driver loading without validation
5. Result: Multiple print spooler RCEs throughout 2021

**The pattern**: Whenever you see an `*Ex`, `*2`, `*Safe` function added as a secure version, the original function is likely still vulnerable.

### 5.4 Automated Variant Analysis Pipeline

```bash
#!/bin/bash
# variant_analysis.sh - Automated variant hunting after understanding a bug

BUG_PATTERN="$1"  # e.g., "copy_from_user.*without.*size.*check"
SOURCE_DIR="$2"    # e.g., /path/to/linux

echo "[*] Searching for pattern: $BUG_PATTERN"
echo "[*] In: $SOURCE_DIR"
echo ""

# Step 1: Find exact pattern matches
echo "[1] EXACT PATTERN MATCHES:"
rg -n "$BUG_PATTERN" --type c "$SOURCE_DIR"

# Step 2: Find similar function calls (same function, different callers)
echo "[2] CALLERS OF VULNERABLE FUNCTION:"
# Extract function names from the pattern
FUNC=$(echo "$BUG_PATTERN" | grep -oP '[a-z_]+(?=\()')
rg -n "${FUNC}\(" --type c "$SOURCE_DIR" | head -50

# Step 3: Find struct-based variants (same struct, different accessors)
echo "[3] STRUCT-BASED VARIANTS:"
# If the bug involves struct X, find all users of struct X
# STRUCT=$(echo "$BUG_PATTERN" | grep -oP 'struct \w+')
# rg -n "$STRUCT" --type c "$SOURCE_DIR" | head -50

# Step 4: Check commit history for similar patches
echo "[4] SIMILAR COMMITS:"
cd "$SOURCE_DIR"
git log --oneline --all --grep="$(echo $BUG_PATTERN | cut -c1-20)" | head -20

# Step 5: Find co-developed patches (same author, same timeframe)
echo "[5] CO-DEVELOPED PATCHES:"
# Get author of the fix commit
FIX_AUTHOR=$(git log -1 --format='%an <%ae>' "$3" 2>/dev/null)
FIX_DATE=$(git log -1 --format='%ci' "$3" 2>/dev/null | cut -d' ' -f1)
echo "Fix by $FIX_AUTHOR on $FIX_DATE"
git log --oneline --all --author="$FIX_AUTHOR" --since="${FIX_DATE}T00:00:00" --until="${FIX_DATE}T23:59:59" | head -20
```

---

## Appendix A: Quick Reference — Key Commands

```bash
# Ghidra headless analysis
analyzeHeadless /tmp/project binary -import ./target -postScript FindVulns.java

# Radare2 quick analysis
r2 -AA binary -c "afl; iz; axt @ sym.imp.strcpy; quit"

# Binary diffing with Diaphora
python3 diaphora.py old.dba new.dba

# Kernel oops decoding
./scripts/decodecode < oops.txt
addr2line -e vmlinux -i <rip_offset>

# Dynamic tracing
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_ioctl { printf("%s: fd=%d cmd=0x%x\n", comm, args->fd, args->cmd); }'

# GDB kernel debugging
gdb vmlinux
target remote localhost:1234
b vuln_ioctl
c

# CodeQL analysis
codeql database create db --language=cpp --source-root=.
codeql database analyze db codeql/cpp-queries:Security --format=csv --output=results.csv

# Semgrep
semgrep --config p/security-audit .

# Coccinelle
spatch --sp-file find_memcpy_overflow.cocci --dir linux/drivers/
```

## Appendix B: Cheat Sheet — Vulnerability Patterns in Disassembly

| Source Pattern | Assembly Signature | Vulnerability Class |
|---------------|-------------------|---------------------|
| `strcpy(dst, src)` | `call strcpy` with no bounds check | Stack/heap overflow |
| `sprintf(buf, fmt, ...)` | `call sprintf` | Format string / overflow |
| `printf(user_data)` | `call printf` with 1 arg | Format string |
| `malloc(count * size)` | `imul; call malloc` | Integer overflow |
| `free(ptr); ... use(ptr)` | `call free; ... mov reg,[ptr]` | Use-after-free |
| `array[index]` with no bounds | `mov [base+index*8]` | Out-of-bounds |
| `copy_from_user(dst, src, len)` | `call copy_from_user` | Missing validation |
| `ptr->field` after `kfree(ptr)` | `call kfree; ... mov reg,[ptr+offset]` | UAF (kernel) |
| XOR decryption loop | `xor [reg], reg; loop/jnz` | String obfuscation |
| `ptrace(PTRACE_TRACEME)` | Anti-debug: `cmp rax, 0; je ok` | Debug detection |

## References

1. [Linux Kernel — Torvalds Git](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) — Mainline Linux kernel source repository
2. [GitHub CodeQL](https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip) — Semantic code analysis engine for vulnerability discovery
3. [Elixir Cross Referencer](https://elixir.bootlin.com) — Browse kernel source with cross-references and symbol navigation
4. [Diaphora — Binary Diffing Tool](https://github.com/joxeankoret/diaphora) — Firmware and binary patch diffing for vulnerability research
5. [Ghidra — NSA Reverse Engineering Framework](https://ghidra-sre.org/) — Open-source decompiler and disassembler
6. [Binwalk — Firmware Analysis Tool](https://github.com/ReFirmLabs/binwalk) — Firmware extraction and analysis
7. [CISA BOD 22-01 — Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Binding directive for vulnerability management
8. [semgrep — Static Analysis](https://semgrep.dev/) — Pattern-based static analysis for multiple languages
9. [Joern — Code Property Graph](https://joern.io/) — Static analysis using code property graphs
10. [BinDiff — Binary Diffing](https://zynamics.com/software.html) — Commercial binary diffing tool (now free)

---

*This document serves as both a learning resource and a field reference. The methodology described here has been applied to discover numerous CVEs across operating systems, device drivers, and application software. Always practice responsible disclosure.*