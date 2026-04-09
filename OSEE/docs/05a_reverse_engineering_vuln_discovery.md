# Reverse Engineering and Vulnerability Discovery — OSEE Reference

## Table of Contents

1. [Static Analysis Techniques](#1-static-analysis-techniques)
   - [IDA Pro Workflow](#11-ida-pro-workflow-for-windows-binary-analysis)
   - [Ghidra as an Alternative](#12-ghidra-as-an-alternative)
   - [PE File Format Analysis](#13-pe-file-format-analysis)
   - [Identifying Vulnerability Patterns in Disassembly](#14-identifying-vulnerability-patterns-in-disassembly)
   - [Cross-Referencing and Call Graph Analysis](#15-cross-referencing-and-call-graph-analysis)
   - [Structure Reconstruction and Type Recovery](#16-structure-reconstruction-and-type-recovery)
   - [Security-Relevant Functions](#17-identifying-security-relevant-functions)
2. [Dynamic Analysis Techniques](#2-dynamic-analysis-techniques)
   - [WinDbg for User-Mode and Kernel-Mode Debugging](#21-windbg-for-user-mode-and-kernel-mode-debugging)
   - [Essential WinDbg Commands for Exploit Development](#22-essential-windbg-commands-for-exploit-development)
   - [x64dbg for User-Mode Analysis](#23-x64dbg-for-user-mode-analysis)
   - [Setting Breakpoints on Key APIs](#24-setting-breakpoints-on-key-apis)
   - [Tracing Execution Flow](#25-tracing-execution-flow-with-conditional-breakpoints-and-logging)
   - [Memory Inspection Techniques](#26-memory-inspection-techniques)
   - [Crash Analysis and Triage](#27-crash-analysis-with-analyze--v-and-triage-methodology)
3. [Vulnerability Discovery Methodology](#3-vulnerability-discovery-methodology)
   - [Attack Surface Mapping](#31-attack-surface-mapping)
   - [Input Vector Identification](#32-input-vector-identification-in-drivers-and-applications)
   - [Fuzzing Approaches](#33-fuzzing-approaches)
   - [Code Auditing Patterns](#34-code-auditing-patterns-for-cc-vulnerabilities)
   - [Identifying Memory Corruption Through Static Patterns](#35-identifying-memory-corruption-bugs-through-static-patterns)
   - [Taint Analysis](#36-taint-analysis-concepts-and-tools)
4. [Patch Diffing](#4-patch-diffing)
   - [BinDiff and Diaphora](#41-using-bindiff-and-diaphora-for-binary-comparison)
   - [Analyzing Microsoft Patch Tuesday](#42-analyzing-microsoft-patch-tuesday-updates)
   - [1-Day Exploit Development Methodology](#43-methodology-for-1-day-exploit-development-from-patches)
   - [Case Studies](#44-case-studies-of-notable-patch-diff-discoveries)

---

## 1. Static Analysis Techniques

Static analysis is the foundation of reverse engineering for exploit development. Before any debugger is attached, the analyst must understand the binary's structure, its attack surface, and the code paths that handle untrusted input. For OSEE, this means fluency with professional disassemblers, deep understanding of the PE format, and the ability to recognize vulnerability patterns in assembly or decompiled pseudocode.

### 1.1 IDA Pro Workflow for Windows Binary Analysis

IDA Pro remains the industry standard for binary reverse engineering in Windows exploit development. Its combination of powerful auto-analysis, an interactive disassembly view, and the Hex-Rays decompiler makes it indispensable for OSEE-level work.

#### Loading Binaries

When loading a Windows binary into IDA:

1. **Select the correct processor module**: IDA auto-detects, but verify `metapc` (x86/x64) is selected for PE files.
2. **Loading options**: For kernel drivers (`.sys` files), ensure "Load as kernel module" is selected. For DLLs, consider enabling "Load resources" and "Load debug info" if PDB symbols are available.
3. **Symbol loading**: If Microsoft public symbols are available (PDB files), load them via `File -> Load file -> PDB file`. For `ntoskrnl.exe` and other OS binaries, set up the symbol path:

```
_NT_SYMBOL_PATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
```

4. **Rebasing**: If analyzing a module extracted from memory at a known base address, rebase the database via `Edit -> Segments -> Rebase program`.

#### Navigation

| Action | Shortcut | Description |
|--------|----------|-------------|
| Go to address | `G` | Jump to a specific address or symbol |
| Go to function | `Ctrl+P` | Open function list for navigation |
| Cross-references to | `X` | Show all references to the current symbol |
| Cross-references from | `Ctrl+J` | Show references from the current location |
| Go back | `Esc` | Return to previous navigation position |
| Go forward | `Ctrl+Enter` | Move forward in navigation history |
| Search text | `Alt+T` | Search for text strings in disassembly |
| Search binary | `Alt+B` | Search for binary byte patterns |
| Rename symbol | `N` | Rename the current symbol/variable |
| Set type | `Y` | Set or change the type of a function/variable |
| Toggle graph/text | `Space` | Switch between graph and linear disassembly |

#### The Hex-Rays Decompiler

The Hex-Rays decompiler transforms disassembly into C-like pseudocode, dramatically accelerating analysis. Key usage:

```c
// Raw decompiler output for a typical IOCTL handler
__int64 __fastcall DriverDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PIO_STACK_LOCATION IoStackLocation;
  ULONG IoControlCode;
  PVOID InputBuffer;
  ULONG InputBufferLength;
  
  IoStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
  IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
  InputBuffer = Irp->AssociatedIrp.SystemBuffer;
  InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
  
  if ( IoControlCode == 0x22200C )
  {
    // VULNERABILITY: InputBufferLength not validated before copy
    memmove(StackBuffer, InputBuffer, InputBufferLength);  // <-- Stack overflow
  }
  // ...
}
```

**Decompiler tips for OSEE work:**

- Press `Y` on function parameters to set correct types — especially apply `PIRP`, `PDEVICE_OBJECT`, and `PIO_STACK_LOCATION` structures from the Windows Driver Kit (WDK) type libraries.
- Use `T` to apply struct member types when the decompiler shows raw offsets like `*((_DWORD *)a1 + 0x18)`.
- Press `/` to add comments in the pseudocode view.
- Right-click variables and select "Set lvar type" to correct misidentified types — this propagates through the decompilation and often reveals the logic more clearly.
- Use `Tab` to toggle between disassembly and decompiler views for the same function.

#### Essential IDA Plugins for Exploit Development

| Plugin | Purpose |
|--------|---------|
| **Findcrypt** | Identifies cryptographic constants in binaries (AES S-boxes, SHA constants) |
| **LazyIDA** | Bulk operations: copy bytes, convert data types, search for format strings |
| **Keypatch** | Patch assembly instructions inline using Keystone engine |
| **FLIRT signatures** | Identify statically linked library functions (File -> Load FLIRT signature) |
| **BinDiff** | Compare two binaries for patch analysis (see Section 4) |
| **ret-sync** | Synchronize IDA view with a running debugger (WinDbg, x64dbg) |
| **HexRaysPyTools** | Reconstruct structures, rename fields, propagate types in Hex-Rays |
| **IDAPython console** | Script custom analysis (Shift+F2 opens the script editor) |

#### IDAPython Scripting Examples

```python
# Find all calls to memcpy/memmove/RtlCopyMemory in the binary
import idautils
import idc

dangerous_funcs = ['memcpy', 'memmove', 'RtlCopyMemory', 'RtlCopyBytes', 
                   'strcpy', 'strncpy', 'sprintf', 'vsprintf']

for func_name in dangerous_funcs:
    ea = idc.get_name_ea_simple(func_name)
    if ea != idc.BADADDR:
        print(f"\n[*] References to {func_name} at {hex(ea)}:")
        for ref in idautils.CodeRefsTo(ea, True):
            caller = idc.get_func_name(ref)
            print(f"    {hex(ref)} in {caller}")

# Enumerate IOCTL dispatch codes from a switch statement
# Useful for mapping a driver's attack surface
def find_ioctl_codes(dispatch_func_ea):
    """Extract IOCTL codes from a dispatch function's switch/case."""
    func = ida_funcs.get_func(dispatch_func_ea)
    if not func:
        return []
    
    ioctl_codes = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(head)
        if mnem == 'cmp' or mnem == 'sub':
            op1 = idc.get_operand_value(head, 1)
            # IOCTL codes are typically in the range 0x00220000 - 0x002FFFFF
            if 0x00220000 <= op1 <= 0x002FFFFF:
                ioctl_codes.append(op1)
                print(f"  IOCTL code: {hex(op1)} at {hex(head)}")
    return ioctl_codes
```

### 1.2 Ghidra as an Alternative

Ghidra, the NSA's open-source reverse engineering framework, is a capable free alternative to IDA Pro. For OSEE preparation where budget is a concern, Ghidra provides the essential capabilities.

#### Setup

1. **Install Java**: Ghidra requires JDK 17+ (Adoptium/Temurin recommended).
2. **Download Ghidra**: From [ghidra-sre.org](https://ghidra-sre.org/).
3. **Symbol configuration**: Configure Ghidra to download Microsoft PDB symbols:
   - `Edit -> Tool Options -> Symbol Server Config`
   - Add `https://msdl.microsoft.com/download/symbols` as a symbol server
   - Set local symbol storage directory

4. **Apply Windows type libraries**: Import Windows Driver Kit (WDK) headers via `File -> Parse C Source` to get proper structure definitions for kernel types.

#### Key Features for Exploit Development

**Decompiler**: Ghidra's decompiler is integrated and free (unlike Hex-Rays, which is a paid IDA add-on). Quality is generally good, though Hex-Rays remains superior for complex code.

**Program Trees / Section View**: Visualize PE sections, exports, and imports hierarchically.

**Data Type Manager**: Import `.h` files or `.gdt` (Ghidra Data Type) archives to apply kernel structures. Apply types with right-click -> "Retype Variable".

**Function Call Trees**: Right-click a function -> "Show Call Trees" to visualize caller/callee relationships.

**Version Tracking**: Compare two versions of a binary (similar to BinDiff). `Tools -> Version Tracking` enables diffing two Ghidra program databases.

#### Ghidra Scripting (Java and Python)

Ghidra supports both Java and Python (Jython) scripting via the Script Manager (`Window -> Script Manager`):

```python
# Ghidra Python script: Find all xrefs to dangerous functions
# Run via Script Manager or headless analyzer

from ghidra.program.model.symbol import SymbolType

dangerous = ['memcpy', 'memmove', 'RtlCopyMemory', 'strcpy', 
             'sprintf', 'RtlCopyBytes', 'ProbeForRead', 'ProbeForWrite']

sym_table = currentProgram.getSymbolTable()
ref_mgr = currentProgram.getReferenceManager()

for name in dangerous:
    symbols = sym_table.getSymbols(name)
    for sym in symbols:
        refs = ref_mgr.getReferencesTo(sym.getAddress())
        for ref in refs:
            caller = getFunctionContaining(ref.getFromAddress())
            caller_name = caller.getName() if caller else "unknown"
            print("[!] {} called from {} at {}".format(
                name, caller_name, ref.getFromAddress()))
```

**Headless analysis** for batch processing:

```bash
# Analyze a directory of driver binaries in headless mode
analyzeHeadless /tmp/ghidra_projects MyProject \
    -import /path/to/drivers/*.sys \
    -postScript FindDangerousCalls.py \
    -scriptPath /path/to/scripts \
    -log /tmp/analysis.log
```

#### Ghidra vs IDA Pro for OSEE Work

| Aspect | IDA Pro | Ghidra |
|--------|---------|--------|
| **Cost** | $2,800+ (with Hex-Rays) | Free (open source) |
| **Decompiler** | Hex-Rays (superior) | Built-in (good) |
| **Auto-analysis** | Excellent, fast | Good, slower on large binaries |
| **Plugin ecosystem** | Mature, extensive | Growing rapidly |
| **Kernel driver support** | Excellent with WDK TILs | Good with imported types |
| **Scripting** | IDAPython (Python 3) | Java + Jython |
| **Collaboration** | IDA Teams (paid) | Ghidra Server (free) |
| **Debugging** | Built-in remote debug | Limited (mostly static) |

### 1.3 PE File Format Analysis

Understanding the Portable Executable (PE) format is fundamental for Windows exploit development. Every `.exe`, `.dll`, `.sys`, and `.ocx` file uses this format.

#### PE Structure Overview

```
┌─────────────────────────────────────┐
│        DOS Header (MZ)              │  ← e_magic = 0x5A4D ("MZ")
│        (IMAGE_DOS_HEADER)           │  ← e_lfanew → PE signature
├─────────────────────────────────────┤
│        DOS Stub                     │  ← "This program cannot be run..."
├─────────────────────────────────────┤
│        PE Signature (4 bytes)       │  ← 0x00004550 ("PE\0\0")
├─────────────────────────────────────┤
│        COFF File Header             │  ← IMAGE_FILE_HEADER (20 bytes)
│  (Machine, NumberOfSections,        │
│   TimeDateStamp, SizeOfOptHeader)   │
├─────────────────────────────────────┤
│        Optional Header              │  ← IMAGE_OPTIONAL_HEADER
│  ┌─────────────────────────────┐    │
│  │  Standard Fields             │   │  ← Magic (0x10B=PE32, 0x20B=PE32+)
│  │  AddressOfEntryPoint         │   │  ← RVA of first executed instruction
│  │  ImageBase                   │   │  ← Preferred load address
│  ├─────────────────────────────┤    │
│  │  Windows-Specific Fields     │   │
│  │  SectionAlignment            │   │  ← Memory alignment (usually 0x1000)
│  │  FileAlignment               │   │  ← File alignment (usually 0x200)
│  │  SizeOfImage                 │   │
│  │  DllCharacteristics          │   │  ← ASLR, DEP, CFG flags
│  ├─────────────────────────────┤    │
│  │  Data Directories (16)       │   │
│  │  [0] Export Table            │   │
│  │  [1] Import Table            │   │
│  │  [2] Resource Table          │   │
│  │  [3] Exception Table         │   │
│  │  [5] Relocation Table        │   │
│  │  [6] Debug Directory         │   │
│  │  [10] Load Config (CFG)      │   │
│  │  [14] CLR Runtime Header     │   │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│        Section Headers              │  ← IMAGE_SECTION_HEADER array
│  .text   (code, RX)                │
│  .rdata  (read-only data, R)       │
│  .data   (read-write data, RW)     │
│  .rsrc   (resources, R)            │
│  .reloc  (relocations, R)          │
│  .pdata  (exception info, R)       │
│  INIT    (kernel init, RWX)        │  ← Discarded after DriverEntry
│  PAGE    (pageable kernel code)    │
├─────────────────────────────────────┤
│        Section Data                 │
│        (raw content mapped per      │
│         section headers)            │
└─────────────────────────────────────┘
```

#### Security-Relevant PE Fields

The `DllCharacteristics` field in the Optional Header reveals which exploit mitigations are enabled:

```c
// IMAGE_OPTIONAL_HEADER.DllCharacteristics flags
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // ASLR: 64-bit high-entropy
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE       0x0040  // ASLR enabled
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080  // Code integrity checks
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT          0x0100  // DEP enabled
#define IMAGE_DLLCHARACTERISTICS_NO_SEH             0x0400  // No SEH (cannot be SE handler)
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF           0x4000  // Control Flow Guard
```

Checking these in practice:

```
# Using dumpbin (from Visual Studio)
dumpbin /headers target.sys | findstr /i "DLL characteristics"

# Using Python pefile
import pefile
pe = pefile.PE('target.sys')
print(f"ASLR:    {bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)}")
print(f"DEP:     {bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)}")
print(f"CFG:     {bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)}")
print(f"HiASLR:  {bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0020)}")
```

#### Imports and Exports Analysis

**Import Address Table (IAT)**: Lists all external functions the binary calls. For kernel drivers, imports from `ntoskrnl.exe` and `HAL.dll` are the norm. Security-critical imports to watch for:

```
# Dangerous imports in kernel drivers (from ntoskrnl.exe):
ExAllocatePool              # Deprecated, no NX enforcement
ExAllocatePoolWithTag       # Legacy pool allocation
RtlCopyMemory               # memcpy equivalent — check length validation
MmMapLockedPagesSpecifyCache # Maps kernel pages — potential info leak
ZwCreateFile / ZwOpenFile    # File I/O from kernel — path traversal risk
MmMapIoSpace                 # Maps physical memory — arbitrary read/write
ProbeForRead / ProbeForWrite # User-buffer validation — check before use
IoGetCurrentIrpStackLocation # IOCTL parameter access
```

**Export Table**: For DLLs and some drivers, exported functions are directly reachable. Enumerate with:

```bash
dumpbin /exports target.dll
# Or in Python:
python -c "import pefile; pe=pefile.PE('target.dll'); [print(f'{e.ordinal}: {e.name}') for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]"
```

#### Relocation Table

The `.reloc` section contains base relocation entries that allow the loader to fix up absolute addresses when the binary is loaded at a different base than `ImageBase`. Understanding relocations is essential for:

- **ASLR**: If `.reloc` is stripped, the binary cannot be relocated and ASLR is effectively disabled.
- **Shellcode development**: Understanding which addresses are absolute vs. relative.
- **Patch diffing**: Relocation entries can mask real code differences.

```c
// Base relocation block structure
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;    // Page RVA
    DWORD SizeOfBlock;       // Size of this block including header
    // WORD TypeOffset[];     // Array of type:offset entries
    //   High 4 bits = type (3=HIGHLOW for x86, 10=DIR64 for x64)
    //   Low 12 bits = offset within the page
} IMAGE_BASE_RELOCATION;
```

### 1.4 Identifying Vulnerability Patterns in Disassembly

Recognizing vulnerability patterns in disassembly or decompiled code is a core OSEE skill. The following patterns represent the most common vulnerability classes in Windows kernel drivers and applications.

#### Stack Buffer Overflows

**Pattern**: A fixed-size stack buffer receives data of user-controlled length without bounds checking.

```asm
; Vulnerable IOCTL handler — stack buffer overflow
; rcx = Irp->AssociatedIrp.SystemBuffer (user-controlled input)
; edx = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength
DriverIoctl_Handler:
    sub     rsp, 0x128              ; Allocate 0x100-byte stack buffer + locals
    ; ...
    mov     r8d, edx                ; r8 = InputBufferLength (user-controlled!)
    lea     rdx, [rsp+0x28]         ; rdx = &StackBuffer (destination)
    mov     rcx, [rax+18h]          ; rcx = SystemBuffer (source)
    call    memcpy                  ; memcpy(StackBuffer, SystemBuffer, InputBufferLength)
                                    ; NO CHECK: InputBufferLength > 0x100 → overflow
```

**What to look for:**
- `sub rsp, <size>` followed by a `memcpy`/`memmove`/`RtlCopyMemory` where the third argument (length) is derived from user input without comparison against the stack buffer size.
- In the decompiler: `memcpy(local_buf, user_buf, user_len)` where `local_buf` is on the stack and `user_len` is not validated.

#### Heap/Pool Buffer Overflows

**Pattern**: A pool allocation of size N is followed by a copy of user-controlled size M where M > N is possible.

```c
// Decompiled pseudocode — pool overflow
PVOID PoolBuffer = ExAllocatePoolWithTag(NonPagedPool, 0x100, 'Tag1');
if (PoolBuffer) {
    // BUG: InputLength from IOCTL can exceed 0x100
    RtlCopyMemory(PoolBuffer, UserBuffer, InputLength);
}
```

**In disassembly:**
```asm
    mov     edx, 100h               ; NumberOfBytes = 0x100
    mov     ecx, 0                   ; NonPagedPool
    mov     r8d, '1gaT'             ; Tag
    call    ExAllocatePoolWithTag
    test    rax, rax
    jz      short error
    mov     r8d, [rbx+10h]          ; r8 = InputLength (user-controlled, not clamped!)
    mov     rdx, rax                ; rdx = PoolBuffer
    mov     rcx, [rbx+18h]          ; rcx = UserBuffer
    call    memmove                  ; Overflow if InputLength > 0x100
```

#### Integer Overflow / Truncation

**Pattern**: An arithmetic operation on a length value wraps around, causing a small allocation followed by a large copy.

```c
// Classic integer overflow pattern
ULONG TotalSize = UserHeader->Count * sizeof(ELEMENT);  // Integer overflow if Count is large
PVOID Buffer = ExAllocatePoolWithTag(PagedPool, TotalSize, 'Vuln');
// TotalSize wrapped to small value, but Count elements are copied
for (ULONG i = 0; i < UserHeader->Count; i++) {
    RtlCopyMemory(&Buffer[i * sizeof(ELEMENT)], &Input[i], sizeof(ELEMENT));
}
```

**In disassembly** — look for `imul` or `mul` on user-controlled values without overflow checks:

```asm
    mov     eax, [rcx]              ; eax = UserHeader->Count
    imul    eax, 0x20               ; TotalSize = Count * 32 — NO overflow check
    mov     edx, eax                ; NumberOfBytes for allocation
    xor     ecx, ecx
    call    ExAllocatePoolWithTag
```

**Also watch for 32-bit truncation on 64-bit systems:**

```asm
    mov     rax, [rcx+8]            ; 64-bit user-supplied length
    mov     edx, eax                ; TRUNCATED to 32 bits! 
    ; If original value was 0x1_0000_0100, edx = 0x100
    call    ExAllocatePoolWithTag   ; Allocates 0x100 bytes
    ; But later copy uses the full 64-bit value...
```

#### Use-After-Free (UAF)

**Pattern**: An object is freed, a pointer to it is retained, and later dereferenced.

```c
// UAF pattern in decompiled code
ExFreePoolWithTag(ObjectPtr, 'Tag1');
// ObjectPtr is NOT set to NULL
// ... later, possibly in a different IOCTL handler:
if (ObjectPtr != NULL) {          // Check passes — dangling pointer
    ObjectPtr->Callback(arg);     // UAF — dereferences freed memory
}
```

**In disassembly**, track the lifecycle of pointers stored in global variables or device extension fields. Look for:
- `ExFreePoolWithTag` / `ExFreePool` without subsequent zeroing of the pointer.
- Global or structure-member pointers that are checked for non-NULL after the free.

#### Type Confusion

**Pattern**: A pointer is cast to an incorrect type, causing fields to be misinterpreted.

```c
// Type confusion — object type not validated before cast
PVOID Object = LookupObjectById(UserSuppliedId);
// BUG: No verification that Object is actually of type EXPECTED_STRUCT
PEXPECTED_STRUCT TypedObj = (PEXPECTED_STRUCT)Object;
TypedObj->FunctionPointer(TypedObj->Data);  // Controlled call if type is wrong
```

### 1.5 Cross-Referencing and Call Graph Analysis

Cross-references (xrefs) are the single most important navigation tool for mapping a binary's attack surface. Every time you identify a dangerous function or an interesting code path, xrefs tell you who calls it and with what arguments.

#### Attack Surface Mapping Workflow

```
Step 1: Identify Entry Points
    ├── DriverEntry → IoCreateDevice → IRP dispatch table
    ├── DllMain → Exported functions
    └── WinMain → Window procedures → message handlers

Step 2: Trace from Entry Points to Dangerous Sinks
    IRP_MJ_DEVICE_CONTROL handler
        → Switch on IoControlCode
            → Case 0x22200C: Handler_A()
                → memcpy(stack_buf, user_buf, user_len)  ← SINK
            → Case 0x222010: Handler_B()
                → ProbeForRead(user_ptr, ...)
                → MmMapLockedPagesSpecifyCache(...)       ← SINK

Step 3: Verify User Input Reaches Sinks (Taint Tracking)
    User controls: SystemBuffer, InputBufferLength, OutputBufferLength,
                   Type3InputBuffer (METHOD_NEITHER)
```

#### Building Call Graphs in IDA

```python
# IDAPython: Build call graph from a specific function
import idautils
import idc

def build_callgraph(ea, depth=0, max_depth=5, visited=None):
    if visited is None:
        visited = set()
    if ea in visited or depth > max_depth:
        return
    visited.add(ea)
    
    func_name = idc.get_func_name(ea)
    indent = "  " * depth
    print(f"{indent}├── {func_name} ({hex(ea)})")
    
    func = ida_funcs.get_func(ea)
    if not func:
        return
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, False):
            ref_func = ida_funcs.get_func(ref)
            if ref_func and ref_func.start_ea != ea:
                build_callgraph(ref_func.start_ea, depth + 1, max_depth, visited)

# Usage: build_callgraph(idc.get_name_ea_simple("DispatchDeviceControl"))
```

#### Cross-Reference Types

| Xref Type | IDA Notation | Meaning |
|-----------|-------------|---------|
| Code call | `call` (sub) | Direct function call |
| Code jump | `jmp` / `jcc` | Jump/branch to target |
| Data read | `r` | Data is read at this location |
| Data write | `w` | Data is written at this location |
| Data offset | `o` | Address of data is taken (LEA, pointer tables) |

**Data xrefs are critical** for finding where function pointers, vtables, and callback registrations occur. If a function pointer is stored in a global table, data xrefs reveal where that table is populated and where it is invoked.

### 1.6 Structure Reconstruction and Type Recovery

Raw binaries often lack type information. Reconstructing structures from access patterns is essential for understanding how objects are used and where boundaries can be violated.

#### Recognizing Structure Access Patterns

When the decompiler shows:

```c
v3 = *(_QWORD *)(a1 + 0x10);
*(_DWORD *)(a1 + 0x18) = 0;
result = (*(__int64 (__fastcall **)(_QWORD, _QWORD))(a1 + 0x20))(v3, a2);
```

This indicates a structure with at least the following layout:

```c
struct ReconstructedStruct {
    /* +0x00 */ UCHAR Unknown_0x00[0x10];
    /* +0x10 */ PVOID Pointer_0x10;         // 8-byte pointer (QWORD read)
    /* +0x18 */ ULONG Value_0x18;           // 4-byte value (DWORD write)
    /* +0x1C */ UCHAR Padding_0x1C[0x04];   // Alignment padding
    /* +0x20 */ PFUNC Callback_0x20;         // Function pointer (called)
    // Total minimum size: 0x28
};
```

#### IDA Structure Reconstruction

1. **Create a new struct**: `View -> Open subviews -> Structures` or `Shift+F9`. Press `Insert` to create.
2. **Add members**: Press `D` to add data members. Set type with `Y`.
3. **Apply to function**: In the decompiler, right-click the variable → "Set lvar type" → use the struct pointer type.

**Using HexRaysPyTools plugin (recommended):**
- Select multiple accesses to the same base in decompiled code.
- Right-click → "Reconstruct Structure" → auto-generates a struct definition.
- "Apply Structure" to propagate it throughout the function.

#### Recovering Known Windows Structures

For kernel drivers, many accessed structures are documented in the WDK. Common ones to recognize by access patterns:

```c
// _IRP structure — common access patterns:
// Irp->IoStatus.Status          = *(NTSTATUS *)(Irp + 0x30)
// Irp->IoStatus.Information     = *(ULONG_PTR *)(Irp + 0x38)
// Irp->AssociatedIrp.SystemBuffer = *(PVOID *)(Irp + 0x18)
// Irp->UserBuffer               = *(PVOID *)(Irp + 0x70)

// _IO_STACK_LOCATION — DeviceIoControl parameters:
// IoSL->Parameters.DeviceIoControl.OutputBufferLength  = *(ULONG *)(IoSL + 0x08)
// IoSL->Parameters.DeviceIoControl.InputBufferLength   = *(ULONG *)(IoSL + 0x10)
// IoSL->Parameters.DeviceIoControl.IoControlCode       = *(ULONG *)(IoSL + 0x18)
// IoSL->Parameters.DeviceIoControl.Type3InputBuffer    = *(PVOID *)(IoSL + 0x20)
```

Load Windows type libraries in IDA:
- `View -> Open subviews -> Type libraries` → Add `ntddk64` (for 64-bit kernel) or `ntapi64`.
- In Ghidra: `File -> Parse C Source` → add WDK `ntddk.h` with appropriate preprocessor definitions.

### 1.7 Identifying Security-Relevant Functions

A targeted approach to code auditing begins with identifying calls to functions that handle memory, validate user input, or perform privileged operations.

#### Critical Functions by Category

**Memory Copy/Move (check length validation):**

| Function | Source | Notes |
|----------|--------|-------|
| `memcpy` / `RtlCopyMemory` | C runtime / ntoskrnl | No bounds checking; verify length arg |
| `memmove` / `RtlMoveMemory` | C runtime / ntoskrnl | Overlap-safe; still no bounds check |
| `RtlCopyBytes` | ntoskrnl | Equivalent to RtlCopyMemory |
| `RtlCopyUnicodeString` | ntoskrnl | Copies UNICODE_STRING; check MaximumLength |
| `memset` / `RtlFillMemory` | C runtime / ntoskrnl | Check length for overwrite bugs |
| `RtlZeroMemory` | ntoskrnl | Zero-fill; check length |

**String Operations (check buffer sizes):**

| Function | Risk |
|----------|------|
| `strcpy` / `wcscpy` | No length limit — always dangerous |
| `strncpy` / `wcsncpy` | May not null-terminate |
| `sprintf` / `swprintf` | No output bounds; use snprintf |
| `strcat` / `wcscat` | No length limit |
| `RtlStringCbCopyW` / `RtlStringCchCopyW` | Safe variants — still check usage |

**User-Buffer Validation (check for missing or incorrect validation):**

| Function | Purpose |
|----------|---------|
| `ProbeForRead(Addr, Length, Alignment)` | Verify user-mode address is readable |
| `ProbeForWrite(Addr, Length, Alignment)` | Verify user-mode address is writable |
| `MmIsAddressValid` | Checks if address is valid (NOT a security check — can be TOCTOU) |
| `ExGetPreviousMode()` | Returns `UserMode` or `KernelMode` — must be checked before trusting pointers |

**ProbeForRead/Write are critical and commonly misused:**

```c
// CORRECT pattern:
__try {
    ProbeForRead(UserBuffer, Length, sizeof(UCHAR));
    RtlCopyMemory(KernelBuffer, UserBuffer, Length);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode();
}

// VULNERABLE patterns:
// 1. Missing probe entirely (METHOD_NEITHER without validation)
// 2. Probing once but using the buffer multiple times (double-fetch / TOCTOU)
// 3. Not wrapping access in __try/__except (user can unmap the page)
// 4. Wrong probe length (probes 4 bytes but copies 0x100)
```

**Memory Allocation (check for allocation/copy size mismatches):**

| Function | Notes |
|----------|-------|
| `ExAllocatePool` | Deprecated — no NX flag |
| `ExAllocatePoolWithTag` | Check tag for tracking; verify size |
| `ExAllocatePool2` | Modern replacement (Win10 2004+) |
| `ExAllocatePoolZero` | Zero-initialized; prevents info leak |
| `ExFreePoolWithTag` | Must match allocation tag |
| `MmAllocateContiguousMemory` | Physical contiguous; rare in normal drivers |

**Privileged Operations (potential for escalation):**

| Function | Risk |
|----------|------|
| `MmMapIoSpace` | Maps physical address to virtual — arbitrary read/write physical memory |
| `MmMapLockedPagesSpecifyCache` | Maps MDL pages — info leak if mapped to user space |
| `ZwMapViewOfSection` | Maps section into process — memory injection |
| `SePrivilegeCheck` | Privilege validation — check if bypassed |
| `SeSinglePrivilegeCheck` | Single privilege check — verify correct privilege |
| `ObReferenceObjectByHandle` | Object access — check access mask validation |

---

## 2. Dynamic Analysis Techniques

Dynamic analysis complements static analysis by revealing runtime behavior — actual memory layouts, register states during vulnerable code paths, heap/pool states, and the precise conditions under which crashes occur. For OSEE, WinDbg is the primary tool for both kernel and user-mode debugging.

### 2.1 WinDbg for User-Mode and Kernel-Mode Debugging

#### Setup and Configuration

**Kernel debugging with a VM (typical OSEE setup):**

1. **Configure the debuggee VM** (Windows target):
   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:<HostIP> port:50000 key:1.2.3.4
   ```
   For serial/pipe debugging (VMware/VirtualBox):
   ```cmd
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```

2. **Configure the host** (WinDbg):
   - Open WinDbg → `File -> Kernel Debug`
   - Select `NET` tab, enter port and key matching the debuggee
   - Or select `COM` tab for serial debugging

3. **Symbol path** (essential):
   ```
   .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   .reload
   ```

4. **Source path** (if source is available):
   ```
   .srcpath C:\DriverSource
   ```

**User-mode debugging:**
```
# Attach to process
windbg -p <PID>

# Launch process under debugger
windbg target.exe arguments

# Attach non-invasively (inspect without stopping)
windbg -pv -p <PID>
```

#### WinDbg Variants

| Variant | Use Case |
|---------|----------|
| **WinDbg (classic)** | Lightweight, fast startup, familiar UI |
| **WinDbg Preview** | Modern UI, Time Travel Debugging (TTD), better UX |
| **kd.exe** | Command-line only kernel debugger |
| **cdb.exe** | Command-line only user-mode debugger |
| **KDNET** | Network-based kernel debugging (fastest for VMs) |

### 2.2 Essential WinDbg Commands for Exploit Development

#### Crash Analysis

```
!analyze -v
```
The single most important command after a crash. It provides:
- Exception type and code
- Faulting instruction
- Call stack with symbols
- The "probably caused by" module
- Bucket ID for categorization

```
!analyze -v
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

SYSTEM_SERVICE_EXCEPTION (3b)
An exception happened while executing a system service routine.
Arguments:
Arg1: 00000000c0000005, Exception code (STATUS_ACCESS_VIOLATION)
Arg2: fffff80012345678, Address where the exception occurred
Arg3: ffffa50012340000, Exception record address
Arg4: 0000000000000000

STACK_TEXT:
fffff802`1a3b5678 nt!KeBugCheckEx
fffff802`1a3b5700 nt!KiDispatchException+0x1a5
fffff802`1a3b5890 VulnDriver!DispatchIoctl+0x142
fffff802`1a3b58f0 nt!IofCallDriver+0x55
fffff802`1a3b5930 nt!IopSynchronousServiceTail+0x1a8
```

#### Memory Display Commands

```
# Display memory in various formats
db <addr>            # Display bytes (hex + ASCII)
dw <addr>            # Display words (16-bit)
dd <addr>            # Display dwords (32-bit)
dq <addr>            # Display qwords (64-bit)
dp <addr>            # Display pointer-sized values
da <addr>            # Display ASCII string
du <addr>            # Display Unicode string
dps <addr>           # Display pointers with symbols
dpp <addr>           # Display pointer-to-pointer with symbols
dyb <addr>           # Display binary and bytes

# Display with length
db <addr> L<count>   # Display <count> bytes
dq <addr> L8         # Display 8 qwords

# Display memory as specific type
dt nt!_EPROCESS <addr>              # Display EPROCESS structure
dt nt!_POOL_HEADER <addr>           # Display pool header
dt nt!_IRP <addr>                   # Display IRP structure
dt nt!_IO_STACK_LOCATION <addr>     # Display IO stack location
dt -r nt!_EPROCESS <addr>           # Recursive display (expand sub-structures)
dt -r2 nt!_EPROCESS <addr>          # Recursive depth of 2 levels
```

#### Pool Analysis Commands

```
# Pool information (critical for kernel heap exploitation)
!pool <addr>                # Show pool allocation info for address
!poolval <addr>             # Validate pool page
!poolfind <tag>             # Find all pool allocations with a given tag
!poolused                   # Summary of pool usage by tag
!poolused 2                 # Sort by paged pool usage

# Example output of !pool:
!pool ffffda8012345000
Pool page ffffda8012345000 region is Nonpaged pool
 ffffda8012344ff0 size:   30 previous size:    0  (Allocated)  VulT
*ffffda8012345020 size:  120 previous size:   30  (Allocated) *VulT    ← Target
 ffffda8012345140 size:   40 previous size:  120  (Free)       ....

# Pool search by tag
!poolfind VulT 2            # Search nonpaged pool for tag "VulT"
```

#### Breakpoint Commands

```
# Software breakpoints
bp <addr>                            # Break at address
bp VulnDriver!DispatchIoctl          # Break at symbol
bp nt!NtDeviceIoControlFile          # Break at IOCTL syscall
bu <addr>                            # Deferred breakpoint (unresolved symbols)
bu VulnDriver!DispatchIoctl          # Will resolve when module loads

# Hardware breakpoints (no memory modification — essential for pool/heap)
ba r4 <addr>                         # Break on read of 4 bytes at addr
ba w8 <addr>                         # Break on write of 8 bytes at addr
ba e1 <addr>                         # Break on execute at addr

# Conditional breakpoints
bp VulnDriver!DispatchIoctl ".if (dwo(@rcx+0x18) == 0x22200C) {} .else {gc}"
# Only break if IoControlCode == 0x22200C

# Breakpoint with logging (don't stop, just log)
bp kernel32!CreateFileW ".printf \"CreateFileW(%mu)\\n\", @rcx; gc"
bp nt!NtDeviceIoControlFile ".printf \"IOCTL: Handle=%p Code=%x InLen=%x\\n\", @rcx, @r9, poi(@rsp+0x28); gc"

# Manage breakpoints
bl                                   # List all breakpoints
bc <num>                             # Clear breakpoint by number
bc *                                 # Clear all breakpoints
bd <num>                             # Disable breakpoint
be <num>                             # Enable breakpoint
```

#### Register and Stack Commands

```
r                    # Display all registers
r rax                # Display specific register
r rax=0              # Modify register value
r @$ip               # Instruction pointer (alias)
r @$retreg           # Return value register (rax on x64)

# Stack operations
k                    # Display call stack
kp                   # Call stack with parameters
kv                   # Call stack with FPO data and calling convention
kn                   # Call stack with frame numbers
kf                   # Call stack with frame distances
.frame <n>           # Switch to frame n for local variable inspection
dv                   # Display local variables in current frame
```

#### Execution Control

```
g                    # Go (continue execution)
p                    # Step over (execute one instruction, skip calls)
t                    # Trace (step into calls)
pt                   # Step to next return instruction
ph                   # Step to next branch instruction
pc                   # Step to next call instruction
gu                   # Go up (execute until return from current function)
pa <addr>            # Step to address
```

#### Search Commands

```
# Search memory
s -b <start> L<length> <byte pattern>   # Search bytes
s -d <start> L<length> <dword>          # Search dwords
s -q <start> L<length> <qword>          # Search qwords
s -a <start> L<length> "string"         # Search ASCII string
s -u <start> L<length> "string"         # Search Unicode string

# Examples:
s -b fffff800`00000000 L?7fffffff 41 41 41 41     # Search kernel space for "AAAA"
s -d 0 L?80000000 0x22200C                         # Search for IOCTL code
s -q fffff800`00000000 L?1000000 nt!MiGetPteAddress # Search for function pointer
```

#### Module and Symbol Commands

```
lm                           # List loaded modules
lm m Vuln*                   # List modules matching pattern
lmDvm VulnDriver             # Detailed module info
x VulnDriver!*               # List all symbols in module
x nt!MmMap*                  # List symbols matching pattern
ln <addr>                    # List nearest symbols to address
.reload                      # Reload symbols
.reload /f VulnDriver.sys    # Force reload specific module
!lmi VulnDriver              # Module information with PE details
```

#### Process and Thread Commands

```
!process 0 0                     # List all processes (brief)
!process 0 7                     # List all processes (detailed)
!process <addr> 7                # Detailed info for specific process
.process /i <EPROCESS addr>      # Switch to process context (invasive)
.process /r /p <EPROCESS addr>   # Switch context and reload user symbols

!thread <addr>                   # Thread information
!thread -t <TID>                 # Thread by ID
.thread <ETHREAD addr>           # Switch to thread context

# Current process/thread
!process -1 0                    # Current process
!thread -1 0                     # Current thread
```

#### Additional Essential Extensions

```
!object <addr>              # Display object header and type
!handle <handle> f          # Display handle information
!devobj <addr>              # Device object information
!drvobj <name> 2            # Driver object with dispatch table
!irp <addr>                 # IRP information
!ioctldecode <code>         # Decode IOCTL code (device type, function, method, access)

# Example: Decode IOCTL 0x22200C
!ioctldecode 0x22200C
# Device type: FILE_DEVICE_UNKNOWN (0x22)
# Function:    0x803
# Method:      METHOD_BUFFERED (0)
# Access:      FILE_READ_DATA | FILE_WRITE_DATA (3)

# Security-related
!token <addr>               # Display token information
!token -n                   # Current thread's token
!acl <addr>                 # Display ACL
!sd <addr>                  # Display security descriptor

# Miscellaneous
!pte <virtual_addr>         # Page table entry for virtual address
!vtop <pgd> <vaddr>         # Virtual to physical translation
!address <addr>             # Show memory region type and protections
!address -summary           # Summary of address space usage
!vprot <addr>               # Virtual memory protection on user-mode address
```

### 2.3 x64dbg for User-Mode Analysis

x64dbg is a free, open-source user-mode debugger with a modern interface. While WinDbg is superior for kernel debugging, x64dbg excels at user-mode binary analysis with its visual approach.

#### Key Features for Exploit Development

- **Graph view**: Visualize control flow of functions (similar to IDA's graph view).
- **Conditional breakpoints with scripting**: Rich expression language for complex break conditions.
- **Plugin architecture**: Extensive plugin ecosystem.
- **Trace recording**: Log all executed instructions to a file for post-mortem analysis.
- **Memory map visualization**: Interactive view of the process address space.
- **Pattern scanning**: Built-in byte pattern scanning with wildcard support.

#### Essential x64dbg Operations

```
# Breakpoints
bp <addr>                       # Software breakpoint
bph <addr>, r, 4                # Hardware read breakpoint, 4 bytes
bph <addr>, w, 8                # Hardware write breakpoint, 8 bytes
bpc <addr>                      # Conditional: break if condition true
SetBreakpointCondition <addr>, "eax==0x22200C"

# Tracing
TraceIntoConditional <condition> # Trace into until condition met
TraceOverConditional <condition> # Trace over until condition met
StartRunTrace                    # Begin recording trace
StopRunTrace                     # Stop recording

# Memory
findall <module>, <pattern>      # Find byte pattern in module
findallmem <start>, <pattern>, <size>  # Find in memory range

# Scripting (x64dbgpy — Python plugin)
import x64dbg
x64dbg.DbgCmdExec("bp ntdll.NtDeviceIoControlFile")
```

#### Useful x64dbg Plugins

| Plugin | Purpose |
|--------|---------|
| **x64dbgpy** | Python scripting support |
| **ScyllaHide** | Anti-anti-debug (hide debugger from target) |
| **SharpOD** | Anti-anti-debug plugin |
| **SwissArmyKnife** | Automation utilities |
| **ret-sync** | Synchronize with IDA Pro |
| **xAnalyzer** | Auto-analysis of API calls and parameters |
| **Multiline Ultimate Assembler** | Inline patching with assembler |

### 2.4 Setting Breakpoints on Key APIs

Strategic breakpoint placement is critical for observing how a target processes untrusted input. The following APIs are the most relevant for OSEE vulnerability discovery.

#### Kernel-Mode Breakpoints (WinDbg)

```
# IOCTL Handling — the primary attack surface for drivers
bp nt!NtDeviceIoControlFile       # All IOCTLs from user mode
bp nt!IopXxxControlFile           # Internal IOCTL dispatcher

# Break on specific driver's dispatch routine:
# First, find the dispatch table:
!drvobj \Driver\VulnDriver 2
# Then set breakpoint on IRP_MJ_DEVICE_CONTROL handler:
bp <IRP_MJ_DEVICE_CONTROL_addr>

# Memory allocation — track what's allocated and where
bp nt!ExAllocatePoolWithTag ".printf \"AllocPool: Tag=%c%c%c%c Size=%x\\n\", by(@r8), by(@r8+1), by(@r8+2), by(@r8+3), @edx; gc"
bp nt!ExFreePoolWithTag ".printf \"FreePool: Addr=%p Tag=%c%c%c%c\\n\", @rcx, by(@rdx), by(@rdx+1), by(@rdx+2), by(@rdx+3); gc"

# Memory copy — detect potential overflows
bp nt!memcpy ".printf \"memcpy(dst=%p, src=%p, len=%x)\\n\", @rcx, @rdx, @r8; gc"
bp nt!memmove ".printf \"memmove(dst=%p, src=%p, len=%x)\\n\", @rcx, @rdx, @r8; gc"

# User-buffer validation — verify probing is done
bp nt!ProbeForRead ".printf \"ProbeForRead(addr=%p, len=%x, align=%x)\\n\", @rcx, @edx, @r8d; gc"
bp nt!ProbeForWrite ".printf \"ProbeForWrite(addr=%p, len=%x, align=%x)\\n\", @rcx, @edx, @r8d; gc"

# Virtual memory — detect user-mode allocation for shellcode staging
bp nt!NtAllocateVirtualMemory ".printf \"NtAllocVMem: Proc=%p, Addr=%p, Size=%p, Prot=%x\\n\", @rcx, poi(@rdx), poi(@r9), dwo(@rsp+0x30); gc"

# Object management
bp nt!ObReferenceObjectByHandle
bp nt!ObDereferenceObject

# Token/privilege operations
bp nt!SePrivilegeCheck
bp nt!NtSetInformationToken
```

#### User-Mode Breakpoints (WinDbg or x64dbg)

```
# File operations
bp kernel32!CreateFileW ".printf \"CreateFileW(%mu)\\n\", @rcx; gc"
bp kernel32!ReadFile
bp kernel32!WriteFile

# Memory operations
bp kernel32!VirtualAlloc ".printf \"VAlloc: Addr=%p Size=%x Prot=%x\\n\", @rcx, @rdx, @r9; gc"
bp kernel32!VirtualProtect ".printf \"VProtect: Addr=%p Size=%x NewProt=%x\\n\", @rcx, @rdx, @r8; gc"

# Process/thread
bp kernel32!CreateProcessW
bp ntdll!NtCreateThreadEx

# Registry
bp advapi32!RegOpenKeyExW
bp advapi32!RegSetValueExW

# Network
bp ws2_32!recv
bp ws2_32!send
bp ws2_32!WSARecv

# IOCTL from user mode
bp kernel32!DeviceIoControl ".printf \"DeviceIoControl: Handle=%p, Code=%x, InBuf=%p, InLen=%x, OutBuf=%p, OutLen=%x\\n\", @rcx, @edx, @r8, @r9, poi(@rsp+0x28), poi(@rsp+0x30); gc"
```

### 2.5 Tracing Execution Flow with Conditional Breakpoints and Logging

Conditional breakpoints allow selective breaking and logging without halting execution on every hit. This is essential for high-frequency functions.

#### WinDbg Conditional Breakpoint Syntax

```
# General syntax:
bp <addr> ".if (<condition>) {<true_cmds>} .else {gc}"

# Break only when specific IOCTL code is used:
bp VulnDriver!DispatchIoctl ".if (dwo(@rdx+0x18) == 0x22200C) {.printf \"Target IOCTL hit!\\n\"; k} .else {gc}"

# Break when buffer size exceeds expected maximum:
bp VulnDriver!CopyHandler ".if (@r8 > 0x100) {.printf \"OVERSIZED COPY: len=%x\\n\", @r8; k} .else {gc}"

# Break when a specific process calls into the driver:
bp VulnDriver!DispatchIoctl ".if (@$peb == <target_peb>) {} .else {gc}"
# Or by image name:
bp VulnDriver!DispatchIoctl ".if (dwo(@$peb+0x10) == 'expl') {} .else {gc}"

# Log all calls with parameters without stopping:
bp VulnDriver!InternalCopy ".printf \"Copy: dst=%p src=%p len=%x caller=%y\\n\", @rcx, @rdx, @r8, poi(@rsp); gc"
```

#### Trace Logging to File

```
# Open a log file
.logopen C:\debug_log.txt

# Set logging breakpoints (gc = go-continue, doesn't stop)
bp VulnDriver!DispatchIoctl ".printf \"[%08x] IOCTL=%x InLen=%x OutLen=%x\\n\", @$tid, dwo(@rdx+0x18), dwo(@rdx+0x10), dwo(@rdx+0x08); gc"

# Run the target
g

# After testing, close the log
.logclose
```

#### Windows Performance Toolkit (WPT) / ETW Tracing

For broader system-level tracing without a debugger, Event Tracing for Windows (ETW) can capture:
- System call activity
- File I/O and registry operations
- Network activity
- Driver activity

```powershell
# Start an ETW trace for IOCTL activity
logman create trace IOCTLTrace -p "Microsoft-Windows-Kernel-IoTrace" 0xFFFF -ets
# ... exercise the target ...
logman stop IOCTLTrace -ets
# Analyze with Windows Performance Analyzer (WPA) or tracerpt
```

### 2.6 Memory Inspection Techniques

#### Heap State Analysis (User-Mode)

```
# Windows heap commands
!heap -s                    # Summary of all heaps
!heap -a <heap_addr>        # Detailed dump of a heap
!heap -h <heap_addr>        # Heap entries
!heap -p -a <addr>          # Page heap info for an address (requires gflags)
!heap -flt s <size>         # Find heap entries of specific size

# Enable page heap for detailed tracking (run before debugging):
# gflags.exe /p /enable target.exe /full
# This places guard pages around allocations → instant detection of overflows

# Low Fragmentation Heap (LFH) — common in modern Windows
# LFH uses buckets of fixed sizes; inspect with:
!heap -p -all               # Show all page heap allocations
dt ntdll!_HEAP_ENTRY <addr> # Display heap entry metadata
```

#### Kernel Pool State Analysis

```
# Pool header inspection
dt nt!_POOL_HEADER <addr>

# Output:
#    +0x000 PreviousSize     : 0y00000000 (0)
#    +0x000 PoolIndex        : 0y0000000 (0)
#    +0x002 BlockSize        : 0y00010010 (0x12) → actual size = 0x12 * 0x10 = 0x120
#    +0x002 PoolType         : 0y0000010 (2) → NonPagedPool
#    +0x004 PoolTag          : 0x546c7556 ('VulT')

# Pool spraying verification — check adjacent allocations:
!pool <addr>                # Shows neighboring chunks
# Walk forward/backward:
dt nt!_POOL_HEADER <addr>+0x120   # Next chunk (BlockSize * 0x10)

# Verify pool corruption:
!poolval <page_addr>        # Validates pool page integrity

# Kernel pool types (Windows 10 19H1+ with segment heap):
# NonPagedPoolNx (default for new allocations)
# PagedPool
# Pool segments are managed differently — use:
!ext !poolpage <addr>        # Extended pool info
```

#### Stack Analysis

```
# View raw stack contents with symbols
dps @rsp L40                # Display 40 pointer-sized values from stack with symbols

# Find return addresses on stack:
dps @rsp @rsp+0x200         # Dump stack range with symbol resolution

# Check stack limits:
!thread -1 0                # Shows stack base and limit
# Or manually:
r @rsp                      # Current stack pointer
dt nt!_KTHREAD <thread_addr> StackBase
dt nt!_KTHREAD <thread_addr> StackLimit
dt nt!_KTHREAD <thread_addr> InitialStack

# Calculate remaining stack space:
? <StackLimit> - @rsp       # Space used
? @rsp - <StackBase>        # Space remaining (x64 stacks grow down)
```

### 2.7 Crash Analysis with !analyze -v and Triage Methodology

#### Systematic Crash Triage

When a crash occurs (BSOD for kernel, access violation for user-mode), follow this methodology:

```
Step 1: Initial Analysis
─────────────────────────
!analyze -v                   # Automated analysis
# Note: Exception code, faulting address, call stack, "probably caused by"

Step 2: Examine the Faulting Context
─────────────────────────────────────
r                             # Register state at crash
u @rip L10                    # Disassemble around faulting instruction
db @rcx L20                   # Examine memory at faulting address (if access violation)

Step 3: Analyze the Call Stack
──────────────────────────────
k                             # Call stack
.frame 1                      # Switch to caller's frame
dv                            # Local variables in caller
.frame 2                      # Continue up the stack

Step 4: Determine Root Cause
────────────────────────────
# For pool corruption:
!pool @rcx                    # Check if the faulting address is in a pool allocation
dt nt!_POOL_HEADER @rcx-0x10  # Check pool header before the allocation

# For stack overflow:
!thread -1 0                  # Check stack boundaries
? @rsp - <StackBase>          # Was the stack exhausted?

# For use-after-free:
!pool @rcx                    # Is the pool chunk freed?
# If "(Free)" appears, it's a UAF

Step 5: Assess Exploitability
─────────────────────────────
# Check if attacker controls the faulting address:
# - If the crash is at an address derived from user input → likely exploitable
# - If crash is READ at controlled address → info leak or read primitive
# - If crash is WRITE to controlled address → write primitive
# - If crash is EXECUTE at controlled address → code execution
# - If crash is in memcpy with controlled length → overflow → likely exploitable
```

#### Common Bugcheck Codes Relevant to Exploitation

| Bugcheck | Code | Typical Root Cause |
|----------|------|-------------------|
| `IRQL_NOT_LESS_OR_EQUAL` | 0x0A | Accessing pageable memory at elevated IRQL; often from corrupted pointer |
| `DRIVER_IRQL_NOT_LESS_OR_EQUAL` | 0x0D1 | Same, but specifically in a driver |
| `SYSTEM_SERVICE_EXCEPTION` | 0x3B | Unhandled exception in system service; buffer overflow, null deref |
| `KMODE_EXCEPTION_NOT_HANDLED` | 0x1E | Unhandled kernel exception |
| `PAGE_FAULT_IN_NONPAGED_AREA` | 0x50 | Access to invalid memory; UAF, corrupted pointer |
| `KERNEL_DATA_INPAGE_ERROR` | 0x7A | Page could not be read; may indicate corruption |
| `SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION` | 0xC1 | Special pool detected overflow |
| `BAD_POOL_HEADER` | 0x19 | Pool header corruption; overflow or UAF |
| `BAD_POOL_CALLER` | 0xC2 | Invalid pool operation; double free, bad tag |

#### Time Travel Debugging (TTD)

WinDbg Preview supports Time Travel Debugging for user-mode processes — recording execution for replay:

```
# Record a trace
# In WinDbg Preview: File -> Launch executable (advanced) -> Check "Record with Time Travel"
# Or command-line:
tttracer.exe -out C:\traces -launch target.exe

# Replay and reverse-execute
g-                           # Reverse-go (go backward)
p-                           # Reverse step-over
t-                           # Reverse step-into

# Set breakpoints and reverse to find who corrupted memory:
ba w8 <addr>                 # Hardware write breakpoint on corrupted address
g-                           # Reverse-execute to find the write

# TTD query objects:
dx @$cursession.TTD.Calls("ntdll!NtDeviceIoControlFile")     # All calls to API
dx @$cursession.TTD.Memory(0x1234, 0x1238, "w")              # All writes to address range
```

---

## 3. Vulnerability Discovery Methodology

Vulnerability discovery for OSEE requires a systematic approach that maps the attack surface, identifies input vectors, and then applies a combination of fuzzing and manual auditing to find exploitable bugs.

### 3.1 Attack Surface Mapping

The attack surface is every code path reachable from an untrusted input. For Windows kernel drivers, the attack surface is well-defined:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Attack Surface Map                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  User Mode → Kernel Mode Entry Points:                             │
│                                                                     │
│  1. IOCTL Handlers (IRP_MJ_DEVICE_CONTROL)                        │
│     └── DeviceIoControl() → NtDeviceIoControlFile()               │
│         └── Driver's IRP_MJ_DEVICE_CONTROL dispatch function       │
│             └── Switch on IoControlCode                            │
│                 ├── IOCTL_CODE_1: Handler_1()                      │
│                 ├── IOCTL_CODE_2: Handler_2()                      │
│                 └── IOCTL_CODE_N: Handler_N()                      │
│                                                                     │
│  2. File Operation Handlers                                        │
│     ├── IRP_MJ_CREATE    (CreateFile)                              │
│     ├── IRP_MJ_READ      (ReadFile)                                │
│     ├── IRP_MJ_WRITE     (WriteFile)                               │
│     └── IRP_MJ_CLOSE     (CloseHandle)                             │
│                                                                     │
│  3. Fast I/O Handlers                                              │
│     └── FastIoDeviceControl (bypasses IRP creation)                │
│                                                                     │
│  4. Network Handlers (NDIS/WFP/TDI drivers)                       │
│     ├── Packet receive callbacks                                   │
│     ├── Protocol handlers                                          │
│     └── Filter callbacks                                           │
│                                                                     │
│  5. Registry Callbacks (CmRegisterCallback)                        │
│                                                                     │
│  6. File System Filter Callbacks                                   │
│     ├── Pre/Post operation callbacks                               │
│     └── Name provider callbacks                                    │
│                                                                     │
│  7. Win32k.sys (GDI/User syscalls)                                 │
│     ├── NtGdiXxx / NtUserXxx syscalls                              │
│     ├── Window message handlers                                    │
│     └── Font parsing (historically rich bug source)                │
│                                                                     │
│  8. Syscall Handlers                                               │
│     └── Direct Nt/Zw system calls to ntoskrnl                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### IOCTL Attack Surface Enumeration

For a driver-focused assessment, enumerate all supported IOCTL codes:

```python
# Python script to enumerate IOCTLs from a driver binary using pefile + disassembly
# This is a static approach — complement with dynamic tracing

import pefile
import struct

def decode_ioctl(code):
    """Decode IOCTL code into device type, function, method, and access."""
    device_type = (code >> 16) & 0xFFFF
    access      = (code >> 14) & 0x3
    function    = (code >> 2) & 0xFFF
    method      = code & 0x3
    
    methods = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT", 
               2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}
    access_map = {0: "FILE_ANY_ACCESS", 1: "FILE_READ_ACCESS", 
                  2: "FILE_WRITE_ACCESS", 3: "FILE_READ|WRITE_ACCESS"}
    
    return {
        "code": hex(code),
        "device_type": hex(device_type),
        "function": hex(function),
        "method": methods.get(method, f"UNKNOWN({method})"),
        "access": access_map.get(access, f"UNKNOWN({access})")
    }

# Example:
info = decode_ioctl(0x22200C)
# {'code': '0x22200c', 'device_type': '0x22', 'function': '0x803',
#  'method': 'METHOD_BUFFERED', 'access': 'FILE_READ|WRITE_ACCESS'}
```

**METHOD_NEITHER** is particularly dangerous — the kernel does not buffer or probe user-mode pointers. The driver receives raw user-mode addresses and must validate them manually:

```c
// METHOD_NEITHER handling — common source of vulnerabilities
case IOCTL_METHOD_NEITHER:
    UserInputBuffer  = IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
    UserOutputBuffer = Irp->UserBuffer;
    
    // VULNERABLE if the driver does not:
    // 1. Check PreviousMode (ExGetPreviousMode())
    // 2. Call ProbeForRead/ProbeForWrite on user pointers
    // 3. Wrap all accesses in __try/__except
    // 4. Prevent double-fetch (TOCTOU) conditions
```

### 3.2 Input Vector Identification in Drivers and Applications

#### Driver Input Vectors

For each IOCTL code, identify:

1. **Input buffer and length**: Where does user data enter the kernel?
2. **Output buffer and length**: Where does the kernel write results?
3. **Buffer method**: How is the buffer transferred (Buffered, Direct, Neither)?

```c
// Buffered I/O (METHOD_BUFFERED):
// Input:  Irp->AssociatedIrp.SystemBuffer  (kernel copy of user input)
// Output: Irp->AssociatedIrp.SystemBuffer  (same buffer, overwritten on output)
// Lengths: IoStackLocation->Parameters.DeviceIoControl.InputBufferLength
//          IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength

// Direct I/O (METHOD_IN_DIRECT / METHOD_OUT_DIRECT):
// Input:  Irp->AssociatedIrp.SystemBuffer  (small input, kernel-buffered)
// Output: Irp->MdlAddress → MmGetSystemAddressForMdlSafe()  (large buffer, MDL-mapped)

// Neither I/O (METHOD_NEITHER):
// Input:  IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer  (RAW user pointer)
// Output: Irp->UserBuffer  (RAW user pointer)
// WARNING: Driver must validate these pointers manually!
```

#### Application Input Vectors

For user-mode applications:

```
┌──────────────────────────────────────────┐
│           Application Input Vectors       │
├──────────────────────────────────────────┤
│  • File parsing (images, documents,      │
│    fonts, media, archives, configs)      │
│  • Network protocols (HTTP, RPC, SMB,    │
│    custom TCP/UDP protocols)             │
│  • IPC mechanisms (named pipes, shared   │
│    memory, LPC/ALPC, COM/DCOM)           │
│  • Registry data                          │
│  • Environment variables                  │
│  • Command-line arguments                 │
│  • Clipboard data                         │
│  • Drag-and-drop                          │
│  • Window messages (WM_COPYDATA, etc.)   │
│  • Active Directory / LDAP data           │
│  • Certificate / ASN.1 parsing           │
│  • USB / device descriptors              │
└──────────────────────────────────────────┘
```

### 3.3 Fuzzing Approaches

Fuzzing is the most efficient method for discovering memory corruption vulnerabilities at scale. Three main approaches are relevant for OSEE work.

#### Dumb Fuzzing with ioctlbf

`ioctlbf` (IOCTL Brute Forcer) is a simple but effective tool for finding kernel driver vulnerabilities by sending randomized IOCTLs:

```c
// Conceptual operation of ioctlbf:
// 1. Open handle to device: CreateFile("\\\\.\\VulnDevice", ...)
// 2. For each IOCTL code in range:
//    a. Generate random input buffers of various sizes
//    b. Call DeviceIoControl(handle, ioctl_code, inbuf, insize, outbuf, outsize, ...)
//    c. Detect crash (driver bugcheck → system crash)
// 3. Record crashing inputs for reproduction

// Custom IOCTL fuzzer skeleton:
#include <windows.h>
#include <stdio.h>

#define DEVICE_NAME L"\\\\.\\VulnDevice"

int main() {
    HANDLE hDevice = CreateFileW(DEVICE_NAME, 
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %d\n", GetLastError());
        return 1;
    }
    
    BYTE inBuf[0x1000];
    BYTE outBuf[0x1000];
    DWORD bytesReturned;
    
    // Enumerate IOCTL codes: device type 0x22, function 0x800-0x900
    for (DWORD func = 0x800; func < 0x900; func++) {
        for (DWORD method = 0; method < 4; method++) {
            DWORD ioctl = CTL_CODE(0x22, func, method, FILE_ANY_ACCESS);
            
            // Test with various buffer sizes
            DWORD sizes[] = {0, 1, 4, 8, 0x10, 0x40, 0x100, 0x200, 0x1000};
            for (int i = 0; i < ARRAYSIZE(sizes); i++) {
                // Fill with pattern for overflow detection
                memset(inBuf, 'A', sizeof(inBuf));
                *(DWORD*)inBuf = 0xDEADBEEF;  // Magic header
                
                BOOL result = DeviceIoControl(hDevice, ioctl,
                    inBuf, sizes[i], outBuf, sizeof(outBuf), 
                    &bytesReturned, NULL);
                
                printf("[%s] IOCTL=%08X InLen=%04X OutLen=%04X Ret=%d\n",
                    result ? "+" : "-", ioctl, sizes[i], bytesReturned,
                    GetLastError());
            }
        }
    }
    
    CloseHandle(hDevice);
    return 0;
}
```

**Advantages**: Simple, fast, low barrier. Finds shallow bugs quickly.
**Limitations**: No code coverage feedback, unlikely to reach deep code paths, no state awareness.

#### Smart Fuzzing with WinAFL

WinAFL is a Windows port of AFL (American Fuzzy Lop) that uses DynamoRIO or Intel PT for code coverage feedback:

```bash
# Step 1: Identify the target function and build a harness
# The harness should:
# - Open the target file/data from argv[1] or stdin
# - Call the parsing function
# - Return cleanly

# Step 2: Dry run to verify instrumentation
afl-fuzz.exe -D C:\DynamoRIO\bin64 -i corpus -o output \
    -t 10000 --                                        \
    -coverage_module target.dll                        \
    -target_module harness.exe                         \
    -target_method TargetFunction                      \
    -nargs 2                                            \
    -- harness.exe @@

# Step 3: Run the fuzzer
afl-fuzz.exe -D C:\DynamoRIO\bin64 -i corpus -o output \
    -t 5000+ -M master --                              \
    -coverage_module target.dll                        \
    -target_module harness.exe                         \
    -target_method TargetFunction                      \
    -nargs 2                                            \
    -- harness.exe @@
```

**WinAFL harness template:**

```c
// harness.c — WinAFL harness for a file parser
#include <windows.h>
#include <stdio.h>

// Import the target parsing function
typedef int (*ParseFunc)(const char* filename);

// This function is called in a loop by WinAFL
extern "C" __declspec(dllexport)
int TargetFunction(const char* filename) {
    HMODULE hMod = LoadLibraryA("target.dll");
    ParseFunc Parse = (ParseFunc)GetProcAddress(hMod, "ParseFile");
    
    int result = Parse(filename);
    
    // Clean up state for next iteration
    // (Important: WinAFL calls this function in a loop without restarting the process)
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    return TargetFunction(argv[1]);
}
```

**Key WinAFL options:**

| Option | Description |
|--------|-------------|
| `-D <path>` | Path to DynamoRIO |
| `-coverage_module <dll>` | Module to instrument for coverage |
| `-target_module <exe>` | Module containing the target function |
| `-target_method <func>` | Function name to fuzz |
| `-nargs <n>` | Number of arguments to the target function |
| `-t <ms>` | Timeout per execution |
| `-M master` / `-S slave` | Master/slave mode for parallel fuzzing |
| `-x <dict>` | Dictionary file for format-aware mutation |

#### Coverage-Guided Fuzzing for Kernel Drivers

For kernel drivers, direct coverage-guided fuzzing is more complex. Approaches include:

**kAFL (Kernel AFL)**: Uses Intel PT (Processor Trace) for hardware-based code coverage without modifying the target kernel:

```
┌────────────────────────────────────────┐
│            Host (Linux)                │
│  ┌─────────────────────────────────┐   │
│  │  kAFL Fuzzer                     │  │
│  │  - Generates test cases          │  │
│  │  - Monitors Intel PT traces      │  │
│  │  - Coverage-guided mutation      │  │
│  └──────────┬──────────────────────┘   │
│             │ QEMU                      │
│  ┌──────────▼──────────────────────┐   │
│  │  Guest VM (Windows)              │  │
│  │  ┌──────────────────────────┐    │  │
│  │  │  Agent (user-mode)       │    │  │
│  │  │  - Receives test case    │    │  │
│  │  │  - DeviceIoControl()     │    │  │
│  │  │  - Reports crash/clean   │    │  │
│  │  └──────────────────────────┘    │  │
│  │  ┌──────────────────────────┐    │  │
│  │  │  Target Driver (.sys)    │    │  │
│  │  │  (Traced by Intel PT)    │    │  │
│  │  └──────────────────────────┘    │  │
│  └─────────────────────────────────┘   │
└────────────────────────────────────────┘
```

**IOCTL fuzzing with state awareness** — some IOCTLs must be called in sequence (e.g., `IOCTL_INIT` before `IOCTL_PROCESS`). Structure-aware fuzzing respects these dependencies:

```python
# Conceptual state-aware IOCTL fuzzer (Python with ctypes)
import ctypes
from ctypes import wintypes
import struct
import random

kernel32 = ctypes.windll.kernel32

# State machine for IOCTL sequences
IOCTL_INIT    = 0x222000
IOCTL_CONFIG  = 0x222004
IOCTL_PROCESS = 0x222008  # Bug is here, but only reachable after INIT + CONFIG
IOCTL_CLEANUP = 0x22200C

def fuzz_session(device_handle):
    """One fuzzing session with proper IOCTL sequencing."""
    # Phase 1: Initialize (required)
    init_data = struct.pack("<II", random.randint(0, 0xFFFF), 0x100)
    DeviceIoControl(device_handle, IOCTL_INIT, init_data, 0x100)
    
    # Phase 2: Configure (required)
    config_data = bytes(random.getrandbits(8) for _ in range(random.randint(8, 256)))
    DeviceIoControl(device_handle, IOCTL_CONFIG, config_data, 0x100)
    
    # Phase 3: Fuzz the processing IOCTL
    for _ in range(100):
        fuzz_len = random.choice([0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1000, 0xFFFF])
        fuzz_data = bytes(random.getrandbits(8) for _ in range(min(fuzz_len, 0x10000)))
        DeviceIoControl(device_handle, IOCTL_PROCESS, fuzz_data, fuzz_len)
    
    # Phase 4: Cleanup
    DeviceIoControl(device_handle, IOCTL_CLEANUP, b"", 0)
```

### 3.4 Code Auditing Patterns for C/C++ Vulnerabilities

Manual code auditing is the gold standard for finding complex, multi-step vulnerabilities that fuzzers cannot easily reach. The following patterns systematize the audit process.

#### Buffer Overflow Checklist

```
□ Stack buffers:
  □ Fixed-size local arrays receiving variable-length input
  □ snprintf/swprintf with incorrect buffer size calculation
  □ Off-by-one in loop bounds writing to stack buffer

□ Heap/Pool buffers:
  □ Allocation size doesn't match copy size
  □ Size calculation can integer-overflow before allocation
  □ Realloc patterns where new size < old data length

□ String operations:
  □ strcpy/strcat on user-supplied strings
  □ wcscat/wcsncpy with wrong count (element vs byte confusion)
  □ UNICODE_STRING.Length vs .MaximumLength mismatch

□ Structure copies:
  □ Variable-length structures with length field in header
  □ Array member at end of struct (flexible array member)
  □ sizeof() used on pointer instead of pointed-to object
```

#### Integer Vulnerability Checklist

```
□ Integer overflow in size calculations:
  □ count * element_size (can wrap to small value)
  □ header_size + data_size (can wrap)
  □ Signed/unsigned comparison leading to large unsigned value

□ Integer truncation:
  □ 64-bit value assigned to 32-bit variable (size_t → DWORD)
  □ 32-bit value assigned to 16-bit (short, USHORT)
  □ Return value of strlen (size_t) used as int

□ Signedness errors:
  □ Negative value passed as unsigned size parameter
  □ Signed comparison allows negative length to bypass check:
    if (length > MAX_SIZE) return ERROR;  // length is signed, -1 passes check
    memcpy(buf, src, length);             // length cast to size_t → huge copy

□ Arithmetic errors:
  □ Subtraction underflow: if (end - start > max)  // underflow if end < start
  □ Division/modulo with user-controlled values (potential divide-by-zero)
```

#### Use-After-Free Checklist

```
□ Object lifecycle:
  □ Object freed in one code path, pointer not zeroed
  □ Object freed in error handler, but caller continues to use it
  □ Reference counting errors: premature decrement leads to early free
  □ Race condition: object freed on one thread, used on another

□ Common UAF patterns in drivers:
  □ IRP completion race: IRP freed by I/O manager while driver still references it
  □ Work item callback races: work item references freed context
  □ Timer callback races: timer fires after object is freed
  □ Cancel routine races: cancel races with normal completion

□ Detection in disassembly:
  □ ExFreePoolWithTag followed by continued use of same register
  □ Global/structure pointer not cleared after free
  □ Lock not held around free + zero sequence
```

#### Type Confusion Checklist

```
□ Object type validation:
  □ Objects retrieved by handle/ID without type check
  □ Pointer cast without verifying actual type
  □ Union fields accessed with wrong interpretation
  □ Polymorphic objects (vtables) with corrupted type indicator

□ COM/OLE-specific:
  □ QueryInterface returning wrong interface
  □ IUnknown cast without proper QI
  □ Variant type (VARTYPE) mismatch

□ Kernel-specific:
  □ ObReferenceObjectByHandle with wrong ObjectType
  □ Object header type not validated after lookup
  □ Generic callback contexts cast to specific types without validation
```

### 3.5 Identifying Memory Corruption Bugs Through Static Patterns

Beyond individual function-level patterns, certain structural code patterns indicate higher vulnerability risk.

#### Double-Fetch (TOCTOU) Vulnerabilities

A double-fetch occurs when kernel code reads user-mode memory multiple times. Between reads, a concurrent user-mode thread can modify the data:

```c
// VULNERABLE: double-fetch pattern
ULONG Size = ProbeForReadUlong(UserBuffer);        // First fetch: read size
if (Size > MAX_ALLOWED_SIZE) return STATUS_INVALID_PARAMETER;

PVOID KernelBuf = ExAllocatePoolWithTag(PagedPool, Size, 'Tag1');
RtlCopyMemory(KernelBuf, UserBuffer + 4, Size);    // Second fetch: copy data

// RACE CONDITION: Between the check and the copy, another thread could:
// 1. Change Size in user memory to a larger value
// 2. The copy uses the validated Size (still small), so no overflow HERE
// BUT if the code later re-reads Size from UserBuffer for another operation:
ULONG Size2 = *(ULONG*)UserBuffer;                  // Third fetch: re-read size (now huge!)
ProcessData(KernelBuf, Size2);                       // BUG: Size2 != original validated Size
```

**Detection pattern in disassembly**: Look for multiple reads from the same user-mode address (especially `METHOD_NEITHER` buffers) where the first read validates and the second read uses.

#### Information Disclosure Patterns

```c
// Uninitialized stack buffer leaked to user mode:
UCHAR ResponseBuffer[256];
// BUG: ResponseBuffer not zeroed — contains stack residue (previous kernel frames)
ResponseBuffer[0] = STATUS_SUCCESS;
ResponseBuffer[1] = result_code;
// Only first 2 bytes initialized, but all 256 returned to user:
Irp->IoStatus.Information = sizeof(ResponseBuffer);  // Returns 256 bytes
RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, ResponseBuffer, sizeof(ResponseBuffer));

// Fix: Zero the buffer first
RtlZeroMemory(ResponseBuffer, sizeof(ResponseBuffer));
```

```c
// Uninitialized pool allocation leaked to user mode:
PVOID OutputBuffer = ExAllocatePoolWithTag(PagedPool, OutputSize, 'Leak');
// BUG: Pool memory contains data from previous allocations
OutputBuffer->StatusField = STATUS_SUCCESS;
// Only StatusField written; rest of buffer contains stale pool data
RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, OutputBuffer, OutputSize);

// Fix: Use ExAllocatePoolZero or zero after allocation
```

#### Race Condition Patterns in Drivers

```c
// Classic TOCTOU in file path handling:
if (AccessCheck(FilePath)) {        // Check access to "/safe/path"
    // RACE: Between check and use, attacker replaces symlink
    OpenFile(FilePath);             // Opens "/sensitive/path" (symlink target changed)
}

// Kernel object race (reference counting):
void WorkItemCallback(PVOID Context) {
    PMyContext ctx = (PMyContext)Context;
    // BUG: Object may have been freed by another thread
    // No reference taken before queueing work item
    UseObject(ctx->Object);         // Potential UAF
}
```

### 3.6 Taint Analysis Concepts and Tools

Taint analysis tracks the flow of untrusted (user-controlled) data through a program to determine if it can reach sensitive operations (sinks) without proper validation (sanitization).

#### Taint Analysis Concepts

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│   SOURCES    │ ───→ │  PROPAGATION │ ───→ │    SINKS     │
│ (User Input) │      │   (Data Flow)│      │  (Dangerous  │
│              │      │              │      │   Operations) │
│ • SystemBuf  │      │ • Assignment │      │ • memcpy len │
│ • UserBuffer │      │ • Arithmetic │      │ • Pool alloc │
│ • InputLen   │      │ • Array idx  │      │ • Func ptrs  │
│ • Type3Input │      │ • Struct fld │      │ • Loop bounds│
│ • Network    │      │ • Return val │      │ • Permissions│
└──────────────┘      └──────────────┘      └──────────────┘
```

**Sources** (where tainted data enters):
- IOCTL input buffers (SystemBuffer, Type3InputBuffer)
- Input buffer lengths (InputBufferLength, OutputBufferLength)
- Network packet data
- File content
- Registry values
- User-mode pointers and values

**Sinks** (where tainted data is dangerous):
- Length argument to memory copy functions
- Size argument to allocation functions
- Array index or pointer arithmetic operand
- Function pointer or indirect call target
- Comparison operand in security checks
- Loop bound
- Argument to privilege/access check functions

**Sanitizers** (operations that make tainted data safe):
- Range checks: `if (len > MAX) return ERROR;`
- Mask/truncation to safe range: `index &= 0xFF;`
- Validation functions: `ProbeForRead`, `ProbeForWrite`

#### Tools for Taint Analysis

**Manual taint tracking** (most common for OSEE):
- In IDA/Ghidra decompiler, trace a user-controlled variable through all code paths from source to sink.
- Mark each variable as "tainted" or "clean" based on whether user data can influence it.
- Look for paths where tainted data reaches sinks without intervening sanitization.

**DynamoRIO with Dr. Memory / Dr. Taint**:
```bash
# Run with taint tracking (user-mode only)
drrun.exe -t drtaint -- target.exe input_file
```

**Intel Pin with taint tracking pintool**:
```bash
# Custom Pin tool for taint tracking
pin.exe -t TaintTracker.dll -taint_source file -source_file input.dat -- target.exe input.dat
```

**Binary Ninja with taint plugin**: Binary Ninja's MLIL (Medium Level IL) provides data flow analysis that can approximate taint tracking through its `SSA` form.

**Practical taint analysis in WinDbg** — trace a specific input value through execution:

```
# 1. Set breakpoint at IOCTL entry, note input buffer address and contents
bp VulnDriver!DispatchIoctl
g
# Hit breakpoint
# rcx = DeviceObject, rdx = Irp
dt nt!_IRP @rdx
# Note SystemBuffer address
dq poi(@rdx+0x18) L4    # SystemBuffer contents

# 2. Set hardware watchpoints on key input values
ba r4 <SystemBuffer+offset>   # Watch when the driver reads the input

# 3. Each time the watchpoint fires, note:
#    - Which instruction reads the value
#    - What register it goes into  
#    - How it's used (size? index? pointer?)
# Continue tracing until the value reaches a sink (memcpy, array access, etc.)
```

---

## 4. Patch Diffing

Patch diffing (binary differential analysis) is the process of comparing two versions of a binary — typically before and after a security patch — to identify the specific code changes that fix a vulnerability. This is a critical skill for 1-day exploit development and understanding new vulnerability classes.

### 4.1 Using BinDiff and Diaphora for Binary Comparison

#### BinDiff

BinDiff (originally by Zynamics, now Google) is the industry-standard tool for binary comparison. It integrates with IDA Pro and Ghidra.

**Setup:**
1. Install BinDiff (available from Google's security tools page).
2. Install the IDA Pro or Ghidra plugin.
3. Export `.BinExport` files from each binary version.

**Workflow:**

```
Step 1: Obtain the two binary versions
────────────────────────────────────────
# Example: ntoskrnl.exe from before and after a Patch Tuesday
# Use WSUS, Windows Update Catalog, or symbol server timestamps
# Tools like "winbindex" can help locate specific builds

Step 2: Generate IDB/BinExport files
────────────────────────────────────────
# In IDA:
# a. Load pre-patch binary → auto-analysis → File -> BinExport -> Export as BinExport2
# b. Load post-patch binary → auto-analysis → File -> BinExport -> Export as BinExport2

Step 3: Run BinDiff comparison
────────────────────────────────────────
# In IDA: File -> BinDiff -> Diff Database
# Or command-line:
bindiff.exe pre_patch.BinExport post_patch.BinExport -o diff_result

Step 4: Analyze results
────────────────────────────────────────
# Focus on functions with similarity < 1.0 (modified)
# Sort by "Similarity" column — functions closest to 1.0 are minor changes
# Functions with similarity 0.7-0.95 are the most interesting (significant changes)
```

**BinDiff match quality indicators:**

| Similarity | Interpretation |
|-----------|----------------|
| 1.00 | Identical function |
| 0.95-0.99 | Minor changes (cosmetic, recompilation artifacts) |
| 0.70-0.95 | **Significant changes — likely security fix** |
| 0.30-0.70 | Major restructuring or refactoring |
| < 0.30 | Almost completely different |
| Unmatched | New function or removed function |

**Reading BinDiff results in IDA:**
- Green blocks: Matching instructions
- Yellow blocks: Changed instructions
- Red blocks: Removed instructions (in primary)
- Blue blocks: Added instructions (in secondary)

#### Diaphora

Diaphora is a free, open-source alternative to BinDiff that runs as an IDA Python plugin. It provides more granular analysis and is highly scriptable.

**Setup:**
1. Download from [github.com/joxeankoret/diaphora](https://github.com/joxeankoret/diaphora).
2. Place `diaphora.py` in IDA's plugins directory.

**Workflow:**

```python
# Step 1: Export pre-patch binary
# In IDA with pre-patch binary loaded:
# File -> Script File -> diaphora.py
# Click "Export" → saves a .sqlite database

# Step 2: Export post-patch binary
# Open post-patch binary in IDA
# Run diaphora.py again
# Click "Diff" → select the pre-patch .sqlite file

# Step 3: Analyze results
# Diaphora shows:
# - Best matches (high confidence identical)
# - Partial matches (modified functions) ← Focus here
# - Unmatched functions (added/removed)
```

**Diaphora advantages over BinDiff:**
- Decompiler-level diffing (compares Hex-Rays pseudocode, not just control flow graphs)
- More match heuristics (constants, string references, call sequences)
- Fully scriptable (Python)
- Free and open source

**Example Diaphora pseudocode diff:**

```c
// Pre-patch (vulnerable):
void ProcessInput(PVOID Buffer, ULONG Length) {
    UCHAR LocalBuf[256];
    RtlCopyMemory(LocalBuf, Buffer, Length);  // ← No bounds check
    ParseData(LocalBuf);
}

// Post-patch (fixed):
void ProcessInput(PVOID Buffer, ULONG Length) {
    UCHAR LocalBuf[256];
    if (Length > sizeof(LocalBuf)) {           // ← ADDED: bounds check
        return;                                // ← ADDED: early return
    }
    RtlCopyMemory(LocalBuf, Buffer, Length);
    ParseData(LocalBuf);
}
```

### 4.2 Analyzing Microsoft Patch Tuesday Updates

Microsoft releases security patches on the second Tuesday of each month. Analyzing these patches reveals fixed vulnerabilities that can be weaponized for 1-day exploits (on unpatched systems) or studied for technique development.

#### Patch Tuesday Analysis Workflow

```
1. Identify Relevant Patches
───────────────────────────
   • Review Microsoft Security Response Center (MSRC) advisories
   • Filter by component (kernel, Win32k, drivers, browsers)
   • Focus on:
     - Remote Code Execution (RCE)
     - Elevation of Privilege (EoP) in kernel/drivers
     - Bugs with high CVSS scores
     - Bugs marked "Exploitation More Likely"

2. Obtain Pre-Patch and Post-Patch Binaries
──────────────────────────────────────────────
   • Windows Update Catalog (catalog.update.microsoft.com)
     - Download the specific KB update
     - Extract using: expand -f:* <msu_file> <output_dir>
     - Further extract CAB: expand -f:* <cab_file> <output_dir>
   • Use Winbindex (winbindex.m417z.com) to find specific file versions
   • Historical versions from symbol server timestamps
   • Or snapshot VMs before/after patching

3. Extract and Prepare Binaries
────────────────────────────────
   # Extract MSU/CAB:
   mkdir extracted && expand -f:* Windows10.0-KB5012345-x64.msu extracted\
   # Find the target binary:
   dir /s /b extracted\ntoskrnl.exe
   dir /s /b extracted\win32kfull.sys

4. Run Binary Diff
───────────────────
   # Load both versions in IDA
   # Export BinExport files
   # Run BinDiff or Diaphora comparison

5. Analyze Changed Functions
─────────────────────────────
   # For each modified function:
   # a. What changed? (Added check, modified condition, new function call)
   # b. What was the vulnerability? (Infer from the fix)
   # c. What is the trigger? (How does user input reach the vulnerable code)
   # d. Is it exploitable? (What primitive does it provide)
```

#### Common Patch Patterns

| Patch Pattern | Likely Vulnerability |
|--------------|---------------------|
| Added bounds check before `memcpy`/`RtlCopyMemory` | Buffer overflow |
| Added `ProbeForRead`/`ProbeForWrite` calls | Missing user-buffer validation |
| Added integer overflow check (`if (a + b < a)`) | Integer overflow |
| Added `ExGetPreviousMode()` check | Missing caller-mode validation |
| Added `try/except` block around memory access | Missing exception handler |
| Pointer set to `NULL` after `ExFreePoolWithTag` | Use-after-free |
| Added reference counting (`ObfReferenceObject`) | UAF / race condition |
| Added lock acquisition around operation | Race condition / TOCTOU |
| Changed `ExAllocatePool` to `ExAllocatePoolZero` | Information disclosure (uninitialized memory) |
| Added type validation before cast | Type confusion |
| Changed `METHOD_NEITHER` to `METHOD_BUFFERED` | User-pointer validation issue |

### 4.3 Methodology for 1-Day Exploit Development from Patches

Once a vulnerability is identified through patch diffing, the process of developing a working exploit follows a systematic methodology.

#### Step-by-Step 1-Day Development

```
Phase 1: Understand the Vulnerability (from the diff)
──────────────────────────────────────────────────────
□ Identify the vulnerable function and its callers
□ Determine the input that triggers the bug
□ Understand the primitive (what does the bug give you?)
  - Overflow: How many bytes? On stack or pool? What's adjacent?
  - UAF: What object? How large? What operations on the freed memory?
  - Integer issue: What calculation? What's the resulting primitive?
  - Info leak: What data is disclosed? Kernel addresses? Pool content?
□ Map the path from user-mode input to the vulnerable code

Phase 2: Reproduce the Vulnerability
──────────────────────────────────────
□ Install the pre-patch version of the target component
□ Write a PoC that triggers the crash
□ Verify the crash in WinDbg:
  - Does !analyze -v point to the expected function?
  - Is the crash type consistent with the vulnerability class?
  - Can you control the relevant parameters (overflow size, freed object)?
□ Iterate on the PoC until the crash is reliable

Phase 3: Develop Exploitation Primitive
────────────────────────────────────────
□ Stack overflow:
  - Control return address → ROP chain
  - Bypass stack cookies (if present) via SEH or information leak
□ Pool overflow:
  - Identify adjacent pool allocations (pool grooming)
  - Overflow into adjacent object's function pointer or metadata
  - Or overflow pool header to corrupt pool freelist
□ UAF:
  - Determine freed allocation size
  - Spray replacement objects of the same size
  - Trigger the dangling pointer use
□ Info leak:
  - Determine what addresses/data are leaked
  - Use to defeat ASLR/KASLR

Phase 4: Build Full Exploit
────────────────────────────
□ Chain primitives (e.g., info leak + write primitive)
□ Implement payload (token stealing, ACL modification, etc.)
□ Handle mitigations (SMEP, SMAP, kCFG, VBS)
□ Test on target OS version(s)
□ Ensure reliability (clean state restoration, no BSOD after exploit)

Phase 5: Verify and Document
─────────────────────────────
□ Test on fresh VM with exact target patch level
□ Verify privilege escalation succeeds
□ Document exploitation requirements and limitations
□ Note which mitigations were bypassed and how
```

#### Practical Example: Analyzing a Pool Overflow Fix

```c
// Hypothetical CVE-2024-XXXXX — Pool overflow in VulnDriver.sys

// PRE-PATCH (vulnerable):
NTSTATUS HandleIoctl(PIRP Irp, PIO_STACK_LOCATION IoSl) {
    ULONG InputLength = IoSl->Parameters.DeviceIoControl.InputBufferLength;
    PVOID InputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PUSER_HEADER Header = (PUSER_HEADER)InputBuffer;
    
    // Allocation based on header field
    ULONG AllocSize = Header->DataSize + sizeof(INTERNAL_HEADER);
    // BUG: Header->DataSize is user-controlled, addition can overflow
    // If Header->DataSize = 0xFFFFFFE0, AllocSize = 0xFFFFFFE0 + 0x20 = 0x00000000
    
    PVOID PoolBuf = ExAllocatePoolWithTag(NonPagedPoolNx, AllocSize, 'VulT');
    // Allocates 0 bytes (or very small allocation)
    
    RtlCopyMemory(PoolBuf + sizeof(INTERNAL_HEADER), 
                   InputBuffer + sizeof(USER_HEADER),
                   Header->DataSize);
    // Copies 0xFFFFFFE0 bytes → massive pool overflow
}

// POST-PATCH (fixed):
NTSTATUS HandleIoctl(PIRP Irp, PIO_STACK_LOCATION IoSl) {
    ULONG InputLength = IoSl->Parameters.DeviceIoControl.InputBufferLength;
    PVOID InputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PUSER_HEADER Header = (PUSER_HEADER)InputBuffer;
    
    // FIX 1: Validate InputBufferLength >= sizeof(USER_HEADER) + Header->DataSize
    if (InputLength < sizeof(USER_HEADER) || 
        Header->DataSize > InputLength - sizeof(USER_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // FIX 2: Check for integer overflow in size calculation
    ULONG AllocSize;
    if (!NT_SUCCESS(RtlULongAdd(Header->DataSize, sizeof(INTERNAL_HEADER), &AllocSize))) {
        return STATUS_INTEGER_OVERFLOW;
    }
    
    PVOID PoolBuf = ExAllocatePoolWithTag(NonPagedPoolNx, AllocSize, 'VulT');
    // ...
}
```

The diff reveals:
1. Missing input length validation → overflow trigger
2. Integer overflow in size calculation → small allocation + large copy
3. The fix uses `RtlULongAdd` for safe arithmetic — classic Windows pattern for integer overflow fixes

### 4.4 Case Studies of Notable Patch Diff Discoveries

#### Case Study 1: CVE-2021-1732 — Win32k EoP (Type Confusion)

**Discovery method**: Patch diffing of `win32kfull.sys` after the February 2021 Patch Tuesday.

**Diff findings**:
- A type-check condition was added in `xxxClientAllocWindowClassExtraBytes`.
- The fix validated that a window's extra bytes flag hadn't been unexpectedly modified.
- The vulnerability was a type confusion: by manipulating window class extra bytes and using a crafted callback, an attacker could confuse the kernel into treating a user-controlled offset as a kernel pointer.

**Exploitation primitive**: Arbitrary kernel read/write via controlled offset in `tagWND` structure.

**Key lesson**: Win32k callback mechanisms are a rich vulnerability class. The user-mode callback allows modifying kernel state between operations — a design pattern inherently prone to TOCTOU and type confusion bugs.

#### Case Study 2: CVE-2020-0986 — splwow64 Sandbox Escape

**Discovery method**: Identified through analysis of a patched LPC (Local Procedure Call) handler in `splwow64.exe`.

**Diff findings**:
- Added validation on an LPC message type that previously allowed arbitrary `memcpy` operations.
- The pre-patch code accepted user-controlled source, destination, and length parameters for a `memcpy` call without proper validation.

**Exploitation primitive**: Full arbitrary read/write within `splwow64.exe` process context, reachable from a sandboxed process.

**Key lesson**: LPC/ALPC message handlers are high-value attack surfaces. Any service that processes messages from lower-privilege callers must validate all message parameters — a pattern often overlooked in older Windows services.

#### Case Study 3: CVE-2021-21551 — Dell dbutil_2_3.sys EoP

**Discovery method**: Direct audit of a third-party kernel driver (not a patch diff, but discovered through static analysis patterns described in this document).

**Findings**:
- The driver exposed IOCTL handlers accessible to any user.
- Several IOCTLs provided direct physical memory read/write via `MmMapIoSpace`.
- No access control — any user, including low-integrity sandboxed processes, could achieve full kernel read/write.

**Exploitation**:
```c
// Simplified PoC concept:
// 1. Open device handle (no privileges needed)
HANDLE hDev = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE, ...);

// 2. Read arbitrary physical memory
struct {
    ULONGLONG PhysAddr;
    ULONG Size;
} ReadReq = { target_phys_addr, 8 };
DeviceIoControl(hDev, IOCTL_READ_PHYS, &ReadReq, sizeof(ReadReq), &Result, ...);

// 3. Write arbitrary physical memory
struct {
    ULONGLONG PhysAddr;
    ULONGLONG Value;
} WriteReq = { target_phys_addr, malicious_value };
DeviceIoControl(hDev, IOCTL_WRITE_PHYS, &WriteReq, sizeof(WriteReq), NULL, ...);

// 4. Translate virtual → physical, modify kernel structures, escalate
```

**Key lesson**: Third-party kernel drivers are frequently the weakest link. Drivers from hardware vendors, antivirus products, and system utilities often lack security review. IOCTL handlers that expose physical memory access or other powerful primitives with no access control represent critical vulnerabilities. The "Bring Your Own Vulnerable Driver" (BYOVD) technique exploits this by loading known-vulnerable signed drivers.

#### Case Study 4: CVE-2023-28252 — CLFS.sys EoP

**Discovery method**: Patch diffing of `clfs.sys` (Common Log File System) across multiple Patch Tuesday cycles, combined with fuzzing of CLFS log file parsing.

**Diff findings**:
- Multiple bounds checks added to base log file (BLF) parsing routines.
- Metadata block validation was tightened — the driver previously trusted certain offset and length fields within BLF files without adequate validation.

**Vulnerability class**: Out-of-bounds write when processing a crafted CLFS log file. The attacker creates a malicious BLF file, and when the kernel parses it (via CLFS APIs), corrupt metadata causes an out-of-bounds write in kernel pool memory.

**Key lesson**: CLFS has been a persistent source of kernel vulnerabilities because:
1. It parses complex file formats in kernel mode.
2. Log files can be crafted and placed by unprivileged users.
3. The parsing code was written without defensive assumptions about file integrity.
4. The attack surface is reachable without any special privileges.

This pattern — kernel-mode parsing of user-influenced file formats — is a consistently fertile area for vulnerability discovery.

---

## Appendix A: Quick Reference — WinDbg Command Cheat Sheet

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WinDbg Quick Reference for OSEE                      │
├─────────────────────────────────────────────────────────────────────────┤
│ CRASH ANALYSIS                                                          │
│   !analyze -v             Full crash analysis                           │
│   .bugcheck               Display bugcheck code and parameters          │
│   !error <ntstatus>       Decode NTSTATUS error code                    │
│                                                                         │
│ MEMORY DISPLAY                                                          │
│   db/dw/dd/dq <addr>      Display bytes/words/dwords/qwords            │
│   dps <addr> L<n>         Display pointers with symbols                │
│   da/du <addr>            Display ASCII/Unicode string                  │
│   dt <type> <addr>        Display typed structure                       │
│   dt -r <type> <addr>     Display structure recursively                 │
│                                                                         │
│ BREAKPOINTS                                                             │
│   bp/bu <addr>            Software breakpoint (immediate/deferred)      │
│   ba <r|w|e> <size> <addr>  Hardware breakpoint                        │
│   bl / bc <n> / bd / be   List / clear / disable / enable              │
│   bp <addr> "<cmds>"      Breakpoint with commands                     │
│                                                                         │
│ EXECUTION                                                               │
│   g                       Continue                                      │
│   p / t                   Step over / step into                         │
│   gu / pt                 Go up (return) / step to return              │
│   .restart                Restart target                                │
│                                                                         │
│ MODULES & SYMBOLS                                                       │
│   lm                      List modules                                  │
│   x <module>!<pattern>    List matching symbols                         │
│   ln <addr>               Nearest symbol                               │
│   .reload /f              Force reload symbols                          │
│                                                                         │
│ POOL & HEAP                                                             │
│   !pool <addr>            Pool allocation info                          │
│   !poolfind <tag>         Find pool allocations by tag                  │
│   !heap -s                Heap summary (user-mode)                      │
│   !heap -p -a <addr>      Page heap info                               │
│                                                                         │
│ PROCESS & THREAD                                                        │
│   !process 0 0            List all processes                            │
│   !thread <addr>          Thread info                                   │
│   .process /i <addr>      Switch process context                       │
│                                                                         │
│ KERNEL OBJECTS                                                          │
│   !drvobj <name> 2        Driver dispatch table                        │
│   !devobj <addr>          Device object info                           │
│   !irp <addr>             IRP info                                     │
│   !object <addr>          Object header                                │
│   !token -n               Current token                                │
│   !ioctldecode <code>     Decode IOCTL code                            │
│                                                                         │
│ SEARCH                                                                  │
│   s -b <start> L<len> <bytes>   Search bytes                          │
│   s -a/-u <start> L<len> "str"  Search ASCII/Unicode string            │
│                                                                         │
│ LOGGING                                                                 │
│   .logopen <file>         Start logging to file                        │
│   .logclose               Stop logging                                 │
│   .writemem <file> <addr> L<len>  Write memory to file                 │
└─────────────────────────────────────────────────────────────────────────┘
```

## Appendix B: Quick Reference — Vulnerability Pattern Recognition

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Vulnerability Pattern Recognition Cheat Sheet              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  STACK OVERFLOW                                                         │
│  ✦ sub rsp, <fixed_size> ... memcpy(stack_buf, input, user_len)       │
│  ✦ No comparison of user_len against fixed_size before copy            │
│                                                                         │
│  POOL/HEAP OVERFLOW                                                     │
│  ✦ ExAllocatePool(size_A) ... RtlCopyMemory(pool, input, size_B)     │
│  ✦ size_B > size_A is possible with user-controlled size_B            │
│                                                                         │
│  INTEGER OVERFLOW                                                       │
│  ✦ alloc_size = count * elem_size (no overflow check on multiply)     │
│  ✦ alloc_size = hdr_size + data_size (no overflow check on add)       │
│  ✦ 64-bit value truncated to 32-bit for allocation                    │
│                                                                         │
│  USE-AFTER-FREE                                                         │
│  ✦ ExFreePool(ptr); /* ptr not set to NULL */                         │
│  ✦ Later: if (ptr) { ptr->callback(); }  /* dangling */              │
│  ✦ Work item / timer callback references freed context                 │
│                                                                         │
│  TYPE CONFUSION                                                         │
│  ✦ obj = LookupById(user_id); ((TypeA*)obj)->method();               │
│  ✦ No validation that obj is actually TypeA                           │
│                                                                         │
│  DOUBLE FETCH (TOCTOU)                                                  │
│  ✦ size = *(user_ptr); validate(size); copy(buf, user_ptr, size);    │
│  ✦ Second read of user_ptr between check and use                     │
│                                                                         │
│  INFO DISCLOSURE                                                        │
│  ✦ Stack buffer not zeroed before partial initialization + copy out   │
│  ✦ Pool alloc without zero → stale data returned to user mode        │
│                                                                         │
│  MISSING PROBE                                                          │
│  ✦ METHOD_NEITHER without ProbeForRead/Write on Type3InputBuffer     │
│  ✦ Missing __try/__except around user-mode pointer dereference        │
│  ✦ Missing ExGetPreviousMode() check before trusting caller's ptrs   │
│                                                                         │
│  RACE CONDITION                                                         │
│  ✦ Check-then-use pattern without holding a lock                      │
│  ✦ Reference count not taken before asynchronous operation            │
│  ✦ IRP completion racing with cancel routine                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Appendix C: Recommended Tools Summary

| Tool | Category | License | Primary Use |
|------|----------|---------|-------------|
| IDA Pro + Hex-Rays | Static analysis | Commercial | Disassembly, decompilation, scripting |
| Ghidra | Static analysis | Free (NSA) | Disassembly, decompilation, diffing |
| WinDbg / WinDbg Preview | Dynamic analysis | Free (Microsoft) | Kernel + user-mode debugging |
| x64dbg | Dynamic analysis | Free (OSS) | User-mode debugging |
| BinDiff | Patch diffing | Free (Google) | Binary comparison |
| Diaphora | Patch diffing | Free (OSS) | IDA-based binary comparison |
| WinAFL | Fuzzing | Free (OSS) | Coverage-guided user-mode fuzzing |
| kAFL | Fuzzing | Free (OSS) | Coverage-guided kernel fuzzing |
| ioctlbf | Fuzzing | Free (OSS) | IOCTL brute-force fuzzing |
| DynamoRIO | Dynamic instrumentation | Free (OSS) | Code coverage, taint tracking |
| pefile (Python) | PE analysis | Free (OSS) | PE header parsing and analysis |
| PE-bear | PE analysis | Free (OSS) | Visual PE structure viewer |
| Process Monitor | System monitoring | Free (Microsoft) | File/registry/process activity |
| API Monitor | API tracing | Free | User-mode API call monitoring |
| Driver Verifier | Kernel testing | Built-in (Windows) | Driver bug detection (pool, IRQL) |
| Special Pool (gflags) | Heap debugging | Built-in (Windows) | Heap overflow detection |

---

*This document is part of the OSEE (Offensive Security Exploitation Expert) reference series. The techniques and tools described are intended for authorized security research and certification preparation only.*
