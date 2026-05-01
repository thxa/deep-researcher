# Reverse Engineering — Quick Reference Cheatsheet

## ELF Section Headers Reference

| Section | Type | Description | RE Significance |
|---------|------|-------------|-----------------|
| `.text` | `SHT_PROGBITS` | Executable code | Primary disassembly target |
| `.data` | `SHT_PROGBITS` | Initialized data | Global variables, vtables |
| `.bss` | `SHT_NOBITS` | Uninitialized data | Zero-initialized globals |
| `.rodata` | `SHT_PROGBITS` | Read-only data | Strings, constants, jump tables |
| `.plt` | `SHT_PROGBITS` | Procedure Linkage Table | Lazy binding stubs; GOT overwrite target |
| `.got` | `SHT_PROGBITS` | Global Offset Table | Full RELRO makes this read-only |
| `.got.plt` | `SHT_PROGBITS` | GOT for PLT | Partial RELRO: writable; full RELRO: read-only |
| `.symtab` | `SHT_SYMTAB` | Symbol table | Stripped = removed; present = symbol recovery |
| `.dynsym` | `SHT_DYNSYM` | Dynamic symbol table | Imported/exported functions |
| `.strtab` | `SHT_STRTAB` | String table (symbols) | Symbol names |
| `.dynstr` | `SHT_STRTAB` | String table (dynamic) | Import/export names |
| `.rela.dyn` | `SHT_RELA` | Runtime relocations | ASLR fixup locations |
| `.rela.plt` | `SHT_RELA` | PLT relocations | IAT equivalent |
| `.init_array` | `SHT_INIT_ARRAY` | Constructors | Executes before `main`; malware persistence |
| `.fini_array` | `SHT_FINI_ARRAY` | Destructors | Executes on exit |
| `.eh_frame` | `SHT_PROGBITS` | Exception handling frames | ROP gadget source; function boundary recovery |
| `.eh_frame_hdr` | `SHT_PROGBITS` | EH frame index | Fast lookup for unwinding |
| `.note.*` | `SHT_NOTE` | Vendor/version notes | Build ID, ABI version |

### ELF Program Headers Reference

| Type | Value | Purpose | RE/Exploitation |
|------|-------|---------|-----------------|
| `PT_NULL` | 0 | Unused | N/A |
| `PT_LOAD` | 1 | Loadable segment | Memory mapping; RWX check |
| `PT_DYNAMIC` | 2 | Dynamic linking info | GOT/PLT resolution |
| `PT_INTERP` | 3 | Interpreter path | Dynamic linker (`/lib64/ld-linux-x86-64.so.2`) |
| `PT_NOTE` | 4 | Auxiliary info | Build ID, vendor strings |
| `PT_SHLIB` | 5 | Shared library | Unused/unspecified |
| `PT_PHDR` | 6 | Program header table | Self-reference |
| `PT_GNU_EH_FRAME` | 0x6474E550 | EH frame location | Exception handling |
| `PT_GNU_STACK` | 0x6474E551 | Stack flags | NX bit: PF_X=0 means NX enabled |
| `PT_GNU_RELRO` | 0x6474E552 | Read-only after reloc | RELRO region |

### ELF Header Key Fields

```
Offset  Size  Field           Significance
0x00    16    e_ident          Magic: 7f 45 4c 46; Class (32/64); Endian; OS/ABI
0x10    2     e_type           ET_EXEC(2), ET_DYN(3), ET_CORE(4)
0x12    2     e_machine        EM_X86_64(62), EM_ARM(40), EM_AARCH64(183), EM_MIPS(8)
0x14    4     e_version        EV_CURRENT(1)
0x18    8     e_entry          Entry point virtual address (_start)
0x20    8     e_phoff          Program header table offset
0x28    8     e_shoff          Section header table offset (0 if stripped)
0x30    4     e_flags          Processor-specific flags
0x34    2     e_ehsize         ELF header size (64 for ELF64)
0x36    2     e_phentsize      Program header entry size
0x38    2     e_phnum          Program header entry count
0x3A    2     e_shentsize      Section header entry size
0x3C    2     e_shnum          Section header entry count (0 if >SHN_LORESERVE)
0x3E    2     e_shstrndx       Section header string table index
```

---

## PE Format Header Reference

### DOS Header (IMAGE_DOS_HEADER)

```
Offset  Size  Field              Significance
0x00    2     e_magic            MZ (0x4D5A)
0x02    58    (legacy DOS fields)  Irrelevant for PE analysis
0x3C    4     e_lfanew           Offset to PE signature (NT header)
```

### PE Signature + File Header (IMAGE_FILE_HEADER)

```
Offset (+e_lfanew)  Size  Field              Significance
0x00                 4     Signature          PE\0\0 (0x4550)
0x04                 2     Machine            IMAGE_FILE_MACHINE_AMD64(0x8664)/I386(0x14C)
0x06                 2     NumberOfSections   Section count
0x08                 4     TimeDateStamp      Compile timestamp (Unix epoch)
0x0C                 4     PointerToSymbolTable Debug info offset (COFF)
0x10                 4     NumberOfSymbols     Debug symbol count
0x14                 2     SizeOfOptionalHeader Must be >= 0xF0 for PE32+
0x16                 2     Characteristics    IMAGE_FILE_EXECUTABLE_IMAGE(0x2), DLL(0x2000)
```

### Optional Header Key Fields (IMAGE_OPTIONAL_HEADER64)

```
Offset  Size  Field                        Significance
0x00    2     Magic                        PE32(0x10B), PE32+(0x20B)
0x02    1     MajorLinkerVersion           Linker version (MSVC≈14)
0x10    4     AddressOfEntryPoint          RVA of entry point
0x18    4     ImageBase                    Preferred load address (0x140000000 for 64-bit)
0x20    4     SectionAlignment             Section alignment in memory (0x1000)
0x24    4     FileAlignment                Section alignment in file (0x200)
0x5C    4     SizeOfImage                  Virtual size of image
0x60    4     SizeOfHeaders                Size of headers
0x74    2     MajorSubsystemVersion        Subsystem version
0x84    4     DllCharacteristics          DLL characteristics flags (see below)
0x88    8     SizeOfStackReserve           Stack reserve size
0x90    8     SizeOfHeapReserve            Heap reserve size
0xB0    4     NumberOfRvaAndSizes          Data directory count (16)
0xB8    128   DataDirectory[16]            Data directories (see below)
```

### PE Data Directory Indices

| Index | Name | Description |
|-------|------|-------------|
| 0 | IMAGE_DIRECTORY_ENTRY_EXPORT | Export table |
| 1 | IMAGE_DIRECTORY_ENTRY_IMPORT | Import table |
| 2 | IMAGE_DIRECTORY_ENTRY_RESOURCE | Resources (icons, strings, encrypted payloads) |
| 3 | IMAGE_DIRECTORY_ENTRY_EXCEPTION | Exception handling tables |
| 4 | IMAGE_DIRECTORY_ENTRY_SECURITY | Authenticode digital signature |
| 5 | IMAGE_DIRECTORY_ENTRY_BASERELOC | Base relocation table |
| 6 | IMAGE_DIRECTORY_ENTRY_DEBUG | Debug information (PDB path!) |
| 7 | IMAGE_DIRECTORY_ENTRY_ARCHITECTURE | Architecture-specific |
| 8 | IMAGE_DIRECTORY_ENTRY_GLOBALPTR | Global pointer |
| 9 | IMAGE_DIRECTORY_ENTRY_TLS | Thread Local Storage directory |
| 10 | IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG | Load config (CFG, SafeSEH, SecurityCookie) |
| 11 | IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT | Bound import directory |
| 12 | IMAGE_DIRECTORY_ENTRY_IAT | Import Address Table |
| 13 | IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT | Delay import descriptors |
| 14 | IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR | CLR metadata |
| 15 | (Reserved) | |

### PE DllCharacteristics Flags

| Flag | Value | Mitigation |
|------|-------|-----------|
| `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` | 0x0020 | ASLR with 64-bit address space |
| `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | 0x0040 | ASLR compatible |
| `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` | 0x0080 | Code integrity checks |
| `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | 0x0100 | DEP/NX compatible |
| `IMAGE_DLLCHARACTERISTICS_NO_ISOLATION` | 0x0200 | No SxS isolation |
| `IMAGE_DLLCHARACTERISTICS_NO_SEH` | 0x0400 | No SEH (disables SEHOP) |
| `IMAGE_DLLCHARACTERISTICS_NO_BIND` | 0x0800 | No bind |
| `IMAGE_DLLCHARACTERISTICS_APPCONTAINER` | 0x1000 | AppContainer (UWP) |
| `IMAGE_DLLCHARACTERISTICS_WMD_DRIVER` | 0x2000 | WDM driver |
| `IMAGE_DLLCHARACTERISTICS_GUARD_CF` | 0x4000 | Control Flow Guard (CFG) |
| `IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE` | 0x8000 | Terminal Server aware |

---

## Mach-O Load Command Reference

| Command | Value | Description | RE Use |
|---------|-------|-------------|--------|
| `LC_SEGMENT` | 0x1 | Map 32-bit segment | Section mapping |
| `LC_SYMTAB` | 0x2 | Symbol table | Symbol recovery |
| `LC_DYSYMTAB` | 0xB | Dynamic symbol table | Import/export symbols |
| `LC_LOAD_DYLIB` | 0xC | Load dylib | Dylib injection vector |
| `LC_ID_DYLIB` | 0xD | Dylib identity | Library identification |
| `LC_LOAD_DYLINKER` | 0xE | Dynamic linker | `/usr/lib/dyld` |
| `LC_UUID` | 0x1B | UUID | Binary identification |
| `LC_MAIN` | 0x80000028 | Entry point (offset) | Entry point analysis (replaces LC_UNIXTHREAD) |
| `LC_LOAD_WEAK_DYLIB` | 0x80000018 | Weak dylib load | Optional dependencies |
| `LC_SEGMENT_64` | 0x19 | Map 64-bit segment | Section mapping (modern) |
| `LC_ROUTINES_64` | 0x1A | 64-bit routine addresses | Constructor init |
| `LC_FUNCTION_STARTS` | 0x26 | Function boundary data | Essential when symbols stripped |
| `LC_DATA_IN_CODE` | 0x29 | Data-in-code entries | Jump table identification |
| `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` | 0x22 / 0x80000022 | Dyld bind/rebase info | Chained fixups, symbol binding |
| `LC_CODE_SIGNATURE` | 0x1D | Code signing | Required on iOS; tamper detection |
| `LC_ENCRYPTION_INFO` | 0x21 | FairPlay DRM (32-bit) | App Store encryption |
| `LC_ENCRYPTION_INFO_64` | 0x2C | FairPlay DRM (64-bit) | `cryptoff`/`cryptsize`/`cryptid` |
| `LC_BUILD_VERSION` | 0x32 | Build version info | MinOS, SDK version |

### Mach-O Segment Types

| Segment | Purpose | RE Significance |
|---------|---------|-----------------|
| `__TEXT` | Executable code + readonly data | Main code section; code signing hashes this |
| `__DATA` | Writable data | GOT, lazy symbol pointers, initialized data |
| `__DATA_CONST` | Const data (post-dyld writable) | CFStrings, ObjC metadata |
| `__DATA_DIRTY` | Writable data (dirty pages) | Frequently modified globals |
| `__LINKEDIT` | Linker metadata | Symbol tables, bind/rebase, code signature |
| `__PAGEZERO` | Null page guard | 4GB guard page (64-bit); catch NULL deref |

---

## GDB Essential Commands

### Execution Control

```gdb
# Start/attach
gdb -q ./binary                     # Start GDB
gdb -q -p <pid>                     # Attach to process
gdb -q ./binary core                # Analyze core dump
gdb -q -x script.gdb ./binary       # Run GDB script

# Running
run                                  # Start execution
run arg1 arg2                        # Start with arguments
run < input.txt                      # Redirect stdin
attach <pid>                         # Attach to running process
detach                               # Detach from process
kill                                 # Kill target process

# Stepping
stepi          (si)                  # Step one instruction (into calls)
nexti          (ni)                  # Step one instruction (over calls)
step           (s)                   # Step one source line (into calls)
next           (n)                   # Step one source line (over calls)
finish                               # Run until current function returns
advance *0x401234                   # Run until address
until 42                             # Run until line 42 (skip loops)
```

### Breakpoints & Watchpoints

```gdb
# Breakpoints
break main                           # Symbol breakpoint
break *0x401000                       # Address breakpoint
break *main+0x20                     # Offset breakpoint
break file.c:42                       # Source line breakpoint
break *0x7f... if $rdi==0x41414141   # Conditional breakpoint
tbreak *0x401234                     # Temporary breakpoint (one-shot)
hbreak *0x401234                     # Hardware breakpoint (4 available x86_64)

# Watchpoints (data breakpoints)
watch global_var                     # Write watchpoint
rwatch global_var                    # Read watchpoint
awatch global_var                    # Access watchpoint (read + write)
watch *(int*)0x601234                # Watch memory address

# Management
info breakpoints                     # List all breakpoints
delete 1                             # Delete breakpoint #1
disable 2                            # Disable breakpoint #2
enable 2                             # Enable breakpoint #2
clear *0x401000                      # Clear breakpoint at address
condition 1 $rax == 0                # Add condition to breakpoint #1
commands 1                           # Commands to execute at breakpoint #1
  > printf "rdi=%s\n", $rdi
  > continue
  > end
```

### Memory Examination

```gdb
# Format: x/NFU address
# N = count, F = format, U = unit size

# Formats
x/20i $rip                           # 20 instructions at RIP
x/20wx $rsp                          # 20 words (4-byte) at stack
x/4gx &struct_var                    # 4 giant words (8-byte)
x/s *(char**)0x401234                # Dereference and print string
x/10bx 0x601234                      # 10 bytes (hex)
x/10hd 0x601234                      # 10 halfwords (decimal)

# Unit sizes
# b = byte (1 byte)    h = halfword (2 bytes)
# w = word (4 bytes)    g = giant word (8 bytes)

# Format letters
# x = hex    d = decimal    u = unsigned    o = octal
# t = binary a = address    c = character   s = string
# i = instruction   f = float

# Examine types
ptype struct_name                    # Print type definition
print *(struct_name*)0x601234        # Print struct at address
print /x $rax                        # Print register in hex

# Memory search
find /b 0x600000, 0x601000, 0x41, 0x42  # Search for byte pattern
find /w 0x600000, 0x601000, 0xdeadbeef   # Search for word
```

### Advanced GDB (pwndbg/gef)

```gdb
# pwndbg extensions (recommended)
context                               # Display context (regs, code, stack, disasm)
vmmap                                # Show virtual memory map
checksec                             # Check binary mitigations
piebase                              # Calculate PIE base from leaked address
heap bins                            # Show heap bin state
fastbin                              # Show fastbin entries
tcache                               # Show tcache entries
have                                 # Check if symbols available

# GDB scripting (Python)
py import gdb; gdb.execute("info functions")
py gdb.write(str(gdb.parse_and_eval("$rax")))

# Register manipulation
set $rax = 0x1337                    # Set register value
set {int}$rsp+8 = 42                  # Write to memory at stack
info registers                       # Show all registers
info registers rax rbx rcx           # Show specific registers

# Process information
info proc mappings                   # Show memory map
info sharedlibrary                   # Show loaded libraries
info files                           # Show target files
maintenance info sections            # Show ELF sections

# Reverse debugging (requires recording)
record                               # Start recording execution
run                                  # Execute
reverse-step                         # Step backwards
reverse-continue                     # Continue backwards
record stop                          # Stop recording
```

---

## WinDBG Essential Commands

```
# Connection
.attach  <pid>                       # Attach to process (usermode)
.breakin                             # Break into target (kernel debugging)
.detach                              # Detach from target

# Execution
g                                    # Go (continue)
p                                   # Step over (source)
t                                   # Trace into (source)
p                                   # Step over (source)
gu                                  # Go up (step out)
pc                                  # Step to next call
tc                                  # Trace to next call
bb                                 # Break on branch (ARM)

# Breakpoints
bp <address>                         # Software breakpoint
bp <module>!<symbol>                # Symbol breakpoint
ba w4 <address>                      # Hardware write breakpoint (4 bytes)
ba r4 <address>                      # Hardware read breakpoint
ba e1 <address>                      # Hardware execute breakpoint
bp <address> "condition; .if (condition) {gc}";  # Conditional breakpoint

# Registers & Memory
r                                    # Show all registers
r @rax = 0x1337                      # Set register
r eax                                # Show specific register
dd <address>                         # Display dwords (4-byte)
dq <address>                         # Display qwords (8-byte)
db <address>                         # Display bytes
du <address>                         # Display unicode string
da <address>                         # Display ascii string
dt nt!_EPROCESS <addr>               # Display type (struct)
dt nt!_EPROCESS <addr> -r1           # Recursively display (1 level)
eb <address> <byte>                  # Write byte

# Kernel-specific
!process 0 0                         # List all processes
!process 0 7 <name>                  # Detailed process info
!thread                              # Current thread info
!object <addr>                       # Object info
!poolfind <tag>                      # Find pool allocations
!irp <addr>                          # IRP info
!devobj <addr>                       # Device object info
!drvobj <addr>                       # Driver object info
!handle <addr>                       # Handle table info

# Analysis
!analyze -v                          # Detailed crash analysis
!exploitable                         # Assess crash exploitability
kc                                   # Call stack (compact)
kP                                   # Call stack (with parameters)
!locks                               # Show all lock state (kernel)
!vm                                  # Virtual memory stats

# Extensions
.load winext\secobj                  # Load security extension
.load ext\exts                       # Load standard extensions
.chain                              # List loaded extensions
!process 0 1 explorer.exe            # Find explorer process
```

---

## x64dbg Quick Reference

```
# Navigation
Ctrl+G         _goto address/expression
Ctrl+B          Breakpoints tab
Ctrl+M          Memory map
Ctrl+S          Symbols tab
Ctrl+R          References tab

# Execution
F7             Step into (instruction)
F8             Step over (instruction)
F9             Run
Ctrl+F7         Trace into
Ctrl+F8         Trace over
Shift+F7        Step into (source)
Shift+F8        Step over (source)

# Breakpoints
F2             Toggle breakpoint
F3             Hardware breakpoint (on current instruction)
F4             Run to selection (run until cursor)

# Memory
Ctrl+B          Find pattern in memory
Ctrl+E          Edit memory at address
Ctrl+D          Follow dword in disassembly
Ctrl+L          Follow QWORD in disassembly

# Analysis
Right-click → Analyze module       Run analysis
Right-click → Search for → Command Search all commands
Right-click → Search for → Constant Find constant usage
Right-click → Search for → String  Find string references

# Scylla (dumping)
Plugins → Scylla → Dump            Dump process
Plugins → Scylla → IAT Autosearch   Find IAT
Plugins → Scylla → Get Imports      Rebuild imports
Plugins → Scylla → Fix Dump         Fix dumped executable
```

---

## IDAPython Quick Reference

```python
import idaapi
import idautils
import idc

# === Navigation & Information ===

# Get function at address
func = idaapi.get_func(0x401000)
print(f"Function: {idc.get_func_name(0x401000)}")
print(f"Start: {hex(func.start_ea)}, End: {hex(func.end_ea)}")

# Iterate all functions
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    print(f"{hex(func_ea)}: {name}")

# Iterate segments
for seg in idautils.Segments():
    print(f"Segment: {idc.get_segm_name(seg)}, Start: {hex(seg)}, End: {hex(idc.get_segm_end(seg))}")

# === Cross-References ===

# Find all references to address
for xref in idautils.XrefsTo(0x401000, 0):
    print(f"Xref from {hex(xref.frm)} type={xref.type}")

# Find all references from address
for xref in idautils.XrefsFrom(0x401000, 0):
    print(f"Xref to {hex(xref.to)} type={xref.type}")

# === Names & Comments ===

# Rename address
idc.set_name(0x401000, "decrypt_config", idc.SN_CHECK)

# Set comment (0=repeatable, 1=non-repeatable)
idc.set_cmt(0x401005, "XOR key = 0x42", 0)

# Set function comment
idc.set_func_cmt(0x401000, "Decrypts configuration blob", 0)

# === Data Types ===

# Define type at address
idc.define_local_type(0, "struct Config { int magic; char *key; };")

# Get operand type
print(idc.get_operand_type(0x401000, 0))  # 0=none, 1=reg, 2=mem, 3=imm

# Define array
idc.create_array(0x601000, 10, 4)  # Array of 10 dwords

# === Byte Patterns ===

# Search for byte pattern
pattern = "48 89 E5 48 83 EC"  # push rbp; mov rbp, rsp; sub rsp, ...
ea = idc.find_binary(0, idc.SEARCH_DOWN, pattern)

# Search all occurrences
ea = 0
while True:
    ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN, pattern)
    if ea == idc.BADADDR:
        break
    print(f"Found at {hex(ea)}")

# === Decompiler (Hex-Rays) ===

# Decompile function
try:
    cfunc = idaapi.decompile(0x401000)
    # Get local variables
    for var in cfunc.lvars:
        print(f"Var: {var.name}, Type: {var.type()}")
    # Get pseudocode
    print(str(cfunc))
except idaapi.DecompilationFailure:
    print("Decompilation failed")

# === Exporting ===

# Dump all function names
with open("functions.txt", "w") as f:
    for func_ea in idautils.Functions():
        f.write(f"{hex(func_ea)} {idc.get_func_name(func_ea)}\n")

# Dump all strings
for string in idautils.Strings():
    print(f"{hex(string.ea)}: {string}")
```

---

## Ghidra Scripting Quick Reference

```java
// === Java API (Ghidra Scripts) ===
// @category Examples

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

// Get current program
Program program = getCurrentProgram();

// Iterate functions
FunctionManager fm = program.getFunctionManager();
for (Function func : fm.getFunctions(true)) {
    println(func.getName() + " at " + func.getEntryPoint());
}

// Iterate symbols
SymbolTable st = program.getSymbolTable();
for (Symbol sym : st.getAllSymbols(true)) {
    println(sym.getName() + " = " + sym.getAddress());
}

// Cross-references
ReferenceManager rm = program.getReferenceManager();
for (Reference ref : rm.getReferencesFrom(addr)) {
    println("Ref from " + addr + " to " + ref.getToAddress());
}

// Set comment
setPlateComment(addr, "Important function - XOR decryption");

// Create bookmark
createBookmark(addr, "Analysis", "Decryption routine found");

// Define data type
StructureDataType configStruct = new StructureDataType("Config", 0);
configStruct.add(DWordDataType.dataType, "magic", "Magic number");
configStruct.add(PointerDataType.dataType, "key_ptr", "Key pointer");
program.getDataTypeManager().addDataType(configStruct, DataTypeConflictHandler.DEFAULT_HANDLER);

// === Python (Jython) API ===
# @category Examples

from ghidra.program.model.symbol import SymbolType

# Get decompiler
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)

# Decompile function at cursor
func = getFunctionContaining(currentAddress)
if func:
    results = decomp.decompileFunction(func, 60, monitor)
    if results and results.decompiledFunction:
        print(results.decompiledFunction.getC())

# Search memory for pattern
pattern = [0x48, 0x89, 0xE5]  # push rbp; mov rbp, rsp
addr = findBytes(currentAddress, "48 89 E5")

# Get function body
body = func.getBody()
print(f"Function spans {body.numAddresses} addresses")

# Data type manager
dtm = currentProgram.getDataTypeManager()
for dt in dtm.getAllDataTypes():
    if "config" in dt.getName().lower():
        print(dt.getName(), dt.getLength())
```

---

## radare2 / rizin Command Reference

```
# === Analysis ===
aaa                         # Analyze all (aggressive)
aaaa                        # Analyze all + more (experimental)
s main                      # Seek to symbol
af                          # Analyze function at current address
afl                         # List all functions
axt <addr>                  # Find cross-references to address
axf <addr>                  # Find cross-references from address

# === Disassembly ===
pdf                         # Print disassembly function
pdf @ sym.main              # Disassemble sym.main
pd 30                       # Print 30 instructions
pdr                         # Print disassembly recursively

# === Visual Mode ===
V                           # Enter visual mode
VV                          # Enter graph visual mode
p/P                         # Cycle print modes (hex, disasm, debugger, etc.)
h/j/k/l                    # Move cursor
u/U                         # Undo/redo seek
_                           # HUD (search)

# === Debugging ===
db <addr>                   # Set breakpoint
db -<addr>                  # Remove breakpoint
dc                          # Continue execution
ds                          # Step instruction
dso                        # Step over
dr                          # Display registers
dr rax = 0x1337             # Set register
dm                          # Display memory maps
px 64 @ rsp                 # Hex dump at stack

# === Binary Info ===
ii                          # Import table
iE                          # Export table
iz                          # Strings in data section
izz                         # All strings
iS                          # Sections
ih                          # Headers
ir                          # Relocations

# === Write Mode ===
oo+                         # Reopen in write mode
wa nop                      # Write assembly
wx 90                       # Write hex bytes
w Hello                     # Write string

# === Scripting (r2pipe) ===
# Python
import r2pipe
r2 = r2pipe.open("./binary")
r2.cmd("aaa")
functions = r2.cmd("afl")
r2.quit()
```

---

## Frida Quick Reference

```javascript
// === Core Operations ===

// Attach to running process
var session = frida.attach(pid);
// Spawn and attach
var pid = frida.spawn(["./binary", "--arg"]);
var session = frida.attach(pid);
frida.resume(pid);

// Load script
var script = session.create_script(js_code);
script.message.connect(function(message) {
    console.log(JSON.stringify(message));
});
script.load();

// === Interceptor (Function Hooking) ===

// Hook libc open
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        console.log("open('" + path + "', " + args[1] + ")");
        this.path = path;
    },
    onLeave: function(retval) {
        console.log("  -> fd=" + retval.toInt32() + " for " + this.path);
    }
});

// Replace function implementation
Interceptor.replace(target, new NativeCallback(function(arg0) {
    console.log("Replaced function called with " + arg0);
    return 0; // Custom return value
}, 'int', ['int']));

// === Module Enumeration ===

Process.enumerateModules().forEach(function(m) {
    console.log(m.name + " @ " + m.base + " size=" + m.size);
});

Module.findExportByName("libc.so.6", "malloc");          // Find export
Module.enumerateExports("libc.so.6").forEach(function(e) {
    console.log(e.name + " @ " + e.address);
});

Module.enumerateSymbols("/path/to/binary").forEach(function(s) {
    console.log(s.name + " " + s.type + " @ " + s.address);
});

// === Memory Operations ===

// Read/write memory
var buf = Memory.readUtf8String(ptr("0x401000"));
Memory.writeUtf8String(ptr("0x601000"), "injected");

// Scan for pattern
Memory.scan(ptr("0x400000"), 0x10000, "48 89 E5 48 83 EC", {
    onMatch: function(address, size) {
        console.log("Found at " + address);
    },
    onError: function(reason) {},
    onComplete: function() {}
});

// Allocate and write shellcode
var sc = Memory.alloc(Process.pageSize);
Memory.protect(sc, Process.pageSize, 'rwx');
Memory.writeByteArray(sc, [0x48, 0x31, 0xc0, 0xc3]); // xor rax,rax; ret

// === Stalker (Code Tracing) ===

Stalker.follow(tid, {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            // Log every basic block entry
            if (instruction.address.equals(ptr("0x401000"))) {
                iterator.putCallout(function(context) {
                    console.log("Hit target @ " + context.pc);
                });
            }
            iterator.keep();
        }
    }
});

Stalker.unfollow();  // Stop following

// === NativeFunction (Call from JS) ===

var openPtr = Module.findExportByName(null, "open");
var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
var fd = open(Memory.allocUtf8String("/etc/passwd"), 0);

// === Thread Operations ===

Process.enumerateThreads().forEach(function(t) {
    console.log("Thread " + t.id + " state=" + t.state);
});

// === Communication with Host ===

// Send message to Python
send({type: "hit", address: ptr("0x401000").toString()});

// Receive message from Python
var op = recv("input", function(value) {
    console.log("Received: " + value.payload);
});

// Python side
script.on("message", function(message, data) {
    print(message)
})
```

---

## Common Anti-Debugging Techniques and Bypass

| Technique | Platform | Check Method | Bypass Method |
|-----------|----------|-------------|---------------|
| `IsDebuggerPresent()` | Windows | `PEB.BeingDebugged` | Patch PEB byte; hook return 0 |
| `NtQueryInformationProcess(DebugPort)` | Windows | ProcessDebugPort class | Hook; return STATUS_PORT_NOT_SET |
| `NtQueryInformationProcess(DebugObjectHandle)` | Windows | Debug object handle | Hook; return STATUS_PORT_NOT_SET |
| `CheckRemoteDebuggerPresent()` | Windows | Wraps NtQueryInformationProcess | Same bypass |
| `NtSetInformationProcess(DebugPort)` | Windows | Attempts detach | NOP call; hook return |
| Hardware breakpoint check | Windows | `DR0-DR3` != 0 | `SetThreadContext` to clear DRs |
| `rdtsc` timing | x86/x64 | CPI delta > threshold | Patch comparison; single-step trace |
| `GetTickCount()` timing | Windows | Delta > threshold | Hook; return monotonic values |
| `QueryPerformanceCounter()` timing | Windows | High-precision check | Hook; synchronized return values |
| `NtClose(invalid_handle)` | Windows | STATUS_INVALID_HANDLE only under debugger | SEH; ignore exception |
| `OutputDebugString()` error | Windows | `GetLastError()` changes under debugger | Hook `SetLastError` |
| `INT 2Dh` | Windows | Exception under debugger | Custom exception handler |
| TLS callback | Windows | Executes before `main` | Set BP on TLS callback address |
| `/proc/self/status` TracerPid | Linux | `TracerPid: N` (non-zero if traced) | Close FD; `prctl(PR_SET_DUMPABLE, 0)` |
| `ptrace(PTRACE_TRACEME)` | Linux | Only one tracer allowed | Hook `ptrace`; twice-attach trick |
| `ptrace(PTRACE_TRACEME)` fork trick | Linux | Parent traces child | Use hardware debug instead |
| `SIGTRAP` behavior | Linux | Differs under tracer | Custom signal handler comparison |
| Anti-VM (CPUID) | x86/x64 | Hypervisor CPUID bit | Patch comparison; run on bare metal |
| Anti-VM (timing) | x86/x64 | `cpuid` timing > physical | Timing normalization |

---

## Pack Identification Reference

| Packer | Section Names | Magic/Signature | Entropy | Key Indicators | Unpacking |
|--------|---------------|-----------------|---------|---------------|-----------|
| UPX | `UPX0`, `UPX1`, `UPX2` | `UPX!` at overlay | 7.0-7.8 | `NRV2E` decompressor | `upx -d` |
| UPX (modified) | Modified headers | Deleted or changed | 7.0-7.8 | No UPX section names | Manual: find decompressor, trace to OEP |
| ASPack | `.aspack` | `\xCC\xCC\xCC` padding | 7.3-7.8 | `AsPack` in overlay | ESP trick; find OEP |
| PECompact | `PEC2`, `PECompact2` | — | 7.0-7.7 | `PEC2` section | ESP trick |
| Themida | `.winlik`, custom | — | 7.8-8.0 | VM handler, anti-debug extensive | Hardware BP on OEP; Stalker |
| VMProtect | `.vmp0`, `.vmp1` | `VMP` in overlay | 7.8-8.0 | Mutation, virtualization | Hardware BP on OEP; memory dump |
| Enigma | `.enigma1`, `.enigma2` | — | 7.5-7.9 | Anti-debug, import hashing | Manual trace to OEP |
| MPRESS | `MPRESS1`, `MPRESS2` | `MPRESS` header | 7.5-8.0 | LZMA compression | Find OEP manually |
| PELock | Custom | `PL` signature | 7.0-7.8 | Anti-debug, CRC checks | Dump after OEP |
| PELock32 | `PELock` | — | 7.0-7.8 | Import protection | SEH-based OEP finding |
| Obsidium | Custom | `Obsidium` string | 7.5-8.0 | VM-based, anti-debug | Hardware BP; memory dump |
| Custom/Unknown | — | — | >7.5 | No known signatures | Behavioral analysis; entropy scan |

### Entropy-Based Detection Thresholds

| Entropy Range | Likely Content | Detection Action |
|---------------|---------------|------------------|
| 0.0–3.0 | Plaintext, uncompressed code | Normal; continue analysis |
| 3.0–5.0 | Typical compiled code | Normal; proceed with static analysis |
| 5.0–6.5 | Compressed data | Examine for legitimate compression |
| 6.5–7.5 | Encrypted or packed | Probable packing; attempt unpacking |
| 7.5–8.0 | Encrypted/packed | High confidence packing/encryption |
| >7.5 per section | Packed or encrypted | Definitely packed; identify packer first |

---

## Common Crypto Function Signatures

### AES (Advanced Encryption Standard)

| Constant | Value | Location | Context |
|----------|-------|----------|---------|
| S-box first byte | `0x63` | S-box[0] | AES SubBytes |
| S-box last byte | `0x16` | S-box[255] | AES SubBytes |
| Inv S-box first byte | `0x00` | InvS-box[0] | AES InvSubBytes |
| Round constant table | `0x01, 0x02, 0x04, 0x08, 0x10...` | Rcon[] | AES key expansion |
| MixColumns constant | `0x02, 0x03, 0x01, 0x01` | — | AES MixColumns |
| Key schedule pattern | 4/6/8 32-bit words ± 4-word round keys | Expanded key | AES-128/192/256 |
| Block size | 16 bytes (128 bits) | — | AES block |
| Key sizes | 16/24/32 bytes | — | AES-128/192/256 |

**AES key schedule detection:** An expanded AES-256 key contains 60 consecutive 32-bit words. Search for these patterns in `.rodata` or `.data` sections. The key schedule can be reconstructed: `key[i*4] ^ key[(i-1)*4]` at specific intervals.

### RSA

| Constant | Value | Description |
|----------|-------|-------------|
| Public exponent | `0x10001` (65537) | Most common RSA public exponent |
| Private key structure | `0x3082` | ASN.1 SEQUENCE tag (DER-encoded RSA key) |
| Modulus | Large random prime product | Found in `.rodata` as 1024/2048/4096-bit big integer |
| Private exponent | `d = e^(-1) mod φ(n)` | Computed; stored in RSA private key |

**RSA key detection:** Search for ASN.1 DER-encoded structures starting with `0x30 0x82` (SEQUENCE, length > 127). OpenSSL key format: `0x30 0x82 [2-byte length] 0x02 0x82 [modulus length] [modulus bytes]`.

### SHA Family

| Algorithm | Init Values (H0-H7) | Block Size | Output Size |
|-----------|---------------------|------------|-------------|
| SHA-1 | `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`, `0xC3D2E1F0` (+ 0 where applicable) | 64 bytes | 20 bytes |
| SHA-256 | `0x6A09E667`, `0xBB67AE85`, `0x3C6EF372`, `0xA54FF53A`, `0x510E527F`, `0x9B05688C`, `0x1F83D9AB`, `0x5BE0CD19` | 64 bytes | 32 bytes |
| SHA-512 | `0x6A09E667F3BCC908`, `0xBB67AE8584CAA73B`, `0x3C6EF372FE94F82B`, `0xA54FF53A5F1D36F1`, ... | 128 bytes | 64 bytes |
| SHA-384 | `0xCBBB9D5DC1059ED8`, `0x629A292A367CD507`, `0x9159015A3070DD17`, `0x152FECD8F70E5939`, ... | 128 bytes | 48 bytes |

**SHA detection:** Search for the initialization constants in `.rodata`. These are always loaded at the start of a hash computation. SHA-256 is most common in modern binaries.

### Other Crypto

| Algorithm | Signature | Detection |
|-----------|-----------|-----------|
| MD5 | Init: `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476` | Four 32-bit init constants |
| DES | S-box tables (8 × 64 entries) | Large constant table (256 bytes per S-box) |
| 3DES | Triple DES with 2-3 keys | DES S-boxes + three key schedule calls |
| ChaCha20/Salsa20 | `expand 32-byte k` (constant) | Sigma constant string |

## References

1. Dennis Yurichev, "Reverse Engineering for Beginners," https://begin.reversing.info/
2. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
3. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
4. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
5. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
6. IDA Pro documentation, https://hex-rays.com/ida-pro/
7. Ghidra documentation, https://ghidra-sre.org/
8. radare2 documentation, https://rada.re/n/
9. Phrack Magazine, various issues, http://phrack.org/
10. NIST, "SP 800-147B: BIOS Protection Guidelines," 2023.
| Blowfish | P-array init: `0x243F6A88`, `0x13198A2E`, ... | 18 32-bit P-array values |
| RC4 | Initial permutation (0-255 sequential) | Initialization loop `S[i] = i` followed by swap |
| Curve25519 | Constants `121666`, `121665`, `32560`, `32561` | Field arithmetic constants |
| CRC32 | Polynomial `0xEDB88320` | Reflected polynomial constant |

### Crypto Identification Checklist

```
1. Search for known constants (AES S-box, SHA init vectors, RSA ASN.1)
2. Identify key loading patterns (memcpy, register loads from .rodata)
3. Trace key derivation (keys from passwords → PBKDF2, scrypt, Argon2)
4. Identify mode of operation (ECB: block-by-block; CBC: XOR with previous; GCM: GHASH)
5. Locate IV/nonce (16 bytes random or sequential for AES, 12 bytes for GCM)
6. Check for side-channel mitigations (constant-time implementations, blinding)
7. Verify implementation correctness (compare with reference implementation)
```