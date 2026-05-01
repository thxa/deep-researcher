# Reverse Engineering Fundamentals & Methodology

> A comprehensive reference covering the foundational principles, methodology, legal frameworks, ethics, and binary theory required for professional reverse engineering.

---

## Table of Contents

1. [What Is Reverse Engineering?](#1-what-is-reverse-engineering)
2. [Reverse Engineering Methodology](#2-reverse-engineering-methodology)
3. [Static vs Dynamic Analysis](#3-static-vs-dynamic-analysis)
4. [Legal Considerations](#4-legal-considerations)
5. [Ethics in Reverse Engineering](#5-ethics-in-reverse-engineering)
6. [Binary Formats](#6-binary-formats)
7. [Linking Models & Symbol Resolution](#7-linking-models--symbol-resolution)
8. [Disassembly vs Decompilation](#8-disassembly-vs-decompilation)
9. [Address Spaces, Sections & Segments](#9-address-spaces-sections--segments)
10. [Cross-References & Further Reading](#10-cross-references--further-reading)

---

## 1. What Is Reverse Engineering?

Reverse engineering (RE) is the process of analyzing a compiled binary, firmware image, protocol, or system to understand its design, architecture, and functionality — without access to the original source code. The goal ranges from understanding malware behavior to auditing closed-source software, interoperability research, vulnerability discovery, and exploit development.

Reverse engineering sits at the intersection of multiple disciplines:

```
+--------------------+    +--------------------+    +--------------------+
|   Computer Science  |    |   Electrical Eng.  |    |   Cryptography     |
|   (Algorithms, OS,  |    |   (Signal Analysis, |   |   (Cipher ID,      |
|    Compilers)       |    |    Hardware)        |    |    Key Extraction)  |
+--------+-----------+    +--------+-----------+    +--------+-----------+
         |                         |                         |
         v                         v                         v
    +-------------------------------------------------------------------+
    |                    REVERSE ENGINEERING                            |
    |   Static Analysis · Dynamic Analysis · Protocol RE · Firmware RE |
    +-------------------------------------------------------------------+
         ^                         ^                         ^
         |                         |                         |
+--------+-----------+    +--------+-----------+    +--------+-----------+
|   Security Research  |    |   Malware Analysis  |    |   Interoperability |
|   (Vuln Discovery,   |    |   (Triage, Behavior, |   |   (Protocol Spec    |
|    Exploit Dev)      |    |    Attribution)      |    |    Reconstruction)   |
+---------------------+    +---------------------+    +----------------------+
```

The core challenge: compiled binaries are lossy transformations of source code. Variable names, type information, comments, macros, and high-level control flow abstractions are stripped during compilation. The reverse engineer must reconstruct meaning from the residue.

### 1.1 The Information Loss Problem

Consider the compilation pipeline:

```c
// Original source
void process_request(User *user, Request *req) {
    if (!is_authenticated(user)) {
        log_event(AUTH_FAILURE, user->id);
        send_error(req, 403);
        return;
    }
    execute_request(user, req);
}
```

After compilation to x86-64 assembly:

```asm
process_request:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    mov     [rbp-0x18], rdi          ; arg1 (user)
    mov     [rbp-0x20], rsi          ; arg2 (req)
    mov     rax, [rbp-0x18]
    mov     rdi, rax
    call    is_authenticated
    test    eax, eax
    jne     0x1189                    ; jump if authenticated
    mov     rax, [rbp-0x18]
    mov     eax, [rax+0x10]          ; user->id offset
    mov     esi, eax
    mov     edi, 0x1                  ; AUTH_FAILURE constant
    call    log_event
    mov     esi, 0x193                ; 403 decimal
    mov     rax, [rbp-0x20]
    mov     rdi, rax
    call    send_error
    jmp     0x11a0
execute_path:
    mov     rax, [rbp-0x20]
    mov     rsi, rax
    mov     rax, [rbp-0x18]
    mov     rdi, rax
    call    execute_request
    nop
    leave
    ret
```

The information lost is immense: variable names (`user`, `req`), struct member names (`id`), enum values (`AUTH_FAILURE`), the semantic intent of constants (`0x193` = 403). The reverse engineer reconstructs these by combining multiple evidence sources: cross-reference analysis, pattern recognition, domain knowledge, and dynamic observation.

---

## 2. Reverse Engineering Methodology

A rigorous methodology separates productive RE from aimless disassembly browsing. The standard RE process follows four phases:

### 2.1 Phase 1: Identification

**Goal**: Determine what the binary IS before diving into HOW it works.

```
Identification Checklist:
├── File type and architecture (ELF x86-64? PE ARM? Mach-O?)
├── Compiler and language (strip vs. debug info, C++ name mangling, Rust, Go)
├── Linking model (statically linked? dynamically linked? which libraries?)
├── Stripping status (symbols present? partial? fully stripped?)
├── Obfuscation/packing indicators (high entropy sections, unusual entry point)
├── Imphash, fuzzy hash comparison against known samples
├── Strings of interest (URIs, registry keys, crypto constants, error messages)
├── Version information, digital signatures
└── Similarity to known families (YARA rules, ssdeep)
```

Tools for identification:

```bash
# Basic file identification
file target_binary
readelf -h target_binary          # ELF header
objdump -f target_binary          # Format summary

# SHA256 and imphash
sha256sum target_binary
python3 -c "
import pefile
pe = pefile.PE('target.exe')
print(f'Imphash: {pe.get_imphash()}')
"

# Section entropy analysis
python3 -c "
import math, sys
from collections import Counter

with open(sys.argv[1], 'rb') as f:
    data = f.read()

def entropy(data):
    count = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in count.values())

print(f'Overall entropy: {entropy(data):.4f}')
# Entropy > 7.0 suggests compression/encryption
" target_binary

# YARA scanning
yara -r malware_rules.yar target_binary

# ssdeep fuzzy hashing
ssdeep -b target_binary
```

### 2.2 Phase 2: Analysis

**Goal**: Develop a mental model of the binary's behavior through systematic examination.

Analysis proceeds in layers:

**Layer 1 — Structural Analysis**: Understand the binary's format, sections, imports, exports, and overall layout. This gives you the "skeleton" of the program.

**Layer 2 — Functional Analysis**: Identify and understand individual functions. Start with `main()` or the entry point, follow cross-references outward. Document function prototypes, calling conventions, and purpose.

**Layer 3 — Behavioral Analysis**: Understand the program's runtime behavior — what it does with what inputs, how state flows through the program, what external resources it accesses.

```python
# Example: Automated function identification via heuristic patterns
import idaapi

def identify_memcpy_functions():
    """Find memcpy-like functions by pattern matching."""
    results = []
    for func_ea in Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        # Pattern: loop with byte-level copy
        has_rep_movsb = False
        has_byte_copy_loop = False
        
        ea = func.start_ea
        while ea < func.end_ea:
            mnem = idc.print_insn_mnem(ea)
            if mnem == 'rep' or mnem == 'rep movsb':
                has_rep_movsb = True
            ea = idc.next_head(ea)
        
        if has_rep_movsb:
            results.append((func_ea, "likely_memcpy"))
    
    return results
```

### 2.3 Phase 3: Documentation

**Goal**: Record findings systematically so they persist beyond a single analysis session.

Documentation standards:

```markdown
# Binary Analysis: [SHA256_PREFIX]

## Metadata
- **File**: target_binary
- **Architecture**: x86-64
- **Compiler**: GCC 11.4.0
- **Linking**: Dynamic, glibc 2.35
- **Stripping**: Partially stripped (lib symbols only)

## Function Map
| Address    | Inferred Name       | Purpose                | Called By          |
|-----------|--------------------|-----------------------|--------------------|
| 0x401000  | main               | Entry point, CLI parse | __libc_start_main |
| 0x401200  | parse_config       | Read config file      | main               |
| 0x401500  | init_network       | Socket setup          | main               |
| 0x401800  | process_command    | Command dispatcher     | main               |
| 0x401C00  | send_response      | Network reply         | process_command     |

## Key Findings
- Uses AES-256-CBC (identified by S-box constant at 0x403000)
- Connects to C2 at 192.168.1.100:4443 (string at 0x402150)
- XOR key derived from hostname (anti-sandbox technique)

## Open Questions
- Purpose of 0x402000 function: appears to be encryption but unclear algorithm
- Large data blob at 0x405000: possibly embedded payload
```

### 2.4 Phase 4: Reconstruction

**Goal**: Produce a coherent mental or written model equivalent to (or close to) the original source design.

This may include:
- Reconstructed C header files with struct definitions
- Protocol specification documents
- Manually decompiled source with annotated comments
- Control flow graphs with semantic labels

---

## 3. Static vs Dynamic Analysis

### 3.1 Static Analysis

Static analysis examines the binary without executing it. This is the primary RE modality and involves:

**Disassembly**: Converting machine code bytes to assembly mnemonics.

```
Raw bytes:    55 48 89 e5 48 83 ec 20 89 7d ec 48 89 75 e0
Disassembly:  push rbp
              mov  rbp, rsp
              sub  rsp, 0x20
              mov  [rbp-0x14], edi
              mov  [rbp-0x20], rsi
```

**Decompilation**: Attempting to reconstruct high-level source from assembly. Decompilers apply pattern matching, type inference, and control flow structuring to produce C-like pseudocode.

**Control Flow Analysis**: Building CFGs (Control Flow Graphs) that map all possible execution paths through functions.

```python
# Building a basic CFG analyzer
from collections import defaultdict

class BasicBlock:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.successors = []
        self.predecessors = []
    
    def __repr__(self):
        return f"BB(0x{self.start:x}-0x{self.end:x})"

def build_cfg(instructions):
    """Build CFG from linearly scanned instructions."""
    blocks = {}
    leaders = set()
    
    # Identify basic block leaders
    leaders.add(0)  # First instruction is always a leader
    for addr, mnem, operands in instructions:
        if mnem.startswith('j'):  # All jumps
            leaders.add(addr)
            # Target address (simplified)
            target = int(operands[0], 16) if operands else None
            if target is not None:
                leaders.add(target)
        if mnem.startswith('j') or mnem == 'ret':
            # Instruction after branch is a leader
            next_addr = addr + instruction_size(addr)
            leaders.add(next_addr)
    
    # Construct basic blocks
    sorted_leaders = sorted(leaders)
    for i, start in enumerate(sorted_leaders):
        end = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
        blocks[start] = BasicBlock(start, end)
    
    return blocks
```

**Cross-Reference Analysis**: Understanding which code references which data (and vice versa) to build a dependency graph.

**String Analysis**: Extracting and categorizing embedded strings for quick behavioral insight:

```bash
# Extract strings with encoding detection
strings -a -el target_binary    # Little-endian 16-bit (UTF-16LE)
strings -a -t x target_binary   # Include offset in hex
strings -n 4 target_binary     # Minimum 4 chars

# Filter for indicators of compromise
strings target_binary | grep -iE '(http|https|ftp|\.exe|\.dll|registry|HKLM|HKCU|cmd\.exe|powershell|/etc/passwd|/bin/sh)'
```

### 3.2 Dynamic Analysis

Dynamic analysis observes the binary during execution. This complements static analysis by revealing:

- **Actual code paths taken** (vs. all possible paths from static analysis)
- **Runtime values** of registers, memory, and variables
- **System interactions** (syscalls, network connections, file operations)
- **Decrypted/decompressed content** (only visible at runtime when self-modifying code runs)

```bash
# System call tracing with strace
strace -f -e trace=network,file,process -o trace.log ./target_binary

# Library call tracing with ltrace
ltrace -f -S -o ltrace.log ./target_binary

# Combined approach: run under debugger with breakpoints on key functions
gdb -batch \
    -ex "b *0x401000" \
    -ex "b memcpy" \
    -ex "b send" \
    -ex "r" \
    -ex "info registers" \
    -ex "x/20x \$rsp" \
    ./target_binary
```

### 3.3 Hybrid Approach

Professional RE always combines both. The recommended workflow:

```
1. Triaged Static Analysis (strings, imports, sections, entropy)
     ↓
2. Dynamic Analysis (run in sandbox, observe behavior, dump memory)
     ↓
3. Targeted Static Analysis (decompile functions observed in step 2)
     ↓
4. Iterate (dynamic reveals new areas, static reveals new hypotheses)
```

Each modality compensates for the other's blind spots. Static analysis sees all possible paths but cannot determine which ones are actually taken. Dynamic analysis sees actual paths but may miss rare or triggered-only paths.

---

## 4. Legal Considerations

### 4.1 DMCA Section 1201

The Digital Millennium Copyright Act (DMCA) Section 1201 is the primary legal concern for reverse engineers in the United States. It criminalizes:

- **Circumventing technological measures** that control access to copyrighted works
- **Manufacturing/trafficking** in circumvention tools

Key provisions:

| Provision | Scope | RE Impact |
|-----------|-------|-----------|
| **17 U.S.C. §1201(a)(1)** | Access control circumvention | Criminalizes breaking DRM/encryption to access content |
| **17 U.S.C. §1201(a)(2)** | Trafficking in access circumvention tools | Criminalizes distributing tools that break access controls |
| **17 U.S.C. §1201(b)(1)** | Rights control circumvention | Criminalizes breaking copy protection mechanisms |
| **17 U.S.C. §1201(f)** | Reverse engineering exemption | Permits RE for interoperability (narrow!) |

The **interoperability exemption** (§1201(f)) allows circumvention *solely* to identify elements necessary for interoperability with independently created programs. This does NOT cover:
- Vulnerability research (unless directly tied to interoperability)
- Security research generally
- Modifying the program for any purpose beyond interoperability
- Distributing circumvention tools even for interoperability purposes

```python
# The DMCA exemption is narrow. Example scenarios:

# LIKELY ALLOWED under §1201(f):
# - Reverse engineering a proprietary file format to write a compatible reader
# - Analyzing network protocol to create an interoperable client

# LIKELY NOT COVERED by §1201(f):
# - Breaking DRM to analyze a game's anti-cheat for vulnerability research
# - Circumventing license checks in medical device firmware for safety analysis
# - Distributing tools that bypass access controls (even for research)

# The Librarian of Congress issues triennial rulemaking exemptions:
# - 2015-2018: Security research on vehicles
# - 2018-2021: Security research on medical devices
# - 2021-2024: Expanded to include security testing on consumer devices
# These exemptions are time-limited and must be renewed
```

### 4.2 EULA Considerations

End User License Agreements frequently contain clauses that:

- **Prohibit reverse engineering** outright
- **Prohibit disassembly or decompilation**
- **Restrict benchmarking or performance analysis**
- **Require arbitration instead of litigation**

Enforceability varies by jurisdiction:

| Jurisdiction | General Stance on EULA Anti-RE Clauses |
|-------------|---------------------------------------|
| **United States** | Often enforced, especially shrink-wrap licenses. Some courts apply fair use. |
| **European Union** | Article 5(3) of Directive 2009/24/EC: RE for interoperability is permitted and EULA clauses cannot override this right. |
| **United Kingdom** | Similar to EU; CRD 2009 aligns with EU directive. Post-Brexit status unchanged. |
| **Japan** | Copyright Act Article 47bis permits RE for interoperability. |
| **Australia** | Less clear; copyright fair dealing is narrower than US fair use. |

**Practical guidance**: Always consult legal counsel before engaging in RE where legal exposure exists. Document your authorization (bug bounty scope, employer authorization, purchase agreements that don't prohibit RE).

### 4.3 Export Controls

Reverse engineering tools and knowledge can be subject to export controls:

- **Wassenaar Arrangement**: Controls export of "intrusion software" and related technology. covers exploit development tools and certain RE capabilities.
- **EAR (Export Administration Regulations)**: U.S. export controls that may classify RE tooling as dual-use technology.
- **ITAR**: Relevant if working with defense-related systems.

The 2013 Wassenaar Plenary introduced controls on:
- Intrusion software (software designed to bypass security controls)
- IP surveillance systems
- Technology for creating intrusion software

These controls impact sharing RE knowledge across borders, particularly for:
- Exploit development techniques
- Anti-forensics tools
- Network intercept tools

> **Note**: These regulations are complex and frequently updated. See also the [zero_day track](../zero_day/docs/08_ethics_disclosure_legal.md) for deeper legal analysis of vulnerability research.

### 4.4 Responsible Disclosure

Reverse engineering vulnerabilities creates a disclosure decision point:

```
Responsible Disclosure Decision Tree:

Discover vulnerability via RE
         │
         ├─ Is it in software you're authorized to test?
         │    ├─ YES → Follow the vendor's responsible disclosure process
         │    └─ NO  → Consider: is public disclosure justified? (imminent threat?
         │              critical infrastructure? no vendor response after 90 days?)
         │
         ├─ Could disclosure cause immediate harm?
         │    ├─ YES → Coordinate with CERT/vendor before disclosure
         │    └─ NO  → Follow standard disclosure timeline (90 days typical)
         │
         └─ Is the vulnerability being actively exploited in the wild?
              ├─ YES → Immediate disclosure may be warranted to enable defense
              └─ NO  → Standard responsible disclosure timeline
```

---

## 5. Ethics in Reverse Engineering

### 5.1 The Dual-Use Dilemma

Reverse engineering knowledge is inherently dual-use — the same techniques that enable security research also enable malware development, piracy, and exploitation. The ethical reverse engineer must:

1. **Hold intent constant**: Maintain defensive/security research intent throughout the process.
2. **Minimize harm**: Consider whether published findings could cause disproportionate harm.
3. **Respect boundaries**: Honor authorization scope, EULAs where legally binding, and vendor disclosure timelines.
4. **Document responsibly**: Redact exploit details when disclosure could cause immediate harm without providing defensive benefit.

### 5.2 Ethical Framework

```
+------------------+     +------------------+     +------------------+
|   Authorization  |────>│    Capability    |────>│    Application   |
|  Am I authorized |    |  Can I do this   |    |  Should I do     |
|  to analyze this |    |  competently?    |    |  this? Is it     |
|  binary/system?  |    |                  |    |  ethical?         |
+------------------+     +------------------+     +------------------+
         │                        │                         │
         v                        v                         v
   Legal clearance        Technical skill          Moral framework
   Contract scope         Tool proficiency         Harm assessment
   Bug bounty scope       Domain knowledge         Proportionality
```

### 5.3 Professional Standards

The reverse engineering community has developed several professional standards:

- **IEEE P7000-2021**: Standard model process for addressing ethical concerns during system design
- **ACM Code of Ethics**: Section 1.2 explicitly addresses avoiding harm, which includes responsible vulnerability handling
- **CREST Code of Conduct**: Defines professional standards for penetration testers and RE analysts
- **NIAC Vulnerability Disclosure Framework**: U.S. framework for coordinating vulnerability disclosure in critical infrastructure

> **Cross-reference**: The [OSEE track](../OSEE/docs/05a_reverse_engineering_vuln_discovery.md) covers professional RE for offensive security certification.

---

## 6. Binary Formats

### 6.1 ELF (Executable and Linkable Format)

ELF is the standard binary format on Linux and most Unix-like systems. It supports executables, shared objects, relocatable objects, and core dumps.

**ELF Header** (first 64 bytes for 64-bit):

```c
typedef struct {
    unsigned char e_ident[16];    // Magic number and other info
    uint16_t      e_type;         // Object file type (ET_EXEC, ET_DYN, ET_REL)
    uint16_t      e_machine;      // Architecture (EM_X86_64=62, EM_ARM=40, EM_AARCH64=183)
    uint32_t      e_version;      // Object file version
    Elf64_Addr    e_entry;        // Entry point virtual address
    Elf64_Off     e_phoff;        // Program header table file offset
    Elf64_Off     e_shoff;        // Section header table file offset
    uint32_t      e_flags;        // Processor-specific flags
    uint16_t      e_ehsize;       // ELF header size in bytes
    uint16_t      e_phentsize;    // Program header table entry size
    uint16_t      e_phnum;        // Program header table entry count
    uint16_t      e_shentsize;    // Section header table entry size
    uint16_t      e_shnum;        // Section header table entry count
    uint16_t      e_shstrndx;     // Section header string table index
} Elf64_Ehdr;
```

Reading the ELF magic bytes:

```bash
xxd -l 16 target_binary
# Expected: 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
#           ^  E  L  F  ^  ^  ^
#           |         |  |  |
#        magic      64-bit LE ELFv1 OSABI
```

The `e_ident` array fields:

| Offset | Size | Field        | Description                              |
|--------|------|-------------|------------------------------------------|
| 0      | 4    | EI_MAG      | Magic number: `\x7fELF`                 |
| 4      | 1    | EI_CLASS    | 1=32-bit, 2=64-bit                       |
| 5      | 1    | EI_DATA     | 1=Little-endian, 2=Big-endian            |
| 6      | 1    | EI_VERSION  | ELF version (always 1)                   |
| 7      | 1    | EI_OSABI    | OS/ABI identification                    |
| 8      | 8    | EI_ABIVERSION + padding | ABI version and padding     |

**Program Headers** (Segments — runtime view):

```c
typedef struct {
    Elf64_Word  p_type;     // Segment type (PT_LOAD, PT_DYNAMIC, PT_INTERP, etc.)
    Elf64_Word  p_flags;    // Segment flags (PF_R, PF_W, PF_X)
    Elf64_Off   p_offset;   // Segment file offset
    Elf64_Addr  p_vaddr;    // Segment virtual address
    Elf64_Addr  p_paddr;    // Segment physical address
    Elf64_Xword p_filesz;   // Segment size in file
    Elf64_Xword p_memsz;   // Segment size in memory
    Elf64_Xword p_align;    // Segment alignment
} Elf64_Phdr;
```

Key segment types for RE:

```bash
readelf -l target_binary

# Key segments for analysis:
# PT_INTERP  — Path to dynamic linker (/lib64/ld-linux-x86-64.so.2)
# PT_LOAD    — Loadable segments (code + data mapped into memory)
# PT_DYNAMIC — Dynamic linking information (shared library deps, GOT, PLT)
# PT_NOTE    — Note segments (build IDs, ABI info)
# PT_GNU_RELRO — Read-only after relocation (security hardening)
# PT_GNU_STACK  — Stack executability flag (NX bit status)
```

**Section Headers** (Link-time view):

```bash
readelf -S target_binary
# Key sections for RE:
# .text      — Executable code
# .plt       — Procedure Linkage Table (dynamic linking trampolines)
# .got       — Global Offset Table
# .got.plt   — GOT entries for PLT
# .data      — Initialized data
# .bss       — Uninitialized data
# .rodata    — Read-only data (strings, constants)
# .symtab    — Symbol table (stripped in production binaries)
# .dynsym    — Dynamic symbol table (present even when stripped)
# .dynstr    — Dynamic string table
# .rela.dyn  — Relocations (static initialization)
# .rela.plt  — Relocations (PLT linking)
# .strtab    — String table for .symtab
# .shstrtab  — Section header string table
# .init_array — Constructor functions
# .fini_array — Destructor functions
# .debug_*   — Debug information (DWARF)
```

### 6.2 PE/COFF (Portable Executable)

The PE format is used on Windows. It extends the COFF (Common Object File Format) with a DOS header for backward compatibility.

```
PE File Layout:
+-------------------+
| DOS Header        |  64 bytes (MZ header)
| DOS Stub          |  "This program cannot be run in DOS mode"
+-------------------+
| PE Signature      |  "PE\0\0" at offset from e_lfanew
+-------------------+
| COFF Header        |  Machine, NumberOfSections, Characteristics
+-------------------+
| Optional Header    |  Magic (0x10b=PE32, 0x20b=PE32+)
|   - Standard Fields
|   - Windows-Specific Fields
|   - Data Directories
+-------------------+
| Section Table      |  Array of IMAGE_SECTION_HEADER
+-------------------+
| Sections           |  .text, .data, .rdata, .reloc, etc.
+-------------------+
```

DOS Header structure (critical fields):

```c
typedef struct {
    WORD   e_magic;      // MZ (0x5A4D)
    // ... 28 WORD fields ...
    LONG   e_lfanew;     // Offset to PE signature (CRITICAL for RE)
} IMAGE_DOS_HEADER;
```

The `e_lfanew` field at offset 0x3C is essential — it tells you where the PE header actually starts, which allows you to skip past the DOS stub.

**Optional Header Data Directories** — these are crucial for PE analysis:

```c
typedef struct {
    DWORD   RVA;         // Relative Virtual Address
    DWORD   Size;         // Size in bytes
} IMAGE_DATA_DIRECTORY;

// Data directory indices:
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0  // Export table
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1  // Import table  
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2  // Resources
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3  // Exception info
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4  // Authenticode signature
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5  // Relocations
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6  // Debug info
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   7  // Architecture specific
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8  // Global pointer
#define IMAGE_DIRECTORY_ENTRY_TLS            9  // Thread-local storage
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10 // Load configuration
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11 // Bound import
#define IMAGE_DIRECTORY_ENTRY_IAT            12 // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13 // Delay import
#define IMAGE_DIRECTORY_ENTRY_COM_DESC       14 // COM descriptor
```

### 6.3 Mach-O

Mach-O is Apple's binary format, used on macOS, iOS, and other Apple platforms:

```
Mach-O File Layout:
+-------------------+
| Mach-O Header      |  magic, cputype, cpusubtype, filetype
+-------------------+
| Load Commands      |  LC_SEGMENT, LC_SYMTAB, LC_DYSYMTAB, etc.
+-------------------+
| Segments           |  __TEXT, __DATA, __LINKEDIT, etc.
|   (Sections)       |  __text, __stubs, __const, __cstring, etc.
+-------------------+
```

```c
struct mach_header_64 {
    uint32_t magic;          // MH_MAGIC_64 = 0xFEEDFACF
    cpu_type_t cputype;      // CPU_TYPE_X86_64, CPU_TYPE_ARM64, etc.
    cpu_subtype_t cpusubtype;
    uint32_t filetype;       // MH_EXECUTE, MH_DYLIB, MH_BUNDLE, etc.
    uint32_t ncmds;         // Number of load commands
    uint32_t sizeofcmds;    // Size of all load commands
    uint32_t flags;         // Flags (MH_NOUNDEFS, MH_PIE, etc.)
    uint32_t reserved;      // Reserved
};
```

FAT (Universal) binaries contain multiple architectures:

```bash
# Examine Mach-O binary
otool -h target_binary          # Header
otool -l target_binary          # Load commands
otool -L target_binary          # Linked libraries
nm -gU target_binary           # Exported symbols

# FAT binary examination
lipo -info target_binary        # Show architectures
lipo -thin x86_64 target_binary -output thin_binary  # Extract single arch
otool -arch arm64 -h fat_binary  # Examine specific arch in FAT binary
```

> **Cross-reference**: See [01b_binary_formats_linking.md](01b_binary_formats_linking.md) for deep binary format analysis. See the [MacOS track](../MacOS/) for Apple-specific RE techniques.

---

## 7. Linking Models & Symbol Resolution

### 7.1 Static vs Dynamic Linking

**Static Linking**: All library code is embedded in the binary. Larger binary, no runtime dependencies, easier to analyze (everything is self-contained).

```bash
# Compile with static linking
gcc -static -o target_static target.c

# Check if statically linked
file target_static
# target_static: ELF 64-bit LSB executable, x86-64, statically linked

# All libc functions are visible in the binary
nm target_static | grep -c " T "
# Much larger count than dynamic
```

**Dynamic Linking**: Library code is loaded at runtime from shared objects (.so, .dll, .dylib). Smaller binary, but requires library presence and uses PLT/GOT indirection.

```bash
# Compile with dynamic linking (default)
gcc -o target_dynamic target.c

# Check shared library dependencies
ldd target_dynamic
# linux-vdso.so.1
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
# /lib64/ld-linux-x86-64.so.2
```

### 7.2 PLT/GOT Mechanism

The Procedure Linkage Table (PLT) and Global Offset Table (GOT) implement lazy dynamic linking on Linux:

```
Call to printf():
  call printf@plt
      │
      v
  PLT Entry (printf@plt):
      jmp    *GOT[printf]     ────┐
      push   $reloc_index     │
      jmp    PLT[0] (resolver)│
                                │
                        First call? ──YES──> GOT[printf] points back to PLT
                        │                   (next instruction pushes reloc_index)
                        │                   Then jumps to dynamic resolver
                        │                   Resolver finds printf, updates GOT
                        │                   Calls printf
                        │
                        NO ──> GOT[printf] points to real printf
                               Direct jump, no resolution overhead
```

This mechanism is critical for security analysis because:

```bash
# Check for RELRO (read-only GOT after relocation)
readelf -d target_binary | grep RELRO
readelf -l target_binary | grep RELRO

# Full RELRO: GOT is mapped read-only after relocation (better security)
# Partial RELRO: GOT.PLT is writable (default, enables lazy binding)
# No RELRO: Entire GOT is writable (insecure)
```

### 7.3 Symbol Resolution Process

During dynamic linking, the runtime linker (`ld.so`) performs:

1. **Map shared objects**: Load all DT_NEEDED libraries into memory
2. **Resolve symbols**: Build a complete symbol table from all loaded objects
3. **Perform relocations**: Fix up address references using the symbol table
4. **Initialize**: Call `.init` and `.init_array` functions

```bash
# Trace the dynamic linking process
LD_DEBUG=libs ./target_binary        # Show library loading
LD_DEBUG=symbols ./target_binary     # Show symbol resolution
LD_DEBUG=reloc ./target_binary       # Show relocations
LD_DEBUG=all ./target_binary         # Show everything
```

### 7.4 Import Address Table (Windows)

On Windows, the IAT serves a similar role to the GOT:

```python
import pefile

pe = pefile.PE('target.exe')

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"\nDLL: {entry.dll.decode()}")
    for imp in entry.imports:
        if imp.name:
            print(f"  {imp.name.decode():40s} @ 0x{imp.address:08x}")
        else:
            print(f"  Ordinal #{imp.ordinal:5d}               @ 0x{imp.address:08x}")
```

---

## 8. Disassembly vs Decompilation

### 8.1 Disassembly

Disassembly converts raw machine code bytes to human-readable assembly language. This is a well-defined process (mostly), but several challenges exist:

**Challenge 1 — Code vs Data**: Binary sections like `.text` contain both code and embedded data (jump tables, constants). Distinguishing them requires control flow analysis.

```bash
# Linear sweep disassembly (objdump) — doesn't handle code/data separation well
objdump -d target_binary

# Recursive descent disassembly (IDA Pro, Ghidra) — follows control flow
# Much more accurate for code/data separation
```

**Challenge 2 — Indirect Jumps**: Switch statements, virtual function calls, and callback-based dispatch use indirect jumps whose targets may not be statically determinable.

```asm
; Indirect jump through jump table (switch statement)
mov     eax, [rbp-0xC]          ; switch variable
lea     rdx, [rax*4+0x401000]   ; jump table at 0x401000
mov     eax, [rdx]
cdqe
add     rax, 0x401050
jmp     rax                       ; indirect jump — target is runtime-dependent
```

**Challenge 3 — Self-Modifying Code**: Some obfuscated binaries modify their own code at runtime, making static disassembly inaccurate.

### 8.2 Decompilation

Decompilation attempts to reconstruct C-like pseudocode from assembly. This is fundamentally harder than assembly because it requires reverse-engineering the compiler's transformation:

```
Source → Compiler → Assembly → Decompiler → Pseudocode
  (lossy)                      (approximate reconstruction)

Information lost:                  Information that must be reconstructed:
- Variable names                   - Variable lifetimes and types
- Type information                 - Control flow structures (loops, switches)
- Comments                         - Function boundaries and prototypes
- Macro expansions                 - Struct layouts
- Template instantiations          - Class hierarchies
```

Decompilation quality varies dramatically:

```c
// Original source
int process_packet(uint8_t *data, size_t len) {
    if (len < 4) return -1;
    uint16_t opcode = *(uint16_t *)data;
    uint16_t flags = *(uint16_t *)(data + 2);
    if (opcode > MAX_OPCODE) return -2;
    handlers[opcode](data + 4, len - 4, flags);
    return 0;
}
```

```c
// Typical decompiler output (Ghidra/IDA)
void process_packet(byte *data, ulong len) {
    ushort uVar1;
    ushort uVar2;
    
    if (len < 4) {
        return -1;  // Actually returns 0xffffffffffffffff on 64-bit
    }
    uVar1 = *(ushort *)data;
    uVar2 = *(ushort *)(data + 2);
    if ((uint)uVar1 < 0x100) {  // MAX_OPCODE was 256
        (*handlers)(data + 4, len - 4, uVar2);  // Jump table call
    }
    return -2;  // Actually 0xfffffffffffffffe
}
```

Note the quality issues:
- Return type is `void` instead of `int` (decompiler couldn't determine)
- Integer sign/size issues (returns shown as negative instead of unsigned)
- Jump table call not resolved as array indexing
- Constants appear as raw hex instead of named constants

### 8.3 Tool Comparison

| Feature | IDA Pro | Ghidra | radare2/rizin | Binary Ninja |
|---------|---------|--------|---------------|---------------|
| **Disassembler** | Industry standard | Good | Good | Good |
| **Decompiler** | Hex-Rays (paid add-on) | Built-in, open source | Built-in (rizin) | Built-in (HLIL) |
| **Scripting** | IDAPython (excellent) | Java/Python (good) | r2pipe (fair) | Python API (good) |
| **Collaboration** | IDA Teams (paid) | Git-based (free) | Limited | Limited |
| **Architecture Support** | Extensive | Extensive | Extensive | Growing |
| **Price** | $1000+ | Free | Free | $150+ |

> **Cross-reference**: See [02a_static_analysis.md](02a_static_analysis.md) and [06_re_tooling_workflow.md](06_re_tooling_workflow.md) for detailed tool workflows.

---

## 9. Address Spaces, Sections & Segments

### 9.1 Virtual Address Space Layout

When a binary is loaded, the OS creates a virtual address space. Understanding this layout is essential for RE:

```
Linux x86-64 Process Address Space:

0xFFFFFFFFFFFFFFFF
┌──────────────────┐ 
│ Kernel Space      │ <- Not accessible from user mode
│ (1 page gap)      │    See [linux_kernel track] for kernel RE
├──────────────────┤ 0x7FFFFFFFFFFF
│ Stack             │ <- Grows downward
│  (RLIMIT_STACK)   │
├──────────────────┤
│  (gap)            │
├──────────────────┤
│ Memory-mapped     │ <- Shared libraries, mmapped files
│ region            │
├──────────────────┤
│  (gap)            │
├──────────────────┤
│ Heap              │ <- Grows upward (brk/sbrk for program break,
│  (brk)            │    mmap for large allocations)
├──────────────────┤
│ BSS               │ <- Zero-initialized data (.bss section)
│ Data              │ <- Initialized data (.data section)
│ Read-only data    │ <- String constants, jump tables (.rodata)
│ Text              │ <- Executable code (.text section)
├──────────────────┤
│ ELF Header        │ <- Mapped from file offset 0
├──────────────────┤
│  (unmapped)       │
└──────────────────┘ 0x0000000000000000
```

Key virtual memory concepts:

```bash
# Examine a process's memory map
cat /proc/$(pidof target)/maps

# Typical output:
# 00400000-0040d000 r-xp 00000000 08:01 12345  /path/to/target    (text)
# 0060c000-0060d000 r--p 0000c000 08:01 12345  /path/to/target    (rodata)
# 0060d000-0060e000 rw-p 0000d000 08:01 12345  /path/to/target    (data)
# 0060e000-00610000 rw-p 00000000 00:00 0                          (bss)
# 7f1000000000-7f10001d5000 r-xp ...           libc.so.6           (libc text)
# 7f10001f4000-7f10001f6000 r--p ...           libc.so.6           (libc rodata)
# 7f10001f6000-7f10001f8000 rw-p ...           libc.so.6           (libc data)
# 7f1000213000-7f1000214000 rw-p ...                                (libc bss)
# 7f1000239000-7f100025c000 r-xp ...           ld-linux-x86-64.so (ld text)
# 7ffff7dda000-7ffff7ddc000 rw-p ...                                (ld data)
# 7ffff7ddd000-7ffff7de1000 r--p ...           [vvar]              (vvar)
# 7ffff7de1000-7ffff7de3000 r-xp ...           [vdso]              (vdso)
# 7ffffffde000-7ffffffff000 rw-p ...           [stack]             (stack)
```

### 9.2 Sections vs Segments

Sections and segments serve different purposes:

**Sections** (link-time): Used by the linker to combine object files. Rich metadata — names, types, alignment, flags.

**Segments** (run-time): Used by the OS loader to map the binary into memory. Minimal metadata — type, permissions, address, size.

```
File:                                  Memory:
┌───────────────┐                     ┌───────────────┐
│ ELF Header     │ ──e_entry──>       │ Text Segment    │ r-x
│ Program Headers│                     │  (.text)        │
├───────────────┤                     │  (.plt)         │
│ .text          │──┐                  │  (.init)        │
├───────────────┤  ├─PT_LOAD──>       ├───────────────┤
│ .rodata        │  │                  │ Data Segment    │ rw-
│ .data          │──┘                  │  (.data)        │
├───────────────┤                     │  (.got.plt)     │
│ .bss           │                     │  (.bss)         │
├───────────────┤                     └───────────────┘
│ .symtab        │  (not loaded)
│ .strtab        │  (not loaded)
│ .shstrtab      │  (not loaded)
└───────────────┘
```

Key insight for RE: **Not all sections map to segments.** Debugging sections (`.symtab`, `.debug_*`) exist only in the file, not in memory. This is why stripped binaries still work — the section header table can be removed entirely, and only program headers matter for execution.

### 9.3 Address Translation

Understanding the relationship between file offsets, virtual addresses, and physical addresses is essential:

```
Conversion formulas:
  VA = File_Offset + (p_vaddr - p_offset)
  File_Offset = VA - p_vaddr + p_offset
  
  For malware packed binary: the on-disk sections may be compressed/encrypted,
  and the actual code only exists in memory AFTER the packer's stub decompresses
  it. This is why we must often dump from memory (Volatility, process dump) 
  rather than analyze the file on disk.
```

```python
def va_to_file_offset(va, phdr_list):
    """Convert virtual address to file offset using program headers."""
    for phdr in phdr_list:
        if phdr['p_vaddr'] <= va < phdr['p_vaddr'] + phdr['p_memsz']:
            return va - phdr['p_vaddr'] + phdr['p_offset']
    return None

def file_offset_to_va(offset, phdr_list):
    """Convert file offset to virtual address using program headers."""
    for phdr in phdr_list:
        if phdr['p_offset'] <= offset < phdr['p_offset'] + phdr['p_filesz']:
            return offset - phdr['p_offset'] + phdr['p_vaddr']
    return None
```

### 9.4 PIE and ASLR Implications

Position-Independent Executables (PIE) and Address Space Layout Randomization (ASLR) have significant implications for RE:

```bash
# Check if binary is PIE
readelf -h target_binary | grep Type
# DYN (Shared object file) = PIE
# EXEC (Executable file) = non-PIE

# Check if NX is enabled
readelf -l target_binary | grep NX
# GNU_STACK      0x000000 noexec = NX enabled

# Check for RELRO
readelf -l target_binary | grep RELRO
# GNU_RELRO      — Partial RELRO
# With -z,relro,-z,now — Full RELRO

# Check for canaries
python3 -c "
import pefile
# Check for stack canaries in ELF
with open('target_binary', 'rb') as f:
    data = f.read()
    if b'__stack_chk_fail' in data:
        print('Stack canaries: PRESENT')
    else:
        print('Stack canaries: ABSENT')
"
```

When analyzing PIE binaries under ASLR, remember that all addresses shown in the disassembler are relative offsets from the binary's base address. The actual runtime addresses are:

```
Runtime VA = Binary Base Address (randomized by ASLR) + Offset in Binary
```

> **Cross-reference**: See the [Linux Kernel track](../linux_kernel/) for kernel地址空间布局, and the [ring_and_vulns track](../ring_and_vulns/) for CPU ring transitions and segment descriptor handling.

---

## 10. Cross-References & Further Reading

### Internal Cross-References

- **[01b_binary_formats_linking.md](01b_binary_formats_linking.md)** — Deep dive into ELF, PE, Mach-O internals
- **[02a_static_analysis.md](02a_static_analysis.md)** — Static analysis tools and techniques
- **[02b_dynamic_analysis.md](02b_dynamic_analysis.md)** — Dynamic analysis and debugging
- **[04b_anti_tamper_obfuscation.md](04b_anti_tamper_obfuscation.md)** — Anti-RE techniques and bypasses
- **[OSEE Track](../OSEE/docs/05a_reverse_engineering_vuln_discovery.md)** — RE for vulnerability discovery
- **[Zero-Day Track](../zero_day/docs/02b_vuln_discovery_audit_re.md)** — RE in vulnerability research

### External References

- **"Practical Binary Analysis"** by Dennis Andriesse (No Starch Press, 2019) — Comprehensive ELF/binary analysis
- **"Reverse Engineering for Beginners"** by Dennis Yurichev — Free online reference
- **"The ELF format and ABI specifications"** — https://refspecs.linuxbase.org/elf/elf.pdf
- **"PE Format"** — Microsoft Learn documentation
- **"Mach-O Programming"** — Apple Developer documentation
- **"Linkers and Loaders"** by John R. Levine — Definitive reference on linking
- **Wargames**: Crackmes.one, Reversing.Kr, OverTheWire, Pwnable.kr

---

*This document is part of the Deep Researcher Reverse Engineering track. The methodology described here is foundational for all subsequent modules.*

## References

1. Dennis Yurichev, "Reverse Engineering for Beginners," https://begin.reversing.info/
2. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.
3. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
4. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
5. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
6. John R. Levine, "Linkers and Loaders," Morgan Kaufmann, 2000.
7. TIS Committee, "Tool Interface Standard (TIS) — Executable and Linking Format (ELF) Specification," 1995, https://refspecs.linuxbase.org/elf/elf.pdf
8. Microsoft, "PE Format Documentation," https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
9. Apple Developer, "Mach-O Programming Documentation," https://developer.apple.com/documentation/kernel/mach-o
10. SANS Institute, "Reverse Engineering Malware" (FOR610), https://www.sans.org/
11. DEF CON conference proceedings, https://www.defcon.org/
12. DMCA Section 1201, 17 U.S.C. §1201, https://www.copyright.gov/title17/92chap12.html