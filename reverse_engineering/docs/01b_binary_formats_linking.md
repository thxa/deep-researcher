# Deep Binary Format Analysis: ELF, PE, Mach-O & DEX/ART

> An in-depth technical reference on binary file formats, linking mechanisms, and runtime structures essential for reverse engineering.

---

## Table of Contents

1. [ELF In Depth](#1-elf-in-depth)
2. [PE/COFF In Depth](#2-pecoff-in-depth)
3. [Mach-O In Depth](#3-mach-o-in-depth)
4. [Android DEX/ART Formats](#4-android-dexart-formats)
5. [Format Comparison & Quick Reference](#5-format-comparison--quick-reference)

---

## 1. ELF In Depth

### 1.1 ELF Header — Complete Analysis

The ELF header is the first structure in every ELF file, located at offset 0. Understanding every field is essential for binary format analysis.

```c
// /usr/include/elf.h — Elf64_Ehdr
typedef struct {
    unsigned char e_ident[16];    // ELF identification bytes
    Elf64_Half    e_type;        // Object file type
    Elf64_Half    e_machine;     // Machine type
    Elf64_Word    e_version;     // Object file version
    Elf64_Addr    e_entry;       // Entry point address
    Elf64_Off     e_phoff;       // Program header table offset
    Elf64_Off     e_shoff;       // Section header table offset
    Elf64_Word    e_flags;       // Processor-specific flags
    Elf64_Half    e_ehsize;      // ELF header size
    Elf64_Half    e_phentsize;   // Program header entry size
    Elf64_Half    e_phnum;       // Number of program headers
    Elf64_Half    e_shentsize;   // Section header entry size
    Elf64_Half    e_shnum;       // Number of section headers
    Elf64_Half    e_shstrndx;    // Section header string table index
} Elf64_Ehdr;
```

Detailed field analysis for RE:

**`e_ident[16]` — ELF Identification Array**:

```python
import struct

with open('target_binary', 'rb') as f:
    e_ident = f.read(16)

# Byte-by-byte breakdown:
magic      = e_ident[0:4]     # \x7fELF — must be 7f 45 4c 46
ei_class   = e_ident[4]       # 1=32-bit, 2=64-bit
ei_data    = e_ident[5]       # 1=LE, 2=BE
ei_version = e_ident[6]       # Always 1 (EV_CURRENT)
ei_osabi   = e_ident[7]       # Target OS/ABI
# EI_OSABI values:
#   0 = ELFOSABI_NONE        (System V)
#   1 = ELFOSABI_HPUX        (HP-UX)
#   2 = ELFOSABI_NETBSD       (NetBSD)
#   3 = ELFOSABI_GNU          (GNU/Linux)
#   6 = ELFOSABI_SOLARIS      (Solaris)
#   7 = ELFOSABI_AIX          (AIX)
#   8 = ELFOSABI_IRIX         (IRIX)
#   9 = ELFOSABI_FREEBSD      (FreeBSD)
#  10 = ELFOSABI_TRU64        (Tru64 UNIX)
#  11 = ELFOSABI_MODESTO      (Novell Modesto)
#  12 = ELFOSABI_OPENBSD      (OpenBSD)
#  64 = ELFOSABI_ARM_AEABI    (ARM EABI)
#  97 = ELFOSABI_ARM          (ARM)
# 255 = ELFOSABI_STANDALONE   (Standalone/embedded)

ei_abiversion = e_ident[8]    # ABI version
ei_pad        = e_ident[9:16] # Padding (should be zero)
```

**`e_type` — Object File Type**:

| Value | Name | Description |
|-------|------|-------------|
| 0 | ET_NONE | Unknown type |
| 1 | ET_REL | Relocatable file (.o) |
| 2 | ET_EXEC | Executable file |
| 3 | ET_DYN | Shared object (.so) or PIE executable |
| 4 | ET_CORE | Core dump file |

Critical RE note: PIE executables have `e_type = ET_DYN`, not `ET_EXEC`. This is because PIE executables are position-independent shared objects that the dynamic linker can load at any address.

```bash
# Distinguish PIE executable from shared library:
readelf -h target | grep Type
# Type: DYN (Shared object file) — could be PIE exec OR shared lib

# Check for PT_INTERP — only executables have this:
readelf -l target | grep INTERP
# If present → PIE executable
# If absent → shared library
```

**`e_machine` — Architecture**:

| Value | Name | Architecture |
|-------|------|-------------|
| 3 | EM_386 | Intel 80386 |
| 8 | EM_MIPS | MIPS I |
| 40 | EM_ARM | ARM |
| 50 | EM_IA_64 | IA-64 |
| 62 | EM_X86_64 | AMD x86-64 |
| 183 | EM_AARCH64 | ARM AARCH64 |
| 243 | EM_RISCV | RISC-V |

**`e_flags` — Processor-Specific Flags** (critical for ARM/MIPS):

```bash
# ARM flags indicate instruction set:
readelf -h arm_binary | grep Flags
# Flags: 0x50000000 — Version5 EABI

# MIPS flags indicate ABI:
# 0x00000001 — NOREORDER (explicit reorder control)
# 0x00000002 — PIC (position-independent code)
# 0x00000004 — CPIC (calls PIC using $25)
# O32, N32, 64, N64 ABI flags

# These flags are ESSENTIAL for correct disassembly:
# - ARM: determines whether code is ARM or Thumb mode
# - MIPS: determines register conventions and instruction encoding
```

### 1.2 Program Headers — Segment Analysis

Program headers describe the segments that the kernel loads into memory.

```c
typedef struct {
    Elf64_Word  p_type;      // Segment type
    Elf64_Word  p_flags;     // Segment permissions (PF_R|PF_W|PF_X)
    Elf64_Off   p_offset;    // File offset of segment
    Elf64_Addr  p_vaddr;     // Virtual address in memory
    Elf64_Addr  p_paddr;     // Physical address (usually = p_vaddr)
    Elf64_Xword p_filesz;    // Size in file
    Elf64_Xword p_memsz;    // Size in memory (memsz > filesz → BSS)
    Elf64_Xword p_align;     // Alignment (must be power of 2)
} Elf64_Phdr;
```

Complete segment type reference:

| `p_type` | Name | Description | RE Significance |
|----------|------|-------------|-----------------|
| 0 | PT_NULL |Unused | — |
| 1 | PT_LOAD | Loadable segment | Core code/data mappings |
| 2 | PT_DYNAMIC | Dynamic linking info | Library dependencies, GOT/PLT |
| 3 | PT_INTERP | Path to interpreter | Dynamic linker path |
| 4 | PT_NOTE | Auxiliary info | Build ID, ABI info |
| 5 | PT_SHLIB | Reserved | — |
| 6 | PT_PHDR | Program header itself | Self-reference |
| 7 | PT_TLS | Thread-local storage | TLS template |
| 0x6474e550 | PT_GNU_EH_FRAME | Exception handling | C++ exception unwinding |
| 0x6474e551 | PT_GNU_STACK | Stack executability | NX bit status |
| 0x6474e552 | PT_GNU_RELRO | Read-only after reloc | Security hardening |

```bash
# Comprehensive program header analysis
readelf -lW target_binary

# Security-relevant flags analysis:
python3 << 'EOF'
import struct, sys

def analyze_elf_security(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Check ELF magic
    if data[:4] != b'\x7fELF':
        print("Not an ELF file")
        return
    
    ei_class = data[4]
    is_64 = (ei_class == 2)
    
    # Parse ELF header
    if is_64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]
    
    has_stack_noexec = False
    has_relro = False
    has_interp = False
    
    PT_GNU_STACK = 0x6474e551
    PT_GNU_RELRO = 0x6474e552
    PT_INTERP = 3
    
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        if is_64:
            p_type, p_flags = struct.unpack_from('<II', data, offset)
        else:
            p_type, p_flags = struct.unpack_from('<II', data, offset)
        
        if p_type == PT_INTERP:
            has_interp = True
        elif p_type == PT_GNU_STACK:
            if not (p_flags & 1):  # PF_X = 1, if absent → NX enabled
                has_stack_noexec = True
            else:
                print("WARNING: Stack is executable (NX disabled)")
        elif p_type == PT_GNU_RELRO:
            has_relro = True
    
    print(f"PIE: {'Yes' if has_interp and e_type == 3 else 'No'}")
    print(f"NX (No-execute stack): {'Enabled' if has_stack_noexec else 'Disabled'}")
    print(f"RELRO: {'Yes' if has_relro else 'No'}")

analyze_elf_security(sys.argv[1])
EOF
```

### 1.3 Section Headers — Detailed Analysis

```c
typedef struct {
    Elf64_Word  sh_name;       // Name (index into .shstrtab)
    Elf64_Word  sh_type;       // Section type
    Elf64_Xword sh_flags;      // Section flags
    Elf64_Addr  sh_addr;       // Virtual address (0 if not loaded)
    Elf64_Off   sh_offset;     // File offset
    Elf64_Xword sh_size;       // Size in bytes
    Elf64_Word  sh_link;       // Link to another section
    Elf64_Word  sh_info;       // Additional section info
    Elf64_Xword sh_addralign;  // Alignment
    Elf64_Xword sh_entsize;    // Entry size (if table)
} Elf64_Shdr;
```

Essential section types for RE:

| `sh_type` | Name | Description |
|-----------|------|-------------|
| SHT_NULL | 0 | Inactive/unused |
| SHT_PROGBITS | 1 | Program-defined data (code, initialized data) |
| SHT_SYMTAB | 2 | Symbol table |
| SHT_STRTAB | 3 | String table |
| SHT_RELA | 4 | Relocation entries with addends |
| SHT_HASH | 5 | Symbol hash table |
| SHT_DYNAMIC | 6 | Dynamic linking information |
| SHT_NOTE | 7 | Note section |
| SHT_NOBITS | 8 | BSS — occupied space in memory, no file data |
| SHT_REL | 9 | Relocation entries without addends |
| SHT_DYNSYM | 11 | Dynamic symbol table |
| SHT_INIT_ARRAY | 14 | Pointers to initialization functions |
| SHT_FINI_ARRAY | 15 | Pointers to termination functions |
| SHT_GNU_HASH | 0x6ffffff6 | GNU hash table (faster lookup) |
| SHT_GNU_VERSYM | 0x6fffffff | Version symbol table |
| SHT_GNU_VERNEED | 0x6ffffffe | Version requirements |

Section flags: `SHF_WRITE=1`, `SHF_ALLOC=2`, `SHF_EXECINSTR=4`

```bash
# Detailed section analysis
readelf -SW target_binary

# Find all executable sections (candidate code locations)
readelf -SW target_binary | grep "AX\|WAX" 
# AX = Alloc + eXecute — code sections
# WA = Write + Alloc — data sections
# WAX = All three — suspicious! writable+executable code
```

### 1.4 Symbol Tables & Dynamic Linking

**Symbol Table Structure**:

```c
typedef struct {
    Elf64_Word    st_name;     // Symbol name (string table index)
    unsigned char st_info;     // Symbol type and binding
    unsigned char st_other;    // Symbol visibility
    Elf64_Half    st_shndx;    // Section index
    Elf64_Addr    st_value;    // Symbol value (address)
    Elf64_Xword   st_size;    // Symbol size
} Elf64_Sym;

// st_info encoding:
#define ELF64_ST_BIND(i)    ((i) >> 4)
#define ELF64_ST_TYPE(i)    ((i) & 0xf)

// Symbol binding:
// STB_LOCAL  = 0   — Local symbol, not visible outside object
// STB_GLOBAL = 1   — Global symbol, visible to all
// STB_WEAK   = 2   — Weak symbol, can be overridden
// STB_LOOS   = 10  — OS-specific range start
// STB_HIOS   = 12  — OS-specific range end
// STB_LOPROC = 13  — Processor-specific range start

// Symbol type:
// STT_NOTYPE  = 0   — Unspecified type
// STT_OBJECT  = 1   — Data object
// STT_FUNC    = 2   — Function
// STT_SECTION = 3   — Section symbol
// STT_FILE    = 4   — Source file name
// STT_COMMON  = 5   — Common (unallocated) symbol
// STT_TLS     = 6   — Thread-local storage
```

**Dynamic Linking in Detail**:

The dynamic segment (`PT_DYNAMIC`) contains entries that drive the runtime linker:

```c
typedef struct {
    Elf64_Sxword d_tag;        // Dynamic entry type
    union {
        Elf64_Xword d_val;     // Integer value
        Elf64_Addr  d_ptr;     // Address value
    } d_un;
} Elf64_Dyn;

// Critical dynamic tags for RE:
// DT_NEEDED      — Name of needed shared library
// DT_HASH         — Symbol hash table address
// DT_STRTAB       — Dynamic string table address
// DT_SYMTAB       — Dynamic symbol table address
// DT_STRSZ        — String table size
// DT_SYMENT       — Symbol table entry size
// DT_INIT         — Address of init function
// DT_FINI         — Address of fini function
// DT_INIT_ARRAY   — Pointer to init function array
// DT_INIT_ARRAYSZ — Size of init function array
// DT_FINI_ARRAY   — Pointer to fini function array
// DT_FINI_ARRAYSZ — Size of fini function array
// DT_PLTGOT       — Address of GOT (or PLT-related GOT)
// DT_PLTRELSZ     — PLT relocation table size
// DT_PLTREL       — PLT relocation type (REL or RELA)
// DT_JMPREL       — PLT relocation table address
// DT_REL/DT_RELA  — Relocation table address
// DT_RVASZ        — Relocation entry size
```

```bash
# Extract all DT_NEEDED entries (library dependencies)
readelf -d target_binary | grep NEEDED

# Extract dynamic symbol table
readelf --dyn-syms target_binary

# Extract init/fini arrays (these run before main!)
readelf -d target_binary | grep -E '(INIT|FINI)'
```

### 1.5 PLT/GOT — The Complete Picture

The Procedure Linkage Table (PLT) and Global Offset Table (GOT) implement lazy binding for dynamically linked functions:

```
High-level flow for calling printf():

Source code:     printf("hello");
Compiled:       call printf@plt

PLT entry (printf@plt):
    0x401020: jmp *GOT_PRINTF_OFFSET    ; First time: points back to next line
    0x401026: push $0x5                 ; Push relocation offset index
    0x40102b: jmp PLT[0]               ; Jump to dynamic resolver

PLT[0] (resolver stub):
    0x401000: push GOT[1]              ; Push link_map pointer
    0x401006: jmp *GOT[2]              ; Jump to _dl_runtime_resolve

_dl_runtime_resolve:
    1. Looks up the symbol using the relocation offset
    2. Writes the real printf address into GOT_PRINTF_OFFSET
    3. Calls printf

Subsequent calls:
    call printf@plt
    → jmp *GOT_PRINTF_OFFSET           ; Now points directly to printf
    → Direct jump, no indirection
```

```bash
# Dump PLT entries
objdump -d -j .plt target_binary

# Dump GOT entries
objdump -s -j .got.plt target_binary

# In IDA/Ghidra: PLT entries show as external thunks
# In stripped binaries: PLT entries may have no names
```

**Relocation Entries** — How the linker patches addresses:

```c
typedef struct {
    Elf64_Addr    r_offset;    // Address to apply relocation
    Elf64_Xword   r_info;      // Symbol table index and type
    Elf64_Sxword  r_addend;    // Addend
} Elf64_Rela;

#define ELF64_R_SYM(i)    ((i) >> 32)      // Symbol index
#define ELF64_R_TYPE(i)    ((unsigned long)(i) & 0xffffffff)  // Reloc type

// Common x86-64 relocation types:
// R_X86_64_NONE      = 0    — No relocation
// R_X86_64_64        = 1    — Direct 64-bit (S + A)
// R_X86_64_PC32      = 2    — PC-relative 32-bit (S + A - P)
// R_X86_64_GOT32     = 3    — GOT entry 32-bit (G + A)
// R_X86_64_PLT32     = 4    — PLT-relative 32-bit (L + A - P)
// R_X86_64_COPY      = 5    — Copy symbol at runtime
// R_X86_64_GLOB_DAT  = 6    — Create GOT entry (S)
// R_X86_64_JUMP_SLOT = 7    — Create PLT entry (S)
// R_X86_64_RELATIVE  = 8    — Adjust by base address (B + A)
// R_X86_64_IRELATIVE = 37   — Indirect (execute resolver function)
```

```bash
# List all relocations
readelf -r target_binary

# Key relocation types for RE:
# R_X86_64_JUMP_SLOT — These are PLT/GOT function calls
# R_X86_64_GLOB_DAT  — Global data references
# R_X86_64_RELATIVE  — Base-address-dependent relocations (PIE)
# R_X86_64_IRELATIVE — Indirect resolution (ifunc — resolver function)
```

### 1.6 Debug Information (DWARF)

DWARF is the standard debug information format embedded in ELF sections:

```bash
# Check for debug sections
readelf -S target_debug | grep debug
# .debug_info       — Core type and line information
# .debug_abbrev     — Abbreviation tables
# .debug_line       — Line number information
# .debug_str        — String table for debug info
# .debug_ranges     — Address ranges
# .debug_frame      — CFI (Call Frame Information)
# .debug_aranges    — Address range lookup table

# Extract debug information with readelf
readelf --debug-dump=info target_debug   // Type info
readelf --debug-dump=line target_debug   // Line numbers
readelf --debug-dump=frames target_debug // Stack frames

# Use dwsvc for more detailed DWARF analysis
dwsvc target_debug | less
```

When debug info is available, it dramatically simplifies RE:

```python
# Extract function names and source locations from DWARF
import subprocess

def extract_dwarf_functions(binary):
    """Extract function names and source locations from DWARF debug info."""
    result = subprocess.run(
        ['readelf', '--debug-dump=info', binary],
        capture_output=True, text=True
    )
    functions = {}
    current_cu = None
    
    for line in result.stdout.splitlines():
        if 'DW_AT_comp_dir' in line:
            current_cu = line.split(':')[-1].strip()
        if 'DW_AT_name' in line and 'DW_TAG_subprogram' in result.stdout:
            name = line.split(':')[-1].strip()
        if 'DW_AT_low_pc' in line:
            addr = int(line.split(':')[-1].strip(), 16)
            functions[addr] = {'name': name, 'cu': current_cu}
    
    return functions
```

> **Cross-reference**: Debug symbols can be separated from the binary using `objcopy --only-keep-debug`. See the [Linux Kernel track](../linux_kernel/) for DWARF in kernel debugging.

---

## 2. PE/COFF In Depth

### 2.1 DOS Header and Stub

Every PE file starts with a DOS header for backward compatibility. The key field is `e_lfanew` at offset 0x3C, which points to the PE signature:

```c
typedef struct {
    WORD   e_magic;          // MZ (0x5A4D) — "Mark Zbikowski"
    WORD   e_cblp;           // Bytes on last page of file
    WORD   e_cp;             // Pages in file
    WORD   e_crlc;           // Relocations
    WORD   e_cparhdr;        // Size of header in paragraphs
    WORD   e_minalloc;       // Minimum extra paragraphs needed
    WORD   e_maxalloc;       // Maximum extra paragraphs needed
    WORD   e_ss;             // Initial (relative) SS value
    WORD   e_sp;             // Initial SP value
    WORD   e_csum;           // Checksum
    WORD   e_ip;             // Initial IP value
    WORD   e_cs;             // Initial (relative) CS value
    WORD   e_lfarlc;         // File address of relocation table
    WORD   e_ovno;           // Overlay number
    WORD   e_res[4];         // Reserved words
    WORD   e_oemid;          // OEM identifier
    WORD   e_oeminfo;        // OEM information
    WORD   e_res2[10];       // Reserved words
    LONG   e_lfanew;         // File address of new exe header ← KEY FIELD
} IMAGE_DOS_HEADER;
```

```python
import struct

def parse_dos_header(data):
    """Parse the DOS header of a PE file."""
    if data[:2] != b'MZ':
        raise ValueError("Not a PE file (missing MZ signature)")
    
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    
    # Validate PE signature at e_lfanew
    pe_sig = data[e_lfanew:e_lfanew+4]
    if pe_sig != b'PE\x00\x00':
        raise ValueError(f"Invalid PE signature at 0x{e_lfanew:x}: {pe_sig}")
    
    return {
        'e_magic': struct.unpack_from('<H', data, 0)[0],
        'e_lfanew': e_lfanew,
        'dos_stub_size': e_lfanew - 0x40  # DOS stub between headers
    }
```

### 2.2 PE Header (COFF Header and Optional Header)

```c
typedef struct {
    WORD  Machine;                    // 0x14c=i386, 0x8664=AMD64, 0xAA64=ARM64
    WORD  NumberOfSections;
    DWORD TimeDateStamp;              // Build timestamp (Unix epoch)
    DWORD PointerToSymbolTable;       // COFF symbol table (usually 0)
    DWORD NumberOfSymbols;            // COFF symbol count
    WORD  SizeOfOptionalHeader;       // Size of optional header
    WORD  Characteristics;            // File characteristics flags
} IMAGE_FILE_HEADER;
```

**Characteristics flags** — essential for PE analysis:

```python
# PE Characteristics flags
IMAGE_FILE_RELOCS_STRIPPED     = 0x0001  # No relocation info
IMAGE_FILE_EXECUTABLE_IMAGE    = 0x0002  # File is executable
IMAGE_FILE_LINE_NUMS_STRIPPED  = 0x0004  # No line numbers
IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008  # No local symbols
IMAGE_FILE_AGGRESSIVE_WS_TRIM  = 0x0010  # Aggressive working set trim
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020  # Can handle >2GB addresses
IMAGE_FILE_32BIT_MACHINE       = 0x0100  # 32-bit word machine
IMAGE_FILE_DEBUG_STRIPPED      = 0x0200  # Debug info stripped
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400  # Run from swap
IMAGE_FILE_NET_RUN_FROM_SWAP   = 0x0800  # Run from network swap
IMAGE_FILE_SYSTEM              = 0x1000  # System file
IMAGE_FILE_DLL                 = 0x2000  # This is a DLL
IMAGE_FILE_UP_SYSTEM_ONLY      = 0x4000  # Uniprocessor only
```

**Optional Header** — the most important PE structure:

```c
typedef struct {
    WORD    Magic;                      // 0x10b=PE32, 0x20b=PE32+
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;                 // Size of .text section
    DWORD   SizeOfInitializedData;      // Size of .data section
    DWORD   SizeOfUninitializedData;   // Size of .bss section
    DWORD   AddressOfEntryPoint;        // Entry point RVA
    DWORD   BaseOfCode;                 // Code section RVA
    DWORD   BaseOfData;                 // Data section RVA (PE32 only)
    // --- PE32+ additional fields ---
    ULONGLONG ImageBase;                // Preferred load address
    DWORD   SectionAlignment;           // Section alignment in memory
    DWORD   FileAlignment;              // Section alignment in file
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;          // Reserved
    DWORD   SizeOfImage;                // Total image size
    DWORD   SizeOfHeaders;             // Size of all headers
    DWORD   CheckSum;
    WORD    Subsystem;                  // GUI, CUI, NATIVE, etc.
    WORD    DllCharacteristics;         // DLL characteristics flags
    // --- Stack/heap sizes ---
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD   LoaderFlags;               // Reserved
    DWORD   NumberOfRvaAndSizes;       // Number of data directories
    IMAGE_DATA_DIRECTORY DataDirectory[]; // Data directories!
} IMAGE_OPTIONAL_HEADER64;
```

**DllCharacteristics** — security hardening flags:

```python
DLL_FLAGS = {
    0x0020: 'HIGH_ENTROPY_VA',       # Supports >2GB address space
    0x0040: 'DYNAMIC_BASE',           # ASLR compatible (relocatable)
    0x0080: 'FORCE_INTEGRITY',        # Code integrity checks
    0x0100: 'NX_COMPAT',             # DEP (No-execute) compatible
    0x0200: 'NO_ISOLATION',          # No isolation
    0x0400: 'NO_SEH',                # No SEH (structured exception handling)
    0x0800: 'NO_BIND',               # Do not bind
    0x1000: 'APPCONTAINER',          # AppContainer (UWP app)
    0x2000: 'WDM_DRIVER',            # WDM driver
    0x4000: 'GUARD_CF',              # Control Flow Guard enabled
    0x8000: 'TERMINAL_SERVER_AWARE',  # Terminal server aware
}

# Quick security check with pefile
import pefile

pe = pefile.PE('target.exe')
flags = pe.OPTIONAL_HEADER.DllCharacteristics
for bit, name in DLL_FLAGS.items():
    if flags & bit:
        print(f"  {name}: ENABLED")
```

### 2.3 Import Address Table (IAT)

The IAT is the Windows equivalent of the GOT. When a PE binary imports functions from DLLs, each imported function has a slot in the IAT:

```c
typedef struct {
    union {
        DWORD   Function;         // Memory address after binding
        DWORD   Ordinal;           // Ordinal value if importing by ordinal
        PIMAGE_IMPORT_BY_NAME Name; // Pointer to hint/name structure
    } u;
    DWORD   TimeDateStamp;         // 0 if not bound
    DWORD   ForwarderChain;        // -1 if no forwarders
    DWORD   Name;                  // RVA of DLL name string
    PIMAGE_THUNK_DATA FirstThunk;  // RVA of IAT (RVA from data dir)
} IMAGE_IMPORT_DESCRIPTOR;
```

The IAT resolution process:

```
On-disk (before loading):
  IAT[0] → Hint/Name RVA for "CreateFileA"
  IAT[1] → Hint/Name RVA for "WriteFile"
  IAT[2] → Hint/Name RVA for "CloseHandle"

After loading (loader resolves addresses):
  IAT[0] → 0x7FFE12345678  (actual address of CreateFileA in KernelBase.dll)
  IAT[1] → 0x7FFE1234ABCD  (actual address of WriteFile in KernelBase.dll)
  IAT[2] → 0x7FFE1234CDEF  (actual address of CloseHandle in KernelBase.dll)

This is why DLL injection and API hooking target the IAT — 
overwriting IAT entries redirects function calls.
```

```python
import pefile

def analyze_iat(filename):
    """Comprehensive IAT analysis."""
    pe = pefile.PE(filename)
    
    print("=" * 70)
    print("IMPORT ADDRESS TABLE ANALYSIS")
    print("=" * 70)
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            print(f"\nDLL: {dll_name}")
            print("-" * 50)
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='replace')
                    ordinal_str = f" (hint: {imp.hint})" if imp.hint else ""
                else:
                    func_name = f"Ordinal#{imp.ordinal}"
                    ordinal_str = ""
                
                print(f"  {func_name:45s} @ 0x{imp.address:08x}{ordinal_str}")
    
    # Export table (for DLLs)
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("\n" + "=" * 70)
        print("EXPORT TABLE")
        print("=" * 70)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('utf-8', errors='replace') if exp.name else f"Ordinal#{exp.ordinal}"
            print(f"  {name:40s} @ 0x{exp.address:08x}")
```

### 2.4 PE Sections — Security Analysis

```python
def analyze_pe_sections(pe):
    """Analyze PE sections for security anomalies."""
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        virt_size = section.Misc_VirtualSize
        raw_size = section.SizeOfRawData
        entropy = section.get_entropy()
        
        flags = []
        if section.Characteristics & 0x20000000: flags.append('IMAGE_SCN_MEM_EXECUTE')
        if section.Characteristics & 0x40000000: flags.append('IMAGE_SCN_MEM_READ')
        if section.Characteristics & 0x80000000: flags.append('IMAGE_SCN_MEM_WRITE')
        if section.Characteristics & 0x00000020: flags.append('IMAGE_SCN_CNT_CODE')
        if section.Characteristics & 0x00000040: flags.append('IMAGE_SCN_CNT_INITIALIZED_DATA')
        if section.Characteristics & 0x00000080: flags.append('IMAGE_SCN_CNT_UNINITIALIZED_DATA')
        
        print(f"\nSection: {name}")
        print(f"  VirtualSize:  0x{virt_size:08x}")
        print(f"  RawSize:      0x{raw_size:08x}")
        print(f"  Entropy:      {entropy:.4f}", end="")
        if entropy > 7.0:
            print(" [PACKED/ENCRYPTED]", end="")
        elif entropy > 6.5:
            print(" [COMPRESSED]", end="")
        print()
        print(f"  Flags:        {' | '.join(flags)}")
        
        # Anomaly detection
        is_wx = (section.Characteristics & 0x20000000 and 
                  section.Characteristics & 0x80000000)
        if is_wx:
            print(f"  ⚠ W+X section detected — possible shellcode or self-modifying code")
        
        if raw_size == 0 and virt_size > 0:
            print(f"  ⚠ BSS-like section — uninitialized data")
        
        if virt_size > raw_size * 10:
            print(f"  ⚠ VirtualSize >> RawSize — possible unpacked data region")
```

### 2.5 Authenticode Digital Signatures

PE files can contain Authenticode signatures in the `IMAGE_DIRECTORY_ENTRY_SECURITY` data directory:

```python
def verify_authenticode(pe):
    """Extract and verify Authenticode signature information."""
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY
    if security_dir.Size == 0:
        print("No Authenticode signature present")
        return
    
    # The signature data is at the file offset (NOT RVA) specified in the directory
    offset = security_dir.VirtualAddress
    size = security_dir.Size
    
    # WIN_CERTIFICATE structure
    dwLength = struct.unpack_from('<I', pe.__data__, offset)[0]
    wRevision = struct.unpack_from('<H', pe.__data__, offset + 4)[0]
    wCertificateType = struct.unpack_from('<H', pe.__data__, offset + 6)[0]
    
    print(f"Signature Length: {dwLength}")
    print(f"Revision: {wRevision} (WIN_CERT_REVISION_2_0 = 0x0200)")
    print(f"Type: {wCertificateType} (WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002)")
    
    # Extract the PKCS#7 SignedData for offline verification
    cert_data = pe.__data__[offset + 8:offset + dwLength]
    
    # SIG.check() uses Windows API for verification
    # For cross-platform, use asn1crypto or oscrypto
    with open('/tmp/signature.p7b', 'wb') as f:
        f.write(cert_data)
    print("Signature extracted to /tmp/signature.p7b")
```

### 2.6 PE Resources

PE resources are stored in a hierarchical structure accessible via `IMAGE_DIRECTORY_ENTRY_RESOURCE`:

```python
def dump_pe_resources(pe):
    """Walk the PE resource tree and extract metadata."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print("No resources found")
        return
    
    def walk_resources(entry, level=0):
        indent = "  " * level
        if hasattr(entry, 'directory'):
            name = entry.name or f"Type {entry.id}"
            print(f"{indent}[DIR] {name}")
            for e in entry.directory.entries:
                walk_resources(e, level + 1)
        elif hasattr(entry, 'data'):
            name = entry.name or f"ID {entry.id}"
            rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            print(f"{indent}[DATA] {name} @ RVA 0x{rva:x}, Size 0x{size:x}")
    
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        walk_resources(entry)
```

---

## 3. Mach-O In Depth

### 3.1 Mach-O Header and Load Commands

```c
struct mach_header_64 {
    uint32_t magic;          // MH_MAGIC_64 = 0xFEEDFACF
    cpu_type_t cputype;      // CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM64 = 0x0100000C
    cpu_subtype_t cpusubtype;
    uint32_t filetype;       // MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8, etc.
    uint32_t ncmds;         // Number of load commands
    uint32_t sizeofcmds;    // Total size of load commands
    uint32_t flags;          // Binary flags
    uint32_t reserved;      // Reserved (64-bit only)
};
```

**Mach-O file types**:

| Type | Value | Description |
|------|-------|-------------|
| MH_OBJECT | 1 | Relocatable object file (.o) |
| MH_EXECUTE | 2 | Executable |
| MH_FVMLIB | 3 | Fixed VM shared library |
| MH_CORE | 4 | Core dump |
| MH_PRELOAD | 5 | Preloaded executable |
| MH_DYLIB | 6 | Dynamic shared library (.dylib) |
| MH_DYLINKER | 7 | Dynamic linker |
| MH_BUNDLE | 8 | Loadable bundle (.bundle) |
| MH_DYLIB_STUB | 9 | Shared library stub |
| MH_DSYM | 10 | Debug symbols (dSYM companion file) |
| MH_KEXT_BUNDLE | 11 | Kernel extension |

**Mach-O flags** important for RE:

```python
MH_FLAGS = {
    0x1: 'MH_NOUNDEFS',            # No undefined references
    0x2: 'MH_DYLDLINK',            # Dynamic linker linked
    0x4: 'MH_TWOLEVEL',            # Two-level namespace
    0x8: 'MH_BINDATLOAD',          # Bind symbols at load time
    0x10: 'MH_PREBOUND',           # Prebound
    0x20: 'MH_SPLIT_SEGS',         # Read-only and read-write segments split
    0x40: 'MH_LAZY_INIT',          # Obsolete
    0x80: 'MH_NOHEAPEXEC',         # Heap not executable
    0x100: 'MH_ALLOW_STACK_EXEC',  # Stack executable (INSECURE)
    0x200: 'MH_ROOT_EXEMPT',       # Root safe
    0x400: 'MH_SETUID_SAFE',       # setuid safe
    0x800: 'MH_NO_REEXPORTED_DYLIBS', # No re-exported dylibs
    0x1000: 'MH_PIE',              # Position-independent executable
    0x2000: 'MH_DEAD_STRIPPABLE',   # Dead strippable
    0x4000: 'MH_HAS_TLV_DESCRIPTORS', # Thread-local variables
    0x8000: 'MH_NO_HEAP_EXEC',     # Heap not executable
    0x10000: 'MH_APP_EXTENSION_SAFE', # App extension safe
}
```

### 3.2 Load Commands

Load commands follow the mach_header and describe how to load the binary:

```c
struct load_command {
    uint32_t cmd;        // Load command type
    uint32_t cmdsize;    // Size of load command
};

// Critical load commands:
#define LC_SEGMENT              0x1   // Map a segment
#define LC_SYMTAB               0x2   // Symbol table
#define LC_SEGMENT_64           0x19  // Map a 64-bit segment
#define LC_DYSYMTAB             0xB   // Dynamic symbol table
#define LC_LOAD_DYLINKER        0xE   // Load dynamic linker
#define LC_UUID                 0x1B  // 128-bit UUID
#define LC_CODE_SIGNATURE       0x1D  // Code signature
#define LC_ENCRYPTION_INFO      0x21  // Encrypted segment info (32-bit)
#define LC_ENCRYPTION_INFO_64   0x2C  // Encrypted segment info (64-bit)
#define LC_LOAD_DYLIB           0xC   // Load dynamic library
#define LC_MAIN                 0x80000028  // Main executable entry point
#define LC_DYLD_INFO            0x22  // Compressed dyld information
#define LC_DYLD_INFO_ONLY       0x80000022  // Compressed dyld information (only)
#define LC_FUNCTION_STARTS      0x26  // Function start addresses
#define LC_DATA_IN_CODE         0x29  // Data in code entries
#define LC_SOURCE_VERSION       0x2A  // Source version
#define LC_DYLIB_CODE_SIGN_DRS 0x2B  // Code signing DRs
#define LC_BUILD_VERSION        0x32  // Build version
```

**LC_SEGMENT_64** — the most important load command:

```c
struct segment_command_64 {
    uint32_t cmd;           // LC_SEGMENT_64
    uint32_t cmdsize;       // Total size including section headers
    char     segname[16];   // Segment name
    uint64_t vmaddr;        // Virtual address
    uint64_t vmsize;        // Virtual size
    uint64_t fileoff;        // File offset
    uint64_t filesize;       // File size
    int32_t  maxprot;        // Maximum protection (r/w/x)
    int32_t  initprot;       // Initial protection (r/w/x)
    uint32_t nsects;        // Number of sections
    uint32_t flags;          // Segment flags
};

struct section_64 {
    char     sectname[16];  // Section name
    char     segname[16];   // Segment name
    uint64_t addr;          // Virtual address
    uint64_t size;          // Section size
    uint32_t offset;        // File offset
    uint32_t align;         // Alignment (power of 2)
    uint32_t reloff;        // Relocation offset
    uint32_t nreloc;        // Number of relocations
    uint32_t flags;         // Section type and attributes
    uint32_t reserved1;     // Reserved (for section_index)
    uint32_t reserved2;     // Reserved
    uint32_t reserved3;     // Reserved
};
```

Standard Mach-O segments:

```
__PAGEZERO    — Null page (catches NULL pointer derefs)
__TEXT        — Read-only, executable code
  __text      — Main code section
  __stubs     — Symbol stubs (like PLT)
  __stub_helper — Stub helper code
  __cstring   — C string constants
  __const     — Read-only data
  __objc_methname — Objective-C method names
  __objc_classname — Objective-C class names
__DATA        — Writable data
  __la_symbol_ptr — Lazy symbol pointers (like GOT.PLT)
  __nl_symbol_ptr — Non-lazy symbol pointers (like GOT)
  __got       — Global offset table
  __data      — Initialized data
  __bss       — Uninitialized data
  __objc_classlist — Objective-C class list
  __objc_protolist — Objective-C protocol list
__DATA_CONST  — Read-only after initialization
__LINKEDIT    — Linker information (symbol tables, strings, codesig)
```

```bash
# Comprehensive Mach-O analysis
otool -h binary               # Header
otool -l binary               # Load commands
otool -L binary               # Linked libraries
otool -tV binary              # Disassemble text section
size binary                    # Section sizes
nm -gU binary                  # Global symbols
codesign -dvvv binary          # Code signature details
```

### 3.3 Code Signing and Encryption

Mach-O binaries on Apple platforms are signed and can be encrypted:

```python
def check_macho_encryption(binary_data):
    """Check for encrypted Mach-O segments (iOS App Store DRM)."""
    import struct
    
    # Parse load commands looking for LC_ENCRYPTION_INFO(_64)
    magic = struct.unpack_from('<I', binary_data, 0)[0]
    
    is_64 = (magic == 0xFEEDFACF)  # MH_MAGIC_64
    
    if is_64:
        ncmds = struct.unpack_from('<I', binary_data, 16)[0]
        sizeofcmds = struct.unpack_from('<I', binary_data, 20)[0]
    else:
        ncmds = struct.unpack_from('<I', binary_data, 16)[0]
        sizeofcmds = struct.unpack_from('<I', binary_data, 20)[0]
    
    offset = 32 if is_64 else 28  # After header
    
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', binary_data, offset)
        
        if cmd == 0x21:  # LC_ENCRYPTION_INFO
            cryptoff = struct.unpack_from('<I', binary_data, offset + 8)[0]
            cryptsize = struct.unpack_from('<I', binary_data, offset + 12)[0]
            cryptid = struct.unpack_from('<I', binary_data, offset + 16)[0]
            
            if cryptid != 0:
                print(f"ENCRYPTED: offset=0x{cryptoff:x}, size=0x{cryptsize:x}, id={cryptid}")
                print("This binary is FairPlay encrypted (App Store DRM)")
                print("Must be decrypted before analysis")
                return True
        
        elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            cryptoff = struct.unpack_from('<I', binary_data, offset + 8)[0]
            cryptsize = struct.unpack_from('<I', binary_data, offset + 12)[0]
            cryptid = struct.unpack_from('<I', binary_data, offset + 16)[0]
            
            if cryptid != 0:
                print(f"ENCRYPTED (64-bit): offset=0x{cryptoff:x}, size=0x{cryptsize:x}, id={cryptid}")
                return True
        
        offset += cmdsize
    
    print("Not encrypted")
    return False
```

**Decrypting iOS binaries**:

```bash
# Method 1: Using class-dump and decrypt from jailbroken device
# 1. On jailbroken device, install ldid and class-dump
# 2. Find the decrypted binary in memory:
#    ps aux | grep TargetApp
#    # Get PID
#    # Dump decrypted regions:
#    ./dumpdecrypt.py /path/to/app/target /tmp/decrypted

# Method 2: Using frida-ios-dump
frida-ios-dump -U -n target_app -o decrypted_binary

# Method 3: Manual decryption from dumped memory
# The cryptid field is set to 0 in memory after the dyld decrypts
# So dumping from process memory gives decrypted binary
```

### 3.4 FAT (Universal) Binaries

FAT binaries contain multiple architectures:

```c
struct fat_header {
    uint32_t magic;       // FAT_MAGIC = 0xCAFEBABE (big-endian)
                         // FAT_MAGIC_64 = 0xCAFEBABF
    uint32_t nfat_arch;   // Number of architectures
};

struct fat_arch {
    cpu_type_t cputype;     // CPU type
    cpu_subtype_t cpusubtype; // CPU subtype
    uint32_t offset;        // Offset to Mach-O header
    uint32_t size;          // Size of this architecture
    uint32_t align;         // Alignment
};

struct fat_arch_64 {
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint64_t offset;        // Offset (64-bit)
    uint64_t size;           // Size (64-bit)
    uint32_t align;
    uint32_t reserved;
};
```

```bash
# Inspect FAT binary
lipo -info universal_binary
# Architectures in the fat file: universal_binary are: x86_64 arm64

# Extract single architecture
lipo -thin arm64 universal_binary -output arm64_binary
lipo -thin x86_64 universal_binary -output x86_64_binary

# Or use otool with architecture flag
otool -arch arm64 -h universal_binary
```

> **Cross-reference**: See the [MacOS track](../MacOS/) for Apple-specific RE techniques including Objective-C/Swift analysis, iOS sandbox RE, and macOS security framework analysis.

---

## 4. Android DEX/ART Formats

### 4.1 DEX (Dalvik Executable) Format

DEX files contain Dalvik bytecode executed by the Android runtime:

```c
// DEX header structure
struct DexHeader {
    u1  magic[8];           /* dex\n035\0 or dex\n039\0 */
    u4  checksum;           /* Adler32 checksum */
    u1  signature[20];     /* SHA-1 hash */
    u4  file_size;          /* Total file size */
    u4  header_size;       /* Header size (0x70) */
    u4  endian_tag;        /* Endian marker (0x12345678) */
    u4  link_size;          /* Link section size */
    u4  link_off;           /* Link section offset */
    u4  map_off;            /* Map list offset */
    u4  string_ids_size;    /* String identifiers count */
    u4  string_ids_off;     /* String identifiers offset */
    u4  type_ids_size;      /* Type identifiers count */
    u4  type_ids_off;       /* Type identifiers offset */
    u4  proto_ids_size;     /* Prototype identifiers count */
    u4  proto_ids_off;      /* Prototype identifiers offset */
    u4  field_ids_size;     /* Field identifiers count */
    u4  field_ids_off;      /* Field identifiers offset */
    u4  method_ids_size;    /* Method identifiers count */
    u4  method_ids_off;    /* Method identifiers offset */
    u4  class_defs_size;    /* Class definitions count */
    u4  class_defs_off;     /* Class definitions offset */
    u4  data_size;          /* Data section size */
    u4  data_off;           /* Data section offset */
};
```

```bash
# DEX analysis tools
# baksmali — disassemble DEX to smali
baksmali d classes.dex -o smali_output/

# smali — assemble smali back to DEX
smali a smali_output/ -o modified.dex

# dexdump — comprehensive DEX information
dexdump -f classes.dex    # Full dump
dexdump -l plain classes.dex  # Plain text output

# jadx — DEX to Java decompiler
jadx -d output_java/ target.apk
jadx-gui target.apk       # GUI version
```

### 4.2 ART (Android Runtime) Format

ART uses OAT (Ahead-of-Time compiled) and VDEX (verified DEX) formats:

```bash
# OAT file analysis
oatdump --oat-file=base.odex --output=oat_dump.txt

# VDEX file analysis
vdexExtractor -i base.vdex -o extracted_dex/

# ART heap analysis (for runtime dumps)
# art::gc::heap dumping via kill -SIGQUIT <pid>
```

### 4.3 APK Structure and Analysis

```bash
# APK is a ZIP file with specific structure
unzip -l target.apk

# Typical APK contents:
# AndroidManifest.xml  — App manifest (binary XML format)
# classes.dex          — Dalvik bytecode
# classes2.dex, etc.   — Multidex
# resources.arsc       — Compiled resources
# res/                  — Resource files
# lib/                  — Native libraries (ARM, x86)
# assets/               — Raw assets
// META-INF/            — Signing info (CERT.SF, CERT.RSA, MANIFEST.MF)

# Decompile APK
apktool d target.apk -o target_dir/

# Rebuild APK
apktool b target_dir/ -o modified.apk

# Sign modified APK
apksigner sign --ks mykey.jks --ks-pass pass:password modified.apk

# Analyze with Androguard
python3 << 'EOF'
from androguard.core.apk import APK

apk = APK('target.apk')
print(f"Package: {apk.get_package()}")
print(f"Main Activity: {apk.get_main_activity()}")
print(f"Min SDK: {apk.get_min_sdk_version()}")
print(f"Target SDK: {apk.get_target_sdk_version()}")
print(f"Permissions: {apk.get_permissions()}")
print(f"Activities: {apk.get_activities()}")
print(f"Services: {apk.get_services()}")
print(f"Receivers: {apk.get_receivers()}")
EOF
```

> **Cross-reference**: See the [Android and CVEs track](../android_and_CVEs/) for Android-specific vulnerability analysis.

---

## 5. Format Comparison & Quick Reference

### Quick Reference: Format Field Cross-Walk

| Concept | ELF | PE/COFF | Mach-O |
|---------|-----|---------|--------|
| **File identification** | `\x7fELF` magic | `MZ` at 0, `PE\x00\x00` at e_lfanew | `0xFEEDFACE`/`0xFEEDFACF` |
| **Entry point** | `e_entry` in Ehdr | `AddressOfEntryPoint` in OptHdr | `LC_MAIN` or `LC_UNIXTHREAD` |
| **Architecture** | `e_machine` in Ehdr | `Machine` in FileHeader | `cputype` in mach_header |
| **Sections** | Section headers (`SHT_PROGBITS`, etc.) | Section table | Sections inside `LC_SEGMENT_64` |
| **Segments** | Program headers (`PT_LOAD`, etc.) | Sections with PE characteristics | Segments (`LC_SEGMENT_64`) |
| **Imports** | `.dynsym` + `.dynstr` | Import Directory + IAT | `LC_LOAD_DYLIB` + `__la_symbol_ptr` |
| **Exports** | `.dynsym` + `.dynstr` | Export Directory | `LC_DYSYMTAB` + `__DATA.__la_symbol_ptr` |
| **Dynamic linking** | `PT_DYNAMIC` + `.plt`/`.got.plt` | IAT + Import Directory | Dyld info + stubs |
| **Relocation** | `.rela.dyn`, `.rela.plt` | `.reloc` section | `LC_DYLD_INFO` chains |
| **Debug info** | `.debug_*` (DWARF) | Debug directory (PDB, CodeView) | dSYM companion files |
| **Code signing** | `.note.sig` (rare) | `IMAGE_DIRECTORY_ENTRY_SECURITY` | `LC_CODE_SIGNATURE` |
| **ASLR/PIE** | `ET_DYN` type | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | `MH_PIE` flag |
| **NX/DEP** | `PT_GNU_STACK` no-execute | `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | `MH_NO_HEAP_EXEC` |
| **Stack canaries** | `__stack_chk_fail` symbol | `__security_cookie` in `.data` | `___stack_chk_guard` symbol |

### Security Feature Check Script

```python
#!/usr/bin/env python3
"""Universal binary security feature checker for ELF, PE, and Mach-O."""

import struct, sys

def check_elf(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    if data[:4] != b'\x7fELF':
        return None
    
    is_64 = data[4] == 2
    fmt = '<Q' if is_64 else '<I'
    
    print("\n=== ELF Security Features ===")
    
    # Check PIE
    e_type = struct.unpack_from('<H', data, 16)[0]
    print(f"PIE: {'Yes' if e_type == 3 else 'No'} (e_type={e_type})")
    
    # Parse program headers for security features
    if is_64:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]
    
    relro = "No"
    nx = "Unknown"
    
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, offset)[0]
        p_flags = struct.unpack_from('<I', data, offset + 4)[0]
        
        if p_type == 0x6474e552:  # PT_GNU_RELRO
            relro = "Partial"
            # Check PT_DYNAMIC for BIND_NOW
        elif p_type == 0x6474e551:  # PT_GNU_STACK
            nx = "Enabled" if not (p_flags & 1) else "Disabled"
    
    print(f"RELRO: {relro}")
    print(f"NX: {nx}")
    
    # Check for stack canary
    has_canary = b'__stack_chk_fail' in data
    print(f"Stack Canary: {'Yes' if has_canary else 'No'}")
    
    # Check for stripped symbols
    has_symtab = b'\x00.symtab\x00' in data
    print(f"Symbols: {'Present' if has_symtab else 'Stripped'}")

def check_pe(filename):
    import pefile
    pe = pefile.PE(filename)
    
    print("\n=== PE Security Features ===")
    
    flags = pe.OPTIONAL_HEADER.DllCharacteristics
    
    print(f"ASLR: {'Yes' if flags & 0x40 else 'No'}")
    print(f"DEP/NX: {'Yes' if flags & 0x100 else 'No'}")
    print(f"SEH: {'No (SAFESEH)' if flags & 0x400 else 'Yes'}")  
    print(f"CFG: {'Yes' if flags & 0x4000 else 'No'}")
    print(f"High Entropy VA: {'Yes' if flags & 0x20 else 'No'}")
    
    # Check for Authenticode signature
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    print(f"Authenticode: {'Present' if sec_dir.Size > 0 else 'Absent'}")

if __name__ == '__main__':
    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        magic = f.read(4)
    
    if magic[:4] == b'\x7fELF':
        check_elf(filename)
    elif magic[:2] == b'MZ':
        check_pe(filename)
    else:
        print("Unsupported format")
```

> **Cross-reference**: See [02a_static_analysis.md](02a_static_analysis.md) for tool-based analysis of these binary formats. See [04b_anti_tamper_obfuscation.md](04b_anti_tamper_obfuscation.md) for how packers and obfuscators manipulate binary format structures. See the [Linux Kernel track](../linux_kernel/) for ELF loading in the kernel, and the [Windows Security track](../windows_security/) for PE loading in the Windows kernel.

---

*This document is part of the Deep Researcher Reverse Engineering track. Binary format knowledge is foundational for all subsequent analysis techniques.*

## References

1. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
2. TIS Committee, "Tool Interface Standard (TIS) — Executable and Linking Format (ELF) Specification," 1995, https://refspecs.linuxbase.org/elf/elf.pdf
3. Microsoft, "PE Format Documentation," https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
4. Apple Developer, "Mach-O Programming Documentation," https://developer.apple.com/documentation/kernel/mach-o
5. John R. Levine, "Linkers and Loaders," Morgan Kaufmann, 2000.
6. Dennis Yurichev, "Reverse Engineering for Beginners," https://yurichev.com/writings/RE_for_beginners-en.pdf
7. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
8. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
9. Android Developers, "DEX Format Specification," https://source.android.com/docs/core/runtime/dex-format
10. NIST, "SP 800-147B: BIOS Protection Guidelines," 2023.
11. UEFI Specification, https://uefi.org/specifications