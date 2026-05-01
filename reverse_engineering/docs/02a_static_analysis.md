# Static Analysis Techniques & Tooling

> Comprehensive reference on static analysis methodologies, tool workflows, and automation for reverse engineering compiled binaries.

---

## Table of Contents

1. [Static Analysis Overview](#1-static-analysis-overview)
2. [IDA Pro Architecture & Workflow](#2-ida-pro-architecture--workflow)
3. [Ghidra: Decompiler, Scripting & Collaboration](#3-ghidra-decompiler-scripting--collaboration)
4. [radare2/rizin Analysis Pipeline](#4-radare2rizin-analysis-pipeline)
5. [Binary Ninja IL-Based Analysis](#5-binary-ninja-il-based-analysis)
6. [Pattern Matching & Function Identification](#6-pattern-matching--function-identification)
7. [Cross-Reference Analysis](#7-cross-reference-analysis)
8. [Data Flow Static Analysis](#8-data-flow-static-analysis)
9. [Symbol Recovery](#9-symbol-recovery)
10. [String Analysis](#10-string-analysis)
11. [Entropy Analysis for Packed Binaries](#11-entropy-analysis-for-packed-binaries)
12. [YARA Rules for Classification](#12-yara-rules-for-classification)

---

## 1. Static Analysis Overview

Static analysis examines a binary without executing it. It encompasses disassembly, decompilation, pattern recognition, cross-reference construction, and data flow analysis. The goal is to reconstruct a mental model of the program's behavior sufficient for understanding, vulnerability discovery, or modification.

The static analysis workflow follows a systematic progression:

```
                     ┌─────────────────────┐
                     │  1. Binary Triage    │
                     │  (file, strings,     │
                     │   sections, entropy)  │
                     └──────────┬──────────-┘
                                │
                     ┌──────────▼──────────-┐
                     │  2. Structural Analysis│
                     │  (imports, exports,   │
                     │   sections, symbols)   │
                     └──────────┬──────────-┘
                                │
                     ┌──────────▼──────────-┐
                     │  3. Functional Analysis│
                     │  (decompile, label,    │
                     │   prototype functions) │
                     └──────────┬──────────-┘
                                │
                     ┌──────────▼──────────-┐
                     │  4. Behavioral Analysis│
                     │  (cross-refs, data     │
                     │   flow, call graphs)   │
                     └──────────┬──────────-┘
                                │
                     ┌──────────▼──────────-┐
                     │  5. Deep Analysis      │
                     │  (crypto, protocol,   │
                     │   vulnerability)       │
                     └─────────────────────────┘
```

Each layer builds on the previous. Skipping triage wastes time on binaries that are trivially understood. Skipping structural analysis leads to misinterpreting library code as application logic.

---

## 2. IDA Pro Architecture & Workflow

### 2.1 IDA Pro Overview

IDA Pro (Interactive DisAssembler) is the industry-standard reverse engineering platform. Its architecture is built around several core concepts:

- **Database (IDB)**: IDA stores all analysis results in a `.idb` (32-bit) or `.i64` (64-bit) database file, separate from the original binary
- **Netnodes**: Internal storage units that hold disassembly, cross-references, comments, and type information
- **Processor Modules**: Architecture-specific disassembly engines (x86, ARM, MIPS, PowerPC, etc.)
- **File Loaders**: Format-specific parsers (ELF, PE, Mach-O, etc.)
- **Plugins/Extensions**: IDAPython and C SDK extensions

### 2.2 Initial Analysis Workflow

```python
# IDAPython: Automated initial analysis script
import idaapi
import idautils
import idc

def initial_analysis():
    """Run automated initial analysis on the current IDB."""
    
    # 1. Wait for auto-analysis to complete
    idaapi.auto_wait()
    
    # 2. Identify and label entry point
    entry = idaapi.get_inf_structure().start_ea
    idc.set_name(entry, "entry_point", idc.SN_NOWARN)
    
    # 3. Enumerate all imports
    print("=== IMPORTS ===")
    for i in range(idaapi.get_import_module_qty()):
        module_name = idaapi.get_import_module_name(i)
        print(f"\nModule: {module_name}")
        
        def imp_cb(ea, name, ordinal):
            if name:
                print(f"  {name:40s} @ 0x{ea:08x}")
            else:
                print(f"  Ordinal #{ordinal:5d}       @ 0x{ea:08x}")
            return True
        
        idaapi.enum_import_names(i, imp_cb)
    
    # 4. Enumerate all exports
    print("\n=== EXPORTS ===")
    for i, (ea, _, name) in enumerate(idautils.Entries()):
        print(f"  {name:40s} @ 0x{ea:08x}")
    
    # 5. List all functions with their sizes
    print("\n=== FUNCTIONS ===")
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if func:
            name = idc.get_func_name(func_ea)
            size = func.end_ea - func.start_ea
            print(f"  {name:40s} @ 0x{func_ea:08x} (size: {size})")
    
    # 6. Identify strings
    print("\n=== STRINGS ===")
    for s in idautils.Strings():
        print(f"  0x{s.ea:08x}: {str(s)}")

# Run
initial_analysis()
```

### 2.3 Advanced IDA Techniques

**Function chunk recognition**: Large functions may be split into multiple chunks due to optimization. IDA must be told to merge them:

```python
# IDAPython: Detect and merge function chunks
import idaapi
import idautils

def detect_function_chunks():
    """Find function chunks that should be merged."""
    chunks = {}
    
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        # Check for tail chunks (code that belongs to a function
        # but is separated by optimization)
        fci = idaapi.func_tail_iterator_t(func)
        ok = fci.first()
        while ok:
            chunk = fci.chunk()
            if chunk.start_ea != func.start_ea:
                print(f"  Tail chunk at 0x{chunk.start_ea:x} "
                      f"(parent: 0x{func.start_ea:x})")
            ok = fci.next()

detect_function_chunks()
```

**Type reconstruction with IDA's type system**:

```python
# IDAPython: Apply standard C types to known patterns
import ida_typeinf
import idaapi

def create_struct_types():
    """Create and apply struct types based on access patterns."""
    
    # Create a struct type
    tif = ida_typeinf.tinfo_t()
    struct_name = "packet_header"
    
    # Define struct using IDC-style type string
    struct_def = """
    struct packet_header {
        unsigned short magic;
        unsigned short version;
        unsigned int length;
        unsigned int type;
        unsigned int flags;
        unsigned int checksum;
    };
    """
    
    result = ida_typeinf.parse_decl_string(struct_def)
    if result:
        print(f"Created struct: {struct_name}")
    else:
        print(f"Failed to create struct: {struct_name}")

create_struct_types()
```

**Hex-Rays Decompiler scripting**:

```python
# IDAPython: Hex-Rays decompiler scripting
import ida_hexrays

def decompile_function(ea):
    """Decompile a function and return the pseudocode."""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)
    except ida_hexrays.DecompilationFailure as e:
        print(f"Decompilation failed at 0x{ea:x}: {e}")
        return None

# Batch decompile all functions
for func_ea in idautils.Functions():
    pseudocode = decompile_function(func_ea)
    if pseudocode:
        name = idc.get_func_name(func_ea)
        with open(f"decompiled/{name}.c", "w") as f:
            f.write(pseudocode)
```

---

## 3. Ghidra: Decompiler, Scripting & Collaboration

### 3.1 Ghidra Architecture

Ghidra is NSA's open-source reverse engineering framework, built on Java with a powerful decompiler that generates C-like pseudocode:

```
Ghidra Architecture:
┌─────────────────────────────────────────────────┐
│                   Ghidra GUI                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐    │
│  │ Listing  │ │ Decompile│ │ Data Type    │    │
│  │ View     │ │ View    │ │ Manager     │    │
│  └──────────┘ └──────────┘ └──────────────┘    │
├─────────────────────────────────────────────────┤
│                   Program API                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐    │
│  │ Listing  │ │ Symbol   │ │ Cross-Ref    │    │
│  │ Service  │ │ Table    │ │ Service     │    │
│  └──────────┘ └──────────┘ └──────────────┘    │
├─────────────────────────────────────────────────┤
│                   Analysis Pipeline               │
│  ┌──────┐ ┌───────┐ ┌─────────┐ ┌──────────┐  │
│  │ P-Code│ │ Decomp │ │ Analysis │ │ Emulation│ │
│  │ Gen  │ │ Engine │ │ Modules │ │ Engine  │  │
│  └──────┘ └───────┘ └─────────┘ └──────────┘  │
└─────────────────────────────────────────────────┘
```

**P-Code** is Ghidra's intermediate representation (IR):

```
Original:  MOV EAX, [EBX+8]
P-Code:    %1 = COPY EBX
           %2 = CONST 0x8
           %3 = INT_ADD %1, %2
           %4 = LOAD ram[%3]     ; Load from computed address
           EAX = COPY %4

This IR enables:
- Architecture-independent analysis
- Type inference and propagation
- Data flow analysis on P-Code
- Emulation and symbolic execution
```

### 3.2 Ghidra Scripting (Java and Python)

**Java scripting** (more powerful, full API access):

```java
// Ghidra Java script: FindCryptoConstants.java
// @category CryptoAnalysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

public class FindCryptoConstants extends GhidraScript {
    // AES S-box
    static final int[] AES_SBOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
        // ... (full 256-byte S-box)
    };
    
    @Override
    public void run() throws Exception {
        System.out.println("Searching for crypto constants...");
        
        // Search for AES S-box in memory
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        
        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) continue;
            
            Address start = block.getStart();
            Address end = block.getEnd();
            
            // Search for first 8 bytes of AES S-box
            byte[] pattern = new byte[8];
            for (int i = 0; i < 8; i++) {
                pattern[i] = (byte) AES_SBOX[i];
            }
            
            Address addr = find(start, pattern);
            while (addr != null && addr.compareTo(end) < 0) {
                // Verify more of the S-box
                boolean match = true;
                for (int i = 0; i < 16 && match; i++) {
                    try {
                        byte b = memory.getByte(addr.add(i));
                        if ((b & 0xFF) != AES_SBOX[i]) {
                            match = false;
                        }
                    } catch (AddressOutOfBoundsException e) {
                        match = false;
                    }
                }
                
                if (match) {
                    System.out.printf("AES S-box found at 0x%s\n", addr);
                    // Create data type and label
                    createLabel(addr, "aes_sbox", true);
                }
                
                addr = find(addr.add(1), pattern);
            }
        }
    }
}
```

**Python scripting** (via Ghidra's Jython bridge):

```python
# Ghidra Python script: FunctionAnalysis.py
# @category Analysis

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import RefType

def analyze_function(func):
    """Analyze a single function and report metrics."""
    body = func.getBody()
    num_instructions = 0
    num_calls = 0
    num_branches = 0
    complexity = 0
    
    listing = currentProgram.getListing()
    inst_iter = listing.getInstructions(body, True)
    
    while inst_iter.hasNext():
        inst = inst_iter.next()
        num_instructions += 1
        
        flow_type = inst.getFlowType()
        if flow_type.isCall():
            num_calls += 1
        if flow_type.isJump():
            num_branches += 1
    
    # McCabe cyclomatic complexity approximation
    complexity = num_branches + 1
    
    return {
        'name': func.getName(),
        'address': func.getEntryPoint(),
        'size': body.getNumAddresses(),
        'instructions': num_instructions,
        'calls': num_calls,
        'branches': num_branches,
        'complexity': complexity
    }

def find_high_complexity_functions():
    """Find functions with high complexity — likely important."""
    func_mgr = currentProgram.getFunctionManager()
    results = []
    
    for func in func_mgr.getFunctions(True):
        info = analyze_function(func)
        if info['complexity'] > 10:
            results.append(info)
            print(f"HIGH COMPLEXITY: {info['name']} at 0x{info['address']} "
                  f"(complexity={info['complexity']})")
    
    # Sort by complexity
    results.sort(key=lambda x: x['complexity'], reverse=True)
    return results

high_complexity = find_high_complexity_functions()
```

### 3.3 Ghidra Collaboration

Ghidra supports Git-based project sharing:

```bash
# Create shared Ghidra project
# 1. File → New Project → "Shared Project"
# 2. Configure Git repository:
#    - Server: Local or remote Git server
#    - Repository: ghidra-projects
#    - Project name: target-analysis

# 3. Team workflow:
#    - Checkout file for editing
#    - Make analysis changes
#    - Check in file with version comment
#    - Other analysts see updated version

# Ghidra Server (alternative to Git)
# Install: java -jar ghidra_x.x/server/server.conf
# Start:   ./ghidraRun.sh -server
# Connect: File → New Project → Shared Project → Server URL
```

---

## 4. radare2/rizin Analysis Pipeline

### 4.1 radare2 Overview

radare2 (r2) is a free, portable, and feature-rich RE framework. rizin is a fork that maintains cleaner code:

```bash
# Basic r2/rizin workflow
r2 -A target_binary              # Open with auto-analysis
# Or with rizin:
rizin -A target_binary

# Key r2 commands:
aaa            # Analyze all (thorough analysis)
afl            # List all functions
aflc           # Count functions
axt <addr>     # Cross-references to address
axf <addr>     # Cross-references from address
pdf @ <addr>   # Disassemble function
VV             # Visual mode (graph view)
VVV            # Visual mode (full screen graph)
Vp             # Visual mode (pannels)
iz             # List strings in data sections
izz            # List all strings
ii             # List imports
iE             # List exports
is             # List symbols
ic             # List classes (C++/ObjC)
iS             # List sections
iS-            # List sections with entropy
ie             # List entry points
```

### 4.2 r2pipe for Automation

```python
#!/usr/bin/env python3
"""r2pipe automation script for binary analysis."""

import r2pipe
import json

def analyze_binary(filepath):
    r2 = r2pipe.open(filepath)
    
    # Run initial analysis
    r2.cmd("aaa")
    
    # Get binary info
    info = json.loads(r2.cmd("ij"))
    print(f"Architecture: {info['bin']['arch']}")
    print(f"Bits: {info['bin']['bits']}")
    print(f"Type: {info['bin']['type']}")
    print(f"Endian: {info['bin']['endian']}")
    
    # Get function list
    functions = json.loads(r2.cmd("aflj"))
    print(f"\nTotal functions: {len(functions)}")
    
    # Analyze each function
    for func in functions[:10]:  # First 10 functions
        name = func['name']
        offset = func['offset']
        size = func['size']
        
        # Get function complexity
        r2.cmd(f"s {offset}")
        complexity = r2.cmd("afbc").strip()  # Basic block count
        
        print(f"\n{name} @ 0x{offset:x} (size={size}, blocks={complexity})")
    
    # Extract strings
    strings = json.loads(r2.cmd("izzj"))
    interesting_strings = []
    for s in strings:
        string = s['string']
        if any(kw in string.lower() for kw in ['http', 'password', 'key', 'encrypt', 'decrypt', 'flag', 'cmd']):
            interesting_strings.append(string)
    
    print(f"\nInteresting strings ({len(interesting_strings)}):")
    for s in interesting_strings[:20]:
        print(f"  {s}")
    
    # Get imports
    imports = json.loads(r2.cmd("iij"))
    print(f"\nImports ({len(imports)}):")
    for imp in imports[:20]:
        print(f"  {imp.get('name', 'ordinal')} @ 0x{imp.get('plt', 0):x}")
    
    r2.quit()

if __name__ == '__main__':
    import sys
    analyze_binary(sys.argv[1])
```

### 4.3 r2 Scripting with r2pipe and R2-Jupyter

```python
# Advanced r2pipe analysis: identify crypto usage
import r2pipe
import json

def find_crypto_patterns(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")
    
    # Search for crypto constants
    patterns = {
        'AES_SBOX': ['63 7c 77 7b f2 6b 6f c5'],           # AES S-box
        'MD5_INIT': ['67452301 efcdab89 98badcfe 10325476'], # MD5 constants
        'SHA1_INIT': ['67452301 efcdab89 98badcfe 10325476 c3d2e1f0'],  # SHA-1
        'SHA256_K': ['428a2f98 71374491 b5c0fbcf e9b5dba5'], # SHA-256 K[0-3]
    }
    
    for name, pattern_list in patterns.items():
        for pattern in pattern_list:
            result = r2.cmd(f"/x {pattern}")
            if result.strip():
                print(f"[FOUND] {name} at: {result.strip()}")
                # Add comment at found address
                addr = result.strip().split()[0]
                r2.cmd(f"CC {name} @ {addr}")
    
    # Find crypto API calls
    crypto_apis = [
        'AES_set_encrypt_key', 'AES_encrypt', 'AES_decrypt',
        'EVP_EncryptInit', 'EVP_EncryptUpdate', 'EVP_EncryptFinal',
        'RSA_public_encrypt', 'RSA_private_decrypt',
        'RC4_set_key', 'RC4',
        'DES_set_key', 'DES_encrypt',
        'MD5_Init', 'MD5_Update', 'MD5_Final',
        'SHA1_Init', 'SHA256_Init',
        'CryptEncrypt', 'CryptDecrypt',           # Windows CryptoAPI
        'BCryptEncrypt', 'BCryptDecrypt',          # Windows CNG
    ]
    
    imports = json.loads(r2.cmd("iij"))
    for imp in imports:
        name = imp.get('name', '')
        if any(api in name for api in crypto_apis):
            print(f"[CRYPTO IMPORT] {name} @ 0x{imp.get('plt', 0):x}")
    
    r2.quit()
```

---

## 5. Binary Ninja IL-Based Analysis

### 5.1 Binary Ninja Architecture

Binary Ninja uses a layered Intermediate Language (IL) approach:

```
Binary Ninja IL Stack:
┌─────────────────┐
│   High Level IL  │  ← C-like statements, if/else, loops
│   (HLIL)        │     Structs, functions, type info
├─────────────────┤
│ Medium Level IL  │  ← Operations on variables (not registers)
│   (MLIL)        │     Function calls, conditions
├─────────────────┤
┌─────────────────┐
│   Low Level IL   │  ← Register-based operations
│   (LLIL)        │     Similar to disassembly but normalized
├─────────────────┤
│ Disassembly      │  ← Raw assembly
│   (Architecture- │     Architecture-specific
│    specific)    │
└─────────────────┘
```

### 5.2 Binary Ninja Python API

```python
# Binary Ninja Python API script
import binaryninja

def analyze_binary(bv):
    """Comprehensive analysis using Binary Ninja API."""
    
    print(f"Binary: {bv.file.filename}")
    print(f"Architecture: {bv.arch.name}")
    print(f"Platform: {bv.platform.name}")
    print(f"Entry point: 0x{bv.start:x}")
    
    # List all functions
    for func in bv.functions:
        if func.symbol:
            name = func.symbol.name
        else:
            name = f"sub_{func.start:x}"
        
        print(f"\n{name} @ 0x{func.start:x}")
        
        # Analyze HLIL (high-level IL)
        if func.hlil:
            for il in func.hlil.instructions:
                # Find interesting patterns
                if 'call' in str(il):
                    # Track function calls
                    pass
    
    # Search for crypto constants
    aes_sbox_bytes = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
    results = bv.find_data(aes_sbox_bytes)
    if results:
        print(f"\n[!] AES S-box found at: {[hex(r) for r in results]}")

# Run analysis
bv = binaryninja.open_view("/path/to/binary")
analyze_binary(bv)
```

---

## 6. Pattern Matching & Function Identification

### 6.1 FLIRT (Fast Library Identification and Recognition Technology)

FLIRT is IDA Pro's signature matching system. It creates pattern databases for known library functions so they can be automatically identified in stripped binaries:

```
FLIRT Pattern Generation Process:

1. Build library from source with known compiler flags
   $ gcc -O2 -c libcrypto.a

2. Generate signatures using sigmake
   $ sigmake -n"OpenSSL 1.1.1" libcrypto.a crypto.pat
   $ sigmake crypto.pat crypto.sig

3. Apply signatures in IDA
   File → Load File → FLIRT Signature File

4. IDA matches patterns against functions in the binary
   - Matched functions are automatically labeled (e.g., "AES_encrypt")
   - Remaining functions are more likely custom/application code
```

Creating custom FLIRT signatures:

```bash
# Step 1: Create a pattern file from a library
# Build the library with known settings
gcc -O2 -c mylib.c -o mylib.o
ar rcs libmylib.a mylib.o

# Step 2: Generate FLIRT patterns
# Using IDA's sigmake tool:
sigmake -n"MyLib v1.0" libmylib.a mylib.pat
# This creates a .pat file with function patterns

# Step 3: Convert to signature file
sigmake mylib.pat mylib.sig
# This creates a .sig file that IDA can load

# Step 4: Install the signature
# Copy mylib.sig to IDA's sig/ directory
cp mylib.sig /path/to/ida/sig/

# Step 5: Apply in IDA
# File → Load File → FLIRT Signature File → select mylib.sig
```

### 6.2 Library Identification Without FLIRT

```python
# Identify library functions by constants, strings, and patterns
import hashlib

def compute_function_hash(binary_data, func_offset, func_size):
    """Compute a hash of function bytes for identification."""
    func_bytes = binary_data[func_offset:func_offset + func_size]
    # Normalize: replace relative offsets with zeros for relocation-independent matching
    normalized = bytearray(func_bytes)
    # This is a simplified approach; real FLIRT does more sophisticated normalization
    return hashlib.md5(normalized).hexdigest()

# Common crypto function identification by constants
CRYPTO_CONSTANTS = {
    'AES_SBOX': bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                       0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
    'MD5_INIT_A': 0x67452301,
    'MD5_INIT_B': 0xEFCDAB89,
    'MD5_INIT_C': 0x98BADCFE,
    'MD5_INIT_D': 0x10325476,
    'SHA1_H0': 0x67452301,
    'SHA1_H1': 0xEFCDAB89,
    'SHA256_K0': 0x428A2F98,
    'CRC32_TABLE': bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]),
}

def identify_crypto_functions(binary_data):
    """Search for crypto algorithm implementations by their constants."""
    findings = []
    
    for name, pattern in CRYPTO_CONSTANTS.items():
        if isinstance(pattern, bytes):
            offset = binary_data.find(pattern)
            while offset != -1:
                findings.append({
                    'type': 'constant',
                    'name': name,
                    'offset': offset,
                })
                offset = binary_data.find(pattern, offset + 1)
        elif isinstance(pattern, int):
            # Search for 32-bit little-endian integer
            pattern_bytes = pattern.to_bytes(4, 'little')
            offset = binary_data.find(pattern_bytes)
            while offset != -1:
                findings.append({
                    'type': 'constant',
                    'name': name,
                    'offset': offset,
                })
                offset = binary_data.find(pattern_bytes, offset + 1)
    
    return findings
```

---

## 7. Cross-Reference Analysis

Cross-references (xrefs) are the most powerful navigation tool in static analysis. They tell you where data is accessed and where code is called.

### 7.1 Types of Cross-References

```
Code Cross-References:
  - Call references: function A calls function B
  - Jump references: code at address X jumps to address Y
  - Fall-through: sequential code flow (implicit xref)

Data Cross-References:
  - Read references: code reads data at address Z
  - Write references: code writes data at address Z
  - Address references: code takes the address of data at Z (lea, &)
```

```python
# IDAPython: Comprehensive cross-reference analysis
import idautils
import idc

def analyze_xrefs(ea):
    """Analyze all cross-references to and from an address."""
    print(f"\n=== Cross-References for 0x{ea:x} ({idc.get_name(ea, idc.GN_VISIBLE)}) ===")
    
    # References TO this address
    print("\nReferences TO:")
    for xref in idautils.XrefsTo(ea, 0):
        xref_type = {
            idautils.XREF_CALL: "Call",
            idautils.XREF_JUMP: "Jump",
            1: "Data Read",
            2: "Data Write",
        }.get(xref.type, f"Type {xref.type}")
        print(f"  0x{xref.frm:x} ({idc.get_func_name(xref.frm)}) → {xref_type}")
    
    # References FROM this address
    print("\nReferences FROM:")
    for xref in idautils.XrefsFrom(ea, 0):
        xref_type = {
            idautils.XREF_CALL: "Call",
            idautils.XREF_JUMP: "Jump",
            1: "Data Read",
            2: "Data Write",
        }.get(xref.type, f"Type {xref.type}")
        print(f"  {xref_type} → 0x{xref.to:x} ({idc.get_name(xref.to, idc.GN_VISIBLE)})")

def find_interesting_xrefs():
    """Find functions that are called from many places (likely important)."""
    call_counts = {}
    
    for func_ea in idautils.Functions():
        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.type in (idautils.XREF_CALL, 17, 16):  # Call references
                call_counts[func_ea] = call_counts.get(func_ea, 0) + 1
    
    # Sort by call count (most-called functions first)
    sorted_funcs = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)
    
    print("\n=== Most-Called Functions ===")
    for func_ea, count in sorted_funcs[:20]:
        name = idc.get_func_name(func_ea)
        print(f"  {name:40s} called {count} times")

find_interesting_xrefs()
```

### 7.2 Call Graph Construction

```python
# Build a call graph from cross-references
import idautils
import idc
from collections import defaultdict

def build_call_graph():
    """Build a directed call graph of all functions."""
    call_graph = defaultdict(set)  # {caller: set(callees)}
    
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        
        # Get all call references from this function
        for xref in idautils.XrefsFrom(func_ea, 0):
            if xref.type in (17, 16):  # Call references
                callee_func = idaapi.get_func(xref.to)
                if callee_func:
                    callee_name = idc.get_func_name(callee_func.start_ea)
                    call_graph[func_name].add(callee_name)
    
    return call_graph

def find_entry_points(call_graph):
    """Find functions that are not called by any other function (entry points)."""
    all_callees = set()
    for callees in call_graph.values():
        all_callees.update(callees)
    
    all_callers = set(call_graph.keys())
    entry_points = all_callers - all_callees
    
    print("=== Entry Point Functions ===")
    for ep in sorted(entry_points):
        print(f"  {ep}")
    
    return entry_points

call_graph = build_call_graph()
entry_points = find_entry_points(call_graph)
```

---

## 8. Data Flow Static Analysis

### 8.1 Taint Analysis

Static taint analysis tracks how data flows through a program without executing it:

```python
# Simplified static taint analysis in IDAPython
import idaapi
import idautils
import idc

def taint_forward(ea, max_depth=50):
    """Forward taint analysis: track where data from address ea flows."""
    visited = set()
    worklist = [(ea, 0)]
    tainted = set()
    
    while worklist and len(tainted) < 1000:
        current_ea, depth = worklist.pop(0)
        
        if current_ea in visited or depth > max_depth:
            continue
        
        visited.add(current_ea)
        func = idaapi.get_func(current_ea)
        if not func:
            continue
        
        # Get instruction at current address
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, current_ea)
        if length == 0:
            continue
        
        # Track data flow through registers and memory
        mnem = insn.get_canon_mnemonic()
        
        # If this is a MOV instruction, track the propagation
        if mnem in ('mov', 'lea'):
            op0 = insn.ops[0]  # Destination
            op1 = insn.ops[1]  # Source
            tainted.add(current_ea)
        
        # Follow xrefs forward
        for xref in idautils.XrefsFrom(current_ea, 0):
            if xref.type in (17, 16):  # Code references
                worklist.append((xref.to, depth + 1))
    
    return tainted

# Track user input from recv() calls
for xref in idautils.XrefsTo(idc.get_name_ea_simple("recv"), 0):
    tainted_addresses = taint_forward(xref.frm)
    print(f"Taint from recv() call at 0x{xref.frm:x}: {len(tainted_addresses)} tainted addresses")
```

### 8.2 Value Set Analysis

Value set analysis tracks possible values of variables at each program point:

```python
# Simplified value set analysis using Binary Ninja's MLIL
import binaryninja as bn

def value_set_analysis(bv, func):
    """Analyze possible value ranges for variables in a function."""
    mlil = func.mlil
    if not mlil:
        return {}
    
    variable_values = {}
    
    for block in mlil:
        for il in block:
            # Track constant assignments
            if il.operation == bn.MediumLevelILOperation.MLIL_VAR_STORE:
                src = il.src
                if src.operation == bn.MediumLevelILOperation.MLIL_CONST:
                    var = il.dest
                    value = src.constant
                    if var not in variable_values:
                        variable_values[var] = set()
                    variable_values[var].add(value)
    
    return variable_values
```

---

## 9. Symbol Recovery

### 9.1 Techniques for Recovering Symbol Information

When binaries are stripped, symbol recovery becomes essential:

```python
# Multiple techniques for symbol recovery in stripped binaries

# Technique 1: Format string recovery
# printf-style format strings reveal function prototypes
import re

def recover_from_format_strings(binary_data):
    """Recover function signatures from format strings."""
    format_strings = re.findall(rb'("%[^"]{3,}")', binary_data)
    
    for fmt in format_strings:
        fmt_str = fmt.decode('utf-8', errors='replace')
        # Count format specifiers
        specifiers = re.findall(r'%[0-9]*[lhqL]?[diuoxXfFeEgGaAcspn%]', fmt_str)
        
        # Infer parameter types
        params = []
        for spec in specifiers:
            if spec[-1] in 'diu':
                params.append('int')
            elif spec[-1] in 'xXo':
                params.append('unsigned int')
            elif spec[-1] in 'fFeEgGaA':
                params.append('double')
            elif spec[-1] == 's':
                params.append('const char *')
            elif spec[-1] == 'p':
                params.append('void *')
            elif spec[-1] == 'c':
                params.append('char')
        
        print(f"Format: {fmt_str}")
        print(f"  Inferred params: {', '.join(params)}")

# Technique 2: PLT/GOT analysis for imported function identification
def recover_from_plt(binary_data, base=0):
    """Recover function names from PLT stubs in stripped ELF binaries."""
    # In ELF, even stripped binaries have .dynsym with imported symbol names
    # PLT entries jump through GOT which points to .dynsym entries
    
    # Find .dynstr and .dynsym sections
    # (simplified — in practice use proper ELF parsing)
    pass

# Technique 3: RTTI/vtable recovery (C++ binaries)
def recover_from_rtti(binary_data):
    """Recover C++ class names from RTTI information."""
    # Look for RTTI typeinfo structures
    # GCC: vtable starts with 0, 0, typeinfo_pointer
    # MSVC: vtable starts with typeinfo_pointer
    rtti_pattern = rb'typeinfo name for '
    offset = binary_data.find(rtti_pattern)
    while offset != -1:
        print(f"RTTI at 0x{offset:x}")
        offset = binary_data.find(rtti_pattern, offset + 1)
    
    # Also look for vtable demangled names
    # __ZTS prefix for GCC RTTI name symbols
    # .?AV prefix for MSVC RTTI
    for prefix in [b'__ZTS', b'.?AV', b'__ZTI']:
        offset = binary_data.find(prefix)
        while offset != -1:
            # Extract the full name string
            end = binary_data.find(b'\x00', offset)
            name = binary_data[offset:end].decode('utf-8', errors='replace')
            print(f"C++ RTTI: {name} at 0x{offset:x}")
            offset = binary_data.find(prefix, offset + 1)
```

### 9.2 Debug Symbol Recovery

```bash
# Recover symbols from separate debug files

# Linux: .debug files and build IDs
# Build ID in ELF header → find matching debug file
readelf -n target_binary | grep "Build ID"
# Search debug file repositories:
#   /usr/lib/debug/.build-id/XX/YYYYYY.debug
#   /usr/lib/debug/usr/lib/
#   /usr/lib/debug/lib/

# Extract debug link
objdump -s -j .gnu_debuglink target_binary

# Windows: PDB files
# .pdb path is stored in the PE debug directory
python3 -c "
import pefile
pe = pefile.PE('target.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        if hasattr(dbg, 'entry') and hasattr(dbg.entry, 'PdbFileName'):
            print(f'PDB: {dbg.entry.PdbFileName.decode()}')
            print(f'Age: {dbg.entry.Age}')
            print(f'GUID: {dbg.entry.Signature}')
"

# Download PDBs from Microsoft symbol servers
# sympd is a tool for managing symbol paths
# symchk /if target.exe /s SRV*C:\symbols*https://msdl.microsoft.com/download/symbols

# Use PDB in IDA/Ghidra
# IDA: File → Load File → PDB file
# Ghidra: File → Import PDB
```

---

## 10. String Analysis

### 10.1 Advanced String Extraction

```bash
# Beyond basic 'strings' command

# Extract ASCII strings with minimum length and offsets
strings -a -n 4 -t x target_binary > strings_ascii.txt

# Extract Unicode strings (common in Windows binaries)
strings -a -e l -n 4 target_binary > strings_unicode.txt

# Extract wide strings (UTF-16LE)
strings -a -e l target_binary > strings_wide.txt

# Search for base64-encoded strings
strings -n 8 target_binary | grep -E '^[A-Za-z0-9+/]{8,}={0,2}$' | while read line; do
    decoded=$(echo "$line" | base64 -d 2>/dev/null)
    if [ $? -eq 0 ] && echo "$decoded" | grep -qE '[\x20-\x7E]{4,}'; then
        echo "BASE64: $line -> $decoded"
    fi
done

# Search for URLs, IPs, domains
strings -n 8 target_binary | grep -iE '(https?://|ftp://|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-z0-9][-a-z0-9]*\.[a-z]{2,6})'
```

### 10.2 Encoded String Decoding

```python
# Decode common string obfuscation techniques

def decode_xor_strings(binary_data, key_sizes=range(1, 5)):
    """Search for XOR-encoded strings by trying common key patterns."""
    results = []
    
    # Common string prefixes to search for
    prefixes = [b'http', b'HTTP', b'GET ', b'POST', b'User', b'Host', b'pass', b'key=', b'cmd=']
    
    for key_size in key_sizes:
        for key in range(256 if key_size == 1 else 0, 256 ** key_size):
            if key_size == 1:
                key_bytes = bytes([key])
            else:
                key_bytes = key.to_bytes(key_size, 'little')
            
            for prefix in prefixes:
                # XOR the prefix with the key
                xor_prefix = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(prefix)])
                
                # Search for the XOR'd prefix
                offset = binary_data.find(xor_prefix)
                while offset != -1:
                    # Decode surrounding bytes
                    start = max(0, offset - 16)
                    end = min(len(binary_data), offset + 256)
                    encoded = binary_data[offset:end]
                    decoded = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encoded)])
                    
                    # Check if decoded result looks like a string
                    try:
                        decoded_str = decoded.decode('ascii', errors='strict')
                        if any(c.isalnum() for c in decoded_str):
                            results.append({
                                'offset': offset,
                                'key': key_bytes.hex(),
                                'decoded': decoded_str[:100]
                            })
                    except UnicodeDecodeError:
                        pass
                    
                    offset = binary_data.find(xor_prefix, offset + 1)
    
    return results
```

### 10.3 String-Based Behavioral Profiling

```python
# String-based behavioral profiling
import re

BEHAVIORAL_PATTERNS = {
    'network_communication': [
        r'(?:https?|ftp)://[^\x00]+',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,6}',
        r'(?:socket|connect|bind|listen|accept|recv|send|WSAStartup)',
    ],
    'file_operations': [
        r'(?:CreateFile|ReadFile|WriteFile|DeleteFile|MoveFile|CopyFile)[AW]?',
        r'(?:open|fopen|fread|fwrite|fclose|unlink|rename|mkdir|rmdir)',
        r'[A-Za-z]:\\[^\x00]+',  # Windows paths
        r'/usr/[^\x00]+',           # Unix paths
        r'/etc/[^\x00]+',           # Config paths
        r'/tmp/[^\x00]+',           # Temp paths
    ],
    'registry_operations': [
        r'HKEY_[A-Z_]+\\[^\x00]+',  # Registry keys
        r'Reg(?:Open|Set|Query|Delete)Key[AW]?',
        r'Reg(?:Get|Set)Value[AW]?',
    ],
    'crypto_operations': [
        r'(?:AES|DES|RSA|MD5|SHA[0-9]*|HMAC|RC4|Chacha)',
        r'(?:CryptEncrypt|CryptDecrypt|CryptDeriveKey|BCryptEncrypt)',
        r'(?:EVP_|BIO_|PEM_|X509_)',  # OpenSSL functions
    ],
    'process_operations': [
        r'(?:CreateProcess|ShellExecute|WinExec|system|exec[lv]p?e?)',
        r'(?:cmd\.exe|/bin/sh|/bin/bash|powershell)',
        r'(?:NtCreateProcess|RtlCreateUserProcess)',
    ],
    'anti_analysis': [
        r'(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)',
        r'(?:VirtualProtect|VirtualAlloc|NtProtectVirtualMemory)',
        r'(?:OutputDebugString|GetTickCount|QueryPerformanceCounter)',
        r'(?:VMware|VirtualBox|VBOX|QEMU|Sandboxie)',
    ],
}

def profile_binary_behavior(strings_file, binary_data):
    """Profile binary behavior based on string patterns."""
    profile = {}
    
    for category, patterns in BEHAVIORAL_PATTERNS.items():
        matches = []
        for pattern in patterns:
            for match in re.finditer(pattern.encode(), binary_data):
                matches.append({
                    'offset': match.start(),
                    'match': match.group().decode('utf-8', errors='replace')[:80]
                })
        
        if matches:
            profile[category] = matches
    
    # Print behavioral summary
    print("=== Behavioral Profile ===")
    for category, matches in profile.items():
        print(f"\n{category.upper()}:")
        for m in matches[:10]:
            print(f"  0x{m['offset']:08x}: {m['match']}")
    
    return profile
```

---

## 11. Entropy Analysis for Packed Binaries

### 11.1 Entropy Calculation and Interpretation

```python
import math
from collections import Counter

def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) 
                   for count in counter.values())
    return entropy

def analyze_section_entropy(binary_data, sections):
    """Analyze entropy of each section to detect packing/encryption."""
    print("\n=== Section Entropy Analysis ===")
    print(f"{'Section':<20} {'Entropy':>8} {'Assessment':<20}")
    print("-" * 50)
    
    for name, offset, size in sections:
        section_data = binary_data[offset:offset + size]
        if not section_data:
            continue
        
        entropy = calculate_entropy(section_data)
        
        if entropy > 7.5:
            assessment = "LIKELY ENCRYPTED/PACKED"
        elif entropy > 7.0:
            assessment = "POSSIBLY COMPRESSED"
        elif entropy > 6.0:
            assessment = "MODERATE (normal code)"
        elif entropy > 5.0:
            assessment = "MODERATE (mixed data)"
        elif entropy > 3.0:
            assessment = "LOW (sparse data)"
        else:
            assessment = "VERY LOW (mostly null)"
        
        print(f"{name:<20} {entropy:>8.4f} {assessment:<20}")

def detect_packing(binary_data):
    """Detect common packing indicators."""
    indicators = []
    
    # Check 1: High overall entropy
    overall_entropy = calculate_entropy(binary_data)
    if overall_entropy > 7.0:
        indicators.append(f"High overall entropy: {overall_entropy:.4f}")
    
    # Check 2: Few sections with one very large
    # (packers often have 1-3 sections)
    
    # Check 3: Section names
    packer_sections = ['.upx', '. UPX', 'UPX0', 'UPX1', '.MPRESS1', '.MPRESS2',
                       '.nsp0', '.nsp1', '.petite', '._winzip_',
                       '.enigma1', '.enigma2', '.vmp0', '.vmp1']
    
    # Check 4: Entry point outside .text section
    # Check 5: Imports from only kernel32.dll (packer stub)
    # Check 6: Raw size much smaller than virtual size
    
    return indicators
```

### 11.2 Entropy Visualization

```bash
# Generate entropy visualization with binwalk
binwalk -E target_binary

# Or with a custom Python script
python3 << 'EOF'
import sys, struct, math
from collections import Counter

def entropy(data, block_size=256):
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        counter = Counter(block)
        length = len(block)
        ent = -sum((c/length) * math.log2(c/length) for c in counter.values() if c > 0)
        results.append((i, ent))
    return results

with open(sys.argv[1], 'rb') as f:
    data = f.read()

entropy_data = entropy(data, block_size=256)

# Generate simple ASCII bar chart
max_len = 60
print("Offset      Entropy  Bar")
print("-" * 80)
for offset, ent in entropy_data[:50]:  # First 50 blocks
    bar_len = int(ent / 8.0 * max_len)
    bar = '#' * bar_len + '-' * (max_len - bar_len)
    print(f"0x{offset:08x}  {ent:.4f}  {bar}")
EOF
```

---

## 12. YARA Rules for Classification

### 12.1 YARA Rule Development

YARA is the de facto standard for binary pattern matching and classification:

```yaml
# YARA rules for malware family identification

rule Crypto_Miner_Generic {
    meta:
        description = "Detects cryptocurrency mining software"
        author = "RE Track"
        severity = "high"
        
    strings:
        $s1 = "stratum+tcp://" nocase wide
        $s2 = "stratum+ssl://" nocase wide
        $s3 = "--pool" nocase
        $s4 = "--wallet" nocase
        $s5 = "xmrig" nocase
        $s6 = "cryptonight" nocase
        $s7 = "monero" nocase
        $s8 = "donate.gratis" nocase
        
        $crypto_xor1 = { (66 66 66 66 66 66 66 66) xor(0x55) } # XOR-decoded https://
        
    condition:
        uint16(0) == 0x5A4D or uint16(0) == 0x457F and
        filesize > 100KB and filesize < 50MB and
        (2 of ($s1, $s2, $s3, $s4) or 1 of ($s5, $s6, $s7, $s8) or $crypto_xor1)
}

rule Packer_UPX {
    meta:
        description = "UPX packed binary"
        author = "RE Track"
        
    strings:
        $upx0 = "UPX0" ascii wide
        $upx1 = "UPX1" ascii wide
        $upx2 = ".UPX" ascii wide
        $sig1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? }  # Common UPX stub
        
    condition:
        any of them
}

rule Packer_VMProtect {
    meta:
        description = "VMProtect protected binary"
        author = "RE Track"
        
    strings:
        $vmp0 = ".vmp0" ascii wide
        $vmp1 = ".vmp1" ascii wide
        $sig_vmp = { E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }  # VMP call pattern
        
    condition:
        any of them
}

rule Ransomware_Generic {
    meta:
        description = "Generic ransomware indicators"
        author = "RE Track"
        severity = "critical"
        
    strings:
        $ransom_note1 = "your files have been encrypted" nocase wide
        $ransom_note2 = "decrypt your files" nocase wide
        $ransom_note3 = "pay the ransom" nocase wide
        $ransom_note4 = "bitcoin" nocase wide
        $ransom_note5 = "restore your data" nocase wide
        
        $ext_list1 = ".locked" wide
        $ext_list2 = ".encrypted" wide  
        $ext_list3 = ".crypt" wide
        $ext_list4 = ".enc" wide
        
        $crypto1 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }  # AES S-box
        $crypto2 = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }  # MD5 init
        
        $vss_delete = "vssadmin delete shadows" nocase wide
        $wbadmin = "wbadmin delete catalog" nocase wide
        $bcdedit = "bcdedit /set {default} recoveryenabled No" nocase wide
        
    condition:
        (1 of ($ransom_note1, $ransom_note2, $ransom_note3) and 1 of ($ext_list1, $ext_list2, $ext_list3, $ext_list4)) or
        (1 of ($vss_delete, $wbadmin, $bcdedit) and 1 of ($crypto1, $crypto2)) or
        (2 of ($ransom_note1, $ransom_note2, $ransom_note3, $ransom_note4, $ransom_note5) and 1 of ($crypto1, $crypto2))
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Cobalt Strike Beacon payload"
        author = "RE Track"
        severity = "critical"
        
    strings:
        $jitter = "%%d" ascii
        $mask = { 48 8B ?? E8 ?? ?? ?? ?? 48 85 ?? 74 ?? 48 8B ?? 48 8B ?? FF }  # Beacon pattern
        $meta = { 4D 5F 46 52 45 45 }  # "M_FREE" pattern
        
    condition:
        uint16(0) == 0x5A4D and
        filesize > 200KB and filesize < 500KB and
        1 of them
}

rule Anti_Debug_Techniques {
    meta:
        description = "Binary with anti-debugging techniques"
        author = "RE Track"
        
    strings:
        $api1 = "IsDebuggerPresent" ascii wide nocase
        $api2 = "CheckRemoteDebuggerPresent" ascii wide nocase
        $api3 = "NtQueryInformationProcess" ascii wide nocase
        $api4 = "OutputDebugString" ascii wide nocase
        $api5 = "GetTickCount" ascii wide nocase
        $api6 = "QueryPerformanceCounter" ascii wide nocase
        $api7 = "ZwQuerySystemInformation" ascii wide nocase
        $api8 = "FindWindowA" ascii wide nocase
        
        $anti1 = { 64 FF 35 00 00 00 00 }  # FS:[0] (PEB access)
        $anti2 = { 64 A1 30 00 00 00 }      # mov eax, fs:[30] (PEB.BeingDebugged)
        $anti3 = { 0F B6 40 02 }            # movzx eax, [eax+2] (read BeingDebugged)
        $anti4 = { EB FE }                  # jmp $ (infinite loop, timing check)
        $anti5 = { CC } xor(0x00)           # INT3 detection
        
    condition:
        2 of ($api1, $api2, $api3, $api4, $api5, $api6, $api7, $api8) or
        1 of ($anti1, $anti2, $anti3, $anti4)
}
```

### 12.2 Fuzzy Hashing for Similarity

```bash
# ssdeep — context-triggered piecewise hashing
ssdeep -b target_binary
# Output: hash,filename

# Compare two binaries
ssdeep -b -c target1 target2

# Import into malware analysis pipeline
# ssdeep hashes can be stored in databases for rapid lookup

# tlsh — Trend Micro Locality Sensitive Hash
# Better for malware similarity than ssdeep
import tlsh
with open('target_binary', 'rb') as f:
    data = f.read()
h = tlsh.hash(data)
print(f"TLSH: {h}")

# Compare TLSH hashes (lower distance = more similar)
# tlsh.diff(h1, h2)
```

> **Cross-reference**: See [02b_dynamic_analysis.md](02b_dynamic_analysis.md) for dynamic analysis techniques that complement static analysis. See [03a_malware_analysis.md](03a_malware_analysis.md) for malware-specific static analysis patterns. See [04b_anti_tamper_obfuscation.md](04b_anti_tamper_obfuscation.md) for anti-analysis techniques and bypasses. See [06_re_tooling_workflow.md](06_re_tooling_workflow.md) for comprehensive tool setup and configuration.

---

*This document is part of the Deep Researcher Reverse Engineering track. Static analysis is the foundation upon which all deeper analysis is built.*

## References

1. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
2. Ghidra documentation, https://ghidra-sre.org/
3. radare2 documentation, https://rada.re/n/
4. Binary Ninja documentation, https://docs.binary.ninja/
5. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
6. Michael Sikorski & Andrew Honig, "Practical Malware Analysis," No Starch Press, 2012.
7. YARA documentation, https://virustotal.github.io/yara/
8. FLIRT signatures, https://hex-rays.com/products/ida/tech/flirt/
9. Dennis Yurichev, "Reverse Engineering for Beginners," https://begin.reversing.info/
10. Eldad Eilam, "Reversing: Secrets of Reverse Engineering," Wiley, 2005.