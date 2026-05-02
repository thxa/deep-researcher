# RE Tooling & Workflow

> Complete guide to setting up, configuring, and integrating reverse engineering tools; scripting automation; collaborative RE; and lab environment design.

---

## Table of Contents

1. [Complete Tool Chain Setup](#1-complete-tool-chain-setup)
2. [IDA Pro: Advanced Configuration](#2-ida-pro-advanced-configuration)
3. [Ghidra: Advanced Workflow](#3-ghidra-advanced-workflow)
4. [radare2/rizin Pipeline](#4-radare2rizin-pipeline)
5. [Binary Ninja Integration](#5-binary-ninja-integration)
6. [Dynamic Analysis Toolkit](#6-dynamic-analysis-toolkit)
7. [Collaborative RE Analysis](#7-collaborative-re-analysis)
8. [Scripting & Automation](#8-scripting--automation)
9. [LLM-Assisted RE](#9-llm-assisted-re)
10. [Binary Comparison: Diaphora & BinDiff](#10-binary-comparison-diaphora--bindiff)
11. [Lab Setup Recommendations](#11-lab-setup-recommendations)

---

## 1. Complete Tool Chain Setup

### 1.1 Essential RE Tool Stack

```bash
# === Static Analysis ===
# IDA Pro (commercial)
# Download from: https://hex-rays.com/IDA-Pro/
# License: $500+ (Free version available for non-commercial)

# Ghidra (free, open source)
# Install: https://github.com/NationalSecurityAgency/ghidra
sudo apt install openjdk-17-jdk
wget https://github.com/NationalSecurityAgency/ghidra/releases/latest/download/ghidra_*.zip
unzip ghidra_*.zip -d /opt/ghidra

# radare2 (free, open source)
git clone https://github.com/radareorg/radare2.git
cd radare2 && sys/install.sh

# rizin (radare2 fork)
git clone https://github.com/rizinorg/rizin.git
cd rizin && meson build && ninja -C build install

# Binary Ninja (commercial)
# Download from: https://binary.ninja/

# === Dynamic Analysis ===
# GDB with GEF/pwndbg
sudo apt install gdb
# GEF:
wget -qO- https://github.com/hugsy/gef/raw/main/scripts/gef.sh | sh
# Or pwndbg:
git clone https://github.com/pwndbg/pwndbg.git && cd pwndbg && ./setup.sh

# WinDBG (Windows)
# Download from: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/

# x64dbg (Windows)
# Download from: https://x64dbg.com/

# Frida (dynamic instrumentation)
pip install frida-tools frida

# === Binary Analysis Utilities ===
# binwalk (firmware extraction)
sudo apt install binwalk

# file, strings, objdump, readelf (standard Linux tools)
sudo apt install binutils file

# pefile (Python PE analysis)
pip install pefile

# capstone (disassembly framework)
pip install capstone

# keystone (assembler framework)
pip install keystone-engine

# unicorn (CPU emulator)
pip install unicorn

# angr (binary analysis platform)
pip install angr

# volatility (memory forensics)
pip install volatility3

# YARA (pattern matching)
pip install yara-python

# === Network Analysis ===
# Wireshark
sudo apt install wireshark

# tcpdump
sudo apt install tcpdump

# mitmproxy
pip install mitmproxy

# can-utils (automotive)
sudo apt install can-utils

# === Crypto ===
# PyCryptodome (crypto library)
pip install pycryptodome

# HashDB (crypto hash database)
# https://hashdb.openanalysis.net/

# === Package Management ===
# pipx for isolated tool installation
pip install pipx
pipx install r2pipe
pipx install ropper
pipx install ROPgadget
pipx install one_gadget
```

---

## 2. IDA Pro: Advanced Configuration

### 2.1 IDA Pro Plugins and Scripts

```python
# Essential IDA Pro plugins and configurations

# Plugin: Ghidra Decompiler for IDA (bridge between IDA and Ghidra decompiler)
# Download: https://github.com/nikitalytyuk/ghidra-decompiler-ida-plugin

# Plugin: LazyIDA (workflow improvements)
# Download: https://github.com/L4ys/LazyIDA

# Plugin: Keypatch (assembler patching)
# Download: https://github.com/keystone-engine/keypatch

# Plugin: ida-signsrch (signature search for crypto constants)
# Download: https://github.com/nihilus/idt_signsrch

# Plugin: FindCrypt (find crypto constants)
# Download: https://github.com/polymorf/findcrypt-yara

# Plugin: D-810 (deobfuscation)
# Download: https://github.com/seriezhliao/D-810

# Plugin: Diaphora (binary diffing)
# Download: https://github.com/joxeankoret/diaphora

# IDAPython rc file (~/.idapyrc.py or Edit → Scripts → Execute script)
# Run at IDA startup for personal configuration

import idaapi
import idautils
import idc

# Set default comments
idaapi.set_segm_comment(idaapi.get_first_seg().start_ea, "Main binary segment")

# Configure disassembly options
# Show operand values in hex by default
idc.set_segm_comment(idc.get_segm_start(0), "Main binary")

# Key IDA configuration settings:
# Options → General → Analysis:
#   - Reanalyze program on startup: Yes (for initial analysis)
#   - Use FLIRT signatures: Yes
#   - Create function tails: Yes
#   - Rename tail bytes: Yes
# Options → General → Cross-references:
#   - Show xref type: Yes
#   - Max xref count: 500 (increase for complex binaries)
# Options → General → Strings:
#   - Default string type: C-style (0-terminated)
#   - Minimum string length: 4
#   - Only ASCII: No (include Unicode)
```

### 2.2 IDAPython Automation Scripts

```python
# Batch decompile all functions and save to files
import ida_hexrays
import idautils
import idc
import os

def decompile_all(output_dir="/tmp/decompiled"):
    """Decompile all functions and save to individual files."""
    os.makedirs(output_dir, exist_ok=True)
    
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        # Sanitize filename
        safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
        
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                with open(os.path.join(output_dir, f"{safe_name}.c"), "w") as f:
                    f.write(str(cfunc))
                print(f"Decompiled: {name}")
        except Exception as e:
            print(f"Failed: {name} @ 0x{func_ea:x}: {e}")

# Find all calls to dangerous functions
def find_dangerous_calls():
    """Find calls to dangerous C library functions."""
    dangerous = {
        'strcpy': 'Buffer overflow (no bounds check)',
        'strcat': 'Buffer overflow (no bounds check)',
        'sprintf': 'Buffer overflow (no bounds check)',
        'gets': 'Buffer overflow (no bounds check)',
        'scanf': 'Buffer overflow (no bounds check)',
        'vsprintf': 'Buffer overflow (no bounds check)',
        'strncpy': 'Potential off-by-one',
        'strncat': 'Potential off-by-one',
        'memcpy': 'Potential overflow if size is user-controlled',
        'malloc': 'Potential integer overflow in size calculation',
        'free': 'Potential double-free or UAF',
    }
    
    print("=== Dangerous Function Calls ===")
    for func_name, risk in dangerous.items():
        ea = idc.get_name_ea_simple(func_name)
        if ea != idc.BADADDR:
            # Find all callers
            for xref in idautils.XrefsTo(ea, 0):
                caller = idc.get_func_name(xref.frm)
                if caller:
                    print(f"  [{risk}] {func_name} called from {caller} @ 0x{xref.frm:x}")

# Rename functions based on string references
def rename_from_strings():
    """Rename functions based on format strings they use."""
    for func_ea in idautils.Functions():
        # Check if function calls printf/sprintf with a string
        for xref in idautils.XrefsFrom(func_ea, 0):
            if xref.type in (17, 16):  # Call reference
                called_name = idc.get_func_name(xref.to)
                if called_name in ('printf', 'sprintf', 'fprintf', 'snprintf'):
                    # Look for string argument
                    prev = idc.prev_head(xref.frm)
                    if prev != idc.BADADDR:
                        op = idc.print_operand(prev, 1)
                        if op and op.startswith('"'):
                            # Extract format string
                            fmt = op.strip('"').split('%')[0].strip()
                            if fmt:
                                new_name = f"func_{fmt[:30].replace(' ', '_')}"
                                idc.set_name(func_ea, new_name, idc.SN_NOWARN)
                                print(f"Renamed 0x{func_ea:x} to {new_name}")
```

---

## 3. Ghidra: Advanced Workflow

### 3.1 Ghidra Project Configuration

```bash
# Ghidra project setup for collaborative analysis

# 1. Create shared project (Git-backed)
# File → New Project → "Shared Project"
# Configure Git repository location

# 2. Set project properties
# Edit → Project Properties → Analysis
# Enable: "Decompiler Parameter ID", "Create Functions", "Reference Parameter ID"

# 3. Configure Ghidra extensions
# File → Install Extensions → Select:
#   - Ghidra.mvc (Model-View-Controller pattern)
#   - Ghidra.python (Python 3 scripting)
#   - Eclipse Integration (for Java development)
```

### 3.2 Ghidra Headless Analysis

```bash
# Ghidra headless analysis for batch processing

# Analyze a binary headlessly
analyzeHeadless /tmp/ghidra_project MyProject \
    -import target_binary \
    -postScript MyAnalysisScript.java \
    -scriptPath /path/to/scripts \
    -readOnly

# Analyze multiple binaries
for binary in binaries/*.exe; do
    analyzeHeadless /tmp/ghidra_project MyProject \
        -import "$binary" \
        -postScript DecompileAll.java \
        -scriptPath /path/to/scripts
done

# Export decompiled output
analyzeHeadless /tmp/ghidra_project MyProject \
    -import target_binary \
    -postScript ExportFunctions.java /tmp/output
```

```java
// Ghidra script: ExportFunctions.java
// @category Export
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.*;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputDir = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/decompiled";
        new File(outputDir).mkdirs();
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        for (Function func : funcMgr.getFunctions(true)) {
            String name = func.getName();
            String safeName = name.replaceAll("[^a-zA-Z0-9._-]", "_");
            
            DecompileResults result = decompiler.decompileFunction(func, 60, monitor);
            if (result.decompiledFunction() != null) {
                String code = result.getDecompiledFunction().getC();
                String filename = outputDir + "/" + safeName + ".c";
                
                try (PrintWriter out = new PrintWriter(filename)) {
                    out.println("// Function: " + name);
                    out.println("// Address: 0x" + Long.toHexString(func.getEntryPoint().getOffset()));
                    out.println("// Size: " + func.getBody().getNumAddresses());
                    out.println();
                    out.println(code);
                }
            }
        }
        
        decompiler.dispose();
        println("Exported " + funcMgr.getFunctionCount() + " functions to " + outputDir);
    }
}
```

---

## 4. radare2/rizin Pipeline

### 4.1 Automated r2 Analysis Pipeline

```bash
# r2 batch analysis pipeline

# Step 1: Initial analysis
r2 -q -e anal.timeout=120 -e anal.hasnext=true -c "aaa; aflc; isq" target_binary

# Step 2: Extract all function information
r2 -q -c "aflj" target_binary > functions.json

# Step 3: Extract strings
r2 -q -c "izzj" target_binary > strings.json

# Step 4: Extract imports/exports
r2 -q -c "iij; iEj" target_binary > imports_exports.json

# Step 5: Extract xrefs
r2 -q -c "axtj @ sym.imp.printf" target_binary > printf_xrefs.json

# Step 6: Batch decompile with r2ghidra
r2 -q -c "aaa; af @ main; pdg @ main" target_binary > main_decompiled.c
```

### 4.2 r2pipe Automation

```python
#!/usr/bin/env python3
"""Automated RE pipeline using r2pipe."""

import r2pipe
import json
import os

def full_analysis(filepath, output_dir):
    """Complete automated analysis pipeline."""
    os.makedirs(output_dir, exist_ok=True)
    
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")  # Full analysis
    
    # 1. Binary info
    info = json.loads(r2.cmd("ij"))
    with open(os.path.join(output_dir, "info.json"), "w") as f:
        json.dump(info, f, indent=2)
    
    # 2. Function list
    functions = json.loads(r2.cmd("aflj"))
    with open(os.path.join(output_dir, "functions.json"), "w") as f:
        json.dump(functions, f, indent=2)
    
    # 3. Strings
    strings = json.loads(r2.cmd("izzj"))
    with open(os.path.join(output_dir, "strings.json"), "w") as f:
        json.dump(strings, f, indent=2)
    
    # 4. Imports
    imports = json.loads(r2.cmd("iij"))
    with open(os.path.join(output_dir, "imports.json"), "w") as f:
        json.dump(imports, f, indent=2)
    
    # 5. Exports
    exports = json.loads(r2.cmd("iEj"))
    with open(os.path.join(output_dir, "exports.json"), "w") as f:
        json.dump(exports, f, indent=2)
    
    # 6. Sections
    sections = json.loads(r2.cmd("iSj"))
    with open(os.path.join(output_dir, "sections.json"), "w") as f:
        json.dump(sections, f, indent=2)
    
    # 7. Crypto constant search
    crypto_constants = r2.cmd("/x 637c777b6f6b4c5a")  # AES S-box start
    with open(os.path.join(output_dir, "crypto_constants.txt"), "w") as f:
        f.write(crypto_constants)
    
    # 8. Batch decompile (requires r2ghidra)
    for func in functions[:20]:  # First 20 functions
        offset = func['offset']
        name = func['name'].replace('.', '_').replace(' ', '_')
        try:
            decompiled = r2.cmd(f"pdg @ {offset}")
            if decompiled and len(decompiled) > 10:
                with open(os.path.join(output_dir, f"{name}.c"), "w") as f:
                    f.write(f"// Function: {func['name']}\n")
                    f.write(f"// Address: 0x{offset:x}\n\n")
                    f.write(decompiled)
        except Exception:
            pass
    
    r2.quit()
    print(f"Analysis complete. Results saved to {output_dir}/")
    return output_dir

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary> [output_dir]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/r2_analysis"
    full_analysis(filepath, output_dir)
```

---

## 5. Binary Ninja Integration

### 5.1 Binary Ninja API

```python
# Binary Ninja automation script
import binaryninja

def full_analysis(filepath):
    """Complete analysis using Binary Ninja API."""
    bv = binaryninja.open_view(filepath)
    if not bv:
        print(f"Failed to open: {filepath}")
        return
    
    # Wait for analysis
    bv.update_analysis_and_wait()
    
    results = {
        'functions': [],
        'strings': [],
        'imports': [],
        'exports': [],
        'sections': [],
    }
    
    # List all functions
    for func in bv.functions:
        results['functions'].append({
            'name': func.symbol.name if func.symbol else f"sub_{func.start:x}",
            'address': hex(func.start),
            'size': func.total_bytes,
            'type': func.type if func.type else 'unknown',
        })
    
    # List strings
    for string in bv.strings:
        results['strings'].append({
            'address': hex(string.start),
            'value': string.value,
            'type': string.type.name if string.type else 'unknown',
        })
    
    # List imports
    for sym in bv.get_symbols_of_type(binaryninja.SymbolType.ImportedFunctionSymbol):
        results['imports'].append({
            'name': sym.name,
            'address': hex(sym.address),
        })
    
    # List exports
    for sym in bv.get_symbols_of_type(binaryninja.SymbolType.FunctionSymbol):
        if sym.address >= bv.start and sym.address < bv.end:
            results['exports'].append({
                'name': sym.name,
                'address': hex(sym.address),
            })
    
    # List sections
    for section in bv.sections:
        results['sections'].append({
            'name': section.name,
            'start': hex(section.start),
            'size': section.length,
        })
    
    bv.file.close()
    return results
```

---

## 6. Dynamic Analysis Toolkit

### 6.1 Windows Dynamic Analysis Setup

```powershell
# Windows RE analysis VM setup (PowerShell)

# Install chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[iNet.ServicePointManager]::SecurityProtocol = [iNet.SecurityProtocolType]::Tls12
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install essential RE tools
choco install -y x64dbg
choco install -y wireshark
choco install -y procmon
choco install -y procexp
choco install -y processhacker
choco install -y pestudio
choco install -y die
choco install -y hashcalc
choco install -y python3
choco install -y vscode

# Install Python packages
pip install pefile yara-python frida-tools capstone unicorn

# Install ScyllaHide (anti-anti-debug for x64dbg)
# Download from: https://github.com/x64dbg/ScyllaHide
# Copy ScyllaHide.x64.dll and ScyllaHide.x32.dll to x64dbg plugins directory

# Install API Monitor
# Download from: http://www.rohitab.com/apimonitor

# FLARE-VM (Mandiant's RE VM)
# Install: https://github.com/mandiant/flare-vm
# Includes IDA Free, Ghidra, x64dbg, Wireshark, YARA, etc.
```

### 6.2 Linux Dynamic Analysis Setup

```bash
# Linux RE analysis environment setup

# Install GDB with GEF
sudo apt install gdb
wget -qO- https://github.com/hugsy/gef/raw/main/scripts/gef.sh | sh

# Install strace, ltrace, and other tracing tools
sudo apt install strace ltrace perf-tools-unstable

# Install Frida
pip install frida-tools

# Install radare2 with plugins
git clone https://github.com/radareorg/radare2.git
cd radare2 && sys/install.sh

# Install angr platform
pip install angr

# Install Volatility (memory forensics)
pip install volatility3

# Set up Python virtual environment for RE
python3 -m venv ~/re_venv
source ~/re_venv/bin/activate
pip install pefile capstone unicorn keystone-engine yara-python
pip install ropper ROPgadget one_gadget
pip install pwntools  # CTF/exploit development framework

# Network analysis tools
sudo apt install wireshark tcpdump nmap netcat-openbsd

# Firmware analysis tools
sudo apt install binwalk firmware-mod-kit
pip install jefferson  # JFFS2 extraction
pip install ubi_reader  # UBI extraction
```

---

## 7. Collaborative RE Analysis

### 7.1 Version Control for RE Projects

```bash
# Git-based collaboration for RE projects

# Project structure:
# re-project/
# ├── README.md              # Project overview
# ├── notes/                 # Analysis notes (Markdown)
# │   ├── 01_triage.md
# │   ├── 02_static_analysis.md
# │   ├── 03_dynamic_analysis.md
# │   └── 04_exploit.md
# ├── scripts/               # Analysis scripts
# │   ├── idapython/
# │   ├── ghidra/
# │   ├── r2/
# │   └── python/
# ├── yara/                  # YARA rules
# │   └── rules/
# ├── idb/                   # IDA database (git-ignored for conflicts)
# ├── ghidra/                # Ghidra project (shared via Git)
# ├── evidence/              # Capture files, dumps (git-ignored, large)
# ├── tools/                 # Tool configurations
# └── reports/               # Final reports

# .gitignore for RE projects
cat > .gitignore << 'EOF'
# Binary databases (use Git LFS for small ones)
*.idb
*.i64
*.id0
*.id1
*.id2
*.nam
*.til

# Large binary files
*.bin
*.exe
*.dll
*.so
*.dylib
*.dmg

# Large evidence files
*.pcap
*.pcapng
*.mem
*.raw
*.dump

# OS files
.DS_Store
Thumbs.db

# IDE files
.idea/
.vscode/
*.swp
EOF

# Git LFS for large files
git lfs install
git lfs track "*.pcap"
git lfs track "*.pcapng"
git lfs track "*.mem"
git lfs track "*.raw"
git lfs track "*.idb"
git lfs track "*.i64"
```

### 7.2 Shared Analysis Projects

```python
# Collaborative RE analysis using shared notes

# Use Markdown for all notes with consistent format:
RE_NOTE_TEMPLATE = '''# [Function/Feature Name]

## Metadata
- **Address**: 0x00401000
- **File**: target_binary.exe
- **Architecture**: x86-64
- **Analyst**: [Name]
- **Date**: [YYYY-MM-DD]

## Purpose
[What this function does]

## Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| arg1 | int | First argument |
| arg2 | char* | String buffer |

## Pseudocode
```c
int process_request(int request_type, char* buffer) {
    // Decompiled pseudocode
}
```

## Cross-references
- Called by: [list of callers]
- Calls: [list of callees]
- References: [list of data references]

## Notes
[Any observations, theories, or questions]

## Status
- [ ] Analyzed
- [x] Verified
- [ ] Documented
'''
```

---

## 8. Scripting & Automation

### 8.1 Cross-Tool Automation

```python
#!/usr/bin/env python3
"""RE Automation Pipeline - Bridge between multiple tools."""

import subprocess
import json
import os
import sys

class REPipeline:
    """Automated RE pipeline that bridges multiple tools."""
    
    def __init__(self, target_binary, output_dir="/tmp/re_output"):
        self.target = target_binary
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = {}
    
    def run_command(self, cmd, tool_name):
        """Run a command and capture output."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"[!] {tool_name} timed out")
            return ""
        except Exception as e:
            print(f"[!] {tool_name} error: {e}")
            return ""
    
    def static_analysis(self):
        """Run static analysis tools."""
        print("[*] Running static analysis...")
        
        # File identification
        output = self.run_command(['file', self.target], 'file')
        self.results['file'] = output
        print(f"  File type: {output.strip()}")
        
        # Strings extraction
        output = self.run_command(['strings', '-a', '-n', '8', self.target], 'strings')
        self.results['strings'] = output.splitlines()
        with open(os.path.join(self.output_dir, 'strings.txt'), 'w') as f:
            f.write(output)
        print(f"  Strings: {len(self.results['strings'])} found")
        
        # Hash calculation
        for algo in ['md5sum', 'sha256sum']:
            output = self.run_command([algo, self.target], algo)
            self.results[algo] = output.split()[0] if output else ""
        print(f"  SHA256: {self.results.get('sha256sum', 'N/A')}")
        
        # Binary format analysis
        if 'ELF' in self.results.get('file', ''):
            output = self.run_command(['readelf', '-h', self.target], 'readelf')
            self.results['elf_header'] = output
            
            # Sections
            output = self.run_command(['readelf', '-S', self.target], 'readelf_sections')
            self.results['sections'] = output
            
            # Symbols
            output = self.run_command(['readelf', '-s', self.target], 'readelf_symbols')
            self.results['symbols'] = output
            
            # Dynamic symbols
            output = self.run_command(['readelf', '--dyn-syms', self.target], 'readelf_dynsyms')
            self.results['dynamic_symbols'] = output
        
        # YARA scanning
        if os.path.exists('/usr/share/yara-rules'):
            output = self.run_command(
                ['yara', '-r', '/usr/share/yara-rules', self.target], 
                'yara')
            self.results['yara_matches'] = output
        
        return self.results
    
    def behavioral_analysis(self, timeout=30):
        """Run behavioral analysis (if safe to execute)."""
        print("[*] Running behavioral analysis...")
        
        # strace (Linux)
        if sys.platform == 'linux':
            cmd = ['timeout', str(timeout), 'strace', '-f', '-o', 
                   os.path.join(self.output_dir, 'strace.log'), self.target]
            self.run_command(cmd, 'strace')
            
            # Parse strace output
            with open(os.path.join(self.output_dir, 'strace.log'), 'r') as f:
                syscalls = f.read()
            self.results['syscalls'] = len(syscalls.splitlines())
            print(f"  Syscalls: {self.results['syscalls']}")
        
        # ltrace (Linux)
        if sys.platform == 'linux':
            cmd = ['timeout', str(timeout), 'ltrace', '-f', '-o',
                   os.path.join(self.output_dir, 'ltrace.log'), self.target]
            self.run_command(cmd, 'ltrace')
        
        return self.results
    
    def generate_report(self):
        """Generate analysis report."""
        report = f"""# RE Analysis Report: {os.path.basename(self.target)}

## File Information
- **Path**: {self.target}
- **Type**: {self.results.get('file', 'Unknown').strip()}
- **MD5**: {self.results.get('md5sum', 'N/A')}
- **SHA256**: {self.results.get('sha256sum', 'N/A')}

## Statistics
- **Strings**: {len(self.results.get('strings', []))}
- **Syscalls**: {self.results.get('syscalls', 'N/A')}

## Analysis Results
- **Output directory**: {self.output_dir}
- **Strings file**: strings.txt
- **Strace log**: strace.log (if available)

## Recommendations
- [ ] Manual analysis with IDA Pro/Ghidra
- [ ] Dynamic analysis with x64dbg/GDB
- [ ] YARA rule development
- [ ] Vulnerability assessment
"""
        
        report_path = os.path.join(self.output_dir, 'report.md')
        with open(report_path, 'w') as f:
            f.write(report)
        print(f"\n[*] Report saved to: {report_path}")
        return report

# Usage
if __name__ == '__main__':
    pipeline = REPipeline(sys.argv[1])
    pipeline.static_analysis()
    # pipeline.behavioral_analysis()  # Uncomment if safe
    pipeline.generate_report()
```

---

## 9. LLM-Assisted RE

### 9.1 Using LLMs for RE Assistance

```
LLM-Assisted RE Workflows:

1. Pseudocode Explanation:
   - Paste decompiled code into LLM
   - Ask: "Explain what this function does"
   - Ask: "What vulnerability does this code have?"
   - Ask: "What is the algorithm being implemented?"

2. Code Annotation:
   - Ask LLM to add comments to decompiled code
   - Ask LLM to suggest variable names based on usage patterns

3. Pattern Recognition:
   - Paste assembly/disassembly and ask: "What crypto algorithm is this?"
   - Ask: "What known vulnerability pattern does this code match?"

4. Protocol Reconstruction:
   - Paste hex dumps and ask: "What protocol structure does this follow?"
   - Ask: "Based on these packet captures, what's the protocol format?"

5. Exploit Development:
   - Ask: "Given this vulnerability, how would I exploit it on [platform]?"
   - Ask: "Write a ROP chain for [binary] with these gadgets"

LIMITATIONS:
- LLMs can hallucinate function names, addresses, and algorithms
- Always verify LLM suggestions against the actual binary
- LLMs may not understand architecture-specific nuances
- Use LLMs as a starting point, not a final answer
- NEVER trust LLM output for security-critical decisions without verification
```

### 9.2 LLM Prompt Templates for RE

```python
# Prompt templates for LLM-assisted RE

PROMPTS = {
    'pseudocode_explanation': """
Given the following decompiled C code, explain:
1. What the function does overall
2. What each parameter represents
3. What the return value means
4. Any potential vulnerabilities

```c
{code}
```
""",
    
    'crypto_identification': """
I have the following assembly code. What cryptographic algorithm is this implementing?
Look at the constants, operations, and structure.

```asm
{assembly}
```
""",
    
    'vulnerability_assessment': """
Analyze the following binary code for security vulnerabilities.
For each vulnerability found, provide:
1. Vulnerability type
2. Severity (Low/Medium/High/Critical)
3. Exploitation potential
4. Suggested remediation

```c
{code}
```
""",
    
    'protocol_reconstruction': """
Based on the following packet captures, reconstruct the protocol format.
For each field, provide:
1. Offset and size
2. Data type
3. Purpose
4. Possible values

Packet 1: {hex1}
Packet 2: {hex2}
Packet 3: {hex3}
""",
    
    'variable_renaming': """
Given the following decompiled function with generic variable names, suggest meaningful names.
Explain your reasoning for each rename.

```c
{code}
```
""",
}
```

---

## 10. Binary Comparison: Diaphora & BinDiff

### 10.1 Diaphora (Ghidra/IDA)

```bash
# Diaphora — binary diffing tool for vulnerability analysis
# https://github.com/joxeankoret/diaphora

# Diaphora with IDA Pro
# 1. Open binary v1 in IDA, run analysis
# 2. File → Script Command → Run Diaphora → Export
# 3. Open binary v2 in IDA, run analysis
# 4. File → Script Command → Run Diaphora → Import & Diff
# 5. Select v1 database, run diffing

# Diaphora with Ghidra (via Ghidra bridge)
# 1. Analyze both binaries in Ghidra
# 2. Export with Diaphora
# 3. Compare databases

# Key diffing results:
# - Identical functions (same assembly)
# - Similar functions (same logic, different compilation)
# - Modified functions (changed logic)
# - New functions (added in v2)
# - Removed functions (removed in v2)

# Patch diffing workflow:
# 1. Obtain original binary (vulnerable)
# 2. Obtain patched binary (fixed)
# 3. Diff with Diaphora
# 4. Analyze modified functions for security fix
# 5. Identify vulnerability from the fix
# 6. Develop exploit for the original binary
```

### 10.2 BinDiff

```bash
# BinDiff — commercial binary diffing tool (now free)
# https://www.zynamics.com/software.html

# BinDiff works as an IDA Pro plugin
# 1. Open binary v1 in IDA, run full analysis
# 2. Open binary v2 in IDA, run full analysis
# 3. BinDiff → Compare → Select v1 database
# 4. View results in BinDiff window

# Key features:
# - Call graph matching
# - Basic block matching
# - Instruction-level diffing
# - Graph visualization of changes
# - Confidence scores for matches

# Common patch diffing pattern:
# 1. Find a function that differs between versions
# 2. Look for added bounds checks, NULL pointer checks
# 3. The vulnerability is in the ORIGINAL version (missing the fix)
# 4. Develop exploit targeting the original code path
```

### 10.3 Binary Diffing for Patch Analysis

```python
# Automated patch diffing script
import subprocess
import os

def patch_diff(original, patched, output_dir):
    """Diff two binary versions to identify security patches."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Step 1: Extract symbols and strings from both
    for binary, name in [(original, 'original'), (patched, 'patched')]:
        # Symbols
        subprocess.run(['nm', '-C', binary], 
                       capture_output=True,
                       text=True).stdout
        # Strings
        subprocess.run(['strings', '-n', '8', binary],
                       capture_output=True,
                       text=True).stdout
    
    # Step 2: Function-level comparison
    # Use objdump to disassemble both
    for binary, name in [(original, 'original'), (patched, 'patched')]:
        result = subprocess.run(['objdump', '-d', '-C', binary],
                               capture_output=True, text=True)
        with open(os.path.join(output_dir, f'{name}_disasm.S'), 'w') as f:
            f.write(result.stdout)
    
    # Step 3: Diff disassembly
    result = subprocess.run(
        ['diff', '-u',
         os.path.join(output_dir, 'original_disasm.S'),
         os.path.join(output_dir, 'patched_disasm.S')],
        capture_output=True, text=True)
    
    with open(os.path.join(output_dir, 'diff.txt'), 'w') as f:
        f.write(result.stdout)
    
    # Step 4: Identify security-relevant changes
    security_keywords = [
        'strcpy', 'strcat', 'sprintf', 'gets',   # Buffer overflow fixes
        'malloc', 'realloc', 'free',               # Memory fixes
        'NULL', 'null', 'nullptr',                  # NULL pointer fixes
        'boundary', 'bound', 'limit', 'size',     # Bounds checking
        'check', 'validate', 'verify',             # Input validation
        'sanitiz', 'encode', 'escape',             # Sanitization
        'auth', 'perm', 'access',                  # Auth/access fixes
    ]
    
    # Parse diff output for security-relevant changes
    findings = []
    for line in result.stdout.splitlines():
        for keyword in security_keywords:
            if keyword.lower() in line.lower():
                findings.append(line)
    
    print(f"\n=== Security-Relevant Changes ===")
    for finding in findings[:20]:
        print(f"  {finding}")
    
    return findings

# Usage:
# patch_diff('vulnerable_v1.exe', 'patched_v2.exe', '/tmp/diff_output')
```

---

## 11. Lab Setup Recommendations

### 11.1 VM Topology

```
RE Lab Network Topology:

┌───────────────────────────────────────────────────────────────────┐
│                     ISOLATED RE NETWORK (NAT)                    │
│                                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
│  │ Analysis VM  │    │  Malware VM  │    │  Target VM   │           │
│  │ (Linux)      │    │  (Windows)   │    │  (Varies)    │           │
│  │ - IDA Pro    │    │  - REMnux    │    │  - Target OS  │          │
│  │ - Ghidra     │    │  - INetSim   │    │  - Target App │          │
│  │ - Wireshark  │    │  - FakeDNS   │    │              │           │
│  │ - YARA       │    │  - Cuckoo    │    │              │           │
│  └──────┬──────-┘    └──────┬──────-┘    └──────┬──────-┘          │
│         │                    │                    │                  │
│         └────────────────────┼────────────────────┘                  │
│                              │                                       │
│                    ┌─────────┴─────────┐                            │
│                    │  Network Tap/     │                            │
│                    │  Firewall          │                            │
│                    │  (pfSense/OPNsense)│                            │
│                    └───────────────────┘                             │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
                              │
                     ┌────────┴─────────┐
                     │  Host Machine    │
                     │  (Management)    │
                     │  - Snapshots     │
                     │  - VPN Access    │
                     └──────────────────┘
```

### 11.2 VM Configuration

```
Analysis VM (Linux - REMnux):
- OS: Ubuntu 22.04 LTS or REMnux
- RAM: 16GB minimum (32GB recommended)
- CPU: 4+ cores (8 recommended)
- Disk: 100GB minimum
- Tools: Ghidra, radare2, Wireshark, YARA, pefile, binwalk, etc.
- Network: Isolated NAT with internet for tool updates
- Snapshots: Clean state with all tools installed

Malware Analysis VM (Windows):
- OS: Windows 10/11 (64-bit)
- RAM: 8GB minimum
- CPU: 2 cores
- Disk: 60GB minimum
- Tools: x64dbg, IDA Free, Process Monitor, API Monitor, Pestudio
- Network: Isolated, fake DNS/DHCP
- IMPORTANT: Take snapshot BEFORE executing any malware

Target VMs (varies by target):
- Windows XP (for legacy targets)
- Windows 7 (for older targets)
- Windows 10 (for modern targets)
- Router firmware (QEMU MIPS/ARM)
- IoT firmware (QEMU + custom kernel)
```

### 11.3 Snapshot Management

```bash
# VirtualBox snapshot management
# Create clean snapshot
VBoxManage snapshot "RE-Analysis" take "clean-state"

# Restore clean snapshot after analysis
VBoxManage snapshot "RE-Analysis" restore "clean-state"

# List snapshots
VBoxManage snapshot "RE-Analysis" list

# QEMU snapshot management
# Create snapshot during analysis
(qemu) savevm analysis-point-1

# Restore snapshot
(qemu) loadvm analysis-point-1

# Delete snapshot
(qemu) delvm analysis-point-1
```

> **Cross-reference**: See [01a_re_fundamentals_methodology.md](01a_re_fundamentals_methodology.md) for foundational RE methodology. See [02a_static_analysis.md](02a_static_analysis.md) for detailed tool workflows. See [02b_dynamic_analysis.md](02b_dynamic_analysis.md) for debugging tool setup. See the [fuzzing_vuln_research track](../fuzzing_vuln_research/) for fuzzing tool integration.

---

*This document is part of the Deep Researcher Reverse Engineering track. Proper tool setup and configuration is essential for effective RE work.*

## References

1. IDA Pro documentation, https://hex-rays.com/ida-pro/
2. Ghidra documentation, https://ghidra-sre.org/
3. radare2 documentation, https://rada.re/n/
4. Binary Ninja documentation, https://docs.binary.ninja/
5. Chris Eagle, "The IDA Pro Book," No Starch Press, 2011.
6. Dennis Andriesse, "Practical Binary Analysis," No Starch Press, 2018.
7. GDB documentation, https://sourceware.org/gdb/documentation/
8. Frida documentation, https://frida.re/docs/home/
9. Diaphora documentation, https://github.com/joxeankoret/diaphora
10. SANS Institute, "Reverse Engineering Malware" (FOR610), https://www.sans.org/
11. DEF CON conference proceedings, https://www.defcon.org/
12. Dennis Yurichev, "Reverse Engineering for Beginners," https://yurichev.com/writings/RE_for_beginners-en.pdf