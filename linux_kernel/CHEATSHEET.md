# Linux Kernel Security — Quick Reference

## Security Mechanisms

| Mechanism | Purpose | Kernel Config |
|-----------|---------|---------------|
| SMEP | Prevent kernel executing user-space code | `CONFIG_X86_SMEP` (CR4.SMEP) |
| SMAP | Prevent kernel accessing user-space data | `CONFIG_X86_SMAP` (CR4.SMAP) |
| KASLR | Randomize kernel base address | `CONFIG_RANDOMIZE_BASE` |
| KPTI | Separate kernel/user page tables | `CONFIG_PAGE_TABLE_ISOLATION` |
| Stack Canary | Detect stack buffer overflows | `CONFIG_STACKPROTECTOR_STRONG` |
| kCFI | Forward-edge control flow integrity | `CONFIG_CFI_CLANG` |
| Shadow Call Stack | Protect return addresses | `CONFIG_SHADOW_CALL_STACK` |
| HARDENED_USERCOPY | Validate copy_from_user bounds | `CONFIG_HARDENED_USERCOPY` |
| FORTIFY_SOURCE | Runtime buffer overflow detection | `CONFIG_FORTIFY_SOURCE` |
| INIT_STACK_ALL_ZERO | Zero-init stack variables | `CONFIG_INIT_STACK_ALL_ZERO` |
| KASAN | Kernel address sanitizer (UAF/OOB) | `CONFIG_KASAN` |
| KMSAN | Kernel memory sanitizer (uninit) | `CONFIG_KMSAN` |
| KCSAN | Kernel concurrency sanitizer | `CONFIG_KCSAN` |
| KFENCE | Low-overhead heap bug sampling | `CONFIG_KFENCE` |
| LOCKDEP | Lock ordering validator | `CONFIG_LOCKDEP` |
| SLAB_FREELIST_HARDENED | XOR-encod slab freelist pointers | `CONFIG_SLAB_FREELIST_HARDENED` |
| SLAB_FREELIST_RANDOM | Randomize slab freelist order | `CONFIG_SLAB_FREELIST_RANDOM` |
| RANDSTRUCT | Randomize struct layouts | `CONFIG_RANDSTRUCT` |
| STRICT_DEVMEM | Restrict /dev/mem access | `CONFIG_STRICT_DEVMEM` |
| seccomp-BPF | Syscall filtering | `CONFIG_SECCOMP` |
| Lockdown LSM | Restrict kernel features by integrity level | `CONFIG_LOCK_DOWN_KERNEL` |
| Module Signing | Verify module signatures | `CONFIG_MODULE_SIG` |
| VMAP_STACK | Guard pages for kernel stacks | `CONFIG_VMAP_STACK` |

## Vulnerability Classes

| Class | Frequency | Key Examples |
|-------|-----------|--------------|
| Use-After-Free | ~25-30% CVEs, **67% ITW 0-days** | netfilter UAF, msg_msg misuse |
| Out-of-Bounds Write | 15-20% | heap overflow, stack overflow |
| Out-of-Bounds Read | 10-15% | info leaks for KASLR bypass |
| Race Condition (TOCTOU) | 8-12% | Dirty COW, io_uring races |
| Integer Overflow | 5-8% | size calculation truncation |
| NULL Pointer Dereference | 5-8% | mapped-low exploit (mmap_min_addr) |
| Information Leak | 5-7% | uninitialized memory, pointer leaks |
| Type Confusion | 3-5% | eBPF verifier bypasses |
| Double-Free | rare but critical | CVE-2024-1086 (nf_tables) |

## Exploitation Primitives

| Primitive | Mechanism | Goal |
|-----------|-----------|------|
| Arbitrary Read | Corrupt msg_msg.m_ts or seq_operations | KASLR defeat, leak credentials |
| Arbitrary Write | Corrupt msg_msg.next + userfaultfd; Dirty Pagetable | Overwrite modprobe_path, cred, page tables |
| Stack Pivot | `mov esp, <imm32>` gadget redirect RSP | Navigate ROP chain |
| modprobe_path Overwrite | Write to kernel BSS global | Execute arbitrary binary as root (data-only) |
| core_pattern Overwrite | Write to kernel data | Execute on process crash (data-only) |
| commit_creds + prepare_kernel_cred | ROP chain calls | Set uid/gid to 0 |
| DirtyCred | Replace struct cred/struct file via UAF | Privilege escalation without code exec |
| Dirty Pagetable | Convert UAF/overflow into PTE manipulation | Arbitrary physical R/W |
| ret2dir | Dual mapping via kernel physmap | Bypass SMEP+SMAP |
| physmap spray | Spray controlled data in physical map region | Reliable heap spray target |

## Key Kernel Structures

| Structure | Size | Cache | Exploitation Use |
|-----------|------|-------|------------------|
| `task_struct` | ~9.5KB | kmalloc (custom) | Contains `cred` pointer — overwrite for priv esc |
| `struct cred` | 192 bytes | cred_jar (kmalloc-192) | uid/gid/euid — overwrite for root |
| `msg_msg` | 48-4096+ bytes | kmalloc-* | Elastic spray, arb read/write/free via field corruption |
| `pipe_buffer` | 40 bytes (×16) | kmalloc-cg-1024 | Function pointer hijack (`ops->release`) |
| `seq_operations` | 32 bytes | kmalloc-32 | Leak kernel text pointers (KASLR bypass) |
| `struct file` | 232 bytes | kmalloc-256 | DirtyCred file substitution target |
| `sk_buff` | Variable | kmalloc-* | Network-triggered heap spray |
| `subsys_private` | Variable | kmalloc-* | Contains kmalloc function pointer |
| `tty_struct` | ~696 bytes | kmalloc-1024 | Contains `ops` pointer for hijack |
| `page` | 64 bytes | mem_map | Dirty Pagetable target — PTE manipulation |

## Fuzzing Tools & Configs

| Tool | Type | Kernel Configs Required | Bugs Found |
|------|------|------------------------|------------|
| **Syzkaller** | Coverage-guided syscall fuzzer | `CONFIG_KCOV`, `CONFIG_KASAN`/`CONFIG_KMSAN`, `CONFIG_DEBUG_INFO`, `CONFIG_CONFIG_RANDSTRUCT`, kvm/gce setup | 5,000+ |
| **kAFL** | Hardware-assisted (Intel PT) | `CONFIG_KCOV`, Intel PT support, HDD/SSD tracing | Hundreds |
| **HEALER** | Relation-learning fuzzer | Same as Syzkaller | Significant |
| **AFL++** | General-purpose fuzzer | Kernel module harnessing | Requires custom harness |
| **Trinity** | Knowledge-based syscall fuzzer | `CONFIG_DEBUG_FS`, test system | Historical |

**Syzkaller key syzlang coverage**: syscalls, ioctl, netlink, eBPF, io_uring, files, sockets, namespaces, cgroups, futexes.

## Kernel Hardening Config Quick Reference

### Must-Enable
```
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_RANDOMIZE_BASE=y              # KASLR
CONFIG_X86_SMEP=y                    # SMEP (hardware)
CONFIG_X86_SMAP=y                    # SMAP (hardware)
CONFIG_PAGE_TABLE_ISOLATION=y        # KPTI
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_STRICT_DEVMEM=y
CONFIG_SECURITY_DMESG_RESTRICT=y
CONFIG_KALLSYMS_EXTRA_PASS=y
CONFIG_INIT_STACK_ALL_ZERO=y
CONFIG_VMAP_STACK=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_MERGE_DEFAULT=n
```

### Recommended
```
CONFIG_CFI_CLANG=y                   # kCFI (LLVM)
CONFIG_SHADOW_CALL_STACK=y           # SCS (ARM64)
CONFIG_KASAN=y                        # Debug/test only (2-3x overhead)
CONFIG_KFENCE=y                       # Production-safe heap sampling
CONFIG_RANDSTRUCT=y                   # Randomize struct layouts
CONFIG_MODULE_SIG=y                   # Module signing
CONFIG_MODULE_SIG_FORCE=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_BPF_SYSCALL=n                  # Or restrict via sysctl
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y      # Memory zeroing on free
```

### Sysctl Hardening
```bash
kernel.kptr_restrict = 2              # Hide kernel pointers
kernel.dmesg_restrict = 1             # Restrict dmesg
kernel.perf_event_paranoid = 3        # Restrict perf
kernel.unprivileged_bpf_disabled = 1  # Disable unprivileged eBPF
kernel.unprivileged_userns_clone = 0   # Restrict user namespaces
kernel.kexec_load_disabled = 1        # Disable kexec
vm.mmap_min_addr = 65536              # Prevent NULL deref exploitation
vm.unprivileged_userfaultfd = 0        # Restrict userfaultfd
kernel.randomize_va_space = 2         # Full ASLR
```

### grsecurity/PaX Specific
- **RAP**: Return Address Protection (strongest CFI)
- **UDEREF**: Strict kernel/user memory separation
- **AUTOSLAB**: Per-type slab isolation (defeats cross-cache)
- **SIZE_OVERFLOW**: Compile-time integer overflow detection
- **RANDKSTACK**: Per-syscall stack randomization

## Notable CVEs Covered

| CVE | Name | Type | Impact |
|-----|------|------|--------|
| CVE-2016-5195 | Dirty COW | Race condition (COW) | Write to read-only files |
| CVE-2022-0847 | DirtyPipe | Uninitialized flag | Overwrite any readable file, trivial LPE |
| CVE-2021-33909 | Sequoia | Integer truncation | LPE via seq_file |
| CVE-2023-32233 | nf_tables UAF | Use-after-free | Privilege escalation via netfilter |
| CVE-2024-1086 | nf_tables double-free | Double-free | Universal LPE (99.4% success), Dirty Pagedirectory |
| CVE-2023-3269 | StackRot | Race in maple tree | UAF-by-RCU |
| CVE-2022-29582 | io_uring race | Race condition | Cross-cache exploitation |
| CVE-2022-4543 | EntryBleed | Side-channel KASLR bypass | Unprivileged KASLR defeat |
| CVE-2022-0185 | Filesystem context overflow | Heap overflow | Container escape |
| CVE-2016-0728 | refcount overflow | Integer overflow in keyring | UAF via refcount |
| CVE-2023-2008 | udmabuf OOB | Out-of-bounds access | DMA buffer exploitation |

## UAF Exploitation Phases

```
1. TRIGGER    → Free the target object while retaining a dangling reference
2. RECLAIM    → Spray replacement objects (msg_msg, setxattr, pipe_buffer) into freed slot
3. USE        → Access via dangling pointer: read (info leak), write (corruption), or call (func ptr hijack)
```

## Modern Exploitation Evolution

```
Pre-2012:  ret2usr           → Direct user-code execution from ring 0
2012-15:   SMEP era          → Kernel ROP chains required
2015-18:   SMEP+SMAP era     → Stack pivoting + kernel-to-kernel data copies
2018-20:   KPTI+KASLR era   → Info leaks + ROP + KPTI trampoline return
2020-23:   CFI era           → Data-only attacks (DirtyCred, modprobe_path)
2024+:     Full hardening    → Cross-cache, page-level, coprocessor exploitation
```