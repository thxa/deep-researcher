# Zero-Day Research & Exploit Development: The Definitive Reference

## For CTF Competitors, Security Researchers, and Exploit Developers

> **Difficulty:** 🟡 Intermediate to 🔴 Advanced | **Prerequisites:** C/C++, x86 assembly, basic exploitation concepts | **Estimated reading time:** ~30 minutes (master index; full corpus ~8 hours)
>
> **81,000+ words of expert-level content** covering zero-day fundamentals through advanced kernel exploitation, designed to take you from intermediate CTF player to world-class competitor.

---

## About This Reference

This document serves as an index and synthesis of a comprehensive 11-part research corpus on zero-day vulnerability research and exploit development. Each section is a standalone deep-dive, and together they form a complete curriculum for mastering exploitation at the highest level.

**Philosophy**: To be the best in the world at CTFs, you need to understand exploitation at every level — from the theory of why vulnerabilities exist, to the precise mechanics of exploiting them in both userspace and kernel, to the strategic approach that wins competitions. This reference covers all of that and more.

---

## Document Index

### Part 1: FOUNDATIONS

| Document | Description | Key Topics |
|----------|-------------|------------|
| [01a — Zero-Day Fundamentals, Taxonomy & Landscape](01a_zero_day_fundamentals_taxonomy.md) | Core concepts, vulnerability classification, lifecycle, historical zero-days, current threat landscape | 0-day/1-day/N-day taxonomy, 10+ landmark CVEs deep-dives, vulnerability class encyclopedia, APT landscape |
| [01b — Zero-Day Ecosystem & Attack Surfaces](01b_zero_day_ecosystem_attack_surfaces.md) | Economics, markets, attack surface mapping, N-day methodology, adversarial mindset | Zero-day pricing by target, systematic attack surface enumeration, vulnerability classes by exploit type, patch diffing for 1-days |

### Part 2: DISCOVERY

| Document | Description | Key Topics |
|----------|-------------|------------|
| [02a — Vulnerability Discovery: Fuzzing & Dynamic Analysis](02a_vuln_discovery_fuzzing_dynamic.md) | AFL++, libFuzzer, syzkaller, crash triage, dynamic instrumentation | Coverage-guided fuzzing setup, kernel fuzzing with syzkaller, structure-aware fuzzing, crash analysis & exploitability assessment, taint analysis |
| [02b — Vulnerability Discovery: Code Audit & Reverse Engineering](02b_vuln_discovery_audit_re.md) | Source auditing, binary RE, Ghidra, patch diffing, variant analysis | Dangerous pattern identification, CodeQL/Semgrep queries, Ghidra scripting, kernel code audit methodology, diffing security patches |

### Part 3: USERSPACE EXPLOITATION

| Document | Description | Key Topics |
|----------|-------------|------------|
| [03a — Userspace Exploit Development: Stack & Heap](03a_userspace_stack_heap.md) | Complete stack and heap exploitation for glibc and alternative allocators | Stack overflows, off-by-one, stack pivoting, ROP chains, SROP, ret2csu; glibc heap internals (chunks, bins, tcache, safe-linking), modern heap techniques (House of Apple/Botcake/Cat/Husk), FILE/FSOP exploitation |
| [03b — Userspace Exploit Development: Advanced Techniques](03b_userspace_advanced_techniques.md) | Format strings, integer bugs, UAF, advanced ROP, shellcode, race conditions | Format string read/write primitives, type confusion, JOP/DOP, ret2dlresolve, one-gadgets, constrained shellcraft, heap Feng Shui, exploit reliability |

### Part 4: KERNEL EXPLOITATION

| Document | Description | Key Topics |
|----------|-------------|------------|
| [04a — Kernel Exploit Development: Foundations & Slab Exploitation](04a_kernel_slab_exploitation.md) | Linux kernel architecture, SLUB allocator, heap exploitation primitives | Kernel memory management, kmalloc/slab internals, cross-cache attacks, msg_msg/pipe_buffer/tty_struct/seq_operations spray techniques, info leak primitives |
| [04b — Kernel Exploit Development: Advanced LPE](04b_kernel_advanced_lpe.md) | Kernel ROP, privilege escalation, concurrency bugs, eBPF, notable exploit walkthroughs | commit_creds/prepare_kernel_cred, KROP, SMEP/SMAP/KASLR/KPTI bypass, userfaultfd/FUSE techniques, Dirty COW & Dirty Pipe walkthroughs, io_uring vulns |

### Part 5: DEFENSE EVASION

| Document | Description | Key Topics |
|----------|-------------|------------|
| [05 — Mitigation Bypass Techniques](05_mitigation_bypass_techniques.md) | Comprehensive bypass strategies for every major security mitigation | NX/DEP → ROP/ret2libc; ASLR → info leak/partial overwrite; canary → leak/bruteforce; PIE → address disclosure; RELRO → GOT alternatives; SMEP/SMAP/KASLR/KPTI → kernel bypass; seccomp → allowed syscall abuse |

### Part 6: CTF MASTERY

| Document | Description | Key Topics |
|----------|-------------|------------|
| [06 — CTF Strategy, Methodology & Competition Mastery](06_ctf_strategy_mastery.md) | The complete guide to dominating CTF competitions | Competition landscape, systematic pwn challenge methodology, kernel CTF methodology, speed optimization, mental game, training regiment, practice platform roadmap |

### Part 7: TOOLING

| Document | Description | Key Topics |
|----------|-------------|------------|
| [07 — Tooling, Infrastructure & Debug Environments](07_tooling_infrastructure.md) | Building the ultimate exploit development workstation | GDB/pwndbg mastery, pwntools complete reference, kernel debugging setup, QEMU launch scripts, checksec/one_gadget/patchelf/seccomp-tools, exploit templates |

### Part 8: ETHICS & PROFESSION

| Document | Description | Key Topics |
|----------|-------------|------------|
| [08 — Ethics, Disclosure & Legal Framework](08_ethics_disclosure_legal.md) | Responsible disclosure, legal considerations, career paths | CVD process, CFAA/DMCA/legal framework by jurisdiction, bug bounty economics, zero-day market debate, career trajectories from CTF to professional research |

---

## Learning Roadmap

### Phase 1: Foundations (Weeks 1-2)
1. Read **01a** and **01b** — Understand what zero-days are, how they're classified, and the ecosystem
2. Skim **05** — Know what mitigations exist so you understand what you're bypassing
3. Read **07** — Set up your workstation and tools
4. Read **08** — Understand the legal and ethical boundaries

### Phase 2: Discovery Skills (Weeks 3-5)
1. Read **02a** — Learn fuzzing methodology
2. Read **02b** — Learn auditing and reverse engineering
3. Practice: Run AFL++ on open-source targets, do RE challenges on CrackMes

### Phase 3: Userspace Exploitation (Weeks 6-10)
1. Read **03a** — Master stack and heap exploitation
2. Read **03b** — Master advanced techniques
3. Read **05** in depth — Learn mitigation bypasses
4. Practice: pwnable.kr, pwnable.tw, CTF archive challenges

### Phase 4: Kernel Exploitation (Weeks 11-15)
1. Read **04a** — Understand kernel internals and slab exploitation
2. Read **04b** — Master advanced kernel primitives and LPE
3. Practice: Kernel CTF challenges, build custom kernels, write practice modules

### Phase 5: CTF Competition (Ongoing)
1. Read **06** — Internalize CTF methodology
2. Compete in every CTF you can find
3. Study writeups systematically
4. Build your personal exploit library and templates

---

## Quick-Reference: The Exploit Developer's Checklist

### Before You Start a Challenge
```
□ checksec binary                    # Check protections
□ file binary                        # Identify arch/type
□ readelf -s binary | grep -i useful # Find interesting symbols
□ strings binary                     # Quick recon
```

### Userspace Exploitation Decision Tree
```
Has NX? ──── Yes → ROP / ret2libc / mprotect
          └── No  → Shellcode on stack

Has ASLR? ── Yes → Need info leak or partial overwrite
          └── No  → Hardcoded addresses

Has Canary? ─ Yes → Leak canary (format string, fork brute) or overwrite other targets
           └── No  → Direct overflow

Has PIE? ─── Yes → Leak code address first
          └── No  → Known code addresses

Heap challenge? → Identify allocator version → Choose technique (tcache, fastbin, etc.)
```

### Kernel Exploitation Decision Tree
```
What primitive? ── UAF → Choose spray target (msg_msg, pipe_buffer, etc.)
                  ├── OOB → Determine if read or write, which slab
                  ├── Arb write → Target cred/modprobe_path/hardcoded
                  └── Race → Need userfaultfd/FUSE for heap shaping

Has SMEP? ─── Yes → ROP in kernel, don't ret2user
          └── No  → Can ret2user with prepared shellcode

Has SMAP? ─── Yes → Can't access user memory from kernel; ROP-only
          └── No  → Copy_from_user available, pivot to user data

Has KASLR? ── Yes → Need kernel info leak (dmesg, /proc/kallsyms, heap leak)
          └── No  → Known kernel addresses
```

### pwntools Quick-Start Template
```python
#!/usr/bin/env python3
from pwn import *

context.update(arch='amd64', os='linux', log_level='info')
e = ELF('./vuln')
libc = ELF('./libc.so.6') if args.REMOTE else ELF('/lib/x86_64-linux-gnu/libc.so.6')

def conn():
    if args.REMOTE:
        return remote('host', port)
    elif args.GDB:
        return gdb.debug('./vuln', 'b *main\ncontinue')
    else:
        return process('./vuln')

r = conn()
# Your exploit here
r.interactive()
```

### Kernel CTF QEMU Launch Template
```bash
#!/bin/bash
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -nographic \
    -append "console=ttyS0 loglevel=3 oops=panic panic=1" \
    -monitor /dev/null \
    -s -S \
    -cpu qemu64,+smep,+smap \
    -no-reboot
# Connect gdb: target remote localhost:1234
# Or remove -S to boot without waiting for gdb
```

---

## Key Concepts by Difficulty Level

### Beginner (pwnable.kr, picoCTF)
- Simple buffer overflows
- ret2libc
- Basic shellcode
- format string basics (%x, %n)
- Basic heap (fastbin dup)

### Intermediate (pwnable.tw, OverTheWire, Root-Me)
- ROP chains
- Heap exploitation (tcache poisoning, House of Force)
- Partial overwrites
- Format string write primitives
- ret2dlresolve
- One-gadgets

### Advanced (HITCON, Balsn, hxp CTF)
- Modern glibc heap (House of Apple/Cat/Husk, largebin attack)
- FSOP exploitation
- Kernel exploitation (UAF, double-free in slab)
- Race condition exploitation
- Sandbox escapes

### World-Class (DEF CON CTF Finals, PlaidCTF top 10)
- Novel exploitation primitives
- Multi-stage kernel-to-user escapes
- Bypassing latest mitigations (CFI, IBT, kFORTIFY)
- Exploit reliability under ASLR
- eBPF verifier exploitation
- Hypervisor escapes

---

## Cross-Reference: Technique → Document Mapping

| Technique | Primary Document | Supporting Documents |
|----------|-----------------|---------------------|
| Buffer Overflow | 03a (Stack & Heap) | 05 (Mitigation Bypass) |
| ROP Chains | 03a (Stack & Heap), 04b (Kernel Advanced) | 03b (Advanced), 05 |
| Heap Exploitation | 03a (Stack & Heap) | 04a (Kernel Slab) |
| Kernel UAF | 04a (Kernel Slab) | 04b (Kernel Advanced) |
| Fuzzing | 02a (Fuzzing) | 02b (Audit/RE) |
| Format String | 03b (Advanced) | 05 (Mitigation Bypass) |
| ASLR Bypass | 05 (Mitigation Bypass) | 03b (Advanced), 04b |
| SMEP/SMAP Bypass | 04b (Kernel Advanced) | 05 (Mitigation Bypass) |
| CTF Strategy | 06 (CTF Mastery) | All others |
| Tool Setup | 07 (Tooling) | All others |
| Patch Diffing | 02b (Audit/RE) | 01b (Ecosystem) |

---

## Statistics

| Metric | Value |
|--------|-------|
| Total words | ~81,000 |
| Total documents | 11 |
| Covered vulnerability classes | 20+ |
| Documented exploit techniques | 100+ |
| Code/repo examples | 200+ |
| Historical zero-day case studies | 15+ |
| Notable CVEs referenced | 50+ |
| pwntools code examples | 40+ |
| GDB commands documented | 50+ |
| Kernel exploitation techniques | 30+ |

---

## Related Tracks

- [**Linux Kernel Vulnerabilities & Exploitation**](../../linux_kernel/docs/FINAL_REPORT.md) — Kernel exploitation is a core topic in this reference; the linux_kernel report provides the comprehensive technical deep-dive into kernel vulnerability classes and exploitation techniques.
- [**CPU Protection Rings & Vulnerabilities**](../../ring_and_vulns/FULL_REPORT.md) — Privilege rings (Ring 3 userland → Ring 0 kernel → Ring -1 hypervisor) define the escalation targets in exploitation; understanding ring boundaries is fundamental to LPE methodology.
- [**Android Architecture, Vulnerabilities & CVEs**](../../android_and_CVEs/FINAL_REPORT_Android_Architecture_Vulnerabilities_and_CVEs.md) — Mobile exploitation is a major branch of zero-day research; Android kernel exploitation and defense-in-depth provide real-world context.
- [**Chromium Architecture & Vulnerability**](../../Chromium_Architecture_and_Vulnerability/Chromium_Architecture_and_Vulnerability_Report.md) — Browser exploitation (V8 JIT, sandbox escape) is the most active zero-day target class; Chromium's multi-process architecture defines modern browser exploit chain methodology.
- [**OSEE Certification**](../../OSEE/docs/01a_osee_overview_history.md) — The OSEE represents the pinnacle of exploit development certification; the methodology and techniques covered here directly support OSEE-level expertise.

---

## Recommended External Resources

### Books
- *Hacking: The Art of Exploitation* (Erickson) — Foundations
- *A Bug Hunter's Diary* (Klein) — Practical vulnerability discovery
- *Practical Binary Analysis* (Andriesse) — RE and binary analysis
- *The Art of Software Security Assessment* (Dowd et al.) — Code audit methodology
- *Understanding the Linux Kernel* (Bovet & Cesati) — Kernel internals

### Online
- **pwn.college** — Structured exploitation course from ASU
- **CTFtime.org** — CTF schedule and rankings
- **pwntools docs** — readthedocs.io/projects/pwntools
- **AFL++ docs** — github.com/AFLplusplus/AFLplusplus
- **Kernel exploit DB** — github.com/xairy/linux-kernel-exploitation
- **How2Heap** — github.com/shellphish/how2heap

### Practice Platforms
- pwnable.kr / pwnable.tw
- OverTheWire (Bandit, Narnia, Behemoth)
- picoCTF
- Root-Me
- Hack The Box
- CTFtime archives

---

## Document Generation Details

This reference was generated by 16 specialized research agents covering 8 sub-topics, each investigated from two different angles. The resulting 11 documents were compiled into this master index.

**Research completed**: April 2026
**Scope**: Userspace and kernel exploit development, vulnerability discovery, CTF strategy, tooling, and ethics
**Intent**: Educational and professional security research; CTF competition preparation

---

> *"The difference between a good CTF player and a world-class one is not talent — it's systematic practice, deep understanding of primitives, and the ability to think adversarially about every interface."*

**Start with Part 1. Master each section before moving on. Compete relentlessly. You will get there.**