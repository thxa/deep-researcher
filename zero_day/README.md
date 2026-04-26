# Zero-Day Research & Exploit Development

A comprehensive zero-day vulnerability research and exploit development curriculum spanning from vulnerability taxonomy and fuzzing fundamentals through advanced kernel heap exploitation and CTF competition strategy. This track covers the full lifecycle — discovery, analysis, exploitation, and disclosure — with working pwntools exploits, GDB workflows, and real CVE walkthroughs drawn from landmark zero-days and top-tier CTF challenges.

| | |
|---|---|
| **Difficulty** | 🟡 Intermediate → 🔴 Advanced (progressive) |
| **Reading Time** | ~13 hours |
| **Prerequisites** | C, Python, x86 assembly, basic exploitation concepts (buffer overflows, shellcode), Linux CLI proficiency |

---

## Reading Order

| # | Document | Topic |
|---|----------|-------|
| 00 | [Master Report](docs/00_MASTER_REPORT.md) | Index, synthesis, and learning roadmap for the entire corpus |
| 01a | [Zero-Day Fundamentals & Taxonomy](docs/01a_zero_day_fundamentals_taxonomy.md) | 0-day/1-day/N-day classification, vulnerability class encyclopedia, 10+ landmark CVEs, threat landscape |
| 01b | [Zero-Day Ecosystem & Attack Surfaces](docs/01b_zero_day_ecosystem_attack_surfaces.md) | Zero-day economics, markets, attack surface mapping, patch diffing for 1-days, adversarial mindset |
| 02a | [Vuln Discovery: Fuzzing & Dynamic Analysis](docs/02a_vuln_discovery_fuzzing_dynamic.md) | AFL++, libFuzzer, syzkaller, coverage-guided fuzzing, crash triage, dynamic instrumentation |
| 02b | [Vuln Discovery: Code Audit & Reverse Engineering](docs/02b_vuln_discovery_audit_re.md) | Source auditing, Ghidra scripting, CodeQL/Semgrep, kernel code audit, patch diffing & variant analysis |
| 03a | [Userspace: Stack & Heap Exploitation](docs/03a_userspace_stack_heap.md) | Stack overflows, ROP/SROP/ret2csu, glibc heap internals, modern heap techniques (House of Apple/Botcake/Cat), FILE/FSOP |
| 03b | [Userspace: Advanced Techniques](docs/03b_userspace_advanced_techniques.md) | Format strings, integer bugs, type confusion, UAF, ret2dlresolve, one-gadgets, shellcraft, race conditions |
| 04a | [Kernel: Foundations & Slab Exploitation](docs/04a_kernel_slab_exploitation.md) | Linux kernel architecture, SLUB allocator internals, cross-cache attacks, msg_msg/pipe_buffer/tty spray, info leaks |
| 04b | [Kernel: Advanced LPE](docs/04b_kernel_advanced_lpe.md) | Kernel ROP, commit_creds/modprobe_path, SMEP/SMAP/KASLR/KPTI bypass, userfaultfd/FUSE, Dirty COW/Pipe, io_uring |
| 05 | [Mitigation Bypass Techniques](docs/05_mitigation_bypass_techniques.md) | NX→ROP, ASLR→info leak, canary→leak/bruteforce, PIE→disclosure, RELRO→GOT alternatives, seccomp escapes |
| 06 | [CTF Strategy & Mastery](docs/06_ctf_strategy_mastery.md) | Competition landscape, systematic pwn/kernel methodology, speed optimization, mental game, training regiment |
| 07 | [Tooling & Infrastructure](docs/07_tooling_infrastructure.md) | GDB/pwndbg mastery, pwntools reference, kernel debugging, QEMU scripts, checksec/one_gadget/patchelf, exploit templates |
| 08 | [Ethics, Disclosure & Legal](docs/08_ethics_disclosure_legal.md) | CVD process, CFAA/DMCA framework, bug bounty economics, zero-day market debate, career trajectories |

---

## Related Tracks

- [Linux Kernel](../linux_kernel/) — Deep kernel exploitation reference (subsystems, driver audit, kernel internals)
- [Ring & Vulnerabilities](../ring_and_vulns/) — Privilege ring architecture and hardware-enforced security boundaries
- [Chromium](../Chromium_Architecture_and_Vulnerability/) — Browser exploitation, V8, sandbox escapes
- [OSEE](../OSEE/) — Advanced exploitation certification preparation (CREST OSWE/OSEE level)