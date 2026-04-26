# Linux Kernel Vulnerabilities and Exploitation Techniques

The largest track in this repository, covering the full attack surface of the Linux kernel — from monolithic architecture and vulnerability classes through heap/stack exploitation, race conditions, and modern data-only attacks, to fuzzing, mitigations, and defense strategies. With over 37 million lines of code and 460+ system calls, the kernel's monolithic ring-0 design makes every subsystem a potential compromise vector, and this track maps that landscape end-to-end.

- **Difficulty**: 🔴 Advanced
- **Estimated reading time**: ~15 hours (~247,000 words across 20 documents)
- **Prerequisites**: C programming, x86-64 assembly, operating system fundamentals, Linux kernel basics (syscalls, slab allocator, process model)

## Reading Order

| # | File | Topic |
|---|------|-------|
| 01a | [01a_kernel_architecture.md](docs/01a_kernel_architecture.md) | Kernel architecture overview — monolithic design, address space layout, subsystem organization |
| 01b | [01b_attack_surface.md](docs/01b_attack_surface.md) | Attack surface enumeration — codebase size, targeted subsystems, user-namespace amplification |
| 02a | [02a_vuln_classes.md](docs/02a_vuln_classes.md) | Vulnerability classification — taxonomy of memory safety, concurrency, logic, and info-leak bugs |
| 02b | [02b_vuln_patterns.md](docs/02b_vuln_patterns.md) | Vulnerability patterns — copy_from_user misuse, refcount bugs, slab allocator issues, uninitialized memory |
| 03a | [03a_heap_exploitation.md](docs/03a_heap_exploitation.md) | Kernel heap exploitation — SLUB allocator internals, heap spray, cross-cache attacks, msg_msg technique |
| 03b | [03b_stack_memory_corruption.md](docs/03b_stack_memory_corruption.md) | Stack & memory corruption — kernel stack layout, canaries, stack pivoting, OOB access, data-only targets |
| 04a | [04a_race_conditions.md](docs/04a_race_conditions.md) | Race conditions — TOCTOU, data races, userfaultfd/FUSE techniques, CPU pinning, Dirty COW analysis |
| 04b | [04b_use_after_free.md](docs/04b_use_after_free.md) | Use-after-free — UAF phases, object reclamation, DirtyCred technique, cross-cache UAF exploitation |
| 05a | [05a_core_exploitation.md](docs/05a_core_exploitation.md) | Core exploitation — ret2usr, kernel ROP, JOP, stack pivoting, commit_creds primitive, modprobe_path |
| 05b | [05b_advanced_exploitation.md](docs/05b_advanced_exploitation.md) | Advanced exploitation — data-only attacks, DirtyPipe, msg_msg arb R/W, io_uring, eBPF, Dirty Pagetable |
| 06a | [06a_software_mitigations.md](docs/06a_software_mitigations.md) | Software mitigations — KASLR, SMEP, SMAP, KPTI, stack canaries, CFI, slab hardening, HARDENED_USERCOPY |
| 06b | [06b_hardware_mitigations.md](docs/06b_hardware_mitigations.md) | Hardware mitigations — Intel CET, ARM PAC/BTI/MTE, PKS, Lockdown LSM, distribution hardening |
| 07a | [07a_kaslr_smep_bypass.md](docs/07a_kaslr_smep_bypass.md) | KASLR/SMEP/SMAP bypass — info leaks, EntryBleed, side channels, ret2dir, ROP chain construction |
| 07b | [07b_advanced_bypasses.md](docs/07b_advanced_bypasses.md) | Advanced bypasses — CFI bypass, slab hardening defeat, seccomp escape, page-level exploitation |
| 08a | [08a_notable_cves.md](docs/08a_notable_cves.md) | Classic & high-impact CVEs — Dirty COW, Stack Clash, Sequoia, io_uring races, detailed root-cause analysis |
| 08b | [08b_modern_cves.md](docs/08b_modern_cves.md) | Modern CVEs (2020-2026) — CVE-2024-1086, eBPF verifier bypasses, Android kernel exploits, container escapes |
| 09a | [09a_kernel_fuzzing.md](docs/09a_kernel_fuzzing.md) | Kernel fuzzing — Syzkaller, kAFL, HEALER, Trinity, KCOV, kernel configs for fuzzing |
| 09b | [09b_static_analysis.md](docs/09b_static_analysis.md) | Static analysis & auditing — Sparse, Smatch, Coccinelle, CodeQL, Coverity, manual audit methodology |
| 10a | [10a_kernel_hardening.md](docs/10a_kernel_hardening.md) | Kernel hardening — KSPP, grsecurity/PaX, Android GKI, ChromeOS, compile-time flags, attack surface reduction |
| 10b | [10b_defense_operations.md](docs/10b_defense_operations.md) | Defense operations — exploit detection heuristics, eBPF monitoring, integrity verification, sysctl hardening, Rust |

## Related Tracks

- **Android Architecture & CVEs** — [../android_and_CVEs/](../android_and_CVEs/) — Android uses the Linux kernel; this track covers Android-specific kernel hardening, Binder, and mobile CVEs
- **Zero-Day Exploit Development** — [../zero_day/](../zero_day/) — kernel 0-day development methodology and the exploitation pipeline
- **Ring & Vulnerabilities** — [../ring_and_vulns/](../ring_and_vulns/) — Ring 0 (kernel mode) vulnerability classes and privilege boundary analysis
- **CVE-2023-20938** — [../CVE-2023-20938/](../CVE-2023-20938/) — A kernel exploitation case study in the Android Binder subsystem