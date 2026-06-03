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

## References

- Robert Love, "Linux Kernel Development," 3rd Edition, Addison-Wesley, 2010.
- Linux Kernel Documentation, https://www.kernel.org/doc/html/latest/
- Linux Kernel Source Tree, https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
- Phrack Magazine, various articles on kernel exploitation, http://www.phrack.org/
- NIST National Vulnerability Database (NVD), https://nvd.nist.gov/
- Linux Kernel Mailing List (LKML), https://lore.kernel.org/lkml/
- Google Project Zero Blog, https://googleprojectzero.blogspot.com/
- KASAN Documentation, https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
- KMSAN Documentation, https://www.kernel.org/doc/html/latest/dev-tools/kmsan.html
- grsecurity/PaX Documentation, https://grsecurity.net/
- KSPP (Kernel Self-Protection Project), https://kernsec.org/wiki/
- LWN.net, https://lwn.net/
- Black Hat and DEF CON presentations on kernel exploitation (various years)

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-38617: af_packet Use-After-Free Race ('A Race Within A Race')** *(2026-03)* — A use-after-free in the Linux packet-socket subsystem caused by a race between packet_set_ring() and packet_notifier() when po->bind_lock is released, present since Linux 2.6.12 and fixed in 6.16. Quang Le of Calif weaponized it for a kernelCTF submission, chaining a deterministic race (stretched by sleeping while holding pg_vec_lock) with a probabilistic tpacket_rcv() race to reach a freed ring buffer, yielding LPE/container escape from only CAP_NET_RAW (obtainable via user namespaces). [[source]](https://blog.calif.io/p/a-race-within-a-race-exploiting-cve)
- **CVE-2025-21836: io_uring/kbuf Buffer-List Reuse Use-After-Free** *(2025)* — IORING_REGISTER_PBUF_RING could reuse a stale struct io_buffer_list created for a legacy selected buffer after it was emptied, violating the requirement that the structure stays stable after publish; the fix always reallocates it. It affects Linux 5.19 through 6.14-rc2 (CVSS 5.5) and was presented at Hexacon 2025 by Pumpkin Chang in 'Deja Vu in Linux io_uring: Breaking Memory Sharing Again After Generations of Fixes.' [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-21836)
- **CVE-2025-38001: HFSC qdisc Use-After-Free Powers Record kernelCTF Exploit** *(2025)* — A reentrant-enqueue bug in the net_sched HFSC scheduler adds a class to the eligible-tree (eltree) RBTree twice, causing a use-after-free and infinite loop; it affects kernels from 5.x through 6.15 and is fixed by an explicit eltree membership check. Researcher D3vil (with FizzBuzz101) turned it into a page-level data-only attack over RBTree transformations that defeated all Google kernelCTF instances (LTS 6.6, COS 105/109) and Debian 12 for roughly $82,000, including the fastest submission in kernelCTF history. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-38001)
- **CVE-2026-43494 'PinTheft': RDS + io_uring Page-Cache Root via Refcount Bug** *(2026-05)* — A reference-counting/double-free flaw in the Linux RDS zerocopy send path (op_nents not reset when a page pin fails in rds_message_zcopy_from_user), present since Linux 4.17, is chained with io_uring fixed buffers to overwrite page-cache bytes of a SUID-root binary and gain root without touching the filesystem. Disclosed by Aaron Esau of V12 Security in May 2026 with a candidate netdev patch posted May 5, 2026; public PoC exists and requires RDS/RDS_TCP loadable plus io_uring enabled. [[source]](https://tuxcare.com/blog/cve-pintheft/)

### Incidents & In-the-Wild Exploitation

- **kernelCTF / CISA KEV Signal: Old Kernel LPEs Re-Exploited and Cataloged in 2025** *(2025)* — CISA added the long-standing nftables LPE CVE-2021-22555 to its Known Exploited Vulnerabilities catalog on 2025-10-06 (over four years after disclosure), while CVE-2024-1086 was tied to in-the-wild ransomware abuse, underscoring rapid PoC turnaround (2-7 days) for kernel LPEs in 2025-2026. This reflects an operational trend of weaponizing previously-known kernel bugs reachable by unprivileged users through user namespaces. [[source]](https://linuxsecurity.com/news/security-vulnerabilities/7-linux-kernel-vulnerabilities-exploited-in-2025)

### Research

- **USENIX Security 2025: Defense-Amplified TLB Side-Channel Leaks Break KASLR/Heap Isolation** *(2025-08)* — Lukas Maar, Lukas Giner, Daniel Gruss, and Stefan Mangard show in 'When Good Kernel Defenses Go Bad' that enabling certain hardening defenses (strict memory permissions, kernel heap virtualization, or stack virtualization) ironically exposes fine-grained TLB-contention patterns. Across a study of 127 defenses, these leaks reveal the locations of security-critical kernel objects, enabling reliable, stable exploitation even with state-of-the-art mitigations on. [[source]](https://www.usenix.org/conference/usenixsecurity25/presentation/maar-kernel)
- **CCS 2025: 'Reviving Discarded Vulnerabilities' via Control Metadata Fields (MetaXploit)** *(2025)* — Xiaochen Zou, Guoren Li, Weiteng Chen, Hang Zhang, and Zhiyun Qian (CCS '25) introduce exploitation of Control Metadata Fields (CMFs) inside kernel objects rather than traditional data/function pointers, reviving bugs previously triaged as unexploitable. The work argues many discarded Linux kernel vulnerabilities warrant re-evaluation because corrupting these metadata fields yields usable primitives. [[source]](https://dl.acm.org/doi/10.1145/3719027.3744841)
