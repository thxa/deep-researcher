# CPU Protection Rings: Vulnerabilities & Exploitation from Ring 3 to Ring −3

A comprehensive technical reference covering the x86/x86-64 privilege hierarchy — from Ring 3 (userland) through Ring 0 (kernel), Ring −1 (hypervisor), Ring −2 (SMM), to Ring −3 (Intel ME/AMD PSP) — documenting vulnerabilities, CVEs, exploitation techniques, and defensive strategies at each boundary. Each ring represents both a security boundary and an attack surface; this track traces the escalation paths that chain across them.

**Difficulty**: 🔴 Advanced  
**Estimated reading time**: ~13 hours  
**Prerequisites**: x86/x64 architecture, operating system fundamentals, virtualization concepts, basic exploitation

---

## Reading Order

| # | Document | Topic |
|---|----------|-------|
| 1 | [ring3_userland_A](docs/ring3_userland_A.md) | Ring 3 architecture, privilege restrictions, vulnerability classes, and boundary mechanics |
| 2 | [ring3_userland_B](docs/ring3_userland_B.md) | Ring 3 attack surface, kernel entry exploitation methodology, and real-world LPE analysis |
| 3 | [ring2_ring1_A](docs/ring2_ring1_A.md) | Rings 1 & 2 architecture, historical context, and modern virtualization overlay usage |
| 4 | [ring2_ring1_B](docs/ring2_ring1_B.md) | Ring transition mechanics, GDT/LDT/call gates, IOPL escalation, and sysret vulnerability class |
| 5 | [ring0_kernel_A](docs/ring0_kernel_A.md) | Ring 0 kernel attack surface, major kernel CVEs, and kernel hardening countermeasures |
| 6 | [ring0_kernel_B](docs/ring0_kernel_B.md) | Advanced kernel exploitation (kROP, heap spraying), rootkits, and eBPF attack surface |
| 7 | [ring_minus1_hypervisor_A](docs/ring_minus1_hypervisor_A.md) | Ring −1 hypervisor architecture, VMCS/VMCB controls, and VM escape CVEs |
| 8 | [ring_minus1_hypervisor_B](docs/ring_minus1_hypervisor_B.md) | Hypervisor exploitation case studies (VENOM, etc.), side channels, and hyperjacking |
| 9 | [ring_minus2_smm_A](docs/ring_minus2_smm_A.md) | Ring −2 SMM architecture, SMRAM/SMRR protection, SMI handler vulnerabilities, and tools |
| 10 | [ring_minus3_me_A](docs/ring_minus3_me_A.md) | Ring −3 Intel ME/AMD PSP architecture, ME firmware internals, and CVE-2017-5705–5715 |
| 11 | [cross_ring_chains_A](docs/cross_ring_chains_A.md) | Multi-ring attack chains — LoJax, Stuxnet, Striped Fly, and full Ring 3→Ring −2 escalation |
| 12 | [cross_ring_chains_B](docs/cross_ring_chains_B.md) | Defense-in-depth across all rings, monitoring/detection strategies, and complete reference card |

## Related Tracks

- [Linux kernel](../linux_kernel/) — Deep-dive into Ring 0 kernel exploitation and hardening
- [Zero-day exploit development](../zero_day/) — Exploitation techniques for 0-day vulnerability research
- [CVE-2023-20938](../CVE-2023-20938/) — Kernel use-after-free case study (Ring 0)
- [MacOS](../MacOS/) — macOS kernel exploit mitigations and comparison with Linux hardening