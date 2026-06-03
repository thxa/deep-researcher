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
## References

- Intel 64 and IA-32 Architecture Software Developer's Manual. Intel Corporation.
- AMD64 Architecture Programmer's Manual. AMD.
- UEFI Specification, Version 2.10. Unified Extensible Firmware Interface Forum.
- Rafal Wojtczuk, "Attacking Intel BIOS," coreboot/CHIPSEC research.
- ESET Research, "LoJax: First UEFI bootkit found in the wild," 2018.
- Kaspersky, "MoonBounce: Dark side of the UEFI bootkit," 2022.
- Kaspersky, "CosmicStrand: Sophisticated UEFI bootkit," 2022.
- Intel Management Engine research — Igor Skochinsky, Positive Technologies.
- Positive Technologies, "Intel ME: Myths and Reality."
- CVE-2015-3456 (VENOM) — QEMU Floppy Disk Controller Heap Overflow.
- Android Security Bulletin — https://source.android.com/docs/security/bulletin


---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-22224 — VMware ESXi/Workstation TOCTOU VM escape (Ring -1)** *(2025-03)* — A critical TOCTOU race-condition (CWE-367) in VMware ESXi and Workstation causes an out-of-bounds write that lets an attacker with local admin in a guest VM execute code as the host VMX process, achieving full VM escape. Broadcom rated it CVSS 9.3 (NVD 8.2); it was patched on March 4, 2025 and added to CISA KEV after confirmed in-the-wild exploitation, chained with CVE-2025-22225 (arbitrary kernel write) and CVE-2025-22226 (HGFS info leak) by ransomware actors. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-22224)
- **CVE-2025-7026..7029 — Gigabyte UEFI SMM callout flaws enabling Ring -2 code execution** *(2025-07)* — Binarly's REsearch team disclosed four SMM callout vulnerabilities in Gigabyte UEFI firmware (originally AMI Aptio issues that resurfaced) via CERT/CC VU#746790 in July 2025. Each abuses unvalidated attacker-controlled pointers (e.g. the RBX/RCX registers in CommandRcx0 and flash function blocks) to perform arbitrary writes into SMRAM, allowing arbitrary code execution in System Management Mode (Ring -2), disabling Secure Boot and installing persistent firmware implants beneath the OS and hypervisor. [[source]](https://kb.cert.org/vuls/id/746790)
- **CVE-2025-62215 — Windows Kernel race-condition double-free, exploited in the wild (Ring 0)** *(2025-11)* — Microsoft patched a Windows Kernel elevation-of-privilege flaw (CWE-362 race condition leading to CWE-415 double free, CVSS 7.0) on November 11, 2025, affecting Windows 10/11 and Server 2019/2022/2025. Improper synchronization when multiple processes access a shared resource lets a local low-privileged attacker win a race to gain SYSTEM; Microsoft flagged it 'Exploitation Detected' and CISA added it to KEV with a December 3, 2025 remediation deadline. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-62215)
- **CVE-2025-3052 — Microsoft-signed UEFI firmware Secure Boot bypass (firmware/boot boundary)** *(2025-06)* — Binarly (advisory BRLY-DVA-2025-001) disclosed an arbitrary-write vulnerability in a Microsoft-signed UEFI module that allows execution of untrusted code, bypassing Secure Boot via an unvalidated NVRAM variable. Published June 10, 2025 with CVSS 8.2, it permits attackers to run code in the pre-OS environment and tamper with firmware configuration, enabling bootkit-style persistence; Microsoft addressed it through DBX revocation updates. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-3052)

### Incidents & In-the-Wild Exploitation

- **CVE-2024-1086 actively weaponized in ransomware campaigns (Ring 0 nf_tables UAF)** *(2025-10)* — On October 31, 2025 CISA confirmed active ransomware exploitation of CVE-2024-1086, a use-after-free in the Linux kernel netfilter nf_tables subsystem (nft_verdict_init) affecting kernels v5.14–v6.6. Operators including RansomHub and Akira use it for post-compromise local privilege escalation to root; reporting prompted urgent patching to v5.15.149+, v6.1.76+, and v6.6.15+, demonstrating real-world adoption of a public kernel LPE primitive. [[source]](https://www.bleepingcomputer.com/news/security/cisa-linux-privilege-escalation-flaw-now-exploited-in-ransomware-attacks/)

### Techniques

- **CVE-2025-8061 — BYOVD Ring-0 exploitation via Lenovo LnvMSRIO.sys driver** *(2025-09)* — Quarkslab (Luis Casvella, September 23, 2025) detailed exploitation of CVE-2025-8061 in Lenovo's signed LnvMSRIO.sys driver, which exposes the WinMsrDev device without access controls and offers IOCTLs for arbitrary physical-memory and MSR read/write. The Bring-Your-Own-Vulnerable-Driver chain leaks kernel addresses via the LSTAR MSR, bypasses SMEP/SMAP with ROP, redirects syscalls to shellcode, and steals the SYSTEM token — a current example of weaponizing a signed driver to bypass EDR/PPL and reach Ring 0. [[source]](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html)

### Research

- **Battering RAM — $50 DRAM interposer breaks Intel SGX and AMD SEV-SNP (Ring -1 confidential computing)** *(2025-10)* — Researchers from KU Leuven and University of Birmingham (De Meulemeester, Oswald, Verbauwhede, Van Bulck) presented Battering RAM in October 2025, a $50 DDR4 interposer placed between CPU and DIMM that dynamically introduces memory aliases at runtime, defeating the boot-time alias checks added after BadRAM. It fully bypasses Intel SGX and AMD SEV-SNP confidential-computing protections, breaking attestation and enabling silent decryption/injection; Intel and AMD consider physical-access attacks out of their threat model. [[source]](https://batteringram.eu/)
