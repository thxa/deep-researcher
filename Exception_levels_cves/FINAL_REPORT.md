# ARM64 Exception Level (EL0–EL3) Security Vulnerabilities: Comprehensive Research Report

**Date:** 2026-07-15  
**Methodology:** 12 parallel Kimi-powered research agents (2 per sub-topic: technical depth + practical/real-world), compiled and synthesized by orchestrator  
**Sources:** NVD, CISA KEV, Android Security Bulletins, Google Project Zero, ARM documentation, Linux kernel source, vendor advisories, peer-reviewed papers

---

## Executive Summary

ARM64's four Exception Levels (EL0–EL3) form the hardware privilege hierarchy for billions of mobile, server, and embedded devices. Each level boundary represents an attack surface, and real-world adversaries — from commercial spyware vendors to nation-state actors — routinely chain vulnerabilities across multiple levels to achieve full device compromise.

**Key findings:**

1. **EL0→EL1 (App→Kernel)** is the most exploited boundary. GPU drivers (Mali, Adreno), Binder, and media parsers are the dominant attack surfaces. Notable in-the-wild CVEs include CVE-2019-2215, CVE-2024-43047, and CVE-2024-4610.

2. **EL1 Kernel vulnerabilities** cluster around UAF, OOB, and race conditions in device drivers. Android's GKI reduces fragmentation but vendor GPU/DSP drivers remain the primary attack surface. The "patch gap" (upstream fix → device OTA) creates n-day exploitation windows that have historically ranged from 2 to 19+ months in documented cases.

3. **EL2 Hypervisor** exploitation is emerging. Samsung RKP has multiple documented bypasses (CVE-2019-19273, CVE-2020-25053). Google's pKVM has its first confirmed vulnerability (CVE-2025-22413). Cloud ARM64 hypervisors (AWS Graviton/Nitro, Azure Cobalt) have no documented public escapes yet.

4. **EL3/TrustZone** compromise equals full device ownership. Qualcomm QSEE has the longest vulnerability history (CVE-2015-6639 through present). TF-A has 17+ security advisories. The GlobalConfusion research found 14 critical 0-days across 14,777 trusted applications.

5. **Hardware mitigations** (PAC, MTE, BTI, PAN, PXN, CFI) raise attacker cost but are consistently bypassed via **coverage gaps** — untagged GPU memory, async-MTE timing windows, and data-only attacks — rather than cryptographic breaks.

6. **Full-chain cost** is estimated at $700K–$1.4M+, with commercial spyware vendors (Pegasus, Predator) charging governments millions per deployment.

---

## Table of Contents

1. [ARM64 Exception Level Architecture](#1-arm64-exception-level-architecture)
2. [EL0 → EL1: Userspace to Kernel](#2-el0--el1-userspace-to-kernel)
3. [EL1: Kernel Vulnerabilities](#3-el1-kernel-vulnerabilities)
4. [EL2: Hypervisor Vulnerabilities](#4-el2-hypervisor-vulnerabilities)
5. [EL3: Secure Monitor / TrustZone](#5-el3-secure-monitor--trustzone)
6. [Cross-EL Attack Chains](#6-cross-el-attack-chains)
7. [Hardware Mitigations & Bypasses](#7-hardware-mitigations--bypasses)
8. [Key Takeaways & Defensive Recommendations](#8-key-takeaways--defensive-recommendations)
9. [CVE Reference Table](#9-cve-reference-table)
10. [Sources & References](#10-sources--references)

---

## 1. ARM64 Exception Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│ EL3: Secure Monitor (ARM Trusted Firmware / TF-A)        │  ← Highest privilege
│      Controls world switching (SCR_EL3.NS bit)           │
├──────────────────────────┬───────────────────────────────┤
│   Normal World           │   Secure World                │
├──────────────────────────┤───────────────────────────────┤
│ EL2: Hypervisor          │                               │
│      KVM, pKVM, RKP, Xen │   (No secure EL2 until RME)  │
├──────────────────────────┤───────────────────────────────┤
│ EL1: OS Kernel           │ S-EL1: TEE Kernel             │
│      Linux/Android       │   OP-TEE, QSEE, TEEGRIS      │
├──────────────────────────┤───────────────────────────────┤
│ EL0: Applications        │ S-EL0: Trusted Applications   │
│      Apps, browsers      │   KeyMaster, Widevine, DRM    │
└──────────────────────────┴───────────────────────────────┘
```

**Transition instructions:**
- `SVC` (Supervisor Call): EL0 → EL1 — system calls
- `HVC` (Hypervisor Call): EL1 → EL2 — hypervisor services, PSCI
- `SMC` (Secure Monitor Call): EL1/EL2 → EL3 — TEE services, firmware
- `ERET`: return to lower EL from any higher EL

**Key registers at each boundary:**
- `VBAR_ELn` — exception vector base addresses
- `ELR_ELn` / `SPSR_ELn` — saved PC and processor state
- `TTBR0_EL1` / `TTBR1_EL1` — userspace / kernel page table bases
- `VTTBR_EL2` — Stage-2 (hypervisor) page table base
- `SCR_EL3` — controls secure/non-secure world switching

---

## 2. EL0 → EL1: Userspace to Kernel

### 2.1 Attack Surface

The EL0/EL1 boundary is the richest attack surface because every syscall, ioctl, and driver interface crosses it. Primary targets:

| Attack Surface | Why It's Targeted | Example CVEs |
|---------------|-------------------|--------------|
| **GPU drivers** (Mali, Adreno/KGSL) | Complex memory management, reachable from app sandbox | CVE-2024-4610, CVE-2022-22706, CVE-2025-0072 |
| **Binder IPC** | Android's universal IPC, complex reference counting | CVE-2019-2215, CVE-2024-56556 |
| **Media parsers** | Process untrusted data (images, video, audio) | CVE-2023-0266 (ALSA), Samsung Quram |
| **perf / io_uring / futex** | High-performance interfaces with complex state | CVE-2023-6931, CVE-2023-2008 |
| **DSP/compute drivers** | ML accelerator interfaces (fastrpc) | CVE-2024-43047 |
| **32-bit compat layer** | Type confusion from 32→64-bit struct conversion | Multiple compat syscall bugs |

### 2.2 Vulnerability Classes

- **Use-After-Free (UAF):** Most common class. Object freed while still referenced; reclaimed with attacker-controlled data. Examples: Binder epoll UAF (CVE-2019-2215), KGSL timeline fence UAF (CVE-2022-22057), Mali JIT UAF (CVE-2024-4610).
- **Out-of-Bounds (OOB) Read/Write:** Buffer overflows in driver ioctls. Examples: ALSA USB descriptor OOB (CVE-2024-53197), perf_read_group heap OOB (CVE-2023-6931).
- **Race Conditions:** TOCTOU in concurrent driver paths. Examples: fastrpc mmap/munmap race (CVE-2024-43047), ALSA compat ioctl missing lock (CVE-2023-0266).
- **Type Confusion:** Misinterpretation of object types, especially in compat layers and media parsers.

### 2.3 Notable Real-World Exploits

**CVE-2019-2215 ("Bad Binder")** — The canonical ARM64 EL0→EL1 exploit. A Binder UAF (epoll + binder_thread) was exploited by NSO Group's Pegasus to compromise Pixel 1/2. The upstream fix existed for 19 months before it reached Android devices.

**Samsung Quram DNG (2024–2025)** — A malformed DNG image sent via WhatsApp triggered an OOB write in Samsung's closed-source Quram image library, eventually achieving kernel R/W. Linked to the Landfall commercial spyware.

**CVE-2024-43047 (Qualcomm fastrpc)** — UAF in DMA buffer reference counting, confirmed exploited in the wild targeting journalists. Affects 60+ Qualcomm chipsets.

**CVE-2025-0072 (Mali CSF UAF)** — A UAF in Mali CSF queue binding demonstrated that GPU-managed memory is not MTE-tagged by SLUB, allowing exploitation via untagged page reclamation with pipe_buffer even on MTE-enabled devices like Pixel 8.

### 2.4 The Patch Gap Problem

The time between an upstream kernel fix and a device OTA consistently creates exploitation windows:

| CVE | Upstream Fix | Device Patch | Gap |
|-----|-------------|--------------|-----|
| CVE-2019-2215 | Feb 2018 | Oct 2019 | ~19 months |
| CVE-2023-0266 | Jan 2023 | Mar 2023 | ~2 months (but bug existed since 2017 refactor) |
| CVE-2022-22706 | Jan 2022 | Jun 2022 | ~5 months |

---

## 3. EL1: Kernel Vulnerabilities

### 3.1 Kernel Attack Surfaces on ARM64

Beyond the EL0→EL1 crossing, kernel vulnerabilities matter because they can enable lateral movement to EL2 or persistence. Key surfaces:

- **GPU driver internals:** Mali (midgard/bifrost/valhall) and Adreno (kgsl) manage GPU memory, JIT, command streams, and fence objects. Their complexity and direct physical memory access make them the highest-value kernel target.
- **Vendor kernel forks:** Samsung Exynos, Qualcomm MSM, MediaTek kernels add hundreds of thousands of lines of proprietary driver code not subject to upstream Linux review.
- **High-performance subsystems:** eBPF verifier bugs, io_uring async state management, and perf event handling have produced a steady stream of CVEs.

### 3.2 Exploitation Primitives on ARM64

Modern ARM64 kernel exploitation follows established patterns:

| Primitive | Technique | Bypasses |
|-----------|-----------|----------|
| **Heap reclamation** | Cross-cache, slab cache manipulation | INIT_ON_ALLOC (zeroes freed objects) |
| **Arbitrary R/W** | Dirty Pagetable, pipe_buffer corruption | PAN, PXN (but data-only) |
| **Credential overwrite** | DirtyCred (file struct swap) | kCFI, PAC (irrelevant to data-only) |
| **Code execution** | modprobe_path, call_usermodehelper | SELinux (if enforcing) |
| **KASLR defeat** | perf callchain leak, prefetch timing | Entropy: ~9-10 bits on ARM64 |

### 3.3 Post-Compromise Barriers

Modern ARM64 Android devices deploy multiple barriers after kernel compromise:

- **Samsung RKP/KDP:** Hypervisor-level (EL2) protection of kernel credentials, page tables, and SELinux state. Bypass documented via AVC cache poisoning and root-process stack hijacking.
- **Google pKVM:** Protected KVM at EL2 isolates the kernel from itself. Prevents direct physical memory access from a compromised EL1.
- **Verified Boot (AVB):** Prevents persistent filesystem modifications. Attackers use memory-only implants or target partitions not covered by AVB.

---

## 4. EL2: Hypervisor Vulnerabilities

### 4.1 Architecture

EL2 controls Stage-2 address translation (IPA → PA), VMID-tagged TLBs, and trap-and-emulate for device I/O. Key implementations:

| Hypervisor | Platform | Role |
|-----------|----------|------|
| **KVM/ARM** | Linux servers, Android | General-purpose VM management |
| **pKVM** | Android 13+ | Protected KVM; isolates kernel from VMs |
| **Samsung RKP** | Galaxy devices | Kernel integrity protection |
| **Xen on ARM** | Cloud, embedded | Multi-VM isolation |
| **AWS Nitro** | Graviton instances | Minimized cloud hypervisor |

### 4.2 Attack Surfaces

- **HVC interface:** Hypervisor calls from EL1 — argument validation bugs, missing checks on vCPU state
- **Stage-2 page table manipulation:** Bugs in IPA→PA mapping can break VM isolation
- **MMIO trap handling:** Emulated device accesses; parsing complexity creates bugs
- **TLB invalidation races:** CPU errata where TLBI completion races with memory accesses

### 4.3 Notable CVEs

| CVE | Component | Impact |
|-----|-----------|--------|
| **CVE-2025-22413** | pKVM hyp-main.c | Protected vCPU could run before entering PSCI runnable state; information disclosure (High) |
| **CVE-2025-10263 (XSA-493)** | Xen ARM TLB | TLBI ordering erratum lets guest write to unmapped memory |
| **CVE-2018-18021** | KVM ARM | Control-flow redirection via manipulated guest registers |
| **CVE-2024-26598** | KVM GIC-ITS | UAF in interrupt translation service |
| **CVE-2019-19273** | Samsung RKP | Arbitrary write to hypervisor-protected memory |
| **CVE-2020-25053** | Samsung RKP | Arbitrary code execution in the hypervisor |

### 4.4 Cloud vs. Mobile

- **Mobile:** Samsung RKP and pKVM have documented bypasses and CVEs. RKP is the best real-world benchmark for ARM64 EL2 exploitation.
- **Cloud:** AWS Graviton (Nitro), Azure Cobalt, Google Axion have **no documented public VM escapes**, but they share the same KVM/ARM64 CVE surface. AWS Nitro's minimized design and removed admin access represent the strongest current cloud posture.

---

## 5. EL3: Secure Monitor / TrustZone

### 5.1 Architecture

EL3 runs the Secure Monitor (typically ARM Trusted Firmware / TF-A), which controls world switching between Normal and Secure states. The Secure World runs a TEE kernel at S-EL1 and Trusted Applications at S-EL0.

**Why EL3/TrustZone compromise is catastrophic:**
- Full control over both Normal and Secure worlds
- Access to all cryptographic keys (FDE, DRM, biometric)
- Undetectable persistence (invisible to Android OS)
- Can modify the Normal-world kernel from the Secure side

### 5.2 TEE Implementations and Vulnerability History

| TEE | Vendor | Notable Issues |
|-----|--------|----------------|
| **QSEE/QTEE** | Qualcomm | CVE-2015-6639 (Widevine code exec), CVE-2017-18141 (confused deputy SMC), CVE-2018-11976 (ECDSA key leak), FDE key extraction chain |
| **TEEGRIS** | Samsung | CVE-2019-20545 (HDCP overflow), CVE-2020-10837 (stack overflow), pre-2020: no ASLR, no stack cookies |
| **Kinibi** | Trustonic/Samsung | Pre-v400: no rollback protection, no ASLR |
| **OP-TEE** | Linaro/Open source | CVE-2019-101029x series, CVE-2022-46152, CVE-2025-46733 (fTPM PCR reset via tee-supplicant return-code sanitization) |
| **TF-A** | ARM | 17+ advisories (TFV-1 through TFV-17): SMC validation failures, X.509 parser bugs, register leaks, CPU errata |

### 5.3 Critical Research Findings

**GlobalConfusion (2024):** Found 14 critical 0-days across 14,777 Trusted Applications by exploiting a GlobalPlatform API design weakness. Affects billions of devices.

**Project Zero TEE research (2017):** Demonstrated that trustlet revocation was effectively unused across 45+ firmware images. Patched devices remained vulnerable to old trustlet rollback.

**Qualcomm FDE key extraction:** A chain from QSEE code execution to extracting Android full-disk encryption keys, demonstrating that TrustZone compromise directly undermines data-at-rest security.

### 5.4 Research Tools

| Tool | Target | Approach |
|------|--------|----------|
| **PARTEMU** | OP-TEE, QSEE | Rehosting TEE in QEMU for fuzzing |
| **TEEzz** | Multiple TEEs | Automated TA interface fuzzing |
| **EL3XIR** | TF-A / EL3 | EL3 monitor fuzzing |
| **GPCheck** | GlobalPlatform TAs | Systematic TA security validation |

---

## 6. Cross-EL Attack Chains

### 6.1 Chain Architecture

Real-world attacks chain across exception levels. The typical progression:

```
[Entry Point]          [EL0 → EL1]           [EL1 → EL2]        [EL2 → EL3]
0-click message  →  kernel driver UAF  →  HVC/SMC abuse  →  secure monitor bug
or browser RCE      → arbitrary R/W        or pte corruption    → TEE compromise
                     → root                 → hypervisor bypass   → full device
```

### 6.2 Commercial Spyware Chains

| Campaign | Entry | Kernel Stage | Higher Levels | Dates |
|----------|-------|-------------|---------------|-------|
| **NSO Pegasus** | iMessage 0-click (FORCEDENTRY: CVE-2021-30860) | Binder UAF (CVE-2019-2215) or equivalent | Implant persistence | 2016–present |
| **Intellexa Predator** | Chrome Portals UAF (CVE-2021-37973) → kernel epoll UAF (CVE-2021-1048) | Also: V8 type confusion (CVE-2023-4762) → Adreno GPU (CVE-2023-33106) | Implant framework | 2021–2023 |
| **Quadream** | iMessage 0-click (ENDOFDAYS) | iOS kernel exploit | Implant persistence | 2021–2023 |
| **Samsung Quram/Landfall** | DNG image via WhatsApp | Quram OOB → kernel R/W | N/A (EL1 sufficient) | 2024–2025 |

### 6.3 Rooting and Bootloader Chains

| Tool/Method | Mechanism | EL Levels Crossed |
|-------------|-----------|-------------------|
| **Magisk** | Boot image patching (requires unlocked bootloader) | Modifies EL1 init |
| **KernelSU/APatch** | Kernel module/patch injection | EL1 modification |
| **Qualcomm EDL** | Emergency Download mode — physical R/W at EL3 level | EL3 access |
| **MediaTek BROM/kamakiri** | Boot ROM exploit + DMA → arbitrary memory | Below EL3 |
| **mtk-su** | MediaTek command queue driver → kernel R/W | EL0→EL1 |

### 6.4 Cost of Full Chains

Full-chain ARM64 exploits are estimated to cost **$700K–$1.4M+** to develop. Exploit brokers have reportedly listed prices exceeding $2M for Android full-chain with persistence. The cost is driven by:
- Multiple independent vulnerabilities required
- Each mitigation bypass adds development time
- Device/SoC fragmentation requires per-target adaptation
- Short shelf life due to monthly Android security bulletins

---

## 7. Hardware Mitigations & Bypasses

### 7.1 Mitigation Summary

| Mitigation | ARM Version | What It Protects | Deployment Status |
|-----------|------------|-----------------|-------------------|
| **PAC** | ARMv8.3 | Return addresses, function pointers | iOS: always-on (A12+); Android: partial |
| **MTE** | ARMv8.5 | Heap memory safety (spatial+temporal) | Android: Pixel 8+ (opt-in, mostly async) |
| **BTI** | ARMv8.5 | Forward-edge control flow | Linux kernel: enabled on supporting CPUs |
| **PAN** | ARMv8.1 | Kernel access to user memory | Widely deployed |
| **PXN** | ARMv8.0 | Kernel execution of user memory (ret2user) | Universal on ARMv8 |
| **KASLR** | Software | Kernel address randomization | Universal (~9-10 bits entropy) |
| **kCFI** | Software (Clang) | Indirect call type checking | Android GKI 6.1+ |
| **Shadow Call Stack** | Software | Return address integrity | Android GKI |
| **INIT_ON_ALLOC** | Software | Zero freed memory | Most Android kernels |

### 7.2 Bypass Patterns

**The dominant pattern: coverage gaps, not cryptographic breaks.**

| Mitigation | Primary Bypass Method | Example |
|-----------|----------------------|---------|
| **PAC** | Data-only attacks; signing gadgets; PACMAN speculative leak | iOS FORCEDENTRY (logic-only), kernel cred overwrite |
| **MTE** | Untagged GPU memory; async-MTE timing window; TikTag speculative tag leak; 1/16 brute force | CVE-2025-0072 (Mali page not tagged by SLUB) |
| **BTI** | Coarse-grained (function-entry only); data-only attacks bypass entirely | Any heap corruption exploit |
| **PAN** | copy_to/from_user gadgets; kernel virtual address operations | Standard in all modern exploits |
| **KASLR** | Info leaks (perf callchain, /proc, driver leaks); prefetch side channels | CVE-2021-25369 (Samsung sec_log) |
| **kCFI** | Data-only corruption; type-compatible gadgets | DirtyCred, AVC cache poisoning |
| **Shadow Call Stack** | Data-only attacks don't need return addresses | Credential/modprobe_path overwrites |

### 7.3 Future Mitigations

- **ARM CCA (Confidential Compute Architecture) / RME (Realm Management Extension):** Adds a fourth world (Realm) at EL2 for confidential VMs. Hardware-enforced memory encryption per realm.
- **CHERI (Capability Hardware Enhanced RISC Instructions):** Fat pointers with hardware-enforced bounds and permissions. ARM Morello prototype exists but not in production.
- **Deterministic MTE (IUBIK model):** Two-tag isolation between user-controlled kernel objects and core kernel memory. Harder to bypass than probabilistic random tagging.

---

## 8. Key Takeaways & Defensive Recommendations

### For Defenders

1. **Patch velocity is paramount.** The patch gap is the single largest systemic risk. Monthly Android security bulletins are meaningless if OEMs take 6+ months to ship OTAs.

2. **GPU/DSP drivers are the #1 kernel attack surface.** Mali, Adreno, and fastrpc drivers account for more in-the-wild exploits than all other kernel surfaces combined. Prioritize driver audit and sandboxing.

3. **MTE must be synchronous to be effective.** Async-MTE provides a timing window for exploitation. Enable sync-MTE for security-critical processes.

4. **Hypervisor-level protection works but has limits.** Samsung RKP and Google pKVM raise the bar significantly but have documented bypasses. Defense-in-depth across all levels is essential.

5. **TrustZone is a high-value, under-audited target.** TEE implementations often lack basic exploit mitigations (ASLR, stack cookies, rollback protection). Trustlet revocation must be enforced.

6. **Monitor for coverage gaps.** Mitigations are bypassed where they don't apply (untagged GPU memory, unprotected AVC caches, non-CFI driver code). Map your mitigation coverage.

### For Researchers

7. **Data-only attacks are the future.** PAC, BTI, CFI, and SCS all protect control flow. The field has shifted to corrupting data structures (credentials, SELinux state, page tables) that are not protected by these mitigations.

8. **Cross-EL chains are the gold standard.** Single-level exploits are becoming less valuable as post-compromise barriers (RKP, pKVM, verified boot) become more robust.

9. **TEE fuzzing is an open frontier.** Tools like PARTEMU, TEEzz, and EL3XIR have found bugs in every TEE they've been applied to. The GlobalConfusion research shows systemic API-level weaknesses.

---

## 9. CVE Reference Table

| CVE | EL Boundary | Component | Type | Exploited ITW | Impact |
|-----|------------|-----------|------|--------------|--------|
| CVE-2019-2215 | EL0→EL1 | Binder | UAF | ✅ (Pegasus) | Full device compromise |
| CVE-2022-22057 | EL0→EL1 | Qualcomm KGSL | UAF race | Research | Root, bypass RKP/KDP |
| CVE-2022-22706 | EL0→EL1 | Mali GPU | UAF | ✅ | Kernel code execution |
| CVE-2023-0266 | EL0→EL1 | ALSA compat | Race/UAF | ✅ | Kernel R/W |
| CVE-2023-26083 | EL0→EL1 | Mali tlstream | Info leak | ✅ | KASLR bypass |
| CVE-2023-6931 | EL0→EL1 | perf | Heap OOB | Research | Kernel R/W |
| CVE-2024-4610 | EL0→EL1 | Mali GPU | UAF | ✅ | Kernel R/W |
| CVE-2024-43047 | EL0→EL1 | Qualcomm fastrpc | UAF race | ✅ | Full device compromise |
| CVE-2024-53197 | EL0→EL1 | ALSA USB | OOB | ✅ | Kernel R/W |
| CVE-2025-0072 | EL0→EL1 | Mali CSF | UAF | Research | MTE bypass, root |
| CVE-2018-18021 | EL1→EL2 | KVM ARM | Control flow | Research | Host compromise |
| CVE-2024-26598 | EL1→EL2 | KVM GIC-ITS | UAF | Research | Hypervisor compromise |
| CVE-2025-22413 | EL1→EL2 | pKVM | Logic error | Research | Information disclosure (High) |
| CVE-2025-10263 | EL1→EL2 | Xen ARM TLB | Race | Research | VM isolation bypass |
| CVE-2019-19273 | EL1→EL2 | Samsung RKP | Arb write | Research | Hypervisor bypass |
| CVE-2020-25053 | EL1→EL2 | Samsung RKP | Code exec | Research | Full hypervisor control |
| CVE-2015-6639 | EL1→S-EL1 | Qualcomm QSEE/Widevine | Priv esc | Research | TEE code execution |
| CVE-2017-18141 | EL1→EL3 | Qualcomm SMC | Confused deputy | Research | Secure monitor access |
| CVE-2018-11976 | S-EL1 | Qualcomm QSEE | Side channel | Research | ECDSA key extraction |
| CVE-2021-30860 | EL0 (iOS) | CoreGraphics | Logic/integer | ✅ (Pegasus) | Sandbox escape |
| CVE-2021-1048 | EL0→EL1 | epoll | UAF | ✅ (Predator) | Kernel R/W |

---

## 10. Sources & References

### Primary Sources
- ARM Architecture Reference Manual (ARMv8-A): https://developer.arm.com/documentation/ddi0487/latest
- Linux kernel ARM64 documentation: https://docs.kernel.org/arch/arm64/
- Android Security Bulletins: https://source.android.com/docs/security/bulletin
- NVD (National Vulnerability Database): https://nvd.nist.gov/
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Research & Analysis
- Google Project Zero blog: https://projectzero.google/
- ARM Trusted Firmware security advisories: https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories/index.html
- Xen Security Advisories: https://xenbits.xenproject.org/xsa/
- GitHub Security Lab (Android kernel research): https://github.blog/security/
- OP-TEE documentation: https://optee.readthedocs.io/

### Papers & Presentations
- PACMAN (Ravichandran et al., ISCA 2022): Speculative PAC bypass
- TikTag (Kim et al., 2024): Speculative MTE tag leakage
- GlobalConfusion (2024): Systematic TEE trustlet vulnerability discovery
- PARTEMU (Harrison et al., USENIX 2020): TEE rehosting for fuzzing
- EL3XIR: EL3 monitor fuzzing framework
- BlindSide (2020): Speculative probing for KASLR bypass

### Detailed Sub-Topic Reports
All intermediate research documents are available in the `docs/` directory:
- [01-el0-el1-technical.md](docs/01-el0-el1-technical.md) / [01-el0-el1-practical.md](docs/01-el0-el1-practical.md)
- [02-el1-kernel-technical.md](docs/02-el1-kernel-technical.md) / [02-el1-kernel-practical.md](docs/02-el1-kernel-practical.md)
- [03-el2-hypervisor-technical.md](docs/03-el2-hypervisor-technical.md) / [03-el2-hypervisor-practical.md](docs/03-el2-hypervisor-practical.md)
- [04-el3-trustzone-technical.md](docs/04-el3-trustzone-technical.md) / [04-el3-trustzone-practical.md](docs/04-el3-trustzone-practical.md)
- [05-cross-el-chains-technical.md](docs/05-cross-el-chains-technical.md) / [05-cross-el-chains-practical.md](docs/05-cross-el-chains-practical.md)
- [06-mitigations-technical.md](docs/06-mitigations-technical.md) / [06-mitigations-practical.md](docs/06-mitigations-practical.md)

---

*Report compiled from 12 parallel Kimi-powered research agents. Total intermediate research: ~268 KB across 3,035 lines. Each sub-topic was investigated from two independent angles (technical depth + practical/real-world) to ensure comprehensive coverage.*
