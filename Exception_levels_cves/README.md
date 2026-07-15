# ARM64 Exception Levels & CVEs

> **~38,600 words** across **14 documents** — comprehensive vulnerability research covering ARM64 EL0 through EL3 security boundaries, real-world CVEs, cross-EL attack chains, and hardware mitigation bypasses.

## Overview

This track provides a deep analysis of security vulnerabilities at each ARM64 Exception Level (EL0–EL3), how attackers chain across levels, and how hardware mitigations are bypassed in practice. Each sub-topic is researched from two independent angles: **technical depth** (architecture, mechanisms, CVE internals) and **practical/real-world** (case studies, impact, vendor response).

## Prerequisites

- Familiarity with ARM64 architecture basics (registers, memory model)
- Understanding of operating system concepts (kernel, userspace, virtual memory)
- Basic knowledge of vulnerability classes (UAF, OOB, race conditions)
- Recommended prior reading: [`linux_kernel/`](../linux_kernel/), [`android_and_CVEs/`](../android_and_CVEs/), [`ring_and_vulns/`](../ring_and_vulns/)

## Reading order

| # | Document | Topic | Est. time |
|---|----------|-------|-----------|
| 1 | [`FINAL_REPORT.md`](FINAL_REPORT.md) | **Start here** — compiled report with executive summary, CVE table, and recommendations | 25 min |
| 2 | [`docs/01-el0-el1-technical.md`](docs/01-el0-el1-technical.md) | EL0→EL1 boundary: exception vectors, SVC dispatch, attack surfaces | 20 min |
| 3 | [`docs/01-el0-el1-practical.md`](docs/01-el0-el1-practical.md) | Real-world EL0→EL1 exploits: Pegasus, Quram/Landfall, fastrpc | 18 min |
| 4 | [`docs/02-el1-kernel-technical.md`](docs/02-el1-kernel-technical.md) | Kernel attack surfaces, vulnerability classes, GKI, hardening | 25 min |
| 5 | [`docs/02-el1-kernel-practical.md`](docs/02-el1-kernel-practical.md) | Vendor-specific kernels, patch gaps, post-compromise barriers | 18 min |
| 6 | [`docs/03-el2-hypervisor-technical.md`](docs/03-el2-hypervisor-technical.md) | Hypervisor architecture: KVM, pKVM, Xen, Stage-2 translation | 20 min |
| 7 | [`docs/03-el2-hypervisor-practical.md`](docs/03-el2-hypervisor-practical.md) | Cloud ARM64 hypervisors, Samsung RKP, pKVM deployment | 20 min |
| 8 | [`docs/04-el3-trustzone-technical.md`](docs/04-el3-trustzone-technical.md) | TrustZone architecture, TF-A, TEE implementations, SMC surface | 30 min |
| 9 | [`docs/04-el3-trustzone-practical.md`](docs/04-el3-trustzone-practical.md) | Real-world TrustZone attacks: QSEE, TEEGRIS, key extraction | 25 min |
| 10 | [`docs/05-cross-el-chains-technical.md`](docs/05-cross-el-chains-technical.md) | Cross-EL chain architecture: primitives at each transition | 25 min |
| 11 | [`docs/05-cross-el-chains-practical.md`](docs/05-cross-el-chains-practical.md) | Commercial spyware chains, rooting tools, full-chain costs | 25 min |
| 12 | [`docs/06-mitigations-technical.md`](docs/06-mitigations-technical.md) | PAC, MTE, BTI, PAN, PXN, KASLR, CFI — architecture & bypasses | 20 min |
| 13 | [`docs/06-mitigations-practical.md`](docs/06-mitigations-practical.md) | Mitigation effectiveness in the wild, iOS vs Android, future directions | 20 min |
| 14 | [`VERIFICATION.md`](VERIFICATION.md) | Quality audit: CVE accuracy checks, source verification, gap analysis | 10 min |

**Total estimated reading time:** ~5 hours

## Related tracks

| Track | Relationship |
|-------|-------------|
| [`ring_and_vulns/`](../ring_and_vulns/) | CPU protection rings (x86 focus) — complementary to ARM64 exception levels |
| [`linux_kernel/`](../linux_kernel/) | Deeper kernel internals and exploitation techniques |
| [`android_and_CVEs/`](../android_and_CVEs/) | Android-specific architecture, SELinux, Binder, vendor landscape |
| [`zero_day/`](../zero_day/) | Exploitation methodology and fundamentals |
| [`fuzzing_vuln_research/`](../fuzzing_vuln_research/) | Kernel and driver fuzzing (syzkaller, TEE fuzzers) |

## Key topics covered

- **21+ CVEs** analyzed in detail across all four exception levels
- **ARM64 exception vector dispatch** — SVC, HVC, SMC calling conventions
- **GPU driver exploitation** — Mali and Adreno as primary EL0→EL1 attack surface
- **Hypervisor security** — KVM/ARM, pKVM, Samsung RKP, Xen Stage-2
- **TrustZone/TEE** — QSEE, TEEGRIS, OP-TEE, TF-A advisories, GlobalConfusion
- **Commercial spyware** — Pegasus, Predator, Quadream chain analysis
- **Hardware mitigation analysis** — PAC/PACMAN, MTE/TikTag, BTI, KASLR bypasses
- **Patch gap analysis** — upstream-to-device OTA delay patterns
