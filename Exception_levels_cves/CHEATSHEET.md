# ARM64 Exception Levels & CVEs — Cheat Sheet

Quick reference for ARM64 exception level security boundaries, key CVEs, and exploitation patterns.

---

## ARM64 Exception Level Model

```
EL3  Secure Monitor (TF-A)         ← SMC from EL1/EL2
EL2  Hypervisor (KVM/pKVM/RKP/Xen) ← HVC from EL1
EL1  OS Kernel (Linux/Android)      ← SVC from EL0
EL0  Applications (apps, browsers)  ← Userspace
```

| Instruction | Transition | Purpose |
|------------|-----------|---------|
| `SVC #0` | EL0 → EL1 | System calls |
| `HVC #imm` | EL1 → EL2 | Hypervisor calls (PSCI, KVM) |
| `SMC #0` | EL1/EL2 → EL3 | Secure Monitor calls (TEE, firmware) |
| `ERET` | ELn → ELn-1 | Return from exception |

## Key System Registers

| Register | Level | Purpose |
|----------|-------|---------|
| `VBAR_EL1` | EL1 | Exception vector base |
| `TTBR0_EL1` / `TTBR1_EL1` | EL1 | User/kernel page table bases |
| `VTTBR_EL2` | EL2 | Stage-2 page table base |
| `SCR_EL3` | EL3 | Secure/non-secure world control |
| `ELR_ELn` | Any | Saved return address |
| `SPSR_ELn` | Any | Saved processor state |
| `FAR_EL1` | EL1 | Faulting address |
| `ESR_EL1` | EL1 | Exception syndrome |

## Top CVEs by Exception Level

### EL0 → EL1 (App → Kernel)

| CVE | Component | Type | ITW |
|-----|-----------|------|-----|
| CVE-2019-2215 | Binder | UAF | ✅ Pegasus |
| CVE-2024-43047 | Qualcomm fastrpc | UAF race | ✅ |
| CVE-2024-4610 | Mali GPU | UAF | ✅ |
| CVE-2024-53197 | ALSA USB | OOB | ✅ |
| CVE-2023-0266 | ALSA compat | Race/UAF | ✅ |
| CVE-2022-22057 | KGSL fence | UAF race | Research |
| CVE-2025-0072 | Mali CSF | UAF | Research |
| CVE-2023-6931 | perf | Heap OOB | Research |

### EL1 → EL2 (Kernel → Hypervisor)

| CVE | Component | Type |
|-----|-----------|------|
| CVE-2025-22413 | pKVM | Logic error |
| CVE-2025-10263 | Xen ARM TLB | Race |
| CVE-2019-19273 | Samsung RKP | Arb write |
| CVE-2020-25053 | Samsung RKP | Code exec |
| CVE-2018-18021 | KVM ARM | Control flow |
| CVE-2024-26598 | KVM GIC-ITS | UAF |

### EL1 → EL3 / S-EL1 (Kernel → TrustZone)

| CVE | Component | Type |
|-----|-----------|------|
| CVE-2015-6639 | QSEE Widevine | Priv esc |
| CVE-2017-18141 | Qualcomm SMC | Confused deputy |
| CVE-2018-11976 | QSEE | ECDSA key leak |
| CVE-2019-20545 | Samsung TEEGRIS | HDCP overflow |
| CVE-2020-10837 | Samsung TEEGRIS | Stack overflow |
| TFV-1 to TFV-17 | ARM TF-A | Various |

## Exploitation Patterns

### Typical EL0 → EL1 Chain
```
1. Trigger UAF/OOB in kernel driver (GPU, Binder, ALSA, fastrpc)
2. Heap spray to reclaim freed object (cross-cache / pipe_buffer)
3. Achieve arbitrary kernel R/W
4. Overwrite credentials / modprobe_path / SELinux state
5. Root shell
```

### Typical Full-Chain (EL0 → EL3)
```
1. 0-click entry (messaging / media parser)
2. Sandbox escape → privileged process
3. Kernel driver UAF → kernel R/W → root
4. SMC abuse → TrustZone compromise
5. Persistent implant (or memory-only for stealth)
```

### Data-Only Attack Pattern (Bypasses PAC/BTI/CFI/SCS)
```
1. Achieve arbitrary kernel write (via UAF/OOB)
2. Overwrite non-pointer data: cred struct, SELinux AVC cache,
   modprobe_path, pipe_buffer fields
3. Never corrupt a code/function pointer → all control-flow
   mitigations are irrelevant
```

## Hardware Mitigations Quick Reference

| Mitigation | ARM Ver | Protects | Known Bypass |
|-----------|---------|----------|--------------|
| **PAC** | v8.3 | Return addrs, func ptrs | PACMAN (speculative), signing gadgets, data-only |
| **MTE** | v8.5 | Heap spatial+temporal | Untagged GPU mem, async timing, TikTag, 1/16 brute |
| **BTI** | v8.5 | Forward-edge CF | Coarse-grained, data-only bypass |
| **PAN** | v8.1 | Kernel→user access | copy_to/from_user gadgets |
| **PXN** | v8.0 | Kernel exec user pages | ROP/JOP, data-only |
| **KASLR** | Software | Kernel addr random | Info leaks (~9-10 bits entropy) |
| **kCFI** | Software | Indirect call types | Type-compatible gadgets, data-only |
| **SCS** | Software | Return addresses | Data-only (never needs ret addr) |

## TrustZone TEE Implementations

| TEE | Vendor | Key Weakness |
|-----|--------|-------------|
| QSEE/QTEE | Qualcomm | No trustlet revocation, key extraction chains |
| TEEGRIS | Samsung | Pre-2020: no ASLR, no stack cookies |
| Kinibi | Trustonic | Pre-v400: no rollback protection |
| OP-TEE | Open source | DMA-bypass via CSU misconfiguration |
| TF-A | ARM | 17+ advisories (SMC validation, X.509, register leaks) |

## Commercial Spyware Chains

| Campaign | Entry | Kernel | Cost Est. |
|----------|-------|--------|-----------|
| **Pegasus** | 0-click iMessage | Binder UAF variants | $2M+ per target |
| **Predator** | Chrome RCE | epoll/GPU UAF | $2M+ per target |
| **Quadream** | 0-click iMessage | iOS kernel | Unknown |
| **Landfall** | DNG image (WhatsApp) | Quram OOB → kernel R/W | Unknown |

## Key Research Tools

| Tool | Target | Use |
|------|--------|-----|
| syzkaller | Linux kernel | Syscall fuzzing |
| PARTEMU | TEE (QSEE, OP-TEE) | Rehosting for fuzzing |
| TEEzz | Multiple TEEs | TA interface fuzzing |
| EL3XIR | TF-A / EL3 | Secure monitor fuzzing |
| GPCheck | GlobalPlatform TAs | Systematic TA validation |

## Patch Gap Reference

| CVE | Upstream Fix | Device OTA | Gap |
|-----|-------------|------------|-----|
| CVE-2019-2215 | Feb 2018 | Oct 2019 | ~19 months |
| CVE-2023-0266 | Jan 2023 | Mar 2023 | ~2 months |
| CVE-2022-22706 | Jan 2022 | Jun 2022 | ~5 months |

## Quick Links

- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [TF-A Security Advisories](https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories/index.html)
- [NVD](https://nvd.nist.gov/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Project Zero Blog](https://projectzero.google/)
