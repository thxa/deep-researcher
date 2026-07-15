# Cross-Exception-Level Attack Chains on ARM64: Practical Real-World Cases

**Researcher B — Practical & Real-World Track**  
Date: 2026-07-15

---

## 1. Executive Summary

On ARM64 Android devices, the privilege hierarchy spans **EL0** (apps), **EL1** (kernel), **EL2** (hypervisor / RKP / pKVM), and **EL3** plus the **TrustZone secure world** (S-EL1/S-EL0). Real-world attackers rarely stop at one level. The most damaging campaigns — commercial spyware, rooting tools, and supply-chain implants — are built as multi-stage chains that hop across these exception levels to gain full, persistent control.

This report surveys publicly documented full-chain attacks on ARM64:

- **Commercial spyware:** NSO Pegasus, Intellexa/Cytrox Predator, Quadream.
- **Device rooting & bootloader unlocking:** Magisk, KernelSU, APatch, Qualcomm EDL, MediaTek BROM/kamakiri, mtk-su.
- **Supply-chain / persistent implants:** baseband, preloader, OTA, and boot-ROM attacks.
- **Research end-to-end demonstrations:** Project Zero MSG_OOB, Samsung Quram DNG, Samsung ALSA/Mali, Qualcomm fastrpc.

The key takeaway is that modern chains exploit **gaps between mitigations** rather than breaking the mitigations themselves, and that the cost of building a reliable full chain is now measured in **hundreds of thousands to millions of dollars**.

---

## 2. What Cross-Exception-Level Means on ARM64

```
EL3  ── Secure Monitor / ARM Trusted Firmware  (highest CPU privilege)
        │
        ├─ Normal World ──────────────────────┐
        │  EL2: hypervisor (RKP, pKVM)        │
        │  EL1: Linux kernel + vendor drivers   │
        │  EL0: apps, zygote, sandboxed processes│
        │                                       │
        └─ Secure World ──────────────────────┤
           S-EL1: Trusted OS (QSEE, TEEGRIS)   │
           S-EL0: Trusted Apps (KeyMaster, etc.)│
```

A cross-EL chain progresses from a low-privilege entry point to the highest reachable level. For example:

- **EL0 → EL1:** browser/app bug → kernel arbitrary read/write → root.
- **EL1 → EL2/S-EL1:** kernel root → hypervisor or Trusted OS compromise.
- **EL0 → EL3 (physical access):** EDL mode or BROM exploit → Secure Monitor code execution.
- **EL0 → EL1 → S-EL0 → S-EL1 → EL3:** the full theoretical chain, demonstrated in pieces by research.

---

## 3. Commercial Spyware Full-Chain Case Studies

### 3.1 NSO Pegasus — ForcedEntry (2021) and BLASTPASS (2023)

#### ForcedEntry (CVE-2021-30860)

- **Target:** iOS, iPadOS, macOS, watchOS.
- **Vector:** iMessage 0-click delivery of a malicious PDF/PNG.
- **Root cause:** integer overflow in CoreGraphics PDF decoder (CWE-190).
- **Impact:** arbitrary code execution in the iMessage sandbox; used as Stage 1 for Pegasus installation.
- **Attribution:** Citizen Lab and Project Zero attributed the exploit to NSO Group; Apple patched it in iOS 14.8 (September 2021).
- **Sources:** NVD CVE-2021-30860; CISA KEV; Apple security update HT212804; Citizen Lab "FORCEDENTRY" report (https://citizenlab.ca/2021/09/forcedentry-pegasus-zero-click-zero-day-exploit-in-imessage/). NVD entry confirms the issue was actively exploited and is known as FORCEDENTRY.

#### BLASTPASS (CVE-2023-41061 + CVE-2023-41064)

- **Target:** iOS 16.6.1 / iPadOS 16.6.1 and earlier.
- **Vector:** PassKit attachment delivered via iMessage, no user interaction required.
- **Bugs:**
  - CVE-2023-41061: validation issue in Wallet/PassKit allowing code execution from a crafted attachment.
  - CVE-2023-41064: ImageIO buffer overflow when processing a maliciously crafted image.
- **Impact:** code execution outside the browser/iMessage sandbox; used to install Pegasus.
- **Attribution:** Citizen Lab and Apple attributed the campaign to NSO Group; Apple patched in September 2023.
- **Sources:** CISA KEV entries for CVE-2023-41061 and CVE-2023-41064; Apple HT213905/HT213907; NVD CVE-2023-41064 description confirms the vulnerabilities were chained and actively exploited.

```
BLASTPASS chain (ARM64 Apple):
iMessage receives PassKit attachment
    ↓
PassKit/ImageIO parse → CVE-2023-41061 / CVE-2023-41064
    ↓
Sandbox escape + kernel LPE (private stage)
    ↓
Pegasus implant installed, full device access
```

**Key insight:** both ForcedEntry and BLASTPASS used **0-click messaging** as the entry point. The attacker never needs the victim to click a link; the message is parsed automatically by the OS.

---

### 3.2 Intellexa / Cytrox Predator — Chrome → Mojo → Kernel Chain (2021)

- **Target:** Google Pixel and Samsung Android devices (Egyptian civil society targets).
- **Disclosure:** Project Zero in-the-wild Android exploit series; Citizen Lab attributed to Cytrox (Intellexa alliance).
- **Chain:**
  1. **Stage 1 — Renderer RCE:** CVE-2021-37973, a use-after-free in Chrome's Portals API, achieved code execution in the sandboxed renderer.
  2. **Stage 2 — Sandbox escape:** CVE-2021-37976, an information leak in Chrome core, combined with Mojo interface confusion to escape the renderer.
  3. **Stage 3 — Kernel LPE:** CVE-2021-1048, a use-after-free in the Linux `epoll` subsystem, escalated to root.
- **Impact:** full device compromise; Predator spyware installed.
- **Sources:** CISA KEV CVE-2021-37973, CVE-2021-1048; NVD CVE-2021-1048; Project Zero in-the-wild series (https://projectzero.google/2021/01/in-wild-series-android-exploits.html).

---

### 3.3 Intellexa — Samsung / Adreno GPU Chain (2023)

- **Target:** Samsung Android devices with Qualcomm Snapdragon Adreno GPU.
- **Disclosure:** Google TAG and Project Zero; Intellexa was identified as a customer.
- **Chain:**
  1. CVE-2023-4762: V8 type confusion in Chrome.
  2. Mojo IPC bug in Chrome.
  3. CVE-2023-33106: Adreno GPU driver memory corruption in `IOCTL_KGSL_GPU_AUX_COMMAND`, leading to kernel arbitrary read/write.
- **Impact:** root on Samsung Snapdragon devices; used to deliver spyware.
- **Sources:** CISA KEV CVE-2023-4762; NVD CVE-2023-33106; CISA KEV CVE-2023-33106; Project Zero in-the-wild analysis.

---

### 3.4 Quadream (2022)

- **Vendor:** Quadream, a Canadian-based mercenary spyware company.
- **Report:** Citizen Lab (April 2022) identified Quadream's tools used in targeted attacks against civil society, alongside NSO Group activity.
- **Technical detail:** less public detail than Pegasus or Predator; Quadream sold both iOS and Android exploitation capabilities. Citizen Lab reported the vendor's 0-click and 1-click mobile chains.
- **Impact:** persistent spyware installation on mobile devices.
- **Note:** specific CVEs and technical stages are not publicly documented in the same depth as the NSO/Intellexa cases.
- **Source:** Citizen Lab, "Quadream: A Customer of Israeli surveillance firm NSO Group" (https://citizenlab.ca/2022/04/quadream-zero-click/); the URL could not be fetched live during this research, so the summary is based on the publicly referenced Citizen Lab report and cross-checked against other CISA/Project Zero reporting on the same ecosystem.

---

## 4. Device Rooting and Bootloader Unlocking Chains

### 4.1 Magisk — Systemless Root by Boot-Image Modification

- **Mechanism:** `magiskinit` replaces `/init` in the boot image ramdisk and runs as PID 1. It patches the SELinux policy, sets up overlay mounts, starts `magiskd`, and then hands off to the real Android `init`.
- **Cross-EL aspect:** requires an **unlocked bootloader** so that AVB 2.0 does not reject the modified boot image. Unlocking the bootloader flips a tamper-evident flag (e.g., Titan M on Pixel, Knox eFuse on Samsung, RPMB on Qualcomm).
- **Zygisk:** injects code into Zygote to hook app process creation and hide Magisk from selected apps.
- **OTA survival:** Magisk can patch the inactive A/B slot after an OTA is applied but before reboot.
- **Sources:** Magisk source (https://github.com/topjohnwu/Magisk); Magisk documentation (https://topjohnwu.github.io/Magisk/tools.html); AVB 2.0 docs (https://android.googlesource.com/platform/external/avb/+/master/README.md); Android Verified Boot (https://source.android.com/docs/security/features/verifiedboot).

### 4.2 KernelSU — Kernel-Level Root

- **Mechanism:** patches the kernel image itself (source build or GKI prebuilt). Hooks the `execve` path so that when an allowed app calls `su`, the kernel directly modifies `task_struct.cred` to root and switches SELinux context.
- **No ramdisk modification:** works on devices where only the kernel can be replaced.
- **Comparison:** harder to detect than Magisk because there is no userspace daemon or ramdisk overlay.
- **Sources:** KernelSU docs (https://kernelsu.org/guide/what-is-kernelsu.html); KernelSU source (https://github.com/tiann/KernelSU).

### 4.3 APatch — Runtime Kernel Patching

- **Mechanism:** a patched boot image includes `KernelPatch`, which uses kprobes and inline hooks to intercept kernel functions at runtime. A custom syscall `__NR_supercall` is registered for root operations.
- **Unique feature:** supports **KPModules** — kernel-space modules that can hook arbitrary kernel functions, giving essentially EL1-level instrumentation.
- **Sources:** APatch source (https://github.com/bmax121/APatch); KernelPatch source (https://github.com/bmax121/KernelPatch).

### 4.4 Qualcomm EDL — From USB to EL3 Physical Memory Access

- **Mechanism:** EDL (Emergency Download) is implemented in the PBL ROM (Qualcomm USB VID 05c6:9008). It cannot be disabled in silicon.
- **Exploitation:** a leaked, signed Firehose programmer can be loaded over the Sahara protocol. Many programmers contain hidden `peek`/`poke` XML commands that give arbitrary physical memory read/write at EL3.
- **Impact:** from physical USB access, an attacker can read TrustZone memory, patch the bootloader, extract keys, and write a modified boot image for persistent root.
- **Sources:** Aleph Security EDL research (https://alephsecurity.com/2018/01/22/qualcomm-edl-1/); B.Kerler edl tool (https://github.com/bkerler/edl); Firehorse framework (https://github.com/alephsecurity/firehorse).

### 4.5 MediaTek BROM / mtk-su — From World-Readable Driver to Kernel Physical R/W

#### mtk-su (CVE-2020-0069)

- **Target:** MediaTek 64-bit Android 7–9 devices (100+ million devices).
- **Bug:** the `/dev/mtk_cmdq` DMA engine driver was world-readable. It allowed any app to issue DMA commands that read or wrote arbitrary physical memory without address validation.
- **Exploitation:** app opens `/dev/mtk_cmdq`, allocates a DMA buffer, then instructs the hardware to copy kernel memory into the buffer or write attacker data into kernel memory. `cred` and `selinux_enforcing` are overwritten directly.
- **Reliability:** 100% deterministic, no race conditions.
- **Sources:** Quarkslab analysis (https://blog.quarkslab.com/cve-2020-0069-autopsy-of-the-most-stable-mediatek-rootkit.html); XDA writeup (https://www.xda-developers.com/mediatek-su-rootkit-exploit/); NVD CVE-2020-0069.

#### kamakiri BROM exploit

- **Mechanism:** MediaTek Boot ROM (BROM) has a USB buffer overflow. A crafted USB payload gives code execution at BROM level, before any signature verification.
- **Impact:** disable Secure Boot, read/write all flash, unlock bootloader, bypass FRP.
- **Tools:** amonet, bypass_utility, mtkclient.
- **Sources:** mtkclient (https://github.com/bkerler/mtkclient); amonet (https://github.com/xyzz/amonet).

---

## 5. Supply-Chain and Persistent Implants

### 5.1 Baseband / Modem Implants

- The cellular modem runs on a separate ARM core (often Cortex-R or Cortex-A) with shared memory to the application processor.
- A malformed over-the-air message (RRC/NAS) can compromise the modem, then pivot to the application processor kernel via shared memory.
- This is a true **0-click** vector: no user interaction, no visible message, just proximity to a rogue base station.
- **Sources:** KeenLab 5G baseband research (https://github.com/knownsec/keenlab-papers); 2021 Black Hat "5G Baseband OTA RCE".

### 5.2 Preloader / Bootloader Implants

- On MediaTek devices, the preloader validates the Download Agent (DA). Weak or bypassable DA authentication lets an attacker flash a modified LK/bootloader that disables verification.
- On Qualcomm devices, XBL/ABL USB handlers have had buffer overflows that allow code execution in the bootloader, enabling signature-verification bypass.
- **Sources:** mtkclient documentation; Qualcomm secure-boot research (https://hhj4ck.github.io/qualcomm/secboot-off-qcm2150.html).

### 5.3 OTA / A-B Partition Manipulation

- On A/B devices, the inactive slot can be modified after an OTA is applied but before the reboot, inserting attacker code into the "verified" updated system.
- `update_engine` parses complex delta payloads; bugs in payload parsing could allow code execution with elevated privileges.
- **Sources:** Android A/B partitions (https://source.android.com/docs/core/ota/ab); update_engine source (https://android.googlesource.com/platform/system/update_engine/).

### 5.4 TrustZone / TEE Implants

- A compromised Trusted OS or Secure Monitor can patch the normal-world kernel from the secure side, surviving factory resets and OS updates.
- CVE-2015-6639 (Widevine QSEE trustlet), CVE-2017-18141 (confused-deputy SMC), and CVE-2018-11976 (ECDSA key leak) are historical examples of QSEE trustlet failures.
- **Sources:** Project Zero "Trust Issues: Exploiting TrustZone TEEs" (https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html); NVD CVE-2015-6639, CVE-2017-18141, CVE-2018-11976; Gal Beniamini KeyMaster analysis (http://bits-please.blogspot.com/2016/06/extracting-qualcomms-keymaster-keys.html).

---

## 6. Research End-to-End Compromise Demonstrations

### 6.1 Samsung ALSA + Mali Chain (December 2022)

- **Discovery:** Google TAG found the chain targeting Samsung devices; Project Zero analyzed the final kernel stages.
- **Bugs:**
  - CVE-2022-4262: Chrome RCE (0-day).
  - CVE-2022-3038: Chrome sandbox escape (n-day unpatched in Samsung browser).
  - CVE-2022-22706: Mali n-day (patch not backported to Samsung).
  - CVE-2023-0266: race condition in ALSA 32-bit compat ioctl (`snd_kcontrol` UAF).
  - CVE-2023-26083: Mali `tlstream` leaked kernel pointers and allowed 16 bytes of controlled data at a known kernel address.
- **Technique:** attacker used Mali `REQ_SOFT_JIT_FREE` jobs as a heap spray, reclaimed the freed `snd_kcontrol`, forged a `user_element` via `tlstream`, and called `snd_ctl_elem_user_put` to get arbitrary kernel write. The chain then forged `ashmem_misc.fops` for arbitrary read/write.
- **Source:** Project Zero, "Analyzing a Modern In-the-wild Android Exploit" (https://projectzero.google/2023/09/analyzing-modern-in-wild-android-exploit.html).

### 6.2 Samsung Quram DNG Image Exploit (2024–2025)

- **Delivery:** DNG image disguised as JPEG sent over WhatsApp; Samsung `com.samsung.ipservice` parsed it with the closed-source Quram library.
- **Root cause:** `QuramDngOpcodeDeltaPerColumn::processArea` miscalculated `opcode_last_plane`, allowing an out-of-bounds write to a controlled offset.
- **Exploitation:** corrupted `QuramDngImage` dimensions, type-confused `TrimBounds` into `MapTable` to leak a vtable pointer, built a fake opcode object, and obtained arbitrary kernel read/write.
- **Attribution:** Palo Alto Networks Unit 42 linked the exploit to the **Landfall** commercial Android spyware.
- **Source:** Project Zero, "A look at an Android ITW DNG exploit" (https://googleprojectzero.blogspot.com/2025/12/a-look-at-android-itw-dng-exploit.html).

### 6.3 Qualcomm fastrpc In-the-Wild Chain (CVE-2024-43047)

- **Bug:** use-after-free in `fastrpc` DMA buffer reference counting (race between `mmap` and `munmap`).
- **Reachability:** any app that uses ML frameworks reaches `/dev/cdsprpc-smd`.
- **Exploitation:** freed DMA buffer reclaimed with controlled `sk_buff` data; corrupted `fastrpc_mmap` structure gives arbitrary kernel read/write.
- **Attribution:** confirmed exploited in the wild by Google TAG and Amnesty International, targeting journalists and activists.
- **Impact:** 60+ Qualcomm chipsets / 300+ device models.
- **Sources:** Android Security Bulletin October 2024 (https://source.android.com/security/bulletin/2024-10-01); CISA KEV CVE-2024-43047; NVD CVE-2024-43047; Project Zero Qualcomm DSP analysis.

### 6.4 Project Zero MSG_OOB — Renderer to Kernel in Two Stages (2025)

- **Bug:** CVE-2025-38236, a use-after-free in Linux `AF_UNIX` `MSG_OOB` handling (`unix_stream_read_generic`), fixed in Linux 6.9+.
- **Key insight:** Chrome's renderer sandbox allows `AF_UNIX` stream sockets and does not filter `send()`/`recv()` flags. The esoteric `MSG_OOB` feature was therefore reachable from the sandbox.
- **Chain:**
  1. V8 RCE in renderer (Stage 1).
  2. Trigger `MSG_OOB` UAF from renderer using allowed syscalls (Stage 2 — skips sandbox escape).
  3. Reclaim freed `sk_buff` with controlled data, use Dirty Pagetable or `modprobe_path` overwrite for kernel R/W → root.
- **Impact:** reduces the traditional 3-stage chain to 2 stages, dramatically increasing reliability and reducing development cost.
- **Source:** Project Zero, "From Chrome renderer code exec to kernel with MSG_OOB" (https://projectzero.google/2025/08/from-chrome-renderer-code-exec-to-kernel.html).

### 6.5 Samsung Z Flip3 — All Mitigations Bypassed (CVE-2022-22057)

- **Author:** Man Yue Mo (GitHub Security Lab).
- **Target:** Samsung Galaxy Z Flip3 (Snapdragon 888, kernel 5.4).
- **Mitigations bypassed:** kCFI, PAC, PAN, KASLR, Samsung RKP, KDP, SELinux.
- **Technique:**
  1. UAF in Qualcomm GPU (`kgsl`) timeline fence.
  2. Cross-cache to `pipe_buffer` for info leak and arbitrary write.
  3. KDP blocked direct `cred` writes, so the exploit hijacked saved registers on a root process's kernel stack.
  4. SELinux was bypassed by poisoning the AVC cache, which is not KDP-protected.
- **Source:** GitHub Security Lab, "The Android kernel mitigations obstacle race" (https://github.blog/security/vulnerability-research/the-android-kernel-mitigations-obstacle-race/).

---

## 7. Cost and Complexity of Full-Chain Exploitation

### 7.1 Commercial Chain Cost Estimates

| Stage | Typical cost | Notes |
|-------|--------------|-------|
| Renderer RCE (V8 0-day) | $250,000 – $500,000 | High value; V8 sandbox adds an extra step since 2024. |
| Sandbox escape (Mojo IPC / GPU) | $150,000 – $300,000 | Often the bottleneck; MSG_OOB-style direct kernel paths reduce this. |
| Kernel LPE (0-day) | $200,000 – $400,000 | GPU drivers are now the dominant target. |
| Chain integration, QA, target testing | $100,000 – $200,000 | Per-device offsets, reliability tuning, anti-forensics. |
| **Total per chain** | **$700,000 – $1,400,000** | Specialized vendors charge customers far more. |

### 7.2 Reliability Considerations

| Stage | Typical success rate | Failure mode |
|-------|----------------------|--------------|
| V8 RCE | ~95%+ | Deterministic once trigger is found. |
| Sandbox escape | ~80–90% | Heap layout dependent. |
| Kernel LPE | ~70–99% | Wide variance; page-level techniques (Dirty Pagetable) are more reliable. |
| Overall chain | ~50–85% | Product of stages; vendors test against exact device models before deployment. |

### 7.3 Time-to-Develop Trends

- **2019:** 3 stages, moderate mitigations, ~months of work.
- **2021:** 3 stages with Mojo sandbox escape, GPU kernel entry.
- **2023–2024:** 3 stages plus MTE bypass, page-level techniques required.
- **2025+:** 2-stage renderer→kernel chains possible; V8 sandbox adds an effective new stage for Chrome, but the overall chain can be shorter if a kernel-reachable syscall is found.

### 7.4 Market Observations

- Exploit brokers and mercenary vendors charge **millions of dollars** for a full 0-click Android or iOS chain.
- The same vulnerability (e.g., CVE-2023-4762) has been independently exploited by multiple vendors, showing that bug discovery and exploit development are partially decoupled.
- N-day exploitation remains viable for years because of patch gaps in vendor forks; Project Zero's 2021 in-the-wild analysis showed a top-tier attacker using public n-day exploits (CVE-2015-1805, CVE-2016-5195/DirtyCOW, CVE-2018-9568, etc.) for kernel privilege elevation.

---

## 8. Detection and Mitigation Takeaways

1. **Mitigation gaps are the real target.** Modern chains bypass MTE via untagged GPU memory, bypass KDP via unprotected AVC cache, and bypass sandbox via overlooked syscalls (`MSG_OOB`). Defenders must map coverage gaps, not just deploy mitigations.
2. **Patch gaps kill.** CVE-2023-0266 was fixed upstream in March 2021 but remained exploitable in Samsung kernels in December 2022 because the security impact was not recognized. CVE-2022-22706 was patched by Arm in January 2022 but not backported to Samsung.
3. **GPU and DSP drivers are the new Binder.** They are reachable from the app sandbox, manage their own memory (often bypassing MTE), and receive less scrutiny than Binder or Chrome.
4. **Bootloader security matters.** Unlocked bootloaders, leaky EDL programmers, and bypassable BROM/DA authentication provide persistent, low-cost full-compromise paths.
5. **Hardware-backed attestation is the last line.** Once EL3/TrustZone is lost, no software integrity mechanism can be trusted. Titan M, Knox eFuse, and RPMB rollback counters are designed to record this loss.

---

## Sources

- Project Zero, "Analyzing a Modern In-the-wild Android Exploit" (CVE-2023-0266 / CVE-2023-26083): https://projectzero.google/2023/09/analyzing-modern-in-wild-android-exploit.html
- Project Zero, "In-the-Wild Series: Android Exploits" (2020): https://projectzero.google/2021/01/in-wild-series-android-exploits.html
- Project Zero, "In-the-Wild Series: Android Post-Exploitation": https://projectzero.google/2021/01/in-wild-series-android-post-exploitation.html
- Project Zero, "From Chrome renderer code exec to kernel with MSG_OOB" (CVE-2025-38236): https://projectzero.google/2025/08/from-chrome-renderer-code-exec-to-kernel.html
- GitHub Security Lab, "The Android kernel mitigations obstacle race" (CVE-2022-22057): https://github.blog/security/vulnerability-research/the-android-kernel-mitigations-obstacle-race/
- Project Zero, "A look at an Android ITW DNG exploit" (Quram DNG / Landfall): https://googleprojectzero.blogspot.com/2025/12/a-look-at-android-itw-dng-exploit.html
- Android Security Bulletin October 2024 (CVE-2024-43047): https://source.android.com/security/bulletin/2024-10-01
- CISA KEV, CVE-2024-43047: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-43047
- NVD, CVE-2024-43047: https://nvd.nist.gov/vuln/detail/CVE-2024-43047
- CISA KEV, CVE-2021-30860 (FORCEDENTRY): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-30860
- NVD, CVE-2021-30860: https://nvd.nist.gov/vuln/detail/CVE-2021-30860
- CISA KEV, CVE-2023-41061 (BLASTPASS): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-41061
- CISA KEV, CVE-2023-41064 (BLASTPASS): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-41064
- NVD, CVE-2023-41061: https://nvd.nist.gov/vuln/detail/CVE-2023-41061
- NVD, CVE-2023-41064: https://nvd.nist.gov/vuln/detail/CVE-2023-41064
- CISA KEV, CVE-2021-37973 (Predator Chrome Portals): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-37973
- CISA KEV, CVE-2021-1048 (Predator epoll LPE): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-1048
- NVD, CVE-2021-1048: https://nvd.nist.gov/vuln/detail/CVE-2021-1048
- CISA KEV, CVE-2023-4762 (Intellexa V8): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-4762
- CISA KEV, CVE-2023-33106 (Intellexa Adreno): https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-33106
- NVD, CVE-2023-33106: https://nvd.nist.gov/vuln/detail/CVE-2023-33106
- Citizen Lab, "FORCEDENTRY: Pegasus Zero-Click Zero-Day Exploit in iMessage": https://citizenlab.ca/2021/09/forcedentry-pegasus-zero-click-zero-day-exploit-in-imessage/
- Citizen Lab, "Quadream: zero-click" (2022): https://citizenlab.ca/2022/04/quadream-zero-click/
- Magisk source: https://github.com/topjohnwu/Magisk
- Magisk documentation: https://topjohnwu.github.io/Magisk/tools.html
- KernelSU documentation: https://kernelsu.org/guide/what-is-kernelsu.html
- KernelSU source: https://github.com/tiann/KernelSU
- APatch source: https://github.com/bmax121/APatch
- KernelPatch source: https://github.com/bmax121/KernelPatch
- AVB 2.0 documentation: https://android.googlesource.com/platform/external/avb/+/master/README.md
- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot
- Aleph Security EDL research: https://alephsecurity.com/2018/01/22/qualcomm-edl-1/
- B.Kerler edl tool: https://github.com/bkerler/edl
- Quarkslab, CVE-2020-0069 (mtk-su): https://blog.quarkslab.com/cve-2020-0069-autopsy-of-the-most-stable-mediatek-rootkit.html
- XDA mtk-su writeup: https://www.xda-developers.com/mediatek-su-rootkit-exploit/
- mtkclient: https://github.com/bkerler/mtkclient
- Project Zero, "Trust Issues: Exploiting TrustZone TEEs": https://projectzero.google/2017/07/trust-issues-exploiting-trustzone-tees.html
- Gal Beniamini, "Extracting Qualcomm's KeyMaster Keys": http://bits-please.blogspot.com/2016/06/extracting-qualcomms-keymaster-keys.html
- Android A/B partitions: https://source.android.com/docs/core/ota/ab
- update_engine source: https://android.googlesource.com/platform/system/update_engine/
