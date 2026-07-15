# Cross-Exception-Level Attack Chains on ARM64

**Researcher A (Technical Depth)**  
**Scope:** How ARM64 exploits chain across EL0 → EL1 → EL2 → EL3, the primitives used at each transition, the role of SMC/HVC, bootloader-to-kernel chains, and representative full-device chains.  
**Date:** 2026-07-15

---

## 1. ARM64 Exception-Level Model and Cross-EL Transitions

ARM64 defines four standard Exception Levels (ELs) [^1]:

| EL | Typical software | World |
|----|------------------|-------|
| EL0 | Apps / untrusted userspace | Normal |
| EL1 | Linux/Android kernel | Normal |
| EL2 | Hypervisor (KVM, Xen, RKP, pKVM) | Normal |
| EL3 | Secure Monitor / Trusted Firmware-A | Secure |

The architectural instructions that move execution between levels are:

- **`svc`** (Supervisor Call): EL0 → EL1. Used for normal system calls.
- **`hvc`** (Hypervisor Call): EL1 → EL2. Used by guests or the host kernel to request hypervisor services (PSCI, KVM hypercalls, pKVM memory management).
- **`smc`** (Secure Monitor Call): EL1/EL2 → EL3. Used to request secure-world services (TEE, PSCI, firmware update).
- **`eret`** returns from EL3/EL2/EL1 to the saved lower level.

The ARM SMC Calling Convention (DEN0028/C) encodes SMC function IDs in `x0`/`w0` and passes up to six arguments in `x1–x6` [^2]. The Secure Monitor at EL3 is the only component that can switch `SCR_EL3.NS` and move between the Secure and Non-secure worlds. Because it saves and restores the entire CPU context on every SMC, bugs in context management can leak registers or corrupt the return path [^3].

---

## 2. EL0 → EL1: From App Sandbox to Kernel

### 2.1 Common Primitives

An unprivileged Android app at EL0 must first obtain arbitrary code execution in a privileged process or kernel context. The typical primitives are:

- **Memory corruption in a privileged userspace service** (image decoder, media codec, system service).
- **Use-after-free (UAF) / out-of-bounds (OOB) / type confusion** in a kernel driver reachable from the sandbox.
- **Heap shaping** to reclaim a freed object with attacker-controlled data (cross-cache, slab cache manipulation, scudo transfer batches).
- **Information leaks** to defeat KASLR (e.g., `perf_event` call chains, pointer leaks, side channels).
- **Arbitrary kernel read/write** via page-table corruption (Dirty Pagetable, self-referencing PTE) or credential swapping (DirtyCred).

### 2.2 Example Chain: Android In-The-Wild DNG Exploit (2024–2025)

Google Project Zero analyzed a series of malicious DNG images targeting Samsung devices via WhatsApp [^4]:

1. **Entry vector**: A DNG image is delivered over WhatsApp and inserted into Android `MediaStore`. Samsung’s `com.samsung.ipservice` periodically scans `MediaStore` and parses images.
2. **Vulnerability**: The closed-source Quram DNG decoder (`libimagecodec.quram.so`) mishandles `DeltaPerColumn` opcode parameters. It computes `opcode_last_plane = image_number_of_planes + opcode_number_of_planes` instead of `opcode_first_plane + opcode_number_of_planes`, and never bounds-checks the result against the actual number of planes.
3. **Primitive**: A 1×1 stage-3 image with plane parameters `5125` and `5123` yields a single **controlled add at a controlled offset** from the raw pixel buffer.
4. **Exploit flow**: The attacker uses thousands of DNG opcodes (including “unknown” opcode 23 sprays) to shape the scudo heap so that the raw pixel buffer sits near a `QuramDngImage` object. The controlled write corrupts the image object, producing an unbounded buffer and eventually arbitrary read/write inside the `com.samsung.ipservice` process.
5. **Patched**: Samsung fixed the vulnerability in April 2025; the samples were observed between July 2024 and February 2025.

This chain demonstrates the classic pattern: **0-/1-click app delivery → decoder sandbox escape → memory corruption → arbitrary code execution in a privileged process**. The next step would normally be a kernel LPE from that privileged process.

### 2.3 Example Chain: CVE-2026-43499 “GhostLock” (EL0 → EL1 LPE)

A recent rt_mutex vulnerability in the Linux kernel (affecting Linux v2.6.39 to v7.1) has been confirmed from a 24 KB APK on six devices across three vendors, four SoCs, five kernel versions, and both ARM32 and ARM64 [^5]:

- **Trigger**: A deterministic `rt_mutex` deadlock/`EDEADLK` path corrupts a waiter object on the stack.
- **Primitive**: UAF/controlled write on the kernel stack, then cross-cache or stack-based exploitation.
- **Confirmed devices**: Galaxy S25 Ultra (Snapdragon 8 Elite, kernel 6.1.99), Galaxy S23 (Snapdragon 8 Gen2, kernel 5.15.153), Galaxy A35 (Exynos 1380, kernel 5.15.123), Galaxy A13 (Exynos 850, kernel 4.14.186, 32-bit), Xiaomi 14 (Snapdragon 8 Gen3, kernel 6.1.138), Pixel 6 (Google Tensor, kernel 6.1.124).
- **Observed crash**: On Pixel 6 the crash occurred at `rt_mutex_adjust_prio_chain+0x200/0x944`, with `CLUSTER0_NONCPU_WDTRESET` (APC Watchdog reset) recorded in `pstore/console-ramoops-0`.

A full local-privilege-escalation exploit was later achieved on a Pixel 6 by matching the exact factory build, yielding `uid=2000→0`, SELinux `enforcing→permissive`, and a `u:r:kernel:s0` context [^6]. The key lesson is that hardcoded exploit addresses must match the target kernel build; flashing the matching stock image is far more reliable than adapting offsets.

### 2.4 Example Chain: CVE-2025-21479 GPU-to-Root (EL0 → EL1)

A publicly documented and actively exploited (CISA KEV) Qualcomm Adreno/KGSL vulnerability demonstrates a complete app-to-root path on Android [^7]:

1. **Stage 1 — GPU physical read/write**: The APK triggers a memory corruption in the KGSL GPU micronode and uses an SMMU (System MMU) spray plus physical-ASLR brute force to obtain arbitrary GPU physical memory read/write.
2. **Stage 2 — CPU kernel R/W**: A “self-referencing PTE” is corrupted so that a page-table entry points back to its own page-table page, giving the CPU kernel-level arbitrary read/write.
3. **Stage 3 — Disable SELinux**: Write `0` to `selinux_state.enforcing`.
4. **Stage 4 — Symbol resolution**: Dump the kernel or use `/proc/kallsyms` to resolve needed symbols.
5. **Stage 5A — Disable seccomp**: Walk the `thread_group` and zero `seccomp.mode` on every thread.
6. **Stage 5B — DirtyPipe shellcode**: Hijack the page cache of `libc++.so` in the `storaged` daemon; a 684-byte ARM64 shellcode is the maximum that fits without overwriting adjacent functions.
7. **App-context tricks**: Because the app runs as `untrusted_app`, the exploit must bypass zygote seccomp (use the NDK, not glibc), `hidepid=2` (walk the kernel task list), and the restricted `/data/local/tmp` permissions (use `O_PATH` and rewrite `i_mode` via kernel R/W). On Samsung devices, KDP (Kernel Data Protection) blocks direct credential modification, but flipping a single bit in `task->cred->cap_effective` (e.g., `CAP_KILL`) is not shadow-checked and allows killing `storaged` so that init restarts it with a clean state [^8].

This chain is an end-to-end example of **EL0 APK → kernel R/W → root shell**. It is also an example of how modern vendor mitigations (Knox, KDP, RKP, DEFEX, seccomp) are bypassed progressively rather than all at once.

---

## 3. EL1 → EL2: From Kernel to Hypervisor

Once the attacker controls the kernel, the next level is EL2. The kernel can issue `hvc` instructions directly, and many hypervisors expose powerful HVC handlers. A compromised kernel can also corrupt Stage-2 page tables if it can write to hypervisor-owned pages, or exploit hardware errata that create windows where memory protection is not yet globally observable.

### 3.1 HVC/SMC Abuse at the EL1–EL2 Boundary

A hypervisor must validate every HVC:

- **Caller privilege**: Is the caller a guest or the host? Some HVCs should only be reachable from one.
- **IPA/PA validity**: Does the requested physical address belong to the caller?
- **State-machine legality**: Can a page be donated, shared, or reclaimed in the current ownership state?
- **No double mapping**: Does the requested mapping create an alias that breaks isolation?

A single missing check can let the kernel remap hypervisor memory or a guest escape its VM. The same logic applies to SMC forwarding: when EL2 proxies an SMC to EL3, it must sanitize arguments so the host cannot use the secure world as a confused deputy to access protected memory.

### 3.2 Example: CVE-2025-22413 — pKVM Protected-VCPU Logic Error

In Google’s Protected KVM (pKVM), the file `arch/arm64/kvm/hyp/nvhe/hyp-main.c` failed to verify that a protected vCPU was in a runnable PSCI state before running it [^9]:

- **Root cause**: Missing state check in the protected-VCPU path.
- **Impact**: Local privilege escalation / information disclosure from host/guest context to hypervisor.
- **Fix**: `ANDROID: KVM: arm64: Don't run a protected VCPU if it isn't in a runnable PSCI state`.
- **Affected**: Android devices with pKVM enabled.

This is a representative case of an HVC/state-machine bug that crosses the EL1–EL2 boundary.

### 3.3 Example: CVE-2025-10263 / XSA-493 — ARM TLBI Ordering Erratum

A hardware erratum on many ARM cores (Cortex-X1/X2/X3/X4/X925, Cortex-A76/A77/A78/A710, Neoverse V1/V2/V3/N1/N2, C1-Ultra/Premium) allows a broadcast TLBI to complete on one PE before a store on another PE is globally observed [^10][^11].

- **Effect**: A malicious guest can write to memory after the hypervisor has changed Stage-2 to forbid writes.
- **Impact**: Guest → hypervisor privilege escalation or cross-VM data corruption.
- **Significance**: This is a **hardware-level cross-EL primitive**; even a correct hypervisor can be bypassed by micro-architectural behavior.

### 3.4 Proprietary Hypervisors: Samsung RKP

Samsung’s Real-time Kernel Protection (RKP) runs at EL2 and enforces read-only kernel `.text`/`.rodata` and Kernel Data Protection (KDP) over credentials/SELinux structures. Historical bypasses abused HVCs that altered Stage-2 permissions without validating that the target IPA was not EL2 memory. KDP specifically blocks direct writes to `task->cred` and UID fields, but experiments show that a single-bit capability flip (`CAP_KILL`) is not shadow-validated on every read, allowing a root shell to be obtained without tripping KDP [^8].

---

## 4. EL2 → EL3: From Hypervisor to Secure Monitor / TrustZone

The Secure Monitor at EL3 is the highest software privilege. It can read or write any normal-world or secure-world memory, reconfigure TZASC, and disable the MMU. Compromise at EL3 therefore defeats everything below it.

### 4.1 SMC Interface Abuse

The SMC interface is a direct CPU-level exception. Vulnerability classes include:

- **Missing argument validation**: trusting caller-supplied length/offset/ID.
- **Integer overflow**: arithmetic on SMC arguments bypasses bounds checks.
- **Information leakage**: failure to sanitize return registers or shared memory.
- **Confused deputy**: an SMC intended only for the TEE is reachable from the normal world.
- **Memory corruption in trustlets**: TAs parse untrusted input from shared memory.

### 4.2 ARM Trusted Firmware (TF-A) CVEs

TF-A is the reference EL3 implementation. Notable cross-EL issues include [^12][^13][^14]:

| CVE | Advisory | Root Cause | Cross-EL Impact |
|-----|----------|------------|-----------------|
| **CVE-2018-19440** | TFV-8 | `restore_gp_registers()` restores stale `x0–x3` from a previous SMC request | Leaks return values between SMC clients; can disclose EL3/TEE state |
| **CVE-2022-47630** | TFV-10 | Out-of-bounds read in X.509 certificate parser (`get_ext`, `auth_nvctr`) | Boot-certificate parser bug; can subvert Chain of Trust in custom configurations |
| **CVE-2016-10319** | TFV-1 | Integer overflow in Firmware-Update SMC (`bl1_fwu_image_copy`) | Oversized copy into secure memory from normal world |
| **CVE-2025-10263** | TFV-17 | TLBI+DSB ordering erratum in TF-A xlat library | Higher-EL memory corruption on affected cores |

### 4.3 Qualcomm QSEE / QTEE CVEs

Qualcomm’s Secure Execution Environment (QSEE, now QTEE) runs at Secure EL1. The normal-world `qseecom` driver and the EL3 SMC dispatcher are the primary gates [^15]:

- **CVE-2014-4322 / CVE-2016-3931**: `qseecom.c` failed to validate offsets/lengths, allowing memory corruption from a crafted app.
- **CVE-2017-18141**: After a third-party TEE was loaded, the non-secure world could issue an SMC to access privileged functions intended only for the TEE, across many Snapdragon chipsets [^16].
- **CVE-2018-11976**: ECDSA signing code in QSEE leaked private-key material to the non-secure world [^17].

### 4.4 NCC Group: Qualcomm TrustZone ECDSA Key Extraction

NCC Group demonstrated a microarchitectural side-channel attack against Qualcomm’s TrustZone implementation of Android’s hardware-backed keystore [^18]. Cache attacks with high temporal and spatial precision were used to monitor TrustZone code flow, leading to full recovery of a 256-bit ECDSA private key. While this is a side-channel rather than a memory-corruption chain, it illustrates how EL3/TEE cryptographic code can be attacked from the normal world, and the extracted key can then be used to forge signatures or decrypt data.

---

## 5. Bootloader-to-Kernel and Secure-Boot Bypass Sequences

The boot chain is the root of trust. If it is subverted, the attacker controls BL31/EL3 and can defeat higher-level mitigations. TF-A implements the Trusted Board Boot Requirements (TBBR-CLIENT) model [^19]:

1. BL1 (immutable ROM) verifies BL2 with the ROTPK.
2. BL2 verifies BL31 (EL3 runtime), BL32 (TEE), and BL33 (normal-world bootloader).
3. Images may include non-volatile counter certificates for anti-rollback.
4. Only after all images are authenticated is control transferred.

### 5.1 Key Attack Points

- **Certificate parser bugs**: TFV-10 / CVE-2022-47630 is an OOB read in the X.509 parser; upstream it is not pre-auth exploitable, but custom chains of trust may be vulnerable.
- **Firmware update path**: TFV-1 / CVE-2016-10319 allowed untrusted normal-world code to copy an oversized recovery image into secure memory before BL31 started.
- **Anti-rollback bypass**: tampering with the non-volatile counter or its certificate allows downgrade to a vulnerable firmware.
- **Hardcoded keys**: CVE-2020-12789 affected a Microchip Secure Monitor because the applet encryption key was hardcoded.
- **Bootloader unlock/debug**: CVE-2013-3051 showed the Motorola TrustZone kernel on MSM8960 failing to verify a physical-address argument, allowing crafted SMCs to unlock the bootloader.

### 5.2 Example: NCC Group MediaTek BootROM Glitch

NCC Group demonstrated a voltage-glitch attack against the MediaTek MT8163V BootROM [^20]:

- The BootROM is the immutable first stage and the hardware root of trust.
- It verifies the signature of the mutable preloader before executing it.
- A precisely timed voltage glitch (shorting `VCCK_PMU` to ground) corrupted the internal CPU state, causing the signature check to be skipped.
- With ~20% success rate per attempt and simple reboot retries, an attacker can achieve near-100% reliability.
- Once the preloader is bypassed, the attacker can run arbitrary code and load a modified TrustZone image or Android kernel, completely undermining secure boot.

Because the vulnerability is in mask ROM, it cannot be patched in the field. This is a classic **physical → bootloader → kernel → TrustZone** chain.

---

## 6. Typical Full Android Device Chain: App → Root → Hypervisor → TrustZone

A complete nation-state or high-end rooting chain on a modern Android ARM64 device often follows this progression:

```
EL0  untrusted_app / sandboxed decoder
 │   (1) memory corruption in driver/decoder/system service
 ▼
EL0  privileged process (e.g., mediacodec, ipservice, system_server)
 │   (2) kernel driver bug or second-stage sandbox escape
 ▼
EL1  Linux kernel arbitrary read/write
 │   (3) disable SELinux, resolve symbols, disable seccomp, obtain root shell
 ▼
EL1  root context
 │   (4) HVC/SMC abuse or Stage-2 corruption
 ▼
EL2  hypervisor / RKP / pKVM
 │   (5) SMC to EL3 or direct TrustZone memory access
 ▼
EL3  Secure Monitor / TEE
```

### 6.1 Stage-by-Stage Details Using CVE-2025-21479

The Qualcomm Adreno/KGSL chain from Section 2.4 is one of the cleanest publicly documented examples of the lower half of this diagram [^8]:

1. **EL0 → EL0 privileged**: The APK loads a native library and uses the KGSL driver to trigger a GPU bug. No special permissions are required beyond the standard GPU driver interface.
2. **EL0 → EL1**: GPU physical R/W is converted to CPU kernel R/W via PTE corruption. The kernel’s page tables are now attacker-controlled.
3. **EL1 → EL1 root**: SELinux is disabled, seccomp is cleared per thread, symbols are resolved, and DirtyPipe is used to inject shellcode into a root-owned daemon. Samsung KDP is bypassed by flipping `CAP_KILL` rather than rewriting credentials.
4. **EL1 → EL2 (optional)**: From root, the attacker can target Samsung RKP by abusing HVCs that change Stage-2 mappings, or target pKVM by exploiting HVC handler logic errors such as CVE-2025-22413.
5. **EL1/EL2 → EL3**: With kernel or hypervisor control, the attacker can issue SMCs to the Secure Monitor, exploit QSEE/QTEE trustlets (e.g., CVE-2018-11976, CVE-2017-18141), or attack the TEE kernel directly (e.g., Samsung TEEGRIS trustlet CVEs).

Modern devices often stop the public chain at root because EL2/EL3 mitigations are strong and the attack surface is small. However, the architectural layout means that **any code execution at EL3 automatically defeats EL2, EL1, and EL0**, so a high-value target will continue the chain if a usable EL3 bug is available.

---

## 7. How Mitigations Are Bypassed Progressively

| Level | Mitigation | Bypass technique |
|-------|------------|------------------|
| EL0 | App sandbox / SELinux app context | Exploit a system service or driver reachable from the sandbox; abuse `MediaStore`, `ContentProvider`, or IPC confused deputy |
| EL0 | Seccomp (zygote) | Use the NDK (bionic) instead of glibc; from kernel R/W, walk `thread_group` and zero `seccomp.mode` |
| EL1 | KASLR | `perf_event` call-chain leak, `/proc/kallsyms`, kernel pointer leaks, or side channels |
| EL1 | CFI / PAC / BTI | Reuse existing code paths or corrupt data pointers rather than code pointers; UAF reuse of existing objects |
| EL1 | MTE | Same-tag reallocation, heap shaping, or use-after-free on non-MTE slabs |
| EL1 | SELinux | Write `selinux_state.enforcing = 0` or patch the current `cred` security context |
| EL2 | Samsung RKP / KDP | Abuse HVCs that change Stage-2 permissions; flip `cap_effective` bits rather than rewriting credentials |
| EL2 | pKVM isolation | HVC state-machine logic errors (CVE-2025-22413), page-ownership confusion, or TLBI errata (CVE-2025-10263) |
| EL3 | TrustZone / SMC argument validation | Missing checks on SMC IDs or arguments (CVE-2017-18141); confused-deputy via SMC proxy; physical glitching of BootROM |
| EL3 | Secure boot / Chain of Trust | X.509 parser bugs (CVE-2022-47630), FWU integer overflow (CVE-2016-10319), hardcoded keys (CVE-2020-12789), or BootROM glitching |

The pattern is cumulative: each level’s mitigations are designed to stop the previous level, but once the attacker is inside the level they can repurpose the same hardware primitives (page tables, HVCs, SMCs) that the level itself uses for isolation.

---

## 8. Notable Multi-Stage CVE Chains

### 8.1 Pegasus / FORCEDENTRY (iOS, CVE-2021-30860)

NSO Group’s Pegasus used an iMessage zero-click exploit chain [^21]:

1. A malicious iMessage containing a fake-GIF PDF is received.
2. The PDF contains a JBIG2 stream with an integer overflow in the symbol-count calculation.
3. The overflow corrupts the segment list and unbounds the current page bitmap, giving arbitrary read/write in the `IMTranscoderAgent` process.
4. The attacker then uses the JBIG2 refinement operators (AND/OR/XOR/XNOR) to implement a Turing-complete logical circuit with registers and a 64-bit adder, searching memory and escaping the sandbox.
5. The final stage reaches the kernel.

This is not an ARM exception-level chain, but it is a canonical example of how a single integer overflow in a complex codec is amplified into a full device compromise through a multi-stage chain.

### 8.2 Chrysaor / Lipizzan (Android, 2017)

Google’s Play Protect and Threat Analysis Group identified Chrysaor and Lipizzan as targeted Android spyware families [^22]. These families used multiple exploit stages to gain root and persist, demonstrating that Android multi-stage chains comparable to Pegasus were already in use by 2017.

### 8.3 Predator (Cytrox)

Cytrox’s Predator is a commercial spyware framework reported to target both Android and iOS devices using 0-click and 1-click chains. Public reporting (Citizen Lab, ESET, Lookout) describes Predator as relying on a combination of browser, RCS, and image/attachment bugs, although detailed public CVE-level breakdowns are less complete than for FORCEDENTRY. Conceptually, Predator chains follow the same EL0 → EL1 → persistence pattern as the DNG and GPU-to-root chains above.

### 8.4 Android ITW DNG + GPU-to-Root

The DNG exploit (Section 2.2) and the CVE-2025-21479 GPU chain (Section 2.4) are the most clearly documented Android-side examples of the same class of chaining: an untrusted media file delivered by a messaging app is turned into arbitrary code in a privileged process, then into kernel R/W, and finally into a root shell.

---

## 9. Sources

[^1]: ARM Architecture Reference Manual for ARMv8-A — `https://developer.arm.com/documentation/ddi0487/latest/`
[^2]: ARM SMC Calling Convention (DEN0028) — `https://developer.arm.com/documentation/den0028/latest/`
[^3]: Trusted Firmware-A Documentation — `https://trustedfirmware-a.readthedocs.io/en/latest/`
[^4]: Google Project Zero, “A look at an Android ITW DNG exploit” (2025) — `https://googleprojectzero.blogspot.com/2025/12/a-look-at-android-itw-dng-exploit.html`
[^5]: Persistent memory observation: CVE-2026-43499 “GhostLock” confirmed on 6 devices across 3 vendors, 4 SoCs, 5 kernel versions, ARM32+ARM64 (2026-07-12).
[^6]: Persistent memory observation: CVE-2026-43499 exploit.c full-chain LPE on Pixel 6 (2026-07-13).
[^7]: NVD, CVE-2025-21479 — `https://nvd.nist.gov/vuln/detail/CVE-2025-21479` (Qualcomm, CISA KEV)
[^8]: Local skill reference: `/home/t/.pi/agent/skills/android-gpu-to-root/SKILL.md` — “Android GPU-to-Root Exploit Chain” based on CVE-2025-21479.
[^9]: NVD, CVE-2025-22413 — `https://nvd.nist.gov/vuln/detail/CVE-2025-22413` (Android Security Bulletin, pKVM)
[^10]: NVD, CVE-2025-10263 — `https://nvd.nist.gov/vuln/detail/CVE-2025-10263` (Arm TLBI ordering erratum)
[^11]: Xen Security Advisory XSA-493 — `https://xenbits.xen.org/xsa/advisory-493.html`
[^12]: NVD, CVE-2018-19440 — `https://nvd.nist.gov/vuln/detail/CVE-2018-19440` (TF-A TFV-8 context leak)
[^13]: NVD, CVE-2022-47630 — `https://nvd.nist.gov/vuln/detail/CVE-2022-47630` (TF-A TFV-10 X.509 parser)
[^14]: TF-A Security Advisories Index — `https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories/index.html`
[^15]: Android EL3 TrustZone technical reference in this repository: `docs/04-el3-trustzone-technical.md`
[^16]: NVD, CVE-2017-18141 — `https://nvd.nist.gov/vuln/detail/CVE-2017-18141` (Qualcomm SMC access-control bypass)
[^17]: NVD, CVE-2018-11976 — `https://nvd.nist.gov/vuln/detail/CVE-2018-11976` (QSEE ECDSA key leak)
[^18]: NCC Group, “Hardware-Backed Heist: Extracting ECDSA Keys from Qualcomm’s TrustZone” (2019) — `https://www.nccgroup.com/research/whitepaper-hardware-backed-heist-extracting-ecdsa-keys-from-qualcomm-s-trustzone/`
[^19]: Linux Kernel Documentation, “Memory Layout on AArch64 Linux” — `https://docs.kernel.org/arch/arm64/memory.html`
[^20]: NCC Group, “There’s A Hole In Your SoC: Glitching The MediaTek BootROM” (2020) — `https://www.nccgroup.com/research/there-s-a-hole-in-your-soc-glitching-the-mediatek-bootrom/`
[^21]: Google Project Zero, “A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution” (2021) — `https://googleprojectzero.blogspot.com/2021/12/a-deep-dive-into-nso-zero-click.html`
[^22]: Google Online Security Blog, “From Chrysaor to Lipizzan: Blocking a new targeted spyware family” (2017) — `https://security.googleblog.com/2017/07/from-chrysaor-to-lipizzan-blocking-new.html`
