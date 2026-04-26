# Android Defense-in-Depth Strategies and Their Effectiveness

## Overview

Android's security posture relies on a layered defense-in-depth approach: no single mechanism is expected to be impenetrable, but the combination of compiler-level hardening, kernel protections, hardware-backed features, app verification, and runtime scanning creates a composite barrier that dramatically raises the cost of exploitation. This document analyzes each major layer, its design rationale, empirical effectiveness, and known limitations.

---

## 1. Compiler-Level Mitigations

Android's native codebase (C/C++) is compiled with Clang/LLVM, and Google has progressively enabled a suite of sanitizers and hardening passes in production builds. Unlike debug-only sanitizers (ASan, MSan), several of these are designed for production deployment with acceptable performance overhead.

### 1.1 UBSan (Undefined Behavior Sanitizer)

UBSan instruments code to detect undefined behavior at runtime, including signed integer overflow, null pointer dereference, and misaligned pointer access. Android selectively enables UBSan sub-checks in production rather than the full suite, since some checks carry unacceptable overhead.

### 1.2 IntSan (Integer Overflow Sanitizer)

IntSan is Android's production deployment of UBSan's signed and unsigned integer overflow checks. It was first enabled broadly in Android's media frameworks (mediaserver, libstagefright) following the catastrophic Stagefright vulnerabilities (CVE-2015-1538 through CVE-2015-1542), where integer overflows in media parsing led to remote code execution. IntSan aborts the process on overflow, converting potential code execution into a denial of service — a significant reduction in severity. Google reported that enabling IntSan in media components caught numerous latent bugs during testing and effectively eliminated integer overflow as an exploitable primitive in those components.

**Performance cost:** Approximately 1-2% overhead in instrumented code, which is acceptable for media codecs that are not CPU-bound during normal operation.

**Known limitations:** IntSan does not protect against overflows in inline assembly, and wrapping arithmetic that is intentional must be explicitly annotated with `__builtin_*_overflow` or compiler attributes, creating maintenance burden.

### 1.3 BoundsSan (Bounds Sanitizer)

BoundsSan instruments array accesses to check bounds at runtime, using LLVM's `-fsanitize=bounds` pass. It targets stack and heap buffer overflows that arise from out-of-bounds array indexing. Android enables BoundsSan on security-critical components where arrays are accessed based on untrusted input.

**Limitations:** BoundsSan relies on compiler-visible type information. It cannot instrument accesses through raw pointer arithmetic that bypasses array semantics — for example, `*(ptr + offset)` where `ptr` is a `char*` with no associated array bounds. This means manually managed buffers, which are common in legacy C code, often fall outside its coverage.

### 1.4 CFI (Control-Flow Integrity)

Clang CFI restricts indirect call targets to only valid functions matching the expected type signature. Android enables forward-edge CFI (`-fsanitize=cfi`) in the kernel (since Android 9 / Linux 4.14 on arm64) and in critical userspace components. CFI prevents an attacker who has achieved an arbitrary-write primitive from trivially redirecting function pointers to arbitrary gadgets.

**Kernel CFI (kCFI):** Starting with Linux 6.1, the kernel uses kCFI, a hardware-assisted variant that embeds type hashes before function entry points and validates them at indirect call sites. kCFI has lower overhead than software-only Clang CFI and is resilient to certain metadata corruption attacks because the type tags are embedded in the code section (read-only in memory).

**Known bypasses:**
- **Type confusion within the same signature:** CFI validates that a target has the correct function type. If two functions share the same signature (e.g., `void (*)(struct sock *)`) an attacker can redirect to any valid function of that type. In the kernel, which has many functions with similar signatures, this creates "CFI-compatible" gadgets.
- **JIT code and trampolines:** CFI cannot protect dynamically generated code (BPF JIT, module trampolines) unless specifically instrumented.
- **Data-only attacks:** CFI only protects control flow. Attacks that corrupt non-pointer data (e.g., credentials structures, SELinux labels) bypass CFI entirely.

### 1.5 SCS (Shadow Call Stack)

Shadow Call Stack protects backward-edge control flow (return addresses) by maintaining a separate, hidden stack that stores only return addresses. On function entry, the return address is pushed to both the regular stack and the shadow stack; on return, the value is loaded from the shadow stack. An attacker who corrupts the regular stack's return address cannot hijack control flow because the return is sourced from the shadow stack.

Android enables SCS in the kernel (arm64) and in critical userspace daemons. On AArch64, the shadow stack pointer is stored in register `x18`, which is reserved by the platform ABI and not accessible via normal stack corruption.

**Known limitations:**
- SCS protects only return addresses, not other saved registers or local variables on the stack.
- If an attacker achieves an arbitrary read, they can locate the shadow stack (its address is in `x18`) and potentially corrupt it. However, this requires a stronger primitive than typical stack buffer overflows provide.
- ARM's hardware-backed **Pointer Authentication (PAC)** provides an alternative approach that signs return addresses cryptographically; modern Android devices use PAC when available, and SCS serves as the software fallback.

---

## 2. Kernel Hardening

The Android kernel (based on the Android Common Kernel, ACK) applies a substantial set of hardening measures beyond upstream Linux defaults.

### 2.1 KASLR (Kernel Address Space Layout Randomization)

KASLR randomizes the kernel's virtual base address at boot time, forcing attackers to discover the kernel's location before they can reliably target specific functions or data structures. On arm64, Android kernels typically provide 13-21 bits of entropy for the kernel image and additional entropy for modules and the linear mapping region.

**Bypasses:** KASLR is undermined by information leaks. Kernel pointer leaks via `/proc`, `dmesg`, or side channels (e.g., timing-based KASLR derandomization, speculative execution attacks like PREFETCH-based oracles) have been repeatedly demonstrated. Android mitigates this with `kptr_restrict=2`, `dmesg_restrict=1`, and restricted `/proc`/`/sys` access via SELinux. However, a single information disclosure vulnerability in a reachable kernel interface can negate KASLR.

### 2.2 PAN, PXN, and UAO (ARM Hardware Features)

- **PAN (Privileged Access Never):** Prevents the kernel from directly accessing user-space memory. Without PAN, an attacker could map crafted data in user-space and trick the kernel into reading it. PAN forces the kernel to use explicit copy routines (`copy_from_user`/`copy_to_user`) that perform validation.
- **PXN (Privileged Execute Never):** Prevents the kernel from executing code mapped in user-space pages. This defeats ret2usr attacks where the attacker places shellcode in user-space and redirects kernel execution there.
- **UAO (User Access Override):** Works with PAN to ensure `copy_to/from_user` functions still work correctly while PAN is active.

These are hardware-enforced and have no known software bypasses — they fundamentally alter the privilege model of memory access.

### 2.3 PAC (Pointer Authentication Codes)

ARMv8.3-A introduced Pointer Authentication, which uses spare bits in 64-bit pointers to store a cryptographic authentication code (PAC). The kernel and userspace sign pointers (return addresses, function pointers) using a per-process secret key. Any corruption of a signed pointer invalidates the PAC, causing a fault on use.

**Effectiveness:** PAC provides probabilistic protection — the authentication codes are typically 7-16 bits wide depending on virtual address space configuration. Brute-force attacks against PAC are impractical for single-shot exploits but potentially feasible in scenarios allowing repeated attempts (e.g., forking servers). Google's Pixel devices use PAC for both kernel and userspace from Pixel 6 onward.

**Known attacks:** The PACMAN attack (MIT, 2022) demonstrated speculative execution can be used to test PAC values without triggering a fault, effectively brute-forcing the PAC in certain microarchitectures. However, PACMAN requires an existing memory corruption vulnerability and a specific speculative execution window, making it a partial weakening rather than a complete bypass.

### 2.4 BTI (Branch Target Identification)

ARMv8.5-A BTI marks valid branch targets with a `BTI` instruction. Any indirect branch that lands on a non-BTI instruction causes a fault. This provides coarse-grained forward-edge CFI in hardware. Android kernels enable BTI on supported hardware, and it complements kCFI by adding a hardware enforcement layer.

### 2.5 CONFIG_HARDENED_USERCOPY

This kernel config option adds bounds checking to `copy_from_user()` and `copy_to_user()`, validating that the source/destination in kernel memory lies within a single allocation (slab object or stack frame). This prevents a class of vulnerabilities where a user-controlled length parameter causes the kernel to read/write beyond the intended object, leaking adjacent slab data or corrupting neighboring allocations.

### 2.6 Kernel Lockdown Mode

Android devices can enable kernel lockdown mode, which restricts even root (UID 0) from modifying the running kernel. When lockdown is set to "integrity" or "confidentiality" mode, it blocks:
- Writing to `/dev/mem`, `/dev/kmem`, `/dev/port`
- Loading unsigned kernel modules
- Accessing kprobes/eBPF in ways that could modify kernel memory
- Hibernation image creation (which could be tampered with)

This prevents a compromised root process from directly patching the kernel to disable SELinux or other protections, forcing attackers to find in-kernel vulnerabilities rather than simply leveraging root access.

---

## 3. Biometric Authentication Security

### 3.1 Architecture

Android's biometric framework follows a layered architecture. The `BiometricPrompt` API (introduced in Android 9) provides a unified interface for all biometric modalities. Underneath, each modality is implemented by a vendor-specific HAL (Hardware Abstraction Layer) that communicates with a dedicated sensor and runs biometric matching in a Trusted Execution Environment (TEE) or Secure Element (SE). The critical design principle: **raw biometric data and matching templates never leave the TEE**.

### 3.2 Fingerprint Security

The fingerprint HAL (`android.hardware.biometrics.fingerprint`) requires that template storage and matching occur within the TEE. Android classifies fingerprint as a **Class 3 (Strong)** biometric, meaning it can be used to unlock the Keystore and authorize transactions. Requirements include:
- **Spoof Acceptance Rate (SAR):** Must be below 7% against presentation attacks (e.g., silicone molds, printed fingerprints).
- **False Acceptance Rate (FAR):** Must be below 1/50,000.
- Enrollment and matching must be tamper-resistant — a compromised Android OS should not be able to extract templates or bypass matching.

**Attacks:** Research has demonstrated practical spoofing of capacitive and optical sensors using gelatin/silicone replicas, 3D-printed fingerprints, and even conductive ink on paper. Ultrasonic sensors (e.g., Qualcomm 3D Sonic) are more resistant but have been spoofed with higher-effort 3D-printed replicas. The BrutePrint attack (2023) demonstrated that firmware-level flaws in some implementations allowed unlimited matching attempts, bypassing the Android-mandated lockout after 5 failed attempts.

### 3.3 Face Recognition

Android's face authentication supports Class 2 (Weak) and Class 3 (Strong) tiers. Class 3 requires a depth-sensing system (structured light or ToF) to prevent flat-image spoofing. The Pixel 4's face unlock used an IR dot projector similar to Apple's Face ID, achieving Class 3. Many cheaper implementations use a single 2D camera and are classified as Class 2 — these cannot be used for Keystore operations or payments.

**Spoof resistance:** Class 2 face recognition is trivially defeated by photographs, video playback, or 3D-printed masks. Class 3 implementations with IR depth sensing are significantly more robust but have been bypassed with custom 3D-printed masks incorporating IR-reflective materials.

### 3.4 BiometricPrompt API Security

`BiometricPrompt` enforces several security policies:
- It requires a cryptographic binding between biometric authentication and Keystore operations. The app provides a `CryptoObject`, and the biometric HAL releases the corresponding Keystore key only on successful match.
- The system UI controls the biometric dialog — apps cannot overlay or fake it.
- Fallback to device credential (PIN/pattern) is controlled by the API caller and the device policy.

---

## 4. APK Signing and Verification

### 4.1 Signature Scheme Evolution

| Scheme | Introduced | Mechanism | Key Property |
|--------|-----------|-----------|-------------|
| **v1 (JAR signing)** | Android 1.0 | Signs individual ZIP entries via `META-INF/*.SF` | Only protects listed entries; ZIP metadata is unsigned |
| **v2** | Android 7.0 | Signs the entire APK as a binary blob (APK Signing Block) | Protects all bytes; resistant to ZIP manipulation |
| **v3** | Android 9.0 | Adds key rotation support via proof-of-rotation chains | Allows signing key updates without losing identity |
| **v3.1** | Android 13 | Targets rotation to Android 13+ devices only | Prevents rotation-unaware older platforms from confusion |
| **v4** | Android 11 | Separate `.idsig` file containing a Merkle tree over APK contents | Enables ADB incremental install; complements v2/v3 |

### 4.2 Past Signing Vulnerabilities

**Janus (CVE-2017-13156):** Exploited the fact that the Android runtime could execute DEX files, and the APK (ZIP) format allows prepended data. An attacker could prepend a valid DEX file to a signed APK. The v1 signature remained valid (it only signs ZIP entries, not prepended data), but the runtime would execute the prepended DEX code. This allowed complete replacement of app logic while preserving the original signature. **v2 signing blocks this** because it signs the entire file contents.

**FakeID (CVE-2014-8609):** Exploited a flaw in Android's certificate chain validation for APK signatures. Android did not verify that the issuer of a certificate in the chain actually signed the subject certificate. An attacker could construct a certificate chain claiming to be issued by Adobe (which had special Flash plugin privileges) or other privileged signers. This granted the malicious app elevated privileges. Fixed in Android 4.4/5.0 with proper chain validation.

**Master Key (CVE-2013-4787):** ZIP files can contain duplicate filenames. Android's signature verification read one entry, but the installer extracted a different entry with the same name, allowing substitution of arbitrary files within a signed APK.

### 4.3 Current Security Properties

With v2+ signing enforced (Android 7.0+), any byte-level modification to the APK invalidates the signature. The signing block is positioned between the ZIP central directory and the ZIP entries, and the signature covers the digest of all other APK sections. Key rotation (v3) uses a proof-of-rotation structure where the old key signs an attestation transferring trust to the new key, forming a verifiable chain.

---

## 5. Google Play Protect

### 5.1 Architecture

Google Play Protect (GPP) operates as a multi-tier scanning system:

1. **Upload-time scanning:** When a developer submits an APK to the Play Store, it undergoes static analysis (decompilation, permission analysis, API call pattern matching) and dynamic analysis (execution in sandboxed emulators to observe runtime behavior).
2. **On-device scanning:** The Play Protect module within Google Play Services periodically scans installed apps (including sideloaded APKs) against a cloud-maintained threat intelligence database.
3. **Real-time install scanning:** Since late 2023, GPP performs real-time code-level analysis of novel sideloaded apps, sending code-level signals to Google's infrastructure for immediate ML-based evaluation.

### 5.2 ML-Based Detection

GPP uses machine learning models trained on features including:
- API call graphs and permission usage patterns
- String constants, URLs, and command-and-control indicators
- Behavioral signals from dynamic analysis (network connections, file access patterns, accessibility service abuse)
- Code similarity to known malware families (fuzzy hashing, neural code embeddings)

Google reports that Play Protect scans over 125 billion apps per day and prevents approximately 1.6 million PHA (Potentially Harmful Application) installations per day.

### 5.3 Limitations and Bypass Techniques

- **Deferred payloads:** Malware can pass upload-time scanning by shipping a clean APK that later downloads malicious code via `DexClassLoader` or native code loading. The dropper pattern remains the most common GPP bypass.
- **Versioning attacks:** An app establishes reputation as benign over multiple versions, then introduces malicious behavior in an update.
- **Dynamic code loading and reflection:** Heavy use of reflection, encrypted DEX files, and custom class loaders can evade static analysis.
- **WebView-based attacks:** Malicious behavior implemented entirely in JavaScript within a WebView is harder for static analysis to detect.
- **Geographic/temporal evasion:** Malware that checks the device's locale, time zone, or IP geolocation before activating can avoid triggering during analysis (which typically uses US-based infrastructure).
- **Sideloading gap:** GPP's on-device scanning has a detection lag for novel sideloaded malware. The real-time scanning feature introduced in 2023 partially addresses this.

---

## 6. Seccomp-BPF in Android

### 6.1 Implementation

Android applies seccomp-BPF (Secure Computing with Berkeley Packet Filter) filters to all Zygote-forked app processes starting with Android 8.0. The filter is installed in the Zygote before any app code executes, making it mandatory and unmodifiable by the app.

### 6.2 Blocked Syscalls

The seccomp policy blocks syscalls that:
- Are not needed by any legitimate Android app (e.g., `swapon`, `swapoff`, `reboot`, `mount`, `init_module`, `finit_module`, `kexec_load`)
- Have historically been sources of kernel vulnerabilities (e.g., `perf_event_open`, `add_key`, `keyctl`, certain `ioctl` commands)
- Enable namespace manipulation (`unshare`, `setns` for certain namespace types)
- Provide raw kernel interfaces (`process_vm_readv`, `process_vm_writev`, `ptrace`)

The filter operates in strict mode: any blocked syscall kills the process rather than returning an error. This prevents attackers from probing which syscalls are available.

### 6.3 Attack Surface Reduction

The seccomp filter significantly reduces the kernel attack surface reachable from app context. Many kernel vulnerabilities (particularly in subsystems like perf events, keyrings, and namespaces) become unexploitable from app context because the relevant syscalls are blocked before reaching the kernel. Google has stated that seccomp filters block approximately 271 out of ~380 arm64 syscalls for 64-bit processes, and even more for 32-bit processes.

**Limitations:**
- Seccomp cannot filter `ioctl` subcommands granularly — it can block the `ioctl` syscall entirely or allow it, but cannot distinguish between `ioctl` command codes. Since many Android drivers communicate via `ioctl`, the syscall must remain permitted, and driver-specific vulnerabilities remain reachable.
- Binder IPC, the primary Android IPC mechanism, uses `ioctl` on `/dev/binder` and thus remains fully accessible. Binder-facing attack surface (servicemanager, system_server) is not reduced by seccomp.

---

## 7. Treble and VNDK (Vendor Native Development Kit)

### 7.1 Architecture Separation

Project Treble, introduced in Android 8.0, created a formal interface boundary between the Android framework (maintained by Google) and vendor implementations (maintained by SoC vendors and OEMs). The **HIDL (HAL Interface Definition Language)** and later **AIDL (Android Interface Definition Language)** define stable interfaces that vendor HALs must implement.

### 7.2 Security Benefits

- **Process isolation of HALs:** Pre-Treble, many HALs ran within `system_server` or `mediaserver`, meaning a vulnerability in a vendor driver-interface HAL could compromise the entire system server. Post-Treble, HALs run in their own sandboxed processes with dedicated SELinux domains and minimal privileges.
- **VNDK restriction:** The VNDK defines which system libraries vendor code may link against. Vendor processes cannot call into arbitrary framework libraries, reducing the attack surface available after compromising a vendor process.
- **Stable ABI boundary:** The HIDL/AIDL interface forces structured data exchange rather than raw memory sharing, reducing the likelihood of memory corruption bugs at the framework-vendor boundary.
- **Update decoupling:** By separating framework and vendor, Treble enables faster security patches. The framework can be updated independently of vendor blobs, reducing the window of vulnerability exposure.

### 7.3 Limitations

- The separation is only as strong as the SELinux policy enforcement. Misconfigured SELinux policies (common on poorly maintained vendor BSPs) can negate the isolation.
- The kernel remains shared between framework and vendor, and vendor kernel modules (GPU drivers, Wi-Fi drivers, sensor HAL kernel components) run in kernel context with full access. A vulnerability in a Qualcomm GPU driver still provides complete kernel compromise regardless of Treble boundaries.
- Some vendors continue to use passthrough HALs (running in-process rather than out-of-process), weakening the isolation guarantees.

---

## 8. Rust in Android

### 8.1 Adoption Timeline

| Release | Milestone |
|---------|-----------|
| **Android 12 (2021)** | Rust support added to AOSP build system; initial components written in Rust |
| **Android 13 (2022)** | First release where majority of new native code (C/C++/Rust) is memory-safe; ~21% of new native code is Rust; ~1.5 million lines of Rust in AOSP |
| **Android 14 (2023)** | Continued expansion; Rust used in Keystore2, UWB stack, DNS-over-HTTP/3, AVF (Android Virtualization Framework) |
| **Android 15+ (2024-2025)** | Userspace HALs in Rust; Rust trusted applications; VM firmware in AVF migrated to Rust; Kernel driver support via Rust-for-Linux |

### 8.2 Memory Safety Impact

Google's data from the Android Security Bulletin demonstrates a clear correlation between increased Rust adoption and decreased memory safety vulnerabilities:

- **2019:** 223 memory safety vulnerabilities (76% of total)
- **2020:** ~200 memory safety vulnerabilities
- **2021:** ~150 memory safety vulnerabilities
- **2022:** 85 memory safety vulnerabilities (35% of total) — first year memory safety is not the majority
- **2023-2024:** Continued downward trend

**Critical finding:** As of Google's December 2022 report, there have been **zero memory safety vulnerabilities** discovered in Android's Rust code, across approximately 1.5 million lines spanning security-critical components like Keystore2, the UWB stack, and DNS-over-HTTP/3.

Historical vulnerability density in C/C++ Android components (media, Bluetooth, NFC) exceeds 1 vulnerability per 1,000 lines of code (1/kLOC). Based on this density, Google estimates Rust has already prevented hundreds of vulnerabilities from reaching production.

### 8.3 Severity Reduction

Memory safety vulnerabilities are disproportionately severe:
- In 2022, memory safety bugs represented only 36% of bulletin vulnerabilities but accounted for **86% of critical-severity** and **89% of remotely exploitable** vulnerabilities.
- They also represent **78% of confirmed in-the-wild exploited** Android vulnerabilities.

The shift to Rust therefore reduces not just the quantity but the severity of the remaining vulnerability pool.

### 8.4 The `unsafe` Question

Rust's `unsafe` blocks are used sparingly in Android's Rust code. The UWB stack, for example, contains exactly two uses of `unsafe` — both for FFI (Foreign Function Interface) interactions with Java objects via JNI. This mirrors the Java + JNI model: the bulk of code is memory-safe, and the small `unsafe` surface is manageable enough for focused security review.

### 8.5 Performance Implications

Beyond security, Rust eliminates the need for some defensive runtime measures:
- The UWB stack saved several megabytes of memory by running in an existing process rather than requiring a separate sandbox.
- DNS-over-HTTP/3 uses Rust's async/await to process many tasks on a single thread safely, reducing thread overhead.
- Components that would otherwise require sanitizer instrumentation or additional sandboxing in C/C++ can be deployed with fewer mitigations in Rust, improving both code size and runtime performance.

---

## 9. Cross-Cutting Analysis: Effectiveness of the Defense Stack

### 9.1 Layered Defense in Practice

A real-world Android exploit chain targeting a fully patched device must typically defeat:

1. **ASLR/KASLR** — requires an information leak
2. **Seccomp** — must use only permitted syscalls
3. **SELinux** — must escape MAC policy or pivot through allowed domains
4. **CFI/kCFI** — must find type-compatible gadgets or use data-only corruption
5. **PAC/BTI** — must brute-force or bypass pointer signing
6. **SCS** — must locate and corrupt the shadow stack, or avoid return-address corruption entirely
7. **Treble isolation** — compromising a HAL process doesn't automatically yield system_server or kernel access

Each layer independently raises the cost of exploitation. Together, they push the price of a full Android exploit chain into the millions of dollars on the zero-day market, as reflected in Zerodium and other broker pricing (Android full chain RCE with persistence: $2.5M+).

### 9.2 Remaining Weak Points

- **GPU/DSP kernel drivers:** These remain written in C, are reachable from app context (via `ioctl` through seccomp), and have consistently been the most exploited kernel components on Android.
- **Baseband processors:** The cellular baseband runs a separate RTOS that is remotely reachable and historically poorly audited. Android's Linux-side defenses are irrelevant to baseband exploitation.
- **Vendor fragmentation:** Many OEMs ship devices with outdated kernels, missing security patches, disabled hardening features, or overly permissive SELinux policies. The theoretical defense stack may not match the deployed reality.
- **Supply chain and pre-installed malware:** Defense-in-depth assumes a clean starting state. Devices with pre-installed malware (documented on certain low-cost OEMs) bypass all of these mechanisms.

---

## 10. Conclusion

Android's defense-in-depth strategy has demonstrably matured over the past decade. The combination of compiler hardening (CFI, IntSan, BoundsSan, SCS), hardware security features (PAC, BTI, PAN/PXN, MTE in newer SoCs), architectural separation (Treble, seccomp, SELinux), and the strategic adoption of Rust has shifted the vulnerability landscape. Memory safety vulnerabilities — historically the most dangerous class — have dropped from 76% of Android's security bulletin in 2019 to 35% in 2022, with zero memory safety bugs found in Rust components. The remaining challenges lie in vendor-specific components, kernel driver code, and the difficulty of ensuring uniform deployment across the diverse Android ecosystem.

---

## References

1. Vander Stoep, J. "Memory Safe Languages in Android 13." Google Security Blog, December 2022.
2. Vander Stoep, J. & Hines, S. "Rust in the Android platform." Google Security Blog, April 2021.
3. Android Open Source Project. "Android Security Features." source.android.com.
4. Android Open Source Project. "APK Signature Scheme v2/v3." source.android.com.
5. Chen, Y. et al. "BrutePrint: Expose Smartphone Fingerprint Authentication to Brute-Force Attack." IEEE S&P, 2023.
6. Ravichandran, R. et al. "PACMAN: Attacking ARM Pointer Authentication with Speculative Execution." ISCA, 2022.
7. Guard Square. "CVE-2017-13156 - The Janus Vulnerability." 2017.
8. Bluebox Security. "Android FakeID Vulnerability." BlackHat USA, 2014.
9. Google. "Google Play Protect: Scanning apps for security." developers.google.com.
10. Android Open Source Project. "Seccomp filter on Android." source.android.com.
11. Android Open Source Project. "Treble: Modular architecture." source.android.com.
