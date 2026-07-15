# ARM64 Hardware Security Mitigations and Their Bypasses

This document summarizes the architectural operation and publicly documented bypass techniques for the main ARM64 hardware-backed security mitigations used in modern Linux/Android kernels. It is intended as a technical reference for exploit development and mitigation analysis.

---

## 1. Pointer Authentication (PAC)

### 1.1 Architecture
ARMv8.3-A introduces **Pointer Authentication** (PAC). A short cryptographic signature—the **Pointer Authentication Code (PAC)**—is stored in the otherwise unused upper bits of a 64-bit pointer. Special instructions are used to sign a pointer (`PAC*`) and verify it later (`AUT*`); if verification fails, the pointer is corrupted so that dereferencing it causes a fault. The architecture defines five 128-bit keys: APIAKey/APIBKey for instruction pointers, APDAKey/APDBKey for data pointers, and APGAKey for general-purpose signing (`PACGA`). Keys are set in system registers that are inaccessible from EL0.

On Linux, the kernel generates per-process keys at `exec()` time and stores them in the process context. GCC/Clang support return-address signing via `-msign-return-address`, which emits `PACIASP`/`AUTIASP` pairs around function calls.

### 1.2 Tag size and keying
Because only the upper, non-address bits are available, the effective PAC size depends on the configured virtual address (VA) size. On typical ARM64 systems with a 40-bit or 48-bit VA, the PAC can be 7–25 bits. The signature is computed over the pointer value, a 64-bit context/tweak, and the secret key. The standard algorithm is the tweakable block cipher **QARMA**; Apple’s A12 SoC uses an implementation-defined variant.

### 1.3 Documented bypasses
- **PACMAN (speculative bypass).** Ravichandran et al. (ISCA 2022) showed that the result of a PAC authentication can be leaked through speculative side channels. Even though an `AUT*` failure does not architecturally change state, the transient execution path can perform a dependent load that leaves a cache trace, allowing an attacker to brute-force or oracle PAC values without crashing. This is the **PACMAN** attack.
- **Signing gadgets / PAC oracles.** PAC is designed to resist memory-disclosure attackers, but a writable, attacker-controlled value that is subsequently signed by a legitimate kernel code path can be used as a signing oracle. Project Zero’s analysis of Apple’s iOS kernel on the A12 demonstrated that an attacker with arbitrary kernel read/write can forge PAC signatures by locating or coercing such signing code paths (e.g., by patching a vtable and abusing a `getTargetAndTrapForIndex` method that returns a writable `IOExternalTrap`).
- **Cross-EL / cross-key forgeries.** Because the same underlying cryptographic machinery is used for EL0 and EL1 PAC keys, an attacker who can read or write the per-thread key registers can substitute keys. This can turn a signing gadget for one key into a forgery for another, or sign kernel pointers from userspace if keys are shared.
- **Data-only attacks.** Exploits that never dereference a forged pointer (e.g., overwriting `cred` fields, `modprobe_path`, or `selinux_enforcing` directly) simply bypass PAC.

### 1.4 iOS / Android exploit context
Apple devices use PAC extensively for vtables and function pointers; Android devices with ARMv8.3+ use PAC for return addresses and selected function pointers. Real-world exploits therefore either use data-only corruption (DirtyCred, DirtyPipe) or chain a signing oracle to call a forged function pointer.

---

## 2. Memory Tagging Extension (MTE)

### 2.1 Architecture
ARMv8.5-A **Memory Tagging Extension (MTE)** assigns a **4-bit tag** to each **16-byte granule** of memory. The tag is stored in unused bits of the physical address space (in the page tables and/or physical memory tag bits) and is also embedded in the upper bits of the pointer. Every load/store performs a **tag check**: the pointer’s tag must match the memory tag or the CPU raises a **Tag Check Fault (TCF)**.

### 2.2 Modes of operation
MTE supports three enforcement modes:
- **Synchronous (sync-MTE):** the fault is delivered precisely at the offending instruction. Strongest security guarantee.
- **Asynchronous (async-MTE):** the fault is recorded in a per-core flag (`TFSR_ELx`) and delivered later, usually at the next kernel entry. Weaker but faster.
- **Asymmetric:** loads are synchronous, stores are asynchronous. This is the default mode on Android.

### 2.3 Tag granularity and deterministic vs. probabilistic tagging
With 4-bit tags there are only 16 possible values. Random-tag heap allocators (Scudo, PartitionAlloc) choose a tag per allocation, giving an attacker a **1/15 (or 1/16) chance** of guessing the correct tag on a stray access. This is a **soft probabilistic mitigation**, not a deterministic solution. Deterministic tagging schemes assign fixed tags to isolate memory regions (e.g., IUBIK uses two tags to separate user-controlled kernel objects from the rest of kernel memory).

### 2.4 Speculative and software bypasses
Project Zero’s pre-production evaluation of MTE found no direct micro-architectural side channel for tag-check success, but identified several bypass classes:
- **Known-tag bypasses:** any channel that leaks the tag value (e.g., Spectre-style speculative disclosure, pointer equality comparisons such as `kcmp`, or pointer-keyed data structures) collapses the 1/16 probability to 1.
- **Unknown-tag bypasses (async-MTE):** because async faults are deferred, a compromised thread can sometimes complete a short exploit sequence before entering the kernel and receiving the fault. Examples include installing a malicious first-chance signal handler (Breakpad/Crashpad), using a coerced thread in a multi-threaded process, or exploiting system-call argument handling.
- **TCMA1 (tag `0b1111`).** The kernel sets `TCR_ELx.TCMA1` so that any pointer with tag `0b1111` can be dereferenced without tag checks. This is required for converting physical addresses and `struct page` offsets into usable pointers, but it gives an attacker a reliably forgeable tag.

### 2.5 TikTag: speculative tag leakage
Kim et al. (IEEE S&P 2024, *TikTag*) demonstrated that MTE tag checks **do** create exploitable speculative side channels. They discovered two gadgets, **TikTag-v1** and **TikTag-v2**, that leak the tag of an arbitrary memory address through speculation shrinkage in branch prediction/data prefetchers and store-to-load forwarding, respectively. Their end-to-end attacks against Chrome V8 and the Linux kernel leak tags with **>95% success in under 4 seconds**, turning MTE’s probabilistic defense into a near-certain bypass. ARM acknowledged the issue in December 2023.

### 2.6 Rowhammer interaction
MTE tags are stored in physical memory (in the page-table entry bits `[59:56]` and/or dedicated physical tag bits). Because DRAM bit flips are agnostic to semantic meaning, a Rowhammer-induced flip can corrupt a stored tag, either matching a forged pointer tag (false negative) or mismatching a legitimate pointer tag (denial of service). This makes MTE only as strong as the underlying DRAM integrity against Rowhammer-class faults. (No dedicated empirical Rowhammer+MTE study was retrieved in this research pass; the interaction follows from the tag-in-memory design.)

### 2.7 Android status
MTE first shipped on the **Pixel 8 (Tensor G3)** in October 2023 and is enabled in asymmetric mode for selected processes. Exploit bypasses observed in the wild and in research include:
- GPU paths (Mali allocations on Pixel devices are not MTE-tagged).
- Brute-forcing the 4-bit tag (16 attempts on average).
- Speculative tag leakage (TikTag).
- Corrupting allocator metadata before the tag check is reached.

---

## 3. Branch Target Identification (BTI)

### 3.1 Architecture
ARMv8.5-A **BTI** requires that the target of any indirect branch be a **BTI landing-pad instruction** (`BTI`/`BTI c`/`BTI j`/`BTI jc`). If execution reaches an indirect branch target that is not a valid landing pad, the CPU raises a Branch Target Exception. This is a coarse-grained **forward-edge control-flow integrity** mechanism: it prevents an attacker from jumping into the middle of an arbitrary instruction, but it does not restrict which *function* is called at a given call site.

### 3.2 Limitations
- **No type safety.** BTI only checks that the target is a function entry; it does not verify that the called function matches the expected prototype or return type. Any function with the same entry instruction pattern is a legal target.
- **Data-only attacks bypass BTI.** Because BTI only mediates indirect control transfers, corruption of data pointers, credentials, or page tables does not trigger it.
- **Indirect calls and JOP.** Attackers can still chain calls through legitimate functions (JOP) as long as each target begins with a landing pad. Compiler-emitted landing pads are dense at function entries, so the gadget set is only slightly reduced compared to unrestricted JOP.

### 3.3 Relationship to CFI
BTI is the hardware counterpart to software CFI. In the Linux/Android ecosystem, **kCFI** (Clang `-fsanitize=kcfi`) is preferred for forward-edge protection because it enforces type-signature matching, whereas BTI is too coarse. BTI is typically enabled as a complementary hardening measure (`-mbranch-protection=bti+pac` on ARM64).

---

## 4. PAN (Privileged Access Never)

### 4.1 Architecture
ARMv8.1+ **PAN** is an EL1 control bit that prevents the kernel from accessing userspace memory. Any attempt to dereference a user virtual address from kernel mode faults, mirroring x86 SMAP. This stops attackers from placing exploit data or ROP stacks in user memory and having the kernel dereference them directly.

### 4.2 Documented bypasses
- **Intentional copy primitives.** The kernel uses `copy_from_user()` and `copy_to_user()` to move data across the EL1/EL0 boundary. A kernel bug that controls these calls can still be exploited.
- **Kernel-to-kernel primitives.** If the attacker has arbitrary kernel read/write, they can operate entirely on kernel objects (e.g., `DirtyCred`, `DirtyPipe`) and never need to touch user memory.
- **USMA / KSMA.** An attacker who can corrupt page tables can map physical memory (including user memory) at a kernel virtual address, bypassing PAN by accessing it through a kernel VA.

---

## 5. PXN (Privileged Execute Never)

### 5.1 Architecture
**PXN** is a page-table permission bit that marks a page as non-executable when the CPU is in EL1. It is the ARM equivalent of x86 SMEP. With PXN, the kernel cannot execute code from userspace pages, blocking the classic **ret2user** attack where the kernel is tricked into jumping to attacker-controlled shellcode in user memory.

### 5.2 Documented bypasses
- **ROP/JOP in kernel text.** Because userspace code is no longer executable, attackers build return-oriented or jump-oriented programming chains using existing kernel code.
- **USMA / KSMA.** If the attacker can remap kernel code pages as writable or map attacker-controlled physical memory as executable in the kernel page tables, PXN can be bypassed.
- **Data-only privilege escalation.** Techniques like overwriting `modprobe_path` or `cred` fields do not require executing attacker-controlled code, so PXN is irrelevant.

---

## 6. KASLR (Kernel Address Space Layout Randomization)

### 6.1 Architecture
ARM64 **KASLR** (`CONFIG_RANDOMIZE_BASE`) randomizes the virtual base address of the kernel image at boot. The bootloader supplies entropy via `/chosen/kaslr-seed` (device tree) or the UEFI `EFI_RNG_PROTOCOL`; a displacement of less than `MIN_KIMG_ALIGN` disables KASLR. With `CONFIG_RANDOMIZE_MODULE_REGION_FULL`, the module region is randomized within a 2 GB window covering the core kernel. KASLR also randomizes the kernel stack base and, where supported, dynamic memory regions.

### 6.2 Entropy on ARM64
The kernel image must be placed at a 2 MB-aligned base. The randomization window is architecture- and configuration-dependent; in practice, ARM64 kernels commonly randomize the kernel text within a 512 MB–2 GB window aligned to 2 MB, yielding on the order of **9–10 bits of effective entropy** for the kernel base, plus additional module and stack entropy. The exact entropy is constrained by early-boot physical memory layout, the `MIN_KIMG_ALIGN` requirement, and the `KIMAGE` size.

### 6.3 Information-leak attacks
The canonical bypass is to leak a kernel code or data pointer from the vulnerability itself (e.g., an out-of-bounds read, uninitialized stack/heap variable, or `kfree` of a stale object containing a function pointer). Once one pointer is known, the entire kernel layout is derandomized because the slide is constant.

### 6.4 Prefetch side channels
**EntryBleed (CVE-2022-4543)** demonstrated that on x86_64, KPTI left syscall entry stubs mapped in userspace page tables with the **global bit** set, so prefetch timings could reveal the slid entry address and thus the KASLR base. While EntryBleed is x86-specific, the underlying principle—using timing of cached vs. uncached kernel addresses—applies to ARM64 as well. ARM64 has its own prefetch instructions (`PRFM`) and TLB behavior, and vulnerabilities in the placement of KPTI/unmap_kernel_at_el0 entry stubs or vector tables can create analogous side channels. The kernel’s own KASLR documentation notes that information exposures are the primary target of KASLR attacks.

### 6.5 Exploitation without KASLR
Many modern exploit chains bypass the need for KASLR entirely by using **data-only** corruption (e.g., `DirtyCred`) or by deriving the kernel base from the corrupted page tables or physmap (`ret2dir`).

---

## 7. Control-Flow Integrity (CFI)

### 7.1 Clang CFI and kCFI
Android has shipped two CFI implementations in the kernel:
- **Clang CFI** (Linux ≤ 6.0): requires Link-Time Optimization (LTO). The compiler builds jump tables of all functions sharing the same type signature; every indirect call is checked against the appropriate jump table before dispatching.
- **Clang KCFI** (Linux ≥ 6.1): does not require LTO. Each valid indirect-call target is annotated with a hash/ID in the instruction stream; the call site checks the ID before calling. This is what Android GKI kernels use today.

Both are controlled by `CONFIG_CFI_CLANG` and can be run in permissive mode (`CONFIG_CFI_PERMISSIVE`) for debugging.

### 7.2 Forward-edge and backward-edge
CFI’s **forward-edge** protection restricts indirect calls to functions with the correct signature. **Backward-edge** protection is provided separately by the **Shadow Call Stack** (see Section 8). CFI does not protect direct calls or returns; it only validates that the destination of an indirect function-pointer call is a legitimate target.

### 7.3 Limitations and bypasses
- **Same-signature gadgets.** If many kernel functions share the same prototype (e.g., `void fn(void)`), an attacker can still choose among all of them. LWN’s coverage of Kees Cook’s CFI work notes that 55% of indirect-call targets had ≤5 possible targets, but 7% had >100.
- **Data-only attacks.** DirtyCred, DirtyPipe, and Dirty Pagetable never hijack control flow; they modify data directly, so CFI is not triggered.
- **Type confusion.** Kernel code that casts function pointers to incompatible types will cause CFI failures in development, but a determined attacker can find call sites where the type check is weak or where the compiler cannot resolve the type.
- **KSMA / kernel text patching.** An attacker with arbitrary kernel write can patch the CFI check itself or overwrite the jump tables, disabling CFI.
- **BTI is too coarse.** As noted above, BTI only enforces landing pads, not signatures, so it does not replace kCFI.

---

## 8. Shadow Call Stack (SCS)

### 8.1 Architecture
The **Shadow Call Stack** is a software instrumentation mode (Clang `-fsanitize=shadow-call-stack`) that protects the **backward edge** of function calls. On ARM64, a separate shadow stack is allocated and referenced via the **x18** platform register. In the function prologue, the return address is saved to both the regular stack and the shadow stack; in the epilogue, the return address is loaded from the shadow stack, not from the regular stack. The regular stack copy is kept only for unwinders and compatibility.

Because x18 is reserved for the shadow stack pointer and not spilled to memory, the shadow stack location is hidden from attackers with arbitrary memory read. Android supports SCS for both kernel (`CONFIG_SHADOW_CALL_STACK`) and selected userspace components.

### 8.2 Bypasses
- **Data-only attacks.** As with PAC, CFI, and BTI, SCS is irrelevant if the attacker never needs to corrupt a return address.
- **Leaking/corrupting the shadow stack.** If an attacker can discover the shadow stack location (e.g., through an info leak or by corrupting x18 itself), return addresses can be overwritten.
- **Forward-edge corruption.** SCS only protects returns; it does not stop indirect-call or vtable corruption, which is handled by CFI.
- **Partial overwrites.** If a function does not save x30 to the shadow stack (e.g., leaf functions, assembly routines), the regular stack copy remains the authoritative return address.

---

## 9. Cross-cutting themes

| Mitigation | Control-flow attacks | Data-only attacks | Page-table attacks |
|---|---|---|---|
| PAC | Partial (signing gadgets) | **Bypassed** | **Bypassed** |
| MTE | Partial (tag brute force, TikTag) | Partial (tagged heap) | May bypass (untagged PT pages, TCMA1) |
| BTI | Coarse-grained block | **Bypassed** | **Bypassed** |
| PAN | Need kernel VA | **Bypassed** | **Bypassed** (physmap) |
| PXN | Need ROP/JOP in kernel | N/A | N/A |
| KASLR | Need info leak | Often unnecessary | Need physmap leak |
| CFI | Blocked (need type gadgets) | **Bypassed** | **Bypassed** |
| SCS | Blocked (returns protected) | **Bypassed** | **Bypassed** |

The dominant trend in modern Android kernel exploitation is to **avoid the control plane entirely**: once a read/write primitive is obtained (via cross-cache, Dirty Pagetable, or KSMA), the exploit writes `modprobe_path`, `cred` fields, or SELinux state rather than calling a forged pointer. This bypasses PAC, BTI, CFI, and SCS simultaneously.

---

## Sources

- Corbet, J. “ARM pointer authentication.” LWN.net, 2017. https://lwn.net/Articles/718888/
- Azad, B. “Examining Pointer Authentication on the iPhone XS.” Google Project Zero, 2019. https://projectzero.google/2019/02/examining-pointer-authentication-on.html
- Ravichandran, J., et al. “PACMAN: Attacking ARM Pointer Authentication with Speculative Execution.” ISCA 2022. https://pacmanattack.com/
- Brand, M. “Summary: MTE As Implemented.” Google Project Zero, 2023. https://projectzero.google/2023/08/summary-mte-as-implemented.html
- Brand, M. “MTE As Implemented, Part 1: Implementation Testing.” Google Project Zero, 2023. https://projectzero.google/2023/08/mte-as-implemented-part-1.html
- Brand, M. “MTE As Implemented, Part 2: Mitigation Case Studies.” Google Project Zero, 2023. https://projectzero.google/2023/08/mte-as-implemented-part-2-mitigation.html
- Brand, M. “MTE As Implemented, Part 3: The Kernel.” Google Project Zero, 2023. https://projectzero.google/2023/08/mte-as-implemented-part-3-kernel.html
- Kim, J., et al. “TikTag: Breaking ARM’s Memory Tagging Extension with Speculative Execution.” IEEE S&P 2024. arXiv:2406.08719. https://arxiv.org/abs/2406.08719
- Momeu, M., et al. “IUBIK: Isolating User Bytes in Commodity Operating System Kernels via Memory Tagging Extensions.” IEEE S&P 2025. https://cs.brown.edu/~vpk/papers/iubik.sp25.pdf
- Edge, J. “Control-flow integrity for the kernel.” LWN.net, 2020. https://lwn.net/Articles/810077/
- “Control flow integrity in the kernel.” Android Open Source Project, 2026. https://source.android.com/docs/security/test/kcfi
- “ShadowCallStack.” Android Open Source Project, 2026. https://source.android.com/docs/security/test/shadow-call-stack
- “Kernel Self-Protection.” Linux Kernel Documentation. https://www.kernel.org/doc/html/latest/security/self-protection.html
- Willsroot. “EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543).” 2022. https://www.willsroot.io/2022/12/entrybleed.html
- Linux ARM64 Kconfig — `RANDOMIZE_BASE` / `RANDOMIZE_MODULE_REGION_FULL`. https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/Kconfig
- Linux ARM64 KASLR initialization source. https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/kernel/kaslr.c
- Göktaş, E., et al. “Speculative Probing: Hacking Blind in the Spectre Era (BlindSide).” CCS 2020. https://download.vusec.net/papers/blindside_ccs20.pdf
- Maar, L., et al. “Defects-in-Depth: Analyzing the Integration of Effective Defenses against One-Day Exploits in Android Kernels.” USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/maar-defects
- Android & Linux Kernel Mitigations Reference. Local knowledge base, `mitigations.md`. `/home/t/.pi/agent/skills/android-kernel-exploitation/chapters/mitigations.md`
- ARM64 KSMA/USMA chapter (MTE tag bits in PTEs). Local knowledge base. `/home/t/.pi/agent/skills/android-kernel-exploitation/chapters/07-ksma-usma.md`
