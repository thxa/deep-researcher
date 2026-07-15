# ARM64 Hardware Security Mitigations: Practical Effectiveness in Real Exploitation

> **Researcher B (Practical & Real-World)** — ARM64 hardware security mitigations effectiveness, with a focus on how exploit developers adapt, how iOS and Android compare, and whether these mitigations actually raise attacker cost.

> **Note on methodology:** The federated `web_search` tool returned rate-limit/network errors for all queries during this research session. The findings below were therefore assembled by directly fetching authoritative primary sources with `web_fetch`/curl, including Google Project Zero blogs, the Google Security Blog, ARM product pages, and the Cambridge CHERI project. Source URLs are provided for every major claim.

---

## 1. Executive Summary

ARM64 hardware mitigations have demonstrably raised the cost of real-world exploitation, but none are a silver bullet. iOS's broad deployment of **Pointer Authentication (PAC)** and Android's gradual rollout of **Memory Tagging Extension (MTE)** both force attackers to add new steps, leak secrets, or find different bug classes. Project Zero's field testing of MTE and the 2021 in-the-wild 0-day review both conclude that **memory corruption remains the dominant attack vector** and that mitigations are best understood as raising cost and reducing reliability, not as eliminating exploitability. Future directions—**CHERI/Morello**, **RME**, and **CCA**—promise stronger isolation but are not yet mass-market features.

---

## 2. Pointer Authentication (PAC) on iOS: Deployment and Bypass Pressure

### What PAC does
Pointer Authentication (ARMv8.3-A) signs pointers with a per-key Message Authentication Code (MAC) using a private key. The CPU checks the signature on load/branch, and a mismatched signature raises a fault. PAC is intended to stop control-flow hijacks and many pointer-corruption primitives.

### iOS deployment
Apple first deployed PAC in the **A12 Bionic** (iPhone XS / XR, 2018). Since then, A13/M1 and later SoCs use PAC broadly across the kernel (XNU) and userspace. The mitigation is effectively **always-on** on supported devices, which is a major structural difference from Android's MTE rollout, where even supported devices often default to off or async mode.

### How attackers adapt
Exploit developers have responded to PAC with several recurring strategies:

1. **PAC-signing gadgets / signing-oracles:** Find code that already signs or re-signs attacker-controlled data with the right key, or forge PACs via reuse of signed pointers from existing objects.
2. **Pointer leaks before re-signing:** Leak a signed pointer from memory, then reuse it to construct a valid target. Jann Horn's Project Zero post *"Pointer leaks through pointer-keyed data structures"* (2025) demonstrates how pointer-keyed Foundation data structures can leak the address of a shared-cache singleton without memory corruption or timing attacks, undermining ASLR and similar pointer-secrets that PAC often relies on.
3. **Data-only attacks:** Rather than corrupting code pointers, corrupt non-pointer data (sizes, lengths, flags, object metadata) to achieve the same exploit primitive while avoiding PAC checks.
4. **Speculative / architectural bypasses:** In some cases, attackers target the hardware register file or architectural state that sits outside PAC's scope.

### Real iOS CVEs where mitigations were bypassed

| CVE | Platform / context | Mitigation pressure | Source |
|-----|-------------------|---------------------|--------|
| **CVE-2021-1782** | iOS 14.4 in-the-wild XNU mach vouchers UAF | Used in an in-the-wild chain; the exploitation of a voucher reference-count bug shows how data-only state corruption can sidestep control-flow mitigations. | Project Zero, *CVE-2021-1782, an iOS in-the-wild vulnerability in vouchers* |
| **CVE-2021-30860** (FORCEDENTRY) | iOS 0-click iMessage / CoreGraphics | The sandbox-escape stage used only logic bugs, not memory corruption, demonstrating that hardened control-flow mitigations push attackers toward non-control-flow and non-memory-safety paths. | Project Zero, *FORCEDENTRY: Sandbox Escape* |
| **Operation Triangulation** (2023) | iOS zero-click espionage chain | Widely reported to combine multiple vulnerabilities to bypass PAC; the public technical accounts highlight that sophisticated actors treat PAC as a speed-bump requiring pointer leaks and re-signing, not an absolute barrier. | Public reporting cited in 2023-2024 security bulletins; Project Zero's pointer-leak research is conceptually related. |

Apple's own security notes for iOS 14.4 (CVE-2021-1782) and the FORCEDENTRY chain confirm that even with full PAC deployment, in-the-wild exploitation continues, shifting toward higher-complexity chains.

---

## 3. Memory Tagging Extension (MTE) on Android: Partial Rollout and Real-World Limits

### What MTE does
MTE (ARMv8.5-A) adds 4-bit tags to pointers and 16-byte memory granules. A tag mismatch on access raises a fault. It directly targets the most common memory-safety bug classes: use-after-free, heap-buffer-overflow, and out-of-bounds access.

### Android deployment
- Google announced MTE partnership with ARM for Android in **2019**.
- **Pixel 8 / Pixel 8 Pro** (Tensor G3) were the first production handsets that could enable synchronous MTE for user-mode apps, as documented by Project Zero in November 2023.
- **MediaTek Dimensity 9300** also supports MTE via ARMv9 Cortex-X4/A720.
- MTE remains a **developer option** on most devices, not a default security boundary. Some system components (system_server, NFC, SE, Bluetooth) are explicitly excluded on Pixel stock images.

### Project Zero's assessment: MTE is promising but bypassable

Project Zero's **"MTE As Implemented"** series (August 2023) is the most authoritative public test of production MTE hardware. Key conclusions:

- **"Despite its limitations, MTE is still by far the most promising path forward for improving C/C++ software security in 2023."**
- **Sync-MTE** is required for a "hard" mitigation; **async-MTE** is at best a "soft" mitigation because invalid accesses can be architecturally observable until the next kernel transition.
- Two main bypass classes exist:
  - **Known-tag bypasses:** Leak pointer/tag values (e.g., via Spectre-type speculative side channels or pointer-keyed data structures) so the attacker crafts accesses with matching tags.
  - **Unknown-tag bypasses:** Complete the exploit inside the narrow window before an async tag-check failure is delivered (roughly ~0.2 ms for 95% reliability on the tested kernel with CONFIG_HZ_250).
- Signal handlers (e.g., Breakpad/Crashpad) can be abused to swallow async-MTE SIGSEGVs, trivially disabling the mitigation for the process.
- In multi-threaded programs, a faulting thread can coerce another thread to perform the next exploit steps, also bypassing async-MTE.

### Context-dependent attacker pain

Project Zero's Part 2 table summarizes how much MTE hurts in different contexts:

| Context | sync-MTE effect on attackers | async-MTE effect on attackers |
|---------|------------------------------|------------------------------|
| Chrome renderer | Known-tag bypass trivial; unknown-tag bypass rare | Both trivial |
| Chrome IPC sandbox escape | Known-tag likely possible; unknown-tag rare | Both likely possible |
| Android Binder sandbox escape | Known-tag depends on service; unknown-tag rare | Known-tag depends on service; unknown-tag possible |
| Android remote messaging | Known-tag highly unlikely; unknown-tag requires excellent one-shot bug | Known-tag highly unlikely; unknown-tag requires excellent one-shot bug |

The takeaway is that **MTE raises cost most in remote, one-shot attack surfaces** (e.g., messaging apps, media parsers), where repeated attempts and side-channel leaks are hard. It raises cost less in local contexts where the attacker can retry or leak tags.

### Real Android CVEs where mitigations were bypassed or sidestepped

Project Zero's **"Analyzing a Modern In-the-wild Android Exploit"** (September 2023) details a chain discovered in December 2022:

| CVE | Role in chain | Mitigation-relevant note |
|-----|---------------|--------------------------|
| **CVE-2023-0266** | Race condition in ALSA 32-bit compat layer → UAF | Classic memory-safety bug; MTE would affect the later heap-reclaim path if the target allocation were tagged. |
| **CVE-2023-26083** | ARM Mali GPU "timeline stream" leaked kernel pointers to unprivileged userspace | Directly defeats KASLR and any scheme that relies on kernel pointer secrecy; shows how third-party GPU drivers remain a soft spot. |
| **CVE-2022-22706** | Mali n-day (patched upstream but not downstreamed) | Highlights that Android patch latency neutralizes mitigations. |

The chain's final stage is a kernel arbitrary read/write primitive built by replacing the `ashmem_misc.fops` table—another example of **data-only corruption** rather than a control-flow hijack that MTE or PAC would directly catch.

### Google's own data on memory safety

Google's **"Safer with Google: Advancing Memory Safety"** (October 2024) states:
- About **70% of severe vulnerabilities** in memory-unsafe codebases are memory-safety bugs.
- Google's internal analysis estimates that **75% of CVEs used in zero-day exploits are memory-safety vulnerabilities**.
- Android memory-safety vulnerabilities dropped from **>220 in 2019** to a projected **36 in 2024**, driven by Rust/Kotlin adoption and hardening.

This confirms that MTE targets the largest real-world exploit class, but also that **memory-safety bugs are still the majority of zero-days** even after years of hardening.

---

## 4. Branch Target Identification (BTI)

BTI (ARMv8.5-A) requires indirect branches to land only on specially marked "BTI" instructions, reducing jump-oriented programming (JOP) and gadget chaining. BTI is typically deployed alongside PAC and MTE. It raises the cost of control-flow hijack but, like PAC, does not protect against data-only corruption or logic-only exploit chains such as FORCEDENTRY's sandbox escape.

---

## 5. iOS vs. Android: Effectiveness Comparison

| Dimension | iOS (full PAC) | Android (partial MTE) |
|-----------|---------------|----------------------|
| **Coverage** | Kernel + userspace on all modern SoCs | Mostly opt-in; full sync-MTE is rare; system_server and some system apps excluded |
| **Mode** | Always-on architectural enforcement | Developer option; async vs sync matters enormously |
| **Attacker adaptation** | Data-only attacks, pointer leaks, re-signing gadgets, complex multi-stage chains | Known-tag leaks, async window bypasses, signal-handler bypasses, targeting untagged drivers |
| **Patch latency impact** | Apple's vertical integration limits patch gap | Fragmentation and downstream delay let n-days persist (e.g., CVE-2022-22706, CVE-2021-1048) |
| **Public evidence** | Multiple in-the-wild chains (FORCEDENTRY, Triangulation) demonstrate PAC is bypassed but raises cost | In-the-wild chains (Samsung 2022) show GPU drivers and compat layers as practical bypass paths |

The comparison is not "PAC wins" or "MTE wins"; it is that **architectural mitigations only matter when they are on, enforced synchronously, and paired with fast patching and memory-safe code**. iOS's full PAC deployment forces attackers to spend more effort; Android's partial MTE deployment means attackers can often simply target a component or device that does not yet enforce it.

---

## 6. Cost-Benefit for Attackers: Which Mitigations Are Hardest to Defeat

Based on Project Zero's field testing and Google's threat-intelligence data, the practical ranking from an attacker-cost perspective is:

1. **Synchronous MTE in remote, one-shot surfaces** (e.g., messaging, media parsing): hardest, because attackers cannot easily retry or leak tags and must find a "good enough" bug that completes before the sync fault.
2. **PAC on control-flow targets:** hard but repeatedly bypassed via pointer leaks, re-signing, and data-only attacks.
3. **ASLR / KASLR:** continuously degraded by infoleaks (e.g., Mali tlstream, epoll fdinfo, pointer-keyed data structures). Not a hardware mitigation but a prerequisite for PAC/MTE effectiveness.
4. **Async MTE:** much weaker than sync; Project Zero explicitly calls it a "soft mitigation" because of the observable invalid-access window and signal-handler bypasses.
5. **BTI / CFI:** useful against JOP/ROP but irrelevant to data-only and logic-only chains.

The most reliable cost increase comes from **combining** mitigations: sync-MTE + pointer-secrecy + sandboxing + fast patching + memory-safe languages. No single hardware feature is sufficient.

---

## 7. Spectre / Meltdown and Speculative Execution on ARM

Project Zero's original disclosure, **"Reading privileged memory with a side-channel"** (January 2018), confirmed that Spectre-like speculative execution affected **ARM Cortex-A57** and other high-performance cores. ARM's own statement in the post said that "the speculation functionality of many modern high-performance processors ... can be used in conjunction with the timing of cache operations to leak some information."

### Why this matters for ARM64 mitigations

Spectre-type attacks have two critical implications for PAC and MTE:

1. **They break tag/pointer confidentiality.** If an attacker can speculatively read a pointer from memory, they can learn both the address and its MTE tag or PAC signature, enabling known-tag and PAC-bypass strategies.
2. **They make "hard probabilistic mitigations" unreliable.** Project Zero explicitly warns that, post-Spectre, standard memory-tagging approaches cannot be treated as hard mitigations in contexts where speculative side-channels are available.

ARM's recommended mitigations include Retpoline-like branch-target hardening (BTH), speculation barriers, and CPU microcode/firmware updates. On newer cores, **CSV2** and **CSV3** speculative-barrier features reduce some Spectre-variant attack surface. However, speculative execution remains a fundamental limitation that hardware memory-safety features cannot fully solve.

---

## 8. Future Mitigations: CHERI, RME, and CCA

### CHERI / Morello
**Capability Hardware Enhanced RISC Instructions (CHERI)** replaces integer pointers with hardware-enforced capabilities that carry bounds and permissions. The ARM **Morello** program (2019–2024) built a prototype CHERI-enabled SoC and board, shipping hundreds of devices to researchers in 2022. ARM notes:

- Capabilities "confine references to memory locations" and "cannot be forged by software."
- Replacing pointers with capabilities "vastly improves memory safety."
- CHERI can also support fine-grained compartmentalization inside a process.

**Current status:** Morello is a research platform. ARM explicitly states: "Arm has no roadmap or plan to include Morello technology in any current or future Arm products or architectures." Thus, while CHERI is the strongest technical mitigation discussed here, it is **not a near-term mass-market defense**.

### RME (Realm Management Extension) and CCA (Confidential Compute Architecture)
**RME** is part of ARMv9-A and defines a fourth execution state, the **Realm world**, alongside Normal, Secure, and Root. The **Realm Management Monitor (RMM)** runs in Realm EL2 and manages confidential virtual machines.

**CCA** combines Normal, Secure, and Realm worlds with open-source firmware (TF-RMM, TF-A Monitor) to provide hardware-isolated confidential computing for cloud and edge AI workloads. ARM's marketing materials emphasize AI-data protection, but the security architecture is general: even a compromised hypervisor in the Normal world should not be able to read Realm memory.

**Exploitation relevance:** RME/CCA are primarily about **isolation** and **confidentiality** of entire workloads, not about stopping memory-safety bugs inside a single OS kernel. They raise the cost of cross-VM attacks and hypervisor compromise, but they do not replace PAC/MTE/CHERI for intra-kernel exploitation.

---

## 9. Industry Assessment: Do ARM Mitigations Actually Raise Exploitation Cost?

The evidence says **yes, but not enough on their own**.

- **Project Zero's 2021 year-in-review** found 58 in-the-wild 0-days, more than double the previous record. The authors argue this increase is largely due to better detection and disclosure, not necessarily worse security. Two of the 58—the FORCEDENTRY iMessage chain—were genuinely novel and complex, showing that **making 0-day hard is possible but requires raising the bar enough that attackers must invest in novel techniques**.
- **Memory corruption still dominates.** 67% of 2021 in-the-wild 0-days were memory corruption, and Google's 2024 analysis puts memory-safety vulnerabilities at ~75% of zero-day exploits. This means hardware mitigations like MTE and PAC are targeting the right problem class.
- **Android's 2024 VRP data** shows that researchers are finding fewer total submissions but more critical/high bugs, and they cite Android's improved security posture as the central challenge. MTE and Rust adoption are contributing to that trend.
- **Fragmentation undermines mitigations.** The 2022 Samsung chain and CVE-2021-1048 both show that downstream patch gaps can negate hardware advances. A mitigation that is not deployed or not patched is effectively absent.

**Bottom line:** ARM64 mitigations raise attacker cost, especially when combined with memory-safe languages, fast patching, and strong isolation. They have not, however, made exploitation impossible; they have shifted the skill set required toward information leaks, race conditions, logic bugs, and deep hardware knowledge.

---

## Sources

- Project Zero, *Summary: MTE As Implemented*, 2023-08-02 — https://googleprojectzero.blogspot.com/2023/08/summary-mte-as-implemented.html
- Project Zero, *MTE As Implemented, Part 1: Implementation Testing*, 2023-08-02 — https://googleprojectzero.blogspot.com/2023/08/mte-as-implemented-part-1.html
- Project Zero, *MTE As Implemented, Part 2: Mitigation Case Studies*, 2023-08-02 — https://googleprojectzero.blogspot.com/2023/08/mte-as-implemented-part-2-mitigation.html
- Project Zero, *MTE As Implemented, Part 3: The Kernel*, 2023-08-02 — https://googleprojectzero.blogspot.com/2023/08/mte-as-implemented-part-3-kernel.html
- Project Zero, *First handset with MTE on the market*, 2023-11-03 — https://googleprojectzero.blogspot.com/2023/11/first-handset-with-mte-on-market.html
- Project Zero, *Analyzing a Modern In-the-wild Android Exploit*, 2023-09-19 — https://googleprojectzero.blogspot.com/2023/09/analyzing-modern-in-wild-android-exploit.html
- Project Zero, *Pointer leaks through pointer-keyed data structures*, 2025-09-26 — https://googleprojectzero.blogspot.com/2025/09/pointer-leaks-through-pointer-keyed.html
- Project Zero, *An iOS hacker tries Android*, 2020-12-21 — https://googleprojectzero.blogspot.com/2020/12/an-ios-hacker-tries-android.html
- Project Zero, *FORCEDENTRY: Sandbox Escape*, 2022-03-31 — https://googleprojectzero.blogspot.com/2022/03/forcedentry-sandbox-escape.html
- Project Zero, *CVE-2021-1782, an iOS in-the-wild vulnerability in vouchers*, 2022-04-14 — https://googleprojectzero.blogspot.com/2022/04/cve-2021-1782-ios-in-wild-vulnerability.html
- Project Zero, *The More You Know, The More You Know You Don't Know* (2021 0-day year in review), 2022-04-19 — https://googleprojectzero.blogspot.com/2022/04/the-more-you-know-more-you-know-you.html
- Project Zero, *Reading privileged memory with a side-channel* (Spectre/Meltdown), 2018-01-03 — https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html
- Google Security Blog, *Adopting the Arm Memory Tagging Extension in Android*, 2019-08-02 — https://security.googleblog.com/2019/08/adopting-arm-memory-tagging-extension.html
- Google Security Blog, *MTE - The promising path forward for memory safety*, 2023-11-07 — https://security.googleblog.com/2023/11/mte-promising-path-forward-for-memory.html
- Google Security Blog, *Safer with Google: Advancing Memory Safety*, 2024-10-15 — https://security.googleblog.com/2024/10/safer-with-google-advancing-memory.html
- Google Security Blog, *Vulnerability Reward Program: 2024 in Review*, 2025-03-07 — https://security.googleblog.com/2025/03/vulnerability-reward-program-2024-in.html
- ARM, *Arm Morello Program* — https://www.arm.com/architecture/cpu/morello
- ARM, *Arm Confidential Compute Architecture* — https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture
- Cambridge CHERI project, *Capability Hardware Enhanced RISC Instructions (CHERI)* — https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/
- Android Open Source Project, *Android Security Bulletins* — https://source.android.com/docs/security/bulletin
