# macOS / XNU Security Architecture & Exploitation

A deep technical exploration of macOS security internals — from the XNU hybrid kernel (Mach, BSD, IOKit) through hardware-enforced mitigations on Apple Silicon — covering vulnerability classes, real-world exploit chains (FORCEDENTRY, Operation Triangulation), post-exploitation persistence, the macOS malware landscape, and the evolution of Apple's defense-in-depth model.

**Difficulty:** 🟡 Intermediate to Advanced  
**Estimated reading time:** ~4 hours  
**Prerequisites:** macOS fundamentals, understanding of Unix permissions and processes, basic exploitation concepts (heap UAF, stack overflows, privilege escalation)

---

## Reading Order

| # | Document | Topic |
|---|----------|-------|
| 1 | [`docs/01a_system_architecture_xnu.md`](docs/01a_system_architecture_xnu.md) | XNU hybrid kernel: Mach IPC, BSD syscalls, IOKit driver framework, zone allocator, boot chain |
| 2 | [`docs/01b_system_architecture_userland.md`](docs/01b_system_architecture_userland.md) | Userland architecture: launchd, XPC services, dyld shared cache, APFS, framework stack |
| 3 | [`docs/02a_security_architecture_sip_gatekeeper_tcc.md`](docs/02a_security_architecture_sip_gatekeeper_tcc.md) | System Integrity Protection, Gatekeeper, XProtect, TCC consent framework, secure boot |
| 4 | [`docs/02b_security_architecture_entitlements_sandbox.md`](docs/02b_security_architecture_entitlements_sandbox.md) | Entitlements (public & private), App Sandbox (Seatbelt/SBPL), MACF policy hooks, code signing |
| 5 | [`docs/03a_kernel_vulnerabilities_xnu_iokit.md`](docs/03a_kernel_vulnerabilities_xnu_iokit.md) | XNU attack surface: Mach traps, BSD syscalls, IOKit external methods, MIG vulnerabilities |
| 6 | [`docs/03b_kernel_vulnerabilities_race_logic.md`](docs/03b_kernel_vulnerabilities_race_logic.md) | Race conditions, TOCTOU, integer overflows, logic bugs, and remote network attack surface |
| 7 | [`docs/04a_userland_vulnerabilities_privesc.md`](docs/04a_userland_vulnerabilities_privesc.md) | Local privilege escalation, sudo vulnerabilities, SIP bypasses, TCC circumvention |
| 8 | [`docs/04b_userland_vulnerabilities_apps.md`](docs/04b_userland_vulnerabilities_apps.md) | Application attack surface: WebKit/JIT, Electron, XPC validation flaws, Objective-C runtime |
| 9 | [`docs/05a_exploitation_memory_corruption.md`](docs/05a_exploitation_memory_corruption.md) | Heap feng shui, magazine malloc, kalloc zone exploitation, stack canaries, ROP on macOS |
| 10 | [`docs/05b_exploitation_chains_advanced.md`](docs/05b_exploitation_chains_advanced.md) | Real exploit chains (FORCEDENTRY, Operation Triangulation, Ian Beer AWDL), PAC/KTRR bypass |
| 11 | [`docs/06a_post_exploitation_persistence.md`](docs/06a_post_exploitation_persistence.md) | Persistence mechanisms: LaunchAgents/Daemons, dylib hijacking, cron, Folder Actions, EFI |
| 12 | [`docs/06b_post_exploitation_evasion_lateral.md`](docs/06b_post_exploitation_evasion_lateral.md) | Defense evasion, credential harvesting (Keychain, SSH), lateral movement (SSH, ARD, MDM) |
| 13 | [`docs/07a_malware_landscape_families.md`](docs/07a_malware_landscape_families.md) | Malware families: Lazarus/AppleJeus, OceanLotus, Shlayer, XCSSET, Atomic Stealer, ransomware |
| 14 | [`docs/07b_malware_detection_trends.md`](docs/07b_malware_detection_trends.md) | Detection (XProtect, EDR, ES framework), forensic artifacts, emerging trends (ARM64 native, MaaS) |
| 15 | [`docs/08a_mitigations_hardware.md`](docs/08a_mitigations_hardware.md) | Hardware mitigations: PAC, KTRR, PPL, SEP, DART, W^X, ARM64e, Intel vs Apple Silicon comparison |
| 16 | [`docs/08b_mitigations_software_evolution.md`](docs/08b_mitigations_software_evolution.md) | Software mitigations: ASLR/KASLR, stack canaries, kCFI, zone isolation, SSV, Lockdown Mode, RSR |

---

## Related Tracks

- **[Chromium Architecture & Vulnerability](../Chromium_Architecture_and_Vulnerability/)** — Browser security overlaps with macOS WebKit/JIT exploitation
- **[Linux Kernel](../linux_kernel/)** — Kernel architecture comparison (Monolithic vs. hybrid XNU)
- **[Ring & Vulnerabilities](../ring_and_vulns/)** — Privilege levels and ring protection overlap with macOS kernel/user boundary
- **[Zero-Day Exploit Development](../zero_day/)** — Advanced exploit development techniques applicable to macOS targets