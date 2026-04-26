# Security Evolution Timeline: Vulnerabilities, Exploits, and Mitigations

## A Cross-Track Chronological Map Across All 8 Research Tracks

> **Scope**: Android · Chromium · CVE-2023-20938 · Linux Kernel · macOS/XNU · OSEE/EXP-401 · CPU Rings · Zero-Day Research

---

### Era 1: The Wild West (Pre-2005)

The era of no meaningful memory protections. Stack overflows were trivial, shellcode ran directly on the stack, and rootkits were simple kernel module insertions.

| Year | Event | Track |
|------|-------|-------|
| 1982 | **x86 ring architecture introduced** (i286) — Rings 0-3 defined; Rings 1-2 never adopted by mainstream OSes | [CPU Rings](../ring_and_vulns/) |
| 1990 | **Intel 386SL introduces SMM** (Ring -2) — System Management Mode provides hidden execution invisible to OS | [CPU Rings](../ring_and_vulns/) |
| 1996 | **"Smashing the Stack for Fun and Profit"** (Aleph One) — Canonical Phrack article on stack buffer overflow exploitation | [Zero-Day](../zero_day/) |
| 1996 | **Linux kernel grows monolithic** — By 2.x era, codebase already massive; all drivers share ring 0 address space | [Linux Kernel](../linux_kernel/) |
| 1999 | **Windows DEP introduced** (software DEP/SafeSEH for exception handlers) — Minimal NX enforcement, easily bypassed | [OSEE](../OSEE/) |
| 2001 | **Code Red & Nimda worms** — Mass exploitation of IIS buffer overflows; no ASLR, no DEP to stop propagation | [OSEE](../OSEE/) |
| 2003 | **adore-ng rootkit** — Kernel module rootkit operating at Ring 0, hooking syscalls and hiding processes in `/proc` | [CPU Rings](../ring_and_vulns/) |
| 2004 | **Slammer worm** — Exploits MS03-026 buffer overflow in SQL Server; spreads worldwide in <15 minutes; no NX enforcement | [OSEE](../OSEE/) |
| 2004 | **PaX/grsecurity patches** — Early Linux kernel hardening: ASLR (PaX), non-executable pages, and kernel protection | [Linux Kernel](../linux_kernel/) |
| 2005 | **OSX.RSPlug** — First macOS financial trojan; marks beginning of meaningful macOS malware targeting | [macOS](../MacOS/) |

---

### Era 2: The Mitigation Arms Race (2005–2012)

Mitigations are deployed. Attackers respond with ROP, info leaks, and heap feng shui. The arms race begins in earnest.

| Year | Event | Track |
|------|-------|-------|
| 2005 | **Windows XP SP2: DEP/NX becomes standard** — Hardware-enforced NX bit prevents code execution on stack/heap; researchers immediately pivot to Return-Oriented Programming (ROP) | [OSEE](../OSEE/) |
| 2005 | **Intel VT-x released** — Hardware virtualization introduces Ring -1, creating new hypervisor attack surface | [CPU Rings](../ring_and_vulns/) |
| 2006 | **Offensive Security founded** — OSCP certification launched; beginning of formalized offensive security training | [OSEE](../OSEE/) |
| 2007 | **Windows Vista ships with ASLR** — Address Space Layout Randomization makes hardcoded addresses unreliable; info leak vulnerabilities become critical | [OSEE](../OSEE/) |
| 2007 | **Linux PaX ASLR upstreamed** — `randomize_va_space=2` shipped, randomizing stack, heap, mmap, and VDSO | [Linux Kernel](../linux_kernel/) |
| 2007 | **Dirty COW bug introduced** — Race condition in `mm/gup.c` copy-on-write handling; latent for 9 years before discovery (CVE-2016-5195) | [Linux Kernel](../linux_kernel/) |
| 2008 | **Chrome multi-process architecture launches** — Sandboxed renderer processes require 2-3 independent bugs for full compromise; revolutionary defense-in-depth | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2008 | **Android 1.0 released** — Linux kernel + application sandbox model; SELinux in permissive mode initially | [Android](../android_and_CVEs/) |
| 2008-2009 | **AWE course first delivered at Black Hat** — Advanced Windows Exploitation becomes OffSec's most elite course | [OSEE](../OSEE/) |
| 2009 | **iOS 3.0: Code signing enforced** — Apple mandates code signing; jailbreak community responds with kernel exploits and code signing bypasses | [macOS](../MacOS/) |
| 2010 | **ROP formalized** — Academic and practical works establish Return-Oriented Programming as the standard DEP bypass technique | [Zero-Day](../zero_day/) |
| 2011 | **Android 4.3: SELinux permissive mode** — Mandatory access control introduced but not enforced; experimental phase | [Android](../android_and_CVEs/) |
| 2012 | **Android 4.1-4.2: ASLR improvements** — Position-independent executables (PIE), read-only relocations (RELRO), and padding for ASLR entropy | [Android](../android_and_CVEs/) |
| 2012 | **CVE-2012-0217 (sysret bug)** — `sysret` instruction on x86-64 presents as Ring 0 #GP after CPL has changed to Ring 3; exploited via non-canonical RIP addresses | [CPU Rings](../ring_and_vulns/) |

---

### Era 3: Hardening Escalation (2013–2018)

SMEP, SMAP, KPTI, CFI, and sophisticated sandboxing raise the exploitation bar dramatically. Spectre/Meltdown reshapes the landscape.

| Year | Event | Track |
|------|-------|-------|
| 2013 | **Chrome Blink fork from WebKit** — Google diverges rendering engine; Oilpan GC development begins to reduce UAF bugs in renderer | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2013 | **CVE-2013-2094 (perf_event)** — Linux kernel `perf_swevent_init` integer overflow leading to privilege escalation; exploited in the wild | [Linux Kernel](../linux_kernel/) |
| 2014 | **Shellshock (CVE-2014-6271)** — Bash function definition parsing vulnerability; critical infrastructure affected; CVSS 10.0 | [Linux Kernel](../linux_kernel/) |
| 2014 | **FakeID (CVE-2014-8609)** — Android certificate chain validation bypass; allows malicious APK signing | [Android](../android_and_CVEs/) |
| 2015 | **Stagefright (CVE-2015-1538)** — Integer overflows in `libstagefright` media framework; ~950M Android devices vulnerable via MMS zero-click; transforms Android security | [Android](../android_and_CVEs/) |
| 2015 | **VENOM (CVE-2015-3456)** — QEMU floppy controller heap overflow; VM escape from guest to host via emulated device; CVSS 10.0 | [CPU Rings](../ring_and_vulns/) |
| 2015 | **Intel SA-00086 (ME vulnerabilities)** — CVE-2017-5705 through CVE-2017-5715; remote code execution on Intel ME processor itself (Ring -3); firmware-level compromise | [CPU Rings](../ring_and_vulns/) |
| 2015 | **QEMU PCNET heap overflow (CVE-2015-7504)** — Another hypervisor device emulation bug enabling VM escape from guest | [CPU Rings](../ring_and_vulns/) |
| 2016 | **Dirty COW (CVE-2016-5195)** — 9-year-old race condition in COW page fault handling; any user can write to read-only files; widely exploited for Android rooting | [Linux Kernel](../linux_kernel/) [Android](../android_and_CVEs/) [CPU Rings](../ring_and_vulns/) |
| 2016 | **Broadpwn (CVE-2017-0561)** — Zero-click wormable WiFi RCE in Broadcom WiFi driver on Android; CVSS 9.8 | [Android](../android_and_CVEs/) |
| 2016 | **OSX.Flashback** — 600K+ macOS infections via Java CVE-2012-0507; DGA-based C2; one of the largest macOS malware outbreaks | [macOS](../MacOS/) |
| 2017 | **Meltdown (CVE-2017-5754) & Spectre (CVE-2017-5753, CVE-2017-5715)** — Speculative execution side-channel vulnerabilities affecting virtually all CPUs; KPTI deployed as Linux kernel mitigation | [Linux Kernel](../linux_kernel/) [CPU Rings](../ring_and_vulns/) |
| 2017 | **KEpler/KPTI deployed in Linux** — Kernel Page-Table Isolation separates user and kernel page tables; 5-30% performance penalty | [Linux Kernel](../linux_kernel/) |
| 2017 | **SMEP/SMAP standard in Linux** — Supervisor Mode Execution/Access Prevention prevents kernel from executing/accessing user-space memory | [Linux Kernel](../linux_kernel/) |
| 2017 | **Chrome CFI deployed** — Control-Flow Integrity enabled on Linux/ChromeOS builds; forward-edge vtable protection | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2018 | **Chrome Site Isolation enabled** (Chrome 67) — Every cross-site iframe in its own process; defense against Spectre and compromised renderers | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2018 | **LoJax UEFI bootkit discovered** — First UEFI bootkit seen in the wild; APT28/Sednit implants SPI flash persistence at Ring -2; survives OS reinstall | [CPU Rings](../ring_and_vulns/) |
| 2018 | **CVE-2018-4407** — Single-packet remote kernel crash on macOS via ICMP heap overflow; no authentication needed | [macOS](../MacOS/) |
| 2018 | **macOS Mojave: UAKEL/codeless kext system** — User-Approved Kernel Extensions phase-out begins; kext loading restrictions tighten | [macOS](../MacOS/) |
| 2018 | **KeRanger ransomware** — First functional macOS ransomware; signs itself with valid developer certificate | [macOS](../MacOS/) |

---

### Era 4: Modern Exploitation (2019–2026)

Data-only attacks, GPU driver exploitation, PAC/MTE deployment, commercial spyware dominance, Rust adoption, and the V8 Sandbox reshape the game.

#### 2019

| Date | Event | Track |
|------|-------|-------|
| Mar 2019 | **CVE-2019-5786 + CVE-2019-0808** — First confirmed Chrome full-chain in the wild; FileReader UAF → Win32k kernel EoP; attributed to state actor | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2019 | **Bad Binder (CVE-2019-2215)** — UAF in Android Binder driver via `binder_thread` + `epoll` interaction; exploited by NSO Group Pegasus spyware | [Android](../android_and_CVEs/) [CVE-2023-20938](../CVE-2023-20938/) |
| 2019 | **CVE-2019-8605 (SockPuppet)** — UAF in macOS BSD networking `in6_pcbdetach`; enables full jailbreak on iOS | [macOS](../MacOS/) |
| 2019 | **CVE-2019-15666** — Linux kernel setxattr OOB write; integer overflow leading to kernel compromise | [Linux Kernel](../linux_kernel/) |
| 2019 | **CVE-2019-5736 (runc escape)** — Container escape via `/proc/self/exe` overwrite; host root from within container | [CPU Rings](../ring_and_vulns/) |
| 2019 | **V8 Sandbox design begins** — Chrome team starts designing memory cage for V8 to constrain corrupted pointer scope | [Chromium](../Chromium_Architecture_and_Vulnerability/) |

#### 2020

| Date | Event | Track |
|------|-------|-------|
| Jan 2020 | **CVE-2020-6418** — V8 TurboFan type confusion (JSCallReducer); in-the-wild Chrome exploit | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2020 | **CVE-2020-0041** — OOB write in Android Binder transaction handling; exploited in the wild | [Android](../android_and_CVEs/) |
| 2020 | **CVE-2020-3843 (Ian Beer AWDL chain)** — Zero-click WiFi heap overflow on Apple devices; remote kernel compromise without authentication | [macOS](../MacOS/) |
| 2020 | **CVE-2020-3892–3898** — Cluster of Bluetooth HCI heap overflows on macOS reachable without pairing | [macOS](../MacOS/) |
| 2020 | **CVE-2020-9934** — TCC bypass via `$HOME` manipulation; `tccd` reads attacker-controlled TCC.db | [macOS](../Macos/) |
| 2020 | **Cyberpunk 2077/Broadpwn aftermath** — GPU driver exploitation recognized as primary kernel attack vector on mobile | [Android](../android_and_CVEs/) |
| 2020 | **Chrome network service out-of-process** — Network stack isolated into sandboxed utility process; reduces browser process attack surface | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2020 | **MoonBounce UEFI bootkit** — Sophisticated UEFI implant modifying DXE driver; discovered in the wild | [CPU Rings](../ring_and_vulns/) |
| 2020 | **MS-DOS era rootkits to UEFI** — Rootkit evolution: from simple LKMs (adore-ng) → MBR bootkits → UEFI implants (LoJax, MoonBounce) | [CPU Rings](../ring_and_vulns/) |

#### 2021

| Date | Event | Track |
|------|-------|-------|
| Jan 2021 | **CVE-2021-3156 (Baron Samedit)** — Sudo heap overflow in `set_cmnd()` function; affects all sudo versions 1.8.2–1.8.31p2; trivial local root | [Linux Kernel](../linux_kernel/) [CPU Rings](../ring_and_vulns/) |
| Feb 2021 | **CVE-2021-21166 + CVE-2021-21148** — Chrome audio UAF + V8 heap overflow chain; attributed to state actor targeting Armenian entities | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| Jun 2021 | **CVE-2021-30551 + CVE-2021-30554** — V8 type confusion + WebGL UAF sandbox escape chain; attributed to Candiru spyware targeting journalists | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2021 | **CVE-2021-1048** — Android epoll race condition kernel UAF; exploited in the wild by commercial spyware | [Android](../android_and_CVEs/) |
| 2021 | **CVE-2021-1782** — Mach voucher race condition / UAF in macOS; in-the-wild kernel privilege escalation | [macOS](../MacOS/) |
| Aug 2021 | **CVE-2021-30860 (FORCEDENTRY)** — NSO Group zero-click iMessage exploit; JBIG2 decoder flaw weaponized as logic circuit within image; BlastDoor sandbox escape | [macOS](../Macos/) |
| 2021 | **CVE-2021-30883** — IOMobileFrameBuffer type confusion; in-the-wild iOS kernel code execution | [macOS](../Macos/) |
| 2021 | **CVE-2021-30892 (Shrootless)** — `system_installd` SIP bypass via heritable entitlement; macOS security boundaries subverted | [macOS](../Macos/) |
| 2021 | **CVE-2021-4154** — eBPF verifier OOB write in Linux kernel; bounds combining error in 32-bit path | [Linux Kernel](../linux_kernel/) |
| 2021 | **Chrome record year: 14+ in-the-wild exploits** — Highest number of actively exploited Chrome zero-days ever recorded | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2021 | **macOS Monterey: Accelerated kext deprecation** — Third-party kernel extensions increasingly restricted; DriverKit transition begins | [macOS](../Macos/) |
| 2021 | **CosmicStrand UEFI bootkit** — Sophisticated firmware implant persisted in SPI flash; attributed to Chinese APT | [CPU Rings](../ring_and_vulns/) |

#### 2022

| Date | Event | Track |
|------|-------|-------|
| Jan 2022 | **CVE-2022-0847 (DirtyPipe)** — Stale `PIPE_BUF_FLAG_CAN_MERGE` allows writing to any readable file; trivial exploitation; affects Linux 5.8–5.16.11; data-only attack bypassing all control-flow mitigations | [Linux Kernel](../linux_kernel/) [CPU Rings](../ring_and_vulns/) |
| Feb 2022 | **CVE-2022-0609** — Chrome animation UAF; DPRK Lazarus group exploits used in campaign against 250+ media/crypto targets | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| Mar 2022 | **CVE-2022-1096** — V8 TurboFan type confusion; emergency Chrome patch; type transition handling bug | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| Apr 2022 | **OSEE/EXP-401 rebranding** — Advanced Windows Exploitation course formally rebranded to EXP-401 under OffSec's new course numbering system | [OSEE](../OSEE/) |
| Jul 2022 | **CVE-2022-2294 (WebRTC overflow)** — Chrome WebRTC heap buffer overflow; exploited in the wild by Candiru/Heliconia | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2022 | **CVE-2022-38181 (ARM Mali UAF)** — Exploited in the wild on Android; GPU driver exploitation displaces syscall-based kernel attacks | [Android](../android_and_CVEs/) |
| 2022 | **CVE-2022-32894** — XNU kernel OOB write; in-the-wild exploit on Apple platforms | [macOS](../Macos/) |
| 2022 | **CVE-2022-29582** — io_uring race condition in Linux; cross-cache exploitation technique demonstrated | [Linux Kernel](../linux_kernel/) |
| 2022 | **Linux 6.1: Rust introduced** — First non-trivial Rust code merged into the Linux kernel; memory safety at compile time for new subsystems | [Linux Kernel](../linux_kernel/) |
| 2022 | **V8 Sandbox enabled in Chrome** — V8 heap pointers become 40-bit sandbox-relative offsets; constrains corrupted pointer scope; revolutionary mitigation | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2022 | **macOS Ventura: RSR (Rapid Security Response)** — Cryptex overlay patching enables security updates without full OS restart | [macOS](../Macos/) |
| 2022 | **macOS Ventura: Lockdown Mode** — Voluntary extreme hardening: disables JIT, blocks attachments/profiles/USB, reduces attack surface | [macOS](../Macos/) |
| 2022 | **macOS Ventura: kCFI deployed** — Kernel Control-Flow Integrity; 32-bit type hash before function entry | [macOS](../Macos/) |
| 2022 | **CVE-2022-20421** — Binder UAF in `binder_thread_release`; third major Binder vulnerability exploited in the wild | [Android](../android_and_CVEs/) [CVE-2023-20938](../CVE-2023-20938/) |
| 2022 | **APT41/ShadowPad** — Supply chain compromise via kernel driver; Ring 3→0 attack in widespread campaign | [CPU Rings](../ring_and_vulns/) |

#### 2023

| Date | Event | Track |
|------|-------|-------|
| Jan 2023 | **CVE-2023-0266** — ALSA PCM sound timer UAF in Linux kernel; exploited by commercial spyware vendors on Android | [Android](../android_and_CVEs/) [Linux Kernel](../linux_kernel/) |
| Feb 2023 | **CVE-2023-20938 disclosed** — Android Binder UAF via missing bounds check and C truthiness trap in `binder_transaction_buffer_release()`; deterministic LPE from unprivileged app; affects all Android kernels | [CVE-2023-20938](../CVE-2023-20938/) [Android](../android_and_CVEs/) |
| Apr 2023 | **CVE-2023-2033 + CVE-2023-2136** — V8 type confusion + Skia integer overflow in GPU process; Chrome full-chain in the wild | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| Jun 2023 | **CVE-2023-3079** — Third V8 zero-day of 2023; type confusion in V8 optimizer; another actively exploited Chrome bug | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2023 | **Operation Triangulation (Kaspersky)** — Most sophisticated publicly known iOS/macOS exploit chain: iMessage zero-click → CVE-2023-32434 (integer overflow in kernel VM) → CVE-2023-38606 (undocumented MMIO registers bypass PPL/KTRR) | [macOS](../Macos/) |
| 2023 | **CVE-2023-32233 (nf_tables UAF)** — Linux netfilter use-after-free; privilege escalation via nftables verdict handling | [Linux Kernel](../linux_kernel/) |
| 2023 | **CVE-2023-3269 (StackRot)** — Race condition in Linux maple tree; UAF-by-RCU exploitation; very high complexity | [Linux Kernel](../linux_kernel/) |
| 2023 | **CVE-2023-21036 (aCropalypse)** — Pixel Markup tool leaks original image data from cropped screenshots; privacy vulnerability | [Android](../android_and_CVEs/) |
| Sep 2023 | **CVE-2023-4863 (libwebp)** — Heap buffer overflow in Huffman table construction; affects Chrome, Firefox, Safari, Signal, all Electron; NSO Group BLASTPASS exploit chain exploit | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2023 | **CVE-2023-4211 & CVE-2023-6241** — ARM Mali GPU driver UAF vulnerabilities; exploited in the wild on Android | [Android](../android_and_CVEs/) |
| 2023 | **CVE-2023-4762** — V8 type confusion + sandbox escape chain; Predator spyware attribution | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2023 | **CVE-2023-38606** — Apple SoC GPU coprocessor MMIO register abuse bypasses PPL/KTRR hardware protections; undocumented hardware registers used for kernel code write | [macOS](../macos/) [CPU Rings](../ring_and_vulns/) |
| 2023 | **macOS Sonoma: kalloc.type zone isolation** — Type-segregated kernel heap zones prevent cross-type heap grooming attacks | [macOS](../Macos/) |
| 2023 | **MosaicRegressor UEFI bootkit** — Multi-stage UEFI bootkit discovered in the wild (2020 discovery, 2023 analysis publish) | [CPU Rings](../ring_and_vulns/) |

#### 2024

| Date | Event | Track |
|------|-------|-------|
| Jan 2024 | **CVE-2024-0519** — V8 OOB memory access in optimizing compiler; classical bounds check elimination bug; in-the-wild Chrome exploit | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2024 | **CVE-2024-1086 (nf_tables double-free)** — Missing verdict value sanitization in `nft_verdict_init()`; 99.4% success rate universal LPE; Dirty Pagedirectory technique | [Linux Kernel](../linux_kernel/) |
| 2024 | **CVE-2024-29745 / CVE-2024-29748** — Pixel bootloader and firmware vulnerabilities exploited by forensic companies | [Android](../android_and_CVEs/) |
| 2024 | **CVE-2024-36971** — Linux kernel network route UAF; actively exploited in the wild | [Android](../android_and_CVEs/) |
| 2024 | **CVE-2024-43047** — Qualcomm KGSL DMA-buf UAF; CISA KEV listed; GPU driver exploitation as primary kernel attack vector on Android | [Android](../android_and_CVEs/) |
| May 2024 | **CVE-2024-4947** — V8 Maglev type confusion; first in-the-wild Maglev-era exploit; discovered by Kaspersky | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| Aug 2024 | **CVE-2024-7971 + kernel exploit** — V8 type confusion chained with Windows kernel EoP; DPRK Citrine Sleet attribution; Chrome full-chain | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2024 | **CVE-2024-23222** — macOS XNU kernel type confusion; in-the-wild exploit on Apple Silicon platforms | [macOS](../Macos/) |
| 2024 | **CVE-2024-44133 (HM Surf)** — Safari TCC bypass via back-forward cache navigation; confused deputy in permission enforcement | [macOS](../Macos/) |
| 2024 | **DirtyCred technique (2024 adoption)** — Generic mitigation-agnostic UAF exploitation: replace `struct cred`/`struct file` with privileged versions; bypasses KASLR, CFI, slab hardening | [Linux Kernel](../linux_kernel/) |
| 2024 | **V8 Sandbox enters Chrome VRP** — Bounty program now includes V8 Sandbox bypass category; no successful bypass claim as of mid-2024 | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2024 | **MTE adoption on ARM64** — Memory Tagging Extension deployed on Pixel 8+ and Galaxy S24+; probabilistic UAF/overflow detection at 3-5% overhead | [Android](../android_and_CVEs/) [Linux Kernel](../linux_kernel/) |
| 2024 | **Google Pixel 9 zero-click chain** — Project Zero demonstrates zero-click exploitation via Dolby audio decoder + BigWave kernel driver | [Android](../android_and_CVEs/) |
| 2024 | **Striped Fly hypervisor implant** — Cross-ring attack using custom hypervisor implant (Ring 0→-1); discovered by Sophos | [CPU Rings](../ring_and_vulns/) |

#### 2025–2026

| Date | Event | Track |
|------|-------|-------|
| 2025 | **Samsung DNG image exploit** — Quram library vulnerability deploying "Landfall" spyware via image codec parsing | [Android](../android_and_CVEs/) |
| 2025 | **Continued GPU driver exploitation** — Both ARM Mali and Qualcomm Adreno remain primary Android kernel attack vectors | [Android](../android_and_CVEs/) |
| 2025 | **Apple PACMAN-inspired attacks** — Speculative execution side-channels used to brute-force PAC values on Apple Silicon; MIT research influences hardening | [macOS](../Macos/) [CPU Rings](../ring_and_vulns/) |
| 2025 | **Rust expansion in Linux kernel** — Growing adoption in drivers, VFS, and networking subsystems; measurable reduction in memory safety bugs in new Rust code | [Linux Kernel](../linux_kernel/) |
| 2025 | **Chrome V8 Sandbox hardening** — Ongoing work to eliminate all sandbox violations; type-safe external pointer tables hardened | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2025 | **AI/ML-assisted fuzzing** — LLM-guided input generation reaches deeper code paths in JIT compilers and IPC handlers | [Zero-Day](../zero_day/) [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| 2025 | **Hardware security (MTE, PAC, CET)** — ARM MTE/PAC and Intel CET deployment expands; shifts exploitation toward data-only attacks and logic bugs | [macOS](../Macos/) [Android](../android_and_CVEs/) [Linux Kernel](../linux_kernel/) |
| 2025 | **Commercial spyware market matures** — Full Android zero-click chains valued at $2.5M+ on Zerodium; 75% of known zero-days targeting Googleproducts attributed to CSVs | [Android](../android_and_CVEs/) [Zero-Day](../zero_day/) |
| 2025 | **kalloc.type hardening on macOS** — Kernel heap zone isolation by C type signature prevents cross-type heap grooming | [macOS](../Macos/) |
| 2025-2026 | **CVE-2023-20938 upstream fix** — The Binder UAF bounds check patch finally merged to mainline Linux (August 2024), 18 months after Android patch | [CVE-2023-20938](../CVE-2023-20938/) |
| 2026 | **Confidential Compute expansion** — ARM CCA and Intel TDX hardware-isolated VMs Begin production deployment; new attack surfaces emerge | [Linux Kernel](../linux_kernel/) [CPU Rings](../ring_and_vulns/) |
| 2026 | **eBPF verifier remains critical** — Syzkaller and manual auditing continue to find verifier bugs; eBPF provides powerful attack surface visible from unprivileged userspace | [Linux Kernel](../linux_kernel/) |
| 2026 | **7-year Android update commitments** — Samsung, Google, OnePlus commit to 7 years of security updates for flagships; patch fragmentation slowly improving | [Android](../android_and_CVEs/) |
| 2026 | **Future: CHERI architecture** — Capability Hardware Enhanced RISC Instructions proposed to replace PAC with hardware-enforced pointer bounds; research phase | [macOS](../Macos/) [CPU Rings](../ring_and_vulns/) |

---

## Cross-Track Thematic Index

### By Vulnerability Class

| Class | Key CVEs | Track(s) |
|-------|----------|----------|
| **Use-After-Free** | CVE-2019-2215, CVE-2022-20421, CVE-2023-20938, CVE-2023-32233, CVE-2024-1086, CVE-2024-43047, CVE-2021-30858 | [Android](../android_and_CVEs/) [Linux Kernel](../linux_kernel/) [CVE-2023-20938](../CVE-2023-20938/) [macOS](../Macos/) [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| **Type Confusion** | CVE-2020-6418, CVE-2024-4947, CVE-2024-7971, CVE-2021-30883, CVE-2016-4656 | [Chromium](../Chromium_Architecture_and_Vulnerability/) [macOS](../Macos/) |
| **Race Condition** | CVE-2016-5195 (Dirty COW), CVE-2023-3269 (StackRot), CVE-2019-2215 (Binder+epoll) | [Linux Kernel](../linux_kernel/) [Android](../android_and_CVEs/) |
| **Integer Overflow** | CVE-2023-32434, CVE-2021-30860, CVE-2023-20938 (bounds check) | [macOS](../Macos/) [CVE-2023-20938](../CVE-2023-20938/) |
| **Logic Bug** | CVE-2022-0847 (Dirty Pipe), CVE-2021-4034 (PwnKit), CVE-2021-30892 (Shrootless) | [Linux Kernel](../linux_kernel/) [CPU Rings](../ring_and_vulns/) [macOS](../Macos/) |

### By Mitigation Deployment

| Mitigation | Year | Platform | Track |
|-----------|------|----------|-------|
| DEP/NX | 2005 | Windows XP SP2 | [OSEE](../OSEE/) |
| ASLR | 2007 | Windows Vista, Linux PaX | [OSEE](../OSEE/) [Linux Kernel](../linux_kernel/) |
| Chrome Sandbox | 2008 | Chrome | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| SELinux Enforcing | 2012 | Android 5.0 | [Android](../android_and_CVEs/) |
| SMEP | 2012 | Linux (Ivy Bridge+) | [Linux Kernel](../linux_kernel/) |
| SMAP | 2015 | Linux (Broadwell+) | [Linux Kernel](../linux_kernel/) |
| Site Isolation | 2018 | Chrome 67 | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| KPTI | 2018 | Linux (Meltdown response) | [Linux Kernel](../linux_kernel/) |
| SIP | 2015 | macOS 10.11 | [macOS](../Macos/) |
| App Sandbox / Seccomp-BPF | 2012-2016 | Android / Chrome | [Android](../android_and_CVEs/) [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| CFI (kCFI / Clang CFI) | 2017-2022 | Linux, Chrome, macOS | [Linux Kernel](../linux_kernel/) [Chromium](../Chromium_Architecture_and_Vulnerability/) [macOS](../Macos/) |
| V8 Sandbox | 2022 | Chrome | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| Rust in Linux kernel | 2022 | Linux 6.1 | [Linux Kernel](../linux_kernel/) |
| kalloc.type | 2023 | macOS 14 | [macOS](../Macos/) |
| MTE (ARM) | 2023-2024 | Android (Pixel 8+), Linux | [Android](../android_and_CVEs/) [Linux Kernel](../linux_kernel/) |
| GKI (Android) | 2020-2021 | Android 11+ | [Android](../android_and_CVEs/) |
| Lockdown Mode | 2022 | macOS | [macOS](../Macos/) |
| PAC (ARM) | 2020+ | Apple Silicon, ARMv8.3+ | [macOS](../Macos/) [Android](../android_and_CVEs/) |
| MiraclePtr | 2020-2024 | Chrome | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| CFG (Windows) | 2015+ | Windows 10+ | [OSEE](../OSEE/) |

### By Attack Surface

| Surface | Key Events | Track(s) |
|---------|-----------|----------|
| **Binder IPC** | CVE-2019-2215, CVE-2020-0041, CVE-2022-20421, CVE-2023-20938 | [Android](../android_and_CVEs/) [CVE-2023-20938](../CVE-2023-20938/) |
| **V8 JIT** | CVE-2020-6418, CVE-2024-0519, CVE-2024-4947, CVE-2024-7971 (~60% of ITW Chrome exploits) | [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| **GPU Drivers** | ARM Mali CVE-2021-28663 through CVE-2023-6241; Qualcomm Adreno CVE-2023-33063, CVE-2024-43047 | [Android](../android_and_CVEs/) |
| **Linux Netfilter** | CVE-2023-32233, CVE-2024-1086 | [Linux Kernel](../linux_kernel/) |
| **macOS IOKit** | CVE-2016-4656, CVE-2021-30883, CVE-2024-23222 | [macOS](../Macos/) |
| **XNU Mach IPC** | CVE-2019-6225, CVE-2020-27950, CVE-2021-1782 | [macOS](../Macos/) |
| **Hypervisor (Ring -1)** | CVE-2015-3456 (VENOM), CVE-2021-28476 (Hyper-V) | [CPU Rings](../ring_and_vulns/) |
| **SMM/UEFI (Ring -2)** | LoJax, MoonBounce, CosmicStrand, BlackLotus | [CPU Rings](../ring_and_vulns/) |
| **Intel ME (Ring -3)** | CVE-2017-5705–5715, CVE-2019-0090, CVE-2020-8758 | [CPU Rings](../ring_and_vulns/) |

### By Threat Actor

| Actor | Key CVEs / Campaigns | Primary Target | Track(s) |
|-------|---------------------|----------------|----------|
| **NSO Group** | CVE-2019-2215, FORCEDENTRY (CVE-2021-30860), BLASTPASS (CVE-2023-4863) | Mobile/iOS/Android | [Android](../android_and_CVEs/) [macOS](../Macos/) [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| **DPRK/Lazarus** | CVE-2022-0609, CVE-2024-7971, AppleJeus | Cryptocurrency, media | [Chromium](../Chromium_Architecture_and_Vulnerability/) [macOS](../Macos/) |
| **Candiru/Intellexa** | CVE-2021-30551, CVE-2022-2294, Predator spyware | Journalists, activists | [Android](../android_and_CVEs/) [Chromium](../Chromium_Architecture_and_Vulnerability/) |
| **APT28/Sednit** | LoJax UEFI bootkit, XAgent | Government, military | [macOS](../Macos/) [CPU Rings](../ring_and_vulns/) |
| **APT41** | ShadowPad supply chain | Broad espionage | [CPU Rings](../ring_and_vulns/) |

---

## Key Observations

1. **Mitigations shift exploit classes, not eliminate them.** Every deployed mitigation (DEP → ROP, ASLR → info leaks, CFI → data-only attacks, PAC → logic bugs) has been bypassed. Defense-in-depth is the only viable posture.

2. **Data-only attacks are the modern frontier.** DirtyPipe, DirtyCred, and modprobe_path overwrites demonstrate that compromising data structures (not control flow) bypasses CFI, PAC, and shadow stacks entirely. [Linux Kernel](../linux_kernel/)

3. **Commercial spyware drives zero-day demand.** 75% of known Google-targeting zero-days are attributed to commercial surveillance vendors (NSO, Candiru, Intellexa). Full Android zero-click chains command $2.5M+. [Android](../android_and_CVEs/) [Zero-Day](../zero_day/)

4. **GPU drivers are the new kernel attack surface.** On mobile (Mali, Adreno) and desktop, GPU drivers offer kernel-reachable complexity from unprivileged contexts. [Android](../android_and_CVEs/)

5. **The Ring -2/-3 frontier is critical infrastructure.** UEFI bootkits (LoJax, MoonBounce) and ME vulnerabilities (SA-00086) demonstrate persistence mechanisms that survive OS reinstallation. [CPU Rings](../ring_and_vulns/)

6. **Cross-ring chains exist in the wild.** Stuxnet (Ring 3→0→Physical), LoJax (Ring 3→0→-2), and Operation Triangulation (app→kernel→MMIO hardware registers) demonstrate multi-boundary exploitation. [CPU Rings](../ring_and_vulns/) [macOS](../Macos/)

7. **Memory-safe languages are the long-term answer.** Android's Rust adoption reduced memory safety bugs from 76% to <24%. Linux 6.1+ enables Rust for kernel modules. V8 Sandbox constrains heap corruption scope. [Android](../android_and_CVEs/) [Linux Kernel](../linux_kernel/) [Chromium](../Chromium_Architecture_and_Vulnerability/)

8. **Patch fragmentation remains the Achilles heel.** While Pixels receive same-day patches, billions of Android devices wait 3-6+ months or never receive updates. [Android](../android_and_CVEs/)

---

*Timeline compiled from 8 research tracks totaling 300,000+ words of technical analysis. All dates derived from primary source reports in this repository.*