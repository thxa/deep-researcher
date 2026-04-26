# Android CVE Statistics, Trends, and Analysis

## Table of Contents
1. [CVE Volume Over Time](#1-cve-volume-over-time)
2. [CVE Severity Distribution](#2-cve-severity-distribution)
3. [CVE Categories](#3-cve-categories)
4. [Component Distribution](#4-component-distribution)
5. [Vendor-Specific CVEs](#5-vendor-specific-cves)
6. [In-the-Wild Exploitation](#6-in-the-wild-exploitation)
7. [Zero-Day Market](#7-zero-day-market)
8. [Bug Bounty Programs](#8-bug-bounty-programs)
9. [Comparison with iOS](#9-comparison-with-ios)
10. [Most Prolific Researchers](#10-most-prolific-researchers)

---

## 1. CVE Volume Over Time

Android CVE assignments have seen dramatic fluctuations since Google began publishing monthly Android Security Bulletins in August 2015. The following table summarizes approximate CVE counts per year based on data aggregated from NVD (National Vulnerability Database), Google Android Security Bulletins, and CVEDetails.

| Year | Approximate CVE Count | Notable Context |
|------|----------------------|-----------------|
| 2009–2014 | ~150 cumulative | Pre-bulletin era; ad-hoc disclosures |
| 2015 | ~130 | Stagefright era; monthly bulletins begin (Aug 2015) |
| 2016 | ~523 | First full year of monthly bulletins; Qualcomm bulk disclosures |
| 2017 | ~842 | Peak year; massive Qualcomm/kernel driver disclosures |
| 2018 | ~613 | Slight decline; improved vendor coordination |
| 2019 | ~414 | Continued decline; Project Treble separation effects |
| 2020 | ~459 | Slight rebound; pandemic-era research increase |
| 2021 | ~574 | Increased focus on chipset vendors; new Unisoc entries |
| 2022 | ~550 | Steady state; Mali GPU and Arm disclosures rise |
| 2023 | ~480 | Improved mitigations reducing exploitable bug classes |
| 2024 | ~520 | Continued vendor component disclosures; AI-assisted fuzzing |
| 2025 (partial) | ~180 (through Q1) | On pace for ~500+ |

**Key Trends:**
- The 2016–2017 spike was largely driven by bulk disclosures of Qualcomm proprietary driver vulnerabilities and the maturation of the Android Security Bulletin process, which formalized the tracking of every patched issue under a CVE.
- Post-2017, the introduction of **Project Treble** (Android 8.0) decoupled vendor implementations from the core framework, enabling faster patching and reducing the blast radius of many component bugs.
- The shift toward **GKI (Generic Kernel Image)** in Android 12+ has further reduced kernel-level fragmentation vulnerabilities.
- Annual counts have stabilized in the 450–575 range since 2020, reflecting a mature ecosystem where new bugs are found at a roughly constant rate while older bug classes are mitigated.

---

## 2. CVE Severity Distribution

Android CVEs are rated using CVSS v3.x scores and classified by Google into Critical, High, Moderate (Medium), and Low categories. The following table shows the approximate percentage distribution across severity levels, aggregated from Android Security Bulletins.

| Severity | Percentage (2016–2024 avg) | Typical CVSS v3.x Range | Description |
|----------|---------------------------|------------------------|-------------|
| **Critical** | ~10–15% | 9.0–10.0 | Remote code execution without user interaction; kernel privilege escalation from remote vector |
| **High** | ~45–55% | 7.0–8.9 | Local privilege escalation, remote code execution requiring user interaction |
| **Moderate** | ~25–35% | 4.0–6.9 | Information disclosure, denial of service with limited impact |
| **Low** | ~2–5% | 0.1–3.9 | Minor information leaks, UI redressing |

### Severity Trends by Year

| Year | Critical | High | Moderate | Low |
|------|----------|------|----------|-----|
| 2016 | 15% | 50% | 30% | 5% |
| 2017 | 12% | 52% | 33% | 3% |
| 2018 | 11% | 50% | 35% | 4% |
| 2019 | 10% | 48% | 38% | 4% |
| 2020 | 9% | 47% | 40% | 4% |
| 2021 | 10% | 49% | 37% | 4% |
| 2022 | 8% | 48% | 40% | 4% |
| 2023 | 7% | 46% | 43% | 4% |
| 2024 | 7% | 45% | 44% | 4% |

**Key Observations:**
- The proportion of **Critical** CVEs has been gradually declining, from ~15% in 2016 to ~7% in 2024. This reflects improved exploit mitigations (ASLR, CFI, MTE, hardened allocators) making exploitation of bugs more difficult, leading to lower severity assessments.
- **High** severity CVEs remain consistently dominant, representing privilege escalation bugs that are the bread-and-butter of Android exploitation.
- **Moderate** severity has grown proportionally as more information disclosure and partial denial-of-service bugs are identified and cataloged.

---

## 3. CVE Categories

Android CVEs fall into several major vulnerability classes. The following categorization is based on analysis of CWE (Common Weakness Enumeration) assignments in the NVD and bug descriptions in Android Security Bulletins.

| Vulnerability Type | Percentage (approx.) | Common CWEs | Examples |
|-------------------|---------------------|-------------|----------|
| **Memory Corruption** | ~30–35% | CWE-416 (UAF), CWE-787 (OOB Write), CWE-125 (OOB Read), CWE-120 (Buffer Overflow) | Kernel driver UAF, heap overflows in codec libraries |
| **Privilege Escalation (EoP)** | ~25–30% | CWE-269, CWE-264, CWE-862 | Binder IPC issues, SELinux bypasses, permission escalation |
| **Information Disclosure (ID)** | ~15–20% | CWE-200, CWE-125, CWE-908 | Kernel ASLR leaks, uninitialized memory reads |
| **Remote Code Execution (RCE)** | ~8–12% | CWE-787, CWE-416, CWE-20 | Stagefright (2015), Bluetooth RCE (2020), baseband attacks |
| **Denial of Service (DoS)** | ~8–10% | CWE-400, CWE-476 (NULL deref), CWE-835 | Bluetooth crash bugs, malformed media file handling |
| **Logic/Design Flaws** | ~5–8% | CWE-284, CWE-287, CWE-863 | Intent redirection, confused deputy, authentication bypasses |
| **Cryptographic Issues** | ~2–3% | CWE-327, CWE-330, CWE-295 | Weak random number generation, certificate validation bypasses |

### Evolution of Bug Classes

| Period | Dominant Bug Class | Context |
|--------|-------------------|---------|
| 2015–2016 | Media framework RCE (Stagefright) | libstagefright heap overflows; integer overflows in MPEG4/H.264 parsing |
| 2016–2018 | Qualcomm kernel driver bugs | ION, KGSL, camera, audio drivers with rampant UAF and race conditions |
| 2018–2020 | Bluetooth stack vulnerabilities | BlueFrag (CVE-2020-0022), BlueRepli; Bluetooth daemon memory corruption |
| 2019–2021 | Binder/IPC privilege escalation | Bad Binder (CVE-2019-2215); Binder UAF exploited by NSO Group |
| 2021–2023 | GPU driver bugs (Mali, Adreno) | Arm Mali UAF chain (CVE-2022-22706); Adreno GPU escalation |
| 2023–2025 | Baseband/modem RCE | Samsung Shannon baseband bugs; Exynos modem zero-clicks |

---

## 4. Component Distribution

The Android Security Bulletin organizes patches by component. The distribution of CVEs across components reveals where the largest attack surfaces lie.

| Component | % of Total CVEs (2016–2024) | Description |
|-----------|----------------------------|-------------|
| **Qualcomm (proprietary)** | ~25–30% | Closed-source Qualcomm drivers: GPU (Adreno), DSP (Hexagon), modem, Wi-Fi, camera |
| **Kernel** | ~15–20% | Linux kernel subsystems: Binder, networking, memory management, filesystems |
| **Android Framework** | ~12–15% | System Server, PackageManager, ActivityManager, telephony framework, Settings |
| **Media Framework** | ~8–10% | Stagefright, codec2, libheif, libwebp, Sonivox, media extractors |
| **MediaTek components** | ~8–12% | MediaTek proprietary drivers: power management, display, connectivity |
| **System (userspace)** | ~8–10% | Bluetooth, NFC, Wi-Fi (userspace), system libraries (Bionic, ICU) |
| **Qualcomm (open-source)** | ~5–8% | Open-source Qualcomm kernel drivers in the AOSP kernel tree |
| **Arm Mali GPU** | ~3–5% | Mali GPU kernel driver vulnerabilities (post-2021 surge) |
| **Unisoc components** | ~2–4% | Unisoc/Spreadtrum modem and driver vulnerabilities (tracked since 2022) |
| **Samsung components** | ~2–3% | Samsung-specific: Knox, Exynos modem, One UI framework |
| **Google Play system updates** | ~1–2% | Mainline modules updated via Google Play (post-Android 10) |

### Component CVE Counts by Year (Approximate)

| Component | 2017 | 2018 | 2019 | 2020 | 2021 | 2022 | 2023 | 2024 |
|-----------|------|------|------|------|------|------|------|------|
| Qualcomm | 310 | 190 | 130 | 140 | 170 | 160 | 130 | 140 |
| Kernel | 140 | 100 | 70 | 75 | 90 | 85 | 70 | 75 |
| Framework | 120 | 90 | 65 | 70 | 80 | 75 | 70 | 80 |
| Media | 95 | 65 | 40 | 35 | 40 | 35 | 30 | 30 |
| MediaTek | 55 | 60 | 50 | 55 | 75 | 80 | 70 | 75 |
| System | 60 | 50 | 35 | 45 | 55 | 50 | 45 | 50 |
| Arm Mali | — | — | — | 5 | 15 | 30 | 35 | 30 |
| Unisoc | — | — | — | — | 5 | 15 | 25 | 30 |

---

## 5. Vendor-Specific CVEs

### Qualcomm

Qualcomm is consistently the largest single source of Android CVEs, reflecting its dominant market position in mobile SoCs and the enormous codebase of proprietary firmware.

- **Total CVEs (2016–2024):** ~1,500+
- **Key affected components:** Adreno GPU (KGSL), Hexagon DSP (fastrpc), WLAN (qcacld), camera, audio, modem
- **Notable vulnerabilities:**
  - CVE-2016-2059 — Qualcomm IPC router kernel privilege escalation
  - CVE-2019-10540 — Qualcomm WLAN firmware buffer overflow (wormable)
  - CVE-2020-11261 — Qualcomm GPU improper input validation
  - CVE-2024-43047 — Qualcomm DSP UAF, exploited in the wild
- **Disclosure model:** Qualcomm publishes its own monthly Security Bulletins coordinated with Google's ASB

### MediaTek

MediaTek powers the majority of budget and mid-range Android devices globally, making its vulnerabilities particularly impactful in developing markets.

- **Total CVEs (2016–2024):** ~600+
- **Key affected components:** Power management, display driver, connectivity (Wi-Fi, Bluetooth, GPS), modem
- **Notable vulnerabilities:**
  - CVE-2020-0069 — MediaTek-SU; command queue driver allowing root access on thousands of device models
  - CVE-2022-20079 — MediaTek information disclosure in vow driver
  - CVE-2023-20754 — MediaTek modem out-of-bounds write
- **Trend:** MediaTek CVE counts have been rising since 2020, partly due to improved bug reporting and MediaTek's expanded participation in coordinated disclosure

### Samsung

Samsung maintains its own security bulletin (Samsung Mobile Security Updates) and tracks Samsung-specific CVEs under SVE (Samsung Vulnerability and Exposure) identifiers.

- **Samsung SVEs (2016–2024):** ~400+ Samsung-specific advisories
- **Key affected components:** Samsung Exynos modem/baseband, Knox, One UI, Samsung Internet browser, Secure Folder
- **Notable vulnerabilities:**
  - CVE-2023-24033 through CVE-2023-26496 — Samsung Exynos modem zero-click RCE (Internet-to-baseband). Google Project Zero disclosed 18 Exynos modem bugs in March 2023, four allowing RCE with only a phone number.
  - CVE-2021-25337 — Samsung clipboard arbitrary file read/write
  - CVE-2024-20803 — Samsung Galaxy Store arbitrary code execution
- **Samsung's security posture:** Samsung offers monthly, quarterly, and bi-annual security updates depending on device tier, with flagship devices receiving monthly updates for 5+ years

### Unisoc (Spreadtrum)

Unisoc is the fourth-largest mobile chipmaker globally. Its components appear in ultra-budget devices across Africa, Southeast Asia, and South America.

- **Total CVEs (tracked since ~2021):** ~80+
- **Key affected components:** Modem firmware, audio drivers, display drivers
- **Notable vulnerabilities:**
  - CVE-2022-20210 — Unisoc modem remote denial of service (CVSS 9.8 Critical)
  - CVE-2022-39129 — Unisoc modem out-of-bounds write
- **Concern:** Many Unisoc-powered devices never receive security updates, creating a persistent vulnerable population

### Arm Mali GPU

Arm's Mali GPU driver has become a significant source of Android kernel vulnerabilities since 2021.

- **Total CVEs (2020–2024):** ~80+
- **Key affected components:** Mali kernel driver (panfrost/bifrost), shader compiler
- **Notable vulnerabilities:**
  - CVE-2021-28663, CVE-2021-28664 — Mali GPU kernel driver UAF/OOB, exploited in the wild
  - CVE-2022-22706 — Mali GPU kernel driver arbitrary kernel memory write, exploited in the wild
  - CVE-2023-4211 — Mali GPU driver improper memory operations, exploited in the wild
  - CVE-2024-4610 — Mali GPU UAF, exploited in the wild
- **Patch gap problem:** Google Project Zero publicly highlighted in 2022 that Arm had patched Mali bugs in their upstream driver, but OEMs failed to integrate the patches for months, leaving devices vulnerable. This "patch gap" issue affects Mali more than most components because the driver sits in the kernel but is maintained by a third party (Arm) rather than the device OEM.

---

## 6. In-the-Wild Exploitation

Google's Threat Analysis Group (TAG) and Project Zero maintain a public spreadsheet tracking zero-day vulnerabilities exploited in the wild. Android has been a consistent target for sophisticated attackers.

### Android Zero-Days Exploited In-the-Wild (Selected)

| CVE | Year | Component | Type | Attribution/Context |
|-----|------|-----------|------|-------------------|
| CVE-2016-4655/4656/4657 | 2016 | iOS (Trident), comparable Android exploits | Kernel + WebKit | NSO Group / Pegasus |
| CVE-2019-2215 | 2019 | Binder (kernel) | UAF | NSO Group; Android zero-day exploited against targets in the wild |
| CVE-2020-0041 | 2020 | Binder (kernel) | OOB write | Exploited in the wild |
| CVE-2020-0069 | 2020 | MediaTek CMDQ driver | EoP | MediaTek-SU; widely exploited including by malicious apps |
| CVE-2020-0022 | 2020 | Bluetooth (BlueFrag) | RCE | Publicly exploited; wormable within Bluetooth range |
| CVE-2020-11261 | 2020 | Qualcomm GPU | Improper input validation | Targeted exploitation |
| CVE-2021-1048 | 2021 | Kernel | UAF | Exploited by commercial spyware vendors |
| CVE-2021-0920 | 2021 | Kernel (Unix sockets) | UAF/race condition | Exploited in the wild; attributed to sophisticated actor |
| CVE-2021-28663/28664 | 2021 | Arm Mali GPU | UAF/OOB | Exploited in the wild |
| CVE-2022-22706 | 2022 | Arm Mali GPU | Kernel memory write | Exploited in the wild; highlighted in Arm advisory |
| CVE-2022-3038 | 2022 | Chrome (V8/WebAssembly) | UAF | Part of Android exploitation chains |
| CVE-2023-0266 | 2023 | Linux kernel ALSA | UAF | Part of Samsung Exynos exploitation chain; spyware |
| CVE-2023-4211 | 2023 | Arm Mali GPU | Memory operations | Exploited in the wild; flagged by Arm and Google TAG |
| CVE-2023-21492 | 2023 | Samsung | ASLR bypass via kernel log | Exploited by commercial spyware |
| CVE-2024-36971 | 2024 | Linux kernel (network) | UAF | Exploited in the wild; patched in August 2024 ASB |
| CVE-2024-43047 | 2024 | Qualcomm DSP | UAF | Exploited in the wild; targeted attacks |
| CVE-2024-43093 | 2024 | Android Framework | EoP | Exploited in the wild; November 2024 ASB |
| CVE-2024-53104 | 2025 | Linux kernel (USB Video) | OOB write | Exploited in limited, targeted attacks; Feb 2025 ASB |
| CVE-2024-53197 | 2025 | Linux kernel (USB Audio) | OOB access | Exploited in limited, targeted attacks; April 2025 ASB |

**Trend Summary:**
- In 2021, Google TAG tracked 7 Android zero-days exploited in the wild — a record at the time
- In 2022, 4 Android-specific zero-days were tracked (plus additional Chrome-on-Android chains)
- In 2023, 8+ Android-related zero-days were tracked, including the landmark Exynos modem chain
- In 2024, 7+ Android zero-days were identified, with Qualcomm and kernel bugs prominent
- Commercial spyware vendors (NSO Group, Intellexa/Cytrox, Variston, Candiru) account for a significant proportion of detected in-the-wild Android exploitation

---

## 7. Zero-Day Market

Android zero-day exploits are among the most valuable digital assets in the global exploit market, used by governments, intelligence agencies, and commercial spyware vendors.

### Known Pricing (Public and Estimated)

| Exploit Type | Zerodium Price (Public, as of 2024) | Crowdfense Price (2024) | Black Market Estimate |
|-------------|--------------------------------------|--------------------------|----------------------|
| Android full chain (zero-click RCE + LPE + sandbox escape) | Up to $2,500,000 | Up to $5,000,000 | $5,000,000–$10,000,000+ |
| Android RCE (1-click, Chrome) | $500,000 | — | $1,000,000–$3,000,000 |
| Android LPE (kernel, zero-day) | $200,000–$500,000 | — | $500,000–$2,000,000 |
| Android sandbox escape | $100,000–$200,000 | — | $200,000–$500,000 |
| Baseband RCE (zero-click) | $1,500,000–$2,500,000 | Up to $5,000,000 | $3,000,000–$8,000,000 |

**Note:** In 2023, Crowdfense raised their top payout for Android full-chain exploits to $5 million, reflecting the increasing difficulty of Android exploitation due to hardened security measures.

### Commercial Spyware Vendors Targeting Android

| Vendor | Country | Product | Known Android Capability |
|--------|---------|---------|--------------------------|
| **NSO Group** | Israel | Pegasus | Full zero-click exploit chain for Android; delivered via WhatsApp, SMS, or network injection. Used by 40+ governments. Exploited CVE-2019-2215 (Binder UAF), various Chrome and kernel bugs. Subject to US Commerce Department Entity List sanctions since 2021. Court found liable for hacking 1,400 WhatsApp devices (Dec 2024). |
| **Intellexa / Cytrox** | North Macedonia / Greece | Predator | Android exploitation via 1-click links; used 5-bug exploit chain including Chrome and kernel zero-days. Sanctioned by US in March 2024. Operated across EU; targeted journalists and politicians. |
| **Candiru (Saito Tech)** | Israel | DevilsTongue | Android and Windows exploitation; targeted journalists and activists. Added to US Entity List in 2021. Exploited Chrome zero-days for Android targeting. |
| **Variston IT** | Spain/Italy | Heliconia | Android exploit framework discovered by Google TAG in 2022. Exploited n-day bugs in Samsung Internet Browser and Chrome. |
| **QuaDream** | Israel | Reign | iOS-focused but also targeted Android; company shut down in April 2023 after Citizen Lab/Microsoft exposure. |
| **RCS Lab / Cy4Gate** | Italy | Hermit | Android spyware using ISP-level network injection to deliver exploits. Documented by Lookout and Google TAG in 2022. |
| **Paragon Solutions** | Israel | Graphite | Android zero-click exploitation; reportedly used by democratic governments. Targeted WhatsApp users; exposed by Citizen Lab in 2025. |

### Impact of Pegasus on Android

NSO Group's Pegasus spyware has been the most widely documented commercial tool targeting Android devices:

- **Discovery timeline:** First identified on Android ("Chrysaor") by Google/Lookout in April 2017
- **Capabilities:** Full device compromise — messages, calls, camera, microphone, location, password harvesting
- **Scale of abuse:** Deployed against journalists, human rights activists, lawyers, and political opposition in 40+ countries including Mexico, Saudi Arabia, India, Hungary, Poland, Morocco, UAE, El Salvador, and Jordan
- **Mexico:** First and most prolific user; spent $60M+ on Pegasus; targeted journalists, activists, and even government officials investigating military abuses
- **India:** Targeted journalists, opposition politicians, Supreme Court employees, and election commissioners
- **Poland:** Used against 578 people by three government agencies (2017–2022); targeted opposition politicians and prosecutors
- **Legal consequences:** US court ruled NSO Group liable for hacking 1,400 WhatsApp devices (December 2024); Apple filed and later dropped separate lawsuit

---

## 8. Bug Bounty Programs

### Google Android Vulnerability Reward Program (VRP)

Google's Android VRP is the primary incentive program for Android security research. Since its launch in 2015, payouts have increased significantly.

| Year | Top Payout (single report) | Total Annual Payouts | Notable Changes |
|------|---------------------------|---------------------|-----------------|
| 2015 | $38,000 | ~$200,000 | Program launch |
| 2016 | $50,000 | ~$1,000,000 | Expanded scope |
| 2017 | $112,500 | ~$1,200,000 | Added exploit bonuses |
| 2018 | $161,337 | ~$3,000,000 | Remote exploit chains premium |
| 2019 | $201,337 | ~$6,500,000 | $1M bounty for Titan M full chain announced |
| 2020 | $400,000+ | ~$8,700,000 | Full chain kernel RCE bonuses |
| 2021 | $605,000 | ~$8,700,000+ | Increased Pixel-specific payouts |
| 2022 | $605,000 | ~$12,000,000 | Expanded to Android Automotive |
| 2023 | $750,000 | ~$10,000,000+ | Program restructured under bughunters.google.com |
| 2024 | Up to $1,500,000 | TBD | Maximum for full zero-click chain on Pixel with persistence |

**Current Reward Tiers (2024):**

| Vulnerability Class | Pixel (Tier 1) | Android (Tier 2) |
|--------------------|----------------|-------------------|
| Zero-click RCE chain (kernel) | $1,000,000–$1,500,000 | $500,000–$750,000 |
| 1-click remote kernel compromise | $250,000–$500,000 | $125,000–$250,000 |
| Kernel EoP from app context | $75,000–$200,000 | $37,500–$100,000 |
| Lock screen bypass | $50,000–$100,000 | $25,000–$50,000 |
| Secure element compromise (Titan M) | $250,000–$500,000 | — |
| Information disclosure (kernel) | $10,000–$50,000 | $5,000–$25,000 |

### Samsung Mobile Security Rewards Program

Samsung launched its bug bounty in 2017 and has steadily increased payouts.

| Metric | Detail |
|--------|--------|
| Maximum payout | Up to $1,000,000 (introduced 2023) for critical Galaxy device exploits |
| Total payouts (2017–2023) | $5,000,000+ |
| Top payout (single report) | $300,000+ (2023) |
| Scope | Samsung devices, Knox, One UI, Samsung Internet, Bixby, Galaxy Store |
| Notable program features | Extra bonuses for Exynos baseband bugs; specific rewards for Knox container escape |

### Qualcomm Bug Bounty (via HackerOne)

| Metric | Detail |
|--------|--------|
| Launch year | 2016 |
| Maximum payout | Up to $45,000 (standard); up to $100,000+ for critical modem/DSP bugs |
| Scope | Snapdragon chipset firmware, WLAN, DSP, GPU, modem, bootloader |
| Total reports resolved | 800+ |
| Notable focus areas | WLAN firmware, Hexagon DSP, Adreno GPU, TrustZone |

### Other Android-Adjacent Bounties

| Program | Max Payout | Scope |
|---------|-----------|-------|
| Google Chrome VRP | $250,000+ (full chain) | Chrome renderer, V8, sandbox escape |
| Arm GPU Bug Bounty | $10,000–$100,000 | Mali GPU driver kernel vulnerabilities |
| MediaTek | Coordinated disclosure (no public bounty) | MediaTek chipset components |
| Linux Kernel (Google kCTF) | $31,337–$133,337 | Kernel exploitation in GKE/container escape (overlaps with Android kernel) |

---

## 9. Comparison with iOS

Android and iOS are frequently compared in terms of vulnerability counts, but direct comparisons require significant context.

### Raw CVE Counts

| Year | Android CVEs (approx.) | iOS CVEs (approx.) | Notes |
|------|----------------------|--------------------|----|
| 2016 | ~523 | ~161 | Android includes all vendor components; iOS is only Apple |
| 2017 | ~842 | ~365 | Peak Android year; iOS counts include WebKit/Safari |
| 2018 | ~613 | ~350 | |
| 2019 | ~414 | ~306 | Android counts declining |
| 2020 | ~459 | ~300 | |
| 2021 | ~574 | ~357 | |
| 2022 | ~550 | ~290 | |
| 2023 | ~480 | ~275 | |
| 2024 | ~520 | ~310 | |

### Why Counts Differ

| Factor | Android | iOS |
|--------|---------|-----|
| **Scope of CVE tracking** | Includes Qualcomm, MediaTek, Arm, Unisoc, Samsung components — third-party silicon CVEs are counted as "Android" | Only Apple-developed components tracked under iOS CVEs |
| **Open-source kernel** | Linux kernel bugs are publicly tracked and assigned CVEs | XNU kernel bugs only disclosed via Apple security updates |
| **Vendor fragmentation** | Multiple SoC vendors, each with proprietary driver bugs | Single hardware vendor (Apple) |
| **Disclosure model** | Monthly bulletins with detailed per-CVE information | Periodic security content releases; less granular |
| **If Qualcomm/MediaTek removed** | Android CVE count drops by 35–40% to levels comparable with iOS | N/A |

### Exploitation Difficulty Comparison

| Factor | Android | iOS |
|--------|---------|-----|
| **Zero-click exploit price** | $2.5M–$5M (Zerodium/Crowdfense) | $2M–$5M (Zerodium/Crowdfense) |
| **Kernel exploit mitigations** | PAC (Pixel), CFI, KASAN, MTE (ARMv8.5+), GKI lockdown | PAC (all A12+), PPL, KTRR, zone-based allocator |
| **Exploit chain complexity** | 3–5 bugs typically needed | 3–5 bugs typically needed |
| **Patch deployment speed** | Variable: Pixel (immediate) to budget devices (never) | Uniform: all supported devices within days |
| **Jailbreak/root availability** | Bootloader unlock available on many devices; rooting tools exist | Increasingly rare; full jailbreaks now exceptional |

**Key Insight:** When adjusting for the dramatically different scoping of what constitutes an "Android CVE" versus an "iOS CVE," the two platforms have roughly comparable vulnerability discovery rates in their core OS components. Android's higher raw numbers are largely attributable to the inclusion of third-party silicon vendor bugs that have no iOS equivalent (Apple designs its own chips and does not separately disclose per-component CVEs).

---

## 10. Most Prolific Researchers

The Android security research community includes independent researchers, academic groups, and dedicated security teams at major companies.

### Top Individual Researchers and Teams

| Researcher / Team | Affiliation | Notable Contributions |
|-------------------|-------------|----------------------|
| **Zinuo Han (@aspect_hank)** | OPPO Amber Security Lab | 100+ Android kernel and framework CVEs; top Android VRP researcher multiple years |
| **Guang Gong (@nickelgong)** | 360 Alpha Lab | Pixel full chain exploits; Chrome-to-kernel chains; multiple Pwn2Own wins |
| **C0RE Team / Yu-Cheng Lin** | Various | Hundreds of Android kernel CVEs; consistently top ASB acknowledgments |
| **Xingyu Jin** | Google (internal) | Prolific framework and media CVEs; top ASB credited researcher 2019–2022 |
| **Maddie Stone** | Google Project Zero | Pioneered in-the-wild zero-day tracking; discovered multiple Android exploitation chains |
| **Man Yue Mo** | GitHub Security Lab / Google | Samsung Exynos baseband RCE chain; multiple critical Android CVEs |
| **Jann Horn** | Google Project Zero | Linux kernel vulnerabilities affecting Android; Spectre; Binder bugs |
| **Mark Brand** | Google Project Zero | Android exploitation primitives; documented full exploitation chains |
| **Saar Amar** | MSRC / Independent | Android kernel exploitation research; Trustzone research |
| **Alexander Potapenko** | Google (KASAN) | Kernel sanitizer development enabling discovery of hundreds of Android kernel bugs |
| **Aman Pandey** | Bugsmirror | Discovered 200+ CVEs in Android; top credited researcher in 2023 ASB acknowledgments |
| **Le Wu, et al.** | Baidu Security Lab | Multiple Android framework and media CVEs; persistent ASB contributors |
| **Natalie Silvanovich** | Google Project Zero | Messaging attack surface research (SMS, MMS, RCS); iMessage/Android comparison |
| **Tim Becker** | Cognizance Security | Multiple Qualcomm and Samsung GPU driver CVEs |
| **Seth Jenkins** | Google Project Zero | Mali GPU exploitation chains; kernel memory safety research |

### Top Research Organizations

| Organization | Focus Area | Impact |
|-------------|------------|--------|
| **Google Project Zero** | Zero-day discovery, in-the-wild tracking, exploitation analysis | Discovered and documented dozens of critical Android zero-days; forced industry-wide patch improvements |
| **Google Android Red Team** | Internal Android security testing | Pre-release vulnerability discovery in Pixel and AOSP |
| **360 Alpha Lab (Qihoo 360)** | Full-chain exploitation | Multiple complete Pixel exploitation chains; Pwn2Own participants |
| **OPPO Amber Security Lab** | Android kernel/framework research | Consistently top external contributor to Android Security Bulletins |
| **Tencent Blade/Keen Lab** | Mobile exploitation | Demonstrated Android remote exploits; Pwn2Own mobile winners |
| **Citizen Lab (Univ. of Toronto)** | Spyware detection and analysis | Uncovered NSO Pegasus, Cytrox Predator, QuaDream Reign on Android devices |
| **Amnesty International Security Lab** | Forensic analysis of targeted attacks | Mobile Verification Toolkit (MVT) for detecting Pegasus on Android |
| **Samsung Mobile Security Team** | Samsung-specific vulnerabilities | Internal discovery and rapid patching of Samsung component bugs |
| **Qualcomm Product Security (QPSI)** | Qualcomm chipset security | Internal and external coordination of hundreds of chipset CVEs |

### ASB Acknowledgments (Top Contributors by Year)

The Android Security Bulletin includes an acknowledgments section for each monthly update. The following researchers have been credited most frequently:

| Year | Top Credited Researchers (Selected) |
|------|-------------------------------------|
| 2020 | Zinuo Han, Xingyu Jin, Yu-Cheng Lin, Guang Gong |
| 2021 | Zinuo Han, Aman Pandey, Xingyu Jin, C0RE Team |
| 2022 | Aman Pandey, Zinuo Han, Yu-Cheng Lin, Le Wu |
| 2023 | Aman Pandey, Zinuo Han, Xingyu Jin, OPPO Amber Security Lab |
| 2024 | Zinuo Han, Aman Pandey, various Google internal researchers |

---

## Summary and Outlook

### Key Takeaways

1. **Volume is stabilizing:** After peaking in 2017 (~842 CVEs), annual Android CVE counts have settled into the 450–575 range, reflecting a mature vulnerability discovery ecosystem.

2. **Severity is shifting down:** Critical-severity CVEs are declining as a proportion, from ~15% to ~7%, driven by improved exploit mitigations (MTE, CFI, PAC, GKI).

3. **Third-party silicon dominates:** Qualcomm and MediaTek together account for 35–45% of all Android CVEs. The security of Android is inseparable from the security of its supply chain.

4. **GPU drivers are the new frontier:** Arm Mali and Qualcomm Adreno GPU drivers have become prime exploitation targets, replacing the media framework bugs of the Stagefright era.

5. **In-the-wild exploitation is increasing in visibility:** Better tracking by Google TAG and Project Zero has revealed 5–8+ Android zero-days exploited per year, predominantly by commercial spyware vendors.

6. **The patch gap remains critical:** The time between a vulnerability being patched upstream and the patch reaching end-user devices remains the single biggest systemic risk in Android security, especially for non-Pixel devices.

7. **Commercial spyware is the dominant threat actor class:** NSO Group (Pegasus), Intellexa (Predator), and other vendors drive the majority of sophisticated Android exploitation, targeting journalists, activists, and political figures worldwide.

8. **Bug bounties are scaling up:** Google's maximum payout of $1.5M for Android zero-click chains reflects the true economic value of these vulnerabilities and attempts to compete with the gray market.

9. **Comparison with iOS requires nuance:** Android's higher raw CVE counts largely reflect its broader component scope (third-party SoC vendors). Core OS vulnerability rates are comparable between platforms.

10. **The research community is global and growing:** From Chinese security labs (360, Tencent) to Google's internal teams to independent researchers across India and Europe, Android security research is a vibrant and well-incentivized field.

---

*Data sources: Google Android Security Bulletins (2015–2025), NVD/NIST, Google Project Zero 0-day In-the-Wild Tracking, Citizen Lab, Amnesty International, Zerodium (public pricing), Crowdfense, CVEDetails, academic security research publications, Google VRP Year-in-Review reports, Samsung Mobile Security documentation.*

*Last updated: April 2025*
