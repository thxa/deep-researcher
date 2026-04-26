# deep-researcher

> **~780,000 words** of security research documentation across **9 interconnected tracks** — 156 Markdown files.

Document-first security research repository covering browser, operating system, and exploit-development topics. The repo is organized as long-form Markdown reports and chaptered notes rather than as an application or library codebase.

## What this repository contains

- 🌐 **Chromium** architecture and vulnerability research
- 🐧 **Linux kernel** security research
- 🍎 **macOS / XNU** architecture, exploitation, and mitigation research
- 📱 **Android** architecture, vulnerability landscape, and CVE research
- 💍 **CPU protection rings** — vulnerabilities and exploitation from userland to Ring −3
- 🎯 **Zero-day** research and exploit development — fundamentals through advanced kernel exploitation
- 🔬 **CVE-2023-20938** — a focused Android Binder use-after-free case study
- 🎓 **OSEE / EXP-401** — study and reference material for the most advanced exploitation certification
- 🧩 **Most Complex Exploit Ever** — cross-domain ranking of 80+ exploits; FORCEDENTRY, Stuxnet, and more

## What this repository is not

- Not a packaged application, service, or SDK
- Not a root-level lab environment with install/build/test workflows
- Not a ready-to-run exploit toolkit

## Quick reference

| Resource | Description |
|----------|-------------|
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | 320+ terms — exploitation, mitigations, kernel, Android, macOS, Chromium, CPU rings, fuzzing, CTF jargon |
| [`docs/TIMELINE.md`](docs/TIMELINE.md) | Chronological map of vulnerabilities, exploits, and mitigations across all tracks (pre-2005 → 2026) |

Every directory also has its own **cheat sheet** for fast lookup during research or CTFs:

| Track | Cheat sheet |
|-------|-------------|
| Android | [`android_and_CVEs/CHEATSHEET.md`](android_and_CVEs/CHEATSHEET.md) |
| Chromium | [`Chromium_Architecture_and_Vulnerability/CHEATSHEET.md`](Chromium_Architecture_and_Vulnerability/CHEATSHEET.md) |
| CVE-2023-20938 | [`CVE-2023-20938/CHEATSHEET.md`](CVE-2023-20938/CHEATSHEET.md) |
| Linux kernel | [`linux_kernel/CHEATSHEET.md`](linux_kernel/CHEATSHEET.md) |
| macOS | [`MacOS/CHEATSHEET.md`](MacOS/CHEATSHEET.md) |
| OSEE / EXP-401 | [`OSEE/CHEATSHEET.md`](OSEE/CHEATSHEET.md) |
| CPU rings | [`ring_and_vulns/CHEATSHEET.md`](ring_and_vulns/CHEATSHEET.md) |
| Zero-day | [`zero_day/CHEATSHEET.md`](zero_day/CHEATSHEET.md) |

## Learning paths

The tracks are organized by **topic**, but learners think in **goals**. Pick a path below based on what you want to achieve.

### 🟢 Beginner → Exploit Developer

Start with foundational concepts and work toward professional exploitation skills:

> **zero_day** (fundamentals & methodology) → **linux_kernel** (kernel internals) → **ring_and_vulns** (privilege escalation context) → **OSEE** (certification-level mastery)

### 📱 Mobile Security Specialist

Understand the full Android attack surface from architecture to specific exploits:

> **android_and_CVEs** (Android architecture & landscape) → **CVE-2023-20938** (concrete kernel UAF case study) → **linux_kernel** (kernel exploitation deep dive)

### 🌐 Browser Security Researcher

Cover browser internals, sandboxing, and the modern browser exploit chain:

> **Chromium_Architecture_and_Vulnerability** (browser architecture & V8) → **zero_day** (Parts 03a/03b for userspace exploitation) → **ring_and_vulns** (Ring 3 sandbox boundaries)

### 🔐 Kernel Hardening & Internals

Deep comparative study of kernel security across operating systems:

> **linux_kernel** (Linux kernel architecture & hardening) → **MacOS** (XNU & macOS mitigations) → **android_and_CVEs** (Android's kernel hardening: GKI, SELinux, seccomp) → **ring_and_vulns** (Ring 0 → Ring −3 escalation)

### 🏆 CTF Competitor

Practical exploit development for competition:

> **zero_day** (full curriculum including CTF strategy) → **linux_kernel** (kernel pwn) → **OSEE** (advanced Windows exploitation) → any cheat sheet during competition

### 💍 Firmware & Hardware Security

From userland down to the Management Engine:

> **ring_and_vulns** (Ring −3 to Ring 3 coverage) → **linux_kernel** (kernel attack surface) → **MacOS** (Apple Silicon & Secure Enclave)

### 🎓 OSEE Exam Preparation

Structured preparation for the most advanced exploitation certification:

> **OSEE** (curriculum overview & exam strategy) → **zero_day** (exploitation methodology) → **ring_and_vulns** (privilege rings context) → **linux_kernel** (kernel exploitation foundations)

### 🧩 Exploit Complexity & Advanced Case Studies

Study the most sophisticated exploits ever discovered across all domains:

> **most_complex_exploit_ever** (80+ exploits ranked across 8 categories) → **zero_day** (exploitation curriculum) → **CVE-2023-20938** (deep-dive kernel UAF case study)

## Start here

If you are new to the repo, start with one of these entry documents:

| Topic | Difficulty | Entry point |
|-------|-----------|-------------|
| Chromium research | 🔴 Advanced | [`Chromium_Architecture_and_Vulnerability/`](Chromium_Architecture_and_Vulnerability/) |
| Android Binder CVE case study | 🔴 Advanced | [`CVE-2023-20938/`](CVE-2023-20938/) |
| Linux kernel research | 🔴 Advanced | [`linux_kernel/`](linux_kernel/) |
| macOS research | 🟡 Intermediate→Advanced | [`MacOS/`](MacOS/) |
| Android architecture & CVEs | 🟡 Intermediate | [`android_and_CVEs/`](android_and_CVEs/) |
| CPU rings & vulnerabilities | 🔴 Advanced | [`ring_and_vulns/`](ring_and_vulns/) |
| Zero-day research & exploit dev | 🟡→🔴 Progressive | [`zero_day/`](zero_day/) |
| OSEE / EXP-401 | 🔴 Expert | [`OSEE/`](OSEE/) |
| Most Complex Exploit Ever | 🔴 Advanced | [`most_complex_exploit_ever/FINAL_REPORT.md`](most_complex_exploit_ever/FINAL_REPORT.md) |

Each directory has its own **README.md** with reading order, prerequisites, and estimated reading time (except `most_complex_exploit_ever/`, which starts directly from its `FINAL_REPORT.md`).

## Repository structure

```
deep-researcher/
├── android_and_CVEs/                          📱 Android architecture, security model, CVEs, patch management
│   ├── README.md                              Entry point, reading order, prerequisites
│   ├── CHEATSHEET.md                          Quick reference: ADB commands, CVEs, mitigations
│   ├── FINAL_REPORT_Android_Architecture...md  Main report (~78,700 words)
│   └── docs/                                  16 numbered chapter documents (01a–08b)
│
├── Chromium_Architecture_and_Vulnerability/   🌐 Chrome internals, V8, sandboxing, exploit chains
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── Chromium_Architecture_and_Vulnerability_Report.md
│   └── docs/                                  20 numbered chapter documents (01–10b)
│
├── CVE-2023-20938/                            🔬 Binder UAF deep-dive case study
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── CVE-2023-20938_FINAL_REPORT.md
│   └── docs/                                  12 numbered chapter documents (01–06b)
│
├── linux_kernel/                              🐧 Kernel security end-to-end (~137,000 words)
│   ├── README.md
│   ├── CHEATSHEET.md
│   └── docs/                                  21 files: 20 numbered chapter docs (01a–10b) + FINAL_REPORT.md
│
├── MacOS/                                     🍎 XNU, SIP, IOKit, malware, mitigations
│   ├── README.md
│   ├── CHEATSHEET.md
│   └── docs/                                  17 files: 16 numbered chapter docs (01a–08b) + FINAL_REPORT
│
├── ring_and_vulns/                            💍 Ring 3 → Ring −3: vulnerabilities at every privilege level
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── FULL_REPORT.md
│   └── docs/                                  12 topic-based chapter documents (Ring −3 through Ring 3)
│
├── zero_day/                                  🎯 Zero-day research & exploit dev curriculum
│   ├── README.md
│   ├── CHEATSHEET.md
│   └── docs/                                  13 chapter documents: 00_MASTER_REPORT + 01a through 08
│
├── OSEE/                                      🎓 EXP-401 / OSEE certification prep
│   ├── README.md
│   ├── CHEATSHEET.md
│   └── docs/                                  15 numbered chapter documents (01a–08b)
│
├── most_complex_exploit_ever/                 🧩 Cross-domain ranking of the most sophisticated exploits
│   ├── FINAL_REPORT.md                        Main report: FORCEDENTRY as #1, Stuxnet as top weapon
│   └── docs/                                  6 research reports by domain (kernel, hardware, browser, crypto, supply chain, APT)
│
└── docs/                                      📚 Cross-cutting reference material
    ├── GLOSSARY.md                            320+ term glossary across all tracks
    └── TIMELINE.md                            Chronological vulnerability & mitigation map (1982–2026)
```

## How to navigate

1. **Pick a learning path** from the section above, or pick a topic directory that interests you.
2. **Start with the directory's README.md** — it lists prerequisites, reading order, and related tracks.
3. **Read the main report** for a high-level overview of the topic.
4. **Dive into the numbered docs/** files for deep chapters.
5. **Use the cheat sheet** for quick reference during research or CTFs.
6. **Follow cross-references** to related tracks when you hit a concept covered more deeply elsewhere.
7. **Consult the glossary** [`docs/GLOSSARY.md`](docs/GLOSSARY.md) when you encounter unfamiliar terminology.

## Intended audience

This repository is most useful for:

- Security researchers studying vulnerability classes and exploitation techniques
- Exploit developers and red teamers needing architecture-level context
- Security engineers and defenders understanding attack surfaces and mitigations
- CTF competitors building exploitation skills from intermediate to world-class
- Advanced learners studying operating-system, browser, and vulnerability research topics
- OSEE / EXP-401 candidates preparing for the certification exam

Some sections assume familiarity with systems internals, debugging, exploit-development concepts, and security terminology. The **glossary** [`docs/GLOSSARY.md`](docs/GLOSSARY.md) covers 320+ specialized terms used throughout.

## Usage expectations

You generally only need a Markdown-capable editor or viewer to use this repository. Expect substantial reading, cross-references, and report-style material rather than runnable code. For hands-on practice, see the lab sections in the `zero_day/` and `OSEE/` tracks.

## Safety and responsible use

This repository contains dual-use security material, including discussion of vulnerabilities, exploitation techniques, persistence, evasion, and mitigation bypasses. Use it only for authorized research, education, and defensive/security-improvement purposes.

- Do not run commands or adapt techniques against systems you do not own or administer with permission.
- Prefer isolated lab environments for any hands-on experimentation.
- Independently verify technical details before operational use.

## Notes

- This repo is a living reference collection of approximately **780,000 words** across **156 Markdown files** spanning 9 tracks.
- Depth and document structure vary by topic. Some tracks are polished report sets; others are more handbook-like study material.
- Tracks cross-reference each other. When a concept is covered more deeply in another track, you'll find a link.
- Each directory's README provides prerequisites, estimated reading time, and a complete reading-order table.
- The `most_complex_exploit_ever/` track starts directly from its [`FINAL_REPORT.md`](most_complex_exploit_ever/FINAL_REPORT.md) — no separate README.

---

**Repository:** [github.com/thxa/deep-researcher](https://github.com/thxa/deep-researcher)
