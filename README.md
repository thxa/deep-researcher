# deep-researcher

> **~1,200,000+ words** of security research documentation across **19 interconnected tracks** — 300+ Markdown files.

Document-first security research repository covering browser, operating system, cloud, web, network, cryptography, reverse engineering, supply chain, IoT, fuzzing, AI/ML security, and exploit-development topics. The repo is organized as long-form Markdown reports and chaptered notes rather than as an application or library codebase.

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
- 🤖 **Agentic AI** — complete guide from ML fundamentals through multi-agent architectures, orchestration, and production deployment
- 🪟 **Windows Security & Internals** — Windows architecture, kernel vulnerabilities, memory protections, Active Directory attacks, and hardening
- ☁️ **Cloud & Container Security** — cloud architecture, IAM, Kubernetes, serverless, IaC security, and exploitation techniques
- 🕸️ **Web Application Security** — OWASP Top 10, injection, authentication, API security, WAF bypass, and exploitation chains
- 📡 **Network & Protocol Security** — TLS, DNS, BGP, Wi-Fi, VPN, MITM attacks, IDS/IPS, and zero-trust hardening
- 🔧 **Reverse Engineering** — binary analysis, malware analysis, ransomware, firmware RE, anti-tamper, and protocol RE
- 🔐 **Cryptography & Crypto Attacks** — symmetric/RSA/ECC attacks, side channels, hardware attacks, post-quantum crypto
- 📦 **Supply Chain Security** — dependency attacks, malicious packages, SBOM, SLSA framework, code signing, and hardening
- 📲 **IoT & Embedded Security** — hardware interfaces, firmware analysis, wireless protocols, automotive, medical devices, and botnets
- 🐛 **Fuzzing & Vulnerability Research** — AFL++, libFuzzer, kernel/browser/protocol fuzzing, harnessing, and vulnerability research methodology
- 🧠 **AI/ML Security & Adversarial AI** — adversarial ML, data poisoning, LLM security, AI red teaming, and AI agent security

## What this repository is not

- Not a packaged application, service, or SDK
- Not a root-level lab environment with install/build/test workflows
- Not a ready-to-run exploit toolkit

## Quick reference

| Resource | Description |
|----------|-------------|
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | 320+ terms — exploitation, mitigations, kernel, Android, macOS, Chromium, CPU rings, fuzzing, CTF jargon |
| [`docs/TIMELINE.md`](docs/TIMELINE.md) | Chronological map of vulnerabilities, exploits, and mitigations across all tracks (pre-2005 → 2026) |
| [`docs/REFERENCES.md`](docs/REFERENCES.md) | Complete bibliography across all 19 tracks |

Every directory also has its own **cheat sheet** for fast lookup during research or CTFs:

| Track | Cheat sheet |
|-------|-------------|
| Chromium | [`Chromium_Architecture_and_Vulnerability/CHEATSHEET.md`](Chromium_Architecture_and_Vulnerability/CHEATSHEET.md) |
| Linux kernel | [`linux_kernel/CHEATSHEET.md`](linux_kernel/CHEATSHEET.md) |
| macOS | [`MacOS/CHEATSHEET.md`](MacOS/CHEATSHEET.md) |
| Android | [`android_and_CVEs/CHEATSHEET.md`](android_and_CVEs/CHEATSHEET.md) |
| CPU rings | [`ring_and_vulns/CHEATSHEET.md`](ring_and_vulns/CHEATSHEET.md) |
| Zero-day | [`zero_day/CHEATSHEET.md`](zero_day/CHEATSHEET.md) |
| CVE-2023-20938 | [`CVE-2023-20938/CHEATSHEET.md`](CVE-2023-20938/CHEATSHEET.md) |
| OSEE / EXP-401 | [`OSEE/CHEATSHEET.md`](OSEE/CHEATSHEET.md) |
| Most Complex Exploit Ever | *(included in [`FINAL_REPORT.md`](most_complex_exploit_ever/FINAL_REPORT.md))* |
| Windows Security | [`windows_security/CHEATSHEET.md`](windows_security/CHEATSHEET.md) |
| Cloud & Container Security | [`cloud_security/CHEATSHEET.md`](cloud_security/CHEATSHEET.md) |
| Web Application Security | [`web_security/CHEATSHEET.md`](web_security/CHEATSHEET.md) |
| Network & Protocol Security | [`network_security/CHEATSHEET.md`](network_security/CHEATSHEET.md) |
| Reverse Engineering | [`reverse_engineering/CHEATSHEET.md`](reverse_engineering/CHEATSHEET.md) |
| Cryptography & Crypto Attacks | [`cryptography/CHEATSHEET.md`](cryptography/CHEATSHEET.md) |
| Supply Chain Security | [`supply_chain_security/CHEATSHEET.md`](supply_chain_security/CHEATSHEET.md) |
| IoT & Embedded Security | [`iot_security/CHEATSHEET.md`](iot_security/CHEATSHEET.md) |
| Fuzzing & Vulnerability Research | [`fuzzing_vuln_research/CHEATSHEET.md`](fuzzing_vuln_research/CHEATSHEET.md) |
| AI/ML Security & Adversarial AI | [`ai_security/CHEATSHEET.md`](ai_security/CHEATSHEET.md) |

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

> **linux_kernel** (Linux kernel architecture & hardening) → **MacOS** (XNU & macOS mitigations) → **android_and_CVEs** (Android's kernel hardening: GKI, SELinux, seccomp) → **ring_and_vulns** (Ring 0 → Ring −3 escalation) → **windows_security** (Windows kernel vulnerabilities & memory protections)

### 🏆 CTF Competitor

Practical exploit development for competition:

> **zero_day** (full curriculum including CTF strategy) → **linux_kernel** (kernel pwn) → **OSEE** (advanced Windows exploitation) → **cryptography** (crypto challenges) → **reverse_engineering** (binary RE & malware analysis) → any cheat sheet during competition

### 💍 Firmware & Hardware Security

From userland down to the Management Engine:

> **ring_and_vulns** (Ring −3 to Ring 3 coverage) → **linux_kernel** (kernel attack surface) → **MacOS** (Apple Silicon & Secure Enclave) → **iot_security** (embedded & firmware analysis) → **cryptography** (hardware crypto & side channels)

### 🎓 OSEE Exam Preparation

Structured preparation for the most advanced exploitation certification:

> **OSEE** (curriculum overview & exam strategy) → **zero_day** (exploitation methodology) → **ring_and_vulns** (privilege rings context) → **linux_kernel** (kernel exploitation foundations) → **windows_security** (Windows-specific exploitation)

### 🧩 Exploit Complexity & Advanced Case Studies

Study the most sophisticated exploits ever discovered across all domains:

> **most_complex_exploit_ever** (80+ exploits ranked across 8 categories) → **zero_day** (exploitation curriculum) → **CVE-2023-20938** (deep-dive kernel UAF case study)

### ☁️ Cloud & DevSecOps Practitioner

Cloud-native security from architecture to exploitation:

> **cloud_security** (cloud architecture, IAM, Kubernetes, serverless) → **supply_chain_security** (dependency attacks, SBOM, SLSA) → **web_security** (OWASP Top 10, API security, exploitation chains) → **network_security** (zero-trust, VPN, IDS/IPS)

### 🕸️ Web & Application Security Professional

Full-stack web attack and defense:

> **web_security** (OWASP Top 10, injection, auth, API security) → **cryptography** (TLS, certificate attacks) → **network_security** (DNS, BGP, MITM) → **fuzzing_vuln_research** (browser & protocol fuzzing)

### 🐛 Vulnerability Researcher

Systematic vulnerability discovery and triage:

> **fuzzing_vuln_research** (AFL++, libFuzzer, kernel/browser fuzzing) → **reverse_engineering** (binary RE, malware analysis) → **zero_day** (exploitation methodology) → **supply_chain_security** (dependency & build pipeline attacks)

### 🧠 AI Security Researcher

Attack and defend AI/ML systems:

> **ai_security** (adversarial ML, data poisoning, LLM security, AI red teaming) → **agentic_AI** (multi-agent architectures, production deployment) → **fuzzing_vuln_research** (model fuzzing & harnessing) → **cryptography** (crypto for secure ML pipelines)

## Start here

If you are new to the repo, start with one of these entry documents:

| Topic | Difficulty | Entry point |
|-------|-----------|-------------|
| Chromium research | 🔴 Advanced | [`Chromium_Architecture_and_Vulnerability/`](Chromium_Architecture_and_Vulnerability/) |
| Linux kernel research | 🔴 Advanced | [`linux_kernel/`](linux_kernel/) |
| macOS research | 🟡 Intermediate→Advanced | [`MacOS/`](MacOS/) |
| Android architecture & CVEs | 🟡 Intermediate | [`android_and_CVEs/`](android_and_CVEs/) |
| CPU rings & vulnerabilities | 🔴 Advanced | [`ring_and_vulns/`](ring_and_vulns/) |
| Zero-day research & exploit dev | 🟡→🔴 Progressive | [`zero_day/`](zero_day/) |
| CVE-2023-20938 case study | 🔴 Advanced | [`CVE-2023-20938/`](CVE-2023-20938/) |
| OSEE / EXP-401 | 🔴 Expert | [`OSEE/`](OSEE/) |
| Most Complex Exploit Ever | 🔴 Advanced | [`most_complex_exploit_ever/FINAL_REPORT.md`](most_complex_exploit_ever/FINAL_REPORT.md) |
| Agentic AI | 🟡 Intermediate | [`agentic_AI/`](agentic_AI/) |
| Windows Security & Internals | 🔴 Advanced | [`windows_security/`](windows_security/) |
| Cloud & Container Security | 🟡 Intermediate→Advanced | [`cloud_security/`](cloud_security/) |
| Web Application Security | 🟡 Intermediate | [`web_security/`](web_security/) |
| Network & Protocol Security | 🟡 Intermediate | [`network_security/`](network_security/) |
| Reverse Engineering | 🟡→🔴 Progressive | [`reverse_engineering/`](reverse_engineering/) |
| Cryptography & Crypto Attacks | 🔴 Advanced | [`cryptography/`](cryptography/) |
| Supply Chain Security | 🟡 Intermediate | [`supply_chain_security/`](supply_chain_security/) |
| IoT & Embedded Security | 🟡 Intermediate | [`iot_security/`](iot_security/) |
| Fuzzing & Vulnerability Research | 🟡→🔴 Progressive | [`fuzzing_vuln_research/`](fuzzing_vuln_research/) |
| AI/ML Security & Adversarial AI | 🟡 Intermediate→Advanced | [`ai_security/`](ai_security/) |

Each directory has its own **README.md** with reading order, prerequisites, and estimated reading time (except `most_complex_exploit_ever/` and `agentic_AI/`, which start directly from their top-level reports).

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
├── agentic_AI/                                🤖 ML fundamentals through multi-agent architectures & deployment
│   ├── COMPLETE_GUIDE.md                       Comprehensive guide (~22 chapter documents)
│   └── docs/                                  22 numbered chapter documents (01–22)
│
├── windows_security/                          🪟 Windows architecture, kernel vulns, AD attacks, hardening
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── WINDOWS_SECURITY_FINAL_REPORT.md
│   └── docs/                                  14 numbered chapter documents (01a–07b)
│
├── cloud_security/                            ☁️ Cloud architecture, IAM, K8s, serverless, IaC, exploitation
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── CLOUD_SECURITY_FINAL_REPORT.md
│   └── docs/                                  11 numbered chapter documents (01a–06)
│
├── web_security/                              🕸️ OWASP Top 10, injection, auth, API security, WAF bypass
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── WEB_SECURITY_FINAL_REPORT.md
│   └── docs/                                  13 numbered chapter documents (01a–07)
│
├── network_security/                          📡 TLS, DNS, BGP, Wi-Fi, VPN, MITM, IDS/IPS, zero trust
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── NETWORK_SECURITY_FINAL_REPORT.md
│   └── docs/                                  11 numbered chapter documents (01a–06)
│
├── reverse_engineering/                       🔧 Binary analysis, malware, ransomware, firmware RE, protocols
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── REVERSE_ENGINEERING_FINAL_REPORT.md
│   └── docs/                                  12 numbered chapter documents (01a–07)
│
├── cryptography/                              🔐 Symmetric/RSA/ECC attacks, side channels, post-quantum
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── CRYPTOGRAPHY_FINAL_REPORT.md
│   └── docs/                                  11 numbered chapter documents (01a–06)
│
├── supply_chain_security/                     📦 Dependency attacks, SBOM, SLSA, code signing, hardening
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── SUPPLY_CHAIN_FINAL_REPORT.md
│   └── docs/                                  10 numbered chapter documents (01–10)
│
├── iot_security/                              📲 Hardware interfaces, firmware, wireless, automotive, medical
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── IOT_SECURITY_FINAL_REPORT.md
│   └── docs/                                  10 numbered chapter documents (01–10)
│
├── fuzzing_vuln_research/                     🐛 AFL++, libFuzzer, kernel/browser fuzzing, VR methodology
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── FUZZING_VULN_RESEARCH_FINAL_REPORT.md
│   └── docs/                                  11 numbered chapter documents (01–10)
│
├── ai_security/                               🧠 Adversarial ML, data poisoning, LLM security, AI red teaming
│   ├── README.md
│   ├── CHEATSHEET.md
│   ├── AI_SECURITY_FINAL_REPORT.md
│   └── docs/                                  10 numbered chapter documents (01–10)
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
- Cloud security engineers and DevSecOps practitioners securing cloud-native infrastructure
- Web application security professionals and penetration testers
- Network security engineers working on protocol security and zero-trust architectures
- Reverse engineers and malware analysts examining binaries and firmware
- Cryptography engineers evaluating crypto implementations and protocols
- IoT and embedded security researchers analyzing hardware and firmware
- Vulnerability researchers and fuzzing engineers discovering and triaging bugs
- AI/ML security researchers studying adversarial attacks and LLM vulnerabilities

Some sections assume familiarity with systems internals, debugging, exploit-development concepts, and security terminology. The **glossary** [`docs/GLOSSARY.md`](docs/GLOSSARY.md) covers 320+ specialized terms used throughout.

## Usage expectations

You generally only need a Markdown-capable editor or viewer to use this repository. Expect substantial reading, cross-references, and report-style material rather than runnable code. For hands-on practice, see the lab sections in the `zero_day/`, `OSEE/`, `fuzzing_vuln_research/`, and `reverse_engineering/` tracks.

## Safety and responsible use

This repository contains dual-use security material, including discussion of vulnerabilities, exploitation techniques, persistence, evasion, and mitigation bypasses. Use it only for authorized research, education, and defensive/security-improvement purposes.

- Do not run commands or adapt techniques against systems you do not own or administer with permission.
- Prefer isolated lab environments for any hands-on experimentation.
- Independently verify technical details before operational use.

## References & Citations

Every track in this repository includes proper references and citations to real, verifiable sources including academic papers, CVE records, official documentation, security research blog posts, conference presentations, and authoritative textbooks. Each chapter document ends with a References section with numbered citations. For a complete bibliography across all tracks, see [`docs/REFERENCES.md`](docs/REFERENCES.md).

## Notes

- This repo is a living reference collection of approximately **1,200,000+ words** across **300+ Markdown files** spanning 19 tracks.
- Depth and document structure vary by topic. Some tracks are polished report sets; others are more handbook-like study material.
- Tracks cross-reference each other. When a concept is covered more deeply in another track, you'll find a link.
- Each directory's README provides prerequisites, estimated reading time, and a complete reading-order table.
- The `most_complex_exploit_ever/` track starts directly from its [`FINAL_REPORT.md`](most_complex_exploit_ever/FINAL_REPORT.md) — no separate README.
- The `agentic_AI/` track starts from its [`COMPLETE_GUIDE.md`](agentic_AI/COMPLETE_GUIDE.md) — no separate README.

---

**Repository:** [github.com/thxa/deep-researcher](https://github.com/thxa/deep-researcher)

*Made by Deep Researcher AI Agent*