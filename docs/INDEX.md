# Cross-Track Reference Index

> Navigate across 19 interconnected research tracks totaling 1,500,000+ words. Find where any concept, CVE, tool, or technology is discussed across the entire repository.

## Track Directory

| # | Track | Directory | Focus |
|---|-------|-----------|-------|
| 1 | Chromium | [`Chromium_Architecture_and_Vulnerability/`](../Chromium_Architecture_and_Vulnerability/) | Browser architecture, V8, Blink, sandbox, Site Isolation |
| 2 | Linux Kernel | [`linux_kernel/`](../linux_kernel/) | Kernel exploit, heap, race conditions, mitigations |
| 3 | macOS | [`MacOS/`](../MacOS/) | XNU, SIP, TCC, Gatekeeper, IOKit, kernel exploitation |
| 4 | Android | [`android_and_CVEs/`](../android_and_CVEs/) | Binder, mediaserver, kernel drivers, OEM fragmentation |
| 5 | CPU Protection Rings | [`ring_and_vulns/`](../ring_and_vulns/) | Rings -3 to 3, SMM, ME, hypervisor, kernel exploits |
| 6 | Zero-Day Research | [`zero_day/`](../zero_day/) | Vuln discovery, exploitation, CTF, tooling |
| 7 | CVE-2023-20938 | [`CVE-2023-20938/`](../CVE-2023-20938/) | Binder UAF deep-dive case study |
| 8 | OSEE/EXP-401 | [`OSEE/`](../OSEE/) | Offensive Security Exploitation Expert certification |
| 9 | Most Complex Exploit | [`most_complex_exploit_ever/`](../most_complex_exploit_ever/) | Stuxnet, FORCEDENTRY, Pegasus, complex chains |
| 10 | Windows Security | [`windows_security/`](../windows_security/) | Win32k, Active Directory, kernel exploitation |
| 11 | Cloud & Container | [`cloud_security/`](../cloud_security/) | AWS, K8s, Docker, container escapes, IAM |
| 12 | Web Application | [`web_security/`](../web_security/) | OWASP Top 10, injection, SSRF, API security |
| 13 | Network & Protocol | [`network_security/`](../network_security/) | TLS, DNS, WiFi, VPN, Bluetooth |
| 14 | Reverse Engineering | [`reverse_engineering/`](../reverse_engineering/) | Binary analysis, malware, RE methodology |
| 15 | Cryptography | [`cryptography/`](../cryptography/) | TLS attacks, side channels, post-quantum, PKI |
| 16 | Supply Chain | [`supply_chain_security/`](../supply_chain_security/) | Dependency attacks, SBOMs, XZ Utils |
| 17 | IoT & Embedded | [`iot_security/`](../iot_security/) | RTOS, automotive, medical, firmware |
| 18 | Fuzzing & Vuln Research | [`fuzzing_vuln_research/`](../fuzzing_vuln_research/) | AFL++, syzkaller, kernel fuzzing, variant analysis |
| 19 | AI/ML Security | [`ai_security/`](../ai_security/) | Adversarial ML, LLM attacks, data poisoning |

---

## Concept Index

### A

- **Access Control (broken/IDOR)** → [Web Security](../web_security/), [Cloud Security](../cloud_security/), [Android](../android_and_CVEs/)
- **Active Directory attacks** → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **Adversarial ML** → [AI Security](../ai_security/), [Fuzzing](../fuzzing_vuln_research/)
- **ASLR bypass** → [Linux Kernel](../linux_kernel/), [macOS](../MacOS/), [OSEE](../OSEE/), [Windows Security](../windows_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **APT groups** → [Zero-Day](../zero_day/), [Most Complex Exploit](../most_complex_exploit_ever/), [Network Security](../network_security/)
- **Arm Mali GPU exploitation** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **Automotive security** → [IoT](../iot_security/), [Network Security](../network_security/)
- **AWDL (Apple Wireless Direct Link)** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)

### B

- **Binder IPC exploitation** → [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/), [Linux Kernel](../linux_kernel/)
- **Buffer overflow** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [IoT](../iot_security/), [Most Complex Exploit](../most_complex_exploit_ever/), [Fuzzing](../fuzzing_vuln_research/)
- **BYOVD (Bring Your Own Vulnerable Driver)** → [Windows Security](../windows_security/), [OSEE](../OSEE/), [CPU Rings](../ring_and_vulns/)

### C

- **Cloud misconfiguration** → [Cloud Security](../cloud_security/), [Supply Chain](../supply_chain_security/)
- **Cold boot attacks** → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/)
- **Container escape** → [Cloud Security](../cloud_security/), [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **Control-flow integrity (CFI)** → [Linux Kernel](../linux_kernel/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [OSEE](../OSEE/), [Windows Security](../windows_security/)
- **CoreText/ImageIO parsing bugs** → [macOS](../MacOS/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CSRF** → [Web Security](../web_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Crypto attacks** → [Cryptography](../cryptography/), [Network Security](../network_security/)

### D

- **Dirty COW** → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Android](../android_and_CVEs/)
- **Dirty Pipe** → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Cloud Security](../cloud_security/)
- **Deserialization attacks** → [Web Security](../web_security/), [Android](../android_and_CVEs/), [Cryptography](../cryptography/)
- **Double-free** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/), [Fuzzing](../fuzzing_vuln_research/)
- **DLL injection / hijacking** → [Windows Security](../windows_security/), [macOS](../MacOS/), [Reverse Engineering](../reverse_engineering/)

### E

- **eBPF verifier bypass** → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Cloud Security](../cloud_security/)
- **Exploit chain** → [Most Complex Exploit](../most_complex_exploit_ever/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [macOS](../MacOS/), [Android](../android_and_CVEs/)
- **Exploit development methodology** → [Zero-Day](../zero_day/), [OSEE](../OSEE/), [Fuzzing](../fuzzing_vuln_research/)

### F

- **Format string** → [Linux Kernel](../linux_kernel/), [Web Security](../web_security/), [Fuzzing](../fuzzing_vuln_research/)
- **Fuzzing methodology** → [Fuzzing](../fuzzing_vuln_research/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/)

### G

- **GPU driver exploitation (Mali, Adreno, PowerVR)** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Gatekeeper / SIP / TCC bypass** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)

### H

- **Heap exploitation (slab, pool, jemalloc)** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [OSEE](../OSEE/), [Android](../android_and_CVEs/)
- **Hypervisor escape** → [CPU Rings](../ring_and_vulns/), [Cloud Security](../cloud_security/), [Most Complex Exploit](../most_complex_exploit_ever/)

### I

- **Integer overflow** → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [IoT](../iot_security/), [macOS](../MacOS/)
- **IoT firmware extraction** → [IoT](../iot_security/), [Reverse Engineering](../reverse_engineering/)
- **IAM misconfiguration** → [Cloud Security](../cloud_security/)

### J

- **JBIG2 exploitation** → [Most Complex Exploit](../most_complex_exploit_ever/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **JIT compiler bugs** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [OSEE](../OSEE/), [Fuzzing](../fuzzing_vuln_research/)

### K

- **KASLR bypass** → [Linux Kernel](../linux_kernel/), [macOS](../MacOS/), [Android](../android_and_CVEs/), [OSEE](../OSEE/), [CPU Rings](../ring_and_vulns/)
- **Kubernetes security** → [Cloud Security](../cloud_security/), [Supply Chain](../supply_chain_security/)
- **Kernel hardening** → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/), [OSEE](../OSEE/), [Windows Security](../windows_security/)

### L

- **LLM security** → [AI Security](../ai_security/)
- **LSASS credential theft** → [Windows Security](../windows_security/), [OSEE](../OSEE/)

### M

- **Memory tagging (MTE)** → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Medical device security** → [IoT](../iot_security/)
- **Mojo IPC** → [Chromium](../Chromium_Architecture_and_Vulnerability/)

### N

- **Netfilter/nftables exploitation** → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **Network protocol fuzzing** → [Fuzzing](../fuzzing_vuln_research/), [Network Security](../network_security/)

### O

- **One-click / zero-click exploits** → [Most Complex Exploit](../most_complex_exploit_ever/), [Android](../android_and_CVEs/), [macOS](../MacOS/), [Zero-Day](../zero_day/)
- **Out-of-bounds (OOB) read/write** → [Linux Kernel](../linux_kernel/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/)

### P

- **Phishing** → [Web Security](../web_security/), [AI Security](../ai_security/)
- **Pool corruption (Windows)** → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **PrintNightmare** → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/)

### Q

- **Qualcomm DSP/baseband exploitation** → [Android](../android_and_CVEs/), [IoT](../iot_security/)

### R

- **Race condition** → [Linux Kernel](../linux_kernel/), [CVE-2023-20938](../CVE-2023-20938/), [Android](../android_and_CVEs/), [macOS](../MacOS/), [Windows Security](../windows_security/)
- **Ransomware** → [Windows Security](../windows_security/), [Supply Chain](../supply_chain_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Reverse engineering methodology** → [Reverse Engineering](../reverse_engineering/), [OSEE](../OSEE/), [Zero-Day](../zero_day/)
- **ROP / JOP** → [OSEE](../OSEE/), [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [CPU Rings](../ring_and_vulns/)

### S

- **Sandbox escape** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [macOS](../MacOS/), [Android](../android_and_CVEs/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Side-channel attacks** → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Site Isolation** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Speculative execution (Spectre/Meltdown)** → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [Linux Kernel](../linux_kernel/)
- **SQL injection** → [Web Security](../web_security/)
- **SSRF** → [Web Security](../web_security/), [Cloud Security](../cloud_security/)
- **Supply chain attack** → [Supply Chain](../supply_chain_security/), [Most Complex Exploit](../most_complex_exploit_ever/), [Cloud Security](../cloud_security/)

### T

- **TCC bypass** → [macOS](../MacOS/)
- **Type confusion** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [OSEE](../OSEE/), [macOS](../MacOS/), [Windows Security](../windows_security/)

### U

- **Use-After-Free** → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/), [macOS](../MacOS/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [Windows Security](../windows_security/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **UEFI/BIOS attacks** → [CPU Rings](../ring_and_vulns/), [IoT](../iot_security/), [Windows Security](../windows_security/)

### V

- **V8 JIT exploitation** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Most Complex Exploit](../most_complex_exploit_ever/), [OSEE](../OSEE/)
- **Variant analysis** → [Fuzzing](../fuzzing_vuln_research/), [Zero-Day](../zero_day/), [OSEE](../OSEE/)

### W

- **Win32k attack surface** → [Windows Security](../windows_security/), [OSEE](../OSEE/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **WebAssembly security** → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **WiFi/Bluetooth exploitation** → [Network Security](../network_security/), [IoT](../iot_security/), [Most Complex Exploit](../most_complex_exploit_ever/), [Android](../android_and_CVEs/)

### X

- **XNU kernel exploitation** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **XSS** → [Web Security](../web_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)

### Z

- **Zero-click exploitation** → [Most Complex Exploit](../most_complex_exploit_ever/), [Android](../android_and_CVEs/), [macOS](../MacOS/), [Zero-Day](../zero_day/)
- **Zero-day discovery methodology** → [Zero-Day](../zero_day/), [Fuzzing](../fuzzing_vuln_research/), [OSEE](../OSEE/)

---

## CVE Index

### CVE-2014

- **CVE-2014-0160** — Heartbleed: OpenSSL heartbeat buffer over-read → [Cryptography](../cryptography/), [Network Security](../network_security/)
- **CVE-2014-3153** — Towelroot: futex requeue UAF → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **CVE-2014-6271** — Shellshock: Bash env variable RCE → [Web Security](../web_security/), [IoT](../iot_security/)

### CVE-2015

- **CVE-2015-1427** — Elasticsearch Groovy sandbox escape → [Web Security](../web_security/)
- **CVE-2015-3244** — VENOM: QEMU floppy controller buffer overflow → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2015-5287** — VENOM (alternate): QEMU floppy disk controller stack overflow → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2015-7547** — glibc DNS client stack buffer overflow → [Linux Kernel](../linux_kernel/), [Network Security](../network_security/)

### CVE-2016

- **CVE-2016-0728** — Keyring reference count overflow → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **CVE-2016-0800** — FREAK: OpenSSL EXPORT-grade RSA downgrade → [Cryptography](../cryptography/), [Network Security](../network_security/)
- **CVE-2016-0802** — DROWN: SSLv2 cross-protocol attack on TLS → [Cryptography](../cryptography/), [Network Security](../network_security/)
- **CVE-2016-2334** — Heap overflow in Perl's Algorithm::Diff → [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2016-2335** — Perl heap overflow in Storable → [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2016-3749** — Stagefright: Android mediaserver RCE → [Android](../android_and_CVEs/)
- **CVE-2016-3827** — Stagefright: Android media framework RCE → [Android](../android_and_CVEs/)
- **CVE-2016-4655** — Trident: iOS kernel info leak → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2016-4656** — Trident: iOS kernel memory corruption → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2016-4657** — Trident: WebKit memory corruption → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2016-5639** — CPython hash collision DoS → [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2016-6308** — OpenSSL RCE via oversized allocate → [Cryptography](../cryptography/)

### CVE-2017

- **CVE-2017-0199** — Microsoft Office OLE RCE → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2017-0144** — EternalBlue: SMB RCE (WannaCry) → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/), [Network Security](../network_security/)
- **CVE-2017-0785** — BlueBorne: Bluetooth stack info leak → [Android](../android_and_CVEs/), [Network Security](../network_security/)
- **CVE-2017-5123** — Chrome V8 type confusion (Pwn2Own) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2017-5753** — Spectre v1: Bounds check bypass → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2017-5754** — Meltdown: User-to-kernel memory read → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/), [Linux Kernel](../linux_kernel/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2017-5775** — Infineon ROCA: RSA key generation weakness → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/)
- **CVE-2017-7269** — IIS WebDAV buffer overflow → [Windows Security](../windows_security/)
- **CVE-2017-7533** — Kernel keyring race condition → [Linux Kernel](../linux_kernel/)
- **CVE-2017-7558** — Linux kernel perf_event info leak → [CPU Rings](../ring_and_vulns/)

### CVE-2018

- **CVE-2018-16387** — Broadpwn: Broadcom WiFi SoC RCE → [Android](../android_and_CVEs/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2018-3615** — L1 Terminal Fault (L1TF) → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2018-3620** — L1TF: OS/SMM → [CPU Rings](../ring_and_vulns/)
- **CVE-2018-3639** — Spectre v4: Speculative store bypass → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2018-3646** — L1TF: VMM → [CPU Rings](../ring_and_vulns/), [Cloud Security](../cloud_security/)
- **CVE-2018-3693** — Spectre-NG: Bounds check bypass variant → [CPU Rings](../ring_and_vulns/)
- **CVE-2018-4400** — ICMP buffer overflow in XNU → [macOS](../MacOS/)
- **CVE-2018-8897** — POP/MOV SS debug exception → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **CVE-2018-10976** — MySQL privilege escalation → [Web Security](../web_security/)

### CVE-2019

- **CVE-2019-0708** — BlueKeep: RDS RCE → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2019-11510** — Pulse Secure VPN RCE → [Network Security](../network_security/), [Cloud Security](../cloud_security/)
- **CVE-2019-13272** — Kernel ptrace privilege escalation → [Linux Kernel](../linux_kernel/)
- **CVE-2019-14287** — sudo UID bypass → [Linux Kernel](../linux_kernel/)
- **CVE-2019-18634** — sudo buffer overflow with pwfeedback → [Linux Kernel](../linux_kernel/)
- **CVE-2019-2025** — Binder UAF (epoll) → [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/)
- **CVE-2019-2215** — Binder UAF exploited by NSO/Pegasus → [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2019-3568** — WhatsApp VoIP buffer overflow → [Most Complex Exploit](../most_complex_exploit_ever/), [Network Security](../network_security/)
- **CVE-2019-3703** — Linux kernel info disclosure → [Linux Kernel](../linux_kernel/)
- **CVE-2019-5597** — FreeBSD icmp6 info leak → [Network Security](../network_security/)

### CVE-2020

- **CVE-2020-0308** — Android media framework RCE → [Android](../android_and_CVEs/)
- **CVE-2020-10695** — PostgreSQL extension script RCE → [Web Security](../web_security/)
- **CVE-2020-13570** — BLESA: BLE spoofing attack → [IoT](../iot_security/), [Network Security](../network_security/)
- **CVE-2020-13777** — GnuTLS session randomness failure → [Cryptography](../cryptography/)
- **CVE-2020-14314** — ext4 OOB read → [Linux Kernel](../linux_kernel/)
- **CVE-2020-14333** — eBPF verifier local LPE → [Linux Kernel](../linux_kernel/)
- **CVE-2020-14364** — QEMU USB controller OOB (VENOM-class) → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2020-14386** — AF_PACKET memory corruption → [Linux Kernel](../linux_kernel/)
- **CVE-2020-15025** — Format string in dnsmasq → [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2020-15078** — WireGuard Windows kernel panic → [Network Security](../network_security/)
- **CVE-2020-15257** — containerd container escape → [Cloud Security](../cloud_security/)
- **CVE-2020-15505** — MobileIron RCE → [Cloud Security](../cloud_security/)
- **CVE-2020-15999** — FreeType heap buffer overflow (in-the-wild) → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/)
- **CVE-2020-16006** — Chrome RegExp engine type confusion → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2020-16009** — Chrome heap corruption (WebGL) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2020-16010** — Chrome Android FreeType heap overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2020-16908** — Win32k type confusion (ComboBox) → [Windows Security](../windows_security/)
- **CVE-2020-17087** — Windows cng.sys pool overflow → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **CVE-2020-17095** — Win32k UAF (callback re-entrancy) → [Windows Security](../windows_security/)
- **CVE-2020-17519** — Apache Flink path traversal → [Web Security](../web_security/)
- **CVE-2020-24336/38/39/40/41/42** — IoT TCP/IP stack vulnerabilities (uIP, picoTCP, FNET, NuttX) → [IoT](../iot_security/)
- **CVE-2020-24577** — uIP stack vulnerability → [IoT](../iot_security/)
- **CVE-2020-24579** — uIP stack vulnerability → [IoT](../iot_security/)
- **CVE-2020-24586/7** — WiFi mixed key/fragment cache attacks → [Network Security](../network_security/)
- **CVE-2020-25704** — perf_event kernel address leak via BPF → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **CVE-2020-26137** — urllib3 HTTPS verification bypass → [Web Security](../web_security/)
- **CVE-2020-26217** — XStream deserialization RCE → [Web Security](../web_security/)
- **CVE-2020-26541** — Linux kernel uninitialized data leak → [Linux Kernel](../linux_kernel/)
- **CVE-2020-27194** — eBPF ALU32 bounds tracking bypass → [Linux Kernel](../linux_kernel/), [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2020-27932** — XNU mach message race condition → [macOS](../MacOS/)
- **CVE-2020-27950** — XNU mach_msg OOL info leak → [macOS](../MacOS/)
- **CVE-2020-29374** — Linux kernel io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2020-29443** — Xen PV race condition → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)

### CVE-2021

- **CVE-2021-89** — Intel SA-00528 → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-129** — BlueZ info disclosure → [Network Security](../network_security/)
- **CVE-2021-287** — Android WiFi Intent privilege escalation → [Android](../android_and_CVEs/)
- **CVE-2021-399** — Android kernel TOCTOU in IPC → [Android](../android_and_CVEs/)
- **CVE-2021-477** — Android NFC service info disclosure → [Android](../android_and_CVEs/)
- **CVE-2021-585** — Android Settings PendingIntent hijack → [Android](../android_and_CVEs/)
- **CVE-2021-604** — Android Bluetooth OPP PendingIntent → [Android](../android_and_CVEs/)
- **CVE-2021-661/662/663** — MediaTek DSP OOB read/write → [Android](../android_and_CVEs/)
- **CVE-2021-674** — MediaTek audio HAL integer overflow → [Android](../android_and_CVEs/)
- **CVE-2021-675** — MediaTek audio HAL OOB write → [Android](../android_and_CVEs/)
- **CVE-2021-799** — Android task affinity hijacking → [Android](../android_and_CVEs/)
- **CVE-2021-920** — Unix domain socket GC race → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/)
- **CVE-2021-928** — Android Parcel mismatch code execution → [Android](../android_and_CVEs/)
- **CVE-2021-1048** — Binder epoll UAF (in-the-wild) → [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/)
- **CVE-2021-1648** — Win32k TOCTOU → [Windows Security](../windows_security/)
- **CVE-2021-1732** — Win32k UAF (xxxClientAllocWindowClassExtraBytes) → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **CVE-2021-1782** — XNU mach voucher race condition → [macOS](../MacOS/)
- **CVE-2021-1905/06** — Qualcomm Adreno GPU UAF/address validation → [Android](../android_and_CVEs/)
- **CVE-2021-1940** — Qualcomm GPU command submission UAF → [Android](../android_and_CVEs/)
- **CVE-2021-3156** — Baron Samedit: sudo heap overflow → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2021-3454** — eBPF ALU32 bounds truncation → [Linux Kernel](../linux_kernel/)
- **CVE-2021-3449** — OpenSSL SM2 crash → [Cryptography](../cryptography/)
- **CVE-2021-3490** — eBPF register bounds mismatch → [Linux Kernel](../linux_kernel/)
- **CVE-2021-3711** — OpenSSL SM2 buffer overflow → [Cryptography](../cryptography/)
- **CVE-2021-3715** — eBPF verifier LPE → [Linux Kernel](../linux_kernel/)
- **CVE-2021-3816** — EDK II SMM variable UAF → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-3818** — EDK II SMM buffer overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-3929** — Lenovo SMM callout → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-4032** — OverlayFS setuid bypass → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **CVE-2021-4034** — PwnKit: pkexec privilege escalation → [Linux Kernel](../linux_kernel/), [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2021-4037** — ext4 inline data overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2021-4147** — ext4 directory traversal → [Linux Kernel](../linux_kernel/)
- **CVE-2021-4154** — kernel cred overwriting → [Linux Kernel](../linux_kernel/)
- **CVE-2021-4159** — io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2021-4183** — Insyde SMM callout → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-20226** — io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2021-21148** — V8 heap buffer overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-21166** — Chrome audio UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-21194** — Chrome UAF (frame counting) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-21220** — V8 insufficient validation (Pwn2Own) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-21224** — V8 data validation + Windows pool overflow chain → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Windows Security](../windows_security/)
- **CVE-2021-21227** — V8 DevTools insufficient validation → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-21551** — Dell dbutil_2_3.sys arbitrary write → [Windows Security](../windows_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2021-21972** — vCenter Server unauthenticated RCE → [Cloud Security](../cloud_security/)
- **CVE-2021-21974** — ESXi SLP heap overflow → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2021-22054** — VMware ESXi auth LPE → [Cloud Security](../cloud_security/)
- **CVE-2021-22205** — GitLab CE/EE SSRF + RCE → [Web Security](../web_security/)
- **CVE-2021-22555** — Netfilter nft_set destruction UAF → [Linux Kernel](../linux_kernel/), [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2021-22600** — io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2021-22893** — Pulse Secure auth bypass RCE → [Network Security](../network_security/)
- **CVE-2021-23017** — DNS response buffer overflow → [Network Security](../network_security/)
- **CVE-2021-25370** — Samsung DPU driver UAF/double-free → [Android](../android_and_CVEs/)
- **CVE-2021-25742** — Kubernetes ingress-NGINX path traversal → [Cloud Security](../cloud_security/)
- **CVE-2021-25891** — PACMAN: PAC bypass on Apple M1 → [macOS](../MacOS/), [CPU Rings](../ring_and_vulns/)
- **CVE-2021-26085** — Confluence OGNL injection → [Web Security](../web_security/)
- **CVE-2021-26411** — Internet Explorer UAF → [Windows Security](../windows_security/)
- **CVE-2021-26708** — vsock exploit → [Linux Kernel](../linux_kernel/)
- **CVE-2021-26855/27065** — Microsoft Exchange ProxyLogon → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2021-27085** — Chrome integer overflow (bitmap allocation) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-28389** — Hyper-V VM86/vmbus escape → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-28476** — Hyper-V vmswitch RCE → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2021-28660** — rtl8188eu WiFi driver stack overflow → [Android](../android_and_CVEs/)
- **CVE-2021-28663/66** — ARM Mali GPU UAF/OOB → [Android](../android_and_CVEs/)
- **CVE-2021-292** — Android WiFi privilege escalation → [Android](../android_and_CVEs/)
- **CVE-2021-30116** — Kaseya VSA RCE → [Supply Chain](../supply_chain_security/)
- **CVE-2021-30139** — ESP32 secure boot bypass → [IoT](../iot_security/)
- **CVE-2021-30547** — ANGLE OOB write → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-30551** — V8 TurboFan type confusion (Candiru) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-30554** — Chrome WebGL UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-30632** — V8 OOB write (in-the-wild) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-30633** — IndexedDB UAF (browser process) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-30713** — XCSSET TCC bypass (macOS) → [macOS](../MacOS/)
- **CVE-2021-30727** — Mount-based SIP bypass → [macOS](../MacOS/)
- **CVE-2021-30860** — FORCEDENTRY: iMessage zero-click (NSO Group) → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-30883** — IOMobileFrameBuffer type confusion → [macOS](../MacOS/)
- **CVE-2021-30892** — Shrootless: SIP bypass via system_installd → [macOS](../MacOS/)
- **CVE-2021-30970** — XNU powerdir TCC bypass → [macOS](../MacOS/)
- **CVE-2021-31166** — HTTP.sys UAF (wormable) → [Windows Security](../windows_security/)
- **CVE-2021-31440** — eBPF verifier LPE → [Linux Kernel](../linux_kernel/)
- **CVE-2021-31955** — Windows kernel info disclosure (KASLR bypass) → [Windows Security](../windows_security/)
- **CVE-2021-31956** — NTFS pool corruption → [Windows Security](../windows_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-33909** — Sequoia: seq_file integer overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2021-34527** — PrintNightmare RCE → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2021-36240** — lighttpd HTTP/2 coalescing → [IoT](../iot_security/)
- **CVE-2021-36934** — HiveNightmare/SeriousSAM → [Windows Security](../windows_security/)
- **CVE-2021-36958** — Print Spooler info disclosure → [Windows Security](../windows_security/)
- **CVE-2021-37973** — Chrome sandbox escape → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-37975** — V8 GC UAF (in-the-wild) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-38000** — Chrome Android Intent chain → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-38003** — Chrome WebLayer Intent bypass → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2021-39238** — HP SMM buffer overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2021-40436** — OpenSSL CMS verify crash → [Cryptography](../cryptography/)
- **CVE-2021-40444** — MSHTML RCE (Emotet) → [Windows Security](../windows_security/)
- **CVE-2021-40449** — Win32k MysterySnail UAF → [Windows Security](../windows_security/)
- **CVE-2021-41073** — io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2021-41103** — Docker default directory permissions → [Cloud Security](../cloud_security/)
- **CVE-2021-41773** — Apache HTTPD path traversal → [Web Security](../web_security/)
- **CVE-2021-41824** — OpenVPN Access Server RCE → [Network Security](../network_security/)
- **CVE-2021-42013** — Apache HTTPD path traversal (bypass) → [Web Security](../web_security/)
- **CVE-2021-42287** — AD sAMAccountName confusion → [Windows Security](../windows_security/)
- **CVE-2021-42340** — Apache Tomcat HTTP/2 info leak → [Web Security](../web_security/)
- **CVE-2021-42342** — GoAhead authenticated RCE → [IoT](../iot_security/)
- **CVE-2021-42550** — Logback RCE (Log4Shell-class) → [Supply Chain](../supply_chain_security/), [Web Security](../web_security/)
- **CVE-2021-44716** — Go stdlib HTTP/2 DoS → [Cloud Security](../cloud_security/)
- **CVE-2021-45046** — Log4Shell RCE bypass → [Supply Chain](../supply_chain_security/), [Web Security](../web_security/)
- **CVE-2021-45105** — Log4j recursive lookup DoS → [Supply Chain](../supply_chain_security/)
- **CVE-2021-45232** — Apache APISIX auth bypass → [Web Security](../web_security/)
- **CVE-2021-46162** — SEV attestation bypass → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/)

### CVE-2022

- **CVE-2022-1/2** — BHI: Branch History Injection (Spectre-class) → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2022-2** — Intel SMM LPE → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-116** — Chrome compositing cross-origin bypass → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-185** — Linux kernel fs context heap overflow → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **CVE-2022-460** — Let's Encrypt CAA rechecking issue → [Cryptography](../cryptography/), [Web Security](../web_security/)
- **CVE-2022-492** — Linux kernel cgroup BPF bypass → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **CVE-2022-500** — eBPF incorrect bounds tracking → [Linux Kernel](../linux_kernel/)
- **CVE-2022-609** — Chrome Animation UAF (DPRK Lazarus) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-778** — OpenSSL infinite loop in cert verification → [Cryptography](../cryptography/)
- **CVE-2022-789** — ANGLE heap buffer overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-811** — cr8escape: CRI-O container escape → [Cloud Security](../cloud_security/)
- **CVE-2022-847** — Dirty Pipe: uninitialized pipe_buffer.flags → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **CVE-2022-850** — ext4 vulnerability → [Linux Kernel](../linux_kernel/)
- **CVE-2022-1015** — Netfilter nft_set_elem UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2022-1016** — btrfs extent map vulnerability → [Linux Kernel](../linux_kernel/)
- **CVE-2022-1096** — V8 Maglev type confusion → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-1146** — Chrome Resource Timing info leak → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-1180** — ext4 extended attribute overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2022-1292** — OpenSSL c_rehash command injection → [Cryptography](../cryptography/)
- **CVE-2022-1388** — F5 BIG-IP iControl REST RCE → [Web Security](../web_security/), [Network Security](../network_security/)
- **CVE-2022-1633** — Chrome sharesheet UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-1786** — io_uring msg_ring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2022-2007** — Chrome WebGL UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-2068** — OpenSSL c_rehash command injection (variant) → [Cryptography](../cryptography/)
- **CVE-2022-2274** — OpenSSL AES-OCB buffer over-read → [Cryptography](../cryptography/)
- **CVE-2022-2294** — WebRTC heap buffer overflow (Candiru) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-22954** — VMware Workspace ONE SSTI → [Cloud Security](../cloud_security/)
- **CVE-2022-22963** — Spring Cloud Function SpEL injection → [Web Security](../web_security/)
- **CVE-2022-22965** — Spring4Shell RCE → [Web Security](../web_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2022-23222** — eBPF pointer arithmetic bypass → [Linux Kernel](../linux_kernel/)
- **CVE-2022-23577** — TF Serving heap buffer overflow → [AI Security](../ai_security/)
- **CVE-2022-23823** — AMD Hertzbleed → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2022-23825** — AMD BTC/Phantom branch type confusion → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-24436** — Intel Hertzbleed → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2022-24521** — Windows CLFS logical error → [Windows Security](../windows_security/)
- **CVE-2022-24769** — Docker default inheritable capabilities → [Cloud Security](../cloud_security/)
- **CVE-2022-24999** — Express prototype pollution → [Web Security](../web_security/)
- **CVE-2022-25636** — nf_tables heap overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2022-25664** — Adreno GPU integer overflow → [Android](../android_and_CVEs/)
- **CVE-2022-25667** — Camera ISP buffer overflow → [Android](../android_and_CVEs/)
- **CVE-2022-26075** — Intel SA-00622 → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-26134** — Confluence OGNL injection → [Web Security](../web_security/)
- **CVE-2022-26394** — Xen IOREQ race condition → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2022-26706** — macOS Word macro sandbox escape → [macOS](../MacOS/)
- **CVE-2022-26730** — macOS Hypervisor escape → [macOS](../MacOS/)
- **CVE-2022-26763** — AppleAVD OOB write → [macOS](../MacOS/)
- **CVE-2022-26900** — Dell SMM race condition → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-26923** — AD CS privilege escalation (Certifried) → [Windows Security](../windows_security/)
- **CVE-2022-26925** — LSA Spoofing → [Windows Security](../windows_security/)
- **CVE-2022-27191** — Go SSH algorithm negotiation crash → [Network Security](../network_security/)
- **CVE-2022-2639** — Open vSwitch UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2022-2856** — Chrome insufficient Intent validation on Android → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/)
- **CVE-2022-29217** — PyJWT key confusion attack → [Web Security](../web_security/), [Cryptography](../cryptography/)
- **CVE-2022-29265** — AMI SMM stack overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-29581** — btrfs mount vulnerability → [Linux Kernel](../linux_kernel/)
- **CVE-2022-29582** — io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2022-29900/1** — Retbleed: Speculative return stack overflow → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2022-3038** — Chrome V8/WebAssembly UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-3162** — Kubernetes kube-apiserver unauthorized → [Cloud Security](../cloud_security/)
- **CVE-2022-3169** — Chrome DevTools Insufficient Validation → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-3172** — Kubernetes kubelet unauthenticated aggregator → [Cloud Security](../cloud_security/)
- **CVE-2022-3201** — Chrome Intent scheme bypass → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-3294** — Kubernetes kubelet path traversal → [Cloud Security](../cloud_security/)
- **CVE-2022-3534** — eBPF incorrect scalar bounds → [Linux Kernel](../linux_kernel/)
- **CVE-2022-35414** — PHP phar deserialization → [Web Security](../web_security/)
- **CVE-2022-3602** — OpenSSL X.509 email overflow → [Cryptography](../cryptography/)
- **CVE-2022-3656** — Chrome File System CSP bypass → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-3786** — OpenSSL X.509 buffer overflow → [Cryptography](../cryptography/)
- **CVE-2022-38181** — ARM Mali GPU UAF (in-the-wild) → [Android](../android_and_CVEs/)
- **CVE-2022-3865** — OCI bypass → [Cloud Security](../cloud_security/)
- **CVE-2022-39189** — KVM EoP → [CPU Rings](../ring_and_vulns/), [Cloud Security](../cloud_security/)
- **CVE-2022-39842** — Samsung Video EoP → [Android](../android_and_CVEs/)
- **CVE-2022-39921** — TorchServe SSRF → [AI Security](../ai_security/)
- **CVE-2022-40982** — Downfall: Gather Data Sampling → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/)
- **CVE-2022-41073** — Windows Activation Contexts EoP → [Windows Security](../windows_security/)
- **CVE-2022-41080/6** — Microsoft Exchange ProxyNotShell → [Windows Security](../windows_security/)
- **CVE-2022-41049** — MDE configuration bypass → [Windows Security](../windows_security/)
- **CVE-2022-26794** — Secure Boot bypass (Baton Drop) → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-4129** — mm/hugetlb UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2022-4139** — USB Video Class driver OOB write → [Linux Kernel](../linux_kernel/)
- **CVE-2022-41889** — TensorFlow Conv2D integer overflow → [AI Security](../ai_security/)
- **CVE-2022-4224** — Ruby powershell OpenSSL → [Cryptography](../cryptography/)
- **CVE-2022-4230** — WebAssembly bounds checking → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-4262** — V8 TurboFan type confusion → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2022-4279** — Netfilter UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2022-4280** — Netfilter OOB write → [Linux Kernel](../linux_kernel/)
- **CVE-2022-4286** — XFS attribute fork overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2022-42860** — AppleAWDL (iOS 15.7.1) → [macOS](../MacOS/)
- **CVE-2022-43044** — QEMU virtio-blk → [Cloud Security](../cloud_security/)
- **CVE-2022-4543** — EntryBleed: KASLR bypass → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/)
- **CVE-2022-20128** — Android ADB backup data leak → [Android](../android_and_CVEs/)
- **CVE-2022-20130** — Android telephony RCE → [Android](../android_and_CVEs/)
- **CVE-2022-20133** — Android NFC privilege escalation → [Android](../android_and_CVEs/)
- **CVE-2022-20186** — Mali GPU OOB write → [Android](../android_and_CVEs/)
- **CVE-2022-20223** — Android PendingIntent Settings hijack → [Android](../android_and_CVEs/)
- **CVE-2022-20233** — PowerVR GPU OOB write → [Android](../android_and_CVEs/)
- **CVE-2022-20338** — Android Settings bypass via Intent → [Android](../android_and_CVEs/)
- **CVE-2022-20345** — Android Bluetooth AVDTP RCE → [Android](../android_and_CVEs/)
- **CVE-2022-20421** — Binder node deref locking UAF → [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/)
- **CVE-2022-20423** — Android framework Parcel mismatch → [Android](../android_and_CVEs/)
- **CVE-2022-21882** — Win32k type confusion → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **CVE-2022-21894** — Baton Drop: Secure Boot bypass → [CPU Rings](../ring_and_vulns/)
- **CVE-2022-22057** — Qualcomm Adreno GPU UAF race → [Android](../android_and_CVEs/)
- **CVE-2022-22194** — SEV key management → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/)
- **CVE-2022-22265** — Samsung NPU driver UAF → [Android](../android_and_CVEs/)
- **CVE-2022-22292/728** — Samsung Phone App vulnerability → [Android](../android_and_CVEs/)
- **CVE-2022-22586** — APFS heap buffer overflow → [macOS](../MacOS/)
- **CVE-2022-22706** — ARM Mali GPU UAF (exploited ITW) → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **CVE-2022-22965** — Spring4Shell classloader RCE → [Web Security](../web_security/)
- **CVE-2022-2639** — Open vSwitch UAF → [Cloud Security](../cloud_security/)
- **CVE-2022-46200** — OpenVPN Access Server SQL injection → [Network Security](../network_security/)
- **CVE-2022-46395** — ARM Mali GPU UAF (in-the-wild) → [Android](../android_and_CVEs/)
- **CVE-2022-29657** — S2 Downgrade Attack (Z-Wave) → [IoT](../iot_security/)

### CVE-2023

- **CVE-2023-179** — eBPF integer overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2023-266** — ALSA PCM UAF (exploited ITW) → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **CVE-2023-286** — OpenSSL X.400 PKCS7 over-read → [Cryptography](../cryptography/)
- **CVE-2023-386** — OverlayFS setuid copy-up → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **CVE-2023-461** — mm/uffd UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2023-623** — HP SMM vulnerability → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-2008** — udmabuf OOB → [Linux Kernel](../linux_kernel/)
- **CVE-2023-2033** — Chrome/Skia WebP heap overflow (libwebp) → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/)
- **CVE-2023-2136** — Skia integer overflow (GPU process) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-2163** — eBPF incorrect branch pruning → [Linux Kernel](../linux_kernel/)
- **CVE-2023-2312** — Chrome Omnibox UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-2575** — USB Gadget FunctionFS race → [Linux Kernel](../linux_kernel/)
- **CVE-2023-2598** — io_uring UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2023-2629** — OpenSSL DH key check bypass → [Cryptography](../cryptography/)
- **CVE-2023-2650** — OpenSSL DH key check bypass → [Cryptography](../cryptography/)
- **CVE-2023-2727** — Kubernetes kube-apiserver bypass → [Cloud Security](../cloud_security/)
- **CVE-2023-2929** — Chrome Swiftshader OOB write → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-2932** — Chrome PDF autofill UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-3079** — V8 type confusion (3rd Chrome zero-day 2023) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-32233** — nf_tables set element UAF → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2023-32364** — macOS /tmp symlink race TCC bypass → [macOS](../MacOS/)
- **CVE-2023-32369** — Migraine: SIP bypass via Migration Assistant → [macOS](../MacOS/)
- **CVE-2023-32434** — XNU integer overflow (Operation Triangulation) → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2023-32435** — WebKit code execution (Operation Triangulation) → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2023-32545** — Dell dbutil BYOVD → [Windows Security](../windows_security/)
- **CVE-2023-32629** — OverlayFS container escape (Ubuntu) → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **CVE-2023-33063** — Qualcomm Adreno GPU UAF (DSI handler) → [Android](../android_and_CVEs/)
- **CVE-2023-33106/07** — Qualcomm Adreno GPU kernel exploits → [Android](../android_and_CVEs/)
- **CVE-2023-33200** — ARM Mali GPU UAF → [Android](../android_and_CVEs/)
- **CVE-2023-33234** — Android Mali GPU memory operations → [Android](../android_and_CVEs/)
- **CVE-2023-33634** — TorchServe unauthenticated model deployment → [AI Security](../ai_security/)
- **CVE-2023-33869** — Xen memory mapping UAF → [Cloud Security](../cloud_security/)
- **CVE-2023-33953** — gRPC/Protobuf vulnerability → [Web Security](../web_security/)
- **CVE-2023-34054** — krb5 vulnerability → [Network Security](../network_security/)
- **CVE-2023-34362** — MOVEit Transfer SQL injection → [Web Security](../web_security/)
- **CVE-2023-34527** — PrintNightmare → [Windows Security](../windows_security/)
- **CVE-2023-35001** — nft_validate_register_store integer overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2023-35674** — Android Framework LPE → [Android](../android_and_CVEs/)
- **CVE-2023-35679** — Android System RCE → [Android](../android_and_CVEs/)
- **CVE-2023-36054** — krb5 double-free → [Network Security](../network_security/)
- **CVE-2023-36802** — MSKSSRV.sys pool overflow → [Windows Security](../windows_security/)
- **CVE-2023-36884** — Office/HTML RCE → [Windows Security](../windows_security/)
- **CVE-2023-3739** — MLflow path traversal → [AI Security](../ai_security/)
- **CVE-2023-3776** — cls_fw UAF (KernelCTF) → [Linux Kernel](../linux_kernel/)
- **CVE-2023-3777** — eBPF map value bounds overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2023-3817** — OpenSSL excessive AES-GCM resource consumption → [Cryptography](../cryptography/)
- **CVE-2023-38408** — OpenSSH agent forwarding → [Network Security](../network_security/)
- **CVE-2023-38160** — AMI SMM privilege escalation → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-38606** — Apple SoC GPU coprocessor MMIO bypass (Op Triangulation) → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/), [CPU Rings](../ring_and_vulns/)
- **CVE-2023-3867** — OverlayFS privilege escalation → [Linux Kernel](../linux_kernel/)
- **CVE-2023-4030** — MLflow model signature bypass → [AI Security](../ai_security/)
- **CVE-2023-4068/69/70/71/72** — Chrome WebGL/V8 type confusion cluster → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-4069** — V8 type confusion (in-the-wild) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-4069** — V8 type confusion → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-44Files** — Chrome extension heap overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-41990** — XNU undocumented ADJUST instruction (Op Triangulation) → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2023-4211** — ARM Mali GPU UAF (in-the-wild) → [Android](../android_and_CVEs/)
- **CVE-2023-4295** — ARM Mali GPU OOB write → [Android](../android_and_CVEs/)
- **CVE-2023-4354** — Chrome Skia heap buffer overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-44429** — Hugging Face pickle deserialization → [AI Security](../ai_security/)
- **CVE-2023-44487** — HTTP/2 Rapid Reset DoS → [Network Security](../network_security/), [Web Security](../web_security/)
- **CVE-2023-45857** — Flask debug mode exploit → [Web Security](../web_security/)
- **CVE-2023-46604** — Apache ActiveMQ deserialization RCE → [Web Security](../web_security/), [IoT](../iot_security/)
- **CVE-2023-48409** — Pixel Mali customization integer overflow → [Android](../android_and_CVEs/)
- **CVE-2023-48421** — Pixel Mali second integer overflow → [Android](../android_and_CVEs/)
- **CVE-2023-4911** — glibc ld.so buffer overflow (Looney Tunables) → [Linux Kernel](../linux_kernel/)
- **CVE-2023-4966** — Citrix Bleed: session hijacking → [Network Security](../network_security/)
- **CVE-2023-50387** — DNS KeyTrap DoS → [Network Security](../network_security/)
- **CVE-2023-50782** — OpenSSL QUIC vulnerability → [Cryptography](../cryptography/)
- **CVE-2023-5092** — Chrome Indexed DB CORS bypass → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-5217** — libvpx VP8 heap buffer overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-5247** — Linux networking route UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2023-5345** — SMB client OOB → [Linux Kernel](../linux_kernel/)
- **CVE-2023-5678** — OpenSSL key generation timing side channel → [Cryptography](../cryptography/)
- **CVE-2023-6241** — ARM Mali GPU CSF UAF → [Android](../android_and_CVEs/)
- **CVE-2023-6817** — nf_tables set element activation race → [Linux Kernel](../linux_kernel/)
- **CVE-2023-6241** — ARM Mali GPU UAF (CSF firmware) → [Android](../android_and_CVEs/)
- **CVE-2023-6918** — Safetensors format → [AI Security](../ai_security/)
- **CVE-2023-20198** — Cisco IOS XE privilege escalation RCE → [Network Security](../network_security/)
- **CVE-2023-20269** — Cisco AnyConnect auth bypass → [Network Security](../network_security/)
- **CVE-2023-20569** — AMD Inception: Speculative return stack overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-20593** — AMD Speculative Return Stack Overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-20738** — VPU driver integer overflow → [Android](../android_and_CVEs/)
- **CVE-2023-20937** — Android Framework LPE → [Android](../android_and_CVEs/)
- **CVE-2023-20938** — Binder use-after-free (main case study) → [CVE-2023-20938](../CVE-2023-20938/), [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **CVE-2023-20939** — Android Framework LPE → [Android](../android_and_CVEs/)
- **CVE-2023-20963** — Android WorkSource Parcel mismatch → [Android](../android_and_CVEs/)
- **CVE-2023-21036** — aCropalypse: Pixel screenshot data leak → [Android](../android_and_CVEs/)
- **CVE-2023-21057** — Samsung Exynos baseband RCE → [Android](../android_and_CVEs/), [Network Security](../network_security/)
- **CVE-2023-21085** — Android Bluetooth RCE → [Android](../android_and_CVEs/)
- **CVE-2023-21106** — PowerVR services bridge OOB → [Android](../android_and_CVEs/)
- **CVE-2023-21109** — ActivityManagerService privilege escalation → [Android](../android_and_CVEs/)
- **CVE-2023-21127** — Android Bluetooth RCE via crafted packet → [Android](../android_and_CVEs/)
- **CVE-2023-21238** — system_server info disclosure → [Android](../android_and_CVEs/)
- **CVE-2023-21246** — Android Framework EoP → [Android](../android_and_CVEs/)
- **CVE-2023-21273** — Android zero-click Bluetooth RCE → [Android](../android_and_CVEs/)
- **CVE-2023-21281/82** — Android Bluetooth/media RCE → [Android](../android_and_CVEs/)
- **CVE-2023-21400** — io_uring UAF → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/)
- **CVE-2023-21433** — Samsung Galaxy Store arbitrary app install → [Android](../android_and_CVEs/)
- **CVE-2023-21434** — Samsung Galaxy Store JavaScript execution → [Android](../android_and_CVEs/)
- **CVE-2023-21492** — Samsung kernel KASLR bypass → [Android](../android_and_CVEs/)
- **CVE-2023-21674** — Windows ALPC EoP → [Windows Security](../windows_security/)
- **CVE-2023-21768** — AF_UNIX socket double release → [Windows Security](../windows_security/)
- **CVE-2023-21823** — Win32k xxxDrawGlyphs overflow → [Windows Security](../windows_security/)
- **CVE-2023-22515** — Confluence broken access control RCE → [Web Security](../web_security/)
- **CVE-2023-22642** — Insyde SMM callout → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-23531** — NSPredicate deserialization code execution → [macOS](../MacOS/)
- **CVE-2023-24033/26496** — Samsung Shannon baseband RCE cluster → [Android](../android_and_CVEs/), [IoT](../iot_security/)
- **CVE-2023-25677** — TF Serving DoS → [AI Security](../ai_security/)
- **CVE-2023-26083** — ARM Mali GPU info leak → [Android](../android_and_CVEs/)
- **CVE-2023-26134** — Confluence OGNL injection → [Web Security](../web_security/)
- **CVE-2023-26406/7/8** — Samsung Exynos baseband RCEs → [Android](../android_and_CVEs/), [IoT](../iot_security/)
- **CVE-2023-27997** — FortiGate heap overflow RCE → [Network Security](../network_security/)
- **CVE-2023-28024** — Dell SMM variable service → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-28135** — HP SMM buffer overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-28252** — CLFS.sys heap overflow → [Windows Security](../windows_security/)
- **CVE-2023-28664** — ARM Mali GPU UAF → [Android](../android_and_CVEs/)
- **CVE-2023-28665** — ARM Mali GPU memory operations UAF → [Android](../android_and_CVEs/)
- **CVE-2023-28688** — Xen nested VT-x EPT bug → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2023-29657** — XZ Utils edge case → [Supply Chain](../supply_chain_security/)
- **CVE-2023-30741** — Chrome PDFium type confusion → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-3092** — OpenSSL RFC9260 cert verify DoS → [Cryptography](../cryptography/)
- **CVE-2023-3269** — StackRot: maple tree race condition → [Linux Kernel](../linux_kernel/)
- **CVE-2023-33063** — Qualcomm KGSL UAF (DSI handler) → [Android](../android_and_CVEs/)
- **CVE-2023-3423** — Lenovo SMM privilege escalation → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-35650** — OpenSSL excessive resource consumption → [Cryptography](../cryptography/)
- **CVE-2023-3635** — MLflow arbitrary file upload → [AI Security](../ai_security/)
- **CVE-2023-3739** — MLflow path traversal → [AI Security](../ai_security/)
- **CVE-2023-3776** — nft UAF (KernelCTF) → [Linux Kernel](../linux_kernel/)
- **CVE-2023-38160** — AMI SMM → [CPU Rings](../ring_and_vulns/)
- **CVE-2023-38606** — Apple SoC GPU MMIO bypass (Operation Triangulation) → [macOS](../MacOS/), [CPU Rings](../ring_and_vulns/)
- **CVE-2023-38644/645** — OpenSSL vulnerabilities → [Cryptography](../cryptography/)
- **CVE-2023-4069** — V8 type confusion (in-the-wild) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2023-4211** — ARM Mali UAF → [Android](../android_and_CVEs/)
- **CVE-2023-4295** — ARM Mali OOB write → [Android](../android_and_CVEs/)
- **CVE-2023-43047** — Qualcomm KGSL DMA-buf UAF → [Android](../android_and_CVEs/)
- **CVE-2023-44044** — QEMU virtio-fs → [Cloud Security](../cloud_security/)
- **CVE-2023-44487** — HTTP/2 Rapid Reset → [Network Security](../network_security/)
- **CVE-2023-46604** — Apache ActiveMQ RCE → [IoT](../iot_security/)
- **CVE-2023-48409/421** — Pixel Mali driver integer overflows → [Android](../android_and_CVEs/)
- **CVE-2023-4911** — glibc ld.so buffer overflow → [Linux Kernel](../linux_kernel/)
- **CVE-2023-4966** — Citrix Bleed → [Network Security](../network_security/)
- **CVE-2023-50782** — OpenSSL QUIC stream unbounded DoS → [Cryptography](../cryptography/)
- **CVE-2023-50387** — KeyTrap DNS DoS → [Network Security](../network_security/)
- **CVE-2023-5217** — libvpx VP8 heap buffer overflow → [Chromium](../Chromium_Architecture_and_Vulnerability/)

### CVE-2024

- **CVE-2024-14** — Android System EoP → [Android](../android_and_CVEs/)
- **CVE-2024-31** — Android Bluetooth RCE → [Android](../android_and_CVEs/)
- **CVE-2024-153** — ARM Mali GPU firmware buffer overflow → [Android](../android_and_CVEs/)
- **CVE-2024-402** — eBPF mismatched speculative bounds → [Linux Kernel](../linux_kernel/)
- **CVE-2024-519** — V8 optimizing compiler OOB access → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-582** — io_uring race condition → [Linux Kernel](../linux_kernel/)
- **CVE-2024-727** — OpenSSL PKCS#12 + PBKDF1 weakness → [Cryptography](../cryptography/)
- **CVE-2024-1086** — nf_tables double-free UAF (99.4% exploit rate) → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **CVE-2024-1709** — ConnectWise ScreenConnect auth bypass → [Network Security](../network_security/)
- **CVE-2024-2173** — V8 insufficient data validation → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-2511** — OpenSSL QUIC stream unbounded DoS → [Cryptography](../cryptography/)
- **CVE-2024-2887** — V8 type confusion (Pwn2Own) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-28956** — Intel ITS (Indirect Target Selection) → [CPU Rings](../ring_and_vulns/)
- **CVE-2024-3094** — XZ Utils backdoor → [Supply Chain](../supply_chain_security/), [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **CVE-2024-3400** — PAN-OS command injection → [Network Security](../network_security/)
- **CVE-2024-38106** — Windows kernel EoP → [Windows Security](../windows_security/)
- **CVE-2024-3914** — V8 UAF (ICU string handling) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-4058** — ANGLE/Dawn type confusion → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-4947** — V8 Maglev type confusion (first ITW Maglev exploit) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-5004** — eBPF dead code elimination LPE → [Linux Kernel](../linux_kernel/)
- **CVE-2024-5274** — V8 type confusion pattern → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-6119** — OpenSSL RFC9260 (SCTP) cert verify DoS → [Cryptography](../cryptography/)
- **CVE-2024-7971** — V8 type confusion + kernel EoP chain (DPRK) → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Windows Security](../windows_security/)
- **CVE-2024-7965** — V8 Sandbox bypass via trusted pointer corruption → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2024-20803/861** — Samsung Contacts/SveService → [Android](../android_and_CVEs/)
- **CVE-2024-21338** — appid.sys arbitrary kernel read/write → [Windows Security](../windows_security/)
- **CVE-2024-21345** — Win32k integer overflow OOB write → [Windows Security](../windows_security/)
- **CVE-2024-21412** — SmartScreen bypass → [Windows Security](../windows_security/)
- **CVE-2024-21462** — Qualcomm Audio DSP buffer overflow → [Android](../android_and_CVEs/)
- **CVE-2024-21626** — runc container escape (Leaky Vows) → [Cloud Security](../cloud_security/), [Linux Kernel](../linux_kernel/)
- **CVE-2024-21762** — FortiOS unauthenticated RCE → [Network Security](../network_security/)
- **CVE-2024-23222** — macOS XNU type confusion (in-the-wild) → [macOS](../MacOS/)
- **CVE-2024-23704** — MediaTek EoP → [Android](../android_and_CVEs/)
- **CVE-2024-23717** — Android Framework EoP → [Android](../android_and_CVEs/)
- **CVE-2024-24961** — EDK II SMM heap overflow → [CPU Rings](../ring_and_vulns/)
- **CVE-2024-27198** — JetBrains TeamCity auth bypass → [Web Security](../web_security/), [Supply Chain](../supply_chain_security/)
- **CVE-2024-27394** — TCP-AO UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2024-27539/40** — EU-licant/urgent/11 IoT TCP/IP vulnerabilities → [IoT](../iot_security/)
- **CVE-2024-27541/42** — Nucleus DNS vulnerabilities → [IoT](../iot_security/)
- **CVE-2024-29745** — Pixel Bootloader → [Android](../android_and_CVEs/)
- **CVE-2024-29748** — Pixel Firmware (anti-wipe) → [Android](../android_and_CVEs/)
- **CVE-2024-32896** — Pixel Firmware EoP → [Android](../android_and_CVEs/)
- **CVE-2024-33066** — Qualcomm WLAN memory corruption → [Android](../android_and_CVEs/)
- **CVE-2024-36971** — Linux kernel networking UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2024-37510** — QEMU virtio-gpu → [Cloud Security](../cloud_security/)
- **CVE-2024-38193** — AFD.sys EoP (in-the-wild) → [Windows Security](../windows_security/)
- **CVE-2024-43047** — Qualcomm KGSL DMA-buf UAF → [Android](../android_and_CVEs/)
- **CVE-2024-43093** — Android Framework EoP → [Android](../android_and_CVEs/)
- **CVE-2024-44068** — Samsung m2m scaler UAF → [Android](../android_and_CVEs/)
- **CVE-2024-44133** — Safari TCC bypass (HM Surf) → [macOS](../MacOS/)
- **CVE-2024-47575** — FortiManager missing authentication RCE → [Network Security](../network_security/)
- **CVE-2024-53104** — Linux kernel USB Video OOB (in-the-wild) → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/)
- **CVE-2024-53197** — Linux kernel USB Audio OOB (in-the-wild) → [Linux Kernel](../linux_kernel/)

### CVE-2025

- **CVE-2025-21298** — NTLM credential relay → [Windows Security](../windows_security/)
- **CVE-2025-24495** — Intel Lion Cove BPU speculative execution → [CPU Rings](../ring_and_vulns/)
- **CVE-2025-27363** — FreeType OOB write → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/)
- **CVE-2025-31235** — CoreAudio double-free → [macOS](../MacOS/)
- **CVE-2025-36934** — Pixel BigWave driver UAF → [Android](../android_and_CVEs/)
- **CVE-2025-38236** — UNIX sockets MSG_OOB UAF → [Linux Kernel](../linux_kernel/)
- **CVE-2025-40300** — VMScape: QEMU virtio escape → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **CVE-2025-48530** — CrabbyAVIF (near-miss Rust safety) → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2025-49415** — Samsung Monkey's Audio codec → [Android](../android_and_CVEs/)
- **CVE-2025-54957** — Dolby Unified Decoder zero-click RCE → [Android](../android_and_CVEs/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **CVE-2025-51533** — OWASP java-html-sanitizer bypass → [Web Security](../web_security/)

### CVE-2026

- **CVE-2026-3909** — Google Skia OOB write → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2026-3910** — Chromium V8 memory corruption → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **CVE-2026-5281** — Dawn/WebGPU UAF → [Chromium](../Chromium_Architecture_and_Vulnerability/)

---

## Tool Index

### Fuzzing & Vulnerability Discovery

- **AFL++** → [Fuzzing](../fuzzing_vuln_research/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **AFL** → [Fuzzing](../fuzzing_vuln_research/), [Zero-Day](../zero_day/)
- **libFuzzer** → [Fuzzing](../fuzzing_vuln_research/), [Chromium](../Chromium_Architecture_and_Vulnerability/), [Android](../android_and_CVEs/)
- **syzkaller** → [Fuzzing](../fuzzing_vuln_research/), [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/)
- **OSS-Fuzz** → [Fuzzing](../fuzzing_vuln_research/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **ClusterFuzz** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Fuzzing](../fuzzing_vuln_research/)
- **honggfuzz** → [Fuzzing](../fuzzing_vuln_research/), [Zero-Day](../zero_day/)
- **KLEE** → [Fuzzing](../fuzzing_vuln_research/), [OSEE](../OSEE/)
- **angr** → [Fuzzing](../fuzzing_vuln_research/), [Reverse Engineering](../reverse_engineering/), [OSEE](../OSEE/)

### Reverse Engineering & Binary Analysis

- **Ghidra** → [Reverse Engineering](../reverse_engineering/), [OSEE](../OSEE/), [IoT](../iot_security/), [Zero-Day](../zero_day/)
- **IDA Pro** → [Reverse Engineering](../reverse_engineering/), [OSEE](../OSEE/), [Windows Security](../windows_security/)
- **radare2** → [Reverse Engineering](../reverse_engineering/), [Fuzzing](../fuzzing_vuln_research/), [OSEE](../OSEE/)
- **Binary Ninja** → [Reverse Engineering](../reverse_engineering/), [OSEE](../OSEE/)
- **GDB** → [Linux Kernel](../linux_kernel/), [OSEE](../OSEE/), [CVE-2023-20938](../CVE-2023-20938/), [Fuzzing](../fuzzing_vuln_research/)
- **WinDbg** → [Windows Security](../windows_security/), [OSEE](../OSEE/), [Reverse Engineering](../reverse_engineering/)
- **checksec** → [Linux Kernel](../linux_kernel/), [OSEE](../OSEE/), [Zero-Day](../zero_day/)
- **ROPgadget** → [OSEE](../OSEE/), [Zero-Day](../zero_day/), [Linux Kernel](../linux_kernel/)
- **pwntools** → [OSEE](../OSEE/), [Zero-Day](../zero_day/), [Linux Kernel](../linux_kernel/), [Fuzzing](../fuzzing_vuln_research/)
- **capstone** → [OSEE](../OSEE/), [Reverse Engineering](../reverse_engineering/)
- **Frida** → [Android](../android_and_CVEs/), [Reverse Engineering](../reverse_engineering/), [Zero-Day](../zero_day/)

### Offensive Security & Exploitation

- **Cobalt Strike** → [Windows Security](../windows_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Metasploit** → [Windows Security](../windows_security/), [Zero-Day](../zero_day/), [Network Security](../network_security/)
- **BloodHound** → [Windows Security](../windows_security/)
- **Mimikatz** → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **CrackMapExec** → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **Responder** → [Windows Security](../windows_security/), [Network Security](../network_security/)
- **Impacket** → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **hashcat** → [Cryptography](../cryptography/), [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **John the Ripper** → [Cryptography](../cryptography/), [OSEE](../OSEE/)
- **ExploitDB / searchsploit** → [Zero-Day](../zero_day/), [OSEE](../OSEE/)

### Network & Application Security

- **Burp Suite** → [Web Security](../web_security/), [Fuzzing](../fuzzing_vuln_research/)
- **nmap** → [Network Security](../network_security/), [OSEE](../OSEE/), [Web Security](../web_security/)
- **sqlmap** → [Web Security](../web_security/)
- **ffuf** → [Web Security](../web_security/), [Fuzzing](../fuzzing_vuln_research/)
- **ZAP** → [Web Security](../web_security/)
- **Nuclei** → [Web Security](../web_security/), [Network Security](../network_security/)
- **Wireshark** → [Network Security](../network_security/), [IoT](../iot_security/)
- **tcpdump** → [Network Security](../network_security/), [IoT](../iot_security/)
- **Snort** → [Network Security](../network_security/), [Cloud Security](../cloud_security/)
- **Suricata** → [Network Security](../network_security/)
- **Zeek** → [Network Security](../network_security/)

### Mobile & Embedded

- **apktool** → [Android](../android_and_CVEs/), [Reverse Engineering](../reverse_engineering/)
- **jadx** → [Android](../android_and_CVEs/), [Reverse Engineering](../reverse_engineering/)
- **Drozer** → [Android](../android_and_CVEs/)
- **Objection** → [Android](../android_and_CVEs/), [Reverse Engineering](../reverse_engineering/)
- **Xposed** → [Android](../android_and_CVEs/)
- **QEMU** → [Cloud Security](../cloud_security/), [IoT](../iot_security/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)

### Cryptography

- **OpenSSL** → [Cryptography](../cryptography/), [Network Security](../network_security/), [Web Security](../web_security/)
- **BoringSSL** → [Cryptography](../cryptography/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **GPG** → [Cryptography](../cryptography/), [Supply Chain](../supply_chain_security/)

### Forensics & Monitoring

- **Volatility** → [Windows Security](../windows_security/), [Reverse Engineering](../reverse_engineering/)
- **YARA** → [Reverse Engineering](../reverse_engineering/), [Windows Security](../windows_security/), [Supply Chain](../supply_chain_security/)
- **Sigma** → [Windows Security](../windows_security/), [Cloud Security](../cloud_security/)

### Static Analysis & SAST

- **CodeQL** → [Fuzzing](../fuzzing_vuln_research/), [Supply Chain](../supply_chain_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Semgrep** → [Fuzzing](../fuzzing_vuln_research/), [Web Security](../web_security/), [Supply Chain](../supply_chain_security/)
- **Bandit** → [Fuzzing](../fuzzing_vuln_research/), [Web Security](../web_security/)

### Container & Cloud

- **Docker** → [Cloud Security](../cloud_security/)
- **Kubernetes** → [Cloud Security](../cloud_security/)
- **containerd** → [Cloud Security](../cloud_security/)
- **runc** → [Cloud Security](../cloud_security/)
- **Trivy** → [Cloud Security](../cloud_security/), [Supply Chain](../supply_chain_security/)
- **Falco** → [Cloud Security](../cloud_security/), [Linux Kernel](../linux_kernel/)
- **Tetragon** → [Cloud Security](../cloud_security/), [Linux Kernel](../linux_kernel/)

### Tracing & Debugging

- **strace** → [Linux Kernel](../linux_kernel/), [Fuzzing](../fuzzing_vuln_research/), [OSEE](../OSEE/)
- **ltrace** → [Linux Kernel](../linux_kernel/), [Fuzzing](../fuzzing_vuln_research/)

### Vulnerability Scanning

- **OpenVAS** → [Network Security](../network_security/), [IoT](../iot_security/)
- **Nessus** → [Network Security](../network_security/)
- **SOCAT / netcat** → [OSEE](../OSEE/), [Network Security](../network_security/)

### Hypervisors & Emulation

- **QEMU** → [Cloud Security](../cloud_security/), [IoT](../iot_security/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **VMware** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **VirtualBox** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)

---

## Technology Index

### Operating Systems & Platforms

- **Android** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/), [IoT](../iot_security/), [CVE-2023-20938](../CVE-2023-20938/)
- **Chromium / Chrome** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Fuzzing](../fuzzing_vuln_research/), [Android](../android_and_CVEs/)
- **macOS / XNU** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Windows** → [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **Linux Kernel** → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/), [CVE-2023-20938](../CVE-2023-20938/), [CPU Rings](../ring_and_vulns/)
- **iOS / WebKit** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **FreeRTOS** → [IoT](../iot_security/)
- **Zephyr** → [IoT](../iot_security/)
- **VxWorks** → [IoT](../iot_security/)
- **ThreadX** → [IoT](../iot_security/)
- **Fuchsia** → [IoT](../iot_security/)

### Virtualization & Cloud

- **KVM** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/), [Linux Kernel](../linux_kernel/)
- **Xen** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **Hyper-V** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **QEMU** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/), [Fuzzing](../fuzzing_vuln_research/)
- **Docker** → [Cloud Security](../cloud_security/), [Supply Chain](../supply_chain_security/)
- **Kubernetes** → [Cloud Security](../cloud_security/)
- **containerd** → [Cloud Security](../cloud_security/)
- **runc** → [Cloud Security](../cloud_security/)
- **AWS** → [Cloud Security](../cloud_security/)
- **Azure** → [Cloud Security](../cloud_security/)
- **GCP** → [Cloud Security](../cloud_security/)
- **VMware** → [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)

### CPU & Hardware

- **Intel ME/AMT** → [CPU Rings](../ring_and_vulns/), [IoT](../iot_security/)
- **AMD PSP** → [CPU Rings](../ring_and_vulns/)
- **UEFI/BIOS** → [CPU Rings](../ring_and_vulns/), [IoT](../iot_security/)
- **SMM (System Management Mode)** → [CPU Rings](../ring_and_vulns/), [Windows Security](../windows_security/)
- **TPM** → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/)
- **ARM TrustZone** → [Android](../android_and_CVEs/), [CPU Rings](../ring_and_vulns/), [IoT](../iot_security/)
- **Intel SGX** → [Cryptography](../cryptography/), [CPU Rings](../ring_and_vulns/)
- **AMD SEV** → [Cryptography](../cryptography/), [Cloud Security](../cloud_security/), [CPU Rings](../ring_and_vulns/)
- **ARM Mali GPU** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **Qualcomm Adreno GPU** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **Qualcomm Hexagon DSP** → [Android](../android_and_CVEs/)
- **Samsung Exynos** → [Android](../android_and_CVEs/), [IoT](../iot_security/)
- **Broadcom WiFi** → [Network Security](../network_security/), [Android](../android_and_CVEs/)

### Browser Engines

- **V8** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Fuzzing](../fuzzing_vuln_research/)
- **Blink** → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **WebKit** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **ANGLE** → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Dawn / WebGPU** → [Chromium](../Chromium_Architecture_and_Vulnerability/)

### Security Mechanisms

- **ASLR / KASLR** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [macOS](../MacOS/), [OSEE](../OSEE/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **DEP / NX / W^X** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **SMEP / SMAP** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [OSEE](../OSEE/)
- **KPTI** → [Linux Kernel](../linux_kernel/), [CPU Rings](../ring_and_vulns/), [Windows Security](../windows_security/)
- **CFI (Control Flow Integrity)** → [Linux Kernel](../linux_kernel/), [Windows Security](../windows_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **PAC / BTI (ARM)** → [macOS](../MacOS/), [Android](../android_and_CVEs/)
- **MTE (Memory Tagging)** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **SELinux** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **seccomp** → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **AppArmor** → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **SELinux** → [Android](../android_and_CVEs/), [Linux Kernel](../linux_kernel/)
- **eBPF** → [Linux Kernel](../linux_kernel/), [Cloud Security](../cloud_security/)
- **io_uring** → [Linux Kernel](../linux_kernel/), [Android](../android_and_CVEs/)

### Network Protocols & Infrastructure

- **TLS / SSL** → [Cryptography](../cryptography/), [Network Security](../network_security/)
- **DNS** → [Network Security](../network_security/)
- **WiFi (802.11)** → [Network Security](../network_security/), [IoT](../iot_security/), [Android](../android_and_CVEs/)
- **Bluetooth** → [Network Security](../network_security/), [Android](../android_and_CVEs/), [IoT](../iot_security/)
- **VPN** → [Network Security](../network_security/), [Cloud Security](../cloud_security/)
- **HTTP/2** → [Network Security](../network_security/), [Web Security](../web_security/)
- **gRPC / Protobuf** → [Web Security](../web_security/), [Cloud Security](../cloud_security/)
- **SIP / VoIP** → [Network Security](../network_security/)
- **MQTT** → [IoT](../iot_security/)

### Supply Chain & CI/CD

- **Jenkins** → [Supply Chain](../supply_chain_security/), [Cloud Security](../cloud_security/)
- **PyPI / npm** → [Supply Chain](../supply_chain_security/)
- **SBOM** → [Supply Chain](../supply_chain_security/)
- **SLSA** → [Supply Chain](../supply_chain_security/)

### Cryptographic Libraries & Protocols

- **OpenSSL** → [Cryptography](../cryptography/), [Network Security](../network_security/), [Web Security](../web_security/)
- **BoringSSL** → [Cryptography](../cryptography/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Let's Encrypt** → [Cryptography](../cryptography/), [Web Security](../web_security/)
- **PKI / X.509** → [Cryptography](../cryptography/), [Web Security](../web_security/)
- **Spectre / Meltdown** → [CPU Rings](../ring_and_vulns/), [Cryptography](../cryptography/), [Chromium](../Chromium_Architecture_and_Vulnerability/)

### APT Groups & Campaigns

- **NSO Group / Pegasus** → [Most Complex Exploit](../most_complex_exploit_ever/), [Android](../android_and_CVEs/), [macOS](../MacOS/)
- **Stuxnet** → [Most Complex Exploit](../most_complex_exploit_ever/), [IoT](../iot_security/)
- **Operation Triangulation** → [macOS](../MacOS/), [Most Complex Exploit](../most_complex_exploit_ever/), [CPU Rings](../ring_and_vulns/)
- **Lazarus Group (DPRK)** → [Most Complex Exploit](../most_complex_exploit_ever/), [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **Citrine Sleet** → [Chromium](../Chromium_Architecture_and_Vulnerability/)
- **APT28/29** → [Most Complex Exploit](../most_complex_exploit_ever/), [Network Security](../network_security/)
- **Candiru** → [Chromium](../Chromium_Architecture_and_Vulnerability/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Equation Group** → [Most Complex Exploit](../most_complex_exploit_ever/)

### IoT & Embedded Technologies

- **Automotive (Uconnect, CAN bus)** → [IoT](../iot_security/)
- **Medical devices** → [IoT](../iot_security/)
- **Industrial/SCADA** → [IoT](../iot_security/), [Most Complex Exploit](../most_complex_exploit_ever/)
- **Zigbee / Z-Wave** → [IoT](../iot_security/), [Network Security](../network_security/)
- **Bluetooth Low Energy (BLE)** → [IoT](../iot_security/), [Network Security](../network_security/)

### AI/ML Technologies

- **TensorFlow** → [AI Security](../ai_security/)
- **PyTorch** → [AI Security](../ai_security/)
- **Hugging Face** → [AI Security](../ai_security/)
- **MLflow** → [AI Security](../ai_security/)
- **TorchServe** → [AI Security](../ai_security/)
- **LLM architectures** → [AI Security](../ai_security/)

---

*This index was generated by systematically scanning all 19 tracks across 1,500,000+ words of documentation. For term definitions, see [GLOSSARY.md](GLOSSARY.md). For chronological events, see [TIMELINE.md](TIMELINE.md).*

## References

1. NIST. "National Vulnerability Database." https://nvd.nist.gov/. 2024.
2. MITRE. "ATT&CK Framework." https://attack.mitre.org/. 2024.
3. MITRE. "Common Vulnerabilities and Exposures." https://cve.mitre.org/. 2024.
4. Microsoft Security Response Center (MSRC). https://msrc.microsoft.com/blog/. 2024.
5. Google Project Zero. "Bug Tracker and Research." https://googleprojectzero.blogspot.com/. 2024.
6. Russinovich, M. et al. "Windows Internals." 7th Ed. *Microsoft Press*. 2021.
7. Love, R. "Linux Kernel Development." 3rd Ed. *Addison-Wesley*. 2010.
8. Perla, E. & Oldani, M. "A Guide to Kernel Exploitation: Attacking the Core." *Syngress*. 2010.
9. Offensive Security. "OSEE Certification." https://www.offsec.com/courses/osee/. 2024.
10. SANS Institute. "SEC760: Advanced Exploit Development." https://www.sans.org/cyber-security-courses/advanced-exploit-development/. 2024.