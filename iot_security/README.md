# IoT & Embedded Security Track

A comprehensive deep-research track covering IoT and embedded security from hardware to cloud, with extreme technical depth including CVE references, code snippets, and practical attack/defense details.

## Track Overview

This track covers 10 core domains of IoT and embedded security, culminating in a comprehensive synthesis report and quick-reference cheatsheet.

## Core Documents

| # | Document | Focus | Words |
|---|----------|-------|-------|
| 01 | [IoT Architecture & Threat Modeling](docs/01_iot_architecture_threat_model.md) | MCU architectures, RTOS vs Linux, TrustZone-M, Zigbee/Z-Wave/BLE/Matter protocols, STRIDE for IoT | ~3500 |
| 02 | [Hardware Interface Attacks](docs/02_hardware_interfaces_attacks.md) | UART, JTAG/SWD, SPI/I2C, flash extraction, glitching, side channels, chip-off forensics | ~3500 |
| 03 | [IoT Firmware Analysis](docs/03_iot_firmware_analysis.md) | Firmware acquisition & extraction, binwalk, QEMU emulation, static/dynamic analysis, credential extraction | ~3500 |
| 04 | [Wireless Protocol Attacks](docs/04_wireless_protocols_attacks.md) | Zigbee, Z-Wave, BLE, LoRaWAN, Thread/Matter, RFID/NFC, sub-GHz | ~3500 |
| 05 | [IoT Exploitation](docs/05_iot_exploitation.md) | Command injection, UPnP, MQTT, CoAP, TR-069, DNS rebinding, mDNS | ~3500 |
| 06 | [Automotive Security](docs/06_automotive_security.md) | CAN bus, OBD-II, ECU exploitation, keyless entry, V2X, OTA updates | ~3500 |
| 07 | [Medical Device Security](docs/07_medical_device_security.md) | Pacemaker/ICD vulnerabilities, infusion pumps, DICOM, FDA guidance, regulatory landscape | ~3500 |
| 08 | [IoT Malware & Botnets](docs/08_iot_malware_botnets.md) | Mirai and variants, botnet architecture, cryptojacking, persistence, honeypots | ~3500 |
| 09 | [IoT Hardening & Security](docs/09_iot_hardening_security.md) | Secure boot, hardware root of trust, firmware signing, OTA security, regulatory compliance | ~3500 |
| 10 | [Case Studies & Future](docs/10_iot_case_studies_future.md) | Mirai DYN, VPNFilter, Ripple20, Amnesia:33, Name:Wreck, Urgent/11, regulation trends | ~3500 |

## Reports

| Document | Description | Words |
|----------|-------------|-------|
| [Final Report](IOT_SECURITY_FINAL_REPORT.md) | Comprehensive synthesis across all domains with strategic assessment | ~4000 |
| [Cheatsheet](CHEATSHEET.md) | Quick-reference: UART/JTAG pinouts, default credentials, binwalk/QEMU commands, wireless tools, testing checklist |

## Key Technical References

### Major CVEs Referenced

| CVE | Domain | Description |
|-----|--------|-------------|
| CVE-2017-17562 | Firmware | GoAhead LD_PRELOAD RCE |
| CVE-2021-42342 | Firmware | GoAhead authenticated RCE |
| CVE-2019-9506 | Wireless | BLE KNOB attack |
| CVE-2020-15802 | Wireless | BLE BLURtooth |
| CVE-2019-15948 | Wireless | Z-Wave S0/S2 downgrade (Z-Shaver) |
| CVE-2020-12684 | Wireless | Zigbee Touchlink |
| CVE-2019-12256 | RTOS | VxWorks Urgent/11 stack overflow |
| CVE-2020-11899 | RTOS | Ripple20 ICMPv6 RCE |
| CVE-2020-11901 | RTOS | Ripple20 IPv4 fragment RCE (CVSS 10.0) |
| CVE-2018-14781 | Medical | Medtronic Conexus RF no auth |
| CVE-2019-6547 | Medical | BD Alaris stack overflow |
| CVE-2015-3455 | Medical | Hospira Plum A+ telnet root access |
| CVE-2017-17215 | IoT | Huawei HG532 TR-064 RCE |
| CVE-2019-17624 | Automotive | Jeep Uconnect D-Bus RCE |

### Tools Referenced

| Category | Tools |
|----------|-------|
| Hardware | Saleae Logic, ChipWhisperer, JTAGulator, OpenOCD, pyOCD, flashrom, CH341A |
| Firmware | binwalk, sasquatch, jefferson, Firmadyne, FirmAE, Ghidra, IDA Pro |
| Wireless | KillerBee, Ubertooth, HackRF, Proxmark3, Flipper Zero, bettercap |
| Automotive | can-utils, Scapy, Macchina M2, CANtact, SavvyCAN |
| Exploitation | Frida, objection, Burp Suite, mitmproxy, mitmproxy, GDB multiarch |
| Malware | Cowrie, Dionaea, IoTPOT, Zeek, VirusTotal |

## Prerequisites

- Basic embedded systems knowledge (ARM, RTOS, serial communication)
- Linux command-line proficiency
- Networking fundamentals (TCP/IP, Wi-Fi, Bluetooth)
- Familiarity with at least one programming language (Python, C)
- Basic hardware skills (soldering, multimeter, oscilloscope)

## Recommended Learning Path

1. **Start with**: Architecture & Threat Modeling (01) — establishes the framework
2. **Hardware first**: Hardware Interface Attacks (02) — physical access is highest-value
3. **Firmware extraction**: Firmware Analysis (03) — the bridge between hardware and software
4. **Wireless attacks**: Wireless Protocols (04) — radio is the most accessible remote attack surface
5. **Exploitation**: IoT Exploitation (05) — network-level attacks on devices
6. **Domain-specific**: Automotive (06) and Medical (07) — specialized domains
7. **Offensive**: Malware & Botnets (08) — understand the adversary
8. **Defensive**: Hardening & Security (09) — mitigation and defense
9. **Context**: Case Studies & Future (10) — real-world incidents and trends
10. **Reference**: Cheatsheet and Final Report — synthesis and quick reference

## Caveats

- All techniques described are for authorized security research and testing only
- Obtain proper authorization before testing any device or network
- Medical device testing requires IRB approval and FDA coordination
- Automotive testing should only be performed on closed test tracks
- Responsible disclosure: report vulnerabilities to manufacturers and CERT/CC

## References

1. OWASP IoT Top 10 (2014, 2024 drafts). Open Web Application Security Project. https://owasp.org/www-project-top-ten/
2. NIST SP 800-183: Networks of Things. Boyes, M. et al. (2016). National Institute of Standards and Technology. https://csrc.nist.gov/publications/detail/sp/800-183/final
3. IEC 62443: Industrial Communication Networks — Network and System Security. International Electrotechnical Commission.
4. FDA. Content of Premarket Submissions for Management of Cybersecurity Risks in Medical Devices (2023). U.S. Food and Drug Administration.
5. ARM Security Technology — Building a Secure System using TrustZone for ARMv8-M (ARM DEN0028A). ARM Limited.
6. JSOF Research Lab. Ripple20: 19 Vulnerabilities Affecting Millions of IoT Devices (2020). https://www.jsof-tech.com/disclosures/ripple20/
7. Armis Labs. Urgent/11: Critical Vulnerabilities in VxWorks Affecting Millions of Critical Devices (2019). https://armis.com/urgent11/
8. Forescout Research Labs. Amnesia:33: TCP/IP Stack Vulnerabilities Affecting Millions of IoT Devices (2020). https://www.forescout.com/blog/amnesia33/
9. Forescout & JSOF. Name:Wreck: DNS Vulnerabilities Affecting Over 100 Million Devices (2021). https://www.forescout.com/research-labs/namewreck/
10. Mirai Source Code Analysis. MalwareMustDie. https://malwaremustdie.org/
11. KrebsOnSecurity. "All Mirai Variants" and DDoS Analysis. https://krebsonsecurity.com/
12. DEF CON IoT Village Presentations (2015–2024). https://iotvillage.org/
13. Zigbee Alliance. Zigbee 3.0 Specification (05-3474-22). Connectivity Standards Alliance.
14. Bluetooth SIG. Bluetooth Core Specification Version 5.4. https://www.bluetooth.com/specifications/specs/core-specification-5-4/
15. ETSI EN 303 645: Cyber Security for Consumer Internet of Things: Baseline Requirements. European Telecommunications Standards Institute (2020).
16. NISTIR 8259: Foundational Cybersecurity Activities for IoT Device Manufacturers. National Institute of Standards and Technology (2020).

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **Nissan Leaf remote takeover chain (CVE-2025-32056 through CVE-2025-32063)** *(2025-04)* — At Black Hat Asia 2025, PCAutomotive disclosed an 11-vulnerability attack chain against the 2020 Nissan Leaf, assigned eight CVEs (CVE-2025-32056 to CVE-2025-32063). Entry is via a stack buffer overflow in the Bluetooth Hands-Free Profile (CVE-2025-32059, CVSS 8.8, root RCE on the Bosch/Alps infotainment ECU), combined with a secure-boot bypass (CVE-2017-7932) and a DNS-based C2 channel, yielding persistent CAN-bus control over doors, wipers, mirrors, horn, and steering—even while driving. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-32059)

### Incidents & In-the-Wild Exploitation

- **Aisuru / TurboMirai botnet drives record-breaking 29.7 Tbps DDoS attacks** *(2025-12)* — The Aisuru botnet, a Mirai-derived 'TurboMirai-class' family built from compromised consumer routers, CCTV cameras, and DVR systems, powered the largest DDoS attacks ever recorded in 2025. Cloudflare mitigated an attack peaking at 29.7 Tbps and 14.1 billion packets per second, and NETSCOUT documented related campaigns exceeding 20 Tbps targeting gaming and broadband infrastructure. Aisuru also operates as a DDoS-for-hire and residential-proxy service used for credential stuffing and scraping. [[source]](https://www.securityweek.com/aisuru-botnet-powers-record-ddos-attack-peaking-at-29-tbps/)
- **BadBox 2.0 botnet infects 10+ million Android IoT devices; Google and FBI act** *(2025-07)* — BadBox 2.0, uncovered by HUMAN Security, Trend Micro, and Shadowserver, grew into the largest known botnet of internet-connected TVs, compromising over 10 million uncertified Android Open Source Project devices such as streaming boxes, projectors, digital picture frames, and aftermarket car infotainment units (mostly preloaded with malware in the supply chain). In June 2025 the FBI issued a public warning, and on July 11, 2025 Google filed a federal lawsuit against the operators; the botnet was used for ad/click fraud and residential-proxy-based abuse. [[source]](https://blog.google/innovation-and-ai/technology/safety-security/google-taking-legal-action-against-the-badbox-20-botnet/)
- **Digiever NVR command-injection flaw added to CISA KEV amid Mirai/ShadowV2 exploitation** *(2025-12)* — On December 22, 2025, CISA added CVE-2023-52163 (CVSS 8.8), a missing-authorization/command-injection flaw in the time_tzsetup.cgi interface of end-of-life Digiever DS-2105 Pro network video recorders, to its Known Exploited Vulnerabilities catalog after confirmed in-the-wild attacks. Akamai and Fortinet reported threat actors abusing the unpatched flaw to enlist devices into Mirai and ShadowV2 botnets; with no fix available, CISA advised removing devices from the internet and changing default credentials. [[source]](https://securityaffairs.com/186021/security/u-s-cisa-adds-a-flaw-in-digiever-ds-2105-pro-to-its-known-exploited-vulnerabilities-catalog.html)

### Standards & Frameworks

- **EU Cyber Resilience Act in force; phased IoT obligations begin 2026** *(2025)* — The EU Cyber Resilience Act (Regulation (EU) 2024/2847) entered into force on December 10, 2024, establishing mandatory cybersecurity requirements for products with digital elements, including IoT devices, across their lifecycle. The vulnerability and incident reporting obligations apply from September 11, 2026, and the full set of essential requirements (secure-by-default, no known exploitable vulnerabilities at sale, SBOM, security updates, coordinated disclosure) becomes enforceable on December 11, 2027. [[source]](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- **U.S. Cyber Trust Mark consumer IoT labeling program launches** *(2025-01)* — On January 7, 2025 the White House and FCC launched the U.S. Cyber Trust Mark, a voluntary cybersecurity labeling program for wireless consumer IoT products (e.g., security cameras, smart appliances, baby monitors, fitness trackers) built on NIST IoT criteria, featuring a QR code linking to a product security registry. Personal computers, smartphones, and routers are excluded; by January 4, 2027 vendors supplying consumer IoT to the U.S. government must carry the mark. Notably, lead administrator UL Solutions withdrew effective December 19, 2025. [[source]](https://www.fcc.gov/CyberTrustMark)
