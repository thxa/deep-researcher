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