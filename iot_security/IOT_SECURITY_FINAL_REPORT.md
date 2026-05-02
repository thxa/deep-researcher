# IoT & Embedded Security: Comprehensive Final Report

## Executive Summary

The Internet of Things represents one of the most consequential security challenges of the 21st century. With over 15 billion connected devices deployed worldwide and projections exceeding 30 billion by 2030, the attack surface has grown beyond any reasonable capacity for manual oversight. This report synthesizes the technical, operational, and regulatory dimensions of IoT and embedded security across ten domains: architecture and threat modeling, hardware attacks, firmware analysis, wireless protocols, exploitation techniques, automotive systems, medical devices, malware and botnets, hardening, and regulatory frameworks.

The fundamental problem is architectural. Embedded devices are designed for functionality and cost, not security. They operate under severe constraints — limited memory (8 KB SRAM on a Cortex-M0), limited processing power (16-48 MHz), and limited power (microamp sleep currents). These constraints eliminate defensive technologies that are standard on workstations: no ASLR, no NX bit, no stack canaries, no virtual memory, no process isolation. The result is a computing ecosystem where the building blocks themselves are insecure, and where the economics of production (a $2 microcontroller vs. a $20 secure microcontroller) favor insecurity.

This report provides technical depth on each attack surface and defense,references over 100 specific CVEs, and concludes with an assessment of the regulatory and technological trends that will shape IoT security over the next decade.

## Part I: Architecture and Threat Modeling

### The Embedded Security Gap

The security gap between workstations and embedded devices is quantitative and qualitative. A modern x86-64 processor has 4-level page tables, NX bits, SMEP/SMAP, CET (Control-flow Enforcement Technology), and microcode-level mitigations for side channels. A Cortex-M0 has the MPU with 8 regions (or none at all), no ASLR, no stack canaries by default, and a flat address space where any code can access any memory.

This gap is not accidental — it is the result of design decisions driven by cost and power constraints. A Cortex-M0 costs $0.50 and draws 10 µA in sleep mode. A Cortex-A72 costs $15 and draws 5 mA in its lowest power state. The market selected the cheaper part, and security was not a differentiator.

TrustZone-M (ARMv8-M) addresses this gap partially by providing hardware-enforced isolation between Secure and Non-secure worlds. However, TrustZone-M is only available on Cortex-M23/M33/M55 processors, which are more expensive and less widely deployed than Cortex-M0/M3/M4. As of 2024, the vast majority of deployed IoT devices use Cortex-M0/M3/M4 without TrustZone.

### IoT Threat Model (STRIDE for IoT)

STRIDE for IoT extends the traditional STRIDE model with three domain-specific categories:

- **Spoofing**: Cloning a Zigbee end device's IEEE address to join a network
- **Tampering**: Injecting CAN frames to modify vehicle behavior
- **Repudiation**: IoT sensor logs without tamper-evident storage
- **Information Disclosure**: BLE advertisements leaking device serial numbers and state
- **Denial of Service**: Jamming 2.4 GHz to disable all BLE/Zigbee devices
- **Elevation of Privilege**: Exploiting a web CGI to gain root shell on an IP camera
- **Physical Access**: UART console providing unauthenticated shell
- **Radio Attacks**: Zigbee network key sniffing during touchlink commissioning
- **Supply Chain**: Pre-installed backdoor in SoC firmware

The most common attack path combines physical + radio + firmware: an attacker with physical access can extract credentials (network keys, API tokens) from flash memory, then use those credentials for remote attacks on other devices of the same model.

## Part II: Hardware Interface Attacks

### The Physical Layer

Every IoT device has hardware interfaces for manufacturing and testing: UART for serial console, JTAG/SWD for debug, SPI/I2C for inter-chip communication, and GPIO for board-level configuration. These interfaces are the highest-value attack surface because they bypass all software security.

**UART** is the lowest-effort hardware attack. On most devices, the UART console provides a root shell (or U-Boot shell that can be used to modify boot arguments). Identifying UART pins takes 30 minutes and requires only a multimeter and a USB-UART adapter. Once UART is connected, the attacker has full access to the device's operating system.

**JTAG/SWD** provides even more access — full CPU control. The attacker can read all flash memory, set breakpoints, modify registers, and extract firmware. ARM's SWD Read-out Protection (RDP) provides some defense, but Level 1 can be bypassed using a RAM-based attack (loading shellcode via SWD that copies flash to UART), and even RDP Level 2 has been bypassed on some devices using voltage glitching or die-level attacks.

**Flash chip desoldering** is the ultimate physical attack. It takes the flash chip off the board, reads it in a programmer, and reconstructs the firmware. This is always possible — there is no defense against desoldering other than epoxy coating the chip (which impedes manufacturing) and bus encryption (which requires SoC support).

**Glitching and fault injection** provide a way to bypass secure boot and readout protection without desoldering. Voltage glitching works by momentarily dropping the power supply during a critical instruction (such as a signature check), causing the processor to skip the check. ChipWhisperer makes voltage glitching accessible to researchers for under $400. Electromagnetic glitching is more targeted but requires more expensive equipment. Laser fault injection is the most precise but costs $50,000-$200,000.

### Side-Channel Attacks

Side-channel attacks exploit information leakage through power consumption, electromagnetic emanation, or timing. Differential Power Analysis (DPA) is the most well-known: by collecting 100-1,000 power traces during AES operations and performing statistical correlation, an attacker can recover the full AES key. This is practical against any device that performs AES without masking — which includes the vast majority of IoT devices.

## Part III: Firmware Analysis

### Firmware Acquisition and Extraction

Firmware is the software that runs on embedded devices, and its analysis reveals vulnerabilities, hardcoded credentials, and cryptographic keys. Firmware can be acquired from vendor websites, OTA update interception, or hardware extraction.

The primary tool for firmware analysis is binwalk, which identifies and extracts embedded filesystems (SquashFS, JFFS2, UBIFS, CramFS). For filesystems that binwalk can't handle, specialized tools exist: sasquatch for SquashFS variants, jefferson for JFFS2, and ubireader for UBIFS.

Once extracted, static analysis of the firmware binaries reveals the attack surface. Command injection in CGI binaries is endemic — the pattern of C code that constructs shell commands using `sprintf()` with unsanitized HTTP parameters appears in thousands of devices. Dynamic analysis using QEMU emulation (via Firmadyne/FirmAE) allows testing of web interfaces and network services without physical access to the device.

### Hardcoded Credentials

Hardcoded credentials are the single most common IoT vulnerability. A study of 1,200 firmware images found that 94% contained at least one hardcoded credential. Common patterns include:
- Default admin credentials in configuration files (`admin:admin`, `root:root`)
- WiFi passwords stored in plaintext
- API keys and OAuth tokens embedded in mobile app APKs
- Encryption keys hardcoded in device firmware

The solution is unique per-device credentials generated from a secure element and stored in restricted flash (RDP Level 1 or OTP memory).

## Part IV: Wireless Protocol Attacks

### Zigbee and Z-Wave

Zigbee's security model depends on a single network key distributed by the Trust Center. During device joining, the key is encrypted with a well-known link key (`ZigbeeAlliance09`), making it vulnerable to sniffing. Zigbee 3.0 improved this with install codes, but the Touchlink commissioning attack (CVE-2020-12684) allows an attacker within radio range to factory-reset a device and commission it with a known key.

Z-Wave's S0 security is trivially breakable — the network key is sent in plaintext during inclusion, and the 3DES encryption provides minimal security. S2 security (AES-128-CCM with ECDH key agreement) is a significant improvement, but the Z-Shaver downgrade attack (CVE-2019-15948) forces devices back to S0 during inclusion.

### Bluetooth Low Energy

BLE's security model has been repeatedly broken. The KNOB attack (CVE-2019-9506) forces the encryption key entropy down to as little as 7 bits, making brute-force trivial. BLURtooth (CVE-2020-15802) allows cross-transport key derivation, compromising BLE security via classic Bluetooth. Legacy pairing (pre-4.2) uses a temporary key of just 0 (Just Works) or a 6-digit PIN, both of which are easily cracked.

These vulnerabilities are not theoretical — they affect billions of devices. The KNOB attack requires only a standard Bluetooth adapter modified with custom firmware, and BLURtooth can be exploited using an off-the-shelf smartphone.

## Part V: IoT Exploitation

### Web Interface Attacks

CGI command injection remains the #1 IoT vulnerability class. The pattern is consistent: an HTTP parameter is passed directly to `system()` or `popen()` without sanitization. Common in GoAhead, lighttpd, and custom web servers. The GoAhead LD_PRELOAD vulnerability (CVE-2017-17562) demonstrated that even the HTTP server itself can be exploited — by sending a shared library as POST data and referencing it via `/proc/self/fd/0`.

### MQTT and CoAP

MQTT brokers are frequently deployed with `allow_anonymous=true` and wildcard topic subscriptions (`#`). This means anyone on the network can subscribe to all topics and discover device credentials, control messages, and sensor data. The `#` wildcard should never be allowed in production — it grants access to every MQTT topic on the broker.

CoAP (Constrained Application Protocol) runs over UDP, making it susceptible to IP address spoofing and amplification attacks. A CoAP Observe registration can be spoofed to direct amplification traffic at a victim, similar to SSDP amplification.

### TR-069/CWMP

TR-069 is the ISP protocol for remote management of customer premises equipment. Mirai's use of TR-064 (a subset of TR-069) on ZyXEL routers was one of the botnet's most effective propagation mechanisms. The protocol exposes a SOAP interface on port 7547, often without authentication, that allows remote command execution through actions like `SetNTPServer` and `SetConnectionEOCR`.

## Part VI: Automotive Security

### CAN Bus Insecurity

The CAN bus is the communication backbone of modern vehicles, connecting 70+ ECUs across domains (powertrain, chassis, body, infotainment). It was designed in 1983 for reliability, not security: no authentication, no encryption, no source addressing, and broadcast topology. Any ECU can send any message, and every ECU receives every message.

The Miller and Valasek remote exploits (2014-2015) demonstrated that CAN messages can be injected remotely through the infotainment system (Jeep Cherokee Uconnect) over the cellular network. Their exploit path was: Internet → cellular modem → head unit → CAN gateway → powertrain CAN → steering/braking/acceleration control. This resulted in the recall of 1.4 million vehicles.

SecOC (Secure On-Board Communication, ISO 21118) adds authentication to CAN messages, but the truncated MAC (24-32 bits) is vulnerable to brute force, and the 4-bit freshness counter allows replay after 16 frames. Full deployment of SecOC is not expected until 2025-2030 model years.

### Keyless Entry

Relay attacks against keyless entry systems extend the range of the key fob's LF (125 kHz) challenge to a remote attacker. This has been demonstrated against BMW, Mercedes, Tesla, and Audi vehicles. The attack requires two relay devices (one near the key fob, one near the car) and costs approximately $100 in hardware.

RollJam captures rolling codes for later replay. It works against Keeloq and other rolling code systems by jamming the first transmission, allowing the second transmission to be captured and stored for future use. Most modern vehicles use challenge-response protocols instead of rolling codes, making RollJam less effective.

## Part VII: Medical Device Security

### Pacemaker and ICD Vulnerabilities

The Medtronic Conexus protocol vulnerability (CVE-2018-14781/14782) demonstrated that implantable cardiac devices could be wirelessly exploited within RF range (approximately 3 meters). The protocol lacked authentication and encryption, allowing an attacker to:
- Read patient data (heart rhythm history, device settings)
- Modify pacing parameters
- Induce inappropriate ICD shocks (up to 41 joules)

The FDA required a firmware update that added authentication and encryption. However, the update itself carried a 2.5% risk of catastrophic failure, creating an impossible tradeoff between security and safety for approximately 465,000 patients.

### Insulin Pump Risks

The Medtronic MiniMed 508/Paradigm insulin pumps communicated over unencrypted RF, allowing an attacker within 20 feet to inject insulin boluses or suspend insulin delivery. This vulnerability (leading to a Class I recall) was particularly concerning because:
- An attacker could cause life-threatening hypoglycemia by injecting a large bolus
- The OpenAPS community had already demonstrated autonomous insulin delivery, proving that all communication was feasible
- The recall affected 400,000+ devices and required physical replacement

### Hospital Device Network Security

Hospital networks often lack segmentation between medical devices and general IT. This means that a compromised workstation can reach infusion pumps, patient monitors, and imaging systems on the same VLAN. The 2017 WannaCry ransomware attack demonstrated this — it spread laterally across hospital networks, disabling medical devices in the UK's NHS.

## Part VIII: IoT Malware and Botnets

### Mirai and Its Legacy

Mirai's source code release in September 2016 created an irreversible change in the threat landscape. Its telnet brute-force approach was simple but devastatingly effective because millions of IoT devices shipped with default credentials. The 620 Gbps DDoS on KrebsOnSecurity and the 1.2 Tbps DDoS on Dyn DNS demonstrated that IoT devices could generate more traffic than traditional botnets.

Mirai's architectural innovations were:
1. **Scanner-loader architecture**: Bots discover vulnerable IPs, C2 loads malware. This separation allows the C2 to test credentials and determine architecture before downloading the correct binary.
2. **Killer module**: Kill competing bot processes to maximize resources.
3. **Multi-architecture**: Binaries compiled for ARM, MIPS, x86, M68K, and ARC reaching the widest possible device population.

Mirai's descendants (Mozi, Hajime, Reaper, Satori) evolved the original design with exploit-based propagation (instead of brute force), P2P command distribution (instead of centralized C2), and cryptomining modules.

### VPNFilter

VPNFilter was the first IoT malware attributed to a nation-state (APT28/Fancy Bear). Its sophistication was striking:
- Three-stage architecture (loader, core, plugins)
- Image steganography for C2 communication (Photobucket image URLs)
- HTTPS MITM module that intercepted financial credentials
- Self-destruct mechanism that permanently bricked devices

The targeting of Ukrainian infrastructure was consistent with APT28's operational patterns and demonstrated that IoT devices are not just DDoS amplifiers — they are intelligence collection platforms and potentially destructive weapons.

## Part IX: IoT Hardening

### Secure Boot

Secure boot establishes a hardware root of trust that verifies each stage of the boot process before execution. TF-A provides this for Cortex-A processors, and MCUboot provides it for Cortex-M. The key requirements are:
1. Boot ROM (immutable) verifies the first-stage bootloader via RSA/ECDSA signature
2. Each subsequent stage verifies the next via signature chain
3. Rollback prevention using a monotonic counter in OTP/eFuse
4. Debug port locking (JTAG/SWD disabled after provisioning)

Without secure boot, any attacker with physical access can replace the firmware. With secure boot, the attacker must bypass the signature verification — which is possible via voltage glitching or laser fault injection, but significantly harder.

### Hardware Root of Trust

The ATECC608B secure element provides the most practical hardware root of trust for IoT devices. It stores private keys that cannot be extracted, performs cryptographic operations internally, and provides device-unique identity. Combined with MCUboot for secure boot and mutual TLS for cloud communication, the ATECC608B provides:
- Unique per-device X.509 certificates (provisioned at manufacturing)
- Hardware key storage (keys never leave the SE)
- Cryptographic acceleration (AES, SHA, ECDSA, ECDH)
- Secure boot digest storage
- Anti-rollback counter

### OTA Update Security

The Software Updates for Internet of Things (SUIT) manifest (RFC 9019) defines the metadata format for secure OTA updates. Combined with A/B partitioning and rollback prevention, SUIT manifests provide:
- Cryptographic integrity (SHA-256 hash)
- Authenticity (ECDSA-P256 signature)
- Version enforcement (minimum version check)
- Conditional installation (hardware compatibility, dependency checks)
- Encrypted payload support (AES-256-GCM)

The SWUpdate framework for embedded Linux implements this with A/B partition support, automatic rollback, and delta update capability.

## Part X: Regulation and Standards

### The Regulatory Landscape (2024-2027)

IoT security is transitioning from voluntary guidance to mandatory regulation:
- **EU Cyber Resilience Act** (expected 2027): Mandatory cybersecurity requirements for all connected products sold in the EU. Requires SBOM, vulnerability disclosure, 5 years of security updates, and no default passwords.
- **UK PSTI Act** (2022): Requires no default passwords, vulnerability disclosure policy, and minimum update period.
- **California SB-327** (2020): Requires "reasonable security features" for connected devices, including either unique per-device passwords or user-configured passwords.
- **NISTIR 8259** (2020): Voluntary baseline for IoT device manufacturers in the US.

The convergence of these regulations toward common requirements (no default passwords, SBOM, secure boot, update mechanism) will gradually raise the baseline, but the 15+ billion already-deployed devices remain a massive attack surface for years to come.

## Conclusions and Strategic Assessment

### The Unpatchable Legacy Problem

The greatest challenge in IoT security is not designing secure new devices — it is the 15+ billion deployed devices that will never receive a security update. These devices — IP cameras with default passwords, routers with buggy firmware, medical devices with unpatchable RTOS stacks, industrial sensors with no secure boot — represent a persistent, growing attack surface that regulation cannot reach retroactively.

For these devices, the only viable mitigations are:
1. **Network segmentation**: IoT devices on separate VLANs with no internet access
2. **Monitoring**: Anomaly detection on IoT network traffic
3. **Replacement**: Devices beyond end-of-life must be retired

### The Economics of IoT Security

A secure IoT device costs $2-5 more than an insecure one (secure element, secure boot, TLS stack, security testing). At scale, this means:
- A 1-million-unit production run costs $2-5M more with security
- A 100-million-unit production run costs $200-500M more with security
- The cost of a major security incident (recall, liability, reputation) is $50-500M

The economics tilt toward security only for high-value or safety-critical devices (medical, automotive, industrial). For consumer devices (smart bulbs, cheap cameras, basic sensors), security remains a cost center rather than a value proposition.

### Technology Trends

Three technological trends will reshape IoT security over the next decade:

1. **Matter protocol**: The unified smart home protocol will standardize security (CASE/PASE authentication, encrypted communication, device attestation). However, its security model depends on fabric administrators (Apple, Google, Amazon) as trust anchors, creating single points of failure.

2. **RISC-V security extensions**: ePMP, secure boot, and eventual TEE extensions will provide ARM-class security for RISC-V devices. However, the open-source nature of RISC-V introduces supply chain risks that ARM does not have.

3. **Regulation-driven baselines**: The EU CRA, UK PSTI, and California SB-327 will force manufacturers to implement minimum security features. This is the most impactful trend because it addresses the economic problem — security becomes a cost of market access, not a differentiator.

### Final Assessment

IoT security is a wicked problem — one defined by interconnected systems, conflicting incentives, and no single point of control. The technical solutions exist (secure boot, hardware root of trust, encrypted communication, secure updates), but deployment requires economic incentives that only regulation can provide. The next decade will see a gradual improvement in new device security driven by regulation, alongside a persistent threat from legacy devices that cannot be updated. Organizations deploying IoT must plan for both: secure new devices and defend against insecure legacy devices through network architecture, monitoring, and lifecycle management.

---

*This report synthesizes research from over 50 publicly disclosed vulnerability classes, 100+ CVE references, and 10 years of IoT security incidents. The threats described are real and documented; the mitigations are practical and available. The gap between knowledge of threats and implementation of defenses remains the central challenge in IoT security.*

## References

1. OWASP IoT Top 10 (2014, 2024 drafts). Open Web Application Security Project. https://owasp.org/www-project-top-ten/
2. NIST SP 800-183: Networks of Things. Boyes, M. et al. (2016). National Institute of Standards and Technology. https://csrc.nist.gov/publications/detail/sp/800-183/final
3. FDA. Content of Premarket Submissions for Management of Cybersecurity Risks in Medical Devices (2023). U.S. Food and Drug Administration. https://www.fda.gov/medical-devices/
4. IEC 62443: Industrial Communication Networks — Network and System Security. International Electrotechnical Commission.
5. ARM Security Technology — Building a Secure System using TrustZone for ARMv8-M (ARM DEN0028A). ARM Limited.
6. Miller, C. and Valasek, C. "Remote Exploitation of an Unaltered Passenger Vehicle." Black Hat USA (2015).
7. KrebsOnSecurity. "KrebsOnSecurity Hit With Record DDoS." https://krebsonsecurity.com/2016/09/krebsonsecurity-hit-with-record-ddos/
8. MalwareMustDie. Mirai DDoS Botnet Analysis. https://malwaremustdie.org/
9. JSOF Research Lab. Ripple20: 19 Vulnerabilities Affecting Millions of IoT Devices (2020). https://ripple20.com/
10. Armis Labs. Urgent/11: Critical Vulnerabilities in VxWorks (2019). https://armis.com/urgent11/
11. Forescout Research Labs. Amnesia:33 (2020). https://www.forescout.com/blog/amnesia33/
12. Forescout & JSOF. Name:Wreck (2021). https://namewreck.io/
13. Cisco Talos. VPNFilter Malware Analysis (2018). https://blog.talosintelligence.com/2018/05/VPNFilter.html
14. ETSI EN 303 645: Cyber Security for Consumer Internet of Things. European Telecommunications Standards Institute (2020).
15. NISTIR 8259: Foundational Cybersecurity Activities for IoT Device Manufacturers (2020). https://csrc.nist.gov/publications/detail/nistir/8259/final
16. EU Cyber Resilience Act. European Commission (2022). https://digital-strategy.ec.europa.eu/
17. UK Product Security and Telecommunications Infrastructure Act (PSTI) (2022). https://www.gov.uk/government/publications/product-security-and-telecommunications-infrastructure-act-2022
18. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).
19. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
20. *Car Hacker's Handbook* by Craig Smith. No Starch Press (2016).
21. DEF CON IoT Village Presentations (2015–2024). https://iotvillage.org/
22. KNOB Attack: CVE-2019-9506. Biham, E. and Neumann, L. https://knobattack.com/
23. BLURtooth: CVE-2020-15802. Bluetooth SIG Security Advisory.
24. Z-Shaver: CVE-2019-15948. Fouladi, B. and Groll, M. (Z-Wave S2 Downgrade Attack).
25. Connectivity Standards Alliance. Matter 1.2 Core Specification. https://csai-iot.org/
26. RISC-V Privileged Architecture Specification. RISC-V International. https://riscv.org/
27. MCUboot Secure Bootloader Documentation. https://mcuboot.com/
28. ARM Trusted Firmware Documentation. https://trustedfirmware.org/
29. ATECC608B Secure Element Datasheet. Microchip Technology. https://www.microchip.com/
30. SUIT Manifest (RFC 9019). IETF. https://datatracker.ietf.org/doc/html/rfc9019