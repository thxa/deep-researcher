# IoT and Embedded Architecture & Threat Modeling

## 1. Embedded System Constraints

Embedded systems underpin nearly every IoT device, yet their resource constraints fundamentally shape their security posture. Understanding these constraints is prerequisite to any meaningful threat modeling or exploitation work.

### Memory Constraints

IoT microcontrollers typically ship with 8 KB to 2 MB of SRAM and 64 KB to 16 MB of flash storage. A typical ARM Cortex-M4 (STM32F407) provides 192 KB SRAM and 1 MB flash. Compare this with a workstation: the MCU has roughly 0.00005% of the RAM. This deficit eliminates entire classes of defensive technology:

- **No ASLR**: Address randomization requires a virtual memory unit (MMU). Cortex-M processors lack an MMU, using instead an MPU (Memory Protection Unit) with a limited number of regions (typically 8). Without ASLR, ROP exploitation is deterministic.
- **No stack canaries**: While technically possible, canary values consume 4-8 bytes per function frame and require comparison logic. On a device with 192 KB RAM running an RTOS with 10 threads each consuming 2 KB stack, canaries would consume ~80 bytes per thread — a non-trivial overhead.
- **No NX bit**: The MPU can mark regions as execute-never (XN), but many firmware images place code and data in a single flat address space with the MPU left unconfigured.

### CPU Constraints

Cortex-M0/M0+ cores implement the ARMv6-M architecture (Thumb-1 instruction set only). The lack of certain instructions (e.g., `BKPT` in some implementations, `CBNZ`, `IT` blocks) constrains debuggers. Cortex-M3/M4 (ARMv7-M) add Thumb-2 and hardware divide. Cortex-M33/M55 (ARMv8-M) introduce TrustZone-M. The practical exploitation implication: shellcode must be Thumb-1 compatible on M0 targets.

Clock speeds range from 16 MHz to 480 MHz. Cryptographic operations are expensive: a single RSA-2048 signature verification on a Cortex-M4 at 168 MHz takes ~1.5 seconds without hardware acceleration. This drives use of hardware crypto accelerators (e.g., STM32 AES/DES peripheral, NXP LPC Cryptographic Engine), which become attack surfaces themselves.

### Power Constraints

Battery-powered devices (sensor nodes, wearables) operate on microamp sleep currents. A typical BLE sensor node draws 10 µA in sleep and 15 mA during radio transmission. Cryptographic operations that keep the CPU awake for seconds devastate battery life. This creates pressure to:

1. Use weaker cryptographic primitives (e.g., 128-bit AES instead of 256-bit, ECC P-256 instead of RSA-2048)
2. Skip cryptographic verification (e.g., firmware signature checks bypassed for "performance")
3. Reduce key sizes or reuse nonces (e.g., Zigbee networks using well-known network keys)

## 2. RTOS vs Linux-Based IoT

### Real-Time Operating Systems (RTOS)

**FreeRTOS** (Amazon): The most deployed RTOS. Tasks share a flat address space. inter-task protection is optional (`configENABLE_MPU` is off by default). The FreeRTOS kernel itself has had critical vulnerabilities:

- **CVE-2021-3152**: Integer overflow in `prvInsertBlockIntoFreeList` enabling heap corruption
- **CVE-2021-27263**: Buffer overflow in FreeRTOS+TCP DNS response parsing
- **CVE-2021-27264**: Use-after-free in FreeRTOS+TCP `vDNSParse`

**Zephyr** (Linux Foundation): Growing rapidly, especially in Nordic Semiconductor ecosystem. Provides `k_thread` isolation via MPU and supports Cortex-M Security Extension (TrustZone-M). Zephyr's Kconfig system allows disabling security features (`CONFIG_STACK_CANARIES` defaults to `y` but `CONFIG_HW_STACK_PROTECTION` requires explicit enablement).

**ThreadX / Azure RTOS** (Microsoft → Eclipse): The ThreadX kernel powers billions of devices (several Qualcomm chipsets, Marvell WiFi, numerous IoT SoCs). Critical vulnerabilities include:

- **CVE-2020-17518/17519**: The NetX Duo TCP/IP stack had remote code execution and information disclosure flaws.
- **Urgent/11 (CVE-2019-12256 et al.)**: A suite of 11 vulnerabilities in the InterNiche TCP/IP stack used by ThreadX, VxWorks, and others, enabling remote code execution over the network without authentication.

**VxWorks** (Wind River): Used in industrial, automotive, and aerospace. The Urgent/11 vulnerabilities (CVE-2019-12256) affected over 200 million devices. VxWorks' IP stack had a flaw in `ipnat_getnport()` enabling stack overflow via crafted IP fragments.

### Embedded Linux

Devices with 32 MB+ RAM and 128 MB+ flash can run Linux. Common configurations:

- **OpenWrt**: Router/AP firmware, musl libc, BusyBox userland, `procd` init
- **Yocto/Buildroot**: Custom embedded Linux distributions
- **Android Things** (deprecated)** / AOSP-based**: Smart displays, TVs

Linux provides process isolation, ASLR, NX, stack canaries — but embedded Linux deployments often:

1. Run as root (no user separation)
2. Disable ASLR (`kernel.randomize_va_space = 0`)
3. Use static, older kernels (3.x, 4.x) without patching
4. Leave debug ports enabled (telnetd on port 23 with `admin:admin`)
5. Include outdated BusyBox with known CVEs

## 3. MCU Architectures

### ARM Cortex-M Series

| Core | Architecture | TrustZone | FPU | Typical Use |
|------|-------------|-----------|-----|-------------|
| Cortex-M0 | ARMv6-M | No | No | Sensor nodes, basic IoT |
| Cortex-M0+ | ARMv6-M | No | No | Wearables, Beacons |
| Cortex-M3 | ARMv7-M | No | No | Industrial, motor control |
| Cortex-M4 | ARMv7-M | No | Yes | BLE SoCs (nRF52) |
| Cortex-M7 | ARMv7E-M | No | Yes (double) | Audio, vision processing |
| Cortex-M23 | ARMv8-M (Base) | Yes | No | Low-cost secure IoT |
| Cortex-M33 | ARMv8-M (Main) | Yes | Yes | Secure connectivity |
| Cortex-M55 | ARMv8.1-M | Yes | Yes (Helium) | ML inference at edge |

### ARMv8-M and TrustZone-M

TrustZone-M divides execution into **Secure** and **Non-secure** worlds, enforced by hardware. The **Secure Attribution Unit (SAU)** and **Implementation-Defined Attribution Unit (IAU)** define which memory regions, peripherals, and interrupts belong to each world.

Key security mechanisms:
- **Secure Gateway (SG) instruction**: `SG` at address `0x00000000` marks a secure entry point. Non-secure code must branch through an SG instruction to enter secure state.
- **Non-secure Callable (NSC) memory**: Only memory regions marked NSC can contain SG instructions. This prevents arbitrary non-secure code from jumping into secure regions.
- **Secure Fault Handler**: Violations (e.g., non-secure access to secure peripheral) trigger a Secure Fault, handled separately from non-secure faults.

**Attacking TrustZone-M**: While TrustZone-M provides hardware isolation, implementation flaws are common:

1. **NSC region misconfiguration**: If too much memory is marked NSC, attack surface expands. If too little, legitimate secure services cannot expose entry points, leading developers to disable TZ entirely.
2. **Secure peripheral access from non-secure world**: Misconfigured AHB/APB bus matrices may allow non-secure DMA to overwrite secure memory (similar to the Thunderclap attacks on Thunderbolt/PCIe).
3. **Side channels**: Conditional branches in secure code create timing differences observable from the non-secure world (e.g., comparing a supplied key against the stored key byte-by-byte).

### RISC-V in IoT

RISC-V is gaining traction (SiFive E2/E3/S2 cores, ESP32-C3/C6, GD32VF103). Security-relevant extensions:

- **PMP (Physical Memory Protection)**: Similar to ARM MPU but supports up to 16 regions. Entry-level cores may have 0-4 regions.
- **ePMP (Enhanced PMP)**: Adds rule-based locking and non-strict modes. Required for secure boot implementations.
- **屉 extended**: Proposed extension for trusted execution (not yet ratified).

The ESP32-C3 (RISC-V single-core, 160 MHz, 400 KB SRAM) is rapidly replacing ESP32 (Xtensa) in new designs. Its security model includes secure boot V2 (RSA-3072), flash encryption (AES-256-XTS), and a hardware MAC for unique device identity. However, early ESP32-C3 silicon had a bug where secure boot could be bypassed by injecting faults during boot — demonstrating that even well-designed hardware security can fail in implementation.

## 4. SoC Security

### ARM TrustZone-M in Practice

Texas Instruments CC2652R (Zigbee/Thread SoC, Cortex-M4F with TrustZone):
- Uses a Security IP block for AES-128/SHA-256
- Secure zone stores network keys and application keys
- Side-channel countermeasures include constant-time crypto operations

Nordic nRF5340 (BLE/Thread SoC, dual-core: Cortex-M33 application + Cortex-M33 network):
- The network core runs the BLE/802.15.4 stack in a secure domain
- Application core is programmable; SPU (Secure Privilege Unit) controls inter-domain access
- The SPU can be misconfigured, allowing the app core to read network core crypto material

### Secure Boot Chains

A typical secure boot chain for Cortex-M with TrustZone:

```
Boot ROM (immutable) → validates BL2 (first-stage bootloader) via RSA/ECDSA signature
BL2 → validates secure firmware (TF-M) via signature
TF-M → validates non-secure application via signature
Non-secure application executes
```

**Common failures**:
1. Boot ROM checks signature but then executes code that reads unsigned images from external flash (TOCTOU).
2. RSA key stored alongside firmware images with no hardware binding — key replacement attack.
3. Debug access left enabled after manufacturing (SWD port accessible).
4. Rollback protection not implemented — attacker reflashes an older, vulnerable firmware version.

## 5. IoT Communication Protocols

### Zigbee (IEEE 802.15.4)

**Architecture**: Coordinator (trust center) → Router → End Device. Network key distributed by trust center.

**Security model**: AES-128-CCM encryption with 8-byte MIC. Two security levels: Network layer (all nodes share one key) and Application layer (link keys between specific node pairs).

**Known weaknesses**:
- **Network key transport**: During joining, the trust center sends the network key encrypted with the default link key ("ZigbeeAlliance09" — CVE-2020-12684). An attacker sniffing the join can decrypt the network key.
- **Touchlink commissioning**: Allows factory reset and network key extraction within physical proximity. The ZLL (Zigbee Light Link) commissioning procedure uses a well-known transaction key.
- **Green Power**: Proxies can inject decrypted frames. CVE-2020-12689 allows bypass of Green Power sink table validation.
- **Replay attacks**: The Zigbee 3.0 specification improved frame counter handling, but legacy devices (Zigbee PRO 2007) accept frames with counter value 0, enabling replay.

**Attack tools**: KillerBee (framework for Zigbee attacks), rzusbstick firmware, ZigBee Sniffer.

### Z-Wave

**Architecture**: Controller → Slave. Single primary controller manages network keys.

**Security levels**:
- **S0**: Uses 3DES encryption. Key exchange sends the key in plaintext during inclusion. The DES key space (56-bit) is trivially brute-forceable. About 75% of Z-Wave devices still use S0 as of 2024.
- **S2**: Introduced in Z-Wave Plus v2. Uses AES-128-CCM. Key exchange is authenticated via a 5-digit PIN (DCK — Device Confirmation Key). The PIN is only 16.6 bits of entropy — susceptible to brute force.

**CVE-2019-15948 (Z-Shaver)**: A downgrade attack where an attacker forces an S2 device to negotiate S0 during inclusion, then sniffs the plaintext key exchange. This affects any Z-Wave device supporting backwards compatibility with S0.

### Bluetooth Low Energy (BLE)

**Architecture**: Central (master) ↔ Peripheral (slave). Connection intervals, advertising channels (37, 38, 39), data channels (0-36).

**Security model**: Pairing methods — Just Works, Passkey Entry, Out-of-Band (OOB). Legacy pairing uses AES-CCM but the Temporary Key (TK) is derived from a 0-value (Just Works) or 6-digit PIN. LE Secure Connections (BLE 4.2+) use ECDH (P-256) for key agreement.

**Known attacks**:
- **KNOB attack (CVE-2019-9506)**: Forces entropy of the encryption key to as low as 1 byte (7 bits) by negotiating `max_enc_key_size = 7` during pairing, then brute-forces the key. Affects all BLE devices that accept low key sizes.
- **BLURtooth (CVE-2020-15802)**: Cross-transport key derivation allows a BLE pairing key to be used for classic Bluetooth (BR/EDR) and vice versa. An attacker who compromises one transport gains access to the other.
- **BLESA (CVE-2020-13570)**: Spoofed advertisements can trick a previously bonded peripheral into accepting attacker data without re-authentication.
- **GATT enumeration**: The GATT hierarchy (Services → Characteristics → Descriptors) reveals device capabilities. Writes to Characteristics without authentication are a common vulnerability class.

### Thread (IEEE 802.15.4 / 6LoWPAN)

**Architecture**: Mesh networking over 6LoWPAN (IPv6 over 802.15.4). Device types: Border Router, Router, Sleepy End Device.

**Security model**: MLE (Mesh Link Establishment) uses AES-128-CCM. The Commissioner provides network credentials. DTLS is used for joining.

**Security considerations**: Thread 1.3 is the foundation for the Matter protocol. Thread networks use a single network key (like Zigbee Network Key). However, the key is provisioned differently — it's delivered via DTLS from the Commissioner, not in plaintext. The joining device authenticates with a passphrase.

### Matter (formerly CHIP / Connected Home over IP)

**Architecture**: Runs over Thread (for low-power) or Wi-Fi/Ethernet (for powered devices). Uses a unified application layer protocol.

**Security model**:
- Device Attestation Certificate (DAC) chain: Root CA → Product Attestation Authority (PAA) → PAI → DAC on device
- CASE (Certificate Authenticated Session Establishment): ECDH (P-256) key agreement with mutual certificate authentication
- PASE (Passcode Authenticated Session Establishment): SPAKE2+ for initial commissioning
- Fabric-scoped ACLs: Each fabric (administrative domain) has separate ACLs
- Secure channel: AES-128-CCM with session keys derived from CASE/PASE

**Potential attack surfaces**:
- **PASE passcode**: The setup code is typically an 11-digit number (QR code or manual). SPAKE2+ protects against offline dictionary attacks during the protocol, but physical observation of the QR code or PIN enables on-network attacks.
- **Fabric admin key compromise**: A single fabric administrator (e.g., Apple Home, Google Home) holds the root of trust for all devices in that fabric. Compromise of the admin keys grants full device control.
- **OTA downgrade**: Matter specifications require rollback protection, but implementation quality varies.

## 6. IoT Threat Modeling (STRIDE for IoT)

STRIDE adapted for IoT adds three domain-specific threat categories to the classic six:

| Category | Threat | IoT Example |
|----------|--------|-------------|
| **S**poofing | Identity falsification | Clone a Zigbee end device's IEEE address |
| **T**ampering | Data modification | Inject CAN frames to change vehicle state |
| **R**epudiation | Non-repudiation denial | IoT sensor logs without tamper-evident storage |
| **I**nformation Disclosure | Data exposure | BLE advertisement leaking device serial and state |
| **D**enial of Service | Availability loss | Jam 2.4 GHz to disable all BLE/Zigbee devices |
| **E**levation of Privilege | Unauthorized access | Exploit web CGI to gain root shell on camera |
| **P**hysical | Physical access attacks | UART console access, flash chip desoldering |
| **R**adio | Wireless attacks | Replay, key extraction, jamming |
| **S**upply Chain | Component compromise | Pre-installed backdoor in SoC or firmware image |

### Threat Modeling Process for IoT

1. **Asset inventory**: List all components — MCU/SoC, radio modules, sensors, actuators, power supply, debug interfaces, external flash, cloud endpoints, mobile apps.
2. **Data flow mapping**: Trace every data flow — sensor readings → MCU → radio → gateway → cloud → mobile app. Each transition point introduces a trust boundary.
3. **Trust boundary identification**:
   - MCU ↔ external flash (SPI bus — sniffable)
   - MCU ↔ radio module (serial interface — injectable)
   - Device ↔ gateway (wireless — interceptable, jamable)
   - Gateway ↔ cloud (TLS — but check certificate validation)
   - Cloud ↔ mobile app (API — authentication/authorization)
4. **Attack tree construction**: For each high-value asset (e.g., "extract encryption keys"), construct attack trees with OR/AND nodes showing different paths and required resources.

## 7. IoT Attack Surfaces

### Firmware Attack Surface

- **Web interface**: CGI binaries, Lua scripts, GoAhead/lighttpd HTTP servers. Command injection via unsanitized parameters is endemic (e.g., `ping` diagnostic pages accepting `127.0.0.1; telnetd`).
- **UPnP/SSDP**: SOAP actions for port mapping, device description XML parsing. TR-064 exploitation (Mirai variant). Buffer overflows in miniupnpd parsing.
- **MQTT broker**: Often deployed with default credentials (`mosquitto` with no auth), wildcard subscriptions (`#`), and insecure `allow_anonymous` settings.
- **Firmware update mechanism**: Missing signature verification, no rollback protection. OTA updates fetched over HTTP without TLS.

### Hardware Interface Attack Surface

- **UART**: Debug console with U-Boot/CFE bootloader access, factory reset commands
- **JTAG/SWD**: Full MCU control — read flash, set breakpoints, modify registers
- **SPI/I2C**: Bus sniffing for inter-chip communication (MCU ↔ flash, MCU ↔ sensor)
- **GPIO**: Aggregated debug pins, undocumented test modes accessible via specific pin states
- **eMMC**: Raw flash access on embedded Linux SoCs (e.g., router NAND flash, eMMC desoldering)

### Radio Attack Surface

- **Zigbee/Z-Wave/BLE/Thread**: Protocol-specific attacks (key sniffing, replay, downgrade)
- **Wi-Fi**: WPA2/WPA3 attacks, deauthentication, KRACK, PMKID
- **Sub-GHz**: 433/868 MHz remote controls using OOK/FSK without encryption — replay attacks with cheap SDRs (YardStick One, HackRF)
- **SDR**: Wideband capture for protocol reverse engineering (GNURadio, gr-review)

### Cloud API Attack Surface

- **Authentication**: Bearer tokens in URL parameters, JWT with `alg: none`, Facebook/Google OAuth misconfigurations
- **Authorization**: IDOR (Insecure Direct Object Reference) — accessing other users' devices by changing device ID in URL
- **WebSocket**: Unencrypted WS:// instead of WSS://, missing origin validation
- **REST API**: Mass assignment, missing rate limiting, debug endpoints (`/v1/debug`, `/api/internal`)

### Mobile Companion App Attack Surface

- **Hardcoded credentials**: API keys, cloud tokens embedded in APK/IPA
- **Certificate pinning bypass**: Frida SSL pinning bypass scripts, dynamic analysis with objection
- **Local storage**: SharedPreferences (Android), Keychain/UserDefaults (iOS) containing auth tokens
- **Native libraries**: `.so`/`.dylib` containing crypto operations, key material
- **Deep links**: Custom URL schemes enabling unauthorized actions (`nimble://device/add?ssid=attacker_ap`)

### Supply Chain Attack Surface

- **SDK components**: Third-party libraries with known CVEs bundled into firmware
- **Chip-level backdoors**: Undocumented debug modes in SoCs (e.g., Broadcom BCM47xx debug interfaces)
- **Firmware build pipeline**: Compromised CI/CD injecting backdoors (XZ/liblzma backdoor as a template)
- **OEM firmware**: White-label devices receive security updates only when the OEM requests them — which may be never

## 8. IoT Device Taxonomy and Risk Profiles

| Device Category | MCU Class | OS | Radio | Risk Profile |
|----------------|-----------|-----|-------|-------------|
| Smart bulb | Cortex-M0 | No OS / bare metal | BLE/Zigbee | Low cost, no updates, physical proximity |
| Smart plug | Cortex-M0/M3 | FreeRTOS | Wi-Fi | HTTP interface, cloud dependency |
| IP camera | Cortex-A7 | Embedded Linux | Wi-Fi/Ethernet | Web CGI, UPnP, remote attacks |
| Smart lock | Cortex-M4 | Zephyr/FreeRTOS | BLE/Z-Wave | Physical access, relay attacks |
| Thermostat | Cortex-A7 | Embedded Linux | Wi-Fi/Zigbee | Cloud API, mobile app |
| Wearable | Cortex-M4 | FreeRTOS/Zephyr | BLE | Health data privacy |
| Industrial sensor | Cortex-M7 | Zephyr/VxWorks | LoRa/Thread | Safety-critical, hard to update |
| Vehicle ECU | Cortex-R52 | AUTOSAR/VxWorks | CAN/Automotive Ethernet | Safety-critical,Cyber-physical |
| Medical device | Cortex-M4/M7 | FreeRTOS/QNX | BLE/Telemetry | Life-critical, FDA regulated |
| Smart speaker | Cortex-A35 | Linux | Wi-Fi/BLE | Audio privacy, cloud dependency |

## 9. References

- ARMv8-M Architecture Reference Manual (ARM DDI 0553)
- ARM Security Technology — Building a Secure System using TrustZone for ARMv8-M (ARM DEN0028A)
- Zigbee 3.0 Specification (05-3474-22)
- Matter 1.2 Core Specification
- NIST SP 800-183: Networks of Things
- OWASP IoT Top 10 (2014, 2024 drafts)
- IEC 62443: Industrial communication networks — Network and system security
- RIPPLE20 (JSOF): CVE-2020-11899 et al.
- Amnesia:33 (Forescout): TCP/IP stack vulnerabilities in uIP, picoTCP, FNET, NuttX
- Name:Wreck (Forescout): DNS vulnerabilities in uIP, picoTCP, NuttX, and others

## References

1. ARMv8-M Architecture Reference Manual (ARM DDI 0553). ARM Limited.
2. ARM Security Technology — Building a Secure System using TrustZone for ARMv8-M (ARM DEN0028A). ARM Limited.
3. Zigbee 3.0 Specification (05-3474-22). Connectivity Standards Alliance.
4. Matter 1.2 Core Specification. Connectivity Standards Alliance.
5. NIST SP 800-183: Networks of Things. Boyes, M. et al. (2016). National Institute of Standards and Technology.
6. OWASP IoT Top 10 (2014, 2024 drafts). Open Web Application Security Project. https://owasp.org/www-project-iot-top-10/
7. IEC 62443: Industrial Communication Networks — Network and System Security. International Electrotechnical Commission.
8. JSOF Research Lab. Ripple20: 19 Vulnerabilities Affecting Millions of IoT Devices (2020). https://ripple20.com/
9. Forescout Research Labs. Amnesia:33 (2020). https://www.forescout.com/blog/amnesia33/
10. Forescout & JSOF. Name:Wreck (2021). https://namewreck.io/
11. KNOB Attack: CVE-2019-9506. https://knobattack.com/
12. BLURtooth: CVE-2020-15802. Bluetooth SIG Security Advisory.
13. Z-Shaver: CVE-2019-15948 (Z-Wave S2 Downgrade Attack).
14. Zigbee Touchlink: CVE-2020-12684. NVD.
15. Zigbee Green Power: CVE-2020-12689. NVD.
16. RISC-V Privileged Architecture Specification. RISC-V International. https://riscv.org/
17. ESP32 Secure Boot V2 Documentation. Espressif Systems.
18. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022).
19. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
20. FreeRTOS Kernel Vulnerabilities: CVE-2021-3152, CVE-2021-27263, CVE-2021-27264. NVD.
21. Thread 1.3 Specification. Thread Group.
22. BLESA: CVE-2020-13570. NVD.
23. DEF CON IoT Village Presentations. https://iotvillage.org/