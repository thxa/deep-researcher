# Hardware Crypto Attacks

> An in-depth catalog of attacks targeting cryptographic implementations at the hardware level: HSM vulnerabilities, TPM exploits, smart card attacks, Secure Element weaknesses, bus sniffing, JTAG extraction, and fault injection techniques including glitching and laser fault attacks.

---

## Table of Contents

1. [HSM Attacks](#1-hsm-attacks)
2. [TPM Vulnerabilities](#2-tpm-vulnerabilities)
3. [Smart Card Attacks](#3-smart-card-attacks)
4. [Secure Element Attacks](#4-secure-element-attacks)
5. [Bus Sniffing Attacks](#5-bus-sniffing-attacks)
6. [JTAG-Based Key Extraction](#6-jtag-based-key-extraction)
7. [Glitching Attacks](#7-glitching-attacks)
8. [Laser Fault Injection](#8-laser-fault-injection)

---

## 1. HSM Attacks

### 1.1 HSM Architecture

Hardware Security Modules (HSMs) are tamper-resistant devices designed to securely generate, store, and use cryptographic keys. They are used in PKI root key storage, payment card processing, code signing, and blockchain key management.

**Key architectural features**:
- **Tamper-responsive enclosure**: Detects physical intrusion (drilling, cutting, chemical exposure) and zeroizes (erases) all keys upon detection.
- **Secure key storage**: Keys are stored in battery-backed SRAM or EEPROM inside the tamper-responsive boundary.
- **Cryptographic accelerator**: Dedicated hardware for RSA, AES, ECC, and hash operations, providing high throughput and constant-time execution.
- **Access control**: Keys are accessed through authenticated sessions (MFA, role-based access) and never leave the HSM boundary.
- **FIPS 140-2/3 certification**: Validates the HSM's security mechanisms at Levels 1–4 (Level 4 being the highest, with identity-based authentication and tamper response).

### 1.2 HSM Attack Surfaces

Despite their tamper-resistant design, HSMs have been compromised through several attack vectors:

**Firmware vulnerabilities**: HSM firmware is complex (often running a custom RTOS with TCP/IP stack, PKCS#11 API, and management interface). Bugs in the firmware can be exploited remotely:

- **CVE-2018-6979 (VMware ESXi HSM bypass)**: The VMCI virtual HSM driver had a buffer overflow that allowed guest VMs to execute arbitrary code in the VMX process, bypassing the HSM's isolation boundary.
- **Thales Luna HSM firmware vulnerabilities (CVE-2020-12710)**: Multiple vulnerabilities in the Luna Network HSM's web interface allowed unauthenticated remote code execution, enabling extraction of sensitive key material.

**Side-channel attacks on HSMs**:
- **DPA on HSMs**: Although HSMs incorporate DPA countermeasures (masking, shuffling), the high-speed RSA accelerator produces strong EM emanations that can be captured with a proximal EM probe. The Thales Luna and Entrust nShield HSMs have been shown to leak key material through DPA when the attacker has physical access to the device.
- **Timing attacks on HSM APIs**: The PKCS#11 API's `C_Sign` and `C_Decrypt` functions may have timing differences depending on the key and data. Remote timing attacks over the network can recover RSA keys from HSMs with poor constant-time implementations.

**Supply chain attacks**: If an HSM is intercepted during shipping, the attacker can:
1. Open the HSM enclosure (defeating the tamper detection if the attacker can access the tamper sensor circuitry).
2. Replace the firmware with a modified version that exfiltrates keys.
3. Reseal the HSM and forward it to the intended recipient.

This is mitigated by FIPS 140-2 Level 3+ requirements for tamper-evident seals and firmware integrity verification (signed firmware, secure boot).

### 1.3 PKCS#11 API Attacks

PKCS#11 (Cryptographic Token Interface) is the standard API for interacting with HSMs. It defines objects (keys, certificates, data) and operations (sign, encrypt, decrypt). Several attacks exploit PKCS#11's flexibility:

**Key wrapping attack**: PKCS#11 allows wrapping (exporting) a key encrypted under another key. If a key has `CKA_WRAP=true` and `CKA_EXTRACTABLE=true`, it can be wrapped under any wrapping key — including one supplied by the attacker. The attacker:
1. Generates a wrapping key on the HSM with `CKA_WRAP=true`.
2. Wraps the target key under the attacker's wrapping key.
3. Unwraps the target key on the attacker's machine.

This attack is possible because PKCS#11 does not enforce a strict wrapping key hierarchy. The fix is to set `CKA_TRUSTED=true` only on keys that are explicitly authorized to wrap other keys, and to set `CKA_WRAP_WITH_TRUSTED=true` on keys that should only be wrapped by trusted keys.

**Authentication bypass**: Older HSMs used `CKU_SO` (Security Officer) and `CKU_USER` (User) authentication with PINs. Weak PINs (short numeric PINs) are vulnerable to brute-force:
- FIPS 140-2 Level 3 requires a maximum of 5 failed PIN attempts before lockout.
- However, some HSMs allow the SO to reset the user's PIN, bypassing the lockout.
- FIPS 140-2 Level 4 requires identity-based authentication (smart card + PIN, biometric).

**Object attribute modification**: PKCS#11 allows modifying object attributes after creation. An attacker with a `CKU_USER` session can change `CKA_SENSITIVE=false` on a key, making it extractable through `C_GetAttributeValue`. The fix: set `CKA_MODIFIABLE=false` on sensitive keys.

### 1.4 Notable HSM Compromises

| Year | HSM | Attack | Impact |
|---|---|---|---|
| 2011 | RSA SecurID | Attack on seed database stored in HSM; APT exfiltrated seeds | Compromised 2FA for major US defense contractors |
| 2015 | Samsung SmartTV HSM | DPA on TV's key storage | Extracted DRM keys |
| 2018 | Intel SGX (HSM-like) | Foreshadow (L1TF) attack on SGX enclaves | Extracted sealed keys from enclaves |
| 2020 | Thales Luna | Remote firmware RCE (CVE-2020-12710) | Potential key exfiltration |
| 2021 | Microsoft Azure HSM | Cloud HSM IP allowlist bypass | Unauthorized API access |

---

## 2. TPM Vulnerabilities

### 2.1 TPM Architecture

The Trusted Platform Module (TPM) is a secure cryptoprocessor defined by the Trusted Computing Group (TCG) specification. TPMs are present in virtually all modern laptops, desktops, and servers.

**TPM versions**:
- **TPM 1.2**: RSA and SHA-1 based. Limited key hierarchy. No algorithm agility.
- **TPM 2.0**: Supports RSA, ECC, AES, SHA-256, SHA-384, HMAC. Algorithm agility. Enhanced authorization (EA) with policy binding.

**Key features**:
- **Secure key storage**: Keys are stored inside the TPM and never leave in plaintext (keys are wrapped with a Storage Root Key, SRK).
- **Attestation**: The TPM can sign measurements of the platform's boot chain (TCG Log / Event Log) using an Attestation Identity Key (AIK), providing remote attestation.
- **Sealing**: Data can be "sealed" to specific PCR (Platform Configuration Register) values, making it accessible only when the platform is in a specific state.
- **Random number generation**: The TPM includes a hardware RNG (TRNG) or DRNG that feeds the system's entropy pool.

### 2.2 TPM-FAIL (CVE-2019-16863)

**TPM-FAIL** (Moghimi et al., 2020) demonstrated that TPMs from Infineon, STMicroelectronics, and Nuvoton are vulnerable to timing side-channel attacks on their ECC implementations. The attack targets the TPM's ECC scalar multiplication, which uses a non-constant-time Montgomery ladder.

**Attack procedure**:
1. The attacker sends ECDSA signing requests to the TPM via the TPM command interface (available to any process with access to `/dev/tpm0` or over the LPC/SPI bus).
2. The attacker measures the time of each signing operation with nanosecond precision.
3. Statistical analysis of the timing variation reveals the Hamming weight of the ephemeral key $k$ in each ECDSA signature.
4. Combining timing information from $\sim 40{,}000$ signatures, the attacker recovers the private signing key using lattice-based cryptanalysis (Lenstra et al.'s lattice attack on ECDSA with biased nonces).

**Impact**: Full recovery of an ECC-256 private key from an Infineon TPM in $\sim 34{,}000$ signatures. The attack requires physical access to the TPM bus (LPC or SPI) or local code execution on the host system.

**Mitigation**: TPM firmware updates (available from Infineon, STMicroelectronics, and Nuvoton) patch the ECC implementation to use constant-time scalar multiplication. However, many TPMs are not field-upgradeable, and the fix requires replacing the TPM chip.

### 2.3 ROCA (CVE-2017-15361)

**ROCA (Return of Coppersmith's Attack)** targets Infineon TPMs that generate RSA keys with a specific structure (see §02a for the full mathematical treatment). The attack recovers the private key from the public key in $O(n^5)$ time (where $n$ is the modulus size), compared to the expected $O(\exp(n^{1/3}))$ for general factoring.

**Affected TPMs**:
- Infineon TPMs with firmware versions before 2017.12.28
- Specific Infineon Optiga TPM chips: SLB9645, SLB9670
- YubiKey 4 (which uses an Infineon TPM core)

**Key sizes vulnerable**:
- 1024-bit keys: $\sim 2^{73}$ operations (practical, $\sim 2$ days on a cluster)
- 2048-bit keys: $\sim 2^{108}$ operations (borderline practical, $\sim 80$ years on a single CPU)
- 4096-bit keys: not vulnerable (the prime generation algorithm differs)

**Practical impact**: $\sim 750{,}000$ TPM-generated RSA keys were found to be vulnerable on GitHub, GitLab, and other platforms (scanned by the ROCA research team). Microsoft Azure issued emergency key rotation for affected HSMs.

### 2.4 TPM Bus Sniffing

TPMs communicate with the host CPU via the LPC (Low Pin Count) bus (TPM 1.2) or SPI bus (TPM 2.0). Both buses expose all TPM commands and responses in cleartext:

- **LPC bus**: 4-bit multiplexed address/data bus, clocked at 33 MHz. All TPM commands (including key material, passwords, and attestation data) are transmitted in cleartext.
- **SPI bus**: Serial bus, clocked at 33–50 MHz. Same cleartext exposure.

An attacker with physical access (or a malicious peripheral on the LPC/SPI bus) can:
1. **Intercept** all TPM commands and responses, including sealed data, key wrapping, and attestation quotes.
2. **Inject** commands to the TPM, including key creation, sealing, and unsealing requests.
3. **Reset** the TPM by cycling the LPC reset line, clearing volatile state.

**LPC bus sniffing** (Kauer, 2008): An FPGA-based LPC bus analyzer can be attached to the TPM's LPC pins (easily accessible on most motherboards). The analyzer captures all TPM commands, extracting sealed data blobs, key handles, and attestation quotes.

**SPI bus sniffing** (TPM 2.0): TPM 2.0 uses an SPI bus, which is slightly harder to sniff (higher clock rate, serial protocol) but still feasible with a logic analyzer or FPGA.

**Mitigation**: TPM 2.0 supports encrypting the SPI bus (TPM 2.0 command and response encryption), but this feature is optional and not widely implemented. Some server platforms fold the TPM into the Platform Controller Hub (PCH) or CPU package, making bus sniffing harder.

### 2.5 TPM Reset and State Manipulation

**TPM reset attack**: The TPM's `tpm2_Clear` command (or the physical presence assertion mechanism) resets the TPM to its default state, erasing all keys. An attacker with physical access can reset the TPM and then create new keys, breaking the chain of trust.

**PCR manipulation**: TPM PCRs (Platform Configuration Registers) can only be extended (hashed) or reset (at specific TPM-locality boundaries). An attacker cannot set a PCR to an arbitrary value. However:
- **TPM 1.2**: The `tpm2_Clear` command resets all PCRs to zero. An attacker who can clear the TPM can then extend the PCRs to arbitrary values by running a modified boot chain.
- **TPM 2.0**: The `TPM2_Clear` command requires authorization (either Lockout auth or Physical Presence). If the attacker has this authorization, they can clear the TPM.

**Defense**: Secure the TPM's authorization values (strong passwords, no default passwords). Enable TPM's dictionary attack protection, which locks the TPM after a configurable number of failed authorization attempts.

---

## 3. Smart Card Attacks

### 3.1 Smart Card Architecture

Smart cards (ICC — Integrated Circuit Cards) contain a microcontroller (typically 8-bit or 32-bit) with:
- **CPU**: ARM Cortex-M0/M3 or custom 8-bit core, running at 1–10 MHz.
- **Memory**: 32–512 KB ROM (firmware), 4–64 KB RAM, 64–1024 KB EEPROM/Flash (key storage).
- **Cryptographic coprocessor**: Hardware accelerator for RSA, AES, ECC, SHA.
- **Communication interface**: ISO 7816 contact interface (serial, 9600–115200 bps) or NFC contactless interface (ISO 14443, 106–424 kbps).

Smart cards are used in payment cards (EMV), SIM cards, e-passports, access control cards, and government ID cards.

### 3.2 Fault Injection on Smart Cards

**Fault injection** (also called fault attacks or perturbation attacks) induces errors in the smart card's computation by disrupting its operating conditions. The most common methods:

**Power glitching**: Momentarily reducing the supply voltage ($V_{CC}$) during a specific instruction causes the CPU to skip or incorrectly execute that instruction. For example, reducing $V_{CC}$ to 0V for 1–10 $\mu s$ during a conditional branch can cause the branch to be taken or not taken incorrectly.

**Clock glitching**: Momentarily increasing the clock frequency beyond the chip's maximum rating causes setup/hold time violations, resulting in incorrect instruction execution. A single clock pulse at 2× the normal frequency can cause an instruction to be skipped.

**Electromagnetic glitching**: A brief, intense EM pulse from a coil antenna placed near the chip induces transient currents that corrupt register values or skip instructions. EM glitching is non-invasive (no decapsulation required) and can be performed through the card's plastic substrate.

**Typical fault attacks on smart cards**:

1. **RSA-CRT fault attack** (Boneh, DeMillo, Lipton 1997): The Chinese Remainder Theorem optimization for RSA computes $m^d \mod n$ as $m_p = m^{d \mod (p-1)} \mod p$ and $m_q = m^{d \mod (q-1)} \mod q$, then combines them. A fault during $m_p$ computation (causing an incorrect result $\tilde{m}_p$) yields:

$$\tilde{m} = \text{CRT}(\tilde{m}_p, m_q) \neq m$$

$$\gcd(\tilde{m} - m, n) = \gcd(\tilde{m}_p - m_p, n) = p$$

 recover $p$ (and hence $q = n/p$) from a single faulty signature.

2. **AES fault attack** (Piret and Quisquater 2003): A single-byte fault injected during AES round 8 (of 10) propagates through rounds 9 and 10, producing a specific pattern in the output. By comparing the correct and faulty ciphertexts, the attacker recovers the last round key (4 bytes per fault, requiring $\sim 4$ faults for the full 128-bit key).

3. **PIN bypass**: Glitching past the PIN comparison instruction allows an attacker to bypass PIN verification without knowing the correct PIN:
```c
// VULNERABLE code on smart card:
if (verify_pin(input_pin, stored_pin)) {
    grant_access();
} else {
    increment_retry_counter();
    deny_access();
}

// Glitch the branch instruction to always take the "grant_access" path
// regardless of the PIN comparison result.
```

### 3.3 Probing and Microsurgery

**Invasive attacks** (requiring decapsulation) provide direct access to the smart card's internal circuitry:

**Decapsulation**: The smart card's plastic substrate and epoxy layer are removed using nitric acid or fuming sulfuric acid, exposing the bare die. This process takes 30–60 minutes and costs approximately $200 in chemicals and equipment.

**Microprobing**: After decapsulation, the attacker uses a microprobing station (a microscope with micromanipulators and tungsten probes) to attach to the chip's bond pads or internal bus lines. This allows:
- **Bus sniffing**: Reading data from the internal bus during cryptographic operations.
- **ROM extraction**: Reading the ROM contents byte-by-byte by probing the ROM data bus during a read cycle.
- **RAM/EEPROM reading**: Reading the contents of RAM and EEPROM, which may contain keys, PINs, and other secrets.

**FIB (Focused Ion Beam) editing**: A FIB can modify the chip's circuitry by cutting metal traces or depositing new connections. This is used to:
- Disconnect security sensors (tamper detection circuits).
- Reconnect cut traces to bypass security features.
- Create probe pads by depositing platinum contacts on internal metal layers.

**Cost**: A FIB station costs $\sim \$1\text{M}$, and a microprobing station costs $\sim \$100\text{K}$. FIB time costs $\sim \$1{,}000\text{/hour}$ at a service bureau. These attacks are within the budget of nation-state adversaries and well-funded criminal organizations.

### 3.4 Semi-Invasive Attacks

**Semi-invasive attacks** require decapsulation but not direct probing:

**Optical fault injection**: A photonic (laser) pulse targeted at a specific transistor causes a photoelectric effect that temporarily changes the transistor's state. This is more precise than power/clock glitching and can target specific bits of a register.

**UV EEPROM erasure**: UV light erases EEPROM memory. If the smart card stores security configuration bits (e.g., the "access locked" flag) in EEPROM, exposure to UV light can erase these bits, resetting the card to its initial state.

**Backside imaging**: Using an infrared camera through the back of the die (which is thinner and allows IR transmission), the attacker can observe the chip's activity in real-time without damaging the front-side metal layers.

### 3.5 EM Probing of Smart Cards

As discussed in §04a, EM probing captures the electromagnetic emanations from the smart card's CPU during cryptographic operations. The attack setup is simpler than microprobing (no decapsulation needed) and can be performed at a distance of 1–5 mm.

**Steps for EM probing a smart card**:
1. Place the smart card on a reader.
2. Position a small coil antenna (1 mm diameter) over the chip.
3. Connect the coil to a low-noise amplifier (LNA, $\sim 40$ dB gain, 1 MHz–1 GHz bandwidth).
4. Feed the amplified signal to an oscilloscope (1 GS/s, $\geq 100$ MHz bandwidth).
5. Synchronize the scope with the smart card's clock signal (available on the ISO 7816 CLOCK contact).
6. Collect EM traces during cryptographic operations.
7. Apply DPA/CPA (Correlation Power Analysis) to recover the key.

**Results**: EM probing of a typical EMV payment card can recover the AES key in $\sim 500$ traces and the RSA key in $\sim 1{,}000$ traces. The entire setup costs under $\$5{,}000$.

---

## 4. Secure Element Attacks

### 4.1 Secure Element Architecture

A Secure Element (SE) is a dedicated tamper-resistant chip (similar to a smart card but smaller and more deeply integrated) that provides secure key storage, cryptographic operations, and isolation from the main processor. SEs are used in:
- **Smartphones**: Apple's Secure Enclave, Google's Titan M, Samsung's Knox.
- **Payment terminals**: EMV chip readers.
- **IoT devices**: Trusted execution environments (ARM TrustZone-based SEs).

### 4.2 Oracle Glass Attacks on Apple Secure Enclave

The Apple Secure Enclave Processor (SEP) is an ARM-based secure microcontroller integrated into Apple's A-series and M-series chips. It has:
- Its own secure boot chain.
- A hardware random number generator.
- AES and ECC accelerators.
- Isolated SRAM (4 MB) and ROM (1.5 MB).
- A dedicated mailbox interface for communication with the application processor.

**Oracle Glass** (Markowsky and Sklyar, 2021) is a technique for reading the SE's internal state through the chip's glass cover:
1. Remove the phone's screen and back glass.
2. Expose the SoC die by removing the package (mechanical decapsulation).
3. Use a laser to induce photoelectric effects in specific transistors.
4. Read the resulting current with a microprobe to determine the transistor's state.
5. Map the SE's SRAM layout to locate keys and counters.

This attack requires $\sim \$500\text{K}$ in equipment and $1$–$2$ weeks of effort per chip. It is primarily a nation-state level attack.

**SEP firmware extraction**: The SEP's firmware can be extracted using the `checkm8` bootROM exploit (for A8–A11 chips) or the `Blackbird` exploit (for A12+). The firmware reveals the SEP's code structure and assists in planning side-channel attacks.

### 4.3 Side-Channel on Apple Secure Enclave

The SEP's AES and ECC accelerators are designed to be constant-time, but the isolation boundary between the SEP and the application processor is not absolute:

- **DRAM side channels**: The SEP and application processor share the DRAM bus. The SEP's memory access patterns can be observed from the application processor using DRAM timing side channels (similar to Prime+Probe on the L3 cache).
- **Inter-processor interrupt (IPI) side channels**: The SEP communicates with the application processor via IPIs. The timing and frequency of IPIs can reveal the SEP's operation (e.g., the time between a request and response reveals whether a Touch ID match succeeded).
- **Power side channels**: The SEP's power consumption affects the SoC's overall power draw. A detailed power monitoring IC (like the one in the iPhone for battery management) can observe the SEP's power fluctuations.

### 4.4 Google Titan M Attacks

Google's Titan M (used in Pixel 3+) and Titan M2 (Pixel 6+) are ARM SecurCore SC000-based SEs with:
- Hardware AES and ECC accelerators.
- Secure boot with hardware root of trust.
- Tamper detection (voltage, frequency, temperature sensors).
- Independent DRAM (not shared with the application processor).

**Known vulnerabilities**:
- **CVE-2022-20227**: A buffer over-read in the Titan M's Weaver key derivation function allowed a local attacker with root access to read beyond the buffer boundary, potentially leaking cryptographic material.
- **Clock glitching**: The Titan M's clock source is accessible from the mainboard. Glitching the clock during the secure boot verification can bypass the boot chain integrity check, allowing unsigned firmware execution.

---

## 5. Bus Sniffing Attacks

### 5.1 LPC Bus Sniffing

The LPC (Low Pin Count) bus connects the TPM to the chipset on PC motherboards. The bus operates at 33 MHz with a 4-bit multiplexed address/data bus. All TPM commands and responses (including key material, passwords, and attestation data) are transmitted in cleartext over this bus.

**Sniffing setup**:
1. Attach a logic analyzer or FPGA to the LPC bus pins on the motherboard (easily accessible near the TPM chip).
2. Capture the LPC bus transactions during TPM operations (boot, key creation, attestation).
3. Decode the TPM command/response packets according to the TIS (TPM Interface Specification).
4. Extract relevant data (sealed blobs, SRK public key, EK certificate, attestation quotes).

**Practical attack**: In a corporate environment, an attacker with brief physical access to an employee's laptop (e.g., during a conference break) can attach a small LPC sniffer device ($\sim \$50$ in parts) and capture all TPM transactions. The sniffer can be concealed inside the laptop chassis.

### 5.2 SPI Bus Sniffing (TPM 2.0)

TPM 2.0 typically uses SPI (Serial Peripheral Interface) instead of LPC. The SPI bus operates at 33–50 MHz with a 4-wire interface (CLK, MOSI, MISO, CS#). TPM 2.0 SPI transactions are frame-based:

- **Command frame**: `START` + `Transaction Type` + `Address` + `Data`.
- **Response frame**: `START` + `Transaction Type` + `Address` + `Data`.

The TPM 2.0 specification includes optional encryption for command and response data (using a session-based encryption scheme), but this is rarely enabled in practice.

### 5.3 JTAG and Debug Interface Sniffing

Many embedded devices (routers, IoT devices, industrial controllers) expose JTAG or SWD (Serial Wire Debug) interfaces on their PCBs. These interfaces provide direct access to the CPU's debug features:
- **Memory access**: Read/write all memory (RAM, Flash, registers).
- **Breakpoint/watchpoint**: Set breakpoints on specific addresses.
- **Register access**: Read/write all CPU registers.
- **Trace**: Capture instruction and data traces.

An attacker with JTAG/SWD access can:
1. **Dump firmware**: Read the entire Flash contents through the debug interface.
2. **Extract keys**: Read RAM and Flash to find cryptographic keys.
3. **Modify firmware**: Write a backdoored firmware image to the device.

**JTAGulator**: An open-source tool ($\sim \$50$) that automatically identifies JTAG pins on unknown PCBs by trying all pin combinations.

---

## 6. JTAG-Based Key Extraction

### 6.1 JTAG Access for Key Extraction

**Method 1: Direct memory dump**:
1. Connect JTAG to the target device.
2. Halt the CPU.
3. Dump the entire Flash and RAM contents.
4. Search for cryptographic keys (using entropy analysis, known patterns, or string searches).

```bash
# OpenOCD commands for JTAG key extraction
openocd -f interface/ftdi/olimex-arm-usb-tiny-h.cfg -f target/stm32f4x.cfg

# In OpenOCD telnet session:
> halt
> mdw 0x08000000 0x10000   # Dump first 64KB of Flash
> mdw 0x20000000 0x10000   # Dump first 64KB of RAM
```

**Method 2: Runtime key extraction**:
1. Set a breakpoint on the cryptographic operation (e.g., AES encryption).
2. When the breakpoint hits, read the key register or memory location.
3. Resume execution and capture the next key.

This is more precise than a full memory dump and works even if the key is stored encrypted and only decrypted in RAM during use.

### 6.2 Securing JTAG Interfaces

**JTAG lock**: Most microcontrollers have a JTAG lock feature (e.g., STM32 `RDP` level 1, NXP `FSL_*)*`). When locked, JTAG access is restricted:
- **Level 1**: JTAG read access to Flash is disabled. JTAG can still be used for debugging (breakpoints, single-step).
- **Level 2**: JTAG access is completely disabled. The chip cannot be reprogrammed or debugged via JTAG.

**Bypassing JTAG lock**:
- **Voltage glitching** during the JTAG unlock sequence can cause the lock check to be bypassed.
- **Decapsulation and FIB** can reconnect cut fuses (separate metal traces that control JTAG access).
- **Side-channel analysis** of the JTAG unlock response can reveal the unlock code.

**Best practice**: Set JTAG lock to the highest security level (complete lockout) for production devices. Use a secure boot mechanism for firmware updates instead of JTAG.

---

## 7. Glitching Attacks

### 7.1 Voltage Glitching

Voltage glitching (also called power glitching) is the most common and cost-effective fault injection technique. By momentarily reducing the supply voltage, the attacker causes the CPU to skip an instruction or corrupt a register value.

**Setup**:
1. Identify the target chip's $V_{CC}$ pins.
2. Connect a glitch generator (e.g., ChipWhisperer, Riscure Inspector, or a custom MOSFET circuit) between the power supply and the chip.
3. Synchronize the glitch generator with the target's clock or a trigger signal (e.g., a GPIO pin that toggles before the vulnerable code).
4. Inject the glitch at the precise moment when the target instruction is executing.

**ChipWhisperer** is the most accessible glitching platform ($\sim \$300$ for the CW1170 Lite). It provides:
- Synchronized glitch generation (single or double glitches).
- Variable glitch width (1–100 ns) and offset (0–10 $\mu s$ from the trigger).
- Integrated FPGA for precise timing control.
- Python-based control software.

```python
# ChipWhisperer voltage glitching example
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)

# Configure glitch parameters
scope.glitch.width = 5       # Glitch width in clock cycles
scope.glitch.offset = 20     # Glitch offset from trigger
scope.glitch.ext_offset = 0  # External offset
scope.glitch.repeat = 1      # Single glitch
scope.glitch.trigger_src = "manual"

# Run target with glitch
scope.arm()
target.simpleserial_write("a", b"\x00")  # Send command
scope.glitch.manual_trigger()             # Fire glitch
ret = scope.capture()                     # Capture trace
```

### 7.2 Clock Glitching

Clock glitching injects a fast clock pulse (2–10× the normal frequency) into the target's clock line. The fast pulse causes a setup time violation in the CPU's flip-flops, resulting in instruction skipping or register corruption.

**Setup**:
1. Replace the target's clock source with a glitchable clock (FPGA-based clock generator).
2. Generate the target's normal clock (e.g., 7.37 MHz for an ATMega328P).
3. At a precise moment, insert a fast clock pulse (e.g., 30 MHz, $\sim 33$ ns) that is shorter than the CPU's minimum instruction time.
4. The fast pulse causes the CPU to skip the next instruction because the instruction result hasn't propagated through the pipeline in time.

**Advantages over voltage glitching**:
- More precise (single-cycle resolution).
- More repeatable (less dependent on the chip's power distribution network).
- Easier to synchronize with specific instructions.

**Disadvantages**:
- Requires access to the clock line (which may not be exposed on all platforms).
- Some chips have internal PLLs that filter out clock glitches.

### 7.3 Electromagnetic (EM) Glitching

EM glitching uses a coil antenna (1–5 mm diameter) positioned near the target chip to inject a transient EM pulse. The pulse induces currents in the chip's metal layers, causing transient faults similar to voltage glitching.

**Setup**:
1. Decapsulate the target chip (remove the plastic package above the die).
2. Position a coil antenna over the target area of the die.
3. Generate a short, high-current pulse (10–100 ns, 1–10 A) through the coil.
4. The induced EM field causes transient faults in nearby transistors.

**Advantages**:
- Non-invasive if the chip is accessible through the card substrate (no decapsulation needed for smart cards).
- Spatially precise (the coil affects only the transistors directly below it).
- Can target specific functional units (e.g., the AES coprocessor, ALU, or register file).

**Disadvantages**:
- Requires precise positioning (within 0.1 mm of the target area).
- The coil must be designed for the specific chip's frequency response.

### 7.4 Glitching Attack Case Studies

**Nintendo Switch (CVE-2018-6242)**: The Tegra X1 SoC's RCM (Recovery Mode) can be bypassed by voltage glitching. Shorting a specific pad on the right Joy-Con rail while the Switch boots causes the boot ROM to skip the signature verification, allowing unsigned code execution. This was patched in later hardware revisions by adding a fuse that disables RCM.

**Xbox 360**: The Reset Glitch Hack (RGH) used clock glitching on the Xbox 360's XCGPU. A CPLD generated a precisely-timed clock glitch that caused the CPU to skip a comparison instruction in the boot ROM, allowing downgraded firmware execution.

**STM32F4 readout protection bypass**: Several researchers have demonstrated bypassing STM32's readout protection (RDP Level 1) using voltage glitching. The glitch is injected during the Flash read access check, causing the CPU to read protected Flash contents despite the RDP lock. This is possible because RDP Level 1 only disables external read access (JTAG/SWD), not internal read access by the CPU itself.

---

## 8. Laser Fault Injection

### 8.1 Laser Fault Injection Setup

Laser fault injection uses a focused laser beam to induce photoelectric effects in a specific transistor of a chip. When the laser illuminates a transistor, it generates electron-hole pairs that temporarily change the transistor's state, causing a bit flip or instruction skip.

**Equipment**:
- **Laser**: A near-infrared (NIR) laser (1064 nm) or green laser (532 nm) with $\sim 1$–5 W output. NIR lasers are preferred because silicon is transparent to IR, allowing through-backside attacks.
- **Microscope**: An inverted microscope with motorized X-Y stage ($\sim 0.1$ $\mu$m precision).
- **Triggering system**: A pulse generator synchronized to the target's clock that fires the laser at a specific clock cycle.
- **Decapsulation**: The chip must be decapsulated (front-side) or thinned (backside) to allow the laser to reach the active transistors.

**Backside laser fault injection** (preferred for modern chips):
1. Thin the chip's backside silicon to $\sim 100$ $\mu$m using mechanical polishing.
2. Focus the NIR laser through the backside silicon onto the transistor layer.
3. The laser passes through the silicon substrate (which is transparent to 1064 nm) but is absorbed by the transistor's active regions, causing photocurrent.

Backside laser fault injection requires $\sim \$100\text{K}$–$\$500\text{K}$ in equipment and significant expertise. It is primarily a nation-state level attack.

### 8.2 Laser Fault Injection on AES

**Piret-Quisqueter (PQ) fault attack on AES** (2003): A single-byte fault injected during AES round 8 (of 10) propagates through rounds 9 and 10, producing a specific pattern in the faulty ciphertext:
- The fault affects a single state byte after round 8.
- The MixColumns operation in round 9 spreads this byte to 4 bytes.
- The MixColumns operation in round 10 spreads it to 4 bytes of the final state (but MixColumns is not applied in the last round, so it remains 4 bytes).

By comparing the correct and faulty ciphertexts, the attacker can recover 4 bytes of the round 10 key per fault. With $\sim 4$ faults on different state bytes, the entire 128-bit key is recovered.

**Laser fault injection procedure**:
1. Decapsulate the target chip and mount it on a test board.
2. Run AES encryption with a known plaintext and capture the correct ciphertext.
3. Inject a laser pulse during round 8 (approximately 6–8 $\mu s$ after the AES operation starts, depending on the clock frequency).
4. Capture the faulty ciphertext.
5. Repeat steps 3–4 with different laser positions and timings until a single-byte fault is obtained.
6. Apply the PQ differential fault analysis to recover the round key.

**Results**: With precise laser timing and positioning, an AES-128 key can be recovered in $\sim 4$ laser injections (one per column of the MixColumns operation).

### 8.3 Laser Fault Injection on RSA-CRT

The RSA-CRT optimization computes $m^d \mod n$ as:
$$s_p = m^{d_p} \mod p, \quad s_q = m^{d_q} \mod q$$
$$s = (s_q - s_p) \cdot q_{inv} \mod p \cdot q + s_q$$

A single fault during $s_p$ or $s_q$ computation yields a signature $\tilde{s}$ such that:
- $\tilde{s}^e \equiv \tilde{s}^e \mod n$ (correct, since the public exponent verification uses the faulty signature).
- $\gcd(\tilde{s}^e - m \mod n, n) = p$ (or $q$, depending on which half was faulted).

This recovers one prime factor, completely breaking the key. The fault requires only a single bit flip in $s_p$ or $s_q$ — achievable with one laser pulse.

**Practical results**: Faulting the RSA-CRT computation on an EMV payment card smart chip using a laser requires:
1. Decapsulation of the smart card chip (30–60 minutes).
2. Identification of the RSA coprocessor area on the die (2–4 hours of laser scanning).
3. Fault injection during the CRT computation (requires timing precision of $\sim 1$ $\mu s$).
4. Recovery of the RSA modulus's prime factor from the faulty signature (immediate computation).

### 8.4 Countermeasures Against Laser Fault Injection

- **Redundant computation**: Compute the operation twice and check that the results match. If they differ, the key is zeroized. This doubles the computation time but detects any single fault.
- **Randomized execution order**: Randomize the order of operations within each round (e.g., process AES S-boxes in random order). This makes it harder for the attacker to inject a fault at a specific point in the computation.
- **Error detection codes**: Add parity or CRC checks to intermediate values. If an error is detected, the key is zeroized.
- **Shields and sensors**: Cover the die with a metal shield that detects laser penetration. Modern SEs include optical sensors that trigger key zeroization when laser light is detected.
- **Active mesh**: A mesh of active circuits over the crypto block that detect probe attempts and laser illumination. Any detected intrusion triggers immediate key zeroization.

---

## Cross-References

- **§02a** — RSA/ECC attacks: RSA-CRT fault attack (Boneh-DeMillo-Lipton), ROCA vulnerability
- **§04a** — Side-channel attacks: DPA/SPA on smart cards, cache timing on AES, EM emanation attacks
- **§05b** — Crypto engineering: HSM architecture, key management lifecycle, secure key storage
- **§06** — Case studies: Infineon TPM-FAIL, ROCA vulnerability, Intel SGX Foreshadow attack
- **Linux Kernel track** — TPM driver interface, Linux TPM2 stack, kernel key retention service

## References

1. Boneh, D., DeMillo, R.A., Lipton, R.J., "On the Importance of Checking Computations," EUROCRYPT 1997. https://link.springer.com/chapter/10.1007/3-540-69053-0_6
2. Biham, E., Shamir, A., "Differential Fault Analysis of Secret Key Cryptosystems," CRYPTO 1997. https://link.springer.com/chapter/10.1007/BFb0052249
3. Piret, G., Quisquater, J.-J., "A Differential Fault Attack Technique Against SPN Structures," CHES 2003. https://link.springer.com/chapter/10.1007/978-3-540-45238-6_6
4. NIST, "Security Requirements for Cryptographic Modules," FIPS 140-3, September 2019. https://csrc.nist.gov/publications/detail/fips/140/3/final
5. Common Criteria Recognition Arrangement, "Common Criteria for Information Technology Security Evaluation," Version 3.1, 2017. https://www.commoncriteriaportal.org/
6. ISO/IEC 19790:2012, "Information Technology — Security Techniques — Security Requirements for Cryptographic Modules." https://www.iso.org/standard/53431.html
7. TPM 2.0 Specification, Trusted Computing Group, "TPM Library Specification, Level 00, Revision 01.59," November 2019. https://trustedcomputinggroup.org/resource/tpm-library-specification/
8. Némec, M., Švenda, P., Klinec, V., "The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli," CCS 2017. CVE-2017-15361 (ROCA). https://eprint.iacr.org/2017/1159
9. Moghimi, D., et al., "TPM-FAIL: TPM meets Timing Attacks," CCS 2020. CVE-2019-11090. https://tpm.fail/
10. Van Bulck, J., et al., "Foreshadow: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution," USENIX Security 2018. CVE-2018-3615. https://foreshadowAttack.com/
11. Lee, J., et al., "Infineon Vulnerability: RSA Key Generation via TPM," ROCA, 2017. https://eprint.iacr.org/2017/1159
12. Anderson, R., Kuhn, M., "Low Cost Attacks on Tamper Resistant Devices," Security Protocols Workshop, 1997. https://www.cl.cam.ac.uk/~rja14/tamper.html
13. Skorobogatov, S., "Semi-Invasive Attacks — A New Approach to Hardware Security Analysis," Technical Report, University of Cambridge, 2005. https://www.cl.cam.ac.uk/~sps32/
14. Weingart, S.H., "Physical Security Devices for Computer Subsystems: A Taxonomy of Attacks and Challenges," IEEE Symposium on Security and Privacy, 2000. https://ieeexplore.ieee.org/document/884255
15. NIST SP 800-147, "BIOS Protection Guidelines," April 2011. https://csrc.nist.gov/publications/detail/sp/800-147/final
16. NIST SP 800-147B, "BIOS Protection Guidelines for Servers," September 2014. https://csrc.nist.gov/publications/detail/sp/800-147b/final
17. Intel, "Intel Software Guard Extensions (SGX) Developer Guide," 2020. https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/
18. ARM, "TrustZone Technology for ARM Architecture," ARM DDI 0301, 2009. https://developer.arm.com/documentation/102142/latest