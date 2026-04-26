# Ring -3: Intel Management Engine & AMD Platform Security Processor

> *"The deepest privilege level on modern x86 hardware — a system within the system, invisible to the OS, immutable to the administrator, and with unrestricted access to everything."*

---

## Table of Contents

1. [What is Ring -3?](#1-what-is-ring--3)
2. [Intel Management Engine (ME) Architecture](#2-intel-management-engine-me-architecture)
3. [Intel ME Vulnerabilities and CVEs](#3-intel-me-vulnerabilities-and-cves)
4. [AMD Platform Security Processor (PSP)](#4-amd-platform-security-processor-psp)
5. [ME/PSP Attack Surface](#5-mepsp-attack-surface)
6. [Disabling/Limiting ME](#6-disablinglimiting-me)
7. [References](#7-references)

---

## 1. What is Ring -3?

### 1.1 The Privilege Hierarchy

The x86 privilege architecture defines four numeric rings (Ring 0 through Ring 3), but modern processor architectures embed subsystems that operate **below** even Ring 0 (kernel) and Ring -2 (System Management Mode / SMM). This informal designation — **Ring -3** — refers to coprocessors that:

- Execute their own firmware from masked ROM or signed flash regions
- Run independently of the host CPU at all times (including when the host is in S3/S5 sleep states)
- Have DMA (Direct Memory Access) to host physical memory
- Cannot be inspected, halted, or disabled by the host OS or even SMM
- Are architecturally guaranteed to be running whenever the platform has power

```
┌──────────────────────────────────────────────┐
│  Ring 3  — User-space applications           │
├──────────────────────────────────────────────┤
│  Ring 0  — OS kernel                         │
├──────────────────────────────────────────────┤
│  Ring -1 — Hypervisor (VT-x / SVM)           │
├──────────────────────────────────────────────┤
│  Ring -2 — System Management Mode (SMM)      │
├──────────────────────────────────────────────┤
│  Ring -3 — Intel ME / AMD PSP                │
│           (Separate processor, own firmware,  │
│            always-on, full DMA to host RAM)  │
└──────────────────────────────────────────────┘
```

### 1.2 The "Below SMM" Problem

SMM (System Management Mode) was long considered the most privileged execution state on x86. SMM operates at Ring -2: it can intercept any interrupt via SMIs, has a separate memory region (SMRAM) that is invisible to the OS, and cannot be preempted by Ring 0 code. However, Ring -3 subverts even SMM because:

- **The ME can trigger SMIs** into the host processor via the `PMC_SMDATA` / `PMC_SMMSG` registers, meaning Ring -3 can invoke Ring -2 code.
- **The ME has DMA access** to any physical address, including SMRAM, meaning Ring -2 memory is **not** protected from Ring -3 inspection or modification.
- **The ME runs on physically separate silicon** — it cannot be single-stepped or halted by any host-CPU debug mechanism.

This creates a fundamental trust relationship: the operating system must trust the ME/PSP because there is no architectural mechanism to contain it.

### 1.3 Why Ring -3 Exists

Intel and AMD introduced these subsystems to provide:

| Function | Intel ME | AMD PSP |
|----------|----------|---------|
| Remote management | AMT / vPro | — |
| Firmware verification | Boot Guard | Platform Secure Boot |
| Full-disk encryption key management | EPID / fTPM | fTPM / SEV |
| DRM / content protection | PAVP | — |
| Out-of-band monitoring | PET / watchdog | — |
| Secure boot enforcement | Boot Guard | Secure Boot |
| Hardware attestation | EPID | SEV attestation |

The design philosophy: provide **out-of-band management** and **hardware-rooted trust** even when the host OS is compromised, unreachable, or powered off.

---

## 2. Intel Management Engine (ME) Architecture

### 2.1 What is Intel ME?

The Intel Management Engine is a **complete, autonomous computer system** embedded within the Platform Controller Hub (PCH) or, starting with ME 11+, integrated into the SoC package. Key characteristics:

- **Runs a MINIX 3–based operating system** (confirmed by Positive Technologies' reverse engineering in 2017)
- **Operates on a separate processor core**: originally a 32-bit SPARC core (ME 1.x–10.x), later a 32-bit ARC (Argonaut RISC Core) processor (ME 11+ on PCH, or on-die ARC on SoCs like Skylake/Kaby Lake)
- **Always-on**: the ME begins execution as soon as the platform receives standby power (S5 state) and continues running in all power states including S0, S3 (suspend-to-RAM), and S5 (soft-off). Only a hard power disconnect (PSU switch or battery removal) halts it.
- **Owns its own firmware**: stored in a dedicated region of the SPI flash chip (typically 1.5–7 MB), signed by Intel with RSA-3072 keys
- **Has dedicated SRAM**: the ME has its own ~1.5 MB (ME 11+) or ~384 KB (earlier) embedded SRAM, not shared with the host
- **Network stack**: full TCP/IP stack with its own MAC address, independent of the host NIC
- **Crypto engine**: hardware-accelerated RSA, ECC, AES, SHA, and Intel EPID (Enhanced Privacy ID) operations

```
┌─────────────────────────────────────────────────────────────────┐
│                     Intel SoC / PCH Package                     │
│                                                                 │
│  ┌──────────────────┐          ┌──────────────────────────┐      │
│  │   Host CPU       │          │   Management Engine       │      │
│  │  (x86-64 cores)  │          │  ┌────────────────────┐  │      │
│  │                  │          │  │ ARC/SPARC Processor │  │      │
│  │  Ring 0 (kernel) │◄────────┤  │ MINIX-3 OS         │  │      │
│  │  Ring 3 (user)   │  HECI   │  │ Applications:      │  │      │
│  │                  │          │  │  AMT, ICC, MDES...  │  │      │
│  └──────────────────┘          │  └────────────────────┘  │      │
│         ▲                      │  ┌────────────────────┐  │      │
│         │ DMA                  │  │  ME SRAM (1.5 MB)  │  │      │
│         │                      │  └────────────────────┘  │      │
│  ┌──────┴───────────┐          │  ┌────────────────────┐  │      │
│  │  Host RAM        │◄─────────┤  │  Crypto Engine      │  │      │
│  │  (DDR4)          │  DMA     │  │  (RSA/ECC/AES/SHA) │  │      │
│  └──────────────────┘          │  └────────────────────┘  │      │
│                                │  ┌────────────────────┐  │      │
│  ┌──────────────────┐          │  │  Network MAC       │  │      │
│  │  SPI Flash        │◄────────┤  │  (OOB channel)      │  │      │
│  │  ┌────┐┌────┐    │          │  └────────────────────┘  │      │
│  │  │BIOS││ME  │    │          │  ┌────────────────────┐  │      │
│  │  │    ││FW  │    │          │  │  HECI Interface    │  │      │
│  │  └────┘└────┘    │          │  └────────────────────┘  │      │
│  └──────────────────┘          └──────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 ME Firmware Architecture

The ME firmware is stored in the SPI flash in a dedicated region (the "`ME Region`") and follows a layered architecture:

```
┌─────────────────────────────────────┐
│       ME Applications Layer         │
│  ┌───────┐ ┌──────┐ ┌───────────┐  │
│  │  AMT  │ │ MDES │ │  ICC      │  │
│  └───────┘ └──────┘ └───────────┘  │
│  ┌───────┐ ┌──────┐ ┌───────────┐  │
│  │  MNG  │ │ PAVP │ │  KERNEL   │  │
│  └───────┘ └──────┘ └───────────┘  │
├─────────────────────────────────────┤
│       ME Kernel / MINIX-3           │
│  ┌───────────────────────────────┐  │
│  │ Process scheduler, IPC, VFS,  │  │
│  │ memory manager, driver model  │  │
│  └───────────────────────────────┘  │
├─────────────────────────────────────┤
│       Hardware Abstraction (HAL)    │
│  ┌───────────────────────────────┐  │
│  │ DMA, HECI, SPI, GPIO, Clocks │  │
│  └───────────────────────────────┘  │
├─────────────────────────────────────┤
│       Boot ROM (masked, immutable)  │
│  ┌───────────────────────────────┐  │
│  │ Root of trust, initial boot, │  │
│  │ RSA signature verification    │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

#### 2.2.1 Boot ROM

The ME boot ROM is masked into the silicon during manufacturing and cannot be modified. Its responsibilities:

1. **Initial hardware bring-up**: Configure clocks, SRAM, and DMA controllers
2. **Load and verify the first-stage bootloader** from the SPI flash `ME Region`
3. **Establish the root of trust**: The ROM contains Intel's public key hash; it verifies the RSA-3072 signature on the ME firmware partition using SHA-256 + RSA
4. **Chain of trust**: After verification, control transfers to `RBE` (Root Boot Extension) which verifies subsequent modules

#### 2.2.2 ME Kernel (MINIX-3)

Positive Technologies confirmed in 2017 that the ME 11+ kernel is based on **MINIX 3**, a microkernel OS designed for reliability by Andrew Tanenbaum. Key subsystems:

| MINIX-3 Subsystem | ME Role |
|---|---|
| Microkernel | Scheduling, IPC, interrupt routing |
| VFS (Virtual File System) | Abstracts SPI flash partitions as file-like objects |
| Process manager | Manages ME application processes (each as a separate MINIX process) |
| Memory manager | Manages ME SRAM allocation |
| Driver model | Hardware drivers for DMA, HECI, GPIO, network MAC |

The MINIX kernel provides **process isolation** between ME applications, but this isolation has been repeatedly defeated through memory corruption vulnerabilities (see Section 3).

#### 2.2.3 ME Applications

ME applications are MINIX-3 user-space processes loaded from signed firmware partitions. Major applications:

| Application | Description |
|---|---|
| **AMT / iAMT** | Active Management Technology — remote management via web interface, KVM over IP, IDE-Redirection, Serial-over-LAN |
| **MDES** | Manageability and Security Engine Subsystem — core manageability framework |
| **ICC** | Integrated Clock Control — clock/calibration management |
| **PAVP** | Protected Audio/Video Path — DRM engine for HDCP / content protection |
| **MNG** | Manageability Engine — platform event handling, watchdog |
| **KERNEL** | Internal kernel module for specific cryptographic operations |
| **FTPM** | Firmware TPM — implements TPM 2.0 in ME firmware |
| **SELED/ALEX** | DAL (Dynamic Application Loader) — runtime code loading mechanism |

### 2.3 ME's Network Capabilities: Active Management Technology (AMT)

Intel AMT is one of the most significant and controversial ME subsystems. It provides **out-of-band (OOB) management** of a platform regardless of the host OS state.

#### 2.3.1 AMT Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Remote Management Console            │
│            (Web UI / WS-Man / SOAP)                   │
└──────────────────┬───────────────────────────────────┘
                   │ HTTPS (TCP/16993)
                   │ SOAP/WS-Man
                   ▼
┌──────────────────────────────────────────────────────┐
│              Intel AMT (inside ME)                    │
│  ┌─────────────────────────────────────────────┐     │
│  │ Web Server (lighttpd-based)                 │     │
│  │  • Digest auth / Kerberos auth               │     │
│  │  • TLS 1.0–1.2 (ME 11+)                     │     │
│  └─────────────────────────────────────────────┘     │
│  ┌─────────────────────────────────────────────┐     │
│  │ KVM over IP (VNC-derived)                   │     │
│  │  • Redirects host VGA framebuffer            │     │
│  │  • Injects keyboard/mouse via USB emulation  │     │
│  └─────────────────────────────────────────────┘     │
│  ┌─────────────────────────────────────────────┐     │
│  │ IDE-Redirection (IDE-R)                     │     │
│  │  • Virtual CD/DVD/ISO mount                 │     │
│  └─────────────────────────────────────────────┘     │
│  ┌─────────────────────────────────────────────┐     │
│  │ Serial-over-LAN (SoL)                       │     │
│  │  • Redirects serial port over network        │     │
│  └─────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────┘
```

#### 2.3.2 AMT Network Access

| Feature | Detail |
|---------|--------|
| **Default port** | TCP/16992 (HTTP), TCP/16993 (HTTPS) |
| **OOB access** | Can access network even when host OS is down (S3/S5) |
| **Dedicated MAC** | ME has its own MAC address on the shared NIC; in some configurations, a completely separate physical NIC (dedicated management port on server platforms) |
| **IPv6** | AMT supports IPv6 since ME 6.x |
| **VLAN** | ME can tag its traffic on a separate VLAN |
| **TLS** | Supports TLS but historically used weak ciphers; certificate management is opaque |

#### 2.3.3 AMT Capabilities

- **Power control**: Remote power on/off/reset/cycle regardless of host state
- **KVM over IP**: Full graphical console access (VGA redirection + keyboard/mouse injection)
- **IDE-R**: Boot from a remote ISO image — complete remote provisioning
- **Serial-over-LAN**: Text console redirection
- **Hardware inventory**: Read SMBIOS, CPU/mem/disk info without host OS
- **Event log**: PET (Platform Event Trap) alerts for hardware failures, thermal events, OS hang detection
- **User-based authorization**: Up to 200 local user accounts with role-based ACL

### 2.4 ME's Access to Host Memory: HECI Interface

#### 2.4.1 HECI (Host Embedded Controller Interface)

HECI is the primary communication channel between the host OS and the ME. It is implemented as a PCIe-like ring-buffer interface:

```
              Host Side (Ring 0 driver)                ME Side
         ┌──────────────────────┐              ┌──────────────────────┐
         │  mei driver          │              │  HECI daemon         │
         │  /dev/mei0           │              │  (MINIX process)     │
         └──────────┬───────────┘              └──────────┬───────────┘
                    │                                      │
         ┌──────────▼────────────────────────────────────▼───────────┐
         │                    HECI Hardware Registers                  │
         │  ┌─────────────────┐    ┌─────────────────────────┐      │
         │  │ CB (Host→ME)    │    │ HB (ME→Host)            │      │
         │  │ Circular Buffer │    │ Circular Buffer          │      │
         │  │ Head/Tail regs  │    │ Head/Tail regs           │      │
         │  └─────────────────┘    └─────────────────────────┘      │
         │  ┌─────────────────────────────────────────────────┐      │
         │  │ Interrupt status, depth, ME ready bits          │      │
         │  └─────────────────────────────────────────────────┘      │
         └────────────────────────────────────────────────────────────┘
```

- The host writes messages into the Host Control Buffer (CB); the ME reads them
- The ME writes responses into the Host Buffer (HB); the host reads them
- Each message has a fixed header with `length`, `client ID`, and `message type`
- The host driver (`mei`) creates `/dev/mei0` which user-space clients (like `amttool`) connect to

#### 2.4.2 HECI Clients

| Client ID | Name | Purpose |
|-----------|------|---------|
| 0 | HECI Bus Driver | Enumeration, version info |
| 1 | AMT Host Interface | AMT management commands |
| 2 | Watchdog | Hardware watchdog timer |
| 3 | MKHI (Manageability Kernel Host Interface) | Firmware update, capability queries |
| 4 | NVM / FTC | Flash configuration |
| 5 | PAVP | DRM / content protection |
| 7 | ESDM | Data at rest encryption |
| 8 | FTC | Factory test commands |
| 9 | fTPM | Firmware TPM 2.0 interface |

#### 2.4.3 DMA Access

Beyond HECI, the ME has **unrestricted DMA access** to the entire host physical address space:

- The ME's DMA engine can read/write any 64-bit physical address
- This includes RAM, MMIO regions, and even SMRAM (SMM memory) — meaning Ring -3 fully subverts Ring -2
- The ME can also generate SMIs via `PMC_SMDATA`/`PMC_SMMSG` PMC registers to invoke SMM handlers on the host CPU at will
- DMA is used internally for operations like:
  - KVM frame buffer capture (AMT)
  - IDE-R virtual media redirection  
  - TPM command/response buffers
  - Boot Guard policy enforcement (reading boot policy from flash and measuring/verifying the OS bootloader)

### 2.5 ME Versions and Processor Evolution

| ME Version | Processor Architecture | Platform | Notes |
|---|---|---|---|
| ME 1.x–4.x | **SPARC** (32-bit) | ICH8–ICH10 | First ME; minimal AMT |
| ME 5.x–7.x | **SPARC** (32-bit) | Ibex Peak–Cougar Point | AMT 5.0+; TPM added |
| ME 8.x–10.x | **SPARC** (32-bit) | Lynx Point–Sunrise Point | HECI expanded; Boot Guard |
| ME 11.x+ | **ARC** (32-bit, ARCompact) | Union Point (ME 11.0), Cannon Point (ME 11.8), Comet Point (ME 11.12) | MINIX-based; much larger codebase |
| **ME 12.x** | **ARC** (32-bit) | Lake Point (cancelled) | Never shipped commercially |
| ME 14.x+ | **ARC** (HS38) | Tiger Point / Alder Lake | Current generation; DAL improvements |

**Key transition (ME 10 → ME 11):** The move from SPARC to ARC (and from a custom microkernel to MINIX-3) represented a complete architecture overhaul. The ME 11+ firmware is significantly larger (~7 MB vs ~1.5 MB) and more complex, expanding the attack surface considerably.

### 2.6 ME Subsystems Deep Dive

#### 2.6.1 Intel Active Management Technology (AMT)

(Described in Section 2.3 above.)

#### 2.6.2 Intel vPro

vPro is Intel's umbrella brand for business-oriented manageability and security features. It **requires** a ME with AMT enabled. vPro features include:

- **Intel Standard Manageability (ISM)**: Subset of AMT for basic OOB management
- **Intel Standard Manageability Upgrade (ISUM)**: Upgrades ISM to full AMT via license key activation
- **Intel Trusted Execution Technology (TXT)**: Measured launch environment using TPM
- **Intel Virtualization for Directed I/O (VT-d)**: IOMMU for DMA protection
- **Intel Endpoint Security Assist**: Integration with EDR/AV products

#### 2.6.3 Intel One-Click Recovery

A ME subsystem that enables recovery of the OS image via remote provisioning. The ME can:

- Detect OS boot failure (watchdog timeout)
- Automatically download and mount a recovery image via AMT
- Redirect the host to boot from the recovery image (IDE-R)

This is an extremely powerful remote administration capability — it means the ME can **replace the host OS entirely** without physical access.

#### 2.6.4 DAL (Dynamic Application Loader) / ALEX

Introduced in ME 11.6+, DAL allows **runtime loading of signed Java applets** into the ME:

- Applets are signed with Intel's private key and loaded via HECI
- The DAL Java VM runs in a sandboxed MINIX process
- Used for: fTPM implementation, Secure Device Onboarding (SDO), and vendor-specific extensions
- Creates a new attack surface: the DAL Java runtime itself

```c
// DAL applet loading via HECI (simplified)
struct dal_applet_header {
    uint32_t magic;           // 0x44414C31 ("DAL1")
    uint32_t applet_size;
    uint8_t  rsa_signature[384]; // RSA-3072
    uint8_t  sha256_hash[32];    // SHA-256 of applet body
    // ... applet body follows
};
```

#### 2.6.5 Intel Boot Guard

Boot Guard is a ME subsystem that enforces **verified boot** at the hardware level:

1. On manufacturing, a **Boot Guard Key Manifest (BGKM)** is fused into the PCH eFuse array — this contains the OEM's public key hash
2. On every boot, the ME verifies the IBB (Initial Boot Block) of the BIOS using the OEM's key stored in the BGKM
3. If verification fails, the ME can force a halt or redirect to recovery
4. Once verified, the IBB measures the remaining BIOS and OS bootloader into TPM PCR0

Boot Guard is **immutable once fused**: it cannot be disabled by the end user, making it the ultimate enforcement of the boot chain.

---

## 3. Intel ME Vulnerabilities and CVEs

### 3.1 Overview

The Intel ME has been the subject of extensive security research since at least 2009, when the first detailed analysis was published. The ME's complexity (~7 MB of firmware in ME 11+), its MINIX-3 kernel, network stack, and multiple application layers create a massive attack surface. Below is a detailed analysis of the most significant vulnerabilities.

### 3.2 CVE-2017-5705 through CVE-2017-5715 (INSALEM / SKYFALL — Intel SA-00086)

**Intel Security Advisory SA-00086** (November 2017) was the most critical ME vulnerability disclosure in history. It revealed multiple privilege escalation and arbitrary code execution flaws.

#### CVE-2017-5705 — Arbitrary Code Execution in ME Kernel

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-5705 |
| **CVSS** | 9.8 (Critical) |
| **Component** | ME Kernel (MINIX-3 kernel) |
| **Affected** | ME 11.0–11.20, SPS 4.0, ISM 7.0–7.5 |
| **Type** | Buffer overflow → privilege escalation |
| **Impact** | Arbitrary code execution in ME kernel context |
| **Attack vector** | Network (AMT) or local (HECI) |

The vulnerability existed in the ME kernel's **IPC (Inter-Process Communication) handler**. A MINIX-3 message whose payload exceeded the expected size would overflow a kernel buffer, allowing an attacker to overwrite adjacent kernel memory and hijack control flow.

```c
// Simplified representation of the vulnerable IPC path
int me_ipc_handler(struct ipc_msg *msg) {
    struct ipc_buffer kbuf;
    // Vulnerable: no bounds check on msg->payload_len
    memcpy(&kbuf, msg->payload, msg->payload_len);  // OVERFLOW
    return dispatch_ipc(kbuf.sender, kbuf.receiver, kbuf.type);
}
```

**Exploitation**: An attacker who could send a message to the ME's IPC system (via AMT network interface or via HECI from a compromised host) could achieve **arbitrary code execution in the ME kernel (Ring -3)**, giving full control over:

- All ME application processes (AMT, fTPM, PAVP, etc.)
- DMA access to host memory
- The ability to persist across reboots (firmware modification)

#### CVE-2017-5706 — Privilege Escalation in ME Application

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-5706 |
| **CVSS** | 8.4 (High) |
| **Component** | ME Application (AMT) |
| **Affected** | ME 11.0–11.20 |
| **Type** | Privilege escalation (user-space → kernel) |
| **Impact** | ME kernel compromise from AMT process |

This allowed an AMT application-level vulnerability to escalate into a full ME kernel compromise, breaking the MINIX-3 process isolation boundary.

#### CVE-2017-5707 — Buffer Overflow in ME Kernel

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-5707 |
| **CVSS** | 9.8 (Critical) |
| **Component** | ME Kernel |
| **Affected** | ME 11.0–11.20, SPS 4.0 |
| **Type** | Heap buffer overflow |
| **Impact** | Arbitrary code execution in ME kernel |

A heap-based buffer overflow in the kernel memory allocator allowed an attacker to corrupt heap metadata and achieve arbitrary write primitives.

#### CVE-201201-5712 — Execution in AMT Web Interface

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-5712 |
| **CVSS** | 9.8 (Critical) |
| **Component** | AMT web server (lighttpd) |
| **Affected** | ME 11.x–12.x |
| **Type** | Remote code execution via AMT web interface |
| **Impact** | Full ME compromise from network |
| **Attack vector** | Network (TCP/16992 or TCP/16993) |

This was a **remotely exploitable** vulnerability in the AMT web server. An unauthenticated attacker on the local network (or via the internet if AMT ports were exposed) could craft an HTTP request that triggered a buffer overflow in the AMT lighttpd server, achieving remote code execution within the ME.

#### CVE-2017-5715 — Information Disclosure in ME

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-5715 |
| **CVSS** | 5.3 (Medium) |
| **Component** | ME firmware |
| **Affected** | ME 11.x |
| **Type** | Information disclosure |
| **Impact** | Disclosure of ME memory contents |

### 3.3 CVE-2017-12188 — JTAG Debug Access

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-12188 |
| **CVSS** | 7.5 (High) |
| **Component** | ME debug infrastructure |
| **Affected** | ME 11.x |
| **Type** | Design flaw — exposed JTAG |
| **Impact** | Full ME compromise via JTAG; read/write ME SRAM |

**Description**: Researchers (including Mark Ermolov and Maxim Goryachy from Positive Technologies) discovered that on certain Intel platforms, the **JTAG debug interface** to the ME processor was left enabled in production silicon. By connecting a JTAG debugger to the appropriate pins on the PCH (or using the DCI — Direct Connect Interface — over USB), an attacker with physical access could:

1. Halt the ME processor
2. Read/write all ME SRAM
3. Extract the ME firmware (bypassing SPI flash read protections)
4. Modify the ME's runtime state
5. Bypass Boot Guard key verification

This was particularly devastating because:
- JTAG access subverts all software-level protections
- It allows extraction of the ME firmware for offline analysis (enabling discovery of further vulnerabilities)
- On some platforms, the JTAG interface was accessible via a **USB** connection (DCI), requiring no specialized hardware

### 3.4 CVE-2019-0090 — Intel SA-00213

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2019-0090 |
| **CVSS** | 9.0 (Critical) |
| **Component** | ME / SPS (Server Platform Services) |
| **Affected** | ME 11.x–12.x, SPS 4.0+ |
| **Type** | Logic error enabling privilege escalation |
| **Impact** | Arbitrary code execution in ME context |

**Description**: This was a logic flaw in the ME's firmware update mechanism. The ME's signed firmware update process had a flaw that allowed an attacker with local access (via HECI) to **escalate privileges from a limited ME application to the ME kernel**. Combined with other ME vulnerabilities, this could lead to full ME compromise.

Intel's advisory SA-00213 indicated that the vulnerability could be exploited by "an unprivileged user" on the host system, meaning attack required only local code execution on the host (Ring 3 or Ring 0), not physical access.

### 3.5 CVE-2020-8758 — Intel SA-00318

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2020-8758 |
| **CVSS** | 7.5 (High) |
| **Component** | AMT / ISM web interface |
| **Affected** | ME 11.x–12.x, ISM 11.x–12.x |
| **Type** | Improper input validation in AMT web server |
| **Impact** | Denial of service or information disclosure via network |

**Description**: A network-adjacent attacker could exploit improper input validation in the AMT web server to cause a denial of service (crash the ME AMT process) or potentially disclose ME memory contents. While not achieving full RCE, this demonstrated continued weaknesses in the AMT web server component.

### 3.6 PSAncillary Attack

The **PSAncillary** attack was disclosed by researchers at Positive Technologies and represents a class of vulnerabilities in the ME's **ancillary data structures** used during firmware loading and module verification.

**Key findings**:

- The ME's firmware partition structure contains **ancillary headers** that describe module metadata (name, size, compression type, hash)
- In certain ME versions, these ancillary headers were processed **before** or **alongside** signature verification, creating a window for exploitation
- By manipulating ancillary header fields (particularly compression parameters), an attacker could trigger:
  - **Heap corruption** in the ME firmware loader
  - **Arbitrary memory reads** via crafted decompression parameters
  - **Bypass of module integrity checks** by substituting module hashes in the ancillary metadata

```c
// Simplified ancillary header structure
struct me_ancillary_header {
    uint8_t  module_name[8];     // e.g., "KERNEL  ", "AMT     "
    uint32_t compressed_size;    // Compressed size of module
    uint32_t decompressed_size;  // Decompressed size
    uint8_t  compression_type;   // 0=none, 1=LZMA, 2=LZ4
    uint8_t  sha256_hash[32];    // Expected SHA-256 of decompressed data
    uint8_t  rsa_sig[384];       // RSA-3072 signature
};
// Vulnerability: if compression_type is untrusted at
// decompression time, size mismatches cause heap overflow
```

The PSAncillary attack enables **firmware-level persistence**: an attacker who can modify the SPI flash (via a BIOS update vulnerability, for example) could inject a malicious module that exploits the ancillary parsing flaw to bypass signature verification and achieve code execution in the ME.

### 3.7 Additional ME CVEs

#### CVE-2017-3710 — Intel SA-00086 (Variant)

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2017-3710 |
| **CVSS** | 9.8 (Critical) |
| **Component** | ME Firmware |
| **Affected** | ME 8.x–10.x (6th Gen and earlier) |
| **Type** | Privilege escalation via buffer overflow |
| **Impact** | ME kernel compromise |

Affected older platforms (pre-ME 11). Demonstrated that the kernel-level vulnerability was not limited to the MINIX-3 rewrite but also existed in the SPARC-based ME.

#### CVE-2018-3640 — ME Information Disclosure (Variant of L1TF)

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2018-3640 (part of L1 Terminal Fault — L1TF) |
| **CVSS** | 7.5 (High) |
| **Component** | ME speculative execution |
| **Affected** | ME 11.x+ |
| **Type** | Side-channel information disclosure |
| **Impact** | ME SRAM content leak via L1TF |

The L1 Terminal Fault (Foreshadow) vulnerability also affected the ME processor. Because the ME ARC processor has an L1 data cache, a malicious host process could use the L1TF technique to read ME SRAM contents, potentially extracting:

- fTPM keys
- AMT credentials
- EPID private keys

#### CVE-2019-11091 — Intel SA-00270 (Microarchitectural Data Sampling — MDS)

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2019-11091 |
| **CVSS** | 6.5 (Medium) |
| **Component** | ME / SPS speculative execution |
| **Affected** | ME 11.x, SPS 4.0+ |
| **Type** | Microarchitectural Data Sampling (MDS) |
| **Impact** | Potential ME SRAM data leak |

Part of the MDS/ZombieLoad family of speculative execution vulnerabilities. The ME's ARC processor was vulnerable to data sampling attacks, potentially leaking ME-internal data to the host.

#### CVE-2020-0555 — Intel SA-00320 (ME Q3 2020)

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2020-0555 |
| **CVSS** | 7.1 (High) |
| **Component** | ME kernel |
| **Affected** | ME 11.8+ |
| **Type** | Improper isolation in ME kernel IPC |
| **Impact** | Privilege escalation from ME application to kernel |

Another MINIX-3 kernel IPC vulnerability allowing an ME application to break out of its process isolation and gain kernel-level access.

#### CVE-2021-0089 — Intel SA-00528

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2021-0089 |
| **CVSS** | 7.5 (High) |
| **Component** | ME firmware update mechanism |
| **Affected** | Multiple ME versions |
| **Type** | Improper firmware update validation |
| **Impact** | Potential arbitrary code execution via firmware update |

A logic flaw in how the ME validated firmware update payloads. An attacker could craft a firmware update that passed signature checks but exploited a parsing vulnerability during the update roll-out process.

#### CVE-2022-26075 — Intel SA-00622

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2022-26075 |
| **CVSS** | 8.4 (High) |
| **Component** | ME kernel |
| **Affected** | ME 11.x–15.x |
| **Type** | Privilege escalation |
| **Impact** | ME kernel compromise from application context |

Demonstrated that kernel-level privilege escalation remained possible years after SA-00086.

### 3.8 Summary of Key ME CVEs

| CVE | Year | CVSS | Component | Type | Impact |
|-----|------|------|-----------|------|--------|
| CVE-2017-5705 | 2017 | 9.8 | ME Kernel (IPC) | Buffer overflow | RCE in ME kernel |
| CVE-2017-5706 | 2017 | 8.4 | ME AMT app | Privilege escalation | ME kernel compromise |
| CVE-2017-5707 | 2017 | 9.8 | ME Kernel (heap) | Heap overflow | RCE in ME kernel |
| CVE-2017-5712 | 2017 | 9.8 | AMT web server | Remote RCE | Network RCE in ME |
| CVE-2017-5715 | 2017 | 5.3 | ME firmware | Info disclosure | ME memory leak |
| CVE-2017-3710 | 2017 | 9.8 | ME Kernel (8-10) | Buffer overflow | RCE in ME kernel |
| CVE-2017-12188 | 2017 | 7.5 | ME JTAG debug | Design flaw | Full ME compromise |
| CVE-2018-3640 | 2018 | 7.5 | ME L1 (speculative) | Side channel | ME SRAM data leak |
| CVE-2019-0090 | 2019 | 9.0 | ME update logic | Privilege escalation | ME kernel compromise |
| CVE-2019-11091 | 2019 | 6.5 | ME speculative | MDS side channel | ME data leak |
| CVE-2020-8758 | 2020 | 7.5 | AMT web server | Input validation | DoS / info disclosure |
| CVE-2020-0555 | 2020 | 7.1 | ME kernel IPC | Isolation bypass | Privilege escalation |
| CVE-2021-0089 | 2021 | 7.5 | ME firmware update | Update validation | Potential RCE |
| CVE-2022-26075 | 2022 | 8.4 | ME kernel | Privilege escalation | ME kernel compromise |

---

## 4. AMD Platform Security Processor (PSP)

### 4.1 PSP Architecture

AMD's equivalent to the Intel ME is the **Platform Security Processor (PSP)**, integrated into all AMD processors since the Steamroller microarchitecture (2013). Key characteristics:

- **Processor**: ARM Cortex-A5 (32-bit ARMv7-A)
- **Operating system**: Custom RTOS (not MINIX; AMD's proprietary firmware)
- **Location**: Embedded within the CPU die (not in a separate chipset)
- **Always-on**: Activates before the x86 cores and remains active during all power states
- **Firmware**: Stored in a dedicated region of the SPI flash (similar to Intel ME region)
- **SRAM**: Small dedicated SRAM (~256 KB–1 MB depending on generation)
- **Cryptographic capabilities**: Hardware-accelerated AES, SHA, RSA, ECC

```
┌──────────────────────────────────────────────────────────────┐
│                      AMD SoC Die                            │
│                                                              │
│  ┌────────────────────┐     ┌───────────────────────────┐   │
│  │  x86-64 Cores      │     │  PSP (ARM Cortex-A5)       │   │
│  │  (Zen 2/3/4)       │     │  ┌─────────────────────┐  │   │
│  │                    │     │  │  Custom RTOS         │  │   │
│  │  ┌──┐  ┌──┐       │     │  │  Apps: fTPM, SEV,   │  │   │
│  │  │C0│  │C1│  ...  │     │  │       SMU, DRTM      │  │   │
│  │  └──┘  └──┘       │     │  └─────────────────────┘  │   │
│  └────────────────────┘     │  ┌─────────────────────┐  │   │
│         ▲                    │  │  PSP SRAM           │  │   │
│         │ CCx / Mailbox      │  └─────────────────────┘  │   │
│         │                    │  ┌─────────────────────┐  │   │
│  ┌──────┴───────────┐       │  │  Crypto Engine      │  │   │
│  │  Host RAM (DDR4)  │◄──────┤  │  (AES/SHA/RSA/ECC) │  │   │
│  └──────────────────┘  DMA  │  └─────────────────────┘  │   │
│                              └───────────────────────────┘   │
│                                                              │
│  ┌────────────────────┐                                      │
│  │  SPI Flash          │                                      │
│  │  ┌────┐┌────┐      │                                      │
│  │  │BIOS││PSP │      │                                      │
│  │  │    ││FW  │      │                                      │
│  │  └────┘└────┘      │                                      │
│  └────────────────────┘                                      │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 PSP Firmware and Role

The PSP firmware is organized into several components:

| Component | Description |
|-----------|-------------|
| **PSP Boot Loader (PBL)** | First-stage loader from boot ROM; verifies and loads the PSP OS |
| **PSP OS** | Custom ARM RTOS kernel |
| **fTPM** | Firmware TPM 2.0 implementation |
| **SEV** | Secure Encrypted Virtualization (see 4.4) |
| **SMU** | System Management Unit — power management, fuse control |
| **DRTM** | Dynamic Root of Trust for Measurement (AMD SKINIT) |
| **CCx Mailbox** | Communication interface between PSP and x86 cores |
| **Validated Boot** | Enforces secure boot chain (analogous to Intel Boot Guard) |

The PSP's primary roles:

1. **Secure boot enforcement**: Verifies BIOS/UEFI integrity before x86 cores exit reset
2. **TPM functionality**: Implements fTPM for measured boot and key storage
3. **SEV key management**: Manages encryption keys for virtual machines (see 4.4)
4. **Hardware fuse management**: Reads and manages eFuses for security policy enforcement
5. **DRTM**: Provides SKINIT instruction support for establishing a measured launch environment

### 4.3 PSP Communication

Unlike Intel's HECI, the PSP communicates with the host via:

- **CCx Mailbox**: Register-based interface for control messages
- **SMN (System Management Network)**: PSP's internal bus for accessing system resources
- **DMA**: The PSP has DMA access to host memory (like Intel ME)
- **BIOS Mailbox**: Communication during early boot (before OS)

```c
// Simplified PSP mailbox communication (from Linux kernel)
#define PSP_MAILBOX_COMMAND    0x10580  /* CMD register */
#define PSP_MAILBOX_BUFFER     0x10584  /* Buffer address register */

struct psp_mailbox {
    uint32_t cmd;        // Command code
    uint32_t status;     // Response status
    uint32_t *buffer;   // Shared memory buffer in host RAM
    uint32_t buf_len;   // Buffer length
};

// Send command to PSP
int psp_send_command(uint32_t cmd, void *data, size_t len) {
    write_register(PSP_MAILBOX_BUFFER, virt_to_phys(data));
    write_register(PSP_MAILBOX_COMMAND, cmd | PSP_CMD_RESPONSE_BIT);
    // Wait for PSP to process...
}
```

### 4.4 AMD SEV (Secure Encrypted Virtualization)

AMD SEV is one of the most important PSP-driven security features. It uses the PSP's AES engine to encrypt VM memory with a unique key per VM, protecting guest memory from the hypervisor.

#### SEV Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Hypervisor (Ring 0)                     │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │  VM 1    │  │  VM 2    │  │  VM 3    │                  │
│  │ Encr.Key │  │ Encr.Key │  │ Encr.Key │                  │
│  │  = ASID1 │  │  = ASID2 │  │  = ASID3 │                  │
│  │  (per-VM │  │  (per-VM │  │  (per-VM │                  │
│  │   key)   │  │   key)   │  │   key)   │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│                                                              │
│          ▲ Encryption/Decryption by AES engine in PSP       │
│          │ Key selected by ASID (Address Space ID)           │
│  ┌───────┴──────────────────────────────────────────────┐   │
│  │  Memory Controller with AES-128 Engine               │   │
│  │  (Transparent encryption/decryption per-VM)         │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

#### SEV Versions

| Version | Key Size | Integrity | Attestation | Notes |
|---------|----------|-----------|-------------|-------|
| **SEV** | AES-128 | None | EPID-based | Original; no integrity protection |
| **SEV-ES** | AES-128 | Register state encryption | EPID-based | Encrypts guest register state on world-switch |
| **SEV-SNP** | AES-128 | Full (MAC + replay protection) | Versioned CAs | Strongest; prevents VM replay attacks |

**Critical observation**: The PSP holds all SEV encryption keys. This means a PSP compromise would allow an attacker to **decrypt any SEV-encrypted VM**, completely undermining the security guarantee.

### 4.5 PSP Vulnerabilities

#### CVE-2019-1548 — AMD PSP fTPM Information Disclosure

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2019-1548 |
| **CVSS** | 7.5 (High) |
| **Component** | PSP fTPM |
| **Affected** | AMD EPYC, Ryzen, Threadripper (multiple generations) |
| **Type** | Information disclosure in fTPM implementation |
| **Impact** | Potential extraction of fTPM keys and attestation data |

The PSP's fTPM implementation had a vulnerability where certain TPM commands could be manipulated to leak internal PSP state, potentially disclosing key material or allowing TPM state rollback.

#### CVE-2020-8909 — AMD PSP SMM Call-Out Vulnerability

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2020-8909 |
| **CVSS** | 7.5 (High) |
| **Component** | PSP → SMM call-out |
| **Affected** | Multiple AMD platforms |
| **Type** | Logic flaw in PSP-SMM interaction |
| **Impact** | Potential SMM code execution from PSP |

A vulnerability in how the PSP could invoke SMI handlers on the host processor, potentially allowing the PSP (or an attacker who compromised the PSP) to inject malicious SMI handlers.

#### CTS Labs / AMD Flaws (2018)

In March 2018, CTS-Labs disclosed a set of AMD PSP vulnerabilities with dramatic names:

| Name | Description | Severity |
|------|-------------|----------|
| **RYZENFALL** | PSP kernel-level vulnerability enabling arbitrary code execution; DMA attack on host memory | Critical |
| **FALLOUT** | PSP boot ROM vulnerability enabling persistent firmware modification | Critical |
| **CHIMERA** | Backdoor-like functionality in AMD PCIe chipset (not PSP, but related) | High |
| **MASTERKEY** | Vulnerability in AMD secure boot (PSP validated boot) | High |

**Critical note on CTS-Labs disclosure**: The CTS-Labs report was controversial because it was published with **only 24 hours' notice** to AMD (violating responsible disclosure norms) and was released alongside a short-stock-position report, raising questions about financial motivation. However, subsequent independent research confirmed some of the underlying vulnerabilities.

#### AMD SEV Vulnerabilities

| CVE | Year | Name | Type | Impact |
|-----|------|------|------|--------|
| CVE-2021-46162 | 2021 | — | SEV attestation bypass | Fake attestation reports |
| CVE-2022-22194 | 2022 | — | SEV key management | Potential key extraction |
| Multiple | 2018-2022 | — | SEV/SEV-ES integrity attacks | VM memory tampering (pre-SNP) |
| N/A | 2020 | SEVered | SEV page table manipulation | Decrypt VM memory via ASID manipulation |

**SEVered Attack (2018)**: Researchers demonstrated that by manipulating the ASID (Address Space ID) assigned to a VM, a malicious hypervisor could cause the memory controller to decrypt a victim VM's memory using a key from a different VM (or no key at all), effectively breaking SEV's confidentiality guarantee. This was a fundamental design weakness addressed in SEV-SNP.

### 4.6 PSP vs. ME Comparison

| Aspect | Intel ME | AMD PSP |
|--------|----------|---------|
| **Processor** | ARC (ME 11+) / SPARC (earlier) | ARM Cortex-A5 |
| **OS** | MINIX-3 (ME 11+) | Custom proprietary RTOS |
| **Firmware Size** | ~7 MB (ME 11+) | ~512 KB–1 MB |
| **Network Stack** | Full TCP/IP + AMT web server | No network stack (design choice) |
| **DMA** | Full DMA to host memory | Limited DMA (SEV key operations) |
| **Boot Document** | Signed ME firmware region in SPI flash | Signed PSP firmware region in SPI flash |
| **Debug Access** | JTAG / DCI (CVE-2017-12188) | JTAG on debug parts only |
| **Remote Manage** | Yes (AMT/vPro) | No |
| **Source Visibility** | Partially reverse-engineered | Partially reverse-engineered |
| **Open Source Efforts** | me_cleaner, HEADS | None significant |

**Key difference**: The PSP has **no network stack**, which significantly reduces the attack surface compared to Intel ME. There is no AMD equivalent of AMT's network-facing web server.

---

## 5. ME/PSP Attack Surface

### 5.1 Attack Surface Overview

```
                    ┌─────────────────────────────────┐
                    │        Intel ME / AMD PSP       │
                    │                                 │
  NETWORK ─────────┤  AMT Web Interface (ME only)    │
                    │  (TCP/16992-16993)              │
                    │                                 │
  USB/DCI ─────────┤  JTAG / Debug Interface          │
                    │                                 │
  HOST ────────────┤  HECI / CCx Mailbox              │
  (Ring 0/3)       │  (driver interface)              │
                    │                                 │
  FIRMWARE ────────┤  SPI Flash Partition             │
  (update mechs)   │  (signed ME/PSP region)         │
                    │                                 │
  VENDOR ──────────┤  OEM Extensions / DAL Applets    │
                    │  (ME only)                      │
                    │                                 │
  PHYSICAL ────────┤  DMA / Bus Access                │
                    │                                 │
                    └─────────────────────────────────┘
```

### 5.2 Network-Facing: AMT Web Interface (Intel ME Only)

This is the **most exposed** attack surface and is unique to Intel ME:

| Vector | Detail |
|--------|--------|
| **Protocol** | HTTPS on TCP/16992 (HTTP) and TCP/16993 (HTTPS) |
| **Authentication** | Digest auth, Kerberos, or default credentials |
| **Software** | Custom lighttpd web server within ME |
| **Attack surface** | HTTP parser, TLS stack, authentication logic, WS-Man/SOAP parser |
| **Default credentials** | Often `admin` / `$admin` or blank in enterprise deployments |
| **Remotely reachable** | Yes — AMT is designed for OOB management over the network |

**Notable attacks through AMT**:

- **CVE-2017-5712**: RCE via crafted HTTP request to AMT web interface
- **CVE-2020-8758**: DoS/info disclosure via AMT web interface
- **Silent Bob is Silent (2017)**: Researchers demonstrated that default AMT credentials were present on millions of enterprise laptops, enabling complete remote takeover
- **AMT privilege escalation**: Web interface allows IDE-R (virtual media), which effectively grants the attacker the ability to boot any OS image

### 5.3 HECI / CCx Mailbox Interface (Host-Facing)

The host-facing interface allows Ring 0 (and sometimes Ring 3, via the `mei` driver) to communicate with the ME/PSP:

| Vector | Detail |
|--------|--------|
| **Interface** | `/dev/mei0` (Linux) or MEI driver (Windows) |
| **Protocol** | HECI message protocol with client IDs and typed messages |
| **Access** | Ring 0 (kernel) always; Ring 3 (user) via driver |
| **Attack surface** | HECI message parsers, firmware update commands, TPM command processing |

**Notable attacks**:

- **Local privilege escalation**: Compromised host OS (Ring 0) can send crafted HECI messages to exploit ME application vulnerabilities
- **Firmware update downgrade**: Malformed HECI firmware update commands (CVE-2019-0090)
- **Information disclosure**: HECI version queries can leak ME firmware version, build date, and capabilities
- **MEI driver attack surface**: The Linux `mei` driver itself has had vulnerabilities (CVE-2019-0121) that could allow local privilege escalation

### 5.4 JTAG Debug Access

| Vector | Detail |
|--------|--------|
| **Interface** | JTAG (IEEE 1149.1) / Intel DCI (USB-based debug) |
| **Access** | Physical (pin access on PCH) or USB (DCI class) |
| **Attack surface** | ME/PSP SRAM read/write, register access, breakpoint control |
| **Impact** | Complete firmware extraction, real-time ME state manipulation |

**CVE-2017-12188** demonstrated that JTAG was left enabled on production Intel silicon. For AMD PSP, JTAG access is only available on special debug-ordered parts, but physical modification can potentially bridge fuses.

**Typical JTAG attack flow**:

1. Identify JTAG pins on PCH die or board (TRST, TCK, TMS, TDI, TDO)
2. Connect JTAG debugger (e.g., Segger J-Link, Intel ITP)
3. Halt ME processor
4. Dump ME SRAM (full firmware extraction)
5. Set breakpoints on RSA signature verification
6. Patch firmware or skip verification
7. Resume execution with modified state

For **DCI (Intel) over USB**:

```
# Enable DCI on supported platforms (requires BIOS access)
# Write to DCI enable register in PCH PMC
setpci -s 00:1f.2 0x84.l=0x00000002

# Connect via OpenOCD with Intel DCI configuration
openocd -f interface/dci.cfg -f target/arc_em.cfg
```

### 5.5 Firmware Update Mechanism

The ME/PSP firmware update mechanism is a critical attack surface:

| Vector | Detail |
|--------|--------|
| **Interface** | BIOS/UEFI capsule update or OS-level ME update tool |
| **Verification** | RSA-3072 signature (Intel) or RSA-2048 (AMD) |
| **Delivery** | SPI flash write via BIOS update path |
| **Attack surface** | Signature verification logic, decompression, ancillary parsing |

**Attack scenarios**:

1. **Rollback attack**: Downgrade ME firmware to a version with known vulnerabilities
2. **evil maiden / supply chain**: Replace SPI flash chip with one containing modified ME firmware
3. **Flash descriptor manipulation**: Modify the Intel Flash Descriptor to change ME region permissions
4. **PSAncillary** (see Section 3.6): Exploit ancillary header parsing during firmware update
5. **Signature bypass**: Find flaws in the RSA signature verification code

```c
// Typical ME firmware update flow
int me_update_firmware(struct me_update_image *img) {
    // Step 1: Verify RSA-3072 signature
    if (!verify_rsa_signature(img->signature, img->data, img->data_len)) {
        return UPDATE_ERROR_INVALID_SIGNATURE;
    }
    // Step 2: Verify SHA-256 hash
    if (!verify_sha256(img->hash, img->data, img->data_len)) {
        return UPDATE_ERROR_INVALID_HASH;
    }
    // Step 3: Decompress (VULNERABILITY: size mismatch → heap overflow)
    void *buf = malloc(img->decompressed_size);  // From ancillary header
    decompress(img->data, img->compressed_size, buf, img->decompressed_size);
    // Step 4: Write to SPI flash ME region
    spi_write(ME_FLASH_OFFSET, buf, img->decompressed_size);
    // Step 5: Reset ME
    me_reset();
    return UPDATE_SUCCESS;
}
```

### 5.6 Vendor-Specific Extensions

Intel ME (and to a lesser extent AMD PSP) supports vendor-specific extensions that increase the attack surface:

| Extension | ME Only? | Risk |
|-----------|----------|------|
| **DAL applets** (Java) | Yes | Runtime code loading → new code execution path |
| **OEM-specific modules** | Both | Custom code in ME/PSP context → limited review |
| **Intel SDO** (Secure Device Onboarding) | Yes | Network provisioning → network attack surface |
| **Intel IPT** (Identity Protection Technology) | Yes | OTP generation → key material exposure risk |
| **Intel PAVP** (Protected Audio/Video Path) | Yes | DRM code → complex crypto/Media path |
| **Lenovo ThinkShield** | Yes | OEM DAL applet for remote management |

**DAL (Dynamic Application Loader)** is particularly notable because it allows **runtime loading of signed Java applets** into the ME. While each applet is signed, the DAL Java VM itself is an attack surface (JVM exploitation is well-understood), and each applet increases the ME's attack surface.

---

## 6. Disabling/Limiting ME

### 6.1 The me_cleaner Project

**me_cleaner** (by Nicola Corna, https://github.com/corna/me_cleaner) is the most well-known tool for reducing ME firmware to a minimal functional set. It operates by:

1. **Parsing the ME firmware** from the SPI flash image
2. **Identifying and removing unnecessary ME modules** (AMT, PAVP, MDES, etc.)
3. **Keeping only the essential modules** required for platform stability:
   - `RBE` (Root Boot Extension) — required for ME initialization
   - `KERNEL` — MINIX kernel (required for module loading)
   - `BUP` (Bring-Up) — hardware init
   - `PMC` (Power Management Controller) — required for power state transitions
4. **Patching the ME firmware partition table** to remove references to deleted modules
5. **Setting the `me_disable` bit** (see 6.2)

**Usage**:

```bash
# Extract ME region from SPI flash dump
ifdtool -x firmware.bin
# Result: flashregion_2_me.bin

# Clean the ME firmware (remove non-essential modules)
me_cleaner.py -r -t -O cleaned_me.bin flashregion_2_me.bin

# Reassemble and flash
# (platform-specific; requires external programmer or BIOS update hack)
```

**What me_cleaner removes**:

| Removed Module | Function | Impact of Removal |
|----------------|----------|-------------------|
| AMT | Remote management | No remote management |
| PAVP | Audio/video DRM | No HDCP/DRM playback |
| MDES | Manageability | No remote monitoring |
| FTCM | Factory test | — |
| DAL | Dynamic app loader | No fTPM, no SDO |
| LT | Intel LAN tools | — |
| LME | Local management | — |
| iAMT | Integrated AMT | — |
| TELEMETRY | Telemetry reporting | — |

**What me_cleaner keeps**:

| Kept Module | Why Required |
|------------|--------------|
| RBE | ME will not boot without it; triggers platform reset if missing |
| BUP | Hardware bring-up; required for power management |
| KERNEL | Module loader; required even for reduced ME |
| PMC | Power management; required for S3/S4/S5 transitions |

**Result**: ME firmware size is reduced from ~7 MB to ~300 KB–1 MB, dramatically reducing the attack surface.

### 6.2 The `me_disable` Bit

The Intel Flash Descriptor contains a **`me_disable`** bit that signals the ME to halt after initialization:

```
┌─────────────────────────────────────────────────────────────┐
│ Intel Flash Descriptor (IFD) Structure                      │
│                                                              │
│  Offset 0x00:  Flash Descriptor Master Section              │
│    ...                                                       │
│  Offset 0x0C:  ME Disable bit                                │
│    Bit 0:  ME Disable (0 = ME enabled, 1 = ME disabled)     │
│    Bits 1-7: Reserved                                       │
│                                                              │
│  NOTE: On many consumer platforms, setting me_disable does   │
│  NOT actually disable the ME. It merely causes the ME to    │
│  report "ME Disabled" to the host via HECI while continuing │
│  to run in the background.                                  │
└─────────────────────────────────────────────────────────────┘
```

**Critical caveat**: On most consumer platforms, setting `me_disable = 1` does **NOT** actually halt the ME. Instead:

- The ME continues to run normally
- The HECI reports "ME is disabled" to the host
- The AMT web interface may still be partially accessible
- Only on certain **corporate/government** platforms (with HAP support, see 6.3) does `me_disable` actually stop the ME

This means that **merely setting `me_disable` is insufficient for security** — it provides a false sense of security.

### 6.3 HAP Bit (High Assurance Platform)

The **High Assurance Platform (HAP)** program is a US government initiative that requires Intel to provide a mechanism to **truly disable** the ME on classified/networks. The HAP bit is an eFuse that, when set, causes the ME to:

1. Complete hardware initialization
2. Perform power management setup (required for the host to boot)
3. **Halt its ARC/SPARC processor** — the ME goes into a permanent sleep state
4. Report "HAP mode" via HECI status

```c
// HAP bit detection (from coreboot)
// In ME firmware's FPT (Flash Partition Table)
struct me_fpt_entry {
    uint8_t  name[4];          // e.g., "NFTP", "FTPR"
    uint8_t  type;
    uint8_t  subtype;
    uint32_t offset;
    uint32_t length;
    uint8_t  reserved[3];
    uint8_t  flags;
};

// If HAP bit is set, ME enters minimal mode:
// 1. Boot ROM executes
// 2. BUP (Bring-Up) module loads and runs
// 3. PM (Power Management) initializes
// 4. ME processor HALTs
// 5. Host can boot normally
// 6. No AMT, no fTPM, no DAL, no remote management
```

**HAP status by platform**:

| Platform Generation | HAP Support | Notes |
|---|---|---|
| ME 1.x–7.x | No | No HAP mechanism |
| ME 8.x–10.x | Partial | HAP bit exists but may not fully halt ME |
| ME 11.x–12.x | Yes | HAP bit fully halts ME after BUP |
| ME 14.x+ | Yes | HAP supported; confirmed functional |

**How to set the HAP bit**:

```bash
# Check if HAP is supported (from SPI flash dump)
# Look in the ME FTPR partition for HAP marker
# 
# me_cleaner can set HAP:
me_cleaner.py -H cleaned_me.bin flashregion_2_me.bin

# Alternatively, manual HAP setting:
# In the ME firmware, find the BUP module and set the HAP flag
# (Platform-specific; consult me_cleaner source for details)
```

### 6.4 What Functionality is Lost When ME is Disabled

| Functionality | ME Active | ME Disabled (HAP/me_cleaner) | Impact |
|---|---|---|---|
| **Remote management (AMT/vPro)** | Yes | No | No OOB management; requires physical access |
| **fTPM** | Yes | No | No TPM 2.0; must use discrete TPM (dTPM) |
| **Intel Boot Guard** | Yes | Partial (may still be active via fused BGKM) | Boot verification may enforce but cannot update policy |
| **Intel PAVP / HDCP** | Yes | No | No protected audio/video; DRM content may fail |
| **ME firmware updates** | Yes | No | Cannot update ME firmware via OS |
| **Power management (S3/S5)** | Yes | Varies (may break on some platforms) | Resume from suspend may fail |
| **Clock calibration (ICC)** | Yes | No | May cause clock drift on some platforms |
| **Intel TXT (DRTM)** | Yes | No | No measured launch environment |
| **Intel EPID** | Yes | No | No remote attestation |
| **IDE-R / SoL** | Yes | No | No virtual media or serial-over-LAN |
| **Watchdog** | Yes | No | No hardware watchdog for OS hang detection |
| **USB selective suspend** | Yes | Varies | May affect USB power management |
| **System stability** | Yes | Varies | Some platforms are unstable with ME disabled |

### 6.5 Likely Side Effects and Risks of ME Disabling

1. **Platform instability**: Some laptops (particularly ThinkPads and Dell Latitudes) may fail to resume from S3 sleep or experience random freezes when the ME is disabled.

2. **Boot Guard enforcement**: On platforms where Boot Guard is fused (BGKM written to eFuses), disabling the ME via software may not prevent Boot Guard from enforcing verified boot. The ME's role in the boot verification chain may be replaced by hardware-anchored checks.

3. **Thermal management**: The ME participates in thermal management on some platforms. Disabling it may cause unpredictable fan behavior or thermal throttling.

4. **Firmware update compatibility**: After me_cleaner modifies the ME region, subsequent BIOS/UEFI updates from the OEM will fail (because the ME region signature no longer matches). Users must either:
   - Skip ME region updates manually
   - Re-apply me_cleaner after each BIOS update
   - Use coreboot (which bypasses the issue entirely)

5. **Legal/warranty**: OEMs may void warranties for platforms with modified ME firmware. Enterprise management tools may flag the platform as "non-compliant."

### 6.6 Alternative Approaches

| Approach | Description | Effectiveness |
|----------|-------------|---------------|
| **coreboot** | Open-source BIOS replacement that can be configured without ME modules | High — if hardware supports it |
| **HEADS** | coreboot + measured boot + TPM (uses dTPM instead of fTPM) | High — but requires dTPM |
| **me_cleaner + coreboot** | Combine ME cleaning with coreboot | Highest practical security |
| **Intel HAP** | Official HAP-ordered platforms from Dell/HP/Lenovo | High — but limited availability |
| **Neutralize** (Skochinsky) | Script that replaces ME modules with NOPs | Medium — less tested than me_cleaner |
| **Hardware modification** | Desolder SPI flash and replace with clean image | High — but risk of bricking |

### 6.7 Detection of ME State

```bash
# Check ME status on Linux
cat /sys/class/mei/mei0/firmware_version   # ME firmware version
cat /sys/class/mei/mei0/protocols          # Supported HECI clients

# Check if ME is in "disabled" or "HAP" mode
dmesg | grep -i mei
# Look for: "ME is disabled" (may be false positive — me_disable bit)
# Look for: "ME: HAP mode" (authentic HAP)

# Check Intel Flash Descriptor for ME region info
ifdtool -d firmware_dump.bin

# Using intelmetool (from coreboot)
intelmetool -m   # Show ME mode
intelmetool -s   # Show ME status
```

---

## 7. References

1. Positive Technologies, "Intel Management Engine: Drive Me Crazy" (2017) — [link to PT research on MINIX-3 in ME]
2. Intel Security Advisory SA-00086 (November 2017) — CVE-2017-5705 through CVE-2017-5715
3. Intel Security Advisory SA-00213 (March 2019) — CVE-2019-0090
4. Intel Security Advisory SA-00318 (June 2020) — CVE-2020-8758
5. Ermolov, M., Goryachy, M. — "How to Hack a Turned-Off Computer, or Running Unsigned Code in Intel Management Engine" (Black Hat Europe 2017)
6. CTS Labs, "AMD Flaws: RYZENFALL, FALLOUT, CHIMERA, MASTERKEY" (March 2018)
7. me_cleaner project — https://github.com/corna/me_cleaner
8. Skochinsky, N. — "Intel ME Secrets" (REcon 2014)
9. AMD SEV Specification — AMD Developer Documentation
10. Bulygin, Y., Samyde, D. — "Ring -3: The Hypervisor Nobody Talked About" (2011)
11. SevVered Attack Paper — "SevVered: Decrypting SEV Encrypted VMs" (2018)
12. Intel 64 and IA-32 Architectures Software Developer's Manual — Chapter on System Management Mode
13. coreboot project — https://www.coreboot.org/
14. Dulau-Narevsky, B. — "PSAncillary: A New Attack Surface in Intel ME" (2018)
15. Moghimi, D. et al. — "Take A Way: Exploring the Security Implications of AMD's Cache Way Predictors" (2020)

---

*Document version: 2025-04-26 | Author: Security Research Report | Classification: Technical Reference*