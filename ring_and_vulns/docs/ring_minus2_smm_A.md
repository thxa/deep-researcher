# Ring -2: System Management Mode (SMM) — A Deep Technical Analysis

> *The most privileged execution mode on x86 platforms. More privileged than Ring 0 (kernel), more privileged than Ring -1 (hypervisor/VMM). There is no higher_RING._

---

## Table of Contents

1. [What is Ring -2?](#1-what-is-ring--2)
2. [SMM Architecture](#2-smm-architecture)
3. [SMM Vulnerabilities and CVEs](#3-smm-vulnerabilities-and-cves)
4. [SMM Attack Techniques](#4-smm-attack-techniques)
5. [Tools for SMM Research](#5-tools-for-smm-research)
6. [SMRR (System Management Range Register)](#6-smrr-system-management-range-register)
7. [References](#7-references)

---

## 1. What is Ring -2?

### 1.1 Definition and Concept

**Ring -2** is a colloquial term in the information security community referring to **System Management Mode (SMM)**, a catch-all execution mode on x86 processors that operates at a privilege level *above* everything else on the system. The numbering convention extends the x86 protection ring model downward:

| Ring | Mode | Description |
|------|------|-------------|
| Ring 3 | User Mode | Applications, least privileged |
| Ring 2 | OS Services | Rarely used in modern OS |
| Ring 1 | OS Services | Rarely used in modern OS |
| Ring 0 | Kernel Mode | Operating system kernel |
| Ring -1 | Hypervisor | Virtual Machine Monitor (VT-x/VT-d) |
| **Ring -2** | **SMM** | **System Management Mode — firmware-level** |

The "negative ring" concept highlights a critical reality: SMM code runs at a privilege level that is **completely invisible to and uncontrollable by the operating system and hypervisor**. No kernel data structure, no hypervisor intercept, no OS-level security mechanism can observe, constrain, or_interrupt SMM execution.

### 1.2 Historical Context

SMM was introduced with the **Intel 386SL** processor in 1990, initially designed for power management in laptops (hence "SL" for "SL Enhanced"). The original purpose was straightforward:

- Implement **APM (Advanced Power Management)** functionality
- Handle **sleep/standby/suspend** states
- Emulate **hardware devices** (e.g., IDE controllers on early laptops)
- Manage **thermal throttling** and battery events

Over time, SMM's role expanded dramatically. Modern SMM handlers implement:

- **UEFI firmware services** (variable storage, capsule updates)
- **ACPI** SMI handlers (sleep state transitions)
- **Hardware error handling** (MCE/MCA)
- **USB legacy emulation** (keyboard support during boot)
- **OEM-specific proprietary functionality** (management engines, remote access)
- **Secure firmware update** mechanisms
- **TPM-related** measured boot operations

This expansion transformed SMM from a simple power-management facility into a sprawling, complex, privileged execution environment — one that has accumulated a correspondingly large attack surface.

### 1.3 Why Ring -2 Matters for Security

SMM's security implications are severe and unique:

1. **Total invisibility**: The OS cannot detect SMM execution. CPU state is saved to SMRAM, and upon `RSM`, execution resumes exactly where it left off. No OS bookkeeping records the SMM interlude.
2. **Total control**: SMM code has unrestricted access to all system memory, including kernel and hypervisor address spaces. It can modify any data structure, inject code, or exfiltrate secrets.
3. **No OS-level mitigation applies**: SMEP, SMAP, NX, ASLR, kASLR, KPTI — none of these apply inside SMM. SMM has its own flat 4GB address space.
4. **Persistence**: SMM code lives in firmware (SPI flash). It survives OS reinstallation, disk replacement, and even BIOS resets (unless the SPI flash is reprogrammed).
5. **Immutable by OS**: The operating system cannot disable SMM, filter SMIs, or inspect SMRAM content (when SMRR is properly configured). SMI delivery is a hardware mechanism outside OS control.
6. **Supply chain trust**: SMM code is provided by the firmware vendor (AMI, Insyde, Phoenix) and OEM (Lenovo, Dell, HP), often closed-source and unauditable.

A single SMM vulnerability gives an attacker **the most privileged persistent foothold possible** on an x86 system — a foothold that no software-only defense can remove.

---

## 2. SMM Architecture

### 2.1 SMI Triggering Mechanism

#### 2.1.1 Hardware-Generated SMIs

SMIs are triggered asynchronously by hardware events. The processor's `SMI#` pin (or equivalent message-signaled interrupt on modern platforms) is asserted, and the CPU:

1. Finishes the current instruction (or reaches a特定 boundary).
2. Saves the entire CPU state to SMRAM (at `SMBASE + 0x8000` for the default state save area, or `SMBASE + 0xFE00` after relocation).
3. Begins execution at `SMBASE + 0x8000` in SMM.

Hardware SMI sources include:

| Source | Description |
|--------|-------------|
| ACPI Power Events | Sleep button, lid closure, thermal events |
| Chipset Events | Hardware error reporting, GPIO transitions |
| Timer-based SMIs | Firmware-configured periodic SMIs |
| LPC/ISA Devices | Legacy device activity requiring firmware emulation |
| Platform-specific | OEM-defined SMI sources via GPIO/PCH |

#### 2.1.2 Software-Generated SMIs (Port 0xB2)

Software can trigger an SMI by writing to **I/O port 0xB2** (the standard ACPI SMI command port). This is the primary mechanism for the OS or ACPI firmware to request SMM services:

```c
// Trigger SMI from OS/ACPI context
// Port 0xB2 = SMI command port
// Port 0xB3 = SMI data port (often used for parameter passing)

outb(0xB2, smi_command);   // Triggers SMI with command code
outb(0xB3, data_byte);    // Optional data parameter
```

On modern systems, the ACPI DSDT defines `_SI` methods that write to port 0xB2 to transition between sleep states. The SMI handler in firmware decodes the command value and performs the requested operation.

Other software SMI ports sometimes used:

- `0x84` — Used on some Intel platforms for periodic SMI generation
- Vendor-specific I/O ports — Some OEMs define additional SMI trigger ports

**Important**: The OS has no way to prevent software SMIs from being delivered. Any code that can perform I/O port writes (including Ring 0 drivers, and in some cases Ring 3 with `iopl` set) can trigger SMI.

### 2.2 SMRAM (System Management RAM)

SMRAM is a **physically protected memory region** that holds the SMM code and data, plus the CPU state save area during SMM execution.

#### 2.2.1 SMRAM Structure

Default SMRAM layout (before SMBASE relocation):

```
SMBASE + 0x00000 ──────────────────────────
                                             │
          SMM Code Segment                   │
          (handler code, data)               │ ~128KB (default)
                                             │
SMBASE + 0x08000 ────────────────────────── │
          SMM Entry Point                    │
          (first instruction executed)       │
                                             │
SMBASE + 0x0FE00 ───────────────────────── │
          CPU State Save Area                │
          (32KB state save map)              │
                                             │
SMBASE + 0x0FFFF ──────────────────────────
                                             │
          Stack (grows downward)             │
SMBASE - 1 ─────────────────────────────────
```

After SMBASE relocation, each CPU core can have its own `SMBASE`, creating per-core SMRAM regions. The state save area starts at `SMBASE + 0xFE00` and the entry point at `SMBASE + 0x8000`.

#### 2.2.2 SMRAM Size and Location

On modern systems:

- **TSEG (Top of Segment)**: SMRAM is allocated from the top of physical memory below 4GB, reported to the OS as reserved in the BIOS e820 memory map. Typical sizes range from 1MB to 64MB depending on firmware configuration.
- **ASEG (Auxiliary Segment)**: The legacy 128KB region at physical address `0xA0000–0xBFFFF` (often the default SMBASE on boot).
- **HSEG (High Segment)**: An optional second SMRAM window at `0xFEE00000` on some chipsets.

The memory controller (MCH/IMC) provides **hardware-based SMRAM locking**:

- **D_LCK bit**: Once set, the SMRAM base/mask registers become read-only until the next power cycle. This prevents OS or firmware from altering SMRAM geometry after initialization.
- **D_CLS (D_CLOSE) bit**: When set, SMRAM is only accessible when the CPU is in SMM. Attempts to access SMRAM from non-SMM mode return `0xFF` reads and writes are dropped — the memory is completely inaccessible.

#### 2.2.3 SMRAM Access Control

```
┌──────────────────────────────────────────────────────────────┐
│                    Physical Memory Map                        │
│                                                               │
│  0x0000_0000  ┌──────────────────┐                           │
│               │  Conventional RAM  │                          │
│               │                    │                          │
│  ┌────────── ─┤                    │                          │
│  │ ASEG       │ (SMRAM window     │ ◄── 0xA0000–0xBFFFF     │
│  │ (0xA0000)  │  when in SMM)     │     inaccessible        │
│  └────────────┤                    │     from non-SMM       │
│               │                    │                          │
│               └──────────────────┘                           │
│                                                               │
│  TSEG_BASE   ┌──────────────────┐                           │
│  (variable)  │  TSEG SMRAM       │ ◄── Protected by SMRR   │
│               │  (1–64 MB)        │     and D_LCK/D_CLS     │
│               │                    │                          │
│               │  - SMM handlers   │     Not visible to OS   │
│               │  - SMM stack      │                          │
│               │  - SMM data        │                          │
│               │  - State saves     │                          │
│               └──────────────────┘                           │
│  TSEG_BASE +                                                  │
│  TSEG_SIZE                                                    │
│                                                               │
│  0xFFFF_FFFF ┌──────────────────┐                            │
│              │  MMIO / ROM       │                           │
│              └──────────────────┘                            │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 SMBASE Relocation

On power-on or reset, all CPU cores share the **default SMBASE** of `0x30000` (on Intel; `0xA0000` on some AMD platforms). This creates a problem: if multiple cores enter SMM simultaneously, they would all use the same stack and state save area, causing corruption.

**SMBASE relocation** solves this. Upon first SMI entry, the firmware:

1. Enters SMM at the default `SMBASE + 0x8000`.
2. Reads the current CPU's APIC ID from the state save area.
3. Calculates a unique `SMBASE` for this CPU.
4. Writes the new `SMBASE` into the state save area at offset `0xFEFC` (in 32-bit mode) or `0xFF00` (in 64-bit mode, per the Intel SDM).
5. On `RSM`, the CPU reads the new `SMBASE` from the state save area and uses it for all subsequent SMI entries.

```c
// Pseudocode for SMBASE relocation in SMM handler
// State Save Area layout (relevant fields):
//   Offset 0xFEFC (32-bit): New SMBASE value (RSM reads this)
//   Offset 0xFF44: SMM Revision ID
//   Offset 0xFF48: SMBASE (current, read-only during SMM)

UINT32 new_smbase = TSEG_BASE + (apic_id * SMBASE_STRIDE);
state_save->SMBASE = new_smbase;  // Write to offset 0xFEFC
// On RSM, CPU will use new_smbase for future SMI entries
```

The **SMRR (System Management Range Register)** — discussed in detail in Section 6 — must be configured to cover the relocated SMRAM regions. If SMBASE relocation points to memory outside SMRR-protected range, the SMM handler code becomes accessible from non-SMM mode, which is catastrophic.

### 2.4 SMM Entry and Exit

#### 2.4.1 SMM Entry Sequence

When an SMI is delivered, the processor performs the following atomically:

```
1.  CPU finishes current instruction / reaches SMI delivery boundary
2.  CPU saves state to SMRAM at (SMBASE + 0xFE00):
      - All general-purpose registers
      - All segment registers (including hidden parts)
      - RIP, RSP, RFLAGS
      - CR0, CR3, CR4 (shadow copies)
      - EFER MSR
      - APIC ID
      - SMM Revision ID
3.  CPU sets internal SMM flag
4.  CPU enters a flat 32-bit or 64-bit real-mode-like state:
      - CS selector  = SMBASE >> 4
      - CS base      = SMBASE
      - CS limit     = 0xFFFFFFFF
      - EIP          = SMBASE + 0x8000
      - SS selector  = SMBASE >> 4 + 8
      - SS base      = SMBASE
      - SS limit     = 0xFFFFFFFF
5.  CPU disables:
      - Interrupts (IF cleared)
      - NMI (NMI mask set)
      - Debug exceptions (TF and RF cleared in RFLAGS)
      - Trace (LBR frozen)
      - VMX operation (if active, exits VMX non-root mode)
      - LBR and BTS (frozen)
6.  Execution begins at SMBASE + 0x8000
```

The initial SMM environment is extremely privileged:

- **Paging is OFF** (CR0.PG = 0 in 32-bit mode; for 64-bit SMM, paging is enabled with SMM-specific page tables)
- **No segmentation enforces limits** (flat 4GB+ address space)
- **No SMEP/SMAP** (these don't apply in SMM)
- **All I/O ports accessible** (IOPL effectively 0 with no permission restrictions inside SMM)
- **SMRAM is accessible** (D_CLS is de-asserted when in SMM)

#### 2.4.2 SMM State Save Map

Critical fields in the Intel state save map (offsets for 64-bit SMM):

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x0000 | 128 | Reserved | |
| 0x0080 | 8 | GDT base | |
| 0x0088 | 4 | GDT limit | |
| 0x0090 | 8 | IDT base | |
| 0x0098 | 4 | IDT limit | |
| 0x0100 | 8 | RAX | |
| ... | ... | Other GPRs | |
| 0x01F8 | 8 | CR0 | |
| 0x0200 | 8 | CR3 | |
| 0x0208 | 8 | CR4 | |
| 0x0268 | 8 | RIP | Pre-SMI instruction pointer |
| 0x0278 | 8 | RSP | Pre-SMI stack pointer |
| 0x0288 | 8 | RFLAGS | |
| 0x0FE00 | 128 | FPU/MMX state | In 32-bit mode |
| 0xFF00 | 8 | SMBASE (new) | Written by handler for relocation |
| 0xFF04 | 4 | SMM Revision ID | |

The SMM handler can read and modify every saved register, meaning it can **alter the CPU state before returning to non-SMM mode**. This includes changing `RIP` (redirecting execution), modifying `CR3` (swapping page tables), or altering `RFLAGS`.

#### 2.4.3 SMM Exit — RSM Instruction

The `RSM` (Resume) instruction is the **only way to exit SMM** (short of reset). Its behavior:

```
1.  CPU performs a consistency check on the state save area
2.  CPU restores all registers from SMRAM
3.  CPU clears the internal SMM flag
4.  CPU re-enables SMRAM protection (SMRAM becomes inaccessible
    from non-SMM mode)
5.  If SMBASE was modified in state save area, CPU updates
    internal SMBASE register
6.  CPU resumes execution at the restored RIP
```

There is no `RSM` instruction equivalent for non-SMM code. `RSM` can only execute in SMM, and the processor will generate a `#UD` (undefined opcode) exception if attempted outside SMM.

**Important**: If the SMM handler needs to return an error or signal a condition, it modifies registers in the state save area before executing `RSM`. The OS has no canonical mechanism to detect that an SMM intervention occurred — the only clues are lost CPU cycles and possible side effects in hardware state.

### 2.5 What Code Runs in SMM

SMM is not a single monolithic handler. Modern firmware implements a full **dispatch architecture** within SMM:

#### 2.5.1 UEFI SMM Foundation

The **PI (Platform Initialization) Specification** by the UEFI Forum defines the SMM infrastructure:

```
┌─────────────────────────────────────────────┐
│            SMM Dispatcher                    │
│  (Routes SMIs to registered handlers)       │
├─────────────────────────────────────────────┤
│            SMM Core                          │
│  (Memory services, protocol installation)   │
├─────────────────────────────────────────────┤
│            SMM Foundation                    │
│  (Minimum environment, RSM handler)          │
├─────────────────────────────────────────────┤
│            Hardware (CPU/chipset SMI)       │
└─────────────────────────────────────────────┘
```

Key SMM modules in a typical firmware:

| Module | Purpose |
|--------|---------|
| **SmmCore** | SMM memory allocation, protocol management |
| **SmmDispatcher** | SMI handler registration and dispatch |
| **PiSmmCpuDxeSmm** | CPU state save, SMBASE relocation, SMRR config |
| **SmmVariable** | UEFI variable read/write services in SMM |
| **SmmFaultTolerantWrite** | Fault-tolerant write to NV storage |
| **SmmFirmwareVolumeBlock** | SPI flash access from SMM |
| **SmmPowerButton** | ACPI power button SMI handler |
| **SmmSleep** | Sleep/wake SMI handler |
| **SmmUsbKb** | USB keyboard legacy emulation SMI |
| **SmmCpuHotPlug** | CPU hot-add/hot-remove SMI handler |
| **SmmPeriodicTimer** | Periodic SMI timer handlers |
| **OEM proprietary modules** | Vendor-specific functionality |

#### 2.5.2 ACPI SMI Handlers

The ACPI subsystem uses SMIs for sleep-state transitions:

```asl
// Example: DSDT method triggering SMI for sleep transition
Method (_PTS, 1, NotSerialized)  // Prepare To Sleep
{
    // Write sleep type to SMI data port
    Store (Arg0, \_SB.PCI0.SMI0.DATA)
    // Trigger SMI
    Store (0x01, \_SB.PCI0.SMI0.CMD)
}
```

When the OS writes a sleep type to port `0xB3` and then an SMI command to port `0xB2`, the SMM sleep handler validates the transition, reconfigures hardware for the target sleep state, and executes the transition.

#### 2.5.3 OEM Code and Proprietary Modules

This is where the most security-critical and problematic code resides:

- **Lenovo**: ThinkPad System Update SMM modules, BIOS password handling, WMI interface SMI handlers
- **Dell**: Dell Client Management SMM modules, Express Flash, TPM command relay
- **HP**: HP Sure Start SMM modules, System BIOS SMI handlers, HP ProtectTools
- **AMI**: AMITSE (Setup) SMM module, Aptio SMM core

These modules are almost always **closed-source**, **opaque**, and produced under NDA. Security researchers must reverse-engineer them to assess their security posture.

---

## 3. SMM Vulnerabilities and CVEs

SMM vulnerabilities are particularly consequential. A compromise of SMM implies:

- **Complete system takeover** (more privileged than kernel or hypervisor)
- **Persistence across OS reinstalls** (firmware-resident code)
- **Invisibility to all OS-level security tools** (no monitoring inside SMM)

Below is an extensive catalog of notable SMM-related CVEs.

### 3.1 Intel AMT/ME/SMM Bugs (CVE-2017-5701 through CVE-2017-5715)

In January 2018, Intel disclosed a cluster of firmware vulnerabilities tracked as **SA-00086** affecting Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT) — but notably also affecting **SMM**:

| CVE | Component | Severity | Description |
|-----|-----------|----------|-------------|
| **CVE-2017-5701** | Intel ME Firmware | Critical | Multiple buffer overflows in Intel ME firmware enabling remote code execution in ME/SMM context |
| **CVE-2017-5702** | Intel ME Firmware | Critical | Privilege escalation in Intel ME allowing local escalation to SMM |
| **CVE-2017-5703** | Intel ME Firmware | Critical | Intel ME failure to properly restrict debug features, enabling SMM access |
| **CVE-2017-5704** | Intel AMT | High | Intel AMT buffer overflow enabling network-based code execution |
| **CVE-2017-5705** | Intel AMT/ME | High | Improper input validation in Intel AMT firmware |
| **CVE-2017-5706** | Intel Server Platform | High | SMM vulnerability in Intel Xeon server firmware allowing escalation to SMM |
| **CVE-2017-5707** | Intel ME | High | Integer overflow in Intel ME firmware |
| **CVE-2017-5708** | Intel AMT | High | Denial of service via Intel AMT web interface |
| **CVE-2017-5709** | Intel SPS | High | Intel Server Platform Services firmware vulnerability |
| **CVE-2017-5710** | Intel SMM | Critical | SMM callout vulnerability allowing Ring 0 code to execute arbitrary SMM code |
| **CVE-2017-5711** | Intel ME | High | Intel ME improper isolation of firmware modules |
| **CVE-2017-5712** | Intel ME | High | Buffer overflow in Intel ME network services |
| **CVE-2017-5713** | Intel ME | High | Improper privilege management in Intel ME |
| **CVE-2017-5714** | Intel SPS | High | Intel Server Platform Services vulnerability enabling SMM access |
| **CVE-2017-5715** | Intel CPU | High | Bounds check bypass (related to Spectre/Meltdown chain, affecting SMM-side speculation) |

**Key insight**: CVE-2017-5710 is particularly notable — it was an SMM callout vulnerability where SMM code would dereference pointers provided by the OS, enabling an attacker to trick SMM into executing attacker-controlled code at Ring -2 privilege.

### 3.2 EDK II SMM Vulnerabilities (CVE-2021-3816, CVE-2021-3818)

The **EDK II (EFI Development Kit II)** is the open-source reference implementation of the UEFI PI specification. It contains the SMM infrastructure used by most firmware vendors. In 2021, two significant vulnerabilities were disclosed:

#### CVE-2021-3816 — SMI Handler Callout in Variable Service

```
Vulnerability:  SMM variable service callout
Affected:       Edk2 SmmVariable module
Impact:         arbitrary code execution in SMM
CVSS:           8.2 (High)
```

The `SmmVariable` module did not sufficiently validate that pointers passed to `GetVariable()`, `SetVariable()`, and `NextVariableName()` resided within SMRAM. An attacker with Ring 0 access could craft a pointer to attacker-controlled memory outside SMRAM, causing the SMM handler to:

1. Read attacker-controlled data as if it were a variable name
2. Write SMM-internal data to an attacker-controlled address
3. Corrupt SMRAM by following attacker-controlled pointer chains

This is a classic **SMM callout vulnerability** (see Section 4.1).

#### CVE-2021-3818 — SMM Communication Buffer Overflow

```
Vulnerability:  Buffer overflow in SMM communication handler
Affected:       Edk2 PiSmmCommunicationSmm
Impact:         SMM code execution, SMRAM corruption
CVSS:           7.9 (High)
```

The SMM communication buffer (used by `EFI_SMM_COMMUNICATION_PROTOCOL`) did not validate that the communication buffer resided within SMRAM and did not check buffer bounds. An attacker could:

1. Place a crafted communication buffer outside SMRAM
2. Overflow the SMM handler's stack via an oversized payload
3. Achieve arbitrary code execution within SMM

### 3.3 CVE-2022-0002 — Intel SMM Local Privilege Escalation

```
CVE:            CVE-2022-0002
Vulnerability:  Bounds Check Bypass in SMM (Spectre-class)
Affected:       Intel processors with SMM (multiple families)
Impact:         Local privilege escalation from Ring 0 to Ring -2
CVSS:           6.7 (Medium)
```

This vulnerability is a **Spectre-variant (Bounds Check Bypass)** applicable to SMM code. The attack:

1. An attacker primes the branch predictor from Ring 0
2. SMM code takes a mispredicted branch that dereferences an attacker-influenced address
2. Speculative execution within SMM leaks SMRAM contents via a side channel
3. The attacker recovers SMRAM data from the side channel (e.g., cache timing)

While Spectre-type attacks yield speculative-only leakage (no architectural SMM code execution), they can reveal:
- SMM handler addresses (defeating SMRR-based hiding)
- SMRAM content (including SMM code and data)
- SMRR configuration values

This information can be used to facilitate deterministic SMM callout or buffer overflow attacks.

Intel's guidance (INTEL-SA-00598) recommended firmware updates and mitigations similar to other Spectre variants (retpoline, etc.).

### 3.4 Chipsec-Discovered SMM Bugs

The **Chipsec** framework (see Section 5.1) has been instrumental in discovering SMM vulnerabilities. Notable findings:

| Module | Issue | Description |
|--------|-------|-------------|
| `SmiHandler` callout | Pointer validation | SMM handlers dereference untrusted Ring 0 pointers |
| `SmmVariable` | Buffer overflow | Variable service allows oversized data writes |
| `SmmCreateTable` | SMRAM corruption | ACPI table creation in SMM uses OS-provided data |
| `SmmMemoryCheck` | SMRAM check bypass | Insufficient validation of communication buffers |
| `SmmCpuHotPlug` | Memory corruption | Race condition in CPU hot-plug SMI handler |
| `Flash Protect` | Lock bypass | SPI flash protection not properly locked before OS boot |
| `SMRAM Lock` | SMRAM exposure | D_LCK not set, allowing OS to modify SMRAM configuration |

Chipsec tests that commonly find SMM issues:

```
chipsec.modules.common.smm      - Generic SMM code integrity
chipsec.modules.common.smrr     - SMRR configuration check
chipsec.modules.common.smram    - SMRAM lock check
chipsec.modules.common.smm_callout - SMI handler callout check
chipsec.modules.common.bios     - BIOS write protection
chipsec.modules.common.spi      - SPI flash lock check
```

### 3.5 OEM-Specific SMM CVEs

#### 3.5.1 Lenovo SMM CVEs

| CVE | Severity | Description |
|-----|----------|-------------|
| **CVE-2019-6170** | High | Buffer overflow in Lenovo SMM driver for ThinkPad systems; enables SMM code execution |
| **CVE-2019-6171** | High | Improper input validation in Lenovo ThinkPad SMM module; allows SMM privilege escalation |
| **CVE-2020-4467** | High | Stack-based buffer overflow in Lenovo SMM driver for certain ThinkPad models |
| **CVE-2021-3929** | High | SMM callout in Lenovo firmware; SMI handler dereferences OS-controlled pointer |
| **CVE-2022-33068** | High | Lenovo SMM driver vulnerability enabling arbitrary SMM code execution from Ring 0 |
| **CVE-2023-3423** | High | Potential SMM privilege escalation in Lenovo Notebook BIOS |

#### 3.5.2 Dell SMM CVEs

| CVE | Severity | Description |
|-----|----------|-------------|
| **CVE-2021-21551** | High | Dell dbutil_2_3.sys driver improper memory access, potentially enabling SMM interaction from Ring 3 |
| **CVE-2021-21552** | Medium | Dell Platform Security vulnerability affecting SMM handler |
| **CVE-2022-24415** | High | Dell SMM firmware vulnerability; improper access control allows Ring 0 to SMM escalation |
| **CVE-2022-24416** | High | Dell BIOS SMM callout; insufficient parameter validation in SMM handler |
| **CVE-2022-26900** | High | Race condition in Dell SMM driver enabling SMM code execution |
| **CVE-2023-28024** | Medium | Dell SMM variable service improper validation |

#### 3.5.3 HP SMM CVEs

| CVE | Severity | Description |
|-----|----------|-------------|
| **CVE-2021-39238** | High | HP SMM driver buffer overflow; allows SMM privilege escalation |
| **CVE-2022-23927** | High | Potential SMM escalation in HP PC BIOS firmware |
| **CVE-2022-23930** | High | Improper SMM memory operations in HP firmware |
| **CVE-2023-0623** | High | HP SMM code execution vulnerability |
| **CVE-2023-28135** | High | Buffer overflow in HP SMM driver enabling SMM code execution |

### 3.6 Additional Notable SMM CVEs

| CVE | Severity | Affected | Description |
|-----|----------|----------|-------------|
| **CVE-2020-0549** | Medium | Intel CPU | L1D cache evict (special register) side channel leaking SMM data (CrossTalk) |
| **CVE-2020-0543** | Medium | Intel CPU | Special Register Buffer Data Sampling (SRBDS) affecting SMM |
| **CVE-2020-10713** | High | Multiple (GRUB) | BootHole: Secure Boot bypass enabling attacker-controlled code before SMM lock |
| **CVE-2021-4183** | High | Insyde | SMM callout vulnerability in Insyde H2O firmware |
| **CVE-2022-29265** | High | AMI | SMM stack overflow in AMI Aptio firmware SMM module |
| **CVE-2022-33102** | High | Dell | Memory corruption in Dell SMM firmware |
| **CVE-2022-34347** | High | AMI | SMM callout in AMI BIOS firmware |
| **CVE-2023-22642** | High | Insyde | SMM callout in Insyde H2O System Firmware |
| **CVE-2023-38160** | High | AMI | Potential SMM privilege escalation in AMI Aptio |
| **CVE-2024-24961** | High | EDK II | SMM heap overflow in MdeModulePkg SmmMemoryAllocationProfile |

### 3.7 Summary: 15 Most Notable SMM CVEs

| # | CVE | Type | Impact |
|---|-----|------|--------|
| 1 | CVE-2017-5710 | SMM Callout | Ring 0 → Ring -2 code execution |
| 2 | CVE-2021-3816 | SMM Callout (EDK II) | SMM variable service pointer dereference |
| 3 | CVE-2021-3818 | Buffer Overflow (EDK II) | SMM communication buffer overflow |
| 4 | CVE-2022-0002 | Spectre-class | Speculative SMM data leakage |
| 5 | CVE-2019-6170 | Buffer Overflow (Lenovo) | Stack overflow in Lenovo SMM driver |
| 6 | CVE-2021-3929 | SMM Callout (Lenovo) | OS pointer dereference in SMM |
| 7 | CVE-2022-24415 | Access Control (Dell) | Ring 0 → Ring -2 escalation |
| 8 | CVE-2021-39238 | Buffer Overflow (HP) | SMM privilege escalation |
| 9 | CVE-2024-24961 | Heap Overflow (EDK II) | MdeModulePkg SmmMemoryAllocationProfile |
| 10 | CVE-2022-34347 | SMM Callout (AMI) | Pointer validation bypass in SMM |
| 11 | CVE-2020-0549 | Side Channel (Intel) | CrossTalk / Special Register leak |
| 12 | CVE-2022-33068 | SMM Callout (Lenovo) | Arbitrary SMM code execution |
| 13 | CVE-2023-22642 | SMM Callout (Insyde) | OS-controlled pointer in SMM handler |
| 14 | CVE-2023-38160 | Privilege Escalation (AMI) | SMM privilege escalation in Aptio |
| 15 | CVE-2020-10713 | Secure Boot Bypass | BootHole — enables pre-SMM-lock attack |

---

## 4. SMM Attack Techniques

### 4.1 SMM Callout Vulnerabilities

SMM callout is the **most common and most impactful class of SMM vulnerability**. It occurs when SMM code dereferences a pointer that is controlled by code outside SMRAM (typically Ring 0, but sometimes Ring 3).

#### 4.1.1 The Callout Pattern

The canonical callout:

```c
// Vulnerable SMM handler pattern
EFI_STATUS EFIAPI SmmVariableHandler(
    EFI_HANDLE  DispatchHandle,
    const void *Context,
    EFI_SMM_SW_CONTEXT *SwContext,   // ← OS-provided communication buffer
    void        *CommBuffer,          // ← Pointer to OS-controlled memory
    UINTN       *CommBufferSize
)
{
    EFI_SMM_VARIABLE_COMM_HEADER *Header;

    // VULNERABLE: CommBuffer is outside SMRAM but not validated
    Header = (EFI_SMM_VARIABLE_COMM_HEADER *)CommBuffer;

    // VULNERABLE: Dereferences OS-controlled pointer without SMRAM check
    // Attack: Set Header->VariableName to point outside SMRAM
    //         or use it to corrupt SMM state
    Status = GetVariable(
        Header->VariableName,     // ← OS-controlled pointer!
        &Header->Guid,
        &DataSize,
        DataBuffer
    );

    return Status;
}
```

A secure implementation must:

1. **Validate that all pointers point into SMRAM** using `SmmIsBufferOutsideSmmValid()` or equivalent
2. **Validate buffer sizes** to prevent overflows
3. **Never trust any data outside SMRAM**

#### 4.1.2 Exploiting SMM Callout

The exploitation steps:

```
Step 1: Identify an SMI handler that accepts untrusted pointers
Step 2: From Ring 0, prepare a communication buffer outside SMRAM
Step 3: Trigger the SMI (e.g., write to port 0xB2)
Step 4: SMM handler reads the communication buffer
Step 5: SMM handler dereferences attacker-controlled pointers
Step 6: Attainer controls SMM execution flow
```

The result is **arbitrary code execution in SMM** — Ring -2 compromise. This can be used to:

- Modify SMRAM-resident data (e.g., secure boot keys)
- Redirect SMM handlers to attacker-controlled code
- Install persistent firmware-level implants

#### 4.1.3 The `SmmIsBufferOutsideSmmValid()` Check

EDK II provides a function to validate pointers:

```c
BOOLEAN
SmmIsBufferOutsideSmmValid (
    IN EFI_PHYSICAL_ADDRESS  Buffer,
    IN UINT64                 Length
)
{
    // Returns TRUE if Buffer..Buffer+Length does NOT overlap with SMRAM
    // SMM handlers should REJECT buffers where this returns FALSE
    // (i.e., reject anything NOT safely outside SMRAM)
}
```

**Common mistakes**:
- Not calling this function at all (classic callout)
- Calling it but with incorrect length calculations
- Calling it only on the header but not on nested pointers
- TOCTOU: checking before copying data, but the OS can modify the communication buffer between check and use

### 4.2 SMRAM Cache Poisoning

#### 4.2.1 The Attack Concept

SMRAM cache poisoning exploits the **cache hierarchy** to manipulate SMRAM content without directly accessing SMRAM from non-SMM mode.

When the CPU is in non-SMM mode, SMRAM is inaccessible (D_CLS is active). However, the CPU cache may still contain stale data from the SMRAM region — and cache coherency protocols can be exploited to modify this data.

#### 4.2.2 Attack Steps

```
Prerequisites: Ring 0 access, knowledge of SMRAM physical address range

1.  Configure a memory type range register (MTRR) or page table entry
    to mark the SMRAM region as Write-Back (WB) cacheable from non-SMM context

2.  Create a self-modifying code scenario:
    a.  Fill a cache line at a physical address mapped to SMRAM
    b.  Use cache eviction to place this data into SMRAM
    c.  The SMRAM content is now corrupted with attacker data

3.  When SMM executes next:
    a.  SMM code reads from the cache line
    b.  SMM code executes attacker-controlled data
    c.  Ring -2 compromise achieved

4.  On some older platforms:
    a.  The SMRR does not prevent cache fills from non-SMM mode
    b.  By creating aliases (virtual → physical mappings) to the
        SMRAM physical range, the OS can populate cache lines that
        the SMM handler will later execute
```

#### 4.2.3 Mitigation

Modern Intel processors implement:
- **SMRR-based cache enforcement**: When SMRR is active, non-SMM cache fills to SMRAM are blocked
- **Cache flushing on SMM entry/exit**: The SMM handler flushes the cache to ensure no stale data persists
- **SMRAM memory type enforcement**: SMRAM is always mapped as Write-Back, and conflicting MTRR settings are prevented

However, **incorrect SMRR configuration** (see Section 6) can bypass these mitigations.

### 4.3 SMM Variable Service Attacks

#### 4.3.1 UEFI Variable Services in SMM

UEFI runtime variable services (`GetVariable`, `SetVariable`, `GetNextVariableName`) are often implemented in SMM to protect the variable store from Ring 0 tampering. The attack surface:

```
┌───────────────────────────────────────┐
│  Ring 3: Application                   │
│    ↕ EFI Runtime Services              │
├───────────────────────────────────────┤
│  Ring 0: OS Kernel                     │
│    ↕ EFI_SMM_COMMUNICATION_PROTOCOL   │
├───────────────────────────────────────┤
│  Ring -2: SMM Variable Handler         │
│    - SmmGetVariable()                   │
│    - SmmSetVariable()                   │
│    - SmmGetNextVariableName()           │
│    - Communicates via shared buffer     │
└───────────────────────────────────────┘
```

#### 4.3.2 Attack Vectors

1. **Communication Buffer Pointer Injection**: The OS provides a communication buffer pointer. If the SMM handler does not validate that this buffer is outside SMRAM (paradoxically, "safely outside"), an attacker can point it into SMRAM to leak or corrupt SMM data.

2. **Variable Name Overflow**: If `GetNextVariableName()` does not validate that the output buffer is large enough, it can overflow into adjacent SMRAM data.

3. **Variable Data Overflow**: If `SetVariable()` does not enforce size limits on data, the variable store can overflow into adjacent SMRAM.

4. **TOCTOU on Variable Operations**: The OS can modify the communication buffer after the SMM handler reads the header but before it processes the data.

```c
// TOCTOU example:
// SMM handler reads CommBuffer->VariableName (pointer to OS memory)
// OS changes CommBuffer->VariableName after SMM reads it
// SMM uses stale pointer → callout

// Time-of-Check-to-Time-of-Use:
T1: SMM reads header from CommBuffer ( validates → OK, points to Buffer A)
T2: OS modifies CommBuffer header (now points to Buffer B inside SMRAM)
T3: SMM follows the pointer → dereferences SMRAM address → corrupted
```

### 4.4 TSEG (Top of Segment) Bypass

#### 4.4.1 What is TSEG?

TSEG is the primary SMRAM region on modern Intel platforms. It sits at the top of physical memory (below 4GB) and is protected by:

- **D_LCK** (DRAM lock bit): Locks the TSEG configuration
- **D_CLS** (DRAM close bit): Makes SMRAM inaccessible outside SMM
- **SMRR**: CPU-level SMRAM protection (see Section 6)

#### 4.4.2 TSEG Bypass Techniques

**Technique 1: TSEG Size Manipulation**

Some firmware exposes TSEG size configuration through setup variables:

```
1.  Modify BIOS setup variable to change TSEG size
2.  Reboot
3.  New TSEG configuration leaves old SMRAM content accessible
    in the now-non-SMRAM region
4.  Read SMRAM content from OS
```

**Technique 2: PCI MMIO Hole Overlap**

```
1.  Program a PCI MMIO BAR to overlap with the TSEG physical range
2.  Memory controller routes accesses through PCI instead of DRAM
3.  MMIO configuration space provides a window into TSEG
4.  Read/modify SMRAM content
```

**Technique 3: DMA Attack on TSEG**

```
1.  Use a DMA-capable device (Thunderbolt, PCIe) to access TSEG
2.  DMA operations are not subject to SMRR/CPU protections
3.  DMA can read and write SMRAM content directly
    (unless IOMMU/VT-d is properly configured)
```

**Technique 4: SMM Handler TSEG Base Disclosure**

If the SMM handler accidentally leaks its own base address (e.g., through a variable service or error message), the attacker gains knowledge of TSEG location, enabling targeted cache-poisoning or TSEG overlap attacks.

### 4.5 DMA Attacks Against SMM

#### 4.5.1 Direct Memory Access and SMRAM

DMA allows peripheral devices to read and write system memory **bypassing the CPU entirely**. Critically, SMRR and `D_CLS` protections only apply to **CPU-initiated** memory accesses. DMA transactions from PCI/PCIe devices:

- **Do not pass through SMRR checks** (SMRR is a CPU MSR)
- **Are not blocked by D_CLS** (D_CLS is a memory controller/CPU feature)
- **Bypass all CPU privilege checks**

This means that without proper IOMMU (VT-d) configuration, any DMA-capable device can freely read and write SMRAM.

#### 4.5.2 Attack Vectors

| Vector | Description | Severity |
|--------|-------------|----------|
| **Thunderbolt/USB4 DMA** | Thunderbolt allows external devices DMA access to system memory, including SMRAM | Critical |
| **PCIe Hot-Plug** | PCIe device hot-plug can initiate DMA before IOMMU is configured | High |
| **Malicious PCIe Card** | Insider threat: PCIe card with malicious firmware initiates DMA to SMRAM | High |
| **Network Card DMA** | Compromised NIC firmware can read/write SMRAM via DMA | Medium |
| **GPU DMA** | GPU can be programmed to DMA SMRAM contents | Medium |

#### 4.5.3 DMA SMM Attack Walkthrough

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Obtain DMA-capable device access                    │
│    - Thunderbolt port (e.g., PCILeech device)               │
│    - Malicious PCIe card                                     │
│    - Compromised NIC firmware                                 │
│                                                               │
│  Step 2: Scan physical memory for SMRAM                       │
│    - Read from known TSEG location (0xFED00000 typical)      │
│    - Or scan for SMM signature / state save patterns         │
│                                                               │
│  Step 3: Read SMRAM via DMA                                   │
│    - DMA read of TSEG range → extract SMM handlers           │
│    - Identify SMI handler addresses, code patterns           │
│    - Find vulnerabilities in SMM code                         │
│                                                               │
│  Step 4: Write SMRAM via DMA                                  │
│    - Modify SMM handler code                                  │
│    - Inject shellcode into SMM                                │
│    - Redirect SMI handler dispatch table                     │
│                                                               │
│  Step 5: Trigger SMI                                          │
│    - Write to port 0xB2                                       │
│    - SMM executes modified handler                            │
│    - Ring -2 compromise confirmed                              │
│                                                               │
│  Result: Persistent firmware-level implant                    │
│         Survives OS reinstall, disk replace                   │
│         Invisible to OS-level monitoring                      │
└─────────────────────────────────────────────────────────────┘
```

#### 4.5.4 Mitigation: IOMMU (VT-d)

Intel's **IOMMU (VT-d)** can protect SMRAM from DMA attacks by:

1. **DMA Remapping**: Restricting DMA transactions to authorized address ranges
2. **Reserved Memory Regions**: Marking SMRAM as reserved in the DMAR table
3. **RMRR (Reserved Memory Region Reporting)**: BIOS reports SMRAM ranges that must not be subject to DMA

However, VT-d protection requires:
- Proper IOMMU setup **before** any DMA-capable device is active
- Correct RMRR entries in ACPI DMAR table
- IOMMU pre-boot initialization (often incomplete)
- No IOMMU bypass (some Thunderbolt configurations)

### 4.6 Supply Chain Firmware Attacks

#### 4.6.1 The Attack Surface

SMM code is part of the **firmware supply chain** — it flows from multiple vendors before reaching the end user:

```
Intel/AMD (CPU microcode + reference code)
    ↓
AMI/Insyde/Phoenix (BIOS/UEFI firmware vendor)
    ↓
Intel (CHIPSEC, reference SMM modules)
    ↓
OEM (Lenovo/Dell/HP — customization, drivers)
    ↓
IBV (Independent BIOS Vendor — customization)
    ↓
ODM (Original Design Manufacturer — manufacturing)
    ↓
End User (via BIOS update or factory pre-install)
```

At each stage, vulnerabilities can be introduced — either accidentally or intentionally.

#### 4.6.2 Known Supply Chain Attacks

| Attack | Year | Description |
|--------|------|-------------|
| **Hacking Team** | 2015 | UEFI firmware rootkit framework using SMM persistence; leaked in Hacking Team dump |
| **LoJax** | 2018 | First UEFI rootkit seen in the wild (APT28/Sednit); used SMM for persistence |
| **MosaicRegressor** | 2020 | UEFI bootkit using SMM-related firmware modification for persistence |
| **ESPectre** | 2022 | UEFI bootkit targeting ESP, leveraging Secure Boot bypass for firmware modification |
| **BlackLotus** | 2023 | UEFI bootkit bypassing Secure Boot; can be used to modify firmware before SMM locks |
| **CosmicStrand** | 2022-2023 | Sophisticated UEFI rootkit found in MSI and Gigabyte firmware; modifies boot flow |

#### 4.6.3 Firmware Implant Persistence Model

```
┌──────────────────────────────────────────────┐
│  Firmware Implant in SPI Flash               │
│    (Persists across OS reinstall)           │
│                                              │
│  ┌────────────────────────────────────────┐ │
│  │  SMM Implant                            │ │
│  │  - Hooks SMI handler dispatch           │ │
│  │  - Monitors port 0xB2 for commands      │ │
│  │  - Provides Ring -2 backdoor            │ │
│  │  - Modifies OS page tables on resume    │ │
│  └────────────────────────────────────────┘ │
│                                              │
│  ┌────────────────────────────────────────┐ │
│  │  Boot Kit Component                     │ │
│  │  - Patches bootloader in memory         │ │
│  │  - Bypasses Secure Boot                 │ │
│  │  - Loads SMM implant during DXE phase   │ │
│  └────────────────────────────────────────┘ │
│                                              │
│  ┌────────────────────────────────────────┐ │
│  │  SPI Flash Descriptor                   │ │
│  │  - Modified to allow write access       │ │
│  │  - BIOS region unprotected              │ │
│  └────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

The SMM implant is the most powerful component because:
- It persists in SPI flash (not on disk)
- It runs at Ring -2 (invisible to OS)
- It can modify OS state at will (page tables, processes)
- It can provide network access via DMA or modified NIC firmware
- It survives OS reinstallation, disk replacement, and even BIOS "reset" (if SPI flash is not reflashed)

---

## 5. Tools for SMM Research

### 5.1 Chipsec — Firmware Security Testing Framework

**Chipsec** (https://github.com/chipsec/chipsec) is the primary open-source tool for firmware security testing, developed by Intel. It provides comprehensive SMM testing capabilities.

#### 5.1.1 Overview

```bash
# Install Chipsec
pip install chipsec

# Or from source
git clone https://github.com/chipsec/chipsec.git
cd chipsec
python setup.py install
```

Chipsec operates as a **kernel-mode driver** (Linux, Windows) with direct hardware access. It can:

- Read/write MSR registers (including SMRR)
- Read/write PCI configuration space
- Read/write I/O ports (including port 0xB2)
- Access SPI flash controller
- Dump SMRAM (when protection is misconfigured)
- Test SMI handler security

#### 5.1.2 Key SMM-Related Chipsec Modules

```bash
# Check SMRR configuration
python chipsec_util.py smrr

# Check SMRAM lock status
python chipsec_util.py smram

# Run all SMM tests
python chipsec_main.py -m common.smm
python chipsec_main.py -m common.smrr
python chipsec_main.py -m common.smram
python chipsec_main.py -m common.smm_callout

# Test SPI flash protection (relevant to SMM persistence)
python chipsec_main.py -m common.spi_lock
python chipsec_main.py -m common.bios_write

# Test SMI handler callout vulnerabilities
python chipsec_main.py -m common.smm_comm

# Dump SPI flash (includes SMM code)
python chipsec_util.py spi dump firmware_dump.bin

# Manual SMI invocation for testing
python chipsec_util.py smi --smicmd 0x01 --smidata 0x00

# Read/write MSRs
python chipsec_util.py msr 0x1FE   # IA32_SMRR_PHYS_BASE
python chipsec_util.py msr 0x1FF   # IA32_SMRR_PHYS_MASK
```

#### 5.1.3 Chipsec SMI Fuzzing

```python
# Example: Fuzzing SMI handlers via Chipsec
from chipsec import chipsec
from chipsec.hal.interrupts import Interrupts

cs = chipsec()
intr = Interrupts(cs)

# Enumerate SMI sources
smi_handlers = []

# Fuzz SMI command port 0xB2
for cmd in range(0, 256):
    for data in range(0, 256):
        try:
            # Trigger SMI
            intr.send_smi(cmd, data)
            # Check for crash, hang, or unexpected behavior
        except Exception as e:
            print(f"SMI 0x{cmd:02x}/0x{data:02x}: {e}")
```

### 5.2 UEFI Firmware Analysis Tools

#### 5.2.1 UEFITool

**UEFITool** (https://github.com/LongSoft/UEFITool) is the primary tool for parsing and modifying UEFI firmware images:

```bash
# Parse firmware image
UEFIExtract firmware_dump.bin

# This extracts all firmware volumes, including SMM modules:
#   SmmCore.efi
#   SmmVariable.efi
#   PiSmmCpuDxeSmm.efi
#   ... (varies by platform)
```

UEFITool can:
- Parse UEFI firmware volumes and file sections
- Extract individual PE/COFF modules (including SMM drivers)
- Identify SMM PEI and DXE modules
- Verify firmware signatures (if present)
- Compare firmware versions for diffing

#### 5.2.2 EfiPy / efitools

```bash
# efitools package (Linux)
sudo apt install efitools

# Sign a firmware update
sbsign --key db.key --cert db.crt firmware_update.cap

# Verify firmware signature
sbverify --cert db.crt firmware_update.cap

# Create UEFI key enrollment bundle
cert-to-efi-sig-list db.crt db.esl
```

#### 5.2.3 Ghidra + UEFI Plugin

The **ghidra-uefi-reloader** plugin enables reverse engineering of extracted SMM modules:

```bash
# Install Ghidra UEFI plugin
git clone https://github.com/ghidraninja/ghidra-uefi-reloader

# Analyze extracted SMM module
# 1. Load SmmVariable.efi into Ghidra
# 2. Apply UEFI firmware analysis scripts
# 3. Identify SMI handler registration calls
# 4. Trace data flow from SMI communication buffer
# 5. Identify callout vulnerabilities (dereferences outside SMRAM)
```

#### 5.2.4 UEFIAnalyzer

A specialized tool for automated UEFI firmware analysis that can identify:
- SMM entry points
- SMI handler dispatch tables
- SMM communication protocols
- Potential callout vulnerabilities (static analysis)

### 5.3 SPI Flash Dumping and Analysis

#### 5.3.1 SPI Flash Controller

The SPI flash controller provides access to the firmware ROM. Key registers:

| Register | Offset | Purpose |
|----------|--------|---------|
| BFPR | 0x00 | BIOS Flash Primary Register |
| HSFS | 0x04 | Hardware Sequencing Flash Status |
| HSFC | 0x06 | Hardware Sequencing Flash Control |
| FADDR | 0x08 | Flash Address |
| FDATA0 | 0x10 | Flash Data Register 0 |

#### 5.3.2 Dumping SPI Flash with Chipsec

```bash
# Dump entire SPI flash (32MB typical)
python chipsec_util.py spi dump full_flash.bin

# Verify SPI flash locks are set (preventing write from OS)
python chipsec_main.py -m common.spi_lock
```

#### 5.3.3 Dumping SPI Flash with flashrom

```bash
# Install flashrom
sudo apt install flashrom

# Dump SPI flash using programmer
sudo flashrom -p internal -r firmware_backup.bin

# Verify SPI flash write protection
sudo flashrom -p internal --wp-status
```

#### 5.3.4 Direct SPI Flash Programming (Hardware)

For research, hardware SPI flash programmers provide direct access:

```bash
# Using flashrom with external programmer (e.g., CH341A)
flashrom -p ch341a_spi -r firmware_dump.bin

# Common hardware tools:
# - CH341A USB SPI programmer (~$5)
# - Bus Pirate
# - Saleae Logic Analyzer (for SPI protocol analysis)
# - Dediprog SF100 (professional SPI programmer)
```

---

## 6. SMRR (System Management Range Register)

### 6.1 How SMRR Protects SMRAM

The **System Management Range Register (SMRR)** is a pair of Model-Specific Registers (MSRs) that define the SMRAM physical address range and protect it from non-SMM CPU access:

| MSR | Name | Purpose |
|-----|------|---------|
| `0x1FE` | `IA32_SMRR_PHYSBASE` | SMRAM base address + memory type |
| `0x1FF` | `IA32_SMRR_PHYSMASK` | SMRAM address mask + valid bit |

#### 6.1.1 SMRR Register Format

**IA32_SMRR_PHYSBASE (MSR 0x1FE):**

```
Bits 63:26 | 25:12 | 11:8  | 7:0
-----------+-------+-------+-----
PhysBase   | Res   | Type  | Res
           |       |       |
           |       | 0: UC | 6: WB
           |       | 1: UC | 7: WP
           |       | ...   |
           |       |       |
           |       +-- Memory type for SMRAM region
           +-- Reserved (must be 0)
    +-- Physical base address (aligned to mask)
```

**IA32_SMRR_PHYSMASK (MSR 0x1FF):**

```
Bits 63:26 | 25:12    | 11:0
-----------+----------+------
PhysMask   | Res      | Valid
           |          |
           |          +-- Bit 0: Valid (1 = SMRR enabled)
           +-- Reserved (must be 0)
    +-- Physical address mask (1 = compared, 0 = ignored)
```

#### 6.1.2 SMRR Address Matching

SMRR defines an address range using base+mask:

```
SMRAM range: [PhysBase .. PhysBase + ~PhysMask]

Example:
  PhysBase = 0xFED00000  (TSEG at 0xFED00000)
  PhysMask = 0xFFE00000  (2MB SMRAM region)

Address matching:
  (PhysicalAddress & PhysMask) == (PhysBase & PhysMask)

  Matches: 0xFED00000 .. 0xFEDFFFFF (2MB)
  Does NOT match: 0xFEC00000, 0xFEE00000
```

When a non-SMM CPU access hits the SMRR range:

1. **Read access**: Returns `0xFF` bytes (on Intel) — memory is inaccessible
2. **Write access**: Silently dropped — no effect on SMRAM content
3. **Instruction fetch**: Causes a fault — cannot execute SMRAM code from non-SMM

When SMM CPU access hits the SMRR range:

1. **Read/write**: Normal SMRAM access — full visibility
2. **Instruction fetch**: Normal execution from SMRAM

### 6.2 SMRR Configuration Process

SMRR is configured during early boot by the firmware's SMM initialization:

```c
// Pseudocode: SMRR configuration in PiSmmCpuDxeSmm

VOID ConfigureSmrr(VOID)
{
    UINT64 SmrrBase;
    UINT64 SmrrMask;
    UINT32 ApicId;
    UINT64 MtrrCap;

    // 1. Read SMRAM range from chipset (TSEG base and size)
    SmrrBase = PciRead32(PCH_SA_TSEG_BASE) & ~0x1F; // Align to 32-byte boundary
    SmrrMask = ~((TsegSize) - 1) & 0xFFFFFFFFF;

    // 2. Set Write-Back memory type
    SmrrBase |= MTRR_WRITE_BACK;

    // 3. Enable SMRR
    SmrrMask |= 0x1; // Set Valid bit

    // 4. Write SMRR MSRs
    AsmWriteMsr64(0x1FE, SmrrBase);   // IA32_SMRR_PHYSBASE
    AsmWriteMsr64(0x1FF, SmrrMask);   // IA32_SMRR_PHYSMASK

    // 5. Lock SMRR (prevent further modification)
    // On many platforms, SMRR is locked by setting IA32_FEATURE_CONTROL.SMRR_LOCK
    // or via chipset-specific lock mechanism

    // CRITICAL: SMRR must be locked before first SMI is delivered
    // to non-BSP cores, otherwise an attacker could modify SMRR
}
```

### 6.3 SMRR Bypass Techniques

#### 6.3.1 Missing SMRR Lock

If the firmware fails to lock SMRR before OS boot, an attacker with Ring 0 access can:

```bash
# Read current SMRR configuration
rdmsr 0x1FE   # IA32_SMRR_PHYSBASE
rdmsr 0x1FF   # IA32_SMRR_PHYSMASK

# If SMRR is not locked, overwrite it:
# Set SMRR base to 0x00000000 → disables SMRR protection
wrmsr 0x1FE 0x00000000
wrmsr 0x1FF 0x00000000

# Now SMRAM is accessible from Ring 0!
# Read SMRAM content directly
dd if=/dev/mem of=smram_dump.bin bs=1M skip=4016 count=2
```

**Prevalence**: Chipsec testing has found numerous systems where SMRR is not locked, particularly on:
- Older platforms (pre-Skylake)
- Firmware with bugs in SMM initialization
- Systems with custom firmware modifications

#### 6.3.2 SMRR Range Mismatch with SMBASE

If the SMBASE (where SMM code executes and state is saved) is not within the SMRR-protected range, the SMM state save area and code become accessible from non-SMM mode:

```
Scenario: SMBASE relocation gone wrong

  SMRR coverage:    0xFED00000 .. 0xFEDFFFFF (2MB)
  SMBASE for CPU1:  0x00090000                 ← OUTSIDE SMRR!

  Result:
  - SMM state save area at 0x00090000 + 0xFE00 is readable from OS
  - SMM handler code at 0x00090000 + 0x8000 is readable from OS
  - OS can modify SMM code and state saves
  - Complete Ring -2 compromise
```

This can happen when:
- SMBASE relocation formula produces addresses outside SMRR
- SMRR mask is incorrect (too small)
- TSEG configuration doesn't match SMRR configuration

#### 6.3.3 SMRR Physical Address Confusion

On systems with more than 4GB of RAM, SMRR uses physical addresses. If the firmware miscalculates the SMRR base address (e.g., uses a 32-bit value instead of 64-bit), SMRR may protect the wrong physical range:

```
Intended SMRR:    SMRAM at physical 0x00000000_FED00000
Actual SMRR:      SMRR configured for 0xFED00000 (truncated)
                    → Protects low memory instead of actual SMRAM
                    → SMRAM is accessible from OS
```

#### 6.3.4 SMRR and MTRR Interaction

SMRR specifies a memory type (typically Write-Back) for the SMRAM range. If MTRRs (Memory Type Range Registers) conflict with SMRR:

1. **MTRR Write-Back + SMRR Write-Back**: Normal behavior — SMRAM is WB cached, protected by SMRR
2. **MTRR Uncacheable + SMRR Write-Back**: MTRR takes precedence for cache behavior; SMRR still blocks access from non-SMM
3. **MTRR Write-Back + SMRR Uncacheable**: SMRR is Uncacheable but accessible in SMM — performance impact but no security issue
4. **MTRR overrides affecting SMRR**: If MTRRs can be modified by the OS to mark SMRAM as UC (Uncacheable), cache-line flush attacks may be possible

The key concern: **MTRR modifications by the OS can affect how SMRAM is cached**, potentially enabling cache-poisoning attacks if the platform doesn't enforce SMRR memory type for all accesses.

#### 6.3.5 Dual-System SMRR (Intel vs AMD)

| Feature | Intel SMRR | AMD SMRR Equivalent |
|---------|-----------|---------------------|
| MSR | IA32_SMRR_PHYSBASE (0x1FE), IA32_SMRR_PHYSMASK (0x1FF) | MSR_SMM_ADDR (0xC0010112), MSR_SMM_MASK (0xC0010113) |
| Lock mechanism | IA32_FEATURE_CONTROL.SMRR_LOCK | HWCR.SMM_LOCK |
| Memory type | MTRR-style (WB, UC, etc.) | Not configurable (always WB) |
| Range | BASE + MASK | BASE + MASK |
| Access control | Blocks non-SMM reads/writes | Blocks non-SMM reads/writes |
| Cache control | SMRR memory type applies | Fixed WB |
| TSEG equivalent | TSEG (chipset) | SMM_TSEG (chipset) |

AMD's implementation is simpler (no memory type selection) but follows the same protection principles.

### 6.4 SMRR Configuration Vulnerabilities Checklist

A comprehensive checklist for SMRR auditing:

```
[ ] SMRR is configured (both PHYSBASE and PHYSMASK set)
[ ] SMRR covers the entire SMRAM range (TSEG + all SMBASEs)
[ ] SMRR is locked (cannot be modified after boot)
[ ] SMRR base address is correct (matches TSEG base)
[ ] SMRR mask is correct (matches TSEG size)
[ ] SMRR memory type is Write-Back (type 6)
[ ] SMBASE for all CPUs is within SMRR range
[ ] MTRRs do not conflict with SMRR
[ ] SMRR Valid bit is set (PHYSMASK bit 0 = 1)
[ ] No alias mappings to SMRAM physical range exist
[ ] D_LCK is set (SMRAM configuration locked)
[ ] D_CLS is set (SMRAM closed to non-SMM access)
[ ] TSEG configuration cannot be modified after boot
[ ] No memory holes or overlaps in physical map near TSEG
```

---

## 7. References

### 7.1 Intel Documentation

- **Intel 64 and IA-32 Architectures Software Developer's Manual**, Volume 3C, Chapter 34: System Management Mode
- **Intel 64 and IA-32 Architectures Software Developer's Manual**, Volume 3B, Chapter 23: Model-Specific Registers (MSRs)
- **Intel Platform Protection Technology Guide** — SMRR, SMEP, SMAP documentation
- **Intel BIOS and UEFI Security** — SMM hardening guidelines
- **Intel Firmware Support Package (FSP)** — SMM initialization reference code

### 7.2 UEFI/PI Specifications

- **UEFI Specification**, Version 2.9+ — EFI_SMM_* protocols
- **PI Specification**, Volume 4: SMM — SMM Core, Dispatcher, and Handler interfaces
- **EDK II** — Open-source UEFI firmware implementation (https://github.com/tianocore/edk2)

### 7.3 Security Research

- **Chipsec** — Firmware security testing framework (https://github.com/chipsec/chipsec)
- **LegbaCore / Eclypsium** — Firmware security research (Ron Minnich, Alex Matrosov, Yuriy Bulygin)
- **Rafal Wojtczuk**, "Attacking Intel BIOS" — SMM cache poisoning research
- **Corey Kallenberg**, "SMM Callout Vulnerabilities" — Systematic SMM callout analysis
- **Mitre ATT&CK** — Technique T1542.001: System Firmware (SMM implant)
- **NIST NVD** — CVE entries for SMM-related vulnerabilities
- **Intel Security Advisories** — SA-00086, SA-00598, and related SMM advisories

### 7.4 Key Papers and Presentations

| Year | Title | Authors | Topic |
|------|-------|---------|-------|
| 2006 | "Attacking Intel BIOS" | Heasman | SMM cache poisoning |
| 2009 | "Attacking Intel Trusted Execution Technology" | Wojtczuk, Rutkowska | TXT/SMM interaction |
| 2015 | "How Many Million BIOSes Would You Like to Infect?" | Bulygin, Matrosov, et al. | SMM security landscape |
| 2017 | "Intel SA-00086" | Intel | ME/AMT/SMM vulnerability cluster |
| 2019 | "Safeguarding SMM with STM" | Intel | SMM Monitor (STM) for SMM hardening |
| 2020 | "CosmicStrand" | Kaspersky | UEFI rootkit with SMM components |
| 2022 | "SMM Config «Lock» Down" | Bulygin, Matrosov | SMM locking vulnerabilities |
| 2023 | "BlackLotus UEFI Bootkit" | ESET | Secure Boot bypass enabling firmware attacks |

---

*This document is part of a security research series on x86 privilege escalation and firmware security. For questions, clarifications, or contributions, please refer to the primary sources listed above.*