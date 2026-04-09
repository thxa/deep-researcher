# macOS Security Architecture: SIP, Gatekeeper, TCC, and Code Signing

## Overview

macOS implements a defense-in-depth security model composed of multiple interlocking enforcement layers. From the hardware root of trust established at boot through runtime protections governing process behavior, each layer constrains the attack surface available to adversaries even when adjacent layers are compromised. This document provides a technical examination of six core subsystems: System Integrity Protection, Gatekeeper, Transparency Consent and Control, Code Signing, App Sandbox, and the Secure Boot Chain.

---

## 1. System Integrity Protection (SIP)

### Architecture

System Integrity Protection (introduced in OS X 10.11 El Capitan) is a kernel-level policy enforcement mechanism that restricts the root user from modifying protected system components. SIP is not a single feature but a collection of protections governed by a bitmask stored in NVRAM (`csr-active-config`), evaluated by the kernel through the `csr_check()` function in `bsd/kern/kern_csr.c`.

### Protected Domains

SIP enforces restrictions across three domains:

- **Filesystem protection**: Write access is denied to protected paths regardless of UID. Protected directories include `/System`, `/usr` (excluding `/usr/local`), `/bin`, `/sbin`, and all bundled system applications in `/Applications` that ship with macOS. The kernel consults a sealed system volume (SSV) on APFS, where the entire system volume is cryptographically hashed via a Merkle tree rooted in the volume superblock.
- **Kernel extension protection**: Only kexts signed by Apple or developers with an approved Team ID can load. Since macOS 11, kernel extensions are deprecated in favor of System Extensions running in userspace.
- **Runtime protection**: SIP prevents attachment to Apple-signed system processes via `task_for_pid()`, blocks injection of dynamic libraries through `DYLD_INSERT_LIBRARIES` into protected processes, and prevents modification of NVRAM variables related to boot security.

### CSR Flags

The `csr_check()` kernel function evaluates a bitmask of flags. Key flags include:

| Flag | Value | Effect |
|------|-------|--------|
| `CSR_ALLOW_UNTRUSTED_KEXTS` | 0x01 | Allow unsigned kexts |
| `CSR_ALLOW_UNRESTRICTED_FS` | 0x02 | Disable filesystem protection |
| `CSR_ALLOW_TASK_FOR_PID` | 0x04 | Allow task_for_pid on protected processes |
| `CSR_ALLOW_UNRESTRICTED_DTRACE` | 0x20 | Allow DTrace on restricted processes |
| `CSR_ALLOW_UNRESTRICTED_NVRAM` | 0x40 | Allow NVRAM modification |

### Configuration

SIP can only be modified from recoveryOS (booted via holding Command+R, or on Apple Silicon by holding the power button). The `csrutil` utility communicates with a privileged helper:

```bash
csrutil status              # Query current SIP configuration
csrutil disable             # Set csr-active-config to 0x77 (all flags)
csrutil enable              # Set csr-active-config to 0x00
csrutil authenticated-root disable  # Disable SSV enforcement
```

On Apple Silicon, SIP changes require authentication through the Secure Enclave and modify the LocalPolicy, not just NVRAM.

### Historical Bypasses

Notable SIP bypasses have exploited components that operate with elevated entitlements:

- **CVE-2021-30892 (Shrootless)**: The `system_installd` daemon carried `com.apple.rootless.install.heritable`, allowing Apple-signed installer packages to execute post-install scripts with SIP bypass capability. Attackers could craft malicious packages exploiting this trust.
- **CVE-2022-22583**: Exploited the mount/snapshot restoration flow during macOS updates to write to SIP-protected paths.
- **CVE-2023-32369 (Migraine)**: Abused Migration Assistant's elevated entitlements to bypass SIP by manipulating the migration workflow.

---

## 2. Gatekeeper

### Verification Flow

Gatekeeper prevents execution of untrusted software by enforcing a multi-stage verification pipeline triggered when a user opens an application downloaded from the internet:

1. **Quarantine check**: The kernel examines the extended attribute `com.apple.quarantine` on the file. This attribute is set by quarantine-aware applications (Safari, Mail, AirDrop, Messages, most Chromium-based browsers) using the `LSQuarantine` API. The attribute encodes a hex flag field, timestamp, and the downloading agent's bundle ID (e.g., `0083;66a1b2c3;Safari;UUID`).
2. **Signature verification**: `syspolicyd` verifies the code signature against Apple's certificate chain. The binary must be signed with a valid Developer ID certificate or distributed via the App Store.
3. **Notarization check**: Since macOS 10.15, all Developer ID-signed software must be notarized. The system checks for a stapled notarization ticket (embedded in the code signature as a CMS blob) or performs an online lookup against Apple's notarization service (`api.apple-cloudkit.com`). The ticket is a signed assertion from Apple confirming the binary passed automated malware scans.
4. **XProtect scan**: The payload is scanned against XProtect's YARA-based signature database.

### XProtect Subsystems

Apple's anti-malware infrastructure comprises three components:

- **XProtect**: YARA-based signature rules located in `/Library/Apple/System/Library/CoreServices/XProtect.bundle`. Updated silently via background content delivery. Rules are evaluated at first launch of quarantined executables.
- **XProtect Remediator (XProtectRemediatorMRT)**: A periodic scanning engine that runs remediation modules on a schedule (roughly every 12 hours). Each module targets a specific malware family (e.g., `XProtectRemediatorPirrit`, `XProtectRemediatorDubRobber`). Modules can detect and remove known malware from running systems.
- **MRT (Malware Removal Tool)**: Legacy remediation tool, largely superseded by XProtect Remediator but still present for backward compatibility.

### Management

```bash
spctl --status                    # Check Gatekeeper status
spctl --assess --type execute app.app  # Manually assess an app
spctl --add --label "Approved" /path/to/app  # Add override rule
xattr -d com.apple.quarantine app.app  # Remove quarantine (bypass)
xattr -p com.apple.quarantine app.app  # Inspect quarantine flag
```

Since macOS 15 Sequoia, the ability to right-click bypass Gatekeeper for unsigned apps was removed; users must now navigate to System Settings > Privacy & Security to approve blocked applications.

---

## 3. Transparency, Consent, and Control (TCC)

### Architecture

TCC mediates access to privacy-sensitive resources by requiring explicit user consent before granting access to a requesting process. The policy daemon `tccd` runs in two instances: a user-level daemon managing per-user decisions and a system-level daemon for machine-wide policy.

### Databases

Consent decisions are stored in SQLite databases:

- **User TCC.db**: `~/Library/Application Support/com.apple.TCC/TCC.db` — stores per-user consent decisions. Protected by SIP and requires Full Disk Access to read directly.
- **System TCC.db**: `/Library/Application Support/com.apple.TCC/TCC.db` — stores system-wide policy, typically managed by MDM profiles. Requires Full Disk Access and SIP bypass to modify directly.

The `access` table schema includes: `service` (resource identifier), `client` (bundle ID or binary path), `client_type` (bundle ID = 0, absolute path = 1), `auth_value` (0 = denied, 2 = allowed), `auth_reason`, `indirect_object_identifier`, and timing fields.

### Protected Resources

Key TCC-protected services and their identifiers:

| Resource | Service Identifier | Notes |
|----------|-------------------|-------|
| Camera | `kTCCServiceCamera` | Per-application consent |
| Microphone | `kTCCServiceMicrophone` | Per-application consent |
| Full Disk Access | `kTCCServiceSystemPolicyAllFiles` | Grants access to Mail, Safari data, TM backups |
| Screen Recording | `kTCCServiceScreenCapture` | Required for `CGWindowListCreateImage` |
| Accessibility | `kTCCServiceAccessibility` | AX API, synthetic input events |
| Location Services | `kTCCServiceLocation` | Core Location framework |
| Contacts | `kTCCServiceAddressBook` | Address Book database |
| Photos Library | `kTCCServicePhotos` | Photos.app media library |

### Management and MDM

```bash
tccutil reset All                    # Reset all TCC decisions for all apps
tccutil reset Camera com.app.bundle  # Reset camera for a specific app
```

MDM solutions (via `com.apple.TCC.configuration-profile-policy` payloads) can silently pre-approve TCC consent for managed deployments, enabling enterprise tools to receive Full Disk Access, Accessibility, or Screen Recording permissions without user interaction. This is the only supported mechanism for silent TCC approval. The `TCCProfile` payload uses the `Privacy_Preferences_Policy_Control` key.

### Historical Bypasses

TCC has been a frequent bypass target:

- **CVE-2020-9934**: Environment variable manipulation of `HOME` redirected `tccd` to read an attacker-controlled TCC.db.
- **CVE-2021-30713**: A logic flaw in `tccd` allowed crafted AppleScript to bypass consent prompts.
- **CVE-2023-38571 (Migraine-related)**: Abused process exceptions in `IMTransferAgent` which had implicit TCC consent for certain operations.
- **CVE-2024-44133 (HM Surf)**: Exploited Safari's special TCC entitlements by modifying its per-site preferences to gain access to camera and microphone without user consent.

A recurring pattern in TCC bypasses involves finding Apple-signed binaries with pre-granted TCC access that can be coerced into performing actions on behalf of the attacker (confused deputy attacks).

---

## 4. Code Signing

### Signing Types

macOS code signing operates at multiple trust levels:

- **Ad-hoc signing** (`codesign -s -`): Generates a code hash without an identity. The binary is tied to its exact content but carries no trust assertion. Sufficient for local development.
- **Developer ID**: Apple-issued certificate for distribution outside the App Store. Required for notarization. Certificates are tied to a Team ID and validated against Apple's certificate chain.
- **Apple-signed**: System binaries signed by Apple's own Software Signing certificate. These receive the highest trust and can carry restricted entitlements.

### Entitlements and Hardened Runtime

Entitlements are key-value pairs embedded in the code signature that declare capabilities:

```xml
<key>com.apple.security.cs.allow-dyld-environment-variables</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.private.tcc.allow</key>
<array><string>kTCCServiceCamera</string></array>
```

The **hardened runtime** (required for notarization) enables a strict set of security defaults: library validation (only Apple-signed or same-team libraries may be loaded), DYLD environment variable restrictions, debugging protection, and memory protection (no unsigned executable pages). Developers opt out of specific restrictions via entitlements.

### Kernel Enforcement (cs_blobs)

At the kernel level, every executable page is validated against code directory hashes stored in `cs_blob` structures attached to the vnode. The `mac_vnode_check_signature()` hook evaluates these blobs during `mmap()` with executable permissions. On Apple Silicon, this enforcement is augmented by Page Protection Layer (PPL) in the kernel, which prevents modification of page table entries for executable pages without code signature validation.

### Trust Caches

**Static trust caches** are pre-built lists of `cdhash` values (SHA-256 truncated to 20 bytes) for every system binary, embedded in the firmware/iBoot. These allow first-party binaries to be validated without consulting the filesystem code signature. **Loadable trust caches** can be added at runtime by entitled processes (e.g., `cryptexd` for Rapid Security Responses). On Apple Silicon, the trust cache is loaded into the secure page table domain managed by PPL, making it tamper-resistant from the kernel itself.

---

## 5. App Sandbox

### Architecture

The App Sandbox is a mandatory access control system built on the macOS `sandbox.kext` kernel extension (also known as Seatbelt). Applications declare sandbox entitlements, and upon launch, the process is confined by a sandbox profile that restricts system call behavior.

### Sandbox Profiles

Profiles are written in the Sandbox Profile Language (SBPL), a Scheme-based DSL:

```scheme
(version 1)
(deny default)
(allow file-read* (subpath "/usr/lib"))
(allow file-read-data (literal "/etc/hosts"))
(allow mach-lookup (global-name "com.apple.securityd"))
(allow network-outbound (remote tcp "*:443"))
```

System profiles are stored in `/System/Library/Sandbox/Profiles/`. App Store apps use a parameterized container profile that restricts file access to `~/Library/Containers/<bundle-id>/`.

### Container Directories

Each sandboxed application receives a container at `~/Library/Containers/<bundle-id>/` containing a private `Data/` directory mirroring the standard directory layout (`Documents/`, `Library/`, `Caches/`). Access outside the container requires explicit user consent (via Powerbox/NSOpenPanel) or declared entitlements for specific resource groups.

### Sandbox Escape Patterns

Historical sandbox escapes have exploited:
- **IPC attack surface**: Mach service endpoints accessible from the sandbox that themselves have unsandboxed access. Crafted XPC messages to privileged helpers (e.g., `CVE-2023-32364` via a WindowServer flaw).
- **File-based escapes**: Symlink races or writing to locations that are later processed by unsandboxed services.
- **`sandbox-exec` utility**: While available for development (`sandbox-exec -p '(allow default)' /bin/sh`), it is deprecated and should not be used for production enforcement.

---

## 6. Secure Boot Chain

### Apple Silicon Boot Flow

Apple Silicon Macs implement a hardware-rooted chain of trust:

1. **Boot ROM (SecureROM)**: Immutable code in the application processor, loaded at first instruction. Contains Apple's root certificate (Apple Root CA). Verifies the next stage (LLB/iBoot).
2. **LLB/iBoot**: The low-level bootloader verifies the kernel collection and auxiliary kernel collections against signatures anchored to the Boot ROM root of trust.
3. **Secure Enclave Processor (SEP)**: Independent secure processor with its own boot ROM, OS (sepOS), and encrypted memory. Manages biometric data (Touch ID/Face ID), key storage (Secure Enclave Keys), and boot policy evaluation.
4. **LocalPolicy**: A signed structure (Image4 manifest) stored in the Secure Enclave's nonvolatile storage. It defines the boot security posture for each macOS installation and is signed by the Owner Identity Key (OIK), which is itself certified by Apple's servers during activation.

### Boot Security Modes

| Mode | Description | Requirements |
|------|-------------|--------------|
| **Full Security** | Default. Only current signed OS versions can boot. Equivalent to iOS security model. Kernel extensions disallowed. | Requires network for OS personalization |
| **Reduced Security** | Permits any Apple-signed OS version (including older releases). Allows notarized kernel extensions and MDM-managed kernel extensions. | Authenticated user in recoveryOS |
| **Permissive Security** | Allows custom kernel collections, disables SIP enforcement. Used for kernel development and research. | Authenticated owner in recoveryOS, explicit csrutil disable |

### Intel Mac Differences

Intel Macs use a T2 security chip (on 2018+ models) or firmware-based UEFI Secure Boot. The T2 chip verifies the bootloader and bridges to the main processor, but lacks the full hardware isolation of Apple Silicon's PPL and Secure Enclave boot policy architecture. Intel Macs without T2 have no hardware root of trust and rely on software-based UEFI secure boot which is significantly weaker.

---

## Security Model Interactions

These subsystems do not operate in isolation. A complete attack chain against a modern macOS target typically requires chaining bypasses across multiple layers:

1. **Initial execution**: Bypass Gatekeeper (e.g., quarantine attribute removal, CVE in notarization check)
2. **Privilege escalation**: Escape App Sandbox (IPC flaw), then escalate to root
3. **Persistence**: Bypass SIP to write to protected filesystem paths
4. **Data access**: Bypass TCC to access camera, microphone, or user files

Each layer adds cost to exploitation. Apple's security model assumes individual layers will be breached and designs each successive layer to independently limit the impact of such breaches. This architectural principle — that no single bypass should compromise the entire system — is the defining characteristic of macOS security in its current form.
