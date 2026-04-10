# Android Architecture: A Security and Attack Surface Perspective

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Attack Surface Mapping by Layer](#2-attack-surface-mapping-by-layer)
3. [Inter-Process Communication (IPC) Attack Surface](#3-inter-process-communication-ipc-attack-surface)
4. [Trust Boundaries](#4-trust-boundaries)
5. [The Android Treble Architecture](#5-the-android-treble-architecture)
6. [Project Mainline](#6-project-mainline)
7. [TEE — Trusted Execution Environment](#7-tee--trusted-execution-environment)
8. [Bootloader and Firmware](#8-bootloader-and-firmware)
9. [Android Architecture Evolution — Security-Relevant Changes](#9-android-architecture-evolution--security-relevant-changes)

---

## 1. Architectural Overview

Android's architecture is a layered software stack built on top of a modified Linux kernel. From bottom to top, the canonical layers are:

| Layer | Key Components |
|---|---|
| **Linux Kernel** | Drivers, Binder IPC, SELinux, seccomp-bpf, dm-verity |
| **Hardware Abstraction Layer (HAL)** | Camera HAL, Audio HAL, Sensors, Graphics (HIDL / AIDL interfaces) |
| **Native Libraries & Daemons** | libc (Bionic), libssl (BoringSSL), media codecs, surfaceflinger, vold, netd, installd |
| **Android Runtime (ART)** | DEX bytecode execution, JIT/AOT compilation, garbage collection |
| **Java API Framework** | Activity Manager, Package Manager, Telephony, Content Providers, Window Manager |
| **System Apps & User Apps** | Settings, SystemUI, Phone, third-party applications |

Each layer boundary represents a potential trust boundary and each component within a layer exposes its own attack surface. The security posture of an Android device is the aggregate of defenses applied across all of these layers.

---

## 2. Attack Surface Mapping by Layer

### 2.1 Linux Kernel

The kernel is the highest-privilege software component on the device (excluding TrustZone). Compromise of the kernel yields full device control.

| Threat Actor | Attack Vectors |
|---|---|
| **Local app (unprivileged)** | Syscall interface abuse, `/dev` and `/proc`/`/sys` file access, ioctl to drivers (GPU, binder, ion/dmabuf allocator, USB gadget), exploiting race conditions in kernel code paths reachable from sandboxed processes |
| **Remote attacker** | Network stack bugs (TCP/IP, Wi-Fi driver, Bluetooth L2CAP/SMP), NFC kernel drivers, USB host/device drivers if physical access is combined |
| **Physical attacker** | USB debug interfaces (ADB if enabled), JTAG/SWD debug ports, DMA attacks via exposed buses, fault injection |

**Key kernel attack surfaces:**
- **Binder driver** (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`): The single most exercised kernel driver on Android; reachable from every app. Bugs here (e.g., CVE-2019-2215, CVE-2022-20421) yield kernel code execution.
- **GPU drivers**: Qualcomm Adreno (`/dev/kgsl-3d0`), ARM Mali (`/dev/mali0`), PowerVR — historically a rich source of privilege-escalation bugs (CVE-2023-4211, CVE-2023-26083, CVE-2021-0920).
- **ION / DMA-BUF heap allocator**: Shared-memory management between userspace and kernel; use-after-free and double-free bugs are common.
- **Filesystem drivers**: ext4, f2fs, FUSE — crafted filesystem images can trigger bugs during mount.
- **Netfilter / nf_tables**: Reachable via unprivileged user namespaces on some configurations (CVE-2022-1015, CVE-2023-32233).
- **USB gadget / configfs**: Attack surface when device is connected to a hostile host.

**Kernel hardening measures:** SELinux (enforcing, mandatory), seccomp-bpf syscall filtering per process, KASLR, PAN/PXN (ARM), CFI (Clang Control-Flow Integrity), SCS (Shadow Call Stack), kASAN in userdebug builds, MTE (Memory Tagging Extension on ARMv8.5+), GKI (Generic Kernel Image) lockdown.

### 2.2 Hardware Abstraction Layer (HAL)

HALs run as separate processes (since Treble) and communicate with the framework via HIDL or AIDL interfaces over `hwbinder`.

| Threat Actor | Attack Vectors |
|---|---|
| **Local app** | Indirect — must go through framework services that invoke HALs; cannot typically reach HALs directly |
| **Compromised framework service** | Malformed HIDL/AIDL parcels sent to HAL processes; shared-memory corruption |
| **Physical attacker** | Feeding malicious data through hardware sensors (e.g., crafted NFC tags, malicious USB peripherals, rogue base stations) |

HAL processes often run with access to kernel drivers (e.g., camera HAL opens `/dev/video*`), so compromising a HAL can be a stepping stone to kernel exploitation. Vendor HALs are a frequent source of vulnerabilities because they are maintained by SoC vendors with varying code quality and update cadences.

### 2.3 Native Libraries and System Daemons

Native code executing outside the ART runtime includes:

- **Media codecs** (`mediacodec`, `mediaextractor`): Historically the most exploited native attack surface on Android. Stagefright (CVE-2015-1538 through CVE-2015-1542) demonstrated remote code execution via MMS. Post-Stagefright, media processing was isolated into constrained, seccomp-filtered processes.
- **surfaceflinger**: Compositor with GPU access; reachable from apps via Binder.
- **vold** (volume daemon): Handles disk mounting; has run as root historically.
- **netd**: Network management daemon; handles iptables rules, DNS.
- **installd**: Package installation daemon; runs with elevated privileges.
- **adbd**: ADB daemon; when enabled, provides shell (and in userdebug builds, root) access over USB or TCP.
- **Bionic libc**: Android's C library; bugs here affect every native process.
- **BoringSSL / Conscrypt**: TLS implementation; memory corruption here could enable MITM or RCE.
- **libstagefright / libheif / libwebp / libpng**: Image and media parsing libraries; frequently targeted due to complexity of file formats.

### 2.4 Android Runtime (ART)

ART executes DEX bytecode for all Java/Kotlin framework and application code.

| Threat Actor | Attack Vectors |
|---|---|
| **Local app** | Exploiting JNI boundary bugs, crafted DEX files targeting the verifier/compiler |
| **Remote attacker** | Delivering crafted code via app update mechanisms (if compromised) |

ART itself provides **memory safety** for managed code (no buffer overflows in pure Java), but the JNI boundary between Java and native code is a common source of bugs. ART's OAT/dex2oat compilation pipeline has also had vulnerabilities.

### 2.5 Java API Framework

The framework consists of system services running in `system_server` and exposed to apps via Binder:

- **ActivityManagerService (AMS)**: Controls app lifecycle; abuse can lead to task hijacking, denial of service.
- **PackageManagerService (PMS)**: Manages app installation; bugs can lead to privilege escalation through permission bypass.
- **WindowManagerService (WMS)**: Overlay attacks, tapjacking.
- **AccountManagerService**: Credential theft if improperly guarded.
- **NotificationManagerService**: Information leakage via notification access.
- **TelephonyManager / SmsManager**: Premium SMS fraud, call interception.
- **LocationManager**: Stalking / surveillance if permission checks are bypassed.

Framework services are the primary enforcement point for Android's **permission model**. A bug in a framework service's permission check can expose protected functionality to unprivileged apps.

### 2.6 Applications Layer

| Component | Attack Surface |
|---|---|
| **Exported Activities** | Activity hijacking, UI spoofing, intent redirection |
| **Exported Content Providers** | SQL injection, path traversal, data leakage |
| **Exported Broadcast Receivers** | Triggering privileged actions, denial of service |
| **Exported Services** | Unauthorized access to background functionality |
| **WebViews** | JavaScript interface attacks, universal XSS, file:// scheme abuse |
| **Deep Links / App Links** | Intent injection, OAuth token theft, open redirect |
| **Backup mechanisms** | Data extraction from `android:allowBackup="true"` |

Pre-installed (system) apps run with elevated privileges and expanded SELinux domains, making them high-value targets. Vulnerabilities in system apps such as the Phone app, Settings, or SystemUI can yield system-level access.

---

## 3. Inter-Process Communication (IPC) Attack Surface

### 3.1 Binder

Binder is Android's primary IPC mechanism, implemented as a kernel driver with a userspace library layer. Every interaction between an app and a system service traverses Binder.

**Attack vectors:**
- **Transaction data parsing**: Binder transactions carry `Parcel` objects. A service that incorrectly deserializes a `Parcel` may be vulnerable to type-confusion, buffer overflow, or logic bugs. The "Bundle mismatch" / "LazyValue" class of vulnerabilities (e.g., CVE-2017-13288, CVE-2017-13315, CVE-2023-20963) allowed privilege escalation by exploiting inconsistent Parcel serialization/deserialization.
- **Race conditions**: TOCTOU bugs between permission checks and action execution.
- **File descriptor passing**: Binder can pass file descriptors between processes; a service that passes an FD to a caller without proper checks can leak access to protected files.
- **Death notifications**: `linkToDeath` / `unlinkToDeath` can be abused for information leakage about process lifecycle.

**Binder hardening:** SELinux enforces which processes can communicate over Binder (the `binder_call` permission). Android 8.0+ introduced three separate Binder domains (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`) to isolate framework, HAL, and vendor IPC traffic.

### 3.2 Intents

Intents are the primary messaging mechanism at the framework level. They can be **explicit** (targeting a specific component) or **implicit** (resolved by the system based on intent filters).

**Attack vectors:**
- **Intent interception**: A malicious app declares an intent filter matching a victim's implicit intent, intercepting sensitive data (e.g., OAuth callbacks).
- **Intent injection / redirection**: A victim app takes a `PendingIntent` or `Intent` from an untrusted source and uses it to start a component, enabling the attacker to access the victim's private components or bypass permission checks.
- **Pending Intent hijacking**: Mutable `PendingIntent` objects can be modified by recipients to redirect actions.
- **Sticky broadcasts (deprecated)**: Could be spoofed by any app.

### 3.3 Content Providers

Content Providers expose structured data via a URI-based interface.

**Attack vectors:**
- **SQL injection**: If the provider constructs raw SQL from caller-supplied `selection` / `selectionArgs`.
- **Path traversal**: `openFile()` implementations that accept caller-controlled paths without sanitization (e.g., `../../../data/data/com.victim/databases/secret.db`).
- **Permission confusion**: Providers with `android:grantUriPermissions="true"` can be tricked into granting URI permissions to unintended recipients.
- **Information disclosure**: Providers exported without read/write permission requirements.

### 3.4 Broadcast Receivers

**Attack vectors:**
- **Broadcast injection**: Sending crafted broadcasts to receivers that don't verify the sender, triggering privileged logic.
- **Broadcast sniffing**: Registering receivers for broadcasts that carry sensitive data without using `android:permission` or `LocalBroadcastManager`.
- **Ordered broadcast manipulation**: Intercepting and modifying or aborting ordered broadcasts (e.g., `SMS_RECEIVED` — mitigated since Android 4.4 by restricting SMS broadcasts to the default SMS app).

---

## 4. Trust Boundaries

Trust boundaries are the critical lines where the level of trust changes and where enforcement mechanisms must be strongest.

### 4.1 Major Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│              TrustZone Secure World              │  ← Highest trust
│  (TEE OS, Keymaster TA, Gatekeeper TA, DRM TA)  │
├─────────────────────────────────────────────────┤
│              Linux Kernel                        │  ← Kernel trust boundary
│  (Drivers, Binder, SELinux, seccomp)             │
│  ┌───────────────────────────────────────────┐   │
│  │         system_server                     │   │  ← Framework trust boundary
│  │  (AMS, PMS, WMS — uid: system)            │   │
│  ├───────────────────────────────────────────┤   │
│  │    System apps / Privileged apps          │   │  ← Privileged app boundary
│  │  (uid: system, radio, bluetooth, nfc)     │   │
│  ├───────────────────────────────────────────┤   │
│  │    Third-party apps (sandboxed)           │   │  ← App sandbox boundary
│  │  (unique UID, SELinux: untrusted_app)     │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
│              Hardware / Bootloader               │  ← Physical trust boundary
│  (Verified Boot, Secure Boot ROM, Fuses)         │
└─────────────────────────────────────────────────┘
```

### 4.2 Key Trust Boundary Details

- **App-to-App**: Each app has a unique Linux UID and dedicated data directory (`/data/data/<pkg>`). SELinux labels apps as `untrusted_app` (or variants like `untrusted_app_25`, `untrusted_app_27` for API level targeting). Apps from the same developer can share a UID via `sharedUserId` (deprecated in Android 13+).
- **App-to-Framework**: Apps invoke system services via Binder. The service checks the caller's UID, PID, and granted permissions before servicing requests. This is the most heavily exercised trust boundary.
- **Framework-to-Kernel**: System services invoke syscalls. seccomp-bpf profiles restrict which syscalls are available to each process. SELinux restricts which kernel resources (device nodes, files, sockets) each process can access.
- **Normal World to Secure World**: Communication with TrustZone TAs occurs via SMC (Secure Monitor Call) instructions. The interface is narrow by design but driver bugs in the normal-world TEE driver (e.g., Qualcomm's QSEE driver, Trustonic's `mobicore` driver) have been exploited (CVE-2015-6639, CVE-2016-2431).
- **User-to-Device**: Lockscreen authentication (PIN, pattern, password, biometrics) forms a trust boundary. Gatekeeper (or Weaver on newer devices) runs in the TEE and enforces rate-limiting and credential verification.

---

## 5. The Android Treble Architecture

### 5.1 Overview

Introduced in Android 8.0 (Oreo), **Project Treble** re-architected the boundary between the Android OS framework and vendor-specific (SoC/OEM) code. The core motivation was faster OS updates, but the architectural changes had significant security implications.

### 5.2 Architectural Changes

**Before Treble:** Vendor code (HAL implementations, kernel drivers, proprietary daemons) was deeply intertwined with the framework. A framework update required vendor code to be rebuilt and retested, creating a bottleneck.

**After Treble:**
- A **Vendor Interface (VINTF)** was defined, separating the system partition (`/system`) from the vendor partition (`/vendor`).
- HALs were moved into their own processes (**binderized HALs**) communicating via `hwbinder` with HIDL (and later stable AIDL) interfaces.
- A **Vendor NDK (VNDK)** restricted which system libraries vendor code could link against.
- **hwbinder** and **vndbinder** domains were introduced, separating vendor IPC from framework IPC.

### 5.3 Security Implications

| Aspect | Impact |
|---|---|
| **Reduced blast radius** | A compromised HAL process no longer runs in the same address space as a framework service. Process isolation + SELinux confine each HAL. |
| **Clearer SELinux policy separation** | Vendor and system SELinux policies are compiled separately and combined at boot. This prevents vendor code from inadvertently (or intentionally) weakening system policy. |
| **Faster updates** | The system image can be updated independently of the vendor image. Generic System Images (GSIs) enable framework updates without vendor cooperation for Treble-compliant devices. |
| **Persistent vendor attack surface** | The vendor partition may remain on an older, unpatched version even when the system partition is updated. This creates a split where kernel and vendor HALs may lag behind. |
| **HIDL/AIDL interface attack surface** | The introduction of serialized IPC between system and vendor introduces new deserialization attack surface. Fuzzing of HIDL/AIDL interfaces has revealed bugs. |
| **Vendor init and sepolicy** | Vendors can add their own init services and SELinux policy, which may be less well-audited than AOSP code. |

### 5.4 VINTF and Compatibility Matrix

The Vendor Interface Object (VINTF) declares which HALs the vendor provides and which the framework expects. A mismatch prevents boot, enforcing API stability but also ensuring that the security contract (which services run at which privilege level) is maintained.

---

## 6. Project Mainline

### 6.1 Overview

Introduced in Android 10, **Project Mainline** (formally "Modular System Components") allows Google to update core OS components directly via the Google Play Store infrastructure, bypassing OEM and carrier update pipelines.

### 6.2 Updatable Modules (as of Android 15)

Mainline modules are delivered as **APEX** (Android Pony EXpress) packages — a container format with dm-verity protection for native code and a standard APK for Java code. Key security-relevant modules include:

| Module | Security Relevance |
|---|---|
| **Conscrypt (TLS)** | Certificate validation, TLS implementation; critical for MITM prevention |
| **DNS Resolver** | DNS-over-TLS, DNS-over-HTTPS; protects against DNS spoofing |
| **Media codecs** | Historically the largest remote attack surface; Mainline updates enable rapid patching |
| **Permission Controller** | Central permission enforcement UI |
| **DocumentsUI** | File access framework; storage scoping |
| **Network Stack (Tethering, Captive Portal)** | Network configuration, DHCP, captive portal detection |
| **Wi-Fi** | Wi-Fi service and framework; updatable since Android 12 |
| **Bluetooth** | Bluetooth stack; updatable since Android 13 |
| **UWB** | Ultra-wideband ranging; new in Android 13 |
| **IPsec / IKEv2** | VPN stack |
| **Statsd** | Metrics collection |
| **CellBroadcast** | Emergency alert handling |
| **adservices** | Privacy Sandbox / ad attribution |
| **ondevicepersonalization** | On-device ML model management |
| **HealthFitness** | Health Connect API |

### 6.3 Security Model Impact

- **Faster patch deployment**: Critical bugs in media codecs or the TLS stack can be patched within days across all Mainline-supported devices, instead of waiting for monthly or quarterly OEM security updates.
- **Reduced OEM fragmentation**: The same Conscrypt or media codec version runs across Samsung, Pixel, Xiaomi, etc., reducing the surface area auditors need to cover.
- **APEX integrity**: APEX packages are verified using dm-verity at mount time. The signing key is controlled by Google, establishing a trust anchor.
- **Rollback protection**: APEX supports rollback protection via verified boot's rollback index.
- **Limitations**: Mainline cannot update the kernel, vendor HALs, or bootloader. These remain dependent on OEM/SoC vendor pipelines.

---

## 7. TEE — Trusted Execution Environment

### 7.1 ARM TrustZone

Most Android devices use ARM processors with **TrustZone** — a hardware-enforced separation between a "Normal World" (where Android runs) and a "Secure World" (where a TEE OS runs). The TEE OS (e.g., Qualcomm QSEE/SPU, Trustonic Kinibi, Google Trusty) hosts **Trusted Applications (TAs)** that perform security-sensitive operations.

The Normal World cannot access Secure World memory, but the Secure World can access Normal World memory. Communication occurs via the SMC instruction and a shared memory region.

### 7.2 Keymaster / KeyMint

**Keymaster** (replaced by **KeyMint** starting Android 12) is a TEE-hosted TA that provides:
- Hardware-backed key generation and storage
- Key usage binding to device state (verified boot, lockscreen authentication)
- Key attestation (cryptographic proof that a key was generated in hardware)
- Key access control (requiring user authentication via Gatekeeper/Weaver or biometrics)

**Security implications:**
- Keys stored in the TEE cannot be extracted even if the Android OS is fully compromised.
- Key attestation enables servers to verify that a client's key is genuinely hardware-backed, combating device spoofing.
- ID attestation binds device identifiers to the TEE, though this is optional and privacy-sensitive.

### 7.3 StrongBox

Introduced in Android 9, **StrongBox** is a discrete, tamper-resistant hardware security module (commonly a secure element or embedded SE). StrongBox provides a higher assurance level than TrustZone because:
- It has its own CPU, memory, and RNG, isolated from the application processor.
- It resists physical attacks (side-channel, glitching, probing).
- It meets requirements similar to Common Criteria EAL 4+ / AVA_VAN.5.

Google Pixel devices implement StrongBox via the **Titan M2** chip. Samsung uses **eSE (embedded Secure Element)** or Samsung's **SSP (Samsung Secure Processor)**.

### 7.4 TEE Attack Surface

Despite its isolation, the TEE is not immune to attack:
- **Normal-world TEE drivers**: The kernel driver that mediates communication with the Secure World (e.g., `/dev/qseecom`, `/dev/mobicore`) has been a source of privilege escalation bugs.
- **TEE OS vulnerabilities**: Bugs in the Secure World OS itself (e.g., Qualcomm QSEE integer overflows, Trustonic Kinibi memory corruption) can be exploited from the Normal World if the attacker can reach the SMC interface (typically requires kernel-level access first).
- **TA vulnerabilities**: Individual Trusted Applications (e.g., DRM TAs like Widevine) can have bugs that allow code execution within the Secure World (CVE-2015-6639 in Qualcomm QSEE Widevine TA).
- **Side-channel attacks**: TrustZone shares the CPU and cache hierarchy with the Normal World, making it vulnerable to cache-timing attacks and speculative execution attacks in theory.

### 7.5 Android Protected Confirmation

**Android Protected Confirmation** (Android 9+) uses the TEE to display a hardware-protected UI prompt that cannot be spoofed by a compromised Android OS. The TEE signs the user's confirmation, providing cryptographic assurance that the user saw and approved a specific message. This is used for high-assurance transaction confirmation.

---

## 8. Bootloader and Firmware

### 8.1 Secure Boot Chain

Android devices implement a **chain of trust** starting from a hardware root of trust (typically ROM or fuses):

```
Boot ROM (immutable, in silicon)
  → Bootloader Stage 1 (BL1)
    → Bootloader Stage 2 (BL2 / ABL / LK)
      → Linux Kernel + dtb
        → System / Vendor images (dm-verity)
```

Each stage verifies the signature of the next before executing it. **Android Verified Boot (AVB)** protects the kernel and all read-only partitions.

### 8.2 Bootloader Unlocking

Most Android devices allow **OEM unlocking**, which disables Verified Boot enforcement. This is a deliberate user action that:
- Requires a developer option toggle + a physical button press during boot
- Wipes all user data (factory reset)
- Sets a **tamper-evident flag** (the "orange" boot state) visible at boot and queryable via key attestation

**Security implications:** An unlocked bootloader allows booting unsigned code, enabling full device compromise. However, the tamper-evident state means attestation-relying services can detect the modification. Enterprise MDM solutions can enforce locked bootloaders.

### 8.3 Baseband Processor

The baseband (modem) processor handles cellular radio communication (2G/3G/4G/5G). It runs its own RTOS (typically a proprietary stack from Qualcomm, Samsung Shannon, MediaTek, etc.) and operates on a separate processor, but historically has had access to shared memory with the application processor.

**Attack surface:**
- **Over-the-air**: An attacker with a rogue base station (IMSI catcher, rogue eNodeB) can send crafted radio layer messages to the baseband. Bugs in protocol parsing (RRC, NAS, RLP, SIP) can yield code execution on the baseband processor.
- **Remote via network**: SMS/MMS processing, SIP call handling, IMS (IP Multimedia Subsystem) protocol handling.
- **Baseband-to-AP escalation**: A compromised baseband may be able to access application processor memory via shared memory regions or DMA, depending on hardware isolation (IOMMU configuration). This is a critical trust boundary that varies by SoC.

**Notable baseband vulnerabilities:** Samsung Shannon baseband bugs (Project Zero, 2023), Qualcomm MSM bugs (CVE-2020-11292), MediaTek baseband RCE (CVE-2022-32402).

**Mitigations:** Modern SoCs increasingly use IOMMUs to isolate baseband DMA, and some move to separate chips entirely. Samsung's "Baseband Hardening" initiative adds ASLR and stack canaries to the baseband firmware.

### 8.4 Firmware Attack Surface — Other Processors

Modern Android devices contain numerous auxiliary processors, each running firmware:
- **Wi-Fi SoC firmware** (e.g., Broadcom/Cypress FullMAC chips): Broadpwn (CVE-2017-9417) demonstrated RCE on the Wi-Fi chip from a nearby attacker.
- **Bluetooth controller firmware**: Separate from the host stack; BlueBorne-style attacks targeted both.
- **DSP firmware** (e.g., Qualcomm Hexagon DSP / ADSP / CDSP): Accessible from Android via FastRPC; Check Point's "Achilles" research (2020) found over 400 vulnerabilities in Hexagon DSP code.
- **GPU firmware / microcontroller**: Increasingly complex; ARM Mali and Qualcomm Adreno have firmware components.
- **Sensor hub firmware**: Low-power processor for always-on sensor processing.
- **NFC controller firmware**: Runs an RTOS; receives crafted data from NFC tags and readers.

---

## 9. Android Architecture Evolution — Security-Relevant Changes

### Android 4.x (2011–2014) — Foundation

- **4.0**: Full-disk encryption (optional), VPN API, `KeyChain` API
- **4.1**: ASLR for all processes, `READ_LOGS` permission removed from third-party apps
- **4.2**: Application verification (`Verify Apps`), SELinux in permissive mode, `ContentProvider` default exported=false for targetSdk≥17, SecureRandom fix
- **4.3**: SELinux enforcing for core domains (`installd`, `netd`, `vold`, `zygote`), restricted `setuid`/`setgid` programs, `KeyStore` provider improvements
- **4.4**: Full SELinux enforcing mode, verified boot (dm-verity) for system partition, default SMS app model (restricted `SMS_RECEIVED` broadcast), `ART` runtime introduced (optional)

### Android 5.x (2014–2015) — Lollipop

- ART as default runtime (replacing Dalvik) — harder to exploit JIT spraying
- Full-disk encryption mandatory (on capable devices)
- SELinux enforcing for all processes (no more permissive domains for apps)
- `Smart Lock` (trusted agents for lock screen)
- Guest/multi-user mode (user data isolation)
- `WebView` updated via Play Store (decoupled from OS)

### Android 6.0 (2015) — Marshmallow

- **Runtime permissions**: Apps must request dangerous permissions at runtime, not just at install time — fundamental change to the permission trust model
- Verified Boot with error correction (forward error correction for dm-verity)
- Hardware-backed `KeyStore` required for devices with fingerprint
- Fingerprint API (standardized biometric authentication)
- `adoptable storage` encryption

### Android 7.x (2016–2017) — Nougat

- **File-based encryption (FBE)**: Replaced full-disk encryption; enables Direct Boot
- **Network Security Config**: Per-app TLS trust configuration (custom CAs, certificate pinning)
- MediaServer split into multiple processes (`mediaextractor`, `mediacodec`, etc.) with individual seccomp-bpf profiles — direct response to Stagefright
- `StrictMode` improvements, APK signature scheme v2 (whole-file signing)
- Default removal of user-added CAs from the system trust store for apps targeting N+

### Android 8.x (2017–2018) — Oreo — Project Treble

- **Project Treble**: HAL process isolation, HIDL, hwbinder/vndbinder separation
- Seccomp-bpf for all apps (not just mediaserver)
- `WebView` multiprocess mode (renderer in separate sandboxed process)
- Install-unknown-apps permission (per-source, replacing global toggle)
- Background execution limits (reduce persistent spyware capability)
- `android.permission.ANSWER_PHONE_CALLS` — previously any app could answer calls
- Google Play Protect on-device ML scanning

### Android 9 (2018) — Pie

- **StrongBox KeyStore** (hardware SE)
- **Android Protected Confirmation** (TEE-protected UI)
- **BiometricPrompt** (unified biometric API with strength classification)
- `FLAG_SECURE` enforcement improvements
- Locked-down access to `/proc/net` (information leak mitigation)
- DNS-over-TLS by default (Private DNS)
- Restrictions on background access to camera, microphone, sensors
- MAC address randomization (per-network)
- `READ_CLIPBOARD` restrictions for background apps

### Android 10 (2019) — Q

- **Project Mainline** (APEX updatable modules)
- **Scoped Storage**: Apps can no longer freely access external storage; must use `MediaStore` or SAF
- Background location access requires separate permission (`ACCESS_BACKGROUND_LOCATION`)
- TLS 1.3 by default
- Restrictions on launching activities from background
- Boundary for app access to device identifiers (IMEI, serial number) — requires `READ_PRIVILEGED_PHONE_STATE`
- `execute-only` memory for native code (AArch64)

### Android 11 (2020) — R

- One-time permissions (camera, microphone, location)
- Auto-reset permissions for unused apps
- Scoped storage enforcement for all apps
- `foregroundServiceType` requirement
- Package visibility restrictions (`<queries>`) — apps cannot enumerate all installed packages
- Heap pointer tagging (ARM TBI) — probabilistic use-after-free detection
- Async `APK Signature Scheme v4` for incremental installation integrity

### Android 12 (2021) — S

- **Privacy Dashboard** — visual log of permission usage
- Approximate location permission option
- Microphone/camera indicators and quick toggles
- Clipboard access notifications
- **Bluetooth permissions refactoring** — `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE` replace legacy blanket permissions
- **Wi-Fi module** made Mainline-updatable
- `MANAGE_EXTERNAL_STORAGE` audit and restriction
- Generic Kernel Image (GKI) enforced for new devices — uniform kernel base with vendor modules
- Kernel CFI enforced
- `compat-change` framework for safer API behavior changes

### Android 13 (2022) — Tiramisu

- Photo picker (no need for broad storage access)
- Per-app language settings
- Notification permission (`POST_NOTIFICATIONS`) — now a runtime permission
- Intent filter matching tightened (exported receivers must explicitly declare intent filters)
- Bluetooth module made Mainline-updatable
- `sharedUserId` deprecated — long-standing cross-app trust mechanism removed
- Wi-Fi and UWB ranging permissions
- Credential Manager API (passkeys / FIDO2 integration)
- Foreground Service Task Manager (user can stop any foreground service)

### Android 14 (2023) — Upside Down Cake

- Minimum target SDK enforced (cannot install apps targeting SDK < 23 / Android 6.0)
- Credential Manager API expansion (passwordless authentication)
- Restrictions on implicit intents and pending intents
- Background activity launch restrictions tightened further
- Screenshot detection API (legitimate use without `MEDIA_PROJECTION`)
- Partial photos/videos access (fine-grained media permission)
- Block installation of apps with malformed manifests
- Lockdown of dynamic code loading (DCL) files — must be marked read-only
- `targetSdkVersion` enforcement for SDK Runtime

### Android 15 (2024) — Vanilla Ice Cream

- Lockdown mode improvements
- File integrity protection API (fs-verity for app files)
- Partial screen sharing (single app, not full screen)
- Enhanced screen recording indicators
- Private Space (sandboxed user profile for sensitive apps)
- More restrictive background activity launches
- ABI-level hardening: MTE (Memory Tagging Extension) enabled by default on supported hardware (Pixel 8+), providing deterministic detection and probabilistic mitigation of spatial and temporal memory safety bugs in native code
- 16 KB page size support for improved ASLR entropy
- Credential Manager enhancements for passkey ecosystems
- NFC tap-to-pay security improvements
- Health Connect permission hardening

---

## 10. Summary: Layered Defense Model

Android's security architecture follows a **defense-in-depth** strategy where no single layer is trusted in isolation:

1. **Hardware root of trust** anchors the boot chain (Secure Boot ROM → Verified Boot → dm-verity).
2. **TEE/StrongBox** protects cryptographic keys and critical security operations from software compromise.
3. **Kernel hardening** (SELinux, seccomp-bpf, KASLR, CFI, MTE) limits the impact of memory corruption bugs.
4. **Process isolation** (Treble HALs, media codec sandboxing) confines compromise to individual services.
5. **Framework permission enforcement** restricts what applications can access.
6. **App sandboxing** (unique UIDs, separate data directories, SELinux labels) isolates applications from each other.
7. **Project Mainline** enables rapid patching of critical components without waiting for OEM update cycles.
8. **Play Protect** provides on-device ML-based detection of malicious applications.

The attack surface remains vast — billions of lines of code across kernel, vendor firmware, native libraries, and the Java framework — but the layered architecture ensures that exploitation of a single vulnerability rarely yields full device compromise without chaining multiple bugs across trust boundaries.

---

*This document was prepared as part of the Android Architecture and Vulnerabilities research report. All CVE references are included for illustrative purposes and refer to publicly disclosed vulnerabilities.*
