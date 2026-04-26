# Android Security Model and Defense Mechanisms

## Table of Contents

1. [Application Sandboxing](#1-application-sandboxing)
2. [Permission System](#2-permission-system)
3. [SELinux on Android (SEAndroid)](#3-selinux-on-android-seandroid)
4. [Verified Boot / Android Verified Boot (AVB)](#4-verified-boot--android-verified-boot-avb)
5. [File-Based Encryption (FBE)](#5-file-based-encryption-fbe)
6. [Network Security](#6-network-security)
7. [SafetyNet / Play Integrity API](#7-safetynet--play-integrity-api)
8. [Scoped Storage](#8-scoped-storage)
9. [Memory Safety Mitigations](#9-memory-safety-mitigations)
10. [GKI (Generic Kernel Image) and Kernel Hardening](#10-gki-generic-kernel-image-and-kernel-hardening)

---

Android's security architecture is designed as a layered defense-in-depth system. No single mechanism is expected to be impenetrable; instead, each layer constrains the blast radius of a compromise at the layer below or above it. This document provides a technical examination of each major defense mechanism, how they interrelate, and where their boundaries lie.

---

## 1. Application Sandboxing

Application sandboxing is the foundational security primitive in Android. It enforces the principle of least privilege at the OS level, ensuring that each application operates within a tightly constrained environment.

### UID-Based Isolation

Android leverages the Linux multiuser model in a non-traditional way: each installed application is assigned a unique Linux user ID (UID) at install time. While traditional Linux uses UIDs to separate human users, Android repurposes them to separate applications. The UID is typically assigned from the range `10000`-`19999` (the `AID_APP_START` to `AID_APP_END` range defined in `system/core/libcutils/include/private/android_filesystem_config.h`). This means:

- Each app's files are owned by its unique UID and are mode `0600` or `0700` by default, preventing other apps from reading or writing them.
- Kernel-level DAC (Discretionary Access Control) enforces that process A (UID 10045) cannot read the files of process B (UID 10078) through standard filesystem permission checks.
- Apps that need to share data must explicitly opt in via `sharedUserId` (deprecated as of Android 13) or use content providers, bound services, or other IPC mechanisms.

System processes run under well-known UIDs with lower values (e.g., `system` is UID 1000, `radio` is UID 1001), and these carry specific DAC privileges.

### Process Isolation

Each Android application runs in its own Dalvik/ART virtual machine instance within a dedicated Linux process. The Zygote process forks to create new app processes, which inherit a pre-warmed runtime but immediately diverge in UID, SELinux context, and namespace configuration. Key aspects include:

- **PID namespace isolation**: While Android does not use full PID namespaces for apps (unlike containers), each app process is a distinct PID that the kernel tracks independently.
- **Filesystem view**: Apps access a restricted view of the filesystem. Directories like `/data/data/<package_name>/` are private to the app.
- **IPC restrictions**: Binder, Android's primary IPC mechanism, enforces caller UID/PID checks. The `servicemanager` process acts as a gatekeeper, and individual services validate the identity of callers through `Binder.getCallingUid()`.

### Seccomp-BPF Filters

Starting with Android 8.0 (Oreo), seccomp-BPF (Secure Computing with Berkeley Packet Filters) is applied to all application processes. The Zygote applies a seccomp filter before forking app processes, restricting the set of system calls available:

- The filter operates as an allowlist: system calls not on the list are blocked, and the process receives a `SIGKILL` or `SIGSYS` signal (configurable per-policy).
- This drastically reduces the kernel attack surface. Historically, many kernel vulnerabilities have been reachable through obscure or rarely-used syscalls (e.g., `keyctl`, `recvmmsg`, `add_key`). By blocking these at the seccomp layer, an attacker who has achieved code execution within an app process cannot invoke them.
- The filter is architecture-specific. ARM64 processes receive a different filter profile than ARM32 processes, reflecting the different syscall ABIs.
- System apps and services may run with more permissive seccomp profiles depending on their operational requirements.

The combination of UID isolation, process isolation, and seccomp-BPF creates a robust sandbox that requires multiple independent bypasses to escape.

---

## 2. Permission System

Android's permission system mediates access to sensitive APIs and user data. It has evolved significantly across Android versions.

### Permission Protection Levels

Permissions are classified by protection level:

- **Normal permissions** (`PROTECTION_NORMAL`): Granted automatically at install time. These cover low-risk operations such as setting the time zone, accessing network state, or setting the wallpaper. The user is not prompted.
- **Dangerous permissions** (`PROTECTION_DANGEROUS`): Guard access to user-private data or device capabilities that could affect the user's privacy or stored data. Examples include `READ_CONTACTS`, `CAMERA`, `ACCESS_FINE_LOCATION`, and `READ_EXTERNAL_STORAGE`. These require explicit user approval at runtime (Android 6.0+).
- **Signature permissions** (`PROTECTION_SIGNATURE`): Granted only if the requesting app is signed with the same certificate as the app or the platform that declared the permission. This is the primary mechanism for protecting inter-app APIs that should only be used by trusted components. For example, `MANAGE_USB` is a signature permission that only system-signed apps can hold.
- **Signature|Privileged** (`PROTECTION_SIGNATURE|PRIVILEGED`): A variant that also grants the permission to apps pre-installed in the `/system/priv-app/` partition, even if signed with a different key. Access is further gated by the `privapp-permissions-<package>.xml` allowlists introduced in Android 8.0.

### Runtime Permissions (Android 6.0+)

Before Android 6.0 (Marshmallow), all permissions were granted at install time on an all-or-nothing basis. The runtime permission model changed this:

- Dangerous permissions must be requested at the point of use via `ActivityCompat.requestPermissions()`.
- The user can grant or deny individual permissions independently.
- The user can revoke permissions at any time through Settings.
- If a permission is denied twice with the "Don't ask again" option selected, subsequent requests are auto-denied and the app must direct the user to Settings manually.

### Permission Groups

Dangerous permissions are organized into groups (e.g., `LOCATION` group contains `ACCESS_FINE_LOCATION` and `ACCESS_COARSE_LOCATION`). Historically, granting one permission in a group implicitly granted all others in the same group, but this behavior has been tightened in recent Android versions. Android 12 introduced the ability to grant approximate location independently of precise location.

### Auto-Revocation of Unused Permissions

Android 11 introduced automatic permission revocation (also called "permission auto-reset"). If an app is not used for an extended period (typically a few months), the system automatically resets its dangerous permissions. This limits the long-term risk of apps that accumulate permissions and then sit dormant. Android 13 extended this feature to apps targeting API level 23 and above by default on GMS devices.

### Additional Permission Hardening

- **One-time permissions** (Android 11): Users can grant location, camera, or microphone access for a single session only. The permission is revoked when the app goes to the background.
- **Permission indicators** (Android 12): Visual indicators in the status bar show when an app is actively using the camera or microphone.
- **Nearby device permission** (Android 12): Decoupled Bluetooth scanning from location permissions.
- **Photo picker** (Android 13): Apps can access user-selected photos without requiring broad media permissions.

---

## 3. SELinux on Android (SEAndroid)

Mandatory Access Control (MAC) via SELinux is one of the most consequential security additions to Android, deployed starting with Android 4.3 (permissive) and enforced since Android 5.0 (Lollipop).

### Mandatory Access Control Fundamentals

Unlike DAC (which relies on file ownership and permission bits that processes can modify), SELinux enforces a centralized policy that no process, regardless of its UID, can bypass. Even if an attacker gains root-equivalent UID 0, SELinux policies can prevent the process from accessing resources outside its defined domain.

### Policy Structure

SEAndroid policies are written in a combination of Common Intermediate Language (CIL) and the traditional SELinux policy language (m4 macros). The policy consists of:

- **Type declarations**: Every process runs in a *domain* (a process type), and every file/object has a *type*. For example, `untrusted_app` is the domain for third-party apps, and `app_data_file` is the type for their private data.
- **Type Enforcement (TE) rules**: `allow` statements specify which domains can perform which operations on which types. For example: `allow untrusted_app app_data_file:file { read write open create };`
- **Type transitions**: Automatically assign types when processes are forked or files are created, ensuring that new objects inherit the correct security context.
- **Attribute-based grouping**: Domains and types can be grouped via attributes (e.g., `appdomain` groups all app domains) to write rules that apply broadly.

### Domains and Types in Android

Key domains include:

| Domain | Description |
|--------|-------------|
| `init` | The init process (PID 1) |
| `kernel` | Kernel threads |
| `system_server` | The core system_server process |
| `untrusted_app` | Third-party applications |
| `priv_app` | Privileged system applications |
| `isolated_app` | Renderer processes (e.g., WebView) with no permissions |
| `hal_*` | Hardware Abstraction Layer services |
| `vendor_init` | Vendor-specific init scripts |
| `su` | Superuser (heavily restricted on production builds) |

### Neverallow Rules

`neverallow` rules are compile-time assertions that prevent policy authors from accidentally introducing overly permissive rules. They are checked by `checkpolicy` and the CTS (Compatibility Test Suite). Examples include:

- `neverallow untrusted_app kmem_device:chr_file *;` -- No third-party app may access `/dev/kmem`.
- `neverallow { domain -init -kernel } self:capability sys_rawio;` -- Only init and kernel may use raw I/O.
- `neverallow * kernel:security *;` -- No domain may modify the SELinux security server state.

Google enforces a set of platform neverallow rules through CTS. OEMs that add custom policy must not violate these constraints, or their devices fail CTS certification.

### Policy Evolution

- **Android 4.3**: SELinux in permissive mode; logs violations but does not enforce.
- **Android 5.0**: Full enforcement for all system domains.
- **Android 8.0 (Treble)**: Policy split into *platform* and *vendor* partitions. The platform policy is maintained by Google, and vendor policy is maintained by the OEM. A compatibility mapping layer (`mapping/`) allows the platform to evolve its types without breaking vendor policy.
- **Android 11+**: Further policy modularization with APEX modules carrying their own SELinux policy fragments.

---

## 4. Verified Boot / Android Verified Boot (AVB)

Verified Boot establishes a chain of trust from the hardware root of trust through the bootloader, kernel, and system partitions.

### Chain of Trust

1. **Hardware Root of Trust**: A tamper-resistant component (often a secure element or ROM-based key) verifies the first-stage bootloader.
2. **Bootloader stages**: Each bootloader stage verifies the cryptographic signature of the next stage before executing it.
3. **Boot image verification**: The bootloader verifies the `boot.img` (containing the kernel and ramdisk) against a signature embedded in the `vbmeta` image.
4. **System partition verification**: `dm-verity` verifies system partition blocks at read time.

### dm-verity

`dm-verity` is a device-mapper target in the Linux kernel that provides transparent integrity checking of block devices. It works by:

- Computing a Merkle tree (hash tree) over the entire partition at build time.
- Storing the root hash in the `vbmeta` image, which is signed by the OEM's key.
- At runtime, each block read from the partition is verified against the hash tree. If a block has been tampered with, the I/O returns an error (or the device reboots, depending on the mode).

This ensures that even if an attacker gains write access to the system partition (e.g., through a bootloader unlock or a kernel exploit), any modification is detected.

### vbmeta and Rollback Protection

The `vbmeta` structure (defined by libavb) contains:

- Hash descriptors for each verified partition.
- The public key used for verification.
- A **rollback index**: a monotonically increasing counter stored in tamper-evident storage (e.g., RPMB on eMMC). This prevents an attacker from flashing an older, vulnerable image that would still pass signature verification. Each vbmeta image declares a minimum rollback index, and the bootloader refuses to boot images with an index lower than the stored value.

### Verified Boot States

The bootloader reports the verified boot state to the kernel via properties:

- **Green (Locked)**: All partitions verified against OEM keys. Full chain of trust intact.
- **Yellow**: Boot image verified against a user-provided key (custom ROM with locked bootloader).
- **Orange (Unlocked)**: Bootloader unlocked; verification disabled. A warning is displayed at boot.
- **Red**: Verification failed. The device refuses to boot (or displays a persistent warning).

---

## 5. File-Based Encryption (FBE)

Android transitioned from Full-Disk Encryption (FDE) to File-Based Encryption (FBE) starting with Android 7.0, with FBE becoming mandatory on Android 10+.

### How FBE Works

FBE uses the Linux kernel's `fscrypt` framework (previously `ext4 encryption`) to encrypt file contents and names on a per-file basis using AES-256-XTS for file contents and AES-256-CTS (or Adiantum on low-end hardware) for file names.

### CE and DE Storage

FBE introduces two storage classes:

- **Credential Encrypted (CE) storage** (`/data/user_ce/<user_id>/`): Encrypted with a key derived from the user's lock screen credential (PIN, pattern, password) combined with a hardware-bound key from the Trusted Execution Environment (TEE) or Strongbox. CE storage is only available *after* the user unlocks the device for the first time after boot (Direct Boot completes). This is where most app data lives.
- **Device Encrypted (DE) storage** (`/data/user_de/<user_id>/`): Encrypted with a key bound to the hardware but *not* to the user credential. DE storage is available immediately after boot, before the user unlocks the device. This allows essential services (alarm clock, phone dialer, accessibility services) to function in the Direct Boot state.

### Metadata Encryption

Android 9 introduced metadata encryption, which encrypts the filesystem metadata (file sizes, layout, and attributes) that `fscrypt` does not cover. This uses `dm-default-key`, a device-mapper target that encrypts all sectors on the underlying block device with a hardware-wrapped key. Combined with FBE, this ensures that even a physical attacker performing a chip-off attack sees no meaningful plaintext.

### Key Hierarchy

The encryption key derivation involves multiple layers:

1. **User credential** (PIN/password/pattern) is combined with a **scrypt/Argon2** derived secret.
2. This is further bound to a **hardware-bound key** in the TEE/Strongbox via Keymaster/KeyMint HAL.
3. The resulting key encrypts a randomly-generated **per-file key** (or per-CE/DE class key in some modes).

This hierarchy ensures that brute-forcing the credential requires interaction with rate-limited hardware.

---

## 6. Network Security

Android provides several mechanisms to secure network communications at the application and platform level.

### Network Security Config

Introduced in Android 7.0, the Network Security Config (`res/xml/network_security_config.xml`) allows apps to declaratively configure network security parameters:

- **Custom trust anchors**: Apps can specify which Certificate Authorities (CAs) they trust, overriding the system default. This is critical for apps that communicate only with their own backend.
- **Debug overrides**: Apps can allow additional CAs (e.g., an intercepting proxy) only in debug builds.
- **Certificate pinning**: Apps can pin specific certificates or public keys for their domains, rejecting connections to servers presenting different certificates even if signed by a trusted CA.
- **Cleartext traffic restrictions**: Apps can declare `cleartextTrafficPermitted="false"` to block all unencrypted HTTP connections. Since Android 9, cleartext traffic is blocked by default for apps targeting API 28+.

### Platform-Level Enforcement

- **TLS version restrictions**: Android has progressively deprecated older TLS versions. TLS 1.0 and 1.1 are disabled by default since Android 10.
- **DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH)**: Android 9+ supports Private DNS, which encrypts DNS queries system-wide.
- **Wi-Fi security**: Android 10+ supports WPA3, and Android 12+ supports opportunistic Wi-Fi encryption.

### Certificate Transparency

Android includes support for Certificate Transparency (CT) logs, helping detect misissued certificates. Chrome on Android enforces CT policies for web browsing.

---

## 7. SafetyNet / Play Integrity API

### SafetyNet Attestation (Legacy)

SafetyNet Attestation provided a device integrity signal by collecting device state information and sending it to Google's servers for evaluation. It returned a signed JWS (JSON Web Signature) response containing:

- `ctsProfileMatch`: Whether the device profile matches a CTS-certified device.
- `basicIntegrity`: Whether the device has not been tampered with (looser check).

SafetyNet could detect unlocked bootloaders, custom ROMs, root access, and certain hooking frameworks.

### Play Integrity API (Replacement)

The Play Integrity API, which supersedes SafetyNet, provides three levels of verdict:

- **Device integrity**: Whether the device runs a genuine Android build with a locked bootloader and passes verified boot.
- **App integrity**: Whether the calling app binary matches what was published on Google Play (detects repackaging and tampering).
- **Account integrity**: Whether the user has a licensed Google Play account.

The API uses hardware-backed attestation (KeyMint/Keymaster attestation) where available, making it significantly harder to spoof than software-only checks. The attestation certificate chain roots to a Google-controlled CA, and the device's TEE or Strongbox generates the attestation.

### Limitations and Bypass Landscape

These attestation mechanisms are designed to be an asymmetric defense: easy for legitimate devices and hard for modified ones. However, the cat-and-mouse dynamic is well documented. Projects that modify the boot image or hook framework code (e.g., Magisk with MagiskHide/Zygisk, or more recently various "Play Integrity Fix" modules) attempt to hide device modifications from the integrity checks. Google has responded by moving to hardware-level attestation signals that are harder to spoof from software alone.

---

## 8. Scoped Storage

### Motivation

Prior to Android 10, apps with `READ_EXTERNAL_STORAGE` or `WRITE_EXTERNAL_STORAGE` permissions had unrestricted access to the shared external storage (`/sdcard`), which contained photos, downloads, documents, and other apps' exported files. This was a significant privacy and security concern.

### Android 10+ Restrictions

Scoped Storage, enforced for apps targeting Android 11+ (with a transitional opt-out via `requestLegacyExternalStorage` on Android 10), restructures external storage access:

- **App-specific directories**: Each app gets a private directory at `/sdcard/Android/data/<package_name>/` and `/sdcard/Android/media/<package_name>/` that it can read/write without any permission.
- **MediaStore API**: Access to shared media (photos, videos, audio) goes through the `MediaStore` content provider. Apps can read their own contributed media without permissions and need `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, or `READ_MEDIA_AUDIO` (Android 13+) to access other apps' media.
- **Storage Access Framework (SAF)**: For non-media files (PDFs, documents), apps must use the SAF document picker, which gives the user explicit control over which files/directories an app can access. Grants are URI-based and can be persisted.
- **No direct filesystem path access**: Attempts to use `File` APIs to access paths outside the app's private directory are intercepted by the FUSE daemon, which enforces MediaStore permissions.

### Special Permissions

Apps that genuinely need broad filesystem access (e.g., file managers, backup utilities) can request `MANAGE_EXTERNAL_STORAGE`, which is a special permission granted through Settings and subject to Google Play policy review.

---

## 9. Memory Safety Mitigations

Memory corruption vulnerabilities remain the dominant class of critical Android vulnerabilities. Android deploys multiple layers of compiler- and hardware-based mitigations.

### ASLR (Address Space Layout Randomization)

Android has supported ASLR since Android 4.0 and full ASLR (including PIE -- Position Independent Executables) since Android 5.0. ASLR randomizes the base addresses of the stack, heap, shared libraries, and executable segments, making it difficult for exploits to predict memory layout. On 64-bit ARM devices, the entropy is significantly higher than on 32-bit, making brute-force approaches impractical.

### Stack Canaries

GCC/Clang stack canaries (also called stack protectors) are inserted before return addresses on the stack. If a buffer overflow overwrites the canary, the corruption is detected before the function returns, and the process is terminated. Android builds use `-fstack-protector-strong` by default, which protects functions that use local arrays or take addresses of local variables.

### Control Flow Integrity (CFI)

LLVM's CFI is deployed across Android's native codebase, including media frameworks, Bluetooth, NFC, and other attack-surface-heavy components. CFI validates that indirect calls (function pointers, virtual method calls, etc.) target valid functions of the expected type. This mitigates exploitation techniques that corrupt function pointers or vtable entries to redirect control flow. Android uses both forward-edge CFI (for indirect calls) and backward-edge protection (via Shadow Call Stack).

### Shadow Call Stack (SCS)

Shadow Call Stack maintains a separate, hidden copy of return addresses. When a function is called, the return address is pushed to both the regular stack and the shadow stack (stored in a register, typically `x18` on AArch64). On return, the address is taken from the shadow stack, rendering stack buffer overflow attacks that overwrite return addresses ineffective. SCS has been enabled in the Android kernel since Android 10 on ARM64.

### Integer Sanitizers (IntSan)

Undefined Behavior Sanitizer (UBSan) with integer overflow checks (`-fsanitize=integer`) is applied to security-critical components. Signed and unsigned integer overflows that would lead to undefined behavior or unexpected wrapping are trapped at runtime. This is particularly important in media codec code, where integer overflows have historically led to heap corruption (e.g., Stagefright-class vulnerabilities).

### Memory Tagging Extension (MTE)

ARMv8.5-A introduced MTE, which Android supports starting with Android 12 (developer option) and increasingly in production. MTE works by:

1. Assigning a 4-bit tag (stored in the top byte of a pointer via TBI -- Top Byte Ignore) to each memory allocation.
2. Tagging the corresponding physical memory granules (16-byte aligned) with the same 4-bit tag.
3. On every memory access, the hardware checks that the pointer tag matches the memory tag. A mismatch raises a fault.

MTE detects use-after-free, buffer overflows, and other spatial/temporal memory errors with minimal performance overhead (typically 1-3% in async mode). Android uses MTE in both userspace (selected system processes) and the kernel (KASAN-like in-field detection). In synchronous mode, it provides deterministic detection; in asymmetric or asynchronous mode, it provides probabilistic detection (1/16 chance per tag mismatch in the worst case) with lower overhead.

### Bound Sanitizer (BoundSan)

Applied to kernel code and selected userspace components, BoundSan inserts bounds checking for array accesses, catching out-of-bounds reads and writes that the compiler can statically reason about.

---

## 10. GKI (Generic Kernel Image) and Kernel Hardening

### The GKI Architecture

Historically, each Android device shipped a heavily modified Linux kernel, with vendor-specific patches, driver code, and configuration changes. This made it nearly impossible to deliver timely kernel security patches. The Generic Kernel Image (GKI) initiative, introduced with Android 11 and mandatory from Android 12 (for devices launching with that version), changes this:

- **GKI kernel**: A single, Google-built kernel binary (`Image.lz4`) that is common across all devices using the same architecture and kernel version. It contains the core kernel, common drivers, and all security hardening features.
- **Vendor modules**: Device-specific drivers and vendor code are delivered as loadable kernel modules (`.ko` files) that run against a stable Kernel Module Interface (KMI). The KMI is an ABI contract between the GKI kernel and vendor modules.
- **Updatability**: Because the GKI kernel is decoupled from vendor code, Google can push kernel security updates independently of the OEM's vendor BSP update cycle. GKI kernel updates can be delivered via Mainline (Project Mainline) mechanisms.

### Kernel Hardening Features

The GKI kernel ships with a hardened configuration that enables or mandates:

- **`CONFIG_CFI_CLANG`**: Kernel-mode Control Flow Integrity, preventing hijacking of indirect function calls in kernel code.
- **`CONFIG_SHADOW_CALL_STACK`**: Kernel Shadow Call Stack on ARM64.
- **`CONFIG_RANDOMIZE_BASE` (KASLR)**: Kernel Address Space Layout Randomization, randomizing the kernel's load address at boot.
- **`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`**: Zero-initializes heap allocations, preventing information leaks from uninitialized memory.
- **`CONFIG_KFENCE`**: A low-overhead sampling-based memory error detector for production kernels.
- **`CONFIG_ARM64_MTE`**: Support for Memory Tagging Extension in kernel mode.
- **`CONFIG_SECCOMP`**: Seccomp-BPF support for userspace sandboxing.
- **Read-only memory protections**: Marking kernel text and rodata as read-only post-init (`CONFIG_STRICT_KERNEL_RWX`), and marking page tables read-only.
- **`CONFIG_STATIC_USERMODEHELPER`**: Prevents attackers from abusing `call_usermodehelper()` to execute arbitrary binaries from kernel context.
- **Restricted `/dev/mem` and `/dev/kmem`**: Kernel memory access devices are either absent or heavily restricted.
- **SELinux in enforcing mode**: The kernel ensures SELinux cannot be switched to permissive mode at runtime on production builds.
- **W^X enforcement**: Memory pages cannot be simultaneously writable and executable, preventing basic code injection in both kernel and userspace.

### Kernel Module Restrictions

GKI enforces that only signed vendor modules can be loaded. Module loading is further restricted by SELinux policy, and the `modules.load` file controls which modules are loaded at boot. This prevents an attacker who gains filesystem write access from loading a malicious kernel module.

---

## Summary: Defense in Depth

Android's security model is not defined by any single mechanism but by the interaction and layering of all the mechanisms described above. An attacker targeting a modern Android device faces a formidable series of barriers:

| Layer | Mechanism | What It Prevents |
|-------|-----------|-----------------|
| Hardware | Verified Boot, TEE/Strongbox, MTE | Boot-time tampering, key extraction, memory corruption |
| Kernel | SELinux, seccomp-BPF, KASLR, CFI, SCS, GKI | Privilege escalation, kernel exploitation, policy bypass |
| Framework | Permissions, Scoped Storage, FBE | Unauthorized data access, cross-app data leakage |
| Network | TLS enforcement, cert pinning, Private DNS | Traffic interception, MITM attacks |
| Ecosystem | Play Integrity, app signing, Play Protect | Tampered apps, compromised devices |

Each layer is designed to assume the others may be compromised. SELinux constrains root processes. Verified Boot detects kernel modifications. MTE catches memory corruption that CFI misses. FBE protects data even if the filesystem is physically extracted. This defense-in-depth philosophy is why modern Android exploitation typically requires chaining multiple vulnerabilities across multiple layers, driving up the cost and complexity of attacks significantly. High-value exploit chains targeting fully-patched Android devices on the open market routinely command prices in the millions of dollars, reflecting the cumulative difficulty of defeating these layered defenses.
