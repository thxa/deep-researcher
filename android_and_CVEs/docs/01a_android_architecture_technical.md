# Android System Architecture: A Security-Focused Technical Analysis

## Table of Contents

1. [Architectural Overview](#architectural-overview)
2. [Linux Kernel Layer](#1-linux-kernel-layer)
3. [Hardware Abstraction Layer (HAL)](#2-hardware-abstraction-layer-hal)
4. [Android Runtime (ART)](#3-android-runtime-art)
5. [Native Libraries](#4-native-libraries)
6. [Application Framework](#5-application-framework)
7. [Applications Layer](#6-applications-layer)
8. [Boot Process and Chain of Trust](#7-boot-process-and-chain-of-trust)
9. [Binder IPC In Depth](#8-binder-ipc-in-depth)
10. [Cross-Layer Security Considerations](#9-cross-layer-security-considerations)

---

## Architectural Overview

Android's architecture follows a layered software stack model. Each layer provides services to the layer above it while abstracting the complexity beneath. From a security perspective, this layering creates distinct trust boundaries, privilege domains, and attack surfaces.

```
+-----------------------------------------------+
|            Applications Layer                  |  (Untrusted)
|  System Apps | Third-Party Apps | Instant Apps |
+-----------------------------------------------+
|          Application Framework                 |  (Privileged)
|  ActivityMgr | PkgMgr | ContentProviders | ... |
+-----------------------------------------------+
|   Android Runtime (ART)  |  Native Libraries  |  (Privileged)
|   DEX / OAT execution    |  Bionic, Media, SSL|
+-----------------------------------------------+
|     Hardware Abstraction Layer (HAL)           |  (Privileged / Kernel boundary)
|     HIDL / AIDL interfaces to drivers          |
+-----------------------------------------------+
|            Linux Kernel                        |  (Highest privilege)
|  Binder | Drivers | SELinux | seccomp | cgroups|
+-----------------------------------------------+
|         Bootloader / TEE / Hardware            |  (Root of trust)
+-----------------------------------------------+
```

The security model is fundamentally based on **process isolation** enforced by Linux kernel primitives (UIDs, namespaces, SELinux), with **Binder IPC** as the only sanctioned cross-process communication channel. Every layer boundary is a potential attack surface.

---

## 1. Linux Kernel Layer

### 1.1 Role and Version History

The Linux kernel is the foundation of Android's security model. It provides process isolation, memory management, the filesystem, networking, and the driver model. Android has historically lagged upstream Linux by several versions, creating a window where upstream-patched vulnerabilities remain exploitable on Android devices.

| Android Version | Typical Kernel Version | Notable Security Features Added          |
|-----------------|------------------------|------------------------------------------|
| 4.x (KitKat)   | 3.4 - 3.10            | SELinux enforcing, dm-verity             |
| 5.x (Lollipop) | 3.10 - 3.18           | Full-disk encryption mandatory           |
| 7.x (Nougat)   | 3.18 - 4.4            | File-based encryption, seccomp-bpf       |
| 8.x (Oreo)     | 4.4 - 4.9             | Project Treble, HIDL                     |
| 10              | 4.9 - 4.14            | KASLR mandatory, CFI                     |
| 11              | 4.14 - 5.4            | GKI (Generic Kernel Image)               |
| 12              | 5.4 - 5.10            | LTO + CFI by default in GKI             |
| 13              | 5.10 - 5.15           | Memory tagging (MTE) on ARMv9           |
| 14              | 5.15 - 6.1            | Rust in kernel modules, PAC/BTI          |

The introduction of the **Generic Kernel Image (GKI)** starting with Android 11 was a landmark security decision. By separating the core kernel from vendor modules, Google can ship kernel security patches independently of SoC vendors, reducing the patch gap from months to weeks.

### 1.2 Android-Specific Kernel Modifications

Android does not use a vanilla Linux kernel. It carries a set of out-of-tree patches and subsystems that have historically been major sources of vulnerabilities.

#### Wakelocks (now Wakeup Sources)

Wakelocks prevent the system from entering suspend. The original Android wakelock implementation was a contentious out-of-tree patch. It was eventually reworked upstream as `wakeup_sources` in the kernel's power management subsystem.

**Security relevance**: A malicious or buggy application holding wakelocks can cause denial-of-service through battery drain. The kernel exposes `/sys/power/wake_lock` and `/sys/power/wake_unlock` which must be protected by SELinux policy.

#### Ashmem (Android Shared Memory)

Ashmem (`drivers/staging/android/ashmem.c`) provides file-descriptor-based shared memory regions that can be passed between processes via Binder. Unlike POSIX shared memory, ashmem regions can be unpinned, allowing the kernel to reclaim memory under pressure.

```c
// Typical ashmem usage (simplified)
int fd = ashmem_create_region("my_region", SIZE);
ashmem_set_prot_region(fd, PROT_READ | PROT_WRITE);
void *ptr = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```

**Security relevance**: Ashmem has been the source of multiple privilege escalation vulnerabilities. CVE-2020-0069 exploited a race condition in ashmem to achieve arbitrary kernel read/write. As of Android 12+, ashmem is being replaced by `memfd_create()` which is upstream Linux and better audited.

#### ION Memory Allocator (now DMA-BUF Heaps)

ION was Android's unified memory allocator for multimedia buffers, GPU memory, and DMA operations. It managed multiple heap types (system, carveout, CMA) through a single `/dev/ion` interface.

**Security relevance**: The ION driver was a high-value attack target because:
- It ran in kernel context with direct access to physical memory.
- The ioctl interface was complex and vendor-extended.
- Multiple CVEs (CVE-2019-2025, CVE-2016-0728) targeted ION heap management.

ION has been replaced by the upstream **DMA-BUF heaps** framework (`/dev/dma_heap/`) starting in Android 12, reducing the Android-specific kernel attack surface.

#### Low Memory Killer (LMK)

The original in-kernel LMK (`drivers/staging/android/lowmemorykiller.c`) killed processes based on `oom_adj` scores when memory pressure was detected. It was replaced by `lmkd`, a userspace daemon using kernel memory pressure notifications (`PSI` - Pressure Stall Information).

**Security relevance**: The in-kernel LMK had access to all process memory state and operated at highest privilege. Moving it to userspace (`lmkd`) reduces the kernel attack surface and allows finer-grained SELinux policy enforcement.

### 1.3 Kernel Security Hardening

Modern Android kernels employ multiple hardening techniques:

- **KASLR** (Kernel Address Space Layout Randomization): Randomizes the kernel's virtual base address at boot.
- **PAN/PXN** (Privileged Access/Execute Never): Prevents the kernel from accessing or executing userspace memory.
- **CFI** (Control Flow Integrity): Prevents hijacking of indirect function calls (via Clang CFI).
- **SCS** (Shadow Call Stack): Protects return addresses from stack buffer overflows.
- **MTE** (Memory Tagging Extension): Hardware-based detection of use-after-free and buffer overflow on ARMv9.
- **seccomp-bpf**: Restricts system calls available to processes. Applied to all apps since Android 8.0.
- **SELinux**: Mandatory access control enforced in the kernel. Android uses a strict, deny-by-default policy.

---

## 2. Hardware Abstraction Layer (HAL)

### 2.1 Purpose and Architecture

The HAL sits between the Android framework and the Linux kernel drivers. It provides standardized interfaces for hardware capabilities (camera, sensors, audio, graphics, radio) without exposing kernel driver internals to higher layers.

Before Project Treble (Android 8.0), HALs were shared libraries (`.so` files) loaded directly into framework processes. This meant vendor-specific code ran in the same address space as privileged system services -- a significant security risk.

### 2.2 HIDL and AIDL Interfaces

**Project Treble** restructured HALs to run in separate processes, communicating via two interface definition languages:

**HIDL (HAL Interface Definition Language)** -- introduced in Android 8.0:

```hidl
// ICameraDevice.hal
interface ICameraDevice {
    getCameraCharacteristics()
        generates (Status status, CameraMetadata characteristics);
    open(ICameraDeviceCallback callback)
        generates (Status status);
};
```

HIDL HALs run as separate processes (or in `passthrough` mode for backward compatibility). The HIDL transport is built on top of Binder (specifically `hwbinder`), with its own SELinux domain (`hal_camera_default`, etc.).

**AIDL for HALs** -- replacing HIDL starting in Android 11:

```aidl
// ICameraDevice.aidl
interface ICameraDevice {
    CameraMetadata getCameraCharacteristics();
    void open(in ICameraDeviceCallback callback);
}
```

AIDL HALs unify the framework and HAL IPC mechanism onto a single Binder transport, simplifying the security model.

### 2.3 Security Implications

- **Process Isolation**: Each HAL runs in its own process with a dedicated SELinux context. A vulnerability in the camera HAL cannot directly compromise the audio HAL.
- **Attack Surface Reduction**: HAL processes have minimal permissions via seccomp filters and SELinux. A compromised HAL has far less reach than a compromised system server.
- **Vendor Code Sandboxing**: Since vendor HAL code is often closed-source and less audited, isolating it in separate processes limits blast radius.
- **`hwbinder` Separation**: Hardware Binder (`/dev/hwbinder`) is distinct from framework Binder (`/dev/binder`) and vndBinder (`/dev/vndbinder`). SELinux policy prevents cross-domain Binder calls, so an app cannot directly call a HAL.

```
App Process  --(binder)--> System Server --(hwbinder)--> HAL Process --> Kernel Driver
   [untrusted_app]          [system_server]              [hal_*_default]
```

---

## 3. Android Runtime (ART)

### 3.1 Evolution from Dalvik to ART

**Dalvik** (Android 1.0 - 4.4) used a register-based bytecode interpreter with a trace-based JIT compiler. Its security model relied on process isolation but had weaker internal memory safety.

**ART** (Android 5.0+) replaced Dalvik with key improvements:

| Feature              | Dalvik                | ART                           |
|----------------------|-----------------------|-------------------------------|
| Compilation          | JIT (trace-based)     | AOT + JIT (profile-guided)    |
| Executable format    | DEX (interpreted)     | OAT (native ELF wrapper)     |
| GC                   | Stop-the-world        | Concurrent, compacting        |
| Memory safety        | Limited               | Improved bounds checking      |

### 3.2 DEX Bytecode and the OAT Format

Android applications are compiled from Java/Kotlin source to **DEX** (Dalvik Executable) bytecode. DEX files are stored in APKs and contain class definitions, method bytecode, and constant pools.

At install time (or via profile-guided compilation), ART compiles DEX bytecode to native machine code stored in **OAT** (Of Ahead-of-Time) files. The OAT format is an ELF binary wrapping both the compiled native code and the original DEX data.

```
APK
 +-- classes.dex          (DEX bytecode)
 +-- classes2.dex         (multidex)
 +-- lib/arm64-v8a/*.so   (native libraries)
 +-- META-INF/            (signatures)
 +-- AndroidManifest.xml  (permissions, components)

After installation:
/data/dalvik-cache/arm64/
 +-- app@@com.example-XXX==@classes.dex  (OAT file)
```

### 3.3 Security Enforcement in ART

- **Bytecode Verification**: The DEX verifier checks bytecodes at install time for type safety, valid register usage, and method resolution. This prevents a class of attacks where malformed DEX manipulates the runtime.
- **Bounds Checking**: Array access is bounds-checked at runtime, preventing buffer overflows in managed code.
- **Null Pointer Checks**: Null dereferences are caught and converted to `NullPointerException` rather than segfaults.
- **Sandboxed JIT Code**: JIT-compiled code is mapped with W^X (write XOR execute) protections. Code pages are writable during compilation and made executable afterward -- never both simultaneously.
- **DEX-to-DEX Compilation**: Dangerous quickening optimizations that bypass verification are avoided.

ART does not protect against **logic vulnerabilities** in application code, nor does it sandbox native (JNI) code executed via `System.loadLibrary()`. Native code runs with the full privileges of the app's UID and is subject only to kernel-level protections.

---

## 4. Native Libraries

### 4.1 Bionic libc

Android uses **Bionic** rather than glibc or musl. Bionic is designed for embedded use with security-focused differences:

- **Reduced attack surface**: Bionic omits rarely-used functions (e.g., `system()` is present but discouraged, `gets()` was removed early).
- **Hardened allocator** (`scudo`): Since Android 11, Bionic uses the Scudo hardened allocator, which provides quarantine zones, chunk checksums, and randomization to resist heap exploitation.
- **Stack protections**: Stack canaries (`-fstack-protector-strong`) are enabled by default.
- **Format string hardening**: `_FORTIFY_SOURCE=2` is enabled for all platform builds.
- **`fdsan`** (File Descriptor Sanitizer): Detects use-after-close and double-close of file descriptors, which are a common source of security bugs.

```c
// Bionic's fdsan in action
android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_FATAL);
// Double-close now aborts instead of silently corrupting state
```

### 4.2 Media Frameworks

The media stack has historically been Android's most critical native attack surface.

**libstagefright**: Android's media framework for parsing and decoding audio/video formats. It processes untrusted input (media files from the internet) in a privileged context. The "Stagefright" vulnerabilities (CVE-2015-1538 through CVE-2015-1539, CVE-2015-3824 through CVE-2015-3864) demonstrated that a single MMS message could achieve remote code execution.

Post-Stagefright mitigations:
- The `mediaserver` process was decomposed into multiple isolated services: `mediacodec`, `mediaextractor`, `mediadrmserver`, `mediaswcodec`.
- Each runs in a restrictive SELinux domain with minimal capabilities.
- `mediaextractor` (which parses untrusted formats) runs in a dedicated sandbox with seccomp-bpf restricting available syscalls.
- Software codecs (`mediaswcodec`) run in an even tighter sandbox.

```
Untrusted Media File
       |
       v
 [mediaextractor]  <-- Sandboxed, seccomp-bpf, minimal SELinux
       |
       v
 [mediacodec]      <-- Hardware codec access, still isolated
       |
       v
 [SurfaceFlinger]  <-- Display compositor
```

### 4.3 WebKit/Chromium

Android's WebView is backed by Chromium. The rendering engine processes untrusted web content and is a prime target for exploitation. Security measures include:

- **Multi-process model**: Renderer processes are sandboxed with seccomp-bpf, restricted SELinux contexts, and namespace isolation.
- **Site isolation**: Different origins run in different renderer processes (on supported devices).
- **Updatable via Play Store**: Since Android 5.0, WebView is an updatable APK (`com.google.android.webview`), decoupling security updates from OS updates.

### 4.4 OpenSSL/BoringSSL

Android replaced OpenSSL with **BoringSSL** (Google's fork) starting in Android 6.0. BoringSSL aggressively removes legacy code, deprecated protocols (SSLv3, RC4), and unused features to minimize attack surface. The `conscrypt` module provides the Java TLS implementation and is updatable via Project Mainline.

---

## 5. Application Framework

The application framework provides the Java/Kotlin APIs that apps use. From a security perspective, key system services include:

### 5.1 Activity Manager Service (AMS)

The AMS manages the lifecycle of application components (activities, services, broadcast receivers). Security roles:

- **Intent validation**: Verifies that callers have permission to start activities or send broadcasts.
- **Permission enforcement**: Checks `android:permission` attributes on components before allowing interaction.
- **Process management**: Assigns UIDs, starts app processes via `zygote`, enforces process limits.
- **Task affinity control**: Prevents task hijacking attacks (StrandHogg-type vulnerabilities, CVE-2020-0096).

### 5.2 Package Manager Service (PMS)

The PMS handles APK installation, verification, and permission grants. It is a critical trust anchor:

- **Signature verification**: Validates APK signing certificates using v1 (JAR), v2, v3, and v4 signing schemes.
- **Permission management**: Tracks declared and granted permissions per package.
- **SELinux label assignment**: Maps app package names to SELinux security contexts.
- **Install-time checks**: Verifies shared UID consistency, detects package name conflicts, enforces minimum SDK requirements.

### 5.3 Content Providers

Content Providers expose structured data between apps. They are protected by:

- **URI permissions**: Fine-grained, temporary permission grants via `FLAG_GRANT_READ_URI_PERMISSION`.
- **Path-permission elements**: Different permission requirements for different URI paths.
- **`android:exported`**: Since Android 12 (API 31), components must explicitly declare `exported=true` to be accessible to other apps.
- **SQL injection prevention**: The `ContentProvider` API encourages parameterized queries, but improper implementations remain vulnerable.

```xml
<!-- Secure Content Provider declaration -->
<provider
    android:name=".SecureProvider"
    android:authorities="com.example.provider"
    android:exported="false"
    android:permission="com.example.READ_DATA">
    <path-permission
        android:pathPrefix="/sensitive/"
        android:permission="com.example.READ_SENSITIVE" />
</provider>
```

### 5.4 Telephony Manager

The Telephony Manager interfaces with the radio interface layer (RIL). Security concerns:

- **Privileged APIs**: Reading IMEI, phone state, and call logs requires `READ_PHONE_STATE` or `READ_PRIVILEGED_PHONE_STATE`.
- **RIL attack surface**: The RIL communicates with the baseband processor via vendor-specific protocols. Vulnerabilities in the RIL can bridge the application processor / baseband boundary.
- **USSD handling**: Historically exploited for remote command execution (CVE-2012-6636).

---

## 6. Applications Layer

### 6.1 System Apps vs. Third-Party Apps

Android distinguishes apps by privilege level:

| Category           | Installation Path              | Signature            | UID Range     | SELinux Context          |
|--------------------|---------------------------------|----------------------|---------------|--------------------------|
| Core Platform      | `/system/app/`, `/system/priv-app/` | Platform key    | 1000-9999     | `system_app`             |
| Pre-installed OEM  | `/vendor/app/`, `/product/app/`      | Vendor key     | Varies        | `platform_app`           |
| Third-party        | `/data/app/`                         | Developer key  | 10000-19999   | `untrusted_app`          |
| Instant Apps       | Ephemeral                            | Developer key  | 10000-19999   | `ephemeral_app`          |

**Privileged permissions** (`protectionLevel="signature|privileged"`) are only grantable to apps in `/system/priv-app/` that are signed with the platform key and explicitly allowlisted in `/etc/permissions/privapp-permissions-*.xml`.

### 6.2 APK Structure

An APK is a ZIP archive with a defined structure:

```
example.apk (ZIP)
+-- AndroidManifest.xml        (binary XML, app metadata + permissions)
+-- classes.dex                (Dalvik bytecode)
+-- classes2.dex               (multidex overflow)
+-- resources.arsc             (compiled resources)
+-- res/                       (resource files: layouts, drawables)
+-- lib/
|   +-- arm64-v8a/             (native .so libraries for ARM64)
|   +-- armeabi-v7a/           (native .so libraries for ARM32)
|   +-- x86_64/                (native .so libraries for x86_64)
+-- assets/                    (raw asset files)
+-- META-INF/
    +-- MANIFEST.MF            (v1 signature manifest)
    +-- CERT.SF                (v1 signature file)
    +-- CERT.RSA               (v1 signing certificate)
```

For APK Signature Scheme v2+, the signature is stored in the APK Signing Block, located between the ZIP entries and the central directory. This covers the entire file contents, preventing modification of any entry without invalidating the signature.

### 6.3 App Signing

Android uses app signing as a **persistent identity**. The signing certificate is bound to the package name, and updates must be signed with the same key (or a rotated key via v3 signing).

- **v1 (JAR signing)**: Signs individual ZIP entries. Vulnerable to Janus (CVE-2017-13156) where a file could be simultaneously a valid APK and DEX.
- **v2 (Android 7.0+)**: Signs the entire APK as a binary blob. Immune to Janus.
- **v3 (Android 9.0+)**: Adds key rotation support via `SigningCertificateLineage`.
- **v4 (Android 11+)**: Supports incremental APK installation with streaming verification using a Merkle tree.

---

## 7. Boot Process and Chain of Trust

### 7.1 Boot Sequence

```
[Power On]
    |
    v
[Boot ROM] --> Fixed in silicon, loads primary bootloader
    |
    v
[Primary Bootloader (PBL)] --> Vendor-specific, verifies secondary bootloader
    |
    v
[Secondary Bootloader (SBL/ABL)] --> Loads and verifies boot.img
    |        (this is what "fastboot" interacts with)
    v
[boot.img] = [kernel + ramdisk + dtb]
    |
    v
[Linux Kernel] --> Mounts system, initializes SELinux
    |
    v
[init (PID 1)] --> Parses init.rc, starts services
    |
    v
[zygote] --> Pre-forks app runtime, starts system_server
    |
    v
[system_server] --> Starts AMS, PMS, WMS, all framework services
    |
    v
[Launcher] --> Home screen, system ready
```

### 7.2 Android Verified Boot (AVB)

AVB (also known as **dm-verity** for the block layer) establishes a chain of trust from hardware to userspace:

1. **Hardware Root of Trust**: A fused key in the SoC verifies the bootloader.
2. **Bootloader Verification**: The bootloader verifies `boot.img`, `vendor_boot.img`, and `vbmeta.img` using RSA/ECDSA signatures embedded in `vbmeta`.
3. **dm-verity**: The kernel uses a Merkle hash tree to verify every block read from `system`, `vendor`, and `product` partitions. Any modification causes an I/O error.
4. **Rollback Protection**: AVB stores a rollback index in tamper-evident storage (RPMB) to prevent booting older, vulnerable images.

The `vbmeta` structure:

```
vbmeta.img
+-- Header (magic, algorithm, key)
+-- Authentication Block (signature)
+-- Auxiliary Block
    +-- HashDescriptor (boot.img hash)
    +-- HashtreeDescriptor (system.img Merkle root)
    +-- ChainPartitionDescriptor (points to vendor vbmeta)
    +-- PropertyDescriptors (rollback index, flags)
```

If the bootloader is unlocked, AVB sets the **device state** to `orange`, and the OS displays a warning at boot. The `ro.boot.verifiedbootstate` property reflects the state (`green`, `yellow`, `orange`, `red`).

### 7.3 SELinux Initialization

SELinux is initialized very early in the boot process:

1. The kernel loads a compiled SELinux policy from the ramdisk (`/sepolicy` or from `/system/etc/selinux/`).
2. `init` process transitions to the `init` SELinux context.
3. `init` labels the filesystem based on `file_contexts`.
4. Services started by `init` transition to their designated SELinux domains (e.g., `zygote` -> `zygote` domain, `surfaceflinger` -> `surfaceflinger` domain).
5. Since Android 8.0, the policy is split: **platform policy** (from Google) and **vendor policy** (from SoC vendor) are compiled separately and combined at boot via `secilc`.

Android's SELinux policy enforces **deny-by-default**: if a rule does not explicitly allow an action, it is denied. There are no unconfined domains in production builds.

---

## 8. Binder IPC In Depth

### 8.1 Architecture

Binder is Android's primary IPC mechanism. It replaces traditional Unix IPC (pipes, sockets, SysV shared memory) with a transactional, object-oriented RPC system mediated by a kernel driver.

```
+-------------------+         +-------------------+
|   Client Process  |         |   Server Process  |
|                   |         |                   |
|  [BpInterface]    |         |  [BnInterface]    |
|  (Proxy object)   |         |  (Native object)  |
|       |           |         |       ^           |
|       v           |         |       |           |
|  [IPCThreadState] |         |  [IPCThreadState] |
|       |           |         |       ^           |
+-------|----------+         +-------|----------+
        |                            |
        v      Kernel Space          ^
   +------------------------------------+
   |       /dev/binder                  |
   |   Binder Driver (binder.c)        |
   |                                    |
   |  - Transaction buffer management  |
   |  - Thread pool management         |
   |  - Reference counting             |
   |  - Death notification             |
   |  - PID/UID credential passing     |
   +------------------------------------+
```

### 8.2 Transaction Flow

1. The client constructs a `Parcel` containing method arguments.
2. The client calls `transact()` on its proxy object.
3. `IPCThreadState` writes the parcel to the Binder driver via `ioctl(BINDER_WRITE_READ)`.
4. The kernel driver copies the transaction data from the client's address space to the server's **binder buffer** (a pre-mapped shared memory region). This is a **single-copy** mechanism -- data is copied once from client to server, not twice through the kernel.
5. The driver wakes a thread in the server's thread pool.
6. The server's `onTransact()` method dispatches the call, processes it, and writes a reply `Parcel`.
7. The reply is copied back to the client.

```c
// Simplified kernel-side transaction handling (drivers/android/binder.c)
static void binder_transaction(struct binder_proc *proc,
                                struct binder_thread *thread,
                                struct binder_transaction_data *tr,
                                int reply) {
    // 1. Look up target process from handle
    // 2. Allocate buffer in target's binder_mmap'd region
    // 3. Copy data from sender to target buffer (copy_from_user)
    // 4. Translate Binder objects (handles, file descriptors)
    // 5. Queue transaction on target thread/process
    // 6. Wake up target
}
```

### 8.3 Security Enforcement

Binder provides several security mechanisms that are fundamental to Android's security model:

**Caller Identity**: The kernel driver embeds the caller's **PID** and **UID** in every transaction. These credentials cannot be forged because they are set by the kernel, not userspace. Server-side code accesses them via:

```java
// In a Binder service implementation
@Override
public boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
    int callerUid = Binder.getCallingUid();
    int callerPid = Binder.getCallingPid();
    // Enforce permission checks based on caller identity
    mContext.enforceCallingPermission("android.permission.CAMERA", "Need CAMERA");
    // ...
}
```

**SELinux Integration**: The Binder driver passes the caller's SELinux security context to the target. The SELinux policy contains `binder_call` rules that control which domains can communicate:

```
# Allow untrusted apps to call system_server via binder
allow untrusted_app system_server:binder { call transfer };

# Deny untrusted apps from calling HAL processes via hwbinder
neverallow untrusted_app hal_camera_server:binder call;
```

**Reference Counting and Death Notifications**: Binder objects are reference-counted. When a service process dies, the driver sends `BINDER_DEAD_BINDER` notifications to all clients holding references. This prevents dangling references and the security bugs that follow.

**File Descriptor Passing**: Binder can pass file descriptors between processes. The kernel translates the FD number from the sender's FD table to the receiver's, ensuring correct process-level isolation.

### 8.4 Binder Domains

Android uses three separate Binder devices to enforce trust boundaries:

| Device           | Purpose                            | Users                              |
|------------------|------------------------------------|------------------------------------|
| `/dev/binder`    | Framework IPC                      | Apps <-> System Services           |
| `/dev/hwbinder`  | HAL IPC                            | System Services <-> HAL processes  |
| `/dev/vndbinder` | Vendor-to-vendor IPC               | Vendor processes <-> Vendor processes |

SELinux policy ensures strict separation: an untrusted app can only access `/dev/binder`, never `/dev/hwbinder` or `/dev/vndbinder`.

### 8.5 Historical Binder Vulnerabilities

Binder has been the target of high-profile exploits:

- **CVE-2019-2215** (Bad Binder): A use-after-free in the Binder driver's `epoll` integration. Exploited in the wild by the NSO Group. The bug occurred when a Binder file descriptor was registered with `epoll` and then freed while still referenced by the epoll instance.
- **CVE-2020-0041**: An out-of-bounds write in `binder_transaction()` when handling Binder objects in a transaction buffer.
- **CVE-2022-20421**: A use-after-free when a Binder buffer was freed while still referenced by a transaction.

These vulnerabilities highlight that the Binder driver, despite being a relatively small kernel module (~7000 lines), is one of the most security-critical components due to its direct accessibility from untrusted app processes.

---

## 9. Cross-Layer Security Considerations

### 9.1 The Privilege Escalation Path

A typical Android exploit chain traverses multiple layers:

```
1. Untrusted App Code (Java/Kotlin)
   -- exploit logic bug in ContentProvider or Activity -->
2. Native Code (JNI / .so library)
   -- exploit memory corruption in native library -->
3. System Service (system_server)
   -- exploit confused deputy or Binder vulnerability -->
4. Kernel
   -- exploit driver vulnerability (Binder, GPU, ION) -->
5. Root / Full Device Compromise
```

Each layer crossing requires a new exploit primitive. Android's defense-in-depth means that a single vulnerability rarely achieves full compromise -- instead, attackers must chain multiple bugs across layers.

### 9.2 Attack Surface Summary

| Layer               | Attack Surface                              | Trust Level      | Common CVE Targets                   |
|---------------------|---------------------------------------------|------------------|--------------------------------------|
| Applications        | Exported components, deep links, Intents    | Untrusted        | Logic bugs, data leaks               |
| App Framework       | Binder services, Content Providers          | Privileged       | Permission bypasses, confused deputy  |
| ART                 | DEX verification, JIT code cache            | Privileged       | Type confusion, JIT spray            |
| Native Libraries    | Media parsers, SSL, Bluetooth               | Privileged       | Memory corruption, buffer overflows   |
| HAL                 | HIDL/AIDL interfaces, vendor blobs          | Privileged       | Memory corruption in vendor code     |
| Kernel              | Binder, GPU drivers, filesystem             | Highest          | UAF, race conditions, OOB access     |
| Bootloader/TEE      | Fastboot, TrustZone TAs                     | Root of Trust    | Secure boot bypass, TEE escapes     |

### 9.3 Defense-in-Depth Stack

Android's layered defenses mean that an attacker must bypass multiple independent mechanisms:

1. **Google Play Protect** -- Pre-install and runtime scanning for known malware.
2. **App Sandbox** -- UID isolation, SELinux `untrusted_app` domain.
3. **Permission Model** -- Runtime permissions (Android 6.0+), one-time permissions (Android 11+), auto-revocation of unused permissions (Android 11+).
4. **seccomp-bpf** -- Restricts syscalls per process profile.
5. **SELinux (MAC)** -- Mandatory access control with deny-by-default policy.
6. **ASLR / CFI / MTE** -- Memory corruption mitigations at the compiler/hardware level.
7. **dm-verity / AVB** -- Filesystem integrity verification.
8. **Hardware-backed Keystore** -- Cryptographic keys in TEE/StrongBox, immune to software extraction.

---

## References

- Android Open Source Project: [source.android.com/docs/security](https://source.android.com/docs/security)
- Android Kernel Security: [source.android.com/docs/security/overview/kernel-security](https://source.android.com/docs/security/overview/kernel-security)
- Binder Driver Source: `drivers/android/binder.c` in the Linux kernel tree
- Project Treble: [source.android.com/docs/core/architecture](https://source.android.com/docs/core/architecture)
- Android Verified Boot: [source.android.com/docs/security/features/verifiedboot](https://source.android.com/docs/security/features/verifiedboot)
- Scudo Hardened Allocator: [llvm.org/docs/ScudoHardenedAllocator.html](https://llvm.org/docs/ScudoHardenedAllocator.html)
- CVE-2019-2215 (Bad Binder): [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html)

---

*Document prepared as part of the Android Architecture and Vulnerabilities research series.*
*Last updated: April 2026*
