# macOS System Architecture — Userland, Frameworks, and System Services

## 1. Userland Architecture

### launchd (PID 1)

`launchd` is the first userspace process on macOS, assigned PID 1. It replaces the traditional Unix `init`, `cron`, `inetd`, and `xinetd` subsystems with a single unified service management daemon. launchd owns the Mach bootstrap port for the system, making it the root of all Mach service registration and lookup in userland. Every other userspace process is either spawned by launchd directly or inherits from a process that was.

launchd operates in two domains:

- **System domain** (`/Library/LaunchDaemons`, `/System/Library/LaunchDaemons`): Services run as root, started at boot before any user logs in. These are *daemons* — they have no connection to a GUI session or user context.
- **Per-user domain** (`/Library/LaunchAgents`, `~/Library/LaunchAgents`): Services run as the logged-in user within a GUI session. These are *agents* — they can interact with the window server, pasteboard, and user keychain.

The distinction matters for security: daemons run with elevated privileges but lack access to user-session resources (no access to the Aqua window server port), while agents run as the user but within the user's login session Mach bootstrap namespace.

### Launch Plists and Job Definitions

Services are declared via property list (plist) files conforming to `launchd.plist(5)`. Critical keys include:

| Key | Purpose |
|-----|---------|
| `Label` | Unique reverse-DNS identifier for the job |
| `Program` / `ProgramArguments` | Executable path and arguments |
| `MachServices` | Mach ports to register in the bootstrap namespace |
| `RunAtLoad` | Start immediately when the plist is loaded |
| `KeepAlive` | Restart policy (boolean or conditional dictionary) |
| `UserName` / `GroupName` | Credential drop for daemons |
| `AssociatedBundleIdentifiers` | Ties the job to a specific application (SIP-protected on system volume) |

From a security perspective, the `MachServices` key is critical — it registers named Mach ports that any process in the same bootstrap domain can look up via `bootstrap_look_up()`. Hijacking or impersonating these services is a well-known attack vector, mitigated in modern macOS by code-signing checks and the sealed system volume.

### XPC Services

XPC (Cross-Process Communication) is Apple's modern IPC framework built atop Mach messages. XPC services are lightweight helper processes embedded inside application bundles (under `Contents/XPCServices/`) or registered as launchd jobs. They run in their own process with a minimal sandbox and communicate with their host via `libxpc`.

XPC enforces a privilege-separation model: a privileged daemon can expose specific operations over XPC while keeping the attack surface minimal. The XPC runtime handles process lifecycle — services are launched on demand and can be terminated when idle.

Each XPC connection carries an **audit token** (`audit_token_t`) that identifies the sender's PID, UID, GID, and code-signing information. Services use `xpc_connection_get_audit_token()` to verify the caller before processing requests. Failure to validate audit tokens is a recurring vulnerability class.

---

## 2. Framework Stack

macOS exposes system functionality through a layered framework hierarchy:

### Core Foundation (CF)

Core Foundation is a C-based framework providing fundamental data types (`CFString`, `CFDictionary`, `CFArray`, `CFData`, `CFRunLoop`) and memory management via `CFRetain`/`CFRelease`. It is toll-free bridged with Foundation — a `CFStringRef` is layout-compatible with `NSString *` and can be cast between the two. CF operates at a lower level than Foundation and is used extensively inside system daemons that avoid Objective-C overhead.

### Foundation

The Objective-C (and Swift-bridged) layer built on top of Core Foundation. Provides `NSObject`-based APIs for collections, file management, networking (`NSURLSession`), serialization (`NSKeyedArchiver`, `NSJSONSerialization`), and distributed notifications. Foundation is the primary API surface for application development.

### Security.framework

Wraps the Security subsystem — keychain access (`SecItemAdd`, `SecItemCopyMatching`), code-signing verification (`SecStaticCodeCheckValidity`), certificate and trust evaluation (`SecTrustEvaluateWithError`), and cryptographic operations (`SecKeyCreateRandomKey`, `SecKeyCreateEncryptedData`). Under the hood, most operations are XPC calls to `securityd` (system keychain and crypto operations) and `trustd` (certificate trust evaluation).

### IOKit.framework (Userland)

The userland interface to the IOKit driver framework in the kernel. Applications use `IOServiceGetMatchingServices()`, `IOServiceOpen()`, and `IOConnectCallMethod()` to discover and communicate with kernel drivers via Mach ports. Each `io_connect_t` is a Mach port representing a user client connection to a specific driver object. IOKit user clients have historically been a major kernel attack surface — malformed input to `IOConnectCallMethod` external methods can trigger kernel memory corruption.

### DiskArbitration

Manages disk mount/unmount events, volume claim arbitration, and filesystem notifications. `DADiskRef` objects represent disks; callbacks notify applications when volumes appear or disappear. Used by Disk Utility and the Finder's mount logic.

### SystemConfiguration

Provides network configuration and reachability APIs (`SCNetworkReachability`, `SCDynamicStore`). The backing daemon is `configd`, which maintains a dynamic configuration store in memory, keyed by hierarchical paths (e.g., `State:/Network/Interface/en0/IPv4`).

---

## 3. Inter-Process Communication

### Mach Ports in Userland

All userland IPC on macOS is ultimately built on Mach messages. A Mach port is a kernel-managed unidirectional message queue, referenced in userspace by `mach_port_t` (a port name local to the task's IPC namespace). Ports carry **send rights**, **receive rights**, and **send-once rights**. Transferring a send right through a Mach message allows one process to grant another the ability to communicate with a service. The bootstrap server (launchd) acts as the name server — processes register named ports and look them up by string name.

### libxpc

`libxpc` serializes structured data (dictionaries, arrays, strings, data blobs, file descriptors, Mach ports) into Mach messages. The XPC protocol is asynchronous, event-driven, and integrated with `dispatch_queue_t`. Connection types:

- **`xpc_connection_create_mach_service()`**: Connects to a launchd-registered Mach service by name.
- **`xpc_connection_create()`**: Creates an anonymous XPC connection (used for embedded XPC services).

XPC messages are `xpc_object_t` dictionaries. The wire format is an Apple-private binary serialization.

### NSXPC

`NSXPCConnection` is the Objective-C abstraction over libxpc. It provides a proxy-based remoting model: the client obtains an `NSXPCInterface`-typed proxy object and calls Objective-C methods on it; NSXPC serializes the invocation (using `NSSecureCoding`), sends it over XPC, and deserializes it in the service process. This is the modern replacement for Distributed Objects (`NSConnection`).

### NSDistributedNotificationCenter

A system-wide notification mechanism backed by `notifyd` and `distnoted`. Processes post and observe named notifications across process boundaries. The notification payload is limited to property-list types. Not suitable for high-frequency or large-payload IPC. From a security standpoint, any process can post a distributed notification with any name, making it unsuitable for trusted signaling.

---

## 4. File System Architecture

### APFS (Apple File System)

APFS is a copy-on-write (CoW) filesystem with native encryption, snapshots, clones, and space sharing. An APFS **container** occupies a GPT partition and contains one or more **volumes** that share the container's free space.

### Sealed System Volume (SSV)

Since macOS 11 (Big Sur), the system volume is a **cryptographically sealed snapshot**. Every file on the system volume is covered by a Merkle tree rooted in a single hash stored in the boot policy. Any modification to a system file invalidates the seal and causes a boot failure. The SSV is mounted read-only at `/` via a firmlink mechanism.

### Firmlinks

Firmlinks are bidirectional, synthetic links that merge the system volume and data volume into a single unified directory hierarchy. For example, `/System` lives on the read-only system volume, while `/Users` is a firmlink to the writable data volume. Firmlinks are kernel-enforced and not visible as symlinks — they appear as native directory entries. The firmlink list is stored in `/usr/share/firmlinks`.

### Cryptographic Volume Structure

APFS supports per-volume and per-file encryption using a key hierarchy:

- **Volume Encryption Key (VEK)**: Encrypts all data on the volume.
- **Key Encryption Key (KEK)**: Wraps the VEK; itself wrapped by the user's password-derived key via the Secure Enclave (on T2/Apple Silicon).
- **Per-file keys**: Each file extent can have its own encryption key, wrapped by the VEK.

### Snapshots

APFS snapshots are point-in-time, read-only images of a volume achieved through CoW semantics. Time Machine uses APFS snapshots as its local backup mechanism. The sealed system volume is itself a snapshot (`com.apple.os.update-<hash>`).

---

## 5. dyld and Dynamic Linking

### dyld Shared Cache

`dyld` (the dynamic linker, `/usr/lib/dyld`) loads Mach-O binaries and resolves dynamic library dependencies. To optimize startup, Apple pre-links all system frameworks into the **dyld shared cache** (`/System/Library/dyld/dyld_shared_cache_*`), a single memory-mapped file containing all system dylibs with pre-computed binding and rebasing information. On Apple Silicon, the shared cache is mapped at a randomized address (independent from ASLR slide of individual binaries).

### DYLD_INSERT_LIBRARIES

Analogous to `LD_PRELOAD` on Linux, this environment variable instructs dyld to load additional libraries before the main executable's dependencies. It is **disabled** when any of the following are true: the binary is setuid/setgid, the binary has restricted entitlements, the binary is hardened-runtime signed, SIP is enabled for the process, or library validation is active. These restrictions are enforced by dyld itself in its `_main()` initialization path.

### Library Validation

Processes signed with the `com.apple.security.cs.library-validation` entitlement (or inheriting it via the hardened runtime) reject dylibs that are not signed by the same team ID, Apple, or the operating system. This prevents injection of arbitrary code via dylib loading.

### @rpath, @loader_path, @executable_path

Mach-O `LC_LOAD_DYLIB` commands reference libraries by install name. Special prefixes allow relocatable paths:

- `@executable_path`: Resolves relative to the main executable.
- `@loader_path`: Resolves relative to the binary containing the load command (useful for framework-within-framework).
- `@rpath`: Resolves against the list of `LC_RPATH` entries in the binary, searched in order.

Misconfigured rpaths can create **dylib hijacking** opportunities — if an `@rpath`-referenced dylib is missing from earlier search paths, an attacker can place a malicious dylib there.

### Objective-C and Swift Runtimes

The Objective-C runtime (`libobjc`) maintains class tables, method caches, and performs message dispatch (`objc_msgSend`). The Swift runtime (`libswiftCore`) manages metadata, witness tables, and ABI-stable type descriptors. Both runtimes are loaded from the dyld shared cache.

---

## 6. System Daemons and Services

| Daemon | Role | Attack Surface |
|--------|------|----------------|
| **securityd** | System keychain operations, cryptographic key management, code-signing evaluation | XPC interface processes keychain queries; bugs can leak credentials or bypass access controls |
| **trustd** | Certificate trust evaluation, OCSP/CRL checking, certificate pinning | Trust evaluation bypass can enable MITM; processes `SecTrustEvaluate` requests via XPC |
| **syspolicyd** | Gatekeeper policy enforcement, notarization ticket checking, launch policy | Bypass leads to execution of unsigned/unnotarized code; maintains a SQLite policy database |
| **taskgated** | Validates `task_for_pid()` entitlements, controls process introspection rights | Compromise allows arbitrary process memory access; checks `com.apple.security.get-task-allow` |
| **configd** | Network configuration, `SCDynamicStore`, interface monitoring | Writable configuration store keys can influence network routing; listens on Mach port |
| **notifyd** | Darwin notification system (`notify_post`, `notify_register_dispatch`) | Low-risk but spoofable — any process can post arbitrary notification names |
| **distnoted** | Distributed notification delivery for `NSDistributedNotificationCenter` | No authentication on notification source; payload is not integrity-protected |
| **opendirectoryd** | Directory services, user/group resolution, authentication | Handles password verification; authentication bypass bugs are critical |
| **sandboxd** | Sandbox violation logging and policy evaluation support | Policy bypass allows sandbox escape |

---

## 7. Process Lifecycle

### posix_spawn vs. fork/exec

On modern macOS, `posix_spawn()` is the preferred process creation API. Traditional `fork()` is increasingly problematic:

- On Apple Silicon, `fork()` without `exec()` is restricted in hardened-runtime processes.
- `fork()` duplicates the entire Mach port namespace, creating complex cleanup requirements.
- `posix_spawn()` atomically creates a new process with specified attributes (file actions, signal masks, ASLR flags, entitlement evaluation) without the intermediate forked state.

The kernel implementation of `posix_spawn` calls `exec_activate_image()` internally, performing code-signing and entitlement evaluation as a single atomic operation.

### Entitlements at Exec Time

When a Mach-O binary is loaded, the kernel extracts the embedded entitlements from the code signature's `LC_CODE_SIGNATURE` blob. The entitlements are a plist embedded in the signature and are evaluated by AMFI (AppleMobileFileIntegrity.kext) in conjunction with the provisioning profile or platform policy. Key behaviors gated by entitlements include:

- `com.apple.security.app-sandbox`: Mandatory App Sandbox activation.
- `com.apple.private.security.no-sandbox`: Exemption from sandboxing (Apple-internal only).
- `com.apple.security.cs.allow-dyld-environment-variables`: Permits `DYLD_*` variables.
- `com.apple.security.cs.disable-library-validation`: Allows loading third-party dylibs.
- `task_for_pid-allow`: Permits `task_for_pid()` on arbitrary processes.

### Mach-O Binary Format

macOS executables use the Mach-O format, consisting of:

1. **Header** (`mach_header_64`): Magic number, CPU type, file type (executable, dylib, bundle), number of load commands.
2. **Load Commands**: Instructions for the dynamic linker — `LC_SEGMENT_64` (memory mapping), `LC_LOAD_DYLIB` (dependencies), `LC_MAIN` (entry point), `LC_CODE_SIGNATURE` (signature offset), `LC_RPATH` (search paths).
3. **Segments/Sections**: `__TEXT` (executable code, read-only), `__DATA` (writable globals), `__DATA_CONST` (read-only after launch), `__LINKEDIT` (symbol tables, signature data).

Universal (fat) binaries contain multiple Mach-O slices for different architectures, selected at load time by the kernel.

### Code Signing at Load Time

Code signature verification occurs at multiple stages:

1. **Exec time**: The kernel validates the code directory hash and checks the signature against AMFI policy. Invalid signatures result in `EPERM` on exec.
2. **Page fault time**: Each `__TEXT` page is hashed on demand and compared against the code directory hashes. Modified pages trigger a `SIGKILL`. This is the basis of **runtime code integrity**.
3. **Library load time**: dyld validates loaded dylibs against library validation policy and checks their code signatures before mapping.

On Apple Silicon, all code must be signed — even ad-hoc signatures (without an identity) are required for execution. This is enforced by hardware page protection in concert with AMFI.

---

## References

- Apple Developer Documentation: launchd, XPC Services, Code Signing
- `man launchd.plist`, `man dyld`, `man posix_spawn`
- *OS Internals* by Jonathan Levin, Volumes I–III
- Apple Platform Security Guide (2024)
- APFS Reference (Apple Developer)
