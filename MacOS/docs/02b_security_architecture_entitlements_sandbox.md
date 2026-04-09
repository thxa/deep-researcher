# macOS Security Architecture: Entitlements, Sandbox Internals, and Access Control

## 1. Entitlements Deep Dive

### What Entitlements Are

Entitlements are key-value pairs embedded in a code signature that declare capabilities a process requests from the operating system. They function as a capability-based access control mechanism: the kernel and system daemons inspect a process's entitlements at runtime to gate access to privileged APIs, hardware resources, and protected data. Unlike UNIX permissions, which attach to files, entitlements attach to *code identity* and are validated cryptographically through the code signing infrastructure.

### Embedding in Binaries

Entitlements are stored in the `LC_CODE_SIGNATURE` load command of a Mach-O binary. Within the code signature blob (a `SuperBlob` structure), entitlements occupy a dedicated slot — specifically, slot `0xfffe0007` (the entitlement blob) in the code directory. Starting with macOS 12, Apple introduced DER-encoded entitlements (slot `0xfffe0009`) alongside the legacy XML plist format, enabling more efficient kernel-side parsing.

The signing workflow is:

1. Developer specifies entitlements in an XML plist file.
2. `codesign -s "Identity" --entitlements entitlements.plist ./binary` embeds them into the signature.
3. At load time, the kernel's `mac_vnode_check_signature` hook (via AMFI — Apple Mobile File Integrity) extracts and validates entitlements against the code directory hash.
4. `amfid` (userland daemon) assists with provisioning profile and entitlement validation for non-platform binaries.

Extraction for inspection:

```bash
codesign -d --entitlements - /path/to/binary       # XML format
codesign -d --entitlements - --der /path/to/binary  # DER format
```

### Public vs. Private Entitlements

**Public entitlements** (`com.apple.security.*`) are documented and available to third-party developers through the App Sandbox and Hardened Runtime systems. Examples:

| Entitlement | Purpose |
|---|---|
| `com.apple.security.app-sandbox` | Enables App Sandbox confinement |
| `com.apple.security.network.client` | Allows outbound network connections |
| `com.apple.security.files.user-selected.read-write` | Access to user-selected files via Open/Save dialogs |
| `com.apple.security.device.audio-input` | Microphone access |
| `com.apple.security.cs.disable-library-validation` | Allows loading unsigned libraries |

**Private entitlements** (`com.apple.private.*`) are reserved for Apple-signed binaries and are enforced by AMFI. They cannot be claimed by third-party code unless signed with an Apple-internal certificate or an appropriate provisioning profile. Critical private entitlements include:

- `com.apple.private.security.no-sandbox` — Exempts a process from sandbox enforcement entirely.
- `com.apple.private.tcc.allow` — Bypasses TCC (Transparency, Consent, and Control) prompts for specified services.
- `com.apple.rootless.install` — Allows modification of SIP-protected paths.
- `com.apple.rootless.storage.TCC` — Grants direct access to TCC.db, the privacy consent database.
- `com.apple.private.amfi.can-load-cdhash` — Allows loading code by its cdhash without full signature validation.

### Entitlement Checking

**Kernel-side**: The `AppleMobileFileIntegrity.kext` (AMFI) registers MAC policy hooks that intercept process execution and library loading. When a process calls `execve()`, AMFI's `mac_vnode_check_exec` hook parses the entitlement blob from the code signature and caches it in the process's `cs_blob` structure attached to the `ubc_info` of the vnode. Subsequent entitlement queries use `csproc_get_blob()` and `cs_entitlements_dictionary_copy()` to read entitlements without re-parsing the binary.

**Userland**: The `SecTask` API (`Security.framework`) allows daemons to inspect a connecting client's entitlements:

```c
SecTaskRef task = SecTaskCreateWithAuditToken(NULL, auditToken);
CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.example"), NULL);
```

XPC services use this pattern extensively — `xpc_connection_copy_entitlement_value()` checks a peer's entitlements to authorize IPC requests.

---

## 2. Sandbox Internals (Seatbelt)

### Architecture Overview

The macOS sandbox (codenamed **Seatbelt**) is implemented as a MAC policy module within the MACF. Its components span kernel and userland:

- **Sandbox.kext** — Kernel extension that registers MAC policy hooks and evaluates access decisions against compiled sandbox profiles.
- **libsandbox.dylib** — Userland library that compiles human-readable Sandbox Profile Language (SBPL) into a bytecode format the kernel interprets.
- **sandboxd** — Daemon that logs sandbox violations (deny decisions) to the unified logging system.

### Sandbox Profile Language (SBPL)

SBPL is a Scheme-based DSL. Profiles consist of rules that match operations against filters and produce `allow` or `deny` decisions. A simplified example:

```scheme
(version 1)
(deny default)
(allow file-read*
    (subpath "/usr/lib")
    (literal "/etc/hosts"))
(allow process-exec
    (literal "/usr/bin/python3"))
(allow network-outbound
    (remote tcp "example.com:443"))
```

Compilation flow: `libsandbox` parses the SBPL text, resolves filter parameters, and emits a binary profile. This profile is passed to the kernel via `sandbox_init()`, `sandbox_init_with_parameters()`, or the `__mac_syscall("Sandbox", ...)` system call (operation 0 = set profile). The kernel stores the compiled profile in the process's sandbox context (`proc->p_sandbox`).

### Sandbox.kext Hooks

Sandbox.kext registers hooks for virtually every MACF callback category:

- **Vnode hooks**: `mpo_vnode_check_open`, `mpo_vnode_check_read`, `mpo_vnode_check_write`, `mpo_vnode_check_unlink`, `mpo_vnode_check_rename`, etc.
- **Process hooks**: `mpo_proc_check_fork`, `mpo_proc_check_signal`, `mpo_proc_check_get_task`.
- **Socket hooks**: `mpo_socket_check_connect`, `mpo_socket_check_bind`, `mpo_socket_check_listen`.
- **IPC hooks**: `mpo_mach_check_*` for Mach port operations.
- **System hooks**: `mpo_system_check_sysctlbyname`, `mpo_iokit_check_open`.

Each hook invokes the sandbox evaluator, which walks the compiled profile's bytecode to determine if the operation + arguments match an allow rule. If no rule matches and the default is deny, the operation returns `EPERM` (or `EACCES`).

---

## 3. Mandatory Access Control Framework (MACF)

### MAC Policy Registration

MACF is XNU's implementation of the TrustedBSD MAC framework, providing a pluggable hook infrastructure for mandatory access control. Policy modules register via `mac_policy_register()`, providing a `mac_policy_conf` structure that declares:

- A `mac_policy_ops` function pointer table (hundreds of hook callbacks).
- Policy flags (`MPC_LOADTIME_FLAG_UNLOADOK`, etc.).
- A policy name and label slot requirements.

On macOS, three primary policies are always loaded:

| Policy | KEXT | Purpose |
|---|---|---|
| Sandbox | `Sandbox.kext` | Application sandboxing |
| AMFI | `AppleMobileFileIntegrity.kext` | Code signing, entitlements, SIP |
| TMSafetyNet | `TMSafetyNet.kext` | Time Machine protection |

### Hook Categories

MACF hooks are organized by subsystem:

- **Vnode hooks** (`mac_vnode_check_*`): Gate all filesystem operations. Every `open()`, `read()`, `write()`, `stat()`, `unlink()`, `rename()`, `exchangedata()`, and `setattrlist()` call passes through registered vnode hooks.
- **Process hooks** (`mac_proc_check_*`): Control `fork()`, `exec()`, signal delivery, `task_for_pid()`, and debugging (`ptrace`).
- **Socket hooks** (`mac_socket_check_*`): Filter `connect()`, `bind()`, `listen()`, and `accept()`.
- **System hooks** (`mac_system_check_*`): Protect `sysctl`, `reboot()`, `settimeofday()`, and kernel extension loading.

### SIP, Sandbox, and TCC on MACF

**System Integrity Protection (SIP)** is enforced primarily by AMFI's MAC hooks. When a vnode check fires on a SIP-protected path (tagged with the `SF_RESTRICTED` or `SF_NOUNLINK` flag, or residing under `/System`, `/usr`, `/Library`), AMFI denies the operation unless the caller holds `com.apple.rootless.install` or SIP is disabled in NVRAM (`csr-active-config`).

**TCC** operates in userland via `tccd`, but its authorization decisions are backed by Sandbox.kext hooks. When a sandboxed process accesses a TCC-protected resource (Camera, Microphone, Desktop, Documents, Downloads), the sandbox hook issues a query to `tccd` via XPC, which consults `TCC.db` (`~/Library/Application Support/com.apple.TCC/TCC.db` for per-user, `/Library/Application Support/com.apple.TCC/TCC.db` for system-wide). The result is cached and the hook returns allow or deny.

---

## 4. Keychain and Credential Storage

### Architecture

The macOS Keychain is managed by `securityd` (and its modern replacement, `secd`) using the `Security.framework`. Keychain data is stored in SQLite databases:

- **Login keychain**: `~/Library/Keychains/login.keychain-db` — Encrypted with the user's login password, auto-unlocked at login.
- **System keychain**: `/Library/Keychains/System.keychain` — Stores system-wide credentials (Wi-Fi passwords, certificates).
- **Data Protection keychain** (modern, iOS-derived): `~/Library/Keychains/<UUID>/keychain-2.db` — Uses the iOS-style class key hierarchy.

### SecItem API

Applications interact with the Keychain through the `SecItem*` C API:

- `SecItemAdd()` — Stores a new item (password, key, certificate, identity).
- `SecItemCopyMatching()` — Queries items by attributes (service, account, class, access group).
- `SecItemUpdate()` — Modifies existing items.
- `SecItemDelete()` — Removes items.

Access control is governed by **keychain access groups** — string identifiers derived from the app's code signing identity and `keychain-access-groups` entitlement. An item's `kSecAttrAccessGroup` restricts which processes can read it.

### Secure Enclave Integration

Keys created with `kSecAttrTokenIDSecureEnclave` are generated inside the Secure Enclave Processor (SEP) and never leave it. The SEP exposes ECDSA P-256 signing and key agreement operations. These keys can be bound to biometric authentication via `SecAccessControlCreateWithFlags()`:

```c
SecAccessControlRef acl = SecAccessControlCreateWithFlags(NULL,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
    NULL);
```

The SEP stores key material in its own encrypted storage, sealed to the device's UID key — a hardware-fused AES-256 key unique to each chip.

---

## 5. Endpoint Security Framework

### Client Architecture

Endpoint Security (ES), introduced in macOS 10.15, is the sanctioned replacement for the deprecated `kauth` KPI and `OpenBSM` audit trail. ES clients run in userland and communicate with `EndpointSecurity.kext` via a Mach port interface. Clients must hold the `com.apple.developer.endpoint-security.client` entitlement and be approved via MDM or user consent in System Preferences > Privacy & Security.

### Event Model

ES distinguishes two event delivery modes:

- **AUTH events**: Synchronous. The kernel blocks the operation until the ES client responds with `ES_AUTH_RESULT_ALLOW` or `ES_AUTH_RESULT_DENY`. Subject to a configurable deadline (default ~60s). Used for real-time prevention (e.g., blocking malware execution).
- **NOTIFY events**: Asynchronous. The client receives a notification after the operation completes. Used for telemetry, auditing, and detection without impacting system performance.

Key event types include `ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_AUTH_OPEN`, `ES_EVENT_TYPE_NOTIFY_FORK`, `ES_EVENT_TYPE_NOTIFY_EXIT`, `ES_EVENT_TYPE_AUTH_MMAP`, and `ES_EVENT_TYPE_NOTIFY_WRITE`.

### Muting and Performance

ES clients can **mute** processes or paths to reduce event volume:

```c
es_mute_process(client, &audit_token);            // Mute by process
es_mute_path(client, "/usr/lib", ES_MUTE_PATH_TYPE_PREFIX);  // Mute by path prefix
```

Muting is critical for EDR performance — without it, system daemons like `mdworker` or `fseventsd` would flood the client with irrelevant events.

### Comparison with Predecessors

| Feature | kauth (deprecated) | OpenBSM (deprecated) | Endpoint Security |
|---|---|---|---|
| Execution context | Kernel | Kernel/Userland | Userland |
| Can block operations | Yes (with caveats) | No (audit only) | Yes (AUTH events) |
| Stability guarantee | None (KPI) | Stable but limited | Stable API, versioned |
| Process context | Limited | Full audit token | Full, including cdhash |
| Modern support | Removed (macOS 15) | Reduced scope | Actively developed |

---

## 6. Privacy and Data Protection

### Data Vaults

Data Vaults are SIP-protected directories that restrict access even from `root`. They are identified by the `com.apple.rootless` extended attribute and require specific entitlements (e.g., `com.apple.private.tcc.manager`) to access. Examples: `~/Library/Mail`, `~/Library/Messages`, Safari browsing data. Data Vaults underpin TCC enforcement at the filesystem level.

### FileVault 2 and Volume Encryption

FileVault 2 provides full-volume encryption using AES-XTS-128 (or AES-256 on Apple Silicon). The volume master key (VMK) is wrapped by one or more key encryption keys (KEKs) derived from:

- The user's password via PBKDF2.
- An institutional recovery key.
- An iCloud recovery escrow key.

On Apple Silicon Macs, the volume hierarchy is:

1. **Hardware UID key** (fused in SEP) encrypts the volume encryption key (VEK).
2. **VEK** encrypts the APFS volume data.
3. **KEK** (derived from user password + SEP) wraps the VEK.
4. A **sealed key** (effaceable storage) allows instant remote wipe by destroying the wrapping key.

### Per-File Encryption on APFS

APFS supports per-file (per-extent) encryption natively. Each file can have its own encryption key, wrapped by a class key that corresponds to a data protection class:

| Class | Availability | Use Case |
|---|---|---|
| Class A (Complete Protection) | Only when device unlocked | Sensitive user data |
| Class B (Protected Unless Open) | File creation anytime, read only when unlocked | Background downloads |
| Class C (Protected Until First Auth) | After first unlock until reboot | Most app data |
| Class D (No Protection) | Always available | System resources |

On macOS, these classes are primarily leveraged by the Data Protection keychain and by iOS-style apps. The volume key hierarchy ensures that even with physical disk access, data cannot be decrypted without the appropriate credentials and (on Apple Silicon) the hardware UID key from the specific device's SEP.

### Sealed System Volume

Starting with macOS 11 (Big Sur), the system volume is cryptographically sealed using a Merkle tree (Signed System Volume, SSV). Every file's hash is incorporated into a tree whose root hash is signed by Apple. The kernel validates this seal at mount time, ensuring that any offline modification of the system volume is detected and rejected. This provides tamper-evidence beyond what SIP alone offers.

---

## Summary

macOS security is a defense-in-depth architecture where entitlements define what code *may* do, the Sandbox restricts what it *actually can* do, MACF provides the kernel hook infrastructure for policy enforcement, and hardware-backed encryption (via the Secure Enclave) protects data at rest. Each layer reinforces the others: SIP protects the enforcement mechanisms themselves, TCC adds user-consent gates atop Sandbox file restrictions, and Endpoint Security gives third-party security tools a stable, performant interface to monitor it all without resorting to kernel extensions. Understanding the interplay between these layers is essential for both security research and building robust macOS security tooling.
