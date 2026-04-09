# macOS Userland Vulnerabilities: Privilege Escalation and Sandbox Escapes

## 1. Local Privilege Escalation (LPE)

Local Privilege Escalation on macOS targets the boundary between unprivileged user execution and root or kernel-level access. Several recurring attack surfaces exist.

### SUID/SGID Binaries

macOS ships fewer SUID binaries than traditional Unix systems, but those that remain are high-value targets. Historically `/usr/bin/newgrp`, `/usr/bin/at`, and `/usr/sbin/traceroute` carried the SUID bit. Exploitation follows classic patterns: environment variable injection, unsafe `PATH` resolution, and symlink races. Apple has progressively eliminated SUID binaries, replacing them with XPC-mediated privilege brokers, but third-party software frequently reintroduces SUID attack surface.

Enumeration is straightforward:

```bash
find / -perm -4000 -type f 2>/dev/null   # SUID
find / -perm -2000 -type f 2>/dev/null   # SGID
```

### Authorization Services and AuthorizationExecuteWithPrivileges

The `Security.framework` Authorization Services API provides a structured mechanism for privilege elevation. The deprecated function `AuthorizationExecuteWithPrivileges()` was historically the primary vector: it executes an arbitrary path as root after presenting an authentication dialog but performs **no code-signing or integrity verification** on the target binary. This enables a classic TOCTOU attack: replace the binary between authorization and execution.

The attack chain:
1. Legitimate application calls `AuthorizationExecuteWithPrivileges()` pointing to a helper tool.
2. Attacker wins a race condition, swapping the helper with a malicious payload.
3. The malicious binary executes as root with the user's authorization token.

Apple deprecated this API in macOS 10.7 but never removed it. Applications using it remain exploitable. The modern replacement is `SMJobBless()`, which requires code signing and places the helper under `launchd` control.

### Misconfigured launchd Plists

Launch daemons (`/Library/LaunchDaemons/`) run as root. Misconfigurations include:

- **Writable program paths**: If the `Program` or `ProgramArguments[0]` binary is writable by non-root users, an attacker replaces it with a payload that executes at next load.
- **Writable plist files**: If the plist itself is world-writable, an attacker modifies `Program` to point to an attacker-controlled binary.
- **Unquoted/relative paths**: A `Program` value without an absolute path may resolve through a controllable search order.
- **World-writable `WatchPaths` or `QueueDirectories`**: Triggering daemon execution by writing to watched paths.

CVE-2019-8802 demonstrated LPE through a vulnerable privileged helper tool installed by a system service with inadequate client validation.

### sudo and su Attacks

macOS `sudo` inherits standard Unix attack vectors. The CVE-2021-3156 (Baron Samedit) heap overflow in `sudoedit` affected macOS builds of sudo, enabling any local user to gain root through a crafted command-line argument triggering a heap-based buffer overflow in argument parsing. Apple patched this in Security Update 2021-002.

---

## 2. XPC Service Vulnerabilities

XPC (Cross-Process Communication) is the primary IPC mechanism on macOS, underpinning privilege separation between user-facing applications and root-level helpers. The attack surface is substantial.

### Connection Validation Flaws

An XPC service declares its connection handler via `xpc_connection_set_event_handler()` or through an `NSXPCListener` delegate. The critical security check occurs in the `-listener:shouldAcceptNewConnection:` method. Common flaws:

- **Missing entitlement checks**: The service accepts connections from any process without verifying the client's entitlements via `SecTaskCopyValueForEntitlement()`.
- **Missing code-signing verification**: No call to `SecCodeCheckValidity()` on the connecting client, allowing arbitrary processes to invoke privileged operations.
- **Overly broad entitlement matching**: Checking for an entitlement's existence rather than its value.

### PID Reuse Attacks

A recurring vulnerability class involves services that validate the connecting client's PID via `xpc_connection_get_pid()` and then perform a secondary check (code-signing, path verification) using that PID. Because PIDs are recycled, an attacker can:

1. Craft a legitimate process that initiates the XPC connection.
2. Kill that process immediately after the connection is established but before the service validates it.
3. Fork a malicious process that reuses the same PID.
4. The service's deferred validation sees the malicious process as the original legitimate caller.

This is a TOCTOU condition on the PID. The correct mitigation is audit tokens (`xpc_connection_get_audit_token()`), which are immutable per-process and cannot be reused.

CVE-2020-9839 exploited a PID reuse vulnerability in a system XPC service to achieve privilege escalation. The `diagnosticd` service validated clients by PID, enabling unauthorized access to privileged diagnostic operations.

### XPC Service Hijacking

If an XPC service's Mach service name is registered in a user-controllable launchd domain, an attacker can register a malicious service under the same name before the legitimate service starts. Clients connecting to that service name reach the attacker's code instead.

---

## 3. Sandbox Escape Techniques

The App Sandbox (`/System/Library/Sandbox/`) restricts file system access, network operations, and IPC for sandboxed applications. Escapes target the boundary between sandboxed and unsandboxed execution contexts.

### XPC-Based Escapes

Sandboxed applications can communicate with unsandboxed XPC services. If an unsandboxed XPC service performs operations on behalf of a sandboxed client without re-validating the request against sandbox constraints, the sandboxed client inherits the service's broader capabilities. CVE-2018-4331 demonstrated this through a vulnerability in `cfprefsd`, where a sandboxed process could manipulate arbitrary preference files through the unsandboxed preferences daemon.

### File System Sandbox Bypasses

- **Symlink attacks**: Creating symbolic links within the sandbox container that point to locations outside the sandbox. If a privileged process follows these symlinks without `O_NOFOLLOW`, the sandboxed process achieves out-of-bounds file access.
- **Mount point manipulation**: CVE-2022-26706 (discovered by Mickey Jin) allowed escaping the Word sandbox by abusing `Launch Services` to open a Python script with a crafted shell-escaped filename, bypassing macro sandbox restrictions.
- **Directory hardlinks**: Historically, macOS allowed directory hardlinks for Time Machine. Abuse of this mechanism allowed sandbox container escapes before Apple restricted the capability.

### IPC-Based Escapes

Beyond XPC, other IPC mechanisms provide sandbox escape potential:
- **Distributed Notifications** (`NSDistributedNotificationCenter`): Messages cross sandbox boundaries. A privileged unsandboxed listener acting on attacker-controlled notification content can be co-opted.
- **Pasteboard manipulation**: Writing crafted data to the pasteboard that triggers unsafe processing in an unsandboxed application.
- **Apple Events / AppleScript**: CVE-2020-9934 and related bugs exploited the ability of sandboxed apps to send Apple Events to unsandboxed scripting targets that lacked TCC restrictions.

---

## 4. TCC Bypass Vulnerabilities

Transparency, Consent, and Control (TCC) manages access to sensitive resources: camera, microphone, Full Disk Access, Contacts, Photos, and more. The TCC database (`~/Library/Application Support/com.apple.TCC/TCC.db` for user-level, `/Library/Application Support/com.apple.TCC/TCC.db` for system-level) stores consent decisions.

### CVE-2020-9934 — Environment Variable Abuse

The `tccd` daemon loaded its preferences using `$HOME` to resolve the user-level TCC database path. By setting `HOME` to an attacker-controlled directory containing a crafted `TCC.db` with pre-authorized entries, a malicious process could grant itself arbitrary TCC permissions. Apple mitigated this by having `tccd` resolve the home directory through the directory services framework rather than environment variables.

### CVE-2021-30713 — XCSSET TCC Bypass

The XCSSET malware exploited a zero-day TCC bypass by injecting code into a process that already held TCC permissions (e.g., `Zoom.app` with screen recording permission). The injection technique leveraged a vulnerability in how TCC validated the requesting process identity, allowing a trojanized Xcode project to inherit the host application's TCC grants. This was observed in the wild before Apple patched it.

### CVE-2021-30970 — powerdir

Discovered by Microsoft's Jonathan Bar Or, this vulnerability exploited the Directory Services `dsimport` tool. An attacker could change a user's home directory via `dsimport` to point to an attacker-controlled path, modify the TCC database at that location, then change the home directory back. The `tccd` daemon would read the poisoned database, granting unauthorized access.

### Injection into TCC-Entitled Processes

A persistent attack pattern involves injecting code into applications that already possess TCC entitlements:
- **Dylib injection** into apps with `com.apple.security.cs.allow-dyld-environment-variables` or `com.apple.security.cs.disable-library-validation`.
- **Plugin loading**: Applications that load third-party bundles (e.g., Finder Sync extensions, Safari extensions in legacy mode) inherit the host's TCC permissions.
- **Automation (Apple Events)**: Using `osascript` to script TCC-entitled applications to perform privileged operations on the attacker's behalf.

### CVE-2023-32364 — /tmp Symlink Race

This bypass exploited a race condition in how Apple's file operations resolved paths, allowing a symlink in `/tmp` to redirect a TCC-protected operation to an unprotected location, effectively leaking protected data.

---

## 5. SIP Bypass Vulnerabilities

System Integrity Protection (SIP / `rootless`) prevents even root from modifying protected system locations (`/System`, `/usr` excluding `/usr/local`, `/bin`, `/sbin`) and restricts kernel extension loading, NVRAM modification, and task-for-pid on protected processes.

### CVE-2021-30892 — Shrootless

Discovered by Microsoft Threat Intelligence, this vulnerability targeted `system_installd`, a daemon that runs with the `com.apple.rootless.install` entitlement (bypasses SIP for package installation). When processing Apple-signed packages with a `postinstall` script, `system_installd` executed the script under a new default environment. An attacker could craft a package with a `postinstall` script that wrote to SIP-protected locations because `system_installd` passed its SIP-bypass entitlement to child processes. The attack was possible by creating a symlink in the package payload that redirected the script's output to a protected directory.

### CVE-2021-30727 — Mount-Based SIP Bypass

By mounting a crafted disk image containing a modified system file hierarchy, attackers could overlay SIP-protected paths. The mount-based approach exploited the fact that mounted volumes were not always subject to SIP restrictions, allowing modification of protected binaries through the overlay.

### CVE-2023-32369 — Migraine

Discovered by Microsoft, this SIP bypass exploited the Migration Assistant (`migrationTool`). The migration utility runs with SIP-bypass entitlements to facilitate data transfer from an old system. By manipulating the migration workflow, an attacker could use the tool's elevated privileges to modify SIP-protected file system locations, load arbitrary kernel extensions, or access protected data.

### Installer Package Abuse

The `installer` binary and `PackageKit.framework` process `.pkg` files with elevated privileges. Historical vectors include:
- `preinstall`/`postinstall` scripts executing under SIP-exempt entitlements inherited from the installer daemon.
- BOM (Bill of Materials) manipulation to write files to protected locations during legitimate package installation.
- Distribution XML scripts performing operations as root with SIP-bypass context.

---

## 6. dyld / Library Injection Attacks

The dynamic linker (`dyld`) provides multiple injection vectors for code execution within target processes.

### DYLD_INSERT_LIBRARIES

Analogous to `LD_PRELOAD` on Linux, this environment variable forces `dyld` to load a specified library into every spawned process. Protections:
- SIP prevents use against protected system binaries.
- The hardened runtime flag (`com.apple.security.cs.runtime`) ignores `DYLD_*` variables unless the binary also carries `com.apple.security.cs.allow-dyld-environment-variables`.
- SUID/SGID binaries strip `DYLD_*` variables.

However, applications without hardened runtime or with the allow-dyld entitlement remain vulnerable. Many third-party applications and some Apple utilities in non-protected locations are exploitable.

### Dylib Hijacking and @rpath Attacks

macOS applications reference dynamic libraries through install names that may include `@rpath`, `@loader_path`, or `@executable_path`. The `dyld` search order for `@rpath`-referenced libraries checks each `LC_RPATH` entry in order. If an earlier search path is writable by an attacker and the library does not exist there, the attacker plants a malicious dylib that loads before the legitimate one.

Identification:

```bash
# Find missing rpath libraries that could be hijacked
otool -l /path/to/binary | grep -A2 LC_RPATH
# Check for weak imports that load without error if missing
otool -l /path/to/binary | grep -A2 LC_LOAD_WEAK_DYLIB
```

CVE-2015-3760 and CVE-2019-8629 exploited dylib hijacking in Apple system services. The `Objective-See` project maintains tooling (`DylibHijackScanner`) for systematic discovery.

### Electron Application Injection

Electron apps are particularly susceptible because:
- They bundle a Chromium runtime that supports `--inspect` and `--remote-debugging-port` flags.
- Many Electron apps lack hardened runtime, enabling `DYLD_INSERT_LIBRARIES`.
- The `ELECTRON_RUN_AS_NODE` environment variable forces the Electron binary to behave as a raw Node.js interpreter, bypassing the application's packaging and any associated entitlements or TCC permissions.

CVE-2020-9934 and related issues demonstrated TCC bypasses through Electron app injection where the host app held camera/microphone permissions.

### Library Validation Bypass

The `com.apple.security.cs.disable-library-validation` entitlement (or the absence of the `library-validation` flag in code-signing options) allows a process to load unsigned or differently-signed libraries. Processes with this entitlement are prime targets for dylib injection, as they explicitly opt out of the protection that ensures only Apple-signed or same-team-ID-signed libraries load.

---

## Summary of Key CVEs

| CVE | Year | Category | Description |
|-----|------|----------|-------------|
| CVE-2021-3156 | 2021 | LPE | sudo heap overflow (Baron Samedit) |
| CVE-2020-9839 | 2020 | XPC | PID reuse in diagnosticd |
| CVE-2018-4331 | 2018 | Sandbox Escape | cfprefsd sandbox bypass |
| CVE-2022-26706 | 2022 | Sandbox Escape | Word macro sandbox escape |
| CVE-2020-9934 | 2020 | TCC Bypass | $HOME env variable TCC.db redirect |
| CVE-2021-30713 | 2021 | TCC Bypass | XCSSET zero-day TCC bypass |
| CVE-2021-30970 | 2021 | TCC Bypass | powerdir — dsimport home directory manipulation |
| CVE-2023-32364 | 2023 | TCC Bypass | /tmp symlink race condition |
| CVE-2021-30892 | 2021 | SIP Bypass | Shrootless — system_installd abuse |
| CVE-2023-32369 | 2023 | SIP Bypass | Migraine — Migration Assistant abuse |
| CVE-2021-30727 | 2021 | SIP Bypass | Mount-based SIP bypass |

---

## Defensive Recommendations

1. **Audit XPC services** with `launchctl list` and verify entitlement checks use audit tokens, not PIDs.
2. **Enable hardened runtime** for all distributed binaries and avoid `com.apple.security.cs.disable-library-validation`.
3. **Remove deprecated API usage** — replace `AuthorizationExecuteWithPrivileges()` with `SMJobBless()`.
4. **Monitor TCC.db** integrity and watch for unauthorized `HOME` environment variable changes.
5. **Validate launchd plists** — ensure `Program` paths are absolute, signed, and non-writable by unprivileged users.
6. **Use `@loader_path`** instead of `@rpath` where possible and ensure all rpath search directories are non-writable.
7. **Strip `DYLD_*` environment variables** in setuid contexts and enforce library validation.
