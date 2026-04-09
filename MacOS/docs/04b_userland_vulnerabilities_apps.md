# macOS Userland Vulnerabilities: Application-Level and IPC Attack Surface

## Overview

The macOS userland attack surface extends far beyond the kernel. Applications, their IPC mechanisms, runtime environments, and installer infrastructure all present exploitable vectors. This document examines six critical areas: browser exploitation via WebKit/JavaScriptCore, installer package abuse, Apple Event and AppleScript attack primitives, Mach-O binary format exploitation, third-party application vulnerability patterns, and Objective-C/Swift runtime attacks.

---

## 1. Browser Exploitation on macOS

### Safari and WebKit Architecture

Safari delegates rendering to WebKit, which runs web content in a sandboxed process (`com.apple.WebKit.WebContent`). The architecture follows a multi-process model: the UI process (`Safari`), the web content process, the networking process (`com.apple.WebKit.Networking`), and GPU/media helper processes. Each web content process is confined by a `Sandbox` profile restricting file system access, Mach port lookups, and syscall usage.

### JavaScriptCore (JSC) Exploitation

JavaScriptCore is WebKit's JavaScript engine and contains a multi-tier JIT compiler: LLInt (interpreter), Baseline JIT, DFG (Data Flow Graph) JIT, and FTL (Faster Than Light) backed by B3/Air. Each tier introduces distinct vulnerability classes:

- **JIT Type Confusion**: The DFG and FTL compilers perform speculative optimizations based on profiled types. When speculation is incorrect and bounds checks are elided, attackers achieve type confusion. CVE-2019-8623 demonstrated a DFG compiler bug where `CheckStructure` nodes were incorrectly eliminated, allowing a `JSArray` to be treated as a different structure, yielding an `addrof`/`fakeobj` primitive.

- **Bounds Check Elimination (BCE) Bugs**: JIT compilers attempt to prove array accesses are in-bounds to eliminate runtime checks. Flawed range analysis in the DFG `IntegerRangeOptimization` phase has produced OOB read/write primitives. The attacker constructs a loop where the JIT incorrectly concludes the index is always within bounds, then triggers the optimized code path.

- **Garbage Collector (GC) Interactions**: JSC uses a copying and marking collector. Race conditions between GC marking and JIT-compiled code mutating object layouts have led to use-after-free conditions. The `MarkedBlock` allocator and `SlotVisitor` must remain synchronized; failures here expose dangling pointers.

A standard JSC exploit chain proceeds: trigger a bug to gain `addrof` (leak object address) and `fakeobj` (forge a fake JS object at a controlled address), then construct an `ArrayBuffer` with an overwritten backing store pointer to achieve arbitrary read/write. From there, overwrite JIT code page permissions or a function pointer to gain code execution.

### DOM and Renderer Exploits

WebKit's DOM implementation in C++ is a rich source of use-after-free bugs. DOM node lifecycle management — particularly during tree mutations, event dispatch, and layout recalculation — creates conditions where a callback (e.g., a `MutationObserver` or `DOMNodeRemoved` event handler) can free a node that is still referenced on the stack.

CVE-2021-30858, an actively exploited WebKit UAF, involved processing maliciously crafted web content that could trigger arbitrary code execution. These renderer bugs execute within the sandboxed WebContent process, requiring a sandbox escape for full compromise.

### Browser Sandbox Escapes

The WebContent sandbox communicates with the privileged UI process and system services via Mach IPC. Sandbox escapes target:

- **Mach service interactions**: The WebContent process holds send rights to specific Mach ports. Vulnerabilities in the message handlers of privileged services (e.g., `com.apple.windowserver`) allow the sandboxed process to escalate. CVE-2020-9839 demonstrated a Mach port name collision issue enabling sandbox escape.
- **Shared memory regions**: Bugs in shared memory handling between WebContent and GPU processes.
- **File quarantine bypass**: Chaining a renderer exploit with a download mechanism that strips the `com.apple.quarantine` extended attribute.

---

## 2. Installer Package Vulnerabilities

### PKG Format and Attack Surface

macOS `.pkg` files are XAR archives containing a `Distribution` XML manifest, `PackageInfo` metadata, a BOM (Bill of Materials), a payload archive, and optional pre/post-install scripts. The `installer` binary and the `installd` daemon process these with root privileges.

### Pre/Post-Install Script Abuse

Installation scripts (`preinstall`, `postinstall`) execute as root. An attacker who can modify or supply a malicious `.pkg` convinces the user to run the installer, gaining root code execution. Legitimate applications that download and execute `.pkg` files without verification are also vulnerable.

**TOCTOU in script execution**: The `installd` daemon extracts scripts to a temporary directory before execution. A race condition between extraction and execution allows an attacker with local access to replace the script file, escalating privileges (demonstrated in CVE-2019-8561).

### Distribution XML Manipulation

The `Distribution` XML file controls installation flow: volume checks, choices, and script references. Manipulating `<pkg-ref>` elements can redirect payload extraction to arbitrary paths. The `<script>` element can reference JavaScript executed in the installer context. A crafted `Distribution` file can alter the installation to overwrite arbitrary files by manipulating `<relocate>` entries or using symlink attacks against the chosen install location.

### BOM (Bill of Materials) Manipulation

The BOM file defines file ownership, permissions, and paths for installed files. Tools like `lsbom` and `mkbom` allow inspection and creation. Manipulating the BOM to set SUID bits on installed binaries or to specify paths containing directory traversal sequences (`../`) can lead to privilege escalation. CVE-2019-8513 exploited a parsing inconsistency in BOM handling to write files outside the intended installation directory.

---

## 3. Apple Event and AppleScript Attacks

### osascript Abuse

`osascript` executes AppleScript and JavaScript for Automation (JXA) from the command line. It is a favored post-exploitation tool because it uses legitimate system APIs and blends with normal system activity.

Key attack patterns include: displaying fake authentication dialogs via `display dialog` with `hidden answer` to phish credentials, manipulating the Finder and System Events to access files, and using `do shell script` with administrator privileges to escalate. JXA provides direct access to the Objective-C bridge via `ObjC.import()`, enabling arbitrary framework calls from script.

### Apple Events for Automation Attacks

Apple Events are the underlying IPC for inter-application scripting. Since macOS Mojave, Transparency, Consent, and Control (TCC) requires user approval before an application can send Apple Events to another. However, several bypass techniques exist:

- **TCC database manipulation**: Direct modification of `~/Library/Application Support/com.apple.TCC/TCC.db` (if SIP is disabled) or using an application already granted `kTCCServiceAppleEvents` permission.
- **Inherited permissions**: A child process inherits the TCC permissions of its parent. If a permitted application can be induced to spawn a controlled process, the child inherits Apple Event access.
- **Synthetic clicks**: Before tightening in Catalina, programmatic UI clicks could dismiss TCC prompts. CVE-2019-8642 demonstrated a synthetic click attack bypassing the consent dialog.

### Accessibility API Abuse

The Accessibility API (`AXUIElement`) enables full programmatic control of any application's UI. An application granted Accessibility permission can keystroke-inject, read screen contents, click buttons, and exfiltrate data. Attackers who obtain this permission (via social engineering or TCC bypass) achieve near-complete user-session control.

---

## 4. Mach-O Binary Exploitation

### Format Abuse: Fat and Universal Binaries

A fat (universal) binary contains multiple architecture slices (x86_64, arm64, etc.). The `fat_header` specifies offsets and sizes for each slice. Vulnerabilities arise in parsers that fail to validate:

- **Overlapping slices**: Two architecture entries whose offset/size ranges overlap, causing tools to process ambiguous data. This has been used to confuse code signing verification — one slice passes validation while the other (actually executed) slice contains malicious code.
- **Integer overflows**: The `offset` and `size` fields in `fat_arch` are 32-bit. Arithmetic on these values without overflow checks leads to OOB reads in Mach-O parsers.

### Code Signing Edge Cases

Apple's code signing infrastructure validates Mach-O binaries via `codesign` and the kernel's `AMFI` (Apple Mobile File Integrity) subsystem. Known edge cases include:

- **Code Signature Slot Confusion**: The code directory specifies slots for Info.plist, resources, and the code signature itself. Manipulating slot hashes or adding extra slots has bypassed validation in older macOS versions.
- **Detached Signatures**: Signatures can be stored in a detached file rather than embedded in the binary. Tools that check only embedded signatures miss detached-signature binaries.
- **Ad-hoc signing pitfalls**: Ad-hoc signed binaries (no Apple identity) are trusted differently. On Apple Silicon, all binaries must be signed, but ad-hoc signatures carry no identity verification, allowing code injection into ad-hoc-signed binaries if SIP does not block it.

### Mach-O Parser Vulnerabilities

The `dyld` loader, `otool`, and third-party security tools all parse Mach-O files. Malformed load commands — truncated `LC_SEGMENT_64` commands, cyclic `LC_LOAD_DYLIB` chains, or corrupted string tables — have triggered buffer overflows and NULL dereferences in these parsers. CVE-2022-42813 and related issues demonstrated that carefully crafted Mach-O files could crash or exploit analysis tools.

---

## 5. Third-Party Application Vulnerabilities

### Electron Application Weaknesses

Electron apps bundle Chromium and Node.js. On macOS, common vulnerabilities include:

- **`nodeIntegration` enabled in renderers**: If a renderer process has Node.js access and loads remote content, XSS becomes RCE. The attacker injects `require('child_process').exec(...)` via a DOM vulnerability.
- **Insecure `webPreferences`**: Disabled `contextIsolation`, enabled `nodeIntegrationInSubFrames`, or overly permissive `webSecurity:false` settings.
- **Protocol handler injection**: Custom protocol handlers (`myapp://`) that pass user input to shell commands or `shell.openExternal()` without sanitization.

### Privileged Helper Tool Vulnerabilities

macOS apps that need root access use the `SMJobBless` API to install a privileged helper in `/Library/PrivilegedHelperTools/`. The helper communicates with the main app over XPC. Vulnerabilities arise when:

- **Missing XPC client validation**: The helper does not verify the calling application's code signature via `SecCodeCopySigningInformation`, allowing any process to send commands to the root helper.
- **Command injection via XPC**: The helper passes XPC message contents to `NSTask` or `system()` without sanitization. CVE-2020-8511 (in a backup application) demonstrated a local privilege escalation through an unsanitized XPC parameter passed to a shell command.

### Auto-Updater Exploits (Sparkle Framework)

Sparkle is the dominant auto-update framework for macOS applications. Historical vulnerabilities include:

- **HTTP appcast feeds**: Prior to Sparkle 1.18, many apps fetched update manifests over HTTP, enabling MITM to serve malicious updates. CVE-2016-2402 affected hundreds of applications.
- **Signature bypass**: Sparkle uses DSA/EdDSA signatures on updates. Implementations that checked signatures only on the `.zip` but not the extracted `.app` were vulnerable to replacement between verification and installation.
- **Quarantine bypass via Sparkle**: Updates applied by Sparkle may not carry quarantine attributes, bypassing Gatekeeper checks on the updated binary.

---

## 6. Objective-C/Swift Runtime Attacks

### Method Swizzling

The Objective-C runtime allows replacing method implementations at runtime via `method_exchangeImplementations()`. An attacker who can inject a dylib (via `DYLD_INSERT_LIBRARIES` on non-hardened-runtime binaries) can swizzle security-critical methods:

```objc
Method orig = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
Method repl = class_getInstanceMethod([HookClass class], @selector(hooked_dataTaskWithRequest:completionHandler:));
method_exchangeImplementations(orig, repl);
```

This intercepts all network requests in the process, enabling credential theft and data exfiltration without modifying the binary on disk.

### ISA Pointer Manipulation

Every Objective-C object begins with an `isa` pointer identifying its class. Corrupting the `isa` pointer redirects all method dispatch for that object. In exploitation, this is used after achieving a controlled write: overwriting an object's `isa` to point to an attacker-controlled fake class structure redirects `objc_msgSend` to attacker-controlled function pointers.

Modern `isa` pointers use non-pointer ISA encoding (tagged pointers with class index, reference count, and flags packed into 64 bits). Exploitation must account for the bitmask layout: bits 0-2 contain flags, bits 3-35 encode the class pointer (shifted), and upper bits store the reference count and other metadata.

### Selector and `objc_msgSend` Abuse

Objective-C method dispatch resolves selectors through `objc_msgSend`, which reads the class's method cache and then the method list. Attacks include:

- **Cache poisoning**: If an attacker can write to the method cache (`cache_t`), inserting a fake `bucket_t` entry causes `objc_msgSend` to call an arbitrary function when the target selector is invoked.
- **`class_addMethod` injection**: Dynamically adding methods to existing classes. If a class does not implement a method, `class_addMethod` registers a new IMP. This is used to add backdoor methods to system classes.

### Retain/Release and ARC Vulnerabilities

Objective-C memory management (both MRC and ARC) uses reference counting. Exploitation targets:

- **Over-release (double-free)**: Sending an extra `release` message drops the reference count to zero prematurely, freeing the object while other references exist. Subsequent use of the dangling pointer provides a use-after-free primitive.
- **Autorelease pool manipulation**: Objects added to an autorelease pool are released when the pool drains. If an attacker controls when a pool drains (e.g., by triggering a nested run loop), they can cause premature deallocation.
- **ARC bypass via `__bridge_transfer`**: Incorrect bridging between Core Foundation and Objective-C types (`__bridge_transfer` vs. `__bridge_retained`) mismanages ownership, leading to double-free or memory leaks exploitable in specific contexts.

---

## Conclusion

The macOS userland attack surface is broad and multi-layered. Browser exploitation via JSC/WebKit remains the highest-impact remote vector, while installer packages and privileged helper tools provide local escalation paths. The Objective-C runtime's dynamism — method swizzling, ISA manipulation, and dynamic method resolution — offers post-exploitation persistence and interception capabilities unique to the platform. Effective defense requires hardened runtime enforcement, strict XPC client validation, JIT hardening (enabled via `MAP_JIT` on Apple Silicon), and proper code signature verification at every trust boundary.

---

*Document version 1.0 — macOS Userland Application & IPC Vulnerability Research*
