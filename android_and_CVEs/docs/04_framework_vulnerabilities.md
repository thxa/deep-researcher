# Android Framework and System Service Vulnerabilities

## Table of Contents

1. [System Server Vulnerabilities](#1-system-server-vulnerabilities)
2. [Package Manager Vulnerabilities](#2-package-manager-vulnerabilities)
3. [Activity Manager Vulnerabilities](#3-activity-manager-vulnerabilities)
4. [Notification and PendingIntent Vulnerabilities](#4-notification-and-pendingintent-vulnerabilities)
5. [Bluetooth Vulnerabilities](#5-bluetooth-vulnerabilities)
6. [WiFi Stack Vulnerabilities](#6-wifi-stack-vulnerabilities)
7. [NFC Vulnerabilities](#7-nfc-vulnerabilities)
8. [Telephony/SMS Vulnerabilities](#8-telephonysms-vulnerabilities)
9. [Android Debug Bridge (ADB)](#9-android-debug-bridge-adb)
10. [Settings/System UI Vulnerabilities](#10-settingssystem-ui-vulnerabilities)

---

## 1. System Server Vulnerabilities

### Overview

The `system_server` process is the most privileged userspace process in Android after `init` and `zygote`. It hosts all core system services — ActivityManagerService, PackageManagerService, WindowManagerService, PowerManagerService, and dozens more — running under the `system` UID (1000). Compromising `system_server` grants an attacker control over virtually all device functionality without requiring a kernel exploit.

### Attack Surface

The `system_server` exposes its services via Binder IPC. Every app on the device communicates with `system_server` through Binder transactions. Each transaction crosses a privilege boundary: the calling app runs in an unprivileged sandbox while the receiving service runs with system-level permissions. Vulnerabilities arise from:

- **Insufficient input validation** on Binder transaction data (Parcels). Malformed Parcels can trigger type confusion, buffer overflows, or deserialization bugs within system services.
- **Serialization/Deserialization mismatches** in `Parcelable` objects. The `Bundle` class has historically been a vector for "Parcel mismatch" attacks where a crafted Bundle deserializes differently on read than on write, enabling attackers to smuggle extra key-value pairs past security checks (the "Bundle mismatch" or "LaunchAnywhere" class of bugs).
- **Race conditions** in service state management, particularly in multi-step operations that involve checking permissions and then performing actions (TOCTOU).
- **Unsafe handling of file descriptors** passed through Binder, potentially allowing an app to gain access to files owned by system_server.

### Notable CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2014-7911 | 2014 | `ObjectInputStream` deserialization in `system_server` allowed arbitrary code execution via a crafted `Serializable` object sent through Binder | Critical |
| CVE-2015-3825 | 2015 | "LaunchAnywhere" — Bundle serialization/deserialization mismatch allowing an app to launch arbitrary activities with system privileges | High |
| CVE-2017-0806 | 2017 | Parcel read/write mismatch in `GateKeeperResponse` leading to privilege escalation within `system_server` | High |
| CVE-2020-0001 | 2020 | Privilege escalation in `system_server` via ActivityManagerService allowing a local attacker to execute code in the context of `system_server` | High |
| CVE-2021-0928 | 2021 | `Parcelable` mismatch in `OutputConfiguration` leading to arbitrary code execution in `system_server` | High |
| CVE-2023-21238 | 2023 | Information disclosure in `system_server` via side-channel in the screenshot handling logic | Moderate |

### Exploitation Pattern: Bundle Mismatch

The classic `system_server` exploitation pattern exploits the `Bundle` (or `Parcel`) serialization layer:

1. Attacker constructs a `Bundle` containing a `Parcelable` object whose `writeToParcel()` and `createFromParcel()` implementations produce asymmetric byte streams.
2. When `system_server` reads the `Bundle` to perform a permission check, it deserializes a benign payload.
3. When `system_server` re-reads the same `Bundle` to execute the action, the deserialization offset has shifted, and a different (malicious) payload is extracted.
4. This allows bypassing `checkCallingPermission()` checks and performing privileged operations such as launching activities as `system`, installing packages, or modifying settings.

Google has incrementally hardened `Bundle` handling over multiple Android releases, introducing stricter type checking and deprecating `Parcel.readSerializable()` without class filters.

---

## 2. Package Manager Vulnerabilities

### Overview

The PackageManagerService (PMS) is responsible for installing, verifying, and managing all APK packages. It handles APK parsing, signature verification, permission granting, and package metadata management. Vulnerabilities here can allow installation of malicious apps with elevated permissions or complete bypass of signature verification.

### APK Parsing Bugs

Android's APK parser (originally in `PackageParser`, later refactored into `PackageParser2` and `ParsingPackageUtils`) must handle the ZIP format, XML binary format (AndroidManifest.xml), DEX files, and signing blocks. Malformed APKs can exploit:

- Integer overflows in ZIP header parsing
- Inconsistencies between the ZIP central directory and local file headers
- Ambiguities in how different components (the installer, the runtime, the verifier) interpret the same APK file

### Signature Bypass Vulnerabilities

#### Janus (CVE-2017-13156)

The Janus vulnerability exploited the fact that Android's APK signature verification (v1 scheme, JAR-based) and the Dalvik/ART runtime interpreted APK files differently. Because an APK is a ZIP file (read from the end) and a DEX file (read from the beginning), an attacker could prepend a malicious DEX file to a legitimately signed APK. The signature verification would validate the original ZIP content while the runtime would execute the prepended DEX code.

**Impact**: An attacker could replace any app on the device with a trojanized version that retained the original app's valid signature. This meant the malicious app inherited all the original app's permissions, data access, and trust relationships — including system apps.

**Affected Versions**: Android 5.0 through 8.1 (before APK Signature Scheme v2 enforcement).

**Mitigation**: APK Signature Scheme v2 (introduced in Android 7.0) signs the entire APK file as a binary blob rather than individual ZIP entries, making prepending attacks impossible. Android 9.0 introduced v3 with key rotation support, and Android 11 introduced v4 for incremental installation.

#### FakeID (CVE-2014-8609)

The FakeID vulnerability exploited a flaw in how Android verified the certificate chain of APK signatures. Android checked that each certificate in the chain was valid but failed to verify that the issuer certificate actually signed the subject certificate — it only compared the issuer's `Subject` field against the subject certificate's `Issuer` field without performing cryptographic verification of the chain.

**Impact**: A malicious app could claim to be signed by any certificate (including Adobe Flash's certificate, which granted plugin privileges, or the device manufacturer's certificate, granting device administration capabilities) simply by including a forged certificate chain with matching subject/issuer names.

**Affected Versions**: Android 2.1 through 4.4.

### Notable CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2014-8609 | 2014 | FakeID — Certificate chain validation bypass allowing arbitrary identity impersonation | Critical |
| CVE-2017-13156 | 2017 | Janus — APK signature bypass via DEX/ZIP polyglot file | Critical |
| CVE-2020-0099 | 2020 | Installer hijacking via improper handling of session parameters in PackageInstaller | High |
| CVE-2020-0418 | 2020 | Privilege escalation in PackageManagerService due to improper permission management | High |
| CVE-2021-0org | 2021 | Multiple APK parsing issues leading to app installation with unexpected permissions | High |
| CVE-2023-21085 | 2023 | Remote code execution in Bluetooth-adjacent APK handling component | Critical |

### Installer Hijacking

Installer hijacking attacks exploit the time window between when a user confirms installation and when the APK is actually installed. In a classic installer hijacking scenario:

1. The victim downloads a legitimate APK to external storage (world-readable before scoped storage).
2. The malicious app monitors the download directory using `FileObserver`.
3. When the APK is written and the user initiates installation, the malicious app replaces the APK with a trojaned version before `PackageInstaller` reads it.
4. The user sees the original app's name and permissions dialog but installs the attacker's payload.

Mitigations include scoped storage (Android 10+), which restricts access to other apps' files, and the Session-based installer API that copies APKs to a protected staging directory.

---

## 3. Activity Manager Vulnerabilities

### Overview

The ActivityManagerService (AMS) manages the lifecycle of all Activities, Services, BroadcastReceivers, and ContentProviders. It controls task stacks, the back stack, recent apps, and inter-component communication via Intents. Vulnerabilities in AMS can allow task hijacking, activity spoofing, and phishing attacks that are nearly indistinguishable from legitimate system UI.

### Task Hijacking and StrandHogg

#### StrandHogg (CVE-2019-2215 related, publicly as "StrandHogg 1.0")

The original StrandHogg attack exploited Android's task affinity mechanism. By setting `taskAffinity` to match a target app and using `allowTaskReparenting`, a malicious app could inject its activity into the target app's task stack. When the user launched the legitimate app, the malicious activity would appear on top, enabling credential phishing or permission hijacking.

#### StrandHogg 2.0 (CVE-2020-0096)

StrandHogg 2.0 was a more severe escalation vulnerability in ActivityManagerService that allowed a malicious app to hijack virtually any app on the device simultaneously, without requiring specific task affinity configuration.

**Technical Details**: The vulnerability existed in `ActivityStarter.java` and related AMS components. It exploited how Android handled activity launch modes and task assignment when `startActivities()` was called with specific Intent flag combinations. A malicious app could:

1. Use reflection or direct Binder calls to invoke `startActivities()` with crafted Intent arrays.
2. The crafted Intents would cause AMS to place the malicious activities into the task stacks of other running apps.
3. The malicious activities would overlay the legitimate apps' UIs, appearing as part of those apps.

**Impact**: Full phishing capability — the malicious overlay could request permissions (appearing as if the legitimate app was requesting them), harvest credentials, or display fake login screens. The attack was invisible to the user because the malicious activity appeared in the target app's task, with the correct app icon in the recent apps screen.

**Affected Versions**: Android 8.0, 8.1, and 9.0 (Android 10 was not affected due to activity launch restrictions).

**CVSS**: 7.8 (High) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

### Activity Spoofing via Intent Redirection

A related class of vulnerabilities involves "Intent redirection" — when a privileged app (or system service) receives an Intent from an untrusted source and uses attacker-controlled data to construct a new Intent that launches an activity. If the privileged app doesn't validate the target component, the attacker can cause a system-level component to launch arbitrary activities, potentially with elevated privileges.

### Notable CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2020-0096 | 2020 | StrandHogg 2.0 — Activity hijacking via AMS task manipulation | High |
| CVE-2020-0017 | 2020 | Information disclosure via improper activity lifecycle handling | Moderate |
| CVE-2021-0585 | 2021 | Privilege escalation via Intent redirection in Settings activity | High |
| CVE-2021-0799 | 2021 | Task hijacking through crafted task affinity and launch mode abuse | High |
| CVE-2023-21109 | 2023 | Privilege escalation in ActivityManagerService | High |

---

## 4. Notification and PendingIntent Vulnerabilities

### Overview

`PendingIntent` is a token that wraps an `Intent` and grants the holder the ability to perform an operation (starting an Activity, sending a Broadcast, or starting a Service) with the permissions and identity of the app that created it. This delegation mechanism is fundamental to notifications, alarms, and app widgets — but it introduces serious security risks when PendingIntents are constructed improperly.

### The Core Vulnerability: Mutable Implicit PendingIntents

A PendingIntent created with an implicit (unspecified component) base Intent and mutable flags allows any app that receives the PendingIntent to:

1. Fill in the unspecified fields (target component, action, data, extras).
2. Send the now-complete Intent, which executes with the creating app's identity and permissions.

If a privileged app (running as `system` or holding dangerous permissions) creates an implicit mutable PendingIntent and exposes it through a notification, any app that can read the notification (via `NotificationListenerService`) can weaponize it.

### Attack Scenario

```
1. System app creates: PendingIntent.getActivity(ctx, 0, new Intent(), FLAG_MUTABLE)
2. This PendingIntent is attached to a notification
3. Malicious NotificationListener reads the notification and extracts the PendingIntent
4. Attacker calls: pendingIntent.send(ctx, 0, new Intent("android.settings.MANAGE_ALL_APPLICATIONS"))
5. The Intent executes with the system app's permissions
```

### Notable CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2020-0189 | 2020 | Privilege escalation via mutable PendingIntent in system notification | High |
| CVE-2020-0294 | 2020 | PendingIntent hijacking in system services | High |
| CVE-2021-0287 | 2021 | Implicit PendingIntent in Wi-Fi service allowing privilege escalation | High |
| CVE-2021-0604 | 2021 | PendingIntent vulnerability in Bluetooth OPP service | Moderate |
| CVE-2022-20223 | 2022 | Mutable PendingIntent in Settings leading to arbitrary activity launch as system | High |

### Mitigations

Android 12 (API 31) introduced `FLAG_IMMUTABLE` as the default for PendingIntents and requires developers to explicitly opt into `FLAG_MUTABLE`. The platform also began warning about implicit PendingIntents at build time through lint checks, and Android 14 further restricted mutable PendingIntents to cases that explicitly require input injection (e.g., inline reply notifications).

---

## 5. Bluetooth Vulnerabilities

### Overview

Android's Bluetooth stack (Fluoride/Gabeldorsche, transitioning to the newer Bluetooth stack in Android 13+) is a complex C/C++ codebase handling multiple protocols (L2CAP, RFCOMM, SDP, AVDTP, AVRCP, GATT, SMP, and more). It runs in the `com.android.bluetooth` process with `bluetooth` UID privileges. Remote Bluetooth vulnerabilities are especially dangerous because they require no user interaction and can be exploited from physical proximity (typically ~10m, extendable with directional antennas).

### BlueFrag (CVE-2020-0022)

**Technical Details**: BlueFrag is a remote code execution vulnerability in Android's Bluetooth stack, specifically in the `reassemble_and_dispatch()` function in `packet_fragmenter.cc`. The vulnerability is an out-of-bounds write caused by an incorrect bounds calculation when reassembling fragmented L2CAP packets.

When the Bluetooth controller receives fragmented ACL data packets, the `packet_fragmenter` module reassembles them into complete L2CAP frames. The bug was in the calculation of the remaining buffer space during reassembly — the code failed to account for the L2CAP header size when checking whether the incoming fragment would fit in the reassembly buffer, allowing an attacker to write beyond the allocated buffer.

**CVSS**: 8.8 HIGH — CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Impact**:
- On Android 8.0–9.0: Full remote code execution (RCE) with Bluetooth daemon privileges.
- On Android 10: Denial of Service (crash of the Bluetooth daemon).
- The difference is due to ASLR and other hardening measures that made reliable exploitation harder on Android 10, but the memory corruption itself was present.

**Exploitation Requirements**: The attacker needs to know the target's Bluetooth MAC address and the target's Bluetooth must be discoverable or the attacker must know/predict the address. No pairing is required.

### BlueRepli

BlueRepli is a class of Bluetooth profile impersonation attacks where an attacker exploits the Bluetooth pairing and authentication process to impersonate a previously paired device's profile (e.g., PBAP — Phone Book Access Profile). By spoofing the Bluetooth address and profile UUID of a trusted device (like a car's hands-free kit), the attacker can access the victim's contacts, call logs, and SMS messages without triggering a new pairing request.

### BrakTooth

BrakTooth is a family of over 16 Bluetooth Classic vulnerabilities discovered in 2021 that affect the Link Manager Protocol (LMP) layer of commercial Bluetooth chipsets from Intel, Qualcomm, Texas Instruments, and others. While not Android-specific, these vulnerabilities affect Android devices using those chipsets. Attacks include:

- **Feature response flooding**: Sending malformed LMP feature response packets causing firmware crashes.
- **Truncated SCO connections**: Crafted SCO link requests that crash the Bluetooth baseband.
- **Paging procedure abuse**: Malformed paging responses causing deadlocks in the controller firmware.

### Notable Bluetooth CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2020-0022 | 2020 | BlueFrag — RCE via OOB write in L2CAP reassembly | High (8.8) |
| CVE-2019-2009 | 2019 | RCE in Bluetooth SDP (Service Discovery Protocol) | Critical |
| CVE-2018-9355 | 2018 | RCE in Bluetooth SMP (Security Manager Protocol) | Critical |
| CVE-2020-0069 | 2020 | Information leak via Bluetooth allowing memory disclosure | High |
| CVE-2021-0129 | 2021 | Improper access control in BlueZ allowing authenticated info disclosure | Medium |
| CVE-2022-20345 | 2022 | RCE in Bluetooth AVDTP (Audio/Video Distribution Transport Protocol) | High |
| CVE-2023-21127 | 2023 | RCE in Bluetooth stack via crafted packet processing | Critical |

---

## 6. WiFi Stack Vulnerabilities

### Overview

Android's WiFi stack involves multiple layers: the Linux kernel WiFi drivers, `wpa_supplicant` (for WPA/WPA2/WPA3 authentication), `hostapd` (for hotspot mode), and the Java-level `WifiService`. Each layer presents a distinct attack surface.

### wpa_supplicant Vulnerabilities

`wpa_supplicant` runs as a native daemon and handles 802.1X authentication, WPA handshakes, and connection management. Being written in C, it is susceptible to memory corruption vulnerabilities:

- **P2P (Wi-Fi Direct) SSID processing** (CVE-2015-1863): A buffer overflow in the P2P SSID handling code allowed remote code execution when processing Wi-Fi Direct service discovery responses. An attacker within WiFi range could trigger the overflow by sending a crafted P2P response.
- **EAP-pwd (CVE-2019-9494, CVE-2019-9495)**: Part of the "Dragonblood" attack family, these vulnerabilities allowed side-channel attacks against the WPA3 SAE (Dragonfly) handshake implementation in `wpa_supplicant`, potentially allowing password recovery.

### KRACK on Android (CVE-2017-13077 through CVE-2017-13088)

The Key Reinstallation Attacks (KRACK) were devastating to Android devices, particularly those running Android 6.0+ which used `wpa_supplicant` v2.4+. This version had a bug where, upon receiving a retransmitted message 3 of the WPA2 4-way handshake, it would reinstall an **all-zero encryption key** rather than the legitimate session key.

**Impact**: An attacker could decrypt all WiFi traffic from the vulnerable Android device. The all-zero key made exploitation trivial compared to other platforms where the reinstalled key was the legitimate key (still enabling replay/decryption but requiring more effort).

**Affected Versions**: Android 6.0 and later (using wpa_supplicant v2.4+). Patched in the November 2017 Android security bulletin.

### WiFi Direct Exploitation

WiFi Direct (P2P) creates a direct connection between devices without a traditional access point. The P2P group negotiation and service discovery protocols have been a source of bugs:

- Malformed P2P probe responses can crash the WiFi service
- Group Owner Negotiation manipulation can force a device into an insecure group owner configuration
- Service discovery response injection can trigger buffer overflows in `wpa_supplicant`

### Notable WiFi CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2015-1863 | 2015 | wpa_supplicant P2P SSID overflow — RCE via WiFi | Critical |
| CVE-2017-13077 | 2017 | KRACK — WPA2 key reinstallation in 4-way handshake | High |
| CVE-2017-13086 | 2017 | KRACK — Key reinstallation in TDLS handshake | High |
| CVE-2019-9494 | 2019 | Dragonblood — Side-channel attack on WPA3 SAE | Medium |
| CVE-2020-0069 | 2020 | WiFi firmware vulnerability allowing privilege escalation | High |
| CVE-2021-0477 | 2021 | Privilege escalation in WiFi service via Intent handling | High |
| CVE-2022-20location | 2022 | WiFi HAL vulnerability allowing code execution in privileged context | High |

---

## 7. NFC Vulnerabilities

### Overview

Android's NFC stack supports NFC Forum protocols (NDEF, NFC-A/B/F/V), card emulation (HCE), and peer-to-peer communication (Android Beam, deprecated in Android 10). The NFC service (`com.android.nfc`) runs with `nfc` UID privileges. NFC attacks require close physical proximity (< 4cm in practice) but can be automated using purpose-built hardware or weaponized NFC tags.

### NFC-Based Attack Vectors

#### NDEF Tag Exploitation

NDEF (NFC Data Exchange Format) tags can contain URLs, contact cards, WiFi credentials, or raw application data. Malicious NDEF payloads can:

- Trigger automatic browser navigation to phishing sites (via URL records)
- Initiate phone calls or send SMS messages (via `tel:` or `sms:` URI schemes)
- Trigger auto-pairing with malicious Bluetooth devices (via Bluetooth OOB records)
- Exploit parsing bugs in the NFC tag reading libraries

#### Android Beam Attacks (Pre-Android 10)

Android Beam used NFC's LLCP (Logical Link Control Protocol) and SNEP (Simple NDEF Exchange Protocol) to transfer data between devices. Attackers could:

- Push APK files to the victim device, which would prompt installation (mitigated by requiring user confirmation and Unknown Sources)
- Send crafted NDEF messages that exploit the receiving app's handler
- Leverage Beam to initiate a WiFi Direct or Bluetooth connection for larger data transfer exploitation

#### NFC Tag Memory Corruption

Low-level NFC protocol handling in the native NFC HAL and firmware has been a source of memory corruption bugs. Malformed NFC-A/B/F frames processed by the NFC controller firmware can trigger buffer overflows before Android's userspace code even sees the data.

### Notable NFC CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2015-0235 | 2015 | NFC tag handling leading to memory corruption in libnfc | High |
| CVE-2019-2114 | 2019 | NFC Beam could install apps from non-market sources silently | High |
| CVE-2020-0050 | 2020 | OOB read in NFC tag parsing | Moderate |
| CVE-2020-0215 | 2020 | NFC tag parsing leading to privilege escalation | High |
| CVE-2021-0523 | 2021 | Information disclosure via NFC service | Moderate |
| CVE-2022-20133 | 2022 | Privilege escalation via NFC service | High |

---

## 8. Telephony/SMS Vulnerabilities

### Overview

Android's telephony stack is a multi-layered architecture spanning the application framework (`TelephonyManager`, `SmsManager`), the Radio Interface Layer (RIL), and the baseband modem processor. SMS processing is particularly dangerous because incoming SMS messages are processed automatically with no user interaction required.

### SMS-Based Attacks

#### StageFright via MMS (CVE-2015-1538, CVE-2015-1539)

Although primarily a media framework vulnerability, the StageFright family of bugs was triggered via MMS messages. Android's default messaging app (Hangouts/Messenger) would automatically download and process MMS content, triggering media parsing code. The attacker needed only the victim's phone number.

#### SMS PDU Parsing Bugs

The SMS Protocol Data Unit (PDU) format is parsed in both Java (for application-layer processing) and native code (in the RIL). Malformed PDUs can:

- Crash the telephony process (`com.android.phone`)
- Trigger buffer overflows in the RIL daemon
- Exploit WAP Push message handling to inject browser bookmarks or configuration profiles
- Send class-0 ("flash") SMS messages that overlay the screen

### SIM Swapping and SIM Toolkit Attacks

While SIM swapping is primarily a social engineering attack against carriers, the SIM Toolkit (STK) application on Android presents a technical attack surface:

- STK proactive commands can display menus, send SMS, initiate calls, and launch browsers
- A compromised SIM card can execute STK commands to exfiltrate data or initiate calls
- The "Simjacker" attack (using S@T browser on SIM cards) demonstrated remote exploitation via specially crafted binary SMS messages

### Baseband Interaction Vulnerabilities

The RIL (Radio Interface Layer) daemon bridges the Android application processor and the baseband modem. Vulnerabilities in this interface include:

- Improper validation of responses from the baseband modem, allowing a compromised modem to escalate to the application processor
- Injection of AT commands through debug interfaces
- Exploitation of OTA (Over-the-Air) update mechanisms for the baseband firmware

### Notable Telephony CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2015-1538 | 2015 | StageFright — RCE via MMS message processing | Critical |
| CVE-2015-3843 | 2015 | Telephony API abuse allowing interception of calls | High |
| CVE-2020-0069 | 2020 | MediaTek baseband command injection (MediaTek-SU) | Critical |
| CVE-2020-0245 | 2020 | RCE in telephony framework | High |
| CVE-2021-0920 | 2021 | Linux kernel use-after-free exploited via telephony socket (ITW) | High |
| CVE-2022-20130 | 2022 | RCE in Android telephony component | Critical |
| CVE-2023-21057 | 2023 | Baseband RCE in Samsung Exynos modems | Critical |

---

## 9. Android Debug Bridge (ADB)

### Security Model

ADB provides a powerful debugging interface that, if accessible to an attacker, essentially provides full device control. The ADB security model relies on several layers:

1. **USB debugging toggle**: Disabled by default, must be enabled via Developer Options.
2. **RSA authentication**: Since Android 4.2.2, when a device connects via ADB, the host presents an RSA public key. The device prompts the user to verify and accept the fingerprint.
3. **SELinux confinement**: ADB shell runs in the `u:r:shell:s0` SELinux context, which restricts access compared to a full root shell.
4. **adbd privilege dropping**: The ADB daemon drops to `shell` UID (2000) after initialization on user builds.

### ADB-over-Network Risks

ADB over TCP/IP (enabled via `adb tcpip 5555`) is the most critical ADB security risk. Once enabled:

- ADB listens on port 5555 (or configured port) on **all network interfaces**.
- There is **no authentication** for the initial TCP connection — any device on the network can connect.
- RSA key verification still applies, but on some devices (especially Android-based IoT devices, smart TVs, set-top boxes), the RSA prompt is auto-accepted or absent.
- Factory images of some budget Android devices ship with ADB over TCP enabled by default.

### Attack Scenarios

```
# Scanning for open ADB ports on a network
nmap -p 5555 192.168.1.0/24 --open

# Connecting to a vulnerable device
adb connect 192.168.1.100:5555

# If accepted, full shell access:
adb shell pm list packages
adb shell screencap /sdcard/screen.png
adb install malicious.apk
adb shell am start -n com.malicious/.PayloadActivity
```

Real-world exploitation has included:

- **Android.Trojan.ADB.Miner** (2018): A worm that spread across networks by scanning for devices with open ADB ports and installing cryptocurrency mining malware.
- **ADB.Miner botnet**: Targeted Android-based smart TVs and set-top boxes, reaching tens of thousands of devices.

### Notable ADB CVEs and Issues

| CVE/Issue | Year | Description | Severity |
|-----------|------|-------------|----------|
| CVE-2017-0554 | 2017 | Privilege escalation from ADB shell to system via race condition | High |
| CVE-2020-0069 | 2020 | MediaTek-SU — ADB shell to root escalation on MediaTek devices | Critical |
| ADB.Miner | 2018 | Worm spreading via open ADB ports (not a CVE, real-world malware) | Critical (impact) |
| CVE-2022-20128 | 2022 | ADB backup mechanism leaking sensitive data | Moderate |

### Mitigations

- Android 11+ restricts ADB over WiFi to require an explicit pairing code (wireless debugging).
- The `persist.adb.tcp.port` property is restricted on user builds.
- Enterprise MDM solutions can enforce `adb_enabled=0` via device policy.

---

## 10. Settings/System UI Vulnerabilities

### Overview

The Settings app and SystemUI are privileged system applications running with `system` UID. Settings manages device configuration, permissions, and security parameters. SystemUI renders the status bar, notification shade, lock screen, recent apps, and various system dialogs. Bugs in these components are high-impact because they run with system privileges and control security-critical UI.

### Lock Screen Bypasses

Lock screen bypasses have been among the most publicly visible Android vulnerabilities, often requiring complex multi-step physical interactions:

- **Emergency call sequence bypasses**: A series of specific interactions with the emergency dialer can crash the lock screen and land on the home screen. These typically involve overflow of input fields, rotation changes, or camera interactions from the lock screen.
- **Accessibility service abuse**: An accessibility service enabled before the lock is set can sometimes interact with elements behind the lock screen.
- **Notification interaction bypass**: Interacting with notification actions (e.g., replying inline) from the lock screen can sometimes expose app content or trigger transitions that bypass the lock.
- **Guest user trick**: Creating or switching to a guest user from the lock screen's user switcher can sometimes bypass the device lock.

### Settings App Vulnerabilities

The Settings app is a common target for privilege escalation because it hosts `exported` activities that perform privileged operations:

- **Intent redirection in Settings**: Settings activities that accept `Intent` extras and use them to launch sub-activities can be exploited to launch arbitrary components with system privileges.
- **Fragment injection** (CVE-2014-8609 related): Before Android 4.4 KitKat, the `PreferenceActivity` base class accepted a `fragment` extra that specified which `Fragment` to load. Any app could launch a Settings activity with an arbitrary fragment class name, causing Settings to instantiate and display an internal fragment that should not be accessible — including fragments that could modify device security settings.
- **Overlay attacks on Settings**: A malicious app with `SYSTEM_ALERT_WINDOW` permission can draw over Settings screens, tricking users into enabling dangerous permissions or settings.

### SystemUI Vulnerabilities

SystemUI vulnerabilities can undermine trust in the device's UI:

- **Tapjacking**: Although not strictly a SystemUI bug, the system toast and overlay mechanisms have been exploited to obscure permission dialogs, making users unknowingly grant dangerous permissions.
- **Screenshot/screen recording bypass**: Bugs allowing background apps to capture screen content despite restrictions.
- **Status bar spoofing**: Displaying fake status bar icons (VPN, encryption indicators) to mislead users about device security state.

### Notable CVEs

| CVE | Year | Description | Severity |
|-----|------|-------------|----------|
| CVE-2014-8609 | 2014 | Fragment injection in Settings allowing arbitrary fragment loading | High |
| CVE-2015-3860 | 2015 | Lock screen bypass via emergency call crash sequence | Moderate |
| CVE-2017-0752 | 2017 | Toast overlay attack (TOASTER) — permission escalation via overlays | High |
| CVE-2020-0094 | 2020 | Lock screen bypass via accessibility service interaction | High |
| CVE-2020-0301 | 2020 | SystemUI crash leading to lock screen bypass | High |
| CVE-2021-0585 | 2021 | Intent redirection in Settings allowing launch of arbitrary activities as system | High |
| CVE-2022-20338 | 2022 | Bypass of Settings restrictions via crafted Intent | Moderate |
| CVE-2023-21036 | 2023 | "aCropalypse" — Pixel Markup tool failed to truncate file when cropping screenshots, leaking original image data | Moderate |

---

## Summary of Mitigation Strategies

The Android security team has implemented several architectural mitigations across framework and system services:

| Mitigation | Introduced | Impact |
|-----------|-----------|--------|
| APK Signature Scheme v2/v3/v4 | Android 7.0 / 9.0 / 11 | Eliminates Janus-class APK signature bypass |
| `FLAG_IMMUTABLE` default for PendingIntents | Android 12 | Prevents PendingIntent hijacking |
| StrictMode Parcel checks | Android 13 | Detects Bundle/Parcel mismatch exploits |
| Scoped Storage | Android 10 | Prevents installer hijacking via file access |
| Background Activity Launch restrictions | Android 10 | Mitigates StrandHogg-class task hijacking |
| Wireless Debugging pairing requirement | Android 11 | Protects against unauthorized ADB-over-WiFi access |
| Fragment injection prevention | Android 4.4 | Blocks arbitrary Fragment loading in Settings |
| Bluetooth stack hardening (ASLR, CFI) | Ongoing | Reduces exploitability of memory corruption bugs |
| Mandatory VPN indicators | Android 7.0 | Prevents VPN status bar spoofing |
| Immutable notification channels | Android 8.0 | Limits notification-based manipulation |

---

## References

1. Android Security Bulletins — https://source.android.com/docs/security/bulletin
2. NIST National Vulnerability Database — https://nvd.nist.gov/
3. GuardSquare — Janus Vulnerability Technical Analysis (2017)
4. Bluebox Security — FakeID Vulnerability Research (2014)
5. Promon — StrandHogg 2.0 Technical Report (2020)
6. ERNW — BlueFrag: Android Bluetooth Zero-Click RCE (2020)
7. Mathy Vanhoef — KRACK Attacks: Breaking WPA2 (2017)
8. Mathy Vanhoef — Dragonblood: Analyzing WPA3's Dragonfly Handshake (2019)
9. Zimperium — StageFright: Scary Code in the Heart of Android (2015)
10. ASSET Research Group — BrakTooth: Causing Havoc on Bluetooth Link Manager (2021)
11. Google Project Zero — Various Android vulnerability analyses
12. Android Open Source Project — Security documentation and source code
