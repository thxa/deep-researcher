# Chapter 4: Android Application-Layer Vulnerabilities

## 4.1 Overview

The Android application layer represents the broadest and most diverse attack surface in the Android ecosystem. Unlike kernel or firmware vulnerabilities that require deep systems expertise, application-layer flaws are often introduced by developers who lack security training, rely on insecure defaults, or misunderstand the Android component model. This chapter provides a systematic examination of the principal vulnerability classes that affect Android applications, each illustrated with real-world CVEs and technical root-cause analysis.

Android applications execute within the Dalvik/ART virtual machine, interact through a rich inter-process communication (IPC) mechanism built on Binder, and store data across multiple backends. Every one of these layers introduces distinct vulnerability classes. The consequences range from information disclosure and privilege escalation to full remote code execution. Because the Play Store hosts millions of applications --- and sideloading is commonplace --- the aggregate risk to the Android user base is enormous.

---

## 4.2 Intent-Based Vulnerabilities

### 4.2.1 The Android Intent Model

Intents are the fundamental IPC mechanism on Android. They carry action descriptors, data URIs, extras (key-value bundles), and component targets. An intent is either *explicit* (names a target component) or *implicit* (declares an action and lets the system resolve it). This flexibility is also the root cause of several vulnerability classes.

### 4.2.2 Intent Hijacking and Implicit Intent Interception

When an application sends an implicit intent, any application on the device that declares a matching `<intent-filter>` can receive it. A malicious app can register a high-priority filter to intercept intents intended for legitimate receivers. This is known as **intent hijacking**.

Consider a banking application that uses an implicit intent to launch a "verify identity" screen. A malicious app registers a filter with higher priority for the same action string, intercepts the intent, harvests credentials from the extras, and then forwards the intent to the real component --- a classic man-in-the-middle within the IPC layer.

Starting with Android 12 (API 31), the platform enforces explicit intents for `PendingIntent` objects and restricts mutability, mitigating a large class of these bugs. However, backward-compatible apps targeting older API levels remain vulnerable.

### 4.2.3 PendingIntent Vulnerabilities

A `PendingIntent` wraps an intent and grants the recipient the right to execute it with the *sender's* identity and permissions. If the base intent inside a `PendingIntent` is implicit or mutable, an attacker who obtains the `PendingIntent` can re-target it to an arbitrary component and execute actions under the original sender's UID.

**CVE-2020-0188** affected the Android Settings application. The `SettingsSliceProvider` created a `PendingIntent` with an implicit base intent. A local attacker could obtain this `PendingIntent` through the Slice API, modify the target component, and launch arbitrary activities with the Settings app's elevated privileges, including toggling device security settings without user consent. The root cause was the use of `PendingIntent.getActivity()` with an empty (implicit) base intent.

**CVE-2020-0389** was a similar flaw in the `NotificationManagerService`. A `PendingIntent` used for notification actions was constructed without specifying an explicit component. A malicious application installed on the same device could intercept the `PendingIntent`, fill in its own component, and perform actions --- such as dismissing or interacting with notifications --- under the system's identity. The fix involved making the base intent explicit and setting the `PendingIntent` as immutable via `PendingIntent.FLAG_IMMUTABLE`.

### 4.2.4 Intent Spoofing

Intent spoofing is the converse of hijacking: rather than intercepting an outgoing intent, the attacker *sends* a crafted intent to a victim component. If an exported activity, service, or broadcast receiver does not validate the caller's identity, it will process the spoofed intent as legitimate. This has led to vulnerabilities where attackers trigger privileged functionality --- factory resets, account deletion, or data exports --- simply by crafting the right intent extras.

### 4.2.5 Intent Redirection

Intent redirection occurs when an application receives an intent that itself contains a nested intent (often as a `Parcelable` extra), and then forwards or starts the nested intent without validation. The attacker supplies a nested intent pointing at a non-exported component of the victim application, bypassing export restrictions. **CVE-2021-0928** and related bugs in the Android framework exploited exactly this pattern, allowing access to non-exported activities in system apps.

---

## 4.3 Content Provider Vulnerabilities

### 4.3.1 Architecture

Content providers expose structured data across application boundaries via a URI-based interface (`content://authority/path`). They translate URI operations into database queries, file reads, or other backend operations. Because they are often backed by SQLite databases and can serve files, they are susceptible to injection and path traversal attacks.

### 4.3.2 SQL Injection in Content Providers

If a content provider passes user-controlled `selection` or `projection` parameters directly into raw SQL queries, it is vulnerable to SQL injection. For example:

```java
// VULNERABLE
Cursor c = db.query("users", projection, selection, selectionArgs, null, null, null);
// If 'projection' is attacker-controlled:
// projection = new String[]{"* FROM sqlite_master--"}
```

An attacker who can interact with the provider (either because it is exported or because they hold the necessary permission) can extract arbitrary data from the backing database. Real-world examples include contact providers, calendar providers, and third-party app providers that failed to sanitize projection arrays. **CVE-2018-9493** demonstrated SQL injection via the `selection` parameter in the Android download manager's content provider (`DownloadProvider`), allowing a malicious app to extract information about all downloads on the device, including URLs and file paths.

### 4.3.3 Path Traversal

Content providers that serve files via `openFile()` must validate the requested path. A common mistake is to append the URI's last path segment directly to a base directory:

```java
// VULNERABLE
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File file = new File(baseDir, uri.getLastPathSegment());
    return ParcelFileDescriptor.open(file, MODE_READ_ONLY);
}
```

An attacker supplies `content://authority/..%2F..%2Fetc%2Fpasswd` and escapes the base directory. **CVE-2021-0591** in the Telecom framework allowed path traversal through a content provider's `openFile()` implementation to read files belonging to the telephony process. The fix required canonicalizing paths and ensuring the resolved file remained within the intended directory.

### 4.3.4 Unprotected Content Providers

Prior to Android 4.2 (API 17), content providers were exported by default. Even on modern Android, developers sometimes explicitly set `android:exported="true"` without declaring `android:readPermission` or `android:writePermission`. This exposes the provider to every application on the device. Sensitive data --- authentication tokens, session cookies, user PII --- has been leaked through unprotected providers in major applications.

---

## 4.4 WebView Vulnerabilities

### 4.4.1 The WebView Attack Surface

`WebView` embeds a Chromium-based browser engine inside an Android application. It renders web content with the same privileges as the host app, creating a bridge between web-origin attacks and native Android capabilities. The attack surface includes JavaScript execution, URL scheme handling, and the Java-JavaScript bridge.

### 4.4.2 JavaScript Interface Exploitation (`addJavascriptInterface`)

The `addJavascriptInterface()` API exposes Java objects to JavaScript running inside the WebView. Prior to Android 4.2, JavaScript could use Java reflection to call *any* public method on the exposed object --- or on any object reachable through it --- including `Runtime.exec()`:

```javascript
// Pre-Android 4.2 exploitation
var runtime = exposed_obj.getClass().forName("java.lang.Runtime");
var exec = runtime.getMethod("exec", "java.lang.String");
exec.invoke(runtime.getMethod("getRuntime").invoke(null), "id");
```

**CVE-2012-6636** (and the closely related CVE-2013-4710) documented this flaw. On Android versions prior to 4.2, any WebView loading untrusted content with a JavaScript interface was trivially exploitable for arbitrary code execution. The mitigation, introduced in API 17, requires methods to be annotated with `@JavascriptInterface` to be accessible from JavaScript.

### 4.4.3 Universal Cross-Site Scripting (UXSS)

Bugs in the underlying Chromium engine can bypass the same-origin policy, enabling a malicious page loaded in a WebView to read data from other origins. These are classified as Universal XSS (UXSS). **CVE-2020-6506** was a UXSS in Chrome for Android (which shares the rendering engine with WebView) that allowed a remote attacker to perform cross-origin reads via a crafted HTML page. Because many apps load partially-trusted content in WebViews (ads, OAuth flows, in-app browsers), UXSS in the engine propagates to every app using WebView.

### 4.4.4 `file://` Protocol Abuse

If a WebView is configured with `setAllowFileAccessFromFileURLs(true)` or `setAllowUniversalAccessFromFileURLs(true)`, JavaScript running from a `file://` origin can read arbitrary local files:

```javascript
var xhr = new XMLHttpRequest();
xhr.open("GET", "file:///data/data/com.victim.app/shared_prefs/secrets.xml", true);
xhr.onload = function() { exfiltrate(xhr.responseText); };
xhr.send();
```

These flags default to `true` on API levels below 16 and `false` on 16+, but many legacy apps or poorly-maintained codebases explicitly re-enable them. Combined with a path traversal or intent-redirect that forces a WebView to load a local HTML file, this becomes a reliable data-exfiltration primitive.

### 4.4.5 Intent Scheme URLs

WebView can handle `intent://` scheme URLs to launch activities. If not properly filtered with `Intent.URI_INTENT_SCHEME` and category restrictions, a malicious web page can craft intent URLs that launch arbitrary application components, potentially triggering privileged operations or accessing non-exported components.

---

## 4.5 Insecure Data Storage

### 4.5.1 SharedPreferences

`SharedPreferences` stores key-value pairs as XML files in `/data/data/<package>/shared_prefs/`. On non-rooted devices, Linux DAC protections prevent cross-app access. However, if the mode is set to `MODE_WORLD_READABLE` (deprecated since API 17), any app can read the file. Even with correct permissions, data is stored in plaintext --- a problem on rooted devices, in backups, or when combined with other vulnerabilities that grant file-read access.

### 4.5.2 SQLite Databases

Unencrypted SQLite databases in `/data/data/<package>/databases/` are readable via backup extraction (`adb backup`), root access, or content-provider vulnerabilities. Sensitive apps (password managers, banking) must use encrypted storage such as SQLCipher or the Jetpack Security library. **CVE-2019-10875** in a major messaging application stored messages in a plaintext SQLite database accessible through the Android backup mechanism, allowing trivial offline extraction.

### 4.5.3 External Storage

Files written to external storage (`/sdcard/`) are world-readable prior to Android 10's scoped storage enforcement. Applications that cache sensitive data, download updates, or store configuration on external storage are vulnerable to:

- **Data theft**: Any app with `READ_EXTERNAL_STORAGE` can read the files.
- **Data tampering**: Files used for code loading (DEX, native libraries) or configuration can be replaced, leading to arbitrary code execution in the context of the victim application. This is known as a **man-in-the-disk** attack.

**CVE-2020-8913** (the SHAREit vulnerability) and research by Check Point on "Man-in-the-Disk" demonstrated that applications relying on external storage for code or data integrity could be fully compromised by a malicious app with only storage permissions.

### 4.5.4 Backup Vulnerabilities

By default, `android:allowBackup="true"` in the manifest permits `adb backup` to extract an application's private data directory. On a device with USB debugging enabled, an attacker with physical access can extract tokens, databases, and preferences without root. **CVE-2017-13156** (Janus) is a related class where backup/install-time integrity checks could be bypassed to inject code into APKs.

---

## 4.6 Cryptographic Weaknesses

### 4.6.1 Hardcoded Keys

Static analysis of Android applications routinely reveals AES keys, HMAC secrets, and API tokens embedded directly in source code or resource files. Hardcoded keys provide zero security once the APK is decompiled (a trivial operation with tools like `jadx` or `apktool`). Firebase API keys, AWS credentials, and symmetric encryption keys are the most commonly exposed secrets.

### 4.6.2 Weak Algorithms

Use of DES, RC4, MD5 for integrity, ECB mode for AES, or 1024-bit RSA persists in the Android ecosystem. These algorithms have known practical attacks. OWASP's MASVS (Mobile Application Security Verification Standard) requires AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption and SHA-256 or SHA-3 for hashing.

### 4.6.3 Improper Certificate Validation

Custom `TrustManager` implementations that accept all certificates, or `HostnameVerifier` implementations that always return `true`, disable TLS verification entirely:

```java
// VULNERABLE - accepts any certificate
TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String type) {}
        public void checkServerTrusted(X509Certificate[] chain, String type) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};
```

This enables trivial man-in-the-middle attacks. **CVE-2015-3837** and numerous findings from the CERT/CC Tapioca testing tool documented that thousands of Android apps in the Play Store shipped with disabled certificate validation. Android 7.0 introduced Network Security Configuration to provide a declarative way to enforce certificate pinning and restrict cleartext traffic, partially mitigating developer error.

---

## 4.7 Component Export Vulnerabilities

### 4.7.1 Exported Activities

An activity with `android:exported="true"` (or one that declares an intent filter, which implicitly exports it) can be launched by any application. If the activity performs a privileged operation --- displaying sensitive data, modifying settings, processing payment --- without verifying the caller, any app on the device can invoke it.

**CVE-2020-0108** in the `ActivityManagerService` allowed a malicious application to launch activities in a way that hijacked the victim application's task stack, enabling phishing by presenting a fake UI on top of a legitimate app. This is known as **StrandHogg 2.0**, building on the original StrandHogg vulnerability (CVE-2020-0096) that exploited task affinity manipulation to overlay malicious activities onto legitimate ones.

### 4.7.2 Exported Services

Exported services (`android:exported="true"`) that accept arbitrary commands through `onBind()` or `onStartCommand()` can be abused to perform actions with the service's UID. Bound services backed by AIDL interfaces are particularly dangerous if they expose privileged methods without caller verification.

### 4.7.3 Exported Broadcast Receivers

An exported broadcast receiver processes intents from any sender. If the receiver performs privileged actions (e.g., toggling airplane mode, initiating a file transfer) based solely on the intent's action string or extras, an attacker can trigger those actions at will. The mitigation is to declare `android:permission` on the receiver or use `LocalBroadcastManager` (now deprecated in favor of `LiveData` or other observable patterns).

Starting with Android 12 (API 31), the platform requires developers to explicitly declare `android:exported` for every component with an intent filter, closing a significant gap where implicit export was the default behavior.

---

## 4.8 Tapjacking and Overlay Attacks

### 4.8.1 Mechanism

Android allows apps with the `SYSTEM_ALERT_WINDOW` permission to draw overlay windows on top of other applications. A malicious overlay can:

1. **Obscure security dialogs**: Cover a permission prompt with an innocuous-looking UI so the user taps "Allow" without realizing it.
2. **Clickjack**: Position a transparent overlay over a victim app's button so that taps pass through to the underlying UI.
3. **Harvest input**: Display a fake keyboard or login form over a legitimate app.

### 4.8.2 Cloak and Dagger

The "Cloak and Dagger" attack, published by researchers at Georgia Tech in 2017, demonstrated that an app with only `SYSTEM_ALERT_WINDOW` and `BIND_ACCESSIBILITY_SERVICE` permissions could:

- Silently install a secondary app with full permissions by overlaying the "Install" and "Allow" buttons during the permission grant flow.
- Capture keystrokes via the accessibility service.
- Perform a complete device takeover without the user's awareness.

At the time of disclosure, the `SYSTEM_ALERT_WINDOW` permission was automatically granted to apps installed from the Play Store, making the attack practical at scale. Google subsequently restricted this permission in Android 8.0+ (TYPE_APPLICATION_OVERLAY) and Android 10+ (limiting overlay behavior during permission dialogs).

### 4.8.3 CVE Examples

**CVE-2017-0752** was a tapjacking vulnerability in the Android framework where a malicious overlay could intercept touches intended for the system permission dialog. **CVE-2020-0096** (StrandHogg) also incorporated overlay-like behavior through task-affinity manipulation, achieving similar visual spoofing without the `SYSTEM_ALERT_WINDOW` permission. Android 12 introduced further mitigations by blocking touches that pass through overlays for security-critical system dialogs.

---

## 4.9 Serialization and Deserialization Bugs

### 4.9.1 The Parcel/Bundle Attack Surface

Android's `Parcel` is a binary serialization format used for IPC through Binder. `Bundle` (a typed key-value map) is the most common Parcelable container passed between components. Crucially, `Bundle` uses *lazy deserialization*: values are not unpacked until accessed. This creates a class of vulnerabilities known as **Bundle/Parcel mismatch bugs**.

### 4.9.2 Parcel Mismatch (Serialization/Deserialization Asymmetry)

A Parcel mismatch occurs when a `Parcelable` object writes a different number of bytes during serialization (`writeToParcel`) than it reads during deserialization (`createFromParcel`). When such an object is placed in a `Bundle`, the offset mismatch causes subsequent entries in the Bundle to be read from incorrect positions in the underlying Parcel buffer. An attacker can craft a Bundle that, after re-serialization and deserialization (which occurs during IPC), contains different key-value pairs than the original --- effectively bypassing Bundle-level security checks.

**CVE-2017-13288** was a Parcel mismatch in the `PeriodicAdvertisingReport` class. The `writeToParcel()` method wrote a different number of fields than `createFromParcel()` read. This allowed an attacker to craft a malicious Bundle that, when passed through the `system_server`, would deserialize with different contents than what was originally serialized. The attacker could use this to launch arbitrary activities with system privileges, including accessing the Settings app's account management to perform a factory reset or install certificates.

**CVE-2017-13289**, **CVE-2017-13286**, and **CVE-2017-13287** were additional Parcel mismatch bugs in different Parcelable classes (`ParcelableRttResults`, `OutputConfiguration`, `VerifyCredentialResponse`), all following the same pattern. These bugs were systematically discovered by auditing all `Parcelable` implementations in the Android framework for serialization/deserialization asymmetry.

### 4.9.3 LaunchAnyWhere and the EvilParcel Pattern

The exploitation pattern for Parcel mismatch bugs is sometimes called "EvilParcel" or "LaunchAnyWhere." The attack flow is:

1. Craft a `Bundle` containing a malicious `Parcelable` with a mismatch bug, plus a hidden intent targeting a non-exported component.
2. Send the Bundle to a system service (e.g., `AccountManagerService`) that re-serializes and deserializes it.
3. On the second deserialization, the mismatch causes the system to interpret the hidden intent as a legitimate entry, which it then uses to launch an activity with system privileges.

This class of bugs was particularly dangerous because it bypassed the restriction that non-exported components cannot be started by third-party apps, enabling full privilege escalation to `system_server`.

### 4.9.4 Mitigations

Android 13 introduced hardened `Parcel` deserialization that validates the total number of bytes consumed matches the expected size. The `BaseBundle.mParcelledData` handling was rewritten to perform eager type checking. Additionally, `android.os.Parcel` now logs and rejects mismatched reads.

---

## 4.10 Media Processing Vulnerabilities

### 4.10.1 Stagefright and Its Legacy

The **Stagefright** vulnerabilities (CVE-2015-1538, CVE-2015-1539, CVE-2015-3824, CVE-2015-3826, CVE-2015-3827, CVE-2015-3828, CVE-2015-3829, CVE-2015-6602) were a set of remote code execution bugs in Android's `libstagefright` media processing library. An attacker could send a specially crafted MMS message containing a malformed MP4 video, and the device would automatically process it --- triggering a heap overflow or integer overflow in the MPEG4 parser --- *before the user even opened the message*.

The impact was staggering: nearly 950 million devices were vulnerable at the time of disclosure. Stagefright was the catalyst for Google's monthly Android security bulletin program and the establishment of the Android Security Rewards program.

### 4.10.2 Post-Stagefright Media Bugs

Despite significant hardening (moving `mediaserver` to its own sandbox, enabling ASLR and CFI, decomposing media services into `mediaextractor`, `mediacodec`, and `mediadrmserver`), media parsing continues to be a rich vulnerability source:

- **CVE-2019-2107**: A heap buffer overflow in the Android framework's HEVC (H.265) decoder allowed remote code execution via a crafted video file. The vulnerability existed in the `ihevcd_parse_slice_data()` function and could be triggered by viewing a malicious video in any app using the system media framework.
- **CVE-2020-0069**: While primarily a MediaTek-specific command queue vulnerability, it demonstrated how media HAL (Hardware Abstraction Layer) interactions could be exploited for privilege escalation.
- **CVE-2023-21282**: A critical RCE in the MPEG4 extractor component of the media framework, patched in the August 2023 security bulletin.

### 4.10.3 Image Parser Vulnerabilities

Image parsing libraries (libpng, libjpeg-turbo, libwebp, Skia) process untrusted input from the network, local files, and intents. **CVE-2023-4863** was a heap buffer overflow in `libwebp`'s Huffman coding implementation that affected Chrome, Android WebView, and every application using the system's WebP decoder. This was exploited in the wild as a zero-day. **CVE-2016-3862** was a remote code execution vulnerability in `libjhead`, Android's EXIF processing library, triggerable by viewing a crafted JPEG image.

### 4.10.4 Font Rendering

The FreeType and HarfBuzz libraries handle font rendering on Android. **CVE-2020-15999** was a heap buffer overflow in FreeType's `Load_SBit_Png` function, exploited in the wild as part of a Chrome exploit chain that also affected Android WebView. Font files received via web content, documents, or messaging applications represent a passive attack vector.

---

## 4.11 Third-Party Library Vulnerabilities

### 4.11.1 The Dependency Problem

Modern Android applications include dozens to hundreds of third-party libraries. A vulnerability in a widely-used library affects every application that bundles it. Unlike server-side dependencies managed by centralized package managers, Android libraries are compiled into the APK and require an app update to patch.

### 4.11.2 Notable Vulnerable Libraries

| Library | Vulnerability | Impact |
|---------|--------------|--------|
| **OkHttp** (pre-3.12.1) | Certificate pinning bypass (CVE-2018-20200) | MitM attacks against apps relying on OkHttp's pinning |
| **Apache Cordova** (pre-4.1.1) | Bridge hijacking, secondary WebView exploitation | RCE within the Cordova WebView context |
| **Facebook SDK** | Token leakage through `logcat` (CVE-2018-6758) | OAuth token theft on shared devices |
| **Zip4j / various ZIP libs** | ZipSlip path traversal (CVE-2018-1000544) | Arbitrary file write during extraction, leading to code execution |
| **ExoPlayer** (pre-2.11.5) | Buffer overflow in FMP4 parser | Potential RCE via crafted media streams |
| **libpng** (bundled in apps) | Multiple integer overflows (CVE-2015-8126) | Crash or code execution via malicious PNG |
| **Bouncy Castle** (pre-1.56) | Bleichenbacher-style RSA padding oracle (CVE-2016-1000338) | Plaintext recovery in RSA-encrypted communications |
| **Google Play Core Library** (pre-1.7.3) | Local code execution (CVE-2020-8913) | Arbitrary code execution via path traversal in SplitCompat |

### 4.11.3 CVE-2020-8913: Google Play Core Library

This vulnerability deserves special attention. The Google Play Core Library's SplitCompat feature allows apps to download and install feature modules on demand. **CVE-2020-8913** was a local code execution vulnerability where a malicious application could copy a crafted file to the victim application's internal split verification directory. When the victim app loaded the module, it would execute the attacker's code in the victim's context, inheriting all of its permissions and data access. This affected high-profile applications including Google Chrome, Grindr, Booking.com, and Cisco Teams before they updated the library.

### 4.11.4 Supply Chain Risks

Beyond known CVEs, third-party libraries introduce supply-chain risks:

- **Abandoned libraries**: Libraries no longer maintained accumulate unpatched vulnerabilities.
- **Trojanized SDKs**: Ad SDKs and analytics libraries have been caught exfiltrating data beyond their stated scope (e.g., the X-Mode, Predicio, and Pushwoosh incidents).
- **Transitive dependencies**: An app may include a library that itself depends on a vulnerable sub-dependency, invisible to the app developer without deep dependency analysis.

Google's efforts to address this include the Play SDK Index, which tracks SDK usage across the ecosystem, and mandatory SDK declarations in the Play Console.

---

## 4.12 Mitigation Strategies and Defense in Depth

### 4.12.1 Developer-Side Mitigations

1. **Explicit intents**: Always use explicit intents for intra-app communication. Use `PendingIntent.FLAG_IMMUTABLE` on API 23+.
2. **Component export controls**: Explicitly declare `android:exported="false"` for components that do not need external access. Use custom permissions with `signature` protection level.
3. **Input validation**: Treat all IPC inputs --- intent extras, content provider queries, URI parameters --- as untrusted. Use parameterized queries for content providers.
4. **Encrypted storage**: Use `EncryptedSharedPreferences` and `EncryptedFile` from Jetpack Security. Use SQLCipher for sensitive databases.
5. **WebView hardening**: Disable JavaScript unless required. Never enable `setAllowUniversalAccessFromFileURLs`. Use `WebViewAssetLoader` for local content. Set `android:usesCleartextTraffic="false"` in Network Security Configuration.
6. **Certificate pinning**: Use Network Security Configuration for declarative pinning with backup pins and reasonable expiration.
7. **Dependency management**: Audit dependencies with tools like `dependency-check`, Snyk, or GitHub Dependabot. Pin library versions and monitor for CVEs.

### 4.12.2 Platform-Side Mitigations

- **Android 12+**: Mandatory explicit export declarations, immutable PendingIntents by default, restricted overlay behavior.
- **Android 13+**: Notification permission requirements, hardened Parcel deserialization, per-photo media permissions.
- **Android 14+**: Restricted implicit intents for apps targeting API 34, credential manager API to reduce phishing surface.
- **Google Play Protect**: On-device ML-based scanning for known malware patterns and suspicious behaviors.
- **App Signing v2/v3/v4**: Cryptographic integrity verification preventing APK tampering after signing.

---

## 4.13 Conclusion

Application-layer vulnerabilities remain Android's largest attack surface by volume. The component model (intents, content providers, broadcast receivers, services) provides rich IPC capabilities but demands careful security configuration that developers frequently get wrong. WebView bridges the gap between web and native attack vectors. Serialization bugs in Parcel/Bundle have enabled some of the most potent privilege-escalation chains in Android's history. Media processing, despite a decade of hardening since Stagefright, continues to yield critical RCE bugs because binary parsers operating on untrusted input are inherently difficult to secure.

The shift toward declarative security policies (Network Security Configuration, mandatory export declarations, immutable PendingIntents) represents a sound architectural direction: replacing error-prone imperative security checks with fail-safe defaults. However, the backward-compatibility burden --- millions of apps targeting older API levels --- means that legacy vulnerability patterns will persist for years. Defenders must combine platform updates, static analysis, dependency auditing, and runtime protection (Play Protect, SafetyNet/Play Integrity) to achieve adequate coverage across this diverse and evolving threat landscape.

---

## References

- Android Security Bulletins: https://source.android.com/docs/security/bulletin
- OWASP Mobile Application Security Verification Standard (MASVS): https://mas.owasp.org/MASVS/
- Stagefright: Zimperium Research, July 2015
- Cloak and Dagger: Fratantonio et al., IEEE S&P 2017
- EvilParcel / LaunchAnyWhere: documented in Android Security Bulletins (see [source.android.com/docs/security](https://source.android.com/docs/security))
- Man-in-the-Disk: Check Point Research, August 2018
- StrandHogg 2.0: Promon Research, May 2020
- CVE-2020-8913 (Play Core Library): Oversecured, August 2020
- CVE-2023-4863 (libwebp): Google TAG, September 2023
