# 5. Major Historical Android CVEs and Their Impact

## Table of Contents
1. [Stagefright (2015)](#51-stagefright---the-vulnerability-that-changed-android-security)
2. [Dirty COW (2016)](#52-dirty-cow-cve-2016-5195)
3. [Dirty Pipe (2022)](#53-dirty-pipe-cve-2022-0847)
4. [Bad Binder (2019)](#54-bad-binder-cve-2019-2215)
5. [Janus (2017)](#55-janus-cve-2017-13156)
6. [FakeID (2014)](#56-fakeid-cve-2014-8609)
7. [Certifi-gate (2015)](#57-certifi-gate-cve-2015-3825)
8. [StrandHogg (2020)](#58-strandhogg-cve-2020-0096)
9. [Broadcom WiFi Bugs (2017)](#59-broadcom-wifi-bugs-broadpwn-and-related)
10. [Samsung-Specific CVEs](#510-samsung-specific-cves)
11. [Qualcomm DSP and GPU CVEs](#511-qualcomm-dsp-and-gpu-cves---achilles-and-related)
12. [MediaTek-SU (2020)](#512-mediatek-su-cve-2020-0069)

---

## 5.1 Stagefright --- The Vulnerability That Changed Android Security

| Attribute | Details |
|---|---|
| **CVE IDs** | CVE-2015-1538, CVE-2015-1539, CVE-2015-3824, CVE-2015-3826, CVE-2015-3827, CVE-2015-3828, CVE-2015-3829, CVE-2015-6602 |
| **CVSS v2** | 10.0 (Critical) |
| **CWE** | CWE-189 (Numeric Errors), CWE-119 (Buffer Overflow) |
| **Affected Versions** | Android 2.2 through 5.1.1 (approximately 950 million devices at disclosure) |
| **Discovered By** | Joshua Drake, Zimperium zLabs |
| **Disclosed** | July 27, 2015 (Black Hat USA 2015) |
| **Patched** | Android Security Bulletin, August 2015 |

### Timeline

- **April 2015**: Joshua Drake discovers the first set of vulnerabilities in the `libstagefright` media playback library.
- **May 2015**: Drake reports the bugs to Google with proposed patches. Google assigns the CVE identifiers.
- **July 27, 2015**: Public disclosure at Black Hat USA and DEF CON 23.
- **August 5, 2015**: Google releases the Nexus Security Bulletin --- the **first ever monthly Android security bulletin**, a direct consequence of Stagefright.
- **October 2015**: Stagefright 2.0 (CVE-2015-6602) is disclosed, affecting the `libutils` library.

### Technical Root Cause

Stagefright was not a single vulnerability but a collection of memory corruption bugs in Android's native media processing library, `libstagefright`, written in C++. The library is responsible for parsing and decoding audio and video formats including MP4, 3GPP, and MPEG-4.

**CVE-2015-1538** was the most prominent: an integer overflow in `SampleTable::setSampleToChunkParams()` within `SampleTable.cpp`. When parsing specially crafted MPEG-4 atoms (container metadata structures), the function performed an unchecked integer multiplication to calculate a buffer size. An attacker could craft atom values that caused the multiplication to wrap around, resulting in a far smaller heap allocation than expected. Subsequent data copy operations then wrote beyond the allocated buffer, achieving a classic heap buffer overflow.

```c
// Simplified vulnerable pattern in SampleTable.cpp
uint64_t allocation_size = num_entries * sizeof(SampleToChunkEntry);
// No overflow check -- if num_entries is large enough, allocation_size wraps
mSampleToChunkEntries = new SampleToChunkEntry[allocation_size];
// Subsequent memcpy writes beyond the undersized buffer
```

The remaining CVEs targeted similar patterns:
- **CVE-2015-1539**: Integer underflow in `ESDS::parseESDescriptor()`.
- **CVE-2015-3824**: Integer underflow in `MPEG4Extractor.cpp` parsing `tx3g` atoms.
- **CVE-2015-3826**: Buffer overflow in `MPEG4Extractor.cpp` during `pssh` atom processing.
- **CVE-2015-3827**: Integer underflow in `MPEG4Extractor.cpp` when processing 3GPP metadata.
- **CVE-2015-3828**: Integer overflow in `MPEG4Extractor.cpp` when parsing MPEG-4 `covr` atoms.
- **CVE-2015-3829**: Buffer overflow in `Mpeg4Extractor.cpp` triggered by crafted chunk offsets.
- **CVE-2015-6602** (Stagefright 2.0): A vulnerability in `libutils` triggered when processing specially crafted MP3 or MP4 files, extending the attack surface beyond the original library.

### Exploitation

The attack vector was devastating in its simplicity: **a specially crafted MMS message**. Because Android's default messaging applications (Google Hangouts and the stock MMS app) automatically retrieved and pre-processed MMS attachments --- including media files --- an attacker only needed to know the victim's phone number. The media parsing happened **before the user ever viewed the message**, making this a truly zero-click, remotely exploitable vulnerability.

The exploitation chain:
1. Attacker sends a crafted MP4 file embedded in an MMS.
2. The messaging app automatically downloads and pre-processes the attachment.
3. `libstagefright` parses the malicious MP4 atoms.
4. Integer overflow triggers an undersized heap allocation.
5. Subsequent data copy causes heap corruption.
6. Attacker gains code execution within the `mediaserver` process, which runs with elevated privileges (access to camera, microphone, external storage).

On devices prior to Android 4.1 (no ASLR for `mediaserver`), exploitation was straightforward. On newer devices, ASLR had to be defeated, but the `mediaserver` process had a habit of respawning on crash, enabling brute-force ASLR bypass.

### Impact and Legacy

Stagefright's impact extends far beyond the vulnerability itself:

- **Monthly Security Bulletins**: Google established the Android Security Bulletin program, beginning in August 2015, to deliver regular security patches. This was a fundamental shift in Android's security posture.
- **Android Security Patch Level**: The "Android security patch level" date was introduced in device settings, providing users visibility into their device's patch status.
- **Carrier/OEM Patch Agreements**: Google negotiated agreements with major carriers and OEMs to deliver monthly security updates.
- **ASLR Hardening**: Later Android versions strengthened ASLR implementation in `mediaserver` and moved media processing into a sandboxed service (Media Extractor service) with minimal privileges.
- **Media Framework Redesign**: Android 7.0 Nougat decomposed the monolithic `mediaserver` process into multiple sandboxed services (`mediaextractor`, `mediacodec`, `mediadrmserver`), applying the principle of least privilege.

---

## 5.2 Dirty COW (CVE-2016-5195)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2016-5195 |
| **CVSS v3.1** | 7.0 (High) --- AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 7.2 (High) |
| **CWE** | CWE-362 (Race Condition) |
| **Affected Versions** | Linux Kernel 2.x through 4.x before 4.8.3; all Android versions using these kernels |
| **Discovered By** | Phil Oester |
| **Disclosed** | October 19, 2016 |
| **Patched** | Linux 4.8.3 (October 2016); Android December 2016 security patch |

### Timeline

- **2007**: The vulnerable code is introduced in Linux kernel 2.6.22 (`mm/gup.c`).
- **October 2016**: Phil Oester discovers the vulnerability being exploited in the wild against Linux servers.
- **October 19, 2016**: Public disclosure. Linus Torvalds commits fix noting he attempted a related fix years earlier.
- **October 20, 2016**: Linux 4.8.3 released with the patch.
- **November 2016**: First Android-specific exploits demonstrated.
- **December 5, 2016**: Google includes the fix in the Android December 2016 security bulletin.

### Technical Root Cause

Dirty COW is a race condition in the Linux kernel's memory management subsystem, specifically in how copy-on-write (COW) page handling interacts with the `get_user_pages()` function in `mm/gup.c`.

Copy-on-write is a fundamental memory optimization: when a process forks, the child shares the parent's memory pages (marked read-only). When either process attempts to write, the kernel creates a private copy of the page --- the "copy-on-write" mechanism.

The race condition occurs between two kernel operations:
1. The COW fault handler breaking the COW mapping and creating a private copy of the page.
2. The `get_user_pages()` function re-traversing the page table after the COW break.

By racing these two operations (using `madvise(MADV_DONTNEED)` in a second thread to discard the private copy between steps), an attacker could cause the kernel to write to the **original** read-only page rather than the private copy. This permitted writing to any file the user had read access to, including SUID binaries and system configuration files.

```
Thread 1 (write via /proc/self/mem):    Thread 2 (discard):
  write() to read-only mapping
    -> triggers COW fault
    -> kernel creates private copy
                                          madvise(MADV_DONTNEED)
                                          -> discards the private copy
  -> kernel writes to original page!
```

### Android-Specific Exploitation

On Android, Dirty COW was weaponized for root access. The most common exploitation methods:
- **Overwriting SUID binaries**: The exploit could modify `/system/bin/run-as` (an SUID binary) to inject a shell that runs as root.
- **Modifying VDSO (Virtual Dynamic Shared Object)**: Overwriting the kernel-mapped VDSO page allowed code execution in kernel context.
- **App-based root**: Several Android rooting tools incorporated Dirty COW. The "DirtyCow" app was publicly available and could root devices with a single tap.

Affected devices included virtually every Android phone and tablet in use at the time, as the vulnerable code had been present in the Linux kernel since 2007. Devices running Android 4.x through 7.x were all susceptible. Some devices never received patches due to end-of-life status.

### Remediation

The kernel patch added proper sequencing using the `FOLL_COW` flag to ensure that `get_user_pages()` correctly verifies the COW break was completed before proceeding:

```c
// Fix: verify the COW break persisted by checking the dirty bit
if ((flags & FOLL_WRITE) && !pte_dirty(pte))
    goto retry;
```

---

## 5.3 Dirty Pipe (CVE-2022-0847)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2022-0847 |
| **CVSS v3.1** | 7.8 (High) --- AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 7.2 (High) |
| **CWE** | CWE-665 (Improper Initialization) |
| **Affected Versions** | Linux Kernel 5.8 through 5.16.11 / 5.15.25 / 5.10.102 |
| **Discovered By** | Max Kellermann (CM4all / IONOS) |
| **Disclosed** | March 7, 2022 |
| **Patched** | Linux 5.16.11, 5.15.25, 5.10.102 (February 2022) |

### Timeline

- **April 2021**: Max Kellermann investigates a customer-reported data corruption issue at CM4all.
- **February 2022**: Kellermann identifies the root cause as a kernel vulnerability and develops a proof-of-concept.
- **February 20, 2022**: Report sent to the Linux kernel security team and Google Android security team.
- **February 23-24, 2022**: Fixes land in Linux stable trees (5.16.11, 5.15.25, 5.10.102).
- **March 7, 2022**: Public disclosure with detailed writeup and PoC.
- **March-April 2022**: Android OEM patches begin rolling out. Samsung Galaxy S22 and Pixel 6 received early fixes.

### Technical Root Cause

Dirty Pipe exploits a flaw in how the Linux kernel initializes `pipe_buffer` structures. When the `splice()` system call is used to move data from a file into a pipe, the kernel creates a `pipe_buffer` that references the page cache page of the source file. Critically, the `flags` field of the new `pipe_buffer` structure was not being properly initialized.

The functions `copy_page_to_iter_pipe()` and `push_pipe()` allocated new `pipe_buffer` entries but failed to clear the `flags` field. If a previous pipe operation had set the `PIPE_BUF_FLAG_CAN_MERGE` flag on a buffer in the same pipe ring slot, that flag persisted (stale data). When a subsequent `write()` to the pipe occurred, the kernel checked this flag and, finding it set, merged the new data directly into the existing page cache page --- which belonged to the original file.

This effectively allowed an unprivileged user to overwrite the contents of **any readable file** in the page cache, including read-only files and files owned by root.

```c
// Exploitation sequence:
int fd = open("/etc/passwd", O_RDONLY);
int pfd[2];
pipe(pfd);

// Step 1: Fill pipe completely, then drain it, leaving stale flags
for (int i = 0; i < PIPE_SIZE; i++)
    write(pfd[1], "A", 1);
for (int i = 0; i < PIPE_SIZE; i++)
    read(pfd[0], buf, 1);

// Step 2: Splice one byte from the target file into the pipe
// This places a page cache reference in the pipe with STALE flags
splice(fd, &offset, pfd[1], NULL, 1, 0);

// Step 3: Write to the pipe -- due to stale CAN_MERGE flag,
// data goes directly into the file's page cache
write(pfd[1], "root::0:0...", payload_len);
```

### Android-Specific Impact

Dirty Pipe affected Android devices running kernel 5.8+, which included:
- **Google Pixel 6 / 6 Pro** (Linux 5.10)
- **Samsung Galaxy S22 series** (Linux 5.10)
- Various devices launched with Android 12 using 5.10 GKI kernels

The vulnerability was demonstrated to achieve root on a Pixel 6 within seconds. Unlike Dirty COW, the exploit was **highly reliable** (no race condition) and required no special capabilities. It was added to CISA's Known Exploited Vulnerabilities Catalog on April 25, 2022.

### Remediation

The fix was a one-line change ensuring proper initialization of the `flags` field:

```c
// Fix in lib/iov_iter.c
buf->flags = 0;  // Ensure flags are cleared on new pipe_buffer usage
```

---

## 5.4 Bad Binder (CVE-2019-2215)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2019-2215 |
| **CVSS v3.1** | 7.8 (High) --- AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 4.6 (Medium) |
| **CWE** | CWE-416 (Use After Free) |
| **Affected Versions** | Android kernel versions prior to October 2019 patches; specific kernel trees (3.18, 4.4, 4.9, 4.14) |
| **Discovered By** | Maddie Stone, Google Project Zero / TAG (attribution: exploitation by NSO Group) |
| **Disclosed** | October 3, 2019 (as a 0-day under active exploitation) |
| **Patched** | Android October 2019 security bulletin |

### Timeline

- **September 2019**: Google's Threat Analysis Group (TAG) identifies the exploit being used in the wild by NSO Group's Pegasus spyware.
- **September 27, 2019**: Maddie Stone of Project Zero files the bug report.
- **October 3, 2019**: Public disclosure as a 0-day with PoC, noting active exploitation.
- **October 6, 2019**: Android open-source patch is merged.
- **October 7, 2019**: Google releases the October 2019 Android Security Bulletin including the fix.
- **November 2019**: Full exploit analysis published.

### Technical Root Cause

The vulnerability is a use-after-free in the Android Binder IPC driver (`drivers/android/binder.c`), the core inter-process communication mechanism in Android.

The bug occurs in the `binder_ioctl()` function specifically through the interaction between `BINDER_THREAD_EXIT` and `epoll`. When a Binder thread is registered with an `epoll` instance and then exits via `BINDER_THREAD_EXIT`, the Binder driver frees the `binder_thread` structure. However, the `epoll` subsystem retains a pointer to the waitqueue entry embedded within the now-freed `binder_thread` structure. When `epoll` subsequently accesses this waitqueue entry, it dereferences the freed memory.

```c
// Simplified exploitation flow:
// 1. Create binder fd, register thread
int binder_fd = open("/dev/binder", O_RDWR);

// 2. Add binder fd to epoll
epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event);

// 3. Trigger BINDER_THREAD_EXIT -- frees binder_thread, but epoll
//    still holds a reference to its embedded waitqueue
ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

// 4. Now the freed binder_thread memory can be reclaimed and
//    controlled by the attacker using heap spray
// 5. When epoll triggers, it uses the attacker-controlled data
//    -> arbitrary kernel code execution
```

### Real-World Exploitation

This vulnerability is historically significant because it was confirmed as a **0-day exploited by NSO Group**, the Israeli surveillance company behind the Pegasus spyware platform. The exploit was part of a chain that:

1. Used a Chrome renderer bug for initial code execution.
2. Used CVE-2019-2215 for kernel privilege escalation.
3. Installed the Pegasus implant for full device surveillance.

Affected devices included:
- Google Pixel 1, 1 XL, 2, 2 XL
- Huawei P20
- Xiaomi Redmi 5A, Redmi Note 5, A1
- Oppo A3
- Motorola Moto Z3
- Samsung Galaxy S7, S8, S9
- LG Oreo devices

The vulnerability was added to CISA's Known Exploited Vulnerabilities Catalog.

### Remediation

The fix ensured proper cleanup of the waitqueue entry upon `BINDER_THREAD_EXIT` by calling `remove_wait_queue()` before freeing the thread structure. Additionally, the upstream Linux kernel received the fix through a backport to affected stable trees.

---

## 5.5 Janus (CVE-2017-13156)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2017-13156 |
| **CVSS v3.0** | 7.8 (High) --- AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 7.2 (High) |
| **CWE** | CWE-434 (Unrestricted Upload of File with Dangerous Type) |
| **Affected Versions** | Android 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0 |
| **Discovered By** | Guard Square (Eric Lafortune) |
| **Disclosed** | December 2017 (Android Security Bulletin 2017-12-01) |
| **Patched** | December 2017 security patch |

### Technical Root Cause

The Janus vulnerability exploited a fundamental flaw in how Android verified APK signatures under the **JAR signature scheme (v1)**. Named after the Roman two-faced god, the vulnerability leveraged the fact that a file can be simultaneously valid as both a DEX file and an APK (ZIP) file.

**DEX file format**: The Dalvik Executable format reads the file from the **beginning**. The header at offset 0 defines all structures.

**ZIP file format**: ZIP files are parsed from the **end** of the file. The central directory at the end of the file contains offsets to all entries.

An attacker could prepend a DEX file to a legitimate APK. The Android package installer and the APK signature verifier would parse the file as a ZIP (from the end), finding the original signed contents intact and the signature valid. However, the Android Runtime (ART) would load the file as a DEX (from the beginning), executing the attacker's code.

```
+-------------------+
| Malicious DEX     |  <-- ART reads from here (DEX header at offset 0)
| (attacker code)   |
+-------------------+
| Original APK      |  <-- Package verifier reads from here (ZIP)
| (signed content)  |
| with valid v1 sig |
+-------------------+
```

### Exploitation Scenario

The attack was practical for several scenarios:
1. **Supply chain attacks**: A man-in-the-middle attacker intercepting APK downloads could inject malicious code while preserving the legitimate signature.
2. **Update hijacking**: A malicious app update could pass signature verification while containing entirely different code.
3. **Privilege escalation**: An attacker could modify a system app or a privileged app and replace it on the device, inheriting all the original app's permissions.

### Remediation

Google addressed this in two ways:
1. **Immediate fix**: The December 2017 patch added additional validation to reject APK files with non-ZIP data prepended.
2. **APK Signature Scheme v2 and v3**: These newer signature schemes sign the **entire file** (not just ZIP entries), making prepend attacks impossible. Android 7.0+ devices using APK Signature Scheme v2 were not affected.

---

## 5.6 FakeID (CVE-2014-8609)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2014-8609 |
| **CVSS v2** | 6.8 (Medium) |
| **CWE** | CWE-295 (Improper Certificate Validation) |
| **Affected Versions** | Android 2.1 through 4.4 |
| **Discovered By** | Jeff Forristal, Bluebox Security |
| **Disclosed** | July 2014 (Black Hat USA 2014) |
| **Patched** | Android Lollipop 5.0 (and backported to 4.4.x) |

### Technical Root Cause

FakeID exploited a critical flaw in how the Android package manager validated X.509 certificate chains used for APK signing. The vulnerability was in `JarUtils.verifySignature()` within the Java certificate chain verification code.

Android uses certificates to establish trust relationships between applications. Certain system features rely on the signing certificate identity --- for example, apps signed by Adobe's certificate can act as webview plugins, and apps signed by the device manufacturer's certificate can access certain privileged APIs.

The flaw was that Android **failed to validate the certificate chain of trust**. When an APK presented a certificate chain, Android verified that the certificates were structurally valid but did not verify that each certificate in the chain was actually issued by (signed by) the next certificate up the chain. An attacker could construct a certificate chain where:
1. Their own self-signed certificate was the leaf certificate.
2. A copy of Adobe's (or Google's, or the OEM's) certificate was appended to the chain.

Android would see Adobe's certificate in the chain and grant the app Adobe-level trust --- without verifying that Adobe actually signed the attacker's certificate.

### Exploitation

Practical attack scenarios included:
- **WebView plugin injection**: An app could claim to be signed by Adobe, gaining the ability to inject arbitrary plugins into any app's WebView, enabling cross-app data theft.
- **Device administration**: An app could impersonate a Google-signed app to gain device administrator privileges.
- **NFC payment access**: Impersonating the Google Wallet certificate chain to access the secure element.

### Remediation

The fix added proper certificate chain validation, verifying that each certificate was genuinely signed by its issuer in the chain. Android 5.0 Lollipop included the complete fix, and it was backported to Android 4.4.x maintenance releases.

---

## 5.7 Certifi-gate (CVE-2015-3825)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2015-3825 |
| **CVSS v2** | ~7.5 (High) |
| **CWE** | CWE-295 (Improper Certificate Validation) / CWE-269 (Improper Privilege Management) |
| **Affected Versions** | Android 4.x -- 5.x; devices from LG, Samsung, HTC, ZTE with pre-installed remote support tools |
| **Discovered By** | Ohad Bobrov and Avi Bashan, Check Point |
| **Disclosed** | August 2015 (Black Hat USA 2015) |
| **Patched** | Vendor-specific updates throughout late 2015/2016 |

### Technical Root Cause

Certifi-gate was not a vulnerability in Android's core code but in the **OEM remote support tool ecosystem**. OEMs like Samsung, LG, HTC, and ZTE shipped devices with pre-installed remote support plugins (from companies like TeamViewer, Rsupport, and CommuniTake) that ran with **system-level privileges**.

These remote support tools operated as two components:
1. A **user-facing app** (e.g., TeamViewer QuickSupport).
2. A **privileged plugin** (system service) pre-installed by the OEM with `SYSTEM` or `signature`-level permissions.

The vulnerability lay in how the privileged plugin authenticated the requesting app. The plugins verified the calling app's certificate serial number but did not properly validate the certificate chain. An attacker could create an app with a certificate whose serial number matched the legitimate remote support app, and the privileged plugin would grant it full system access, including:

- Screen capture/recording without notification.
- Simulating user input (taps, swipes, keystrokes).
- Installing and uninstalling apps silently.
- Accessing all user data.

### Exploitation

Check Point demonstrated a practical attack where a malicious app, installed from the Play Store, could exploit the pre-installed vulnerable plugin to gain full remote control of the device. Approximately 50% of Android devices at the time shipped with at least one vulnerable remote support plugin.

### Remediation

Because the vulnerable plugins were signed by OEM certificates and shipped as system apps, they could not be easily removed by users. Remediation required:
1. OEM firmware updates with fixed plugin versions.
2. Google Play Protect detection of apps exploiting the vulnerability.
3. Some OEMs chose to remove the vulnerable plugins entirely.

---

## 5.8 StrandHogg (CVE-2020-0096)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2020-0096 (StrandHogg 2.0) |
| **CVSS v3.1** | 7.8 (High) --- AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 7.2 (High) |
| **CWE** | Confused Deputy / Privilege Escalation |
| **Affected Versions** | Android 8.0, 8.1, 9.0 (StrandHogg 2.0); Android 6.0 through 9.0 (StrandHogg 1.0) |
| **Discovered By** | Promon (Norwegian security firm) |
| **Disclosed** | December 2019 (v1.0); May 2020 (v2.0) |
| **Patched** | May 2020 Android security bulletin |

### Technical Root Cause

StrandHogg (named after the Norse Viking raiding tactic) exploits Android's multitasking/activity management system.

**StrandHogg 1.0** abused the `taskAffinity` attribute in the Android manifest. Every Android activity belongs to a task (a stack of activities). The `taskAffinity` attribute controls which task an activity is placed in. A malicious app could declare an activity with the same `taskAffinity` as a target app (e.g., a banking app) and set `allowTaskReparenting="true"`. When the victim launched the banking app, Android's task manager would insert the malicious activity on top of the legitimate app's task stack. The user would see the malicious activity (e.g., a fake login screen) believing it was part of the real banking app.

**StrandHogg 2.0 (CVE-2020-0096)** was more severe: a confused deputy vulnerability in `ActivityStartController.java`'s `startActivities()` method. The flaw allowed a malicious app to hijack the launch of **any** activity on the device by exploiting how the Activity Manager resolved task placement. The malicious app could, through reflection and careful intent construction, redirect any app launch to its own phishing activity without declaring any special manifest attributes.

### Exploitation

Real-world exploitation was confirmed by Promon:
- **Credential harvesting**: Fake login screens overlaid on banking, email, and social media apps.
- **Permission hijacking**: When a legitimate app requested a permission, the malicious overlay would intercept the grant.
- **36 malicious apps** were identified exploiting StrandHogg 1.0 in the wild.

StrandHogg was particularly dangerous because:
- No root or special permissions required.
- Virtually undetectable by the user.
- Could target any app on the device.
- Left no trace in traditional antimalware scanning.

### Remediation

The May 2020 security bulletin patched the `startActivities()` logic to properly validate the caller's identity and intent parameters. Android 10 was not vulnerable to StrandHogg 2.0 due to activity launch restrictions introduced in that version.

---

## 5.9 Broadcom WiFi Bugs: Broadpwn and Related

| Attribute | Details |
|---|---|
| **CVE IDs** | CVE-2017-0561, CVE-2017-9417 (Broadpwn) |
| **CVSS v3.0** | 9.8 (Critical) --- AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 10.0 (High) |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **Affected Versions** | Broadcom BCM43xx WiFi chipsets; Android devices using kernel 3.10 and 3.18; iPhones through iOS 10.3.2 |
| **Discovered By** | Gal Beniamini, Google Project Zero (CVE-2017-0561); Nitay Artenstein, Exodus Intelligence (CVE-2017-9417) |
| **Disclosed** | April 2017 (CVE-2017-0561); July 2017 at Black Hat (CVE-2017-9417) |
| **Patched** | April 2017 and July 2017 Android security bulletins |

### Technical Root Cause

These vulnerabilities targeted the Broadcom BCM43xx series WiFi chipset firmware, which runs on an ARM Cortex-R4 core **separate from the main application processor**. The WiFi firmware runs its own RTOS (HNDRTE) with **no ASLR, no stack canaries, no DEP/NX protections**, and full read-write-execute memory.

**CVE-2017-0561** was a heap buffer overflow in the Broadcom WiFi firmware triggered by processing crafted wireless management frames. The vulnerability existed in the firmware's handling of TDLS (Tunneled Direct Link Setup) frames, where insufficient length validation allowed an attacker within WiFi range to overflow a heap buffer and achieve code execution on the WiFi chip.

**CVE-2017-9417 (Broadpwn)** was Nitay Artenstein's landmark exploit that achieved a **fully remote, zero-click, wormable** WiFi attack. The bug was a heap overflow triggered by specially crafted WiFi association responses. When a device with a vulnerable Broadcom chip scanned for WiFi networks, the malicious response corrupted the firmware heap, allowing arbitrary code execution on the WiFi SoC.

### Exploitation

Broadpwn demonstrated a terrifying attack scenario:
1. Attacker sets up a malicious WiFi access point (or spoofs one).
2. Any device within range that scans for WiFi networks (which happens automatically) receives the malicious frame.
3. The frame triggers a heap overflow in the WiFi firmware.
4. Attacker gains code execution on the WiFi SoC.
5. From the WiFi chip, the attacker could potentially pivot to the application processor via the PCIe/SDIO bus interface.

Gal Beniamini further published research demonstrating a full chain from WiFi chip compromise to application processor compromise, effectively achieving remote kernel code execution over WiFi.

The affected devices included virtually all flagship Android phones and iPhones produced between 2012-2017, including Samsung Galaxy, Google Nexus/Pixel, LG, HTC, and Apple iPhone models.

### Remediation

- Broadcom released firmware updates distributed through Android and iOS security bulletins.
- Google's April 2017 and July 2017 Android security bulletins included the fixes.
- Apple patched in iOS 10.3.3.
- Long-term: Samsung and other OEMs began requiring firmware isolation and hardware-based separation between the WiFi chip and application processor.

---

## 5.10 Samsung-Specific CVEs

Samsung devices, holding the largest Android market share globally, have been subject to numerous high-profile vulnerabilities unique to their custom software stack.

### CVE-2015-7888: Samsung SwiftKey Remote Code Execution

| Attribute | Details |
|---|---|
| **CVSS** | ~7.5 (High) |
| **Affected** | Samsung Galaxy S4, S5, S6 series (600M+ devices) |
| **Discovered By** | Ryan Welton, NowSecure |
| **Disclosed** | June 2015 |

**Root Cause**: Samsung shipped a customized version of SwiftKey keyboard as an irremovable system app. Language pack updates were downloaded over unencrypted HTTP and processed with system-level privileges. An attacker performing a man-in-the-middle attack (e.g., on public WiFi) could inject a malicious language pack ZIP file, which was extracted with path traversal, allowing arbitrary file writes as the system user.

### CVE-2019-16253 / CVE-2020-28341: Samsung Qmage Codec Bugs

| Attribute | Details |
|---|---|
| **CVSS** | 9.8 (Critical, estimated) |
| **Affected** | Samsung devices running Android 8.x through 11.0 with Samsung's custom Skia graphics library |
| **Discovered By** | Mateusz Jurczyk, Google Project Zero |

**Root Cause**: Samsung added a proprietary image format called "Qmage" (`.qmg`) to the Skia graphics rendering library. This codec was reached automatically when **any** image was processed, including MMS messages, notifications, and wallpapers. Multiple memory corruption bugs in the Qmage decoder (heap overflows, type confusions) allowed zero-click remote code execution via a crafted MMS message --- effectively recreating the Stagefright attack scenario. Jurczyk demonstrated a full zero-click exploit chain requiring approximately 100-300 MMS messages over 2+ hours to defeat ASLR.

### CVE-2022-22292: Samsung Phone App Vulnerability

| Attribute | Details |
|---|---|
| **CVSS** | 7.8 (High) |
| **Affected** | Samsung devices running Android 9 through 12 |
| **Discovered By** | Kryptowire |

**Root Cause**: The Samsung Phone app (used for making calls) had an exported component with an insecure intent handling vulnerability. Any app on the device, including zero-permission apps, could forge intents to the Phone app that would: make phone calls without user interaction, silently install/uninstall apps, execute arbitrary code through a factory-reset intent, or weaken HTTPS security by installing attacker-chosen CA certificates.

---

## 5.11 Qualcomm DSP and GPU CVEs --- Achilles and Related

| Attribute | Details |
|---|---|
| **CVE IDs** | CVE-2020-11201, CVE-2020-11202, CVE-2020-11206, CVE-2020-11207, CVE-2020-11208, CVE-2020-11209 (Achilles); CVE-2020-11239, CVE-2021-1905, CVE-2021-1906 (Adreno GPU) |
| **CVSS** | 6.0 -- 8.4 (Medium to High, varies by CVE) |
| **CWE** | CWE-787 (Out-of-bounds Write), CWE-125 (Out-of-bounds Read), CWE-416 (Use After Free) |
| **Affected Versions** | Qualcomm Snapdragon chipsets with Hexagon DSP (Snapdragon 400, 600, 700, 800 series) |
| **Discovered By** | Slava Makkaveev, Check Point Research (Achilles); various researchers (GPU bugs) |
| **Disclosed** | August 2020 (Achilles); 2020-2021 (GPU bugs) |
| **Patched** | Qualcomm security bulletins from September 2020 onward |

### Technical Root Cause: Achilles

The "Achilles" vulnerability cluster targeted the **Qualcomm Hexagon DSP (Digital Signal Processor)**, a specialized processor present in virtually all Snapdragon SoCs. The Hexagon DSP handles compute-intensive tasks including image processing, machine learning inference, audio processing, and sensor data fusion. Approximately 40% of all Android smartphones worldwide use Snapdragon chipsets.

The vulnerabilities were found in the Hexagon DSP's software interface layer --- specifically in the `libfastcvadsp.so`, `libdsp_streamer.so`, and related shared libraries that bridge the application processor and the DSP. The core issues were:

1. **CVE-2020-11201**: Heap-based buffer overflow in the DSP's FastRPC (Fast Remote Procedure Call) framework. The FastRPC interface allows user-space applications to offload computation to the DSP. Insufficient bounds checking on input buffers passed through the FastRPC interface allowed an attacker to overflow a heap buffer on the DSP, achieving code execution in the DSP context.

2. **CVE-2020-11202**: Improper validation of array indices in the DSP's shared memory management, allowing out-of-bounds memory access.

3. **CVE-2020-11206**: Integer overflow leading to buffer overflow in the DSP's compute library.

4. **CVE-2020-11207 / CVE-2020-11208**: Additional buffer overflow and integer overflow variants in DSP compute libraries.

5. **CVE-2020-11209**: Time-of-check-time-of-use (TOCTOU) race condition in the DSP's memory validation logic.

### Exploitation

An attacker with a malicious app (requiring no special permissions) could:
- Execute arbitrary code on the Hexagon DSP, which runs outside the Android security sandbox.
- Access and exfiltrate photos, videos, and call recordings.
- Activate the microphone and GPS without user awareness.
- Render the device permanently unresponsive (persistent DoS).
- Install stealthy malware hidden within the DSP firmware, invisible to the Android OS.

The DSP operates as a black box from the Android OS perspective, making detection of DSP-level compromise nearly impossible with standard mobile security tools.

### Adreno GPU Vulnerabilities

Related Qualcomm GPU vulnerabilities in the Adreno driver:

- **CVE-2021-1905**: Use-after-free in the Adreno GPU driver's command submission path. Exploited in the wild as part of a targeted attack chain. The vulnerability allowed kernel code execution from a GPU render context.
- **CVE-2021-1906**: Improper address validation in the Adreno GPU driver, enabling arbitrary kernel memory read/write from user space.

These GPU bugs were significant because GPU drivers run in kernel space, and GPU command queues provide a rich attack surface accessible from any app using OpenGL/Vulkan.

### Remediation

Qualcomm distributed patches through their own monthly security bulletins, which OEMs then integrated into their firmware. The Achilles vulnerabilities required both application-processor-side library updates and DSP firmware updates, making the patch process slower than typical Android security fixes.

---

## 5.12 MediaTek-SU (CVE-2020-0069)

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2020-0069 |
| **CVSS v3.1** | 7.8 (High) --- AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CVSS v2** | 7.2 (High) |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **Affected Versions** | Dozens of MediaTek SoCs (MT6580, MT6735, MT6737, MT6739, MT6753, MT6755, MT6757, MT6761, MT6763, MT6765, MT6771, MT6779, MT6795, MT6797, MT8163, MT8167, MT8173, MT8176, and others) |
| **Discovered By** | XDA Developers community member "diplomatic" (January 2019); independently reported to MediaTek |
| **Publicly Known** | January 2019 (on XDA-Developers forums) |
| **Patched** | Android March 2020 security bulletin |
| **Active Exploitation** | Confirmed by Google in CISA KEV catalog |

### Timeline

- **January 2019**: XDA member "diplomatic" publishes a one-click root exploit for Amazon Fire tablets using MediaTek chipsets.
- **February 2019**: The exploit is found to work on nearly all MediaTek-based devices. It spreads rapidly through the XDA community.
- **April 2019**: MediaTek releases a patch to OEMs.
- **Throughout 2019**: Most OEMs fail to incorporate the patch. The exploit remains viable on millions of devices.
- **January 2020**: XDA-Developers publishes a detailed article highlighting the severity and the year-long patching failure.
- **March 2, 2020**: Google includes the fix in the March 2020 Android Security Bulletin, 14 months after public disclosure.
- **November 2021**: Added to CISA's Known Exploited Vulnerabilities Catalog.

### Technical Root Cause

The vulnerability existed in MediaTek's proprietary **CMDQ (Command Queue) driver**, a kernel module that provides an interface for offloading GPU/display operations. The CMDQ driver exposes an `ioctl()` interface to user space via a device node (`/dev/mtk_cmdq` or similar).

The root cause was an out-of-bounds write due to insufficient input sanitization in the CMDQ `ioctl` handlers, combined with the critical absence of **SELinux restrictions** on the device node. On most MediaTek devices, the CMDQ device node was accessible from the `untrusted_app` SELinux context --- meaning any installed application could interact with it.

The exploit worked as follows:
1. Open the CMDQ device node from any app context.
2. Send crafted `ioctl` commands that write arbitrary values to arbitrary physical memory addresses.
3. Use this arbitrary write primitive to:
   a. Disable SELinux enforcement by overwriting the `selinux_enforcing` global variable in kernel memory.
   b. Escalate the calling process to root by modifying the `cred` structure of the current task.

```c
// Simplified exploit logic
int fd = open("/dev/mtk_cmdq", O_RDWR);

// Craft CMDQ command that writes to arbitrary physical address
struct cmdq_command cmd;
cmd.addr = virt_to_phys(&selinux_enforcing);
cmd.value = 0;  // Set to permissive
ioctl(fd, CMDQ_IOCTL_EXEC, &cmd);

// SELinux is now permissive; escalate to root
cmd.addr = /* address of current->cred->uid */;
cmd.value = 0;
ioctl(fd, CMDQ_IOCTL_EXEC, &cmd);
```

### Affected Devices

The scale of impact was enormous. MediaTek chipsets power budget and mid-range devices globally, with disproportionate market share in developing countries. Affected devices included:
- Amazon Fire tablets (all generations using MediaTek)
- Dozens of phones from Alcatel, Huawei, Oppo, Vivo, ZTE, LG, Sony, and others
- Various Lenovo, Acer, and ASUS tablets
- Numerous smart TVs and set-top boxes

Estimates put the number of affected devices in the **hundreds of millions**.

### Real-World Exploitation

MediaTek-SU was unique in that it was **first exploited by enthusiasts for rooting** (a benign use case) before being adopted for malicious purposes. However, malicious exploitation was confirmed:
- Multiple Play Store apps were found incorporating the exploit to silently gain root access.
- The vulnerability was used by adware and click-fraud malware to persist across factory resets.
- The 14-month gap between public disclosure and official patch left a massive window of exploitation.

### Remediation

The March 2020 patch addressed the vulnerability by:
1. Adding proper bounds checking to the CMDQ `ioctl` handler.
2. Restricting the CMDQ device node with proper SELinux policies to prevent access from untrusted app contexts.
3. Adding input validation for all DMA (Direct Memory Access) command addresses.

---

## Summary: Comparative Analysis of Major Android CVEs

| CVE | Year | Type | CVSS | Remote? | 0-Click? | In-Wild Exploit | Legacy Impact |
|---|---|---|---|---|---|---|---|
| Stagefright | 2015 | Memory Corruption | 10.0 | Yes | Yes | Not confirmed | Monthly security bulletins |
| Dirty COW | 2016 | Race Condition | 7.0 | No | N/A | Yes | Kernel COW hardening |
| Dirty Pipe | 2022 | Improper Init | 7.8 | No | N/A | Yes | Pipe subsystem audit |
| Bad Binder | 2019 | Use-After-Free | 7.8 | No | N/A | Yes (NSO) | Binder hardening |
| Janus | 2017 | Signature Bypass | 7.8 | No | N/A | Not confirmed | APK Sig v2/v3 adoption |
| FakeID | 2014 | Cert Validation | 6.8 | No | N/A | Not confirmed | Certificate chain validation |
| Certifi-gate | 2015 | OEM Trust Abuse | ~7.5 | No | N/A | Not confirmed | OEM plugin auditing |
| StrandHogg | 2020 | Task Hijacking | 7.8 | No | N/A | Yes | Activity launch restrictions |
| Broadpwn | 2017 | Heap Overflow | 9.8 | Yes | Yes | Not confirmed | WiFi firmware isolation |
| Samsung Qmage | 2020 | Memory Corruption | ~9.8 | Yes | Yes | Not confirmed | Custom codec auditing |
| Achilles | 2020 | DSP Buffer Overflow | 6.0-8.4 | No | N/A | Not confirmed | DSP interface hardening |
| MediaTek-SU | 2020 | OOB Write | 7.8 | No | N/A | Yes | SELinux for driver nodes |

### Key Themes

1. **The media processing attack surface** (Stagefright, Qmage) has proven to be one of the most dangerous vectors, enabling zero-click remote exploitation. Android responded with extensive sandboxing (mediaextractor, constrained_codec2) and fuzzing investment.

2. **Linux kernel vulnerabilities** (Dirty COW, Dirty Pipe, Bad Binder) demonstrate that Android inherits the full attack surface of the Linux kernel. GKI (Generic Kernel Image) and KAPI stability efforts aim to make kernel updates faster.

3. **Hardware component firmware** (Broadpwn, Achilles, MediaTek-SU) represents a growing concern. Code running on WiFi chips, DSPs, and GPUs operates outside Android's security model but can compromise the entire device. Efforts toward hardware-based isolation (IOMMU enforcement, firmware compartmentalization) continue.

4. **OEM customizations** (Samsung Qmage, Certifi-gate, Samsung Phone app) consistently introduce vulnerabilities absent from stock Android. The Android security team has expanded CTS (Compatibility Test Suite) security requirements and encouraged OEMs to minimize custom native code.

5. **The patching gap** remains the most persistent challenge. MediaTek-SU was publicly known for 14 months before appearing in an official Android Security Bulletin. Project Mainline (APEX modules) and GKI aim to decouple critical security components from OEM update cycles, allowing Google to deliver fixes directly through Play System Updates.
