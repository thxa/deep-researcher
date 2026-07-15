# EL0 to EL1 Privilege Escalation on ARM64: Practical Real-World Case Studies

**Researcher B — Practical & Real-World Track**  
Date: 2026-07-15

---

## 1. Executive Summary

On ARM64 Android, user applications run at **EL0** while the Linux kernel runs at **EL1**. The boundary between the two is the richest, most reliable path to full device compromise because the kernel is shared across most devices from a vendor. This report examines publicly documented cases where real-world attackers or researchers crossed that boundary, the devices affected, how the bugs were found, and the patch ecosystem that lets them stay exploitable.

---

## 2. What EL0→EL1 Means on ARM64 Android

- **EL0** = userspace: apps, browser renderers, zygote children, untrusted_app SELinux context.
- **EL1** = kernel: Linux kernel plus vendor drivers (GPU, display, DSP, Binder, ALSA, etc.).
- A kernel driver bug reachable from an app (e.g., an `ioctl` on `/dev/mali0`, `/dev/binder`, or a Samsung DECON fd) is the most common way to escalate from EL0 to EL1.
- Once inside the kernel, attackers disable mitigations and obtain arbitrary read/write, then root.

---

## 3. Real-World Exploit Chains (Case Studies)

### 3.1 Samsung Quram DNG image exploit — 2024-2025 (in-the-wild)

- **Disclosure:** Project Zero, 2025-12-12. Samples were on VirusTotal between July 2024 and February 2025. Fixed by Samsung in April 2025.
- **Delivery:** A DNG image disguised as a JPEG was sent over WhatsApp. When the user clicked it, the image was added to the Android `MediaStore`, which caused Samsung's `com.samsung.ipservice` to parse it with the closed-source **Quram** image library.
- **Root cause:** `QuramDngOpcodeDeltaPerColumn::processArea` miscalculated `opcode_last_plane` and did not bound the plane index, so a malformed opcode could add a controlled value at a controlled offset beyond the raw pixel buffer.
- **Exploitation:** The attackers first corrupted a `QuramDngImage` dimension field to make later `MapTable` opcodes work out of bounds, then type-confused a `TrimBounds` opcode into a `MapTable` opcode to leak a vtable pointer, built a fake opcode object, and eventually obtained arbitrary kernel read/write and executed a shell command.
- **Actor impact:** Palo Alto Networks Unit 42 linked the same exploit to the **Landfall** commercial Android spyware.

Source: [Project Zero — A look at an Android ITW DNG exploit](https://googleprojectzero.blogspot.com/2025/12/a-look-at-android-itw-dng-exploit.html)

---

### 3.2 Samsung ALSA / Mali chain — December 2022

- **Disclosure:** Project Zero, 2023-09-19. Google's Threat Analysis Group (TAG) found the chain targeting Samsung Android devices.
- **N-days used upstream:**
  - Chrome RCE: CVE-2022-4262
  - Chrome sandbox escape: CVE-2022-3038
  - Mali driver n-day: CVE-2022-22706
- **Kernel bugs:**
  - **CVE-2023-0266** — a race condition in the 32-bit ALSA compatibility `ioctl` path. The upstream refactor moved locking out of `snd_ctl_elem_write`, but the 32-bit compat path was left without `controls_rwsem`, producing a use-after-free on `struct snd_kcontrol`.
  - **CVE-2023-26083** — the Mali `tlstream` (timeline stream) performance facility was readable by unprivileged code, leaked kernel pointers, and allowed 16 bytes of attacker-controlled data to be placed at a known kernel address.
- **Exploitation:** The attacker used Mali `REQ_SOFT_JIT_FREE` jobs as a heap spray, reclaimed the freed `snd_kcontrol` with controlled data, forged a `user_element` via `tlstream`, and called `snd_ctl_elem_user_put` to get an arbitrary kernel write. The chain then forged `ashmem_misc.fops` and used a configfs/ashmem type confusion to obtain stable arbitrary read/write.
- **Lesson:** Even a bug that was accidentally fixed upstream in March 2021 was exploitable because the fix was not backported to the Android kernel.

Source: [Project Zero — Analyzing a Modern In-the-wild Android Exploit](https://googleprojectzero.blogspot.com/2023/09/analyzing-modern-in-wild-android-exploit.html)

---

### 3.3 Samsung Clipboard / DECON chain — late 2020

- **Disclosure:** Project Zero, 2022-11-04. All three bugs fixed in Samsung's March 2021 release.
- **Vulnerabilities:**
  - **CVE-2021-25337** — Samsung's `SemClipboardProvider` in `system_server` was exported without access control, allowing any untrusted app to insert arbitrary `_data` paths and read/write files via `system_server`.
  - **CVE-2021-25369** — Samsung's `sec_log` copied kernel `WARN_ON` backtraces to `/data/log/sec_log.log`, which was readable by many apps. Triggering a `WARN_ON` in the Mali `hwcnt` driver leaked `task_struct` and `sys_call_table` addresses.
  - **CVE-2021-25370** — a use-after-free in the Samsung DECON display driver (`decon_set_win_config`). `fd_install` was called before `get_file`, so a user `close()` could free the underlying `struct file` while the driver still used it.
- **Targets:** Samsung Exynos devices on kernel 4.14.113, including Galaxy S10, A50, and A51. The Mali r19p0 driver was still in use.
- **Exploitation:** Stage 1 wrote a malicious ELF into `/data/system/users/0/` via the clipboard bug and hijacked the Samsung Text-to-Speech app (`com.samsung.SMT`) to load it as `system_app`. Stage 2 leaked kernel addresses, then sprayed fake `file` structs via the Mali `MEM_PROFILE_ADD` ioctl and used the DECON UAF to overwrite `addr_limit`, gaining arbitrary kernel read/write.

Source: [Project Zero — A Very Powerful Clipboard](https://googleprojectzero.blogspot.com/2022/11/a-very-powerful-clipboard-samsung-in-the-wild-exploit-chain.html)

---

### 3.4 Pixel Binder UAF — CVE-2019-2215 (Pegasus)

- **Disclosure:** Project Zero, 2019-10-03, under a 7-day deadline because of credible evidence of in-the-wild use by NSO Group to install **Pegasus**.
- **Root cause:** The Binder driver embedded a `wait_queue_head_t` inside `struct binder_thread`. When `BINDER_THREAD_EXIT` freed the `binder_thread`, an epoll watch could still reference the embedded wait queue, causing a use-after-free in `remove_wait_queue`.
- **Affected devices:** Pixel 1 and Pixel 2, and many Android devices with kernels before 4.14. Pixel 3/3a were not affected because the upstream fix was already present.
- **Exploitation:** The PoC triggered the UAF twice. The first time it reclaimed the freed `binder_thread` with an `iovec` array and used the `list_del` unlink primitive to leak the `task_struct` pointer. The second time it overwrote `task_struct->addr_limit` with `0xFFFFFFFFFFFFFFFE`, giving the unprivileged process arbitrary kernel read/write.
- **Significance:** The bug was originally found by **syzkaller** in November 2017 and patched in upstream Linux in February 2018, but the fix was never included in an Android Security Bulletin, leaving Pixel and Pixel 2 unpatched for almost two years.

Source: [Project Zero — Bad Binder: Android In-The-Wild Exploit](https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html)

---

### 3.5 MediaTek JPEG driver bugs — 2023

- **Disclosure:** Project Zero, 2024-06-13. Research on Pixel 7, Xiaomi 11T, and Asus ROG 6D.
- **Vulnerabilities:**
  - **CVE-2023-32837** — an out-of-bounds read/write in the `mtk_jpeg` driver in an array of structs. MediaTek had partially fixed it in July 2021 with a Coverity static-analysis patch, but the patch did not reach all device trees (e.g., Xiaomi 11T on kernel 4.14).
  - **CVE-2023-32832** — a race between `jpeg_drv_hybrid_dec_start` and `jpeg_drv_hybrid_dec_unlock` that caused a `struct file` / `dma_buf` use-after-free.
- **Exploitation:** The attacker used the `GED` (GPU Extension Device) driver's GE buffers as a powerful heap spray: fully controlled, readable/writable while allocated, and freely allocatable. By reclaiming the freed `dma_buf` with a GE buffer, the attacker controlled the `dma_buf` struct, obtained arbitrary read via `dma_buf_show_fdinfo`, arbitrary `kfree` via `mtk_dma_buf_set_name`, and finally arbitrary write by type-confusing a GE buffer with a GE buffer array.
- **Discovery method:** Manual enumeration of `/dev` and `/proc`, SELinux policy analysis, and kernel source review. CVE-2023-32837 was originally flagged by **Coverity** static analysis, but its security impact was not recognized.

Source: [Project Zero — Driving forward in Android drivers](https://googleprojectzero.blogspot.com/2024/06/driving-forward-in-android-drivers.html)

---

### 3.6 Qualcomm GPU micronode — CVE-2025-21479

- **CVE details:** NVD entry published 2025-06-04. CISA KEV added 2025-06-03.
- **Description:** "Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands." Classified as incorrect authorization (CWE-863).
- **CVSS 3.1:** 8.6 (AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
- **Affected SoCs:** A long list of Snapdragon platforms, including SM8550P, SM8650Q, Snapdragon 8 Gen 2/Gen 3, 7/6/4-series, FastConnect, and others.
- **Real-world impact:** Listed in CISA's Known Exploited Vulnerabilities catalog, meaning it has been observed exploited in the wild.

Source: [NVD — CVE-2025-21479](https://nvd.nist.gov/vuln/detail/CVE-2025-21479), [CISA KEV — CVE-2025-21479](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-21479)

---

### 3.7 ARM Mali GPU driver — CVE-2024-4610

- **CVE details:** NVD entry published 2024-06-07. CISA KEV added 2024-06-12.
- **Description:** Use-after-free in ARM Mali **Bifrost** and **Valhall** GPU kernel drivers from r34p0 through r40p0. A local, non-privileged user can make improper GPU memory processing operations to gain access to already freed memory.
- **CVSS 3.1:** 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
- **Real-world impact:** CISA KEV entry confirms active exploitation. Because the Mali driver ships across many SoCs, this is a cross-device kernel attack surface.

Source: [NVD — CVE-2024-4610](https://nvd.nist.gov/vuln/detail/CVE-2024-4610), [CISA KEV — CVE-2024-4610](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-4610)

---

## 4. APT / Commercial Surveillance Campaigns

- **NSO Group / Pegasus:** CVE-2019-2215 was used to install Pegasus on Android devices. Project Zero disclosed it with a 7-day deadline based on marketing materials and technical leads that matched the exploit.
- **Landfall spyware:** The 2024-2025 Samsung DNG exploit was used by a commercial-grade Android spyware family described by Palo Alto Networks Unit 42 in November 2025.
- **Samsung chains (2020-2022):** TAG attributed the Samsung clipboard and ALSA/Mali chains to commercial surveillance vendors.
- Common thread: these campaigns chain a **remote or app-level entry bug** with a **kernel EL0→EL1 bug** to bypass Android's sandbox and SELinux.

Sources: Project Zero DNG and Bad Binder posts; Unit 42 referenced in the DNG post.

---

## 5. Bug Bounty Findings and Project Zero Research

- **Google Android Vulnerability Rewards Program (VRP)** and **Project Zero** are the two main channels that surface these issues. VRP pays researchers for full exploit chains; Project Zero publishes deep technical analyses of 0-days used in the wild.
- Project Zero's **in-the-wild series** (Android Exploits, Android Post-Exploitation) showed that modern attackers rely heavily on **n-day vulnerabilities** and patch-gaps.
- **KASLR research:** Project Zero's November 2025 post "Defeating KASLR by Doing Nothing at All" demonstrated that on Pixel devices the linear-map base and physical kernel load address are effectively static, so an attacker can compute kernel virtual addresses without a leak. Samsung randomizes the physical kernel load address, but the non-randomized linear map still makes heap sprays predictable.

Source: [Project Zero — Defeating KASLR by Doing Nothing at All](https://googleprojectzero.blogspot.com/2025/11/defeating-kaslr-by-doing-nothing-at-all.html)

---

## 6. Android Security Bulletin Patterns and Patch Timelines

- **Monthly cadence:** Android Security Bulletins are published monthly with one or two patch levels (e.g., `2025-06-01` and `2025-06-05`). The split allows partners to ship a smaller, faster fix set while still being able to declare a patch level.
- **Partner notification:** Android partners are notified at least one month before publication; AOSP links are added within 48 hours of the bulletin.
- **Three-layer fix model:**
  1. Android platform/framework fixes
  2. Upstream Linux kernel fixes
  3. SoC vendor fixes (Qualcomm, MediaTek, ARM, Imagination)
- **Patch gap is the dominant real-world problem:**
  - CVE-2019-2215 was fixed in upstream Linux in February 2018 but only reached Android devices in October 2019.
  - CVE-2023-0266 was partially fixed upstream in March 2021 but not backported to the Android kernel until discovered in the wild in December 2022.
  - MediaTek's CVE-2023-32837 was partially fixed in 2021 with Coverity but remained exploitable on some devices because the patch did not propagate to all trees.

Source: [Android Security Bulletin — June 2025](https://source.android.com/docs/security/bulletin/2025-06-01), [Android Security Bulletins overview](https://source.android.com/docs/security/bulletin)

---

## 7. Device-Specific Impact

| Vendor / SoC | Real-world examples | Notes |
|---|---|---|
| **Google Pixel** | CVE-2019-2215 (Pixel 1/2); KASLR bypass on Pixel 9 | Binder and generic kernel bugs; Pixel 3+ avoided CVE-2019-2215 because of the 4.14 kernel. Linear-map randomization is effectively absent on Pixel. |
| **Samsung Exynos** | DNG exploit, CVE-2023-0266/26083, CVE-2021-25337/25369/25370 | Exynos models use ARM Mali and Samsung DPU/DECON drivers, giving a large OEM-specific attack surface. SamsungTTS and clipboard providers have been used as privilege-escalation stepping stones. |
| **Samsung Qualcomm** | CVE-2025-21479 | Qualcomm-based Galaxy devices share the Adreno/KGSL GPU attack surface with other Snapdragon phones. |
| **Qualcomm** | CVE-2025-21479 | Many Snapdragon platforms listed; GPU micronode bugs are reachable from unprivileged app contexts. |
| **MediaTek** | CVE-2023-32837/32832 | Xiaomi 11T and Asus ROG 6D had extra `/proc` drivers (`ged`, `perfmgr`, `mtk_jpeg`) reachable from `untrusted_app`. |
| **ARM Mali (cross-vendor)** | CVE-2024-4610 | Bifrost/Valhall drivers affect many Exynos, MediaTek, and other devices. |

---

## 8. How These Vulnerabilities Are Discovered

- **Kernel fuzzing:** `syzkaller` / `syzbot` found the original Binder UAF behind CVE-2019-2215 in 2017. Project Zero used the syzkaller corpus to perform variant analysis after in-the-wild leads.
- **Manual code audit:** The Samsung DNG, ALSA compat, and DECON bugs were found by reading closed-source or vendor-modified kernel code. Project Zero's driver enumeration work combined `/dev`/`/proc` listing, SELinux policy review, and kernel source analysis.
- **Static analysis:** MediaTek detected CVE-2023-32837 with **Coverity** but did not recognize the security impact; the partial fix left other device trees vulnerable.
- **In-the-wild sample analysis:** Project Zero and TAG reverse-engineered exploit samples (Samsung chains, DNG images) to recover the root cause and identify patch gaps.
- **Variant analysis:** After CVE-2019-2215, Project Zero looked for other poll/wait-queue lifetime mismatches in drivers. The same mindset applies to Mali `tlstream` and GPU driver command handling.

---

## 9. Conclusion

EL0→EL1 on ARM64 is not a theoretical concern. Real attackers — from NSO Group to commercial spyware vendors — routinely chain app-level or remote bugs with kernel driver vulnerabilities to gain root. The most reliable targets are not the core Linux kernel but the **vendor-specific drivers** (GPU, display, DSP, Binder, media) that are accessible from `untrusted_app` and that vary in patch propagation speed. The biggest systemic issue is the **patch gap**: upstream fixes, static-analysis warnings, and even Android Security Bulletins frequently do not reach end-user devices in time, turning fixed bugs into exploitable n-days.

---

## Sources

1. Project Zero — *A look at an Android ITW DNG exploit* (2025-12-12): https://googleprojectzero.blogspot.com/2025/12/a-look-at-android-itw-dng-exploit.html
2. Project Zero — *Analyzing a Modern In-the-wild Android Exploit* (2023-09-19): https://googleprojectzero.blogspot.com/2023/09/analyzing-modern-in-wild-android-exploit.html
3. Project Zero — *A Very Powerful Clipboard: Analysis of a Samsung in-the-wild exploit chain* (2022-11-04): https://googleprojectzero.blogspot.com/2022/11/a-very-powerful-clipboard-samsung-in-the-wild-exploit-chain.html
4. Project Zero — *Bad Binder: Android In-The-Wild Exploit* (2019-10-03): https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html
5. Project Zero — *Driving forward in Android drivers* (2024-06-13): https://googleprojectzero.blogspot.com/2024/06/driving-forward-in-android-drivers.html
6. Project Zero — *Defeating KASLR by Doing Nothing at All* (2025-11-03): https://googleprojectzero.blogspot.com/2025/11/defeating-kaslr-by-doing-nothing-at-all.html
7. NVD — CVE-2024-4610: https://nvd.nist.gov/vuln/detail/CVE-2024-4610
8. CISA KEV — CVE-2024-4610: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-4610
9. NVD — CVE-2025-21479: https://nvd.nist.gov/vuln/detail/CVE-2025-21479
10. CISA KEV — CVE-2025-21479: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-21479
11. Android Security Bulletin — June 2025: https://source.android.com/docs/security/bulletin/2025-06-01
12. Android Security Bulletins overview: https://source.android.com/docs/security/bulletin
13. MediaTek Product Security Bulletin — June 2025: https://corp.mediatek.com/product-security-bulletin/june-2025
14. Android Security reports / Year in Review archive: https://source.android.com/docs/security/reports
