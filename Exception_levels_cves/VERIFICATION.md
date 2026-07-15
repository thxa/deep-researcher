# Verification Report: ARM64 Exception Level Security Vulnerabilities

**Verifier:** pi verifier agent  
**Date:** 2026-07-15  
**Target:** `FINAL_REPORT.md`  
**Method:** NVD API cross-checks via `web_fetch`/`curl`, primary-source URL spot-checks, claim-by-claim triage.

---

## 1. CVE Fabrication / Accuracy Check

All **sampled CVEs exist in NVD** and map to the components described in the report. No fully fabricated CVEs were found in the checked set.

| CVE | Status vs. Report | Notes |
|-----|-------------------|-------|
| CVE-2025-0072 | ✅ Real | Mali/Arm GPU UAF (Valhall / 5th Gen). Report's "first public MTE bypass on Pixel 8" is **not corroborated** by NVD/Android bulletin; NVD lists exploitation "none". Treat as unverified interpretation. |
| CVE-2025-22413 | ✅ Real | pKVM `hyp-main.c` logic error. Report calls it "privilege escalation / pVM escape". **NVD and Android March 2025 bulletin classify it as Information Disclosure (ID), High.** This is an overstatement of impact. |
| CVE-2025-10263 | ✅ Real | Matches XSA-493. Report says "guest write to unmapped memory"; NVD/XSA more precisely say "writes to resources owned by a higher exception level" / TLBI-completion issue. Minor framing inaccuracy. |
| CVE-2025-46733 | ✅ Real | OP-TEE fTPM PCR reset via malicious tee-supplicant. Report adds "DMA-bypass CSU bugs", which is **not in NVD or GitHub advisory**. Unsupported add-on. |
| CVE-2024-56556 | ✅ Real | Binder UAF in `binder_add_freeze_work()`. Consistent. |
| CVE-2021-1048 | ✅ Real, ITW | epoll UAF; CISA KEV confirms active exploitation. Consistent with Predator chain claim. |
| CVE-2024-4610 | ✅ Real, ITW | Mali Bifrost/Valhall UAF; CISA KEV. Consistent. |
| CVE-2024-43047 | ✅ Real, ITW | Qualcomm fastrpc memory corruption; long affected-chipset list supports "60+ chipsets". |
| CVE-2024-53197 | ✅ Real, ITW | ALSA USB-audio OOB; CISA KEV. |
| CVE-2019-19273 | ✅ Real | Samsung RKP arbitrary write on Exynos 8895. |
| CVE-2020-25053 | ✅ Real | Samsung RKP code exec on Exynos 9830. |
| CVE-2017-18141 | ✅ Real | Qualcomm SMC confused-deputy style issue. |
| CVE-2018-11976 | ✅ Real | QSEE ECDSA private-key leak. |
| CVE-2015-6639 | ✅ Real | QSEE/Widevine privilege escalation. |
| CVE-2024-26598 | ✅ Real | KVM ARM64 GIC-ITS UAF. |
| CVE-2018-18021 | ✅ Real | KVM ARM64 guest-register control-flow issue. |
| CVE-2022-22706 | ✅ Real | Mali GPU write-to-read-only-pages. |
| CVE-2022-22057 | ✅ Real | Qualcomm KGSL fence UAF race. |
| CVE-2023-0266 | ✅ Real, ITW | ALSA compat UAF. Report's "Upstream fix: Mar 2021 (accidental)" is **incorrect**; the fixing commit is dated 2023-01-13. |
| CVE-2023-26083 | ✅ Real, ITW | Mali info leak. |
| CVE-2023-6931 | ✅ Real | perf heap OOB. |
| CVE-2021-30860 | ✅ Real | iOS CoreGraphics FORCEDENTRY; not an Android/ARM64 Linux EL boundary issue, but technically EL0. |

**Conclusion:** No fabricated CVEs detected, but **3 impact/description overstatements** and **1 incorrect date** were found.

---

## 2. Source URL Reality Check

| URL in Report | Status | Notes |
|---------------|--------|-------|
| `https://developer.arm.com/documentation/ddi0487/latest` | ✅ Works | ARM ARMv8-A reference manual landing page. |
| `https://trustedfirmware-a.readthedocs.io/en/latest/threat_model/threat_model.html` | ❌ **404** | Correct TF-A security-advisories page is `.../security_advisories/index.html`. The report's count of TFV-1–TFV-17 is itself correct, but the link is broken. |
| `https://xenbits.xenproject.org/xsa/` | ✅ Works | Confirms XSA-493 ↔ CVE-2025-10263. |
| `https://optee.readthedocs.io/` | ✅ Works | OP-TEE documentation landing page. |
| `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | ✅ Works | CISA KEV catalog loads. |
| `https://projectzero.google/` | ✅ Works | Project Zero blog; independently corroborates Samsung Quram DNG/Landfall story (2025-Dec-12 post). |

**Conclusion:** One broken primary URL; other spot-checked sources are real and corroborate report claims.

---

## 3. Unsupported Claims / Overstatements

1. **CVE-2025-22413 impact overstated.** Report: "local privilege escalation", "pVM escape". NVD/Android bulletin: **Information Disclosure, High**. Downgrade to info-disclosure with possible escalation *potential* only if further evidence is provided.
2. **CVE-2025-0072 "first public MTE bypass on Pixel 8".** NVD lists no known exploitation; Android bulletin treats it as a standard High-severity Mali driver bug. No primary source confirming a public Pixel 8 MTE bypass was located. Flag as **unverified marketing-style framing**.
3. **CVE-2025-46733 "DMA-bypass CSU bugs".** NVD/GitHub advisory describe a tee-supplicant return-code sanitization issue leading to fTPM PCR reset. The CSU/DMA-bypass wording is **unsupported**.
4. **CVE-2023-0266 accidental-fix date.** Report says March 2021; the actual upstream fix commit is 2023-01-13. **Incorrect.**
5. **"Zerodium has publicly listed prices of $2.5M for Android full-chain with persistence".** Could not be independently verified during this run because `zerodium.com` was unreachable and web search was rate-limited. Should be cited with a live source or softened.
6. **Patch-gap "averaging 3–19 months".** The report derives this from only three examples; it is an illustrative range, not a statistical average. Acceptable if framed as examples, but the word "averaging" implies rigor not present.

---

## 4. Coverage Gaps

The report is broad and accurate for its timeframe, but notable recent or adjacent EL-boundary work is absent:

1. **Recent 0-click EL0→EL1 chains (2025–2026).** Project Zero published a Pixel 9/10 chain using:
   - CVE-2025-54957 (Dolby Unified Decoder, 0-click RCE)
   - CVE-2025-36934 (BigWave driver, EL0→EL1 kernel R/W from `mediacodec` sandbox)
   These are highly relevant to the EL0→EL1 boundary and post-compromise barriers discussion.
2. **S-EL2 / RME / ARM CCA as an attack surface.** Mentioned only under future mitigations; no CVEs or bypass research covered, despite RME-enabled devices shipping.
3. **Boot ROM / BL1 vulnerabilities.** MediaTek BROM is mentioned, but no BL1/ROM-level ARM64 EL3 attack surface discussion (e.g., vendor secure-boot bypasses).
4. **Apple Silicon M-series EL research.** The report includes iOS CVE-2021-30860 but omits macOS/iOS ARM64 EL1→EL3/TEE research that informs the broader ARM64 ecosystem.
5. **CVE-2026-43499 "GhostLock" (rt_mutex).** A newly disclosed Linux kernel bug affecting many Android devices; within scope of EL0→EL1 but not covered.

---

## 5. Internal Consistency

- **No contradictions** between the CVE reference table and narrative sections for the checked CVEs.
- CVE-2021-1048 is consistently tied to the Predator campaign in both §6.2 and the table.
- CVE-2024-4610 is consistently marked exploited ITW in the summary and table.
- The executive summary's "17+ TF-A advisories" matches the documented TFV-1 through TFV-17.
- Minor terminology drift: report sometimes says "pKVM escape" for CVE-2025-22413 while sources say "info disclosure" (see §3).

---

## 6. Overall Verdict

**Reliability: Mostly accurate with targeted overstatements.**

The report successfully compiles a large, mostly correct body of ARM64 EL security research. CVEs are real, source URLs are largely correct, and high-profile research claims (GlobalConfusion, Samsung Quram, TF-A advisories) check out. However, a few CVE impact descriptions are inflated, one date is wrong, one primary URL is broken, and very recent 2025–2026 exploit chains are missing. The report should be revised to:

- Correct CVE-2025-22413 impact to "information disclosure".
- Soften or source the CVE-2025-0072 "first public MTE bypass on Pixel 8" claim.
- Remove or source the "DMA-bypass CSU bugs" wording for CVE-2025-46733.
- Fix CVE-2023-0266 upstream-fix date.
- Replace the broken TF-A URL with `https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories/index.html`.
- Add citations for the Zerodium $2.5M claim or soften it.
- Consider adding a short 2025–2026 developments section (Dolby/BigWave 0-click chains, RME/S-EL2 surface).
