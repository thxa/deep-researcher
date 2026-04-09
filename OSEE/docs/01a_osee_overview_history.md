# OSEE - Offensive Security Exploitation Expert

## Certification Overview, History, and Place in the OffSec Hierarchy

---

## 1. What is OSEE?

**OSEE** stands for **Offensive Security Exploitation Expert**. It is the most advanced and elite certification offered by **Offensive Security** (now branded as **OffSec**), the organization behind Kali Linux and some of the most respected hands-on cybersecurity certifications in the industry.

### Definition

The OSEE certifies that its holder possesses **expert-level skills in software exploitation**, specifically in the domain of **advanced Windows exploitation**. A certified OSEE has demonstrated the ability to:

- Develop custom exploits against hardened, modern Windows environments
- Bypass advanced security mitigations including DEP (Data Execution Prevention), ASLR (Address Space Layout Randomization), CFG (Control Flow Guard), ACG (Arbitrary Code Guard), and other kernel-level protections
- Perform Windows kernel-mode exploitation, including driver vulnerability analysis and exploitation
- Craft precision exploit chains that combine multiple vulnerability classes
- Write custom shellcode and position-independent code for constrained environments
- Reverse engineer complex binaries and identify subtle vulnerability patterns
- Execute exploit development against real-world targets with modern defenses enabled

### What It Certifies

Unlike certifications that test breadth of knowledge across many domains, OSEE tests **extreme depth** in a narrow, highly specialized area: the ability to develop working exploits against hardened systems. The exam is a **72-hour (3-day) proctored practical exam** where candidates must demonstrate real exploitation skills against live targets --- no multiple choice, no theoretical questions. You either produce working exploits or you fail.

The certification proves that the holder operates at the level of a **professional exploit developer** --- the kind of person who discovers zero-day vulnerabilities, writes exploits for government agencies, works on red teams attacking the most hardened environments, or contributes to the offensive security research community.

---

## 2. History of the Certification

### Timeline

| Year | Event |
|------|-------|
| **2006** | Offensive Security founded by Mati Aharoni (muts) and others |
| **2007** | OSCP (Offensive Security Certified Professional) launched with PWK course |
| **2008-2009** | AWE (Advanced Windows Exploitation) course first developed and delivered at Black Hat |
| **~2012** | OSEE certification formalized as the credential earned upon passing the AWE final exam |
| **2012-2019** | AWE delivered exclusively as an in-person course at Black Hat USA (Las Vegas) and select live events |
| **2019** | OSCE (Offensive Security Certified Expert) retired (CTP course discontinued) |
| **2020** | COVID-19 forces transition --- OffSec begins adapting live training model |
| **2021** | OSCE3 introduced as replacement path for OSCE; AWE content updated |
| **2022** | AWE course rebranded to **EXP-401** under OffSec's new course numbering system |
| **2022-2023** | EXP-401 made available through OffSec's live training platform (no longer exclusively Black Hat) |
| **2024-2025** | EXP-401 continues as OffSec's most advanced course; content updated to cover modern Windows mitigations |

### Evolution of the Course Content

The AWE/EXP-401 course has evolved significantly over the years to keep pace with Windows security improvements:

**Early Era (2009-2014):**
- Focus on classic Windows exploitation techniques
- DEP bypass via ROP (Return-Oriented Programming)
- ASLR bypass techniques
- Kernel pool exploitation (Windows 7 era)
- Custom shellcode development
- Browser exploitation fundamentals

**Middle Era (2015-2019):**
- Updated to cover Windows 8.1/10 mitigations
- Introduction of more advanced kernel exploitation
- Enhanced focus on bypassing modern mitigations
- Exploit chain development
- Sandbox escape techniques

**Modern Era (2020-Present, as EXP-401):**
- Windows 10/11 kernel exploitation
- Bypassing CFG (Control Flow Guard)
- Bypassing ACG (Arbitrary Code Guard)
- Modern kernel pool exploitation (segment heap, etc.)
- VMware/Hyper-V aware exploitation considerations
- Advanced type confusion and use-after-free exploitation
- Modern edge cases in Windows memory management

### The Black Hat Connection

For many years, AWE was **exclusively offered as a 4-day course at Black Hat USA** in Las Vegas. This created an artificial scarcity and an aura of exclusivity:

- The course was typically offered once per year
- Class sizes were limited (often 20-40 students per session)
- It sold out rapidly, sometimes within hours of registration opening
- The cost was significant: Black Hat training registration plus travel/accommodation
- Students had to already possess strong exploitation skills just to keep up with the material

This delivery model meant that even *attempting* the OSEE was a significant logistical and financial commitment, further contributing to its rarity.

---

## 3. The Associated Course: AWE / EXP-401

### Course Details

| Attribute | Detail |
|-----------|--------|
| **Original Name** | AWE - Advanced Windows Exploitation |
| **Current Name** | EXP-401: Advanced Windows Exploitation |
| **Duration** | 4 days (live/instructor-led) + additional lab time |
| **Delivery** | Originally in-person only (Black Hat); now also via OffSec Live |
| **Prerequisites** | Strong exploitation background; OSCP and OSCE/OSCE3 strongly recommended |
| **Exam Duration** | 72 hours (proctored) |
| **Exam Format** | 100% practical --- develop working exploits against live targets |
| **Certification Earned** | OSEE (Offensive Security Exploitation Expert) |

### Course Syllabus (EXP-401)

The EXP-401 course covers the following major areas:

1. **Custom Shellcode Development**
   - Writing position-independent shellcode
   - Egghunters and staged payloads for constrained spaces
   - Encoding and evasion techniques

2. **DEP Bypass and Advanced ROP**
   - Return-Oriented Programming on modern Windows
   - Chaining ROP gadgets across modules
   - Dealing with limited gadget availability

3. **ASLR Bypass Techniques**
   - Information disclosure vulnerabilities
   - Partial overwrite techniques
   - Heap spray and other memory layout manipulation

4. **Kernel Exploitation**
   - Windows kernel architecture and internals
   - Kernel pool internals and exploitation
   - Arbitrary read/write primitives
   - Token stealing and privilege escalation
   - Driver vulnerability analysis

5. **Advanced Mitigation Bypass**
   - Control Flow Guard (CFG) bypass
   - Supervisor Mode Execution Prevention (SMEP) bypass
   - Kernel ASLR (KASLR) bypass
   - Additional Windows 10/11 hardening bypass

6. **Browser/Application Exploitation**
   - Type confusion vulnerabilities
   - Use-after-free exploitation
   - Sandbox analysis and escape
   - Multi-stage exploit chains

### Exam Structure

The OSEE exam is widely regarded as the **most difficult practical exam** in the cybersecurity certification world:

- **72 continuous hours** (3 full days) to complete the challenges
- Candidates must exploit multiple targets with increasing difficulty
- Each target requires developing a **working, reliable exploit**
- Partial credit is limited --- exploits must work
- A comprehensive professional report must be submitted after the exam
- The report must document the full exploitation methodology

---

## 4. OSEE in OffSec's Certification Hierarchy

### The Traditional Path (Pre-2020)

The original OffSec certification progression was linear and clear:

```
OSCP (Certified Professional)
  |
  v
OSCE (Certified Expert)
  |
  v
OSEE (Exploitation Expert)  <-- Pinnacle
```

- **OSCP (PWK/PEN-200):** Entry-level penetration testing. Network enumeration, basic exploitation, privilege escalation, Active Directory attacks. 24-hour exam.
- **OSCE (CTP):** Intermediate exploitation. Custom exploit development, AV evasion, network attacks, basic Windows exploitation. 48-hour exam.
- **OSEE (AWE/EXP-401):** Expert-level exploitation. Advanced Windows kernel exploitation, modern mitigation bypass, custom shellcode. 72-hour exam.

Each step represented a significant jump in difficulty and specialization.

### The Modern Path (2020-Present)

OffSec restructured its certification offerings with a new course numbering system and multiple specialized tracks:

```
                        PEN-200 (OSCP)
                       /       |       \
                      /        |        \
              PEN-300      WEB-300      EXP-301
              (OSEP)       (OSWE)      (OSED)
                 \           |          /
                  \          |         /
                   +----OSCE3----+
                         |
                         v
                    EXP-401 (OSEE)  <-- Pinnacle
```

**The 200-Level (Foundation):**
- PEN-200 (OSCP) --- Penetration Testing with Kali Linux
- SOC-200 (OSDA) --- Security Operations and Defensive Analysis
- WEB-200 (OSWA) --- Web Application Assessment

**The 300-Level (Advanced):**
- PEN-300 (OSEP) --- Evasion Techniques and Breaching Defenses
- WEB-300 (OSWE) --- Advanced Web Attacks and Exploitation
- EXP-301 (OSED) --- Windows User Mode Exploit Development

**The 400-Level (Expert):**
- EXP-401 (OSEE) --- Advanced Windows Exploitation (the apex)

### Where OSEE Sits

OSEE stands **alone at the top** of the OffSec hierarchy. It is the only 400-level certification, meaning OffSec themselves categorize it as a tier above everything else. There is nothing after OSEE --- it is the terminal certification in the OffSec ecosystem.

---

## 5. The OSCE to OSCE3 Transition

### The Original OSCE

The **OSCE (Offensive Security Certified Expert)** was earned by completing the **CTP (Cracking the Perimeter)** course. CTP covered:

- Custom exploit development (basic buffer overflows with mitigations)
- Antivirus evasion and backdooring
- Network-level attacks
- Web application attacks (advanced)
- 0-day research methodology

OSCE served as the **bridge between OSCP and OSEE**, providing the intermediate exploitation skills needed to attempt AWE.

### Why OSCE Was Retired

By 2019-2020, the CTP course content had become **dated**. Many of the techniques covered were no longer relevant against modern systems:

- The exploit development content focused on older Windows versions
- AV evasion techniques had been overtaken by modern EDR
- The course hadn't kept pace with the rapid evolution of defenses

Rather than update a single monolithic course, OffSec chose to **split the OSCE-level content into three specialized courses**.

### OSCE3: The Replacement

**OSCE3** is earned by passing **all three** 300-level exams:

1. **PEN-300 (OSEP)** --- Advanced penetration testing, evasion, Active Directory
2. **WEB-300 (OSWE)** --- Advanced web application exploitation (source code review, custom exploits)
3. **EXP-301 (OSED)** --- Windows user-mode exploit development (ROP, SEH, egghunters, format strings)

OSCE3 represents a **broader and more current** skill set than the original OSCE.

### How OSEE Relates to OSCE3

- OSCE3 is the **recommended prerequisite** for attempting OSEE/EXP-401
- **EXP-301 (OSED)** in particular provides the foundation for EXP-401:
  - OSED covers user-mode exploitation
  - OSEE builds on this with kernel-mode and advanced bypass techniques
- The progression is now: OSED (user-mode) -> OSEE (kernel-mode + advanced)
- OSCE3 ensures breadth; OSEE ensures extreme depth in exploitation
- Having OSCE3 + OSEE represents the absolute peak of OffSec credentialing

### Transition Notes for Legacy OSCE Holders

- The original OSCE certification **remains valid** --- it was not revoked
- Legacy OSCE holders are not automatically granted OSCE3
- Many legacy OSCE holders pursued OSCE3 and/or OSEE independently
- The industry generally recognizes both, though OSCE3 is the current standard

---

## 6. Why OSEE Is Considered the Pinnacle

### Technical Difficulty

OSEE is considered the most elite OffSec certification for several compounding reasons:

1. **Depth of Knowledge Required:**
   - Candidates must understand Windows internals at a level comparable to Microsoft kernel developers
   - Both user-mode and kernel-mode exploitation must be mastered
   - Understanding of CPU architecture, memory management, and OS design is essential

2. **The Exam Is Brutally Difficult:**
   - 72 hours is the longest OffSec exam (OSCP is 24h, OSCE3 exams are 48h each)
   - Even with 72 hours, many candidates run out of time
   - The targets have modern protections enabled --- no "easy mode"
   - Pass rates are rumored to be very low (OffSec does not publish official statistics)

3. **Prerequisites Are Already Elite:**
   - To even register for EXP-401, you should already be an accomplished exploit developer
   - Most successful candidates hold OSCP + OSCE/OSCE3 or equivalent real-world experience
   - The course material assumes significant prior knowledge

### Scarcity and Exclusivity

- **Limited delivery:** Historically one offering per year at Black Hat
- **Small class sizes:** 20-40 students per session
- **High cost:** Black Hat training fees + travel + the exam fee
- **High failure rate:** Many students who take the course never pass the exam
- **Time investment:** Months of preparation beyond the course itself

### Industry Recognition

- OSEE holders are actively recruited for the most elite positions:
  - Government vulnerability research teams
  - Zero-day exploit development firms
  - Top-tier red team operations
  - Security product development (offensive tools)
  - Bug bounty hunting at the highest levels
- OSEE is often listed alongside PhDs and decades of experience in job requirements for senior exploit development roles
- It is recognized globally as a marker of elite offensive capability

### Comparison to Other Elite Certifications

| Certification | Focus | Difficulty | Exam Type |
|--------------|-------|-----------|-----------|
| **OSEE** | Windows exploitation (kernel + user) | Extreme | 72h practical |
| **OSCE3** | Broad advanced offensive security | Very High | Three 48h practicals |
| **GXPN (SANS)** | Exploit development & advanced pen testing | High | Proctored multiple-choice + practical |
| **CCSAS** | CREST certified simulated attack specialist | High | Practical |
| **OSCP** | General penetration testing | Moderate-High | 24h practical |

OSEE stands distinctly above the rest due to its laser focus on exploitation, practical-only format, and extreme difficulty.

---

## 7. Number of Certified Professionals Globally

### Rarity

OffSec does not publish official counts of certified individuals, but the OSEE is widely acknowledged as one of the **rarest cybersecurity certifications in existence**. Estimates and indicators:

- **Estimated total OSEE holders worldwide: ~200-500** (as of 2025, based on community tracking and LinkedIn data)
- By comparison, OSCP holders number in the **tens of thousands** (likely 100,000+)
- OSCE holders (legacy) are estimated in the low thousands
- OSCE3 holders are estimated at a few thousand

### Why So Few?

The small number is a function of multiple bottleneck factors:

1. **Limited course availability:** For over a decade, only ~20-40 students per year could even take the course
2. **High failure rate on the exam:** Not all students who take the course pass
3. **Prerequisites filter:** The required skill level eliminates most professionals before they even attempt it
4. **Time and cost:** The total investment (preparation + course + exam + potential retakes) is substantial
5. **Niche specialization:** Most security professionals don't need or pursue this level of exploitation expertise

### Verification

- OSEE holders can be partially verified through:
  - OffSec's certification directory (if the holder opts in)
  - LinkedIn certifications (self-reported but generally reliable for this tier)
  - Conference speaker bios and published research
  - Professional community recognition

---

## 8. Notable Figures and Researchers Who Hold OSEE

### Caveats

- Not all OSEE holders publicly disclose their certification status
- Many work in classified or sensitive roles and maintain low profiles
- The list below represents publicly known holders based on conference talks, blog posts, social media, and professional profiles
- This is not exhaustive --- many accomplished OSEE holders are not publicly visible

### The Course Creators and Instructors

- **Mati Aharoni (muts):** Co-founder of Offensive Security and creator of the original OffSec training methodology. While not exclusively an OSEE instructor, he shaped the entire certification ecosystem.
- **Offensive Security Core Instructors:** The AWE/EXP-401 course has been taught by a small group of elite instructors over the years. These individuals are among the world's top exploitation experts. Past instructors have included researchers with backgrounds in zero-day discovery and advanced exploit development.

### Notable Community Members

Several well-known security researchers and professionals have publicly confirmed holding OSEE or have been identified through conference appearances and professional profiles:

- **Exploit developers at major security firms:** Researchers at companies like Exodus Intelligence, ZDI (Zero Day Initiative), and similar vulnerability research organizations
- **Government security researchers:** Personnel at agencies and national labs focused on offensive cyber capabilities
- **Red team leaders:** Senior members of elite red teams at Fortune 500 companies and defense contractors
- **Conference speakers:** Presenters at Black Hat, DEF CON, OffensiveCon, and similar top-tier conferences who reference their OSEE in speaker bios
- **Bug bounty researchers:** Top-tier bug bounty hunters who specialize in memory corruption and browser exploitation

### Community Observations

- OSEE holders tend to be concentrated in a few sectors:
  - Vulnerability research firms
  - Government/intelligence agencies (US, UK, Israel, Australia, etc.)
  - Major tech company security teams (Microsoft, Google, Apple, etc.)
  - Defense and aerospace contractors
  - Boutique offensive security consultancies
- Many OSEE holders go on to discover CVEs, present original research, and contribute to the advancement of exploitation techniques
- The OSEE community, while small, is tightly knit and mutually recognized

---

## Summary

The OSEE (Offensive Security Exploitation Expert) stands as the **most prestigious and difficult certification** in the Offensive Security portfolio and arguably in the entire cybersecurity certification landscape. Earned by completing the EXP-401 (formerly AWE) course and passing a grueling 72-hour practical exam, OSEE certifies that its holder can develop reliable exploits against modern, hardened Windows systems --- including kernel-level exploitation and advanced mitigation bypass.

With an estimated few hundred holders worldwide, OSEE is extraordinarily rare. Its position at the apex of the OffSec hierarchy (above OSCP at the 200-level and OSCE3 at the 300-level) reflects both its extreme technical demands and its recognition within the industry as a true marker of elite exploitation capability.

For anyone pursuing the deepest levels of offensive security expertise, OSEE remains the definitive goal and the ultimate professional credential.

---

*Document prepared as part of the OSEE certification research project.*
*Last updated: 2025*
