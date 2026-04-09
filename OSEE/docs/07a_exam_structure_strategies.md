# OSEE Exam Structure, Format, and Strategies for Success

## Table of Contents

1. [Exam Overview](#1-exam-overview)
2. [Exam Format and Scoring](#2-exam-format-and-scoring)
3. [Exam Environment](#3-exam-environment)
4. [Proctoring Requirements](#4-proctoring-requirements)
5. [Types of Challenges Expected](#5-types-of-challenges-expected)
6. [Report Requirements](#6-report-requirements)
7. [What Is and Is Not Allowed](#7-what-is-and-is-not-allowed)
8. [Success Strategies](#8-success-strategies)
9. [Retry Policies and Logistics](#9-retry-policies-and-logistics)
10. [OSEE vs Other OffSec Exams](#10-osee-vs-other-offsec-exams)

---

## 1. Exam Overview

The OffSec Exploitation Expert (OSEE) certification exam is the culmination of the EXP-401: Advanced Windows Exploitation course. It is widely recognized as the most difficult certification exam offered by Offensive Security (OffSec) and arguably one of the hardest in the entire cybersecurity industry.

**Key facts at a glance:**

| Attribute | Detail |
|---|---|
| **Course** | EXP-401: Advanced Windows Exploitation |
| **Certification** | OSEE (OffSec Exploitation Expert) |
| **Exam Duration** | 71 hours and 45 minutes |
| **Report Submission Window** | 24 hours after exam ends |
| **Total Time Investment** | ~96 hours (exam + report) |
| **Number of Assignments** | 2 |
| **Maximum Points** | 100 |
| **Passing Score** | 75 points |
| **Proctored** | Yes, fully proctored for entire duration |
| **Delivery** | Remote, via VPN to dedicated exam lab |
| **Results Timeline** | Within 10 business days |

The OSEE exam is fundamentally different from other OffSec exams. Rather than exploiting known vulnerabilities or using existing tools, candidates must discover unknown vulnerabilities in real-world enterprise software and develop custom, reliable exploits from scratch. The exam tests the ability to think laterally, adapt to new challenges, and apply advanced exploitation techniques under time pressure.

### Who Should Attempt the OSEE

The OSEE is designed for experienced penetration testers who:

- Have significant experience developing Windows exploits
- Are proficient with debuggers (particularly WinDbg)
- Understand x86_64 assembly language
- Have working knowledge of IDA Pro (or equivalent disassemblers)
- Can write C/C++ code for exploit development
- Have completed (or have equivalent knowledge to) OffSec's 300-level certifications (OSED, OSEP, OSWE)
- Understand modern Windows exploitation mitigations at a deep level

---

## 2. Exam Format and Scoring

### Duration

- **Exam time:** 71 hours and 45 minutes from the scheduled start time
- **Example:** If your exam begins at 09:00 GMT, it ends at 08:45 GMT three days later
- **Report submission:** An additional 24 hours after exam completion to upload documentation
- **Total commitment:** Approximately 4 full days from start to report submission

The 15-minute reduction from a full 72 hours accounts for the pre-exam onboarding process with the proctor.

### Assignments and Scoring

The OSEE exam contains **two (2) assignments**. Points are awarded for partial or full completion:

| Completion Level | Points per Assignment |
|---|---|
| Partial completion | 25 points |
| Full completion | 50 points |

| Scoring Scenario | Total Points | Result |
|---|---|---|
| Both assignments fully completed | 100 | PASS |
| One full + one partial | 75 | PASS (minimum) |
| Both assignments partially completed | 50 | FAIL |
| One full + zero on the other | 50 | FAIL |
| One partial + zero on the other | 25 | FAIL |

**To pass the exam, you need a minimum of 75 points.** This means you must achieve at least:
- Full completion of both assignments (100 points), OR
- Full completion of one assignment + partial completion of the other (75 points)

### What Constitutes "Partial" vs "Full" Completion

While OffSec does not publish exact criteria for partial vs full completion, based on the exam guide and the nature of the course material:

- **Partial completion (25 points):** Typically involves demonstrating a significant step in the exploitation chain, such as achieving an initial crash, demonstrating a vulnerability trigger, achieving information leakage, bypassing some (but not all) mitigations, or gaining limited code execution without full reliability
- **Full completion (50 points):** Requires a complete, reliable exploit that achieves full compromise (Administrator-level access) with a `proof.txt` file retrieved from the Administrator's desktop, along with working exploit code that OffSec's graders can reproduce

### Proof of Exploitation

- Each target machine has a `proof.txt` file located in the **Administrator's desktop directory**
- You must retrieve the contents of these files and include them in your documentation
- Your exploit code must be **reliable and reproducible** -- OffSec's grading team will replicate your steps

---

## 3. Exam Environment

### VPN Connectivity

The exam lab is accessed via OpenVPN from a Kali Linux machine:

1. You receive an `exam-connection.tar.bz2` file via email
2. Extract the archive: `tar jxpf exam-connection.tar.bz2`
3. Connect using OpenVPN: `sudo openvpn OS-XXXXX-OSEE.ovpn`
4. Authenticate with the credentials provided in your challenge email

**Important connectivity notes:**
- OffSec provides VPN connectivity support **only for Kali Linux**
- You may use any OS that supports OpenVPN, but you are on your own for troubleshooting
- The exam lab is a **dedicated environment** with no other learners connected
- If you disconnect from the proctoring session, your VPN will be paused until you reconnect
- You have a **backup plan obligation** -- OffSec expects you to have contingency plans for internet, power, and VM failures

### Target Machines

- Targets are accessible over the OSEE Exam Labs via **Remote Desktop (RDP)**
- You will connect to machines to debug vulnerable software remotely
- Target machines run Windows operating systems with various security mitigations enabled
- The specific vulnerable applications are **unknown beforehand** -- they are custom targets not seen during training

### Student Control Panel

- A web-based control panel allows you to manage exam machines
- You can **revert machines** to their original state (maximum **50 reverts** total across the exam)
- Reverting erases all changes you have made to the machine
- Wait patiently for reverts -- only click the button once per attempt
- Access details are provided in the challenge email

### Tools and Software

Based on the course material and exam environment:

**Debuggers:**
- WinDbg (primary debugger used in EXP-401)
- Potentially other debuggers available on target machines

**Disassemblers/Reverse Engineering:**
- IDA Pro (recommended proficiency before the exam)
- Any tools you bring on your own Kali VM

**Development:**
- C/C++ compiler toolchains
- Python (for exploit scripting)
- Visual Studio (on Windows targets for compilation)

**Other:**
- Standard Kali Linux tools
- Any personally developed scripts and tools
- Course materials and personal notes (physical or digital)

---

## 4. Proctoring Requirements

All OSEE exams are fully proctored for the entire 71 hours and 45 minutes. Proctors are full-time OffSec employees who have undergone background checks and signed NDAs.

### Pre-Exam Setup (Log in 15 minutes early)

1. **Log in** to the proctoring tool at `proctoring.offsec.com/student/login`
2. **Allow permissions:** Camera access, screen sharing, and notifications
3. **Identity verification:** Present a valid, government-issued, English-language photo ID showing:
   - Full legal name (must match student profile)
   - Photograph
   - Year of birth
   - Country of issuance
   - Issue/expiration dates
   - Both front and back of ID, or fully opened passport
4. **Run verification script:** Windows script (PowerShell) or macOS script, depending on your host OS
5. **Room scan:** Show your room and surroundings via webcam
6. **Screen sharing:** Share all screens and display all running programs
7. **VPN connection:** Connect to the exam VPN; proctor confirms you are only connected to the exam VPN

### During the Exam

- **Webcam must remain on at all times**, correctly positioned to show your face, at least half your body, and surrounding environment
- **Up to 4 monitors/screens** are allowed (all must be shared)
- Communication with the proctor is via the **built-in chat client only** (no audio)
- Proctors **cannot hear you** and you **cannot see or hear them**
- A proctor is assigned for the **full duration** -- proctors rotate but do not announce transitions
- The proctoring session is **recorded**

### Breaks and Sleep

- You are **encouraged** to take breaks, eat, drink, and sleep
- Notify the proctor via chat before leaving and when returning (no need to wait for acknowledgment)
- **Leave the proctoring session active** while on break to keep VPN running
- If you disconnect during a break, VPN pauses until you reconnect
- You may **pause your webcam** using the proctoring tool's "PAUSE WEBCAM" function for breaks
- Resume webcam when you return
- You can **change physical locations** during the exam (inform proctor; VPN pauses; room scan at new location)

### Technical Requirements for Host Machine

| Requirement | Specification |
|---|---|
| CPU | 64-bit Dual Core, 2.2 GHz minimum |
| RAM | 8 GB minimum (16 GB recommended for VMs) |
| Display | 1024x768 minimum |
| Storage | 20 GB free minimum |
| Webcam | External or integrated (must render ID text legible) |
| Browser | Chrome, Firefox, Brave, Edge, or Chromium |
| Internet | 20 Mbps down / 10 Mbps up minimum, stable |
| Host OS | Windows 8.1+ / macOS Yosemite+ / Kali 2017+ / Debian 9.3+ / Ubuntu 17.10+ |
| GUI (Linux) | Xorg/X11 (Wayland not supported for screen sharing) |
| VM Software | VMware Workstation/Player/Fusion (run VMs locally) |

### Grace Period

You have a **1-hour grace period** from your scheduled start time to log in. If you fail to log in within that hour, your exam is automatically canceled.

---

## 5. Types of Challenges Expected

### Overview of Challenge Categories

The OSEE exam challenges are derived from the EXP-401 course topics. While exact exam content is confidential, the following areas are tested based on the course syllabus and official descriptions:

### 5.1 User Mode Security Mitigation Bypasses

Candidates should expect to bypass modern Windows exploit mitigations including:

- **DEP (Data Execution Prevention):** Return-Oriented Programming (ROP) chains and other DEP bypass techniques
- **ASLR (Address Space Layout Randomization):** Information leak discovery and exploitation to defeat ASLR
- **CFG (Control Flow Guard):** Techniques to bypass Microsoft's forward-edge control-flow integrity
- **ACG (Arbitrary Code Guard):** Bypass techniques for code generation restrictions
- **CIG (Code Integrity Guard):** Working around restrictions on loaded modules
- **Sandbox escapes:** Breaking out of application sandboxes (e.g., browser sandboxes)

### 5.2 Advanced Heap Manipulation

The EXP-401 course dedicates significant time to heap exploitation:

- **Windows heap internals:** Understanding the Windows heap allocator (NT Heap, Segment Heap)
- **Heap grooming/feng shui:** Precise manipulation of heap layout to achieve reliable exploitation
- **Use-after-free exploitation:** Triggering and leveraging UAF conditions
- **Type confusion vulnerabilities:** Understanding and exploiting type confusion in complex applications
- **Heap-based information leaks:** Leveraging heap metadata or object layouts for ASLR bypass

### 5.3 64-bit Kernel Exploitation

Kernel exploitation is a major component of EXP-401:

- **Kernel driver vulnerability discovery:** Finding bugs in kernel-mode code
- **SMEP (Supervisor Mode Execution Prevention) bypass:** Techniques to execute user-mode code from kernel context
- **SMEP/SMAP bypass via ROP:** Building kernel-mode ROP chains
- **Token stealing:** Escalating privileges by manipulating process tokens
- **Kernel ASLR bypass:** Defeating KASLR through information leaks
- **WDEG (Windows Defender Exploit Guard) bypasses:** Disarming kernel mitigations
- **Version independence:** Creating exploits that work across Windows versions

### 5.4 Multi-Step Exploitation Chains

Exam challenges are not single-step exploits. Expect:

- **Vulnerability chaining:** Combining multiple vulnerabilities (e.g., info leak + memory corruption + privilege escalation)
- **Multiple mitigation bypasses in sequence:** Each step of the chain may require defeating different mitigations
- **Reliability requirements:** Exploits must work consistently, not just as a one-off proof of concept
- **Complex application targets:** Real-world enterprise software with significant code complexity

### 5.5 Vulnerability Research Component

Unlike most OffSec exams where vulnerabilities are pre-identified:

- You may need to **discover** the vulnerability yourself through reverse engineering and debugging
- This involves analyzing the target application's code paths, input handling, and memory management
- The ability to use WinDbg and IDA Pro effectively for root-cause analysis is essential

### What Makes OSEE Challenges Unique

The distinguishing characteristics vs other OffSec exam challenges:

1. **Discovery over exploitation:** You are finding 0-day-like vulnerabilities, not using known CVEs
2. **Custom exploit development:** No Metasploit modules or pre-built tools will help
3. **Mitigation stacking:** Multiple modern mitigations are active simultaneously
4. **Reliability mandate:** Exploits must be reliable and reproducible by graders
5. **Application complexity:** Targets are large, real-world enterprise applications
6. **Depth over breadth:** Two deep challenges vs many shallow ones

---

## 6. Report Requirements

The report is a critical component of the OSEE exam. Inadequate documentation can result in point deductions or failure even if exploitation was achieved.

### Documentation Standards

From the official exam guide (emphasis in original):

> "The documentation requirements are very strict and failure to provide sufficient documentation will result in reduced or zero points being awarded. Please note that once your exam and lab report is submitted, your submission is final. If any screenshots or other information is missing, you will not be allowed to send them and we will not request them."

### Report Template

OffSec provides an official report template:
- **Download:** `https://offsec.com/awe/AWE-Exam-Report.docx`
- Using this template is strongly recommended

### Report Content Requirements

Your report must include:

1. **All steps taken** during exploitation, in logical order
2. **All commands issued** with complete syntax
3. **Console/debugger output** showing results of each step
4. **Screenshots** at every significant stage:
   - Vulnerability discovery and analysis
   - Debugger state showing crash/corruption
   - Each mitigation bypass technique
   - Memory layouts and heap states
   - Successful code execution
   - Privilege escalation
   - `proof.txt` file contents (shown in context)
5. **Complete exploit source code** included as text within the PDF
6. **Explanation of methodology:** Why each technique was chosen and how it works
7. **Any scripts or proof-of-concept code** as text inside the report

### Report Format and Submission

| Requirement | Detail |
|---|---|
| **Format** | PDF only |
| **Filename** | `OSEE-OS-XXXXX-Exam-Report.pdf` (case sensitive) |
| **Archive** | `.7z` format, **no password** |
| **Archive filename** | `OSEE-OS-XXXXX-Exam-Report.7z` (case sensitive) |
| **Archive max size** | 300 MB |
| **Extracted max size** | 400 MB |
| **Submission URL** | `https://upload.offsec.com` |
| **Submission deadline** | 24 hours after exam ends |
| **Verification** | MD5 hash verification after upload |
| **Confirmation** | Confirmation email sent upon successful upload |
| **Contents** | Only PDF files accepted within the .7z archive |
| **Code inclusion** | All scripts/PoCs must be included as text inside the PDF |

### Post-Upload Verification

1. After uploading, the site displays the MD5 hash of your uploaded file
2. Compare with your local file: `md5sum OSEE-OS-XXXXX-Exam-Report.7z`
3. If hashes do not match, re-upload using "Select a new file"
4. Click "Submit File" button after verifying the hash
5. A confirmation email is sent immediately upon successful submission

### Common Report Mistakes That Lead to Failure

Based on community experience and official guidance:

1. **Insufficient screenshots:** Not capturing every critical step. Take screenshots obsessively -- you cannot go back to add them after the exam ends.

2. **Missing debugger output:** Failing to show WinDbg/debugger state at key moments (register states, memory contents, stack traces).

3. **Incomplete reproduction steps:** The report must be detailed enough that OffSec graders can replicate your attack step-by-step. If any step is ambiguous or missing, points may not be awarded.

4. **Unreliable exploits:** Submitting exploit code that works intermittently. Graders will test your exploits, and they must work reliably.

5. **Missing proof.txt:** Forgetting to include or clearly show the contents of `proof.txt` from the Administrator's desktop.

6. **Code not included in PDF:** Submitting exploit code as separate files. All code must be embedded as text within the PDF itself.

7. **Wrong filename format:** Using incorrect case or format for the PDF or .7z file. The upload system enforces exact filename matching.

8. **Password-protected archives:** The system rejects password-protected .7z files.

9. **Exceeding size limits:** Not compressing screenshots or using excessively large images.

10. **Submitting after the deadline:** The 24-hour report window is strict. There are no extensions.

11. **Not clicking "Submit File":** Uploading without clicking the final submission button means your report is not submitted.

12. **Formatting errors in PDF conversion:** Not reviewing the final PDF to ensure formatting, screenshots, and code blocks survived the export process.

---

## 7. What Is and Is Not Allowed

### Permitted

- Kali Linux (primary supported OS) or any OS supporting OpenVPN
- Up to 4 monitors/screens (all shared with proctor)
- Physical printed books, notes, paper, and pen
- Digital notes on your host machine
- Personal scripts and tools
- Course materials (physical book from class, slides, class code)
- Internet access for research
- Discord for **searching information only** (not for soliciting help)
- VMware Workstation/Player/Fusion (VMs run locally)
- Taking breaks, sleeping, eating, and changing locations

### Prohibited

- **Receiving assistance from others** -- no collaboration, chat help, or solicitation on any platform
- **Electronic devices** other than the host machine and shared screens (phones must be away from desk)
- **Headphones/earphones/earpods** (exception: documented hearing disability with prior approval)
- **Screen recording** of any kind while connected to exam machines
- **Other machines** besides your host (if you need to attend to work, take a break and use a separate machine away from the exam workstation)
- **Calls or meetings** on the exam machine
- **Sharing exam content** with anyone at any time
- **Taking the exam in the same room** as another exam candidate
- **Closing the proctoring tab/browser** (disconnects the session)
- **Disabling your laptop display** (even if using external monitors)

### Communication Channels During the Exam

| Purpose | Channel |
|---|---|
| VPN/connectivity issues | Live chat: `https://chat.offsec.com/` or `help@offsec.com` |
| Exam-related questions (non-technical) | `challenges@offsec.com` |
| Proctoring issues | Proctoring tool chat box |
| Hints or help with objectives | **Not available** -- OffSec will not assist with exam objectives |

### Special Note from the Exam Guide

> "While debugging in kernel mode remember to `.reload` symbols if you encounter issues in getting information about the drivers."

This hint from the official exam guide is notable -- it suggests that kernel-mode debugging is a component of the exam and that symbol loading issues are common enough to warrant mention.

---

## 8. Success Strategies

### 8.1 Time Management Across 72 Hours

The 72-hour (71:45) window is both a luxury and a trap. Proper time management is critical.

#### Recommended Time Allocation

```
Hours 0-2:    Environment setup, VPN, RDP, tool verification
Hours 2-8:    Initial reconnaissance of both assignments
              - Identify target applications
              - Set up debugging environments
              - Begin reverse engineering
              - Identify attack surfaces
Hours 8-12:   Deep dive into first assignment
              - Vulnerability discovery
              - Root cause analysis
              - Begin exploit development
Hour 12:      BREAK - meal and short rest (30-60 min)
Hours 13-24:  Continue exploit development on first assignment
              - Mitigation bypass development
              - Exploit stabilization
              - If stuck, switch to second assignment
Hour 24:      SLEEP - mandatory rest (4-6 hours)
Hours 28-30:  Review progress, adjust strategy
Hours 30-48:  Primary exploitation phase
              - Complete first assignment
              - Begin or continue second assignment
Hour 48:      SLEEP - second rest period (4-6 hours)
Hours 52-64:  Final exploitation push
              - Complete second assignment
              - Stabilize all exploits
              - Verify reliability
Hours 64-72:  Documentation and cleanup
              - Ensure all screenshots are captured
              - Verify proof.txt contents
              - Begin report if not already done
```

**Post-exam (next 24 hours):** Complete and submit the report.

#### Critical Time Rules

1. **Do not spend more than 6-8 hours on a single approach without progress.** If you are stuck, switch to the other assignment or take a break. Fresh eyes often see what tired eyes miss.

2. **Start documenting from hour zero.** Do not plan to "go back and document later." Screenshots disappear when machines revert, and memory fades under exhaustion.

3. **Budget at least 8 hours total for the report.** A complete, well-documented report with reliable exploits is what passes the exam. Many people fail not because they could not exploit the targets, but because their documentation was insufficient.

4. **Use your reverts wisely.** You have 50 total reverts. While that sounds generous, complex exploit development involving kernel debugging can consume reverts quickly, especially if targets crash or become unstable.

### 8.2 Sleep, Nutrition, and Breaks

This is a 3-day exam. Treating it like an endurance event without rest is a recipe for failure.

#### Sleep Strategy

- **Plan for two full sleep periods** of 4-6 hours each (around hours 24 and 48)
- Sleep deprivation severely impairs the cognitive function needed for exploit development
- The difference between "almost works" and "works reliably" is often found after sleep
- Set alarms -- do not oversleep beyond your planned rest period
- Inform the proctor via chat before sleeping; leave the proctoring session active

#### Nutrition

- Prepare meals and snacks **before the exam starts**
- Have water, coffee/tea, and high-protein snacks at your desk
- Avoid heavy meals that cause energy crashes
- Stay hydrated -- dehydration impairs concentration
- Eat meals during natural break points (when waiting for reverts, during compilation, etc.)

#### Break Strategy

- Take a **5-10 minute break every 2-3 hours** (stretch, walk, look away from screen)
- Take **longer breaks (30-60 min)** for meals, roughly every 8 hours
- If frustrated or stuck, a break is often more productive than grinding
- Physical movement helps reset mental state

### 8.3 Prioritization of Challenges

With only two assignments, prioritization is simpler but still critical:

1. **Spend the first 2-4 hours surveying both assignments.** Identify which one you feel more confident about based on the target application, vulnerability type, and mitigations present.

2. **Start with your stronger assignment.** Getting partial or full completion on one challenge builds confidence and secures points.

3. **Aim for at least partial completion on both** before deep-diving into full completion on either. Two partials (50 points) is not enough to pass, but having partial work on both gives you options.

4. **If stuck on one assignment, switch.** Context switching has a cost, but it is better than burning 8 hours making no progress.

5. **Remember the math:** You need 75 points. One full (50) + one partial (25) = pass. This means your secondary goal can be partial completion if you achieve full completion on your primary target.

### 8.4 Document-As-You-Go Approach

This cannot be overstated: **document everything in real time.**

#### Practical Documentation Workflow

1. **Set up a note-taking tool before the exam:** KeepNote, CherryTree, Obsidian, or even a plain text file. Have your template ready.

2. **Screenshot every significant step:**
   - Use keyboard shortcuts (e.g., `Alt+PrintScreen` for active window)
   - Include debugger state, register values, memory dumps
   - Capture the full command and its output
   - Screenshot the `proof.txt` contents with context showing the target machine

3. **Record all commands in a running log:**
   ```
   [timestamp] Command: <what you ran>
   [timestamp] Result: <what happened>
   [timestamp] Analysis: <what this means>
   ```

4. **Save exploit code iterations.** Use version numbers (`exploit_v1.py`, `exploit_v2.py`, etc.) so you can reference or revert to earlier versions.

5. **Write explanatory notes while your understanding is fresh.** "I used this offset because..." is much easier to write right after you figure it out than 24 hours later.

6. **Do not rely on machine state.** If you need to screenshot something on a target, do it NOW. The machine might crash or be reverted.

### 8.5 Mental Preparation and Stress Management

#### Before the Exam

- **Practice under time pressure.** Set up 24-48 hour personal challenges with exploit development targets.
- **Build exploit templates** for common patterns (heap sprays, ROP chain builders, info leak harnesses) so you are not writing boilerplate under pressure.
- **Review all course material** at least twice. The exam tests material beyond what is in the course, but the course provides the foundation.
- **Ensure your environment is ready.** Test your VPN setup, VM performance, debugger configurations, and compilation toolchains days before the exam.
- **Clear your calendar.** Inform family, friends, and work that you will be unavailable for 4 days.

#### During the Exam

- **Expect to get stuck.** Every OSEE candidate hits walls. This is normal and part of the exam design.
- **Avoid panic spirals.** When stuck, step back and re-read your notes. The solution is often in the details you already uncovered.
- **Talk to yourself (or write to yourself).** Rubber duck debugging is real. Writing out "Here is what I know, here is what I do not know" often reveals the path forward.
- **Do not compare yourself to others.** The only metric that matters is 75 points.
- **Celebrate small victories.** Each crash reproduced, each leak found, each bypass achieved is progress.

#### Common Psychological Pitfalls

| Pitfall | Mitigation |
|---|---|
| "I should have this by now" | The exam is designed to be hard. There is no expected timeline. |
| Tunnel vision on one approach | Set a timer. If no progress in 4-6 hours, try a different angle or switch assignments. |
| Exhaustion masquerading as inability | Sleep. The exploit will still be there when you wake up, and your brain will work better. |
| Documentation procrastination | Document now. You are trading 5 minutes of documenting for potentially failing due to missing evidence. |
| "It worked once, I will document later" | If it worked once, reproduce it and screenshot it NOW. Intermittent exploits are not reliable. |

### 8.6 Technical Preparation Checklist

Before starting the exam, ensure you have:

- [ ] Kali Linux VM fully updated and tested
- [ ] OpenVPN installed and working
- [ ] WinDbg configured and proficiency confirmed
- [ ] IDA Pro (or equivalent) installed and ready
- [ ] C/C++ compiler toolchain functional
- [ ] Python exploit development environment set up
- [ ] ROP gadget finding tools ready (e.g., rp++, ROPgadget)
- [ ] Heap analysis scripts and tools prepared
- [ ] Report template downloaded and customized with your OSID
- [ ] Note-taking tool configured
- [ ] Screenshot tool tested
- [ ] Backup internet connection available
- [ ] Backup power (UPS) if possible
- [ ] Food and drinks prepared
- [ ] Workspace clean and comfortable
- [ ] Webcam positioned correctly
- [ ] All screens tested for sharing
- [ ] Government-issued photo ID ready

---

## 9. Retry Policies and Logistics

### Exam Retakes

- If you fail, you can purchase an exam retake by submitting a request to OffSec support
- Cooling-off periods apply (though OffSec does not publicly specify OSEE-specific cooling periods, their general policy is):
  - After 1st attempt: 4 weeks
  - After 2nd attempt: 8 weeks
  - After 3rd attempt and beyond: 12 weeks

### Results Timeline

- Results are delivered via email within **10 business days** of report submission
- OffSec provides a pass/fail result only
- **No score breakdown** is provided
- **No solutions** to exam targets are provided
- No feedback on specific areas of weakness

### Scheduling and No-Shows

- Log in to the proctoring session **15 minutes before** scheduled start time
- **1-hour grace period** to log in; after that, the exam is automatically canceled
- If you cannot meet pre-exam requirements, the proctor may allow you to continue or require rescheduling
- Exams can be rescheduled up to **48 hours before** the start time

### Unforeseen Issues During the Exam

- OffSec acknowledges that life events happen during a 72-hour period
- You are expected to have contingency plans for internet, power, and hardware failures
- If you experience legitimate issues, email `challenges@offsec.com` with your OSID and all supporting documentation immediately
- Lab time extensions are only granted for issues **on OffSec's side** and only if the exam subnet is not immediately scheduled for another learner
- If OffSec-side issues occur and the subnet is scheduled, a **free retake** is provided

### Pass Rates

OffSec does not officially publish pass rates for any of their exams. However, based on community discussions and the number of OSEE holders relative to exam takers:

- The OSEE is widely considered to have the **lowest pass rate** of any OffSec certification
- The total number of OSEE holders worldwide is estimated to be in the **low hundreds** (compared to tens of thousands of OSCP holders)
- First-attempt pass rates are anecdotally estimated to be very low
- Many successful OSEE candidates report requiring multiple attempts
- The difficulty is compounded by the fact that EXP-401 is only available as in-person training, limiting the pool of candidates

---

## 10. OSEE vs Other OffSec Exams

| Attribute | OSEE (EXP-401) | OSED (EXP-301) | OSEP (PEN-300) | OSCP (PEN-200) |
|---|---|---|---|---|
| **Exam Duration** | 71h 45m | 47h 45m | 47h 45m | 23h 45m |
| **Report Window** | 24 hours | 24 hours | 24 hours | 24 hours |
| **Number of Targets** | 2 assignments | 3 assignments | Objective-based | Multiple machines |
| **Passing Score** | 75/100 | 70/100 | Objective completion | 70/100 |
| **Vulnerability Discovery** | Required | Partial | No | No |
| **Exploit Development** | Custom from scratch | Custom from scratch | Using existing + custom | Using existing tools |
| **Mitigation Bypasses** | Multiple modern | User-mode | Endpoint evasion | Basic |
| **Kernel Exploitation** | Yes (64-bit) | No | No | No |
| **Heap Exploitation** | Advanced | Basic | No | No |
| **Course Delivery** | In-person only | Online | Online | Online |
| **Difficulty Level** | 400 (highest) | 300 | 300 | 200 |
| **Prerequisites** | 300-level recommended | OSCP recommended | OSCP recommended | Foundational |

### Key Differentiators

1. **In-person training only:** EXP-401 is not available online. You must attend a live training event (typically at conferences or through authorized training partners). This creates a natural bottleneck on the number of exam candidates.

2. **Vulnerability discovery:** OSEE is the only OffSec exam where you may need to find the vulnerability yourself rather than exploiting a known issue.

3. **Exploit reliability:** While other exams accept "it works," OSEE demands reliable, reproducible exploits that graders will independently verify.

4. **Depth over breadth:** Two deep challenges vs. many shallow ones. There is nowhere to hide -- you cannot make up for a failed challenge with extra credit on easier targets.

5. **Kernel exploitation:** OSEE is the only OffSec certification that tests 64-bit Windows kernel exploitation.

6. **No online content:** Unlike every other OffSec course, EXP-401 has no online portal, no video content, and no online lab environment. Your materials are what you received during the in-person class.

---

## Appendix A: Official Resources

| Resource | URL |
|---|---|
| OSEE Exam Guide | https://help.offsec.com/hc/en-us/articles/360046458732 |
| EXP-401 FAQ | https://help.offsec.com/hc/en-us/articles/25190559024276 |
| Attending EXP-401 Live Training | https://help.offsec.com/hc/en-us/articles/36016533907860 |
| Proctoring Tool Manual | https://help.offsec.com/hc/en-us/articles/360050299352 |
| Proctored Exam Requirements | https://help.offsec.com/hc/en-us/articles/15295546432148 |
| General Proctoring FAQ | https://help.offsec.com/hc/en-us/articles/15299882976660 |
| Report Template | https://offsec.com/awe/AWE-Exam-Report.docx |
| EXP-401 Syllabus | https://www.offsec.com/awe/EXP401_syllabus.pdf |
| Upcoming Training Events | https://www.offsec.com/events/training/ |
| Exam Submission Portal | https://upload.offsec.com |
| Proctoring Login | https://proctoring.offsec.com/student/login |
| Live Chat (Technical Issues) | https://chat.offsec.com/ |

## Appendix B: Recommended Pre-Exam Reading

These readings are officially recommended by OffSec for EXP-401 preparation:

1. **DEP Bypass:** http://uninformed.org/?v=2&a=4
2. **Return-Oriented Programming:** http://cseweb.ucsd.edu/~hovav/dist/geometry.pdf
3. **ASLR Bypass:** BlackHat US 2012 - Serna "Leak Era" slides
4. **Sandboxing:** https://en.wikipedia.org/wiki/Sandbox_(computer_security)
5. **Windows 10 Mitigations:** BlackHat US 2016 - Weston "Windows 10 Mitigation Improvements"
6. **Microsoft Edge Mitigations:** Microsoft Edge Dev Blog - "Mitigating Arbitrary Native Code Execution"
7. **CFG Bypass:** Improsec - "Bypassing Control Flow Guard in Windows 10"
8. **JIT Attacks:** Google Project Zero - "Bypassing Mitigations by Attacking JIT"
9. **Type Confusion:** Microsoft Security Blog - CVE-2015-0336
10. **Kernel Exploitation:** http://www.uninformed.org/?v=3&a=4
11. **x64 Architecture:** Wikipedia x86-64; MSDN x64 Architecture documentation
12. **Virtual Memory:** UT Austin CS 372 - Virtual Memory and Address Translation
13. **Windows SMEP Bypass:** CoreSecurity - "Windows SMEP Bypass"

## Appendix C: Day-by-Day Exam Plan Template

### Day 0 (Pre-Exam)
- [ ] Confirm exam start time and convert to local timezone
- [ ] Test VPN connectivity setup
- [ ] Verify all tools are functional
- [ ] Prepare workspace, food, and drinks
- [ ] Get a full night's sleep
- [ ] Set up note-taking and screenshot tools
- [ ] Download and customize report template with your OSID

### Day 1 (Hours 0-24)
- [ ] Complete pre-exam check-in with proctor
- [ ] Connect VPN, verify access to all machines
- [ ] Survey both assignments (2-4 hours)
- [ ] Begin primary assignment exploitation
- [ ] Document all findings continuously
- [ ] Take meal breaks every 4-6 hours
- [ ] Sleep for 4-6 hours around hour 20-24

### Day 2 (Hours 24-48)
- [ ] Review Day 1 progress with fresh eyes
- [ ] Continue or adjust exploitation strategy
- [ ] Aim for full completion on primary assignment
- [ ] Begin secondary assignment in earnest
- [ ] Continue documenting
- [ ] Sleep for 4-6 hours around hour 44-48

### Day 3 (Hours 48-72)
- [ ] Final exploitation push on both assignments
- [ ] Stabilize and verify exploit reliability
- [ ] Run exploits multiple times to confirm reliability
- [ ] Capture any missing screenshots
- [ ] Retrieve and document all proof.txt files
- [ ] Begin finalizing report content
- [ ] End exam session when satisfied or time expires

### Post-Exam (24-hour report window)
- [ ] Compile report using official template
- [ ] Include all exploit code as text in PDF
- [ ] Review all screenshots for completeness
- [ ] Verify all commands are documented
- [ ] Export to PDF and review formatting
- [ ] Archive as .7z without password
- [ ] Verify filename: `OSEE-OS-XXXXX-Exam-Report.7z`
- [ ] Upload to https://upload.offsec.com
- [ ] Verify MD5 hash matches
- [ ] Click "Submit File" button
- [ ] Confirm receipt email received
- [ ] Rest -- you have earned it

---

*This document was compiled from official OffSec documentation, the OSEE Exam Guide, EXP-401 FAQ, Proctoring Tool Manual, Proctored Exam Requirements FAQ, and General Proctoring FAQ. Always refer to the official OffSec exam guide for the most current and authoritative information, as policies may change. Last updated: April 2026.*
