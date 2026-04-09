# OSEE Exam: Challenges, Pitfalls, and Lessons Learned

## A Practical Guide for EXP-401 / OSEE Candidates

> "The OSEE exam evaluates not only the course content but also the ability to think
> laterally and adapt to new challenges." -- OffSec

---

## Table of Contents

1. [Exam Overview and Format](#1-exam-overview-and-format)
2. [Common Failure Points](#2-common-failure-points)
3. [Lessons from OSEE Holders](#3-lessons-from-osee-holders)
4. [Mental and Physical Preparation](#4-mental-and-physical-preparation)
5. [Technical Preparation Checklist](#5-technical-preparation-checklist)
6. [Post-Exam Process](#6-post-exam-process)
7. [Final Words](#7-final-words)

---

## 1. Exam Overview and Format

Before discussing pitfalls and strategies, every candidate must internalize these facts
from the official exam guide:

| Attribute | Detail |
|---|---|
| **Duration** | 71 hours 45 minutes (approximately 72 hours) |
| **Report window** | Additional 24 hours after exam ends |
| **Assignments** | 2 target machines |
| **Scoring** | 25 points partial / 50 points full per assignment (100 total) |
| **Pass threshold** | 75 points |
| **Proctored** | Yes, continuously |
| **Connection** | VPN from Kali Linux (OpenVPN) |
| **Machine reverts** | 50 total reverts across the exam |
| **Proof** | `proof.txt` on Administrator's desktop |
| **Report format** | PDF in `.7z` archive, no password |
| **Results timeline** | Within 10 business days |

**Critical detail from the exam guide:** "Your exploits must be reliable and working
code must be provided as our team is going to repeat your steps in order to grade your
exam challenge." This means partial, flaky, or race-condition-dependent exploits without
proper documentation will not earn full credit.

---

## 2. Common Failure Points

### 2.1 Technical Mistakes That Lead to Failure

#### Not Understanding the Vulnerability Class Before Exploiting It

The OSEE exam presents **unknown vulnerabilities** in a controlled lab -- not the same
bugs from the course. Candidates who memorized course exploits without understanding the
underlying vulnerability classes (UAF, type confusion, pool overflow, integer overflow,
double-free) often fail because they cannot adapt when the target differs from what they
practiced.

**How to avoid it:**
- For every course case study, ask: "What is the root cause? How would I recognize this
  pattern in a different application?"
- Practice identifying vulnerability classes from crash analysis alone, before looking at
  source code or course notes.
- Build a mental flowchart: crash triage -> root cause analysis -> exploitation strategy.

#### Hardcoded Offsets and Non-Portable Exploits

A common exam failure pattern: the exploit works on the candidate's local VM but fails on
the exam target because offsets, structure sizes, or gadget addresses were hardcoded for a
specific patch level.

**How to avoid it:**
- Always resolve offsets dynamically at runtime when possible.
- Use symbol resolution (e.g., `GetProcAddress`, module base + offset calculation).
- Test your exploit framework against multiple Windows builds before the exam.
- The exam guide itself hints at this: "While debugging in kernel mode remember to
  `.reload` symbols if you encounter issues."

#### Incomplete Mitigation Bypass Chains

Modern Windows exploitation requires chaining multiple bypasses (ASLR + DEP + CFG + ACG +
SMEP + kASLR, etc.). Failing to account for even one mitigation in the chain collapses the
entire exploit.

**How to avoid it:**
- Maintain a checklist of active mitigations for each target.
- Use WinDbg to verify which mitigations are actually enforced:
  ```
  !process 0 0 target.exe
  .process /p /r <EPROCESS>
  !token
  dt nt!_EPROCESS <addr> MitigationFlags
  dt nt!_EPROCESS <addr> MitigationFlags2
  ```
- For kernel targets, verify SMEP/SMAP status in CR4 and check for kCFG.
- Document the complete bypass chain before writing exploit code.

#### Crashing the Target Repeatedly Without Root-Cause Analysis

Each crash costs time. With only 50 reverts available for the entire exam, wasting reverts
on blind fuzzing or trial-and-error exploitation is dangerous.

**How to avoid it:**
- Attach a debugger and analyze EVERY crash before trying again.
- Capture the full crash context: registers, stack, heap state, pool state.
- Form a hypothesis before each exploitation attempt.
- Track your reverts -- you have 50 total, not 50 per machine.

#### Ignoring Heap/Pool State

For user-mode heap exploits or kernel pool exploits, the initial state of the allocator is
critical. Candidates often skip heap grooming/pool grooming, leading to unreliable
exploitation.

**How to avoid it:**
- Spend time understanding the allocator state before exploitation.
- For kernel pool: know the segment heap vs. classic pool differences across Windows
  versions, understand pool chunk headers, and practice deterministic grooming.
- For user-mode heap: understand LFH bucket activation, chunk coalescing, and the
  differences between NT heap, segment heap, and the front-end allocator.

### 2.2 Time Management Failures

The 72-hour exam is a marathon, not a sprint. Time management is the second most common
reason for failure after technical gaps.

#### The First 24 Hours: Analysis Paralysis vs. Rushing

**Failure pattern:** Spending too long on reconnaissance and never starting exploitation.
**Opposite failure pattern:** Jumping into exploitation without understanding the target.

**Balanced approach:**
```
Hours 0-4:   Reconnaissance and target enumeration
             - Identify the software, version, and running services
             - Check enabled mitigations (WDEG, ASLR, DEP, CFG, SMEP)
             - Set up debugging (attach WinDbg, load symbols)
             
Hours 4-8:   Vulnerability discovery and crash triage
             - If a crash is provided, analyze root cause
             - If discovery is required, use structured approach
             - Identify the vulnerability class
             
Hours 8-24:  Exploitation development for first target
             - Design the bypass chain
             - Build primitives (read, write, code execution)
             - Test iteratively
```

#### Not Time-Boxing Rabbit Holes

**The single most dangerous time sink in the OSEE exam is a rabbit hole.** You can lose
8-12 hours chasing a dead-end exploitation path.

**Rules of thumb:**
- If you have been stuck on the same specific sub-problem for 3+ hours with zero
  progress, deliberately stop and reassess.
- Write down what you know, what you do not know, and what assumptions you are making.
- Consider whether you are fighting the wrong vulnerability, using the wrong primitive,
  or missing a simpler path.
- Switch to the other assignment if you are completely blocked. Fresh perspective on
  return often breaks the deadlock.

#### Common Rabbit Holes Specific to OSEE

| Rabbit Hole | Why It Happens | How to Escape |
|---|---|---|
| Trying to bypass a mitigation that is not actually enabled | Assumed based on OS version without checking | Use `!process`, `!exploitable`, check `_EPROCESS` fields |
| Building a complex ROP chain when a simpler primitive exists | Over-engineering from course muscle memory | Step back and enumerate available primitives first |
| Fighting heap layout for hours | Not understanding allocator internals well enough | Review allocator documentation, use `!heap` commands, consider different allocation sizes |
| Debugging a crash that is actually a red herring | Not validating the crash reaches the intended code path | Verify the vulnerability trigger is deterministic and controllable |
| Trying to leak kernel addresses from user-mode | Missing a simpler info leak mechanism | Check for driver-provided IOCTLs, mapped sections, or predictable allocations |

#### Recommended Time Allocation

```
Total exam time: ~72 hours

Assignment 1 (primary):     24-30 hours
Assignment 2:               24-30 hours
Report writing:              8-12 hours (during exam window)
Sleep (three nights):        12-15 hours total
Meals and breaks:             4-6 hours total
Buffer/contingency:           2-4 hours

WARNING: Do NOT leave report writing until after the exam ends.
         The 24-hour report window is for FINISHING the report,
         not starting it from scratch.
```

### 2.3 Report Deficiencies

OffSec is explicit: "Failure to provide sufficient documentation will result in reduced or
zero points being awarded." This is not a soft warning. People fail the OSEE because of
poor reports even when their exploits work.

#### Common Report Failures

1. **Missing screenshots of key steps.** Every command, every debugger output, every proof
   of exploitation must be screenshotted. If you cannot prove you did it, it did not
   happen.

2. **Exploit code without explanation.** Submitting a working Python script without
   explaining WHY each step works is insufficient. The graders need to understand your
   thought process.

3. **Missing proof.txt contents.** You must include the contents of `proof.txt` from the
   Administrator's desktop. Forgetting this loses you the points entirely.

4. **Screenshots that are unreadable.** Low-resolution screenshots, screenshots of
   terminals with tiny fonts, or screenshots where critical information is cut off.

5. **Non-reproducible steps.** The grading team will replay your exploit. If your report
   says "run exploit.py" but does not specify the exact Python version, dependencies,
   command-line arguments, and target state, they cannot reproduce it.

6. **Wrong file format or naming.** The exam guide specifies exact naming:
   `OSEE-OS-XXXXX-Exam-Report.pdf` inside `OSEE-OS-XXXXX-Exam-Report.7z`. Case-sensitive.
   No password. PDF only inside the archive. Getting this wrong means your report is not
   graded.

#### Report Best Practices

- **Document as you go.** Take screenshots after every significant step during
  exploitation. Do not rely on memory.
- **Use the official template.** Download from: `https://offsec.com/awe/AWE-Exam-Report.docx`
- **Include your exploit code inline in the PDF.** OffSec states: "Please make sure to
  include all your scripts or any PoCs as text inside the exam/lab report PDF file itself."
  No external files.
- **Verify the PDF before submission.** Convert from your source format (DOCX, LaTeX,
  Markdown) and verify all formatting, images, and code blocks render correctly.
- **Check the MD5 hash after upload.** The submission portal shows the MD5 of your
  uploaded file. Verify it matches your local copy.

### 2.4 Not Reading Instructions Carefully

This deserves its own section because it is embarrassingly common and entirely preventable.

**Specific mistakes from the exam guide that candidates overlook:**

- The exam is **71 hours 45 minutes**, not exactly 72 hours. Miscalculating the deadline
  means losing 15 minutes or, worse, failing to submit in time.
- The report deadline is **24 hours after the exam ends**, not 24 hours after you stop
  working.
- You access target machines via **Remote Desktop** for debugging -- this means your
  tooling must be set up for RDP-based debugging workflows.
- The file size limit is **300MB for the archive** and **400MB extracted**. Large
  screenshots can push you over this limit.
- Discord may be used as a **search resource** during the exam, but you are **prohibited
  from seeking or receiving assistance** from anyone on the platform.
- No password on the `.7z` archive. If you habitually password-protect archives, this will
  get your report rejected.
- Your submission is **final**. If screenshots or information are missing, "you will not
  be allowed to send them and we will not request them."

**Action item:** Print out the exam guide. Read it three times before exam day. Highlight
every requirement. Create a pre-submission checklist from it.

---

## 3. Lessons from OSEE Holders

The following insights are synthesized from publicly available blog posts, conference
talks, OffSec community discussions, and social media posts by certified OSEE holders.

### 3.1 What Surprised Them About the Exam

#### "The targets were not the same as the course."

This is the most consistently reported surprise. The course teaches specific case studies
against known applications (e.g., VMware Workstation, Edge/Chakra, kernel drivers). The
exam presents **different software with different vulnerability classes**. Candidates who
only practiced the course exercises without broadening their skills were caught off guard.

#### "I had to discover the vulnerability, not just exploit it."

Several OSEE holders report that vulnerability discovery -- not just exploitation -- was a
significant part of the exam. This includes reverse engineering unfamiliar binaries,
identifying the vulnerable code path, and understanding the root cause before exploitation
can begin.

#### "The mitigations were real."

Unlike some lab environments where mitigations are selectively disabled, the exam targets
run with production-level mitigations enabled. Candidates must demonstrate genuine bypass
techniques, not just theoretical knowledge.

#### "72 hours still was not enough."

Even successful candidates report using nearly all available time. Many finished their last
exploit in the final 12 hours and scrambled to complete documentation.

### 3.2 What They Wish They Had Studied More

Based on recurring themes from OSEE holder retrospectives:

1. **Windows internals beyond the course material.** The course covers specific case
   studies, but the exam demands a deeper understanding of Windows memory management,
   process/thread internals, and security subsystems. Books like *Windows Internals* by
   Russinovich et al. and *The Art of Software Security Assessment* by Dowd, McDonald, and
   Schuh are consistently recommended.

2. **Heap exploitation across different allocators.** The Windows heap has changed
   significantly across versions (NT heap, LFH, segment heap). Understanding all variants
   and their exploitation implications is essential.

3. **64-bit kernel exploitation and pool internals.** The kernel pool allocator,
   particularly post-Windows 10 19H1 with segment heap, is complex. Many candidates wish
   they had spent more time on pool overflow exploitation, pool spray techniques, and
   understanding `ExAllocatePoolWithTag` / `ExAllocatePool2` internals.

4. **WinDbg scripting and automation.** Manually inspecting structures during the exam
   wastes time. Candidates who had pre-built WinDbg scripts (JavaScript or LINQ-based)
   for common tasks (heap inspection, pool enumeration, gadget finding) saved hours.

5. **IDA Pro / Ghidra proficiency for rapid reverse engineering.** Speed in RE directly
   correlates with exam success. Being able to quickly identify vulnerability patterns in
   disassembled code is critical.

6. **CFG (Control Flow Guard) bypass techniques.** CFG bypasses are a significant area
   that candidates underestimate. Understanding CFG bitmap validation, call-site
   validation, and known bypass classes is essential.

7. **Practical shellcode development.** Writing custom shellcode (not just using
   msfvenom) for specific constraints (size limits, bad characters, position-independence)
   is harder under pressure than expected.

### 3.3 Technical Areas That Were Harder Than Expected

| Area | Why It Was Hard |
|---|---|
| **Reliable heap/pool grooming** | Theoretical knowledge does not translate to practical reliability. Allocator behavior varies with system load, timing, and fragmentation. |
| **Chaining multiple primitives** | Getting a read primitive, a write primitive, and code execution to work together across mitigations is significantly harder than each individually. |
| **Debugging kernel exploits remotely** | RDP + WinDbg kernel debugging over VPN introduces latency. Candidates who practiced only on local VMs were surprised by the speed difference. |
| **Version-specific offsets** | Structure offsets change between Windows builds. Finding the right offsets for the exam target's exact build number under time pressure is stressful. |
| **Report writing under exhaustion** | Writing a clear, reproducible report after 50+ hours of exploitation work is genuinely difficult. Cognitive function degrades significantly. |

### 3.4 Tips Shared Publicly by OSEE Holders

These are paraphrased tips that consistently appear in public OSEE reviews:

1. **"Build your exploit framework before the exam."** Have template exploit scripts in
   Python with configurable parameters for target IP, offsets, payload, and ROP chains.
   Do not start from scratch during the exam.

2. **"Take notes obsessively during the course."** The in-person AWE course moves fast.
   Your notes from the live class are your primary study material since there is no online
   content to revisit later.

3. **"Practice on real CVEs."** After the course, practice by reproducing published CVEs
   in similar software. Set up vulnerable VMs and develop exploits from scratch.

4. **"Sleep. Seriously."** Multiple OSEE holders report that they solved critical
   problems after sleeping when they had been stuck for hours before. The 72-hour format
   requires strategic rest.

5. **"Write the report as you go."** Do not wait until the end. After each successful
   step, immediately document it with screenshots and explanation. This also serves as a
   checkpoint -- if the VM crashes or you revert, you still have your documentation.

6. **"Know your tools cold."** WinDbg commands, IDA hotkeys, Python pwntools patterns --
   these should be muscle memory. Any time spent looking up basic tool usage is time lost.

7. **"Understand the allocator, not just the exploit."** Blindly copying a heap spray
   technique from the course without understanding why it works will fail when the target
   uses a different heap configuration.

8. **"Have a plan B for every exploitation step."** If your primary ROP chain fails, have
   an alternative. If your heap spray is unreliable, have a different grooming strategy.
   Flexibility is the key skill being tested.

---

## 4. Mental and Physical Preparation

### 4.1 72-Hour Exam Endurance Strategies

The OSEE is one of the longest certification exams in cybersecurity. Endurance is not
optional -- it is a test requirement.

#### Sleep Strategy

You have three nights during the exam. Do not skip all of them.

```
Recommended sleep schedule:

Night 1 (after ~16 hours): Sleep 4-5 hours
  - By this point you should have initial reconnaissance complete
  - Your subconscious will process problems while you sleep

Night 2 (after ~40 hours): Sleep 4-5 hours
  - Critical recovery point
  - Set an alarm -- do not oversleep

Night 3 (after ~60 hours): Sleep 2-3 hours IF needed
  - Only if you have remaining work
  - If you are done exploiting, use this time for report writing

Total sleep: 10-13 hours over 72 hours
Active working time: ~55-60 hours
```

**Why sleep matters:** Exploit development requires creative problem-solving and pattern
recognition. Both degrade catastrophically with sleep deprivation. Research consistently
shows that cognitive performance after 24 hours without sleep is equivalent to a blood
alcohol level of 0.10% -- legally drunk in most jurisdictions. You cannot write reliable
exploits in that state.

#### The 20-Minute Power Nap

If you are stuck and exhausted but cannot afford a full sleep cycle, a 20-minute nap
(strictly timed) can restore some cognitive function. Set an alarm. Do not nap longer than
30 minutes or you risk entering deep sleep and waking groggy.

### 4.2 Setting Up a Comfortable Exam Environment

Your physical environment directly affects your performance over 72 hours. Prepare it
before the exam starts.

#### Workspace Checklist

- [ ] **Desk and chair:** Ergonomic chair is strongly recommended. You will be sitting
      for 60+ hours total. A bad chair causes back pain that compounds over the exam.
- [ ] **Monitor(s):** Dual monitors minimum. One for the RDP session (WinDbg/IDA), one
      for your notes and exploit development. Triple monitors are ideal.
- [ ] **Keyboard and mouse:** Use what you are accustomed to. Do not introduce new
      peripherals right before the exam.
- [ ] **Lighting:** Adjustable lighting. Avoid harsh overhead fluorescents. You will be
      staring at screens for extended periods.
- [ ] **Temperature:** Slightly cool (68-70F / 20-21C). Warm rooms make you drowsy.
- [ ] **Noise:** Quiet environment or noise-cancelling headphones. Inform household
      members of the exam schedule.
- [ ] **Webcam and microphone:** Required for proctoring. Test them before the exam.
- [ ] **Backup everything:**
  - Backup internet connection (mobile hotspot)
  - Backup power (UPS / laptop battery)
  - Backup Kali VM
  - The exam guide states: "ensure you have access to a backup Internet connection,
    Kali Virtual Machine, power etc."

#### Technical Environment

- [ ] Kali Linux VM configured and tested with OpenVPN
- [ ] WinDbg workspace configured with your preferred layout
- [ ] IDA Pro / Ghidra installed and configured
- [ ] Python environment with all required libraries installed
- [ ] All scripts and templates accessible locally (not dependent on internet)
- [ ] Report template downloaded and pre-filled with your OSID and formatting
- [ ] Screenshot tool configured and tested (Flameshot, ShareX, or similar)
- [ ] Note-taking application open and organized

### 4.3 Nutrition and Hydration Strategy

This is not a joke section. Nutrition directly affects cognitive performance over 72 hours.

#### Do

- **Hydrate consistently.** Keep a large water bottle at your desk. Dehydration causes
  headaches and reduces concentration. Aim for 2-3 liters per day.
- **Eat regular meals.** Prepare or pre-order meals in advance. Do not skip meals to
  "save time" -- the cognitive deficit from low blood sugar costs more time than the meal.
- **Protein and complex carbohydrates.** Sustain energy levels. Eggs, chicken, rice, oats,
  nuts, fruit.
- **Caffeine strategically.** If you use caffeine, use it in the morning and early
  afternoon. Avoid caffeine after 4 PM if you plan to sleep that night.
- **Healthy snacks at your desk.** Nuts, fruit, protein bars, dark chocolate.

#### Do Not

- **Energy drink binge.** The crash from excessive caffeine and sugar will cost you hours
  of productivity. One or two energy drinks over 72 hours is fine. Eight is not.
- **Heavy meals.** Large, carb-heavy meals cause post-meal drowsiness. Eat moderate
  portions.
- **Alcohol.** Obviously. But stated for completeness.
- **Skip meals to keep working.** This is counterproductive. A 20-minute meal break
  improves the next 4 hours of work.

### 4.4 Dealing With Frustration and Imposter Syndrome

#### Frustration Management

The OSEE exam is designed to be frustrating. You will get stuck. You will watch hours
disappear on approaches that do not work. This is expected and normal.

**When you are stuck:**

1. **Walk away physically.** Stand up, walk around the room for 5 minutes. Do not stare
   at the same debugger output hoping for insight.
2. **Write down what you know.** Articulate the problem in writing. Often, the act of
   explaining the problem reveals the solution (rubber duck debugging).
3. **Question your assumptions.** List every assumption you are making. Which ones have
   you actually verified? Which are you taking on faith?
4. **Switch targets.** If you have been stuck on one assignment for hours, switch to the
   other. Return with fresh eyes.
5. **Review your notes.** The answer might be in your course notes or cheat sheets. Under
   stress, people forget things they know.
6. **Sleep on it.** If it is nighttime and you are stuck, sleep. Many OSEE holders report
   solving problems immediately after waking up.

#### Imposter Syndrome

Imposter syndrome is extremely common among OSEE candidates, even those who ultimately
pass. The exam is designed to push beyond your comfort zone.

**Reframe your thinking:**

- "I do not know how to do this" -> "I do not know how to do this *yet*. I have 72 hours
  to figure it out."
- "Everyone else found this easy" -> "No one finds this easy. The pass rate is low
  because it is genuinely hard."
- "I am not smart enough for this" -> "I was selected for AWE training. My skills are
  sufficient. I need persistence, not genius."

**Remember:** The OSEE is the most advanced certification OffSec offers. Struggling with
it is not a sign of incompetence -- it is the expected experience.

### 4.5 Building Confidence Through Practice

Confidence comes from competence, which comes from practice. There are no shortcuts.

#### Pre-Exam Practice Regimen

1. **Redo all course exercises from memory.** Close your notes and redo every course
   exercise. If you cannot, you need more practice.

2. **Reproduce published CVEs.** Find CVEs in similar classes to the course material:
   - Browser use-after-free vulnerabilities
   - Win32k kernel vulnerabilities
   - Pool overflow vulnerabilities in third-party drivers
   - Heap corruption in large applications

3. **Time yourself.** Set up a practice scenario and give yourself a time limit. If you
   can exploit a known vulnerability in a similar class within 8-12 hours including
   documentation, you are in reasonable shape for the exam.

4. **Practice under realistic conditions.** Debug over RDP if possible. Use the same
   tooling you will use in the exam. Practice with the official report template.

5. **Build and refine your toolkit.** Each practice session should improve your scripts,
   templates, and cheat sheets. By exam day, you should have a polished toolkit.

---

## 5. Technical Preparation Checklist

### 5.1 Scripts and Templates to Have Ready

#### Exploit Template (Python)

Have a base exploit template ready for common scenarios:

```python
#!/usr/bin/env python3
"""
OSEE Exam Exploit Template
Target: [FILL IN]
Vulnerability: [FILL IN]
Author: [YOUR OSID]
"""

import struct
import socket
import sys
from ctypes import *

# ============================================================
# Configuration
# ============================================================
TARGET_IP   = "CHANGE_ME"
TARGET_PORT = 0       # CHANGE_ME
OFFSET      = 0       # CHANGE_ME - offset to control point

# ============================================================
# Helper Functions
# ============================================================
def p32(val):
    return struct.pack("<I", val)

def p64(val):
    return struct.pack("<Q", val)

def u32(data):
    return struct.unpack("<I", data)[0]

def u64(data):
    return struct.unpack("<Q", data)[0]

# ============================================================
# ROP Chain
# ============================================================
def build_rop_chain(base_addr):
    """Build ROP chain relative to module base."""
    rop = b""
    # rop += p64(base_addr + 0x1234)  # pop rcx; ret
    # rop += p64(0x40)                 # PAGE_EXECUTE_READWRITE
    # ... add gadgets here
    return rop

# ============================================================
# Shellcode
# ============================================================
# Replace with your actual shellcode
SHELLCODE = b""
SHELLCODE += b"\xcc"  # INT3 breakpoint for testing

# ============================================================
# Payload Construction
# ============================================================
def build_payload():
    """Construct the full exploit payload."""
    buf  = b""
    buf += b"A" * OFFSET
    # Add ROP chain, shellcode, etc.
    buf += build_rop_chain(0)
    buf += SHELLCODE
    return buf

# ============================================================
# Exploit Delivery
# ============================================================
def exploit():
    """Send the exploit to the target."""
    payload = build_payload()
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Sending exploit to {TARGET_IP}:{TARGET_PORT}")

    try:
        # Modify delivery mechanism as needed
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send(payload)
        s.close()
        print("[+] Exploit sent!")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()
```

#### Kernel Exploit Template

```python
#!/usr/bin/env python3
"""
OSEE Kernel Exploit Template
Target: Windows [VERSION]
Driver: [DRIVER NAME]
Vulnerability: [TYPE]
Author: [YOUR OSID]
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys

# ============================================================
# Windows API Setup
# ============================================================
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll    = ctypes.WinDLL("ntdll",    use_last_error=True)

# DeviceIoControl
kernel32.DeviceIoControl.restype  = wt.BOOL
kernel32.DeviceIoControl.argtypes = [
    wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD,
    wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID
]

# CreateFileW
kernel32.CreateFileW.restype  = wt.HANDLE
kernel32.CreateFileW.argtypes = [
    wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
    wt.DWORD, wt.DWORD, wt.HANDLE
]

GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
OPEN_EXISTING   = 3
INVALID_HANDLE  = wt.HANDLE(-1).value

# ============================================================
# Configuration
# ============================================================
DEVICE_NAME = r"\\.\YOURDEVICE"
IOCTL_CODE  = 0x00000000  # CHANGE_ME

def get_device_handle():
    """Open a handle to the vulnerable driver."""
    handle = kernel32.CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, None, OPEN_EXISTING, 0, None
    )
    if handle == INVALID_HANDLE:
        print(f"[-] Failed to open device: {ctypes.get_last_error()}")
        sys.exit(1)
    print(f"[+] Device handle: 0x{handle:x}")
    return handle

def send_ioctl(handle, ioctl_code, in_buf, in_size, out_size=0):
    """Send an IOCTL to the driver."""
    out_buf = ctypes.create_string_buffer(out_size) if out_size else None
    bytes_returned = wt.DWORD(0)
    result = kernel32.DeviceIoControl(
        handle, ioctl_code,
        in_buf, in_size,
        out_buf, out_size,
        ctypes.byref(bytes_returned), None
    )
    return result, out_buf, bytes_returned.value

def exploit():
    """Main exploitation logic."""
    print("[*] OSEE Kernel Exploit")
    handle = get_device_handle()

    # Step 1: Information leak / KASLR bypass
    print("[*] Step 1: Leaking kernel base...")
    # TODO: Implement info leak

    # Step 2: Heap/Pool grooming
    print("[*] Step 2: Grooming pool...")
    # TODO: Implement pool spray

    # Step 3: Trigger vulnerability
    print("[*] Step 3: Triggering vulnerability...")
    # TODO: Trigger the bug

    # Step 4: Arbitrary read/write primitive
    print("[*] Step 4: Achieving arbitrary R/W...")
    # TODO: Build primitive

    # Step 5: Privilege escalation (token stealing)
    print("[*] Step 5: Stealing SYSTEM token...")
    # TODO: Token stealing shellcode or data-only attack

    # Step 6: Spawn elevated shell
    print("[*] Step 6: Spawning SYSTEM shell...")
    # TODO: os.system("cmd.exe") or CreateProcess

    kernel32.CloseHandle(handle)

if __name__ == "__main__":
    exploit()
```

#### Report Screenshot Script

Automate screenshot capture with timestamps:

```bash
#!/bin/bash
# save as: screenshot.sh
# Usage: ./screenshot.sh "description of what this screenshot shows"
EXAM_DIR="$HOME/osee-exam/screenshots"
mkdir -p "$EXAM_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DESC=$(echo "$1" | tr ' ' '_' | tr -cd '[:alnum:]_')
FILENAME="${EXAM_DIR}/${TIMESTAMP}_${DESC}.png"
import -window root "$FILENAME"  # or use flameshot/scrot
echo "[+] Screenshot saved: $FILENAME"
```

### 5.2 WinDbg Cheat Sheet

#### Essential Commands

```
=== PROCESS AND THREAD ===
!process 0 0                        # List all processes
!process 0 0 target.exe             # Find specific process
.process /i /p <EPROCESS>           # Switch to process context (invasive)
.process /r /p <EPROCESS>           # Switch context (reload user symbols)
!thread <ETHREAD>                   # Thread details
~* k                                # All thread stacks

=== MEMORY ===
dd <addr>                           # Display DWORDs
dq <addr>                           # Display QWORDs
db <addr>                           # Display bytes
da <addr>                           # Display ASCII string
du <addr>                           # Display Unicode string
dps <addr>                          # Display pointers with symbols
!address <addr>                     # Memory region info
!vprot <addr>                       # Virtual memory protection
s -q <start> L<len> <pattern>       # Search memory for QWORD

=== STRUCTURES ===
dt nt!_EPROCESS <addr>              # Dump EPROCESS
dt nt!_KPROCESS <addr>              # Dump KPROCESS
dt nt!_ETHREAD <addr>               # Dump ETHREAD
dt nt!_TOKEN <addr>                 # Dump token
dt nt!_POOL_HEADER <addr>           # Pool chunk header
dt nt!_OBJECT_HEADER <addr>         # Object header
dt nt!_PEB <addr>                   # Process Environment Block
dt nt!_TEB <addr>                   # Thread Environment Block
dt nt!_LDR_DATA_TABLE_ENTRY <addr>  # Module list entry

=== BREAKPOINTS ===
bp <addr>                           # Software breakpoint
ba r4 <addr>                        # Hardware read breakpoint (4 bytes)
ba w4 <addr>                        # Hardware write breakpoint
ba e1 <addr>                        # Hardware execute breakpoint
bp <addr> ".printf \"Hit!\\n\"; g"  # Conditional/logging breakpoint
bl                                  # List breakpoints
bc *                                # Clear all breakpoints

=== HEAP / POOL ===
!heap -s                            # Heap summary
!heap -a <heap_handle>              # Detailed heap info
!heap -p -a <addr>                  # Page heap info for address
!pool <addr>                        # Pool allocation info
!poolused                           # Pool tag usage
!poolfind <tag>                     # Find pool allocations by tag
!lookaside                          # Lookaside list info

=== EXPLOITATION ===
!exchain                            # Exception handler chain
!seh                                # SEH chain
!pte <addr>                         # Page table entry
!pfn <pfn>                          # Page frame info
r cr4                               # Read CR4 (SMEP bit 20)
r cr0                               # Read CR0
!token                              # Current process token
!object <addr>                      # Object info

=== MODULES ===
lm                                  # List loaded modules
lmf m <module>                      # Module info with full path
!lmi <module>                       # Detailed module info
x <module>!*<pattern>*              # Search module symbols
.reload                             # Reload symbols
.reload /f <module>.sys             # Force reload specific module

=== SYMBOLS AND TYPES ===
x nt!*Pool*                         # Search kernel symbols
? <expression>                      # Evaluate expression
.formats <value>                    # Display value in multiple formats
ln <addr>                           # Nearest symbol to address

=== CONTROL FLOW ===
g                                   # Go (continue)
p                                   # Step over
t                                   # Step into
gu                                  # Step out (go up)
.restart                            # Restart target
.reboot                             # Reboot target (kernel debug)
```

#### Mitigation Checking Commands

```
=== CHECK PROCESS MITIGATIONS ===
# For a given process EPROCESS address:
dt nt!_EPROCESS <addr> MitigationFlags
dt nt!_EPROCESS <addr> MitigationFlags2

# Individual mitigation checks:
!process <addr> 1                   # Shows mitigation flags in output

=== CHECK SYSTEM MITIGATIONS ===
r cr4                               # Bit 20 = SMEP, Bit 21 = SMAP
vertarget                           # OS version info
!sysinfo                            # System information

=== CHECK DEP/NX ===
!vprot <addr>                       # Check page protection
!pte <addr>                         # NX bit in PTE

=== CHECK ASLR ===
lm                                  # Compare base addresses across reboots
!dh <module_base>                   # DllCharacteristics -> DYNAMIC_BASE
```

### 5.3 x86-64 Assembly Quick Reference

```
=== REGISTERS ===
RAX, RBX, RCX, RDX                 # General purpose (64-bit)
RSI, RDI                           # Source/Destination index
RSP                                # Stack pointer
RBP                                # Base pointer
R8-R15                             # Additional GP registers
RIP                                # Instruction pointer

=== CALLING CONVENTION (x64 Windows) ===
Arguments: RCX, RDX, R8, R9, then stack (shadow space: 0x20 bytes)
Return value: RAX
Volatile: RAX, RCX, RDX, R8-R11
Non-volatile: RBX, RBP, RDI, RSI, RSP, R12-R15

=== COMMON INSTRUCTIONS FOR EXPLOITATION ===
ret                                 # Pop RIP from stack
pop rcx; ret                        # Load RCX from stack
mov rsp, <reg>; ret                 # Stack pivot
xchg rax, rsp; ret                  # Stack pivot
push rax; pop rsp; ret              # Stack pivot variant
mov cr4, rcx; ret                   # Disable SMEP (clear bit 20)
wbinvd                              # Flush cache (kernel)

=== SYSCALL ===
syscall                             # System call entry (RAX = syscall #)
                                    # RCX = return addr (set by CPU)
                                    # R10 = first arg (since RCX is clobbered)

=== USEFUL GADGET PATTERNS ===
pop rcx; ret                        # Control first argument
pop rdx; ret                        # Control second argument
pop r8; ret                         # Control third argument
mov [rcx], rdx; ret                 # Arbitrary write
mov rax, [rcx]; ret                 # Arbitrary read
add [rcx], edx; ret                 # Relative write
```

### 5.4 Key Windows Kernel Structures Reference

```
=== EPROCESS (selected fields for exploitation) ===
+0x000 Pcb                          : _KPROCESS
+0x2e0 UniqueProcessId             : Ptr64 Void
+0x2e8 ActiveProcessLinks          : _LIST_ENTRY
+0x360 Token                       : _EX_FAST_REF
+0x4b8 ImageFileName               : [15] UChar

NOTE: Offsets vary by Windows version. Always verify with:
  dt nt!_EPROCESS -y Token
  dt nt!_EPROCESS -y UniqueProcessId
  dt nt!_EPROCESS -y ActiveProcessLinks
  dt nt!_EPROCESS -y ImageFileName

=== TOKEN STEALING APPROACH ===
1. Find current EPROCESS (PsGetCurrentProcess / gs:[0x188] -> KTHREAD -> EPROCESS)
2. Walk ActiveProcessLinks to find System (PID 4)
3. Copy System's Token to current process's Token field
4. Return cleanly to user-mode

=== POOL_HEADER (pre-segment-heap) ===
+0x000 PreviousSize                : Uint2B
+0x002 PoolIndex                   : UChar
+0x003 BlockSize                   : Uint2B (in units of 16 bytes)
+0x004 PoolType                    : UChar
+0x005 PoolTag                     : Uint4B

=== OBJECT_HEADER ===
+0x000 PointerCount                : Int8B
+0x008 HandleCount                 : Int8B
+0x018 TypeIndex                   : UChar
+0x01e InfoMask                    : UChar
+0x020 SecurityDescriptor          : Ptr64 Void
+0x028 Body                        : _QUAD (start of object body)
```

### 5.5 Notes Organization System

Organize your study and exam notes with this structure:

```
osee-prep/
  course-notes/
    day1-user-mode-mitigations/
    day2-advanced-heap/
    day3-kernel-exploitation/
    day4-kernel-mitigations/
    day5-putting-it-together/
  
  cheat-sheets/
    windbg-commands.md
    assembly-reference.md
    windows-structures.md
    mitigation-bypasses.md
    heap-exploitation.md
    pool-exploitation.md
    rop-chain-patterns.md
  
  exploit-templates/
    user-mode-template.py
    kernel-template.py
    rop-builder.py
    shellcode-generator.py
    pool-spray.py
    heap-spray.py
  
  tools/
    gadget-finder/
    offset-resolver/
    pool-inspector/
    token-stealer/
  
  practice/
    cve-YYYY-XXXX/
      writeup.md
      exploit.py
      notes.md
  
  exam/
    report-template.docx
    screenshots/
    exploit-code/
    pre-submission-checklist.md
```

**Recommended note-taking tools:**
- **Obsidian** or **Notion** for linked notes with search capability
- **CherryTree** for hierarchical notes (popular in the OffSec community)
- **Plain Markdown files** in a git repository for version control

---

## 6. Post-Exam Process

### 6.1 Report Writing Best Practices

#### Structure Your Report

Use the official OffSec report template. The expected structure:

1. **Title Page** -- OSID, exam date, target information
2. **Table of Contents**
3. **Executive Summary** -- High-level overview of findings
4. **Per-Target Sections:**
   - Target information (IP, OS version, software version)
   - Vulnerability discovery methodology
   - Vulnerability description and root cause analysis
   - Exploitation methodology (step-by-step)
   - Mitigation bypasses explained
   - Screenshots of every significant step
   - Full exploit code with inline comments
   - Proof of exploitation (proof.txt contents, screenshots)
5. **Appendices** -- Full exploit source code, tool versions used

#### Writing Tips

- **Write in present tense, active voice.** "The exploit sends a crafted buffer..." not
  "A crafted buffer was sent..."
- **Explain WHY, not just WHAT.** "We overwrite the return address because DEP prevents
  execution on the stack, requiring a ROP chain to call VirtualProtect" -- not just
  "We use ROP."
- **Every screenshot must have a caption** explaining what it shows.
- **Code blocks must have comments.** A grader reviewing a 200-line exploit at 2 AM needs
  inline comments to follow your logic.
- **Include exact commands.** Not "run the exploit" but
  `python3 exploit.py --target 192.168.X.X --port 1337`
- **State the exploit's reliability.** "This exploit succeeds approximately 9/10 times
  due to heap layout dependency" is honest and useful.

#### Pre-Submission Checklist

```
[ ] Report is in PDF format
[ ] Filename: OSEE-OS-XXXXX-Exam-Report.pdf (exact format, case-sensitive)
[ ] Archive: OSEE-OS-XXXXX-Exam-Report.7z (no password)
[ ] Archive size < 300MB, extracted < 400MB
[ ] All exploit code included as TEXT in the PDF (not separate files)
[ ] proof.txt contents included for each completed target
[ ] All screenshots are legible and captioned
[ ] Steps are reproducible by a third party
[ ] PDF formatting verified (images render, code blocks readable)
[ ] Uploaded to https://upload.offsec.com
[ ] MD5 hash verified against local copy
[ ] "Submit File" button clicked after upload
[ ] Confirmation email received
```

### 6.2 Timeline for Results

- **Submission deadline:** 24 hours after the exam ends
- **Results notification:** Within **10 business days** (not calendar days) after
  submission
- **Results format:** Pass/fail email only. OffSec does **not** provide your score or
  solutions to the exam targets.

**What "10 business days" means in practice:**
- If your exam ends on a Friday, the 24-hour report window closes Saturday. Counting
  starts the next business day (Monday). Results could arrive as late as two Fridays later.
- During high-volume periods (after major conferences where AWE is offered), results may
  take the full 10 business days.

### 6.3 What Happens If You Fail

Failing the OSEE exam is common and not a career-ending event. The exam is widely regarded
as the most difficult certification in offensive security.

**After a failure:**
1. You receive a pass/fail email. No detailed feedback is provided. You will not know
   which targets you passed or failed, or what specific points you missed.
2. You can purchase a retake by submitting a support request to OffSec.
3. Use the time between attempts to address the areas where you struggled.

**Common reasons people fail and how to address them:**

| Reason | Recovery Strategy |
|---|---|
| Could not find the vulnerability | Practice vulnerability discovery in unfamiliar software. Reproduce CVEs from advisories without looking at existing exploits first. |
| Exploit was unreliable | Focus on heap/pool internals. Practice grooming until you achieve >90% reliability. |
| Ran out of time | Practice timed exploitation. Improve tooling and automation. Refine your methodology for faster initial analysis. |
| Report was insufficient | Practice writing reports for your practice exploits. Have someone else try to reproduce your exploit from your report alone. |
| Could not bypass mitigations | Study each mitigation in isolation. Build a library of bypass techniques with working PoCs. |

### 6.4 Retake Policies and Cooling-Off Periods

OffSec's retake policies for OSEE (based on publicly available information):

- **Retake eligibility:** Available after receiving your fail result.
- **How to schedule:** Submit a support request at
  `https://help.offensive-security.com/hc/en-us/requests/new`
- **Retake cost:** Retake fees apply. Contact OffSec support for current pricing.
- **Cooling-off period:** There is typically a mandatory waiting period between attempts.
  Exact duration varies -- check with OffSec support for current policy.
- **No limit on attempts:** You can retake the exam as many times as needed (subject to
  scheduling availability and cooling-off periods).

**Use the cooling-off period productively:**
- Review your notes from the failed attempt
- Identify your weakest areas
- Practice specifically in those areas
- Rebuild and improve your toolkit
- Redo course exercises until they are second nature

### 6.5 Maintaining the Certification

As of the latest available information:

- **OSEE does not expire.** Once earned, the certification is valid indefinitely. Unlike
  some certifications (CISSP, CEH), there are no continuing education requirements or
  renewal fees.
- **Digital badge:** Issued via Credly. You can share it on LinkedIn and other platforms.
- **CPE credits:** You can request a course completion letter for (ISC)2 CPE credits.
  See: `https://help.offsec.com/hc/en-us/articles/15568144981780`
- **Verification:** Employers and clients can verify your certification through OffSec's
  verification process.

---

## 7. Final Words

### The Mindset That Passes the OSEE

The OSEE is not a test of how much you have memorized. It is a test of whether you can
apply deep technical knowledge to solve problems you have never seen before, under
extreme time pressure, while managing exhaustion and frustration.

**The candidates who pass share these traits:**

1. **Deep understanding over memorization.** They understand WHY exploits work, not just
   HOW to run them.
2. **Systematic methodology.** They follow a consistent process for vulnerability
   discovery and exploitation, rather than guessing.
3. **Prepared tooling.** Their scripts, templates, and cheat sheets are battle-tested from
   months of practice.
4. **Time discipline.** They time-box their efforts and switch strategies when stuck.
5. **Physical endurance.** They sleep, eat, and take breaks strategically.
6. **Honest documentation.** They document every step as they go, not from memory
   afterwards.
7. **Resilience.** They keep working through frustration, knowing that persistence --
   combined with skill -- is the ultimate differentiator.

### Pre-Exam Day Checklist

The day before your exam:

```
[ ] Read the exam guide one final time
[ ] Verify VPN connectivity with Kali
[ ] Test all tools (WinDbg, IDA/Ghidra, Python environment)
[ ] Verify backup internet connection
[ ] Charge UPS / backup power
[ ] Prepare meals for the next 3 days
[ ] Inform household members of exam schedule
[ ] Set up workspace (monitors, chair, lighting)
[ ] Pre-fill report template with OSID and formatting
[ ] Review cheat sheets one final time
[ ] Get a full night's sleep (8+ hours)
[ ] Set alarm for 1 hour before exam start

On exam morning:
[ ] Eat a solid breakfast
[ ] Hydrate
[ ] Clear your desk of distractions
[ ] Open all required tools
[ ] Start the VPN connection
[ ] Take a deep breath and begin
```

---

*This guide was compiled from official OffSec documentation, publicly shared experiences
from OSEE holders, and established best practices for endurance-based technical
examinations. All official exam policies should be verified against the current exam guide
at `https://help.offsec.com/hc/en-us/articles/360046458732` as policies may change.*
