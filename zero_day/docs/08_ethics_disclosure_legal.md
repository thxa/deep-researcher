# Responsible Disclosure, Ethics & Legal Framework for Zero-Day Research

**Authoritative Reference — v1.0**

---

## 1. Ethical Framework for Vulnerability Research

### 1.1 Core Ethical Principles

Vulnerability research sits at the intersection of technological capability and moral responsibility. Three foundational principles govern ethical practice:

**Do No Harm.** The researcher's primary obligation is to avoid causing measurable damage to systems, data, or individuals. This extends beyond immediate technical impact to consider secondary effects: a proof-of-concept that crashes a hospital system is not "harmless." The principle demands that researchers calibrate their methods to the minimum force necessary to demonstrate a vulnerability.

**Authorized Testing.** Ethical research requires a good-faith basis for believing that testing is permitted. Authorization may be explicit (a bug bounty program, a scope document, a signed engagement letter) or implied (testing your own software, operating within published acceptable-use policies). The absence of a "no trespassing" sign is not authorization.

**Responsible Disclosure.** Discovering a vulnerability carries an implicit duty to ensure it reaches someone who can fix it before it reaches someone who will exploit it. This does not mean disclosure must always be delayed indefinitely, but it does mean the discoverer should make a reasonable effort to notify affected parties and allow them a fair interval to respond.

### 1.2 The Hacker Ethic and Its Evolution

Steven Levy's original articulation of the hacker ethic — hands-on access to technology, mistrust of authority, the conviction that information should be free — has aged unevenly. The principle that "all information should be free" collides with the reality that some information, in the wrong hands at the wrong time, causes harm. The modern ethical researcher inherits the hacker ethic's curiosity and skepticism but tempers its absolutism with consequentialist reasoning.

The community has, over decades, developed normative standards. The RFC 3115-era full-disclosure culture of Bugtraq in the late 1990s gave way to the coordinated-disclosure consensus of the 2010s. This evolution reflects a maturation: from "the world has a right to know immediately" to "the world has a right to know, and we should minimize the window of exposure."

### 1.3 White Hat, Grey Hat, Black Hat — Nuance and Realities

The tripartite color scheme is a simplification that obscures more than it illuminates.

- **White hat**: Researchers who operate within clear authorization boundaries and follow responsible disclosure. In practice, many respected researchers have, at some point, tested systems without explicit authorization — scooping a publicly exposed endpoint is rarely covered by a signed document.

- **Grey hat**: Researchers who lack explicit authorization but act in good faith — notifying vendors, not exploiting for personal gain. The 1998 RSA-129 factoring team, the researchers who found the SSRF in Capital One's infrastructure, and many others occupied this space. The legal system often treats grey-hat activity identically to black-hat activity, which is itself a problem.

- **Black hat**: Actors who exploit vulnerabilities for unauthorized access, financial gain, or disruption. The boundary is real but porous: a researcher who sells a zero-day to a broker who supplies an authoritarian regime has crossed from grey to black, even if they never exploit it themselves.

The real world is messier. A researcher may simultaneously hold white-hat employment, sell grey-hat research to brokers, and contribute black-hat tools to underground communities. Categories describe actions, not people.

### 1.4 Responsible vs. Full Disclosure

**Full disclosure** — publishing vulnerability details immediately, without advance notice to the vendor — is the nuclear option. It forces remediation by eliminating the vendor's option to ignore the problem. It also creates a zero-day window during which every attacker on earth can exploit the vulnerability before patches exist.

**Responsible (coordinated) disclosure** — notifying the vendor privately and allowing a reasonable interval before publication — attempts to minimize that window. The criticism is that it gives vendors cover to delay indefinitely, and it withholds information from defenders who could implement mitigations.

The pragmatic consensus, as codified by organizations like CERT/CC, is coordinated vulnerability disclosure (CVD): notify the vendor, negotiate a timeline, and publish regardless after that timeline expires. This preserves the accountability mechanism of full disclosure while giving vendors a fair chance to respond.

### 1.5 Coordinated Vulnerability Disclosure (CVD)

CVD is a process, not a policy. The key elements:

1. A discoverer reports the vulnerability to the vendor (or a coordinator).
2. The parties agree on a remediation timeline.
3. The vendor develops and ships a fix.
4. The vulnerability is disclosed publicly, ideally alongside the fix.

The process breaks down when vendors are unresponsive, when the vulnerability affects multiple vendors with divergent timelines, or when the discoverer and vendor disagree on severity. CERT/CC and other coordinators exist to mediate these breakdowns.

### 1.6 When Is It Ethical to Hold or Withhold a Zero-Day?

There are legitimate reasons to delay disclosure that do not involve hoarding:

- **Patch readiness**: Publishing before a patch exists exposes users who cannot deploy workarounds.
- **Multi-vendor coordination**: A vulnerability in a shared protocol or library may require coordinated patching across many products.
- **Active negotiation**: If the vendor is engaged and making progress, premature disclosure may undermine good-faith efforts.
- **Physical safety**: Vulnerabilities in medical devices, industrial control systems, or vehicles may require extended timelines to avoid endangering lives.

Illegitimate reasons include: maximizing the value of a zero-day for sale, government stockpiling without a defined equities process, or retaliatory disclosure ("the vendor was rude, so I'm dropping this on Full Disclosure").

The ethical calculus is always context-dependent. The question is not "disclose or not?" but "disclose when, to whom, and with what details?"

---

## 2. Responsible Disclosure Process

### 2.1 Step-by-Step Disclosure Workflow

**Step 1: Discovery.** You find a vulnerability. Document it thoroughly: reproduction steps, affected versions, impact assessment, proof-of-concept code. The quality of your documentation directly affects the speed and quality of the vendor's response.

**Step 2: Verification.** Confirm the vulnerability exists in a current release. Test edge cases. Determine scope: does it affect all deployments, or only specific configurations? Check for existing reports — a duplicate report wastes everyone's time.

**Step 3: Vendor Contact.** Identify the correct contact. Use `security@`, `secalert@`, or `vulnerability@` at the vendor's domain. Check for a security.txt file (per RFC 9116) at `/.well-known/security.txt`. Check the vendor's bug bounty program, if one exists. If no contact is apparent, reach out via CERT/CC.

**Step 4: Initial Report.** Provide a clear, technical report. Include:
- A descriptive title and severity estimate
- Affected software and versions
- Detailed reproduction steps
- Proof-of-concept code or screenshots
- Suggested remediation (if you have one)
- Your preferred disclosure timeline
- Your PGP key for encrypted communication

**Step 5: Negotiation.** The vendor may request more time, dispute severity, or propose alternative remediation. Negotiate in good faith. If you believe the vendor is stalling, involve a coordinator.

**Step 6: Timeline.** If no timeline was pre-agreed, a 90-day window from initial report to public disclosure is the de facto standard (following Google Project Zero's model). Some vendors request extensions; grant them if progress is evident, deny them if it is not.

**Step 7: Disclosure.** Publish the vulnerability details, proof-of-concept, and advisory. Coordinate publication with the vendor's advisory if possible. Credit all contributors.

### 2.2 CVE Assignment Process

Common Vulnerabilities and Exposures (CVE) IDs provide a universal identifier for vulnerabilities. The process:

1. **Discover the vulnerability** and confirm it is genuinely new.
2. **Contact a CVE Numbering Authority (CNA)** — the vendor's CNA, a bug bounty platform's CNA, or MITRE directly.
3. **Reserve a CVE ID** through the CNA. Many CNAs allow self-service reservation.
4. **Provide details** to the CNA for validation.
5. **The CNA publishes** the CVE record once the vulnerability is disclosed or the vendor confirms.

Bug bounty platforms (HackerOne, Bugcrowd) often handle CVE assignment as part of their triage process. For independent researchers, MITRE's open submission process or the CNA of Last Resort can be used.

### 2.3 Working with Coordinators

**CERT/CC** (US): The oldest and most established coordinator. Accepts reports on any product, coordinates with vendors, and publishes advisories (VU# identifiers). Operates under a formal disclosure policy with a 45-day default timeline.

**CERT-EU** (European Union): Coordinates vulnerability disclosure for EU institutions and European infrastructure. Works similarly to CERT/CC but with EU-specific policy considerations.

**JPCERT/CC** (Japan): Handles coordination for Japanese vendors and infrastructure. Operates in Japanese and English, with a 60-day default disclosure timeline.

**NCSC** (UK, Netherlands, etc.): National cybersecurity agencies increasingly serve as coordinators for vulnerabilities affecting their national infrastructure.

Coordinators are particularly valuable when: the vendor is unresponsive, the vulnerability affects multiple vendors, or the discoverer wishes to remain anonymous.

### 2.4 Bug Bounty Programs and Engagement

Bug bounty programs formalize the disclosure process: the vendor authorizes testing within a defined scope, commits to safe harbor for good-faith research, and pays bounties based on severity. When engaging with a bug bounty program:

- **Read the scope and policy carefully.** Out-of-scope testing can be treated as unauthorized access regardless of intent.
- **Follow the rules of engagement.** Some programs prohibit certain techniques (e.g., social engineering, DoS, data exfiltration).
- **Report promptly.** Many programs award bounties on a first-to-report basis.
- **Document everything.** Timestamps, screenshots, network logs — because other researchers may be racing you to the same finding.

### 2.5 When a Vendor Is Unresponsive

If the vendor does not respond to your initial contact:

1. **Escalate through alternative channels.** Try LinkedIn, Twitter, GitHub security advisories, or personal contacts.
2. **Involve a coordinator.** CERT/CC will attempt to contact the vendor on your behalf.
3. **Set a final deadline.** Communicate a specific date after which you will disclose publicly.
4. **Disclose.** If the deadline passes without substantive response, publish through your preferred channel (blog, Full Disclosure mailing list, GitHub advisory) and assign a CVE.

The community broadly supports disclosure after reasonable effort to contact the vendor has failed. The 90-day standard (or the vendor's own stated timeline, if shorter) applies.

### 2.6 The 90-Day Disclosure Timeline (Google Project Zero Model)

Google's Project Zero (GPZ) established the 90-day deadline as the industry norm: after reporting a vulnerability, GPZ discloses it publicly in 90 days, regardless of whether a patch is available. Exceptions are rare and require extenuating circumstances (e.g., a 14-day extension when the vendor demonstrates active progress).

The policy is intentionally aggressive. Its rationale: vendors routinely delay patching indefinite vulnerabilities absent external pressure; the 90-day deadline creates that pressure; and the brief window of exposure after disclosure before patch deployment is preferable to perpetual zero-day exposure.

Critics argue the deadline is inflexible, particularly for complex embedded systems or multi-vendor coordination. GPZ has adjusted: in 2022, they extended the deadline to 90 days from report submission (previously it was 90 days from discovery) and added a grace period mechanism.

---

## 3. Legal Framework by Jurisdiction

### 3.1 United States

**Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.** The CFAA criminalizes unauthorized access to protected computers. "Authorization" is undefined in the statute, creating decades of legal uncertainty. The key provision, § 1030(a)(2), criminalizes obtaining information from a computer "without authorization" or "exceeding authorized access." The DOJ's 2022 revised charging policy (following the Van Buren Supreme Court decision) narrowed CFAA application, declining to prosecute terms-of-service violations alone. However, the CFAA remains a risk for researchers who access systems beyond explicit authorization.

**DMCA § 1201 Exemptions.** The Digital Millennium Copyright Act prohibits circumvention of technological measures that control access to copyrighted works. Section 1201 has been used to threaten researchers who reverse-engineer software, even for security purposes. The Librarian of Congress grants triennial exemptions; the current cycle (2024–2026) includes exemptions for security research and testing, but these are time-limited, scope-limited, and require renewal. The exemption does not protect distribution of circumvention tools.

**DEFCON/CTF Legality.** CTF competitions operate within explicit authorization: organizers grant participants permission to attack target systems. This authorization is narrow, time-limited, and specific to the competition infrastructure. CTF activity performed outside the competition scope is not protected. Additionally, tools developed or techniques learned in CTFs can be used for unauthorized purposes; the law evaluates conduct, not context.

**Defense and Safe Harbor.** No federal statute provides a general safe harbor for security research. The DOJ's 2022 policy is guidance, not law. State laws vary: some (e.g., California) provide limited immunities for good-faith research, but none are comprehensive.

### 3.2 European Union

**Cyber Resilience Act (CRA).** Adopted in 2024, the CRA imposes security obligations on manufacturers of products with digital elements connected to a network. Critically for researchers, the CRA mandates that manufacturers establish coordinated vulnerability handling policies and processes, and it creates a legal basis for reporting vulnerabilities to ENISA and national CSIRTs. The CRA does not create a researcher safe harbor per se, but it does create a statutory duty for vendors to receive and process vulnerability reports — reducing the risk that a researcher's report will be ignored or weaponized against them.

**EU Directive on Attack Systems (2022/2565, amending Directive 2013/40/EU).** Harmonizes criminalization of attacks against information systems across the EU. Allows member states to create exemptions for legitimate security research, testing, or the development of security tools, but does not mandate such exemptions. Implementation varies by member state.

**National Protections.** Several EU member states have specific legal protections for security researchers:
- **France**: The 2021 "Loi Renseignement" amendment and the 2023 Cyber Act provide legal recognition for bug bounty participants operating under contract.
- **Germany**: § 202c StGB (preparation of data espionage) has been interpreted to exclude good-faith security research, though the statute is broadly written.
- **Netherlands**: The Netherlands has a well-established responsible disclosure tradition, with the NCSC-NL providing formal guidance that courts have referenced favorably.

**GDPR Considerations.** If vulnerability research involves processing personal data (e.g., accessing a database to demonstrate an SQL injection), the GDPR applies. Researchers should minimize data access, use synthetic data where possible, and report only the vulnerability's existence rather than exfiltrated personal data.

### 3.3 Vulnerability Equities Process (VEP) — United States

The US Vulnerability Equities Process (codified in a 2017 Obama-era policy and continued under subsequent administrations) governs how the US government decides whether to disclose or retain vulnerabilities it discovers or acquires.

The process requires agencies to submit newly discovered or acquired vulnerabilities to an interagency Equities Review Board, which weighs:
- **Pro-disclosure factors**: The vulnerability's impact on public safety, the availability of alternative intelligence sources, the risk of adversary discovery.
- **Pro-retention factors**: The intelligence or law enforcement value of exploiting the vulnerability, the difficulty of developing alternative access, the scope and duration of anticipated utility.

The stated default is disclosure ("a bias toward disclosure"), but in practice, the process has been criticized for opacity and for prioritizing intelligence collection. The EPICFOIA litigation and subsequent FOIA releases have shown that the NSA retained vulnerabilities for years — including the EternalBlue vulnerability later leaked by the Shadow Brokers and used in the WannaCry and NotPetya attacks, causing billions in damage.

The VEP applies only to the US government. Private researchers are not bound by it, but the government's retention of vulnerabilities directly affects the risk landscape for all users.

### 3.4 Export Controls on Exploits (Wassenaar Arrangement)

The Wassenaar Arrangement, a multilateral export control regime, was amended in 2013 to include "intrusion software" in its control lists. The implementing regulations vary by member state:

- The 2013 amendment controls the export of software "specially designed" for exploiting vulnerabilities, and of IP addresses and exploits described in a way that enables exploitation.
- In the US, the Bureau of Industry and Security (BIS) implemented Wassenaar through the Export Administration Regulations (EAR). After significant pushback from the security community, BIS revised the rule to narrow the definition and create exceptions for vulnerability disclosure, incident response, and sharing of vulnerability information in the normal course of business.
- The EU implemented Wassenaar through dual-use regulation 2021/821, which includes similar exceptions for vulnerability disclosure.

The practical impact: selling or transferring exploits across borders may require export licenses. Sharing vulnerability details for responsible disclosure purposes is generally exempt, but the line between "disclosure" and "transfer of intrusion software" can be unclear.

### 3.5 Legal Protections for Security Researchers — Summary

| Jurisdiction | Statutory Safe Harbor | Case Law | Practical Risk |
|---|---|---|---|
| United States | None (DOJ guidance only) | Van Buren narrowed CFAA | Moderate — prosecutorial discretion |
| EU (CRA) | Limited (vendor duty to receive reports) | Varies by state | Low–moderate |
| UK | Computer Misuse Act — no research exception | Limited | Moderate |
| Germany | Implicit (§ 202c StGB interpretation) | Limited | Low–moderate |
| Netherlands | Strong normative framework | Supportive case law | Low |
| France | Emerging statutory protections | Limited | Low |

### 3.6 CTF Competition Legal Considerations

CTF competitions occupy a legally privileged position because they operate with explicit authorization. However:

- **Scope matters.** Authorization extends only to the competition infrastructure. Attacking the competition organizers' production systems is unauthorized.
- **Tools developed in CTFs** are not legally distinct from other offensive tools. If you develop a tool during a CTF and later use it for unauthorized access, the CTF context provides no defense.
- **Cross-border participation** may implicate export control laws if exploit tools are transferred between participants in different countries.
- **Recording and streaming** CTF activities does not inherently violate law, but distributing detailed exploitation guides targeting specific, real-world systems could be construed as facilitating unauthorized access.

---

## 4. Bug Bounty Economics

### 4.1 Major Programs

| Platform | Model | Notable Programs | Typical Scope |
|---|---|---|---|
| **HackerOne** | Open/pUBLIC, managed | USPS, DoD, Google, Uber | Broad — web, mobile, API |
| **Bugcrowd** | Open, private, managed | Tesla, Mastercard, Atlassian | Often product-specific |
| **Synack** | Private, vetted researchers | US DoD, major banks | High-value targets |
| **Intigriti** | Open, private, managed | European enterprises | EU-focused |
| **Vendor programs** | Direct | Apple, Microsoft, Google (VRP), Meta | Own products only |

### 4.2 Typical Bounty Ranges by Severity

| Severity | Web/Mobile (typical) | Enterprise/Cloud | Apple | Google VRP |
|---|---|---|---|---|
| Critical (RCE, auth bypass) | $5,000–$30,000 | $15,000–$100,000+ | $100,000–$2,000,000 | $60,000–$151,000 |
| High (data access, privilege escalation) | $2,000–$10,000 | $5,000–$30,000 | $20,000–$100,000 | $15,000–$60,000 |
| Medium (XSS, CSRF, info disclosure) | $500–$3,000 | $2,000–$10,000 | $5,000–$20,000 | $5,000–$15,000 |
| Low (open redirect, minor info leak) | $100–$500 | $500–$2,000 | $1,000–$5,000 | $1,000–$5,000 |

These are indicative. Apple's bounties for lockscreen bypasses and sandbox escapes can reach $2 million. The US DoD's "Hack the Pentagon" program paid up to $15,000 for critical findings — a fraction of the black-market value of similar vulnerabilities.

### 4.3 Maximizing Earnings Ethically

1. **Target high-bounty programs.** Focus on programs that pay commensurately with severity. A $500 maximum bounty is not worth the effort for a critical RCE.
2. **Specialize.** Deep knowledge of a specific technology stack (e.g., Android kernel, Kubernetes, SAP) produces higher-value findings than broad surface-level testing.
3. **Chain vulnerabilities.** A low-severity bug that enables a high-severity impact (e.g., an XSS that leads to account takeover) should be reported and paid at the higher severity.
4. **Report promptly and thoroughly.** First-to-report wins. A well-documented report with a clear proof-of-concept reduces triage time and accelerates payment.
5. **Maintain ethics.** Do not extort vendors, do not access data beyond what is necessary, do not threaten disclosure to force payment. These actions degrade the ecosystem and may constitute criminal offenses.
6. **Track duplicates.** Before investing time in a deep investigation, check public channels for existing reports on the target.

### 4.4 Duplicate Issues and Race Conditions

Duplicate reports — where two researchers independently discover the same vulnerability — are a fact of bug bounty life. Most programs award bounties to the first reporter only. This creates a race condition:

- **Mitigation**: Report early, even with an incomplete proof-of-concept. Most programs allow you to add detail after initial submission.
- **Dispute resolution**: If you believe a report was marked duplicate in error, provide timestamps, log entries, or other evidence of independent discovery. Some programs split bounties between duplicate reporters.
- **Persistent programs**: HackerOne and Bugcrowd maintain closed reports that triagers check against. If your finding matches a previously reported (but undisclosed) vulnerability, it will be marked duplicate regardless of independent discovery.

The "duplicate problem" is partly why some researchers prefer direct vendor programs or private programs with smaller researcher pools — lower probability of duplication.

---

## 5. The Zero-Day Market Debate

### 5.1 What Is the Zero-Day Market?

The zero-day market is the ecosystem in which vulnerabilities and exploits are bought and sold. It is not a single marketplace but a spectrum:

- **White market**: Bug bounty programs, vendor VRPs, and legitimate security companies that purchase vulnerabilities for defensive purposes (e.g., reporting them to vendors or building protective detection rules).
- **Grey market**: Brokers who purchase vulnerabilities from researchers and sell them to government agencies and law enforcement. Zerodium, NSO Group's acquisition channels, and similar intermediaries operate in this space.
- **Black market**: Underground forums and intermediaries where vulnerabilities are sold to criminal actors for use in ransomware, espionage, and fraud.

### 5.2 Arguments For a Zero-Day Market

**Pricing reflects reality.** Vulnerabilities have value; a market assigns that value transparently. Without a legitimate market, the only buyers are criminals and intelligence agencies willing to pay far more than bug bounty programs.

**Incentivizes research.** The prospect of substantial payment ($100,000–$1,000,000+ for premium iOS/Android zero-days) draws talent into security research who might otherwise work in offensive cyber operations for state actors.

**Defensive benefit.** White- and grey-market brokers often (claim to) report vulnerabilities to vendors after acquiring them, or at minimum build detection rules that protect defenders.

**Economic efficiency.** If a vulnerability will be found eventually, paying a researcher to find and sell it on the white market is preferable to it being found and exploited on the black market.

### 5.3 Arguments Against a Zero-Day Market

**Proliferation.** Exploits sold to government agencies have a documented history of leaking. EternalBlue (NSA), Pegasus (NSO Group), and Hacking Team's tools all escaped their intended users. A market that facilitates sales to governments inevitably facilitates proliferation.

**Hoarding.** Government purchasers have no incentive to disclose vulnerabilities to vendors — doing so would eliminate their own access. This prolongs the period during which the vulnerability is exploitable by anyone who knows about it.

**Ethical complicity.** Selling an exploit to a broker who supplies authoritarian regimes for surveillance of journalists and dissidents makes the researcher complicit in human rights abuses, regardless of the researcher's intent.

**Market distortion.** A robust grey market draws researchers away from responsible disclosure and bug bounty programs. If a researcher can earn $500,000 on the grey market for an exploit that would earn $100,000 on a bug bounty program, the economic incentive pushes toward opacity and weaponization.

### 5.4 Government Hoarding vs. Disclosure

The fundamental tension: governments argue that retaining zero-days is necessary for intelligence collection and law enforcement operations. Privacy and security advocates argue that hoarding creates risk for all users of the affected software, because the vulnerability is simultaneously exploitable by adversaries who may independently discover it.

The VEP (Section 3.3) attempts to formalize this trade-off, but the process is opaque and its outcomes classified. The WannaCry incident — in which an NSA-retained vulnerability was leaked and used in a ransomware attack that disrupted hospitals worldwide — is the canonical example of hoarding gone wrong.

### 5.5 Cyber Weapons and Proliferation Concerns

Exploits are dual-use: the same technique that enables lawful intercept also enables unlawful surveillance. The Stuxnet precedent demonstrated that cyber weapons can cause physical destruction. Pegasus demonstrated that mobile exploits enable pervasive surveillance.

Proliferation is not a hypothetical risk. The Shadow Brokers' leak of NSA tools in 2016–2017 is estimated to have enabled hundreds of millions of dollars in damage through WannaCry, NotPetya, and derivative attacks. The Hacking Team breach in 2015 released 400 GB of offensive tools into the public domain.

The argument for controlling proliferation is straightforward: the probability of a zero-day leaking or being independently rediscovered approaches 1 over time. Therefore, any retention of a zero-day imposes a risk on the users of the affected software that they did not consent to and cannot mitigate.

### 5.6 The Role of Brokers

Brokers — companies like Zerodium, Crowdfense, and their predecessors — act as intermediaries between researchers and buyers. Their role:

- **Aggregation**: They acquire from many researchers and supply to many buyers, reducing transaction costs.
- **Verification**: They validate exploits before purchase, providing quality assurance.
- **Anonymization**: They shield researchers from direct contact with end users, which can be both a privacy benefit and an ethical shield.
- **Pricing**: They establish market rates, which increasingly serve as benchmarks for bug bounty programs.

Critics argue that brokers — even "legitimate" ones —facilitate the flow of exploits to end users with poor human rights records. The 2019 FTI Consulting report on NSO Group's client list included governments with well-documented records of surveillance abuses. Brokers argue they comply with export control laws and vet buyers, but the vetting is opaque and the compliance is minimal.

---

## 6. Career Paths in Vulnerability Research

### 6.1 CTF to Professional Trajectory

CTF competitions are an unparalleled training ground for vulnerability research. The trajectory from CTF competitor to professional researcher is well-established:

1. **Compete.** Start with beginner-friendly CTFs (picoCTF, OverTheWire, HTB). Focus on the category that matches your interest (pwn, web, crypto, reverse).
2. **Write up.** Documenting your solutions builds understanding, establishes a public portfolio, and teaches you to communicate findings — a critical professional skill.
3. **Contribute.** Open-source security tools, CTF challenge design, and community mentoring establish reputation.
4. **Recruit.** Top CTF performers are actively recruited by security companies and research teams. DEFCON CTF finalists, PlaidCTF winners, and consistent high performers on CTFtime are in demand.

### 6.2 Working at Security Companies

Several organizations employ professional vulnerability researchers:

- **Google Project Zero**: The gold standard for independent vulnerability research. GPZ researchers have a mandate to find vulnerabilities in any software, not just Google's. The team's 90-day disclosure policy and high-impact findings make it the most visible research team in the industry.

- **Team82 (Claroty)**: Focused on industrial control systems and operational technology. Their research has disclosed critical vulnerabilities in SCADA, DCS, and IoT systems.

- **Microsoft Security Response Center (MSRC)**: Microsoft's internal research and response team. MSRC researchers find and fix vulnerabilities in Microsoft's own products and in third-party software that affects the Windows ecosystem.

- **Trend Micro's Zero Day Initiative (ZDI)**: One of the largest vulnerability acquisition programs. ZDI purchases vulnerabilities from researchers, coordinates disclosure with vendors, and publishes advisories. Working at ZDI means triaging, verifying, and coordinating disclosure for a high volume of submissions.

- **CrowdStrike, FireEye/Mandiant, etc.**: Threat intelligence teams that research vulnerabilities used by advanced persistent threats. These roles focus on understanding adversary TTPs as much as vulnerability discovery.

### 6.3 Independent Consulting

Independent vulnerability research can be financially viable through:

- **Bug bounty platforms**: Consistent high-severity findings on platforms like HackerOne can generate six-figure annual income.
- **Direct contracts**: Some companies engage researchers directly for security assessments, outside the bug bounty model.
- **Vulnerability brokerage**: Selling findings through legitimate brokers (Zerodium, ZDI). Ethical considerations apply (see Section 5).
- **Consulting**: Providing expert testimony, incident response, or security architecture review services.

The independent path offers autonomy but lacks the stability, legal support, and resources of institutional employment.

### 6.4 Academic Research

University security groups (UC Berkeley, ETH Zurich, CISPA, INRIA, etc.) produce foundational vulnerability research. Academic work has distinct advantages:

- **Long time horizons**: Academic researchers can invest months or years in deep analysis without the pressure of bounty deadlines.
- **Publication norms**: Academic conferences (IEEE S&P, USENIX Security, ACM CCS, NDSS) value thorough analysis and novel technique development.
- **Funding**: Research grants (NSF, DoD, EU Horizon) support long-term projects.
- **Credibility**: Academic publications carry weight in standardization bodies, policy circles, and legal proceedings.

The disadvantage: academic research is often slower to produce timely, actionable findings, and the responsible disclosure process in academia can be complicated by the imperative to publish.

### 6.5 Building Reputation

Reputation in the vulnerability research community is built on verifiable, public contributions:

- **CVEs**: The number and severity of CVEs attributed to you is a direct measure of output. A portfolio of high-severity CVEs in widely used software is the most tangible credential.
- **Writeups and blog posts**: Detailed technical writeups demonstrate depth of understanding and communication skill. See: the GPZ blog, ZDI writeups, Project RB's disclosures.
- **Conference talks**: Presenting at Black Hat, DEFCON, CCC, OffensiveCon, and Infiltrate establishes visibility and credibility.
- **Open-source tools**: Creating or maintaining widely used security tools (Burp extensions, Ghidra scripts, fuzzing frameworks) builds reputation among practitioners.
- **CTF performance**: Consistent high rankings on CTFtime, wins at major CTFs, and organizing team membership.
- **Bug bounty rankings**: Top positions on HackerOne and Bugcrowd leaderboards are visible signals of skill.

The most effective career strategy combines several of these: compete in CTFs, publish writeups, find and report vulnerabilities (earning CVEs), present at conferences, and contribute to open source. Each reinforces the others.

---

## Appendix: Key References

- **RFC 9116**: Security.txt — A File Format for Security Policies
- **ISO/IEC 29147**: Vulnerability Disclosure
- **ISO/IEC 30111**: Vulnerability Handling
- **FIRST Coordinated Vulnerability Disclosure Guide** (2023)
- **Google Project Zero Disclosure Policy** (project-zero.gitlab.io)
- **US Vulnerability Equities Process — Charter and Implementation** (whitehouse.gov, 2017)
- **Wassenaar Arrangement — Implementation Document** (wassenaar.org)
- **EU Cyber Resilience Act** — Regulation (EU) 2024/2847
- **Van Buren v. United States**, 593 U.S. ___ (2021)
- **DOJ Charging Policy for CFAA** (2022 revision)

## References

1. [CVE Program — Common Vulnerabilities and Exposures](https://www.cve.org/) — Standardized vulnerability identifier system
2. [CVSS — Common Vulnerability Scoring System](https://www.first.org/cvss/) — Quantitative vulnerability severity measurement
3. [ISO 29147 — Vulnerability Disclosure](https://www.iso.org/standard/72391.html) — International standard for vulnerability disclosure processes
4. [ISO 30111 — Vulnerability Handling](https://www.iso.org/standard/69325.html) — International standard for vulnerability handling processes
5. [CISA — Vulnerability Disclosure Policy](https://www.cisa.gov/vulnerability-disclosure-policy) — US Government VDP template and guidance
6. [Bugcrowd — Vulnerability Disclosure Programs](https://www.bugcrowd.com/) — Coordinated vulnerability disclosure platform
7. [HackerOne — Bug Bounty Platform](https://www.hackerone.com/) — Vulnerability coordination and bug bounty platform
8. [C2 — Council to Secure the Digital Economy](https://www.c2sec.org/) — Vulnerability disclosure framework and best practices
9. [EFF — CFAA Legal Guide](https://www.eff.org/issues/cfaa) — Computer Fraud and Abuse Act legal resource
10. [NIST — Vulnerability Disclosure Framework](https://www.nist.gov/) — National vulnerability disclosure and coordination standards

---

*This document is intended as a reference and does not constitute legal advice. Laws and policies change; consult qualified legal counsel for jurisdiction-specific guidance.*