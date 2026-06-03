# Web Application Security

Comprehensive deep-research track covering the full landscape of web application security — from OWASP Top 10 vulnerability classes through advanced exploitation chains, SSRF, API security, client-side attacks, deserialization, HTTP Request Smuggling, WAF bypass, and future trends. Includes structured payloads, CVE references, testing methodology, and cross-references to the Chromium, Zero-Day, Cloud Security, and Cryptography tracks.

| | |
|---|---|
| **Difficulty** | 🟡 Intermediate → 🔴 Advanced (progressive) |
| **Reading Time** | ~14 hours |
| **Prerequisites** | HTTP protocol, HTML/JavaScript, SQL, one server-side language (Python/Java/PHP/Node), basic networking, Linux CLI |

---

## Prerequisites (Assumed Knowledge)

Before starting this track, you should be comfortable with:

- **HTTP protocol:** Request/response structure, headers, methods, status codes, HTTP/2 framing
- **Web fundamentals:** HTML, CSS, JavaScript (DOM manipulation, fetch API, event handling)
- **Server-side development:** At least one web framework (Django/Flask, Express, Spring Boot, Rails, ASP.NET)
- **SQL:** SELECT, JOIN, UNION, subqueries — enough to understand injection
- **Networking:** DNS, TLS, TCP/IP, load balancers, reverse proxies
- **Linux CLI:** curl, netcat, basic shell scripting
- **Security basics:** The OWASP Top 10 at a conceptual level; basic understanding of XSS, SQLi, CSRF

If you need to refresh any of these, the individual chapters provide sufficient context to follow along, but the track is not a beginner tutorial.

---

## Reading Order

| # | Document | Topic | Est. Time |
|---|----------|-------|-----------|
| 01 | [Web Architecture & Attack Surface](docs/01_web_architecture_attack_surface.md) | Modern web stack, trust boundaries, SOP, CORS, data flow, threat modeling | 45 min |
| 02 | [OWASP Top 10 Deep Dive](docs/02_owasp_top10_deep_dive.md) | Full analysis of OWASP Top 10 (2021): broken access control, crypto failures, injection, insecure design, misconfiguration, vulnerable components, auth failures, data integrity, logging failures, SSRF | 90 min |
| 03 | [Injection Attacks](docs/03_injection_attacks.md) | SQLi (union, blind, time-based, out-of-band, NoSQL), XSS (reflected, stored, DOM, CSP bypass), command injection, SSTI, LDAP/XPATH injection, HTTP Header injection | 75 min |
| 04 | [Authentication & Session Management](docs/04_authentication_session_management.md) | Credential stuffing, brute force, MFA bypass, JWT attacks (none, confusion, jku, kid), OAuth/OIDC flaws, session fixation, password reset, WebAuthn | 60 min |
| 05 | [Server-Side Request Forgery](docs/05_ssrf.md) | SSRF fundamentals, cloud metadata (AWS/GCP/Azure), bypass techniques, DNS rebinding, protocol smuggling, SSRF-to-RCE chains, IMDSv2 | 45 min |
| 06 | [API Security](docs/06_api_security.md) | REST, GraphQL, gRPC security; BOLA/IDOR, mass assignment, excessive data exposure, rate limiting, schema validation, OWASP API Security Top 10 (2019/2023) | 60 min |
| 07 | [Client-Side Security](docs/07_client_side_security.md) | CSP, Trusted Types, SRI, CORS, postMessage, DOM clobbering, prototype pollution, service workers, cookie security, SameSite | 60 min |
| 08 | [Deserialization Vulnerabilities](docs/08_deserialization.md) | Java gadget chains (Commons Collections, Spring, Jackson, XStream), PHP (unserialize, phar), Python (pickle, PyYAML), .NET (ViewState, BinaryFormatter), YSoSerial tools | 60 min |
| 09 | [HTTP Request Smuggling](docs/09_http_request_smuggling.md) | CL-TE, TE-CL, TE-TE, HTTP/2 smuggling, detection methodology, impact (auth bypass, cache poisoning, cache deception), real-world cases | 45 min |
| 10 | [Exploitation Chains](docs/10_exploitation_chains.md) | Chain composition methodology: open redirect → OAuth token theft, SSRF → metadata → account takeover, XSS → CSRF → admin, deserialization → RCE → pivot, real-world chain case studies | 45 min |
| 11 | [WAF Bypass Techniques](docs/11_waf_bypass.md) | Encoding/obfuscation, protocol-level bypasses, parser differentials, HTTP parameter pollution, chunked transfer, HTTP/2, JSON/XML parsing gaps, WAF-as-monitoring philosophy | 45 min |
| 12 | [Web Security Testing Methodology](docs/12_testing_methodology.md) | Reconnaissance (subdomain enum, tech ID, JS analysis, API discovery), automated scanning (DAST, SAST, SCA), manual testing methodology per vulnerability class, burp/ZAP workflows | 60 min |
| 13 | [Hardening & Defense](docs/13_hardening_defense.md) | Application-layer hardening (input validation, output encoding, CSP, trusted types), infrastructure hardening (TLS, WAF posture, rate limiting, network segmentation), container/K8s security | 45 min |
| 14 | [Future Trends & Emerging Threats](docs/14_future_trends.md) | WebAssembly security, supply chain attacks, LLM-generated code vulnerabilities, HTTP/3/QUIC, post-quantum TLS, zero-trust web architecture, browser security evolution | 30 min |
| — | [Final Synthesis Report](WEB_SECURITY_FINAL_REPORT.md) | Comprehensive cross-cutting synthesis of the entire track | 45 min |
| — | [Cheat Sheet](CHEATSHEET.md) | Quick-reference: payloads, CVEs, tools, checklists | — |

---

## Cross-References to Related Tracks

| Topic | Cross-Reference | Connection |
|-------|-----------------|------------|
| Browser exploit chains | [Chromium](../Chromium_Architecture_and_Vulnerability/) | XSS in browser context → V8 type confusion → sandbox escape |
| V8 type confusion → renderer RCE | [Chromium](../Chromium_Architecture_and_Vulnerability/) | Stored XSS as renderer compromise vector |
| Site Isolation / SOP enforcement | [Chromium](../Chromium_Architecture_and_Vulnerability/) | Browser-level enforcement of origin boundaries |
| Spectre / side channels | [Chromium](../Chromium_Architecture_and_Vulnerability/) | Cross-origin read bypass via microarchitectural leaks |
| Zero-day discovery methodology | [Zero-Day](../zero_day/) | Fuzzing web parsers, CodeQL/Semgrep for web codebases |
| Fuzzing for web vulnerabilities | [Zero-Day](../zero_day/) | AFL++/libFuzzer for HTTP parsers, template engines |
| Cloud metadata SSRF | [Cloud Security](../cloud_security/) | IAM roles, metadata endpoints, Kubernetes API from pods |
| Container escape from web app | [Cloud Security](../cloud_security/) | SSRF → K8s API → pod creation → host mount |
| Cryptographic failures | [Cryptography](../cryptography/) | JWT algorithm attacks, TLS misconfiguration, key management |
| Post-quantum TLS | [Cryptography](../cryptography/) | ML-KEM/ML-DSA migration for HTTPS |
| Supply chain compromise | [Chromium](../Chromium_Architecture_and_Vulnerability/) | npm/PyPI dependency attacks, SRI, Sigstore |

---

## Learning Paths by Goal

### Web Penetration Tester

Focus on practical exploitation, testing methodology, and report writing:

> **02** (OWASP Top 10) → **03** (Injection) → **04** (Auth) → **05** (SSRF) → **06** (API Security) → **09** (Request Smuggling) → **10** (Exploitation Chains) → **11** (WAF Bypass) → **12** (Testing Methodology) → **CHEATSHEET.md**

Emphasis: Payloads, testing methodology, WAF bypass, and chain composition. Skim chapters 01 (architecture) and 07 (client-side) for context, deep-read everything else.

### Bug Bounty Hunter

Focus on high-impact, frequently-rewarded vulnerability classes and chaining:

> **03** (Injection) → **05** (SSRF) → **06** (API Security — BOLA focus) → **09** (Request Smuggling) → **10** (Exploitation Chains) → **11** (WAF Bypass) → **04** (Auth — JWT/OAuth focus) → **08** (Deserialization — Java/.NET focus) → **12** (Testing Methodology — recon focus)

Emphasis: BOLA, SSRF (cloud metadata), auth bypass, and request smuggling are the highest-paying bug bounty categories. Chain composition separates $500 findings from $10,000 findings.

### Application Security Engineer

Focus on hardening, secure development lifecycle, and defense-in-depth:

> **01** (Architecture) → **02** (OWASP Top 10 — all mitigation sections) → **13** (Hardening) → **07** (Client-Side Security — CSP, Trusted Types, SRI) → **06** (API Security — defense patterns) → **04** (Auth — session management, MFA, WebAuthn) → **12** (Testing — SAST/DAST integration) → **14** (Future Trends) → **08** (Deserialization — detection and prevention)

Emphasis: Secure defaults, CSP deployment, CI/CD security scanning, SAST/DAST integration, and understanding how to detect and prevent each vulnerability class during development.

---

## Key References

- **OWASP Top 10 (2021):** https://owasp.org/Top10/
- **OWASP API Security Top 10 (2023):** https://owasp.org/API-Security/
- **PortSwigger Web Security Academy:** https://portswigger.net/web-security
- **HackerOne Top 10 (by bounty):** IDOR, XSS, information disclosure, SSRF, auth bypass
- **James Kettle — HTTP Request Smuggling (2019):** https://portswigger.net/research/http-desync-attacks
- **Orange Tsai — SSRF, SSRF + Deserialization, ProxyShell:** https://blog.orange.tw/
- **Web Security Academy Labs:** https://portswigger.net/web-security/learning-path

---

## References

1. OWASP Foundation. "OWASP Top 10:2021." https://owasp.org/Top10/
2. OWASP Foundation. "OWASP API Security Top 10 (2023)." https://owasp.org/API-Security/
3. PortSwigger Ltd. "Web Security Academy." https://portswigger.net/web-security
4. Kettle, J. "HTTP Desync Attacks: Request Smuggling Reborn." PortSwigger Research, 2019. https://portswigger.net/research/http-desync-attacks
5. Orange Tsai. "A New Attack Surface on SSRF." Black Hat USA, 2019. https://blog.orange.tw/
6. MITRE Corporation. "CWE/SANS Top 25 Most Dangerous Software Weaknesses." https://cwe.mitre.org/top25/
7. RFC 9110-9114. "HTTP Core Specifications." IETF, 2022.
8. RFC 9000. "QUIC: A UDP-Based Multipath and Secure Transport." IETF, 2021.
9. RFC 6455. "The WebSocket Protocol." IETF, 2011.
10. Chromium Project. "Chromium Security Architecture." https://www.chromium.org/Home/chromium-security/
11. NIST. "SP 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management." https://pages.nist.gov/800-63-3/sp800-63b.html

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **CVE-2025-29927: Next.js Middleware Authorization Bypass** *(2025-03)* — A critical (CVSS 9.1) flaw in the Next.js framework lets attackers bypass middleware-based authorization by spoofing the internal x-middleware-subrequest HTTP header, which the framework blindly trusted to prevent recursive middleware loops. It affects Next.js versions 11.1.4 through those before 12.3.5, 13.5.9, 14.2.25, and 15.2.3, allowing access to protected/admin routes and enabling cache poisoning or DoS in some cases. The fix strips the header; reverse proxies can also remove it at the edge. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- **CVE-2025-55182 (React2Shell): Pre-Auth RCE in React Server Components** *(2025-12)* — A maximum-severity (CVSS 10.0) unauthenticated remote code execution flaw in React Server Components that unsafely deserializes payloads sent to Server Function endpoints, affecting react-server-dom-* packages (React 19.0.0-19.2.0) and Next.js 15.0.0 through 16.0.x. Disclosed by Meta on December 3, 2025 and added to CISA's Known Exploited Vulnerabilities catalog on December 5, 2025, it was quickly weaponized with ~145 public PoCs (including WAF bypasses) and mass-scanning, drawing comparisons to Log4Shell. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)

### Incidents & In-the-Wild Exploitation

- **ToolShell: SharePoint Zero-Day CVE-2025-53770 Mass-Exploited** *(2025-07)* — A critical (CVSS 9.8) deserialization-of-untrusted-data flaw in on-premises Microsoft SharePoint Server (2016/2019/Subscription Edition), published July 19, 2025 and immediately added to CISA's KEV catalog. Dubbed 'ToolShell' (chained with a patch-bypass CVE-2025-53771), it gave unauthenticated attackers RCE; by late July over 4,600 compromise attempts hit 300+ organizations, with Microsoft attributing activity to China-linked actors Linen Typhoon, Violet Typhoon, and Storm-2603, some deploying Warlock ransomware. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)

### Research

- **PortSwigger Top 10 Web Hacking Techniques of 2025** *(2026-02)* — The 19th annual community-ranked list of the most significant web security research, drawn from 63 nominations. The #1 technique was Vladislav Korchagin's 'Successful Errors: New Code Injection and SSTI Techniques' (error-based blind SSTI exploitation with polyglot detection and an open-source toolkit), followed by ORM Leak expansion, a novel HTTP-redirect-loop SSRF technique by Shubham Shah, Unicode normalization exploitation, and SOAPwn (.NET WSDL/HTTP-client RCE), with side-channels and XS-leaks recurring as primitives. [[source]](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)

### Tools

- **Shadow Repeater: AI-Enhanced Manual Web Testing for Burp Suite** *(2025-02)* — Released by PortSwigger (Gareth Heyes) on February 20, 2025, Shadow Repeater is an open-source Burp Suite extension that monitors requests sent through Burp Repeater, identifies changing parameters, and uses AI to automatically generate and test payload variations in the background. It surfaces unconventional findings such as novel XSS vectors, path traversal, and email-splitting bugs, reporting them via Organizer, and is distributed through the BApp Store for the Burp Pro Early Adopter channel. [[source]](https://portswigger.net/research/shadow-repeater-ai-enhanced-manual-testing)

### Standards & Frameworks

- **OWASP Top 10:2025 Adds Supply Chain and Exceptional-Conditions Categories** *(2025)* — The 8th edition of the OWASP Top 10 keeps Broken Access Control at #1 and introduces two new categories: A03:2025 Software Supply Chain Failures (expanding the old 'Vulnerable and Outdated Components' to dependencies, build systems, and distribution, and ranked the top concern by 50% of survey respondents) and A10:2025 Mishandling of Exceptional Conditions (24 CWEs on improper error handling and fail-open logic). SSRF was consolidated and the list shifts focus from symptoms toward root causes. [[source]](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
