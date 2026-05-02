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