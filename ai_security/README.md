# AI/ML Security & Adversarial AI

A comprehensive deep-research track covering the security landscape of artificial intelligence and machine learning systems — from adversarial attacks and data poisoning to LLM security, AI red teaming, agent security, and infrastructure hardening.

## Track Contents

### Core Documents

| # | Document | Topic | Words |
|---|----------|-------|-------|
| 01 | [AI/ML Security Landscape](docs/01_ai_ml_security_landscape.md) | Attack taxonomy, threat model, OWASP ML Top 10, NIST AI RMF, EU AI Act | ~3500 |
| 02 | [Adversarial ML](docs/02_adversarial_ml.md) | FGSM, PGD, CW attacks, physical-world examples, defenses, TRADES, certified robustness | ~3500 |
| 03 | [Data Poisoning](docs/03_data_poisoning.md) | Label flipping, BadNets, TrojanNN, clean-label attacks, spectral signatures, supply chain | ~3500 |
| 04 | [Model Attacks & Privacy](docs/04_model_attacks_privacy.md) | Model extraction, inversion, membership inference, gradient leakage, DP-SGD, Opacus | ~3500 |
| 05 | [LLM Security](docs/05_llm_security.md) | Prompt injection, jailbreaking, guardrails bypass, data exfiltration, RAG security, red teaming | ~3500 |
| 06 | [AI Red Teaming](docs/06_ai_red_teaming.md) | Microsoft AI red team, adversarial simulation, PyRIT, automated red teaming, disclosure | ~3000 |
| 07 | [AI Agent Security](docs/07_ai_agent_security.md) | Tool use attack surface, sandbox escapes, context manipulation, multi-agent security | ~3000 |
| 08 | [AI Infrastructure Security](docs/08_ai_infrastructure_security.md) | GPU attacks, model serving, registries, pickle deserialization, cloud AI, supply chain | ~3500 |
| 09 | [AI Defense & Mitigations](docs/09_ai_defense_mitigations.md) | Adversarial training, certified robustness, DP, guardrails, monitoring, confidential computing | ~3500 |
| 10 | [Case Studies & Future](docs/10_ai_security_case_studies_future.md) | Tay, GPT-2 extraction, deepfakes, AI-powered fuzzing, regulation, future directions | ~3000 |

### Synthesis & Reference

| Document | Description |
|----------|-------------|
| [AI Security Final Report](AI_SECURITY_FINAL_REPORT.md) | 4000+ word synthesis of the entire track |
| [Cheat Sheet](CHEATSHEET.md) | Attack code templates, LLM testing checklist, red team flowchart, tool reference, CVEs |

## Key Themes

1. **Prompt injection is the new XSS** — untrusted data interpreted as instructions in instruction-following models
2. **Adversarial examples are eternal** — no complete defense exists; adversarial training is the best empirical approach
3. **Data poisoning is the ML supply chain attack** — backdoored models from Hugging Face, clean-label attacks
4. **Agent security is the frontier** — prompt injection with tool access = arbitrary code execution
5. **AI red teaming is becoming standard** — PyRIT, Microsoft, NIST AI RMF, EU AI Act requirements

## Cross-References

- **Agentic AI** (`../agentic_AI/`) — Agent architectures and security implications
- **Web Security** (`../web_security/`) — Prompt injection parallels to XSS/injection attacks
- **Cloud Security** (`../cloud_security/`) — Cloud AI service vulnerabilities
- **Supply Chain** (`../supply_chain_security/`) — Model and dependency supply chain attacks

## Recommended Reading Order

1. Start with `docs/01_ai_ml_security_landscape.md` for the attack taxonomy and threat model
2. Read `docs/02_adversarial_ml.md` and `docs/03_data_poisoning.md` for classical ML attacks
3. Read `docs/05_llm_security.md` for LLM-specific attacks (prompt injection, jailbreaking)
4. Read `docs/07_ai_agent_security.md` for agent security (the highest-impact emerging threat)
5. Read `docs/09_ai_defense_mitigations.md` for defensive techniques
6. Read `AI_SECURITY_FINAL_REPORT.md` for the complete synthesis

## Tools Referenced

- **CleverHans / ART** — Adversarial attack and defense libraries
- **AutoAttack** — Standardized robustness evaluation
- **PyRIT** — Microsoft LLM red teaming framework
- **Opacus** — PyTorch differential privacy
- **safetensors** — Safe model serialization
- **NeMo Guardrails / Llama Guard** — LLM safety guardrails
- **RobustBench** — Adversarial robustness leaderboard
- **MITRE ATLAS** — Adversarial threat landscape for AI

## References

1. Goodfellow, I., Shlens, J., & Szegedy, C. (2015). "Explaining and Harnessing Adversarial Examples." *ICLR*.
2. Carlini, N., & Wagner, D. (2017). "Towards Evaluating the Robustness of Neural Networks." *IEEE S&P*.
3. Madry, A., et al. (2018). "Towards Deep Learning Models Resistant to Adversarial Attacks." *ICLR*.
4. Carlini, N., et al. (2021). "Extracting Training Data from Large Language Models." *USENIX Security*.
5. Carlini, N., et al. (2023). "Quantifying Memorization in Neural Language Models." *ICML*.
6. OWASP (2023). "OWASP Top 10 for Machine Learning." https://owasp.org/www-project-machine-learning-security-top-10/
7. OWASP (2023). "OWASP Top 10 for LLM Applications." https://owasp.org/www-project-top-10-for-large-language-model-applications/
8. NIST (2023). "Artificial Intelligence Risk Management Framework (AI RMF 1.0)." NIST AI 100-1. https://doi.org/10.6028/NIST.AI.100-1
9. European Parliament (2024). "Regulation (EU) 2024/1689 — Artificial Intelligence Act." *Official Journal of the European Union*.
10. Microsoft (2023). "PyRIT: Python Risk Identification Tool for LLMs." https://github.com/microsoft/pyrit
11. NVIDIA (2023). "NeMo Guardrails: Programmable Guardrails for LLMs." https://github.com/NVIDIA/NeMo-Guardrails
12. Croce, F., & Hein, M. (2020). "Reliable Evaluation of Adversarial Robustness with an Ensemble of Diverse Attacks." *ICML*.
13. Papernot, N., et al. (2016). "CleverHans: An Adversarial Example Library." https://github.com/cleverhans-lab/cleverhans
14. Tramer, F., et al. (2016). "Stealing Machine Learning Models via Prediction APIs." *USENIX Security*.
15. Gu, T., et al. (2019). "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain." *IEEE Access*.
16. Anthropic (2023). "Constitutional AI: Harmlessness from AI Feedback." *arXiv:2212.08073*.
17. RobustBench (2023). "Adversarial Robustness Leaderboard." https://robustbench.github.io/
18. MITRE (2023). "ATLAS: Adversarial Threat Landscape for AI Systems." https://atlas.mitre.org
19. Opacus (2023). "Opacus: PyTorch Differential Privacy Library." https://opacus.ai
20. Hugging Face (2023). "safetensors: Safe Model Serialization." https://github.com/huggingface/safetensors

---

## Recent Developments (2025–2026)

*Independently verified against primary sources (NVD / vendor advisories / papers) during the 2026-06 accuracy audit. Each CVE was confirmed to exist with the stated characterization.*

### Vulnerabilities (CVEs)

- **EchoLeak (CVE-2025-32711): first real-world zero-click prompt injection in a production LLM system** *(2025-06)* — Aim Labs disclosed a zero-click indirect prompt injection in Microsoft 365 Copilot that exfiltrated organizational data (chat logs, OneDrive, SharePoint, Teams content) via a single crafted email with no user interaction. The chain bypassed Microsoft's XPIA classifier, evaded link redaction using reference-style Markdown, and abused auto-fetched images plus a CSP-allowed Teams proxy. Microsoft rated it 9.3 critical (NVD CVSS 7.5, CWE-74) and patched it server-side; NVD published it June 11, 2025. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-32711)
- **CVE-2025-6514: critical RCE in mcp-remote MCP proxy (CVSS 9.6)** *(2025-07)* — JFrog Security Research disclosed an OS command injection in mcp-remote (versions 0.0.5 to 0.1.15) that achieves arbitrary command execution on a client when it connects to a malicious or untrusted MCP server. The flaw stems from unsafe handling of a crafted authorization_endpoint URL during OAuth setup via the npm 'open' package, giving full shell control on Windows. It was disclosed July 9, 2025 and fixed in version 0.1.16, marking one of the first full client compromises via the Model Context Protocol ecosystem. [[source]](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- **CVE-2025-68664 (LangGrinch): serialization injection in LangChain Core** *(2025-12)* — A CWE-502 deserialization flaw in LangChain's dumps()/dumpd() functions fails to escape dictionaries containing 'lc' keys, letting user- or LLM-controlled data be rehydrated as legitimate LangChain objects on load. This enables extraction of sensitive secrets/environment variables and unsafe object instantiation in AI workflows. NVD rated it 8.2 HIGH (vendor 9.3 critical), published December 23, 2025; fixed in LangChain 0.3.81 and 1.2.5. [[source]](https://nvd.nist.gov/vuln/detail/CVE-2025-68664)

### Incidents & In-the-Wild Exploitation

- **NullifAI: malicious ML models on Hugging Face evade Picklescan via broken pickle format** *(2025-02)* — In February 2025 ReversingLabs identified two malicious PyTorch models on Hugging Face that smuggled reverse-shell payloads inside pickle files. Attackers compressed the models with 7z instead of the expected ZIP and used corrupted/truncated pickle streams so that torch.load() still executed the payload while Picklescan failed to flag it, a defense-evasion technique dubbed nullifAI. The incident underscored the systemic risk of pickle-based model serialization in the ML supply chain. [[source]](https://www.reversinglabs.com/press-releases/reversinglabs-identifies-novel-ml-malware-hosted-on-leading-hugging-face-ai-model-platform)

### Techniques

- **Prompt injection as a code-execution primitive: RCE in AI agent frameworks (Semantic Kernel)** *(2026-05)* — Microsoft security research demonstrated that prompt injection can cross from a content-safety problem into remote code execution in agent frameworks, disclosing two Semantic Kernel CVEs. CVE-2026-26030 abuses unsafe string interpolation using eval() in filter functions (with blocklist bypass), and CVE-2026-25592 exploits an unvalidated file-writing tool (SessionsPythonPlugin) to drop a payload into the Windows Startup folder. The research, published May 7, 2026, frames these as architectural agent-design flaws rather than model defects. [[source]](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)

### Standards & Frameworks

- **NIST AI 100-2 E2025: updated adversarial machine learning taxonomy with GenAI coverage** *(2025-03)* — NIST finalized the 2025 edition of 'Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations' (NIST AI 100-2 E2025) on March 24, 2025, updating the 2023 version. The revision integrates generative AI throughout, adding attack and mitigation taxonomy specific to large language models, RAG systems, and agent-based deployments, alongside the existing evasion, poisoning, and privacy categories. It provides unified terminology intended for those who design, evaluate, and govern AI systems. [[source]](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
