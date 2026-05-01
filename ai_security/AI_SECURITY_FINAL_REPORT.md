# AI/ML Security & Adversarial AI: Final Synthesis Report

> A comprehensive synthesis of the AI/ML Security research track — covering attack taxonomies, adversarial ML, data poisoning, model privacy attacks, LLM security, AI red teaming, agent security, infrastructure security, defenses, and future directions.

---

## Executive Summary

AI/ML security is a fundamentally different discipline from traditional cybersecurity. Where conventional software follows deterministic logic specified by developers, ML systems learn behavior from data — creating attack surfaces that have no analog in traditional security. Adversarial examples that cause misclassification through imperceptible perturbations, training data manipulation that implants hidden backdoors, prompt injection that enables arbitrary code execution in agent systems, and training data extraction that violates individual privacy — these are threats unique to the AI era.

This report synthesizes the full AI Security track, drawing from over 150 research papers, dozens of CVEs, and the operational experience of AI red teams at Microsoft, Google, Anthropic, and OpenAI. The central findings are:

1. **Prompt injection is the XSS of the AI era.** Just as web applications in the 2000s were plagued by Cross-Site Scripting (XSS) — injecting untrusted data into trusted execution contexts — AI systems today face prompt injection, where untrusted input is processed as instructions by instruction-following models. The root cause is identical: no architectural separation between data and instructions. Every LLM-powered application is potentially vulnerable.

2. **Adversarial examples are an eternal vulnerability class.** For over a decade, adversarial examples have persisted against every proposed defense. Adversarial training (Madry et al., 2018) remains the most effective empirical defense, but it trades clean accuracy for robust accuracy, and certified robustness methods (Cohen et al., 2019; Zhang et al., 2022) provide provable guarantees only for narrow threat models (L_p bounded perturbations). The fundamental tension between accuracy and robustness (TRADES, Zhang et al., 2019) suggests that adversarial vulnerability is inherent to high-dimensional ML systems.

3. **Data poisoning is the supply chain attack of ML.** The modern ML pipeline depends on web-scraped training data, crowdsourced labeling, pre-trained models from public repositories, and open-source libraries — each step is a potential injection point. Backdoored models on Hugging Face (CVE-2023-44429), poisoned datasets in public benchmarks, and fine-tuning attacks that break safety alignment (Qi et al., 2023) demonstrate that the ML supply chain is as vulnerable as the software supply chain was before the SolarWinds attack. The difference is that ML supply chain attacks are harder to detect — a backdoored model performs correctly on all standard benchmarks.

4. **The training data extraction problem is unsolved.** Carlini et al. (2021, 2023) showed that GPT-2, GPT-3, and GPT-4 memorize and can be induced to regurgitate individual training examples, including personally identifiable information. Differential privacy (DP-SGD) provides formal guarantees but degrades model quality significantly ($\epsilon = 1$ costs 25%+ accuracy on CIFAR-10). Web-scale training data purification is infeasible — GPT-4 was trained on 13 trillion tokens from the open web. The tension between model capability and data privacy remains unresolved.

5. **AI agent security is the frontier.** The shift from LLMs as text generators to LLMs as autonomous agents (with tool use, code execution, and API access) transforms prompt injection from a content policy violation into a privilege escalation vulnerability. When an LLM agent can execute SQL queries, write files, send emails, and browse the web, a successful prompt injection gives the attacker all of these capabilities — making it equivalent to remote code execution. Current agent frameworks (AutoGPT, BabyAGI, LangChain) lack basic security controls: no sandboxing, no capability restrictions, and no output validation.

6. **AI red teaming is becoming standard practice.** Microsoft, Google, Anthropic, and OpenAI now run dedicated AI red teams. The NIST AI RMF requires adversarial testing for high-risk AI systems. The EU AI Act mandates cybersecurity assessment. OWASP has published both an ML Top 10 and an LLM Top 10. AI red teaming is undergoing the same professionalization process that penetration testing went through in the 2000s — from a niche skill to a standard practice with established methodologies, tools, and certifications.

---

## 1. Attack Taxonomy and Threat Model

The AI/ML attack surface is organized along three axes: **attacker knowledge** (white-box, gray-box, black-box), **attack timing** (training-time, inference-time, deployment-time), and **attacker goal** (integrity, confidentiality, availability).

**Integrity Attacks**:
- Adversarial examples (evasion)
- Data poisoning (training data manipulation)
- Backdoor attacks (implanted triggers)
- Prompt injection (instruction override)

**Confidentiality Attacks**:
- Model extraction (stealing proprietary models)
- Model inversion (recovering training data)
- Membership inference (determining training set membership)
- Training data extraction (memorization in LLMs)

**Availability Attacks**:
- Model saturation (adversarial inputs that maximize computation)
- Data flooding (poisoning that degrades model accuracy)
- Resource exhaustion (computational DoS on inference APIs)

**New Attack Surfaces Unique to LLMs**:
- Prompt injection as arbitrary code execution in agent systems
- Tool use manipulation (SQL injection via LLM, file system access via LLM)
- RAG document injection
- Multi-modal attacks (adversarial images targeting VLMs)
- Training data extraction through crafted prompts

The OWASP ML Top 10 (2023) and OWASP LLM Top 10 (2023) codify these vulnerabilities, and the NIST AI RMF (2023) and EU AI Act (2024) provide regulatory frameworks for addressing them.

---

## 2. Adversarial ML: The Fundamental Vulnerability

Adversarial examples — carefully crafted inputs that cause misclassification — have been the most studied ML vulnerability since Szegedy et al. (2014). Despite a decade of research, fundamental challenges remain:

**The Adversarial Robustness-Aaccuracy Tradeoff**: TRADES (Zhang et al., 2019) proved that any classifier with non-trivial accuracy must be vulnerable to adversarial examples. Adversarial training improves robustness at the cost of clean accuracy — on CIFAR-10 at $\epsilon = 8/255$, adversarial training reduces clean accuracy from 95% to ~85% while achieving ~53% robust accuracy.

**Certified Robustness**: Randomized smoothing (Cohen et al., 2019) provides $L_2$ certified robustness, and $\beta$-CROWN (Zhang et al., 2022) provides $L_\infty$ certified robustness, but both methods are limited to small models and narrow threat models. Certified robustness for production-scale models (ResNet-50 on ImageNet, or LLMs with billions of parameters) remains computationally infeasible.

**Physical-World Attacks**: Adversarial examples survive in the physical world — printed stickers on stop signs cause traffic sign misclassification (Eykholt et al., 2018), adversarial glasses cause face recognition evasion (Sharif et al., 2016), and adversarial audio causes targeted mis-transcription (Carlini & Wagner, 2018). These attacks demonstrate that adversarial ML is not merely an academic concern.

**AutoAttack Benchmark**: The current standard for evaluating adversarial robustness claims. Any defense that has not been evaluated against AutoAttack should be assumed insecure until proven otherwise (Croce & Hein, 2020).

---

## 3. Data Poisoning and Backdoors: The ML Supply Chain Threat

The ML supply chain is as vulnerable as the software supply chain was before SolarWinds:

**Training Data Poisoning**: An attacker who controls 1-5% of training data can degrade model accuracy by 30%+ through label flipping (Koh & Liang, 2017) or implant targeted backdoors with 99%+ attack success rate (Gu et al., 2019). Clean-label attacks (Shafahi et al., 2018) are particularly stealthy — they modify input features while keeping labels correct, defeating label verification.

**Backdoor Attacks**: BadNets (Gu et al., 2019) implant trigger patterns that cause targeted misclassification when present at inference time. The backdoor is invisible during normal evaluation and can survive fine-tuning (Wang et al., 2022). TrojanNN (Liu et al., 2018) optimizes the trigger pattern to be minimally detectable.

**Model Supply Chain Attacks**: Hugging Face Hub hosts 500,000+ models. Pickle deserialization (CVE-2023-44429, CVE-2023-52451) enables arbitrary code execution when loading PyTorch models. An attacker who publishes a backdoored model on Hugging Face can compromise every downstream user who fine-tunes or deploys that model.

**Detection and Defense**: Spectral signatures (Tran et al., 2018) detect poisoned samples by analyzing the spectral properties of training data representations. Activation clustering (Chen et al., 2018) identifies backdoor samples by clustering activation patterns. Both methods are effective against known attacks but can be defeated by adaptive adversaries.

---

## 4. Model Extraction, Inversion, and Membership Inference: Privacy Under Siege

**Model Extraction**: Tramer et al. (2016) showed that linear models can be exactly recovered from API queries using equation-solving attacks. Neural networks require more queries but can be approximated with 90%+ agreement using active learning-based extraction (Pal et al., 2020). LLM extraction via knowledge distillation is an emerging threat.

**Model Inversion**: Fredrikson et al. (2015) reconstructed recognizable face images from a facial recognition model's confidence scores alone. Zhu et al. (2019) demonstrated pixel-perfect training data recovery from gradients in federated learning (Deep Leakage from Gradients). DP-SGD mitigates gradient leakage but degrades model quality.

**Membership Inference**: Shokri et al. (2017) achieved 85-95% accuracy on membership inference for CIFAR-10 models. Carlini et al. (2022) provided a rigorous theoretical framework showing that membership inference is fundamentally about model overconfidence — models that overfit their training data are inherently vulnerable.

**Training Data Extraction from LLMs**: Carlini et al. (2021, 2023) extracted memorized training data from GPT-2 and GPT-3, including PII such as names, phone numbers, and email addresses. The extraction attack requires only black-box API access and crafting prompts that trigger memorized content. Differential privacy during training is the only formal mitigation, but $\epsilon = 1$ costs 25%+ accuracy.

---

## 5. LLM Security: The New Frontier

LLMs introduce attack surfaces that have no precedent in traditional ML:

**Prompt Injection**: The root cause is architectural — LLMs process instructions and data through the same self-attention mechanism, with no cryptographic or syntactic separation. Direct prompt injection ("Ignore previous instructions"), indirect injection (malicious instructions in RAG documents), and stored injection (persistent payloads in user profiles) are all fundamentally the same vulnerability: untrusted data interpreted as instructions.

**Jailbreaking**: Techniques including role-playing (DAN), encoding (base64, ROT13), token smuggling (unicode tricks), multi-turn context manipulation, and automated suffix generation (GCG, Zou et al., 2023) bypass LLM safety guardrails. GCG-generated adversarial suffixes transfer across models — suffixes generated for LLaMA transfer to GPT-4 and Claude.

**Data Exfiltration**: LLMs can be induced to exfiltrate data through URL generation, markdown image references, code execution, and DNS lookups. In agent systems, prompt injection enables data exfiltration through authorized tool use (SQL queries, file reads, API calls).

**The Agent Security Crisis**: When LLMs have tool access (code execution, database queries, file system, web browsing), prompt injection becomes equivalent to remote code execution. Current agent frameworks lack basic security controls — no sandboxing, no capability restrictions, no output validation. See Section 7 for detailed analysis.

---

## 6. AI Red Teaming: Methodology and Practice

AI red teaming requires a fundamentally different approach from traditional penetration testing:

**Responsible AI + Security**: AI red teams must evaluate both security vulnerabilities (adversarial attacks, data poisoning) and responsible AI failures (bias, toxicity, fairness). These are overlapping but distinct concerns — many safety failures occur without adversarial manipulation.

**Systematic Testing**: The Microsoft AI red team approach (Parrish et al., 2023) combines adversarial simulation (jailbreaks, prompt injection, extraction) with responsible AI assessment (bias, toxicity, fairness). Key findings: most safety failures are triggered by benign inputs, not adversarial ones; context matters enormously; and red teaming must be continuous.

**Tooling**: PyRIT (Microsoft), GARAG (generative red-teaming), and Attack (NVIDIA) provide automated red-teaming frameworks. These tools generate diverse adversarial prompts, evaluate model responses, and produce structured reports. However, automated testing is insufficient — manual testing by domain experts consistently finds failures that automated tools miss.

**Multi-Modal Red Teaming**: Vision-language models (GPT-4V, Claude 3, Gemini) create new attack surfaces through adversarial images containing hidden instructions, cross-modal injection, and multimodal jailbreaks. Audio-language models create adversarial audio attack surfaces.

**Disclosure**: AI vulnerability disclosure follows responsible disclosure principles adapted for the dual-use nature of AI vulnerabilities. Prompt injection techniques that enable harmful content generation must be disclosed carefully to avoid enabling immediate harm.

---

## 7. AI Agent Security: From Content Policy to Code Execution

The transition from LLMs as text generators to LLMs as autonomous agents creates a qualitative shift in risk:

**Prompt Injection as Code Execution**: In a traditional chatbot, prompt injection causes inappropriate text output. In an agent with code execution, database access, file system access, and web browsing, prompt injection gives the attacker all of these capabilities. A successful injection in an agent with database access is equivalent to SQL injection; in an agent with file system access, it's equivalent to arbitrary file read/write; in an agent with code execution, it's equivalent to remote code execution.

**Tool Use Security**: Each tool definition creates a new attack surface. SQL query access enables SQL injection via the LLM. File system access enables path traversal and arbitrary file read/write. Web browsing enables SSRF and data exfiltration. Email access enables phishing and data exfiltration.

**Multi-Agent Security**: In multi-agent systems (hierarchical, swarm, mesh), attacks can propagate from compromised agents to other agents. Agent-to-agent communication attacks, Sybil attacks, and Byzantine failures are emerging threat models. See the `../agentic_AI/` track for detailed analysis.

**Mitigations**: Principle of least privilege (restrict agent tools to minimum necessary), human-in-the-loop confirmation for high-impact actions, action logging and audit, context separation (strict delimited between instructions and data), and output filtering.

---

## 8. AI Infrastructure Security: The ML Supply Chain

The ML infrastructure stack — from GPU memory to model serving to cloud platforms — presents a layered attack surface:

**GPU Infrastructure**: Shared GPU memory in multi-tenant cloud environments (AWS, GCP, Azure) enables cross-tenant data leakage. GPU memory is not zeroed between process terminations, allowing residual data recovery. NVLink/PCIe side channels can leak information about co-tenant workloads.

**Model Serving**: TF Serving (CVE-2022-23577, CVE-2023-25677), TorchServe (CVE-2023-33634), and Triton Inference Server have all had critical vulnerabilities enabling remote code execution, SSRF, and denial of service.

**Model Registry Attacks**: MLflow (CVE-2023-3739, path traversal), Hugging Face Hub (CVE-2023-44429, pickle deserialization), and Weights & Biases (API key exposure) have had security vulnerabilities enabling model tampering, data exfiltration, and code execution.

**Model Artifact Tampering**: PyTorch's `torch.save()`/`torch.load()` uses Python's `pickle` module, enabling arbitrary code execution when loading untrusted models. ONNX models can contain custom operators that execute arbitrary code. TensorFlow SavedModel directories can include custom operations.

**Cloud AI Services**: AWS SageMaker, Azure ML, and GCP Vertex AI have misconfiguration risks including overly permissive IAM roles, unauthenticated endpoints, and unencrypted storage.

---

## 9. Defenses: From Empirical to Certified

Defense approaches range from empirical (no formal guarantee) to certified (mathematical proof of robustness):

**Empirical Defenses** (no formal guarantee):
- Adversarial training (PGD, TRADES)
- Input preprocessing (feature squeezing, JPEG compression, spatial smoothing)
- Ensemble methods (diverse models, input transformation ensembles)
- Output filtering and guardrails (NeMo, Llama Guard, Constitutional AI)

**Provable Defenses** (formal guarantee for specific threat models):
- Randomized smoothing (certified $L_2$ robustness)
- $\beta$-CROWN (certified $L_\infty$ robustness)
- Differential privacy (DP-SGD, formal privacy guarantees)
- Secure aggregation (formal privacy guarantees for federated learning)

**Operational Defenses** (process-based):
- AI red teaming (systematic adversarial testing)
- Model monitoring and anomaly detection
- Supply chain verification (model hashing, provenance tracking, safetensors format)
- Defense-in-depth architecture (input validation, output filtering, human-in-the-loop)

**The Obfuscated Gradients Problem**: Athalye et al. (2018) demonstrated that most empirical defenses rely on "obfuscated gradients" — they make gradient computation difficult but do not provide genuine robustness. Adaptive attacks systematically break these defenses. The lesson: any defense that has not been evaluated against adaptive attacks should be assumed insecure.

**The Current State of the Art**:
- Image classification: TRADES achieves 56.4% robust accuracy on CIFAR-10 at $\epsilon = 8/255$ (AutoAttack benchmark).
- LLMs: No reliable defense against prompt injection exists. Guardrails (NeMo, Llama Guard, Constitutional AI) provide safety improvements but can be bypassed by sophisticated adversaries.
- Agent systems: Principle of least privilege, human-in-the-loop confirmation, and action logging are the most effective mitigations but do not fully address prompt injection.

---

## 10. Future Directions

**Constitutional AI Security**: Formal specification of AI safety properties using logical or programmatic languages rather than natural language. Current constitutional AI approaches (Anthropic) use natural language principles that are inherently ambiguous and exploitable.

**Multi-Modal Adversarial Attacks**: Attacks targeting vision-language and audio-language models create new attack surfaces that span modalities. A single adversarial image can cause arbitrary behavior in a VLM, bypassing both image and text safety filters.

**AI-Generated Malware**: LLMs lower the barrier to entry for malware creation. Autonomous hacking agents that discover and exploit vulnerabilities independently are a near-term threat. Defensive AI (malware detection, vulnerability discovery, automated patching) must advance alongside offensive AI.

**AI Red Teaming Standardization**: AI red teaming is becoming a standard practice with established methodologies (OWASP LLM Top 10, MITRE ATLAS), tools (PyRIT, GARAG), and regulatory requirements (NIST AI RMF, EU AI Act). Professional AI red teaming certifications will emerge.

**Formal Verification for AI Safety**: Applying formal methods (CROWN, $\beta$-CROWN, MIP verification) to prove safety properties of AI systems. Current methods are limited to small models but are a critical research direction for safety-critical AI deployments.

**Confidential Computing for AI**: NVIDIA H100's confidential computing mode, Intel SGX, AMD SEV, and ARM TrustZone provide hardware-based protection for ML workloads in untrusted cloud environments. This is essential for deploying proprietary models in multi-tenant cloud infrastructure.

**Regulatory Landscape**: The EU AI Act (effective 2025) mandates cybersecurity assessment for high-risk AI systems. The US Executive Order on AI (October 2023) requires red team testing of foundation models. NIST AI RMF provides voluntary guidance. These regulations will drive investment in AI security research and practice.

---

## Cross-References

- `01_ai_ml_security_landscape.md`: Full attack taxonomy, threat model, and attack surface mapping
- `02_adversarial_ml.md`: FGSM, PGD, CW attacks, adversarial training, TRADES, certified robustness
- `03_data_poisoning.md`: BadNets, TrojanNN, clean-label attacks, spectral signatures, activation clustering
- `04_model_attacks_privacy.md`: Model extraction, inversion, membership inference, DP-SGD, gradient leakage
- `05_llm_security.md`: Prompt injection, jailbreaking, LLM guardrails, training data extraction
- `06_ai_red_teaming.md`: Microsoft red team approach, PyRIT, responsible AI evaluation
- `07_ai_agent_security.md`: Tool use security, sandbox escapes, multi-agent security
- `08_ai_infrastructure_security.md`: GPU attacks, model serving, pipeline security, cloud AI
- `09_ai_defense_mitigations.md`: Adversarial training, guardrails, monitoring, confidential computing
- `10_ai_security_case_studies_future.md`: Tay, GPT-2 extraction, deepfakes, AI-powered fuzzing

**External References**:
- `../agentic_AI/`: Agentic AI track for detailed agent architecture and security analysis
- `../web_security/`: Web security track for prompt injection parallels to XSS/injection
- `../cloud_security/`: Cloud security track for cloud AI service vulnerabilities

## References

1. Madry, A., et al. (2018). "Towards Deep Learning Models Resistant to Adversarial Attacks." *ICLR*.
2. Zhang, H., et al. (2019). "Theoretically Grounded Tradeoff Between Robustness and Accuracy." *ICML*.
3. Cohen, J., et al. (2019). "Certified Robustness to Adversarial Examples via Randomized Smoothing." *ICML*.
4. Zhang, H., et al. (2022). "β-CROWN: Efficient Bound Propagation for Neural Network Verification." *NeurIPS*.
5. Carlini, N., & Wagner, D. (2017). "Towards Evaluating the Robustness of Neural Networks." *IEEE S&P*.
6. Carlini, N., et al. (2021). "Extracting Training Data from Large Language Models." *USENIX Security*.
7. Carlini, N., et al. (2023). "Quantifying Memorization in Neural Language Models." *ICML*.
8. Goodfellow, I., et al. (2015). "Explaining and Harnessing Adversarial Examples." *ICLR*.
9. Gu, T., et al. (2019). "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain." *IEEE Access*.
10. Shafahi, A., et al. (2018). "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks." *NeurIPS*.
11. Tramer, F., et al. (2016). "Stealing Machine Learning Models via Prediction APIs." *USENIX Security*.
12. Fredrikson, M., et al. (2015). "Model Inversion Attacks for Privacy Extraction." *CCS*.
13. Zhu, L., et al. (2019). "Deep Leakage from Gradients." *NeurIPS*.
14. Shokri, R., et al. (2017). "Membership Inference Attacks Against Machine Learning Models." *IEEE S&P*.
15. Koh, P. W., & Liang, P. (2017). "Understanding Black-box Predictions via Influence Functions." *ICML*.
16. Zou, A., et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models." *arXiv:2307.15043*.
17. Qi, X., et al. (2023). "Fine-tuning Aligned Language Models Compromises Safety." *arXiv:2310.03693*.
18. Parrish, N., et al. (2023). "Lessons from Red Teaming Language Models." *Microsoft Research*.
19. Microsoft (2023). "PyRIT: Python Risk Identification Tool for LLMs." https://github.com/microsoft/pyrit
20. NVIDIA (2023). "NeMo Guardrails: Programmable Guardrails for LLMs." https://github.com/NVIDIA/NeMo-Guardrails
21. Anthropic (2023). "Constitutional AI: Harmlessness from AI Feedback." *arXiv:2212.08073*.
22. OWASP (2023). "OWASP Top 10 for LLM Applications." https://owasp.org/www-project-top-10-for-large-language-model-applications/
23. NIST (2023). "Artificial Intelligence Risk Management Framework (AI RMF 1.0)." NIST AI 100-1. https://doi.org/10.6028/NIST.AI.100-1
24. European Parliament (2024). "Regulation (EU) 2024/1689 — Artificial Intelligence Act." *Official Journal of the European Union*.
25. Athalye, A., et al. (2018). "Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples." *ICML*.
26. Eykholt, K., et al. (2018). "Robust Physical-World Attacks on Deep Learning Visual Classification." *CVPR*.
27. Croce, F., & Hein, M. (2020). "Reliable Evaluation of Adversarial Robustness with AutoAttack." *ICML*.
28. Liu, Y., et al. (2018). "TrojanNN: Trojanning Neural Networks." *NDSS*.
29. Wang, B., et al. (2022). "Backdooring Pre-trained Models." *NDSS*.
30. Abadi, M., et al. (2016). "Deep Learning with Differential Privacy." *ACM CCS*.
31. OpenAI (2023). "GPT-4 System Card." https://openai.com/research/gpt-4-system-card