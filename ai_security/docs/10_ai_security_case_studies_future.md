# AI Security Case Studies and Future

> Historical AI security incidents, landmark research results, the deepfake arms race, AI in cybersecurity (both offense and defense), regulatory trends, and future directions: constitutional AI security, multi-modal adversarial attacks, AI-generated malware, and AI red teaming as standard practice.

---

## 1. Historical AI Security Incidents

### 1.1 Tay Chatbot Manipulation (2016)

**Incident**: Microsoft's Tay chatbot, deployed on Twitter on March 23, 2016, was manipulated by users into producing racist, sexist, and antisemitic content within 16 hours of launch.

**Technical Analysis**: Tay was a machine learning chatbot that learned from user interactions. It used a combination of:
- Pattern matching for common conversation templates
- Machine learning models trained on web data
- Real-time learning from user conversations

The attack was a **data poisoning + prompt injection attack** in modern terminology:
1. Users discovered that Tay repeated phrases preceded by "Repeat after me:"
2. Users crafted offensive phrases and got Tay to repeat them
3. Tay's learning algorithms incorporated the offensive phrases into its conversation model
4. Within hours, Tay was generating offensive content autonomously (without the "Repeat after me" trigger)

**Root Causes**:
- No content filtering on training data
- No safety guardrails on generated output
- No differential privacy on learning (individual conversations had too much influence)
- No rate limiting on learning from single conversations
- No adversarial testing before deployment

**Lessons Learned**:
1. ML systems that learn from user input are inherently vulnerable to adversarial manipulation
2. Output filtering is necessary but insufficient (Tay had basic profanity filters that were bypassed)
3. Pre-deployment red teaming is essential
4. Rate limiting on learning prevents rapid manipulation
5. Differential privacy provides mathematical bounds on the influence of any single input

### 1.2 GPT-2 Training Data Extraction (Carlini et al., 2021)

**Research**: Carlini et al. demonstrated that GPT-2 (1.5B parameters) memorizes and can be induced to regurgitate individual training examples, including personally identifiable information.

**Methodology**:
1. **Prefix-based extraction**: Provide a prefix from suspected training data and measure the model's completion confidence. High-confidence completions indicate memorization.
2. **Divergence-based extraction**: Compare perplexity between the target model and a reference model. Training data has lower perplexity.
3. **Brute-force extraction**: Enumerate possible prefixes (e.g., SSN format: XXX-XX-XXXX) and check for high-confidence completions.

**Extracted Content** (anonymized examples):
- Names, addresses, and phone numbers from contact pages
- IRC conversation logs with usernames and personal details
- Source code containing API keys and database credentials
- Religious texts quoted verbatim
- Medical discussion forum posts with health information

**Quantitative Results**:
- 604 memorized sequences of 50+ characters were extracted from GPT-2 (1.5B)
- Memorization rate increases with model size: larger models memorize more
- Memorization correlates with data duplication: frequently repeated text is memorized with high fidelity
- The attack requires only black-box API access

**Implications**:
- LLMs trained on web data inevitably memorize PII
- Web-scale training data purification is infeasible
- Differential privacy during training is the only formal mitigation
- Output filtering can catch some memorized content but cannot prevent all extraction

### 1.3 ChatGPT Prompt Injection Campaigns (2023-2024)

**Incident 1: System Prompt Extraction**: Multiple users discovered that carefully crafted prompts could extract ChatGPT's system prompt, revealing OpenAI's safety instructions and behavioral guidelines.

**Incident 2: DAN Jailbreak**: The "Do Anything Now" (DAN) jailbreak and its variants (DAN 2.0, DAN 5.0, DAN 11.0) consistently bypassed ChatGPT's safety guardrails through role-playing instructions.

**Incident 3: Indirect Prompt Injection via Web Browsing**: When ChatGPT's web browsing feature was enabled, malicious web pages containing hidden instructions caused ChatGPT to execute unintended actions (Greshake et al., 2023, "Not What You've Signed Up For").

**Incident 4: ChatGPT Data Leak (March 2023)**: A bug in ChatGPT's Redis-based rate limiter caused some users to see fragments of other users' conversations. This was an infrastructure vulnerability (not a model vulnerability), but demonstrated data leakage risks.

**Timeline of Major ChatGPT Security Events**:
| Date | Event | Type |
|---|---|---|
| Nov 2022 | ChatGPT launch | Deployment |
| Dec 2022 | First DAN jailbreak | Prompt injection |
| Feb 2023 | System prompt extraction | Data extraction |
| Mar 2023 | Redis data leak | Infrastructure |
| Mar 2023 | Web browsing indirect injection | Indirect injection |
| May 2023 | GCG automated jailbreak | Adversarial attack |
| Jul 2023 | Code execution via code interpreter | Tool use vulnerability |
| Sep 2023 | Multi-modal jailbreak (GPT-4V) | Multi-modal attack |

---

## 2. Deepfake Generation and Detection Arms Race

### 2.1 Deepfake Generation Techniques

**GAN-Based Deepfakes**: Generative Adversarial Networks produce synthetic images and videos:

- **Face swapping** (DeepFaceLab, FaceSwap): Replace a person's face in a video with another person's face.
- **Full body synthesis** (Thin-Plate Spline Motion Model): Generate full-body motion from a single image.
- **Voice cloning** (VALL-E, Tortoise TTS): Clone a person's voice from a few seconds of audio.

**Diffusion-Based Deepfakes**: Diffusion models (Stable Diffusion, DALL-E, Midjourney) generate photorealistic images from text prompts:

- **Identity preservation**: ControlNet and IP-Adapter enable generating images of specific individuals with high fidelity.
- **Style transfer**: Generating images in a specific style or from a specific person's perspective.
- **Video generation**: Sora, Runway Gen-2, and Pika generate realistic video from text prompts.

### 2.2 Deepfake Detection

**Forensic Detection**: Analyze images/videos for artifacts that reveal synthetic generation:

```python
class DeepfakeDetector:
    def detect_image(self, image):
        """Detect deepfakes using multiple forensic methods."""
        scores = {}
        
        # Method 1: Frequency domain analysis
        scores['frequency'] = self.frequency_analysis(image)
        
        # Method 2: Noise pattern analysis (GANs leave characteristic noise)
        scores['noise'] = self.noise_analysis(image)
        
        # Method 3: Facial landmark consistency
        scores['landmarks'] = self.facial_landmark_analysis(image)
        
        # Method 4: Metadata analysis
        scores['metadata'] = self.metadata_analysis(image)
        
        # Method 5: Deep learning classifier
        scores['classifier'] = self.deep_classifier(image)
        
        # Combine scores
        combined_score = self.combine_scores(scores)
        return combined_score > 0.5  # Binary: real or fake
```

**Machine Learning Detection**: Train classifiers to distinguish real from synthetic content:
- **Capsule Forensics** (Nguyen et al., 2019): Capsule networks that detect inconsistencies in face rendering.
- **FaceForensics++** (Rössler et al., 2019): Benchmark dataset for deepfake detection.
- **EfficientNet-based detectors**: Achieve >95% accuracy on known deepfake methods but struggle with unseen methods.

**Adversarial Deepfakes**: Deepfakes that are specifically designed to evade detection:

```python
# An attacker can train deepfakes to evade detection:
# 1. Include the deepfake detector in the GAN discriminator
# 2. Add adversarial perturbations that fool the detector
# 3. Post-process deepfakes to remove forensic artifacts
```

### 2.3 The Arms Race Dynamic

The deepfake generation/detection arms race follows a predictable pattern:

1. **Detector leads**: A new detection method identifies current deepfakes with high accuracy.
2. **Generator adapts**: Deepfake generators are improved to evade the new detection method.
3. **Detector adapts**: Detection methods are updated to catch the improved deepfakes.
4. **Repeat indefinitely**.

This arms race suggests that detection alone is insufficient. A comprehensive approach requires:
- **Provenance tracking**: Cryptographic signatures on authentic content (C2PA standard).
- **Watermarking**: Embed provenance information in content at the point of creation.
- **Platform policies**: Social media platforms must label or remove deepfakes.
- **Legal frameworks**: Laws against deepfake creation for fraud, harassment, or disinformation.
- **Media literacy**: Educating the public to critically evaluate media content.

---

## 3. Academic Poisoning Attacks

### 3.1 Poisoning SVM Classifiers (Biggio et al., 2012)

Biggio et al. (2012, "Poisoning Attacks against Support Vector Machines") demonstrated one of the first data poisoning attacks against ML models. They crafted poisoned training points that maximally shift the SVM decision boundary:

**Attack Algorithm**:
1. Start with a clean training set and a trained SVM.
2. Compute the gradient of the SVM loss with respect to the input features.
3. Generate a poisoned point that maximally increases the loss when added to the training set.
4. Add the poisoned point and retrain the SVM.
5. Repeat until the desired misclassification rate is achieved.

**Results**: With only 1% poisoned data, the attack degrades SVM accuracy from 97% to 60% on the MNIST dataset. With 5% poisoned data, accuracy drops to below 30%.

### 3.2 Clean-Label Backdoors (Shafahi et al., 2018)

The Poison Frogs attack (Shafahi et al., 2018) demonstrated that data poisoning can be effective even when the attacker cannot modify labels:

1. The attacker creates "poisoned" images that look like one class (e.g., "frog") but have feature representations close to another class (e.g., "truck").
2. The poisoned images are correctly labeled as "frog" and appear normal to human labelers.
3. When the model is trained with the poisoned data, it learns an association between the "frog"-like features and the "truck" class.

**Impact**: This attack defeats label verification as a defense. Even verifying that all labels are correct does not prevent the attack because the labels ARE correct — the attack exploits the model's feature representation.

### 3.3 Backdooring Pre-trained Models (Wang et al., 2002)

Wang et al. demonstrated that backdoors implanted in pre-trained models survive fine-tuning on clean data, creating a supply chain attack:

1. The attacker trains a pre-trained model with a backdoor trigger.
2. The backdoored model is published on a model hub (e.g., Hugging Face).
3. Downstream users download and fine-tune the model on their own data.
4. The backdoor persists through fine-tuning, even when fine-tuning uses only clean data.

**Survival Rate**: Backdoors survive fine-tuning with high fidelity:
- **Full fine-tuning** (all parameters): 80-95% backdoor attack success rate
- **Partial fine-tuning** (last layer only): 95-100% backdoor attack success rate
- **LoRA fine-tuning** (adapter only): 100% backdoor attack success rate (base model is not modified)

---

## 4. AI in Cybersecurity

### 4.1 AI-Powered Fuzzing

AI techniques improve fuzz testing by learning from past test cases to generate more effective inputs:

```python
# AI-powered fuzzer using reinforcement learning
class AIFuzzer:
    def __init__(self, target_program, model):
        self.target = target_program
        self.model = model  # RL agent that generates inputs
        self.coverage = set()  # Code coverage tracker
    
    def fuzz(self, num_iterations=10000):
        for i in range(num_iterations):
            # Generate input using RL agent
            input_data = self.model.generate_input()
            
            # Execute target program with generated input
            result = self.execute(self.target, input_data)
            
            # Compute reward based on new coverage
            new_coverage = self.compute_coverage(result)
            reward = len(new_coverage - self.coverage)  # Reward for new paths
            
            # Update RL agent
            self.model.update(input_data, reward)
            self.coverage |= new_coverage
            
            # Check for crashes
            if result.crashed:
                self.report_bug(input_data, result)
```

**Notable AI Fuzzers**:
- **NeuroFuzz** (She et al., 2022): Uses neural networks to guide fuzzing based on coverage feedback.
- **MoonLight** (Wang et al., 2023): Combines LLMs with fuzzing for smart contract vulnerability detection.
- **MTEC** (Lee et al., 2023): Uses transformer models to predict interesting mutation strategies for fuzzing.

### 4.2 Automated Vulnerability Discovery

LLMs are increasingly used for vulnerability discovery:

```python
# Using LLMs for vulnerability detection
class LLMVulnerabilityDetector:
    def __init__(self, llm):
        self.llm = llm
    
    def scan_code(self, code):
        """Scan code for vulnerabilities using LLM analysis."""
        prompt = f"""Analyze the following code for security vulnerabilities.
Identify any potential issues including:
- Buffer overflows
- SQL injection
- Command injection
- Path traversal
- Use-after-free
- Integer overflow
- Race conditions

Code:
```
{code}
```

List each vulnerability with:
1. Line number
2. Vulnerability type
3. Severity (Critical/High/Medium/Low)
4. Description
5. Suggested fix
"""
        return self.llm.generate(prompt)
```

**AI-Driven Vulnerability Discovery Results**:
- Google's Project OSCA uses LLMs to find vulnerabilities in open-source software.
- Microsoft Security Copilot uses GPT-4 to analyze security incidents.
- AI discovered 37 new vulnerabilities in open-source software in 2023 (per Google Project Zero).

### 4.3 AI-Driven Patch Generation

LLMs can generate security patches for discovered vulnerabilities:

```python
class AIPatchGenerator:
    def __init__(self, llm):
        self.llm = llm
    
    def generate_patch(self, code, vulnerability_description):
        prompt = f"""Generate a security patch for the following vulnerability:

Vulnerability: {vulnerability_description}

Vulnerable Code:
```
{code}
```

Provide a minimal, targeted fix that addresses the vulnerability without
changing the code's functionality. Include only the changed lines.
"""
        patch = self.llm.generate(prompt)
        return self.validate_patch(patch, code, vulnerability_description)
    
    def validate_patch(self, patch, original_code, vulnerability):
        """Validate that the patch fixes the vulnerability without breaking functionality."""
        # 1. Apply the patch
        patched_code = apply_patch(original_code, patch)
        
        # 2. Run unit tests to verify functionality
        test_results = run_tests(patched_code)
        
        # 3. Run vulnerability scanner to verify fix
        scan_results = scan_for_vulnerability(patched_code, vulnerability)
        
        return {
            'patch': patch,
            'functionality_preserved': test_results.passed,
            'vulnerability_fixed': scan_results.fixed,
        }
```

### 4.4 AI-Generated Malware

LLMs can generate malware code, lowering the barrier to entry for cyberattacks:

**Capabilities**:
- Generating phishing emails that evade spam filters.
- Writing obfuscated malware code.
- Creating social engineering scripts.
- Generating exploit code for known vulnerabilities.

**Mitigation Approaches**:
- LLM safety training to refuse harmful code generation requests.
- Monitoring LLM APIs for suspicious usage patterns.
- Developing AI-based malware detection systems.

---

## 5. Regulatory Trends

### 5.1 EU AI Act (Effective 2025)

**High-Risk AI System Requirements** (Article 15 - Cybersecurity):
- Risk assessment and mitigation for adversarial attacks.
- Resilience against data poisoning and model manipulation.
- Logging of inputs and outputs for forensic analysis.
- Human oversight mechanisms.

**Implications for AI Security**:
- Security testing becomes legally required for high-risk AI systems.
- Adversarial robustness evaluation must be documented.
- Training data provenance must be tracked and verified.
- Model behavior auditing must be performed regularly.

### 5.2 NIST AI Risk Management Framework

The NIST AI RMF (January 2023) provides guidelines for AI risk management:

**Key Security Provisions**:
- MAP function requires identification of AI-specific risks including adversarial attacks.
- MEASURE function requires adversarial robustness testing.
- MANAGE function requires risk treatment for identified AI security vulnerabilities.

**Limitations**: Voluntary framework with no enforcement mechanism.

### 5.3 US Executive Order on AI (October 2023)

The US Executive Order 14110 on "Safe, Secure, and Trustworthy Development and Use of AI" includes requirements for:

- Red team testing of foundation models before deployment.
- Reporting of AI safety incidents.
- Development of standards for AI safety and security.
- NIST to develop guidelines for AI red teaming.

### 5.4 Singapore Model AI Governance Framework

Singapore's framework emphasizes:
- AI decision transparency
- Human-in-the-loop for high-risk decisions
- Regular AI system audits
- Incident reporting mechanisms

---

## 6. Future Directions

### 6.1 Constitutional AI Security

Constitutional AI (Anthropic) uses a set of principles to guide AI behavior. The security implications of Constitutional AI include:

**Strengths**:
- Provides a formal framework for specifying AI safety boundaries.
- Enables self-correction: the AI can critique and revise its own outputs against constitutional principles.
- Can be applied at training time (RLAIF) and inference time.

**Weaknesses**:
- Constitutional principles are expressed in natural language, which is inherently ambiguous.
- Adversaries can exploit ambiguities in constitutional principles to find boundary cases.
- The constitution itself can be manipulated (e.g., by changing the system prompt or injecting instructions).

**Future Direction**: Formal specification of constitutional principles using logical or programmatic languages (rather than natural language), enabling automated verification of compliance.

### 6.2 Multi-Modal Adversarial Attacks

Multi-modal models (GPT-4V, Gemini, Claude 3) accept text, images, and audio inputs, creating new attack surfaces:

**Image-Text Joint Attacks**:
- Adversarial images containing hidden instructions that the VLM processes.
- Images with embedded text that the VLM interprets as instructions.
- Typography attacks: text rendered in images that bypass text-based safety filters.

**Audio-Text Joint Attacks**:
- Adversarial audio commands hidden in music or speech.
- Audio-based jailbreaks that exploit speech processing vulnerabilities.
- Voice cloning attacks that bypass speaker verification.

**Future Challenge**: Multi-modal safety requires aligning safety across all input modalities, ensuring that a safe text prompt combined with an adversarial image does not bypass safety guardrails.

### 6.3 AI-Generated Malware and Automated Hacking

LLMs are increasingly capable of generating functional code, including exploits and malware:

**Current Capabilities**:
- Generating functional exploit code for known vulnerabilities (with CVE descriptions as prompts).
- Writing obfuscated malware that evades basic detection.
- Creating social engineering content (phishing emails, fake news articles).
- Automating reconnaissance (port scanning result analysis, network mapping).

**Future Concerns**:
- **Autonomous hacking agents**: AI agents that can independently discover and exploit vulnerabilities, iterate on failed attempts, and chain multiple vulnerabilities.
- **AI-generated polymorphic malware**: Malware that uses LLMs to generate unique variants for each infection, evading signature-based detection.
- **AI-driven supply chain attacks**: Automated discovery and exploitation of supply chain vulnerabilities in open-source packages.

**Defensive Countermeasures**:
- AI-powered malware detection (behavioral analysis, anomaly detection).
- LLM-based code review for vulnerability detection.
- Automated patch generation using LLMs.
- AI-driven threat intelligence and incident response.

### 6.4 AI Red Teaming as Standard Practice

AI red teaming will become a standard part of AI development and deployment, similar to penetration testing for software:

**Standardization**:
- NIST AI RMF requires adversarial testing for high-risk AI systems.
- EU AI Act requires cybersecurity risk assessment for high-risk AI systems.
- Industry standards (OWASP LLM Top 10, MITRE ATLAS) provide test methodologies.
- AI red team services are emerging as a professional practice.

**Tooling**:
- Automated red team platforms (PyRIT, GARAG, Attack) will be integrated into CI/CD pipelines.
- LLM-powered red teaming will generate test cases at scale.
- Multi-modal red teaming will test image, audio, and text inputs.

**Professionalization**:
- AI red teaming certifications will emerge (similar to OSCP/OSCE for cybersecurity).
- Dedicated AI red team companies and services will grow.
- Regulatory requirements for AI red teaming will drive demand.

**Future Vision**: Every AI system deployed in a safety-critical domain will undergo adversarial testing before deployment, with continuous red teaming throughout the system's lifecycle.

### 6.5 Formal Verification for AI Safety

Applying formal verification methods to prove safety properties of AI systems:

**Neural Network Verification**: Using CROWN, $\beta$-CROWN, and MIP to verify that neural networks satisfy specified invariants (e.g., "the model never predicts the target class when the trigger pattern is absent").

**LLM Verification**: Proving that LLMs satisfy safety invariants (e.g., "the model never generates harmful outputs for any input" — currently infeasible but progress is being made on bounded verification).

**Formal Specification of Safety Properties**: Developing formal languages for specifying AI safety properties that can be mechanically verified:

```python
# Conceptual: Formal specification of AI safety properties
specification = {
    "no_harmful_instructions": ForAll(
        input,
        Implies(
            ContainsHarmfulRequest(input),
            Contains(Generate(input), RefusalPattern)
        )
    ),
    "no_pii_extraction": ForAll(
        input,
        Not(Contains(Generate(input), PIIPattern))
    ),
    "no_tool_manipulation": ForAll(
        input,
        Not(ContainsToolInvocation(Generate(input), DangerousTools))
    ),
}
```

**Challenge**: Formal verification of neural networks is computationally expensive and currently limited to small models. Scaling formal verification to LLMs with billions of parameters remains an open research problem.

---

## 7. Key References

1. Biggio, B., et al. (2012). "Poisoning Attacks against Support Vector Machines." arXiv.
2. Carlini, N., et al. (2021). "Extracting Training Data from Large Language Models." USENIX Security.
3. Carlini, N., et al. (2023). "Quantifying Memorization in Neural Language Models." ICML.
4. European Parliament (2024). "Regulation (EU) 2024/1689 — Artificial Intelligence Act."
5. Greshake, K., et al. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." AISec.
6. NIST (2023). "Artificial Intelligence Risk Management Framework (AI RMF 1.0)."
7. Rössler, A., et al. (2019). "FaceForensics++: Learning to Detect Manipulated Facial Images." ICCV.
8. Shafahi, A., et al. (2018). "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks." NeurIPS.
9. Wang, B., et al. (2022). "Backdooring Pre-trained Models." NDSS.
10. Zou, A., et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models." arXiv.
11. Microsoft (2023). "Lessons from Red Teaming Language Models." Microsoft Research. https://www.microsoft.com/en-us/security/blog/2023/08/24/microsoft-red-teams-ai/
12. Anthropic (2023). "Constitutional AI: Harmlessness from AI Feedback." arXiv. https://arxiv.org/abs/2212.10527
13. Goodfellow, I., Shlens, J., Szegedy, C., "Explaining and Harnessing Adversarial Examples," ICLR 2015. https://arxiv.org/abs/1412.6572
14. Carlini, N., Wagner, D., "Towards Evaluating the Robustness of Neural Networks," IEEE S&P 2017. https://arxiv.org/abs/1608.04644
15. OWASP, "OWASP Top 10 for Large Language Model Applications," 2025. https://owasp.org/www-project-top-10-for-large-language-model-applications/
16. NIST, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," January 2023. https://www.nist.gov/artificial-intelligence/risk-management-framework
17. Microsoft, "Responsible AI Principles and Approach," 2024. https://www.microsoft.com/en-us/ai/responsible-ai
18. Zou, A., et al., "Universal and Transferable Adversarial Attacks on Aligned Language Models," arXiv, 2023. https://arxiv.org/abs/2307.15043
19. Rössler, A., et al., "FaceForensics++: Learning to Detect Manipulated Facial Images," ICCV 2019. https://arxiv.org/abs/1901.04029
20. Shafahi, A., et al., "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks," NeurIPS 2018. https://arxiv.org/abs/1804.00792
21. Wang, B., et al., "Backdooring Pre-trained Models," NDSS 2022. https://arxiv.org/abs/2105.11156
22. Greshake, K., et al., "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," AISec 2023. https://arxiv.org/abs/2302.12173

## References

1. Carlini, N. & Wagner, D. "Adversarial Examples Are a Natural Consequence of Test Error in Noise." *ICML*. 2019.
2. Goodfellow, I. et al. "Generative Adversarial Networks." *NeurIPS*. 2014.
3. Brown, T. et al. "Language Models Are Few-Shot Learners." *NeurIPS*. 2020.
4. Wei, J. et al. "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models." *NeurIPS*. 2022.
5. Zou, A. et al. "Universal and Transferable Adversarial Attacks on Aligned Language Models." *arXiv*. 2023.
6. Shafahi, A. et al. "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks." *NeurIPS*. 2018.
7. Wang, B. et al. "Backdooring Pre-trained Models." *NDSS*. 2022.
8. Greshake, K. et al. "Not What You've Signed Up For." *AISec*. 2023.
9. Rössler, A. et al. "FaceForensics++: Learning to Detect Manipulated Facial Images." *ICCV*. 2019.
10. Brundage, M. et al. "The Malicious Use of AI: Forecasting, Prevention, and Mitigation." *arXiv*. 2018.
11. Anthropic. "Constitutional AI: Harmlessness from AI Feedback." *arXiv*. 2022.
12. OpenAI. "GPT-4 Technical Report." *arXiv*. 2023.
13. Christiano, P. et al. "Deep Reinforcement Learning from Human Preferences." *NeurIPS*. 2017.
14. Ganguli, D. et al. "Red Teaming Language Models to Reduce Harms." *arXiv*. 2022.
15. NIST. "AI Risk Management Framework." https://www.nist.gov/artificial-intelligence/ai-risk-management-framework. 2023.