# Adversarial Machine Learning: Attacks, Defenses, and Robustness

> A comprehensive treatment of adversarial ML covering gradient-based attacks (FGSM, PGD, CW), black-box evasion, transferability, physical-world adversarial examples, and defenses (adversarial training, certified robustness, TRADES). Includes attack implementations using CleverHans and Adversarial Robustness Toolbox (ART).

---

## 1. Foundations of Adversarial ML

### 1.1 The Adversarial Example Phenomenon

Adversarial examples are inputs to machine learning models that an attacker has intentionally designed to cause the model to make a mistake. The seminal discovery by Szegedy et al. (2014, "Intriguing Properties of Neural Networks") demonstrated that imperceptible perturbations to an image could cause state-of-the-art neural networks to misclassify with high confidence.

**Key Properties**:
- **Imperceptibility**: Adversarial perturbations are often too small for humans to detect (e.g., $L_\infty$ perturbation of $\epsilon = 8/255$ on ImageNet).
- **Transferability**: Adversarial examples crafted for one model often fool other models with different architectures and training data (Papernot et al., 2016).
- **Universality**: Adversarial examples exist for virtually all ML model types — neural networks, SVMs, decision trees, and k-nearest neighbors.
- **Physical realizability**: Adversarial perturbations can be printed on physical objects and survive photographing under varying angles and lighting conditions.

**Mathematical Formulation**: Given a classifier $f: \mathcal{X} \rightarrow \mathcal{Y}$, a legitimate input $x \in \mathcal{X}$ with true label $y \in \mathcal{Y}$, and a perturbation bound $\epsilon$, find $x' \in \mathcal{X}$ such that:

$$f(x') \neq y, \quad \|x' - x\|_p \leq \epsilon$$

The choice of norm ($L_0$, $L_2$, $L_\infty$) defines theperturbation constraint and the nature of the attack.

### 1.2 Why Adversarial Examples Exist

Multiple theoretical explanations have been proposed:

**Linear Explanation (Goodfellow et al., 2015)**: Neural networks are approximately linear in high-dimensional spaces. A small perturbation in each of $d$ dimensions adds up to a large total perturbation in the dot product $w^T x$. For an image with $d = 224 \times 224 \times 3 = 150{,}528$ dimensions, an $L_\infty$ perturbation of $\epsilon$ per dimension produces a dot product change of $\epsilon \cdot d \cdot \mathbb{E}[|w_i|]$, which can be enormous even for small $\epsilon$.

**Boundary Tilting (Gilmer et al., 2018)**: In high dimensions, the decision boundary of a classifier is a $(d-1)$-dimensional hyperplane. Any data point is close to this boundary, and a small perturbation in the normal direction crosses it. "Adversarial examples are not bugs, they are features" (Ilyas et al., 2019) — they exploit non-robust features that are predictive but human-incomprehensible.

**Double Descent and Overparameterization**: Overparameterized models memorize training data and learn brittle decision boundaries that are easily crossed. The double descent phenomenon (Belkin et al., 2019) shows that test error can increase as model size grows beyond the interpolation threshold, precisely the regime where adversarial examples are most prevalent.

### 1.3 Threat Model Formalization

Adversarial ML attacks are classified along several axes:

**Attacker Knowledge**:
- **White-box**: Full access to model architecture, parameters, and training data. The attacker can compute exact gradients.
- **Black-box**: Access limited to model inputs and outputs. The attacker observes predictions (and optionally confidence scores) for submitted inputs.
- **Gray-box**: Partial knowledge. The attacker may know the architecture but not the weights, or have access to a surrogate model trained on similar data.

**Attacker Goal**:
- **Untargeted misclassification**: Cause the model to predict ANY wrong class.
- **Targeted misclassification**: Cause the model to predict a SPECIFIC wrong class.
- **Source/target misclassification**: Map a specific source class to a specific target class.

**Perturbation Constraint**:
- $L_\infty$: Each pixel/component can change by at most $\epsilon$. Common for image attacks.
- $L_2$: The Euclidean norm of the perturbation is bounded. Allows larger changes in fewer components.
- $L_0$: The number of modified components is bounded. Results in sparse perturbations.
- $L_1$: The Manhattan distance is bounded. Promotes sparse perturbations (used in sparse adversarial examples).

---

## 2. White-Box Attacks

### 2.1 Fast Gradient Sign Method (FGSM)

FGSM (Goodfellow et al., 2015, "Explaining and Harnessing Adversarial Examples") generates adversarial examples using a single gradient step:

$$x' = x + \epsilon \cdot \text{sign}(\nabla_x J(\theta, x, y))$$

Where $J$ is the loss function, $\theta$ are model parameters, $x$ is the input, and $y$ is the true label. FGSM is fast (one forward and one backward pass) but produces suboptimal perturbations compared to iterative methods.

```python
import torch
import torch.nn.functional as F

def fgsm_attack(model, x, y, epsilon):
    x_adv = x.clone().detach().requires_grad_(True)
    outputs = model(x_adv)
    loss = F.cross_entropy(outputs, y)
    loss.backward()
    perturbation = epsilon * x_adv.grad.sign()
    x_adv = x + perturbation
    x_adv = torch.clamp(x_adv, 0, 1)
    return x_adv.detach()
```

**CleverHans Implementation**:
```python
from cleverhans.torch.attacks.fast_gradient_method import fast_gradient_method

x_adv = fast_gradient_method(
    model_fn=model,
    x=x,
    eps=epsilon,
    norm=np.inf,
    clip_min=0.0,
    clip_max=1.0,
    y=y,
    targeted=False
)
```

**ART Implementation**:
```python
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import PyTorchClassifier

classifier = PyTorchClassifier(model=model, ...)
attack = FastGradientMethod(estimator=classifier, eps=0.2, norm=np.inf)
x_adv = attack.generate(x=x_test)
```

### 2.2 Projected Gradient Descent (PGD)

PGD (Madry et al., 2018, "Towards Deep Learning Models Resistant to Adversarial Attacks") is the strongest first-order attack and the foundation of adversarial training:

$$x^{t+1} = \Pi_{x+S} \left( x^t + \alpha \cdot \text{sign}(\nabla_x J(\theta, x^t, y)) \right)$$

Where $\Pi_{x+S}$ is the projection onto the $\epsilon$-ball around $x$, and $\alpha$ is the step size. PGD applies FGSM iteratively with random initialization and projection back to the feasible set.

Key parameters:
- $\epsilon$: Maximum perturbation ($L_\infty$ norm bound)
- $\alpha$: Step size per iteration (typically $\epsilon / 4$ or $\alpha = 2\epsilon/(\text{num\_steps})$)
- Number of iterations: Typically 10-40 for evaluation, 7-10 for adversarial training

```python
def pgd_attack(model, x, y, epsilon, alpha, num_iter, random_start=True):
    if random_start:
        x_adv = x + torch.empty_like(x).uniform_(-epsilon, epsilon)
        x_adv = torch.clamp(x_adv, 0, 1)
    else:
        x_adv = x.clone().detach()

    for i in range(num_iter):
        x_adv.requires_grad_(True)
        outputs = model(x_adv)
        loss = F.cross_entropy(outputs, y)
        loss.backward()
        perturbation = alpha * x_adv.grad.sign()
        x_adv = x_adv.detach() + perturbation
        delta = torch.clamp(x_adv - x, min=-epsilon, max=epsilon)
        x_adv = torch.clamp(x + delta, 0, 1)

    return x_adv.detach()
```

**PGD with Random Restart**: PGD's effectiveness depends heavily on initialization. Multiple random restarts (typically 5-20) significantly improve attack success rate:

```python
def pgd_attack_with_restarts(model, x, y, epsilon, alpha, num_iter, num_restarts=5):
    best_adv = x.clone()
    best_loss = -float('inf')

    for _ in range(num_restarts):
        x_adv = pgd_attack(model, x, y, epsilon, alpha, num_iter, random_start=True)
        with torch.no_grad():
            loss = F.cross_entropy(model(x_adv), y)
        if loss > best_loss:
            best_loss = loss
            best_adv = x_adv

    return best_adv
```

### 2.3 Carlini & Wagner (C&W) Attack

The C&W attack (Carlini & Wagner, 2017, "Towards Evaluating the Robustness of Neural Networks") is the most effective $L_2$, $L_0$, and $L_\infty$ attack. It formulates adversarial example generation as an optimization problem:

$$\min_{\delta} \|\delta\|_2 + c \cdot f(x + \delta)$$

Where $f$ is a carefully chosen objective function:
$$f(x') = \max(\max\{Z(x')_i : i \neq t\} - Z(x')_t, -\kappa)$$

$Z(x')_i$ are the logits for class $i$, $t$ is the target class, and $\kappa$ is the confidence parameter. The constant $c$ is found via binary search.

The $L_2$ version uses $\tanh$ to transform the optimization into an unconstrained problem:
$$x' = \frac{1}{2}(\tanh(w) + 1)$$

```python
def cw_l2_attack(model, x, y, targeted=False, c=1.0, kappa=0, max_iter=1000, learning_rate=0.01):
    x_adv = x.clone().detach()
    w = torch.atanh(torch.clamp(2 * x_adv - 1, min=-0.999, max=0.999)).detach().requires_grad_(True)

    optimizer = torch.optim.Adam([w], lr=learning_rate)

    for step in range(max_iter):
        x_adv = 0.5 * (torch.tanh(w) + 1)
        logits = model(x_adv)
        real = logits.gather(1, y.unsqueeze(1)).squeeze(1)
        other_logit = logits - torch.eye(logits.size(1))[y].to(logits.device) * 1e4
        other = other_logit.max(1)[0]

        if targeted:
            loss_adv = torch.max(other - real, torch.tensor(kappa).to(real.device))
        else:
            loss_adv = torch.max(real - other, torch.tensor(kappa).to(real.device))

        loss = loss_adv.sum() + c * torch.sum((x_adv - x) ** 2)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    return x_adv.detach()
```

**C&W Effectiveness**: The C&W attack achieves near-perfect success rates against undefended models. Against adversarially trained models, C&W remains effective when PGD-based defenses succeed, making it the standard evaluation attack for robustness claims.

### 2.4 Other Gradient-Based Attacks

**DeepFool** (Moosavi-Dezfooli et al., 2016): Finds the minimal perturbation to cross the decision boundary by iteratively linearizing the classifier. Produces smaller perturbations than FGSM but is computationally expensive.

**Jacobian-based Saliency Map Attack (JSMA)** (Papernot et al., 2016): Selects the most impactful input features to perturb using the Jacobian matrix. Produces sparse, targeted adversarial examples with few modified pixels.

**Momentum Iterative FGSM (MI-FGSM)** (Dong et al., 2018): Incorporates momentum into the iterative FGSM process, improving transferability across models. Essential for black-box attacks based on transferability.

**Nesterov Accelerated Gradient (NI-FGSM)** (Lin et al., 2020): Uses Nesterov momentum instead of standard momentum for better convergence properties in adversarial example generation.

**AutoAttack** (Croce & Hein, 2020): An ensemble of attacks that combines AutoPGD (a variant of PGD with adaptive step size), FAB (Fast Adaptive Boundary), and the Square Attack. AutoAttack is the current standard for evaluating adversarial robustness because it minimizes the risk of overestimating defense effectiveness. Available at https://github.com/fra31/auto-attack.

```python
from autoattack import AutoAttack

adversary = AutoAttack(model, norm='Linf', eps=epsilon, version='standard')
x_adv = adversary.run_standard_evaluation(x_test, y_test)
```

---

## 3. Black-Box Evasion Attacks

### 3.1 Transferability-Based Attacks

Adversarial examples transfer across models (Papernot et al., 2016, "Transferability in Machine Learning: from Phenomena to Black-Box Attacks"). Transferability arises because adversarial perturbations exploit features common to multiple models rather than model-specific quirks.

**Transfer rates** vary by:
- **Model similarity**: Transfer is higher between models with similar architectures.
- **Training data overlap**: Models trained on similar data transfer better.
- **Perturbation size**: Larger perturbations transfer more reliably.
- **Task difficulty**: Transfer is higher for harder classification tasks.

**Ensemble-based Transferability** (Liu et al., 2017): Generating adversarial examples against an ensemble of models significantly improves transferability:
$$\nabla_x \sum_{i=1}^{k} \alpha_i J(\theta_i, x, y)$$
Where $\alpha_i$ are ensemble weights.

**Input Transformation-Based Transfer**: Apply transformations to the input before gradient computation:
- **DIM (Diverse Input Method)** (Xie et al., 2019): Randomly resize and pad the input before gradient computation.
- **TIM (Translation-Invariant Method)** (Dong et al., 2019): Convolve the gradient with a predefined kernel.
- **SIM (Scale-Invariant Method)**: Compute gradients at multiple input scales.

### 3.2 Query-Based Black-Box Attacks

When transferability fails, query-based attacks use model API responses to craft adversarial examples:

**Boundary Attack** (Brendel et al., 2018): Starts from a large perturbation that already causes misclassification and progressively reduces the perturbation while staying on the decision boundary. Requires only the final classification label (no confidence scores).

**Square Attack** (Andriushchenko et al., 2020): A random search-based attack that modifies square-shaped regions of the input. Achieves near state-of-the-art success rates with $O(1000)$ queries, significantly fewer than gradient-estimation methods.

**HopSkipJumpAttack** (Chen et al., 2020): Combines boundary tracing with gradient estimation. Queries the model to estimate the gradient direction near the decision boundary, then takes a step along that direction.

**Sign-Oriented Attacks**: ZOO (Zhou et al., 2018) and NES (Natural Evolution Strategies) estimate gradients using finite differences:
$$\frac{\partial f}{\partial x_i} \approx \frac{f(x + \epsilon e_i) - f(x - \epsilon e_i)}{2\epsilon}$$

Query complexity is $O(d)$ per gradient estimation (where $d$ is input dimensionality), making these attacks expensive for high-dimensional inputs.

---

## 4. Physical-World Adversarial Examples

### 4.1 Stop Sign Evasion

Eykholt et al. (2018, "Robust Physical-World Attacks on Deep Learning Visual Classification") demonstrated that printed stickers on stop signs cause traffic sign recognition systems to misclassify them as speed limit signs or other classes.

**Key Challenges for Physical-World Attacks**:
- **Viewpoint variation**: The perturbation must be effective from multiple camera angles.
- **Lighting variation**: Indoor/outdoor, day/night, shadow/lighting changes.
- **Distance variation**: The perturbation must survive resolution changes due to camera distance.
- **Motion blur**: Moving objects introduce additional perturbation.
- **Camera noise**: Digital noise from camera sensors.
- **Environmental conditions**: Rain, fog, occlusion.

**Robust Physical Perturbations (RP2)**: The RP2 algorithm extends Expectation over Transformation (EOT) to generate physically robust adversarial examples:

```python
# Conceptual RP2 approach
def rp2_attack(model, x, y, epsilon, num_transforms=30):
    """Generate physically robust adversarial examples using EOT."""
    x_adv = x.clone().detach().requires_grad_(True)
    optimizer = torch.optim.Adam([x_adv], lr=0.01)

    for step in range(num_iter):
        total_loss = 0
        for _ in range(num_transforms):
            x_transformed = apply_random_transform(x_adv,
                rotations=(-30, 30),
                scales=(0.5, 2.0),
                brightness=(-0.3, 0.3),
                noise_std=0.05
            )
            loss = F.cross_entropy(model(x_transformed), y)
            total_loss += loss
        avg_loss = total_loss / num_transforms
        optimizer.zero_grad()
        avg_loss.backward()
        optimizer.step()
        delta = torch.clamp(x_adv - x, -epsilon, epsilon)
        x_adv = torch.clamp(x + delta, 0, 1)

    return x_adv.detach()
```

### 4.2 Adversarial Patches

Adversarial patches (Brown et al., 2017, "Adversarial Patch") are localized, printable perturbations that can be placed anywhere in the scene to cause misclassification. Unlike full-image perturbations, patches are constrained to a small region and work regardless of the background.

```python
def train_adversarial_patch(model, target_class, patch_size=64, num_epochs=100):
    """Train an adversarial patch that causes misclassification when applied to any image."""
    patch = torch.randn(3, patch_size, patch_size, requires_grad=True)
    optimizer = torch.optim.Adam([patch], lr=0.01)

    for epoch in range(num_epochs):
        for batch_images, _ in dataloader:
            patched_images = apply_patch(batch_images, patch)
            logits = model(patched_images)
            loss = -F.cross_entropy(logits, torch.full((len(batch_images),), target_class))
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            patch.data = torch.clamp(patch.data, 0, 1)

    return patch.detach()
```

**Real-World Adversarial Patch Attacks**:
- **Face recognition evasion**: Printed adversarial eyeglass frames that cause face recognition to misidentify the wearer (Sharif et al., 2016).
- **Object detection evasion**: Adversarial patches that cause YOLO and Faster R-CNN to miss objects (Thys et al., 2019, "Fooling automated surveillance cameras").
- **Autonomous vehicle attacks**: Adversarial patches on road surfaces that cause lane detection failure.
- **QR code attacks**: Adversarial perturbations on QR codes that cause misreading by QR scanners while remaining scannable by correct decoders.

### 4.3 Adversarial Examples in Other Domains

**Audio**: Carlini & Wagner (2018) demonstrated audio adversarial examples against speech recognition (Deeplearning2.0). A perturbation of ~1% amplitude causes targeted mis-transcription. Qin et al. (2019) showed imperceptible audio adversarial examples.

**Malware Detection**: Adversarial examples against PE file classifiers (Demetrio et al., 2021) modify header fields and section characteristics while preserving executable functionality. Grosse et al. (2017) showed adversarial perturbations against Android malware detectors.

**Network Traffic**: Adversarial examples against network intrusion detection systems (NIDS) modify packet features to evade detection while preserving attack functionality.

**Text**: Adversarial examples for NLP modify tokens in text inputs to cause misclassification (Ebrahimi et al., 2018, "HotFlip"; Gao et al., 2018, "TextFooler").

**Tabular Data**: Adversarial examples for fraud detection modify transaction features within feasible constraints (e.g., changing transaction amount but keeping the merchant the same).

---

## 5. Transferability of Adversarial Examples

### 5.1 Transferability Properties

Transferability is the property that adversarial examples crafted for one model can fool another model. This is critical for black-box attacks where the attacker cannot access the target model's gradients.

**Intra-model Transfer**: Adversarial examples transfer between instances of the same architecture with different initializations or training data. Transfer rates are typically 80-100%.

**Cross-Architecture Transfer**: Adversarial examples transfer between models with different architectures (e.g., from ResNet to DenseNet). Transfer rates are typically 30-70% for untargeted attacks and 5-30% for targeted attacks.

**Cross-Task Transfer**: Adversarial examples transfer between models trained for different tasks on the same domain. Transfer rates are typically 10-40%.

### 5.2 Factors Affecting Transferability

**Model Similarity**: More similar architectures transfer better. This creates a security risk — if an attacker trains a similar surrogate model, transfer attacks are highly effective.

**Decision Boundary Alignment**: Models trained on the same data tend to align their decision boundaries near the data manifold. Adversarial perturbations that move inputs perpendicular to the data manifold transfer better because they exploit shared boundary geometry.

**Gradient Alignment**: The cosine similarity of gradients between source and target models predicts transferability (Liu et al., 2017). Models with higher gradient alignment transfer adversarial examples more effectively.

**Attack Method**: MI-FGSM and ensemble-based attacks produce the most transferable adversarial examples. C&W attacks, while more effective in white-box settings, tend to be less transferable because they overfit to the source model's decision boundary.

### 5.3 Transferability as a Security Threat

The transferability phenomenon has profound security implications:

1. **Black-box attacks are practical**: An attacker can train a surrogate model on publicly available data, craft adversarial examples against the surrogate, and transfer them to the target API.

2. **Theoretical lower bound on defense**: No single-model defense can prevent transfer attacks. Adversarial training against one attack model does not guarantee robustness against transfer from a different model.

3. **Ensemble defenses are necessary**: Training an ensemble of diverse models and using their consensus as the prediction provides some robustness against transfer attacks (Tramer et al., 2020).

---

## 6. Adversarial Detection and Defenses

### 6.1 Adversarial Training

Adversarial training (Madry et al., 2018) augments training data with adversarial examples:

$$\min_\theta \mathbb{E}_{(x,y) \sim \mathcal{D}} \left[ \max_{\delta \in S} J(\theta, x + \delta, y) \right]$$

This is formulated as a min-max optimization where the inner maximization finds the worst-case perturbation (via PGD), and the outer minimization updates the model to be robust against it.

```python
def adversarial_train(model, train_loader, optimizer, epsilon, alpha, num_iter):
    model.train()
    for x, y in train_loader:
        # Inner maximization: find adversarial example
        x_adv = pgd_attack(model, x, y, epsilon, alpha, num_iter)

        # Outer minimization: train on adversarial examples
        optimizer.zero_grad()
        logits = model(x_adv)
        loss = F.cross_entropy(logits, y)
        loss.backward()
        optimizer.step()
```

**Trade-offs of Adversarial Training**:
- **Clean accuracy degradation**: Adversarially trained models typically lose 5-15% clean accuracy compared to standard models.
- **Robustness-accuracy tradeoff**: There is a fundamental tension between standard accuracy and adversarial robustness (Zhang et al., 2019/TRADES).
- **Computational cost**: PGD-based adversarial training requires 7-10 forward-backward passes per training step, increasing training time by 7-10x.
- **Catastrophic overfitting**: Training with strong inner attacks (many PGD steps) can cause the model to become robust to multi-step attacks but vulnerable to single-step attacks (Wong et al., 2020).

**CIFAR-10 and ImageNet Benchmarks**:
- Standard model: ~95% clean accuracy, ~0% adversarial accuracy
- Adversarially trained ($\epsilon = 8/255$): ~87% clean accuracy, ~53% adversarial accuracy (Madry et al.)
- AutoAttack benchmark (https://www.autoattack.org/): Standard for evaluating adversarial robustness claims

### 6.2 Defensive Distillation

Defensive distillation (Papernot et al., 2016, "Distillation as a Defense to Adversarial Perturbations against Deep Neural Networks") trains a second model using soft labels from the first model:

1. Train model $f_{\theta_1}$ at temperature $T$ on hard labels.
2. Generate soft labels: $\tilde{y} = \text{softmax}(f_{\theta_1}(x) / T)$.
3. Train model $f_{\theta_2}$ at temperature $T$ using soft labels $\tilde{y}$.

The temperature parameter $T$ flattens the softmax distribution, providing "dark knowledge" about class relationships. Defensive distillation was claimed to reduce adversarial example success rates, but Carlini & Wagner (2017) showed it merely gradient-masks — hiding gradients rather than truly improving robustness. C&W attacks bypass distillation defenses.

### 6.3 Input Preprocessing Defenses

**Feature Squeezing** (Xu et al., 2017): Reduces the color bit depth and applies spatial smoothing to remove adversarial perturbations. Effective against small perturbations but can be circumvented by larger perturbations that survive the squeezing.

**JPEG Compression**: Converts images to JPEG format and back, discarding high-frequency components where adversarial perturbations concentrate. Partially effective but circumventable (Shin & Kim, 2017).

**Bit Depth Reduction**: Reduces color depth (e.g., from 8-bit to 3-bit), quantizing adversarial perturbations. Ineffective against attacks designed to survive quantization.

**Spatial Smoothing**: Applies Gaussian or median filtering to remove adversarial noise. Effective against $L_\infty$ perturbations but introduces blurring that degrades clean accuracy.

**Input Randomization**: Applies random resizing and padding to input images before classification (Xie et al., 2018). Improves robustness against transfer attacks but provides marginal benefit against white-box attacks.

**Limitation**: Most input preprocessing defenses suffer from **obfuscated gradients** — they make gradient computation difficult but do not provide genuine robustness. Athalye et al. (2018, "Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples") systematically broke 7 of 8 ICLR 2018 defense papers using adaptive attacks.

### 6.4 Ensemble Methods

**Adaptive Diversity Ensemble** (Pang et al., 2019): Train an ensemble of models with a diversity-promoting loss that encourages different models to make different mistakes. The ensemble prediction is more robust than any individual model.

**Randomized Smoothing** (Cohen et al., 2019): Guarantees certified robustness by averaging predictions over random noise perturbations. For input $x$, the smoothed classifier is:

$$g(x) = \operatorname{argmax}_c \Pr(f(x + \epsilon) = c)$$

Where $\epsilon \sim \mathcal{N}(0, \sigma^2 I)$. The certified radius is:

$$r = \frac{\sigma}{2} \left( \Phi^{-1}(p_A) - \Phi^{-1}(p_B) \right)$$

Where $p_A$ is the probability of the top class, $p_B$ is the probability of the second class, and $\Phi^{-1}$ is the inverse Gaussian CDF.

```python
from certify import certify # Cohen et al. implementation

def smoothed_predict(model, x, sigma, n_samples=1000):
    predictions = []
    for _ in range(n_samples):
        noise = torch.randn_like(x) * sigma
        pred = model(x + noise).argmax(dim=1)
        predictions.append(pred)
    counts = torch.bincount(torch.cat(predictions))
    return counts.argmax()
```

### 6.5 TRADES: A Principled Tradeoff

TRADES (Zhang et al., 2019, "Theoretically Grounded Tradeoff Between Robustness and Accuracy") decomposes the robustness-accuracy tradeoff into two terms:

$$\min_\theta \mathbb{E}_{(x,y)} \left[ \underbrace{J(\theta, x, y)}_{\text{cross-entropy loss on clean examples}} + \beta \cdot \underbrace{\max_{x' \in S} J(\theta, x, f_{\theta}(x'))}_{\text{KL divergence between clean and adversarial predictions}} \right]$$

The hyperparameter $\beta$ controls the tradeoff between accuracy and robustness:
- $\beta \to 0$: Equivalent to standard training (high accuracy, low robustness).
- $\beta \to \infty$: Equivalent to adversarial training (low accuracy, high robustness).

**TRADES achieved state-of-the-art certified robustness** on CIFAR-10 ($\ell_\infty$ robustness accuracy of 56.43% at $\epsilon = 8/255$) and remains the standard approach for provably robust classification.

```python
def trades_train(model, x, y, optimizer, epsilon, alpha, num_iter, beta):
    # Standard cross-entropy loss on clean examples
    logits_clean = model(x)
    loss_clean = F.cross_entropy(logits_clean, y)

    # Adversarial example generation for TRADES
    x_adv = pgd_attack(model, x, y, epsilon, alpha, num_iter)

    # KL divergence between clean and adversarial predictions
    logits_adv = model(x_adv)
    loss_kl = F.kl_div(
        F.log_softmax(logits_adv, dim=1),
        F.softmax(logits_clean, dim=1),
        reduction='batchmean'
    )

    loss = loss_clean + beta * loss_kl
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
```

### 6.6 Certified Robustness

Certified robustness provides mathematical guarantees that no adversarial example exists within a specified perturbation bound.

**Exact Certification** (for small models): Mixed-integer programming (MIP) formulations that exactly verify robustness properties. Scalable to networks with ~100 neurons per layer (Tjeng et al., 2019).

**Abstract Interpretation**: Uses abstract domains (intervals, zonotopes, DeepPoly) to propagate bounds through network layers. Provides sound (but incomplete) robustness certificates.

**Randomized Smoothing** (Cohen et al., 2019): The most scalable certified defense. See Section 6.4 above. Provides probabilistic certificates for $L_2$ robustness that scale to ImageNet.

**CROWN/β-CROWN** (Zhang et al., 2022): Neural network verification via bound propagation. β-CROWN adds neuron split constraints, enabling tighter bounds than previous methods. Benchmarked on VNN-COMP (Verification Neural Network Competition).

**Limitations**: Certified methods provide robustness guarantees for specific threat models ($L_p$ bounded perturbations) but do not defend against other attack types (spatial transformations, semantic adversarial examples, distribution shifts).

---

## 7. Attack Implementations with CleverHans and ART

### 7.1 CleverHans

CleverHans (Papernot et al.) is a PyTorch/TensorFlow library for benchmarking adversarial attacks and defenses.

```python
import torch
import torchvision
import numpy as np
from cleverhans.torch.attacks.projected_gradient_descent import (
    projected_gradient_descent,
)
from cleverhans.torch.attacks.carlini_wagner_l2 import carlini_wagner_l2

model = torchvision.models.resnet50(pretrained=True).eval()
x = torch.randn(1, 3, 224, 224)

# PGD attack
x_adv_pgd = projected_gradient_descent(
    model_fn=model,
    x=x,
    eps=8/255,
    eps_iter=2/255,
    nb_iter=20,
    norm=np.inf,
    clip_min=0.0,
    clip_max=1.0,
)

# C&W L2 attack
x_adv_cw = carlini_wagner_l2(
    model_fn=model,
    x=x,
    num_classes=1000,
    y=torch.tensor([281]),
)
```

### 7.2 Adversarial Robustness Toolbox (ART)

ART (IBM) provides a comprehensive framework for adversarial ML with support for TensorFlow, PyTorch, Keras, and scikit-learn.

```python
import numpy as np
from art.attacks.evasion import (
    FastGradientMethod,
    ProjectedGradientDescent,
    CarliniL2Method,
    AutoAttack,
)
from art.estimators.classification import PyTorchClassifier
import torch.nn as nn

model = nn.Sequential(
    nn.Conv2d(1, 32, 3), nn.ReLU(),
    nn.Conv2d(32, 64, 3), nn.ReLU(),
    nn.MaxPool2d(2), nn.Flatten(),
    nn.Linear(9216, 128), nn.ReLU(),
    nn.Linear(128, 10),
)

classifier = PyTorchClassifier(
    model=model,
    clip_values=(0, 1),
    loss=nn.CrossEntropyLoss(),
    optimizer=torch.optim.Adam(model.parameters(), lr=0.01),
    input_shape=(1, 28, 28),
    nb_classes=10,
)

# PGD attack
attack_pgd = ProjectedGradientDescent(
    estimator=classifier,
    norm=np.inf,
    eps=0.3,
    eps_step=0.01,
    max_iter=20,
)
x_adv = attack_pgd.generate(x=x_test)

# AutoAttack for robust evaluation
attack_auto = AutoAttack(
    estimator=classifier,
    norm=np.inf,
    eps=0.3,
)
x_adv = attack_auto.generate(x=x_test)
```

### 7.3 Defensive Training with ART

```python
from art.defences.trainer import AdversarialTrainerPGD

# Adversarial training with PGD
trainer = AdversarialTrainerPGD(
    classifier=classifier,
    nb_epochs=100,
    eps=0.3,
    eps_step=0.01,
    max_iter=7,
)
trainer.fit(x_train, y_train)

# Evaluate robust accuracy
predictions_clean = classifier.predict(x_test)
predictions_adv = classifier.predict(x_adv)
clean_acc = np.mean(np.argmax(predictions_clean, axis=1) == np.argmax(y_test, axis=1))
robust_acc = np.mean(np.argmax(predictions_adv, axis=1) == np.argmax(y_test, axis=1))
print(f"Clean accuracy: {clean_acc:.4f}")
print(f"Robust accuracy: {robust_acc:.4f}")
```

---

## 8. Adversarial ML in Practice

### 8.1 Real-World Attack Scenarios

**Autonomous Vehicles**: Researchers have demonstrated physical-world attacks against traffic sign recognition, lane detection, and pedestrian detection. The Tesla Autopilot lane detection evasion (Keen Security Lab, 2019) and the Mobileye stop sign evasion (Eykholt et al., 2018) are landmark demonstrations.

**Malware Detection**: Adversarial PE files that evade ML-based malware detection (Demetrio et al., 2021). These attacks modify file structure while preserving functionality.

**Facial Recognition**: Adversarial glasses and makeup patterns that cause face recognition systems to misidentify individuals (Sharif et al., 2016; Komkov & Lempitsky, 2019).

**Medical Imaging**: Adversarial perturbations on medical images that cause misdiagnosis (Finlayson et al., 2019). Perturbations too small for radiologists to detect can change diagnosis from benign to malignant.

**Content Moderation**: Adversarial text and image modifications that bypass content moderation systems on social media platforms.

### 8.2 Evaluation Standards

The robustness evaluation community has converged on several standards:

**AutoAttack** (Croce & Hein, 2020): The default evaluation suite for $L_\infty$ and $L_2$ robustness. Combines APGD-CE, APGD-DLR, FAB, and Square Attack. If a defense claims robustness, it should be evaluated against AutoAttack.

**RobustBench** (https://robustbench.org): Standardized benchmark for adversarial robustness. Provides leaderboard rankings of models by AutoAttack accuracy on CIFAR-10, CIFAR-100, and ImageNet.

**VNN-COMP** (Verification Neural Network Competition): Annual competition for certified robustness verification tools.

**ML Safety GitHub** (https://github.com/centerforaisafety): Aggregated resources for ML safety evaluation.

### 8.3 Open Problems

1. **Adversarial robustness in the real world**: Lab attacks (digital perturbations, fixed conditions) do not always transfer to real-world conditions (physical objects, variable environment).

2. **Robustness beyond $L_p$ norms**: Most defenses and certifications assume $L_p$-bounded perturbations. Real-world attacks may involve semantic changes (rotation, translation, lighting) that are not captured by $L_p$ bounds.

3. **Adversarial robustness for NLP and LLMs**: Token-level adversarial attacks on text are qualitatively different from image perturbations. The discrete, compositional nature of language creates fundamentally different attack surfaces.

4. **Certified robustness at scale**: Current certification methods either provide tight bounds for small models (MIP, abstract interpretation) or loose bounds for large models (randomized smoothing). Scalable, tight certification for production models remains an open problem.

5. **The robustness-accuracy tradeoff**: TRADES provides a theoretical framework, but the empirical Pareto frontier between clean accuracy and robust accuracy is not well characterized for large-scale models.

---

## 9. Key References

1. Athalye, A., et al. (2018). "Obfuscated Gradients Give a False Sense of Security." ICML.
2. Brown, T. B., et al. (2017). "Adversarial Patch." arXiv:1712.09665.
3. Carlini, N., & Wagner, D. (2017). "Towards Evaluating the Robustness of Neural Networks." IEEE S&P.
4. Cohen, J., et al. (2019). "Certified Robustness to Adversarial Examples via Randomized Smoothing." ICML.
5. Croce, F., & Hein, M. (2020). "Reliable evaluation of adversarial robustness with an ensemble of diverse attacks." ICML.
6. Dong, Y., et al. (2018). "Boosting Adversarial Attacks with Momentum." CVPR.
7. Eykholt, K., et al. (2018). "Robust Physical-World Attacks on Deep Learning Visual Classification." CVPR.
8. Goodfellow, I., et al. (2015). "Explaining and Harnessing Adversarial Examples." ICLR.
9. Madry, A., et al. (2018). "Towards Deep Learning Models Resistant to Adversarial Attacks." ICLR.
10. Papernot, N., et al. (2016). "Transferability in Machine Learning: from Phenomena to Black-Box Attacks." arXiv.
11. Papernot, N., et al. (2016). "Distillation as a Defense to Adversarial Perturbations." IEEE S&P.
12. Szegedy, C., et al. (2014). "Intriguing Properties of Neural Networks." ICLR.
13. Zhang, H., et al. (2019). "Theoretically Grounded Tradeoff Between Robustness and Accuracy." ICML.
14. Zhang, H., et al. (2022). "β-CROWN: Efficient Bound Propagation for Neural Network Robustness Verification." NeurIPS.

## References

1. Athalye, A., et al. (2018). "Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples." *ICML*.
2. Belkin, M., et al. (2019). "Reconciling Modern Machine Learning and the Bias-Variance Trade-Off." *PNAS*.
3. Brendel, W., et al. (2018). "Decision-Based Adversarial Attacks: Reliable Attacks Against Avoiding Misclassification." *arXiv*.
4. Brown, T. B., et al. (2017). "Adversarial Patch." *arXiv:1712.09665*.
5. Carlini, N., & Wagner, D. (2017). "Towards Evaluating the Robustness of Neural Networks." *IEEE S&P*.
6. Carlini, N., & Wagner, D. (2018). "Audio Adversarial Examples: Targeted Attacks on Speech-to-Text." *IEEE S&P*.
7. Chen, J., et al. (2020). "HopSkipJumpAttack: A Query-Efficient Decision-Based Attack." *CVPR*.
8. Cohen, J., et al. (2019). "Certified Robustness to Adversarial Examples via Randomized Smoothing." *ICML*.
9. Croce, F., & Hein, M. (2020). "Reliable Evaluation of Adversarial Robustness with AutoAttack." *ICML*.
10. Dong, Y., et al. (2018). "Boosting Adversarial Attacks with Momentum." *CVPR*.
11. Ebrahimi, J., et al. (2018). "HotFlip: White-Box Adversarial Examples for Text Classification." *ACL*.
12. Eykholt, K., et al. (2018). "Robust Physical-World Attacks on Deep Learning Visual Classification." *CVPR*.
13. Gao, J., et al. (2018). "Black-Box Generation of Adversarial Text Examples to Evade Deep Learning Filters." *arXiv*.
14. Gilmer, J., et al. (2018). "Adversarial Spheres." *ICML Workshop*.
15. Goodfellow, I., et al. (2015). "Explaining and Harnessing Adversarial Examples." *ICLR*.
16. Ilyas, A., et al. (2019). "Adversarial Examples Are Not Bugs, They Are Features." *NeurIPS*.
17. Liu, Y., et al. (2017). "Delving into Transferable Adversarial Examples." *CVPR*.
18. Madry, A., et al. (2018). "Towards Deep Learning Models Resistant to Adversarial Attacks." *ICLR*.
19. Moosavi-Dezfooli, S., et al. (2016). "DeepFool: A Simple and Accurate Method to Fool Deep Neural Networks." *CVPR*.
20. Papernot, N., et al. (2016). "Transferability in Machine Learning: from Phenomena to Black-Box Attacks." *arXiv*.
21. Papernot, N., et al. (2016). "Distillation as a Defense to Adversarial Perturbations Against Deep Neural Networks." *IEEE S&P*.
22. Sharif, M., et al. (2016). "Accessorize to a Crime: Real and Stealthy Attacks on State-of-the-Art Face Recognition." *CCS*.
23. Szegedy, C., et al. (2014). "Intriguing Properties of Neural Networks." *ICLR*.
24. Thys, S., et al. (2019). "Fooling Automated Surveillance Cameras: Adversarial Patches Against Object Detection." *CVPR Workshops*.
25. Tramer, F., et al. (2020). "The Space of Transferable Adversarial Examples." *arXiv*.
26. Wong, E., et al. (2020). "Fast is Better than Free: Revisiting Adversarial Training." *ICLR*.
27. Xie, C., et al. (2019). "Improving Transferability of Adversarial Examples with Input Diversity." *CVPR*.
28. Zhang, H., et al. (2019). "Theoretically Grounded Tradeoff Between Robustness and Accuracy." *ICML*.
29. Zhang, H., et al. (2022). "β-CROWN: Efficient Bound Propagation for Neural Network Robustness Verification." *NeurIPS*.
30. Papernot, N., et al. (2016). "The Limitations of Deep Learning in Adversarial Settings." *EuroS&P*.
31. Andriushchenko, M., et al. (2020). "Square Attack: A Query-Efficient Score-Based Black-Box Adversarial Attack." *ECCV*.
32. Qin, Y., et al. (2019). "Imperceptible, Robust, and Targeted Adversarial Examples for Automatic Speech Recognition." *ICML*.
33. Grosse, K., et al. (2017). "Adversarial Examples for Malware Detection." *EuroS&P*.
34. Papernot, N., et al. (2016). "CleverHans: An Adversarial Example Library." https://github.com/cleverhans-lab/cleverhans
35. Nicolae, M., et al. (2019). "Adversarial Robustness Toolbox v1.0.0." *IBM Research*. https://github.com/Trusted-AI/adversarial-robustness-toolbox
36. RobustBench (2023). "Adversarial Robustness Leaderboard." https://robustbench.org