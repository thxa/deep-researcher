# 08 — Fine-Tuning Techniques & Alignment Methods

> A deep-dive into adapting large language models: from full parameter updates to parameter-efficient methods, and from supervised fine-tuning through RLHF to modern direct alignment approaches.

---

## Table of Contents

1. [Full Fine-Tuning vs PEFT](#1-full-fine-tuning-vs-peft)
2. [PEFT Techniques in Detail](#2-peft-techniques-in-detail)
3. [LoRA Deep Dive](#3-lora-deep-dive)
4. [Supervised Fine-Tuning (SFT)](#4-supervised-fine-tuning-sft)
5. [RLHF — Reinforcement Learning from Human Feedback](#5-rlhf--reinforcement-learning-from-human-feedback)
6. [DPO and Variants](#6-dpo-and-variants)
7. [Constitutional AI and Self-Alignment](#7-constitutional-ai-and-self-alignment)
8. [Instruction Tuning & Chat Template Design](#8-instruction-tuning--chat-template-design)
9. [Domain Adaptation Fine-Tuning](#9-domain-adaptation-fine-tuning)
10. [Fine-Tuning Frameworks](#10-fine-tuning-frameworks)
11. [Practical Tips](#11-practical-tips)

---

## 1. Full Fine-Tuning vs PEFT

### 1.1 Full Fine-Tuning

Full fine-tuning updates **every parameter** in the model. For a 70B-parameter model, this means optimizing all 70B weights during backpropagation. This approach yields the maximum expressivity and capacity to learn new behaviors, but at enormous cost:

| Aspect | Full Fine-Tuning | PEFT |
|---|---|---|
| Trainable params | 100% | 0.01–5% |
| GPU memory (70B, bf16) | ~140 GB | ~20–40 GB |
| Training time | High | Low |
| Catastrophic forgetting risk | High | Low |
| Multiple task switching | One model per task | Swap adapters |
| Deployment | One full copy per task | Merge or hot-swap |

### 1.2 Parameter-Efficient Fine-Tuning (PEFT)

PEFT methods freeze the pre-trained base model and introduce a small number of trainable parameters. The base model acts as a fixed feature extractor, while the new parameters adapt its behavior to the target task.

```
┌──────────────────────────────────────────────────────────────────────┐
│                    PEFT METHODS COMPARISON                           │
├──────────────┬───────────┬──────────┬──────────┬───────────┬─────────┤
│   Method     │ Added %   │ Inference│ Training │ Inference │ Task    │
│              │ Params    │ Overhead │ Speedup  │ Quality   │ Switch │
├──────────────┼───────────┼──────────┼──────────┼───────────┼─────────┤
│ LoRA         │ ~0.1-1%   │ None*    │ ~3x      │ ★★★★★    │ Merge   │
│ QLoRA        │ ~0.1-1%   │ None*    │ ~5x      │ ★★★★☆    │ Merge   │
│ AdaLoRA      │ ~0.1-1%   │ None*    │ ~3x      │ ★★★★★    │ Merge   │
│ IA³          │ ~0.01%    │ None*    │ ~4x      │ ★★★★☆    │ Merge   │
│ Prefix Tun.  │ ~0.1%     │ Latency  │ ~3x      │ ★★★☆☆    │ Swap    │
│ Prompt Tun.  │ ~0.01%    │ Minimal  │ ~5x      │ ★★★☆☆    │ Swap    │
│ Adapters     │ ~1-5%     │ Latency  │ ~2x      │ ★★★★☆    │ Swap    │
│ Full FT      │ 100%      │ None     │ 1x       │ ★★★★★    │ N/A     │
├──────────────┴───────────┴──────────┴──────────┴───────────┴─────────┤
│  * After merging LoRA deltas back into base weights                 │
└──────────────────────────────────────────────────────────────────────┘

  Parameter Budget vs Quality Trade-off:

  Quality
    ▲
    │          ★ Full FT
    │         ╱
    │       ★ LoRA / AdaLoRA
    │      ╱    ★ QLoRA
    │    ╱      ★ Adapters
    │   ╱           ★ IA³
    │  ╱       ★ Prefix Tuning
    │ ╱              ★ Prompt Tuning
    │╱
    └──────────────────────────────────▶ Trainable Params %
     0%      0.1%     1%      10%    100%
```

---

## 2. PEFT Techniques in Detail

### 2.1 LoRA (Low-Rank Adaptation)

LoRA decomposes weight updates into low-rank matrices. Instead of updating a weight matrix `W₀ ∈ ℝ^{d×k}` directly, it adds a delta `ΔW = BA` where `B ∈ ℝ^{d×r}` and `A ∈ ℝ^{r×k}` with rank `r << min(d, k)`.

**Key properties:**
- At inference, `ΔW` can be merged into `W₀` — zero latency cost
- Multiple LoRA adapters can be trained for different tasks and hot-swapped
- Typically applied to query and value projection matrices in attention layers

### 2.2 QLoRA (Quantized LoRA)

QLoRA combines 4-bit NormalFloat (NF4) quantization of the base model with LoRA adapters trained in bf16. The three innovations are:

1. **NF4 quantization** — information-theoretically optimal for normally-distributed weights
2. **Double quantization** — quantize the quantization constants themselves to save memory
3. **Paged optimizers** — leverage CPU RAM via unified memory to avoid OOM during checkpointing

```
  Memory breakdown for 65B model:

  Full FT (bf16):     ████████████████████████████████████████  ~130 GB
  LoRA (bf16):        ████████████████████                     ~80 GB
  QLoRA (4-bit):      █████                                     ~10 GB
                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                       Base model quantized to NF4 (4 bits)
```

### 2.3 AdaLoRA

AdaLoRA dynamically allocates the parameter budget across layers. Instead of a uniform rank `r` for every module, it learns which layers need higher or lower rank:

- Layers that are more critical for the target task receive higher rank
- Less important layers get lower rank, saving parameters
- Uses an importance score based on the singular values of the delta matrix
- Prunes less important ranks during training via a regularization term

The total parameter budget is fixed, but distributed non-uniformly: `Σ r_i = budget`.

### 2.4 IA³ (Infused Adapter by Inhibiting and Amplifying Inner Activations)

IA³ injects three learned vectors rather than matrices — one each to scale keys, values, and feed-forward activations:

```
  Standard Attention:     attn = softmax(Q · Kᵀ / √d) · V
  IA³ Attention:          attn = softmax(Q · (l_k ⊙ K)ᵀ / √d) · (l_v ⊙ V)

  Standard FFN:           out = W₂ · act(W₁ · x)
  IA³ FFN:                out = W₂ · act(W₁ · (l_ff ⊙ x))

  l_k, l_v ∈ ℝ^{d_k},  l_ff ∈ ℝ^{d_ff}    (vectors, not matrices!)
```

This reduces learnable parameters to ~0.01% of the model — the most parameter-efficient method among those that preserve full model quality.

### 2.5 Prefix Tuning

Prefix tuning prepends `N` trainable "virtual tokens" to every attention layer's key-value cache. These tokens do not correspond to real words — they are free parameters learned via backpropagation.

```
  ┌─────────────────────────────────────────────────┐
  │              Prefix Tuning                       │
  │                                                 │
  │  Real input:     [x₁] [x₂] [x₃] ... [xₙ]      │
  │                  ─────────────────────────       │
  │  Virtual prefix: [p₁] [p₂] ... [pₙ]            │
  │                  ───────────────────            │
  │                                                 │
  │  K, V = concat([Pₖ, K_real], [Pᵥ, V_real])     │
  │                                                 │
  │  Pₖ, Pᵥ are learned per layer                  │
  │  Only the prefix embeddings are trainable       │
  └─────────────────────────────────────────────────┘

  Note: At inference, the prefix occupies context window space,
  adding N tokens per layer to the KV cache.
```

### 2.6 Prompt Tuning

Prompt tuning is the simplest PEFT method — it learns a single sequence of soft tokens prepended to the input at the **embedding layer only** (not per-layer like prefix tuning). The entire prompt is a matrix `P ∈ ℝ^{l×d}` where `l` is prompt length and `d` is hidden size.

- Easiest to implement
- Least computational overhead
- Tends to be less expressive than LoRA and adapters
- Works best with larger models (≥10B parameters)

### 2.7 Adapters (Houlsby-style)

Adapters insert small bottleneck feed-forward modules between Transformer layers:

```
  ┌────────────────────────────────────────────┐
  │           Adapter Block                    │
  │                                            │
  │  x ─→ Down Projection ─→ ReLU ─→ Up Proj. ─→ + x (residual)
  │         (d → r)                (r → d)     │
  │                                            │
  │  Typically r = 16-64                       │
  │  Adds ~1.5-4% parameters                   │
  └────────────────────────────────────────────┘

  Placement (Houlsby): after both self-attention and FFN
  Placement (Pfeiffer): after FFN only (more parameter-efficient)
```

---

## 3. LoRA Deep Dive

### 3.1 Architecture Diagram

```
                    LoRA Modification of a Linear Layer

  Input x ──┬──────────────────────────────────────────────┬──► Output
             │                                              │
             ▼                                              │
        ┌─────────┐                                        │
        │  W₀     │   Pre-trained weights (FROZEN)         │
        │ d × k   │                                        │
        └─────────┘                                        │
             │                                              │
             │     ┌──────────────────────┐                │
             │     │    LoRA Branch       │                │
             │     │  ┌─────┐  ┌─────┐  │                │
             ├────►│  │  A  │─►│  B  │──┼────────────────┘
             │     │  │r × k│  │d × r│  │    ΔW = BA
             │     │  └─────┘  └─────┘  │    (trainable)
             │     └──────────────────────┘
             │
             │   W = W₀ + ΔW = W₀ + BA
             │
             │   Where: r << min(d, k)
             │   A initialized with Gaussian: N(0, σ²)
             │   B initialized to zero ⇒ ΔW = 0 at start

  Example: d=4096, k=4096, r=8
  ──────────────────────────────────
  Full update:       4096 × 4096 = 16,777,216 params
  LoRA update:  2 × (4096 × 8)  =     65,536 params
  Reduction:                         ~0.4% of full update
```

### 3.2 Mathematical Derivation

The core insight is that pre-trained language models have an **intrinsic low-rank dimensionality**. While a weight matrix `W₀ ∈ ℝ^{d×k}` has rank up to `min(d,k)`, the effective rank needed for adaptation is far lower.

**Aghajanyan et al. (2021)** showed that pre-trained models already live in a low intrinsic dimension — the delta needed to adapt to a new task `ΔW` has a low effective rank. Specifically, they demonstrated that `ΔW` can be approximated by a rank-`r` matrix where `r << min(d,k)`.

**Formal setup:**

```
  h = W₀ · x + ΔW · x
    = W₀ · x + B · A · x

  Where:
    W₀ ∈ ℝ^{d×k}   — frozen pre-trained weight
    A  ∈ ℝ^{r×k}   — low-rank projection (down)
    B  ∈ ℝ^{d×r}   — low-rank projection (up)
    r  << min(d, k) — bottleneck dimension

  Initialization:
    A ← N(0, σ²)   (random Gaussian, σ typically 0.01)
    B ← 0           (zero matrix)

    → At initialization, ΔW = BA = 0
    → Model starts identical to pre-trained behavior
    → Gradients flow through B to update the decomposition
```

**Scaling with alpha:** Hu et al. (2021) introduced a scaling factor `α` to control the magnitude of the LoRA update independently of rank:

```
  h = W₀ · x + (α / r) · B · A · x

  The (α/r) scaling ensures that:
  1. When r changes, the effective learning rate for ΔW stays constant
  2. α acts as a hyperparameter controlling adapter "strength"
  3. Common choice: α = 2r (i.e., α/r = 2)
```

**Gradient analysis:**

```
  ∂L/∂A = Bᵀ · (∂L/∂h) · xᵀ · (α/r)
  ∂L/∂B = (∂L/∂h) · A · xᵀ · (α/r)

  Number of trainable parameters per layer:
    |A| + |B| = r × k + d × r = r × (d + k)

  Compare to full fine-tuning: d × k
  Ratio: r(d + k) / (dk) ≈ 2r/d  (when d ≈ k)
```

### 3.3 Rank (r) Selection

| Rank | Use Case | % Params (7B) | Notes |
|------|----------|---------------|-------|
| 1–4 | Style / format tasks | ~0.01% | Minimal change |
| 8–16 | Single domain adaptation | ~0.05% | Good default |
| 32–64 | Multi-task, complex reasoning | ~0.2% | Balances capacity & efficiency |
| 128+ | Approaching full fine-tuning quality | ~0.5%+ | Diminishing returns |

**Practical heuristic:** Start with `r=8` and `α=16`, then sweep. If training loss stalls early, increase rank. If overfitting occurs, decrease rank.

### 3.4 Target Modules

The choice of which layers to apply LoRA to significantly impacts performance:

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    Target Module Options                    │
  ├────────────────────────┬────────────────────────────────────┤
  │  Conservative (faster)  │  Aggressive (better quality)       │
  │                        │                                    │
  │  Q, V projections      │  Q, K, V, O projections           │
  │  (2 matrices/layer)    │  (4 matrices/layer)               │
  │                        │                                    │
  │  + attention only      │  + FFN gate, up, down projections  │
  │                        │  (7 matrices/layer)               │
  │                        │                                    │
  │  ~0.1% params          │  ~0.5-1% params                    │
  │  Quick experiments     │  Maximum quality                   │
  └────────────────────────┴────────────────────────────────────┘
```

Common naming in HuggingFace models:
- LLaMA: `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj`
- Mistral: Same as LLaMA
- GPT-NeoX: `query_key_value, dense, dense_h_to_4h, dense_4h_to_h`

### 3.5 LoRA Merging

After training, the LoRA deltas can be **merged** into the base weights for zero-cost inference:

```python
# Merging: W_merged = W₀ + (α/r) · B · A
W_merged = W_base + (alpha / rank) * (B @ A)

# This is done in float32 for numerical stability:
# 1. Compute BA in float32
# 2. Scale by alpha/rank
# 3. Add to base weights
# 4. Re-quantize if using quantized base
```

**Multi-LoRA serving:** When you need to serve multiple adapters simultaneously (e.g., different users need different adaptations), the base model stays frozen and adapters are loaded on-the-fly:

```
  ┌─────────────┐
  │  Base Model  │  (shared, loaded once in GPU memory)
  │  (frozen)    │
  └──────┬──────┘
         │
    ┌────┼────┬────────────┐
    ▼    ▼    ▼            ▼
  LoRA₁ LoRA₂ LoRA₃  ...  LoRAₙ
  (med)  (code) (math)     (legal)
    │      │      │          │
    ▼      ▼      ▼          ▼
  Batch  Batch  Batch     Batch
  routing via attention batching
```

---

## 4. Supervised Fine-Tuning (SFT)

### 4.1 SFT Training Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SFT TRAINING PIPELINE                          │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐      │
│  │  Raw Data │───►│ Preprocessing│───►│ Format to Chat MLA  │      │
│  │           │    │  - decontam  │    │  - system/user/asn't │      │
│  │  instr.   │    │  - dedup     │    │  - token masks       │      │
│  │  pairs    │    │  - quality   │    │  - train labels only │      │
│  └──────────┘    │    filter    │    │    on response      │      │
│                   └──────────────┘    └──────────┬───────────┘      │
│                                                 │                   │
│                                                 ▼                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │               Training Loop (SFT)                             │  │
│  │                                                              │  │
│  │  for batch in dataloader:                                    │  │
│  │      input_ids, labels = batch                               │  │
│  │      # Labels: -100 for prompt tokens, real ids for response │  │
│  │      outputs = model(input_ids)                              │  │
│  │      loss = cross_entropy(logits, labels)  # masked         │  │
│  │      loss.backward()                                         │  │
│  │      optimizer.step()                                         │  │
│  │      scheduler.step()                                         │  │
│  │                                                              │  │
│  │  Hyperparams:                                                │  │
│  │    lr: 1e-5 to 3e-4  (LoRA higher, full FT lower)           │  │
│  │    epochs: 1-3 (avoid overfitting!)                          │  │
│  │    warmup: 3-10% of total steps                              │  │
│  │    scheduler: cosine decay                                    │  │
│  │    precision: bf16 mixed                                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                 │                   │
│                                                 ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │  Checkpoint  │───►│   Merge LoRA  │───►│  Evaluation  │          │
│  │  Selection   │    │   (if needed) │    │  - benchmark │          │
│  │  (best val   │    │   into base   │    │  - human eval│          │
│  │   loss)      │    │   weights     │    │  - toxicity  │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 SFT Best Practices

**Loss masking:** Only compute loss on the **response tokens**, not the prompt. Set prompt token labels to `-100` (PyTorch's `ignore_index`):

```python
# Example: masking input IDs for loss computation
input_ids = [system_prompt + user_message + assistant_response]
labels = [-100 * len(system+user)] + assistant_response_ids
```

**Learning rate & schedule:**
- Full fine-tuning: `1e-5` to `5e-6`
- LoRA: `1e-4` to `3e-4`
- QLoRA: `2e-4` to `5e-4`
- Always use a **warmup** phase (3-10% of training) and **cosine decay**

**Epochs & overfitting:**
- 1-3 epochs is typical for SFT
- Monitor eval loss — if it starts increasing while train loss decreases, you're overfitting
- Use weight decay (0.01-0.1) and dropout (0.1 in LoRA)

**Data quality > quantity:**
- 1K-10K high-quality examples often outperform 100K noisy ones
- The LIMA paper showed strong performance with just 1K curated examples
- Deduplicate and decontaminate against benchmark test sets

---

## 5. RLHF — Reinforcement Learning from Human Feedback

### 5.1 Complete Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                        RLHF FULL PIPELINE                           │
│                                                                     │
│  STAGE 1: SFT                                                       │
│  ┌──────────────┐    ┌─────────┐                                    │
│  │  Instruction │───►│  SFT    │───► π_sft (Supervised Model)      │
│  │  Dataset     │    │ Training│                                    │
│  └──────────────┘    └─────────┘                                    │
│                            │                                         │
│                            ▼                                         │
│  STAGE 2: Reward Model                                              │
│  ┌─────────────────────────────────────────────────┐                │
│  │                                                 │                │
│  │  Prompt ──► π_sft ──► 2 completions             │                │
│  │                          │     │                │                │
│  │                          ▼     ▼                │                │
│  │                      Human ranks them:          │                │
│  │                      y_w (preferred) vs y_l     │                │
│  │                                                 │                │
│  │  RM Training:                                   │                │
│  │    loss = -log(σ(r(y_w) - r(y_l)))             │                │
│  │                                                 │                │
│  │  Where r(x,y) = RM(x,y) scalar reward score    │                │
│  └──────────────────────┬──────────────────────────┘                │
│                          │ Reward Model r(x,y)                      │
│                          ▼                                          │
│  STAGE 3: PPO Optimization                                         │
│  ┌─────────────────────────────────────────────────┐               │
│  │                                                 │               │
│  │  Prompt x ──► π_θ (policy) ──► completion y     │               │
│  │                                  │              │               │
│  │                                  ▼              │               │
│  │              r(x,y) = RM(x,y) ←────┘          │               │
│  │                                  │              │               │
│  │              Advantage = r(x,y) - V(x)          │               │
│  │                                  │              │               │
│  │              ┌──────────────────────────┐       │               │
│  │              │  PPO Objective:           │       │               │
│  │              │                          │       │               │
│  │              │  max E[ A·ratio -        │       │               │
│  │              │      β·KL(π_θ||π_ref) ]  │       │               │
│  │              │                          │       │               │
│  │              │  ratio = π_θ(y|x)        │       │               │
│  │              │         / π_old(y|x)     │       │               │
│  │              │                          │       │               │
│  │              │  Clipped: ratio clipped   │       │               │
│  │              │  to [1-ε, 1+ε]           │       │               │
│  │              └──────────────────────────┘       │               │
│  │                                                 │               │
│  │  KL penalty prevents:                           │               │
│  │    - Reward hacking (gaming RM loopholes)      │               │
│  │    - Drifting too far from SFT model           │               │
│  │    - Language degradation / mode collapse      │               │
│  └─────────────────────────────────────────────────┘               │
│                                                                     │
│  FOUR MODELS IN MEMORY (PPO):                                      │
│  ┌─────────────────┬──────────────────────────────────┐            │
│  │ π_θ  (policy)   │ trainable, generates completions  │            │
│  │ π_ref (ref)     │ frozen SFT, for KL penalty        │            │
│  │ RM    (reward)  │ frozen, provides reward signal     │            │
│  │ V     (critic)  │ trainable, estimates value function │            │
│  └─────────────────┴──────────────────────────────────┘            │
│                                                                     │
│  Total GPU memory: ~4× model size (significant!)                    │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Reward Model Training Details

The reward model is trained on **comparison data** — pairs (or rankings) of model outputs where humans have indicated which is better:

```
  Bradley-Terry Model (pairwise):

  P(y_w > y_l | x) = σ(r(x, y_w) - r(x, y_l))

  Loss = -E[log σ(r(x, y_w) - r(x, y_l))]

  For K-wise comparisons (K responses ranked):
  L = -log (exp r(x,y_w)) / (Σ_i exp r(x,y_i))
```

**Data requirements:** 10K-100K comparisons minimum. Quality of annotations matters more than quantity — inter-annotator agreement should be >70%.

### 5.3 PPO Implementation Considerations

```
  PPO Hyperparameters (typical for LLM training):

  ┌─────────────────────────┬──────────────┐
  │ Parameter               │ Value        │
  ├─────────────────────────┼──────────────┤
  │ PPO clip range (ε)      │ 0.2          │
  │ KL coefficient (β)      │ 0.02-0.2     │
  │   (adaptive schedule)   │ target: 6-10  │
  │ Discount factor (γ)     │ 1.0          │
  │ GAE lambda              │ 0.95         │
  │ Mini-batch size         │ 128-512      │
  │ PPO epochs per batch    │ 2-4          │
  │ Forward batch size      │ 64-256       │
  │ Max new tokens          │ 256-512      │
  │ Generation temperature  │ 1.0          │
  │ Value function coefficient│ 0.5-1.0     │
  └─────────────────────────┴──────────────┘
```

---

## 6. DPO and Variants

### 6.1 DPO (Direct Preference Optimization)

DPO eliminates the need for a separate reward model and PPO optimization loop. It directly optimizes the policy using preference data.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                DPO vs RLHF COMPARISON                                    │
│                                                                          │
│  ┌─────────────────────────────┐  ┌────────────────────────────────┐   │
│  │         RLHF Pipeline       │  │       DPO Pipeline             │   │
│  │                             │  │                                │   │
│  │  1. Train SFT model        │  │  1. Train SFT model            │   │
│  │       ↓                     │  │       ↓                        │   │
│  │  2. Collect comparisons     │  │  2. Collect comparisons         │   │
│  │       ↓                     │  │       ↓                        │   │
│  │  3. Train Reward Model      │  │  3. Train DPO directly        │   │
│  │       ↓                     │  │       on preferences           │   │
│  │  4. Train PPO policy        │  │                                │   │
│  │       (4 models in memory)  │  │  Models in memory:            │   │
│  │                             │  │    π_θ  (trainable)            │   │
│  │  Models in memory:          │  │    π_ref (frozen reference)    │   │
│  │    π_θ   (trainable policy) │  │                                │   │
│  │    π_ref (frozen reference)  │  │  = 2 models (2× memory)       │   │
│  │    RM    (frozen reward)    │  │                                │   │
│  │    V     (trainable critic) │  │                                │   │
│  │                             │  │                                │   │
│  │  = 4 models (4× memory)    │  │                                │   │
│  │                             │  │                                │   │
│  │  Training: Unstable         │  │  Training: Stable (SFT-like)  │   │
│  │  Hyperparams: Many          │  │  Hyperparams: Few              │   │
│  │  Data: Prefs + prompts      │  │  Data: Prefs only             │   │
│  │  Quality: ★★★★★ (tuned)    │  │  Quality: ★★★★☆ (simpler)   │   │
│  └─────────────────────────────┘  └────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 6.2 DPO Mathematical Formulation

DPO derives from the RLHF objective. The optimal policy under the KL-constrained reward maximization is:

```
  π*(y|x) = (1/Z(x)) · π_ref(y|x) · exp(r(x,y)/β)

  Key insight: the reward can be expressed in terms of the optimal policy:

  r(x,y) = β · log(π*(y|x) / π_ref(y|x)) + β · log Z(x)

  Substituting into the Bradley-Terry preference model and eliminating Z(x):

  L_DPO(θ) = -E[log σ(β · log(π_θ(y_w|x) / π_ref(y_w|x))
                        - β · log(π_θ(y_l|x) / π_ref(y_l|x)))]

  This is completely self-contained — no reward model needed!
  The implicit reward is: r_θ(x,y) = β · log(π_θ(y|x) / π_ref(y|x))
```

### 6.3 DPO Variants

**IPO (Identity Preference Optimization):**
```
  IPO generalizes DPO by using a different regularizer.
  It solves the issue of DPO overfitting when preferences are noisy.

  L_IPO = E[(log(π_θ(y_w|x)/π_ref(y_w|x))
            - log(π_θ(y_l|x)/π_ref(y_l|x))
            - 1/(2β))²]

  IPO uses a squared hinge loss instead of logistic loss,
  making it more robust to preference noise.
```

**KTO (Kahneman-Tversky Optimization):**
```
  KTO only needs binary signal (good/bad) instead of pairwise preferences.
  Based on prospect theory from behavioral economics.

  L_KTO = λ_w · E[1 - σ(β · (r_θ(x,y) - z_w))]   (for winners)
        + λ_l · E[1 - σ(β · (z_l - r_θ(x,y)))]    (for losers)

  Where z_w, z_l are margins derived from win/loss base rates.

  Advantage: Much easier to collect data — just label "good" or "bad"
  No need for paired comparisons.
```

**ORPO (Odds Ratio Preference Optimization):**
```
  ORPO combines SFT and alignment into a single phase.
  No reference model needed at all!

  L_ORPO = L_SFT + λ · L_OR

  L_OR = -log σ(log(odds_ratio(y_w|x) / odds_ratio(y_l|x)))

  where odds_ratio = π(y|x) / (1 - π(y|x))

  Advantage: Single-phase training, no reference model,
             computationally cheapest alignment method.
```

### 6.4 Choosing Between DPO Variants

```
  ┌─────────────────────────────────────────────────────────┐
  │           When to use what?                              │
  │                                                         │
  │  Have pairwise preference data?                         │
  │    ├── YES + high quality → DPO                        │
  │    ├── YES + noisy labels  → IPO                       │
  │    └── NO, only good/bad   → KTO                       │
  │                                                         │
  │  Want simplest pipeline?                                │
  │    └── Single-phase, no ref model → ORPO                │
  │                                                         │
  │  Production deployment with RLHF infrastructure?        │
  │    └── PPO (still gold standard if tuned well)          │
  └─────────────────────────────────────────────────────────┘
```

---

## 7. Constitutional AI and Self-Alignment

### 7.1 Constitutional AI (CAI)

Developed by Anthropic, Constitutional AI uses an AI model to provide feedback on its own outputs, reducing the need for human annotators.

```
  Constitutional AI Pipeline:

  Step 1: Supervised Learning from Self-Critiques (SLC)
  ┌────────────────────────────────────────────────────┐
  │  Prompt ──► AI generates response                  │
  │                    │                                │
  │                    ▼                                │
  │  Constitution Rule ──► AI critiques its own output │
  │  (e.g., "Is this harmful?")  │                     │
  │                              ▼                     │
  │                    AI revises its response          │
  │                              │                     │
  │                              ▼                     │
  │  Collect (prompt, revised) pairs for SFT           │
  └────────────────────────────────────────────────────┘

  Step 2: RL from AI Feedback (RLAIF)
  ┌────────────────────────────────────────────────────┐
  │  Prompt ──► AI generates 2 responses              │
  │                    │     │                          │
  │  Constitution ──► AI evaluates which is better      │
  │                    │                                │
  │                    ▼                                │
  │  AI preference data → train reward model           │
  │                    │                                │
  │                    ▼                                │
  │  PPO (using AI-trained RM instead of human RM)     │
  └────────────────────────────────────────────────────┘

  Example Constitutional Principles:
  ─────────────────────────────────────
  1. Choose the response that is most helpful and least harmful
  2. Choose the response that is most honest and transparent
  3. Choose the response that respects different perspectives
  4. Choose the response that does not assist with dangerous activities
  ...
  (Typically 15-50 principles)
```

### 7.2 Self-Alignment Methods

Beyond Constitutional AI, several self-alignment approaches have emerged:

- **Self-Instruct:** The model generates its own instruction-following data, filters for quality, then fine-tunes on it
- **Dromedary / Alpaca:** Uses GPT-4 to generate instruction data from seed tasks
- **RLAIF:** Replaces human annotators with stronger models (GPT-4) for preference labeling
- **SPA (Self-Play Alignment):** Models debate each other to generate preference signals

---

## 8. Instruction Tuning & Chat Template Design

### 8.1 Chat Template Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CHAT TEMPLATE STRUCTURE                          │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  SYSTEM MESSAGE                                             │   │
│  │  ┌───────────────────────────────────────────────────────┐  │   │
│  │  │ You are a helpful, harmless, and honest AI assistant. │  │   │
│  │  │ Always provide accurate information. If unsure, say   │  │   │
│  │  │ so rather than guessing.                               │  │   │
│  │  └───────────────────────────────────────────────────────┘  │   │
│  │        ▲ Defines persona, constraints, safety guidelines     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  TURN 1                                                     │   │
│  │  ┌───────────────────────────────────────────────────────┐  │   │
│  │  │ USER: Explain quantum entanglement in simple terms.  │  │   │
│  │  └───────────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────────┐  │   │
│  │  │ ASSISTANT: Quantum entanglement is a phenomenon...    │  │   │
│  │  │ [response tokens — LOSS COMPUTED HERE]                │  │   │
│  │  └───────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  TURN 2                                                     │   │
│  │  ┌───────────────────────────────────────────────────────┐  │   │
│  │  │ USER: Can you give me a practical application?        │  │   │
│  │  └───────────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────────┐  │   │
│  │  │ ASSISTANT: One major application is quantum key...     │  │   │
│  │  │ [response tokens — LOSS COMPUTED HERE]                │  │   │
│  │  └───────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Special Tokens (model-specific):                                   │
│  ┌──────────────┬────────────────────────────────────────────┐      │
│  │ Model        │ Template tokens                              │      │
│  ├──────────────┼────────────────────────────────────────────┤      │
│  │ LLaMA 2/3   │ [INST] ... [/INST] <<SYS>> ... <</SYS>>   │      │
│  │ Mistral      │ [INST] ... [/INST]                          │      │
│  │ ChatML       │ <|im_start|>system<|im_end|> ...            │      │
│  │ Alpaca       │ ### Instruction: ... ### Response:          │      │
│  │ Vicuna       │ USER: ... ASSISTANT:                        │      │
│  │ Qwen2        │ <|im_start|>system ... <|im_end|>           │      │
│  └──────────────┴────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Loss Masking — Critical Detail

Only compute loss on assistant response tokens. Set all other positions to `-100`:

```python
# ChatML example
tokens = tokenizer.apply_chat_template(messages)

# Create labels: mask everything except assistant responses
labels = [-100] * len(tokens)  # Start with all masked

# Only unmask assistant response positions
for start, end in assistant_response_spans:
    for i in range(start, end):
        labels[i] = tokens[i]
```

### 8.3 Instruction Tuning Data Categories

```
  ┌────────────────────────────────────────────────────────┐
  │         Instruction Tuning Data Mix                    │
  │                                                        │
  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │  General QA  │  │  Code Gen    │  │  Math/Reason │  │
  │  │   30-40%     │  │   20-30%     │  │   10-20%     │  │
  │  └─────────────┘  └──────────────┘  └──────────────┘  │
  │                                                        │
  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │  Creative    │  │  Summarize   │  │  Safety      │  │
  │  │   10-15%     │  │   10%        │  │   5-10%      │  │
  │  └─────────────┘  └──────────────┘  └──────────────┘  │
  │                                                        │
  │  Key datasets:                                         │
  │  - Open-Orca / SlimOrca (general)                     │
  │  - CodeAlpaca / CodeInstruct (code)                   │
  │  - MetaMathQA / GSM8K-style (math)                   │
  │  - Alpaca / Dolly (general instruction)               │
  │  - ShareGPT / WildChat (conversations)                │
  └────────────────────────────────────────────────────────┘
```

---

## 9. Domain Adaptation Fine-Tuning

### 9.1 Continual Pre-training vs SFT for Domains

```
  Domain Adaptation Strategy:

  ┌───────────────────────────────────────────────┐
  │  How much domain shift from base model?       │
  │                                               │
  │  ──► Small shift (same language, new style)   │
  │       → SFT with domain data only             │
  │       → 5K-50K examples, LoRA r=16           │
  │                                               │
  │  ──► Medium shift (new terminology/domain)    │
  │       → Continual pretraining → then SFT     │
  │       → CPT: 1-10B domain tokens             │
  │       → SFT: domain instruction pairs        │
  │                                               │
  │  ──► Large shift (new language/script)        │
  │       → Extended continual pretraining        │
  │       → CPT: 10-100B tokens                  │
  │       → Vocabulary extension needed           │
  │       → Then SFT + alignment                  │
  └───────────────────────────────────────────────┘
```

### 9.2 Continual Pre-Training (CPT)

CPT trains on raw domain text (not instruction pairs) to adapt the model's internal representations before SFT:

```yaml
# CPT Configuration
data: raw_domain_corpus.txt  # Unstructured text
learning_rate: 1e-4           # Higher than SFT (new knowledge)
warmup_steps: 500
weight_decay: 0.01
max_length: 4096
batch_size: 512               # Large batch for stability
gradient_accumulation: 8
precision: bf16
epochs: 1                     # Usually 1 pass over data

# LoRA for CPT (optional)
lora_rank: 64                 # Higher rank for CPT vs SFT
lora_alpha: 128
target_modules: [q_proj, k_proj, v_proj, o_proj,
                 gate_proj, up_proj, down_proj]  # All modules
```

### 9.3 Domain-Specific SFT

After CPT, fine-tune on domain instruction pairs:

```
  CPT + SFT Pipeline:

  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ Base LLM  │────►│   CPT    │────►│   SFT    │────► Domain
  │           │     │ (domain  │     │ (domain  │      Expert
  │           │     │  corpus) │     │  instr.) │      Model
  └──────────┘     └──────────┘     └──────────┘
       │                                  │
       │         (optional)               │
       │    ┌──────────┐                  │
       │    │   DPO    │                  │
       │    │ (domain  │◄─────────────────┘
       │    │  prefs)  │
       │    └──────────┘
       │
       ▼
  The resulting model should:
  1. Understand domain terminology
  2. Follow domain-specific conventions
  3. Answer domain questions accurately
  4. Maintain general capabilities (avoid forgetting)
```

---

## 10. Fine-Tuning Frameworks

### 10.1 Framework Comparison

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                  FINE-TUNING FRAMEWORKS                         │
  ├─────────────┬────────────┬───────────┬──────────┬───────────────┤
  │  Feature     │ HF PEFT    │ Axolotl   │ Unsloth  │ LLaMA-Factory │
  ├─────────────┼────────────┼───────────┼──────────┼───────────────┤
  │  LoRA        │ ✓          │ ✓         │ ✓        │ ✓             │
  │  QLoRA       │ ✓          │ ✓         │ ✓        │ ✓             │
  │  Full FT     │ ✓          │ ✓         │ ✓        │ ✓             │
  │  DPO         │ ✓ (TRL)    │ ✓         │ ✓        │ ✓             │
  │  RLHF/PPO    │ ✓ (TRL)    │ ✓         │ ✗        │ ✓             │
  │  Speed       │ Baseline   │ 1-2x      │ 2x       │ ~1.5x         │
  │  Memory      │ Baseline   │ Good      │ Best     │ Good          │
  │  Config      │ Python     │ YAML      │ Python   │ YAML/WebUI    │
  │  Models      │ All HF     │ Most      │ LLaMA/   │ Most          │
  │              │            │           │ Mistral  │               │
  │  Ease of Use │ Moderate   │ Moderate  │ Easy     │ Easiest       │
  │  Community   │ Largest   │ Active    │ Growing  │ Very Active   │
  └─────────────┴────────────┴───────────┴──────────┴───────────────┘
```

### 10.2 HuggingFace PEFT + TRL

The standard open-source stack:

```python
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTTrainer, SFTConfig

model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-2-7b-hf",
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj", "k_proj", "o_proj",
                     "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)

trainer = SFTTrainer(
    model=model,
    train_dataset=dataset,
    args=SFTConfig(
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        num_train_epochs=3,
        logging_steps=10,
        bf16=True,
        max_seq_length=2048,
    ),
    processing_class=tokenizer,
)
trainer.train()
```

### 10.3 Unsloth

Unsloth provides up to 2× faster training and up to 70% less VRAM usage through custom Triton kernels:

```python
from unsloth import FastLanguageModel

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/llama-3-8b-bnb-4bit",
    max_seq_length=4096,
    load_in_4bit=True,
)

model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    lora_alpha=16,
    lora_dropout=0,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                     "up_proj", "down_proj", "gate_proj"],
)
```

### 10.4 Axolotl

Axolotl uses YAML-based configuration:

```yaml
base_model: meta-llama/Llama-2-7b-hf
model_type: LlamaForCausalLM
tokenizer_type: LlamaTokenizer

load_in_4bit: true
strict: false

lora_rank: 16
lora_alpha: 32
lora_dropout: 0.05
lora_target_modules:
  - q_proj
  - k_proj
  - v_proj
  - o_proj

datasets:
  - path: dataset.jsonl
    type: alpaca
    split: train

sequence_len: 2048
micro_batch_size: 4
gradient_accumulation_steps: 4
num_epochs: 3
learning_rate: 2e-4
bf16: true

optimizer: paged_adamw_8bit
lr_scheduler: cosine
warmup_steps: 100
```

### 10.5 LLaMA-Factory

LLaMA-Factory provides both CLI and WebUI training, making it the most accessible option:

```bash
llamafactory-cli train \
    --model_name_or_path meta-llama/Llama-2-7b-hf \
    --stage sft \
    --do_train \
    --dataset alpaca_en \
    --template llama2 \
    --finetuning_type lora \
    --lora_rank 16 \
    --lora_alpha 32 \
    --lora_target q_proj,v_proj,k_proj,o_proj \
    --output_dir ./output \
    --per_device_train_batch_size 4 \
    --gradient_accumulation_steps 4 \
    --lr_scheduler_type cosine \
    --logging_steps 10 \
    --save_steps 1000 \
    --learning_rate 2e-4 \
    --num_train_epochs 3.0 \
    --bf16
```

---

## 11. Practical Tips for Fine-Tuning LLMs

### 11.1 Fine-Tuning Decision Flowchart

```
                FINE-TUNING DECISION FLOWCHART
                ================================

                        Need to adapt an LLM?
                               │
                    ┌──────────┴──────────┐
                    │                     │
               New domain?          Style/format only?
                    │                     │
                    │                ┌─────┴─────┐
                    │                │           │
                    │           Simple       Complex
                    │           format?     behavior?
                    │                │           │
                    │          LoRA r=4     LoRA r=16
                    │          1K examples  10K examples
                    │                │           │
                    ▼                ▼           │
              ┌─────────────┐                 │
              │ Significant  │                 │
              │ domain shift?│                 │
              └──────┬──────┘                 │
                     │                        │
          ┌──────────┴──────────┐             │
          │                     │             │
        Yes                     No            │
          │                     │             │
          ▼                     ▼             │
    CPT first ──────────► Straight SFT ◄──────┘
    (raw domain text)     (instruction data)
          │                     │
          ▼                     ▼
    Then SFT on          Need alignment?
    domain instr.              │
          │              ┌─────┴─────┐
          │              │           │
          │           Pairwise    Binary
          │           prefs?      good/bad?
          │              │           │
          │        ┌─────┴─────┐     │
          │        │     │     │     │
          │       DPO  IPO   PPO   KTO
          │        │     │     │     │
          │        └─────┴─────┴─────┘
          │              │
          │         OR: ORPO
          │        (single phase)
          │              │
          ▼              ▼
    ┌─────────────────────────────────────┐
    │            GPU Budget?              │
    ├──────────┬──────────┬───────────────┤
    │  < 24GB  │  24-80GB │   > 80GB     │
    │  QLoRA   │  LoRA    │  Full FT      │
    │  r=8-16  │  r=16-64 │  all params  │
    │  4-bit   │  bf16    │  bf16/fp16   │
    └──────────┴──────────┴───────────────┘
```

### 11.2 Dataset Size Guidelines

| Task Complexity | Minimum Examples | Recommended | Optimal |
|---|---|---|---|
| Style transfer | 100 | 500-1K | 2K-5K |
| Instruction following | 500 | 5K-10K | 50K-100K |
| Domain adaptation (SFT) | 1K | 10K-50K | 100K+ |
| Domain adaptation (CPT) | 10M tokens | 100M tokens | 1B+ tokens |
| Code generation | 1K | 10K-50K | 100K+ |
| Multi-turn conversation | 5K | 20K-50K | 100K+ |

### 11.3 Learning Rate Guidelines

```
  ┌────────────────────────────────────────────────────────┐
  │  Learning Rate Selection Guide                          │
  │                                                        │
  │  Method          │  Recommended LR Range               │
  │  ────────────────┼───────────────────────────          │
  │  Full FT         │  5e-6 — 2e-5                       │
  │  LoRA           │  1e-4 — 5e-4                       │
  │  QLoRA          │  2e-4 — 1e-3                       │
  │  IA³            │  5e-4 — 1e-3                       │
  │  CPT (domain)   │  1e-4 — 5e-4                       │
  │  DPO/RLHF       │  5e-7 — 5e-6  (much lower!)        │
  │                                                        │
  │  Schedule: Cosine decay with warmup                   │
  │  Warmup: 3-10% of total steps                        │
  │  Weight decay: 0.01-0.1 (higher for smaller datasets) │
  └────────────────────────────────────────────────────────┘
```

### 11.4 Epochs and Overfitting

- **SFT:** 1-3 epochs. More epochs cause overfitting and reduced diversity.
- **CPT:** 1 epoch over the domain corpus.
- **DPO:** 1 epoch. DPO overfits quickly — do NOT train for multiple epochs.
- **PPO:** Use steps-based training (e.g., 100K-1M steps), not epochs.

**Early stopping:** Monitor eval loss. If it increases for 2-3 evaluations, stop training. Save the checkpoint with the lowest eval loss, not the last one.

### 11.5 Common Mistakes

```
  ┌──────────────────────────────────────────────────────────────┐
  │  ❌ Common Mistakes                      ✅ Correct Approach  │
  │  ──────────────────                      ─────────────────── │
  │                                                            │
  │  Training on prompt tokens                 Mask prompt with  │
  │  (computing loss on everything)            labels = -100     │
  │                                                            │
  │  Too high learning rate for full FT        Use 1-2e-5       │
  │  (destroys pre-trained knowledge)          for full FT      │
  │                                                            │
  │  Not using warmup                         Warm up for 3-10% │
  │                                            of total steps    │
  │                                                            │
  │  Training DPO for multiple epochs         DPO: 1 epoch only │
  │  (causes overfitting on preferences)                        │
  │                                                            │
  │  Forgetting to merge LoRA before          Merge: W = W₀    │
  │  inference (wasting compute on            + (α/r)·B·A      │
  │  dual forward pass)                                          │
  │                                                            │
  │  Benchmark contamination in               Deduplicate and  │
  │  training data                             decontaminate    │
  │                                            against eval set │
  │                                                            │
  │  Using same data for SFT and              Proper split:    │
  │  evaluation                                train/val/test   │
  │                                            with no overlap  │
  └──────────────────────────────────────────────────────────────┘
```

### 11.6 Evaluation Checklist

After fine-tuning, evaluate along these axes:

1. **Capability preservation** — Does the model still perform on general benchmarks (MMLU, HellaSwag, etc.)?
2. **Domain performance** — Does it improve on the target task?
3. **Safety alignment** — Does it refuse harmful requests?
4. **Hallucination rate** — Has the model's tendency to fabricate increased?
5. **Verbosity** — Has it become overly wordy or terse?
6. **Format compliance** — Does it follow the expected output format?

Use a combination of:
- **Automatic benchmarks** (MMLU, domain-specific evals)
- **LLM-as-judge** (GPT-4 evaluating outputs)
- **Human evaluation** (gold standard, but expensive)

---

## Summary

Fine-tuning LLMs spans a spectrum from lightweight PEFT methods to full alignment pipelines:

1. **LoRA/QLoRA** should be your default starting point — they offer the best quality-to-efficiency ratio
2. **SFT** is the foundation — get this right before attempting alignment
3. **DPO** has largely replaced RLHF for most practical applications due to simplicity
4. **KTO** is ideal when you only have binary good/bad labels, not pairwise preferences
5. **Domain adaptation** often requires CPT before SFT when the domain shift is significant
6. **Data quality** matters more than data quantity — curate carefully
7. **Evaluate comprehensively** — both on the target domain and on general benchmarks to detect capability regression

The field is evolving rapidly — ORPO and other single-phase methods are making alignment more accessible, while more efficient attention mechanisms (grouped query attention, flash attention) are reducing the compute requirements for training.

---

## Real References

### Parameter-Efficient Fine-Tuning (PEFT)

1. Hu, E.J., Shen, Y., Wallis, P., Allen-Zhu, Z., Li, Y., Wang, S., Wang, L., & Chen, W., "LoRA: Low-Rank Adaptation of Large Language Models", *ICLR 2022*, arXiv:2106.09685. https://arxiv.org/abs/2106.09685

2. Dettmers, T., Pagnoni, A., Holtzman, A., & Zettlemoyer, L., "QLoRA: Efficient Finetuning of Quantized LLMs", *NeurIPS 2023*, arXiv:2305.14314. https://arxiv.org/abs/2305.14314

3. Zhang, Q., Chen, M., Bukharin, A., Karampatziakis, N., He, P., Cheng, Y., Chen, W., & Zhao, T., "AdaLoRA: Adaptive Budget Allocation for Parameter-Efficient Fine-Tuning", *ICLR 2023*, arXiv:2303.10512. https://arxiv.org/abs/2303.10512

4. Liu, H., Tam, D., Muqeeth, M., Mohta, J., Huang, T., Bansal, M., & Raffel, C., "Few-Shot Parameter-Efficient Fine-Tuning is Better and Cheaper than In-Context Learning", *NeurIPS 2022* (IA³). https://arxiv.org/abs/2205.05638

5. Li, X.L. & Liang, P., "Prefix-Tuning: Optimizing Continuous Prompts for Generation", *ACL 2021*, arXiv:2101.00190. https://arxiv.org/abs/2101.00190

6. Liu, P., Yuan, W., Fu, J., Jiang, Z., Hayashi, H., & Neubig, G., "Pre-train, Prompt, and Predict: A Systematic Survey of Prompting Paradigms in Natural Language Processing", arXiv:2107.13586. https://arxiv.org/abs/2107.13586

7. Lester, B., Al-Rfou, R., & Constant, N., "The Power of Scale for Parameter-Efficient Prompt Tuning", *EMNLP 2021*, arXiv:2104.08691. https://arxiv.org/abs/2104.08691

8. Houlsby, N., Giurgiu, A., Jastrzebski, S., Morrone, B., De Laroussilhe, Q., Gesmundo, A., Attariyan, M., & Gelly, S., "Parameter-Efficient Transfer Learning for NLP", *ICML 2019*. https://arxiv.org/abs/1902.00751

9. Pfeiffer, J., Kamath, A., Rücklé, A., Cho, K., & Gurevych, I., "AdapterFusion: Non-Destructive Task Composition for Transfer Learning", *EACL 2021*, arXiv:2005.00247. https://arxiv.org/abs/2005.00247

10. Hu, Z., Wang, L., Liu, Y., & Zettlemoyer, L., "LoRA+: Efficient Low Rank Adaptation of Large Language Models", arXiv:2402.12354. https://arxiv.org/abs/2402.12354

11. Aghajanyan, A., Zettlemoyer, L., & Gupta, S., "Intrinsic Dimensionality Explains the Effectiveness of Language Model Fine-Tuning", *ACL 2021*, arXiv:2012.13255. https://arxiv.org/abs/2012.13255

### Supervised Fine-Tuning (SFT)

12. Wang, Y., Kordi, Y., Mishra, S., Liu, A., Smith, N.A., Khashabi, D., & Hajishirzi, H., "Self-Instruct: Aligning Language Models with Self-Generated Instructions", *ACL 2023*, arXiv:2212.10560. https://arxiv.org/abs/2212.10560

13. Zhou, C., Liu, J., Wang, P., Zhang, R., Ho, C., Yu, D., Zhao, T., & Neubig, G., "LIMA: Less Is More for Alignment", *NeurIPS 2023*, arXiv:2305.11206. https://arxiv.org/abs/2305.11206

14. Taori, R., Gulrajani, I., Zhang, T., Dubois, Y., Liang, P., "Stanford Alpaca: An Instruction-following LLaMA Model", 2023. https://github.com/tatsu-lab/stanford_alpaca

15. Chung, H.W., Hou, L., Longpre, S., Zoph, B., Tay, Y., Fedus, W., Li, Y., Wang, H., Siddhant, S., & Wei, J., "Scaling Instruction-Finetuned Language Models", *JMLR 2024*, arXiv:2210.11416. https://arxiv.org/abs/2210.11416

16. Wei, J., Bosma, M., Zhao, V.Y., Guu, K., Yu, A., Fazel, B., Li, Y., & Le, Q.V., "Finetuned Language Models Are Zero-Shot Learners", *ICLR 2022* (FLAN), arXiv:2109.01652. https://arxiv.org/abs/2109.01652

17. Sanh, V., Webson, A., Raffel, C., et al., "Multitask Prompted Training Enables Zero-Shot Task Generalization", *ICLR 2022* (T0). https://arxiv.org/abs/2110.08207

### Reinforcement Learning from Human Feedback (RLHF)

18. Ouyang, L., Wu, J., Jiang, X., Almeida, D., Wainwright, C., Mishkin, P., Zhang, C., Agarwal, S., Slama, K., Ray, A., Schulman, J., Hilton, J., Kelton, S., Miller, L., Simens, M., Askell, A., Welinder, P., Christiano, P., Leike, J., & Lowe, R., "Training language models to follow instructions with human feedback" (InstructGPT), *NeurIPS 2022*, arXiv:2203.02155. https://arxiv.org/abs/2203.02155

19. Christiano, P.F., Leike, J., Brown, T.B., Martic, M., Legg, S., & Amodei, D., "Deep Reinforcement Learning from Human Preferences", *NeurIPS 2017*, arXiv:1706.03741. https://arxiv.org/abs/1706.03741

20. Schulman, J., Wolski, F., Dhariwal, P., Radford, A., & Klimov, O., "Proximal Policy Optimization Algorithms" (PPO), arXiv:1707.06347. https://arxiv.org/abs/1707.06347

21. Bai, Y., Jones, A., Ndousse, K., Askell, A., Chen, A., DasSarma, N., Drain, D., Fort, S., Ganguli, D., Henighan, T., Jones, A., Joseph, N., Kadavath, S., Kernion, J., Conerly, T., Elhage, N., Lovitt, L., Ngo, N., Olsson, C., Ringer, J., Sorensen, T., & Kaplan, J., "Constitutional AI: Harmlessness from AI Feedback", arXiv:2212.08073. https://arxiv.org/abs/2212.08073

22. Ziegler, D.M., Stiennon, N., Wu, J., Brown, T.B., Radford, A., Amodei, D., Christiano, P., & Irving, G., "Fine-Tuning Language Models from Human Preferences", arXiv:1909.08593. https://arxiv.org/abs/1909.08593

23. Bradley, R.A. & Terry, M.E., "Rank Analysis of Incomplete Block Designs: I. The Method of Paired Comparisons", *Biometrika*, 39(3/4):324–345, 1952. DOI: 10.1093/biomet/39.3-4.324

### Direct Alignment Methods (DPO and Variants)

24. Rafailov, R., Sharma, A., Mitchell, E., Ermon, S., Manning, C.D., & Finn, C., "Direct Preference Optimization: Your Language Model is Secretly a Reward Model" (DPO), *NeurIPS 2023*, arXiv:2305.18290. https://arxiv.org/abs/2305.18290

25. Azar, M.G., Rowland, M., Piot, B., Munos, R., Calandriello, D., Valko, M., & Heess, N., "A General Theoretical Paradigm to Understand Learning from Human Preferences" (IPO), *AISTATS 2024* (PMLR 238:4447-4455), arXiv:2310.12036. https://arxiv.org/abs/2310.12036

26. Ethayarajh, K., Xu, W., Muennighoff, N., Jurafsky, D., & Kiela, D., "KTO: Model Alignment as Prospect Theoretic Optimization" (KTO), arXiv:2402.01306. https://arxiv.org/abs/2402.01306

27. Hong, J., Lee, N., & Thorne, J., "ORPO: Monolithic Preference Optimization without Reference Model" (ORPO), *EMNLP 2024*, arXiv:2403.07691. https://arxiv.org/abs/2403.07691

28. Meng, Y., Xia, M., & Chen, D., "SimPO: Simple Preference Optimization with a Reference-Free Reward", arXiv:2405.14734. https://arxiv.org/abs/2405.14734

### Quantization and Efficient Training

29. Dettmers, T., Lewis, M., Belkada, Y., & Zettlemoyer, L., "LLM.int8(): 8-bit Matrix Multiplication for Transformers at Scale", *NeurIPS 2022*, arXiv:2208.07339. https://arxiv.org/abs/2208.07339

30. Frantar, E., Ashkboos, S., Hoefler, T., & Alistarh, D., "GPTQ: Accurate Post-Training Quantization for Generative Pre-trained Transformers", *ICLR 2023*, arXiv:2210.17323. https://arxiv.org/abs/2210.17323

31. Xiao, G., Lin, J., Seznec, M., Wu, H., Demouth, J., & Han, S., "SmoothQuant: Accurate and Efficient Post-Training Quantization for Large Language Models", *ICML 2023*, arXiv:2211.10438. https://arxiv.org/abs/2211.10438

32. Dao, T., Fu, D.Y., Ermon, S., Rudra, A., & Ré, C., "FlashAttention: Fast and Memory-Efficient Exact Attention with IO-Awareness", *NeurIPS 2022*, arXiv:2205.14135. https://arxiv.org/abs/2205.14135

### Self-Alignment and AI Feedback

33. Ganguli, D., Lovitt, L., Kernion, J., et al., "Red Teaming Language Models to Reduce Harms: Methods, Scaling Behaviors, and Lessons Learned", arXiv:2209.07858. https://arxiv.org/abs/2209.07858

34. Lee, H., Phatale, S., Mansoor, H., Mesgar, K., Huang, L., & Rengarajan, S., "RLAIF vs. RLHF: Scaling Reinforcement Learning from Human Feedback with AI Feedback", *ICML 2024*, arXiv:2309.00267. https://arxiv.org/abs/2309.00267

35. Sun, H., Zhang, W., & Tiu, J., "Self-Alignment with Instruction Backtranslation", *ICLR 2024*, arXiv:2308.06259. https://arxiv.org/abs/2308.06259

### Foundational Model Papers

36. Touvron, H., Lavril, T., Izber, G., Martinet, V., Lachaux, M.-A., Lacroix, T., Rozière, B., Goriat, N., Hambro, E., Azhar, F., Rodriguez, A., Joulin, A., Grave, E., & Lample, G., "LLaMA: Open and Efficient Foundation Language Models", arXiv:2302.13971. https://arxiv.org/abs/2302.13971

37. Touvron, H., Martin, L., Stone, K., Albert, P., Almahairi, A., et al., "LLaMA 2: Open Foundation and Fine-Tuned Chat Models", arXiv:2307.09288. https://arxiv.org/abs/2307.09288

38. Jiang, A.Q., Sablayrolles, A., Mensch, A., Bamford, S., Chaplot, D.S., et al., "Mistral 7B", arXiv:2310.06825. https://arxiv.org/abs/2310.06825

39. Brown, T.B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., et al., "Language Models are Few-Shot Learners" (GPT-3), *NeurIPS 2020*, arXiv:2005.14165. https://arxiv.org/abs/2005.14165

### Frameworks and Tools

40. HuggingFace PEFT: Parameter-Efficient Fine-Tuning library. https://huggingface.co/docs/peft

41. von Werra, L., Belkada, Y., Tunstall, L., Scholz, A., et al., "TRL: Transformer Reinforcement Learning Library", GitHub. https://github.com/huggingface/trl

42. Axolotl: Streamlined LLM Fine-Tuning. OpenAccess AI Collective. https://github.com/OpenAccess-AI-Collective/axolotl

43. Unsloth: 2x Faster LLM Fine-Tuning. https://github.com/unslothai/unsloth

44. Zheng, Y., Zhang, R., Zhang, X., Xue, Y., Wu, X., & Guo, T., "LlamaFactory: Unified Efficient Fine-Tuning of 100+ Language Models", *Proceedings of the 62nd Annual Meeting of the ACL (Volume 3: System Demonstrations)*, pp. 400-410, 2024, arXiv:2403.13372. https://arxiv.org/abs/2403.13372

### Evaluation and Benchmarks

45. Hendrycks, D., Burns, C., Basart, S., Zou, A., Mazeika, M., Song, D., & Steinhardt, J., "Measuring Massive Multitask Language Understanding" (MMLU), *ICLR 2021*, arXiv:2009.03300. https://arxiv.org/abs/2009.03300

46. Zellers, R., Holtzman, A., Bisk, Y., Farhadi, A., & Choi, Y., "HellaSwag: Can a Machine Really Finish Your Sentence?", *ACL 2019*, arXiv:1905.07830. https://arxiv.org/abs/1905.07830

47. Zheng, L., Chiang, W.-L., Sheng, Y., Zhuang, S., Wu, Z., Zhuang, Y., Lin, W., Li, Z., Li, D., Xing, E.P., Zhang, J., & Gonzalez, J.E., "Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena", *NeurIPS 2023*, arXiv:2306.05685. https://arxiv.org/abs/2306.05685
## References

- Hu, E.J. et al., "LoRA: Low-Rank Adaptation of Large Language Models," ICLR 2022. https://arxiv.org/abs/2106.09685
- Ouyang, L. et al., "Training language models to follow instructions with human feedback," NeurIPS 2022. https://arxiv.org/abs/2203.02155
- Rafailov, R. et al., "Direct Preference Optimization: Your Language Model is Secretly a Reward Model," NeurIPS 2023. https://arxiv.org/abs/2305.18290
- Schulman, J. et al., "Proximal Policy Optimization Algorithms," 2017. https://arxiv.org/abs/1707.06347
- Stiennon, N. et al., "Learning to Summarize with Human Feedback," NeurIPS 2020. https://arxiv.org/abs/2009.01325
- Christiano, P. et al., "Deep Reinforcement Learning from Human Preferences," NeurIPS 2017. https://arxiv.org/abs/1706.03741
- Li, X.L. & Liang, P., "Prefix-Tuning: Optimizing Continuous Prompts for Generation," ACL 2021. https://arxiv.org/abs/2101.00190
- Lester, B. et al., "The Power of Scale for Parameter-Efficient Prompt Tuning," EMNLP 2021. https://arxiv.org/abs/2104.08691
- Hugging Face PEFT Documentation. https://huggingface.co/docs/peft/
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
