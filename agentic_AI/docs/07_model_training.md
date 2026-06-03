# 07: Model Training — From Scratch to Scale

## Table of Contents

1. [Training from Scratch Methodology](#1-training-from-scratch-methodology)
2. [Optimizers Deep Dive](#2-optimizers-deep-dive)
3. [Learning Rate Schedules](#3-learning-rate-schedules)
4. [Regularization Techniques](#4-regularization-techniques)
5. [Gradient Management](#5-gradient-management)
6. [istributed Training](#6-distributed-training)
7. [Training Monitoring and Debugging](#7-training-monitoring-and-debugging)
8. [Common Training Failures and Debugging](#8-common-training-failures-and-debugging)
9. [Memory Optimization Techniques](#9-memory-optimization-techniques)
10. [Training LLMs at Scale](#10-training-llms-at-scale)

---

## End-to-End Training Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TRAINING PIPELINE (End-to-End)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐  │
│  │  RAW DATA │───>│  TOKENIZER   │───>│  DATALOADER  │───>│  BATCH QUEUE  │  │
│  │          │    │  (BPE/Sentence│    │  (shuffle,  │    │  (prefetch,  │  │
│  │  .jsonl  │    │   Piece/     │    │   bucket,   │    │   pin mem)   │  │
│  │  .parquet│    │   WordPiece)  │    │   pack)     │    │              │  │
│  └──────────┘    └──────────────┘    └─────────────┘    └──────┬───────┘  │
│                                                                  │          │
│  ┌───────────────────────────────────────────────────────────────▼───────┐  │
│  │                     FORWARD + BACKWARD PASS                           │  │
│  │  ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌───────────────┐   │  │
│  │  │  EMBED   │──>│ TRANSFORM │──>│  LOSS FM  │──>│  BACKPROP     │   │  │
│  │  │  LAYER   │   │  ER BLOCK│   │  (CE+reg)  │   │  (grad calc)  │   │  │
│  │  │  d_model │   │  x N     │   │            │   │               │   │  │
│  │  └──────────┘   └──────────┘   └───────────┘   └───────┬───────┘   │  │
│  │                                                          │           │  │
│  │  ┌───────────────┐   ┌────────────┐   ┌────────────┐   │           │  │
│  │  │ GRAD          │<──│  GRAD       │<──│  GRAD      │<──┘           │  │
│  │  │ ACCUMULATOR   │   │  CLIPPING   │   │  SCALING   │ (AMP)        │  │
│  │  │ (micro-batch) │   │  (norm/val) │   │  (fp16)    │               │  │
│  │  └───────┬───────┘   └────────────┘   └────────────┘               │  │
│  │          │                                                            │  │
│  └──────────┼────────────────────────────────────────────────────────────┘  │
│             │                                                               │
│  ┌──────────▼───────────────────────────────────────────────────────────┐   │
│  │                     OPTIMIZER STEP                                   │   │
│  │  ┌────────────┐   ┌───────────────┐   ┌──────────────┐              │   │
│  │  │  LR        │──>│  PARAM UPDATE  │──>│  PARAM SYNC   │              │   │
│  │  │  SCHEDULER │   │  (AdamW/       │   │  (DDP/FSDP/   │             │   │
│  │  │  (cosine)  │   │   Lion/etc)   │   │   all-reduce) │              │   │
│  │  └────────────┘   └───────────────┘   └──────────────┘              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     MONITORING & CHECKPOINTING                       │   │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────────────┐  │   │
│  │  │  W&B /   │  │  CHECKPT  │  │  EVAL    │  │  EARLY STOPPING  │  │   │
│  │  │  TB      │  │  (async)  │  │  (valid) │  │  (patience)      │  │   │
│  │  └──────────┘  └───────────┘  └──────────┘  └───────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Training from Scratch Methodology

### Weight Initialization

Proper initialization is critical — it determines whether gradients flow meaningfully in early training or vanish/explode immediately.

| Method | Formula | Use Case |
|--------|---------|----------|
| Xavier/Glorot | `std = sqrt(2 / (fan_in + fan_out))` | Tanh, Sigmoid activations |
| Kaiming/He | `std = sqrt(2 / fan_in)` | ReLU and variants |
| Normal Init | `N(0, 0.02)` | Transformer default (GPT-style) |
| Small-Scale Init | `N(0, 0.002)` or `N(0, 1/sqrt(d_model))` | Deep Transformers (pre-norm) |
| Embedding Init | `N(0, 1/sqrt(d_model))` | Token/position embeddings |

**Why small initialization matters in Transformers:** Residual pathways depend on additive shortcuts. If layers start with large outputs, the residual stream becomes dominated by random noise, drowning out the embedding signal. Empirically, initializing residual projections with ~`1/sqrt(N_layers)` scaling (GPT-2 style) stabilizes early training.

```python
# Transformer initialization (GPT-2 style)
def _init_weights(module, n_layers, d_model):
    if isinstance(module, nn.Linear):
        std = 0.02
        if module.out_features == d_model:  # residual projections
            std *= (1.0 / math.sqrt(2.0 * n_layers))
        nn.init.normal_(module.weight, mean=0.0, std=std)
        if module.bias is not None:
            nn.init.zeros_(module.bias)
    elif isinstance(module, nn.Embedding):
        nn.init.normal_(module.weight, mean=0.0, std=0.02)
    elif isinstance(module, nn.LayerNorm):
        nn.init.ones_(module.weight)
        nn.init.zeros_(module.bias)
```

### Batch Size Selection

```
┌─────────────────────────────────────────────────────────────────────┐
│               BATCH SIZE TRADE-OFFS                                 │
│                                                                     │
│  Small Batch (1-32)          Medium Batch (32-256)    Large Batch   │
│  ┌──────────────────┐       ┌──────────────────┐    (256-4M+)      │
│  │ + More noise =   │       │ + Good general-   │    ┌──────────┐  │
│  │   implicit reg    │       │   ization         │    │ + Fastest │  │
│  │ + Good general.  │       │ + Stable training │    │   wall-   │  │
│  │ - Slow wall-time │       │ - Need tuning     │    │   time    │  │
│  │ - Unstable grads │       │                    │    │ - LR must│  │
│  │ - Underutilize   │       │                    │    │   scale   │  │
│  │   hardware       │       │                    │    │ - Sharp   │  │
│  └──────────────────┘       └──────────────────┘    │   minima  │  │
│                                                      └──────────┘  │
│                                                                     │
│  LR SCALING RULE:  lr = base_lr * (batch_size / reference_size)    │
│  Square-root scaling: lr = base_lr * sqrt(batch_size / ref)        │
│  Linear scaling (Goyal et al.): lr = base_lr * (batch / ref)       │
└─────────────────────────────────────────────────────────────────────┘
```

**Practical guidance:**
- Start with batch size 32–256 for fine-tuning
- For pre-training LLMs: start at global batch size ~256–4K tokens (scaling up during training is common)
- Use **gradient accumulation** to simulate larger batch sizes when GPU memory is constrained
- Large-batch training requires **warmup** — linear warmup for the first 0.5–2% of total steps is standard

---

## 2. Optimizers Deep Dive

### Optimizer Comparison

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        OPTIMIZER DECISION MATRIX                             │
├────────────┬──────────────────┬────────────────┬──────────────────────────── │
│ Optimizer  │  Update Rule     │  Memory/Param  │  Best For                  │
├────────────┼──────────────────┼────────────────┼─────────────────────────────┤
│ SGD+Momentum│ v = μv + ∇θ    │  2x (param+mom)│  CV, converged fine-tune   │
│            │ θ = θ - lr·v    │                │                             │
├────────────┼──────────────────┼────────────────┼─────────────────────────────┤
│ Adam       │ m = β₁m+(1-β₁)g │  4x (param+2m)│  General purpose, NLP,     │
│            │ v = β₂v+(1-β₂)g² │                │  Transformers (pre-2019)   │
│            │ θ -= lr·m/(√v+ε) │                │                             │
├────────────┼──────────────────┼────────────────┼─────────────────────────────┤
│ AdamW      │  Same as Adam   │  4x            │  LLMs, Transformers,       │
│            │  + decoupled wd │                │  modern standard           │
├────────────┼──────────────────┼────────────────┼─────────────────────────────┤
│ LAMB       │  Adam + layer-  │  4x + trust    │  Very large batch (64K+)   │
│            │  wise lr scaling │  ratio         │  BERT pre-training         │
├────────────┼──────────────────┼────────────────┼─────────────────────────────┤
│ Lion       │  Sign(g) update │  2x (param+mom)│  Memory-efficient, LLMs    │
│ (EvoLved)  │  θ -= lr·sign(m)│                │  works w/ smaller lr      │
├────────────┼──────────────────┼────────────────┼────────────────┼────────────┤
│ Adafactor  │  Factored 2nd    │  ~2.5x         │  T5, large models          │
│            │  moment (row+col)│  (no param m)  │  memory-constrained        │
└────────────┴──────────────────┴────────────────┴────────────────────────────┘
```

### When to Use Each Optimizer

**SGD with Momentum** — Still SOTA for conv nets and some fine-tuning. Reaches better generalization minima but harder to tune. Use for: CV classification, when you need the absolute best test accuracy.

**Adam** — The go-to default. Adaptive per-parameter learning rates handle sparse gradients well. Use for: quick prototyping, NLP tasks, training不稳定 settings.

**AdamW** — Decouples weight decay from the gradient update (Loshchilov & Hutter, 2019). Weight decay is applied *directly to weights*, not through the gradient. This is the **de facto standard for Transformers**. Use for: all LLM training, any model using weight decay.

**LAMB** (Large Batch Adam) — Scales Adam to batch sizes of 64K+ by normalizing the update per-layer ("trust ratio"). Critical for BERT pre-training at scale. Use for: distributed pre-training on TPU pods or massive GPU clusters.

**Lion** (EvoLved Sign Momentum) — Discovered via program search. Uses the *sign* of the momentum (not the raw value), halving memory to 2x params. Requires 3-10x smaller learning rate than AdamW and larger weight decay. Use for: memory-constrained LLM training, when you want simpler updates.

**Adafactor** — Factorizes the second moment into row/column statistics, reducing memory. Eliminates the parameter-first-moment storage entirely. Used in T5 training. Use for: when optimizer state memory is the bottleneck (>1B params).

```python
# Practical AdamW configuration for LLM training
optimizer = torch.optim.AdamW(
    model.parameters(),
    lr=3e-4,                    # peak learning rate
    betas=(0.9, 0.95),         # β₂=0.95 (not 0.999!) for Transformers
    eps=1e-8,
    weight_decay=0.1,          # decoupled weight decay
    fused=True,                 # fused CUDA kernel for speed
)
```

> **Critical detail:** GPT-3, LLaMA, and most modern LLMs use `β₂=0.95` rather than the default `0.999`. The lower β₂ makes the second moment estimate more responsive, preventing the learning rate from collapsing too quickly in later training.

---

## 3. Learning Rate Schedules

### Schedule Comparison Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│           LEARNING RATE SCHEDULE COMPARISON                                │
│                                                                             │
│ LR│                                                                        │
│   │  ***                     **********                                   │
│   │  * *                   ***          ***                                 │
│   │  *  *                 *               *                                │
│   │  *   *               *                *                               │
│   │  *    *              *                 *                               │
│   │  *     *            *                   *                              │
│   │  *      *          *                     *                             │
│   │  *  ONE *         *      COSINE          *  ___                        │
│   │  *CYCLE *        *         ANNEAL          *    ─── STEP DECAY         │
│   │  *  (30epoch)*   *                          *        (at 60%,80%)      │
│   │  *           * *                             ──*                        │
│   │  *            *                                ──*──────                 │
│   │  *             *                                   ──*──                 │
│   │  *              *                                    *──                │
│   └──┼──────────────┼────────────────────────────────────┼──────> step     │
│     0             warmup                                   end              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────┐              │
│   │  WARMUP PHASE (first 0.5-2% of steps):                 │              │
│   │    lr = base_lr * (step / warmup_steps)                │              │
│   │                                                         │              │
│   │  Why? Large initial grads cause instability; warmup     │              │
│   │  lets Adam's second moment estimate stabilize before     │              │
│   │  taking large steps.                                    │              │
│   └─────────────────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Cosine Annealing (Standard for LLMs)

```
LR │  ***
    │  *  ****
    │  *      ****
    │  *          ****
    │  *              ****
    │  *                  ****
    │  *                      ****
    │  *                          ****
    │  *                              ****
    │  *************************************** (min_lr)
    └──┼──────────┼────────────────────────┼──> step
       0       warmup                     end

    lr = min_lr + 0.5 * (base_lr - min_lr) * (1 + cos(π * step / total_steps))

    After warmup: smooth decay to min_lr (typically 10% of base_lr or 0)
    Most common schedule for: GPT, LLaMA, Mistral, etc.
```

### OneCycleLR (Smith 2018)

```
LR │      ****
    │     *    ***
    │    *        **
    │   *           **
    │  *              **
    │ *                 **         ← "super-convergence"
    │**                   **        fast training at high LR
    │*                     **      then anneal for refinement
    │                        ***
    │                           ****
    └──┼──────┼────────────────┼────┼──> step
       0   warmup   peak(30%)  70%  end

    Two phases:
    1. LR ramps UP from low → peak → then BACK DOWN to base_lr (45% of steps)
    2. LR decays from base_lr → min_lr (55% of steps, final 5% very steep)

    Often achieves same accuracy in 1/5th the epochs. Best for: fine-tuning, CV.
```

### Cyclical Learning Rates

```
LR │  *   *   *   *   *
    │  * * * * * * * * * *      Triangular: simple sawtooth
    │  * * * * * * * * * *      between lr_min and lr_max
    │  * * * * * * * * * *
    │********* * * * * * *      ↓ decreasing amplitude
    └──┼───────────────────> step

    Useful for: escaping saddle points, exploring loss landscape
    Rarely used in LLM training; more common in CV
```

### Key Practical Advice

- **Warmup is non-negotiable** for Transformers. Without it, early-step gradients are enormous and Adam's second-moment accumulator is unreliable.
- **Min LR matters.** Going all the way to 0 makes late training unstable. Setting min_lr = 0.1 × max_lr (or even 0.05 × max_lr) is standard.
- **Cooldown:** Some recipes (LLaMA 2) add a linear "cooldown" phase in the last ~5% of training rather than cosining to min_lr.

---

## 4. Regularization Techniques

### Comprehensive Regularization Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    REGULARIZATION TECHNIQUES                             │
├─────────────────┬───────────────────────────────────────────────────────┤
│ CATEGORY        │ TECHNIQUES                                          │
├─────────────────┼───────────────────────────────────────────────────────┤
│ Weight Penalty   │ L2 (weight decay): λ||W||²                         │
│                 │ L1: λ||W||₁ (sparsity-inducing)                    │
│                 │ Weight decay (decoupled, AdamW-style)               │
│                 │ Max-norm: clip ||w|| ≤ c per row                   │
├─────────────────┼───────────────────────────────────────────────────────┤
│ Stochastic      │ Dropout: randomly zero activations (p=0.1-0.5)      │
│                 │ Dropout1d/2d: structured dropout (conv)             │
│                 │ Attention dropout (p≈0.1 in attention weights)       │
│                 │ Stochastic depth: skip entire residual blocks        │
│                 │ DropConnect: randomly zero weights                   │
├─────────────────┼───────────────────────────────────────────────────────┤
│ Label           │ Label smoothing: y_k = (1-ε)y + ε/K               │
│                 │ ε=0.1 for classification, ε=0.05-0.1 for LLMs       │
│                 │ Prevents overconfident predictions                  │
├─────────────────┼───────────────────────────────────────────────────────┤
│ Data            │ Random crop, flip, rotate (CV)                      │
│ Augmentation    │ Mixup: x = λx₁ + (1-λ)x₂                          │
│                 │ CutMix: patch-level mixing                          │
│                 │ Back-translation, paraphrase (NLP)                   │
│                 │ Random deletion, swap, mask (text)                   │
└─────────────────┴───────────────────────────────────────────────────────┘
```

### Dropout in Transformers

```python
class TransformerLayer(nn.Module):
    def __init__(self, d_model, n_heads, dropout=0.1):
        super().__init__()
        # Dropout is placed AFTER every sub-layer
        self.attn_dropout = nn.Dropout(dropout)    # attention weights
        self.resid_dropout = nn.Dropout(dropout)   # residual stream
        self.mlp_dropout = nn.Dropout(dropout)     # MLP activations

    def forward(self, x):
        # Attention with dropout
        attn_out = self.attn(x)                    # [B, T, D]
        attn_out = self.attn_dropout(attn_out)      # ← drop attention outputs
        x = x + self.resid_dropout(attn_out)        # ← drop residual

        # MLP with dropout
        mlp_out = self.mlp(x)
        mlp_out = self.mlp_dropout(mlp_out)         # ← drop MLP outputs
        x = x + self.resid_dropout(mlp_out)         # ← drop residual
        return x
```

### Stochastic Depth

Randomly skip entire residual blocks during training. Each layer has a "survival probability" `p_l` that increases linearly from `p_0` (at early layers) to `1.0` (at the last layer):

```
p_l = 1 - (l / L) * (1 - p_0)

Training:  with prob p_l, apply block; with prob (1-p_l), identity shortcut
Inference: always apply block (scaled by expected value if needed)

Used in: DeepNet, ViT-G, etc.  Reduces training time by ~25-30%.
```

### Label Smoothing in LLMs

For causal language modeling with vocabulary size V:
- Hard target: `one_hot(next_token)` → probability 1.0 on correct token
- Smoothed target: `(1 - ε)` on correct token, `ε / (V - 1)` on all others
- Default ε = 0.1 for LLMs. Critical — without it, models become overconfident and generalize poorly.

---

## 5. Gradient Management

### Gradient Clipping

```
┌─────────────────────────────────────────────────────────────────┐
│  GRADIENT CLIPPING BY GLOBAL NORM                               │
│                                                                 │
│  1. Compute: grad_norm = sqrt(Σ ||g_i||²) for all parameters    │
│  2. If grad_norm > max_norm:                                    │
│       g_i = g_i * (max_norm / grad_norm)  for all i            │
│                                                                 │
│  Typical values:                                                │
│    • LLM pre-training:  max_norm = 1.0                         │
│    • Fine-tuning:        max_norm = 1.0                         │
│    • RLHF / PPO:         max_norm = 0.1 - 0.5                  │
│    • Unstable training:  max_norm = 0.5                         │
│                                                                 │
│  CRITICAL: Clip BEFORE optimizer.step(), AFTER backward()       │
│  This is the #1 fix for NaN losses in Transformer training.     │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Standard gradient clipping pattern
scaler.unscale_(optimizer)                           # unscale before clipping
grad_norm = torch.nn.utils.clip_grad_norm_(
    model.parameters(),
    max_norm=1.0,
)
scaler.step(optimizer)                               # skip if inf/nan grads
scaler.update()
```

### Gradient Accumulation

```
┌──────────────────────────────────────────────────────────────────────────┐
│  GRADIENT ACCUMULATION: Simulating Larger Batch Sizes                    │
│                                                                          │
│  Desired global batch = 2048 tokens                                      │
│  GPU memory fits micro-batch = 256 tokens                                │
│  → Accumulation steps = 2048 / 256 = 8                                  │
│                                                                          │
│  Step 1: forward + backward  ──→  gradients accumulate in .grad          │
│  Step 2: forward + backward  ──→  gradients accumulate in .grad          │
│  ...                                                                     │
│  Step 8: forward + backward  ──→  gradients accumulate in .grad          │
│  ──────────────────────────→  optimizer.step()  (average or sum?)       │
│                                                                          │
│  IMPORTANT: If using loss averaging over tokens in micro-batch,          │
│  the accumulated grads already represent the mean over the full batch.    │
│  If loss is summed, divide by accumulation_steps before step().          │
└──────────────────────────────────────────────────────────────────────────┘
```

```python
accumulation_steps = 8
optimizer.zero_grad(set_to_none=True)

for i, batch in enumerate(dataloader):
    with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
        loss = model(batch) / accumulation_steps  # normalize per micro-batch

    scaler.scale(loss).backward()

    if (i + 1) % accumulation_steps == 0:
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        scaler.step(optimizer)
        scaler.update()
        optimizer.zero_grad(set_to_none=True)
```

### Mixed Precision Training Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     MIXED PRECISION TRAINING (AMP)                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  FP32 MASTER WEIGHTS (kept in FP32 for numerical stability)        │    │
│  │  ┌──────────────────┐                                              │    │
│  │  │  W_fp32          │                                              │    │
│  │  └────────┬─────────┘                                              │    │
│  │           │ Cast to BF16/FP16                                      │    │
│  │           ▼                                                         │    │
│  │  ┌──────────────────┐    ┌──────────────────┐                      │    │
│  │  │  W_bf16 (copy)  │───>│  FORWARD PASS    │───> Loss_bf16         │    │
│  │  └──────────────────┘    │  (all matmuls in │                      │    │
│  │                          │   BF16 for speed) │                      │    │
│  │                          └──────────────────┘                      │    │
│  │                                  │                                  │    │
│  │                          Loss_bf16 (scaled ×2¹⁵ for FP16,         │    │
│  │                                  │     ×1 for BF16)                │    │
│  │                                  ▼                                  │    │
│  │  ┌──────────────────┐    ┌──────────────────┐                      │    │
│  │  │  Gradients FP32  │<───│  BACKWARD PASS   │                      │    │
│  │  │  (always FP32!)  │    │  (grads in FP32  │                      │    │
│  │  └────────┬─────────┘    │   for accuracy)  │                      │    │
│  │           │              └──────────────────┘                      │    │
│  │           ▼                                                        │    │
│  │  ┌──────────────────┐                                              │    │
│  │  │  UNSCALE grads   │ ← (divide by scale factor)                  │    │
│  │  │  CLIP grads      │ ← (clip in FP32)                            │    │
│  │  │  CHECK inf/NaN   │ ← (skip step if overflow)                    │    │
│  │  └────────┬─────────┘                                              │    │
│  │           │                                                         │    │
│  │           ▼                                                         │    │
│  │  ┌──────────────────┐                                              │    │
│  │  │  FP32 UPDATE     │ ←  optimizer.step() updates FP32 master     │    │
│  │  │  (W_fp32)        │                                              │    │
│  │  └──────────────────┘                                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  BF16 vs FP16:                                                               │
│    BF16: same exponent range as FP32 (no scaling needed), less precision     │
│    FP16: limited range → requires loss scaling, more prone to overflow       │
│    → BF16 is preferred on Ampere+ GPUs (A100, H100)                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Key point:** Gradients are *always* computed in FP32. The mixed precision only applies to the forward pass activations and weight copies. The optimizer updates the FP32 master copy, ensuring no precision loss in long-running accumulation.

---

## 6. Distributed Training

### Distributed Training Topologies

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     DATA PARALLELISM (DDP)                               │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │  GPU 0   │  │  GPU 1   │  │  GPU 2   │  │  GPU 3   │               │
│  │ ┌──────┐ │  │ ┌──────┐ │  │ ┌──────┐ │  │ ┌──────┐ │               │
│  │ │MODEL │ │  │ │MODEL │ │  │ │MODEL │ │  │ │MODEL │ │  (FULL COPY) │
│  │ │COPY  │ │  │ │COPY  │ │  │ │COPY  │ │  │ │COPY  │ │               │
│  │ └──────┘ │  │ └──────┘ │  │ └──────┘ │  │ └──────┘ │               │
│  │ BATCH 0  │  │ BATCH 1  │  │ BATCH 2  │  │ BATCH 3  │               │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘               │
│        │             │             │             │                       │
│        └─────────────┴─────────────┴─────────────┘                      │
│                      │                                                  │
│              ALL-REDUCE (avg gradients)                                  │
│                      │                                                  │
│              Synced optimizer step                                       │
│                      ▼                                                  │
│            All GPUs get same updated model                               │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                     TENSOR PARALLELISM (TP)                               │
│                                                                          │
│  Split individual LAYERS across GPUs                                     │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐                                     │
│  │    GPU 0     │  │    GPU 1     │                                     │
│  │  ┌────────┐  │  │  ┌────────┐  │                                     │
│  │  │Q·K·V   │  │  │  │Q·K·V   │  │   Attention heads split            │
│  │  │heads   │  │  │  │heads   │  │   across GPUs                      │
│  │  │0-3     │  │  │  │4-7     │  │                                     │
│  │  └───┬────┘  │  │  └───┬────┘  │                                     │
│  │  ┌───▼────┐  │  │  ┌───▼────┐  │                                     │
│  │  │MLP     │  │  │  │MLP     │  │   MLP columns split across GPUs    │
│  │  │col 0-3 │  │  │  │col 4-7 │  │                                     │
│  │  └───┬────┘  │  │  └───┬────┘  │                                     │
│  │      │       │  │      │       │                                     │
│  └──────┼───────┘  └──────┼───────┘                                     │
│         │    All-Reduce    │                                              │
│         └─────────────────┘                                              │
│        (communicate after attn + after MLP)                               │
│                                                                          │
│  Requires: NVLink within same node (high bandwidth)                      │
│  Used in: Megatron-LM, Tensor Parallelism in transformers                │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                     PIPELINE PARALLELISM (PP)                             │
│                                                                          │
│  Split model LAYERS across GPUs (sequential)                             │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │  GPU 0   │  │  GPU 1   │  │  GPU 2   │  │  GPU 3   │                │
│  │ Layers   │→│ Layers   │→│ Layers   │→│ Layers   │                │
│  │  0-5     │  │  6-11    │  │ 12-17    │  │ 18-23    │                │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘                │
│                                                                          │
│  Problem: GPU idle time ("bubble") while waiting for other stages        │
│                                                                          │
│  Naive:    ████░░░░░░░░░░░░  (75% idle — pipeline bubble)                │
│  1F1B:     ████░░░░░░░░░░░░  (much less idle time)                      │
│  Interleaved: ███░░░░░░░░░░  (even less idle — virtual stages)          │
│                                                                          │
│  Micro-batch pipelining (1F1B schedule):                                 │
│                                                                          │
│  Time →   T1   T2   T3   T4   T5   T6   T7   T8                       │
│  GPU 0:  [F1] [F2] [F3] [F4] [B1] [B2] [B3] [B4]                      │
│  GPU 1:       [F1] [F2] [F3] [B1] [F4] [B2] [B3] [B4]                 │
│  GPU 2:            [F1] [F2] [B1] [F3] [B2] [F4] [B3] [B4]            │
│  GPU 3:                 [F1] [B1] [F2] [B2] [F3] [B3] [F4] [B4]       │
│                                                                          │
│  F = forward micro-batch, B = backward micro-batch                      │
│  → Each GPU alternates forward/backward to minimize idle time           │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                     FSDP (Fully Sharded Data Parallel)                   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────┐               │
│  │  GPU 0            GPU 1            GPU 2            GPU 3          │               │
│  │  ┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐       │               │
│  │  │Shard 0 │      │Shard 1 │      │Shard 2 │      │Shard 3 │       │               │
│  │  │of model│      │of model│      │of model│      │of model│       │               │
│  │  └────────┘      └────────┘      └────────┘      └────────┘       │               │
│  │       ↓ Gather (all-gather) ← ─ ─ ─ ─ ─ ─ ─ ─ ─ → ↓              │               │
│  │  ┌─────────────────────────────────────────────────────┐            │               │
│  │  │          Full model (unsharded, temporarily)        │            │               │
│  │  └─────────────────────────────────────────────────────┘            │               │
│  │       ↓ Run forward for this layer, then DISCARD        │           │               │
│  │  ← Only the active layer (or layer group) lives in GPU memory →     │               │
│  └──────────────────────────────────────────────────────────────────────┘               │
│                                                                          │
│  Key insight: At any time, each GPU stores only 1/N of the model.       │
│  Layers are all-gathered on-demand and immediately discarded.            │
│                                                                          │
│  Memory = 1/N × (model params) + 1/N × (optimizer state) + activations │
│  → Scales to arbitrarily large models with enough GPUs                  │
│                                                                          │
│  FSDP vs DDP vs Sharded DDP:                                            │
│  ┌───────────────┬──────────────────────────────────────────────┐       │
│  │ Method        │ GPU Memory Usage                            │       │
│  ├───────────────┼──────────────────────────────────────────────┤       │
│  │ DDP           │ Full model + Full optimizer + activations    │       │
│  │ ShardedDDP    │ Full model + 1/N optimizer + activations    │       │
│  │ FSDP          │ 1/N model + 1/N optimizer + activations     │       │
│  └───────────────┴──────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────────┘
```

### Ring All-Reduce (Communication Pattern)

```
┌──────────────────────────────────────────────────────────────────────────┐
│              RING ALL-REDUCE (Bandwidth-Optimal)                         │
│                                                                          │
│  4 GPUs each have a gradient chunk: [A₁,B₁,C₁,D₁] ... [A₄,B₄,C₄,D₄]   │
│                                                                          │
│  PHASE 1: REDUCE-SCATTER (each GPU gets sum of one chunk)               │
│                                                                          │
│   GPU 0 ──→ GPU 1 ──→ GPU 2 ──→ GPU 3 ──→ (ring)                       │
│     │         │         │         │                                      │
│   Step 1:  Each GPU sends one chunk to next                              │
│     0→1: B₁   1→2: C₂   2→3: D₃   3→0: A₄                              │
│   Step 2:  Accumulate and forward                                       │
│     0→1: A₄+A₁  1→2: B₁+B₂  2→3: C₂+C₃  3→0: D₃+D₄                  │
│   Step 3:  Accumulate and forward                                       │
│   ...                                                                    │
│   Result: GPU 0 has ΣA, GPU 1 has ΣB, GPU 2 has ΣC, GPU 3 has ΣD      │
│                                                                          │
│  PHASE 2: ALL-GATHER (broadcast each reduced chunk to all)              │
│                                                                          │
│   Same ring pattern but in reverse, each GPU shares its chunk           │
│   Result: All GPUs have [ΣA, ΣB, ΣC, ΣD]                              │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────┐          │
│  │  Bandwidth: O(N × model_size / K)  where K = num_GPUs     │          │
│  │  Latency:   O(K) ring steps                               │          │
│  │  → Scales efficiently; bandwidth per GPU decreases w/ K   │          │
│  └────────────────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────────────┘
```

### DeepSpeed ZeRO Stages

```
┌──────────────────────────────────────────────────────────────────────────┐
│              DEEPSPEED ZERO STAGES                                       │
│                                                                          │
│  Stage 0:  Standard DDP (no sharding)                                   │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                                   │
│  │ GPU 0│ │ GPU 1│ │ GPU 2│ │ GPU 3│  Each GPU: full model             │
│  │P+O+A │ │P+O+A │ │P+O+A │ │P+O+A │  + full optimizer                │
│  └──────┘ └──────┘ └──────┘ └──────┘  + full activations               │
│                                                                          │
│  Stage 1:  Shard optimizer state only                                    │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                                   │
│  │ GPU 0│ │ GPU 1│ │ GPU 2│ │ GPU 3│  Each GPU: full model             │
│  │P+O/4 │ │P+O/4 │ │P+O/4 │ │P+O/4 │  + 1/4 optimizer state           │
│  │+  A  │ │+  A  │ │+  A  │ │+  A  │  + full activations              │
│  └──────┘ └──────┘ └──────┘ └──────┘                                    │
│                                                                          │
│  Stage 2:  Shard optimizer + gradients                                   │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                                   │
│  │ GPU 0│ │ GPU 1│ │ GPU 2│ │ GPU 3│  Each GPU: full model             │
│  │P+O/4 │ │P+O/4 │ │P+O/4 │ │P+O/4 │  + 1/4 optimizer + 1/4 grads    │
│  │+ A   │ │+ A   │ │+ A   │ │+ A   │  + full activations              │
│  └──────┘ └──────┘ └──────┘ └──────┘                                    │
│                                                                          │
│  Stage 3:  Shard optimizer + gradients + parameters (= FSDP)             │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                                   │
│  │ GPU 0│ │ GPU 1│ │ GPU 2│ │ GPU 3│  Each GPU: 1/4 model             │
│  │P/4+  │ │P/4+  │ │P/4+  │ │P/4+  │  + 1/4 optimizer + 1/4 grads    │
│  │O/4+  │ │O/4+  │ │O/4+  │ │O/4+  │  + activations (local)           │
│  │A     │ │A     │ │A     │ │A     │                                    │
│  └──────┘ └──────┘ └──────┘ └──────┘                                    │
│                                                                          │
│  Memory per GPU for a 7B model (AdamW, fp32 params):                    │
│    Stage 0: ~112 GB (model 28GB + optimizer 56GB + grads 28GB)         │
│    Stage 3: ~28 GB / num_gpus (4 GPUs → ~7GB each)                     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Combining Parallelism Strategies

```
┌──────────────────────────────────────────────────────────────────────────┐
│  3D PARALLELISM: TP + PP + DP (e.g., Megatron-Deepspeed)                │
│                                                                          │
│  ┌────────────────────────── Node 0 ──────────────────────────┐         │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │         │
│  │  │GPU 0   │  │GPU 1   │  │GPU 2   │  │GPU 3   │           │         │
│  │  │TP=0    │  │TP=1    │  │TP=0    │  │TP=1    │           │         │
│  │  │PP=0    │  │PP=0    │  │PP=1    │  │PP=1    │ ← TP within│         │
│  │  │        │  │        │  │        │  │        │   NVLink   │         │
│  │  └────────┘  └────────┘  └────────┘  └────────┘           │         │
│  │         PP group 0              PP group 1                │         │
│  └─────────────────────────────────────────────────────────────┘         │
│  ┌────────────────────────── Node 1 ──────────────────────────┐         │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │         │
│  │  │GPU 4   │  │GPU 5   │  │GPU 6   │  │GPU 7   │           │         │
│  │  │TP=0    │  │TP=1    │  │TP=0    │  │TP=1    │           │         │
│  │  │PP=0    │  │PP=0    │  │PP=1    │  │PP=1    │           │         │
│  │  └────────┘  └────────┘  └────────┘  └────────┘           │         │
│  └─────────────────────────────────────────────────────────────┘         │
│       ↑ DP across nodes (gradient all-reduce over network) ↑             │
│                                                                          │
│  TP: Within a node (NVLink, 600+ GB/s)                                  │
│  PP: Across pipeline stages (NVLink or NVSwitch)                        │
│  DP: Across data replicas (InfiniBand, 100+ GB/s)                      │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Training Monitoring and Debugging

### Monitoring Checklist

| Metric | What to Track | Normal Range | Red Flag |
|--------|--------------|-------------|----------|
| Loss (train) | Every 100 steps | Steadily decreasing | NaN, spiking, no decrease |
| Loss (val) | Every epoch | Decreasing, then plateauing | Diverging from train loss |
| Grad norm | Every 100 steps | 0.1 — 10.0 | >100 or 0.0 or NaN |
| Learning rate | Every step | Following schedule | Not decaying, jumping |
| Weight norm | Every epoch | Stable, slowly growing | Exploding or collapsing |
| Throughput | Every step | Consistent tokens/sec | Sudden drops |
| GPU memory | Every step | Stable | OOM spikes |

```python
# Weights & Biases integration for comprehensive monitoring
import wandb

wandb.init(project="llm-training", config={
    "model": "7B-transformer",
    "learning_rate": 3e-4,
    "optimizer": "AdamW",
    "batch_size": 2048,
    "schedule": "cosine",
    "warmup_steps": 2000,
})

# Log in training loop
if step % 100 == 0:
    wandb.log({
        "train/loss": loss.item(),
        "train/perplexity": torch.exp(loss).item(),
        "train/grad_norm": grad_norm,
        "train/lr": scheduler.get_last_lr()[0],
        "train/throughput_tokens_per_sec": tokens_per_sec,
        "train/epoch": epoch,
        "optim/weight_norm": sum(p.norm().item() for p in model.parameters()),
        "optim/step_norm": sum(
            (p.grad.norm().item() if p.grad is not None else 0)
            for p in model.parameters()
        ),
    })
```

### Loss Curve Patterns and Their Meanings

```
┌──────────────────────────────────────────────────────────────────────────┐
│               LOSS CURVE PATTERNS & DIAGNOSIS                            │
│                                                                          │
│  1. HEALTHY TRAINING                    2. LEARNING RATE TOO HIGH        │
│     Loss │                                                               │
│     10.0 │\                                                             │
│           │ \                                                            │
│      5.0 │  \                                                           │
│           │   \___________                                              │
│      2.0 │                ─────────────                                │
│           │                     plateau (not overfitting yet)           │
│      1.0 │                                                        step  │
│                                                                           │
│     Loss │                          Loss │  ╱╲╱╲╱╲                     │
│    10.0 │\                          10.0 │ ╱  ╲╱  ╲╱╲                  │
│           │ \                              │╱         ╲                 │
│     5.0 │  \_______                 5.0 │              ╲___           │
│           │         ─────                  │                   │          │
│     2.0 │              ────────     2.0 │                    ──│      │
│           │                                               step        │
│                                                                           │
│  3. LR TOO LOW                          4. OVERFITTING                   │
│     Loss │                               Loss │                         │
│    10.0 │                               10.0 │\                         │
│           │\                                   │ \                       │
│     5.0 │ \                              5.0 │  \___                    │
│           │  \                                  │      \___              │
│     2.0 │   \___                       2.0 │          \___train          │
│           │       ────────                   │              \  val ↑     │
│     1.0 │            (barely          1.0 │               ╱╱          │
│           │             moving)                           step          │
│     0.1 │   (needs 10x more steps)                         ↑ gap=      │
│           │                                                overfit!    │
│                                                                           │
│  5. WARMUP TOO SHORT                    6. GRADIENT EXPLOSION           │
│     Loss │                               Loss │                        │
│    10.0 │─ ─                             10.0 │  ╱╲                     │
│           │ ╲                                  │ ╱  ╲  NaN!             │
│     5.0 │  ╲───                    5.0 │╱    ╲                     │
│           │      ──────                       │      ╲──               │
│     2.0 │            ──────          2.0 │          ╲─────────       │
│           │  (initial spike, then          │                          │
│     1.0 │   recovers slowly)               │  NaN loss, grad spikes   │
│           │                                │  Check: clipping, LR,     │
│           │        step                     │  dtype overflow          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Common Training Failures and Debugging

### Debugging Decision Tree

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     TRAINING DEBUGGING DECISION TREE                         │
│                                                                              │
│  START: Training is not working                                              │
│       │                                                                      │
│       ├── Loss is NaN?                                                        │
│       │     ├── YES → Check:                                                 │
│       │     │     ├── Gradient norm exploding? → Add gradient clipping (1.0) │
│       │     │     ├── LR too high? → Reduce by 10x                           │
│       │     │     ├── Data has NaN/Inf? → Add data validation pipeline       │
│       │     │     ├── Division by zero? → Add eps=1e-8 to normalizations     │
│       │     │     └── fp16 overflow? → Switch to bf16 or add loss scaling   │
│       │     │                                                                │
│       │     └── NO → Loss not decreasing?                                    │
│       │           ├── Loss completely flat?                                  │
│       │           │     ├── LR = 0? → Check scheduler                        │
│       │           │     ├── Gradients all zero? → Check dead neurons         │
│       │           │     ├── Data not shuffled? → Shuffle dataset             │
│       │           │     └── Wrong labels? → Verify data pipeline            │
│       │           │                                                          │
│       │           └── Loss decreasing too slowly?                           │
│       │                 ├── LR too low? → Increase by 3-10x                  │
│       │                 ├── Batch too small? → Increase or accumulate        │
│       │                 ├── Warmup too long? → Shorten to 0.5-2% steps     │
│       │                 └── Model capacity insufficient? → Scale up          │
│       │                                                                      │
│       ├── Train loss ↓ but val loss ↑ ?                                     │
│       │     └── OVERFITTING →                                               │
│       │           ├── Add dropout (0.1-0.3)                                 │
│       │           ├── Add weight decay (0.01-0.1 for AdamW)                │
│       │           ├── Add data augmentation                                 │
│       │           ├── Reduce model size                                     │
│       │           ├── Early stopping                                       │
│       │           └── More training data                                   │
│       │                                                                      │
│       ├── Loss oscillating wildly?                                           │
│       │     ├── LR too high → Reduce by 3-10x                              │
│       │     ├── Batch too small → Accumulate gradients                      │
│       │     ├── No warmup → Add linear warmup (1-2% of steps)              │
│       │     └── Data ordering issue → Shuffle properly                      │
│       │                                                                      │
│       ├── OOM (Out of Memory)?                                               │
│       │     ├── Reduce batch size → Use gradient accumulation               │
│       │     ├── Enable mixed precision (bf16)                               │
│       │     ├── Use FSDP/DeepSpeed ZeRO-3                                  │
│       │     ├── Enable activation checkpointing                             │
│       │     ├── Use Flash Attention                                         │
│       │     └── Use gradient checkpointing                                  │
│       │                                                                      │
│       └── Training too slow?                                                 │
│             ├── Profile with torch.profiler                                 │
│             ├── Increase batch size (if memory allows)                      │
│             ├── Use fused optimizer (fused=True in AdamW)                   │
│             ├── Use torch.compile()                                         │
│             ├── Enable Flash Attention                                      │
│             └── Check dataloader bottleneck                                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Common Failure Patterns and Fixes

| Symptom | Most Likely Cause | Fix |
|---------|------------------|-----|
| NaN loss at step 0 | Bad initialization or LR too high | Reduce LR to 1e-5, check init |
| NaN loss after N steps | Gradient explosion | Gradient clipping (max_norm=1.0) |
| Loss spikes periodically | LR schedule boundary or bad data | Check schedule, filter data |
| Train/val gap widening | Overfitting | Dropout, weight decay, data aug |
| Val loss plateaus early | Insufficient model capacity | Wider/deeper model |
| Loss very noisy | Batch size too small | Gradient accumulation |
| Secondary loss rise | LR too high in late training | Increase min LR ratio |
| Perplexity stuck at ~vocab_size | Model predicting uniform | Check embedding init, warmup |

---

## 9. Memory Optimization Techniques

### GPU Memory Breakdown

```
┌──────────────────────────────────────────────────────────────────────────┐
│  GPU MEMORY FOOTPRINT FOR A 7B PARAMETER MODEL                          │
│  (fp16 params + AdamW optimizer in fp32)                                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Parameters (fp16):           14 GB    (7B × 2 bytes)          │    │
│  │  Gradients (fp16):            14 GB    (7B × 2 bytes)          │    │
│  │  Optimizer state (fp32):       56 GB    (7B × 4 × 2 for m+v)   │    │
│  │  ─────────────────────────────────────────────────────────────  │    │
│  │  Subtotal (weights):           84 GB                             │    │
│  │                                                                  │    │
│  │  Activations (varies):        8-20 GB   (depends on seq_len)    │    │
│  │  Temporary buffers:            2-4 GB                             │    │
│  │  ─────────────────────────────────────────────────────────────  │    │
│  │  TOTAL:                   ~94-108 GB  → Needs A100 80GB + offload│    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  OPTIMIZATION STACK (apply in order):                                    │
│                                                                          │
│  1. Mixed Precision (bf16)          → 14 GB params (was 28 GB fp32)    │
│  2. Flash Attention                  → 50-70% activation reduction      │
│  3. Gradient Checkpointing           → Trade compute for memory         │
│     - Recompute activations during backward                           │
│     - Reduces activation mem by ~70%, slows training by ~25%          │
│  4. FSDP / ZeRO Stage 3             → Shard everything across GPUs    │
│  5. CPU Offloading (ZeRO-Offload)    → Move optimizer state to CPU     │
│  6. KV-cache compression (inference) → Not applicable to training     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Activation Checkpointing (Gradient Checkpointing)

```python
# Without checkpointing: ALL activations stored for backward pass
# Memory = O(n_layers × batch × seq_len × d_model)

# With checkpointing: Only store activations at checkpoint boundaries
# Recompute intermediate activations during backward pass
# Memory = O(n_checkpoints × batch × seq_len × d_model)

from torch.utils.checkpoint import checkpoint

class TransformerBlock(nn.Module):
    def forward(self, x):
        if self.training and self.use_checkpoint:
            return checkpoint(self._forward, x, use_reentrant=False)
        return self._forward(x)

    def _forward(self, x):
        x = x + self.attn(self.ln1(x))
        x = x + self.mlp(self.ln2(x))
        return x

# Rule of thumb: checkpoint every ~4 layers
# This reduces activation memory by ~4x at cost of ~25% more compute
```

### Flash Attention

```
┌──────────────────────────────────────────────────────────────────────────┐
│  FLASH ATTENTION: Memory-Efficient Attention                             │
│                                                                          │
│  Standard Attention:                                                     │
│    Q, K, V → [B, T, D]                                                  │
│    Attn = softmax(Q @ K^T / √d) @ V                                    │
│    Memory: O(T²) for full attention matrix                               │
│    Problem: For T=128K, that's 128K² × 2 bytes = 32 GB per head!       │
│                                                                          │
│  Flash Attention:                                                        │
│    - Splits Q, K, V into blocks that fit in SRAM                        │
│    - Computes attention per block, never materializes full T×T matrix    │
│    - Uses online softmax trick to maintain numerical accuracy            │
│    - Memory: O(T) instead of O(T²)                                      │
│    - 2-4x faster on A100 due to reduced HBM reads/writes                │
│                                                                          │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐               │
│  │  Q block    │────>│  SRAM:       │────>│  O block    │               │
│  │             │     │  QK^T →      │     │  (output)   │               │
│  │             │     │  softmax →   │     │             │               │
│  │  K block    │────>│  × V         │     │             │               │
│  │  V block    │     │  (no HBM!)   │     │             │               │
│  └─────────────┘     └──────────────┘     └─────────────┘               │
│                                                                          │
│  Usage: model = model.to(torch.bfloat16)                                │
│         with torch.backends.cuda.sdp_kernel(                             │
│             flash_sdp_enabled=True):                                     │
│             output = F.scaled_dot_product_attention(Q, K, V)            │
│                                                                          │
│  Or simply: attn_output = torch.nn.functional.scaled_dot_product_       │
│                                 attention(Q, K, V, is_causal=True)      │
│  (PyTorch 2.0+ automatically uses Flash Attention when possible)         │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Training LLMs at Scale

### The Pre-Training Mechanics

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    LLM PRE-TRAINING PIPELINE                                 │
│                                                                              │
│  ┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────┐  │
│  │ WEB TEXT│────>│  DEDUPLICATE │────>| QUALITY FILTER│────>│  TOKENIZE │  │
│  │ BOOKS   │     │  (exact &    │     │ (perplexity,  │     │  (BPE,    │  │
│  │ CODE    │     │   fuzzy)     │     │  toxicity,    │     │  32K-256K │  │
│  │ SCIENCE │     │              │     │  quality clf) │     │  vocab)   │  │
│  └─────────┘     └──────────────┘     └──────────────┘     └─────┬─────┘  │
│                                                                   │          │
│  ┌───────────────────────────────────────────────────────────────▼────┐     │
│  │                     DATA MIXTURE                                   │     │
│  │  Web text:  67%  │  Books: 4.5%  │  Code: 4.5%  │  Sci: 2.5%    │     │
│  │  (with upsampling of high-quality sources like Wikipedia,          │     │
│  │   ArXiv, StackOverflow, GitHub, etc.)                             │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  TRAINING CONFIG (7B model example):                                        │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  Model: 7B parameters, 32 layers, 4096 hidden, 32 heads          │      │
│  │  Data: 1-2T tokens (Web, Books, Code, Scientific papers)         │      │
│  │  Global batch: 4M tokens (2048 seq_len × 2048 batch)              │      │
│  │  Optimizer: AdamW, β₁=0.9, β₂=0.95, weight_decay=0.1            │      │
│  │  LR: 3e-4 peak, cosine decay to 3e-5, warmup 2000 steps          │      │
│  │  Grad clip: 1.0                                                   │      │
│  │  Precision: bf16 + bf16 optimizer (or fp32 optimizer)            │      │
│  │  Hardware: ~256 A100s for ~7 days                                │      │
│  │                                                                   │      │
│  │  Total steps = 1T tokens / (4M tokens/step) ≈ 250K steps        │      │
│  │  Warmup = 2000 steps (0.8% of total)                              │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│  CHECKPOINTING:                                                              │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  • Save every 1000-5000 steps                                    │      │
│  │  • Keep last 2-3 + best validation checkpoint                    │      │
│  │  • Each checkpoint: ~14 GB (bf16) + optimizer state              │      │
│  │  • Use async checkpointing to avoid training stalls              │      │
│  │  • Store optimizer state for resume capability                   │      │
│  └───────────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Scaling Laws and Chinchilla Implications

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CHINCHILLA SCALING LAWS (Hoffmann et al., 2022)                        │
│                                                                          │
│  Key findings:                                                           │
│  1. For compute-optimal training: model_size ≈ data_size (in tokens)    │
│  2. Optimal tokens = 20 × model_parameters (Chinchilla optimal)         │
│     → A 7B model needs ~140B tokens (but most train on 1T+ tokens)     │
│  3. Both model size and data must scale together                        │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────┐          │
│  │  Parameters │  Optimal Tokens │  Chinchilla │ LLaMA-style │          │
│  │              │  (20x params)   │  epochs=1   │  data/training│         │
│  ├──────────────┼─────────────────┼─────────────┼──────────────┤         │
│  │  1.4B        │    28B          │    28B      │   1T (35ep)  │         │
│  │  7B          │   140B          │   140B      │   1T (7ep)   │         │
│  │  13B         │   260B          │   260B      │   1T (4ep)  │         │
│  │  70B         │  1.4T           │   1.4T      │   1.4T (1ep)│         │
│  │  175B        │  3.5T           │   3.5T      │   ???       │         │
│  └──────────────┴─────────────────┴─────────────┴──────────────┘          │
│                                                                          │
│  LLaMA trained beyond Chinchilla optimal with more data, fewer epochs:  │
│  - Shows that training longer on more data (even multi-epoch) works    │
│  - Degradation from multi-epoch is modest (1-2 epochs: fine)          │
│  - But data quality matters MORE than quantity after sufficient data   │
│                                                                          │
│  L(hu) ≈ A/N^α + B/D^β + C                                            │
│  N = model parameters, D = training tokens                              │
│  α ≈ 0.34, β ≈ 0.28 (Chinchilla estimates)                            │
└──────────────────────────────────────────────────────────────────────────┘
```

### Pre-Training to Fine-Tuning Continuum

```
┌──────────────────────────────────────────────────────────────────────────┐
│  FROM PRE-TRAINING TO DEPLOYMENT                                         │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Phase 1: PRE-TRAINING                                         │    │
│  │  • Next-token prediction on massive text (1T+ tokens)          │    │
│  │  • All parameters updated                                      │    │
│  │  • LR: 3e-4, batch: 4M tokens, cosine schedule                 │    │
│  │  • Duration: weeks to months                                   │    │
│  │  • Output: Base model (general capabilities)                    │    │
│  └────────────────────────────┬────────────────────────────────────┘    │
│                               │                                          │
│  ┌────────────────────────────▼────────────────────────────────────┐    │
│  │  Phase 2: SUPERVISED FINE-TUNING (SFT)                         │    │
│  │  • Instruction-following data (10K-100K examples)              │    │
│  │  • All parameters or LoRA updated                              │    │
│  │  • LR: 1e-5 to 5e-5, 3-5 epochs                               │    │
│  │  • Duration: hours                                              │    │
│  │  • Output: Chat model (follows instructions)                    │    │
│  └────────────────────────────┬────────────────────────────────────┘    │
│                               │                                          │
│  ┌────────────────────────────▼────────────────────────────────────┐    │
│  │  Phase 3: RLHF / DPO / PPO                                     │    │
│  │  • Human preference data (10K-100K comparisons)              │    │
│  │  • Train reward model → optimize with PPO/DPO                 │    │
│  │  • LR: 1e-6 to 5e-6, conservative updates                     │    │
│  │  • Duration: hours                                               │    │
│  │  • Output: Aligned model (helpful, harmless, honest)           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  LoRA (Low-Rank Adaptation) for fine-tuning:                            │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Original:  Y = XW     where W ∈ ℝ^{d×d}  (e.g., 4096×4096)  │   │
│  │  LoRA:      Y = X(W + BA)  where B ∈ ℝ^{d×r}, A ∈ ℝ^{r×d}   │   │
│  │                                   r << d  (r = 8, 16, 64)      │   │
│  │                                                                  │   │
│  │  Parameters: 2 × d × r = 2 × 4096 × 16 = 131K (vs 16.7M)     │   │
│  │  Reduction: 128x fewer trainable parameters                     │   │
│  │                                                                  │   │
│  │  W is FROZEN. Only A and B are trained.                         │   │
│  │  At inference: merge W' = W + α·B·A (zero latency overhead)    │   │
│  │  α = scaling factor (typically α = r for init stability)        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### Full Training Loop (PyTorch Reference)

```python
import torch
import torch.nn.functional as F
from torch.distributed.fsdp import FullyShardedDataParallel as FSDP

def train_loop(model, dataloader, optimizer, scheduler, scaler, grad_clip=1.0, 
               accumulation_steps=8, use_bf16=True):
    model.train()
    optimizer.zero_grad(set_to_none=True)

    for step, batch in enumerate(dataloader):
        # Forward pass (mixed precision)
        with torch.autocast(device_type="cuda", dtype=torch.bfloat16 if use_bf16 else torch.float16):
            loss = model(batch)  # model returns (loss / accumulation_steps) if averaging
            loss = loss / accumulation_steps  # normalize for accumulation

        # Backward pass
        if use_bf16:
            # BF16: no loss scaling needed
            loss.backward()
        else:
            # FP16: use GradScaler
            scaler.scale(loss).backward()

        # Gradient accumulation boundary
        if (step + 1) % accumulation_steps == 0:
            # Unscale gradients (for FP16 mixed precision)
            if not use_bf16:
                scaler.unscale_(optimizer)

            # Gradient clipping
            grad_norm = torch.nn.utils.clip_grad_norm_(
                model.parameters(), max_norm=grad_clip
            )

            # Optimizer step
            if use_bf16:
                optimizer.step()
            else:
                scaler.step(optimizer)
                scaler.update()

            # Learning rate schedule step
            scheduler.step()

            # Zero gradients
            optimizer.zero_grad(set_to_none=True)

            # Logging
            if step % 100 == 0:
                lr = scheduler.get_last_lr()[0]
                print(f"Step {step} | Loss {loss.item() * accumulation_steps:.4f} | "
                      f"Grad Norm {grad_norm:.4f} | LR {lr:.2e}")

        # Checkpointing
        if step > 0 and step % 5000 == 0:
            save_checkpoint(model, optimizer, scheduler, step)
```

### Key Hyperparameters for LLM Training (Reference)

| Hyperparameter | 125M | 1.3B | 7B | 13B | 70B |
|---|---|---|---|---|---|
| Learning Rate | 6e-4 | 3e-4 | 3e-4 | 3e-4 | 1.5e-4 |
| Min LR Ratio | 0.1 | 0.1 | 0.1 | 0.1 | 0.1 |
| Warmup Steps | 2000 | 2000 | 2000 | 2000 | 2000 |
| Batch Size (tokens) | 2M | 4M | 4M | 4M | 4M |
| Weight Decay | 0.1 | 0.1 | 0.1 | 0.1 | 0.1 |
| Grad Clip | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| β₁, β₂ | 0.9, 0.95 | 0.9, 0.95 | 0.9, 0.95 | 0.9, 0.95 | 0.9, 0.95 |
| Dropout | 0.0 (pretrain) | 0.0 | 0.0 | 0.0 | 0.0 |
| Precision | bf16 | bf16 | bf16 | bf16 | bf16 |
| Schedule | Cosine | Cosine | Cosine | Cosine | Cosine |
| Seq Length | 2048 | 2048 | 4096 | 4096 | 4096 |

> **Note on dropout:** Modern LLM pre-training typically uses **zero dropout**. The model size and data volume provide sufficient regularization. Dropout is added back during fine-tuning (typically 0.1).

---

## Quick Reference: Training Recipes

```
┌──────────────────────────────────────────────────────────────────────────┐
│  QUICK REFERENCE: WHAT TO USE WHEN                                       │
│                                                                          │
│  Pre-training LLM (7B+):                                                 │
│    Optimizer:  AdamW (β₁=0.9, β₂=0.95, wd=0.1)                        │
│    Schedule:   Cosine with warmup (0.5-2% of steps)                     │
│    Precision:  bf16                                                       │
│    Parallel:   FSDP or 3D (TP+PP+DP)                                    │
│    Grad clip:  1.0                                                       │
│    Dropout:    0.0                                                        │
│                                                                          │
│  Fine-tuning LLM (full):                                                 │
│    Optimizer:  AdamW (β₁=0.9, β₂=0.999, wd=0.01)                      │
│    Schedule:   Cosine with warmup (short, 10-100 steps)                  │
│    Precision:  bf16                                                       │
│    Parallel:   DDP or FSDP                                               │
│    Grad clip:  1.0                                                       │
│    Dropout:    0.1                                                        │
│    LR:          1e-5 to 5e-5                                             │
│                                                                          │
│  LoRA Fine-tuning:                                                        │
│    Optimizer:  AdamW (wd=0.01, or 0.0 for LoRA params only)            │
│    Schedule:   Cosine or constant with warmup                            │
│    Precision:  bf16                                                       │
│    Parallel:   Single-GPU or DDP                                         │
│    Grad clip:  1.0                                                       │
│    LR:          1e-4 to 3e-4 (higher than full fine-tuning)              │
│    LoRA r:      8-64, α = r (or 2r)                                     │
│    LoRA targets: q_proj, v_proj, k_proj, o_proj, gate_proj, up_proj,    │
│                  down_proj                                                │
│                                                                          │
│  RLHF / DPO:                                                             │
│    Optimizer:  AdamW (conservative LR: 1e-6 to 5e-6)                    │
│    Schedule:   Linear decay or constant                                   │
│    Precision:  bf16                                                       │
│    Grad clip:  0.1 - 0.5 (more aggressive clipping)                     │
│    LR:          1e-6 to 5e-6 (much lower than SFT)                       │
│    Key risk:   reward hacking, mode collapse                              │
└──────────────────────────────────────────────────────────────────────────┘
```

---

*This guide covers the core mechanics of model training from first principles. For implementation-specific details, refer to framework documentation (PyTorch FSDP, DeepSpeed, Megatron-LM) and the training recipes published with major model releases (LLaMA, GPT-NeoX, MPT).*

---

## Real References

### Optimizers

1. Kingma, D., Ba, J., "Adam: A Method for Stochastic Optimization", ICLR 2015. arXiv:1412.6980. https://doi.org/10.48550/arXiv.1412.6980

2. Loshchilov, I., Hutter, F., "Decoupled Weight Decay Regularization" (AdamW), ICLR 2019. arXiv:1711.05101. https://doi.org/10.48550/arXiv.1711.05101

3. You, Y., Li, J., Reddi, S., Kumar, S., Bhojanapalli, S., Yang, X., Hsieh, C.-J., "Large Batch Optimization for Deep Learning: Training BERT in 76 minutes" (LAMB), ICLR 2020. arXiv:1904.00962. https://doi.org/10.48550/arXiv.1904.00962

4. Chen, L., Xie, X., Wu, Z., Hong, M., "Symbolic Discovery of Optimization Algorithms" (Lion), arXiv 2023. arXiv:2302.06675. https://doi.org/10.48550/arXiv.2302.06675

5. Shazeer, N., Stern, M., "Adafactor: Adaptive Learning Rates with Sublinear Memory Cost", ICML 2018. arXiv:1804.04235. https://doi.org/10.48550/arXiv.1804.04235

6. Reddi, S. J., Kale, S., Kumar, S., "On the Convergence of Adam and Beyond", ICLR 2018. arXiv:1904.09237. https://doi.org/10.48550/arXiv.1904.09237

### Learning Rate Schedules

7. Smith, L. N., "Cyclical Learning Rates for Training Neural Networks", WACV 2017. arXiv:1506.01186. https://doi.org/10.1109/WACV.2017.58

8. Smith, L. N., Topin, N., "Super-Convergence: Very Fast Training of Neural Networks Using Large Learning Rates", arXiv 2018. arXiv:1708.07120. https://doi.org/10.48550/arXiv.1708.07120

9. Loshchilov, I., Hutter, F., "SGDR: Stochastic Gradient Descent with Warm Restarts", ICLR 2017. arXiv:1608.03983. https://doi.org/10.48550/arXiv.1608.03983

10. Loshchilov, I., Hutter, F., "Online Batch Selection for Faster Convergence of Stochastic Gradient Descent", arXiv 2015. arXiv:1511.06343. https://doi.org/10.48550/arXiv.1511.06343

### Weight Initialization

11. Glorot, X., Bengio, Y., "Understanding the Difficulty of Training Deep Feedforward Neural Networks", AISTATS 2010. http://proceedings.mlr.press/v9/glorot10a.html

12. He, K., Zhang, X., Ren, S., Sun, J., "Delving Deep into Rectifiers: Surpassing Human-Level Performance on ImageNet Classification", ICCV 2015. arXiv:1502.01852. https://doi.org/10.1109/ICCV.2015.123

### Mixed Precision Training

13. Micikevicius, P., Narang, S., Alben, J., Diamos, G., Elsen, E., Garcia, D., Ginsburg, B., Houston, M., Kuchaiev, O., Venkatesh, G., Wu, H., "Mixed Precision Training", ICLR 2018. arXiv:1710.03740. https://doi.org/10.48550/arXiv.1710.03740

14. NVIDIA, "Automatic Mixed Precision (AMP) Documentation", PyTorch AMP. https://pytorch.org/docs/stable/amp.html

### Distributed Training & Parallelism

15. Rajbhandari, S., Rasley, J., Ruwase, O., He, Y., "ZeRO: Memory Optimizations Toward Training Trillion Parameter Models", SC 2020. arXiv:1910.02054.

16. Li, M., Rollings, N., Wu, Q., Ruwase, O., He, Y., "Efficient Large-Scale Language Model Training on GPU Clusters Using Megatron-LM", SC 2021. arXiv:2104.04473. https://doi.org/10.1145/3458817.3476209

17. Shoeybi, M., Patwary, M., Puri, R., LeGresley, P., Casper, J., Catanzaro, B., "Megatron-LM: Training Multi-Billion Parameter Language Models Using Model Parallelism", arXiv 2019. arXiv:1909.08053. https://doi.org/10.48550/arXiv.1909.08053

18. Huang, Y., Cheng, Y., Bapna, A., Firat, O., Chen, D., Chen, M., Lee, H., "GPipe: Efficient Training of Giant Neural Networks using Pipeline Parallelism", NeurIPS 2019. arXiv:1811.06965. https://doi.org/10.48550/arXiv.1811.06965

19. Narayanan, D., Shoeybi, M., Casper, J., LeGresley, P., Paul, M., Zhou, W., Li, M., He, Y., "Efficient Large-Scale Language Model Training on GPU Clusters", SC 2021. arXiv:2104.04473. https://doi.org/10.1145/3458817.3476209

20. Zhao, H., et al., "PyTorch FSDP: Experiences on Scaling Fully Sharded Data Parallel", VLDB 2023. arXiv:2304.11277. https://doi.org/10.48550/arXiv.2304.11277

21. Ren, Y., Rajbhandari, S., Aminabadi, R. Y., Zhang, Z., Ruwase, O., He, Y., "ZeRO-Offload: Democratizing Billion-Scale Model Training", arXiv 2021. arXiv:2101.06840. https://doi.org/10.48550/arXiv.2101.06840

22. Rajbhandari, S., Li, M., Yao, J., He, Y., "DeepSpeed: System Optimizations Enable Training Deep Learning Models with Over 100 Billion Parameters", arXiv 2020. DeepSpeed Documentation: https://www.deepspeed.ai/

23. PyTorch Team, "PyTorch Distributed: Distributed Data Parallel and Beyond", PyTorch Documentation. https://pytorch.org/tutorials/distributed.html

### Scaling Laws & Compute-Optimal Training

24. Hoffmann, J., et al., "Training Compute-Optimal Large Language Models" (Chinchilla), arXiv 2022. arXiv:2203.15556. https://doi.org/10.48550/arXiv.2203.15556

25. Kaplan, J., et al., "Scaling Laws for Neural Language Models", arXiv 2020. arXiv:2001.08361. https://doi.org/10.48550/arXiv.2001.08361

### Regularization

26. Srivastava, N., Hinton, G., Krizhevsky, A., Sutskever, I., Salakhutdinov, R., "Dropout: A Simple Way to Prevent Neural Networks from Overfitting", JMLR 2014. http://jmlr.org/papers/v15/srivastava14a.html

27. Huang, G., Sun, L., Liu, Z., Sedra, D., Weinberger, K., "Deep Networks with Stochastic Depth", ECCV 2016. arXiv:1603.09382.

28. Szegedy, C., Vanhoucke, V., Ioffe, S., Shlens, J., Wojna, Z., "Rethinking the Inception Architecture for Computer Vision", CVPR 2016. arXiv:1512.00567. https://doi.org/10.1109/CVPR.2016.308

29. Hu, E. J., Shen, Y., Wallis, P., Allen-Zhu, Z., Li, Y., Wang, S., Wang, L., Chen, W., "LoRA: Low-Rank Adaptation of Large Language Models", ICLR 2022. arXiv:2106.09685. https://doi.org/10.48550/arXiv.2106.09685

### Gradient Management & Large-Batch Training

30. Pascanu, R., Mikolov, T., Bengio, Y., "On the Difficulty of Training Recurrent Neural Networks", ICML 2013. arXiv:1211.5063. https://doi.org/10.48550/arXiv.1211.5063

31. Goyal, P., Dollar, P., Girshick, R., Noord, N. v. d., Misra, D., "Accurate, Large Minibatch SGD: Training ImageNet in 1 Hour", arXiv 2017. arXiv:1706.02677. https://doi.org/10.48550/arXiv.1706.02677

### Activation Checkpointing & Memory Optimization

32. Chen, T., Xu, B., Zhang, C., Guestrin, C., "Training Deep Nets with Sublinear Memory Cost", arXiv 2016. arXiv:1604.06174. https://doi.org/10.48550/arXiv.1604.06174

33. Dao, T., "FlashAttention-2: Faster Attention with Better Parallelism and Work Partitioning", arXiv 2023. arXiv:2307.08691. https://doi.org/10.48550/arXiv.2307.08691

34. Dao, T., Fu, D. Y., Ermon, S., Rudra, A., Re, C., "FlashAttention: Fast and Memory-Efficient Exact Attention with IO-Awareness", NeurIPS 2022. arXiv:2205.14135. https://doi.org/10.48550/arXiv.2205.14135

### Notable LLM Training References

35. Touvron, H., et al., "LLaMA: Open and Efficient Foundation Language Models", arXiv 2023. arXiv:2302.13971. https://doi.org/10.48550/arXiv.2302.13971

36. Brown, T. B., et al., "Language Models are Few-Shot Learners" (GPT-3), NeurIPS 2020. arXiv:2005.14165. https://doi.org/10.48550/arXiv.2005.14165

37. Zhang, S., et al., "OPT: Open Pre-trained Transformer Language Models", arXiv 2022. arXiv:2205.01068. https://doi.org/10.48550/arXiv.2205.01068

38. Black, S., et al., "GPT-NeoX-20B: An Open-Source Autoregressive Language Model", arXiv 2022. arXiv:2204.06745. https://doi.org/10.48550/arXiv.2204.06745
## References

- Kingma, D.P. & Ba, J., "Adam: A Method for Stochastic Optimization," ICLR 2015. https://arxiv.org/abs/1412.6980
- Loshchilov, I. & Hutter, F., "Decoupled Weight Decay Regularization," ICLR 2019. https://arxiv.org/abs/1711.05101
- Loshchilov, I. & Hutter, F., "SGDR: Stochastic Gradient Descent with Warm Restarts," ICLR 2017. https://arxiv.org/abs/1608.03983
- Goyal, P. et al., "Accurate, Large Minibatch SGD: Training ImageNet in 1 Hour," 2017. https://arxiv.org/abs/1706.02677
- Li, M. et al., "Scaling Laws for Neural Language Models," 2020. https://arxiv.org/abs/2001.08361
- Shoeybi, M. et al., "Megatron-LM: Training Multi-Billion Parameter Language Models," 2020. https://arxiv.org/abs/1909.08053
- Rajbhandari, S. et al., "ZeRO: Memory Optimizations Toward Training Trillion Parameter Models," SC 2020. https://arxiv.org/abs/1910.02054
- Zhang, M. et al., "Mixed Precision Training," ICLR 2018. https://arxiv.org/abs/1710.03740
- Ioffe, S. & Szegedy, C., "Batch Normalization: Accelerating Deep Network Training," ICML 2015. https://arxiv.org/abs/1502.03167
- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
